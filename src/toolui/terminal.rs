//! Терминал устройства: эмуляция VT100/xterm (vt100), ввод с клавиатуры, вставка,
//! прокрутка истории; знает производителя — меню типовых команд и разбор вывода
//! в таблицу.

use std::num::NonZeroU16;
use std::time::Duration;

use egui::text::LayoutJob;
use egui::{Color32, FontId, RichText, TextFormat};
use tokio::sync::{mpsc, oneshot};

use crate::devices::{Device, Vendor};
use crate::tools::conn::{self, Conn, In, Out};

pub struct Term {
    pub device: Device,
    parser: vt100::Parser,
    tx: Option<mpsc::UnboundedSender<In>>,
    rx: Option<mpsc::UnboundedReceiver<Out>>,
    pending: Option<oneshot::Receiver<Result<Conn, String>>>,
    pub status: String,
    pub closed: bool,
    /// Весь вывод без управляющих последовательностей (для разбора).
    pub transcript: String,
    pub vendor: Vendor,
    size: (u16, u16),
    scroll: usize,
    pub table: Option<(Vec<String>, Vec<Vec<String>>)>,
    /// Автовход по Telnet/COM: сколько раз уже отвечали (имя, пароль).
    login: (u8, u8),
    /// Когда подключились (для «побудки» молчащего Telnet/COM).
    connected_at: Option<std::time::Instant>,
}

fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v.max(1)).unwrap()
}

impl Term {
    pub fn open(device: Device, rt: &tokio::runtime::Handle) -> Self {
        let (tx, rx) = oneshot::channel();
        let d = device.clone();
        rt.spawn(async move {
            let _ = tx.send(conn::open(&d, 120, 40, Duration::from_secs(10)).await);
        });
        let vendor = device.vendor;
        Self {
            status: format!("подключение к {}…", device.host),
            device,
            parser: vt100::Parser::new(nz(40), nz(120), 5000),
            tx: None,
            rx: None,
            pending: Some(rx),
            closed: false,
            transcript: String::new(),
            vendor,
            size: (40, 120),
            scroll: 0,
            table: None,
            login: (0, 0),
            connected_at: None,
        }
    }

    pub fn title(&self) -> String {
        let mark = if self.closed { " ✖" } else if self.pending.is_some() { " …" } else { "" };
        format!("{}{mark}", self.device.title())
    }

    pub fn send(&self, b: &[u8]) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(In::Data(b.to_vec()));
        }
    }

    pub fn send_line(&self, cmd: &str) {
        let nl = self.newline();
        self.send(format!("{cmd}{nl}").as_bytes());
    }

    /// Enter: Telnet (NVT) и MikroTik — CR LF, иначе CR.
    fn newline(&self) -> &'static str {
        if self.vendor == Vendor::Mikrotik || self.device.proto == crate::devices::Proto::Telnet { "\r\n" } else { "\r" }
    }

    pub fn close(&mut self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(In::Close);
        }
    }

    /// Новые данные; true — что-то изменилось.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        if let Some(p) = &mut self.pending
            && let Ok(r) = p.try_recv()
        {
            self.pending = None;
            changed = true;
            match r {
                Ok(c) => {
                    self.tx = Some(c.tx);
                    self.rx = Some(c.rx);
                    self.status = format!("{} {}", self.device.proto.label(), self.device.host);
                    self.connected_at = Some(std::time::Instant::now());
                }
                Err(e) => {
                    self.status = e;
                    self.closed = true;
                }
            }
        }
        if let Some(rx) = &mut self.rx {
            while let Ok(m) = rx.try_recv() {
                changed = true;
                match m {
                    Out::Data(d) => {
                        self.parser.process(&d);
                        self.transcript.push_str(&conn::clean(&d));
                        if self.transcript.len() > 2_000_000 {
                            let cut = self.transcript.len() - 1_500_000;
                            let cut = self.transcript.ceil_char_boundary(cut);
                            self.transcript.drain(..cut);
                        }
                        if self.vendor == Vendor::Auto && self.transcript.len() < 20_000 {
                            let v = Vendor::detect(&self.transcript);
                            if v != Vendor::Auto {
                                self.vendor = v;
                            }
                        }
                    }
                    Out::Closed(why) => {
                        self.status = why;
                        self.closed = true;
                    }
                }
            }
        }
        if changed {
            self.auto_login();
        }
        // Telnet/COM молчит полторы секунды — шлём перевод строки, чтобы появилось приглашение.
        if let Some(t) = self.connected_at
            && t.elapsed() > Duration::from_millis(1500)
        {
            self.connected_at = None;
            if self.transcript.trim().is_empty() && self.device.proto != crate::devices::Proto::Ssh {
                let nl = self.newline();
                self.send(nl.as_bytes());
            }
        }
        changed
    }

    /// Ответить на запрос имени и пароля сохранёнными данными (Telnet и COM;
    /// в SSH вход уже выполнен). Не больше двух раз — чтобы не зациклиться на неверном пароле.
    fn auto_login(&mut self) {
        if self.device.proto == crate::devices::Proto::Ssh || self.transcript.len() > 20_000 {
            return;
        }
        let tail = self.transcript.trim_end().rsplit('\n').next().unwrap_or("").trim().to_lowercase();
        if (tail.ends_with("username:") || tail.ends_with("login:") || tail.ends_with("user name:")) && self.login.0 < 2 && !self.device.user.is_empty() {
            self.login.0 += 1;
            let u = self.device.user.clone();
            self.send_line(&u);
        } else if tail.ends_with("password:") && self.login.1 < 2 {
            let p = self.device.password();
            if !p.is_empty() {
                self.login.1 += 1;
                self.send_line(&p);
            }
        }
    }

    /// Вывод последней команды: текст между строкой «приглашение + команда»
    /// и текущим приглашением.
    pub fn last_output(&self) -> String {
        last_output(&self.transcript)
    }

    fn color(c: vt100::Color, fg: bool, dark: bool) -> Color32 {
        const BASE: [Color32; 16] = [
            Color32::from_rgb(0, 0, 0),
            Color32::from_rgb(205, 49, 49),
            Color32::from_rgb(13, 188, 121),
            Color32::from_rgb(229, 229, 16),
            Color32::from_rgb(36, 114, 200),
            Color32::from_rgb(188, 63, 188),
            Color32::from_rgb(17, 168, 205),
            Color32::from_rgb(229, 229, 229),
            Color32::from_rgb(102, 102, 102),
            Color32::from_rgb(241, 76, 76),
            Color32::from_rgb(35, 209, 139),
            Color32::from_rgb(245, 245, 67),
            Color32::from_rgb(59, 142, 234),
            Color32::from_rgb(214, 112, 214),
            Color32::from_rgb(41, 184, 219),
            Color32::from_rgb(255, 255, 255),
        ];
        match c {
            vt100::Color::Default => {
                if fg {
                    if dark { Color32::from_rgb(220, 220, 220) } else { Color32::from_rgb(30, 30, 30) }
                } else {
                    Color32::TRANSPARENT
                }
            }
            vt100::Color::Idx(i) if i < 16 => BASE[i as usize],
            vt100::Color::Idx(i) if i >= 232 => {
                let v = 8 + (i - 232) * 10;
                Color32::from_rgb(v, v, v)
            }
            vt100::Color::Idx(i) => {
                let i = i - 16;
                let (r, g, b) = (i / 36, (i / 6) % 6, i % 6);
                let k = |x: u8| if x == 0 { 0 } else { 55 + x * 40 };
                Color32::from_rgb(k(r), k(g), k(b))
            }
            vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        }
    }

    /// Экран терминала с вводом. Занимает всё доступное место.
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let font = FontId::monospace(13.0);
        let (cw, ch) = ui.fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
        let avail = ui.available_size();
        let cols = ((avail.x - 8.0) / cw).floor().clamp(20.0, 400.0) as u16;
        let rows = ((avail.y - 8.0) / ch).floor().clamp(5.0, 200.0) as u16;
        if (rows, cols) != self.size {
            self.size = (rows, cols);
            self.parser.set_size(nz(rows), nz(cols));
            if let Some(tx) = &self.tx {
                let _ = tx.send(In::Resize(cols, rows));
            }
        }
        if self.connected_at.is_some() || self.pending.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(300));
        }
        let (rect, resp) = ui.allocate_exact_size(avail, egui::Sense::click());
        let id = resp.id;
        if resp.clicked() {
            ui.memory_mut(|m| m.request_focus(id));
        }
        let focused = ui.memory(|m| m.has_focus(id));
        if focused {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true })
            });
            self.input(ui);
        }
        // Прокрутка истории колесом.
        if resp.hovered() {
            let dy = ui.input(|i| i.smooth_scroll_delta.y);
            if dy.abs() > 0.5 {
                let step = (dy / ch).round() as i64;
                let max = 5000i64;
                self.scroll = (self.scroll as i64 + step).clamp(0, max) as usize;
                self.parser.screen_mut().set_scrollback(self.scroll);
                self.scroll = self.parser.screen().scrollback();
            }
        }
        let dark = ui.visuals().dark_mode;
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, if dark { Color32::from_rgb(18, 18, 20) } else { Color32::from_rgb(250, 250, 250) });
        let screen = self.parser.screen();
        let origin = rect.min + egui::vec2(4.0, 4.0);
        for r in 0..rows {
            let mut job = LayoutJob::default();
            for c in 0..cols {
                let Some(cell) = screen.cell(r, c) else { continue };
                if cell.is_wide_continuation() {
                    continue;
                }
                let mut fg = Self::color(cell.fgcolor(), true, dark);
                let mut bg = Self::color(cell.bgcolor(), false, dark);
                if cell.inverse() {
                    let f = if bg == Color32::TRANSPARENT { if dark { Color32::from_rgb(18, 18, 20) } else { Color32::WHITE } } else { bg };
                    bg = fg;
                    fg = f;
                }
                if cell.bold() && let vt100::Color::Idx(i) = cell.fgcolor() && i < 8 {
                    fg = Self::color(vt100::Color::Idx(i + 8), true, dark);
                }
                let text = if cell.has_contents() { cell.contents().to_string() } else { " ".to_string() };
                job.append(&text, 0.0, TextFormat { font_id: font.clone(), color: fg, background: bg, ..Default::default() });
            }
            let galley = ui.fonts_mut(|f| f.layout_job(job));
            painter.galley(origin + egui::vec2(0.0, r as f32 * ch), galley, Color32::WHITE);
        }
        if !screen.hide_cursor() && self.scroll == 0 {
            let (cr, cc) = screen.cursor_position();
            let p = origin + egui::vec2(cc as f32 * cw, cr as f32 * ch);
            let cur = egui::Rect::from_min_size(p, egui::vec2(cw, ch));
            if focused {
                painter.rect_filled(cur, 0.0, Color32::from_rgba_unmultiplied(120, 180, 255, 140));
            } else {
                painter.rect_stroke(cur, 0.0, egui::Stroke::new(1.0, Color32::from_rgb(120, 180, 255)), egui::StrokeKind::Inside);
            }
        }
        if !focused {
            painter.text(rect.right_top() + egui::vec2(-8.0, 6.0), egui::Align2::RIGHT_TOP, "щёлкните, чтобы печатать", FontId::proportional(11.0), Color32::GRAY);
        }
        if self.scroll > 0 {
            painter.text(rect.right_bottom() + egui::vec2(-8.0, -6.0), egui::Align2::RIGHT_BOTTOM, format!("история: −{} строк", self.scroll), FontId::proportional(11.0), Color32::GRAY);
        }
    }

    fn input(&mut self, ui: &mut egui::Ui) {
        let app_cursor = self.parser.screen().application_cursor();
        let events = ui.input(|i| i.events.clone());
        let mut out: Vec<u8> = Vec::new();
        for e in events {
            match e {
                egui::Event::Text(t) => out.extend(t.as_bytes()),
                egui::Event::Paste(t) => out.extend(t.replace("\r\n", "\r").replace('\n', "\r").as_bytes()),
                egui::Event::Copy => {
                    ui.ctx().copy_text(self.parser.screen().contents());
                }
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    use egui::Key::*;
                    if modifiers.ctrl && !modifiers.shift {
                        let c = key.name().chars().next().unwrap_or(' ');
                        if c.is_ascii_alphabetic() && key.name().len() == 1 {
                            out.push((c.to_ascii_uppercase() as u8) - b'A' + 1);
                            continue;
                        }
                    }
                    let arrow = |c: char| if app_cursor { format!("\x1bO{c}") } else { format!("\x1b[{c}") };
                    let seq: Option<String> = match key {
                        Enter => Some(self.newline().into()),
                        Backspace => Some("\x7f".into()),
                        Tab => Some("\t".into()),
                        Escape => Some("\x1b".into()),
                        ArrowUp => Some(arrow('A')),
                        ArrowDown => Some(arrow('B')),
                        ArrowRight => Some(arrow('C')),
                        ArrowLeft => Some(arrow('D')),
                        Home => Some("\x1b[H".into()),
                        End => Some("\x1b[F".into()),
                        Delete => Some("\x1b[3~".into()),
                        PageUp => Some("\x1b[5~".into()),
                        PageDown => Some("\x1b[6~".into()),
                        Insert => Some("\x1b[2~".into()),
                        F1 => Some("\x1bOP".into()),
                        F2 => Some("\x1bOQ".into()),
                        F3 => Some("\x1bOR".into()),
                        F4 => Some("\x1bOS".into()),
                        _ => None,
                    };
                    if let Some(s) = seq {
                        out.extend(s.as_bytes());
                    }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            if self.scroll > 0 {
                self.scroll = 0;
                self.parser.screen_mut().set_scrollback(0);
            }
            self.send(&out);
        }
    }

    /// Панель над терминалом: типовые команды, разбор вывода.
    pub fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.weak(&self.status);
            ui.separator();
            ui.weak(if self.vendor == Vendor::Auto { "производитель: ?".to_string() } else { self.vendor.label().to_string() });
            ui.menu_button("Команды ▾", |ui| {
                for (title, cmd) in crate::devices::library(self.vendor) {
                    if ui.button(format!("{title}  ·  {cmd}")).clicked() {
                        self.send_line(&cmd);
                        ui.close();
                    }
                }
            });
            if ui.button("Таблицей").on_hover_text("Разобрать вывод последней команды в таблицу").clicked() {
                self.table = crate::devices::parse_table(&self.last_output());
                if self.table.is_none() {
                    self.status = "вывод не похож на таблицу".into();
                }
            }
            if ui.button("Копировать").on_hover_text("Весь вывод сессии").clicked() {
                ui.ctx().copy_text(self.transcript.clone());
            }
            if self.closed {
                ui.label(RichText::new("отключено").color(super::RED));
            }
        });
    }
}

/// Вывод последней команды из стенограммы сессии.
pub fn last_output(transcript: &str) -> String {
    let lines: Vec<&str> = transcript.lines().collect();
    let Some(last) = lines.iter().rposition(|l| !l.trim().is_empty()) else { return String::new() };
    let tail = lines[last].trim();
    // Текущее приглашение — последняя строка, если похожа на приглашение.
    if let Some(prompt) = conn::prompt_of(tail) {
        let base = prompt.trim_end_matches(['#', '>', ']', '$', ' ']);
        let base = base.trim_start_matches(['<', '[']);
        if let Some(start) = lines[..last].iter().rposition(|l| !base.is_empty() && l.trim_start().trim_start_matches(['<', '[']).starts_with(base)) {
            return lines[start + 1..last].join("\n");
        }
        return lines[..last].join("\n");
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    #[test]
    fn last_command_output() {
        let t = "Username: Password:\nsw-lab#pw\n% Invalid input\nsw-lab#show interfaces status\nPort Name\nGi1 x\nsw-lab#";
        assert_eq!(super::last_output(t), "Port Name\nGi1 x");
        let h = "<core>display version\nVRP 8\n<core>";
        assert_eq!(super::last_output(h), "VRP 8");
        let m = "[admin@gw] > /ip address print\n 0 10.0.0.1/24\n[admin@gw] > ";
        assert_eq!(super::last_output(m), " 0 10.0.0.1/24");
    }
}
