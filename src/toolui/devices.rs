//! Устройства: список с паролями в хранилище, редактор, терминалы во вкладках,
//! массовые команды со сравнением ответов.

use std::time::Duration;

use egui::RichText;
use egui_extras::{Column, TableBuilder};

use super::terminal::Term;
use super::{AMBER, Env, GREEN, RED};
use crate::devices::{self, Device, Proto, Vendor};
use crate::tools::Sink;
use crate::tools::Task;
use tokio_util::sync::CancellationToken;

/// Редактируемая запись: индекс (None — новая), устройство, пароли в открытом виде.
struct Edit {
    index: Option<usize>,
    dev: Device,
    pass: String,
    enable: String,
    error: Option<String>,
}

pub struct Panel {
    pub list: Vec<Device>,
    selected: Option<usize>,
    filter: String,
    edit: Option<Edit>,
    terms: Vec<Term>,
    active: usize,
    load_error: Option<String>,
}

impl Default for Panel {
    fn default() -> Self {
        Self {
            list: devices::load(),
            selected: None,
            filter: String::new(),
            edit: None,
            terms: Vec::new(),
            active: 0,
            load_error: None,
        }
    }
}

/// Строка списка подходит под фильтр.
pub fn matches(d: &Device, f: &str) -> bool {
    let f = f.to_lowercase();
    f.is_empty() || format!("{} {} {} {:?}", d.name, d.host, d.group, d.vendor).to_lowercase().contains(&f)
}

impl Panel {
    pub fn busy(&self) -> bool {
        self.terms.iter().any(|t| !t.closed)
    }

    pub fn open_sessions(&self) -> usize {
        self.terms.iter().filter(|t| !t.closed).count()
    }

    pub fn poll(&mut self) -> bool {
        let mut ch = false;
        for t in &mut self.terms {
            ch |= t.poll();
        }
        ch
    }

    fn save(&mut self) {
        if let Err(e) = devices::save(&self.list) {
            self.load_error = Some(e);
        }
    }

    pub fn connect(&mut self, d: Device, env: &Env) {
        self.terms.push(Term::open(d, env.rt));
        self.active = self.terms.len() - 1;
    }

    /// Добавить устройства из найденного (узлы с SSH/Telnet), без повторов.
    pub fn import(&mut self, found: &[(String, String, u16)]) -> usize {
        let mut n = 0;
        for (ip, name, port) in found {
            if self.list.iter().any(|d| d.host == *ip) {
                continue;
            }
            self.list.push(Device {
                name: name.clone(),
                host: ip.clone(),
                proto: if *port == 23 { Proto::Telnet } else { Proto::Ssh },
                port: *port,
                ..Default::default()
            });
            n += 1;
        }
        if n > 0 {
            self.save();
        }
        n
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, found: &[(String, String, u16)]) {
        ui.horizontal(|ui| {
            if ui.button("➕ Добавить").clicked() {
                self.edit = Some(Edit {
                    index: None,
                    dev: Device { proto: Proto::Ssh, ..Default::default() },
                    pass: String::new(),
                    enable: String::new(),
                    error: None,
                });
            }
            if !found.is_empty() && ui.button(format!("из найденного ({})", found.len())).on_hover_text("Узлы с открытыми SSH (22) и Telnet (23) из «Узлов», «Наблюдения» и сканирования").clicked() {
                let n = self.import(found);
                *env.message = Some(format!("добавлено устройств: {n}"));
            }
        });
        ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("поиск: имя, адрес, группа").desired_width(f32::INFINITY));
        let mut groups: Vec<String> = self.list.iter().map(|d| d.group.clone()).collect();
        groups.sort();
        groups.dedup();
        let mut connect = None;
        egui::ScrollArea::vertical().id_salt("dev_list").max_height(360.0).show(ui, |ui| {
            for g in &groups {
                let items: Vec<usize> = (0..self.list.len()).filter(|i| self.list[*i].group == *g && matches(&self.list[*i], &self.filter)).collect();
                if items.is_empty() {
                    continue;
                }
                ui.weak(if g.is_empty() { "без группы".to_string() } else { g.clone() });
                for i in items {
                    let d = &self.list[i];
                    let text = format!("{}  ·  {} {}", d.title(), d.proto.label(), d.host);
                    let r = ui.selectable_label(self.selected == Some(i), text).on_hover_text(format!(
                        "{}{}",
                        if d.vendor == Vendor::Auto { "производитель определится при подключении".into() } else { d.vendor.label().to_string() },
                        if d.notes.is_empty() { String::new() } else { format!("\n{}", d.notes) }
                    ));
                    if r.clicked() {
                        self.selected = Some(i);
                    }
                    if r.double_clicked() {
                        connect = Some(i);
                    }
                }
            }
            if self.list.is_empty() {
                ui.weak("Устройств нет: «Добавить» или «из найденного».");
            }
        });
        if let Some(i) = self.selected.filter(|i| *i < self.list.len()) {
            ui.horizontal_wrapped(|ui| {
                if ui.button("▶ Подключиться").clicked() {
                    connect = Some(i);
                }
                if ui.button("Изменить").clicked() {
                    let d = self.list[i].clone();
                    self.edit = Some(Edit { index: Some(i), pass: d.password(), enable: d.enable_password(), dev: d, error: None });
                }
                if ui.button("Удалить").clicked() {
                    self.list.remove(i);
                    self.selected = None;
                    self.save();
                }
            });
        }
        if let Some(i) = connect {
            let d = self.list[i].clone();
            self.connect(d, env);
        }
        if let Some(e) = &self.load_error {
            ui.colored_label(RED, e);
        }
        ui.add_space(6.0);
        ui.weak("Двойной щелчок — подключиться. Пароли хранятся зашифрованными (ключ — файл рядом с программой).");
        self.edit_window(ui.ctx());
    }

    fn edit_window(&mut self, ctx: &egui::Context) {
        let Some(e) = &mut self.edit else { return };
        let mut open = true;
        let mut save = false;
        egui::Window::new(if e.index.is_some() { "Устройство" } else { "Новое устройство" })
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(420.0)
            .show(ctx, |ui| {
                let d = &mut e.dev;
                egui::Grid::new("dev_edit").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    super::labeled(ui, "Название", |ui| ui.add(egui::TextEdit::singleline(&mut d.name).hint_text("sw-core-1")));
                    ui.label("Подключение");
                    ui.horizontal(|ui| {
                        for p in [Proto::Ssh, Proto::Telnet, Proto::Serial] {
                            if ui.radio(d.proto == p, p.label()).clicked() {
                                d.proto = p;
                                d.port = 0;
                            }
                        }
                    });
                    ui.end_row();
                    if d.proto == Proto::Serial {
                        ui.label("Порт");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut d.host).hint_text(if cfg!(windows) { "COM3" } else { "/dev/ttyUSB0" }).desired_width(140.0));
                            let ports = crate::tools::conn::serial_ports();
                            if !ports.is_empty() {
                                egui::ComboBox::from_id_salt("dev_com").selected_text("найденные").show_ui(ui, |ui| {
                                    for p in ports {
                                        if ui.button(&p).clicked() {
                                            d.host = p;
                                        }
                                    }
                                });
                            }
                        });
                        ui.end_row();
                        super::labeled(ui, "Скорость", |ui| ui.add(egui::DragValue::new(&mut d.port).range(0..=921_600).custom_formatter(|v, _| if v == 0.0 { "9600".into() } else { format!("{v}") })));
                    } else {
                        super::labeled(ui, "Адрес", |ui| ui.add(egui::TextEdit::singleline(&mut d.host).hint_text("10.0.0.2")));
                        super::labeled(ui, "Порт", |ui| ui.add(egui::DragValue::new(&mut d.port).range(0..=65535).custom_formatter(|v, _| if v == 0.0 { "по умолчанию".into() } else { format!("{v}") })));
                    }
                    ui.label("Производитель");
                    egui::ComboBox::from_id_salt("dev_vendor").selected_text(d.vendor.label()).show_ui(ui, |ui| {
                        for v in Vendor::ALL {
                            ui.selectable_value(&mut d.vendor, v, v.label());
                        }
                    });
                    ui.end_row();
                    super::labeled(ui, "Пользователь", |ui| ui.text_edit_singleline(&mut d.user));
                    super::labeled(ui, "Пароль", |ui| ui.add(egui::TextEdit::singleline(&mut e.pass).password(true)));
                    super::labeled(ui, "Пароль enable", |ui| ui.add(egui::TextEdit::singleline(&mut e.enable).password(true).hint_text("если нужен")));
                    if d.proto == Proto::Ssh {
                        super::labeled(ui, "Ключ SSH", |ui| ui.add(egui::TextEdit::singleline(&mut d.key_file).hint_text("путь к закрытому ключу (необязательно)")));
                    }
                    super::labeled(ui, "SNMP community", |ui| ui.add(egui::TextEdit::singleline(&mut d.community).hint_text("для мониторинга интерфейсов")));
                    super::labeled(ui, "Группа", |ui| ui.add(egui::TextEdit::singleline(&mut d.group).hint_text("ядро, этаж 3, филиал…")));
                    super::labeled(ui, "Заметка", |ui| ui.text_edit_singleline(&mut d.notes));
                });
                if let Some(err) = &e.error {
                    ui.colored_label(RED, err);
                }
                ui.horizontal(|ui| {
                    if ui.button("Сохранить").clicked() {
                        save = true;
                    }
                });
            });
        if save {
            let e = self.edit.as_mut().unwrap();
            if e.dev.host.trim().is_empty() {
                e.error = Some("укажите адрес или порт".into());
                return;
            }
            match (crate::vault::seal(&e.pass), crate::vault::seal(&e.enable)) {
                (Ok(p), Ok(en)) => {
                    let mut d = e.dev.clone();
                    d.secret = p;
                    d.enable = en;
                    match e.index {
                        Some(i) if i < self.list.len() => self.list[i] = d,
                        _ => self.list.push(d),
                    }
                    self.edit = None;
                    self.save();
                }
                (Err(x), _) | (_, Err(x)) => e.error = Some(x),
            }
        } else if !open {
            self.edit = None;
        }
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, _env: &mut Env) {
        if self.terms.is_empty() {
            ui.weak("Выберите устройство слева и нажмите «Подключиться» (или двойной щелчок). Сессии открываются вкладками; меню «Команды» — типовые команды производителя, «Таблицей» — разбор вывода последней команды.");
            return;
        }
        let mut close = None;
        ui.horizontal_wrapped(|ui| {
            for (i, t) in self.terms.iter().enumerate() {
                let text = RichText::new(t.title());
                let text = if t.closed { text.color(ui.visuals().weak_text_color()) } else { text };
                if ui.selectable_label(i == self.active, text).clicked() {
                    self.active = i;
                }
                if ui.small_button("×").on_hover_text("Закрыть сессию").clicked() {
                    close = Some(i);
                }
            }
        });
        if let Some(i) = close {
            self.terms[i].close();
            self.terms.remove(i);
            if self.active >= self.terms.len() {
                self.active = self.terms.len().saturating_sub(1);
            }
            return;
        }
        let Some(t) = self.terms.get_mut(self.active) else { return };
        t.toolbar(ui);
        if let Some((h, rows)) = t.table.clone() {
            let mut clear = false;
            egui::Panel::bottom(format!("term_table_{}", self.active)).resizable(true).default_size(220.0).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong(format!("Таблица: {} строк", rows.len()));
                    if ui.small_button("Копировать (CSV)").clicked() {
                        let mut s = h.join(";") + "\n";
                        for r in &rows {
                            s += &(r.join(";") + "\n");
                        }
                        ui.ctx().copy_text(s);
                    }
                    if ui.small_button("✖").clicked() {
                        clear = true;
                    }
                });
                table(ui, "term_tbl", &h, &rows);
            });
            if clear {
                t.table = None;
            }
        }
        t.ui(ui);
    }
}

/// Простая таблица строк.
pub fn table(ui: &mut egui::Ui, id: &str, header: &[String], rows: &[Vec<String>]) {
    egui::ScrollArea::horizontal().id_salt(id).show(ui, |ui| {
        let mut tb = TableBuilder::new(ui).id_salt(id).striped(true).resizable(true).min_scrolled_height(0.0);
        for _ in header {
            tb = tb.column(Column::initial(120.0).at_least(30.0).clip(true));
        }
        tb.header(20.0, |mut h| {
            for c in header {
                h.col(|ui| {
                    ui.strong(c);
                });
            }
        })
        .body(|body| {
            body.rows(18.0, rows.len(), |mut row| {
                let r = &rows[row.index()];
                for i in 0..header.len() {
                    row.col(|ui| {
                        ui.label(r.get(i).cloned().unwrap_or_default());
                    });
                }
            });
        });
    });
}

/// Выбор устройств флажками: фильтр, «все», группы.
pub fn pick_devices(ui: &mut egui::Ui, id: &str, list: &[Device], picked: &mut Vec<String>, filter: &mut String) {
    ui.label("Устройства");
    ui.add(egui::TextEdit::singleline(filter).hint_text("фильтр").desired_width(f32::INFINITY));
    let mut groups: Vec<String> = list.iter().map(|d| d.group.clone()).collect();
    groups.sort();
    groups.dedup();
    ui.horizontal_wrapped(|ui| {
        if ui.small_button("все").clicked() {
            *picked = list.iter().filter(|d| matches(d, filter)).map(|d| d.title()).collect();
        }
        if ui.small_button("никаких").clicked() {
            picked.clear();
        }
        for g in groups.iter().filter(|g| !g.is_empty()) {
            if ui.small_button(g).on_hover_text("выбрать группу").clicked() {
                *picked = list.iter().filter(|d| d.group == *g).map(|d| d.title()).collect();
            }
        }
    });
    egui::ScrollArea::vertical().id_salt(id).max_height(200.0).show(ui, |ui| {
        for d in list.iter().filter(|d| matches(d, filter)) {
            let t = d.title();
            let mut on = picked.contains(&t);
            if ui.checkbox(&mut on, format!("{t}  ·  {}", d.host)).changed() {
                if on {
                    picked.push(t);
                } else {
                    picked.retain(|x| *x != t);
                }
            }
        }
        if list.is_empty() {
            ui.weak("Сначала добавьте устройства на вкладке «Терминал».");
        }
    });
}

// ---------------------------------------------------------------------------
// Массовые команды
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Event {
    Done(String, Result<crate::tools::conn::Session, String>),
}

pub struct Commands {
    picked: Vec<String>,
    pub commands: String,
    task: Option<Task<Event>>,
    results: Vec<(String, Result<crate::tools::conn::Session, String>)>,
    total: usize,
    view: u8,
    filter: String,
    concurrency: usize,
}

impl Default for Commands {
    fn default() -> Self {
        Self {
            picked: Vec::new(),
            commands: String::new(),
            task: None,
            results: Vec::new(),
            total: 0,
            view: 0,
            filter: String::new(),
            concurrency: 8,
        }
    }
}

/// Сравнение ответов: группы одинаковых ответов на команду (самая большая — «норма»).
pub fn group_outputs<'a>(items: &[(&'a str, &'a str)]) -> Vec<(String, Vec<&'a str>)> {
    let norm = |s: &str| s.lines().map(|l| l.trim_end()).filter(|l| !l.trim().is_empty()).collect::<Vec<_>>().join("\n");
    let mut groups: Vec<(String, Vec<&str>)> = Vec::new();
    for (dev, out) in items {
        let n = norm(out);
        match groups.iter_mut().find(|g| g.0 == n) {
            Some(g) => g.1.push(dev),
            None => groups.push((n, vec![dev])),
        }
    }
    groups.sort_by_key(|g| std::cmp::Reverse(g.1.len()));
    groups
}

impl Commands {
    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    pub fn done(&self) -> usize {
        self.results.len()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let ev = t.drain();
        let fin = t.finished();
        let ch = !ev.is_empty() || fin;
        for Event::Done(d, r) in ev {
            self.results.push((d, r));
        }
        if fin {
            self.task = None;
        }
        ch
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, list: &[Device]) {
        pick_devices(ui, "cmd_devs", list, &mut self.picked, &mut self.filter);
        ui.label(format!("Команды (по одной в строке) — выбрано устройств: {}", self.picked.len()));
        super::multiline(ui, &mut self.commands, 4, "show version\nshow interfaces status");
        ui.horizontal_wrapped(|ui| {
            ui.weak("Готовые:");
            for (t, c) in [
                ("версия", "@version"),
                ("интерфейсы", "@interfaces"),
                ("LLDP", "@lldp"),
                ("MAC-таблица", "@mac"),
            ] {
                if ui.small_button(t).on_hover_text("Команда подставится под производителя каждого устройства").clicked() {
                    if !self.commands.is_empty() && !self.commands.ends_with('\n') {
                        self.commands.push('\n');
                    }
                    self.commands.push_str(c);
                }
            }
        });
        let (start, stop) = super::run_button(ui, self.busy(), "Выполнить");
        if start && !self.picked.is_empty() && !self.commands.trim().is_empty() {
            let devs: Vec<Device> = list.iter().filter(|d| self.picked.contains(&d.title())).cloned().collect();
            let cmds: Vec<String> = self.commands.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
            self.results.clear();
            self.total = devs.len();
            let conc = self.concurrency;
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| run_many(devs, cmds, conc, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if self.busy() {
            super::progress(ui, self.results.len() as u64, self.total as u64, true);
        }
        super::advanced(ui, "cmd_adv", |ui| {
            ui.horizontal(|ui| {
                ui.label("Параллельно");
                ui.add(egui::DragValue::new(&mut self.concurrency).range(1..=64));
            });
        });
        ui.add_space(4.0);
        ui.weak("@version, @interfaces, @lldp, @mac, @config — команда под производителя каждого устройства. Вход, enable и отключение постраничного вывода — автоматически.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui) {
        if self.results.is_empty() {
            if self.busy() {
                ui.spinner();
            } else {
                ui.weak("Выберите устройства, впишите команды и нажмите «Выполнить». Ответы можно сравнить: какие устройства ответили иначе, чем большинство.");
            }
            return;
        }
        let ok = self.results.iter().filter(|r| r.1.is_ok()).count();
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.view, 0, "Сравнение");
            ui.selectable_value(&mut self.view, 1, "По устройствам");
            ui.selectable_value(&mut self.view, 2, "Таблицей");
            ui.separator();
            ui.colored_label(GREEN, format!("успешно: {ok}"));
            if ok < self.results.len() {
                ui.colored_label(RED, format!("ошибок: {}", self.results.len() - ok));
            }
            if ui.small_button("Копировать всё").clicked() {
                let mut s = String::new();
                for (d, r) in &self.results {
                    s += &format!("===== {d}\n");
                    match r {
                        Ok(x) => {
                            for (c, o) in &x.outputs {
                                s += &format!("--- {c}\n{o}\n");
                            }
                        }
                        Err(e) => s += &format!("ошибка: {e}\n"),
                    }
                }
                ui.ctx().copy_text(s);
            }
        });
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (d, r) in self.results.iter().filter(|r| r.1.is_err()) {
                if let Err(e) = &r {
                    ui.colored_label(RED, format!("✖ {d}: {e}"));
                }
            }
            let cmds: Vec<String> = self.results.iter().filter_map(|r| r.1.as_ref().ok()).flat_map(|s| s.outputs.iter().map(|o| o.0.clone())).fold(Vec::new(), |mut v, c| {
                if !v.contains(&c) {
                    v.push(c);
                }
                v
            });
            match self.view {
                0 => {
                    for c in &cmds {
                        let items: Vec<(&str, &str)> = self
                            .results
                            .iter()
                            .filter_map(|(d, r)| r.as_ref().ok().and_then(|s| s.outputs.iter().find(|o| o.0 == *c).map(|o| (d.as_str(), o.1.as_str()))))
                            .collect();
                        let groups = group_outputs(&items);
                        ui.add_space(6.0);
                        ui.label(RichText::new(format!("{c} — вариантов ответа: {}", groups.len())).strong());
                        for (i, (out, devs)) in groups.iter().enumerate() {
                            let head = if i == 0 && groups.len() > 1 {
                                RichText::new(format!("большинство ({}): {}", devs.len(), devs.join(", "))).color(GREEN)
                            } else if groups.len() > 1 {
                                RichText::new(format!("иначе ({}): {}", devs.len(), devs.join(", "))).color(AMBER)
                            } else {
                                RichText::new(format!("одинаково у всех ({})", devs.len())).color(GREEN)
                            };
                            egui::CollapsingHeader::new(head).id_salt(("cmp", c, i)).default_open(i > 0).show(ui, |ui| {
                                super::mono_block(ui, &format!("cmp_{c}_{i}"), out, 260.0);
                            });
                        }
                    }
                }
                1 => {
                    for (d, r) in &self.results {
                        let Ok(s) = r else { continue };
                        egui::CollapsingHeader::new(RichText::new(format!("{d} · {}", s.vendor.label())).strong()).id_salt(("dev_out", d)).show(ui, |ui| {
                            for (c, o) in &s.outputs {
                                ui.weak(c);
                                super::mono_block(ui, &format!("o_{d}_{c}"), o, 260.0);
                            }
                        });
                    }
                }
                _ => {
                    for c in &cmds {
                        let mut header: Option<Vec<String>> = None;
                        let mut rows: Vec<Vec<String>> = Vec::new();
                        for (d, r) in &self.results {
                            let Some(o) = r.as_ref().ok().and_then(|s| s.outputs.iter().find(|o| o.0 == *c)) else { continue };
                            if let Some((h, rs)) = devices::parse_table(&o.1) {
                                if header.is_none() {
                                    let mut hh = vec!["Устройство".to_string()];
                                    hh.extend(h);
                                    header = Some(hh);
                                }
                                for mut row in rs {
                                    row.insert(0, d.clone());
                                    rows.push(row);
                                }
                            }
                        }
                        ui.add_space(6.0);
                        match header {
                            Some(h) => {
                                ui.label(RichText::new(format!("{c} — {} строк", rows.len())).strong());
                                table(ui, &format!("mt_{c}"), &h, &rows);
                            }
                            None => {
                                ui.weak(format!("{c}: вывод не похож на таблицу"));
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Подставить команды под производителя: @version, @interfaces, @lldp, @mac, @config.
pub fn expand(cmd: &str, v: Vendor) -> String {
    let p = v.profile();
    match cmd.trim() {
        "@version" => p.version.into(),
        "@interfaces" => p.interfaces.into(),
        "@lldp" => p.lldp.into(),
        "@mac" => p.mac.into(),
        "@config" => p.config.into(),
        c => c.into(),
    }
}

pub async fn run_many(devs: Vec<Device>, cmds: Vec<String>, conc: usize, sink: Sink<Event>, cancel: CancellationToken) {
    crate::tools::for_each_limited(devs, conc, &cancel, |d| {
        let sink = sink.clone();
        let cmds = cmds.clone();
        async move {
            // Для макросов нужен производитель: сначала определяем его по входу.
            let need_vendor = cmds.iter().any(|c| c.starts_with('@')) && d.vendor == Vendor::Auto;
            let r = if need_vendor {
                match crate::tools::conn::run_commands(&d, &[], Duration::from_secs(10)).await {
                    Ok(s) => {
                        let mut d2 = d.clone();
                        d2.vendor = s.vendor;
                        let real: Vec<String> = cmds.iter().map(|c| expand(c, s.vendor)).collect();
                        crate::tools::conn::run_commands(&d2, &real, Duration::from_secs(10)).await.map(|mut s2| {
                            for (o, c) in s2.outputs.iter_mut().zip(&cmds) {
                                o.0 = c.clone();
                            }
                            s2
                        })
                    }
                    Err(e) => Err(e),
                }
            } else {
                let real: Vec<String> = cmds.iter().map(|c| expand(c, d.vendor)).collect();
                crate::tools::conn::run_commands(&d, &real, Duration::from_secs(10)).await.map(|mut s| {
                    for (o, c) in s.outputs.iter_mut().zip(&cmds) {
                        o.0 = c.clone();
                    }
                    s
                })
            };
            sink.send(Event::Done(d.title(), r));
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouping() {
        let items = vec![("sw1", "ver 15.2\n"), ("sw2", "ver 15.2"), ("sw3", "ver 12.1"), ("sw4", " ver 15.2 ".trim())];
        let g = group_outputs(&items);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].1, vec!["sw1", "sw2", "sw4"]);
        assert_eq!(g[1].1, vec!["sw3"]);
        assert_eq!(expand("@interfaces", Vendor::Huawei), "display interface brief");
        assert_eq!(expand("show clock", Vendor::Huawei), "show clock");
    }
}
