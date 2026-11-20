use egui::RichText;

use super::{AMBER, Env, GREEN, RED, Tool};
use super::UiNz;
use crate::tools::Task;
use crate::tools::capture::{self, Config, Device, Event, Packet, Raw, Summary};

#[derive(PartialEq, Clone, Copy)]
enum View {
    Summary,
    Packets,
}

pub struct Panel {
    pub cfg: Config,
    task: Option<Task<Event>>,
    packets: Vec<Packet>,
    raws: Vec<Raw>,
    pub summary: Summary,
    linktype: i32,
    devices: Option<Result<Vec<Device>, String>>,
    status: String,
    view: View,
    text: String,
    follow: bool,
}

const MAX_SHOWN: usize = 50_000;

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            task: None,
            packets: Vec::new(),
            raws: Vec::new(),
            summary: Summary::default(),
            linktype: 1,
            devices: None,
            status: String::new(),
            view: View::Summary,
            text: String::new(),
            follow: true,
        }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let events = t.drain();
        let finished = t.finished();
        let changed = !events.is_empty() || finished;
        for e in events {
            match e {
                Event::Log(m) => self.status = m,
                Event::Started(l) => {
                    self.linktype = l;
                    self.status = "идёт захват…".into();
                }
                Event::Packets(p, r) => {
                    // Сводку пересчитываем по сырым кадрам: это быстрее, чем пересылать её целиком.
                    for raw in &r {
                        self.summary.packets += 1;
                        self.summary.bytes += raw.len as u64;
                        capture::dissect(&raw.data, self.linktype, &mut self.summary);
                    }
                    self.packets.extend(p);
                    if self.packets.len() > MAX_SHOWN {
                        let cut = self.packets.len() - MAX_SHOWN;
                        self.packets.drain(..cut);
                    }
                    self.raws.extend(r);
                    if self.raws.len() > self.cfg.keep_packets {
                        let cut = self.raws.len() - self.cfg.keep_packets;
                        self.raws.drain(..cut);
                    }
                }
                Event::Stopped(m) => self.status = format!("захват завершён: {m}"),
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    fn start(&mut self, env: &Env) {
        self.packets.clear();
        self.raws.clear();
        self.summary = Summary::default();
        self.status = "запуск…".into();
        let cfg = self.cfg.clone();
        self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| capture::run(cfg, s, c)));
    }

    /// Короткие органы управления для «Угроз»: интерфейс и прослушивание служебного трафика.
    pub fn listen_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        if self.devices.is_none() {
            self.devices = Some(capture::Pcap::load().and_then(|p| p.devices()));
        }
        match self.devices.as_ref().unwrap() {
            Err(e) => {
                ui.colored_label(RED, e);
                return;
            }
            Ok(devs) => {
                ui.label("Интерфейс");
                let current = devs.iter().find(|d| d.name == self.cfg.device).map(|d| d.label()).unwrap_or("автоматически".into());
                egui::ComboBox::from_id_salt("thr_dev").width(ui.available_width()).selected_text(current).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.cfg.device, String::new(), "автоматически");
                    for d in devs {
                        ui.selectable_value(&mut self.cfg.device, d.name.clone(), d.label());
                    }
                });
            }
        }
        let (start, stop) = super::run_button(ui, self.busy(), "Слушать сегмент");
        if start {
            self.cfg.filter = capture::PASSIVE_FILTER.into();
            self.start(env);
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if !self.status.is_empty() {
            ui.weak(&self.status);
        }
        if self.summary.packets > 0 {
            ui.weak(format!("пакетов: {}", self.summary.packets));
        }
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        if self.devices.is_none() {
            self.devices = Some(capture::Pcap::load().and_then(|p| p.devices()));
        }
        super::preset_bar(ui, env, "capture", &mut self.cfg);
        match self.devices.as_ref().unwrap() {
            Err(e) => {
                ui.colored_label(RED, e);
                ui.weak("Захват пакетов использует тот же драйвер, что и masscan.");
                return;
            }
            Ok(devs) => {
                ui.label("Интерфейс");
                let current = devs.iter().find(|d| d.name == self.cfg.device).map(|d| d.label()).unwrap_or("автоматически".into());
                egui::ComboBox::from_id_salt("cap_dev").width(ui.available_width()).selected_text(current).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.cfg.device, String::new(), "автоматически");
                    for d in devs {
                        ui.selectable_value(&mut self.cfg.device, d.name.clone(), d.label());
                    }
                });
            }
        }
        ui.horizontal(|ui| {
            ui.label("Фильтр (BPF)");
            if ui.small_button("служебные протоколы").on_hover_text("DHCP, LLDP, CDP, STP, ARP, LLMNR, NBT-NS, mDNS, SSDP").clicked() {
                self.cfg.filter = capture::PASSIVE_FILTER.into();
            }
            if ui.small_button("всё").clicked() {
                self.cfg.filter.clear();
            }
        });
        ui.add(egui::TextEdit::multiline(&mut self.cfg.filter).font(egui::TextStyle::Monospace).desired_rows(2).desired_width(f32::INFINITY).hint_text("tcp port 443 and host 10.0.0.5"));
        let (start, stop) = super::run_button(ui, self.busy(), "Начать захват");
        if start {
            self.start(env);
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if !self.status.is_empty() {
            ui.weak(&self.status);
        }
        if !crate::util::is_admin() {
            ui.colored_label(AMBER, format!("Для захвата нужны права «{}».", crate::util::ADMIN_NAME));
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.raws.is_empty(), egui::Button::new("Сохранить pcapng…"))
                .on_hover_text("Открывается в Wireshark")
                .clicked()
                && let Some(path) = rfd::FileDialog::new().add_filter("pcapng", &["pcapng"]).set_file_name("capture.pcapng").save_file()
            {
                *env.message = Some(match std::fs::write(&path, capture::pcapng(&self.raws, self.linktype as u16)) {
                    Ok(()) => format!("сохранено пакетов: {} → {}", self.raws.len(), path.display()),
                    Err(e) => e.to_string(),
                });
            }
            if ui
                .button("Найти DHCP-серверы")
                .on_hover_text("Отправить DHCP DISCOVER: ответят все DHCP-серверы сегмента, в том числе посторонние. Захват должен быть запущен.")
                .clicked()
            {
                env.rt.spawn(async {
                    let _ = capture::dhcp_discover().await;
                });
                *env.message = Some(if self.busy() {
                    "DHCP DISCOVER отправлен — ответы появятся в сводке".into()
                } else {
                    "Сначала запустите захват, затем нажмите «Найти DHCP-серверы»".into()
                });
            }
        });
        let c = &mut self.cfg;
        super::advanced(ui, "cap_adv", |ui| {
            ui.checkbox(&mut c.promiscuous, "Неразборчивый режим (весь трафик сегмента)");
            egui::Grid::new("cap_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Остановить через, с (0 — нет)", |ui| ui.add(egui::DragValue::new(&mut c.seconds).range(0..=86_400)));
                super::labeled(ui, "Остановить после пакетов", |ui| ui.add(egui::DragValue::new(&mut c.max_packets).range(0..=100_000_000)));
                super::labeled(ui, "Хранить для pcapng", |ui| ui.add(egui::DragValue::new(&mut c.keep_packets).range(1000..=5_000_000)));
            });
        });
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.view, View::Summary, "Сводка");
            ui.selectable_value(&mut self.view, View::Packets, format!("Пакеты ({})", self.summary.packets));
            ui.weak(format!("{:.1} МБ", self.summary.bytes as f64 / 1e6));
            if self.busy() {
                ui.spinner();
            }
            let sum = self.summary.clone();
            super::export_buttons(ui, env, "traffic-summary", &sum, render_summary);
        });
        ui.separator();
        match self.view {
            View::Summary => self.summary_ui(ui, env),
            View::Packets => self.packets_ui(ui),
        }
    }

    fn summary_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let s = &self.summary;
        if s.packets == 0 {
            ui.weak("Запустите захват с фильтром «служебные протоколы»: через 30–60 секунд здесь появятся коммутатор и порт (LLDP/CDP), DHCP-серверы, корень STP, конфликты ARP и широковещательные запросы имён.");
            return;
        }
        let nav = &mut *env.nav;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.strong("Куда подключена машина (LLDP / CDP)");
            if s.neighbors.is_empty() {
                ui.weak("нет объявлений (коммутатор не шлёт LLDP/CDP или они отфильтрованы)");
            }
            for n in &s.neighbors {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("{} {}", n.protocol, n.device)).strong());
                    ui.label(format!("порт {}", n.port));
                    if !n.port_description.is_empty() {
                        ui.weak_nz(&n.port_description);
                    }
                    if !n.vlan.is_empty() {
                        ui.colored_label(GREEN, format!("VLAN {}", n.vlan));
                    }
                    if !n.mgmt.is_empty() {
                        ui.mono_nz(&n.mgmt);
                    }
                    if !n.platform.is_empty() {
                        ui.weak_nz(&n.platform);
                    }
                });
            }
            ui.add_space(6.0);
            ui.strong("DHCP-серверы");
            if s.dhcp.is_empty() {
                ui.weak("ответов DHCP не было — нажмите «Найти DHCP-серверы» во время захвата");
            } else if s.dhcp.len() > 1 {
                ui.colored_label(RED, format!("в сегменте {} DHCP-сервера — возможен посторонний", s.dhcp.len()));
            }
            for d in &s.dhcp {
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(&d.ip).context_menu(|ui| super::send_menu(ui, &d.ip, nav, Tool::Capture));
                    ui.weak_nz(&d.mac);
                    ui.label(format!("шлюз {} · DNS {} · выдал {}", d.router, d.dns, d.offered));
                });
            }
            ui.add_space(6.0);
            ui.strong("STP");
            ui.label(s.stp_root.as_ref().map(|r| format!("корневой мост: {r}")).unwrap_or("BPDU не замечены".into()));
            ui.add_space(6.0);
            let conflicts = s.arp_conflicts();
            ui.strong(format!("ARP: адресов {}", s.arp.len()));
            if conflicts.is_empty() {
                ui.weak("конфликтов нет");
            }
            for (ip, macs) in conflicts {
                ui.colored_label(RED, format!("{ip} отвечает с разных MAC: {} — возможна подмена ARP", macs.join(", ")));
            }
            ui.add_space(6.0);
            ui.strong(format!("Широковещательные запросы имён ({})", s.name_queries.len()));
            if !s.name_queries.is_empty() {
                ui.weak("LLMNR/NBT-NS можно перехватить и получить хеши паролей — их лучше отключить групповой политикой.");
            }
            for (q, n) in s.name_queries.iter().take(200) {
                ui.label(format!("{q} × {n}"));
            }
            if !s.sni.is_empty() {
                ui.add_space(6.0);
                ui.strong("Сайты (SNI в TLS)");
                let mut v: Vec<_> = s.sni.iter().collect();
                v.sort_by(|a, b| b.1.cmp(a.1));
                for (name, n) in v.into_iter().take(100) {
                    ui.label(format!("{name} × {n}"));
                }
            }
            ui.add_space(6.0);
            ui.strong("Протоколы");
            let mut p: Vec<_> = s.protocols.iter().collect();
            p.sort_by(|a, b| b.1.cmp(a.1));
            ui.label(p.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(" · "));
        });
    }

    fn packets_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.text).desired_width(240.0).hint_text("поиск: адрес, протокол, текст"));
            ui.checkbox(&mut self.follow, "следовать за новыми");
        });
        let q = self.text.to_lowercase();
        let rows: Vec<&Packet> = self
            .packets
            .iter()
            .filter(|p| q.is_empty() || p.src.contains(&q) || p.dst.contains(&q) || p.proto.to_lowercase().contains(&q) || p.info.to_lowercase().contains(&q))
            .collect();
        let mut tb = egui_extras::TableBuilder::new(ui)
            .id_salt("cap_table")
            .striped(true)
            .resizable(true)
            .min_scrolled_height(0.0)
            .stick_to_bottom(self.follow)
            .column(egui_extras::Column::initial(60.0))
            .column(egui_extras::Column::initial(80.0))
            .column(egui_extras::Column::initial(170.0))
            .column(egui_extras::Column::initial(170.0))
            .column(egui_extras::Column::initial(70.0))
            .column(egui_extras::Column::initial(60.0))
            .column(egui_extras::Column::remainder());
        tb = tb.cell_layout(egui::Layout::left_to_right(egui::Align::Center));
        tb.header(20.0, |mut h| {
            for t in ["№", "Время", "Откуда", "Куда", "Протокол", "Байт", "Сведения"] {
                h.col(|ui| {
                    ui.strong(t);
                });
            }
        })
        .body(|body| {
            body.rows(18.0, rows.len(), |mut row| {
                let p = rows[row.index()];
                row.col(|ui| {
                    ui.weak(p.n.to_string());
                });
                row.col(|ui| {
                    ui.monospace(format!("{:.3}", p.t));
                });
                row.col(|ui| {
                    ui.monospace(&p.src);
                });
                row.col(|ui| {
                    ui.monospace(&p.dst);
                });
                row.col(|ui| {
                    ui.label(&p.proto);
                });
                row.col(|ui| {
                    ui.label(p.len.to_string());
                });
                row.col(|ui| {
                    ui.label(&p.info);
                });
            });
        });
    }
}

pub fn render_summary(s: &Summary) -> String {
    let mut o = format!("Пакетов {}, байт {}\n\nСоседи:\n", s.packets, s.bytes);
    for n in &s.neighbors {
        o += &format!("  {} {} порт {} VLAN {} {}\n", n.protocol, n.device, n.port, n.vlan, n.mgmt);
    }
    o += "\nDHCP-серверы:\n";
    for d in &s.dhcp {
        o += &format!("  {} ({}) шлюз {} DNS {}\n", d.ip, d.mac, d.router, d.dns);
    }
    o += &format!("\nSTP: {}\n", s.stp_root.clone().unwrap_or("-".into()));
    o += "\nКонфликты ARP:\n";
    for (ip, m) in s.arp_conflicts() {
        o += &format!("  {ip}: {}\n", m.join(", "));
    }
    o += "\nЗапросы имён:\n";
    for (q, n) in &s.name_queries {
        o += &format!("  {q} × {n}\n");
    }
    o
}
