use super::{Env, RED, Tool};
use crate::tools::Task;
use crate::tools::discovery::{self, Config, Event, Report};

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
    total: u64,
    done: u64,
    filter: String,
    selected: Option<usize>,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            log: Vec::new(),
            total: 0,
            done: 0,
            filter: String::new(),
            selected: None,
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
                Event::Log(m) => self.log.push(m),
                Event::Total(n) => self.total = n,
                Event::Progress(n) => self.done = n,
                Event::Host(h) => self.report.hosts.push(*h),
            }
        }
        if finished {
            self.task = None;
            self.done = self.total;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "discovery", &mut self.cfg);
        let c = &mut self.cfg;
        ui.horizontal(|ui| {
            ui.label("Адреса");
            if let Some(cidr) = &env.local_cidr
                && ui.small_button(format!("моя подсеть {cidr}")).clicked()
            {
                c.targets = cidr.clone();
            }
        });
        super::multiline(ui, &mut c.targets, 2, "192.168.1.0/24, 10.0.0.1-10.0.0.50");
        match crate::targets::parse_targets(&c.targets) {
            Ok(t) if t.total_hosts() > 65536 => {
                ui.colored_label(RED, "больше /16");
            }
            Ok(t) if !t.is_empty() => {
                ui.weak(format!("{} адресов", t.total_hosts()));
            }
            Err(e) if !c.targets.trim().is_empty() => {
                ui.colored_label(RED, e);
            }
            _ => {}
        }
        super::advanced(ui, "disc_adv", |ui| {
            ui.label("Методы");
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut c.icmp, "ICMP");
                ui.checkbox(&mut c.arp, "ARP");
                ui.checkbox(&mut c.netbios, "NetBIOS");
                ui.checkbox(&mut c.mdns, "mDNS");
                ui.checkbox(&mut c.ssdp, "SSDP");
                ui.checkbox(&mut c.reverse_dns, "обратный DNS");
            });
            ui.label("TCP-порты (открыт или RST — узел жив)");
            super::singleline(ui, &mut c.tcp_ports, "22,80,135,139,443,445,3389");
            egui::Grid::new("disc_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(100..=10_000)));
                super::labeled(ui, "Параллельно узлов", |ui| ui.add(egui::DragValue::new(&mut c.concurrency).range(1..=1024)));
                super::labeled(ui, "Повторов ICMP", |ui| ui.add(egui::DragValue::new(&mut c.retries).range(0..=5)));
            });
            ui.checkbox(&mut c.show_dead, "Показывать узлы без ответа");
        });
        ui.add_space(6.0);
        let (start, stop) = super::run_button(ui, self.busy(), "Искать узлы");
        if start {
            self.report = Report::default();
            self.log.clear();
            self.selected = None;
            self.done = 0;
            self.total = 0;
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| discovery::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in self.log.iter().rev().take(4) {
            ui.weak(l);
        }
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui| {
            ui.label("Поиск");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(220.0).hint_text("адрес, имя, производитель, ОС"));
            let alive = self.report.hosts.iter().filter(|h| h.alive).count();
            ui.label(format!("найдено: {alive}"));
            if !self.report.hosts.is_empty() {
                super::export_buttons(ui, env, "hosts", &self.report, discovery::render_text);
                if ui.button("Все → Сервисы").on_hover_text("Передать найденные адреса в сканер сервисов").clicked() {
                    let list: Vec<String> = self.report.hosts.iter().filter(|h| h.alive).map(|h| h.ip.to_string()).collect();
                    *env.nav = Some(super::Nav::Send(Tool::Services, list.join(", ")));
                }
            }
        });
        super::progress(ui, self.done, self.total, self.busy());
        let f = self.filter.to_lowercase();
        let rows: Vec<&discovery::Host> = self
            .report
            .hosts
            .iter()
            .filter(|h| {
                f.is_empty()
                    || h.ip.to_string().contains(&f)
                    || h.best_name().to_lowercase().contains(&f)
                    || h.vendor.as_deref().unwrap_or("").to_lowercase().contains(&f)
                    || h.os_guess.as_deref().unwrap_or("").to_lowercase().contains(&f)
                    || h.mac.as_deref().unwrap_or("").to_lowercase().contains(&f)
            })
            .collect();
        let nav = &mut *env.nav;
        let clicked = super::table(
            ui,
            "disc_table",
            &[
                ("Адрес", 110.0),
                ("MAC", 130.0),
                ("Производитель", 160.0),
                ("Имя", 200.0),
                ("ОС", 150.0),
                ("мс", 50.0),
                ("TTL", 36.0),
                ("Открытые порты", 120.0),
                ("Признаки", 160.0),
            ],
            rows.len(),
            self.selected,
            |i, c, ui| {
                let h = rows[i];
                let t = match c {
                    0 => h.ip.to_string(),
                    1 => h.mac.clone().unwrap_or_default(),
                    2 => h.vendor.clone().unwrap_or_default(),
                    3 => h.best_name(),
                    4 => h.os_guess.clone().unwrap_or_default(),
                    5 => super::opt_ms(h.rtt_ms),
                    6 => h.ttl.map(|t| t.to_string()).unwrap_or_default(),
                    7 => h.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                    _ => h.evidence.join(", "),
                };
                if h.alive {
                    ui.label(t);
                } else {
                    ui.weak(t);
                }
            },
            |i, ui| super::send_menu(ui, &rows[i].ip.to_string(), nav, Tool::Discovery),
        );
        if let Some(i) = clicked {
            self.selected = if self.selected == Some(i) { None } else { Some(i) };
        }
        if let Some(h) = self.selected.and_then(|i| rows.get(i)) {
            ui.separator();
            egui::Grid::new("disc_detail").num_columns(2).show(ui, |ui| {
                let mut row = |k: &str, v: String| {
                    if !v.is_empty() {
                        ui.weak(k);
                        ui.label(v);
                        ui.end_row();
                    }
                };
                row("DNS", h.dns_name.clone().unwrap_or_default());
                if let Some(nb) = &h.netbios {
                    row("NetBIOS", nb.name.clone().unwrap_or_default());
                    row("Группа/домен", nb.group.clone().unwrap_or_default());
                    row("Пользователь", nb.user.clone().unwrap_or_default());
                    row("Роли", nb.roles.join(", "));
                }
                row("mDNS", h.mdns_name.clone().unwrap_or_default());
                row("SSDP/UPnP", h.ssdp.clone().unwrap_or_default());
            });
        }
    }
}
