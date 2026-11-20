use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::services::{self, Config, Event, Report};

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
                Event::Found(s) => {
                    self.report.services.push(*s);
                }
            }
        }
        if changed {
            self.report.services.sort_by_key(|s| (s.ip, s.proto.clone(), s.port));
        }
        if finished {
            self.task = None;
            self.done = self.total;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "services", &mut self.cfg);
        let c = &mut self.cfg;
        ui.label("Узлы");
        super::multiline(ui, &mut c.targets, 2, "10.0.0.0/24, srv01.corp.local");
        let scan = &env.scan;
        match super::from_scan(
            ui,
            scan,
            &[
                (format!("найденные узлы и порты ({})", scan.hosts().len()), "Узлы и открытые порты, которые нашло сканирование"),
                ("вся сеть сканирования".into(), "Те же сети и диапазоны, что сканировались на вкладке «Прокси»"),
            ],
        ) {
            Some(0) => {
                c.targets = scan.hosts_text();
                c.tcp_ports = scan.ports_text();
            }
            Some(1) => c.targets = scan.targets.clone(),
            _ => {}
        }
        ui.label("TCP-порты");
        super::multiline(ui, &mut c.tcp_ports, 2, "22,80,443,445,3389");
        ui.label("UDP-порты");
        super::singleline(ui, &mut c.udp_ports, "53,123,137,161,1900");
        super::advanced(ui, "svc_adv", |ui| {
            ui.horizontal(|ui| {
                ui.label("SNMP community");
                ui.add(egui::TextEdit::singleline(&mut c.snmp_community).desired_width(120.0).hint_text("пусто — не опрашивать"));
            });
            egui::Grid::new("svc_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Подключение, мс", |ui| ui.add(egui::DragValue::new(&mut c.connect_timeout_ms).range(100..=30_000)));
                super::labeled(ui, "Ожидание ответа, мс", |ui| ui.add(egui::DragValue::new(&mut c.read_timeout_ms).range(100..=30_000)));
                super::labeled(ui, "Параллельно", |ui| ui.add(egui::DragValue::new(&mut c.concurrency).range(1..=4000)));
            });
            ui.checkbox(&mut c.active_probes, "Активные пробы (HTTP, TLS, SMB, RDP, СУБД)");
            ui.checkbox(&mut c.show_udp_silent, "Показывать молчащие UDP-порты (open|filtered)");
        });
        let checks = crate::tools::HostList::parse(&c.targets).ok().map(|h| {
            let n = |s: &str| crate::targets::parse_ports(s).map(|p| p.len() as u64).unwrap_or(0);
            h.len() * (n(&c.tcp_ports) + n(&c.udp_ports))
        });
        if let Some(n) = checks {
            ui.weak(format!("{n} проверок"));
        }
        ui.add_space(6.0);
        let (start, stop) = super::run_button(ui, self.busy(), "Сканировать");
        if start {
            self.report = Report::default();
            self.log.clear();
            self.selected = None;
            self.done = 0;
            self.total = 0;
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| services::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in self.log.iter().rev().take(4) {
            ui.colored_label(RED, l);
        }
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui| {
            ui.label("Поиск");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(220.0).hint_text("адрес, сервис, версия"));
            ui.label(format!("сервисов: {}", self.report.services.len()));
            if !self.report.services.is_empty() {
                super::export_buttons(ui, env, "services", &self.report, services::render_text);
            }
        });
        super::progress(ui, self.done, self.total, self.busy());
        let f = self.filter.to_lowercase();
        let rows: Vec<&services::Service> = self
            .report
            .services
            .iter()
            .filter(|s| {
                f.is_empty()
                    || format!("{}:{}", s.ip, s.port).contains(&f)
                    || s.service.to_lowercase().contains(&f)
                    || s.version.to_lowercase().contains(&f)
                    || s.banner.to_lowercase().contains(&f)
                    || s.details.iter().any(|d| d.to_lowercase().contains(&f))
            })
            .collect();
        let nav = &mut *env.nav;
        let clicked = super::table(
            ui,
            "svc_table",
            &[
                ("Адрес", 110.0),
                ("Порт", 70.0),
                ("Сервис", 100.0),
                ("Версия", 220.0),
                ("TLS", 160.0),
                ("Подробности", 260.0),
                ("Баннер", 200.0),
            ],
            rows.len(),
            self.selected,
            |i, c, ui| {
                let s = rows[i];
                match c {
                    0 => {
                        ui.monospace(s.ip.to_string());
                    }
                    1 => {
                        ui.monospace(format!("{}/{}", s.port, s.proto));
                    }
                    2 => {
                        if s.state == "open" {
                            ui.strong(&s.service);
                        } else {
                            ui.weak(format!("{}?", s.service));
                        }
                    }
                    3 => {
                        ui.label(&s.version);
                    }
                    4 => {
                        if let Some(t) = &s.tls {
                            let color = if !t.trusted || t.days_left < 0 { RED } else if t.days_left < 30 { AMBER } else { GREEN };
                            ui.colored_label(color, format!("{} {} ({} дн.)", t.version, t.subject, t.days_left));
                        }
                    }
                    5 => {
                        let risky = s.details.iter().any(|d| {
                            d.contains("SMBv1") || d.contains("без NLA") || d.contains("без пароля") || d.contains("не обязательна") || d.contains("community") || d.contains("5 минут")
                        });
                        let text = s.details.join("; ");
                        if risky {
                            ui.colored_label(AMBER, text);
                        } else {
                            ui.label(text);
                        }
                    }
                    _ => {
                        ui.weak(&s.banner);
                    }
                }
            },
            |i, ui| {
                let s = rows[i];
                super::send_menu(ui, &format!("{}:{}", s.ip, s.port), nav, Tool::Services);
            },
        );
        if let Some(i) = clicked {
            self.selected = if self.selected == Some(i) { None } else { Some(i) };
        }
        if let Some(s) = self.selected.and_then(|i| rows.get(i)) {
            ui.separator();
            ui.strong(format!("{}:{}/{} — {} {}", s.ip, s.port, s.proto, s.service, s.version));
            for d in &s.details {
                ui.label(format!("• {d}"));
            }
            if let Some(t) = &s.tls {
                ui.label(format!(
                    "TLS: {} {} · {} ← {} · {} дн. · {}",
                    t.version,
                    t.cipher,
                    t.subject,
                    t.issuer,
                    t.days_left,
                    if t.trusted { "доверен" } else { "не доверен" }
                ));
            }
            if !s.banner.is_empty() {
                super::mono_block(ui, "svc_banner", &s.banner, 120.0);
            }
        }
    }
}
