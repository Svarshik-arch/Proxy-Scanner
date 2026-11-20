
use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::watch::{self, Config, Event, Report};

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
    next_at: Option<u64>,
    polling: bool,
    filter: String,
    only_alarm: bool,
    tab: u8,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            log: Vec::new(),
            next_at: None,
            polling: false,
            filter: String::new(),
            only_alarm: false,
            tab: 0,
        }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// Тревог среди изменений.
    pub fn alarms(&self) -> usize {
        self.report.changes.iter().filter(|c| c.alarm).count()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let events = t.drain();
        let finished = t.finished();
        let changed = !events.is_empty() || finished;
        for e in events {
            match e {
                Event::Log(l) => self.log.push(l),
                Event::Cycle(n) => {
                    self.polling = true;
                    self.report.cycles = self.report.cycles.max(n);
                }
                Event::Snapshot(s) => {
                    self.polling = false;
                    if self.report.baseline.is_none() {
                        self.report.baseline = Some((*s).clone());
                    }
                    self.report.last = Some(*s);
                }
                Event::Change(c) => self.report.changes.push(*c),
                Event::Next(at) => self.next_at = Some(at),
            }
        }
        if finished {
            self.task = None;
            self.polling = false;
            self.next_at = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "watch", &mut self.cfg);
        let c = &mut self.cfg;
        ui.horizontal(|ui| {
            ui.label("Подсети");
            if let Some(cidr) = &env.local_cidr
                && ui.small_button(format!("моя подсеть {cidr}")).clicked()
            {
                c.targets = cidr.clone();
            }
        });
        super::multiline(ui, &mut c.targets, 2, "10.0.0.0/24, 10.0.1.0/24");
        super::subnet_hint(ui, &c.targets);
        if super::from_scan(ui, &env.scan, &[("сеть сканирования".into(), "Те же сети, что сканировались на вкладке «Прокси»")]).is_some() {
            c.targets = env.scan.targets.clone();
        }
        ui.label("Порты, за которыми следить");
        super::multiline(ui, &mut c.tcp_ports, 2, "22,80,443,445,3389");
        ui.horizontal(|ui| {
            ui.label("Опрос каждые");
            ui.add(egui::DragValue::new(&mut c.interval_min).range(1..=1440).suffix(" мин"));
        });
        ui.checkbox(&mut c.certs, "Следить за сертификатами (HTTPS, LDAPS…)");
        let (start, stop) = super::run_button(ui, self.busy(), "Начать наблюдение");
        if start {
            self.log.clear();
            let cfg = self.cfg.clone();
            let prev = self.report.last.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| watch::run(cfg, prev, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if self.busy() {
            if self.polling {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.weak(format!("опрос №{}…", self.report.cycles));
                });
            } else if let Some(at) = self.next_at {
                let left = at.saturating_sub(crate::session::now_unix());
                ui.weak(format!("следующий опрос через {} мин {} с", left / 60, left % 60));
            }
        }
        for l in self.log.iter().rev().take(5) {
            ui.colored_label(RED, l);
        }
        let a = &mut self.cfg.alerts;
        super::alerts_ui(ui, a, "watch_alerts", "О новых узлах, смене MAC, новых опасных портах и сменах сертификатов.");
        let c = &mut self.cfg;
        super::advanced(ui, "watch_adv", |ui| {
            ui.horizontal(|ui| {
                ui.label("Опросов (0 — до остановки)");
                ui.add(egui::DragValue::new(&mut c.cycles).range(0..=100_000));
            });
            ui.horizontal(|ui| {
                ui.label("Таймаут, мс");
                ui.add(egui::DragValue::new(&mut c.timeout_ms).range(200..=10_000));
            });
        });
        ui.add_space(4.0);
        ui.weak("Пропажа узла или порта засчитывается после двух опросов подряд — короткий сбой связи не даёт ложных тревог. Наблюдение продолжается с последнего опроса из сессии.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let Some(last) = &self.report.last else {
            if self.busy() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.weak("первый опрос — он станет эталоном");
                });
            } else {
                ui.weak("Укажите подсети и запустите наблюдение. Первый опрос — эталон; дальше по расписанию появятся изменения: новые узлы, пропавшие узлы, смена MAC, открытые и закрытые порты, смена сертификатов.");
            }
            return;
        };
        let alarms = self.alarms();
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.tab, 0, format!("Изменения ({})", self.report.changes.len()));
            ui.selectable_value(&mut self.tab, 1, format!("Узлы сейчас ({})", last.hosts.len()));
            ui.separator();
            if alarms > 0 {
                ui.colored_label(RED, format!("тревог: {alarms}"));
            } else {
                ui.colored_label(GREEN, "тревог нет");
            }
            ui.weak(format!("опросов: {} · последний {}", self.report.cycles, crate::session::format_time(last.at)));
            if !self.report.changes.is_empty() && ui.small_button("Очистить список").on_hover_text("Изменения просмотрены; эталоном остаётся последний опрос").clicked() {
                self.report.changes.clear();
            }
        });
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("поиск").desired_width(180.0));
            if self.tab == 0 {
                ui.checkbox(&mut self.only_alarm, "только тревоги");
            }
        });
        let f = self.filter.to_lowercase();
        let nav = &mut *env.nav;
        if self.tab == 0 {
            let rows: Vec<&watch::Change> = self
                .report
                .changes
                .iter()
                .rev()
                .filter(|c| !self.only_alarm || c.alarm)
                .filter(|c| f.is_empty() || format!("{} {} {}", c.host, c.kind.label(), c.detail).to_lowercase().contains(&f))
                .collect();
            if rows.is_empty() {
                ui.weak("Изменений нет.");
                return;
            }
            super::table(
                ui,
                "watch_changes",
                &[("Когда", 140.0), ("", 24.0), ("Узел", 110.0), ("Что", 150.0), ("Подробности", 300.0)],
                rows.len(),
                None,
                |i, col, ui| {
                    let c = rows[i];
                    match col {
                        0 => {
                            ui.weak(crate::session::format_time(c.at));
                        }
                        1 => {
                            if c.alarm {
                                ui.colored_label(RED, "⚠");
                            }
                        }
                        2 => {
                            ui.monospace(c.host.to_string());
                        }
                        3 => {
                            ui.colored_label(if c.alarm { RED } else { AMBER }, c.kind.label());
                        }
                        _ => {
                            ui.label(&c.detail);
                        }
                    }
                },
                |i, ui| super::send_menu(ui, &rows[i].host.to_string(), nav, Tool::Watch),
            );
        } else {
            let rows: Vec<(&std::net::Ipv4Addr, &watch::HostSnap)> = last
                .hosts
                .iter()
                .filter(|(ip, h)| {
                    f.is_empty()
                        || format!("{ip} {} {} {}", h.mac.clone().unwrap_or_default(), h.vendor.clone().unwrap_or_default(), h.name.clone().unwrap_or_default())
                            .to_lowercase()
                            .contains(&f)
                })
                .collect();
            super::table(
                ui,
                "watch_hosts",
                &[("Узел", 110.0), ("Имя", 160.0), ("MAC", 130.0), ("Производитель", 130.0), ("Порты", 200.0)],
                rows.len(),
                None,
                |i, col, ui| {
                    let (ip, h) = rows[i];
                    let text = match col {
                        0 => ip.to_string(),
                        1 => h.name.clone().unwrap_or_default(),
                        2 => h.mac.clone().unwrap_or_default(),
                        3 => h.vendor.clone().unwrap_or_default(),
                        _ => h.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                    };
                    if col == 0 || col == 2 {
                        ui.monospace(text);
                    } else {
                        ui.label(text);
                    }
                },
                |i, ui| super::send_menu(ui, &rows[i].0.to_string(), nav, Tool::Watch),
            );
        }
    }

}
