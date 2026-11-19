use egui::RichText;

use super::{AMBER, Env, RED, Tool};
use crate::tools::Task;
use crate::tools::audit::{self, Config, Event, Issue, Report};
use crate::tools::tlsaudit::Severity;

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
    total: u64,
    done: u64,
    filter: Option<Severity>,
    text: String,
}

fn color(s: Severity, ui: &egui::Ui) -> egui::Color32 {
    match s {
        Severity::High => RED,
        Severity::Medium => AMBER,
        Severity::Low => egui::Color32::from_rgb(100, 150, 220),
        Severity::Info => ui.visuals().weak_text_color(),
    }
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
            filter: None,
            text: String::new(),
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
                Event::Service(s) => self.report.services.push(*s),
                Event::Issue(i) => self.report.issues.push(*i),
            }
        }
        if changed {
            audit::sort(&mut self.report);
        }
        if finished {
            self.task = None;
            self.done = self.total;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "audit", &mut self.cfg);
        let c = &mut self.cfg;
        ui.horizontal(|ui| {
            ui.label("Узлы");
            if let Some(cidr) = &env.local_cidr
                && ui.small_button(format!("моя подсеть {cidr}")).clicked()
            {
                c.targets = cidr.clone();
            }
        });
        super::multiline(ui, &mut c.targets, 2, "10.0.0.0/24, srv01.corp.local");
        ui.add_space(4.0);
        let (start, stop) = super::run_button(ui, self.busy(), "Начать аудит");
        if start {
            self.report = Report::default();
            self.log.clear();
            self.done = 0;
            self.total = 0;
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| audit::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in self.log.iter().rev().take(3) {
            ui.colored_label(RED, l);
        }
        let c = &mut self.cfg;
        super::advanced(ui, "audit_adv", |ui| {
            ui.label("TCP-порты");
            super::multiline(ui, &mut c.tcp_ports, 2, audit::DEFAULT_TCP);
            ui.label("UDP-порты");
            super::singleline(ui, &mut c.udp_ports, "53,123,161,1434");
            ui.horizontal(|ui| {
                ui.label("SNMP community");
                ui.add(egui::TextEdit::singleline(&mut c.snmp_community).desired_width(100.0));
            });
            ui.checkbox(&mut c.ftp_anonymous, "Проверять анонимный вход на FTP");
            ui.checkbox(&mut c.tls_versions, "Проверять SSL 3.0 / TLS 1.0 / 1.1");
            egui::Grid::new("audit_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(300..=30_000)));
                super::labeled(ui, "Параллельно", |ui| ui.add(egui::DragValue::new(&mut c.concurrency).range(1..=4000)));
            });
        });
        ui.add_space(6.0);
        ui.weak("Только проверка конфигурации своих узлов: уязвимости не эксплуатируются, пароли не подбираются.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let r = &self.report;
        ui.horizontal_wrapped(|ui| {
            let all = r.issues.len();
            if ui.selectable_label(self.filter.is_none(), format!("Все ({all})")).clicked() {
                self.filter = None;
            }
            for s in [Severity::High, Severity::Medium, Severity::Low] {
                let n = r.count(s);
                let label = RichText::new(format!("{} ({n})", s.label())).color(color(s, ui));
                if ui.selectable_label(self.filter == Some(s), label).clicked() {
                    self.filter = if self.filter == Some(s) { None } else { Some(s) };
                }
            }
            ui.add(egui::TextEdit::singleline(&mut self.text).desired_width(180.0).hint_text("поиск"));
            ui.weak(format!("сервисов: {}", r.services.len()));
            if !r.services.is_empty() {
                super::export_buttons(ui, env, "audit", r, audit::render_text);
            }
        });
        super::progress(ui, self.done, self.total, self.task.is_some());
        if r.issues.is_empty() {
            if !self.busy() && !r.services.is_empty() {
                ui.colored_label(super::GREEN, "Проблем не найдено.");
            } else if !self.busy() {
                ui.weak("Укажите узлы или подсеть и нажмите «Начать аудит».");
            }
            return;
        }
        let q = self.text.to_lowercase();
        let rows: Vec<&Issue> = r
            .issues
            .iter()
            .filter(|i| self.filter.is_none_or(|f| f == i.severity))
            .filter(|i| {
                q.is_empty()
                    || i.ip.to_string().contains(&q)
                    || i.title.to_lowercase().contains(&q)
                    || i.service.to_lowercase().contains(&q)
            })
            .collect();
        let nav = &mut *env.nav;
        super::table(
            ui,
            "audit_table",
            &[("Важность", 80.0), ("Узел", 150.0), ("Сервис", 90.0), ("Проблема", 340.0), ("Что сделать", 300.0)],
            rows.len(),
            None,
            |i, c, ui| {
                let x = rows[i];
                match c {
                    0 => {
                        ui.colored_label(color(x.severity, ui), x.severity.label());
                    }
                    1 => {
                        ui.monospace(format!("{}:{}/{}", x.ip, x.port, x.proto));
                    }
                    2 => {
                        ui.label(&x.service);
                    }
                    3 => {
                        ui.label(&x.title).on_hover_text(&x.title);
                    }
                    _ => {
                        ui.weak(&x.advice).on_hover_text(&x.advice);
                    }
                }
            },
            |i, ui| super::send_menu(ui, &format!("{}:{}", rows[i].ip, rows[i].port), nav, Tool::Audit),
        );
    }
}
