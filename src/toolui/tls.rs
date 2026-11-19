use egui::RichText;

use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::tlsaudit::{self, Config, Event, Report, Severity, Strength};

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
    total: usize,
    selected: Option<usize>,
}

fn grade_color(g: &str) -> egui::Color32 {
    match g {
        "A" | "A-" => GREEN,
        "B" => AMBER,
        _ => RED,
    }
}

fn strength_color(s: Strength) -> egui::Color32 {
    match s {
        Strength::Strong => GREEN,
        Strength::Ok => egui::Color32::from_rgb(140, 170, 90),
        Strength::Weak => AMBER,
        Strength::Insecure => RED,
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
                Event::Target(t) => self.report.targets.push(*t),
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "tls", &mut self.cfg);
        let c = &mut self.cfg;
        ui.label("Узлы");
        super::multiline(ui, &mut c.targets, 2, "portal.corp.local, 10.0.0.0/24");
        ui.label("Порты");
        super::singleline(ui, &mut c.ports, "443,8443,636");
        ui.label("SNI (необязательно)");
        super::singleline(ui, &mut c.sni, "имя для IP-адресов");
        ui.checkbox(&mut c.versions, "Проверять версии протокола (SSL 3.0 … TLS 1.3)");
        ui.add_enabled(c.versions, egui::Checkbox::new(&mut c.ciphers, "Перебирать наборы шифров"));
        egui::Grid::new("tls_grid").num_columns(2).show(ui, |ui| {
            super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(300..=60_000)));
            super::labeled(ui, "Параллельно узлов", |ui| ui.add(egui::DragValue::new(&mut c.concurrency).range(1..=256)));
            super::labeled(ui, "Предупреждать за, дней", |ui| ui.add(egui::DragValue::new(&mut c.expiry_warn_days).range(0..=365)));
        });
        ui.add_space(6.0);
        let (start, stop) = super::run_button(ui, self.busy(), "Проверить");
        if start {
            self.report = Report::default();
            self.log.clear();
            self.selected = None;
            self.total = 0;
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| tlsaudit::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in &self.log {
            ui.colored_label(RED, l);
        }
        ui.weak(format!("Корневых сертификатов в системе: {}", crate::tools::tls::roots().len()));
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui| {
            if self.total > 0 {
                ui.label(format!("{} / {}", self.report.targets.len(), self.total));
            }
            if self.busy() {
                ui.spinner();
            }
            if !self.report.targets.is_empty() {
                super::export_buttons(ui, env, "tls", &self.report, tlsaudit::render_text);
            }
        });
        let rows = &self.report.targets;
        let nav = &mut *env.nav;
        let clicked = super::table(
            ui,
            "tls_table",
            &[
                ("Узел", 200.0),
                ("Оценка", 54.0),
                ("Версии", 150.0),
                ("Сертификат", 200.0),
                ("Издатель", 200.0),
                ("Дней", 50.0),
                ("Замечания", 300.0),
            ],
            rows.len(),
            self.selected,
            |i, c, ui| {
                let t = &rows[i];
                let leaf = t.chain.first();
                match c {
                    0 => {
                        ui.monospace(format!("{}:{}", t.host, t.port));
                    }
                    1 => {
                        ui.label(RichText::new(&t.grade).strong().color(grade_color(&t.grade)));
                    }
                    2 => {
                        let v: Vec<String> = t
                            .versions
                            .iter()
                            .filter(|v| v.supported)
                            .map(|v| v.version.replace("TLS ", "").replace("SSL ", "SSL"))
                            .collect();
                        ui.label(v.join(" "));
                    }
                    3 => {
                        ui.label(leaf.map(|l| l.short_subject()).unwrap_or_default());
                    }
                    4 => {
                        ui.label(leaf.map(|l| l.short_issuer()).unwrap_or_default());
                    }
                    5 => {
                        if let Some(l) = leaf {
                            let color = if l.days_left < 0 { RED } else if l.days_left < self.cfg.expiry_warn_days { AMBER } else { GREEN };
                            ui.colored_label(color, l.days_left.to_string());
                        }
                    }
                    _ => {
                        if let Some(e) = &t.error {
                            ui.colored_label(RED, e);
                        } else {
                            ui.label(t.findings.iter().map(|f| f.text.clone()).collect::<Vec<_>>().join("; "));
                        }
                    }
                }
            },
            |i, ui| super::send_menu(ui, &format!("{}:{}", rows[i].host, rows[i].port), nav, Tool::Tls),
        );
        if let Some(i) = clicked {
            self.selected = if self.selected == Some(i) { None } else { Some(i) };
        }
        let Some(t) = self.selected.and_then(|i| rows.get(i)) else { return };
        ui.separator();
        egui::ScrollArea::vertical().id_salt("tls_detail").auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading(format!("{}:{}", t.host, t.port));
                ui.label(RichText::new(&t.grade).heading().color(grade_color(&t.grade)));
                ui.monospace(&t.address);
                if let Some(s) = &t.sni {
                    ui.weak(format!("SNI {s}"));
                }
                if !t.negotiated.is_empty() {
                    ui.weak(&t.negotiated);
                }
            });
            for f in &t.findings {
                let color = match f.severity {
                    Severity::High => RED,
                    Severity::Medium => AMBER,
                    _ => ui.visuals().text_color(),
                };
                ui.colored_label(color, format!("[{}] {}", f.severity.label(), f.text));
            }
            ui.add_space(4.0);
            for v in &t.versions {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&v.version).strong().monospace());
                    if v.supported {
                        let bad = v.version == "SSL 3.0" || v.version == "TLS 1.0" || v.version == "TLS 1.1";
                        ui.colored_label(if bad { RED } else { GREEN }, "включён");
                    } else {
                        ui.weak(format!("нет{}", v.note.as_ref().map(|n| format!(" ({n})")).unwrap_or_default()));
                    }
                });
                for (name, s) in &v.ciphers {
                    ui.horizontal(|ui| {
                        ui.add_space(16.0);
                        ui.monospace(name);
                        ui.colored_label(strength_color(*s), s.label());
                    });
                }
            }
            ui.add_space(4.0);
            ui.strong("Цепочка сертификатов");
            match &t.trust_error {
                None if !t.chain.is_empty() => {
                    ui.colored_label(GREEN, "доверена системой");
                }
                Some(e) => {
                    ui.colored_label(RED, e);
                }
                _ => {}
            }
            for (i, c) in t.chain.iter().enumerate() {
                egui::CollapsingHeader::new(format!("[{i}] {} ← {}", c.short_subject(), c.short_issuer()))
                    .id_salt(("tls_cert", i))
                    .show(ui, |ui| {
                        egui::Grid::new(("tls_cert_g", i)).num_columns(2).show(ui, |ui| {
                            let mut row = |k: &str, v: String| {
                                ui.weak(k);
                                ui.add(egui::Label::new(RichText::new(v).monospace()).wrap());
                                ui.end_row();
                            };
                            row("Субъект", c.subject.clone());
                            row("Издатель", c.issuer.clone());
                            row("Действует", format!("{} — {} ({} дн.)", c.not_before, c.not_after, c.days_left));
                            row("Ключ", c.key.clone());
                            row("Подпись", c.signature.clone());
                            row("Имена", c.names.join(", "));
                            row("Серийный", c.serial.clone());
                            row("SHA-256", c.sha256.clone());
                        });
                    });
            }
        });
    }
}
