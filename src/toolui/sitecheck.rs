use egui::RichText;

use super::{AMBER, Env, GREEN, RED};
use crate::tools::Task;
use crate::tools::sitecheck::{self, Config, Event, Report, Status};

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            log: Vec::new(),
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
                Event::Step(s) => self.report.steps.push(*s),
                Event::Verdict(v, ok) => {
                    self.report.verdict = v;
                    self.report.ok = ok;
                }
                Event::Log(l) => self.log.push(l),
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    pub fn start(&mut self, env: &Env) {
        self.report = Report {
            url: self.cfg.url.trim().to_string(),
            ..Default::default()
        };
        self.log.clear();
        let cfg = self.cfg.clone();
        self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| sitecheck::run(cfg, s, c)));
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "sitecheck", &mut self.cfg);
        let c = &mut self.cfg;
        ui.label("Адрес, который не открывается");
        let r = ui.add(egui::TextEdit::singleline(&mut c.url).desired_width(f32::INFINITY).hint_text("portal.corp.local или https://site/путь"));
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        let web = env.scan.web_urls();
        if !web.is_empty() {
            ui.horizontal(|ui| {
                ui.weak("Из сканирования:");
                if let Some(u) = super::pick_menu(ui, &format!("сайт ({}) ▾", web.len()), &web) {
                    c.url = u;
                }
            });
        }
        ui.checkbox(&mut c.system_proxy, "Через системный прокси и PAC этой машины");
        ui.horizontal_wrapped(|ui| {
            ui.label("Ещё через прокси");
            let proxies = env.scan.http_proxies();
            if !proxies.is_empty() && ui.small_button(format!("найденные ({})", proxies.len())).clicked() {
                c.proxies = proxies.join("\n");
            }
        });
        super::multiline(ui, &mut c.proxies, 2, "10.0.0.10:3128 (необязательно)");
        let (start, stop) = super::run_button(ui, self.busy(), "Проверить");
        if (start || (enter && !self.busy())) && !self.cfg.url.trim().is_empty() {
            self.start(env);
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in &self.log {
            ui.colored_label(RED, l);
        }
        let c = &mut self.cfg;
        super::advanced(ui, "sc_adv", |ui| {
            ui.label("Внешние DNS для сравнения");
            super::singleline(ui, &mut c.external_dns, "8.8.8.8, 77.88.8.8 (пусто — не сравнивать)");
            ui.horizontal(|ui| {
                ui.label("Таймаут, мс");
                ui.add(egui::DragValue::new(&mut c.timeout_ms).range(500..=60_000));
            });
        });
        ui.add_space(4.0);
        ui.weak("Цепочка: DNS (системный и внешний) → TCP → TLS → HTTP напрямую → системный прокси/PAC → каждый указанный прокси. В конце — что мешает.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, _env: &mut Env) {
        if self.report.steps.is_empty() && self.report.verdict.is_empty() {
            if self.busy() {
                ui.spinner();
            } else {
                ui.weak("Введите адрес и нажмите «Проверить» — программа пройдёт весь путь запроса и скажет, где он обрывается.");
            }
            return;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if !self.report.verdict.is_empty() {
                let (color, head) = if self.report.ok { (GREEN, "Сайт открывается") } else { (RED, "Что мешает") };
                egui::Frame::group(ui.style()).stroke(egui::Stroke::new(1.5, color)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(head).strong().color(color));
                    for (i, l) in self.report.verdict.iter().enumerate() {
                        let t = RichText::new(l);
                        ui.label(if i == 0 { t.strong().size(15.0) } else { t });
                    }
                });
                ui.add_space(6.0);
            } else if self.busy() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.weak("проверка…");
                });
            }
            ui.strong(&self.report.url);
            let fixed = |ui: &mut egui::Ui, w: f32, add: &mut dyn FnMut(&mut egui::Ui)| {
                ui.allocate_ui_with_layout(egui::vec2(w, 18.0), egui::Layout::left_to_right(egui::Align::Min), |ui| {
                    ui.set_min_width(w);
                    add(ui);
                });
            };
            for (i, s) in self.report.steps.iter().enumerate() {
                let color = match s.status {
                    Status::Ok => GREEN,
                    Status::Warn => AMBER,
                    Status::Fail => RED,
                    Status::Skip => ui.visuals().weak_text_color(),
                };
                let row = |ui: &mut egui::Ui| {
                    ui.horizontal_top(|ui| {
                        fixed(ui, 18.0, &mut |ui| {
                            ui.colored_label(color, s.status.mark());
                        });
                        fixed(ui, 56.0, &mut |ui| {
                            ui.weak(&s.stage);
                        });
                        fixed(ui, 250.0, &mut |ui| {
                            ui.add(egui::Label::new(&s.title).truncate());
                        });
                        fixed(ui, 60.0, &mut |ui| {
                            ui.weak(s.ms.map(|m| format!("{m:.0} мс")).unwrap_or_default());
                        });
                        ui.add(egui::Label::new(RichText::new(&s.detail).color(color)).wrap());
                    });
                };
                if i % 2 == 0 {
                    egui::Frame::new().fill(ui.visuals().faint_bg_color).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        row(ui)
                    });
                } else {
                    row(ui);
                }
            }
        });
    }

}
