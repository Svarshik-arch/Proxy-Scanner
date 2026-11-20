use egui::RichText;

use super::{AMBER, Env, GREEN, RED};
use crate::auth::AuthMode;
use crate::tools::Task;
use crate::tools::http::{self, Config, Event, Hop, ProxyMode, Report};
use crate::tools::tls::Versions;

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    current: Vec<Hop>,
    error: Option<String>,
    run: usize,
    hop: usize,
}

const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"];

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            current: Vec::new(),
            error: None,
            run: 0,
            hop: 0,
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
                Event::Log(m) => self.error = Some(m),
                Event::Hop(h) => {
                    self.current.push(*h);
                    self.hop = self.current.len() - 1;
                }
                Event::RunDone(_) => {
                    self.report.runs.push(std::mem::take(&mut self.current));
                    self.run = self.report.runs.len() - 1;
                }
            }
        }
        if finished {
            if !self.current.is_empty() {
                self.report.runs.push(std::mem::take(&mut self.current));
                self.run = self.report.runs.len() - 1;
            }
            self.task = None;
        }
        changed
    }

    fn start(&mut self, env: &Env) {
        self.report = Report::default();
        self.current.clear();
        self.error = None;
        self.run = 0;
        self.hop = 0;
        let cfg = self.cfg.clone();
        self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| http::run(cfg, s, c)));
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "http", &mut self.cfg);
        let c = &mut self.cfg;
        let mut enter = false;
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("http_method").width(76.0).selected_text(&c.method).show_ui(ui, |ui| {
                for m in METHODS {
                    ui.selectable_value(&mut c.method, m.to_string(), *m);
                }
            });
            let r = ui.add(egui::TextEdit::singleline(&mut c.url).desired_width(f32::INFINITY).hint_text("https://portal.corp.local/"));
            enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        });
        let web = env.scan.web_urls();
        let proxies = env.scan.http_proxies();
        if !env.scan.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.weak("Из сканирования:");
                if !web.is_empty()
                    && let Some(u) = super::pick_menu(ui, &format!("сайт ({}) ▾", web.len()), &web)
                {
                    c.url = u;
                }
                if !proxies.is_empty()
                    && let Some(p) = super::pick_menu(ui, &format!("через прокси ({}) ▾", proxies.len()), &proxies)
                {
                    c.proxy = p;
                    c.proxy_mode = ProxyMode::Manual;
                }
            });
        }
        let (start, stop) = super::run_button(ui, self.busy(), "Отправить");
        if (start || (enter && !self.busy())) && !self.cfg.url.trim().is_empty() {
            self.start(env);
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if let Some(e) = &self.error {
            ui.colored_label(RED, e);
        }
        let c = &mut self.cfg;
        egui::CollapsingHeader::new("Заголовки и тело").default_open(!c.headers.is_empty()).show(ui, |ui| {
            super::multiline(ui, &mut c.headers, 3, "Authorization: Bearer …\nX-Forwarded-For: 10.0.0.1");
            if c.method != "GET" && c.method != "HEAD" {
                ui.label("Тело");
                super::multiline(ui, &mut c.body, 3, "{\"key\": \"value\"}");
            }
            ui.label("User-Agent");
            super::singleline(ui, &mut c.user_agent, "");
        });
        egui::CollapsingHeader::new("Прокси").default_open(c.proxy_mode == ProxyMode::Manual).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.radio_value(&mut c.proxy_mode, ProxyMode::Direct, "напрямую");
                ui.radio_value(&mut c.proxy_mode, ProxyMode::Manual, "через прокси");
            });
            if c.proxy_mode == ProxyMode::Manual {
                super::singleline(ui, &mut c.proxy, "10.0.0.10:3128");
                ui.horizontal(|ui| {
                    ui.label("Вход");
                    egui::ComboBox::from_id_salt("http_auth").selected_text(c.proxy_auth.label()).show_ui(ui, |ui| {
                        for m in [AuthMode::Auto, AuthMode::None, AuthMode::Basic, AuthMode::Ntlm, AuthMode::Negotiate] {
                            ui.selectable_value(&mut c.proxy_auth, m, m.label());
                        }
                    });
                });
                if cfg!(windows) {
                    ui.checkbox(&mut c.proxy_current_user, "под текущим пользователем Windows");
                }
                if !(cfg!(windows) && c.proxy_current_user) || !c.proxy_user.is_empty() {
                    egui::Grid::new("http_cred").num_columns(2).show(ui, |ui| {
                        super::labeled(ui, "Пользователь", |ui| ui.text_edit_singleline(&mut c.proxy_user));
                        super::labeled(ui, "Домен", |ui| ui.text_edit_singleline(&mut c.proxy_domain));
                        super::labeled(ui, "Пароль", |ui| ui.add(egui::TextEdit::singleline(&mut c.proxy_pass).password(true)));
                    });
                }
            }
        });
        egui::CollapsingHeader::new("TLS и соединение").show(ui, |ui| {
            ui.checkbox(&mut c.verify_tls, "Прерывать при недоверенном сертификате (как curl без -k)");
            ui.horizontal(|ui| {
                ui.label("Версии TLS");
                egui::ComboBox::from_id_salt("http_tlsv").selected_text(c.tls_versions.label()).show_ui(ui, |ui| {
                    for v in Versions::ALL {
                        ui.selectable_value(&mut c.tls_versions, v, v.label());
                    }
                });
            });
            ui.label("Подмена адреса (как --resolve)");
            super::singleline(ui, &mut c.resolve, "portal.corp.local:10.0.0.5");
            ui.checkbox(&mut c.follow_redirects, "Переходить по перенаправлениям");
            egui::Grid::new("http_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Максимум переходов", |ui| ui.add(egui::DragValue::new(&mut c.max_redirects).range(0..=50)));
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(100..=300_000)));
                super::labeled(ui, "Тело ответа, КБ", |ui| ui.add(egui::DragValue::new(&mut c.body_limit_kb).range(1..=65536)));
                super::labeled(ui, "Повторов", |ui| ui.add(egui::DragValue::new(&mut c.repeat).range(1..=1000)));
            });
        });
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let busy = self.busy();
        let mut run_idx = self.run;
        let mut hop_idx = self.hop;
        let runs: Vec<&Vec<Hop>> = self.report.runs.iter().chain((!self.current.is_empty()).then_some(&self.current)).collect();
        if runs.is_empty() {
            if busy {
                ui.spinner();
            } else {
                ui.weak("Введите URL и нажмите «Отправить».");
            }
            return;
        }
        ui.horizontal_wrapped(|ui| {
            if runs.len() > 1 {
                let totals: Vec<f64> = runs.iter().filter_map(|r| r.last()).map(|h| h.timings.total_ms).collect();
                let ttfb: Vec<f64> = runs.iter().filter_map(|r| r.last()).map(|h| h.timings.ttfb_ms).collect();
                let stat = |v: &[f64]| {
                    let min = v.iter().cloned().fold(f64::INFINITY, f64::min);
                    let max = v.iter().cloned().fold(0.0, f64::max);
                    let avg = v.iter().sum::<f64>() / v.len().max(1) as f64;
                    format!("{min:.1} / {avg:.1} / {max:.1}")
                };
                ui.label(format!("повторов: {} · всего мин/сред/макс: {} мс · TTFB: {} мс", runs.len(), stat(&totals), stat(&ttfb)));
                ui.add(egui::DragValue::new(&mut run_idx).range(0..=runs.len() - 1).prefix("повтор "));
            }
            if busy {
                ui.spinner();
            }
            super::export_buttons(ui, env, "http", &self.report, http::render_text);
        });
        let run = runs[run_idx.min(runs.len() - 1)];
        ui.horizontal_wrapped(|ui| {
            for (i, h) in run.iter().enumerate() {
                let color = match h.status {
                    _ if h.error.is_some() => RED,
                    200..=299 => GREEN,
                    300..=399 => AMBER,
                    _ => RED,
                };
                let label = RichText::new(format!("{} {}", if h.status == 0 { "—".into() } else { h.status.to_string() }, h.url)).color(color);
                if ui.selectable_label(hop_idx == i, label).clicked() {
                    hop_idx = i;
                }
                if i + 1 < run.len() {
                    ui.label("→");
                }
            }
        });
        let Some(h) = run.get(hop_idx.min(run.len().saturating_sub(1))) else {
            self.run = run_idx;
            self.hop = hop_idx;
            return;
        };
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.monospace(&h.address);
                if let Some(a) = &h.proxy_auth {
                    ui.label(format!("прокси: {a}"));
                }
            });
            if let Some(e) = &h.error {
                ui.colored_label(RED, e);
            }
            waterfall(ui, h);
            if let Some(t) = &h.tls {
                egui::CollapsingHeader::new(RichText::new(format!("TLS: {} {}", t.version, t.cipher)).strong())
                    .default_open(true)
                    .show(ui, |ui| {
                        match &t.trust_error {
                            None => ui.colored_label(GREEN, "сертификат доверен системой"),
                            Some(e) => ui.colored_label(RED, format!("сертификат не доверен: {e}")),
                        };
                        for (i, c) in t.chain.iter().enumerate() {
                            ui.horizontal_wrapped(|ui| {
                                ui.monospace(format!("[{i}]"));
                                ui.strong(c.short_subject());
                                ui.weak(format!("← {}", c.short_issuer()));
                                ui.label(format!("{} · {}", c.key, c.signature));
                                let days = RichText::new(format!("до {} ({} дн.)", c.not_after, c.days_left));
                                ui.label(if c.days_left < 0 { days.color(RED) } else if c.days_left < 30 { days.color(AMBER) } else { days });
                            })
                            .response
                            .on_hover_text(format!("SAN: {}\nSHA-256: {}", c.names.join(", "), c.sha256));
                        }
                    });
            }
            egui::CollapsingHeader::new(RichText::new("Запрос").strong()).show(ui, |ui| {
                super::mono_block(ui, "http_req", h.request.trim_end(), 200.0);
            });
            egui::CollapsingHeader::new(RichText::new("Заголовки ответа").strong())
                .default_open(true)
                .show(ui, |ui| super::mono_block(ui, "http_resp", &h.response_head, 260.0));
            egui::CollapsingHeader::new(RichText::new(format!(
                "Тело: {} байт{}",
                h.body_size,
                if h.body_truncated { " (показано начало)" } else { "" }
            ))
            .strong())
            .show(ui, |ui| {
                let text = h.body_text();
                if ui.small_button("Копировать").clicked() {
                    ui.ctx().copy_text(text.clone());
                }
                let preview: String = text.chars().take(64 * 1024).collect();
                super::mono_block(ui, "http_body", &preview, 400.0);
            });
        });
        self.run = run_idx;
        self.hop = hop_idx;
    }
}

/// Полосы времени по фазам (как в инструментах разработчика браузера).
fn waterfall(ui: &mut egui::Ui, h: &Hop) {
    let t = &h.timings;
    let phases = [
        ("DNS", t.dns_ms, egui::Color32::from_rgb(90, 160, 220)),
        ("TCP", t.connect_ms, egui::Color32::from_rgb(230, 150, 60)),
        ("прокси", t.proxy_ms.unwrap_or(0.0), egui::Color32::from_rgb(170, 110, 210)),
        ("TLS", t.tls_ms.unwrap_or(0.0), egui::Color32::from_rgb(200, 90, 150)),
        ("ожидание (TTFB)", t.ttfb_ms, egui::Color32::from_rgb(80, 180, 120)),
    ];
    let rest = (t.total_ms - phases.iter().map(|p| p.1).sum::<f64>()).max(0.0);
    let total = t.total_ms.max(0.001);
    let width = ui.available_width().clamp(200.0, 700.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 16.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let mut x = rect.left();
    for (_, ms, color) in phases.iter().chain(std::iter::once(&("загрузка", rest, egui::Color32::GRAY))) {
        let w = (*ms / total) as f32 * rect.width();
        if w > 0.0 {
            painter.rect_filled(egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(w.max(1.0), rect.height())), 2.0, *color);
        }
        x += w;
    }
    ui.horizontal_wrapped(|ui| {
        for (name, ms, color) in phases {
            if ms > 0.0 {
                ui.colored_label(color, format!("■ {name} {ms:.1}"));
            }
        }
        ui.label(format!("загрузка {rest:.1} · всего {:.1} мс", t.total_ms));
    });
}
