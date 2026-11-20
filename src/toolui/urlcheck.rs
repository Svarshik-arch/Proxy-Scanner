use egui::RichText;

use super::{AMBER, Env, GREEN, RED};
use crate::auth::AuthMode;
use crate::tools::Task;
use crate::tools::urlcheck::{self, Config, Event, Outcome, Report};

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
    total: usize,
    only_mismatch: bool,
}

const EXAMPLE: &str = "+ https://portal.corp.local/     # должен открываться\n- https://www.torproject.org/     # должен блокироваться\nhttp://example.com/";

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            log: Vec::new(),
            total: 0,
            only_mismatch: false,
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
                Event::Row(r) => self.report.rows.push(*r),
            }
        }
        if finished {
            self.report.rows.sort_by(|a, b| (!a.mismatch, &a.url, &a.proxy).cmp(&(!b.mismatch, &b.url, &b.proxy)));
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "urlcheck", &mut self.cfg);
        let c = &mut self.cfg;
        ui.horizontal_wrapped(|ui| {
            ui.label("Прокси");
            let proxies = env.scan.http_proxies();
            if !proxies.is_empty() && ui.small_button(format!("все найденные ({})", proxies.len())).clicked() {
                c.proxies = proxies.join("\n");
            }
        });
        super::multiline(ui, &mut c.proxies, 2, "10.0.0.10:3128 (пусто — напрямую)");
        ui.horizontal(|ui| {
            ui.label("Адреса: + открываться, − блокироваться");
            if c.urls.trim().is_empty() && ui.small_button("пример").clicked() {
                c.urls = EXAMPLE.into();
            }
        });
        let web = env.scan.web_urls();
        if !web.is_empty()
            && ui
                .small_button(format!("найденные веб-серверы ({})", web.len()))
                .on_hover_text("Добавить адреса веб-серверов из сканирования с ожиданием «+»")
                .clicked()
        {
            for u in web {
                if !c.urls.contains(&u) {
                    if !c.urls.is_empty() && !c.urls.ends_with('\n') {
                        c.urls.push('\n');
                    }
                    c.urls.push_str(&format!("+ {u}\n"));
                }
            }
        }
        ui.add(egui::TextEdit::multiline(&mut c.urls).font(egui::TextStyle::Monospace).desired_rows(6).desired_width(f32::INFINITY).hint_text(EXAMPLE));
        if let Err(e) = urlcheck::parse_urls(&c.urls)
            && !c.urls.trim().is_empty()
        {
            ui.colored_label(RED, e);
        }
        let (start, stop) = super::run_button(ui, self.busy(), "Проверить");
        if start {
            self.report = Report::default();
            self.log.clear();
            self.total = 0;
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| urlcheck::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in &self.log {
            ui.colored_label(RED, l);
        }
        let c = &mut self.cfg;
        super::advanced(ui, "uc_adv", |ui| {
            ui.label("Текст страницы блокировки");
            super::singleline(ui, &mut c.block_marker, "например: Доступ запрещён политикой");
            ui.horizontal(|ui| {
                ui.label("Вход на прокси");
                egui::ComboBox::from_id_salt("uc_auth").selected_text(c.auth.label()).show_ui(ui, |ui| {
                    for m in [AuthMode::Auto, AuthMode::None, AuthMode::Basic, AuthMode::Ntlm, AuthMode::Negotiate] {
                        ui.selectable_value(&mut c.auth, m, m.label());
                    }
                });
            });
            if cfg!(windows) {
                ui.checkbox(&mut c.current_user, "под текущим пользователем Windows");
            }
            egui::Grid::new("uc_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Пользователь", |ui| ui.text_edit_singleline(&mut c.user));
                super::labeled(ui, "Пароль", |ui| ui.add(egui::TextEdit::singleline(&mut c.password).password(true)));
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(500..=60_000)));
                super::labeled(ui, "Параллельно", |ui| ui.add(egui::DragValue::new(&mut c.concurrency).range(1..=256)));
            });
        });
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        if self.report.rows.is_empty() {
            if self.busy() {
                ui.spinner();
            } else {
                ui.weak("Список адресов с ожиданием «+ открываться / − блокироваться» проверяется через каждый прокси. Подходит для проверки политик после изменений.");
            }
            return;
        }
        let m = self.report.mismatches();
        ui.horizontal_wrapped(|ui| {
            if m > 0 {
                ui.colored_label(RED, format!("расхождений с ожиданием: {m}"));
            } else {
                ui.colored_label(GREEN, "всё как ожидалось");
            }
            ui.weak(format!("{} из {}", self.report.rows.len(), self.total.max(self.report.rows.len())));
            ui.checkbox(&mut self.only_mismatch, "только расхождения");
            if self.busy() {
                ui.spinner();
            }
            super::export_buttons(ui, env, "urls", &self.report, urlcheck::render_text);
        });
        let rows: Vec<&urlcheck::Row> = self.report.rows.iter().filter(|r| !self.only_mismatch || r.mismatch).collect();
        super::table(
            ui,
            "uc_table",
            &[("Прокси", 140.0), ("Адрес", 260.0), ("Ожидание", 80.0), ("Результат", 110.0), ("Итог", 100.0), ("Сертификат", 200.0), ("Подробности", 220.0)],
            rows.len(),
            None,
            |i, c, ui| {
                let r = rows[i];
                match c {
                    0 => {
                        ui.monospace(&r.proxy);
                    }
                    1 => {
                        ui.monospace(&r.url).on_hover_text(&r.note);
                    }
                    2 => {
                        ui.label(match r.expect {
                            Some(true) => "открываться",
                            Some(false) => "блокироваться",
                            None => "—",
                        });
                    }
                    3 => {
                        let color = match r.outcome {
                            Outcome::Allowed => GREEN,
                            Outcome::Blocked => AMBER,
                            Outcome::Error => RED,
                        };
                        ui.colored_label(color, r.outcome.label());
                    }
                    4 => {
                        if r.mismatch {
                            ui.label(RichText::new("РАСХОЖДЕНИЕ").strong().color(RED));
                        } else if r.expect.is_some() {
                            ui.colored_label(GREEN, "как ожидалось");
                        }
                    }
                    5 => match (r.inspected, &r.issuer) {
                        (Some(true), Some(i)) => {
                            ui.colored_label(AMBER, format!("подмена: {i}"));
                        }
                        (_, Some(i)) => {
                            ui.weak(i);
                        }
                        _ => {}
                    },
                    _ => {
                        ui.label(&r.detail).on_hover_text(&r.detail);
                    }
                }
            },
            |_, _| {},
        );
    }
}
