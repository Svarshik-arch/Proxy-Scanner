use egui::RichText;

use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::matrix::{self, Config, Event, Report, State, Verdict};

pub struct Panel {
    pub cfg: Config,
    /// Результаты: первая — с этой машины, остальные — импортированные.
    pub reports: Vec<Report>,
    task: Option<Task<Event>>,
    log: Vec<String>,
    total: usize,
    only_mismatch: bool,
    listen_ports: String,
    listener: Option<(tokio_util::sync::CancellationToken, Vec<u16>, Vec<String>)>,
    listener_task: Option<Task<(Vec<u16>, Vec<String>)>>,
}

const EXAMPLE: &str = "10.0.0.5:443 open        # портал\n10.0.0.20:1433 closed     # БД закрыта из этого сегмента\n10.0.1.0/29 22,3389 closed\nfileserver:445 open";

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            reports: Vec::new(),
            task: None,
            log: Vec::new(),
            total: 0,
            only_mismatch: false,
            listen_ports: "443,1433,3389,8080".into(),
            listener: None,
            listener_task: None,
        }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        if let Some(t) = &self.listener_task {
            for (ok, errs) in t.drain() {
                if let Some(l) = &mut self.listener {
                    l.1 = ok;
                    l.2 = errs;
                }
                changed = true;
            }
            if t.finished() {
                self.listener_task = None;
            }
        }
        let Some(t) = &self.task else { return changed };
        let events = t.drain();
        let finished = t.finished();
        changed |= !events.is_empty() || finished;
        for e in events {
            match e {
                Event::Log(m) => self.log.push(m),
                Event::Total(n) => self.total = n,
                Event::Entry(x) => {
                    if self.reports.is_empty() {
                        self.reports.push(matrix::new_report());
                    }
                    self.reports[0].entries.push(*x);
                }
            }
        }
        if finished {
            if let Some(r) = self.reports.first_mut() {
                matrix::sort(r);
            }
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "matrix", &mut self.cfg);
        ui.horizontal(|ui| {
            ui.label("Правила: узел:порт ожидание");
            if self.cfg.rules.trim().is_empty() && ui.small_button("пример").clicked() {
                self.cfg.rules = EXAMPLE.into();
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.cfg.rules)
                .font(egui::TextStyle::Monospace)
                .desired_rows(6)
                .desired_width(f32::INFINITY)
                .hint_text(EXAMPLE),
        );
        if let Err(e) = matrix::parse(&self.cfg.rules)
            && !self.cfg.rules.trim().is_empty()
        {
            ui.colored_label(RED, e);
        }
        let (start, stop) = super::run_button(ui, self.busy(), "Проверить отсюда");
        if start {
            self.log.clear();
            self.total = 0;
            // Результаты этой машины заменяются, импортированные остаются.
            let me = crate::session::computer_name();
            self.reports.retain(|r| r.source != me);
            self.reports.insert(0, matrix::new_report());
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| matrix::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in &self.log {
            ui.colored_label(RED, l);
        }
        ui.add_space(6.0);
        ui.separator();
        ui.strong("Проверка с других машин");
        ui.weak("Запустите на другой машине ту же проверку и сохраните JSON (Экспорт), затем импортируйте его сюда.");
        if ui.button("Импорт результатов…").clicked()
            && let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file()
        {
            let res = std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|t| {
                    serde_json::from_str::<Vec<Report>>(&t)
                        .or_else(|_| serde_json::from_str::<Report>(&t).map(|r| vec![r]))
                        .map_err(|e| format!("не результат матрицы: {e}"))
                });
            match res {
                Ok(list) => {
                    for r in list {
                        self.reports.retain(|x| x.source != r.source);
                        self.reports.push(r);
                    }
                    *env.message = Some("результаты импортированы".into());
                }
                Err(e) => *env.message = Some(e),
            }
        }
        ui.add_space(6.0);
        ui.separator();
        ui.strong("Слушатель на этой машине");
        ui.weak("Чтобы проверить доступ сюда с другой машины: занятые порты отвечают меткой Proxy Scanner.");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.listen_ports).desired_width(160.0));
            if self.listener.is_some() {
                if ui.button("■ Остановить").clicked()
                    && let Some((c, _, _)) = self.listener.take()
                {
                    c.cancel();
                }
            } else if ui.button("▶ Слушать").clicked() {
                match crate::targets::parse_ports(&self.listen_ports) {
                    Ok(ports) => {
                        let cancel = tokio_util::sync::CancellationToken::new();
                        let c2 = cancel.clone();
                        self.listener = Some((cancel, Vec::new(), Vec::new()));
                        self.listener_task = Some(Task::spawn(env.rt, &env.ctx, move |s, _| async move {
                            s.send(crate::egress::start_listener(&ports, c2).await);
                        }));
                    }
                    Err(e) => *env.message = Some(e),
                }
            }
        });
        if let Some((_, ok, errs)) = &self.listener {
            if !ok.is_empty() {
                ui.colored_label(GREEN, format!("слушаю: {}", ok.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
            }
            for e in errs {
                ui.colored_label(AMBER, e);
            }
        }
        let c = &mut self.cfg;
        super::advanced(ui, "mx_adv", |ui| {
            egui::Grid::new("mx_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(100..=30_000)));
                super::labeled(ui, "Повторов при «нет ответа»", |ui| ui.add(egui::DragValue::new(&mut c.retries).range(0..=5)));
                super::labeled(ui, "Параллельно", |ui| ui.add(egui::DragValue::new(&mut c.concurrency).range(1..=2000)));
            });
        });
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        if self.reports.iter().all(|r| r.entries.is_empty()) {
            if self.busy() {
                ui.spinner();
            } else {
                ui.weak("Впишите правила «узел:порт open|closed» и нажмите «Проверить отсюда». Расхождения с ожиданием будут выделены.");
            }
            return;
        }
        let mismatches: usize = self.reports.iter().map(|r| r.mismatches()).sum();
        let total: usize = self.reports.iter().map(|r| r.entries.len()).sum();
        ui.horizontal_wrapped(|ui| {
            if mismatches > 0 {
                ui.colored_label(RED, format!("расхождений: {mismatches}"));
            } else {
                ui.colored_label(GREEN, "расхождений нет");
            }
            ui.weak(format!("проверок: {total}{}", if self.total > 0 && self.busy() { format!(" из {}", self.total) } else { String::new() }));
            ui.checkbox(&mut self.only_mismatch, "только расхождения");
            if self.busy() {
                ui.spinner();
            }
            let reports = self.reports.clone();
            super::export_buttons(ui, env, "matrix", &reports, |r: &Vec<Report>| matrix::render_text(r));
        });
        let rows: Vec<(&str, &matrix::Entry)> = self
            .reports
            .iter()
            .flat_map(|r| r.entries.iter().map(move |e| (r.source.as_str(), e)))
            .filter(|(_, e)| !self.only_mismatch || e.verdict == Verdict::Mismatch)
            .collect();
        let nav = &mut *env.nav;
        super::table(
            ui,
            "mx_table",
            &[
                ("Откуда", 110.0),
                ("Куда", 200.0),
                ("Порт", 50.0),
                ("Ожидание", 70.0),
                ("Результат", 100.0),
                ("Итог", 90.0),
                ("Слушатель", 110.0),
                ("Заметка", 200.0),
            ],
            rows.len(),
            None,
            |i, c, ui| {
                let (src, e) = rows[i];
                match c {
                    0 => {
                        ui.label(src);
                    }
                    1 => {
                        ui.monospace(match e.ip {
                            Some(ip) if ip.to_string() != e.target => format!("{} ({ip})", e.target),
                            _ => e.target.clone(),
                        });
                    }
                    2 => {
                        ui.monospace(e.port.to_string());
                    }
                    3 => {
                        ui.label(e.expect.label());
                    }
                    4 => {
                        let color = match e.state {
                            State::Open => GREEN,
                            State::Refused => ui.visuals().text_color(),
                            _ => AMBER,
                        };
                        ui.colored_label(color, e.state.label()).on_hover_text(&e.detail);
                    }
                    5 => match e.verdict {
                        Verdict::Ok => {
                            ui.colored_label(GREEN, "как ожидалось");
                        }
                        Verdict::Mismatch => {
                            ui.label(RichText::new("РАСХОЖДЕНИЕ").strong().color(RED));
                        }
                        Verdict::Info => {
                            ui.weak("—");
                        }
                    },
                    6 => {
                        ui.label(e.listener.clone().unwrap_or_default());
                    }
                    _ => {
                        ui.weak(&e.note);
                    }
                }
            },
            |i, ui| super::send_menu(ui, &format!("{}:{}", rows[i].1.target, rows[i].1.port), nav, Tool::Matrix),
        );
    }
}
