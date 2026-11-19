use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::monitor::{self, Config, Event, Report, Status};

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    error: Option<String>,
    /// Проверка перешла в «сбой» — попросить внимания окна.
    pub attention: bool,
}

const EXAMPLE: &str = "ping 10.0.0.1\ntcp mail.corp.local:25\nhttp https://portal.corp.local/ expect=200 max_ms=1500\ndns portal.corp.local @10.0.0.53 expect=10.0.0.5\ntls portal.corp.local:443 warn_days=30";

pub fn status_color(s: Status, ui: &egui::Ui) -> egui::Color32 {
    match s {
        Status::Ok => GREEN,
        Status::Warn => AMBER,
        Status::Fail => RED,
        Status::Unknown => ui.visuals().weak_text_color(),
    }
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            error: None,
            attention: false,
        }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// События мониторинга; о переходе в «сбой» сообщаем в строке состояния
    /// и просим внимания окна (мигание на панели задач).
    pub fn poll(&mut self, message: &mut Option<String>) -> bool {
        let Some(t) = &self.task else { return false };
        let events = t.drain();
        let finished = t.finished();
        let changed = !events.is_empty() || finished;
        let keep = self.cfg.history.max(10);
        for e in events {
            if let Event::Log(m) = &e {
                self.error = Some(m.clone());
            }
            if let Some(ch) = monitor::fold(&mut self.report, e, keep)
                && ch.from != Status::Unknown
            {
                *message = Some(format!("мониторинг: {} — {} → {} ({})", ch.line, ch.from.label(), ch.to.label(), ch.detail));
                if ch.to == Status::Fail {
                    self.attention = true;
                }
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "monitor", &mut self.cfg);
        let c = &mut self.cfg;
        ui.horizontal(|ui| {
            ui.label("Проверки — по одной в строке");
            if c.checks.trim().is_empty() && ui.small_button("пример").clicked() {
                c.checks = EXAMPLE.into();
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut c.checks)
                .font(egui::TextStyle::Monospace)
                .desired_rows(6)
                .desired_width(f32::INFINITY)
                .hint_text(EXAMPLE),
        );
        if let Err(e) = monitor::parse(&c.checks)
            && !c.checks.trim().is_empty()
        {
            ui.colored_label(RED, e);
        }
        ui.horizontal(|ui| {
            ui.label("Каждые");
            ui.add(egui::DragValue::new(&mut c.interval_s).range(5..=86_400).suffix(" с"));
        });
        let (start, stop) = super::run_button(ui, self.busy(), "Запустить мониторинг");
        if start {
            self.report = Report::default();
            self.error = None;
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| monitor::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if let Some(e) = &self.error {
            ui.colored_label(RED, e);
        }
        let c = &mut self.cfg;
        super::advanced(ui, "mon_adv", |ui| {
            egui::Grid::new("mon_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(200..=60_000)));
                super::labeled(ui, "Предупреждать от, мс", |ui| ui.add(egui::DragValue::new(&mut c.warn_ms).range(1.0..=60_000.0)));
                super::labeled(ui, "Хранить замеров", |ui| ui.add(egui::DragValue::new(&mut c.history).range(10..=10_000)));
            });
            ui.weak("Параметры строки: expect=, max_ms=, contains= (http), @сервер, type=, expect= (dns), warn_days= (tls).");
        });
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let r = &self.report;
        if r.states.is_empty() {
            ui.weak("Впишите проверки слева и нажмите «Запустить мониторинг». Окно можно держать открытым — состояние обновляется само.");
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for s in [Status::Ok, Status::Warn, Status::Fail] {
                let n = r.states.iter().filter(|x| x.status == s).count();
                ui.colored_label(status_color(s, ui), format!("{} {n}", s.label()));
            }
            ui.weak(format!("циклов: {}", r.cycles));
            if self.task.is_some() {
                ui.spinner();
            }
            super::export_buttons(ui, env, "monitor", r, monitor::render_text);
        });
        let nav = &mut *env.nav;
        super::table(
            ui,
            "mon_table",
            &[("Состояние", 80.0), ("Проверка", 300.0), ("Доступность", 80.0), ("мс", 60.0), ("История", 200.0), ("Результат", 260.0)],
            r.states.len(),
            None,
            |i, c, ui| {
                let s = &r.states[i];
                match c {
                    0 => {
                        ui.colored_label(status_color(s.status, ui), s.status.label());
                    }
                    1 => {
                        ui.monospace(&s.line);
                    }
                    2 => {
                        ui.label(format!("{:.1}%", s.availability()));
                    }
                    3 => {
                        ui.label(super::opt_ms(s.last.as_ref().and_then(|l| l.ms)));
                    }
                    4 => super::sparkline(ui, &s.history, 190.0),
                    _ => {
                        ui.label(s.last.as_ref().map(|l| l.detail.clone()).unwrap_or_default());
                    }
                }
            },
            |i, ui| {
                let target = r.states[i].line.split_whitespace().nth(1).unwrap_or("").to_string();
                super::send_menu(ui, &target, nav, Tool::Monitor);
            },
        );
        if !r.changes.is_empty() {
            ui.separator();
            ui.strong("Журнал изменений");
            egui::ScrollArea::vertical().id_salt("mon_changes").max_height(180.0).show(ui, |ui| {
                for ch in r.changes.iter().rev().take(300) {
                    ui.horizontal_wrapped(|ui| {
                        ui.weak(crate::session::format_time(ch.at));
                        ui.monospace(&ch.line);
                        ui.colored_label(status_color(ch.from, ui), ch.from.label());
                        ui.label("→");
                        ui.colored_label(status_color(ch.to, ui), ch.to.label());
                        ui.weak(&ch.detail);
                    });
                }
            });
        }
    }
}
