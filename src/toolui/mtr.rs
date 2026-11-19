use egui::RichText;

use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::mtr::{self, Config, Event, Mode, Report};

pub struct Panel {
    pub cfg: Config,
    pub report: Option<Report>,
    task: Option<Task<Event>>,
    error: Option<String>,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: None,
            task: None,
            error: None,
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
            let r = self.report.get_or_insert_with(Report::default);
            match e {
                Event::Log(m) => self.error = Some(m),
                Event::Resolved(ip) => r.address = Some(ip),
                Event::Method(m) => r.method = m,
                Event::Hops(h) => r.hops = h,
                Event::Cycle(n) => r.cycles = n,
                Event::Pmtu(p) => r.pmtu = Some(p),
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    fn start(&mut self, env: &Env) {
        self.error = None;
        self.report = Some(Report {
            target: self.cfg.target.clone(),
            ..Default::default()
        });
        let cfg = self.cfg.clone();
        self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| mtr::run(cfg, s, c)));
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "mtr", &mut self.cfg);
        let c = &mut self.cfg;
        ui.label("Узел");
        let r = ui.add(egui::TextEdit::singleline(&mut c.target).desired_width(f32::INFINITY).hint_text("10.0.0.1 или имя"));
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.horizontal(|ui| {
            for m in Mode::ALL {
                ui.radio_value(&mut c.mode, m, m.label());
            }
        });
        if c.mode == Mode::Udp && cfg!(windows) {
            ui.colored_label(AMBER, "В Windows UDP-трассировка недоступна — используйте ICMP");
        }
        egui::Grid::new("mtr_grid").num_columns(2).show(ui, |ui| {
            if c.mode != Mode::Icmp {
                super::labeled(ui, if c.mode == Mode::Tcp { "Порт" } else { "Начальный порт" }, |ui| {
                    ui.add(egui::DragValue::new(&mut c.port).range(1..=65535))
                });
            }
            super::labeled(ui, "Циклов (0 — до остановки)", |ui| ui.add(egui::DragValue::new(&mut c.cycles).range(0..=100_000)));
        });
        if c.mode != Mode::Tcp {
            ui.checkbox(&mut c.pmtu, "Найти MTU пути перед трассировкой");
        }
        super::advanced(ui, "mtr_adv", |ui| {
            egui::Grid::new("mtr_grid2").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Интервал, мс", |ui| ui.add(egui::DragValue::new(&mut c.interval_ms).range(50..=60_000)));
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(50..=30_000)));
                if c.mode != Mode::Tcp {
                    super::labeled(ui, "Первый хоп", |ui| ui.add(egui::DragValue::new(&mut c.first_hop).range(1..=64)));
                    super::labeled(ui, "Максимум хопов", |ui| ui.add(egui::DragValue::new(&mut c.max_hops).range(1..=64)));
                    super::labeled(ui, "Данных в пробе, байт", |ui| ui.add(egui::DragValue::new(&mut c.payload).range(0..=65000)));
                }
            });
            if c.mode != Mode::Tcp {
                ui.checkbox(&mut c.df, "Запрет фрагментации (DF)");
                ui.checkbox(&mut c.resolve_names, "Имена хопов (обратный DNS)");
            }
        });
        ui.add_space(6.0);
        let (start, stop) = super::run_button(ui, self.busy(), "Трассировать");
        if (start || (enter && !self.busy())) && !self.cfg.target.trim().is_empty() {
            self.start(env);
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if let Some(e) = &self.error {
            ui.colored_label(RED, e);
        }
        match crate::tools::icmp::icmp_method() {
            Ok(m) => ui.weak(format!("ICMP: {m}")),
            Err(e) => ui.colored_label(AMBER, e),
        };
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let Some(r) = &self.report else {
            ui.weak("Укажите узел и нажмите «Трассировать».");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.strong(&r.target);
            if let Some(a) = r.address {
                ui.monospace(a.to_string());
            }
            ui.weak(&r.method);
            ui.label(format!("циклов: {}", r.cycles));
            if self.task.is_some() {
                ui.spinner();
            }
            super::export_buttons(ui, env, "mtr", r, mtr::render_text);
        });
        if let Some(p) = &r.pmtu {
            ui.horizontal_wrapped(|ui| {
                ui.strong("MTU пути:");
                match p.mtu {
                    Some(m) => ui.label(RichText::new(m.to_string()).strong().color(if m < 1500 { AMBER } else { GREEN })),
                    None => ui.colored_label(RED, "не определён"),
                };
                if let Some(n) = &p.note {
                    ui.weak(n);
                }
            })
            .response
            .on_hover_ui(|ui| {
                for (size, ok, note) in &p.steps {
                    ui.label(format!("{size}: {} {note}", if *ok { "проходит" } else { "нет" }));
                }
            });
        }
        let hops = &r.hops;
        let nav = &mut *env.nav;
        super::table(
            ui,
            "mtr_table",
            &[
                ("#", 28.0),
                ("Узел", 260.0),
                ("Потери", 64.0),
                ("Отпр.", 48.0),
                ("Посл.", 56.0),
                ("Сред.", 56.0),
                ("Лучш.", 56.0),
                ("Худш.", 56.0),
                ("Откл.", 56.0),
                ("Джиттер", 60.0),
                ("История", 160.0),
            ],
            hops.len(),
            None,
            |i, c, ui| {
                let h = &hops[i];
                match c {
                    0 => {
                        ui.label(if h.ttl == 0 { String::new() } else { h.ttl.to_string() });
                    }
                    1 => {
                        let t = ui.label(RichText::new(h.host_label()).monospace());
                        if let Some(n) = &h.note {
                            t.on_hover_text(n);
                            ui.colored_label(AMBER, "⚠");
                        }
                    }
                    2 => {
                        let l = h.loss_pct();
                        let color = if l == 0.0 { GREEN } else if l < 20.0 { AMBER } else { RED };
                        ui.colored_label(color, format!("{l:.0}%"));
                    }
                    3 => {
                        ui.label(h.sent.to_string());
                    }
                    4 => {
                        ui.label(super::opt_ms(h.last_ms));
                    }
                    5 => {
                        ui.label(if h.recv > 0 { format!("{:.1}", h.avg_ms) } else { "—".into() });
                    }
                    6 => {
                        ui.label(super::opt_ms(h.best_ms));
                    }
                    7 => {
                        ui.label(super::opt_ms(h.worst_ms));
                    }
                    8 => {
                        ui.label(format!("{:.1}", h.stdev_ms));
                    }
                    9 => {
                        ui.label(format!("{:.1}", h.jitter_ms));
                    }
                    _ => super::sparkline(ui, &h.history, 150.0),
                }
            },
            |i, ui| {
                if let Some(a) = hops[i].addrs.first() {
                    super::send_menu(ui, &a.to_string(), nav, Tool::Mtr);
                }
            },
        );
    }
}
