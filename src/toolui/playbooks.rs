use egui::RichText;

use super::{Env, GREEN, RED, Results};
use crate::playbook::{self, Event, Playbook, Step};
use crate::tools::Task;

/// Состояние шага при выполнении.
#[derive(Clone)]
enum StepState {
    Waiting,
    Running,
    Done(String),
}

pub struct Panel {
    list: Vec<(Option<std::path::PathBuf>, Playbook)>,
    selected: usize,
    task: Option<Task<Event>>,
    states: Vec<StepState>,
    log: Vec<String>,
    /// Итог выполнения — забирает Workbench (раскладывает по вкладкам).
    pub finished: Option<Results>,
    editor: Option<String>,
    editor_error: Option<String>,
    new_tool: String,
    pub last_run: Option<(String, u64)>,
    pub schedule: crate::tools::schedule::Config,
    schedule_status: Option<String>,
    schedule_task: Option<Task<crate::tools::schedule::Event>>,
    schedule_log: Vec<String>,
}

impl Default for Panel {
    fn default() -> Self {
        let mut p = Self {
            list: Vec::new(),
            selected: 0,
            task: None,
            states: Vec::new(),
            log: Vec::new(),
            finished: None,
            editor: None,
            editor_error: None,
            new_tool: "services".into(),
            last_run: None,
            schedule: crate::tools::schedule::load_config(&crate::tools::schedule::config_path()).unwrap_or_default(),
            schedule_status: None,
            schedule_task: None,
            schedule_log: Vec::new(),
        };
        p.reload();
        p
    }
}

impl Panel {
    fn reload(&mut self) {
        self.list = playbook::builtin().into_iter().map(|p| (None, p)).collect();
        self.list.extend(playbook::load_user().into_iter().map(|(p, b)| (Some(p), b)));
        if self.selected >= self.list.len() {
            self.selected = 0;
        }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some() || self.schedule_task.is_some()
    }

    pub fn poll(&mut self) -> bool {
        let mut sched_changed = false;
        if let Some(t) = &self.schedule_task {
            let ev = t.drain();
            let fin = t.finished();
            sched_changed = !ev.is_empty() || fin;
            for e in ev {
                match e {
                    crate::tools::schedule::Event::Log(l) => self.schedule_log.push(l),
                    crate::tools::schedule::Event::Done(d) => self.schedule_log.push(d),
                }
            }
            if fin {
                self.schedule_task = None;
            }
        }
        let Some(t) = &self.task else { return sched_changed };
        let events = t.drain();
        let finished = t.finished();
        let changed = !events.is_empty() || finished;
        for e in events {
            match e {
                Event::Step(i, _) => {
                    if let Some(s) = self.states.get_mut(i) {
                        *s = StepState::Running;
                    }
                }
                Event::Done(i, text) => {
                    if let Some(s) = self.states.get_mut(i) {
                        *s = StepState::Done(text);
                    }
                }
                Event::Log(l) => self.log.push(l),
                Event::Finished(r) => self.finished = Some(*r),
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    fn current(&self) -> Option<&Playbook> {
        self.list.get(self.selected).map(|x| &x.1)
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.label("Сценарий");
        let names: Vec<String> = self.list.iter().map(|(p, b)| format!("{}{}", b.name, if p.is_none() { " · встроенный" } else { "" })).collect();
        egui::ComboBox::from_id_salt("pb_sel")
            .width(ui.available_width())
            .selected_text(names.get(self.selected).cloned().unwrap_or_default())
            .show_ui(ui, |ui| {
                for (i, n) in names.iter().enumerate() {
                    if ui.selectable_label(i == self.selected, n).clicked() {
                        self.selected = i;
                        self.states.clear();
                        self.editor = None;
                    }
                }
            });
        if let Some(pb) = self.current() {
            ui.weak(&pb.description);
        }
        let (start, stop) = super::run_button(ui, self.busy(), "Выполнить");
        if start && let Some(pb) = self.current().cloned() {
            self.states = vec![StepState::Waiting; pb.steps.len()];
            self.log.clear();
            self.finished = None;
            self.last_run = Some((pb.name.clone(), crate::session::now_unix()));
            let store = env.store.clone();
            let subnet = env.local_cidr.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| playbook::execute(pb, store, subnet, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            if ui.button("Изменить…").on_hover_text("Сценарий в виде JSON: шаги, пресеты, параметры").clicked() {
                self.editor = self.current().map(|p| serde_json::to_string_pretty(p).unwrap_or_default());
                self.editor_error = None;
            }
            if ui.button("Новый").clicked() {
                let pb = Playbook {
                    name: "Мой сценарий".into(),
                    description: String::new(),
                    steps: vec![Step {
                        tool: "discovery".into(),
                        set: serde_json::json!({"targets": "{subnet}"}).as_object().cloned().unwrap_or_default(),
                        ..Default::default()
                    }],
                };
                self.list.push((None, pb));
                self.selected = self.list.len() - 1;
                self.editor = self.current().map(|p| serde_json::to_string_pretty(p).unwrap_or_default());
            }
            if ui.button("Папка").on_hover_text(playbook::user_dir().display().to_string()).clicked() {
                let _ = std::fs::create_dir_all(playbook::user_dir());
                crate::util::open_path(&playbook::user_dir());
            }
        });
        if let Some(mut text_owned) = self.editor.take() {
            let text = &mut text_owned;
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label("Добавить шаг");
                egui::ComboBox::from_id_salt("pb_add").selected_text(playbook::tool_title(&self.new_tool)).show_ui(ui, |ui| {
                    for (k, t) in playbook::TOOLS {
                        ui.selectable_value(&mut self.new_tool, k.to_string(), *t);
                    }
                });
                if ui.small_button("+").clicked()
                    && let Ok(mut pb) = serde_json::from_str::<Playbook>(text.as_str())
                {
                    let targets = match self.new_tool.as_str() {
                        "discovery" | "watch" => Some("{subnet}"),
                        "services" | "audit" => Some("{hosts}"),
                        "tls" => Some("{tls_hosts}"),
                        "shares" => Some("{smb_hosts}"),
                        _ => None,
                    };
                    let mut set = serde_json::Map::new();
                    if let Some(t) = targets {
                        set.insert("targets".into(), t.into());
                    }
                    pb.steps.push(Step { tool: self.new_tool.clone(), set, ..Default::default() });
                    *text = serde_json::to_string_pretty(&pb).unwrap_or_default();
                }
            });
            ui.add(egui::TextEdit::multiline(text).font(egui::TextStyle::Monospace).desired_rows(14).desired_width(f32::INFINITY));
            ui.weak("Подстановки: {subnet} {hosts} {tls_hosts} {smb_hosts} {dns_servers} {domain}. В «set» — любые параметры инструмента (как в пресетах).");
            if let Some(e) = &self.editor_error {
                ui.colored_label(RED, e);
            }
            let mut close = false;
            ui.horizontal(|ui| {
                if ui.button("Сохранить").clicked() {
                    match serde_json::from_str::<Playbook>(text.as_str()) {
                        Ok(pb) => match playbook::save_user(&pb) {
                            Ok(_) => {
                                let name = pb.name.clone();
                                close = true;
                                self.reload();
                                self.selected = self.list.iter().position(|x| x.1.name == name && x.0.is_some()).unwrap_or(0);
                            }
                            Err(e) => self.editor_error = Some(e),
                        },
                        Err(e) => self.editor_error = Some(format!("ошибка JSON: {e}")),
                    }
                }
                if ui.button("Отмена").clicked() {
                    close = true;
                }
            });
            if close {
                self.reload();
            } else {
                self.editor = Some(text_owned);
            }
        }
        ui.add_space(6.0);
        self.schedule_ui(ui, env);
        ui.add_space(6.0);
        ui.weak("Из командной строки: proxy-scanner-cli playbook файл.json -o отчёт.html.");
    }

    fn schedule_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        use crate::tools::schedule::{self, Every};
        let name = self.current().map(|p| p.name.clone()).unwrap_or_default();
        egui::CollapsingHeader::new("По расписанию с отчётом на почту").id_salt("pb_sched").show(ui, |ui| {
            if self.schedule_status.is_none() {
                self.schedule_status = Some(schedule::status());
            }
            ui.weak(self.schedule_status.clone().unwrap_or_default());
            let c = &mut self.schedule;
            if c.playbook.is_empty() || ui.small_button(format!("взять выбранный: «{name}»")).clicked() {
                c.playbook = name.clone();
            }
            ui.label(format!("Сценарий: «{}»", c.playbook));
            ui.horizontal(|ui| {
                ui.radio_value(&mut c.every, Every::Day, "каждый день");
                ui.radio_value(&mut c.every, Every::Week, "раз в неделю");
                ui.radio_value(&mut c.every, Every::Hours, "каждые N часов");
            });
            ui.horizontal(|ui| match c.every {
                Every::Hours => {
                    ui.add(egui::DragValue::new(&mut c.hours).range(1..=168).suffix(" ч"));
                }
                Every::Week => {
                    egui::ComboBox::from_id_salt("pb_wd")
                        .selected_text(["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"][(c.weekday.clamp(1, 7) - 1) as usize])
                        .show_ui(ui, |ui| {
                            for (i, d) in ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"].iter().enumerate() {
                                ui.selectable_value(&mut c.weekday, i as u8 + 1, *d);
                            }
                        });
                    ui.label("в");
                    ui.add(egui::DragValue::new(&mut c.hour).range(0..=23).suffix(":00"));
                }
                Every::Day => {
                    ui.label("в");
                    ui.add(egui::DragValue::new(&mut c.hour).range(0..=23).suffix(":00"));
                }
            });
            super::alerts_ui(ui, &mut c.alerts, "pb_sched_mail", "Отчёт HTML с блоком «Что изменилось с прошлого прогона» — на почту; в файл журнала — строка об итоге.");
            ui.horizontal(|ui| {
                ui.label("Хранить прогонов");
                ui.add(egui::DragValue::new(&mut c.keep).range(1..=1000));
            });
            ui.horizontal_wrapped(|ui| {
                if ui.button("Установить").on_hover_text("Задание Планировщика Windows (SYSTEM) или таймер systemd; нужны права администратора").clicked() {
                    self.schedule_status = Some(match schedule::install(&self.schedule) {
                        Ok(m) => m,
                        Err(e) => format!("не установлено: {e}"),
                    });
                }
                if ui.button("Удалить").clicked() {
                    self.schedule_status = Some(match schedule::uninstall() {
                        Ok(m) => m,
                        Err(e) => e,
                    });
                }
                let running = self.schedule_task.is_some();
                if ui.add_enabled(!running, egui::Button::new("Выполнить сейчас")).on_hover_text("Прогон как по расписанию: история, сравнение, отчёт и письмо").clicked() {
                    self.schedule_log.clear();
                    let cfg = self.schedule.clone();
                    let store = env.store.clone();
                    self.schedule_task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| schedule::run_once(cfg, store, s, c)));
                }
                if running {
                    ui.spinner();
                }
                if ui.button("История").on_hover_text(schedule::history_dir().display().to_string()).clicked() {
                    let _ = std::fs::create_dir_all(schedule::history_dir());
                    crate::util::open_path(&schedule::history_dir());
                }
            });
            for l in &self.schedule_log {
                ui.add(egui::Label::new(RichText::new(l).small()).wrap());
            }
        });
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, _env: &mut Env) {
        let Some(pb) = self.current().cloned() else {
            ui.weak("Сценариев нет.");
            return;
        };
        ui.label(RichText::new(&pb.name).heading());
        if !pb.description.is_empty() {
            ui.weak(&pb.description);
        }
        ui.add_space(6.0);
        egui::Grid::new("pb_steps").num_columns(3).spacing([12.0, 8.0]).show(ui, |ui| {
            for (i, s) in pb.steps.iter().enumerate() {
                ui.label(RichText::new(format!("{}.", i + 1)).strong());
                ui.label(RichText::new(s.label()).strong());
                match self.states.get(i) {
                    Some(StepState::Running) => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.weak("выполняется…");
                        });
                    }
                    Some(StepState::Done(t)) => {
                        let bad = t.starts_with("ошибка");
                        ui.colored_label(if bad { RED } else { GREEN }, t);
                    }
                    _ => {
                        let params = s.set.iter().map(|(k, v)| format!("{k}={}", v.as_str().map(String::from).unwrap_or(v.to_string()))).collect::<Vec<_>>().join("  ");
                        ui.weak(if s.preset.is_empty() { params } else { format!("пресет «{}» {params}", s.preset) });
                    }
                }
                ui.end_row();
            }
        });
        if !self.states.is_empty() && !self.busy() {
            ui.add_space(8.0);
            ui.colored_label(GREEN, "Готово: результаты разложены по вкладкам; отчёт — кнопка «Отчёт» в шапке.");
        }
        for l in &self.log {
            ui.colored_label(RED, l);
        }
    }
}
