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
        self.task.is_some()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
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
        ui.weak("Из командной строки: proxy-scanner-cli playbook файл.json -o отчёт.html — удобно по расписанию.");
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
