//! Резервные копии конфигураций: снятие, история версий, сравнение, проверка.

use egui::RichText;

use super::{AMBER, Env, GREEN, RED};
use crate::devices::{Device, Vendor};
use crate::tools::Task;
use crate::tools::configs::{self, Event, Level};

/// Сравнение версий (было, стало, строки) — пересчитывается при смене выбора.
type DiffCache = (String, String, Vec<(char, String)>);

#[derive(Default)]
pub struct Panel {
    picked: Vec<String>,
    filter: String,
    task: Option<Task<Event>>,
    total: usize,
    /// Итог последнего снятия по устройствам.
    status: Vec<(String, Result<String, String>)>,
    log: String,
    /// Выбранное устройство и версии (A — старая, B — новая).
    device: Option<String>,
    a: Option<usize>,
    b: Option<usize>,
    view: u8,
    cache: Option<DiffCache>,
}

impl Panel {
    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    pub fn problems(&self) -> usize {
        self.status.iter().filter(|s| s.1.is_err()).count()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let ev = t.drain();
        let fin = t.finished();
        let ch = !ev.is_empty() || fin;
        for e in ev {
            match e {
                Event::Log(l) => self.log = l,
                Event::Done(d, r) => self.status.push((
                    d,
                    r.map(|(p, c, f)| match p {
                        Some(_) => format!("сохранено: +{} −{} строк, замечаний {f}", c.added, c.removed),
                        None => format!("без изменений, замечаний {f}"),
                    }),
                )),
            }
        }
        if fin {
            self.task = None;
            self.log.clear();
            self.cache = None;
        }
        ch
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, list: &[Device]) {
        super::devices::pick_devices(ui, "cfg_devs", list, &mut self.picked, &mut self.filter);
        let (start, stop) = super::run_button(ui, self.busy(), "Снять копии");
        if start && !self.picked.is_empty() {
            let devs: Vec<Device> = list.iter().filter(|d| self.picked.contains(&d.title())).cloned().collect();
            self.total = devs.len();
            self.status.clear();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| configs::run(devs, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if self.busy() {
            super::progress(ui, self.status.len() as u64, self.total as u64, true);
            ui.weak(&self.log);
        }
        for (d, r) in &self.status {
            match r {
                Ok(t) => ui.colored_label(GREEN, format!("✔ {d}: {t}")),
                Err(e) => ui.colored_label(RED, format!("✖ {d}: {e}")),
            };
        }
        ui.add_space(6.0);
        ui.weak("Новая версия сохраняется, только если конфигурация изменилась. Строки со временем и счётчиками не считаются изменением.");
        ui.weak("По расписанию: proxy-scanner-cli configs --all (cron, systemd-таймер или Планировщик заданий Windows).");
        if ui.small_button("Открыть папку копий").clicked() {
            let _ = std::fs::create_dir_all(configs::root());
            crate::util::open_path(&configs::root());
        }
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, _env: &mut Env, list: &[Device]) {
        // Устройства с копиями: из списка и из папки (удалённые из списка тоже видны).
        let mut names: Vec<String> = list.iter().map(|d| d.title()).collect();
        for e in std::fs::read_dir(configs::root()).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if e.path().is_dir() && !names.iter().any(|x| configs::folder(x) == n) {
                names.push(n);
            }
        }
        if names.is_empty() {
            ui.weak("Копий пока нет. Выберите устройства слева и нажмите «Снять копии».");
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for n in &names {
                let v = configs::versions(n);
                let text = format!("{n} ({})", v.len());
                if ui.selectable_label(self.device.as_deref() == Some(n.as_str()), text).clicked() {
                    self.device = Some(n.clone());
                    self.a = (v.len() > 1).then_some(1);
                    self.b = (!v.is_empty()).then_some(0);
                    self.cache = None;
                }
            }
        });
        let Some(dev) = self.device.clone() else {
            ui.weak("Выберите устройство.");
            return;
        };
        let versions = configs::versions(&dev);
        if versions.is_empty() {
            ui.weak("У этого устройства копий нет.");
            return;
        }
        let vendor = list.iter().find(|d| d.title() == dev).map(|d| d.vendor).unwrap_or(Vendor::Auto);
        ui.separator();
        ui.columns(2, |cols| {
            let ui = &mut cols[0];
            ui.strong("Версии");
            egui::ScrollArea::vertical().id_salt("cfg_versions").max_height(140.0).show(ui, |ui| {
                egui::Grid::new("cfg_vgrid").num_columns(3).show(ui, |ui| {
                    ui.weak("было");
                    ui.weak("стало");
                    ui.weak("");
                    ui.end_row();
                    for (i, v) in versions.iter().enumerate() {
                        if ui.radio(self.a == Some(i), "").clicked() {
                            self.a = Some(i);
                            self.cache = None;
                        }
                        if ui.radio(self.b == Some(i), "").clicked() {
                            self.b = Some(i);
                            self.cache = None;
                        }
                        ui.label(format!("{}  ·  {} КБ", configs::pretty(&v.stamp), v.size.div_ceil(1024)));
                        ui.end_row();
                    }
                });
            });
            let ui = &mut cols[1];
            ui.strong("Проверка последней версии");
            let text = std::fs::read_to_string(&versions[0].path).unwrap_or_default();
            let f = configs::audit(&text, vendor);
            egui::ScrollArea::vertical().id_salt("cfg_audit").max_height(140.0).show(ui, |ui| {
                if f.is_empty() {
                    ui.colored_label(GREEN, "✔ типовых ошибок не найдено");
                }
                for x in &f {
                    let c = match x.level {
                        Level::High => RED,
                        Level::Medium => AMBER,
                        Level::Low => ui.visuals().text_color(),
                    };
                    ui.colored_label(c, format!("[{}] {}", x.level.label(), x.title)).on_hover_text(match &x.line {
                        Some(l) => format!("{}\n\nСтрока: {l}", x.advice),
                        None => x.advice.clone(),
                    });
                }
            });
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.view, 0, "Изменения");
            ui.selectable_value(&mut self.view, 1, "Текст версии «стало»");
        });
        let (Some(a), Some(b)) = (self.a.filter(|a| *a < versions.len()), self.b.filter(|b| *b < versions.len())) else {
            ui.weak("Выберите версии «было» и «стало».");
            return;
        };
        if self.view == 1 {
            let text = std::fs::read_to_string(&versions[b].path).unwrap_or_default();
            ui.horizontal(|ui| {
                if ui.small_button("Копировать").clicked() {
                    ui.ctx().copy_text(text.clone());
                }
            });
            super::mono_block(ui, "cfg_text", &text, f32::INFINITY);
            return;
        }
        let key = (versions[a].stamp.clone(), versions[b].stamp.clone());
        if self.cache.as_ref().is_none_or(|c| (c.0.clone(), c.1.clone()) != key) {
            let old = std::fs::read_to_string(&versions[a].path).unwrap_or_default();
            let new = std::fs::read_to_string(&versions[b].path).unwrap_or_default();
            self.cache = Some((key.0, key.1, configs::diff(&old, &new, 3).0));
        }
        let lines = &self.cache.as_ref().unwrap().2;
        if a == b || lines.is_empty() {
            ui.weak("Версии одинаковые.");
            return;
        }
        let added = lines.iter().filter(|l| l.0 == '+').count();
        let removed = lines.iter().filter(|l| l.0 == '-').count();
        ui.label(RichText::new(format!("{} → {}: добавлено {added}, удалено {removed}", configs::pretty(&versions[a].stamp), configs::pretty(&versions[b].stamp))).strong());
        egui::ScrollArea::both().id_salt("cfg_diff").auto_shrink([false, false]).show(ui, |ui| {
            for (sign, text) in lines {
                let (c, bg) = match sign {
                    '+' => (GREEN, egui::Color32::from_rgba_unmultiplied(60, 170, 90, 30)),
                    '-' => (RED, egui::Color32::from_rgba_unmultiplied(220, 70, 70, 30)),
                    '@' => (ui.visuals().weak_text_color(), egui::Color32::TRANSPARENT),
                    _ => (ui.visuals().text_color(), egui::Color32::TRANSPARENT),
                };
                egui::Frame::new().fill(bg).show(ui, |ui| {
                    ui.label(RichText::new(format!("{sign} {text}")).monospace().color(c));
                });
            }
        });
    }
}
