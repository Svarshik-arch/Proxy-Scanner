use egui::RichText;

use super::{AMBER, Env, GREEN, RED};
use crate::session::{self, Session};
use crate::tools::compare::{self, Diff, Kind};

#[derive(Default)]
pub struct Panel {
    old: Option<(String, Session)>,
    newer: Option<(String, Session)>,
    pub diff: Option<Diff>,
    category: Option<String>,
    kind: Option<Kind>,
    error: Option<String>,
}

fn load(path: &std::path::Path) -> Result<(String, Session), String> {
    let s = session::load(path)?;
    Ok((path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default(), s))
}

impl Panel {
    /// `current` — снимок текущей сессии (для сравнения «файл ↔ сейчас»).
    pub fn settings_ui(&mut self, ui: &mut egui::Ui, current: Option<&Session>, archive: &[(String, std::path::PathBuf)]) {
        ui.label("Что изменилось между двумя проверками: узлы, сервисы, прокси, сертификаты, DNS, находки.");
        ui.add_space(6.0);
        ui.strong("Было");
        ui.horizontal_wrapped(|ui| {
            ui.label(self.old.as_ref().map(|o| format!("{} ({})", o.0, compare::label(&o.1))).unwrap_or("не выбрано".into()));
        });
        ui.horizontal(|ui| {
            if ui.button("Открыть файл…").clicked()
                && let Some(p) = rfd::FileDialog::new().add_filter("Сессия", &["json"]).pick_file()
            {
                match load(&p) {
                    Ok(x) => self.old = Some(x),
                    Err(e) => self.error = Some(e),
                }
            }
            ui.menu_button("Из архива ▾", |ui| {
                if archive.is_empty() {
                    ui.weak("архив пуст");
                }
                for (label, path) in archive.iter().take(30) {
                    if ui.button(label).clicked() {
                        match load(path) {
                            Ok(x) => self.old = Some(x),
                            Err(e) => self.error = Some(e),
                        }
                        ui.close();
                    }
                }
            });
        });
        ui.add_space(6.0);
        ui.strong("Стало");
        ui.label(self.newer.as_ref().map(|o| format!("{} ({})", o.0, compare::label(&o.1))).unwrap_or("текущая сессия".into()));
        ui.horizontal(|ui| {
            if ui.button("Открыть файл…").clicked()
                && let Some(p) = rfd::FileDialog::new().add_filter("Сессия", &["json"]).pick_file()
            {
                match load(&p) {
                    Ok(x) => self.newer = Some(x),
                    Err(e) => self.error = Some(e),
                }
            }
            if self.newer.is_some() && ui.button("текущая").clicked() {
                self.newer = None;
            }
        });
        ui.add_space(8.0);
        let ready = self.old.is_some() && (self.newer.is_some() || current.is_some());
        if ui.add_enabled(ready, egui::Button::new(RichText::new("▶ Сравнить").strong())).clicked() {
            let old = &self.old.as_ref().unwrap().1;
            let new = self.newer.as_ref().map(|n| &n.1).or(current).unwrap();
            self.diff = Some(compare::diff(old, new));
            self.category = None;
            self.kind = None;
            self.error = None;
        }
        if let Some(e) = &self.error {
            ui.colored_label(RED, e);
        }
        ui.add_space(6.0);
        ui.weak("Архив: копии сессий сохраняются перед каждым новым сканированием.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let Some(d) = &self.diff else {
            ui.weak("Выберите, с чем сравнивать (файл или архив), и нажмите «Сравнить».");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("было: {} → стало: {}", d.old_label, d.new_label));
            super::export_buttons(ui, env, "compare", d, compare::render_text);
        });
        if d.changes.is_empty() {
            ui.colored_label(GREEN, "Изменений нет.");
            return;
        }
        ui.horizontal_wrapped(|ui| {
            if ui.selectable_label(self.category.is_none(), format!("Всё ({})", d.changes.len())).clicked() {
                self.category = None;
            }
            for c in d.categories() {
                let n = d.changes.iter().filter(|x| x.category == c).count();
                let sel = self.category.as_deref() == Some(c.as_str());
                if ui.selectable_label(sel, format!("{c} ({n})")).clicked() {
                    self.category = if sel { None } else { Some(c.clone()) };
                }
            }
            ui.separator();
            for k in [Kind::Added, Kind::Removed, Kind::Changed] {
                let sel = self.kind == Some(k);
                if ui.selectable_label(sel, k.label()).clicked() {
                    self.kind = if sel { None } else { Some(k) };
                }
            }
        });
        let rows: Vec<&compare::Change> = d
            .changes
            .iter()
            .filter(|c| self.category.as_ref().is_none_or(|x| *x == c.category))
            .filter(|c| self.kind.is_none_or(|k| k == c.kind))
            .collect();
        super::table(
            ui,
            "cmp_table",
            &[("Раздел", 110.0), ("Что", 90.0), ("Объект", 240.0), ("Было", 260.0), ("Стало", 260.0)],
            rows.len(),
            None,
            |i, c, ui| {
                let x = rows[i];
                match c {
                    0 => {
                        ui.label(&x.category);
                    }
                    1 => {
                        let color = match x.kind {
                            Kind::Added => GREEN,
                            Kind::Removed => RED,
                            Kind::Changed => AMBER,
                        };
                        ui.colored_label(color, x.kind.label());
                    }
                    2 => {
                        ui.monospace(&x.key);
                    }
                    3 => {
                        ui.weak(&x.before).on_hover_text(&x.before);
                    }
                    _ => {
                        ui.label(&x.after).on_hover_text(&x.after);
                    }
                }
            },
            |_, _| {},
        );
    }
}
