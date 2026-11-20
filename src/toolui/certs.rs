use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::certs::{self, Cert};

pub struct Panel {
    pub certs: Vec<Cert>,
    pub warn_days: i64,
    filter: Filter,
    text: String,
}

#[derive(PartialEq, Clone, Copy)]
enum Filter {
    All,
    Problems,
}

impl Default for Panel {
    fn default() -> Self {
        Self {
            certs: Vec::new(),
            warn_days: 30,
            filter: Filter::All,
            text: String::new(),
        }
    }
}

impl Panel {
    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.label("Сертификаты, найденные в этой сессии: TLS-аудит, сервисы, аудит, LDAPS контроллеров, HTTP, прокси.");
        ui.weak("Чтобы пополнить список — запустите TLS-аудит или сканер сервисов по нужным узлам.");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Предупреждать за");
            ui.add(egui::DragValue::new(&mut self.warn_days).range(1..=365).suffix(" дн."));
        });
        ui.add_space(6.0);
        if ui.button("Сохранить для Excel (CSV)…").clicked()
            && let Some(path) = rfd::FileDialog::new().add_filter("CSV", &["csv"]).set_file_name("certificates.csv").save_file()
        {
            *env.message = Some(match std::fs::write(&path, certs::to_csv(&self.certs, self.warn_days)) {
                Ok(()) => format!("сохранено: {}", path.display()),
                Err(e) => e.to_string(),
            });
        }
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        if self.certs.is_empty() {
            ui.weak("Сертификатов пока нет: запустите TLS-аудит, сканер сервисов или аудит.");
            return;
        }
        let w = self.warn_days;
        let expired = self.certs.iter().filter(|c| c.days_left.is_some_and(|d| d < 0)).count();
        let soon = self.certs.iter().filter(|c| c.days_left.is_some_and(|d| (0..w).contains(&d))).count();
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.filter, Filter::All, format!("Все ({})", self.certs.len()));
            ui.selectable_value(&mut self.filter, Filter::Problems, format!("Требуют внимания ({})", expired + soon));
            if expired > 0 {
                ui.colored_label(RED, format!("просрочено: {expired}"));
            }
            if soon > 0 {
                ui.colored_label(AMBER, format!("истекают за {w} дн.: {soon}"));
            }
            ui.add(egui::TextEdit::singleline(&mut self.text).desired_width(180.0).hint_text("поиск"));
            let list = self.certs.clone();
            super::export_buttons(ui, env, "certificates", &list, move |c: &Vec<Cert>| certs::render_text(c, w));
        });
        let q = self.text.to_lowercase();
        let rows: Vec<&Cert> = self
            .certs
            .iter()
            .filter(|c| self.filter == Filter::All || c.status(w) != "в порядке")
            .filter(|c| {
                q.is_empty()
                    || c.subject.to_lowercase().contains(&q)
                    || c.issuer.to_lowercase().contains(&q)
                    || c.endpoints.iter().any(|e| e.to_lowercase().contains(&q))
                    || c.names.iter().any(|n| n.to_lowercase().contains(&q))
            })
            .collect();
        let nav = &mut *env.nav;
        super::table(
            ui,
            "certs_table",
            &[
                ("Состояние", 90.0),
                ("Дней", 50.0),
                ("До", 150.0),
                ("Субъект", 200.0),
                ("Издатель", 180.0),
                ("Где", 220.0),
                ("Ключ", 80.0),
                ("Источник", 120.0),
            ],
            rows.len(),
            None,
            |i, col, ui| {
                let c = rows[i];
                match col {
                    0 => {
                        let st = c.status(w);
                        let color = match st {
                            "просрочен" => RED,
                            "истекает" | "не доверен" => AMBER,
                            _ => GREEN,
                        };
                        ui.colored_label(color, st);
                    }
                    1 => {
                        ui.label(c.days_left.map(|d| d.to_string()).unwrap_or_default());
                    }
                    2 => {
                        ui.label(&c.not_after);
                    }
                    3 => {
                        ui.label(&c.subject).on_hover_text(c.names.join("\n"));
                    }
                    4 => {
                        ui.label(&c.issuer);
                    }
                    5 => {
                        ui.monospace(c.endpoints.join(", "));
                    }
                    6 => {
                        ui.label(&c.key);
                    }
                    _ => {
                        ui.weak(c.sources.join(", "));
                    }
                }
            },
            |i, ui| {
                if let Some(e) = rows[i].endpoints.first() {
                    super::send_menu(ui, e.trim_start_matches("через прокси "), nav, Tool::Certs);
                }
            },
        );
    }
}
