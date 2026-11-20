use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::shares::{self, Config, Event, Login, Report};

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
    total: u64,
    done: u64,
    text: String,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            log: Vec::new(),
            total: 0,
            done: 0,
            text: String::new(),
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
                Event::Host(h, list) => {
                    self.done += 1;
                    self.report.hosts.push(*h);
                    self.report.shares.extend(list);
                }
            }
        }
        if finished {
            self.report.shares.sort_by(|a, b| (&a.host, &a.kind, &a.name).cmp(&(&b.host, &b.kind, &b.name)));
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "shares", &mut self.cfg);
        let c = &mut self.cfg;
        ui.label("Узлы");
        super::multiline(ui, &mut c.targets, 2, "fs01.corp.local, 10.0.0.0/24");
        let file_hosts = env.scan.hosts_with(&[139, 445, 111, 2049]);
        match super::from_scan(
            ui,
            &env.scan,
            &[
                (format!("с SMB/NFS ({})", file_hosts.len()), "Узлы, где открыты порты 139, 445, 111 или 2049"),
                (format!("все найденные ({})", env.scan.hosts().len()), "Все узлы из сканирования"),
            ],
        ) {
            Some(0) => c.targets = file_hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(", "),
            Some(1) => c.targets = env.scan.hosts_text(),
            _ => {}
        }
        ui.horizontal(|ui| {
            ui.checkbox(&mut c.smb, "SMB");
            ui.checkbox(&mut c.nfs, "NFS");
        });
        if c.smb {
            ui.horizontal(|ui| {
                ui.label("Вход");
                egui::ComboBox::from_id_salt("sh_login").selected_text(c.login.label()).show_ui(ui, |ui| {
                    ui.selectable_value(&mut c.login, Login::Anonymous, Login::Anonymous.label());
                    ui.selectable_value(&mut c.login, Login::Account, Login::Account.label());
                    if cfg!(windows) {
                        ui.selectable_value(&mut c.login, Login::CurrentUser, Login::CurrentUser.label());
                    }
                });
            });
            if c.login == Login::Account {
                egui::Grid::new("sh_cred").num_columns(2).show(ui, |ui| {
                    super::labeled(ui, "Пользователь", |ui| ui.add(egui::TextEdit::singleline(&mut c.user).hint_text("DOMAIN\\user")));
                    super::labeled(ui, "Пароль", |ui| ui.add(egui::TextEdit::singleline(&mut c.password).password(true)));
                });
            }
        }
        let (start, stop) = super::run_button(ui, self.busy(), "Найти ресурсы");
        if start {
            self.report = Report::default();
            self.log.clear();
            self.total = 0;
            self.done = 0;
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| shares::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in &self.log {
            ui.colored_label(RED, l);
        }
        let c = &mut self.cfg;
        super::advanced(ui, "sh_adv", |ui| {
            ui.checkbox(&mut c.check_access, "Проверять подключение к каждой шаре (без чтения файлов)");
            egui::Grid::new("sh_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(500..=30_000)));
                super::labeled(ui, "Параллельно узлов", |ui| ui.add(egui::DragValue::new(&mut c.concurrency).range(1..=256)));
            });
        });
        ui.add_space(6.0);
        ui.weak("Показывает имена ресурсов и доступ к ним. Содержимое не читается.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        if self.report.hosts.is_empty() {
            if self.busy() {
                ui.spinner();
            } else {
                ui.weak("Укажите узлы и нажмите «Найти ресурсы». Анонимный доступ к шарам — частая находка аудита.");
            }
            return;
        }
        let open = self.report.shares.iter().filter(|s| s.accessible == Some(true) && s.login == "анонимно" || s.login == "гостем").count();
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("ресурсов: {}", self.report.shares.len()));
            if open > 0 {
                ui.colored_label(AMBER, format!("доступны без пароля: {open}"));
            }
            ui.add(egui::TextEdit::singleline(&mut self.text).desired_width(180.0).hint_text("поиск"));
            super::progress(ui, self.done, self.total, self.busy());
            super::export_buttons(ui, env, "shares", &self.report, shares::render_text);
        });
        let errors: Vec<String> = self
            .report
            .hosts
            .iter()
            .flat_map(|h| {
                [("SMB", &h.smb), ("NFS", &h.nfs)]
                    .into_iter()
                    .filter_map(move |(k, r)| match r {
                        Some(Err(e)) => Some(format!("{} {k}: {e}", h.host)),
                        _ => None,
                    })
            })
            .collect();
        if !errors.is_empty() {
            egui::CollapsingHeader::new(format!("Не удалось получить ({})", errors.len())).show(ui, |ui| {
                for e in &errors {
                    ui.weak(e);
                }
            });
        }
        let q = self.text.to_lowercase();
        let rows: Vec<&shares::Share> = self
            .report
            .shares
            .iter()
            .filter(|s| q.is_empty() || s.name.to_lowercase().contains(&q) || s.host.contains(&q) || s.comment.to_lowercase().contains(&q))
            .collect();
        let nav = &mut *env.nav;
        super::table(
            ui,
            "sh_table",
            &[("Узел", 130.0), ("Тип", 140.0), ("Ресурс", 180.0), ("Доступ", 200.0), ("Комментарий / клиенты", 260.0)],
            rows.len(),
            None,
            |i, c, ui| {
                let s = rows[i];
                match c {
                    0 => {
                        ui.monospace(&s.host);
                    }
                    1 => {
                        ui.label(&s.kind);
                    }
                    2 => {
                        ui.monospace(&s.name);
                    }
                    3 => match s.accessible {
                        Some(true) if s.login == "анонимно" || s.login == "гостем" => {
                            ui.colored_label(AMBER, format!("открыт {}", s.login));
                        }
                        Some(true) => {
                            ui.colored_label(GREEN, format!("есть ({})", s.login));
                        }
                        Some(false) => {
                            ui.weak("нет доступа");
                        }
                        None => {}
                    },
                    _ => {
                        ui.label(if s.clients.is_empty() { s.comment.clone() } else { format!("клиенты: {}", s.clients) });
                    }
                }
            },
            |i, ui| super::send_menu(ui, &rows[i].host, nav, Tool::Shares),
        );
    }
}
