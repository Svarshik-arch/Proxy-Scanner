//! Встроенные серверы: TFTP, HTTP, Syslog, SNMP-уведомления.

use std::collections::{BTreeMap, VecDeque};

use egui::RichText;
use egui_extras::{Column, TableBuilder};

use super::{AMBER, Env, GREEN, RED};
use crate::tools::Task;
use crate::tools::servers::{self, Config, Entry, Event, Kind};

const KEEP: usize = 20_000;

pub struct Panel {
    pub cfg: Config,
    task: Option<Task<Event>>,
    status: BTreeMap<Kind, Result<String, String>>,
    pub log: VecDeque<Entry>,
    filter: String,
    kind: Option<Kind>,
    max_sev: u8,
    paused: bool,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self { cfg, task: None, status: BTreeMap::new(), log: VecDeque::new(), filter: String::new(), kind: None, max_sev: 7, paused: false }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// Важные события (ошибка и выше) — для вкладки и обзора.
    pub fn alarms(&self) -> usize {
        self.log.iter().filter(|e| e.severity <= 3).count()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let ev = t.drain();
        let fin = t.finished();
        let ch = !ev.is_empty() || fin;
        for e in ev {
            match e {
                Event::Status(k, r) => {
                    self.status.insert(k, r);
                }
                Event::Entry(e) => {
                    self.log.push_back(e);
                    while self.log.len() > KEEP {
                        self.log.pop_front();
                    }
                }
            }
        }
        if fin {
            self.task = None;
            for v in self.status.values_mut() {
                if v.is_ok() {
                    *v = Ok("остановлен".into());
                }
            }
        }
        ch
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let busy = self.busy();
        ui.add_enabled_ui(!busy, |ui| {
            egui::Grid::new("srv_grid").num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
                for (on, name, port, k) in [
                    (&mut self.cfg.tftp, "TFTP", &mut self.cfg.tftp_port, Kind::Tftp),
                    (&mut self.cfg.http, "HTTP", &mut self.cfg.http_port, Kind::Http),
                    (&mut self.cfg.syslog, "Syslog", &mut self.cfg.syslog_port, Kind::Syslog),
                    (&mut self.cfg.traps, "SNMP-трапы", &mut self.cfg.trap_port, Kind::Trap),
                ] {
                    ui.checkbox(on, name);
                    ui.add(egui::DragValue::new(port).range(1..=65535));
                    match self.status.get(&k) {
                        Some(Ok(t)) => ui.colored_label(GREEN, t),
                        Some(Err(e)) => ui.colored_label(RED, "ошибка").on_hover_text(e),
                        None => ui.label(""),
                    };
                    ui.end_row();
                }
            });
            ui.checkbox(&mut self.cfg.tftp_write, "Принимать файлы по TFTP").on_hover_text("Чтобы устройства могли выгрузить конфигурацию: copy running-config tftp:");
            ui.label("Папка с файлами");
            super::singleline(ui, &mut self.cfg.dir, "папка для TFTP и HTTP");
            super::labeled(ui, "Слушать на", |ui| ui.add(egui::TextEdit::singleline(&mut self.cfg.bind).desired_width(120.0)));
        });
        let (start, stop) = super::run_button(ui, busy, "Запустить");
        if start {
            let cfg = self.cfg.clone();
            self.status.clear();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| servers::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for (k, r) in &self.status {
            if let Err(e) = r {
                ui.colored_label(RED, format!("{}: {e}", k.label()));
            }
        }
        if ui.small_button("Открыть папку").clicked() {
            let _ = std::fs::create_dir_all(&self.cfg.dir);
            crate::util::open_path(std::path::Path::new(&self.cfg.dir));
        }
        ui.add_space(6.0);
        let ip = crate::tools::sitecheck::local_ip();
        egui::CollapsingHeader::new("Что ввести на устройстве").default_open(true).show(ui, |ui| {
            let lines = [
                format!("logging host {ip}"),
                format!("snmp-server host {ip} version 2c public"),
                format!("copy running-config tftp://{ip}/sw1.cfg"),
                format!("info-center loghost {ip}   (Huawei)"),
                format!("tftp {ip} put vrpcfg.zip   (Huawei)"),
                format!("/system logging action set remote remote={ip}   (MikroTik)"),
            ];
            for l in lines {
                let cmd = l.split("   (").next().unwrap_or(&l).to_string();
                ui.horizontal(|ui| {
                    if ui.small_button("⧉").on_hover_text("Копировать").clicked() {
                        ui.ctx().copy_text(cmd.clone());
                    }
                    ui.add(egui::Label::new(RichText::new(&l).monospace()).truncate()).on_hover_text(&l);
                });
            }
        });
        ui.weak("Пока серверы запущены, журналы и уведомления копятся здесь. Порты ниже 1024 в Linux требуют прав; в Windows может понадобиться разрешение брандмауэра.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.kind, None, format!("Все ({})", self.log.len()));
            for k in [Kind::Syslog, Kind::Trap, Kind::Tftp, Kind::Http] {
                let n = self.log.iter().filter(|e| e.kind == k).count();
                ui.selectable_value(&mut self.kind, Some(k), format!("{} ({n})", k.label()));
            }
            ui.separator();
            egui::ComboBox::from_id_salt("srv_sev").selected_text(format!("до «{}»", servers::severity_label(self.max_sev))).show_ui(ui, |ui| {
                for s in 0..8u8 {
                    ui.selectable_value(&mut self.max_sev, s, servers::severity_label(s));
                }
            });
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("поиск").desired_width(160.0));
            ui.checkbox(&mut self.paused, "пауза");
            if ui.small_button("Очистить").clicked() {
                self.log.clear();
            }
            if ui.small_button("Копировать").clicked() {
                let s: String = self.view().iter().map(|e| format!("{}\t{}\t{}\t{}\t{}\n", crate::session::format_time(e.at), e.kind.label(), e.from, servers::severity_label(e.severity), e.text)).collect();
                ui.ctx().copy_text(s);
            }
        });
        if self.log.is_empty() {
            ui.weak("Запустите серверы слева и направьте на эту машину журналы и уведомления с оборудования.");
            return;
        }
        // Кто шлёт больше всего важного.
        let mut per: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for e in &self.log {
            let x = per.entry(e.from.as_str()).or_default();
            x.0 += 1;
            if e.severity <= 3 {
                x.1 += 1;
            }
        }
        let mut top: Vec<_> = per.into_iter().collect();
        top.sort_by_key(|x| std::cmp::Reverse((x.1.1, x.1.0)));
        ui.horizontal_wrapped(|ui| {
            ui.weak("Источники:");
            for (a, (n, bad)) in top.iter().take(12) {
                let t = format!("{a} {n}{}", if *bad > 0 { format!(" ⚠{bad}") } else { String::new() });
                if ui.small_button(RichText::new(t).color(if *bad > 0 { AMBER } else { ui.visuals().text_color() })).on_hover_text("показать только этот адрес").clicked() {
                    self.filter = a.to_string();
                }
            }
        });
        let rows = self.view();
        let mut tb = TableBuilder::new(ui)
            .striped(true)
            .column(Column::initial(130.0))
            .column(Column::initial(70.0))
            .column(Column::initial(110.0))
            .column(Column::initial(90.0))
            .column(Column::remainder().clip(true))
            .min_scrolled_height(0.0);
        if !self.paused {
            tb = tb.stick_to_bottom(true);
        }
        tb.header(20.0, |mut h| {
            for t in ["Время", "Тип", "Откуда", "Важность", "Сообщение"] {
                h.col(|ui| {
                    ui.strong(t);
                });
            }
        })
        .body(|body| {
            body.rows(18.0, rows.len(), |mut row| {
                let e = rows[row.index()];
                let c = match e.severity {
                    0..=3 => RED,
                    4 => AMBER,
                    _ => egui::Color32::PLACEHOLDER,
                };
                row.col(|ui| {
                    ui.label(crate::session::format_time(e.at).trim_end_matches(" UTC").to_string());
                });
                row.col(|ui| {
                    ui.label(e.kind.label());
                });
                row.col(|ui| {
                    ui.label(&e.from);
                });
                row.col(|ui| {
                    ui.colored_label(c, servers::severity_label(e.severity));
                });
                row.col(|ui| {
                    ui.label(&e.text).on_hover_text(&e.text);
                });
            });
        });
    }

    fn view(&self) -> Vec<&Entry> {
        let f = self.filter.to_lowercase();
        self.log
            .iter()
            .filter(|e| self.kind.is_none_or(|k| e.kind == k))
            .filter(|e| e.severity <= self.max_sev)
            .filter(|e| f.is_empty() || e.from.contains(&f) || e.text.to_lowercase().contains(&f))
            .collect()
    }
}
