use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::snmp::{self, Config, Event, Report};

/// (коммутатор, запись, адрес и имя узла).
type Row<'a> = (String, &'a snmp::FdbEntry, Option<(String, String)>);

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
    filter: String,
    only_access: bool,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            log: Vec::new(),
            filter: String::new(),
            only_access: true,
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
                Event::Log(l) => self.log.push(l),
                Event::Switch(s) => {
                    self.report.switches.retain(|x| x.address != s.address);
                    self.report.switches.push(*s);
                }
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, gateways: &[String]) {
        super::preset_bar(ui, env, "snmp", &mut self.cfg);
        let c = &mut self.cfg;
        ui.horizontal_wrapped(|ui| {
            ui.label("Коммутаторы");
            if !gateways.is_empty() && ui.small_button(format!("шлюзы ({})", gateways.len())).on_hover_text("Шлюзы этой машины — часто это и есть коммутатор ядра").clicked() {
                c.switches = gateways.join(", ");
            }
        });
        super::multiline(ui, &mut c.switches, 2, "10.0.0.2, sw-floor3.corp.local");
        ui.horizontal(|ui| {
            ui.label("Community");
            ui.add(egui::TextEdit::singleline(&mut c.community).desired_width(140.0));
        });
        let (start, stop) = super::run_button(ui, self.busy(), "Опросить");
        if start {
            self.log.clear();
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| snmp::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in &self.log {
            ui.colored_label(RED, l);
        }
        super::advanced(ui, "snmp_adv", |ui| {
            ui.horizontal(|ui| {
                ui.label("Таймаут, мс");
                ui.add(egui::DragValue::new(&mut self.cfg.timeout_ms).range(300..=20_000));
            });
        });
        ui.add_space(4.0);
        ui.weak("SNMPv2c, только чтение: таблица MAC-адресов (BRIDGE/Q-BRIDGE-MIB), имена портов, соседи LLDP. После опроса в меню любого узла (правый щелчок) работает «Где воткнут?», а на карте узлы привязываются к портам.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, names: &dyn Fn(&str) -> Option<(String, String)>) {
        if self.report.switches.is_empty() {
            if self.busy() {
                ui.spinner();
            } else {
                ui.weak("Укажите коммутаторы и community — получите, какой MAC за каким портом и в каком VLAN. Магистральные порты (много MAC или сосед LLDP) помечаются отдельно.");
            }
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for s in &self.report.switches {
                match &s.error {
                    None => ui.colored_label(GREEN, format!("{} {} — {} MAC", s.address, s.name, s.entries.len())),
                    Some(e) => ui.colored_label(RED, format!("{}: {e}", s.address)),
                };
            }
        });
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("MAC, порт, VLAN, адрес").desired_width(200.0));
            ui.checkbox(&mut self.only_access, "только порты доступа");
        });
        let f = self.filter.to_lowercase();
        // (коммутатор, запись, адрес/имя узла).
        let rows: Vec<Row> = self
            .report
            .switches
            .iter()
            .flat_map(|s| s.entries.iter().map(move |e| (if s.name.is_empty() { s.address.clone() } else { s.name.clone() }, e)))
            .filter(|(_, e)| !self.only_access || !e.uplink)
            .map(|(s, e)| {
                let who = names(&e.mac);
                (s, e, who)
            })
            .filter(|(s, e, who)| {
                f.is_empty()
                    || format!(
                        "{s} {} {} {} {} {}",
                        e.mac,
                        e.port,
                        e.port_alias,
                        e.vlan.map(|v| v.to_string()).unwrap_or_default(),
                        who.as_ref().map(|w| format!("{} {}", w.0, w.1)).unwrap_or_default()
                    )
                    .to_lowercase()
                    .contains(&f)
            })
            .collect();
        let nav = &mut *env.nav;
        super::table(
            ui,
            "snmp_fdb",
            &[("Коммутатор", 130.0), ("Порт", 110.0), ("VLAN", 50.0), ("MAC", 130.0), ("Узел", 140.0), ("Описание порта", 200.0)],
            rows.len(),
            None,
            |i, col, ui| {
                let (sw, e, who) = &rows[i];
                match col {
                    0 => {
                        ui.label(sw);
                    }
                    1 => {
                        if e.uplink {
                            ui.colored_label(AMBER, format!("{} ⇅{}", e.port, e.macs_on_port)).on_hover_text("магистральный порт");
                        } else {
                            ui.label(&e.port);
                        }
                    }
                    2 => {
                        ui.label(e.vlan.map(|v| v.to_string()).unwrap_or_default());
                    }
                    3 => {
                        ui.monospace(&e.mac);
                    }
                    4 => {
                        ui.label(who.as_ref().map(|w| if w.1.is_empty() { w.0.clone() } else { format!("{} ({})", w.0, w.1) }).unwrap_or_default());
                    }
                    _ => {
                        ui.weak(&e.port_alias);
                    }
                }
            },
            |i, ui| {
                if let Some((ip, _)) = &rows[i].2 {
                    super::send_menu(ui, ip, nav, Tool::Switches);
                } else if ui.button("Копировать MAC").clicked() {
                    ui.ctx().copy_text(rows[i].1.mac.clone());
                    ui.close();
                }
            },
        );
    }
}
