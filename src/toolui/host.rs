use egui::RichText;

use super::{Env, GREEN, Nav, Tool};
use super::UiNz;
use crate::tools::hostinfo::{self, Report};

#[derive(Default)]
pub struct Panel {
    pub report: Option<Report>,
    task: Option<crate::tools::Task<Report>>,
    filter: String,
    listen_only: bool,
}

impl Panel {
    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let mut changed = false;
        for r in t.drain() {
            self.report = Some(r);
            changed = true;
        }
        if t.finished() {
            self.task = None;
            changed = true;
        }
        changed
    }

    fn start(&mut self, env: &Env) {
        self.task = Some(crate::tools::Task::spawn(env.rt, &env.ctx, |sink, _| async move {
            if let Ok(r) = tokio::task::spawn_blocking(hostinfo::collect).await {
                sink.send(r);
            }
        }));
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let (start, _) = super::run_button(ui, self.busy(), "Собрать сведения");
        if start || (self.report.is_none() && !self.busy()) {
            self.start(env);
        }
        ui.add_space(6.0);
        ui.label("Фильтр соединений");
        super::singleline(ui, &mut self.filter, "адрес, порт, процесс");
        ui.checkbox(&mut self.listen_only, "Только прослушиваемые порты");
        if let Some(r) = &self.report {
            ui.add_space(6.0);
            super::export_buttons(ui, env, "host", r, hostinfo::render_text);
        }
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let Some(r) = &self.report else {
            if self.busy() {
                ui.spinner();
            }
            return;
        };
        let nav = &mut *env.nav;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(&r.hostname);
                ui.weak(&r.os);
            });
            for n in &r.notes {
                ui.weak(format!("• {n}"));
            }
            egui::CollapsingHeader::new(RichText::new(format!("Интерфейсы ({})", r.interfaces.len())).strong())
                .default_open(true)
                .show(ui, |ui| {
                    for i in &r.interfaces {
                        if !i.up && i.addrs.is_empty() {
                            continue;
                        }
                        ui.horizontal_wrapped(|ui| {
                            if !i.name.is_empty() {
                                ui.label(RichText::new(&i.name).strong().color(if i.up { GREEN } else { super::AMBER }));
                            }
                            ui.weak_nz(&i.description);
                            ui.mono_nz(&i.mac);
                            if let Some(v) = &i.vendor {
                                ui.weak_nz(v);
                            }
                            if let Some(m) = i.mtu {
                                ui.label(format!("MTU {m}"));
                            }
                            if let Some(s) = i.speed_mbps {
                                ui.label(format!("{s} Мбит/с"));
                            }
                        });
                        egui::Grid::new(("if", &i.name)).num_columns(2).show(ui, |ui| {
                            let mut row = |k: &str, v: String| {
                                if !v.is_empty() {
                                    ui.weak(k);
                                    ui.add(egui::Label::new(RichText::new(v).monospace()).wrap());
                                    ui.end_row();
                                }
                            };
                            row("адреса", i.addrs.join(", "));
                            row("шлюз", i.gateways.join(", "));
                            row("DNS", i.dns.join(", "));
                            row("DHCP", i.dhcp_server.clone().unwrap_or_default());
                            row("суффикс", i.dns_suffix.clone().unwrap_or_default());
                        });
                        for g in &i.gateways {
                            ui.horizontal(|ui| {
                                for t in [Tool::Mtr, Tool::Services] {
                                    if ui.small_button(format!("шлюз {g} → {}", t.title())).clicked() {
                                        *nav = Some(Nav::Send(t, g.clone()));
                                    }
                                }
                            });
                        }
                        ui.separator();
                    }
                });
            egui::CollapsingHeader::new(RichText::new(format!("Маршруты ({})", r.routes.len())).strong()).show(ui, |ui| {
                super::table(
                    ui,
                    "routes",
                    &[("Назначение", 160.0), ("Шлюз", 140.0), ("Интерфейс", 140.0), ("Метрика", 60.0)],
                    r.routes.len(),
                    None,
                    |i, c, ui| {
                        let rt = &r.routes[i];
                        ui.monospace(match c {
                            0 => rt.dest.clone(),
                            1 => rt.gateway.clone(),
                            2 => rt.iface.clone(),
                            _ => rt.metric.map(|m| m.to_string()).unwrap_or_default(),
                        });
                    },
                    |_, _| {},
                );
            });
            egui::CollapsingHeader::new(RichText::new(format!("Соседи, ARP ({})", r.neighbors.len())).strong()).show(ui, |ui| {
                super::table(
                    ui,
                    "neigh",
                    &[("IP", 130.0), ("MAC", 150.0), ("Производитель", 180.0), ("Интерфейс", 120.0), ("Состояние", 100.0)],
                    r.neighbors.len(),
                    None,
                    |i, c, ui| {
                        let n = &r.neighbors[i];
                        ui.monospace(match c {
                            0 => n.ip.clone(),
                            1 => n.mac.clone(),
                            2 => n.vendor.clone().unwrap_or_default(),
                            3 => n.iface.clone(),
                            _ => n.state.clone(),
                        });
                    },
                    |i, ui| super::send_menu(ui, &r.neighbors[i].ip, nav, Tool::Host),
                );
            });
            let f = self.filter.to_lowercase();
            let conns: Vec<&hostinfo::Conn> = r
                .connections
                .iter()
                .filter(|c| !self.listen_only || c.state == "LISTEN" || c.state == "Listen" || (c.proto == "udp" && c.remote.is_empty()))
                .filter(|c| {
                    f.is_empty()
                        || c.local.to_lowercase().contains(&f)
                        || c.remote.to_lowercase().contains(&f)
                        || c.process.to_lowercase().contains(&f)
                })
                .collect();
            egui::CollapsingHeader::new(RichText::new(format!("Соединения ({})", conns.len())).strong())
                .default_open(true)
                .show(ui, |ui| {
                    super::table(
                        ui,
                        "conns",
                        &[("Прот.", 44.0), ("Локальный", 190.0), ("Удалённый", 190.0), ("Состояние", 100.0), ("PID", 60.0), ("Процесс", 140.0)],
                        conns.len(),
                        None,
                        |i, c, ui| {
                            let x = conns[i];
                            ui.monospace(match c {
                                0 => x.proto.clone(),
                                1 => x.local.clone(),
                                2 => x.remote.clone(),
                                3 => x.state.clone(),
                                4 => x.pid.map(|p| p.to_string()).unwrap_or_default(),
                                _ => x.process.clone(),
                            });
                        },
                        |i, ui| {
                            let remote = conns[i].remote.clone();
                            if !remote.is_empty() {
                                super::send_menu(ui, &remote, nav, Tool::Host);
                            }
                        },
                    );
                });
        });
    }
}

