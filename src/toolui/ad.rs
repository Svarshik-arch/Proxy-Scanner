use egui::RichText;

use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::ad::{self, Config, Event, Report};
use crate::tools::tlsaudit::Severity;

pub struct Panel {
    pub cfg: Config,
    pub report: Option<Report>,
    task: Option<Task<Event>>,
    log: Vec<String>,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: None,
            task: None,
            log: Vec::new(),
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
                Event::Report(r) => self.report = Some(*r),
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "ad", &mut self.cfg);
        let c = &mut self.cfg;
        ui.label("Домен");
        super::singleline(ui, &mut c.domain, "пусто — домен этой машины");
        ui.add_space(4.0);
        let (start, stop) = super::run_button(ui, self.busy(), "Проверить домен");
        if start {
            self.log.clear();
            self.report = None;
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| ad::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in &self.log {
            ui.weak(l);
        }
        let c = &mut self.cfg;
        super::advanced(ui, "ad_adv", |ui| {
            ui.label("Контроллеры вручную");
            super::singleline(ui, &mut c.dcs, "dc01.corp.local, 10.0.0.10");
            ui.label("DNS-серверы");
            super::singleline(ui, &mut c.dns_servers, "system");
            egui::Grid::new("ad_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(300..=30_000)));
                super::labeled(ui, "Сдвиг часов, предупреждать от, с", |ui| ui.add(egui::DragValue::new(&mut c.skew_warn_s).range(1.0..=300.0)));
            });
            ui.checkbox(&mut c.check_ldaps, "Проверять сертификат LDAPS");
        });
        ui.add_space(6.0);
        ui.weak("Без входа и паролей: SRV-записи, порты, rootDSE, ответ KDC, NTP, подпись SMB.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let Some(r) = &self.report else {
            if self.busy() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Проверка домена…");
                });
            } else {
                ui.weak("Нажмите «Проверить домен». Домен определяется по DNS-суффиксу этой машины.");
            }
            return;
        };
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let high = r.findings.iter().any(|f| f.severity == Severity::High);
            ui.horizontal_wrapped(|ui| {
                ui.heading(&r.domain);
                if !r.verdict.is_empty() {
                    ui.label(RichText::new(&r.verdict).strong().color(if r.dcs.is_empty() || high { RED } else { GREEN }));
                }
                super::export_buttons(ui, env, "ad", r, ad::render_text);
            });
            ui.weak(format!("область Kerberos {} · DNS: {}", r.realm, r.dns_servers.join(", ")));
            ui.add_space(4.0);
            for f in &r.findings {
                let color = match f.severity {
                    Severity::High => RED,
                    Severity::Medium => AMBER,
                    _ => ui.visuals().weak_text_color(),
                };
                ui.colored_label(color, format!("• {}", f.text));
            }
            ui.add_space(6.0);
            for (dn, dc) in r.dcs.iter().enumerate() {
                let ok_ports = dc.ports.iter().filter(|p| p.open).count();
                let title = format!(
                    "{}  {}  ·  портов {}/{}",
                    dc.attr("dnsHostName").unwrap_or(&dc.host),
                    dc.ip.map(|i| i.to_string()).unwrap_or_default(),
                    ok_ports,
                    dc.ports.len()
                );
                let resp = egui::CollapsingHeader::new(RichText::new(title).strong())
                    .id_salt(("dc", dn))
                    .default_open(r.dcs.len() <= 3)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            for p in &dc.ports {
                                let color = if p.open { GREEN } else if p.required { RED } else { AMBER };
                                ui.label(RichText::new(format!("{} {}", p.port, if p.open { "✔" } else { "✖" })).color(color))
                                    .on_hover_text(format!("{}{}", p.purpose, p.error.as_ref().map(|e| format!(": {e}")).unwrap_or_default()));
                            }
                        });
                        egui::Grid::new(("dc_g", dn)).num_columns(2).show(ui, |ui| {
                            let mut row = |k: &str, v: RichText| {
                                ui.weak(k);
                                ui.label(v);
                                ui.end_row();
                            };
                            for k in &dc.kdc {
                                row(
                                    &format!("Kerberos {}", k.transport),
                                    RichText::new(format!("{}{}", k.text, k.code.map(|c| format!(" (код {c})")).unwrap_or_default()))
                                        .color(if k.ok { GREEN } else { RED }),
                                );
                            }
                            if let Some((skew, src)) = dc.skew() {
                                let color = if skew.abs() > 300.0 { RED } else if skew.abs() > 60.0 { AMBER } else { GREEN };
                                row("Сдвиг часов", RichText::new(format!("{skew:+.1} с ({src})")).color(color));
                            }
                            if let Some(e) = &dc.ldap_error {
                                row("LDAP", RichText::new(e).color(RED));
                            }
                            if let Some(v) = dc.attr("defaultNamingContext") {
                                row("Контекст", RichText::new(v).monospace());
                            }
                            if let Some(v) = dc.attr("domainControllerFunctionality") {
                                row("Уровень DC", RichText::new(format!("{v} {}", ad::functional_level(v))));
                            }
                            if let Some(v) = dc.attr("domainFunctionality") {
                                row("Уровень домена", RichText::new(format!("{v} {}", ad::functional_level(v))));
                            }
                            for (k, label) in [("isGlobalCatalogReady", "Global Catalog"), ("isSynchronized", "Синхронизирован")] {
                                if let Some(v) = dc.attr(k) {
                                    row(label, RichText::new(if v.eq_ignore_ascii_case("TRUE") { "да" } else { "нет" }));
                                }
                            }
                            if let Some(v) = &dc.smb {
                                let req = dc.smb_signing_required == Some(true);
                                row(
                                    "SMB",
                                    RichText::new(format!("{v}, подпись {}", if req { "обязательна" } else { "не обязательна" }))
                                        .color(if req { GREEN } else { RED }),
                                );
                            }
                            if let Some(t) = &dc.ldaps
                                && let Some(l) = t.chain.first()
                            {
                                let bad = t.trust_error.is_some() || l.days_left < 30;
                                row(
                                    "LDAPS",
                                    RichText::new(format!(
                                        "{} {} · {} дн.{}",
                                        t.version,
                                        l.short_subject(),
                                        l.days_left,
                                        t.trust_error.as_ref().map(|e| format!(" · {e}")).unwrap_or_default()
                                    ))
                                    .color(if bad { AMBER } else { GREEN }),
                                );
                            }
                            if let Some(p) = &dc.ptr {
                                row("PTR", RichText::new(p).monospace());
                            }
                        });
                    });
                if let Some(ip) = dc.ip {
                    resp.header_response.context_menu(|ui| super::send_menu(ui, &ip.to_string(), env.nav, Tool::Ad));
                }
            }
            egui::CollapsingHeader::new("SRV-записи").default_open(r.dcs.is_empty()).show(ui, |ui| {
                egui::Grid::new("ad_srv").striped(true).show(ui, |ui| {
                    for s in &r.srv {
                        ui.monospace(&s.name);
                        ui.weak(&s.purpose);
                        if s.records.is_empty() {
                            ui.colored_label(AMBER, s.error.clone().unwrap_or("нет записей".into()));
                        } else {
                            ui.monospace(s.records.join("\n"));
                        }
                        ui.end_row();
                    }
                });
            });
        });
    }
}
