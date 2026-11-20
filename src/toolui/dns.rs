use egui::RichText;

use super::{AMBER, Env, GREEN, RED, Tool};
use crate::tools::Task;
use crate::tools::dns::{self, Config, Event, Report, Transport};

#[derive(PartialEq, Eq, Clone, Copy)]
enum View {
    Answers,
    Compare,
}

pub struct Panel {
    pub cfg: Config,
    pub report: Report,
    task: Option<Task<Event>>,
    log: Vec<String>,
    total: usize,
    view: View,
}

const QUICK_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA", "DS", "DNSKEY", "ANY"];

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            report: Report::default(),
            task: None,
            log: Vec::new(),
            total: 0,
            view: View::Answers,
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
                Event::Answer(a) => self.report.answers.push(*a),
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        super::preset_bar(ui, env, "dns", &mut self.cfg);
        let c = &mut self.cfg;
        ui.label("Имена (или IP — для PTR)");
        super::multiline(ui, &mut c.names, 3, "example.com\n_ldap._tcp.dc._msdcs.{domain}\n10.0.0.1");
        if super::from_scan(
            ui,
            &env.scan,
            &[(format!("имена найденных узлов (PTR, {})", env.scan.hosts().len()), "Обратные записи для узлов из сканирования")],
        )
        .is_some()
        {
            c.names = env.scan.hosts().iter().map(|h| h.to_string()).collect::<Vec<_>>().join("\n");
            c.types = "PTR".into();
        }
        ui.label("Типы записей");
        super::singleline(ui, &mut c.types, "A AAAA MX");
        ui.horizontal_wrapped(|ui| {
            for t in QUICK_TYPES {
                let present = c.types.split(|ch: char| ch == ',' || ch.is_whitespace()).any(|x| x.eq_ignore_ascii_case(t));
                if ui.selectable_label(present, *t).clicked() {
                    let mut list: Vec<String> = c
                        .types
                        .split(|ch: char| ch == ',' || ch.is_whitespace())
                        .filter(|x| !x.is_empty())
                        .map(String::from)
                        .collect();
                    if present {
                        list.retain(|x| !x.eq_ignore_ascii_case(t));
                    } else {
                        list.push(t.to_string());
                    }
                    c.types = list.join(" ");
                }
            }
        });
        ui.label("Серверы");
        super::multiline(ui, &mut c.servers, 2, "system, 10.0.0.53, tls://1.1.1.1, https://dns.example/dns-query");
        ui.checkbox(&mut c.dnssec, "DNSSEC");
        super::advanced(ui, "dns_adv", |ui| {
            ui.horizontal(|ui| {
                ui.label("Транспорт по умолчанию");
                egui::ComboBox::from_id_salt("dns_tr").selected_text(c.transport.label()).show_ui(ui, |ui| {
                    for t in Transport::ALL {
                        ui.selectable_value(&mut c.transport, t, t.label());
                    }
                });
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut c.recursion, "Рекурсия (RD)");
                ui.checkbox(&mut c.checking_disabled, "CD");
                ui.checkbox(&mut c.nsid, "NSID");
            });
            egui::Grid::new("dns_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "Таймаут, мс", |ui| ui.add(egui::DragValue::new(&mut c.timeout_ms).range(100..=30_000)));
                super::labeled(ui, "Повторов", |ui| ui.add(egui::DragValue::new(&mut c.retries).range(0..=5)));
            });
        });
        ui.add_space(6.0);
        let (start, stop) = super::run_button(ui, self.busy(), "Запросить");
        if start {
            self.report = Report::default();
            self.log.clear();
            let cfg = self.cfg.clone();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| dns::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        for l in &self.log {
            ui.colored_label(RED, l);
        }
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.view, View::Answers, "Ответы");
            ui.selectable_value(&mut self.view, View::Compare, "Сравнение серверов");
            if self.total > 0 {
                ui.label(format!("{} / {}", self.report.answers.len(), self.total));
            }
            if self.busy() {
                ui.spinner();
            }
            if !self.report.answers.is_empty() {
                super::export_buttons(ui, env, "dns", &self.report, dns::render_text);
            }
        });
        ui.separator();
        let nav = &mut *env.nav;
        match self.view {
            View::Answers => {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    for (i, a) in self.report.answers.iter().enumerate() {
                        let status = if a.error.is_some() {
                            RichText::new("ошибка").color(RED)
                        } else if a.rcode == "NOERROR" {
                            RichText::new(if a.answers.is_empty() { "NOERROR (пусто)" } else { "NOERROR" }).color(if a.answers.is_empty() { AMBER } else { GREEN })
                        } else {
                            RichText::new(&a.rcode).color(AMBER)
                        };
                        let title = format!(
                            "{} {} @{} ({}) {}",
                            a.name,
                            a.qtype,
                            a.server,
                            a.transport.label(),
                            super::opt_ms(a.rtt_ms)
                        );
                        egui::CollapsingHeader::new(RichText::new(title).monospace())
                            .id_salt(("dns_ans", i))
                            .default_open(self.report.answers.len() <= 12)
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(status);
                                    ui.weak(format!("флаги: {}", a.flags));
                                    if a.flags.contains("ad") {
                                        ui.colored_label(GREEN, "DNSSEC подтверждён (AD)");
                                    }
                                    if a.tcp_fallback {
                                        ui.weak("ответ обрезан по UDP → TCP");
                                    }
                                    if let Some(n) = &a.nsid {
                                        ui.weak(format!("NSID {n}"));
                                    }
                                    ui.weak(format!("{} байт", a.size));
                                });
                                if let Some(e) = &a.error {
                                    ui.colored_label(RED, e);
                                }
                                for (title, recs) in [("ответ", &a.answers), ("полномочия", &a.authority), ("дополнительно", &a.additional)] {
                                    if recs.is_empty() {
                                        continue;
                                    }
                                    ui.weak(title);
                                    egui::Grid::new(("dns_recs", i, title)).striped(true).show(ui, |ui| {
                                        for r in recs {
                                            ui.monospace(&r.name);
                                            ui.monospace(r.ttl.to_string());
                                            ui.monospace(&r.rtype);
                                            let resp = ui.add(egui::Label::new(RichText::new(&r.data).monospace()).sense(egui::Sense::click()));
                                            let target = record_target(&r.rtype, &r.data);
                                            resp.context_menu(|ui| {
                                                if ui.button("Копировать").clicked() {
                                                    ui.ctx().copy_text(r.data.clone());
                                                    ui.close();
                                                }
                                                if let Some(t) = &target {
                                                    ui.separator();
                                                    super::send_menu(ui, t, nav, Tool::Dns);
                                                }
                                            });
                                            ui.end_row();
                                        }
                                    });
                                }
                            });
                    }
                });
            }
            View::Compare => {
                let groups = dns::compare(&self.report.answers);
                let mut servers: Vec<String> = Vec::new();
                for a in &self.report.answers {
                    if !servers.contains(&a.server) {
                        servers.push(a.server.clone());
                    }
                }
                egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                    egui::Grid::new("dns_cmp").striped(true).show(ui, |ui| {
                        ui.strong("запрос");
                        for s in &servers {
                            ui.strong(s);
                        }
                        ui.end_row();
                        for ((name, t), answers, differ) in &groups {
                            let label = RichText::new(format!("{name} {t}")).monospace();
                            ui.label(if *differ { label.color(AMBER) } else { label });
                            for s in &servers {
                                match answers.iter().find(|a| &a.server == s) {
                                    Some(a) => {
                                        let text = format!("{} · {}", a.summary(), super::opt_ms(a.rtt_ms));
                                        let rt = RichText::new(text).monospace();
                                        ui.label(if a.error.is_some() { rt.color(RED) } else if *differ { rt.color(AMBER) } else { rt });
                                    }
                                    None => {
                                        ui.weak("—");
                                    }
                                }
                            }
                            ui.end_row();
                        }
                    });
                });
            }
        }
    }
}

/// Узел из данных записи (A/AAAA — адрес, MX/SRV/NS/CNAME/PTR — имя).
fn record_target(rtype: &str, data: &str) -> Option<String> {
    let last = data.split_whitespace().last()?.trim_end_matches('.').to_string();
    match rtype {
        "A" | "AAAA" | "NS" | "CNAME" | "PTR" => Some(data.trim_end_matches('.').to_string()),
        "MX" => Some(last),
        "SRV" => {
            let port = data.split_whitespace().nth(2)?;
            Some(format!("{last}:{port}"))
        }
        _ => None,
    }
}
