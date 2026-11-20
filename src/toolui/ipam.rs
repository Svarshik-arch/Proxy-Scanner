use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use egui::RichText;

use super::{AMBER, Env, GREEN, RED, Tool};
use crate::hostcard::HostNote;
use crate::tools::Task;
use crate::tools::ipam::{self, Config, DnsCheck, Event, Known};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Show {
    All,
    Used,
    Free,
    Stale,
    Problems,
}

pub struct Panel {
    pub cfg: Config,
    pub dns: BTreeMap<Ipv4Addr, DnsCheck>,
    task: Option<Task<Event>>,
    total: usize,
    show: Show,
    subnet: usize,
    want_free: u32,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            dns: BTreeMap::new(),
            task: None,
            total: 0,
            show: Show::All,
            subnet: 0,
            want_free: 10,
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
                Event::Total(n) => self.total = n,
                Event::Dns(ip, c) => {
                    self.dns.insert(ip, c);
                }
            }
        }
        if finished {
            self.task = None;
        }
        changed
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, known: &BTreeMap<Ipv4Addr, Known>) {
        super::preset_bar(ui, env, "ipam", &mut self.cfg);
        ui.horizontal(|ui| {
            ui.label("Подсети учёта");
            if let Some(cidr) = &env.local_cidr
                && ui.small_button(format!("моя подсеть {cidr}")).clicked()
            {
                self.cfg.subnets = cidr.clone();
            }
        });
        super::multiline(ui, &mut self.cfg.subnets, 2, "пусто — /24 всех найденных узлов");
        super::subnet_hint(ui, &self.cfg.subnets);
        if super::from_scan(ui, &env.scan, &[("сеть сканирования".into(), "Те же сети, что сканировались на вкладке «Прокси»")]).is_some() {
            self.cfg.subnets = env.scan.targets.clone();
        }
        ui.horizontal(|ui| {
            ui.label("«Давно не было» — дней");
            ui.add(egui::DragValue::new(&mut self.cfg.stale_days).range(1..=3650));
        });
        ui.add_space(4.0);
        let (start, stop) = super::run_button(ui, self.busy(), "Проверить DNS");
        if start {
            self.dns.clear();
            let ips: Vec<Ipv4Addr> = known.keys().copied().collect();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| ipam::check_dns(ips, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if self.busy() {
            super::progress(ui, self.dns.len() as u64, self.total as u64, true);
        }
        ui.add_space(6.0);
        ui.weak("Занятые адреса берутся из всего собранного: «Узлы», «Наблюдение», ARP-таблица, прокси, сервисы, прослушивание. Чем больше проверок проведено, тем точнее учёт.");
        ui.weak("«Проверить DNS» — обратная запись для каждого занятого адреса и совпадение прямой записи.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, known: &BTreeMap<Ipv4Addr, Known>, notes: &BTreeMap<String, HostNote>) {
        let nets = match ipam::subnets(&self.cfg, known) {
            Ok(n) => n,
            Err(e) => {
                ui.colored_label(RED, e);
                return;
            }
        };
        if nets.is_empty() {
            ui.weak("Учитывать нечего: запустите «Узлы» или «Наблюдение» либо укажите подсети слева.");
            return;
        }
        if self.subnet >= nets.len() {
            self.subnet = 0;
        }
        let now = crate::session::now_unix();
        let stale_after = self.cfg.stale_days * 86_400;
        // Сводка по подсетям.
        egui::ScrollArea::horizontal().id_salt("ipam_nets").show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, (net, p)) in nets.iter().enumerate() {
                    let range = ipam::hosts_of(*net, *p);
                    let total = (range.end() - range.start() + 1) as usize;
                    let used = range.filter(|a| known.contains_key(&Ipv4Addr::from(*a))).count();
                    let share = used as f32 / total.max(1) as f32;
                    let color = if share > 0.9 { RED } else if share > 0.75 { AMBER } else { GREEN };
                    let r = egui::Frame::group(ui.style())
                        .stroke(egui::Stroke::new(if i == self.subnet { 2.0 } else { 1.0 }, if i == self.subnet { ui.visuals().selection.bg_fill } else { ui.visuals().widgets.noninteractive.bg_stroke.color }))
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.set_width(180.0);
                                ui.label(RichText::new(format!("{net}/{p}")).strong().monospace());
                                let (rect, _) = ui.allocate_exact_size(egui::vec2(170.0, 8.0), egui::Sense::hover());
                                ui.painter().rect_filled(rect, 2.0, ui.visuals().faint_bg_color);
                                let mut f = rect;
                                f.set_width(rect.width() * share);
                                ui.painter().rect_filled(f, 2.0, color);
                                ui.label(RichText::new(format!("занято {used} из {total}")).small());
                                ui.label(RichText::new(format!("свободно {}", total - used)).small());
                            });
                        })
                        .response
                        .interact(egui::Sense::click());
                    if r.clicked() {
                        self.subnet = i;
                    }
                }
            });
        });
        let (net, p) = nets[self.subnet];
        let free = ipam::free_ranges(net, p, known);
        ui.horizontal_wrapped(|ui| {
            ui.label("Свободные:");
            for (a, b) in free.iter().take(8) {
                let n = u32::from(*b) - u32::from(*a) + 1;
                ui.monospace(if a == b { a.to_string() } else { format!("{a} – {b} ({n})") });
            }
            if free.len() > 8 {
                ui.weak(format!("и ещё {} диапазонов", free.len() - 8));
            }
        });
        ui.horizontal(|ui| {
            ui.add(egui::DragValue::new(&mut self.want_free).range(1..=1024));
            if ui.button("свободных адресов — скопировать").clicked() {
                let list: Vec<String> = free
                    .iter()
                    .flat_map(|(a, b)| (u32::from(*a)..=u32::from(*b)).map(Ipv4Addr::from))
                    .take(self.want_free as usize)
                    .map(|a| a.to_string())
                    .collect();
                ui.ctx().copy_text(list.join("\n"));
                *env.message = Some(format!("скопировано свободных адресов: {}", list.len()));
            }
        });
        ui.horizontal(|ui| {
            for (s, label) in [(Show::All, "все"), (Show::Used, "занятые"), (Show::Free, "свободные"), (Show::Stale, "давно не было"), (Show::Problems, "проблемы")] {
                ui.selectable_value(&mut self.show, s, label);
            }
        });
        // Строки.
        struct Row {
            ip: Ipv4Addr,
            known: Option<Known>,
            problem: Vec<String>,
            stale: bool,
        }
        let rows: Vec<Row> = ipam::hosts_of(net, p)
            .map(Ipv4Addr::from)
            .filter_map(|ip| {
                let k = known.get(&ip).cloned();
                let mut problem = Vec::new();
                if let Some(k) = &k
                    && k.mac.len() > 1
                {
                    problem.push(format!("конфликт: {} MAC", k.mac.len()));
                }
                if let Some(d) = self.dns.get(&ip) {
                    match (&d.ptr, d.forward_ok) {
                        (None, _) => problem.push("нет обратной записи DNS".into()),
                        (Some(n), Some(false)) => problem.push(format!("{n} указывает на {}", if d.forward.is_empty() { "ничего".into() } else { d.forward.join(", ") })),
                        _ => {}
                    }
                }
                let stale = k.as_ref().and_then(|k| k.last_seen).is_some_and(|l| now.saturating_sub(l) > stale_after);
                let keep = match self.show {
                    Show::All => true,
                    Show::Used => k.is_some(),
                    Show::Free => k.is_none(),
                    Show::Stale => stale,
                    Show::Problems => !problem.is_empty(),
                };
                keep.then_some(Row { ip, known: k, problem, stale })
            })
            .collect();
        let nav = &mut *env.nav;
        super::table(
            ui,
            "ipam_rows",
            &[("Адрес", 110.0), ("Состояние", 90.0), ("Имя", 170.0), ("MAC", 130.0), ("Последний раз", 130.0), ("DNS", 180.0), ("Метки", 120.0), ("Откуда", 150.0)],
            rows.len(),
            None,
            |i, col, ui| {
                let r = &rows[i];
                let ips = r.ip.to_string();
                match col {
                    0 => {
                        ui.monospace(&ips);
                    }
                    1 => {
                        match (&r.known, r.stale, r.problem.is_empty()) {
                            (None, _, _) => ui.weak("свободен"),
                            (Some(_), _, false) => ui.colored_label(RED, "занят ⚠").on_hover_text(r.problem.join("\n")),
                            (Some(_), true, _) => ui.colored_label(AMBER, "давно не было"),
                            (Some(_), false, true) => ui.colored_label(GREEN, "занят"),
                        };
                    }
                    2 => {
                        ui.label(r.known.as_ref().and_then(|k| k.name.clone()).unwrap_or_default());
                    }
                    3 => {
                        ui.monospace(r.known.as_ref().map(|k| k.mac.join(", ")).unwrap_or_default());
                    }
                    4 => {
                        ui.weak(r.known.as_ref().and_then(|k| k.last_seen).map(crate::session::format_time).unwrap_or_default());
                    }
                    5 => {
                        if let Some(d) = self.dns.get(&r.ip) {
                            let t = d.ptr.clone().unwrap_or("—".into());
                            if d.forward_ok == Some(false) || d.ptr.is_none() {
                                ui.colored_label(AMBER, t).on_hover_text(r.problem.join("\n"));
                            } else {
                                ui.label(t);
                            }
                        }
                    }
                    6 => {
                        ui.label(notes.get(&ips).map(|n| n.tags.clone()).unwrap_or_default());
                    }
                    _ => {
                        ui.weak(r.known.as_ref().map(|k| k.sources.join(", ")).unwrap_or_default());
                    }
                }
            },
            |i, ui| super::send_menu(ui, &rows[i].ip.to_string(), nav, Tool::Ipam),
        );
    }
}
