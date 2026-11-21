//! Интерфейсы по SNMP и топология L2.

use std::collections::{BTreeMap, VecDeque};

use egui::RichText;
use egui_extras::{Column, TableBuilder};

use super::{AMBER, Env, GREEN, RED};
use crate::devices::Device;
use crate::graph::{GraphSettings, GraphView};
use crate::tools::Task;
use crate::tools::ifmon::{self, Config, Counters, Event, Rate, Severity, TopoConfig, TopoEvent, Topology};

const HISTORY: usize = 180;

#[derive(Default)]
struct Dev {
    name: String,
    error: Option<String>,
    at: f64,
    ports: Vec<Counters>,
    rates: BTreeMap<u32, Rate>,
    /// Загрузка (большее из направлений, бит/с) по портам.
    history: BTreeMap<u32, VecDeque<Option<f64>>>,
}

pub struct Panel {
    pub cfg: Config,
    task: Option<Task<Event>>,
    devs: BTreeMap<String, Dev>,
    only_problems: bool,
    hide_down: bool,
    selected: Option<(String, u32)>,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self { cfg, task: None, devs: BTreeMap::new(), only_problems: false, hide_down: true, selected: None }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// Порты с плохими выводами.
    pub fn problems(&self) -> usize {
        self.devs
            .values()
            .flat_map(|d| d.ports.iter().map(move |p| (d, p)))
            .filter(|(d, p)| ifmon::verdicts(p, d.rates.get(&p.index), self.cfg.warn_util).iter().any(|v| v.0 == Severity::Bad))
            .count()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let ev = t.drain();
        let fin = t.finished();
        let ch = !ev.is_empty() || fin;
        for e in ev {
            match e {
                Event::Sample(addr, name, at, ports) => {
                    let d = self.devs.entry(addr).or_default();
                    d.name = name;
                    d.error = None;
                    if !d.ports.is_empty() {
                        let dt = at - d.at;
                        for p in &ports {
                            if let Some(old) = d.ports.iter().find(|o| o.index == p.index) {
                                let r = ifmon::rate(old, p, dt);
                                let h = d.history.entry(p.index).or_default();
                                h.push_back(Some(r.in_bps.max(r.out_bps)));
                                while h.len() > HISTORY {
                                    h.pop_front();
                                }
                                d.rates.insert(p.index, r);
                            }
                        }
                    }
                    d.at = at;
                    d.ports = ports;
                }
                Event::Error(addr, e) => self.devs.entry(addr).or_default().error = Some(e),
            }
        }
        if fin {
            self.task = None;
        }
        ch
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, list: &[Device]) {
        ui.label("Устройства (адрес [community] в строке)");
        super::multiline(ui, &mut self.cfg.targets, 4, "10.0.0.1\n10.0.0.2 secret");
        let with_snmp: Vec<&Device> = list.iter().filter(|d| !d.community.is_empty()).collect();
        if !with_snmp.is_empty() && ui.small_button(format!("из «Устройств» ({})", with_snmp.len())).on_hover_text("Устройства, у которых указан SNMP community").clicked() {
            self.cfg.targets = with_snmp.iter().map(|d| format!("{} {}", d.host, d.community)).collect::<Vec<_>>().join("\n");
        }
        egui::Grid::new("ifm_grid").num_columns(2).show(ui, |ui| {
            super::labeled(ui, "Community", |ui| ui.text_edit_singleline(&mut self.cfg.community));
            super::labeled(ui, "Опрос, с", |ui| ui.add(egui::DragValue::new(&mut self.cfg.interval_s).range(2..=3600)));
            super::labeled(ui, "Порог загрузки, %", |ui| ui.add(egui::DragValue::new(&mut self.cfg.warn_util).range(10.0..=99.0)));
        });
        let (start, stop) = super::run_button(ui, self.busy(), "Наблюдать");
        if start && !self.cfg.targets.trim().is_empty() {
            let cfg = self.cfg.clone();
            self.devs.clear();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| ifmon::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        ui.checkbox(&mut self.only_problems, "Только порты с замечаниями");
        ui.checkbox(&mut self.hide_down, "Скрыть выключенные и без линка");
        ui.add_space(6.0);
        ui.weak("Скорость считается между опросами, поэтому появится со второго опроса. Нужен SNMP v2c на чтение.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui) {
        if self.devs.is_empty() {
            ui.weak("Впишите адреса коммутаторов и нажмите «Наблюдать»: загрузка портов, ошибки, дуплекс, флапы — и что с этим делать.");
            return;
        }
        // Сводка выводов.
        let mut all: Vec<(Severity, String)> = Vec::new();
        for (a, d) in &self.devs {
            if let Some(e) = &d.error {
                all.push((Severity::Bad, format!("{a}: {e}")));
            }
            for p in &d.ports {
                for (s, t) in ifmon::verdicts(p, d.rates.get(&p.index), self.cfg.warn_util) {
                    all.push((s, format!("{} {}: {t}", if d.name.is_empty() { a } else { &d.name }, p.name)));
                }
            }
        }
        all.sort_by_key(|x| x.0);
        if all.is_empty() {
            ui.colored_label(GREEN, "✔ замечаний нет");
        } else {
            egui::CollapsingHeader::new(RichText::new(format!("Выводы: {}", all.len())).strong()).default_open(true).show(ui, |ui| {
                egui::ScrollArea::vertical().id_salt("ifm_sum").max_height(140.0).show(ui, |ui| {
                    for (s, t) in &all {
                        ui.colored_label(if *s == Severity::Bad { RED } else { AMBER }, t);
                    }
                });
            });
        }
        if let Some((a, i)) = &self.selected
            && let Some(d) = self.devs.get(a)
            && let Some(h) = d.history.get(i)
        {
            let p = d.ports.iter().find(|p| p.index == *i);
            ui.horizontal(|ui| {
                ui.label(format!("{} {}:", d.name, p.map(|p| p.name.as_str()).unwrap_or("")));
                let v: Vec<Option<f64>> = h.iter().copied().collect();
                super::sparkline(ui, &v, 300.0);
                if let Some(r) = d.rates.get(i) {
                    ui.label(format!("↓ {}  ↑ {}", ifmon::human_bps(r.in_bps), ifmon::human_bps(r.out_bps)));
                }
            });
        }
        let mut select = None;
        egui::ScrollArea::vertical().id_salt("ifm_devs").auto_shrink([false, false]).show(ui, |ui| {
            for (a, d) in &self.devs {
                let title = if d.name.is_empty() { a.clone() } else { format!("{} ({a})", d.name) };
                egui::CollapsingHeader::new(RichText::new(title).strong()).id_salt(("ifm", a)).default_open(true).show(ui, |ui| {
                    if let Some(e) = &d.error {
                        ui.colored_label(RED, e);
                    }
                    let ports: Vec<&Counters> = d
                        .ports
                        .iter()
                        .filter(|p| !self.hide_down || (p.oper == 1 || (p.admin == 1 && !p.alias.is_empty())))
                        .filter(|p| !self.only_problems || !ifmon::verdicts(p, d.rates.get(&p.index), self.cfg.warn_util).is_empty())
                        .collect();
                    TableBuilder::new(ui)
                        .id_salt(("ifm_t", a))
                        .striped(true)
                        .sense(egui::Sense::click())
                        .column(Column::initial(110.0).clip(true))
                        .column(Column::initial(140.0).clip(true))
                        .column(Column::initial(70.0))
                        .column(Column::initial(90.0))
                        .column(Column::initial(90.0))
                        .column(Column::initial(90.0))
                        .column(Column::initial(60.0))
                        .column(Column::remainder().clip(true))
                        .header(20.0, |mut h| {
                            for t in ["Порт", "Описание", "Состояние", "Скорость", "Вход", "Выход", "Загрузка", "Вывод"] {
                                h.col(|ui| {
                                    ui.strong(t);
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(18.0, ports.len(), |mut row| {
                                let p = ports[row.index()];
                                let r = d.rates.get(&p.index);
                                let v = ifmon::verdicts(p, r, self.cfg.warn_util);
                                row.col(|ui| {
                                    ui.label(&p.name);
                                });
                                row.col(|ui| {
                                    ui.label(&p.alias);
                                });
                                row.col(|ui| {
                                    match (p.admin, p.oper) {
                                        (2, _) => ui.weak("выключен"),
                                        (_, 1) => ui.colored_label(GREEN, if p.duplex == 2 { "up, half" } else { "up" }),
                                        _ => ui.colored_label(AMBER, "нет линка"),
                                    };
                                });
                                row.col(|ui| {
                                    ui.label(if p.speed_mbps >= 1000 { format!("{} Гбит/с", p.speed_mbps / 1000) } else if p.speed_mbps > 0 { format!("{} Мбит/с", p.speed_mbps) } else { String::new() });
                                });
                                row.col(|ui| {
                                    ui.label(r.map(|r| ifmon::human_bps(r.in_bps)).unwrap_or_default());
                                });
                                row.col(|ui| {
                                    ui.label(r.map(|r| ifmon::human_bps(r.out_bps)).unwrap_or_default());
                                });
                                row.col(|ui| {
                                    if let Some(u) = r.and_then(|r| r.util) {
                                        let c = if u >= 90.0 { RED } else if u >= self.cfg.warn_util { AMBER } else { GREEN };
                                        ui.add(egui::ProgressBar::new((u / 100.0).clamp(0.0, 1.0) as f32).fill(c).text(format!("{u:.0}%")));
                                    }
                                });
                                row.col(|ui| {
                                    if let Some((s, t)) = v.first() {
                                        ui.colored_label(if *s == Severity::Bad { RED } else { AMBER }, t).on_hover_text(v.iter().map(|x| x.1.clone()).collect::<Vec<_>>().join("\n"));
                                    }
                                });
                                if row.response().clicked() {
                                    select = Some((a.clone(), p.index));
                                }
                            });
                        });
                });
            }
        });
        if select.is_some() {
            self.selected = select;
        }
    }
}

// ---------------------------------------------------------------------------
// Топология
// ---------------------------------------------------------------------------

pub struct Topo {
    pub cfg: TopoConfig,
    task: Option<Task<TopoEvent>>,
    pub topo: Topology,
    log: String,
    graph: GraphView,
    settings: GraphSettings,
    nodes: Vec<crate::graph::MapNode>,
    view: u8,
}

impl Topo {
    pub fn new(cfg: TopoConfig) -> Self {
        Self { cfg, task: None, topo: Topology::default(), log: String::new(), graph: GraphView::default(), settings: GraphSettings::default(), nodes: Vec::new(), view: 0 }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    pub fn count(&self) -> usize {
        self.topo.nodes.len()
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let ev = t.drain();
        let fin = t.finished();
        let ch = !ev.is_empty() || fin;
        for e in ev {
            match e {
                TopoEvent::Log(l) => self.log = l,
                TopoEvent::Node(n, links) => {
                    self.topo.nodes.push(n);
                    self.topo.links.extend(links);
                    self.nodes = ifmon::map_nodes(&self.topo);
                    self.graph.reheat();
                }
            }
        }
        if fin {
            self.task = None;
            self.log.clear();
        }
        ch
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env, list: &[Device], gateways: &[String]) {
        ui.label("С каких устройств начать (адрес [community])");
        super::multiline(ui, &mut self.cfg.seeds, 3, "10.0.0.1");
        ui.horizontal_wrapped(|ui| {
            let with_snmp: Vec<&Device> = list.iter().filter(|d| !d.community.is_empty()).collect();
            if !with_snmp.is_empty() && ui.small_button(format!("из «Устройств» ({})", with_snmp.len())).clicked() {
                self.cfg.seeds = with_snmp.iter().map(|d| format!("{} {}", d.host, d.community)).collect::<Vec<_>>().join("\n");
            }
            if !gateways.is_empty() && ui.small_button("мой шлюз").clicked() {
                self.cfg.seeds = gateways.join("\n");
            }
        });
        egui::Grid::new("topo_grid").num_columns(2).show(ui, |ui| {
            super::labeled(ui, "Community", |ui| ui.text_edit_singleline(&mut self.cfg.community));
            super::labeled(ui, "Не больше устройств", |ui| ui.add(egui::DragValue::new(&mut self.cfg.max_devices).range(1..=1000)));
        });
        ui.checkbox(&mut self.cfg.recurse, "Идти дальше по соседям").on_hover_text("Опросить соседей по адресу управления из LLDP/CDP, и их соседей…");
        let (start, stop) = super::run_button(ui, self.busy(), "Построить");
        if start && !self.cfg.seeds.trim().is_empty() {
            let cfg = self.cfg.clone();
            self.topo = Topology::default();
            self.nodes.clear();
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| ifmon::discover(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        if self.busy() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak(format!("{} · опрошено {}", self.log, self.topo.nodes.len()));
            });
        }
        ui.add_space(6.0);
        ui.weak("Связи берутся из таблиц соседей LLDP и CDP. Оранжевые — соседи, которых не удалось опросить (нет адреса управления или SNMP).");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui) {
        if self.topo.nodes.is_empty() {
            ui.weak("Укажите один-два коммутатора и нажмите «Построить»: программа пройдёт по соседям LLDP/CDP и нарисует схему, кто в какой порт подключён.");
            return;
        }
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.view, 0, "Схема");
            ui.selectable_value(&mut self.view, 1, format!("Связи ({})", self.topo.links.len()));
            let errs: Vec<String> = self.topo.nodes.iter().filter_map(|n| n.error.as_ref().map(|e| format!("{}: {e}", n.address))).collect();
            if !errs.is_empty() {
                ui.colored_label(RED, format!("не ответили: {}", errs.len())).on_hover_text(errs.join("\n"));
            }
        });
        if self.view == 0 {
            self.graph.ui_map(ui, &self.nodes, &mut self.settings);
            return;
        }
        let rows: Vec<Vec<String>> = self
            .topo
            .links
            .iter()
            .map(|l| vec![l.from.clone(), l.from_port.clone(), l.to.clone(), l.to_port.clone(), l.to_address.clone().unwrap_or_default(), l.via.to_uppercase()])
            .collect();
        let h: Vec<String> = ["Устройство", "Порт", "Сосед", "Порт соседа", "Адрес соседа", "Протокол"].iter().map(|s| s.to_string()).collect();
        super::devices::table(ui, "topo_links", &h, &rows);
    }
}
