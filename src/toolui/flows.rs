//! Коллектор NetFlow/sFlow/IPFIX и замер скорости.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;

use egui::RichText;

use super::{Env, GREEN, RED};
use crate::tools::Task;
use crate::tools::flows::{self, Config, Event, Flow};
use crate::tools::ifmon::human_bps;
use crate::tools::speed::{self, Direction};

#[derive(Default, Clone, Copy)]
struct Acc {
    bytes: u64,
    packets: u64,
    flows: u64,
}

impl Acc {
    fn add(&mut self, f: &Flow) {
        self.bytes += f.bytes;
        self.packets += f.packets;
        self.flows += 1;
    }
}

pub struct Panel {
    pub cfg: Config,
    task: Option<Task<Event>>,
    status: Option<Result<String, String>>,
    started: Option<std::time::Instant>,
    exporters: BTreeMap<IpAddr, (&'static str, Acc)>,
    src: HashMap<IpAddr, Acc>,
    dst: HashMap<IpAddr, Acc>,
    pairs: HashMap<(IpAddr, IpAddr), Acc>,
    apps: HashMap<String, Acc>,
    total: Acc,
    /// Байт за каждые 5 секунд.
    timeline: VecDeque<u64>,
    bucket: (u64, u64),
    view: u8,
}

impl Panel {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            task: None,
            status: None,
            started: None,
            exporters: BTreeMap::new(),
            src: HashMap::new(),
            dst: HashMap::new(),
            pairs: HashMap::new(),
            apps: HashMap::new(),
            total: Acc::default(),
            timeline: VecDeque::new(),
            bucket: (0, 0),
            view: 0,
        }
    }

    pub fn busy(&self) -> bool {
        self.task.is_some()
    }

    pub fn count(&self) -> usize {
        self.exporters.len()
    }

    fn clear(&mut self) {
        let cfg = self.cfg.clone();
        *self = Self::new(cfg);
    }

    pub fn poll(&mut self) -> bool {
        let Some(t) = &self.task else { return false };
        let ev = t.drain();
        let fin = t.finished();
        let ch = !ev.is_empty() || fin;
        let now = self.started.map(|s| s.elapsed().as_secs() / 5).unwrap_or(0);
        for e in ev {
            match e {
                Event::Status(s) => self.status = Some(s),
                Event::Flows(exp, kind, fl) => {
                    let x = self.exporters.entry(exp).or_insert((kind, Acc::default()));
                    for f in &fl {
                        x.1.add(f);
                        self.src.entry(f.src).or_default().add(f);
                        self.dst.entry(f.dst).or_default().add(f);
                        self.pairs.entry((f.src, f.dst)).or_default().add(f);
                        self.apps.entry(flows::app(f)).or_default().add(f);
                        self.total.add(f);
                        if self.bucket.0 != now {
                            self.timeline.push_back(self.bucket.1);
                            while self.timeline.len() > 120 {
                                self.timeline.pop_front();
                            }
                            self.bucket = (now, 0);
                        }
                        self.bucket.1 += f.bytes;
                    }
                }
            }
        }
        if fin {
            self.task = None;
        }
        ch
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.add_enabled_ui(!self.busy(), |ui| {
            egui::Grid::new("fl_grid").num_columns(2).show(ui, |ui| {
                super::labeled(ui, "NetFlow / IPFIX, UDP", |ui| ui.add(egui::DragValue::new(&mut self.cfg.netflow_port).range(1..=65535)));
                super::labeled(ui, "sFlow, UDP", |ui| ui.add(egui::DragValue::new(&mut self.cfg.sflow_port).range(1..=65535)));
                super::labeled(ui, "Слушать на", |ui| ui.add(egui::TextEdit::singleline(&mut self.cfg.bind).desired_width(120.0)));
            });
        });
        let (start, stop) = super::run_button(ui, self.busy(), "Принимать");
        if start {
            self.clear();
            let cfg = self.cfg.clone();
            self.started = Some(std::time::Instant::now());
            self.task = Some(Task::spawn(env.rt, &env.ctx, move |s, c| flows::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.task {
            t.cancel();
        }
        match &self.status {
            Some(Ok(t)) => {
                ui.colored_label(GREEN, format!("слушаем: {t}"));
            }
            Some(Err(e)) => {
                ui.colored_label(RED, e);
            }
            None => {}
        }
        ui.add_space(6.0);
        let ip = crate::tools::sitecheck::local_ip();
        egui::CollapsingHeader::new("Что ввести на устройстве").default_open(true).show(ui, |ui| {
            for l in [
                format!("ip flow-export destination {ip} {}   (Cisco)", self.cfg.netflow_port),
                format!("netstream export host {ip} {}   (Huawei)", self.cfg.netflow_port),
                format!("sflow collector-ip {ip} port {}", self.cfg.sflow_port),
                format!("/ip traffic-flow target add dst-address={ip} port={}   (MikroTik)", self.cfg.netflow_port),
            ] {
                ui.add(egui::Label::new(RichText::new(&l).monospace()).truncate()).on_hover_text(&l);
            }
        });
        ui.weak("Шаблоны NetFlow v9/IPFIX приходят раз в несколько минут — до первого шаблона данные v9 не видны. sFlow пересчитывается по частоте выборки.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui) {
        if self.total.flows == 0 {
            ui.weak(if self.busy() { "Ждём данные от маршрутизаторов и коммутаторов…" } else { "Нажмите «Принимать» и направьте NetFlow/sFlow/IPFIX с оборудования на эту машину: кто занимает канал, с кем и каким приложением." });
            for (a, (k, _)) in &self.exporters {
                ui.label(format!("{a}: {k}"));
            }
            return;
        }
        let secs = self.started.map(|s| s.elapsed().as_secs_f64()).unwrap_or(1.0).max(1.0);
        ui.horizontal_wrapped(|ui| {
            ui.strong(format!("Всего {} · в среднем {}", bytes(self.total.bytes), human_bps(self.total.bytes as f64 * 8.0 / secs)));
            ui.weak(format!("· записей {} · источников данных {}", self.total.flows, self.exporters.len()));
            let tl: Vec<Option<f64>> = self.timeline.iter().map(|b| Some(*b as f64 * 8.0 / 5.0)).collect();
            if tl.len() > 1 {
                super::sparkline(ui, &tl, 200.0);
            }
        });
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.view, 0, "Кто качает");
            ui.selectable_value(&mut self.view, 1, "Куда");
            ui.selectable_value(&mut self.view, 2, "Пары");
            ui.selectable_value(&mut self.view, 3, "Приложения");
            ui.selectable_value(&mut self.view, 4, "Источники данных");
        });
        let total = self.total.bytes.max(1) as f64;
        let rows: Vec<(String, Acc)> = match self.view {
            0 => top(self.src.iter().map(|(k, v)| (k.to_string(), *v))),
            1 => top(self.dst.iter().map(|(k, v)| (k.to_string(), *v))),
            2 => top(self.pairs.iter().map(|((a, b), v)| (format!("{a} → {b}"), *v))),
            3 => top(self.apps.iter().map(|(k, v)| (k.clone(), *v))),
            _ => top(self.exporters.iter().map(|(k, (kind, v))| (format!("{k} ({kind})"), *v))),
        };
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("fl_top").num_columns(4).striped(true).show(ui, |ui| {
                for (name, a) in rows.iter().take(100) {
                    let share = a.bytes as f64 / total;
                    ui.label(name);
                    ui.add(egui::ProgressBar::new(share as f32).desired_width(160.0).text(format!("{:.1}%", share * 100.0)));
                    ui.label(bytes(a.bytes));
                    ui.weak(format!("{} · {} пакетов", human_bps(a.bytes as f64 * 8.0 / secs), a.packets));
                    ui.end_row();
                }
            });
        });
    }
}

fn top(it: impl Iterator<Item = (String, Acc)>) -> Vec<(String, Acc)> {
    let mut v: Vec<(String, Acc)> = it.collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1.bytes));
    v
}

pub fn bytes(b: u64) -> String {
    let b = b as f64;
    if b >= 1e9 {
        format!("{:.2} ГБ", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} МБ", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.0} КБ", b / 1e3)
    } else {
        format!("{b:.0} Б")
    }
}

// ---------------------------------------------------------------------------
// Замер скорости
// ---------------------------------------------------------------------------

pub struct Speed {
    pub cfg: speed::Config,
    server: Option<Task<speed::Event>>,
    client: Option<Task<speed::Event>>,
    server_log: VecDeque<String>,
    log: String,
    points: Vec<(Direction, f64, f64)>,
    totals: Vec<(Direction, f64)>,
    udp: Option<speed::UdpResult>,
    error: Option<String>,
}

impl Speed {
    pub fn new(cfg: speed::Config) -> Self {
        Self { cfg, server: None, client: None, server_log: VecDeque::new(), log: String::new(), points: Vec::new(), totals: Vec::new(), udp: None, error: None }
    }

    pub fn busy(&self) -> bool {
        self.client.is_some() || self.server.is_some()
    }

    pub fn best(&self) -> Option<String> {
        self.totals.iter().map(|t| t.1).reduce(f64::max).map(|v| format!("{v:.0}"))
    }

    pub fn poll(&mut self) -> bool {
        let mut ch = false;
        if let Some(t) = &self.server {
            let ev = t.drain();
            ch |= !ev.is_empty();
            for e in ev {
                let line = match e {
                    speed::Event::Client(c) => c,
                    speed::Event::Log(l) => l,
                    speed::Event::Error(e) => format!("ошибка: {e}"),
                    _ => continue,
                };
                self.server_log.push_back(line);
                while self.server_log.len() > 50 {
                    self.server_log.pop_front();
                }
            }
            if t.finished() {
                self.server = None;
                ch = true;
            }
        }
        if let Some(t) = &self.client {
            let ev = t.drain();
            ch |= !ev.is_empty();
            for e in ev {
                match e {
                    speed::Event::Log(l) => self.log = l,
                    speed::Event::Point(d, t, v) => self.points.push((d, t, v)),
                    speed::Event::Total(d, v) => self.totals.push((d, v)),
                    speed::Event::Udp(u) => self.udp = Some(u),
                    speed::Event::Error(e) => self.error = Some(e),
                    speed::Event::Client(_) => {}
                }
            }
            if t.finished() {
                self.client = None;
                self.log.clear();
                ch = true;
            }
        }
        ch
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.strong("На второй машине");
        ui.horizontal(|ui| {
            if self.server.is_none() {
                if ui.button("▶ Запустить сервер замера").on_hover_text("Запустите на той стороне канала (та же программа)").clicked() {
                    let port = self.cfg.port;
                    self.server_log.clear();
                    self.server = Some(Task::spawn(env.rt, &env.ctx, move |s, c| speed::serve("0.0.0.0".into(), port, s, c)));
                }
            } else if ui.button("■ Остановить сервер").clicked()
                && let Some(t) = &self.server
            {
                t.cancel();
            }
        });
        if self.server.is_some() {
            ui.colored_label(GREEN, format!("сервер ждёт на {}:{}", crate::tools::sitecheck::local_ip(), self.cfg.port));
        }
        for l in self.server_log.iter().rev().take(5) {
            ui.weak(l);
        }
        ui.separator();
        ui.strong("На этой машине");
        egui::Grid::new("sp_grid").num_columns(2).show(ui, |ui| {
            super::labeled(ui, "Сервер", |ui| ui.add(egui::TextEdit::singleline(&mut self.cfg.server).hint_text("адрес второй машины")));
            super::labeled(ui, "Порт", |ui| ui.add(egui::DragValue::new(&mut self.cfg.port).range(1..=65535)));
            super::labeled(ui, "Потоков", |ui| ui.add(egui::DragValue::new(&mut self.cfg.streams).range(1..=64)));
            super::labeled(ui, "Секунд", |ui| ui.add(egui::DragValue::new(&mut self.cfg.seconds).range(2..=120)));
            ui.label("Направление");
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.cfg.direction, Direction::Both, "оба");
                ui.radio_value(&mut self.cfg.direction, Direction::Down, "загрузка");
                ui.radio_value(&mut self.cfg.direction, Direction::Up, "отдача");
            });
            ui.end_row();
            super::labeled(ui, "UDP, Мбит/с", |ui| ui.add(egui::DragValue::new(&mut self.cfg.udp_mbps).range(0..=10_000)).on_hover_text("Потери и джиттер при заданной скорости; 0 — не проверять"));
        });
        let busy = self.client.is_some();
        let (start, stop) = super::run_button(ui, busy, "Замерить");
        if start && !self.cfg.server.trim().is_empty() {
            self.points.clear();
            self.totals.clear();
            self.udp = None;
            self.error = None;
            let cfg = self.cfg.clone();
            self.client = Some(Task::spawn(env.rt, &env.ctx, move |s, c| speed::run(cfg, s, c)));
        }
        if stop && let Some(t) = &self.client {
            t.cancel();
        }
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak(&self.log);
            });
        }
        ui.add_space(6.0);
        ui.weak("Свой протокол (не iperf): на другой стороне нужна эта же программа с запущенным сервером. Первая секунда — разгон TCP, в итог не входит.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui) {
        if let Some(e) = &self.error {
            ui.colored_label(RED, e);
        }
        if self.points.is_empty() && self.totals.is_empty() {
            ui.weak("Запустите сервер замера на второй машине, впишите её адрес и нажмите «Замерить».");
            return;
        }
        for (d, v) in &self.totals {
            ui.label(RichText::new(format!("{}: {v:.0} Мбит/с", if *d == Direction::Up { "Отдача" } else { "Загрузка" })).size(22.0).strong());
        }
        for d in [Direction::Down, Direction::Up] {
            let v: Vec<Option<f64>> = self.points.iter().filter(|p| p.0 == d).map(|p| Some(p.2)).collect();
            if v.len() > 1 {
                ui.horizontal(|ui| {
                    ui.label(if d == Direction::Up { "отдача" } else { "загрузка" });
                    super::sparkline(ui, &v, 360.0);
                    ui.weak(format!("макс {:.0} Мбит/с", v.iter().flatten().cloned().fold(0.0, f64::max)));
                });
            }
        }
        if let Some(u) = &self.udp {
            ui.label(format!("UDP: отправлено {}, дошло {}, потери {:.2}%, джиттер {:.2} мс, не по порядку {}, {:.0} Мбит/с", u.sent, u.received, u.lost_pct, u.jitter_ms, u.out_of_order, u.mbps));
        }
        if !self.totals.is_empty() {
            let best = self.totals.iter().map(|t| t.1).fold(0.0, f64::max);
            ui.add_space(6.0);
            for (ok, t) in speed::verdict(best, self.udp.as_ref()) {
                ui.colored_label(if ok { GREEN } else { super::AMBER }, format!("{} {t}", if ok { "✔" } else { "⚠" }));
            }
        }
    }
}
