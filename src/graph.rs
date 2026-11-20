//! Граф инфраструктуры в духе Obsidian Graph View: силовая раскладка
//! (подсети → узлы → сервисы, сервисы → издатели сертификатов), подсветка
//! соседей при наведении, плавные анимации и линза «рыбий глаз» под курсором.
//!
//! Граф строится из уже отфильтрованных строк таблицы, поэтому все фильтры
//! действуют и здесь.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::Ipv4Addr;

use egui::{
    Align2, Color32, CornerRadius, FontId, Pos2, Rect, Sense, Stroke, Ui, Vec2, pos2,
    vec2,
};
use serde::{Deserialize, Serialize};

use crate::model::{ProxyKind, ProxyRow, RowState, SslInspection};
use crate::targets;

pub type RowKey = (Ipv4Addr, u16);

// ---------------------------------------------------------------------------
// Настройки (сохраняются между запусками)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GraphSettings {
    pub show_subnets: bool,
    pub show_issuers: bool,
    pub show_labels: bool,
    /// Масштаб, начиная с которого появляются подписи.
    pub label_zoom: f32,
    pub node_size: f32,
    pub link_width: f32,
    pub fisheye: bool,
    /// Сила искажения линзы.
    pub fisheye_strength: f32,
    /// Радиус линзы в пикселях.
    pub fisheye_radius: f32,
    pub center_force: f32,
    pub repel_force: f32,
    pub link_force: f32,
    pub link_distance: f32,
}

impl Default for GraphSettings {
    fn default() -> Self {
        Self {
            show_subnets: true,
            show_issuers: true,
            show_labels: true,
            label_zoom: 1.8,
            node_size: 1.0,
            link_width: 1.0,
            fisheye: true,
            fisheye_strength: 3.0,
            fisheye_radius: 220.0,
            center_force: 0.5,
            repel_force: 2.2,
            link_force: 1.0,
            link_distance: 32.0,
        }
    }
}

/// Что граф просит сделать приложение.
#[derive(Debug, Default)]
pub struct GraphOutput {
    /// Выбрать строку (открыть подробности).
    pub select: Option<RowKey>,
    /// Двойной щелчок по узлу карты: его подпись.
    pub map_activate: Option<String>,
    /// Оставить в фильтре только эту подсеть.
    pub filter_subnet: Option<String>,
    /// Найти по тексту (издатель, адрес).
    pub filter_text: Option<String>,
}

// ---------------------------------------------------------------------------
// Модель графа
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    Subnet,
    Host,
    Service(ProxyKind),
    Issuer,
    Map(MapKind),
}

/// Тип узла карты сети.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapKind {
    /// Эта машина.
    Me,
    /// Шлюз.
    Router,
    /// Промежуточный хоп трассировки.
    Hop,
    Subnet,
    Host,
    /// Узел с найденными сервисами.
    Server,
    /// Контроллер домена.
    Dc,
    /// Прокси-сервер.
    Proxy,
}

/// Узел карты сети (вход для [`GraphView::ui_map`]).
#[derive(Debug, Clone, Hash)]
pub struct MapNode {
    pub key: String,
    pub kind: MapKind,
    pub label: String,
    pub detail: Vec<String>,
    /// Узел, к которому он «подвешен» (ребро).
    pub parent: Option<String>,
    /// Дополнительные связи.
    pub links: Vec<String>,
    /// Проблема (красное кольцо) и предупреждение (оранжевое).
    pub problem: bool,
    pub warning: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
struct Flags {
    ssl: bool,
    violations: bool,
    error: bool,
    auth: bool,
}

#[derive(Debug, Clone)]
struct Node {
    key: String,
    kind: NodeKind,
    label: String,
    detail: Vec<String>,
    row: Option<RowKey>,
    flags: Flags,
    pos: Vec2,
    vel: Vec2,
    degree: usize,
    /// Анимации: появление и подсветка (0..1).
    appear: f32,
    light: f32,
}

#[derive(Debug, Clone, Copy)]
struct Edge {
    a: usize,
    b: usize,
}

/// Описание узла до раскладки.
struct Spec {
    key: String,
    kind: NodeKind,
    label: String,
    detail: Vec<String>,
    row: Option<RowKey>,
    flags: Flags,
    parent: Option<String>,
}

pub struct GraphView {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    adj: Vec<Vec<usize>>,
    signature: u64,
    // Камера
    pan: Vec2,
    zoom: f32,
    user_moved_camera: bool,
    // Симуляция
    alpha: f32,
    alpha_target: f32,
    // Взаимодействие
    hovered: Option<usize>,
    /// Карта сети (другая легенда и подсказки).
    map_mode: bool,
    dragging: Option<usize>,
    lens: f32,
    settings_open: bool,
    /// Живая карта: нагрузка на связях (ключи узлов → доля 0..1, тревога).
    heat: std::collections::HashMap<(String, String), (f32, bool)>,
}

impl Default for GraphView {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            adj: Vec::new(),
            signature: 0,
            pan: Vec2::ZERO,
            zoom: 1.0,
            user_moved_camera: false,
            alpha: 1.0,
            alpha_target: 0.0,
            hovered: None,
            dragging: None,
            lens: 0.0,
            settings_open: false,
            heat: Default::default(),
            map_mode: false,
        }
    }
}

const ALPHA_MIN: f32 = 0.002;
const ALPHA_DECAY: f32 = 0.0228; // 1 - 0.001^(1/300), как в d3-force
const VELOCITY_DECAY: f32 = 0.4;
const REPEL_CUTOFF: f32 = 320.0;

fn short_issuer(issuer: &str) -> String {
    issuer
        .split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("CN="))
        .unwrap_or(issuer)
        .to_string()
}

fn hash_of<T: Hash>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

/// Детерминированное смещение для новых узлов (чтобы раскладка не «прыгала»).
fn jitter(key: &str, radius: f32) -> Vec2 {
    let h = hash_of(&key);
    let angle = (h % 6283) as f32 / 1000.0;
    let r = radius * (0.5 + ((h >> 16) % 1000) as f32 / 2000.0);
    vec2(angle.cos(), angle.sin()) * r
}

/// Узлы и дополнительные рёбра (сервис — издатель сертификата).
fn specs(rows: &[&ProxyRow], s: &GraphSettings) -> (Vec<Spec>, Vec<(String, String)>) {
    let mut out: Vec<Spec> = Vec::new();
    let mut extra_edges: Vec<(String, String)> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut push = |out: &mut Vec<Spec>, spec: Spec| -> usize {
        if let Some(&i) = seen.get(&spec.key) {
            return i;
        }
        seen.insert(spec.key.clone(), out.len());
        out.push(spec);
        out.len() - 1
    };

    for r in rows {
        let net = targets::network_cidr(r.ip, 24);
        let net_key = format!("net:{net}");
        if s.show_subnets {
            push(
                &mut out,
                Spec {
                    key: net_key.clone(),
                    kind: NodeKind::Subnet,
                    label: net.clone(),
                    detail: vec!["подсеть /24".into()],
                    row: None,
                    flags: Flags::default(),
                    parent: None,
                },
            );
        }
        let host_key = format!("ip:{}", r.ip);
        let hi = push(
            &mut out,
            Spec {
                key: host_key.clone(),
                kind: NodeKind::Host,
                label: r.ip.to_string(),
                detail: vec!["узел".into()],
                row: Some((r.ip, r.port)),
                flags: Flags::default(),
                parent: s.show_subnets.then(|| net_key.clone()),
            },
        );

        let (ok, total) = r.policy_counts();
        let flags = Flags {
            ssl: r.ssl == SslInspection::Yes,
            violations: ok < total,
            error: r.state == RowState::Error,
            auth: r.probe.auth_required || !r.probe.auth.is_empty(),
        };
        // Флаги сервиса поднимаем и на узел, чтобы проблемные хосты были видны издалека.
        let hf = &mut out[hi].flags;
        hf.ssl |= flags.ssl;
        hf.violations |= flags.violations;
        hf.error |= flags.error;

        let mut detail = vec![r.kind.label().to_string()];
        let auth = r.auth_label();
        if !auth.is_empty() {
            detail.push(format!("аутентификация: {auth}"));
        }
        let connect = r.connect_label();
        if !connect.is_empty() {
            detail.push(format!("CONNECT: {connect}"));
        }
        if r.ssl != SslInspection::Unknown {
            detail.push(format!("SSL-инспекция: {}", r.ssl.label()));
        }
        if total > 0 {
            detail.push(format!("политики: {}", r.policy_label()));
        }
        let server = r.server_label();
        if !server.is_empty() {
            detail.push(server);
        }
        if let Some(e) = &r.probe.error {
            detail.push(format!("ошибка: {e}"));
        }
        let svc_key = format!("svc:{}:{}", r.ip, r.port);
        push(
            &mut out,
            Spec {
                key: svc_key.clone(),
                kind: NodeKind::Service(r.kind),
                label: format!(":{}", r.port),
                detail,
                row: Some((r.ip, r.port)),
                flags,
                parent: Some(host_key),
            },
        );

        if s.show_issuers
            && let Some(cert) = &r.probe.cert
            && !cert.issuer.is_empty()
        {
            let iss_key = format!("iss:{}", cert.issuer);
            push(
                &mut out,
                Spec {
                    key: iss_key.clone(),
                    kind: NodeKind::Issuer,
                    label: short_issuer(&cert.issuer),
                    detail: vec!["издатель сертификата".into(), cert.issuer.clone()],
                    row: None,
                    flags: Flags::default(),
                    parent: None,
                },
            );
            extra_edges.push((svc_key, iss_key));
        }
    }
    (out, extra_edges)
}

impl GraphView {
    /// Перестраивает граф, если изменились данные; сохраняет положение известных узлов.
    fn sync(&mut self, rows: &[&ProxyRow], s: &GraphSettings) {
        let mut h = DefaultHasher::new();
        s.show_subnets.hash(&mut h);
        s.show_issuers.hash(&mut h);
        for r in rows {
            (r.ip, r.port, r.kind as u8, r.ssl as u8, r.state as u8).hash(&mut h);
            r.policy_counts().hash(&mut h);
            r.probe.auth.hash(&mut h);
            r.probe.connect_status.hash(&mut h);
            r.probe.cert.as_ref().map(|c| &c.issuer).hash(&mut h);
        }
        let sig = h.finish();
        if sig == self.signature && !self.nodes.is_empty() == !rows.is_empty() {
            return;
        }
        let (specs, pending_edges) = specs(rows, s);
        self.rebuild(sig, specs, pending_edges, s);
    }

    /// Карта сети: узлы задаются снаружи.
    fn sync_map(&mut self, nodes: &[MapNode], s: &GraphSettings) {
        let sig = hash_of(&nodes) ^ 0x6d61_7000;
        if sig == self.signature && !self.nodes.is_empty() == !nodes.is_empty() {
            return;
        }
        let mut edges = Vec::new();
        let specs = nodes
            .iter()
            .map(|n| {
                for l in &n.links {
                    edges.push((n.key.clone(), l.clone()));
                }
                Spec {
                    key: n.key.clone(),
                    kind: NodeKind::Map(n.kind),
                    label: n.label.clone(),
                    detail: n.detail.clone(),
                    row: None,
                    flags: Flags {
                        ssl: n.problem,
                        violations: n.warning,
                        ..Default::default()
                    },
                    parent: n.parent.clone(),
                }
            })
            .collect();
        self.rebuild(sig, specs, edges, s);
    }

    fn rebuild(&mut self, sig: u64, specs: Vec<Spec>, mut pending_edges: Vec<(String, String)>, s: &GraphSettings) {
        self.signature = sig;

        let old: HashMap<String, (Vec2, Vec2, f32)> = self
            .nodes
            .iter()
            .map(|n| (n.key.clone(), (n.pos, n.vel, n.appear)))
            .collect();
        let had_nodes = !self.nodes.is_empty();

        let mut nodes: Vec<Node> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();

        for spec in specs {
            if let Some(p) = &spec.parent {
                pending_edges.push((spec.key.clone(), p.clone()));
            }
            let (pos, vel, appear) = match old.get(&spec.key) {
                Some(&v) => v,
                None => {
                    let parent_pos = spec
                        .parent
                        .as_ref()
                        .and_then(|p| index.get(p))
                        .map(|&i| nodes[i].pos)
                        .or_else(|| {
                            spec.parent.as_ref().and_then(|p| old.get(p)).map(|v| v.0)
                        });
                    let i = nodes.len() as f32;
                    let pos = match parent_pos {
                        Some(p) => p + jitter(&spec.key, 18.0),
                        // Начальная раскладка «подсолнухом», как в d3-force.
                        None => {
                            let r = 10.0 * (0.5 + i).sqrt();
                            let a = i * std::f32::consts::PI * (3.0 - 5f32.sqrt());
                            vec2(a.cos(), a.sin()) * r
                        }
                    };
                    (pos, Vec2::ZERO, 0.0)
                }
            };
            index.insert(spec.key.clone(), nodes.len());
            nodes.push(Node {
                key: spec.key,
                kind: spec.kind,
                label: spec.label,
                detail: spec.detail,
                row: spec.row,
                flags: spec.flags,
                pos,
                vel,
                degree: 0,
                appear,
                light: 1.0,
            });
        }

        let mut edges = Vec::new();
        let mut adj = vec![Vec::new(); nodes.len()];
        for (a, b) in pending_edges {
            if let (Some(&a), Some(&b)) = (index.get(&a), index.get(&b))
                && a != b
                && !adj[a].contains(&b)
            {
                edges.push(Edge { a, b });
                adj[a].push(b);
                adj[b].push(a);
            }
        }
        for (i, n) in nodes.iter_mut().enumerate() {
            n.degree = adj[i].len();
        }

        self.nodes = nodes;
        self.edges = edges;
        self.adj = adj;
        self.hovered = None;
        self.dragging = None;
        self.alpha = if had_nodes { self.alpha.max(0.5) } else { 1.0 };
        if !had_nodes {
            self.user_moved_camera = false;
            // Короткий «прогрев», чтобы первый кадр не был кашей.
            for _ in 0..30 {
                self.tick(s);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Симуляция сил (по мотивам d3-force)
    // -----------------------------------------------------------------------

    fn tick(&mut self, s: &GraphSettings) {
        let n = self.nodes.len();
        if n == 0 {
            return;
        }
        self.alpha += (self.alpha_target - self.alpha) * ALPHA_DECAY;
        let alpha = self.alpha;

        // Связи-пружины.
        let dist = s.link_distance.max(5.0);
        for e in &self.edges {
            let (da, db) = (self.nodes[e.a].degree as f32, self.nodes[e.b].degree as f32);
            let strength = s.link_force / da.min(db).max(1.0);
            let bias = da / (da + db);
            let pa = self.nodes[e.a].pos + self.nodes[e.a].vel;
            let pb = self.nodes[e.b].pos + self.nodes[e.b].vel;
            let mut d = pb - pa;
            let mut l = d.length();
            if l < 1e-3 {
                d = jitter(&self.nodes[e.b].key, 1e-3);
                l = d.length().max(1e-3);
            }
            let k = (l - dist) / l * alpha * strength;
            let d = d * k;
            self.nodes[e.b].vel -= d * bias;
            self.nodes[e.a].vel += d * (1.0 - bias);
        }

        // Отталкивание: сетка ячеек, учитываются только ближайшие соседи.
        let strength = -30.0 * s.repel_force;
        let cell = REPEL_CUTOFF;
        let mut grid: HashMap<(i32, i32), Vec<usize>> = HashMap::new();
        for (i, node) in self.nodes.iter().enumerate() {
            let c = ((node.pos.x / cell).floor() as i32, (node.pos.y / cell).floor() as i32);
            grid.entry(c).or_default().push(i);
        }
        let cutoff2 = REPEL_CUTOFF * REPEL_CUTOFF;
        let mut dv = vec![Vec2::ZERO; n];
        for (&(cx, cy), members) in &grid {
            for dx in -1..=1 {
                for dy in -1..=1 {
                    let Some(others) = grid.get(&(cx + dx, cy + dy)) else { continue };
                    for &i in members {
                        for &j in others {
                            if j <= i {
                                continue;
                            }
                            let mut d = self.nodes[j].pos - self.nodes[i].pos;
                            let mut l2 = d.length_sq();
                            if l2 >= cutoff2 {
                                continue;
                            }
                            if l2 < 1e-6 {
                                d = jitter(&self.nodes[j].key, 1e-2);
                                l2 = d.length_sq();
                            }
                            let l2 = l2.max(1.0);
                            let w = strength * alpha / l2;
                            dv[i] += d * w;
                            dv[j] -= d * w;
                        }
                    }
                }
            }
        }

        // Притяжение к центру и интегрирование.
        let center = 0.05 * s.center_force;
        for (i, node) in self.nodes.iter_mut().enumerate() {
            if Some(i) == self.dragging {
                node.vel = Vec2::ZERO;
                continue;
            }
            node.vel += dv[i] - node.pos * center * alpha;
            node.vel *= 1.0 - VELOCITY_DECAY;
            node.pos += node.vel;
        }
    }

    pub fn reheat(&mut self) {
        self.alpha = self.alpha.max(0.6);
    }

    // -----------------------------------------------------------------------
    // Камера и линза
    // -----------------------------------------------------------------------

    fn to_screen(&self, rect: Rect, p: Vec2) -> Pos2 {
        rect.center() + self.pan + p * self.zoom
    }

    fn to_world(&self, rect: Rect, p: Pos2) -> Vec2 {
        (p - rect.center() - self.pan) / self.zoom
    }

    fn bounds(&self) -> Option<Rect> {
        let mut it = self.nodes.iter();
        let first = it.next()?;
        let mut r = Rect::from_center_size(first.pos.to_pos2(), Vec2::ZERO);
        for n in it {
            r.extend_with(n.pos.to_pos2());
        }
        Some(r)
    }

    /// Камера, вписывающая весь граф в область.
    fn fit_target(&self, rect: Rect) -> Option<(Vec2, f32)> {
        let b = self.bounds()?;
        let size = b.size().max(vec2(80.0, 80.0));
        let zoom = ((rect.width() - 80.0) / size.x)
            .min((rect.height() - 80.0) / size.y)
            .clamp(0.08, 2.5);
        Some((-b.center().to_vec2() * zoom, zoom))
    }

    fn fit_now(&mut self, rect: Rect) {
        if let Some((pan, zoom)) = self.fit_target(rect) {
            self.pan = pan;
            self.zoom = zoom;
        }
        self.user_moved_camera = false;
    }

    // -----------------------------------------------------------------------
    // Отрисовка
    // -----------------------------------------------------------------------

    pub fn ui(
        &mut self,
        ui: &mut Ui,
        rows: &[&ProxyRow],
        selected: Option<RowKey>,
        s: &mut GraphSettings,
    ) -> GraphOutput {
        self.sync(rows, s);
        self.map_mode = false;
        let empty = if rows.is_empty() {
            "Нет узлов для отображения. Запустите сканирование или ослабьте фильтры."
        } else {
            "Нет узлов для отображения."
        };
        self.draw(ui, selected, s, empty)
    }

    /// Карта сети из узлов [`MapNode`].
    /// Нагрузка на связях живой карты (обновляется без перестройки раскладки).
    pub fn set_heat(&mut self, v: Vec<(String, String, f32, bool)>) {
        self.heat = v.into_iter().map(|(a, b, w, alert)| ((a, b), (w, alert))).collect();
    }

    fn edge_heat(&self, e: &Edge) -> Option<(f32, bool)> {
        if self.heat.is_empty() {
            return None;
        }
        let (a, b) = (&self.nodes[e.a].key, &self.nodes[e.b].key);
        self.heat.get(&(a.clone(), b.clone())).or_else(|| self.heat.get(&(b.clone(), a.clone()))).copied()
    }

    pub fn ui_map(&mut self, ui: &mut Ui, nodes: &[MapNode], s: &mut GraphSettings) -> GraphOutput {
        self.sync_map(nodes, s);
        self.map_mode = true;
        self.draw(ui, None, s, "Карта пуста: соберите сведения о хосте, запустите трассировку или поиск узлов.")
    }

    fn draw(&mut self, ui: &mut Ui, selected: Option<RowKey>, s: &mut GraphSettings, empty: &str) -> GraphOutput {
        let mut out = GraphOutput::default();

        let (rect, response) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        let dark = ui.visuals().dark_mode;
        let pal = Palette::new(dark);
        let dt = ui.input(|i| i.stable_dt).clamp(0.001, 0.05);

        painter.rect_filled(rect, CornerRadius::ZERO, pal.bg);

        if self.nodes.is_empty() {
            painter.text(
                rect.center(),
                Align2::CENTER_CENTER,
                empty,
                FontId::proportional(14.0),
                pal.muted,
            );
            return out;
        }

        // --- Камера: вписывание, перемещение, масштаб -------------------------
        if !self.user_moved_camera
            && let Some((pan, zoom)) = self.fit_target(rect)
        {
            // Пока раскладка «разлетается», плавно подстраиваем камеру.
            let t = (dt * 4.0).min(1.0);
            self.pan += (pan - self.pan) * t;
            self.zoom += (zoom - self.zoom) * t;
        }

        let pointer = response.hover_pos();
        if let Some(p) = pointer {
            let (scroll, pinch) = ui.input(|i| (i.smooth_scroll_delta.y, i.zoom_delta()));
            let factor = pinch * (scroll * 0.0018).exp();
            if (factor - 1.0).abs() > 1e-4 {
                let w = self.to_world(rect, p);
                self.zoom = (self.zoom * factor).clamp(0.05, 8.0);
                self.pan = p - rect.center() - w * self.zoom;
                self.user_moved_camera = true;
            }
            if ui.input(|i| i.key_pressed(egui::Key::F)) && !ui.ctx().egui_wants_keyboard_input() {
                s.fisheye = !s.fisheye;
            }
        }

        // --- Линза «рыбий глаз» ----------------------------------------------
        let lens_target = if s.fisheye && pointer.is_some() && self.dragging.is_none() {
            1.0
        } else {
            0.0
        };
        self.lens += (lens_target - self.lens) * (dt * 8.0).min(1.0);
        let lens = Fisheye::new(
            pointer.unwrap_or(rect.center()),
            s.fisheye_radius,
            s.fisheye_strength * self.lens,
        );

        // Экранные позиции узлов с учётом линзы.
        let base_r = |n: &Node| -> f32 {
            let k = match n.kind {
                NodeKind::Subnet => 6.5,
                NodeKind::Issuer => 5.5,
                NodeKind::Host => 3.6,
                NodeKind::Service(_) => 3.0,
                NodeKind::Map(k) => match k {
                    MapKind::Me => 7.5,
                    MapKind::Router => 6.0,
                    MapKind::Subnet => 6.5,
                    MapKind::Dc => 5.5,
                    MapKind::Server | MapKind::Proxy => 4.2,
                    MapKind::Hop => 3.8,
                    MapKind::Host => 3.2,
                },
            };
            s.node_size * (k + 1.3 * (n.degree as f32).sqrt())
        };
        let screen: Vec<(Pos2, f32)> = self
            .nodes
            .iter()
            .map(|n| {
                let p = self.to_screen(rect, n.pos);
                let (p, z) = lens.apply(p);
                let r = (base_r(n) * self.zoom.powf(0.85)).max(1.6);
                (p, r * (1.0 + (z - 1.0) * 0.55))
            })
            .collect();

        // --- Наведение, перетаскивание, клики ------------------------------------
        let hit = |p: Pos2| -> Option<usize> {
            let mut best: Option<(usize, f32)> = None;
            for (i, (sp, r)) in screen.iter().enumerate() {
                let d = sp.distance(p);
                if d <= r + 5.0 && best.is_none_or(|(_, bd)| d < bd) {
                    best = Some((i, d));
                }
            }
            best.map(|(i, _)| i)
        };
        if self.dragging.is_none() {
            self.hovered = pointer.and_then(hit);
        }

        if response.drag_started()
            && let Some(i) = pointer.and_then(hit)
        {
            self.dragging = Some(i);
            self.alpha_target = 0.3;
            self.reheat();
        }
        if response.dragged() {
            match (self.dragging, pointer) {
                (Some(i), Some(p)) => {
                    let w = self.to_world(rect, p);
                    self.nodes[i].pos = w;
                    self.nodes[i].vel = Vec2::ZERO;
                }
                (None, _) => {
                    self.pan += response.drag_delta();
                    self.user_moved_camera = true;
                }
                _ => {}
            }
        }
        if response.drag_stopped() {
            self.dragging = None;
            self.alpha_target = 0.0;
        }
        if response.clicked()
            && let Some(i) = self.hovered
        {
            out.select = self.nodes[i].row;
        }
        if response.double_clicked()
            && let Some(i) = self.hovered
        {
            let n = &self.nodes[i];
            match n.kind {
                NodeKind::Subnet => out.filter_subnet = Some(n.label.clone()),
                NodeKind::Issuer => out.filter_text = Some(n.label.clone()),
                NodeKind::Host => out.filter_subnet = Some(n.label.clone()),
                NodeKind::Service(_) => {}
                NodeKind::Map(_) => out.map_activate = Some(n.label.clone()),
            }
        }

        // --- Анимации подсветки и появления --------------------------------------
        let focus = self.hovered.or(self.dragging);
        let k = (dt * 10.0).min(1.0);
        let mut animating = false;
        for (i, n) in self.nodes.iter_mut().enumerate() {
            let target = match focus {
                None => 1.0,
                Some(f) if f == i || self.adj[f].contains(&i) => 1.0,
                Some(_) => 0.14,
            };
            n.light += (target - n.light) * k;
            n.appear += (1.0 - n.appear) * (dt * 3.0).min(1.0);
            animating |= (target - n.light).abs() > 0.01 || n.appear < 0.99;
        }

        // --- Связи ---------------------------------------------------------------
        let link_w = (s.link_width * self.zoom.sqrt()).clamp(0.4, 2.5);
        for e in &self.edges {
            let (pa, _) = screen[e.a];
            let (pb, _) = screen[e.b];
            let (na, nb) = (&self.nodes[e.a], &self.nodes[e.b]);
            let active = focus.is_some_and(|f| f == e.a || f == e.b);
            let fade = na.appear.min(nb.appear) * na.light.min(nb.light);
            let (color, w) = if active {
                (pal.accent.gamma_multiply(0.9), link_w * 1.6)
            } else {
                (pal.link.gamma_multiply(fade), link_w)
            };
            if let Some((share, alert)) = self.edge_heat(e) {
                // Живая связь: толщина по объёму трафика, бегущие точки по направлению потока.
                let hot = if alert { Color32::from_rgb(230, 80, 70) } else { pal.accent };
                painter.line_segment([pa, pb], Stroke::new(w + 3.5 * share, hot.gamma_multiply(0.35 + 0.5 * share * fade)));
                let t = ui.input(|i| i.time) as f32;
                let len = (pb - pa).length().max(1.0);
                let dots = ((len / 40.0) as usize).clamp(1, 12);
                for k in 0..dots {
                    let f = ((t * (0.25 + 0.6 * share) * 60.0 / len) + k as f32 / dots as f32).fract();
                    painter.circle_filled(pa + (pb - pa) * f, 1.5 + 1.5 * share, hot.gamma_multiply(fade));
                }
                animating = true;
                continue;
            }
            painter.line_segment([pa, pb], Stroke::new(w, color));
        }

        // --- Узлы ----------------------------------------------------------------
        let label_alpha = if s.show_labels {
            smoothstep(s.label_zoom - 0.25, s.label_zoom + 0.25, self.zoom)
        } else {
            0.0
        };
        // Сначала тусклые, затем яркие — подсвеченные узлы оказываются сверху.
        let mut order: Vec<usize> = (0..self.nodes.len()).collect();
        order.sort_by(|&a, &b| self.nodes[a].light.total_cmp(&self.nodes[b].light));
        for &i in &order {
            let n = &self.nodes[i];
            let (p, r) = screen[i];
            if !rect.expand(r + 40.0).contains(p) {
                continue;
            }
            let fade = n.appear * n.light;
            let is_focus = focus == Some(i);
            let is_selected = n.row.is_some_and(|k| Some(k) == selected)
                && matches!(n.kind, NodeKind::Service(_));
            let base = pal.node(n.kind);
            let fill = if is_focus { pal.accent } else { base };

            // Свечение для фокуса и проблемных узлов.
            let glow = if is_focus {
                Some(pal.accent)
            } else if n.flags.ssl {
                Some(pal.danger)
            } else {
                None
            };
            if let Some(g) = glow {
                for (scale, a) in [(2.6, 0.06), (1.9, 0.10), (1.45, 0.16)] {
                    painter.circle_filled(p, r * scale, g.gamma_multiply(a * fade));
                }
            }
            painter.circle_filled(p, r, fill.gamma_multiply(fade));

            // Кольца-индикаторы.
            let ring = |color: Color32, extra: f32| {
                painter.circle_stroke(p, r + extra, Stroke::new(1.4, color.gamma_multiply(fade)));
            };
            if n.flags.ssl {
                ring(pal.danger, 2.0);
            } else if n.flags.violations {
                ring(pal.warn, 2.0);
            } else if n.flags.error {
                ring(pal.danger.gamma_multiply(0.6), 2.0);
            }
            if is_selected {
                painter.circle_stroke(p, r + 4.5, Stroke::new(1.8, pal.text));
            }

            // Подписи: появляются при приближении, у фокуса и соседей — всегда.
            let near_focus = focus.is_some_and(|f| f == i || self.adj[f].contains(&i));
            let lens_boost = ((r / (base_r(n) * self.zoom.powf(0.85)).max(1.6)) - 1.0).max(0.0);
            let a = if near_focus {
                1.0
            } else {
                (label_alpha + lens_boost * 0.8).min(1.0) * n.light
            } * n.appear;
            if a > 0.03 && !n.label.is_empty() {
                let size = (11.5 * self.zoom.powf(0.35)).clamp(9.5, 16.0) * (1.0 + lens_boost * 0.35);
                let color = if is_focus { pal.text } else { pal.label };
                painter.text(
                    p + vec2(0.0, r + 3.0),
                    Align2::CENTER_TOP,
                    &n.label,
                    FontId::proportional(size),
                    color.gamma_multiply(a),
                );
            }
        }

        // Контур линзы.
        if self.lens > 0.02 && s.fisheye_strength > 0.05 {
            painter.circle_stroke(
                lens.focus,
                s.fisheye_radius,
                Stroke::new(1.0, pal.accent.gamma_multiply(0.18 * self.lens)),
            );
        }

        // --- Карточка наведённого узла ----------------------------------------------
        if let Some(i) = self.hovered
            && self.dragging.is_none()
        {
            self.paint_card(&painter, rect, &pal, i, screen[i]);
        }

        // --- Наложения: легенда и панель настроек -----------------------------------
        self.paint_legend(ui, rect, &pal);
        let changed = self.overlay(ui, rect, s);
        if changed {
            self.reheat();
        }

        // --- Шаг симуляции и перерисовка -----------------------------------------
        if self.alpha > ALPHA_MIN || self.alpha_target > 0.0 {
            self.tick(s);
            animating = true;
        }
        if animating || (self.lens - lens_target).abs() > 0.01 || pointer.is_some() {
            ui.ctx().request_repaint();
        }
        if response.hovered() {
            ui.ctx().set_cursor_icon(if self.dragging.is_some() {
                egui::CursorIcon::Grabbing
            } else if self.hovered.is_some() {
                egui::CursorIcon::PointingHand
            } else {
                egui::CursorIcon::Grab
            });
        }
        out
    }

    fn paint_card(&self, painter: &egui::Painter, rect: Rect, pal: &Palette, i: usize, (p, r): (Pos2, f32)) {
        let n = &self.nodes[i];
        let title = match (n.kind, n.row) {
            (NodeKind::Service(_), Some((ip, port))) => format!("{ip}:{port}"),
            _ => n.label.clone(),
        };
        let title = painter.layout_no_wrap(title, FontId::proportional(13.5), pal.text);
        let lines: Vec<_> = n
            .detail
            .iter()
            .take(7)
            .map(|d| painter.layout_no_wrap(d.clone(), FontId::proportional(12.0), pal.label))
            .collect();
        let hint = match n.kind {
            NodeKind::Service(_) => "щелчок — подробности",
            NodeKind::Subnet | NodeKind::Host => "двойной щелчок — фильтр по адресу",
            NodeKind::Issuer => "двойной щелчок — поиск по издателю",
            NodeKind::Map(MapKind::Subnet) => "двойной щелчок — поиск узлов в подсети",
            NodeKind::Map(_) => "двойной щелчок — трассировка до узла",
        };
        let hint = painter.layout_no_wrap(hint.into(), FontId::proportional(11.0), pal.muted);
        let w = lines
            .iter()
            .map(|g| g.size().x)
            .chain([title.size().x, hint.size().x])
            .fold(0.0, f32::max)
            + 20.0;
        let h = title.size().y + lines.iter().map(|g| g.size().y + 2.0).sum::<f32>() + hint.size().y + 22.0;
        let mut pos = p + vec2(r + 14.0, -h / 2.0);
        if pos.x + w > rect.right() - 8.0 {
            pos.x = p.x - r - 14.0 - w;
        }
        pos.y = pos.y.clamp(rect.top() + 8.0, (rect.bottom() - h - 8.0).max(rect.top() + 8.0));
        let card = Rect::from_min_size(pos, vec2(w, h));
        painter.rect_filled(card.translate(vec2(0.0, 3.0)), CornerRadius::same(8), Color32::from_black_alpha(50));
        painter.rect_filled(card, CornerRadius::same(8), pal.card);
        painter.rect_stroke(card, CornerRadius::same(8), Stroke::new(1.0, pal.card_border), egui::StrokeKind::Inside);
        let mut y = card.top() + 9.0;
        painter.galley(pos2(card.left() + 10.0, y), title.clone(), pal.text);
        y += title.size().y + 4.0;
        for g in lines {
            painter.galley(pos2(card.left() + 10.0, y), g.clone(), pal.label);
            y += g.size().y + 2.0;
        }
        painter.galley(pos2(card.left() + 10.0, y + 3.0), hint, pal.muted);
    }

    fn paint_legend(&self, ui: &Ui, rect: Rect, pal: &Palette) {
        if rect.width() < 420.0 || rect.height() < 260.0 {
            return;
        }
        let painter = ui.painter_at(rect);
        let map_items: [(Color32, &str, bool); 9] = [
            (pal.node(NodeKind::Map(MapKind::Me)), "эта машина", false),
            (pal.node(NodeKind::Map(MapKind::Router)), "шлюз", false),
            (pal.node(NodeKind::Map(MapKind::Hop)), "хоп трассировки", false),
            (pal.node(NodeKind::Map(MapKind::Subnet)), "подсеть", false),
            (pal.node(NodeKind::Map(MapKind::Server)), "сервер (сервисы)", false),
            (pal.node(NodeKind::Map(MapKind::Dc)), "контроллер домена", false),
            (pal.node(NodeKind::Map(MapKind::Proxy)), "прокси", false),
            (pal.danger, "проблема", true),
            (pal.warn, "предупреждение", true),
        ];
        let items: [(Color32, &str, bool); 8] = [
            (pal.node(NodeKind::Subnet), "подсеть", false),
            (pal.node(NodeKind::Host), "узел", false),
            (pal.node(NodeKind::Service(ProxyKind::HttpProxy)), "HTTP-прокси", false),
            (pal.node(NodeKind::Service(ProxyKind::Socks5)), "SOCKS", false),
            (pal.node(NodeKind::Service(ProxyKind::HttpServer)), "веб-сервер", false),
            (pal.node(NodeKind::Issuer), "издатель сертификата", false),
            (pal.danger, "SSL-инспекция", true),
            (pal.warn, "нарушение политик", true),
        ];
        let items: &[(Color32, &str, bool)] = if self.map_mode { &map_items } else { &items };
        let font = FontId::proportional(11.5);
        let line_h = 17.0;
        let mut y = rect.bottom() - 12.0 - items.len() as f32 * line_h;
        let x = rect.left() + 14.0;
        for &(color, label, ring) in items {
            let c = pos2(x + 5.0, y + line_h / 2.0);
            if ring {
                painter.circle_stroke(c, 4.5, Stroke::new(1.4, color));
            } else {
                painter.circle_filled(c, 4.0, color);
            }
            painter.text(pos2(x + 16.0, c.y), Align2::LEFT_CENTER, label, font.clone(), pal.muted);
            y += line_h;
        }
        let stats = format!(
            "{} узлов · {} связей · масштаб {:.0}%",
            self.nodes.len(),
            self.edges.len(),
            self.zoom * 100.0
        );
        painter.text(
            pos2(rect.right() - 12.0, rect.bottom() - 10.0),
            Align2::RIGHT_BOTTOM,
            stats,
            FontId::proportional(11.0),
            pal.muted,
        );
    }

    /// Масштаб к центру области (точка в центре остаётся на месте).
    fn zoom_to(&mut self, z: f32) {
        let z = z.clamp(0.05, 8.0);
        if self.zoom > 0.0 {
            self.pan *= z / self.zoom;
        }
        self.zoom = z;
        self.user_moved_camera = true;
    }

    /// Ползунок масштаба у правого края: «+», вертикальный ползунок, «−».
    fn zoom_slider(&mut self, ui: &mut Ui, rect: Rect) {
        let h = (rect.height() - 120.0).clamp(80.0, 220.0);
        let area = Rect::from_min_size(pos2(rect.right() - 44.0, rect.top() + 50.0), vec2(34.0, h + 64.0));
        ui.scope_builder(egui::UiBuilder::new().max_rect(area).layout(egui::Layout::top_down(egui::Align::Center)), |ui| {
            if ui.button("➕").on_hover_text("Приблизить").clicked() {
                self.zoom_to(self.zoom * 1.25);
            }
            let mut z = self.zoom;
            ui.spacing_mut().slider_width = h;
            let r = ui
                .add(egui::Slider::new(&mut z, 0.05..=8.0).logarithmic(true).vertical().show_value(false))
                .on_hover_text(format!("Масштаб {:.0}% (колесо мыши — тоже)", self.zoom * 100.0));
            if r.changed() {
                self.zoom_to(z);
            }
            if ui.button("➖").on_hover_text("Отдалить").clicked() {
                self.zoom_to(self.zoom / 1.25);
            }
        });
    }

    /// Кнопки и панель настроек в правом верхнем углу (как в Obsidian).
    /// Возвращает `true`, если изменились параметры сил.
    fn overlay(&mut self, ui: &mut Ui, rect: Rect, s: &mut GraphSettings) -> bool {
        let mut forces_changed = false;
        let bar = Rect::from_min_max(pos2(rect.right() - 260.0, rect.top() + 10.0), pos2(rect.right() - 10.0, rect.top() + 40.0));
        let mut fit = false;
        ui.scope_builder(egui::UiBuilder::new().max_rect(bar).layout(egui::Layout::right_to_left(egui::Align::Center)), |ui| {
            if ui
                .selectable_label(self.settings_open, "⚙")
                .on_hover_text("Настройки графа")
                .clicked()
            {
                self.settings_open = !self.settings_open;
            }
            fit = ui.button("⤢").on_hover_text("Вписать граф в окно").clicked();
            ui.toggle_value(&mut s.fisheye, "◉ рыбий глаз")
                .on_hover_text("Линза под курсором (клавиша F)");
        });
        if fit {
            self.fit_now(rect);
        }

        if !self.settings_open {
            self.zoom_slider(ui, rect);
            return false;
        }
        let w = 250.0f32.min(rect.width() - 20.0);
        let panel = Rect::from_min_size(pos2(rect.right() - w - 10.0, rect.top() + 46.0), vec2(w, (rect.height() - 56.0).max(100.0)));
        ui.scope_builder(egui::UiBuilder::new().max_rect(panel), |ui| {
            egui::Frame::popup(ui.style()).show(ui, |ui| {
                ui.set_width(w - 16.0);
                egui::ScrollArea::vertical().max_height(panel.height() - 16.0).show(ui, |ui| {
                    egui::CollapsingHeader::new("Отображение").default_open(true).show(ui, |ui| {
                        ui.checkbox(&mut s.show_subnets, "Подсети /24");
                        ui.checkbox(&mut s.show_issuers, "Издатели сертификатов");
                        ui.checkbox(&mut s.show_labels, "Подписи");
                        ui.add(egui::Slider::new(&mut s.label_zoom, 0.2..=3.0).text("порог подписей"));
                        ui.add(egui::Slider::new(&mut s.node_size, 0.4..=3.0).text("размер узлов"));
                        ui.add(egui::Slider::new(&mut s.link_width, 0.2..=3.0).text("толщина связей"));
                    });
                    egui::CollapsingHeader::new("Рыбий глаз").default_open(true).show(ui, |ui| {
                        ui.checkbox(&mut s.fisheye, "Включён (F)");
                        ui.add(egui::Slider::new(&mut s.fisheye_strength, 0.5..=8.0).text("сила"));
                        ui.add(egui::Slider::new(&mut s.fisheye_radius, 60.0..=600.0).text("радиус"));
                    });
                    egui::CollapsingHeader::new("Силы").default_open(false).show(ui, |ui| {
                        forces_changed |= ui.add(egui::Slider::new(&mut s.center_force, 0.0..=3.0).text("к центру")).changed();
                        forces_changed |= ui.add(egui::Slider::new(&mut s.repel_force, 0.0..=5.0).text("отталкивание")).changed();
                        forces_changed |= ui.add(egui::Slider::new(&mut s.link_force, 0.0..=2.0).text("притяжение связей")).changed();
                        forces_changed |= ui.add(egui::Slider::new(&mut s.link_distance, 10.0..=200.0).text("длина связей")).changed();
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.button("Встряхнуть").clicked() {
                            self.alpha = 1.0;
                        }
                        if ui.button("По умолчанию").clicked() {
                            *s = GraphSettings::default();
                            forces_changed = true;
                        }
                    });
                });
            });
        });
        forces_changed
    }
}

fn smoothstep(e0: f32, e1: f32, x: f32) -> f32 {
    let t = ((x - e0) / (e1 - e0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// Круговой «рыбий глаз» Саркара — Брауна (как d3-fisheye).
#[derive(Debug, Clone, Copy)]
struct Fisheye {
    focus: Pos2,
    radius: f32,
    distortion: f32,
    k0: f32,
    k1: f32,
}

impl Fisheye {
    fn new(focus: Pos2, radius: f32, distortion: f32) -> Self {
        let radius = radius.max(1.0);
        let distortion = distortion.max(0.0);
        let e = distortion.exp();
        let k0 = if distortion > 1e-4 { e / (e - 1.0) * radius } else { 0.0 };
        Self { focus, radius, distortion, k0, k1: distortion / radius }
    }

    /// Новое положение точки и коэффициент увеличения (≥ 1 внутри линзы).
    fn apply(&self, p: Pos2) -> (Pos2, f32) {
        if self.distortion <= 1e-4 {
            return (p, 1.0);
        }
        let d = p - self.focus;
        let dd = d.length();
        if dd < 1e-3 {
            return (p, (self.k0 * self.k1 * 0.75 + 0.25).min(4.0));
        }
        if dd >= self.radius {
            return (p, 1.0);
        }
        let k = self.k0 * (1.0 - (-dd * self.k1).exp()) / dd * 0.75 + 0.25;
        (self.focus + d * k, k.clamp(1.0, 4.0))
    }
}

struct Palette {
    bg: Color32,
    link: Color32,
    accent: Color32,
    text: Color32,
    label: Color32,
    muted: Color32,
    danger: Color32,
    warn: Color32,
    card: Color32,
    card_border: Color32,
    grey: Color32,
    subnet: Color32,
    proxy: Color32,
    socks: Color32,
    web: Color32,
    issuer: Color32,
}

impl Palette {
    fn new(dark: bool) -> Self {
        if dark {
            Self {
                bg: Color32::from_rgb(30, 30, 30),
                link: Color32::from_rgba_unmultiplied(160, 160, 160, 70),
                accent: Color32::from_rgb(168, 130, 255),
                text: Color32::from_rgb(235, 235, 235),
                label: Color32::from_rgb(190, 190, 190),
                muted: Color32::from_rgb(130, 130, 130),
                danger: Color32::from_rgb(251, 70, 76),
                warn: Color32::from_rgb(233, 151, 63),
                card: Color32::from_rgb(38, 38, 40),
                card_border: Color32::from_rgb(64, 64, 68),
                grey: Color32::from_rgb(150, 150, 150),
                subnet: Color32::from_rgb(220, 220, 225),
                proxy: Color32::from_rgb(138, 92, 245),
                socks: Color32::from_rgb(83, 223, 221),
                web: Color32::from_rgb(2, 122, 255),
                issuer: Color32::from_rgb(224, 172, 0),
            }
        } else {
            Self {
                bg: Color32::from_rgb(250, 250, 250),
                link: Color32::from_rgba_unmultiplied(120, 120, 120, 70),
                accent: Color32::from_rgb(124, 77, 255),
                text: Color32::from_rgb(30, 30, 30),
                label: Color32::from_rgb(70, 70, 70),
                muted: Color32::from_rgb(140, 140, 140),
                danger: Color32::from_rgb(224, 49, 71),
                warn: Color32::from_rgb(217, 115, 13),
                card: Color32::from_rgb(255, 255, 255),
                card_border: Color32::from_rgb(220, 220, 224),
                grey: Color32::from_rgb(130, 130, 130),
                subnet: Color32::from_rgb(60, 60, 66),
                proxy: Color32::from_rgb(124, 77, 255),
                socks: Color32::from_rgb(8, 166, 164),
                web: Color32::from_rgb(8, 109, 221),
                issuer: Color32::from_rgb(196, 140, 0),
            }
        }
    }

    fn node(&self, kind: NodeKind) -> Color32 {
        match kind {
            NodeKind::Subnet => self.subnet,
            NodeKind::Host => self.grey,
            NodeKind::Issuer => self.issuer,
            NodeKind::Service(ProxyKind::HttpProxy) => self.proxy,
            NodeKind::Service(ProxyKind::Socks5 | ProxyKind::Socks4) => self.socks,
            NodeKind::Service(ProxyKind::HttpServer) => self.web,
            NodeKind::Service(_) => self.grey.gamma_multiply(0.7),
            NodeKind::Map(k) => match k {
                MapKind::Me => self.accent,
                MapKind::Router => self.warn,
                MapKind::Hop => self.grey.gamma_multiply(0.8),
                MapKind::Subnet => self.subnet,
                MapKind::Host => self.grey,
                MapKind::Server => self.web,
                MapKind::Dc => self.issuer,
                MapKind::Proxy => self.proxy,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CertInfo;

    fn row(ip: [u8; 4], port: u16, kind: ProxyKind, issuer: Option<&str>) -> ProxyRow {
        let mut r = ProxyRow::new(Ipv4Addr::from(ip), port, "tcp-connect");
        r.kind = kind;
        if let Some(i) = issuer {
            r.ssl = SslInspection::Yes;
            r.probe.cert = Some(CertInfo { issuer: i.into(), ..Default::default() });
        }
        r
    }

    #[test]
    fn builds_hierarchy_with_shared_issuer() {
        let rows = [
            row([10, 0, 0, 1], 3128, ProxyKind::HttpProxy, Some("CN=Corp CA, O=Corp")),
            row([10, 0, 0, 1], 8080, ProxyKind::HttpProxy, Some("CN=Corp CA, O=Corp")),
            row([10, 0, 1, 7], 1080, ProxyKind::Socks5, None),
        ];
        let refs: Vec<&ProxyRow> = rows.iter().collect();
        let mut g = GraphView::default();
        g.sync(&refs, &GraphSettings::default());
        // 2 подсети, 2 узла, 3 сервиса, 1 издатель
        assert_eq!(g.nodes.len(), 8);
        // подсеть–узел ×2, узел–сервис ×3, сервис–издатель ×2
        assert_eq!(g.edges.len(), 7);
        let iss = g.nodes.iter().position(|n| n.kind == NodeKind::Issuer).unwrap();
        assert_eq!(g.nodes[iss].label, "Corp CA");
        assert_eq!(g.nodes[iss].degree, 2);
        let host = g.nodes.iter().find(|n| n.key == "ip:10.0.0.1").unwrap();
        assert!(host.flags.ssl, "флаг SSL-инспекции поднимается на узел");
    }

    #[test]
    fn rebuild_keeps_positions_and_respects_toggles() {
        let rows = [row([10, 0, 0, 1], 3128, ProxyKind::HttpProxy, Some("CN=X"))];
        let refs: Vec<&ProxyRow> = rows.iter().collect();
        let mut g = GraphView::default();
        let mut s = GraphSettings::default();
        g.sync(&refs, &s);
        let pos = g.nodes.iter().find(|n| n.key == "ip:10.0.0.1").unwrap().pos;
        s.show_subnets = false;
        s.show_issuers = false;
        g.sync(&refs, &s);
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.nodes.iter().find(|n| n.key == "ip:10.0.0.1").unwrap().pos, pos);
    }

    #[test]
    fn simulation_settles_without_nan() {
        let rows: Vec<ProxyRow> = (0..60)
            .map(|i| row([10, 0, (i / 20) as u8, i as u8], 3128, ProxyKind::HttpProxy, None))
            .collect();
        let refs: Vec<&ProxyRow> = rows.iter().collect();
        let mut g = GraphView::default();
        let s = GraphSettings::default();
        g.sync(&refs, &s);
        for _ in 0..400 {
            g.tick(&s);
        }
        assert!(g.alpha < 0.01);
        assert!(g.nodes.iter().all(|n| n.pos.x.is_finite() && n.pos.y.is_finite()));
        let b = g.bounds().unwrap();
        assert!(b.width() < 5000.0 && b.height() < 5000.0, "граф не разлетается: {b:?}");
        // Соседние узлы не слипаются в одну точку.
        let p: Vec<Vec2> = g.nodes.iter().map(|n| n.pos).collect();
        let min_d = (0..p.len())
            .flat_map(|i| ((i + 1)..p.len()).map(move |j| (i, j)))
            .map(|(i, j)| (p[i] - p[j]).length())
            .fold(f32::MAX, f32::min);
        assert!(min_d > 0.5, "минимальное расстояние {min_d}");
    }

    #[test]
    fn fisheye_magnifies_near_focus_only() {
        let f = Fisheye::new(pos2(0.0, 0.0), 200.0, 3.0);
        let (near, z_near) = f.apply(pos2(20.0, 0.0));
        assert!(near.x > 20.0 && z_near > 1.5, "точки у фокуса раздвигаются");
        let (edge, z_edge) = f.apply(pos2(199.0, 0.0));
        assert!((edge.x - 199.0).abs() < 2.0 && z_edge < 1.1, "на краю линзы искажение сходит на нет");
        assert_eq!(f.apply(pos2(300.0, 0.0)), (pos2(300.0, 0.0), 1.0));
        let off = Fisheye::new(pos2(0.0, 0.0), 200.0, 0.0);
        assert_eq!(off.apply(pos2(20.0, 0.0)), (pos2(20.0, 0.0), 1.0));
    }
}
