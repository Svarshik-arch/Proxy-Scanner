//! SNMP-мониторинг интерфейсов (загрузка, ошибки, дуплекс, флапы) и топология L2
//! по LLDP/CDP с обходом соседей.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;
use super::snmp::{Client, Value, parse_oid};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Устройства: `адрес [community]` по одному в строке.
    pub targets: String,
    pub community: String,
    pub interval_s: u64,
    /// Порог загрузки, % (предупреждение).
    pub warn_util: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self { targets: String::new(), community: "public".into(), interval_s: 10, warn_util: 70.0 }
    }
}

/// Строки целей: (адрес, community).
pub fn parse_targets(text: &str, default: &str) -> Vec<(String, String)> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut w = l.split_whitespace();
            let a = w.next().unwrap_or("").to_string();
            (a, w.next().unwrap_or(default).to_string())
        })
        .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counters {
    pub index: u32,
    pub name: String,
    pub alias: String,
    /// 1 up, 2 down, …
    pub oper: i64,
    pub admin: i64,
    pub speed_mbps: u64,
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
    /// 1 неизвестно, 2 полудуплекс, 3 полный.
    pub duplex: i64,
    pub last_change: u64,
}

#[derive(Debug, Clone)]
pub enum Event {
    /// Адрес, имя устройства, время снятия (с), счётчики.
    Sample(String, String, f64, Vec<Counters>),
    Error(String, String),
}

const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
const IF_ADMIN: &str = "1.3.6.1.2.1.2.2.1.7";
const IF_OPER: &str = "1.3.6.1.2.1.2.2.1.8";
const IF_LASTCHANGE: &str = "1.3.6.1.2.1.2.2.1.9";
const IF_SPEED: &str = "1.3.6.1.2.1.2.2.1.5";
const IF_IN: &str = "1.3.6.1.2.1.2.2.1.10";
const IF_IN_DISC: &str = "1.3.6.1.2.1.2.2.1.13";
const IF_IN_ERR: &str = "1.3.6.1.2.1.2.2.1.14";
const IF_OUT: &str = "1.3.6.1.2.1.2.2.1.16";
const IF_OUT_DISC: &str = "1.3.6.1.2.1.2.2.1.19";
const IF_OUT_ERR: &str = "1.3.6.1.2.1.2.2.1.20";
const IF_NAME: &str = "1.3.6.1.2.1.31.1.1.1.1";
const IF_HC_IN: &str = "1.3.6.1.2.1.31.1.1.1.6";
const IF_HC_OUT: &str = "1.3.6.1.2.1.31.1.1.1.10";
const IF_HIGHSPEED: &str = "1.3.6.1.2.1.31.1.1.1.15";
const IF_ALIAS: &str = "1.3.6.1.2.1.31.1.1.1.18";
const DOT3_DUPLEX: &str = "1.3.6.1.2.1.10.7.2.1.19";
const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";

async fn column(c: &mut Client, oid: &str) -> BTreeMap<u32, Value> {
    c.walk(&parse_oid(oid), 8192).await.unwrap_or_default().into_iter().filter_map(|(i, v)| Some((*i.first()?, v))).collect()
}

fn num(v: Option<&Value>) -> u64 {
    v.and_then(|v| v.as_int()).map(|x| x as u64).unwrap_or(0)
}

/// Один опрос устройства.
pub async fn sample(addr: &str, community: &str, timeout: Duration) -> Result<(String, Vec<Counters>), String> {
    let mut c = Client::new(addr, community, timeout).await?;
    let name = c.get(&parse_oid(SYS_NAME)).await?.text();
    let mut names = column(&mut c, IF_NAME).await;
    if names.is_empty() {
        names = column(&mut c, IF_DESCR).await;
    }
    let alias = column(&mut c, IF_ALIAS).await;
    let admin = column(&mut c, IF_ADMIN).await;
    let oper = column(&mut c, IF_OPER).await;
    let last = column(&mut c, IF_LASTCHANGE).await;
    let hs = column(&mut c, IF_HIGHSPEED).await;
    let sp = column(&mut c, IF_SPEED).await;
    let mut inn = column(&mut c, IF_HC_IN).await;
    let mut out = column(&mut c, IF_HC_OUT).await;
    if inn.is_empty() {
        inn = column(&mut c, IF_IN).await;
        out = column(&mut c, IF_OUT).await;
    }
    let ie = column(&mut c, IF_IN_ERR).await;
    let oe = column(&mut c, IF_OUT_ERR).await;
    let id = column(&mut c, IF_IN_DISC).await;
    let od = column(&mut c, IF_OUT_DISC).await;
    let dup = column(&mut c, DOT3_DUPLEX).await;
    let mut v = Vec::new();
    for (i, n) in &names {
        let speed = match num(hs.get(i)) {
            0 => num(sp.get(i)) / 1_000_000,
            x => x,
        };
        v.push(Counters {
            index: *i,
            name: n.text(),
            alias: alias.get(i).map(|x| x.text()).unwrap_or_default(),
            oper: oper.get(i).and_then(|x| x.as_int()).unwrap_or(0),
            admin: admin.get(i).and_then(|x| x.as_int()).unwrap_or(0),
            speed_mbps: speed,
            in_octets: num(inn.get(i)),
            out_octets: num(out.get(i)),
            in_errors: num(ie.get(i)),
            out_errors: num(oe.get(i)),
            in_discards: num(id.get(i)),
            out_discards: num(od.get(i)),
            duplex: dup.get(i).and_then(|x| x.as_int()).unwrap_or(1),
            last_change: num(last.get(i)),
        });
    }
    if v.is_empty() {
        return Err("таблица интерфейсов пуста".into());
    }
    Ok((name, v))
}

fn now_s() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let targets = parse_targets(&cfg.targets, &cfg.community);
    let every = Duration::from_secs(cfg.interval_s.max(2));
    loop {
        let t0 = tokio::time::Instant::now();
        super::for_each_limited(targets.clone(), 16, &cancel, |(a, c)| {
            let sink = sink.clone();
            async move {
                match sample(&a, &c, Duration::from_secs(3)).await {
                    Ok((name, v)) => sink.send(Event::Sample(a, name, now_s(), v)),
                    Err(e) => sink.send(Event::Error(a, e)),
                }
            }
        })
        .await;
        tokio::select! {
            _ = tokio::time::sleep_until(t0 + every) => {}
            _ = cancel.cancelled() => return,
        }
    }
}

// ---------------------------------------------------------------------------
// Скорости и выводы
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Rate {
    pub in_bps: f64,
    pub out_bps: f64,
    /// Загрузка, % от скорости порта (большее из направлений).
    pub util: Option<f64>,
    pub errors: u64,
    pub discards: u64,
    pub flapped: bool,
}

/// Скорость между двумя снятиями (с учётом переполнения 32-битных счётчиков).
pub fn rate(a: &Counters, b: &Counters, dt: f64) -> Rate {
    let d = |x: u64, y: u64| if y >= x { y - x } else if x <= u32::MAX as u64 { (u32::MAX as u64 - x) + y + 1 } else { 0 };
    let dt = dt.max(0.001);
    let in_bps = d(a.in_octets, b.in_octets) as f64 * 8.0 / dt;
    let out_bps = d(a.out_octets, b.out_octets) as f64 * 8.0 / dt;
    let util = (b.speed_mbps > 0).then(|| in_bps.max(out_bps) / (b.speed_mbps as f64 * 1e6) * 100.0);
    Rate {
        in_bps,
        out_bps,
        util,
        errors: b.in_errors.saturating_sub(a.in_errors) + b.out_errors.saturating_sub(a.out_errors),
        discards: b.in_discards.saturating_sub(a.in_discards) + b.out_discards.saturating_sub(a.out_discards),
        flapped: a.last_change != b.last_change && a.last_change != 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Bad,
    Warn,
    Info,
}

/// Выводы по порту: что не так и что делать.
pub fn verdicts(c: &Counters, r: Option<&Rate>, warn_util: f64) -> Vec<(Severity, String)> {
    let mut v = Vec::new();
    if c.admin == 1 && c.oper == 2 && !c.alias.is_empty() {
        v.push((Severity::Warn, format!("порт включён и подписан «{}», но линка нет — кабель, устройство или трансивер", c.alias)));
    }
    if c.oper != 1 {
        return v;
    }
    if c.duplex == 2 {
        v.push((Severity::Bad, "полудуплекс — почти всегда рассогласование с соседом: коллизии и потери. Выставьте автосогласование с обеих сторон".into()));
    }
    if (c.speed_mbps == 10 || c.speed_mbps == 100) && !c.name.to_lowercase().starts_with("fa") {
        v.push((Severity::Warn, format!("скорость {} Мбит/с — проверьте кабель (пары) и настройки соседа", c.speed_mbps)));
    }
    if let Some(r) = r {
        if let Some(u) = r.util {
            if u >= 90.0 {
                v.push((Severity::Bad, format!("загрузка {u:.0}% — канал забит, будут потери и задержки")));
            } else if u >= warn_util {
                v.push((Severity::Warn, format!("загрузка {u:.0}%")));
            }
        }
        if r.errors > 0 {
            v.push((Severity::Bad, format!("растут ошибки (+{}) — кабель, разъём, трансивер или дуплекс", r.errors)));
        }
        if r.discards > 0 {
            v.push((Severity::Warn, format!("отбрасываются пакеты (+{}) — переполнение буферов или QoS", r.discards)));
        }
        if r.flapped {
            v.push((Severity::Bad, "линк переподнимался между опросами (флап)".into()));
        }
    }
    v.sort_by_key(|x| x.0);
    v
}

pub fn human_bps(b: f64) -> String {
    if b >= 1e9 {
        format!("{:.2} Гбит/с", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} Мбит/с", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.0} кбит/с", b / 1e3)
    } else {
        format!("{b:.0} бит/с")
    }
}

// ---------------------------------------------------------------------------
// Топология по LLDP и CDP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Node {
    pub address: String,
    pub name: String,
    pub descr: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Link {
    pub from: String,
    pub from_port: String,
    /// Имя соседа (как он себя называет).
    pub to: String,
    pub to_port: String,
    pub to_address: Option<String>,
    /// lldp / cdp
    pub via: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Topology {
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TopoConfig {
    pub seeds: String,
    pub community: String,
    /// Идти к соседям (по адресу управления из LLDP/CDP).
    pub recurse: bool,
    pub max_devices: usize,
}

impl Default for TopoConfig {
    fn default() -> Self {
        Self { seeds: String::new(), community: "public".into(), recurse: true, max_devices: 64 }
    }
}

#[derive(Debug, Clone)]
pub enum TopoEvent {
    Log(String),
    Node(Node, Vec<Link>),
}

const LLDP_LOC_PORT_ID: &str = "1.0.8802.1.1.2.1.3.7.1.3";
const LLDP_LOC_PORT_DESC: &str = "1.0.8802.1.1.2.1.3.7.1.4";
const LLDP_REM_PORT_ID: &str = "1.0.8802.1.1.2.1.4.1.1.7";
const LLDP_REM_PORT_DESC: &str = "1.0.8802.1.1.2.1.4.1.1.8";
const LLDP_REM_SYSNAME: &str = "1.0.8802.1.1.2.1.4.1.1.9";
const LLDP_REM_MAN_ADDR: &str = "1.0.8802.1.1.2.1.4.2.1.4";
const CDP_ADDR: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1.4";
const CDP_DEVICE: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1.6";
const CDP_PORT: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1.7";
const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const IF_NAME_T: &str = "1.3.6.1.2.1.31.1.1.1.1";

/// Порт-ID бывает MAC-адресом в байтах — показываем текстом.
fn port_text(v: &Value) -> String {
    match v {
        Value::Bytes(b) if b.len() == 6 && b.iter().any(|x| !x.is_ascii_graphic()) => b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"),
        _ => v.text(),
    }
}

/// Адрес управления из индекса lldpRemManAddrTable:
/// timeMark.localPort.remIndex.subtype.len.addr…
pub fn man_addr(idx: &[u32]) -> Option<(u32, u32, Ipv4Addr)> {
    if idx.len() >= 9 && idx[3] == 1 && idx[4] == 4 {
        let a = Ipv4Addr::new(idx[5] as u8, idx[6] as u8, idx[7] as u8, idx[8] as u8);
        return Some((idx[1], idx[2], a));
    }
    None
}

/// Соседи одного устройства.
pub async fn neighbors(addr: &str, community: &str) -> (Node, Vec<Link>) {
    let mut node = Node { address: addr.into(), ..Default::default() };
    let mut c = match Client::new(addr, community, Duration::from_secs(3)).await {
        Ok(c) => c,
        Err(e) => {
            node.error = Some(e);
            return (node, Vec::new());
        }
    };
    match c.get(&parse_oid(SYS_NAME)).await {
        Ok(v) => node.name = v.text(),
        Err(e) => {
            node.error = Some(e);
            return (node, Vec::new());
        }
    }
    node.descr = c.get(&parse_oid(SYS_DESCR)).await.map(|v| v.text()).unwrap_or_default();
    let mut walk = async |oid: &str| c.walk(&parse_oid(oid), 4096).await.unwrap_or_default();
    let loc_id: BTreeMap<u32, String> = walk(LLDP_LOC_PORT_ID).await.into_iter().filter_map(|(i, v)| Some((*i.first()?, port_text(&v)))).collect();
    let loc_desc: BTreeMap<u32, String> = walk(LLDP_LOC_PORT_DESC).await.into_iter().filter_map(|(i, v)| Some((*i.first()?, v.text()))).collect();
    let local = |p: u32| loc_desc.get(&p).filter(|s| !s.is_empty()).or(loc_id.get(&p)).cloned().unwrap_or_else(|| format!("порт {p}"));
    // Ключ соседа: (localPort, remIndex).
    let key = |i: &[u32]| (i.get(1).copied().unwrap_or(0), i.get(2).copied().unwrap_or(0));
    let names: BTreeMap<(u32, u32), String> = walk(LLDP_REM_SYSNAME).await.into_iter().map(|(i, v)| (key(&i), v.text())).collect();
    let rport: BTreeMap<(u32, u32), String> = walk(LLDP_REM_PORT_ID).await.into_iter().map(|(i, v)| (key(&i), port_text(&v))).collect();
    let rdesc: BTreeMap<(u32, u32), String> = walk(LLDP_REM_PORT_DESC).await.into_iter().map(|(i, v)| (key(&i), v.text())).collect();
    let addrs: BTreeMap<(u32, u32), Ipv4Addr> = walk(LLDP_REM_MAN_ADDR).await.into_iter().filter_map(|(i, _)| man_addr(&i).map(|(p, r, a)| ((p, r), a))).collect();
    let mut links = Vec::new();
    let mut keys: BTreeSet<(u32, u32)> = names.keys().copied().collect();
    keys.extend(rport.keys().copied());
    for k in keys {
        let to = names.get(&k).cloned().filter(|s| !s.is_empty()).unwrap_or_else(|| rport.get(&k).cloned().unwrap_or_default());
        links.push(Link {
            from: node.name.clone(),
            from_port: local(k.0),
            to,
            to_port: rdesc.get(&k).filter(|s| !s.is_empty()).or(rport.get(&k)).cloned().unwrap_or_default(),
            to_address: addrs.get(&k).map(|a| a.to_string()),
            via: "lldp".into(),
        });
    }
    // CDP (Cisco и совместимые): индекс ifIndex.deviceIndex.
    let devs = walk(CDP_DEVICE).await;
    if !devs.is_empty() {
        let ifn: BTreeMap<u32, String> = walk(IF_NAME_T).await.into_iter().filter_map(|(i, v)| Some((*i.first()?, v.text()))).collect();
        let ports: BTreeMap<Vec<u32>, String> = walk(CDP_PORT).await.into_iter().map(|(i, v)| (i, v.text())).collect();
        let caddr: BTreeMap<Vec<u32>, String> = walk(CDP_ADDR)
            .await
            .into_iter()
            .filter_map(|(i, v)| match v {
                Value::Bytes(b) if b.len() == 4 => Some((i, Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())),
                Value::Ip(a) => Some((i, a.to_string())),
                _ => None,
            })
            .collect();
        for (i, v) in devs {
            let to = v.text();
            let from_port = i.first().and_then(|x| ifn.get(x)).cloned().unwrap_or_default();
            if links.iter().any(|l: &Link| l.from_port == from_port && same_name(&l.to, &to)) {
                continue;
            }
            links.push(Link {
                from: node.name.clone(),
                from_port,
                to,
                to_port: ports.get(&i).cloned().unwrap_or_default(),
                to_address: caddr.get(&i).cloned(),
                via: "cdp".into(),
            });
        }
    }
    (node, links)
}

/// Имена совпадают без домена (`sw1.corp.local` = `sw1`) и регистра.
pub fn same_name(a: &str, b: &str) -> bool {
    let s = |x: &str| x.split(['.', '(']).next().unwrap_or("").trim().to_lowercase();
    !a.is_empty() && s(a) == s(b)
}

pub async fn discover(cfg: TopoConfig, sink: Sink<TopoEvent>, cancel: CancellationToken) {
    let mut queue: VecDeque<(String, String)> = parse_targets(&cfg.seeds, &cfg.community).into();
    let mut seen: BTreeSet<String> = queue.iter().map(|x| x.0.clone()).collect();
    let mut names: Vec<String> = Vec::new();
    let mut done = 0;
    while let Some((a, c)) = queue.pop_front() {
        if cancel.is_cancelled() || done >= cfg.max_devices {
            break;
        }
        done += 1;
        sink.send(TopoEvent::Log(format!("опрос {a}…")));
        let (node, links) = tokio::select! {
            r = neighbors(&a, &c) => r,
            _ = cancel.cancelled() => break,
        };
        if !node.name.is_empty() {
            names.push(node.name.clone());
        }
        if cfg.recurse {
            for l in &links {
                if let Some(addr) = &l.to_address
                    && !names.iter().any(|n| same_name(n, &l.to))
                    && seen.insert(addr.clone())
                {
                    queue.push_back((addr.clone(), c.clone()));
                }
            }
        }
        sink.send(TopoEvent::Node(node, links));
    }
}

/// Узлы для карты: опрошенные устройства и соседи, которых опросить не удалось.
pub fn map_nodes(t: &Topology) -> Vec<crate::graph::MapNode> {
    use crate::graph::{MapKind, MapNode};
    let mut out: Vec<MapNode> = Vec::new();
    let key_of = |name: &str| format!("dev:{}", name.split('.').next().unwrap_or(name).to_lowercase());
    for n in t.nodes.iter().filter(|n| !n.name.is_empty()) {
        out.push(MapNode {
            key: key_of(&n.name),
            kind: MapKind::Router,
            label: n.name.clone(),
            detail: vec![n.address.clone(), n.descr.lines().next().unwrap_or("").chars().take(80).collect()],
            parent: None,
            links: Vec::new(),
            problem: false,
            warning: false,
        });
    }
    for l in &t.links {
        if l.to.is_empty() {
            continue;
        }
        let a = key_of(&l.from);
        let b = key_of(&l.to);
        if !out.iter().any(|n| n.key == b) {
            out.push(MapNode {
                key: b.clone(),
                kind: MapKind::Host,
                label: l.to.clone(),
                detail: vec![l.to_address.clone().unwrap_or_default(), "не опрошен (нет SNMP или адреса)".into()],
                parent: None,
                links: Vec::new(),
                problem: false,
                warning: true,
            });
        }
        if let Some(n) = out.iter_mut().find(|n| n.key == a) {
            n.detail.push(format!("{} → {} {}", l.from_port, l.to, l.to_port));
            let already = n.links.contains(&b);
            if !already && a != b {
                n.links.push(b);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(i: u64, o: u64, e: u64, lc: u64) -> Counters {
        Counters { index: 1, name: "Gi0/1".into(), oper: 1, admin: 1, speed_mbps: 100, in_octets: i, out_octets: o, in_errors: e, duplex: 3, last_change: lc, ..Default::default() }
    }

    #[test]
    fn rates_and_verdicts() {
        let a = c(0, 0, 0, 5);
        let b = c(1_250_000_000 / 10, 0, 3, 9); // 125 МБ за 10 с = 100 Мбит/с
        let r = rate(&a, &b, 10.0);
        assert!((r.in_bps - 1e8).abs() < 1.0);
        assert!((r.util.unwrap() - 100.0).abs() < 0.01);
        assert_eq!(r.errors, 3);
        assert!(r.flapped);
        let v = verdicts(&b, Some(&r), 70.0);
        assert!(v.iter().any(|x| x.1.contains("загрузка 100%")));
        assert!(v.iter().any(|x| x.1.contains("ошибки")));
        assert!(v.iter().any(|x| x.1.contains("скорость 100")));
        // Переполнение 32-битного счётчика.
        let r = rate(&c(u32::MAX as u64 - 9, 0, 0, 0), &c(10, 0, 0, 0), 1.0);
        assert_eq!(r.in_bps, 20.0 * 8.0);
        let mut h = b.clone();
        h.duplex = 2;
        assert_eq!(verdicts(&h, None, 70.0)[0].0, Severity::Bad);
    }

    #[test]
    fn lldp_index() {
        assert_eq!(man_addr(&[0, 12, 3, 1, 4, 10, 0, 0, 2]), Some((12, 3, Ipv4Addr::new(10, 0, 0, 2))));
        assert!(same_name("sw1.corp.local", "SW1"));
        let t = Topology {
            nodes: vec![Node { address: "10.0.0.1".into(), name: "core".into(), ..Default::default() }],
            links: vec![Link { from: "core".into(), from_port: "Gi1".into(), to: "sw1.corp".into(), to_port: "Gi24".into(), to_address: None, via: "lldp".into() }],
        };
        let m = map_nodes(&t);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].links, vec!["dev:sw1".to_string()]);
        assert_eq!(parse_targets("10.0.0.1\n10.0.0.2 secret # ядро\n", "public"), vec![("10.0.0.1".into(), "public".into()), ("10.0.0.2".into(), "secret".into())]);
    }
}
