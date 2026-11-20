//! Наблюдение за изменениями сети: по расписанию опрашивает подсети (узлы, MAC,
//! имена, открытые порты, сертификаты TLS), сравнивает с прошлым опросом и сообщает
//! об изменениях: новый узел, пропавший узел, сменился MAC, открылся или закрылся
//! порт, сменился сертификат.
//!
//! Чтобы короткий сбой связи не давал ложных «узел пропал / порт закрылся»,
//! пропажа считается подтверждённой после двух опросов подряд.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;
use super::discovery;
use super::monitor::Status;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub targets: String,
    /// Порты, за которыми следим.
    pub tcp_ports: String,
    /// Интервал между опросами, минуты.
    pub interval_min: u64,
    /// Количество опросов (0 — до остановки).
    pub cycles: u32,
    /// Следить за сертификатами на TLS-портах.
    pub certs: bool,
    pub timeout_ms: u64,
    pub alerts: super::notify::Alerts,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: String::new(),
            tcp_ports: "21,22,23,25,53,80,135,139,443,445,1433,3306,3389,5432,5900,5985,8080,8443".into(),
            interval_min: 60,
            cycles: 0,
            certs: true,
            timeout_ms: 1000,
            alerts: Default::default(),
        }
    }
}

const TLS_PORTS: [u16; 6] = [443, 636, 993, 3269, 8443, 9443];
/// Порты, появление которых — повод для тревоги.
const RISKY: [u16; 8] = [21, 23, 135, 139, 445, 3389, 5900, 6379];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HostSnap {
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub name: Option<String>,
    pub ports: BTreeSet<u16>,
    /// Порт → «отпечаток SHA-256 (кратко) · субъект».
    pub certs: BTreeMap<u16, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub at: u64,
    pub hosts: BTreeMap<std::net::Ipv4Addr, HostSnap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    NewHost,
    GoneHost,
    MacChanged,
    NameChanged,
    PortOpened,
    PortClosed,
    CertChanged,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::NewHost => "новый узел",
            Kind::GoneHost => "узел пропал",
            Kind::MacChanged => "сменился MAC",
            Kind::NameChanged => "сменилось имя",
            Kind::PortOpened => "открылся порт",
            Kind::PortClosed => "закрылся порт",
            Kind::CertChanged => "сменился сертификат",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub at: u64,
    pub kind: Kind,
    pub host: std::net::Ipv4Addr,
    pub detail: String,
    /// Тревога (новый узел с неизвестным производителем, рискованный порт, смена MAC).
    pub alarm: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    /// Первый опрос — эталон.
    pub baseline: Option<Snapshot>,
    pub last: Option<Snapshot>,
    pub changes: Vec<Change>,
    pub cycles: u32,
    /// Когда узел впервые и в последний раз отвечал (unix).
    pub seen: BTreeMap<std::net::Ipv4Addr, (u64, u64)>,
}

impl Report {
    /// Учесть опрос: обновить время появления узлов.
    pub fn note_seen(&mut self, s: &Snapshot) {
        for ip in s.hosts.keys() {
            let e = self.seen.entry(*ip).or_insert((s.at, s.at));
            e.1 = e.1.max(s.at);
        }
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    /// Начался опрос номер N.
    Cycle(u32),
    Snapshot(Box<Snapshot>),
    Change(Box<Change>),
    /// Следующий опрос — в это время (unix).
    Next(u64),
}

/// Счётчики пропаж между опросами (узел или узел+порт → сколько опросов подряд нет).
#[derive(Default)]
pub struct Misses {
    hosts: BTreeMap<std::net::Ipv4Addr, u32>,
    ports: BTreeMap<(std::net::Ipv4Addr, u16), u32>,
}

/// Изменения между прошлым и новым опросом. `prev` дополняется подтверждёнными
/// пропажами (узел/порт, которых нет второй раз подряд, удаляются из него).
pub fn diff(prev: &mut Snapshot, new: &Snapshot, misses: &mut Misses) -> Vec<Change> {
    let mut out = Vec::new();
    let at = new.at;
    let mut push = |kind: Kind, host, detail: String, alarm: bool| out.push(Change { at, kind, host, detail, alarm });
    for (ip, h) in &new.hosts {
        misses.hosts.remove(ip);
        match prev.hosts.get(ip) {
            None => {
                let who = [h.name.clone(), h.vendor.clone(), h.mac.clone()].into_iter().flatten().collect::<Vec<_>>().join(", ");
                let ports = h.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                let alarm = h.vendor.is_none() || h.ports.iter().any(|p| RISKY.contains(p));
                push(Kind::NewHost, *ip, format!("{who}{}", if ports.is_empty() { String::new() } else { format!(" · порты {ports}") }), alarm);
            }
            Some(old) => {
                if let (Some(a), Some(b)) = (&old.mac, &h.mac)
                    && !a.eq_ignore_ascii_case(b)
                {
                    push(
                        Kind::MacChanged,
                        *ip,
                        format!("{a} ({}) → {b} ({})", old.vendor.clone().unwrap_or_default(), h.vendor.clone().unwrap_or_default()),
                        true,
                    );
                }
                if let (Some(a), Some(b)) = (&old.name, &h.name)
                    && !a.eq_ignore_ascii_case(b)
                {
                    push(Kind::NameChanged, *ip, format!("{a} → {b}"), false);
                }
                for p in h.ports.difference(&old.ports) {
                    misses.ports.remove(&(*ip, *p));
                    push(Kind::PortOpened, *ip, format!("{p}/tcp"), RISKY.contains(p));
                }
                for p in old.ports.difference(&h.ports) {
                    let n = misses.ports.entry((*ip, *p)).or_insert(0);
                    *n += 1;
                    if *n >= 2 {
                        push(Kind::PortClosed, *ip, format!("{p}/tcp"), false);
                    }
                }
                for (p, c) in &h.certs {
                    if let Some(oc) = old.certs.get(p)
                        && oc != c
                    {
                        push(Kind::CertChanged, *ip, format!("порт {p}: {oc} → {c}"), true);
                    }
                }
            }
        }
    }
    for (ip, old) in &prev.hosts {
        if !new.hosts.contains_key(ip) {
            let n = misses.hosts.entry(*ip).or_insert(0);
            *n += 1;
            if *n >= 2 {
                let who = [old.name.clone(), old.mac.clone()].into_iter().flatten().collect::<Vec<_>>().join(", ");
                push(Kind::GoneHost, *ip, who, false);
            }
        }
    }
    // Новое состояние: всё новое плюс пропавшее, но ещё не подтверждённое.
    let mut merged = new.clone();
    for (ip, old) in &prev.hosts {
        match merged.hosts.get_mut(ip) {
            None if misses.hosts.get(ip).is_some_and(|n| *n < 2) => {
                merged.hosts.insert(*ip, old.clone());
            }
            Some(h) => {
                for p in &old.ports {
                    if !h.ports.contains(p) && misses.ports.get(&(*ip, *p)).is_some_and(|n| *n < 2) {
                        h.ports.insert(*p);
                    }
                }
            }
            _ => {}
        }
    }
    misses.hosts.retain(|_, n| *n < 2);
    misses.ports.retain(|_, n| *n < 2);
    *prev = merged;
    out
}

/// Один опрос: узлы, открытые порты, сертификаты.
pub async fn snapshot(cfg: &Config, cancel: &CancellationToken) -> Result<Snapshot, String> {
    let dc = discovery::Config {
        targets: cfg.targets.clone(),
        tcp_ports: cfg.tcp_ports.clone(),
        timeout_ms: cfg.timeout_ms,
        ssdp: false,
        ..Default::default()
    };
    let (sink, rx) = Sink::new(None);
    discovery::run(dc, sink, cancel.clone()).await;
    let mut snap = Snapshot {
        at: crate::session::now_unix(),
        hosts: BTreeMap::new(),
    };
    let mut error = None;
    while let Ok(e) = rx.try_recv() {
        match e {
            discovery::Event::Host(h) if h.alive => {
                let name = h.dns_name.clone().or_else(|| h.netbios.as_ref().and_then(|n| n.name.clone())).or(h.mdns_name.clone());
                snap.hosts.insert(
                    h.ip,
                    HostSnap {
                        mac: h.mac.clone(),
                        vendor: h.vendor.clone(),
                        name,
                        ports: h.open_ports.iter().copied().collect(),
                        certs: BTreeMap::new(),
                    },
                );
            }
            discovery::Event::Log(l) if l.contains("ошибка") || l.contains("некоррект") => error = Some(l),
            _ => {}
        }
    }
    if snap.hosts.is_empty()
        && let Some(e) = error
    {
        return Err(e);
    }
    if cfg.certs {
        let jobs: Vec<(std::net::Ipv4Addr, u16)> = snap
            .hosts
            .iter()
            .flat_map(|(ip, h)| h.ports.iter().filter(|p| TLS_PORTS.contains(p)).map(move |p| (*ip, *p)))
            .collect();
        let found = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let timeout = cfg.timeout_ms.max(2000);
        super::for_each_limited(jobs, 16, cancel, |(ip, port)| {
            let found = found.clone();
            async move {
                let hc = super::http::Config {
                    url: format!("https://{ip}:{port}/"),
                    method: "HEAD".into(),
                    timeout_ms: timeout,
                    follow_redirects: false,
                    body_limit_kb: 1,
                    ..Default::default()
                };
                if let Ok(h) = super::http::fetch(&hc, None).await
                    && let Some(leaf) = h.first().and_then(|h| h.tls.as_ref()).and_then(|t| t.chain.first())
                {
                    let fp: String = leaf.sha256.chars().filter(|c| *c != ':').take(16).collect();
                    found.lock().unwrap().push((ip, port, format!("{fp} · {}", leaf.short_subject())));
                }
            }
        })
        .await;
        for (ip, port, c) in found.lock().unwrap().drain(..) {
            if let Some(h) = snap.hosts.get_mut(&ip) {
                h.certs.insert(port, c);
            }
        }
    }
    Ok(snap)
}

fn alert(ch: &Change) -> super::monitor::Change {
    super::monitor::Change {
        at: ch.at,
        line: format!("наблюдение {}", ch.host),
        from: Status::Ok,
        to: if ch.alarm { Status::Fail } else { Status::Warn },
        detail: format!("{}: {}", ch.kind.label(), ch.detail),
    }
}

/// Наблюдение: опросы по расписанию. `prev` — последний известный опрос (из сессии).
pub async fn run(cfg: Config, prev: Option<Snapshot>, sink: Sink<Event>, cancel: CancellationToken) {
    if crate::targets::parse_targets(&cfg.targets).is_err() || cfg.targets.trim().is_empty() {
        return sink.send(Event::Log("укажите подсети для наблюдения".into()));
    }
    let mut state = prev;
    let mut misses = Misses::default();
    let mut n = 0u32;
    loop {
        n += 1;
        sink.send(Event::Cycle(n));
        match snapshot(&cfg, &cancel).await {
            Ok(snap) => {
                if cancel.is_cancelled() {
                    return;
                }
                match &mut state {
                    None => state = Some(snap.clone()),
                    Some(p) => {
                        for ch in diff(p, &snap, &mut misses) {
                            for e in super::notify::send(&cfg.alerts, &alert(&ch)).await {
                                sink.send(Event::Log(format!("уведомление: {e}")));
                            }
                            sink.send(Event::Change(Box::new(ch)));
                        }
                    }
                }
                sink.send(Event::Snapshot(Box::new(snap)));
            }
            Err(e) => sink.send(Event::Log(e)),
        }
        if cfg.cycles > 0 && n >= cfg.cycles {
            return;
        }
        let wait = Duration::from_secs(cfg.interval_min.max(1) * 60);
        sink.send(Event::Next(crate::session::now_unix() + wait.as_secs()));
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!(
        "Опросов: {}, узлов в последнем: {}, изменений: {}\n",
        r.cycles,
        r.last.as_ref().map(|l| l.hosts.len()).unwrap_or(0),
        r.changes.len()
    );
    for c in &r.changes {
        s += &format!(
            "{} {} {:<15} {:<20} {}\n",
            crate::session::format_time(c.at),
            if c.alarm { "!!" } else { "  " },
            c.host,
            c.kind.label(),
            c.detail
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(at: u64, hosts: &[(&str, &str, &[u16])]) -> Snapshot {
        Snapshot {
            at,
            hosts: hosts
                .iter()
                .map(|(ip, mac, ports)| {
                    (
                        ip.parse().unwrap(),
                        HostSnap {
                            mac: Some(mac.to_string()),
                            vendor: Some("Dell".into()),
                            ports: ports.iter().copied().collect(),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn changes_and_debounce() {
        let mut prev = snap(1, &[("10.0.0.1", "aa", &[22, 80]), ("10.0.0.2", "bb", &[443])]);
        let mut m = Misses::default();
        // Узел 2 пропал один раз, у узла 1 открылся 3389 и закрылся 80 (первый раз), новый узел 3.
        let c = diff(&mut prev, &snap(2, &[("10.0.0.1", "aa", &[22, 3389]), ("10.0.0.3", "cc", &[])]), &mut m);
        let kinds: Vec<Kind> = c.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![Kind::PortOpened, Kind::NewHost]);
        assert!(c[0].alarm, "3389 — рискованный порт");
        // Второй раз подряд — подтверждаем пропажу узла 2 и закрытие 80.
        let c = diff(&mut prev, &snap(3, &[("10.0.0.1", "aa", &[22, 3389]), ("10.0.0.3", "cc", &[])]), &mut m);
        let kinds: Vec<Kind> = c.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![Kind::PortClosed, Kind::GoneHost]);
        // Смена MAC.
        let c = diff(&mut prev, &snap(4, &[("10.0.0.1", "dd", &[22, 3389]), ("10.0.0.3", "cc", &[])]), &mut m);
        assert_eq!(c[0].kind, Kind::MacChanged);
        assert!(c[0].alarm);
        // Без изменений — пусто.
        assert!(diff(&mut prev, &snap(5, &[("10.0.0.1", "dd", &[22, 3389]), ("10.0.0.3", "cc", &[])]), &mut m).is_empty());
    }

    #[test]
    fn flapping_host_is_not_reported() {
        let mut prev = snap(1, &[("10.0.0.1", "aa", &[22])]);
        let mut m = Misses::default();
        assert!(diff(&mut prev, &snap(2, &[]), &mut m).is_empty());
        assert!(diff(&mut prev, &snap(3, &[("10.0.0.1", "aa", &[22])]), &mut m).is_empty());
        assert!(diff(&mut prev, &snap(4, &[]), &mut m).is_empty());
    }
}
