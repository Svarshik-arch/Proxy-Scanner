//! Трассировка с постоянным наблюдением (как MTR), TCP-ping и поиск MTU по пути.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::icmp::{self, Probe, Proto, ReplyKind};
use super::Sink;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Mode {
    #[default]
    Icmp,
    /// UDP-пробы на возрастающие порты (как traceroute в Linux, без прав).
    Udp,
    /// Время установления TCP-соединения до узла (без промежуточных хопов).
    Tcp,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Icmp, Mode::Udp, Mode::Tcp];
    pub fn label(self) -> &'static str {
        match self {
            Mode::Icmp => "ICMP",
            Mode::Udp => "UDP",
            Mode::Tcp => "TCP (до узла)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub target: String,
    pub mode: Mode,
    /// UDP: начальный порт; TCP: порт назначения.
    pub port: u16,
    pub first_hop: u8,
    pub max_hops: u8,
    /// Число циклов (0 — до остановки).
    pub cycles: u32,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    /// Размер данных в пробе.
    pub payload: usize,
    /// Запрет фрагментации в обычных пробах.
    pub df: bool,
    /// Имена хопов через обратный DNS.
    pub resolve_names: bool,
    /// Найти MTU пути перед трассировкой.
    pub pmtu: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target: String::new(),
            mode: Mode::Icmp,
            port: 33434,
            first_hop: 1,
            max_hops: 30,
            cycles: 10,
            interval_ms: 1000,
            timeout_ms: 1500,
            payload: 56,
            df: false,
            resolve_names: true,
            pmtu: false,
        }
    }
}

/// Статистика одного хопа.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HopStats {
    pub ttl: u8,
    /// Адреса, ответившие на этом TTL (несколько — балансировка ECMP).
    pub addrs: Vec<Ipv4Addr>,
    pub names: Vec<Option<String>>,
    pub sent: u32,
    pub recv: u32,
    pub last_ms: Option<f64>,
    pub best_ms: Option<f64>,
    pub worst_ms: Option<f64>,
    pub avg_ms: f64,
    /// Стандартное отклонение — джиттер.
    pub stdev_ms: f64,
    /// Средняя разница между соседними замерами (RFC 3550-подобный джиттер).
    pub jitter_ms: f64,
    /// Последние замеры для графика (None — потеря).
    pub history: Vec<Option<f64>>,
    pub note: Option<String>,
    #[serde(skip)]
    m2: f64,
}

impl HopStats {
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { 100.0 * (self.sent - self.recv) as f64 / self.sent as f64 }
    }

    fn add(&mut self, rtt: Option<f64>) {
        self.sent += 1;
        self.history.push(rtt);
        if self.history.len() > 120 {
            self.history.remove(0);
        }
        let Some(v) = rtt else { return };
        if let Some(prev) = self.last_ms {
            self.jitter_ms += ((v - prev).abs() - self.jitter_ms) / 16.0;
        }
        self.recv += 1;
        self.last_ms = Some(v);
        self.best_ms = Some(self.best_ms.map_or(v, |b| b.min(v)));
        self.worst_ms = Some(self.worst_ms.map_or(v, |w| w.max(v)));
        // Алгоритм Уэлфорда для среднего и дисперсии.
        let n = self.recv as f64;
        let delta = v - self.avg_ms;
        self.avg_ms += delta / n;
        self.m2 += delta * (v - self.avg_ms);
        self.stdev_ms = if self.recv > 1 { (self.m2 / (n - 1.0)).sqrt() } else { 0.0 };
    }

    pub fn host_label(&self) -> String {
        if self.addrs.is_empty() {
            return "???".into();
        }
        self.addrs
            .iter()
            .zip(self.names.iter().chain(std::iter::repeat(&None)))
            .map(|(a, n)| match n {
                Some(n) => format!("{n} ({a})"),
                None => a.to_string(),
            })
            .collect::<Vec<_>>()
            .join(" / ")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PmtuResult {
    /// MTU пути (размер IP-пакета), если найден.
    pub mtu: Option<u16>,
    /// Шаги поиска: (размер IP-пакета, прошёл ли, примечание).
    pub steps: Vec<(u16, bool, String)>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Resolved(IpAddr),
    Method(String),
    Hops(Vec<HopStats>),
    Cycle(u32),
    Pmtu(PmtuResult),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub target: String,
    pub address: Option<IpAddr>,
    pub method: String,
    pub cycles: u32,
    pub hops: Vec<HopStats>,
    pub pmtu: Option<PmtuResult>,
}

fn proto(mode: Mode) -> Proto {
    match mode {
        Mode::Udp => Proto::Udp,
        _ => Proto::Icmp,
    }
}

/// Поиск MTU пути: проба 1500, при успехе — 9000, затем двоичный поиск.
pub async fn path_mtu(dst: Ipv4Addr, mode: Mode, port: u16, timeout: Duration, cancel: &CancellationToken) -> PmtuResult {
    let mut res = PmtuResult::default();
    let p = proto(mode);
    let id = icmp::next_id();
    let mut seq = 0u16;
    // true — прошёл; Some(mtu) из ICMP «нужна фрагментация» подсказывает верхнюю границу.
    let mut test = async |size: u16, res: &mut PmtuResult| -> (bool, Option<u16>) {
        let payload = size.saturating_sub(28) as usize;
        let mut hint = None;
        for _ in 0..3 {
            seq = seq.wrapping_add(1);
            let probe = Probe {
                dst,
                ttl: 64,
                payload,
                df: true,
                timeout,
                proto: p,
                port,
                id,
                seq,
            };
            match icmp::probe(probe).await {
                Ok(Some(r)) => match r.kind {
                    ReplyKind::Reached => {
                        res.steps.push((size, true, String::new()));
                        return (true, None);
                    }
                    ReplyKind::FragNeeded(m) => {
                        res.steps.push((size, false, format!("нужна фрагментация от {}{}", r.from, m.map(|m| format!(", MTU {m}")).unwrap_or_default())));
                        return (false, m);
                    }
                    ReplyKind::LocalTooBig(m) => {
                        res.steps.push((size, false, format!("больше MTU интерфейса{}", m.map(|m| format!(" ({m})")).unwrap_or_default())));
                        return (false, m);
                    }
                    other => hint = Some(format!("{other:?}")),
                },
                Ok(None) => {}
                Err(e) => {
                    res.steps.push((size, false, e));
                    return (false, None);
                }
            }
        }
        res.steps.push((size, false, hint.unwrap_or_else(|| "нет ответа (возможна «чёрная дыра» PMTU)".into())));
        (false, None)
    };

    let (mut lo, mut hi): (u16, u16);
    let (ok1500, hint) = test(1500, &mut res).await;
    if ok1500 {
        let (ok9000, hint9) = test(9000, &mut res).await;
        if ok9000 {
            res.mtu = Some(9000);
            return res;
        }
        lo = 1500;
        hi = hint9.map(|h| h.clamp(1501, 9000)).unwrap_or(9000);
    } else {
        // Сначала проверим, что узел вообще отвечает на маленькие пакеты.
        let (ok_small, _) = test(68, &mut res).await;
        if !ok_small {
            res.note = Some("узел не отвечает даже на маленькие пакеты — MTU не определить".into());
            return res;
        }
        lo = 68;
        hi = hint.map(|h| h.clamp(69, 1500)).unwrap_or(1500);
        if let Some(h) = hint {
            let (ok, _) = test(h, &mut res).await;
            if ok {
                res.mtu = Some(h);
                return res;
            }
        }
    }
    while hi - lo > 1 {
        if cancel.is_cancelled() {
            break;
        }
        let mid = lo + (hi - lo) / 2;
        let (ok, h) = test(mid, &mut res).await;
        if ok {
            lo = mid;
        } else {
            hi = h.filter(|h| *h > lo && *h < mid).map(|h| h + 1).unwrap_or(mid);
        }
    }
    res.mtu = Some(lo);
    res
}

async fn tcp_ping(addr: SocketAddr, timeout: Duration) -> Result<Option<f64>, String> {
    let started = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(Some(super::ms_f(started.elapsed()))),
        // RST — узел ответил, время тоже показательно.
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(Some(super::ms_f(started.elapsed()))),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Ok(None),
    }
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(50));
    let ip = match super::resolve(&cfg.target, Duration::from_secs(5)).await {
        Ok(ip) => ip,
        Err(e) => return sink.send(Event::Log(e)),
    };
    sink.send(Event::Resolved(ip));
    let interval = Duration::from_millis(cfg.interval_ms.max(50));
    let max_cycles = if cfg.cycles == 0 { u32::MAX } else { cfg.cycles };

    if cfg.mode == Mode::Tcp {
        sink.send(Event::Method(format!("TCP connect к порту {}", cfg.port)));
        let addr = SocketAddr::new(ip, cfg.port);
        let mut hop = HopStats {
            ttl: 1,
            addrs: match ip {
                IpAddr::V4(v4) => vec![v4],
                _ => vec![],
            },
            names: vec![None],
            note: Some(format!("{addr}")),
            ..Default::default()
        };
        for cycle in 0..max_cycles {
            let started = Instant::now();
            match tcp_ping(addr, timeout).await {
                Ok(v) => hop.add(v),
                Err(e) => {
                    hop.add(None);
                    hop.note = Some(e);
                }
            }
            sink.send(Event::Hops(vec![hop.clone()]));
            sink.send(Event::Cycle(cycle + 1));
            if cycle + 1 < max_cycles {
                tokio::select! {
                    _ = tokio::time::sleep(interval.saturating_sub(started.elapsed())) => {}
                    _ = cancel.cancelled() => return,
                }
            }
        }
        return;
    }

    let IpAddr::V4(dst) = ip else {
        return sink.send(Event::Log("трассировка поддерживает только IPv4".into()));
    };
    let method = match cfg.mode {
        Mode::Icmp => match icmp::icmp_method() {
            Ok(m) => m.to_string(),
            Err(e) => return sink.send(Event::Log(e)),
        },
        _ => {
            if cfg!(windows) {
                return sink.send(Event::Log("UDP-трассировка в Windows недоступна — выберите ICMP".into()));
            }
            "UDP + IP_RECVERR".to_string()
        }
    };
    sink.send(Event::Method(method));

    if cfg.pmtu {
        let r = path_mtu(dst, cfg.mode, cfg.port, timeout, &cancel).await;
        sink.send(Event::Pmtu(r));
    }

    let first = cfg.first_hop.max(1);
    let max = cfg.max_hops.clamp(first, 64);
    let mut hops: Vec<HopStats> = (first..=max)
        .map(|ttl| HopStats {
            ttl,
            ..Default::default()
        })
        .collect();
    // Хоп, на котором достигнут узел (дальше не шлём).
    let mut dest_ttl: Option<u8> = None;
    let id = icmp::next_id();
    let mut seq: u16 = 0;
    for cycle in 0..max_cycles {
        let started = Instant::now();
        let last = dest_ttl.unwrap_or(max);
        let mut futs = Vec::new();
        for ttl in first..=last {
            seq = seq.wrapping_add(1);
            let probe = Probe {
                dst,
                ttl,
                payload: cfg.payload,
                df: cfg.df,
                timeout,
                proto: proto(cfg.mode),
                port: cfg.port.wrapping_add(seq % 512),
                id,
                seq,
            };
            futs.push(async move { (ttl, icmp::probe(probe).await) });
        }
        let results = tokio::select! {
            r = futures_join_all(futs) => r,
            _ = cancel.cancelled() => return,
        };
        for (ttl, r) in results {
            let hop = &mut hops[(ttl - first) as usize];
            match r {
                Ok(Some(reply)) => {
                    if !hop.addrs.contains(&reply.from) {
                        hop.addrs.push(reply.from);
                        hop.names.push(None);
                    }
                    hop.add(Some(reply.rtt_us as f64 / 1000.0));
                    match reply.kind {
                        ReplyKind::Reached => {
                            dest_ttl = Some(dest_ttl.map_or(ttl, |d| d.min(ttl)));
                        }
                        ReplyKind::Unreachable(c) => {
                            hop.note = Some(icmp::unreachable_text(c).into());
                            dest_ttl = Some(dest_ttl.map_or(ttl, |d| d.min(ttl)));
                        }
                        ReplyKind::FragNeeded(m) => {
                            hop.note = Some(format!("нужна фрагментация{}", m.map(|m| format!(", MTU {m}")).unwrap_or_default()))
                        }
                        ReplyKind::LocalTooBig(m) => {
                            hop.note = Some(format!("пакет больше MTU интерфейса{}", m.map(|m| format!(" ({m})")).unwrap_or_default()))
                        }
                        ReplyKind::TimeExceeded => {}
                    }
                }
                Ok(None) => hop.add(None),
                Err(e) => {
                    hop.add(None);
                    hop.note = Some(e);
                }
            }
        }
        if let Some(d) = dest_ttl {
            hops.truncate((d - first + 1) as usize);
        }
        if cfg.resolve_names {
            for hop in &mut hops {
                for (i, a) in hop.addrs.clone().iter().enumerate() {
                    if hop.names.get(i).is_some_and(|n| n.is_none()) {
                        let name = super::dns::reverse_lookup(IpAddr::V4(*a), Duration::from_millis(800)).await;
                        hop.names[i] = Some(name.unwrap_or_default()).filter(|n| !n.is_empty());
                        if hop.names[i].is_none() {
                            // Не повторять неудачный запрос каждый цикл.
                            hop.names[i] = Some(String::new());
                        }
                    }
                }
            }
        }
        let snapshot: Vec<HopStats> = hops
            .iter()
            .cloned()
            .map(|mut h| {
                h.names = h.names.into_iter().map(|n| n.filter(|s| !s.is_empty())).collect();
                h
            })
            .collect();
        sink.send(Event::Hops(snapshot));
        sink.send(Event::Cycle(cycle + 1));
        if cycle + 1 < max_cycles {
            tokio::select! {
                _ = tokio::time::sleep(interval.saturating_sub(started.elapsed())) => {}
                _ = cancel.cancelled() => return,
            }
        }
    }
}

async fn futures_join_all<F: std::future::Future>(futs: Vec<F>) -> Vec<F::Output>
where
    F: Send + 'static,
    F::Output: Send + 'static,
{
    let handles: Vec<_> = futs.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(v) = h.await {
            out.push(v);
        }
    }
    out
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!(
        "{} ({}) — {} — циклов: {}\n",
        r.target,
        r.address.map(|a| a.to_string()).unwrap_or_default(),
        r.method,
        r.cycles
    );
    if let Some(p) = &r.pmtu {
        s += &format!(
            "MTU пути: {}{}\n",
            p.mtu.map(|m| m.to_string()).unwrap_or("не определён".into()),
            p.note.as_ref().map(|n| format!(" ({n})")).unwrap_or_default()
        );
    }
    s += &format!(
        "{:>3}  {:<44} {:>6} {:>5} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
        "#", "узел", "потери", "отпр", "посл", "сред", "лучш", "худш", "откл"
    );
    let f = |v: Option<f64>| v.map(|v| format!("{v:.1}")).unwrap_or("-".into());
    for h in &r.hops {
        s += &format!(
            "{:>3}  {:<44} {:>5.1}% {:>5} {:>8} {:>8} {:>8} {:>8} {:>8.1}{}\n",
            h.ttl,
            h.host_label(),
            h.loss_pct(),
            h.sent,
            f(h.last_ms),
            if h.recv > 0 { format!("{:.1}", h.avg_ms) } else { "-".into() },
            f(h.best_ms),
            f(h.worst_ms),
            h.stdev_ms,
            h.note.as_ref().map(|n| format!("  ({n})")).unwrap_or_default()
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats() {
        let mut h = HopStats::default();
        for v in [Some(10.0), None, Some(20.0), Some(30.0)] {
            h.add(v);
        }
        assert_eq!((h.sent, h.recv), (4, 3));
        assert!((h.loss_pct() - 25.0).abs() < 1e-9);
        assert_eq!(h.best_ms, Some(10.0));
        assert_eq!(h.worst_ms, Some(30.0));
        assert!((h.avg_ms - 20.0).abs() < 1e-9);
        assert!((h.stdev_ms - 10.0).abs() < 1e-9);
        assert_eq!(h.history.len(), 4);
    }

    #[tokio::test]
    async fn tcp_mode_localhost() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = l.accept().await;
            }
        });
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            target: "127.0.0.1".into(),
            mode: Mode::Tcp,
            port,
            cycles: 3,
            interval_ms: 50,
            ..Default::default()
        };
        run(cfg, sink, CancellationToken::new()).await;
        let last = rx
            .try_iter()
            .filter_map(|e| if let Event::Hops(h) = e { Some(h) } else { None })
            .last()
            .unwrap();
        assert_eq!(last[0].sent, 3);
        assert_eq!(last[0].recv, 3);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn udp_trace_localhost() {
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            target: "127.0.0.1".into(),
            mode: Mode::Udp,
            cycles: 2,
            interval_ms: 50,
            resolve_names: false,
            ..Default::default()
        };
        run(cfg, sink, CancellationToken::new()).await;
        let last = rx
            .try_iter()
            .filter_map(|e| if let Event::Hops(h) = e { Some(h) } else { None })
            .last()
            .unwrap();
        assert_eq!(last.len(), 1, "до 127.0.0.1 один хоп");
        assert_eq!(last[0].addrs, vec![Ipv4Addr::LOCALHOST]);
        assert_eq!(last[0].recv, 2);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pmtu_localhost_udp() {
        let r = path_mtu(Ipv4Addr::LOCALHOST, Mode::Udp, 33500, Duration::from_millis(500), &CancellationToken::new()).await;
        // MTU loopback — 65536, значит 9000 проходит.
        assert_eq!(r.mtu, Some(9000), "{:?}", r.steps);
    }
}
