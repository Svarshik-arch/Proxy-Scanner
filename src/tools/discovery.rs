//! Обнаружение узлов: ICMP, TCP (ответ RST тоже признак жизни), ARP, NetBIOS (NBSTAT),
//! mDNS, SSDP, обратный DNS; производитель по MAC и догадка об ОС по TTL и портам.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::icmp::{self, Probe, Proto, ReplyKind};
use super::{Sink, dnsproto, oui};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub targets: String,
    pub icmp: bool,
    pub arp: bool,
    /// Порты для TCP-проверки (открыт или RST — узел жив).
    pub tcp_ports: String,
    pub netbios: bool,
    pub mdns: bool,
    pub ssdp: bool,
    pub reverse_dns: bool,
    /// Показывать и узлы без ответа.
    pub show_dead: bool,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: String::new(),
            icmp: true,
            arp: true,
            tcp_ports: "22,80,135,139,443,445,3389,8080".into(),
            netbios: true,
            mdns: true,
            ssdp: true,
            reverse_dns: true,
            show_dead: false,
            timeout_ms: 1000,
            concurrency: 128,
            retries: 1,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetbiosInfo {
    pub name: Option<String>,
    pub group: Option<String>,
    pub user: Option<String>,
    /// Узел — контроллер домена (группа 0x1C) или мастер-браузер.
    pub roles: Vec<String>,
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub alive: bool,
    /// Чем подтверждён: ICMP, TCP/445, ARP, NetBIOS, mDNS, SSDP.
    pub evidence: Vec<String>,
    pub rtt_ms: Option<f64>,
    pub ttl: Option<u8>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub dns_name: Option<String>,
    pub netbios: Option<NetbiosInfo>,
    pub mdns_name: Option<String>,
    pub ssdp: Option<String>,
    pub open_ports: Vec<u16>,
    pub os_guess: Option<String>,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED,
            alive: false,
            evidence: Vec::new(),
            rtt_ms: None,
            ttl: None,
            mac: None,
            vendor: None,
            dns_name: None,
            netbios: None,
            mdns_name: None,
            ssdp: None,
            open_ports: Vec::new(),
            os_guess: None,
        }
    }
}

impl Host {
    pub fn best_name(&self) -> String {
        self.dns_name
            .clone()
            .or_else(|| self.netbios.as_ref().and_then(|n| n.name.clone()))
            .or_else(|| self.mdns_name.clone())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Total(u64),
    Progress(u64),
    Host(Box<Host>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub hosts: Vec<Host>,
}

/// Догадка об ОС по начальному TTL и открытым портам.
pub fn guess_os(ttl: Option<u8>, ports: &[u16], netbios: bool) -> Option<String> {
    let win_ports = ports.iter().any(|p| [135, 139, 445, 3389].contains(p));
    let by_ttl = ttl.map(|t| match t {
        0..=64 => "Linux/Unix/macOS",
        65..=128 => "Windows",
        _ => "сетевое оборудование",
    });
    match (by_ttl, win_ports || netbios) {
        (Some("Windows"), _) => Some("Windows".into()),
        (Some("Linux/Unix/macOS"), true) if ports.contains(&445) || netbios => Some("Linux/Unix (Samba)".into()),
        (Some(t), _) => Some(t.into()),
        (None, true) if ports.contains(&135) || ports.contains(&3389) => Some("Windows".into()),
        (None, true) => Some("Windows или Samba".into()),
        (None, false) if ports.contains(&22) => Some("Linux/Unix (SSH)".into()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// NetBIOS
// ---------------------------------------------------------------------------

pub fn nbstat_query(id: u16) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20]);
    let mut name = [0u8; 16];
    name[0] = b'*';
    for b in name {
        q.push(b'A' + (b >> 4));
        q.push(b'A' + (b & 0xF));
    }
    q.push(0);
    q.extend_from_slice(&[0, 0x21, 0, 1]);
    q
}

pub fn parse_nbstat(r: &[u8]) -> Option<NetbiosInfo> {
    if r.len() < 57 {
        return None;
    }
    // Заголовок 12 байт, имя 34 байта, тип/класс/TTL/длина = 10 байт.
    let mut i = 12;
    let (_, after) = dnsproto::read_name(r, i).ok()?;
    i = after + 10;
    let count = *r.get(i)? as usize;
    i += 1;
    let mut info = NetbiosInfo::default();
    for _ in 0..count {
        let entry = r.get(i..i + 18)?;
        let name = String::from_utf8_lossy(&entry[..15]).trim_end().to_string();
        let suffix = entry[15];
        let group = u16::from_be_bytes([entry[16], entry[17]]) & 0x8000 != 0;
        match (suffix, group) {
            (0x00, false) if info.name.is_none() => info.name = Some(name),
            (0x00, true) if info.group.is_none() => info.group = Some(name),
            (0x03, false) if Some(&name) != info.name.as_ref() && info.user.is_none() => info.user = Some(name),
            (0x1C, true) => {
                if !info.roles.iter().any(|r| r.contains("контроллер")) {
                    info.roles.push(format!("контроллер домена {name}"));
                }
            }
            (0x1B, false) => info.roles.push("главный обозреватель домена".into()),
            (0x1D, false) => info.roles.push("главный обозреватель сегмента".into()),
            (0x20, false) if !info.roles.iter().any(|r| r == "файловый сервер") => {
                info.roles.push("файловый сервер".into());
            }
            _ => {}
        }
        i += 18;
    }
    if let Some(mac) = r.get(i..i + 6)
        && mac.iter().any(|b| *b != 0)
    {
        info.mac = Some(oui::format_mac(&<[u8; 6]>::try_from(mac).unwrap()));
    }
    Some(info)
}

async fn udp_ask(ip: Ipv4Addr, port: u16, payload: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(payload, (ip, port)).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let (n, from) = tokio::time::timeout(left, sock.recv_from(&mut buf)).await.ok()?.ok()?;
        if from.ip() == IpAddr::V4(ip) {
            buf.truncate(n);
            return Some(buf);
        }
    }
}

async fn netbios(ip: Ipv4Addr, timeout: Duration) -> Option<NetbiosInfo> {
    let resp = udp_ask(ip, 137, &nbstat_query(super::dns::rand_id()), timeout).await?;
    parse_nbstat(&resp)
}

async fn mdns_name(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let mut q = dnsproto::Query::new(super::dns::rand_id(), &dnsproto::reverse_name(IpAddr::V4(ip)), 12);
    q.recursion = false;
    q.edns = false;
    let wire = dnsproto::build_query(&q).ok()?;
    let resp = udp_ask(ip, 5353, &wire, timeout).await?;
    let msg = dnsproto::parse(&resp).ok()?;
    msg.answers
        .iter()
        .chain(msg.additional.iter())
        .find(|r| r.rtype == "PTR")
        .map(|r| r.data.trim_end_matches('.').to_string())
}

/// SSDP M-SEARCH: ответы устройств UPnP (принтеры, камеры, ТВ, роутеры) за `wait`.
pub async fn ssdp_search(wait: Duration) -> BTreeMap<Ipv4Addr, String> {
    let mut out = BTreeMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else { return out };
    let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    for _ in 0..2 {
        let _ = sock.send_to(msg.as_bytes(), "239.255.255.250:1900").await;
    }
    let deadline = Instant::now() + wait;
    let mut buf = vec![0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok(Ok((n, SocketAddr::V4(from)))) = tokio::time::timeout(left, sock.recv_from(&mut buf)).await else {
            break;
        };
        let text = String::from_utf8_lossy(&buf[..n]);
        let field = |name: &str| {
            text.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
        };
        let desc = [field("SERVER"), field("LOCATION")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
        out.entry(*from.ip()).or_insert(desc);
    }
    out
}

/// MAC из системной ARP-таблицы.
fn arp_table() -> BTreeMap<Ipv4Addr, String> {
    let mut out = BTreeMap::new();
    #[cfg(target_os = "linux")]
    if let Ok(t) = std::fs::read_to_string("/proc/net/arp") {
        for line in t.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 4
                && f[2] != "0x0"
                && let (Ok(ip), Some(mac)) = (f[0].parse(), oui::parse_mac(f[3]))
                && mac != [0; 6]
            {
                out.insert(ip, oui::format_mac(&mac));
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    if let Ok(o) = crate::util::run_cmd("arp", &["-a"]) {
        for line in o.stdout.lines() {
            let mut it = line.split_whitespace();
            if let (Some(ip), Some(mac)) = (it.next(), it.next())
                && let (Ok(ip), Some(m)) = (ip.parse(), oui::parse_mac(mac))
                && m != [0xff; 6]
            {
                out.insert(ip, oui::format_mac(&m));
            }
        }
    }
    out
}

async fn arp_one(ip: Ipv4Addr) -> Option<String> {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || icmp::send_arp(ip))
            .await
            .ok()
            .flatten()
            .filter(|m| *m != [0; 6])
            .map(|m| oui::format_mac(&m))
    }
    #[cfg(not(windows))]
    {
        // Без прав ARP-запрос не отправить напрямую: «будим» ядро UDP-пакетом,
        // MAC потом берётся из /proc/net/arp.
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0").await {
            let _ = s.send_to(b"", (ip, 9)).await;
        }
        None
    }
}

async fn tcp_alive(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<(bool, f64)> {
    let started = Instant::now();
    match tokio::time::timeout(timeout, super::connect_fast(SocketAddr::from((ip, port)))).await {
        Ok(Ok(_)) => Some((true, super::ms_f(started.elapsed()))),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some((false, super::ms_f(started.elapsed()))),
        _ => None,
    }
}

async fn probe_host(ip: Ipv4Addr, cfg: Arc<Config>, ports: Arc<Vec<u16>>, icmp_ok: bool) -> Host {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    let mut h = Host {
        ip,
        ..Default::default()
    };
    let icmp_fut = async {
        if !(cfg.icmp && icmp_ok) {
            return None;
        }
        let id = icmp::next_id();
        for seq in 0..=cfg.retries as u16 {
            let p = Probe {
                dst: ip,
                ttl: 64,
                payload: 32,
                df: false,
                timeout,
                proto: Proto::Icmp,
                port: 0,
                id,
                seq,
            };
            if let Ok(Some(r)) = icmp::probe(p).await
                && r.kind == ReplyKind::Reached
            {
                return Some(r);
            }
        }
        None
    };
    let tcp_fut = async {
        let mut set = tokio::task::JoinSet::new();
        for &port in ports.iter() {
            set.spawn(async move { (port, tcp_alive(ip, port, timeout).await) });
        }
        let mut res = Vec::new();
        while let Some(Ok(r)) = set.join_next().await {
            res.push(r);
        }
        res
    };
    let nb_fut = async {
        if cfg.netbios { netbios(ip, timeout).await } else { None }
    };
    let arp_fut = async {
        if cfg.arp { arp_one(ip).await } else { None }
    };
    let mdns_fut = async {
        if cfg.mdns { mdns_name(ip, timeout.min(Duration::from_millis(700))).await } else { None }
    };
    let (echo, tcp, nb, mac, mdns) = tokio::join!(icmp_fut, tcp_fut, nb_fut, arp_fut, mdns_fut);
    if let Some(r) = echo {
        h.alive = true;
        h.evidence.push("ICMP".into());
        h.rtt_ms = Some(r.rtt_us as f64 / 1000.0);
        h.ttl = r.ttl;
    }
    let mut tcp = tcp;
    tcp.sort_by_key(|(p, _)| *p);
    for (port, r) in tcp {
        if let Some((open, rtt)) = r {
            h.alive = true;
            if open {
                h.open_ports.push(port);
            }
            if !h.evidence.iter().any(|e| e.starts_with("TCP")) {
                h.evidence.push(format!("TCP/{port}{}", if open { "" } else { " (RST)" }));
            }
            h.rtt_ms.get_or_insert(rtt);
        }
    }
    if let Some(nb) = nb {
        h.alive = true;
        h.evidence.push("NetBIOS".into());
        if h.mac.is_none() {
            h.mac = nb.mac.clone();
        }
        h.netbios = Some(nb);
    }
    if let Some(m) = mac {
        h.alive = true;
        h.evidence.push("ARP".into());
        h.mac = Some(m);
    }
    if let Some(n) = mdns {
        h.alive = true;
        h.evidence.push("mDNS".into());
        h.mdns_name = Some(n);
    }
    if cfg.reverse_dns && h.alive {
        h.dns_name = super::dns::reverse_lookup(IpAddr::V4(ip), Duration::from_millis(1000)).await;
    }
    h
}

fn finish(h: &mut Host) {
    if let Some(m) = h.mac.as_deref().and_then(oui::parse_mac) {
        h.vendor = oui::vendor(&m);
    }
    h.os_guess = guess_os(h.ttl, &h.open_ports, h.netbios.is_some());
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let targets = match crate::targets::parse_targets(&cfg.targets) {
        Ok(t) if !t.is_empty() => t,
        Ok(_) => return sink.send(Event::Log("не заданы адреса".into())),
        Err(e) => return sink.send(Event::Log(e)),
    };
    let total = targets.total_hosts();
    if total > 65536 {
        return sink.send(Event::Log(format!("слишком много адресов ({total}); максимум — /16")));
    }
    let ports = match crate::targets::parse_ports(if cfg.tcp_ports.trim().is_empty() { "" } else { &cfg.tcp_ports }) {
        Ok(p) => p,
        Err(_) if cfg.tcp_ports.trim().is_empty() => Vec::new(),
        Err(e) => return sink.send(Event::Log(e)),
    };
    let icmp_ok = match icmp::icmp_method() {
        Ok(m) => {
            sink.send(Event::Log(format!("ICMP: {m}")));
            true
        }
        Err(e) => {
            if cfg.icmp {
                sink.send(Event::Log(e));
            }
            false
        }
    };
    sink.send(Event::Total(total));
    let ssdp = if cfg.ssdp {
        Some(tokio::spawn(ssdp_search(Duration::from_secs(3))))
    } else {
        None
    };
    let cfg = Arc::new(cfg);
    let ports = Arc::new(ports);
    let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Узлы без явного ответа: позже проверим их по ARP-таблице и SSDP.
    let silent: Arc<Mutex<Vec<Host>>> = Arc::new(Mutex::new(Vec::new()));
    let found: Arc<Mutex<Vec<Host>>> = Arc::new(Mutex::new(Vec::new()));
    let items: Vec<Ipv4Addr> = targets.iter().collect();
    super::for_each_limited(items, cfg.concurrency, &cancel, |ip| {
        let (cfg, ports, sink, done, silent, found) =
            (cfg.clone(), ports.clone(), sink.clone(), done.clone(), silent.clone(), found.clone());
        async move {
            let h = probe_host(ip, cfg, ports, icmp_ok).await;
            if h.alive {
                found.lock().unwrap().push(h);
            } else {
                silent.lock().unwrap().push(h);
            }
            let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if n % 16 == 0 || n == total {
                sink.send(Event::Progress(n));
            }
        }
    })
    .await;
    if cancel.is_cancelled() {
        return;
    }
    let arp = if cfg.arp { tokio::task::spawn_blocking(arp_table).await.unwrap_or_default() } else { BTreeMap::new() };
    let ssdp = match ssdp {
        Some(h) => h.await.unwrap_or_default(),
        None => BTreeMap::new(),
    };
    let mut all: Vec<Host> = std::mem::take(&mut *found.lock().unwrap());
    let silent = std::mem::take(&mut *silent.lock().unwrap());
    for mut h in silent {
        if arp.contains_key(&h.ip) || ssdp.contains_key(&h.ip) {
            h.alive = true;
            if cfg.reverse_dns {
                h.dns_name = super::dns::reverse_lookup(IpAddr::V4(h.ip), Duration::from_millis(1000)).await;
            }
        }
        if h.alive || cfg.show_dead {
            all.push(h);
        }
    }
    for h in &mut all {
        if let Some(m) = arp.get(&h.ip)
            && h.mac.is_none()
        {
            h.mac = Some(m.clone());
            h.evidence.push("ARP".into());
        }
        if let Some(s) = ssdp.get(&h.ip) {
            h.ssdp = Some(s.clone());
            h.evidence.push("SSDP".into());
        }
        finish(h);
    }
    all.sort_by_key(|h| h.ip);
    for h in all {
        sink.send(Event::Host(Box::new(h)));
    }
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!(
        "{:<15} {:<17} {:<24} {:<28} {:<10} {:<22} {}\n",
        "адрес", "MAC", "производитель", "имя", "мс/TTL", "ОС", "признаки / порты"
    );
    for h in &r.hosts {
        let nb = h
            .netbios
            .as_ref()
            .map(|n| {
                let mut v = Vec::new();
                if let Some(g) = &n.group {
                    v.push(format!("группа {g}"));
                }
                v.extend(n.roles.iter().cloned());
                v.join(", ")
            })
            .unwrap_or_default();
        s += &format!(
            "{:<15} {:<17} {:<24} {:<28} {:<10} {:<22} {}{}{}\n",
            h.ip,
            h.mac.clone().unwrap_or("-".into()),
            h.vendor.clone().unwrap_or_default().chars().take(24).collect::<String>(),
            h.best_name(),
            format!(
                "{}/{}",
                h.rtt_ms.map(|v| format!("{v:.1}")).unwrap_or("-".into()),
                h.ttl.map(|t| t.to_string()).unwrap_or("-".into())
            ),
            h.os_guess.clone().unwrap_or_default(),
            h.evidence.join(","),
            if h.open_ports.is_empty() {
                String::new()
            } else {
                format!(
                    " [{}]",
                    h.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
                )
            },
            if nb.is_empty() { String::new() } else { format!(" {nb}") }
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbstat_roundtrip() {
        let q = nbstat_query(0x1234);
        assert_eq!(q.len(), 50);
        assert_eq!(&q[13..15], b"CK"); // '*' = 0x2A
        // Ответ: заголовок, имя, тип 0x21, класс, TTL, длина, 3 имени, MAC.
        let mut r = vec![0x12, 0x34, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&q[12..12 + 34]);
        r.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0]);
        r.push(4);
        let entry = |name: &str, suffix: u8, group: bool| {
            let mut e = format!("{name:<15}").into_bytes();
            e.push(suffix);
            e.extend_from_slice(&[if group { 0x84 } else { 0x04 }, 0]);
            e
        };
        r.extend(entry("WS-042", 0x00, false));
        r.extend(entry("CORP", 0x00, true));
        r.extend(entry("CORP", 0x1C, true));
        r.extend(entry("WS-042", 0x20, false));
        r.extend_from_slice(&[0x00, 0x15, 0x5d, 1, 2, 3]);
        let info = parse_nbstat(&r).unwrap();
        assert_eq!(info.name.as_deref(), Some("WS-042"));
        assert_eq!(info.group.as_deref(), Some("CORP"));
        assert!(info.roles.iter().any(|r| r.contains("контроллер")));
        assert!(info.roles.contains(&"файловый сервер".to_string()));
        assert_eq!(info.mac.as_deref(), Some("00:15:5D:01:02:03"));
    }

    #[test]
    fn os_guess() {
        assert_eq!(guess_os(Some(127), &[], false).as_deref(), Some("Windows"));
        assert_eq!(guess_os(Some(63), &[22], false).as_deref(), Some("Linux/Unix/macOS"));
        assert_eq!(guess_os(Some(63), &[445], false).as_deref(), Some("Linux/Unix (Samba)"));
        assert_eq!(guess_os(Some(250), &[], false).as_deref(), Some("сетевое оборудование"));
        assert_eq!(guess_os(None, &[135], false).as_deref(), Some("Windows"));
        assert_eq!(guess_os(None, &[], false), None);
    }

    #[tokio::test]
    async fn localhost_tcp_alive() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            targets: "127.0.0.1".into(),
            icmp: false,
            arp: false,
            netbios: false,
            mdns: false,
            ssdp: false,
            reverse_dns: false,
            tcp_ports: port.to_string(),
            ..Default::default()
        };
        run(cfg, sink, CancellationToken::new()).await;
        let hosts: Vec<Host> = rx
            .try_iter()
            .filter_map(|e| if let Event::Host(h) = e { Some(*h) } else { None })
            .collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].open_ports, vec![port]);
        assert!(hosts[0].evidence[0].starts_with("TCP/"));
    }
}
