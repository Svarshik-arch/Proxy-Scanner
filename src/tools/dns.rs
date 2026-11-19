//! DNS-запросы в духе `dig`: любые типы, любые серверы, UDP/TCP/DoT/DoH, AXFR,
//! сравнение ответов разных серверов.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::dnsproto::{self, Message, Query, Record};
use super::{Sink, ms_f};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
    Tls,
    Https,
}

impl Transport {
    pub const ALL: [Transport; 4] = [Transport::Udp, Transport::Tcp, Transport::Tls, Transport::Https];
    pub fn label(self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
            Transport::Tls => "DoT",
            Transport::Https => "DoH",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Имена (или IP-адреса — для них выполняется обратный запрос PTR).
    /// `{domain}` заменяется DNS-суффиксом системы.
    pub names: String,
    /// Типы записей через пробел или запятую.
    pub types: String,
    /// Серверы: `system` (серверы системы), IP[:порт], `tcp://IP`, `tls://узел[:853]`,
    /// `https://узел/dns-query`.
    pub servers: String,
    /// Транспорт для серверов без явной схемы.
    pub transport: Transport,
    pub recursion: bool,
    pub dnssec: bool,
    pub checking_disabled: bool,
    pub nsid: bool,
    pub timeout_ms: u64,
    pub retries: u32,
    pub concurrency: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            names: String::new(),
            types: "A AAAA".into(),
            servers: "system".into(),
            transport: Transport::Udp,
            recursion: true,
            dnssec: false,
            checking_disabled: false,
            nsid: false,
            timeout_ms: 2000,
            retries: 1,
            concurrency: 32,
        }
    }
}

/// Адрес DNS-сервера с транспортом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub label: String,
    pub transport: Transport,
    /// Узел (IP или имя) и порт.
    pub host: String,
    pub port: u16,
    /// Путь для DoH.
    pub path: String,
}

impl Server {
    pub fn parse(s: &str, default: Transport) -> Result<Server, String> {
        let s = s.trim();
        let lower = s.to_ascii_lowercase();
        let (transport, rest) = if let Some(r) = lower.strip_prefix("udp://") {
            (Transport::Udp, &s[s.len() - r.len()..])
        } else if let Some(r) = lower.strip_prefix("tcp://") {
            (Transport::Tcp, &s[s.len() - r.len()..])
        } else if let Some(r) = lower.strip_prefix("tls://") {
            (Transport::Tls, &s[s.len() - r.len()..])
        } else if lower.starts_with("https://") {
            let url = crate::probe::Url::parse(s)?;
            return Ok(Server {
                label: s.to_string(),
                transport: Transport::Https,
                host: url.host,
                port: url.port,
                path: url.path,
            });
        } else {
            (default, s)
        };
        let default_port = match transport {
            Transport::Tls => 853,
            Transport::Https => 443,
            _ => 53,
        };
        let (host, port) = if let Some(r) = rest.strip_prefix('[') {
            let (h, tail) = r.split_once(']').ok_or_else(|| format!("некорректный адрес «{s}»"))?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| format!("некорректный порт в «{s}»"))?,
                None => default_port,
            };
            (h.to_string(), port)
        } else {
            crate::probe::split_host_port(rest, default_port)?
        };
        let path = if transport == Transport::Https { "/dns-query".to_string() } else { String::new() };
        let label = match transport {
            Transport::Udp if port == 53 => host.clone(),
            Transport::Udp => format!("{host}:{port}"),
            Transport::Https => format!("https://{host}{path}"),
            t => format!("{}://{host}:{port}", t.label().to_ascii_lowercase().replace("dot", "tls")),
        };
        Ok(Server {
            label,
            transport,
            host,
            port,
            path,
        })
    }
}

/// DNS-серверы, настроенные в системе.
pub fn system_servers() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    #[cfg(windows)]
    {
        let script = "Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | \
                      ForEach-Object { $_.ServerAddresses } | Select-Object -Unique";
        if let Ok(o) = crate::util::run_powershell(script) {
            out.extend(o.stdout.lines().filter_map(|l| l.trim().parse::<IpAddr>().ok()));
        }
    }
    #[cfg(not(windows))]
    {
        let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
        let parse = |text: &str| -> Vec<IpAddr> {
            text.lines()
                .filter_map(|l| l.trim().strip_prefix("nameserver"))
                .filter_map(|v| v.trim().split('%').next()?.parse().ok())
                .collect()
        };
        let main = parse(&read("/etc/resolv.conf"));
        // systemd-resolved: настоящие серверы — в отдельном файле.
        if main.iter().all(|ip| ip.is_loopback()) {
            out.extend(parse(&read("/run/systemd/resolve/resolv.conf")));
        }
        out.extend(main);
    }
    let mut uniq = Vec::new();
    for ip in out {
        if !uniq.contains(&ip) && !ip.is_unspecified() {
            uniq.push(ip);
        }
    }
    uniq
}

/// DNS-суффикс системы (для подстановки `{domain}`).
pub fn system_domain() -> Option<String> {
    let info = crate::pac::system_info();
    info.suffixes.into_iter().find(|s| s.contains('.') || !s.is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Answer {
    pub server: String,
    pub transport: Transport,
    pub name: String,
    pub qtype: String,
    pub rtt_ms: Option<f64>,
    pub rcode: String,
    pub flags: String,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub nsid: Option<String>,
    pub size: usize,
    /// Ответ по UDP был обрезан (TC) и запрос повторён по TCP.
    pub tcp_fallback: bool,
    pub error: Option<String>,
}

impl Answer {
    /// Ответ без учёта TTL и порядка — для сравнения серверов.
    pub fn signature(&self) -> String {
        if let Some(e) = &self.error {
            return format!("ошибка: {e}");
        }
        let mut v: Vec<String> = self
            .answers
            .iter()
            .map(|r| format!("{} {} {}", r.name.to_ascii_lowercase(), r.rtype, r.data))
            .collect();
        v.sort();
        format!("{} | {}", self.rcode, v.join(" ; "))
    }

    pub fn summary(&self) -> String {
        if let Some(e) = &self.error {
            return e.clone();
        }
        if self.answers.is_empty() {
            return format!("{} (пусто)", self.rcode);
        }
        self.answers.iter().map(|r| r.data.clone()).collect::<Vec<_>>().join(", ")
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Total(usize),
    Answer(Box<Answer>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub answers: Vec<Answer>,
}

// ---------------------------------------------------------------------------
// Транспорты
// ---------------------------------------------------------------------------

async fn with_timeout<T>(t: Duration, f: impl std::future::Future<Output = std::io::Result<T>>) -> Result<T, String> {
    match tokio::time::timeout(t, f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("нет ответа за {} мс", t.as_millis())),
    }
}

async fn server_addr(server: &Server, timeout: Duration) -> Result<SocketAddr, String> {
    let ip = super::resolve(&server.host, timeout).await?;
    Ok(SocketAddr::new(ip, server.port))
}

async fn udp_exchange(addr: SocketAddr, query: &[u8], id: u16, timeout: Duration) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.connect(addr).await.map_err(|e| e.to_string())?;
    sock.send(query).await.map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 65535];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let n = with_timeout(left, sock.recv(&mut buf)).await?;
        // Чужие или запоздавшие ответы пропускаем.
        if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn stream_send<S: AsyncWrite + Unpin>(s: &mut S, query: &[u8]) -> std::io::Result<()> {
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    s.write_all(&framed).await
}

async fn stream_recv<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Один или несколько ответов по потоковому соединению (для AXFR — до второй SOA).
async fn stream_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    query: &[u8],
    axfr: bool,
    timeout: Duration,
) -> Result<Vec<Vec<u8>>, String> {
    with_timeout(timeout, stream_send(s, query)).await?;
    let mut msgs = Vec::new();
    let mut soa = 0;
    loop {
        let m = with_timeout(timeout, stream_recv(s)).await;
        let m = match m {
            Ok(m) => m,
            Err(e) if msgs.is_empty() => return Err(e),
            Err(_) => break,
        };
        if !axfr {
            return Ok(vec![m]);
        }
        let parsed = dnsproto::parse(&m)?;
        soa += parsed.answers.iter().filter(|r| r.rtype == "SOA").count();
        let stop = parsed.rcode != 0 || parsed.answers.is_empty() || soa >= 2;
        msgs.push(m);
        if stop || msgs.len() > 10_000 {
            break;
        }
    }
    Ok(msgs)
}

async fn tcp_exchange(addr: SocketAddr, query: &[u8], axfr: bool, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
    let mut s = with_timeout(timeout, TcpStream::connect(addr)).await?;
    stream_exchange(&mut s, query, axfr, timeout).await
}

async fn tls_exchange(
    server: &Server,
    addr: SocketAddr,
    query: &[u8],
    axfr: bool,
    timeout: Duration,
) -> Result<Vec<Vec<u8>>, String> {
    let s = with_timeout(timeout, TcpStream::connect(addr)).await?;
    let mut tls = crate::probe::tls_connect(s, &server.host, timeout).await?;
    stream_exchange(&mut tls, query, axfr, timeout).await
}

/// Выполнение одного запроса на одном сервере.
pub async fn query(server: &Server, q: &Query, timeout: Duration, retries: u32) -> Answer {
    let mut ans = Answer {
        server: server.label.clone(),
        transport: server.transport,
        name: q.name.clone(),
        qtype: dnsproto::type_name(q.qtype),
        rtt_ms: None,
        rcode: String::new(),
        flags: String::new(),
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        nsid: None,
        size: 0,
        tcp_fallback: false,
        error: None,
    };
    let wire = match dnsproto::build_query(q) {
        Ok(w) => w,
        Err(e) => {
            ans.error = Some(e);
            return ans;
        }
    };
    let axfr = q.qtype == 252;
    let mut last_err = String::new();
    for attempt in 0..=retries {
        let started = Instant::now();
        let res: Result<Vec<Vec<u8>>, String> = async {
            match server.transport {
                Transport::Https => {
                    let url = format!("https://{}:{}{}", server.host, server.port, server.path);
                    Ok(vec![super::http::doh_post(&url, &wire, timeout).await?])
                }
                t => {
                    let addr = server_addr(server, timeout).await?;
                    match t {
                        Transport::Udp if !axfr => {
                            let first = udp_exchange(addr, &wire, q.id, timeout).await?;
                            if dnsproto::parse(&first).map(|m| m.flags.tc).unwrap_or(false) {
                                ans.tcp_fallback = true;
                                tcp_exchange(addr, &wire, false, timeout).await
                            } else {
                                Ok(vec![first])
                            }
                        }
                        Transport::Tls => tls_exchange(server, addr, &wire, axfr, timeout).await,
                        _ => tcp_exchange(addr, &wire, axfr, timeout).await,
                    }
                }
            }
        }
        .await;
        match res {
            Ok(msgs) => {
                ans.rtt_ms = Some(ms_f(started.elapsed()));
                for (i, raw) in msgs.iter().enumerate() {
                    ans.size += raw.len();
                    match dnsproto::parse(raw) {
                        Ok(m) => merge(&mut ans, m, i == 0),
                        Err(e) => {
                            ans.error = Some(format!("ответ не разобран: {e}"));
                            break;
                        }
                    }
                }
                return ans;
            }
            Err(e) => {
                last_err = e;
                if attempt < retries {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    ans.error = Some(last_err);
    ans
}

fn merge(ans: &mut Answer, m: Message, first: bool) {
    if first {
        ans.rcode = m.rcode_name().to_string();
        ans.flags = m.flags.label();
        ans.nsid = m.edns.as_ref().and_then(|e| e.2.clone());
    }
    ans.answers.extend(m.answers);
    ans.authority.extend(m.authority);
    ans.additional.extend(m.additional);
}

/// Подготовка списка (имя, тип): IP-адреса превращаются в PTR-запросы.
pub fn expand_names(cfg: &Config, domain: Option<&str>) -> Result<Vec<(String, u16)>, String> {
    let mut types = Vec::new();
    for t in super::split_list(&cfg.types) {
        types.push(dnsproto::type_code(&t).ok_or_else(|| format!("неизвестный тип записи «{t}»"))?);
    }
    if types.is_empty() {
        types.push(1);
    }
    let mut out = Vec::new();
    for name in super::split_list(&cfg.names) {
        let name = if name.contains("{domain}") {
            let d = domain.ok_or("в имени есть {domain}, но DNS-суффикс системы не определён")?;
            name.replace("{domain}", d.trim_matches('.'))
        } else {
            name
        };
        if let Ok(ip) = name.parse::<IpAddr>() {
            out.push((dnsproto::reverse_name(ip), 12));
            continue;
        }
        for &t in &types {
            if !out.contains(&(name.clone(), t)) {
                out.push((name.clone(), t));
            }
        }
    }
    if out.is_empty() {
        return Err("не задано ни одного имени".into());
    }
    Ok(out)
}

pub fn expand_servers(cfg: &Config) -> Result<Vec<Server>, String> {
    let mut out = Vec::new();
    for s in super::split_list(&cfg.servers) {
        if s.eq_ignore_ascii_case("system") {
            let sys = system_servers();
            if sys.is_empty() {
                return Err("DNS-серверы системы не определены — укажите серверы явно".into());
            }
            for ip in sys {
                let text = match ip {
                    IpAddr::V6(v6) => format!("[{v6}]"),
                    v4 => v4.to_string(),
                };
                out.push(Server::parse(&text, cfg.transport)?);
            }
        } else {
            out.push(Server::parse(&s, cfg.transport)?);
        }
    }
    out.dedup();
    if out.is_empty() {
        return Err("не задан ни один DNS-сервер".into());
    }
    Ok(out)
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let needs_domain = cfg.names.contains("{domain}");
    let domain = if needs_domain {
        tokio::task::spawn_blocking(system_domain).await.ok().flatten()
    } else {
        None
    };
    let names = match expand_names(&cfg, domain.as_deref()) {
        Ok(n) => n,
        Err(e) => return sink.send(Event::Log(e)),
    };
    let servers = match tokio::task::spawn_blocking({
        let cfg = cfg.clone();
        move || expand_servers(&cfg)
    })
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return sink.send(Event::Log(e)),
        Err(e) => return sink.send(Event::Log(e.to_string())),
    };
    let mut jobs = Vec::new();
    for (name, t) in &names {
        for s in &servers {
            jobs.push((s.clone(), name.clone(), *t));
        }
    }
    sink.send(Event::Total(jobs.len()));
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    let cfg = std::sync::Arc::new(cfg);
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(rand_id()));
    super::for_each_limited(jobs, cfg.concurrency, &cancel, |(server, name, t)| {
        let sink = sink.clone();
        let cfg = cfg.clone();
        let id = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        async move {
            let mut q = Query::new(id, &name, t);
            q.recursion = cfg.recursion;
            q.dnssec_ok = cfg.dnssec;
            q.checking_disabled = cfg.checking_disabled;
            q.nsid = cfg.nsid;
            let a = query(&server, &q, timeout, cfg.retries).await;
            sink.send(Event::Answer(Box::new(a)));
        }
    })
    .await;
}

/// Случайный стартовый ID запросов (защита от совпадения с чужими ответами).
pub fn rand_id() -> u16 {
    let mut b = [0u8; 2];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    u16::from_be_bytes(b)
}

/// Группировка для сравнения: (имя, тип) → ответы разных серверов и признак расхождения.
pub fn compare(answers: &[Answer]) -> Vec<((String, String), Vec<&Answer>, bool)> {
    let mut groups: Vec<((String, String), Vec<&Answer>, bool)> = Vec::new();
    for a in answers {
        let key = (a.name.clone(), a.qtype.clone());
        match groups.iter_mut().find(|g| g.0 == key) {
            Some(g) => g.1.push(a),
            None => groups.push((key, vec![a], false)),
        }
    }
    for g in &mut groups {
        let first = g.1.first().map(|a| a.signature());
        g.2 = g.1.iter().any(|a| Some(a.signature()) != first);
    }
    groups
}

pub fn render_text(r: &Report) -> String {
    let mut s = String::new();
    for a in &r.answers {
        let rtt = a.rtt_ms.map(|v| format!("{v:.1} мс")).unwrap_or_else(|| "-".into());
        s += &format!(
            ";; {} {} @{} ({}) {} {} [{}]{}\n",
            a.name,
            a.qtype,
            a.server,
            a.transport.label(),
            rtt,
            if a.error.is_some() { "ERROR" } else { &a.rcode },
            a.flags,
            a.nsid.as_ref().map(|n| format!(" nsid={n}")).unwrap_or_default()
        );
        if let Some(e) = &a.error {
            s += &format!(";; {e}\n");
        }
        for (title, recs) in [("ANSWER", &a.answers), ("AUTHORITY", &a.authority), ("ADDITIONAL", &a.additional)] {
            if recs.is_empty() {
                continue;
            }
            s += &format!(";; {title}\n");
            for rec in recs {
                s += &format!("{}\t{}\tIN\t{}\t{}\n", rec.name, rec.ttl, rec.rtype, rec.data);
            }
        }
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_parsing() {
        let s = Server::parse("8.8.8.8", Transport::Udp).unwrap();
        assert_eq!((s.transport, s.host.as_str(), s.port), (Transport::Udp, "8.8.8.8", 53));
        let s = Server::parse("tls://dns.google", Transport::Udp).unwrap();
        assert_eq!((s.transport, s.port), (Transport::Tls, 853));
        let s = Server::parse("https://dns.example/q", Transport::Udp).unwrap();
        assert_eq!((s.transport, s.port, s.path.as_str()), (Transport::Https, 443, "/q"));
        let s = Server::parse("10.0.0.1:5353", Transport::Tcp).unwrap();
        assert_eq!((s.transport, s.port), (Transport::Tcp, 5353));
        let s = Server::parse("[2001:db8::1]", Transport::Udp).unwrap();
        assert_eq!(s.host, "2001:db8::1");
    }

    #[test]
    fn names_expand() {
        let cfg = Config {
            names: "example.com 10.0.0.1 _ldap._tcp.{domain}".into(),
            types: "A,MX".into(),
            ..Default::default()
        };
        let n = expand_names(&cfg, Some("corp.local.")).unwrap();
        assert_eq!(n[0], ("example.com".into(), 1));
        assert_eq!(n[1], ("example.com".into(), 15));
        assert_eq!(n[2], ("1.0.0.10.in-addr.arpa".into(), 12));
        assert_eq!(n[3], ("_ldap._tcp.corp.local".into(), 1));
        assert!(expand_names(&cfg, None).is_err());
        let bad = Config {
            names: "x".into(),
            types: "BOGUS".into(),
            ..Default::default()
        };
        assert!(expand_names(&bad, None).is_err());
    }

    /// Мини-сервер DNS: отвечает A 192.0.2.1 по UDP, а по UDP для `big.` — с флагом TC.
    async fn fake_dns() -> (SocketAddr, SocketAddr) {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (ua, ta) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
        fn answer(q: &[u8], tc: bool) -> Vec<u8> {
            let (qname, end) = dnsproto::read_name(q, 12).unwrap();
            let mut r = q[..2].to_vec();
            r.extend_from_slice(&[0x81 | if tc { 2 } else { 0 }, 0x80, 0, 1, 0, if tc { 0 } else { 1 }, 0, 0, 0, 0]);
            r.extend_from_slice(&q[12..end + 4]);
            if !tc {
                r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
            }
            let _ = qname;
            r
        }
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = udp.recv_from(&mut buf).await.unwrap();
                let q = &buf[..n];
                let big = dnsproto::read_name(q, 12).unwrap().0 == "big.";
                udp.send_to(&answer(q, big), from).await.unwrap();
            }
        });
        tokio::spawn(async move {
            loop {
                let (mut s, _) = tcp.accept().await.unwrap();
                tokio::spawn(async move {
                    let q = stream_recv(&mut s).await.unwrap();
                    stream_send(&mut s, &answer(&q, false)).await.unwrap();
                });
            }
        });
        (ua, ta)
    }

    #[tokio::test]
    async fn udp_tcp_and_fallback() {
        let (ua, _ta) = fake_dns().await;
        let server = Server::parse(&ua.to_string(), Transport::Udp).unwrap();
        let a = query(&server, &Query::new(7, "example.com", 1), Duration::from_secs(2), 0).await;
        assert_eq!(a.error, None);
        assert_eq!(a.rcode, "NOERROR");
        assert_eq!(a.answers[0].data, "192.0.2.1");
        assert!(!a.tcp_fallback);
        // Для TC нужен TCP на том же порту — здесь его нет, поэтому ждём ошибку TCP,
        // но с отметкой о переходе на TCP.
        let a = query(&server, &Query::new(8, "big", 1), Duration::from_millis(500), 0).await;
        assert!(a.tcp_fallback);
    }

    #[tokio::test]
    async fn tcp_transport() {
        let (_ua, ta) = fake_dns().await;
        let server = Server::parse(&format!("tcp://{ta}"), Transport::Udp).unwrap();
        let a = query(&server, &Query::new(9, "example.com", 1), Duration::from_secs(2), 0).await;
        assert_eq!(a.error, None);
        assert_eq!(a.answers.len(), 1);
    }

    #[test]
    fn compare_detects_difference() {
        let mk = |srv: &str, data: &str| Answer {
            server: srv.into(),
            transport: Transport::Udp,
            name: "x.".into(),
            qtype: "A".into(),
            rtt_ms: Some(1.0),
            rcode: "NOERROR".into(),
            flags: String::new(),
            answers: vec![Record {
                name: "x.".into(),
                rtype: "A".into(),
                class: 1,
                ttl: 5,
                data: data.into(),
            }],
            authority: vec![],
            additional: vec![],
            nsid: None,
            size: 0,
            tcp_fallback: false,
            error: None,
        };
        let same = [mk("a", "1.1.1.1"), mk("b", "1.1.1.1")];
        assert!(!compare(&same)[0].2);
        let diff = [mk("a", "1.1.1.1"), mk("b", "2.2.2.2")];
        assert!(compare(&diff)[0].2);
    }
}

/// Обратное разрешение (PTR) через DNS-серверы системы, с кэшем.
pub async fn reverse_lookup(ip: IpAddr, timeout: Duration) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<IpAddr, Option<String>>>> = OnceLock::new();
    static SERVERS: OnceLock<Vec<IpAddr>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&ip) {
        return v.clone();
    }
    let servers = match SERVERS.get() {
        Some(s) => s.clone(),
        None => {
            let s = tokio::task::spawn_blocking(system_servers).await.unwrap_or_default();
            let _ = SERVERS.set(s.clone());
            s
        }
    };
    let mut result = None;
    for s in servers.iter().take(2) {
        let server = Server {
            label: s.to_string(),
            transport: Transport::Udp,
            host: s.to_string(),
            port: 53,
            path: String::new(),
        };
        let a = query(&server, &Query::new(rand_id(), &dnsproto::reverse_name(ip), 12), timeout, 0).await;
        if a.error.is_none() {
            result = a
                .answers
                .iter()
                .find(|r| r.rtype == "PTR")
                .map(|r| r.data.trim_end_matches('.').to_string());
            break;
        }
    }
    cache.lock().unwrap().insert(ip, result.clone());
    result
}
