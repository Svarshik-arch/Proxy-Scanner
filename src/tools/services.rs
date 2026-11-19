//! Сканер сервисов и версий: TCP (баннеры, HTTP, TLS, SSH, SMB, RDP, СУБД…) и UDP
//! (DNS, NTP, SNMP, NetBIOS, SSDP, mDNS, MSSQL Browser).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::tls::Versions;
use super::{Sink, dnsproto, printable};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub targets: String,
    pub tcp_ports: String,
    pub udp_ports: String,
    /// Community для SNMP (пусто — SNMP не опрашивать).
    pub snmp_community: String,
    pub connect_timeout_ms: u64,
    /// Сколько ждать баннер / ответ на пробу.
    pub read_timeout_ms: u64,
    pub concurrency: usize,
    /// Отправлять активные пробы (HTTP, TLS, SMB, RDP…), а не только ждать баннер.
    pub active_probes: bool,
    /// Показывать UDP-порты без ответа (open|filtered).
    pub show_udp_silent: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: String::new(),
            tcp_ports: "21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6379,8080,8443,9200,11211,27017".into(),
            udp_ports: "53,123,137,161,1434,1900,5353".into(),
            snmp_community: "public".into(),
            connect_timeout_ms: 1500,
            read_timeout_ms: 2500,
            concurrency: 256,
            active_probes: true,
            show_udp_silent: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsSummary {
    pub version: String,
    pub cipher: String,
    pub subject: String,
    pub issuer: String,
    pub days_left: i64,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: String,
    pub version: String,
    pub tls: Option<TlsSummary>,
    pub banner: String,
    pub details: Vec<String>,
    pub rtt_ms: Option<f64>,
}

impl Service {
    fn new(ip: Ipv4Addr, port: u16, proto: &str) -> Self {
        Self {
            ip,
            port,
            proto: proto.into(),
            state: "open".into(),
            service: String::new(),
            version: String::new(),
            tls: None,
            banner: String::new(),
            details: Vec::new(),
            rtt_ms: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Total(u64),
    Progress(u64),
    Found(Box<Service>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub services: Vec<Service>,
}

const TLS_PORTS: &[u16] = &[443, 465, 636, 853, 990, 993, 995, 2376, 3269, 5061, 5986, 6443, 8443, 9443, 10250];
/// Порты, где сервер говорит первым — сначала ждём баннер.
const BANNER_PORTS: &[u16] = &[21, 22, 23, 25, 110, 143, 587, 2222, 3306, 5900, 5901, 6667];
const HTTP_PORTS: &[u16] = &[80, 81, 591, 2375, 3000, 5000, 5985, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 9200];

fn well_known(port: u16, proto: &str) -> &'static str {
    match (proto, port) {
        ("tcp", 21) => "ftp",
        ("tcp", 22) => "ssh",
        ("tcp", 23) => "telnet",
        ("tcp", 25 | 587) => "smtp",
        ("tcp", 465) => "smtps",
        (_, 53) => "dns",
        ("tcp", 80 | 8080 | 8000 | 8008 | 8081 | 8888) => "http",
        ("tcp", 110) => "pop3",
        ("udp", 123) => "ntp",
        ("tcp", 135) => "msrpc",
        ("udp", 137) => "netbios-ns",
        ("tcp", 139) => "netbios-ssn",
        ("tcp", 143) => "imap",
        ("udp", 161) => "snmp",
        ("tcp", 389) => "ldap",
        ("tcp", 443 | 8443) => "https",
        ("tcp", 445) => "smb",
        ("tcp", 636) => "ldaps",
        ("tcp", 993) => "imaps",
        ("tcp", 995) => "pop3s",
        ("tcp", 1433) => "mssql",
        ("udp", 1434) => "mssql-browser",
        ("tcp", 1521) => "oracle",
        ("udp", 1900) => "ssdp",
        ("tcp", 2049) => "nfs",
        ("tcp", 3268) => "ldap-gc",
        ("tcp", 3306) => "mysql",
        ("tcp", 3389) => "rdp",
        ("tcp", 5432) => "postgresql",
        ("udp", 5353) => "mdns",
        ("tcp", 5900..=5903) => "vnc",
        ("tcp", 5985) => "winrm",
        ("tcp", 5986) => "winrm-https",
        ("tcp", 6379) => "redis",
        ("tcp", 9200) => "elasticsearch",
        ("tcp", 11211) => "memcached",
        ("tcp", 27017) => "mongodb",
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// Пробы TCP
// ---------------------------------------------------------------------------

async fn read_some(s: &mut TcpStream, timeout: Duration, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || out.len() >= max {
            break;
        }
        // После первых данных ждём продолжение недолго.
        let wait = if out.is_empty() { left } else { left.min(Duration::from_millis(250)) };
        match tokio::time::timeout(wait, s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => out.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    out
}

async fn connect(addr: SocketAddr, timeout: Duration) -> Option<(TcpStream, f64)> {
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => Some((s, super::ms_f(started.elapsed()))),
        _ => None,
    }
}

fn http_request(host: &str) -> String {
    format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: proxy-scanner\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
}

fn html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let gt = lower[start..].find('>')? + start + 1;
    let end = lower[gt..].find("</title")? + gt;
    let t = body[gt..end].split_whitespace().collect::<Vec<_>>().join(" ");
    (!t.is_empty()).then(|| t.chars().take(80).collect())
}

/// Разбор ответа HTTP: (статус, Server, заголовок страницы, прочее).
fn describe_http(data: &[u8], svc: &mut Service, scheme: &str) -> bool {
    let Some(resp) = crate::probe::parse_head(data) else { return false };
    svc.service = scheme.into();
    let server = resp.header("Server").unwrap_or("").to_string();
    svc.version = server.clone();
    svc.details.push(format!("HTTP {}", resp.status));
    if let Some(p) = resp.header("X-Powered-By") {
        svc.details.push(format!("X-Powered-By: {p}"));
    }
    if let Some(a) = resp.header("WWW-Authenticate") {
        svc.details.push(format!("аутентификация: {}", a.split_whitespace().next().unwrap_or(a)));
    }
    if resp.header("Proxy-Authenticate").is_some() || resp.status == 407 {
        svc.details.push("похоже на прокси (407)".into());
    }
    if let Some(l) = resp.header("Location") {
        svc.details.push(format!("→ {l}"));
    }
    let body_start = data.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(data.len());
    if let Some(t) = html_title(&String::from_utf8_lossy(&data[body_start..])) {
        svc.details.push(format!("«{t}»"));
    }
    if svc.version.is_empty() && resp.header("Content-Type").is_some_and(|c| c.contains("json")) {
        let body = String::from_utf8_lossy(&data[body_start..]);
        if body.contains("\"cluster_name\"") || body.contains("You Know, for Search") {
            svc.version = "Elasticsearch".into();
        }
    }
    svc.banner = printable(resp.head.lines().next().unwrap_or("").as_bytes(), 120);
    true
}

/// Сигнатуры текстовых баннеров.
pub fn match_banner(data: &[u8], port: u16, svc: &mut Service) -> bool {
    let text = String::from_utf8_lossy(data);
    let first = text.lines().next().unwrap_or("").trim().to_string();
    svc.banner = printable(data, 200);
    if let Some(rest) = first.strip_prefix("SSH-") {
        svc.service = "ssh".into();
        let soft = rest.split_once('-').map(|x| x.1).unwrap_or(rest);
        svc.version = soft.replacen('_', " ", 1);
        if rest.starts_with("1.") {
            svc.details.push("протокол SSH 1 — устарел".into());
        }
        return true;
    }
    if first.starts_with("RFB ") {
        svc.service = "vnc".into();
        svc.version = first.clone();
        return true;
    }
    if data.first() == Some(&0xFF) && data.len() >= 3 && (0xFB..=0xFE).contains(&data[1]) {
        svc.service = "telnet".into();
        svc.banner = printable(&data.iter().copied().filter(|b| *b < 0xF0).collect::<Vec<_>>(), 200);
        return true;
    }
    // MySQL/MariaDB: длина(3) + номер(1) + протокол 10 + версия\0
    if data.len() > 5 && data[4] == 0x0A && data[3] == 0 {
        let ver: Vec<u8> = data[5..].iter().copied().take_while(|b| *b != 0).collect();
        if !ver.is_empty() && ver.iter().all(|b| b.is_ascii_graphic()) {
            svc.service = "mysql".into();
            svc.version = String::from_utf8_lossy(&ver).into_owned();
            if svc.version.to_ascii_lowercase().contains("mariadb") {
                svc.service = "mariadb".into();
            }
            return true;
        }
    }
    if data.len() > 4 && data[4] == 0xFF && data[3] == 0 && text.contains("is not allowed to connect") {
        svc.service = "mysql".into();
        svc.details.push("подключение с этого адреса запрещено".into());
        return true;
    }
    if first.starts_with("+OK") {
        svc.service = "pop3".into();
        svc.version = first[3..].trim().to_string();
        return true;
    }
    if first.starts_with("* OK") || first.starts_with("* PREAUTH") {
        svc.service = "imap".into();
        svc.version = first[4..].trim().to_string();
        return true;
    }
    if first.starts_with("220") || first.starts_with("421") {
        let lower = first.to_ascii_lowercase();
        svc.service = if lower.contains("smtp") || lower.contains("mail") || [25, 465, 587].contains(&port) {
            "smtp"
        } else if lower.contains("ftp") || port == 21 {
            "ftp"
        } else {
            "ftp/smtp"
        }
        .into();
        svc.version = first[3..].trim_start_matches(['-', ' ']).to_string();
        return true;
    }
    if first.starts_with("-NOAUTH") || first.starts_with("+PONG") || first.starts_with("-DENIED") {
        svc.service = "redis".into();
        if first.starts_with("+PONG") {
            svc.details.push("доступ без пароля".into());
        } else {
            svc.details.push("требуется пароль".into());
        }
        return true;
    }
    if first.starts_with("VERSION ") {
        svc.service = "memcached".into();
        svc.version = first[8..].to_string();
        return true;
    }
    if first.starts_with("HTTP/") {
        return describe_http(data, svc, "http");
    }
    false
}

pub fn smb_negotiate() -> Vec<u8> {
    let dialects: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];
    let mut smb = vec![0xFE, b'S', b'M', b'B', 64, 0];
    smb.extend_from_slice(&[0; 2]); // credit charge
    smb.extend_from_slice(&[0; 4]); // status
    smb.extend_from_slice(&[0, 0]); // command: NEGOTIATE
    smb.extend_from_slice(&[1, 0]); // credits
    smb.extend_from_slice(&[0; 4]); // flags
    smb.extend_from_slice(&[0; 4]); // next command
    smb.extend_from_slice(&[0; 8]); // message id
    smb.extend_from_slice(&[0; 4]); // reserved
    smb.extend_from_slice(&[0; 4]); // tree id
    smb.extend_from_slice(&[0; 8]); // session id
    smb.extend_from_slice(&[0; 16]); // signature
    smb.extend_from_slice(&36u16.to_le_bytes());
    smb.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    smb.extend_from_slice(&1u16.to_le_bytes()); // security mode: signing enabled
    smb.extend_from_slice(&[0; 2]);
    smb.extend_from_slice(&[0; 4]); // capabilities
    smb.extend_from_slice(b"proxy-scanner\0\0\0"); // client guid
    smb.extend_from_slice(&[0; 8]); // start time
    for d in dialects {
        smb.extend_from_slice(&d.to_le_bytes());
    }
    let mut out = vec![0, 0];
    out.extend_from_slice(&(smb.len() as u16).to_be_bytes());
    out.extend(smb);
    out
}

pub fn parse_smb(data: &[u8], svc: &mut Service) -> bool {
    if data.len() < 8 {
        return false;
    }
    let smb = &data[4..];
    if smb.starts_with(b"\xFFSMB") {
        svc.service = "smb".into();
        svc.version = "SMBv1".into();
        svc.details.push("сервер ответил по SMBv1 — устаревший протокол".into());
        return true;
    }
    if !smb.starts_with(b"\xFESMB") || smb.len() < 64 + 8 {
        return false;
    }
    let body = &smb[64..];
    let security = u16::from_le_bytes([body[2], body[3]]);
    let dialect = u16::from_le_bytes([body[4], body[5]]);
    svc.service = "smb".into();
    svc.version = match dialect {
        0x0202 => "SMB 2.0.2".into(),
        0x0210 => "SMB 2.1".into(),
        0x0300 => "SMB 3.0".into(),
        0x0302 => "SMB 3.0.2+".into(),
        0x0311 => "SMB 3.1.1".into(),
        0x02FF => "SMB 2.???".into(),
        d => format!("SMB {d:#06x}"),
    };
    svc.details.push(if security & 0x02 != 0 {
        "подпись SMB обязательна".into()
    } else {
        "подпись SMB не обязательна".into()
    });
    true
}

pub fn rdp_request() -> Vec<u8> {
    // TPKT + X.224 Connection Request + RDP Negotiation Request (TLS | CredSSP | RDSTLS).
    let mut x224 = vec![0x0E, 0xE0, 0, 0, 0, 0, 0];
    x224.extend_from_slice(&[0x01, 0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00]);
    x224[0] = (x224.len() - 1) as u8;
    let mut out = vec![0x03, 0x00];
    out.extend_from_slice(&((x224.len() + 4) as u16).to_be_bytes());
    out.extend(x224);
    out
}

pub fn parse_rdp(data: &[u8], svc: &mut Service) -> bool {
    if data.len() < 11 || data[0] != 0x03 || data[5] != 0xD0 {
        return false;
    }
    svc.service = "rdp".into();
    if data.len() >= 19 {
        let ty = data[11];
        let val = u32::from_le_bytes([data[15], data[16], data[17], data[18]]);
        match ty {
            2 => {
                svc.version = match val {
                    0 => "стандартная защита RDP (без TLS)".into(),
                    1 => "TLS".into(),
                    2 | 8 | 10 => "NLA (CredSSP)".into(),
                    v => format!("протокол {v:#x}"),
                };
                if val == 0 {
                    svc.details.push("без NLA и TLS — устаревшая защита".into());
                }
            }
            3 => {
                svc.details.push(format!("ошибка согласования {val:#x}"));
                if val == 5 {
                    svc.version = "требуется NLA".into();
                }
            }
            _ => {}
        }
    } else {
        svc.version = "стандартная защита RDP".into();
        svc.details.push("сервер не поддерживает согласование TLS/NLA".into());
    }
    true
}

pub fn mssql_prelogin() -> Vec<u8> {
    let mut payload = vec![0x00, 0x00, 0x0B, 0x00, 0x06, 0x01, 0x00, 0x11, 0x00, 0x01, 0xFF];
    payload.extend_from_slice(&[0; 6]);
    payload.push(0x02);
    let mut out = vec![0x12, 0x01];
    out.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend(payload);
    out
}

pub fn parse_mssql(data: &[u8], svc: &mut Service) -> bool {
    if data.len() < 8 + 11 || data[0] != 0x04 {
        return false;
    }
    let p = &data[8..];
    let mut i = 0;
    while i + 5 <= p.len() && p[i] != 0xFF {
        let (tok, off, len) = (p[i], u16::from_be_bytes([p[i + 1], p[i + 2]]) as usize, u16::from_be_bytes([p[i + 3], p[i + 4]]));
        if tok == 0 && len >= 6 && off + 6 <= p.len() {
            let (maj, min, build) = (p[off], p[off + 1], u16::from_be_bytes([p[off + 2], p[off + 3]]));
            let year = match maj {
                17 => " (2025)",
                16 => " (2022)",
                15 => " (2019)",
                14 => " (2017)",
                13 => " (2016)",
                12 => " (2014)",
                11 => " (2012)",
                10 => " (2008/R2)",
                9 => " (2005)",
                _ => "",
            };
            svc.service = "mssql".into();
            svc.version = format!("SQL Server {maj}.{min}.{build}{year}");
            return true;
        }
        i += 5;
    }
    svc.service = "mssql".into();
    true
}

async fn tls_probe(addr: SocketAddr, host: &str, cfg: &Config, svc: &mut Service) -> bool {
    let timeout = Duration::from_millis(cfg.read_timeout_ms.max(300));
    let Some((s, _)) = connect(addr, Duration::from_millis(cfg.connect_timeout_ms)).await else { return false };
    let Ok((mut tls, info)) = super::tls::handshake(s, host, Versions::Auto, &["http/1.1"], timeout).await else {
        return false;
    };
    let leaf = info.chain.first();
    svc.tls = Some(TlsSummary {
        version: info.version.clone(),
        cipher: info.cipher.clone(),
        subject: leaf.map(|c| c.short_subject()).unwrap_or_default(),
        issuer: leaf.map(|c| c.short_issuer()).unwrap_or_default(),
        days_left: leaf.map(|c| c.days_left).unwrap_or(0),
        trusted: info.trust_error.is_none(),
    });
    if let Some(e) = &info.trust_error {
        svc.details.push(format!("сертификат: {e}"));
    }
    // Что внутри TLS: чаще всего HTTP.
    let base = well_known(addr.port(), "tcp");
    if tokio::time::timeout(timeout, tls.write_all(http_request(host).as_bytes())).await.is_ok() {
        let mut data = Vec::new();
        let mut buf = vec![0u8; 8192];
        let deadline = Instant::now() + timeout;
        while data.len() < 16384 {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, tls.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    data.extend_from_slice(&buf[..n]);
                    if data.windows(4).any(|w| w == b"\r\n\r\n") && data.len() > 2048 {
                        break;
                    }
                }
                _ => break,
            }
        }
        if describe_http(&data, svc, "https") {
            return true;
        }
        if !data.is_empty() && match_banner(&data, addr.port(), svc) {
            svc.service = format!("{}/tls", svc.service);
            return true;
        }
    }
    svc.service = if base.is_empty() { "tls".into() } else { base.into() };
    true
}

async fn scan_tcp(ip: Ipv4Addr, port: u16, cfg: Arc<Config>) -> Option<Service> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let ct = Duration::from_millis(cfg.connect_timeout_ms.max(100));
    let rt = Duration::from_millis(cfg.read_timeout_ms.max(200));
    let (mut s, rtt) = connect(addr, ct).await?;
    let mut svc = Service::new(ip, port, "tcp");
    svc.rtt_ms = Some(rtt);
    let host = ip.to_string();
    if !cfg.active_probes {
        let data = read_some(&mut s, rt, 4096).await;
        if !data.is_empty() && !match_banner(&data, port, &mut svc) {
            svc.banner = printable(&data, 200);
        }
        if svc.service.is_empty() {
            svc.service = well_known(port, "tcp").into();
        }
        return Some(svc);
    }
    // Порт-специфичные пробы.
    let special: Option<(Vec<u8>, fn(&[u8], &mut Service) -> bool)> = match port {
        445 | 139 => Some((smb_negotiate(), parse_smb)),
        3389 => Some((rdp_request(), parse_rdp)),
        1433 => Some((mssql_prelogin(), parse_mssql)),
        _ => None,
    };
    if let Some((req, parse)) = special {
        if tokio::time::timeout(rt, s.write_all(&req)).await.is_ok() {
            let data = read_some(&mut s, rt, 4096).await;
            if parse(&data, &mut svc) {
                return Some(svc);
            }
            if !data.is_empty() {
                svc.banner = printable(&data, 120);
            }
        }
        svc.service = well_known(port, "tcp").into();
        return Some(svc);
    }
    if TLS_PORTS.contains(&port) {
        drop(s);
        if tls_probe(addr, &host, &cfg, &mut svc).await {
            return Some(svc);
        }
        svc.service = well_known(port, "tcp").into();
        return Some(svc);
    }
    // Ждём баннер (кроме заведомо HTTP-портов).
    let wait = if HTTP_PORTS.contains(&port) {
        Duration::ZERO
    } else if BANNER_PORTS.contains(&port) {
        rt
    } else {
        rt.min(Duration::from_millis(1200))
    };
    if !wait.is_zero() {
        let data = read_some(&mut s, wait, 4096).await;
        if !data.is_empty() {
            if !match_banner(&data, port, &mut svc) {
                svc.service = well_known(port, "tcp").into();
            }
            return Some(svc);
        }
    }
    let probe: Vec<u8> = match port {
        5432 => vec![0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F],
        6379 => b"PING\r\n".to_vec(),
        11211 => b"version\r\n".to_vec(),
        _ => http_request(&host).into_bytes(),
    };
    if tokio::time::timeout(rt, s.write_all(&probe)).await.is_ok() {
        let data = read_some(&mut s, rt, 16384).await;
        if port == 5432 && (data == b"S" || data == b"N") {
            svc.service = "postgresql".into();
            svc.details.push(if data == b"S" { "поддерживает SSL".into() } else { "без SSL".to_string() });
            return Some(svc);
        }
        if !data.is_empty() {
            // TLS-сервер на нестандартном порту отвечает на HTTP алертом или ошибкой.
            let looks_tls = data[0] == 0x15 && data.get(1) == Some(&0x03);
            let text = String::from_utf8_lossy(&data).to_ascii_lowercase();
            if looks_tls || text.contains("plain http request was sent to https") {
                if tls_probe(addr, &host, &cfg, &mut svc).await {
                    return Some(svc);
                }
            }
            if match_banner(&data, port, &mut svc) {
                return Some(svc);
            }
            svc.banner = printable(&data, 200);
        }
    }
    drop(s);
    // Молчит на HTTP — может быть TLS.
    if svc.banner.is_empty() && tls_probe(addr, &host, &cfg, &mut svc).await {
        return Some(svc);
    }
    if svc.service.is_empty() {
        svc.service = well_known(port, "tcp").into();
    }
    Some(svc)
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// Простейший разбор BER: последняя строка (OCTET STRING) в сообщении SNMP.
fn ber_strings(data: &[u8], out: &mut Vec<Vec<u8>>, depth: usize) {
    let mut i = 0;
    while i + 2 <= data.len() && depth < 12 {
        let tag = data[i];
        let mut len = data[i + 1] as usize;
        let mut hdr = 2;
        if len & 0x80 != 0 {
            let n = len & 0x7F;
            if n == 0 || n > 3 || i + 2 + n > data.len() {
                return;
            }
            len = data[i + 2..i + 2 + n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
            hdr += n;
        }
        let Some(val) = data.get(i + hdr..i + hdr + len) else { return };
        if tag & 0x20 != 0 {
            ber_strings(val, out, depth + 1);
        } else if tag == 0x04 {
            out.push(val.to_vec());
        }
        i += hdr + len;
    }
}

pub fn snmp_get_sysdescr(community: &str, id: u16) -> Vec<u8> {
    let oid = [0x2B, 6, 1, 2, 1, 1, 1, 0];
    let mut varbind = vec![0x06, oid.len() as u8];
    varbind.extend_from_slice(&oid);
    varbind.extend_from_slice(&[0x05, 0x00]);
    let wrap = |tag: u8, inner: Vec<u8>| {
        let mut v = vec![tag, inner.len() as u8];
        v.extend(inner);
        v
    };
    let vb = wrap(0x30, varbind);
    let vbl = wrap(0x30, vb);
    let mut pdu = vec![0x02, 0x02];
    pdu.extend_from_slice(&id.to_be_bytes());
    pdu.extend_from_slice(&[0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
    pdu.extend(vbl);
    let pdu = wrap(0xA0, pdu);
    let mut msg = vec![0x02, 0x01, 0x01];
    msg.extend(wrap(0x04, community.as_bytes().to_vec()));
    msg.extend(pdu);
    wrap(0x30, msg)
}

/// NTP: сдвиг часов узла относительно наших (секунды).
pub fn parse_ntp(data: &[u8], t_send: f64, t_recv: f64) -> Option<(u8, String, f64)> {
    if data.len() < 48 || data[0] & 0x07 != 4 {
        return None;
    }
    let stratum = data[1];
    let refid = if stratum <= 1 {
        String::from_utf8_lossy(&data[12..16]).trim_matches('\0').to_string()
    } else {
        Ipv4Addr::new(data[12], data[13], data[14], data[15]).to_string()
    };
    let ts = |o: usize| {
        let secs = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) as f64;
        let frac = u32::from_be_bytes([data[o + 4], data[o + 5], data[o + 6], data[o + 7]]) as f64 / 4294967296.0;
        secs + frac - 2_208_988_800.0
    };
    let (t2, t3) = (ts(32), ts(40));
    let offset = ((t2 - t_send) + (t3 - t_recv)) / 2.0;
    Some((stratum, refid, offset))
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

async fn scan_udp(ip: Ipv4Addr, port: u16, cfg: Arc<Config>) -> Option<Service> {
    let timeout = Duration::from_millis(cfg.read_timeout_ms.max(200));
    let id = super::dns::rand_id();
    let payload: Vec<u8> = match port {
        53 => {
            let mut q = dnsproto::Query::new(id, "version.bind", 16);
            q.edns = false;
            q.recursion = false;
            let mut w = dnsproto::build_query(&q).ok()?;
            let n = w.len();
            w[n - 2..].copy_from_slice(&3u16.to_be_bytes()); // класс CHAOS
            w
        }
        123 => {
            let mut p = vec![0u8; 48];
            p[0] = 0x1B;
            p
        }
        137 => super::discovery::nbstat_query(id),
        161 => {
            if cfg.snmp_community.is_empty() {
                return None;
            }
            snmp_get_sysdescr(&cfg.snmp_community, id)
        }
        1434 => vec![0x03],
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".to_vec(),
        5353 => {
            let mut q = dnsproto::Query::new(0, "_services._dns-sd._udp.local", 12);
            q.edns = false;
            q.recursion = false;
            dnsproto::build_query(&q).ok()?
        }
        _ => b"\r\n".to_vec(),
    };
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect((ip, port)).await.ok()?;
    let started = Instant::now();
    let t_send = unix_now();
    sock.send(&payload).await.ok()?;
    let mut buf = vec![0u8; 8192];
    let mut svc = Service::new(ip, port, "udp");
    svc.service = well_known(port, "udp").into();
    let n = match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        // ICMP «порт недоступен» — порт закрыт.
        Ok(Err(_)) => return None,
        Err(_) => {
            if cfg.show_udp_silent {
                svc.state = "open|filtered".into();
                return Some(svc);
            }
            return None;
        }
    };
    let t_recv = unix_now();
    svc.rtt_ms = Some(super::ms_f(started.elapsed()));
    let data = &buf[..n];
    match port {
        53 => {
            if let Ok(m) = dnsproto::parse(data) {
                svc.version = m
                    .answers
                    .iter()
                    .find(|r| r.rtype == "TXT")
                    .map(|r| r.data.trim_matches('"').to_string())
                    .unwrap_or_default();
                svc.details.push(format!("version.bind: {}", m.rcode_name()));
            }
        }
        123 => {
            if let Some((stratum, refid, offset)) = parse_ntp(data, t_send, t_recv) {
                svc.version = format!("stratum {stratum}, источник {refid}");
                svc.details.push(format!("сдвиг часов относительно этого ПК: {offset:+.3} с"));
                if offset.abs() > 300.0 {
                    svc.details.push("расхождение больше 5 минут — Kerberos откажет во входе".into());
                }
            }
        }
        137 => {
            if let Some(nb) = super::discovery::parse_nbstat(data) {
                svc.version = [nb.name.clone(), nb.group.clone()].into_iter().flatten().collect::<Vec<_>>().join(" / ");
                svc.details.extend(nb.roles);
            }
        }
        161 => {
            let mut strings = Vec::new();
            ber_strings(data, &mut strings, 0);
            svc.version = strings.last().map(|s| printable(s, 160)).unwrap_or_default();
            svc.details.push(format!("отвечает с community «{}»", cfg.snmp_community));
        }
        1434 => {
            let text = String::from_utf8_lossy(data.get(3..).unwrap_or(&[]));
            let f: Vec<&str> = text.split(';').collect();
            let get = |k: &str| f.iter().position(|x| x.eq_ignore_ascii_case(k)).and_then(|i| f.get(i + 1)).map(|s| s.to_string());
            svc.version = [get("InstanceName"), get("Version")].into_iter().flatten().collect::<Vec<_>>().join(" ");
            if let Some(tcp) = get("tcp") {
                svc.details.push(format!("TCP-порт экземпляра {tcp}"));
            }
        }
        1900 => {
            let text = String::from_utf8_lossy(data);
            svc.version = text
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("SERVER")).map(|(_, v)| v.trim().to_string()))
                .unwrap_or_default();
        }
        5353 => {
            if let Ok(m) = dnsproto::parse(data) {
                let names: Vec<String> = m.answers.iter().map(|r| r.data.clone()).take(6).collect();
                svc.version = names.join(", ");
            }
        }
        _ => {}
    }
    if svc.version.is_empty() {
        svc.banner = printable(data, 120);
    }
    Some(svc)
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let targets = match super::HostList::parse(&cfg.targets) {
        Ok(t) => t,
        Err(e) => return sink.send(Event::Log(e)),
    };
    let parse = |s: &str| if s.trim().is_empty() { Ok(Vec::new()) } else { crate::targets::parse_ports(s) };
    let (tcp, udp) = match (parse(&cfg.tcp_ports), parse(&cfg.udp_ports)) {
        (Ok(t), Ok(u)) => (t, u),
        (Err(e), _) | (_, Err(e)) => return sink.send(Event::Log(e)),
    };
    // Имена разрешаем заранее.
    let mut ips: Vec<Ipv4Addr> = targets.addrs.iter().collect();
    for name in &targets.names {
        match super::resolve_v4(name, Duration::from_secs(3)).await {
            Ok(ip) => ips.push(ip),
            Err(e) => sink.send(Event::Log(e)),
        }
    }
    let mut jobs: Vec<(Ipv4Addr, u16, bool)> = Vec::new();
    for ip in &ips {
        jobs.extend(tcp.iter().map(|p| (*ip, *p, true)));
        jobs.extend(udp.iter().map(|p| (*ip, *p, false)));
    }
    let total = jobs.len() as u64;
    if total > 2_000_000 {
        return sink.send(Event::Log(format!("слишком много проверок ({total})")));
    }
    sink.send(Event::Total(total));
    let cfg = Arc::new(cfg);
    let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
    super::for_each_limited(jobs, cfg.concurrency, &cancel, |(ip, port, is_tcp)| {
        let (cfg, sink, done) = (cfg.clone(), sink.clone(), done.clone());
        async move {
            let r = if is_tcp { scan_tcp(ip, port, cfg).await } else { scan_udp(ip, port, cfg).await };
            if let Some(s) = r {
                sink.send(Event::Found(Box::new(s)));
            }
            let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if n % 32 == 0 || n == total {
                sink.send(Event::Progress(n));
            }
        }
    })
    .await;
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!("{:<21} {:<5} {:<14} {:<40} {}\n", "адрес", "proto", "сервис", "версия", "подробности");
    for v in &r.services {
        let tls = v
            .tls
            .as_ref()
            .map(|t| format!(" [{} {} до {} дн.]", t.version, t.subject, t.days_left))
            .unwrap_or_default();
        s += &format!(
            "{:<21} {:<5} {:<14} {:<40} {}{}{}\n",
            format!("{}:{}", v.ip, v.port),
            v.proto,
            if v.state == "open" { v.service.clone() } else { format!("{}?", v.service) },
            v.version.chars().take(40).collect::<String>(),
            v.details.join("; "),
            tls,
            if v.version.is_empty() && !v.banner.is_empty() { format!(" «{}»", v.banner) } else { String::new() }
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn svc() -> Service {
        Service::new(Ipv4Addr::LOCALHOST, 1, "tcp")
    }

    #[test]
    fn banners() {
        let mut s = svc();
        assert!(match_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", 22, &mut s));
        assert_eq!((s.service.as_str(), s.version.as_str()), ("ssh", "OpenSSH 9.6p1 Ubuntu-3ubuntu13"));
        let mut s = svc();
        assert!(match_banner(b"220 mail.corp.local ESMTP Postfix\r\n", 25, &mut s));
        assert_eq!(s.service, "smtp");
        let mut s = svc();
        let mysql = b"\x4a\x00\x00\x00\x0a8.0.36\x00rest";
        assert!(match_banner(mysql, 3306, &mut s));
        assert_eq!((s.service.as_str(), s.version.as_str()), ("mysql", "8.0.36"));
        let mut s = svc();
        assert!(match_banner(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n<html><title> Hello  World </title>", 80, &mut s));
        assert_eq!((s.service.as_str(), s.version.as_str()), ("http", "nginx/1.24.0"));
        assert!(s.details.contains(&"«Hello World»".to_string()));
        let mut s = svc();
        assert!(!match_banner(b"\x00\x01garbage", 9999, &mut s));
    }

    #[test]
    fn smb_and_rdp() {
        let n = smb_negotiate();
        assert_eq!(u16::from_be_bytes([n[2], n[3]]) as usize, n.len() - 4);
        let mut resp = vec![0, 0, 0, 0];
        resp.extend_from_slice(b"\xFESMB");
        resp.extend_from_slice(&[0; 60]);
        resp.extend_from_slice(&[65, 0, 0x03, 0, 0x02, 0x03, 0, 0]);
        let mut s = svc();
        assert!(parse_smb(&resp, &mut s));
        assert_eq!(s.version, "SMB 3.0.2+");
        assert!(s.details[0].contains("обязательна") && !s.details[0].contains("не "));

        let r = rdp_request();
        assert_eq!(u16::from_be_bytes([r[2], r[3]]) as usize, r.len());
        let resp = [0x03, 0, 0, 0x13, 0x0E, 0xD0, 0, 0, 0x12, 0x34, 0, 0x02, 0x1F, 0x08, 0, 0x02, 0, 0, 0];
        let mut s = svc();
        assert!(parse_rdp(&resp, &mut s));
        assert_eq!(s.version, "NLA (CredSSP)");
    }

    #[test]
    fn mssql_parse() {
        let mut resp = vec![0x04, 0x01, 0, 0x20, 0, 0, 1, 0];
        resp.extend_from_slice(&[0x00, 0x00, 0x06, 0x00, 0x06, 0xFF]);
        resp.extend_from_slice(&[15, 0, 0x07, 0xD0, 0, 0]);
        let mut s = svc();
        assert!(parse_mssql(&resp, &mut s));
        assert_eq!(s.version, "SQL Server 15.0.2000 (2019)");
        assert_eq!(mssql_prelogin().len(), 26);
    }

    #[test]
    fn snmp_and_ntp() {
        let q = snmp_get_sysdescr("public", 7);
        assert_eq!(q[0], 0x30);
        assert_eq!(q[1] as usize, q.len() - 2);
        // Ответ: те же структуры, но вместо NULL — строка.
        let mut strings = Vec::new();
        let resp = [0x30, 0x0F, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xA2, 0x05, 0x04, 0x03, b'L', b'n', b'x'];
        ber_strings(&resp, &mut strings, 0);
        assert_eq!(strings.last().unwrap(), b"Lnx");

        let mut ntp = vec![0u8; 48];
        ntp[0] = 0x24;
        ntp[1] = 2;
        ntp[12..16].copy_from_slice(&[10, 0, 0, 1]);
        let now = 1_700_000_000.0f64;
        let ntp_secs = ((now + 10.0) as u64 + 2_208_988_800) as u32;
        ntp[32..36].copy_from_slice(&ntp_secs.to_be_bytes());
        ntp[40..44].copy_from_slice(&ntp_secs.to_be_bytes());
        let (st, refid, off) = parse_ntp(&ntp, now, now).unwrap();
        assert_eq!((st, refid.as_str()), (2, "10.0.0.1"));
        assert!((off - 10.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn tcp_scan_local_services() {
        // SSH-подобный баннер.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let _ = s.write_all(b"SSH-2.0-Test_1.0\r\n").await;
            }
        });
        // HTTP-сервер, который молчит, пока не получит запрос.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b).await;
                    let _ = s.write_all(b"HTTP/1.0 200 OK\r\nServer: TestHTTP/2\r\n\r\n").await;
                });
            }
        });
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            targets: "127.0.0.1".into(),
            tcp_ports: format!("{ssh_port},{http_port}"),
            udp_ports: String::new(),
            read_timeout_ms: 800,
            ..Default::default()
        };
        run(cfg, sink, CancellationToken::new()).await;
        let found: Vec<Service> = rx
            .try_iter()
            .filter_map(|e| if let Event::Found(s) = e { Some(*s) } else { None })
            .collect();
        let ssh = found.iter().find(|s| s.port == ssh_port).unwrap();
        assert_eq!(ssh.service, "ssh");
        let http = found.iter().find(|s| s.port == http_port).unwrap();
        assert_eq!((http.service.as_str(), http.version.as_str()), ("http", "TestHTTP/2"));
    }
}
