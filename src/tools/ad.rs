//! Проверка домена Active Directory: «почему не входит в домен».
//!
//! SRV-записи (контроллеры, Kerberos, Global Catalog), доступность портов контроллеров,
//! rootDSE по LDAP без входа, ответ KDC на AS-REQ (Kerberos работает, сдвиг времени),
//! NTP, подпись SMB, сертификат LDAPS. Учётные данные не используются.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::Sink;
use super::dns;
use super::dnsproto::Query;
use super::tlsaudit::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Домен (пусто — DNS-суффикс этой машины).
    pub domain: String,
    /// Контроллеры вручную (пусто — из SRV-записей).
    pub dcs: String,
    /// DNS-серверы (`system` — серверы системы).
    pub dns_servers: String,
    pub timeout_ms: u64,
    /// Предупреждать о сдвиге часов больше N секунд (Kerberos допускает 300).
    pub skew_warn_s: f64,
    pub check_ldaps: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            domain: String::new(),
            dcs: String::new(),
            dns_servers: "system".into(),
            timeout_ms: 3000,
            skew_warn_s: 60.0,
            check_ldaps: true,
        }
    }
}

/// SRV-записи, которые ищет клиент Windows при входе.
pub const SRV_NAMES: &[(&str, &str)] = &[
    ("_ldap._tcp.dc._msdcs.", "контроллеры домена"),
    ("_kerberos._tcp.", "Kerberos (TCP)"),
    ("_kerberos._udp.", "Kerberos (UDP)"),
    ("_kpasswd._tcp.", "смена пароля"),
    ("_gc._tcp.", "Global Catalog"),
    ("_ldap._tcp.pdc._msdcs.", "эмулятор PDC"),
];

/// Порты контроллера: (порт, протокол, назначение, обязателен для входа).
pub const DC_PORTS: &[(u16, &str, &str, bool)] = &[
    (53, "tcp", "DNS", false),
    (88, "tcp", "Kerberos", true),
    (135, "tcp", "RPC", true),
    (389, "tcp", "LDAP", true),
    (445, "tcp", "SMB (SYSVOL, политики)", true),
    (464, "tcp", "смена пароля Kerberos", false),
    (636, "tcp", "LDAPS", false),
    (3268, "tcp", "Global Catalog", false),
    (3269, "tcp", "Global Catalog SSL", false),
    (9389, "tcp", "AD Web Services", false),
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SrvResult {
    pub name: String,
    pub purpose: String,
    /// «приоритет вес порт узел».
    pub records: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortCheck {
    pub port: u16,
    pub purpose: String,
    pub required: bool,
    pub open: bool,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KdcCheck {
    pub transport: String,
    pub ok: bool,
    /// Код ошибки Kerberos и его смысл (ответ на запрос несуществующего пользователя).
    pub code: Option<i64>,
    pub text: String,
    /// Сдвиг часов KDC относительно этого ПК, секунды.
    pub skew_s: Option<f64>,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dc {
    pub host: String,
    pub ip: Option<IpAddr>,
    pub ptr: Option<String>,
    pub ports: Vec<PortCheck>,
    /// Атрибуты rootDSE.
    pub root_dse: BTreeMap<String, Vec<String>>,
    pub ldap_error: Option<String>,
    pub kdc: Vec<KdcCheck>,
    pub ntp_skew_s: Option<f64>,
    pub ldap_skew_s: Option<f64>,
    pub smb: Option<String>,
    pub smb_signing_required: Option<bool>,
    pub ldaps: Option<super::tls::TlsInfo>,
    pub ldaps_error: Option<String>,
}

impl Dc {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.root_dse
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.first())
            .map(String::as_str)
    }

    /// Лучшая оценка сдвига часов: NTP, иначе Kerberos, иначе LDAP.
    pub fn skew(&self) -> Option<(f64, &'static str)> {
        self.ntp_skew_s
            .map(|s| (s, "NTP"))
            .or_else(|| self.kdc.iter().find_map(|k| k.skew_s).map(|s| (s, "Kerberos")))
            .or(self.ldap_skew_s.map(|s| (s, "LDAP")))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub domain: String,
    pub realm: String,
    pub dns_servers: Vec<String>,
    pub srv: Vec<SrvResult>,
    pub dcs: Vec<Dc>,
    pub findings: Vec<Finding>,
    /// Короткий итог.
    pub verdict: String,
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Report(Box<Report>),
}

// ---------------------------------------------------------------------------
// BER/DER
// ---------------------------------------------------------------------------

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n < 0x10000 {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

pub fn der_int(v: i64) -> Vec<u8> {
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0)) {
        bytes.remove(0);
    }
    tlv(0x02, &bytes)
}

/// Разбор одного элемента: (тег, содержимое, остаток).
pub fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let first = *data.get(1)? as usize;
    let (len, hdr) = if first & 0x80 == 0 {
        (first, 2)
    } else {
        let n = first & 0x7F;
        if n == 0 || n > 4 {
            return None;
        }
        let len = data.get(2..2 + n)?.iter().fold(0usize, |a, b| (a << 8) | *b as usize);
        (len, 2 + n)
    };
    let content = data.get(hdr..hdr + len)?;
    Some((tag, content, &data[hdr + len..]))
}

fn read_int(content: &[u8]) -> i64 {
    let mut v: i64 = if content.first().is_some_and(|b| b & 0x80 != 0) { -1 } else { 0 };
    for b in content {
        v = (v << 8) | *b as i64;
    }
    v
}

/// Обход всех элементов (рекурсивно в составных).
fn walk<'a>(data: &'a [u8], out: &mut Vec<(u8, &'a [u8], usize)>, depth: usize) {
    let mut rest = data;
    while let Some((tag, content, tail)) = read_tlv(rest) {
        out.push((tag, content, depth));
        if tag & 0x20 != 0 && depth < 16 {
            walk(content, out, depth + 1);
        }
        rest = tail;
    }
}

// ---------------------------------------------------------------------------
// LDAP rootDSE
// ---------------------------------------------------------------------------

pub const ROOT_DSE_ATTRS: &[&str] = &[
    "defaultNamingContext",
    "rootDomainNamingContext",
    "dnsHostName",
    "serverName",
    "ldapServiceName",
    "currentTime",
    "isSynchronized",
    "isGlobalCatalogReady",
    "domainFunctionality",
    "forestFunctionality",
    "domainControllerFunctionality",
    "supportedLDAPVersion",
    "supportedSASLMechanisms",
];

pub fn root_dse_request(id: i64) -> Vec<u8> {
    let mut sr = tlv(0x04, b"");
    sr.extend(tlv(0x0A, &[0])); // scope: baseObject
    sr.extend(tlv(0x0A, &[0])); // derefAliases: never
    sr.extend(der_int(0));
    sr.extend(der_int(0));
    sr.extend(tlv(0x01, &[0])); // typesOnly
    sr.extend(tlv(0x87, b"objectClass")); // present
    let attrs: Vec<u8> = ROOT_DSE_ATTRS.iter().flat_map(|a| tlv(0x04, a.as_bytes())).collect();
    sr.extend(tlv(0x30, &attrs));
    let mut msg = der_int(id);
    msg.extend(tlv(0x63, &sr));
    tlv(0x30, &msg)
}

/// Атрибуты из SearchResultEntry.
pub fn parse_search_entry(data: &[u8]) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut rest = data;
    let mut attrs = BTreeMap::new();
    while let Some((tag, content, tail)) = read_tlv(rest) {
        rest = tail;
        if tag != 0x30 {
            continue;
        }
        let Some((_, _id, op)) = read_tlv(content) else { continue };
        let Some((op_tag, body, _)) = read_tlv(op) else { continue };
        match op_tag {
            0x64 => {
                let (_, _dn, after) = read_tlv(body).ok_or("ответ LDAP не разобран")?;
                let (_, list, _) = read_tlv(after).ok_or("ответ LDAP не разобран")?;
                let mut items = list;
                while let Some((_, attr, tail)) = read_tlv(items) {
                    items = tail;
                    let Some((_, name, vals_rest)) = read_tlv(attr) else { continue };
                    let Some((_, vals, _)) = read_tlv(vals_rest) else { continue };
                    let mut v = Vec::new();
                    let mut vr = vals;
                    while let Some((_, val, t)) = read_tlv(vr) {
                        v.push(String::from_utf8_lossy(val).into_owned());
                        vr = t;
                    }
                    attrs.insert(String::from_utf8_lossy(name).into_owned(), v);
                }
            }
            0x65 => {
                // SearchResultDone: код результата.
                if let Some((_, code, _)) = read_tlv(body) {
                    let c = read_int(code);
                    if c != 0 && attrs.is_empty() {
                        return Err(format!("LDAP: код результата {c}"));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(attrs)
}

/// Время в формате GeneralizedTime (`20261119153012.0Z`) → секунды Unix.
pub fn generalized_time(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.len() < 14 {
        return None;
    }
    let n = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0, 4)?, n(4, 6)?, n(6, 8)?, n(8, 10)?, n(10, 12)?, n(12, 14)?);
    // Дни от эпохи (алгоритм Howard Hinnant, обратный civil_from_days).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let frac = s[14..].trim_end_matches('Z').trim_start_matches('.').parse::<f64>().ok().map(|f| {
        let digits = s[14..].trim_end_matches('Z').trim_start_matches('.').len() as i32;
        f / 10f64.powi(digits)
    });
    Some((days * 86400 + h * 3600 + mi * 60 + se) as f64 + frac.unwrap_or(0.0))
}

async fn ldap_root_dse(addr: SocketAddr, timeout: Duration) -> Result<(BTreeMap<String, Vec<String>>, f64), String> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| "LDAP: нет подключения".to_string())?
        .map_err(|e| format!("LDAP: {e}"))?;
    tokio::time::timeout(timeout, s.write_all(&root_dse_request(1)))
        .await
        .map_err(|_| "LDAP: таймаут".to_string())?
        .map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    let mut buf = vec![0u8; 16384];
    loop {
        let n = match tokio::time::timeout(timeout, s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        data.extend_from_slice(&buf[..n]);
        // Ждём SearchResultDone.
        let mut items = Vec::new();
        walk(&data, &mut items, 0);
        if items.iter().any(|(t, _, d)| *t == 0x65 && *d == 1) || data.len() > 1 << 20 {
            break;
        }
    }
    let now = unix_now();
    let attrs = parse_search_entry(&data)?;
    if attrs.is_empty() {
        return Err("LDAP: rootDSE пуст или недоступен без входа".into());
    }
    Ok((attrs, now))
}

// ---------------------------------------------------------------------------
// Kerberos
// ---------------------------------------------------------------------------

fn kstr(s: &str) -> Vec<u8> {
    tlv(0x1B, s.as_bytes())
}

fn principal(name_type: i64, parts: &[&str]) -> Vec<u8> {
    let mut seq = tlv(0xA0, &der_int(name_type));
    let names: Vec<u8> = parts.iter().flat_map(|p| kstr(p)).collect();
    seq.extend(tlv(0xA1, &tlv(0x30, &names)));
    tlv(0x30, &seq)
}

/// AS-REQ для заведомо несуществующего пользователя: KDC отвечает KRB-ERROR
/// (обычно «пользователь не найден»), в котором есть время сервера.
pub fn as_req(realm: &str, nonce: u32) -> Vec<u8> {
    let mut body = tlv(0xA0, &tlv(0x03, &[0, 0x40, 0x81, 0x00, 0x10])); // forwardable, renewable, canonicalize, renewable-ok
    body.extend(tlv(0xA1, &principal(1, &["proxy-scanner-probe-nonexistent"])));
    body.extend(tlv(0xA2, &kstr(realm)));
    body.extend(tlv(0xA3, &principal(2, &["krbtgt", realm])));
    body.extend(tlv(0xA5, &tlv(0x18, b"20370913024805Z")));
    body.extend(tlv(0xA7, &der_int(nonce as i64)));
    let etypes: Vec<u8> = [18i64, 17, 23].iter().flat_map(|e| der_int(*e)).collect();
    body.extend(tlv(0xA8, &tlv(0x30, &etypes)));
    let mut req = tlv(0xA1, &der_int(5));
    req.extend(tlv(0xA2, &der_int(10)));
    req.extend(tlv(0xA4, &tlv(0x30, &body)));
    tlv(0x6A, &tlv(0x30, &req))
}

pub fn krb_error_text(code: i64) -> &'static str {
    match code {
        6 => "KDC отвечает (пользователь не найден — ожидаемо)",
        7 => "сервис krbtgt не найден",
        14 => "нет общих алгоритмов шифрования",
        24 => "ошибка предварительной аутентификации",
        25 => "KDC отвечает (требуется предварительная аутентификация)",
        37 => "слишком большой сдвиг часов (KRB_AP_ERR_SKEW)",
        41 => "контрольная сумма не совпадает",
        52 => "ответ не помещается в UDP — нужен TCP",
        60 => "общая ошибка KDC",
        68 => "неверная область (realm)",
        _ => "ошибка Kerberos",
    }
}

/// Разбор ответа KDC: (код ошибки или None для AS-REP, время сервера).
pub fn parse_krb(data: &[u8]) -> Option<(Option<i64>, Option<f64>)> {
    let (tag, content, _) = read_tlv(data)?;
    match tag {
        0x6B => Some((None, None)),
        0x7E => {
            let (_, seq, _) = read_tlv(content)?;
            let mut code = None;
            let mut stime = None;
            let mut rest = seq;
            while let Some((t, c, tail)) = read_tlv(rest) {
                match t {
                    0xA4 => {
                        if let Some((_, v, _)) = read_tlv(c) {
                            stime = generalized_time(&String::from_utf8_lossy(v));
                        }
                    }
                    0xA6 => {
                        if let Some((_, v, _)) = read_tlv(c) {
                            code = Some(read_int(v));
                        }
                    }
                    _ => {}
                }
                rest = tail;
            }
            Some((code, stime))
        }
        _ => None,
    }
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

async fn kdc_check(ip: IpAddr, realm: &str, tcp: bool, timeout: Duration) -> KdcCheck {
    let mut k = KdcCheck {
        transport: if tcp { "TCP" } else { "UDP" }.into(),
        ..Default::default()
    };
    let req = as_req(realm, (unix_now() as u64 & 0x7FFF_FFFF) as u32);
    let started = Instant::now();
    let res: Result<Vec<u8>, String> = async {
        if tcp {
            let mut s = tokio::time::timeout(timeout, TcpStream::connect((ip, 88)))
                .await
                .map_err(|_| "нет подключения".to_string())?
                .map_err(|e| e.to_string())?;
            let mut framed = (req.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&req);
            s.write_all(&framed).await.map_err(|e| e.to_string())?;
            let mut len = [0u8; 4];
            tokio::time::timeout(timeout, s.read_exact(&mut len))
                .await
                .map_err(|_| "нет ответа".to_string())?
                .map_err(|e| e.to_string())?;
            let n = (u32::from_be_bytes(len) as usize).min(1 << 20);
            let mut buf = vec![0u8; n];
            tokio::time::timeout(timeout, s.read_exact(&mut buf))
                .await
                .map_err(|_| "ответ обрезан".to_string())?
                .map_err(|e| e.to_string())?;
            Ok(buf)
        } else {
            let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let s = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
            s.connect((ip, 88)).await.map_err(|e| e.to_string())?;
            s.send(&req).await.map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 8192];
            let n = tokio::time::timeout(timeout, s.recv(&mut buf))
                .await
                .map_err(|_| "нет ответа".to_string())?
                .map_err(|e| e.to_string())?;
            buf.truncate(n);
            Ok(buf)
        }
    }
    .await;
    let now = unix_now();
    k.rtt_ms = Some(super::ms_f(started.elapsed()));
    match res {
        Ok(data) => match parse_krb(&data) {
            Some((code, stime)) => {
                k.code = code;
                k.ok = matches!(code, Some(6) | Some(25) | Some(24) | Some(52) | None);
                k.text = code.map(krb_error_text).unwrap_or("получен AS-REP").to_string();
                k.skew_s = stime.map(|t| t - now);
            }
            None => k.text = "ответ не похож на Kerberos".into(),
        },
        Err(e) => {
            k.text = e;
            k.rtt_ms = None;
        }
    }
    k
}

async fn ntp_skew(ip: IpAddr, timeout: Duration) -> Option<f64> {
    let s = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await.ok()?;
    s.connect((ip, 123)).await.ok()?;
    let mut p = vec![0u8; 48];
    p[0] = 0x1B;
    let t1 = unix_now();
    s.send(&p).await.ok()?;
    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(timeout, s.recv(&mut buf)).await.ok()?.ok()?;
    let t4 = unix_now();
    super::services::parse_ntp(&buf[..n], t1, t4).map(|x| x.2)
}

async fn smb_signing(ip: IpAddr, timeout: Duration) -> Option<(String, bool)> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect((ip, 445))).await.ok()?.ok()?;
    s.write_all(&super::services::smb_negotiate()).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, s.read(&mut buf)).await.ok()?.ok()?;
    let mut svc = super::services::Service {
        ip: std::net::Ipv4Addr::UNSPECIFIED,
        port: 445,
        proto: "tcp".into(),
        state: String::new(),
        service: String::new(),
        version: String::new(),
        tls: None,
        banner: String::new(),
        details: Vec::new(),
        rtt_ms: None,
    };
    if !super::services::parse_smb(&buf[..n], &mut svc) {
        return None;
    }
    let required = svc.details.iter().any(|d| d.contains("обязательна") && !d.contains("не обязательна"));
    Some((svc.version, required))
}

async fn port_check(ip: IpAddr, port: u16, purpose: &str, required: bool, timeout: Duration) -> PortCheck {
    let started = Instant::now();
    let r = tokio::time::timeout(timeout, super::connect_fast(SocketAddr::new(ip, port))).await;
    let (open, error) = match r {
        Ok(Ok(_)) => (true, None),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => (false, Some("отказ (RST)".to_string())),
        Ok(Err(e)) => (false, Some(e.to_string())),
        Err(_) => (false, Some("нет ответа (фильтруется?)".to_string())),
    };
    PortCheck {
        port,
        purpose: purpose.into(),
        required,
        open,
        rtt_ms: open.then(|| super::ms_f(started.elapsed())),
        error,
    }
}

async fn check_dc(host: String, ip: Option<IpAddr>, realm: Arc<String>, cfg: Arc<Config>) -> Dc {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(300));
    let mut dc = Dc {
        host: host.clone(),
        ip,
        ..Default::default()
    };
    let ip = match ip {
        Some(ip) => ip,
        None => match super::resolve(&host, timeout).await {
            Ok(ip) => {
                dc.ip = Some(ip);
                ip
            }
            Err(e) => {
                dc.ldap_error = Some(format!("адрес контроллера не разрешился: {e}"));
                return dc;
            }
        },
    };
    let ports = futures_all(DC_PORTS.iter().map(|(p, _, purpose, req)| port_check(ip, *p, purpose, *req, timeout)).collect()).await;
    dc.ports = ports;
    let port_open = |p: u16| dc.ports.iter().any(|x| x.port == p && x.open);
    let (ldap, kdc_udp, kdc_tcp, ntp, smb, ptr) = tokio::join!(
        async {
            if port_open(389) { Some(ldap_root_dse(SocketAddr::new(ip, 389), timeout).await) } else { None }
        },
        kdc_check(ip, &realm, false, timeout),
        async {
            if port_open(88) { Some(kdc_check(ip, &realm, true, timeout).await) } else { None }
        },
        ntp_skew(ip, timeout),
        async {
            if port_open(445) { smb_signing(ip, timeout).await } else { None }
        },
        dns::reverse_lookup(ip, timeout)
    );
    dc.ptr = ptr;
    match ldap {
        Some(Ok((attrs, t))) => {
            dc.ldap_skew_s = attrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("currentTime"))
                .and_then(|(_, v)| v.first())
                .and_then(|v| generalized_time(v))
                .map(|dt| dt - t);
            dc.root_dse = attrs;
        }
        Some(Err(e)) => dc.ldap_error = Some(e),
        None => dc.ldap_error = Some("порт 389 недоступен".into()),
    }
    dc.kdc.push(kdc_udp);
    if let Some(k) = kdc_tcp {
        dc.kdc.push(k);
    }
    dc.ntp_skew_s = ntp;
    if let Some((ver, req)) = smb {
        dc.smb = Some(ver);
        dc.smb_signing_required = Some(req);
    }
    if cfg.check_ldaps && port_open(636) {
        match tokio::time::timeout(timeout, TcpStream::connect((ip, 636))).await {
            Ok(Ok(s)) => {
                let sni = dc.attr("dnsHostName").map(String::from).unwrap_or(host.clone());
                match super::tls::handshake(s, &sni, super::tls::Versions::Auto, &[], timeout).await {
                    Ok((_, info)) => dc.ldaps = Some(info),
                    Err(e) => dc.ldaps_error = Some(e),
                }
            }
            _ => dc.ldaps_error = Some("нет подключения".into()),
        }
    }
    dc
}

async fn futures_all<F: std::future::Future + Send + 'static>(futs: Vec<F>) -> Vec<F::Output>
where
    F::Output: Send + 'static,
{
    let handles: Vec<_> = futs.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::new();
    for h in handles {
        if let Ok(v) = h.await {
            out.push(v);
        }
    }
    out
}

pub fn evaluate(r: &mut Report, cfg: &Config) {
    let mut f = Vec::new();
    let mut push = |s: Severity, t: String| f.push(Finding { severity: s, text: t });
    if r.dcs.is_empty() {
        let why = r
            .srv
            .iter()
            .find(|s| s.name.starts_with("_ldap._tcp.dc"))
            .and_then(|s| s.error.clone())
            .map(|e| format!(" ({e})"))
            .unwrap_or_default();
        push(
            Severity::High,
            format!("контроллеры не найдены: нет SRV-записи _ldap._tcp.dc._msdcs.{}{why} — проверьте DNS-серверы и имя домена", r.domain),
        );
    }
    for s in &r.srv {
        if s.records.is_empty() && s.name.starts_with("_ldap._tcp.dc") {
            continue;
        } else if s.records.is_empty() && (s.name.starts_with("_kerberos._tcp") || s.name.starts_with("_gc")) {
            push(Severity::Medium, format!("нет записей {} — {}", s.name, s.purpose));
        }
    }
    let mut reachable = 0;
    for dc in &r.dcs {
        let name = &dc.host;
        let missing: Vec<String> = dc
            .ports
            .iter()
            .filter(|p| p.required && !p.open)
            .map(|p| format!("{} ({})", p.port, p.purpose))
            .collect();
        if dc.ip.is_none() {
            push(Severity::High, format!("{name}: адрес не разрешается"));
            continue;
        }
        if missing.len() == dc.ports.iter().filter(|p| p.required).count() {
            push(Severity::High, format!("{name}: контроллер недоступен ни по одному обязательному порту"));
            continue;
        }
        reachable += 1;
        if !missing.is_empty() {
            push(Severity::High, format!("{name}: закрыты порты, нужные для входа: {}", missing.join(", ")));
        }
        if !dc.kdc.iter().any(|k| k.ok) {
            let why = dc.kdc.iter().map(|k| format!("{}: {}", k.transport, k.text)).collect::<Vec<_>>().join("; ");
            push(Severity::High, format!("{name}: KDC не отвечает корректно ({why})"));
        }
        if dc.kdc.iter().any(|k| k.code == Some(68)) {
            push(Severity::High, format!("{name}: KDC не знает область {} — неверное имя домена", r.realm));
        }
        if let Some((skew, src)) = dc.skew() {
            if skew.abs() > 300.0 {
                push(Severity::High, format!("{name}: часы расходятся на {skew:+.0} с ({src}) — больше 5 минут, Kerberos откажет во входе"));
            } else if skew.abs() > cfg.skew_warn_s {
                push(Severity::Medium, format!("{name}: часы расходятся на {skew:+.0} с ({src})"));
            }
        }
        if dc.attr("isSynchronized").is_some_and(|v| v.eq_ignore_ascii_case("FALSE")) {
            push(Severity::Medium, format!("{name}: контроллер не завершил синхронизацию (isSynchronized = FALSE)"));
        }
        if dc.smb_signing_required == Some(false) {
            push(Severity::High, format!("{name}: подпись SMB не обязательна (риск NTLM relay)"));
        }
        if let Some(t) = &dc.ldaps {
            if let Some(e) = &t.trust_error {
                push(Severity::Medium, format!("{name}: сертификат LDAPS не доверен ({e})"));
            }
            if let Some(leaf) = t.chain.first()
                && leaf.days_left < 30
            {
                push(
                    if leaf.days_left < 0 { Severity::High } else { Severity::Medium },
                    format!("{name}: сертификат LDAPS {} ({} дн.)", if leaf.days_left < 0 { "просрочен" } else { "скоро истекает" }, leaf.days_left),
                );
            }
        } else if dc.ports.iter().any(|p| p.port == 636 && !p.open) {
            push(Severity::Low, format!("{name}: LDAPS (636) недоступен"));
        }
        if let (Some(ptr), Some(dns)) = (&dc.ptr, dc.attr("dnsHostName"))
            && !ptr.eq_ignore_ascii_case(dns)
        {
            push(Severity::Low, format!("{name}: обратная запись {ptr} не совпадает с именем {dns}"));
        }
    }
    f.sort_by_key(|x| x.severity);
    let high = f.iter().filter(|x| x.severity == Severity::High).count();
    r.verdict = if r.dcs.is_empty() {
        "Контроллеры не найдены — вход в домен невозможен".into()
    } else if reachable == 0 {
        "Ни один контроллер не доступен".into()
    } else if high > 0 {
        format!("Найдены проблемы ({high} серьёзных) — см. список")
    } else {
        format!("Домен доступен: контроллеров {reachable}, Kerberos и LDAP отвечают")
    };
    r.findings = f;
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(300));
    let domain = if cfg.domain.trim().is_empty() {
        match tokio::task::spawn_blocking(dns::system_domain).await.ok().flatten() {
            Some(d) => d,
            None => return sink.send(Event::Log("домен не задан, а DNS-суффикс системы не определён".into())),
        }
    } else {
        cfg.domain.trim().to_string()
    };
    let domain = domain.trim_matches('.').to_ascii_lowercase();
    let mut report = Report {
        realm: domain.to_ascii_uppercase(),
        domain: domain.clone(),
        ..Default::default()
    };
    let dns_cfg = dns::Config {
        servers: cfg.dns_servers.clone(),
        ..Default::default()
    };
    let servers = match tokio::task::spawn_blocking(move || dns::expand_servers(&dns_cfg)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return sink.send(Event::Log(e)),
        Err(e) => return sink.send(Event::Log(e.to_string())),
    };
    report.dns_servers = servers.iter().map(|s| s.label.clone()).collect();
    sink.send(Event::Log(format!("домен {domain}, DNS: {}", report.dns_servers.join(", "))));

    // SRV-записи (первый ответивший сервер).
    let mut dc_hosts: Vec<(String, Option<IpAddr>)> = Vec::new();
    for (prefix, purpose) in SRV_NAMES {
        if cancel.is_cancelled() {
            return;
        }
        let name = format!("{prefix}{domain}");
        let mut res = SrvResult {
            name: name.clone(),
            purpose: purpose.to_string(),
            ..Default::default()
        };
        for server in &servers {
            let a = dns::query(server, &Query::new(dns::rand_id(), &name, 33), timeout, 1).await;
            if let Some(e) = a.error {
                res.error = Some(format!("{}: {e}", server.label));
                continue;
            }
            res.error = (a.rcode != "NOERROR").then(|| a.rcode.clone());
            res.records = a.answers.iter().filter(|r| r.rtype == "SRV").map(|r| r.data.clone()).collect();
            if prefix.starts_with("_ldap._tcp.dc") {
                for rec in &res.records {
                    if let Some(h) = rec.split_whitespace().nth(3) {
                        let h = h.trim_end_matches('.').to_string();
                        let ip = a
                            .additional
                            .iter()
                            .find(|x| x.rtype == "A" && x.name.trim_end_matches('.').eq_ignore_ascii_case(&h))
                            .and_then(|x| x.data.parse().ok());
                        if !dc_hosts.iter().any(|(x, _)| x.eq_ignore_ascii_case(&h)) {
                            dc_hosts.push((h, ip));
                        }
                    }
                }
            }
            break;
        }
        report.srv.push(res);
    }
    let manual = super::split_list(&cfg.dcs);
    if !manual.is_empty() {
        dc_hosts = manual.into_iter().map(|h| (h.clone(), h.parse().ok())).collect();
    }
    sink.send(Event::Log(format!("контроллеров: {}", dc_hosts.len())));
    let realm = Arc::new(report.realm.clone());
    let cfg2 = Arc::new(cfg.clone());
    let futs: Vec<_> = dc_hosts
        .into_iter()
        .take(16)
        .map(|(h, ip)| check_dc(h, ip, realm.clone(), cfg2.clone()))
        .collect();
    let dcs = tokio::select! {
        d = futures_all(futs) => d,
        _ = cancel.cancelled() => return,
    };
    report.dcs = dcs;
    evaluate(&mut report, &cfg);
    sink.send(Event::Report(Box::new(report)));
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!("Домен {} (область {}) — {}\nDNS: {}\n\n", r.domain, r.realm, r.verdict, r.dns_servers.join(", "));
    for f in &r.findings {
        s += &format!("! [{}] {}\n", f.severity.label(), f.text);
    }
    s += "\nSRV-записи:\n";
    for x in &r.srv {
        s += &format!(
            "  {:<44} {}\n",
            x.name,
            if x.records.is_empty() { x.error.clone().unwrap_or("нет".into()) } else { x.records.join("; ") }
        );
    }
    for dc in &r.dcs {
        s += &format!(
            "\n== {} ({}){}\n",
            dc.host,
            dc.ip.map(|i| i.to_string()).unwrap_or("?".into()),
            dc.ptr.as_ref().map(|p| format!(" PTR {p}")).unwrap_or_default()
        );
        let ports: Vec<String> = dc.ports.iter().map(|p| format!("{}{}", p.port, if p.open { "+" } else { "-" })).collect();
        s += &format!("   порты: {}\n", ports.join(" "));
        for k in &dc.kdc {
            s += &format!("   Kerberos/{}: {}{}\n", k.transport, k.text, k.code.map(|c| format!(" (код {c})")).unwrap_or_default());
        }
        if let Some((sk, src)) = dc.skew() {
            s += &format!("   сдвиг часов: {sk:+.1} с ({src})\n");
        }
        for a in ["dnsHostName", "defaultNamingContext", "domainControllerFunctionality", "isSynchronized", "isGlobalCatalogReady"] {
            if let Some(v) = dc.attr(a) {
                s += &format!("   {a}: {v}\n");
            }
        }
        if let Some(e) = &dc.ldap_error {
            s += &format!("   LDAP: {e}\n");
        }
        if let Some(v) = &dc.smb {
            s += &format!(
                "   SMB: {v}, подпись {}\n",
                if dc.smb_signing_required == Some(true) { "обязательна" } else { "не обязательна" }
            );
        }
        if let Some(t) = &dc.ldaps {
            s += &format!(
                "   LDAPS: {} {} — {}\n",
                t.version,
                t.chain.first().map(|c| format!("{} до {}", c.short_subject(), c.not_after)).unwrap_or_default(),
                t.trust_error.clone().unwrap_or("доверен".into())
            );
        }
    }
    s
}

/// Уровень функциональности домена/леса.
pub fn functional_level(v: &str) -> &'static str {
    match v.trim() {
        "0" => "Windows 2000",
        "1" => "Windows 2003 interim",
        "2" => "Windows Server 2003",
        "3" => "Windows Server 2008",
        "4" => "Windows Server 2008 R2",
        "5" => "Windows Server 2012",
        "6" => "Windows Server 2012 R2",
        "7" => "Windows Server 2016",
        "10" => "Windows Server 2025",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_basics() {
        assert_eq!(der_int(5), vec![2, 1, 5]);
        assert_eq!(der_int(128), vec![2, 2, 0, 128]);
        assert_eq!(der_int(-1), vec![2, 1, 0xFF]);
        let long = tlv(0x04, &[7u8; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2C]);
        let (t, c, rest) = read_tlv(&long).unwrap();
        assert_eq!((t, c.len(), rest.len()), (4, 300, 0));
        assert_eq!(read_int(&[0x01, 0x00]), 256);
        assert_eq!(read_int(&[0xFF]), -1);
    }

    #[test]
    fn time_parsing() {
        assert_eq!(generalized_time("19700101000000Z"), Some(0.0));
        assert_eq!(generalized_time("20231114221320Z"), Some(1_700_000_000.0));
        assert_eq!(generalized_time("20231114221320.5Z"), Some(1_700_000_000.5));
        assert_eq!(generalized_time("garbage"), None);
    }

    #[test]
    fn as_req_structure() {
        let r = as_req("CORP.LOCAL", 12345);
        let (tag, content, rest) = read_tlv(&r).unwrap();
        assert_eq!((tag, rest.len()), (0x6A, 0));
        let mut items = Vec::new();
        walk(content, &mut items, 0);
        let strings: Vec<String> = items.iter().filter(|(t, _, _)| *t == 0x1B).map(|(_, c, _)| String::from_utf8_lossy(c).into_owned()).collect();
        assert_eq!(strings, vec!["proxy-scanner-probe-nonexistent", "CORP.LOCAL", "krbtgt", "CORP.LOCAL"]);
    }

    #[test]
    fn krb_error_parse() {
        let mut seq = tlv(0xA0, &der_int(5));
        seq.extend(tlv(0xA1, &der_int(30)));
        seq.extend(tlv(0xA4, &tlv(0x18, b"20231114221320Z")));
        seq.extend(tlv(0xA5, &der_int(0)));
        seq.extend(tlv(0xA6, &der_int(6)));
        seq.extend(tlv(0xA9, &kstr("CORP.LOCAL")));
        let msg = tlv(0x7E, &tlv(0x30, &seq));
        assert_eq!(parse_krb(&msg), Some((Some(6), Some(1_700_000_000.0))));
        assert_eq!(parse_krb(&tlv(0x6B, &[])), Some((None, None)));
        assert_eq!(parse_krb(b"junk"), None);
    }

    #[test]
    fn root_dse_roundtrip() {
        let req = root_dse_request(1);
        let (t, _, _) = read_tlv(&req).unwrap();
        assert_eq!(t, 0x30);
        // Ответ: SearchResultEntry с двумя атрибутами + SearchResultDone.
        let attr = |name: &str, vals: &[&str]| {
            let mut a = tlv(0x04, name.as_bytes());
            let v: Vec<u8> = vals.iter().flat_map(|x| tlv(0x04, x.as_bytes())).collect();
            a.extend(tlv(0x31, &v));
            tlv(0x30, &a)
        };
        let mut list = attr("dnsHostName", &["dc01.corp.local"]);
        list.extend(attr("supportedLDAPVersion", &["3", "2"]));
        let mut entry = tlv(0x04, b"");
        entry.extend(tlv(0x30, &list));
        let mut m1 = der_int(1);
        m1.extend(tlv(0x64, &entry));
        let mut done_body = tlv(0x0A, &[0]);
        done_body.extend(tlv(0x04, b""));
        done_body.extend(tlv(0x04, b""));
        let mut m2 = der_int(1);
        m2.extend(tlv(0x65, &done_body));
        let mut data = tlv(0x30, &m1);
        data.extend(tlv(0x30, &m2));
        let attrs = parse_search_entry(&data).unwrap();
        assert_eq!(attrs["dnsHostName"], vec!["dc01.corp.local"]);
        assert_eq!(attrs["supportedLDAPVersion"], vec!["3", "2"]);
    }

    #[test]
    fn evaluation() {
        let mut r = Report {
            realm: "CORP.LOCAL".into(),
            ..Default::default()
        };
        evaluate(&mut r, &Config::default());
        assert!(r.findings[0].text.contains("не найдены"));
        let mut dc = Dc {
            host: "dc01".into(),
            ip: Some("10.0.0.1".parse().unwrap()),
            ports: DC_PORTS
                .iter()
                .map(|(p, _, purpose, req)| PortCheck { port: *p, purpose: purpose.to_string(), required: *req, open: true, ..Default::default() })
                .collect(),
            kdc: vec![KdcCheck { ok: true, code: Some(6), skew_s: Some(400.0), ..Default::default() }],
            smb_signing_required: Some(true),
            ..Default::default()
        };
        dc.ports.iter_mut().find(|p| p.port == 445).unwrap().open = false;
        r.dcs = vec![dc];
        evaluate(&mut r, &Config::default());
        let texts: Vec<&str> = r.findings.iter().map(|f| f.text.as_str()).collect();
        assert!(texts.iter().any(|t| t.contains("445")), "{texts:?}");
        assert!(texts.iter().any(|t| t.contains("больше 5 минут")), "{texts:?}");
    }
}
