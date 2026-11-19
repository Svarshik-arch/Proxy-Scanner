//! TLS-аудит в духе testssl/sslscan: поддерживаемые версии протокола (от SSL 3.0 до
//! TLS 1.3), перебор наборов шифров собственным ClientHello, цепочка сертификатов,
//! проверка по системным корням и итоговая оценка.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::Sink;
use super::tls::{CertDetail, Versions};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub targets: String,
    pub ports: String,
    /// Имя для SNI (пусто — имя из списка целей; для IP-адресов SNI не отправляется).
    pub sni: String,
    pub versions: bool,
    pub ciphers: bool,
    pub timeout_ms: u64,
    pub concurrency: usize,
    /// Предупреждать, если до окончания сертификата меньше N дней.
    pub expiry_warn_days: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: String::new(),
            ports: "443".into(),
            sni: String::new(),
            versions: true,
            ciphers: true,
            timeout_ms: 4000,
            concurrency: 8,
            expiry_warn_days: 30,
        }
    }
}

pub const SSL3: u16 = 0x0300;
pub const TLS10: u16 = 0x0301;
pub const TLS11: u16 = 0x0302;
pub const TLS12: u16 = 0x0303;
pub const TLS13: u16 = 0x0304;

pub fn version_name(v: u16) -> &'static str {
    match v {
        SSL3 => "SSL 3.0",
        TLS10 => "TLS 1.0",
        TLS11 => "TLS 1.1",
        TLS12 => "TLS 1.2",
        TLS13 => "TLS 1.3",
        _ => "?",
    }
}

/// Наборы шифров (код IANA, имя). Включены устаревшие — именно их и ищем.
pub const CIPHERS: &[(u16, &str)] = &[
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0x1304, "TLS_AES_128_CCM_SHA256"),
    (0x1305, "TLS_AES_128_CCM_8_SHA256"),
    (0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    (0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    (0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
    (0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
    (0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
    (0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
    (0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    (0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    (0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    (0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    (0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
    (0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    (0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    (0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    (0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    (0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    (0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
    (0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    (0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"),
    (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
    (0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    (0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    (0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"),
    (0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"),
    (0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
    (0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
    (0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
    (0x0009, "TLS_RSA_WITH_DES_CBC_SHA"),
    (0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
    (0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
    (0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    (0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    (0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"),
    (0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"),
    (0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"),
    (0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"),
    (0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"),
    (0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"),
    (0x0001, "TLS_RSA_WITH_NULL_MD5"),
    (0x0002, "TLS_RSA_WITH_NULL_SHA"),
    (0x003B, "TLS_RSA_WITH_NULL_SHA256"),
    (0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
    (0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
    (0x0081, "TLS_GOSTR341001_WITH_28147_CNT_IMIT"),
    (0xFF85, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"),
    (0xC100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"),
    (0xC101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"),
    (0xC102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"),
    (0xC103, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"),
    (0xC104, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"),
    (0xC105, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"),
    (0xC106, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"),
];

pub fn cipher_name(code: u16) -> String {
    CIPHERS
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("0x{code:04X}"))
}

fn is_tls13_suite(code: u16) -> bool {
    (0x1301..=0x1305).contains(&code) || (0xC103..=0xC106).contains(&code)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Strength {
    /// Нельзя использовать: NULL, EXPORT, anon, RC4, DES, MD5.
    Insecure,
    /// Устарел: 3DES, CBC без PFS, обмен ключами RSA.
    Weak,
    Ok,
    Strong,
}

impl Strength {
    pub fn label(self) -> &'static str {
        match self {
            Strength::Insecure => "небезопасный",
            Strength::Weak => "слабый",
            Strength::Ok => "допустимый",
            Strength::Strong => "сильный",
        }
    }
}

pub fn cipher_strength(name: &str) -> Strength {
    let n = name.to_ascii_uppercase();
    if n.contains("NULL") || n.contains("EXPORT") || n.contains("ANON") || n.contains("RC4") || n.contains("_DES_")
        || n.contains("DES40") || n.contains("RC2") || n.ends_with("MD5")
    {
        return Strength::Insecure;
    }
    if n.contains("3DES") || n.contains("IDEA") || n.contains("SEED") {
        return Strength::Weak;
    }
    if n.contains("GOSTR") {
        return if n.contains("28147") { Strength::Ok } else { Strength::Strong };
    }
    let tls13 = !n.contains("_WITH_");
    let pfs = tls13 || n.contains("ECDHE") || n.contains("DHE");
    let aead = n.contains("GCM") || n.contains("CHACHA") || n.contains("CCM");
    match (pfs, aead) {
        (true, true) => Strength::Strong,
        (true, false) => Strength::Ok,
        (false, true) => Strength::Weak,
        (false, false) => Strength::Weak,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "высокая",
            Severity::Medium => "средняя",
            Severity::Low => "низкая",
            Severity::Info => "сведения",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionSupport {
    pub version: String,
    pub supported: bool,
    /// Наборы шифров в порядке выбора сервером.
    pub ciphers: Vec<(String, Strength)>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub address: String,
    pub sni: Option<String>,
    pub versions: Vec<VersionSupport>,
    pub chain: Vec<CertDetail>,
    pub trust_error: Option<String>,
    pub negotiated: String,
    pub findings: Vec<Finding>,
    pub grade: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Total(usize),
    Target(Box<Target>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub targets: Vec<Target>,
}

// ---------------------------------------------------------------------------
// ClientHello и ServerHello
// ---------------------------------------------------------------------------

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    b
}

fn ext(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

pub fn client_hello(version: u16, ciphers: &[u16], sni: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.min(TLS12).to_be_bytes());
    body.extend_from_slice(&random_bytes::<32>());
    if version == TLS13 {
        body.push(32);
        body.extend_from_slice(&random_bytes::<32>());
    } else {
        body.push(0);
    }
    let mut cs: Vec<u8> = ciphers.iter().flat_map(|c| c.to_be_bytes()).collect();
    if version < TLS13 {
        // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        cs.extend_from_slice(&[0x00, 0xFF]);
    }
    body.extend_from_slice(&(cs.len() as u16).to_be_bytes());
    body.extend(cs);
    body.extend_from_slice(&[1, 0]); // сжатие: null
    if version > SSL3 {
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut sn = vec![0];
            sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
            sn.extend_from_slice(name.as_bytes());
            let mut list = (sn.len() as u16).to_be_bytes().to_vec();
            list.extend(sn);
            ext(&mut exts, 0, &list);
        }
        // supported_groups: x25519, P-256, P-384, P-521, ffdhe2048, ГОСТ 256A/B
        let groups: [u16; 7] = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0022, 0x0023];
        let mut g = ((groups.len() * 2) as u16).to_be_bytes().to_vec();
        g.extend(groups.iter().flat_map(|x| x.to_be_bytes()));
        ext(&mut exts, 10, &g);
        ext(&mut exts, 11, &[1, 0]);
        let sigs: [u16; 15] = [
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807, 0x0203, 0x0201, 0x0709,
            0x070A, 0x0840,
        ];
        let mut s = ((sigs.len() * 2) as u16).to_be_bytes().to_vec();
        s.extend(sigs.iter().flat_map(|x| x.to_be_bytes()));
        ext(&mut exts, 13, &s);
        ext(&mut exts, 23, &[]); // extended_master_secret
        if version == TLS13 {
            ext(&mut exts, 43, &[2, 0x03, 0x04]);
            ext(&mut exts, 45, &[1, 1]);
            let mut ks = Vec::new();
            ks.extend_from_slice(&0x001Du16.to_be_bytes());
            ks.extend_from_slice(&32u16.to_be_bytes());
            ks.extend_from_slice(&random_bytes::<32>());
            let mut list = (ks.len() as u16).to_be_bytes().to_vec();
            list.extend(ks);
            ext(&mut exts, 51, &list);
        } else {
            ext(&mut exts, 0xFF01, &[0]);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend(exts);
    }
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![0x16];
    rec.extend_from_slice(&(if version == SSL3 { SSL3 } else { TLS10 }).to_be_bytes());
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloResult {
    /// (версия, выбранный шифр).
    Accepted(u16, u16),
    Alert(u8),
    Rejected(String),
}

/// Разбор первого ответа сервера (ServerHello или alert).
pub fn parse_server_hello(data: &[u8]) -> Option<HelloResult> {
    if data.len() < 5 {
        return None;
    }
    let rlen = u16::from_be_bytes([data[3], data[4]]) as usize;
    match data[0] {
        0x15 => {
            let rec = data.get(5..5 + rlen.min(2))?;
            Some(HelloResult::Alert(*rec.get(1).unwrap_or(&0)))
        }
        0x16 => {
            let rec = data.get(5..5 + rlen)?;
            if rec.len() < 4 || rec[0] != 2 {
                return Some(HelloResult::Rejected(format!("неожиданное сообщение {}", rec[0])));
            }
            let b = &rec[4..];
            if b.len() < 38 {
                return None;
            }
            let mut version = u16::from_be_bytes([b[0], b[1]]);
            let sid_len = b[34] as usize;
            let mut i = 35 + sid_len;
            let cipher = u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]);
            i += 3; // шифр + сжатие
            if i + 2 <= b.len() {
                let elen = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
                let mut j = i + 2;
                let end = (j + elen).min(b.len());
                while j + 4 <= end {
                    let ty = u16::from_be_bytes([b[j], b[j + 1]]);
                    let l = u16::from_be_bytes([b[j + 2], b[j + 3]]) as usize;
                    if ty == 43 && l == 2 && j + 6 <= end {
                        version = u16::from_be_bytes([b[j + 4], b[j + 5]]);
                    }
                    j += 4 + l;
                }
            }
            Some(HelloResult::Accepted(version, cipher))
        }
        0x80..=0xFF if data.get(2) == Some(&4) => Some(HelloResult::Rejected("ответ SSL 2.0".into())),
        other => Some(HelloResult::Rejected(format!("не TLS (байт {other:#04x})"))),
    }
}

async fn hello(addr: SocketAddr, version: u16, ciphers: &[u16], sni: Option<&str>, timeout: Duration) -> HelloResult {
    let res: Result<HelloResult, String> = async {
        let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| "нет подключения".to_string())?
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(timeout, s.write_all(&client_hello(version, ciphers, sni)))
            .await
            .map_err(|_| "таймаут".to_string())?
            .map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = match tokio::time::timeout(timeout, s.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => n,
            };
            data.extend_from_slice(&buf[..n]);
            if data.len() >= 5 {
                let need = 5 + u16::from_be_bytes([data[3], data[4]]) as usize;
                if data.len() >= need.min(5 + 2) && data[0] == 0x15 || data.len() >= need {
                    break;
                }
            }
            if data.len() > 65536 {
                break;
            }
        }
        Ok(parse_server_hello(&data).unwrap_or_else(|| HelloResult::Rejected("соединение закрыто".into())))
    }
    .await;
    res.unwrap_or_else(HelloResult::Rejected)
}

fn offered_for(version: u16) -> Vec<u16> {
    CIPHERS
        .iter()
        .map(|(c, _)| *c)
        .filter(|c| if version == TLS13 { is_tls13_suite(*c) } else { !is_tls13_suite(*c) })
        .collect()
}

/// Поддержка версии и (по желанию) перебор шифров.
async fn check_version(addr: SocketAddr, version: u16, sni: Option<&str>, enum_ciphers: bool, timeout: Duration) -> VersionSupport {
    let mut vs = VersionSupport {
        version: version_name(version).into(),
        ..Default::default()
    };
    let mut remaining = offered_for(version);
    loop {
        if remaining.is_empty() {
            break;
        }
        match hello(addr, version, &remaining, sni, timeout).await {
            HelloResult::Accepted(v, c) if v == version => {
                vs.supported = true;
                let name = cipher_name(c);
                let st = cipher_strength(&name);
                if vs.ciphers.iter().any(|(n, _)| *n == name) || !remaining.contains(&c) {
                    // Сервер выбрал шифр, которого мы не предлагали, — прекращаем.
                    break;
                }
                vs.ciphers.push((name, st));
                remaining.retain(|x| *x != c);
                if !enum_ciphers {
                    break;
                }
            }
            HelloResult::Accepted(v, _) => {
                if vs.ciphers.is_empty() {
                    vs.note = Some(format!("сервер предложил {}", version_name(v)));
                }
                break;
            }
            HelloResult::Alert(code) => {
                if vs.ciphers.is_empty() {
                    vs.note = Some(alert_text(code).into());
                }
                break;
            }
            HelloResult::Rejected(e) => {
                if vs.ciphers.is_empty() {
                    vs.note = Some(e);
                }
                break;
            }
        }
    }
    vs
}

pub fn alert_text(code: u8) -> &'static str {
    match code {
        40 => "handshake_failure",
        47 => "illegal_parameter",
        50 => "decode_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        112 => "unrecognized_name",
        _ => "alert",
    }
}

pub fn evaluate(t: &mut Target, warn_days: i64) {
    let mut f = Vec::new();
    let sup = |name: &str| t.versions.iter().any(|v| v.version == name && v.supported);
    if sup("SSL 3.0") {
        f.push(Finding { severity: Severity::High, text: "включён SSL 3.0 (POODLE)".into() });
    }
    for old in ["TLS 1.0", "TLS 1.1"] {
        if sup(old) {
            f.push(Finding { severity: Severity::Medium, text: format!("включён устаревший {old}") });
        }
    }
    if !t.versions.is_empty() && !sup("TLS 1.3") {
        f.push(Finding { severity: Severity::Low, text: "нет поддержки TLS 1.3".into() });
    }
    if !t.versions.is_empty() && !sup("TLS 1.2") && !sup("TLS 1.3") {
        f.push(Finding { severity: Severity::High, text: "нет ни TLS 1.2, ни TLS 1.3".into() });
    }
    let mut insecure = Vec::new();
    let mut weak = Vec::new();
    for v in &t.versions {
        for (n, s) in &v.ciphers {
            match s {
                Strength::Insecure if !insecure.contains(n) => insecure.push(n.clone()),
                Strength::Weak if !weak.contains(n) => weak.push(n.clone()),
                _ => {}
            }
        }
    }
    if !insecure.is_empty() {
        f.push(Finding { severity: Severity::High, text: format!("небезопасные шифры: {}", insecure.join(", ")) });
    }
    if !weak.is_empty() {
        f.push(Finding { severity: Severity::Medium, text: format!("слабые шифры (без PFS/3DES): {}", weak.join(", ")) });
    }
    if let Some(leaf) = t.chain.first() {
        if leaf.days_left < 0 {
            f.push(Finding { severity: Severity::High, text: format!("сертификат просрочен ({} дн. назад)", -leaf.days_left) });
        } else if leaf.days_left < warn_days {
            f.push(Finding { severity: Severity::Medium, text: format!("сертификат истекает через {} дн.", leaf.days_left) });
        }
        if leaf.weak_key() {
            f.push(Finding { severity: Severity::High, text: format!("слабый ключ: {}", leaf.key) });
        }
        if leaf.weak_signature() {
            f.push(Finding { severity: Severity::Medium, text: format!("устаревшая подпись: {}", leaf.signature) });
        }
        if leaf.self_signed {
            f.push(Finding { severity: Severity::Medium, text: "самоподписанный сертификат".into() });
        }
        for c in t.chain.iter().skip(1) {
            if c.days_left < 0 {
                f.push(Finding { severity: Severity::High, text: format!("в цепочке просрочен «{}»", c.short_subject()) });
            }
            if c.weak_signature() && !c.self_signed {
                f.push(Finding { severity: Severity::Low, text: format!("промежуточный «{}» подписан {}", c.short_subject(), c.signature) });
            }
        }
    }
    if let Some(e) = &t.trust_error {
        f.push(Finding { severity: Severity::High, text: format!("цепочка не доверена: {e}") });
    }
    f.sort_by_key(|x| x.severity);
    let high = f.iter().any(|x| x.severity == Severity::High);
    let medium = f.iter().any(|x| x.severity == Severity::Medium);
    t.grade = if t.error.is_some() {
        "—".into()
    } else if t.trust_error.is_some() && !f.iter().any(|x| x.severity == Severity::High && !x.text.starts_with("цепочка")) {
        "T".into()
    } else if high {
        "F".into()
    } else if medium {
        "B".into()
    } else if f.iter().any(|x| x.severity == Severity::Low) {
        "A-".into()
    } else {
        "A".into()
    };
    t.findings = f;
}

pub async fn audit(host: &str, port: u16, cfg: &Config) -> Target {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(300));
    let mut t = Target {
        host: host.into(),
        port,
        ..Default::default()
    };
    let ip = match super::resolve(host, timeout).await {
        Ok(ip) => ip,
        Err(e) => {
            t.error = Some(e);
            evaluate(&mut t, cfg.expiry_warn_days);
            return t;
        }
    };
    let addr = SocketAddr::new(ip, port);
    t.address = addr.to_string();
    let sni = if !cfg.sni.trim().is_empty() {
        Some(cfg.sni.trim().to_string())
    } else if host.parse::<std::net::IpAddr>().is_err() {
        Some(host.to_string())
    } else {
        None
    };
    t.sni = sni.clone();
    // Цепочка и проверка доверия — через rustls (TLS 1.2/1.3).
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            let name = sni.clone().unwrap_or_else(|| ip.to_string());
            match super::tls::handshake(s, &name, Versions::Auto, &[], timeout).await {
                Ok((_tls, info)) => {
                    t.negotiated = format!("{} {}", info.version, info.cipher);
                    t.chain = info.chain;
                    t.trust_error = info.trust_error;
                }
                Err(e) => t.negotiated = e,
            }
        }
        Ok(Err(e)) => t.error = Some(format!("{addr}: {e}")),
        Err(_) => t.error = Some(format!("{addr}: нет подключения")),
    }
    if t.error.is_none() && cfg.versions {
        for v in [TLS13, TLS12, TLS11, TLS10, SSL3] {
            t.versions.push(check_version(addr, v, sni.as_deref(), cfg.ciphers, timeout).await);
        }
        if t.versions.iter().all(|v| !v.supported) && t.chain.is_empty() {
            t.error = Some("на порту нет TLS".into());
        }
    }
    evaluate(&mut t, cfg.expiry_warn_days);
    t
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let hosts = match super::HostList::parse(&cfg.targets) {
        Ok(h) => h,
        Err(e) => return sink.send(Event::Log(e)),
    };
    let ports = match crate::targets::parse_ports(&cfg.ports) {
        Ok(p) => p,
        Err(e) => return sink.send(Event::Log(e)),
    };
    let jobs: Vec<(String, u16)> = hosts.items().flat_map(|h| ports.iter().map(move |p| (h.clone(), *p))).collect();
    if jobs.len() > 100_000 {
        return sink.send(Event::Log(format!("слишком много целей ({})", jobs.len())));
    }
    sink.send(Event::Total(jobs.len()));
    let cfg = Arc::new(cfg);
    super::for_each_limited(jobs, cfg.concurrency, &cancel, |(h, p)| {
        let (cfg, sink) = (cfg.clone(), sink.clone());
        async move {
            let t = audit(&h, p, &cfg).await;
            sink.send(Event::Target(Box::new(t)));
        }
    })
    .await;
}

pub fn render_text(r: &Report) -> String {
    let mut s = String::new();
    for t in &r.targets {
        s += &format!("== {}:{} ({}) — оценка {}\n", t.host, t.port, t.address, t.grade);
        if let Some(e) = &t.error {
            s += &format!("   ошибка: {e}\n\n");
            continue;
        }
        if !t.negotiated.is_empty() {
            s += &format!("   согласовано: {}\n", t.negotiated);
        }
        for v in &t.versions {
            s += &format!(
                "   {:<8} {}{}\n",
                v.version,
                if v.supported { "да" } else { "нет" },
                v.note.as_ref().filter(|_| !v.supported).map(|n| format!(" ({n})")).unwrap_or_default()
            );
            for (c, st) in &v.ciphers {
                s += &format!("            {c} [{}]\n", st.label());
            }
        }
        for (i, c) in t.chain.iter().enumerate() {
            s += &format!(
                "   [{i}] {} ← {} | {} | {} | до {} ({} дн.)\n",
                c.short_subject(),
                c.short_issuer(),
                c.key,
                c.signature,
                c.not_after,
                c.days_left
            );
        }
        for f in &t.findings {
            s += &format!("   ! [{}] {}\n", f.severity.label(), f.text);
        }
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strengths() {
        assert_eq!(cipher_strength("TLS_AES_128_GCM_SHA256"), Strength::Strong);
        assert_eq!(cipher_strength("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), Strength::Strong);
        assert_eq!(cipher_strength("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"), Strength::Ok);
        assert_eq!(cipher_strength("TLS_RSA_WITH_AES_128_GCM_SHA256"), Strength::Weak);
        assert_eq!(cipher_strength("TLS_RSA_WITH_3DES_EDE_CBC_SHA"), Strength::Weak);
        assert_eq!(cipher_strength("TLS_RSA_WITH_RC4_128_MD5"), Strength::Insecure);
        assert_eq!(cipher_strength("TLS_DH_anon_WITH_AES_128_CBC_SHA"), Strength::Insecure);
        assert_eq!(cipher_strength("TLS_RSA_WITH_DES_CBC_SHA"), Strength::Insecure);
        assert_eq!(cipher_strength("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"), Strength::Strong);
    }

    #[test]
    fn hello_layout() {
        let h = client_hello(TLS12, &[0xC02F, 0x002F], Some("example.com"));
        assert_eq!(h[0], 0x16);
        assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
        assert_eq!(h[5], 1);
        assert_eq!(&h[9..11], &[0x03, 0x03]);
        assert!(h.windows(11).any(|w| w == b"example.com"));
        let h13 = client_hello(TLS13, &[0x1301], None);
        assert!(h13.windows(3).any(|w| w == [2, 3, 4]));
        let ssl3 = client_hello(SSL3, &[0x000A], None);
        assert_eq!(&ssl3[1..3], &[3, 0]);
    }

    #[test]
    fn server_hello_parse() {
        // ServerHello TLS 1.2 с шифром C02F.
        let mut b = vec![0x03, 0x03];
        b.extend_from_slice(&[0; 32]);
        b.push(0);
        b.extend_from_slice(&[0xC0, 0x2F, 0]);
        b.extend_from_slice(&[0, 0]);
        let mut hs = vec![2, 0, 0, b.len() as u8];
        hs.extend(b.clone());
        let mut rec = vec![0x16, 3, 3, 0, hs.len() as u8];
        rec.extend(hs);
        assert_eq!(parse_server_hello(&rec), Some(HelloResult::Accepted(TLS12, 0xC02F)));
        // Тот же ответ с supported_versions = 1.3.
        let mut b13 = b[..b.len() - 2].to_vec();
        b13.extend_from_slice(&[0, 6, 0, 43, 0, 2, 3, 4]);
        let mut hs = vec![2, 0, 0, b13.len() as u8];
        hs.extend(b13);
        let mut rec = vec![0x16, 3, 3, 0, hs.len() as u8];
        rec.extend(hs);
        assert_eq!(parse_server_hello(&rec), Some(HelloResult::Accepted(TLS13, 0xC02F)));
        assert_eq!(parse_server_hello(&[0x15, 3, 3, 0, 2, 2, 40]), Some(HelloResult::Alert(40)));
    }

    #[test]
    fn grading() {
        let mut t = Target::default();
        t.versions = vec![
            VersionSupport { version: "TLS 1.3".into(), supported: true, ciphers: vec![("TLS_AES_128_GCM_SHA256".into(), Strength::Strong)], note: None },
            VersionSupport { version: "TLS 1.2".into(), supported: true, ciphers: vec![], note: None },
        ];
        t.chain = vec![CertDetail { days_left: 200, key: "EC P-256".into(), key_bits: 256, signature: "ecdsa-with-SHA256".into(), ..Default::default() }];
        evaluate(&mut t, 30);
        assert_eq!(t.grade, "A");
        t.versions.push(VersionSupport { version: "TLS 1.0".into(), supported: true, ciphers: vec![], note: None });
        evaluate(&mut t, 30);
        assert_eq!(t.grade, "B");
        t.trust_error = Some("издатель не доверен".into());
        evaluate(&mut t, 30);
        assert_eq!(t.grade, "T");
        t.chain[0].days_left = -3;
        evaluate(&mut t, 30);
        assert_eq!(t.grade, "F");
    }

    /// Локальный TLS-сервер на rustls: TLS 1.2/1.3 есть, TLS 1.0 и SSL 3 — нет.
    #[tokio::test]
    async fn audit_local_rustls_server() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let kd = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let scfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der], kd)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let _ = a.accept(s).await;
                });
            }
        });
        let cfg = Config {
            timeout_ms: 2000,
            ..Default::default()
        };
        let t = audit("localhost", port, &cfg).await;
        assert_eq!(t.error, None);
        let sup: Vec<&str> = t.versions.iter().filter(|v| v.supported).map(|v| v.version.as_str()).collect();
        assert_eq!(sup, vec!["TLS 1.3", "TLS 1.2"], "{:?}", t.versions);
        let tls12 = &t.versions[1];
        assert!(tls12.ciphers.len() >= 3, "{:?}", tls12.ciphers);
        assert!(tls12.ciphers.iter().all(|(_, s)| *s == Strength::Strong));
        assert!(t.trust_error.is_some());
        assert_eq!(t.chain.len(), 1);
        assert_eq!(t.grade, "T");
    }
}
