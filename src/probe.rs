//! Диагностика обнаруженного узла: тип прокси (HTTP / SOCKS), схема аутентификации,
//! поддержка CONNECT, признаки SSL-инспекции, соответствие политикам доступа.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::model::{
    CertInfo, PolicyResult, PolicyVerdict, ProbeResult, ProxyKind, SslInspection,
};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 48 * 1024;
const USER_AGENT: &str = concat!("proxy-scanner/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// Конфигурация
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, String> {
        let s = s.trim();
        let (https, rest) = if let Some(r) = strip_prefix_ci(s, "https://") {
            (true, r)
        } else if let Some(r) = strip_prefix_ci(s, "http://") {
            (false, r)
        } else if s.contains("://") {
            return Err(format!("неподдерживаемая схема в «{s}»"));
        } else {
            (false, s)
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = split_host_port(authority, if https { 443 } else { 80 })?;
        Ok(Url {
            https,
            host,
            port,
            path: path.to_string(),
        })
    }

    pub fn host_header(&self) -> String {
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn absolute(&self) -> String {
        format!(
            "{}://{}{}",
            if self.https { "https" } else { "http" },
            self.host_header(),
            self.path
        )
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| &s[prefix.len()..])
}

/// `host[:port]`
pub fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("пустое имя узла".into());
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !h.contains(':') => {
            let port = p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("некорректный порт в «{s}»"))?;
            Ok((h.to_string(), port))
        }
        _ => Ok((s.to_string(), default_port)),
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub url: Url,
    pub expect_allowed: bool,
}

/// Правила политики, по одному в строке:
/// `+ http://portal.corp.local/` — доступ должен быть разрешён,
/// `- https://blocked.example/` — доступ должен быть заблокирован.
pub fn parse_policy_rules(text: &str) -> Result<Vec<PolicyRule>, String> {
    let mut rules = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (expect_allowed, rest) = if let Some(r) = line.strip_prefix('+') {
            (true, r)
        } else if let Some(r) = line.strip_prefix('-') {
            (false, r)
        } else if let Some(r) = strip_prefix_ci(line, "allow ") {
            (true, r)
        } else if let Some(r) = strip_prefix_ci(line, "deny ") {
            (false, r)
        } else {
            return Err(format!(
                "строка {}: начните правило с «+» (разрешено) или «-» (запрещено)",
                n + 1
            ));
        };
        let url = Url::parse(rest).map_err(|e| format!("строка {}: {e}", n + 1))?;
        rules.push(PolicyRule {
            url,
            expect_allowed,
        });
    }
    Ok(rules)
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub timeout: Duration,
    pub test_url: Url,
    pub tls_host: String,
    pub tls_port: u16,
    /// Эталонный сертификат тестового узла (прямое подключение либо отпечаток вручную).
    pub reference: Option<CertInfo>,
    pub policy: Vec<PolicyRule>,
    pub block_marker: String,
    /// Готовое значение заголовка `Proxy-Authorization`.
    pub proxy_auth: Option<String>,
}

pub fn basic_auth(user: &str, pass: &str) -> Option<String> {
    if user.is_empty() {
        return None;
    }
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    Some(format!("Basic {token}"))
}

pub fn normalize_fp(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct HttpResp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub head: String,
    pub body: Vec<u8>,
}

impl HttpResp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub fn parse_head(head: &[u8]) -> Option<HttpResp> {
    let text = String::from_utf8_lossy(head).into_owned();
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") && !version.starts_with("ICY") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some(HttpResp {
        status,
        headers,
        head: text.trim_end().to_string(),
        body: Vec::new(),
    })
}

/// Читает заголовки ответа побайтно (чтобы не «съесть» данные после них — это важно для CONNECT).
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).await?;
        if n == 0 {
            break;
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
            break;
        }
        // Не HTTP — прекращаем сразу.
        if buf.len() == 5 && &buf[..] != b"HTTP/" && &buf[..4] != b"ICY " {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ответ не является HTTP"));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "слишком длинные заголовки"));
        }
    }
    if buf.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "соединение закрыто без ответа"));
    }
    Ok(buf)
}

fn err_s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

async fn with_timeout<T, E: std::fmt::Display>(
    d: Duration,
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T, String> {
    match tokio::time::timeout(d, fut).await {
        Ok(r) => r.map_err(err_s),
        Err(_) => Err("таймаут".into()),
    }
}

/// Отправляет запрос и читает ответ (заголовки и, при `want_body`, начало тела).
async fn http_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    request: &str,
    timeout: Duration,
    want_body: bool,
) -> Result<HttpResp, String> {
    with_timeout(timeout, s.write_all(request.as_bytes())).await?;
    let head = with_timeout(timeout, read_head(s)).await?;
    let mut resp = parse_head(&head).ok_or("ответ не является HTTP")?;
    if want_body {
        let limit = resp
            .header("Content-Length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(MAX_BODY)
            .min(MAX_BODY);
        let deadline = Instant::now() + timeout.min(Duration::from_millis(1500));
        let mut buf = [0u8; 4096];
        while resp.body.len() < limit {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, s.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => resp.body.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
    }
    Ok(resp)
}

fn get_request(target: &str, host: &str, proxy_auth: Option<&str>) -> String {
    let mut r = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n"
    );
    if let Some(a) = proxy_auth {
        r.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    r.push_str("Proxy-Connection: close\r\nConnection: close\r\n\r\n");
    r
}

fn connect_request(host: &str, port: u16, proxy_auth: Option<&str>) -> String {
    let mut r = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {USER_AGENT}\r\n"
    );
    if let Some(a) = proxy_auth {
        r.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    r.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    r
}

/// Схемы из заголовков `Proxy-Authenticate` / `WWW-Authenticate`.
fn auth_schemes(resp: &HttpResp) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in resp.headers_all("Proxy-Authenticate") {
        if let Some(scheme) = v.split_whitespace().next() {
            let scheme = scheme.trim_end_matches(',').to_string();
            if !out.iter().any(|s| s.eq_ignore_ascii_case(&scheme)) {
                out.push(scheme);
            }
        }
    }
    out
}

/// Заголовки, характерные именно для прокси-серверов.
fn has_proxy_headers(resp: &HttpResp) -> bool {
    const NAMES: &[&str] = &[
        "Via",
        "Proxy-Authenticate",
        "Proxy-Connection",
        "Proxy-Agent",
        "Proxy-Support",
        "X-Squid-Error",
        "X-Cache",
        "X-Cache-Lookup",
        "X-BlueCoat-Via",
        "X-Forwarded-For",
    ];
    NAMES.iter().any(|n| resp.header(n).is_some())
        || resp
            .header("Server")
            .map(|s| {
                let s = s.to_ascii_lowercase();
                ["squid", "proxy", "bluecoat", "zscaler", "mcafee web gateway", "tinyproxy", "3proxy", "privoxy", "ccproxy", "kerio"]
                    .iter()
                    .any(|m| s.contains(m))
            })
            .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// Проверяющий, принимающий любой сертификат: цель — прочитать сертификат,
/// который предъявляет узел, а не доверять ему. По такому каналу отправляются
/// только тестовые GET-запросы из списка политик, без учётных данных.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_connector() -> Result<TlsConnector, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(err_s)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

pub fn cert_info(chain: &[CertificateDer<'_>]) -> Result<CertInfo, String> {
    let leaf = chain.first().ok_or("узел не предъявил сертификат")?;
    let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
    let sha256: String = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect();
    let mut info = CertInfo {
        sha256,
        chain_len: chain.len(),
        ..Default::default()
    };
    match X509Certificate::from_der(leaf.as_ref()) {
        Ok((_, cert)) => {
            info.subject = cert.subject().to_string();
            info.issuer = cert.issuer().to_string();
            info.not_before = cert.validity().not_before.to_string();
            info.not_after = cert.validity().not_after.to_string();
            info.self_signed = cert.subject() == cert.issuer();
        }
        Err(e) => info.subject = format!("(не удалось разобрать сертификат: {e})"),
    }
    Ok(info)
}

type TlsStream<S> = tokio_rustls::client::TlsStream<S>;

async fn tls_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    host: &str,
    timeout: Duration,
) -> Result<(TlsStream<S>, CertInfo), String> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("некорректное имя узла для TLS: «{host}»"))?;
    let tls = with_timeout(timeout, tls_connector()?.connect(name, stream))
        .await
        .map_err(|e| format!("TLS-рукопожатие: {e}"))?;
    let info = cert_info(tls.get_ref().1.peer_certificates().unwrap_or(&[]))?;
    Ok((tls, info))
}

/// Сертификат тестового узла при прямом подключении (эталон для сравнения).
pub async fn direct_reference(host: &str, port: u16, timeout: Duration) -> Result<CertInfo, String> {
    let stream = with_timeout(timeout, TcpStream::connect((host, port)))
        .await
        .map_err(|e| format!("прямое подключение к {host}:{port}: {e}"))?;
    let (_tls, info) = tls_handshake(stream, host, timeout).await?;
    Ok(info)
}

/// Сравнение сертификата, полученного через прокси, с эталоном.
pub fn ssl_verdict(cert: &CertInfo, reference: Option<&CertInfo>) -> (SslInspection, Option<String>) {
    let Some(reference) = reference else {
        return (SslInspection::NoReference, None);
    };
    if normalize_fp(&cert.sha256) == normalize_fp(&reference.sha256) {
        return (SslInspection::No, None);
    }
    if !reference.issuer.is_empty() && reference.issuer == cert.issuer {
        // Другой экземпляр сертификата того же издателя (балансировка, ротация).
        return (
            SslInspection::No,
            Some("отпечаток отличается от эталона, но издатель совпадает".into()),
        );
    }
    (
        SslInspection::Yes,
        Some(format!(
            "сертификат через прокси отличается от эталонного: издатель «{}»{}",
            cert.issuer,
            if reference.issuer.is_empty() {
                String::new()
            } else {
                format!(", эталонный издатель «{}»", reference.issuer)
            }
        )),
    )
}

// ---------------------------------------------------------------------------
// SOCKS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Socks5Auth {
    None,
    UserPass,
    Gssapi,
    NoAcceptable,
}

async fn socks5_greet(s: &mut TcpStream, timeout: Duration) -> Result<Socks5Auth, String> {
    // Версия 5, предлагаем методы: без аутентификации, GSSAPI, логин/пароль.
    with_timeout(timeout, s.write_all(&[5, 3, 0, 1, 2])).await?;
    let mut r = [0u8; 2];
    with_timeout(timeout, s.read_exact(&mut r)).await?;
    if r[0] != 5 {
        return Err("не SOCKS5".into());
    }
    Ok(match r[1] {
        0 => Socks5Auth::None,
        1 => Socks5Auth::Gssapi,
        2 => Socks5Auth::UserPass,
        0xFF => Socks5Auth::NoAcceptable,
        _ => return Err("не SOCKS5".into()),
    })
}

/// SOCKS5 CONNECT по доменному имени; возвращает код ответа (0 — успех).
async fn socks5_connect(
    s: &mut TcpStream,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<u8, String> {
    if host.len() > 255 {
        return Err("слишком длинное имя узла".into());
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    with_timeout(timeout, s.write_all(&req)).await?;
    let mut head = [0u8; 4];
    with_timeout(timeout, s.read_exact(&mut head)).await?;
    if head[0] != 5 {
        return Err("некорректный ответ SOCKS5".into());
    }
    let addr_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            with_timeout(timeout, s.read_exact(&mut l)).await?;
            l[0] as usize
        }
        _ => 0,
    };
    let mut rest = vec![0u8; addr_len + 2];
    with_timeout(timeout, s.read_exact(&mut rest)).await?;
    Ok(head[1])
}

fn socks5_reply_text(code: u8) -> &'static str {
    match code {
        0 => "успех",
        1 => "общая ошибка сервера",
        2 => "соединение запрещено правилами",
        3 => "сеть недоступна",
        4 => "узел недоступен",
        5 => "в соединении отказано",
        6 => "истёк TTL",
        7 => "команда не поддерживается",
        8 => "тип адреса не поддерживается",
        _ => "неизвестный код",
    }
}

/// SOCKS4 CONNECT; возвращает код ответа (0x5A — разрешено).
async fn socks4_probe(
    s: &mut TcpStream,
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
) -> Result<u8, String> {
    let mut req = vec![4, 1];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&ip.octets());
    req.push(0); // пустой user-id
    with_timeout(timeout, s.write_all(&req)).await?;
    let mut r = [0u8; 8];
    with_timeout(timeout, s.read_exact(&mut r)).await?;
    if r[0] == 0 && (0x5A..=0x5D).contains(&r[1]) {
        Ok(r[1])
    } else {
        Err("не SOCKS4".into())
    }
}

// ---------------------------------------------------------------------------
// Политики доступа
// ---------------------------------------------------------------------------

fn contains_marker(resp: &HttpResp, marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    let m = marker.to_lowercase();
    String::from_utf8_lossy(&resp.body).to_lowercase().contains(&m)
        || resp.head.to_lowercase().contains(&m)
}

fn classify_policy(resp: &HttpResp, marker: &str) -> (PolicyVerdict, String) {
    let s = resp.status;
    if contains_marker(resp, marker) {
        return (
            PolicyVerdict::Blocked,
            format!("HTTP {s}, найден маркер страницы блокировки"),
        );
    }
    match s {
        200..=399 => (PolicyVerdict::Allowed, format!("HTTP {s}")),
        407 => (PolicyVerdict::AuthRequired, "HTTP 407".into()),
        502..=504 => (
            PolicyVerdict::Error,
            format!("HTTP {s}: прокси не смог связаться с узлом"),
        ),
        _ => (PolicyVerdict::Blocked, format!("HTTP {s}")),
    }
}

async fn check_policy_rule(addr: SocketAddr, rule: &PolicyRule, cfg: &ProbeConfig) -> PolicyResult {
    let auth = cfg.proxy_auth.as_deref();
    let outcome: Result<(PolicyVerdict, String), String> = async {
        let mut s = with_timeout(cfg.timeout, TcpStream::connect(addr)).await?;
        if !rule.url.https {
            let req = get_request(&rule.url.absolute(), &rule.url.host_header(), auth);
            let resp = http_exchange(&mut s, &req, cfg.timeout, true).await?;
            return Ok(classify_policy(&resp, &cfg.block_marker));
        }
        let req = connect_request(&rule.url.host, rule.url.port, auth);
        let resp = http_exchange(&mut s, &req, cfg.timeout, false).await?;
        if !(200..300).contains(&resp.status) {
            let (v, d) = classify_policy(&resp, &cfg.block_marker);
            return Ok((v, format!("CONNECT: {d}")));
        }
        // Туннель открыт. При SSL-инспекции блокировка может выполняться внутри TLS,
        // поэтому делаем запрос через туннель.
        match tls_handshake(s, &rule.url.host, cfg.timeout).await {
            Ok((mut tls, _)) => {
                let req = get_request(&rule.url.path, &rule.url.host_header(), None);
                match http_exchange(&mut tls, &req, cfg.timeout, true).await {
                    Ok(resp) => {
                        let (v, d) = classify_policy(&resp, &cfg.block_marker);
                        Ok((v, format!("CONNECT 200, {d}")))
                    }
                    Err(e) => Ok((
                        PolicyVerdict::Allowed,
                        format!("CONNECT 200, TLS установлен, ответ не получен ({e})"),
                    )),
                }
            }
            Err(e) => Ok((
                PolicyVerdict::Blocked,
                format!("CONNECT 200, но TLS не установлен ({e})"),
            )),
        }
    }
    .await;

    let (verdict, detail) = outcome.unwrap_or_else(|e| (PolicyVerdict::Error, e));
    let compliant = match verdict {
        PolicyVerdict::Allowed => rule.expect_allowed,
        PolicyVerdict::Blocked => !rule.expect_allowed,
        PolicyVerdict::AuthRequired | PolicyVerdict::Error => false,
    };
    PolicyResult {
        url: rule.url.absolute(),
        expect_allowed: rule.expect_allowed,
        verdict,
        detail,
        compliant,
    }
}

// ---------------------------------------------------------------------------
// Основная процедура
// ---------------------------------------------------------------------------

/// Полная диагностика одного узла `ip:port`.
pub async fn probe_endpoint(ip: Ipv4Addr, port: u16, cfg: &ProbeConfig) -> ProbeResult {
    let addr = SocketAddr::from((ip, port));
    let mut res = ProbeResult::default();
    let auth = cfg.proxy_auth.as_deref();

    // 1. Доступность и время отклика.
    let started = Instant::now();
    let mut stream = match with_timeout(cfg.timeout, TcpStream::connect(addr)).await {
        Ok(s) => s,
        Err(e) => {
            res.error = Some(format!("подключение: {e}"));
            return res;
        }
    };
    res.rtt_ms = Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32);

    // 2. HTTP-запрос с абсолютным URI (так обращаются к прокси).
    let req = get_request(&cfg.test_url.absolute(), &cfg.test_url.host_header(), auth);
    let http = http_exchange(&mut stream, &req, cfg.timeout, false).await;
    drop(stream);

    match http {
        Ok(resp) => {
            res.http_status = Some(resp.status);
            res.raw_headers = resp.head.clone();
            res.server = resp
                .header("Server")
                .or_else(|| resp.header("Proxy-Agent"))
                .unwrap_or("")
                .to_string();
            res.via = resp.header("Via").unwrap_or("").to_string();
            res.auth = auth_schemes(&resp);
            res.auth_required = resp.status == 407;
            let mut is_proxy = resp.status == 407 || has_proxy_headers(&resp);
            if matches!(resp.status, 502 | 504) {
                is_proxy = true;
                res.notes.push(format!(
                    "HTTP {}: узел пытался выполнить запрос к {} как шлюз",
                    resp.status,
                    cfg.test_url.host_header()
                ));
            }

            // 3. CONNECT и проверка SSL-инспекции.
            match probe_connect(addr, cfg, &mut res).await {
                Ok(status) => {
                    if (200..300).contains(&status) || status == 407 {
                        is_proxy = true;
                    }
                }
                Err(e) => res.notes.push(format!("CONNECT: {e}")),
            }

            res.kind = Some(if is_proxy {
                ProxyKind::HttpProxy
            } else {
                ProxyKind::HttpServer
            });

            // 4. Политики доступа.
            if is_proxy {
                for rule in &cfg.policy {
                    res.policy.push(check_policy_rule(addr, rule, cfg).await);
                }
            }
        }
        Err(http_err) => {
            // 5. Не HTTP — пробуем SOCKS.
            probe_socks(addr, cfg, &mut res).await;
            if res.kind.is_none() {
                res.kind = Some(ProxyKind::NotProxy);
                res.notes.push(format!("HTTP: {http_err}"));
            }
        }
    }
    res
}

/// CONNECT к тестовому TLS-узлу; при успехе — чтение сертификата. Возвращает код ответа.
async fn probe_connect(addr: SocketAddr, cfg: &ProbeConfig, res: &mut ProbeResult) -> Result<u16, String> {
    let mut s = with_timeout(cfg.timeout, TcpStream::connect(addr)).await?;
    let req = connect_request(&cfg.tls_host, cfg.tls_port, cfg.proxy_auth.as_deref());
    let resp = http_exchange(&mut s, &req, cfg.timeout, false).await?;
    res.connect_status = Some(resp.status);
    if resp.status == 407 {
        res.auth_required = true;
        for scheme in auth_schemes(&resp) {
            if !res.auth.iter().any(|a| a.eq_ignore_ascii_case(&scheme)) {
                res.auth.push(scheme);
            }
        }
    }
    if res.raw_headers.is_empty() {
        res.raw_headers = resp.head.clone();
    } else {
        res.raw_headers
            .push_str(&format!("\n\n--- CONNECT {}:{} ---\n{}", cfg.tls_host, cfg.tls_port, resp.head));
    }
    if (200..300).contains(&resp.status) {
        read_cert_through(s, cfg, res).await;
    }
    Ok(resp.status)
}

/// TLS-рукопожатие через уже открытый туннель и вывод о SSL-инспекции.
async fn read_cert_through(s: TcpStream, cfg: &ProbeConfig, res: &mut ProbeResult) {
    match tls_handshake(s, &cfg.tls_host, cfg.timeout).await {
        Ok((_tls, cert)) => {
            let (verdict, note) = ssl_verdict(&cert, cfg.reference.as_ref());
            res.ssl = Some(verdict);
            res.notes.extend(note);
            res.cert = Some(cert);
        }
        Err(e) => res.notes.push(format!("туннель открыт, но {e}")),
    }
}

/// IPv4-адрес узла: литерал либо первый A-адрес из DNS.
async fn resolve_v4(host: &str, port: u16, timeout: Duration) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    let addrs = with_timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .ok()?;
    addrs
        .filter_map(|a| match a {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
        .next()
}

async fn probe_socks(addr: SocketAddr, cfg: &ProbeConfig, res: &mut ProbeResult) {
    // SOCKS5
    if let Ok(mut s) = with_timeout(cfg.timeout, TcpStream::connect(addr)).await
        && let Ok(method) = socks5_greet(&mut s, cfg.timeout).await
    {
        res.kind = Some(ProxyKind::Socks5);
        match method {
            Socks5Auth::None => {
                match socks5_connect(&mut s, &cfg.tls_host, cfg.tls_port, cfg.timeout).await {
                    Ok(0) => {
                        res.connect_status = Some(200);
                        read_cert_through(s, cfg, res).await;
                    }
                    Ok(code) => res.notes.push(format!(
                        "SOCKS5 CONNECT {}:{} отклонён: {} (код {code})",
                        cfg.tls_host,
                        cfg.tls_port,
                        socks5_reply_text(code)
                    )),
                    Err(e) => res.notes.push(format!("SOCKS5 CONNECT: {e}")),
                }
            }
            Socks5Auth::UserPass => {
                res.auth_required = true;
                res.auth.push("логин/пароль".into());
            }
            Socks5Auth::Gssapi => {
                res.auth_required = true;
                res.auth.push("GSSAPI".into());
            }
            Socks5Auth::NoAcceptable => {
                res.auth_required = true;
                res.notes
                    .push("SOCKS5: сервер не принял ни один из предложенных методов".into());
            }
        }
        return;
    }
    // SOCKS4 — нужен IPv4-адрес назначения.
    if let Some(target) = resolve_v4(&cfg.tls_host, cfg.tls_port, cfg.timeout).await
        && let Ok(mut s) = with_timeout(cfg.timeout, TcpStream::connect(addr)).await
        && let Ok(code) = socks4_probe(&mut s, target, cfg.tls_port, cfg.timeout).await
    {
        res.kind = Some(ProxyKind::Socks4);
        if code == 0x5A {
            res.connect_status = Some(200);
            read_cert_through(s, cfg, res).await;
        } else {
            res.notes
                .push(format!("SOCKS4: запрос отклонён (код 0x{code:02X})"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn cfg() -> ProbeConfig {
        ProbeConfig {
            timeout: Duration::from_secs(2),
            test_url: Url::parse("http://example.com/").unwrap(),
            tls_host: "example.com".into(),
            tls_port: 443,
            reference: None,
            policy: parse_policy_rules("+ http://ok.test/\n- http://bad.test/x").unwrap(),
            block_marker: String::new(),
            proxy_auth: None,
        }
    }

    #[test]
    fn url_parsing() {
        let u = Url::parse("https://Host.corp:8443/a/b?c=1").unwrap();
        assert!(u.https);
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("Host.corp", 8443, "/a/b?c=1"));
        assert_eq!(u.absolute(), "https://Host.corp:8443/a/b?c=1");
        let u = Url::parse("portal.local").unwrap();
        assert_eq!(u.absolute(), "http://portal.local/");
        assert!(Url::parse("ftp://x/").is_err());
        assert_eq!(split_host_port("example.com:443", 1).unwrap(), ("example.com".into(), 443));
        assert_eq!(split_host_port("example.com", 443).unwrap(), ("example.com".into(), 443));
    }

    #[test]
    fn policy_rules() {
        let r = parse_policy_rules("# комментарий\n+ http://a/\ndeny https://b/\n").unwrap();
        assert_eq!(r.len(), 2);
        assert!(r[0].expect_allowed && !r[1].expect_allowed && r[1].url.https);
        assert!(parse_policy_rules("http://a/").is_err());
    }

    #[test]
    fn head_parsing_and_auth() {
        let head = b"HTTP/1.1 407 Proxy Authentication Required\r\nServer: squid/5.7\r\nProxy-Authenticate: Negotiate\r\nProxy-Authenticate: NTLM\r\nProxy-Authenticate: Basic realm=\"corp\"\r\nVia: 1.1 gw01 (squid/5.7)\r\n\r\n";
        let r = parse_head(head).unwrap();
        assert_eq!(r.status, 407);
        assert_eq!(auth_schemes(&r), vec!["Negotiate", "NTLM", "Basic"]);
        assert!(has_proxy_headers(&r));
        assert!(parse_head(b"SSH-2.0-OpenSSH_9.6\r\n").is_none());
    }

    #[test]
    fn verdicts() {
        let cert = CertInfo { sha256: "AABB".into(), issuer: "CN=Corp Inspection CA".into(), ..Default::default() };
        assert_eq!(ssl_verdict(&cert, None).0, SslInspection::NoReference);
        let same = CertInfo { sha256: "aa:bb".into(), ..Default::default() };
        assert_eq!(ssl_verdict(&cert, Some(&same)).0, SslInspection::No);
        let other = CertInfo { sha256: "CCDD".into(), issuer: "CN=Public CA".into(), ..Default::default() };
        assert_eq!(ssl_verdict(&cert, Some(&other)).0, SslInspection::Yes);
        let rotated = CertInfo { sha256: "CCDD".into(), issuer: "CN=Corp Inspection CA".into(), ..Default::default() };
        assert_eq!(ssl_verdict(&cert, Some(&rotated)).0, SslInspection::No);
    }

    /// Имитация HTTP-прокси: 407 на CONNECT, 200/403 на GET в зависимости от узла.
    async fn fake_http_proxy() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { break };
                tokio::spawn(async move {
                    let Ok(head) = read_request(&mut s).await else { return };
                    let reply: &str = if head.starts_with("CONNECT") {
                        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n"
                    } else if head.contains("bad.test") {
                        "HTTP/1.1 403 Forbidden\r\nVia: 1.1 fake\r\nContent-Length: 0\r\n\r\n"
                    } else {
                        "HTTP/1.1 200 OK\r\nVia: 1.1 fake\r\nServer: squid/6.1\r\nContent-Length: 2\r\n\r\nok"
                    };
                    let _ = s.write_all(reply.as_bytes()).await;
                });
            }
        });
        port
    }

    async fn read_request(s: &mut TcpStream) -> io::Result<String> {
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if s.read(&mut b).await? == 0 {
                break;
            }
            buf.push(b[0]);
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    #[tokio::test]
    async fn detects_http_proxy_and_policy() {
        let port = fake_http_proxy().await;
        let r = probe_endpoint(Ipv4Addr::LOCALHOST, port, &cfg()).await;
        assert_eq!(r.kind, Some(ProxyKind::HttpProxy));
        assert_eq!(r.http_status, Some(200));
        assert_eq!(r.connect_status, Some(407));
        assert!(r.auth_required);
        assert_eq!(r.auth, vec!["NTLM"]);
        assert_eq!(r.server, "squid/6.1");
        assert_eq!(r.policy.len(), 2);
        assert!(r.policy.iter().all(|p| p.compliant), "{:?}", r.policy);
    }

    #[tokio::test]
    async fn detects_socks5() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { break };
                tokio::spawn(async move {
                    let mut b = [0u8; 64];
                    let Ok(n) = s.read(&mut b).await else { return };
                    if n >= 2 && b[0] == 5 {
                        let _ = s.write_all(&[5, 2]).await;
                    }
                    // На HTTP-запрос не отвечаем — закрываем соединение.
                });
            }
        });
        let r = probe_endpoint(Ipv4Addr::LOCALHOST, port, &cfg()).await;
        assert_eq!(r.kind, Some(ProxyKind::Socks5));
        assert!(r.auth_required);
    }

    #[tokio::test]
    async fn plain_web_server_is_not_proxy() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { break };
                tokio::spawn(async move {
                    let Ok(head) = read_request(&mut s).await else { return };
                    let reply = if head.starts_with("CONNECT") {
                        "HTTP/1.1 405 Method Not Allowed\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n"
                    } else {
                        "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n"
                    };
                    let _ = s.write_all(reply.as_bytes()).await;
                });
            }
        });
        let r = probe_endpoint(Ipv4Addr::LOCALHOST, port, &cfg()).await;
        assert_eq!(r.kind, Some(ProxyKind::HttpServer));
        assert!(r.policy.is_empty());
    }
}
