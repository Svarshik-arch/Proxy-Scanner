//! HTTP-запросы в духе `curl -v -w`: сырые заголовки, время по фазам (DNS, TCP, прокси,
//! TLS, первый байт), цепочка перенаправлений, работа через прокси с аутентификацией.

use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::tls::{self, TlsInfo, Versions};
use super::{Sink, ms_f};
use crate::auth::{AuthMode, Credentials, Scheme};
use crate::probe::{HttpResp, Url};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Conn = Pin<Box<dyn Io>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProxyMode {
    #[default]
    Direct,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub url: String,
    pub method: String,
    /// Дополнительные заголовки, по одному в строке: `Имя: значение`.
    pub headers: String,
    pub body: String,
    pub proxy_mode: ProxyMode,
    /// Прокси `host:port`.
    pub proxy: String,
    pub proxy_auth: AuthMode,
    pub proxy_current_user: bool,
    pub proxy_domain: String,
    pub proxy_user: String,
    #[serde(skip)]
    pub proxy_pass: String,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    /// Прерывать запрос, если сертификат не прошёл проверку (как curl без `-k`).
    pub verify_tls: bool,
    pub tls_versions: Versions,
    /// Подменить адрес узла, как `curl --resolve host:ip`.
    pub resolve: String,
    pub timeout_ms: u64,
    pub body_limit_kb: usize,
    pub user_agent: String,
    /// Повторить запрос N раз (статистика времени).
    pub repeat: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: String::new(),
            method: "GET".into(),
            headers: String::new(),
            body: String::new(),
            proxy_mode: ProxyMode::Direct,
            proxy: String::new(),
            proxy_auth: AuthMode::Auto,
            proxy_current_user: true,
            proxy_domain: String::new(),
            proxy_user: String::new(),
            proxy_pass: String::new(),
            follow_redirects: true,
            max_redirects: 10,
            verify_tls: false,
            tls_versions: Versions::Auto,
            resolve: String::new(),
            timeout_ms: 10_000,
            body_limit_kb: 512,
            user_agent: concat!("proxy-scanner/", env!("CARGO_PKG_VERSION")).into(),
            repeat: 1,
        }
    }
}

impl Config {
    fn creds(&self) -> Credentials {
        Credentials {
            mode: self.proxy_auth,
            current_user: self.proxy_current_user,
            user: self.proxy_user.clone(),
            password: self.proxy_pass.clone(),
            domain: self.proxy_domain.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timings {
    pub dns_ms: f64,
    pub connect_ms: f64,
    /// CONNECT через прокси (с аутентификацией).
    pub proxy_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    /// От отправки запроса до первого байта ответа.
    pub ttfb_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hop {
    pub url: String,
    pub address: String,
    pub request: String,
    pub status: u16,
    pub response_head: String,
    pub body: Vec<u8>,
    pub body_size: usize,
    pub body_truncated: bool,
    pub timings: Timings,
    pub tls: Option<TlsInfo>,
    /// Схема и итог аутентификации на прокси.
    pub proxy_auth: Option<String>,
    pub error: Option<String>,
}

impl Hop {
    pub fn header(&self, name: &str) -> Option<String> {
        crate::probe::parse_head(self.response_head.as_bytes())
            .and_then(|r| r.header(name).map(String::from))
    }
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Hop(Box<Hop>),
    /// Номер повтора закончен.
    RunDone(u32),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    /// Для каждого повтора — цепочка переходов.
    pub runs: Vec<Vec<Hop>>,
}

// ---------------------------------------------------------------------------
// Ввод-вывод
// ---------------------------------------------------------------------------

async fn timed<T>(t: Duration, what: &str, f: impl std::future::Future<Output = std::io::Result<T>>) -> Result<T, String> {
    match tokio::time::timeout(t, f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: нет ответа за {} мс", t.as_millis())),
    }
}

/// Тело ответа: по Content-Length, chunked или до закрытия соединения.
async fn read_body<S: AsyncRead + Unpin + ?Sized>(
    s: &mut S,
    resp: &HttpResp,
    method: &str,
    limit: usize,
    timeout: Duration,
) -> Result<(Vec<u8>, usize, bool), String> {
    if method.eq_ignore_ascii_case("HEAD") || resp.status == 204 || resp.status == 304 || (100..200).contains(&resp.status) {
        return Ok((Vec::new(), 0, false));
    }
    let chunked = resp
        .header("Transfer-Encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let cl = resp.header("Content-Length").and_then(|v| v.trim().parse::<usize>().ok());
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut buf = vec![0u8; 16384];
    if chunked {
        let mut raw = Vec::new();
        loop {
            let n = timed(timeout, "чтение тела", s.read(&mut buf)).await?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(done) = chunked_complete(&raw) {
                raw.truncate(done);
                break;
            }
            if raw.len() > limit.saturating_mul(2) + 65536 {
                break;
            }
        }
        let decoded = decode_chunked(&raw);
        total = decoded.len();
        out = decoded;
    } else if let Some(cl) = cl {
        while total < cl {
            let want = (cl - total).min(buf.len());
            let n = timed(timeout, "чтение тела", s.read(&mut buf[..want])).await?;
            if n == 0 {
                break;
            }
            total += n;
            if out.len() < limit {
                out.extend_from_slice(&buf[..n.min(limit - out.len())]);
            }
        }
    } else {
        loop {
            let n = match tokio::time::timeout(timeout, s.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) | Err(_) => break,
            };
            if n == 0 {
                break;
            }
            total += n;
            if out.len() < limit {
                out.extend_from_slice(&buf[..n.min(limit - out.len())]);
            }
            if total > limit.saturating_mul(4) + (1 << 20) {
                break;
            }
        }
    }
    let truncated = total > out.len();
    out.truncate(limit);
    Ok((out, total, truncated))
}

/// Позиция конца chunked-тела, если оно получено целиком.
fn chunked_complete(raw: &[u8]) -> Option<usize> {
    let mut i = 0;
    loop {
        let nl = raw[i..].windows(2).position(|w| w == b"\r\n")?;
        let line = String::from_utf8_lossy(&raw[i..i + nl]);
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        i += nl + 2;
        if size == 0 {
            // Завершающие заголовки и пустая строка.
            let end = raw[i..].windows(2).position(|w| w == b"\r\n")?;
            return Some(i + end + 2);
        }
        i += size + 2;
        if i > raw.len() {
            return None;
        }
    }
}

pub fn decode_chunked(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let Some(nl) = body[i..].windows(2).position(|w| w == b"\r\n") else { break };
        let size_line = String::from_utf8_lossy(&body[i..i + nl]);
        let Ok(size) = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16) else { break };
        i += nl + 2;
        if size == 0 {
            break;
        }
        let end = (i + size).min(body.len());
        out.extend_from_slice(&body[i..end]);
        i = end + 2;
    }
    out
}

async fn read_response(
    s: &mut Conn,
    method: &str,
    limit: usize,
    timeout: Duration,
) -> Result<(HttpResp, f64, usize, bool), String> {
    let started = Instant::now();
    let head = timed(timeout, "ответ", crate::probe::read_head(s)).await?;
    let ttfb = ms_f(started.elapsed());
    let mut resp = crate::probe::parse_head(&head).ok_or("ответ не является HTTP")?;
    let (body, size, truncated) = read_body(s, &resp, method, limit, timeout).await?;
    resp.body = body;
    Ok((resp, ttfb, size, truncated))
}

fn closes(resp: &HttpResp) -> bool {
    ["Connection", "Proxy-Connection"]
        .iter()
        .any(|h| resp.header(h).is_some_and(|v| v.to_ascii_lowercase().contains("close")))
}

fn offered_schemes(resp: &HttpResp) -> Vec<String> {
    resp.headers_all("Proxy-Authenticate")
        .filter_map(|v| v.split_whitespace().next())
        .map(|s| s.trim_end_matches(',').to_ascii_lowercase())
        .collect()
}

/// Подстановка адреса по `--resolve`: «host:ip» через запятую.
fn resolve_override(cfg: &Config, host: &str) -> Option<String> {
    super::split_list(&cfg.resolve).into_iter().find_map(|item| {
        let (h, ip) = item.split_once(':')?;
        h.eq_ignore_ascii_case(host).then(|| ip.to_string())
    })
}

async fn dial(host: &str, port: u16, cfg: &Config, t: &mut Timings) -> Result<(TcpStream, SocketAddr), String> {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    let started = Instant::now();
    let target = resolve_override(cfg, host).unwrap_or_else(|| host.to_string());
    let ip = super::resolve(&target, timeout).await?;
    t.dns_ms += ms_f(started.elapsed());
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    let s = timed(timeout, &format!("подключение к {addr}"), TcpStream::connect(addr)).await?;
    let _ = s.set_nodelay(true);
    t.connect_ms += ms_f(started.elapsed());
    Ok((s, addr))
}

/// Запрос с аутентификацией на прокси: `build(auth)` собирает запрос с нужным
/// `Proxy-Authorization`. Возвращает соединение, ответ, ttfb и описание входа.
async fn exchange(
    conn: &mut Conn,
    method: &str,
    limit: usize,
    timeout: Duration,
    req: String,
) -> Result<(HttpResp, f64, usize, bool), String> {
    timed(timeout, "отправка запроса", conn.write_all(req.as_bytes())).await?;
    // Тело успешного ответа на CONNECT не читаем — дальше идёт туннель.
    if method == "CONNECT" {
        let started = Instant::now();
        let head = timed(timeout, "ответ прокси", crate::probe::read_head(conn)).await?;
        let ttfb = ms_f(started.elapsed());
        let mut resp = crate::probe::parse_head(&head).ok_or("ответ прокси не является HTTP")?;
        if !(200..300).contains(&resp.status) {
            let (b, _, _) = read_body(conn, &resp, "GET", 64 * 1024, timeout.min(Duration::from_secs(2)))
                .await
                .unwrap_or_default();
            resp.body = b;
        }
        Ok((resp, ttfb, 0, false))
    } else {
        read_response(conn, method, limit, timeout).await
    }
}

async fn with_proxy_auth(
    mut conn: Conn,
    build: &(dyn Fn(Option<&str>) -> String + Sync),
    cfg: &Config,
    proxy_host: &str,
    redial: &mut (dyn FnMut() -> Pin<Box<dyn std::future::Future<Output = Result<Conn, String>> + Send>> + Send),
    method: &str,
    connect_only: bool,
) -> Result<(Conn, HttpResp, f64, usize, bool, Option<String>), String> {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    let limit = cfg.body_limit_kb.max(1) * 1024;
    let creds = cfg.creds();
    let read_method = if connect_only { "CONNECT" } else { method };
    let pre_basic = if creds.mode == AuthMode::Basic && creds.has_explicit() {
        Some(crate::auth::new_session(Scheme::Basic, &creds, "")?.step(None)?)
    } else {
        None
    };
    let (resp, ttfb, size, trunc) = exchange(&mut conn, read_method, limit, timeout, build(pre_basic.as_deref())).await?;
    if resp.status != 407 || creds.mode == AuthMode::None {
        let auth = pre_basic.map(|_| format!("{}: {}", Scheme::Basic.describe(&creds), if resp.status == 407 { "отказ" } else { "вход выполнен" }));
        return Ok((conn, resp, ttfb, size, trunc, auth));
    }
    if pre_basic.is_some() {
        return Ok((conn, resp, ttfb, size, trunc, Some(format!("{}: отказ", Scheme::Basic.describe(&creds)))));
    }
    let offered = offered_schemes(&resp);
    let Some(scheme) = creds.choose(&offered) else {
        return Ok((conn, resp, ttfb, size, trunc, Some(format!("прокси требует: {}", offered.join(", ")))));
    };
    let desc = scheme.describe(&creds);
    let mut session = crate::auth::new_session(scheme, &creds, proxy_host)?;
    let mut header = session.step(None)?;
    if closes(&resp) {
        conn = redial().await?;
    }
    for _ in 0..4 {
        let (r, ttfb, size, trunc) = exchange(&mut conn, read_method, limit, timeout, build(Some(&header))).await?;
        if r.status != 407 {
            return Ok((conn, r, ttfb, size, trunc, Some(format!("{desc}: вход выполнен"))));
        }
        let token = r.headers_all("Proxy-Authenticate").find_map(|v| {
            let (name, tok) = v.trim().split_once(' ')?;
            name.eq_ignore_ascii_case(scheme.header_name())
                .then(|| crate::auth::b64_decode(tok))
                .flatten()
        });
        match token {
            Some(t) if scheme != Scheme::Basic => {
                header = session.step(Some(&t))?;
                if closes(&r) {
                    conn = redial().await?;
                }
            }
            _ => return Ok((conn, r, ttfb, size, trunc, Some(format!("{desc}: учётные данные отклонены")))),
        }
    }
    Err(format!("{desc}: слишком много шагов аутентификации"))
}

fn request_text(cfg: &Config, url: &Url, method: &str, absolute: bool, body: &str) -> String {
    let target = if absolute { url.absolute() } else { url.path.clone() };
    let mut r = format!("{method} {target} HTTP/1.1\r\nHost: {}\r\n", url.host_header());
    let custom: Vec<(String, String)> = cfg
        .headers
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect();
    let has = |name: &str| custom.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    if !has("User-Agent") && !cfg.user_agent.is_empty() {
        r += &format!("User-Agent: {}\r\n", cfg.user_agent);
    }
    if !has("Accept") {
        r += "Accept: */*\r\n";
    }
    for (k, v) in &custom {
        r += &format!("{k}: {v}\r\n");
    }
    if !body.is_empty() && !has("Content-Length") {
        r += &format!("Content-Length: {}\r\n", body.len());
    }
    if absolute {
        r += "Proxy-Connection: keep-alive\r\n";
    }
    r
}

fn finish_request(mut head: String, auth: Option<&str>, body: &str) -> String {
    if let Some(a) = auth {
        head += &format!("Proxy-Authorization: {a}\r\n");
    }
    head += "\r\n";
    head += body;
    head
}

/// Один HTTP-переход (без следования перенаправлениям).
pub async fn fetch_once(cfg: &Config, url: &Url, method: &str, body: &str) -> Hop {
    let mut hop = Hop {
        url: url.absolute(),
        ..Default::default()
    };
    let total = Instant::now();
    if let Err(e) = fetch_inner(cfg, url, method, body, &mut hop).await {
        hop.error = Some(e);
    }
    hop.timings.total_ms = ms_f(total.elapsed());
    hop
}

async fn fetch_inner(cfg: &Config, url: &Url, method: &str, body: &str, hop: &mut Hop) -> Result<(), String> {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    let limit = cfg.body_limit_kb.max(1) * 1024;
    let via_proxy = cfg.proxy_mode == ProxyMode::Manual && !cfg.proxy.trim().is_empty();
    let mut t = Timings::default();
    let result: Result<(), String> = async {
        if !via_proxy {
            let (s, addr) = dial(&url.host, url.port, cfg, &mut t).await?;
            hop.address = addr.to_string();
            let mut conn: Conn = if url.https {
                let (tls, info) = tls::handshake(s, &url.host, cfg.tls_versions, &["http/1.1"], timeout).await?;
                t.tls_ms = Some(info.handshake_ms);
                let trust = info.trust_error.clone();
                hop.tls = Some(info);
                if cfg.verify_tls && let Some(e) = trust {
                    return Err(format!("сертификат не прошёл проверку: {e}"));
                }
                Box::pin(tls)
            } else {
                Box::pin(s)
            };
            let req = finish_request(request_text(cfg, url, method, false, body), None, body);
            hop.request = req.clone();
            timed(timeout, "отправка запроса", conn.write_all(req.as_bytes())).await?;
            let (resp, ttfb, size, trunc) = read_response(&mut conn, method, limit, timeout).await?;
            t.ttfb_ms = ttfb;
            fill(hop, resp, size, trunc);
            return Ok(());
        }

        let (phost, pport) = crate::probe::split_host_port(&cfg.proxy, 3128)?;
        let (s, addr) = dial(&phost, pport, cfg, &mut t).await?;
        hop.address = format!("{addr} (прокси)");
        let cfg2 = cfg.clone();
        let (phost2, pport2) = (phost.clone(), pport);
        let mut redial = move || {
            let cfg = cfg2.clone();
            let h = phost2.clone();
            Box::pin(async move {
                let mut tt = Timings::default();
                let (s, _) = dial(&h, pport2, &cfg, &mut tt).await?;
                Ok::<Conn, String>(Box::pin(s))
            }) as Pin<Box<dyn std::future::Future<Output = Result<Conn, String>> + Send>>
        };
        let proxy_ip = addr.ip().to_string();
        if url.https {
            let started = Instant::now();
            let target = format!("{}:{}", url.host, url.port);
            let build = |auth: Option<&str>| {
                let mut r = format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {}\r\nProxy-Connection: keep-alive\r\n",
                    cfg.user_agent
                );
                if let Some(a) = auth {
                    r += &format!("Proxy-Authorization: {a}\r\n");
                }
                r + "\r\n"
            };
            let (conn, resp, _, _, _, auth) =
                with_proxy_auth(Box::pin(s), &build, cfg, &proxy_ip, &mut redial, "CONNECT", true).await?;
            t.proxy_ms = Some(ms_f(started.elapsed()));
            hop.proxy_auth = auth;
            if !(200..300).contains(&resp.status) {
                hop.request = build(None);
                fill(hop, resp, 0, false);
                return Err(format!("прокси отклонил CONNECT: HTTP {}", hop.status));
            }
            let (tls, info) = tls::handshake(conn, &url.host, cfg.tls_versions, &["http/1.1"], timeout).await?;
            t.tls_ms = Some(info.handshake_ms);
            let trust = info.trust_error.clone();
            hop.tls = Some(info);
            if cfg.verify_tls && let Some(e) = trust {
                return Err(format!("сертификат не прошёл проверку: {e}"));
            }
            let mut conn: Conn = Box::pin(tls);
            let req = finish_request(request_text(cfg, url, method, false, body), None, body);
            hop.request = req.clone();
            timed(timeout, "отправка запроса", conn.write_all(req.as_bytes())).await?;
            let (resp, ttfb, size, trunc) = read_response(&mut conn, method, limit, timeout).await?;
            t.ttfb_ms = ttfb;
            fill(hop, resp, size, trunc);
        } else {
            let head = request_text(cfg, url, method, true, body);
            let build = |auth: Option<&str>| finish_request(head.clone(), auth, body);
            hop.request = finish_request(head.clone(), None, body);
            let (_conn, resp, ttfb, size, trunc, auth) =
                with_proxy_auth(Box::pin(s), &build, cfg, &proxy_ip, &mut redial, method, false).await?;
            hop.proxy_auth = auth;
            t.ttfb_ms = ttfb;
            fill(hop, resp, size, trunc);
        }
        Ok(())
    }
    .await;
    hop.timings = t;
    result
}

fn fill(hop: &mut Hop, resp: HttpResp, size: usize, truncated: bool) {
    hop.status = resp.status;
    hop.response_head = resp.head.clone();
    hop.body_size = size;
    hop.body_truncated = truncated;
    hop.body = resp.body;
}

/// Абсолютный адрес из `Location` относительно текущего URL.
pub fn join_location(base: &Url, loc: &str) -> Result<Url, String> {
    let loc = loc.trim();
    if loc.contains("://") {
        return Url::parse(loc);
    }
    if let Some(rest) = loc.strip_prefix("//") {
        return Url::parse(&format!("{}://{rest}", if base.https { "https" } else { "http" }));
    }
    let path = if loc.starts_with('/') {
        loc.to_string()
    } else {
        let dir = base.path.split('?').next().unwrap_or("/");
        let dir = &dir[..dir.rfind('/').map(|i| i + 1).unwrap_or(1)];
        format!("{dir}{loc}")
    };
    Ok(Url { path, ..base.clone() })
}

/// Запрос с переходами по перенаправлениям.
pub async fn fetch(cfg: &Config, sink: Option<&Sink<Event>>) -> Result<Vec<Hop>, String> {
    let mut url = Url::parse(&cfg.url)?;
    let mut method = cfg.method.trim().to_ascii_uppercase();
    if method.is_empty() {
        method = "GET".into();
    }
    let mut body = cfg.body.clone();
    let mut hops = Vec::new();
    for _ in 0..=cfg.max_redirects {
        let hop = fetch_once(cfg, &url, &method, &body).await;
        let next = (cfg.follow_redirects && hop.error.is_none() && [301, 302, 303, 307, 308].contains(&hop.status))
            .then(|| hop.header("Location"))
            .flatten();
        if let Some(s) = sink {
            s.send(Event::Hop(Box::new(hop.clone())));
        }
        hops.push(hop);
        let Some(loc) = next else { break };
        let last = hops.last().unwrap().status;
        if last == 303 || ((last == 301 || last == 302) && method == "POST") {
            method = "GET".into();
            body.clear();
        }
        url = join_location(&url, &loc)?;
    }
    Ok(hops)
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    for i in 0..cfg.repeat.max(1) {
        tokio::select! {
            r = fetch(&cfg, Some(&sink)) => {
                if let Err(e) = r {
                    sink.send(Event::Log(e));
                    return;
                }
            }
            _ = cancel.cancelled() => return,
        }
        sink.send(Event::RunDone(i));
    }
}

/// DoH (RFC 8484): POST application/dns-message, напрямую.
pub async fn doh_post(url: &str, wire: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let u = Url::parse(url)?;
    let mut t = Timings::default();
    let cfg = Config {
        timeout_ms: timeout.as_millis() as u64,
        ..Default::default()
    };
    let (s, _) = dial(&u.host, u.port, &cfg, &mut t).await?;
    let (tls, _) = tls::handshake(s, &u.host, Versions::Auto, &["http/1.1"], timeout).await?;
    let mut conn: Conn = Box::pin(tls);
    let mut req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        u.path,
        u.host_header(),
        wire.len()
    )
    .into_bytes();
    req.extend_from_slice(wire);
    timed(timeout, "DoH", conn.write_all(&req)).await?;
    let (resp, _, _, _) = read_response(&mut conn, "POST", 65535, timeout).await?;
    if resp.status != 200 {
        return Err(format!("DoH: HTTP {}", resp.status));
    }
    Ok(resp.body)
}

pub fn render_text(r: &Report) -> String {
    let mut s = String::new();
    for (i, run) in r.runs.iter().enumerate() {
        if r.runs.len() > 1 {
            s += &format!("=== повтор {} ===\n", i + 1);
        }
        for hop in run {
            s += &format!("* {} → {}\n", hop.url, hop.address);
            if let Some(a) = &hop.proxy_auth {
                s += &format!("* прокси: {a}\n");
            }
            if let Some(t) = &hop.tls {
                s += &format!(
                    "* {} {} ALPN={} сертификат: {}\n",
                    t.version,
                    t.cipher,
                    t.alpn.clone().unwrap_or("-".into()),
                    t.trust_error.clone().unwrap_or_else(|| "доверенный".into())
                );
                for c in &t.chain {
                    s += &format!("*   {} ← {} (до {}, {} дн.)\n", c.short_subject(), c.short_issuer(), c.not_after, c.days_left);
                }
            }
            for l in hop.request.lines().take_while(|l| !l.is_empty()) {
                s += &format!("> {l}\n");
            }
            for l in hop.response_head.lines() {
                s += &format!("< {l}\n");
            }
            if let Some(e) = &hop.error {
                s += &format!("! {e}\n");
            }
            let tm = &hop.timings;
            s += &format!(
                "  dns {:.1} | tcp {:.1} | прокси {} | tls {} | ttfb {:.1} | всего {:.1} мс | тело {} Б{}\n\n",
                tm.dns_ms,
                tm.connect_ms,
                tm.proxy_ms.map(|v| format!("{v:.1}")).unwrap_or("-".into()),
                tm.tls_ms.map(|v| format!("{v:.1}")).unwrap_or("-".into()),
                tm.ttfb_ms,
                tm.total_ms,
                hop.body_size,
                if hop.body_truncated { " (обрезано)" } else { "" }
            );
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn location_join() {
        let base = Url::parse("http://a.test/x/y?z=1").unwrap();
        assert_eq!(join_location(&base, "/new").unwrap().absolute(), "http://a.test/new");
        assert_eq!(join_location(&base, "rel").unwrap().absolute(), "http://a.test/x/rel");
        assert_eq!(join_location(&base, "https://b.test/").unwrap().absolute(), "https://b.test/");
        assert_eq!(join_location(&base, "//c.test/p").unwrap().absolute(), "http://c.test/p");
    }

    #[test]
    fn chunked() {
        let raw = b"4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n";
        assert_eq!(chunked_complete(raw), Some(raw.len()));
        assert_eq!(chunked_complete(&raw[..10]), None);
        assert_eq!(decode_chunked(raw), b"Wikipedia");
    }

    async fn read_req(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if s.read(&mut b).await? == 0 {
                break;
            }
            buf.push(b[0]);
        }
        Ok(buf)
    }

    async fn server(responses: Vec<&'static str>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            for resp in responses {
                let (mut s, _) = l.accept().await.unwrap();
                let _ = read_req(&mut s).await;
                s.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn redirects_and_bodies() {
        let addr = server(vec![
            "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        ])
        .await;
        let cfg = Config {
            url: format!("http://{addr}/start"),
            timeout_ms: 2000,
            ..Default::default()
        };
        let hops = fetch(&cfg, None).await.unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].status, 302);
        assert_eq!(hops[1].status, 200);
        assert_eq!(hops[1].body_text(), "hello");
        assert!(hops[1].request.starts_with("GET /final HTTP/1.1"));
        assert!(hops[1].timings.total_ms >= hops[1].timings.ttfb_ms);
    }

    #[tokio::test]
    async fn body_limit_and_custom_headers() {
        let addr = server(vec!["HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"]).await;
        let cfg = Config {
            url: format!("http://{addr}/"),
            headers: "X-Test: 1\nUser-Agent: custom".into(),
            body_limit_kb: 1,
            ..Default::default()
        };
        let hops = fetch(&cfg, None).await.unwrap();
        assert_eq!(hops[0].body_size, 10);
        assert!(hops[0].request.contains("X-Test: 1\r\n"));
        assert!(hops[0].request.contains("User-Agent: custom\r\n"));
        assert!(!hops[0].request.contains("proxy-scanner/"));
    }

    #[tokio::test]
    async fn via_proxy_basic_auth() {
        // Прокси: первый запрос — 407, второй (с Basic) — 200.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let head = read_req(&mut s).await.unwrap();
            assert!(String::from_utf8_lossy(&head).starts_with("GET http://example.test/ HTTP/1.1"));
            s.write_all(b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let head = String::from_utf8_lossy(&read_req(&mut s).await.unwrap()).into_owned();
            assert!(head.contains("Proxy-Authorization: Basic dTpw"));
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
        });
        let cfg = Config {
            url: "http://example.test/".into(),
            proxy_mode: ProxyMode::Manual,
            proxy: addr.to_string(),
            proxy_auth: AuthMode::Auto,
            proxy_current_user: false,
            proxy_user: "u".into(),
            proxy_pass: "p".into(),
            ..Default::default()
        };
        let hops = fetch(&cfg, None).await.unwrap();
        assert_eq!(hops[0].error, None);
        assert_eq!(hops[0].status, 200);
        assert_eq!(hops[0].body_text(), "ok");
        assert!(hops[0].proxy_auth.as_deref().unwrap().contains("вход выполнен"));
    }
}
