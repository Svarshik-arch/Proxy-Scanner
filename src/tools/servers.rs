//! Встроенные серверы для работы с оборудованием: TFTP (прошивки и конфигурации),
//! HTTP (раздача файлов), приём Syslog и SNMP-уведомлений.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::Sink;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Папка с файлами (TFTP и HTTP).
    pub dir: String,
    pub bind: String,
    pub tftp: bool,
    pub tftp_port: u16,
    /// Разрешить загрузку файлов на сервер (copy running-config tftp:).
    pub tftp_write: bool,
    pub http: bool,
    pub http_port: u16,
    pub syslog: bool,
    pub syslog_port: u16,
    pub traps: bool,
    pub trap_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dir: default_dir().display().to_string(),
            bind: "0.0.0.0".into(),
            tftp: true,
            tftp_port: 69,
            tftp_write: true,
            http: false,
            http_port: 8080,
            syslog: true,
            syslog_port: 514,
            traps: true,
            trap_port: 162,
        }
    }
}

pub fn default_dir() -> PathBuf {
    crate::updates::data_dir().with_file_name("proxy-scanner-files")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Kind {
    Tftp,
    Http,
    Syslog,
    Trap,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Tftp => "TFTP",
            Kind::Http => "HTTP",
            Kind::Syslog => "Syslog",
            Kind::Trap => "SNMP-уведомления",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub at: u64,
    pub kind: Kind,
    pub from: String,
    /// Важность 0 (авария) … 7 (отладка), как в Syslog.
    pub severity: u8,
    pub text: String,
}

#[derive(Debug, Clone)]
pub enum Event {
    /// Сервер запущен (текст — где слушает) или не смог.
    Status(Kind, Result<String, String>),
    Entry(Entry),
}

fn entry(kind: Kind, from: SocketAddr, severity: u8, text: String) -> Event {
    Event::Entry(Entry { at: crate::session::now_unix(), kind, from: from.ip().to_string(), severity, text })
}

fn bind_error(port: u16, e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied && port < 1024 {
        if cfg!(windows) {
            format!("порт {port}: нет прав — запустите от администратора или выберите порт выше 1024")
        } else {
            format!("порт {port}: порты ниже 1024 требуют прав — sudo setcap cap_net_bind_service=+ep <программа> или порт выше 1024")
        }
    } else if e.kind() == std::io::ErrorKind::AddrInUse {
        format!("порт {port} уже занят другой программой")
    } else {
        format!("порт {port}: {e}")
    }
}

/// Безопасный путь внутри папки: без `..`, абсолютных путей и дисков.
pub fn safe_path(root: &Path, name: &str) -> Option<PathBuf> {
    let mut p = root.to_path_buf();
    let mut any = false;
    for part in name.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') {
            return None;
        }
        p.push(part);
        any = true;
    }
    any.then_some(p)
}

// ---------------------------------------------------------------------------
// Syslog
// ---------------------------------------------------------------------------

/// Разбор `<PRI>…`: (важность, текст без PRI).
pub fn parse_syslog(raw: &str) -> (u8, String) {
    let raw = raw.trim_end_matches(['\n', '\r', '\0']);
    if let Some(rest) = raw.strip_prefix('<')
        && let Some(end) = rest.find('>')
        && let Ok(pri) = rest[..end].parse::<u16>()
    {
        let mut text = rest[end + 1..].to_string();
        // RFC 5424: «1 2026-…» — убираем номер версии.
        if text.starts_with("1 ") {
            text = text[2..].to_string();
        }
        return ((pri % 8) as u8, text);
    }
    (6, raw.to_string())
}

pub fn severity_label(s: u8) -> &'static str {
    ["авария", "тревога", "критично", "ошибка", "предупреждение", "внимание", "инфо", "отладка"].get(s as usize).copied().unwrap_or("?")
}

async fn syslog(sock: UdpSocket, sink: Sink<Event>, cancel: CancellationToken) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, from) = tokio::select! {
            r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
            _ = cancel.cancelled() => return,
        };
        let (sev, text) = parse_syslog(&String::from_utf8_lossy(&buf[..n]));
        sink.send(entry(Kind::Syslog, from, sev, text));
    }
}

// ---------------------------------------------------------------------------
// SNMP-уведомления
// ---------------------------------------------------------------------------

pub fn describe_trap(t: &super::snmp::Trap) -> (u8, String) {
    let oid = t.trap_oid.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".");
    let name = super::snmp::trap_name(&t.trap_oid);
    let sev = match name {
        Some(n) if n.contains("упал") || n.contains("неверный") => 3,
        Some(n) if n.contains("старт") || n.contains("STP") || n.contains("изменена") => 4,
        _ => 5,
    };
    // Интересные значения: имя интерфейса, текстовые поля.
    let mut details: Vec<String> = Vec::new();
    for (o, v) in &t.vars {
        let os = o.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".");
        if os.starts_with("1.3.6.1.2.1.1.3") || os.starts_with("1.3.6.1.6.3.1.1.4.1") {
            continue;
        }
        let txt = v.text();
        if txt.is_empty() {
            continue;
        }
        let label = if os.starts_with("1.3.6.1.2.1.31.1.1.1.1.") || os.starts_with("1.3.6.1.2.1.2.2.1.2.") {
            "порт"
        } else if os.starts_with("1.3.6.1.2.1.31.1.1.1.18.") {
            "описание"
        } else if os.starts_with("1.3.6.1.2.1.2.2.1.1.") {
            "ifIndex"
        } else {
            ""
        };
        details.push(if label.is_empty() { format!("{os} = {txt}") } else { format!("{label} {txt}") });
        if details.len() >= 6 {
            break;
        }
    }
    let head = name.map(|n| n.to_string()).unwrap_or(oid);
    let text = if details.is_empty() { head } else { format!("{head}: {}", details.join(", ")) };
    (sev, format!("{text}{}", if t.inform { " (inform)" } else { "" }))
}

async fn traps(sock: UdpSocket, sink: Sink<Event>, cancel: CancellationToken) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, from) = tokio::select! {
            r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
            _ = cancel.cancelled() => return,
        };
        match super::snmp::parse_trap(&buf[..n]) {
            Some(t) => {
                if t.inform {
                    let _ = sock.send_to(&super::snmp::inform_response(&t), from).await;
                }
                let (sev, text) = describe_trap(&t);
                let from = t.agent.map(|a| SocketAddr::from((a, from.port()))).unwrap_or(from);
                sink.send(entry(Kind::Trap, from, sev, format!("{text} [community {}]", t.community)));
            }
            None => sink.send(entry(Kind::Trap, from, 7, format!("непонятный пакет {n} байт (SNMPv3?)"))),
        }
    }
}

// ---------------------------------------------------------------------------
// TFTP (RFC 1350, размер блока RFC 2348, tsize RFC 2349)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct Request {
    pub write: bool,
    pub file: String,
    pub blksize: Option<usize>,
    pub tsize: bool,
}

pub fn parse_request(p: &[u8]) -> Option<Request> {
    if p.len() < 4 {
        return None;
    }
    let op = u16::from_be_bytes([p[0], p[1]]);
    if op != 1 && op != 2 {
        return None;
    }
    let parts: Vec<String> = p[2..].split(|b| *b == 0).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
    let file = parts.first()?.clone();
    let mut r = Request { write: op == 2, file, blksize: None, tsize: false };
    let mut i = 2;
    while i + 1 < parts.len() {
        match parts[i].to_ascii_lowercase().as_str() {
            "blksize" => r.blksize = parts[i + 1].parse::<usize>().ok().map(|b| b.clamp(8, 65464)),
            "tsize" => r.tsize = true,
            _ => {}
        }
        i += 2;
    }
    Some(r)
}

fn error_packet(code: u16, msg: &str) -> Vec<u8> {
    let mut v = vec![0, 5];
    v.extend(code.to_be_bytes());
    v.extend(msg.as_bytes());
    v.push(0);
    v
}

fn oack(opts: &[(&str, String)]) -> Vec<u8> {
    let mut v = vec![0, 6];
    for (k, val) in opts {
        v.extend(k.as_bytes());
        v.push(0);
        v.extend(val.as_bytes());
        v.push(0);
    }
    v
}

/// Отправить пакет и дождаться ACK с номером `block`.
async fn send_wait(sock: &UdpSocket, pkt: &[u8], block: u16) -> Result<(), String> {
    let mut buf = [0u8; 1024];
    for _ in 0..5 {
        sock.send(pkt).await.map_err(|e| e.to_string())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while let Ok(r) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
            let n = r.map_err(|e| e.to_string())?;
            if n >= 4 && buf[1] == 4 && u16::from_be_bytes([buf[2], buf[3]]) == block {
                return Ok(());
            }
            if n >= 4 && buf[1] == 5 {
                return Err(format!("клиент прервал: {}", String::from_utf8_lossy(&buf[4..n]).trim_end_matches('\0')));
            }
        }
    }
    Err("клиент не отвечает".into())
}

async fn tftp_transfer(root: PathBuf, allow_write: bool, req: Request, peer: SocketAddr, bind: String) -> Result<String, String> {
    let sock = UdpSocket::bind(format!("{bind}:0")).await.map_err(|e| e.to_string())?;
    sock.connect(peer).await.map_err(|e| e.to_string())?;
    let Some(path) = safe_path(&root, &req.file) else {
        let _ = sock.send(&error_packet(2, "access violation")).await;
        return Err(format!("запрещённый путь {}", req.file));
    };
    let blk = req.blksize.unwrap_or(512);
    if !req.write {
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => {
                let _ = sock.send(&error_packet(1, "file not found")).await;
                return Err(format!("нет файла {}", req.file));
            }
        };
        let mut opts = Vec::new();
        if req.blksize.is_some() {
            opts.push(("blksize", blk.to_string()));
        }
        if req.tsize {
            opts.push(("tsize", data.len().to_string()));
        }
        if !opts.is_empty() {
            send_wait(&sock, &oack(&opts), 0).await?;
        }
        let mut block: u16 = 1;
        let mut off = 0usize;
        loop {
            let end = (off + blk).min(data.len());
            let mut pkt = vec![0, 3];
            pkt.extend(block.to_be_bytes());
            pkt.extend(&data[off..end]);
            send_wait(&sock, &pkt, block).await?;
            if end - off < blk {
                break;
            }
            off = end;
            block = block.wrapping_add(1);
        }
        Ok(format!("отдан {} ({} байт)", req.file, data.len()))
    } else {
        if !allow_write {
            let _ = sock.send(&error_packet(2, "write disabled")).await;
            return Err(format!("загрузка {} запрещена в настройках", req.file));
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Существующий файл не затираем — кладём рядом с номером.
        let mut target = path.clone();
        let mut n = 1;
        while target.exists() {
            n += 1;
            let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let ext = path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
            target = path.with_file_name(format!("{stem}-{n}{ext}"));
        }
        let first = if req.blksize.is_some() { oack(&[("blksize", blk.to_string())]) } else { vec![0, 4, 0, 0] };
        let mut data = Vec::new();
        let mut expect: u16 = 1;
        let mut last = first;
        let mut buf = vec![0u8; blk + 4];
        'outer: loop {
            for attempt in 0..5 {
                sock.send(&last).await.map_err(|e| e.to_string())?;
                match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
                    Ok(Ok(n)) if n >= 4 && buf[1] == 3 => {
                        let b = u16::from_be_bytes([buf[2], buf[3]]);
                        if b == expect {
                            data.extend_from_slice(&buf[4..n]);
                            if data.len() > 512 * 1024 * 1024 {
                                let _ = sock.send(&error_packet(3, "too big")).await;
                                return Err("файл больше 512 МБ".into());
                            }
                            let mut ack = vec![0, 4];
                            ack.extend(b.to_be_bytes());
                            last = ack;
                            expect = expect.wrapping_add(1);
                            if n - 4 < blk {
                                sock.send(&last).await.map_err(|e| e.to_string())?;
                                break 'outer;
                            }
                            continue 'outer;
                        }
                    }
                    Ok(Ok(n)) if n >= 4 && buf[1] == 5 => return Err("клиент прервал передачу".into()),
                    _ => {}
                }
                if attempt == 4 {
                    return Err("клиент перестал присылать данные".into());
                }
            }
        }
        std::fs::write(&target, &data).map_err(|e| e.to_string())?;
        Ok(format!("принят {} ({} байт) → {}", req.file, data.len(), target.display()))
    }
}

async fn tftp(sock: UdpSocket, cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = tokio::select! {
            r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
            _ = cancel.cancelled() => return,
        };
        let Some(req) = parse_request(&buf[..n]) else { continue };
        let sink = sink.clone();
        let root = PathBuf::from(&cfg.dir);
        let (w, bind) = (cfg.tftp_write, cfg.bind.clone());
        sink.send(entry(Kind::Tftp, from, 6, format!("{} {}", if req.write { "приём" } else { "запрос" }, req.file)));
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let r = tokio::select! {
                r = tftp_transfer(root, w, req, from, bind) => r,
                _ = cancel.cancelled() => return,
            };
            match r {
                Ok(t) => sink.send(entry(Kind::Tftp, from, 6, t)),
                Err(e) => sink.send(entry(Kind::Tftp, from, 3, e)),
            }
        });
    }
}

// ---------------------------------------------------------------------------
// HTTP: раздача файлов из папки (GET/HEAD), список файлов
// ---------------------------------------------------------------------------

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn listing(root: &Path, dir: &Path, url: &str) -> String {
    let mut items: Vec<(String, bool, u64)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path().is_dir(), e.metadata().map(|m| m.len()).unwrap_or(0)))
        .collect();
    items.sort();
    let base = if url.ends_with('/') { url.to_string() } else { format!("{url}/") };
    let mut s = format!("<!doctype html><meta charset=utf-8><title>{0}</title><h3>{0}</h3><ul>", html_escape(&base));
    if dir != root {
        s += "<li><a href=\"../\">..</a></li>";
    }
    for (n, d, size) in items {
        let n2 = html_escape(&n);
        s += &if d { format!("<li><a href=\"{base}{n2}/\">{n2}/</a></li>") } else { format!("<li><a href=\"{base}{n2}\">{n2}</a> — {size} байт</li>") };
    }
    s + "</ul>"
}

async fn http_conn(mut s: tokio::net::TcpStream, root: PathBuf) -> Result<String, String> {
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
        let r = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf[n..])).await.map_err(|_| "тайм-аут".to_string())?.map_err(|e| e.to_string())?;
        if r == 0 {
            return Err("соединение закрыто".into());
        }
        n += r;
        if n == buf.len() {
            return Err("слишком длинный запрос".into());
        }
    }
    let head = String::from_utf8_lossy(&buf[..n]).into_owned();
    let line = head.lines().next().unwrap_or("");
    let mut w = line.split_whitespace();
    let method = w.next().unwrap_or("");
    let path = url_decode(w.next().unwrap_or("/").split('?').next().unwrap_or("/"));
    let respond = async |s: &mut tokio::net::TcpStream, code: &str, ctype: &str, body: &[u8], head_only: bool| {
        let h = format!("HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = s.write_all(h.as_bytes()).await;
        if !head_only {
            let _ = s.write_all(body).await;
        }
    };
    if method != "GET" && method != "HEAD" {
        respond(&mut s, "405 Method Not Allowed", "text/plain", b"only GET", false).await;
        return Ok(format!("{method} {path} → 405"));
    }
    let target = if path.trim_matches('/').is_empty() { Some(root.clone()) } else { safe_path(&root, &path) };
    let Some(target) = target else {
        respond(&mut s, "403 Forbidden", "text/plain", b"forbidden", false).await;
        return Ok(format!("{path} → 403"));
    };
    if target.is_dir() {
        let body = listing(&root, &target, &path);
        respond(&mut s, "200 OK", "text/html; charset=utf-8", body.as_bytes(), method == "HEAD").await;
        return Ok(format!("{path} → список"));
    }
    match std::fs::read(&target) {
        Ok(data) => {
            respond(&mut s, "200 OK", "application/octet-stream", &data, method == "HEAD").await;
            Ok(format!("{path} → {} байт", data.len()))
        }
        Err(_) => {
            respond(&mut s, "404 Not Found", "text/plain", b"not found", false).await;
            Ok(format!("{path} → 404"))
        }
    }
}

async fn http(l: TcpListener, cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    loop {
        let (s, from) = tokio::select! {
            r = l.accept() => match r { Ok(x) => x, Err(_) => continue },
            _ = cancel.cancelled() => return,
        };
        let sink = sink.clone();
        let root = PathBuf::from(&cfg.dir);
        tokio::spawn(async move {
            match http_conn(s, root).await {
                Ok(t) => sink.send(entry(Kind::Http, from, 6, t)),
                Err(e) => sink.send(entry(Kind::Http, from, 4, e)),
            }
        });
    }
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let _ = std::fs::create_dir_all(&cfg.dir);
    let mut set = tokio::task::JoinSet::new();
    let udp = async |port: u16| UdpSocket::bind(format!("{}:{port}", cfg.bind)).await.map_err(|e| bind_error(port, e));
    if cfg.tftp {
        match udp(cfg.tftp_port).await {
            Ok(s) => {
                sink.send(Event::Status(Kind::Tftp, Ok(format!("UDP {}", cfg.tftp_port))));
                set.spawn(tftp(s, cfg.clone(), sink.clone(), cancel.clone()));
            }
            Err(e) => sink.send(Event::Status(Kind::Tftp, Err(e))),
        }
    }
    if cfg.syslog {
        match udp(cfg.syslog_port).await {
            Ok(s) => {
                sink.send(Event::Status(Kind::Syslog, Ok(format!("UDP {}", cfg.syslog_port))));
                set.spawn(syslog(s, sink.clone(), cancel.clone()));
            }
            Err(e) => sink.send(Event::Status(Kind::Syslog, Err(e))),
        }
    }
    if cfg.traps {
        match udp(cfg.trap_port).await {
            Ok(s) => {
                sink.send(Event::Status(Kind::Trap, Ok(format!("UDP {}", cfg.trap_port))));
                set.spawn(traps(s, sink.clone(), cancel.clone()));
            }
            Err(e) => sink.send(Event::Status(Kind::Trap, Err(e))),
        }
    }
    if cfg.http {
        match TcpListener::bind(format!("{}:{}", cfg.bind, cfg.http_port)).await {
            Ok(l) => {
                sink.send(Event::Status(Kind::Http, Ok(format!("TCP {}", cfg.http_port))));
                set.spawn(http(l, cfg.clone(), sink.clone(), cancel.clone()));
            }
            Err(e) => sink.send(Event::Status(Kind::Http, Err(bind_error(cfg.http_port, e)))),
        }
    }
    if set.is_empty() {
        return;
    }
    cancel.cancelled().await;
    set.abort_all();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_parse() {
        assert_eq!(parse_syslog("<187>42: Nov 18 10:00:01: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n"), (3, "42: Nov 18 10:00:01: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down".into()));
        assert_eq!(parse_syslog("<14>1 2026-11-18T10:00:00Z host app - - - hi").0, 6);
        assert_eq!(parse_syslog("no pri").1, "no pri");
    }

    #[test]
    fn paths() {
        let r = Path::new("/srv");
        assert_eq!(safe_path(r, "/sw1.cfg"), Some(PathBuf::from("/srv/sw1.cfg")));
        assert_eq!(safe_path(r, "fw/image.bin"), Some(PathBuf::from("/srv/fw/image.bin")));
        assert_eq!(safe_path(r, "../etc/passwd"), None);
        assert_eq!(safe_path(r, "C:\\x"), None);
        assert_eq!(url_decode("/a%20b+c"), "/a b c");
    }

    #[test]
    fn tftp_request() {
        let mut p = vec![0, 1];
        p.extend(b"sw1.cfg\x00octet\x00blksize\x001428\x00tsize\x000\x00");
        assert_eq!(parse_request(&p), Some(Request { write: false, file: "sw1.cfg".into(), blksize: Some(1428), tsize: true }));
    }

    #[tokio::test]
    async fn tftp_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ps-tftp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..1300u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("fw.bin"), &data).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let cfg = Config { dir: dir.display().to_string(), bind: "127.0.0.1".into(), ..Default::default() };
        let (sink, rx) = Sink::new(None);
        let cancel = CancellationToken::new();
        tokio::spawn(tftp(sock, cfg, sink, cancel.clone()));
        // Клиент: скачать с blksize 512 (без опций).
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut req = vec![0, 1];
        req.extend(b"fw.bin\0octet\0");
        c.send_to(&req, ("127.0.0.1", port)).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 600];
        loop {
            let (n, from) = c.recv_from(&mut buf).await.unwrap();
            assert_eq!(buf[1], 3);
            got.extend_from_slice(&buf[4..n]);
            c.send_to(&[0, 4, buf[2], buf[3]], from).await.unwrap();
            if n - 4 < 512 {
                break;
            }
        }
        assert_eq!(got, data);
        // Загрузить на сервер.
        let mut req = vec![0, 2];
        req.extend(b"up.cfg\0octet\0");
        c.send_to(&req, ("127.0.0.1", port)).await.unwrap();
        let (_, from) = c.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..4], &[0, 4, 0, 0]);
        c.send_to(&[&[0u8, 3, 0, 1][..], b"hostname sw1\n"].concat(), from).await.unwrap();
        let (_, _) = c.recv_from(&mut buf).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(std::fs::read_to_string(dir.join("up.cfg")).unwrap(), "hostname sw1\n");
        cancel.cancel();
        assert!(rx.try_iter().count() >= 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trap_v2() {
        use crate::tools::snmp::*;
        // Собираем trap v2c linkDown вручную.
        let ad = |t: u8, c: &[u8]| crate::tools::ad::tlv(t, c);
        let vb = |oid: &str, val: Vec<u8>| {
            let mut v = encode_oid(&parse_oid(oid));
            v.extend(val);
            ad(0x30, &v)
        };
        let mut vbl = vb("1.3.6.1.2.1.1.3.0", ad(0x43, &[1]));
        vbl.extend(vb("1.3.6.1.6.3.1.1.4.1.0", encode_oid(&parse_oid("1.3.6.1.6.3.1.1.5.3"))));
        vbl.extend(vb("1.3.6.1.2.1.31.1.1.1.1.5", ad(0x04, b"Gi0/5")));
        let mut pdu = ad(0x02, &[7]);
        pdu.extend(ad(0x02, &[0]));
        pdu.extend(ad(0x02, &[0]));
        pdu.extend(ad(0x30, &vbl));
        let mut msg = ad(0x02, &[1]);
        msg.extend(ad(0x04, b"public"));
        msg.extend(ad(0xA7, &pdu));
        let t = parse_trap(&ad(0x30, &msg)).unwrap();
        let (sev, text) = describe_trap(&t);
        assert_eq!(sev, 3);
        assert!(text.contains("линк упал") && text.contains("порт Gi0/5"), "{text}");
    }
}
