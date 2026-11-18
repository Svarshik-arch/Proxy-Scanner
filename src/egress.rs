//! Проверка обхода прокси: можно ли с рабочей станции выйти наружу напрямую,
//! минуя прокси, — по TCP-портам, через внешний DNS, по HTTP и HTTPS.
//!
//! Для закрытого контура есть встроенный «слушатель»: его запускают на машине
//! в другом сегменте, он отвечает меткой [`MARKER`], и клиент видит, что
//! соединение действительно дошло до слушателя (а не было «принято» межсетевым
//! экраном или прозрачным прокси).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Метка, которой отвечает слушатель.
pub const MARKER: &str = "PROXY-SCANNER-EGRESS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressKind {
    Tcp,
    Dns,
    Http,
    Https,
}

impl EgressKind {
    pub fn label(self) -> &'static str {
        match self {
            EgressKind::Tcp => "TCP",
            EgressKind::Dns => "DNS (UDP)",
            EgressKind::Http => "HTTP",
            EgressKind::Https => "HTTPS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressStatus {
    /// Прямой выход есть (подтверждён ответом).
    Open,
    /// Узел явно отказал в подключении (порт закрыт на той стороне, но пакет дошёл).
    Refused,
    /// Ответа нет — заблокировано межсетевым экраном.
    Filtered,
    /// Перехвачено прозрачным прокси / подменено.
    Intercepted,
    /// Проверка не выполнена.
    Error,
}

impl EgressStatus {
    pub fn label(self) -> &'static str {
        match self {
            EgressStatus::Open => "ОТКРЫТ",
            EgressStatus::Refused => "отказ",
            EgressStatus::Filtered => "заблокирован",
            EgressStatus::Intercepted => "перехвачен",
            EgressStatus::Error => "ошибка",
        }
    }

    /// Означает ли статус, что трафик уходит наружу мимо прокси.
    pub fn is_leak(self) -> bool {
        matches!(self, EgressStatus::Open | EgressStatus::Refused)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressItem {
    pub kind: EgressKind,
    pub target: String,
    pub status: EgressStatus,
    /// Ответ получен именно от слушателя Proxy Scanner.
    pub confirmed: bool,
    pub rtt_ms: Option<u32>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct EgressConfig {
    /// Узел, куда пробуем подключаться по TCP (portquiz.net или свой слушатель).
    pub target: String,
    pub ports: Vec<u16>,
    pub dns_servers: Vec<Ipv4Addr>,
    /// Имя для DNS-запросов и сайт для HTTP/HTTPS.
    pub test_domain: String,
    pub timeout: Duration,
    pub concurrency: usize,
}

fn ms(t: Instant) -> Option<u32> {
    Some(t.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

async fn resolve(host: &str, timeout: Duration) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let addrs = tokio::time::timeout(timeout, tokio::net::lookup_host((host, 0)))
        .await
        .map_err(|_| format!("таймаут разрешения имени «{host}»"))?
        .map_err(|e| format!("имя «{host}» не разрешается ({e})"))?;
    addrs
        .filter_map(|a| match a {
            SocketAddr::V4(v) => Some(*v.ip()),
            SocketAddr::V6(_) => None,
        })
        .next()
        .ok_or_else(|| format!("у «{host}» нет IPv4-адреса"))
}

/// Одна TCP-проверка: подключение и, если пришёл ответ, проверка метки слушателя.
pub async fn check_tcp(ip: Ipv4Addr, port: u16, label: &str, timeout: Duration) -> EgressItem {
    let target = format!("{label}:{port}");
    let started = Instant::now();
    let item = |status, confirmed, rtt, detail: String| EgressItem {
        kind: EgressKind::Tcp,
        target: target.clone(),
        status,
        confirmed,
        rtt_ms: rtt,
        detail,
    };
    match tokio::time::timeout(timeout, TcpStream::connect((ip, port))).await {
        Err(_) => item(EgressStatus::Filtered, false, None, "нет ответа — порт блокируется".into()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => item(
            EgressStatus::Refused,
            false,
            ms(started),
            "узел ответил отказом: пакеты наружу проходят, порт на той стороне закрыт".into(),
        ),
        Ok(Err(e)) => item(EgressStatus::Filtered, false, None, format!("подключение не удалось: {e}")),
        Ok(Ok(mut s)) => {
            let rtt = ms(started);
            let mut buf = [0u8; 128];
            let banner = match tokio::time::timeout(Duration::from_millis(1500), s.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).into_owned(),
                _ => String::new(),
            };
            if banner.starts_with(MARKER) {
                item(
                    EgressStatus::Open,
                    true,
                    rtt,
                    format!("подтверждено слушателем: {}", banner.trim()),
                )
            } else {
                item(EgressStatus::Open, false, rtt, "соединение установлено".into())
            }
        }
    }
}

/// DNS-запрос типа A для `name` с идентификатором `id`.
pub fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, QDCOUNT=1
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // конец имени, QTYPE=A, QCLASS=IN
    q
}

pub async fn check_dns(server: Ipv4Addr, port: u16, name: &str, timeout: Duration) -> EgressItem {
    let target = format!("{server}:{port}");
    let started = Instant::now();
    let r: Result<(usize, u8), String> = async {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.map_err(|e| e.to_string())?;
        let id: u16 = (started.elapsed().subsec_nanos() as u16) ^ 0x5a5a;
        sock.send_to(&dns_query(id, name), (server, port))
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = [0u8; 512];
        loop {
            let (n, from) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
                .await
                .map_err(|_| "нет ответа".to_string())?
                .map_err(|e| e.to_string())?;
            if from.ip() == std::net::IpAddr::V4(server) && n >= 12 && buf[..2] == id.to_be_bytes() {
                return Ok((u16::from_be_bytes([buf[6], buf[7]]) as usize, buf[3] & 0x0f));
            }
        }
    }
    .await;
    match r {
        Ok((answers, rcode)) => EgressItem {
            kind: EgressKind::Dns,
            target,
            status: EgressStatus::Open,
            confirmed: false,
            rtt_ms: ms(started),
            detail: format!(
                "внешний DNS отвечает напрямую (ответов: {answers}, код {rcode}) — имена можно разрешать мимо корпоративных DNS"
            ),
        },
        Err(e) => EgressItem {
            kind: EgressKind::Dns,
            target,
            status: EgressStatus::Filtered,
            confirmed: false,
            rtt_ms: None,
            detail: format!("заблокирован ({e})"),
        },
    }
}

/// Прямой HTTP-запрос без прокси. Наличие `Via` и подобных заголовков означает
/// прозрачный прокси на пути.
pub async fn check_http(host: &str, port: u16, timeout: Duration) -> EgressItem {
    let target = format!("http://{host}:{port}/");
    let started = Instant::now();
    let r: Result<(u16, String), String> = async {
        let ip = resolve(host, timeout).await?;
        let mut s = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| "нет ответа".to_string())?
            .map_err(|e| e.to_string())?;
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: proxy-scanner\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 8192];
        let n = tokio::time::timeout(timeout, s.read(&mut buf))
            .await
            .map_err(|_| "нет ответа на запрос".to_string())?
            .map_err(|e| e.to_string())?;
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or("ответ не является HTTP")?;
        Ok((status, head))
    }
    .await;
    match r {
        Ok((status, head)) => {
            let lower = head.to_ascii_lowercase();
            let proxied = ["\nvia:", "\nx-cache", "\nproxy-", "\nx-squid", "squid"]
                .iter()
                .any(|m| lower.contains(m));
            let (st, detail) = if proxied || status == 407 {
                (
                    EgressStatus::Intercepted,
                    format!("HTTP {status}: запрос перехвачен прозрачным прокси"),
                )
            } else {
                (EgressStatus::Open, format!("HTTP {status}: прямой выход по HTTP разрешён"))
            };
            EgressItem { kind: EgressKind::Http, target, status: st, confirmed: false, rtt_ms: ms(started), detail }
        }
        Err(e) => EgressItem {
            kind: EgressKind::Http,
            target,
            status: if e.contains("разреш") { EgressStatus::Error } else { EgressStatus::Filtered },
            confirmed: false,
            rtt_ms: None,
            detail: e,
        },
    }
}

/// Прямое TLS-подключение без прокси; издатель сертификата показывает,
/// не стоит ли на пути прозрачная SSL-инспекция.
pub async fn check_https(host: &str, port: u16, timeout: Duration) -> EgressItem {
    let target = format!("{host}:{port}");
    let started = Instant::now();
    match crate::probe::direct_reference(host, port, timeout).await {
        Ok(cert) => EgressItem {
            kind: EgressKind::Https,
            target,
            status: EgressStatus::Open,
            confirmed: false,
            rtt_ms: ms(started),
            detail: format!(
                "прямой выход по HTTPS разрешён; издатель сертификата «{}» (если это CA вашей \
                 организации — на пути прозрачная SSL-инспекция)",
                cert.issuer
            ),
        },
        Err(e) => EgressItem {
            kind: EgressKind::Https,
            target,
            status: if e.contains("не разрешается") { EgressStatus::Error } else { EgressStatus::Filtered },
            confirmed: false,
            rtt_ms: None,
            detail: e,
        },
    }
}

/// Полная проверка; результаты отдаются по одному через `on_item`.
pub async fn run(
    cfg: EgressConfig,
    cancel: CancellationToken,
    on_item: impl Fn(EgressItem) + Send + Sync + 'static,
) {
    let on_item = Arc::new(on_item);
    let t = cfg.timeout;

    // Прямые HTTP/HTTPS и DNS.
    if !cfg.test_domain.trim().is_empty() {
        let d = cfg.test_domain.trim().to_string();
        on_item(check_http(&d, 80, t).await);
        if cancel.is_cancelled() {
            return;
        }
        on_item(check_https(&d, 443, t).await);
    }
    for &server in &cfg.dns_servers {
        if cancel.is_cancelled() {
            return;
        }
        let name = if cfg.test_domain.trim().is_empty() { "example.com" } else { cfg.test_domain.trim() };
        on_item(check_dns(server, 53, name, t).await);
    }

    // TCP-порты до тестового узла.
    if cfg.target.trim().is_empty() || cfg.ports.is_empty() {
        return;
    }
    let label = cfg.target.trim().to_string();
    let ip = match resolve(&label, t).await {
        Ok(ip) => ip,
        Err(e) => {
            on_item(EgressItem {
                kind: EgressKind::Tcp,
                target: label,
                status: EgressStatus::Error,
                confirmed: false,
                rtt_ms: None,
                detail: format!(
                    "{e}. Если внешний DNS закрыт, укажите IP-адрес тестового узла или своего слушателя"
                ),
            });
            return;
        }
    };
    let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for &port in &cfg.ports {
        let permit = tokio::select! {
            p = sem.clone().acquire_owned() => match p { Ok(p) => p, Err(_) => break },
            _ = cancel.cancelled() => break,
        };
        let (on_item, label) = (on_item.clone(), label.clone());
        set.spawn(async move {
            on_item(check_tcp(ip, port, &label, t).await);
            drop(permit);
        });
    }
    while set.join_next().await.is_some() {}
}

/// Слушатель для закрытого контура: принимает подключения на указанных портах
/// и отвечает меткой. Возвращает список портов, которые удалось занять, и ошибки.
pub async fn start_listener(
    ports: &[u16],
    cancel: CancellationToken,
) -> (Vec<u16>, Vec<String>) {
    let host = crate::session::computer_name();
    let banner = Arc::new(format!("{MARKER} {host}\n"));
    let (mut ok, mut errors) = (Vec::new(), Vec::new());
    for &port in ports {
        match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(l) => {
                ok.push(port);
                let (cancel, banner) = (cancel.clone(), banner.clone());
                tokio::spawn(async move {
                    loop {
                        let accepted = tokio::select! {
                            a = l.accept() => a,
                            _ = cancel.cancelled() => break,
                        };
                        if let Ok((mut s, _)) = accepted {
                            let banner = banner.clone();
                            tokio::spawn(async move {
                                let _ = s.write_all(banner.as_bytes()).await;
                                let _ = s.shutdown().await;
                            });
                        }
                    }
                });
            }
            Err(e) => errors.push(format!("{port}: {e}")),
        }
    }
    (ok, errors)
}

pub fn parse_dns_servers(text: &str) -> Result<Vec<Ipv4Addr>, String> {
    text.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().map_err(|_| format!("некорректный адрес DNS-сервера «{s}»")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_format() {
        let q = dns_query(0x1234, "example.com");
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&q[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
        assert_eq!(parse_dns_servers("8.8.8.8, 1.1.1.1").unwrap().len(), 2);
        assert!(parse_dns_servers("8.8.8").is_err());
    }

    #[tokio::test]
    async fn listener_confirms_and_closed_port_is_refused() {
        // Свободный порт для слушателя.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let cancel = CancellationToken::new();
        let (ok, errors) = start_listener(&[port], cancel.clone()).await;
        assert_eq!(ok, vec![port], "{errors:?}");

        // Windows при отказе (RST) повторяет попытку около 2 с — даём запас.
        let t = Duration::from_secs(6);
        let item = check_tcp(Ipv4Addr::LOCALHOST, port, "localhost", t).await;
        assert_eq!(item.status, EgressStatus::Open);
        assert!(item.confirmed, "{item:?}");

        // Порт без слушателя: отказ (пакеты доходят).
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cport = closed.local_addr().unwrap().port();
        drop(closed);
        let item = check_tcp(Ipv4Addr::LOCALHOST, cport, "localhost", t).await;
        assert_eq!(item.status, EgressStatus::Refused);
        assert!(item.status.is_leak());
        cancel.cancel();
    }

    #[tokio::test]
    async fn dns_answer_and_silence() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, from)) = server.recv_from(&mut buf).await {
                let mut resp = buf[..n].to_vec();
                resp[2] = 0x81;
                resp[3] = 0x80;
                resp[7] = 1; // ANCOUNT = 1
                let _ = server.send_to(&resp, from).await;
            }
        });
        let item = check_dns(Ipv4Addr::LOCALHOST, port, "example.com", Duration::from_secs(2)).await;
        assert_eq!(item.status, EgressStatus::Open, "{item:?}");

        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sport = silent.local_addr().unwrap().port();
        let item = check_dns(Ipv4Addr::LOCALHOST, sport, "example.com", Duration::from_millis(300)).await;
        assert_eq!(item.status, EgressStatus::Filtered);
        drop(silent);
    }

    #[tokio::test]
    async fn transparent_proxy_is_detected() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nVia: 1.1 squid\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let item = check_http("127.0.0.1", port, Duration::from_secs(2)).await;
        assert_eq!(item.status, EgressStatus::Intercepted, "{item:?}");
    }
}
