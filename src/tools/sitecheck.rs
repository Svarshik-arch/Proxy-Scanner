//! «Почему не открывается сайт?» — сквозная проверка одного адреса:
//! DNS (системный и внешний) → TCP → TLS → HTTP напрямую → системный прокси / PAC →
//! каждый указанный прокси. В конце — вывод одной-двумя строками, что мешает.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;
use super::dns::{self, Server, Transport};
use super::dnsproto::Query;
use super::http::{self, ProxyMode};
use super::urlcheck::{self, Outcome, UrlRule};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub url: String,
    /// Внешние DNS-серверы для сравнения (в закрытом контуре можно оставить пустым).
    pub external_dns: String,
    /// Прокси `узел:порт`, через которые проверить адрес.
    pub proxies: String,
    /// Проверить системный прокси и PAC-файл этой машины.
    pub system_proxy: bool,
    pub timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: String::new(),
            external_dns: "8.8.8.8, 77.88.8.8".into(),
            proxies: String::new(),
            system_proxy: true,
            timeout_ms: 8000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl Status {
    pub fn mark(self) -> &'static str {
        match self {
            Status::Ok => "✔",
            Status::Warn => "⚠",
            Status::Fail => "✖",
            Status::Skip => "–",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    /// Этап: DNS, TCP, TLS, HTTP, прокси.
    pub stage: String,
    pub title: String,
    pub status: Status,
    pub detail: String,
    pub ms: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub url: String,
    pub steps: Vec<Step>,
    /// Итог: главная причина первой строкой.
    pub verdict: Vec<String>,
    /// Итог хороший (сайт открывается хотя бы одним путём, которым ходит пользователь).
    pub ok: bool,
}

#[derive(Debug, Clone)]
pub enum Event {
    Step(Box<Step>),
    Verdict(Vec<String>, bool),
    Log(String),
}

fn step(stage: &str, title: impl Into<String>, status: Status, detail: impl Into<String>, ms: Option<f64>) -> Step {
    Step {
        stage: stage.into(),
        title: title.into(),
        status,
        detail: detail.into(),
        ms,
    }
}

/// Что выяснили по ходу — для вывода.
#[derive(Default)]
struct Facts {
    dns_system: Option<Vec<String>>,
    dns_system_error: Option<String>,
    dns_external: Option<Vec<String>>,
    dns_differs: bool,
    tcp_ok: Option<bool>,
    tcp_error: String,
    tls_untrusted: Option<String>,
    direct: Option<(Outcome, String)>,
    direct_issuer: Option<String>,
    /// Системный прокси/PAC: (прокси, итог, подробности).
    system: Option<(String, Outcome, String)>,
    system_direct: bool,
    proxies: Vec<(String, Outcome, String, Option<String>)>,
}

fn local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("192.0.2.1:9")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

/// Прокси, который система выбрала бы для адреса: (описание источника, `узел:порт` или пусто — напрямую).
async fn system_proxy_for(url: &str, timeout: Duration) -> Result<Option<(String, String)>, String> {
    let info = tokio::task::spawn_blocking(crate::pac::system_info).await.map_err(|e| e.to_string())?;
    for s in &info.settings {
        if let Some(pac_url) = &s.pac_url {
            let src = crate::pac::fetch(pac_url, timeout).await.map_err(|e| format!("PAC {pac_url}: {e}"))?;
            let url = url.to_string();
            let ip = local_ip();
            let res = tokio::task::spawn_blocking(move || {
                let mut e = crate::pac::PacEngine::new(&src, &ip)?;
                e.find(&url)
            })
            .await
            .map_err(|e| e.to_string())??;
            let first = crate::pac::parse_result(&res)
                .into_iter()
                .find(|p| p.kind == "PROXY" || p.kind == "HTTP" || p.kind == "HTTPS");
            let src = format!("{} → {res}", s.source);
            return Ok(Some((src, first.map(|p| format!("{}:{}", p.host, p.port)).unwrap_or_default())));
        }
    }
    let https = url.starts_with("https");
    for s in &info.settings {
        if s.source.contains("исключения") || s.source.contains("NO_PROXY") || s.source.contains("no_proxy") {
            continue;
        }
        let v = s.value.trim();
        // «http=a:3128;https=b:3128» или «a:3128».
        let pick = if v.contains('=') {
            v.split(';').find_map(|p| {
                let (k, a) = p.split_once('=')?;
                let k = k.trim().to_ascii_lowercase();
                ((https && k == "https") || (!https && k == "http")).then(|| a.trim().to_string())
            })
        } else if s.source.contains("WinHTTP") {
            v.lines()
                .find_map(|l| l.split_once("Proxy Server(s)").or_else(|| l.split_once("Прокси-сервер")))
                .and_then(|(_, rest)| rest.split(':').skip(1).collect::<Vec<_>>().join(":").split_whitespace().next().map(String::from))
        } else {
            Some(v.to_string())
        };
        if let Some(p) = pick {
            let p = p.trim_start_matches("http://").trim_start_matches("https://").trim_end_matches('/').to_string();
            if !p.is_empty() && p.contains(':') {
                return Ok(Some((s.source.clone(), p)));
            }
        }
    }
    Ok(None)
}

async fn dns_ask(server: &Server, name: &str, timeout: Duration) -> Result<Vec<String>, String> {
    let q = Query::new(dns::rand_id(), name, 1);
    let a = dns::query(server, &q, timeout, 1).await;
    if let Some(e) = a.error {
        return Err(e);
    }
    if a.rcode != "NOERROR" {
        return Err(a.rcode);
    }
    let mut v: Vec<String> = a.answers.iter().filter(|r| r.rtype == "A").map(|r| r.data.clone()).collect();
    v.sort();
    if v.is_empty() {
        return Err("нет A-записей".into());
    }
    Ok(v)
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let raw = cfg.url.trim();
    if raw.is_empty() {
        return sink.send(Event::Log("укажите адрес сайта".into()));
    }
    let url_s = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}/") };
    let url = match crate::probe::Url::parse(&url_s) {
        Ok(u) => u,
        Err(e) => return sink.send(Event::Log(e)),
    };
    let timeout = Duration::from_millis(cfg.timeout_ms.max(500));
    let mut f = Facts::default();
    let send = |s: Step| sink.send(Event::Step(Box::new(s)));
    let host_is_ip = url.host.parse::<IpAddr>().is_ok();

    // --- DNS ---
    let mut target_ip: Option<IpAddr> = url.host.parse().ok();
    if !host_is_ip {
        let t = Instant::now();
        match tokio::time::timeout(timeout, tokio::net::lookup_host((url.host.as_str(), url.port))).await {
            Ok(Ok(addrs)) => {
                let mut v: Vec<String> = addrs.filter(|a| a.is_ipv4()).map(|a| a.ip().to_string()).collect();
                v.sort();
                v.dedup();
                target_ip = v.first().and_then(|s| s.parse().ok());
                send(step("DNS", "Системный резолвер", Status::Ok, v.join(", "), Some(super::ms_f(t.elapsed()))));
                f.dns_system = Some(v);
            }
            Ok(Err(e)) => {
                send(step("DNS", "Системный резолвер", Status::Fail, e.to_string(), None));
                f.dns_system_error = Some(e.to_string());
            }
            Err(_) => {
                send(step("DNS", "Системный резолвер", Status::Fail, "нет ответа", None));
                f.dns_system_error = Some("нет ответа".into());
            }
        }
        // Каждый DNS-сервер системы.
        let servers = tokio::task::spawn_blocking(dns::system_servers).await.unwrap_or_default();
        for ip in servers.iter().take(3) {
            if cancel.is_cancelled() {
                return;
            }
            let Ok(s) = Server::parse(&ip.to_string(), Transport::Udp) else { continue };
            let t = Instant::now();
            match dns_ask(&s, &url.host, timeout.min(Duration::from_secs(3))).await {
                Ok(v) => send(step("DNS", format!("DNS-сервер {ip}"), Status::Ok, v.join(", "), Some(super::ms_f(t.elapsed())))),
                Err(e) => send(step("DNS", format!("DNS-сервер {ip}"), Status::Fail, e, None)),
            }
        }
        for ext in super::split_list(&cfg.external_dns) {
            if cancel.is_cancelled() {
                return;
            }
            let Ok(s) = Server::parse(&ext, Transport::Udp) else { continue };
            let t = Instant::now();
            match dns_ask(&s, &url.host, timeout.min(Duration::from_secs(3))).await {
                Ok(v) => {
                    let differs = f.dns_system.as_ref().is_some_and(|sys| !sys.iter().any(|a| v.contains(a)));
                    if differs {
                        f.dns_differs = true;
                    }
                    let st = if differs { Status::Warn } else { Status::Ok };
                    let d = if differs { format!("{} — не совпадает с системным", v.join(", ")) } else { v.join(", ") };
                    send(step("DNS", format!("Внешний DNS {ext}"), st, d, Some(super::ms_f(t.elapsed()))));
                    f.dns_external.get_or_insert(v);
                }
                Err(e) => send(step("DNS", format!("Внешний DNS {ext}"), Status::Warn, format!("{e} (в закрытом контуре это нормально)"), None)),
            }
        }
        if target_ip.is_none()
            && let Some(ip) = f.dns_external.as_ref().and_then(|v| v.first()).and_then(|s| s.parse().ok())
        {
            target_ip = Some(ip);
        }
    }

    // --- TCP напрямую ---
    if let Some(ip) = target_ip {
        let addr = SocketAddr::new(ip, url.port);
        let t = Instant::now();
        match tokio::time::timeout(timeout, super::connect_fast(addr)).await {
            Ok(Ok(_)) => {
                f.tcp_ok = Some(true);
                send(step("TCP", format!("Подключение к {addr}"), Status::Ok, "порт открыт", Some(super::ms_f(t.elapsed()))));
            }
            Ok(Err(e)) => {
                f.tcp_ok = Some(false);
                f.tcp_error = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    "отказ (RST): порт закрыт или отклонён межсетевым экраном".into()
                } else {
                    e.to_string()
                };
                send(step("TCP", format!("Подключение к {addr}"), Status::Fail, f.tcp_error.clone(), None));
            }
            Err(_) => {
                f.tcp_ok = Some(false);
                f.tcp_error = "нет ответа — пакеты отбрасываются (межсетевой экран или нет маршрута)".into();
                send(step("TCP", format!("Подключение к {addr}"), Status::Fail, f.tcp_error.clone(), None));
            }
        }
    } else {
        send(step("TCP", "Подключение напрямую", Status::Skip, "адрес не определён", None));
    }

    // --- HTTP (и TLS) напрямую ---
    if f.tcp_ok == Some(true) {
        let hc = http::Config {
            url: url_s.clone(),
            method: "GET".into(),
            proxy_mode: ProxyMode::Direct,
            follow_redirects: false,
            timeout_ms: cfg.timeout_ms,
            body_limit_kb: 64,
            ..Default::default()
        };
        let hops = http::fetch(&hc, None).await.unwrap_or_default();
        let hop = hops.into_iter().next().unwrap_or_default();
        if let Some(t) = &hop.tls {
            let leaf = t.chain.first();
            let issuer = leaf.map(|l| l.short_issuer()).unwrap_or_default();
            f.direct_issuer = leaf.map(|l| l.short_issuer());
            match &t.trust_error {
                None => send(step("TLS", "Сертификат", Status::Ok, format!("{} {}, выдан {issuer}", t.version, t.cipher), Some(t.handshake_ms))),
                Some(e) => {
                    f.tls_untrusted = Some(format!("{e} (издатель {issuer})"));
                    send(step("TLS", "Сертификат", Status::Warn, format!("не доверен: {e}; издатель {issuer}"), Some(t.handshake_ms)));
                }
            }
        } else if url.https && hop.error.is_some() {
            send(step("TLS", "Рукопожатие", Status::Fail, hop.error.clone().unwrap_or_default(), None));
        }
        let (outcome, detail) = match (&hop.error, hop.status) {
            (Some(e), _) => (Outcome::Error, e.clone()),
            (None, s) if (200..400).contains(&s) => (Outcome::Allowed, format!("HTTP {s}")),
            (None, s @ (403 | 451)) => (Outcome::Blocked, format!("HTTP {s}")),
            (None, s) => (Outcome::Allowed, format!("HTTP {s} — сайт отвечает ошибкой")),
        };
        let st = match (outcome, hop.status) {
            (Outcome::Allowed, 200..=399) => Status::Ok,
            (Outcome::Allowed, _) => Status::Warn,
            _ => Status::Fail,
        };
        send(step("HTTP", "Запрос напрямую", st, detail.clone(), Some(hop.timings.total_ms)));
        f.direct = Some((outcome, detail));
    } else {
        send(step("HTTP", "Запрос напрямую", Status::Skip, "нет TCP-подключения", None));
    }

    // --- Прокси ---
    let uc = urlcheck::Config {
        timeout_ms: cfg.timeout_ms,
        ..Default::default()
    };
    let rule = UrlRule { url: url_s.clone(), expect: None, note: String::new() };
    if cfg.system_proxy && !cancel.is_cancelled() {
        match system_proxy_for(&url_s, timeout).await {
            Ok(None) => {
                f.system_direct = true;
                send(step("Прокси", "Системный прокси / PAC", Status::Skip, "не настроен — браузер идёт напрямую", None));
            }
            Ok(Some((src, p))) if p.is_empty() => {
                f.system_direct = true;
                send(step("Прокси", "Системный прокси / PAC", Status::Ok, format!("{src}: для этого адреса — напрямую"), None));
            }
            Ok(Some((src, p))) => {
                let row = urlcheck::check(&p, &rule, &uc, f.direct_issuer.clone()).await;
                let st = match row.outcome {
                    Outcome::Allowed if row.inspected == Some(true) => Status::Warn,
                    Outcome::Allowed => Status::Ok,
                    _ => Status::Fail,
                };
                let mut d = format!("{src}: {p} — {}, {}", row.outcome.label(), row.detail);
                if row.inspected == Some(true) {
                    d += &format!("; сертификат подменён ({})", row.issuer.clone().unwrap_or_default());
                }
                send(step("Прокси", "Системный прокси / PAC", st, d, Some(row.ms)));
                f.system = Some((p, row.outcome, row.detail.clone()));
            }
            Err(e) => send(step("Прокси", "Системный прокси / PAC", Status::Warn, e, None)),
        }
    }
    for p in super::split_list(&cfg.proxies) {
        if cancel.is_cancelled() {
            return;
        }
        let row = urlcheck::check(&p, &rule, &uc, f.direct_issuer.clone()).await;
        let st = match row.outcome {
            Outcome::Allowed if row.inspected == Some(true) => Status::Warn,
            Outcome::Allowed => Status::Ok,
            _ => Status::Fail,
        };
        let mut d = format!("{}, {}", row.outcome.label(), row.detail);
        if row.inspected == Some(true) {
            d += &format!("; сертификат подменён ({})", row.issuer.clone().unwrap_or_default());
        }
        send(step("Прокси", format!("Через {p}"), st, d, Some(row.ms)));
        f.proxies.push((p, row.outcome, row.detail, if row.inspected == Some(true) { row.issuer } else { None }));
    }

    let (verdict, ok) = conclude(&f, &url.host);
    sink.send(Event::Verdict(verdict, ok));
}

/// Вывод по собранным фактам: главная причина первой строкой.
fn conclude(f: &Facts, host: &str) -> (Vec<String>, bool) {
    let mut v = Vec::new();
    let direct_ok = matches!(f.direct, Some((Outcome::Allowed, _)));
    let user_path_ok = if let Some((_, o, _)) = &f.system { *o == Outcome::Allowed } else { direct_ok };
    // DNS.
    if f.dns_system.is_none() && f.dns_system_error.is_some() {
        if f.dns_external.is_some() {
            v.push(format!(
                "Внутренний DNS не знает имя {host}, внешний — знает: имя не заведено во внутренней зоне или запросы наружу запрещены. Браузер через прокси может открыть сайт, приложения напрямую — нет."
            ));
        } else {
            v.push(format!("Имя {host} не разрешается ни одним DNS-сервером: опечатка в адресе или имени нет."));
        }
    } else if f.dns_differs {
        v.push(format!(
            "DNS этой машины и внешний DNS дают для {host} разные адреса: разделённая зона (split-horizon) или подмена ответа."
        ));
    }
    // Путь пользователя: через системный прокси или напрямую.
    match &f.system {
        Some((p, Outcome::Blocked, d)) => v.insert(0, format!("Блокирует прокси {p}: {d}.")),
        Some((p, Outcome::Error, d)) => v.insert(0, format!("Системный прокси {p} не пропускает запрос: {d}.")),
        _ => {}
    }
    if f.system.is_none() || f.system_direct {
        match (f.tcp_ok, &f.direct) {
            (Some(false), _) => {
                let through: Vec<&str> = f.proxies.iter().filter(|x| x.1 == Outcome::Allowed).map(|x| x.0.as_str()).collect();
                if through.is_empty() {
                    v.insert(0, format!("Напрямую подключиться нельзя: {}.", f.tcp_error));
                } else {
                    v.insert(
                        0,
                        format!(
                            "Напрямую закрыто ({}), а через прокси {} открывается — у пользователя не настроен прокси.",
                            f.tcp_error,
                            through.join(", ")
                        ),
                    );
                }
            }
            (_, Some((Outcome::Blocked, d))) => v.insert(0, format!("Сайт или промежуточное устройство отвечает запретом: {d}.")),
            (_, Some((Outcome::Error, d))) => v.insert(0, format!("Подключение есть, но запрос не проходит: {d}.")),
            _ => {}
        }
    }
    if let Some(t) = &f.tls_untrusted {
        v.push(format!("Сертификат не доверен этой машиной: {t}. Если это SSL-инспекция — корневой сертификат инспекции не установлен."));
    }
    for (p, _, _, issuer) in &f.proxies {
        if let Some(i) = issuer {
            v.push(format!("Прокси {p} подменяет сертификат (SSL-инспекция, издатель {i})."));
        }
    }
    let blocked: Vec<&str> = f.proxies.iter().filter(|x| x.1 != Outcome::Allowed).map(|x| x.0.as_str()).collect();
    if !blocked.is_empty() && blocked.len() < f.proxies.len() {
        v.push(format!("Не пропускают: {}; остальные прокси пропускают — разные политики на прокси.", blocked.join(", ")));
    } else if !blocked.is_empty() && f.system.is_none() && !direct_ok {
        let (p, _, d, _) = &f.proxies[0];
        v.push(format!("Все указанные прокси не пропускают адрес (например, {p}: {d})."));
    }
    let ok = user_path_ok && v.is_empty();
    if v.is_empty() {
        v.push(if user_path_ok {
            "Сайт открывается: DNS, подключение и ответ в порядке. Если у пользователя не открывается — проверьте его браузер, расширения и время на ПК.".into()
        } else {
            "Явной причины не найдено: проверьте доступность с машины пользователя.".into()
        });
    }
    (v, ok)
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!("Проверка {}\n", r.url);
    for st in &r.steps {
        s += &format!(
            "  {} {:<7} {:<34} {}{}\n",
            st.status.mark(),
            st.stage,
            st.title,
            st.detail,
            st.ms.map(|m| format!(" ({m:.0} мс)")).unwrap_or_default()
        );
    }
    s += "\nИтог:\n";
    for l in &r.verdict {
        s += &format!("  • {l}\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        let f = Facts {
            dns_system: Some(vec!["10.0.0.5".into()]),
            tcp_ok: Some(false),
            tcp_error: "нет ответа".into(),
            proxies: vec![("10.0.0.10:3128".into(), Outcome::Allowed, "HTTP 200".into(), None)],
            ..Default::default()
        };
        let (v, ok) = conclude(&f, "site.test");
        assert!(v[0].contains("не настроен прокси"), "{v:?}");
        assert!(!ok);

        let f = Facts {
            dns_system: Some(vec!["10.0.0.5".into()]),
            tcp_ok: Some(true),
            direct: Some((Outcome::Allowed, "HTTP 200".into())),
            system: Some(("gw:3128".into(), Outcome::Blocked, "HTTP 403".into())),
            ..Default::default()
        };
        let (v, _) = conclude(&f, "site.test");
        assert!(v[0].starts_with("Блокирует прокси gw:3128"), "{v:?}");

        let f = Facts {
            dns_system_error: Some("not found".into()),
            dns_external: Some(vec!["1.2.3.4".into()]),
            ..Default::default()
        };
        let (v, _) = conclude(&f, "site.test");
        assert!(v.iter().any(|l| l.contains("Внутренний DNS")), "{v:?}");

        let f = Facts {
            dns_system: Some(vec!["10.0.0.5".into()]),
            tcp_ok: Some(true),
            direct: Some((Outcome::Allowed, "HTTP 200".into())),
            ..Default::default()
        };
        assert!(conclude(&f, "site.test").1);
    }

    #[tokio::test]
    async fn local_site() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 2048];
                    let _ = s.read(&mut b).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
                });
            }
        });
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            url: format!("http://{addr}/"),
            external_dns: String::new(),
            system_proxy: false,
            timeout_ms: 2000,
            ..Default::default()
        };
        run(cfg, sink, CancellationToken::new()).await;
        let mut verdict = None;
        let mut steps = 0;
        while let Ok(e) = rx.try_recv() {
            match e {
                Event::Step(_) => steps += 1,
                Event::Verdict(v, ok) => verdict = Some((v, ok)),
                Event::Log(l) => panic!("{l}"),
            }
        }
        let (v, ok) = verdict.unwrap();
        assert!(ok, "{v:?}");
        assert!(steps >= 2);
    }
}
