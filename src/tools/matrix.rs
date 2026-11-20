//! Матрица доступности: проверка правил межсетевого экрана «отсюда → туда → порт»
//! с ожидаемым результатом. На машине назначения можно запустить встроенный слушатель
//! (`proxy-scanner-cli listen 443,1433`) — тогда видно, что соединение дошло именно до неё.
//! Результаты с разных машин объединяются в одну таблицу.
//!
//! Формат правил — по одному в строке:
//! ```text
//! 10.0.0.5:443 open          # портал
//! db01.corp.local:1433 closed
//! 10.0.1.0/29 22,3389 closed
//! fileserver 445
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::Sink;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub rules: String,
    pub timeout_ms: u64,
    pub retries: u32,
    pub concurrency: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules: String::new(),
            timeout_ms: 2000,
            retries: 1,
            concurrency: 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Expect {
    #[default]
    Any,
    Open,
    Closed,
}

impl Expect {
    pub fn label(self) -> &'static str {
        match self {
            Expect::Any => "—",
            Expect::Open => "открыт",
            Expect::Closed => "закрыт",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    /// Соединение установлено.
    Open,
    /// Узел ответил RST: маршрут есть, порт не слушается.
    Refused,
    /// Нет ответа: скорее всего, фильтруется.
    Filtered,
    Error,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            State::Open => "открыт",
            State::Refused => "отказ (RST)",
            State::Filtered => "нет ответа",
            State::Error => "ошибка",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Ok,
    Mismatch,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub target: String,
    pub ports: Vec<u16>,
    pub expect: Expect,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub target: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub expect: Expect,
    pub state: State,
    /// Ответил слушатель Proxy Scanner (имя машины).
    pub listener: Option<String>,
    pub rtt_ms: Option<f64>,
    pub verdict: Verdict,
    pub note: String,
    pub detail: String,
}

/// Результаты с одной машины-источника.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub source: String,
    pub source_ip: String,
    pub at: u64,
    pub entries: Vec<Entry>,
}

impl Report {
    pub fn mismatches(&self) -> usize {
        self.entries.iter().filter(|e| e.verdict == Verdict::Mismatch).count()
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Total(usize),
    Entry(Box<Entry>),
}

pub fn parse(text: &str) -> Result<Vec<Rule>, String> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let (body, note) = match raw.split_once('#') {
            Some((b, c)) => (b, c.trim().to_string()),
            None => (raw, String::new()),
        };
        let mut words: Vec<&str> = body.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        let mut expect = Expect::Any;
        if let Some(last) = words.last() {
            let e = match last.to_lowercase().as_str() {
                "open" | "открыт" | "allow" | "разрешён" | "разрешен" | "+" => Some(Expect::Open),
                "closed" | "закрыт" | "deny" | "запрещён" | "запрещен" | "-" => Some(Expect::Closed),
                _ => None,
            };
            if let Some(e) = e {
                expect = e;
                words.pop();
            }
        }
        let (target, ports) = match words.as_slice() {
            [one] => match one.rsplit_once(':') {
                Some((t, p)) if !t.contains(':') => (t.to_string(), p.to_string()),
                _ => return Err(format!("строка {}: укажите порт (узел:порт или «узел порты»)", n + 1)),
            },
            [t, p] => (t.to_string(), p.to_string()),
            _ => return Err(format!("строка {}: ожидается «узел:порт [open|closed]»", n + 1)),
        };
        let ports = crate::targets::parse_ports(&ports).map_err(|e| format!("строка {}: {e}", n + 1))?;
        out.push(Rule { target, ports, expect, note });
    }
    Ok(out)
}

async fn probe(addr: SocketAddr, timeout: Duration) -> (State, Option<String>, Option<f64>, String) {
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(mut s)) => {
            let rtt = super::ms_f(started.elapsed());
            let mut buf = [0u8; 256];
            let listener = match tokio::time::timeout(Duration::from_millis(400), s.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let text = String::from_utf8_lossy(&buf[..n]);
                    text.strip_prefix(crate::egress::MARKER).map(|rest| rest.trim().to_string())
                }
                _ => None,
            };
            (State::Open, listener, Some(rtt), String::new())
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            (State::Refused, None, Some(super::ms_f(started.elapsed())), String::new())
        }
        Ok(Err(e)) => (State::Error, None, None, e.to_string()),
        Err(_) => (State::Filtered, None, None, String::new()),
    }
}

pub fn verdict(expect: Expect, state: State) -> Verdict {
    match (expect, state) {
        (Expect::Any, _) => Verdict::Info,
        (Expect::Open, State::Open) => Verdict::Ok,
        (Expect::Closed, State::Refused | State::Filtered) => Verdict::Ok,
        _ => Verdict::Mismatch,
    }
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let rules = match parse(&cfg.rules) {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => return sink.send(Event::Log("список правил пуст".into())),
        Err(e) => return sink.send(Event::Log(e)),
    };
    let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
    // Развёртка: подсети и диапазоны → адреса.
    let mut jobs: Vec<(String, Option<IpAddr>, u16, Expect, String)> = Vec::new();
    for r in &rules {
        let hosts = match super::HostList::parse(&r.target) {
            Ok(h) => h,
            Err(e) => {
                sink.send(Event::Log(format!("{}: {e}", r.target)));
                continue;
            }
        };
        if hosts.addrs.total_hosts() > 4096 {
            sink.send(Event::Log(format!("{}: слишком много адресов (больше 4096)", r.target)));
            continue;
        }
        for h in hosts.items() {
            let ip = h.parse().ok();
            for &p in &r.ports {
                jobs.push((h.clone(), ip, p, r.expect, r.note.clone()));
            }
        }
    }
    sink.send(Event::Total(jobs.len()));
    let cfg = Arc::new(cfg);
    super::for_each_limited(jobs, cfg.concurrency, &cancel, |(target, ip, port, expect, note)| {
        let (sink, cfg) = (sink.clone(), cfg.clone());
        async move {
            let ip = match ip {
                Some(ip) => Some(ip),
                None => super::resolve(&target, timeout).await.ok(),
            };
            let (state, listener, rtt, detail) = match ip {
                Some(ip) => {
                    let mut res = probe(SocketAddr::new(ip, port), timeout).await;
                    for _ in 0..cfg.retries {
                        if res.0 != State::Filtered {
                            break;
                        }
                        res = probe(SocketAddr::new(ip, port), timeout).await;
                    }
                    res
                }
                None => (State::Error, None, None, "имя не разрешилось".to_string()),
            };
            sink.send(Event::Entry(Box::new(Entry {
                target,
                ip,
                port,
                expect,
                verdict: verdict(expect, state),
                state,
                listener,
                rtt_ms: rtt,
                note,
                detail,
            })));
        }
    })
    .await;
}

pub fn new_report() -> Report {
    Report {
        source: crate::session::computer_name(),
        source_ip: String::new(),
        at: crate::session::now_unix(),
        entries: Vec::new(),
    }
}

pub fn sort(r: &mut Report) {
    r.entries.sort_by(|a, b| (a.verdict != Verdict::Mismatch, &a.target, a.port).cmp(&(b.verdict != Verdict::Mismatch, &b.target, b.port)));
}

pub fn render_text(reports: &[Report]) -> String {
    let mut s = String::new();
    for r in reports {
        s += &format!(
            "== источник {}{} — правил {}, расхождений {}\n",
            r.source,
            if r.source_ip.is_empty() { String::new() } else { format!(" ({})", r.source_ip) },
            r.entries.len(),
            r.mismatches()
        );
        for e in &r.entries {
            s += &format!(
                "{:<3} {:<32} {:<11} {:<12} {}{}{}\n",
                match e.verdict {
                    Verdict::Ok => "ok",
                    Verdict::Mismatch => "!!",
                    Verdict::Info => "",
                },
                format!("{}:{}", e.target, e.port),
                format!("ожид. {}", e.expect.label()),
                e.state.label(),
                e.listener.as_ref().map(|l| format!("слушатель {l} ")).unwrap_or_default(),
                if e.note.is_empty() { String::new() } else { format!("# {}", e.note) },
                if e.detail.is_empty() { String::new() } else { format!(" ({})", e.detail) }
            );
        }
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        let r = parse("10.0.0.5:443 open # портал\ndb:1433 закрыт\n10.0.1.0/30 22,3389 -\nfs 445\n\n# только комментарий").unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!((r[0].target.as_str(), r[0].ports.clone(), r[0].expect, r[0].note.as_str()), ("10.0.0.5", vec![443], Expect::Open, "портал"));
        assert_eq!(r[1].expect, Expect::Closed);
        assert_eq!(r[2].ports, vec![22, 3389]);
        assert_eq!(r[3].expect, Expect::Any);
        assert!(parse("host").is_err());
        assert!(parse("a b c d").is_err());
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(Expect::Open, State::Open), Verdict::Ok);
        assert_eq!(verdict(Expect::Open, State::Filtered), Verdict::Mismatch);
        assert_eq!(verdict(Expect::Closed, State::Refused), Verdict::Ok);
        assert_eq!(verdict(Expect::Closed, State::Open), Verdict::Mismatch);
        assert_eq!(verdict(Expect::Any, State::Open), Verdict::Info);
    }

    #[tokio::test]
    async fn with_listener() {
        let cancel = CancellationToken::new();
        // Свободный порт: занимаем и освобождаем.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (ok, _) = crate::egress::start_listener(&[port], cancel.clone()).await;
        assert_eq!(ok, vec![port]);
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            rules: format!("127.0.0.1:{port} open\n127.0.0.1:1 open"),
            ..Default::default()
        };
        run(cfg, sink, CancellationToken::new()).await;
        let mut entries: Vec<Entry> = rx.try_iter().filter_map(|e| if let Event::Entry(x) = e { Some(*x) } else { None }).collect();
        entries.sort_by_key(|e| e.port);
        assert_eq!(entries[0].state, State::Refused);
        assert_eq!(entries[0].verdict, Verdict::Mismatch);
        assert_eq!(entries[1].state, State::Open);
        assert_eq!(entries[1].verdict, Verdict::Ok);
        assert_eq!(entries[1].listener.as_deref(), Some(crate::session::computer_name().as_str()));
        cancel.cancel();
    }
}
