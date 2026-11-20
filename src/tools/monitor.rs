//! Мониторинг: список проверок, выполняемых по расписанию, с историей и журналом
//! изменений состояния (норма → предупреждение → сбой).
//!
//! Формат списка — по одной проверке в строке:
//! ```text
//! ping 10.0.0.1
//! tcp  mail.corp.local:25
//! http https://portal.corp.local/ expect=200 max_ms=1500 contains=Вход
//! dns  portal.corp.local @10.0.0.53 expect=10.0.0.5
//! tls  portal.corp.local:443 warn_days=30
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub checks: String,
    /// Период опроса, секунды.
    pub interval_s: u64,
    pub timeout_ms: u64,
    /// Порог задержки для предупреждения, мс.
    pub warn_ms: f64,
    /// Число циклов (0 — до остановки).
    pub cycles: u32,
    /// Сколько последних замеров хранить.
    pub history: usize,
    /// Уведомления о смене состояния.
    pub alerts: super::notify::Alerts,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            checks: String::new(),
            interval_s: 60,
            timeout_ms: 5000,
            warn_ms: 1000.0,
            cycles: 0,
            history: 240,
            alerts: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum Status {
    #[default]
    Unknown,
    Ok,
    Warn,
    Fail,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Unknown => "—",
            Status::Ok => "норма",
            Status::Warn => "внимание",
            Status::Fail => "сбой",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Kind {
    Ping,
    Tcp,
    Http,
    Dns,
    Tls,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub line: String,
    pub kind: Kind,
    pub target: String,
    pub opts: Vec<(String, String)>,
}

impl Check {
    pub fn opt(&self, k: &str) -> Option<&str> {
        self.opts.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
    }
}

pub fn parse(text: &str) -> Result<Vec<Check>, String> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let kind = match words.next().unwrap_or("").to_ascii_lowercase().as_str() {
            "ping" | "icmp" => Kind::Ping,
            "tcp" | "port" => Kind::Tcp,
            "http" | "https" | "url" => Kind::Http,
            "dns" => Kind::Dns,
            "tls" | "cert" => Kind::Tls,
            other => return Err(format!("строка {}: неизвестный тип проверки «{other}» (ping, tcp, http, dns, tls)", n + 1)),
        };
        let target = words.next().ok_or_else(|| format!("строка {}: не указан узел", n + 1))?.to_string();
        let mut opts = Vec::new();
        for w in words {
            if let Some(server) = w.strip_prefix('@') {
                opts.push(("server".into(), server.into()));
            } else if let Some((k, v)) = w.split_once('=') {
                opts.push((k.to_ascii_lowercase(), v.into()));
            } else {
                return Err(format!("строка {}: непонятный параметр «{w}» (ожидается ключ=значение)", n + 1));
            }
        }
        if kind == Kind::Tcp && !target.contains(':') {
            return Err(format!("строка {}: для tcp нужен порт (узел:порт)", n + 1));
        }
        out.push(Check {
            line: line.to_string(),
            kind,
            target,
            opts,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub at: u64,
    pub status: Status,
    pub ms: Option<f64>,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub line: String,
    pub status: Status,
    pub since: u64,
    pub last: Option<Sample>,
    pub history: Vec<Option<f64>>,
    pub ok: u32,
    pub warn: u32,
    pub fail: u32,
}

impl State {
    pub fn availability(&self) -> f64 {
        let n = self.ok + self.warn + self.fail;
        if n == 0 { 0.0 } else { 100.0 * (self.ok + self.warn) as f64 / n as f64 }
    }

    pub fn apply(&mut self, s: Sample, keep: usize) -> Option<(Status, Status)> {
        match s.status {
            Status::Ok => self.ok += 1,
            Status::Warn => self.warn += 1,
            Status::Fail => self.fail += 1,
            Status::Unknown => {}
        }
        self.history.push(if s.status == Status::Fail { None } else { s.ms });
        if self.history.len() > keep {
            self.history.remove(0);
        }
        let prev = self.status;
        self.last = Some(s.clone());
        if prev != s.status {
            self.status = s.status;
            self.since = s.at;
            return Some((prev, s.status));
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub at: u64,
    pub line: String,
    pub from: Status,
    pub to: Status,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub states: Vec<State>,
    pub changes: Vec<Change>,
    pub cycles: u32,
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Checks(Vec<String>),
    Sample(usize, Sample),
    Cycle(u32),
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn latency_status(ms: f64, warn: f64) -> Status {
    if ms > warn { Status::Warn } else { Status::Ok }
}

async fn run_check(c: &Check, cfg: &Config) -> Sample {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(200));
    let warn = c.opt("max_ms").and_then(|v| v.parse().ok()).unwrap_or(cfg.warn_ms);
    let started = Instant::now();
    let (status, ms, detail) = match c.kind {
        Kind::Ping => match super::resolve(&c.target, timeout).await {
            Ok(IpAddr::V4(ip)) => {
                let mut got = Vec::new();
                let mut err = None;
                let id = super::icmp::next_id();
                for seq in 0..3u16 {
                    let p = super::icmp::Probe {
                        dst: ip,
                        ttl: 64,
                        payload: 32,
                        df: false,
                        timeout: timeout.min(Duration::from_secs(2)),
                        proto: super::icmp::Proto::Icmp,
                        port: 0,
                        id,
                        seq,
                    };
                    match super::icmp::probe(p).await {
                        Ok(Some(r)) if r.kind == super::icmp::ReplyKind::Reached => got.push(r.rtt_us as f64 / 1000.0),
                        Ok(_) => {}
                        Err(e) => err = Some(e),
                    }
                }
                if let Some(e) = err.filter(|_| got.is_empty()) {
                    (Status::Fail, None, e)
                } else if got.is_empty() {
                    (Status::Fail, None, "нет ответа (3 из 3 потеряны)".into())
                } else {
                    let avg = got.iter().sum::<f64>() / got.len() as f64;
                    let loss = 3 - got.len();
                    let st = if loss > 0 { Status::Warn } else { latency_status(avg, warn) };
                    (st, Some(avg), format!("{avg:.1} мс, потери {loss}/3"))
                }
            }
            Ok(_) => (Status::Fail, None, "IPv6 не поддерживается для ping".into()),
            Err(e) => (Status::Fail, None, e),
        },
        Kind::Tcp => {
            let (host, port) = match crate::probe::split_host_port(&c.target, 0) {
                Ok(v) => v,
                Err(e) => return sample(Status::Fail, None, e),
            };
            match super::resolve(&host, timeout).await {
                Ok(ip) => match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(SocketAddr::new(ip, port))).await {
                    Ok(Ok(_)) => {
                        let ms = super::ms_f(started.elapsed());
                        (latency_status(ms, warn), Some(ms), format!("порт открыт, {ms:.1} мс"))
                    }
                    Ok(Err(e)) => (Status::Fail, None, e.to_string()),
                    Err(_) => (Status::Fail, None, "нет ответа".into()),
                },
                Err(e) => (Status::Fail, None, e),
            }
        }
        Kind::Http => {
            let url = if c.target.contains("://") { c.target.clone() } else { format!("http://{}/", c.target) };
            let hc = super::http::Config {
                url,
                timeout_ms: cfg.timeout_ms,
                body_limit_kb: 256,
                follow_redirects: c.opt("follow").is_none_or(|v| v != "no"),
                ..Default::default()
            };
            match super::http::fetch(&hc, None).await {
                Ok(hops) => {
                    let last = hops.last().cloned().unwrap_or_default();
                    let ms = hops.iter().map(|h| h.timings.total_ms).sum::<f64>();
                    if let Some(e) = last.error {
                        (Status::Fail, None, e)
                    } else {
                        let expect = c.opt("expect").and_then(|v| v.parse::<u16>().ok());
                        let ok_code = match expect {
                            Some(code) => last.status == code,
                            None => (200..400).contains(&last.status),
                        };
                        let contains_ok = c.opt("contains").is_none_or(|t| last.body_text().contains(t));
                        let cert_warn = last.tls.as_ref().and_then(|t| t.chain.first()).is_some_and(|l| l.days_left < 14);
                        if !ok_code {
                            (Status::Fail, Some(ms), format!("HTTP {}", last.status))
                        } else if !contains_ok {
                            (Status::Fail, Some(ms), format!("HTTP {}, нет текста «{}»", last.status, c.opt("contains").unwrap_or("")))
                        } else if cert_warn {
                            (Status::Warn, Some(ms), format!("HTTP {}, сертификат истекает", last.status))
                        } else {
                            (latency_status(ms, warn), Some(ms), format!("HTTP {}, {ms:.0} мс", last.status))
                        }
                    }
                }
                Err(e) => (Status::Fail, None, e),
            }
        }
        Kind::Dns => {
            let servers = c.opt("server").unwrap_or("system").to_string();
            let qtype = c.opt("type").unwrap_or("A").to_string();
            let dc = super::dns::Config {
                servers,
                timeout_ms: cfg.timeout_ms,
                ..Default::default()
            };
            let list = match tokio::task::spawn_blocking(move || super::dns::expand_servers(&dc)).await {
                Ok(Ok(l)) => l,
                Ok(Err(e)) => return sample(Status::Fail, None, e),
                Err(e) => return sample(Status::Fail, None, e.to_string()),
            };
            let Some(server) = list.first() else { return sample(Status::Fail, None, "нет DNS-сервера".into()) };
            let code = super::dnsproto::type_code(&qtype).unwrap_or(1);
            let a = super::dns::query(server, &super::dnsproto::Query::new(super::dns::rand_id(), &c.target, code), timeout, 1).await;
            if let Some(e) = a.error {
                (Status::Fail, None, e)
            } else if a.rcode != "NOERROR" || a.answers.is_empty() {
                (Status::Fail, a.rtt_ms, format!("{} {}", a.rcode, if a.answers.is_empty() { "(пусто)" } else { "" }))
            } else {
                let values: Vec<String> = a.answers.iter().map(|r| r.data.trim_end_matches('.').to_string()).collect();
                let ms = a.rtt_ms.unwrap_or(0.0);
                match c.opt("expect") {
                    Some(exp) if !values.iter().any(|v| v == exp) => (Status::Fail, Some(ms), format!("ответ {} вместо {exp}", values.join(", "))),
                    _ => (latency_status(ms, warn), Some(ms), values.join(", ")),
                }
            }
        }
        Kind::Tls => {
            let (host, port) = match crate::probe::split_host_port(&c.target, 443) {
                Ok(v) => v,
                Err(e) => return sample(Status::Fail, None, e),
            };
            let warn_days: i64 = c.opt("warn_days").and_then(|v| v.parse().ok()).unwrap_or(30);
            match super::resolve(&host, timeout).await {
                Ok(ip) => match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(SocketAddr::new(ip, port))).await {
                    Ok(Ok(s)) => match super::tls::handshake(s, &host, super::tls::Versions::Auto, &[], timeout).await {
                        Ok((_, info)) => {
                            let ms = super::ms_f(started.elapsed());
                            match info.chain.first() {
                                Some(l) if l.days_left < 0 => (Status::Fail, Some(ms), format!("сертификат просрочен ({} дн.)", -l.days_left)),
                                Some(l) if l.days_left < warn_days => (Status::Warn, Some(ms), format!("сертификат истекает через {} дн.", l.days_left)),
                                Some(_) if info.trust_error.is_some() => {
                                    (Status::Warn, Some(ms), format!("не доверен: {}", info.trust_error.unwrap_or_default()))
                                }
                                Some(l) => (Status::Ok, Some(ms), format!("{} дн., {}", l.days_left, info.version)),
                                None => (Status::Fail, Some(ms), "нет сертификата".into()),
                            }
                        }
                        Err(e) => (Status::Fail, None, e),
                    },
                    Ok(Err(e)) => (Status::Fail, None, e.to_string()),
                    Err(_) => (Status::Fail, None, "нет ответа".into()),
                },
                Err(e) => (Status::Fail, None, e),
            }
        }
    };
    sample(status, ms, detail)
}

fn sample(status: Status, ms: Option<f64>, detail: String) -> Sample {
    Sample {
        at: now(),
        status,
        ms,
        detail,
    }
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let mut text = cfg.checks.clone();
    if text.contains("{domain}") {
        match tokio::task::spawn_blocking(super::dns::system_domain).await.ok().flatten() {
            Some(d) => text = text.replace("{domain}", d.trim_matches('.')),
            None => return sink.send(Event::Log("в проверках есть {domain}, но DNS-суффикс системы не определён".into())),
        }
    }
    let checks = match parse(&text) {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => return sink.send(Event::Log("список проверок пуст".into())),
        Err(e) => return sink.send(Event::Log(e)),
    };
    sink.send(Event::Checks(checks.iter().map(|c| c.line.clone()).collect()));
    // Собственное отслеживание состояний — для уведомлений (работает и без окна).
    let states = Arc::new(std::sync::Mutex::new(
        checks
            .iter()
            .map(|c| State {
                line: c.line.clone(),
                ..Default::default()
            })
            .collect::<Vec<_>>(),
    ));
    let checks = Arc::new(checks);
    let cfg = Arc::new(cfg);
    let interval = Duration::from_secs(cfg.interval_s.max(5));
    let max = if cfg.cycles == 0 { u32::MAX } else { cfg.cycles };
    for cycle in 0..max {
        let started = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for i in 0..checks.len() {
            let (checks, cfg, sink, states) = (checks.clone(), cfg.clone(), sink.clone(), states.clone());
            set.spawn(async move {
                let s = run_check(&checks[i], &cfg).await;
                let change = {
                    let mut st = states.lock().unwrap();
                    let detail = s.detail.clone();
                    st[i].apply(s.clone(), 4).map(|(from, to)| Change {
                        at: s.at,
                        line: checks[i].line.clone(),
                        from,
                        to,
                        detail,
                    })
                };
                sink.send(Event::Sample(i, s));
                if let Some(ch) = change
                    && !cfg.alerts.is_empty()
                {
                    for e in super::notify::send(&cfg.alerts, &ch).await {
                        sink.send(Event::Log(format!("уведомление не отправлено: {e}")));
                    }
                }
            });
        }
        tokio::select! {
            _ = async { while set.join_next().await.is_some() {} } => {}
            _ = cancel.cancelled() => return,
        }
        sink.send(Event::Cycle(cycle + 1));
        if cycle + 1 < max {
            tokio::select! {
                _ = tokio::time::sleep(interval.saturating_sub(started.elapsed())) => {}
                _ = cancel.cancelled() => return,
            }
        }
    }
}

/// Применение события к отчёту; возвращает изменение состояния, если было.
pub fn fold(r: &mut Report, e: Event, keep: usize) -> Option<Change> {
    match e {
        Event::Checks(lines) => {
            r.states = lines
                .into_iter()
                .map(|line| State {
                    line,
                    ..Default::default()
                })
                .collect();
            None
        }
        Event::Sample(i, s) => {
            let st = r.states.get_mut(i)?;
            let detail = s.detail.clone();
            let at = s.at;
            let (from, to) = st.apply(s, keep)?;
            let ch = Change {
                at,
                line: st.line.clone(),
                from,
                to,
                detail,
            };
            r.changes.push(ch.clone());
            Some(ch)
        }
        Event::Cycle(n) => {
            r.cycles = n;
            None
        }
        Event::Log(_) => None,
    }
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!("Циклов: {}\n", r.cycles);
    for st in &r.states {
        s += &format!(
            "{:<9} {:<50} {:>6.1}%  {}\n",
            st.status.label(),
            st.line,
            st.availability(),
            st.last.as_ref().map(|l| l.detail.clone()).unwrap_or_default()
        );
    }
    if !r.changes.is_empty() {
        s += "\nИзменения:\n";
        for c in &r.changes {
            s += &format!(
                "{} {} : {} → {} ({})\n",
                crate::session::format_time(c.at),
                c.line,
                c.from.label(),
                c.to.label(),
                c.detail
            );
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        let c = parse("# коммент\nping 10.0.0.1\ntcp mail:25\nhttp https://x/ expect=200 max_ms=500\ndns a.b @10.0.0.53 expect=1.2.3.4\ntls x:443 warn_days=10").unwrap();
        assert_eq!(c.len(), 5);
        assert_eq!(c[0].kind, Kind::Ping);
        assert_eq!(c[2].opt("max_ms"), Some("500"));
        assert_eq!(c[3].opt("server"), Some("10.0.0.53"));
        assert!(parse("tcp host").is_err());
        assert!(parse("ftp host").is_err());
        assert!(parse("http x junk").is_err());
    }

    #[test]
    fn state_transitions() {
        let mut st = State::default();
        let mk = |status| Sample { at: 1, status, ms: Some(5.0), detail: String::new() };
        assert_eq!(st.apply(mk(Status::Ok), 10), Some((Status::Unknown, Status::Ok)));
        assert_eq!(st.apply(mk(Status::Ok), 10), None);
        assert_eq!(st.apply(mk(Status::Fail), 10), Some((Status::Ok, Status::Fail)));
        assert_eq!(st.history, vec![Some(5.0), Some(5.0), None]);
        assert!((st.availability() - 66.666).abs() < 0.1);
    }

    #[tokio::test]
    async fn tcp_and_http_checks() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
                });
            }
        });
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            checks: format!("tcp {addr}\nhttp http://{addr}/ contains=hello\nhttp http://{addr}/ contains=nope\ntcp 127.0.0.1:1"),
            cycles: 1,
            ..Default::default()
        };
        run(cfg, sink, CancellationToken::new()).await;
        let mut r = Report::default();
        for e in rx.try_iter() {
            fold(&mut r, e, 10);
        }
        let st: Vec<Status> = r.states.iter().map(|s| s.status).collect();
        assert_eq!(st, vec![Status::Ok, Status::Ok, Status::Fail, Status::Fail]);
        assert_eq!(r.changes.len(), 4);
    }
}
