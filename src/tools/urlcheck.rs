//! Пакетная проверка URL через прокси: для каждой пары «прокси × адрес» — пропущен,
//! заблокирован или подменён сертификат (SSL-инспекция); сверка с ожиданием (`+`/`-`).
//!
//! Формат списка адресов:
//! ```text
//! + https://portal.corp.local/     # должен открываться
//! - https://www.torproject.org/    # должен блокироваться
//! http://example.com/              # без ожидания
//! ```

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;
use super::http::{self, ProxyMode};
use crate::auth::AuthMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Прокси `узел:порт` (пусто — напрямую).
    pub proxies: String,
    pub urls: String,
    /// Текст страницы блокировки (если прокси отвечает 200 со страницей запрета).
    pub block_marker: String,
    pub auth: AuthMode,
    pub current_user: bool,
    pub user: String,
    pub domain: String,
    #[serde(skip)]
    pub password: String,
    pub timeout_ms: u64,
    pub concurrency: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxies: String::new(),
            urls: String::new(),
            block_marker: String::new(),
            auth: AuthMode::Auto,
            current_user: true,
            user: String::new(),
            domain: String::new(),
            password: String::new(),
            timeout_ms: 10_000,
            concurrency: 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Allowed,
    Blocked,
    Error,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Allowed => "пропущен",
            Outcome::Blocked => "заблокирован",
            Outcome::Error => "ошибка",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlRule {
    pub url: String,
    /// Some(true) — должен открываться, Some(false) — должен блокироваться.
    pub expect: Option<bool>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub proxy: String,
    pub url: String,
    pub expect: Option<bool>,
    pub outcome: Outcome,
    pub status: u16,
    pub detail: String,
    /// Издатель сертификата сайта (HTTPS).
    pub issuer: Option<String>,
    /// Сертификат не доверен системой или подменён (издатель отличается от прямого).
    pub inspected: Option<bool>,
    pub mismatch: bool,
    pub ms: f64,
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub rows: Vec<Row>,
}

impl Report {
    pub fn mismatches(&self) -> usize {
        self.rows.iter().filter(|r| r.mismatch).count()
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Total(usize),
    Row(Box<Row>),
}

pub fn parse_urls(text: &str) -> Result<Vec<UrlRule>, String> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let (body, note) = match raw.split_once(" #") {
            Some((b, c)) => (b.trim(), c.trim().to_string()),
            None => (raw.trim(), String::new()),
        };
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let (expect, url) = if let Some(r) = body.strip_prefix('+') {
            (Some(true), r.trim())
        } else if let Some(r) = body.strip_prefix('-') {
            (Some(false), r.trim())
        } else {
            (None, body)
        };
        let url = if url.contains("://") { url.to_string() } else { format!("http://{url}/") };
        crate::probe::Url::parse(&url).map_err(|e| format!("строка {}: {e}", n + 1))?;
        out.push(UrlRule { url, expect, note });
    }
    Ok(out)
}

/// Типичные признаки страницы блокировки, если маркер не задан.
fn looks_blocked(body: &str) -> bool {
    let b = body.to_lowercase();
    ["access denied", "доступ запрещ", "доступ к ресурсу ограничен", "blocked by", "web page blocked", "url filtering", "заблокирован"]
        .iter()
        .any(|m| b.contains(m))
}

pub async fn check(proxy: &str, rule: &UrlRule, cfg: &Config, direct_issuer: Option<String>) -> Row {
    let hc = http::Config {
        url: rule.url.clone(),
        method: "GET".into(),
        proxy_mode: if proxy.is_empty() { ProxyMode::Direct } else { ProxyMode::Manual },
        proxy: proxy.to_string(),
        proxy_auth: cfg.auth,
        proxy_current_user: cfg.current_user,
        proxy_user: cfg.user.clone(),
        proxy_domain: cfg.domain.clone(),
        proxy_pass: cfg.password.clone(),
        follow_redirects: false,
        timeout_ms: cfg.timeout_ms,
        body_limit_kb: 64,
        ..Default::default()
    };
    let hops = http::fetch(&hc, None).await.unwrap_or_default();
    let hop = hops.into_iter().next().unwrap_or_default();
    let mut row = Row {
        proxy: if proxy.is_empty() { "напрямую".into() } else { proxy.to_string() },
        url: rule.url.clone(),
        expect: rule.expect,
        outcome: Outcome::Error,
        status: hop.status,
        detail: String::new(),
        issuer: None,
        inspected: None,
        mismatch: false,
        ms: hop.timings.total_ms,
        note: rule.note.clone(),
    };
    if let Some(t) = &hop.tls
        && let Some(leaf) = t.chain.first()
    {
        row.issuer = Some(leaf.short_issuer());
        row.inspected = Some(match &direct_issuer {
            Some(d) => *d != leaf.short_issuer(),
            None => t.trust_error.is_some(),
        });
    }
    let body = hop.body_text();
    match (&hop.error, hop.status) {
        (Some(e), _) if e.contains("CONNECT") || e.contains("сброс") || e.contains("reset") => {
            row.outcome = Outcome::Blocked;
            row.detail = e.clone();
        }
        (Some(e), _) => row.detail = e.clone(),
        (None, 407) => {
            row.outcome = Outcome::Blocked;
            row.detail = format!("прокси требует вход{}", hop.proxy_auth.map(|a| format!(" ({a})")).unwrap_or_default());
        }
        (None, 403 | 451 | 511) => {
            row.outcome = Outcome::Blocked;
            row.detail = format!("HTTP {}", hop.status);
        }
        (None, s) => {
            let marker = !cfg.block_marker.trim().is_empty() && body.contains(cfg.block_marker.trim());
            if marker || (s == 200 && looks_blocked(&body) && body.len() < 32 * 1024) {
                row.outcome = Outcome::Blocked;
                row.detail = format!("HTTP {s}, страница блокировки");
            } else {
                row.outcome = Outcome::Allowed;
                row.detail = format!("HTTP {s}");
            }
        }
    }
    row.mismatch = matches!(
        (rule.expect, row.outcome),
        (Some(true), Outcome::Blocked | Outcome::Error) | (Some(false), Outcome::Allowed)
    );
    row
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let rules = match parse_urls(&cfg.urls) {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => return sink.send(Event::Log("список адресов пуст".into())),
        Err(e) => return sink.send(Event::Log(e)),
    };
    let mut proxies = super::split_list(&cfg.proxies);
    if proxies.is_empty() {
        proxies.push(String::new());
    }
    // Эталон издателя: прямое подключение (в закрытом контуре может не работать — тогда
    // подмена определяется по доверию к сертификату).
    let mut direct: std::collections::HashMap<String, String> = Default::default();
    for r in rules.iter().filter(|r| r.url.starts_with("https")) {
        let host = crate::probe::Url::parse(&r.url).map(|u| u.host).unwrap_or_default();
        if direct.contains_key(&host) {
            continue;
        }
        let hc = http::Config {
            url: r.url.clone(),
            timeout_ms: cfg.timeout_ms.min(4000),
            follow_redirects: false,
            body_limit_kb: 1,
            method: "HEAD".into(),
            ..Default::default()
        };
        if let Ok(h) = http::fetch(&hc, None).await
            && let Some(leaf) = h.first().and_then(|h| h.tls.as_ref()).and_then(|t| t.chain.first())
        {
            direct.insert(host, leaf.short_issuer());
        }
    }
    let jobs: Vec<(String, UrlRule)> = proxies.iter().flat_map(|p| rules.iter().map(move |r| (p.clone(), r.clone()))).collect();
    sink.send(Event::Total(jobs.len()));
    let cfg = Arc::new(cfg);
    let direct = Arc::new(direct);
    super::for_each_limited(jobs, cfg.concurrency, &cancel, |(p, r)| {
        let (cfg, sink, direct) = (cfg.clone(), sink.clone(), direct.clone());
        async move {
            let host = crate::probe::Url::parse(&r.url).map(|u| u.host).unwrap_or_default();
            let row = check(&p, &r, &cfg, direct.get(&host).cloned()).await;
            sink.send(Event::Row(Box::new(row)));
        }
    })
    .await;
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!("Проверок: {}, расхождений: {}\n", r.rows.len(), r.mismatches());
    for x in &r.rows {
        s += &format!(
            "{} {:<22} {:<48} {:<13} {}{}\n",
            if x.mismatch { "!!" } else { "  " },
            x.proxy,
            x.url,
            x.outcome.label(),
            x.detail,
            match (x.inspected, &x.issuer) {
                (Some(true), Some(i)) => format!(" [подмена сертификата: {i}]"),
                _ => String::new(),
            }
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parsing() {
        let r = parse_urls("+ https://a.test/ # портал\n- b.test\nhttp://c.test/x\n# комментарий").unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!((r[0].expect, r[0].note.as_str()), (Some(true), "портал"));
        assert_eq!((r[1].expect, r[1].url.as_str()), (Some(false), "http://b.test/"));
        assert_eq!(r[2].expect, None);
    }

    #[tokio::test]
    async fn through_fake_proxy() {
        // Прокси: example.test разрешён, bad.test — 403.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let resp: &[u8] = if req.contains("bad.test") {
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                    } else if req.contains("page.test") {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nAccess denied by policy ......"
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                    };
                    let _ = s.write_all(resp).await;
                });
            }
        });
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            proxies: addr.to_string(),
            urls: "+ http://example.test/\n+ http://bad.test/\n- http://page.test/".into(),
            auth: AuthMode::None,
            ..Default::default()
        };
        run(cfg, sink, CancellationToken::new()).await;
        let mut rows: Vec<Row> = rx.try_iter().filter_map(|e| if let Event::Row(r) = e { Some(*r) } else { None }).collect();
        rows.sort_by(|a, b| a.url.cmp(&b.url));
        assert_eq!(rows[0].url, "http://bad.test/");
        assert_eq!(rows[0].outcome, Outcome::Blocked);
        assert!(rows[0].mismatch);
        assert_eq!(rows[1].outcome, Outcome::Allowed);
        assert!(!rows[1].mismatch);
        assert_eq!(rows[2].outcome, Outcome::Blocked);
        assert!(!rows[2].mismatch);
    }
}
