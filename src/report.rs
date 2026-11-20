//! Сводный отчёт HTML по сессии: один самодостаточный файл (стили внутри,
//! без внешних ресурсов) — для заявки, акта проверки или пересылки коллегам.

use std::fmt::Write as _;

use crate::model::{ProxyKind, SslInspection};
use crate::session::Session;
use crate::tools::monitor::Status;
use crate::tools::tlsaudit::Severity;

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root { --bg:#ffffff; --fg:#1d1f23; --muted:#6a6f78; --line:#e3e5e9; --card:#f6f7f9;
        --high:#c62828; --med:#b26a00; --low:#3b6fb6; --ok:#2e7d32; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16181c; --fg:#e6e8eb; --muted:#9aa0a8; --line:#2c3036; --card:#1e2126;
          --high:#ef5350; --med:#ffa726; --low:#64b5f6; --ok:#66bb6a; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:1200px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:24px; margin:0 0 4px; }
h2 { font-size:18px; margin:32px 0 8px; padding-bottom:4px; border-bottom:1px solid var(--line); }
h3 { font-size:15px; margin:18px 0 6px; }
.muted { color:var(--muted); }
.cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(170px,1fr)); gap:10px; margin:16px 0; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
.card b { display:block; font-size:22px; }
.wrap { overflow-x:auto; }
table { border-collapse:collapse; width:100%; margin:6px 0 12px; font-size:13px; }
th, td { text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
td.mono, .mono { font-family:ui-monospace,Consolas,"DejaVu Sans Mono",monospace; }
.high { color:var(--high); font-weight:600; } .med { color:var(--med); font-weight:600; }
.low { color:var(--low); } .ok { color:var(--ok); }
nav a { margin-right:12px; color:var(--low); text-decoration:none; }
@media print { nav { display:none; } h2 { break-after:avoid; } }
"#;

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
        Severity::Info => "muted",
    }
}

struct Doc {
    body: String,
    toc: Vec<(String, String)>,
}

impl Doc {
    fn section(&mut self, id: &str, title: &str) {
        self.toc.push((id.into(), title.into()));
        let _ = write!(self.body, "<h2 id=\"{id}\">{}</h2>", esc(title));
    }
    fn table(&mut self, headers: &[&str], rows: Vec<Vec<String>>) {
        self.body.push_str("<div class=\"wrap\"><table><tr>");
        for h in headers {
            let _ = write!(self.body, "<th>{}</th>", esc(h));
        }
        self.body.push_str("</tr>");
        for r in rows {
            self.body.push_str("<tr>");
            for c in r {
                // Ячейки уже экранированы (могут содержать разметку классов).
                let _ = write!(self.body, "<td>{c}</td>");
            }
            self.body.push_str("</tr>");
        }
        self.body.push_str("</table></div>");
    }
}

fn span(class: &str, text: &str) -> String {
    format!("<span class=\"{class}\">{}</span>", esc(text))
}

/// Все находки разных инструментов одним списком: (важность, где, что).
pub fn findings(s: &Session) -> Vec<(Severity, String, String)> {
    let mut out = Vec::new();
    if let Some(a) = &s.tools.audit {
        for i in &a.issues {
            out.push((i.severity, format!("{}:{}/{}", i.ip, i.port, i.proto), format!("{} → {}", i.title, i.advice)));
        }
    }
    if let Some(ad) = &s.tools.ad {
        for f in &ad.findings {
            out.push((f.severity, format!("домен {}", ad.domain), f.text.clone()));
        }
    }
    if let Some(t) = &s.tools.tls {
        for tg in &t.targets {
            for f in &tg.findings {
                out.push((f.severity, format!("{}:{}", tg.host, tg.port), f.text.clone()));
            }
        }
    }
    // Обход прокси: однотипные утечки (TCP-порты) сводятся в одну строку.
    let mut tcp_ports: Vec<String> = Vec::new();
    for e in s.egress.iter().filter(|e| e.status.is_leak()) {
        if e.kind == crate::egress::EgressKind::Tcp {
            tcp_ports.push(e.target.rsplit(':').next().unwrap_or(&e.target).to_string());
        } else {
            out.push((Severity::High, "обход прокси".into(), format!("{} {} — {}", e.kind.label(), e.target, e.detail)));
        }
    }
    if !tcp_ports.is_empty() {
        out.push((
            Severity::High,
            "обход прокси".into(),
            format!("прямой выход по TCP мимо прокси на {} порт(ов): {}", tcp_ports.len(), tcp_ports.join(", ")),
        ));
    }
    for r in &s.rows {
        if matches!(r.kind, ProxyKind::HttpProxy | ProxyKind::Socks5 | ProxyKind::Socks4) && !r.probe.auth_required {
            out.push((Severity::Medium, format!("{}:{}", r.ip, r.port), format!("{} без аутентификации", r.kind.label())));
        }
    }
    if let Some(mx) = &s.tools.matrix {
        for r in mx {
            for e in r.entries.iter().filter(|e| e.verdict == crate::tools::matrix::Verdict::Mismatch) {
                out.push((
                    Severity::High,
                    format!("{} → {}:{}", r.source, e.target, e.port),
                    format!("ожидалось «{}», на деле «{}»", e.expect.label(), e.state.label()),
                ));
            }
        }
    }
    if let Some(u) = &s.tools.urlcheck {
        for r in u.rows.iter().filter(|r| r.mismatch) {
            out.push((
                Severity::Medium,
                format!("{} через {}", r.url, r.proxy),
                format!(
                    "ожидалось «{}», на деле «{}» ({})",
                    if r.expect == Some(true) { "открываться" } else { "блокироваться" },
                    r.outcome.label(),
                    r.detail
                ),
            ));
        }
    }
    for c in crate::tools::certs::collect(s) {
        match c.days_left {
            Some(d) if d < 0 => out.push((Severity::High, c.endpoints.join(", "), format!("сертификат «{}» просрочен ({} дн.)", c.subject, -d))),
            Some(d) if d < 30 => out.push((Severity::Medium, c.endpoints.join(", "), format!("сертификат «{}» истекает через {d} дн.", c.subject))),
            _ => {}
        }
    }
    out.dedup_by(|a, b| a.2 == b.2);
    if let Some(m) = &s.tools.monitor {
        for st in m.states.iter().filter(|x| x.status == Status::Fail) {
            out.push((Severity::Medium, "мониторинг".into(), format!("{}: {}", st.line, st.last.as_ref().map(|l| l.detail.clone()).unwrap_or_default())));
        }
    }
    out.sort_by_key(|f| f.0);
    out
}

pub fn html(s: &Session, title: &str) -> String {
    let mut d = Doc {
        body: String::new(),
        toc: Vec::new(),
    };
    let t = &s.tools;
    let all = findings(s);
    let count = |sev: Severity| all.iter().filter(|f| f.0 == sev).count();

    // Сводка.
    let mut cards: Vec<(String, String, &str)> = vec![
        (count(Severity::High).to_string(), "серьёзных находок".into(), if count(Severity::High) > 0 { "high" } else { "ok" }),
        (count(Severity::Medium).to_string(), "средних".into(), if count(Severity::Medium) > 0 { "med" } else { "ok" }),
        (count(Severity::Low).to_string(), "низких".into(), "low"),
    ];
    let proxies = s.rows.iter().filter(|r| matches!(r.kind, ProxyKind::HttpProxy | ProxyKind::Socks5 | ProxyKind::Socks4)).count();
    if !s.rows.is_empty() {
        cards.push((proxies.to_string(), "прокси-серверов".into(), ""));
    }
    if let Some(dsc) = &t.discovery {
        cards.push((dsc.hosts.iter().filter(|h| h.alive).count().to_string(), "узлов в сети".into(), ""));
    }
    if let Some(sv) = &t.services {
        cards.push((sv.services.len().to_string(), "сервисов".into(), ""));
    }
    if let Some(ad) = &t.ad {
        cards.push((ad.dcs.len().to_string(), format!("контроллеров {}", ad.domain), ""));
    }
    let mut summary = String::from("<div class=\"cards\">");
    for (v, l, c) in &cards {
        let _ = write!(summary, "<div class=\"card\"><b class=\"{c}\">{}</b>{}</div>", esc(v), esc(l));
    }
    summary.push_str("</div>");

    if !all.is_empty() {
        d.section("findings", "Находки");
        d.table(
            &["Важность", "Где", "Что"],
            all.iter()
                .map(|(sev, w, x)| vec![span(sev_class(*sev), sev.label()), format!("<span class=\"mono\">{}</span>", esc(w)), esc(x)])
                .collect(),
        );
    }

    if let Some(ad) = &t.ad {
        d.section("ad", &format!("Домен {}", ad.domain));
        let _ = write!(d.body, "<p><b>{}</b><br><span class=\"muted\">DNS: {}</span></p>", esc(&ad.verdict), esc(&ad.dns_servers.join(", ")));
        d.table(
            &["Контроллер", "Адрес", "Порты", "Kerberos", "Сдвиг часов", "SMB", "LDAPS"],
            ad.dcs
                .iter()
                .map(|dc| {
                    let closed: Vec<String> = dc.ports.iter().filter(|p| !p.open).map(|p| p.port.to_string()).collect();
                    vec![
                        esc(dc.attr("dnsHostName").unwrap_or(&dc.host)),
                        format!("<span class=\"mono\">{}</span>", dc.ip.map(|i| i.to_string()).unwrap_or_default()),
                        if closed.is_empty() { span("ok", "все открыты") } else { span("high", &format!("закрыты: {}", closed.join(", "))) },
                        if dc.kdc.iter().any(|k| k.ok) { span("ok", "отвечает") } else { span("high", "нет") },
                        dc.skew().map(|(v, src)| {
                            let cls = if v.abs() > 300.0 { "high" } else if v.abs() > 60.0 { "med" } else { "ok" };
                            span(cls, &format!("{v:+.1} с ({src})"))
                        }).unwrap_or_default(),
                        match dc.smb_signing_required {
                            Some(true) => span("ok", "подпись обязательна"),
                            Some(false) => span("high", "подпись не обязательна"),
                            None => String::new(),
                        },
                        dc.ldaps
                            .as_ref()
                            .and_then(|l| l.chain.first().map(|c| (c.days_left, l.trust_error.is_none())))
                            .map(|(days, trusted)| span(if days < 30 || !trusted { "med" } else { "ok" }, &format!("{days} дн.{}", if trusted { "" } else { ", не доверен" })))
                            .unwrap_or_default(),
                    ]
                })
                .collect(),
        );
    }

    if let Some(a) = &t.audit {
        d.section("audit", "Аудит настроек");
        let _ = write!(
            d.body,
            "<p>Проверено сервисов: {}. Высокая важность: {}, средняя: {}, низкая: {}.</p>",
            a.services.len(),
            a.count(Severity::High),
            a.count(Severity::Medium),
            a.count(Severity::Low)
        );
        d.table(
            &["Важность", "Узел", "Сервис", "Проблема", "Что сделать"],
            a.issues
                .iter()
                .map(|i| {
                    vec![
                        span(sev_class(i.severity), i.severity.label()),
                        format!("<span class=\"mono\">{}:{}/{}</span>", i.ip, i.port, i.proto),
                        esc(&i.service),
                        esc(&i.title),
                        esc(&i.advice),
                    ]
                })
                .collect(),
        );
    }

    if !s.rows.is_empty() {
        d.section("proxies", "Прокси-серверы");
        d.table(
            &["Адрес", "Тип", "Аутентификация", "CONNECT", "SSL-инспекция", "Server"],
            s.rows
                .iter()
                .filter(|r| r.kind != ProxyKind::NotProxy)
                .map(|r| {
                    vec![
                        format!("<span class=\"mono\">{}:{}</span>", r.ip, r.port),
                        esc(r.kind.label()),
                        esc(&r.auth_label()),
                        r.probe.connect_status.map(|c| c.to_string()).unwrap_or_default(),
                        if r.ssl == SslInspection::Yes { span("med", r.ssl.label()) } else { esc(r.ssl.label()) },
                        esc(&r.probe.server),
                    ]
                })
                .collect(),
        );
    }
    if !s.egress.is_empty() {
        d.section("egress", "Обход прокси");
        d.table(
            &["Проверка", "Цель", "Результат", "Подробности"],
            s.egress
                .iter()
                .map(|e| {
                    vec![
                        esc(e.kind.label()),
                        format!("<span class=\"mono\">{}</span>", esc(&e.target)),
                        if e.status.is_leak() { span("high", e.status.label()) } else { span("ok", e.status.label()) },
                        esc(&e.detail),
                    ]
                })
                .collect(),
        );
    }
    if let Some(tl) = &t.tls {
        d.section("tls", "TLS-аудит");
        d.table(
            &["Узел", "Оценка", "Версии", "Сертификат", "Издатель", "Дней", "Замечаний"],
            tl.targets
                .iter()
                .map(|x| {
                    let leaf = x.chain.first();
                    let cls = match x.grade.as_str() {
                        "A" | "A-" => "ok",
                        "B" => "med",
                        _ => "high",
                    };
                    vec![
                        format!("<span class=\"mono\">{}:{}</span>", esc(&x.host), x.port),
                        span(cls, &x.grade),
                        esc(&x.versions.iter().filter(|v| v.supported).map(|v| v.version.clone()).collect::<Vec<_>>().join(", ")),
                        esc(&leaf.map(|l| l.short_subject()).unwrap_or_default()),
                        esc(&leaf.map(|l| l.short_issuer()).unwrap_or_default()),
                        leaf.map(|l| l.days_left.to_string()).unwrap_or_default(),
                        x.findings.len().to_string(),
                    ]
                })
                .collect(),
        );
    }
    if let Some(mx) = &t.matrix {
        d.section("matrix", "Доступность портов");
        d.table(
            &["Откуда", "Куда", "Ожидание", "Результат", "Итог"],
            mx.iter()
                .flat_map(|r| r.entries.iter().map(move |e| (r, e)))
                .map(|(r, e)| {
                    vec![
                        esc(&r.source),
                        format!("<span class=\"mono\">{}:{}</span>", esc(&e.target), e.port),
                        esc(e.expect.label()),
                        esc(e.state.label()),
                        match e.verdict {
                            crate::tools::matrix::Verdict::Ok => span("ok", "как ожидалось"),
                            crate::tools::matrix::Verdict::Mismatch => span("high", "расхождение"),
                            crate::tools::matrix::Verdict::Info => String::new(),
                        },
                    ]
                })
                .collect(),
        );
    }
    let certs = crate::tools::certs::collect(s);
    if !certs.is_empty() {
        d.section("certs", "Сертификаты");
        d.table(
            &["Состояние", "Дней", "Субъект", "Издатель", "Где"],
            certs
                .iter()
                .map(|c| {
                    let st = c.status(30);
                    let cls = match st {
                        "просрочен" => "high",
                        "истекает" | "не доверен" => "med",
                        _ => "ok",
                    };
                    vec![
                        span(cls, st),
                        c.days_left.map(|d| d.to_string()).unwrap_or_default(),
                        esc(&c.subject),
                        esc(&c.issuer),
                        format!("<span class=\"mono\">{}</span>", esc(&c.endpoints.join(", "))),
                    ]
                })
                .collect(),
        );
    }
    if let Some(sv) = &t.services {
        d.section("services", "Сервисы");
        d.table(
            &["Адрес", "Порт", "Сервис", "Версия", "Подробности"],
            sv.services
                .iter()
                .map(|x| {
                    vec![
                        format!("<span class=\"mono\">{}</span>", x.ip),
                        format!("{}/{}", x.port, x.proto),
                        esc(&x.service),
                        esc(&x.version),
                        esc(&x.details.join("; ")),
                    ]
                })
                .collect(),
        );
    }
    if let Some(dsc) = &t.discovery {
        d.section("hosts", "Узлы в сети");
        d.table(
            &["Адрес", "MAC", "Производитель", "Имя", "ОС", "Порты"],
            dsc.hosts
                .iter()
                .filter(|h| h.alive)
                .map(|h| {
                    vec![
                        format!("<span class=\"mono\">{}</span>", h.ip),
                        format!("<span class=\"mono\">{}</span>", esc(h.mac.as_deref().unwrap_or(""))),
                        esc(h.vendor.as_deref().unwrap_or("")),
                        esc(&h.best_name()),
                        esc(h.os_guess.as_deref().unwrap_or("")),
                        h.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
                    ]
                })
                .collect(),
        );
    }
    if let Some(m) = &t.monitor {
        d.section("monitor", "Мониторинг");
        d.table(
            &["Состояние", "Проверка", "Доступность", "Последний результат"],
            m.states
                .iter()
                .map(|x| {
                    let cls = match x.status {
                        Status::Ok => "ok",
                        Status::Warn => "med",
                        Status::Fail => "high",
                        Status::Unknown => "muted",
                    };
                    vec![
                        span(cls, x.status.label()),
                        format!("<span class=\"mono\">{}</span>", esc(&x.line)),
                        format!("{:.1}%", x.availability()),
                        esc(&x.last.as_ref().map(|l| l.detail.clone()).unwrap_or_default()),
                    ]
                })
                .collect(),
        );
    }
    if let Some(mt) = &t.mtr {
        d.section("mtr", &format!("Трассировка до {}", mt.target));
        d.table(
            &["#", "Узел", "Потери", "Среднее, мс", "Худшее, мс"],
            mt.hops
                .iter()
                .map(|h| {
                    let l = h.loss_pct();
                    vec![
                        h.ttl.to_string(),
                        format!("<span class=\"mono\">{}</span>", esc(&h.host_label())),
                        span(if l == 0.0 { "ok" } else if l < 20.0 { "med" } else { "high" }, &format!("{l:.0}%")),
                        if h.recv > 0 { format!("{:.1}", h.avg_ms) } else { "—".into() },
                        h.worst_ms.map(|v| format!("{v:.1}")).unwrap_or("—".into()),
                    ]
                })
                .collect(),
        );
    }
    if let Some(h) = &t.host {
        d.section("host", &format!("Рабочая станция {}", h.hostname));
        let _ = write!(d.body, "<p class=\"muted\">{}</p>", esc(&h.os));
        d.table(
            &["Интерфейс", "MAC", "Адреса", "Шлюз", "DNS"],
            h.interfaces
                .iter()
                .filter(|i| !i.addrs.is_empty())
                .map(|i| {
                    vec![
                        esc(&i.name),
                        format!("<span class=\"mono\">{}</span>", esc(&i.mac)),
                        format!("<span class=\"mono\">{}</span>", esc(&i.addrs.join(", "))),
                        esc(&i.gateways.join(", ")),
                        esc(&i.dns.join(", ")),
                    ]
                })
                .collect(),
        );
    }

    let mut toc = String::from("<nav>");
    for (id, t) in &d.toc {
        let _ = write!(toc, "<a href=\"#{id}\">{}</a>", esc(t));
    }
    toc.push_str("</nav>");
    format!(
        "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title><style>{STYLE}</style></head><body><main><h1>{}</h1>\
         <div class=\"muted\">ПК {} · сессия сохранена {} · отчёт Proxy Scanner {}</div>{summary}{toc}{}</main></body></html>",
        esc(title),
        esc(title),
        esc(&s.computer),
        esc(&crate::session::format_time(s.saved_at)),
        env!("CARGO_PKG_VERSION"),
        d.body
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Settings;

    #[test]
    fn report_contains_sections_and_escapes() {
        let mut s = Session::new(&Settings::default(), None, Vec::new());
        s.tools.audit = Some(crate::tools::audit::Report {
            issues: vec![crate::tools::audit::Issue {
                ip: "10.0.0.5".parse().unwrap(),
                port: 23,
                proto: "tcp".into(),
                service: "telnet".into(),
                severity: Severity::High,
                title: "Telnet <script>".into(),
                advice: "Отключите".into(),
            }],
            ..Default::default()
        });
        let html = html(&s, "Проверка");
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("id=\"findings\""));
        assert!(html.contains("id=\"audit\""));
        assert!(html.contains("Telnet &lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("http://") && !html.contains("https://"), "отчёт не должен ссылаться на внешние ресурсы");
    }
}
