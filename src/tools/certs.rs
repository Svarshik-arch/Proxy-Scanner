//! Инвентаризация сертификатов: все сертификаты, найденные в сессии (TLS-аудит,
//! сканер сервисов, LDAPS контроллеров, HTTP, прокси), в одной таблице по сроку окончания.

use serde::{Deserialize, Serialize};

use crate::session::Session;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cert {
    /// Где найден: `узел:порт`.
    pub endpoints: Vec<String>,
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
    pub days_left: Option<i64>,
    pub key: String,
    pub signature: String,
    pub names: Vec<String>,
    pub sha256: String,
    pub trusted: Option<bool>,
    pub self_signed: bool,
    /// Откуда сведения: «TLS-аудит», «сервисы», «AD», «HTTP», «прокси».
    pub sources: Vec<String>,
}

impl Cert {
    pub fn status(&self, warn_days: i64) -> &'static str {
        match self.days_left {
            Some(d) if d < 0 => "просрочен",
            Some(d) if d < warn_days => "истекает",
            _ if self.trusted == Some(false) => "не доверен",
            Some(_) => "в порядке",
            None => "—",
        }
    }
}

fn push(out: &mut Vec<Cert>, c: Cert) {
    // Один и тот же сертификат на разных узлах — одна строка.
    let same = out.iter_mut().find(|x| {
        (!c.sha256.is_empty() && x.sha256 == c.sha256)
            || (c.sha256.is_empty() && x.subject == c.subject && x.not_after == c.not_after && x.issuer == c.issuer)
    });
    match same {
        Some(x) => {
            for e in c.endpoints {
                if !x.endpoints.contains(&e) {
                    x.endpoints.push(e);
                }
            }
            for s in c.sources {
                if !x.sources.contains(&s) {
                    x.sources.push(s);
                }
            }
            if x.trusted.is_none() {
                x.trusted = c.trusted;
            }
            if x.key.is_empty() {
                x.key = c.key;
                x.signature = c.signature;
                x.names = c.names;
            }
            if x.sha256.is_empty() {
                x.sha256 = c.sha256;
            }
        }
        None => out.push(c),
    }
}

fn from_detail(d: &super::tls::CertDetail, endpoint: String, trusted: Option<bool>, source: &str) -> Cert {
    Cert {
        endpoints: vec![endpoint],
        subject: d.short_subject(),
        issuer: d.short_issuer(),
        not_after: d.not_after.clone(),
        days_left: Some(d.days_left),
        key: d.key.clone(),
        signature: d.signature.clone(),
        names: d.names.clone(),
        sha256: d.sha256.clone(),
        trusted,
        self_signed: d.self_signed,
        sources: vec![source.into()],
    }
}

/// Дней до даты в формате x509 (`Dec 19 01:20:08 2026 +00:00`).
fn days_from_x509(s: &str) -> Option<i64> {
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mut it = s.split_whitespace();
    let mon = months.iter().position(|m| Some(*m) == it.next())? + 1;
    let day: u32 = it.next()?.parse().ok()?;
    let _time = it.next()?;
    let year: u32 = it.next()?.parse().ok()?;
    let gt = format!("{year:04}{mon:02}{day:02}000000Z");
    let t = super::ad::generalized_time(&gt)?;
    Some(((t - super::tls::now_unix() as f64) / 86400.0).floor() as i64)
}

pub fn collect(s: &Session) -> Vec<Cert> {
    let mut out = Vec::new();
    let t = &s.tools;
    if let Some(tls) = &t.tls {
        for tg in &tls.targets {
            if let Some(leaf) = tg.chain.first() {
                push(&mut out, from_detail(leaf, format!("{}:{}", tg.host, tg.port), Some(tg.trust_error.is_none()), "TLS-аудит"));
            }
        }
    }
    if let Some(ad) = &t.ad {
        for dc in &ad.dcs {
            if let Some(l) = &dc.ldaps
                && let Some(leaf) = l.chain.first()
            {
                push(&mut out, from_detail(leaf, format!("{}:636", dc.attr("dnsHostName").unwrap_or(&dc.host)), Some(l.trust_error.is_none()), "AD (LDAPS)"));
            }
        }
    }
    if let Some(http) = &t.http {
        for run in &http.runs {
            for hop in run {
                if let Some(tl) = &hop.tls
                    && let Some(leaf) = tl.chain.first()
                {
                    let ep = crate::probe::Url::parse(&hop.url).map(|u| format!("{}:{}", u.host, u.port)).unwrap_or(hop.url.clone());
                    push(&mut out, from_detail(leaf, ep, Some(tl.trust_error.is_none()), "HTTP"));
                }
            }
        }
    }
    for svc_list in [t.services.as_ref().map(|x| &x.services), t.audit.as_ref().map(|x| &x.services)].into_iter().flatten() {
        for sv in svc_list {
            if let Some(tl) = &sv.tls {
                push(
                    &mut out,
                    Cert {
                        endpoints: vec![format!("{}:{}", sv.ip, sv.port)],
                        subject: tl.subject.clone(),
                        issuer: tl.issuer.clone(),
                        days_left: Some(tl.days_left),
                        trusted: Some(tl.trusted),
                        sources: vec!["сервисы".into()],
                        ..Default::default()
                    },
                );
            }
        }
    }
    for r in &s.rows {
        if let Some(c) = &r.probe.cert {
            push(
                &mut out,
                Cert {
                    endpoints: vec![format!("через прокси {}:{}", r.ip, r.port)],
                    subject: super::tls::short_dn(&c.subject),
                    issuer: super::tls::short_dn(&c.issuer),
                    not_after: c.not_after.clone(),
                    days_left: days_from_x509(&c.not_after),
                    names: c.names.clone(),
                    sha256: c.sha256.clone(),
                    self_signed: c.self_signed,
                    sources: vec!["прокси".into()],
                    ..Default::default()
                },
            );
        }
    }
    out.sort_by_key(|c| c.days_left.unwrap_or(i64::MAX));
    out
}

/// CSV для Excel: `;`, BOM.
pub fn to_csv(certs: &[Cert], warn_days: i64) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let mut s = String::from("\u{feff}Состояние;Дней;Действует до;Субъект;Издатель;Узлы;Имена;Ключ;Подпись;Доверен;SHA-256;Источник\r\n");
    for c in certs {
        s += &[
            q(c.status(warn_days)),
            c.days_left.map(|d| d.to_string()).unwrap_or_default(),
            q(&c.not_after),
            q(&c.subject),
            q(&c.issuer),
            q(&c.endpoints.join(", ")),
            q(&c.names.join(", ")),
            q(&c.key),
            q(&c.signature),
            match c.trusted {
                Some(true) => "да".into(),
                Some(false) => "нет".into(),
                None => String::new(),
            },
            q(&c.sha256),
            q(&c.sources.join(", ")),
        ]
        .join(";");
        s += "\r\n";
    }
    s
}

pub fn render_text(certs: &[Cert], warn_days: i64) -> String {
    let mut s = format!("{:<11} {:>6}  {:<36} {:<32} {}\n", "состояние", "дней", "субъект", "издатель", "узлы");
    for c in certs {
        s += &format!(
            "{:<11} {:>6}  {:<36} {:<32} {}\n",
            c.status(warn_days),
            c.days_left.map(|d| d.to_string()).unwrap_or("-".into()),
            c.subject.chars().take(36).collect::<String>(),
            c.issuer.chars().take(32).collect::<String>(),
            c.endpoints.join(", ")
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_and_deduplicates() {
        let mut s = Session::new(&crate::model::Settings::default(), None, Vec::new());
        let leaf = super::super::tls::CertDetail {
            subject: "CN=portal".into(),
            issuer: "CN=Corp CA".into(),
            not_after: "x".into(),
            days_left: 10,
            sha256: "AA".into(),
            ..Default::default()
        };
        let target = |host: &str| super::super::tlsaudit::Target {
            host: host.into(),
            port: 443,
            chain: vec![leaf.clone()],
            ..Default::default()
        };
        let old = super::super::tls::CertDetail { days_left: 300, sha256: "BB".into(), subject: "CN=old".into(), ..leaf.clone() };
        s.tools.tls = Some(super::super::tlsaudit::Report {
            targets: vec![
                target("a"),
                target("b"),
                super::super::tlsaudit::Target { host: "c".into(), port: 8443, chain: vec![old], ..Default::default() },
            ],
        });
        let c = collect(&s);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].endpoints, vec!["a:443", "b:443"]);
        assert_eq!(c[0].status(30), "истекает");
        assert_eq!(c[1].status(30), "в порядке");
        let csv = to_csv(&c, 30);
        assert!(csv.starts_with('\u{feff}'));
        assert!(csv.contains("\"a:443, b:443\""));
    }

    #[test]
    fn x509_dates() {
        let d = days_from_x509("Jan 1 00:00:00 2100 +00:00").unwrap();
        assert!(d > 20_000);
        assert!(days_from_x509("bogus").is_none());
    }
}
