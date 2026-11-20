//! Сравнение двух сессий: что появилось, пропало и изменилось — узлы, порты и сервисы,
//! прокси, сертификаты, DNS-ответы, находки аудита и домена, обход прокси.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::session::Session;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Kind {
    Added,
    Removed,
    Changed,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Added => "появилось",
            Kind::Removed => "пропало",
            Kind::Changed => "изменилось",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub category: String,
    pub key: String,
    pub kind: Kind,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Diff {
    pub old_label: String,
    pub new_label: String,
    pub changes: Vec<Change>,
}

impl Diff {
    pub fn categories(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for c in &self.changes {
            if !v.contains(&c.category) {
                v.push(c.category.clone());
            }
        }
        v
    }
}

/// Сравнение двух словарей «ключ → описание».
fn diff_maps(out: &mut Vec<Change>, category: &str, old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) {
    for (k, v) in new {
        match old.get(k) {
            None => out.push(Change { category: category.into(), key: k.clone(), kind: Kind::Added, before: String::new(), after: v.clone() }),
            Some(o) if o != v => out.push(Change { category: category.into(), key: k.clone(), kind: Kind::Changed, before: o.clone(), after: v.clone() }),
            _ => {}
        }
    }
    for (k, v) in old {
        if !new.contains_key(k) {
            out.push(Change { category: category.into(), key: k.clone(), kind: Kind::Removed, before: v.clone(), after: String::new() });
        }
    }
}

fn hosts(s: &Session) -> Option<BTreeMap<String, String>> {
    let d = s.tools.discovery.as_ref()?;
    Some(
        d.hosts
            .iter()
            .filter(|h| h.alive)
            .map(|h| {
                let desc = [h.mac.clone().unwrap_or_default(), h.best_name(), h.os_guess.clone().unwrap_or_default()]
                    .into_iter()
                    .filter(|x| !x.is_empty())
                    .collect::<Vec<_>>()
                    .join(" · ");
                (h.ip.to_string(), desc)
            })
            .collect(),
    )
}

fn services(s: &Session) -> Option<BTreeMap<String, String>> {
    let lists: Vec<_> = [s.tools.services.as_ref().map(|x| &x.services), s.tools.audit.as_ref().map(|x| &x.services)]
        .into_iter()
        .flatten()
        .collect();
    if lists.is_empty() {
        return None;
    }
    let mut m = BTreeMap::new();
    for l in lists {
        for sv in l {
            m.insert(format!("{}:{}/{}", sv.ip, sv.port, sv.proto), format!("{} {}", sv.service, sv.version).trim().to_string());
        }
    }
    Some(m)
}

fn proxies(s: &Session) -> Option<BTreeMap<String, String>> {
    if s.rows.is_empty() {
        return None;
    }
    Some(
        s.rows
            .iter()
            .map(|r| (format!("{}:{}", r.ip, r.port), format!("{} · {} · SSL {}", r.kind.label(), r.auth_label(), r.ssl.label())))
            .collect(),
    )
}

fn certs(s: &Session) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for c in super::certs::collect(s) {
        for e in &c.endpoints {
            m.insert(
                e.clone(),
                format!(
                    "{} ← {}, до {}{}",
                    c.subject,
                    c.issuer,
                    if c.not_after.is_empty() { c.days_left.map(|d| format!("{d} дн.")).unwrap_or_default() } else { c.not_after.clone() },
                    if c.sha256.is_empty() { String::new() } else { format!(" [{}]", &c.sha256[..c.sha256.len().min(12)]) }
                ),
            );
        }
    }
    m
}

fn tls_grades(s: &Session) -> Option<BTreeMap<String, String>> {
    let t = s.tools.tls.as_ref()?;
    Some(
        t.targets
            .iter()
            .map(|x| {
                let v: Vec<String> = x.versions.iter().filter(|v| v.supported).map(|v| v.version.clone()).collect();
                (format!("{}:{}", x.host, x.port), format!("оценка {} · {}", x.grade, v.join(", ")))
            })
            .collect(),
    )
}

fn dns(s: &Session) -> Option<BTreeMap<String, String>> {
    let d = s.tools.dns.as_ref()?;
    Some(d.answers.iter().map(|a| (format!("{} {} @{}", a.name, a.qtype, a.server), a.signature())).collect())
}

fn findings(s: &Session) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(a) = &s.tools.audit {
        for i in &a.issues {
            m.insert(format!("{}:{}/{} {}", i.ip, i.port, i.proto, i.title), i.severity.label().to_string());
        }
    }
    if let Some(ad) = &s.tools.ad {
        for f in &ad.findings {
            m.insert(format!("домен {}: {}", ad.domain, f.text), f.severity.label().to_string());
        }
    }
    m
}

fn egress(s: &Session) -> Option<BTreeMap<String, String>> {
    if s.egress.is_empty() {
        return None;
    }
    Some(s.egress.iter().map(|e| (format!("{} {}", e.kind.label(), e.target), e.status.label().to_string())).collect())
}

fn matrix(s: &Session) -> Option<BTreeMap<String, String>> {
    let reports = s.tools.matrix.as_ref()?;
    let mut m = BTreeMap::new();
    for r in reports {
        for e in &r.entries {
            m.insert(format!("{} → {}:{}", r.source, e.target, e.port), e.state.label().to_string());
        }
    }
    Some(m)
}

pub fn label(s: &Session) -> String {
    format!("{} · {}", s.computer, crate::session::format_time(s.saved_at))
}

/// Сравнение. Раздел сравнивается, только если он есть в обеих сессиях
/// (иначе всё выглядело бы «появившимся» или «пропавшим»).
pub fn diff(old: &Session, new: &Session) -> Diff {
    let mut out = Vec::new();
    type Getter = fn(&Session) -> Option<BTreeMap<String, String>>;
    let optional: [(&str, Getter); 7] = [
        ("Узлы", hosts),
        ("Сервисы", services),
        ("Прокси", proxies),
        ("TLS", tls_grades),
        ("DNS", dns),
        ("Обход прокси", egress),
        ("Матрица доступности", matrix),
    ];
    for (cat, get) in optional {
        if let (Some(a), Some(b)) = (get(old), get(new)) {
            diff_maps(&mut out, cat, &a, &b);
        }
    }
    let (c1, c2) = (certs(old), certs(new));
    if !c1.is_empty() && !c2.is_empty() {
        diff_maps(&mut out, "Сертификаты", &c1, &c2);
    }
    let (f1, f2) = (findings(old), findings(new));
    if old.tools.audit.is_some() && new.tools.audit.is_some() || old.tools.ad.is_some() && new.tools.ad.is_some() {
        diff_maps(&mut out, "Находки", &f1, &f2);
    }
    Diff {
        old_label: label(old),
        new_label: label(new),
        changes: out,
    }
}

pub fn render_text(d: &Diff) -> String {
    let mut s = format!("Было: {}\nСтало: {}\nИзменений: {}\n", d.old_label, d.new_label, d.changes.len());
    for cat in d.categories() {
        s += &format!("\n== {cat}\n");
        for c in d.changes.iter().filter(|c| c.category == cat) {
            let sign = match c.kind {
                Kind::Added => "+",
                Kind::Removed => "-",
                Kind::Changed => "~",
            };
            s += &match c.kind {
                Kind::Changed => format!("{sign} {}: {} → {}\n", c.key, c.before, c.after),
                Kind::Added => format!("{sign} {}: {}\n", c.key, c.after),
                Kind::Removed => format!("{sign} {}: {}\n", c.key, c.before),
            };
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::services::Service;

    fn svc(port: u16, version: &str) -> Service {
        Service {
            ip: "10.0.0.1".parse().unwrap(),
            port,
            proto: "tcp".into(),
            state: "open".into(),
            service: "http".into(),
            version: version.into(),
            tls: None,
            banner: String::new(),
            details: vec![],
            rtt_ms: None,
        }
    }

    #[test]
    fn detects_changes() {
        let settings = crate::model::Settings::default();
        let mut a = Session::new(&settings, None, vec![]);
        let mut b = Session::new(&settings, None, vec![]);
        a.tools.services = Some(crate::tools::services::Report { services: vec![svc(80, "nginx/1.18"), svc(8080, "")] });
        b.tools.services = Some(crate::tools::services::Report { services: vec![svc(80, "nginx/1.24"), svc(443, "")] });
        // DNS есть только в одной сессии — не сравнивается.
        b.tools.dns = Some(Default::default());
        let d = diff(&a, &b);
        let kinds: Vec<(Kind, &str)> = d.changes.iter().map(|c| (c.kind, c.key.as_str())).collect();
        assert!(kinds.contains(&(Kind::Changed, "10.0.0.1:80/tcp")));
        assert!(kinds.contains(&(Kind::Added, "10.0.0.1:443/tcp")));
        assert!(kinds.contains(&(Kind::Removed, "10.0.0.1:8080/tcp")));
        assert_eq!(d.categories(), vec!["Сервисы"]);
        assert!(render_text(&d).contains("nginx/1.18 → http nginx/1.24") || render_text(&d).contains("→"));
    }
}
