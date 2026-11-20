//! Карточка узла: всё, что программа знает об адресе, собранное из всех разделов.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::session::Session;

/// Заметка и метки пользователя к узлу (хранятся в сессии).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostNote {
    /// Метки через запятую: «сервер», «1С», «ответственный Иванов».
    pub tags: String,
    pub text: String,
}

impl HostNote {
    pub fn is_empty(&self) -> bool {
        self.tags.trim().is_empty() && self.text.trim().is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Normal,
    Good,
    Warn,
    Bad,
}

#[derive(Debug, Clone)]
pub struct Line {
    pub text: String,
    pub level: Level,
}

#[derive(Debug, Clone, Default)]
pub struct Card {
    pub ip: String,
    pub title: String,
    pub subtitle: Vec<String>,
    pub mac: Option<String>,
    pub sections: Vec<(String, Vec<Line>)>,
}

fn line(text: impl Into<String>, level: Level) -> Line {
    Line { text: text.into(), level }
}

pub fn build(s: &Session, ip: Ipv4Addr) -> Card {
    use Level::*;
    let t = &s.tools;
    let ips = ip.to_string();
    let mut card = Card {
        ip: ips.clone(),
        title: ips.clone(),
        ..Default::default()
    };
    let mut names: Vec<String> = Vec::new();
    let mut general: Vec<Line> = Vec::new();
    let mut mac: Option<String> = None;
    let mut vendor: Option<String> = None;

    if let Some(d) = &t.discovery
        && let Some(h) = d.hosts.iter().find(|h| h.ip == ip)
    {
        names.extend([h.dns_name.clone(), h.netbios.as_ref().and_then(|n| n.name.clone()), h.mdns_name.clone()].into_iter().flatten());
        mac = mac.or(h.mac.clone());
        vendor = vendor.or(h.vendor.clone());
        if let Some(os) = &h.os_guess {
            general.push(line(format!("ОС (догадка): {os}"), Normal));
        }
        if let Some(r) = h.rtt_ms {
            general.push(line(format!("отклик {r:.1} мс, TTL {}", h.ttl.map(|x| x.to_string()).unwrap_or("-".into())), Normal));
        }
        if let Some(nb) = &h.netbios {
            if let Some(g) = &nb.group {
                general.push(line(format!("NetBIOS: группа {g}{}", nb.user.as_ref().map(|u| format!(", пользователь {u}")).unwrap_or_default()), Normal));
            }
            for r in &nb.roles {
                general.push(line(format!("роль: {r}"), Normal));
            }
        }
        if let Some(sd) = &h.ssdp {
            general.push(line(format!("SSDP: {sd}"), Normal));
        }
    }
    if let Some(w) = &t.watch
        && let Some(h) = w.last.as_ref().and_then(|l| l.hosts.get(&ip))
    {
        names.extend(h.name.clone());
        mac = mac.or(h.mac.clone());
        vendor = vendor.or(h.vendor.clone());
    }
    if mac.is_none()
        && let Some(n) = t.host.as_ref().and_then(|h| h.neighbors.iter().find(|n| n.ip == ips))
    {
        mac = Some(n.mac.clone());
        vendor = vendor.or(n.vendor.clone());
    }
    if mac.is_none()
        && let Some(m) = t.capture.as_ref().and_then(|c| c.arp.get(&ips)).and_then(|v| v.first())
    {
        mac = Some(m.clone());
    }
    names.dedup();
    if let Some(n) = names.first() {
        card.title = format!("{n} ({ips})");
    }
    if names.len() > 1 {
        general.insert(0, line(format!("имена: {}", names.join(", ")), Normal));
    }
    if let Some(m) = &mac {
        card.subtitle.push(format!("MAC {m}{}", vendor.as_ref().map(|v| format!(" · {v}")).unwrap_or_default()));
    }
    // Где воткнут.
    if let (Some(sn), Some(m)) = (&t.snmp, &mac)
        && let Some(l) = sn.locate(m)
    {
        card.subtitle.push(format!(
            "воткнут: {} порт {}{}{}",
            l.switch,
            l.port,
            l.vlan.map(|v| format!(", VLAN {v}")).unwrap_or_default(),
            if l.alias.is_empty() { String::new() } else { format!(" «{}»", l.alias) }
        ));
    }
    if !general.is_empty() {
        card.sections.push(("Общее".into(), general));
    }

    // Порты и сервисы.
    let mut svc: Vec<Line> = Vec::new();
    let mut seen_ports = std::collections::BTreeSet::new();
    for list in [t.services.as_ref().map(|x| &x.services), t.audit.as_ref().map(|x| &x.services)].into_iter().flatten() {
        for sv in list.iter().filter(|x| x.ip == ip) {
            if !seen_ports.insert((sv.port, sv.proto.clone())) {
                continue;
            }
            let mut text = format!("{}/{} {} {}", sv.port, sv.proto, sv.service, sv.version);
            if let Some(tl) = &sv.tls {
                text += &format!(" · TLS {} ({} дн.)", tl.version, tl.days_left);
            }
            svc.push(line(text.trim().to_string(), Normal));
            for v in crate::tools::cve::check(sv) {
                svc.push(line(format!("   ⚠ {} {} {}: {}", v.product, v.version, v.cve, v.title), Bad));
            }
        }
    }
    if let Some(d) = &t.discovery
        && let Some(h) = d.hosts.iter().find(|h| h.ip == ip)
    {
        for p in &h.open_ports {
            if seen_ports.insert((*p, "tcp".into())) {
                svc.push(line(format!("{p}/tcp открыт"), Normal));
            }
        }
    }
    for r in s.rows.iter().filter(|r| r.ip == ip) {
        let auth = if r.probe.auth_required { "с входом" } else { "без входа" };
        svc.push(line(
            format!("{}/tcp {} · {auth}{}", r.port, r.kind.label(), if r.probe.server.is_empty() { String::new() } else { format!(" · {}", r.probe.server) }),
            if r.probe.auth_required { Normal } else { Warn },
        ));
    }
    if !svc.is_empty() {
        card.sections.push(("Порты и сервисы".into(), svc));
    }

    // Находки: аудит и TLS.
    let mut issues: Vec<Line> = Vec::new();
    if let Some(a) = &t.audit {
        for i in a.issues.iter().filter(|i| i.ip == ip) {
            let lvl = match i.severity {
                crate::tools::tlsaudit::Severity::High => Bad,
                crate::tools::tlsaudit::Severity::Medium => Warn,
                _ => Normal,
            };
            issues.push(line(format!("{}/{}: {} → {}", i.port, i.proto, i.title, i.advice), lvl));
        }
    }
    if let Some(tl) = &t.tls {
        for tg in tl.targets.iter().filter(|x| x.address.starts_with(&format!("{ips}:")) || x.host == ips) {
            let lvl = if tg.grade.starts_with('A') { Good } else if tg.grade.starts_with('F') || tg.grade.starts_with('T') { Bad } else { Warn };
            issues.push(line(format!("TLS {}:{} — оценка {}", tg.host, tg.port, tg.grade), lvl));
        }
    }
    if !issues.is_empty() {
        card.sections.push(("Находки".into(), issues));
    }

    // Сертификаты.
    let certs: Vec<Line> = crate::tools::certs::collect(s)
        .into_iter()
        .filter(|c| c.endpoints.iter().any(|e| e.starts_with(&format!("{ips}:")) || names.iter().any(|n| e.starts_with(&format!("{n}:")))))
        .map(|c| {
            let lvl = match c.days_left {
                Some(d) if d < 0 => Bad,
                Some(d) if d < 30 => Warn,
                _ => Normal,
            };
            line(format!("{} ← {} · до {} ({} дн.)", c.subject, c.issuer, c.not_after, c.days_left.map(|d| d.to_string()).unwrap_or("?".into())), lvl)
        })
        .collect();
    if !certs.is_empty() {
        card.sections.push(("Сертификаты".into(), certs));
    }

    // Мониторинг.
    let mon: Vec<Line> = t
        .monitor
        .iter()
        .flat_map(|m| m.states.iter())
        .filter(|st| st.line.contains(&ips) || names.iter().any(|n| st.line.contains(n.as_str())))
        .map(|st| {
            let lvl = match st.status {
                crate::tools::monitor::Status::Fail => Bad,
                crate::tools::monitor::Status::Warn => Warn,
                crate::tools::monitor::Status::Ok => Good,
                _ => Normal,
            };
            line(format!("{} — {} · доступность {:.1}%", st.line, st.status.label(), st.availability()), lvl)
        })
        .collect();
    if !mon.is_empty() {
        card.sections.push(("Мониторинг".into(), mon));
    }

    // История из наблюдения.
    let hist: Vec<Line> = t
        .watch
        .iter()
        .flat_map(|w| w.changes.iter())
        .filter(|c| c.host == ip)
        .rev()
        .take(30)
        .map(|c| line(format!("{} {} {}", crate::session::format_time(c.at), c.kind.label(), c.detail), if c.alarm { Bad } else { Normal }))
        .collect();
    if !hist.is_empty() {
        card.sections.push(("История изменений".into(), hist));
    }

    // Трафик и угрозы.
    let mut traffic: Vec<Line> = Vec::new();
    if let Some(c) = &t.capture {
        let mut peers: Vec<(String, u64)> = c
            .talk
            .iter()
            .filter_map(|(k, n)| {
                let (a, b) = k.split_once(" ↔ ")?;
                if a == ips {
                    Some((b.to_string(), *n))
                } else if b == ips {
                    Some((a.to_string(), *n))
                } else {
                    None
                }
            })
            .collect();
        peers.sort_by_key(|x| std::cmp::Reverse(x.1));
        for (p, n) in peers.iter().take(8) {
            traffic.push(line(format!("↔ {p}: {:.1} МБ", *n as f64 / 1e6), Normal));
        }
        if c.dhcp.len() > 1 && c.dhcp.iter().any(|d| d.ip == ips) {
            traffic.push(line("раздаёт адреса по DHCP (в сегменте несколько DHCP-серверов)", Bad));
        }
        if let Some(names) = c.name_responders.get(&ips)
            && names.len() >= 3
        {
            traffic.push(line(format!("отвечает на {} широковещательных имён — похоже на Responder", names.len()), Bad));
        }
        if c.arp.get(&ips).is_some_and(|m| m.len() > 1) {
            traffic.push(line(format!("адрес отвечает с разных MAC: {}", c.arp[&ips].join(", ")), Bad));
        }
    }
    if !traffic.is_empty() {
        card.sections.push(("Трафик".into(), traffic));
    }
    card.mac = mac;
    card
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gathers_from_tools() {
        let mut s = Session::new(&crate::model::Settings::default(), None, Vec::new());
        s.tools.discovery = Some(crate::tools::discovery::Report {
            hosts: vec![crate::tools::discovery::Host {
                ip: "10.0.0.5".parse().unwrap(),
                alive: true,
                dns_name: Some("srv.corp.local".into()),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                open_ports: vec![22, 445],
                ..Default::default()
            }],
        });
        let c = build(&s, "10.0.0.5".parse().unwrap());
        assert_eq!(c.title, "srv.corp.local (10.0.0.5)");
        assert_eq!(c.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        let ports = &c.sections.iter().find(|x| x.0 == "Порты и сервисы").unwrap().1;
        assert_eq!(ports.len(), 2);
    }
}
