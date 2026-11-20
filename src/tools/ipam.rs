//! Учёт адресов: какие адреса заняты (по всем собранным данным), какие свободны,
//! какие давно не появлялись; расхождения DNS (нет обратной записи, обратная и прямая
//! не совпадают) и конфликты адресов (один IP — разные MAC).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;
use crate::session::Session;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Подсети учёта (пусто — подсети найденных узлов).
    pub subnets: String,
    /// «Давно не появлялся» — дней без ответа в наблюдении.
    pub stale_days: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            subnets: String::new(),
            stale_days: 30,
        }
    }
}

/// Что известно об адресе.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Known {
    pub mac: Vec<String>,
    pub name: Option<String>,
    /// Откуда известно: «узлы», «наблюдение», «ARP», «прокси», «сервисы», «трафик».
    pub sources: Vec<String>,
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
}

fn add(m: &mut BTreeMap<Ipv4Addr, Known>, ip: Ipv4Addr, src: &str, mac: Option<&str>, name: Option<&str>) {
    let k = m.entry(ip).or_default();
    if !k.sources.iter().any(|s| s == src) {
        k.sources.push(src.into());
    }
    if let Some(mac) = mac.filter(|x| !x.is_empty()) {
        let n = super::snmp::norm_mac(mac);
        if !k.mac.contains(&n) {
            k.mac.push(n);
        }
    }
    if k.name.is_none() {
        k.name = name.filter(|x| !x.is_empty()).map(String::from);
    }
}

/// Занятые адреса по всем разделам сессии.
pub fn known_hosts(s: &Session) -> BTreeMap<Ipv4Addr, Known> {
    let mut m = BTreeMap::new();
    let t = &s.tools;
    if let Some(d) = &t.discovery {
        for h in d.hosts.iter().filter(|h| h.alive) {
            let name = h.best_name();
            add(&mut m, h.ip, "узлы", h.mac.as_deref(), Some(&name));
        }
    }
    if let Some(w) = &t.watch {
        if let Some(l) = &w.last {
            for (ip, h) in &l.hosts {
                add(&mut m, *ip, "наблюдение", h.mac.as_deref(), h.name.as_deref());
            }
        }
        for (ip, (first, last)) in &w.seen {
            let k = m.entry(*ip).or_default();
            if !k.sources.iter().any(|s| s == "наблюдение") {
                k.sources.push("наблюдение".into());
            }
            k.first_seen = Some(*first);
            k.last_seen = Some(*last);
        }
    }
    if let Some(h) = &t.host {
        for n in &h.neighbors {
            if let Ok(ip) = n.ip.parse::<Ipv4Addr>()
                && !n.state.to_ascii_lowercase().contains("fail")
                && !n.state.to_ascii_lowercase().contains("incomplete")
            {
                add(&mut m, ip, "ARP", Some(&n.mac), None);
            }
        }
    }
    for r in &s.rows {
        add(&mut m, r.ip, "прокси", None, None);
    }
    for list in [t.services.as_ref().map(|x| &x.services), t.audit.as_ref().map(|x| &x.services)].into_iter().flatten() {
        for sv in list {
            add(&mut m, sv.ip, "сервисы", None, None);
        }
    }
    if let Some(c) = &t.capture {
        for (ip, macs) in &c.arp {
            if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                for mac in macs {
                    add(&mut m, ip, "трафик", Some(mac), None);
                }
            }
        }
    }
    m
}

/// Подсети учёта: из настройки или /24 найденных узлов.
pub fn subnets(cfg: &Config, known: &BTreeMap<Ipv4Addr, Known>) -> Result<Vec<(Ipv4Addr, u8)>, String> {
    let mut out = Vec::new();
    if cfg.subnets.trim().is_empty() {
        for ip in known.keys() {
            if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                continue;
            }
            let o = ip.octets();
            let net = Ipv4Addr::new(o[0], o[1], o[2], 0);
            if !out.contains(&(net, 24)) {
                out.push((net, 24));
            }
        }
    } else {
        for part in super::split_list(&cfg.subnets) {
            let (a, p) = part.split_once('/').ok_or_else(|| format!("«{part}»: укажите сеть с префиксом, например 10.0.0.0/24"))?;
            let a: Ipv4Addr = a.trim().parse().map_err(|_| format!("«{part}»: некорректный адрес"))?;
            let p: u8 = p.trim().parse().map_err(|_| format!("«{part}»: некорректный префикс"))?;
            if !(16..=30).contains(&p) {
                return Err(format!("«{part}»: префикс от /16 до /30"));
            }
            let mask = u32::MAX << (32 - p as u32);
            out.push((Ipv4Addr::from(u32::from(a) & mask), p));
        }
    }
    out.sort();
    Ok(out)
}

/// Адреса узлов подсети (без адреса сети и широковещательного).
pub fn hosts_of(net: Ipv4Addr, prefix: u8) -> std::ops::RangeInclusive<u32> {
    let n = u32::from(net);
    let size = 1u32 << (32 - prefix as u32);
    if prefix >= 31 { n..=n + size - 1 } else { n + 1..=n + size - 2 }
}

/// Свободные диапазоны подсети: «10.0.0.20 – 10.0.0.39 (20)».
pub fn free_ranges(net: Ipv4Addr, prefix: u8, known: &BTreeMap<Ipv4Addr, Known>) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let mut out = Vec::new();
    let mut start: Option<u32> = None;
    let r = hosts_of(net, prefix);
    let end = *r.end();
    for a in r {
        let used = known.contains_key(&Ipv4Addr::from(a));
        match (used, start) {
            (false, None) => start = Some(a),
            (true, Some(s)) => {
                out.push((Ipv4Addr::from(s), Ipv4Addr::from(a - 1)));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((Ipv4Addr::from(s), Ipv4Addr::from(end)));
    }
    out
}

/// Проверка DNS для занятого адреса.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsCheck {
    pub ptr: Option<String>,
    /// Прямая запись имени из PTR указывает на этот адрес.
    pub forward_ok: Option<bool>,
    pub forward: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Total(usize),
    Dns(Ipv4Addr, DnsCheck),
}

/// Обратные и прямые записи для адресов.
pub async fn check_dns(ips: Vec<Ipv4Addr>, sink: Sink<Event>, cancel: CancellationToken) {
    sink.send(Event::Total(ips.len()));
    let timeout = Duration::from_millis(1500);
    super::for_each_limited(ips, 32, &cancel, |ip| {
        let sink = sink.clone();
        async move {
            let mut c = DnsCheck::default();
            if let Some(name) = super::dns::reverse_lookup(std::net::IpAddr::V4(ip), timeout).await {
                let name = name.trim_end_matches('.').to_string();
                let fwd: Vec<String> = tokio::time::timeout(timeout, tokio::net::lookup_host((name.as_str(), 0)))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .map(|it| it.filter(|a| a.is_ipv4()).map(|a| a.ip().to_string()).collect())
                    .unwrap_or_default();
                c.forward_ok = Some(fwd.contains(&ip.to_string()));
                c.forward = fwd;
                c.ptr = Some(name);
            }
            sink.send(Event::Dns(ip, c));
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_and_subnets() {
        let mut k = BTreeMap::new();
        for a in ["10.0.0.1", "10.0.0.2", "10.0.0.10", "10.0.1.5"] {
            k.insert(a.parse().unwrap(), Known::default());
        }
        let nets = subnets(&Config::default(), &k).unwrap();
        assert_eq!(nets, vec![("10.0.0.0".parse().unwrap(), 24), ("10.0.1.0".parse().unwrap(), 24)]);
        let f = free_ranges("10.0.0.0".parse().unwrap(), 24, &k);
        assert_eq!(f[0], ("10.0.0.3".parse().unwrap(), "10.0.0.9".parse().unwrap()));
        assert_eq!(f[1], ("10.0.0.11".parse().unwrap(), "10.0.0.254".parse().unwrap()));
        let cfg = Config { subnets: "10.0.0.77/29".into(), ..Default::default() };
        assert_eq!(subnets(&cfg, &k).unwrap(), vec![("10.0.0.72".parse().unwrap(), 29)]);
        assert!(subnets(&Config { subnets: "10.0.0.0/8".into(), ..Default::default() }, &k).is_err());
    }
}
