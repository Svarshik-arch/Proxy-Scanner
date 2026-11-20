//! Карта сети из собранных данных: эта машина и шлюзы (Хост), путь трассировки (MTR),
//! подсети и узлы (Узлы), серверы (Сервисы, аудит), контроллеры домена (AD), прокси.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::graph::{MapKind, MapNode};
use crate::session::Session;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub hosts: bool,
    pub trace: bool,
    pub services: bool,
    /// Связи по захваченному трафику.
    pub traffic: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            hosts: true,
            trace: true,
            services: true,
            traffic: true,
        }
    }
}

fn rank(k: MapKind) -> u8 {
    match k {
        MapKind::Me => 9,
        MapKind::Dc => 8,
        MapKind::Router => 7,
        MapKind::Proxy => 6,
        MapKind::Server => 5,
        MapKind::Hop => 4,
        MapKind::Host => 3,
        MapKind::Subnet => 2,
    }
}

struct Builder {
    nodes: BTreeMap<String, MapNode>,
    order: Vec<String>,
}

impl Builder {
    fn add(&mut self, key: &str, kind: MapKind, label: &str, detail: Vec<String>, parent: Option<String>) {
        match self.nodes.get_mut(key) {
            Some(n) => {
                if rank(kind) > rank(n.kind) {
                    n.kind = kind;
                }
                for d in detail {
                    if !n.detail.contains(&d) {
                        n.detail.push(d);
                    }
                }
                if n.parent.is_none() {
                    n.parent = parent;
                } else if let Some(p) = parent
                    && n.parent.as_ref() != Some(&p)
                    && !n.links.contains(&p)
                {
                    n.links.push(p);
                }
                if label.len() > n.label.len() && !label.is_empty() && n.label.parse::<Ipv4Addr>().is_ok() && label.parse::<Ipv4Addr>().is_err() {
                    n.label = label.to_string();
                }
            }
            None => {
                self.order.push(key.to_string());
                self.nodes.insert(
                    key.to_string(),
                    MapNode {
                        key: key.to_string(),
                        kind,
                        label: label.to_string(),
                        detail,
                        parent,
                        links: Vec::new(),
                        problem: false,
                        warning: false,
                    },
                );
            }
        }
    }

    fn mark(&mut self, key: &str, problem: bool, warning: bool) {
        if let Some(n) = self.nodes.get_mut(key) {
            n.problem |= problem;
            n.warning |= warning;
        }
    }
}

fn my_nets_contain(nets: &[String], ip: Ipv4Addr) -> bool {
    nets.iter().any(|n| crate::targets::parse_targets(n).map(|t| t.contains(ip)).unwrap_or(false))
}

/// Узел из строки мониторинга (`tcp 10.0.0.5:3389`, `http https://10.0.0.7/`, `ping 10.0.0.1`).
fn monitor_host(line: &str) -> Option<Ipv4Addr> {
    let target = line.split_whitespace().nth(1)?;
    let t = target.split("://").last()?;
    let host = t.split(['/', ':']).next()?;
    host.parse().ok()
}

/// Самые нагруженные пары адресов из захвата: (a, b, байт).
pub fn flows(s: &Session, limit: usize) -> Vec<(Ipv4Addr, Ipv4Addr, u64)> {
    let Some(c) = &s.tools.capture else { return Vec::new() };
    let mut v: Vec<(Ipv4Addr, Ipv4Addr, u64)> = c
        .talk
        .iter()
        .filter_map(|(k, n)| {
            let (a, z) = k.split_once(" ↔ ")?;
            Some((a.parse().ok()?, z.parse().ok()?, *n))
        })
        .collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.2));
    v.truncate(limit);
    v
}

/// Нагрузка на связях для живой карты: (ключ a, ключ b, доля 0..1, тревога).
pub fn heat(s: &Session) -> Vec<(String, String, f32, bool)> {
    let f = flows(s, 60);
    let max = f.first().map(|x| x.2).unwrap_or(1).max(1) as f32;
    let failing: std::collections::BTreeSet<Ipv4Addr> = s
        .tools
        .monitor
        .iter()
        .flat_map(|m| m.states.iter())
        .filter(|st| st.status == crate::tools::monitor::Status::Fail)
        .filter_map(|st| monitor_host(&st.line))
        .collect();
    f.into_iter()
        .map(|(a, z, n)| {
            let share = ((n as f32).ln_1p() / max.ln_1p()).clamp(0.05, 1.0);
            (ip_key(&a.to_string()), ip_key(&z.to_string()), share, failing.contains(&a) || failing.contains(&z))
        })
        .collect()
}

fn ip_key(ip: &str) -> String {
    format!("ip:{ip}")
}

fn subnet_of(ip: Ipv4Addr) -> String {
    crate::targets::network_cidr(ip, 24)
}

pub fn build(s: &Session, o: Options) -> Vec<MapNode> {
    let mut b = Builder {
        nodes: BTreeMap::new(),
        order: Vec::new(),
    };
    let t = &s.tools;
    let me = "me".to_string();
    let host_name = t.host.as_ref().map(|h| h.hostname.clone()).filter(|h| !h.is_empty()).unwrap_or(s.computer.clone());
    let mut my_addrs = Vec::new();
    let mut gateways: Vec<String> = Vec::new();
    if let Some(h) = &t.host {
        for i in h.interfaces.iter().filter(|i| i.up && !i.addrs.is_empty() && i.name != "lo") {
            for a in &i.addrs {
                if !a.contains(':') {
                    my_addrs.push(a.clone());
                }
            }
            gateways.extend(i.gateways.iter().filter(|g| g.parse::<Ipv4Addr>().is_ok()).cloned());
        }
    }
    b.add(&me, MapKind::Me, &host_name, my_addrs.iter().map(|a| format!("адрес {a}")).collect(), None);
    for g in &gateways {
        b.add(&ip_key(g), MapKind::Router, g, vec!["шлюз по умолчанию".into()], Some(me.clone()));
    }
    let first_router = gateways.first().map(|g| ip_key(g));

    // Подсеть узла: к шлюзу, если подсеть — своя; иначе к шлюзу/машине.
    let my_nets: Vec<String> = my_addrs
        .iter()
        .filter_map(|a| {
            let (ip, p) = a.split_once('/')?;
            Some(crate::targets::network_cidr(ip.parse().ok()?, p.parse::<u8>().ok()?.clamp(8, 32)))
        })
        .collect();
    let subnet = |b: &mut Builder, ip: Ipv4Addr| -> String {
        let net = subnet_of(ip);
        let key = format!("net:{net}");
        let local = my_nets.iter().any(|n| {
            crate::targets::parse_targets(n).map(|t| t.contains(ip)).unwrap_or(false)
        });
        let parent = if local { Some(me.clone()) } else { first_router.clone().or(Some(me.clone())) };
        b.add(&key, MapKind::Subnet, &net, vec![if local { "своя подсеть".into() } else { "подсеть /24".into() }], parent);
        key
    };

    if o.trace
        && let Some(m) = &t.mtr
    {
        let mut prev = me.clone();
        for h in &m.hops {
            let Some(a) = h.addrs.first() else {
                continue;
            };
            let key = ip_key(&a.to_string());
            let label = h.names.first().cloned().flatten().unwrap_or_else(|| a.to_string());
            let detail = vec![
                format!("хоп {}", h.ttl),
                format!("потери {:.0}%, среднее {:.1} мс", h.loss_pct(), h.avg_ms),
            ];
            b.add(&key, MapKind::Hop, &label, detail, Some(prev.clone()));
            b.mark(&key, h.loss_pct() >= 50.0, h.loss_pct() > 0.0);
            prev = key;
        }
        if let Some(addr) = m.address {
            let key = ip_key(&addr.to_string());
            if b.nodes.contains_key(&key) {
                b.add(&key, MapKind::Host, &m.target, vec![format!("цель трассировки {}", m.target)], None);
            }
        }
    }

    if o.hosts
        && let Some(d) = &t.discovery
    {
        for h in d.hosts.iter().filter(|h| h.alive) {
            let net = subnet(&mut b, h.ip);
            let mut detail = Vec::new();
            if let Some(v) = &h.vendor {
                detail.push(v.clone());
            }
            if let Some(os) = &h.os_guess {
                detail.push(os.clone());
            }
            if !h.open_ports.is_empty() {
                detail.push(format!("порты {}", h.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")));
            }
            let name = h.best_name();
            let label = if name.is_empty() { h.ip.to_string() } else { name };
            b.add(&ip_key(&h.ip.to_string()), MapKind::Host, &label, detail, Some(net));
        }
    }

    if o.services {
        let lists = [t.services.as_ref().map(|x| &x.services), t.audit.as_ref().map(|x| &x.services)];
        let mut per_host: BTreeMap<Ipv4Addr, Vec<String>> = BTreeMap::new();
        for l in lists.into_iter().flatten() {
            for sv in l {
                per_host.entry(sv.ip).or_default().push(format!("{}/{} {}", sv.port, sv.proto, sv.service));
            }
        }
        for (ip, svcs) in per_host {
            let net = subnet(&mut b, ip);
            b.add(&ip_key(&ip.to_string()), MapKind::Server, &ip.to_string(), svcs, Some(net));
        }
        if let Some(a) = &t.audit {
            for i in &a.issues {
                b.mark(&ip_key(&i.ip.to_string()), i.severity == crate::tools::tlsaudit::Severity::High, true);
            }
        }
    }

    if let Some(ad) = &t.ad {
        for dc in &ad.dcs {
            let Some(std::net::IpAddr::V4(ip)) = dc.ip else { continue };
            let net = subnet(&mut b, ip);
            let name = dc.attr("dnsHostName").unwrap_or(&dc.host).to_string();
            b.add(&ip_key(&ip.to_string()), MapKind::Dc, &name, vec![format!("контроллер домена {}", ad.domain)], Some(net));
            let bad_ports = dc.ports.iter().any(|p| p.required && !p.open);
            let skew = dc.skew().is_some_and(|(v, _)| v.abs() > 300.0);
            b.mark(&ip_key(&ip.to_string()), bad_ports || skew, dc.smb_signing_required == Some(false));
        }
    }

    for r in s.rows.iter().filter(|r| r.kind == crate::model::ProxyKind::HttpProxy || matches!(r.kind, crate::model::ProxyKind::Socks4 | crate::model::ProxyKind::Socks5)) {
        let net = subnet(&mut b, r.ip);
        b.add(&ip_key(&r.ip.to_string()), MapKind::Proxy, &r.ip.to_string(), vec![format!("{}:{} {}", r.ip, r.port, r.kind.label())], Some(net));
        b.mark(&ip_key(&r.ip.to_string()), !r.probe.auth_required, false);
    }

    // Коммутаторы (SNMP): узел привязывается к порту коммутатора.
    if let Some(sn) = &t.snmp {
        let mac_ip: BTreeMap<String, Ipv4Addr> = t
            .discovery
            .iter()
            .flat_map(|d| d.hosts.iter())
            .filter_map(|h| Some((crate::tools::snmp::norm_mac(h.mac.as_deref()?), h.ip)))
            .chain(t.watch.iter().filter_map(|w| w.last.as_ref()).flat_map(|l| l.hosts.iter()).filter_map(|(ip, h)| Some((crate::tools::snmp::norm_mac(h.mac.as_deref()?), *ip))))
            .collect();
        for sw in sn.switches.iter().filter(|s| s.error.is_none()) {
            let key = sw.address.parse::<Ipv4Addr>().map(|a| ip_key(&a.to_string())).unwrap_or_else(|_| format!("sw:{}", sw.address));
            let label = if sw.name.is_empty() { sw.address.clone() } else { sw.name.clone() };
            let parent = first_router.clone().filter(|r| *r != key).or(Some(me.clone()));
            b.add(&key, MapKind::Router, &label, vec![format!("коммутатор, {} MAC", sw.entries.len())], parent);
            for e in sw.entries.iter().filter(|e| !e.uplink) {
                if let Some(ip) = mac_ip.get(&e.mac) {
                    let hk = ip_key(&ip.to_string());
                    if !b.nodes.contains_key(&hk) {
                        let net = subnet(&mut b, *ip);
                        b.add(&hk, MapKind::Host, &ip.to_string(), vec![], Some(net));
                    }
                    let where_ = format!("{label} порт {}{}", e.port, e.vlan.map(|v| format!(", VLAN {v}")).unwrap_or_default());
                    b.add(&hk, MapKind::Host, "", vec![format!("воткнут: {where_}")], Some(key.clone()));
                }
            }
        }
    }

    // Живые данные: сбои мониторинга, тревоги наблюдения, трафик.
    if let Some(m) = &t.monitor {
        for st in &m.states {
            if let Some(ip) = monitor_host(&st.line) {
                let key = ip_key(&ip.to_string());
                let fail = st.status == crate::tools::monitor::Status::Fail;
                let warn = st.status == crate::tools::monitor::Status::Warn;
                if !b.nodes.contains_key(&key) && (fail || warn) {
                    let net = subnet(&mut b, ip);
                    b.add(&key, MapKind::Server, &ip.to_string(), vec![], Some(net));
                }
                b.add(&key, MapKind::Host, "", vec![format!("мониторинг: {} — {}", st.line, st.status.label())], None);
                b.mark(&key, fail, warn);
            }
        }
    }
    if let Some(w) = &t.watch {
        for c in w.changes.iter().rev().take(200) {
            let key = ip_key(&c.host.to_string());
            if b.nodes.contains_key(&key) {
                b.add(&key, MapKind::Host, "", vec![format!("изменение: {} {}", c.kind.label(), c.detail)], None);
                b.mark(&key, false, c.alarm);
            }
        }
    }
    if o.traffic {
        for (a, z, _) in flows(s, 60) {
            let (ka, kz) = (ip_key(&a.to_string()), ip_key(&z.to_string()));
            for (k, ip) in [(&ka, a), (&kz, z)] {
                if !b.nodes.contains_key(k) && (ip.is_private() || my_nets_contain(&my_nets, ip)) {
                    let net = subnet(&mut b, ip);
                    b.add(k, MapKind::Host, &ip.to_string(), vec!["виден в трафике".into()], Some(net));
                }
            }
            if b.nodes.contains_key(&kz)
                && let Some(n) = b.nodes.get_mut(&ka)
                && n.parent.as_ref() != Some(&kz)
                && !n.links.contains(&kz)
            {
                n.links.push(kz.clone());
            }
        }
    }

    let mut out = Vec::new();
    for k in b.order {
        if let Some(n) = b.nodes.remove(&k) {
            out.push(n);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_topology() {
        let mut s = Session::new(&crate::model::Settings::default(), None, Vec::new());
        s.tools.host = Some(crate::tools::hostinfo::Report {
            hostname: "ws01".into(),
            interfaces: vec![crate::tools::hostinfo::Interface {
                name: "eth0".into(),
                up: true,
                addrs: vec!["10.0.0.5/24".into()],
                gateways: vec!["10.0.0.1".into()],
                ..Default::default()
            }],
            ..Default::default()
        });
        s.tools.discovery = Some(crate::tools::discovery::Report {
            hosts: vec![
                crate::tools::discovery::Host { ip: "10.0.0.20".parse().unwrap(), alive: true, ..Default::default() },
                crate::tools::discovery::Host { ip: "10.1.0.7".parse().unwrap(), alive: true, ..Default::default() },
            ],
        });
        let nodes = build(&s, Options::default());
        let get = |k: &str| nodes.iter().find(|n| n.key == k).unwrap();
        assert_eq!(get("me").label, "ws01");
        assert_eq!(get("ip:10.0.0.1").kind, MapKind::Router);
        // Своя подсеть висит на машине, чужая — на шлюзе.
        assert_eq!(get("net:10.0.0.0/24").parent.as_deref(), Some("me"));
        assert_eq!(get("net:10.1.0.0/24").parent.as_deref(), Some("ip:10.0.0.1"));
        assert_eq!(get("ip:10.1.0.7").parent.as_deref(), Some("net:10.1.0.0/24"));
    }
}
