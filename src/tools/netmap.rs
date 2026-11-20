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
}

impl Default for Options {
    fn default() -> Self {
        Self {
            hosts: true,
            trace: true,
            services: true,
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
