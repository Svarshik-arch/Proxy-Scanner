//! Калькулятор подсетей. Понимает:
//! * `10.0.1.5/22`, `10.0.1.5 255.255.252.0` — сеть, маска, обратная маска, адреса;
//! * `10.0.0.0/22 /24` (или `на /24`) — разбиение на подсети;
//! * `10.0.1.5 в 10.0.0.0/22` (или `in`) — входит ли адрес в сеть;
//! * `10.0.0.0/24 10.0.1.0/24 …` — суммаризация (общая сеть и минимальный набор);
//! * `10.0.0.5-10.0.0.70` — диапазон как набор сетей (для ACL).

use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Calc {
    pub title: String,
    pub rows: Vec<(String, String)>,
    pub list: Vec<String>,
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) }
}

fn ip(v: u32) -> Ipv4Addr {
    Ipv4Addr::from(v)
}

/// `a.b.c.d/n` или `a.b.c.d маска`.
fn parse_net(s: &str) -> Option<(u32, u8)> {
    let s = s.trim();
    if let Some((a, p)) = s.split_once('/') {
        let a: Ipv4Addr = a.trim().parse().ok()?;
        let p: u8 = p.trim().parse().ok()?;
        return (p <= 32).then_some((u32::from(a), p));
    }
    let mut it = s.split_whitespace();
    let a: Ipv4Addr = it.next()?.parse().ok()?;
    let m: Ipv4Addr = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    let m = u32::from(m);
    let p = m.leading_ones() as u8;
    (mask(p) == m).then_some((u32::from(a), p))
}

fn count(p: u8) -> u64 {
    1u64 << (32 - p as u32)
}

fn usable(p: u8) -> u64 {
    match p {
        32 => 1,
        31 => 2,
        _ => count(p) - 2,
    }
}

fn info(a: u32, p: u8) -> Calc {
    let net = a & mask(p);
    let bc = net | !mask(p);
    let (first, last) = if p >= 31 { (net, bc) } else { (net + 1, bc - 1) };
    let class = match ip(net).octets()[0] {
        10 => "частная (RFC 1918)",
        172 if (16..32).contains(&ip(net).octets()[1]) => "частная (RFC 1918)",
        192 if ip(net).octets()[1] == 168 => "частная (RFC 1918)",
        100 if (64..128).contains(&ip(net).octets()[1]) => "CGNAT (RFC 6598)",
        169 if ip(net).octets()[1] == 254 => "link-local (APIPA)",
        127 => "loopback",
        224..=239 => "групповая (multicast)",
        _ => "публичная",
    };
    let mut rows = vec![
        ("Сеть".into(), format!("{}/{p}", ip(net))),
        ("Маска".into(), ip(mask(p)).to_string()),
        ("Обратная маска".into(), ip(!mask(p)).to_string()),
        ("Широковещательный".into(), ip(bc).to_string()),
        ("Узлы".into(), format!("{} – {}", ip(first), ip(last))),
        ("Адресов для узлов".into(), usable(p).to_string()),
        ("Тип".into(), class.into()),
    ];
    if net != a {
        rows.insert(0, ("Адрес".into(), format!("{} — {}-й в сети", ip(a), a - net)));
    }
    Calc {
        title: format!("{}/{p}", ip(net)),
        rows,
        list: Vec::new(),
    }
}

/// Минимальный набор сетей, покрывающий диапазон [lo, hi].
pub fn range_to_cidrs(mut lo: u32, hi: u32) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    while lo <= hi {
        let mut p = if lo == 0 { 0 } else { 32 - lo.trailing_zeros().min(32) as u8 };
        while (lo as u64 + count(p) - 1) > hi as u64 {
            p += 1;
        }
        out.push((lo, p));
        let next = lo as u64 + count(p);
        if next > u32::MAX as u64 {
            break;
        }
        lo = next as u32;
    }
    out
}

/// Минимальный набор сетей для списка сетей (слияние соседних и вложенных).
pub fn aggregate(nets: &[(u32, u8)]) -> Vec<(u32, u8)> {
    let mut ranges: Vec<(u64, u64)> = nets.iter().map(|(a, p)| {
        let n = (a & mask(*p)) as u64;
        (n, n + count(*p) - 1)
    }).collect();
    ranges.sort();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (lo, hi) in ranges {
        match merged.last_mut() {
            Some(m) if lo <= m.1 + 1 => m.1 = m.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    merged.into_iter().flat_map(|(lo, hi)| range_to_cidrs(lo as u32, hi as u32)).collect()
}

pub fn calc(input: &str) -> Option<Calc> {
    let s = input.trim();
    if s.is_empty() || !s.chars().next()?.is_ascii_digit() {
        return None;
    }
    // Входит ли адрес в сеть.
    for sep in [" в ", " in ", " IN "] {
        if let Some((a, n)) = s.split_once(sep) {
            let a: Ipv4Addr = a.trim().parse().ok()?;
            let (na, p) = parse_net(n)?;
            let inside = u32::from(a) & mask(p) == na & mask(p);
            return Some(Calc {
                title: format!("{a} {} {}/{p}", if inside { "входит в" } else { "не входит в" }, ip(na & mask(p))),
                rows: vec![("Итог".into(), if inside { "да".into() } else { "нет".into() })],
                list: Vec::new(),
            });
        }
    }
    // Разбиение: «сеть /новый_префикс».
    let norm = s.replace(" на ", " ").replace(" > ", " ");
    if let Some((n, sub)) = norm.rsplit_once(' ')
        && let Some(sub) = sub.strip_prefix('/')
        && let Ok(sub) = sub.parse::<u8>()
        && let Some((a, p)) = parse_net(n)
        && sub >= p
        && sub <= 32
    {
        let net = a & mask(p);
        let parts = 1u64 << (sub - p);
        let list = (0..parts.min(512))
            .map(|i| format!("{}/{sub}", ip(net + (i * count(sub)) as u32)))
            .collect::<Vec<_>>();
        let mut rows = vec![
            ("Подсетей".into(), parts.to_string()),
            ("Адресов для узлов в каждой".into(), usable(sub).to_string()),
        ];
        if parts > 512 {
            rows.push(("Показаны".into(), "первые 512".into()));
        }
        return Some(Calc {
            title: format!("{}/{p} на /{sub}", ip(net)),
            rows,
            list,
        });
    }
    // Диапазон.
    if let Some((a, b)) = s.split_once('-')
        && let (Ok(a), Ok(b)) = (a.trim().parse::<Ipv4Addr>(), b.trim().parse::<Ipv4Addr>())
    {
        let (lo, hi) = (u32::from(a).min(u32::from(b)), u32::from(a).max(u32::from(b)));
        let list: Vec<String> = range_to_cidrs(lo, hi).into_iter().map(|(n, p)| format!("{}/{p}", ip(n))).collect();
        return Some(Calc {
            title: format!("{} – {} как сети", ip(lo), ip(hi)),
            rows: vec![("Адресов".into(), (hi as u64 - lo as u64 + 1).to_string()), ("Сетей".into(), list.len().to_string())],
            list,
        });
    }
    // Несколько сетей — суммаризация.
    let parts: Vec<&str> = s.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).filter(|x| !x.is_empty()).collect();
    if parts.len() > 1 && parts.iter().all(|p| p.contains('/')) {
        let nets: Vec<(u32, u8)> = parts.iter().map(|p| parse_net(p)).collect::<Option<_>>()?;
        let lo = nets.iter().map(|(a, p)| a & mask(*p)).min()?;
        let hi = nets.iter().map(|(a, p)| (a & mask(*p)) | !mask(*p)).max()?;
        let common = (lo ^ hi).leading_zeros() as u8;
        let agg = aggregate(&nets);
        return Some(Calc {
            title: format!("Общая сеть {}/{common}", ip(lo & mask(common))),
            rows: vec![
                ("Общая сеть".into(), format!("{}/{common}", ip(lo & mask(common)))),
                ("Без лишних адресов".into(), format!("{} сетей", agg.len())),
            ],
            list: agg.into_iter().map(|(n, p)| format!("{}/{p}", ip(n))).collect(),
        });
    }
    let (a, p) = parse_net(s)?;
    Some(info(a, p))
}

/// Короткая подсказка для поля адресов: «/22 · 1022 узла · 10.0.0.1 – 10.0.3.254».
pub fn hint(s: &str) -> Option<String> {
    let (a, p) = parse_net(s)?;
    let c = info(a, p);
    let get = |k: &str| c.rows.iter().find(|r| r.0 == k).map(|r| r.1.clone()).unwrap_or_default();
    Some(format!("{} · маска {} · узлов {} · {}", get("Сеть"), get("Маска"), get("Адресов для узлов"), get("Узлы")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let c = calc("10.0.1.5/22").unwrap();
        assert_eq!(c.title, "10.0.0.0/22");
        assert!(c.rows.iter().any(|r| r.0 == "Адресов для узлов" && r.1 == "1022"));
        assert!(c.rows.iter().any(|r| r.1.contains("10.0.0.1 – 10.0.3.254")));
        assert_eq!(calc("192.168.5.7 255.255.255.0").unwrap().title, "192.168.5.0/24");
        assert!(calc("10.0.0.0 255.0.255.0").is_none());
        assert!(calc("example.com").is_none());
    }

    #[test]
    fn split_contains_range_aggregate() {
        let c = calc("10.0.0.0/22 /24").unwrap();
        assert_eq!(c.list, vec!["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]);
        assert_eq!(calc("10.0.1.5 в 10.0.0.0/22").unwrap().rows[0].1, "да");
        assert_eq!(calc("10.0.4.5 in 10.0.0.0/22").unwrap().rows[0].1, "нет");
        assert_eq!(calc("10.0.0.0-10.0.0.255").unwrap().list, vec!["10.0.0.0/24"]);
        assert_eq!(calc("10.0.0.5-10.0.0.8").unwrap().list, vec!["10.0.0.5/32", "10.0.0.6/31", "10.0.0.8/32"]);
        let a = calc("10.0.0.0/24, 10.0.1.0/24 10.0.3.0/24").unwrap();
        assert_eq!(a.title, "Общая сеть 10.0.0.0/22");
        assert_eq!(a.list, vec!["10.0.0.0/23", "10.0.3.0/24"]);
        assert!(hint("10.0.0.0/30").unwrap().contains("узлов 2"));
    }
}
