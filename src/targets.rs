//! Разбор списка целей (IP, CIDR, диапазоны) и списка портов.

use std::net::Ipv4Addr;

/// Максимальное число адресов для встроенного TCP-connect сканера (/16).
pub const TCP_SCAN_MAX_HOSTS: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Range {
    pub start: u32,
    pub end: u32, // включительно
}

impl Ipv4Range {
    pub fn len(self) -> u64 {
        (self.end as u64) - (self.start as u64) + 1
    }

    pub fn first(self) -> Ipv4Addr {
        Ipv4Addr::from(self.start)
    }

    /// Строковое представление, понятное masscan.
    pub fn to_masscan(self) -> String {
        if self.start == self.end {
            Ipv4Addr::from(self.start).to_string()
        } else {
            format!("{}-{}", Ipv4Addr::from(self.start), Ipv4Addr::from(self.end))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TargetSet {
    pub ranges: Vec<Ipv4Range>,
}

impl TargetSet {
    pub fn total_hosts(&self) -> u64 {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    /// Первый адрес целевой сети (для определения source-ip через таблицу маршрутов).
    pub fn first_addr(&self) -> Option<Ipv4Addr> {
        self.ranges.first().map(|r| r.first())
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Отсортированные непересекающиеся диапазоны (соседние склеены).
    pub fn normalized(&self) -> TargetSet {
        let mut r = self.ranges.clone();
        r.sort_by_key(|x| x.start);
        let mut out: Vec<Ipv4Range> = Vec::with_capacity(r.len());
        for x in r {
            match out.last_mut() {
                Some(last) if (x.start as u64) <= last.end as u64 + 1 => {
                    last.end = last.end.max(x.end);
                }
                _ => out.push(x),
            }
        }
        TargetSet { ranges: out }
    }

    /// Адреса из `self`, которых нет в `other`.
    pub fn subtract(&self, other: &TargetSet) -> TargetSet {
        let other = other.normalized();
        let mut out = Vec::new();
        for r in self.normalized().ranges {
            let mut start = r.start as u64;
            let end = r.end as u64;
            for o in &other.ranges {
                let (os, oe) = (o.start as u64, o.end as u64);
                if oe < start || os > end {
                    continue;
                }
                if os > start {
                    out.push(Ipv4Range { start: start as u32, end: (os - 1) as u32 });
                }
                start = oe + 1;
                if start > end {
                    break;
                }
            }
            if start <= end {
                out.push(Ipv4Range { start: start as u32, end: end as u32 });
            }
        }
        TargetSet { ranges: out }
    }

    /// Первые `n` адресов в порядке обхода.
    pub fn take_first(&self, mut n: u64) -> TargetSet {
        let mut out = Vec::new();
        for r in &self.ranges {
            if n == 0 {
                break;
            }
            let take = r.len().min(n);
            out.push(Ipv4Range { start: r.start, end: (r.start as u64 + take - 1) as u32 });
            n -= take;
        }
        TargetSet { ranges: out }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        self.ranges.iter().any(|r| (r.start..=r.end).contains(&v))
    }

    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.ranges
            .iter()
            .flat_map(|r| (r.start..=r.end).map(Ipv4Addr::from))
    }

    pub fn to_masscan_arg(&self) -> String {
        self.ranges
            .iter()
            .map(|r| r.to_masscan())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn split_items(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|x| !x.is_empty() && !x.starts_with('#'))
}

pub fn parse_ipv4(s: &str) -> Result<Ipv4Addr, String> {
    s.trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("некорректный IPv4-адрес: «{s}»"))
}

pub fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// CIDR сети, к которой относится адрес с указанной длиной префикса.
pub fn network_cidr(addr: Ipv4Addr, prefix: u8) -> String {
    let mask = prefix_to_mask(prefix);
    format!("{}/{}", Ipv4Addr::from(u32::from(addr) & mask), prefix)
}

/// Разбор строки целей: `10.0.0.0/24, 10.0.1.5, 10.0.2.1-10.0.2.50, 10.0.3.1-20`.
pub fn parse_targets(s: &str) -> Result<TargetSet, String> {
    let mut ranges = Vec::new();
    for item in split_items(s) {
        let range = if let Some((addr, prefix)) = item.split_once('/') {
            let addr = parse_ipv4(addr)?;
            let prefix: u8 = prefix
                .trim()
                .parse()
                .ok()
                .filter(|p| *p <= 32)
                .ok_or_else(|| format!("некорректная длина префикса в «{item}»"))?;
            let mask = prefix_to_mask(prefix);
            let start = u32::from(addr) & mask;
            Ipv4Range {
                start,
                end: start | !mask,
            }
        } else if let Some((a, b)) = item.split_once('-') {
            let start = parse_ipv4(a)?;
            let b = b.trim();
            let end = if b.contains('.') {
                parse_ipv4(b)?
            } else {
                // Сокращённая форма: 10.0.0.1-50
                let last: u8 = b
                    .parse()
                    .map_err(|_| format!("некорректный диапазон «{item}»"))?;
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            };
            let (s, e) = (u32::from(start), u32::from(end));
            if e < s {
                return Err(format!("конец диапазона меньше начала: «{item}»"));
            }
            Ipv4Range { start: s, end: e }
        } else {
            let a = u32::from(parse_ipv4(item)?);
            Ipv4Range { start: a, end: a }
        };
        ranges.push(range);
    }
    if ranges.is_empty() {
        return Err("не задано ни одной цели".into());
    }
    Ok(TargetSet { ranges })
}

/// Разбор портов: `80,443,3128,8000-8100`.
pub fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for item in split_items(s) {
        if let Some((a, b)) = item.split_once('-') {
            let a: u16 = a
                .trim()
                .parse()
                .map_err(|_| format!("некорректный порт «{item}»"))?;
            let b: u16 = b
                .trim()
                .parse()
                .map_err(|_| format!("некорректный порт «{item}»"))?;
            if a == 0 || b < a {
                return Err(format!("некорректный диапазон портов «{item}»"));
            }
            ports.extend(a..=b);
        } else {
            let p: u16 = item
                .parse()
                .map_err(|_| format!("некорректный порт «{item}»"))?;
            if p == 0 {
                return Err("порт 0 недопустим".into());
            }
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err("не задано ни одного порта".into());
    }
    Ok(ports)
}

/// Компактная запись списка портов для masscan (`-p80,443,8000-8100`).
pub fn ports_to_masscan(ports: &[u16]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < ports.len() {
        let start = ports[i];
        let mut end = start;
        while i + 1 < ports.len() && ports[i + 1] == end + 1 {
            i += 1;
            end = ports[i];
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    out.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_and_ranges() {
        let t = parse_targets("10.0.0.0/24, 10.0.1.5 10.0.2.1-10.0.2.10;10.0.3.1-5").unwrap();
        assert_eq!(t.total_hosts(), 256 + 1 + 10 + 5);
        assert_eq!(t.first_addr(), Some(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(
            t.to_masscan_arg(),
            "10.0.0.0-10.0.0.255,10.0.1.5,10.0.2.1-10.0.2.10,10.0.3.1-10.0.3.5"
        );
        assert!(parse_targets("10.0.0.300").is_err());
        assert!(parse_targets("10.0.0.5-10.0.0.1").is_err());
    }

    #[test]
    fn ports() {
        let p = parse_ports("8080, 80,3128 8000-8002,80").unwrap();
        assert_eq!(p, vec![80, 3128, 8000, 8001, 8002, 8080]);
        assert_eq!(ports_to_masscan(&p), "80,3128,8000-8002,8080");
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn set_operations() {
        let a = parse_targets("10.0.0.0/24, 10.0.0.10-10.0.1.5").unwrap().normalized();
        assert_eq!(a.to_masscan_arg(), "10.0.0.0-10.0.1.5");
        let b = parse_targets("10.0.0.0/24").unwrap();
        let rest = parse_targets("10.0.0.0-10.0.1.5").unwrap().subtract(&b);
        assert_eq!(rest.to_masscan_arg(), "10.0.1.0-10.0.1.5");
        let hole = parse_targets("10.0.0.0/24").unwrap().subtract(&parse_targets("10.0.0.10-20").unwrap());
        assert_eq!(hole.to_masscan_arg(), "10.0.0.0-10.0.0.9,10.0.0.21-10.0.0.255");
        assert!(b.subtract(&b).is_empty());
        let first = parse_targets("10.0.0.0/30, 10.0.1.0/30").unwrap().take_first(6);
        assert_eq!(first.to_masscan_arg(), "10.0.0.0-10.0.0.3,10.0.1.0-10.0.1.1");
        assert_eq!(b.take_first(0).total_hosts(), 0);
        let edge = parse_targets("255.255.255.0/24").unwrap().subtract(&parse_targets("255.255.255.255").unwrap());
        assert_eq!(edge.total_hosts(), 255);
    }

    #[test]
    fn contains() {
        let t = parse_targets("10.0.0.0/24, 192.168.1.5").unwrap();
        assert!(t.contains(Ipv4Addr::new(10, 0, 0, 200)));
        assert!(t.contains(Ipv4Addr::new(192, 168, 1, 5)));
        assert!(!t.contains(Ipv4Addr::new(10, 0, 1, 0)));
    }

    #[test]
    fn network() {
        assert_eq!(network_cidr(Ipv4Addr::new(192, 168, 7, 33), 24), "192.168.7.0/24");
        assert_eq!(network_cidr(Ipv4Addr::new(10, 20, 30, 40), 16), "10.20.0.0/16");
    }
}
