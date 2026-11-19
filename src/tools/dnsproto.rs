//! Формат сообщений DNS (RFC 1035, EDNS0 — RFC 6891): сборка запросов и разбор ответов.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// Типы записей, известные инструменту (остальные задаются числом: `TYPE65534`).
pub const TYPES: &[(&str, u16)] = &[
    ("A", 1),
    ("NS", 2),
    ("CNAME", 5),
    ("SOA", 6),
    ("PTR", 12),
    ("HINFO", 13),
    ("MX", 15),
    ("TXT", 16),
    ("AAAA", 28),
    ("SRV", 33),
    ("NAPTR", 35),
    ("OPT", 41),
    ("DS", 43),
    ("SSHFP", 44),
    ("RRSIG", 46),
    ("NSEC", 47),
    ("DNSKEY", 48),
    ("NSEC3", 50),
    ("NSEC3PARAM", 51),
    ("TLSA", 52),
    ("SVCB", 64),
    ("HTTPS", 65),
    ("AXFR", 252),
    ("ANY", 255),
    ("CAA", 257),
];

pub fn type_name(t: u16) -> String {
    TYPES
        .iter()
        .find(|(_, v)| *v == t)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("TYPE{t}"))
}

pub fn type_code(name: &str) -> Option<u16> {
    let up = name.trim().to_ascii_uppercase();
    if let Some((_, v)) = TYPES.iter().find(|(n, _)| *n == up) {
        return Some(*v);
    }
    up.strip_prefix("TYPE").unwrap_or(&up).parse().ok()
}

pub fn rcode_name(rc: u16) -> &'static str {
    match rc {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS",
        _ => "RCODE?",
    }
}

/// Параметры запроса.
#[derive(Debug, Clone)]
pub struct Query {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    /// Рекурсия (RD).
    pub recursion: bool,
    /// Добавлять EDNS0 (OPT) с размером буфера.
    pub edns: bool,
    /// Бит DO: запросить записи DNSSEC.
    pub dnssec_ok: bool,
    /// Бит CD: не проверять DNSSEC на резолвере.
    pub checking_disabled: bool,
    /// Запросить NSID (RFC 5001) — идентификатор сервера в anycast.
    pub nsid: bool,
}

impl Query {
    pub fn new(id: u16, name: &str, qtype: u16) -> Self {
        Self {
            id,
            name: name.to_string(),
            qtype,
            recursion: true,
            edns: true,
            dnssec_ok: false,
            checking_disabled: false,
            nsid: false,
        }
    }
}

pub fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), String> {
    let name = name.trim().trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(format!("некорректное имя «{name}»"));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() > 512 {
        return Err("слишком длинное имя".into());
    }
    Ok(())
}

pub fn build_query(q: &Query) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&q.id.to_be_bytes());
    let mut flags: u16 = 0;
    if q.recursion {
        flags |= 0x0100;
    }
    if q.checking_disabled {
        flags |= 0x0010;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0]); // AN, NS
    out.extend_from_slice(&(q.edns as u16).to_be_bytes()); // AR
    encode_name(&mut out, &q.name)?;
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    if q.edns {
        out.push(0); // корень
        out.extend_from_slice(&41u16.to_be_bytes());
        out.extend_from_slice(&1232u16.to_be_bytes()); // размер буфера UDP
        let ttl: u32 = if q.dnssec_ok { 0x8000 } else { 0 };
        out.extend_from_slice(&ttl.to_be_bytes());
        if q.nsid {
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&3u16.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
        } else {
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    Ok(out)
}

/// Имя для обратного запроса: `4.3.2.1.in-addr.arpa`, `….ip6.arpa`.
pub fn reverse_name(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(v6) => {
            let mut s = String::new();
            for b in v6.octets().iter().rev() {
                let _ = write!(s, "{:x}.{:x}.", b & 0xf, b >> 4);
            }
            s + "ip6.arpa"
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub name: String,
    pub rtype: String,
    pub class: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Flags {
    pub qr: bool,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
}

impl Flags {
    pub fn label(&self) -> String {
        let mut v = Vec::new();
        for (on, n) in [
            (self.qr, "qr"),
            (self.aa, "aa"),
            (self.tc, "tc"),
            (self.rd, "rd"),
            (self.ra, "ra"),
            (self.ad, "ad"),
            (self.cd, "cd"),
        ] {
            if on {
                v.push(n);
            }
        }
        v.join(" ")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Message {
    pub id: u16,
    pub opcode: u8,
    pub rcode: u16,
    pub flags: Flags,
    pub question: Vec<(String, String)>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    /// Параметры EDNS из записи OPT: (размер буфера, DO, NSID).
    pub edns: Option<(u16, bool, Option<String>)>,
}

impl Message {
    pub fn rcode_name(&self) -> &'static str {
        rcode_name(self.rcode)
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, String> {
        let v = *self.buf.get(self.pos).ok_or("ответ обрезан")?;
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes([self.u8()?, self.u8()?, self.u8()?, self.u8()?]))
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("ответ обрезан")?;
        let s = self.buf.get(self.pos..end).ok_or("ответ обрезан")?;
        self.pos = end;
        Ok(s)
    }
    /// Имя со сжатием (указатели на ранее встретившиеся имена).
    fn name(&mut self) -> Result<String, String> {
        let (name, next) = read_name(self.buf, self.pos)?;
        self.pos = next;
        Ok(name)
    }
}

/// Чтение имени с позиции `pos`; возвращает имя и позицию сразу после него.
pub fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos).ok_or("имя обрезано")? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let label = buf.get(pos + 1..pos + 1 + len).ok_or("имя обрезано")?;
                labels.push(escape_label(label));
                pos += 1 + len;
            }
            0xC0 => {
                let lo = *buf.get(pos + 1).ok_or("имя обрезано")? as usize;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                pos = ((len & 0x3F) << 8) | lo;
                jumps += 1;
                if jumps > 64 {
                    return Err("цикл указателей в имени".into());
                }
            }
            _ => return Err("неизвестный тип метки".into()),
        }
    }
    let name = if labels.is_empty() { ".".to_string() } else { labels.join(".") + "." };
    Ok((name, end.unwrap_or(pos)))
}

fn escape_label(label: &[u8]) -> String {
    let mut s = String::new();
    for &b in label {
        match b {
            b'.' | b'\\' => {
                s.push('\\');
                s.push(b as char);
            }
            0x21..=0x7e => s.push(b as char),
            _ => {
                let _ = write!(s, "\\{b:03}");
            }
        }
    }
    s
}

fn txt_strings(data: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let n = data[i] as usize;
        let s = data.get(i + 1..i + 1 + n).unwrap_or(&data[i + 1..]);
        let mut q = String::from("\"");
        for c in String::from_utf8_lossy(s).chars() {
            match c {
                '"' | '\\' => {
                    q.push('\\');
                    q.push(c);
                }
                c if c.is_control() => {
                    let _ = write!(q, "\\{:03}", c as u32);
                }
                c => q.push(c),
            }
        }
        q.push('"');
        parts.push(q);
        i += 1 + n;
    }
    parts.join(" ")
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn type_bitmap(data: &[u8]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let window = data[i] as u16;
        let len = data[i + 1] as usize;
        let bits = data.get(i + 2..i + 2 + len).unwrap_or(&[]);
        for (byte_i, b) in bits.iter().enumerate() {
            for bit in 0..8 {
                if b & (0x80 >> bit) != 0 {
                    out.push(type_name(window * 256 + (byte_i * 8 + bit) as u16));
                }
            }
        }
        i += 2 + len;
    }
    out.join(" ")
}

fn svc_params(buf: &[u8], start: usize, end: usize) -> Result<String, String> {
    let mut r = Reader { buf: &buf[..end], pos: start };
    let prio = r.u16()?;
    let target = r.name()?;
    let mut s = format!("{prio} {target}");
    while r.pos + 4 <= end {
        let key = r.u16()?;
        let len = r.u16()? as usize;
        let val = r.bytes(len)?;
        let v = match key {
            1 => {
                let mut alpn = Vec::new();
                let mut i = 0;
                while i < val.len() {
                    let n = val[i] as usize;
                    alpn.push(String::from_utf8_lossy(val.get(i + 1..i + 1 + n).unwrap_or(&[])).into_owned());
                    i += 1 + n;
                }
                format!("alpn={}", alpn.join(","))
            }
            3 if val.len() == 2 => format!("port={}", u16::from_be_bytes([val[0], val[1]])),
            4 => format!(
                "ipv4hint={}",
                val.chunks(4)
                    .filter(|c| c.len() == 4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            5 => format!("ech={}", b64(val)),
            6 => format!(
                "ipv6hint={}",
                val.chunks(16)
                    .filter(|c| c.len() == 16)
                    .map(|c| Ipv6Addr::from(<[u8; 16]>::try_from(c).unwrap()).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            _ => format!("key{key}={}", super::hex(val)),
        };
        s.push(' ');
        s.push_str(&v);
    }
    Ok(s)
}

/// Текстовое представление данных записи (как в файле зоны).
fn rdata(buf: &[u8], rtype: u16, start: usize, len: usize) -> Result<String, String> {
    let end = start + len;
    let data = buf.get(start..end).ok_or("данные записи обрезаны")?;
    let mut r = Reader { buf: &buf[..end], pos: start };
    Ok(match rtype {
        1 if len == 4 => Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        28 if len == 16 => Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap()).to_string(),
        2 | 5 | 12 | 39 => r.name()?,
        6 => {
            let mname = r.name()?;
            let rname = r.name()?;
            format!(
                "{mname} {rname} {} {} {} {} {}",
                r.u32()?,
                r.u32()?,
                r.u32()?,
                r.u32()?,
                r.u32()?
            )
        }
        13 => txt_strings(data),
        15 => {
            let pref = r.u16()?;
            format!("{pref} {}", r.name()?)
        }
        16 => txt_strings(data),
        33 => {
            let (prio, weight, port) = (r.u16()?, r.u16()?, r.u16()?);
            format!("{prio} {weight} {port} {}", r.name()?)
        }
        35 => {
            let (order, pref) = (r.u16()?, r.u16()?);
            let mut strs = Vec::new();
            for _ in 0..3 {
                let n = r.u8()? as usize;
                strs.push(txt_strings(&[&[n as u8][..], r.bytes(n)?].concat()));
            }
            format!("{order} {pref} {} {}", strs.join(" "), r.name()?)
        }
        43 if len >= 4 => format!(
            "{} {} {} {}",
            u16::from_be_bytes([data[0], data[1]]),
            data[2],
            data[3],
            super::hex(&data[4..]).to_uppercase()
        ),
        44 if len >= 2 => format!("{} {} {}", data[0], data[1], super::hex(&data[2..])),
        46 if len >= 18 => {
            let covered = r.u16()?;
            let alg = r.u8()?;
            let labels = r.u8()?;
            let ottl = r.u32()?;
            let exp = r.u32()?;
            let inc = r.u32()?;
            let tag = r.u16()?;
            let signer = r.name()?;
            let sig = &buf[r.pos..end];
            format!(
                "{} {alg} {labels} {ottl} {} {} {tag} {signer} {}",
                type_name(covered),
                dns_time(exp),
                dns_time(inc),
                b64(sig)
            )
        }
        47 => {
            let next = r.name()?;
            format!("{next} {}", type_bitmap(&buf[r.pos..end]))
        }
        48 if len >= 4 => {
            let flags = u16::from_be_bytes([data[0], data[1]]);
            let role = if flags & 1 == 1 { " ; KSK" } else { " ; ZSK" };
            format!("{flags} {} {} {}{role}", data[2], data[3], b64(&data[4..]))
        }
        50 if len >= 5 => {
            let salt_len = data[4] as usize;
            let salt = data.get(5..5 + salt_len).unwrap_or(&[]);
            let hlen_pos = 5 + salt_len;
            let hlen = *data.get(hlen_pos).unwrap_or(&0) as usize;
            let hash = data.get(hlen_pos + 1..hlen_pos + 1 + hlen).unwrap_or(&[]);
            let bitmap = data.get(hlen_pos + 1 + hlen..).unwrap_or(&[]);
            format!(
                "{} {} {} {} {} {}",
                data[0],
                data[1],
                u16::from_be_bytes([data[2], data[3]]),
                if salt.is_empty() { "-".to_string() } else { super::hex(salt) },
                base32hex(hash),
                type_bitmap(bitmap)
            )
        }
        51 if len >= 5 => {
            let salt = &data[5..];
            format!(
                "{} {} {} {}",
                data[0],
                data[1],
                u16::from_be_bytes([data[2], data[3]]),
                if salt.is_empty() { "-".to_string() } else { super::hex(salt) }
            )
        }
        52 if len >= 3 => format!("{} {} {} {}", data[0], data[1], data[2], super::hex(&data[3..])),
        64 | 65 => svc_params(buf, start, end)?,
        257 if len >= 2 => {
            let tlen = data[1] as usize;
            let tag = String::from_utf8_lossy(data.get(2..2 + tlen).unwrap_or(&[]));
            let val = String::from_utf8_lossy(data.get(2 + tlen..).unwrap_or(&[]));
            format!("{} {tag} \"{val}\"", data[0])
        }
        _ => format!("\\# {len} {}", super::hex(data)),
    })
}

fn dns_time(t: u32) -> String {
    let secs = t as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}", rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Дата по числу дней от 1970-01-01 (алгоритм Howard Hinnant).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn base32hex(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHA[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHA[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn parse(buf: &[u8]) -> Result<Message, String> {
    let mut r = Reader { buf, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let ns = r.u16()?;
    let ar = r.u16()?;
    let mut msg = Message {
        id,
        opcode: ((flags >> 11) & 0xF) as u8,
        rcode: flags & 0xF,
        flags: Flags {
            qr: flags & 0x8000 != 0,
            aa: flags & 0x0400 != 0,
            tc: flags & 0x0200 != 0,
            rd: flags & 0x0100 != 0,
            ra: flags & 0x0080 != 0,
            ad: flags & 0x0020 != 0,
            cd: flags & 0x0010 != 0,
        },
        ..Default::default()
    };
    for _ in 0..qd {
        let name = r.name()?;
        let t = r.u16()?;
        let _class = r.u16()?;
        msg.question.push((name, type_name(t)));
    }
    for section in 0..3 {
        let count = [an, ns, ar][section];
        for _ in 0..count {
            let name = r.name()?;
            let t = r.u16()?;
            let class = r.u16()?;
            let ttl = r.u32()?;
            let len = r.u16()? as usize;
            let start = r.pos;
            r.bytes(len)?;
            if t == 41 {
                // OPT: класс — размер буфера, TTL — расширенный RCODE, версия и флаги.
                let ext_rcode = (ttl >> 24) as u16;
                msg.rcode |= ext_rcode << 4;
                let mut nsid = None;
                let opts = &buf[start..start + len];
                let mut i = 0;
                while i + 4 <= opts.len() {
                    let code = u16::from_be_bytes([opts[i], opts[i + 1]]);
                    let olen = u16::from_be_bytes([opts[i + 2], opts[i + 3]]) as usize;
                    let val = opts.get(i + 4..i + 4 + olen).unwrap_or(&[]);
                    if code == 3 {
                        let text: String = String::from_utf8_lossy(val).into();
                        nsid = Some(if text.chars().all(|c| !c.is_control()) && !text.is_empty() {
                            text
                        } else {
                            super::hex(val)
                        });
                    }
                    i += 4 + olen;
                }
                msg.edns = Some((class, ttl & 0x8000 != 0, nsid));
                continue;
            }
            let data = rdata(buf, t, start, len).unwrap_or_else(|e| format!("(ошибка разбора: {e})"));
            let rec = Record {
                name,
                rtype: type_name(t),
                class,
                ttl,
                data,
            };
            match section {
                0 => msg.answers.push(rec),
                1 => msg.authority.push(rec),
                _ => msg.additional.push(rec),
            }
        }
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let mut q = Query::new(0x1234, "example.com", 1);
        q.edns = false;
        let b = build_query(&q).unwrap();
        assert_eq!(
            b,
            [
                0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c',
                b'o', b'm', 0, 0, 1, 0, 1
            ]
        );
        q.edns = true;
        q.dnssec_ok = true;
        let b = build_query(&q).unwrap();
        assert_eq!(&b[10..12], &[0, 1]);
        assert_eq!(&b[b.len() - 11..], &[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]);
        assert!(build_query(&Query::new(1, "a..b", 1)).is_err());
    }

    fn rr(name_ptr: bool, t: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        if name_ptr {
            v.extend_from_slice(&[0xC0, 12]);
        } else {
            v.push(0);
        }
        v.extend_from_slice(&t.to_be_bytes());
        v.extend_from_slice(&[0, 1, 0, 0, 0x0E, 0x10]);
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn parse_answers_with_compression() {
        let mut m = vec![0xab, 0xcd, 0x81, 0xa0, 0, 1, 0, 4, 0, 0, 0, 1];
        encode_name(&mut m, "example.com").unwrap();
        m.extend_from_slice(&[0, 15, 0, 1]);
        m.extend(rr(true, 1, &[93, 184, 216, 34]));
        // MX 10 mail.<ptr example.com>
        m.extend(rr(true, 15, &[0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 12]));
        m.extend(rr(true, 16, b"\x05hello\x03a\"b"));
        m.extend(rr(true, 33, &[0, 1, 0, 2, 0x01, 0xBB, 0xC0, 12]));
        // OPT с NSID
        m.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0x01, 0, 0x80, 0, 0, 8, 0, 3, 0, 4, b'n', b's', b'-', b'1']);
        let msg = parse(&m).unwrap();
        assert_eq!(msg.id, 0xabcd);
        assert!(msg.flags.qr && msg.flags.rd && msg.flags.ra && msg.flags.ad);
        assert_eq!(msg.question, vec![("example.com.".into(), "MX".into())]);
        assert_eq!(msg.answers.len(), 4);
        assert_eq!(msg.answers[0].data, "93.184.216.34");
        assert_eq!(msg.answers[0].ttl, 3600);
        assert_eq!(msg.answers[1].data, "10 mail.example.com.");
        assert_eq!(msg.answers[2].data, "\"hello\" \"a\\\"b\"");
        assert_eq!(msg.answers[3].data, "1 2 443 example.com.");
        let (size, d_o, nsid) = msg.edns.clone().unwrap();
        assert_eq!((size, d_o, nsid.as_deref()), (1232, true, Some("ns-1")));
        // Расширенный RCODE: 1 << 4 = 16 (BADVERS).
        assert_eq!(msg.rcode, 16);
    }

    #[test]
    fn pointer_loop_rejected() {
        let buf = [0xC0, 0x00];
        assert!(read_name(&buf, 0).is_err());
    }

    #[test]
    fn reverse_names() {
        assert_eq!(reverse_name("10.1.2.3".parse().unwrap()), "3.2.1.10.in-addr.arpa");
        let v6 = reverse_name("2001:db8::1".parse().unwrap());
        assert!(v6.starts_with("1.0.0.0.") && v6.ends_with("8.b.d.0.1.0.0.2.ip6.arpa"));
    }

    #[test]
    fn types_and_time() {
        assert_eq!(type_code("mx"), Some(15));
        assert_eq!(type_code("TYPE65534"), Some(65534));
        assert_eq!(type_name(65534), "TYPE65534");
        assert_eq!(dns_time(0), "19700101000000");
        assert_eq!(dns_time(1_700_000_000), "20231114221320");
        assert_eq!(base32hex(&[0xff]), "VS");
    }

    #[test]
    fn nsec_bitmap() {
        // Окно 0: A(1), MX(15), RRSIG(46), NSEC(47)
        let mut bits = vec![0u8; 6];
        for t in [1u16, 15, 46, 47] {
            bits[(t / 8) as usize] |= 0x80 >> (t % 8);
        }
        let mut data = vec![0, 6];
        data.extend(bits);
        assert_eq!(type_bitmap(&data), "A MX RRSIG NSEC");
    }
}
