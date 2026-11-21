//! Коллектор NetFlow v5/v9, IPFIX и sFlow v5: кто, с кем и чем занимает канал.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::Sink;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind: String,
    /// NetFlow v5/v9 и IPFIX.
    pub netflow_port: u16,
    pub sflow_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self { bind: "0.0.0.0".into(), netflow_port: 2055, sflow_port: 6343 }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Debug, Clone)]
pub enum Event {
    Status(Result<String, String>),
    /// Экспортёр, формат, записи.
    Flows(IpAddr, &'static str, Vec<Flow>),
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}
fn uint(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0u64, |a, x| (a << 8) | *x as u64)
}

/// NetFlow v5: заголовок 24 байта, записи по 48.
pub fn parse_v5(b: &[u8]) -> Vec<Flow> {
    let n = u16_at(b, 2).unwrap_or(0) as usize;
    let mut out = Vec::new();
    for i in 0..n.min(30) {
        let r = 24 + i * 48;
        let Some(rec) = b.get(r..r + 48) else { break };
        out.push(Flow {
            src: IpAddr::V4(Ipv4Addr::new(rec[0], rec[1], rec[2], rec[3])),
            dst: IpAddr::V4(Ipv4Addr::new(rec[4], rec[5], rec[6], rec[7])),
            packets: u32_at(rec, 16).unwrap_or(0) as u64,
            bytes: u32_at(rec, 20).unwrap_or(0) as u64,
            sport: u16_at(rec, 32).unwrap_or(0),
            dport: u16_at(rec, 34).unwrap_or(0),
            proto: rec[38],
        });
    }
    out
}

/// Шаблон v9/IPFIX: (тип поля, длина).
type Template = Vec<(u16, u16)>;

/// Шаблоны по (экспортёр, домен, номер шаблона).
#[derive(Default)]
pub struct Templates(HashMap<(IpAddr, u32, u16), Template>);

fn record(t: &Template, data: &[u8]) -> Option<(Flow, usize)> {
    let mut f = Flow { src: IpAddr::V4(Ipv4Addr::UNSPECIFIED), dst: IpAddr::V4(Ipv4Addr::UNSPECIFIED), sport: 0, dport: 0, proto: 0, bytes: 0, packets: 0 };
    let mut off = 0;
    for &(ty, len) in t {
        let mut len = len as usize;
        if len == 65535 {
            // IPFIX: поле переменной длины.
            let l = *data.get(off)? as usize;
            off += 1;
            len = if l == 255 {
                let l2 = u16_at(data, off)? as usize;
                off += 2;
                l2
            } else {
                l
            };
        }
        let v = data.get(off..off + len)?;
        match ty {
            1 | 23 | 85 => f.bytes = f.bytes.max(uint(v)),
            2 | 24 | 86 => f.packets = f.packets.max(uint(v)),
            4 => f.proto = uint(v) as u8,
            7 => f.sport = uint(v) as u16,
            11 => f.dport = uint(v) as u16,
            8 if len == 4 => f.src = IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            12 if len == 4 => f.dst = IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            27 if len == 16 => f.src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(v).ok()?)),
            28 if len == 16 => f.dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(v).ok()?)),
            _ => {}
        }
        off += len;
    }
    Some((f, off))
}

impl Templates {
    /// NetFlow v9 (version 9) и IPFIX (version 10).
    pub fn parse(&mut self, exporter: IpAddr, b: &[u8]) -> Vec<Flow> {
        let ver = u16_at(b, 0).unwrap_or(0);
        let (mut off, domain, tmpl_set, opt_set) = match ver {
            9 => (20, u32_at(b, 16).unwrap_or(0), 0u16, 1u16),
            10 => (16, u32_at(b, 12).unwrap_or(0), 2, 3),
            _ => return Vec::new(),
        };
        let end = if ver == 10 { (u16_at(b, 2).unwrap_or(0) as usize).min(b.len()) } else { b.len() };
        let mut out = Vec::new();
        while off + 4 <= end {
            let (Some(id), Some(len)) = (u16_at(b, off), u16_at(b, off + 2)) else { break };
            let len = len as usize;
            if len < 4 || off + len > end {
                break;
            }
            let set = &b[off + 4..off + len];
            if id == tmpl_set {
                let mut p = 0;
                while p + 4 <= set.len() {
                    let tid = u16_at(set, p).unwrap_or(0);
                    let count = u16_at(set, p + 2).unwrap_or(0) as usize;
                    p += 4;
                    let mut t = Vec::new();
                    for _ in 0..count {
                        let (Some(mut ty), Some(l)) = (u16_at(set, p), u16_at(set, p + 2)) else { break };
                        p += 4;
                        if ver == 10 && ty & 0x8000 != 0 {
                            ty = 0; // поле производителя: пропускаем значение
                            p += 4;
                        }
                        t.push((ty, l));
                    }
                    if tid >= 256 {
                        self.0.insert((exporter, domain, tid), t);
                    }
                }
            } else if id == opt_set {
                // Шаблоны опций не нужны.
            } else if id >= 256
                && let Some(t) = self.0.get(&(exporter, domain, id))
            {
                let mut p = 0;
                let min: usize = t.iter().map(|x| if x.1 == 65535 { 1 } else { x.1 as usize }).sum();
                while min > 0 && p + min <= set.len() {
                    let Some((f, used)) = record(t, &set[p..]) else { break };
                    p += used;
                    if f.bytes > 0 || f.packets > 0 {
                        out.push(f);
                    }
                }
            }
            off += len;
        }
        out
    }
}

/// Разобрать IPv4/IPv6 из заголовка Ethernet (для sFlow).
fn from_ethernet(h: &[u8], frame_len: u64, rate: u64) -> Option<Flow> {
    let mut et = u16_at(h, 12)?;
    let mut off = 14;
    while et == 0x8100 || et == 0x88a8 {
        et = u16_at(h, off + 2)?;
        off += 4;
    }
    let (src, dst, proto, l4) = match et {
        0x0800 => {
            let ip = h.get(off..)?;
            let ihl = ((*ip.first()? & 0x0f) as usize) * 4;
            (IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])), IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])), *ip.get(9)?, off + ihl)
        }
        0x86dd => {
            let ip = h.get(off..off + 40)?;
            (IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?)), IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?)), ip[6], off + 40)
        }
        _ => return None,
    };
    let (sport, dport) = if proto == 6 || proto == 17 { (u16_at(h, l4).unwrap_or(0), u16_at(h, l4 + 2).unwrap_or(0)) } else { (0, 0) };
    Some(Flow { src, dst, sport, dport, proto, bytes: frame_len * rate, packets: rate })
}

/// sFlow v5: выборки пакетов (flow sample) с заголовками, умноженные на частоту выборки.
pub fn parse_sflow(b: &[u8]) -> Vec<Flow> {
    let mut out = Vec::new();
    if u32_at(b, 0) != Some(5) {
        return out;
    }
    let addr_len = match u32_at(b, 4) {
        Some(1) => 4,
        Some(2) => 16,
        _ => return out,
    };
    let mut off = 8 + addr_len + 12; // agent, sub_agent_id, seq, uptime
    let n = u32_at(b, off).unwrap_or(0);
    off += 4;
    for _ in 0..n.min(64) {
        let (Some(fmt), Some(len)) = (u32_at(b, off), u32_at(b, off + 4)) else { break };
        let len = len as usize;
        let body = off + 8;
        let Some(s) = b.get(body..body + len) else { break };
        // 1 — flow sample, 3 — expanded flow sample.
        let (rate_at, recs_at) = match fmt & 0xfff {
            1 => (8, 28),
            3 => (12, 44),
            _ => {
                off = body + len;
                continue;
            }
        };
        let rate = u32_at(s, rate_at).unwrap_or(1).max(1) as u64;
        let nrec = u32_at(s, recs_at).unwrap_or(0);
        let mut p = recs_at + 4;
        for _ in 0..nrec.min(16) {
            let (Some(rf), Some(rl)) = (u32_at(s, p), u32_at(s, p + 4)) else { break };
            let rl = rl as usize;
            let rd = p + 8;
            // Запись 1 — сырой заголовок пакета: protocol, frame_length, stripped, header_len, header.
            if rf & 0xfff == 1
                && let Some(r) = s.get(rd..rd + rl)
                && u32_at(r, 0) == Some(1)
            {
                let frame = u32_at(r, 4).unwrap_or(0) as u64;
                let hl = u32_at(r, 12).unwrap_or(0) as usize;
                if let Some(h) = r.get(16..16 + hl)
                    && let Some(f) = from_ethernet(h, frame, rate)
                {
                    out.push(f);
                }
            }
            p = rd + rl;
        }
        off = body + len;
    }
    out
}

async fn listen(sock: UdpSocket, sflow: bool, sink: Sink<Event>, cancel: CancellationToken) {
    let mut buf = vec![0u8; 65535];
    let mut templates = Templates::default();
    loop {
        let (n, from): (usize, SocketAddr) = tokio::select! {
            r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
            _ = cancel.cancelled() => return,
        };
        let b = &buf[..n];
        let (kind, flows) = if sflow {
            ("sFlow", parse_sflow(b))
        } else {
            match u16_at(b, 0) {
                Some(5) => ("NetFlow v5", parse_v5(b)),
                Some(9) => ("NetFlow v9", templates.parse(from.ip(), b)),
                Some(10) => ("IPFIX", templates.parse(from.ip(), b)),
                _ => continue,
            }
        };
        sink.send(Event::Flows(from.ip(), kind, flows));
    }
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let nf = UdpSocket::bind(format!("{}:{}", cfg.bind, cfg.netflow_port)).await;
    let sf = UdpSocket::bind(format!("{}:{}", cfg.bind, cfg.sflow_port)).await;
    let mut set = tokio::task::JoinSet::new();
    let mut ok = Vec::new();
    match nf {
        Ok(s) => {
            ok.push(format!("NetFlow/IPFIX UDP {}", cfg.netflow_port));
            set.spawn(listen(s, false, sink.clone(), cancel.clone()));
        }
        Err(e) => sink.send(Event::Status(Err(format!("порт {}: {e}", cfg.netflow_port)))),
    }
    match sf {
        Ok(s) => {
            ok.push(format!("sFlow UDP {}", cfg.sflow_port));
            set.spawn(listen(s, true, sink.clone(), cancel.clone()));
        }
        Err(e) => sink.send(Event::Status(Err(format!("порт {}: {e}", cfg.sflow_port)))),
    }
    if ok.is_empty() {
        return;
    }
    sink.send(Event::Status(Ok(ok.join(", "))));
    cancel.cancelled().await;
    set.abort_all();
}

/// Название приложения по порту.
pub fn app(f: &Flow) -> String {
    let port = if f.dport != 0 && (f.dport < f.sport || f.sport == 0) { f.dport } else { f.sport };
    let proto = match f.proto {
        6 => "TCP",
        17 => "UDP",
        1 => return "ICMP".into(),
        58 => return "ICMPv6".into(),
        47 => return "GRE".into(),
        50 => return "IPsec ESP".into(),
        x => return format!("IP {x}"),
    };
    let name = match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 465 | 587 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 | 8080 => "HTTP",
        110 | 995 => "POP3",
        123 => "NTP",
        137..=139 | 445 => "SMB",
        143 | 993 => "IMAP",
        161 | 162 => "SNMP",
        389 | 636 => "LDAP",
        443 | 8443 => if f.proto == 17 { "QUIC" } else { "HTTPS" },
        514 => "Syslog",
        1194 => "OpenVPN",
        1433 => "MS SQL",
        1521 => "Oracle",
        3128 => "Прокси",
        3306 => "MySQL",
        3389 => "RDP",
        5060 | 5061 => "SIP",
        5432 => "PostgreSQL",
        5900..=5910 => "VNC",
        51820 => "WireGuard",
        _ => "",
    };
    if name.is_empty() { format!("{proto}/{port}") } else { name.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v5() {
        let mut b = vec![0u8; 24 + 48];
        b[1] = 5;
        b[3] = 1;
        let r = &mut b[24..];
        r[..4].copy_from_slice(&[10, 0, 0, 5]);
        r[4..8].copy_from_slice(&[8, 8, 8, 8]);
        r[16..20].copy_from_slice(&10u32.to_be_bytes());
        r[20..24].copy_from_slice(&1500u32.to_be_bytes());
        r[32..34].copy_from_slice(&50000u16.to_be_bytes());
        r[34..36].copy_from_slice(&443u16.to_be_bytes());
        r[38] = 6;
        let f = parse_v5(&b);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].bytes, f[0].packets, f[0].dport), (1500, 10, 443));
        assert_eq!(app(&f[0]), "HTTPS");
    }

    #[test]
    fn v9_template_then_data() {
        let exp: IpAddr = "10.0.0.1".parse().unwrap();
        let fields: [(u16, u16); 7] = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4)];
        let mut tset = vec![0, 0, 0, 0, 1, 0, 0, fields.len() as u8];
        for (t, l) in fields {
            tset.extend(t.to_be_bytes());
            tset.extend(l.to_be_bytes());
        }
        let tl = tset.len() as u16;
        tset[2..4].copy_from_slice(&tl.to_be_bytes());
        let mut rec = vec![192, 168, 1, 10, 1, 1, 1, 1];
        rec.extend(40000u16.to_be_bytes());
        rec.extend(53u16.to_be_bytes());
        rec.push(17);
        rec.extend(300u32.to_be_bytes());
        rec.extend(3u32.to_be_bytes());
        let mut dset = vec![1, 0, 0, 0];
        dset.extend(&rec);
        dset.extend([0, 0, 0]); // выравнивание
        let dl = dset.len() as u16;
        dset[2..4].copy_from_slice(&dl.to_be_bytes());
        let mut pkt = vec![0, 9, 0, 2];
        pkt.extend([0u8; 12]);
        pkt.extend(7u32.to_be_bytes());
        pkt.extend(&tset);
        pkt.extend(&dset);
        let mut t = Templates::default();
        let f = t.parse(exp, &pkt);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].src, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!((f[0].bytes, f[0].dport, f[0].proto), (300, 53, 17));
        assert_eq!(app(&f[0]), "DNS");
    }

    #[test]
    fn sflow_sample() {
        // Ethernet + IPv4 + TCP заголовок.
        let mut h = vec![0u8; 14 + 20 + 4];
        h[12] = 0x08;
        h[14] = 0x45;
        h[14 + 9] = 6;
        h[26..30].copy_from_slice(&[10, 1, 1, 1]);
        h[30..34].copy_from_slice(&[10, 2, 2, 2]);
        h[34..36].copy_from_slice(&3389u16.to_be_bytes());
        h[36..38].copy_from_slice(&50123u16.to_be_bytes());
        let mut raw = Vec::new();
        raw.extend(1u32.to_be_bytes()); // ethernet
        raw.extend(1000u32.to_be_bytes()); // frame length
        raw.extend(4u32.to_be_bytes());
        raw.extend((h.len() as u32).to_be_bytes());
        raw.extend(&h);
        while raw.len() % 4 != 0 {
            raw.push(0);
        }
        let mut sample = Vec::new();
        sample.extend(1u32.to_be_bytes()); // seq
        sample.extend(1u32.to_be_bytes()); // source id
        sample.extend(512u32.to_be_bytes()); // sampling rate
        sample.extend([0u8; 16]); // pool, drops, input, output
        sample.extend(1u32.to_be_bytes()); // records
        sample.extend(1u32.to_be_bytes()); // raw header
        sample.extend((raw.len() as u32).to_be_bytes());
        sample.extend(&raw);
        let mut d = Vec::new();
        d.extend(5u32.to_be_bytes());
        d.extend(1u32.to_be_bytes());
        d.extend([10, 0, 0, 1]);
        d.extend([0u8; 12]);
        d.extend(1u32.to_be_bytes());
        d.extend(1u32.to_be_bytes());
        d.extend((sample.len() as u32).to_be_bytes());
        d.extend(&sample);
        let f = parse_sflow(&d);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].bytes, f[0].packets), (512_000, 512));
        assert_eq!(app(&f[0]), "RDP");
    }
}
