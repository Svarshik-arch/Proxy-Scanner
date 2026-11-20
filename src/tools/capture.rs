//! Захват пакетов и пассивное прослушивание через libpcap / Npcap (загружается
//! динамически, при наличии): разбор основных протоколов, сохранение в pcapng и сводка
//! для сетевика — DHCP-серверы, соседи LLDP/CDP (коммутатор и порт), корень STP,
//! подмена ARP, широковещательные запросы имён (LLMNR, NBT-NS, mDNS), SNI в TLS.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;

// ---------------------------------------------------------------------------
// libpcap
// ---------------------------------------------------------------------------

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut PcapAddr,
    flags: c_uint,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *mut libc_sockaddr,
    netmask: *mut libc_sockaddr,
    broadaddr: *mut libc_sockaddr,
    dstaddr: *mut libc_sockaddr,
}

#[repr(C)]
struct libc_sockaddr {
    family: u16,
    data: [u8; 14],
}

#[repr(C)]
struct BpfProgram {
    len: c_uint,
    insns: *mut c_void,
}

#[cfg(windows)]
#[repr(C)]
struct TimeVal {
    sec: i32,
    usec: i32,
}
#[cfg(not(windows))]
#[repr(C)]
struct TimeVal {
    sec: i64,
    usec: i64,
}

#[repr(C)]
struct PktHdr {
    ts: TimeVal,
    caplen: u32,
    len: u32,
}

type FindAll = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FreeAll = unsafe extern "C" fn(*mut PcapIf);
type OpenLive = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
type Compile = unsafe extern "C" fn(*mut c_void, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type SetFilter = unsafe extern "C" fn(*mut c_void, *mut BpfProgram) -> c_int;
type FreeCode = unsafe extern "C" fn(*mut BpfProgram);
type NextEx = unsafe extern "C" fn(*mut c_void, *mut *mut PktHdr, *mut *const u8) -> c_int;
type Close = unsafe extern "C" fn(*mut c_void);
type GetErr = unsafe extern "C" fn(*mut c_void) -> *mut c_char;
type DataLink = unsafe extern "C" fn(*mut c_void) -> c_int;
type SetNonBlock = unsafe extern "C" fn(*mut c_void, c_int, *mut c_char) -> c_int;

pub struct Pcap {
    _lib: libloading::Library,
    findall: FindAll,
    freeall: FreeAll,
    open_live: OpenLive,
    compile: Compile,
    setfilter: SetFilter,
    freecode: FreeCode,
    next_ex: NextEx,
    close: Close,
    geterr: GetErr,
    datalink: DataLink,
    setnonblock: SetNonBlock,
}

const LIB_NAMES: &[&str] = if cfg!(windows) {
    &["C:\\Windows\\System32\\Npcap\\wpcap.dll", "wpcap.dll"]
} else {
    &["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"]
};

impl Pcap {
    pub fn load() -> Result<Self, String> {
        let mut last = String::new();
        for name in LIB_NAMES {
            // SAFETY: загружаем системную библиотеку libpcap/Npcap; её инициализация безопасна.
            match unsafe { libloading::Library::new(name) } {
                Ok(lib) => {
                    // SAFETY: сигнатуры соответствуют pcap.h.
                    unsafe {
                        macro_rules! sym {
                            ($n:literal) => {
                                *lib.get($n).map_err(|e| format!("{}: {e}", String::from_utf8_lossy($n)))?
                            };
                        }
                        return Ok(Self {
                            findall: sym!(b"pcap_findalldevs\0"),
                            freeall: sym!(b"pcap_freealldevs\0"),
                            open_live: sym!(b"pcap_open_live\0"),
                            compile: sym!(b"pcap_compile\0"),
                            setfilter: sym!(b"pcap_setfilter\0"),
                            freecode: sym!(b"pcap_freecode\0"),
                            next_ex: sym!(b"pcap_next_ex\0"),
                            close: sym!(b"pcap_close\0"),
                            geterr: sym!(b"pcap_geterr\0"),
                            datalink: sym!(b"pcap_datalink\0"),
                            setnonblock: sym!(b"pcap_setnonblock\0"),
                            _lib: lib,
                        });
                    }
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(format!(
            "не найден {} ({last}); {}",
            if cfg!(windows) { "Npcap (wpcap.dll)" } else { "libpcap" },
            if cfg!(windows) { "установите Npcap с npcap.com" } else { "установите пакет libpcap" }
        ))
    }

    pub fn devices(&self) -> Result<Vec<Device>, String> {
        let mut err = [0 as c_char; 256];
        let mut head: *mut PcapIf = std::ptr::null_mut();
        // SAFETY: буфер ошибки на 256 байт (PCAP_ERRBUF_SIZE), список освобождается ниже.
        unsafe {
            if (self.findall)(&mut head, err.as_mut_ptr()) != 0 {
                return Err(CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned());
            }
            let mut out = Vec::new();
            let mut cur = head;
            while !cur.is_null() {
                let d = &*cur;
                let name = CStr::from_ptr(d.name).to_string_lossy().into_owned();
                let description = if d.description.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(d.description).to_string_lossy().into_owned()
                };
                let mut addrs = Vec::new();
                let mut a = d.addresses;
                while !a.is_null() {
                    let sa = (*a).addr;
                    if !sa.is_null() && (*sa).family == 2 {
                        let b = &(*sa).data;
                        addrs.push(Ipv4Addr::new(b[2], b[3], b[4], b[5]).to_string());
                    }
                    a = (*a).next;
                }
                out.push(Device {
                    name,
                    description,
                    addrs,
                    loopback: d.flags & 1 != 0,
                });
                cur = d.next;
            }
            (self.freeall)(head);
            Ok(out)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Device {
    pub name: String,
    pub description: String,
    pub addrs: Vec<String>,
    pub loopback: bool,
}

impl Device {
    pub fn label(&self) -> String {
        let d = if self.description.is_empty() { self.name.clone() } else { self.description.clone() };
        if self.addrs.is_empty() { d } else { format!("{d} — {}", self.addrs.join(", ")) }
    }
}

// ---------------------------------------------------------------------------
// Конфигурация и события
// ---------------------------------------------------------------------------

/// Фильтр для пассивного прослушивания служебных протоколов.
pub const PASSIVE_FILTER: &str = "arp or udp port 67 or udp port 68 or ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc or stp or udp port 5355 or udp port 137 or udp port 5353 or udp port 1900 or icmp6 or (icmp and icmp[0] = 5)";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub device: String,
    pub filter: String,
    pub promiscuous: bool,
    /// Ограничение по времени, секунды (0 — до остановки).
    pub seconds: u64,
    /// Ограничение по числу пакетов (0 — без ограничения).
    pub max_packets: u64,
    /// Сколько пакетов хранить для сохранения в pcapng.
    pub keep_packets: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device: String::new(),
            filter: String::new(),
            promiscuous: true,
            seconds: 0,
            max_packets: 0,
            keep_packets: 200_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub n: u64,
    /// Секунды от начала захвата.
    pub t: f64,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub len: u32,
    pub info: String,
}

/// Сырой пакет для pcapng.
#[derive(Debug, Clone)]
pub struct Raw {
    pub ts_us: u64,
    pub len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DhcpServer {
    pub ip: String,
    pub mac: String,
    pub messages: u32,
    pub router: String,
    pub dns: String,
    pub offered: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Neighbor {
    pub protocol: String,
    pub device: String,
    pub port: String,
    pub port_description: String,
    pub vlan: String,
    pub platform: String,
    pub mgmt: String,
    pub mac: String,
}

/// Сводка пассивного прослушивания.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Summary {
    pub dhcp: Vec<DhcpServer>,
    pub neighbors: Vec<Neighbor>,
    pub stp_root: Option<String>,
    /// IP → MAC (если MAC больше одного — возможна подмена ARP).
    pub arp: BTreeMap<String, Vec<String>>,
    /// (протокол, имя, кто спрашивает) → число запросов.
    pub name_queries: BTreeMap<String, u32>,
    pub sni: BTreeMap<String, u32>,
    pub protocols: BTreeMap<String, u64>,
    pub packets: u64,
    pub bytes: u64,
    /// Все замеченные корневые мосты STP (смена корня — признак атаки или сбоя).
    pub stp_roots: Vec<String>,
    /// Объявления маршрутизатора IPv6 (RA): «адрес (MAC)» → количество.
    pub ipv6_ra: BTreeMap<String, u32>,
    /// ICMP Redirect: «от кого → какой шлюз предлагает» → количество.
    pub icmp_redirects: BTreeMap<String, u32>,
    /// Кто отвечает на широковещательные запросы имён: адрес → имена.
    pub name_responders: BTreeMap<String, std::collections::BTreeSet<String>>,
    /// Объём трафика между адресами: «a ↔ b» → байт (для живой карты).
    pub talk: BTreeMap<String, u64>,
}

impl Summary {
    pub fn arp_conflicts(&self) -> Vec<(&String, &Vec<String>)> {
        self.arp.iter().filter(|(_, m)| m.len() > 1).collect()
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Started(i32),
    Packets(Vec<Packet>, Vec<Raw>),
    Stopped(String),
}

// ---------------------------------------------------------------------------
// Разбор пакетов
// ---------------------------------------------------------------------------

fn mac(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

/// Результат разбора: строка для таблицы и обновление сводки.
pub fn dissect(frame: &[u8], linktype: i32, sum: &mut Summary) -> (String, String, String, String) {
    let proto_count = |sum: &mut Summary, p: &str| *sum.protocols.entry(p.to_string()).or_insert(0) += 1;
    if linktype != 1 || frame.len() < 14 {
        proto_count(sum, "другое");
        return (String::new(), String::new(), format!("link {linktype}"), String::new());
    }
    let dst = &frame[0..6];
    let src = &frame[6..12];
    let mut et = be16(frame, 12);
    let mut off = 14;
    let mut vlan = None;
    if et == 0x8100 && frame.len() >= 18 {
        vlan = Some(be16(frame, 14) & 0x0FFF);
        et = be16(frame, 16);
        off = 18;
    }
    let payload = &frame[off..];
    let (smac, dmac) = (mac(src), mac(dst));
    let vtag = vlan.map(|v| format!(" [VLAN {v}]")).unwrap_or_default();
    // IEEE 802.3 с LLC: CDP и STP.
    if et <= 1500 {
        if payload.len() >= 8 && payload[0] == 0xAA && payload[1] == 0xAA && payload[3..6] == [0, 0, 0x0c] && be16(payload, 6) == 0x2000 {
            proto_count(sum, "CDP");
            let n = parse_cdp(&payload[8..], &smac);
            let info = format!("CDP {} порт {}{}", n.device, n.port, if n.vlan.is_empty() { String::new() } else { format!(" VLAN {}", n.vlan) });
            upsert_neighbor(sum, n);
            return (smac, dmac, "CDP".into(), info);
        }
        if payload.len() >= 3 && payload[0] == 0x42 && payload[1] == 0x42 {
            proto_count(sum, "STP");
            let bpdu = &payload[3..];
            if bpdu.len() >= 13 {
                let prio = be16(bpdu, 5);
                let root = format!("{} / {}", prio & 0xF000, mac(&bpdu[7..13]));
                sum.stp_root = Some(root.clone());
                if !sum.stp_roots.contains(&root) {
                    sum.stp_roots.push(root.clone());
                }
                return (smac, dmac, "STP".into(), format!("корень {root}"));
            }
            return (smac, dmac, "STP".into(), String::new());
        }
        proto_count(sum, "LLC");
        return (smac, dmac, "LLC".into(), String::new());
    }
    match et {
        0x0806 if payload.len() >= 28 => {
            proto_count(sum, "ARP");
            let op = be16(payload, 6);
            let sha = mac(&payload[8..14]);
            let spa = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);
            let tpa = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);
            if !spa.is_unspecified() {
                let e = sum.arp.entry(spa.to_string()).or_default();
                if !e.contains(&sha) {
                    e.push(sha.clone());
                }
            }
            let info = if op == 1 { format!("кто {tpa}? скажите {spa}") } else { format!("{spa} — это {sha}") };
            (smac, dmac, "ARP".into(), info + &vtag)
        }
        0x88CC => {
            proto_count(sum, "LLDP");
            let n = parse_lldp(payload, &smac);
            let info = format!("LLDP {} порт {}{}", n.device, n.port, if n.vlan.is_empty() { String::new() } else { format!(" VLAN {}", n.vlan) });
            upsert_neighbor(sum, n);
            (smac, dmac, "LLDP".into(), info)
        }
        0x0800 if payload.len() >= 20 => {
            let ihl = ((payload[0] & 0x0F) as usize) * 4;
            let proto = payload[9];
            let s = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]).to_string();
            let d = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]).to_string();
            let l4 = payload.get(ihl..).unwrap_or(&[]);
            let key = if s < d { format!("{s} ↔ {d}") } else { format!("{d} ↔ {s}") };
            if sum.talk.len() < 5000 || sum.talk.contains_key(&key) {
                *sum.talk.entry(key).or_insert(0) += frame.len() as u64;
            }
            let (p, info) = transport(proto, l4, &s, &d, &smac, sum);
            (s, d, p, info + &vtag)
        }
        0x86DD if payload.len() >= 40 => {
            let next = payload[6];
            let s = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[8..24]).unwrap()).to_string();
            let d = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[24..40]).unwrap()).to_string();
            let (p, info) = transport(next, &payload[40..], &s, &d, &smac, sum);
            (s, d, format!("{p}/6"), info + &vtag)
        }
        other => {
            proto_count(sum, "другое");
            (smac, dmac, format!("0x{other:04x}"), vtag)
        }
    }
}

fn transport(proto: u8, l4: &[u8], src: &str, _dst: &str, smac: &str, sum: &mut Summary) -> (String, String) {
    let mut count = |p: &str| *sum.protocols.entry(p.to_string()).or_insert(0) += 1;
    match proto {
        6 if l4.len() >= 20 => {
            let (sp, dp) = (be16(l4, 0), be16(l4, 2));
            let flags = l4[13];
            let names = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH")];
            let f: Vec<&str> = names.iter().filter(|(b, _)| flags & b != 0).map(|(_, n)| *n).collect();
            let doff = ((l4[12] >> 4) as usize) * 4;
            let data = l4.get(doff..).unwrap_or(&[]);
            let mut info = format!("{sp} → {dp} [{}]", f.join(","));
            if let Some(sni) = tls_sni(data) {
                count("TLS");
                *sum.sni.entry(sni.clone()).or_insert(0) += 1;
                info = format!("{info} TLS ClientHello SNI={sni}");
                return ("TLS".into(), info);
            }
            if let Some(line) = http_line(data) {
                count("HTTP");
                return ("HTTP".into(), format!("{info} {line}"));
            }
            count("TCP");
            ("TCP".into(), info)
        }
        17 if l4.len() >= 8 => {
            let (sp, dp) = (be16(l4, 0), be16(l4, 2));
            let data = &l4[8..];
            match (sp, dp) {
                (67, _) | (_, 67) | (68, _) | (_, 68) => {
                    count("DHCP");
                    ("DHCP".into(), parse_dhcp(data, src, smac, sum))
                }
                (_, 5355) | (5355, _) => {
                    count("LLMNR");
                    let q = dns_qname(data).unwrap_or_default();
                    if dp == 5355 {
                        *sum.name_queries.entry(format!("LLMNR {q} ← {src}")).or_insert(0) += 1;
                    } else if sp == 5355 && data.len() > 3 && data[2] & 0x80 != 0 && !q.is_empty() {
                        sum.name_responders.entry(src.to_string()).or_default().insert(format!("LLMNR {q}"));
                    }
                    ("LLMNR".into(), format!("запрос {q}"))
                }
                (_, 137) | (137, _) => {
                    count("NBNS");
                    let q = dns_qname(data).map(|n| nbns_decode(&n)).unwrap_or_default();
                    if dp == 137 && !q.is_empty() && data.len() > 3 && data[2] & 0x80 == 0 {
                        *sum.name_queries.entry(format!("NBT-NS {q} ← {src}")).or_insert(0) += 1;
                    } else if !q.is_empty() && data.len() > 3 && data[2] & 0x80 != 0 {
                        sum.name_responders.entry(src.to_string()).or_default().insert(format!("NBT-NS {q}"));
                    }
                    ("NBNS".into(), format!("имя {q}"))
                }
                (_, 5353) | (5353, _) => {
                    count("mDNS");
                    let q = dns_qname(data).unwrap_or_default();
                    if dp == 5353 && data.len() > 3 && data[2] & 0x80 == 0 {
                        *sum.name_queries.entry(format!("mDNS {q} ← {src}")).or_insert(0) += 1;
                    }
                    ("mDNS".into(), q)
                }
                (_, 53) | (53, _) => {
                    count("DNS");
                    let q = dns_qname(data).unwrap_or_default();
                    let resp = data.len() > 3 && data[2] & 0x80 != 0;
                    ("DNS".into(), format!("{} {q}", if resp { "ответ" } else { "запрос" }))
                }
                (_, 1900) | (1900, _) => {
                    count("SSDP");
                    let first = String::from_utf8_lossy(data).lines().next().unwrap_or("").to_string();
                    ("SSDP".into(), first)
                }
                _ => {
                    count("UDP");
                    ("UDP".into(), format!("{sp} → {dp} ({} Б)", data.len()))
                }
            }
        }
        1 if l4.len() >= 8 && l4[0] == 5 => {
            count("ICMP");
            let gw = Ipv4Addr::new(l4[4], l4[5], l4[6], l4[7]);
            *sum.icmp_redirects.entry(format!("{src} → шлюз {gw}")).or_insert(0) += 1;
            ("ICMP".into(), format!("Redirect: предлагает шлюз {gw}"))
        }
        1 if !l4.is_empty() => {
            count("ICMP");
            let t = match l4[0] {
                0 => "echo reply",
                3 => "недоступен",
                8 => "echo request",
                11 => "TTL истёк",
                _ => "",
            };
            ("ICMP".into(), format!("тип {} {t}", l4[0]))
        }
        58 if !l4.is_empty() && l4[0] == 134 => {
            count("ICMPv6");
            *sum.ipv6_ra.entry(format!("{src} ({smac})")).or_insert(0) += 1;
            ("ICMPv6".into(), "тип 134 RA — объявление маршрутизатора".into())
        }
        58 if !l4.is_empty() => {
            count("ICMPv6");
            let t = match l4[0] {
                133 => "RS",
                134 => "RA",
                135 => "NS",
                136 => "NA",
                128 => "echo request",
                129 => "echo reply",
                _ => "",
            };
            ("ICMPv6".into(), format!("тип {} {t}", l4[0]))
        }
        p => {
            count("IP");
            (format!("IP/{p}"), String::new())
        }
    }
}

fn http_line(data: &[u8]) -> Option<String> {
    let methods: [&[u8]; 8] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"CONNECT ", b"HTTP/1."];
    if !methods.iter().any(|m| data.starts_with(m)) {
        return None;
    }
    let end = data.iter().position(|b| *b == b'\r' || *b == b'\n').unwrap_or(data.len().min(120));
    Some(String::from_utf8_lossy(&data[..end.min(160)]).into_owned())
}

/// Имя сервера (SNI) из TLS ClientHello.
pub fn tls_sni(d: &[u8]) -> Option<String> {
    if d.len() < 43 || d[0] != 0x16 || d[5] != 1 {
        return None;
    }
    let mut i = 5 + 4 + 2 + 32;
    let sid = *d.get(i)? as usize;
    i += 1 + sid;
    let cs = be16(d.get(i..i + 2)?, 0) as usize;
    i += 2 + cs;
    let comp = *d.get(i)? as usize;
    i += 1 + comp;
    let ext_len = be16(d.get(i..i + 2)?, 0) as usize;
    i += 2;
    let end = (i + ext_len).min(d.len());
    while i + 4 <= end {
        let ty = be16(d, i);
        let len = be16(d, i + 2) as usize;
        if ty == 0 {
            let e = d.get(i + 4..i + 4 + len)?;
            let n = be16(e.get(3..5)?, 0) as usize;
            return Some(String::from_utf8_lossy(e.get(5..5 + n)?).into_owned());
        }
        i += 4 + len;
    }
    None
}

fn dns_qname(data: &[u8]) -> Option<String> {
    if data.len() < 13 || be16(data, 4) == 0 {
        return None;
    }
    super::dnsproto::read_name(data, 12).ok().map(|(n, _)| n.trim_end_matches('.').to_string())
}

/// Имя NetBIOS из закодированной метки (CK… → ИМЯ).
fn nbns_decode(label: &str) -> String {
    let first = label.split('.').next().unwrap_or("");
    if first.len() != 32 {
        return first.to_string();
    }
    let b = first.as_bytes();
    let mut out = String::new();
    for i in 0..15 {
        let c = ((b[i * 2].wrapping_sub(b'A')) << 4) | (b[i * 2 + 1].wrapping_sub(b'A'));
        out.push(c as char);
    }
    out.trim_end().to_string()
}

fn parse_dhcp(d: &[u8], src: &str, smac: &str, sum: &mut Summary) -> String {
    if d.len() < 240 || d[236..240] != [99, 130, 83, 99] {
        return "DHCP (не разобран)".into();
    }
    let yiaddr = Ipv4Addr::new(d[16], d[17], d[18], d[19]);
    let mut i = 240;
    let (mut msg, mut router, mut dns, mut server) = (0u8, String::new(), String::new(), String::new());
    while i + 2 <= d.len() && d[i] != 255 {
        if d[i] == 0 {
            i += 1;
            continue;
        }
        let (code, len) = (d[i], d[i + 1] as usize);
        let v = d.get(i + 2..i + 2 + len).unwrap_or(&[]);
        let ips = || v.chunks(4).filter(|c| c.len() == 4).map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string()).collect::<Vec<_>>().join(", ");
        match code {
            53 if !v.is_empty() => msg = v[0],
            3 => router = ips(),
            6 => dns = ips(),
            54 => server = ips(),
            _ => {}
        }
        i += 2 + len;
    }
    let name = match msg {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        _ => "?",
    };
    if msg == 2 || msg == 5 || msg == 6 {
        let ip = if server.is_empty() { src.to_string() } else { server.clone() };
        match sum.dhcp.iter_mut().find(|x| x.ip == ip) {
            Some(x) => {
                x.messages += 1;
                if !yiaddr.is_unspecified() {
                    x.offered = yiaddr.to_string();
                }
            }
            None => sum.dhcp.push(DhcpServer {
                ip,
                mac: smac.to_string(),
                messages: 1,
                router: router.clone(),
                dns: dns.clone(),
                offered: if yiaddr.is_unspecified() { String::new() } else { yiaddr.to_string() },
            }),
        }
    }
    format!("{name}{}", if yiaddr.is_unspecified() { String::new() } else { format!(" {yiaddr}") })
}

fn upsert_neighbor(sum: &mut Summary, n: Neighbor) {
    match sum.neighbors.iter_mut().find(|x| x.protocol == n.protocol && x.mac == n.mac && x.port == n.port) {
        Some(x) => *x = n,
        None => sum.neighbors.push(n),
    }
}

pub fn parse_lldp(mut d: &[u8], smac: &str) -> Neighbor {
    let mut n = Neighbor {
        protocol: "LLDP".into(),
        mac: smac.to_string(),
        ..Default::default()
    };
    while d.len() >= 2 {
        let h = be16(d, 0);
        let (ty, len) = (h >> 9, (h & 0x1FF) as usize);
        let v = d.get(2..2 + len).unwrap_or(&[]);
        let text = |v: &[u8]| String::from_utf8_lossy(v).trim_matches('\0').to_string();
        match ty {
            0 => break,
            1 if !v.is_empty() => {
                if n.device.is_empty() {
                    n.device = if v[0] == 4 && v.len() == 7 { mac(&v[1..]) } else { text(&v[1..]) };
                }
            }
            2 if !v.is_empty() => n.port = if v[0] == 3 && v.len() == 7 { mac(&v[1..]) } else { text(&v[1..]) },
            4 => n.port_description = text(v),
            5 => n.device = text(v),
            6 => n.platform = text(v).lines().next().unwrap_or("").to_string(),
            8 if v.len() >= 7 && v[1] == 1 => n.mgmt = Ipv4Addr::new(v[2], v[3], v[4], v[5]).to_string(),
            127 if v.len() >= 6 && v[0..3] == [0x00, 0x80, 0xc2] && v[3] == 1 => n.vlan = be16(v, 4).to_string(),
            _ => {}
        }
        d = d.get(2 + len..).unwrap_or(&[]);
    }
    n
}

pub fn parse_cdp(d: &[u8], smac: &str) -> Neighbor {
    let mut n = Neighbor {
        protocol: "CDP".into(),
        mac: smac.to_string(),
        ..Default::default()
    };
    let mut i = 4;
    while i + 4 <= d.len() {
        let (ty, len) = (be16(d, i), be16(d, i + 2) as usize);
        if len < 4 {
            break;
        }
        let v = d.get(i + 4..i + len).unwrap_or(&[]);
        let text = String::from_utf8_lossy(v).trim_matches('\0').to_string();
        match ty {
            1 => n.device = text,
            3 => n.port = text,
            6 => n.platform = text,
            10 if v.len() >= 2 => n.vlan = be16(v, 0).to_string(),
            _ => {}
        }
        i += len;
    }
    n
}

// ---------------------------------------------------------------------------
// pcapng
// ---------------------------------------------------------------------------

fn block(ty: u32, body: &[u8]) -> Vec<u8> {
    let pad = (4 - body.len() % 4) % 4;
    let total = (12 + body.len() + pad) as u32;
    let mut b = ty.to_le_bytes().to_vec();
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(body);
    b.extend(std::iter::repeat_n(0u8, pad));
    b.extend_from_slice(&total.to_le_bytes());
    b
}

pub fn pcapng(packets: &[Raw], linktype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut shb = 0x1A2B_3C4Du32.to_le_bytes().to_vec();
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    out.extend(block(0x0A0D_0D0A, &shb));
    let mut idb = linktype.to_le_bytes().to_vec();
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&262_144u32.to_le_bytes());
    out.extend(block(1, &idb));
    for p in packets {
        let mut epb = 0u32.to_le_bytes().to_vec();
        epb.extend_from_slice(&((p.ts_us >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(p.ts_us as u32).to_le_bytes());
        epb.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&p.len.to_le_bytes());
        epb.extend_from_slice(&p.data);
        out.extend(block(6, &epb));
    }
    out
}

// ---------------------------------------------------------------------------
// Захват
// ---------------------------------------------------------------------------

/// Захват в отдельном потоке; события пачками раз в ~150 мс.
pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        c2.cancelled().await;
        stop2.store(true, Ordering::Relaxed);
    });
    let s2 = sink.clone();
    let res = tokio::task::spawn_blocking(move || capture_blocking(&cfg, &s2, &stop)).await;
    let msg = match res {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => {
            sink.send(Event::Log(e.clone()));
            e
        }
        Err(e) => e.to_string(),
    };
    sink.send(Event::Stopped(msg));
}

fn capture_blocking(cfg: &Config, sink: &Sink<Event>, stop: &AtomicBool) -> Result<String, String> {
    let pcap = Pcap::load()?;
    let dev = if cfg.device.is_empty() {
        pcap.devices()?
            .into_iter()
            .find(|d| !d.loopback && !d.addrs.is_empty())
            .map(|d| d.name)
            .ok_or("не найден сетевой интерфейс для захвата")?
    } else {
        cfg.device.clone()
    };
    let cdev = CString::new(dev.clone()).map_err(|e| e.to_string())?;
    let mut err = [0 as c_char; 256];
    // SAFETY: работа с дескриптором pcap по документированному API; закрывается в конце.
    unsafe {
        let h = (pcap.open_live)(cdev.as_ptr(), 262_144, cfg.promiscuous as c_int, 100, err.as_mut_ptr());
        if h.is_null() {
            let e = CStr::from_ptr(err.as_ptr()).to_string_lossy().into_owned();
            return Err(format!("{dev}: {e}{}", if e.contains("ermission") || e.contains("ccess") { " — нужны права администратора/root" } else { "" }));
        }
        let linktype = (pcap.datalink)(h);
        // Неблокирующий режим: в Linux таймаут чтения может не срабатывать без пакетов.
        (pcap.setnonblock)(h, 1, err.as_mut_ptr());
        if !cfg.filter.trim().is_empty() {
            let f = CString::new(cfg.filter.trim()).map_err(|e| e.to_string())?;
            let mut prog = BpfProgram { len: 0, insns: std::ptr::null_mut() };
            if (pcap.compile)(h, &mut prog, f.as_ptr(), 1, 0xFFFF_FFFF) != 0 {
                let e = CStr::from_ptr((pcap.geterr)(h)).to_string_lossy().into_owned();
                (pcap.close)(h);
                return Err(format!("фильтр: {e}"));
            }
            let rc = (pcap.setfilter)(h, &mut prog);
            (pcap.freecode)(&mut prog);
            if rc != 0 {
                let e = CStr::from_ptr((pcap.geterr)(h)).to_string_lossy().into_owned();
                (pcap.close)(h);
                return Err(format!("фильтр: {e}"));
            }
        }
        sink.send(Event::Started(linktype));
        let started = Instant::now();
        let mut n: u64 = 0;
        let mut batch = Vec::new();
        let mut raws = Vec::new();
        let mut last_flush = Instant::now();
        let mut first_ts: Option<f64> = None;
        let mut sum = Summary::default();
        let reason = loop {
            if stop.load(Ordering::Relaxed) {
                break "остановлено".to_string();
            }
            if cfg.seconds > 0 && started.elapsed() >= Duration::from_secs(cfg.seconds) {
                break format!("прошло {} с", cfg.seconds);
            }
            if cfg.max_packets > 0 && n >= cfg.max_packets {
                break format!("получено {n} пакетов");
            }
            let mut hdr: *mut PktHdr = std::ptr::null_mut();
            let mut data: *const u8 = std::ptr::null();
            let rc = (pcap.next_ex)(h, &mut hdr, &mut data);
            if rc == 1 && !hdr.is_null() {
                let hd = &*hdr;
                let bytes = std::slice::from_raw_parts(data, hd.caplen as usize);
                let ts = hd.ts.sec as f64 + hd.ts.usec as f64 / 1e6;
                let t0 = *first_ts.get_or_insert(ts);
                n += 1;
                let (src, dst, proto, info) = dissect(bytes, linktype, &mut sum);
                batch.push(Packet {
                    n,
                    t: ts - t0,
                    src,
                    dst,
                    proto,
                    len: hd.len,
                    info,
                });
                raws.push(Raw {
                    ts_us: (ts * 1e6) as u64,
                    len: hd.len,
                    data: bytes.to_vec(),
                });
            } else if rc < 0 {
                let e = CStr::from_ptr((pcap.geterr)(h)).to_string_lossy().into_owned();
                break format!("ошибка захвата: {e}");
            } else {
                std::thread::sleep(Duration::from_millis(5));
            }
            if last_flush.elapsed() >= Duration::from_millis(150) && !batch.is_empty() {
                sink.send(Event::Packets(std::mem::take(&mut batch), std::mem::take(&mut raws)));
                last_flush = Instant::now();
            }
        };
        if !batch.is_empty() {
            sink.send(Event::Packets(batch, raws));
        }
        (pcap.close)(h);
        Ok(reason)
    }
}

/// DHCP DISCOVER с отдельным (локально назначенным) MAC: серверы ответят OFFER,
/// которые видит захват. Так находятся посторонние DHCP-серверы.
pub async fn dhcp_discover() -> Result<(), String> {
    let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    s.set_broadcast(true).map_err(|e| e.to_string())?;
    let mut m = vec![0u8; 240];
    m[0] = 1;
    m[1] = 1;
    m[2] = 6;
    let mut xid = [0u8; 4];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut xid);
    m[4..8].copy_from_slice(&xid);
    m[10] = 0x80; // ответ широковещательно
    let mut chaddr = [0x02, 0x50, 0x53, 0, 0, 0];
    chaddr[3..].copy_from_slice(&xid[..3]);
    m[28..34].copy_from_slice(&chaddr);
    m[236..240].copy_from_slice(&[99, 130, 83, 99]);
    m.extend_from_slice(&[53, 1, 1, 55, 4, 1, 3, 6, 15, 255]);
    s.send_to(&m, "255.255.255.255:67").await.map_err(|e| format!("DHCP DISCOVER: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(et: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.extend_from_slice(&et.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn arp_conflict_detection() {
        let mut sum = Summary::default();
        let arp = |mac_last: u8| {
            let mut p = vec![0, 1, 8, 0, 6, 4, 0, 2];
            p.extend_from_slice(&[0, 0x11, 0x22, 0x33, 0x44, mac_last]);
            p.extend_from_slice(&[10, 0, 0, 1]);
            p.extend_from_slice(&[0; 6]);
            p.extend_from_slice(&[10, 0, 0, 5]);
            eth(0x0806, &p)
        };
        dissect(&arp(1), 1, &mut sum);
        dissect(&arp(2), 1, &mut sum);
        assert_eq!(sum.arp_conflicts().len(), 1);
    }

    #[test]
    fn lldp_neighbor() {
        let tlv = |ty: u16, v: &[u8]| {
            let mut b = ((ty << 9) | v.len() as u16).to_be_bytes().to_vec();
            b.extend_from_slice(v);
            b
        };
        let mut p = tlv(1, &[4, 0, 1, 2, 3, 4, 5]);
        p.extend(tlv(2, b"\x05Gi1/0/12"));
        p.extend(tlv(5, b"sw-floor2"));
        p.extend(tlv(127, &[0x00, 0x80, 0xc2, 1, 0, 120]));
        p.extend(tlv(0, &[]));
        let mut sum = Summary::default();
        let (_, _, proto, info) = dissect(&eth(0x88CC, &p), 1, &mut sum);
        assert_eq!(proto, "LLDP");
        assert!(info.contains("sw-floor2") && info.contains("Gi1/0/12") && info.contains("VLAN 120"), "{info}");
        assert_eq!(sum.neighbors[0].vlan, "120");
    }

    #[test]
    fn sni_and_dhcp() {
        let h = super::super::tlsaudit::client_hello(super::super::tlsaudit::TLS12, &[0xC02F], Some("intranet.corp.local"));
        assert_eq!(tls_sni(&h).as_deref(), Some("intranet.corp.local"));
        let mut d = vec![0u8; 240];
        d[0] = 2;
        d[16..20].copy_from_slice(&[10, 0, 0, 50]);
        d[236..240].copy_from_slice(&[99, 130, 83, 99]);
        d.extend_from_slice(&[53, 1, 2, 54, 4, 10, 0, 0, 1, 3, 4, 10, 0, 0, 1, 255]);
        let mut sum = Summary::default();
        let info = parse_dhcp(&d, "10.0.0.1", "aa:bb", &mut sum);
        assert_eq!(info, "OFFER 10.0.0.50");
        assert_eq!(sum.dhcp[0].ip, "10.0.0.1");
        assert_eq!(sum.dhcp[0].router, "10.0.0.1");
    }

    #[test]
    fn pcapng_layout() {
        let f = pcapng(&[Raw { ts_us: 1, len: 3, data: vec![1, 2, 3] }], 1);
        assert_eq!(&f[..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
        // Длина каждого блока кратна 4.
        assert_eq!(f.len() % 4, 0);
        assert_eq!(nbns_decode("FHEPFCELEHFCEPFFFACACACACACACAAA"), "WORKGROUP");
    }

    /// Захват на loopback (если есть libpcap и права).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_loopback() {
        if Pcap::load().is_err() || !crate::util::is_admin() {
            return;
        }
        let (sink, rx) = Sink::new(None);
        let cfg = Config {
            device: "lo".into(),
            filter: "udp port 39999".into(),
            seconds: 2,
            ..Default::default()
        };
        let h = tokio::spawn(run(cfg, sink, CancellationToken::new()));
        tokio::time::sleep(Duration::from_millis(500)).await;
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..3 {
            u.send_to(b"hello", "127.0.0.1:39999").unwrap();
        }
        h.await.unwrap();
        let n: usize = rx.try_iter().map(|e| if let Event::Packets(p, _) = e { p.len() } else { 0 }).sum();
        assert!(n >= 3, "пакетов: {n}");
    }
}
