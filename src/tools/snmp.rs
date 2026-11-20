//! SNMPv2c: обход таблиц коммутатора (GETBULK). Где воткнут узел: MAC → порт → VLAN
//! (BRIDGE-MIB / Q-BRIDGE-MIB), имена портов (IF-MIB), соседи LLDP.
//!
//! Порт считается магистральным (uplink), если за ним много MAC-адресов или виден
//! сосед LLDP — тогда узел «воткнут» не в него, а глубже.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::Sink;
use super::ad::{read_tlv, tlv};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Коммутаторы (адреса или имена).
    pub switches: String,
    pub community: String,
    pub timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            switches: String::new(),
            community: "public".into(),
            timeout_ms: 2000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdbEntry {
    pub mac: String,
    pub vlan: Option<u16>,
    pub port: String,
    pub port_alias: String,
    /// Сколько MAC-адресов видно за этим портом.
    pub macs_on_port: usize,
    pub uplink: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwitchReport {
    pub address: String,
    pub name: String,
    pub entries: Vec<FdbEntry>,
    /// Порт → имя соседа LLDP.
    pub neighbors: BTreeMap<String, String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub switches: Vec<SwitchReport>,
}

/// Где воткнут узел: (коммутатор, порт, VLAN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub switch: String,
    pub port: String,
    pub alias: String,
    pub vlan: Option<u16>,
}

impl Report {
    /// Порт доступа, за которым виден MAC: из всех коммутаторов берём порт с наименьшим
    /// числом MAC-адресов (магистральные пропускаем, если есть другие варианты).
    pub fn locate(&self, mac: &str) -> Option<Location> {
        let m = norm_mac(mac);
        let mut best: Option<(&SwitchReport, &FdbEntry)> = None;
        for sw in &self.switches {
            for e in sw.entries.iter().filter(|e| e.mac == m) {
                let better = match best {
                    None => true,
                    Some((_, b)) => (e.uplink, e.macs_on_port) < (b.uplink, b.macs_on_port),
                };
                if better {
                    best = Some((sw, e));
                }
            }
        }
        best.map(|(sw, e)| Location {
            switch: if sw.name.is_empty() { sw.address.clone() } else { format!("{} ({})", sw.name, sw.address) },
            port: e.port.clone(),
            alias: e.port_alias.clone(),
            vlan: e.vlan,
        })
    }
}

pub fn norm_mac(m: &str) -> String {
    let hex: String = m.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase();
    hex.as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(":")
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Switch(Box<SwitchReport>),
}

// ---------------------------------------------------------------------------
// Кодирование
// ---------------------------------------------------------------------------

pub fn parse_oid(s: &str) -> Vec<u32> {
    s.trim_start_matches('.').split('.').filter_map(|x| x.parse().ok()).collect()
}

fn encode_oid(oid: &[u32]) -> Vec<u8> {
    let mut out = vec![(oid[0] * 40 + oid.get(1).copied().unwrap_or(0)) as u8];
    for &n in &oid[2.min(oid.len())..] {
        let mut stack = vec![(n & 0x7F) as u8];
        let mut v = n >> 7;
        while v > 0 {
            stack.push((v & 0x7F) as u8 | 0x80);
            v >>= 7;
        }
        stack.reverse();
        out.extend(stack);
    }
    tlv(0x06, &out)
}

fn decode_oid(b: &[u8]) -> Vec<u32> {
    let Some(&first) = b.first() else { return Vec::new() };
    let mut out = vec![(first / 40) as u32, (first % 40) as u32];
    let mut v = 0u32;
    for &x in &b[1..] {
        v = (v << 7) | (x & 0x7F) as u32;
        if x & 0x80 == 0 {
            out.push(v);
            v = 0;
        }
    }
    out
}

fn int(v: i64) -> Vec<u8> {
    super::ad::der_int(v)
}

/// GETBULK (v2c): non-repeaters 0, max-repetitions `n`.
pub fn getbulk(community: &str, id: i32, oid: &[u32], n: i64) -> Vec<u8> {
    let mut vb = encode_oid(oid);
    vb.extend_from_slice(&[0x05, 0x00]);
    let vbl = tlv(0x30, &tlv(0x30, &vb));
    let mut pdu = int(id as i64);
    pdu.extend(int(0));
    pdu.extend(int(n));
    pdu.extend(vbl);
    let mut msg = int(1);
    msg.extend(tlv(0x04, community.as_bytes()));
    msg.extend(tlv(0xA5, &pdu));
    tlv(0x30, &msg)
}

pub fn get(community: &str, id: i32, oid: &[u32]) -> Vec<u8> {
    let mut vb = encode_oid(oid);
    vb.extend_from_slice(&[0x05, 0x00]);
    let vbl = tlv(0x30, &tlv(0x30, &vb));
    let mut pdu = int(id as i64);
    pdu.extend(int(0));
    pdu.extend(int(0));
    pdu.extend(vbl);
    let mut msg = int(1);
    msg.extend(tlv(0x04, community.as_bytes()));
    msg.extend(tlv(0xA0, &pdu));
    tlv(0x30, &msg)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Oid(Vec<u32>),
    Ip(Ipv4Addr),
    /// noSuchObject / noSuchInstance / endOfMibView.
    End,
    Null,
}

impl Value {
    pub fn text(&self) -> String {
        match self {
            Value::Int(v) => v.to_string(),
            Value::Bytes(b) => String::from_utf8_lossy(b).trim_end_matches('\0').to_string(),
            Value::Oid(o) => o.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("."),
            Value::Ip(i) => i.to_string(),
            Value::End | Value::Null => String::new(),
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(*v),
            _ => None,
        }
    }
}

fn decode_int(b: &[u8]) -> i64 {
    let mut v: i64 = if b.first().is_some_and(|x| x & 0x80 != 0) { -1 } else { 0 };
    for &x in b {
        v = (v << 8) | x as i64;
    }
    v
}

/// Пары (OID, значение).
pub type VarBinds = Vec<(Vec<u32>, Value)>;

/// Разбор ответа: (request-id, error-status, [(OID, значение)]).
pub fn parse_response(data: &[u8]) -> Option<(i64, i64, VarBinds)> {
    let (_, msg, _) = read_tlv(data)?;
    let (_, _, rest) = read_tlv(msg)?; // version
    let (_, _, rest) = read_tlv(rest)?; // community
    let (tag, pdu, _) = read_tlv(rest)?;
    if tag != 0xA2 {
        return None;
    }
    let (_, id, rest) = read_tlv(pdu)?;
    let (_, err, rest) = read_tlv(rest)?;
    let (_, _, rest) = read_tlv(rest)?; // error-index
    let (_, mut vbl, _) = read_tlv(rest)?;
    let mut out = Vec::new();
    while !vbl.is_empty() {
        let (_, vb, next) = read_tlv(vbl)?;
        vbl = next;
        let (_, oid, rest) = read_tlv(vb)?;
        let (t, val, _) = read_tlv(rest)?;
        let v = match t {
            0x02 | 0x41 | 0x42 | 0x43 | 0x46 => Value::Int(decode_int(val)),
            0x04 => Value::Bytes(val.to_vec()),
            0x06 => Value::Oid(decode_oid(val)),
            0x40 if val.len() == 4 => Value::Ip(Ipv4Addr::new(val[0], val[1], val[2], val[3])),
            0x80..=0x82 => Value::End,
            _ => Value::Null,
        };
        out.push((decode_oid(oid), v));
    }
    Some((decode_int(id), decode_int(err), out))
}

// ---------------------------------------------------------------------------
// Обход
// ---------------------------------------------------------------------------

struct Client {
    sock: UdpSocket,
    community: String,
    timeout: Duration,
    id: i32,
}

impl Client {
    async fn new(addr: &str, community: &str, timeout: Duration) -> Result<Self, String> {
        let target = super::resolve_v4(addr, timeout).await?;
        let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
        sock.connect((target, 161)).await.map_err(|e| e.to_string())?;
        Ok(Self {
            sock,
            community: community.into(),
            timeout,
            id: (super::dns::rand_id() as i32) << 8,
        })
    }

    async fn exchange(&mut self, req: Vec<u8>, id: i32) -> Result<Vec<(Vec<u32>, Value)>, String> {
        let mut buf = vec![0u8; 65535];
        for _ in 0..2 {
            self.sock.send(&req).await.map_err(|e| e.to_string())?;
            let deadline = tokio::time::Instant::now() + self.timeout;
            loop {
                match tokio::time::timeout_at(deadline, self.sock.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        if let Some((rid, err, vbs)) = parse_response(&buf[..n])
                            && rid == id as i64
                        {
                            if err != 0 {
                                return Err(format!("ошибка SNMP {err}"));
                            }
                            return Ok(vbs);
                        }
                    }
                    Ok(Err(e)) => return Err(e.to_string()),
                    Err(_) => break,
                }
            }
        }
        Err("нет ответа (проверьте community и доступ по SNMP)".into())
    }

    async fn get(&mut self, oid: &[u32]) -> Result<Value, String> {
        self.id += 1;
        let id = self.id;
        let r = self.exchange(get(&self.community, id, oid), id).await?;
        Ok(r.into_iter().next().map(|x| x.1).unwrap_or(Value::Null))
    }

    /// Обход поддерева: (суффикс OID после корня, значение).
    async fn walk(&mut self, root: &[u32], limit: usize) -> Result<Vec<(Vec<u32>, Value)>, String> {
        let mut out = Vec::new();
        let mut cur = root.to_vec();
        while out.len() < limit {
            self.id += 1;
            let id = self.id;
            let vbs = self.exchange(getbulk(&self.community, id, &cur, 40), id).await?;
            if vbs.is_empty() {
                break;
            }
            let mut done = false;
            for (oid, v) in vbs {
                if !oid.starts_with(root) || v == Value::End || oid <= cur {
                    done = true;
                    break;
                }
                cur = oid.clone();
                out.push((oid[root.len()..].to_vec(), v));
            }
            if done {
                break;
            }
        }
        Ok(out)
    }
}

const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
const BASE_PORT_IFINDEX: &str = "1.3.6.1.2.1.17.1.4.1.2";
const IF_NAME: &str = "1.3.6.1.2.1.31.1.1.1.1";
const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
const IF_ALIAS: &str = "1.3.6.1.2.1.31.1.1.1.18";
const Q_FDB_PORT: &str = "1.3.6.1.2.1.17.7.1.2.2.1.2";
const FDB_PORT: &str = "1.3.6.1.2.1.17.4.3.1.2";
const LLDP_REM_SYSNAME: &str = "1.0.8802.1.1.2.1.4.1.1.9";
/// Больше стольких MAC за портом — порт магистральный.
const UPLINK_MACS: usize = 4;

fn mac_of(idx: &[u32]) -> Option<String> {
    (idx.len() == 6).then(|| idx.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"))
}

pub async fn query_switch(addr: &str, community: &str, timeout: Duration) -> SwitchReport {
    let mut rep = SwitchReport {
        address: addr.to_string(),
        ..Default::default()
    };
    let mut c = match Client::new(addr, community, timeout).await {
        Ok(c) => c,
        Err(e) => {
            rep.error = Some(e);
            return rep;
        }
    };
    match c.get(&parse_oid(SYS_NAME)).await {
        Ok(v) => rep.name = v.text(),
        Err(e) => {
            rep.error = Some(e);
            return rep;
        }
    }
    let port_if: BTreeMap<u32, i64> = c
        .walk(&parse_oid(BASE_PORT_IFINDEX), 4096)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(i, v)| Some((*i.first()?, v.as_int()?)))
        .collect();
    let mut names: BTreeMap<i64, String> = c
        .walk(&parse_oid(IF_NAME), 4096)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(i, v)| Some((*i.first()? as i64, v.text())))
        .collect();
    if names.is_empty() {
        names = c
            .walk(&parse_oid(IF_DESCR), 4096)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(i, v)| Some((*i.first()? as i64, v.text())))
            .collect();
    }
    let aliases: BTreeMap<i64, String> = c
        .walk(&parse_oid(IF_ALIAS), 4096)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(i, v)| Some((*i.first()? as i64, v.text())))
        .collect();
    // (MAC, VLAN, порт моста).
    let mut fdb: Vec<(String, Option<u16>, u32)> = c
        .walk(&parse_oid(Q_FDB_PORT), 50_000)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(i, v)| {
            let (vlan, mac) = i.split_first()?;
            Some((mac_of(mac)?, Some(*vlan as u16), v.as_int()? as u32))
        })
        .collect();
    if fdb.is_empty() {
        fdb = c
            .walk(&parse_oid(FDB_PORT), 50_000)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(i, v)| Some((mac_of(&i)?, None, v.as_int()? as u32)))
            .collect();
    }
    // Соседи LLDP: индекс timeMark.localPort.index.
    let mut lldp_ports = std::collections::BTreeSet::new();
    for (i, v) in c.walk(&parse_oid(LLDP_REM_SYSNAME), 1024).await.unwrap_or_default() {
        if let Some(lp) = i.get(1) {
            lldp_ports.insert(*lp);
            let port_name = port_if.get(lp).and_then(|ifi| names.get(ifi)).cloned().unwrap_or_else(|| lp.to_string());
            rep.neighbors.insert(port_name, v.text());
        }
    }
    let mut per_port: BTreeMap<u32, usize> = BTreeMap::new();
    for (_, _, p) in &fdb {
        *per_port.entry(*p).or_insert(0) += 1;
    }
    for (mac, vlan, p) in fdb {
        if p == 0 {
            continue;
        }
        let ifi = port_if.get(&p).copied().unwrap_or(p as i64);
        let n = per_port.get(&p).copied().unwrap_or(0);
        rep.entries.push(FdbEntry {
            mac,
            vlan,
            port: names.get(&ifi).cloned().unwrap_or_else(|| format!("порт {p}")),
            port_alias: aliases.get(&ifi).cloned().unwrap_or_default(),
            macs_on_port: n,
            uplink: n > UPLINK_MACS || lldp_ports.contains(&p),
        });
    }
    if rep.entries.is_empty() && rep.error.is_none() {
        rep.error = Some("таблица MAC-адресов пуста или недоступна по этому community".into());
    }
    rep
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let list = super::split_list(&cfg.switches);
    if list.is_empty() {
        return sink.send(Event::Log("укажите коммутаторы".into()));
    }
    let timeout = Duration::from_millis(cfg.timeout_ms.max(300));
    super::for_each_limited(list, 8, &cancel, |sw| {
        let (sink, community) = (sink.clone(), cfg.community.clone());
        async move {
            let r = query_switch(&sw, &community, timeout).await;
            sink.send(Event::Switch(Box::new(r)));
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip() {
        let o = parse_oid("1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.80.86.200.1.2");
        let enc = encode_oid(&o);
        let (_, body, _) = read_tlv(&enc).unwrap();
        assert_eq!(decode_oid(body), o);
    }

    /// Ответ коммутатора, собранный вручную: sysName и две записи FDB.
    #[test]
    fn parse_bulk_response() {
        let vb = |oid: &str, v: Vec<u8>| {
            let mut x = encode_oid(&parse_oid(oid));
            x.extend(v);
            tlv(0x30, &x)
        };
        let mut vbl = vb("1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.80.86.200.1.2", int(5));
        vbl.extend(vb("1.3.6.1.2.1.1.5.0", tlv(0x04, b"sw-floor3")));
        vbl.extend(vb("1.3.6.1.2.1.2", vec![0x82, 0x00]));
        let mut pdu = int(77);
        pdu.extend(int(0));
        pdu.extend(int(0));
        pdu.extend(tlv(0x30, &vbl));
        let mut msg = int(1);
        msg.extend(tlv(0x04, b"public"));
        msg.extend(tlv(0xA2, &pdu));
        let (id, err, vbs) = parse_response(&tlv(0x30, &msg)).unwrap();
        assert_eq!((id, err, vbs.len()), (77, 0, 3));
        assert_eq!(vbs[0].1, Value::Int(5));
        assert_eq!(mac_of(&vbs[0].0[14..]).unwrap(), "00:50:56:c8:01:02");
        assert_eq!(vbs[1].1.text(), "sw-floor3");
        assert_eq!(vbs[2].1, Value::End);
    }

    #[test]
    fn locate_prefers_access_port() {
        let e = |port: &str, n: usize, uplink: bool| FdbEntry {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vlan: Some(10),
            port: port.into(),
            port_alias: String::new(),
            macs_on_port: n,
            uplink,
        };
        let r = Report {
            switches: vec![
                SwitchReport { address: "10.0.0.1".into(), name: "core".into(), entries: vec![e("Te1/0/1", 300, true)], ..Default::default() },
                SwitchReport { address: "10.0.0.2".into(), name: "floor3".into(), entries: vec![e("Gi1/0/12", 1, false)], ..Default::default() },
            ],
        };
        let l = r.locate("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!((l.port.as_str(), l.vlan), ("Gi1/0/12", Some(10)));
        assert!(l.switch.contains("floor3"));
    }
}
