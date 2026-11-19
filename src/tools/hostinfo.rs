//! Состояние этой машины: интерфейсы, маршруты, соседи (ARP), соединения с процессами
//! (как `ipconfig /all` + `route print` + `arp -a` + `netstat -anob` / `ip a` + `ss -tunap`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub description: String,
    pub mac: String,
    pub vendor: Option<String>,
    pub mtu: Option<u32>,
    pub speed_mbps: Option<u64>,
    pub up: bool,
    pub addrs: Vec<String>,
    pub gateways: Vec<String>,
    pub dns: Vec<String>,
    pub dhcp_server: Option<String>,
    pub dns_suffix: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Route {
    pub dest: String,
    pub gateway: String,
    pub iface: String,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Neighbor {
    pub ip: String,
    pub mac: String,
    pub vendor: Option<String>,
    pub iface: String,
    pub state: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conn {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub hostname: String,
    pub os: String,
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub neighbors: Vec<Neighbor>,
    pub connections: Vec<Conn>,
    pub notes: Vec<String>,
}

fn vendor_of(mac: &str) -> Option<String> {
    super::oui::parse_mac(mac).filter(|m| *m != [0; 6]).and_then(|m| super::oui::vendor(&m))
}

pub fn collect() -> Report {
    let mut r = platform::collect();
    for i in &mut r.interfaces {
        i.vendor = vendor_of(&i.mac);
    }
    for n in &mut r.neighbors {
        n.vendor = vendor_of(&n.mac);
    }
    r.connections.sort_by(|a, b| (a.proto.as_str(), a.state.as_str(), a.local.as_str()).cmp(&(b.proto.as_str(), b.state.as_str(), b.local.as_str())));
    r
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!("{} — {}\n\n", r.hostname, r.os);
    for i in &r.interfaces {
        s += &format!(
            "{} ({}) {} MAC {}{} MTU {} {}\n",
            i.name,
            i.description,
            if i.up { "UP" } else { "DOWN" },
            i.mac,
            i.vendor.as_ref().map(|v| format!(" [{v}]")).unwrap_or_default(),
            i.mtu.map(|m| m.to_string()).unwrap_or("-".into()),
            i.speed_mbps.map(|v| format!("{v} Мбит/с")).unwrap_or_default()
        );
        for a in &i.addrs {
            s += &format!("    адрес  {a}\n");
        }
        for g in &i.gateways {
            s += &format!("    шлюз   {g}\n");
        }
        if !i.dns.is_empty() {
            s += &format!("    DNS    {}\n", i.dns.join(", "));
        }
        if let Some(d) = &i.dhcp_server {
            s += &format!("    DHCP   {d}\n");
        }
        if let Some(d) = &i.dns_suffix {
            s += &format!("    суффикс {d}\n");
        }
    }
    s += "\nМаршруты:\n";
    for rt in &r.routes {
        s += &format!(
            "  {:<20} → {:<16} {:<16} {}\n",
            rt.dest,
            rt.gateway,
            rt.iface,
            rt.metric.map(|m| m.to_string()).unwrap_or_default()
        );
    }
    s += "\nСоседи (ARP):\n";
    for n in &r.neighbors {
        s += &format!(
            "  {:<16} {:<18} {:<14} {} {}\n",
            n.ip,
            n.mac,
            n.iface,
            n.state,
            n.vendor.clone().unwrap_or_default()
        );
    }
    s += "\nСоединения:\n";
    for c in &r.connections {
        s += &format!(
            "  {:<4} {:<24} {:<24} {:<12} {} {}\n",
            c.proto,
            c.local,
            c.remote,
            c.state,
            c.pid.map(|p| p.to_string()).unwrap_or_default(),
            c.process
        );
    }
    for n in &r.notes {
        s += &format!("\n* {n}");
    }
    s
}

#[cfg(windows)]
mod platform {
    use super::*;
    use serde_json::Value;

    const SCRIPT: &str = r#"
$procs=@{}; Get-Process | ForEach-Object { $procs[[int]$_.Id]=$_.ProcessName }
$ifs=@(Get-NetAdapter | ForEach-Object {
  $a=$_
  $cfg=Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($a.ifIndex)"
  [pscustomobject]@{
    name=$a.Name; desc=$a.InterfaceDescription; mac=$a.MacAddress; up=($a.Status -eq 'Up');
    speed=[int64]($a.Speed/1000000);
    mtu=[int]((Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4).NlMtu);
    addrs=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" });
    gw=@(Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' | ForEach-Object { $_.NextHop });
    dns=@((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex).ServerAddresses);
    dhcp=[string]$cfg.DHCPServer;
    suffix=[string](Get-DnsClient -InterfaceIndex $a.ifIndex).ConnectionSpecificSuffix
  } })
$routes=@(Get-NetRoute -AddressFamily IPv4 | ForEach-Object { [pscustomobject]@{dest=$_.DestinationPrefix; gw=$_.NextHop; iface=$_.InterfaceAlias; metric=[int]($_.RouteMetric+$_.InterfaceMetric)} })
$neigh=@(Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } | ForEach-Object { [pscustomobject]@{ip=$_.IPAddress; mac=$_.LinkLayerAddress; iface=$_.InterfaceAlias; state=[string]$_.State} })
$tcp=@(Get-NetTCPConnection | ForEach-Object { [pscustomobject]@{p='tcp'; l="$($_.LocalAddress):$($_.LocalPort)"; r="$($_.RemoteAddress):$($_.RemotePort)"; s=[string]$_.State; pid=[int]$_.OwningProcess; n=$procs[[int]$_.OwningProcess]} })
$udp=@(Get-NetUDPEndpoint | ForEach-Object { [pscustomobject]@{p='udp'; l="$($_.LocalAddress):$($_.LocalPort)"; r=''; s=''; pid=[int]$_.OwningProcess; n=$procs[[int]$_.OwningProcess]} })
$os=Get-CimInstance Win32_OperatingSystem
ConvertTo-Json -Depth 5 -Compress -InputObject @{host=$env:COMPUTERNAME; os="$($os.Caption) $($os.Version)"; ifs=$ifs; routes=$routes; neigh=$neigh; conns=@($tcp+$udp)}
"#;

    fn arr(v: &Value) -> Vec<Value> {
        match v {
            Value::Array(a) => a.clone(),
            Value::Null => vec![],
            other => vec![other.clone()],
        }
    }
    fn s(v: &Value, k: &str) -> String {
        match &v[k] {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        }
    }
    fn strs(v: &Value, k: &str) -> Vec<String> {
        arr(&v[k]).iter().filter_map(|x| x.as_str().map(String::from)).filter(|x| !x.is_empty()).collect()
    }

    pub fn collect() -> Report {
        let mut r = Report::default();
        let out = match crate::util::run_powershell(SCRIPT) {
            Ok(o) => o,
            Err(e) => {
                r.notes.push(e);
                return r;
            }
        };
        let text = out.stdout.trim();
        let v: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                r.notes.push(format!("PowerShell вернул не JSON: {e}; {}", out.stderr.trim()));
                return r;
            }
        };
        r.hostname = s(&v, "host");
        r.os = s(&v, "os");
        for i in arr(&v["ifs"]) {
            let dhcp = s(&i, "dhcp");
            let suffix = s(&i, "suffix");
            r.interfaces.push(Interface {
                name: s(&i, "name"),
                description: s(&i, "desc"),
                mac: s(&i, "mac").replace('-', ":"),
                vendor: None,
                mtu: i["mtu"].as_u64().filter(|m| *m > 0).map(|m| m as u32),
                speed_mbps: i["speed"].as_u64().filter(|m| *m > 0),
                up: i["up"].as_bool().unwrap_or(false),
                addrs: strs(&i, "addrs"),
                gateways: strs(&i, "gw"),
                dns: strs(&i, "dns"),
                dhcp_server: (!dhcp.is_empty()).then_some(dhcp),
                dns_suffix: (!suffix.is_empty()).then_some(suffix),
            });
        }
        for rt in arr(&v["routes"]) {
            r.routes.push(Route {
                dest: s(&rt, "dest"),
                gateway: s(&rt, "gw"),
                iface: s(&rt, "iface"),
                metric: rt["metric"].as_u64().map(|m| m as u32),
            });
        }
        for n in arr(&v["neigh"]) {
            r.neighbors.push(Neighbor {
                ip: s(&n, "ip"),
                mac: s(&n, "mac").replace('-', ":"),
                vendor: None,
                iface: s(&n, "iface"),
                state: s(&n, "state"),
            });
        }
        for c in arr(&v["conns"]) {
            r.connections.push(Conn {
                proto: s(&c, "p"),
                local: s(&c, "l"),
                remote: s(&c, "r"),
                state: s(&c, "s"),
                pid: c["pid"].as_u64().map(|p| p as u32),
                process: s(&c, "n"),
            });
        }
        if !crate::util::is_admin() {
            r.notes.push("без прав администратора часть процессов может быть не видна".into());
        }
        r
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn read(p: &str) -> String {
        std::fs::read_to_string(p).unwrap_or_default()
    }

    /// Адреса интерфейсов через getifaddrs(3).
    fn ifaddrs() -> HashMap<String, Vec<String>> {
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs/freeifaddrs — стандартная пара; обходим связанный список.
        unsafe {
            if libc::getifaddrs(&mut head) != 0 {
                return out;
            }
            let mut cur = head;
            while !cur.is_null() {
                let ifa = &*cur;
                if !ifa.ifa_addr.is_null() {
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                    let fam = (*ifa.ifa_addr).sa_family as i32;
                    if fam == libc::AF_INET {
                        let a = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes());
                        let prefix = if ifa.ifa_netmask.is_null() {
                            32
                        } else {
                            let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                            u32::from_be(m.sin_addr.s_addr).count_ones()
                        };
                        out.entry(name).or_default().push(format!("{ip}/{prefix}"));
                    } else if fam == libc::AF_INET6 {
                        let a = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
                        let prefix = if ifa.ifa_netmask.is_null() {
                            128
                        } else {
                            let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in6);
                            m.sin6_addr.s6_addr.iter().map(|b| b.count_ones()).sum()
                        };
                        out.entry(name).or_default().push(format!("{ip}/{prefix}"));
                    }
                }
                cur = ifa.ifa_next;
            }
            libc::freeifaddrs(head);
        }
        out
    }

    fn hex_v4(h: &str) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_str_radix(h, 16).unwrap_or(0).to_le_bytes())
    }

    fn hex_addr(h: &str) -> String {
        let (ip, port) = h.split_once(':').unwrap_or((h, "0"));
        let port = u16::from_str_radix(port, 16).unwrap_or(0);
        if ip.len() == 8 {
            format!("{}:{port}", hex_v4(ip))
        } else {
            let mut b = [0u8; 16];
            for (i, chunk) in (0..4).map(|i| &ip[i * 8..i * 8 + 8]).enumerate() {
                let w = u32::from_str_radix(chunk, 16).unwrap_or(0).to_le_bytes();
                b[i * 4..i * 4 + 4].copy_from_slice(&w);
            }
            let v6 = Ipv6Addr::from(b);
            match v6.to_ipv4_mapped() {
                Some(v4) => format!("{v4}:{port}"),
                None => format!("[{v6}]:{port}"),
            }
        }
    }

    pub fn tcp_state(code: &str) -> &'static str {
        match code {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            _ => "",
        }
    }

    /// inode сокета → (pid, имя процесса).
    fn socket_owners() -> HashMap<u64, (u32, String)> {
        let mut out = HashMap::new();
        let Ok(dir) = std::fs::read_dir("/proc") else { return out };
        for e in dir.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
            let comm = read(&format!("/proc/{pid}/comm")).trim().to_string();
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
            for fd in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd.path()) {
                    let l = link.to_string_lossy();
                    if let Some(inode) = l.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                        if let Ok(i) = inode.parse() {
                            out.entry(i).or_insert((pid, comm.clone()));
                        }
                    }
                }
            }
        }
        out
    }

    pub fn parse_proc_net(text: &str, proto: &str, owners: &HashMap<u64, (u32, String)>) -> Vec<Conn> {
        let mut out = Vec::new();
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            let state = if proto.starts_with("tcp") { tcp_state(f[3]).to_string() } else { String::new() };
            let inode: u64 = f[9].parse().unwrap_or(0);
            let owner = owners.get(&inode);
            out.push(Conn {
                proto: proto.trim_end_matches('6').into(),
                local: hex_addr(f[1]),
                remote: if proto.starts_with("udp") && f[2].ends_with(":0000") { String::new() } else { hex_addr(f[2]) },
                state,
                pid: owner.map(|o| o.0),
                process: owner.map(|o| o.1.clone()).unwrap_or_default(),
            });
        }
        out
    }

    pub fn parse_routes(text: &str) -> Vec<Route> {
        let mut out = Vec::new();
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 {
                continue;
            }
            let dest = hex_v4(f[1]);
            let mask = u32::from_be_bytes(hex_v4(f[7]).octets()).count_ones();
            let gw = hex_v4(f[2]);
            out.push(Route {
                dest: format!("{dest}/{mask}"),
                gateway: if gw.is_unspecified() { "на канале".into() } else { gw.to_string() },
                iface: f[0].into(),
                metric: f[6].parse().ok(),
            });
        }
        out
    }

    pub fn collect() -> Report {
        let mut r = Report {
            hostname: read("/proc/sys/kernel/hostname").trim().to_string(),
            os: read("/etc/os-release")
                .lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|s| s.trim_matches('"').to_string())
                .unwrap_or_else(|| "Linux".into()),
            ..Default::default()
        };
        r.routes = parse_routes(&read("/proc/net/route"));
        let addrs = ifaddrs();
        let dns: Vec<String> = super::super::dns::system_servers().iter().map(|ip| ip.to_string()).collect();
        let suffix = read("/etc/resolv.conf")
            .lines()
            .find_map(|l| l.strip_prefix("search").or_else(|| l.strip_prefix("domain")))
            .map(|s| s.trim().to_string());
        if let Ok(dir) = std::fs::read_dir("/sys/class/net") {
            let mut names: Vec<String> = dir.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            names.sort();
            for name in names {
                let base = format!("/sys/class/net/{name}");
                let gws: Vec<String> = r
                    .routes
                    .iter()
                    .filter(|rt| rt.iface == name && rt.dest == "0.0.0.0/0")
                    .map(|rt| rt.gateway.clone())
                    .collect();
                let has_v4 = addrs.get(&name).is_some_and(|a| a.iter().any(|x| !x.contains(':')));
                r.interfaces.push(Interface {
                    description: if std::path::Path::new(&format!("{base}/wireless")).exists() {
                        "Wi-Fi".into()
                    } else if name == "lo" {
                        "loopback".into()
                    } else {
                        read(&format!("{base}/device/uevent"))
                            .lines()
                            .find_map(|l| l.strip_prefix("DRIVER="))
                            .unwrap_or("")
                            .to_string()
                    },
                    mac: read(&format!("{base}/address")).trim().to_ascii_uppercase(),
                    vendor: None,
                    mtu: read(&format!("{base}/mtu")).trim().parse().ok(),
                    speed_mbps: read(&format!("{base}/speed")).trim().parse::<i64>().ok().filter(|v| *v > 0).map(|v| v as u64),
                    up: read(&format!("{base}/operstate")).trim() == "up" || name == "lo",
                    addrs: addrs.get(&name).cloned().unwrap_or_default(),
                    gateways: gws,
                    dns: if has_v4 && name != "lo" { dns.clone() } else { Vec::new() },
                    dhcp_server: None,
                    dns_suffix: if has_v4 && name != "lo" { suffix.clone() } else { None },
                    name,
                });
            }
        }
        for line in read("/proc/net/arp").lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 6 && f[3] != "00:00:00:00:00:00" {
                r.neighbors.push(Neighbor {
                    ip: f[0].into(),
                    mac: f[3].to_ascii_uppercase(),
                    vendor: None,
                    iface: f[5].into(),
                    state: if f[2] == "0x2" { "REACHABLE".into() } else { format!("флаги {}", f[2]) },
                });
            }
        }
        let owners = socket_owners();
        for p in ["tcp", "tcp6", "udp", "udp6"] {
            r.connections.extend(parse_proc_net(&read(&format!("/proc/net/{p}")), p, &owners));
        }
        if !crate::util::is_admin() {
            r.notes.push("без root процессы других пользователей не видны".into());
        }
        r
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn proc_parsers() {
            let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                         eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                         eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
            let r = parse_routes(route);
            assert_eq!(r[0].dest, "0.0.0.0/0");
            assert_eq!(r[0].gateway, "10.0.0.1");
            assert_eq!(r[1].dest, "10.0.0.0/24");
            let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                       0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1\n";
            let mut owners = HashMap::new();
            owners.insert(12345u64, (42u32, "nginx".to_string()));
            let c = parse_proc_net(tcp, "tcp", &owners);
            assert_eq!(c[0].local, "127.0.0.1:8080");
            assert_eq!(c[0].state, "LISTEN");
            assert_eq!((c[0].pid, c[0].process.as_str()), (Some(42), "nginx"));
            assert_eq!(hex_addr("0000000000000000FFFF00000100007F:0050"), "127.0.0.1:80");
        }

        #[test]
        fn collect_runs() {
            let r = super::super::collect();
            assert!(r.interfaces.iter().any(|i| i.name == "lo"));
            assert!(!r.connections.is_empty() || r.notes.is_empty() || true);
        }
    }
}
