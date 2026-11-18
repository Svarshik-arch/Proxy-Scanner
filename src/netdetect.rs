//! Автоопределение сетевых параметров рабочей станции:
//! source-ip, шлюз, адаптер Npcap (`\Device\NPF_{GUID}`), MAC шлюза.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;

use serde_json::Value;

use crate::util::{run_cmd, run_powershell};

/// Интерфейс из вывода `masscan --iflist` либо построенный по данным PowerShell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceEntry {
    /// Имя устройства, например `\Device\NPF_{4D36E972-...}`.
    pub device: String,
    /// Человекочитаемое описание.
    pub description: String,
}

impl IfaceEntry {
    pub fn label(&self) -> String {
        if self.description.is_empty() {
            self.device.clone()
        } else {
            format!("{} — {}", self.description, self.device)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AdapterInfo {
    pub name: String,
    pub description: String,
    pub if_index: i64,
    pub guid: String, // в фигурных скобках, верхний регистр
}

impl AdapterInfo {
    /// Имя устройства для `masscan --adapter`: в Windows — `\Device\NPF_{GUID}`,
    /// в Linux — имя интерфейса (`eth0`).
    pub fn npf_device(&self) -> String {
        if self.guid.is_empty() {
            self.name.clone()
        } else {
            format!("\\Device\\NPF_{}", self.guid)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetDetect {
    pub source_ip: Option<Ipv4Addr>,
    pub prefix_len: Option<u8>,
    pub router_ip: Option<Ipv4Addr>,
    pub router_mac: Option<String>,
    /// Адаптер, которому принадлежит source-ip.
    pub adapter: Option<AdapterInfo>,
    /// Устройство Npcap, вычисленное по GUID адаптера.
    pub npf_device: Option<String>,
    /// Все интерфейсы для выпадающего списка.
    pub ifaces: Vec<IfaceEntry>,
    /// Индекс автоопределённого интерфейса в `ifaces`.
    pub selected_iface: Option<usize>,
    /// Журнал шагов определения.
    pub log: Vec<String>,
}

/// source-ip: «подключаем» UDP-сокет к адресу целевой сети и читаем локальный адрес.
/// Пакеты при этом не отправляются — ОС лишь выбирает маршрут.
pub fn detect_source_ip(target: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|e| format!("bind: {e}"))?;
    sock.connect(SocketAddr::from((target, 9)))
        .map_err(|e| format!("нет маршрута к {target}: {e}"))?;
    match sock.local_addr().map_err(|e| e.to_string())? {
        SocketAddr::V4(a) if !a.ip().is_unspecified() => Ok(*a.ip()),
        other => Err(format!("неожиданный локальный адрес: {other}")),
    }
}

// ---------------------------------------------------------------------------
// PowerShell: маршруты, адреса, адаптеры
// ---------------------------------------------------------------------------

const PS_NET_SCRIPT: &str = "\
$r=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | Select-Object ifIndex,NextHop,RouteMetric,InterfaceMetric);\
$a=@(Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,InterfaceIndex,InterfaceAlias,PrefixLength);\
$n=@(Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,ifIndex,InterfaceGuid);\
ConvertTo-Json -Compress -Depth 4 -InputObject @{routes=$r;addrs=$a;adapters=$n}";

#[derive(Debug, Clone, Default)]
pub struct PsRoute {
    pub if_index: i64,
    pub next_hop: String,
    pub metric: i64,
}

#[derive(Debug, Clone, Default)]
pub struct PsAddr {
    pub ip: String,
    pub if_index: i64,
    pub alias: String,
    pub prefix: u8,
}

#[derive(Debug, Clone, Default)]
pub struct PsNet {
    pub routes: Vec<PsRoute>,
    pub addrs: Vec<PsAddr>,
    pub adapters: Vec<AdapterInfo>,
}

/// ConvertTo-Json возвращает объект вместо массива при одном элементе — нормализуем.
fn as_list(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other],
    }
}

fn js_str(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn js_int(v: &Value, key: &str) -> i64 {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

pub fn normalize_guid(g: &str) -> String {
    let inner = g.trim().trim_matches(|c| c == '{' || c == '}');
    format!("{{{}}}", inner.to_ascii_uppercase())
}

pub fn parse_ps_net(json: &str) -> Result<PsNet, String> {
    // Отбрасываем возможный BOM/мусор перед JSON.
    let start = json.find('{').ok_or("в выводе PowerShell нет JSON")?;
    let v: Value =
        serde_json::from_str(json[start..].trim()).map_err(|e| format!("разбор JSON: {e}"))?;
    let mut net = PsNet::default();
    for r in as_list(v.get("routes")) {
        net.routes.push(PsRoute {
            if_index: js_int(r, "ifIndex"),
            next_hop: js_str(r, "NextHop"),
            metric: js_int(r, "RouteMetric") + js_int(r, "InterfaceMetric"),
        });
    }
    for a in as_list(v.get("addrs")) {
        net.addrs.push(PsAddr {
            ip: js_str(a, "IPAddress"),
            if_index: js_int(a, "InterfaceIndex"),
            alias: js_str(a, "InterfaceAlias"),
            prefix: js_int(a, "PrefixLength").clamp(0, 32) as u8,
        });
    }
    for n in as_list(v.get("adapters")) {
        let guid = js_str(n, "InterfaceGuid");
        if guid.is_empty() {
            continue;
        }
        net.adapters.push(AdapterInfo {
            name: js_str(n, "Name"),
            description: js_str(n, "InterfaceDescription"),
            if_index: js_int(n, "ifIndex"),
            guid: normalize_guid(&guid),
        });
    }
    Ok(net)
}

// ---------------------------------------------------------------------------
// ipconfig (запасной способ определения шлюза)
// ---------------------------------------------------------------------------

fn ipv4_in_line(line: &str) -> Option<Ipv4Addr> {
    // Значение идёт после последнего « : », либо строка целиком — адрес (перенос значения).
    let candidate = match line.rfind(": ") {
        Some(i) => &line[i + 2..],
        None => line,
    };
    let token = candidate
        .trim()
        .split(|c: char| c.is_whitespace() || c == '(' || c == '%')
        .next()?;
    token.parse().ok()
}

fn is_netmask(ip: Ipv4Addr) -> bool {
    let m = u32::from(ip);
    m != 0 && m.leading_ones() + m.trailing_zeros() == 32
}

/// Разбор вывода `ipconfig` без привязки к языку системы: в блоке адаптера,
/// содержащем `source_ip`, порядок строк всегда «адрес → маска → шлюз».
/// Если `source_ip` не задан — берётся первый блок, где шлюз присутствует.
pub fn parse_ipconfig_gateway(output: &str, source_ip: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    // Блоки адаптеров начинаются со строки без отступа.
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if !indented || blocks.is_empty() {
            blocks.push(Vec::new());
        }
        if indented {
            blocks.last_mut().unwrap().push(line);
        }
    }

    let gateway_of = |block: &[&str]| -> Option<(Ipv4Addr, Ipv4Addr)> {
        let mut addr: Option<Ipv4Addr> = None;
        let mut seen_mask = false;
        for line in block {
            let Some(ip) = ipv4_in_line(line) else { continue };
            if addr.is_none() {
                addr = Some(ip);
            } else if !seen_mask {
                if is_netmask(ip) {
                    seen_mask = true;
                }
            } else if !is_netmask(ip) {
                return Some((addr?, ip));
            }
        }
        None
    };

    let mut first = None;
    for block in &blocks {
        if let Some((addr, gw)) = gateway_of(block) {
            match source_ip {
                Some(src) if src == addr => return Some(gw),
                _ => {
                    first.get_or_insert(gw);
                }
            }
        }
    }
    first
}

// ---------------------------------------------------------------------------
// arp -a
// ---------------------------------------------------------------------------

/// Поиск MAC-адреса для IP в выводе `arp -a`.
pub fn parse_arp_mac(output: &str, ip: Ipv4Addr) -> Option<String> {
    let ip_s = ip.to_string();
    for line in output.lines() {
        let mut it = line.split_whitespace();
        if it.next() != Some(ip_s.as_str()) {
            continue;
        }
        if let Some(mac) = it.next().filter(|m| is_mac(m)) {
            let mac = mac.to_ascii_lowercase().replace(':', "-");
            if mac != "ff-ff-ff-ff-ff-ff" && mac != "00-00-00-00-00-00" {
                return Some(mac);
            }
        }
    }
    None
}

pub fn is_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(['-', ':']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn detect_router_mac(router: Ipv4Addr) -> Result<String, String> {
    if !cfg!(windows) {
        let arp = std::fs::read_to_string("/proc/net/arp").map_err(|e| format!("/proc/net/arp: {e}"))?;
        return parse_proc_arp(&arp, router)
            .ok_or_else(|| format!("в ARP-таблице нет записи для {router}"));
    }
    let out = run_cmd("arp", &["-a", &router.to_string()])?;
    if let Some(mac) = parse_arp_mac(&out.stdout, router) {
        return Ok(mac);
    }
    // Записи может не быть в кэше — смотрим полную таблицу.
    let out = run_cmd("arp", &["-a"])?;
    parse_arp_mac(&out.stdout, router)
        .ok_or_else(|| format!("в ARP-таблице нет записи для {router}"))
}

// ---------------------------------------------------------------------------
// masscan --iflist
// ---------------------------------------------------------------------------

/// Разбор вывода `masscan --iflist`. Формат в разных сборках отличается
/// (`0  \Device\NPF_{GUID} \t(Описание)` либо описание на следующей строке),
/// поэтому ищем токен `\Device\NPF_` в любой строке.
pub fn parse_masscan_iflist(output: &str) -> Vec<IfaceEntry> {
    const MARK: &str = "\\Device\\NPF_";
    let lines: Vec<&str> = output.lines().collect();
    let mut result: Vec<IfaceEntry> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(pos) = line.find(MARK) else {
            // Linux: ` 0  eth0 \t(описание)` — номер, имя устройства, описание.
            let mut it = line.split_whitespace();
            if let (Some(n), Some(dev)) = (it.next(), it.next())
                && n.chars().all(|c| c.is_ascii_digit())
                && !dev.starts_with('(')
            {
                let desc = line[line.find(dev).unwrap_or(0) + dev.len()..]
                    .trim()
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .trim()
                    .to_string();
                let desc = if desc.eq_ignore_ascii_case("No description available") {
                    String::new()
                } else {
                    desc
                };
                if !result.iter().any(|e| e.device == dev) {
                    result.push(IfaceEntry { device: dev.to_string(), description: desc });
                }
            }
            continue;
        };
        let rest = &line[pos..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '(')
            .unwrap_or(rest.len());
        let device = rest[..end].to_string();
        let mut description = rest[end..].trim().to_string();
        if description.is_empty() {
            // Описание на следующей строке (если это не очередное устройство).
            if let Some(next) = lines.get(i + 1)
                && !next.contains(MARK)
                && (next.starts_with(' ') || next.starts_with('\t'))
            {
                description = next.trim().to_string();
            }
        }
        let description = description
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim()
            .to_string();
        let description = if description.eq_ignore_ascii_case("No description available") {
            String::new()
        } else {
            description
        };
        if !result.iter().any(|e| e.device.eq_ignore_ascii_case(&device)) {
            result.push(IfaceEntry { device, description });
        }
    }
    result
}

pub fn masscan_iflist(masscan: &Path) -> Result<Vec<IfaceEntry>, String> {
    let out = run_cmd(masscan, &["--iflist"])?;
    let list = parse_masscan_iflist(&out.combined());
    if list.is_empty() {
        let hint = out.combined();
        let hint = hint.trim();
        return Err(if hint.is_empty() {
            "masscan --iflist не вернул интерфейсов (нужны Npcap и права администратора)".into()
        } else {
            format!(
                "masscan --iflist не вернул интерфейсов: {}",
                hint.lines().next().unwrap_or("")
            )
        });
    }
    Ok(list)
}

fn guid_of_device(device: &str) -> Option<String> {
    let start = device.find('{')?;
    let end = device[start..].find('}')? + start;
    Some(normalize_guid(&device[start..=end]))
}

// ---------------------------------------------------------------------------
// Linux: ip addr, /proc/net/route, /proc/net/arp
// ---------------------------------------------------------------------------

/// Разбор `ip -o -4 addr show`: `2: eth0    inet 10.0.0.5/24 brd … scope global eth0`.
pub fn parse_ip_addr(output: &str) -> PsNet {
    let mut net = PsNet::default();
    for line in output.lines() {
        let mut it = line.split_whitespace();
        let (Some(idx), Some(name), Some(fam), Some(cidr)) = (it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        if fam != "inet" {
            continue;
        }
        let Ok(if_index) = idx.trim_end_matches(':').parse::<i64>() else { continue };
        let name = name.split('@').next().unwrap_or(name).to_string();
        let (ip, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
        net.addrs.push(PsAddr {
            ip: ip.to_string(),
            if_index,
            alias: name.clone(),
            prefix: prefix.parse().unwrap_or(32),
        });
        if !net.adapters.iter().any(|a| a.if_index == if_index) {
            net.adapters.push(AdapterInfo {
                name: name.clone(),
                description: name,
                if_index,
                guid: String::new(),
            });
        }
    }
    net
}

/// Маршруты по умолчанию из `/proc/net/route` (адреса — 32-битные little-endian в hex).
pub fn parse_proc_route(content: &str, net: &PsNet) -> Vec<PsRoute> {
    let mut routes = Vec::new();
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
            continue;
        }
        let Ok(gw) = u32::from_str_radix(f[2], 16) else { continue };
        let Some(if_index) = net
            .adapters
            .iter()
            .find(|a| a.name == f[0])
            .map(|a| a.if_index)
        else {
            continue;
        };
        routes.push(PsRoute {
            if_index,
            next_hop: Ipv4Addr::from(gw.to_le_bytes()).to_string(),
            metric: f[6].parse().unwrap_or(0),
        });
    }
    routes
}

/// MAC из `/proc/net/arp`: `10.0.0.1  0x1  0x2  aa:bb:cc:dd:ee:ff  *  eth0`.
pub fn parse_proc_arp(content: &str, ip: Ipv4Addr) -> Option<String> {
    let ip_s = ip.to_string();
    content.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        (f.len() >= 4 && f[0] == ip_s && f[2] != "0x0" && is_mac(f[3]) && f[3] != "00:00:00:00:00:00")
            .then(|| f[3].to_ascii_lowercase().replace(':', "-"))
    })
}

/// Адреса без утилиты `ip`: интерфейсы из `/sys/class/net`, а адрес `source`
/// привязывается к интерфейсу по прямому (без шлюза) маршруту из `/proc/net/route`.
pub fn net_from_proc(route: &str, ifaces: &[(String, i64)], source: Option<Ipv4Addr>) -> PsNet {
    let mut net = PsNet::default();
    for (name, idx) in ifaces {
        net.adapters.push(AdapterInfo {
            name: name.clone(),
            description: name.clone(),
            if_index: *idx,
            guid: String::new(),
        });
    }
    if let Some(src) = source {
        let v = u32::from(src);
        let best = route
            .lines()
            .skip(1)
            .filter_map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 8 || f[2] != "00000000" {
                    return None;
                }
                let dest = u32::from_be_bytes(u32::from_str_radix(f[1], 16).ok()?.to_le_bytes());
                let mask = u32::from_be_bytes(u32::from_str_radix(f[7], 16).ok()?.to_le_bytes());
                (mask != 0 && v & mask == dest).then_some((f[0].to_string(), mask.count_ones() as u8))
            })
            .max_by_key(|(_, prefix)| *prefix);
        if let Some((name, prefix)) = best
            && let Some(a) = net.adapters.iter().find(|a| a.name == name)
        {
            net.addrs.push(PsAddr {
                ip: src.to_string(),
                if_index: a.if_index,
                alias: name,
                prefix,
            });
        }
    }
    net.routes = parse_proc_route(route, &net);
    net
}

fn sys_class_net() -> Vec<(String, i64)> {
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else { return Vec::new() };
    let mut out: Vec<(String, i64)> = dir
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let idx = std::fs::read_to_string(e.path().join("ifindex")).ok()?.trim().parse().ok()?;
            Some((name, idx))
        })
        .collect();
    out.sort_by_key(|(_, i)| *i);
    out
}

fn linux_net(source: Option<Ipv4Addr>) -> Result<PsNet, String> {
    let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    if let Ok(out) = run_cmd("ip", &["-o", "-4", "addr", "show"]) {
        let mut net = parse_ip_addr(&out.stdout);
        if !net.addrs.is_empty() {
            net.routes = parse_proc_route(&route, &net);
            return Ok(net);
        }
    }
    let net = net_from_proc(&route, &sys_class_net(), source);
    if net.adapters.is_empty() {
        return Err("не удалось получить список интерфейсов (нет `ip` и /sys/class/net)".into());
    }
    Ok(net)
}

// ---------------------------------------------------------------------------
// Полное определение
// ---------------------------------------------------------------------------

/// Определяет все сетевые параметры. `target` — адрес целевой сети (если известен),
/// `masscan` — путь к masscan64.exe (для `--iflist`), `want_mac` — искать ли MAC шлюза.
pub fn detect_all(target: Option<Ipv4Addr>, masscan: Option<&Path>, want_mac: bool) -> NetDetect {
    let mut d = NetDetect::default();

    // 1. source-ip
    let probe_target = target.unwrap_or(Ipv4Addr::new(8, 8, 8, 8));
    match detect_source_ip(probe_target) {
        Ok(ip) => {
            d.log.push(format!("source-ip: {ip} (маршрут к {probe_target})"));
            d.source_ip = Some(ip);
        }
        Err(e) => d.log.push(format!("source-ip: не определён — {e}")),
    }

    // 2. Маршруты, адреса, адаптеры: PowerShell в Windows, `ip` и /proc в Linux
    let (ps, route_src) = if cfg!(windows) {
        (run_powershell(PS_NET_SCRIPT).and_then(|o| parse_ps_net(&o.stdout)), "Get-NetRoute")
    } else {
        (linux_net(d.source_ip), "/proc/net/route")
    };
    let ps = match ps {
        Ok(ps) => Some(ps),
        Err(e) => {
            d.log.push(format!("сетевые интерфейсы: {e}"));
            None
        }
    };

    let mut src_if_index: Option<i64> = None;
    if let Some(ps) = &ps {
        if d.source_ip.is_none() {
            // Нет маршрута к цели: берём адрес интерфейса с маршрутом по умолчанию
            // либо первый «обычный» адрес.
            let best_route = ps.routes.iter().min_by_key(|r| r.metric);
            let pick = ps
                .addrs
                .iter()
                .find(|a| Some(a.if_index) == best_route.map(|r| r.if_index))
                .or_else(|| {
                    ps.addrs
                        .iter()
                        .find(|a| !a.ip.starts_with("127.") && !a.ip.starts_with("169.254."))
                });
            if let Some(a) = pick
                && let Ok(ip) = a.ip.parse::<Ipv4Addr>()
            {
                d.log
                    .push(format!("source-ip: {ip} (по интерфейсу «{}»)", a.alias));
                d.source_ip = Some(ip);
            }
        }
        if let Some(src) = d.source_ip {
            let src_s = src.to_string();
            if let Some(a) = ps.addrs.iter().find(|a| a.ip == src_s) {
                src_if_index = Some(a.if_index);
                d.prefix_len = Some(a.prefix);
                if let Some(ad) = ps.adapters.iter().find(|n| n.if_index == a.if_index) {
                    d.log.push(format!(
                        "адаптер: «{}» ({}), ifIndex {}, {}",
                        ad.name, ad.description, ad.if_index, ad.npf_device()
                    ));
                    d.npf_device = Some(ad.npf_device());
                    d.adapter = Some(ad.clone());
                } else {
                    d.log.push(format!(
                        "адаптер: для ifIndex {} нет сведений об адаптере",
                        a.if_index
                    ));
                }
            } else {
                d.log
                    .push(format!("адаптер: адрес {src} не найден среди адресов интерфейсов"));
            }
        }
        // Шлюз: предпочитаем маршрут через интерфейс source-ip.
        let route = ps
            .routes
            .iter()
            .filter(|r| Some(r.if_index) == src_if_index)
            .min_by_key(|r| r.metric)
            .or_else(|| ps.routes.iter().min_by_key(|r| r.metric));
        if let Some(r) = route
            && let Ok(gw) = r.next_hop.parse::<Ipv4Addr>()
            && !gw.is_unspecified()
        {
            d.log.push(format!("router-ip: {gw} ({route_src})"));
            d.router_ip = Some(gw);
        }
    }

    // 3. Запасной способ определения шлюза (Windows) — ipconfig
    if d.router_ip.is_none() && !cfg!(windows) {
        d.log.push("router-ip: маршрут по умолчанию не найден".into());
    }
    if d.router_ip.is_none() && cfg!(windows) {
        match run_cmd("ipconfig", &[]) {
            Ok(out) => match parse_ipconfig_gateway(&out.stdout, d.source_ip) {
                Some(gw) => {
                    d.log.push(format!("router-ip: {gw} (ipconfig)"));
                    d.router_ip = Some(gw);
                }
                None => d.log.push("router-ip: шлюз не найден".into()),
            },
            Err(e) => d.log.push(format!("ipconfig: {e}")),
        }
    }

    // 4. MAC шлюза (по запросу)
    if want_mac && let Some(gw) = d.router_ip {
        match detect_router_mac(gw) {
            Ok(mac) => {
                d.log.push(format!(
                    "router-mac: {mac} ({})",
                    if cfg!(windows) { "arp -a" } else { "/proc/net/arp" }
                ));
                d.router_mac = Some(mac);
            }
            Err(e) => d.log.push(format!("router-mac: {e}")),
        }
    }

    // 5. Список интерфейсов: masscan --iflist, дополненный данными PowerShell
    if let Some(path) = masscan {
        match masscan_iflist(path) {
            Ok(list) => {
                d.log
                    .push(format!("masscan --iflist: интерфейсов — {}", list.len()));
                d.ifaces = list;
            }
            Err(e) => d.log.push(format!("masscan --iflist: {e}")),
        }
    }
    if let Some(ps) = &ps {
        // Подставляем понятные описания и добавляем адаптеры, которых нет в списке masscan.
        for e in &mut d.ifaces {
            let ad = match guid_of_device(&e.device) {
                Some(g) => ps.adapters.iter().find(|a| a.guid == g),
                None => ps.adapters.iter().find(|a| a.guid.is_empty() && a.name == e.device),
            };
            if let Some(ad) = ad {
                let ips: Vec<&str> = ps
                    .addrs
                    .iter()
                    .filter(|a| a.if_index == ad.if_index)
                    .map(|a| a.ip.as_str())
                    .collect();
                e.description = format!("{} [{}] {}", ad.name, ad.description, ips.join(", "))
                    .trim()
                    .to_string();
            }
        }
        if d.ifaces.is_empty() {
            for ad in &ps.adapters {
                let ips: Vec<&str> = ps
                    .addrs
                    .iter()
                    .filter(|a| a.if_index == ad.if_index)
                    .map(|a| a.ip.as_str())
                    .collect();
                if ips.is_empty() {
                    continue;
                }
                d.ifaces.push(IfaceEntry {
                    device: ad.npf_device(),
                    description: format!("{} [{}] {}", ad.name, ad.description, ips.join(", ")),
                });
            }
        }
    }
    if let Some(dev) = &d.npf_device {
        match d
            .ifaces
            .iter()
            .position(|e| e.device.eq_ignore_ascii_case(dev))
        {
            Some(i) => d.selected_iface = Some(i),
            None => {
                // Автоопределённого адаптера нет в списке — добавляем его первым.
                let description = d
                    .adapter
                    .as_ref()
                    .map(|a| format!("{} [{}]", a.name, a.description))
                    .unwrap_or_default();
                d.ifaces.insert(
                    0,
                    IfaceEntry {
                        device: dev.clone(),
                        description,
                    },
                );
                d.selected_iface = Some(0);
            }
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_json_single_and_array() {
        let json = r#"{"routes":{"ifIndex":12,"NextHop":"10.1.0.1","RouteMetric":0,"InterfaceMetric":25},
            "addrs":[{"IPAddress":"10.1.0.57","InterfaceIndex":12,"InterfaceAlias":"Ethernet","PrefixLength":24},
                     {"IPAddress":"127.0.0.1","InterfaceIndex":1,"InterfaceAlias":"Loopback","PrefixLength":8}],
            "adapters":[{"Name":"Ethernet","InterfaceDescription":"Intel(R) I219-LM","ifIndex":12,
                         "InterfaceGuid":"{4d36e972-e325-11ce-bfc1-08002be10318}","MacAddress":"AA-BB-CC-DD-EE-FF","Status":"Up"}]}"#;
        let net = parse_ps_net(&format!("\u{feff}{json}")).unwrap();
        assert_eq!(net.routes.len(), 1);
        assert_eq!(net.routes[0].next_hop, "10.1.0.1");
        assert_eq!(net.addrs.len(), 2);
        assert_eq!(
            net.adapters[0].npf_device(),
            "\\Device\\NPF_{4D36E972-E325-11CE-BFC1-08002BE10318}"
        );
    }

    #[test]
    fn ipconfig_ru_and_en() {
        let en = "\r\nWindows IP Configuration\r\n\r\n\r\nEthernet adapter VMware Network Adapter VMnet1:\r\n\r\n   Connection-specific DNS Suffix  . :\r\n   IPv4 Address. . . . . . . . . . . : 192.168.56.1\r\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n   Default Gateway . . . . . . . . . :\r\n\r\nEthernet adapter Ethernet:\r\n\r\n   Connection-specific DNS Suffix  . : corp.local\r\n   Link-local IPv6 Address . . . . . : fe80::1c2b:3a4d:5e6f:7a8b%12\r\n   IPv4 Address. . . . . . . . . . . : 10.1.0.57\r\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n   Default Gateway . . . . . . . . . : fe80::1%12\r\n                                       10.1.0.1\r\n";
        assert_eq!(
            parse_ipconfig_gateway(en, Some(Ipv4Addr::new(10, 1, 0, 57))),
            Some(Ipv4Addr::new(10, 1, 0, 1))
        );
        assert_eq!(
            parse_ipconfig_gateway(en, None),
            Some(Ipv4Addr::new(10, 1, 0, 1))
        );
        // Русская локаль в «битой» кодировке: метки нечитаемы, структура та же.
        let ru = "Настройка протокола IP для Windows\r\n\r\nАдаптер Ethernet Ethernet0:\r\n\r\n   DNS-суффикс подключения . . . . . :\r\n   IPv4-адрес. . . . . . . . . . . . : 172.16.5.20\r\n   Маска подсети . . . . . . . . . . : 255.255.252.0\r\n   Основной шлюз. . . . . . . . . : 172.16.4.1\r\n";
        assert_eq!(
            parse_ipconfig_gateway(ru, Some(Ipv4Addr::new(172, 16, 5, 20))),
            Some(Ipv4Addr::new(172, 16, 4, 1))
        );
    }

    #[test]
    fn arp_table() {
        let out = "\r\nInterface: 10.1.0.57 --- 0xc\r\n  Internet Address      Physical Address      Type\r\n  10.1.0.1              00-1a-2b-3c-4d-5e     dynamic\r\n  10.1.0.255            ff-ff-ff-ff-ff-ff     static\r\n";
        assert_eq!(
            parse_arp_mac(out, Ipv4Addr::new(10, 1, 0, 1)).as_deref(),
            Some("00-1a-2b-3c-4d-5e")
        );
        assert_eq!(parse_arp_mac(out, Ipv4Addr::new(10, 1, 0, 255)), None);
        assert_eq!(parse_arp_mac(out, Ipv4Addr::new(10, 1, 0, 2)), None);
    }

    #[test]
    fn linux_ip_route_arp() {
        let ip = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n\
                  2: eth0    inet 10.1.0.57/24 brd 10.1.0.255 scope global dynamic eth0\\       valid_lft 86000sec\n\
                  5: veth1@if4    inet 172.17.0.1/16 brd 172.17.255.255 scope global veth1\n";
        let net = parse_ip_addr(ip);
        assert_eq!(net.addrs.len(), 3);
        assert_eq!(net.addrs[1].ip, "10.1.0.57");
        assert_eq!(net.addrs[1].prefix, 24);
        assert_eq!(net.adapters[2].name, "veth1");
        assert_eq!(net.adapters[1].npf_device(), "eth0");

        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t0100010A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                     eth0\t0000010A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let routes = parse_proc_route(route, &net);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].next_hop, "10.1.0.1");
        assert_eq!(routes[0].if_index, 2);

        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   10.1.0.1         0x1         0x2         00:1A:2B:3C:4D:5E     *        eth0\n\
                   10.1.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        assert_eq!(parse_proc_arp(arp, Ipv4Addr::new(10, 1, 0, 1)).as_deref(), Some("00-1a-2b-3c-4d-5e"));
        assert_eq!(parse_proc_arp(arp, Ipv4Addr::new(10, 1, 0, 9)), None);
    }

    #[test]
    fn linux_without_ip_tool() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                     eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        let ifaces = vec![("lo".to_string(), 1), ("eth0".to_string(), 2)];
        let net = net_from_proc(route, &ifaces, Some(Ipv4Addr::new(192, 0, 2, 2)));
        assert_eq!(net.addrs.len(), 1);
        assert_eq!(net.addrs[0].alias, "eth0");
        assert_eq!(net.addrs[0].prefix, 24);
        assert_eq!(net.routes.len(), 1);
        assert_eq!(net.routes[0].next_hop, "192.0.2.1");
    }

    #[test]
    fn iflist_linux_format() {
        let out = "If list:\n 0  eth0 \t(No description available)\n 1  any \t(Pseudo-device that captures on all interfaces)\n 2  lo \t(No description available)\n";
        let l = parse_masscan_iflist(out);
        assert_eq!(l.len(), 3);
        assert_eq!(l[0].device, "eth0");
        assert_eq!(l[0].description, "");
        assert_eq!(l[1].description, "Pseudo-device that captures on all interfaces");
    }

    #[test]
    fn iflist_formats() {
        let a = " 0  \\Device\\NPF_{11111111-2222-3333-4444-555555555555} \t(Intel(R) Ethernet Connection I219-LM)\n 1  \\Device\\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE} \t(VMware Virtual Ethernet Adapter)\n 2  \\Device\\NPF_Loopback \t(No description available)\n";
        let l = parse_masscan_iflist(a);
        assert_eq!(l.len(), 3);
        assert_eq!(l[0].device, "\\Device\\NPF_{11111111-2222-3333-4444-555555555555}");
        assert_eq!(l[0].description, "Intel(R) Ethernet Connection I219-LM");
        assert_eq!(l[2].device, "\\Device\\NPF_Loopback");
        assert_eq!(l[2].description, "");

        let b = "If list:\n  1  \\Device\\NPF_{11111111-2222-3333-4444-555555555555}\n        Realtek PCIe GbE\n  2  \\Device\\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}\n        VirtualBox Host-Only Ethernet Adapter\n";
        let l = parse_masscan_iflist(b);
        assert_eq!(l.len(), 2);
        assert_eq!(l[1].description, "VirtualBox Host-Only Ethernet Adapter");
    }
}
