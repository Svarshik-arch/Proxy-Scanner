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
    pub fn npf_device(&self) -> String {
        format!("\\Device\\NPF_{}", self.guid)
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
        let Some(pos) = line.find(MARK) else { continue };
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

    // 2. PowerShell: маршруты, адреса, адаптеры
    let ps = match run_powershell(PS_NET_SCRIPT).and_then(|o| parse_ps_net(&o.stdout)) {
        Ok(ps) => Some(ps),
        Err(e) => {
            d.log.push(format!("PowerShell: {e}"));
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
                        ad.name, ad.description, ad.if_index, ad.guid
                    ));
                    d.npf_device = Some(ad.npf_device());
                    d.adapter = Some(ad.clone());
                } else {
                    d.log.push(format!(
                        "адаптер: для ifIndex {} нет записи Get-NetAdapter",
                        a.if_index
                    ));
                }
            } else {
                d.log
                    .push(format!("адаптер: адрес {src} не найден в Get-NetIPAddress"));
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
            d.log.push(format!("router-ip: {gw} (Get-NetRoute)"));
            d.router_ip = Some(gw);
        }
    }

    // 3. Запасной способ определения шлюза — ipconfig
    if d.router_ip.is_none() {
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
                d.log.push(format!("router-mac: {mac} (arp -a)"));
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
            if let Some(g) = guid_of_device(&e.device)
                && let Some(ad) = ps.adapters.iter().find(|a| a.guid == g)
            {
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
