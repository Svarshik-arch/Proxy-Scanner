//! Сетевые устройства: список (с зашифрованными паролями), профили производителей
//! (как отключить постраничный вывод, какие команды для конфигурации, интерфейсов,
//! MAC-таблицы, LLDP), определение производителя по приглашению и выводу, и разбор
//! табличного вывода `show …` в столбцы.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Proto {
    #[default]
    Ssh,
    Telnet,
    Serial,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Ssh => "SSH",
            Proto::Telnet => "Telnet",
            Proto::Serial => "COM",
        }
    }
    pub fn default_port(self) -> u16 {
        match self {
            Proto::Ssh => 22,
            Proto::Telnet => 23,
            Proto::Serial => 9600,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub enum Vendor {
    #[default]
    Auto,
    CiscoIos,
    CiscoNxos,
    Huawei,
    Eltex,
    Mikrotik,
    Juniper,
    Qtech,
    Snr,
    Dlink,
    Hpe,
    Aruba,
    Linux,
}

impl Vendor {
    pub const ALL: [Vendor; 13] = [
        Vendor::Auto,
        Vendor::CiscoIos,
        Vendor::CiscoNxos,
        Vendor::Huawei,
        Vendor::Eltex,
        Vendor::Mikrotik,
        Vendor::Juniper,
        Vendor::Qtech,
        Vendor::Snr,
        Vendor::Dlink,
        Vendor::Hpe,
        Vendor::Aruba,
        Vendor::Linux,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Vendor::Auto => "определить",
            Vendor::CiscoIos => "Cisco IOS / IOS-XE",
            Vendor::CiscoNxos => "Cisco NX-OS",
            Vendor::Huawei => "Huawei VRP",
            Vendor::Eltex => "Eltex MES",
            Vendor::Mikrotik => "MikroTik RouterOS",
            Vendor::Juniper => "Juniper Junos",
            Vendor::Qtech => "QTech",
            Vendor::Snr => "SNR",
            Vendor::Dlink => "D-Link",
            Vendor::Hpe => "HPE Comware / H3C",
            Vendor::Aruba => "Aruba / ProCurve",
            Vendor::Linux => "Linux / Unix",
        }
    }

    /// Профиль команд.
    pub fn profile(self) -> Profile {
        let p = |paging: &[&'static str], config: &'static str, version: &'static str, interfaces: &'static str, mac: &'static str, lldp: &'static str| Profile {
            paging: paging.to_vec(),
            config,
            version,
            interfaces,
            mac,
            lldp,
        };
        match self {
            Vendor::CiscoIos | Vendor::Auto => p(
                &["terminal length 0", "terminal width 0"],
                "show running-config",
                "show version",
                "show interfaces status",
                "show mac address-table",
                "show lldp neighbors",
            ),
            Vendor::CiscoNxos => p(&["terminal length 0"], "show running-config", "show version", "show interface status", "show mac address-table", "show lldp neighbors"),
            Vendor::Huawei => p(
                &["screen-length 0 temporary"],
                "display current-configuration",
                "display version",
                "display interface brief",
                "display mac-address",
                "display lldp neighbor brief",
            ),
            Vendor::Eltex => p(&["terminal datadump"], "show running-config", "show version", "show interfaces status", "show mac address-table", "show lldp neighbors"),
            Vendor::Qtech | Vendor::Snr => p(&["terminal length 0"], "show running-config", "show version", "show interface brief", "show mac-address-table", "show lldp neighbors brief"),
            Vendor::Mikrotik => p(&[], "/export terse", "/system resource print", "/interface print terse", "/interface bridge host print terse", "/ip neighbor print terse"),
            Vendor::Juniper => p(
                &["set cli screen-length 0", "set cli screen-width 0"],
                "show configuration | display set",
                "show version",
                "show interfaces terse",
                "show ethernet-switching table",
                "show lldp neighbors",
            ),
            Vendor::Dlink => p(&["disable clipaging"], "show config current_config", "show switch", "show ports", "show fdb", "show lldp remote_ports"),
            Vendor::Hpe => p(&["screen-length disable"], "display current-configuration", "display version", "display interface brief", "display mac-address", "display lldp neighbor-information list"),
            Vendor::Aruba => p(&["no page"], "show running-config", "show version", "show interfaces brief", "show mac-address", "show lldp info remote-device"),
            Vendor::Linux => p(&[], "cat /etc/network/interfaces 2>/dev/null; ip -br addr", "uname -a", "ip -s -br link", "ip neigh", "lldpctl 2>/dev/null"),
        }
    }

    /// Определить по приглашению и выводу (баннер, `show version`).
    pub fn detect(text: &str) -> Vendor {
        let t = text.to_ascii_lowercase();
        let has = |s: &str| t.contains(s);
        if has("nx-os") || has("nexus") {
            Vendor::CiscoNxos
        } else if has("cisco ios") || has("ios-xe") || has("cisco systems") || has("ios software") {
            Vendor::CiscoIos
        } else if has("huawei") || has("versatile routing platform") {
            Vendor::Huawei
        } else if has("comware") || has("h3c") {
            Vendor::Hpe
        } else if has("eltex") || has("mes2") || has("mes3") || has("mes5") {
            Vendor::Eltex
        } else if has("routeros") || has("mikrotik") {
            Vendor::Mikrotik
        } else if has("junos") || has("juniper") {
            Vendor::Juniper
        } else if has("qtech") || has("qsw-") {
            Vendor::Qtech
        } else if has("snr-") || has("nag ") {
            Vendor::Snr
        } else if has("d-link") || has("des-") || has("dgs-") {
            Vendor::Dlink
        } else if has("procurve") || has("aruba") {
            Vendor::Aruba
        } else if has("linux") || has("gnu/") || has("ubuntu") || has("debian") {
            Vendor::Linux
        } else if text.lines().any(|l| l.trim_start().starts_with('<') && l.trim_end().ends_with('>')) {
            Vendor::Huawei
        } else if text.lines().any(|l| l.trim_start().starts_with("[") && l.contains("@") && l.trim_end().ends_with("] >")) {
            Vendor::Mikrotik
        } else {
            Vendor::Auto
        }
    }
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub paging: Vec<&'static str>,
    pub config: &'static str,
    pub version: &'static str,
    pub interfaces: &'static str,
    pub mac: &'static str,
    pub lldp: &'static str,
}

/// Библиотека типовых команд для меню терминала: (название, команда).
pub fn library(v: Vendor) -> Vec<(&'static str, String)> {
    let p = v.profile();
    let mut out = vec![
        ("Версия и аптайм", p.version.to_string()),
        ("Интерфейсы", p.interfaces.to_string()),
        ("MAC-таблица", p.mac.to_string()),
        ("Соседи LLDP", p.lldp.to_string()),
        ("Конфигурация", p.config.to_string()),
    ];
    let extra: &[(&str, &str)] = match v {
        Vendor::CiscoIos | Vendor::Auto | Vendor::Eltex | Vendor::Qtech | Vendor::Snr => &[
            ("Адреса интерфейсов", "show ip interface brief"),
            ("VLAN", "show vlan brief"),
            ("ARP", "show ip arp"),
            ("Маршруты", "show ip route"),
            ("Ошибки на портах", "show interfaces counters errors"),
            ("STP", "show spanning-tree summary"),
            ("Журнал", "show logging"),
            ("CDP", "show cdp neighbors"),
        ],
        Vendor::CiscoNxos => &[("Адреса интерфейсов", "show ip interface brief"), ("VLAN", "show vlan brief"), ("Маршруты", "show ip route"), ("Журнал", "show logging last 100")],
        Vendor::Huawei | Vendor::Hpe => &[
            ("Адреса интерфейсов", "display ip interface brief"),
            ("VLAN", "display vlan"),
            ("ARP", "display arp"),
            ("Маршруты", "display ip routing-table"),
            ("STP", "display stp brief"),
            ("Журнал", "display logbuffer"),
        ],
        Vendor::Mikrotik => &[("Адреса", "/ip address print terse"), ("Маршруты", "/ip route print terse"), ("ARP", "/ip arp print terse"), ("Журнал", "/log print")],
        Vendor::Juniper => &[("Маршруты", "show route"), ("ARP", "show arp"), ("Ошибки", "show interfaces extensive | match error"), ("Журнал", "show log messages | last 50")],
        Vendor::Dlink => &[("VLAN", "show vlan"), ("ARP", "show arpentry"), ("Журнал", "show log")],
        Vendor::Aruba => &[("VLAN", "show vlans"), ("ARP", "show arp"), ("Журнал", "show logging")],
        Vendor::Linux => &[("Маршруты", "ip route"), ("Сокеты", "ss -tulpn"), ("Журнал", "journalctl -n 50 --no-pager")],
    };
    out.extend(extra.iter().map(|(a, b)| (*a, b.to_string())));
    out
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Device {
    pub name: String,
    /// Адрес или имя; для COM — имя порта (COM3, /dev/ttyUSB0).
    pub host: String,
    pub proto: Proto,
    /// Порт TCP; для COM — скорость.
    pub port: u16,
    pub vendor: Vendor,
    pub user: String,
    /// Пароль (зашифрован, см. vault).
    pub secret: String,
    /// Пароль привилегированного режима (enable), зашифрован.
    pub enable: String,
    /// Путь к закрытому ключу SSH (необязательно).
    pub key_file: String,
    /// SNMP community (для мониторинга интерфейсов).
    pub community: String,
    /// Группа: «ядро», «этаж 3», «филиал Казань».
    pub group: String,
    pub notes: String,
}

impl Device {
    pub fn title(&self) -> String {
        if self.name.trim().is_empty() { self.host.clone() } else { self.name.clone() }
    }
    pub fn port_or_default(&self) -> u16 {
        if self.port == 0 { self.proto.default_port() } else { self.port }
    }
    pub fn password(&self) -> String {
        crate::vault::open(&self.secret).unwrap_or_default()
    }
    pub fn enable_password(&self) -> String {
        crate::vault::open(&self.enable).unwrap_or_default()
    }
}

pub fn store_path() -> PathBuf {
    crate::updates::data_dir().with_file_name("proxy-scanner-devices.json")
}

pub fn load() -> Vec<Device> {
    std::fs::read_to_string(store_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

pub fn save(list: &[Device]) -> Result<(), String> {
    let p = store_path();
    std::fs::write(&p, serde_json::to_string_pretty(list).map_err(|e| e.to_string())?).map_err(|e| format!("{}: {e}", p.display()))
}

// ---------------------------------------------------------------------------
// Разбор табличного вывода
// ---------------------------------------------------------------------------

/// Таблица из вывода с выровненными столбцами (`show interfaces status`,
/// `show mac address-table`, `display interface brief`…): ищется строка заголовка,
/// границы столбцов — по началу слов заголовка.
pub fn parse_table(text: &str) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    let lines: Vec<&str> = text.lines().map(|l| l.trim_end()).collect();
    // Заголовок: строка из 2+ слов, после которой идут строки похожей длины; разделители «----» пропускаем.
    let is_sep = |l: &str| !l.is_empty() && l.chars().all(|c| c == '-' || c == ' ' || c == '=' || c == '+');
    // Слова строки с позициями начала.
    let words = |l: &str| -> Vec<(usize, String)> {
        let mut v = Vec::new();
        let mut start = None;
        let chars: Vec<char> = l.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            match (*c == ' ', start) {
                (false, None) => start = Some(i),
                (true, Some(s)) => {
                    v.push((s, chars[s..i].iter().collect::<String>()));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = start {
            v.push((s, chars[s..].iter().collect::<String>()));
        }
        v
    };
    // Из всех строк-кандидатов в заголовки выбираем ту, под которой таблица «лучше»:
    // больше строк, где заполнена хотя бы половина столбцов.
    let mut best: Option<(usize, Vec<String>, Vec<Vec<String>>)> = None;
    for (hi, h) in lines.iter().enumerate() {
        let cols = words(h);
        let prompt_like = h.contains('#') || h.trim_end().ends_with('>') || h.contains(':') || h.contains('=');
        if prompt_like || cols.len() < 2 || cols.iter().any(|(_, w)| w.chars().all(|c| c.is_ascii_digit())) {
            continue;
        }
        let is_prompt = |l: &str| {
            let t = l.trim_end();
            !t.contains("  ") && (t.ends_with('#') || t.ends_with('>') || t.ends_with(']')) || t.contains("#show") || t.contains("#display")
        };
        let body: Vec<&str> = lines[hi + 1..]
            .iter()
            .copied()
            .take_while(|l| !is_prompt(l))
            .filter(|l| !l.trim().is_empty() && !is_sep(l))
            .collect();
        // Следующие строки должны начинаться под заголовком и быть не короче половины.
        let good = body.iter().take(5).filter(|l| l.chars().count() >= cols.last().map(|c| c.0).unwrap_or(0).min(h.chars().count()) / 2 && !l.contains('#')).count();
        if body.is_empty() || good < body.len().clamp(1, 5) {
            continue;
        }
        // Граница столбца — начало слова заголовка, перед которым во всех строках данных
        // пробел («Mac Address» — одно имя: адрес пересекает границу).
        let body_chars: Vec<Vec<char>> = body.iter().map(|l| l.chars().collect()).collect();
        let mut merged: Vec<(usize, String)> = Vec::new();
        for (s0, w) in &cols {
            // Большинство строк (итоговые фразы вроде «Total …» не в счёт).
            let ok = body_chars.iter().filter(|r| *s0 == 0 || r.len() <= *s0 || r[*s0 - 1] == ' ').count();
            let boundary = merged.is_empty() || ok * 5 >= body_chars.len() * 3;
            match (boundary, merged.last_mut()) {
                (false, Some(last)) => {
                    last.1.push(' ');
                    last.1.push_str(w);
                }
                _ => merged.push((*s0, w.clone())),
            }
        }
        if merged.len() < 2 {
            continue;
        }
        let header: Vec<String> = merged.iter().map(|c| c.1.trim().to_string()).collect();
        let starts: Vec<usize> = merged.iter().map(|c| c.0).collect();
        let mut rows = Vec::new();
        for l in body {
            // Конец таблицы: приглашение или текст без отступов «под столбцами».
            if l.ends_with('#') || l.ends_with('>') || l.ends_with(']') {
                break;
            }
            let ch: Vec<char> = l.chars().collect();
            let mut row = Vec::new();
            for (i, s) in starts.iter().enumerate() {
                let mut a = (*s).min(ch.len());
                // Значение могло начаться чуть левее заголовка — откатываемся до пробела.
                while a > 0 && ch[a - 1] != ' ' && (i == 0 || a > starts[i - 1] + 1) {
                    a -= 1;
                }
                let e = starts.get(i + 1).map(|n| (*n).min(ch.len())).unwrap_or(ch.len());
                let mut e2 = e;
                while e2 > a && e2 < ch.len() && ch[e2 - 1] != ' ' && ch[e2] != ' ' {
                    e2 -= 1;
                }
                let cell: String = if a < e2 { ch[a..e2].iter().collect() } else { String::new() };
                row.push(cell.trim().to_string());
            }
            if row.iter().any(|c| !c.is_empty()) {
                rows.push(row);
            }
        }
        // Строки-фразы (итоги, примечания) — без значений в большинстве столбцов.
        rows.retain(|r| r.iter().filter(|c| !c.is_empty()).count() * 2 >= header.len());
        let filled = rows.len();
        if filled == 0 || filled * 10 < rows.len() * 6 {
            continue;
        }
        let score = filled * 100 + header.len();
        if best.as_ref().is_none_or(|b| score > b.0) {
            best = Some((score, header, rows));
        }
    }
    best.map(|b| (b.1, b.2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_vendors() {
        assert_eq!(Vendor::detect("Cisco IOS Software, C2960 Software"), Vendor::CiscoIos);
        assert_eq!(Vendor::detect("Huawei Versatile Routing Platform Software"), Vendor::Huawei);
        assert_eq!(Vendor::detect("<SW-core>"), Vendor::Huawei);
        assert_eq!(Vendor::detect("[admin@MikroTik] >"), Vendor::Mikrotik);
        assert_eq!(Vendor::detect("Active-image: flash://mes2324fb"), Vendor::Eltex);
        assert_eq!(Vendor::detect("JUNOS Software Release [21.4R3]"), Vendor::Juniper);
        assert!(!library(Vendor::Huawei).is_empty());
    }

    #[test]
    fn cisco_interfaces_status() {
        let out = "\
sw1#show interfaces status

Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   uplink core        connected    trunk        full   1000 10/100/1000BaseTX
Gi1/0/2                      notconnect   10           auto   auto 10/100/1000BaseTX
Gi1/0/3   printer 3 floor    connected    20         a-half  a-100 10/100/1000BaseTX
sw1#";
        let (h, rows) = parse_table(out).unwrap();
        assert_eq!(h, vec!["Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type"]);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0][1], "uplink core");
        assert_eq!(rows[1][2], "notconnect");
        assert_eq!(rows[2][4], "a-half");
        assert_eq!(rows[2][1], "printer 3 floor");
    }

    #[test]
    fn mac_table() {
        let out = "\
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    0011.2233.4455    DYNAMIC     Gi1/0/5
  20    aabb.ccdd.eeff    DYNAMIC     Gi1/0/7
Total Mac Addresses for this criterion: 2";
        let (h, rows) = parse_table(out).unwrap();
        assert_eq!(h, vec!["Vlan", "Mac Address", "Type", "Ports"]);
        assert_eq!(rows[0], vec!["10", "0011.2233.4455", "DYNAMIC", "Gi1/0/5"]);
    }
}
