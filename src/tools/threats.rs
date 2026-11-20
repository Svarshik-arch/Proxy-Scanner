//! Угрозы в сегменте по пассивному прослушиванию: посторонние DHCP-серверы, подмена
//! ARP, посторонние маршрутизаторы IPv6 (RA, атака mitm6), ICMP Redirect, отравители
//! LLMNR/NBT-NS (Responder), смена корня STP, широковещательные запросы имён.

use serde::{Deserialize, Serialize};

use super::capture::Summary;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    High,
    Medium,
    Low,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::High => "высокая",
            Level::Medium => "средняя",
            Level::Low => "низкая",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub level: Level,
    pub title: String,
    pub detail: String,
    pub advice: String,
}

/// Сколько разных имён должен «знать» отвечающий узел, чтобы считать его отравителем.
const POISONER_NAMES: usize = 3;

pub fn assess(s: &Summary) -> Vec<Threat> {
    let mut out = Vec::new();
    let mut add = |level, title: String, detail: String, advice: &str| {
        out.push(Threat {
            level,
            title,
            detail,
            advice: advice.into(),
        })
    };
    if s.dhcp.len() > 1 {
        let list = s.dhcp.iter().map(|d| format!("{} ({}, шлюз {})", d.ip, d.mac, d.router)).collect::<Vec<_>>().join("; ");
        add(
            Level::High,
            format!("В сегменте {} DHCP-сервера", s.dhcp.len()),
            list,
            "Посторонний DHCP раздаёт свой шлюз и DNS — весь трафик идёт через него. Включите DHCP Snooping на коммутаторе, найдите порт по MAC.",
        );
    }
    for (ip, macs) in s.arp_conflicts() {
        add(
            Level::High,
            format!("Подмена ARP: {ip}"),
            format!("адрес отвечает с разных MAC: {}", macs.join(", ")),
            "Признак ARP-спуфинга (перехват трафика) или конфликта адресов. Включите Dynamic ARP Inspection, найдите порт по второму MAC.",
        );
    }
    if !s.ipv6_ra.is_empty() {
        let list = s.ipv6_ra.iter().map(|(k, n)| format!("{k} ×{n}")).collect::<Vec<_>>().join("; ");
        let (level, title) = if s.ipv6_ra.len() > 1 {
            (Level::High, format!("{} маршрутизатора IPv6 объявляют себя (RA)", s.ipv6_ra.len()))
        } else {
            (Level::Medium, "Объявления маршрутизатора IPv6 (RA)".to_string())
        };
        add(
            level,
            title,
            list,
            "Если IPv6 в сети не используется, RA — признак атаки mitm6: Windows получает посторонний DNS по IPv6. Включите RA Guard или отключите IPv6 на рабочих местах.",
        );
    }
    if !s.icmp_redirects.is_empty() {
        let list = s.icmp_redirects.iter().map(|(k, n)| format!("{k} ×{n}")).collect::<Vec<_>>().join("; ");
        add(
            Level::Medium,
            "ICMP Redirect в сегменте".into(),
            list,
            "Перенаправление на другой шлюз может использоваться для перехвата трафика. Запретите приём ICMP Redirect на узлах и их отправку на маршрутизаторах.",
        );
    }
    for (ip, names) in &s.name_responders {
        if names.len() >= POISONER_NAMES {
            let sample = names.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
            add(
                Level::High,
                format!("Отравитель LLMNR/NBT-NS: {ip}"),
                format!("отвечает на {} разных имён: {sample}", names.len()),
                "Так работает Responder: перехватывает хеши паролей NTLMv2. Найдите узел и отключите LLMNR и NetBIOS over TCP/IP групповой политикой.",
            );
        }
    }
    if s.stp_roots.len() > 1 {
        add(
            Level::Medium,
            "Сменился корневой мост STP".into(),
            s.stp_roots.join(" → "),
            "Посторонний коммутатор или атака на STP: трафик может пойти через чужое устройство. Включите BPDU Guard / Root Guard на портах доступа.",
        );
    }
    let llmnr = s.name_queries.keys().filter(|k| k.starts_with("LLMNR") || k.starts_with("NBT-NS")).count();
    if llmnr > 0 {
        add(
            Level::Low,
            format!("Широковещательные запросы имён LLMNR/NBT-NS ({llmnr})"),
            "узлы ищут имена широковещательно — их ответы можно подделать".into(),
            "Отключите LLMNR и NetBIOS over TCP/IP групповой политикой.",
        );
    }
    out.sort_by_key(|t| t.level);
    out
}

pub fn render_text(t: &[Threat]) -> String {
    if t.is_empty() {
        return "Угроз по прослушиванию не найдено.\n".into();
    }
    let mut s = String::new();
    for x in t {
        s += &format!("[{}] {}\n    {}\n    → {}\n", x.level.label(), x.title, x.detail, x.advice);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::capture::DhcpServer;

    #[test]
    fn assess_all() {
        let mut s = Summary::default();
        assert!(assess(&s).is_empty());
        s.dhcp = vec![
            DhcpServer { ip: "10.0.0.1".into(), ..Default::default() },
            DhcpServer { ip: "10.0.0.66".into(), ..Default::default() },
        ];
        s.arp.insert("10.0.0.1".into(), vec!["aa".into(), "bb".into()]);
        s.ipv6_ra.insert("fe80::1 (cc)".into(), 3);
        s.name_responders.insert("10.0.0.99".into(), ["LLMNR a", "LLMNR b", "NBT-NS C"].iter().map(|x| x.to_string()).collect());
        s.stp_roots = vec!["32768 / aa".into(), "0 / bb".into()];
        let t = assess(&s);
        assert_eq!(t.iter().filter(|t| t.level == Level::High).count(), 3);
        assert!(t.iter().any(|t| t.title.contains("Отравитель")));
        assert!(t.iter().any(|t| t.title.contains("STP")));
        assert_eq!(t[0].level, Level::High);
    }
}
