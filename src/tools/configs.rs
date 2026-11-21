//! Резервные копии конфигураций: снять, хранить историю, сравнить, проверить.
//! Копии лежат в `proxy-scanner-configs/<устройство>/<время>.cfg` рядом с программой.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;
use crate::devices::{Device, Vendor};

pub fn root() -> PathBuf {
    crate::updates::data_dir().with_file_name("proxy-scanner-configs")
}

/// Имя папки устройства (без запрещённых символов).
pub fn folder(title: &str) -> String {
    let s: String = title
        .chars()
        .map(|c| if c.is_alphanumeric() || "-_.".contains(c) { c } else { '_' })
        .collect();
    if s.is_empty() { "device".into() } else { s }
}

/// Убрать из вывода строки, которые меняются без изменения настроек
/// (время, счётчики, «Building configuration»), и мусор вокруг.
pub fn normalize(text: &str) -> String {
    let noisy = |l: &str| {
        let t = l.trim();
        t.starts_with("Building configuration")
            || t.starts_with("Current configuration :")
            || t.starts_with("! Last configuration change")
            || t.starts_with("! NVRAM config last updated")
            || t.starts_with("! No configuration change since")
            || t.starts_with("ntp clock-period")
            || (t.starts_with("# ") && t.contains(" by RouterOS"))
            || t.starts_with("!Software Version")
            || t.starts_with("!Last configuration was")
            || t.starts_with("## Last commit:")
            || t.starts_with("## Last changed:")
            || t.starts_with("Time:")
    };
    let mut out: Vec<&str> = text.lines().map(|l| l.trim_end()).filter(|l| !noisy(l)).collect();
    while out.first().is_some_and(|l| l.trim().is_empty()) {
        out.remove(0);
    }
    while out.last().is_some_and(|l| l.trim().is_empty()) {
        out.pop();
    }
    out.join("\n") + "\n"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub path: PathBuf,
    /// `20261118-143005`
    pub stamp: String,
    pub size: u64,
}

/// Версии устройства, новые первыми.
pub fn versions(title: &str) -> Vec<Version> {
    let dir = root().join(folder(title));
    let mut v: Vec<Version> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "cfg"))
        .map(|e| Version {
            stamp: e.path().file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
            size: e.metadata().map(|m| m.len()).unwrap_or(0),
            path: e.path(),
        })
        .collect();
    v.sort_by(|a, b| b.stamp.cmp(&a.stamp));
    v
}

/// Человекочитаемое время версии: `2026-11-18 14:30:05 UTC`.
pub fn pretty(stamp: &str) -> String {
    let b = stamp.as_bytes();
    if b.len() == 15 && b[8] == b'-' {
        format!("{}-{}-{} {}:{}:{} UTC", &stamp[0..4], &stamp[4..6], &stamp[6..8], &stamp[9..11], &stamp[11..13], &stamp[13..15])
    } else {
        stamp.to_string()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Change {
    pub added: usize,
    pub removed: usize,
}

/// Строки сравнения: (знак, текст), где знак '+', '-', ' ' или '@' (разрыв).
pub fn diff(old: &str, new: &str, context: usize) -> (Vec<(char, String)>, Change) {
    let d = similar::TextDiff::from_lines(old, new);
    let mut out = Vec::new();
    let mut ch = Change::default();
    for (i, group) in d.grouped_ops(context).iter().enumerate() {
        if i > 0 {
            out.push(('@', "…".to_string()));
        }
        for op in group {
            for c in d.iter_changes(op) {
                let sign = match c.tag() {
                    similar::ChangeTag::Delete => {
                        ch.removed += 1;
                        '-'
                    }
                    similar::ChangeTag::Insert => {
                        ch.added += 1;
                        '+'
                    }
                    similar::ChangeTag::Equal => ' ',
                };
                out.push((sign, c.value().trim_end_matches('\n').to_string()));
            }
        }
    }
    (out, ch)
}

// ---------------------------------------------------------------------------
// Проверка конфигурации
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    High,
    Medium,
    Low,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::High => "важно",
            Level::Medium => "средне",
            Level::Low => "совет",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub level: Level,
    pub title: String,
    pub advice: String,
    /// Строка конфигурации, к которой относится (если есть).
    pub line: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Cisco,
    Huawei,
    Mikrotik,
    Juniper,
    Other,
}

fn family(v: Vendor, text: &str) -> Family {
    match v {
        Vendor::CiscoIos | Vendor::CiscoNxos | Vendor::Eltex | Vendor::Qtech | Vendor::Snr | Vendor::Aruba => Family::Cisco,
        Vendor::Huawei | Vendor::Hpe => Family::Huawei,
        Vendor::Mikrotik => Family::Mikrotik,
        Vendor::Juniper => Family::Juniper,
        Vendor::Dlink | Vendor::Linux => Family::Other,
        Vendor::Auto => {
            if text.contains("\nsysname ") || text.contains("\n#\n") {
                Family::Huawei
            } else if text.contains("/interface ") || text.contains("/ip ") {
                Family::Mikrotik
            } else if text.contains("set system ") {
                Family::Juniper
            } else if text.contains("\ninterface ") || text.contains("\nhostname ") {
                Family::Cisco
            } else {
                Family::Other
            }
        }
    }
}

/// Проверить конфигурацию на типовые ошибки безопасности и эксплуатации.
pub fn audit(text: &str, vendor: Vendor) -> Vec<Finding> {
    let lines: Vec<&str> = text.lines().map(|l| l.trim()).collect();
    let has = |p: &str| lines.iter().any(|l| l.starts_with(p));
    let find = |f: &dyn Fn(&str) -> bool| lines.iter().find(|l| f(l)).map(|l| l.to_string());
    let mut v = Vec::new();
    let mut add = |level, title: &str, advice: &str, line: Option<String>| v.push(Finding { level, title: title.into(), advice: advice.into(), line });
    let weak_community = |l: &str| {
        let w: Vec<&str> = l.split_whitespace().collect();
        w.iter().any(|x| ["public", "private", "community"].contains(&x.trim_matches('"').to_ascii_lowercase().as_str()))
    };
    match family(vendor, text) {
        Family::Cisco => {
            if let Some(l) = find(&|l| l.starts_with("snmp-server community") && weak_community(l)) {
                add(Level::High, "SNMP с общеизвестным community", "Смените community на длинное случайное или перейдите на SNMPv3; ограничьте доступ ACL.", Some(l));
            } else if let Some(l) = find(&|l| l.starts_with("snmp-server community") && l.contains(" RW")) {
                add(Level::Medium, "SNMP с правом записи", "Запись по SNMPv1/v2c позволяет менять настройки тому, кто перехватит community. Оставьте RO или SNMPv3.", Some(l));
            }
            if let Some(l) = find(&|l| l.starts_with("transport input") && (l.contains("telnet") || l.ends_with(" all"))) {
                add(Level::High, "Разрешён вход по Telnet", "Пароль передаётся открытым текстом. На линиях vty: transport input ssh.", Some(l));
            }
            if let Some(l) = find(&|l| l.starts_with("enable password")) {
                add(Level::High, "enable password вместо enable secret", "Используйте enable secret (хеш), а enable password удалите.", Some(l));
            }
            if let Some(l) = find(&|l| l.starts_with("username") && (l.contains(" password 0 ") || l.contains(" password 7 ") || (l.contains(" password ") && !l.contains(" secret ")))) {
                add(Level::Medium, "Пароль пользователя в обратимом виде", "Тип 0/7 расшифровывается мгновенно. Используйте username … secret (тип 8/9).", Some(l));
            }
            if !has("service password-encryption") && lines.iter().any(|l| l.contains(" password ")) {
                add(Level::Low, "Нет service password-encryption", "Пароли в конфигурации видны открытым текстом любому, кто увидит копию.", None);
            }
            if let Some(l) = find(&|l| l == "ip http server") {
                add(Level::Medium, "Включён HTTP-сервер управления", "no ip http server; при необходимости — только ip http secure-server с ACL.", Some(l));
            }
            if !has("ntp server") && !has("ntp peer") && !has("sntp server") && !has("clock timezone") {
                add(Level::Low, "Не настроен NTP", "Без точного времени журналы с разных устройств не сопоставить. Добавьте ntp server.", None);
            }
            if !has("logging host") && !lines.iter().any(|l| l.starts_with("logging ") && l.split_whitespace().nth(1).is_some_and(|x| x.parse::<std::net::IpAddr>().is_ok())) && !has("logging server") {
                add(Level::Low, "Журналы не отправляются на сервер", "При сбое или взломе локальный журнал теряется. Добавьте logging host <адрес> (Syslog-сервер есть во вкладке «Серверы»).", None);
            }
            if lines.iter().any(|l| l.starts_with("ip ssh version 1")) {
                add(Level::High, "SSH версии 1", "SSHv1 небезопасен: ip ssh version 2.", find(&|l| l.starts_with("ip ssh version 1")));
            }
            if let Some(l) = find(&|l| l.starts_with("exec-timeout 0") || l == "exec-timeout 0 0") {
                add(Level::Low, "Сессии без тайм-аута", "Забытая сессия остаётся открытой навсегда. Задайте exec-timeout 10 0.", Some(l));
            }
            let portfast = lines.iter().any(|l| l.starts_with("spanning-tree portfast") && !l.contains("bpduguard"));
            let guard = lines.iter().any(|l| l.contains("bpduguard"));
            if portfast && !guard {
                add(Level::Medium, "PortFast без BPDU Guard", "Петля через пользовательский порт положит сегмент. spanning-tree portfast bpduguard default.", None);
            }
            if has("aaa new-model") && !has("aaa authentication login") {
                add(Level::Low, "aaa new-model без правил входа", "Проверьте aaa authentication login: может действовать вход без пароля.", None);
            }
            if !has("aaa new-model") && !has("login local") && !has("login authentication") && lines.iter().any(|l| l.starts_with("line vty")) && lines.iter().any(|l| l.starts_with("password ")) {
                add(Level::Low, "Вход на vty по общему паролю линии", "Нет учёта, кто входил. Заведите пользователей и login local (или TACACS+/RADIUS).", None);
            }
        }
        Family::Huawei => {
            if let Some(l) = find(&|l| l.starts_with("snmp-agent community") && weak_community(l)) {
                add(Level::High, "SNMP с общеизвестным community", "Смените community или используйте snmp-agent sys-info version v3.", Some(l));
            }
            if let Some(l) = find(&|l| l.starts_with("telnet server enable") || l.starts_with("telnet ipv6 server enable")) {
                add(Level::High, "Включён Telnet-сервер", "undo telnet server enable; вход только по stelnet (SSH).", Some(l));
            }
            if let Some(l) = find(&|l| l.contains("protocol inbound telnet") || l.contains("protocol inbound all")) {
                add(Level::High, "Разрешён вход по Telnet на VTY", "user-interface vty 0 4 → protocol inbound ssh.", Some(l));
            }
            if let Some(l) = find(&|l| l.starts_with("local-user") && l.contains("password simple")) {
                add(Level::High, "Пароль пользователя открытым текстом", "Используйте password irreversible-cipher.", Some(l));
            } else if let Some(l) = find(&|l| l.starts_with("local-user") && l.contains("password cipher")) {
                add(Level::Low, "Обратимое шифрование пароля", "password cipher расшифровывается; лучше irreversible-cipher.", Some(l));
            }
            if !has("ntp-service unicast-server") && !has("ntp unicast-server") {
                add(Level::Low, "Не настроен NTP", "ntp-service unicast-server <адрес>.", None);
            }
            if !has("info-center loghost") {
                add(Level::Low, "Журналы не отправляются на сервер", "info-center loghost <адрес> (Syslog-сервер есть во вкладке «Серверы»).", None);
            }
            if let Some(l) = find(&|l| l.starts_with("http server enable")) {
                add(Level::Medium, "Включён HTTP-сервер управления", "undo http server enable; при необходимости только HTTPS с ACL.", Some(l));
            }
            if lines.iter().any(|l| l.starts_with("stp edged-port enable")) && !has("stp bpdu-protection") {
                add(Level::Medium, "Граничные порты без BPDU-защиты", "stp bpdu-protection в системном виде.", None);
            }
            if let Some(l) = find(&|l| l.starts_with("idle-timeout 0")) {
                add(Level::Low, "Сессии без тайм-аута", "idle-timeout 10 0 на user-interface.", Some(l));
            }
        }
        Family::Mikrotik => {
            if let Some(l) = find(&|l| l.contains("/ip service") && l.contains("telnet") && !l.contains("disabled=yes")) {
                add(Level::High, "Включён Telnet", "/ip service disable telnet.", Some(l));
            }
            if !lines.iter().any(|l| l.contains("telnet") && l.contains("disabled=yes")) && !lines.iter().any(|l| l.contains("/ip service") && l.contains("telnet")) {
                add(Level::Medium, "Telnet, FTP, www, api не отключены явно", "В экспорт попадает только изменённое: по умолчанию эти службы включены. /ip service disable telnet,ftp,www,api.", None);
            }
            if let Some(l) = find(&|l| l.contains("/snmp community") && l.contains("name=public")) {
                add(Level::High, "SNMP с community public", "/snmp community set public name=<случайное> addresses=<сеть управления>.", Some(l));
            }
            if !lines.iter().any(|l| l.contains("/system ntp client") && l.contains("enabled=yes")) {
                add(Level::Low, "Не настроен NTP", "/system ntp client set enabled=yes servers=<адрес>.", None);
            }
            if !lines.iter().any(|l| l.contains("/system logging action") && l.contains("remote")) {
                add(Level::Low, "Журналы не отправляются на сервер", "/system logging action add name=remote target=remote remote=<адрес>.", None);
            }
            if lines.iter().any(|l| l.contains("/ip neighbor discovery-settings") && l.contains("discover-interface-list=all")) {
                add(Level::Low, "Обнаружение соседей на всех интерфейсах", "MNDP/CDP/LLDP на внешнем интерфейсе раскрывает модель и версию.", None);
            }
        }
        Family::Juniper => {
            if let Some(l) = find(&|l| l.starts_with("set system services telnet")) {
                add(Level::High, "Включён Telnet", "delete system services telnet.", Some(l));
            }
            if let Some(l) = find(&|l| l.starts_with("set snmp community") && weak_community(l)) {
                add(Level::High, "SNMP с общеизвестным community", "Смените community и ограничьте clients.", Some(l));
            }
            if !has("set system ntp server") {
                add(Level::Low, "Не настроен NTP", "set system ntp server <адрес>.", None);
            }
            if !has("set system syslog host") {
                add(Level::Low, "Журналы не отправляются на сервер", "set system syslog host <адрес> any warning.", None);
            }
            if lines.iter().any(|l| l.starts_with("set system services web-management http")) {
                add(Level::Medium, "Включено управление по HTTP", "Оставьте только https.", find(&|l| l.starts_with("set system services web-management http")));
            }
        }
        Family::Other => {
            if let Some(l) = find(&|l| l.to_ascii_lowercase().contains("community") && weak_community(l)) {
                add(Level::High, "SNMP с общеизвестным community", "Смените community или перейдите на SNMPv3.", Some(l));
            }
            if let Some(l) = find(&|l| l.to_ascii_lowercase().contains("telnet") && (l.contains("enable") || l.contains(" on"))) {
                add(Level::Medium, "Похоже, включён Telnet", "Отключите Telnet, оставьте SSH.", Some(l));
            }
        }
    }
    v.sort_by_key(|f| f.level);
    v
}

// ---------------------------------------------------------------------------
// Снятие копий
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    /// Устройство, итог: (путь новой версии или None — не изменилась, изменения, замечания).
    Done(String, Result<(Option<PathBuf>, Change, usize), String>),
}

/// Сохранить, если отличается от последней версии.
pub fn store(title: &str, text: &str) -> Result<(Option<PathBuf>, Change), String> {
    let text = normalize(text);
    let last = versions(title).into_iter().next();
    let mut change = Change { added: text.lines().count(), removed: 0 };
    if let Some(l) = &last {
        let old = std::fs::read_to_string(&l.path).unwrap_or_default();
        if old == text {
            return Ok((None, Change::default()));
        }
        change = diff(&old, &text, 0).1;
    }
    let dir = root().join(folder(title));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut path = dir.join(format!("{}.cfg", crate::session::compact_time(crate::session::now_unix())));
    let mut n = 1;
    while path.exists() {
        n += 1;
        path = dir.join(format!("{}-{n}.cfg", crate::session::compact_time(crate::session::now_unix())));
    }
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((Some(path), change))
}

/// Снять конфигурацию одного устройства.
pub async fn fetch(d: &Device) -> Result<(String, Vendor), String> {
    let first = d.vendor;
    let cmd = first.profile().config.to_string();
    let mut s = super::conn::run_commands(d, &[cmd], Duration::from_secs(30)).await?;
    // Производитель определился только при входе — повторяем нужной командой.
    if first == Vendor::Auto && s.vendor != Vendor::Auto && s.vendor.profile().config != first.profile().config {
        let mut d2 = d.clone();
        d2.vendor = s.vendor;
        s = super::conn::run_commands(&d2, &[s.vendor.profile().config.to_string()], Duration::from_secs(30)).await?;
    }
    let out = s.outputs.into_iter().next().map(|o| o.1).unwrap_or_default();
    if out.contains("Invalid input") || out.contains("Unrecognized command") || out.contains("Error: Unrecognized") {
        return Err(format!("команда {} не принята; укажите производителя вручную", s.vendor.profile().config));
    }
    if out.lines().filter(|l| !l.trim().is_empty()).count() < 3 {
        return Err("устройство вернуло пустую конфигурацию (не хватает прав? нужен enable?)".into());
    }
    Ok((out, s.vendor))
}

pub async fn run(devs: Vec<Device>, sink: Sink<Event>, cancel: CancellationToken) {
    super::for_each_limited(devs, 6, &cancel, |d| {
        let sink = sink.clone();
        async move {
            let t = d.title();
            sink.send(Event::Log(format!("{t}: подключение…")));
            let r = match fetch(&d).await {
                Ok((text, vendor)) => store(&t, &text).map(|(p, ch)| {
                    let findings = audit(&normalize(&text), vendor).len();
                    (p, ch, findings)
                }),
                Err(e) => Err(e),
            };
            sink.send(Event::Done(t, r));
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const CISCO: &str = "Building configuration...\n\nCurrent configuration : 1234 bytes\n!\n! Last configuration change at 10:00\nhostname sw1\nenable password cisco\nusername admin password 7 0822455D0A16\nsnmp-server community public RO\nip http server\ninterface Gi0/1\n spanning-tree portfast\nline vty 0 4\n transport input telnet ssh\n exec-timeout 0 0\nend\n";

    #[test]
    fn cisco_audit() {
        let f = audit(&normalize(CISCO), Vendor::CiscoIos);
        let t: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        for want in ["SNMP с общеизвестным community", "Разрешён вход по Telnet", "enable password вместо enable secret", "Включён HTTP-сервер управления", "Не настроен NTP", "PortFast без BPDU Guard", "Сессии без тайм-аута"] {
            assert!(t.contains(&want), "нет «{want}» в {t:?}");
        }
        assert_eq!(f[0].level, Level::High);
    }

    #[test]
    fn huawei_audit() {
        let cfg = "#\nsysname core\n#\ntelnet server enable\nsnmp-agent community read public\nlocal-user admin password simple Huawei123\ninfo-center loghost 10.0.0.5\nntp-service unicast-server 10.0.0.1\n#\nreturn\n";
        let f = audit(cfg, Vendor::Auto);
        let t: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert!(t.contains(&"Включён Telnet-сервер"));
        assert!(t.contains(&"Пароль пользователя открытым текстом"));
        assert!(!t.contains(&"Не настроен NTP"));
        assert!(!t.contains(&"Журналы не отправляются на сервер"));
    }

    #[test]
    fn normalize_and_diff() {
        let n = normalize(CISCO);
        assert!(n.starts_with("!\nhostname sw1"), "{n}");
        let new = n.replace("snmp-server community public RO\n", "snmp-server community S3cr3t RO\nntp server 10.0.0.1\n");
        let (lines, ch) = diff(&n, &new, 1);
        assert_eq!((ch.added, ch.removed), (2, 1));
        assert!(lines.iter().any(|(s, t)| *s == '-' && t.contains("public")));
        assert_eq!(pretty("20261118-143005"), "2026-11-18 14:30:05 UTC");
    }
}
