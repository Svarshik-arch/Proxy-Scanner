//! Пресеты настроек: встроенные и пользовательские, для каждого инструмента и общие
//! («Открытый контур», «Закрытый контур»), применяемые сразу ко всем инструментам.
//!
//! Пресет — JSON-объект с изменяемыми полями конфигурации. Встроенные пресеты меняют
//! только нужные поля (остальное остаётся как есть), пользовательские сохраняют все поля,
//! кроме сетевых параметров машины и паролей.

use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const FILE_NAME: &str = "proxy-scanner-presets.json";
/// Общие пресеты, затрагивающие все инструменты.
pub const ALL_TOOLS: &str = "*";

/// Идентификаторы инструментов (ключи в общих пресетах и в командной строке).
pub const TOOLS: &[(&str, &str)] = &[
    ("proxy", "Прокси, обход, PAC"),
    ("host", "Хост"),
    ("mtr", "MTR"),
    ("discovery", "Узлы"),
    ("dns", "DNS"),
    ("http", "HTTP"),
    ("services", "Сервисы"),
    ("tls", "TLS-аудит"),
    ("ad", "Домен AD"),
    ("audit", "Аудит"),
    ("monitor", "Мониторинг"),
    ("matrix", "Доступность"),
    ("urlcheck", "Проверка URL"),
    ("shares", "Общие ресурсы"),
    ("capture", "Трафик"),
];

/// Поля, которые никогда не попадают в пользовательский пресет: они описывают
/// конкретную машину или содержат секреты.
pub fn never_saved(tool: &str) -> &'static [&'static str] {
    match tool {
        "proxy" => &["source_ip", "router_ip", "router_mac", "adapter", "masscan_path", "proxy_pass"],
        "urlcheck" | "shares" => &["password"],
        "http" => &["proxy_pass"],
        _ => &[],
    }
}

/// Поля с целями (адреса, имена, URL) — сохраняются по желанию.
pub fn target_fields(tool: &str) -> &'static [&'static str] {
    match tool {
        "proxy" => &["targets"],
        "mtr" => &["target"],
        "dns" => &["names"],
        "http" => &["url"],
        "discovery" | "services" | "tls" | "audit" => &["targets"],
        "ad" => &["domain", "dcs"],
        "monitor" => &["checks"],
        "matrix" => &["rules"],
        "urlcheck" => &["proxies", "urls"],
        "shares" => &["targets"],
        _ => &[],
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preset {
    pub tool: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub values: Value,
    #[serde(skip)]
    pub builtin: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    format: String,
    #[serde(default)]
    presets: Vec<Preset>,
}

/// Рекурсивное слияние: поля `patch` заменяют поля `base`.
pub fn merge(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                match b.get_mut(k) {
                    Some(bv) if bv.is_object() && v.is_object() => merge(bv, v),
                    _ => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (b, p) => *b = p.clone(),
    }
}

/// Применение значений к конфигурации. Неизвестные поля игнорируются,
/// значения неверного типа дают ошибку (конфигурация не меняется).
pub fn apply<T: Serialize + DeserializeOwned>(cfg: &mut T, values: &Value) -> Result<(), String> {
    let mut v = serde_json::to_value(&*cfg).map_err(|e| e.to_string())?;
    merge(&mut v, values);
    *cfg = serde_json::from_value(v).map_err(|e| format!("пресет не подходит: {e}"))?;
    Ok(())
}

/// Снимок конфигурации для сохранения в пресет.
pub fn snapshot<T: Serialize>(cfg: &T, tool: &str, with_targets: bool) -> Value {
    let mut v = serde_json::to_value(cfg).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        for k in never_saved(tool) {
            m.remove(*k);
        }
        if !with_targets {
            for k in target_fields(tool) {
                m.remove(*k);
            }
        }
    }
    v
}

const PROXY_ALL_PORTS: &str = "80,81,443,808,1080,1081,1085,3128,3129,3130,3131,4145,4153,5555,6588,6666,7777,8000,8001,8008,8010,8080,8081,8082,8083,8085,8088,8090,8118,8123,8181,8443,8800,8880,8888,8889,9000,9050,9080,9090,9091,9150,9999,10080,10800,12345,20000,30000,31280,32768,53281,60000";

fn p(tool: &str, name: &str, description: &str, values: Value) -> Preset {
    Preset {
        tool: tool.into(),
        name: name.into(),
        description: description.into(),
        values,
        builtin: true,
    }
}

pub fn builtin() -> Vec<Preset> {
    vec![
        // --- Общие ---
        p(ALL_TOOLS, "Открытый контур", "Есть выход в интернет: публичные тестовые узлы (example.com, badssl.com, portquiz.net) и публичные DNS для сравнения", json!({
            "proxy": {
                "test_http_url": "http://example.com/", "test_tls_host": "example.com:443",
                "inspect_quality": true,
                "badcert_hosts": "expired.badssl.com\nself-signed.badssl.com\nuntrusted-root.badssl.com\nwrong.host.badssl.com",
                "egress_target": "portquiz.net", "egress_dns": "8.8.8.8, 1.1.1.1, 77.88.8.8", "egress_domain": "example.com"
            },
            "dns": { "servers": "system, 8.8.8.8, 1.1.1.1, 77.88.8.8" },
        })),
        p(ALL_TOOLS, "Закрытый контур", "Интернета нет: никаких обращений к внешним узлам. Только системные DNS; тестовые URL, слушатель обхода и узлы с плохими сертификатами задайте свои внутренние", json!({
            "proxy": {
                "inspect_quality": false, "badcert_hosts": "",
                "egress_target": "", "egress_dns": "", "egress_domain": ""
            },
            "dns": { "servers": "system", "transport": "Udp" },
            "http": { "verify_tls": false },
        })),
        // --- Прокси ---
        p("proxy", "Порты: основные прокси", "13 самых частых портов прокси-серверов", json!({ "ports": "80,808,1080,3128,3129,8000,8080,8081,8088,8118,8443,8888,9090" })),
        p("proxy", "Порты: все популярные", "52 порта: HTTP-прокси, SOCKS, Tor, Squid, панели управления", json!({ "ports": PROXY_ALL_PORTS })),
        p("proxy", "masscan: максимальная скорость", "100 000 пакетов/с, ожидание 3 с. Нужны Npcap/libpcap и права администратора", json!({ "mode": "Masscan", "rate": 100000, "wait_secs": 3 })),
        p("proxy", "masscan: аккуратно", "2 000 пакетов/с, ожидание 10 с — для медленных каналов и чувствительных IDS", json!({ "mode": "Masscan", "rate": 2000, "wait_secs": 10 })),
        p("proxy", "TCP-connect: быстро", "2 000 одновременных подключений, таймаут 400 мс, без повторов", json!({ "mode": "TcpConnect", "tcp_concurrency": 2000, "tcp_timeout_ms": 400, "tcp_retries": 0 })),
        p("proxy", "TCP-connect: надёжно", "300 подключений, таймаут 1,5 с, 2 повтора; диагностика с запасом по времени", json!({
            "mode": "TcpConnect", "tcp_concurrency": 300, "tcp_timeout_ms": 1500, "tcp_retries": 2,
            "probe_timeout_ms": 8000, "probe_retries": 3
        })),
        p("proxy", "Диагностика: быстро", "128 проверок параллельно, таймаут 2,5 с, без проверки качества инспекции", json!({
            "probe_concurrency": 128, "probe_timeout_ms": 2500, "probe_retries": 1, "inspect_quality": false
        })),
        p("proxy", "Вход: текущий пользователь Windows", "NTLM/Kerberos через SSPI без пароля", json!({ "auth_mode": "Auto", "auth_current_user": true })),
        // --- MTR ---
        p("mtr", "ICMP, 10 циклов", "Обычная трассировка с наблюдением", json!({ "mode": "Icmp", "cycles": 10, "interval_ms": 1000, "timeout_ms": 1500, "pmtu": false })),
        p("mtr", "Непрерывно", "Наблюдение до остановки — ловить плавающие потери", json!({ "cycles": 0, "interval_ms": 1000 })),
        p("mtr", "Быстрая трассировка", "Один проход, как tracert без ожиданий", json!({ "cycles": 1, "interval_ms": 100, "timeout_ms": 1000 })),
        p("mtr", "UDP (Linux, без прав)", "Пробы UDP 33434+, как traceroute в Linux", json!({ "mode": "Udp", "port": 33434 })),
        p("mtr", "TCP 443 до узла", "Время установления TCP-соединения — когда ICMP закрыт", json!({ "mode": "Tcp", "port": 443, "cycles": 20, "interval_ms": 500 })),
        p("mtr", "Поиск MTU (VPN, туннели)", "Найти MTU пути с DF, затем 3 цикла трассировки", json!({ "pmtu": true, "df": true, "cycles": 3 })),
        // --- Узлы ---
        p("discovery", "Быстро: ICMP + ARP", "Без NetBIOS/mDNS/SSDP и обратного DNS, таймаут 600 мс", json!({
            "icmp": true, "arp": true, "netbios": false, "mdns": false, "ssdp": false, "reverse_dns": false,
            "tcp_ports": "80,443,445", "timeout_ms": 600, "concurrency": 256
        })),
        p("discovery", "Полно: имена и признаки ОС", "Все методы, имена из DNS, NetBIOS и mDNS", json!({
            "icmp": true, "arp": true, "netbios": true, "mdns": true, "ssdp": true, "reverse_dns": true,
            "tcp_ports": "22,80,135,139,443,445,3389,8080", "timeout_ms": 1000
        })),
        p("discovery", "ICMP закрыт: по TCP", "Узлы, которые не отвечают на ping, ищутся по типичным портам", json!({
            "icmp": false, "tcp_ports": "21,22,23,25,53,80,88,110,135,139,143,389,443,445,3389,5985,8080,9100", "timeout_ms": 1200
        })),
        p("discovery", "Тихо", "Без широковещания и мультикаста, 32 узла параллельно", json!({ "ssdp": false, "mdns": false, "netbios": false, "concurrency": 32 })),
        // --- DNS ---
        p("dns", "A/AAAA через системные", "Как nslookup", json!({ "types": "A AAAA", "servers": "system", "transport": "Udp", "dnssec": false })),
        p("dns", "Все основные записи", "A, AAAA, CNAME, MX, NS, TXT, SOA, CAA", json!({ "types": "A AAAA CNAME MX NS TXT SOA CAA" })),
        p("dns", "Сравнить системные и публичные", "Расхождения ответов (split-horizon, подмена)", json!({ "servers": "system, 8.8.8.8, 1.1.1.1, 77.88.8.8" })),
        p("dns", "AD: SRV-записи домена", "Контроллеры, Kerberos, GC; {domain} — DNS-суффикс этой машины", json!({
            "names": "_ldap._tcp.dc._msdcs.{domain}\n_kerberos._tcp.{domain}\n_kpasswd._tcp.{domain}\n_gc._tcp.{domain}\n_ldap._tcp.pdc._msdcs.{domain}",
            "types": "SRV", "servers": "system"
        })),
        p("dns", "Почта: MX, SPF, DMARC", "Укажите домен и _dmarc.домен", json!({ "types": "MX TXT" })),
        p("dns", "DNSSEC", "Бит DO, записи DNSKEY/DS, флаг AD резолвера", json!({ "dnssec": true, "types": "A DNSKEY DS" })),
        p("dns", "DoT и DoH (открытый контур)", "Шифрованный DNS: Cloudflare и Google", json!({
            "servers": "tls://1.1.1.1, tls://8.8.8.8, https://cloudflare-dns.com/dns-query, https://dns.google/dns-query"
        })),
        p("dns", "Передача зоны (AXFR)", "Проверка, отдают ли ваши серверы зону целиком", json!({ "types": "AXFR", "transport": "Tcp" })),
        // --- HTTP ---
        p("http", "GET с замером времени", "Напрямую, с переходами", json!({ "method": "GET", "proxy_mode": "Direct", "follow_redirects": true, "repeat": 1 })),
        p("http", "Только заголовки (HEAD)", "", json!({ "method": "HEAD" })),
        p("http", "Через прокси с NTLM/Kerberos", "Вход под текущим пользователем Windows (SSPI)", json!({ "proxy_mode": "Manual", "proxy_auth": "Auto", "proxy_current_user": true })),
        p("http", "Строгая проверка сертификата", "Как curl без -k: ошибка, если цепочка не доверена системой", json!({ "verify_tls": true })),
        p("http", "Стабильность: 10 повторов", "Разброс времени ответа", json!({ "repeat": 10, "follow_redirects": false })),
        // --- Сервисы ---
        p("services", "Основные TCP и UDP", "32 TCP-порта и 7 UDP", json!({
            "tcp_ports": "21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6379,8080,8443,9200,11211,27017",
            "udp_ports": "53,123,137,161,1434,1900,5353", "active_probes": true
        })),
        p("services", "Windows и AD", "Kerberos, LDAP, SMB, RPC, WinRM, GC", json!({
            "tcp_ports": "53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986,9389", "udp_ports": "53,88,123,137,389"
        })),
        p("services", "Веб", "HTTP/HTTPS на типичных портах", json!({
            "tcp_ports": "80,81,443,591,2375,3000,5000,8000,8008,8080,8081,8088,8443,8888,9000,9090,9200,9443", "udp_ports": ""
        })),
        p("services", "Базы данных", "MSSQL, Oracle, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch…", json!({
            "tcp_ports": "1433,1521,3306,5432,5984,6379,7474,8086,9042,9200,11211,27017", "udp_ports": "1434"
        })),
        p("services", "Сетевое оборудование", "SSH, Telnet, веб-интерфейсы, Winbox, NETCONF, SNMP, TFTP", json!({
            "tcp_ports": "22,23,80,443,830,2000,8291,8728,8729", "udp_ports": "69,161,500,1900"
        })),
        p("services", "Только UDP", "", json!({ "tcp_ports": "", "udp_ports": "53,69,123,137,161,500,1434,1900,5353" })),
        p("services", "Только баннеры", "Без активных проб: подключиться и ждать приветствие", json!({ "active_probes": false })),
        // --- TLS ---
        p("tls", "Полный аудит", "Версии, все шифры, цепочка", json!({ "versions": true, "ciphers": true })),
        p("tls", "Быстро: только версии", "По одному рукопожатию на версию", json!({ "versions": true, "ciphers": false })),
        p("tls", "Только сертификаты", "Сроки и доверие по всей сети", json!({ "versions": false, "ciphers": false, "concurrency": 64 })),
        // --- AD ---
        p("ad", "Обычная проверка", "Домен этой машины, системные DNS", json!({ "domain": "", "dcs": "", "dns_servers": "system", "check_ldaps": true })),
        p("ad", "Медленная сеть (филиал, VPN)", "Таймаут 8 с", json!({ "timeout_ms": 8000 })),
        // --- Аудит ---
        p("audit", "Полный аудит", "Все порты и дополнительные проверки", json!({
            "tcp_ports": crate::tools::audit::DEFAULT_TCP, "udp_ports": "53,123,161,1434", "ftp_anonymous": true, "tls_versions": true
        })),
        p("audit", "Быстро: Windows-сеть", "SMB, RDP, Telnet, SNMP, LDAP", json!({ "tcp_ports": "23,139,445,389,3389,5985", "udp_ports": "161", "tls_versions": false })),
        p("audit", "Серверы и СУБД", "СУБД, кэши, Docker, Elasticsearch", json!({ "tcp_ports": "1433,2375,3306,5432,6379,9200,11211,27017", "udp_ports": "1434" })),
        p("audit", "Сетевое оборудование", "Telnet, SSH, веб-интерфейсы, SNMP", json!({ "tcp_ports": "22,23,80,443,8080,8443", "udp_ports": "161" })),
        p("audit", "Без входа на FTP", "Не пробовать вход anonymous", json!({ "ftp_anonymous": false })),
        // --- Проверка URL ---
        p("urlcheck", "Типовые категории (открытый контур)", "Соцсети, анонимайзеры, облачные хранилища — что должно блокироваться", json!({
            "urls": "+ https://www.gosuslugi.ru/\n- https://www.torproject.org/\n- https://www.dropbox.com/\n- https://mega.nz/\n- https://web.telegram.org/\n- https://www.speedtest.net/"
        })),
        p("urlcheck", "Через прокси под текущим пользователем", "NTLM/Kerberos через SSPI", json!({ "auth": "Auto", "current_user": true })),
        // --- Трафик ---
        p("capture", "Прослушивание служебных протоколов", "Коммутатор и порт (LLDP/CDP), DHCP, STP, ARP, запросы имён", json!({
            "filter": crate::tools::capture::PASSIVE_FILTER, "seconds": 120
        })),
        p("capture", "Весь трафик, 1 минута", "Для сохранения в pcapng и разбора в Wireshark", json!({ "filter": "", "seconds": 60 })),
        p("capture", "DNS и TLS (какие сайты открываются)", "", json!({ "filter": "udp port 53 or tcp port 443", "seconds": 0 })),
        // --- Общие ресурсы ---
        p("shares", "Анонимный доступ", "Что видно и доступно без пароля — находка для аудита", json!({ "login": "Anonymous", "check_access": true })),
        p("shares", "Только SMB", "", json!({ "smb": true, "nfs": false })),
        // --- Матрица доступности ---
        p("matrix", "Обычная проверка", "Таймаут 2 с, один повтор", json!({ "timeout_ms": 2000, "retries": 1 })),
        p("matrix", "Медленные каналы (филиалы, VPN)", "Таймаут 5 с, два повтора", json!({ "timeout_ms": 5000, "retries": 2 })),
        p("matrix", "Доступ к контроллерам домена", "Порты, нужные клиентам AD; {domain} не подставляется — впишите имя контроллера", json!({
            "rules": "dc01:53 open\ndc01:88 open\ndc01:135 open\ndc01:389 open\ndc01:445 open\ndc01:464 open\ndc01:636 open\ndc01:3268 open"
        })),
        // --- Мониторинг ---
        p("monitor", "Каждую минуту", "", json!({ "interval_s": 60 })),
        p("monitor", "Часто: каждые 10 с", "Для разбора инцидента", json!({ "interval_s": 10, "warn_ms": 300 })),
        p("monitor", "Редко: раз в 15 минут", "Сертификаты и доступность сервисов", json!({ "interval_s": 900 })),
        p("monitor", "Основные службы домена", "{domain} — DNS-суффикс этой машины; добавьте свои адреса", json!({
            "checks": "dns _ldap._tcp.dc._msdcs.{domain} type=SRV\ntcp {domain}:389\ntcp {domain}:88"
        })),
        p("tls", "Все TLS-порты", "443, 465, 636, 853, 993, 995, 3269, 5986, 8443, 9443", json!({ "ports": "443,465,636,853,993,995,3269,5986,8443,9443" })),
    ]
}

pub fn default_path() -> PathBuf {
    crate::session::default_path()
        .parent()
        .map(|d| d.join(FILE_NAME))
        .unwrap_or_else(|| PathBuf::from(FILE_NAME))
}

/// Хранилище пресетов: встроенные + пользовательские из файла рядом с программой.
#[derive(Debug, Clone)]
pub struct Store {
    builtin: Vec<Preset>,
    pub user: Vec<Preset>,
    pub path: PathBuf,
}

impl Store {
    pub fn load(path: PathBuf) -> (Self, Option<String>) {
        let mut store = Store {
            builtin: builtin(),
            user: Vec::new(),
            path,
        };
        let mut warn = None;
        if let Ok(text) = std::fs::read_to_string(&store.path) {
            match serde_json::from_str::<File>(&text) {
                Ok(f) => store.user = f.presets,
                Err(e) => warn = Some(format!("{}: {e}", store.path.display())),
            }
        }
        (store, warn)
    }

    pub fn save(&self) -> Result<(), String> {
        let file = File {
            format: "proxy-scanner-presets".into(),
            presets: self.user.clone(),
        };
        let text = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("{}: {e}", self.path.display()))
    }

    /// Пресеты инструмента: сначала пользовательские, затем встроенные.
    pub fn for_tool(&self, tool: &str) -> Vec<&Preset> {
        self.user
            .iter()
            .filter(|p| p.tool == tool)
            .chain(self.builtin.iter().filter(|p| p.tool == tool))
            .collect()
    }

    pub fn find(&self, tool: &str, name: &str) -> Option<&Preset> {
        let lower = name.to_lowercase();
        self.for_tool(tool)
            .into_iter()
            .find(|p| p.name.to_lowercase() == lower)
            .or_else(|| self.for_tool(tool).into_iter().find(|p| p.name.to_lowercase().contains(&lower)))
    }

    pub fn upsert(&mut self, preset: Preset) {
        self.user.retain(|p| !(p.tool == preset.tool && p.name == preset.name));
        self.user.insert(0, Preset { builtin: false, ..preset });
    }

    pub fn remove(&mut self, tool: &str, name: &str) {
        self.user.retain(|p| !(p.tool == tool && p.name == name));
    }

    /// Импорт пресетов из файла (одиночный пресет или файл хранилища).
    pub fn import(&mut self, path: &std::path::Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let list: Vec<Preset> = if let Ok(f) = serde_json::from_str::<File>(&text)
            && !f.presets.is_empty()
        {
            f.presets
        } else if let Ok(p) = serde_json::from_str::<Preset>(&text) {
            vec![p]
        } else {
            serde_json::from_str::<Vec<Preset>>(&text).map_err(|e| format!("не файл пресетов: {e}"))?
        };
        let n = list.len();
        for p in list {
            self.upsert(p);
        }
        Ok(n)
    }

    pub fn export(&self, presets: &[Preset], path: &std::path::Path) -> Result<(), String> {
        let file = File {
            format: "proxy-scanner-presets".into(),
            presets: presets.to_vec(),
        };
        std::fs::write(path, serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?)
            .map_err(|e| format!("{}: {e}", path.display()))
    }
}

// ---------------------------------------------------------------------------
// Панель пресетов в интерфейсе
// ---------------------------------------------------------------------------

/// Состояние окна «Сохранить пресет».
#[derive(Debug, Default, Clone)]
pub struct SaveDialog {
    pub open: bool,
    pub tool: String,
    pub name: String,
    pub description: String,
    pub with_targets: bool,
}

/// Что сделал пользователь в панели пресетов.
pub enum BarAction {
    Apply(Preset),
    Delete(Preset),
    Save,
    Import,
    Export,
}

/// Кнопка «Пресеты ▾» со списком, сохранением и удалением. Возвращает действие.
pub fn bar(ui: &mut egui::Ui, store: &Store, tool: &str) -> Option<BarAction> {
    let mut action = None;
    ui.menu_button("Пресеты ▾", |ui| {
        ui.set_min_width(280.0);
        let list = store.for_tool(tool);
        let mut user_shown = false;
        for p in &list {
            if !p.builtin && !user_shown {
                ui.weak("Мои");
                user_shown = true;
            }
            if p.builtin && user_shown {
                ui.separator();
                user_shown = false;
            }
            ui.horizontal(|ui| {
                let label = if p.builtin { p.name.clone() } else { format!("★ {}", p.name) };
                let mut r = ui.button(label);
                if !p.description.is_empty() {
                    r = r.on_hover_text(&p.description);
                }
                if r.clicked() {
                    action = Some(BarAction::Apply((*p).clone()));
                    ui.close();
                }
                if !p.builtin && ui.small_button("🗑").on_hover_text("Удалить пресет").clicked() {
                    action = Some(BarAction::Delete((*p).clone()));
                    ui.close();
                }
            });
        }
        ui.separator();
        if ui.button("💾 Сохранить текущие настройки…").clicked() {
            action = Some(BarAction::Save);
            ui.close();
        }
        if ui.button("Импорт из файла…").clicked() {
            action = Some(BarAction::Import);
            ui.close();
        }
        if ui.button("Экспорт моих пресетов…").clicked() {
            action = Some(BarAction::Export);
            ui.close();
        }
    });
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    #[serde(default)]
    struct Cfg {
        targets: String,
        rate: u32,
        nested: Inner,
    }
    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    #[serde(default)]
    struct Inner {
        a: u32,
        b: u32,
    }

    #[test]
    fn apply_merges_partially() {
        let mut c = Cfg {
            targets: "10.0.0.0/24".into(),
            rate: 1,
            nested: Inner { a: 1, b: 2 },
        };
        apply(&mut c, &json!({ "rate": 5, "nested": { "b": 9 }, "unknown": true })).unwrap();
        assert_eq!(c, Cfg { targets: "10.0.0.0/24".into(), rate: 5, nested: Inner { a: 1, b: 9 } });
        // Неверный тип — ошибка, конфигурация не меняется.
        assert!(apply(&mut c, &json!({ "rate": "много" })).is_err());
        assert_eq!(c.rate, 5);
    }

    #[test]
    fn snapshot_excludes() {
        let s = crate::model::Settings {
            source_ip: "10.0.0.5".into(),
            proxy_pass: "secret".into(),
            targets: "10.0.0.0/8".into(),
            ..Default::default()
        };
        let v = snapshot(&s, "proxy", false);
        assert!(v.get("source_ip").is_none());
        assert!(v.get("proxy_pass").is_none());
        assert!(v.get("targets").is_none());
        assert!(v.get("rate").is_some());
        assert!(snapshot(&s, "proxy", true).get("targets").is_some());
    }

    /// Каждый встроенный пресет применяется к своей конфигурации без ошибок.
    #[test]
    fn builtins_are_valid() {
        fn check<T: Serialize + DeserializeOwned + Default>(v: &Value, what: &str) {
            let mut c = T::default();
            apply(&mut c, v).unwrap_or_else(|e| panic!("{what}: {e}"));
        }
        fn check_tool(tool: &str, v: &Value, what: &str) {
            match tool {
                "proxy" => check::<crate::model::Settings>(v, what),
                "mtr" => check::<crate::tools::mtr::Config>(v, what),
                "discovery" => check::<crate::tools::discovery::Config>(v, what),
                "dns" => check::<crate::tools::dns::Config>(v, what),
                "http" => check::<crate::tools::http::Config>(v, what),
                "services" => check::<crate::tools::services::Config>(v, what),
                "tls" => check::<crate::tools::tlsaudit::Config>(v, what),
                "ad" => check::<crate::tools::ad::Config>(v, what),
                "audit" => check::<crate::tools::audit::Config>(v, what),
                "monitor" => check::<crate::tools::monitor::Config>(v, what),
                "matrix" => check::<crate::tools::matrix::Config>(v, what),
                "urlcheck" => check::<crate::tools::urlcheck::Config>(v, what),
                "shares" => check::<crate::tools::shares::Config>(v, what),
                "capture" => check::<crate::tools::capture::Config>(v, what),
                other => panic!("{what}: неизвестный инструмент {other}"),
            }
        }
        for p in builtin() {
            if p.tool == ALL_TOOLS {
                for (tool, v) in p.values.as_object().unwrap() {
                    check_tool(tool, v, &p.name);
                }
            } else {
                check_tool(&p.tool, &p.values, &p.name);
            }
        }
    }

    #[test]
    fn store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ps-presets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        let (mut st, warn) = Store::load(path.clone());
        assert!(warn.is_none());
        st.upsert(Preset {
            tool: "dns".into(),
            name: "Мой".into(),
            description: String::new(),
            values: json!({ "types": "MX" }),
            builtin: false,
        });
        st.save().unwrap();
        let (st2, _) = Store::load(path.clone());
        assert_eq!(st2.for_tool("dns")[0].name, "Мой");
        assert!(!st2.for_tool("dns")[0].builtin);
        assert!(st2.find("dns", "dnssec").unwrap().builtin);
        let exported = dir.join("one.json");
        st2.export(&st2.user, &exported).unwrap();
        let (mut st3, _) = Store::load(dir.join("none.json"));
        assert_eq!(st3.import(&exported).unwrap(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
