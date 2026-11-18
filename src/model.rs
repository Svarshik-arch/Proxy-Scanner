//! Общие типы данных: настройки, строки таблицы, события фоновых задач.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::netdetect::NetDetect;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    /// Внешний masscan (Npcap/libpcap + права администратора/root).
    Masscan,
    /// Встроенный TCP-connect сканер на tokio.
    TcpConnect,
}

/// Сохраняемые настройки приложения.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub mode: ScanMode,
    pub targets: String,
    pub ports: String,

    // masscan
    pub masscan_path: String,
    pub rate: u32,
    pub wait_secs: u32,
    pub source_ip: String,
    pub router_ip: String,
    pub router_mac: String,
    pub adapter: String,
    pub extra_args: String,

    // tcp-connect
    pub tcp_concurrency: usize,
    pub tcp_timeout_ms: u64,
    /// TCP-connect: повторов при таймауте (0 — без повторов).
    pub tcp_retries: u32,

    // диагностика
    pub auto_probe: bool,
    pub probe_concurrency: usize,
    pub probe_timeout_ms: u64,
    /// Диагностика: повторов при сбоях и таймаутах.
    pub probe_retries: u32,
    pub test_http_url: String,
    pub test_tls_host: String,
    pub reference_fp: String,
    pub policy_rules: String,
    pub block_marker: String,
    /// Проверять, не скрывает ли SSL-инспекция ошибки сертификатов сайтов.
    pub inspect_quality: bool,
    /// Узлы с заведомо плохими сертификатами (по одному в строке, host[:port]).
    pub badcert_hosts: String,
    // Проверка обхода прокси
    pub egress_target: String,
    pub egress_ports: String,
    pub egress_dns: String,
    pub egress_domain: String,
    pub egress_timeout_ms: u64,
    /// Режим аутентификации на прокси.
    pub auth_mode: crate::auth::AuthMode,
    /// Windows: входить под текущим пользователем (Kerberos/NTLM без пароля).
    pub auth_current_user: bool,
    pub proxy_domain: String,
    pub proxy_user: String,
    #[serde(skip)]
    pub proxy_pass: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: ScanMode::TcpConnect,
            targets: String::new(),
            ports: "80,808,1080,3128,3129,8000,8080,8081,8088,8118,8443,8888,9090".into(),
            masscan_path: crate::util::MASSCAN_DEFAULT.into(),
            rate: 1000,
            wait_secs: 5,
            source_ip: String::new(),
            router_ip: String::new(),
            router_mac: String::new(),
            adapter: String::new(),
            extra_args: String::new(),
            tcp_concurrency: 500,
            tcp_timeout_ms: 800,
            tcp_retries: 0,
            auto_probe: true,
            probe_concurrency: 32,
            probe_timeout_ms: 4000,
            probe_retries: 2,
            test_http_url: "http://example.com/".into(),
            test_tls_host: "example.com:443".into(),
            reference_fp: String::new(),
            policy_rules: String::new(),
            block_marker: String::new(),
            inspect_quality: true,
            badcert_hosts: "expired.badssl.com\nself-signed.badssl.com\nuntrusted-root.badssl.com\nwrong.host.badssl.com".into(),
            egress_target: "portquiz.net".into(),
            egress_ports: "21,22,23,25,53,80,110,143,443,445,465,587,993,995,1080,1194,1723,3128,3389,5222,8080,8443,9001".into(),
            egress_dns: "8.8.8.8, 1.1.1.1, 77.88.8.8".into(),
            egress_domain: "example.com".into(),
            egress_timeout_ms: 3000,
            auth_mode: crate::auth::AuthMode::Auto,
            auth_current_user: true,
            proxy_domain: String::new(),
            proxy_user: String::new(),
            proxy_pass: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProxyKind {
    Unknown,
    /// Порт открыт, но ни на HTTP, ни на SOCKS не отвечает.
    NotProxy,
    /// Обычный веб-сервер (не проксирует).
    HttpServer,
    HttpProxy,
    Socks5,
    Socks4,
}

impl ProxyKind {
    pub fn label(self) -> &'static str {
        match self {
            ProxyKind::Unknown => "—",
            ProxyKind::NotProxy => "не прокси",
            ProxyKind::HttpServer => "веб-сервер",
            ProxyKind::HttpProxy => "HTTP-прокси",
            ProxyKind::Socks5 => "SOCKS5",
            ProxyKind::Socks4 => "SOCKS4",
        }
    }

    pub fn is_proxy(self) -> bool {
        matches!(
            self,
            ProxyKind::HttpProxy | ProxyKind::Socks5 | ProxyKind::Socks4
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SslInspection {
    /// Проверка не выполнялась / невозможна.
    Unknown,
    /// Сертификат через прокси совпадает с эталонным.
    No,
    /// Сертификат получен, но эталона для сравнения нет.
    NoReference,
    /// Сертификат подменён — активна SSL-инспекция.
    Yes,
}

impl SslInspection {
    pub fn label(self) -> &'static str {
        match self {
            SslInspection::Unknown => "—",
            SslInspection::No => "нет",
            SslInspection::NoReference => "? (нет эталона)",
            SslInspection::Yes => "ДА",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RowState {
    Found,
    Probing,
    Done,
    Error,
}

impl RowState {
    pub fn label(self) -> &'static str {
        match self {
            RowState::Found => "найден",
            RowState::Probing => "проверка…",
            RowState::Done => "готово",
            RowState::Error => "ошибка",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
    pub chain_len: usize,
    pub self_signed: bool,
    /// Срок действия истёк или ещё не наступил.
    pub expired: bool,
    /// Имена, на которые выдан сертификат (CN и SAN).
    pub names: Vec<String>,
}

/// Результат проверки того, как SSL-инспекция обходится с плохим сертификатом сайта.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InspectVerdict {
    /// Прокси переподписал плохой сертификат своим CA — пользователь не увидит ошибку.
    Masked,
    /// Пользователю передан исходный (плохой) сертификат или явная ошибка.
    PassedThrough,
    /// Прокси заблокировал соединение.
    Blocked,
    /// Проверить не удалось (нет связи с узлом и т. п.).
    Error,
}

impl InspectVerdict {
    pub fn label(self) -> &'static str {
        match self {
            InspectVerdict::Masked => "скрывает ошибку",
            InspectVerdict::PassedThrough => "ошибка видна пользователю",
            InspectVerdict::Blocked => "заблокировано",
            InspectVerdict::Error => "не проверено",
        }
    }

    pub fn is_problem(self) -> bool {
        self == InspectVerdict::Masked
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionCheck {
    pub host: String,
    pub verdict: InspectVerdict,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyVerdict {
    Allowed,
    Blocked,
    AuthRequired,
    Error,
}

impl PolicyVerdict {
    pub fn label(self) -> &'static str {
        match self {
            PolicyVerdict::Allowed => "разрешено",
            PolicyVerdict::Blocked => "заблокировано",
            PolicyVerdict::AuthRequired => "требуется аутентификация",
            PolicyVerdict::Error => "ошибка",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub url: String,
    /// Ожидается ли, что доступ разрешён.
    pub expect_allowed: bool,
    pub verdict: PolicyVerdict,
    pub detail: String,
    pub compliant: bool,
}

/// Результат диагностики одного узла.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeResult {
    pub kind: Option<ProxyKind>,
    pub rtt_ms: Option<u32>,
    pub http_status: Option<u16>,
    pub server: String,
    pub via: String,
    /// Схемы аутентификации (Basic, NTLM, Negotiate…), пусто — без аутентификации.
    pub auth: Vec<String>,
    pub auth_required: bool,
    /// Какой схемой и под каким пользователем выполнялась аутентификация.
    #[serde(default)]
    pub auth_used: Option<String>,
    /// Прошла ли аутентификация.
    #[serde(default)]
    pub auth_ok: Option<bool>,
    /// Результат CONNECT: `Some(код)`.
    pub connect_status: Option<u16>,
    pub ssl: Option<SslInspection>,
    pub cert: Option<CertInfo>,
    pub policy: Vec<PolicyResult>,
    /// Проверка качества SSL-инспекции на узлах с плохими сертификатами.
    #[serde(default)]
    pub inspection_checks: Vec<InspectionCheck>,
    pub raw_headers: String,
    pub notes: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRow {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub source: String,
    pub state: RowState,
    pub kind: ProxyKind,
    pub ssl: SslInspection,
    pub probe: ProbeResult,
}

impl ProxyRow {
    pub fn new(ip: Ipv4Addr, port: u16, source: &str) -> Self {
        Self {
            ip,
            port,
            source: source.to_string(),
            state: RowState::Found,
            kind: ProxyKind::Unknown,
            ssl: SslInspection::Unknown,
            probe: ProbeResult::default(),
        }
    }

    pub fn auth_label(&self) -> String {
        if let (Some(used), Some(ok)) = (&self.probe.auth_used, self.probe.auth_ok) {
            let scheme = used.split(' ').next().unwrap_or(used);
            return format!("{scheme} {}", if ok { "✔ вход выполнен" } else { "✖ отказ" });
        }
        if !self.probe.auth.is_empty() {
            self.probe.auth.join(", ")
        } else if self.probe.auth_required {
            "требуется".into()
        } else if self.kind.is_proxy() {
            "нет".into()
        } else {
            String::new()
        }
    }

    pub fn connect_label(&self) -> String {
        match self.probe.connect_status {
            Some(c) if (200..300).contains(&c) => format!("да ({c})"),
            Some(c) => format!("нет ({c})"),
            None => String::new(),
        }
    }

    pub fn policy_counts(&self) -> (usize, usize) {
        let ok = self.probe.policy.iter().filter(|p| p.compliant).count();
        (ok, self.probe.policy.len())
    }

    pub fn policy_label(&self) -> String {
        let (ok, total) = self.policy_counts();
        if total == 0 {
            String::new()
        } else {
            format!("{ok}/{total}")
        }
    }

    /// (скрытых ошибок, проверено) по проверкам качества инспекции.
    pub fn inspect_counts(&self) -> (usize, usize) {
        let checked: Vec<_> = self
            .probe
            .inspection_checks
            .iter()
            .filter(|c| c.verdict != InspectVerdict::Error)
            .collect();
        (checked.iter().filter(|c| c.verdict.is_problem()).count(), checked.len())
    }

    pub fn inspect_label(&self) -> String {
        let (bad, n) = self.inspect_counts();
        if self.probe.inspection_checks.is_empty() {
            String::new()
        } else if n == 0 {
            "не проверено".into()
        } else if bad > 0 {
            format!("скрывает {bad} из {n}")
        } else {
            format!("в порядке ({n})")
        }
    }

    pub fn issuer_label(&self) -> &str {
        self.probe.cert.as_ref().map(|c| c.issuer.as_str()).unwrap_or("")
    }

    pub fn server_label(&self) -> String {
        match (self.probe.server.is_empty(), self.probe.via.is_empty()) {
            (false, false) => format!("{} · via {}", self.probe.server, self.probe.via),
            (false, true) => self.probe.server.clone(),
            (true, false) => format!("via {}", self.probe.via),
            (true, true) => String::new(),
        }
    }
}

/// События от фоновых задач к интерфейсу.
#[derive(Debug)]
pub enum AppEvent {
    Log(String),
    NetDetected(Box<NetDetect>),
    RouterMac(Result<String, String>),
    /// Обнаружен открытый порт.
    Open {
        ip: Ipv4Addr,
        port: u16,
        source: &'static str,
    },
    /// Прогресс обнаружения, 0.0..=1.0 и текст.
    Progress(f32, String),
    ProbeStarted(Ipv4Addr, u16),
    ProbeDone(Ipv4Addr, u16, Box<ProbeResult>),
    /// Эталонный сертификат тестового узла (прямое подключение).
    Reference(Result<CertInfo, String>),
    /// Контрольная точка для продолжения прерванного сканирования.
    Checkpoint(Checkpoint),
    /// Начат этап сканирования `k` из `n`.
    GroupStarted(usize, usize),
    /// Этап `k` завершён полностью.
    GroupDone(usize),
    /// Этап обнаружения завершён.
    DiscoveryFinished(Result<String, String>),
    /// Результат одной проверки обхода прокси.
    Egress(Box<crate::egress::EgressItem>),
    /// Проверка обхода прокси завершена.
    EgressDone,
    /// Слушатель запущен: занятые порты и ошибки.
    ListenerStarted(Vec<u16>, Vec<String>),
}

/// Место, с которого можно продолжить обнаружение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checkpoint {
    /// TCP-connect: столько первых адресов проверены по всем портам.
    TcpHostsDone(u64),
    /// masscan: индекс в псевдослучайной последовательности (`--resume-index`).
    MasscanIndex(u64),
}
