//! Фильтры таблицы результатов: описание, разбор и проверка строк.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::model::{ProxyKind, ProxyRow, RowState, SslInspection};
use crate::targets::{self, TargetSet};

/// Типы узлов, доступные для фильтрации (в порядке показа).
pub const KINDS: &[ProxyKind] = &[
    ProxyKind::HttpProxy,
    ProxyKind::Socks5,
    ProxyKind::Socks4,
    ProxyKind::HttpServer,
    ProxyKind::NotProxy,
    ProxyKind::Unknown,
];

/// Общий интерфейс для перечислений-фильтров: список вариантов и подпись.
pub trait Choice: Copy + PartialEq + Default + 'static {
    const ALL: &'static [Self];
    fn label(self) -> &'static str;
    fn is_any(self) -> bool {
        self == Self::default()
    }
}

macro_rules! choice {
    ($name:ident { $($variant:ident => $label:expr),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub enum $name {
            #[default]
            $($variant),+
        }
        impl Choice for $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            fn label(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
    };
}

choice!(AuthFilter {
    Any => "любая",
    NoAuth => "без аутентификации",
    Required => "требуется",
    Basic => "Basic",
    Ntlm => "NTLM",
    Negotiate => "Negotiate (Kerberos)",
});

choice!(ConnectFilter {
    Any => "любой",
    Allowed => "разрешён",
    Denied => "запрещён",
    NotChecked => "не проверялся",
});

choice!(SslFilter {
    Any => "любая",
    Yes => "обнаружена",
    No => "нет",
    NoReference => "нет эталона",
    NotChecked => "не проверялась",
});

choice!(PolicyFilter {
    Any => "любые",
    Compliant => "все соблюдены",
    Violations => "есть нарушения",
    NotChecked => "не проверялись",
});

choice!(StateFilter {
    Any => "любое",
    Done => "готово",
    Error => "ошибка",
    InProgress => "в работе",
});

choice!(SourceFilter {
    Any => "любой",
    Masscan => "masscan",
    TcpConnect => "TCP-connect",
});

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filters {
    /// Поиск по тексту: все слова должны встретиться в строке.
    pub text: String,
    /// Выбранные типы; пусто — любые.
    pub kinds: Vec<ProxyKind>,
    pub auth: AuthFilter,
    pub connect: ConnectFilter,
    pub ssl: SslFilter,
    pub policy: PolicyFilter,
    pub state: StateFilter,
    pub source: SourceFilter,
    /// Порты: `3128,8080-8090`; пусто — любые.
    pub ports: String,
    /// Адреса: `10.0.0.0/24, 10.1.1.5`; пусто — любые.
    pub subnet: String,
    /// Максимальное время отклика, мс; `None` — без ограничения.
    pub max_rtt_ms: Option<u32>,
}

/// Готовые наборы фильтров для типовых задач.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    AllProxies,
    OpenProxies,
    OpenConnect,
    SslInspection,
    PolicyViolations,
    Errors,
}

impl Preset {
    pub const ALL: &'static [Preset] = &[
        Preset::AllProxies,
        Preset::OpenProxies,
        Preset::OpenConnect,
        Preset::SslInspection,
        Preset::PolicyViolations,
        Preset::Errors,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Preset::AllProxies => "Все прокси",
            Preset::OpenProxies => "Прокси без аутентификации",
            Preset::OpenConnect => "Открытый CONNECT без аутентификации",
            Preset::SslInspection => "С SSL-инспекцией",
            Preset::PolicyViolations => "Нарушения политик",
            Preset::Errors => "Ошибки проверки",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Preset::AllProxies => "HTTP-, SOCKS5- и SOCKS4-прокси",
            Preset::OpenProxies => "Прокси, которые пускают без учётной записи",
            Preset::OpenConnect => {
                "Прокси без аутентификации, разрешающие туннель CONNECT, — \
                 через них можно выйти на любой порт"
            }
            Preset::SslInspection => "Сертификат через прокси отличается от эталонного",
            Preset::PolicyViolations => "Хотя бы одно правило политики не выполняется",
            Preset::Errors => "Узлы, проверка которых завершилась ошибкой",
        }
    }
}

impl Filters {
    pub fn proxy_kinds() -> Vec<ProxyKind> {
        KINDS.iter().copied().filter(|k| k.is_proxy()).collect()
    }

    pub fn apply_preset(&mut self, preset: Preset) {
        let text = std::mem::take(&mut self.text);
        *self = Filters {
            text,
            ..Default::default()
        };
        match preset {
            Preset::AllProxies => self.kinds = Self::proxy_kinds(),
            Preset::OpenProxies => {
                self.kinds = Self::proxy_kinds();
                self.auth = AuthFilter::NoAuth;
            }
            Preset::OpenConnect => {
                self.kinds = Self::proxy_kinds();
                self.auth = AuthFilter::NoAuth;
                self.connect = ConnectFilter::Allowed;
            }
            Preset::SslInspection => self.ssl = SslFilter::Yes,
            Preset::PolicyViolations => self.policy = PolicyFilter::Violations,
            Preset::Errors => self.state = StateFilter::Error,
        }
    }

    pub fn toggle_kind(&mut self, kind: ProxyKind) {
        if let Some(i) = self.kinds.iter().position(|k| *k == kind) {
            self.kinds.remove(i);
        } else {
            self.kinds.push(kind);
        }
    }

    /// Число активных фильтров (без учёта текстового поиска).
    pub fn active_count(&self) -> usize {
        [
            !self.kinds.is_empty(),
            !self.auth.is_any(),
            !self.connect.is_any(),
            !self.ssl.is_any(),
            !self.policy.is_any(),
            !self.state.is_any(),
            !self.source.is_any(),
            !self.ports.trim().is_empty(),
            !self.subnet.trim().is_empty(),
            self.max_rtt_ms.is_some(),
        ]
        .iter()
        .filter(|x| **x)
        .count()
    }

    pub fn is_empty(&self) -> bool {
        self.active_count() == 0 && self.text.trim().is_empty()
    }

    /// Разбор полей; ошибки возвращаются отдельно, неверное поле не применяется.
    pub fn compile(&self) -> (Compiled, Vec<String>) {
        let mut errors = Vec::new();
        let ports = if self.ports.trim().is_empty() {
            None
        } else {
            match targets::parse_ports(&self.ports) {
                Ok(p) => Some(p.into_iter().collect()),
                Err(e) => {
                    errors.push(format!("Порты: {e}"));
                    None
                }
            }
        };
        let nets = if self.subnet.trim().is_empty() {
            None
        } else {
            match targets::parse_targets(&self.subnet) {
                Ok(t) => Some(t),
                Err(e) => {
                    errors.push(format!("Адреса: {e}"));
                    None
                }
            }
        };
        let compiled = Compiled {
            words: self
                .text
                .to_lowercase()
                .split_whitespace()
                .map(String::from)
                .collect(),
            kinds: self.kinds.clone(),
            auth: self.auth,
            connect: self.connect,
            ssl: self.ssl,
            policy: self.policy,
            state: self.state,
            source: self.source,
            ports,
            nets,
            max_rtt_ms: self.max_rtt_ms,
        };
        (compiled, errors)
    }
}

/// Разобранные фильтры, готовые к проверке строк.
pub struct Compiled {
    words: Vec<String>,
    kinds: Vec<ProxyKind>,
    auth: AuthFilter,
    connect: ConnectFilter,
    ssl: SslFilter,
    policy: PolicyFilter,
    state: StateFilter,
    source: SourceFilter,
    ports: Option<HashSet<u16>>,
    nets: Option<TargetSet>,
    max_rtt_ms: Option<u32>,
}

fn has_scheme(r: &ProxyRow, scheme: &str) -> bool {
    r.probe
        .auth
        .iter()
        .any(|a| a.eq_ignore_ascii_case(scheme))
}

impl Compiled {
    pub fn matches(&self, r: &ProxyRow) -> bool {
        if !self.kinds.is_empty() && !self.kinds.contains(&r.kind) {
            return false;
        }
        if let Some(ports) = &self.ports
            && !ports.contains(&r.port)
        {
            return false;
        }
        if let Some(nets) = &self.nets
            && !nets.contains(r.ip)
        {
            return false;
        }
        if let Some(max) = self.max_rtt_ms
            && r.probe.rtt_ms.is_none_or(|v| v > max)
        {
            return false;
        }

        let auth_required = r.probe.auth_required || !r.probe.auth.is_empty();
        let auth_ok = match self.auth {
            AuthFilter::Any => true,
            AuthFilter::NoAuth => r.kind.is_proxy() && !auth_required,
            AuthFilter::Required => auth_required,
            AuthFilter::Basic => has_scheme(r, "Basic"),
            AuthFilter::Ntlm => has_scheme(r, "NTLM"),
            AuthFilter::Negotiate => has_scheme(r, "Negotiate") || has_scheme(r, "Kerberos"),
        };
        if !auth_ok {
            return false;
        }

        let connect_ok = match (self.connect, r.probe.connect_status) {
            (ConnectFilter::Any, _) => true,
            (ConnectFilter::Allowed, Some(c)) => (200..300).contains(&c),
            (ConnectFilter::Denied, Some(c)) => !(200..300).contains(&c),
            (ConnectFilter::NotChecked, None) => true,
            _ => false,
        };
        if !connect_ok {
            return false;
        }

        let ssl_ok = match self.ssl {
            SslFilter::Any => true,
            SslFilter::Yes => r.ssl == SslInspection::Yes,
            SslFilter::No => r.ssl == SslInspection::No,
            SslFilter::NoReference => r.ssl == SslInspection::NoReference,
            SslFilter::NotChecked => r.ssl == SslInspection::Unknown,
        };
        if !ssl_ok {
            return false;
        }

        let (ok, total) = r.policy_counts();
        let policy_ok = match self.policy {
            PolicyFilter::Any => true,
            PolicyFilter::Compliant => total > 0 && ok == total,
            PolicyFilter::Violations => ok < total,
            PolicyFilter::NotChecked => total == 0,
        };
        if !policy_ok {
            return false;
        }

        let state_ok = match self.state {
            StateFilter::Any => true,
            StateFilter::Done => r.state == RowState::Done,
            StateFilter::Error => r.state == RowState::Error,
            StateFilter::InProgress => matches!(r.state, RowState::Found | RowState::Probing),
        };
        if !state_ok {
            return false;
        }

        let source_ok = match self.source {
            SourceFilter::Any => true,
            SourceFilter::Masscan => r.source == "masscan",
            SourceFilter::TcpConnect => r.source == "tcp-connect",
        };
        if !source_ok {
            return false;
        }

        if self.words.is_empty() {
            return true;
        }
        let hay = search_text(r);
        self.words.iter().all(|w| hay.contains(w.as_str()))
    }
}

/// Текст строки для поиска.
fn search_text(r: &ProxyRow) -> String {
    let cert = r.probe.cert.as_ref();
    format!(
        "{}:{} {} {} {} {} {} {} {} {} {}",
        r.ip,
        r.port,
        r.kind.label(),
        r.auth_label(),
        r.server_label(),
        cert.map(|c| c.issuer.as_str()).unwrap_or(""),
        cert.map(|c| c.subject.as_str()).unwrap_or(""),
        r.ssl.label(),
        r.state.label(),
        r.source,
        r.probe.notes.join(" "),
    )
    .to_lowercase()
}

/// Подсеть /24, в которую входит адрес (для быстрого фильтра из контекстного меню).
pub fn subnet_24(ip: Ipv4Addr) -> String {
    targets::network_cidr(ip, 24)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CertInfo, PolicyResult, PolicyVerdict};

    fn row(ip: [u8; 4], port: u16, kind: ProxyKind) -> ProxyRow {
        let mut r = ProxyRow::new(Ipv4Addr::from(ip), port, "tcp-connect");
        r.kind = kind;
        r.state = RowState::Done;
        r
    }

    fn rows() -> Vec<ProxyRow> {
        let mut open = row([10, 0, 0, 1], 3128, ProxyKind::HttpProxy);
        open.probe.connect_status = Some(200);
        open.probe.rtt_ms = Some(5);

        let mut ntlm = row([10, 0, 0, 2], 8080, ProxyKind::HttpProxy);
        ntlm.probe.auth = vec!["Negotiate".into(), "NTLM".into()];
        ntlm.probe.auth_required = true;
        ntlm.probe.connect_status = Some(407);
        ntlm.probe.rtt_ms = Some(40);

        let mut mitm = row([10, 0, 1, 3], 8080, ProxyKind::HttpProxy);
        mitm.probe.connect_status = Some(200);
        mitm.ssl = SslInspection::Yes;
        mitm.probe.cert = Some(CertInfo {
            issuer: "CN=Corp Inspection CA".into(),
            ..Default::default()
        });
        mitm.probe.policy = vec![PolicyResult {
            url: "http://x/".into(),
            expect_allowed: false,
            verdict: PolicyVerdict::Allowed,
            detail: String::new(),
            compliant: false,
        }];

        let mut socks = row([10, 0, 1, 4], 1080, ProxyKind::Socks5);
        socks.source = "masscan".into();

        let web = row([10, 0, 2, 5], 80, ProxyKind::HttpServer);

        let mut err = row([10, 0, 2, 6], 9090, ProxyKind::Unknown);
        err.state = RowState::Error;

        vec![open, ntlm, mitm, socks, web, err]
    }

    fn ips(f: &Filters) -> Vec<String> {
        let (c, errors) = f.compile();
        assert!(errors.is_empty(), "{errors:?}");
        rows()
            .iter()
            .filter(|r| c.matches(r))
            .map(|r| format!("{}:{}", r.ip, r.port))
            .collect()
    }

    #[test]
    fn empty_filter_shows_all() {
        assert_eq!(ips(&Filters::default()).len(), 6);
        assert!(Filters::default().is_empty());
    }

    #[test]
    fn presets() {
        let mut f = Filters::default();
        f.apply_preset(Preset::AllProxies);
        assert_eq!(ips(&f).len(), 4);
        f.apply_preset(Preset::OpenProxies);
        assert_eq!(ips(&f), ["10.0.0.1:3128", "10.0.1.3:8080", "10.0.1.4:1080"]);
        f.apply_preset(Preset::OpenConnect);
        assert_eq!(ips(&f), ["10.0.0.1:3128", "10.0.1.3:8080"]);
        f.apply_preset(Preset::SslInspection);
        assert_eq!(ips(&f), ["10.0.1.3:8080"]);
        f.apply_preset(Preset::PolicyViolations);
        assert_eq!(ips(&f), ["10.0.1.3:8080"]);
        f.apply_preset(Preset::Errors);
        assert_eq!(ips(&f), ["10.0.2.6:9090"]);
    }

    #[test]
    fn individual_filters() {
        let f = Filters { auth: AuthFilter::Ntlm, ..Default::default() };
        assert_eq!(ips(&f), ["10.0.0.2:8080"]);
        let f = Filters { auth: AuthFilter::Negotiate, ..Default::default() };
        assert_eq!(ips(&f), ["10.0.0.2:8080"]);
        let f = Filters { connect: ConnectFilter::Denied, ..Default::default() };
        assert_eq!(ips(&f), ["10.0.0.2:8080"]);
        let f = Filters { connect: ConnectFilter::NotChecked, ..Default::default() };
        assert_eq!(ips(&f).len(), 3);
        let f = Filters { ports: "8080, 1080".into(), ..Default::default() };
        assert_eq!(ips(&f).len(), 3);
        let f = Filters { subnet: "10.0.1.0/24".into(), ..Default::default() };
        assert_eq!(ips(&f), ["10.0.1.3:8080", "10.0.1.4:1080"]);
        let f = Filters { max_rtt_ms: Some(10), ..Default::default() };
        assert_eq!(ips(&f), ["10.0.0.1:3128"]);
        let f = Filters { source: SourceFilter::Masscan, ..Default::default() };
        assert_eq!(ips(&f), ["10.0.1.4:1080"]);
        let f = Filters { state: StateFilter::Done, ..Default::default() };
        assert_eq!(ips(&f).len(), 5);
        let f = Filters { policy: PolicyFilter::NotChecked, ..Default::default() };
        assert_eq!(ips(&f).len(), 5);
        let f = Filters { kinds: vec![ProxyKind::Socks5, ProxyKind::HttpServer], ..Default::default() };
        assert_eq!(ips(&f), ["10.0.1.4:1080", "10.0.2.5:80"]);
    }

    #[test]
    fn text_search_and_combination() {
        let f = Filters { text: "corp inspection".into(), ..Default::default() };
        assert_eq!(ips(&f), ["10.0.1.3:8080"]);
        let f = Filters { text: "10.0.0.".into(), ports: "8080".into(), ..Default::default() };
        assert_eq!(ips(&f), ["10.0.0.2:8080"]);
    }

    #[test]
    fn bad_input_is_reported_and_ignored() {
        let f = Filters { ports: "abc".into(), subnet: "10.0.0.0/40".into(), ..Default::default() };
        let (c, errors) = f.compile();
        assert_eq!(errors.len(), 2);
        assert_eq!(rows().iter().filter(|r| c.matches(r)).count(), 6);
        assert_eq!(f.active_count(), 2);
    }
}
