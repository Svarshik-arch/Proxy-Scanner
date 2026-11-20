//! Интерфейс инструментов диагностики: панели параметров и результатов, пресеты,
//! палитра команд (Ctrl+K) и передача узлов между инструментами.

mod ad;
mod audit;
mod certs;
mod compare;
mod discovery;
mod dns;
mod host;
mod http;
mod matrix;
mod monitor;
mod mtr;
mod services;
mod tls;
mod urlcheck;

use egui::{Color32, RichText};
use egui_extras::{Column, TableBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use crate::presets::{self, BarAction, Preset, SaveDialog, Store};

pub const GREEN: Color32 = Color32::from_rgb(60, 170, 90);
pub const RED: Color32 = Color32::from_rgb(220, 70, 70);
pub const AMBER: Color32 = Color32::from_rgb(215, 160, 40);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tool {
    Host,
    Mtr,
    Discovery,
    Dns,
    Http,
    Services,
    Tls,
    Ad,
    Audit,
    Monitor,
    Matrix,
    Certs,
    Compare,
    UrlCheck,
}

impl Tool {
    pub const ALL: [Tool; 14] = [
        Tool::Host,
        Tool::Mtr,
        Tool::Discovery,
        Tool::Dns,
        Tool::Http,
        Tool::Services,
        Tool::Tls,
        Tool::Ad,
        Tool::Audit,
        Tool::Monitor,
        Tool::Matrix,
        Tool::Certs,
        Tool::Compare,
        Tool::UrlCheck,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tool::Host => "Хост",
            Tool::Mtr => "MTR",
            Tool::Discovery => "Узлы",
            Tool::Dns => "DNS",
            Tool::Http => "HTTP",
            Tool::Services => "Сервисы",
            Tool::Tls => "TLS",
            Tool::Ad => "Домен AD",
            Tool::Audit => "Аудит",
            Tool::Monitor => "Мониторинг",
            Tool::Matrix => "Доступность",
            Tool::Certs => "Сертификаты",
            Tool::Compare => "Сравнение сессий",
            Tool::UrlCheck => "Проверка URL",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Tool::Host => "Интерфейсы, маршруты, ARP-таблица, соединения с процессами",
            Tool::Mtr => "Трассировка с наблюдением: потери и задержка по хопам, поиск MTU",
            Tool::Discovery => "Поиск узлов: ICMP, TCP, ARP, NetBIOS, mDNS, SSDP; производитель и ОС",
            Tool::Dns => "Запросы как dig: любые типы и серверы, DoT/DoH, сравнение, AXFR",
            Tool::Http => "Запрос как curl -v: заголовки, время по фазам, прокси, сертификаты",
            Tool::Services => "Сервисы и версии: баннеры, HTTP, TLS, SMB, RDP, СУБД, UDP",
            Tool::Tls => "TLS-аудит: версии, шифры, цепочка, оценка",
            Tool::Ad => "Почему не входит в домен: контроллеры, Kerberos, LDAP, время, SMB",
            Tool::Audit => "Небезопасные настройки в сети: SMBv1, Telnet, RDP без NLA, SNMP public…",
            Tool::Monitor => "Проверки по расписанию: ping, порты, сайты, DNS, сертификаты",
            Tool::Matrix => "Правила межсетевого экрана: откуда → куда → порт, с ожиданием «открыт/закрыт»",
            Tool::Certs => "Все найденные сертификаты по сроку окончания, выгрузка в Excel",
            Tool::Compare => "Что изменилось между двумя проверками",
            Tool::UrlCheck => "Список адресов через прокси: пропущен, заблокирован, подменён сертификат",
        }
    }

    pub fn preset_id(self) -> &'static str {
        match self {
            Tool::Host => "host",
            Tool::Mtr => "mtr",
            Tool::Discovery => "discovery",
            Tool::Dns => "dns",
            Tool::Http => "http",
            Tool::Services => "services",
            Tool::Tls => "tls",
            Tool::Ad => "ad",
            Tool::Audit => "audit",
            Tool::Monitor => "monitor",
            Tool::Matrix => "matrix",
            Tool::Certs => "certs",
            Tool::Compare => "compare",
            Tool::UrlCheck => "urlcheck",
        }
    }
}

/// Переход, запрошенный из панели.
pub enum Nav {
    /// Открыть инструмент с узлом.
    Send(Tool, String),
    /// Открыть раздел прокси с целями.
    Proxy(String),
}

/// Общий контекст для панелей на кадр.
pub struct Env<'a> {
    pub rt: &'a Handle,
    pub ctx: egui::Context,
    pub store: &'a mut Store,
    pub save: &'a mut SaveDialog,
    pub pending_save: &'a mut Option<(serde_json::Value, serde_json::Value)>,
    pub nav: &'a mut Option<Nav>,
    pub message: &'a mut Option<String>,
    /// Подсеть этой машины (для «Моя подсеть»).
    pub local_cidr: Option<String>,
    /// Открытые порты из сканирования прокси.
    pub proxy_open: Vec<(std::net::Ipv4Addr, u16)>,
    /// Найденные HTTP-прокси `ip:порт`.
    pub http_proxies: Vec<String>,
}

/// Сохраняемые параметры всех инструментов.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub mtr: crate::tools::mtr::Config,
    pub discovery: crate::tools::discovery::Config,
    pub dns: crate::tools::dns::Config,
    pub http: crate::tools::http::Config,
    pub services: crate::tools::services::Config,
    pub tls: crate::tools::tlsaudit::Config,
    pub ad: crate::tools::ad::Config,
    pub audit: crate::tools::audit::Config,
    pub monitor: crate::tools::monitor::Config,
    pub matrix: crate::tools::matrix::Config,
    pub urlcheck: crate::tools::urlcheck::Config,
}

/// Результаты инструментов для файла сессии.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Results {
    pub host: Option<crate::tools::hostinfo::Report>,
    pub mtr: Option<crate::tools::mtr::Report>,
    pub discovery: Option<crate::tools::discovery::Report>,
    pub dns: Option<crate::tools::dns::Report>,
    pub http: Option<crate::tools::http::Report>,
    pub services: Option<crate::tools::services::Report>,
    pub tls: Option<crate::tools::tlsaudit::Report>,
    pub ad: Option<crate::tools::ad::Report>,
    pub audit: Option<crate::tools::audit::Report>,
    pub monitor: Option<crate::tools::monitor::Report>,
    /// Матрица доступности: результаты с разных машин-источников.
    pub matrix: Option<Vec<crate::tools::matrix::Report>>,
    pub urlcheck: Option<crate::tools::urlcheck::Report>,
}

pub struct Workbench {
    pub store: Store,
    save: SaveDialog,
    pending_save: Option<(serde_json::Value, serde_json::Value)>,
    pub message: Option<String>,
    host: host::Panel,
    mtr: mtr::Panel,
    discovery: discovery::Panel,
    dns: dns::Panel,
    http: http::Panel,
    services: services::Panel,
    tls: tls::Panel,
    ad: ad::Panel,
    audit: audit::Panel,
    monitor: monitor::Panel,
    matrix: matrix::Panel,
    certs: certs::Panel,
    compare: compare::Panel,
    urlcheck: urlcheck::Panel,
    /// Снимок текущей сессии и архив — для сертификатов и сравнения.
    current: Option<crate::session::Session>,
    archive: Vec<(String, std::path::PathBuf)>,
    palette: Palette,
}

#[derive(Default)]
struct Palette {
    open: bool,
    query: String,
    focus: bool,
}

/// Пункт палитры команд.
pub enum PaletteItem {
    Tool(Tool),
    Proxy,
    Preset(String, Preset),
    Host(String),
}

impl Workbench {
    pub fn new(prefs: Prefs) -> Self {
        let (store, warn) = Store::load(presets::default_path());
        Self {
            store,
            save: SaveDialog::default(),
            pending_save: None,
            message: warn.map(|w| format!("пресеты: {w}")),
            host: host::Panel::default(),
            mtr: mtr::Panel::new(prefs.mtr),
            discovery: discovery::Panel::new(prefs.discovery),
            dns: dns::Panel::new(prefs.dns),
            http: http::Panel::new(prefs.http),
            services: services::Panel::new(prefs.services),
            tls: tls::Panel::new(prefs.tls),
            ad: ad::Panel::new(prefs.ad),
            audit: audit::Panel::new(prefs.audit),
            monitor: monitor::Panel::new(prefs.monitor),
            matrix: matrix::Panel::new(prefs.matrix),
            certs: certs::Panel::default(),
            compare: compare::Panel::default(),
            urlcheck: urlcheck::Panel::new(prefs.urlcheck),
            current: None,
            archive: Vec::new(),
            palette: Palette::default(),
        }
    }

    /// Параметры инструментов из проекта.
    pub fn set_prefs(&mut self, p: Prefs) {
        self.mtr.cfg = p.mtr;
        self.discovery.cfg = p.discovery;
        self.dns.cfg = p.dns;
        self.http.cfg = p.http;
        self.services.cfg = p.services;
        self.tls.cfg = p.tls;
        self.ad.cfg = p.ad;
        self.audit.cfg = p.audit;
        self.monitor.cfg = p.monitor;
        self.matrix.cfg = p.matrix;
        self.urlcheck.cfg = p.urlcheck;
    }

    pub fn prefs(&self) -> Prefs {
        Prefs {
            mtr: self.mtr.cfg.clone(),
            discovery: self.discovery.cfg.clone(),
            dns: self.dns.cfg.clone(),
            http: self.http.cfg.clone(),
            services: self.services.cfg.clone(),
            tls: self.tls.cfg.clone(),
            ad: self.ad.cfg.clone(),
            audit: self.audit.cfg.clone(),
            monitor: self.monitor.cfg.clone(),
            matrix: self.matrix.cfg.clone(),
            urlcheck: self.urlcheck.cfg.clone(),
        }
    }

    pub fn results(&self) -> Results {
        Results {
            host: self.host.report.clone(),
            mtr: self.mtr.report.clone(),
            discovery: (!self.discovery.report.hosts.is_empty()).then(|| self.discovery.report.clone()),
            dns: (!self.dns.report.answers.is_empty()).then(|| self.dns.report.clone()),
            http: (!self.http.report.runs.is_empty()).then(|| self.http.report.clone()),
            services: (!self.services.report.services.is_empty()).then(|| self.services.report.clone()),
            tls: (!self.tls.report.targets.is_empty()).then(|| self.tls.report.clone()),
            ad: self.ad.report.clone(),
            audit: (!self.audit.report.services.is_empty()).then(|| self.audit.report.clone()),
            monitor: (!self.monitor.report.states.is_empty()).then(|| self.monitor.report.clone()),
            matrix: (!self.matrix.reports.is_empty()).then(|| self.matrix.reports.clone()),
            urlcheck: (!self.urlcheck.report.rows.is_empty()).then(|| self.urlcheck.report.clone()),
        }
    }

    pub fn restore_results(&mut self, r: Results) {
        if r.host.is_some() {
            self.host.report = r.host;
        }
        if r.mtr.is_some() {
            self.mtr.report = r.mtr;
        }
        if let Some(v) = r.discovery {
            self.discovery.report = v;
        }
        if let Some(v) = r.dns {
            self.dns.report = v;
        }
        if let Some(v) = r.http {
            self.http.report = v;
        }
        if let Some(v) = r.services {
            self.services.report = v;
        }
        if let Some(v) = r.tls {
            self.tls.report = v;
        }
        if r.ad.is_some() {
            self.ad.report = r.ad;
        }
        if let Some(v) = r.audit {
            self.audit.report = v;
        }
        if let Some(v) = r.monitor {
            self.monitor.report = v;
        }
        if let Some(v) = r.matrix {
            self.matrix.reports = v;
        }
        if let Some(v) = r.urlcheck {
            self.urlcheck.report = v;
        }
    }

    pub fn clear_results(&mut self) {
        self.restore_results(Results::default());
        self.host.report = None;
        self.mtr.report = None;
        self.discovery.report = Default::default();
        self.dns.report = Default::default();
        self.http.report = Default::default();
        self.services.report = Default::default();
        self.tls.report = Default::default();
        self.ad.report = None;
        self.audit.report = Default::default();
        self.monitor.report = Default::default();
        self.matrix.reports.clear();
        self.certs.certs.clear();
        self.urlcheck.report = Default::default();
    }

    /// Контекст для «Сертификатов» и «Сравнения»: снимок сессии и архив.
    pub fn set_context(&mut self, current: crate::session::Session, archive: Vec<(String, std::path::PathBuf)>) {
        self.certs.certs = crate::tools::certs::collect(&current);
        self.current = Some(current);
        self.archive = archive;
    }

    /// Обработка событий фоновых задач (каждый кадр). true — что-то изменилось.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        changed |= self.host.poll();
        changed |= self.mtr.poll();
        changed |= self.discovery.poll();
        changed |= self.dns.poll();
        changed |= self.http.poll();
        changed |= self.services.poll();
        changed |= self.tls.poll();
        changed |= self.ad.poll();
        changed |= self.audit.poll();
        changed |= self.monitor.poll(&mut self.message);
        changed |= self.matrix.poll();
        changed |= self.urlcheck.poll();
        changed
    }

    /// Мониторинг зафиксировал сбой (один раз).
    pub fn take_attention(&mut self) -> bool {
        std::mem::take(&mut self.monitor.attention)
    }

    pub fn busy(&self, t: Tool) -> bool {
        match t {
            Tool::Host => self.host.busy(),
            Tool::Mtr => self.mtr.busy(),
            Tool::Discovery => self.discovery.busy(),
            Tool::Dns => self.dns.busy(),
            Tool::Http => self.http.busy(),
            Tool::Services => self.services.busy(),
            Tool::Tls => self.tls.busy(),
            Tool::Ad => self.ad.busy(),
            Tool::Audit => self.audit.busy(),
            Tool::Monitor => self.monitor.busy(),
            Tool::Matrix => self.matrix.busy(),
            Tool::Certs | Tool::Compare => false,
            Tool::UrlCheck => self.urlcheck.busy(),
        }
    }

    pub fn any_busy(&self) -> bool {
        Tool::ALL.iter().any(|t| self.busy(*t))
    }

    /// Короткая подпись на вкладке (число результатов).
    pub fn badge(&self, t: Tool) -> Option<String> {
        let n = match t {
            Tool::Host => return None,
            Tool::Mtr => self.mtr.report.as_ref().map(|r| r.hops.len()).unwrap_or(0),
            Tool::Discovery => self.discovery.report.hosts.iter().filter(|h| h.alive).count(),
            Tool::Dns => self.dns.report.answers.len(),
            Tool::Http => self.http.report.runs.len(),
            Tool::Services => self.services.report.services.len(),
            Tool::Tls => self.tls.report.targets.len(),
            Tool::Ad => self.ad.report.as_ref().map(|r| r.dcs.len()).unwrap_or(0),
            Tool::Audit => self.audit.report.issues.len(),
            Tool::Monitor => {
                let fail = self.monitor.report.states.iter().filter(|s| s.status == crate::tools::monitor::Status::Fail).count();
                if fail > 0 {
                    return Some(format!("⚠{fail}"));
                }
                self.monitor.report.states.len()
            }
            Tool::Matrix => {
                let m: usize = self.matrix.reports.iter().map(|r| r.mismatches()).sum();
                if m > 0 {
                    return Some(format!("⚠{m}"));
                }
                self.matrix.reports.iter().map(|r| r.entries.len()).sum()
            }
            Tool::Certs => {
                let bad = self.certs.certs.iter().filter(|c| c.days_left.is_some_and(|d| d < self.certs.warn_days)).count();
                if bad > 0 {
                    return Some(format!("⚠{bad}"));
                }
                self.certs.certs.len()
            }
            Tool::Compare => self.compare.diff.as_ref().map(|d| d.changes.len()).unwrap_or(0),
            Tool::UrlCheck => {
                let m = self.urlcheck.report.mismatches();
                if m > 0 {
                    return Some(format!("⚠{m}"));
                }
                self.urlcheck.report.rows.len()
            }
        };
        (n > 0).then(|| n.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    fn env<'a>(
        store: &'a mut Store,
        save: &'a mut SaveDialog,
        pending_save: &'a mut Option<(serde_json::Value, serde_json::Value)>,
        nav: &'a mut Option<Nav>,
        message: &'a mut Option<String>,
        rt: &'a Handle,
        ctx: egui::Context,
        local_cidr: Option<String>,
        proxy_open: Vec<(std::net::Ipv4Addr, u16)>,
    ) -> Env<'a> {
        Env {
            rt,
            ctx,
            store,
            save,
            pending_save,
            nav,
            message,
            local_cidr,
            proxy_open,
            http_proxies: Vec::new(),
        }
    }

    pub fn settings_ui(
        &mut self,
        t: Tool,
        ui: &mut egui::Ui,
        rt: &Handle,
        local_cidr: Option<String>,
        proxy_open: Vec<(std::net::Ipv4Addr, u16)>,
        http_proxies: Vec<String>,
    ) -> Option<Nav> {
        let mut nav = None;
        let mut env = Self::env(
            &mut self.store,
            &mut self.save,
            &mut self.pending_save,
            &mut nav,
            &mut self.message,
            rt,
            ui.ctx().clone(),
            local_cidr,
            proxy_open,
        );
        env.http_proxies = http_proxies;
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading(t.title());
        });
        ui.weak(t.hint());
        ui.add_space(4.0);
        match t {
            Tool::Host => self.host.settings_ui(ui, &mut env),
            Tool::Mtr => self.mtr.settings_ui(ui, &mut env),
            Tool::Discovery => self.discovery.settings_ui(ui, &mut env),
            Tool::Dns => self.dns.settings_ui(ui, &mut env),
            Tool::Http => self.http.settings_ui(ui, &mut env),
            Tool::Services => self.services.settings_ui(ui, &mut env),
            Tool::Tls => self.tls.settings_ui(ui, &mut env),
            Tool::Ad => self.ad.settings_ui(ui, &mut env),
            Tool::Audit => self.audit.settings_ui(ui, &mut env),
            Tool::Monitor => self.monitor.settings_ui(ui, &mut env),
            Tool::Matrix => self.matrix.settings_ui(ui, &mut env),
            Tool::Certs => self.certs.settings_ui(ui, &mut env),
            Tool::Compare => self.compare.settings_ui(ui, self.current.as_ref(), &self.archive),
            Tool::UrlCheck => self.urlcheck.settings_ui(ui, &mut env),
        }
        nav
    }

    pub fn results_ui(&mut self, t: Tool, ui: &mut egui::Ui, rt: &Handle) -> Option<Nav> {
        let mut nav = None;
        let mut env = Self::env(
            &mut self.store,
            &mut self.save,
            &mut self.pending_save,
            &mut nav,
            &mut self.message,
            rt,
            ui.ctx().clone(),
            None,
            Vec::new(),
        );
        match t {
            Tool::Host => self.host.results_ui(ui, &mut env),
            Tool::Mtr => self.mtr.results_ui(ui, &mut env),
            Tool::Discovery => self.discovery.results_ui(ui, &mut env),
            Tool::Dns => self.dns.results_ui(ui, &mut env),
            Tool::Http => self.http.results_ui(ui, &mut env),
            Tool::Services => self.services.results_ui(ui, &mut env),
            Tool::Tls => self.tls.results_ui(ui, &mut env),
            Tool::Ad => self.ad.results_ui(ui, &mut env),
            Tool::Audit => self.audit.results_ui(ui, &mut env),
            Tool::Monitor => self.monitor.results_ui(ui, &mut env),
            Tool::Matrix => self.matrix.results_ui(ui, &mut env),
            Tool::Certs => self.certs.results_ui(ui, &mut env),
            Tool::Compare => self.compare.results_ui(ui, &mut env),
            Tool::UrlCheck => self.urlcheck.results_ui(ui, &mut env),
        }
        nav
    }

    /// Панель пресетов для настроек вне инструментов (прокси-сканер).
    pub fn preset_bar_for<T: Serialize + DeserializeOwned>(&mut self, ui: &mut egui::Ui, rt: &Handle, tool: &str, cfg: &mut T) {
        let mut nav = None;
        let mut env = Self::env(
            &mut self.store,
            &mut self.save,
            &mut self.pending_save,
            &mut nav,
            &mut self.message,
            rt,
            ui.ctx().clone(),
            None,
            Vec::new(),
        );
        preset_bar(ui, &mut env, tool, cfg);
    }

    /// Пресет конкретного инструмента (из палитры команд).
    pub fn apply_tool_preset(&mut self, t: Tool, p: &Preset) {
        let r = match t {
            Tool::Host => Ok(()),
            Tool::Mtr => presets::apply(&mut self.mtr.cfg, &p.values),
            Tool::Discovery => presets::apply(&mut self.discovery.cfg, &p.values),
            Tool::Dns => presets::apply(&mut self.dns.cfg, &p.values),
            Tool::Http => presets::apply(&mut self.http.cfg, &p.values),
            Tool::Services => presets::apply(&mut self.services.cfg, &p.values),
            Tool::Tls => presets::apply(&mut self.tls.cfg, &p.values),
            Tool::Ad => presets::apply(&mut self.ad.cfg, &p.values),
            Tool::Audit => presets::apply(&mut self.audit.cfg, &p.values),
            Tool::Monitor => presets::apply(&mut self.monitor.cfg, &p.values),
            Tool::Matrix => presets::apply(&mut self.matrix.cfg, &p.values),
            Tool::Certs | Tool::Compare => Ok(()),
            Tool::UrlCheck => presets::apply(&mut self.urlcheck.cfg, &p.values),
        };
        self.message = Some(match r {
            Ok(()) => format!("применён пресет «{}»", p.name),
            Err(e) => e,
        });
    }

    /// Узел передан из другого инструмента или раздела.
    pub fn receive(&mut self, t: Tool, host: &str) {
        match t {
            Tool::Host => {}
            Tool::Mtr => self.mtr.cfg.target = host.to_string(),
            Tool::Discovery => self.discovery.cfg.targets = host.to_string(),
            Tool::Dns => {
                self.dns.cfg.names = host.to_string();
            }
            Tool::Http => {
                self.http.cfg.url = if host.contains("://") { host.to_string() } else { format!("http://{host}/") };
            }
            Tool::Services => self.services.cfg.targets = host.to_string(),
            Tool::Ad => self.ad.cfg.dcs = host.to_string(),
            Tool::Audit => self.audit.cfg.targets = host.to_string(),
            Tool::Monitor => {
                let line = if host.contains("://") {
                    format!("http {host}")
                } else if host.contains(':') {
                    format!("tcp {host}")
                } else {
                    format!("ping {host}")
                };
                if !self.monitor.cfg.checks.lines().any(|l| l.trim() == line) {
                    if !self.monitor.cfg.checks.is_empty() && !self.monitor.cfg.checks.ends_with('\n') {
                        self.monitor.cfg.checks.push('\n');
                    }
                    self.monitor.cfg.checks.push_str(&line);
                }
            }
            Tool::Matrix => {
                let line = if host.contains(':') { format!("{host} open") } else { format!("{host}:443 open") };
                if !self.matrix.cfg.rules.is_empty() && !self.matrix.cfg.rules.ends_with('\n') {
                    self.matrix.cfg.rules.push('\n');
                }
                self.matrix.cfg.rules.push_str(&line);
            }
            Tool::Certs | Tool::Compare => {}
            Tool::UrlCheck => {
                let line = if host.contains("://") { host.to_string() } else { format!("https://{host}/") };
                if !self.urlcheck.cfg.urls.is_empty() && !self.urlcheck.cfg.urls.ends_with('\n') {
                    self.urlcheck.cfg.urls.push('\n');
                }
                self.urlcheck.cfg.urls.push_str(&line);
            }
            Tool::Tls => {
                if let Some((h, p)) = host.rsplit_once(':')
                    && p.parse::<u16>().is_ok()
                    && !h.contains(':')
                {
                    self.tls.cfg.targets = h.to_string();
                    self.tls.cfg.ports = p.to_string();
                } else {
                    self.tls.cfg.targets = host.to_string();
                }
            }
        }
    }

    /// Общий пресет («контур»): значения для инструментов этой панели.
    pub fn apply_common(&mut self, p: &Preset) -> Result<(), String> {
        let get = |k: &str| p.values.get(k).cloned();
        if let Some(v) = get("mtr") {
            presets::apply(&mut self.mtr.cfg, &v)?;
        }
        if let Some(v) = get("discovery") {
            presets::apply(&mut self.discovery.cfg, &v)?;
        }
        if let Some(v) = get("dns") {
            presets::apply(&mut self.dns.cfg, &v)?;
        }
        if let Some(v) = get("http") {
            presets::apply(&mut self.http.cfg, &v)?;
        }
        if let Some(v) = get("services") {
            presets::apply(&mut self.services.cfg, &v)?;
        }
        if let Some(v) = get("tls") {
            presets::apply(&mut self.tls.cfg, &v)?;
        }
        if let Some(v) = get("ad") {
            presets::apply(&mut self.ad.cfg, &v)?;
        }
        if let Some(v) = get("audit") {
            presets::apply(&mut self.audit.cfg, &v)?;
        }
        if let Some(v) = get("monitor") {
            presets::apply(&mut self.monitor.cfg, &v)?;
        }
        if let Some(v) = get("matrix") {
            presets::apply(&mut self.matrix.cfg, &v)?;
        }
        if let Some(v) = get("urlcheck") {
            presets::apply(&mut self.urlcheck.cfg, &v)?;
        }
        Ok(())
    }

    /// Окна, общие для всех инструментов: сохранение пресета, палитра команд.
    pub fn windows(&mut self, ctx: &egui::Context) {
        if self.save.open {
            let mut open = true;
            let mut done = false;
            egui::Window::new("Сохранить пресет")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Название");
                    ui.text_edit_singleline(&mut self.save.name);
                    ui.label("Описание");
                    ui.text_edit_singleline(&mut self.save.description);
                    ui.checkbox(&mut self.save.with_targets, "Сохранить и цели (адреса, имена, URL)");
                    ui.weak("Сетевые параметры этой машины и пароли в пресет не попадают.");
                    ui.horizontal(|ui| {
                        let ok = !self.save.name.trim().is_empty();
                        if ui.add_enabled(ok, egui::Button::new("Сохранить")).clicked() {
                            done = true;
                        }
                    });
                });
            if done && let Some((full, short)) = self.pending_save.take() {
                let values = if self.save.with_targets { full } else { short };
                self.store.upsert(Preset {
                    tool: self.save.tool.clone(),
                    name: self.save.name.trim().to_string(),
                    description: self.save.description.trim().to_string(),
                    values,
                    builtin: false,
                });
                self.message = Some(match self.store.save() {
                    Ok(()) => format!("пресет «{}» сохранён в {}", self.save.name.trim(), self.store.path.display()),
                    Err(e) => format!("пресет не сохранён: {e}"),
                });
                self.save.open = false;
            } else if !open {
                self.save.open = false;
            }
        }
    }

    pub fn palette_open(&mut self) {
        self.palette.open = true;
        self.palette.focus = true;
        self.palette.query.clear();
    }

    /// Палитра: возвращает выбранный пункт.
    pub fn palette_ui(&mut self, ctx: &egui::Context, current_tool: &str, hosts: &[String]) -> Option<PaletteItem> {
        if !self.palette.open {
            return None;
        }
        let mut result: Option<PaletteItem> = None;
        let mut close = false;
        let mut open = true;
        egui::Window::new("Переход (Ctrl+K)")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .anchor(egui::Align2::CENTER_TOP, [0.0, 60.0])
            .fixed_size([480.0, 380.0])
            .show(ctx, |ui| {
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.palette.query)
                        .hint_text("инструмент, пресет или узел…")
                        .desired_width(f32::INFINITY),
                );
                if self.palette.focus {
                    r.request_focus();
                    self.palette.focus = false;
                }
                let q = self.palette.query.to_lowercase();
                let matches = |s: &str| q.is_empty() || s.to_lowercase().contains(&q);
                let mut items: Vec<(String, PaletteItem)> = Vec::new();
                if matches("прокси") {
                    items.push(("Инструмент: Прокси".into(), PaletteItem::Proxy));
                }
                for t in Tool::ALL {
                    if matches(t.title()) || matches(t.hint()) {
                        items.push((format!("Инструмент: {}", t.title()), PaletteItem::Tool(t)));
                    }
                }
                for p in self.store.for_tool(current_tool).into_iter().chain(self.store.for_tool(presets::ALL_TOOLS)) {
                    if matches(&p.name) {
                        items.push((format!("Пресет: {}", p.name), PaletteItem::Preset(current_tool.into(), p.clone())));
                    }
                }
                for h in hosts.iter().filter(|h| !q.is_empty() && matches(h)).take(30) {
                    items.push((format!("Узел: {h}"), PaletteItem::Host(h.clone())));
                }
                let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                let mut picked = None;
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    for (i, (label, _)) in items.iter().enumerate() {
                        let r = ui.add(egui::Button::selectable(i == 0 && !q.is_empty(), label.as_str()).frame(false));
                        if r.clicked() || (enter && i == 0) {
                            picked = Some(i);
                        }
                    }
                });
                if let Some(i) = picked {
                    result = Some(items.swap_remove(i).1);
                }
                if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    close = true;
                }
            });
        if result.is_some() || close || !open {
            self.palette.open = false;
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Общие элементы панелей
// ---------------------------------------------------------------------------

/// Панель пресетов инструмента: применение, сохранение, импорт, экспорт.
pub fn preset_bar<T: Serialize + DeserializeOwned>(ui: &mut egui::Ui, env: &mut Env, tool: &str, cfg: &mut T) {
    match presets::bar(ui, env.store, tool) {
        Some(BarAction::Apply(p)) => match presets::apply(cfg, &p.values) {
            Ok(()) => *env.message = Some(format!("применён пресет «{}»", p.name)),
            Err(e) => *env.message = Some(e),
        },
        Some(BarAction::Delete(p)) => {
            env.store.remove(&p.tool, &p.name);
            *env.message = Some(match env.store.save() {
                Ok(()) => format!("пресет «{}» удалён", p.name),
                Err(e) => e,
            });
        }
        Some(BarAction::Save) => {
            *env.save = SaveDialog {
                open: true,
                tool: tool.into(),
                name: String::new(),
                description: String::new(),
                with_targets: false,
            };
            *env.pending_save = Some((presets::snapshot(cfg, tool, true), presets::snapshot(cfg, tool, false)));
        }
        Some(BarAction::Import) => {
            if let Some(path) = rfd::FileDialog::new().add_filter("Пресеты", &["json"]).pick_file() {
                *env.message = Some(match env.store.import(&path).and_then(|n| env.store.save().map(|_| n)) {
                    Ok(n) => format!("импортировано пресетов: {n}"),
                    Err(e) => e,
                });
            }
        }
        Some(BarAction::Export) => {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("Пресеты", &["json"])
                .set_file_name("proxy-scanner-presets.json")
                .save_file()
            {
                let user = env.store.user.clone();
                *env.message = Some(match env.store.export(&user, &path) {
                    Ok(()) => format!("экспортировано пресетов: {}", user.len()),
                    Err(e) => e,
                });
            }
        }
        None => {}
    }
}

/// Кнопки «Запустить / Остановить».
pub fn run_button(ui: &mut egui::Ui, busy: bool, label: &str) -> (bool, bool) {
    let mut start = false;
    let mut stop = false;
    ui.horizontal(|ui| {
        if busy {
            ui.spinner();
            if ui.button("■ Остановить").clicked() {
                stop = true;
            }
        } else if ui.add(egui::Button::new(RichText::new(format!("▶ {label}")).strong())).clicked() {
            start = true;
        }
    });
    (start, stop)
}

/// Сохранение отчёта в файл (JSON или текст) и копирование текста.
pub fn export_buttons<R: Serialize>(ui: &mut egui::Ui, env: &mut Env, name: &str, report: &R, text: impl Fn(&R) -> String) {
    ui.menu_button("Экспорт ▾", |ui| {
        if ui.button("Сохранить JSON…").clicked() {
            ui.close();
            if let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).set_file_name(format!("{name}.json")).save_file() {
                let res = serde_json::to_string_pretty(report)
                    .map_err(|e| e.to_string())
                    .and_then(|t| std::fs::write(&path, t).map_err(|e| e.to_string()));
                *env.message = Some(match res {
                    Ok(()) => format!("сохранено: {}", path.display()),
                    Err(e) => e,
                });
            }
        }
        if ui.button("Сохранить текст…").clicked() {
            ui.close();
            if let Some(path) = rfd::FileDialog::new().add_filter("Текст", &["txt"]).set_file_name(format!("{name}.txt")).save_file() {
                *env.message = Some(match std::fs::write(&path, text(report)) {
                    Ok(()) => format!("сохранено: {}", path.display()),
                    Err(e) => e.to_string(),
                });
            }
        }
        if ui.button("Копировать текстом").clicked() {
            ui.close();
            ui.ctx().copy_text(text(report));
        }
    });
}

/// Меню «Отправить в…» для узла.
pub fn send_menu(ui: &mut egui::Ui, host: &str, nav: &mut Option<Nav>, except: Tool) {
    ui.label(RichText::new(host).strong());
    if ui.button("Копировать").clicked() {
        ui.ctx().copy_text(host.to_string());
        ui.close();
    }
    ui.separator();
    for t in [Tool::Mtr, Tool::Dns, Tool::Http, Tool::Services, Tool::Tls, Tool::Audit, Tool::Monitor, Tool::Matrix] {
        if t == except {
            continue;
        }
        if ui.button(format!("→ {}", t.title())).clicked() {
            *nav = Some(Nav::Send(t, host.to_string()));
            ui.close();
        }
    }
    if ui.button("→ Прокси (цель сканирования)").clicked() {
        *nav = Some(Nav::Proxy(host.split(':').next().unwrap_or(host).to_string()));
        ui.close();
    }
}

/// Таблица с заголовками; возвращает индекс строки, по которой щёлкнули.
pub fn table(
    ui: &mut egui::Ui,
    id: &str,
    cols: &[(&str, f32)],
    n: usize,
    selected: Option<usize>,
    mut cell: impl FnMut(usize, usize, &mut egui::Ui),
    mut menu: impl FnMut(usize, &mut egui::Ui),
) -> Option<usize> {
    let mut clicked = None;
    egui::ScrollArea::horizontal().id_salt((id, "h")).show(ui, |ui| {
        let mut tb = TableBuilder::new(ui)
            .id_salt(id)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .min_scrolled_height(0.0);
        for (i, (_, w)) in cols.iter().enumerate() {
            tb = tb.column(if i + 1 == cols.len() {
                Column::remainder().at_least(*w).clip(true)
            } else {
                Column::initial(*w).at_least(30.0).clip(true)
            });
        }
        tb.header(22.0, |mut h| {
            for (title, _) in cols {
                h.col(|ui| {
                    ui.strong(*title);
                });
            }
        })
        .body(|body| {
            body.rows(20.0, n, |mut row| {
                let i = row.index();
                row.set_selected(selected == Some(i));
                for c in 0..cols.len() {
                    row.col(|ui| cell(i, c, ui));
                }
                let r = row.response();
                if r.clicked() {
                    clicked = Some(i);
                }
                r.context_menu(|ui| menu(i, ui));
            });
        });
    });
    clicked
}

/// Строка состояния панели: прогресс и сообщение.
pub fn progress(ui: &mut egui::Ui, done: u64, total: u64, busy: bool) {
    if total == 0 {
        return;
    }
    let f = done as f32 / total as f32;
    ui.add(
        egui::ProgressBar::new(f)
            .desired_height(14.0)
            .text(format!("{done} / {total}{}", if busy { "" } else { " — готово" })),
    );
}

pub fn opt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}")).unwrap_or_else(|| "—".into())
}

/// Мини-график задержек (None — потеря, красная черта).
pub fn sparkline(ui: &mut egui::Ui, values: &[Option<f64>], width: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 14.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let n = values.len().min((width / 3.0) as usize).max(1);
    let slice = &values[values.len().saturating_sub(n)..];
    let max = slice.iter().flatten().cloned().fold(1.0f64, f64::max);
    let bw = rect.width() / n as f32;
    for (i, v) in slice.iter().enumerate() {
        let x = rect.left() + i as f32 * bw;
        match v {
            Some(v) => {
                let h = ((*v / max) as f32 * rect.height()).max(1.0);
                painter.rect_filled(
                    egui::Rect::from_min_max(egui::pos2(x, rect.bottom() - h), egui::pos2(x + bw - 1.0, rect.bottom())),
                    0.0,
                    ui.visuals().widgets.active.bg_fill,
                );
            }
            None => {
                painter.rect_filled(
                    egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2(x + bw - 1.0, rect.bottom())),
                    0.0,
                    RED.gamma_multiply(0.7),
                );
            }
        }
    }
}

/// Свёрнутый блок с редко нужными параметрами.
pub fn advanced(ui: &mut egui::Ui, id: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new("Дополнительно").id_salt(id).default_open(false).show(ui, add);
}

pub fn labeled<R>(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.label(label);
    let r = add(ui);
    ui.end_row();
    r
}

/// Многострочное поле на всю ширину.
pub fn multiline(ui: &mut egui::Ui, text: &mut String, rows: usize, hint: &str) {
    ui.add(egui::TextEdit::multiline(text).desired_rows(rows).desired_width(f32::INFINITY).hint_text(hint));
}

pub fn singleline(ui: &mut egui::Ui, text: &mut String, hint: &str) {
    ui.add(egui::TextEdit::singleline(text).desired_width(f32::INFINITY).hint_text(hint));
}

/// Моноширинный текст с прокруткой и копированием.
pub fn mono_block(ui: &mut egui::Ui, id: &str, text: &str, max_height: f32) {
    egui::ScrollArea::both().id_salt(id).max_height(max_height).auto_shrink([false, true]).show(ui, |ui| {
        let mut t = text.to_string();
        ui.add(
            egui::TextEdit::multiline(&mut t)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .interactive(true),
        );
    });
}
