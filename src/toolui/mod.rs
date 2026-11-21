//! Интерфейс инструментов диагностики: панели параметров и результатов, пресеты,
//! палитра команд (Ctrl+K) и передача узлов между инструментами.

mod ad;
mod audit;
mod capture;
mod certs;
mod compare;
mod discovery;
mod dns;
mod host;
mod http;
mod ipam;
mod map;
mod matrix;
mod monitor;
mod mtr;
mod playbooks;
mod services;
mod shares;
mod sitecheck;
mod switches;
mod threats;
mod tls;
mod urlcheck;
mod watch;

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
    Shares,
    Map,
    Capture,
    SiteCheck,
    Watch,
    Threats,
    Switches,
    Playbooks,
    Overview,
    Ipam,
}

impl Tool {
    pub const ALL: [Tool; 24] = [
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
        Tool::Shares,
        Tool::Map,
        Tool::Capture,
        Tool::SiteCheck,
        Tool::Watch,
        Tool::Threats,
        Tool::Switches,
        Tool::Playbooks,
        Tool::Overview,
        Tool::Ipam,
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
            Tool::Shares => "Общие ресурсы",
            Tool::Map => "Карта",
            Tool::Capture => "Трафик",
            Tool::SiteCheck => "Почему не открывается",
            Tool::Watch => "Наблюдение",
            Tool::Threats => "Угрозы",
            Tool::Switches => "Коммутаторы",
            Tool::Playbooks => "Сценарии",
            Tool::Overview => "Обзор",
            Tool::Ipam => "Адреса",
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
            Tool::Shares => "SMB-шары и NFS-экспорты на узлах; доступ без пароля",
            Tool::Map => "Карта сети из собранных данных: шлюзы, путь, подсети, серверы, контроллеры",
            Tool::Capture => "Захват пакетов и прослушивание: коммутатор и порт (LLDP/CDP), DHCP-серверы, подмена ARP, pcapng",
            Tool::SiteCheck => "Сквозная проверка адреса: DNS → TCP → TLS → HTTP → прокси/PAC; вывод, что мешает",
            Tool::Watch => "Опрос подсетей по расписанию: новые и пропавшие узлы, смена MAC, порты, сертификаты",
            Tool::Threats => "Атаки и посторонние устройства в сегменте по служебному трафику",
            Tool::Switches => "SNMP: какой MAC за каким портом и в каком VLAN; соседи LLDP",
            Tool::Playbooks => "Последовательность проверок одной кнопкой: приёмка сегмента, домен, аудит",
            Tool::Overview => "Состояние сети одним экраном: тревоги, сбои, угрозы, сертификаты",
            Tool::Ipam => "Учёт адресов: занято и свободно, давно не появлялись, расхождения DNS, конфликты",
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
            Tool::Shares => "shares",
            Tool::Map => "map",
            Tool::Capture => "capture",
            Tool::SiteCheck => "sitecheck",
            Tool::Watch => "watch",
            Tool::Threats => "threats",
            Tool::Switches => "snmp",
            Tool::Playbooks => "playbooks",
            Tool::Overview => "overview",
            Tool::Ipam => "ipam",
        }
    }
}

/// Переход, запрошенный из панели.
pub enum Nav {
    /// Открыть инструмент с узлом.
    Send(Tool, String),
    /// Открыть раздел прокси с целями.
    Proxy(String),
    /// Открыть инструмент, ничего не меняя.
    Open(Tool),
    /// Карточка узла.
    Card(String),
    /// Разбудить узел (Wake-on-LAN).
    Wake(String),
    /// Где воткнут узел (по таблицам коммутаторов).
    Locate(String),
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
    /// Что нашло сканирование на вкладке «Прокси».
    pub scan: ScanInfo,
}

/// Что нашло сканирование на вкладке «Прокси»: для подстановки в другие разделы.
#[derive(Debug, Clone, Default)]
pub struct ScanInfo {
    /// Что сканировалось (сети, диапазоны).
    pub targets: String,
    pub found: Vec<Found>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundKind {
    HttpProxy,
    Socks,
    Web,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub struct Found {
    pub ip: std::net::Ipv4Addr,
    pub port: u16,
    pub kind: FoundKind,
    /// Отвечает по TLS (есть сертификат или типичный порт HTTPS).
    pub tls: bool,
}

const TLS_PORTS: [u16; 8] = [443, 465, 636, 993, 995, 3269, 8443, 9443];

impl ScanInfo {
    pub fn is_empty(&self) -> bool {
        self.found.is_empty()
    }
    /// Узлы с открытыми портами (без повторов, по порядку адресов).
    pub fn hosts(&self) -> Vec<std::net::Ipv4Addr> {
        let mut v: Vec<_> = self.found.iter().map(|f| f.ip).collect();
        v.sort();
        v.dedup();
        v
    }
    pub fn hosts_text(&self) -> String {
        self.hosts().iter().map(|h| h.to_string()).collect::<Vec<_>>().join(", ")
    }
    fn ports_of(&self, keep: impl Fn(&Found) -> bool) -> Vec<u16> {
        let mut v: Vec<_> = self.found.iter().filter(|f| keep(f)).map(|f| f.port).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
    pub fn ports_text(&self) -> String {
        join_ports(&self.ports_of(|_| true))
    }
    /// Узлы и порты с TLS.
    pub fn tls(&self) -> (Vec<std::net::Ipv4Addr>, Vec<u16>) {
        let is = |f: &Found| f.tls || TLS_PORTS.contains(&f.port);
        let mut hosts: Vec<_> = self.found.iter().filter(|f| is(f)).map(|f| f.ip).collect();
        hosts.sort();
        hosts.dedup();
        (hosts, self.ports_of(is))
    }
    /// Узлы, где открыт один из портов.
    pub fn hosts_with(&self, ports: &[u16]) -> Vec<std::net::Ipv4Addr> {
        let mut v: Vec<_> = self.found.iter().filter(|f| ports.contains(&f.port)).map(|f| f.ip).collect();
        v.sort();
        v.dedup();
        v
    }
    /// Адреса найденных веб-серверов.
    pub fn web_urls(&self) -> Vec<String> {
        self.found
            .iter()
            .filter(|f| f.kind == FoundKind::Web)
            .map(|f| {
                let https = f.tls || TLS_PORTS.contains(&f.port);
                match (https, f.port) {
                    (true, 443) => format!("https://{}/", f.ip),
                    (false, 80) => format!("http://{}/", f.ip),
                    (true, p) => format!("https://{}:{p}/", f.ip),
                    (false, p) => format!("http://{}:{p}/", f.ip),
                }
            })
            .collect()
    }
    /// Найденные HTTP-прокси `ip:порт`.
    pub fn http_proxies(&self) -> Vec<String> {
        self.found.iter().filter(|f| f.kind == FoundKind::HttpProxy).map(|f| format!("{}:{}", f.ip, f.port)).collect()
    }
    /// Все открытые порты `ip:порт`.
    pub fn endpoints(&self) -> Vec<String> {
        self.found.iter().map(|f| format!("{}:{}", f.ip, f.port)).collect()
    }
}

fn join_ports(v: &[u16]) -> String {
    v.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
}

/// Строка кнопок «Из сканирования: …» под полем адресов. Возвращает номер нажатой.
/// Ничего не показывает, если сканирование ничего не нашло.
pub fn from_scan(ui: &mut egui::Ui, scan: &ScanInfo, buttons: &[(String, &str)]) -> Option<usize> {
    if scan.is_empty() {
        return None;
    }
    let mut hit = None;
    ui.horizontal_wrapped(|ui| {
        ui.weak("Из сканирования:");
        for (i, (label, hint)) in buttons.iter().enumerate() {
            // «(0)» — подставлять нечего.
            let some = !label.ends_with("(0)");
            if ui.add_enabled(some, egui::Button::new(label.as_str()).small()).on_hover_text(*hint).clicked() {
                hit = Some(i);
            }
        }
    });
    hit
}

/// Меню выбора одного найденного значения (узел, адрес сайта, прокси).
pub fn pick_menu(ui: &mut egui::Ui, label: &str, items: &[String]) -> Option<String> {
    let mut picked = None;
    ui.menu_button(label, |ui| {
        egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
            for it in items {
                if ui.button(it).clicked() {
                    picked = Some(it.clone());
                    ui.close();
                }
            }
        });
    });
    picked
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
    pub shares: crate::tools::shares::Config,
    pub capture: crate::tools::capture::Config,
    pub sitecheck: crate::tools::sitecheck::Config,
    pub watch: crate::tools::watch::Config,
    pub snmp: crate::tools::snmp::Config,
    pub ipam: crate::tools::ipam::Config,
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
    pub shares: Option<crate::tools::shares::Report>,
    /// Сводка прослушивания (без самих пакетов).
    pub capture: Option<crate::tools::capture::Summary>,
    pub sitecheck: Option<crate::tools::sitecheck::Report>,
    pub snmp: Option<crate::tools::snmp::Report>,
    pub watch: Option<crate::tools::watch::Report>,
    /// Заметки и метки к узлам.
    pub notes: std::collections::BTreeMap<String, crate::hostcard::HostNote>,
}

pub use capture::render_summary as render_capture_summary;

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
    shares: shares::Panel,
    map: map::Panel,
    capture: capture::Panel,
    sitecheck: sitecheck::Panel,
    watch: watch::Panel,
    switches: switches::Panel,
    playbooks: playbooks::Panel,
    ipam: ipam::Panel,
    notes: std::collections::BTreeMap<String, crate::hostcard::HostNote>,
    /// Открытые карточки узлов.
    cards: Vec<crate::hostcard::Card>,
    /// Переход, запрошенный из карточки.
    card_nav: Option<Nav>,
    /// Обновление баз через интернет.
    update_task: Option<crate::tools::Task<crate::updates::Event>>,
    pub update_status: String,
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
            shares: shares::Panel::new(prefs.shares),
            map: map::Panel::default(),
            capture: capture::Panel::new(prefs.capture),
            sitecheck: sitecheck::Panel::new(prefs.sitecheck),
            watch: watch::Panel::new(prefs.watch),
            switches: switches::Panel::new(prefs.snmp),
            playbooks: playbooks::Panel::default(),
            ipam: ipam::Panel::new(prefs.ipam),
            notes: Default::default(),
            cards: Vec::new(),
            card_nav: None,
            update_task: None,
            update_status: String::new(),
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
        self.shares.cfg = p.shares;
        self.capture.cfg = p.capture;
        self.sitecheck.cfg = p.sitecheck;
        self.watch.cfg = p.watch;
        self.switches.cfg = p.snmp;
        self.ipam.cfg = p.ipam;
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
            shares: self.shares.cfg.clone(),
            capture: self.capture.cfg.clone(),
            sitecheck: self.sitecheck.cfg.clone(),
            watch: self.watch.cfg.clone(),
            snmp: self.switches.cfg.clone(),
            ipam: self.ipam.cfg.clone(),
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
            shares: (!self.shares.report.hosts.is_empty()).then(|| self.shares.report.clone()),
            capture: (self.capture.summary.packets > 0).then(|| self.capture.summary.clone()),
            sitecheck: (!self.sitecheck.report.steps.is_empty()).then(|| self.sitecheck.report.clone()),
            snmp: (!self.switches.report.switches.is_empty()).then(|| self.switches.report.clone()),
            watch: self.watch.report.last.is_some().then(|| self.watch.report.clone()),
            notes: self.notes.iter().filter(|(_, n)| !n.is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect(),
        }
    }

    /// Есть ли что сохранять в сессию.
    pub fn has_results(&self) -> bool {
        serde_json::to_value(self.results())
            .ok()
            .and_then(|v| v.as_object().map(|m| m.values().any(|x| !x.is_null() && x.as_object().is_none_or(|o| !o.is_empty()))))
            .unwrap_or(false)
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
        if let Some(v) = r.shares {
            self.shares.report = v;
        }
        if let Some(v) = r.capture {
            self.capture.summary = v;
        }
        if let Some(v) = r.sitecheck {
            self.sitecheck.report = v;
        }
        if let Some(v) = r.snmp {
            self.switches.report = v;
        }
        if let Some(v) = r.watch {
            self.watch.report = v;
        }
        if !r.notes.is_empty() {
            self.notes = r.notes;
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
        self.shares.report = Default::default();
        self.capture.summary = Default::default();
        self.sitecheck.report = Default::default();
        self.switches.report = Default::default();
        self.watch.report = Default::default();
        self.notes.clear();
        self.cards.clear();
    }

    /// Контекст для «Сертификатов» и «Сравнения»: снимок сессии и архив.
    pub fn set_context(&mut self, current: crate::session::Session, archive: Vec<(String, std::path::PathBuf)>) {
        self.certs.certs = crate::tools::certs::collect(&current);
        self.map.refresh(&current);
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
        changed |= self.shares.poll();
        changed |= self.capture.poll();
        changed |= self.sitecheck.poll();
        changed |= self.watch.poll();
        changed |= self.switches.poll();
        changed |= self.ipam.poll();
        if let Some(t) = &self.update_task {
            let ev = t.drain();
            let fin = t.finished();
            changed |= !ev.is_empty() || fin;
            for e in ev {
                match e {
                    crate::updates::Event::Log(l) => self.update_status = l,
                    crate::updates::Event::Done(d, _) => {
                        if !d.is_empty() {
                            self.message = Some(d.clone());
                        }
                        self.update_status = d;
                    }
                }
            }
            if fin {
                self.update_task = None;
            }
        }
        if self.playbooks.poll() {
            changed = true;
            if let Some(r) = self.playbooks.finished.take() {
                self.restore_results(r);
                self.message = Some("сценарий выполнен — результаты во вкладках".into());
            }
        }
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
            Tool::Shares => self.shares.busy(),
            Tool::Map | Tool::Overview => false,
            Tool::Capture | Tool::Threats => self.capture.busy(),
            Tool::SiteCheck => self.sitecheck.busy(),
            Tool::Watch => self.watch.busy(),
            Tool::Switches => self.switches.busy(),
            Tool::Playbooks => self.playbooks.busy(),
            Tool::Ipam => self.ipam.busy(),
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
            Tool::Shares => self.shares.report.shares.len(),
            Tool::Map => return None,
            Tool::Capture => {
                let s = &self.capture.summary;
                if s.dhcp.len() > 1 || !s.arp_conflicts().is_empty() {
                    return Some("⚠".into());
                }
                return (s.packets > 0).then(|| s.packets.to_string());
            }
            Tool::Threats => {
                let n = crate::tools::threats::assess(&self.capture.summary).iter().filter(|t| t.level != crate::tools::threats::Level::Low).count();
                return (n > 0).then(|| format!("⚠{n}"));
            }
            Tool::SiteCheck => {
                if self.sitecheck.report.verdict.is_empty() {
                    return None;
                }
                return Some(if self.sitecheck.report.ok { "✔".into() } else { "✖".into() });
            }
            Tool::Watch => {
                let a = self.watch.alarms();
                if a > 0 {
                    return Some(format!("⚠{a}"));
                }
                self.watch.report.changes.len()
            }
            Tool::Switches => self.switches.report.switches.iter().map(|s| s.entries.len()).sum(),
            Tool::Playbooks | Tool::Overview | Tool::Ipam => return None,
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
        scan: ScanInfo,
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
            scan,
        }
    }

    pub fn settings_ui(
        &mut self,
        t: Tool,
        ui: &mut egui::Ui,
        rt: &Handle,
        local_cidr: Option<String>,
        scan: ScanInfo,
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
            scan,
        );
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
            Tool::Shares => self.shares.settings_ui(ui, &mut env),
            Tool::Map => self.map.settings_ui(ui, &mut env),
            Tool::Capture => self.capture.settings_ui(ui, &mut env),
            Tool::SiteCheck => self.sitecheck.settings_ui(ui, &mut env),
            Tool::Watch => self.watch.settings_ui(ui, &mut env),
            Tool::Threats => threats::settings_ui(&mut self.capture, ui, &mut env),
            Tool::Switches => {
                let gw: Vec<String> = self.host.report.iter().flat_map(|r| r.interfaces.iter()).flat_map(|i| i.gateways.iter().cloned()).filter(|g| g.parse::<std::net::Ipv4Addr>().is_ok_and(|a| !a.is_unspecified())).collect();
                self.switches.settings_ui(ui, &mut env, &gw)
            }
            Tool::Playbooks => self.playbooks.settings_ui(ui, &mut env),
            Tool::Overview => overview_settings(ui),
            Tool::Ipam => {
                let known = self.current.as_ref().map(crate::tools::ipam::known_hosts).unwrap_or_default();
                self.ipam.settings_ui(ui, &mut env, &known)
            }
        }
        nav
    }

    pub fn results_ui(&mut self, t: Tool, ui: &mut egui::Ui, rt: &Handle) -> Option<Nav> {
        if t == Tool::Overview {
            return self.overview_ui(ui).map(Nav::Open);
        }
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
            ScanInfo::default(),
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
            Tool::Shares => self.shares.results_ui(ui, &mut env),
            Tool::Map => self.map.results_ui(ui, &mut env),
            Tool::Capture => self.capture.results_ui(ui, &mut env),
            Tool::SiteCheck => self.sitecheck.results_ui(ui, &mut env),
            Tool::Watch => self.watch.results_ui(ui, &mut env),
            Tool::Threats => threats::results_ui(&self.capture, ui),
            Tool::Switches => {
                let names = |mac: &str| -> Option<(String, String)> {
                    let m = crate::tools::snmp::norm_mac(mac);
                    if let Some(h) = self.discovery.report.hosts.iter().find(|h| h.mac.as_deref().map(crate::tools::snmp::norm_mac).as_deref() == Some(m.as_str())) {
                        return Some((h.ip.to_string(), h.best_name()));
                    }
                    if let Some(last) = &self.watch.report.last
                        && let Some((ip, h)) = last.hosts.iter().find(|(_, h)| h.mac.as_deref().map(crate::tools::snmp::norm_mac).as_deref() == Some(m.as_str()))
                    {
                        return Some((ip.to_string(), h.name.clone().unwrap_or_default()));
                    }
                    None
                };
                self.switches.results_ui(ui, &mut env, &names)
            }
            Tool::Playbooks => self.playbooks.results_ui(ui, &mut env),
            Tool::Overview => {}
            Tool::Ipam => {
                let known = self.current.as_ref().map(crate::tools::ipam::known_hosts).unwrap_or_default();
                self.ipam.results_ui(ui, &mut env, &known, &self.notes)
            }
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
            ScanInfo::default(),
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
            Tool::Certs | Tool::Compare | Tool::Map | Tool::Threats | Tool::Playbooks | Tool::Overview => Ok(()),
            Tool::Capture => presets::apply(&mut self.capture.cfg, &p.values),
            Tool::SiteCheck => presets::apply(&mut self.sitecheck.cfg, &p.values),
            Tool::Watch => presets::apply(&mut self.watch.cfg, &p.values),
            Tool::Switches => presets::apply(&mut self.switches.cfg, &p.values),
            Tool::Ipam => presets::apply(&mut self.ipam.cfg, &p.values),
            Tool::UrlCheck => presets::apply(&mut self.urlcheck.cfg, &p.values),
            Tool::Shares => presets::apply(&mut self.shares.cfg, &p.values),
        };
        self.message = Some(match r {
            Ok(()) => format!("применён пресет «{}»", p.name),
            Err(e) => e,
        });
    }

    /// Обзор: карточки по инструментам контроля сети.
    fn overview_ui(&self, ui: &mut egui::Ui) -> Option<Tool> {
        let mut open = None;
        use crate::tools::monitor::Status as MS;
        use crate::tools::threats::{self, Level};
        let mut cards: Vec<(Tool, Color32, String, Vec<String>)> = Vec::new();
        let muted = ui.visuals().weak_text_color();
        // Наблюдение.
        let w = &self.watch;
        let alarms = w.alarms();
        let mut lines: Vec<String> = w
            .report
            .changes
            .iter()
            .rev()
            .take(5)
            .map(|c| format!("{} {} — {} {}", crate::session::format_time(c.at), c.host, c.kind.label(), c.detail))
            .collect();
        let (color, head) = match (&w.report.last, alarms) {
            (None, _) if !w.busy() => (muted, "не запущено".to_string()),
            (None, _) => (AMBER, "первый опрос…".to_string()),
            (Some(l), 0) => (GREEN, format!("{} узлов, тревог нет", l.hosts.len())),
            (Some(l), a) => (RED, format!("{} узлов, тревог: {a}", l.hosts.len())),
        };
        if w.busy() {
            lines.insert(0, "идёт наблюдение".into());
        }
        cards.push((Tool::Watch, color, head, lines));
        // Мониторинг.
        let m = &self.monitor.report;
        let fails: Vec<String> = m.states.iter().filter(|s| s.status == MS::Fail).map(|s| format!("✖ {}", s.line)).collect();
        let warns = m.states.iter().filter(|s| s.status == MS::Warn).count();
        let (color, head) = if m.states.is_empty() {
            (muted, "не запущен".to_string())
        } else if !fails.is_empty() {
            (RED, format!("сбоев: {}, внимание: {warns}, проверок: {}", fails.len(), m.states.len()))
        } else if warns > 0 {
            (AMBER, format!("внимание: {warns} из {}", m.states.len()))
        } else {
            (GREEN, format!("все {} проверок в норме", m.states.len()))
        };
        cards.push((Tool::Monitor, color, head, fails.into_iter().take(5).collect()));
        // Угрозы.
        let t = threats::assess(&self.capture.summary);
        let high = t.iter().filter(|x| x.level == Level::High).count();
        let (color, head) = if self.capture.summary.packets == 0 {
            (muted, if self.capture.busy() { "слушаю…".to_string() } else { "сегмент не прослушивался".to_string() })
        } else if high > 0 {
            (RED, format!("высокая важность: {high}"))
        } else if !t.is_empty() {
            (AMBER, format!("находок: {}", t.len()))
        } else {
            (GREEN, "угроз не найдено".to_string())
        };
        cards.push((Tool::Threats, color, head, t.iter().take(4).map(|x| format!("{} — {}", x.level.label(), x.title)).collect()));
        // Сертификаты.
        let exp: Vec<String> = self
            .certs
            .certs
            .iter()
            .filter(|c| c.days_left.is_some_and(|d| d < self.certs.warn_days))
            .take(5)
            .map(|c| format!("{} дн. — {}", c.days_left.unwrap_or_default(), c.subject))
            .collect();
        let (color, head) = if self.certs.certs.is_empty() {
            (muted, "сертификатов в сессии нет".to_string())
        } else if !exp.is_empty() {
            (RED, format!("истекают: {}", self.certs.certs.iter().filter(|c| c.days_left.is_some_and(|d| d < self.certs.warn_days)).count()))
        } else {
            (GREEN, format!("{} сертификатов, сроки в порядке", self.certs.certs.len()))
        };
        cards.push((Tool::Certs, color, head, exp));
        // Аудит.
        let a = &self.audit.report;
        let h = a.count(crate::tools::tlsaudit::Severity::High);
        let (color, head) = if a.services.is_empty() {
            (muted, "аудит не проводился".to_string())
        } else if h > 0 {
            (RED, format!("высокая важность: {h}, всего находок: {}", a.issues.len()))
        } else {
            (GREEN, format!("находок: {}", a.issues.len()))
        };
        cards.push((Tool::Audit, color, head, a.issues.iter().take(4).map(|i| format!("{} {}", i.ip, i.title)).collect()));
        // Сценарии.
        let head = match &self.playbooks.last_run {
            Some((n, at)) => format!("последний: «{n}» {}", crate::session::format_time(*at)),
            None => "ещё не запускались".to_string(),
        };
        cards.push((Tool::Playbooks, if self.playbooks.busy() { AMBER } else { muted }, head, Vec::new()));

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let w = ui.available_width();
            let cols = if w > 980.0 { 3 } else if w > 620.0 { 2 } else { 1 };
            ui.columns(cols, |columns| {
                for (i, (tool, color, head, lines)) in cards.iter().enumerate() {
                    let ui = &mut columns[i % cols];
                    let r = egui::Frame::group(ui.style())
                        .stroke(egui::Stroke::new(if *color == muted { 1.0 } else { 1.5 }, *color))
                        .inner_margin(egui::Margin::same(10))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.set_min_height(120.0);
                            ui.label(RichText::new(tool.title()).heading());
                            ui.add(egui::Label::new(RichText::new(head).strong().color(*color)).wrap());
                            for l in lines {
                                ui.add(egui::Label::new(RichText::new(l).small()).truncate());
                            }
                        })
                        .response
                        .interact(egui::Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("Открыть");
                    if r.clicked() {
                        open = Some(*tool);
                    }
                    ui.add_space(8.0);
                }
            });
        });
        open
    }

    /// Обновить базы через интернет (`quiet` — молча, если интернета нет).
    pub fn start_update(&mut self, rt: &Handle, ctx: &egui::Context, quiet: bool) {
        if self.update_task.is_some() {
            return;
        }
        self.update_status = "проверка обновлений…".into();
        self.update_task = Some(crate::tools::Task::spawn(rt, ctx, move |s, c| crate::updates::run(quiet, s, c)));
    }

    pub fn updating(&self) -> bool {
        self.update_task.is_some()
    }

    /// Открыть карточку узла (по снимку сессии).
    pub fn open_card(&mut self, ip: &str, s: &crate::session::Session) {
        let Ok(addr) = ip.split(':').next().unwrap_or(ip).parse::<std::net::Ipv4Addr>() else {
            self.message = Some(format!("{ip}: карточка — только для адресов IPv4"));
            return;
        };
        let card = crate::hostcard::build(s, addr);
        self.cards.retain(|c| c.ip != card.ip);
        self.cards.push(card);
        if self.cards.len() > 4 {
            self.cards.remove(0);
        }
    }

    /// Переход из карточки (забирает приложение).
    pub fn take_card_nav(&mut self) -> Option<Nav> {
        self.card_nav.take()
    }

    /// Пересобрать открытые карточки (после новых результатов).
    pub fn refresh_cards(&mut self, s: &crate::session::Session) {
        for c in &mut self.cards {
            if let Ok(a) = c.ip.parse() {
                *c = crate::hostcard::build(s, a);
            }
        }
    }

    pub fn has_cards(&self) -> bool {
        !self.cards.is_empty()
    }

    fn cards_ui(&mut self, ctx: &egui::Context) {
        use crate::hostcard::Level;
        let mut close = Vec::new();
        for (i, card) in self.cards.iter().enumerate() {
            let mut open = true;
            let note = self.notes.entry(card.ip.clone()).or_default();
            egui::Window::new(RichText::new(&card.title).strong())
                .id(egui::Id::unique(("host_card", &card.ip)))
                .open(&mut open)
                .default_size([520.0, 560.0])
                .default_pos([380.0 + 30.0 * i as f32, 90.0 + 30.0 * i as f32])
                .resizable(true)
                .show(ctx, |ui| {
                    for l in &card.subtitle {
                        ui.label(l);
                    }
                    ui.horizontal_wrapped(|ui| {
                        for (label, nav) in [
                            ("MTR", Nav::Send(Tool::Mtr, card.ip.clone())),
                            ("Сервисы", Nav::Send(Tool::Services, card.ip.clone())),
                            ("Аудит", Nav::Send(Tool::Audit, card.ip.clone())),
                            ("Мониторинг", Nav::Send(Tool::Monitor, card.ip.clone())),
                            ("Где воткнут?", Nav::Locate(card.ip.clone())),
                            ("Разбудить", Nav::Wake(card.ip.clone())),
                        ] {
                            if ui.small_button(label).clicked() {
                                self.card_nav = Some(nav);
                            }
                        }
                        if ui.small_button("Копировать").clicked() {
                            let mut t = vec![card.title.clone()];
                            t.extend(card.subtitle.iter().cloned());
                            for (h, lines) in &card.sections {
                                t.push(format!("\n{h}"));
                                t.extend(lines.iter().map(|l| format!("  {}", l.text)));
                            }
                            if !note.is_empty() {
                                t.push(format!("\nЗаметка: {} {}", note.tags, note.text));
                            }
                            ui.ctx().copy_text(t.join("\n"));
                        }
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Метки");
                        ui.add(egui::TextEdit::singleline(&mut note.tags).hint_text("сервер, 1С, ответственный Иванов").desired_width(f32::INFINITY));
                    });
                    ui.add(egui::TextEdit::multiline(&mut note.text).hint_text("заметка: назначение, где стоит, к кому обращаться").desired_rows(2).desired_width(f32::INFINITY));
                    ui.separator();
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                        if card.sections.is_empty() {
                            ui.weak("Об узле пока ничего не собрано: запустите «Узлы», «Сервисы» или «Аудит».");
                        }
                        for (head, lines) in &card.sections {
                            egui::CollapsingHeader::new(RichText::new(format!("{head} ({})", lines.len())).strong())
                                .id_salt(("card_sec", &card.ip, head))
                                .default_open(true)
                                .show(ui, |ui| {
                                    for l in lines {
                                        let t = RichText::new(&l.text);
                                        let t = match l.level {
                                            Level::Bad => t.color(RED),
                                            Level::Warn => t.color(AMBER),
                                            Level::Good => t.color(GREEN),
                                            Level::Normal => t,
                                        };
                                        ui.add(egui::Label::new(t).wrap());
                                    }
                                });
                        }
                    });
                });
            if !open {
                close.push(i);
            }
        }
        for i in close.into_iter().rev() {
            self.cards.remove(i);
        }
    }

    /// Метки узла (для таблиц).
    pub fn tags_of(&self, ip: &str) -> Option<&str> {
        self.notes.get(ip).map(|n| n.tags.as_str()).filter(|t| !t.trim().is_empty())
    }

    /// MAC узла из того, что уже собрано: «Узлы», «Наблюдение», ARP-таблица, прослушивание.
    pub fn find_mac(&self, ip: &str) -> Option<String> {
        let addr: std::net::Ipv4Addr = ip.parse().ok()?;
        if let Some(m) = self.discovery.report.hosts.iter().find(|h| h.ip == addr).and_then(|h| h.mac.clone()) {
            return Some(m);
        }
        if let Some(m) = self.watch.report.last.as_ref().and_then(|l| l.hosts.get(&addr)).and_then(|h| h.mac.clone()) {
            return Some(m);
        }
        if let Some(m) = self.host.report.as_ref().and_then(|r| r.neighbors.iter().find(|n| n.ip == ip)).map(|n| n.mac.clone()) {
            return Some(m);
        }
        self.capture.summary.arp.get(ip).and_then(|v| v.first().cloned())
    }

    /// Разбудить узел (Wake-on-LAN) — сообщение для строки состояния.
    pub fn wake(&mut self, rt: &Handle, ip: &str) -> String {
        let Some(mac) = self.find_mac(ip) else {
            return format!("{ip}: MAC неизвестен — найдите узел в «Узлах» или «Наблюдении», пока он включён");
        };
        let addr = ip.parse().ok();
        match rt.block_on(crate::tools::wol::wake(&mac, addr)) {
            Ok(m) => m,
            Err(e) => format!("Wake-on-LAN: {e}"),
        }
    }

    /// Где воткнут узел — сообщение для строки состояния.
    pub fn locate(&self, ip: &str) -> String {
        let Some(mac) = self.find_mac(ip) else {
            return format!("{ip}: MAC неизвестен — запустите «Узлы» в этой подсети");
        };
        if self.switches.report.switches.is_empty() {
            return format!("{ip} ({mac}): опросите коммутаторы на вкладке «Коммутаторы» (SNMP)");
        }
        match self.switches.report.locate(&mac) {
            Some(l) => format!(
                "{ip} ({mac}) воткнут в {} порт {}{}{}",
                l.switch,
                l.port,
                l.vlan.map(|v| format!(", VLAN {v}")).unwrap_or_default(),
                if l.alias.is_empty() { String::new() } else { format!(" «{}»", l.alias) }
            ),
            None => format!("{ip} ({mac}) не найден в таблицах опрошенных коммутаторов"),
        }
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
            Tool::Certs | Tool::Compare | Tool::Map | Tool::Threats | Tool::Playbooks | Tool::Overview => {}
            Tool::SiteCheck => self.sitecheck.cfg.url = host.to_string(),
            Tool::Watch => self.watch.cfg.targets = host.split(':').next().unwrap_or(host).to_string(),
            Tool::Switches => self.switches.cfg.switches = host.split(':').next().unwrap_or(host).to_string(),
            Tool::Ipam => {}
            Tool::Capture => self.capture.cfg.filter = format!("host {}", host.split(':').next().unwrap_or(host)),
            Tool::Shares => self.shares.cfg.targets = host.split(':').next().unwrap_or(host).to_string(),
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
        if let Some(v) = get("capture") {
            presets::apply(&mut self.capture.cfg, &v)?;
        }
        if let Some(v) = get("shares") {
            presets::apply(&mut self.shares.cfg, &v)?;
        }
        if let Some(v) = get("sitecheck") {
            presets::apply(&mut self.sitecheck.cfg, &v)?;
        }
        if let Some(v) = get("watch") {
            presets::apply(&mut self.watch.cfg, &v)?;
        }
        if let Some(v) = get("snmp") {
            presets::apply(&mut self.switches.cfg, &v)?;
        }
        Ok(())
    }

    /// Окна, общие для всех инструментов: сохранение пресета, палитра команд.
    pub fn windows(&mut self, ctx: &egui::Context) {
        self.cards_ui(ctx);
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
            .fixed_size([520.0, 440.0])
            .show(ctx, |ui| {
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.palette.query)
                        .hint_text("инструмент, пресет, узел… или 10.0.0.0/22 — калькулятор подсетей")
                        .desired_width(f32::INFINITY),
                );
                if self.palette.focus {
                    r.request_focus();
                    self.palette.focus = false;
                }
                // Калькулятор подсетей прямо в строке перехода.
                if let Some(c) = crate::subnet::calc(&self.palette.query) {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&c.title).strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.small_button("Копировать").clicked() {
                                    let mut t: Vec<String> = c.rows.iter().map(|(k, v)| format!("{k}: {v}")).collect();
                                    t.extend(c.list.iter().cloned());
                                    ui.ctx().copy_text(t.join("\n"));
                                }
                            });
                        });
                        egui::Grid::new("calc_rows").num_columns(2).show(ui, |ui| {
                            for (k, v) in &c.rows {
                                ui.weak(k);
                                ui.monospace(v);
                                ui.end_row();
                            }
                        });
                        if !c.list.is_empty() {
                            egui::ScrollArea::vertical().id_salt("calc_list").max_height(120.0).show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    for n in &c.list {
                                        ui.monospace(n);
                                    }
                                });
                            });
                        }
                    });
                    ui.weak("Ещё: «10.0.0.0/22 /24» — разбить, «10.0.1.5 в 10.0.0.0/22», диапазон «a-b», несколько сетей — суммировать.");
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
    let ip0 = host.split(':').next().unwrap_or(host);
    if ip0.parse::<std::net::Ipv4Addr>().is_ok() && ui.button("🗂 Карточка узла").on_hover_text("Всё, что известно об узле, заметки и метки").clicked() {
        *nav = Some(Nav::Card(ip0.to_string()));
        ui.close();
    }
    if ui.button("Копировать").clicked() {
        ui.ctx().copy_text(host.to_string());
        ui.close();
    }
    ui.separator();
    for t in [Tool::Mtr, Tool::Dns, Tool::Http, Tool::Services, Tool::Tls, Tool::Audit, Tool::Monitor, Tool::Matrix, Tool::Shares] {
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
    if ui.button("→ Почему не открывается").clicked() {
        *nav = Some(Nav::Send(Tool::SiteCheck, host.to_string()));
        ui.close();
    }
    let ip = host.split(':').next().unwrap_or(host).to_string();
    if ip.parse::<std::net::Ipv4Addr>().is_ok() {
        ui.separator();
        if ui.button("Где воткнут? (коммутатор, порт)").on_hover_text("По таблицам MAC-адресов коммутаторов (вкладка «Коммутаторы»)").clicked() {
            *nav = Some(Nav::Locate(ip.clone()));
            ui.close();
        }
        if ui.button("Разбудить (Wake-on-LAN)").on_hover_text("MAC берётся из «Узлов», «Наблюдения» или ARP-таблицы").clicked() {
            *nav = Some(Nav::Wake(ip));
            ui.close();
        }
    }
}

/// Подсказка калькулятора подсетей под полем адресов (если там одна сеть).
pub fn subnet_hint(ui: &mut egui::Ui, text: &str) {
    let t = text.trim();
    if t.contains(',') || t.contains('\n') {
        return;
    }
    if let Some(h) = crate::subnet::hint(t) {
        ui.weak(h);
    }
}

/// Блок «Уведомления» (syslog, почта, файл).
pub fn alerts_ui(ui: &mut egui::Ui, a: &mut crate::tools::notify::Alerts, id: &str, what: &str) {
    let configured = !a.is_empty();
    egui::CollapsingHeader::new(if configured { "Уведомления ✔" } else { "Уведомления" }).id_salt(id).show(ui, |ui| {
        ui.weak(what);
        egui::Grid::new((id, "g")).num_columns(2).show(ui, |ui| {
            labeled(ui, "Syslog", |ui| ui.add(egui::TextEdit::singleline(&mut a.syslog).hint_text("10.0.0.50:514")));
            labeled(ui, "Почта: SMTP", |ui| ui.add(egui::TextEdit::singleline(&mut a.smtp).hint_text("mail.corp.local:25")));
            labeled(ui, "От кого", |ui| ui.add(egui::TextEdit::singleline(&mut a.mail_from).hint_text("monitor@corp.local")));
            labeled(ui, "Кому", |ui| ui.add(egui::TextEdit::singleline(&mut a.mail_to).hint_text("noc@corp.local, …")));
            labeled(ui, "Файл журнала", |ui| ui.add(egui::TextEdit::singleline(&mut a.log_file).hint_text("журнал.log")));
        });
        ui.checkbox(&mut a.on_warn, "Сообщать и о неопасных изменениях");
    });
}

fn overview_settings(ui: &mut egui::Ui) {
    ui.weak("Сводка по всем инструментам контроля. Щелчок по карточке — переход к подробностям.");
    ui.add_space(4.0);
    ui.weak("Чтобы обзор наполнился: запустите «Наблюдение» за подсетями, «Мониторинг» важных узлов и «Угрозы» (прослушивание сегмента).");
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

/// Подписи, которые пропускаются, если текст пустой.
///
/// В строке `horizontal_wrapped` пустая подпись возвращает курсор в начало
/// строки, и следующие элементы рисуются поверх уже выведенных.
pub trait UiNz {
    fn weak_nz(&mut self, text: &str);
    fn mono_nz(&mut self, text: &str);
    fn label_nz(&mut self, text: &str);
}

impl UiNz for egui::Ui {
    fn weak_nz(&mut self, text: &str) {
        if !text.trim().is_empty() {
            self.weak(text);
        }
    }
    fn mono_nz(&mut self, text: &str) {
        if !text.trim().is_empty() {
            self.monospace(text);
        }
    }
    fn label_nz(&mut self, text: &str) {
        if !text.trim().is_empty() {
            self.label(text);
        }
    }
}

#[cfg(test)]
mod scan_info_tests {
    use super::{Found, FoundKind, ScanInfo};

    fn f(ip: &str, port: u16, kind: FoundKind, tls: bool) -> Found {
        Found { ip: ip.parse().unwrap(), port, kind, tls }
    }

    #[test]
    fn helpers() {
        let s = ScanInfo {
            targets: "10.0.0.0/24".into(),
            found: vec![
                f("10.0.0.5", 443, FoundKind::Web, true),
                f("10.0.0.5", 80, FoundKind::Web, false),
                f("10.0.0.2", 3128, FoundKind::HttpProxy, false),
                f("10.0.0.9", 8443, FoundKind::Web, false),
                f("10.0.0.2", 445, FoundKind::Other, false),
            ],
        };
        assert_eq!(s.hosts_text(), "10.0.0.2, 10.0.0.5, 10.0.0.9");
        assert_eq!(s.ports_text(), "80,443,445,3128,8443");
        assert_eq!(s.web_urls(), vec!["https://10.0.0.5/", "http://10.0.0.5/", "https://10.0.0.9:8443/"]);
        assert_eq!(s.http_proxies(), vec!["10.0.0.2:3128"]);
        let (h, p) = s.tls();
        assert_eq!(h.len(), 2);
        assert_eq!(p, vec![443, 8443]);
        assert_eq!(s.hosts_with(&[445]).len(), 1);
    }
}
