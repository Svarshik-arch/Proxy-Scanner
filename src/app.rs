//! Графический интерфейс (egui/eframe) и управление фоновыми задачами.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use egui_extras::{Column, TableBuilder};
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::export;
use crate::model::{
    AppEvent, CertInfo, ProbeResult, ProxyKind, ProxyRow, RowState, ScanMode, Settings,
    SslInspection,
};
use crate::netdetect::{self, IfaceEntry};
use crate::probe::{self, ProbeConfig, Url};
use crate::scan::{self, MasscanConfig, TcpScanConfig, Tx};
use crate::targets::{self, TCP_SCAN_MAX_HOSTS};
use crate::util;

const SETTINGS_KEY: &str = "settings";
const MAX_LOG_LINES: usize = 2000;

const GREEN: Color32 = Color32::from_rgb(60, 170, 90);
const RED: Color32 = Color32::from_rgb(220, 70, 70);
const AMBER: Color32 = Color32::from_rgb(215, 160, 40);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortCol {
    Ip,
    Port,
    Kind,
    Auth,
    Server,
    Connect,
    Ssl,
    Issuer,
    Policy,
    Rtt,
    State,
}

const COLUMNS: &[(SortCol, &str, f32)] = &[
    (SortCol::Ip, "IP-адрес", 110.0),
    (SortCol::Port, "Порт", 50.0),
    (SortCol::Kind, "Тип", 95.0),
    (SortCol::Auth, "Аутентификация", 120.0),
    (SortCol::Connect, "CONNECT", 75.0),
    (SortCol::Ssl, "SSL-инспекция", 105.0),
    (SortCol::Issuer, "Издатель сертификата", 200.0),
    (SortCol::Policy, "Политики", 70.0),
    (SortCol::Server, "Сервер / Via", 180.0),
    (SortCol::Rtt, "мс", 45.0),
    (SortCol::State, "Состояние", 80.0),
];

#[derive(Default)]
struct Filter {
    text: String,
    only_proxy: bool,
    only_ssl: bool,
    only_violations: bool,
}

/// Контекст диагностики, общий для всех проверок одной задачи.
struct ProbeCtx {
    cfg: ProbeConfig,
    sem: Arc<Semaphore>,
}

struct Job {
    cancel: CancellationToken,
    started: Instant,
    discovery_done: bool,
    probe: Option<Arc<ProbeCtx>>,
    /// Эталонный сертификат ещё не получен — проверки ждут в очереди.
    waiting_reference: bool,
    queue: Vec<(Ipv4Addr, u16)>,
    pending_probes: usize,
}

pub struct App {
    rt: Runtime,
    settings: Settings,
    rows: Vec<ProxyRow>,
    index: HashMap<(Ipv4Addr, u16), usize>,
    tx: Sender<AppEvent>,
    rx: Receiver<AppEvent>,
    log: Vec<String>,
    show_log: bool,
    ifaces: Vec<IfaceEntry>,
    detect_busy: bool,
    first_detect: bool,
    job: Option<Job>,
    progress: f32,
    status: String,
    error: Option<String>,
    reference: Option<CertInfo>,
    sort: (SortCol, bool),
    filter: Filter,
    selected: Option<(Ipv4Addr, u16)>,
    is_admin: bool,
    npcap: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: Runtime) -> Self {
        let settings: Settings = cc
            .storage
            .and_then(|s| eframe::get_value(s, SETTINGS_KEY))
            .unwrap_or_default();
        let (tx, rx) = channel();
        let mut app = Self {
            rt,
            settings,
            rows: Vec::new(),
            index: HashMap::new(),
            tx,
            rx,
            log: Vec::new(),
            show_log: false,
            ifaces: Vec::new(),
            detect_busy: false,
            first_detect: true,
            job: None,
            progress: 0.0,
            status: "Готово к работе".into(),
            error: None,
            reference: None,
            sort: (SortCol::Ip, true),
            filter: Filter::default(),
            selected: None,
            is_admin: util::is_admin(),
            npcap: util::npcap_installed(),
        };
        // Автоопределение сетевых параметров при старте.
        app.start_detect(&cc.egui_ctx, false);
        app
    }

    fn tx(&self, ctx: &egui::Context) -> Tx {
        Tx::new(self.tx.clone(), ctx.clone())
    }

    fn push_log(&mut self, msg: impl Into<String>) {
        if self.log.len() >= MAX_LOG_LINES {
            self.log.drain(..MAX_LOG_LINES / 4);
        }
        self.log.push(msg.into());
    }

    fn busy(&self) -> bool {
        self.job.is_some()
    }

    // -----------------------------------------------------------------------
    // Автоопределение сети
    // -----------------------------------------------------------------------

    fn start_detect(&mut self, ctx: &egui::Context, want_mac: bool) {
        if self.detect_busy {
            return;
        }
        self.detect_busy = true;
        let target = targets::parse_targets(&self.settings.targets)
            .ok()
            .and_then(|t| t.first_addr());
        let masscan = util::resolve_masscan(&self.settings.masscan_path);
        let tx = self.tx(ctx);
        self.rt.spawn_blocking(move || {
            let masscan = util::file_exists(&masscan).then_some(masscan);
            let d = netdetect::detect_all(target, masscan.as_deref(), want_mac);
            tx.send(AppEvent::NetDetected(Box::new(d)));
        });
    }

    fn start_router_mac(&mut self, ctx: &egui::Context) {
        let Ok(router) = self.settings.router_ip.trim().parse::<Ipv4Addr>() else {
            self.error = Some("Сначала укажите корректный IP шлюза (router-ip)".into());
            return;
        };
        let tx = self.tx(ctx);
        self.rt.spawn_blocking(move || {
            tx.send(AppEvent::RouterMac(netdetect::detect_router_mac(router)));
        });
    }

    fn apply_detect(&mut self, d: netdetect::NetDetect) {
        self.detect_busy = false;
        for line in &d.log {
            self.push_log(format!("сеть: {line}"));
        }
        // При первом (автоматическом) запуске не затираем значения, введённые вручную ранее.
        let overwrite = !self.first_detect;
        self.first_detect = false;
        let set = |field: &mut String, value: Option<String>| {
            if let Some(v) = value
                && (overwrite || field.trim().is_empty())
            {
                *field = v;
            }
        };
        set(&mut self.settings.source_ip, d.source_ip.map(|v| v.to_string()));
        set(&mut self.settings.router_ip, d.router_ip.map(|v| v.to_string()));
        if let Some(mac) = d.router_mac {
            self.settings.router_mac = mac;
        }
        if !d.ifaces.is_empty() {
            self.ifaces = d.ifaces;
        }
        let known = self
            .ifaces
            .iter()
            .any(|e| e.device.eq_ignore_ascii_case(self.settings.adapter.trim()));
        if let Some(dev) = d.npf_device
            && (overwrite || self.settings.adapter.trim().is_empty() || !known)
        {
            self.settings.adapter = dev;
        }
        if self.settings.targets.trim().is_empty()
            && let (Some(ip), Some(prefix)) = (d.source_ip, d.prefix_len)
        {
            // По умолчанию — локальная подсеть рабочей станции (не шире /16).
            self.settings.targets = targets::network_cidr(ip, prefix.clamp(16, 32));
        }
    }

    // -----------------------------------------------------------------------
    // Запуск задач
    // -----------------------------------------------------------------------

    fn build_probe_cfg(&self) -> Result<ProbeConfig, String> {
        let s = &self.settings;
        let test_url = Url::parse(&s.test_http_url).map_err(|e| format!("Тестовый URL: {e}"))?;
        if test_url.https {
            return Err("Тестовый URL должен быть http:// (для HTTPS служит поле «TLS-узел»)".into());
        }
        let (tls_host, tls_port) =
            probe::split_host_port(&s.test_tls_host, 443).map_err(|e| format!("TLS-узел: {e}"))?;
        let policy =
            probe::parse_policy_rules(&s.policy_rules).map_err(|e| format!("Политики: {e}"))?;
        Ok(ProbeConfig {
            timeout: Duration::from_millis(s.probe_timeout_ms.clamp(200, 60_000)),
            test_url,
            tls_host,
            tls_port,
            reference: None,
            policy,
            block_marker: s.block_marker.trim().to_string(),
            proxy_auth: probe::basic_auth(s.proxy_user.trim(), &s.proxy_pass),
        })
    }

    fn new_job(&mut self, with_probe: bool) -> Result<Job, String> {
        let probe = if with_probe {
            Some(Arc::new(ProbeCtx {
                cfg: self.build_probe_cfg()?,
                sem: Arc::new(Semaphore::new(self.settings.probe_concurrency.clamp(1, 512))),
            }))
        } else {
            None
        };
        Ok(Job {
            cancel: CancellationToken::new(),
            started: Instant::now(),
            discovery_done: false,
            waiting_reference: probe.is_some(),
            probe,
            queue: Vec::new(),
            pending_probes: 0,
        })
    }

    /// Получение эталонного сертификата (вручную заданный отпечаток либо прямое подключение).
    fn reference_future(
        &self,
        cfg: &ProbeConfig,
    ) -> impl Future<Output = Result<CertInfo, String>> + Send + 'static {
        let manual = probe::normalize_fp(&self.settings.reference_fp);
        let (host, port, timeout) = (cfg.tls_host.clone(), cfg.tls_port, cfg.timeout);
        async move {
            if !manual.is_empty() {
                if manual.len() != 64 {
                    return Err("эталонный отпечаток SHA-256 должен содержать 64 hex-символа".into());
                }
                return Ok(CertInfo {
                    sha256: manual.to_ascii_uppercase(),
                    subject: "(задан вручную)".into(),
                    ..Default::default()
                });
            }
            probe::direct_reference(&host, port, timeout).await
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        self.error = None;
        if let Err(e) = self.try_start_scan(ctx) {
            self.error = Some(e);
        }
    }

    fn try_start_scan(&mut self, ctx: &egui::Context) -> Result<(), String> {
        let s = self.settings.clone();
        let target_set = targets::parse_targets(&s.targets).map_err(|e| format!("Цели: {e}"))?;
        let ports = targets::parse_ports(&s.ports).map_err(|e| format!("Порты: {e}"))?;
        let hosts = target_set.total_hosts();

        enum Plan {
            Tcp(TcpScanConfig),
            Masscan(MasscanConfig),
        }
        let plan = match s.mode {
            ScanMode::TcpConnect => {
                if hosts > TCP_SCAN_MAX_HOSTS {
                    return Err(format!(
                        "TCP-connect режим рассчитан на подсети до /16 ({TCP_SCAN_MAX_HOSTS} адресов), \
                         задано {hosts}. Сузьте диапазон или используйте masscan."
                    ));
                }
                Plan::Tcp(TcpScanConfig {
                    targets: target_set,
                    ports,
                    concurrency: s.tcp_concurrency.clamp(1, 4000),
                    timeout: Duration::from_millis(s.tcp_timeout_ms.clamp(50, 30_000)),
                })
            }
            ScanMode::Masscan => {
                let exe = util::resolve_masscan(&s.masscan_path);
                if !s.router_mac.trim().is_empty() && !netdetect::is_mac(s.router_mac.trim()) {
                    return Err("router-mac: ожидается формат 00-11-22-33-44-55".into());
                }
                for (name, v) in [("source-ip", &s.source_ip), ("router-ip", &s.router_ip)] {
                    if !v.trim().is_empty() && v.trim().parse::<Ipv4Addr>().is_err() {
                        return Err(format!("{name}: некорректный IPv4-адрес"));
                    }
                }
                Plan::Masscan(MasscanConfig {
                    exe,
                    targets: target_set,
                    ports,
                    rate: s.rate.clamp(1, 1_000_000),
                    wait_secs: s.wait_secs.min(120),
                    adapter: s.adapter.clone(),
                    source_ip: s.source_ip.clone(),
                    router_ip: s.router_ip.clone(),
                    router_mac: s.router_mac.clone(),
                    extra_args: s.extra_args.clone(),
                })
            }
        };

        let job = self.new_job(s.auto_probe)?;
        let cancel = job.cancel.clone();
        let reference = job.probe.as_ref().map(|p| self.reference_future(&p.cfg));
        let tx = self.tx(ctx);

        self.rows.clear();
        self.index.clear();
        self.selected = None;
        self.progress = 0.0;
        self.status = "Запуск…".into();
        self.job = Some(job);
        self.push_log(format!(
            "— новая задача: {} адресов, режим {} —",
            hosts,
            match s.mode {
                ScanMode::Masscan => "masscan",
                ScanMode::TcpConnect => "TCP-connect",
            }
        ));

        self.rt.spawn(async move {
            if let Some(fut) = reference {
                tx.send(AppEvent::Reference(fut.await));
            }
            let result = match plan {
                Plan::Tcp(cfg) => scan::tcp_connect_scan(cfg, tx.clone(), cancel).await,
                Plan::Masscan(cfg) => scan::masscan_scan(cfg, tx.clone(), cancel).await,
            };
            tx.send(AppEvent::DiscoveryFinished(result));
        });
        Ok(())
    }

    /// Повторная диагностика уже найденных узлов.
    fn start_reprobe(&mut self, ctx: &egui::Context, only: Option<(Ipv4Addr, u16)>) {
        self.error = None;
        let mut job = match self.new_job(true) {
            Ok(j) => j,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        job.queue = match only {
            Some(k) => vec![k],
            None => self.rows.iter().map(|r| (r.ip, r.port)).collect(),
        };
        if job.queue.is_empty() {
            return;
        }
        for k in &job.queue {
            if let Some(&i) = self.index.get(k) {
                self.rows[i].state = RowState::Found;
            }
        }
        let reference = self.reference_future(&job.probe.as_ref().unwrap().cfg);
        let tx = self.tx(ctx);
        self.progress = 0.0;
        self.status = "Повторная диагностика…".into();
        self.job = Some(job);
        self.rt.spawn(async move {
            tx.send(AppEvent::Reference(reference.await));
            tx.send(AppEvent::DiscoveryFinished(Ok("повторная диагностика".into())));
        });
    }

    fn stop(&mut self) {
        if let Some(job) = &self.job {
            job.cancel.cancel();
            self.status = "Остановка…".into();
        }
    }

    fn spawn_probe(&mut self, ctx: &egui::Context, key: (Ipv4Addr, u16)) {
        let Some(job) = &mut self.job else { return };
        let Some(pctx) = job.probe.clone() else { return };
        if job.waiting_reference {
            job.queue.push(key);
            return;
        }
        job.pending_probes += 1;
        let cancel = job.cancel.clone();
        let tx = self.tx(ctx);
        let mut cfg = pctx.cfg.clone();
        cfg.reference = self.reference.clone();
        let (ip, port) = key;
        self.rt.spawn(async move {
            let stopped = || ProbeResult {
                error: Some("остановлено".into()),
                ..Default::default()
            };
            let result = tokio::select! {
                _ = cancel.cancelled() => stopped(),
                r = async {
                    let _permit = pctx.sem.acquire().await;
                    tx.send(AppEvent::ProbeStarted(ip, port));
                    probe::probe_endpoint(ip, port, &cfg).await
                } => r,
            };
            tx.send(AppEvent::ProbeDone(ip, port, Box::new(result)));
        });
    }

    // -----------------------------------------------------------------------
    // Обработка событий
    // -----------------------------------------------------------------------

    fn handle_events(&mut self, ctx: &egui::Context) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                AppEvent::Log(m) => self.push_log(m),
                AppEvent::NetDetected(d) => self.apply_detect(*d),
                AppEvent::RouterMac(Ok(mac)) => {
                    self.push_log(format!("сеть: router-mac {mac} (arp -a)"));
                    self.settings.router_mac = mac;
                }
                AppEvent::RouterMac(Err(e)) => {
                    self.push_log(format!("сеть: router-mac — {e}"));
                    self.error = Some(format!("MAC шлюза: {e}"));
                }
                AppEvent::Open { ip, port, source } => {
                    if !self.index.contains_key(&(ip, port)) {
                        self.index.insert((ip, port), self.rows.len());
                        self.rows.push(ProxyRow::new(ip, port, source));
                        self.spawn_probe(ctx, (ip, port));
                    }
                }
                AppEvent::Progress(p, text) => {
                    if self.job.as_ref().is_some_and(|j| !j.discovery_done) {
                        self.progress = p;
                        self.status = text;
                    }
                }
                AppEvent::Reference(r) => {
                    match r {
                        Ok(info) => {
                            self.push_log(format!(
                                "эталонный сертификат: {} / издатель: {} / SHA-256 {}",
                                info.subject, info.issuer, info.sha256
                            ));
                            self.reference = Some(info);
                        }
                        Err(e) => {
                            self.push_log(format!(
                                "эталонный сертификат не получен ({e}); SSL-инспекция будет \
                                 оцениваться только по издателю сертификата"
                            ));
                            self.reference = None;
                        }
                    }
                    let queue = match &mut self.job {
                        Some(job) => {
                            job.waiting_reference = false;
                            std::mem::take(&mut job.queue)
                        }
                        None => Vec::new(),
                    };
                    for key in queue {
                        self.spawn_probe(ctx, key);
                    }
                }
                AppEvent::ProbeStarted(ip, port) => {
                    if let Some(&i) = self.index.get(&(ip, port)) {
                        self.rows[i].state = RowState::Probing;
                    }
                }
                AppEvent::ProbeDone(ip, port, result) => {
                    if let Some(&i) = self.index.get(&(ip, port)) {
                        let row = &mut self.rows[i];
                        row.state = if result.error.is_some() {
                            RowState::Error
                        } else {
                            RowState::Done
                        };
                        row.kind = result.kind.unwrap_or(ProxyKind::Unknown);
                        row.ssl = result.ssl.unwrap_or(SslInspection::Unknown);
                        row.probe = *result;
                    }
                    if let Some(job) = &mut self.job {
                        job.pending_probes = job.pending_probes.saturating_sub(1);
                    }
                }
                AppEvent::DiscoveryFinished(r) => {
                    match &r {
                        Ok(m) => self.push_log(m.clone()),
                        Err(e) => {
                            self.push_log(format!("ошибка: {e}"));
                            if self.job.as_ref().is_some_and(|j| !j.cancel.is_cancelled()) {
                                self.error = Some(e.clone());
                            }
                        }
                    }
                    if let Some(job) = &mut self.job {
                        job.discovery_done = true;
                    }
                }
            }
        }

        // Завершение задачи: обнаружение окончено и все проверки выполнены.
        let Some(job) = &self.job else { return };
        if !job.discovery_done || job.waiting_reference {
            return;
        }
        if job.pending_probes == 0 {
            let secs = job.started.elapsed().as_secs_f32();
            let proxies = self.rows.iter().filter(|r| r.kind.is_proxy()).count();
            let ssl = self
                .rows
                .iter()
                .filter(|r| r.ssl == SslInspection::Yes)
                .count();
            self.status = format!(
                "{}: узлов — {}, прокси — {proxies}, с SSL-инспекцией — {ssl} ({secs:.1} с)",
                if job.cancel.is_cancelled() { "Остановлено" } else { "Готово" },
                self.rows.len(),
            );
            self.push_log(self.status.clone());
            self.progress = 1.0;
            self.job = None;
        } else {
            let total = self.rows.len().max(1);
            let done = total.saturating_sub(job.pending_probes);
            self.progress = done as f32 / total as f32;
            self.status = format!("Диагностика: {done} из {total}");
        }
    }

    // -----------------------------------------------------------------------
    // Таблица: фильтрация и сортировка
    // -----------------------------------------------------------------------

    fn visible_rows(&self) -> Vec<usize> {
        let needle = self.filter.text.trim().to_lowercase();
        let mut idx: Vec<usize> = (0..self.rows.len())
            .filter(|&i| {
                let r = &self.rows[i];
                if self.filter.only_proxy && !r.kind.is_proxy() {
                    return false;
                }
                if self.filter.only_ssl && r.ssl != SslInspection::Yes {
                    return false;
                }
                if self.filter.only_violations {
                    let (ok, total) = r.policy_counts();
                    if ok == total {
                        return false;
                    }
                }
                if needle.is_empty() {
                    return true;
                }
                let hay = format!(
                    "{}:{} {} {} {} {} {} {}",
                    r.ip,
                    r.port,
                    r.kind.label(),
                    r.auth_label(),
                    r.server_label(),
                    r.issuer_label(),
                    r.ssl.label(),
                    r.state.label()
                )
                .to_lowercase();
                needle.split_whitespace().all(|w| hay.contains(w))
            })
            .collect();

        let (col, asc) = self.sort;
        let rows = &self.rows;
        idx.sort_by(|&a, &b| {
            let (x, y) = (&rows[a], &rows[b]);
            let ord = match col {
                SortCol::Ip => x.ip.cmp(&y.ip),
                SortCol::Port => x.port.cmp(&y.port),
                SortCol::Kind => x.kind.cmp(&y.kind),
                SortCol::Auth => x.auth_label().cmp(&y.auth_label()),
                SortCol::Server => x.server_label().cmp(&y.server_label()),
                SortCol::Connect => x.probe.connect_status.cmp(&y.probe.connect_status),
                SortCol::Ssl => x.ssl.cmp(&y.ssl),
                SortCol::Issuer => x.issuer_label().cmp(y.issuer_label()),
                SortCol::Policy => {
                    let (xo, xt) = x.policy_counts();
                    let (yo, yt) = y.policy_counts();
                    (xt - xo).cmp(&(yt - yo))
                }
                SortCol::Rtt => x.probe.rtt_ms.cmp(&y.probe.rtt_ms),
                SortCol::State => (x.state as u8).cmp(&(y.state as u8)),
            }
            .then_with(|| x.ip.cmp(&y.ip))
            .then_with(|| x.port.cmp(&y.port));
            if asc { ord } else { ord.reverse() }
        });
        idx
    }

    fn export(&mut self, visible: &[usize]) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Сохранить результаты")
            .set_file_name("proxy-inventory.csv")
            .add_filter("CSV (Excel)", &["csv"])
            .add_filter("JSON", &["json"])
            .save_file()
        else {
            return;
        };
        let rows: Vec<&ProxyRow> = visible.iter().map(|&i| &self.rows[i]).collect();
        match export::save(&path, &rows) {
            Ok(()) => self.status = format!("Сохранено: {} ({} строк)", path.display(), rows.len()),
            Err(e) => self.error = Some(e),
        }
    }

    // -----------------------------------------------------------------------
    // Отрисовка
    // -----------------------------------------------------------------------

    fn ui_top(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading("Proxy Scanner");
            ui.separator();
            ui.label("Режим обнаружения:");
            let busy = self.busy();
            ui.add_enabled_ui(!busy, |ui| {
                ui.radio_value(&mut self.settings.mode, ScanMode::Masscan, "masscan (быстрый)")
                    .on_hover_text(
                        "Внешний masscan64.exe. Требуются установленный Npcap и права администратора.",
                    );
                ui.radio_value(&mut self.settings.mode, ScanMode::TcpConnect, "TCP-connect (встроенный)")
                    .on_hover_text(
                        "Встроенный асинхронный сканер. Не требует драйверов и прав администратора; \
                         подсети до /16.",
                    );
            });
            ui.separator();
            if self.is_admin {
                ui.colored_label(GREEN, "● администратор");
            } else {
                ui.colored_label(AMBER, "● обычный пользователь");
                if cfg!(windows)
                    && ui
                        .small_button("Перезапустить от имени администратора")
                        .clicked()
                {
                    match util::relaunch_as_admin() {
                        Ok(()) => ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close),
                        Err(e) => self.error = Some(e),
                    }
                }
            }
            if self.npcap {
                ui.colored_label(GREEN, "● Npcap");
            } else {
                ui.colored_label(AMBER, "● Npcap не найден");
            }
        });
    }

    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let busy = self.busy();
        let s = &mut self.settings;

        ui.add_space(4.0);
        ui.strong("Цели");
        ui.add(
            egui::TextEdit::multiline(&mut s.targets)
                .desired_rows(2)
                .desired_width(f32::INFINITY)
                .hint_text("10.0.0.0/24, 10.0.1.10-10.0.1.50, 10.0.2.7"),
        );
        ui.label("Порты");
        ui.add(
            egui::TextEdit::singleline(&mut s.ports)
                .desired_width(f32::INFINITY)
                .hint_text("3128,8080,8000-8100"),
        );
        match (targets::parse_targets(&s.targets), targets::parse_ports(&s.ports)) {
            (Ok(t), Ok(p)) => {
                let hosts = t.total_hosts();
                let text = format!("{hosts} адр. × {} порт. = {} проверок", p.len(), hosts * p.len() as u64);
                if s.mode == ScanMode::TcpConnect && hosts > TCP_SCAN_MAX_HOSTS {
                    ui.colored_label(RED, format!("{text} — больше /16, используйте masscan"));
                } else {
                    ui.weak(text);
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                if !s.targets.trim().is_empty() {
                    ui.colored_label(RED, e);
                }
            }
        }

        ui.add_space(6.0);
        ui.separator();

        match s.mode {
            ScanMode::TcpConnect => {
                ui.strong("TCP-connect");
                egui::Grid::new("tcp_grid").num_columns(2).show(ui, |ui| {
                    ui.label("Параллельных подключений");
                    ui.add(egui::DragValue::new(&mut s.tcp_concurrency).range(1..=4000));
                    ui.end_row();
                    ui.label("Таймаут подключения, мс");
                    ui.add(egui::DragValue::new(&mut s.tcp_timeout_ms).range(50..=30_000));
                    ui.end_row();
                });
            }
            ScanMode::Masscan => {
                ui.strong("masscan");
                ui.horizontal(|ui| {
                    ui.label("Путь");
                    if ui.button("Обзор…").clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .set_title("Укажите masscan64.exe")
                            .add_filter("Программы", &["exe"])
                            .pick_file()
                    {
                        s.masscan_path = p.display().to_string();
                    }
                    ui.add(egui::TextEdit::singleline(&mut s.masscan_path).desired_width(f32::INFINITY));
                });
                let exe = util::resolve_masscan(&s.masscan_path);
                if !util::file_exists(&exe) {
                    ui.colored_label(
                        AMBER,
                        "Файл не найден. Положите masscan64.exe рядом с программой или укажите путь.",
                    );
                }
                egui::Grid::new("masscan_grid").num_columns(2).show(ui, |ui| {
                    ui.label("Скорость, пакетов/с");
                    ui.add(egui::DragValue::new(&mut s.rate).range(1..=1_000_000).speed(50));
                    ui.end_row();
                    ui.label("Ожидание ответов, с");
                    ui.add(egui::DragValue::new(&mut s.wait_secs).range(0..=120));
                    ui.end_row();
                });
            }
        }

        ui.add_space(6.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong("Сетевые параметры");
            let detect = ui
                .add_enabled(!self.detect_busy, egui::Button::new("Определить"))
                .on_hover_text(
                    "source-ip — по таблице маршрутов (UDP connect без отправки трафика);\n\
                     шлюз — Get-NetRoute, запасной вариант — ipconfig;\n\
                     адаптер — Get-NetIPAddress / Get-NetAdapter и masscan --iflist.",
                );
            if self.detect_busy {
                ui.spinner();
            }
            if detect.clicked() {
                self.first_detect = false;
                self.start_detect(&ctx, false);
            }
        });
        let s = &mut self.settings;
        let masscan_mode = s.mode == ScanMode::Masscan;
        let mut want_mac = false;
        egui::Grid::new("net_grid").num_columns(2).show(ui, |ui| {
            ui.label("source-ip");
            ui.add(egui::TextEdit::singleline(&mut s.source_ip).desired_width(150.0));
            ui.end_row();
            ui.label("router-ip (шлюз)");
            ui.add(egui::TextEdit::singleline(&mut s.router_ip).desired_width(150.0));
            ui.end_row();
            ui.label("router-mac");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut s.router_mac)
                        .desired_width(150.0)
                        .hint_text("необязательно"),
                );
                want_mac = ui
                    .small_button("из ARP")
                    .on_hover_text("Найти MAC шлюза в выводе arp -a")
                    .clicked();
            });
            ui.end_row();
        });
        if want_mac {
            self.start_router_mac(&ctx);
        }
        let s = &mut self.settings;
        ui.label("Адаптер (masscan --adapter)");
        let current = self
            .ifaces
            .iter()
            .find(|e| e.device.eq_ignore_ascii_case(s.adapter.trim()))
            .map(|e| e.label())
            .unwrap_or_else(|| {
                if s.adapter.trim().is_empty() {
                    "(не выбран)".to_string()
                } else {
                    s.adapter.clone()
                }
            });
        egui::ComboBox::from_id_salt("adapter_combo")
            .selected_text(truncate(&current, 48))
            .width(ui.available_width() - 8.0)
            .show_ui(ui, |ui| {
                for e in &self.ifaces {
                    ui.selectable_value(&mut s.adapter, e.device.clone(), e.label());
                }
                if self.ifaces.is_empty() {
                    ui.weak("Список пуст — нажмите «Определить»");
                }
            });
        ui.add(
            egui::TextEdit::singleline(&mut s.adapter)
                .desired_width(f32::INFINITY)
                .hint_text("\\Device\\NPF_{GUID}"),
        );
        if masscan_mode {
            ui.label("Дополнительные аргументы masscan");
            ui.add(
                egui::TextEdit::singleline(&mut s.extra_args)
                    .desired_width(f32::INFINITY)
                    .hint_text("--retries 2"),
            );
        } else {
            ui.weak("В режиме TCP-connect эти параметры носят справочный характер.");
        }

        ui.add_space(6.0);
        ui.separator();
        ui.checkbox(&mut s.auto_probe, "Диагностика найденных узлов")
            .on_hover_text(
                "Определение типа прокси, схемы аутентификации, поддержки CONNECT,\n\
                 признаков SSL-инспекции и соответствия политикам доступа.",
            );
        egui::CollapsingHeader::new("Параметры диагностики")
            .default_open(false)
            .show(ui, |ui| {
                ui.label("Тестовый HTTP URL");
                ui.add(egui::TextEdit::singleline(&mut s.test_http_url).desired_width(f32::INFINITY));
                ui.label("TLS-узел для проверки SSL-инспекции (host:port)");
                ui.add(egui::TextEdit::singleline(&mut s.test_tls_host).desired_width(f32::INFINITY));
                ui.label("Эталонный отпечаток SHA-256 сертификата")
                    .on_hover_text(
                        "Если пусто — эталон берётся прямым подключением к TLS-узлу.\n\
                         Сертификат, полученный через прокси, сравнивается с эталоном.",
                    );
                ui.add(
                    egui::TextEdit::singleline(&mut s.reference_fp)
                        .desired_width(f32::INFINITY)
                        .hint_text("пусто — определить прямым подключением"),
                );
                ui.label("Политики доступа (по одной в строке)").on_hover_text(
                    "+ URL — доступ должен быть разрешён\n- URL — доступ должен быть заблокирован",
                );
                ui.add(
                    egui::TextEdit::multiline(&mut s.policy_rules)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .hint_text("+ http://portal.corp.local/\n- https://blocked.example/"),
                );
                ui.label("Маркер страницы блокировки").on_hover_text(
                    "Подстрока в ответе прокси, по которой распознаётся страница блокировки \
                     (если прокси отдаёт её с кодом 200).",
                );
                ui.add(egui::TextEdit::singleline(&mut s.block_marker).desired_width(f32::INFINITY));
                egui::Grid::new("probe_grid").num_columns(2).show(ui, |ui| {
                    ui.label("Учётная запись (Basic)");
                    ui.add(egui::TextEdit::singleline(&mut s.proxy_user).desired_width(140.0));
                    ui.end_row();
                    ui.label("Пароль");
                    ui.add(
                        egui::TextEdit::singleline(&mut s.proxy_pass)
                            .password(true)
                            .desired_width(140.0),
                    );
                    ui.end_row();
                    ui.label("Параллельных проверок");
                    ui.add(egui::DragValue::new(&mut s.probe_concurrency).range(1..=512));
                    ui.end_row();
                    ui.label("Таймаут, мс");
                    ui.add(egui::DragValue::new(&mut s.probe_timeout_ms).range(200..=60_000).speed(50));
                    ui.end_row();
                });
            });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if busy {
                if ui
                    .add(egui::Button::new(RichText::new("■ Остановить").strong()).min_size([130.0, 28.0].into()))
                    .clicked()
                {
                    self.stop();
                }
                ui.spinner();
            } else {
                if ui
                    .add(egui::Button::new(RichText::new("▶ Сканировать").strong()).min_size([130.0, 28.0].into()))
                    .clicked()
                {
                    self.start_scan(&ctx);
                }
                if ui
                    .add_enabled(!self.rows.is_empty(), egui::Button::new("Перепроверить все"))
                    .on_hover_text("Повторить диагностику найденных узлов без нового сканирования")
                    .clicked()
                {
                    self.start_reprobe(&ctx, None);
                }
            }
        });
        ui.add_space(4.0);
    }

    fn ui_bottom(&mut self, ui: &mut egui::Ui) {
        ui.add_space(2.0);
        if let Some(err) = self.error.clone() {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(RED, format!("⚠ {err}"));
                if ui.small_button("✖").clicked() {
                    self.error = None;
                }
            });
        }
        ui.horizontal(|ui| {
            ui.toggle_value(&mut self.show_log, "Журнал");
            ui.add(
                egui::ProgressBar::new(self.progress)
                    .desired_width(220.0)
                    .show_percentage()
                    .animate(self.busy()),
            );
            ui.label(&self.status);
        });
        if self.show_log {
            ui.separator();
            egui::ScrollArea::vertical()
                .max_height(150.0)
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log {
                        ui.label(RichText::new(line).monospace().size(11.5));
                    }
                });
        }
        ui.add_space(2.0);
    }

    fn ui_details(&mut self, ui: &mut egui::Ui, key: (Ipv4Addr, u16)) {
        let Some(&i) = self.index.get(&key) else {
            self.selected = None;
            return;
        };
        let ctx = ui.ctx().clone();
        let mut close = false;
        let mut reprobe = false;
        let row = &self.rows[i];
        ui.horizontal(|ui| {
            ui.heading(format!("{}:{}", row.ip, row.port));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                close = ui.button("✖").clicked();
                reprobe = ui
                    .add_enabled(!self.busy(), egui::Button::new("Перепроверить"))
                    .clicked();
                if ui.button("Копировать").on_hover_text("Скопировать адрес").clicked() {
                    ctx.copy_text(format!("{}:{}", row.ip, row.port));
                }
            });
        });
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let p = &row.probe;
            egui::Grid::new("details_grid").num_columns(2).striped(true).show(ui, |ui| {
                let mut kv = |k: &str, v: String| {
                    if !v.is_empty() {
                        ui.label(k);
                        ui.add(egui::Label::new(v).wrap());
                        ui.end_row();
                    }
                };
                kv("Тип", row.kind.label().to_string());
                kv("Обнаружен", row.source.clone());
                kv("Отклик", p.rtt_ms.map(|v| format!("{v} мс")).unwrap_or_default());
                kv("HTTP-статус", p.http_status.map(|v| v.to_string()).unwrap_or_default());
                kv("Сервер", p.server.clone());
                kv("Via", p.via.clone());
                kv("Аутентификация", row.auth_label());
                kv("CONNECT", row.connect_label());
                kv("SSL-инспекция", row.ssl.label().to_string());
                kv("Ошибка", p.error.clone().unwrap_or_default());
            });

            if let Some(c) = &p.cert {
                ui.add_space(6.0);
                ui.strong("Сертификат, полученный через прокси");
                egui::Grid::new("cert_grid").num_columns(2).striped(true).show(ui, |ui| {
                    let mut kv = |k: &str, v: String| {
                        ui.label(k);
                        ui.add(egui::Label::new(v).wrap());
                        ui.end_row();
                    };
                    kv("Субъект", c.subject.clone());
                    kv("Издатель", c.issuer.clone());
                    kv("Действует с", c.not_before.clone());
                    kv("Действует до", c.not_after.clone());
                    kv("SHA-256", c.sha256.clone());
                    kv("Длина цепочки", c.chain_len.to_string());
                    if c.self_signed {
                        kv("Примечание", "самоподписанный".into());
                    }
                });
                if let Some(r) = &self.reference {
                    ui.weak(format!(
                        "Эталон: {} / {} / {}",
                        r.subject,
                        if r.issuer.is_empty() { "—" } else { &r.issuer },
                        r.sha256
                    ));
                }
            }

            if !p.policy.is_empty() {
                ui.add_space(6.0);
                ui.strong("Политики доступа");
                for pr in &p.policy {
                    let (mark, color) = if pr.compliant { ("✔", GREEN) } else { ("✖", RED) };
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(color, mark);
                        ui.label(format!(
                            "{} — ожидалось: {}, факт: {} ({})",
                            pr.url,
                            if pr.expect_allowed { "разрешено" } else { "заблокировано" },
                            pr.verdict.label(),
                            pr.detail
                        ));
                    });
                }
            }

            if !p.notes.is_empty() {
                ui.add_space(6.0);
                ui.strong("Примечания");
                for n in &p.notes {
                    ui.label(format!("• {n}"));
                }
            }

            if !p.raw_headers.is_empty() {
                ui.add_space(6.0);
                ui.strong("Заголовки ответа");
                let mut text = p.raw_headers.as_str();
                ui.add(
                    egui::TextEdit::multiline(&mut text)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            }
        });
        if close {
            self.selected = None;
        }
        if reprobe {
            self.start_reprobe(&ctx, Some(key));
        }
    }

    fn ui_table(&mut self, ui: &mut egui::Ui) {
        let visible = self.visible_rows();

        ui.horizontal_wrapped(|ui| {
            ui.label("Фильтр:");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter.text)
                    .desired_width(200.0)
                    .hint_text("IP, порт, тип, издатель…"),
            );
            if ui.small_button("✖").on_hover_text("Сбросить фильтр").clicked() {
                self.filter = Filter::default();
            }
            ui.checkbox(&mut self.filter.only_proxy, "только прокси");
            ui.checkbox(&mut self.filter.only_ssl, "SSL-инспекция");
            ui.checkbox(&mut self.filter.only_violations, "нарушения политик");
            ui.separator();
            ui.label(format!("Показано {} из {}", visible.len(), self.rows.len()));
            if ui
                .add_enabled(!visible.is_empty(), egui::Button::new("Экспорт…"))
                .on_hover_text("Сохранить показанные строки в CSV или JSON")
                .clicked()
            {
                self.export(&visible);
            }
        });
        ui.separator();

        if self.rows.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.weak("Нет данных. Укажите цели и порты слева и нажмите «Сканировать».");
            });
            return;
        }

        let mut clicked: Option<(Ipv4Addr, u16)> = None;
        let mut sort = self.sort;
        let selected = self.selected;
        let rows = &self.rows;

        egui::ScrollArea::horizontal().show(ui, |ui| {
            let mut table = TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .min_scrolled_height(0.0);
            for (_, _, width) in COLUMNS {
                table = table.column(Column::initial(*width).at_least(36.0).clip(true));
            }
            table
                .header(24.0, |mut header| {
                    for (col, title, _) in COLUMNS {
                        header.col(|ui| {
                            let arrow = if sort.0 == *col {
                                if sort.1 { " ⏶" } else { " ⏷" }
                            } else {
                                ""
                            };
                            let resp = ui.add(
                                egui::Button::new(RichText::new(format!("{title}{arrow}")).strong())
                                    .frame(false),
                            );
                            if resp.clicked() {
                                sort = if sort.0 == *col { (*col, !sort.1) } else { (*col, true) };
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(22.0, visible.len(), |mut row| {
                        let r = &rows[visible[row.index()]];
                        row.set_selected(selected == Some((r.ip, r.port)));
                        for (col, _, _) in COLUMNS {
                            row.col(|ui| cell(ui, r, *col));
                        }
                        if row.response().clicked() {
                            clicked = Some((r.ip, r.port));
                        }
                    });
                });
        });

        self.sort = sort;
        if let Some(k) = clicked {
            self.selected = if self.selected == Some(k) { None } else { Some(k) };
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn cell(ui: &mut egui::Ui, r: &ProxyRow, col: SortCol) {
    match col {
        SortCol::Ip => {
            ui.label(RichText::new(r.ip.to_string()).monospace());
        }
        SortCol::Port => {
            ui.label(RichText::new(r.port.to_string()).monospace());
        }
        SortCol::Kind => {
            if r.kind.is_proxy() {
                ui.label(RichText::new(r.kind.label()).strong());
            } else {
                ui.weak(r.kind.label());
            }
        }
        SortCol::Auth => {
            ui.label(r.auth_label());
        }
        SortCol::Server => {
            ui.label(r.server_label());
        }
        SortCol::Connect => {
            ui.label(r.connect_label());
        }
        SortCol::Ssl => match r.ssl {
            SslInspection::Yes => {
                ui.colored_label(RED, RichText::new(r.ssl.label()).strong());
            }
            SslInspection::No => {
                ui.colored_label(GREEN, r.ssl.label());
            }
            SslInspection::NoReference => {
                ui.colored_label(AMBER, r.ssl.label());
            }
            SslInspection::Unknown => {
                ui.weak(r.ssl.label());
            }
        },
        SortCol::Issuer => {
            ui.label(r.issuer_label());
        }
        SortCol::Policy => {
            let (ok, total) = r.policy_counts();
            if total > 0 {
                ui.colored_label(if ok == total { GREEN } else { RED }, r.policy_label());
            }
        }
        SortCol::Rtt => {
            if let Some(v) = r.probe.rtt_ms {
                ui.label(v.to_string());
            }
        }
        SortCol::State => match r.state {
            RowState::Error => {
                ui.colored_label(RED, r.state.label())
                    .on_hover_text(r.probe.error.clone().unwrap_or_default());
            }
            RowState::Probing => {
                ui.colored_label(AMBER, r.state.label());
            }
            _ => {
                ui.weak(r.state.label());
            }
        },
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_events(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("top")
            .show(ui, |ui| {
                ui.add_space(4.0);
                self.ui_top(ui);
                ui.add_space(4.0);
            });
        egui::Panel::bottom("bottom").show(ui, |ui| self.ui_bottom(ui));
        egui::Panel::left("settings")
            .resizable(true)
            .default_size(350.0)
            .min_size(280.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.ui_settings(ui));
            });
        if let Some(key) = self.selected {
            egui::Panel::right("details")
                .resizable(true)
                .default_size(400.0)
                .min_size(260.0)
                .show(ui, |ui| self.ui_details(ui, key));
        }
        egui::CentralPanel::default().show(ui, |ui| self.ui_table(ui));
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, SETTINGS_KEY, &self.settings);
    }
}
