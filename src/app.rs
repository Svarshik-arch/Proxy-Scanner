//! Графический интерфейс (egui/eframe) и управление фоновыми задачами.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::columns::{self, Col};
use crate::egress::{self, EgressItem};
use crate::export;
use crate::filters::{self, Choice, Filters, Preset};
use crate::graph::{GraphSettings, GraphView};
use crate::model::{
    AppEvent, CertInfo, Checkpoint, ProbeResult, ProxyKind, ProxyRow, RowState, ScanMode,
    Settings, SslInspection,
};
use crate::netdetect::{self, IfaceEntry};
use crate::probe::{self, ProbeConfig};
use crate::scan::{self, MasscanConfig, TcpScanConfig, Tx};
use crate::session::{self, ArchiveEntry, Coverage, ScanState, Session};
use crate::targets::{self, TCP_SCAN_MAX_HOSTS};
use crate::toolui::{self, Nav, PaletteItem, Tool, Workbench};
use crate::util;

const SETTINGS_KEY: &str = "settings";
const VIEW_KEY: &str = "view";
const TOOLS_KEY: &str = "tools";
const MAX_LOG_LINES: usize = 2000;
/// Как часто сохранять сессию во время сканирования.
const AUTOSAVE_EVERY: Duration = Duration::from_secs(15);

const GREEN: Color32 = Color32::from_rgb(60, 170, 90);
const RED: Color32 = Color32::from_rgb(220, 70, 70);
const AMBER: Color32 = Color32::from_rgb(215, 160, 40);

/// Файл с выбранной графикой (читается до создания окна).
/// Через что идёт вывод изображения: бэкенд и видеокарта (для журнала и проверки в CI).
fn graphics_info(cc: &eframe::CreationContext<'_>) -> String {
    if let Some(rs) = &cc.wgpu_render_state {
        let i = rs.adapter.get_info();
        return format!("wgpu {:?}, {} ({:?})", i.backend, i.name, i.device_type);
    }
    if let Some(gl) = &cc.gl {
        use eframe::glow::HasContext;
        // SAFETY: контекст OpenGL текущий в потоке создания окна.
        let (renderer, version) = unsafe {
            (gl.get_parameter_string(eframe::glow::RENDERER), gl.get_parameter_string(eframe::glow::VERSION))
        };
        return format!("OpenGL {version}, {renderer}");
    }
    "неизвестно".into()
}

fn renderer_file() -> std::path::PathBuf {
    session::default_path().with_file_name("proxy-scanner-graphics.txt")
}

/// Графика, выбранная в меню «Вид»: `glow`, `wgpu` или нет выбора.
pub fn saved_renderer() -> Option<String> {
    let v = std::fs::read_to_string(renderer_file()).ok()?.trim().to_ascii_lowercase();
    (v == "glow" || v == "wgpu").then_some(v)
}

/// Ширина окна, ниже которой интерфейс переходит на вкладки.
const COMPACT_WIDTH: f32 = 900.0;
/// Ширина окна, ниже которой сокращаются подписи в шапке.
const NARROW_WIDTH: f32 = 640.0;
/// Минимальная ширина таблицы, при которой подробности показываются справа.
const DETAILS_SIDE_MIN_TABLE: f32 = 620.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
enum ThemeChoice {
    #[default]
    System,
    Dark,
    Light,
}

/// Раздел центральной области.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
enum Section {
    #[default]
    Proxies,
    Egress,
    Pac,
    Tool(Tool),
}

/// Группа разделов (верхний ряд вкладок).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    Proxy,
    Network,
    Services,
    Audit,
    Monitor,
}

impl Group {
    const ALL: [Group; 5] = [Group::Proxy, Group::Network, Group::Services, Group::Audit, Group::Monitor];

    fn title(self) -> &'static str {
        match self {
            Group::Proxy => "Прокси",
            Group::Network => "Сеть",
            Group::Services => "Службы",
            Group::Audit => "Аудит",
            Group::Monitor => "Мониторинг",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Group::Proxy => "Поиск и проверка прокси, проверка адресов через прокси, обход прокси, PAC/WPAD",
            Group::Network => "Эта машина, трассировка, узлы, доступность портов, трафик, карта сети",
            Group::Services => "DNS, HTTP, сервисы и версии, TLS, домен AD, общие ресурсы",
            Group::Audit => "Небезопасные настройки, сертификаты, сравнение с прошлой проверкой",
            Group::Monitor => Tool::Monitor.hint(),
        }
    }

    fn sections(self) -> &'static [Section] {
        match self {
            Group::Proxy => &[Section::Proxies, Section::Tool(Tool::UrlCheck), Section::Egress, Section::Pac],
            Group::Network => &[
                Section::Tool(Tool::Host),
                Section::Tool(Tool::Mtr),
                Section::Tool(Tool::Discovery),
                Section::Tool(Tool::Matrix),
                Section::Tool(Tool::Capture),
                Section::Tool(Tool::Map),
            ],
            Group::Services => &[
                Section::Tool(Tool::Dns),
                Section::Tool(Tool::Http),
                Section::Tool(Tool::Services),
                Section::Tool(Tool::Tls),
                Section::Tool(Tool::Ad),
                Section::Tool(Tool::Shares),
            ],
            Group::Audit => &[Section::Tool(Tool::Audit), Section::Tool(Tool::Certs), Section::Tool(Tool::Compare)],
            Group::Monitor => &[Section::Tool(Tool::Monitor)],
        }
    }

    fn of(s: Section) -> Group {
        Group::ALL.into_iter().find(|g| g.sections().contains(&s)).unwrap_or(Group::Proxy)
    }
}

/// Ключ вкладки для предисловий.
fn section_key(s: Section) -> String {
    match s {
        Section::Proxies => "proxies".into(),
        Section::Egress => "egress".into(),
        Section::Pac => "pac".into(),
        Section::Tool(t) => t.preset_id().into(),
    }
}

fn section_title(s: Section) -> (&'static str, &'static str) {
    match s {
        Section::Proxies => ("Поиск прокси", "Обнаружение и диагностика прокси-серверов"),
        Section::Egress => ("Обход прокси", "Можно ли с этой рабочей станции выйти наружу напрямую, мимо прокси"),
        Section::Pac => ("PAC/WPAD", "Настройки прокси в системе, поиск WPAD, проверка PAC-файла"),
        Section::Tool(t) => (t.title(), t.hint()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
enum ResultsView {
    #[default]
    Table,
    Graph,
}

/// Оценка «Дополнить»: (новых проверок, всего по текущим параметрам).
type AppendEstimate = Result<(u64, u64), String>;

/// Как запускается обнаружение портов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartKind {
    /// С чистого листа (прежние результаты уходят в архив).
    Fresh,
    /// Продолжение остановленного сканирования с теми же параметрами.
    Resume,
    /// Дополнение сессии: новые параметры, найденное сохраняется,
    /// уже проверенные адреса × порты пропускаются.
    Append,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactTab {
    Settings,
    Results,
}

/// Настройки внешнего вида (сохраняются между запусками).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct ViewPrefs {
    /// Подбирать столбцы по ширине окна.
    auto_columns: bool,
    /// Столбцы, выбранные вручную.
    columns: Vec<Col>,
    zoom: f32,
    theme: ThemeChoice,
    settings_open: bool,
    filters_open: bool,
    results_view: ResultsView,
    graph: GraphSettings,
    section: Section,
    /// Последний открытый подраздел каждой группы.
    last_sections: Vec<Section>,
    /// Текущий проект (пусто — основной).
    project: String,
    /// Вкладки, у которых скрыто предисловие.
    hidden_intros: Vec<String>,
}

impl Default for ViewPrefs {
    fn default() -> Self {
        Self {
            auto_columns: true,
            columns: columns::default_visible(),
            zoom: 1.0,
            theme: ThemeChoice::System,
            settings_open: true,
            filters_open: false,
            results_view: ResultsView::Table,
            graph: GraphSettings::default(),
            section: Section::Proxies,
            last_sections: Vec::new(),
            project: String::new(),
            hidden_intros: Vec::new(),
        }
    }
}

/// Действие из контекстного меню строки таблицы.
enum RowAction {
    OnlyPort(u16),
    OnlySubnet(String),
    OnlyKind(ProxyKind),
    Search(String),
    Copy(String),
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
    /// Задача без обнаружения портов — только повторная диагностика.
    probe_only: Option<()>,
}

pub struct App {
    rt: Runtime,
    settings: Settings,
    rows: Vec<ProxyRow>,
    index: HashMap<(Ipv4Addr, u16), usize>,
    tx: Sender<AppEvent>,
    rx: Receiver<AppEvent>,
    log: Vec<String>,
    close_after_first_frame: bool,
    show_log: bool,
    ifaces: Vec<IfaceEntry>,
    detect_busy: bool,
    first_detect: bool,
    job: Option<Job>,
    progress: f32,
    status: String,
    error: Option<String>,
    reference: Option<CertInfo>,
    sort: (Col, bool),
    filters: Filters,
    filter_errors: Vec<String>,
    view: ViewPrefs,
    graph: GraphView,
    compact_tab: CompactTab,
    last_compact: Option<bool>,
    selected: Option<(Ipv4Addr, u16)>,
    is_admin: bool,
    npcap: bool,
    /// Состояние текущего или последнего сканирования (для продолжения).
    scan_state: Option<ScanState>,
    session_path: std::path::PathBuf,
    /// Сведения о восстановленной сессии для баннера.
    restored: Option<RestoredInfo>,
    last_autosave: Instant,
    /// Изменились ли данные с последнего сохранения сессии.
    dirty: bool,
    /// Архив предыдущих сессий (новые первыми).
    archive: Vec<ArchiveEntry>,
    /// Ждём подтверждения перед новым сканированием.
    confirm_new_scan: bool,
    /// Уже проверенные адреса × порты этой сессии.
    coverage: Vec<Coverage>,
    /// Текущий этап сканирования (k, n) для строки состояния.
    stage: Option<(usize, usize)>,
    /// Кэш оценки «Дополнить»: ключ параметров → (новых проверок, всего запрошено).
    append_preview: Option<(String, AppendEstimate)>,
    /// Проверка обхода прокси: результаты и отмена идущей проверки.
    egress_items: Vec<EgressItem>,
    egress_cancel: Option<CancellationToken>,
    /// Слушатель: отмена, занятые порты, ошибки.
    listener: Option<(CancellationToken, Vec<u16>, Vec<String>)>,
    /// PAC/WPAD.
    pac: PacState,
    /// Инструменты диагностики (MTR, DNS, HTTP, сервисы, TLS…).
    bench: Workbench,
    /// Подсеть рабочей станции (из автоопределения).
    local_cidr: Option<String>,
    last_context: Option<Instant>,
}

#[derive(Default)]
struct PacState {
    system: Option<crate::pac::SystemInfo>,
    system_busy: bool,
    wpad: Vec<(String, Result<usize, String>)>,
    /// Найденные WPAD-файлы: URL → текст.
    wpad_texts: Vec<(String, String)>,
    wpad_busy: bool,
    /// Загруженный PAC: источник и текст.
    loaded: Option<(String, String)>,
    load_error: Option<String>,
    load_busy: bool,
    results: Vec<(String, Result<String, String>)>,
    eval_error: Option<String>,
    eval_busy: bool,
}

/// Описание сессии, загруженной при запуске или из файла.
struct RestoredInfo {
    computer: String,
    saved_at: u64,
    other_computer: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: Runtime) -> Self {
        let settings: Settings = cc
            .storage
            .and_then(|s| eframe::get_value(s, SETTINGS_KEY))
            .unwrap_or_default();
        let view: ViewPrefs = cc
            .storage
            .and_then(|s| eframe::get_value(s, VIEW_KEY))
            .unwrap_or_default();
        apply_view(&cc.egui_ctx, &view);
        let tool_prefs: toolui::Prefs = cc
            .storage
            .and_then(|s| eframe::get_value(s, TOOLS_KEY))
            .unwrap_or_default();
        let session_path = session::project_path(&view.project);
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
            sort: (Col::Ip, true),
            filters: Filters::default(),
            filter_errors: Vec::new(),
            view,
            graph: GraphView::default(),
            compact_tab: CompactTab::Settings,
            last_compact: None,
            selected: None,
            is_admin: util::is_admin(),
            npcap: util::npcap_installed(),
            scan_state: None,
            session_path,
            restored: None,
            last_autosave: Instant::now(),
            dirty: false,
            archive: Vec::new(),
            confirm_new_scan: false,
            coverage: Vec::new(),
            stage: None,
            append_preview: None,
            egress_items: Vec::new(),
            egress_cancel: None,
            listener: None,
            pac: PacState::default(),
            bench: Workbench::new(tool_prefs),
            local_cidr: None,
            last_context: None,
            close_after_first_frame: false,
        };
        app.archive = session::list_archive(&app.session_path);
        let graphics = graphics_info(cc);
        app.push_log(format!("графика: {graphics}"));
        // Проверка в CI: записать, через что идёт вывод, и закрыть окно после первого кадра.
        if let Ok(path) = std::env::var("PROXY_SCANNER_GRAPHICS_REPORT") {
            let _ = std::fs::write(path, &graphics);
            app.close_after_first_frame = true;
        }
        // Незавершённая сессия рядом с программой (в том числе перенесённая с другого ПК).
        if app.session_path.is_file() {
            match session::load(&app.session_path) {
                Ok(s) => app.restore_session(s),
                Err(e) => app.push_log(format!("сессия: {e}")),
            }
        }
        // Открыть вкладку при запуске: PROXY_SCANNER_OPEN=mtr | proxies | egress | pac | graph.
        if let Ok(v) = std::env::var("PROXY_SCANNER_OPEN") {
            match v.as_str() {
                "proxies" => app.view.section = Section::Proxies,
                "graph" => {
                    app.view.section = Section::Proxies;
                    app.view.results_view = ResultsView::Graph;
                }
                "egress" => app.view.section = Section::Egress,
                "pac" => app.view.section = Section::Pac,
                key => {
                    if let Some(t) = Tool::ALL.into_iter().find(|t| t.preset_id() == key) {
                        app.view.section = Section::Tool(t);
                    }
                }
            }
        }
        // Автоопределение сетевых параметров при старте.
        app.start_detect(&cc.egui_ctx, false);
        app
    }

    // -----------------------------------------------------------------------
    // Сессия: сохранение и восстановление
    // -----------------------------------------------------------------------

    fn restore_session(&mut self, s: Session) {
        let other = !s.is_from_this_computer();
        let mut settings = s.settings;
        if other {
            // Сетевые параметры относятся к конкретному ПК — определим их заново.
            settings.source_ip.clear();
            settings.router_ip.clear();
            settings.router_mac.clear();
            settings.adapter.clear();
            settings.masscan_path = self.settings.masscan_path.clone();
        }
        settings.proxy_pass = std::mem::take(&mut self.settings.proxy_pass);
        self.settings = settings;
        self.rows = s.rows;
        self.index = self
            .rows
            .iter()
            .enumerate()
            .map(|(i, r)| ((r.ip, r.port), i))
            .collect();
        self.scan_state = s.scan;
        if let Some(st) = &mut self.scan_state {
            st.ensure_groups();
        }
        self.coverage = s.coverage;
        self.egress_items = s.egress;
        self.bench.restore_results(s.tools);
        if let Some(p) = s.tool_prefs {
            self.bench.set_prefs(p);
        }
        // Сессии старых версий: завершённое сканирование целиком считается проверенным.
        if self.coverage.is_empty()
            && let Some(st) = &self.scan_state
        {
            if st.finished {
                self.coverage.extend(st.groups.iter().map(|g| g.coverage()));
            } else {
                self.coverage.extend(st.partial_coverage());
            }
        }
        self.append_preview = None;
        self.selected = None;
        self.restored = Some(RestoredInfo {
            computer: s.computer.clone(),
            saved_at: s.saved_at,
            other_computer: other,
        });
        if !self.rows.is_empty() || self.scan_state.is_some() {
            self.compact_tab = CompactTab::Results;
        }
        let progress = self
            .scan_state
            .as_ref()
            .map(|st| format!(", обнаружение выполнено на {:.1}%", st.fraction() * 100.0))
            .unwrap_or_default();
        self.push_log(format!(
            "сессия: загружена ({}, ПК {}): узлов — {}{progress}",
            session::format_time(s.saved_at),
            s.computer,
            self.rows.len()
        ));
    }

    fn session_snapshot(&self) -> Session {
        let mut rows = self.rows.clone();
        // Незавершённые проверки при продолжении выполнятся заново.
        for r in &mut rows {
            if r.state == RowState::Probing {
                r.state = RowState::Found;
            }
        }
        let mut s = Session::new(&self.settings, self.scan_state.clone(), rows);
        s.coverage = self.coverage.clone();
        s.egress = self.egress_items.clone();
        s.tools = self.bench.results();
        s.tool_prefs = Some(self.bench.prefs());
        s
    }

    /// Переключение проекта: текущая сессия сохраняется, загружается сессия проекта.
    fn switch_project(&mut self, name: &str) {
        if self.busy() || self.bench.any_busy() {
            self.status = "Дождитесь окончания работы инструментов, затем переключите проект".into();
            return;
        }
        let name = session::sanitize(name);
        if name == self.view.project {
            return;
        }
        self.autosave();
        self.view.project = name.clone();
        self.session_path = session::project_path(&name);
        if let Some(dir) = self.session_path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Чистое состояние, затем загрузка сессии проекта, если она есть.
        self.rows.clear();
        self.index.clear();
        self.selected = None;
        self.scan_state = None;
        self.coverage.clear();
        self.egress_items.clear();
        self.bench.clear_results();
        self.append_preview = None;
        self.restored = None;
        self.progress = 0.0;
        self.archive = session::list_archive(&self.session_path);
        if self.session_path.is_file() {
            match session::load(&self.session_path) {
                Ok(s) => self.restore_session(s),
                Err(e) => self.push_log(format!("проект: {e}")),
            }
        }
        self.dirty = true;
        self.status = format!("Проект: {}", if name.is_empty() { "основной" } else { &name });
        self.push_log(self.status.clone());
    }

    fn menu_project(&mut self, ui: &mut egui::Ui) {
        let title = if self.view.project.is_empty() { "Проект ▾".to_string() } else { format!("Проект: {} ▾", self.view.project) };
        ui.menu_button(title, |ui| {
            ui.set_min_width(260.0);
            ui.weak("У каждого проекта (объект, филиал) свои цели, настройки инструментов, результаты и архив.");
            ui.separator();
            let mut pick: Option<String> = None;
            if ui.radio(self.view.project.is_empty(), "Основной").clicked() {
                pick = Some(String::new());
            }
            for p in session::list_projects() {
                if ui.radio(self.view.project == p, &p).clicked() {
                    pick = Some(p);
                }
            }
            ui.separator();
            ui.horizontal(|ui| {
                let id = egui::Id::unique("new_project_name");
                let mut name: String = ui.data_mut(|d| d.get_temp(id).unwrap_or_default());
                ui.add(egui::TextEdit::singleline(&mut name).hint_text("новый проект").desired_width(150.0));
                let ok = !session::sanitize(&name).is_empty();
                if ui.add_enabled(ok, egui::Button::new("Создать")).clicked() {
                    pick = Some(name.clone());
                    name.clear();
                }
                ui.data_mut(|d| d.insert_temp(id, name));
            });
            if ui.button("Открыть папку проектов").clicked() {
                let dir = session::projects_dir();
                let _ = std::fs::create_dir_all(&dir);
                let d = dir.display().to_string();
                if cfg!(windows) {
                    let _ = util::run_cmd("explorer.exe", &[&d]);
                } else {
                    let _ = std::process::Command::new("xdg-open").arg(&d).spawn();
                }
            }
            if let Some(p) = pick {
                self.switch_project(&p);
                ui.close();
            }
        })
        .response
        .on_hover_text("Объекты и филиалы: у каждого свои цели и результаты");
    }

    fn save_session_to(&mut self, path: &std::path::Path) -> Result<(), String> {
        session::save(path, &self.session_snapshot())
    }

    fn autosave(&mut self) {
        if self.rows.is_empty() && self.scan_state.is_none() {
            return;
        }
        let path = self.session_path.clone();
        match self.save_session_to(&path) {
            Ok(()) => self.dirty = false,
            Err(e) => self.push_log(format!("сессия: не удалось сохранить — {e}")),
        }
        self.last_autosave = Instant::now();
    }

    fn save_session_as(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Сохранить сессию")
            .set_file_name(session::FILE_NAME)
            .add_filter("Сессия Proxy Scanner", &["json"])
            .save_file()
        else {
            return;
        };
        match self.save_session_to(&path) {
            Ok(()) => self.status = format!("Сессия сохранена: {}", path.display()),
            Err(e) => self.error = Some(e),
        }
    }

    fn open_session(&mut self) {
        if self.busy() {
            self.error = Some("Сначала остановите текущее сканирование".into());
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Открыть сессию")
            .add_filter("Сессия Proxy Scanner", &["json"])
            .pick_file()
        else {
            return;
        };
        self.open_session_path(&path);
    }

    /// Открывает сессию из файла; текущие результаты предварительно уходят в архив.
    fn open_session_path(&mut self, path: &std::path::Path) {
        if self.busy() {
            self.error = Some("Сначала остановите текущее сканирование".into());
            return;
        }
        match session::load(path) {
            Ok(s) => {
                self.archive_current();
                self.restore_session(s);
                self.dirty = true;
                self.autosave();
                self.status = format!("Сессия открыта: {}", path.display());
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Копирует текущие результаты в архив, если есть что сохранять.
    fn archive_current(&mut self) {
        if self.rows.is_empty()
            && self.egress_items.is_empty()
            && self.scan_state.as_ref().is_none_or(|s| !s.has_progress())
        {
            return;
        }
        match session::archive(&self.session_snapshot(), &self.session_path) {
            Ok(path) => self.push_log(format!("сессия: предыдущие результаты сохранены в архив {}", path.display())),
            Err(e) => {
                self.push_log(format!("сессия: не удалось сохранить архивную копию — {e}"));
                self.error = Some(format!("Не удалось сохранить архивную копию сессии: {e}"));
            }
        }
        self.archive = session::list_archive(&self.session_path);
    }

    fn open_archive_folder(&mut self) {
        let dir = session::archive_dir(&self.session_path);
        let _ = std::fs::create_dir_all(&dir);
        let program = if cfg!(windows) { "explorer" } else { "xdg-open" };
        if let Err(e) = std::process::Command::new(program).arg(&dir).spawn() {
            self.error = Some(format!("Не удалось открыть папку {}: {e}", dir.display()));
        }
    }

    fn new_session(&mut self) {
        if self.busy() {
            return;
        }
        self.archive_current();
        self.rows.clear();
        self.index.clear();
        self.selected = None;
        self.scan_state = None;
        self.coverage.clear();
        self.egress_items.clear();
        self.bench.clear_results();
        self.append_preview = None;
        self.restored = None;
        self.progress = 0.0;
        self.status = "Новая сессия".into();
        let _ = std::fs::remove_file(&self.session_path);
    }

    /// Новое сканирование: при наличии результатов сначала спрашиваем подтверждение.
    fn request_new_scan(&mut self, ctx: &egui::Context) {
        if self.rows.is_empty() && self.scan_state.as_ref().is_none_or(|s| !s.has_progress()) {
            self.start_scan(ctx, StartKind::Fresh);
        } else {
            self.confirm_new_scan = true;
        }
    }

    fn ui_confirm_new_scan(&mut self, ctx: &egui::Context) {
        if !self.confirm_new_scan {
            return;
        }
        let pct = self
            .scan_state
            .as_ref()
            .filter(|s| !s.finished)
            .map(|s| format!(", обнаружение выполнено на {:.0}%", s.fraction() * 100.0))
            .unwrap_or_default();
        let mut start = false;
        let mut cancel = false;
        let resp = egui::Modal::new(egui::Id::unique("confirm_new_scan")).show(ctx, |ui| {
            ui.set_max_width(440.0);
            ui.heading("Начать новое сканирование?");
            ui.add_space(6.0);
            ui.label(format!(
                "Текущие результаты (узлов — {}{pct}) будут убраны из таблицы.",
                self.rows.len()
            ));
            ui.label(
                "Они не пропадут: копия сохранится в архив, открыть её можно в меню «Сессия → Архив сессий».",
            );
            if self.can_resume() {
                ui.colored_label(AMBER, "Чтобы продолжить прерванное сканирование, нажмите «Продолжить», а не «Сканировать».");
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                start = ui.button(RichText::new("Начать новое").strong()).clicked();
                cancel = ui.button("Отмена").clicked();
            });
        });
        if resp.should_close() {
            cancel = true;
        }
        if start {
            self.confirm_new_scan = false;
            self.start_scan(ctx, StartKind::Fresh);
        } else if cancel {
            self.confirm_new_scan = false;
        }
    }

    /// Можно ли продолжить последнее сканирование с текущими настройками.
    fn can_resume(&self) -> bool {
        !self.busy()
            && self
                .scan_state
                .as_ref()
                .is_some_and(|st| st.has_progress() && st.resumable_with(&self.settings))
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
        if let (Some(ip), Some(prefix)) = (d.source_ip, d.prefix_len) {
            self.local_cidr = Some(targets::network_cidr(ip, prefix.clamp(16, 32)));
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
        probe::probe_config(&self.settings)
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
            probe_only: None,
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

    fn start_scan(&mut self, ctx: &egui::Context, kind: StartKind) {
        self.error = None;
        if let Err(e) = self.try_start_scan(ctx, kind) {
            self.error = Some(e);
        }
    }

    /// Проверенное в сессии плюс уже сделанная часть незавершённого сканирования.
    fn effective_coverage(&self) -> Vec<Coverage> {
        let mut cov = self.coverage.clone();
        if let Some(st) = &self.scan_state
            && !st.finished
        {
            for c in st.partial_coverage() {
                if !cov.contains(&c) {
                    cov.push(c);
                }
            }
        }
        cov
    }

    /// Оценка для «Дополнить»: (новых проверок, всего по текущим параметрам).
    fn append_estimate(&mut self) -> AppendEstimate {
        let key = format!(
            "{}|{}|{}|{:?}",
            self.settings.targets,
            self.settings.ports,
            self.coverage.len(),
            self.scan_state.as_ref().map(|s| (s.group, s.tcp_hosts_done, s.finished))
        );
        if let Some((k, v)) = &self.append_preview
            && *k == key
        {
            return v.clone();
        }
        let v = (|| {
            let t = targets::parse_targets(&self.settings.targets)?;
            let p = targets::parse_ports(&self.settings.ports)?;
            let groups = session::plan(&t, &p, &self.effective_coverage());
            let new: u64 = groups.iter().map(|g| g.checks()).sum();
            Ok((new, t.normalized().total_hosts() * p.len() as u64))
        })();
        self.append_preview = Some((key, v.clone()));
        v
    }

    fn try_start_scan(&mut self, ctx: &egui::Context, kind: StartKind) -> Result<(), String> {
        let s = self.settings.clone();
        let target_set = targets::parse_targets(&s.targets).map_err(|e| format!("Цели: {e}"))?;
        let ports = targets::parse_ports(&s.ports).map_err(|e| format!("Порты: {e}"))?;
        let new_seed = || {
            // Новое зерно — новый псевдослучайный порядок обхода masscan.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1)
                | 1
        };

        let state = match kind {
            StartKind::Resume => match &self.scan_state {
                Some(st) if st.resumable_with(&s) => st.clone(),
                _ => {
                    return Err(
                        "Продолжить нельзя: цели, порты или режим изменились после остановки. \
                         Нажмите «Дополнить» — уже проверенное повторно сканироваться не будет."
                            .into(),
                    )
                }
            },
            StartKind::Append => {
                let groups = session::plan(&target_set, &ports, &self.effective_coverage());
                if groups.is_empty() {
                    return Err("Все адреса и порты из текущих параметров уже проверены — \
                                добавьте новые порты или подсети."
                        .into());
                }
                ScanState::new(&s, groups, new_seed())
            }
            StartKind::Fresh => ScanState::new(&s, session::plan(&target_set, &ports, &[]), new_seed()),
        };

        // Проверка параметров каждого этапа.
        if s.mode == ScanMode::TcpConnect
            && let Some(g) = state.groups.iter().find(|g| g.hosts > TCP_SCAN_MAX_HOSTS)
        {
            return Err(format!(
                "TCP-connect режим рассчитан на подсети до /16 ({TCP_SCAN_MAX_HOSTS} адресов), \
                 в этапе {} адресов. Сузьте диапазон или используйте masscan.",
                g.hosts
            ));
        }
        let masscan_template = if s.mode == ScanMode::Masscan {
            if !s.router_mac.trim().is_empty() && !netdetect::is_mac(s.router_mac.trim()) {
                return Err("router-mac: ожидается формат 00-11-22-33-44-55".into());
            }
            for (name, v) in [("source-ip", &s.source_ip), ("router-ip", &s.router_ip)] {
                if !v.trim().is_empty() && v.trim().parse::<Ipv4Addr>().is_err() {
                    return Err(format!("{name}: некорректный IPv4-адрес"));
                }
            }
            Some(MasscanConfig {
                exe: util::resolve_masscan(&s.masscan_path),
                targets: Default::default(),
                ports: Vec::new(),
                rate: s.rate.clamp(1, 1_000_000),
                wait_secs: s.wait_secs.min(120),
                adapter: s.adapter.clone(),
                source_ip: s.source_ip.clone(),
                router_ip: s.router_ip.clone(),
                router_mac: s.router_mac.clone(),
                extra_args: s.extra_args.clone(),
                seed: state.masscan_seed,
                resume_index: 0,
            })
        } else {
            None
        };
        let tcp_concurrency = s.tcp_concurrency.clamp(1, 4000);
        let tcp_timeout = Duration::from_millis(s.tcp_timeout_ms.clamp(50, 30_000));
        let tcp_retries = s.tcp_retries.min(5);

        let job = self.new_job(s.auto_probe)?;
        let cancel = job.cancel.clone();
        let reference = job.probe.as_ref().map(|p| self.reference_future(&p.cfg));
        let tx = self.tx(ctx);

        let unfinished: Vec<(Ipv4Addr, u16)> = if kind == StartKind::Fresh {
            // Прежние результаты не теряются: копия уходит в архив сессий.
            self.archive_current();
            self.rows.clear();
            self.index.clear();
            self.selected = None;
            self.coverage.clear();
            Vec::new()
        } else {
            if kind == StartKind::Append {
                // Сделанная часть прерванного сканирования считается проверенной.
                for c in self.effective_coverage() {
                    if !self.coverage.contains(&c) {
                        self.coverage.push(c);
                    }
                }
            }
            self.rows
                .iter()
                .filter(|r| matches!(r.state, RowState::Found | RowState::Probing))
                .map(|r| (r.ip, r.port))
                .collect()
        };

        let checks = state.total_checks();
        self.compact_tab = CompactTab::Results;
        self.progress = state.fraction();
        self.stage = None;
        self.append_preview = None;
        self.status = match kind {
            StartKind::Fresh => "Запуск…",
            StartKind::Resume => "Продолжение…",
            StartKind::Append => "Дополнение…",
        }
        .into();
        self.push_log(format!(
            "— {}: этапов {}, проверок {checks}, режим {} —",
            match kind {
                StartKind::Fresh => "новая задача".to_string(),
                StartKind::Resume => format!("продолжение с {:.1}%", state.fraction() * 100.0),
                StartKind::Append => format!(
                    "дополнение сессии (найденное сохраняется, узлов уже {})",
                    self.rows.len()
                ),
            },
            state.groups.len(),
            match s.mode {
                ScanMode::Masscan => "masscan",
                ScanMode::TcpConnect => "TCP-connect",
            }
        ));
        for (i, g) in state.groups.iter().enumerate().skip(state.group) {
            self.push_log(format!("  этап {}: адреса {} × порты {}", i + 1, g.targets, g.ports));
        }

        let groups = state.groups.clone();
        let start = state.group;
        let (skip_hosts, resume_index) = (state.tcp_hosts_done, state.masscan_index);
        self.scan_state = Some(state);
        self.restored = None;
        self.dirty = true;
        self.job = Some(job);
        // Узлы, проверка которых не успела завершиться, проверяем снова.
        for key in unfinished {
            if let Some(&i) = self.index.get(&key) {
                self.rows[i].state = RowState::Found;
            }
            self.spawn_probe(ctx, key);
        }

        self.rt.spawn(async move {
            if let Some(fut) = reference {
                tx.send(AppEvent::Reference(fut.await));
            }
            let n = groups.len();
            let mut result: Result<String, String> = Ok("обнаружение завершено".into());
            for (k, g) in groups.iter().enumerate().skip(start) {
                if cancel.is_cancelled() {
                    result = Err("остановлено".into());
                    break;
                }
                let (t, p) = match g.parse() {
                    Ok(v) => v,
                    Err(e) => {
                        result = Err(format!("этап {}: {e}", k + 1));
                        break;
                    }
                };
                tx.send(AppEvent::GroupStarted(k, n));
                let first = k == start;
                let r = match &masscan_template {
                    Some(tpl) => {
                        let cfg = MasscanConfig {
                            targets: t,
                            ports: p,
                            resume_index: if first { resume_index } else { 0 },
                            ..tpl.clone()
                        };
                        scan::masscan_scan(cfg, tx.clone(), cancel.clone()).await
                    }
                    None => {
                        let cfg = TcpScanConfig {
                            targets: t,
                            ports: p,
                            concurrency: tcp_concurrency,
                            timeout: tcp_timeout,
                            skip_hosts: if first { skip_hosts } else { 0 },
                            retries: tcp_retries,
                        };
                        scan::tcp_connect_scan(cfg, tx.clone(), cancel.clone()).await
                    }
                };
                match r {
                    Ok(m) => {
                        tx.log(if n > 1 { format!("этап {}/{n}: {m}", k + 1) } else { m });
                        tx.send(AppEvent::GroupDone(k));
                    }
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }
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
        job.probe_only = Some(());
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
                        self.dirty = true;
                        self.spawn_probe(ctx, (ip, port));
                    }
                }
                AppEvent::Checkpoint(c) => {
                    if let Some(st) = &mut self.scan_state {
                        match c {
                            Checkpoint::TcpHostsDone(n) => {
                                st.tcp_hosts_done = st.tcp_hosts_done.max(n)
                            }
                            Checkpoint::MasscanIndex(i) => {
                                st.masscan_index = st.masscan_index.max(i)
                            }
                        }
                        self.dirty = true;
                    }
                }
                AppEvent::Egress(item) => {
                    self.egress_items.push(*item);
                    self.dirty = true;
                }
                AppEvent::EgressDone => {
                    let cancelled = self.egress_cancel.take().is_some_and(|c| c.is_cancelled());
                    let leaks = self.egress_items.iter().filter(|i| i.status.is_leak()).count();
                    self.push_log(format!(
                        "обход прокси: проверок {}, прямых выходов {leaks}{}",
                        self.egress_items.len(),
                        if cancelled { " (остановлено)" } else { "" }
                    ));
                    self.autosave();
                }
                AppEvent::PacSystem(info) => {
                    self.pac.system_busy = false;
                    self.pac.system = Some(*info);
                }
                AppEvent::PacWpad(url, r) => {
                    let summary = r.as_ref().map(|t| t.len()).map_err(|e| e.clone());
                    if let Ok(text) = r {
                        self.pac.wpad_texts.push((url.clone(), text));
                    }
                    self.pac.wpad.push((url, summary));
                }
                AppEvent::PacWpadDone => self.pac.wpad_busy = false,
                AppEvent::PacLoaded(src, r) => {
                    self.pac.load_busy = false;
                    match r {
                        Ok(text) => {
                            self.push_log(format!("PAC: загружен {src} ({} байт)", text.len()));
                            self.pac.loaded = Some((src, text));
                            self.pac.load_error = None;
                            self.pac.results.clear();
                        }
                        Err(e) => self.pac.load_error = Some(e),
                    }
                }
                AppEvent::PacEvaluated(r) => {
                    self.pac.eval_busy = false;
                    match r {
                        Ok(v) => {
                            self.pac.results = v;
                            self.pac.eval_error = None;
                        }
                        Err(e) => self.pac.eval_error = Some(e),
                    }
                }
                AppEvent::PacTargets(found, errors) => {
                    for e in errors {
                        self.push_log(format!("PAC: {e}"));
                    }
                    if found.is_empty() {
                        self.error = Some("В ответах PAC нет прокси, которые удалось разрешить в адреса".into());
                    } else {
                        let mut t = self.settings.targets.trim().to_string();
                        let mut p = self.settings.ports.trim().to_string();
                        let (mut added_t, mut added_p) = (0, 0);
                        for (ip, port) in &found {
                            let ip_s = ip.to_string();
                            if !t.split([',', ' ', '\n', ';']).any(|x| x.trim() == ip_s) {
                                if !t.is_empty() {
                                    t.push_str(", ");
                                }
                                t.push_str(&ip_s);
                                added_t += 1;
                            }
                            let ps = port.to_string();
                            if !p.split([',', ' ']).any(|x| x.trim() == ps) {
                                if !p.is_empty() {
                                    p.push(',');
                                }
                                p.push_str(&ps);
                                added_p += 1;
                            }
                        }
                        self.settings.targets = t;
                        self.settings.ports = p;
                        self.status = if added_t + added_p == 0 {
                            "Все прокси из PAC уже есть в целях и портах сканирования.".to_string()
                        } else {
                            format!(
                                "Из PAC добавлено адресов: {added_t}, портов: {added_p}. Нажмите «Сканировать» или «Дополнить»."
                            )
                        };
                    }
                }
                AppEvent::ListenerStarted(ok, errors) => {
                    if let Some(l) = &mut self.listener {
                        l.1 = ok;
                        l.2 = errors;
                    }
                }
                AppEvent::GroupStarted(k, n) => {
                    self.stage = (n > 1).then_some((k, n));
                }
                AppEvent::GroupDone(k) => {
                    if let Some(st) = &mut self.scan_state
                        && let Some(c) = st.group_done(k)
                        && !self.coverage.contains(&c)
                    {
                        self.coverage.push(c);
                    }
                    self.dirty = true;
                }
                AppEvent::Progress(p, text) => {
                    if self.job.as_ref().is_some_and(|j| !j.discovery_done) {
                        self.progress = self
                            .scan_state
                            .as_ref()
                            .map(|st| st.fraction_with(p))
                            .unwrap_or(p);
                        self.status = match self.stage {
                            Some((k, n)) => format!("Этап {}/{n} · {text}", k + 1),
                            None => text,
                        };
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
                    self.dirty = true;
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
                        let completed = r.is_ok() && !job.cancel.is_cancelled() && job.probe_only.is_none();
                        if completed
                            && let Some(st) = &mut self.scan_state
                            && st.group >= st.groups.len()
                        {
                            st.finished = true;
                        }
                    }
                    self.dirty = true;
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
            if job.cancel.is_cancelled()
                && let Some(st) = &self.scan_state
                && !st.finished
            {
                self.status.push_str(&format!(
                    " · можно продолжить с {:.1}%",
                    st.fraction() * 100.0
                ));
            } else if job.probe_only.is_none() {
                self.status
                    .push_str(" · чтобы досканировать, измените порты или цели и нажмите «Дополнить»");
            }
            self.stage = None;
            self.push_log(self.status.clone());
            self.progress = 1.0;
            self.job = None;
            self.autosave();
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

    fn visible_rows(&mut self) -> Vec<usize> {
        let (compiled, errors) = self.filters.compile();
        self.filter_errors = errors;
        let mut idx: Vec<usize> = (0..self.rows.len())
            .filter(|&i| compiled.matches(&self.rows[i]))
            .collect();

        let (col, asc) = self.sort;
        let rows = &self.rows;
        idx.sort_by(|&a, &b| {
            let (x, y) = (&rows[a], &rows[b]);
            let ord = match col {
                Col::Ip => x.ip.cmp(&y.ip),
                Col::Port => x.port.cmp(&y.port),
                Col::Kind => x.kind.cmp(&y.kind),
                Col::Auth => x.auth_label().cmp(&y.auth_label()),
                Col::Server => x.server_label().cmp(&y.server_label()),
                Col::Connect => x.probe.connect_status.cmp(&y.probe.connect_status),
                Col::Ssl => x.ssl.cmp(&y.ssl),
                Col::Issuer => x.issuer_label().cmp(y.issuer_label()),
                Col::Policy => {
                    let (xo, xt) = x.policy_counts();
                    let (yo, yt) = y.policy_counts();
                    (xt - xo).cmp(&(yt - yo))
                }
                Col::Rtt => x.probe.rtt_ms.cmp(&y.probe.rtt_ms),
                Col::State => (x.state as u8).cmp(&(y.state as u8)),
                Col::Source => x.source.cmp(&y.source),
                Col::Http => x.probe.http_status.cmp(&y.probe.http_status),
                Col::Inspect => {
                    let (xb, xn) = x.inspect_counts();
                    let (yb, yn) = y.inspect_counts();
                    (xb, xn).cmp(&(yb, yn))
                }
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

    fn ui_top(&mut self, ui: &mut egui::Ui, compact: bool, narrow: bool) {
        ui.horizontal_wrapped(|ui| {
            if !compact {
                ui.toggle_value(&mut self.view.settings_open, "☰")
                    .on_hover_text("Показать или скрыть панель параметров");
            }
            if narrow {
                ui.strong("Proxy Scanner");
            } else {
                ui.heading("Proxy Scanner");
            }
            ui.separator();
            if compact {
                ui.selectable_value(&mut self.compact_tab, CompactTab::Settings, "Параметры");
                let count = match self.view.section {
                    Section::Tool(t) => self.bench.badge(t),
                    _ => Some(self.rows.len().to_string()),
                };
                ui.selectable_value(
                    &mut self.compact_tab,
                    CompactTab::Results,
                    match count {
                        Some(n) => format!("Результаты ({n})"),
                        None => "Результаты".to_string(),
                    },
                );
                ui.separator();
            }
            // Режим сканера и признаки прав нужны только в разделах прокси.
            if !matches!(self.view.section, Section::Tool(_)) {
                self.ui_scanner_badges(ui, narrow);
            }

            self.menu_project(ui);
            self.menu_session(ui);
            if ui.button("Отчёт").on_hover_text("Сводный отчёт HTML по всем разделам — для заявки или акта").clicked() {
                self.save_report();
            }
            self.menu_profile(ui);
            self.menu_view(ui);
            if !narrow {
                ui.weak("Ctrl+K — переход");
            }
        });
    }

    fn ui_scanner_badges(&mut self, ui: &mut egui::Ui, narrow: bool) {
        if !narrow {
            ui.label("Режим:");
        }
        let busy = self.busy();
        ui.add_enabled_ui(!busy, |ui| {
            let (m, t) = if narrow {
                ("masscan", "TCP")
            } else {
                ("masscan (быстрый)", "TCP-connect (встроенный)")
            };
            ui.radio_value(&mut self.settings.mode, ScanMode::Masscan, m).on_hover_text(format!(
                "Внешний {}. Требуются {} и права «{}».",
                util::MASSCAN_DEFAULT,
                util::PCAP_NAME,
                util::ADMIN_NAME
            ));
            ui.radio_value(&mut self.settings.mode, ScanMode::TcpConnect, t).on_hover_text(
                "Встроенный асинхронный сканер. Не требует драйверов и прав администратора; \
                 подсети до /16.",
            );
        });
        ui.separator();
        let badge = |ui: &mut egui::Ui, ok: bool, full: &str, hint: &str| {
            let color = if ok { GREEN } else { AMBER };
            let text = if narrow { "●".to_string() } else { format!("● {full}") };
            ui.add(egui::Label::new(RichText::new(text).color(color)).extend())
                .on_hover_text(hint);
        };
        if self.is_admin {
            badge(ui, true, util::ADMIN_NAME, "Программа запущена с повышенными правами");
        } else {
            badge(
                ui,
                false,
                "обычный пользователь",
                if cfg!(windows) {
                    "Для режима masscan нужны права администратора"
                } else {
                    "Для режима masscan запустите программу через sudo (или дайте masscan CAP_NET_RAW)"
                },
            );
            if cfg!(windows)
                && ui
                    .small_button(if narrow { "⛨" } else { "Перезапустить от имени администратора" })
                    .on_hover_text("Перезапустить программу с правами администратора")
                    .clicked()
            {
                self.autosave();
                match util::relaunch_as_admin() {
                    Ok(()) => ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close),
                    Err(e) => self.error = Some(e),
                }
            }
        }
        let pcap_text = if self.npcap {
            util::PCAP_NAME.to_string()
        } else {
            format!("{} не найден", util::PCAP_NAME)
        };
        let pcap_hint = if self.npcap {
            format!("{} установлен", util::PCAP_NAME)
        } else {
            format!("{} не найден: режим masscan недоступен", util::PCAP_NAME)
        };
        badge(ui, self.npcap, &pcap_text, &pcap_hint);
        ui.separator();
    }

    /// Сводный отчёт HTML по текущей сессии.
    fn save_report(&mut self) {
        let name = format!("proxy-scanner-report-{}.html", session::computer_name());
        let Some(path) = rfd::FileDialog::new().add_filter("HTML", &["html"]).set_file_name(name).save_file() else {
            return;
        };
        let html = crate::report::html(&self.session_snapshot(), &format!("Сетевая диагностика — {}", session::computer_name()));
        self.status = match std::fs::write(&path, html) {
            Ok(()) => {
                let p = path.display().to_string();
                if cfg!(windows) {
                    let _ = util::run_cmd("explorer.exe", &[&p]);
                } else {
                    let _ = std::process::Command::new("xdg-open").arg(&p).spawn();
                }
                format!("Отчёт сохранён: {p}")
            }
            Err(e) => format!("Отчёт не сохранён: {e}"),
        };
        self.push_log(self.status.clone());
    }

    fn menu_session(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("Сессия", |ui| {
            if ui
                .button("Сохранить сейчас")
                .on_hover_text("Записать сессию в файл рядом с программой")
                .clicked()
            {
                self.autosave();
                self.status = format!("Сессия сохранена: {}", self.session_path.display());
                ui.close();
            }
            if ui.button("Сохранить как…").clicked() {
                ui.close();
                self.save_session_as();
            }
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Открыть…"))
                .on_hover_text("Загрузить сессию, в том числе сохранённую на другом ПК")
                .clicked()
            {
                ui.close();
                self.open_session();
            }
            ui.separator();
            let busy = self.busy();
            let mut open: Option<std::path::PathBuf> = None;
            ui.menu_button(format!("Архив сессий ({})", self.archive.len()), |ui| {
                ui.weak("Копии сохраняются перед новым сканированием и открытием другой сессии.");
                ui.separator();
                if self.archive.is_empty() {
                    ui.weak("Архив пуст");
                }
                egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                    for e in &self.archive {
                        if ui
                            .add_enabled(!busy, egui::Button::new(e.label()))
                            .on_hover_text(e.path.display().to_string())
                            .clicked()
                        {
                            open = Some(e.path.clone());
                        }
                    }
                });
                ui.separator();
                if ui.button("Открыть папку архива").clicked() {
                    self.open_archive_folder();
                    ui.close();
                }
            });
            if let Some(p) = open {
                ui.close();
                self.open_session_path(&p);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Новая сессия"))
                .on_hover_text("Очистить результаты (копия сохранится в архив)")
                .clicked()
            {
                self.new_session();
                ui.close();
            }
            ui.separator();
            ui.weak("Файл сессии:");
            ui.add(egui::Label::new(RichText::new(self.session_path.display().to_string()).small()).wrap());
            ui.weak("Сохраняется при закрытии программы, остановке и каждые 15 с во время сканирования.");
        });
    }

    fn menu_view(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("Вид", |ui| {
            ui.label("Масштаб интерфейса");
            let mut zoom = ui.ctx().zoom_factor();
            ui.horizontal(|ui| {
                for z in [0.8f32, 1.0, 1.25, 1.5, 2.0] {
                    if ui
                        .selectable_label((zoom - z).abs() < 0.01, format!("{:.0}%", z * 100.0))
                        .clicked()
                    {
                        zoom = z;
                    }
                }
            });
            if ui
                .add(egui::Slider::new(&mut zoom, 0.6..=2.5).show_value(false))
                .on_hover_text("Также Ctrl + «+» / Ctrl + «−» / Ctrl + 0")
                .changed()
                || (zoom - ui.ctx().zoom_factor()).abs() > 1e-3
            {
                self.view.zoom = zoom;
                ui.ctx().set_zoom_factor(zoom);
            }
            ui.separator();
            ui.label("Тема");
            let before = self.view.theme;
            ui.radio_value(&mut self.view.theme, ThemeChoice::System, "как в системе");
            ui.radio_value(&mut self.view.theme, ThemeChoice::Dark, "тёмная");
            ui.radio_value(&mut self.view.theme, ThemeChoice::Light, "светлая");
            if before != self.view.theme {
                apply_view(ui.ctx(), &self.view);
            }
            ui.separator();
            ui.menu_button("Графика", |ui| {
                let current = saved_renderer();
                let mut pick = |ui: &mut egui::Ui, value: Option<&str>, label: &str, hint: &str| {
                    if ui.radio(current.as_deref() == value, label).on_hover_text(hint).clicked() {
                        let res = match value {
                            Some(v) => std::fs::write(renderer_file(), v),
                            None => std::fs::remove_file(renderer_file()).or(Ok(())),
                        };
                        self.status = match res {
                            Ok(()) => "Графика будет изменена после перезапуска программы".into(),
                            Err(e) => format!("Не удалось сохранить выбор графики: {e}"),
                        };
                        ui.close();
                    }
                };
                if cfg!(windows) {
                    pick(ui, None, "Автоматически (DirectX 12)", "DirectX 12, при ошибке — OpenGL");
                    pick(ui, Some("glow"), "OpenGL", "Если экран мигает или гаснет — попробуйте этот вариант");
                    pick(ui, Some("vulkan"), "Vulkan", "Только для проверки: на NVIDIA по DisplayPort возможно мигание");
                } else {
                    pick(ui, None, "Автоматически", "Vulkan, при ошибке — OpenGL");
                    pick(ui, Some("glow"), "OpenGL", "");
                }
                ui.weak("Применяется после перезапуска");
            });
            ui.separator();
            if ui.button("Сбросить вид").clicked() {
                self.view = ViewPrefs::default();
                apply_view(ui.ctx(), &self.view);
                ui.close();
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
                    ui.label("Повторов при таймауте").on_hover_text(
                        "Сколько раз повторять подключение, если ответа нет.\n\
                         0 — быстрее; 1 — надёжнее в сетях с потерями (пустые адреса проверяются дольше).",
                    );
                    ui.add(egui::DragValue::new(&mut s.tcp_retries).range(0..=5));
                    ui.end_row();
                });
            }
            ScanMode::Masscan => {
                ui.strong("masscan");
                ui.horizontal(|ui| {
                    ui.label("Путь");
                    let pick = || {
                        let d = rfd::FileDialog::new().set_title(format!("Укажите {}", util::MASSCAN_DEFAULT));
                        if cfg!(windows) { d.add_filter("Программы", &["exe"]) } else { d }.pick_file()
                    };
                    if ui.button("Обзор…").clicked()
                        && let Some(p) = pick()
                    {
                        s.masscan_path = p.display().to_string();
                    }
                    ui.add(egui::TextEdit::singleline(&mut s.masscan_path).desired_width(f32::INFINITY));
                });
                let exe = util::resolve_masscan(&s.masscan_path);
                if !util::file_exists(&exe) {
                    ui.colored_label(
                        AMBER,
                        format!(
                            "Файл не найден. Положите {} рядом с программой или укажите путь.",
                            util::MASSCAN_DEFAULT
                        ),
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
                .hint_text(if cfg!(windows) { "\\Device\\NPF_{GUID}" } else { "eth0" }),
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
                ui.checkbox(&mut s.inspect_quality, "Проверять качество SSL-инспекции").on_hover_text(
                    "Через прокси с инспекцией открываются сайты с плохими сертификатами.\n\
                     Если прокси переподписывает их своим CA, пользователь не увидит ошибку.",
                );
                if s.inspect_quality {
                    ui.label("Узлы с плохими сертификатами (host[:port], по одному в строке)")
                        .on_hover_text(
                            "По умолчанию — badssl.com. В закрытом контуре поднимите внутренние узлы\n\
                             с просроченным, самоподписанным и «чужим» сертификатом и укажите их здесь.",
                        );
                    ui.add(
                        egui::TextEdit::multiline(&mut s.badcert_hosts)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY),
                    );
                }
                ui.label("Маркер страницы блокировки").on_hover_text(
                    "Подстрока в ответе прокси, по которой распознаётся страница блокировки \
                     (если прокси отдаёт её с кодом 200).",
                );
                ui.add(egui::TextEdit::singleline(&mut s.block_marker).desired_width(f32::INFINITY));
                ui.add_space(4.0);
                ui.strong("Аутентификация на прокси");
                egui::ComboBox::from_id_salt("auth_mode")
                    .selected_text(s.auth_mode.label())
                    .show_ui(ui, |ui| {
                        for &m in crate::auth::AuthMode::ALL {
                            ui.selectable_value(&mut s.auth_mode, m, m.label());
                        }
                    });
                if cfg!(windows) {
                    ui.checkbox(&mut s.auth_current_user, "Под текущим пользователем Windows (без пароля)")
                        .on_hover_text(
                            "Kerberos/NTLM от имени вошедшего пользователя — как браузер.\n\
                             Если указать логин и пароль ниже, будут использоваться они.",
                        );
                } else {
                    ui.weak("В Linux доступны NTLM и Basic с логином и паролем; Kerberos — только в Windows.");
                }
                egui::Grid::new("probe_grid").num_columns(2).show(ui, |ui| {
                    ui.label("Пользователь").on_hover_text("ivan, CORP\\ivan или ivan@corp.local");
                    ui.add(
                        egui::TextEdit::singleline(&mut s.proxy_user)
                            .desired_width(160.0)
                            .hint_text("CORP\\ivan"),
                    );
                    ui.end_row();
                    ui.label("Домен");
                    ui.add(
                        egui::TextEdit::singleline(&mut s.proxy_domain)
                            .desired_width(160.0)
                            .hint_text("необязательно"),
                    );
                    ui.end_row();
                    ui.label("Пароль").on_hover_text("На диск не сохраняется");
                    ui.add(
                        egui::TextEdit::singleline(&mut s.proxy_pass)
                            .password(true)
                            .desired_width(160.0),
                    );
                    ui.end_row();
                    ui.label("Параллельных проверок");
                    ui.add(egui::DragValue::new(&mut s.probe_concurrency).range(1..=512));
                    ui.end_row();
                    ui.label("Таймаут, мс");
                    ui.add(egui::DragValue::new(&mut s.probe_timeout_ms).range(200..=60_000).speed(50));
                    ui.end_row();
                    ui.label("Повторов при сбое").on_hover_text(
                        "Загруженный прокси часто отвечает не с первого раза: при таймауте или обрыве\n\
                         подключение, CONNECT, SOCKS и проверки политик повторяются с паузой.",
                    );
                    ui.add(egui::DragValue::new(&mut s.probe_retries).range(0..=10));
                    ui.end_row();
                });
            });

        ui.add_space(8.0);
        // Есть ли в сессии что дополнять.
        let has_session = !self.rows.is_empty()
            || !self.coverage.is_empty()
            || self.scan_state.as_ref().is_some_and(|st| st.has_progress());
        let estimate = if has_session && !busy { Some(self.append_estimate()) } else { None };
        let big = |text: String| egui::Button::new(RichText::new(text).strong()).min_size([130.0, 28.0].into());
        ui.horizontal_wrapped(|ui| {
            if busy {
                if ui.add(big("■ Остановить".into())).clicked() {
                    self.stop();
                }
                ui.spinner();
                return;
            }
            if self.can_resume() {
                let pct = self.scan_state.as_ref().map(|s| s.fraction() * 100.0).unwrap_or(0.0);
                if ui
                    .add(big(format!("⏵ Продолжить ({pct:.0}%)")))
                    .on_hover_text("Продолжить обнаружение с места остановки с теми же параметрами")
                    .clicked()
                {
                    self.start_scan(&ctx, StartKind::Resume);
                }
            }
            if has_session {
                let can_append = matches!(estimate, Some(Ok((n, _))) if n > 0);
                let resp = ui.add_enabled(can_append, if self.can_resume() {
                    egui::Button::new("➕ Дополнить")
                } else {
                    big("➕ Дополнить".into())
                });
                let resp = resp.on_hover_text(
                    "Сканировать с текущими параметрами, сохранив всё найденное в этой сессии.\n\
                     Уже проверенные адреса × порты пропускаются — добавьте порты или подсети,\n\
                     можно сменить режим, скорость и другие параметры.",
                );
                if resp.clicked() {
                    self.start_scan(&ctx, StartKind::Append);
                }
                if ui
                    .button("▶ Заново")
                    .on_hover_text("Начать с чистого листа (текущие результаты уйдут в архив сессий)")
                    .clicked()
                {
                    self.request_new_scan(&ctx);
                }
            } else if ui.add(big("▶ Сканировать".into())).clicked() {
                self.request_new_scan(&ctx);
            }
            if ui
                .add_enabled(!self.rows.is_empty(), egui::Button::new("Перепроверить все"))
                .on_hover_text("Повторить диагностику найденных узлов без нового сканирования")
                .clicked()
            {
                self.start_reprobe(&ctx, None);
            }
        });
        if let Some(est) = estimate {
            match est {
                Ok((0, _)) => {
                    ui.weak("«Дополнить»: всё по текущим параметрам уже проверено — добавьте порты или подсети.");
                }
                Ok((n, total)) if n < total => {
                    ui.weak(format!(
                        "«Дополнить»: {n} новых проверок из {total} — {} уже проверено, найденное сохранится.",
                        total - n
                    ));
                }
                Ok((n, _)) => {
                    ui.weak(format!("«Дополнить»: {n} проверок, найденное сохранится."));
                }
                Err(_) => {}
            }
        }
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
            let w = (ui.available_width() * 0.25).clamp(80.0, 220.0);
            ui.add(
                egui::ProgressBar::new(self.progress)
                    .desired_width(w)
                    .show_percentage()
                    .animate(self.busy()),
            );
            ui.add(egui::Label::new(&self.status).truncate())
                .on_hover_text(&self.status);
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
        ui.horizontal_wrapped(|ui| {
            ui.heading(format!("{}:{}", row.ip, row.port));
            if ui.button("Копировать").on_hover_text("Скопировать адрес").clicked() {
                ctx.copy_text(format!("{}:{}", row.ip, row.port));
            }
            reprobe = ui
                .add_enabled(!self.busy(), egui::Button::new("Перепроверить"))
                .clicked();
            close = ui.button("✖").on_hover_text("Закрыть").clicked();
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
                if !p.auth.is_empty() {
                    kv("Схемы прокси", p.auth.join(", "));
                }
                kv("Вход", p.auth_used.clone().unwrap_or_default());
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

            if !p.inspection_checks.is_empty() {
                ui.add_space(6.0);
                ui.strong("Качество SSL-инспекции").on_hover_text(
                    "Через прокси открываются сайты с плохими сертификатами. Если инспекция \
                     переподписывает их своим CA, пользователь не увидит ошибку — это уязвимость.",
                );
                for c in &p.inspection_checks {
                    let (mark, color) = match c.verdict {
                        crate::model::InspectVerdict::Masked => ("✖", RED),
                        crate::model::InspectVerdict::Error => ("?", AMBER),
                        _ => ("✔", GREEN),
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(color, mark);
                        ui.label(format!("{} — {}: {}", c.host, c.verdict.label(), c.detail));
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

    fn ui_central(&mut self, ui: &mut egui::Ui) {
        let current = Group::of(self.view.section);
        let intro_key = section_key(self.view.section);
        let intro_hidden = self.view.hidden_intros.contains(&intro_key);
        let mut show_intro = false;
        // Разделы.
        ui.horizontal_wrapped(|ui| {
            for g in Group::ALL {
                let busy = g.sections().iter().any(|s| match s {
                    Section::Tool(t) => self.bench.busy(*t),
                    Section::Proxies => self.busy(),
                    _ => false,
                });
                let mut text = RichText::new(format!("{}{}", g.title(), if busy { " ⏳" } else { "" })).strong();
                let alert = match g {
                    Group::Proxy => self.egress_items.iter().any(|i| i.status.is_leak()),
                    Group::Monitor => self.bench.badge(Tool::Monitor).is_some_and(|b| b.starts_with('⚠')),
                    _ => false,
                };
                if alert {
                    text = text.color(RED);
                }
                if ui.selectable_label(current == g, text).on_hover_text(g.hint()).clicked() && current != g {
                    self.view.section = self
                        .view
                        .last_sections
                        .iter()
                        .copied()
                        .find(|s| Group::of(*s) == g)
                        .unwrap_or(g.sections()[0]);
                }
            }
            if current.sections().len() <= 1 && intro_hidden && ui.small_button("?").on_hover_text("Показать описание вкладки").clicked() {
                show_intro = true;
            }
        });
        // Подразделы, если их несколько.
        let subs = current.sections();
        if subs.len() > 1 {
            ui.horizontal_wrapped(|ui| {
                for s in subs {
                    let (title, hint) = section_title(*s);
                    let mut text = title.to_string();
                    let mut color = None;
                    match s {
                        Section::Tool(t) => {
                            if let Some(b) = self.bench.badge(*t) {
                                text = format!("{text} ({b})");
                            }
                            if self.bench.busy(*t) {
                                text.push_str(" ⏳");
                            }
                        }
                        Section::Egress => {
                            let leaks = self.egress_items.iter().filter(|i| i.status.is_leak()).count();
                            if leaks > 0 {
                                text = format!("{text} ({leaks})");
                                color = Some(RED);
                            }
                        }
                        Section::Proxies if !self.rows.is_empty() => text = format!("{text} ({})", self.rows.len()),
                        _ => {}
                    }
                    let mut rt = RichText::new(text);
                    if let Some(c) = color {
                        rt = rt.color(c);
                    }
                    ui.selectable_value(&mut self.view.section, *s, rt).on_hover_text(hint);
                }
                if intro_hidden && ui.small_button("?").on_hover_text("Показать описание вкладки").clicked() {
                    show_intro = true;
                }
            });
        }
        if show_intro {
            self.view.hidden_intros.retain(|k| *k != intro_key);
        }
        // Предисловие: что можно делать на этой вкладке.
        if section_key(self.view.section) == intro_key
            && !self.view.hidden_intros.contains(&intro_key)
            && let Some((summary, points)) = crate::intro::intro(&intro_key)
        {
            let mut hide = false;
            egui::Frame::group(ui.style()).inner_margin(egui::Margin::symmetric(10, 6)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.add(egui::Label::new(RichText::new(summary).strong()).wrap());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        if ui.small_button("✖").on_hover_text("Скрыть описание (вернуть — кнопка «?»)").clicked() {
                            hide = true;
                        }
                    });
                });
                for p in points {
                    ui.add(egui::Label::new(RichText::new(format!("• {p}")).weak()).wrap());
                }
            });
            if hide {
                self.view.hidden_intros.push(intro_key.clone());
            }
        }
        // Запоминаем подраздел группы.
        let sec = self.view.section;
        self.view.last_sections.retain(|s| Group::of(*s) != Group::of(sec));
        self.view.last_sections.push(sec);
        ui.separator();
        match self.view.section {
            Section::Proxies => self.ui_results(ui),
            Section::Egress => self.ui_egress(ui),
            Section::Pac => self.ui_pac(ui),
            Section::Tool(t) => {
                let handle = self.rt.handle().clone();
                let nav = self.bench.results_ui(t, ui, &handle);
                self.navigate(nav);
            }
        }
    }

    /// Переход между инструментами (передача узла).
    fn navigate(&mut self, nav: Option<Nav>) {
        match nav {
            Some(Nav::Send(t, host)) => {
                self.bench.receive(t, &host);
                self.view.section = Section::Tool(t);
                self.view.settings_open = true;
                self.compact_tab = CompactTab::Settings;
            }
            Some(Nav::Proxy(host)) => {
                if !self.busy() {
                    self.settings.targets = host;
                }
                self.view.section = Section::Proxies;
                self.compact_tab = CompactTab::Settings;
            }
            None => {}
        }
    }

    /// Левая панель: параметры прокси-сканера или выбранного инструмента.
    fn ui_left(&mut self, ui: &mut egui::Ui) {
        match self.view.section {
            Section::Tool(t) => {
                let handle = self.rt.handle().clone();
                let open: Vec<(Ipv4Addr, u16)> = self.rows.iter().map(|r| (r.ip, r.port)).collect();
                let proxies: Vec<String> = self
                    .rows
                    .iter()
                    .filter(|r| r.kind == ProxyKind::HttpProxy)
                    .map(|r| format!("{}:{}", r.ip, r.port))
                    .collect();
                let nav = self.bench.settings_ui(t, ui, &handle, self.local_cidr.clone(), open, proxies);
                self.navigate(nav);
            }
            _ => {
                if !self.busy() {
                    let handle = self.rt.handle().clone();
                    self.bench.preset_bar_for(ui, &handle, "proxy", &mut self.settings);
                }
                self.ui_settings(ui);
            }
        }
    }

    /// Общий пресет («контур») ко всем инструментам и к прокси-сканеру.
    fn menu_profile(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("Контур ▾", |ui| {
            ui.set_min_width(320.0);
            let list: Vec<crate::presets::Preset> =
                self.bench.store.for_tool(crate::presets::ALL_TOOLS).into_iter().cloned().collect();
            for p in list {
                if ui.button(&p.name).on_hover_text(&p.description).clicked() {
                    self.apply_common_preset(&p);
                    ui.close();
                }
            }
        })
        .response
        .on_hover_text("Открытый или закрытый контур: настройки сразу для всех инструментов");
    }

    fn apply_common_preset(&mut self, p: &crate::presets::Preset) {
        let mut res = Ok(());
        if let Some(v) = p.values.get("proxy")
            && !self.busy()
        {
            res = crate::presets::apply(&mut self.settings, v);
        }
        let res = res.and_then(|_| self.bench.apply_common(p));
        self.status = match res {
            Ok(()) => format!("Применён пресет «{}»", p.name),
            Err(e) => format!("Пресет «{}»: {e}", p.name),
        };
        self.push_log(self.status.clone());
    }

    /// Ctrl+K: инструменты, пресеты, узлы.
    fn ui_palette(&mut self, ctx: &egui::Context) {
        if ctx.input_mut(|i| i.consume_shortcut(&egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, egui::Key::K))) {
            self.bench.palette_open();
        }
        let tool_id = match self.view.section {
            Section::Tool(t) => t.preset_id(),
            _ => "proxy",
        };
        let mut hosts: Vec<String> = self.rows.iter().map(|r| format!("{}:{}", r.ip, r.port)).collect();
        hosts.dedup();
        match self.bench.palette_ui(ctx, tool_id, &hosts) {
            Some(PaletteItem::Tool(t)) => self.view.section = Section::Tool(t),
            Some(PaletteItem::Proxy) => self.view.section = Section::Proxies,
            Some(PaletteItem::Preset(tool, p)) => {
                if p.tool == crate::presets::ALL_TOOLS {
                    self.apply_common_preset(&p);
                } else if tool == "proxy" {
                    if !self.busy() {
                        self.status = match crate::presets::apply(&mut self.settings, &p.values) {
                            Ok(()) => format!("Применён пресет «{}»", p.name),
                            Err(e) => e,
                        };
                    }
                } else if let Section::Tool(t) = self.view.section {
                    self.bench.apply_tool_preset(t, &p);
                }
            }
            Some(PaletteItem::Host(h)) => {
                let t = match self.view.section {
                    Section::Tool(t) if t != Tool::Host => t,
                    _ => Tool::Services,
                };
                self.navigate(Some(Nav::Send(t, h)));
            }
            None => {}
        }
    }

    fn pac_detect_system(&mut self, ctx: &egui::Context) {
        self.pac.system_busy = true;
        let tx = self.tx(ctx);
        self.rt.spawn_blocking(move || tx.send(AppEvent::PacSystem(Box::new(crate::pac::system_info()))));
    }

    fn pac_search_wpad(&mut self, ctx: &egui::Context) {
        let suffixes = self.pac.system.as_ref().map(|s| s.suffixes.clone()).unwrap_or_default();
        let urls = crate::pac::wpad_candidates(&suffixes);
        self.pac.wpad.clear();
        self.pac.wpad_texts.clear();
        self.pac.wpad_busy = true;
        let tx = self.tx(ctx);
        self.rt.spawn(async move {
            let mut set = tokio::task::JoinSet::new();
            for url in urls {
                let tx = tx.clone();
                set.spawn(async move {
                    let r = crate::pac::fetch(&url, Duration::from_secs(4)).await;
                    tx.send(AppEvent::PacWpad(url, r));
                });
            }
            while set.join_next().await.is_some() {}
            tx.send(AppEvent::PacWpadDone);
        });
    }

    fn pac_load(&mut self, ctx: &egui::Context, source: String) {
        if source.trim().is_empty() {
            self.pac.load_error = Some("Укажите адрес PAC-файла или путь к файлу".into());
            return;
        }
        self.settings.pac_source = source.clone();
        self.pac.load_busy = true;
        let tx = self.tx(ctx);
        self.rt.spawn(async move {
            let r = crate::pac::fetch(&source, Duration::from_secs(6)).await;
            tx.send(AppEvent::PacLoaded(source, r));
        });
    }

    fn pac_evaluate(&mut self, ctx: &egui::Context) {
        let Some((_, text)) = self.pac.loaded.clone() else { return };
        let urls: Vec<String> = self
            .settings
            .pac_test_urls
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();
        let my_ip = if !self.settings.pac_client_ip.trim().is_empty() {
            self.settings.pac_client_ip.trim().to_string()
        } else if !self.settings.source_ip.trim().is_empty() {
            self.settings.source_ip.trim().to_string()
        } else {
            "127.0.0.1".to_string()
        };
        self.pac.eval_busy = true;
        let tx = self.tx(ctx);
        self.rt.spawn_blocking(move || {
            let r = crate::pac::PacEngine::new(&text, &my_ip).map(|mut engine| {
                urls.iter().map(|u| (u.clone(), engine.find(u))).collect::<Vec<_>>()
            });
            tx.send(AppEvent::PacEvaluated(r));
        });
    }

    fn pac_add_targets(&mut self, ctx: &egui::Context) {
        let mut proxies: Vec<crate::pac::PacProxy> = Vec::new();
        for (_, r) in &self.pac.results {
            if let Ok(s) = r {
                for p in crate::pac::parse_result(s) {
                    if !proxies.contains(&p) {
                        proxies.push(p);
                    }
                }
            }
        }
        let tx = self.tx(ctx);
        self.rt.spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            let (mut found, mut errors) = (Vec::new(), Vec::new());
            for p in proxies {
                let ip = p.host.parse::<Ipv4Addr>().ok().or_else(|| {
                    (p.host.as_str(), p.port)
                        .to_socket_addrs()
                        .ok()
                        .and_then(|mut it| it.find(|a| a.is_ipv4()))
                        .map(|a| match a.ip() {
                            std::net::IpAddr::V4(v) => v,
                            std::net::IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                        })
                });
                match ip {
                    Some(ip) if !found.contains(&(ip, p.port)) => found.push((ip, p.port)),
                    Some(_) => {}
                    None => errors.push(format!("не удалось разрешить «{}»", p.host)),
                }
            }
            tx.send(AppEvent::PacTargets(found, errors));
        });
    }

    fn ui_pac(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.pac.system.is_none() && !self.pac.system_busy {
            self.pac_detect_system(&ctx);
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            // 1. Системные настройки.
            ui.horizontal(|ui| {
                ui.strong("Настройки прокси в системе");
                if ui.small_button("Обновить").clicked() {
                    self.pac_detect_system(&ctx);
                }
                if self.pac.system_busy {
                    ui.spinner();
                }
            });
            let mut open_pac: Option<String> = None;
            if let Some(info) = &self.pac.system {
                if info.settings.is_empty() {
                    ui.weak("Явных настроек прокси не найдено (прокси может задаваться через WPAD или DHCP).");
                }
                for st in &info.settings {
                    ui.horizontal(|ui| {
                        ui.add(egui::Label::new(RichText::new(format!("{}:", st.source)).strong()).extend());
                        if let Some(u) = &st.pac_url
                            && ui.small_button("Открыть PAC").clicked()
                        {
                            open_pac = Some(u.clone());
                        }
                        ui.add(egui::Label::new(RichText::new(&st.value).monospace()).truncate())
                            .on_hover_text(&st.value);
                    });
                }
                if !info.suffixes.is_empty() {
                    ui.weak(format!("DNS-суффиксы: {}", info.suffixes.join(", ")));
                }
            }

            // 2. WPAD.
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.strong("Поиск WPAD");
                if ui
                    .add_enabled(!self.pac.wpad_busy, egui::Button::new("Искать"))
                    .on_hover_text("Пробует http://wpad.<суффикс>/wpad.dat для всех DNS-суффиксов")
                    .clicked()
                {
                    self.pac_search_wpad(&ctx);
                }
                if self.pac.wpad_busy {
                    ui.spinner();
                }
            });
            if !self.pac.wpad.is_empty() {
                egui::Grid::new("pac_wpad").num_columns(3).striped(true).show(ui, |ui| {
                    for (url, r) in &self.pac.wpad {
                        ui.label(RichText::new(url).monospace());
                        match r {
                            Ok(n) => {
                                ui.colored_label(GREEN, format!("найден ({n} байт)"));
                                if ui.small_button("Открыть PAC").clicked() {
                                    open_pac = Some(url.clone());
                                }
                            }
                            Err(e) => {
                                ui.weak(format!("нет: {e}"));
                                ui.label("");
                            }
                        }
                        ui.end_row();
                    }
                });
                if !self.pac.wpad_busy && self.pac.wpad_texts.is_empty() {
                    ui.weak("WPAD не найден. Адрес PAC может раздаваться по DHCP (опция 252) — укажите его вручную.");
                }
            }
            if let Some(u) = open_pac {
                self.pac_load(&ctx, u);
            }

            // 3. PAC-файл.
            ui.add_space(8.0);
            ui.strong("PAC-файл");
            let mut load: Option<String> = None;
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.pac_source)
                        .desired_width((ui.available_width() - 190.0).max(160.0))
                        .hint_text("http://wpad.corp.local/wpad.dat или путь к файлу"),
                );
                if ui.add_enabled(!self.pac.load_busy, egui::Button::new("Загрузить")).clicked() {
                    load = Some(self.settings.pac_source.clone());
                }
                if ui.button("Файл…").clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .set_title("PAC-файл")
                        .add_filter("PAC", &["pac", "dat", "js", "txt"])
                        .pick_file()
                {
                    load = Some(p.display().to_string());
                }
                if self.pac.load_busy {
                    ui.spinner();
                }
            });
            if let Some(src) = load {
                self.pac_load(&ctx, src);
            }
            if let Some(e) = &self.pac.load_error {
                ui.colored_label(RED, e);
            }
            if let Some((src, text)) = &self.pac.loaded {
                ui.colored_label(GREEN, format!("Загружен: {src} ({} байт)", text.len()));
                egui::CollapsingHeader::new("Текст PAC-файла").default_open(false).show(ui, |ui| {
                    let mut t = text.as_str();
                    ui.add(
                        egui::TextEdit::multiline(&mut t)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(10)
                            .desired_width(f32::INFINITY),
                    );
                });
            }

            // 4. Проверка URL.
            ui.add_space(8.0);
            ui.strong("Какой прокси будет выбран для адреса");
            ui.label("Адреса для проверки (по одному в строке)");
            ui.add(
                egui::TextEdit::multiline(&mut self.settings.pac_test_urls)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY),
            );
            ui.horizontal(|ui| {
                ui.label("IP клиента (myIpAddress)").on_hover_text(
                    "От адреса клиента правила PAC часто зависят (филиалы, сегменты).\n\
                     Пусто — source-ip этой рабочей станции.",
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.pac_client_ip)
                        .desired_width(140.0)
                        .hint_text(if self.settings.source_ip.is_empty() { "127.0.0.1" } else { &self.settings.source_ip }),
                );
                let can = self.pac.loaded.is_some() && !self.pac.eval_busy;
                if ui
                    .add_enabled(can, egui::Button::new(RichText::new("▶ Вычислить").strong()))
                    .on_disabled_hover_text("Сначала загрузите PAC-файл")
                    .clicked()
                {
                    self.pac_evaluate(&ctx);
                }
                if self.pac.eval_busy {
                    ui.spinner();
                }
            });
            if let Some(e) = &self.pac.eval_error {
                ui.colored_label(RED, e);
            }
            if !self.pac.results.is_empty() {
                egui::Grid::new("pac_results").num_columns(2).striped(true).show(ui, |ui| {
                    ui.strong("Адрес");
                    ui.strong("Ответ FindProxyForURL");
                    ui.end_row();
                    for (url, r) in &self.pac.results {
                        ui.label(RichText::new(url).monospace());
                        match r {
                            Ok(v) if v.trim().eq_ignore_ascii_case("DIRECT") => {
                                ui.colored_label(AMBER, RichText::new(v).monospace())
                                    .on_hover_text("Напрямую, без прокси");
                            }
                            Ok(v) => {
                                ui.label(RichText::new(v).monospace());
                            }
                            Err(e) => {
                                ui.colored_label(RED, e);
                            }
                        }
                        ui.end_row();
                    }
                });
                ui.add_space(4.0);
                if ui
                    .button("Добавить прокси из PAC в цели сканирования")
                    .on_hover_text("Адреса и порты прокси из ответов PAC добавятся в поля «Цели» и «Порты»")
                    .clicked()
                {
                    self.pac_add_targets(&ctx);
                }
            }
        });
    }

    fn start_egress(&mut self, ctx: &egui::Context) {
        self.error = None;
        let s = &self.settings;
        let cfg = (|| -> Result<egress::EgressConfig, String> {
            Ok(egress::EgressConfig {
                target: s.egress_target.trim().to_string(),
                ports: if s.egress_ports.trim().is_empty() {
                    Vec::new()
                } else {
                    targets::parse_ports(&s.egress_ports).map_err(|e| format!("Порты: {e}"))?
                },
                dns_servers: egress::parse_dns_servers(&s.egress_dns)?,
                test_domain: s.egress_domain.trim().to_string(),
                timeout: Duration::from_millis(s.egress_timeout_ms.clamp(200, 30_000)),
                concurrency: 64,
            })
        })();
        let cfg = match cfg {
            Ok(c) if c.target.is_empty() && c.dns_servers.is_empty() && c.test_domain.is_empty() => {
                self.error = Some(
                    "Нечего проверять: укажите узел-слушатель, DNS-серверы или тестовый сайт \
                     (в закрытом контуре — свои узлы за периметром)"
                        .into(),
                );
                return;
            }
            Ok(c) => c,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        self.egress_items.clear();
        let cancel = CancellationToken::new();
        self.egress_cancel = Some(cancel.clone());
        self.push_log(format!(
            "— проверка обхода прокси: узел {}, портов {}, DNS-серверов {} —",
            cfg.target,
            cfg.ports.len(),
            cfg.dns_servers.len()
        ));
        let tx = self.tx(ctx);
        self.rt.spawn(async move {
            let tx2 = tx.clone();
            egress::run(cfg, cancel, move |item| tx2.send(AppEvent::Egress(Box::new(item)))).await;
            tx.send(AppEvent::EgressDone);
        });
    }

    fn toggle_listener(&mut self, ctx: &egui::Context) {
        if let Some((cancel, _, _)) = self.listener.take() {
            cancel.cancel();
            self.push_log("слушатель остановлен".to_string());
            return;
        }
        let ports = match targets::parse_ports(&self.settings.egress_ports) {
            Ok(p) => p,
            Err(e) => {
                self.error = Some(format!("Порты слушателя: {e}"));
                return;
            }
        };
        let cancel = CancellationToken::new();
        self.listener = Some((cancel.clone(), Vec::new(), Vec::new()));
        let tx = self.tx(ctx);
        self.rt.spawn(async move {
            let (ok, errors) = egress::start_listener(&ports, cancel).await;
            tx.log(format!("слушатель: занято портов {}, ошибок {}", ok.len(), errors.len()));
            tx.send(AppEvent::ListenerStarted(ok, errors));
        });
    }

    fn ui_egress(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let running = self.egress_cancel.is_some();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(
                "Проверяет, может ли эта рабочая станция выйти наружу напрямую, мимо прокси: \
                 по TCP-портам до тестового узла, через внешние DNS-серверы, по HTTP и HTTPS. \
                 Любой «ОТКРЫТ» или «отказ» означает, что трафик уходит наружу без прокси.",
            );
            ui.add_space(6.0);
            let s = &mut self.settings;
            egui::Grid::new("egress_grid").num_columns(2).show(ui, |ui| {
                ui.label("Тестовый узел").on_hover_text(
                    "portquiz.net принимает подключения на любом порту.\n\
                     В закрытом контуре укажите адрес машины со слушателем (см. ниже).",
                );
                ui.add(egui::TextEdit::singleline(&mut s.egress_target).desired_width(220.0));
                ui.end_row();
                ui.label("TCP-порты");
                ui.add(egui::TextEdit::singleline(&mut s.egress_ports).desired_width(f32::INFINITY));
                ui.end_row();
                ui.label("Внешние DNS-серверы");
                ui.add(egui::TextEdit::singleline(&mut s.egress_dns).desired_width(220.0));
                ui.end_row();
                ui.label("Сайт для HTTP/HTTPS/DNS");
                ui.add(egui::TextEdit::singleline(&mut s.egress_domain).desired_width(220.0));
                ui.end_row();
                ui.label("Таймаут, мс");
                ui.add(egui::DragValue::new(&mut s.egress_timeout_ms).range(200..=30_000).speed(50));
                ui.end_row();
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if running {
                    if ui.button(RichText::new("■ Остановить").strong()).clicked()
                        && let Some(c) = &self.egress_cancel
                    {
                        c.cancel();
                    }
                    ui.spinner();
                } else if ui.button(RichText::new("▶ Проверить обход").strong()).clicked() {
                    self.start_egress(&ctx);
                }
            });

            // Итог.
            if !self.egress_items.is_empty() {
                ui.add_space(6.0);
                let leaks: Vec<&EgressItem> = self.egress_items.iter().filter(|i| i.status.is_leak()).collect();
                if leaks.is_empty() {
                    ui.colored_label(GREEN, RichText::new("Прямой выход наружу не обнаружен").strong());
                } else {
                    let mut tcp: Vec<u16> = leaks
                        .iter()
                        .filter(|i| i.kind == egress::EgressKind::Tcp)
                        .filter_map(|i| i.target.rsplit(':').next()?.parse().ok())
                        .collect();
                    tcp.sort_unstable();
                    let tcp: Vec<String> = tcp.iter().map(u16::to_string).collect();
                    let mut other: Vec<String> = Vec::new();
                    for i in leaks.iter().filter(|i| i.kind != egress::EgressKind::Tcp) {
                        let label = if i.kind == egress::EgressKind::Dns {
                            format!("DNS через {}", i.target.trim_end_matches(":53"))
                        } else {
                            i.kind.label().to_string()
                        };
                        if !other.contains(&label) {
                            other.push(label);
                        }
                    }
                    ui.colored_label(
                        RED,
                        RichText::new(format!(
                            "Обход прокси возможен: {}{}{}",
                            if tcp.is_empty() { String::new() } else { format!("TCP-порты {}", tcp.join(", ")) },
                            if !tcp.is_empty() && !other.is_empty() { "; " } else { "" },
                            other.join(", ")
                        ))
                        .strong(),
                    );
                }
                ui.add_space(4.0);
                let mut items: Vec<&EgressItem> = self.egress_items.iter().collect();
                items.sort_by_key(|i| {
                    let port: u32 = i.target.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
                    (!i.status.is_leak(), i.kind as u8, port, i.target.clone())
                });
                egui::Grid::new("egress_results").num_columns(5).striped(true).show(ui, |ui| {
                    for h in ["Проверка", "Цель", "Результат", "мс", "Подробности"] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for i in items {
                        ui.label(i.kind.label());
                        ui.label(RichText::new(&i.target).monospace());
                        let color = match i.status {
                            s if s.is_leak() => RED,
                            egress::EgressStatus::Intercepted => AMBER,
                            egress::EgressStatus::Error => AMBER,
                            _ => GREEN,
                        };
                        let mut text = i.status.label().to_string();
                        if i.confirmed {
                            text.push_str(" ✔");
                        }
                        ui.colored_label(color, RichText::new(text).strong())
                            .on_hover_text(if i.confirmed { "ответил слушатель Proxy Scanner" } else { "" });
                        ui.label(i.rtt_ms.map(|v| v.to_string()).unwrap_or_default());
                        ui.add(egui::Label::new(&i.detail).wrap());
                        ui.end_row();
                    }
                });
            }

            ui.add_space(10.0);
            ui.separator();
            egui::CollapsingHeader::new("Слушатель для закрытого контура")
                .default_open(self.listener.is_some())
                .show(ui, |ui| {
                    ui.label(
                        "Запустите Proxy Scanner на машине за пределами проверяемого сегмента \
                         (другой сегмент, DMZ) и включите слушатель: он займёт порты из поля \
                         «TCP-порты» и будет отвечать меткой. На проверяемой станции укажите адрес \
                         этой машины в поле «Тестовый узел» — «✔» в результатах подтвердит, что \
                         соединение действительно дошло до слушателя.",
                    );
                    if !cfg!(windows) {
                        ui.weak("В Linux порты ниже 1024 занимаются только с правами root.");
                    }
                    ui.horizontal(|ui| {
                        let text = if self.listener.is_some() { "■ Остановить слушатель" } else { "▶ Запустить слушатель" };
                        if ui.button(text).clicked() {
                            self.toggle_listener(&ctx);
                        }
                    });
                    if let Some((_, ok, errors)) = &self.listener {
                        ui.colored_label(
                            if ok.is_empty() { AMBER } else { GREEN },
                            format!(
                                "Слушает портов: {} {}",
                                ok.len(),
                                if ok.is_empty() { String::new() } else { format!("({})", targets::ports_to_masscan(ok)) }
                            ),
                        );
                        for e in errors.iter().take(10) {
                            ui.colored_label(AMBER, format!("не удалось занять порт {e}"));
                        }
                        if errors.len() > 10 {
                            ui.weak(format!("… и ещё {}", errors.len() - 10));
                        }
                    }
                });
        });
    }

    /// Баннер о незавершённом сканировании / восстановленной сессии.
    fn ui_banner(&mut self, ui: &mut egui::Ui) {
        let resumable = self.can_resume();
        let restored = self
            .restored
            .as_ref()
            .map(|r| (r.computer.clone(), r.saved_at, r.other_computer));
        if !resumable && restored.is_none() {
            return;
        }
        let ctx = ui.ctx().clone();
        let mut dismiss = false;
        let mut resume = false;
        let fraction = self.scan_state.as_ref().map(|s| s.fraction()).unwrap_or(0.0);
        let blocked = !resumable
            && self
                .scan_state
                .as_ref()
                .is_some_and(|st| !st.finished && st.has_progress());
        let nrows = self.rows.len();
        egui::Frame::group(ui.style())
            .fill(ui.visuals().faint_bg_color)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    if resumable {
                        ui.strong(format!(
                            "Незавершённое сканирование: выполнено {:.1}%, найдено узлов — {nrows}.",
                            fraction * 100.0
                        ));
                    } else {
                        ui.strong(format!("Загружена сессия: узлов — {nrows}."));
                    }
                    if let Some((computer, saved_at, other)) = &restored {
                        ui.label(format!(
                            "Сохранена {} на ПК «{computer}».",
                            session::format_time(*saved_at)
                        ));
                        if *other {
                            ui.colored_label(AMBER, "Сетевые параметры определены заново для этого ПК.");
                        }
                    }
                    if resumable {
                        resume = ui.button(RichText::new("⏵ Продолжить").strong()).clicked();
                    } else if blocked {
                        ui.colored_label(
                            AMBER,
                            "Цели, порты или режим отличаются от сохранённых — продолжить нельзя.",
                        );
                    }
                    if !resumable {
                        dismiss = ui.small_button("✖").on_hover_text("Скрыть").clicked();
                    }
                });
            });
        if resume {
            self.start_scan(&ctx, StartKind::Resume);
        }
        if dismiss {
            self.restored = None;
        }
        ui.add_space(4.0);
    }

    fn ui_filters_panel(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let right = ui.max_rect().right();
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                ui.label("Тип:");
                for &k in filters::KINDS {
                    let on = self.filters.kinds.contains(&k);
                    if ui.selectable_label(on, k.label()).clicked() {
                        self.filters.toggle_kind(k);
                    }
                }
                ui.end_row();
                choice_combo(ui, right, "f_auth", "Аутентификация:", &mut self.filters.auth);
                choice_combo(ui, right, "f_connect", "CONNECT:", &mut self.filters.connect);
                choice_combo(ui, right, "f_ssl", "SSL-инспекция:", &mut self.filters.ssl);
                choice_combo(ui, right, "f_policy", "Политики:", &mut self.filters.policy);
                choice_combo(ui, right, "f_inspect", "Качество инспекции:", &mut self.filters.inspect);
                choice_combo(ui, right, "f_state", "Состояние:", &mut self.filters.state);
                choice_combo(ui, right, "f_source", "Обнаружен:", &mut self.filters.source);
                flow(ui, right, "f_ports", |ui| {
                    ui.label("Порты:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filters.ports)
                            .desired_width(110.0)
                            .hint_text("3128,8080-8090"),
                    );
                });
                flow(ui, right, "f_subnet", |ui| {
                    ui.label("Адреса:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filters.subnet)
                            .desired_width(150.0)
                            .hint_text("10.0.0.0/24"),
                    );
                });
                flow(ui, right, "f_rtt", |ui| {
                    let mut on = self.filters.max_rtt_ms.is_some();
                    if ui.checkbox(&mut on, "Отклик не более").changed() {
                        self.filters.max_rtt_ms = on.then_some(100);
                    }
                    if let Some(v) = &mut self.filters.max_rtt_ms {
                        ui.add(egui::DragValue::new(v).range(1..=60_000).suffix(" мс"));
                    }
                });
                if ui
                    .add_enabled(!self.filters.is_empty(), egui::Button::new("Сбросить всё"))
                    .clicked()
                {
                    self.filters = Filters::default();
                }
            });
            for e in &self.filter_errors {
                ui.colored_label(RED, e);
            }
        });
    }

    fn ui_results(&mut self, ui: &mut egui::Ui) {
        self.ui_banner(ui);
        let visible = self.visible_rows();

        ui.horizontal_wrapped(|ui| {
            let w = (ui.available_width() * 0.3).clamp(120.0, 280.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.filters.text)
                    .desired_width(w)
                    .hint_text("🔍 IP, порт, тип, издатель…"),
            );
            let n = self.filters.active_count();
            let label = if n > 0 { format!("Фильтры ({n})") } else { "Фильтры".to_string() };
            ui.toggle_value(&mut self.view.filters_open, label)
                .on_hover_text("Показать панель фильтров");
            ui.menu_button("Быстрые", |ui| {
                for &p in Preset::ALL {
                    if ui.button(p.label()).on_hover_text(p.hint()).clicked() {
                        self.filters.apply_preset(p);
                        ui.close();
                    }
                }
                ui.separator();
                if ui.button("Сбросить все фильтры").clicked() {
                    self.filters = Filters::default();
                    ui.close();
                }
            });
            if !self.filters.is_empty() && ui.small_button("✖").on_hover_text("Сбросить фильтры").clicked() {
                self.filters = Filters::default();
            }
            ui.separator();
            ui.selectable_value(&mut self.view.results_view, ResultsView::Table, "☰ Таблица");
            ui.selectable_value(&mut self.view.results_view, ResultsView::Graph, "◎ Граф")
                .on_hover_text("Граф подсетей, узлов и издателей сертификатов");
            if self.view.results_view == ResultsView::Table {
                self.menu_columns(ui);
            }
            ui.separator();
            ui.add(egui::Label::new(format!("{} из {}", visible.len(), self.rows.len())).extend());
            if ui
                .add_enabled(!visible.is_empty(), egui::Button::new("Экспорт…"))
                .on_hover_text("Сохранить показанные строки в CSV или JSON")
                .clicked()
            {
                self.export(&visible);
            }
        });
        if self.view.filters_open {
            ui.add_space(2.0);
            self.ui_filters_panel(ui);
        } else if !self.filter_errors.is_empty() {
            for e in &self.filter_errors {
                ui.colored_label(RED, e);
            }
        }
        ui.separator();

        if self.rows.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.weak("Нет данных. Укажите цели и порты и нажмите «Сканировать».");
            });
            return;
        }
        if visible.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.weak("Нет узлов, подходящих под фильтры.");
                if ui.button("Сбросить фильтры").clicked() {
                    self.filters = Filters::default();
                }
            });
            return;
        }

        match self.view.results_view {
            ResultsView::Table => self.ui_table(ui, &visible),
            ResultsView::Graph => {
                let refs: Vec<&ProxyRow> = visible.iter().map(|&i| &self.rows[i]).collect();
                let out = self.graph.ui(ui, &refs, self.selected, &mut self.view.graph);
                if let Some(k) = out.select {
                    self.selected = Some(k);
                }
                if let Some(net) = out.filter_subnet {
                    self.filters.subnet = net;
                    self.view.filters_open = true;
                }
                if let Some(t) = out.filter_text {
                    self.filters.text = t;
                }
            }
        }
    }

    fn menu_columns(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("Столбцы", |ui| {
            ui.checkbox(&mut self.view.auto_columns, "Подбирать по ширине окна")
                .on_hover_text("Менее важные столбцы скрываются, когда окно узкое");
            ui.separator();
            ui.add_enabled_ui(!self.view.auto_columns, |ui| {
                for d in columns::COLS {
                    let mut on = self.view.columns.contains(&d.col);
                    if ui.checkbox(&mut on, d.title).changed() {
                        if on {
                            self.view.columns.push(d.col);
                        } else if self.view.columns.len() > 1 {
                            self.view.columns.retain(|c| *c != d.col);
                        }
                    }
                }
                if ui.button("По умолчанию").clicked() {
                    self.view.columns = columns::default_visible();
                }
            });
        });
    }

    fn ui_table(&mut self, ui: &mut egui::Ui, visible: &[usize]) {
        let auto = self.view.auto_columns;
        let cols: Vec<Col> = if auto {
            columns::auto_layout(ui.available_width().min(ui.clip_rect().right() - ui.cursor().min.x))
        } else {
            columns::COLS
                .iter()
                .map(|d| d.col)
                .filter(|c| self.view.columns.contains(c))
                .collect()
        };
        let mut clicked: Option<(Ipv4Addr, u16)> = None;
        let mut action: Option<RowAction> = None;
        let mut sort = self.sort;
        let selected = self.selected;
        let rows = &self.rows;
        let salt = (auto, cols.iter().map(|c| *c as u8).collect::<Vec<_>>());

        // В авто-режиме ширины подгоняются под окно: исходные, если помещаются, иначе минимальные.
        let avail = ui.available_width().min(ui.clip_rect().right() - ui.cursor().min.x);
        let natural: f32 = cols.iter().map(|c| columns::def(*c).width + 10.0).sum();
        let fit_natural = natural <= avail;
        let mut show = |ui: &mut egui::Ui| {
            let mut table = TableBuilder::new(ui)
                .id_salt(("results_table", salt.clone(), fit_natural))
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .min_scrolled_height(0.0);
            for (i, c) in cols.iter().enumerate() {
                let d = columns::def(*c);
                let column = if auto && i + 1 == cols.len() {
                    Column::remainder().at_least(d.min.min(60.0))
                } else if auto && !fit_natural {
                    Column::initial(d.min).at_least(36.0)
                } else {
                    Column::initial(d.width).at_least(36.0)
                };
                table = table.column(column.clip(true));
            }
            table
                .header(24.0, |mut header| {
                    for c in &cols {
                        header.col(|ui| {
                            let d = columns::def(*c);
                            let arrow = if sort.0 == *c {
                                if sort.1 { " ⏶" } else { " ⏷" }
                            } else {
                                ""
                            };
                            let resp = ui.add(
                                egui::Button::new(RichText::new(format!("{}{arrow}", d.title)).strong())
                                    .frame(false)
                                    .truncate(),
                            );
                            if resp.on_hover_text(d.title).clicked() {
                                sort = if sort.0 == *c { (*c, !sort.1) } else { (*c, true) };
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(22.0, visible.len(), |mut row| {
                        let r = &rows[visible[row.index()]];
                        row.set_selected(selected == Some((r.ip, r.port)));
                        for c in &cols {
                            row.col(|ui| cell(ui, r, *c));
                        }
                        let resp = row.response();
                        if resp.clicked() {
                            clicked = Some((r.ip, r.port));
                        }
                        resp.context_menu(|ui| {
                            row_menu(ui, r, &mut action);
                        });
                    });
                });
        };
        if auto {
            show(ui);
        } else {
            egui::ScrollArea::horizontal().show(ui, show);
        }

        self.sort = sort;
        if let Some(k) = clicked {
            self.selected = if self.selected == Some(k) { None } else { Some(k) };
        }
        match action {
            Some(RowAction::OnlyPort(p)) => {
                self.filters.ports = p.to_string();
                self.view.filters_open = true;
            }
            Some(RowAction::OnlySubnet(n)) => {
                self.filters.subnet = n;
                self.view.filters_open = true;
            }
            Some(RowAction::OnlyKind(k)) => {
                self.filters.kinds = vec![k];
                self.view.filters_open = true;
            }
            Some(RowAction::Search(t)) => self.filters.text = t,
            Some(RowAction::Copy(t)) => ui.ctx().copy_text(t),
            None => {}
        }
    }
}

/// Контекстное меню строки: быстрые фильтры по значению.
fn row_menu(ui: &mut egui::Ui, r: &ProxyRow, action: &mut Option<RowAction>) {
    let mut pick = |ui: &mut egui::Ui, text: String, a: RowAction| {
        if ui.button(text).clicked() {
            *action = Some(a);
            ui.close();
        }
    };
    pick(ui, format!("Копировать {}:{}", r.ip, r.port), RowAction::Copy(format!("{}:{}", r.ip, r.port)));
    ui.separator();
    pick(ui, format!("Только порт {}", r.port), RowAction::OnlyPort(r.port));
    let net = filters::subnet_24(r.ip);
    pick(ui, format!("Только подсеть {net}"), RowAction::OnlySubnet(net));
    pick(ui, format!("Только тип «{}»", r.kind.label()), RowAction::OnlyKind(r.kind));
    if let Some(c) = &r.probe.cert
        && !c.issuer.is_empty()
    {
        let cn = c
            .issuer
            .split(',')
            .map(str::trim)
            .find_map(|p| p.strip_prefix("CN="))
            .unwrap_or(&c.issuer)
            .to_string();
        pick(ui, format!("Найти издателя «{}»", truncate(&cn, 40)), RowAction::Search(cn));
    }
}

/// Группа элементов в `horizontal_wrapped`, которая переносится целиком.
/// egui не знает размер группы до отрисовки, поэтому ширина берётся с прошлого
/// кадра; если группа не помещается до правого края `right`, она начинается
/// с новой строки.
fn flow(ui: &mut egui::Ui, right: f32, id: &str, add: impl FnOnce(&mut egui::Ui)) {
    let key = ui.scope_id().with(("flow_group", id));
    let last: Option<f32> = ui.data(|d| d.get_temp(key));
    let x = ui.cursor().min.x;
    let at_line_start = x <= ui.max_rect().min.x + 1.0;
    let spacing = ui.spacing().item_spacing.x;
    if let Some(w) = last
        && !at_line_start
        && x + spacing + w > right
    {
        ui.end_row();
    }
    let width = ui.horizontal(add).response.rect.width();
    ui.data_mut(|d| d.insert_temp(key, width));
}

fn choice_combo<T: Choice>(ui: &mut egui::Ui, right: f32, id: &str, label: &str, value: &mut T) {
    flow(ui, right, id, |ui| {
        if value.is_any() {
            ui.label(label);
        } else {
            ui.label(RichText::new(label).strong().color(ui.visuals().selection.stroke.color));
        }
        egui::ComboBox::from_id_salt(id)
            .selected_text(value.label())
            .show_ui(ui, |ui| {
                for &c in T::ALL {
                    ui.selectable_value(value, c, c.label());
                }
            });
    });
}

fn apply_view(ctx: &egui::Context, view: &ViewPrefs) {
    ctx.set_zoom_factor(view.zoom.clamp(0.5, 3.0));
    ctx.set_theme(match view.theme {
        ThemeChoice::System => egui::ThemePreference::System,
        ThemeChoice::Dark => egui::ThemePreference::Dark,
        ThemeChoice::Light => egui::ThemePreference::Light,
    });
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn cell(ui: &mut egui::Ui, r: &ProxyRow, col: Col) {
    match col {
        Col::Ip => {
            ui.label(RichText::new(r.ip.to_string()).monospace());
        }
        Col::Port => {
            ui.label(RichText::new(r.port.to_string()).monospace());
        }
        Col::Kind => {
            if r.kind.is_proxy() {
                ui.label(RichText::new(r.kind.label()).strong());
            } else {
                ui.weak(r.kind.label());
            }
        }
        Col::Auth => {
            ui.label(r.auth_label());
        }
        Col::Server => {
            ui.label(r.server_label());
        }
        Col::Connect => {
            ui.label(r.connect_label());
        }
        Col::Ssl => match r.ssl {
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
        Col::Issuer => {
            ui.label(r.issuer_label());
        }
        Col::Policy => {
            let (ok, total) = r.policy_counts();
            if total > 0 {
                ui.colored_label(if ok == total { GREEN } else { RED }, r.policy_label());
            }
        }
        Col::Rtt => {
            if let Some(v) = r.probe.rtt_ms {
                ui.label(v.to_string());
            }
        }
        Col::State => match r.state {
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
        Col::Source => {
            ui.weak(&r.source);
        }
        Col::Inspect => {
            let (bad, n) = r.inspect_counts();
            let label = r.inspect_label();
            if bad > 0 {
                ui.colored_label(RED, RichText::new(label).strong());
            } else if n > 0 {
                ui.colored_label(GREEN, label);
            } else {
                ui.weak(label);
            }
        }
        Col::Http => {
            if let Some(v) = r.probe.http_status {
                ui.label(v.to_string());
            }
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.close_after_first_frame && ctx.cumulative_pass_nr() > 2 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        self.handle_events(ctx);
        if self.bench.poll() {
            self.dirty = true;
        }
        // «Сертификаты» и «Сравнение» работают со снимком всей сессии.
        if matches!(self.view.section, Section::Tool(Tool::Certs | Tool::Compare | Tool::Map))
            && self.last_context.is_none_or(|t| t.elapsed() >= Duration::from_secs(3))
        {
            let archive = self.archive.iter().map(|a| (a.label(), a.path.clone())).collect();
            self.bench.set_context(self.session_snapshot(), archive);
            self.last_context = Some(Instant::now());
        }
        if self.bench.take_attention() {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Informational));
        }
        self.view.zoom = ctx.zoom_factor();
        if self.busy() && self.dirty && self.last_autosave.elapsed() >= AUTOSAVE_EVERY {
            self.autosave();
        }
        if self.busy() {
            // Таймер автосохранения не должен зависеть от активности пользователя.
            ctx.request_repaint_after(Duration::from_secs(1));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let full = ui.max_rect();
        let compact = full.width() < COMPACT_WIDTH;
        let narrow = full.width() < NARROW_WIDTH;
        if self.last_compact != Some(compact) {
            if compact {
                self.compact_tab = if self.rows.is_empty() && !self.busy() {
                    CompactTab::Settings
                } else {
                    CompactTab::Results
                };
            }
            self.last_compact = Some(compact);
        }

        self.ui_confirm_new_scan(&ui.ctx().clone());
        self.ui_palette(&ui.ctx().clone());
        self.bench.windows(&ui.ctx().clone());
        if let Some(m) = self.bench.message.take() {
            self.status = m.clone();
            self.push_log(m);
        }
        let selected = if self.view.section == Section::Proxies { self.selected } else { None };

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            self.ui_top(ui, compact, narrow);
            ui.add_space(4.0);
        });
        egui::Panel::bottom("bottom").show(ui, |ui| self.ui_bottom(ui));

        let settings_scroll = |app: &mut App, ui: &mut egui::Ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| app.ui_left(ui));
        };

        if compact {
            match self.compact_tab {
                CompactTab::Settings => {
                    egui::CentralPanel::default().show(ui, |ui| settings_scroll(self, ui));
                }
                CompactTab::Results => {
                    if let Some(key) = selected {
                        egui::Panel::bottom("details_bottom")
                            .resizable(true)
                            .default_size(full.height() * 0.42)
                            .min_size(120.0)
                            .max_size(full.height() * 0.75)
                            .show(ui, |ui| self.ui_details(ui, key));
                    }
                    egui::CentralPanel::default().show(ui, |ui| self.ui_central(ui));
                }
            }
            return;
        }

        let mut settings_w = 0.0;
        if self.view.settings_open {
            let r = egui::Panel::left("settings")
                .resizable(true)
                .default_size(340.0)
                .min_size(270.0)
                .max_size((full.width() * 0.45).max(280.0))
                .show(ui, |ui| settings_scroll(self, ui));
            settings_w = r.response.rect.width();
        }
        if let Some(key) = selected {
            let details_w = 380.0;
            if full.width() - settings_w - details_w >= DETAILS_SIDE_MIN_TABLE {
                egui::Panel::right("details_side")
                    .resizable(true)
                    .default_size(details_w)
                    .min_size(260.0)
                    .max_size((full.width() * 0.5).max(300.0))
                    .show(ui, |ui| self.ui_details(ui, key));
            } else {
                egui::Panel::bottom("details_bottom")
                    .resizable(true)
                    .default_size(full.height() * 0.38)
                    .min_size(120.0)
                    .max_size(full.height() * 0.7)
                    .show(ui, |ui| self.ui_details(ui, key));
            }
        }
        egui::CentralPanel::default().show(ui, |ui| self.ui_central(ui));
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, SETTINGS_KEY, &self.settings);
        eframe::set_value(storage, VIEW_KEY, &self.view);
        eframe::set_value(storage, TOOLS_KEY, &self.bench.prefs());
        // Вызывается при закрытии программы и периодически.
        if self.dirty {
            self.autosave();
        }
    }
}
