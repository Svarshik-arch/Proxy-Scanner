//! Файл сессии: настройки, найденные узлы и место остановки сканирования.
//!
//! Файл пишется рядом с программой при её закрытии, при остановке и во время
//! сканирования (периодически). Его можно перенести вместе с программой на
//! другой компьютер и продолжить сканирование с того же места.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::model::{ProxyRow, ScanMode, Settings};

pub const FILE_NAME: &str = "proxy-scanner-session.json";
const FORMAT: &str = "proxy-scanner-session";
const VERSION: u32 = 1;

/// Состояние обнаружения портов для продолжения.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanState {
    pub mode: ScanMode,
    /// Цели и порты в том виде, как их ввёл пользователь.
    pub targets: String,
    pub ports: String,
    pub total_hosts: u64,
    pub total_ports: u64,
    pub finished: bool,
    /// TCP-connect: число первых адресов, проверенных по всем портам.
    pub tcp_hosts_done: u64,
    /// masscan: зерно псевдослучайного порядка (`--seed`).
    pub masscan_seed: u64,
    /// masscan: индекс, с которого продолжать (`--resume-index`).
    pub masscan_index: u64,
}

impl ScanState {
    pub fn new(settings: &Settings, total_hosts: u64, total_ports: u64, seed: u64) -> Self {
        Self {
            mode: settings.mode,
            targets: settings.targets.trim().to_string(),
            ports: settings.ports.trim().to_string(),
            total_hosts,
            total_ports,
            finished: false,
            tcp_hosts_done: 0,
            masscan_seed: seed,
            masscan_index: 0,
        }
    }

    /// Доля выполненного обнаружения, 0..=1.
    pub fn fraction(&self) -> f32 {
        if self.finished {
            return 1.0;
        }
        let f = match self.mode {
            ScanMode::TcpConnect => self.tcp_hosts_done as f64 / self.total_hosts.max(1) as f64,
            ScanMode::Masscan => {
                self.masscan_index as f64 / (self.total_hosts * self.total_ports).max(1) as f64
            }
        };
        f.clamp(0.0, 1.0) as f32
    }

    pub fn has_progress(&self) -> bool {
        match self.mode {
            ScanMode::TcpConnect => self.tcp_hosts_done > 0,
            ScanMode::Masscan => self.masscan_index > 0,
        }
    }

    /// Можно ли продолжить это сканирование с текущими настройками.
    pub fn resumable_with(&self, settings: &Settings) -> bool {
        !self.finished
            && self.mode == settings.mode
            && self.targets == settings.targets.trim()
            && self.ports == settings.ports.trim()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub format: String,
    pub version: u32,
    /// Время сохранения, секунды Unix (UTC).
    pub saved_at: u64,
    /// Имя компьютера, на котором сохранена сессия.
    pub computer: String,
    pub settings: Settings,
    pub scan: Option<ScanState>,
    pub rows: Vec<ProxyRow>,
}

impl Session {
    pub fn new(settings: &Settings, scan: Option<ScanState>, rows: Vec<ProxyRow>) -> Self {
        Self {
            format: FORMAT.into(),
            version: VERSION,
            saved_at: now_unix(),
            computer: computer_name(),
            settings: settings.clone(),
            scan,
            rows,
        }
    }

    pub fn is_from_this_computer(&self) -> bool {
        self.computer.eq_ignore_ascii_case(&computer_name())
    }

    /// Есть ли что продолжать.
    #[cfg(test)]
    pub fn is_unfinished(&self) -> bool {
        self.scan.as_ref().is_some_and(|s| !s.finished)
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "неизвестный ПК".into())
}

/// Дата и время в UTC: `2026-11-18 09:30 UTC`.
pub fn format_time(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Алгоритм «дни → гражданская дата» (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// Файл сессии по умолчанию: рядом с программой (чтобы переносить их вместе),
/// а если туда нельзя писать — в профиле пользователя.
pub fn default_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
        && dir_writable(dir)
    {
        return dir.join(FILE_NAME);
    }
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("proxy-scanner").join(FILE_NAME)
}

fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(".proxy-scanner-write-test");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Сколько архивных копий сессий хранить.
pub const ARCHIVE_KEEP: usize = 30;
const ARCHIVE_DIR: &str = "proxy-scanner-sessions";

/// Папка архива рядом с файлом сессии.
pub fn archive_dir(session_path: &Path) -> PathBuf {
    session_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(ARCHIVE_DIR)
}

/// Время для имени файла: `20261118-143005`.
fn compact_time(unix: u64) -> String {
    format_time(unix)
        .trim_end_matches(" UTC")
        .replace(['-', ':'], "")
        .replace(' ', "-")
        + &format!("{:02}", unix % 60)
}

/// Копия сессии в архив. Возвращает путь к созданному файлу.
pub fn archive(session: &Session, session_path: &Path) -> Result<PathBuf, String> {
    let dir = archive_dir(session_path);
    let base = format!("session-{}-{}", compact_time(session.saved_at), session.rows.len());
    let mut path = dir.join(format!("{base}.json"));
    let mut n = 1;
    while path.exists() {
        n += 1;
        path = dir.join(format!("{base}-{n}.json"));
    }
    save(&path, session)?;
    prune_archive(&dir, ARCHIVE_KEEP);
    Ok(path)
}

fn archive_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|e| e == "json")
                        && p.file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("session-"))
                })
                .collect()
        })
        .unwrap_or_default();
    // Имена начинаются со времени, поэтому сортировка по имени — по времени.
    files.sort();
    files
}

fn prune_archive(dir: &Path, keep: usize) {
    let files = archive_files(dir);
    if files.len() > keep {
        for f in &files[..files.len() - keep] {
            let _ = std::fs::remove_file(f);
        }
    }
}

/// Сведения об архивной сессии для меню.
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub path: PathBuf,
    pub saved_at: u64,
    pub computer: String,
    pub rows: usize,
    pub fraction: Option<f32>,
    pub targets: String,
}

impl ArchiveEntry {
    pub fn label(&self) -> String {
        let progress = self
            .fraction
            .map(|f| format!(" · обнаружение {:.0}%", f * 100.0))
            .unwrap_or_default();
        format!(
            "{} · {} · узлов: {}{} · {}",
            format_time(self.saved_at),
            self.computer,
            self.rows,
            progress,
            self.targets
        )
    }
}

/// Архив, новые сессии первыми.
pub fn list_archive(session_path: &Path) -> Vec<ArchiveEntry> {
    let mut out: Vec<ArchiveEntry> = archive_files(&archive_dir(session_path))
        .into_iter()
        .filter_map(|path| {
            let s = load(&path).ok()?;
            Some(ArchiveEntry {
                saved_at: s.saved_at,
                computer: s.computer,
                rows: s.rows.len(),
                fraction: s.scan.as_ref().map(ScanState::fraction),
                targets: s.settings.targets.trim().chars().take(40).collect(),
                path,
            })
        })
        .collect();
    out.sort_by(|a, b| b.saved_at.cmp(&a.saved_at).then(b.path.cmp(&a.path)));
    out
}

/// Запись через временный файл: при сбое старая сессия не портится.
pub fn save(path: &Path, session: &Session) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let data = serde_json::to_vec_pretty(session).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn load(path: &Path) -> Result<Session, String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let session: Session =
        serde_json::from_slice(&data).map_err(|e| format!("файл сессии повреждён: {e}"))?;
    if session.format != FORMAT {
        return Err("это не файл сессии Proxy Scanner".into());
    }
    if session.version > VERSION {
        return Err(format!(
            "файл создан более новой версией программы (формат {})",
            session.version
        ));
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProxyKind, SslInspection};
    use std::net::Ipv4Addr;

    fn settings() -> Settings {
        Settings {
            targets: "10.0.0.0/24".into(),
            ports: "3128,8080".into(),
            proxy_pass: "secret".into(),
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_without_password() {
        let s = settings();
        let mut state = ScanState::new(&s, 256, 2, 42);
        state.tcp_hosts_done = 64;
        let mut row = ProxyRow::new(Ipv4Addr::new(10, 0, 0, 5), 3128, "tcp-connect");
        row.kind = ProxyKind::HttpProxy;
        row.ssl = SslInspection::Yes;
        let session = Session::new(&s, Some(state.clone()), vec![row]);

        let dir = std::env::temp_dir().join(format!("ps-session-test-{}", std::process::id()));
        let path = dir.join(FILE_NAME);
        save(&path, &session).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("secret"), "пароль не попадает в файл");

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.scan, Some(state));
        assert_eq!(loaded.rows.len(), 1);
        assert_eq!(loaded.rows[0].kind, ProxyKind::HttpProxy);
        assert_eq!(loaded.rows[0].ssl, SslInspection::Yes);
        assert!(loaded.is_unfinished());
        assert!(loaded.is_from_this_computer());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_foreign_files() {
        let dir = std::env::temp_dir().join(format!("ps-session-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.json");
        std::fs::write(&p, "{\"a\":1}").unwrap();
        assert!(load(&p).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resumable_and_fraction() {
        let s = settings();
        let mut st = ScanState::new(&s, 256, 2, 1);
        assert!(st.resumable_with(&s));
        assert!(!st.has_progress());
        st.tcp_hosts_done = 128;
        assert!((st.fraction() - 0.5).abs() < 1e-6);
        let mut other = s.clone();
        other.ports = "80".into();
        assert!(!st.resumable_with(&other));
        st.finished = true;
        assert!(!st.resumable_with(&s));
        assert_eq!(st.fraction(), 1.0);

        let mut m = s.clone();
        m.mode = ScanMode::Masscan;
        let mut ms = ScanState::new(&m, 256, 2, 7);
        ms.masscan_index = 128;
        assert!((ms.fraction() - 0.25).abs() < 1e-6);
    }

    #[test]
    fn archive_keeps_copies_and_prunes() {
        let dir = std::env::temp_dir().join(format!("ps-archive-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let session_path = dir.join(FILE_NAME);
        let s = settings();
        for i in 0..(ARCHIVE_KEEP as u64 + 5) {
            let mut sess = Session::new(&s, None, vec![]);
            sess.saved_at = 1_794_997_800 + i;
            archive(&sess, &session_path).unwrap();
        }
        let list = list_archive(&session_path);
        assert_eq!(list.len(), ARCHIVE_KEEP, "старые копии удаляются");
        assert_eq!(list[0].saved_at, 1_794_997_800 + ARCHIVE_KEEP as u64 + 4, "новые первыми");
        assert!(list[0].label().contains("10.0.0.0/24"));
        // Две копии в одну секунду не затирают друг друга.
        let sess = Session::new(&s, None, vec![]);
        let a = archive(&sess, &session_path).unwrap();
        let b = archive(&sess, &session_path).unwrap();
        assert_ne!(a, b);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn time_format() {
        assert_eq!(format_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_time(1_794_997_800), "2026-11-18 10:30 UTC");
        assert_eq!(compact_time(1_794_997_805), "20261118-103005");
    }
}
