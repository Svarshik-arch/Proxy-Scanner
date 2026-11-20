//! Сценарий по расписанию: выполнить, сохранить в историю, сравнить с прошлым
//! прогоном и отправить HTML-отчёт на почту.
//!
//! Запуск — заданием Планировщика Windows (ежедневно, еженедельно или каждые N часов,
//! от имени SYSTEM) или таймером systemd; команда `proxy-scanner-cli scheduled`.
//! Настройки — `proxy-scanner-schedule.json`, история — папка `proxy-scanner-history`
//! рядом с программой.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::Sink;

pub const NAME: &str = "proxy-scanner-playbook";
pub const CONFIG_FILE: &str = "proxy-scanner-schedule.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Every {
    Day,
    Week,
    Hours,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Имя сценария (встроенного или своего) или путь к файлу JSON.
    pub playbook: String,
    pub every: Every,
    /// Час запуска (для «каждый день» и «каждую неделю»).
    pub hour: u8,
    /// День недели: 1 — понедельник … 7 — воскресенье.
    pub weekday: u8,
    /// Интервал для «каждые N часов».
    pub hours: u32,
    /// Подсеть для `{subnet}` (пусто — определить автоматически).
    pub subnet: String,
    pub alerts: super::notify::Alerts,
    /// Сколько прогонов хранить в истории.
    pub keep: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            playbook: String::new(),
            every: Every::Week,
            hour: 7,
            weekday: 1,
            hours: 6,
            subnet: String::new(),
            alerts: Default::default(),
            keep: 30,
        }
    }
}

impl Config {
    pub fn describe(&self) -> String {
        const DAYS: [&str; 7] = ["понедельник", "вторник", "среду", "четверг", "пятницу", "субботу", "воскресенье"];
        match self.every {
            Every::Day => format!("каждый день в {:02}:00", self.hour),
            Every::Week => format!("каждую {} в {:02}:00", DAYS[(self.weekday.clamp(1, 7) - 1) as usize], self.hour),
            Every::Hours => format!("каждые {} ч", self.hours.max(1)),
        }
    }
}

fn exe_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default()
}

pub fn config_path() -> PathBuf {
    exe_dir().join(CONFIG_FILE)
}

pub fn history_dir() -> PathBuf {
    exe_dir().join("proxy-scanner-history")
}

pub fn load_config(path: &Path) -> Result<Config, String> {
    let t = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn find_playbook(name: &str) -> Result<crate::playbook::Playbook, String> {
    let p = Path::new(name);
    if p.is_file() {
        let t = std::fs::read_to_string(p).map_err(|e| format!("{name}: {e}"))?;
        return serde_json::from_str(&t).map_err(|e| format!("{name}: {e}"));
    }
    crate::playbook::builtin()
        .into_iter()
        .chain(crate::playbook::load_user().into_iter().map(|x| x.1))
        .find(|b| b.name.eq_ignore_ascii_case(name.trim()))
        .ok_or_else(|| format!("сценарий «{name}» не найден"))
}

/// Последний сохранённый прогон в истории (кроме `except`).
fn previous(dir: &Path, except: &Path) -> Option<crate::session::Session> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json") && p != except)
        .collect();
    files.sort();
    files.last().and_then(|p| crate::session::load(p).ok())
}

fn prune(dir: &Path, keep: usize) {
    for ext in ["json", "html"] {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == ext)).collect())
            .unwrap_or_default();
        files.sort();
        while files.len() > keep.max(1) {
            let _ = std::fs::remove_file(files.remove(0));
        }
    }
}

/// HTML-блок «Что изменилось с прошлого прогона».
pub fn diff_html(d: &super::compare::Diff) -> String {
    use crate::report::esc;
    let mut h = String::from("<section style=\"margin:16px 0;padding:12px 16px;border:2px solid #d9822b;border-radius:8px\">");
    if d.changes.is_empty() {
        h += &format!("<h2>С прошлого прогона ({}) изменений нет</h2>", esc(&d.old_label));
    } else {
        h += &format!("<h2>Что изменилось с прошлого прогона ({}) — {}</h2><table><tr><th>Раздел</th><th>Что</th><th></th><th>Было</th><th>Стало</th></tr>", esc(&d.old_label), d.changes.len());
        for c in d.changes.iter().take(300) {
            h += &format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&c.category),
                esc(&c.key),
                c.kind.label(),
                esc(&c.before),
                esc(&c.after)
            );
        }
        h += "</table>";
    }
    h + "</section>"
}

/// Вставить блок сразу после открывающего тега `<body>`.
pub fn inject(report: &str, block: &str) -> String {
    match report.find("<body") {
        Some(i) => match report[i..].find('>') {
            Some(j) => format!("{}{}{}", &report[..i + j + 1], block, &report[i + j + 1..]),
            None => format!("{block}{report}"),
        },
        None => format!("{block}{report}"),
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Done(String),
}

/// Один прогон: сценарий → история → сравнение → отчёт → почта.
pub async fn run_once(cfg: Config, store: crate::presets::Store, sink: Sink<Event>, cancel: CancellationToken) {
    let pb = match find_playbook(&cfg.playbook) {
        Ok(p) => p,
        Err(e) => return sink.send(Event::Done(format!("ошибка: {e}"))),
    };
    let subnet = if cfg.subnet.trim().is_empty() {
        tokio::task::spawn_blocking(crate::netdetect::detect_local_cidr).await.ok().flatten()
    } else {
        Some(cfg.subnet.trim().to_string())
    };
    let (psink, rx) = Sink::new(None);
    let name = pb.name.clone();
    let steps: Vec<String> = pb.steps.iter().map(|s| s.label()).collect();
    crate::playbook::execute(pb, store, subnet, psink, cancel.clone()).await;
    let mut results = None;
    for e in rx.try_iter() {
        match e {
            crate::playbook::Event::Done(i, t) => {
                sink.send(Event::Log(format!("{}. {}: {t}", i + 1, steps.get(i).cloned().unwrap_or_default())));
            }
            crate::playbook::Event::Finished(r) => results = Some(*r),
            crate::playbook::Event::Log(l) => sink.send(Event::Log(l)),
            crate::playbook::Event::Step(..) => {}
        }
    }
    let Some(r) = results else {
        return sink.send(Event::Done("сценарий прерван".into()));
    };
    let mut session = crate::session::Session::new(&crate::model::Settings::default(), None, Vec::new());
    session.tools = r;
    let dir = history_dir();
    let _ = std::fs::create_dir_all(&dir);
    let stamp = format!(
        "{}-{:02}",
        crate::session::format_time(session.saved_at).replace([' ', ':'], "-").replace("-UTC", ""),
        session.saved_at % 60
    );
    let json = dir.join(format!("{stamp}.json"));
    if let Err(e) = crate::session::save(&json, &session) {
        sink.send(Event::Log(format!("история: {e}")));
    }
    let prev = previous(&dir, &json);
    let mut report = crate::report::html(&session, &format!("{name} — {}", crate::session::format_time(session.saved_at)));
    let mut changes = 0;
    if let Some(old) = &prev {
        let d = super::compare::diff(old, &session);
        changes = d.changes.len();
        report = inject(&report, &diff_html(&d));
    }
    let html_path = dir.join(format!("{stamp}.html"));
    let _ = std::fs::write(&html_path, &report);
    prune(&dir, cfg.keep);
    let mut done = format!(
        "«{name}» выполнен; {}; отчёт: {}",
        if prev.is_some() { format!("изменений с прошлого прогона: {changes}") } else { "первый прогон — сравнивать не с чем".into() },
        html_path.display()
    );
    if !cfg.alerts.smtp.trim().is_empty() {
        let subject = format!(
            "[Proxy Scanner] {name}: {}",
            if prev.is_some() { format!("изменений {changes}") } else { "первый отчёт".into() }
        );
        match super::notify::send_html_mail(&cfg.alerts, &subject, &report).await {
            Ok(()) => done += "; отправлен на почту",
            Err(e) => done += &format!("; почта: {e}"),
        }
    }
    if !cfg.alerts.log_file.trim().is_empty() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(cfg.alerts.log_file.trim()) {
            let _ = writeln!(f, "{} {done}", crate::session::format_time(crate::session::now_unix()));
        }
    }
    sink.send(Event::Done(done));
}

// ---------------------------------------------------------------------------
// Установка расписания
// ---------------------------------------------------------------------------

fn args(cli: &Path, config: &Path) -> (String, Vec<String>) {
    let mut a = Vec::new();
    if !cli.file_name().is_some_and(|n| n.to_string_lossy().contains("-cli")) {
        a.push("--cli".to_string());
    }
    a.extend(["scheduled".to_string(), "--config".to_string(), config.display().to_string(), "-q".to_string()]);
    (cli.display().to_string(), a)
}

/// Таймер systemd: OnCalendar для выбранного расписания.
pub fn on_calendar(cfg: &Config) -> String {
    const D: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    match cfg.every {
        Every::Day => format!("*-*-* {:02}:00:00", cfg.hour.min(23)),
        Every::Week => format!("{} *-*-* {:02}:00:00", D[(cfg.weekday.clamp(1, 7) - 1) as usize], cfg.hour.min(23)),
        Every::Hours => format!("*-*-* 00/{}:00:00", cfg.hours.clamp(1, 23)),
    }
}

pub fn systemd_units(cfg: &Config, cli: &Path, config: &Path) -> (String, String) {
    let (prog, a) = args(cli, config);
    let quoted: Vec<String> = std::iter::once(prog).chain(a).map(|x| format!("\"{}\"", x.replace('"', "\\\""))).collect();
    let service = format!(
        "[Unit]\nDescription=Proxy Scanner: сценарий по расписанию\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart={}\n",
        quoted.join(" ")
    );
    let timer = format!(
        "[Unit]\nDescription=Proxy Scanner: расписание сценария ({})\n\n[Timer]\nOnCalendar={}\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        cfg.describe(),
        on_calendar(cfg)
    );
    (service, timer)
}

pub fn task_xml(cfg: &Config, cli: &Path, config: &Path) -> String {
    let (prog, a) = args(cli, config);
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let a: Vec<String> = a.iter().map(|x| if x.contains(' ') { format!("\"{x}\"") } else { x.clone() }).collect();
    let start = format!("2024-01-01T{:02}:00:00", cfg.hour.min(23));
    const D: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    let trigger = match cfg.every {
        Every::Day => format!("<CalendarTrigger><StartBoundary>{start}</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>"),
        Every::Week => format!(
            "<CalendarTrigger><StartBoundary>{start}</StartBoundary><Enabled>true</Enabled><ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><{d} /></DaysOfWeek></ScheduleByWeek></CalendarTrigger>",
            d = D[(cfg.weekday.clamp(1, 7) - 1) as usize]
        ),
        Every::Hours => format!(
            "<TimeTrigger><StartBoundary>2024-01-01T00:00:00</StartBoundary><Enabled>true</Enabled><Repetition><Interval>PT{}H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>",
            cfg.hours.clamp(1, 168)
        ),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Proxy Scanner: сценарий по расписанию ({})</Description></RegistrationInfo>
  <Triggers>{trigger}</Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT12H</ExecutionTimeLimit>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>
</Task>
"#,
        esc(&cfg.describe()),
        esc(&prog),
        esc(&a.join(" "))
    )
}

fn sh(program: &str, a: &[&str]) -> Result<String, String> {
    let o = crate::util::run_cmd_status(program, a)?;
    if !o.1 {
        return Err(format!("{program} {}: {}", a.first().unwrap_or(&""), o.0.combined().trim()));
    }
    Ok(o.0.combined())
}

pub fn install(cfg: &Config) -> Result<String, String> {
    find_playbook(&cfg.playbook)?;
    if !crate::util::is_admin() {
        return Err(if cfg!(windows) { "нужны права администратора".into() } else { "нужны права root (sudo)".into() });
    }
    let config = config_path();
    std::fs::write(&config, serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?).map_err(|e| format!("{}: {e}", config.display()))?;
    let cli = super::service::cli_path();
    if cfg!(windows) {
        let xml_path = std::env::temp_dir().join(format!("{NAME}.xml"));
        let mut bytes = vec![0xFF, 0xFE];
        for u in task_xml(cfg, &cli, &config).encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(&xml_path, bytes).map_err(|e| e.to_string())?;
        sh("schtasks.exe", &["/Create", "/TN", NAME, "/XML", &xml_path.display().to_string(), "/F"])?;
        let _ = std::fs::remove_file(&xml_path);
    } else {
        let (service, timer) = systemd_units(cfg, &cli, &config);
        for (path, text) in [(format!("/etc/systemd/system/{NAME}.service"), service), (format!("/etc/systemd/system/{NAME}.timer"), timer)] {
            std::fs::write(&path, text).map_err(|e| format!("{path}: {e}"))?;
        }
        sh("systemctl", &["daemon-reload"])?;
        sh("systemctl", &["enable", "--now", &format!("{NAME}.timer")])?;
    }
    Ok(format!("«{}» — {}; отчёты: {}", cfg.playbook, cfg.describe(), history_dir().display()))
}

pub fn uninstall() -> Result<String, String> {
    if cfg!(windows) {
        sh("schtasks.exe", &["/Delete", "/TN", NAME, "/F"])?;
    } else {
        let _ = sh("systemctl", &["disable", "--now", &format!("{NAME}.timer")]);
        for ext in ["timer", "service"] {
            let _ = std::fs::remove_file(format!("/etc/systemd/system/{NAME}.{ext}"));
        }
        let _ = sh("systemctl", &["daemon-reload"]);
    }
    Ok("расписание удалено".into())
}

pub fn status() -> String {
    let installed = if cfg!(windows) {
        matches!(crate::util::run_cmd_status("schtasks.exe", &["/Query", "/TN", NAME]), Ok((_, true)))
    } else {
        Path::new(&format!("/etc/systemd/system/{NAME}.timer")).is_file()
    };
    if !installed {
        return "расписание не установлено".into();
    }
    match load_config(&config_path()) {
        Ok(c) => format!("установлено: «{}» {}", c.playbook, c.describe()),
        Err(_) => "установлено".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules() {
        let mut c = Config { playbook: "x".into(), ..Default::default() };
        assert_eq!(on_calendar(&c), "Mon *-*-* 07:00:00");
        c.every = Every::Hours;
        c.hours = 6;
        assert_eq!(on_calendar(&c), "*-*-* 00/6:00:00");
        assert!(task_xml(&c, Path::new("C:\\ps\\proxy-scanner-cli.exe"), Path::new("C:\\ps\\s.json")).contains("PT6H"));
        c.every = Every::Week;
        c.weekday = 5;
        assert!(task_xml(&c, Path::new("cli"), Path::new("s.json")).contains("<Friday />"));
        assert_eq!(c.describe(), "каждую пятницу в 07:00");
    }

    #[test]
    fn inject_after_body() {
        assert_eq!(inject("<html><body class=\"x\"><p>a</p>", "<b>!</b>"), "<html><body class=\"x\"><b>!</b><p>a</p>");
    }
}
