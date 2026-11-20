//! Мониторинг без окна: запуск при старте системы.
//!
//! * Windows — задание Планировщика (при запуске системы, от имени SYSTEM, с
//!   перезапуском при сбое), выполняет `proxy-scanner-cli monitor --config …`.
//! * Linux — служба systemd `proxy-scanner-monitor.service` (Restart=always).
//!
//! Конфигурация (проверки, период, уведомления) хранится в
//! `proxy-scanner-monitor.json` рядом с программой.

use std::path::{Path, PathBuf};

pub const NAME: &str = "proxy-scanner-monitor";
pub const CONFIG_FILE: &str = "proxy-scanner-monitor.json";

/// Программа для запуска без окна: консольная версия рядом, иначе текущая.
pub fn cli_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("proxy-scanner"));
    let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
    let cli = dir.join(if cfg!(windows) { "proxy-scanner-cli.exe" } else { "proxy-scanner-cli" });
    if cli.is_file() { cli } else { exe }
}

pub fn config_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent().map(|d| d.join(CONFIG_FILE)).unwrap_or_else(|| PathBuf::from(CONFIG_FILE))
}

pub fn save_config(cfg: &super::monitor::Config, path: &Path) -> Result<(), String> {
    let text = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Команда, которую выполняет служба.
pub fn command_line(cli: &Path, config: &Path) -> (String, Vec<String>) {
    let mut args = Vec::new();
    // Основная (оконная) программа принимает команды после `--cli`.
    if !cli.file_name().is_some_and(|n| n.to_string_lossy().contains("-cli")) {
        args.push("--cli".to_string());
    }
    args.extend(["monitor".to_string(), "--config".to_string(), config.display().to_string(), "-q".to_string()]);
    (cli.display().to_string(), args)
}

/// Текст unit-файла systemd.
pub fn systemd_unit(cli: &Path, config: &Path) -> String {
    let (prog, args) = command_line(cli, config);
    let quoted: Vec<String> = std::iter::once(prog).chain(args).map(|a| format!("\"{}\"", a.replace('"', "\\\""))).collect();
    format!(
        "[Unit]\nDescription=Proxy Scanner: мониторинг сети\nAfter=network-online.target\nWants=network-online.target\n\n\
         [Service]\nExecStart={}\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n",
        quoted.join(" ")
    )
}

/// XML задания Планировщика Windows: при запуске системы, SYSTEM, перезапуск при сбое,
/// без ограничения времени работы.
pub fn task_xml(cli: &Path, config: &Path) -> String {
    let (prog, args) = command_line(cli, config);
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let args: Vec<String> = args.iter().map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() }).collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Proxy Scanner: мониторинг сети</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>
</Task>
"#,
        esc(&prog),
        esc(&args.join(" "))
    )
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let o = crate::util::run_cmd_status(program, args)?;
    if !o.1 {
        return Err(format!("{program} {}: {}", args.first().unwrap_or(&""), o.0.combined().trim()));
    }
    Ok(o.0.combined())
}

/// Установка и запуск. Нужны права администратора/root.
pub fn install(cfg: &super::monitor::Config) -> Result<String, String> {
    if super::monitor::parse(&cfg.checks).map(|c| c.is_empty()).unwrap_or(true) {
        return Err("список проверок пуст или содержит ошибки".into());
    }
    if !crate::util::is_admin() {
        return Err(if cfg!(windows) {
            "нужны права администратора: перезапустите программу от имени администратора".into()
        } else {
            "нужны права root: запустите программу через sudo".into()
        });
    }
    let config = config_path();
    save_config(cfg, &config)?;
    let cli = cli_path();
    if cfg!(windows) {
        let xml_path = std::env::temp_dir().join(format!("{NAME}.xml"));
        // Планировщик ждёт UTF-16 с BOM.
        let mut bytes = vec![0xFF, 0xFE];
        for u in task_xml(&cli, &config).encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(&xml_path, bytes).map_err(|e| e.to_string())?;
        let xml = xml_path.display().to_string();
        run("schtasks.exe", &["/Create", "/TN", NAME, "/XML", &xml, "/F"])?;
        let _ = std::fs::remove_file(&xml_path);
        run("schtasks.exe", &["/Run", "/TN", NAME])?;
        Ok(format!("задание «{NAME}» создано и запущено; настройки: {}", config.display()))
    } else {
        let unit = format!("/etc/systemd/system/{NAME}.service");
        std::fs::write(&unit, systemd_unit(&cli, &config)).map_err(|e| format!("{unit}: {e}"))?;
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "--now", NAME])?;
        // Новые настройки при повторной установке.
        let _ = run("systemctl", &["restart", NAME]);
        Ok(format!("служба {NAME} включена и запущена; настройки: {}", config.display()))
    }
}

pub fn uninstall() -> Result<String, String> {
    if cfg!(windows) {
        let _ = run("schtasks.exe", &["/End", "/TN", NAME]);
        run("schtasks.exe", &["/Delete", "/TN", NAME, "/F"])?;
        Ok(format!("задание «{NAME}» удалено"))
    } else {
        let _ = run("systemctl", &["disable", "--now", NAME]);
        let unit = format!("/etc/systemd/system/{NAME}.service");
        std::fs::remove_file(&unit).map_err(|e| format!("{unit}: {e}"))?;
        let _ = run("systemctl", &["daemon-reload"]);
        Ok(format!("служба {NAME} удалена"))
    }
}

/// Состояние: установлено ли и работает ли.
pub fn status() -> String {
    if cfg!(windows) {
        match crate::util::run_cmd_status("schtasks.exe", &["/Query", "/TN", NAME, "/FO", "LIST"]) {
            Ok((o, true)) => {
                let state = o
                    .stdout
                    .lines()
                    .find(|l| l.contains(':') && (l.contains("Status") || l.contains("Состояние")))
                    .map(|l| l.split_once(':').map(|x| x.1.trim().to_string()).unwrap_or_default())
                    .unwrap_or_default();
                format!("установлено{}", if state.is_empty() { String::new() } else { format!(", состояние: {state}") })
            }
            _ => "не установлено".into(),
        }
    } else {
        match crate::util::run_cmd_status("systemctl", &["is-active", NAME]).map(|x| x.0) {
            Ok(o) if Path::new(&format!("/etc/systemd/system/{NAME}.service")).exists() => {
                format!("установлено, {}", o.stdout.trim())
            }
            _ => "не установлено".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_and_task() {
        let cli = Path::new("/opt/ps/proxy-scanner-cli");
        let cfg = Path::new("/opt/ps/proxy-scanner-monitor.json");
        let u = systemd_unit(cli, cfg);
        assert!(u.contains("ExecStart=\"/opt/ps/proxy-scanner-cli\" \"monitor\" \"--config\" \"/opt/ps/proxy-scanner-monitor.json\" \"-q\""));
        assert!(u.contains("Restart=always"));
        let gui = Path::new("C:\\Tools\\Proxy Scanner\\proxy-scanner.exe");
        let x = task_xml(gui, Path::new("C:\\Tools\\Proxy Scanner\\proxy-scanner-monitor.json"));
        assert!(x.contains("<Arguments>--cli monitor --config &quot;C:\\Tools\\Proxy Scanner\\proxy-scanner-monitor.json&quot; -q</Arguments>"), "{x}");
        assert!(x.contains("<UserId>S-1-5-18</UserId>"));
    }
}
