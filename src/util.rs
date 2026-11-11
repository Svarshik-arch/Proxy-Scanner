//! Вспомогательные функции: запуск системных команд без окна консоли,
//! проверка прав администратора, перезапуск с повышением прав.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Скрывает окно консоли у дочернего процесса (актуально только для Windows).
pub fn hide_window(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// То же для `tokio::process::Command`.
pub fn hide_window_tokio(cmd: &mut tokio::process::Command) -> &mut tokio::process::Command {
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    /// stdout и stderr одним текстом.
    pub fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Запуск команды с захватом вывода. Вывод декодируется «с потерями»:
/// IP-адреса, GUID и MAC состоят из ASCII, поэтому кодовая страница консоли не важна.
pub fn run_cmd(program: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Result<CmdOutput, String> {
    let program = program.as_ref();
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_window(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| format!("не удалось запустить {}: {e}", program.to_string_lossy()))?;
    Ok(CmdOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Запуск сценария PowerShell; вывод принудительно в UTF-8.
pub fn run_powershell(script: &str) -> Result<CmdOutput, String> {
    let full = format!(
        "$ErrorActionPreference='SilentlyContinue';\
         $ProgressPreference='SilentlyContinue';\
         [Console]::OutputEncoding=[System.Text.Encoding]::UTF8;{script}"
    );
    run_cmd(
        "powershell.exe",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &full,
        ],
    )
}

/// Запущен ли процесс с правами администратора.
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        // SAFETY: функция без аргументов, не имеет предусловий.
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Перезапуск приложения с запросом повышения прав (UAC).
pub fn relaunch_as_admin() -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let wide = |s: &std::ffi::OsStr| -> Vec<u16> { s.encode_wide().chain(Some(0)).collect() };
        let exe_w = wide(exe.as_os_str());
        let verb_w = wide(std::ffi::OsStr::new("runas"));
        // SAFETY: все указатели указывают на корректные UTF-16 строки с завершающим нулём.
        let rc = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb_w.as_ptr(),
                exe_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if (rc as isize) > 32 {
            Ok(())
        } else {
            Err("повышение прав отклонено или недоступно".into())
        }
    }
    #[cfg(not(windows))]
    {
        Err("доступно только в Windows".into())
    }
}

/// Установлен ли Npcap (или совместимый WinPcap).
pub fn npcap_installed() -> bool {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        [
            "System32\\Npcap\\wpcap.dll",
            "System32\\wpcap.dll",
            "SysWOW64\\Npcap\\wpcap.dll",
        ]
        .iter()
        .any(|p| Path::new(&root).join(p).exists())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Поиск masscan: сначала как указано, затем рядом с исполняемым файлом приложения.
pub fn resolve_masscan(path: &str) -> PathBuf {
    let p = PathBuf::from(path.trim());
    if p.is_absolute() || p.exists() {
        return p;
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(&p);
        if candidate.exists() {
            return candidate;
        }
    }
    p // будет найден через PATH, если он там есть
}

pub fn file_exists(path: &Path) -> bool {
    path.is_file()
}
