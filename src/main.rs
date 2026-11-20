//! Proxy Scanner — инвентаризация и диагностика прокси-серверов в корпоративной сети.
//!
//! Предназначен для сетевых администраторов: поиск прокси-шлюзов в собственной
//! инфраструктуре, проверка их конфигурации, политик доступа и SSL-инспекции.

// В релизной сборке не открываем окно консоли.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use proxy_scanner::{app, cli};

use eframe::Renderer;

fn run(renderer: Renderer) -> eframe::Result {
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Proxy Scanner — инвентаризация прокси-серверов")
            .with_inner_size([1360.0, 800.0])
            .with_min_inner_size([480.0, 360.0]),
        renderer,
        ..Default::default()
    };
    // Экономичная (встроенная) видеокарта: запрос «высокопроизводительной» на ноутбуках
    // и ПК с двумя видеокартами переключает вывод между ними — монитор гаснет и мигает.
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(c) = &mut options.wgpu_options.wgpu_setup {
        c.power_preference = eframe::wgpu::PowerPreference::LowPower;
    }
    eframe::run_native(
        "proxy-scanner",
        options,
        Box::new(|cc| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("proxy-scanner-worker")
                .build()?;
            Ok(Box::new(app::App::new(cc, rt)))
        }),
    )
}

fn main() {
    // Подкоманды (`proxy-scanner dns example.com`, `proxy-scanner mtr 10.0.0.1` …)
    // выполняются без окна.
    if let Some(code) = cli::dispatch_from_gui_binary() {
        std::process::exit(code);
    }
    // Порядок графических бэкендов: по умолчанию wgpu (DirectX 12 / Vulkan),
    // при неудаче — OpenGL. Можно задать явно: `--renderer glow` или `--renderer wgpu`.
    let args: Vec<String> = std::env::args().collect();
    let forced = args
        .iter()
        .position(|a| a == "--renderer")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.to_ascii_lowercase());
    // Выбор из меню «Вид → Графика» (сохраняется рядом с файлом сессии).
    let forced = forced.or_else(app::saved_renderer);
    let order: Vec<Renderer> = match forced.as_deref() {
        Some("glow") | Some("opengl") => vec![Renderer::Glow],
        Some("wgpu") => vec![Renderer::Wgpu],
        _ => vec![Renderer::Wgpu, Renderer::Glow],
    };

    let mut last_error = String::new();
    for renderer in order {
        match run(renderer) {
            Ok(()) => return,
            Err(e) => last_error = format!("{renderer:?}: {e}"),
        }
    }
    fatal(&format!(
        "Не удалось инициализировать графическую подсистему.\n{last_error}"
    ));
}

/// Сообщение о фатальной ошибке (в релизной сборке консоли нет — показываем окно).
fn fatal(msg: &str) -> ! {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        let wide = |s: &str| -> Vec<u16> {
            std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
        };
        let (text, title) = (wide(msg), wide("Proxy Scanner"));
        // SAFETY: обе строки — корректные UTF-16 с завершающим нулём.
        unsafe {
            MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
        }
    }
    eprintln!("{msg}");
    std::process::exit(1);
}
