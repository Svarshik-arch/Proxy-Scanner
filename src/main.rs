//! Proxy Scanner — инвентаризация и диагностика прокси-серверов в корпоративной сети.
//!
//! Предназначен для сетевых администраторов: поиск прокси-шлюзов в собственной
//! инфраструктуре, проверка их конфигурации, политик доступа и SSL-инспекции.

// В релизной сборке не открываем окно консоли.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use proxy_scanner::{app, cli, nvidia};

use eframe::Renderer;

fn run(renderer: Renderer, backends: Option<eframe::wgpu::Backends>) -> eframe::Result {
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Proxy Scanner — инвентаризация прокси-серверов")
            .with_inner_size([1360.0, 800.0])
            .with_min_inner_size([480.0, 360.0]),
        renderer,
        ..Default::default()
    };
    // Строго по обновлению экрана: вместе с ровной отрисовкой активного окна
    // (см. App::logic) частота кадров постоянна и адаптивная синхронизация не скачет.
    options.wgpu_options.surface.present_mode = eframe::wgpu::PresentMode::Fifo;
    options.glow_options.vsync = true;
    // Экономичная (встроенная) видеокарта: запрос «высокопроизводительной» на ноутбуках
    // и ПК с двумя видеокартами переключает вывод между ними — монитор гаснет и мигает.
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(c) = &mut options.wgpu_options.wgpu_setup {
        c.power_preference = eframe::wgpu::PowerPreference::LowPower;
        if let Some(b) = backends {
            c.instance_descriptor.backends = b;
        }
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
    // Запуск с правами администратора только для настройки профиля NVIDIA.
    if std::env::args().any(|a| a == nvidia::FIX_ARG) {
        let ok = !matches!(nvidia::ensure_fixed_refresh(), nvidia::Outcome::Failed(_));
        std::process::exit(if ok { 0 } else { 1 });
    }
    // До создания окна: драйвер NVIDIA читает профиль программы при первом
    // обращении к видеокарте.
    let _ = nvidia::STATUS.set(nvidia::prepare());
    // Порядок графических бэкендов: по умолчанию wgpu (в Windows — DirectX 12),
    // при неудаче — OpenGL. Можно задать явно: `--renderer glow|dx12|vulkan|wgpu`.
    let args: Vec<String> = std::env::args().collect();
    let forced = args
        .iter()
        .position(|a| a == "--renderer")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.to_ascii_lowercase());
    // Выбор из меню «Вид → Графика» (сохраняется рядом с файлом сессии).
    let forced = forced.or_else(app::saved_renderer);
    use eframe::wgpu::Backends;
    // В Windows по умолчанию — DirectX 12: так выводят изображение обычные программы
    // Windows. Vulkan в окне на NVIDIA по DisplayPort вызывает мигание монитора.
    let auto = if cfg!(windows) { Some(Backends::DX12) } else { None };
    let order: Vec<(Renderer, Option<Backends>)> = match forced.as_deref() {
        Some("glow") | Some("opengl") => vec![(Renderer::Glow, None)],
        Some("dx12") => vec![(Renderer::Wgpu, Some(Backends::DX12)), (Renderer::Glow, None)],
        Some("vulkan") => vec![(Renderer::Wgpu, Some(Backends::VULKAN))],
        Some("wgpu") => vec![(Renderer::Wgpu, None)],
        _ => vec![(Renderer::Wgpu, auto), (Renderer::Glow, None)],
    };

    let mut last_error = String::new();
    for (renderer, backends) in order {
        match run(renderer, backends) {
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
