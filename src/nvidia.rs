//! Профиль программы в настройках драйвера NVIDIA: адаптивная частота (G-SYNC /
//! G-SYNC Compatible) выключена.
//!
//! Окно программы рисует кадры только при изменениях. С включённой адаптивной
//! частотой монитор подстраивается под такой «рваный» поток кадров, а многие
//! мониторы с узким диапазоном (например, 48–75 Гц) при этом теряют сигнал —
//! экран гаснет при движении мыши. Для браузеров и офисных программ драйвер
//! выключает адаптивную частоту своими профилями; здесь делаем то же самое для
//! себя — как «Технология монитора: фиксированная частота» в панели NVIDIA для
//! одной программы. Остальные программы и игры не затрагиваются.
//!
//! Работа с драйвером — через NvAPI (`nvapi64.dll`, функции по идентификаторам
//! из `nvapi_QueryInterface`). Нет драйвера NVIDIA — ничего не делаем.

/// Строка для журнала: что сделано при запуске.
pub static STATUS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Итог настройки (для журнала).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Видеокарты NVIDIA нет (нет nvapi64.dll).
    NoNvidia,
    /// Профиль уже настроен.
    AlreadySet,
    /// Профиль создан или исправлен — подействует при следующем запуске.
    Applied,
    /// Не удалось (код ошибки NvAPI и шаг).
    Failed(String),
}

impl Outcome {
    pub fn describe(&self) -> String {
        match self {
            Outcome::NoNvidia => "NVIDIA: видеокарты нет — профиль не нужен".into(),
            Outcome::AlreadySet => "NVIDIA: адаптивная частота (G-SYNC) для программы выключена".into(),
            Outcome::Applied => "NVIDIA: создан профиль программы без адаптивной частоты (G-SYNC)".into(),
            Outcome::Failed(e) => format!("NVIDIA: не удалось настроить профиль программы: {e}"),
        }
    }
}

#[cfg(not(windows))]
pub fn ensure_fixed_refresh() -> Outcome {
    Outcome::NoNvidia
}

#[cfg(windows)]
pub fn ensure_fixed_refresh() -> Outcome {
    match imp::run() {
        Ok(o) => o,
        Err(e) => Outcome::Failed(e),
    }
}

/// Аргумент командной строки: только настроить профиль (запускается с правами
/// администратора, если обычных прав не хватило) и выйти.
pub const FIX_ARG: &str = "--nvidia-fixed-refresh";

/// Повторить настройку с правами администратора (окно UAC) и дождаться её.
#[cfg(windows)]
pub fn run_elevated() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    let verb = wide("runas".as_ref());
    let file = wide(exe.as_os_str());
    let args = wide(FIX_ARG.as_ref());
    // SAFETY: структура обнулена и заполнена по документации; строки живут до конца вызова.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = args.as_ptr();
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 {
            return Err("запрос прав администратора отклонён".into());
        }
        if !info.hProcess.is_null() {
            WaitForSingleObject(info.hProcess, 60_000);
            CloseHandle(info.hProcess);
        }
    }
    Ok(())
}

/// Настроить профиль перед созданием окна (драйвер читает профиль, когда программа
/// впервые обращается к видеокарте). Если обычных прав не хватает — один раз
/// спрашиваем права администратора. Возвращает строку для журнала.
pub fn prepare() -> String {
    // Права администратора спрашиваем не больше одного раза.
    let marker = crate::session::default_path().with_file_name("proxy-scanner-nvidia.txt");
    if marker.is_file() {
        let first = ensure_fixed_refresh();
        return match first {
            Outcome::Failed(e) if needs_admin(&e) => {
                "NVIDIA: профиль программы не настроен — нужны права администратора \
                 (Вид → Графика → «Выключить G-SYNC для программы»)"
                    .into()
            }
            o => o.describe(),
        };
    }
    let _ = std::fs::write(&marker, "1");
    let first = ensure_fixed_refresh();
    #[cfg(windows)]
    if let Outcome::Failed(e) = &first
        && needs_admin(e)
    {
        return match run_elevated() {
            Ok(()) => ensure_fixed_refresh().describe(),
            Err(err) => format!("{} ({err})", first.describe()),
        };
    }
    first.describe()
}

#[cfg(windows)]
mod imp {
    use super::Outcome;
    use std::ffi::c_void;

    type QueryInterface = unsafe extern "C" fn(u32) -> *mut c_void;
    type FnInit = unsafe extern "C" fn() -> i32;
    type FnSession = unsafe extern "C" fn(*mut *mut c_void) -> i32;
    type FnHandle = unsafe extern "C" fn(*mut c_void) -> i32;
    type FnFindApp = unsafe extern "C" fn(*mut c_void, *const u16, *mut *mut c_void, *mut u8) -> i32;
    type FnFindProfile = unsafe extern "C" fn(*mut c_void, *const u16, *mut *mut c_void) -> i32;
    type FnCreateProfile = unsafe extern "C" fn(*mut c_void, *mut u8, *mut *mut c_void) -> i32;
    type FnCreateApp = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut u8) -> i32;
    type FnSetting = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut u8) -> i32;
    type FnGetSetting = unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut u8) -> i32;

    // Идентификаторы функций NvAPI.
    const ID_INITIALIZE: u32 = 0x0150_E828;
    const ID_CREATE_SESSION: u32 = 0x0694_D52E;
    const ID_DESTROY_SESSION: u32 = 0xDAD9_CFF8;
    const ID_LOAD_SETTINGS: u32 = 0x375D_BD6B;
    const ID_SAVE_SETTINGS: u32 = 0xFCBC_7E14;
    const ID_FIND_APPLICATION: u32 = 0xEEE5_66B2;
    const ID_FIND_PROFILE: u32 = 0x7E4A_9A0B;
    const ID_CREATE_PROFILE: u32 = 0xCC17_6068;
    const ID_CREATE_APPLICATION: u32 = 0x4347_A9DE;
    const ID_SET_SETTING: u32 = 0x577D_D202;
    const ID_GET_SETTING: u32 = 0x73BF_8338;

    // Параметры драйвера.
    /// «G-SYNC: режим для приложения»: 0 — выключен.
    const VRR_MODE: u32 = 0x1194_F158;
    /// «G-SYNC: состояние для приложения»: 1 — принудительно выключен.
    const VRR_APP_OVERRIDE: u32 = 0x10A8_79CF;
    const WANT: [(u32, u32); 2] = [(VRR_MODE, 0), (VRR_APP_OVERRIDE, 1)];

    const OK: i32 = 0;
    const NOT_FOUND: [i32; 2] = [-163, -166]; // PROFILE_NOT_FOUND, EXECUTABLE_NOT_FOUND
    const INCOMPATIBLE_VERSION: i32 = -9;
    const INVALID_USER_PRIVILEGE: i32 = -137;

    const STR: usize = 2048; // NvAPI_UnicodeString — u16[2048]
    const SETTING_SIZE: usize = 12320; // NVDRS_SETTING_V1
    const PROFILE_SIZE: usize = 4116; // NVDRS_PROFILE_V1
    /// NVDRS_APPLICATION V4…V1: (размер, версия).
    const APP_VERSIONS: [(usize, u32); 4] = [(20492, 4), (16396, 3), (16392, 2), (12296, 1)];

    fn ver(size: usize, v: u32) -> u32 {
        size as u32 | (v << 16)
    }

    fn put_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn get_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    fn put_str(buf: &mut [u8], off: usize, s: &str) {
        for (i, c) in s.encode_utf16().take(STR - 1).enumerate() {
            buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().take(STR - 1).collect();
        v.resize(STR, 0);
        v
    }

    struct Api {
        _lib: libloading::Library,
        q: QueryInterface,
    }

    impl Api {
        fn get<T: Copy>(&self, id: u32, name: &str) -> Result<T, String> {
            // SAFETY: nvapi_QueryInterface возвращает адрес функции или null.
            let p = unsafe { (self.q)(id) };
            if p.is_null() {
                return Err(format!("нет функции {name}"));
            }
            // SAFETY: T — указатель на функцию с сигнатурой из nvapi.h.
            Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&p) })
        }
    }

    struct Session<'a> {
        api: &'a Api,
        h: *mut c_void,
    }

    impl Drop for Session<'_> {
        fn drop(&mut self) {
            if let Ok(f) = self.api.get::<FnHandle>(ID_DESTROY_SESSION, "DestroySession") {
                // SAFETY: сессия создана CreateSession.
                unsafe { f(self.h) };
            }
        }
    }

    fn check(step: &str, r: i32) -> Result<(), String> {
        if r == OK {
            Ok(())
        } else if r == INVALID_USER_PRIVILEGE {
            Err(format!("{step}: нужны права администратора (код {r})"))
        } else {
            Err(format!("{step}: код {r}"))
        }
    }

    pub fn needs_admin(e: &str) -> bool {
        e.contains("права администратора")
    }

    fn exe_name() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()))
            .unwrap_or_else(|| "proxy-scanner.exe".into())
    }

    pub fn run() -> Result<Outcome, String> {
        // SAFETY: загрузка системной библиотеки драйвера.
        let lib = match unsafe { libloading::Library::new("nvapi64.dll") } {
            Ok(l) => l,
            Err(_) => return Ok(Outcome::NoNvidia),
        };
        // SAFETY: экспортируемая функция nvapi_QueryInterface(u32) -> void*.
        let q: QueryInterface = match unsafe { lib.get::<QueryInterface>(b"nvapi_QueryInterface\0") } {
            Ok(f) => *f,
            Err(_) => return Ok(Outcome::NoNvidia),
        };
        let api = Api { _lib: lib, q };
        // SAFETY: вызовы NvAPI с буферами нужного размера и версии.
        unsafe {
            check("Initialize", api.get::<FnInit>(ID_INITIALIZE, "Initialize")?())?;
            let mut h = std::ptr::null_mut();
            check("CreateSession", api.get::<FnSession>(ID_CREATE_SESSION, "CreateSession")?(&mut h))?;
            let s = Session { api: &api, h };
            check("LoadSettings", api.get::<FnHandle>(ID_LOAD_SETTINGS, "LoadSettings")?(s.h))?;

            let exe = exe_name();
            let profile = find_or_create_profile(&api, s.h, &exe)?;

            let get = api.get::<FnGetSetting>(ID_GET_SETTING, "GetSetting")?;
            let set = api.get::<FnSetting>(ID_SET_SETTING, "SetSetting")?;
            let mut changed = false;
            for (id, value) in WANT {
                let mut buf = vec![0u8; SETTING_SIZE];
                put_u32(&mut buf, 0, ver(SETTING_SIZE, 1));
                let r = get(s.h, profile, id, buf.as_mut_ptr());
                // Значение задано в профиле самой программы (settingLocation = 0) и совпадает.
                if r == OK && get_u32(&buf, 4108) == 0 && get_u32(&buf, 8220) == value {
                    continue;
                }
                let mut buf = vec![0u8; SETTING_SIZE];
                put_u32(&mut buf, 0, ver(SETTING_SIZE, 1));
                put_u32(&mut buf, 4100, id); // settingId
                put_u32(&mut buf, 4104, 0); // NVDRS_DWORD_TYPE
                put_u32(&mut buf, 8220, value); // currentValue.u32CurrentValue
                check("SetSetting", set(s.h, profile, buf.as_mut_ptr()))?;
                changed = true;
            }
            if !changed {
                return Ok(Outcome::AlreadySet);
            }
            check("SaveSettings", api.get::<FnHandle>(ID_SAVE_SETTINGS, "SaveSettings")?(s.h))?;
            Ok(Outcome::Applied)
        }
    }

    /// Профиль, к которому привязан исполняемый файл программы; если его нет —
    /// создаётся профиль «Proxy Scanner» с этим файлом.
    unsafe fn find_or_create_profile(api: &Api, h: *mut c_void, exe: &str) -> Result<*mut c_void, String> {
        let find_app = api.get::<FnFindApp>(ID_FIND_APPLICATION, "FindApplicationByName")?;
        let name = wide(exe);
        // Подбираем версию структуры, которую понимает установленный драйвер.
        let mut app_ver = None;
        for (size, v) in APP_VERSIONS {
            let mut app = vec![0u8; size];
            put_u32(&mut app, 0, ver(size, v));
            let mut profile = std::ptr::null_mut();
            // SAFETY: буфер нужного размера, строка — u16[2048].
            let r = unsafe { find_app(h, name.as_ptr(), &mut profile, app.as_mut_ptr()) };
            if r == INCOMPATIBLE_VERSION {
                continue;
            }
            if r == OK && !profile.is_null() {
                return Ok(profile);
            }
            if !NOT_FOUND.contains(&r) {
                check("FindApplicationByName", r)?;
            }
            app_ver = Some((size, v));
            break;
        }
        let (app_size, app_v) = app_ver.ok_or("FindApplicationByName: неизвестная версия драйвера")?;

        const PROFILE_NAME: &str = "Proxy Scanner";
        let mut profile = std::ptr::null_mut();
        let find_profile = api.get::<FnFindProfile>(ID_FIND_PROFILE, "FindProfileByName")?;
        let pname = wide(PROFILE_NAME);
        // SAFETY: строка — u16[2048].
        let r = unsafe { find_profile(h, pname.as_ptr(), &mut profile) };
        if r != OK || profile.is_null() {
            if !NOT_FOUND.contains(&r) {
                check("FindProfileByName", r)?;
            }
            let mut p = vec![0u8; PROFILE_SIZE];
            put_u32(&mut p, 0, ver(PROFILE_SIZE, 1));
            put_str(&mut p, 4, PROFILE_NAME);
            put_u32(&mut p, 4100, 0b111); // GeForce, Quadro, NVS
            let create = api.get::<FnCreateProfile>(ID_CREATE_PROFILE, "CreateProfile")?;
            // SAFETY: буфер NVDRS_PROFILE_V1.
            check("CreateProfile", unsafe { create(h, p.as_mut_ptr(), &mut profile) })?;
        }
        let mut app = vec![0u8; app_size];
        put_u32(&mut app, 0, ver(app_size, app_v));
        put_str(&mut app, 8, exe); // appName
        put_str(&mut app, 8 + STR * 2, "Proxy Scanner"); // userFriendlyName
        let create_app = api.get::<FnCreateApp>(ID_CREATE_APPLICATION, "CreateApplication")?;
        // SAFETY: буфер NVDRS_APPLICATION нужной версии.
        check("CreateApplication", unsafe { create_app(h, profile, app.as_mut_ptr()) })?;
        Ok(profile)
    }
}

#[cfg(windows)]
pub use imp::needs_admin;

#[cfg(not(windows))]
pub fn needs_admin(_e: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    // Раскладка структур NvAPI (nvapi.h) — проверка размеров и смещений, которые
    // используются при заполнении буферов.
    #[repr(C)]
    struct Binary {
        len: u32,
        data: [u8; 4096],
    }
    #[repr(C)]
    union Value {
        u: u32,
        bin: std::mem::ManuallyDrop<Binary>,
        wstr: [u16; 2048],
    }
    #[repr(C)]
    struct Setting {
        version: u32,
        name: [u16; 2048],
        id: u32,
        kind: u32,
        location: u32,
        is_current_predefined: u32,
        is_predefined_valid: u32,
        predefined: Value,
        current: Value,
    }
    #[repr(C)]
    struct Profile {
        version: u32,
        name: [u16; 2048],
        gpu_support: u32,
        is_predefined: u32,
        num_apps: u32,
        num_settings: u32,
    }
    #[repr(C)]
    struct AppV4 {
        version: u32,
        is_predefined: u32,
        app_name: [u16; 2048],
        friendly: [u16; 2048],
        launcher: [u16; 2048],
        file_in_folder: [u16; 2048],
        flags: u32,
        command_line: [u16; 2048],
    }

    #[test]
    fn layouts() {
        assert_eq!(std::mem::size_of::<Setting>(), 12320);
        assert_eq!(std::mem::offset_of!(Setting, id), 4100);
        assert_eq!(std::mem::offset_of!(Setting, kind), 4104);
        assert_eq!(std::mem::offset_of!(Setting, location), 4108);
        assert_eq!(std::mem::offset_of!(Setting, current), 8220);
        assert_eq!(std::mem::size_of::<Profile>(), 4116);
        assert_eq!(std::mem::offset_of!(Profile, gpu_support), 4100);
        assert_eq!(std::mem::size_of::<AppV4>(), 20492);
        assert_eq!(std::mem::offset_of!(AppV4, app_name), 8);
        assert_eq!(std::mem::offset_of!(AppV4, friendly), 8 + 4096);
        assert_eq!(std::mem::offset_of!(AppV4, flags), 16392);
    }

    #[test]
    fn no_nvidia_here() {
        if !cfg!(windows) {
            assert_eq!(super::ensure_fixed_refresh(), super::Outcome::NoNvidia);
        }
    }
}
