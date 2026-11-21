//! Обновление локальных баз через интернет, когда он есть:
//! * производители сетевых карт — реестр IEEE OUI (standards-oui.ieee.org);
//! * известные уязвимости — `data/cve.json` из репозитория проекта;
//! * новая версия программы — последний выпуск на GitHub.
//!
//! Обновлённые базы лежат в папке `proxy-scanner-data` рядом с программой; без неё
//! работают встроенные. Сначала — напрямую, при неудаче — через системный прокси / PAC.
//! В закрытом контуре автообновление выключается.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::tools::Sink;
use crate::tools::http::{self, ProxyMode};

pub const OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";
pub const CVE_URL: &str = "https://raw.githubusercontent.com/Svarshik-arch/Proxy-Scanner/main/data/cve.json";
pub const RELEASE_API: &str = "https://api.github.com/repos/Svarshik-arch/Proxy-Scanner/releases/latest";
pub const RELEASES_PAGE: &str = "https://github.com/Svarshik-arch/Proxy-Scanner/releases/latest";
/// Автопроверка не чаще раза в неделю.
pub const AUTO_EVERY_SECS: u64 = 7 * 86_400;

pub fn data_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_default()
        .join("proxy-scanner-data")
}

/// Номер сборки этой программы (задаётся при сборке в CI).
pub fn current_build() -> Option<u32> {
    option_env!("PS_BUILD").and_then(|s| s.parse().ok())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Meta {
    pub checked_at: u64,
    pub oui_at: u64,
    pub oui_entries: usize,
    pub cve_at: u64,
    pub cve_version: u32,
    pub latest_build: Option<u32>,
    pub latest_tag: String,
}

pub fn load_meta() -> Meta {
    std::fs::read_to_string(data_dir().join("meta.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_meta(m: &Meta) {
    let _ = std::fs::create_dir_all(data_dir());
    let _ = std::fs::write(data_dir().join("meta.json"), serde_json::to_string_pretty(m).unwrap_or_default());
}

/// Пора ли проверять автоматически.
pub fn due() -> bool {
    crate::session::now_unix().saturating_sub(load_meta().checked_at) >= AUTO_EVERY_SECS
}

/// Есть ли более новая сборка (по последней проверке).
pub fn newer_build() -> Option<u32> {
    let m = load_meta();
    match (m.latest_build, current_build()) {
        (Some(l), Some(c)) if l > c => Some(l),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Разбор реестра IEEE
// ---------------------------------------------------------------------------

/// Поля строки CSV (кавычки, запятые внутри кавычек, удвоенные кавычки).
pub fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Короткое имя производителя: «Cisco Systems, Inc» → «Cisco Systems»,
/// «Hangzhou Hikvision Digital Technology Co.,Ltd.» → «Hangzhou Hikvision Digital».
pub fn short_vendor(org: &str) -> String {
    let mut s = org.split(',').next().unwrap_or(org).trim().to_string();
    // Регион в скобках: «(Shenzhen)», «(Malaysia) Sdn. Bhd.».
    if let Some(i) = s.find(" (")
        && i > 2
    {
        s.truncate(i);
    }
    const SUFFIX: [&str; 30] = [
        "Inc.", "Inc", "Incorporated", "Corporation.", "Corporation", "Corp.", "Corp", "Co.Ltd", "Co.", "Co", "Ltd.", "Ltd", "LLC", "GmbH & Co. KG",
        "GmbH & Co KG", "GmbH", "AG", "S.A.", "SA", "B.V.", "BV", "Limited", "Sdn. Bhd.", "PTE", "Company", "Group", "Technologies", "Technology",
        "Electronics", "Communications",
    ];
    loop {
        let before = s.len();
        for suf in SUFFIX {
            let lower = s.to_lowercase();
            let pat = format!(" {}", suf.to_lowercase());
            // Оставляем хотя бы одно слово.
            if lower.ends_with(&pat) && s[..s.len() - pat.len()].trim().contains(|c: char| c.is_alphanumeric()) {
                s.truncate(s.len() - pat.len());
                s = s.trim_end_matches([' ', ',', '.', '-']).to_string();
            }
        }
        if s.len() == before {
            break;
        }
    }
    if s.is_empty() { org.trim().to_string() } else { s }
}

/// CSV IEEE → сжатая таблица в формате встроенной базы.
pub fn oui_from_csv(csv: &str) -> Result<(Vec<u8>, usize), String> {
    let mut lines = Vec::new();
    for l in csv.lines().skip(1) {
        let f = csv_fields(l);
        if f.len() < 3 {
            continue;
        }
        let hex = f[1].trim();
        if hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            lines.push(format!("{}\t{}", hex.to_ascii_uppercase(), short_vendor(&f[2])));
        }
    }
    if lines.len() < 10_000 {
        return Err(format!("в реестре IEEE слишком мало записей ({})", lines.len()));
    }
    let n = lines.len();
    Ok((miniz_oxide::deflate::compress_to_vec(lines.join("\n").as_bytes(), 9), n))
}

// ---------------------------------------------------------------------------
// Загрузка
// ---------------------------------------------------------------------------

async fn get(url: &str, limit_kb: usize, proxy: Option<&str>) -> Result<Vec<u8>, String> {
    let hc = http::Config {
        url: url.into(),
        method: "GET".into(),
        proxy_mode: if proxy.is_some() { ProxyMode::Manual } else { ProxyMode::Direct },
        proxy: proxy.unwrap_or_default().into(),
        follow_redirects: true,
        verify_tls: true,
        timeout_ms: 60_000,
        body_limit_kb: limit_kb,
        user_agent: concat!("proxy-scanner/", env!("CARGO_PKG_VERSION"), " (+https://github.com/Svarshik-arch/Proxy-Scanner)").into(),
        headers: "Accept: application/vnd.github+json, text/csv, */*".into(),
        ..Default::default()
    };
    let hops = http::fetch(&hc, None).await?;
    let last = hops.last().ok_or("нет ответа")?;
    if let Some(e) = &last.error {
        return Err(e.clone());
    }
    if last.status != 200 {
        return Err(format!("HTTP {}", last.status));
    }
    if last.body_truncated {
        return Err("ответ слишком большой".into());
    }
    Ok(last.body.clone())
}

/// Сначала напрямую, затем через системный прокси (если настроен).
async fn fetch(url: &str, limit_kb: usize, proxy: &Option<String>) -> Result<Vec<u8>, String> {
    match get(url, limit_kb, None).await {
        Ok(b) => Ok(b),
        Err(e) => match proxy {
            Some(p) => get(url, limit_kb, Some(p)).await.map_err(|e2| format!("напрямую: {e}; через прокси {p}: {e2}")),
            None => Err(e),
        },
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    /// Итог одной строкой и признак «есть новая версия».
    Done(String, Option<u32>),
}

/// Проверить и обновить базы. `quiet_offline` — без сообщений, если интернета нет.
pub async fn run(quiet_offline: bool, sink: Sink<Event>, cancel: CancellationToken) {
    let proxy = crate::tools::sitecheck::system_proxy_for(CVE_URL, Duration::from_secs(5))
        .await
        .ok()
        .flatten()
        .map(|x| x.1)
        .filter(|p| !p.is_empty());
    let mut meta = load_meta();
    let mut parts = Vec::new();
    let mut errors = Vec::new();
    let _ = std::fs::create_dir_all(data_dir());

    // Версия программы — заодно проверка, есть ли интернет.
    match fetch(RELEASE_API, 256, &proxy).await {
        Ok(b) => {
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
            let tag = v["tag_name"].as_str().unwrap_or_default().to_string();
            let build = tag.rsplit("build.").next().and_then(|n| n.parse::<u32>().ok());
            meta.latest_tag = tag.clone();
            meta.latest_build = build;
            match (build, current_build()) {
                (Some(l), Some(c)) if l > c => parts.push(format!("доступна новая версия: сборка {l} (у вас {c})")),
                (Some(_), Some(_)) => parts.push("версия программы актуальна".into()),
                _ => {}
            }
        }
        Err(e) => {
            if quiet_offline {
                return sink.send(Event::Done(String::new(), None));
            }
            errors.push(format!("GitHub: {e}"));
        }
    }
    if cancel.is_cancelled() {
        return;
    }
    // База уязвимостей.
    sink.send(Event::Log("база уязвимостей…".into()));
    match fetch(CVE_URL, 1024, &proxy).await {
        Ok(b) => match serde_json::from_slice::<crate::tools::cve::Db>(&b) {
            Ok(db) if !db.rules.is_empty() => {
                let cur = crate::tools::cve::db().version;
                if db.version > cur {
                    let _ = std::fs::write(data_dir().join("cve.json"), &b);
                    crate::tools::cve::reload();
                    parts.push(format!("база уязвимостей обновлена до версии {} ({} правил)", db.version, db.rules.len()));
                } else {
                    parts.push(format!("база уязвимостей актуальна (версия {cur})"));
                }
                meta.cve_at = crate::session::now_unix();
                meta.cve_version = db.version.max(cur);
            }
            Ok(_) => errors.push("база уязвимостей: пустой файл".into()),
            Err(e) => errors.push(format!("база уязвимостей: {e}")),
        },
        Err(e) => errors.push(format!("база уязвимостей: {e}")),
    }
    if cancel.is_cancelled() {
        return;
    }
    // Производители сетевых карт.
    sink.send(Event::Log("реестр производителей IEEE…".into()));
    match fetch(OUI_URL, 16 * 1024, &proxy).await {
        Ok(b) => match oui_from_csv(&String::from_utf8_lossy(&b)) {
            Ok((data, n)) => {
                let before = crate::tools::oui::entries();
                let _ = std::fs::write(data_dir().join("oui.deflate"), data);
                crate::tools::oui::reload();
                meta.oui_at = crate::session::now_unix();
                meta.oui_entries = n;
                parts.push(format!("производители: {n} записей (было {before})"));
            }
            Err(e) => errors.push(format!("производители: {e}")),
        },
        Err(e) => errors.push(format!("производители: {e}")),
    }
    meta.checked_at = crate::session::now_unix();
    save_meta(&meta);
    let mut text = parts.join("; ");
    if !errors.is_empty() {
        if !text.is_empty() {
            text += "; ";
        }
        text += &format!("ошибки: {}", errors.join("; "));
    }
    let newer = match (meta.latest_build, current_build()) {
        (Some(l), Some(c)) if l > c => Some(l),
        _ => None,
    };
    sink.send(Event::Done(format!("Обновление баз: {text}"), newer));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_and_vendors() {
        let f = csv_fields(r#"MA-L,00000C,"Cisco Systems, Inc",170 West Tasman Dr. San Jose CA US 95134"#);
        assert_eq!(f[1], "00000C");
        assert_eq!(f[2], "Cisco Systems, Inc");
        assert_eq!(short_vendor("Cisco Systems, Inc"), "Cisco Systems");
        assert_eq!(short_vendor("Hewlett Packard Enterprise Co."), "Hewlett Packard Enterprise");
        assert_eq!(short_vendor("Dell Inc."), "Dell");
        assert_eq!(short_vendor("Intel Corporate"), "Intel Corporate");
        assert_eq!(short_vendor("TP-LINK TECHNOLOGIES CO.,LTD."), "TP-LINK");
        assert_eq!(short_vendor("Samsung Electronics Co.,Ltd"), "Samsung");
        assert_eq!(short_vendor("Huawei Technologies Co.,Ltd"), "Huawei");
        assert_eq!(short_vendor("Technology"), "Technology");
        let f = csv_fields(r#"MA-L,ABCDEF,"Say ""Hi"" Ltd",addr"#);
        assert_eq!(f[2], r#"Say "Hi" Ltd"#);
    }

    #[test]
    fn oui_roundtrip() {
        let mut csv = String::from("Registry,Assignment,Organization Name,Organization Address\n");
        for i in 0..12_000u32 {
            csv += &format!("MA-L,{:06X},\"Vendor {i}, Inc.\",addr\n", i);
        }
        let (data, n) = oui_from_csv(&csv).unwrap();
        assert_eq!(n, 12_000);
        let t = crate::tools::oui::parse_table(&data).unwrap();
        assert_eq!(t[5].1, "Vendor 5");
        assert!(oui_from_csv("Registry\nMA-L,000000,x,y").is_err());
    }

    #[test]
    fn builtin_cve_db_parses() {
        let db: crate::tools::cve::Db = serde_json::from_str(crate::tools::cve::BUILTIN).unwrap();
        assert!(db.rules.len() >= 15);
    }
}
