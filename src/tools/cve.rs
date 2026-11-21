//! Известные уязвимости по версиям из баннеров (встроенная база, без интернета).
//!
//! Совпадение — повод проверить, а не приговор: дистрибутивы часто переносят
//! исправления в старые версии (бэкпорт), и баннер остаётся прежним.

use serde::{Deserialize, Serialize};

use super::services::Service;
use super::tlsaudit::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vuln {
    pub cve: String,
    pub product: String,
    pub version: String,
    pub severity: Severity,
    pub title: String,
    pub fixed: String,
}

/// Версия как список чисел; «8.9p1» → [8, 9, 1], «2.4.49» → [2, 4, 49].
pub fn parse_version(s: &str) -> Vec<u32> {
    s.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).filter_map(|x| x.parse().ok()).take(4).collect()
}

fn ver_lt(a: &[u32], b: &[u32]) -> bool {
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    false
}

/// Версия продукта после метки: «OpenSSH_8.9p1», «nginx/1.18.0», «vsFTPd 2.3.4».
fn after(text: &str, marker: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let i = lower.find(&marker.to_ascii_lowercase())?;
    let rest = &text[i + marker.len()..];
    let rest = rest.trim_start_matches(['/', '_', ' ', '-', 'v', 'V', '(']);
    let v: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').collect();
    (!v.is_empty() && v.chars().next().is_some_and(|c| c.is_ascii_digit())).then_some(v)
}

/// Правило базы: продукт по метке в тексте и уязвимые версии.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub product: String,
    pub marker: String,
    /// `range` — `from <= v < to` (пустой `from` — с начала); `prefix` — версия начинается
    /// с `from`; `letters` — `from` и `from` + буква до `to` включительно (OpenSSL 1.0.1–1.0.1f).
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: String,
    pub cve: String,
    pub severity: Severity,
    pub title: String,
    /// Где исправлено (если не совпадает с `to`).
    #[serde(default)]
    pub fixed: String,
    /// Дополнительное условие: `ajp` — только при открытом AJP.
    #[serde(default)]
    pub requires: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Db {
    pub version: u32,
    #[serde(default)]
    pub updated: String,
    pub rules: Vec<Rule>,
}

/// База, встроенная в программу.
pub const BUILTIN: &str = include_str!("../../data/cve.json");

static DB: std::sync::RwLock<Option<std::sync::Arc<Db>>> = std::sync::RwLock::new(None);

/// Текущая база: обновлённая (если новее встроенной), иначе встроенная.
pub fn db() -> std::sync::Arc<Db> {
    if let Some(d) = DB.read().ok().and_then(|g| g.clone()) {
        return d;
    }
    let builtin: Db = serde_json::from_str(BUILTIN).expect("встроенная база уязвимостей");
    let updated = std::fs::read_to_string(crate::updates::data_dir().join("cve.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Db>(&t).ok())
        .filter(|d| d.version > builtin.version && !d.rules.is_empty());
    let d = std::sync::Arc::new(updated.unwrap_or(builtin));
    if let Ok(mut g) = DB.write() {
        *g = Some(d.clone());
    }
    d
}

/// Перечитать базу (после обновления).
pub fn reload() {
    if let Ok(mut g) = DB.write() {
        *g = None;
    }
    let _ = db();
}

fn rule_hit(r: &Rule, v: &str) -> bool {
    match r.kind.as_str() {
        "prefix" => v.starts_with(&r.from),
        "letters" => {
            let Some(rest) = v.strip_prefix(&r.from) else { return false };
            let last = r.to.chars().next().unwrap_or('a');
            match rest.chars().next() {
                None => true,
                Some(c) => c.is_ascii_lowercase() && c <= last && !rest[1..].starts_with(|x: char| x.is_ascii_alphanumeric()),
            }
        }
        _ => {
            let n = parse_version(v);
            (r.from.is_empty() || !ver_lt(&n, &parse_version(&r.from))) && ver_lt(&n, &parse_version(&r.to))
        }
    }
}

pub fn check_text(text: &str) -> Vec<Vuln> {
    let db = db();
    let mut out: Vec<Vuln> = Vec::new();
    for r in &db.rules {
        let Some(v) = after(text, &r.marker) else { continue };
        if rule_hit(r, &v) && !out.iter().any(|x| x.cve == r.cve) {
            out.push(Vuln {
                cve: r.cve.clone(),
                product: r.product.clone(),
                version: v,
                severity: r.severity,
                title: r.title.clone(),
                fixed: if r.fixed.is_empty() { r.to.clone() } else { r.fixed.clone() },
            });
        }
    }
    out
}

/// Уязвимости сервиса по версии, баннеру и подробностям.
pub fn check(s: &Service) -> Vec<Vuln> {
    let text = format!("{} {} {}", s.version, s.banner, s.details.join(" "));
    let mut v = check_text(&text);
    // Правила с условием «ajp» (Ghostcat) — только при открытом AJP.
    let db = db();
    v.retain(|x| {
        let needs_ajp = db.rules.iter().any(|r| r.cve == x.cve && r.requires == "ajp");
        !needs_ajp || s.port == 8009 || text.contains("AJP")
    });
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cves(t: &str) -> Vec<String> {
        check_text(t).into_iter().map(|v| v.cve).collect()
    }

    #[test]
    fn matching() {
        assert_eq!(cves("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"), vec!["CVE-2024-6387", "CVE-2023-48795"]);
        assert_eq!(cves("SSH-2.0-OpenSSH_9.8p1"), Vec::<String>::new());
        assert_eq!(cves("SSH-2.0-OpenSSH_7.4"), vec!["CVE-2023-48795", "CVE-2018-15473"]);
        assert_eq!(cves("Server: Apache/2.4.49 (Unix)"), vec!["CVE-2021-41773", "CVE-2023-25690"]);
        assert_eq!(cves("Server: nginx/1.18.0"), vec!["CVE-2021-23017"]);
        assert!(cves("Server: nginx/1.24.0").is_empty());
        assert_eq!(cves("Apache/2.2.15 (CentOS) OpenSSL/1.0.1e-fips"), vec!["CVE-2014-0160"]);
        assert!(cves("OpenSSL/1.0.1g").is_empty());
        assert_eq!(cves("220 (vsFTPd 2.3.4)"), vec!["CVE-2011-2523"]);
        assert_eq!(cves("220 Exim 4.89 #2"), vec!["CVE-2019-10149"]);
        assert_eq!(cves("X-Powered-By: PHP/8.1.0-dev"), vec!["закладка 8.1.0-dev"]);
        assert!(cves("X-Powered-By: PHP/8.1.2").is_empty());
        assert_eq!(cves("Microsoft-IIS/6.0"), vec!["CVE-2017-7269"]);
    }

    #[test]
    fn versions() {
        assert!(ver_lt(&parse_version("8.9p1"), &parse_version("9.8")));
        assert!(!ver_lt(&parse_version("2.4.56"), &parse_version("2.4.56")));
        assert_eq!(parse_version("1.20.0"), vec![1, 20, 0]);
    }
}
