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

struct Rule {
    product: &'static str,
    marker: &'static str,
    /// Уязвимы версии `from <= v < to` (пустой `from` — с начала).
    from: &'static str,
    to: &'static str,
    cve: &'static str,
    severity: Severity,
    title: &'static str,
}

use Severity::*;

const RULES: &[Rule] = &[
    Rule { product: "OpenSSH", marker: "OpenSSH", from: "8.5", to: "9.8", cve: "CVE-2024-6387", severity: High, title: "regreSSHion: удалённое выполнение кода в sshd (glibc)" },
    Rule { product: "OpenSSH", marker: "OpenSSH", from: "", to: "4.4", cve: "CVE-2006-5051", severity: High, title: "гонка в обработчике сигналов sshd (предшественник regreSSHion)" },
    Rule { product: "OpenSSH", marker: "OpenSSH", from: "", to: "9.6", cve: "CVE-2023-48795", severity: Medium, title: "Terrapin: обрезка префикса SSH-сессии" },
    Rule { product: "OpenSSH", marker: "OpenSSH", from: "", to: "7.8", cve: "CVE-2018-15473", severity: Low, title: "перебор имён пользователей" },
    Rule { product: "Apache httpd", marker: "Apache/", from: "2.4.49", to: "2.4.50", cve: "CVE-2021-41773", severity: High, title: "обход каталогов и выполнение кода (path traversal)" },
    Rule { product: "Apache httpd", marker: "Apache/", from: "2.4.50", to: "2.4.51", cve: "CVE-2021-42013", severity: High, title: "обход каталогов и выполнение кода (неполное исправление 41773)" },
    Rule { product: "Apache httpd", marker: "Apache/", from: "2.4.0", to: "2.4.56", cve: "CVE-2023-25690", severity: High, title: "HTTP request smuggling в mod_proxy" },
    Rule { product: "nginx", marker: "nginx/", from: "0.6.18", to: "1.20.1", cve: "CVE-2021-23017", severity: High, title: "ошибка в DNS-резолвере (resolver), возможно выполнение кода" },
    Rule { product: "OpenSSL", marker: "OpenSSL/", from: "1.0.1", to: "1.0.1.7", cve: "CVE-2014-0160", severity: High, title: "Heartbleed: утечка памяти сервера, ключей и паролей" },
    Rule { product: "vsftpd", marker: "vsFTPd", from: "2.3.4", to: "2.3.5", cve: "CVE-2011-2523", severity: High, title: "закладка (backdoor) в vsftpd 2.3.4" },
    Rule { product: "ProFTPD", marker: "ProFTPD", from: "1.3.5", to: "1.3.5.1", cve: "CVE-2015-3306", severity: High, title: "mod_copy: копирование файлов без входа" },
    Rule { product: "Exim", marker: "Exim", from: "4.87", to: "4.92", cve: "CVE-2019-10149", severity: High, title: "удалённое выполнение команд (The Return of the WIZard)" },
    Rule { product: "Samba", marker: "Samba", from: "3.5.0", to: "4.6.4", cve: "CVE-2017-7494", severity: High, title: "SambaCry: загрузка и выполнение библиотеки через общий ресурс" },
    Rule { product: "Microsoft IIS", marker: "Microsoft-IIS/", from: "6.0", to: "6.1", cve: "CVE-2017-7269", severity: High, title: "переполнение буфера WebDAV в IIS 6.0" },
    Rule { product: "PHP", marker: "PHP/", from: "8.1.0", to: "8.1.0.1", cve: "закладка 8.1.0-dev", severity: High, title: "закладка в PHP 8.1.0-dev (заголовок User-Agentt)" },
    Rule { product: "Apache Tomcat", marker: "Apache Tomcat/", from: "9.0.0", to: "9.0.31", cve: "CVE-2020-1938", severity: High, title: "Ghostcat: чтение файлов через AJP (порт 8009)" },
    Rule { product: "Apache Tomcat", marker: "Apache Tomcat/", from: "8.5.0", to: "8.5.51", cve: "CVE-2020-1938", severity: High, title: "Ghostcat: чтение файлов через AJP (порт 8009)" },
    Rule { product: "Apache Tomcat", marker: "Apache Tomcat/", from: "7.0.0", to: "7.0.100", cve: "CVE-2020-1938", severity: High, title: "Ghostcat: чтение файлов через AJP (порт 8009)" },
];

/// Особый случай: OpenSSL 1.0.1–1.0.1f — буква в конце версии.
fn openssl_heartbleed(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("1.0.1") else { return false };
    match rest.chars().next() {
        None => true,
        Some(c) => ('a'..='f').contains(&c),
    }
}

pub fn check_text(text: &str) -> Vec<Vuln> {
    let mut out: Vec<Vuln> = Vec::new();
    for r in RULES {
        let Some(v) = after(text, r.marker) else { continue };
        let hit = if r.cve == "CVE-2014-0160" {
            openssl_heartbleed(&v)
        } else if r.product == "PHP" {
            v.starts_with("8.1.0-dev")
        } else {
            let n = parse_version(&v);
            (r.from.is_empty() || !ver_lt(&n, &parse_version(r.from))) && ver_lt(&n, &parse_version(r.to))
        };
        if hit && !out.iter().any(|x| x.cve == r.cve) {
            out.push(Vuln {
                cve: r.cve.into(),
                product: r.product.into(),
                version: v,
                severity: r.severity,
                title: r.title.into(),
                // «1.3.5.1» — служебная граница для «только 1.3.5»: показываем «новее 1.3.5».
                fixed: if r.to.matches('.').count() >= 3 { format!("новее {}", r.from) } else { r.to.into() },
            });
        }
    }
    out
}

/// Уязвимости сервиса по версии, баннеру и подробностям.
pub fn check(s: &Service) -> Vec<Vuln> {
    let text = format!("{} {} {}", s.version, s.banner, s.details.join(" "));
    let mut v = check_text(&text);
    // Ghostcat опасен только при открытом AJP.
    v.retain(|x| x.cve != "CVE-2020-1938" || s.port == 8009 || text.contains("AJP"));
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
