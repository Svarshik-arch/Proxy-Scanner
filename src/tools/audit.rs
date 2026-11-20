//! Аудит небезопасных настроек в своей сети: сканер сервисов + правила + несколько
//! безопасных дополнительных проверок (SMBv1, анонимный FTP, VNC без пароля, старые
//! версии TLS). Уязвимости не эксплуатируются, учётные данные не подбираются.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::Sink;
use super::services::{self, Service};
use super::tlsaudit::{self, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub targets: String,
    pub tcp_ports: String,
    pub udp_ports: String,
    /// Проверять вход anonymous на FTP (стандартная проверка аудита).
    pub ftp_anonymous: bool,
    /// Проверять SSL 3.0 / TLS 1.0 / 1.1 на TLS-портах.
    pub tls_versions: bool,
    pub snmp_community: String,
    pub timeout_ms: u64,
    pub concurrency: usize,
}

pub const DEFAULT_TCP: &str = "21,22,23,25,80,110,135,139,143,389,443,445,636,1433,2375,3306,3389,5432,5900,5901,6379,8080,8443,9200,11211,27017";

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: String::new(),
            tcp_ports: DEFAULT_TCP.into(),
            udp_ports: "53,123,161,1434".into(),
            ftp_anonymous: true,
            tls_versions: true,
            snmp_community: "public".into(),
            timeout_ms: 2500,
            concurrency: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub proto: String,
    pub service: String,
    pub severity: Severity,
    pub title: String,
    pub advice: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub issues: Vec<Issue>,
    /// Найденные сервисы (основа проверок).
    pub services: Vec<Service>,
    pub hosts_scanned: u64,
}

impl Report {
    pub fn count(&self, s: Severity) -> usize {
        self.issues.iter().filter(|i| i.severity == s).count()
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Total(u64),
    Progress(u64),
    Service(Box<Service>),
    Issue(Box<Issue>),
}

// ---------------------------------------------------------------------------
// Дополнительные проверки
// ---------------------------------------------------------------------------

pub fn smb1_negotiate() -> Vec<u8> {
    let mut smb = vec![0xFF, b'S', b'M', b'B', 0x72, 0, 0, 0, 0, 0x18, 0x01, 0x28];
    smb.extend_from_slice(&[0; 12]); // pid high, signature, reserved
    smb.extend_from_slice(&[0, 0, 0xFF, 0xFE, 0, 0, 0, 0]); // tid, pid, uid, mid
    smb.push(0); // word count
    let dialect = b"\x02NT LM 0.12\x00";
    smb.extend_from_slice(&(dialect.len() as u16).to_le_bytes());
    smb.extend_from_slice(dialect);
    let mut out = vec![0, 0];
    out.extend_from_slice(&(smb.len() as u16).to_be_bytes());
    out.extend(smb);
    out
}

/// Ответил ли сервер по SMBv1 и принял диалект.
pub fn smb1_accepted(resp: &[u8]) -> bool {
    resp.len() >= 4 + 37
        && &resp[4..8] == b"\xFFSMB"
        && resp[8] == 0x72
        && resp[9..13] == [0, 0, 0, 0]
        && resp[4 + 32] > 0
        && u16::from_le_bytes([resp[4 + 33], resp[4 + 34]]) != 0xFFFF
}

async fn exchange(addr: SocketAddr, send: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;
    s.write_all(send).await.ok()?;
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(timeout, s.read(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    Some(buf)
}

async fn read_line(s: &mut TcpStream, timeout: Duration) -> Option<String> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = tokio::time::timeout(timeout, s.read(&mut b)).await.ok()?.ok()?;
        if n == 0 {
            break;
        }
        out.push(b[0]);
        if b[0] == b'\n' || out.len() > 1024 {
            break;
        }
    }
    (!out.is_empty()).then(|| String::from_utf8_lossy(&out).into_owned())
}

/// Ответ FTP (с учётом многострочных ответов `220-…`).
async fn ftp_reply(s: &mut TcpStream, timeout: Duration) -> Option<u16> {
    let first = read_line(s, timeout).await?;
    let code: u16 = first.get(..3)?.parse().ok()?;
    if first.as_bytes().get(3) == Some(&b'-') {
        loop {
            let l = read_line(s, timeout).await?;
            if l.starts_with(&format!("{code} ")) {
                break;
            }
        }
    }
    Some(code)
}

pub async fn ftp_anonymous(addr: SocketAddr, timeout: Duration) -> Option<bool> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;
    if ftp_reply(&mut s, timeout).await? != 220 {
        return None;
    }
    s.write_all(b"USER anonymous\r\n").await.ok()?;
    let code = ftp_reply(&mut s, timeout).await?;
    let ok = match code {
        230 => true,
        331 => {
            s.write_all(b"PASS anonymous@example.com\r\n").await.ok()?;
            ftp_reply(&mut s, timeout).await? == 230
        }
        _ => false,
    };
    let _ = s.write_all(b"QUIT\r\n").await;
    Some(ok)
}

/// Типы защиты VNC: true — сервер разрешает подключение без пароля.
pub async fn vnc_no_auth(addr: SocketAddr, timeout: Duration) -> Option<bool> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;
    let mut ver = [0u8; 12];
    tokio::time::timeout(timeout, s.read_exact(&mut ver)).await.ok()?.ok()?;
    if !ver.starts_with(b"RFB ") {
        return None;
    }
    let old = &ver[4..11] == b"003.003";
    s.write_all(if old { b"RFB 003.003\n" } else { b"RFB 003.008\n" }).await.ok()?;
    if old {
        let mut t = [0u8; 4];
        tokio::time::timeout(timeout, s.read_exact(&mut t)).await.ok()?.ok()?;
        return Some(u32::from_be_bytes(t) == 1);
    }
    let mut n = [0u8; 1];
    tokio::time::timeout(timeout, s.read_exact(&mut n)).await.ok()?.ok()?;
    if n[0] == 0 {
        return Some(false);
    }
    let mut types = vec![0u8; n[0] as usize];
    tokio::time::timeout(timeout, s.read_exact(&mut types)).await.ok()?.ok()?;
    Some(types.contains(&1))
}

// ---------------------------------------------------------------------------
// Правила
// ---------------------------------------------------------------------------

fn issue(s: &Service, severity: Severity, title: &str, advice: &str) -> Issue {
    Issue {
        ip: s.ip,
        port: s.port,
        proto: s.proto.clone(),
        service: s.service.clone(),
        severity,
        title: title.into(),
        advice: advice.into(),
    }
}

/// Версия OpenSSH из баннера: (major, minor).
fn openssh_version(v: &str) -> Option<(u32, u32)> {
    let rest = v.split("OpenSSH").nth(1)?.trim_start_matches([' ', '_']);
    let mut it = rest.split(|c: char| !c.is_ascii_digit());
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Правила по результату сканера сервисов.
pub fn rules(s: &Service) -> Vec<Issue> {
    use Severity::*;
    let mut out = Vec::new();
    let has = |needle: &str| s.details.iter().any(|d| d.contains(needle));
    match s.service.as_str() {
        "telnet" => out.push(issue(s, High, "Telnet: логины и пароли передаются открытым текстом", "Отключите Telnet, используйте SSH")),
        "ftp" => out.push(issue(s, Medium, "FTP без шифрования", "Перейдите на SFTP или FTPS")),
        "smb" => {
            if s.version == "SMBv1" {
                out.push(issue(s, High, "Включён SMBv1 (EternalBlue, WannaCry)", "Отключите SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false"));
            }
            if has("не обязательна") {
                out.push(issue(s, Medium, "Подпись SMB не обязательна (NTLM relay)", "Включите «Microsoft network server: Digitally sign communications (always)»"));
            }
        }
        "rdp" => {
            if s.version.contains("без TLS") || s.version.contains("стандартная защита") || has("устаревшая защита") {
                out.push(issue(s, High, "RDP без NLA и TLS", "Включите проверку подлинности на уровне сети (NLA)"));
            } else if s.version == "TLS" {
                out.push(issue(s, Medium, "RDP без NLA: экран входа доступен до аутентификации", "Включите NLA"));
            }
        }
        "snmp" if has("community") => {
            out.push(issue(s, High, "SNMP отвечает на стандартный community", "Смените community или перейдите на SNMPv3; ограничьте доступ ACL"))
        }
        "redis" if has("без пароля") => out.push(issue(s, High, "Redis без пароля", "Задайте requirepass/ACL и привяжите к внутреннему адресу")),
        "memcached" => out.push(issue(s, Medium, "memcached доступен по сети без аутентификации", "Привяжите к localhost или закройте межсетевым экраном")),
        "mongodb" => out.push(issue(s, Low, "MongoDB доступна по сети", "Проверьте, что включена аутентификация (security.authorization)")),
        "mssql-browser" => out.push(issue(s, Low, "Служба SQL Browser раскрывает экземпляры и порты", "Отключите SQL Browser, если не нужен")),
        "mssql" => {
            if let Some(major) = s.version.strip_prefix("SQL Server ").and_then(|v| v.split('.').next()).and_then(|m| m.parse::<u32>().ok())
                && major <= 10
            {
                out.push(issue(s, High, "Неподдерживаемая версия SQL Server (2008 и старше)", "Обновите SQL Server"));
            }
        }
        "ssh" => {
            if has("SSH 1") {
                out.push(issue(s, High, "Поддерживается протокол SSH 1", "Отключите протокол 1"));
            }
            if let Some((maj, min)) = openssh_version(&s.version)
                && (maj, min) < (7, 4)
            {
                out.push(issue(s, Medium, "Устаревший OpenSSH (до 7.4)", "Обновите OpenSSH"));
            }
        }
        "dns" if !s.version.is_empty() => out.push(issue(s, Low, "DNS раскрывает версию (version.bind)", "Скройте версию: options { version \"none\"; }")),
        "ntp" if has("5 минут") => out.push(issue(s, Medium, "Часы узла расходятся больше чем на 5 минут", "Настройте синхронизацию времени с контроллером домена")),
        "vnc" => out.push(issue(s, Low, "VNC доступен по сети", "Ограничьте доступ, используйте туннель")),
        _ => {}
    }
    if s.service.starts_with("http") {
        if s.port == 2375 && !s.version.is_empty() || s.port == 2375 && s.details.iter().any(|d| d.starts_with("HTTP 200")) {
            out.push(issue(s, High, "Docker API без TLS (полный доступ к хосту)", "Закройте порт 2375, используйте TLS (2376) с клиентскими сертификатами"));
        }
        if s.version.contains("Elasticsearch") || (s.port == 9200 && has("HTTP 200")) {
            out.push(issue(s, High, "Elasticsearch без аутентификации", "Включите xpack.security"));
        }
        if s.service == "http" && has("аутентификация: Basic") {
            out.push(issue(s, Medium, "Basic-аутентификация по HTTP без TLS", "Включите HTTPS"));
        }
        if has("похоже на прокси") {
            out.push(issue(s, Low, "Прокси-сервер: проверьте, открыт ли он без аутентификации", "Раздел «Прокси» покажет подробности"));
        }
    }
    if let Some(t) = &s.tls {
        if t.days_left < 0 {
            out.push(issue(s, High, &format!("Сертификат просрочен ({} дн.)", -t.days_left), "Замените сертификат"));
        } else if t.days_left < 30 {
            out.push(issue(s, Medium, &format!("Сертификат истекает через {} дн.", t.days_left), "Запланируйте замену"));
        }
        if !t.trusted {
            out.push(issue(s, Low, "Сертификат не доверен системой (самоподписанный или чужой CA)", "Выпустите сертификат от корпоративного CA"));
        }
    }
    for v in super::cve::check(s) {
        out.push(issue(
            s,
            v.severity,
            &format!("{} {} {}: {}", v.product, v.version, v.cve, v.title),
            &format!("Обновите до {} или проверьте, перенесено ли исправление в пакет дистрибутива", v.fixed),
        ));
    }
    out
}

async fn extra_checks(s: &Service, cfg: &Config) -> Vec<Issue> {
    use Severity::*;
    let timeout = Duration::from_millis(cfg.timeout_ms.max(300));
    let addr = SocketAddr::new(IpAddr::V4(s.ip), s.port);
    let mut out = Vec::new();
    if s.proto != "tcp" {
        return out;
    }
    if s.service == "smb"
        && s.version != "SMBv1"
        && exchange(addr, &smb1_negotiate(), timeout).await.is_some_and(|r| smb1_accepted(&r))
    {
        out.push(issue(s, High, "Включён SMBv1 (EternalBlue, WannaCry)", "Отключите SMBv1"));
    }
    if cfg.ftp_anonymous && s.service.starts_with("ftp") && ftp_anonymous(addr, timeout).await == Some(true) {
        out.push(issue(s, High, "Анонимный вход на FTP разрешён", "Запретите anonymous, если он не нужен"));
    }
    if s.service == "vnc" && vnc_no_auth(addr, timeout).await == Some(true) {
        out.push(issue(s, High, "VNC без пароля", "Включите аутентификацию VNC"));
    }
    if cfg.tls_versions && s.tls.is_some() {
        for (v, sev) in [(tlsaudit::SSL3, High), (tlsaudit::TLS10, Medium), (tlsaudit::TLS11, Medium)] {
            let r = tlsaudit::check_version(addr, v, None, false, timeout).await;
            if r.supported {
                out.push(issue(s, sev, &format!("Включён устаревший {}", r.version), "Оставьте только TLS 1.2 и 1.3"));
            }
        }
    }
    out
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let hosts = match super::HostList::parse(&cfg.targets) {
        Ok(h) => h,
        Err(e) => return sink.send(Event::Log(e)),
    };
    let parse = |s: &str| if s.trim().is_empty() { Ok(Vec::new()) } else { crate::targets::parse_ports(s) };
    let (tcp, udp) = match (parse(&cfg.tcp_ports), parse(&cfg.udp_ports)) {
        (Ok(t), Ok(u)) => (t, u),
        (Err(e), _) | (_, Err(e)) => return sink.send(Event::Log(e)),
    };
    let mut ips: Vec<Ipv4Addr> = hosts.addrs.iter().collect();
    for name in &hosts.names {
        match super::resolve_v4(name, Duration::from_secs(3)).await {
            Ok(ip) => ips.push(ip),
            Err(e) => sink.send(Event::Log(e)),
        }
    }
    let mut jobs = Vec::new();
    for ip in &ips {
        jobs.extend(tcp.iter().map(|p| (*ip, *p, true)));
        jobs.extend(udp.iter().map(|p| (*ip, *p, false)));
    }
    let total = jobs.len() as u64;
    if total > 2_000_000 {
        return sink.send(Event::Log(format!("слишком много проверок ({total})")));
    }
    sink.send(Event::Total(total));
    let svc_cfg = Arc::new(services::Config {
        snmp_community: cfg.snmp_community.clone(),
        connect_timeout_ms: cfg.timeout_ms.min(2000),
        read_timeout_ms: cfg.timeout_ms,
        active_probes: true,
        ..Default::default()
    });
    let cfg = Arc::new(cfg);
    let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
    super::for_each_limited(jobs, cfg.concurrency, &cancel, |(ip, port, is_tcp)| {
        let (cfg, svc_cfg, sink, done) = (cfg.clone(), svc_cfg.clone(), sink.clone(), done.clone());
        async move {
            let found = if is_tcp {
                services::scan_tcp(ip, port, svc_cfg).await
            } else {
                services::scan_udp(ip, port, svc_cfg).await
            };
            if let Some(s) = found {
                let mut issues = rules(&s);
                for i in extra_checks(&s, &cfg).await {
                    if !issues.iter().any(|x| x.title == i.title) {
                        issues.push(i);
                    }
                }
                sink.send(Event::Service(Box::new(s)));
                for i in issues {
                    sink.send(Event::Issue(Box::new(i)));
                }
            }
            let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if n % 32 == 0 || n == total {
                sink.send(Event::Progress(n));
            }
        }
    })
    .await;
}

pub fn sort(r: &mut Report) {
    r.issues.sort_by_key(|a| (a.severity, a.ip, a.port));
    r.services.sort_by_key(|s| (s.ip, s.proto.clone(), s.port));
}

pub fn render_text(r: &Report) -> String {
    let mut s = format!(
        "Находки: высокая {}, средняя {}, низкая {} (сервисов проверено: {})\n\n",
        r.count(Severity::High),
        r.count(Severity::Medium),
        r.count(Severity::Low),
        r.services.len()
    );
    for i in &r.issues {
        s += &format!(
            "[{}] {}:{}/{} {} — {}\n         → {}\n",
            i.severity.label(),
            i.ip,
            i.port,
            i.proto,
            i.service,
            i.title,
            i.advice
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(service: &str, version: &str, details: &[&str]) -> Service {
        Service {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            port: 1,
            proto: "tcp".into(),
            state: "open".into(),
            service: service.into(),
            version: version.into(),
            tls: None,
            banner: String::new(),
            details: details.iter().map(|d| d.to_string()).collect(),
            rtt_ms: None,
        }
    }

    #[test]
    fn rule_matching() {
        assert_eq!(rules(&svc("telnet", "", &[]))[0].severity, Severity::High);
        let smb = rules(&svc("smb", "SMB 3.0.2+", &["подпись SMB не обязательна"]));
        assert_eq!(smb.len(), 1);
        assert_eq!(smb[0].severity, Severity::Medium);
        assert!(rules(&svc("smb", "SMB 3.0.2+", &["подпись SMB обязательна"])).is_empty());
        assert_eq!(rules(&svc("rdp", "TLS", &[])).len(), 1);
        assert!(rules(&svc("rdp", "NLA (CredSSP)", &[])).is_empty());
        assert_eq!(rules(&svc("ssh", "OpenSSH 6.6.1p1 Ubuntu", &[]))[0].severity, Severity::Medium);
        assert!(rules(&svc("ssh", "OpenSSH 9.8p1", &[])).is_empty());
        assert_eq!(rules(&svc("redis", "", &["доступ без пароля"]))[0].severity, Severity::High);
        let mut t = svc("https", "nginx", &["HTTP 200"]);
        t.tls = Some(services::TlsSummary { days_left: -1, trusted: true, ..Default::default() });
        assert!(rules(&t).iter().any(|i| i.title.contains("просрочен")));
        assert_eq!(openssh_version("OpenSSH 7.4p1"), Some((7, 4)));
    }

    #[test]
    fn smb1_packets() {
        let p = smb1_negotiate();
        assert_eq!(u16::from_be_bytes([p[2], p[3]]) as usize, p.len() - 4);
        let mut resp = vec![0, 0, 0, 0x55];
        resp.extend_from_slice(b"\xFFSMB\x72\x00\x00\x00\x00");
        resp.extend_from_slice(&[0; 23]);
        resp.push(17);
        resp.extend_from_slice(&[0, 0]);
        resp.extend_from_slice(&[0; 40]);
        assert!(smb1_accepted(&resp));
        resp[4 + 33] = 0xFF;
        resp[4 + 34] = 0xFF;
        assert!(!smb1_accepted(&resp));
    }

    #[tokio::test]
    async fn ftp_anon_and_vnc() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"220-Welcome\r\n220 FTP ready\r\n").await.unwrap();
            let _ = read_line(&mut s, Duration::from_secs(1)).await;
            s.write_all(b"331 Please specify the password.\r\n").await.unwrap();
            let _ = read_line(&mut s, Duration::from_secs(1)).await;
            s.write_all(b"230 Login successful.\r\n").await.unwrap();
        });
        assert_eq!(ftp_anonymous(addr, Duration::from_secs(2)).await, Some(true));

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"RFB 003.008\n").await.unwrap();
            let mut v = [0u8; 12];
            s.read_exact(&mut v).await.unwrap();
            s.write_all(&[2, 2, 1]).await.unwrap();
        });
        assert_eq!(vnc_no_auth(addr, Duration::from_secs(2)).await, Some(true));
    }
}
