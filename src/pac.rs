//! PAC/WPAD: системные настройки прокси, поиск WPAD, загрузка PAC-файла и
//! вычисление `FindProxyForURL` встроенным JavaScript-движком (Boa).
//!
//! PAC-файл выполняется в песочнице: доступны только стандартные PAC-функции,
//! а число итераций циклов и глубина рекурсии ограничены — испорченный или
//! вредный файл не может «повесить» программу.

use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::Duration;

use boa_engine::{Context, JsArgs, JsResult, JsString, JsValue, NativeFunction, Source};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::util::{run_cmd, run_powershell};

/// Стандартные функции PAC (кроме dnsResolve/myIpAddress — они на стороне Rust).
const PAC_UTILS: &str = r#"
function isPlainHostName(host) { return String(host).indexOf('.') < 0; }
function dnsDomainIs(host, domain) {
  host = String(host).toLowerCase(); domain = String(domain).toLowerCase();
  return host.length >= domain.length && host.substring(host.length - domain.length) == domain;
}
function localHostOrDomainIs(host, hostdom) {
  host = String(host).toLowerCase(); hostdom = String(hostdom).toLowerCase();
  return host == hostdom || hostdom.lastIndexOf(host + '.', 0) == 0;
}
function isResolvable(host) { return dnsResolve(host) !== null; }
function isResolvableEx(host) { return isResolvable(host); }
function dnsResolveEx(host) { var r = dnsResolve(host); return r === null ? '' : r; }
function myIpAddressEx() { return myIpAddress(); }
function __ip2num(ip) {
  var p = String(ip).split('.'); if (p.length != 4) return null;
  var n = 0;
  for (var i = 0; i < 4; i++) {
    var x = parseInt(p[i], 10);
    if (isNaN(x) || x < 0 || x > 255) return null;
    n = n * 256 + x;
  }
  return n;
}
function isInNet(host, pattern, mask) {
  var ip = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? host : dnsResolve(host);
  if (ip === null) return false;
  var a = __ip2num(ip), p = __ip2num(pattern), m = __ip2num(mask);
  if (a === null || p === null || m === null) return false;
  return ((a & m) >>> 0) === ((p & m) >>> 0);
}
function isInNetEx(ip, prefix) {
  var parts = String(prefix).split('/');
  if (parts.length != 2) return false;
  var bits = parseInt(parts[1], 10);
  var mask = bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  var a = __ip2num(ip), p = __ip2num(parts[0]);
  if (a === null || p === null) return false;
  return ((a & mask) >>> 0) === ((p & mask) >>> 0);
}
function dnsDomainLevels(host) { return String(host).split('.').length - 1; }
function shExpMatch(str, shexp) {
  var re = new RegExp('^' + String(shexp).replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
  return re.test(String(str));
}
var __days = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
var __months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
function __gmt(args) { return args.length > 0 && args[args.length - 1] === 'GMT'; }
function __args(args) { var a = []; for (var i = 0; i < args.length; i++) if (args[i] !== 'GMT') a.push(args[i]); return a; }
function weekdayRange() {
  var d = new Date(), g = __gmt(arguments), a = __args(arguments);
  var today = g ? d.getUTCDay() : d.getDay();
  var w1 = __days.indexOf(String(a[0]).toUpperCase());
  if (a.length < 2) return today == w1;
  var w2 = __days.indexOf(String(a[1]).toUpperCase());
  return w1 <= w2 ? (today >= w1 && today <= w2) : (today >= w1 || today <= w2);
}
function __val(x) { var m = __months.indexOf(String(x).toUpperCase()); return m >= 0 ? { m: m } : (x > 31 ? { y: x } : { d: x }); }
function dateRange() {
  var dt = new Date(), g = __gmt(arguments), a = __args(arguments);
  var cur = { d: g ? dt.getUTCDate() : dt.getDate(), m: g ? dt.getUTCMonth() : dt.getMonth(), y: g ? dt.getUTCFullYear() : dt.getFullYear() };
  if (a.length == 1) { var v = __val(a[0]); for (var k in v) return cur[k] == v[k]; }
  if (a.length == 2) {
    var v1 = __val(a[0]), v2 = __val(a[1]);
    for (var k in v1) { var x = cur[k], lo = v1[k], hi = v2[k]; return lo <= hi ? (x >= lo && x <= hi) : (x >= lo || x <= hi); }
  }
  return true;
}
function timeRange() {
  var dt = new Date(), g = __gmt(arguments), a = __args(arguments);
  var h = g ? dt.getUTCHours() : dt.getHours(), mi = g ? dt.getUTCMinutes() : dt.getMinutes(), s = g ? dt.getUTCSeconds() : dt.getSeconds();
  var now = h * 3600 + mi * 60 + s, lo, hi;
  if (a.length == 1) return h == a[0];
  if (a.length == 2) { lo = a[0] * 3600; hi = a[1] * 3600 + 3599; }
  else if (a.length == 4) { lo = a[0] * 3600 + a[1] * 60; hi = a[2] * 3600 + a[3] * 60 + 59; }
  else if (a.length == 6) { lo = a[0] * 3600 + a[1] * 60 + a[2]; hi = a[3] * 3600 + a[4] * 60 + a[5]; }
  else return true;
  return lo <= hi ? (now >= lo && now <= hi) : (now >= lo || now <= hi);
}
function alert(msg) {}
"#;

fn arg_string(args: &[JsValue], i: usize, ctx: &mut Context) -> JsResult<String> {
    Ok(args.get_or_undefined(i).to_string(ctx)?.to_std_string_escaped())
}

/// dnsResolve(host): IPv4-адрес строкой или null.
fn dns_resolve(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let host = arg_string(args, 0, ctx)?;
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(JsValue::from(JsString::from(ip.to_string().as_str())));
    }
    let ip = (host.as_str(), 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.find(|a| a.is_ipv4()))
        .map(|a| a.ip().to_string());
    Ok(match ip {
        Some(ip) => JsValue::from(JsString::from(ip.as_str())),
        None => JsValue::null(),
    })
}

/// Вычислитель PAC. `Context` не `Send` — создавайте и используйте в одном потоке.
pub struct PacEngine {
    ctx: Context,
}

impl PacEngine {
    pub fn new(pac_source: &str, my_ip: &str) -> Result<Self, String> {
        let mut ctx = Context::default();
        let limits = ctx.runtime_limits_mut();
        limits.set_loop_iteration_limit(5_000_000);
        limits.set_recursion_limit(512);
        ctx.register_global_callable(JsString::from("dnsResolve"), 1, NativeFunction::from_fn_ptr(dns_resolve))
            .map_err(|e| e.to_string())?;
        let my_ip_js = format!(
            "function myIpAddress() {{ return {}; }}",
            serde_json::to_string(my_ip).unwrap_or_else(|_| "\"127.0.0.1\"".into())
        );
        for src in [PAC_UTILS, my_ip_js.as_str()] {
            ctx.eval(Source::from_bytes(src)).map_err(|e| format!("встроенные функции PAC: {e}"))?;
        }
        ctx.eval(Source::from_bytes(pac_source))
            .map_err(|e| format!("ошибка в PAC-файле: {e}"))?;
        let has = ctx
            .eval(Source::from_bytes("typeof FindProxyForURL === 'function'"))
            .map(|v| v.to_boolean())
            .unwrap_or(false);
        if !has {
            return Err("в PAC-файле нет функции FindProxyForURL(url, host)".into());
        }
        Ok(Self { ctx })
    }

    /// Результат `FindProxyForURL` для URL (например, `PROXY gw:3128; DIRECT`).
    pub fn find(&mut self, url: &str) -> Result<String, String> {
        let host = url_host(url);
        let call = format!(
            "FindProxyForURL({}, {})",
            serde_json::to_string(url).unwrap_or_default(),
            serde_json::to_string(&host).unwrap_or_default()
        );
        let v = self.ctx.eval(Source::from_bytes(&call)).map_err(|e| e.to_string())?;
        let s = v.to_string(&mut self.ctx).map_err(|e| e.to_string())?;
        Ok(s.to_std_string_escaped())
    }
}

/// Имя узла из URL (без схемы, учётных данных, порта и пути).
pub fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    host.to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacProxy {
    /// PROXY, HTTPS, SOCKS, SOCKS4, SOCKS5.
    pub kind: String,
    pub host: String,
    pub port: u16,
}

/// Прокси из ответа PAC (`PROXY a:3128; SOCKS5 b:1080; DIRECT`).
pub fn parse_result(s: &str) -> Vec<PacProxy> {
    s.split(';')
        .filter_map(|part| {
            let mut it = part.split_whitespace();
            let kind = it.next()?.to_ascii_uppercase();
            if kind == "DIRECT" {
                return None;
            }
            let addr = it.next()?;
            let default = match kind.as_str() {
                "HTTPS" => 443,
                k if k.starts_with("SOCKS") => 1080,
                _ => 80,
            };
            let (host, port) = crate::probe::split_host_port(addr, default).ok()?;
            Some(PacProxy { kind, host, port })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Загрузка PAC
// ---------------------------------------------------------------------------

fn decode_chunked(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let Some(nl) = body[i..].windows(2).position(|w| w == b"\r\n") else { break };
        let size_line = String::from_utf8_lossy(&body[i..i + nl]);
        let Ok(size) = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16) else { break };
        i += nl + 2;
        if size == 0 || i + size > body.len() {
            break;
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size + 2;
    }
    out
}

async fn read_all<S: tokio::io::AsyncRead + Unpin>(s: &mut S, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tokio::time::timeout(timeout, s.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                data.extend_from_slice(&buf[..n]);
                if data.len() > 4 << 20 {
                    return Err("слишком большой ответ".into());
                }
            }
            Ok(Err(e)) if data.is_empty() => return Err(e.to_string()),
            Ok(Err(_)) => break,
            Err(_) if data.is_empty() => return Err("нет ответа".into()),
            Err(_) => break,
        }
    }
    Ok(data)
}

fn split_http(data: &[u8]) -> Result<(u16, String, Vec<u8>), String> {
    let pos = data.windows(4).position(|w| w == b"\r\n\r\n").ok_or("ответ не является HTTP")?;
    let head = String::from_utf8_lossy(&data[..pos]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or("ответ не является HTTP")?;
    let mut body = data[pos + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        body = decode_chunked(&body);
    }
    Ok((status, head, body))
}

/// Загрузка PAC напрямую (без прокси) по http(s):// или из файла.
pub async fn fetch(source: &str, timeout: Duration) -> Result<String, String> {
    let src = source.trim();
    let lower = src.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        let path = src.strip_prefix("file://").unwrap_or(src);
        return std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"));
    }
    let url = crate::probe::Url::parse(src)?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: proxy-scanner\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header()
    );
    let stream = tokio::time::timeout(timeout, TcpStream::connect((url.host.as_str(), url.port)))
        .await
        .map_err(|_| format!("{}: нет ответа", url.host_header()))?
        .map_err(|e| format!("{}: {e}", url.host_header()))?;
    let data = if url.https {
        let mut tls = crate::probe::tls_connect(stream, &url.host, timeout).await?;
        tls.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        read_all(&mut tls, timeout).await?
    } else {
        let mut s = stream;
        s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        read_all(&mut s, timeout).await?
    };
    let (status, _, body) = split_http(&data)?;
    if status != 200 {
        return Err(format!("HTTP {status}"));
    }
    String::from_utf8(body).map_err(|_| "PAC-файл не в UTF-8".into())
}

// ---------------------------------------------------------------------------
// Системные настройки и WPAD
// ---------------------------------------------------------------------------

/// Одна найденная настройка прокси.
#[derive(Debug, Clone)]
pub struct SystemSetting {
    pub source: String,
    pub value: String,
    /// Если это адрес PAC-файла.
    pub pac_url: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub settings: Vec<SystemSetting>,
    /// DNS-суффиксы для поиска WPAD.
    pub suffixes: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinInfo {
    proxy_enable: Option<i64>,
    proxy_server: Option<String>,
    proxy_override: Option<String>,
    auto_config_url: Option<String>,
    policy_auto_config_url: Option<String>,
    policy_proxy_server: Option<String>,
    suffixes: Vec<String>,
    domain: Option<String>,
    win_http: Option<String>,
}

const PS_PROXY_SCRIPT: &str = "\
$i=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';\
$m=Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';\
$s=@((Get-DnsClientGlobalSetting).SuffixSearchList)+@(Get-DnsClient | Where-Object {$_.ConnectionSpecificSuffix} | ForEach-Object {$_.ConnectionSpecificSuffix});\
$w=(netsh winhttp show proxy) -join \"`n\";\
ConvertTo-Json -Compress -InputObject @{ProxyEnable=$i.ProxyEnable;ProxyServer=$i.ProxyServer;ProxyOverride=$i.ProxyOverride;\
AutoConfigURL=$i.AutoConfigURL;PolicyAutoConfigURL=$m.AutoConfigURL;PolicyProxyServer=$m.ProxyServer;\
Suffixes=@($s | Where-Object {$_});Domain=$env:USERDNSDOMAIN;WinHttp=$w}";

fn push(info: &mut SystemInfo, source: &str, value: &str, pac: bool) {
    let v = value.trim();
    if v.is_empty() {
        return;
    }
    info.settings.push(SystemSetting {
        source: source.into(),
        value: v.into(),
        pac_url: pac.then(|| v.to_string()),
    });
}

/// Настройки прокси этой ОС и DNS-суффиксы (блокирующий вызов).
pub fn system_info() -> SystemInfo {
    let mut info = SystemInfo::default();
    // Переменные окружения (есть и в Windows).
    for var in ["http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
        if let Ok(v) = std::env::var(var) {
            push(&mut info, &format!("переменная {var}"), &v, false);
        }
    }
    if cfg!(windows) {
        if let Ok(out) = run_powershell(PS_PROXY_SCRIPT)
            && let Some(start) = out.stdout.find('{')
            && let Ok(w) = serde_json::from_str::<WinInfo>(out.stdout[start..].trim())
        {
            let enabled = w.proxy_enable.unwrap_or(0) != 0;
            if let Some(v) = &w.proxy_server {
                let note = if enabled { "" } else { " (выключено)" };
                push(&mut info, &format!("Internet Settings: ProxyServer{note}"), v, false);
            }
            if let Some(v) = &w.proxy_override {
                push(&mut info, "Internet Settings: исключения", v, false);
            }
            if let Some(v) = &w.auto_config_url {
                push(&mut info, "Internet Settings: AutoConfigURL", v, true);
            }
            if let Some(v) = &w.policy_auto_config_url {
                push(&mut info, "Групповая политика: AutoConfigURL", v, true);
            }
            if let Some(v) = &w.policy_proxy_server {
                push(&mut info, "Групповая политика: ProxyServer", v, false);
            }
            if let Some(v) = &w.win_http {
                let v = v.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" · ");
                push(&mut info, "WinHTTP (netsh winhttp)", &v, false);
            }
            info.suffixes.extend(w.suffixes);
            if let Some(d) = w.domain {
                info.suffixes.push(d);
            }
        }
    } else {
        if let Ok(out) = run_cmd("gsettings", &["get", "org.gnome.system.proxy", "mode"]) {
            let mode = out.stdout.trim().trim_matches('\'').to_string();
            if !mode.is_empty() {
                push(&mut info, "GNOME: режим прокси", &mode, false);
            }
            if let Ok(o) = run_cmd("gsettings", &["get", "org.gnome.system.proxy", "autoconfig-url"]) {
                push(&mut info, "GNOME: PAC (autoconfig-url)", o.stdout.trim().trim_matches('\''), true);
            }
            if let (Ok(h), Ok(p)) = (
                run_cmd("gsettings", &["get", "org.gnome.system.proxy.http", "host"]),
                run_cmd("gsettings", &["get", "org.gnome.system.proxy.http", "port"]),
            ) {
                let host = h.stdout.trim().trim_matches('\'');
                if !host.is_empty() {
                    push(&mut info, "GNOME: HTTP-прокси", &format!("{host}:{}", p.stdout.trim()), false);
                }
            }
        }
        if let Ok(r) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in r.lines() {
                let mut it = line.split_whitespace();
                if let Some("search" | "domain") = it.next() {
                    info.suffixes.extend(it.map(String::from));
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    info.suffixes.retain(|s| {
        let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
        !s.is_empty() && seen.insert(s)
    });
    info
}

/// Адреса WPAD для DNS-суффиксов: wpad.a.b.corp.local → wpad.b.corp.local → wpad.corp.local.
pub fn wpad_candidates(suffixes: &[String]) -> Vec<String> {
    let mut out = vec!["http://wpad/wpad.dat".to_string()];
    for s in suffixes {
        let labels: Vec<&str> = s.trim().trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
        for i in 0..labels.len().saturating_sub(1) {
            let url = format!("http://wpad.{}/wpad.dat", labels[i..].join(".").to_ascii_lowercase());
            if !out.contains(&url) {
                out.push(url);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAC: &str = r#"
        function FindProxyForURL(url, host) {
            if (isPlainHostName(host) || dnsDomainIs(host, ".corp.local")) return "DIRECT";
            if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
            if (shExpMatch(url, "https://*.bank.ru/*")) return "PROXY ssl-gw:8080";
            if (isInNet(myIpAddress(), "192.168.5.0", "255.255.255.0")) return "PROXY branch-gw:3128; DIRECT";
            return "PROXY gw1.corp.local:3128; SOCKS5 gw2:1080; DIRECT";
        }
    "#;

    #[test]
    fn evaluates_pac_rules() {
        let mut e = PacEngine::new(PAC, "10.1.2.3").unwrap();
        assert_eq!(e.find("http://intranet/").unwrap(), "DIRECT");
        assert_eq!(e.find("https://portal.corp.local/x").unwrap(), "DIRECT");
        assert_eq!(e.find("http://10.20.30.40/").unwrap(), "DIRECT");
        assert_eq!(e.find("https://online.bank.ru/login").unwrap(), "PROXY ssl-gw:8080");
        assert_eq!(e.find("http://example.com/").unwrap(), "PROXY gw1.corp.local:3128; SOCKS5 gw2:1080; DIRECT");
        let mut branch = PacEngine::new(PAC, "192.168.5.17").unwrap();
        assert_eq!(branch.find("http://example.com/").unwrap(), "PROXY branch-gw:3128; DIRECT");
    }

    #[test]
    fn bad_pac_and_infinite_loop_are_errors() {
        assert!(PacEngine::new("function nope() {}", "1.2.3.4").is_err());
        assert!(PacEngine::new("function FindProxyForURL( {", "1.2.3.4").is_err());
        let mut e = PacEngine::new("function FindProxyForURL(u, h) { while (true) {} }", "1.2.3.4").unwrap();
        assert!(e.find("http://x/").is_err(), "лимит итераций останавливает бесконечный цикл");
    }

    #[test]
    fn helpers() {
        assert_eq!(url_host("https://user:pw@Host.Corp:8443/a?b"), "host.corp");
        assert_eq!(url_host("http://[::1]:80/"), "::1");
        let p = parse_result("PROXY gw:3128; HTTPS sec:443; SOCKS5 s5:1081; SOCKS s4; DIRECT");
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], PacProxy { kind: "PROXY".into(), host: "gw".into(), port: 3128 });
        assert_eq!(p[3].port, 1080);
        assert_eq!(
            wpad_candidates(&["dept.corp.local".into()]),
            vec!["http://wpad/wpad.dat", "http://wpad.dept.corp.local/wpad.dat", "http://wpad.corp.local/wpad.dat"]
        );
        assert_eq!(decode_chunked(b"4\r\nfunc\r\n2\r\nti\r\n0\r\n\r\n"), b"functi");
    }

    #[tokio::test]
    async fn fetches_pac_over_http() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let body = "function FindProxyForURL(u,h){return \"DIRECT\";}";
                let _ = s
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
                    .await;
            }
        });
        let text = fetch(&format!("http://127.0.0.1:{port}/wpad.dat"), Duration::from_secs(2)).await.unwrap();
        assert!(text.contains("FindProxyForURL"));
        assert!(fetch("/nonexistent/proxy.pac", Duration::from_secs(1)).await.is_err());
    }
}
