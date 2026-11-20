//! Командная строка: те же инструменты без окна, вывод текстом или в JSON.
//!
//! ```text
//! proxy-scanner-cli dns example.com MX @8.8.8.8 --json
//! proxy-scanner-cli mtr 10.0.0.1 --preset "Непрерывно"
//! proxy-scanner-cli tls portal.corp.local -p 443,8443 --preset "Закрытый контур"
//! proxy-scanner-cli services 10.0.0.0/24 --set tcp_ports=22,80,443
//! ```

use std::io::Write as _;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::presets::{self, Store};
use crate::tools::{Sink, discovery, dns, hostinfo, http, mtr, services, tlsaudit};

const COMMANDS: &[(&str, &str, &str)] = &[
    ("host", "host", "состояние этой машины: интерфейсы, маршруты, ARP, соединения"),
    ("mtr", "mtr", "трассировка с наблюдением (ICMP/UDP/TCP), поиск MTU"),
    ("ping", "mtr", "ping узла (ICMP, или TCP: --set mode=Tcp --set port=443)"),
    ("discover", "discovery", "обнаружение узлов: ICMP, TCP, ARP, NetBIOS, mDNS, SSDP"),
    ("dns", "dns", "DNS-запросы как dig: имя [тип…] [@сервер…]"),
    ("http", "http", "HTTP-запрос как curl -v с таймингами"),
    ("services", "services", "сканер сервисов и версий (TCP и UDP)"),
    ("tls", "tls", "TLS-аудит: версии, шифры, сертификаты"),
    ("proxy", "proxy", "поиск и диагностика прокси (TCP-connect + проверки)"),
    ("ad", "ad", "проверка домена AD: контроллеры, Kerberos, LDAP, время, SMB"),
    ("audit", "audit", "аудит небезопасных настроек в сети"),
    ("monitor", "monitor", "мониторинг: проверки из файла или --set checks=…, по расписанию"),
    ("matrix", "matrix", "матрица доступности: matrix правила.txt (узел:порт open|closed)"),
    ("listen", "", "слушатель для проверки доступа сюда: listen 443,1433"),
    ("certs", "", "сертификаты из файла сессии: certs сессия.json [-o certs.csv]"),
    ("compare", "", "сравнение сессий: compare было.json стало.json"),
    ("service", "", "мониторинг без окна: service install|uninstall|status [--config файл]"),
    ("report", "", "HTML-отчёт по файлу сессии: report сессия.json -o отчёт.html"),
    ("presets", "", "список пресетов: presets [инструмент]"),
    ("help", "", "справка"),
];

fn is_command(s: &str) -> bool {
    COMMANDS.iter().any(|(c, _, _)| *c == s) || ["trace", "scan", "--help", "-h", "--cli"].contains(&s)
}

/// Вызов из основной (оконной) программы: если первым аргументом идёт команда,
/// выполнить её в консоли и вернуть код выхода.
pub fn dispatch_from_gui_binary() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let first = args.first()?;
    if !is_command(first) {
        return None;
    }
    #[cfg(windows)]
    {
        // Оконная программа не имеет консоли — подключаемся к консоли родителя.
        // SAFETY: простой вызов WinAPI без указателей.
        unsafe {
            windows_sys::Win32::System::Console::AttachConsole(windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS);
        }
    }
    let args = if first == "--cli" { args[1..].to_vec() } else { args };
    Some(run_args(args))
}

/// Точка входа консольной программы `proxy-scanner-cli`.
pub fn main_from_env() -> i32 {
    run_args(std::env::args().skip(1).collect())
}

#[derive(Debug, Default)]
struct Opts {
    positional: Vec<String>,
    presets: Vec<String>,
    sets: Vec<(String, String)>,
    config: Option<String>,
    out: Option<String>,
    json: bool,
    quiet: bool,
    fields: bool,
    ports: Option<String>,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut it = args.iter();
    let need = |it: &mut std::slice::Iter<String>, flag: &str| it.next().cloned().ok_or_else(|| format!("{flag}: нужно значение"));
    while let Some(a) = it.next() {
        match a.as_str() {
            "--preset" => o.presets.push(need(&mut it, a)?),
            "--set" | "-s" => {
                let kv = need(&mut it, a)?;
                let (k, v) = kv.split_once('=').ok_or_else(|| format!("--set {kv}: нужно поле=значение"))?;
                o.sets.push((k.trim().to_string(), v.to_string()));
            }
            "--config" => o.config = Some(need(&mut it, a)?),
            "--out" | "-o" => o.out = Some(need(&mut it, a)?),
            "-p" | "--ports" => o.ports = Some(need(&mut it, a)?),
            "--json" => o.json = true,
            "-q" | "--quiet" => o.quiet = true,
            "--fields" => o.fields = true,
            "--renderer" => {
                let _ = it.next();
            }
            s if s.starts_with("--") => return Err(format!("неизвестный параметр {s}")),
            s => o.positional.push(s.to_string()),
        }
    }
    Ok(o)
}

/// Значение для `--set`: JSON (числа, true/false, массивы) или строка.
fn set_value(v: &str) -> Value {
    match serde_json::from_str::<Value>(v) {
        Ok(j @ (Value::Number(_) | Value::Bool(_) | Value::Array(_) | Value::Object(_) | Value::Null)) => j,
        _ => Value::String(v.to_string()),
    }
}

fn configure<T: Serialize + DeserializeOwned + Default>(tool: &str, o: &Opts, store: &Store, primary: Value) -> Result<T, String> {
    let mut cfg = T::default();
    for name in &o.presets {
        let p = store
            .find(tool, name)
            .or_else(|| store.find(presets::ALL_TOOLS, name))
            .ok_or_else(|| format!("пресет «{name}» не найден (см. `presets {tool}`)"))?;
        let values = if p.tool == presets::ALL_TOOLS {
            p.values.get(tool).cloned().unwrap_or(Value::Null)
        } else {
            p.values.clone()
        };
        if !values.is_null() {
            presets::apply(&mut cfg, &values)?;
        }
    }
    if let Some(path) = &o.config {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
        presets::apply(&mut cfg, &v)?;
    }
    if primary.as_object().is_some_and(|m| !m.is_empty()) {
        presets::apply(&mut cfg, &primary)?;
    }
    let mut sets = serde_json::Map::new();
    for (k, v) in &o.sets {
        sets.insert(k.clone(), set_value(v));
    }
    if !sets.is_empty() {
        let known = serde_json::to_value(&cfg).map_err(|e| e.to_string())?;
        for k in sets.keys() {
            if known.get(k).is_none() {
                return Err(format!("неизвестное поле «{k}»; список полей: {tool} --fields"));
            }
        }
        presets::apply(&mut cfg, &Value::Object(sets))?;
    }
    Ok(cfg)
}

fn eprint_line(quiet: bool, s: &str) {
    if !quiet {
        eprintln!("{s}");
    }
}

/// Запуск инструмента с обработкой Ctrl+C: события собираются в `fold`.
fn drive<E, F, Fut>(o: &Opts, start: F, mut fold: impl FnMut(E)) -> Result<(), String>
where
    E: Send + 'static,
    F: FnOnce(Sink<E>, CancellationToken) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    let (sink, rx) = Sink::new(None);
    let cancel = CancellationToken::new();
    let fut = start(sink, cancel.clone());
    let quiet = o.quiet;
    rt.block_on(async {
        let mut task = tokio::spawn(fut);
        let c2 = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                if !quiet {
                    eprintln!("\nостановка…");
                }
                c2.cancel();
            }
        });
        loop {
            tokio::select! {
                _ = &mut task => break,
                _ = tokio::time::sleep(Duration::from_millis(150)) => {}
            }
            for e in rx.try_iter() {
                fold(e);
            }
        }
        for e in rx.try_iter() {
            fold(e);
        }
    });
    Ok(())
}

fn emit<R: Serialize>(o: &Opts, report: &R, text: impl FnOnce(&R) -> String) -> Result<(), String> {
    let out = if o.json {
        serde_json::to_string_pretty(report).map_err(|e| e.to_string())?
    } else {
        text(report)
    };
    match &o.out {
        Some(path) => std::fs::write(path, out).map_err(|e| format!("{path}: {e}")),
        None => {
            let mut so = std::io::stdout().lock();
            let _ = writeln!(so, "{out}");
            Ok(())
        }
    }
}

fn help() -> String {
    let mut s = format!(
        "Proxy Scanner {} — сетевая диагностика из командной строки\n\n\
         Использование: proxy-scanner-cli <команда> [цели…] [параметры]\n\n",
        env!("CARGO_PKG_VERSION")
    );
    for (c, _, d) in COMMANDS {
        s += &format!("  {c:<10} {d}\n");
    }
    s += "\nПараметры:\n\
          \x20 --preset ИМЯ      применить пресет (можно несколько, по порядку; общие: «Открытый контур», «Закрытый контур»)\n\
          \x20 --set поле=знач   изменить поле конфигурации (список полей: <команда> --fields)\n\
          \x20 --config файл     взять конфигурацию из JSON-файла\n\
          \x20 -p, --ports       порты (services: tcp_ports, tls, proxy)\n\
          \x20 --json            вывод в JSON\n\
          \x20 -o, --out файл    записать результат в файл\n\
          \x20 -q, --quiet       без сообщений о ходе работы\n\n\
          Примеры:\n\
          \x20 dns example.com MX TXT @8.8.8.8 @tls://1.1.1.1\n\
          \x20 dns _ldap._tcp.dc._msdcs.{domain} SRV\n\
          \x20 mtr 10.10.0.1 --preset \"Поиск MTU (VPN, туннели)\"\n\
          \x20 ping 10.0.0.5 --set cycles=20\n\
          \x20 http https://portal.corp.local/ --set proxy_mode=Manual --set proxy=10.0.0.10:3128\n\
          \x20 services 10.0.0.0/24 --preset \"Windows и AD\" --json -o ad.json\n\
          \x20 tls 10.0.0.0/24 -p 443,8443 --preset \"Только сертификаты\"\n\
          \x20 discover 192.168.1.0/24\n\
          \x20 proxy 10.0.0.0/16 --preset \"Порты: все популярные\" --json\n";
    s
}

fn fields<T: Serialize + Default>() -> String {
    let v = serde_json::to_value(T::default()).unwrap_or(Value::Null);
    let mut s = String::from("Поля конфигурации и значения по умолчанию:\n");
    if let Value::Object(m) = v {
        for (k, v) in m {
            s += &format!("  {k} = {v}\n");
        }
    }
    s
}

pub fn run_args(args: Vec<String>) -> i32 {
    let Some(cmd) = args.first().cloned() else {
        print!("{}", help());
        return 0;
    };
    let o = match parse_opts(&args[1..]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ошибка: {e}");
            return 2;
        }
    };
    let (store, warn) = Store::load(presets::default_path());
    if let Some(w) = warn {
        eprint_line(o.quiet, &format!("пресеты: {w}"));
    }
    let res = match cmd.as_str() {
        "help" | "--help" | "-h" => {
            print!("{}", help());
            Ok(())
        }
        "presets" => {
            let filter = o.positional.first().map(String::as_str);
            for (id, title) in std::iter::once(&(presets::ALL_TOOLS, "Общие")).chain(presets::TOOLS.iter()) {
                if filter.is_some_and(|f| f != *id) {
                    continue;
                }
                let list = store.for_tool(id);
                if list.is_empty() {
                    continue;
                }
                println!("[{id}] {title}");
                for p in list {
                    println!(
                        "  {}{}{}",
                        if p.builtin { "" } else { "★ " },
                        p.name,
                        if p.description.is_empty() { String::new() } else { format!(" — {}", p.description) }
                    );
                }
            }
            Ok(())
        }
        "host" => {
            let r = hostinfo::collect();
            emit(&o, &r, hostinfo::render_text)
        }
        "mtr" | "trace" | "ping" => cmd_mtr(&o, &store, cmd == "ping"),
        "discover" => cmd_discover(&o, &store),
        "dns" => cmd_dns(&o, &store),
        "http" => cmd_http(&o, &store),
        "services" | "scan" => cmd_services(&o, &store),
        "tls" => cmd_tls(&o, &store),
        "proxy" => cmd_proxy(&o, &store),
        "ad" => cmd_ad(&o, &store),
        "audit" => cmd_audit(&o, &store),
        "monitor" => cmd_monitor(&o, &store),
        "report" => cmd_report(&o),
        "matrix" => cmd_matrix(&o, &store),
        "listen" => cmd_listen(&o),
        "certs" => cmd_certs(&o),
        "compare" => cmd_compare(&o),
        "service" => cmd_service(&o, &store),
        other => Err(format!("неизвестная команда «{other}»; см. help")),
    };
    match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ошибка: {e}");
            2
        }
    }
}

fn targets_json(field: &str, o: &Opts) -> Value {
    if o.positional.is_empty() {
        json!({})
    } else {
        json!({ field: o.positional.join(", ") })
    }
}

fn cmd_mtr(o: &Opts, store: &Store, ping: bool) -> Result<(), String> {
    if o.fields {
        print!("{}", fields::<mtr::Config>());
        return Ok(());
    }
    let mut primary = targets_json("target", o);
    if ping {
        // Ping — проба сразу с большим TTL: один «хоп» — сам узел.
        presets::merge(&mut primary, &json!({ "first_hop": 64, "max_hops": 64, "resolve_names": false }));
    }
    let cfg: mtr::Config = configure("mtr", o, store, primary)?;
    if cfg.target.trim().is_empty() {
        return Err("укажите узел".into());
    }
    let mut report = mtr::Report {
        target: cfg.target.clone(),
        ..Default::default()
    };
    let quiet = o.quiet;
    drive(o, |s, c| mtr::run(cfg, s, c), |e| match e {
        mtr::Event::Log(m) => eprint_line(quiet, &m),
        mtr::Event::Resolved(ip) => report.address = Some(ip),
        mtr::Event::Method(m) => report.method = m,
        mtr::Event::Hops(h) => report.hops = h,
        mtr::Event::Cycle(n) => {
            report.cycles = n;
            if !quiet {
                eprint!("\rцикл {n}");
            }
        }
        mtr::Event::Pmtu(p) => report.pmtu = Some(p),
    })?;
    eprint_line(quiet, "");
    if ping {
        for h in &mut report.hops {
            h.ttl = 0;
        }
    }
    emit(o, &report, mtr::render_text)
}

fn cmd_discover(o: &Opts, store: &Store) -> Result<(), String> {
    if o.fields {
        print!("{}", fields::<discovery::Config>());
        return Ok(());
    }
    let cfg: discovery::Config = configure("discovery", o, store, targets_json("targets", o))?;
    let mut report = discovery::Report::default();
    let quiet = o.quiet;
    let mut total = 0;
    drive(o, |s, c| discovery::run(cfg, s, c), |e| match e {
        discovery::Event::Log(m) => eprint_line(quiet, &m),
        discovery::Event::Total(t) => total = t,
        discovery::Event::Progress(n) => {
            if !quiet {
                eprint!("\r{n}/{total}");
            }
        }
        discovery::Event::Host(h) => report.hosts.push(*h),
    })?;
    eprint_line(quiet, &format!("\nнайдено узлов: {}", report.hosts.iter().filter(|h| h.alive).count()));
    emit(o, &report, discovery::render_text)
}

fn cmd_dns(o: &Opts, store: &Store) -> Result<(), String> {
    if o.fields {
        print!("{}", fields::<dns::Config>());
        return Ok(());
    }
    // Как в dig: имена, типы и @серверы вперемешку.
    let (mut names, mut types, mut servers) = (Vec::new(), Vec::new(), Vec::new());
    for a in &o.positional {
        if let Some(s) = a.strip_prefix('@') {
            servers.push(s.to_string());
        } else if crate::tools::dnsproto::TYPES.iter().any(|(n, _)| n.eq_ignore_ascii_case(a)) {
            types.push(a.to_ascii_uppercase());
        } else {
            names.push(a.clone());
        }
    }
    let mut primary = serde_json::Map::new();
    if !names.is_empty() {
        primary.insert("names".into(), json!(names.join("\n")));
    }
    if !types.is_empty() {
        primary.insert("types".into(), json!(types.join(" ")));
    }
    if !servers.is_empty() {
        primary.insert("servers".into(), json!(servers.join(", ")));
    }
    let cfg: dns::Config = configure("dns", o, store, Value::Object(primary))?;
    let mut report = dns::Report::default();
    let quiet = o.quiet;
    drive(o, |s, c| dns::run(cfg, s, c), |e| match e {
        dns::Event::Log(m) => eprint_line(quiet, &m),
        dns::Event::Total(_) => {}
        dns::Event::Answer(a) => report.answers.push(*a),
    })?;
    emit(o, &report, dns::render_text)
}

fn cmd_http(o: &Opts, store: &Store) -> Result<(), String> {
    if o.fields {
        print!("{}", fields::<http::Config>());
        return Ok(());
    }
    let mut cfg: http::Config = configure("http", o, store, targets_json("url", o))?;
    if cfg.url.trim().is_empty() {
        return Err("укажите URL".into());
    }
    if let Ok(p) = std::env::var("PROXY_SCANNER_PROXY_PASSWORD") {
        cfg.proxy_pass = p;
    }
    let mut report = http::Report::default();
    let mut current = Vec::new();
    let quiet = o.quiet;
    drive(o, |s, c| http::run(cfg, s, c), |e| match e {
        http::Event::Log(m) => eprint_line(quiet, &m),
        http::Event::Hop(h) => current.push(*h),
        http::Event::RunDone(_) => report.runs.push(std::mem::take(&mut current)),
    })?;
    if !current.is_empty() {
        report.runs.push(current);
    }
    emit(o, &report, http::render_text)
}

fn cmd_services(o: &Opts, store: &Store) -> Result<(), String> {
    if o.fields {
        print!("{}", fields::<services::Config>());
        return Ok(());
    }
    let mut primary = targets_json("targets", o);
    if let Some(p) = &o.ports {
        presets::merge(&mut primary, &json!({ "tcp_ports": p }));
    }
    let cfg: services::Config = configure("services", o, store, primary)?;
    let mut report = services::Report::default();
    let quiet = o.quiet;
    let mut total = 0;
    drive(o, |s, c| services::run(cfg, s, c), |e| match e {
        services::Event::Log(m) => eprint_line(quiet, &m),
        services::Event::Total(t) => total = t,
        services::Event::Progress(n) => {
            if !quiet {
                eprint!("\r{n}/{total}");
            }
        }
        services::Event::Found(s) => report.services.push(*s),
    })?;
    eprint_line(quiet, "");
    report.services.sort_by_key(|s| (s.ip, s.proto.clone(), s.port));
    emit(o, &report, services::render_text)
}

fn cmd_tls(o: &Opts, store: &Store) -> Result<(), String> {
    if o.fields {
        print!("{}", fields::<tlsaudit::Config>());
        return Ok(());
    }
    let mut primary = targets_json("targets", o);
    if let Some(p) = &o.ports {
        presets::merge(&mut primary, &json!({ "ports": p }));
    }
    let cfg: tlsaudit::Config = configure("tls", o, store, primary)?;
    let mut report = tlsaudit::Report::default();
    let quiet = o.quiet;
    drive(o, |s, c| tlsaudit::run(cfg, s, c), |e| match e {
        tlsaudit::Event::Log(m) => eprint_line(quiet, &m),
        tlsaudit::Event::Total(_) => {}
        tlsaudit::Event::Target(t) => {
            if !quiet {
                eprintln!("{}:{} — {}", t.host, t.port, t.grade);
            }
            report.targets.push(*t)
        }
    })?;
    report.targets.sort_by(|a, b| (a.host.as_str(), a.port).cmp(&(b.host.as_str(), b.port)));
    emit(o, &report, tlsaudit::render_text)
}

fn cmd_ad(o: &Opts, store: &Store) -> Result<(), String> {
    use crate::tools::ad;
    if o.fields {
        print!("{}", fields::<ad::Config>());
        return Ok(());
    }
    let cfg: ad::Config = configure("ad", o, store, targets_json("domain", o))?;
    let mut report = None;
    let quiet = o.quiet;
    drive(o, |s, c| ad::run(cfg, s, c), |e| match e {
        ad::Event::Log(m) => eprint_line(quiet, &m),
        ad::Event::Report(r) => report = Some(*r),
    })?;
    let report = report.ok_or("проверка не выполнена")?;
    emit(o, &report, ad::render_text)
}

fn cmd_audit(o: &Opts, store: &Store) -> Result<(), String> {
    use crate::tools::audit;
    if o.fields {
        print!("{}", fields::<audit::Config>());
        return Ok(());
    }
    let mut primary = targets_json("targets", o);
    if let Some(p) = &o.ports {
        presets::merge(&mut primary, &json!({ "tcp_ports": p }));
    }
    let cfg: audit::Config = configure("audit", o, store, primary)?;
    let mut report = audit::Report::default();
    let quiet = o.quiet;
    let mut total = 0;
    drive(o, |s, c| audit::run(cfg, s, c), |e| match e {
        audit::Event::Log(m) => eprint_line(quiet, &m),
        audit::Event::Total(t) => total = t,
        audit::Event::Progress(n) => {
            if !quiet {
                eprint!("\r{n}/{total}");
            }
        }
        audit::Event::Service(s) => report.services.push(*s),
        audit::Event::Issue(i) => report.issues.push(*i),
    })?;
    eprint_line(quiet, "");
    audit::sort(&mut report);
    emit(o, &report, audit::render_text)
}

/// Мониторинг: изменения состояния печатаются сразу, итог — после Ctrl+C или N циклов.
fn cmd_monitor(o: &Opts, store: &Store) -> Result<(), String> {
    use crate::tools::monitor;
    if o.fields {
        print!("{}", fields::<monitor::Config>());
        return Ok(());
    }
    // Позиционный аргумент — файл со списком проверок.
    let primary = match o.positional.first() {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            json!({ "checks": text })
        }
        None => json!({}),
    };
    let cfg: monitor::Config = configure("monitor", o, store, primary)?;
    let keep = cfg.history.max(10);
    let mut report = monitor::Report::default();
    let quiet = o.quiet;
    drive(o, |s, c| monitor::run(cfg, s, c), |e| {
        if let monitor::Event::Log(m) = &e {
            eprint_line(quiet, m);
        }
        if let Some(ch) = monitor::fold(&mut report, e, keep) {
            println!(
                "{} {:<9} {} ({})",
                crate::session::format_time(ch.at),
                ch.to.label(),
                ch.line,
                ch.detail
            );
        }
    })?;
    emit(o, &report, monitor::render_text)
}

fn cmd_matrix(o: &Opts, store: &Store) -> Result<(), String> {
    use crate::tools::matrix;
    if o.fields {
        print!("{}", fields::<matrix::Config>());
        return Ok(());
    }
    let primary = match o.positional.first() {
        Some(path) => json!({ "rules": std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))? }),
        None => json!({}),
    };
    let cfg: matrix::Config = configure("matrix", o, store, primary)?;
    let mut report = matrix::new_report();
    let quiet = o.quiet;
    drive(o, |s, c| matrix::run(cfg, s, c), |e| match e {
        matrix::Event::Log(m) => eprint_line(quiet, &m),
        matrix::Event::Total(_) => {}
        matrix::Event::Entry(x) => report.entries.push(*x),
    })?;
    matrix::sort(&mut report);
    let mismatches = report.mismatches();
    emit(o, &report, |r| matrix::render_text(std::slice::from_ref(r)))?;
    if mismatches > 0 {
        eprint_line(quiet, &format!("расхождений: {mismatches}"));
    }
    Ok(())
}

fn cmd_listen(o: &Opts) -> Result<(), String> {
    let ports = crate::targets::parse_ports(o.positional.first().ok_or("укажите порты: listen 443,1433")?)?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let cancel = CancellationToken::new();
        let (ok, errs) = crate::egress::start_listener(&ports, cancel.clone()).await;
        for e in &errs {
            eprintln!("не занят {e}");
        }
        if ok.is_empty() {
            return Err("ни один порт не занят".to_string());
        }
        println!(
            "Слушаю порты {} (отвечаю меткой {} {}). Ctrl+C — стоп.",
            ok.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
            crate::egress::MARKER,
            crate::session::computer_name()
        );
        let _ = tokio::signal::ctrl_c().await;
        cancel.cancel();
        Ok(())
    })
}

fn cmd_certs(o: &Opts) -> Result<(), String> {
    let path = o.positional.first().ok_or("укажите файл сессии: certs proxy-scanner-session.json")?;
    let s = crate::session::load(std::path::Path::new(path))?;
    let list = crate::tools::certs::collect(&s);
    if let Some(out) = &o.out
        && out.to_ascii_lowercase().ends_with(".csv")
    {
        return std::fs::write(out, crate::tools::certs::to_csv(&list, 30)).map_err(|e| format!("{out}: {e}"));
    }
    emit(o, &list, |l| crate::tools::certs::render_text(l, 30))
}

fn cmd_compare(o: &Opts) -> Result<(), String> {
    let [a, b] = o.positional.as_slice() else {
        return Err("укажите два файла сессии: compare было.json стало.json".into());
    };
    let old = crate::session::load(std::path::Path::new(a))?;
    let new = crate::session::load(std::path::Path::new(b))?;
    let d = crate::tools::compare::diff(&old, &new);
    emit(o, &d, crate::tools::compare::render_text)
}

fn cmd_service(o: &Opts, store: &Store) -> Result<(), String> {
    use crate::tools::service;
    match o.positional.first().map(String::as_str) {
        Some("install") => {
            let cfg: crate::tools::monitor::Config = configure("monitor", o, store, json!({}))?;
            println!("{}", service::install(&cfg)?);
        }
        Some("uninstall") | Some("remove") => println!("{}", service::uninstall()?),
        Some("status") | None => println!("{}", service::status()),
        Some(x) => return Err(format!("неизвестное действие «{x}»: install, uninstall, status")),
    }
    Ok(())
}

fn cmd_report(o: &Opts) -> Result<(), String> {
    let path = o.positional.first().ok_or("укажите файл сессии: report proxy-scanner-session.json -o отчёт.html")?;
    let s = crate::session::load(std::path::Path::new(path))?;
    let html = crate::report::html(&s, &format!("Сетевая диагностика — {}", s.computer));
    match &o.out {
        Some(p) => std::fs::write(p, html).map_err(|e| format!("{p}: {e}")),
        None => {
            print!("{html}");
            Ok(())
        }
    }
}

/// Поиск прокси без окна: TCP-connect по целям, затем диагностика каждого открытого порта.
fn cmd_proxy(o: &Opts, store: &Store) -> Result<(), String> {
    use crate::model::{AppEvent, ProxyRow, RowState, Settings};
    if o.fields {
        print!("{}", fields::<Settings>());
        return Ok(());
    }
    let mut primary = targets_json("targets", o);
    if let Some(p) = &o.ports {
        presets::merge(&mut primary, &json!({ "ports": p }));
    }
    let mut settings: Settings = configure("proxy", o, store, primary)?;
    if let Ok(p) = std::env::var("PROXY_SCANNER_PROXY_PASSWORD") {
        settings.proxy_pass = p;
    }
    let targets = crate::targets::parse_targets(&settings.targets)?;
    if targets.is_empty() {
        return Err("укажите цели".into());
    }
    if targets.total_hosts() > crate::targets::TCP_SCAN_MAX_HOSTS {
        return Err(format!("в командной строке поддерживается TCP-connect до {} адресов", crate::targets::TCP_SCAN_MAX_HOSTS));
    }
    let ports = crate::targets::parse_ports(&settings.ports)?;
    let probe_cfg = std::sync::Arc::new(crate::probe::probe_config(&settings)?);
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    let (tx, rx) = std::sync::mpsc::channel();
    let quiet = o.quiet;
    let cancel = CancellationToken::new();
    let scan_cfg = crate::scan::TcpScanConfig {
        targets,
        ports,
        concurrency: settings.tcp_concurrency.max(1),
        timeout: Duration::from_millis(settings.tcp_timeout_ms.max(50)),
        skip_hosts: 0,
        retries: settings.tcp_retries,
    };
    let mut open = Vec::new();
    rt.block_on(async {
        let c2 = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                c2.cancel();
            }
        });
        let txw = crate::scan::Tx::new(tx, egui::Context::default());
        let mut task = tokio::spawn(crate::scan::tcp_connect_scan(scan_cfg, txw, cancel.clone()));
        loop {
            tokio::select! {
                _ = &mut task => break,
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            }
            for e in rx.try_iter() {
                match e {
                    AppEvent::Open { ip, port, .. } => open.push((ip, port)),
                    AppEvent::Progress(p, _) if !quiet => eprint!("\rобнаружение {:.0}%", p * 100.0),
                    AppEvent::Log(m) if !quiet => eprintln!("\n{m}"),
                    _ => {}
                }
            }
        }
        for e in rx.try_iter() {
            if let AppEvent::Open { ip, port, .. } = e {
                open.push((ip, port));
            }
        }
    });
    eprint_line(quiet, &format!("\nоткрытых портов: {}", open.len()));
    let mut rows: Vec<ProxyRow> = Vec::new();
    if settings.auto_probe && !cancel.is_cancelled() {
        let results = rt.block_on(async {
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(settings.probe_concurrency.max(1)));
            let mut set = tokio::task::JoinSet::new();
            for (ip, port) in open.clone() {
                let (sem, cfg) = (sem.clone(), probe_cfg.clone());
                set.spawn(async move {
                    let _p = sem.acquire_owned().await;
                    (ip, port, crate::probe::probe_endpoint(ip, port, &cfg).await)
                });
            }
            let mut out = Vec::new();
            while let Some(r) = set.join_next().await {
                if let Ok(r) = r {
                    if !quiet {
                        eprint!("\rдиагностика {}/{}", out.len() + 1, open.len());
                    }
                    out.push(r);
                }
            }
            out
        });
        eprint_line(quiet, "");
        for (ip, port, res) in results {
            let mut row = ProxyRow::new(ip, port, "tcp-connect");
            row.kind = res.kind.unwrap_or(crate::model::ProxyKind::Unknown);
            row.ssl = res.ssl.unwrap_or(crate::model::SslInspection::Unknown);
            row.state = if res.error.is_some() { RowState::Error } else { RowState::Done };
            row.probe = res;
            rows.push(row);
        }
    } else {
        rows = open.iter().map(|(ip, port)| ProxyRow::new(*ip, *port, "tcp-connect")).collect();
    }
    rows.sort_by_key(|r| (r.ip, r.port));
    let refs: Vec<&ProxyRow> = rows.iter().collect();
    if o.json {
        let text = crate::export::to_json(&refs)?;
        return match &o.out {
            Some(p) => std::fs::write(p, text).map_err(|e| format!("{p}: {e}")),
            None => {
                println!("{text}");
                Ok(())
            }
        };
    }
    if let Some(p) = &o.out
        && p.to_ascii_lowercase().ends_with(".csv")
    {
        return crate::export::save(std::path::Path::new(p), &refs);
    }
    let mut s = format!("{:<21} {:<14} {:<22} {:<10} {:<14} {}\n", "адрес", "тип", "аутентификация", "CONNECT", "SSL-инспекция", "Server");
    for r in &rows {
        s += &format!(
            "{:<21} {:<14} {:<22} {:<10} {:<14} {}\n",
            format!("{}:{}", r.ip, r.port),
            r.kind.label(),
            r.auth_label(),
            r.probe.connect_status.map(|c| c.to_string()).unwrap_or("-".into()),
            r.ssl.label(),
            r.probe.server
        );
    }
    match &o.out {
        Some(p) => std::fs::write(p, s).map_err(|e| format!("{p}: {e}")),
        None => {
            print!("{s}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opts_and_values() {
        let a: Vec<String> = ["example.com", "--set", "cycles=3", "--preset", "Быстро", "--json", "-p", "443"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = parse_opts(&a).unwrap();
        assert_eq!(o.positional, vec!["example.com"]);
        assert_eq!(o.sets, vec![("cycles".into(), "3".into())]);
        assert!(o.json);
        assert_eq!(o.ports.as_deref(), Some("443"));
        assert_eq!(set_value("3"), json!(3));
        assert_eq!(set_value("true"), json!(true));
        assert_eq!(set_value("22,80"), json!("22,80"));
        assert!(parse_opts(&["--bogus".into()]).is_err());
    }

    #[test]
    fn configure_layers() {
        let (store, _) = Store::load(std::env::temp_dir().join("no-such-presets.json"));
        let o = Opts {
            presets: vec!["Закрытый контур".into(), "DNSSEC".into()],
            sets: vec![("timeout_ms".into(), "500".into())],
            ..Default::default()
        };
        let cfg: dns::Config = configure("dns", &o, &store, json!({ "names": "x.test" })).unwrap();
        assert_eq!(cfg.servers, "system");
        assert!(cfg.dnssec);
        assert_eq!(cfg.timeout_ms, 500);
        assert_eq!(cfg.names, "x.test");
        let bad = Opts {
            sets: vec![("nope".into(), "1".into())],
            ..Default::default()
        };
        assert!(configure::<dns::Config>("dns", &bad, &store, json!({})).is_err());
    }

    #[test]
    fn commands_run() {
        assert_eq!(run_args(vec!["help".into()]), 0);
        assert_eq!(run_args(vec!["presets".into(), "dns".into()]), 0);
        assert_eq!(run_args(vec!["dns".into(), "--fields".into()]), 0);
        assert_eq!(run_args(vec!["bogus".into()]), 2);
        assert_eq!(run_args(vec!["mtr".into(), "-q".into()]), 2);
    }
}
