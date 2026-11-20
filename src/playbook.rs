//! Сценарии проверок: последовательность инструментов в файле JSON. Один и тот же
//! движок выполняет сценарий в окне (вкладка «Сценарии») и из командной строки
//! (`playbook файл.json -o отчёт.html`).
//!
//! ```json
//! { "name": "Приёмка филиала",
//!   "steps": [
//!     { "tool": "discovery", "set": { "targets": "{subnet}" } },
//!     { "tool": "services",  "set": { "targets": "{hosts}" } },
//!     { "tool": "audit",     "set": { "targets": "{hosts}" } },
//!     { "tool": "tls",       "set": { "targets": "{tls_hosts}" } },
//!     { "tool": "ad",        "preset": "Быстро" } ] }
//! ```
//!
//! Подстановки в строковых значениях: `{subnet}` — подсеть этой машины, `{hosts}` —
//! живые узлы, найденные предыдущими шагами, `{tls_hosts}` — узлы с HTTPS/TLS-портами,
//! `{smb_hosts}` — узлы с SMB/NFS, `{dns_servers}` — DNS-серверы этой машины.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::presets::{self, Store};
use crate::toolui::Results;
use crate::tools::{self, Sink};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Playbook {
    pub name: String,
    pub description: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Step {
    /// discovery, services, tls, audit, shares, ad, dns, mtr, matrix, urlcheck, sitecheck, snmp.
    pub tool: String,
    pub title: String,
    pub preset: String,
    pub set: serde_json::Map<String, Value>,
}

/// Инструменты, которые умеет выполнять сценарий: (ключ, название).
pub const TOOLS: &[(&str, &str)] = &[
    ("discovery", "Узлы"),
    ("services", "Сервисы"),
    ("audit", "Аудит"),
    ("tls", "TLS"),
    ("shares", "Общие ресурсы"),
    ("ad", "Домен AD"),
    ("dns", "DNS"),
    ("mtr", "MTR"),
    ("matrix", "Доступность"),
    ("urlcheck", "Проверка URL"),
    ("sitecheck", "Почему не открывается"),
    ("snmp", "Коммутаторы (SNMP)"),
];

pub fn tool_title(key: &str) -> &str {
    TOOLS.iter().find(|t| t.0 == key).map(|t| t.1).unwrap_or(key)
}

impl Step {
    pub fn label(&self) -> String {
        if self.title.is_empty() { tool_title(&self.tool).to_string() } else { self.title.clone() }
    }
}

/// Готовые сценарии.
pub fn builtin() -> Vec<Playbook> {
    let step = |tool: &str, set: Value| Step {
        tool: tool.into(),
        set: set.as_object().cloned().unwrap_or_default(),
        ..Default::default()
    };
    use serde_json::json;
    vec![
        Playbook {
            name: "Приёмка нового сегмента".into(),
            description: "Узлы → сервисы → аудит → TLS → общие ресурсы: что есть в подсети и что с ним не так".into(),
            steps: vec![
                step("discovery", json!({"targets": "{subnet}"})),
                step("services", json!({"targets": "{hosts}"})),
                step("audit", json!({"targets": "{hosts}"})),
                step("tls", json!({"targets": "{tls_hosts}"})),
                step("shares", json!({"targets": "{smb_hosts}"})),
            ],
        },
        Playbook {
            name: "Почему не работает домен".into(),
            description: "Домен AD, DNS-записи контроллеров, время, SMB".into(),
            steps: vec![
                step("ad", json!({})),
                step("dns", json!({"names": "_ldap._tcp.dc._msdcs.{domain}\n_kerberos._tcp.{domain}", "types": "SRV", "servers": "system"})),
            ],
        },
        Playbook {
            name: "Быстрый аудит подсети".into(),
            description: "Только опасные настройки: SMBv1, Telnet, RDP без NLA, SNMP public, Redis без пароля".into(),
            steps: vec![step("discovery", json!({"targets": "{subnet}"})), step("audit", json!({"targets": "{hosts}"}))],
        },
    ]
}

pub fn user_dir() -> PathBuf {
    crate::session::default_path().with_file_name("proxy-scanner-playbooks")
}

/// Сценарии пользователя из папки рядом с программой.
pub fn load_user() -> Vec<(PathBuf, Playbook)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(user_dir()) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "json")
                && let Ok(t) = std::fs::read_to_string(&p)
                && let Ok(pb) = serde_json::from_str::<Playbook>(&t)
            {
                out.push((p, pb));
            }
        }
    }
    out.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    out
}

pub fn save_user(pb: &Playbook) -> Result<PathBuf, String> {
    let dir = user_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let name = crate::session::sanitize(&pb.name);
    let path = dir.join(format!("{}.json", if name.is_empty() { "сценарий".into() } else { name }));
    std::fs::write(&path, serde_json::to_string_pretty(pb).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(path)
}

#[derive(Debug, Clone)]
pub enum Event {
    Step(usize, String),
    Done(usize, String),
    Log(String),
    Finished(Box<Results>),
}

/// Что найдено предыдущими шагами — для подстановок.
#[derive(Default)]
struct Found {
    hosts: BTreeSet<Ipv4Addr>,
    tls: BTreeSet<Ipv4Addr>,
    smb: BTreeSet<Ipv4Addr>,
}

impl Found {
    fn add(&mut self, ip: Ipv4Addr, port: Option<u16>) {
        self.hosts.insert(ip);
        if let Some(p) = port {
            if [443, 636, 993, 995, 3269, 8443, 9443].contains(&p) {
                self.tls.insert(ip);
            }
            if [139, 445, 2049].contains(&p) {
                self.smb.insert(ip);
            }
        }
    }
}

fn join(set: &BTreeSet<Ipv4Addr>) -> String {
    set.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
}

fn substitute(v: &mut Value, f: &Found, subnet: &str, dns: &str) {
    match v {
        Value::String(s) => {
            *s = s
                .replace("{subnet}", subnet)
                .replace("{hosts}", &join(&f.hosts))
                .replace("{tls_hosts}", &join(&f.tls))
                .replace("{smb_hosts}", &join(&f.smb))
                .replace("{dns_servers}", dns);
        }
        Value::Array(a) => a.iter_mut().for_each(|x| substitute(x, f, subnet, dns)),
        Value::Object(m) => m.values_mut().for_each(|x| substitute(x, f, subnet, dns)),
        _ => {}
    }
}

fn config<T: Serialize + DeserializeOwned + Default>(step: &Step, store: &Store, set: &Value) -> Result<T, String> {
    let mut cfg = T::default();
    if !step.preset.is_empty() {
        let p = store
            .find(&step.tool, &step.preset)
            .or_else(|| store.find(presets::ALL_TOOLS, &step.preset))
            .ok_or_else(|| format!("пресет «{}» не найден", step.preset))?;
        let values = if p.tool == presets::ALL_TOOLS { p.values.get(&step.tool).cloned().unwrap_or(Value::Null) } else { p.values.clone() };
        if !values.is_null() {
            presets::apply(&mut cfg, &values)?;
        }
    }
    presets::apply(&mut cfg, set)?;
    Ok(cfg)
}

/// Запустить инструмент и собрать все его события.
async fn collect<E: Send + 'static, F, Fut>(cancel: &CancellationToken, start: F) -> Vec<E>
where
    F: FnOnce(Sink<E>, CancellationToken) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (sink, rx) = Sink::new(None);
    start(sink, cancel.clone()).await;
    rx.try_iter().collect()
}

/// Выполнить сценарий. Пустые подстановки (например, `{hosts}`, если предыдущий шаг
/// ничего не нашёл) — шаг пропускается.
pub async fn execute(pb: Playbook, store: Store, subnet: Option<String>, sink: Sink<Event>, cancel: CancellationToken) {
    let mut res = Results::default();
    let mut found = Found::default();
    let subnet = subnet.unwrap_or_default();
    let dns = tokio::task::spawn_blocking(tools::dns::system_servers)
        .await
        .unwrap_or_default()
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    for (i, step) in pb.steps.iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        sink.send(Event::Step(i, step.label()));
        let mut set = Value::Object(step.set.clone());
        let before = set.clone();
        substitute(&mut set, &found, &subnet, &dns);
        let empty_target = set
            .as_object()
            .is_some_and(|m| m.iter().any(|(k, v)| ["targets", "target", "names", "switches"].contains(&k.as_str()) && v.as_str().is_some_and(|s| s.trim().is_empty())))
            && set != before;
        if empty_target {
            sink.send(Event::Done(i, "пропущен: предыдущие шаги не нашли подходящих узлов".into()));
            continue;
        }
        let summary = match run_step(step, &store, &set, &cancel, &mut res, &mut found).await {
            Ok(s) => s,
            Err(e) => format!("ошибка: {e}"),
        };
        sink.send(Event::Done(i, summary));
    }
    sink.send(Event::Finished(Box::new(res)));
}

async fn run_step(step: &Step, store: &Store, set: &Value, cancel: &CancellationToken, res: &mut Results, found: &mut Found) -> Result<String, String> {
    use tools::*;
    let c = cancel;
    Ok(match step.tool.as_str() {
        "discovery" => {
            let cfg: discovery::Config = config(step, store, set)?;
            let mut r = discovery::Report::default();
            for e in collect(c, |s, c| discovery::run(cfg, s, c)).await {
                if let discovery::Event::Host(h) = e
                    && h.alive
                {
                    found.add(h.ip, None);
                    for p in &h.open_ports {
                        found.add(h.ip, Some(*p));
                    }
                    r.hosts.push(*h);
                }
            }
            r.hosts.sort_by_key(|h| h.ip);
            let s = format!("живых узлов: {}", r.hosts.len());
            res.discovery = Some(r);
            s
        }
        "services" => {
            let cfg: services::Config = config(step, store, set)?;
            let mut r = services::Report::default();
            for e in collect(c, |s, c| services::run(cfg, s, c)).await {
                if let services::Event::Found(x) = e {
                    found.add(x.ip, Some(x.port));
                    r.services.push(*x);
                }
            }
            let s = format!("сервисов: {}", r.services.len());
            res.services = Some(r);
            s
        }
        "audit" => {
            let cfg: audit::Config = config(step, store, set)?;
            let mut r = audit::Report::default();
            for e in collect(c, |s, c| audit::run(cfg, s, c)).await {
                match e {
                    audit::Event::Issue(x) => r.issues.push(*x),
                    audit::Event::Service(x) => r.services.push(*x),
                    _ => {}
                }
            }
            r.issues.sort_by_key(|x| x.severity);
            let s = format!(
                "находок: {} (высокая важность: {})",
                r.issues.len(),
                r.count(tlsaudit::Severity::High)
            );
            res.audit = Some(r);
            s
        }
        "tls" => {
            let cfg: tlsaudit::Config = config(step, store, set)?;
            let mut r = tlsaudit::Report::default();
            for e in collect(c, |s, c| tlsaudit::run(cfg, s, c)).await {
                if let tlsaudit::Event::Target(x) = e {
                    r.targets.push(*x);
                }
            }
            let s = format!("TLS-портов: {}", r.targets.len());
            res.tls = Some(r);
            s
        }
        "shares" => {
            let cfg: shares::Config = config(step, store, set)?;
            let mut r = shares::Report::default();
            for e in collect(c, |s, c| shares::run(cfg, s, c)).await {
                if let shares::Event::Host(h, sh) = e {
                    r.hosts.push(*h);
                    r.shares.extend(sh);
                }
            }
            let s = format!("ресурсов: {}", r.shares.len());
            res.shares = Some(r);
            s
        }
        "ad" => {
            let cfg: ad::Config = config(step, store, set)?;
            let mut out = String::from("нет ответа");
            for e in collect(c, |s, c| ad::run(cfg, s, c)).await {
                match e {
                    ad::Event::Report(r) => {
                        out = r.verdict.clone();
                        res.ad = Some(*r);
                    }
                    ad::Event::Log(l) => out = l,
                }
            }
            out
        }
        "dns" => {
            let cfg: dns::Config = config(step, store, set)?;
            let mut r = dns::Report::default();
            for e in collect(c, |s, c| dns::run(cfg, s, c)).await {
                if let dns::Event::Answer(a) = e {
                    r.answers.push(*a);
                }
            }
            let bad = r.answers.iter().filter(|a| a.error.is_some() || a.rcode != "NOERROR").count();
            let s = format!("ответов: {}, с ошибкой: {bad}", r.answers.len());
            res.dns = Some(r);
            s
        }
        "mtr" => {
            let mut cfg: mtr::Config = config(step, store, set)?;
            if cfg.cycles == 0 {
                cfg.cycles = 10;
            }
            let mut r = mtr::Report { target: cfg.target.clone(), ..Default::default() };
            for e in collect(c, |s, c| mtr::run(cfg, s, c)).await {
                match e {
                    mtr::Event::Resolved(a) => r.address = Some(a),
                    mtr::Event::Method(m) => r.method = m,
                    mtr::Event::Hops(h) => r.hops = h,
                    mtr::Event::Cycle(n) => r.cycles = n,
                    mtr::Event::Pmtu(p) => r.pmtu = Some(p),
                    _ => {}
                }
            }
            let s = format!("хопов: {}", r.hops.len());
            res.mtr = Some(r);
            s
        }
        "matrix" => {
            let cfg: matrix::Config = config(step, store, set)?;
            let mut r = matrix::Report {
                source: crate::session::computer_name(),
                at: crate::session::now_unix(),
                ..Default::default()
            };
            for e in collect(c, |s, c| matrix::run(cfg, s, c)).await {
                if let matrix::Event::Entry(x) = e {
                    r.entries.push(*x);
                }
            }
            let s = format!("правил: {}, расхождений: {}", r.entries.len(), r.mismatches());
            res.matrix.get_or_insert_with(Vec::new).push(r);
            s
        }
        "urlcheck" => {
            let cfg: urlcheck::Config = config(step, store, set)?;
            let mut r = urlcheck::Report::default();
            for e in collect(c, |s, c| urlcheck::run(cfg, s, c)).await {
                if let urlcheck::Event::Row(x) = e {
                    r.rows.push(*x);
                }
            }
            let s = format!("проверок: {}, расхождений: {}", r.rows.len(), r.mismatches());
            res.urlcheck = Some(r);
            s
        }
        "sitecheck" => {
            let cfg: sitecheck::Config = config(step, store, set)?;
            let mut r = sitecheck::Report { url: cfg.url.clone(), ..Default::default() };
            for e in collect(c, |s, c| sitecheck::run(cfg, s, c)).await {
                match e {
                    sitecheck::Event::Step(x) => r.steps.push(*x),
                    sitecheck::Event::Verdict(v, ok) => {
                        r.verdict = v;
                        r.ok = ok;
                    }
                    sitecheck::Event::Log(l) => r.verdict = vec![l],
                }
            }
            let s = r.verdict.first().cloned().unwrap_or_default();
            res.sitecheck = Some(r);
            s
        }
        "snmp" => {
            let cfg: snmp::Config = config(step, store, set)?;
            let mut r = snmp::Report::default();
            for e in collect(c, |s, c| snmp::run(cfg, s, c)).await {
                if let snmp::Event::Switch(x) = e {
                    r.switches.push(*x);
                }
            }
            let ok = r.switches.iter().filter(|s| s.error.is_none()).count();
            let s = format!("коммутаторов: {ok} из {}", r.switches.len());
            res.snmp = Some(r);
            s
        }
        other => return Err(format!("неизвестный инструмент «{other}»")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution() {
        let mut f = Found::default();
        f.add("10.0.0.5".parse().unwrap(), Some(443));
        f.add("10.0.0.6".parse().unwrap(), Some(445));
        let mut v = serde_json::json!({"targets": "{hosts}", "x": ["{tls_hosts}", "{smb_hosts} {subnet}"]});
        substitute(&mut v, &f, "10.0.0.0/24", "10.0.0.1");
        assert_eq!(v["targets"], "10.0.0.5, 10.0.0.6");
        assert_eq!(v["x"][0], "10.0.0.5");
        assert_eq!(v["x"][1], "10.0.0.6 10.0.0.0/24");
    }

    #[test]
    fn builtins_parse() {
        let (store, _) = Store::load(std::env::temp_dir().join("ps-test-no-presets.json"));
        for pb in builtin() {
            for st in &pb.steps {
                assert!(TOOLS.iter().any(|t| t.0 == st.tool), "{}", st.tool);
                // Конфигурация строится (с неподставленными шаблонами).
                let set = Value::Object(st.set.clone());
                let ok = match st.tool.as_str() {
                    "discovery" => config::<tools::discovery::Config>(st, &store, &set).is_ok(),
                    "services" => config::<tools::services::Config>(st, &store, &set).is_ok(),
                    "audit" => config::<tools::audit::Config>(st, &store, &set).is_ok(),
                    "tls" => config::<tools::tlsaudit::Config>(st, &store, &set).is_ok(),
                    "shares" => config::<tools::shares::Config>(st, &store, &set).is_ok(),
                    "ad" => config::<tools::ad::Config>(st, &store, &set).is_ok(),
                    "dns" => config::<tools::dns::Config>(st, &store, &set).is_ok(),
                    _ => true,
                };
                assert!(ok, "{} {}", pb.name, st.tool);
            }
        }
    }

    #[tokio::test]
    async fn run_matrix_playbook() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let pb = Playbook {
            name: "t".into(),
            steps: vec![
                Step { tool: "matrix".into(), set: serde_json::json!({"rules": format!("127.0.0.1:{port} open")}).as_object().unwrap().clone(), ..Default::default() },
                Step { tool: "services".into(), set: serde_json::json!({"targets": "{hosts}"}).as_object().unwrap().clone(), ..Default::default() },
            ],
            ..Default::default()
        };
        let (store, _) = Store::load(std::env::temp_dir().join("ps-test-no-presets.json"));
        let (sink, rx) = Sink::new(None);
        execute(pb, store, None, sink, CancellationToken::new()).await;
        let ev: Vec<Event> = rx.try_iter().collect();
        let done: Vec<String> = ev.iter().filter_map(|e| if let Event::Done(_, s) = e { Some(s.clone()) } else { None }).collect();
        assert!(done[0].contains("расхождений: 0"), "{done:?}");
        assert!(done[1].contains("пропущен"), "{done:?}");
        assert!(matches!(ev.last(), Some(Event::Finished(r)) if r.matrix.is_some()));
    }
}
