//! Обнаружение открытых портов: внешний masscan либо встроенный TCP-connect сканер.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::model::AppEvent;
use crate::targets::{TargetSet, ports_to_masscan};
use crate::util::hide_window_tokio;

/// Канал событий в интерфейс с автоматической перерисовкой.
#[derive(Clone)]
pub struct Tx {
    tx: std::sync::mpsc::Sender<AppEvent>,
    ctx: egui::Context,
}

impl Tx {
    pub fn new(tx: std::sync::mpsc::Sender<AppEvent>, ctx: egui::Context) -> Self {
        Self { tx, ctx }
    }

    pub fn send(&self, ev: AppEvent) {
        let _ = self.tx.send(ev);
        self.ctx.request_repaint();
    }

    pub fn log(&self, msg: impl Into<String>) {
        self.send(AppEvent::Log(msg.into()));
    }
}

// ---------------------------------------------------------------------------
// TCP-connect
// ---------------------------------------------------------------------------

pub struct TcpScanConfig {
    pub targets: TargetSet,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout: Duration,
}

/// Встроенный сканер: обычные TCP-подключения, права администратора не нужны.
pub async fn tcp_connect_scan(
    cfg: TcpScanConfig,
    tx: Tx,
    cancel: CancellationToken,
) -> Result<String, String> {
    let total = cfg.targets.total_hosts() * cfg.ports.len() as u64;
    let done = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));
    let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    let mut set: JoinSet<()> = JoinSet::new();

    // Периодический отчёт о прогрессе.
    let reporter = {
        let (done, found, tx, cancel) = (done.clone(), found.clone(), tx.clone(), cancel.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = cancel.cancelled() => break,
                }
                let d = done.load(Ordering::Relaxed);
                tx.send(AppEvent::Progress(
                    d as f32 / total.max(1) as f32,
                    format!(
                        "TCP-connect: {d} из {total}, открыто: {}",
                        found.load(Ordering::Relaxed)
                    ),
                ));
                if d >= total {
                    break;
                }
            }
        })
    };

    'outer: for ip in cfg.targets.iter() {
        for &port in &cfg.ports {
            let permit = tokio::select! {
                p = sem.clone().acquire_owned() => p.map_err(|e| e.to_string())?,
                _ = cancel.cancelled() => break 'outer,
            };
            let (tx, done, found) = (tx.clone(), done.clone(), found.clone());
            let timeout = cfg.timeout;
            set.spawn(async move {
                let addr = SocketAddr::from((ip, port));
                if let Ok(Ok(_stream)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await
                {
                    found.fetch_add(1, Ordering::Relaxed);
                    tx.send(AppEvent::Open {
                        ip,
                        port,
                        source: "tcp-connect",
                    });
                }
                done.fetch_add(1, Ordering::Relaxed);
                drop(permit);
            });
            // Не накапливаем завершённые задачи.
            while set.try_join_next().is_some() {}
        }
    }

    if cancel.is_cancelled() {
        set.abort_all();
    }
    while set.join_next().await.is_some() {}
    reporter.abort();

    let d = done.load(Ordering::Relaxed);
    let f = found.load(Ordering::Relaxed);
    if cancel.is_cancelled() {
        Err(format!("остановлено: проверено {d} из {total}, открыто: {f}"))
    } else {
        Ok(format!("TCP-connect: проверено {d}, открытых портов: {f}"))
    }
}

// ---------------------------------------------------------------------------
// masscan
// ---------------------------------------------------------------------------

pub struct MasscanConfig {
    pub exe: PathBuf,
    pub targets: TargetSet,
    pub ports: Vec<u16>,
    pub rate: u32,
    pub wait_secs: u32,
    pub adapter: String,
    pub source_ip: String,
    pub router_ip: String,
    pub router_mac: String,
    pub extra_args: String,
}

impl MasscanConfig {
    pub fn args(&self) -> Vec<String> {
        let mut a = vec![
            self.targets.to_masscan_arg(),
            format!("-p{}", ports_to_masscan(&self.ports)),
            "--rate".into(),
            self.rate.max(1).to_string(),
            "--wait".into(),
            self.wait_secs.to_string(),
            "--open-only".into(),
        ];
        let mut opt = |name: &str, value: &str| {
            let v = value.trim();
            if !v.is_empty() {
                a.push(name.into());
                a.push(v.into());
            }
        };
        opt("--adapter", &self.adapter);
        opt("--source-ip", &self.source_ip);
        opt("--router-ip", &self.router_ip);
        opt("--router-mac", &self.router_mac);
        a.extend(self.extra_args.split_whitespace().map(String::from));
        a
    }
}

/// `Discovered open port 3128/tcp on 10.0.0.5`
pub fn parse_masscan_discovered(line: &str) -> Option<(Ipv4Addr, u16)> {
    let rest = line.trim().strip_prefix("Discovered open port ")?;
    let (port_proto, ip) = rest.split_once(" on ")?;
    let (port, proto) = port_proto.split_once('/')?;
    if proto.trim() != "tcp" {
        return None;
    }
    let ip = ip.split_whitespace().next()?.parse().ok()?;
    Some((ip, port.trim().parse().ok()?))
}

/// Процент выполнения из строки состояния masscan:
/// `rate:  0.99-kpps, 45.31% done,   0:00:12 remaining, found=3`
pub fn parse_masscan_progress(line: &str) -> Option<f32> {
    let idx = line.find("% done")?;
    let head = &line[..idx];
    let start = head
        .rfind(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map(|i| i + 1)
        .unwrap_or(0);
    head[start..].parse::<f32>().ok().map(|p| p / 100.0)
}

/// Запуск masscan как дочернего процесса с разбором его вывода «на лету».
pub async fn masscan_scan(
    cfg: MasscanConfig,
    tx: Tx,
    cancel: CancellationToken,
) -> Result<String, String> {
    let args = cfg.args();
    tx.log(format!("запуск: {} {}", cfg.exe.display(), args.join(" ")));

    let mut cmd = tokio::process::Command::new(&cfg.exe);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    hide_window_tokio(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| {
        format!(
            "не удалось запустить {}: {e}. Укажите путь к masscan64.exe \
             или положите его рядом с программой.",
            cfg.exe.display()
        )
    })?;

    let stdout = child.stdout.take().ok_or("нет stdout")?;
    let mut stderr = child.stderr.take().ok_or("нет stderr")?;
    let found = Arc::new(AtomicU64::new(0));

    // stdout: строки «Discovered open port …»
    let out_task = {
        let (tx, found) = (tx.clone(), found.clone());
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some((ip, port)) = parse_masscan_discovered(&line) {
                    found.fetch_add(1, Ordering::Relaxed);
                    tx.send(AppEvent::Open {
                        ip,
                        port,
                        source: "masscan",
                    });
                } else if !line.trim().is_empty() {
                    tx.log(format!("masscan: {}", line.trim()));
                }
            }
        })
    };

    // stderr: строка состояния обновляется через «\r», поэтому читаем блоками.
    let err_task = {
        let (tx, found) = (tx.clone(), found.clone());
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let mut pending = String::new();
            let mut errors: Vec<String> = Vec::new();
            loop {
                let n = match stderr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                pending.push_str(&String::from_utf8_lossy(&buf[..n]));
                while let Some(pos) = pending.find(['\r', '\n']) {
                    let line: String = pending.drain(..=pos).collect();
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Some(p) = parse_masscan_progress(line) {
                        tx.send(AppEvent::Progress(
                            p.clamp(0.0, 1.0),
                            format!(
                                "masscan: {:.1}%, открыто: {}",
                                p * 100.0,
                                found.load(Ordering::Relaxed)
                            ),
                        ));
                    } else if let Some((ip, port)) = parse_masscan_discovered(line) {
                        found.fetch_add(1, Ordering::Relaxed);
                        tx.send(AppEvent::Open {
                            ip,
                            port,
                            source: "masscan",
                        });
                    } else {
                        if line.contains("FAIL") || line.contains("ERR") || line.contains("rror") {
                            errors.push(line.to_string());
                        }
                        tx.log(format!("masscan: {line}"));
                    }
                }
            }
            errors
        })
    };

    let status = tokio::select! {
        s = child.wait() => Some(s.map_err(|e| e.to_string())?),
        _ = cancel.cancelled() => {
            let _ = child.kill().await;
            None
        }
    };
    let _ = out_task.await;
    let errors = err_task.await.unwrap_or_default();
    let f = found.load(Ordering::Relaxed);

    match status {
        None => Err(format!("masscan остановлен, открытых портов: {f}")),
        Some(s) if s.success() => Ok(format!("masscan завершён, открытых портов: {f}")),
        Some(s) => {
            let detail = errors.last().cloned().unwrap_or_default();
            Err(format!(
                "masscan завершился с кодом {}{}",
                s.code().map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                if detail.is_empty() {
                    ". Проверьте, что установлен Npcap и программа запущена от имени администратора."
                        .to_string()
                } else {
                    format!(": {detail}")
                }
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::{parse_ports, parse_targets};

    #[test]
    fn masscan_lines() {
        assert_eq!(
            parse_masscan_discovered("Discovered open port 3128/tcp on 10.0.0.5     "),
            Some((Ipv4Addr::new(10, 0, 0, 5), 3128))
        );
        assert_eq!(parse_masscan_discovered("Discovered open port 53/udp on 10.0.0.5"), None);
        assert_eq!(parse_masscan_discovered("Starting masscan 1.3.2"), None);
        let p = parse_masscan_progress(
            "rate:  0.99-kpps, 45.31% done,   0:00:12 remaining, found=3",
        )
        .unwrap();
        assert!((p - 0.4531).abs() < 1e-4);
        assert_eq!(parse_masscan_progress("waiting several seconds to exit..."), None);
    }

    #[test]
    fn masscan_args() {
        let cfg = MasscanConfig {
            exe: "masscan64.exe".into(),
            targets: parse_targets("10.0.0.0/30").unwrap(),
            ports: parse_ports("3128,8080-8081").unwrap(),
            rate: 500,
            wait_secs: 3,
            adapter: "\\Device\\NPF_{X}".into(),
            source_ip: "10.0.0.2".into(),
            router_ip: "10.0.0.1".into(),
            router_mac: " ".into(),
            extra_args: "--retries 2".into(),
        };
        assert_eq!(
            cfg.args().join(" "),
            "10.0.0.0-10.0.0.3 -p3128,8080-8081 --rate 500 --wait 3 --open-only \
             --adapter \\Device\\NPF_{X} --source-ip 10.0.0.2 --router-ip 10.0.0.1 --retries 2"
        );
    }

    #[tokio::test]
    async fn tcp_scan_finds_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stx, srx) = std::sync::mpsc::channel();
        let tx = Tx::new(stx, egui::Context::default());
        let cfg = TcpScanConfig {
            targets: parse_targets("127.0.0.1").unwrap(),
            ports: vec![port],
            concurrency: 4,
            timeout: Duration::from_secs(2),
        };
        let res = tcp_connect_scan(cfg, tx, CancellationToken::new()).await;
        assert!(res.is_ok());
        let open: Vec<_> = srx
            .try_iter()
            .filter_map(|e| match e {
                AppEvent::Open { ip, port, .. } => Some((ip, port)),
                _ => None,
            })
            .collect();
        assert_eq!(open, vec![(Ipv4Addr::LOCALHOST, port)]);
    }
}
