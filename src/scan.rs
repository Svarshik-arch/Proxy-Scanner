//! Обнаружение открытых портов: внешний masscan либо встроенный TCP-connect сканер.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::model::{AppEvent, Checkpoint};
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
    /// Пропустить столько первых адресов (продолжение прерванного сканирования).
    pub skip_hosts: u64,
    /// Повторов подключения при таймауте (отказ в подключении не повторяется).
    pub retries: u32,
}

/// Число первых адресов, полностью проверенных по всем портам.
fn hosts_watermark(per_host: &[AtomicU32], from: usize, ports: u32) -> usize {
    let mut w = from;
    while w < per_host.len() && per_host[w].load(Ordering::Relaxed) >= ports {
        w += 1;
    }
    w
}

/// Встроенный сканер: обычные TCP-подключения, права администратора не нужны.
pub async fn tcp_connect_scan(
    cfg: TcpScanConfig,
    tx: Tx,
    cancel: CancellationToken,
) -> Result<String, String> {
    let hosts_total = cfg.targets.total_hosts();
    let skip = cfg.skip_hosts.min(hosts_total);
    let nports = cfg.ports.len() as u64;
    let total = hosts_total * nports;
    // Ранее проверенные адреса учитываются в прогрессе сразу.
    let done = Arc::new(AtomicU64::new(skip * nports));
    let found = Arc::new(AtomicU64::new(0));
    let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
    // Счётчик проверенных портов по каждому оставшемуся адресу.
    let remaining = (hosts_total - skip) as usize;
    let per_host: Arc<Vec<AtomicU32>> = Arc::new((0..remaining).map(|_| AtomicU32::new(0)).collect());
    let mut set: JoinSet<()> = JoinSet::new();

    if skip > 0 {
        tx.log(format!("продолжение: пропущено {skip} уже проверенных адресов из {hosts_total}"));
    }

    // Периодический отчёт о прогрессе и контрольные точки.
    let reporter = {
        let (done, found, tx, cancel, per_host) =
            (done.clone(), found.clone(), tx.clone(), cancel.clone(), per_host.clone());
        let nports32 = nports as u32;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            let mut watermark = 0usize;
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
                let w = hosts_watermark(&per_host, watermark, nports32);
                if w != watermark {
                    watermark = w;
                    tx.send(AppEvent::Checkpoint(Checkpoint::TcpHostsDone(skip + w as u64)));
                }
                if d >= total {
                    break;
                }
            }
        })
    };

    'outer: for (h, ip) in cfg.targets.iter().skip(skip as usize).enumerate() {
        for &port in &cfg.ports {
            let permit = tokio::select! {
                p = sem.clone().acquire_owned() => p.map_err(|e| e.to_string())?,
                _ = cancel.cancelled() => break 'outer,
            };
            let (tx, done, found, per_host) = (tx.clone(), done.clone(), found.clone(), per_host.clone());
            let timeout = cfg.timeout;
            let retries = cfg.retries;
            set.spawn(async move {
                let addr = SocketAddr::from((ip, port));
                let mut open = false;
                for _ in 0..=retries {
                    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                        Ok(Ok(_stream)) => {
                            open = true;
                            break;
                        }
                        // Явный отказ — порт закрыт, повторять незачем.
                        Ok(Err(_)) => break,
                        // Таймаут — пакет мог потеряться, пробуем ещё раз.
                        Err(_) => {}
                    }
                }
                if open {
                    found.fetch_add(1, Ordering::Relaxed);
                    tx.send(AppEvent::Open {
                        ip,
                        port,
                        source: "tcp-connect",
                    });
                }
                per_host[h].fetch_add(1, Ordering::Relaxed);
                done.fetch_add(1, Ordering::Relaxed);
                drop(permit);
            });
            // Не накапливаем завершённые задачи.
            while set.try_join_next().is_some() {}
        }
    }

    if cancel.is_cancelled() {
        // Даём уже начатым подключениям завершиться — так контрольная точка точнее.
        let _ = tokio::time::timeout(cfg.timeout + Duration::from_millis(200), async {
            while set.join_next().await.is_some() {}
        })
        .await;
        set.abort_all();
    }
    while set.join_next().await.is_some() {}
    reporter.abort();

    let w = hosts_watermark(&per_host, 0, nports as u32);
    tx.send(AppEvent::Checkpoint(Checkpoint::TcpHostsDone(skip + w as u64)));

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

#[derive(Clone)]
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
    /// Зерно порядка обхода: при продолжении должно совпадать.
    pub seed: u64,
    /// С какого индекса продолжать (0 — с начала).
    pub resume_index: u64,
}

impl MasscanConfig {
    /// Общее число пакетов, от которого masscan считает «% done».
    pub fn range(&self) -> u64 {
        let base = self.targets.total_hosts() * self.ports.len() as u64;
        base + self.retries() * self.rate as u64
    }

    fn retries(&self) -> u64 {
        let mut it = self.extra_args.split_whitespace();
        while let Some(a) = it.next() {
            if let Some(v) = a.strip_prefix("--retries=") {
                return v.parse().unwrap_or(0);
            }
            if a == "--retries" {
                return it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
        }
        0
    }

    /// Индекс для продолжения по проценту выполнения. Берём с запасом назад
    /// (ответы на последние пакеты могли не успеть прийти) и с учётом
    /// округления процента до сотых.
    pub fn checkpoint_index(&self, fraction: f32) -> u64 {
        let range = self.range();
        let index = (fraction.clamp(0.0, 1.0) as f64 * range as f64) as u64;
        let margin = self.rate as u64 * (self.wait_secs.max(2) as u64 + 1) + range / 10_000 + 1;
        index.saturating_sub(margin).max(self.resume_index.min(index))
    }

    pub fn args(&self) -> Vec<String> {
        let mut a = vec![
            self.targets.to_masscan_arg(),
            format!("-p{}", ports_to_masscan(&self.ports)),
            "--rate".into(),
            self.rate.max(1).to_string(),
            "--wait".into(),
            self.wait_secs.to_string(),
            "--open-only".into(),
            "--seed".into(),
            self.seed.to_string(),
        ];
        if self.resume_index > 0 {
            a.push("--resume-index".into());
            a.push(self.resume_index.to_string());
        }
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
    let checkpoint = {
        let probe = cfg.clone();
        move |p: f32| probe.checkpoint_index(p)
    };
    if cfg.resume_index > 0 {
        tx.log(format!("продолжение masscan с индекса {} (seed {})", cfg.resume_index, cfg.seed));
    }
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
                        tx.send(AppEvent::Checkpoint(Checkpoint::MasscanIndex(checkpoint(p))));
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
            seed: 42,
            resume_index: 0,
        };
        assert_eq!(
            cfg.args().join(" "),
            "10.0.0.0-10.0.0.3 -p3128,8080-8081 --rate 500 --wait 3 --open-only --seed 42 \
             --adapter \\Device\\NPF_{X} --source-ip 10.0.0.2 --router-ip 10.0.0.1 --retries 2"
        );
        // 4 адреса × 3 порта + retries 2 × rate 500
        assert_eq!(cfg.range(), 12 + 1000);
        let resumed = MasscanConfig { resume_index: 7, ..cfg.clone() };
        assert!(resumed.args().join(" ").contains("--seed 42 --resume-index 7 "));
    }

    #[test]
    fn masscan_checkpoint_has_safety_margin() {
        let cfg = MasscanConfig {
            exe: "masscan64.exe".into(),
            targets: parse_targets("10.0.0.0/16").unwrap(),
            ports: parse_ports("3128,8080").unwrap(),
            rate: 1000,
            wait_secs: 3,
            adapter: String::new(),
            source_ip: String::new(),
            router_ip: String::new(),
            router_mac: String::new(),
            extra_args: String::new(),
            seed: 1,
            resume_index: 0,
        };
        let range = 65_536 * 2;
        assert_eq!(cfg.range(), range);
        assert_eq!(cfg.checkpoint_index(0.0), 0);
        let half = cfg.checkpoint_index(0.5);
        // запас: 1000 пакетов/с × 4 с + 0,01 % диапазона
        assert_eq!(half, range / 2 - (4000 + range / 10_000 + 1));
        assert!(cfg.checkpoint_index(1.0) < range);
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
            skip_hosts: 0,
            retries: 0,
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

    #[tokio::test]
    async fn tcp_scan_resumes_and_reports_checkpoints() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stx, srx) = std::sync::mpsc::channel();
        let tx = Tx::new(stx, egui::Context::default());
        // 127.0.0.1-4: первые два адреса уже проверены, слушатель на .1 не должен найтись.
        let cfg = TcpScanConfig {
            targets: parse_targets("127.0.0.1-127.0.0.4").unwrap(),
            ports: vec![port],
            concurrency: 4,
            timeout: Duration::from_millis(500),
            skip_hosts: 2,
            retries: 1,
        };
        tcp_connect_scan(cfg, tx, CancellationToken::new()).await.unwrap();
        let events: Vec<AppEvent> = srx.try_iter().collect();
        assert!(!events.iter().any(|e| matches!(e, AppEvent::Open { .. })));
        let last = events
            .iter()
            .filter_map(|e| match e {
                AppEvent::Checkpoint(Checkpoint::TcpHostsDone(n)) => Some(*n),
                _ => None,
            })
            .next_back();
        assert_eq!(last, Some(4));
    }

    #[test]
    fn watermark_counts_leading_complete_hosts() {
        let v: Vec<AtomicU32> = [3, 3, 1, 3].iter().map(|&n| AtomicU32::new(n)).collect();
        assert_eq!(hosts_watermark(&v, 0, 3), 2);
        assert_eq!(hosts_watermark(&v, 2, 3), 2);
        v[2].store(3, Ordering::Relaxed);
        assert_eq!(hosts_watermark(&v, 2, 3), 4);
    }
}
