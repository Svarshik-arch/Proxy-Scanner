//! Замер скорости между двумя машинами с этой программой: TCP в несколько потоков
//! (вход и выход) и UDP с потерями и джиттером. Свой протокол, порт 5202.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use super::Sink;

pub const PORT: u16 = 5202;
const MAGIC: &[u8; 4] = b"PSSP";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// К серверу (отдача).
    Up,
    /// От сервера (загрузка).
    Down,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: String,
    pub port: u16,
    pub streams: usize,
    pub seconds: u64,
    pub direction: Direction,
    /// UDP: скорость, Мбит/с (0 — не проверять UDP).
    pub udp_mbps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self { server: String::new(), port: PORT, streams: 4, seconds: 10, direction: Direction::Both, udp_mbps: 0 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UdpResult {
    pub sent: u64,
    pub received: u64,
    pub lost_pct: f64,
    pub jitter_ms: f64,
    pub out_of_order: u64,
    pub mbps: f64,
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    /// Направление, секунда от начала, Мбит/с за интервал.
    Point(Direction, f64, f64),
    /// Итог направления, Мбит/с.
    Total(Direction, f64),
    Udp(UdpResult),
    Error(String),
    /// Сервер: подключился клиент.
    Client(String),
}

// ---------------------------------------------------------------------------
// Сервер
// ---------------------------------------------------------------------------

async fn serve_tcp(mut s: TcpStream, sink: Sink<Event>) -> std::io::Result<()> {
    let mut hdr = [0u8; 13];
    s.read_exact(&mut hdr).await?;
    if &hdr[..4] != MAGIC {
        return Ok(());
    }
    let secs = u64::from_be_bytes(hdr[5..13].try_into().unwrap()).min(300);
    let peer = s.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let _ = s.set_nodelay(true);
    match hdr[4] {
        b'U' => {
            sink.send(Event::Client(format!("{peer}: отдаёт нам ({secs} с)")));
            let mut buf = vec![0u8; 256 * 1024];
            while s.read(&mut buf).await? > 0 {}
        }
        b'D' => {
            sink.send(Event::Client(format!("{peer}: забирает у нас ({secs} с)")));
            let buf = vec![0x5au8; 256 * 1024];
            let end = Instant::now() + Duration::from_secs(secs);
            while Instant::now() < end {
                s.write_all(&buf).await?;
            }
            s.shutdown().await?;
        }
        b'R' => {
            // Отчёт UDP по номеру сессии.
            let id = u64::from_be_bytes(hdr[5..13].try_into().unwrap());
            let r = UDP_SESSIONS.lock().ok().and_then(|mut m| m.remove(&id));
            let mut out = Vec::new();
            if let Some(st) = r {
                out.extend(st.received.to_be_bytes());
                out.extend(st.max_seq.to_be_bytes());
                out.extend(st.out_of_order.to_be_bytes());
                out.extend(st.jitter_us().to_be_bytes());
                out.extend(st.bytes.to_be_bytes());
                out.extend(st.span_us().to_be_bytes());
            }
            s.write_all(&out).await?;
        }
        _ => {}
    }
    Ok(())
}

#[derive(Default)]
struct UdpStat {
    received: u64,
    max_seq: u64,
    out_of_order: u64,
    bytes: u64,
    /// Оценка джиттера по RFC 3550, мкс × 16.
    jitter: f64,
    last_transit: Option<i64>,
    first: Option<Instant>,
    last: Option<Instant>,
}

impl UdpStat {
    fn jitter_us(&self) -> u64 {
        self.jitter as u64
    }
    fn span_us(&self) -> u64 {
        match (self.first, self.last) {
            (Some(a), Some(b)) => (b - a).as_micros() as u64,
            _ => 0,
        }
    }
}

static UDP_SESSIONS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<u64, UdpStat>>> = std::sync::LazyLock::new(Default::default);
static EPOCH: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

/// UDP-пакет: MAGIC, сессия u64, номер u64, время отправки (мкс) u64, заполнение.
fn account(stat: &mut UdpStat, seq: u64, sent_us: i64, now_us: i64, len: usize, now: Instant) {
    stat.received += 1;
    stat.bytes += len as u64;
    if seq < stat.max_seq {
        stat.out_of_order += 1;
    }
    stat.max_seq = stat.max_seq.max(seq);
    let transit = now_us - sent_us;
    if let Some(prev) = stat.last_transit {
        let d = (transit - prev).abs() as f64;
        stat.jitter += (d - stat.jitter) / 16.0;
    }
    stat.last_transit = Some(transit);
    stat.first.get_or_insert(now);
    stat.last = Some(now);
}

async fn serve_udp(sock: UdpSocket, cancel: CancellationToken) {
    let mut buf = vec![0u8; 65535];
    loop {
        let n = tokio::select! {
            r = sock.recv_from(&mut buf) => match r { Ok((n, _)) => n, Err(_) => continue },
            _ = cancel.cancelled() => return,
        };
        if n < 28 || &buf[..4] != MAGIC {
            continue;
        }
        let id = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let seq = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        let sent = u64::from_be_bytes(buf[20..28].try_into().unwrap()) as i64;
        let now = Instant::now();
        let now_us = (now - *EPOCH).as_micros() as i64;
        if let Ok(mut m) = UDP_SESSIONS.lock() {
            if m.len() > 1000 {
                m.clear();
            }
            account(m.entry(id).or_default(), seq, sent, now_us, n, now);
        }
    }
}

pub async fn serve(bind: String, port: u16, sink: Sink<Event>, cancel: CancellationToken) {
    let l = match TcpListener::bind(format!("{bind}:{port}")).await {
        Ok(l) => l,
        Err(e) => return sink.send(Event::Error(format!("порт {port}: {e}"))),
    };
    match UdpSocket::bind(format!("{bind}:{port}")).await {
        Ok(u) => {
            tokio::spawn(serve_udp(u, cancel.clone()));
        }
        Err(e) => sink.send(Event::Error(format!("UDP {port}: {e}"))),
    }
    sink.send(Event::Log(format!("ждём клиентов на TCP/UDP {port}")));
    loop {
        let s = tokio::select! {
            r = l.accept() => match r { Ok((s, _)) => s, Err(_) => continue },
            _ = cancel.cancelled() => return,
        };
        let sink = sink.clone();
        tokio::spawn(async move {
            let _ = serve_tcp(s, sink).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Клиент
// ---------------------------------------------------------------------------

fn header(kind: u8, v: u64) -> Vec<u8> {
    let mut h = MAGIC.to_vec();
    h.push(kind);
    h.extend(v.to_be_bytes());
    h
}

async fn tcp_dir(cfg: &Config, dir: Direction, sink: &Sink<Event>, cancel: &CancellationToken) -> Result<f64, String> {
    let counter = Arc::new(AtomicU64::new(0));
    let addr = format!("{}:{}", cfg.server, cfg.port);
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..cfg.streams.max(1) {
        let mut s = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("{addr}: нет ответа — запущен ли там сервер замера?"))?
            .map_err(|e| format!("{addr}: {e} — запущен ли там сервер замера?"))?;
        let _ = s.set_nodelay(true);
        let secs = cfg.seconds;
        s.write_all(&header(if dir == Direction::Up { b'U' } else { b'D' }, secs)).await.map_err(|e| e.to_string())?;
        let c = counter.clone();
        set.spawn(async move {
            if dir == Direction::Up {
                let buf = vec![0xa5u8; 128 * 1024];
                let end = Instant::now() + Duration::from_secs(secs);
                while Instant::now() < end {
                    if s.write_all(&buf).await.is_err() {
                        break;
                    }
                    c.fetch_add(buf.len() as u64, Ordering::Relaxed);
                }
                let _ = s.shutdown().await;
            } else {
                let mut buf = vec![0u8; 256 * 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    c.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        });
    }
    let start = Instant::now();
    let mut last = 0u64;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.tick().await;
    // Первая секунда — разгон TCP, в итог не входит.
    let mut base: Option<(u64, Instant)> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = cancel.cancelled() => { set.abort_all(); return Err("остановлено".into()); }
        }
        let now = counter.load(Ordering::Relaxed);
        let t = start.elapsed().as_secs_f64();
        sink.send(Event::Point(dir, t, (now - last) as f64 * 8.0 / 0.5 / 1e6));
        last = now;
        if base.is_none() && t >= 1.0 {
            base = Some((now, Instant::now()));
        }
        if set.is_empty() || t >= cfg.seconds as f64 + 0.25 {
            break;
        }
        while let Some(r) = set.try_join_next() {
            let _ = r;
        }
    }
    set.abort_all();
    let total = counter.load(Ordering::Relaxed);
    let (b0, t0) = base.unwrap_or((0, start));
    let secs = t0.elapsed().as_secs_f64().max(0.001);
    Ok((total - b0) as f64 * 8.0 / secs / 1e6)
}

async fn udp_test(cfg: &Config, sink: &Sink<Event>, cancel: &CancellationToken) -> Result<UdpResult, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    let target = super::resolve_v4(&cfg.server, Duration::from_secs(3)).await?;
    sock.connect((target, cfg.port)).await.map_err(|e| e.to_string())?;
    let id = (super::dns::rand_id() as u64) << 32 | std::process::id() as u64;
    let size = 1200usize;
    let pps = (cfg.udp_mbps as f64 * 1e6 / 8.0 / size as f64).max(1.0);
    let total = (pps * cfg.seconds as f64) as u64;
    sink.send(Event::Log(format!("UDP {} Мбит/с, {} пакетов", cfg.udp_mbps, total)));
    let start = Instant::now();
    let mut pkt = vec![0u8; size];
    pkt[..4].copy_from_slice(MAGIC);
    pkt[4..12].copy_from_slice(&id.to_be_bytes());
    let mut sent = 0u64;
    while sent < total {
        if cancel.is_cancelled() {
            return Err("остановлено".into());
        }
        let due = start + Duration::from_secs_f64(sent as f64 / pps);
        let now = Instant::now();
        if due > now {
            tokio::time::sleep(due - now).await;
        }
        pkt[12..20].copy_from_slice(&sent.to_be_bytes());
        let us = (Instant::now() - *EPOCH).as_micros() as u64;
        pkt[20..28].copy_from_slice(&us.to_be_bytes());
        let _ = sock.send(&pkt).await;
        sent += 1;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut s = TcpStream::connect(format!("{}:{}", cfg.server, cfg.port)).await.map_err(|e| e.to_string())?;
    s.write_all(&header(b'R', id)).await.map_err(|e| e.to_string())?;
    let mut r = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut r)).await;
    if r.len() < 48 {
        return Ok(UdpResult { sent, lost_pct: 100.0, ..Default::default() });
    }
    let g = |i: usize| u64::from_be_bytes(r[i * 8..i * 8 + 8].try_into().unwrap());
    let received = g(0);
    let span = g(5).max(1) as f64 / 1e6;
    Ok(UdpResult {
        sent,
        received,
        lost_pct: (sent.saturating_sub(received)) as f64 * 100.0 / sent.max(1) as f64,
        out_of_order: g(2),
        // Джиттер меряется по разнице «часов» двух машин: смещение уходит, остаётся разброс.
        jitter_ms: g(3) as f64 / 1000.0,
        mbps: g(4) as f64 * 8.0 / span / 1e6,
    })
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let dirs: &[Direction] = match cfg.direction {
        Direction::Both => &[Direction::Down, Direction::Up],
        Direction::Up => &[Direction::Up],
        Direction::Down => &[Direction::Down],
    };
    for d in dirs {
        sink.send(Event::Log(format!("{} в {} потока…", if *d == Direction::Up { "отдача" } else { "загрузка" }, cfg.streams)));
        match tcp_dir(&cfg, *d, &sink, &cancel).await {
            Ok(v) => sink.send(Event::Total(*d, v)),
            Err(e) => return sink.send(Event::Error(e)),
        }
    }
    if cfg.udp_mbps > 0 {
        match udp_test(&cfg, &sink, &cancel).await {
            Ok(r) => sink.send(Event::Udp(r)),
            Err(e) => sink.send(Event::Error(e)),
        }
    }
}

/// Вывод по итогам: что значит такая скорость.
pub fn verdict(mbps: f64, udp: Option<&UdpResult>) -> Vec<(bool, String)> {
    let mut v = Vec::new();
    let near = |x: f64, cap: f64| x > cap * 0.80 && x <= cap * 1.02;
    if near(mbps, 100.0) {
        v.push((false, "упирается в ~100 Мбит/с: где-то на пути порт или кабель 100 Мбит/с (часто — две пары вместо четырёх)".into()));
    } else if near(mbps, 10.0) {
        v.push((false, "упирается в ~10 Мбит/с: порт работает на 10 Мбит/с или ограничение скорости".into()));
    } else if near(mbps, 1000.0) {
        v.push((true, "гигабит работает в полную силу".into()));
    } else if near(mbps, 10_000.0) {
        v.push((true, "10 Гбит/с работает в полную силу".into()));
    } else if mbps > 0.0 {
        v.push((true, format!("{mbps:.0} Мбит/с — не похоже на упор в скорость порта; если ожидали больше, ищите ограничение (QoS, шифрование, загруженный канал)")));
    }
    if let Some(u) = udp {
        if u.lost_pct >= 1.0 {
            v.push((false, format!("потери UDP {:.1}% — голос и видео будут рваться", u.lost_pct)));
        } else {
            v.push((true, format!("потери UDP {:.2}% — норма", u.lost_pct)));
        }
        if u.jitter_ms >= 30.0 {
            v.push((false, format!("джиттер {:.1} мс — для IP-телефонии много (норма до 30)", u.jitter_ms)));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn loopback() {
        let cancel = CancellationToken::new();
        let (ssink, _srx) = Sink::new(None);
        let port = 40000 + (std::process::id() % 20000) as u16;
        tokio::spawn(serve("127.0.0.1".into(), port, ssink, cancel.clone()));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (sink, rx) = Sink::new(None);
        let cfg = Config { server: "127.0.0.1".into(), port, streams: 2, seconds: 2, direction: Direction::Both, udp_mbps: 20 };
        run(cfg, sink, CancellationToken::new()).await;
        let ev: Vec<Event> = rx.try_iter().collect();
        let totals: Vec<f64> = ev.iter().filter_map(|e| if let Event::Total(_, v) = e { Some(*v) } else { None }).collect();
        assert_eq!(totals.len(), 2, "{ev:?}");
        assert!(totals.iter().all(|v| *v > 50.0), "{totals:?}");
        let udp = ev.iter().find_map(|e| if let Event::Udp(u) = e { Some(u.clone()) } else { None }).expect("udp");
        assert!(udp.received > 0 && udp.lost_pct < 50.0, "{udp:?}");
        cancel.cancel();
    }

    #[test]
    fn verdicts() {
        assert!(!verdict(94.0, None)[0].0);
        assert!(verdict(940.0, None)[0].0);
        let u = UdpResult { lost_pct: 3.0, jitter_ms: 40.0, ..Default::default() };
        assert_eq!(verdict(500.0, Some(&u)).iter().filter(|x| !x.0).count(), 2);
    }
}
