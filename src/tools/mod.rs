//! Инструменты диагностики: общий каркас фоновых задач и вспомогательные функции.
//!
//! Каждый инструмент состоит из конфигурации (`Config`: сериализуется, служит основой
//! пресетов и параметров командной строки), асинхронной функции `run`, которая шлёт
//! события в [`Sink`], и итогового отчёта (сериализуется в JSON).

pub mod ad;
pub mod audit;
pub mod certs;
pub mod compare;
pub mod dns;
pub mod dnsproto;
pub mod discovery;
pub mod hostinfo;
pub mod http;
pub mod icmp;
pub mod matrix;
pub mod monitor;
pub mod mtr;
pub mod netmap;
pub mod notify;
pub mod service;
pub mod shares;
pub mod oui;
pub mod tls;
pub mod urlcheck;
pub mod services;
pub mod tlsaudit;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Получатель событий фоновой задачи: GUI (с перерисовкой окна) или командная строка.
pub struct Sink<E> {
    tx: Sender<E>,
    ctx: Option<egui::Context>,
}

impl<E> Clone for Sink<E> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<E> Sink<E> {
    pub fn new(ctx: Option<egui::Context>) -> (Self, Receiver<E>) {
        let (tx, rx) = channel();
        (Self { tx, ctx }, rx)
    }

    pub fn send(&self, e: E) {
        let _ = self.tx.send(e);
        if let Some(ctx) = &self.ctx {
            // Не чаще ~20 кадров в секунду: тысячи событий сканирования не должны
            // нагружать видеокарту.
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }
}

/// Запущенная фоновая задача инструмента.
pub struct Task<E> {
    rx: Receiver<E>,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

impl<E: Send + 'static> Task<E> {
    pub fn spawn<F, Fut>(rt: &Handle, ctx: &egui::Context, f: F) -> Self
    where
        F: FnOnce(Sink<E>, CancellationToken) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (sink, rx) = Sink::new(Some(ctx.clone()));
        let cancel = CancellationToken::new();
        let fut = f(sink.clone(), cancel.clone());
        let ctx = ctx.clone();
        let handle = rt.spawn(async move {
            fut.await;
            drop(sink);
            ctx.request_repaint();
        });
        Self { rx, cancel, handle }
    }

    /// Новые события (не блокирует).
    pub fn drain(&self) -> Vec<E> {
        self.rx.try_iter().collect()
    }

    pub fn finished(&self) -> bool {
        self.handle.is_finished()
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

impl<E> Drop for Task<E> {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Миллисекунды с дробной частью.
pub fn ms_f(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Разрешение имени в IP-адрес (сначала IPv4) системным резолвером.
pub async fn resolve(host: &str, timeout: Duration) -> Result<IpAddr, String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs: Vec<SocketAddr> = tokio::time::timeout(timeout, tokio::net::lookup_host((host, 0)))
        .await
        .map_err(|_| format!("{host}: имя не разрешилось за {} мс", timeout.as_millis()))?
        .map_err(|e| format!("{host}: {e}"))?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .map(|a| a.ip())
        .ok_or_else(|| format!("{host}: адресов нет"))
}

pub async fn resolve_v4(host: &str, timeout: Duration) -> Result<Ipv4Addr, String> {
    match resolve(host, timeout).await? {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(v6) => Err(format!("{host}: найден только IPv6-адрес {v6}")),
    }
}

/// Разбор списка значений через запятую, пробел, `;` или перевод строки.
pub fn split_list(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .flat_map(|l| l.split(|c: char| c == ',' || c == ';' || c.is_whitespace()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Узлы для инструментов: IP, подсети и диапазоны (как в сканере) плюс имена.
#[derive(Debug, Clone, Default)]
pub struct HostList {
    pub addrs: crate::targets::TargetSet,
    pub names: Vec<String>,
}

impl HostList {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut nets = Vec::new();
        let mut names = Vec::new();
        for item in split_list(text) {
            let looks_numeric = item.chars().all(|c| c.is_ascii_digit() || ".-/".contains(c));
            if looks_numeric {
                nets.push(item);
            } else {
                names.push(item);
            }
        }
        let addrs = if nets.is_empty() {
            crate::targets::TargetSet::default()
        } else {
            crate::targets::parse_targets(&nets.join(","))?
        };
        if addrs.is_empty() && names.is_empty() {
            return Err("не заданы узлы".into());
        }
        Ok(Self { addrs, names })
    }

    pub fn len(&self) -> u64 {
        self.addrs.total_hosts() + self.names.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Все узлы в виде строк (имена — как есть).
    pub fn items(&self) -> impl Iterator<Item = String> + '_ {
        self.names.iter().cloned().chain(self.addrs.iter().map(|a| a.to_string()))
    }
}

/// Ограничение параллельности с отменой: запускает `f` для каждого элемента.
pub async fn for_each_limited<T, F, Fut>(items: Vec<T>, limit: usize, cancel: &CancellationToken, f: F)
where
    T: Send + 'static,
    F: Fn(T) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(limit.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for item in items {
        let permit = tokio::select! {
            p = sem.clone().acquire_owned() => p.expect("semaphore"),
            _ = cancel.cancelled() => break,
        };
        let fut = f(item);
        set.spawn(async move {
            fut.await;
            drop(permit);
        });
        // Освобождаем завершённые задачи, чтобы JoinSet не рос.
        while set.try_join_next().is_some() {}
    }
    tokio::select! {
        _ = async { while set.join_next().await.is_some() {} } => {}
        _ = cancel.cancelled() => set.abort_all(),
    }
}

/// Печатаемое представление байтов (баннеры): управляющие символы экранируются.
pub fn printable(data: &[u8], max: usize) -> String {
    let mut out = String::new();
    let text = String::from_utf8_lossy(&data[..data.len().min(max)]);
    for c in text.chars() {
        match c {
            '\r' => {}
            '\n' => out.push_str("⏎ "),
            '\t' => out.push(' '),
            c if c.is_control() => out.push('·'),
            c => out.push(c),
        }
    }
    let out = out.trim().trim_end_matches('⏎').trim().to_string();
    if data.len() > max { format!("{out}…") } else { out }
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_list_mixed() {
        let h = HostList::parse("10.0.0.1, 10.0.1.0/30 example.com\n# коммент\nintranet").unwrap();
        assert_eq!(h.addrs.total_hosts(), 5);
        assert_eq!(h.names, vec!["example.com", "intranet"]);
        assert_eq!(h.len(), 7);
        assert!(HostList::parse("  ").is_err());
    }

    #[test]
    fn printable_escapes() {
        assert_eq!(printable(b"SSH-2.0-OpenSSH_9.6\r\n", 100), "SSH-2.0-OpenSSH_9.6");
        assert_eq!(printable(b"a\x01b\nc", 100), "a·b⏎ c");
        assert_eq!(printable(b"abcdef", 3), "abc…");
    }

    #[tokio::test]
    async fn limited_runs_all() {
        let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let n2 = n.clone();
        for_each_limited((0..50).collect(), 4, &cancel, move |_| {
            let n = n2.clone();
            async move {
                n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        })
        .await;
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 50);
    }
}
