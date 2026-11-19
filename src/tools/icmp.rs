//! Низкоуровневые пробы для ping, трассировки и поиска MTU (IPv4).
//!
//! * Windows: `IcmpSendEcho` из iphlpapi — работает без прав администратора.
//! * Linux: raw-сокет ICMP (root или CAP_NET_RAW), иначе ping-сокет (если разрешён
//!   `net.ipv4.ping_group_range`). UDP-пробы с `IP_RECVERR` работают всегда, без прав.

use std::net::Ipv4Addr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplyKind {
    /// Ответ от узла назначения (echo reply, ответ UDP или «порт недоступен» от самого узла).
    Reached,
    /// TTL истёк на промежуточном узле.
    TimeExceeded,
    /// Узел/сеть/протокол недоступны (код ICMP).
    Unreachable(u8),
    /// Нужна фрагментация, а стоит DF: MTU следующего участка, если известен.
    FragNeeded(Option<u16>),
    /// Пакет больше MTU локального интерфейса (не ушёл в сеть).
    LocalTooBig(Option<u16>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub from: Ipv4Addr,
    pub rtt_us: u64,
    /// TTL ответа (для догадки об ОС).
    pub ttl: Option<u8>,
    pub kind: ReplyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Proto {
    #[default]
    Icmp,
    Udp,
}

/// Параметры одной пробы.
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub dst: Ipv4Addr,
    pub ttl: u8,
    /// Размер полезной нагрузки (байт данных ICMP/UDP).
    pub payload: usize,
    /// Запретить фрагментацию (DF).
    pub df: bool,
    pub timeout: Duration,
    pub proto: Proto,
    /// Порт назначения для UDP.
    pub port: u16,
    pub id: u16,
    pub seq: u16,
}

/// Уникальный идентификатор ICMP для этого процесса.
pub fn next_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static ID: AtomicU16 = AtomicU16::new(0);
    let base = (std::process::id() as u16).wrapping_mul(31);
    base.wrapping_add(ID.fetch_add(1, Ordering::Relaxed))
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let w = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(w as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn echo_packet(id: u16, seq: u16, payload: usize) -> Vec<u8> {
    let mut p = vec![8, 0, 0, 0];
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend((0..payload).map(|i| (i % 64) as u8 + 0x20));
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

/// Разбор пакета из raw-сокета (IP-заголовок + ICMP): ответ на нашу пробу или None.
pub fn parse_raw(buf: &[u8], dst: Ipv4Addr, id: u16, seq: u16) -> Option<(Ipv4Addr, u8, ReplyKind)> {
    if buf.len() < 20 || buf[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((buf[0] & 0xF) as usize) * 4;
    let ttl = buf[8];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let icmp = buf.get(ihl..)?;
    if icmp.len() < 8 {
        return None;
    }
    let (t, code) = (icmp[0], icmp[1]);
    match t {
        0 => {
            let rid = u16::from_be_bytes([icmp[4], icmp[5]]);
            let rseq = u16::from_be_bytes([icmp[6], icmp[7]]);
            (rid == id && rseq == seq && src == dst).then_some((src, ttl, ReplyKind::Reached))
        }
        3 | 11 => {
            // Вложенный исходный IP-заголовок и первые 8 байт нашего ICMP.
            let inner = icmp.get(8..)?;
            if inner.len() < 28 || inner[0] >> 4 != 4 || inner[9] != 1 {
                return None;
            }
            let iihl = ((inner[0] & 0xF) as usize) * 4;
            let idst = Ipv4Addr::new(inner[16], inner[17], inner[18], inner[19]);
            let iicmp = inner.get(iihl..iihl + 8)?;
            let rid = u16::from_be_bytes([iicmp[4], iicmp[5]]);
            let rseq = u16::from_be_bytes([iicmp[6], iicmp[7]]);
            if idst != dst || iicmp[0] != 8 || rid != id || rseq != seq {
                return None;
            }
            let kind = if t == 11 {
                ReplyKind::TimeExceeded
            } else if code == 4 {
                let mtu = u16::from_be_bytes([icmp[6], icmp[7]]);
                ReplyKind::FragNeeded((mtu != 0).then_some(mtu))
            } else {
                ReplyKind::Unreachable(code)
            };
            Some((src, ttl, kind))
        }
        _ => None,
    }
}

/// Классификация ошибки ICMP, пришедшей через `IP_RECVERR`.
pub fn classify_err(origin: u8, icmp_type: u8, code: u8, info: u32, offender: Ipv4Addr, dst: Ipv4Addr, proto: Proto) -> Option<ReplyKind> {
    const SO_EE_ORIGIN_LOCAL: u8 = 1;
    const SO_EE_ORIGIN_ICMP: u8 = 2;
    match origin {
        SO_EE_ORIGIN_LOCAL => Some(ReplyKind::LocalTooBig((info != 0).then_some(info.min(65535) as u16))),
        SO_EE_ORIGIN_ICMP => Some(match (icmp_type, code) {
            (11, _) => ReplyKind::TimeExceeded,
            (3, 4) => ReplyKind::FragNeeded((info != 0).then_some(info.min(65535) as u16)),
            // «Порт недоступен» от самого узла — UDP-проба дошла до цели.
            (3, 3) if proto == Proto::Udp && offender == dst => ReplyKind::Reached,
            (3, c) => ReplyKind::Unreachable(c),
            _ => return None,
        }),
        _ => None,
    }
}

pub fn unreachable_text(code: u8) -> &'static str {
    match code {
        0 => "сеть недоступна",
        1 => "узел недоступен",
        2 => "протокол недоступен",
        3 => "порт недоступен",
        4 => "нужна фрагментация",
        5 => "ошибка маршрута источника",
        6 | 7 => "сеть/узел неизвестны",
        9 | 10 | 13 => "запрещено администратором",
        _ => "недоступен",
    }
}

/// Какими средствами доступны ICMP-пробы на этой машине.
pub fn icmp_method() -> Result<&'static str, String> {
    #[cfg(windows)]
    {
        Ok("IcmpSendEcho")
    }
    #[cfg(target_os = "linux")]
    {
        linux::method()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("ICMP не поддерживается на этой платформе".into())
    }
}

/// Выполнение пробы (в пуле блокирующих потоков). `Ok(None)` — ответа нет.
pub async fn probe(p: Probe) -> Result<Option<Reply>, String> {
    tokio::task::spawn_blocking(move || probe_blocking(&p))
        .await
        .map_err(|e| e.to_string())?
}

pub fn probe_blocking(p: &Probe) -> Result<Option<Reply>, String> {
    #[cfg(windows)]
    {
        match p.proto {
            Proto::Icmp => windows::icmp(p),
            Proto::Udp => Err("UDP-трассировка в Windows недоступна — используйте ICMP".into()),
        }
    }
    #[cfg(target_os = "linux")]
    {
        match p.proto {
            Proto::Icmp => linux::icmp(p),
            Proto::Udp => linux::udp(p),
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = p;
        Err("не поддерживается на этой платформе".into())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IP_FLAG_DF, IP_OPTION_INFORMATION, IP_PACKET_TOO_BIG, IP_REQ_TIMED_OUT, IP_TTL_EXPIRED_TRANSIT,
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    };

    pub fn icmp(p: &Probe) -> Result<Option<Reply>, String> {
        let data: Vec<u8> = (0..p.payload).map(|i| (i % 64) as u8 + 0x20).collect();
        let opts = IP_OPTION_INFORMATION {
            Ttl: p.ttl,
            Tos: 0,
            Flags: if p.df { IP_FLAG_DF as u8 } else { 0 },
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };
        let mut buf = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + p.payload.max(8) + 64];
        let timeout = p.timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
        // SAFETY: буферы живут до конца вызова, размеры переданы точно.
        let (n, err) = unsafe {
            let h = IcmpCreateFile();
            if h == INVALID_HANDLE_VALUE || h.is_null() {
                return Err(format!("IcmpCreateFile: ошибка {}", GetLastError()));
            }
            let started = Instant::now();
            let n = IcmpSendEcho(
                h,
                u32::from_ne_bytes(p.dst.octets()),
                data.as_ptr().cast(),
                data.len() as u16,
                &opts,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                timeout,
            );
            let err = GetLastError();
            IcmpCloseHandle(h);
            (n, (err, started.elapsed()))
        };
        let (last, elapsed) = err;
        if n == 0 {
            return match last {
                IP_REQ_TIMED_OUT | 11050 => Ok(None),
                IP_PACKET_TOO_BIG => Ok(Some(Reply {
                    from: p.dst,
                    rtt_us: 0,
                    ttl: None,
                    kind: ReplyKind::LocalTooBig(None),
                })),
                e => Err(format!("IcmpSendEcho: ошибка {e}")),
            };
        }
        // SAFETY: при n > 0 в начале буфера лежит ICMP_ECHO_REPLY.
        let r: ICMP_ECHO_REPLY = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        let from = Ipv4Addr::from(r.Address.to_ne_bytes());
        // Собственный замер точнее RoundTripTime (там целые миллисекунды).
        let rtt_us = (elapsed.as_micros() as u64).min(r.RoundTripTime as u64 * 1000 + 999);
        let kind = match r.Status {
            0 => ReplyKind::Reached,
            IP_TTL_EXPIRED_TRANSIT | 11014 => ReplyKind::TimeExceeded,
            IP_PACKET_TOO_BIG => ReplyKind::FragNeeded(None),
            11002 => ReplyKind::Unreachable(0),
            11003 => ReplyKind::Unreachable(1),
            11004 => ReplyKind::Unreachable(2),
            11005 => ReplyKind::Unreachable(3),
            11018 | 11019 => ReplyKind::Unreachable(13),
            IP_REQ_TIMED_OUT => return Ok(None),
            s => return Err(format!("ICMP: состояние {s}")),
        };
        Ok(Some(Reply {
            from,
            rtt_us,
            ttl: Some(r.Options.Ttl),
            kind,
        }))
    }

    /// MAC-адрес узла локальной сети (ARP-запрос средствами Windows, без прав).
    pub fn send_arp(ip: Ipv4Addr) -> Option<[u8; 6]> {
        let mut mac = [0u8; 8];
        let mut len: u32 = 6;
        // SAFETY: буфер на 8 байт, длина передана.
        let rc = unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::SendARP(
                u32::from_ne_bytes(ip.octets()),
                0,
                mac.as_mut_ptr().cast(),
                &mut len,
            )
        };
        (rc == 0 && len == 6).then(|| [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]])
    }
}

#[cfg(windows)]
pub use windows::send_arp;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::time::Instant;

    const IP_RECVERR: libc::c_int = 11;
    const IP_MTU_DISCOVER: libc::c_int = 10;
    const IP_PMTUDISC_DONT: libc::c_int = 0;
    const IP_PMTUDISC_PROBE: libc::c_int = 3;
    const IP_RECVTTL: libc::c_int = 12;
    const IP_MTU: libc::c_int = 14;

    struct Fd(libc::c_int);
    impl Drop for Fd {
        fn drop(&mut self) {
            // SAFETY: дескриптор принадлежит нам.
            unsafe { libc::close(self.0) };
        }
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn setopt(fd: &Fd, level: libc::c_int, name: libc::c_int, val: libc::c_int) -> Result<(), String> {
        // SAFETY: передаём указатель на int и его размер.
        let rc = unsafe {
            libc::setsockopt(
                fd.0,
                level,
                name,
                (&val as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 { Err(std::io::Error::last_os_error().to_string()) } else { Ok(()) }
    }

    fn socket(ty: libc::c_int, proto: libc::c_int) -> Result<Fd, i32> {
        // SAFETY: обычный вызов socket(2).
        let fd = unsafe { libc::socket(libc::AF_INET, ty | libc::SOCK_CLOEXEC, proto) };
        if fd < 0 { Err(errno()) } else { Ok(Fd(fd)) }
    }

    fn sockaddr(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            sin_zero: [0; 8],
        }
    }

    pub fn method() -> Result<&'static str, String> {
        if socket(libc::SOCK_RAW, libc::IPPROTO_ICMP).is_ok() {
            return Ok("raw-сокет ICMP");
        }
        if socket(libc::SOCK_DGRAM, libc::IPPROTO_ICMP).is_ok() {
            return Ok("ping-сокет");
        }
        Err("ICMP недоступен: нужен root/CAP_NET_RAW или sysctl net.ipv4.ping_group_range \
             (UDP-трассировка работает без прав)"
            .into())
    }

    /// poll() одного дескриптора: (готов к чтению, есть ошибка в очереди).
    fn wait(fd: &Fd, until: Instant) -> Option<(bool, bool)> {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let mut pfd = libc::pollfd {
            fd: fd.0,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: один pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, left.as_millis().clamp(1, i32::MAX as u128) as i32) };
        if rc <= 0 {
            return if rc < 0 && errno() == libc::EINTR { Some((false, false)) } else { None };
        }
        Some((pfd.revents & libc::POLLIN != 0, pfd.revents & libc::POLLERR != 0))
    }

    /// Сообщение из очереди ошибок: (origin, type, code, info, offender).
    fn read_errqueue(fd: &Fd) -> Option<(u8, u8, u8, u32, Ipv4Addr)> {
        let mut data = [0u8; 2048];
        let mut control = [0u8; 512];
        let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut from as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        // SAFETY: все буферы корректны и живут до конца вызова.
        let n = unsafe { libc::recvmsg(fd.0, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        if n < 0 {
            return None;
        }
        // SAFETY: обход управляющих сообщений стандартными макросами.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == IP_RECVERR {
                    let ee = libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err;
                    let e = std::ptr::read_unaligned(ee);
                    let off_ptr = (ee as *const u8).add(std::mem::size_of::<libc::sock_extended_err>())
                        as *const libc::sockaddr_in;
                    let off = std::ptr::read_unaligned(off_ptr);
                    let offender = Ipv4Addr::from(off.sin_addr.s_addr.to_ne_bytes());
                    return Some((e.ee_origin, e.ee_type, e.ee_code, e.ee_info, offender));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        None
    }

    fn local_mtu(fd: &Fd) -> Option<u16> {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: int и его длина.
        let rc = unsafe { libc::getsockopt(fd.0, libc::IPPROTO_IP, IP_MTU, (&mut v as *mut libc::c_int).cast(), &mut len) };
        (rc == 0 && v > 0).then_some(v as u16)
    }

    fn prepare(fd: &Fd, p: &Probe, recverr: bool) -> Result<(), String> {
        setopt(fd, libc::IPPROTO_IP, libc::IP_TTL, p.ttl as libc::c_int)?;
        setopt(
            fd,
            libc::IPPROTO_IP,
            IP_MTU_DISCOVER,
            if p.df { IP_PMTUDISC_PROBE } else { IP_PMTUDISC_DONT },
        )?;
        if recverr {
            setopt(fd, libc::IPPROTO_IP, IP_RECVERR, 1)?;
        }
        Ok(())
    }

    fn rtt(start: Instant) -> u64 {
        start.elapsed().as_micros() as u64
    }

    fn send_to(fd: &Fd, pkt: &[u8], to: &libc::sockaddr_in) -> isize {
        // SAFETY: буфер и адрес корректны.
        unsafe {
            libc::sendto(
                fd.0,
                pkt.as_ptr().cast(),
                pkt.len(),
                0,
                (to as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        }
    }

    pub fn icmp(p: &Probe) -> Result<Option<Reply>, String> {
        match socket(libc::SOCK_RAW, libc::IPPROTO_ICMP) {
            Ok(fd) => icmp_raw(fd, p),
            Err(_) => match socket(libc::SOCK_DGRAM, libc::IPPROTO_ICMP) {
                Ok(fd) => icmp_dgram(fd, p),
                Err(_) => Err(method().unwrap_err()),
            },
        }
    }

    fn too_big(fd: &Fd, p: &Probe) -> Option<Reply> {
        (errno() == libc::EMSGSIZE).then(|| Reply {
            from: p.dst,
            rtt_us: 0,
            ttl: None,
            kind: ReplyKind::LocalTooBig(local_mtu(fd)),
        })
    }

    fn icmp_raw(fd: Fd, p: &Probe) -> Result<Option<Reply>, String> {
        prepare(&fd, p, false)?;
        let pkt = echo_packet(p.id, p.seq, p.payload);
        let to = sockaddr(p.dst, 0);
        let start = Instant::now();
        if send_to(&fd, &pkt, &to) < 0 {
            if let Some(r) = too_big(&fd, p) {
                return Ok(Some(r));
            }
            return Err(format!("отправка ICMP: {}", std::io::Error::last_os_error()));
        }
        let until = start + p.timeout;
        let mut buf = vec![0u8; 65536];
        while let Some((readable, _)) = wait(&fd, until) {
            if !readable {
                continue;
            }
            // SAFETY: буфер на 64 КБ.
            let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            if n <= 0 {
                continue;
            }
            if let Some((from, ttl, kind)) = parse_raw(&buf[..n as usize], p.dst, p.id, p.seq) {
                return Ok(Some(Reply {
                    from,
                    rtt_us: rtt(start),
                    ttl: Some(ttl),
                    kind,
                }));
            }
        }
        Ok(None)
    }

    fn icmp_dgram(fd: Fd, p: &Probe) -> Result<Option<Reply>, String> {
        prepare(&fd, p, true)?;
        setopt(&fd, libc::IPPROTO_IP, IP_RECVTTL, 1)?;
        // Ядро само подставит идентификатор (номер «порта» ping-сокета).
        let pkt = echo_packet(0, p.seq, p.payload);
        let to = sockaddr(p.dst, 0);
        let start = Instant::now();
        if send_to(&fd, &pkt, &to) < 0 {
            if let Some(r) = too_big(&fd, p) {
                return Ok(Some(r));
            }
            return Err(format!("отправка ICMP: {}", std::io::Error::last_os_error()));
        }
        let until = start + p.timeout;
        while let Some((readable, err)) = wait(&fd, until) {
            if err && let Some((origin, t, c, info, off)) = read_errqueue(&fd) {
                if let Some(kind) = classify_err(origin, t, c, info, off, p.dst, Proto::Icmp) {
                    return Ok(Some(Reply {
                        from: off,
                        rtt_us: rtt(start),
                        ttl: None,
                        kind,
                    }));
                }
                continue;
            }
            if !readable {
                continue;
            }
            if let Some((seq, ttl)) = recv_echo_dgram(&fd)
                && seq == p.seq
            {
                return Ok(Some(Reply {
                    from: p.dst,
                    rtt_us: rtt(start),
                    ttl,
                    kind: ReplyKind::Reached,
                }));
            }
        }
        Ok(None)
    }

    /// Ответ ping-сокета: (seq, TTL из IP_RECVTTL).
    fn recv_echo_dgram(fd: &Fd) -> Option<(u16, Option<u8>)> {
        let mut data = [0u8; 2048];
        let mut control = [0u8; 256];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        // SAFETY: буферы корректны.
        let n = unsafe { libc::recvmsg(fd.0, &mut msg, libc::MSG_DONTWAIT) };
        if n < 8 || data[0] != 0 {
            return None;
        }
        let seq = u16::from_be_bytes([data[6], data[7]]);
        let mut ttl = None;
        // SAFETY: обход управляющих сообщений.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_TTL {
                    ttl = Some(std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int) as u8);
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        Some((seq, ttl))
    }

    pub fn udp(p: &Probe) -> Result<Option<Reply>, String> {
        let fd = socket(libc::SOCK_DGRAM, libc::IPPROTO_UDP).map_err(|e| std::io::Error::from_raw_os_error(e).to_string())?;
        prepare(&fd, p, true)?;
        let to = sockaddr(p.dst, p.port);
        // SAFETY: connect(2) с корректным адресом.
        let rc = unsafe {
            libc::connect(fd.0, (&to as *const libc::sockaddr_in).cast(), std::mem::size_of::<libc::sockaddr_in>() as u32)
        };
        if rc < 0 {
            return Err(format!("UDP: {}", std::io::Error::last_os_error()));
        }
        let payload: Vec<u8> = (0..p.payload).map(|i| (i % 64) as u8 + 0x20).collect();
        let start = Instant::now();
        // SAFETY: буфер корректен.
        let n = unsafe { libc::send(fd.0, payload.as_ptr().cast(), payload.len(), 0) };
        if n < 0 {
            if let Some(r) = too_big(&fd, p) {
                return Ok(Some(r));
            }
            return Err(format!("UDP: {}", std::io::Error::last_os_error()));
        }
        let until = start + p.timeout;
        while let Some((readable, err)) = wait(&fd, until) {
            if err && let Some((origin, t, c, info, off)) = read_errqueue(&fd) {
                if let Some(kind) = classify_err(origin, t, c, info, off, p.dst, Proto::Udp) {
                    let from = if origin == 1 { p.dst } else { off };
                    return Ok(Some(Reply {
                        from,
                        rtt_us: rtt(start),
                        ttl: None,
                        kind,
                    }));
                }
                continue;
            }
            if readable {
                let mut buf = [0u8; 2048];
                // SAFETY: буфер корректен.
                let n = unsafe { libc::recv(fd.0, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
                if n >= 0 {
                    return Ok(Some(Reply {
                        from: p.dst,
                        rtt_us: rtt(start),
                        ttl: None,
                        kind: ReplyKind::Reached,
                    }));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rfc1071() {
        // Пример из RFC 1071: 0001 f203 f4f5 f6f7 → сумма ddf2, дополнение 220d.
        assert_eq!(checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
        let p = echo_packet(0x1234, 7, 20);
        assert_eq!(checksum(&p), 0);
        assert_eq!(p.len(), 28);
    }

    fn ip_header(src: [u8; 4], dst: [u8; 4], proto: u8, ttl: u8) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, ttl, proto, 0, 0];
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        h
    }

    #[test]
    fn raw_parsing() {
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        // Echo reply.
        let mut pkt = ip_header([8, 8, 8, 8], [10, 0, 0, 2], 1, 117);
        let mut reply = echo_packet(0x42, 3, 4);
        reply[0] = 0;
        pkt.extend_from_slice(&reply);
        assert_eq!(parse_raw(&pkt, dst, 0x42, 3), Some((dst, 117, ReplyKind::Reached)));
        assert_eq!(parse_raw(&pkt, dst, 0x43, 3), None);

        // Time exceeded от 10.0.0.1 с вложенным исходным пакетом.
        let mut te = ip_header([10, 0, 0, 1], [10, 0, 0, 2], 1, 64);
        te.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
        te.extend(ip_header([10, 0, 0, 2], [8, 8, 8, 8], 1, 1));
        te.extend_from_slice(&echo_packet(0x42, 3, 0)[..8]);
        assert_eq!(
            parse_raw(&te, dst, 0x42, 3),
            Some((Ipv4Addr::new(10, 0, 0, 1), 64, ReplyKind::TimeExceeded))
        );

        // Frag needed с MTU 1400.
        let mut fna = ip_header([10, 0, 0, 1], [10, 0, 0, 2], 1, 64);
        fna.extend_from_slice(&[3, 4, 0, 0, 0, 0, 0x05, 0x78]);
        fna.extend(ip_header([10, 0, 0, 2], [8, 8, 8, 8], 1, 5));
        fna.extend_from_slice(&echo_packet(0x42, 3, 0)[..8]);
        assert_eq!(parse_raw(&fna, dst, 0x42, 3).unwrap().2, ReplyKind::FragNeeded(Some(1400)));
    }

    #[test]
    fn errqueue_classification() {
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        let hop = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(classify_err(2, 11, 0, 0, hop, dst, Proto::Udp), Some(ReplyKind::TimeExceeded));
        assert_eq!(classify_err(2, 3, 3, 0, dst, dst, Proto::Udp), Some(ReplyKind::Reached));
        assert_eq!(classify_err(2, 3, 3, 0, hop, dst, Proto::Udp), Some(ReplyKind::Unreachable(3)));
        assert_eq!(classify_err(2, 3, 4, 1400, hop, dst, Proto::Icmp), Some(ReplyKind::FragNeeded(Some(1400))));
        assert_eq!(classify_err(1, 0, 0, 1500, hop, dst, Proto::Udp), Some(ReplyKind::LocalTooBig(Some(1500))));
    }

    /// UDP-проба к закрытому порту на 127.0.0.1: ядро ответит «порт недоступен».
    #[cfg(target_os = "linux")]
    #[test]
    fn udp_probe_localhost() {
        let p = Probe {
            dst: Ipv4Addr::LOCALHOST,
            ttl: 64,
            payload: 8,
            df: false,
            timeout: Duration::from_secs(1),
            proto: Proto::Udp,
            port: 33999,
            id: 1,
            seq: 1,
        };
        let r = probe_blocking(&p).unwrap().expect("ответ");
        assert_eq!(r.kind, ReplyKind::Reached);
        assert_eq!(r.from, Ipv4Addr::LOCALHOST);
    }

    /// ICMP до 127.0.0.1 (если на машине есть права на ICMP).
    #[cfg(target_os = "linux")]
    #[test]
    fn icmp_probe_localhost() {
        if icmp_method().is_err() {
            return;
        }
        let p = Probe {
            dst: Ipv4Addr::LOCALHOST,
            ttl: 64,
            payload: 32,
            df: true,
            timeout: Duration::from_secs(1),
            proto: Proto::Icmp,
            port: 0,
            id: next_id(),
            seq: 9,
        };
        let r = probe_blocking(&p).unwrap().expect("ответ");
        assert_eq!(r.kind, ReplyKind::Reached);
        assert_eq!(r.ttl, Some(64));
        // Больше MTU loopback (65536) — локальная ошибка.
        let big = Probe { payload: 70000, ..p };
        let _ = probe_blocking(&big);
    }
}
