//! Подключение к устройству: SSH (с поддержкой старых алгоритмов сетевого
//! оборудования), Telnet (согласование опций), COM-порт. Общий интерфейс: поток
//! байтов туда и обратно — для терминала и для автоматического выполнения команд.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::devices::{Device, Proto};

pub enum In {
    Data(Vec<u8>),
    Resize(u16, u16),
    Close,
}

pub enum Out {
    Data(Vec<u8>),
    Closed(String),
}

pub struct Conn {
    pub tx: mpsc::UnboundedSender<In>,
    pub rx: mpsc::UnboundedReceiver<Out>,
}

struct SshClient;

impl russh::client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        // Сетевое оборудование почти всегда с самоподписанным ключом: принимаем.
        Ok(true)
    }
}

/// Алгоритмы: современные первыми, затем устаревшие (SHA-1, CBC, 3DES) — их до сих
/// пор используют многие коммутаторы.
#[allow(clippy::field_reassign_with_default)]
fn ssh_config() -> russh::client::Config {
    use russh::{cipher, kex, mac};
    let mut p = russh::Preferred::default();
    p.kex = std::borrow::Cow::Owned(vec![
        kex::CURVE25519,
        kex::CURVE25519_PRE_RFC_8731,
        kex::ECDH_SHA2_NISTP256,
        kex::ECDH_SHA2_NISTP384,
        kex::DH_GEX_SHA256,
        kex::DH_G16_SHA512,
        kex::DH_G14_SHA256,
        kex::DH_G14_SHA1,
        kex::DH_GEX_SHA1,
        kex::DH_G1_SHA1,
        kex::EXTENSION_SUPPORT_AS_CLIENT,
    ]);
    p.cipher = std::borrow::Cow::Owned(vec![
        cipher::CHACHA20_POLY1305,
        cipher::AES_256_GCM,
        cipher::AES_256_CTR,
        cipher::AES_192_CTR,
        cipher::AES_128_CTR,
        cipher::AES_256_CBC,
        cipher::AES_192_CBC,
        cipher::AES_128_CBC,
        cipher::TRIPLE_DES_CBC,
    ]);
    p.mac = std::borrow::Cow::Owned(vec![mac::HMAC_SHA256_ETM, mac::HMAC_SHA512_ETM, mac::HMAC_SHA256, mac::HMAC_SHA512, mac::HMAC_SHA1_ETM, mac::HMAC_SHA1]);
    russh::client::Config {
        preferred: p,
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    }
}

/// Открыть соединение; для SSH — с терминалом `cols × rows`.
pub async fn open(d: &Device, cols: u16, rows: u16, timeout: Duration) -> Result<Conn, String> {
    let (tx_in, rx_in) = mpsc::unbounded_channel::<In>();
    let (tx_out, rx_out) = mpsc::unbounded_channel::<Out>();
    match d.proto {
        Proto::Ssh => ssh(d, cols, rows, timeout, rx_in, tx_out).await?,
        Proto::Telnet => telnet(d, timeout, rx_in, tx_out).await?,
        Proto::Serial => serial(d, rx_in, tx_out)?,
    }
    Ok(Conn { tx: tx_in, rx: rx_out })
}

async fn ssh(d: &Device, cols: u16, rows: u16, timeout: Duration, mut rx_in: mpsc::UnboundedReceiver<In>, tx_out: mpsc::UnboundedSender<Out>) -> Result<(), String> {
    let addr = (d.host.trim().to_string(), d.port_or_default());
    let mut h = tokio::time::timeout(timeout, russh::client::connect(Arc::new(ssh_config()), addr, SshClient))
        .await
        .map_err(|_| "SSH: нет ответа".to_string())?
        .map_err(|e| format!("SSH: {e}"))?;
    let user = if d.user.is_empty() { "admin".to_string() } else { d.user.clone() };
    let mut ok = false;
    if !d.key_file.trim().is_empty() {
        let key = russh::keys::load_secret_key(d.key_file.trim(), None).map_err(|e| format!("ключ {}: {e}", d.key_file))?;
        let hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();
        ok = h
            .authenticate_publickey(user.clone(), russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await
            .map(|r| r.success())
            .unwrap_or(false);
    }
    let pass = d.password();
    if !ok && !pass.is_empty() {
        ok = h.authenticate_password(user.clone(), pass.clone()).await.map(|r| r.success()).unwrap_or(false);
    }
    if !ok && !pass.is_empty() {
        // Многие устройства принимают только keyboard-interactive.
        use russh::client::KeyboardInteractiveAuthResponse as K;
        let mut r = h.authenticate_keyboard_interactive_start(user.clone(), None).await.map_err(|e| e.to_string())?;
        for _ in 0..3 {
            match r {
                K::Success => {
                    ok = true;
                    break;
                }
                K::InfoRequest { ref prompts, .. } => {
                    let answers = prompts.iter().map(|_| pass.clone()).collect();
                    r = h.authenticate_keyboard_interactive_respond(answers).await.map_err(|e| e.to_string())?;
                }
                K::Failure { .. } => break,
            }
        }
    }
    if !ok {
        return Err("SSH: вход не выполнен — проверьте имя и пароль".into());
    }
    let ch = h.channel_open_session().await.map_err(|e| format!("SSH: {e}"))?;
    ch.request_pty(false, "xterm", cols as u32, rows as u32, 0, 0, &[]).await.map_err(|e| e.to_string())?;
    ch.request_shell(false).await.map_err(|e| e.to_string())?;
    let (mut read, write) = ch.split();
    tokio::spawn(async move {
        let _keep = h;
        loop {
            tokio::select! {
                msg = read.wait() => match msg {
                    Some(russh::ChannelMsg::Data { data }) | Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = tx_out.send(Out::Data(data.to_vec()));
                    }
                    Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => {
                        let _ = tx_out.send(Out::Closed("соединение закрыто устройством".into()));
                        return;
                    }
                    _ => {}
                },
                inp = rx_in.recv() => match inp {
                    Some(In::Data(b)) => {
                        if write.data(&b[..]).await.is_err() {
                            let _ = tx_out.send(Out::Closed("ошибка отправки".into()));
                            return;
                        }
                    }
                    Some(In::Resize(c, r)) => {
                        let _ = write.window_change(c as u32, r as u32, 0, 0).await;
                    }
                    Some(In::Close) | None => {
                        let _ = write.eof().await;
                        let _ = tx_out.send(Out::Closed("отключено".into()));
                        return;
                    }
                },
            }
        }
    });
    Ok(())
}

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

/// Убрать команды Telnet из потока и сформировать ответы на согласование:
/// соглашаемся только на ECHO и SUPPRESS-GO-AHEAD со стороны сервера.
pub fn telnet_filter(state: &mut Vec<u8>, input: &[u8], replies: &mut Vec<u8>) -> Vec<u8> {
    state.extend_from_slice(input);
    let mut out = Vec::new();
    let mut i = 0;
    while i < state.len() {
        let b = state[i];
        if b != IAC {
            out.push(b);
            i += 1;
            continue;
        }
        let Some(&cmd) = state.get(i + 1) else { break };
        match cmd {
            IAC => {
                out.push(IAC);
                i += 2;
            }
            DO | DONT | WILL | WONT => {
                let Some(&opt) = state.get(i + 2) else { break };
                match cmd {
                    WILL if opt == 1 || opt == 3 => replies.extend([IAC, DO, opt]),
                    WILL => replies.extend([IAC, DONT, opt]),
                    DO if opt == 3 => replies.extend([IAC, WILL, opt]),
                    DO => replies.extend([IAC, WONT, opt]),
                    _ => {}
                }
                i += 3;
            }
            SB => {
                // До IAC SE.
                match state[i + 2..].windows(2).position(|w| w == [IAC, SE]) {
                    Some(p) => i += 2 + p + 2,
                    None => break,
                }
            }
            _ => i += 2,
        }
    }
    state.drain(..i);
    out
}

async fn telnet(d: &Device, timeout: Duration, mut rx_in: mpsc::UnboundedReceiver<In>, tx_out: mpsc::UnboundedSender<Out>) -> Result<(), String> {
    let s = tokio::time::timeout(timeout, tokio::net::TcpStream::connect((d.host.trim(), d.port_or_default())))
        .await
        .map_err(|_| "Telnet: нет ответа".to_string())?
        .map_err(|e| format!("Telnet: {e}"))?;
    let (mut r, mut w) = s.into_split();
    let (tx_reply, mut rx_reply) = mpsc::unbounded_channel::<Vec<u8>>();
    let tx_out2 = tx_out.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut state = Vec::new();
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = tx_out2.send(Out::Closed("соединение закрыто устройством".into()));
                    return;
                }
                Ok(n) => {
                    let mut replies = Vec::new();
                    let data = telnet_filter(&mut state, &buf[..n], &mut replies);
                    if !replies.is_empty() {
                        let _ = tx_reply.send(replies);
                    }
                    if !data.is_empty() {
                        let _ = tx_out2.send(Out::Data(data));
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        loop {
            tokio::select! {
                rep = rx_reply.recv() => if let Some(b) = rep { let _ = w.write_all(&b).await; },
                inp = rx_in.recv() => match inp {
                    Some(In::Data(b)) => {
                        // IAC в данных удваивается.
                        let mut e = Vec::with_capacity(b.len());
                        for x in b {
                            e.push(x);
                            if x == IAC {
                                e.push(IAC);
                            }
                        }
                        if w.write_all(&e).await.is_err() {
                            let _ = tx_out.send(Out::Closed("ошибка отправки".into()));
                            return;
                        }
                    }
                    Some(In::Resize(..)) => {}
                    Some(In::Close) | None => {
                        let _ = w.shutdown().await;
                        let _ = tx_out.send(Out::Closed("отключено".into()));
                        return;
                    }
                },
            }
        }
    });
    Ok(())
}

fn serial(d: &Device, mut rx_in: mpsc::UnboundedReceiver<In>, tx_out: mpsc::UnboundedSender<Out>) -> Result<(), String> {
    let baud = if d.port == 0 { 9600 } else { d.port as u32 };
    let mut port = serialport::new(d.host.trim(), baud)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|e| format!("{}: {e}", d.host))?;
    let mut writer = port.try_clone().map_err(|e| e.to_string())?;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let tx_out2 = tx_out.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
            match port.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => {
                    let _ = tx_out2.send(Out::Data(buf[..n].to_vec()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    let _ = tx_out2.send(Out::Closed(format!("порт: {e}")));
                    return;
                }
            }
        }
    });
    std::thread::spawn(move || {
        while let Some(m) = rx_in.blocking_recv() {
            match m {
                In::Data(b) => {
                    if std::io::Write::write_all(&mut writer, &b).is_err() {
                        break;
                    }
                }
                In::Resize(..) => {}
                In::Close => break,
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = tx_out.send(Out::Closed("порт закрыт".into()));
    });
    Ok(())
}

/// Доступные COM-порты.
pub fn serial_ports() -> Vec<String> {
    serialport::available_ports().map(|v| v.into_iter().map(|p| p.port_name).collect()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Автоматическое выполнение команд
// ---------------------------------------------------------------------------

/// Текст без управляющих последовательностей терминала, \r и забоев.
pub fn clean(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => {
                // CSI: ESC [ … буква; прочие: ESC + символ.
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for n in chars.by_ref() {
                        if n.is_ascii_alphabetic() || n == '~' {
                            break;
                        }
                    }
                } else {
                    chars.next();
                }
            }
            // Забой не переходит на прошлую строку: так стирают «--More--», который мы уже убрали.
            '\x08' => {
                if !out.ends_with('\n') {
                    out.pop();
                }
            }
            '\r' | '\x07' | '\0' => {}
            c => out.push(c),
        }
    }
    out
}

/// Последняя строка похожа на приглашение (`sw1#`, `<HUAWEI>`, `[admin@MikroTik] >`, `user@host:~$`).
pub fn prompt_of(text: &str) -> Option<String> {
    let last = text.rsplit('\n').next()?.trim_end();
    let l = last.trim_start();
    let ends = l.ends_with('#') || l.ends_with('>') || l.ends_with(']') || l.ends_with('$') || l.ends_with("> ");
    (ends && !l.is_empty() && l.len() < 90 && !l.contains("  ")).then(|| l.to_string())
}

fn more_prompt(text: &str) -> bool {
    let tail: String = text.chars().rev().take(40).collect::<String>().chars().rev().collect();
    let t = tail.to_ascii_lowercase();
    t.contains("--more--") || t.contains("---- more ----") || t.contains("<--- more --->") || t.contains("press any key") || t.trim_end().ends_with("more")
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub vendor: crate::devices::Vendor,
    pub prompt: String,
    pub banner: String,
    pub outputs: Vec<(String, String)>,
}

struct Reader {
    conn: Conn,
    buf: Vec<u8>,
}

impl Reader {
    /// Читать, пока условие не выполнится или не истечёт время.
    async fn until(&mut self, timeout: Duration, mut done: impl FnMut(&str) -> bool) -> Result<String, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let text = clean(&self.buf);
            if more_prompt(&text) {
                let _ = self.conn.tx.send(In::Data(b" ".to_vec()));
                // Убираем «--More--» из накопленного.
                let s = String::from_utf8_lossy(&self.buf).to_string();
                let cut = s.to_ascii_lowercase().rfind("more").map(|p| s[..p].rfind('\n').map(|n| n + 1).unwrap_or(0)).unwrap_or(s.len());
                let mut keep = s.as_bytes()[..cut].to_vec();
                keep.extend_from_slice(b"\n");
                self.buf = keep;
            } else if done(&text) {
                return Ok(text);
            }
            match tokio::time::timeout_at(deadline, self.conn.rx.recv()).await {
                Ok(Some(Out::Data(d))) => self.buf.extend(d),
                Ok(Some(Out::Closed(why))) => return Err(why),
                Ok(None) => return Err("соединение закрыто".into()),
                Err(_) => return Err(format!("нет ответа за {} с; последнее: {}", timeout.as_secs(), text.lines().last().unwrap_or("").trim())),
            }
        }
    }

    fn send(&self, s: &str) {
        let _ = self.conn.tx.send(In::Data(s.as_bytes().to_vec()));
    }
}

/// Выполнить одну команду и вернуть вывод без эха и приглашения.
async fn exec(r: &mut Reader, cmd: &str, nl: &str, timeout: Duration, host_part: &str) -> Result<String, String> {
    r.buf.clear();
    r.send(&format!("{cmd}{nl}"));
    let is_prompt = |t: &str| prompt_of(t).is_some_and(|p| host_part.is_empty() || p.contains(host_part));
    let text = r.until(timeout * 3, |t| t.contains('\n') && is_prompt(t)).await?;
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.first().is_some_and(|l| l.contains(cmd.trim()) || l.trim().is_empty()) {
        lines.remove(0);
    }
    lines.pop();
    Ok(lines.join("\n").trim_end().to_string())
}

/// Войти, определить производителя, отключить постраничный вывод и выполнить команды.
pub async fn run_commands(d: &Device, cmds: &[String], timeout: Duration) -> Result<Session, String> {
    let conn = open(d, 511, 200, timeout).await?;
    let mut r = Reader { conn, buf: Vec::new() };
    // Telnet по стандарту NVT: перевод строки — CR LF.
    let nl = if d.vendor == crate::devices::Vendor::Mikrotik || d.proto == Proto::Telnet { "\r\n" } else { "\r" };
    // Вход для Telnet и COM: ждём приглашение или запрос имени/пароля.
    let mut sent_user = false;
    let mut sent_pass = false;
    // Telnet/COM: если устройство молчит — «разбудить» его переводом строки
    // (сразу слать нельзя: пустая строка уйдёт в ответ на запрос имени).
    if d.proto != Proto::Ssh && r.until(Duration::from_millis(1500), |t| !t.trim().is_empty()).await.is_err() {
        r.send(nl);
    }
    let banner = loop {
        let text = r
            .until(timeout, |t| {
                let low = t.to_ascii_lowercase();
                let last = low.rsplit('\n').next().unwrap_or("").trim_end();
                prompt_of(t).is_some() || last.ends_with("username:") || last.ends_with("login:") || last.ends_with("password:")
            })
            .await?;
        let last = text.rsplit('\n').next().unwrap_or("").trim_end().to_ascii_lowercase();
        if (last.ends_with("username:") || last.ends_with("login:")) && !sent_user {
            sent_user = true;
            r.buf.clear();
            r.send(&format!("{}{nl}", d.user));
        } else if last.ends_with("password:") && !sent_pass {
            sent_pass = true;
            r.buf.clear();
            r.send(&format!("{}{nl}", d.password()));
        } else if last.ends_with("password:") || last.ends_with("username:") {
            return Err("вход не выполнен — проверьте имя и пароль".into());
        } else {
            break text;
        }
    };
    let mut prompt = prompt_of(&banner).ok_or("не найдено приглашение командной строки")?;
    // Привилегированный режим (Cisco-подобные).
    if prompt.ends_with('>') && !prompt.starts_with('<') && !d.enable_password().is_empty() {
        r.buf.clear();
        r.send(&format!("enable{nl}"));
        let t = r.until(timeout, |t| t.to_ascii_lowercase().trim_end().ends_with("password:") || prompt_of(t).is_some_and(|p| p.ends_with('#'))).await?;
        if t.to_ascii_lowercase().trim_end().ends_with("password:") {
            r.buf.clear();
            r.send(&format!("{}{nl}", d.enable_password()));
            let t = r.until(timeout, |t| prompt_of(t).is_some()).await?;
            prompt = prompt_of(&t).unwrap_or(prompt);
        }
    }
    let host_part: String = prompt.trim_matches(|c: char| "<>[]#$ ".contains(c)).chars().take(6).collect();
    let mut vendor = d.vendor;
    let mut session = Session::default();
    if vendor == crate::devices::Vendor::Auto {
        vendor = crate::devices::Vendor::detect(&format!("{banner}\n{prompt}"));
    }
    if vendor == crate::devices::Vendor::Auto {
        // Пробуем `show version`, затем `display version`.
        for probe in ["show version", "display version", "/system resource print"] {
            let out = exec(&mut r, probe, nl, timeout, &host_part).await.unwrap_or_default();
            let v = crate::devices::Vendor::detect(&out);
            if v != crate::devices::Vendor::Auto {
                vendor = v;
                break;
            }
        }
    }
    for p in vendor.profile().paging {
        let _ = exec(&mut r, p, nl, timeout, &host_part).await;
    }
    for c in cmds {
        let out = exec(&mut r, c, nl, timeout, &host_part).await?;
        session.outputs.push((c.clone(), out));
    }
    let _ = r.conn.tx.send(In::Data(format!("exit{nl}").into_bytes()));
    let _ = r.conn.tx.send(In::Close);
    session.vendor = vendor;
    session.prompt = prompt;
    session.banner = banner;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telnet_negotiation() {
        let mut st = Vec::new();
        let mut rep = Vec::new();
        let out = telnet_filter(&mut st, &[IAC, WILL, 1, b'h', b'i', IAC, DO, 24, IAC, IAC, IAC], &mut rep);
        assert_eq!(out, vec![b'h', b'i', IAC]);
        assert_eq!(rep, vec![IAC, DO, 1, IAC, WONT, 24]);
        assert_eq!(st, vec![IAC], "незавершённая команда ждёт продолжения");
        let out = telnet_filter(&mut st, &[SB, 31, 0, 80, IAC, SE, b'!'], &mut rep);
        assert_eq!(out, vec![b'!']);
    }

    #[test]
    fn cleaning_and_prompts() {
        assert_eq!(clean(b"\x1b[0;32mok\x1b[0m\r\nab\x08c"), "ok\nac");
        assert_eq!(prompt_of("text\nsw1#").as_deref(), Some("sw1#"));
        assert_eq!(prompt_of("x\n<HUAWEI>").as_deref(), Some("<HUAWEI>"));
        assert_eq!(prompt_of("[admin@MikroTik] > ").as_deref(), Some("[admin@MikroTik] >"));
        assert!(prompt_of("Building configuration...").is_none());
        assert!(more_prompt("line\n --More-- "));
    }

    /// Поддельное устройство Telnet: вход, приглашение, постраничный вывод.
    #[tokio::test]
    async fn telnet_automation() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let line = async |s: &mut tokio::net::TcpStream| -> String {
                let mut acc = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return String::new();
                    }
                    // Команды Telnet и пустые строки пропускаем.
                    acc.extend(buf[..n].iter().filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\r'));
                    if let Some(p) = acc.iter().position(|b| *b == b'\r') {
                        let l = String::from_utf8_lossy(&acc[..p]).trim().to_string();
                        acc.drain(..=p);
                        if !l.is_empty() {
                            return l;
                        }
                    }
                }
            };
            s.write_all(&[IAC, WILL, 1]).await.unwrap();
            s.write_all(b"\r\nUser Access Verification\r\n\r\nUsername: ").await.unwrap();
            assert_eq!(line(&mut s).await, "admin");
            s.write_all(b"Password: ").await.unwrap();
            assert_eq!(line(&mut s).await, "secret");
            s.write_all(b"\r\nsw-test#").await.unwrap();
            loop {
                let cmd = line(&mut s).await;
                match cmd.as_str() {
                    "" | "exit" => return,
                    "show version" => s.write_all(b"show version\r\nCisco IOS Software, C2960\r\nsw-test#").await.unwrap(),
                    "show vlan brief" => {
                        s.write_all(b"show vlan brief\r\nVLAN Name\r\n1    default\r\n --More-- ").await.unwrap();
                        let _ = s.read(&mut buf).await.unwrap();
                        s.write_all(b"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x0810   users\r\nsw-test#").await.unwrap();
                    }
                    other => s.write_all(format!("{other}\r\nsw-test#").as_bytes()).await.unwrap(),
                }
            }
        });
        let d = Device {
            host: "127.0.0.1".into(),
            proto: Proto::Telnet,
            port,
            user: "admin".into(),
            secret: "secret".into(),
            ..Default::default()
        };
        let s = run_commands(&d, &["show vlan brief".into()], Duration::from_secs(3)).await.unwrap();
        assert_eq!(s.vendor, crate::devices::Vendor::CiscoIos);
        assert_eq!(s.prompt, "sw-test#");
        let out = &s.outputs[0].1;
        assert!(out.contains("1    default") && out.contains("10   users") && !out.contains("More"), "{out:?}");
    }
}

#[cfg(test)]
mod ssh_tests {
    use std::sync::Arc;

    use russh::server::{Auth, Msg, Server as _, Session as SrvSession};
    use russh::{Channel, ChannelId};

    use crate::devices::{Device, Proto, Vendor};

    const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7XI6XeM/fF14o0r3cVe3/I35Svsozs8bUm5Wt/NfwegAAAIj3GLQl9xi0
JQAAAAtzc2gtZWQyNTUxOQAAACB7XI6XeM/fF14o0r3cVe3/I35Svsozs8bUm5Wt/Nfweg
AAAEC/Z5+nd0DAVD0EL2sjJSKMFKwfjRpYwwSIWh21RvU3UXtcjpd4z98XXijSvdxV7f8j
flK+yjOzxtSbla381/B6AAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----
";

    /// Поддельный коммутатор Cisco по SSH.
    #[derive(Clone, Default)]
    struct Fake {
        line: String,
    }

    impl russh::server::Server for Fake {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            Self::default()
        }
    }

    impl russh::server::Handler for Fake {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            Ok(if user == "admin" && password == "pw" { Auth::Accept } else { Auth::reject() })
        }
        async fn channel_open_session(&mut self, _c: Channel<Msg>, reply: russh::server::ChannelOpenHandle, _s: &mut SrvSession) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        #[allow(clippy::too_many_arguments)]
        async fn pty_request(&mut self, ch: ChannelId, _t: &str, _c: u32, _r: u32, _pw: u32, _ph: u32, _m: &[(russh::Pty, u32)], s: &mut SrvSession) -> Result<(), Self::Error> {
            s.channel_success(ch)?;
            Ok(())
        }
        async fn shell_request(&mut self, ch: ChannelId, s: &mut SrvSession) -> Result<(), Self::Error> {
            s.channel_success(ch)?;
            s.data(ch, b"\r\nWelcome\r\nsw-ssh#".to_vec())?;
            Ok(())
        }
        async fn data(&mut self, ch: ChannelId, data: &[u8], s: &mut SrvSession) -> Result<(), Self::Error> {
            for &b in data {
                if b == b'\r' || b == b'\n' {
                    let cmd = std::mem::take(&mut self.line);
                    let out = match cmd.trim() {
                        "" => String::new(),
                        "terminal length 0" | "terminal width 0" => String::new(),
                        "show version" => "Cisco IOS Software, C2960 Software, Version 15.2(7)E\r\nuptime is 3 weeks\r\n".into(),
                        "show clock" => "10:00:00.000 UTC Wed Nov 18 2026\r\n".into(),
                        other => format!("% Invalid input detected: {other}\r\n"),
                    };
                    if !cmd.trim().is_empty() || b == b'\r' {
                        s.data(ch, format!("{cmd}\r\n{out}sw-ssh#").into_bytes())?;
                    }
                } else {
                    self.line.push(b as char);
                }
            }
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ssh_automation() {
        let key = russh::keys::decode_secret_key(KEY, None).unwrap();
        let config = Arc::new(russh::server::Config { keys: vec![key], auth_rejection_time: std::time::Duration::from_millis(10), ..Default::default() });
        let sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut f = Fake::default();
            let _ = f.run_on_socket(config, &sock).await;
        });
        let d = Device { name: "sw-ssh".into(), host: "127.0.0.1".into(), proto: Proto::Ssh, port, user: "admin".into(), secret: "pw".into(), ..Default::default() };
        let s = super::run_commands(&d, &["show version".into(), "show clock".into()], std::time::Duration::from_secs(5)).await.unwrap();
        assert_eq!(s.vendor, Vendor::CiscoIos);
        assert_eq!(s.outputs.len(), 2);
        assert!(s.outputs[0].1.contains("Version 15.2(7)E"), "{:?}", s.outputs);
        assert!(s.outputs[1].1.contains("Nov 18 2026"), "{:?}", s.outputs);
        let mut bad = d.clone();
        bad.secret = "wrong".into();
        assert!(super::run_commands(&bad, &[], std::time::Duration::from_secs(5)).await.is_err());
    }
}
