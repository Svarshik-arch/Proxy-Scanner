//! Общие ресурсы на узлах: SMB-шары (перечень и признак доступа без пароля) и
//! NFS-экспорты. Содержимое ресурсов не читается.
//!
//! SMB — собственный клиент SMB 2.0.2/2.1: вход анонимно или с логином и паролем
//! (NTLMv2, с подписью сообщений), DCERPC srvsvc NetrShareEnum. В Windows можно
//! перечислять под текущим пользователем через `net view`.
//! NFS — ONC RPC: portmapper → mountd EXPORT.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::Sink;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Login {
    /// Анонимно (null session), при отказе — гостем.
    #[default]
    Anonymous,
    /// Логин и пароль (NTLMv2).
    Account,
    /// Windows: текущий пользователь (`net view`).
    CurrentUser,
}

impl Login {
    pub fn label(self) -> &'static str {
        match self {
            Login::Anonymous => "анонимно",
            Login::Account => "учётная запись",
            Login::CurrentUser => "текущий пользователь Windows",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub targets: String,
    pub smb: bool,
    pub nfs: bool,
    pub login: Login,
    pub user: String,
    pub domain: String,
    #[serde(skip)]
    pub password: String,
    /// Проверять подключение к каждой шаре (без чтения содержимого).
    pub check_access: bool,
    pub timeout_ms: u64,
    pub concurrency: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: String::new(),
            smb: true,
            nfs: true,
            login: Login::Anonymous,
            user: String::new(),
            domain: String::new(),
            password: String::new(),
            check_access: true,
            timeout_ms: 4000,
            concurrency: 32,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub host: String,
    pub kind: String,
    pub name: String,
    pub comment: String,
    /// Подключение к шаре удалось (тем способом входа, что выбран).
    pub accessible: Option<bool>,
    pub login: String,
    /// Для NFS — кому разрешено.
    pub clients: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub host: String,
    pub smb: Option<Result<String, String>>,
    pub nfs: Option<Result<String, String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub shares: Vec<Share>,
    pub hosts: Vec<HostResult>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Log(String),
    Total(u64),
    Host(Box<HostResult>, Vec<Share>),
}

// ---------------------------------------------------------------------------
// SMB2
// ---------------------------------------------------------------------------

const STATUS_SUCCESS: u32 = 0;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

fn status_text(s: u32) -> String {
    match s {
        0xC000_0022 => "доступ запрещён".into(),
        0xC000_006D => "вход отклонён (неверные учётные данные или анонимный вход запрещён)".into(),
        0xC000_00CC => "шара не найдена".into(),
        0xC000_0034 => "объект не найден".into(),
        0xC000_00BB => "не поддерживается".into(),
        0xC000_0203 => "сеанс удалён".into(),
        0xC000_015B => "этот тип входа запрещён политикой".into(),
        other => format!("код {other:#010x}"),
    }
}

fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn u32le(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

struct Smb {
    s: TcpStream,
    timeout: Duration,
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    sign_key: Option<[u8; 16]>,
}

struct Reply {
    status: u32,
    header: Vec<u8>,
    body: Vec<u8>,
    raw: Vec<u8>,
}

impl Smb {
    async fn connect(addr: SocketAddr, timeout: Duration) -> Result<Self, String> {
        let s = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| "SMB: нет подключения к 445".to_string())?
            .map_err(|e| format!("SMB: {e}"))?;
        Ok(Self {
            s,
            timeout,
            msg_id: 0,
            session_id: 0,
            tree_id: 0,
            sign_key: None,
        })
    }

    async fn call(&mut self, cmd: u16, body: &[u8]) -> Result<Reply, String> {
        let mut h = vec![0xFE, b'S', b'M', b'B', 64, 0];
        h.extend_from_slice(&1u16.to_le_bytes()); // credit charge
        h.extend_from_slice(&0u32.to_le_bytes()); // status
        h.extend_from_slice(&cmd.to_le_bytes());
        h.extend_from_slice(&31u16.to_le_bytes()); // credits requested
        let flags: u32 = if self.sign_key.is_some() { 0x08 } else { 0 };
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // next command
        h.extend_from_slice(&self.msg_id.to_le_bytes());
        h.extend_from_slice(&0xFEFFu32.to_le_bytes()); // process id
        h.extend_from_slice(&self.tree_id.to_le_bytes());
        h.extend_from_slice(&self.session_id.to_le_bytes());
        h.extend_from_slice(&[0; 16]);
        self.msg_id += 1;
        let mut msg = h;
        msg.extend_from_slice(body);
        if let Some(key) = &self.sign_key {
            let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
            let sig = ring::hmac::sign(&k, &msg);
            msg[48..64].copy_from_slice(&sig.as_ref()[..16]);
        }
        let mut framed = (msg.len() as u32).to_be_bytes().to_vec();
        framed.extend(msg);
        tokio::time::timeout(self.timeout, self.s.write_all(&framed))
            .await
            .map_err(|_| "SMB: таймаут отправки".to_string())?
            .map_err(|e| e.to_string())?;
        loop {
            let mut len = [0u8; 4];
            tokio::time::timeout(self.timeout, self.s.read_exact(&mut len))
                .await
                .map_err(|_| "SMB: нет ответа".to_string())?
                .map_err(|e| format!("SMB: соединение закрыто ({e})"))?;
            let n = (u32::from_be_bytes(len) & 0x00FF_FFFF) as usize;
            let mut buf = vec![0u8; n];
            tokio::time::timeout(self.timeout, self.s.read_exact(&mut buf))
                .await
                .map_err(|_| "SMB: ответ обрезан".to_string())?
                .map_err(|e| e.to_string())?;
            if buf.len() < 64 || &buf[..4] != b"\xFESMB" {
                return Err("SMB: ответ не SMB2".into());
            }
            let status = u32le(&buf, 8);
            if status == STATUS_PENDING {
                continue;
            }
            return Ok(Reply {
                status,
                header: buf[..64].to_vec(),
                body: buf[64..].to_vec(),
                raw: buf,
            });
        }
    }

    async fn negotiate(&mut self) -> Result<bool, String> {
        // Только SMB 2.0.2 и 2.1: подпись HMAC-SHA256 без AES-CMAC.
        let dialects: [u16; 2] = [0x0202, 0x0210];
        let mut b = Vec::new();
        b.extend_from_slice(&36u16.to_le_bytes());
        b.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes()); // signing enabled
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(b"proxy-scanner-sm");
        b.extend_from_slice(&[0; 8]);
        for d in dialects {
            b.extend_from_slice(&d.to_le_bytes());
        }
        let r = self.call(0, &b).await?;
        if r.status != STATUS_SUCCESS || r.body.len() < 8 {
            return Err(format!(
                "SMB: согласование не удалось ({}) — возможно, на сервере отключены SMB 2.0/2.1",
                status_text(r.status)
            ));
        }
        Ok(u16le(&r.body, 2) & 0x02 != 0)
    }

    async fn session_setup(&mut self, token: &[u8]) -> Result<Reply, String> {
        let mut b = Vec::new();
        b.extend_from_slice(&25u16.to_le_bytes());
        b.push(0);
        b.push(1); // signing enabled
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(64u16 + 24).to_le_bytes());
        b.extend_from_slice(&(token.len() as u16).to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(token);
        let r = self.call(1, &b).await?;
        self.session_id = u64::from_le_bytes(r.header[40..48].try_into().unwrap());
        Ok(r)
    }

    /// Вход: анонимно или с NTLMv2. Возвращает описание («анонимно», «гость», «DOMAIN\user»).
    async fn login(&mut self, cfg: &Config) -> Result<String, String> {
        let signing_required = self.negotiate().await?;
        let r = self.session_setup(&crate::auth::negotiate_message()).await?;
        if r.status != STATUS_MORE_PROCESSING || r.body.len() < 8 {
            return Err(format!("SMB: вход ({})", status_text(r.status)));
        }
        let off = u16le(&r.body, 4) as usize;
        let len = u16le(&r.body, 6) as usize;
        let token = r.raw.get(off..off + len).ok_or("SMB: нет токена NTLM")?;
        let ch = crate::auth::parse_challenge(token)?;
        let (auth, key, who) = match cfg.login {
            Login::Account if !cfg.user.trim().is_empty() => {
                let creds = crate::auth::Credentials {
                    user: cfg.user.trim().to_string(),
                    domain: cfg.domain.trim().to_string(),
                    password: cfg.password.clone(),
                    ..Default::default()
                };
                let (user, domain) = creds.split_user();
                let mut cc = [0u8; 8];
                let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut cc);
                let msg = crate::auth::authenticate_message(&ch, &user, &domain, &cfg.password, cc, &crate::session::computer_name());
                // Ключ сеанса NTLMv2 без обмена ключами: HMAC-MD5(NTOWFv2, NTProofStr).
                let nt_off = u32le(&msg, 24) as usize;
                let proof = &msg[nt_off..nt_off + 16];
                let ntowf = crate::auth::ntowf_v2(&user, &cfg.password, &domain);
                let key = crate::auth::hmac_md5(&ntowf, &[proof]);
                let who = if domain.is_empty() { user } else { format!("{domain}\\{user}") };
                (msg, Some(key), who)
            }
            _ => (anonymous_authenticate(ch.flags), None, "анонимно".to_string()),
        };
        let r = self.session_setup(&auth).await?;
        if r.status != STATUS_SUCCESS {
            return Err(format!("SMB: вход «{who}» — {}", status_text(r.status)));
        }
        let session_flags = u16le(&r.body, 2);
        let guest_or_null = session_flags & 0x03 != 0;
        if !guest_or_null && let Some(k) = key {
            // Подписываем, если сервер требует (или всегда — вреда нет).
            let _ = signing_required;
            self.sign_key = Some(k);
        }
        Ok(match (cfg.login, session_flags) {
            (_, f) if f & 0x02 != 0 => "анонимно".into(),
            (_, f) if f & 0x01 != 0 => "гостем".into(),
            _ => who,
        })
    }

    async fn tree_connect(&mut self, path: &str) -> Result<u8, u32> {
        let p = utf16(path);
        let mut b = Vec::new();
        b.extend_from_slice(&9u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(64u16 + 8).to_le_bytes());
        b.extend_from_slice(&(p.len() as u16).to_le_bytes());
        b.extend_from_slice(&p);
        let r = self.call(3, &b).await.map_err(|_| 0xFFFF_FFFFu32)?;
        if r.status != STATUS_SUCCESS {
            return Err(r.status);
        }
        self.tree_id = u32le(&r.header, 36);
        Ok(r.body.get(2).copied().unwrap_or(0))
    }

    async fn tree_disconnect(&mut self) {
        let _ = self.call(4, &[4, 0, 0, 0]).await;
    }

    async fn create_pipe(&mut self, name: &str) -> Result<[u8; 16], String> {
        let n = utf16(name);
        let mut b = Vec::new();
        b.extend_from_slice(&57u16.to_le_bytes());
        b.push(0);
        b.push(0);
        b.extend_from_slice(&2u32.to_le_bytes()); // impersonation
        b.extend_from_slice(&[0; 16]);
        b.extend_from_slice(&0x0012_019Fu32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // FILE_OPEN
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(64u16 + 56).to_le_bytes());
        b.extend_from_slice(&(n.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&n);
        let r = self.call(5, &b).await?;
        if r.status != STATUS_SUCCESS || r.body.len() < 80 {
            return Err(format!("SMB: канал {name}: {}", status_text(r.status)));
        }
        Ok(r.body[64..80].try_into().unwrap())
    }

    async fn write(&mut self, fid: &[u8; 16], data: &[u8]) -> Result<(), String> {
        let mut b = Vec::new();
        b.extend_from_slice(&49u16.to_le_bytes());
        b.extend_from_slice(&(64u16 + 48).to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(fid);
        b.extend_from_slice(&[0; 16]);
        b.extend_from_slice(data);
        let r = self.call(9, &b).await?;
        if r.status != STATUS_SUCCESS {
            return Err(format!("SMB: запись в канал: {}", status_text(r.status)));
        }
        Ok(())
    }

    async fn read(&mut self, fid: &[u8; 16]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        loop {
            let mut b = Vec::new();
            b.extend_from_slice(&49u16.to_le_bytes());
            b.push(0x50);
            b.push(0);
            b.extend_from_slice(&65536u32.to_le_bytes());
            b.extend_from_slice(&0u64.to_le_bytes());
            b.extend_from_slice(fid);
            b.extend_from_slice(&[0; 16]);
            b.push(0);
            let r = self.call(8, &b).await?;
            if r.status != STATUS_SUCCESS && r.status != STATUS_BUFFER_OVERFLOW {
                return Err(format!("SMB: чтение из канала: {}", status_text(r.status)));
            }
            let off = r.body.get(2).copied().unwrap_or(0) as usize;
            let len = u32le(&r.body, 4) as usize;
            out.extend_from_slice(r.raw.get(off..off + len).ok_or("SMB: ответ обрезан")?);
            if r.status == STATUS_SUCCESS {
                return Ok(out);
            }
        }
    }
}

/// NTLMSSP AUTHENTICATE для анонимного входа: пустые имя и ответы, флаг ANONYMOUS.
pub fn anonymous_authenticate(challenge_flags: u32) -> Vec<u8> {
    let flags = (challenge_flags & 0xE288_8215) | 0x0000_0800 | 0x0000_0001;
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend_from_slice(&3u32.to_le_bytes());
    let base = 64u32;
    // LM: один нулевой байт; NT, домен, пользователь, рабочая станция, ключ — пусто.
    let fields: [(u16, u32); 6] = [(1, base), (0, base + 1), (0, base + 1), (0, base + 1), (0, base + 1), (0, base + 1)];
    for (len, off) in fields {
        m.extend_from_slice(&len.to_le_bytes());
        m.extend_from_slice(&len.to_le_bytes());
        m.extend_from_slice(&off.to_le_bytes());
    }
    m.extend_from_slice(&flags.to_le_bytes());
    m.push(0);
    m
}

// ---------------------------------------------------------------------------
// DCERPC srvsvc NetrShareEnum
// ---------------------------------------------------------------------------

const SRVSVC: [u8; 16] = [0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88];
const NDR: [u8; 16] = [0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60];

fn rpc_header(ptype: u8, frag_len: u16, call_id: u32) -> Vec<u8> {
    let mut h = vec![5, 0, ptype, 0x03, 0x10, 0, 0, 0];
    h.extend_from_slice(&frag_len.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes());
    h.extend_from_slice(&call_id.to_le_bytes());
    h
}

pub fn rpc_bind() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&4280u16.to_le_bytes());
    b.extend_from_slice(&4280u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&[1, 0, 0, 0]);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&[1, 0]);
    b.extend_from_slice(&SRVSVC);
    b.extend_from_slice(&3u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&NDR);
    b.extend_from_slice(&2u32.to_le_bytes());
    let mut m = rpc_header(11, (16 + b.len()) as u16, 1);
    m.extend(b);
    m
}

fn ndr_string(out: &mut Vec<u8>, s: &str) {
    let chars: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let n = chars.len() as u32;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    for c in chars {
        out.extend_from_slice(&c.to_le_bytes());
    }
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

pub fn share_enum_request(server: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
    ndr_string(&mut stub, &format!("\\\\{server}"));
    stub.extend_from_slice(&1u32.to_le_bytes()); // level
    stub.extend_from_slice(&1u32.to_le_bytes()); // switch
    stub.extend_from_slice(&0x0002_0004u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes()); // entries read
    stub.extend_from_slice(&0u32.to_le_bytes()); // null buffer
    stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    stub.extend_from_slice(&0x0002_0008u32.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes());
    let mut body = (stub.len() as u32).to_le_bytes().to_vec();
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&15u16.to_le_bytes()); // opnum NetrShareEnum
    body.extend(stub);
    let mut m = rpc_header(0, (16 + body.len()) as u16, 2);
    m.extend(body);
    m
}

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl Cur<'_> {
    fn u32(&mut self) -> Option<u32> {
        let v = u32::from_le_bytes(self.b.get(self.i..self.i + 4)?.try_into().ok()?);
        self.i += 4;
        Some(v)
    }
    fn string(&mut self) -> Option<String> {
        let _max = self.u32()?;
        let _off = self.u32()?;
        let n = self.u32()? as usize;
        let raw = self.b.get(self.i..self.i + n * 2)?;
        self.i += n * 2;
        while !self.i.is_multiple_of(4) {
            self.i += 1;
        }
        let units: Vec<u16> = raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&units).trim_end_matches('\0').to_string())
    }
}

/// Разбор ответа NetrShareEnum (уровень 1): (имя, тип, комментарий).
pub fn parse_share_enum(pdu: &[u8]) -> Result<Vec<(String, u32, String)>, String> {
    if pdu.len() < 24 || pdu[0] != 5 {
        return Err("ответ не DCERPC".into());
    }
    match pdu[2] {
        2 => {}
        3 => return Err(format!("отказ RPC (код {:#x})", u32le(pdu, 24))),
        p => return Err(format!("неожиданный ответ RPC ({p})")),
    }
    let mut c = Cur { b: &pdu[24..], i: 0 };
    let bad = || "ответ NetrShareEnum не разобран".to_string();
    let _level = c.u32().ok_or_else(bad)?;
    let _switch = c.u32().ok_or_else(bad)?;
    let ptr = c.u32().ok_or_else(bad)?;
    if ptr == 0 {
        return Ok(Vec::new());
    }
    let count = c.u32().ok_or_else(bad)? as usize;
    let arr = c.u32().ok_or_else(bad)?;
    if arr == 0 || count == 0 {
        return Ok(Vec::new());
    }
    let max = c.u32().ok_or_else(bad)? as usize;
    let mut entries = Vec::new();
    for _ in 0..max.min(count).min(10_000) {
        let name_ptr = c.u32().ok_or_else(bad)?;
        let ty = c.u32().ok_or_else(bad)?;
        let remark_ptr = c.u32().ok_or_else(bad)?;
        entries.push((name_ptr, ty, remark_ptr));
    }
    let mut out = Vec::new();
    for (np, ty, rp) in entries {
        let name = if np != 0 { c.string().ok_or_else(bad)? } else { String::new() };
        let remark = if rp != 0 { c.string().ok_or_else(bad)? } else { String::new() };
        out.push((name, ty, remark));
    }
    Ok(out)
}

pub fn share_type(t: u32) -> String {
    let base = match t & 0x0FFF_FFFF {
        0 => "диск",
        1 => "принтер",
        2 => "устройство",
        3 => "IPC",
        _ => "?",
    };
    if t & 0x8000_0000 != 0 { format!("{base} (служебная)") } else { base.to_string() }
}

async fn smb_enum(host: &str, ip: IpAddr, cfg: &Config) -> Result<(String, Vec<Share>), String> {
    let timeout = Duration::from_millis(cfg.timeout_ms.max(500));
    let addr = SocketAddr::new(ip, 445);
    let mut smb = Smb::connect(addr, timeout).await?;
    let who = smb.login(cfg).await?;
    smb.tree_connect(&format!("\\\\{host}\\IPC$"))
        .await
        .map_err(|s| format!("IPC$ ({who}): {}", status_text(s)))?;
    let fid = smb.create_pipe("srvsvc").await?;
    smb.write(&fid, &rpc_bind()).await?;
    let ack = smb.read(&fid).await?;
    if ack.get(2) != Some(&12) {
        return Err("srvsvc: привязка RPC отклонена".into());
    }
    smb.write(&fid, &share_enum_request(host)).await?;
    let resp = smb.read(&fid).await?;
    let list = parse_share_enum(&resp)?;
    smb.tree_disconnect().await;
    let mut shares = Vec::new();
    for (name, ty, comment) in list {
        let mut accessible = None;
        if cfg.check_access && ty & 0x0FFF_FFFF == 0 {
            accessible = Some(smb.tree_connect(&format!("\\\\{host}\\{name}")).await.is_ok());
            if accessible == Some(true) {
                smb.tree_disconnect().await;
            }
        }
        shares.push(Share {
            host: host.to_string(),
            kind: format!("SMB {}", share_type(ty)),
            name,
            comment,
            accessible,
            login: who.clone(),
            clients: String::new(),
        });
    }
    Ok((who, shares))
}

/// Windows: перечень под текущим пользователем средствами системы.
#[cfg(windows)]
fn net_view(host: &str) -> Result<Vec<Share>, String> {
    let o = crate::util::run_cmd("net", &["view", &format!("\\\\{host}"), "/all"])?;
    let text = o.stdout;
    let mut started = false;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with("---") {
            started = true;
            continue;
        }
        if !started || line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split("  ").map(str::trim).filter(|c| !c.is_empty()).collect();
        if cols.len() < 2 {
            break;
        }
        out.push(Share {
            host: host.to_string(),
            kind: format!("SMB {}", cols[1].to_lowercase()),
            name: cols[0].to_string(),
            comment: cols.get(2..).map(|c| c.join(" ")).unwrap_or_default(),
            accessible: Some(true),
            login: "текущий пользователь".into(),
            clients: String::new(),
        });
    }
    if out.is_empty() {
        return Err(format!("net view: {}", (text + &o.stderr).trim()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// NFS (ONC RPC)
// ---------------------------------------------------------------------------

fn rpc_call(xid: u32, prog: u32, vers: u32, proc_: u32, args: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    for v in [xid, 0, 2, prog, vers, proc_, 0, 0, 0, 0] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    m.extend_from_slice(args);
    let mut framed = (0x8000_0000u32 | m.len() as u32).to_be_bytes().to_vec();
    framed.extend(m);
    framed
}

async fn rpc_tcp(addr: SocketAddr, msg: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("{addr}: нет подключения"))?
        .map_err(|e| format!("{addr}: {e}"))?;
    s.write_all(msg).await.map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    loop {
        let mut mark = [0u8; 4];
        tokio::time::timeout(timeout, s.read_exact(&mut mark)).await.map_err(|_| "RPC: нет ответа".to_string())?.map_err(|e| e.to_string())?;
        let m = u32::from_be_bytes(mark);
        let len = (m & 0x7FFF_FFFF) as usize;
        let mut frag = vec![0u8; len.min(4 << 20)];
        tokio::time::timeout(timeout, s.read_exact(&mut frag)).await.map_err(|_| "RPC: ответ обрезан".to_string())?.map_err(|e| e.to_string())?;
        out.extend(frag);
        if m & 0x8000_0000 != 0 {
            return Ok(out);
        }
    }
}

/// Тело успешного ответа RPC (после заголовка и verifier).
fn rpc_body(r: &[u8]) -> Result<&[u8], String> {
    let be = |i: usize| r.get(i..i + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap()));
    if be(4) != Some(1) || be(8) != Some(0) {
        return Err("RPC: вызов отклонён".into());
    }
    let vlen = be(16).ok_or("RPC: ответ обрезан")? as usize;
    let p = 20 + vlen.div_ceil(4) * 4;
    if be(p) != Some(0) {
        return Err(format!("RPC: ошибка выполнения ({})", be(p).unwrap_or(0)));
    }
    r.get(p + 4..).ok_or_else(|| "RPC: ответ обрезан".into())
}

/// Разбор списка экспортов mountd: (каталог, кому разрешено).
pub fn parse_exports(b: &[u8]) -> Vec<(String, Vec<String>)> {
    let mut i = 0;
    let be = |i: usize| b.get(i..i + 4).map(|x| u32::from_be_bytes(x.try_into().unwrap()));
    let mut out = Vec::new();
    let read_str = |i: &mut usize| -> Option<String> {
        let n = be(*i)? as usize;
        let s = String::from_utf8_lossy(b.get(*i + 4..*i + 4 + n)?).into_owned();
        *i += 4 + n.div_ceil(4) * 4;
        Some(s)
    };
    while be(i) == Some(1) && out.len() < 10_000 {
        i += 4;
        let Some(dir) = read_str(&mut i) else { break };
        let mut groups = Vec::new();
        while be(i) == Some(1) {
            i += 4;
            match read_str(&mut i) {
                Some(g) => groups.push(g),
                None => break,
            }
        }
        i += 4;
        out.push((dir, groups));
    }
    out
}

async fn nfs_exports(host: &str, ip: IpAddr, timeout: Duration) -> Result<Vec<Share>, String> {
    // portmapper GETPORT(mountd 100005, v3, TCP)
    let mut args = Vec::new();
    for v in [100_005u32, 3, 6, 0] {
        args.extend_from_slice(&v.to_be_bytes());
    }
    let r = rpc_tcp(SocketAddr::new(ip, 111), &rpc_call(1, 100_000, 2, 3, &args), timeout).await?;
    let body = rpc_body(&r)?;
    let port = body.get(..4).map(|x| u32::from_be_bytes(x.try_into().unwrap())).unwrap_or(0);
    if port == 0 || port > 65535 {
        return Err("mountd не зарегистрирован".into());
    }
    let r = rpc_tcp(SocketAddr::new(ip, port as u16), &rpc_call(2, 100_005, 3, 5, &[]), timeout).await?;
    let list = parse_exports(rpc_body(&r)?);
    Ok(list
        .into_iter()
        .map(|(dir, groups)| Share {
            host: host.to_string(),
            kind: "NFS".into(),
            name: dir,
            comment: String::new(),
            accessible: None,
            login: String::new(),
            clients: if groups.is_empty() { "все (*)".into() } else { groups.join(", ") },
        })
        .collect())
}

pub async fn run(cfg: Config, sink: Sink<Event>, cancel: CancellationToken) {
    let hosts = match super::HostList::parse(&cfg.targets) {
        Ok(h) => h,
        Err(e) => return sink.send(Event::Log(e)),
    };
    let items: Vec<String> = hosts.items().collect();
    sink.send(Event::Total(items.len() as u64));
    let cfg = Arc::new(cfg);
    super::for_each_limited(items, cfg.concurrency, &cancel, |host| {
        let (cfg, sink) = (cfg.clone(), sink.clone());
        async move {
            let timeout = Duration::from_millis(cfg.timeout_ms.max(500));
            let mut res = HostResult {
                host: host.clone(),
                smb: None,
                nfs: None,
            };
            let mut shares = Vec::new();
            let ip = match super::resolve(&host, timeout).await {
                Ok(ip) => ip,
                Err(e) => {
                    res.smb = Some(Err(e));
                    sink.send(Event::Host(Box::new(res), shares));
                    return;
                }
            };
            if cfg.smb {
                #[cfg(windows)]
                let via_net = cfg.login == Login::CurrentUser;
                #[cfg(not(windows))]
                let via_net = false;
                if via_net {
                    #[cfg(windows)]
                    {
                        let h = host.clone();
                        res.smb = Some(match tokio::task::spawn_blocking(move || net_view(&h)).await {
                            Ok(Ok(list)) => {
                                shares.extend(list);
                                Ok("текущий пользователь".into())
                            }
                            Ok(Err(e)) => Err(e),
                            Err(e) => Err(e.to_string()),
                        });
                    }
                } else {
                    res.smb = Some(match smb_enum(&host, ip, &cfg).await {
                        Ok((who, list)) => {
                            shares.extend(list);
                            Ok(who)
                        }
                        Err(e) => Err(e),
                    });
                }
            }
            if cfg.nfs {
                res.nfs = Some(match nfs_exports(&host, ip, timeout).await {
                    Ok(list) => {
                        let n = list.len();
                        shares.extend(list);
                        Ok(format!("экспортов: {n}"))
                    }
                    Err(e) => Err(e),
                });
            }
            sink.send(Event::Host(Box::new(res), shares));
        }
    })
    .await;
}

pub fn render_text(r: &Report) -> String {
    let mut s = String::new();
    for h in &r.hosts {
        let st = |x: &Option<Result<String, String>>| match x {
            Some(Ok(v)) => v.clone(),
            Some(Err(e)) => format!("ошибка: {e}"),
            None => "-".into(),
        };
        s += &format!("== {} — SMB: {}; NFS: {}\n", h.host, st(&h.smb), st(&h.nfs));
        for x in r.shares.iter().filter(|x| x.host == h.host) {
            s += &format!(
                "   {:<24} {:<20} {}{}{}\n",
                x.name,
                x.kind,
                match x.accessible {
                    Some(true) => format!("доступ: есть ({})", x.login),
                    Some(false) => "доступа нет".into(),
                    None => String::new(),
                },
                if x.clients.is_empty() { String::new() } else { format!("клиенты: {}", x.clients) },
                if x.comment.is_empty() { String::new() } else { format!("  # {}", x.comment) }
            );
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndr_roundtrip() {
        // Ответ: 2 шары.
        let mut stub = Vec::new();
        for v in [1u32, 1, 0x20000, 2, 0x20004, 2] {
            stub.extend_from_slice(&v.to_le_bytes());
        }
        for (p, t, r) in [(0x20008u32, 0u32, 0x2000cu32), (0x20010, 0x8000_0003, 0x20014)] {
            for v in [p, t, r] {
                stub.extend_from_slice(&v.to_le_bytes());
            }
        }
        for s in ["Public", "Общая папка", "IPC$", "Remote IPC"] {
            ndr_string(&mut stub, s);
        }
        stub.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut pdu = rpc_header(2, 0, 2);
        pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes());
        pdu.extend_from_slice(&[0, 0, 0, 0]);
        pdu.extend(stub);
        let list = parse_share_enum(&pdu).unwrap();
        assert_eq!(list[0], ("Public".into(), 0, "Общая папка".into()));
        assert_eq!(list[1].0, "IPC$");
        assert_eq!(share_type(list[1].1), "IPC (служебная)");
        let req = share_enum_request("fs01");
        assert_eq!(u16::from_le_bytes([req[8], req[9]]) as usize, req.len());
    }

    #[test]
    fn nfs_parse() {
        let mut b = Vec::new();
        let s = |b: &mut Vec<u8>, x: &str| {
            b.extend_from_slice(&(x.len() as u32).to_be_bytes());
            b.extend_from_slice(x.as_bytes());
            while !b.len().is_multiple_of(4) {
                b.push(0);
            }
        };
        b.extend_from_slice(&1u32.to_be_bytes());
        s(&mut b, "/srv/share");
        b.extend_from_slice(&1u32.to_be_bytes());
        s(&mut b, "10.0.0.0/24");
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        s(&mut b, "/pub");
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        let e = parse_exports(&b);
        assert_eq!(e, vec![("/srv/share".into(), vec!["10.0.0.0/24".into()]), ("/pub".into(), vec![])]);
    }

    /// Живая проверка с локальной Samba (если запущена на 127.0.0.1:445).
    #[tokio::test]
    #[ignore]
    async fn samba_local() {
        let cfg = Config {
            targets: "127.0.0.1".into(),
            nfs: false,
            ..Default::default()
        };
        let r = smb_enum("127.0.0.1", "127.0.0.1".parse().unwrap(), &cfg).await;
        println!("anon: {r:?}");
        let cfg = Config {
            login: Login::Account,
            user: "tester".into(),
            password: "Passw0rd!".into(),
            ..cfg
        };
        let r = smb_enum("127.0.0.1", "127.0.0.1".parse().unwrap(), &cfg).await;
        println!("user: {r:?}");
        assert!(r.is_ok());
    }
}
