//! Аутентификация на прокси: Basic, NTLM (NTLMv2, чистый Rust) и, в Windows,
//! Negotiate/NTLM через SSPI — под текущим пользователем (как браузер) или с
//! явно заданной учётной записью.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AuthMode {
    /// Выбирать по тому, что предлагает прокси: Negotiate → NTLM → Basic.
    #[default]
    Auto,
    /// Не аутентифицироваться.
    None,
    Basic,
    Ntlm,
    /// Negotiate (Kerberos, при невозможности — NTLM). Только Windows.
    Negotiate,
}

impl AuthMode {
    pub const ALL: &'static [AuthMode] =
        &[AuthMode::Auto, AuthMode::None, AuthMode::Basic, AuthMode::Ntlm, AuthMode::Negotiate];

    pub fn label(self) -> &'static str {
        match self {
            AuthMode::Auto => "авто (по предложению прокси)",
            AuthMode::None => "без аутентификации",
            AuthMode::Basic => "Basic",
            AuthMode::Ntlm => "NTLM",
            AuthMode::Negotiate => "Negotiate (Kerberos)",
        }
    }
}

/// Учётные данные и режим.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub mode: AuthMode,
    /// Windows: входить под текущим пользователем (SSPI, без пароля).
    pub current_user: bool,
    pub user: String,
    pub password: String,
    pub domain: String,
}

impl Credentials {
    pub fn has_explicit(&self) -> bool {
        !self.user.trim().is_empty()
    }

    /// Пользователь и домен: `DOMAIN\user`, `user@domain` или отдельное поле домена.
    pub fn split_user(&self) -> (String, String) {
        let u = self.user.trim();
        if let Some((d, n)) = u.split_once('\\') {
            return (n.to_string(), d.to_string());
        }
        if let Some((n, d)) = u.split_once('@')
            && self.domain.trim().is_empty()
        {
            return (n.to_string(), d.to_string());
        }
        (u.to_string(), self.domain.trim().to_string())
    }

    /// Выбор схемы по списку из `Proxy-Authenticate`.
    pub fn choose(&self, offered: &[String]) -> Option<Scheme> {
        let has = |s: &str| offered.iter().any(|o| o.eq_ignore_ascii_case(s));
        let sspi = cfg!(windows) && (self.current_user || self.has_explicit());
        match self.mode {
            AuthMode::None => None,
            AuthMode::Basic => (has("Basic") && self.has_explicit()).then_some(Scheme::Basic),
            AuthMode::Ntlm => {
                if !has("NTLM") {
                    None
                } else if sspi {
                    Some(Scheme::SspiNtlm)
                } else if self.has_explicit() {
                    Some(Scheme::Ntlm)
                } else {
                    None
                }
            }
            AuthMode::Negotiate => (has("Negotiate") && sspi).then_some(Scheme::SspiNegotiate),
            AuthMode::Auto => {
                if has("Negotiate") && sspi {
                    Some(Scheme::SspiNegotiate)
                } else if has("NTLM") && sspi {
                    Some(Scheme::SspiNtlm)
                } else if has("NTLM") && self.has_explicit() {
                    Some(Scheme::Ntlm)
                } else if has("Basic") && self.has_explicit() {
                    Some(Scheme::Basic)
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Basic,
    /// NTLMv2, реализованный в программе (нужны логин и пароль).
    Ntlm,
    /// Windows SSPI.
    SspiNtlm,
    SspiNegotiate,
}

impl Scheme {
    /// Имя схемы в заголовке.
    pub fn header_name(self) -> &'static str {
        match self {
            Scheme::Basic => "Basic",
            Scheme::Ntlm | Scheme::SspiNtlm => "NTLM",
            Scheme::SspiNegotiate => "Negotiate",
        }
    }

    pub fn describe(self, creds: &Credentials) -> String {
        let who = if matches!(self, Scheme::SspiNtlm | Scheme::SspiNegotiate) && !creds.has_explicit() {
            "текущий пользователь Windows".to_string()
        } else {
            let (u, d) = creds.split_user();
            if d.is_empty() { u } else { format!("{d}\\{u}") }
        };
        format!("{} ({who})", self.header_name())
    }
}

/// Пошаговый обмен токенами.
pub trait AuthSession: Send {
    /// `challenge` — токен из ответа прокси (`None` на первом шаге).
    /// Возвращает значение заголовка `Proxy-Authorization`.
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<String, String>;
}

pub fn new_session(scheme: Scheme, creds: &Credentials, proxy_host: &str) -> Result<Box<dyn AuthSession>, String> {
    match scheme {
        Scheme::Basic => {
            let (u, d) = creds.split_user();
            let user = if d.is_empty() { u } else { format!("{d}\\{u}") };
            Ok(Box::new(BasicSession(Some(format!("{user}:{}", creds.password)))))
        }
        Scheme::Ntlm => {
            let (u, d) = creds.split_user();
            Ok(Box::new(NtlmSession { user: u, domain: d, password: creds.password.clone(), done: false }))
        }
        Scheme::SspiNtlm | Scheme::SspiNegotiate => sspi::new(scheme, creds, proxy_host),
    }
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()
}

struct BasicSession(Option<String>);

impl AuthSession for BasicSession {
    fn step(&mut self, _challenge: Option<&[u8]>) -> Result<String, String> {
        let creds = self.0.take().ok_or("Basic: учётные данные отклонены")?;
        Ok(format!("Basic {}", b64(creds.as_bytes())))
    }
}

// ---------------------------------------------------------------------------
// NTLMv2 (MS-NLMP)
// ---------------------------------------------------------------------------

const NTLMSSP: &[u8; 8] = b"NTLMSSP\0";
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const REQUEST_TARGET: u32 = 0x0000_0004;
const NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
const NEGOTIATE_128: u32 = 0x2000_0000;
const NEGOTIATE_56: u32 = 0x8000_0000;

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

pub(crate) fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<md5::Md5> as KeyInit>::new_from_slice(key).expect("HMAC принимает ключ любой длины");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// NTOWFv2 = HMAC-MD5(MD4(UTF-16LE(пароль)), UTF-16LE(ВЕРХНИЙ(пользователь) + домен)).
pub fn ntowf_v2(user: &str, password: &str, domain: &str) -> [u8; 16] {
    use md4::{Digest, Md4};
    let nt_hash = Md4::digest(utf16le(password));
    hmac_md5(&nt_hash, &[&utf16le(&(user.to_uppercase() + domain))])
}

pub fn negotiate_message() -> Vec<u8> {
    let flags = NEGOTIATE_UNICODE
        | REQUEST_TARGET
        | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN
        | NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NEGOTIATE_128
        | NEGOTIATE_56;
    let mut m = Vec::with_capacity(32);
    m.extend_from_slice(NTLMSSP);
    m.extend_from_slice(&1u32.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    // Пустые поля домена и рабочей станции (длина, макс. длина, смещение).
    for _ in 0..2 {
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&32u32.to_le_bytes());
    }
    m
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub flags: u32,
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
}

pub fn parse_challenge(m: &[u8]) -> Result<Challenge, String> {
    let bad = || "некорректное сообщение NTLM CHALLENGE".to_string();
    if m.len() < 32 || &m[..8] != NTLMSSP || m[8..12] != 2u32.to_le_bytes() {
        return Err(bad());
    }
    let u16_at = |i: usize| u16::from_le_bytes([m[i], m[i + 1]]) as usize;
    let u32_at = |i: usize| u32::from_le_bytes([m[i], m[i + 1], m[i + 2], m[i + 3]]);
    let flags = u32_at(20);
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&m[24..32]);
    let target_info = if m.len() >= 48 {
        let (len, off) = (u16_at(40), u32_at(44) as usize);
        m.get(off..off + len).ok_or_else(bad)?.to_vec()
    } else {
        Vec::new()
    };
    Ok(Challenge { flags, server_challenge, target_info })
}

/// Временная метка из AV_PAIR MsvAvTimestamp (7), если сервер её прислал.
fn av_timestamp(target_info: &[u8]) -> Option<[u8; 8]> {
    let mut i = 0;
    while i + 4 <= target_info.len() {
        let id = u16::from_le_bytes([target_info[i], target_info[i + 1]]);
        let len = u16::from_le_bytes([target_info[i + 2], target_info[i + 3]]) as usize;
        if id == 0 {
            break;
        }
        if id == 7 && len == 8 && i + 12 <= target_info.len() {
            let mut t = [0u8; 8];
            t.copy_from_slice(&target_info[i + 4..i + 12]);
            return Some(t);
        }
        i += 4 + len;
    }
    None
}

fn filetime_now() -> [u8; 8] {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() / 100)
        .unwrap_or(0) as u64;
    (unix + 116_444_736_000_000_000).to_le_bytes()
}

/// Ответы NTLMv2: (LmChallengeResponse, NtChallengeResponse).
pub fn ntlmv2_responses(
    ntowf: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: &[u8; 8],
    target_info: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut temp = vec![0x01, 0x01, 0, 0, 0, 0, 0, 0];
    temp.extend_from_slice(timestamp);
    temp.extend_from_slice(client_challenge);
    temp.extend_from_slice(&[0, 0, 0, 0]);
    temp.extend_from_slice(target_info);
    temp.extend_from_slice(&[0, 0, 0, 0]);
    let nt_proof = hmac_md5(ntowf, &[server_challenge, &temp]);
    let mut nt = nt_proof.to_vec();
    nt.extend_from_slice(&temp);
    let mut lm = hmac_md5(ntowf, &[server_challenge, client_challenge]).to_vec();
    lm.extend_from_slice(client_challenge);
    (lm, nt)
}

pub fn authenticate_message(
    ch: &Challenge,
    user: &str,
    domain: &str,
    password: &str,
    client_challenge: [u8; 8],
    workstation: &str,
) -> Vec<u8> {
    let ntowf = ntowf_v2(user, password, domain);
    let server_ts = av_timestamp(&ch.target_info);
    let ts = server_ts.unwrap_or_else(filetime_now);
    let (mut lm, nt) = ntlmv2_responses(&ntowf, &ch.server_challenge, &client_challenge, &ts, &ch.target_info);
    if server_ts.is_some() {
        // MS-NLMP: при наличии MsvAvTimestamp LmChallengeResponse заполняется нулями.
        lm = vec![0u8; 24];
    }
    let flags = (ch.flags & !NEGOTIATE_TARGET_INFO)
        & (NEGOTIATE_UNICODE
            | NEGOTIATE_NTLM
            | NEGOTIATE_ALWAYS_SIGN
            | NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NEGOTIATE_128
            | NEGOTIATE_56)
        | NEGOTIATE_UNICODE
        | NEGOTIATE_NTLM;
    let fields = [utf16le(domain), utf16le(user), utf16le(workstation), lm, nt];
    // Порядок полей в заголовке: LM, NT, домен, пользователь, рабочая станция, ключ сеанса.
    let header_order = [3usize, 4, 0, 1, 2];
    let mut offsets = [0u32; 5];
    let mut off = 64u32;
    for (i, f) in fields.iter().enumerate() {
        offsets[i] = off;
        off += f.len() as u32;
    }
    let mut m = Vec::with_capacity(off as usize);
    m.extend_from_slice(NTLMSSP);
    m.extend_from_slice(&3u32.to_le_bytes());
    for &i in &header_order {
        let len = fields[i].len() as u16;
        m.extend_from_slice(&len.to_le_bytes());
        m.extend_from_slice(&len.to_le_bytes());
        m.extend_from_slice(&offsets[i].to_le_bytes());
    }
    // EncryptedRandomSessionKey — пусто.
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&off.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    for f in &fields {
        m.extend_from_slice(f);
    }
    m
}

struct NtlmSession {
    user: String,
    domain: String,
    password: String,
    done: bool,
}

impl AuthSession for NtlmSession {
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<String, String> {
        match challenge {
            None => Ok(format!("NTLM {}", b64(&negotiate_message()))),
            Some(_) if self.done => Err("NTLM: учётные данные отклонены".into()),
            Some(c) => {
                let ch = parse_challenge(c)?;
                let mut cc = [0u8; 8];
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut cc)
                    .map_err(|_| "не удалось получить случайные данные")?;
                let ws = crate::session::computer_name();
                let domain = if self.domain.is_empty() { String::new() } else { self.domain.clone() };
                self.done = true;
                Ok(format!(
                    "NTLM {}",
                    b64(&authenticate_message(&ch, &self.user, &domain, &self.password, cc, &ws))
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows SSPI
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod sspi {
    use super::*;
    pub fn new(_: Scheme, _: &Credentials, _: &str) -> Result<Box<dyn AuthSession>, String> {
        Err("Negotiate/SSPI доступны только в Windows; в Linux укажите логин и пароль для NTLM".into())
    }
}

#[cfg(windows)]
mod sspi {
    use super::*;
    use windows_sys::Win32::Foundation::{SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED};
    use windows_sys::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext, FreeCredentialsHandle,
        ISC_REQ_CONNECTION, InitializeSecurityContextW, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND,
        SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
    };
    use windows_sys::Win32::Security::Credentials::SecHandle;
    use windows_sys::Win32::System::Rpc::{SEC_WINNT_AUTH_IDENTITY_UNICODE, SEC_WINNT_AUTH_IDENTITY_W};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    pub struct Sspi {
        package: &'static str,
        cred: SecHandle,
        ctx: Option<SecHandle>,
        target: Vec<u16>,
    }

    // SAFETY: дескрипторы SSPI — непрозрачные числа; сеанс используется из одной задачи.
    unsafe impl Send for Sspi {}

    impl Drop for Sspi {
        fn drop(&mut self) {
            // SAFETY: дескрипторы получены от SSPI и освобождаются один раз.
            unsafe {
                if let Some(ctx) = &self.ctx {
                    DeleteSecurityContext(ctx);
                }
                FreeCredentialsHandle(&self.cred);
            }
        }
    }

    pub fn new(scheme: Scheme, creds: &Credentials, proxy_host: &str) -> Result<Box<dyn AuthSession>, String> {
        let package = if scheme == Scheme::SspiNegotiate { "Negotiate" } else { "NTLM" };
        let pkg = wide(package);
        let mut cred = SecHandle::default();
        let mut expiry = 0i64;
        let (u, d) = creds.split_user();
        let (mut uw, mut dw, mut pw) = (
            u.encode_utf16().collect::<Vec<u16>>(),
            d.encode_utf16().collect::<Vec<u16>>(),
            creds.password.encode_utf16().collect::<Vec<u16>>(),
        );
        let identity = SEC_WINNT_AUTH_IDENTITY_W {
            User: uw.as_mut_ptr(),
            UserLength: uw.len() as u32,
            Domain: dw.as_mut_ptr(),
            DomainLength: dw.len() as u32,
            Password: pw.as_mut_ptr(),
            PasswordLength: pw.len() as u32,
            Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        };
        let auth_data: *const core::ffi::c_void = if creds.has_explicit() {
            &identity as *const _ as *const core::ffi::c_void
        } else {
            std::ptr::null() // текущий пользователь
        };
        // SAFETY: все указатели действительны на время вызова.
        let rc = unsafe {
            AcquireCredentialsHandleW(
                std::ptr::null(),
                pkg.as_ptr(),
                SECPKG_CRED_OUTBOUND,
                std::ptr::null(),
                auth_data,
                None,
                std::ptr::null(),
                &mut cred,
                &mut expiry,
            )
        };
        if rc != SEC_E_OK {
            return Err(format!("SSPI {package}: AcquireCredentialsHandle вернул 0x{:08X}", rc as u32));
        }
        // SPN прокси для Kerberos.
        let target = wide(&format!("HTTP/{proxy_host}"));
        Ok(Box::new(Sspi { package, cred, ctx: None, target }))
    }

    impl AuthSession for Sspi {
        fn step(&mut self, challenge: Option<&[u8]>) -> Result<String, String> {
            let mut out_buf = vec![0u8; 64 * 1024];
            let mut out = SecBuffer {
                cbBuffer: out_buf.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: out_buf.as_mut_ptr() as *mut _,
            };
            let mut out_desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 1, pBuffers: &mut out };
            let mut input_data = challenge.map(|c| c.to_vec()).unwrap_or_default();
            let mut inp = SecBuffer {
                cbBuffer: input_data.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: input_data.as_mut_ptr() as *mut _,
            };
            let inp_desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 1, pBuffers: &mut inp };
            let mut new_ctx = self.ctx.unwrap_or_default();
            let mut attrs = 0u32;
            let mut expiry = 0i64;
            // SAFETY: буферы живут до конца вызова; контекст передаётся только после первого шага.
            let rc = unsafe {
                InitializeSecurityContextW(
                    &self.cred,
                    self.ctx.as_ref().map_or(std::ptr::null(), |c| c as *const _),
                    self.target.as_ptr(),
                    ISC_REQ_CONNECTION,
                    0,
                    SECURITY_NATIVE_DREP,
                    if challenge.is_some() { &inp_desc } else { std::ptr::null() },
                    0,
                    &mut new_ctx,
                    &mut out_desc,
                    &mut attrs,
                    &mut expiry,
                )
            };
            if rc == SEC_I_COMPLETE_NEEDED || rc == SEC_I_COMPLETE_AND_CONTINUE {
                // SAFETY: контекст и буфер действительны.
                unsafe { CompleteAuthToken(&new_ctx, &out_desc) };
            }
            if rc != SEC_E_OK && rc != SEC_I_CONTINUE_NEEDED && rc != SEC_I_COMPLETE_NEEDED && rc != SEC_I_COMPLETE_AND_CONTINUE {
                return Err(format!("SSPI {}: InitializeSecurityContext вернул 0x{:08X}", self.package, rc as u32));
            }
            self.ctx = Some(new_ctx);
            let token = &out_buf[..out.cbBuffer as usize];
            if token.is_empty() {
                return Err(format!("SSPI {}: пустой токен", self.package));
            }
            let name = if self.package == "Negotiate" { "Negotiate" } else { "NTLM" };
            Ok(format!("{name} {}", b64(token)))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn sspi_produces_first_token() {
            let creds = Credentials { mode: AuthMode::Ntlm, current_user: true, ..Default::default() };
            let mut s = new(Scheme::SspiNtlm, &creds, "proxy.test").unwrap();
            let h = s.step(None).unwrap();
            let token = b64_decode(h.strip_prefix("NTLM ").unwrap()).unwrap();
            assert_eq!(&token[..8], b"NTLMSSP\0");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    /// Тестовые векторы MS-NLMP, раздел 4.2.4 (NTLMv2).
    #[test]
    fn ms_nlmp_ntlmv2_vectors() {
        let ntowf = ntowf_v2("User", "Password", "Domain");
        assert_eq!(ntowf.to_vec(), hex("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f"));

        let server: [u8; 8] = hex("01 23 45 67 89 ab cd ef").try_into().unwrap();
        let client = [0xaa; 8];
        let ts = [0u8; 8];
        let mut target_info = vec![0x02, 0x00, 0x0c, 0x00];
        target_info.extend(utf16le("Domain"));
        target_info.extend([0x01, 0x00, 0x0c, 0x00]);
        target_info.extend(utf16le("Server"));
        target_info.extend([0, 0, 0, 0]);
        let (lm, nt) = ntlmv2_responses(&ntowf, &server, &client, &ts, &target_info);
        assert_eq!(
            lm,
            hex("86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa")
        );
        assert_eq!(nt[..16].to_vec(), hex("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c"));
    }

    #[test]
    fn messages_roundtrip() {
        let neg = negotiate_message();
        assert_eq!(neg.len(), 32);
        assert_eq!(&neg[..8], NTLMSSP);

        // CHALLENGE с target info и меткой времени.
        let mut ti = vec![0x07, 0x00, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8];
        ti.extend([0, 0, 0, 0]);
        let mut ch = Vec::new();
        ch.extend_from_slice(NTLMSSP);
        ch.extend(2u32.to_le_bytes());
        ch.extend([0, 0, 0, 0]);
        ch.extend(48u32.to_le_bytes());
        ch.extend((NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_TARGET_INFO).to_le_bytes());
        ch.extend([9u8; 8]);
        ch.extend([0u8; 8]);
        ch.extend((ti.len() as u16).to_le_bytes());
        ch.extend((ti.len() as u16).to_le_bytes());
        ch.extend(48u32.to_le_bytes());
        ch.extend(&ti);
        let c = parse_challenge(&ch).unwrap();
        assert_eq!(c.server_challenge, [9u8; 8]);
        assert_eq!(c.target_info, ti);
        assert_eq!(av_timestamp(&c.target_info), Some([1, 2, 3, 4, 5, 6, 7, 8]));

        let m = authenticate_message(&c, "user", "CORP", "pw", [0xaa; 8], "WS");
        assert_eq!(&m[..8], NTLMSSP);
        assert_eq!(m[8..12], 3u32.to_le_bytes());
        // LM — нули (есть метка времени), NT начинается с NTProofStr (16 байт) + 0x0101.
        let field = |i: usize| {
            let len = u16::from_le_bytes([m[i], m[i + 1]]) as usize;
            let off = u32::from_le_bytes([m[i + 4], m[i + 5], m[i + 6], m[i + 7]]) as usize;
            m[off..off + len].to_vec()
        };
        assert_eq!(field(12), vec![0u8; 24]);
        assert_eq!(field(20)[16..18], [1, 1]);
        assert_eq!(field(28), utf16le("CORP"));
        assert_eq!(field(36), utf16le("user"));
        assert_eq!(field(44), utf16le("WS"));
        assert!(parse_challenge(b"garbage").is_err());
    }

    #[test]
    fn scheme_choice_and_user_forms() {
        let offered = vec!["Negotiate".to_string(), "NTLM".to_string(), "Basic".to_string()];
        let explicit = Credentials { mode: AuthMode::Auto, user: "CORP\\ivan".into(), password: "x".into(), ..Default::default() };
        assert_eq!(explicit.split_user(), ("ivan".into(), "CORP".into()));
        let at = Credentials { user: "ivan@corp.local".into(), ..Default::default() };
        assert_eq!(at.split_user(), ("ivan".into(), "corp.local".into()));
        let expected = if cfg!(windows) { Scheme::SspiNegotiate } else { Scheme::Ntlm };
        assert_eq!(explicit.choose(&offered), Some(expected));
        let none = Credentials { mode: AuthMode::Auto, current_user: false, ..Default::default() };
        assert_eq!(none.choose(&offered), None);
        let basic = Credentials { mode: AuthMode::Basic, user: "u".into(), ..Default::default() };
        assert_eq!(basic.choose(&offered), Some(Scheme::Basic));
        assert_eq!(basic.choose(&["NTLM".to_string()]), None);
    }
}
