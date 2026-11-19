//! Общие функции TLS: системные корневые сертификаты, проверка цепочки «с записью»
//! (результат проверки сохраняется, а соединение не обрывается) и разбор сертификатов.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

/// Корневые сертификаты системы (хранилище Windows, /etc/ssl в Linux).
/// В закрытом контуре это корпоративные CA — именно они и нужны.
pub fn roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for c in loaded.certs {
                let _ = store.add(c);
            }
            Arc::new(store)
        })
        .clone()
}

/// Проверяет цепочку по системным корням, запоминает ошибку, но не прерывает рукопожатие.
#[derive(Debug)]
pub struct RecordingVerifier {
    inner: Option<Arc<WebPkiServerVerifier>>,
    pub error: Arc<Mutex<Option<String>>>,
}

impl RecordingVerifier {
    pub fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = roots();
        let inner = if roots.is_empty() {
            None
        } else {
            WebPkiServerVerifier::builder_with_provider(roots, provider).build().ok()
        };
        Self {
            inner,
            error: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for RecordingVerifier {
    fn default() -> Self {
        Self::new()
    }
}

fn schemes() -> Vec<SignatureScheme> {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = match &self.inner {
            Some(v) => v
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
                .map(|_| ())
                .map_err(|e| describe_error(&e)),
            None => Err("в системе не найдено корневых сертификатов".to_string()),
        };
        if let Err(e) = result {
            *self.error.lock().unwrap() = Some(e);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

fn describe_error(e: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::Expired | C::ExpiredContext { .. } => "сертификат просрочен".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "сертификат ещё не действует".into(),
            C::UnknownIssuer => "издатель не доверен (нет в системных корневых)".into(),
            C::NotValidForName | C::NotValidForNameContext { .. } => "сертификат выдан на другое имя".into(),
            C::Revoked => "сертификат отозван".into(),
            C::BadSignature => "неверная подпись".into(),
            other => format!("{other:?}"),
        },
        other => other.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Versions {
    #[default]
    Auto,
    Tls12,
    Tls13,
}

impl Versions {
    pub const ALL: [Versions; 3] = [Versions::Auto, Versions::Tls12, Versions::Tls13];
    pub fn label(self) -> &'static str {
        match self {
            Versions::Auto => "TLS 1.2–1.3",
            Versions::Tls12 => "только TLS 1.2",
            Versions::Tls13 => "только TLS 1.3",
        }
    }
}

/// Клиентская конфигурация с записывающим верификатором.
/// Ошибка проверки цепочки, записанная верификатором.
pub type TrustSlot = Arc<Mutex<Option<String>>>;

pub fn client_config(versions: Versions, alpn: &[&str]) -> Result<(ClientConfig, TrustSlot), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let vers: &[&'static rustls::SupportedProtocolVersion] = match versions {
        Versions::Auto => rustls::DEFAULT_VERSIONS,
        Versions::Tls12 => &[&rustls::version::TLS12],
        Versions::Tls13 => &[&rustls::version::TLS13],
    };
    let verifier = RecordingVerifier::new();
    let err = verifier.error.clone();
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(vers)
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok((cfg, err))
}

/// Подробности сертификата.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertDetail {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    /// Дней до окончания (отрицательно — просрочен).
    pub days_left: i64,
    /// «RSA 2048», «EC P-256», «Ed25519».
    pub key: String,
    pub key_bits: u32,
    pub signature: String,
    pub names: Vec<String>,
    pub sha256: String,
    pub self_signed: bool,
    pub is_ca: bool,
    pub serial: String,
}

impl CertDetail {
    /// Короткое имя: CN или первый SAN.
    pub fn short_subject(&self) -> String {
        short_dn(&self.subject)
    }
    pub fn short_issuer(&self) -> String {
        short_dn(&self.issuer)
    }
    pub fn weak_signature(&self) -> bool {
        let s = self.signature.to_ascii_lowercase();
        s.contains("sha1") || s.contains("md5") || s.contains("md2")
    }
    pub fn weak_key(&self) -> bool {
        (self.key.starts_with("RSA") || self.key.starts_with("DSA")) && self.key_bits > 0 && self.key_bits < 2048
            || (self.key.starts_with("EC") && self.key_bits > 0 && self.key_bits < 224)
    }
}

pub fn short_dn(dn: &str) -> String {
    dn.split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("CN="))
        .map(String::from)
        .unwrap_or_else(|| dn.to_string())
}

fn sig_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSA",
        "1.2.840.113549.1.1.5" => "sha1WithRSA",
        "1.2.840.113549.1.1.11" => "sha256WithRSA",
        "1.2.840.113549.1.1.12" => "sha384WithRSA",
        "1.2.840.113549.1.1.13" => "sha512WithRSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "1.2.643.7.1.1.3.2" => "ГОСТ Р 34.10-2012 (256)",
        "1.2.643.7.1.1.3.3" => "ГОСТ Р 34.10-2012 (512)",
        "1.2.643.2.2.3" => "ГОСТ Р 34.10-2001",
        other => return other.to_string(),
    }
    .to_string()
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn cert_detail(der: &[u8]) -> CertDetail {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut d = CertDetail {
        sha256: digest.as_ref().iter().map(|b| format!("{b:02X}")).collect(),
        ..Default::default()
    };
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        d.subject = "(сертификат не разобран)".into();
        return d;
    };
    d.subject = cert.subject().to_string();
    d.issuer = cert.issuer().to_string();
    d.not_before = cert.validity().not_before.to_string();
    d.not_after = cert.validity().not_after.to_string();
    d.days_left = (cert.validity().not_after.timestamp() - now_unix()).div_euclid(86400);
    d.self_signed = cert.subject() == cert.issuer();
    d.serial = cert.raw_serial_as_string();
    d.signature = sig_name(&cert.signature_algorithm.algorithm.to_id_string());
    d.is_ca = cert.is_ca();
    let spki = cert.public_key();
    match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            d.key_bits = rsa.key_size() as u32;
            d.key = format!("RSA {}", d.key_bits);
        }
        Ok(x509_parser::public_key::PublicKey::EC(ec)) => {
            d.key_bits = ec.key_size() as u32;
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| match o.to_id_string().as_str() {
                    "1.2.840.10045.3.1.7" => "P-256".to_string(),
                    "1.3.132.0.34" => "P-384".to_string(),
                    "1.3.132.0.35" => "P-521".to_string(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            d.key = format!("EC {curve}").trim().to_string();
        }
        Ok(x509_parser::public_key::PublicKey::DSA(_)) => {
            d.key = "DSA".into();
        }
        Ok(_) => {
            let oid = spki.algorithm.algorithm.to_id_string();
            d.key = match oid.as_str() {
                "1.3.101.112" => "Ed25519".into(),
                "1.3.101.113" => "Ed448".into(),
                o if o.starts_with("1.2.643") => "ГОСТ".into(),
                o => o.into(),
            };
        }
        Err(_) => d.key = spki.algorithm.algorithm.to_id_string(),
    }
    for cn in cert.subject().iter_common_name() {
        if let Ok(v) = cn.as_str() {
            d.names.push(v.to_string());
        }
    }
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            let name = match gn {
                GeneralName::DNSName(n) => n.to_string(),
                GeneralName::IPAddress(ip) if ip.len() == 4 => std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
                _ => continue,
            };
            if !d.names.iter().any(|x| x.eq_ignore_ascii_case(&name)) {
                d.names.push(name);
            }
        }
    }
    d
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
    pub chain: Vec<CertDetail>,
    /// Ошибка проверки цепочки по системным корням (None — доверенный сертификат).
    pub trust_error: Option<String>,
    pub handshake_ms: f64,
}

pub type TlsStream<S> = tokio_rustls::client::TlsStream<S>;

/// TLS-рукопожатие с записью сведений о соединении и сертификатах.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    sni: &str,
    versions: Versions,
    alpn: &[&str],
    timeout: Duration,
) -> Result<(TlsStream<S>, TlsInfo), String> {
    let name = match sni.parse::<std::net::IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(sni.to_string()).map_err(|_| format!("некорректное имя для TLS: «{sni}»"))?,
    };
    let (cfg, err) = client_config(versions, alpn)?;
    let started = std::time::Instant::now();
    let tls = match tokio::time::timeout(timeout, TlsConnector::from(Arc::new(cfg)).connect(name, stream)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Err(format!("TLS: {e}")),
        Err(_) => return Err("TLS: нет ответа".into()),
    };
    let conn = tls.get_ref().1;
    let info = TlsInfo {
        version: conn
            .protocol_version()
            .map(|v| match v {
                rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
                rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
                other => format!("{other:?}"),
            })
            .unwrap_or_default(),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()))
            .unwrap_or_default(),
        alpn: conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned()),
        chain: conn
            .peer_certificates()
            .unwrap_or(&[])
            .iter()
            .map(|c| cert_detail(c.as_ref()))
            .collect(),
        trust_error: err.lock().unwrap().clone(),
        handshake_ms: super::ms_f(started.elapsed()),
    };
    Ok((tls, info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_of_generated_cert() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["example.test".into(), "www.example.test".into()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "example.test");
        let cert = params.self_signed(&key).unwrap();
        let d = cert_detail(cert.der());
        assert_eq!(d.short_subject(), "example.test");
        assert!(d.self_signed);
        assert_eq!(d.key, "EC P-256");
        assert_eq!(d.signature, "ecdsa-with-SHA256");
        assert!(d.names.contains(&"www.example.test".to_string()));
        assert!(d.days_left > 300);
        assert!(!d.weak_key() && !d.weak_signature());
    }

    #[test]
    fn short_dn_works() {
        assert_eq!(short_dn("C=RU, O=Corp, CN=Corp Root CA"), "Corp Root CA");
        assert_eq!(short_dn("O=NoCN"), "O=NoCN");
    }
}
