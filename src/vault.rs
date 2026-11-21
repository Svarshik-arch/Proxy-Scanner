//! Хранилище паролей устройств: ChaCha20-Poly1305, ключ — случайный файл рядом с
//! программой (в Linux — права 600). В файлах устройств и проектов пароли лежат только
//! в зашифрованном виде; расшифровать их можно лишь на машине с этим ключом.
//! Это защита от случайного чтения файлов, а не от администратора машины.

use std::path::PathBuf;

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

const PREFIX: &str = "enc1:";

pub fn key_path() -> PathBuf {
    crate::updates::data_dir().with_file_name("proxy-scanner-vault.key")
}

fn random(buf: &mut [u8]) {
    let rng = ring::rand::SystemRandom::new();
    let _ = ring::rand::SecureRandom::fill(&rng, buf);
}

fn key() -> Result<[u8; 32], String> {
    let path = key_path();
    if let Ok(b) = std::fs::read(&path)
        && b.len() == 32
    {
        let mut k = [0u8; 32];
        k.copy_from_slice(&b);
        return Ok(k);
    }
    let mut k = [0u8; 32];
    random(&mut k);
    std::fs::write(&path, k).map_err(|e| format!("ключ хранилища {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(k)
}

/// Зашифровать секрет (пустой — пустая строка).
pub fn seal(secret: &str) -> Result<String, String> {
    if secret.is_empty() {
        return Ok(String::new());
    }
    let k = key()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
    let mut nonce = [0u8; 12];
    random(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), secret.as_bytes()).map_err(|_| "шифрование не удалось".to_string())?;
    let mut all = nonce.to_vec();
    all.extend(ct);
    Ok(format!("{PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(all)))
}

/// Расшифровать секрет; строка без префикса считается открытой (ввод вручную в JSON).
pub fn open(sealed: &str) -> Result<String, String> {
    let Some(b64) = sealed.strip_prefix(PREFIX) else { return Ok(sealed.to_string()) };
    let all = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| e.to_string())?;
    if all.len() < 13 {
        return Err("повреждённый секрет".into());
    }
    let k = key()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
    let pt = cipher
        .decrypt(Nonce::from_slice(&all[..12]), &all[12..])
        .map_err(|_| "не удалось расшифровать пароль: ключ хранилища другой (файл перенесён с другой машины?)".to_string())?;
    String::from_utf8(pt).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let s = super::seal("Pa$$w0rd").unwrap();
        assert!(s.starts_with("enc1:"));
        assert_ne!(s, super::seal("Pa$$w0rd").unwrap(), "каждый раз новый nonce");
        assert_eq!(super::open(&s).unwrap(), "Pa$$w0rd");
        assert_eq!(super::open("plain").unwrap(), "plain");
        assert_eq!(super::seal("").unwrap(), "");
    }
}
