//! Производитель сетевой карты по MAC-адресу. База IEEE OUI вшита в программу
//! (сжата deflate) и работает без интернета.

use std::sync::{Arc, RwLock};

static DATA: &[u8] = include_bytes!("../../assets/oui.deflate");

type Table = Vec<(u32, String)>;

static TABLE: RwLock<Option<Arc<Table>>> = RwLock::new(None);

/// Разбор базы: строки «XXXXXX<TAB>Производитель», сжатые deflate.
pub fn parse_table(deflated: &[u8]) -> Option<Table> {
    let raw = miniz_oxide::inflate::decompress_to_vec(deflated).ok()?;
    let text = String::from_utf8_lossy(&raw);
    let mut v: Table = text
        .lines()
        .filter_map(|l| {
            let (hex, name) = l.split_once('\t')?;
            Some((u32::from_str_radix(hex, 16).ok()?, name.to_string()))
        })
        .collect();
    v.sort_by_key(|e| e.0);
    v.dedup_by_key(|e| e.0);
    (v.len() > 10_000).then_some(v)
}

/// Обновлённая база (папка данных рядом с программой), иначе встроенная.
fn table() -> Arc<Table> {
    if let Some(t) = TABLE.read().ok().and_then(|g| g.clone()) {
        return t;
    }
    let updated = std::fs::read(crate::updates::data_dir().join("oui.deflate")).ok().and_then(|d| parse_table(&d));
    let t = Arc::new(updated.unwrap_or_else(|| parse_table(DATA).unwrap_or_default()));
    if let Ok(mut g) = TABLE.write() {
        *g = Some(t.clone());
    }
    t
}

/// Перечитать базу (после обновления).
pub fn reload() {
    if let Ok(mut g) = TABLE.write() {
        *g = None;
    }
    let _ = table();
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn format_mac(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Производитель; для локально назначенных (случайных) адресов — пометка.
pub fn vendor(mac: &[u8; 6]) -> Option<String> {
    if mac[0] & 0x02 != 0 {
        return Some("случайный/локальный MAC".into());
    }
    let key = u32::from_be_bytes([0, mac[0], mac[1], mac[2]]);
    let t = table();
    t.binary_search_by_key(&key, |e| e.0).ok().map(|i| t[i].1.clone())
}

pub fn entries() -> usize {
    table().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup() {
        assert!(entries() > 30_000);
        assert_eq!(vendor(&parse_mac("00:00:0c:12:34:56").unwrap()).as_deref(), Some("Cisco Systems"));
        assert_eq!(vendor(&parse_mac("F0-D1-A9-00-00-01").unwrap()).as_deref(), Some("Apple"));
        assert_eq!(vendor(&parse_mac("02:00:00:00:00:01").unwrap()).as_deref(), Some("случайный/локальный MAC"));
        assert_eq!(parse_mac("zz"), None);
        assert_eq!(format_mac(&[0, 1, 2, 0xa, 0xb, 0xc]), "00:01:02:0A:0B:0C");
    }
}
