//! Wake-on-LAN: «волшебный пакет» (6 × 0xFF и 16 повторов MAC) на UDP 9 —
//! широковещательно и на широковещательный адрес подсети узла.

use std::net::{Ipv4Addr, SocketAddr};

pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return Err(format!("некорректный MAC «{s}»"));
    }
    let mut m = [0u8; 6];
    for (i, b) in m.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(m)
}

pub fn magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0xFF; 6];
    for _ in 0..16 {
        p.extend_from_slice(&mac);
    }
    p
}

/// Отправить пакет. `ip` — последний известный адрес узла: тогда пакет уходит ещё и на
/// широковещательный адрес его /24 (направленная рассылка через маршрутизатор).
pub async fn wake(mac: &str, ip: Option<Ipv4Addr>) -> Result<String, String> {
    let m = parse_mac(mac)?;
    let pkt = magic_packet(m);
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    sock.set_broadcast(true).map_err(|e| e.to_string())?;
    let mut targets: Vec<SocketAddr> = vec![(Ipv4Addr::BROADCAST, 9).into(), (Ipv4Addr::BROADCAST, 7).into()];
    if let Some(ip) = ip {
        let o = ip.octets();
        targets.push((Ipv4Addr::new(o[0], o[1], o[2], 255), 9).into());
    }
    let mut sent = 0;
    for t in &targets {
        for _ in 0..3 {
            if sock.send_to(&pkt, t).await.is_ok() {
                sent += 1;
            }
        }
    }
    if sent == 0 {
        return Err("не удалось отправить пакет".into());
    }
    Ok(format!(
        "Wake-on-LAN отправлен на {} ({})",
        mac,
        targets.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet() {
        let m = parse_mac("AA-bb-cc:dd.ee ff").unwrap();
        let p = magic_packet(m);
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert_eq!(&p[96..], &m);
        assert!(parse_mac("aa:bb").is_err());
    }
}
