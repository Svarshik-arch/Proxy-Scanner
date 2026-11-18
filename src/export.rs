//! Экспорт результатов в CSV и JSON.

use std::path::Path;

use crate::model::ProxyRow;

fn csv_field(s: &str) -> String {
    if s.contains([';', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// CSV с разделителем «;» и BOM — открывается в Excel с русской локалью без настройки.
pub fn to_csv(rows: &[&ProxyRow]) -> String {
    let mut out = String::from("\u{feff}");
    out.push_str(
        "IP;Порт;Источник;Тип;Отклик, мс;HTTP;Сервер;Via;Аутентификация;CONNECT;\
         SSL-инспекция;Качество инспекции;Издатель сертификата;Субъект сертификата;SHA-256;\
         Политики (соответствует/всего);Нарушения политик;Примечания;Состояние\r\n",
    );
    for r in rows {
        let p = &r.probe;
        let cert = p.cert.clone().unwrap_or_default();
        let violations: Vec<String> = p
            .policy
            .iter()
            .filter(|x| !x.compliant)
            .map(|x| format!("{} — {} ({})", x.url, x.verdict.label(), x.detail))
            .collect();
        let mut notes = p.notes.clone();
        notes.extend(p.error.clone());
        let fields = [
            r.ip.to_string(),
            r.port.to_string(),
            r.source.clone(),
            r.kind.label().to_string(),
            p.rtt_ms.map(|v| v.to_string()).unwrap_or_default(),
            p.http_status.map(|v| v.to_string()).unwrap_or_default(),
            p.server.clone(),
            p.via.clone(),
            r.auth_label(),
            r.connect_label(),
            r.ssl.label().to_string(),
            r.inspect_label(),
            cert.issuer,
            cert.subject,
            cert.sha256,
            r.policy_label(),
            violations.join(" | "),
            notes.join(" | "),
            r.state.label().to_string(),
        ];
        let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
        out.push_str(&line.join(";"));
        out.push_str("\r\n");
    }
    out
}

pub fn to_json(rows: &[&ProxyRow]) -> Result<String, String> {
    serde_json::to_string_pretty(rows).map_err(|e| e.to_string())
}

pub fn save(path: &Path, rows: &[&ProxyRow]) -> Result<(), String> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let data = if is_json { to_json(rows)? } else { to_csv(rows) };
    std::fs::write(path, data).map_err(|e| format!("запись {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn csv_escaping() {
        let mut row = ProxyRow::new(Ipv4Addr::new(10, 0, 0, 1), 3128, "tcp-connect");
        row.probe.server = "squid; \"test\"".into();
        let csv = to_csv(&[&row]);
        assert!(csv.contains("10.0.0.1;3128;tcp-connect;"));
        assert!(csv.contains("\"squid; \"\"test\"\"\""));
        assert!(to_json(&[&row]).unwrap().contains("\"port\": 3128"));
    }
}
