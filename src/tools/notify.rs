//! Уведомления мониторинга о смене состояния: syslog (UDP), почта (SMTP, внутренний
//! релей без пароля, при наличии — STARTTLS) и файл журнала. Подходит для закрытого контура.

use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

use super::monitor::{Change, Status};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Alerts {
    /// Syslog-сервер `узел[:514]`.
    pub syslog: String,
    /// SMTP-релей `узел[:25]`.
    pub smtp: String,
    pub mail_from: String,
    /// Получатели через запятую.
    pub mail_to: String,
    /// Файл журнала (дописывается).
    pub log_file: String,
    /// Сообщать и о «внимании», не только о сбое и восстановлении.
    pub on_warn: bool,
}

impl Alerts {
    pub fn is_empty(&self) -> bool {
        self.syslog.trim().is_empty() && self.smtp.trim().is_empty() && self.log_file.trim().is_empty()
    }

    /// Нужно ли сообщать об этом изменении.
    pub fn wants(&self, ch: &Change) -> bool {
        if ch.from == Status::Unknown && ch.to == Status::Ok {
            return false;
        }
        match ch.to {
            Status::Fail => true,
            Status::Ok => ch.from == Status::Fail || (self.on_warn && ch.from == Status::Warn),
            Status::Warn => self.on_warn,
            Status::Unknown => false,
        }
    }
}

pub fn message(ch: &Change) -> String {
    format!("{}: {} → {} ({})", ch.line, ch.from.label(), ch.to.label(), ch.detail)
}

fn syslog_line(ch: &Change, host: &str) -> Vec<u8> {
    // local0 (16) × 8 + важность: err 3, warning 4, notice 5.
    let sev = match ch.to {
        Status::Fail => 3,
        Status::Warn => 4,
        _ => 5,
    };
    let ts = crate::session::format_time(ch.at).replace(" UTC", "Z").replace(' ', "T");
    let mut v = format!("<{}>1 {ts}:00 {host} proxy-scanner - monitor - ", 16 * 8 + sev).into_bytes();
    v.extend_from_slice("\u{feff}".as_bytes());
    v.extend_from_slice(message(ch).as_bytes());
    v
}

async fn send_syslog(target: &str, ch: &Change) -> Result<(), String> {
    let (host, port) = crate::probe::split_host_port(target, 514)?;
    let s = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    s.send_to(&syslog_line(ch, &crate::session::computer_name()), (host.as_str(), port))
        .await
        .map_err(|e| format!("syslog: {e}"))?;
    Ok(())
}

async fn reply<S: AsyncRead + Unpin>(r: &mut BufReader<S>) -> Result<(u16, String), String> {
    let mut all = String::new();
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(15), r.read_line(&mut line))
            .await
            .map_err(|_| "SMTP: нет ответа".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("SMTP: соединение закрыто".into());
        }
        all.push_str(&line);
        if line.len() < 4 || line.as_bytes()[3] != b'-' {
            let code = line.get(..3).and_then(|c| c.parse().ok()).ok_or("SMTP: непонятный ответ")?;
            return Ok((code, all));
        }
    }
}

async fn cmd<S: AsyncRead + AsyncWrite + Unpin>(r: &mut BufReader<S>, line: &str, expect: u16) -> Result<String, String> {
    r.get_mut().write_all(format!("{line}\r\n").as_bytes()).await.map_err(|e| e.to_string())?;
    let (code, text) = reply(r).await?;
    if code / 100 != expect / 100 {
        return Err(format!("SMTP: на «{}» ответ {}", line.split(':').next().unwrap_or(line), text.trim()));
    }
    Ok(text)
}

fn mail_body(from: &str, to: &[String], ch: &Change) -> String {
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    let subject = format!("[{}] {}", ch.to.label(), ch.line);
    let text = format!(
        "{}\r\n\r\nПроверка: {}\r\nБыло: {}\r\nСтало: {}\r\nПодробности: {}\r\nВремя: {}\r\nКомпьютер: {}\r\n",
        message(ch),
        ch.line,
        ch.from.label(),
        ch.to.label(),
        ch.detail,
        crate::session::format_time(ch.at),
        crate::session::computer_name()
    );
    let body = b64(&text);
    let wrapped: Vec<&str> = body.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    format!(
        "From: {from}\r\nTo: {}\r\nSubject: =?UTF-8?B?{}?=\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\nX-Mailer: proxy-scanner\r\n\r\n{}\r\n.",
        to.join(", "),
        b64(&subject),
        wrapped.join("\r\n")
    )
}

async fn smtp_dialog<S: AsyncRead + AsyncWrite + Unpin>(r: &mut BufReader<S>, a: &Alerts, to: &[String], body: &str, greet: bool) -> Result<(), String> {
    if greet {
        let (code, text) = reply(r).await?;
        if code != 220 {
            return Err(format!("SMTP: {}", text.trim()));
        }
    }
    cmd(r, &format!("EHLO {}", crate::session::computer_name().replace(' ', "-")), 250).await?;
    cmd(r, &format!("MAIL FROM:<{}>", a.mail_from.trim()), 250).await?;
    for t in to {
        cmd(r, &format!("RCPT TO:<{t}>"), 250).await?;
    }
    cmd(r, "DATA", 354).await?;
    cmd(r, body, 250).await?;
    let _ = cmd(r, "QUIT", 221).await;
    Ok(())
}

async fn send_mail(a: &Alerts, ch: &Change) -> Result<(), String> {
    let to: Vec<String> = super::split_list(&a.mail_to);
    let body = mail_body(a.mail_from.trim(), &to, ch);
    smtp_send(a, &to, &body).await
}

/// Письмо с HTML-отчётом (тема и HTML в UTF-8).
pub async fn send_html_mail(a: &Alerts, subject: &str, html: &str) -> Result<(), String> {
    let to: Vec<String> = super::split_list(&a.mail_to);
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    let body = b64(html);
    let wrapped: Vec<&str> = body.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    let msg = format!(
        "From: {}\r\nTo: {}\r\nSubject: =?UTF-8?B?{}?=\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\nX-Mailer: proxy-scanner\r\n\r\n{}\r\n.",
        a.mail_from.trim(),
        to.join(", "),
        b64(subject),
        wrapped.join("\r\n")
    );
    smtp_send(a, &to, &msg).await
}

async fn smtp_send(a: &Alerts, to: &[String], body: &str) -> Result<(), String> {
    let (host, port) = crate::probe::split_host_port(&a.smtp, 25)?;
    if to.is_empty() || a.mail_from.trim().is_empty() {
        return Err("почта: укажите отправителя и получателей".into());
    }
    let s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| "SMTP: нет подключения".to_string())?
        .map_err(|e| format!("SMTP: {e}"))?;
    let mut r = BufReader::new(s);
    let (code, text) = reply(&mut r).await?;
    if code != 220 {
        return Err(format!("SMTP: {}", text.trim()));
    }
    let ehlo = cmd(&mut r, &format!("EHLO {}", crate::session::computer_name().replace(' ', "-")), 250).await?;
    if ehlo.to_ascii_uppercase().contains("STARTTLS") {
        cmd(&mut r, "STARTTLS", 220).await?;
        let (tls, _) = super::tls::handshake(r.into_inner(), &host, super::tls::Versions::Auto, &[], Duration::from_secs(10)).await?;
        let mut r = BufReader::new(tls);
        return smtp_dialog(&mut r, a, to, body, false).await;
    }
    // Без STARTTLS: продолжаем в том же соединении (EHLO уже отправлен — повтор допустим).
    smtp_dialog(&mut r, a, to, body, false).await
}

fn append_log(path: &str, ch: &Change) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("{path}: {e}"))?;
    writeln!(f, "{} {}", crate::session::format_time(ch.at), message(ch)).map_err(|e| e.to_string())
}

/// Отправка уведомления по всем настроенным каналам; возвращает ошибки каналов.
pub async fn send(a: &Alerts, ch: &Change) -> Vec<String> {
    let mut errors = Vec::new();
    if !a.wants(ch) {
        return errors;
    }
    if !a.log_file.trim().is_empty()
        && let Err(e) = append_log(a.log_file.trim(), ch)
    {
        errors.push(e);
    }
    if !a.syslog.trim().is_empty()
        && let Err(e) = send_syslog(a.syslog.trim(), ch).await
    {
        errors.push(e);
    }
    if !a.smtp.trim().is_empty()
        && let Err(e) = send_mail(a, ch).await
    {
        errors.push(e);
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(from: Status, to: Status) -> Change {
        Change {
            at: 1_700_000_000,
            line: "ping 10.0.0.1".into(),
            from,
            to,
            detail: "нет ответа".into(),
        }
    }

    #[test]
    fn filtering() {
        let a = Alerts::default();
        assert!(a.wants(&ch(Status::Ok, Status::Fail)));
        assert!(a.wants(&ch(Status::Fail, Status::Ok)));
        assert!(!a.wants(&ch(Status::Unknown, Status::Ok)));
        assert!(!a.wants(&ch(Status::Ok, Status::Warn)));
        let w = Alerts { on_warn: true, ..Default::default() };
        assert!(w.wants(&ch(Status::Ok, Status::Warn)));
    }

    #[test]
    fn syslog_format() {
        let l = String::from_utf8(syslog_line(&ch(Status::Ok, Status::Fail), "pc1")).unwrap();
        assert!(l.starts_with("<131>1 2023-11-14T22:13"), "{l}");
        assert!(l.contains("pc1 proxy-scanner - monitor - "));
        assert!(l.ends_with("ping 10.0.0.1: норма → сбой (нет ответа)"));
    }

    #[tokio::test]
    async fn smtp_and_file() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut r = BufReader::new(s);
            r.get_mut().write_all(b"220 relay ESMTP\r\n").await.unwrap();
            let mut data = String::new();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                if in_data {
                    data.push_str(&line);
                    if line == ".\r\n" {
                        in_data = false;
                        r.get_mut().write_all(b"250 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let up = line.to_ascii_uppercase();
                let resp: &[u8] = if up.starts_with("EHLO") {
                    b"250-relay\r\n250 SIZE 1000000\r\n"
                } else if up.starts_with("DATA") {
                    in_data = true;
                    b"354 go\r\n"
                } else if up.starts_with("QUIT") {
                    r.get_mut().write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                r.get_mut().write_all(resp).await.unwrap();
            }
            data
        });
        let dir = std::env::temp_dir().join(format!("ps-notify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("alerts.log");
        let a = Alerts {
            smtp: addr.to_string(),
            mail_from: "monitor@corp.local".into(),
            mail_to: "noc@corp.local, admin@corp.local".into(),
            log_file: log.display().to_string(),
            ..Default::default()
        };
        let errors = send(&a, &ch(Status::Ok, Status::Fail)).await;
        assert!(errors.is_empty(), "{errors:?}");
        let data = server.await.unwrap();
        assert!(data.contains("Subject: =?UTF-8?B?"));
        assert!(data.contains("To: noc@corp.local, admin@corp.local"));
        assert!(std::fs::read_to_string(&log).unwrap().contains("норма → сбой"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
