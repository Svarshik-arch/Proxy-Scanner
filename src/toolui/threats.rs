use egui::RichText;

use super::{AMBER, Env, GREEN, RED};
use crate::tools::threats::{self, Level};

/// Угрозы в сегменте: прослушивание (через «Трафик») и выводы по нему.
pub fn settings_ui(cap: &mut super::capture::Panel, ui: &mut egui::Ui, env: &mut Env) {
    cap.listen_ui(ui, env);
    ui.add_space(6.0);
    ui.weak("Слушается только служебный трафик: DHCP, ARP, IPv6 RA, ICMP Redirect, LLMNR/NBT-NS/mDNS, STP, LLDP/CDP. Чем дольше слушать, тем вернее вывод — достаточно 5–15 минут.");
    ui.weak("Нужны права администратора и Npcap (Windows) или libpcap (Linux).");
}

pub fn results_ui(cap: &super::capture::Panel, ui: &mut egui::Ui) {
    let s = &cap.summary;
    if s.packets == 0 {
        ui.weak(if cap.busy() {
            "Слушаю… выводы появятся по мере прихода пакетов."
        } else {
            "Запустите прослушивание: программа найдёт посторонние DHCP-серверы, подмену ARP, посторонние маршрутизаторы IPv6 (mitm6), ICMP Redirect, отравители LLMNR/NBT-NS (Responder) и смену корня STP."
        });
        return;
    }
    let list = threats::assess(s);
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        if list.is_empty() {
            ui.colored_label(GREEN, format!("Угроз не найдено ({} пакетов служебного трафика).", s.packets));
        }
        for t in &list {
            let color = match t.level {
                Level::High => RED,
                Level::Medium => AMBER,
                Level::Low => ui.visuals().weak_text_color(),
            };
            egui::Frame::group(ui.style()).stroke(egui::Stroke::new(1.0, color)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(color, t.level.label());
                    ui.label(RichText::new(&t.title).strong());
                });
                ui.add(egui::Label::new(RichText::new(&t.detail).monospace()).wrap());
                ui.add(egui::Label::new(RichText::new(format!("→ {}", t.advice)).weak()).wrap());
            });
            ui.add_space(4.0);
        }
        if !s.neighbors.is_empty() {
            ui.add_space(6.0);
            ui.strong("Куда подключена машина (LLDP/CDP)");
            for n in &s.neighbors {
                ui.label(format!("{} {} порт {}{}", n.protocol, n.device, n.port, if n.vlan.is_empty() { String::new() } else { format!(" VLAN {}", n.vlan) }));
            }
        }
    });
}

