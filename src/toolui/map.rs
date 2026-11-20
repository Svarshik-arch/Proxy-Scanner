use super::{Env, Nav, Tool};
use crate::graph::{GraphSettings, GraphView, MapKind, MapNode};
use crate::tools::netmap::{self, Options};

#[derive(Default)]
pub struct Panel {
    graph: GraphView,
    settings: GraphSettings,
    opts: Options,
    pub nodes: Vec<MapNode>,
}

impl Panel {
    pub fn refresh(&mut self, s: &crate::session::Session) {
        self.nodes = netmap::build(s, self.opts);
    }

    pub fn settings_ui(&mut self, ui: &mut egui::Ui, _env: &mut Env) {
        ui.label("Карта строится из того, что уже собрано:");
        let count = |k: MapKind| self.nodes.iter().filter(|n| n.kind == k).count();
        for (what, how, n) in [
            ("эта машина и шлюзы", "раздел «Сеть → Хост»", count(MapKind::Router)),
            ("путь до узла", "«Сеть → MTR»", count(MapKind::Hop)),
            ("узлы и подсети", "«Сеть → Узлы»", count(MapKind::Host) + count(MapKind::Subnet)),
            ("серверы", "«Службы → Сервисы», «Аудит»", count(MapKind::Server)),
            ("контроллеры домена", "«Службы → Домен AD»", count(MapKind::Dc)),
            ("прокси", "«Прокси»", count(MapKind::Proxy)),
        ] {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("• {what}"));
                if n > 0 {
                    ui.colored_label(super::GREEN, format!("({n})"));
                } else {
                    ui.weak(format!("— {how}"));
                }
            });
        }
        ui.add_space(6.0);
        ui.checkbox(&mut self.opts.hosts, "Показывать найденные узлы");
        ui.checkbox(&mut self.opts.trace, "Показывать трассировку");
        ui.checkbox(&mut self.opts.services, "Показывать серверы");
        ui.add_space(6.0);
        ui.weak("Колесо — масштаб, перетаскивание — сдвиг, F — линза «рыбий глаз». Двойной щелчок по узлу — трассировка до него.");
    }

    pub fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let out = self.graph.ui_map(ui, &self.nodes, &mut self.settings);
        if let Some(label) = out.map_activate {
            if let Some(n) = self.nodes.iter().find(|n| n.label == label) {
                let target = n.key.strip_prefix("ip:").unwrap_or(&n.label).to_string();
                *env.nav = Some(match n.kind {
                    MapKind::Subnet => Nav::Send(Tool::Discovery, n.label.clone()),
                    MapKind::Me => return,
                    _ => Nav::Send(Tool::Mtr, target),
                });
            }
        }
    }
}
