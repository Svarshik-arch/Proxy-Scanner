//! Столбцы таблицы результатов и их автоматическая раскладка по ширине окна.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Col {
    Ip,
    Port,
    Kind,
    Auth,
    Connect,
    Ssl,
    Issuer,
    Policy,
    Server,
    Rtt,
    State,
    Source,
    Http,
}

pub struct ColDef {
    pub col: Col,
    pub title: &'static str,
    /// Начальная ширина.
    pub width: f32,
    /// Минимальная ширина при автоматической раскладке.
    pub min: f32,
    /// Чем меньше, тем дольше столбец остаётся видимым при сужении окна.
    pub priority: u8,
    /// Показывается ли по умолчанию.
    pub default_visible: bool,
}

/// Порядок показа столбцов.
pub const COLS: &[ColDef] = &[
    ColDef { col: Col::Ip, title: "IP-адрес", width: 112.0, min: 100.0, priority: 0, default_visible: true },
    ColDef { col: Col::Port, title: "Порт", width: 52.0, min: 46.0, priority: 1, default_visible: true },
    ColDef { col: Col::Kind, title: "Тип", width: 96.0, min: 80.0, priority: 2, default_visible: true },
    ColDef { col: Col::Auth, title: "Аутентификация", width: 125.0, min: 90.0, priority: 4, default_visible: true },
    ColDef { col: Col::Connect, title: "CONNECT", width: 78.0, min: 70.0, priority: 6, default_visible: true },
    ColDef { col: Col::Ssl, title: "SSL-инспекция", width: 108.0, min: 90.0, priority: 3, default_visible: true },
    ColDef { col: Col::Issuer, title: "Издатель сертификата", width: 210.0, min: 120.0, priority: 8, default_visible: true },
    ColDef { col: Col::Policy, title: "Политики", width: 72.0, min: 64.0, priority: 7, default_visible: true },
    ColDef { col: Col::Server, title: "Сервер / Via", width: 180.0, min: 110.0, priority: 9, default_visible: true },
    ColDef { col: Col::Rtt, title: "мс", width: 48.0, min: 40.0, priority: 10, default_visible: true },
    ColDef { col: Col::State, title: "Состояние", width: 84.0, min: 76.0, priority: 5, default_visible: true },
    ColDef { col: Col::Source, title: "Обнаружен", width: 92.0, min: 80.0, priority: 11, default_visible: false },
    ColDef { col: Col::Http, title: "HTTP", width: 52.0, min: 46.0, priority: 12, default_visible: false },
];

/// Промежуток между столбцами (с запасом на разделитель).
const SPACING: f32 = 10.0;

pub fn def(col: Col) -> &'static ColDef {
    COLS.iter().find(|d| d.col == col).expect("столбец описан в COLS")
}

pub fn default_visible() -> Vec<Col> {
    COLS.iter().filter(|d| d.default_visible).map(|d| d.col).collect()
}

/// Столбцы по умолчанию, которые помещаются в `available` пикселей:
/// добавляются по приоритету, пока хватает места, выводятся в порядке `COLS`.
pub fn auto_layout(available: f32) -> Vec<Col> {
    let mut by_priority: Vec<&ColDef> = COLS.iter().filter(|d| d.default_visible).collect();
    by_priority.sort_by_key(|d| d.priority);
    let mut used = 0.0;
    let mut chosen: Vec<Col> = Vec::new();
    for d in by_priority {
        let need = d.min + SPACING;
        // Первые два столбца (адрес и порт) показываются всегда.
        if chosen.len() >= 2 && used + need > available {
            continue;
        }
        used += need;
        chosen.push(d.col);
    }
    COLS.iter()
        .map(|d| d.col)
        .filter(|c| chosen.contains(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_shrinks_by_priority() {
        let wide = auto_layout(5000.0);
        assert_eq!(wide, default_visible());

        let narrow = auto_layout(300.0);
        assert_eq!(narrow, vec![Col::Ip, Col::Port, Col::Kind]);

        let mid = auto_layout(560.0);
        assert!(mid.contains(&Col::Ssl) && mid.contains(&Col::Auth));
        assert!(!mid.contains(&Col::Server) && !mid.contains(&Col::Rtt));

        // Адрес и порт видны даже в очень узком окне.
        assert_eq!(auto_layout(10.0), vec![Col::Ip, Col::Port]);
    }

    #[test]
    fn display_order_is_stable() {
        let mid = auto_layout(700.0);
        let positions: Vec<usize> = mid
            .iter()
            .map(|c| COLS.iter().position(|d| d.col == *c).unwrap())
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]));
    }
}
