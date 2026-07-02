//! The three shell tabs and the pure decision of whether a key switches tabs.
//!
//! The contract: ONLY `Tab` / `Shift-Tab` switch tabs. Every printable char
//! returns [`TabKey::None`] so it reaches the panel search box — this is the
//! fix for the single-character hotkey conflict.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// The three shell tabs. Default is [`Tab::Hosts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Hosts,
    Credentials,
    Settings,
}

/// Stable left-to-right tab order used by [`Tab::next`] / [`Tab::prev`].
pub const TAB_ORDER: &[Tab] = &[Tab::Hosts, Tab::Credentials, Tab::Settings];

impl Tab {
    /// Cycle to the next tab, wrapping past [`Tab::Settings`] back to
    /// [`Tab::Hosts`].
    pub fn next(self) -> Tab {
        TAB_ORDER[(self.idx() + 1) % TAB_ORDER.len()]
    }

    /// Cycle to the previous tab, wrapping past [`Tab::Hosts`] back to
    /// [`Tab::Settings`].
    pub fn prev(self) -> Tab {
        let len = TAB_ORDER.len();
        TAB_ORDER[(self.idx() + len - 1) % len]
    }

    /// Index of this tab within [`TAB_ORDER`].
    pub fn idx(self) -> usize {
        TAB_ORDER.iter().position(|t| *t == self).unwrap_or(0)
    }

    /// Human-readable label for the tab bar.
    pub fn label(self) -> &'static str {
        match self {
            Tab::Hosts => "Hosts",
            Tab::Credentials => "Credentials",
            Tab::Settings => "Settings",
        }
    }
}

/// Whether a panel-level key switches tabs. Produced by
/// [`tab_key_decision`]; consumed by the panel event loop to decide tab switch
/// vs. forward-to-search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabKey {
    /// Cycle by `delta` (`Tab` = +1, `BackTab` = -1).
    Cycle(i32),
    /// Not a tab key — let the panel handle it (printable chars land here).
    None,
}

/// Pure decision of whether a key event should switch tabs.
///
/// Only `Tab` and `Shift-Tab` (`BackTab`) switch tabs; every other key
/// (including bare digits and letters) returns [`TabKey::None`] so it flows
/// into the panel search box. Only `Press` events are honored; `Release` and
/// `Repeat` are `None`.
pub fn tab_key_decision(key: KeyEvent) -> TabKey {
    if key.kind != KeyEventKind::Press {
        return TabKey::None;
    }
    match key.code {
        KeyCode::Tab if key.modifiers == KeyModifiers::NONE => TabKey::Cycle(1),
        KeyCode::BackTab => TabKey::Cycle(-1),
        _ => TabKey::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_support::press;

    #[test]
    fn tab_cycles_forward_backtab_cycles_backward() {
        assert!(matches!(
            tab_key_decision(press(KeyCode::Tab, KeyModifiers::NONE)),
            TabKey::Cycle(1)
        ));
        assert!(matches!(
            tab_key_decision(press(KeyCode::BackTab, KeyModifiers::NONE)),
            TabKey::Cycle(-1)
        ));
    }

    #[test]
    fn bare_digits_and_chars_do_not_switch_tabs() {
        // The conflict fix: plain '1', '2', '3', 'c', '?' must reach the query.
        for code in [
            KeyCode::Char('1'),
            KeyCode::Char('2'),
            KeyCode::Char('3'),
            KeyCode::Char('c'),
            KeyCode::Char('?'),
            KeyCode::Char('a'),
        ] {
            assert!(
                matches!(
                    tab_key_decision(press(code, KeyModifiers::NONE)),
                    TabKey::None
                ),
                "bare {code:?} must not switch tabs"
            );
        }
    }

    #[test]
    fn next_prev_cycle_through_three_tabs() {
        assert_eq!(Tab::Hosts.next(), Tab::Credentials);
        assert_eq!(Tab::Credentials.next(), Tab::Settings);
        assert_eq!(Tab::Settings.next(), Tab::Hosts);
        assert_eq!(Tab::Hosts.prev(), Tab::Settings);
    }

    #[test]
    fn tab_order_and_labels_are_stable() {
        assert_eq!(TAB_ORDER, &[Tab::Hosts, Tab::Credentials, Tab::Settings]);
        assert_eq!(Tab::Hosts.label(), "Hosts");
        assert_eq!(Tab::Credentials.label(), "Credentials");
        assert_eq!(Tab::Settings.label(), "Settings");
    }
}
