//! Store mode switch view: lets the user change the password storage mode
//! (keyring / vault / plaintext) interactively, rendered as the Settings tab's
//! store-picker overlay.
//!
//! A thin view over the *same* core switch paths `cli::cmd::store` uses. The
//! view holds only its cursor and a transient status string; [`StoreView::on_key`]
//! is pure (no I/O) and signals intent via new [`Outcome`] variants:
//! - [`Outcome::SwitchToKeyring`] / [`Outcome::SwitchToVault`] / [`Outcome::SwitchToPlaintext`]
//!   — the loop runs the I/O-heavy migration (`vault::enable` for vault,
//!   `vault::transform::migrate` for keyring/plaintext) and persists the config.
//! - [`Outcome::Cancel`] — Esc, return to the launcher.
//!
//! Plaintext is a security downgrade: the loop drives a confirm popup
//! ([`TuiPassphrase::confirm`], which renders via [`confirm_popup`]) before
//! migrating. Vault needs a fresh master passphrase: the loop drives
//! [`TuiPassphrase::passphrase_confirm`] (masked, double-entry). Keyring needs a
//! reachable Secret Service: the loop probes [`OsKeyring::available`] and aborts
//! with a status when the daemon is down.
//!
//! Rendering goes into a dialog body supplied by [`super::dialog::draw_dialog`]
//! (the Settings tab opens this as `Overlay::StorePicker`).
//!
//! [`confirm_popup`]: super::prompt::confirm_popup

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListState},
};

use super::intent::Outcome;
use super::theme;

/// The three storage modes the user can pick. Mirrors the CLI `StoreMode` but
/// lives in the view layer (no dependency on the CLI args module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreModeChoice {
    Keyring,
    Vault,
    Plaintext,
}

impl StoreModeChoice {
    /// Top-to-bottom render + navigation order.
    const ORDER: &'static [StoreModeChoice] = &[
        StoreModeChoice::Keyring,
        StoreModeChoice::Vault,
        StoreModeChoice::Plaintext,
    ];

    /// The user-facing label shown in the picker.
    fn label(self) -> &'static str {
        match self {
            StoreModeChoice::Keyring => "keyring",
            StoreModeChoice::Vault => "vault",
            StoreModeChoice::Plaintext => "plaintext",
        }
    }

    /// A one-line description of the trade-offs for this mode.
    fn blurb(self) -> &'static str {
        match self {
            StoreModeChoice::Keyring => {
                "OS keyring (recommended). Plaintext never touches disk; needs a \
                 Secret Service daemon."
            }
            StoreModeChoice::Vault => {
                "Master-passphrase encryption (Argon2id + XChaCha20-Poly1305). \
                 Portable; passphrase unlocks every session."
            }
            StoreModeChoice::Plaintext => {
                "Stored in the clear in config.toml. Security downgrade: anyone \
                 who reads the file gets every password."
            }
        }
    }
}

/// The store mode view's state: which row is highlighted, a transient status
/// line (set by the loop after a switch attempt), and the snapshot of the
/// current mode captured when the view opened (so render can mark it "(active)"
/// even if the loop has not yet reloaded the config).
#[derive(Debug, Clone)]
pub struct StoreView {
    /// The cursor into [`StoreModeChoice::ORDER`].
    pub selected: usize,
    /// A transient status message (success or failure from the last switch).
    /// `None` shows the default hint line.
    pub status: Option<String>,
    /// The mode label that was active when the view opened, for the "(active)"
    /// marker. Stored as a string (not the enum) so a future `None`/undecided
    /// mode renders cleanly as "undecided".
    pub active_label: String,
}

impl StoreView {
    /// Build a fresh store view over the current config. `active` is the mode
    /// active when the view opened; it is shown as "(active)" in the picker.
    pub fn new(active: Option<&str>) -> Self {
        let active_label = active.unwrap_or("undecided").to_string();
        Self {
            selected: 0,
            status: None,
            active_label,
        }
    }

    /// Move the cursor by `delta` (signed), wrapping. Pure.
    fn move_selection(&mut self, delta: i32) {
        let len = StoreModeChoice::ORDER.len() as i32;
        let cur = self.selected as i32;
        self.selected = (cur + delta).rem_euclid(len) as usize;
    }

    /// Content row count the dialog should size to: 3 modes x (name line +
    /// blurb line) + 1 status line. Consumed by the App overlay layer to size
    /// the dialog via [`crate::tui::dialog::draw_dialog`].
    pub fn body_rows(&self) -> u16 {
        StoreModeChoice::ORDER.len() as u16 * 2 + 1
    }

    /// The mode under the cursor, if the list is non-empty (it always is).
    pub fn selected_mode(&self) -> Option<StoreModeChoice> {
        StoreModeChoice::ORDER.get(self.selected).copied()
    }

    /// Pure key decision: inspect `key`, mutate the cursor/status, return an
    /// [`Outcome`]. Performs **no I/O**.
    ///
    /// Bindings:
    /// - `Up` / `Down` — move the cursor (wraps).
    /// - `Enter` — signal the switch intent for the highlighted mode.
    /// - `Esc` / `Ctrl-C` — [`Outcome::Cancel`] (back to the launcher).
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        // Ctrl-C cancels like Esc (Plan B). Exact Control+c so Ctrl-Shift-C
        // (terminal paste) does not accidentally cancel.
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
            return Outcome::Cancel;
        }
        match key.code {
            KeyCode::Esc => Outcome::Cancel,
            KeyCode::Up => {
                self.move_selection(-1);
                Outcome::Continue
            }
            KeyCode::Down => {
                self.move_selection(1);
                Outcome::Continue
            }
            KeyCode::Enter => match self.selected_mode() {
                Some(StoreModeChoice::Keyring) => Outcome::SwitchToKeyring,
                Some(StoreModeChoice::Vault) => Outcome::SwitchToVault,
                Some(StoreModeChoice::Plaintext) => Outcome::SwitchToPlaintext,
                None => Outcome::Continue,
            },
            _ => Outcome::Continue,
        }
    }

    /// Render the store view's three-mode list into a dialog `body` rect
    /// supplied by [`super::dialog::draw_dialog`]. The dialog supplies the outer
    /// border + title + footer hints, so this draws **no** outer `Block`; it
    /// only lays out the mode list (with the active one marked) and a status
    /// line. Selection styling mirrors the Hosts/Credentials panels: the
    /// selected row leads with `theme::focus_marker(true)` (Cyan `▶ `) and is
    /// rendered BOLD. Only writes to the frame; no stdout access.
    pub fn draw_in_dialog(&self, frame: &mut Frame, body: Rect) {
        // Status line pinned to the bottom of the dialog body; the list fills
        // the rest. (The dialog's own footer holds the key-binding hints.)
        let [list_area, status_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(body);

        // Bake the focus marker into each item via `theme::focus_marker`: the
        // selected row carries `▶ ` (accented + bold), every other row carries
        // a two-space pad. Both are 2 cells wide, so labels align regardless of
        // which row is selected (no selected-row left-shift). `highlight_style`
        // adds BOLD to the whole selected row — no dark-background selection bar.
        let items: Vec<Line> = StoreModeChoice::ORDER
            .iter()
            .enumerate()
            .map(|(i, &m)| mode_line(m, &self.active_label, i == self.selected))
            .collect();

        let list = List::new(items).highlight_style(Style::new().add_modifier(Modifier::BOLD));
        let mut state = ListState::default();
        state.select(Some(self.selected));
        frame.render_stateful_widget(list, list_area, &mut state);

        // The transient status (success/failure from the last switch attempt).
        // When None the dialog's footer hints already explain the keys, so this
        // line stays empty rather than duplicating the hint.
        let line = match &self.status {
            Some(msg) => Line::from(vec![
                Span::styled("status: ", Style::new().dim()),
                Span::raw(msg),
            ]),
            None => Line::from(""),
        };
        frame.render_widget(ratatui::widgets::Paragraph::new(line), status_area);
    }
}

/// Build the display line for one mode: the focus marker (`▶ ` when selected,
/// two spaces otherwise — both 2 cells wide so labels align), the mode name
/// (with `(active)` when it matches the snapshot), then the trade-off blurb
/// dimmed.
fn mode_line(mode: StoreModeChoice, active_label: &str, selected: bool) -> Line<'static> {
    let active = mode.label() == active_label;
    let name_span = if active {
        Span::styled(
            format!("{} (active)", mode.label()),
            theme::accent().add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw(mode.label())
    };
    // `theme::focus_marker` yields the accented `▶ ` for the selected row and
    // a two-space pad for the others, so every label starts at the same column.
    let marker = theme::focus_marker(selected);
    Line::from(vec![
        marker,
        name_span,
        Span::raw("\n"),
        Span::styled(mode.blurb(), Style::new().dim()),
    ])
}

#[cfg(test)]
mod tests {
    //! Purity tests for `StoreView::on_key`. The contract: `on_key` takes a key
    //! and returns an outcome with **no I/O**.

    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    #[test]
    fn down_then_up_moves_selection_and_wraps() {
        let mut v = StoreView::new(Some("vault"));
        assert_eq!(v.selected, 0);
        v.on_key(key(KeyCode::Down));
        assert_eq!(v.selected, 1, "Down moves to vault");
        v.on_key(key(KeyCode::Down));
        assert_eq!(v.selected, 2, "Down moves to plaintext");
        v.on_key(key(KeyCode::Down));
        assert_eq!(v.selected, 0, "Down wraps to keyring");
        v.on_key(key(KeyCode::Up));
        assert_eq!(v.selected, 2, "Up wraps to plaintext");
    }

    #[test]
    fn enter_on_keyring_signals_switch_to_keyring() {
        let mut v = StoreView::new(Some("vault"));
        // cursor at index 0 = keyring
        let outcome = v.on_key(key(KeyCode::Enter));
        assert!(matches!(outcome, Outcome::SwitchToKeyring));
    }

    #[test]
    fn enter_on_vault_signals_switch_to_vault() {
        let mut v = StoreView::new(Some("plaintext"));
        v.on_key(key(KeyCode::Down)); // -> vault
        let outcome = v.on_key(key(KeyCode::Enter));
        assert!(matches!(outcome, Outcome::SwitchToVault));
    }

    #[test]
    fn enter_on_plaintext_signals_switch_to_plaintext() {
        let mut v = StoreView::new(Some("keyring"));
        v.on_key(key(KeyCode::Down));
        v.on_key(key(KeyCode::Down)); // -> plaintext
        let outcome = v.on_key(key(KeyCode::Enter));
        assert!(matches!(outcome, Outcome::SwitchToPlaintext));
    }

    #[test]
    fn esc_signals_cancel() {
        let mut v = StoreView::new(Some("vault"));
        let outcome = v.on_key(key(KeyCode::Esc));
        assert!(matches!(outcome, Outcome::Cancel));
    }

    #[test]
    fn ctrl_c_signals_cancel_like_esc() {
        // The `on_key` doc lists Ctrl-C alongside Esc as a Cancel binding; pin
        // it so the contract holds. Regression: Ctrl-C previously fell through
        // to the `_ => Continue` arm because only `KeyCode::Esc` was matched.
        let mut v = StoreView::new(Some("vault"));
        let ctrl_c = KeyEvent::new_with_kind(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        let outcome = v.on_key(ctrl_c);
        assert!(matches!(outcome, Outcome::Cancel));
    }

    #[test]
    fn release_events_are_ignored() {
        let mut v = StoreView::new(Some("vault"));
        let release =
            KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        let outcome = v.on_key(release);
        assert!(matches!(outcome, Outcome::Continue));
    }

    #[test]
    fn neutral_keys_continue_without_moving_cursor() {
        let mut v = StoreView::new(Some("vault"));
        let outcome = v.on_key(key(KeyCode::Char('x')));
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(v.selected, 0, "neutral key must not move the cursor");
    }

    #[test]
    fn active_label_marked_when_new_matches_current_mode() {
        let v = StoreView::new(Some("vault"));
        assert_eq!(v.active_label, "vault");
    }

    #[test]
    fn new_with_none_active_shows_undecided() {
        let v = StoreView::new(None);
        assert_eq!(v.active_label, "undecided");
    }

    // ---- draw_in_dialog: smoke (no panic) + snapshot ----

    /// Render the store picker into a full dialog (chrome + body) the way the
    /// app does, so the snapshot captures the three-mode list + active marker.
    fn render_picker(
        view: &StoreView,
        w: u16,
        h: u16,
    ) -> ratatui::Terminal<ratatui::backend::TestBackend> {
        let backend = ratatui::backend::TestBackend::new(w, h);
        let mut term = ratatui::Terminal::new(backend).expect("test backend");
        term.draw(|f| {
            let body = crate::tui::dialog::draw_dialog(
                f,
                " storage mode ",
                view.body_rows(),
                &[("↑↓", "select"), ("Enter", "switch"), ("Esc/^C", "cancel")],
            );
            view.draw_in_dialog(f, body);
        })
        .expect("draw");
        term
    }

    #[test]
    fn draw_in_dialog_renders_without_panic_80x24_and_narrow() {
        let v = StoreView::new(Some("vault"));
        // 80x24.
        let _ = render_picker(&v, 80, 24);
        // Narrow 40x8 (dialog clamps down; must not panic or overflow).
        let _ = render_picker(&v, 40, 8);
    }

    #[test]
    fn draw_in_dialog_cursor_on_plaintext_renders_without_panic() {
        let mut v = StoreView::new(Some("keyring"));
        v.move_selection(1); // -> vault
        v.move_selection(1); // -> plaintext
        let _ = render_picker(&v, 40, 8);
    }

    #[test]
    fn draw_in_dialog_undecided_active_renders_without_panic() {
        let v = StoreView::new(None);
        let _ = render_picker(&v, 40, 8);
    }

    #[test]
    fn draw_in_dialog_vault_active_cursor_keyring_snapshot_80x24() {
        // Snapshot: vault is the active mode (marked `(active)`), cursor on
        // keyring (the default, focus marker `▶`). Hermetic: TestBackend in
        // memory, fixed labels, no timestamps.
        let v = StoreView::new(Some("vault"));
        let term = render_picker(&v, 80, 24);
        insta::assert_snapshot!(term.backend());
    }
}
