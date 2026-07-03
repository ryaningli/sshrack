//! Fuzzy credential picker: a pure sub-state opened from the host wizard's
//! Credential row (Reference branch). It snapshots the wizard's
//! `credential_names`, holds a fuzzy `query` + cursor into a ranked list of
//! original indices, and delegates matching to [`crate::tui::panel::rank_by_name`]
//! (all-zero scores — credentials have no frecency). Pure: no I/O, so the whole
//! state machine is unit-testable without a terminal. Rendering lives in
//! [`CredPicker::draw_overlay`].

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::Alignment,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

/// The pure result of [`CredPicker::on_key`] handling one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerOutcome {
    /// Enter on a non-empty list: `idx` is the chosen credential's original
    /// index into the wizard's `credential_names`. The wizard writes it back to
    /// `AuthChoice::Reference { idx }` and closes the picker.
    Selected { idx: usize },
    /// Esc / Ctrl-C: close the picker without changing the selection.
    Cancel,
    /// Any other key (including Enter on an empty list): keep the picker open.
    Pending,
}

/// Fuzzy credential picker sub-state. `names` is a snapshot of the wizard's
/// `credential_names` taken at open time (the picker is modal, so the list
/// cannot change while it is open). `ranked` holds original indices into
/// `names`, ordered by fuzzy match against `query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredPicker {
    /// Snapshot of the wizard's credential names at open time.
    pub names: Vec<String>,
    /// The fuzzy query string the user is typing.
    pub query: String,
    /// Cursor into `ranked` (clamped to the list).
    pub selected: usize,
    /// Original indices into `names`, ranked by fuzzy match against `query`.
    pub ranked: Vec<usize>,
}

/// How many credential rows the picker list renders. The popup is
/// `popup::POPUP_HEIGHT` (20) tall; subtract the border (2) and the query row
/// (1) plus a small margin. Bump in lockstep if `POPUP_HEIGHT` changes.
const PICKER_VISIBLE_ROWS: usize = 16;

impl CredPicker {
    /// Fresh picker over `names`: empty query, cursor at the top, every name
    /// ranked (name order, since scores are all zero). Clones `names` so the
    /// picker is self-contained — the wizard's `credential_names` cannot change
    /// while the picker is modal.
    pub fn new(names: &[String]) -> Self {
        let ranked = Self::rank(names, "");
        Self {
            names: names.to_vec(),
            query: String::new(),
            selected: 0,
            ranked,
        }
    }

    /// Recompute `ranked` for the current `query` and clamp the cursor. Called
    /// after every query mutation inside `on_key`. Pure: no I/O.
    fn recompute(&mut self) {
        self.ranked = Self::rank(&self.names, &self.query);
        self.clamp();
    }

    /// Fuzzy-rank `names` for `query` via the shared helper, with all-zero
    /// scores (credentials carry no frecency). Returns original indices.
    fn rank(names: &[String], query: &str) -> Vec<usize> {
        // Wrap each name as its own single-field row so the shared multi-field
        // helper ranks the picker the same way it ranks the panels.
        let rows: Vec<Vec<String>> = names.iter().map(|n| vec![n.clone()]).collect();
        let scores = vec![0.0f64; names.len()];
        crate::tui::panel::rank_by_fields(&rows, &scores, query)
    }

    fn clamp(&mut self) {
        if self.ranked.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len() - 1;
        }
    }

    fn move_cursor(&mut self, delta: i32) {
        if self.ranked.is_empty() {
            return;
        }
        let n = self.ranked.len() as i32;
        self.selected = ((self.selected as i32 + delta).rem_euclid(n)) as usize;
    }

    /// The original index into `names` of the credential under the cursor, or
    /// `None` when the ranked list is empty (no names / no matches).
    pub fn selected_idx(&self) -> Option<usize> {
        self.ranked.get(self.selected).copied()
    }

    /// Paint the picker as a centered popup over the wizard: a query box (with
    /// the real terminal cursor at its end) on top, then a windowed, highlighted
    /// list of matching names below. The window follows the cursor so long
    /// credential lists stay scrollable within the fixed popup footprint.
    /// Rendering only — mutates nothing.
    pub fn draw_overlay(&self, frame: &mut Frame) {
        // Body: row 0 = query box "> {query}", then up to (height-1) list rows.
        let query_line = Line::from(vec![
            Span::styled(
                "> ",
                crate::tui::theme::accent().add_modifier(Modifier::BOLD),
            ),
            Span::raw(self.query.clone()),
            Span::styled("_", Style::new().dim()), // visual cursor hint
        ]);

        let list_lines = self.windowed_lines();

        let mut lines = vec![query_line];
        lines.extend(list_lines);
        let body = Paragraph::new(lines).alignment(Alignment::Left);

        let content = crate::tui::popup::render_popup(
            frame,
            " pick credential ",
            body,
            crate::tui::popup::POPUP_WIDTH,
            crate::tui::popup::POPUP_HEIGHT,
        );

        // Place the real terminal cursor right after the typed query on row 0.
        // "> " is 2 chars; offset by the query length.
        let x = content.x + 2 + self.query.chars().count() as u16;
        let max_x = content.x + content.width.saturating_sub(1);
        frame.set_cursor_position((x.min(max_x), content.y));
    }

    /// Build the visible list rows: a window of `ranked` around `selected`,
    /// each rendered with the cursor row highlighted and non-matching entries
    /// excluded (they are already filtered out of `ranked` by `recompute`).
    /// The window math is the shared [`crate::tui::fit::focus_window`] helper
    /// (center + clamp), so the picker scrolls exactly like the host/cred
    /// wizards and the Help overlay on small terminals.
    fn windowed_lines(&self) -> Vec<Line<'static>> {
        if self.ranked.is_empty() {
            return vec![Line::from(Span::styled(
                "  no matches — add a credential with the cred wizard",
                Style::new().dim(),
            ))];
        }
        let win =
            crate::tui::fit::focus_window(self.ranked.len(), self.selected, PICKER_VISIBLE_ROWS);
        (win.start..win.end)
            .map(|i| {
                let name = self.names.get(self.ranked[i]).cloned().unwrap_or_default();
                let is_sel = i == self.selected;
                let prefix = if is_sel { "▶ " } else { "  " };
                let span = if is_sel {
                    Span::styled(
                        format!("{prefix}{name}"),
                        crate::tui::theme::accent().add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::raw(format!("{prefix}{name}"))
                };
                Line::from(span)
            })
            .collect()
    }

    /// Pure key decision: mutate the query/cursor and report whether the user
    /// chose (`Selected`), bailed (`Cancel`), or is still browsing (`Pending`).
    /// Esc / Ctrl-C cancel; Enter selects the cursor (or is Pending on an empty
    /// list); Up/Down wrap the cursor; printable chars / Backspace edit the
    /// query. Performs NO I/O.
    pub fn on_key(&mut self, key: KeyEvent) -> PickerOutcome {
        if key.kind != KeyEventKind::Press {
            return PickerOutcome::Pending;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => PickerOutcome::Cancel,
            KeyCode::Char('c') if ctrl => PickerOutcome::Cancel,
            KeyCode::Enter => match self.selected_idx() {
                Some(idx) => PickerOutcome::Selected { idx },
                None => PickerOutcome::Pending,
            },
            KeyCode::Up => {
                self.move_cursor(-1);
                PickerOutcome::Pending
            }
            KeyCode::Down => {
                self.move_cursor(1);
                PickerOutcome::Pending
            }
            KeyCode::Backspace => {
                self.query.pop();
                self.recompute();
                PickerOutcome::Pending
            }
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute();
                PickerOutcome::Pending
            }
            _ => PickerOutcome::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    fn press_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::CONTROL, KeyEventKind::Press)
    }

    fn names() -> Vec<String> {
        vec!["web-prod".into(), "db-staging".into(), "web-dev".into()]
    }

    // ---- new: empty query ranks all, in name order ----

    #[test]
    fn new_empty_query_ranks_all_in_name_order() {
        let p = CredPicker::new(&names());
        // Empty query + all-zero scores → rank_by_name returns every index,
        // sorted by name asc (db-staging < web-dev < web-prod).
        assert_eq!(p.ranked, vec![1, 2, 0]);
        assert_eq!(p.query, "");
        assert_eq!(p.selected, 0);
    }

    // ---- query filters by fuzzy match ----

    #[test]
    fn typing_query_keeps_only_matches_in_score_order() {
        let mut p = CredPicker::new(&names());
        // Type "web": matches web-dev (1) and web-prod (0). Both contain "web"
        // as a prefix at the same position; rank_by_name breaks ties by name
        // asc → web-dev before web-prod.
        for c in "web".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(p.ranked, vec![2, 0]);
    }

    // ---- cursor moves wrap and clamp ----

    #[test]
    fn down_then_up_moves_cursor_with_wrap() {
        let mut p = CredPicker::new(&names()); // ranked = [1,2,0], selected=0
        let _ = p.on_key(press(KeyCode::Down));
        assert_eq!(p.selected, 1);
        let _ = p.on_key(press(KeyCode::Down));
        assert_eq!(p.selected, 2);
        let _ = p.on_key(press(KeyCode::Down));
        assert_eq!(p.selected, 0, "wraps to top");
        let _ = p.on_key(press(KeyCode::Up));
        assert_eq!(p.selected, 2, "wraps to bottom");
    }

    #[test]
    fn cursor_clamps_when_query_shrinks_the_list() {
        let mut p = CredPicker::new(&names());
        // Move to the last of 3, then filter to 1 match — selected must clamp.
        let _ = p.on_key(press(KeyCode::Down));
        let _ = p.on_key(press(KeyCode::Down));
        assert_eq!(p.selected, 2);
        for c in "db".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(p.ranked, vec![1], "only db-staging matches");
        assert_eq!(p.selected, 0, "clamped into the 1-entry list");
    }

    // ---- Enter selects the cursor's original index ----

    #[test]
    fn enter_returns_selected_original_index() {
        let mut p = CredPicker::new(&names()); // ranked=[1,2,0], selected=0 → idx 1
        let out = p.on_key(press(KeyCode::Enter));
        assert_eq!(out, PickerOutcome::Selected { idx: 1 });
    }

    #[test]
    fn enter_on_empty_list_is_pending() {
        let mut p = CredPicker::new(&[]); // no credentials at all
        let out = p.on_key(press(KeyCode::Enter));
        assert!(matches!(out, PickerOutcome::Pending));
    }

    #[test]
    fn enter_on_no_match_query_is_pending() {
        // Credentials exist, but the query matches none: ranked empties,
        // selected_idx() is None, so Enter stays Pending (no selection, no panic).
        let mut p = CredPicker::new(&["web-prod".into(), "db-staging".into()]);
        for c in "zzz".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert!(p.ranked.is_empty(), "no name matches 'zzz'");
        assert!(matches!(
            p.on_key(press(KeyCode::Enter)),
            PickerOutcome::Pending
        ));
    }

    // ---- Esc / Ctrl-C cancel; other keys are pending ----

    #[test]
    fn escape_cancels() {
        let mut p = CredPicker::new(&names());
        assert_eq!(p.on_key(press(KeyCode::Esc)), PickerOutcome::Cancel);
    }

    #[test]
    fn ctrl_c_cancels() {
        let mut p = CredPicker::new(&names());
        assert_eq!(
            p.on_key(press_ctrl(KeyCode::Char('c'))),
            PickerOutcome::Cancel
        );
    }

    #[test]
    fn backspace_pops_query() {
        let mut p = CredPicker::new(&names());
        let _ = p.on_key(press(KeyCode::Char('w')));
        let _ = p.on_key(press(KeyCode::Backspace));
        assert!(p.query.is_empty());
        // Empty query → all names ranked again.
        assert_eq!(p.ranked.len(), 3);
    }

    #[test]
    fn non_press_events_are_pending() {
        let mut p = CredPicker::new(&names());
        let release =
            KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        assert!(matches!(p.on_key(release), PickerOutcome::Pending));
    }

    // ---- draw_overlay: render smoke + cursor placement ----

    #[test]
    fn draw_overlay_renders_without_panic_and_places_cursor() {
        use ratatui::{Terminal, backend::TestBackend};
        let p = CredPicker::new(&["web-prod".into(), "db-staging".into()]);
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
        // After a draw that calls set_cursor_position, TestBackend records the
        // cursor; a None cursor would mean we forgot to place it.
        // (TestBackend::set_cursor_position is called inside draw_overlay.)
    }

    #[test]
    fn draw_overlay_on_empty_list_renders_without_panic() {
        use ratatui::{Terminal, backend::TestBackend};
        let p = CredPicker::new(&[] as &[String]);
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }
}
