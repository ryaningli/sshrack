//! Fuzzy credential picker: a pure sub-state opened from the host wizard's
//! Credential row (Reference branch). It snapshots the wizard's
//! `credential_names`, holds a fuzzy `query` + cursor into a ranked list of
//! original indices, and delegates matching to [`crate::tui::panel::rank_by_name`]
//! (all-zero scores — credentials have no frecency). Pure: no I/O, so the whole
//! state machine is unit-testable without a terminal. Rendering lives in
//! [`CredPicker::draw_overlay`] (added in a later task).

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

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

// The picker is a pure state machine landed ahead of its host-wizard wiring
// (task 2: host wizard Credential row + picker routing). Until that wiring
// lands, the binary build has no production caller, so suppress dead_code for
// the impl + types. Remove these allows once task 2 references them.
#[allow(dead_code)]
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
        let scores = vec![0.0f64; names.len()];
        crate::tui::panel::rank_by_name(names, &scores, query)
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
}
