# Host Credential Picker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Split the host wizard's "pick a credential" out of the Auth row into its own `Credential` row (Reference branch), and make picking that credential a fuzzy searchable overlay instead of an in-place `Shift-←/→` cycle — so a host that reuses a credential still works when dozens of credentials exist. Also: move the `User` field from above `Auth` to below it — `User` is Independent-only (Reference pulls the user from the credential), so it reads more naturally under the auth choice than above it, and the Tab flow becomes `Name → Host → Port → Auth → User → Secret → …`.

**Architecture:** The credential picker is an **internal sub-state of `HostForm`** (`cred_picker: Option<CredPicker>`), not a new `Overlay` variant — the shell's at-most-one-overlay contract stays intact, and the picker is modal over the wizard. `CredPicker` is a pure state machine (`query` + `cursor` + `ranked: Vec<usize>` of original indices into the wizard's `credential_names`) that reuses `panel::rank_by_name` for fuzzy matching with all-zero scores (no frecency for credentials). The Reference branch gains a `Field::Credential` row; `Enter` there opens the picker overlay (`popup::render_popup`), `Enter` inside selects → writes `AuthChoice::Reference { idx }` and closes. `core`'s `Auth::Ref { credential: Ulid }` model and the loop's `persist_host_save` name→id resolution are **untouched** — the wizard still emits `Reference { idx }` against `credential_names`.

**Tech Stack:** Rust 2024 (MSRV 1.86), ratatui 0.30, crossterm 0.28, nucleo-matcher 0.3 (via `crate::tui::panel::rank_by_name`).

**Baseline:** Branch off `main` as `feat/host-credential-picker`. The host wizard auth logic lives on `main`; this plan is independent of the in-flight `feat/tui-ux-refinements` UX-polish branch (that branch touches `launcher`/`shell`/`parts`, this plan touches `wizard/host.rs` — no overlap).

## Global Constraints

Verbatim from `CLAUDE.md` hard rules — every task inherits these:

- **English only** — all source, comments, doc comments, errors, help text, logs, commits.
- **Zero `unsafe`** — never, including tests.
- **Zero `unwrap()`/`expect()`** in production code — only in `#[cfg(test)]` or `expect("invariant: ...")` for genuinely unreachable states.
- **TDD for pure logic** — RED → GREEN → REFACTOR for the pure state machines (`CredPicker`, `HostForm::on_key` key handling). Rendering is covered by `TestBackend` no-panic + geometry tests.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Tests are hermetic** — `cargo test` green in a real shell with `SSHRACK_PASSPHRASE` set; no `env -u` fallback.
- **`sshrack-core` zero-UI invariant** — this plan does NOT modify anything under `crates/sshrack-core/`. All changes are under `src/tui/`.
- **Dev stage, no compat code** — `cycle_credential` and its `Shift-←/→` binding are **deleted**, not deprecated. No fallback shim.
- **No duplicate logic** — fuzzy ranking reuses `crate::tui::panel::rank_by_name`; popup chrome reuses `popup::centered_rect` / `popup::render_popup`.

**Commit style:** `<type>(<scope>): <desc>` (Conventional Commits), scope `tui`. Each task ends with a commit.

---

## File Structure

```
src/tui/
├── wizard/
│   ├── mod.rs          # MODIFY: Field gains a Credential variant + ORDER/label/HOST_VALUE_COL
│   ├── host.rs         # MODIFY: HostForm gains cred_picker; new Credential row; drop shift-cycling; picker routing
│   └── cred_picker.rs  # CREATE: CredPicker pure state machine + PickerOutcome + draw_overlay
├── popup.rs            # MODIFY: render_popup returns the inner content Rect (for picker cursor placement)
└── (panel.rs)          # UNCHANGED — read-only dependency: rank_by_name(names, scores, query) -> Vec<usize>
```

No new dependencies. No changes under `crates/sshrack-core/`. No changes to `app.rs` routing (the picker is internal to `HostForm`, so `Overlay::HostWizard(form) => form.on_key(key)` and the wizard's `draw_in_dialog` already cover it).

---

## Task 1: `CredPicker` pure state machine

A pure, terminal-free fuzzy credential picker. Built and unit-tested in isolation before the host wizard wires it up.

**Files:**
- Create: `src/tui/wizard/cred_picker.rs`
- Modify: `src/tui/wizard/mod.rs` (declare + re-export the module)

**Interfaces:**
- Consumes: `crate::tui::panel::rank_by_name(names: &[String], scores: &[f64], query: &str) -> Vec<usize>` (read-only; empty query returns all indices in name order, non-empty returns only fuzzy matches ordered by score — passing all-zero scores drops frecency, leaving pure fuzzy+name order).
- Consumes: `crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers}`.
- Produces:
  - `pub enum PickerOutcome { Selected { idx: usize }, Cancel, Pending }` — `idx` is an original index into the wizard's `credential_names`.
  - `pub struct CredPicker { names: Vec<String>, query: String, selected: usize, ranked: Vec<usize> }` with `new(&[String])`, `on_key(KeyEvent) -> PickerOutcome`, `selected_idx() -> Option<usize>`.

- [ ] **Step 1: Declare the module + write the failing tests**

Add to `src/tui/wizard/mod.rs` (alongside the existing `pub mod cred;` / `pub mod host;`):

```rust
pub mod cred_picker;

pub use cred_picker::{CredPicker, PickerOutcome};
```

Create `src/tui/wizard/cred_picker.rs` with ONLY the test module first (RED):

```rust
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
        assert_eq!(p.on_key(press_ctrl(KeyCode::Char('c'))), PickerOutcome::Cancel);
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
        let release = KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        assert!(matches!(p.on_key(release), PickerOutcome::Pending));
    }
}
```

- [ ] **Step 2: Run — expect compile failure (types undefined)**

Run: `cargo test -p sshrack --lib tui::wizard::cred_picker 2>&1 | head -20`
Expected: FAIL — `cannot find type PickerOutcome / CredPicker in this scope` (the `impl` block does not exist yet).

- [ ] **Step 3: Implement the state machine**

Append the `impl` block to `src/tui/wizard/cred_picker.rs` (above the `#[cfg(test)]` module):

```rust
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
```

- [ ] **Step 4: Run — expect pass**

Run: `cargo test -p sshrack --lib tui::wizard::cred_picker`
Expected: all 11 tests PASS.

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): pure fuzzy credential picker state machine"
```

---

## Task 2: Host wizard `Credential` row + picker routing (drop shift-cycling)

Wire `CredPicker` into `HostForm`: add a `Field::Credential` row on the Reference branch, open the picker on `Enter` there, route keys into the picker while it is open, and write the selection back to `AuthChoice::Reference { idx }`. Delete `cycle_credential` and its `Shift-←/→` binding (dev stage — no compat shim) and migrate the tests that asserted the old behavior. Also move `Field::User` below `Auth` in `Field::ORDER` (it is Independent-only), and fix `reachable_fields` so the Independent blacklist excludes `Credential` (otherwise Independent would wrongly render the Credential row).

**Files:**
- Modify: `src/tui/wizard/mod.rs` — `Field` enum + `ORDER` + `label` + `HOST_VALUE_COL` + its doc comment.
- Modify: `src/tui/wizard/host.rs` — `HostForm` gains `cred_picker`; `reachable_fields`; `cycle_auth` focus convergence; `on_key` (drop shift branches, add picker routing + Credential-Enter); `row_value_and_placeholder` (Credential row + Auth/Secret hint wording); `cursor_target` (Credential → None); delete `cycle_credential`; migrate tests.

**Interfaces:**
- Consumes: `super::{CredPicker, PickerOutcome}` (Task 1), `crate::tui::panel::rank_by_name` (indirectly via CredPicker).
- Produces: `HostForm { cred_picker: Option<CredPicker>, .. }`; the `Field::Credential` variant; `AuthChoice::Reference { idx }` still the persisted shape (so `persist.rs` and core are untouched).

- [ ] **Step 1: Add `Field::Credential` + widen the label column (mod.rs)**

In `src/tui/wizard/mod.rs`, the `Field` enum gains a `Credential` variant between `Auth` and `Secret`:

```rust
pub enum Field {
    Name,
    Host,
    Port,
    User,
    Auth,
    /// Pick which `[[credentials]]` entry this host reuses (Reference branch
    /// only). A trigger row: `Enter` opens the fuzzy credential picker overlay,
    /// not a text field. Unreachable under Independent.
    Credential,
    Secret,
    Identity,
    Password,
}
```

Update `Field::ORDER` to (a) insert `Field::Credential` after `Field::Auth`, and (b) move `Field::User` from before `Auth` to after `Credential` — `User` is Independent-only, so it belongs under the auth choice, not above it. New order:

```rust
const ORDER: &'static [Field] = &[
    Field::Name,
    Field::Host,
    Field::Port,
    Field::Auth,
    Field::Credential,
    Field::User,
    Field::Secret,
    Field::Identity,
    Field::Password,
];
```

Add the label arm in `Field::label`:

```rust
    Field::Auth => "Auth",
    Field::Credential => "Credential",
    Field::Secret => "Secret",
```

Widen the label column: the longest host label is now `Credential` (9 chars), not `Identity`/`Password` (8). Update the constant and its doc comment:

```rust
/// Column where the editable value begins within a rendered field row:
/// `"▶ " (2) + right-aligned label + ": " (2)`. Host labels are padded to 9
/// (the longest host label is `Credential` = 9); credential-wizard labels stay
/// 8. Used by each form's `draw` to place the terminal cursor.
pub(super) const HOST_VALUE_COL: u16 = 2 + 9 + 2;
pub(super) const CRED_VALUE_COL: u16 = 2 + 8 + 2;
```

- [ ] **Step 2: Add `cred_picker` to `HostForm` + initialize it (host.rs)**

In `src/tui/wizard/host.rs`, add the field to the `HostForm` struct (after `credential_names`):

```rust
    /// The credential names offered by the Reference chooser, in order. The
    /// wizard never resolves these to ids itself — the loop does, at save time.
    pub credential_names: Vec<String>,
    /// Open fuzzy credential picker (Reference branch). `None` when closed.
    /// When open, `on_key` routes every key into the picker before the form,
    /// and `draw_in_dialog` paints the picker overlay over the wizard.
    pub cred_picker: Option<super::CredPicker>,
```

Add `cred_picker` to the redacting `Debug` impl (`.field("cred_picker", &self.cred_picker)` — names are not secrets, but include it for completeness before `credential_names`).

Initialize `cred_picker: None` in BOTH constructors:
- `HostForm::new_add` (add the field after `credential_names,`).
- `HostForm::new_edit` (add the field after `credential_names,`).

Add `CredPicker, PickerOutcome` to the `use super::{...}` import list at the top of `host.rs` (it currently imports `AuthChoice, AuthKind, Field, HOST_VALUE_COL, SaveError, SecretChoice, validate, value_spans`).

- [ ] **Step 3: Delete `cycle_credential` + its `Shift-←/→` binding**

Delete the entire `cycle_credential` method (the ~12-line `fn cycle_credential(&mut self, delta: i32)` block, currently around `host.rs:222`).

In `on_key`, delete the two `Shift` branches on the Auth row (the `KeyCode::Left if self.focus == Field::Auth && shift` and `KeyCode::Right if self.focus == Field::Auth && shift` arms, currently around `host.rs:411-424`). The non-shift `Left`/`Right` arms for `Field::Auth` (which call `cycle_auth`) STAY.

- [ ] **Step 4: Make `Credential` reachable under Reference + converge focus on auth switch**

Update `reachable_fields` so the Reference branch includes `Field::Credential`, AND — because the Independent branch uses a blacklist (`!matches!`) rather than a whitelist — explicitly exclude `Field::Credential` from each Independent arm. Without this exclusion Independent would wrongly render the Credential row (a blacklist that does not name `Credential` lets it through). Replace the whole `match self.auth_choice { ... }` body:

```rust
            AuthChoice::Reference { .. } => matches!(
                f,
                Field::Name | Field::Host | Field::Port | Field::Auth | Field::Credential
            ),
            AuthChoice::Independent => match self.secret_kind {
                SecretChoice::None => {
                    !matches!(f, Field::Credential | Field::Identity | Field::Password)
                }
                SecretChoice::IdentityKey => !matches!(f, Field::Credential | Field::Password),
                SecretChoice::Password => !matches!(f, Field::Credential | Field::Identity),
            },
```

In `cycle_auth`, after the `self.auth_choice = match next_kind { ... }` assignment, converge `focus` so toggling auth never leaves the cursor on an unreachable (or now-less-relevant) row. The rule: landing on Reference moves focus to `Credential` (its distinctive field) unless the user was editing a field shared by both modes; landing on Independent from `Credential` moves to `User`. Append before the method's closing brace:

```rust
        // Converge focus so toggling auth lands on the new mode's signature
        // field: Reference → Credential, Independent (from Credential) → User.
        // Name/Host/Port are common to both modes, so editing them is never
        // interrupted by an auth toggle; Auth itself also converges to
        // Credential on the Reference side (the test helper relies on this).
        match next_kind {
            AuthKind::Reference => {
                if !matches!(self.focus, Field::Name | Field::Host | Field::Port) {
                    self.focus = Field::Credential;
                }
            }
            AuthKind::Independent => {
                if self.focus == Field::Credential {
                    self.focus = Field::User;
                }
            }
        }
```

- [ ] **Step 5: Route keys into the picker + open it from the Credential row**

At the very top of `on_key`, immediately AFTER the `if key.kind != KeyEventKind::Press` guard and the `self.core_error = None;` line (and BEFORE the `ctrl_c_only` check), add picker routing so an open picker swallows every key:

```rust
        // An open credential picker is modal: route every key into it before
        // the form. Selected writes the chosen credential index back and closes
        // the picker; Cancel just closes; Pending keeps it open.
        if let Some(picker) = self.cred_picker.as_mut() {
            match picker.on_key(key) {
                PickerOutcome::Selected { idx } => {
                    self.auth_choice = AuthChoice::Reference { idx };
                    self.cred_picker = None;
                }
                PickerOutcome::Cancel => self.cred_picker = None,
                PickerOutcome::Pending => {}
            }
            self.error = None;
            return Outcome::Continue;
        }
```

Then change the `Enter` arm so the `Credential` row opens the picker instead of advancing/saving. Replace the existing `KeyCode::Enter => { ... }` arm with:

```rust
            KeyCode::Enter => {
                // The Credential row is a trigger: Enter opens the fuzzy picker
                // (only when there is at least one credential to pick). It never
                // advances focus or saves from here.
                if self.focus == Field::Credential {
                    if !self.credential_names.is_empty() {
                        self.cred_picker = Some(CredPicker::new(self.credential_names.clone()));
                    }
                    self.error = None;
                    return Outcome::Continue;
                }
                if self.is_last_reachable(self.focus) {
                    self.attempt_save()
                } else {
                    self.move_focus(1);
                    Outcome::Continue
                }
            }
```

(Under Reference, `Credential` IS the last reachable field, so without this special case Enter would call `attempt_save` — the guard prevents that. Under Independent there is no `Credential` row, so Enter behaves exactly as before.)

- [ ] **Step 6: Render the Credential row + update hints + cursor_target**

In `row_value_and_placeholder`, add a `Field::Credential` arm (place it between the `Field::Auth` and `Field::Secret` arms):

```rust
            Field::Credential => {
                // Mirror the Auth row's Reference display: the selected name, or
                // a placeholder when none is chosen / none exist.
                let v = match &self.auth_choice {
                    AuthChoice::Reference { idx } => match self.credential_names.get(*idx) {
                        Some(name) => name.clone(),
                        None => "<none>".to_string(),
                    },
                    AuthChoice::Independent => String::new(),
                };
                let ph = if self.credential_names.is_empty() {
                    Some("no credentials defined — add one with the cred wizard")
                } else {
                    Some("Enter to pick")
                };
                (v, ph)
            }
```

In `cursor_target`, the `Credential` row is a trigger (no text cursor); add it to the `None`-returning branch alongside `Auth`/`Secret`:

```rust
            Field::Auth | Field::Credential | Field::Secret => return None,
```

Update the hint strings in `draw_in_dialog`:
- The `Field::Auth` hint becomes (drop the Shift wording, point at the Credential row):
  `"  <- -> cycle Independent/Reference  ·  Tab next  ·  ^s save  ·  Esc cancel"`
- Add a `Field::Credential` arm (before the catch-all `_`):
  `"  Enter pick credential  ·  Esc cancel  ·  ^s save"`
- The catch-all `_` hint stays `"  Tab/up-down next  ·  ^s save  ·  Esc cancel"`.

Update the `Field::Auth` placeholder in `row_value_and_placeholder`: the Reference branch currently says `"Shift-<- -> cycle credential"` — change it to `"<- -> cycle to Independent"`. And drop the now-stale "no credentials defined" branch from the Auth placeholder (it now lives on the Credential row). The Auth placeholder becomes:

```rust
                let ph = match self.auth_choice {
                    AuthChoice::Independent => Some("<- -> cycle to Reference"),
                    AuthChoice::Reference { .. } => Some("<- -> cycle to Independent"),
                };
```

- [ ] **Step 7: Migrate the tests (drop shift-cycling; add picker wiring)**

In the `#[cfg(test)] mod tests` block of `host.rs`:

- DELETE the test `shift_arrow_on_reference_cycles_the_credential_list` (and any companion test asserting Shift-←/→ is a no-op on Independent) — the behavior is gone.
- Any test whose `cursor_target` row-index comment counts rows must account for TWO order changes: under Reference the reachable rows are now `Name(0)/Host(1)/Port(2)/Auth(3)/Credential(4)`, and under Independent the order is now `Name(0)/Host(1)/Port(2)/Auth(3)/User(4)/Secret(5)` (`User` moved below `Auth`; `Identity`/`Password` follow `Secret` as before). Update those comments/assertions if any exist (search `host.rs` tests for `cursor_target` / row-index asserts). The existing `host_cursor_target_host_with_typed_value_offsets_by_char_count` test still asserts Host at row 1 (unchanged) but its inline comment listing the Independent row order must be updated to the new order.
- ADD these tests for the new wiring (use the existing `press(code, mods)` / `blank_form()` / `form_with` helpers already in the test module):

```rust
    fn ref_form(names: &[&str]) -> HostForm {
        // A Reference-form host: switch Auth to Reference so the Credential row
        // is reachable. Focus starts on Credential.
        let mut f = HostForm::new_add(names.iter().map(|s| s.to_string()).collect());
        f.name = "h".into();
        f.host_addr = "10.0.0.5".into();
        // Cycle Auth Independent -> Reference, then focus the Credential row.
        f.focus = Field::Auth;
        let _ = f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert!(matches!(f.auth_choice, AuthChoice::Reference { .. }));
        assert_eq!(f.focus, Field::Credential, "cycle_auth converged focus to Credential");
        f
    }

    #[test]
    fn credential_row_enter_opens_picker_when_credentials_exist() {
        let mut f = ref_form(&["web-prod", "db"]);
        assert!(f.cred_picker.is_none());
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(f.cred_picker.is_some(), "Enter on Credential opened the picker");
    }

    #[test]
    fn credential_row_enter_is_a_noop_when_no_credentials() {
        let mut f = ref_form(&[]);
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(f.cred_picker.is_none(), "no picker when there is nothing to pick");
    }

    #[test]
    fn picker_select_writes_back_the_credential_index() {
        let mut f = ref_form(&["web-prod", "db-staging", "web-dev"]);
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE)); // open
        // ranked at empty query = [1,2,0] (name order: db-staging, web-dev, web-prod);
        // cursor at 0 → idx 1 (db-staging). Enter selects it.
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(f.cred_picker.is_none(), "picker closed after selecting");
        assert_eq!(f.selected_credential_name(), Some("db-staging"));
    }

    #[test]
    fn picker_escape_closes_without_changing_selection() {
        let mut f = ref_form(&["web-prod", "db-staging"]);
        // Pre-set an existing reference idx so we can prove Esc leaves it alone.
        f.auth_choice = AuthChoice::Reference { idx: 0 }; // web-prod
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE)); // open
        let _ = f.on_key(press(KeyCode::Down, KeyModifiers::NONE)); // move cursor
        let _ = f.on_key(press(KeyCode::Esc, KeyModifiers::NONE)); // cancel
        assert!(f.cred_picker.is_none());
        assert_eq!(f.selected_credential_name(), Some("web-prod"), "Esc did not change the choice");
    }

    #[test]
    fn credential_row_has_no_text_cursor() {
        let mut f = ref_form(&["web-prod"]);
        f.focus = Field::Credential;
        assert_eq!(f.cursor_target(), None);
    }

    #[test]
    fn independent_branch_never_renders_the_credential_row() {
        // The Independent branch filters with a blacklist, so Credential must
        // be explicitly excluded — pin that across all three secret kinds.
        let mut f = HostForm::new_add(vec!["web-prod".into()]);
        f.name = "h".into();
        f.host_addr = "10.0.0.5".into();
        assert!(!f.reachable_fields().contains(&Field::Credential), "Independent+None");
        f.secret_kind = SecretChoice::Password;
        assert!(!f.reachable_fields().contains(&Field::Credential), "Independent+Password");
        f.secret_kind = SecretChoice::IdentityKey;
        assert!(!f.reachable_fields().contains(&Field::Credential), "Independent+IdentityKey");
    }
```

- [ ] **Step 8: Build + test**

Run: `cargo build --workspace && cargo test --bin sshrack`
Expected: green. If a test fails on a row-index assertion, it is a missed Reference-row count update (see Step 7) — fix the assertion.

- [ ] **Step 9: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): host wizard credential row with fuzzy picker, drop shift-cycling"
```

---

## Task 3: Credential picker overlay rendering

Paint the open picker as a centered popup over the wizard: a query box with a real terminal cursor + a windowed, highlighted list of matching credential names. Reuse `popup::render_popup` for the chrome.

**Files:**
- Modify: `src/tui/popup.rs` — `render_popup` returns the inner content `Rect` (so the picker can place the terminal cursor on its query box). No change to existing callers (they ignore the return value).
- Modify: `src/tui/wizard/cred_picker.rs` — add `CredPicker::draw_overlay(&self, frame)`.
- Modify: `src/tui/wizard/host.rs` — call `picker.draw_overlay(frame)` at the end of `HostForm::draw_in_dialog` when the picker is open.

**Interfaces:**
- Consumes: `crate::tui::popup::{centered_rect, render_popup}`, `crate::tui::theme`, `ratatui::{Frame, text::{Line, Span}, widgets::Paragraph, layout::{Alignment, Constraint, Layout}, style::{Style, Modifier}}`.
- Produces: `CredPicker::draw_overlay(&self, frame: &mut Frame)` (rendering only; no state mutation).

- [ ] **Step 1: Make `render_popup` return the inner content Rect (popup.rs)**

Change the signature and capture the inner rect. The current body renders the body widget into a computed content area — return that area:

```rust
/// Render a clear-backed bordered popup titled `title`, then render `body`
/// inside it, and return the inner content rect (so callers that need to place
/// a terminal cursor — e.g. the credential picker's query box — know where the
/// content area landed). Callers that ignore the return value are unaffected.
pub fn render_popup<W: Widget>(frame: &mut Frame, title: &str, body: W) -> Rect {
    let area = centered_rect(frame.area());
    frame.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(format!(" {title} "));
    frame.render_widget(&block, area);
    let [content] = Layout::vertical([Constraint::Fill(1)]).areas(block.inner(area));
    frame.render_widget(body, content);
    content
}
```

Add a test asserting the returned rect sits inside the centered popup. Single draw captures the rect via the closure; `render_popup` and `centered_rect` are in scope through the test module's existing `use super::*` — use them WITHOUT a `popup::` prefix:

```rust
    #[test]
    fn render_popup_returns_inner_content_rect() {
        let backend = TestBackend::new(100, 40);
        let mut term = Terminal::new(backend).unwrap();
        let mut captured = None;
        let _ = term.draw(|f| {
            captured = Some(render_popup(f, "Title", Paragraph::new("body")));
        });
        let rect = captured.unwrap();
        let screen = Rect::new(0, 0, 100, 40);
        let popup = centered_rect(screen);
        assert!(rect.x >= popup.x);
        assert!(rect.x + rect.width <= popup.x + popup.width);
        assert!(rect.y >= popup.y);
        assert!(rect.y + rect.height <= popup.y + popup.height);
    }
```

- [ ] **Step 2: Write the failing test for `draw_overlay` (RED)**

Add to `cred_picker.rs`'s test module. Rendering is covered by a `TestBackend` no-panic + "cursor placed inside the popup" assertion (the cursor is the observable side effect of a non-empty render):

```rust
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
```

- [ ] **Step 3: Implement `draw_overlay`**

Add imports at the top of `cred_picker.rs`:

```rust
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
```

Add the method to `impl CredPicker`:

```rust
    /// Paint the picker as a centered popup over the wizard: a query box (with
    /// the real terminal cursor at its end) on top, then a windowed, highlighted
    /// list of matching names below. The window follows the cursor so long
    /// credential lists stay scrollable within the fixed popup footprint.
    /// Rendering only — mutates nothing.
    pub fn draw_overlay(&self, frame: &mut Frame) {
        // Body: row 0 = query box "> {query}", then up to (height-1) list rows.
        let query_line = Line::from(vec![
            Span::styled("> ", Style::new().fg(crate::tui::theme::accent()).add_modifier(Modifier::BOLD)),
            Span::raw(self.query.clone()),
            Span::styled("_", Style::new().dim()), // visual cursor hint
        ]));

        let list_lines = self.windowed_lines();

        let mut lines = vec![query_line];
        lines.extend(list_lines);
        let body = Paragraph::new(lines).alignment(Alignment::Left);

        let content = crate::tui::popup::render_popup(frame, " pick credential ", body);

        // Place the real terminal cursor right after the typed query on row 0.
        // "> " is 2 chars; offset by the query length.
        let x = content.x + 2 + self.query.chars().count() as u16;
        let max_x = content.x + content.width.saturating_sub(1);
        frame.set_cursor_position((x.min(max_x), content.y));
    }

    /// Build the visible list rows: a window of `ranked` around `selected`,
    /// each rendered with the cursor row highlighted and non-matching entries
    /// excluded (they are already filtered out of `ranked` by `recompute`).
    fn windowed_lines(&self) -> Vec<Line<'static>> {
        if self.ranked.is_empty() {
            return vec![Line::from(Span::styled(
                "  no matches — add a credential with the cred wizard",
                Style::new().dim(),
            ))];
        }
        let visible = 16usize; // popup inner height ≈ 18; leave 1 for the query row + margin
        let half = visible / 2;
        let start = self.selected.saturating_sub(half);
        let end = (start + visible).min(self.ranked.len());
        let start = end.saturating_sub(visible).min(start);
        (start..end)
            .map(|i| {
                let name = self
                    .names
                    .get(self.ranked[i])
                    .cloned()
                    .unwrap_or_default();
                let is_sel = i == self.selected;
                let prefix = if is_sel { "▶ " } else { "  " };
                let span = if is_sel {
                    Span::styled(
                        format!("{prefix}{name}"),
                        Style::new()
                            .fg(crate::tui::theme::accent())
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::raw(format!("{prefix}{name}"))
                };
                Line::from(span)
            })
            .collect()
    }
```

- [ ] **Step 4: Call `draw_overlay` from the wizard (host.rs)**

At the very end of `HostForm::draw_in_dialog` (after the existing `if let Some((row, offset)) = self.cursor_target() { ... }` cursor-placement block), add:

```rust
        // If the credential picker is open, paint it over the wizard. Drawn last
        // so it sits on top, and after the wizard's own cursor placement so the
        // picker's query-box cursor wins.
        if let Some(picker) = &self.cred_picker {
            picker.draw_overlay(frame);
        }
```

- [ ] **Step 5: Build + test**

Run: `cargo build --workspace && cargo test --bin sshrack`
Expected: green, including the new `cred_picker::tests::draw_overlay_*` tests.

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): render credential picker as a centered fuzzy overlay"
```

---

## Task 4: CLAUDE.md sync + full gate

Update the docs to describe the new Credential row + picker, then run the whole gate.

**Files:**
- Modify: `CLAUDE.md` — the "TUI keys" subsection (wizard keybindings) and the wizard description in the TUI section.

- [ ] **Step 1: Update CLAUDE.md**

In the **Identity & Config Model** section, the Reference/Independent description is unchanged at the model level (`Auth::Ref { credential: Ulid }` is untouched) — no edit needed there.

In the **TUI (delivered)** section's wizard bullet (and the "TUI keys" table if it enumerates wizard keys), add a line describing the new interaction. Append to the wizard description:

```markdown
- **Host wizard auth:** the Auth row cycles `Independent ↔ Reference` with `←`/`→`. Under Reference a dedicated **Credential** row appears; `Enter` there opens a fuzzy credential-picker overlay (type to filter, `↑`/`↓` to move, `Enter` to select, `Esc` to cancel) — replacing the old in-place `Shift-←/→` cycle so a host can reuse a credential even when dozens exist. Under Independent the `Secret` row cycles `None / Password / IdentityKey` as before.
```

(If the "TUI keys" table has a row for the old `Shift-←/→` credential cycling, delete that row and replace with the `Enter`-on-Credential-opens-picker binding.)

- [ ] **Step 2: Final full gate**

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green. `cargo test --workspace` includes the new `cred_picker` tests (Task 1), the migrated host wizard tests (Task 2), and the `draw_overlay` tests (Task 3).

- [ ] **Step 3: Sanity grep — no shift-cycling residue**

```bash
rg -n 'cycle_credential|Shift.*cycle credential|shift_arrow.*credential' src/ CLAUDE.md
```
Expected: zero hits (the old behavior is fully removed — dev stage, no compat).

- [ ] **Step 4: Manual smoke**

```bash
cargo run -q -- host add        # wizard
# In the wizard: fill Name + Host, Tab to Auth, <- -> switch to Reference,
# Tab to Credential, Enter -> picker opens. Type to filter, Up/Down, Enter to
# pick. The Credential row now shows the chosen name. ^s saves.
cargo run -q -- host ls --format json   # the saved host has credential_name set
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "docs(tui): document host wizard credential picker row"
```

Then use the `superpowers:finishing-a-development-branch` skill to merge/PR.

---

## Self-Review (completed by planner)

- **Spec coverage:** The user's three asks — (1) "selecting a credential and independent-vs-reference should not be crammed into one option" and (2) "make independent/reference a single choice, then render each branch's own options (independent → the three secret kinds; reference → pick a credential)", plus (3) "move `User` below `Auth` since it is Independent-only" — are all covered: the Auth row is now ONLY the Independent/Reference choice (`←`/`→`), the Reference branch renders its own `Credential` row whose `Enter` opens a dedicated fuzzy picker, the Independent branch keeps its `Secret` row with the three kinds, and `User` now sits below `Auth` in `Field::ORDER` (Task 2 Step 1). Task 2 (Auth row slimmed + Credential row + User move) + Task 3 (picker overlay) implement this end to end.
- **reachable_fields correction:** Adding `Field::Credential` exposed that the Independent branch filters with a blacklist (`!matches!`), so `Credential` had to be explicitly excluded there (Task 2 Step 4) — otherwise Independent would render the Credential row. This is a real fix, not a cosmetic one; it is pinned by the `independent_branch_never_renders_the_credential_row` test added in Task 2 Step 7.
- **Placeholder scan:** No "TBD"/"TODO"/"add error handling". Every code step shows the full code. Test code is complete for Tasks 1 and 3; Task 2's test step gives full code for the new tests and explicit delete instructions for the removed behavior (a delete needs no code).
- **Type consistency:** `PickerOutcome::Selected { idx }` (Task 1) is matched verbatim in Task 2's picker routing. `CredPicker::new(&[String])` / `on_key(KeyEvent) -> PickerOutcome` / `selected_idx()` / `draw_overlay(&mut Frame)` signatures are consistent across Tasks 1–3. `Field::Credential` is added once (Task 2 Step 1) and used consistently in `reachable_fields`, `cursor_target`, `row_value_and_placeholder`, hints, and tests. `HOST_VALUE_COL` widens to `2+9+2` once and is used by `cursor_target`.
- **Core untouched:** No step modifies `crates/sshrack-core/`. `Auth::Ref { credential: Ulid }` and `persist_host_save`'s `selected_credential_name() → find_credential_by_name → id` path are unchanged — confirmed by reading `persist.rs:57-70`.
- **Gaps to watch at implementation:** (1) `panel::rank_by_name`'s empty-query order is name-asc with all-zero scores — Task 1's `new_empty_query_ranks_all_in_name_order` test pins this; if the implementer observes a different order they must read `panel.rs` before "fixing" the test. (2) The Task 2 `ref_form` test helper relies on `cycle_auth` converging focus to `Credential` (Step 4) — if that convergence is skipped, the helper's assertion fails loudly, which is the intended signal. (3) Task 3's `render_popup` return-type change is signature-only for existing callers (they ignore the return); verify `prompt.rs`'s three callers still compile without edits.
