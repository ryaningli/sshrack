# TUI UX Refinements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply five agreed TUI refinements — auto-default store mode to keyring, drop Ctrl-1/2/3, fix/center the empty-state placeholder, relocate status to the panel bottom (footer stays hotkey-only), and give the search row a boxed input with a `matched/total` count.

**Architecture:** All changes are inside the `sshrack` binary's `src/tui/` front end — the pure core crate is untouched. The status surface moves out of the shell's band 3 into a one-line footer at the bottom of each panel's own area; the shell footer becomes hotkey-hints-only. Two new shared render helpers live in a new `src/tui/parts.rs` (search box, status row, vertical centering) so the Hosts and Credentials panels stay DRY. The store-mode auto-default is a one-line pure decision fed by the existing `OsKeyring::available()` probe, applied once in `tui::run` after the config loads.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, sshrack-core (pure, untouched).

## Global Constraints

Copied verbatim from `CLAUDE.md` hard rules — every task implicitly inherits these:

- **English only** — all source, comments, doc comments, errors, help text, logs, commits.
- **Zero `unsafe`** — never, including tests.
- **Zero `unwrap()`/`expect()`** in production code — only `#[cfg(test)]` or `expect("invariant: …")` for genuinely unreachable states.
- **TDD for pure logic** — RED → GREEN → REFACTOR. Pure decisions get a failing test first.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Tests are hermetic** — `cargo test --bin sshrack` green in a real shell with `SSHRACK_PASSPHRASE` set; no `env -u` fallback, no real env mutation (Rust 2024 `set_var` is unsafe — inject values via parameters).
- **`sshrack-core` zero-UI invariant** — its `Cargo.toml` never lists `ratatui`/`crossterm`/`nucleo-matcher`/`console`. This plan adds NO core changes.
- **Dev stage, no compat code** (the user's "不做兼容" requirement) — when a binding/variant/import/comment is removed, remove it fully: no dead `TabKey::To` variant, no stale "single status surface" comment, no orphaned imports. Refactor thoroughly. `cargo clippy --all-targets -- -D warnings` is the enforcer.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits). Each task ends with a commit.

**Rendering convention for this plan:** ratatui 0.30. `Block::borders(Borders::ALL)` with `.padding(Padding::horizontal(1))` gives a boxed input whose `block.inner(area)` is already inset by border + padding, so cursor math is anchored on `inner`. The test backend is `ratatui::backend::TestBackend`.

---

## File Structure (target, after all tasks)

```
src/tui/
├── mod.rs           # +auto_default_store_mode() pure fn, wired into run(); +#[cfg(test)] tests
├── tab.rs           # Ctrl-1/2/3 arms removed; TabKey::To variant removed; docs cleaned
├── intent.rs        # doc comment: drop "Ctrl-1/2/3" mention (Status type unchanged)
├── app.rs           # draw() passes &status to panels (not shell); on_key clears stale status;
│                    #   route_panel: drop TabKey::To arm + Ctrl-1/2/3 doc mentions
├── shell.rs         # draw_shell: drop status param; band 3 always hotkey hints
├── parts.rs         # NEW: draw_search_box, draw_status_row, vertical_center, count_label (shared panel parts)
├── launcher.rs      # draw_in_shell: boxed search + status row + &status param; draw_list: centered empty state, stale copy fixed
├── cred_panel.rs    # mirror of launcher changes
├── settings.rs      # draw_in_shell: +status row + &status param
└── help.rs          # drop "Ctrl-1 / 2 / 3" binding + its test
```

`panel.rs` (pure ranking) is **unchanged** — render helpers go in the new `parts.rs` so the pure-data module stays pure and testable.

---

## Task 1: Auto-default store mode to keyring on TUI startup

When a freshly-loaded config has no store mode and the OS keyring is available, adopt `Keyring` silently so a desktop user never sees the undecided state. When the keyring is absent (headless / no D-Bus), leave it undecided — the existing first-password-save prompt (`persist::recover_store_mode_and_retry_cred_save`) already handles that case.

**Files:**
- Modify: `src/tui/mod.rs`

**Interfaces:**
- Consumes: `sshrack_core::config::schema::SecretStore`, `sshrack_core::secret::{OsKeyring, SecretBackend}` (`.available()`), `sshrack_core::config::store::save`, the already-loaded `cfg: SshrackConfig` and `config_path: Option<PathBuf>` in `run()`.
- Produces: private `fn auto_default_store_mode(undecided: bool, keyring_available: bool) -> Option<SecretStore>` (pure, unit-tested).

- [ ] **Step 1: Add the imports**

At the top of `src/tui/mod.rs`, extend the `use sshrack_core::…` block. The file already has `use sshrack_core::config::store as config_store;` and `use sshrack_core::config::path as config_path;`. Add:

```rust
use sshrack_core::config::schema::SecretStore;
use sshrack_core::secret::{OsKeyring, SecretBackend};
```

- [ ] **Step 2: Write the failing test**

Append a test module at the end of `src/tui/mod.rs` (the file has no `#[cfg(test)]` module yet):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::config::schema::SecretStore;

    #[test]
    fn auto_default_picks_keyring_when_undecided_and_available() {
        assert_eq!(
            auto_default_store_mode(true, true),
            Some(SecretStore::Keyring)
        );
    }

    #[test]
    fn auto_default_never_overrides_a_decided_config() {
        // A user who explicitly chose plaintext or vault must not be silently
        // flipped to keyring on the next launch.
        assert_eq!(auto_default_store_mode(false, true), None);
    }

    #[test]
    fn auto_default_none_when_keyring_absent() {
        // Headless / no D-Bus: stay undecided so the first password save
        // triggers the existing store-pick prompt.
        assert_eq!(auto_default_store_mode(true, false), None);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --bin sshrack tui::tests::auto_default`
Expected: FAIL — `cannot find function auto_default_store_mode`.

- [ ] **Step 4: Implement the pure decision function**

Add immediately above the `pub fn run(` definition in `src/tui/mod.rs`:

```rust
/// The default store mode to apply when a freshly-loaded config has not chosen
/// one yet (`store` is `None`). Returns `Keyring` when the OS keyring is
/// available, so a desktop user lands in the safest mode with zero prompts;
/// returns `None` when the keyring is absent (headless / no D-Bus), leaving the
/// config undecided so the existing first-password-save prompt handles it.
///
/// Pure: the caller performs the keyring probe and passes the boolean.
fn auto_default_store_mode(undecided: bool, keyring_available: bool) -> Option<SecretStore> {
    (undecided && keyring_available).then_some(SecretStore::Keyring)
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --bin sshrack tui::tests::auto_default`
Expected: PASS — 3 tests.

- [ ] **Step 6: Wire it into `run()`**

In `pub fn run()` in `src/tui/mod.rs`, the config currently loads as an immutable binding:

```rust
    let cfg = config_path
        .as_ref()
        .map(|p| config_store::load(p))
        .transpose()?
        .unwrap_or_default();
```

Change `let cfg` to `let mut cfg`, then insert this block immediately after it (before `let data_dir = …`):

```rust
    // Auto-default the store mode: if the loaded config is undecided and the
    // OS keyring is available, adopt keyring silently so a desktop user never
    // sees the store-undecided state. When the keyring is absent the config
    // stays undecided and the first password save will prompt (existing path).
    // Best-effort persist: a write failure is non-fatal — the in-memory mode
    // is correct for this session and the next credential/host save rewrites
    // the whole config anyway.
    if let Some(mode) = auto_default_store_mode(cfg.store.is_none(), OsKeyring.available()) {
        cfg.store = Some(mode);
        if let Some(p) = config_path.as_ref() {
            let _ = config_store::save(p, &cfg);
        }
    }
```

- [ ] **Step 7: Build + clippy + fmt**

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```
Expected: green. (`OsKeyring` is a unit struct; `OsKeyring.available()` resolves because `SecretBackend` is in scope.)

- [ ] **Step 8: Commit**

```bash
git add src/tui/mod.rs
git commit -m "feat(tui): auto-default store mode to keyring on startup when available"
```

---

## Task 2: Drop Ctrl-1/2/3 tab-jump bindings

Remove the `Ctrl-1/2/3` direct tab-jump entirely. Only `Tab` / `Shift-Tab` cycling remains. The `TabKey::To` variant is dead after this, so it goes too (dev stage, no dead code).

**Files:**
- Modify: `src/tui/tab.rs`
- Modify: `src/tui/app.rs` (drop the `TabKey::To` consume arm + doc mentions)
- Modify: `src/tui/help.rs` (drop the binding + its test)
- Modify: `src/tui/intent.rs` (doc-comment mention only)
- Modify: `CLAUDE.md` (TUI keys table)

**Interfaces:**
- Produces: `TabKey` enum reduced to `{ Cycle(i32), None }`; `tab_key_decision` returns only those two.

- [ ] **Step 1: Remove the three Ctrl-digit arms + the now-unused `ctrl` binding in `tab_key_decision`**

In `src/tui/tab.rs`, the function currently is:

```rust
pub fn tab_key_decision(key: KeyEvent) -> TabKey {
    if key.kind != KeyEventKind::Press {
        return TabKey::None;
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Tab if key.modifiers == KeyModifiers::NONE => TabKey::Cycle(1),
        KeyCode::BackTab => TabKey::Cycle(-1),
        KeyCode::Char('1') if ctrl => TabKey::To(Tab::Hosts),
        KeyCode::Char('2') if ctrl => TabKey::To(Tab::Credentials),
        KeyCode::Char('3') if ctrl => TabKey::To(Tab::Settings),
        _ => TabKey::None,
    }
}
```

Replace it with (the `let ctrl` line is gone because nothing else uses it; `KeyModifiers` stays in scope via the `KeyModifiers::NONE` check):

```rust
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
```

- [ ] **Step 2: Remove the `TabKey::To` variant**

In `src/tui/tab.rs`, the enum currently is:

```rust
pub enum TabKey {
    /// Jump directly to a tab (`Ctrl-1/2/3`).
    To(Tab),
    /// Cycle by `delta` (`Tab` = +1, `BackTab` = -1).
    Cycle(i32),
    /// Not a tab key — let the panel handle it (printable chars land here).
    None,
}
```

Replace with:

```rust
pub enum TabKey {
    /// Cycle by `delta` (`Tab` = +1, `BackTab` = -1).
    Cycle(i32),
    /// Not a tab key — let the panel handle it (printable chars land here).
    None,
}
```

- [ ] **Step 3: Update the `tab.rs` module + function doc comments**

In `src/tui/tab.rs`:
- Top-of-file `//!` block: change `ONLY `Tab` / `Shift-Tab` / `Ctrl-1/2/3` switch tabs.` → `ONLY `Tab` / `Shift-Tab` switch tabs.` (two occurrences in the `//!` block and the `tab_key_decision` doc — update every mention of `Ctrl-1/2/3` in this file's prose).
- The `tab_key_decision` doc comment: `Only `Tab`, `Shift-Tab` (`BackTab`), and `Ctrl-1/2/3` switch tabs;` → `Only `Tab` and `Shift-Tab` (`BackTab`) switch tabs;`.

- [ ] **Step 4: Drop the `TabKey::To` consume arm in `route_panel`**

In `src/tui/app.rs`, `route_panel` (around line 587–610) currently matches:

```rust
        // Tab switching first (Tab / BackTab / Ctrl-1/2/3).
        match tab_key_decision(key) {
            TabKey::To(t) => {
                self.active_tab = t;
                return Outcome::SwitchTab(t);
            }
            TabKey::Cycle(d) => {
                let new = if d > 0 {
                    self.active_tab.next()
                } else {
                    self.active_tab.prev()
                };
                self.active_tab = new;
                return Outcome::SwitchTab(new);
            }
            TabKey::None => {}
        }
```

Replace with:

```rust
        // Tab switching first (Tab / BackTab).
        match tab_key_decision(key) {
            TabKey::Cycle(d) => {
                let new = if d > 0 {
                    self.active_tab.next()
                } else {
                    self.active_tab.prev()
                };
                self.active_tab = new;
                return Outcome::SwitchTab(new);
            }
            TabKey::None => {}
        }
```

Also update the two `route_panel` doc lines above it that say `Tab`/`Ctrl-1/2/3` (around lines 585–586, 594): drop the `Ctrl-1/2/3` mention in each.

- [ ] **Step 5: Update the `Outcome::SwitchTab` doc in `intent.rs`**

In `src/tui/intent.rs`, the `SwitchTab(Tab)` variant doc says `switch the active tab (Tab / Shift-Tab / Ctrl-1/2/3).`. Change to `switch the active tab (Tab / Shift-Tab).`. Also update the `App::active_tab` field doc in `src/tui/app.rs` (around line 59) that says `Switched by Tab / Shift-Tab / Ctrl-1/2/3.` → `Switched by Tab / Shift-Tab.`.

- [ ] **Step 6: Remove the `Ctrl-1/2/3` test + adjust the "every surface" test in `tab.rs`**

In `src/tui/tab.rs`, **delete** the whole `ctrl_digits_jump_to_tabs` test (the one asserting `TabKey::To(Tab::Hosts)` etc.). Keep `bare_digits_and_chars_do_not_switch_tabs` (it still verifies bare `1/2/3` reach the query — that invariant is unchanged and now more important).

- [ ] **Step 7: Drop the binding + its test in `help.rs`**

In `src/tui/help.rs`:
- In `help_lines()`, **delete** the line:

```rust
        binding("Ctrl-1 / 2 / 3", "jump to Hosts / Credentials / Settings"),
```

- In the test `help_lines_cover_every_surface_and_dismiss_hint`, **delete** the assertion:

```rust
        assert!(joined.contains("jump to Hosts"), "ctrl-digit jump");
```

- **Delete** the entire `help_lines_document_ctrl_digit_tab_jumps` test.

- [ ] **Step 8: Update `CLAUDE.md` TUI keys table**

In `CLAUDE.md`, under "### TUI keys", delete the table row:

```
| `Ctrl-1` / `2` / `3` | jump to Hosts / Credentials / Settings |
```

- [ ] **Step 9: Build + test + clippy + fmt**

```bash
cargo build --workspace
cargo test --bin sshrack
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```
Expected: green. The baseline bin test count drops by the deleted tests (and stays green). No `TabKey::To` reference survives — `rg -n 'TabKey::To|Ctrl-1|Ctrl-2|Ctrl-3|Ctrl-1 / 2 / 3' src/ CLAUDE.md` returns no hits.

- [ ] **Step 10: Commit**

```bash
git add src/tui/tab.rs src/tui/app.rs src/tui/help.rs src/tui/intent.rs CLAUDE.md
git commit -m "refactor(tui): drop Ctrl-1/2/3 tab-jump bindings"
```

---

## Task 3: Fix the empty-state copy and center it on both axes

The Hosts empty state still says "(not yet implemented)" — stale, since `^a` opens the wizard. Drop that suffix. Both panels' empty state is currently horizontal-center-only, pinned to the top row of the list area; center it vertically too.

**Files:**
- Create: `src/tui/parts.rs` (just the `vertical_center` helper for now; Tasks 4–5 add more)
- Modify: `src/tui/mod.rs` (register the module)
- Modify: `src/tui/launcher.rs`
- Modify: `src/tui/cred_panel.rs`

**Interfaces:**
- Produces: `parts::vertical_center(area: Rect, h: u16) -> Rect` (pure).

- [ ] **Step 1: Create `src/tui/parts.rs` with `vertical_center`**

```rust
//! Shared render parts for the Hosts / Credentials panels: a vertical-center
//! helper (this task), plus the status row and boxed search input added later.
//! Pure layout/render — no I/O, no state. Kept separate from `panel.rs` (which
//! stays pure ranking data) so the data module is not pulled into rendering.

use ratatui::layout::Rect;

/// A sub-rect of `area` with height `h`, vertically centered (horizontal span
/// unchanged). Used to place the empty-state line in the middle of the list
/// area instead of pinned to the top row.
pub fn vertical_center(area: Rect, h: u16) -> Rect {
    Rect {
        y: area.y + area.height.saturating_sub(h) / 2,
        height: h,
        ..area
    }
}
```

- [ ] **Step 2: Register the module**

In `src/tui/mod.rs`, add `pub mod parts;` in alphabetical order (between `panel` and `persist`).

- [ ] **Step 3: Center the Hosts empty state + fix the stale copy**

In `src/tui/launcher.rs`, `draw_list`'s empty branch currently is:

```rust
        if self.ranked.is_empty() {
            let msg = if hosts.is_empty() {
                "No hosts configured. Press ^a to add one (not yet implemented)."
            } else {
                "No hosts match your query."
            };
            frame.render_widget(
                Paragraph::new(msg)
                    .style(Style::new().dim())
                    .alignment(Alignment::Center),
                area,
            );
            return;
        }
```

Replace with (the message renders into a vertically centered 1-row sub-rect, so it is centered on both axes; `Alignment::Center` still handles the horizontal axis):

```rust
        if self.ranked.is_empty() {
            let msg = if hosts.is_empty() {
                "No hosts configured. Press ^a to add one."
            } else {
                "No hosts match your query."
            };
            frame.render_widget(
                Paragraph::new(msg)
                    .style(Style::new().dim())
                    .alignment(Alignment::Center),
                super::parts::vertical_center(area, 1),
            );
            return;
        }
```

- [ ] **Step 4: Center the Credentials empty state**

In `src/tui/cred_panel.rs`, `draw_list`'s empty branch currently renders into `area`. Replace the `area` argument with `super::parts::vertical_center(area, 1)`:

```rust
        if self.ranked.is_empty() {
            let msg = if creds.is_empty() {
                "No credentials configured. Press ^a to add one."
            } else {
                "No credentials match your query."
            };
            frame.render_widget(
                Paragraph::new(msg)
                    .style(Style::new().dim())
                    .alignment(Alignment::Center),
                super::parts::vertical_center(area, 1),
            );
            return;
        }
```

(The credential copy was already clean — only the vertical centering changes here.)

- [ ] **Step 5: Build + clippy + fmt**

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```
Expected: green.

- [ ] **Step 6: Commit**

```bash
git add src/tui/parts.rs src/tui/mod.rs src/tui/launcher.rs src/tui/cred_panel.rs
git commit -m "fix(tui): drop stale empty-state copy, center placeholder on both axes"
```

---

## Task 4: Relocate status to the panel bottom; footer stays hotkey-only; auto-clear on next panel key

Today the shell's band 3 shows status OR hotkey hints (mutually exclusive). Invert that: band 3 is **always** hotkey hints; the status moves to a one-line footer at the bottom of each panel's own area. Stale status auto-clears on the next panel-level keypress.

**Files:**
- Create: nothing (adds `draw_status_row` to the existing `src/tui/parts.rs`)
- Modify: `src/tui/shell.rs`
- Modify: `src/tui/launcher.rs`, `src/tui/cred_panel.rs`, `src/tui/settings.rs`
- Modify: `src/tui/app.rs`
- Modify: `src/tui/mod.rs` (none expected — `Status` is already re-exported)

**Interfaces:**
- Produces: `parts::draw_status_row(frame, area, &Status)`; each panel's `draw_in_shell` gains a trailing `status: &Status` parameter and a bottom status row; `draw_shell` drops its `status` parameter.

- [ ] **Step 1: Add `draw_status_row` to `parts.rs`**

Extend `src/tui/parts.rs`: **merge Task 3's standalone `use ratatui::layout::Rect;` into a single ratatui use-block** (delete the old lone import line) and add the new names. The merged import is (note `layout::Rect` stays — `vertical_center` still uses it):

```rust
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::intent::Status;
use super::theme;

/// Render the consolidated status as the bottom row of a panel's area: a dim
/// `› ` prefix + the message (red on [`Status::is_error`]). A `Status::empty`
/// renders just the dim prefix so the row's height stays stable. This replaces
/// the old shell-footer status branch — the shell footer is now hotkey-only.
pub fn draw_status_row(frame: &mut Frame, area: Rect, status: &Status) {
    let line = match &status.message {
        Some(msg) => {
            let style = if status.is_error {
                Style::new().fg(theme::DANGER)
            } else {
                Style::new()
            };
            Line::from(vec![
                Span::styled("› ", Style::new().dim()),
                Span::styled(msg.clone(), style),
            ])
        }
        None => Line::from(vec![Span::styled("› ", Style::new().dim())]),
    };
    frame.render_widget(Paragraph::new(line), area);
}
```

(`theme::DANGER` already exists — `shell.rs` uses it today.)

- [ ] **Step 2: `draw_shell` — drop the `status` parameter, always render hints**

In `src/tui/shell.rs`:

Change the signature and band-3 block. The signature becomes:

```rust
pub fn draw_shell(
    frame: &mut Frame,
    area: Rect,
    active: Tab,
    footer: &[(&str, &str)],
) -> Rect {
```

Replace the entire "Band 3" block (the `let line = if let Some(msg) …` through `frame.render_widget(Paragraph::new(line), bottom);`) with:

```rust
    // ── Band 3: hotkey hints (always). Status lives in each panel now. ──────
    let mut spans: Vec<Span> = Vec::new();
    for (i, (k, label)) in footer.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::new().dim()));
        }
        spans.push(Span::styled(*k, theme::accent().add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {label}"), Style::new().dim()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), bottom);
```

Update the `draw_shell` doc comment: it currently describes the "status message when `Some`, else hints" behavior — rewrite that sentence to "and the hotkey footer on the bottom (always hints — status renders at the bottom of each panel's own area)".

Remove the now-unused import: delete `use crate::tui::Status;` (line 19). Keep `use crate::tui::{tab, tab::Tab, theme};`.

- [ ] **Step 3: Rewrite the `shell.rs` tests for the hints-only footer**

In `src/tui/shell.rs` `#[cfg(test)]`:

- In `draw_shell_returns_inner_panel_area_and_never_panics`, `draw_shell_clamps_on_tiny_terminal`, and `draw_shell_borders_middle_and_drops_f1_help`: remove every `let status = Status::empty();` line and drop the `&status` argument from each `draw_shell(…)` call (the call now ends at `&[...]`).
- Replace the whole `draw_shell_footer_shows_hints_when_empty_and_message_when_set` test with this hints-only version:

```rust
    /// Band 3 is now hotkey-hints-only: the status no longer feeds the shell,
    /// so the hints always render regardless of any panel status. (Status
    /// rendering is covered by the panel tests + `parts::draw_status_row`.)
    #[test]
    fn draw_shell_footer_always_shows_hints() {
        let backend = TestBackend::new(80, 12);
        let mut term = Terminal::new(backend).unwrap();
        let hints = [("Enter", "connect"), ("F1", "help")];
        term.draw(|f| {
            let _ = draw_shell(f, f.area(), Tab::Hosts, &hints);
        })
        .unwrap();
        let bottom_row: String = (0..term.backend().buffer().area.width)
            .map(|col| {
                term.backend()
                    .buffer()
                    .cell((col, term.backend().buffer().area.height - 1))
                    .map(|c| c.symbol().to_string())
                    .unwrap_or_else(|| " ".to_string())
            })
            .collect();
        let bottom_trim = bottom_row.trim().to_string();
        assert!(
            bottom_trim.contains("Enter") && bottom_trim.contains("connect"),
            "footer must always show the hotkey hints, got: {bottom_trim:?}"
        );
    }
```

- [ ] **Step 4: Launcher — add `status` param + a bottom status row**

In `src/tui/launcher.rs`:

Add `Status` to the intent import (currently `use super::intent::Outcome;`) and add the parts import:

```rust
use super::intent::{Outcome, Status};
use super::parts;
```

Change `draw_in_shell`'s layout from two bands to three and add the `status` parameter. The current body:

```rust
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        hosts: &[Host],
        frecency: &Frecency,
        credentials: &[Credential],
    ) {
        let [search_area, list_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);

        // Search row: `❯ <query>` with the real terminal cursor placed right
        // after the query (no fake cursor glyph — the cursor is the terminal's).
        let search_line = Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(&self.query),
        ]);
        frame.render_widget(Paragraph::new(search_line), search_area);
        // Place the terminal cursor right after the query (2-cell `❯ ` prefix).
        let cursor_x = search_area.x + 2 + self.query.chars().count() as u16;
        let max_x = search_area.x + search_area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), search_area.y));

        self.draw_list(frame, list_area, hosts, frecency, credentials);
    }
```

becomes (Task 5 will replace the inline search row with a boxed input; for now it stays a single row so this task is independently shippable):

```rust
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        hosts: &[Host],
        frecency: &Frecency,
        credentials: &[Credential],
        status: &Status,
    ) {
        let [search_area, list_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        // Search row: `❯ <query>` with the real terminal cursor placed right
        // after the query (no fake cursor glyph — the cursor is the terminal's).
        // (Task 5 replaces this inline row with a boxed input.)
        let search_line = Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(&self.query),
        ]);
        frame.render_widget(Paragraph::new(search_line), search_area);
        let cursor_x = search_area.x + 2 + self.query.chars().count() as u16;
        let max_x = search_area.x + search_area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), search_area.y));

        self.draw_list(frame, list_area, hosts, frecency, credentials);
        parts::draw_status_row(frame, status_area, status);
    }
```

Also delete the stale `// NOTE: the launcher no longer carries a status row…` comment block above `RankedHost` (around lines 36–43) — it describes the old "shell footer is the single status surface" design that this task inverts.

- [ ] **Step 5: Credentials panel — mirror the launcher change**

In `src/tui/cred_panel.rs`:

Add imports:

```rust
use super::intent::{Outcome, Status};
use super::parts;
```

(Replace the existing `use super::intent::Outcome;`.)

In `draw_in_shell`, add `status: &Status` as the trailing parameter, change the layout to three bands, and add the status row. The current body:

```rust
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        creds: &[Credential],
    ) {
        let [search_area, list_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);

        let search_line = Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(&self.query),
        ]);
        frame.render_widget(Paragraph::new(search_line), search_area);
        let cursor_x = search_area.x + 2 + self.query.chars().count() as u16;
        let max_x = search_area.x + search_area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), search_area.y));

        self.draw_list(frame, list_area, creds);
    }
```

becomes:

```rust
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        creds: &[Credential],
        status: &Status,
    ) {
        let [search_area, list_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        let search_line = Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(&self.query),
        ]);
        frame.render_widget(Paragraph::new(search_line), search_area);
        let cursor_x = search_area.x + 2 + self.query.chars().count() as u16;
        let max_x = search_area.x + search_area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), search_area.y));

        self.draw_list(frame, list_area, creds);
        parts::draw_status_row(frame, status_area, status);
    }
```

- [ ] **Step 6: Settings panel — add `status` param + bottom status row**

In `src/tui/settings.rs`:

Change the import `use super::Outcome;` → `use super::{Outcome, Status};` and add `use super::parts;`.

`draw_in_shell` currently:

```rust
    pub fn draw_in_shell(&self, frame: &mut Frame, area: Rect, current_mode: &str) {
        // No search row for Settings: a 2-row band for the single entry and a
        // fill spacer. The status footer lives in the shell (band 3).
        let [row_area, _] =
            Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).areas(area);

        let value_span = if current_mode == "undecided" {
            Span::styled(format!("{current_mode} ▸"), Style::new().fg(theme::DANGER))
        } else {
            Span::styled(
                format!("{current_mode} ▸"),
                theme::accent().add_modifier(Modifier::BOLD),
            )
        };
        let row = Line::from(vec![
            theme::focus_marker(true),
            Span::raw(" Storage mode"),
            Span::raw("    "),
            value_span,
        ]);
        frame.render_widget(Paragraph::new(row), row_area);
    }
```

becomes:

```rust
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: Rect,
        current_mode: &str,
        status: &Status,
    ) {
        // No search row for Settings: a 2-row band for the single entry, a fill
        // spacer, and the status row at the bottom (shared with the other
        // panels). The shell footer is hotkey-only.
        let [row_area, _, status_area] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        let value_span = if current_mode == "undecided" {
            Span::styled(format!("{current_mode} ▸"), Style::new().fg(theme::DANGER))
        } else {
            Span::styled(
                format!("{current_mode} ▸"),
                theme::accent().add_modifier(Modifier::BOLD),
            )
        };
        let row = Line::from(vec![
            theme::focus_marker(true),
            Span::raw(" Storage mode"),
            Span::raw("    "),
            value_span,
        ]);
        frame.render_widget(Paragraph::new(row), row_area);
        parts::draw_status_row(frame, status_area, status);
    }
```

Also update the `draw_in_shell` doc comment that says "no per-panel status row (the shell footer is the single status surface)" — rewrite to "the status row at the bottom is shared with the other panels via `parts::draw_status_row`."

- [ ] **Step 7: `app.rs` — pass status to panels, not the shell; auto-clear on next panel key**

In `src/tui/app.rs`:

`App::draw` currently:

```rust
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        let footer = self.footer_hints();
        let panel_area = draw_shell(frame, area, self.active_tab, &footer, &self.status);
        match self.active_tab {
            Tab::Hosts => self.launcher.draw_in_shell(
                frame,
                panel_area,
                &self.config.hosts,
                &self.frecency,
                &self.config.credentials,
            ),
            Tab::Credentials => {
                self.cred_panel
                    .draw_in_shell(frame, panel_area, &self.config.credentials)
            }
            Tab::Settings => self.settings_panel.draw_in_shell(
                frame,
                panel_area,
                self.current_store_mode_label(),
            ),
        }
        if let Some(ov) = &self.overlay {
            self.draw_overlay(frame, ov);
        }
    }
```

becomes (status now goes to each panel; `draw_shell` takes no status):

```rust
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        let footer = self.footer_hints();
        let panel_area = draw_shell(frame, area, self.active_tab, &footer);
        match self.active_tab {
            Tab::Hosts => self.launcher.draw_in_shell(
                frame,
                panel_area,
                &self.config.hosts,
                &self.frecency,
                &self.config.credentials,
                &self.status,
            ),
            Tab::Credentials => self.cred_panel.draw_in_shell(
                frame,
                panel_area,
                &self.config.credentials,
                &self.status,
            ),
            Tab::Settings => self.settings_panel.draw_in_shell(
                frame,
                panel_area,
                self.current_store_mode_label(),
                &self.status,
            ),
        }
        if let Some(ov) = &self.overlay {
            self.draw_overlay(frame, ov);
        }
    }
```

Then, in `App::on_key`, add the auto-clear at the **Layer 3** entry (panel/tab layer only — overlay and global keys do not clear it). The current tail of `on_key`:

```rust
        // Layer 3 — panel/tab layer (no overlay).
        self.route_panel(key)
    }
```

becomes:

```rust
        // Layer 3 — panel/tab layer (no overlay).
        // Auto-clear stale panel status on the next panel key: the status is a
        // transient per-action hint, not a persistent banner. A new status set
        // during this keypress (e.g. an error) replaces the clear below.
        self.status = Status::empty();
        self.route_panel(key)
    }
```

(`Status` is already imported in `app.rs`.)

- [ ] **Step 8: Build + test + clippy + fmt**

```bash
cargo build --workspace
cargo test --bin sshrack
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```

**Audit the status tests.** The auto-clear changes one assumption: a status set by keypress *N* no longer survives keypress *N+1* in the panel layer. Run the suite; any failing assertion is a test that pressed a second panel key and still expected the earlier status. Fix each by asserting the status **immediately after the keypress that sets it** (before any further `press(…)`), since that is the new correct contract. (The common single-press-then-assert pattern is unaffected — the clear happens on the *next* `on_key`, not the one that sets the status. Note: statuses set by the *loop* after `on_key` returns — e.g. a save — are observed on the next render and cleared on the next panel keypress, matching the user's "下次按键后自动清空" choice.)

Expected: green after the audit.

- [ ] **Step 9: Commit**

```bash
git add src/tui/parts.rs src/tui/shell.rs src/tui/launcher.rs src/tui/cred_panel.rs src/tui/settings.rs src/tui/app.rs
git commit -m "refactor(tui): move status to panel bottom, keep footer hints, auto-clear on next key"
```

---

## Task 5: Boxed search input with a `matched/total` count

Wrap the search row in a bordered box; right-align a `matched/total` count inside it (always shown — `50/50` when unfiltered, `12/50` when filtered). The list renders below the box. Shared by both panels via `parts::draw_search_box`.

**Files:**
- Modify: `src/tui/parts.rs` (add `count_label` + `draw_search_box`)
- Modify: `src/tui/launcher.rs`, `src/tui/cred_panel.rs`

**Interfaces:**
- Produces: `parts::count_label(matched: usize, total: usize) -> String` (pure, tested); `parts::draw_search_box(frame, area, query, matched, total)`.

- [ ] **Step 1: Write the failing test for `count_label`**

In `src/tui/parts.rs`, add a `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_label_is_matched_slash_total_always() {
        assert_eq!(count_label(12, 50), "12/50");
        // Unfiltered: matched == total, still the same form.
        assert_eq!(count_label(50, 50), "50/50");
        // A query that matches nothing still shows 0 over the total.
        assert_eq!(count_label(0, 3), "0/3");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --bin sshrack parts::tests::count_label`
Expected: FAIL — `cannot find function count_label`.

- [ ] **Step 3: Implement `count_label` + `draw_search_box`**

Extend the `ratatui` import in `src/tui/parts.rs` (the file currently imports `layout::Rect`, `Frame`, `style::Style`, `text::{Line, Span}`, `widgets::Paragraph`):

```rust
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Padding, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
```

Add the two functions (after `vertical_center`):

```rust
/// `matched/total` — always this form, even when unfiltered (then
/// `matched == total`, e.g. `50/50`). Extracted so the count format is pure and
/// unit-testable independent of rendering.
pub fn count_label(matched: usize, total: usize) -> String {
    format!("{matched}/{total}")
}

/// Render the search input as a bordered box: `❯ <query>` on the left, the
/// [`count_label`] right-aligned, both inside a 3-row bordered band (top border,
/// one content row, bottom border). The terminal cursor is placed right after
/// the query. `matched` is the filtered (post-query) list length, `total` the
/// full list length. Callers give this a `Length(3)` band.
pub fn draw_search_box(frame: &mut Frame, area: Rect, query: &str, matched: usize, total: usize) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().dim())
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let label = count_label(matched, total);
    let label_w = label.chars().count() as u16;
    let [prompt_area, count_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(label_w)]).areas(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(query),
        ])),
        prompt_area,
    );
    frame.render_widget(
        Paragraph::new(label)
            .alignment(Alignment::Right)
            .style(Style::new().dim()),
        count_area,
    );

    // The terminal cursor sits right after the 2-cell `❯ ` prefix, inside the
    // box's content row. `inner` is already inset by border + padding.
    let cursor_x = inner.x + 2 + query.chars().count() as u16;
    let max_x = inner.x + inner.width.saturating_sub(1);
    frame.set_cursor_position((cursor_x.min(max_x), inner.y));
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --bin sshrack parts::tests::count_label`
Expected: PASS.

- [ ] **Step 5: Launcher — swap the inline search row for the boxed input**

In `src/tui/launcher.rs` `draw_in_shell`, replace the search band's height and the inline search-render block. The Task-4 version:

```rust
        let [search_area, list_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        // Search row: `❯ <query>` with the real terminal cursor placed right
        // after the query (no fake cursor glyph — the cursor is the terminal's).
        // (Task 5 replaces this inline row with a boxed input.)
        let search_line = Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(&self.query),
        ]);
        frame.render_widget(Paragraph::new(search_line), search_area);
        let cursor_x = search_area.x + 2 + self.query.chars().count() as u16;
        let max_x = search_area.x + search_area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), search_area.y));

        self.draw_list(frame, list_area, hosts, frecency, credentials);
        parts::draw_status_row(frame, status_area, status);
```

becomes:

```rust
        let [search_band, list_area, status_area] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        parts::draw_search_box(
            frame,
            search_band,
            &self.query,
            self.ranked.len(),
            hosts.len(),
        );

        self.draw_list(frame, list_area, hosts, frecency, credentials);
        parts::draw_status_row(frame, status_area, status);
```

Update the `draw_in_shell` doc comment to describe the `[boxed search (3), list (fill), status (1)]` split and the right-aligned count.

- [ ] **Step 6: Credentials panel — mirror the launcher change**

In `src/tui/cred_panel.rs` `draw_in_shell`, apply the same swap. The Task-4 version's body becomes:

```rust
        let [search_band, list_area, status_area] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        parts::draw_search_box(
            frame,
            search_band,
            &self.query,
            self.ranked.len(),
            creds.len(),
        );

        self.draw_list(frame, list_area, creds);
        parts::draw_status_row(frame, status_area, status);
```

Update the `draw_in_shell` doc comment to mention the boxed search + count (mirroring the launcher wording).

- [ ] **Step 7: Build + test + clippy + fmt**

```bash
cargo build --workspace
cargo test --bin sshrack
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```
Expected: green. (If `Span`/`Paragraph`/`Style` become unused imports in `launcher.rs` or `cred_panel.rs` after the search row moves to `parts`, clippy will flag them — remove any now-unused names. `Line`/`Span` remain used by `draw_list`; verify before removing.)

- [ ] **Step 8: Commit**

```bash
git add src/tui/parts.rs src/tui/launcher.rs src/tui/cred_panel.rs
git commit -m "feat(tui): boxed search input with matched/total count"
```

---

## Task 6: Docs + final full gate

Sync `CLAUDE.md` to the new shell/panel/keymap reality and run the whole gate.

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update `CLAUDE.md` shell + panel prose**

In `CLAUDE.md`:

- In the **"TUI (delivered)"** section's three-band description: the bottom band is now "hotkey hints (always)" and the status renders "at the bottom of each panel's own area". Rewrite the bullet that currently says band 3 is the status/hotkey surface to reflect: *top band = brand + tab bar; middle band = active panel (which itself ends in a one-line status row); bottom band = hotkey hints, always.*
- In the **"Event routing"** bullet, no change is needed unless it names band 3 as the status surface — if it does, align it with the above.
- Add a one-line note under **"Storage & Security"** (or the first-use paragraph): *"On TUI startup, if no store mode is chosen and the OS keyring is available, sshrack adopts keyring silently; otherwise the mode stays undecided and the first password save prompts."*
- Confirm the TUI keys table no longer lists `Ctrl-1/2/3` (Task 2 removed it).

- [ ] **Step 2: Final full gate**

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green; `cargo test --bin sshrack` green (the baseline count shifts by the net of deleted/added tests across Tasks 2–5 and stays green).

- [ ] **Step 3: Sanity-grep for removed concepts**

```bash
rg -n 'Ctrl-1|Ctrl-2|Ctrl-3|TabKey::To|not yet implemented|single status surface' src/ CLAUDE.md
```
Expected: no hits (the dev-stage rule — no stale references to removed bindings/variants/copy).

- [ ] **Step 4: Manual end-to-end smoke (user runs this)**

These render paths are not covered by unit tests:

```bash
SSHRACK_PASSPHRASE=… cargo run -q --          # launcher: boxed search + count + centered empty state
cargo run -q -- host add                       # host wizard (add flow)
cargo run -q -- cred add                       # cred wizard
cargo run -q -- host ls                        # CLI still non-interactive
# With no config file: confirm a fresh launch shows store mode = keyring (if a
# keyring daemon is available) in the Settings tab, with no prompt.
```

- [ ] **Step 5: Commit + branch finish**

```bash
git add CLAUDE.md
git commit -m "docs(tui): update keymap and shell/panel layout for ux refinements"
```
Then use the `superpowers:finishing-a-development-branch` skill to merge/PR.

---

## Self-Review (completed by planner)

**1. Spec coverage** — all five user items mapped:
- Storage auto-default keyring → **Task 1**.
- Drop Ctrl-1/2/3 → **Task 2** (bindings, `TabKey::To`, help, CLAUDE.md, tests).
- Empty-state copy + centering → **Task 3** (both panels, both axes).
- Footer always hotkey / status to panel bottom / auto-clear → **Task 4** (shell, 3 panels, app draw + on_key).
- Search/list separator (boxed) + `matched/total` count → **Task 5**.

**2. Placeholder scan** — no TBD/TODO/hand-wave. Every code step shows the exact before/after. The one audit step (Task 4 Step 8, status tests) names the exact failure shape and the exact fix (assert right after the setting keypress).

**3. Type/signature consistency** — `draw_in_shell` trailing `status: &Status` is identical across launcher/cred/settings; `parts::draw_status_row(frame, area, &Status)`, `parts::draw_search_box(frame, area, &str, usize, usize)`, `parts::vertical_center(Rect, u16) -> Rect`, `parts::count_label(usize, usize) -> String` are used with matching types in every call site. `draw_shell` drops `status` everywhere consistently (definition + the one call in `App::draw` + the test call sites). `Status` is unchanged in `intent.rs`. No core type changes.

**Cross-task notes for the implementer:**
- Tasks 1, 2, 3 are independent and can land in any order.
- Task 4 must land before Task 5 (Task 5's three-band layout `[Length(3), Fill, Length(1)]` builds on Task 4's `[Length(1), Fill, Length(1)]`).
- After Task 4, `launcher.rs`/`cred_panel.rs` may have newly-unused `Span`/`Paragraph`/`Style` imports only if `draw_list` did not use them — but `draw_list` does use them, so they stay; Task 5 Step 7 still tells the implementer to let clippy decide.
- `parts.rs` is the new shared-render home; `panel.rs` stays pure ranking (unchanged).
