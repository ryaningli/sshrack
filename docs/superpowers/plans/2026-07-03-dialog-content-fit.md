# Dialog Content-Fit & Focus-Scroll Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Make every TUI overlay/popup fit its content snugly (no large empty padding), keep the focused row visible by scrolling on small terminals, never silently clip information, and give the vault passphrase popup a real terminal cursor — so host/cred forms, the Settings store-picker, Help, the credential fuzzy picker, and all prompt popups (passphrase / confirm / store-mode pick) all look intentional and stay complete at any terminal size.

**Architecture:** Introduce one pure helper module `src/tui/fit.rs` with two reusable, unit-tested functions — `focus_window(total, selected, visible)` (focus-following viewport, replaces `CredPicker`'s hand-rolled windowing) and `truncate_cells(s, max)` (display-width-aware ellipsis truncation via the new `unicode-width` crate). Then (a) activate `dialog::draw_dialog`'s dormant `body_area_count` parameter so the dialog height tracks its content row count, (b) make `popup::render_popup` size to its content instead of a fixed 60×20, (c) have the host/cred forms render through `focus_window` + truncate over-wide values, (d) give the Help overlay `↑/↓` scrolling (it currently hides its last ~10 lines), and (e) place a terminal cursor in the passphrase popup. The `sshrack-core` crate is untouched (TUI-only change).

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, **`unicode-width` (new dep, root package only)**.

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via params/seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **TDD for pure logic** — RED → GREEN → REFACTOR. Process/PTY behavior (crossterm key reads, `terminal.draw`) is covered by no-panic `TestBackend` smoke tests, not pixel assertions.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Passwords are `Zeroizing<String>`** end-to-end; never logged/printed/in errors/argv. (This plan renders masked passphrases only.)
- **`sshrack-core` zero-UI invariant** — this plan never touches `crates/sshrack-core/`.
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Dev stage, no compat code** — replace the fixed-size rendering outright; do not keep a parallel old path.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`.

**Scope invariant:** All work is in `src/tui/`. The two render paths must both be covered — Path A (App overlays `Help`/`HostWizard`/`CredWizard`/`StorePicker`, rendered inside `App::draw` via `dialog::draw_dialog`) and Path B (prompt popups `render_password_popup`/`confirm_popup`/`store_pick_popup`, rendered via their own `terminal.draw` via `popup::render_popup`).

---

## File Structure (target)

```
src/tui/
├── fit.rs              # NEW — pure focus_window + truncate_cells (TDD core)
├── dialog.rs           # draw_dialog activates body_rows; dialog_area(screen, body_rows)
├── popup.rs            # centered_rect(r, w, h) + render_popup(..., w, h) — size to content
├── wizard/
│   ├── host.rs         # draw_in_dialog: focus_window viewport + value truncation; body_rows()
│   ├── cred.rs         # same shape as host; body_rows()
│   └── cred_picker.rs  # windowed_lines → reuse fit::focus_window (DRY)
├── help.rs             # draw_help_dialog(scroll): Paragraph::scroll; 31 lines now reachable
├── app.rs              # help_scroll field + on_key scroll keys; pass body_rows at call sites
└── prompt.rs           # render_password_popup sizes to content + set_cursor_position;
                        #   confirm_popup / store_pick_popup size to content
```

`Cargo.toml` (root package): add `unicode-width = "0.2"`.

---

## Inventory (from exploration — the contract this plan must satisfy)

| Overlay | Chrome | Content rows today | Problem |
|---|---|---|---|
| HostWizard (`wizard/host.rs:563`) | `draw_dialog` 80×24 | 7–11 (5–9 fields + error + hint) | ~10 empty rows; no overflow handling |
| CredWizard (`wizard/cred.rs:345`) | `draw_dialog` 80×24 | 6–7 | same padding |
| StorePicker (`store.rs:161`) | `draw_dialog` 80×24 | ~7 (3 modes×2 + status) | same padding |
| **Help (`help.rs:79`)** | `draw_dialog` 80×24 | **31** | **silently clips last ~10 lines (F1/Esc/Ctrl-C unreachable)** |
| CredPicker (`cred_picker.rs:108`) | `render_popup` 60×20 | 17 (1 query + 16) | already scrolls via hand-rolled `windowed_lines` |
| password popup (`prompt.rs:359`) | `render_popup` 60×20 | 3 | ~15 empty rows; **no terminal cursor** |
| confirm popup (`prompt.rs:252`) | `render_popup` 60×20 | 3–5 | padding; clips if `text` long |
| store_pick popup (`prompt.rs:472`) | `render_popup` 60×20 | 5 | padding |

Every production `draw_dialog(` call site passes `_body_area_count = 0` — the param is dormant and is the lever for content-fit height.

---

## Task 1: `src/tui/fit.rs` — `focus_window` + `truncate_cells` (pure, TDD)

**Files:**
- Create: `src/tui/fit.rs`
- Modify: `Cargo.toml` (add `unicode-width`), `src/tui/mod.rs` (declare `pub mod fit;`)

**Interfaces:**
- Produces:
  - `pub fn focus_window(total: usize, selected: usize, visible: usize) -> std::ops::Range<usize>`
  - `pub fn truncate_cells(s: &str, max: usize) -> String`

- [ ] **Step 1: Add the dependency**

```bash
cargo add unicode-width@0.2
```

- [ ] **Step 2: Declare the module**

In `src/tui/mod.rs`, add `pub mod fit;` next to the sibling module declarations (e.g. by `pub mod dialog;`).

- [ ] **Step 3: Write the failing tests (RED)**

Create `src/tui/fit.rs` with only the test module and `use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};` — no impls yet (they'll fail to compile, which is the RED signal):

```rust
//! Pure geometry helpers for overlay content-fitting: a focus-following
//! viewport ([`focus_window`]) and display-width-aware ellipsis truncation
//! ([`truncate_cells`]). Both are pure and unit-tested; renderers consume
//! them so the small-terminal behavior is pinned independently of ratatui.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

// impls go here in Step 5

#[cfg(test)]
mod tests {
    use super::*;

    // ---- focus_window ----

    #[test]
    fn focus_window_empty_total_is_empty_range() {
        assert_eq!(focus_window(0, 0, 5), 0..0);
    }

    #[test]
    fn focus_window_visible_ge_total_returns_everything() {
        assert_eq!(focus_window(5, 2, 10), 0..5);
        assert_eq!(focus_window(5, 0, 5), 0..5);
    }

    #[test]
    fn focus_window_keeps_selected_centered_when_room_on_both_sides() {
        // 10 items, window 4, selected 5 → centered start = 5-2 = 3 → 3..7.
        assert_eq!(focus_window(10, 5, 4), 3..7);
    }

    #[test]
    fn focus_window_clamps_to_top_when_selected_near_head() {
        // selected 0 must stay in-window without a negative start.
        assert_eq!(focus_window(10, 0, 4), 0..4);
        assert_eq!(focus_window(10, 1, 4), 0..4);
    }

    #[test]
    fn focus_window_clamps_to_bottom_when_selected_near_tail() {
        // selected at last item → window hugs the tail.
        assert_eq!(focus_window(10, 9, 4), 6..10);
        assert_eq!(focus_window(10, 8, 4), 6..10);
    }

    #[test]
    fn focus_window_clamps_selected_that_exceeds_total() {
        // Defensive: an out-of-range selected is pulled back to the last item.
        assert_eq!(focus_window(10, 99, 4), 6..10);
    }

    #[test]
    fn focus_window_zero_visible_is_empty() {
        assert_eq!(focus_window(10, 5, 0), 0..0);
    }

    // ---- truncate_cells ----

    #[test]
    fn truncate_cells_zero_max_is_empty() {
        assert_eq!(truncate_cells("abc", 0), "");
    }

    #[test]
    fn truncate_cells_under_max_returns_input_unchanged() {
        assert_eq!(truncate_cells("abc", 10), "abc");
        assert_eq!(truncate_cells("abc", 3), "abc");
    }

    #[test]
    fn truncate_cells_over_max_appends_ellipsis() {
        assert_eq!(truncate_cells("abcdef", 4), "abc…");
    }

    #[test]
    fn truncate_cells_max_one_yields_just_ellipsis_when_first_char_fits() {
        // width budget 1 → can't show any payload char + ellipsis, so just …
        assert_eq!(truncate_cells("abc", 1), "…");
    }

    #[test]
    fn truncate_cells_counts_wide_chars_as_two_cells() {
        // 中/文 are width 2 each. Budget 3 → one wide char (2) + … = "中…".
        assert_eq!(truncate_cells("中文", 3), "中…");
    }

    #[test]
    fn truncate_cells_wide_char_fitting_exactly_is_kept() {
        assert_eq!(truncate_cells("中", 2), "中");
    }
}
```

- [ ] **Step 4: Run — expect compile failure (RED)**

```bash
cargo test -p sshrack --lib tui::fit 2>&1 | head
```
Expected: fails to compile (`cannot find function focus_window`).

- [ ] **Step 5: Implement (GREEN)**

Add the two functions above the test module in `src/tui/fit.rs`:

```rust
/// The focus-following viewport over `total` items: returns the `[start, end)`
/// range of items to render so that `selected` is always visible and roughly
/// centered, with the window clamped to the `[0, total)` bounds.
///
/// Pure. Renderers (forms, help, picker) consume this so the small-terminal
/// scroll behavior is pinned by tests independent of ratatui.
///
/// - `total == 0` or `visible == 0` → empty range (`0..0`).
/// - `visible >= total` → the full range (`0..total`); everything fits.
/// - `selected` is clamped into `[0, total)` defensively.
pub fn focus_window(total: usize, selected: usize, visible: usize) -> std::ops::Range<usize> {
    if total == 0 || visible == 0 {
        return 0..0;
    }
    if visible >= total {
        return 0..total;
    }
    let sel = selected.min(total - 1);
    let half = visible / 2;
    let start = sel.saturating_sub(half).min(total - visible);
    start..start + visible
}

/// Truncate `s` to at most `max` display cells, appending a single `…`
/// (width 1) when anything was dropped. Display width follows Unicode East
/// Asian Width (so CJK glyphs count as 2) via the `unicode-width` crate.
///
/// Pure. `max == 0` → `""`. Input already within budget → returned unchanged.
pub fn truncate_cells(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.width() <= max {
        return s.to_string();
    }
    // Reserve one cell for the ellipsis; fill with as many leading chars as fit.
    let budget = max - 1;
    let mut out = String::new();
    let mut w = 0usize;
    for ch in s.chars() {
        let cw = ch.width().unwrap_or(0);
        if w + cw > budget {
            break;
        }
        out.push(ch);
        w += cw;
    }
    out.push('…');
    out
}
```

- [ ] **Step 6: Run — pass**

```bash
cargo test -p sshrack --lib tui::fit
```
Expected: all tests pass.

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): pure focus_window and truncate_cells helpers"
```

---

## Task 2: `dialog` content-fit height (activate `body_rows`)

**Files:**
- Modify: `src/tui/dialog.rs` (geometry + signature)
- Modify call sites: `src/tui/app.rs:886/895/904`, `src/tui/help.rs:80`, and the test sites `src/tui/dialog.rs:135`, `src/tui/wizard/host.rs:1057/1075/1089`, `src/tui/wizard/cred.rs:921/937/951/964`

**Interfaces:**
- Produces: `pub fn dialog_area(screen: Rect, body_rows: u16) -> Rect` and `pub fn draw_dialog(frame: &mut Frame, title: &str, body_rows: u16, footer_hints: &[(&str, &str)]) -> Rect`.
- Consumes (later tasks): callers compute `body_rows` from content (e.g. `HostForm::body_rows()`).

- [ ] **Step 1: Write/update the geometry tests (RED)**

In `src/tui/dialog.rs` test module, replace the centering assertions to also pin content-fit height:

```rust
#[test]
fn dialog_area_height_tracks_body_rows_then_clamps_to_max() {
    let screen = Rect::new(0, 0, 100, 40);
    // body 5 → outer = 5 + 2 border + 1 footer = 8.
    let d = dialog_area(screen, 5);
    assert_eq!(d.height, 8);
    // body 100 → clamps to MAX_H (24).
    let d = dialog_area(screen, 100);
    assert_eq!(d.height, MAX_H);
}

#[test]
fn dialog_area_height_clamps_to_screen_when_terminal_short() {
    // 12-row screen: outer must fit (minus 4-cell margin → ≤ 8), not overflow.
    let screen = Rect::new(0, 0, 100, 12);
    let d = dialog_area(screen, 50);
    assert!(d.height <= screen.height);
    assert!(d.y + d.height <= screen.height, "must not overflow screen");
}

#[test]
fn dialog_area_still_centers_and_clamps_width() {
    let screen = Rect::new(0, 0, 100, 40);
    let d = dialog_area(screen, 5);
    assert!(d.width <= MAX_W);
    let left = d.x;
    let right = screen.width - (d.x + d.width);
    assert_eq!(left, right, "horizontally centered");
}
```

- [ ] **Step 2: Run — expect RED** (signature mismatch / wrong heights)

```bash
cargo test -p sshrack --lib tui::dialog 2>&1 | head -30
```

- [ ] **Step 3: Implement — size height to content**

In `src/tui/dialog.rs`, change the two functions:

```rust
/// Centered, content-fit dialog rect inside `screen`. The outer height is
/// `body_rows + 2 (border) + 1 (footer)`, clamped down to [`MAX_H`] and to the
/// screen height (minus a 2-cell margin). Width stays at most [`MAX_W`] (forms
/// need the room for long values). Returns `screen` as-is when either axis < 6.
pub fn dialog_area(screen: Rect, body_rows: u16) -> Rect {
    let w = MAX_W.min(screen.width.saturating_sub(4));
    let outer_h = body_rows
        .saturating_add(3) // border(2) + footer(1)
        .min(MAX_H)
        .min(screen.height.saturating_sub(4));
    // Floor the height at the dialog chrome itself (2 border + 1 footer = 3)
    // so a zero/near-zero body_rows still yields a visible chrome.
    let h = outer_h.max(3);
    if screen.width < 6 || screen.height < 6 {
        return screen;
    }
    let [_, vmid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(h),
        Constraint::Fill(1),
    ])
    .areas(screen);
    let [_, area, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(w),
        Constraint::Fill(1),
    ])
    .areas(vmid);
    area
}
```

Update `draw_dialog` to take `body_rows` (drop the underscore) and pass it through:

```rust
pub fn draw_dialog(
    frame: &mut Frame,
    title: &str,
    body_rows: u16,
    footer_hints: &[(&str, &str)],
) -> Rect {
    let area = dialog_area(frame.area(), body_rows);
    frame.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
        .title_style(theme::accent().add_modifier(Modifier::BOLD));
    frame.render_widget(&block, area);
    let inner = block.inner(area);
    let [body, footer] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(inner);
    // … footer rendering unchanged …
    body
}
```
(Keep the existing footer-hint span building verbatim; only the `dialog_area` call changes.)

- [ ] **Step 4: Update every call site to pass real `body_rows`**

The pattern: each caller now computes the content row count. Add a tiny accessor on each form and pass it.

- `src/tui/wizard/host.rs`: add
  ```rust
  /// Content row count the dialog should size to: reachable fields + 1 error
  /// line + 1 hint line. Consumed by the App overlay layer to size the dialog.
  pub fn body_rows(&self) -> u16 {
      self.reachable_fields().len() as u16 + 2
  }
  ```
- `src/tui/wizard/cred.rs`: same `body_rows()` (`reachable_fields().len() + 2`).
- `src/tui/store.rs`: add
  ```rust
  /// 3 modes × (name line + blurb line) + 1 status line.
  pub fn body_rows(&self) -> u16 {
      StoreModeChoice::ORDER.len() as u16 * 2 + 1
  }
  ```
- `src/tui/app.rs:886/895/904`: change the three `draw_dialog(frame, title, 0, …)` calls to `draw_dialog(frame, title, form.body_rows(), …)` (host/cred) and `draw_dialog(frame, " storage mode ", self.store_view.as_ref().expect("…").body_rows(), …)`.
- `src/tui/help.rs:80`: pass `help_lines().len() as u16` (31 → clamps to MAX_H; Task 4 adds scrolling).
- Test call sites (`dialog.rs:135`, `host.rs:1057/1075/1089`, `cred.rs:921/937/951/964`): pass a concrete body_rows (e.g. `5` for the dialog test, `form.body_rows()` for the form tests).

- [ ] **Step 5: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace && cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): size dialog height to its content rows"
```

---

## Task 3: Host/cred forms — focus-following viewport + value truncation

**Files:**
- Modify: `src/tui/wizard/host.rs` (`draw_in_dialog`, `render_row`)
- Modify: `src/tui/wizard/cred.rs` (same shape)

**Interfaces:**
- Consumes: `crate::tui::fit::{focus_window, truncate_cells}`.

- [ ] **Step 1: Add a no-panic small-terminal render test (RED-ish behavior pin)**

In `src/tui/wizard/host.rs` test module, add a `TestBackend` render test that exercises a **short** terminal (height 10) and asserts the focused field's cursor lands inside the screen (i.e. the viewport scrolled it in). Render itself can't easily assert pixels; the pin is "no panic + cursor within screen bounds":

```rust
#[test]
fn draw_in_dialog_keeps_focused_cursor_on_screen_when_terminal_short() {
    use ratatui::{Terminal, backend::TestBackend};
    let mut form = HostForm::new_add(/* same builder the other tests use */);
    // Move focus to the last reachable field (worst case for top-pinned render).
    for _ in 0..form.reachable_fields().len() {
        form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    }
    let backend = TestBackend::new(60, 10); // short terminal
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| {
        let body = crate::tui::dialog::draw_dialog(f, &form.title(), form.body_rows(), &[]);
        form.draw_in_dialog(f, body);
    })
    .unwrap();
    let (cx, cy) = term.backend().cursor_position().unwrap_or((0, 0));
    assert!(cy < 10, "focused field's cursor must stay on-screen (got y={cy})");
}
```
(If `TestBackend::cursor_position` needs a feature/import already used by `cred_picker.rs:354`, mirror that.)

- [ ] **Step 2: Implement the viewport in `HostForm::draw_in_dialog`**

Replace the top of `draw_in_dialog` so the fields render through a `focus_window` viewport when they don't all fit, and the cursor `y` uses the in-window row index:

```rust
pub fn draw_in_dialog(&self, frame: &mut Frame, body: ratatui::layout::Rect) {
    let reachable = self.reachable_fields();
    let total = reachable.len();
    // error(1) + hint(1) sit below the fields area.
    let fields_h = body.height.saturating_sub(2) as usize;
    let win = crate::tui::fit::focus_window(total, self.focus_idx(), fields_h);
    let rows: Vec<Line> = reachable[win.clone()]
        .iter()
        .map(|f| self.render_row(*f, body.width))
        .collect();

    let [fields_area, error_area, hint_area] = Layout::vertical([
        Constraint::Length(rows.len() as u16),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(body);
    frame.render_widget(Paragraph::new(rows), fields_area);

    // … error_line + hint rendering unchanged …
    let hint = /* unchanged hint match */;
    frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);

    // Cursor: use the in-window row index (focus_idx − win.start).
    if let Some((row, offset)) = self.cursor_target() {
        if win.start <= row && row < win.end {
            let in_win_row = row - win.start;
            let max_x = fields_area.x + fields_area.width.saturating_sub(1);
            let x = (fields_area.x + HOST_VALUE_COL + offset as u16).min(max_x);
            let y = fields_area.y + in_win_row as u16;
            frame.set_cursor_position((x, y));
        }
    }

    if let Some(picker) = &self.cred_picker {
        picker.draw_overlay(frame);
    }
}
```

- [ ] **Step 3: Truncate over-wide values in `render_row`**

Change `render_row` to accept the available row width and pass the value through `truncate_cells`. The value column starts at `HOST_VALUE_COL` and runs to the row's right edge:

```rust
fn render_row(&self, f: Field, row_width: u16) -> Line<'static> {
    // … existing marker + label spans unchanged …
    let avail = row_width.saturating_sub(HOST_VALUE_COL) as usize;
    let (value, placeholder) = self.row_value_and_placeholder(f);
    let shown = truncate_cells(value_or_placeholder.as_str(), avail);
    // build the line from marker + label + shown
}
```
(Mirror the existing span assembly; only the value string is now `truncate_cells(...)`-wrapped. The cursor offset in `cursor_target` already uses `chars().count()` of the stored value — keep it, since truncation is display-only.)

- [ ] **Step 4: Apply the same shape to `CredForm::draw_in_dialog` / `render_row`** (`src/tui/wizard/cred.rs:345`), using `CRED_VALUE_COL`.

- [ ] **Step 5: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace && cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): scroll form fields to keep focus visible and truncate wide values"
```

---

## Task 4: Help overlay scrolling (recover the hidden lines)

**Files:**
- Modify: `src/tui/app.rs` (`help_scroll` field + `on_key` scroll keys + open-help resets scroll)
- Modify: `src/tui/help.rs` (`draw_help_dialog` takes `scroll`, renders via `Paragraph::scroll`)
- Modify: `src/tui/app.rs::draw_overlay` to pass `self.help_scroll`

**Interfaces:**
- Produces: `pub fn draw_help_dialog(frame: &mut Frame, scroll: u16)`; `App.help_scroll: u16`.

- [ ] **Step 1: Add a purity test for the scroll-clamp helper (RED)**

Add a pure helper in `help.rs` and test it:

```rust
/// Max scroll offset that still shows the last help line, given the body
/// height. Pure; consumed by `App::on_key` to clamp `help_scroll`.
pub fn max_scroll(body_height: u16) -> u16 {
    let lines = help_lines().len() as u16;
    lines.saturating_sub(body_height)
}

#[test]
fn max_scroll_is_zero_when_body_fits_all_lines() {
    assert_eq!(max_scroll(40), 0); // 31 lines fit in 40
}
#[test]
fn max_scroll_is_excess_lines_when_body_too_short() {
    assert_eq!(max_scroll(21), 10); // 31 − 21
}
```

- [ ] **Step 2: Implement `max_scroll`** in `help.rs` (shown above).

- [ ] **Step 3: Add `help_scroll` to `App` + scroll keys in `on_key`**

In `src/tui/app.rs`:
- Add field `pub help_scroll: u16` (default `0`) to `App`.
- Where `on_key` opens `Overlay::Help`, set `self.help_scroll = 0;`.
- In `on_key`, when the active overlay is `Help`, handle scroll keys (before the generic overlay handling):
  ```rust
  if self.overlay.as_ref().is_some_and(|o| matches!(o, Overlay::Help)) {
      match key.code {
          KeyCode::Down | KeyCode::Char('j') => {
              // Clamp using the largest body a Help dialog can have (MAX_H − 3).
              let m = crate::tui::help::max_scroll(crate::tui::dialog::MAX_H - 3);
              self.help_scroll = self.help_scroll.saturating_add(1).min(m);
              return Outcome::Continue;
          }
          KeyCode::Up | KeyCode::Char('k') => {
              self.help_scroll = self.help_scroll.saturating_sub(1);
              return Outcome::continue;
          }
          KeyCode::PageDown => {
              let m = crate::tui::help::max_scroll(crate::tui::dialog::MAX_H - 3);
              self.help_scroll = (self.help_scroll + 5).min(m);
              return Outcome::continue;
          }
          KeyCode::PageUp => {
              self.help_scroll = self.help_scroll.saturating_sub(5);
              return Outcome::continue;
          }
          _ => {} // F1/Esc fall through to close the overlay
      }
  }
  ```
  (Use the project's existing `Outcome::Continue` / `press` test helpers; match the surrounding `on_key` style.)

- [ ] **Step 4: Render with scroll + update footer**

`src/tui/help.rs`:
```rust
pub fn draw_help_dialog(frame: &mut Frame, scroll: u16) {
    let body = crate::tui::dialog::draw_dialog(
        frame,
        " help ",
        help_lines().len() as u16,
        &[("↑↓", "scroll"), ("F1/Esc", "close")],
    );
    let lines = help_lines();
    let max = max_scroll(body.height);
    let clamped = scroll.min(max);
    frame.render_widget(
        Paragraph::new(lines).scroll((clamped, 0)),
        body,
    );
}
```
In `App::draw_overlay` (`app.rs:884`): `Overlay::Help => draw_help_dialog(frame, self.help_scroll)`.

- [ ] **Step 5: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace && cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): scroll help overlay so all bindings are reachable"
```

---

## Task 5: Prompt popups size to content + passphrase cursor

**Files:**
- Modify: `src/tui/popup.rs` (`centered_rect(r, w, h)`, `render_popup(frame, title, body, w, h)`)
- Modify: `src/tui/prompt.rs` (`render_password_popup` cursor + sizing; `confirm_popup` sizing; `store_pick_popup` sizing)
- Modify call sites: `src/tui/wizard/cred_picker.rs:125`

**Interfaces:**
- Produces: `pub fn centered_rect(r: Rect, w: u16, h: u16) -> Rect`, `pub fn render_popup<W: Widget>(frame: &mut Frame, title: &str, body: W, w: u16, h: u16) -> Rect`.

- [ ] **Step 1: Update the geometry tests (RED)**

In `src/tui/popup.rs` tests, retarget to the new signature:
```rust
#[test]
fn centered_rect_uses_given_size_and_centers() {
    let screen = Rect::new(0, 0, 100, 40);
    let r = centered_rect(screen, 40, 6);
    assert_eq!((r.width, r.height), (40, 6));
    assert_eq!(r.x, 30); // centered horizontally
    assert_eq!(r.y, 17); // centered vertically
}

#[test]
fn centered_rect_clamps_to_screen_when_too_small() {
    let tiny = Rect::new(0, 0, 10, 5);
    let r = centered_rect(tiny, 40, 6);
    assert_eq!((r.width, r.height), (10, 5), "clamps down, never overflows");
}
```

- [ ] **Step 2: Implement — `centered_rect(r, w, h)` + `render_popup(...)`**

```rust
pub fn centered_rect(r: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(r.width);
    let h = h.min(r.height);
    let [_, mid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(h),
        Constraint::Fill(1),
    ])
    .areas(r);
    let [_, area, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(w),
        Constraint::Fill(1),
    ])
    .areas(mid);
    area
}

pub fn render_popup<W: Widget>(frame: &mut Frame, title: &str, body: W, w: u16, h: u16) -> Rect {
    let area = centered_rect(frame.area(), w, h);
    frame.render_widget(Clear, area);
    let block = Block::new().borders(Borders::ALL).title(format!(" {title} "));
    frame.render_widget(&block, area);
    let [content] = Layout::vertical([Constraint::Fill(1)]).areas(block.inner(area));
    frame.render_widget(body, content);
    content
}
```
(Constants `POPUP_WIDTH`/`POPUP_HEIGHT` become default upper bounds; keep them as `pub const` for callers that want the classic cap.)

- [ ] **Step 3: `render_password_popup` — size to 3 rows + place cursor**

In `src/tui/prompt.rs`:
```rust
fn render_password_popup(terminal: &mut Tui, title: &str, buffer: &str, flash: Option<&str>) {
    use crate::tui::fit::truncate_cells;
    let mask_width = buffer.chars().count();
    let hint = "[Enter] confirm   [Esc] cancel";
    // content width = widest line + 2 padding; cap at POPUP_WIDTH - 2 (border).
    let inner_w = (mask_width.max(hint.len()) as u16 + 2).min(popup::POPUP_WIDTH.saturating_sub(2));
    let shown_mask = truncate_cells(&"•".repeat(mask_width), inner_w as usize);
    let lines = vec![
        Line::from(shown_mask).bold(),
        Line::from(""),
        Line::from(hint).style(Style::new().dim()),
    ];
    let title = popup_title(title, flash);
    let content = std::cell::RefCell::new(None);
    let _ = terminal.draw(|f| {
        let c = popup::render_popup(f, title, Paragraph::new(lines.clone()), inner_w + 2, 3 + 2);
        *content.borrow_mut() = Some(c);
        // Place the terminal cursor at the end of the masked input on row 0.
        if let Some(c) = Some(c) {
            let cx = (c.x + mask_width.min(inner_w as usize) as u16).min(c.x + c.width.saturating_sub(1));
            f.set_cursor_position((cx, c.y));
        }
    });
}
```
(Keep `MASK` as the mask char if that constant exists instead of the literal `•`; match the surrounding code. The key change is computing `content` rect from `render_popup`'s return and calling `set_cursor_position`.)

- [ ] **Step 4: Size `confirm_popup` and `store_pick_popup` to content**

For each, compute `content_h = lines + 2` (blank + hint) and `content_w = max_line_width + 2`, then `render_popup(frame, title, body, content_w + 2, content_h + 2)`. Use `UnicodeWidthStr::width` (`use unicode_width::UnicodeWidthStr;`) for the max line width so wide glyphs count. Both keep **no** terminal cursor (they are y/n and number picks, not free text).

- [ ] **Step 5: Update `CredPicker::draw_overlay`** (`cred_picker.rs:125`) to pass its current `(POPUP_WIDTH, POPUP_HEIGHT)` (unchanged footprint) so it compiles against the new signature.

- [ ] **Step 6: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace && cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): size prompt popups to content and show passphrase cursor"
```

---

## Task 6: CredPicker reuses `focus_window` + docs + full gate

**Files:**
- Modify: `src/tui/wizard/cred_picker.rs` (`windowed_lines` → delegate to `fit::focus_window`)
- Modify: `CLAUDE.md` (TUI overlay wording)
- Modify: `src/tui/app.rs:880-881` stale doc (mentions nonexistent `DeleteHost`/`DeleteCred` overlays)

- [ ] **Step 1: Replace the hand-rolled windowing with `focus_window`**

In `cred_picker.rs`, rewrite `windowed_lines` (around `:137`) to compute the window via `crate::tui::fit::focus_window(ranked.len(), self.selected, PICKER_VISIBLE_ROWS)` and slice the ranked list accordingly. Behavior stays identical (the Task 1 tests pin `focus_window` to the same center+clamp semantics the picker already had). Keep the empty-rank-list "no matches" branch.

- [ ] **Step 2: Update `CLAUDE.md`**

In the TUI section, note that overlays/dialogs size to their content and scroll to keep the focus (and, for Help, all lines) visible on small terminals. One sentence; do not re-architect the doc.

- [ ] **Step 3: Fix the stale overlay doc**

`src/tui/app.rs:880-881` — delete/rewrite the comment referencing `DeleteHost`/`DeleteCred` overlay variants (deletes go through `confirm_popup`).

- [ ] **Step 4: Full gate + manual smoke**

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
Manual smoke (run `cargo run -q --`, then exercise each surface):
- Host add wizard: confirm the dialog hugs the field list (no big bottom gap).
- Credentials add wizard: same.
- Settings → storage mode: picker hugs the 3 modes.
- F1 Help: `↑/↓` scrolls; the last binding row (Ctrl-C) is reachable.
- Settings → switch to vault: the New-passphrase popup shows a blinking cursor at the end of the `•••` row (the original bug).
- Resize the terminal down to ~12 rows / ~30 cols while a wizard is open: the focused field stays visible; wide values get `…`.

- [ ] **Step 5: Commit + finish**

```bash
git add -A && git commit -m "refactor(tui): reuse focus_window in cred picker and refresh overlay docs"
```
Then use the `superpowers:finishing-a-development-branch` skill to merge.

---

## Self-Review

**1. Spec coverage (every overlay addressed):**
- HostWizard — Task 2 (height) + Task 3 (scroll/truncate). ✅
- CredWizard — Task 2 + Task 3. ✅
- StorePicker — Task 2 (height). ✅
- Help (clipping bug) — Task 2 (height clamp) + Task 4 (scroll). ✅
- CredPicker — Task 5 (signature) + Task 6 (reuse `focus_window`). ✅
- password/passphrase popup (+ cursor bug) — Task 5. ✅
- confirm / store_pick popups — Task 5. ✅
- small-terminal overflow (height + width) — Tasks 3 & 5 (`focus_window` + `truncate_cells`). ✅
- passphrase cursor (user's point 2) — Task 5 Step 3. ✅

**2. Placeholder scan:** No TBD/TODO. Each step has runnable code or an exact pattern. Where a call site is mechanical (passing `body_rows`), the accessor code is given and the pattern is described once with representative paths.

**3. Type consistency:** `focus_window(_, _, _) -> Range<usize>` and `truncate_cells(&str, usize) -> String` are used identically in Tasks 1/3/5/6. `dialog_area(screen, body_rows)` / `draw_dialog(frame, title, body_rows, …)` consistent across Tasks 2–4. `centered_rect(r, w, h)` / `render_popup(frame, title, body, w, h)` consistent in Task 5. `App.help_scroll: u16` threaded from Task 4 Step 3 to `draw_overlay`.
