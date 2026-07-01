# TUI Visual Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the TUI's visual defects — bordered middle panel, no duplicated footer, aligned columns, `user@ip:port` host display, capitalized wizard labels, and a wizard-style `▶` selection marker that stops the selected row from shifting left.

**Architecture:** Pure-render changes confined to `src/tui/` (shell, launcher, cred_panel, settings, theme, wizard). No core change, no behavior change to data paths. Every pure helper (`focus_marker`, `host_user`, `host_line`/`cred_row` column math, `Field::label`) is TDD'd; render wiring is covered by render-smoke + the existing app/launcher/cred tests updated to new signatures. The shell's footer becomes the single status surface (status message when present, else hotkey hints), and panels stop rendering their own status row.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30 (`Block`/`Borders`/`Layout`), crossterm, nucleo-matcher.

## Global Constraints

Carried verbatim from `CLAUDE.md` hard rules — every task implicitly inherits these:

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests.
- **Zero `unwrap()`/`expect()`** in production code — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **TDD for pure logic** — RED → GREEN → REFACTOR.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Tests hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set; no `env -u`.
- **`cargo test --bin sshrack <filter>`** (NOT `--lib` — sshrack is a binary crate).
- **Dev stage, no dead code** — remove `theme::selected_gutter` once all callers migrate (Task 6); remove `STATUS_LINE` constants and the `Launcher::status` field once their render sites are gone.
- **Out of scope (deferred):** the `app.rs` ~3800-line split (M1) is NOT part of this plan; this plan only edits `app.rs` at specific call sites. `sftp`/port-forward remain deferred.

**Commit style:** `<type>(<scope>): <desc>` (Conventional Commits). Each task ends with a commit.

**Branch:** create `feat/tui-visual-polish` from `refactor/tui-split-large-files` (HEAD `367b9ad`) so the already-split `wizard/{mod,host,cred}.rs` is available. If that branch has been merged to `main` first, branch from `main`.

---

## Design Spec (locked decisions — every task aligns to these)

1. **Middle panel border (#1, #2):** the whole middle band (search + list) is wrapped in a thin, **untitled** `Block::default().borders(Borders::ALL)`. The panel draws into the block's `inner` rect. The top-right `F1 help` text is **removed** from band 1 (the footer's `F1 help` hint remains, so the binding is still discoverable). Removing `F1 help` also lets the tab bar extend further right (drop the `help_text` reservation from the tabs-area width math).
2. **Selection marker (#4a):** replace `theme::selected_gutter()` (`▎`, 1 cell — the cause of the selected row shifting left) with `theme::focus_marker(selected)` = `▶ ` (accent + bold) when selected, `  ` (raw two spaces) otherwise. Both are **2 cells**, so every row's content starts at the same column. This mirrors the wizard's focused-field marker (`wizard/host.rs:496`: `if focused { "▶ " } else { "  " }`).
3. **Status line consolidation (#3):** the shell footer (band 3) becomes the **single** status surface — it renders the app status message when one is set (red on error, normal otherwise), otherwise the hotkey hints. The panels' own status row is **removed** (so `[search(1), list(fill)]`, no third row), and the `STATUS_LINE` fallback constants are deleted (this also fixes the initial "two hint lines on first render" — `Status::empty()` no longer falls back to a second hint line). Cancel-noise writes (`cancelled` / `delete cancelled` / `connect cancelled`) are removed in Task 6; success (`host saved`, `removed '<name>'`, `switched to <mode>`) and red errors are kept.
4. **Column alignment (#4b):** host and cred rows use a fixed-width name column (adaptive: max name width across the visible rows, capped) so the address/kind column starts at one offset, and the trailing badge (host `[tier]` / cred kind) is right-aligned to the list area's right edge via filler spaces. `host_line`/`cred_row` take `name_w: usize` and `width: u16`.
5. **Host display format (#4c):** the host row shows `user@host:port` (dim), resolving the user from `Auth::Ref` (look up the credential's `body.user`) or `Auth::Inline` (`body.user`). When there is no resolvable user (dangling ref, or empty inline user), the user is `?`, yielding `?@1.2.3.4:22`. The credential **name** is no longer shown on the host row (so the launcher's display no longer needs `CredentialNames`; it takes the `&[Credential]` slice and resolves user inline).
6. **Wizard labels capitalized (#5):** `Field::label()` / `CredField::label()` / `AuthChoice::label()` / `SecretChoice::label()` and the static `"identity"` row return first-letter-capitalized English (`name`→`Name`, `host`→`Host`, `port`→`Port`, `user`→`User`, `identity`→`Identity`). Padding widths (`{label:>5}` host, `{label:>8}` cred) stay the same — the longest label (`Identity` = 8) already sets the cred width, and host labels are all 4 chars (< 5).

---

## File Structure

```
src/tui/
├── theme.rs          # +focus_marker(focused); -selected_gutter (Task 6)
├── shell.rs          # border around middle; -F1 help; footer = status-or-hints
├── app.rs            # draw() passes &status to draw_shell; panel calls drop status; -cancel writes (Task 6)
├── launcher.rs       # -status row / STATUS_LINE / Launcher.status; host_line: marker + columns + user@host:port; credential_names→credentials
├── cred_panel.rs     # -status row / STATUS_LINE; cred_row: marker + columns
├── settings.rs       # -status row; selected_gutter→focus_marker
├── store.rs          # -"cancelled" writes (Task 6)
└── wizard/{mod,host,cred}.rs  # label() capitalization; "identity"→"Identity"
```

No new files. No core changes.

---

## Task 1: theme — `focus_marker` helper

**Files:**
- Modify: `src/tui/theme.rs`

**Interfaces:**
- Produces: `pub fn focus_marker(focused: bool) -> Span<'static>` — `▶ ` (accent + BOLD) when `focused`, else `Span::raw("  ")`. Consumed by Tasks 3 (settings), 4 (launcher), 5 (cred).

- [ ] **Step 1: Write the failing test**

In `src/tui/theme.rs` `#[cfg(test)] mod tests`:
```rust
#[test]
fn focus_marker_is_accented_arrow_when_focused_else_two_spaces() {
    let on = focus_marker(true);
    let off = focus_marker(false);
    assert_eq!(on.content.as_ref(), "▶ ");
    assert_eq!(off.content.as_ref(), "  ");
    // Both markers occupy the same number of cells, so a selected row's
    // content starts at the same column as an unselected row's — no shift.
    assert_eq!("▶ ".chars().count(), "  ".chars().count());
}
```

- [ ] **Step 2: Run — expect fail (undefined)**

`cargo test --bin sshrack theme::tests::focus_marker`
Expected: FAIL — `focus_marker` not found.

- [ ] **Step 3: Implement**

In `src/tui/theme.rs` (alongside `selected_gutter`, which stays for now — removed in Task 6):
```rust
/// The selection marker shared by list rows and form fields: `▶ ` accented +
/// bold when focused/selected, two spaces when not. Both forms are 2 cells
/// wide, so every row's content starts at the same column regardless of which
/// row is selected (no selected-row left-shift). Mirrors the wizard's
/// focused-field marker.
pub fn focus_marker(focused: bool) -> Span<'static> {
    if focused {
        Span::styled("▶ ", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("  ")
    }
}
```

- [ ] **Step 4: Run — pass**

`cargo test --bin sshrack theme::tests::focus_marker` → PASS.

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add src/tui/theme.rs
git commit -m "feat(tui): add focus_marker selection helper to theme"
```

---

## Task 2: shell chrome — middle border + remove F1 help

**Files:**
- Modify: `src/tui/shell.rs` (and its `#[cfg(test)]` module)

**Interfaces:**
- Produces: `draw_shell` returns the **inner** rect of a thin bordered block (smaller than the old `middle` by 1 cell on each side). Signature unchanged: `draw_shell(frame, area, active, footer) -> Rect`. The `F1 help` render block and the `help_text` reservation in the tabs-area width math are removed.

- [ ] **Step 1: Write the failing test**

In `src/tui/shell.rs` `#[cfg(test)] mod tests`, add:
```rust
#[test]
fn draw_shell_borders_middle_and_drops_f1_help() {
    let backend = TestBackend::new(60, 12);
    let mut term = Terminal::new(backend).unwrap();
    let mut got = Rect::default();
    term.draw(|f| {
        got = draw_shell(f, f.area(), Tab::Hosts, &[("Enter", "connect"), ("F1", "help")]);
    })
    .unwrap();
    // Inner rect is inset by the 1-cell border on every side of the middle band.
    // Middle band y = 1 (after the 1-row top band); height = 12 - 2 = 10.
    assert_eq!(got.x, 1);
    assert_eq!(got.y, 1);
    assert_eq!(got.width, 60 - 2);
    assert_eq!(got.height, 10 - 2);
    // F1 help text no longer appears in the top band.
    let view: String = term.backend().to_string().chars().filter(|c| !c.is_whitespace()).collect();
    assert!(!view.contains("F1help"), "F1 help should be removed from the header");
}
```
(If `TestBackend::to_string` filtering is awkward, instead assert the buffer cell at the top-right corner is not `F`/`h`. Keep the assertion intent: no `F1 help` in band 1.)

- [ ] **Step 2: Run — expect fail**

`cargo test --bin sshrack shell::tests::draw_shell_borders_middle_and_drops_f1_help`
Expected: FAIL — `got.x == 0` (no border yet), and `F1 help` still present.

- [ ] **Step 3: Implement**

In `draw_shell`:
- Add `use ratatui::widgets::{Block, Borders};` (extend the existing `widgets` import).
- After computing `[top, middle, bottom]`, replace `middle` as the returned value with the inner rect of a bordered block:
```rust
let panel_area = Block::default()
    .borders(Borders::ALL)
    .border_style(Style::new().dim())
    .inner(middle);
```
- Remove the `help_text`/F1-help render block (the whole `// Help on the right.` paragraph, lines ~63-73 in current source). Remove `let help_text = "F1 help";`.
- Fix the `tabs_area` width math so it no longer reserves space for help text: the tab bar now extends from `top.x + brand_len + 2` to near the right edge:
```rust
let tabs_area = Rect {
    x: top.x + brand_len + 2,
    width: top.width.saturating_sub(brand_len + 2 + 1), // +1 right padding
    y: top.y,
    height: 1,
};
```
- Return `panel_area` (was `middle`).

- [ ] **Step 4: Update the existing shell tests**

The two existing tests (`draw_shell_returns_inner_panel_area_and_never_panics`, `draw_shell_clamps_on_tiny_terminal`) assert `got.x == 0` / `got.width == 100`. After the border they must assert the **inset** rect: `got.x == 1`, `got.width == 100 - 2`, `got.height == (30 - 2) - 2`. Update them. The tiny-terminal test should still not panic (the `Block` handles `area < 2` gracefully — verify; if it panics, guard `panel_area` to a non-negative rect).

- [ ] **Step 5: Run — pass**

`cargo test --bin sshrack shell` → all PASS.

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add src/tui/shell.rs
git commit -m "feat(tui): border the middle panel and drop the header F1 help"
```

---

## Task 3: status line consolidation (single bottom line; remove panel status rows)

This is the keystone render task. It makes the shell footer the **only** status surface and removes the per-panel status row that duplicated the hotkey hint (the `#3` bug, including the initial-render duplication).

**Files:**
- Modify: `src/tui/shell.rs` — `draw_shell` gains a `status: &super::app::Status` param; band 3 renders status-or-hints.
- Modify: `src/tui/app.rs` — `draw()` passes `&self.status` to `draw_shell`; the three panel `draw_in_shell` calls drop their `&self.status` argument.
- Modify: `src/tui/launcher.rs` — `draw_in_shell` drops `status` param + the status row (split `[search(1), list(fill)]`); delete `STATUS_LINE` and the now-dead `Launcher::status: Option<String>` field (+ its constructor init).
- Modify: `src/tui/cred_panel.rs` — same shape: drop `status` param + status row; delete `STATUS_LINE`.
- Modify: `src/tui/settings.rs` — drop `status` param + status row; swap `theme::selected_gutter()` → `theme::focus_marker(selected)` (settings has a single row; this keeps its marker consistent with the other panels).

**Interfaces:**
- Produces: `draw_shell(frame, area, active, footer, status: &super::app::Status) -> Rect`. Panel `draw_in_shell` signatures lose their trailing `status: &Status` param and render only `[search, list]`. `Status` stays defined in `app.rs` (shell imports `super::app::Status`).

- [ ] **Step 1: Update `draw_shell` signature + footer band**

In `src/tui/shell.rs`:
```rust
use crate::tui::app::Status; // sibling import; Status stays defined in app.rs

pub fn draw_shell(
    frame: &mut Frame,
    area: Rect,
    active: Tab,
    footer: &[(&str, &str)],
    status: &Status,
) -> Rect {
    // ... bands 1 (no F1 help) + bordered middle unchanged from Task 2 ...

    // Band 3: status message when present, else the hotkey hints.
    let line = if let Some(msg) = &status.message {
        let style = if status.is_error {
            Style::new().fg(theme::DANGER)
        } else {
            Style::new()
        };
        Line::from(vec![
            Span::styled("status: ", Style::new().dim()),
            Span::styled(msg.clone(), style),
        ])
    } else {
        let mut spans: Vec<Span> = Vec::new();
        for (i, (k, label)) in footer.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled(" · ", Style::new().dim()));
            }
            spans.push(Span::styled(*k, theme::accent().add_modifier(Modifier::BOLD)));
            spans.push(Span::styled(format!(" {label}"), Style::new().dim()));
        }
        Line::from(spans)
    };
    frame.render_widget(Paragraph::new(line), bottom);
    panel_area
}
```

- [ ] **Step 2: Remove the panel status rows**

`src/tui/launcher.rs` `draw_in_shell`: drop the `status: &super::app::Status` parameter; change the vertical split to `[search(1), list(fill)]`; delete the status-row `Paragraph` render (the `// Status row: ...` block) and the `STATUS_LINE` const. Delete the `pub status: Option<String>` field on `Launcher` and its `status: None` init in the constructor.

`src/tui/cred_panel.rs` `draw_in_shell`: same — drop `status` param, split `[search(1), list(fill)]`, delete the status row + `STATUS_LINE`.

`src/tui/settings.rs` `draw_in_shell`: drop `status` param, split `[search(1) or header(1), list(fill)]` (keep whichever non-status rows settings currently has — settings has one storage-mode row; keep it, drop only the status row). Swap `theme::selected_gutter()` → `theme::focus_marker(selected)`.

- [ ] **Step 3: Update `app.rs` draw site**

```rust
pub fn draw(&self, frame: &mut Frame) {
    let area = frame.area();
    let footer = self.footer_hints();
    let panel_area = draw_shell(frame, area, self.active_tab, &footer, &self.status);
    match self.active_tab {
        Tab::Hosts => self.launcher.draw_in_shell(
            frame, panel_area, &self.config.hosts, &self.frecency, &self.credential_names,
        ),
        Tab::Credentials => self.cred_panel.draw_in_shell(
            frame, panel_area, &self.config.credentials,
        ),
        Tab::Settings => self.settings_panel.draw_in_shell(
            frame, panel_area, self.current_store_mode_label(),
        ),
    }
    if let Some(ov) = &self.overlay {
        self.draw_overlay(frame, ov);
    }
}
```
(Note: the Hosts call still passes `&self.credential_names` here — Task 4 swaps that to `&self.config.credentials`. For Task 3, keep whatever the current Hosts signature is, minus `status`.)

- [ ] **Step 4: Update tests**

- `shell.rs` tests: pass a `Status` to `draw_shell` (`Status::empty()` and one with a message); assert the footer renders the message when present and the hints when empty. Update all existing `draw_shell(...)` test call sites to add the `&status` arg.
- `launcher.rs` / `cred_panel.rs` / `settings.rs` tests: drop the `&status` arg from every `draw_in_shell(...)` test call. Remove any test that asserted `STATUS_LINE` text was rendered; replace with an assertion that the panel no longer renders a status row (e.g., the bottom line of the panel area is blank when `Status::empty()`).
- Add a regression test: render the launcher with `Status::empty()` and assert the rendered buffer does **not** contain the duplicated hint (only the shell footer does).

- [ ] **Step 5: Build + run tests**

```bash
cargo build --workspace
cargo test --bin sshrack
```
Fix every call site the compiler flags (there are several test call sites of `draw_in_shell` / `draw_shell`).

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A
git commit -m "feat(tui): consolidate status into the shell footer; drop panel status rows"
```

---

## Task 4: host list — focus marker, column alignment, `user@host:port`

**Files:**
- Modify: `src/tui/launcher.rs` — `host_line` (marker + columns + new format), new `host_user`, `draw_list` (compute `name_w`, pass `width`), `draw_in_shell` (signature: `credential_names` → `credentials: &[Credential]`).
- Modify: `src/tui/app.rs` — the Hosts `draw_in_shell` call swaps `&self.credential_names` → `&self.config.credentials`.

**Interfaces:**
- Produces: `fn host_user(host: &Host, credentials: &[Credential]) -> String` (resolves the user, `?` when unresolvable); `fn host_line(host, query, credentials, selected, name_w: usize, width: u16) -> Line`. The launcher's display no longer references `CredentialNames`.

- [ ] **Step 1: Write the failing tests (pure helpers)**

In `src/tui/launcher.rs` `#[cfg(test)]`:
```rust
#[test]
fn host_user_resolves_ref_to_credential_user() {
    let cred = host_cred("ops", "c1");          // helper: Credential id c1, user "ops"
    let host = host_with_auth(Auth::Ref { credential: cred.id });
    assert_eq!(host_user(&host, &[cred]), "ops");
}

#[test]
fn host_user_is_question_mark_for_dangling_ref() {
    let host = host_with_auth(Auth::Ref { credential: Ulid::from_string("01J00000000000000000000000").unwrap() });
    assert_eq!(host_user(&host, &[]), "?");
}

#[test]
fn host_user_uses_inline_body_or_question_mark_when_empty() {
    let host = host_with_auth(Auth::inline("root".into()));   // helper builds Inline body
    assert_eq!(host_user(&host, &[]), "root");
    let host_empty = host_with_auth(Auth::inline("".into()));
    assert_eq!(host_user(&host_empty, &[]), "?");
}

#[test]
fn host_line_renders_user_at_host_port_and_aligns_columns() {
    let cred = host_cred("root", "c1");
    let host = host_referring(&cred, "web1", "1.2.3.4", 22);
    let line = host_line(&host, "", &[cred], true, 8, 40);
    let s = format!("{line}");
    assert!(s.contains("root@1.2.3.4:22"), "row text was: {s}");
    // Name column is padded to name_w=8: "web1" + 4 spaces, so the address
    // column starts at the same offset on every row.
    assert!(s.contains("web1    "), "name not padded to width 8: {s}");
}

#[test]
fn host_line_uses_question_mark_when_no_user() {
    let host = host_with_auth(Auth::Ref { credential: Ulid::from_string("01J00000000000000000000000").unwrap() });
    let line = host_line(&host, "", &[], false, 8, 40);
    assert!(format!("{line}").contains("?@"));
}
```
(Reuse the file's existing test helpers `host()` / `host_with_id()`; add small helpers as needed. `Auth::inline` = `Auth::Inline(CredentialBody::new(user))`.)

- [ ] **Step 2: Run — expect fail**

`cargo test --bin sshrack launcher::tests::host_user` etc. → FAIL (`host_user`, new `host_line` shape undefined).

- [ ] **Step 3: Implement `host_user`**

```rust
use sshrack_core::config::schema::{Auth, Credential};

/// The connect user for a host: the referenced credential's user for
/// [`Auth::Ref`] (resolved from the credential slice), or the inline body's
/// user. Falls back to `?` when there is no resolvable user (dangling ref or
/// empty inline user) so the `user@host:port` line always has a user slot.
fn host_user(host: &Host, credentials: &[Credential]) -> String {
    match &host.auth {
        Auth::Ref { credential } => credentials
            .iter()
            .find(|c| &c.id == credential)
            .map(|c| c.body.user.clone())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "?".into()),
        Auth::Inline(body) => {
            if body.user.is_empty() { "?".into() } else { body.user.clone() }
        }
    }
}
```

- [ ] **Step 4: Implement the new `host_line`**

```rust
/// Width cap for the adaptive name column. Names longer than this overflow
/// gracefully into the gap rather than squeezing the address column.
const NAME_COL_CAP: usize = 20;

fn host_line(
    host: &Host,
    query: &str,
    credentials: &[Credential],
    frecency: &Frecency,
    selected: bool,
    name_w: usize,
    width: u16,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::with_capacity(8);
    spans.push(theme::focus_marker(selected));

    // Name column (padded to name_w) with fuzzy-match highlighting.
    spans.extend(highlighted_name(&host.name, query));
    let name_pad = name_w.saturating_sub(host.name.chars().count());
    spans.push(Span::raw(" ".repeat(name_pad)));
    spans.push(Span::raw("  ")); // gap between name and address

    // Address column: user@host:port.
    let user = host_user(host, credentials);
    let addr = format!("{user}@{}:{}", host.host, host.port);
    spans.push(Span::styled(addr, Style::new().dim()));

    // Tier badge right-aligned to the list area's right edge.
    let tier = frecency_tier(frecency.score(&host.id));
    let tier_str = format!("[{tier}]");
    let used = 2 + name_w + 2 + addr.chars().count();
    let tier_block = format!("  {tier_str}"); // 2 leading spaces + badge
    let fill = (width as usize).saturating_sub(used + tier_block.chars().count());
    spans.push(Span::raw(" ".repeat(fill)));
    spans.push(Span::styled(tier_block, Style::new().fg(theme::ACCENT).dim()));

    Line::from(spans)
}
```

- [ ] **Step 5: Compute `name_w` + pass `width` from `draw_list`**

In `draw_list`, before building items:
```rust
let name_w = self
    .ranked
    .iter()
    .map(|r| hosts[r.host_idx].name.chars().count())
    .max()
    .unwrap_or(0)
    .min(NAME_COL_CAP);
let items: Vec<Line> = self.ranked.iter().enumerate().map(|(i, r)| {
    host_line(&hosts[r.host_idx], &self.query, credentials, frecency, i == self.selected, name_w, area.width)
}).collect();
```
Thread `credentials: &[Credential]` through `draw_in_shell` → `draw_list` (replacing `credential_names: &CredentialNames`). Delete the old `credential_label` fn and the `use super::CredentialNames;` import (if no longer used in this file — the host wizard uses it independently).

- [ ] **Step 6: Update `app.rs` Hosts call**

```rust
Tab::Hosts => self.launcher.draw_in_shell(
    frame, panel_area, &self.config.hosts, &self.frecency, &self.config.credentials,
),
```

- [ ] **Step 7: Update / remove stale launcher tests**

- Tests asserting the old `(cred)` / `@user` format: rewrite to assert `user@host:port` (or `?@`).
- Tests calling `host_line(...)`: update to the new 6-arg signature.
- Tests calling `draw_in_shell(...)` with `credential_names`: pass a `&[Credential]` slice instead. Update `empty_creds()`-style helpers to return `Vec::new()` of credentials.
- The existing Task-10 gutter regression test (`draw_in_shell_renders_without_panic_sets_cursor_and_uses_gutter`) asserted the `▎` glyph; change it to assert `▶ ` on the selected row.

- [ ] **Step 8: Build + run tests**

```bash
cargo build --workspace
cargo test --bin sshrack launcher
```

- [ ] **Step 9: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A
git commit -m "feat(tui): align host columns and show user@host:port with focus marker"
```

---

## Task 5: cred list — focus marker + column alignment

**Files:**
- Modify: `src/tui/cred_panel.rs` — `cred_row` (marker + name column + user column + right-aligned kind), `draw_list` (compute `name_w`, pass `width`).

**Interfaces:**
- Produces: `fn cred_row(cred: &Credential, selected: bool, name_w: usize, user_w: usize, width: u16) -> Line`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn cred_row_aligns_name_user_and_right_aligns_kind() {
    let c = cred("web-key", "root"); // name web-key, user root, default secret → kind "none"
    let line = cred_row(&c, false, 12, 8, 50);
    let s = format!("{line}");
    // Name padded to 12: "web-key" + 5 spaces.
    assert!(s.contains("web-key     "), "name not padded: {s}");
    // Kind right-aligned (trailing), no plaintext.
    assert!(s.contains("none"), "row text: {s}");
    assert!(!s.contains("hunter2"));
}
```

- [ ] **Step 2: Run — expect fail**

`cargo test --bin sshrack cred_panel::tests::cred_row_aligns_name_user_and_right_aligns_kind` → FAIL (new signature).

- [ ] **Step 3: Implement**

```rust
const CRED_NAME_COL_CAP: usize = 20;
const CRED_USER_COL_CAP: usize = 12;

fn cred_row(cred: &Credential, selected: bool, name_w: usize, user_w: usize, width: u16) -> Line<'static> {
    let user = cred.body.user.clone();
    let kind = match cred.body.secret_kind() {
        SecretKind::Password | SecretKind::KeyringPassword => "password",
        SecretKind::Key => "identity",
        SecretKind::Default => "none",
    };
    let mut spans = vec![theme::focus_marker(selected)];
    // Name column.
    spans.push(Span::raw(cred.name.clone()));
    spans.push(Span::raw(" ".repeat(name_w.saturating_sub(cred.name.chars().count()))));
    spans.push(Span::raw("  "));
    // User column (dim).
    spans.push(Span::styled(user.clone(), Style::new().dim()));
    spans.push(Span::raw(" ".repeat(user_w.saturating_sub(user.chars().count()))));
    // Kind right-aligned.
    let used = 2 + name_w + 2 + user_w;
    let kind_block = format!("  {kind}");
    let fill = (width as usize).saturating_sub(used + kind_block.chars().count());
    spans.push(Span::raw(" ".repeat(fill)));
    spans.push(Span::styled(kind_block, Style::new().dim()));
    Line::from(spans)
}
```

- [ ] **Step 4: Compute widths in `draw_list`**

```rust
let name_w = self.ranked.iter().map(|&i| creds[i].name.chars().count()).max().unwrap_or(0).min(CRED_NAME_COL_CAP);
let user_w = self.ranked.iter().map(|&i| creds[i].body.user.chars().count()).max().unwrap_or(0).min(CRED_USER_COL_CAP);
let items: Vec<Line> = self.ranked.iter().enumerate()
    .map(|(i, &idx)| cred_row(&creds[idx], i == self.selected, name_w, user_w, area.width))
    .collect();
```

- [ ] **Step 5: Update tests**

- `kind_label_maps_each_secret_kind_without_plaintext` etc.: update `cred_row(...)` calls to the new 5-arg signature (pass small `name_w`/`user_w`/`width`).
- The Task-10 gutter regression test: assert `▶ ` (selected) instead of `▎`.

- [ ] **Step 6: Build + tests + clippy + fmt + commit**

```bash
cargo build --workspace && cargo test --bin sshrack cred_panel
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A
git commit -m "feat(tui): align credential columns with focus marker"
```

---

## Task 6: cleanup — drop cancel-noise writes + dead `selected_gutter`; final gate

**Files:**
- Modify: `src/tui/theme.rs` — delete `selected_gutter` + its test (all callers now use `focus_marker`: settings Task 3, launcher Task 4, cred Task 5).
- Modify: `src/tui/app.rs` — remove the cancel-noise status writes: `set_status("cancelled"...)` (×2, the `Outcome::Cancel` arms), `"delete cancelled"` (×4), `"connect cancelled"` (×1). On these arms, simply do not set status (the overlay closing is the feedback).
- Modify: `src/tui/store.rs` — remove the `v.status = Some("cancelled".into())` writes (×3) in the cancel arms of the store switch flow. (Keep the success/failure writes — they are dialog-local feedback for the switch attempt.)

**Interfaces:** none new.

- [ ] **Step 1: Delete `selected_gutter`**

In `src/tui/theme.rs`: remove the `pub fn selected_gutter()` fn and its `selected_gutter_is_accented_bar` test. Run `rg -n 'selected_gutter' src/` → expect empty (confirms all panels migrated). If any hit remains, that caller was missed in Tasks 3-5 — migrate it to `focus_marker` first.

- [ ] **Step 2: Remove cancel-noise status writes**

`cargo build` first to confirm the current state. Then in `src/tui/app.rs`, locate and delete (leaving the surrounding control flow intact — the cancel arm just stops setting status):
- `app.set_status("cancelled".to_string());` (the two `Outcome::Cancel` arms)
- `app.set_status("delete cancelled".to_string());` (×4)
- `app.set_status("connect cancelled".to_string());` (×1)

In `src/tui/store.rs`, delete `v.status = Some("cancelled".into());` (×3). Keep `v.status = Some(format!("switch failed: {e}"))` and the success writes.

Use: `rg -n '"cancelled"|"delete cancelled"|"connect cancelled"' src/tui/` → expect empty after.

- [ ] **Step 3: Update tests**

Any test that asserted a "cancelled"/"delete cancelled"/"connect cancelled" status after an Esc-cancel: update to assert the status is **unchanged/empty** (no longer set). (`rg -n 'cancelled' src/tui/` over test code to find them.)

- [ ] **Step 4: Full workspace gate**

```bash
cargo build --workspace --release
cargo test --workspace           # SSHRACK_PASSPHRASE set
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
rg -n 'selected_gutter|STATUS_LINE|"cancelled"|"delete cancelled"|"connect cancelled"' src/tui/   # expect empty
```

- [ ] **Step 5: Manual smoke**

```bash
cargo run -q --                       # TUI launcher: bordered middle panel, NO F1 help top-right,
                                      #   ONE bottom hint line, selected host shows ▶ (no left shift),
                                      #   columns aligned, rows read user@host:port.
# Press ^a to open add-host wizard, then Esc → overlay closes, NO "cancelled" status lingers.
# Type a query containing 'c' → still filters (single-char conflict fix intact).
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(tui): drop cancel-noise status writes and dead selected_gutter"
```

---

## Self-Review (completed by planner)

**Spec coverage (the 6 user issues):**
- #1 middle border → Task 2. ✅
- #2 remove F1 help → Task 2. ✅
- #3 duplicated footer / initial two-line / cancel-noise → Task 3 (panel status row + STATUS_LINE removed; footer consolidated) + Task 6 (cancel writes removed). ✅
- #4a selected-row left shift → Task 1 (`focus_marker`, 2-cell) + Tasks 3/4/5 (panels adopt it). ✅
- #4b column alignment → Task 4 (host) + Task 5 (cred). ✅
- #4c `user@ip:port` (`?@` fallback) → Task 4 (`host_user`). ✅
- #5 capitalized wizard labels → **GAP: no task above covers the wizard labels.** Add Task 7 below.

> **Planner note — Task 7 added after self-review caught the gap.**

### Task 7: wizard labels capitalized (#5)

**Files:**
- Modify: `src/tui/wizard/mod.rs` — `Field::label()`, `CredField::label()`, `AuthChoice::label()`, `SecretChoice::label()`.
- Modify: `src/tui/wizard/cred.rs` — the static `"identity"` field row (`.field("identity", ...)` → `.field("Identity", ...)`) and the rendered label if it is produced by `CredField` (check: identity may be a chooser row, not a `CredField` variant — verify and capitalize consistently).

**Interfaces:** none new — `label()` signatures unchanged, only the returned `&'static str` values change.

- [ ] **Step 1: Write the failing tests**

In `src/tui/wizard/mod.rs` `#[cfg(test)]`:
```rust
#[test]
fn field_labels_are_capitalized() {
    assert_eq!(Field::Name.label(), "Name");
    assert_eq!(Field::Host.label(), "Host");
    assert_eq!(Field::Port.label(), "Port");
    assert_eq!(Field::User.label(), "User");
}

#[test]
fn cred_field_labels_are_capitalized() {
    assert_eq!(CredField::Name.label(), "CredName".trim_start_matches("Cred")); // adjust to actual variant names
    // i.e. assert_eq!(CredField::Name.label(), "Name");  assert_eq!(CredField::User.label(), "User");
}
```
(Use the real `CredField` variant names — see `wizard/mod.rs:248`. The assertion intent: each label starts with an uppercase letter.)

- [ ] **Step 2: Run — expect fail**

`cargo test --bin sshrack wizard` → FAIL (labels still lowercase).

- [ ] **Step 3: Implement**

In `wizard/mod.rs`, capitalize the first letter of every returned label:
- `Field::Name => "name"` → `"Name"`; `Field::Host => "Host"`; `Field::Port => "Port"`; `Field::User => "User"` (and any other `Field` variant).
- `CredField::Name => "Name"`; `CredField::User => "User"` (and any other variant).
- `AuthChoice::label()` (Default / Credential / InlinePassword / InlineKey): `"Default"` / `"Credential"` / `"Inline password"` / `"Inline key"` (match the existing wording, just capitalized).
- `SecretChoice::label()`: capitalize.

In `wizard/cred.rs:74`, `.field("identity", &self.identity)` → `.field("Identity", &self.identity)`. (Verify this is the displayed label; if `field()`'s first arg is a key not a label, find the actual rendered label and capitalize it.)

Verify the padding widths still hold: host `{label:>5}` (longest label "Name"/"Host"/"Port"/"User" = 4 chars, padded to 5 — fine); cred `{label:>8}` (longest "Identity" = 8 — fits exactly). No padding change needed.

- [ ] **Step 4: Build + tests + clippy + fmt + commit**

```bash
cargo build --workspace && cargo test --bin sshrack wizard
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A
git commit -m "feat(tui): capitalize wizard field labels"
```

---

**Type consistency:** `host_user`/`host_line` signatures match across Task 4 steps; `cred_row` 5-arg signature consistent within Task 5; `focus_marker(bool) -> Span` consistent Task 1 ↔ Tasks 3/4/5; `draw_shell` 5-arg (with `&Status`) consistent Task 3 step 1 ↔ step 3.

**Ordering / dependencies:** Task 1 (theme helper) first — Tasks 3/4/5 consume `focus_marker`. Task 2 (border) before Task 3 (footer) only because both edit `draw_shell` — doing border first leaves Task 3 to add the `status` param cleanly. Tasks 4 and 5 are independent of each other (host vs cred). Task 6 must come after 3/4/5 (it removes `selected_gutter` once all migrated). Task 7 (labels) is independent — can be done at any point.
