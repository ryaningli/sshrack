# TUI Shell + Tabs + Popovers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Rebuild the sshrack TUI from a modal full-screen-switching architecture into a persistent three-pane shell (brand + tab bar / active panel / contextual hotkey bar) with three tabs (Hosts / Credentials / Settings), where add/edit/store-mode/help are overlays (dialogs) layered on top of the shell — and fix the single-character hotkey conflict (every printable char must reach the search box).

**Architecture:** The shell is always present. `App` holds `active_tab: Tab` + `overlay: Option<Overlay>` instead of the old `Mode` enum. Hosts/Credentials panels share a "search box + ranked list" shape; Settings is a one-row list (storage mode only for now). Wizards and the store picker stop being full-screen and render inside a centered `Dialog` overlay. `App::on_key` is a three-layer pure router (global keys → overlay → panel/tab); all printable chars flow into the active panel's query. `on_key` stays pure and unit-tested; all I/O stays in `run_loop`.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30 (now using the `Tabs` widget), crossterm 0.28, nucleo-matcher 0.3.

---

## DESIGN SPEC (binding for every render/key task)

> Every task below MUST honor these decisions. They are not suggestions. If a task's code contradicts this spec, the spec wins.

### Color & style tokens (live in `src/tui/theme.rs`)
| Token | Value | Used for |
|---|---|---|
| `ACCENT` | `Color::Cyan` | active tab underline + label, selected-row gutter `▎`, brand `sshrack`, `(active)` marker, links |
| `MATCH` | `Color::Yellow` + `Modifier::BOLD` | fuzzy-matched chars inside a name |
| `DANGER` | `Color::Red` | errors, delete confirm, downgrade warning |
| `OK` | `Color::Green` | transient success ("saved", "removed", "switched") |
| secondary | `Style::new().dim()` | placeholders, address/port, blurbs, inactive tabs, footer hints |

**Single accent + grayscale.** Do not introduce extra colors for decoration.

### Layout (the shell, always 3 horizontal bands)
```
┌─────────────────────────────────────────────────────────────────┐
│  sshrack        HOSTS   CREDENTIALS   SETTINGS           F1 help │ ← band 1 (1 row): brand + tabs + global hint
├─────────────────────────────────────────────────────────────────┤
│  ❯ <query>█                                                      │ ← band 2: panel (search row + list). Settings has no search row.
│   ... list ...                                                   │
├─────────────────────────────────────────────────────────────────┤
│  Enter connect   ^A add   ^E edit   ^D delete                    │ ← band 3 (1 row): contextual hotkeys
└─────────────────────────────────────────────────────────────────┘
```
- **No full-screen borders around panels.** Bands are separated by a single thin horizontal rule (`Symbols::line::HORIZONTAL` or `"─"`), not bordered `Block`s. The shell itself is borderless.
- **Brand** `sshrack` sits at the left of band 1: `Span::styled("sshrack", Style::new().fg(ACCENT).add_modifier(BOLD))`, followed by a gap, then the `Tabs` widget, then a right-aligned dim `F1 help`.
- **Selected row** = a leading Cyan `▎` gutter + `BOLD` text, **no background fill** (replaces the old `bg(DarkGray)`). Unselected rows start with two spaces.
- **Search box** = `❯ ` prompt (dim) + query text + a real terminal cursor via `frame.set_cursor_position` (replaces the old fake `▍` glyph).
- **Empty state** = one centered dim line, e.g. `No hosts yet — press Ctrl-A to add one`.

### Dialog overlay (replaces full-screen wizards/views)
- Centered, clear-backed (`Clear`), bordered `Block` with a title and **its own 1-row hotkey footer** inside the dialog.
- **No dark scrim.** The underlying shell stays visible (terminal can't do translucency; a fill would fully hide the shell and lose the "floating" feel). Modern feel comes from the dialog chrome (title, inline error, footer, real cursor, padding).
- Size: width `min(80, screen-4)`, height `min(24, screen-4)`; clamped when the terminal is too small (reuse the `centered_rect` clamping idea).

### List rows (single-line, compact)
- **Host row:** `▎ ●  name<space>user@host:port<space>tier` — `●` if auth bound (credential ref or inline key), `○` if default; name shows Yellow-Bold matched chars; endpoint + tier dim. Selected → gutter + bold.
- **Credential row:** `▎ name<space>user · kind` — `kind` ∈ `password` / `identity` / `none`, dim. **Never render any secret material.**
- **Settings row:** `▎ Storage mode<space>keyring` — name left, current value right (accent if active). Only one row for now.

### Keymap (THE contract — fixes the single-char conflict)
**Invariant: the panel search box is the default focus. Every printable single char MUST enter the query. Action hotkeys are NEVER bare printable chars.**

| Key | Panel (no overlay) | Inside overlay |
|---|---|---|
| `Tab` / `Shift-Tab` | cycle tab (Hosts→Creds→Settings) | cycle form field |
| `Ctrl-1` / `Ctrl-2` / `Ctrl-3` | jump to Hosts / Creds / Settings | — |
| `↑` `↓` · `Ctrl-N` `Ctrl-P` | move list selection (wrap) | cycle chooser option |
| printable char · `Backspace` | filter the query | edit focused text field |
| `Enter` | Hosts: connect · Creds: edit · Settings: edit row | chooser confirm / save on last field |
| `Ctrl-A` | add (current tab) | — |
| `Ctrl-E` | edit selected (current tab) | — |
| `Ctrl-D` | delete selected (confirm overlay) | — |
| `Ctrl-S` | — | save form |
| `F1` | open Help overlay | (Help still dismisses) |
| `Esc` | clear query; if empty, quit | close overlay |
| `Ctrl-C` | quit | cancel overlay |

**Removed bindings (must NOT exist after this plan):** `c` (was: add credential), `Shift-C` (was: edit credential), `F2` (was: store view), `?` (was: help). Add-credential and edit-credential now happen inside the Credentials tab via `Ctrl-A`/`Ctrl-E`; storage mode lives in the Settings tab; help is F1-only.

### CLI → TUI entry routing
| CLI | Lands on |
|---|---|
| `sshrack` (bare) | Hosts tab, no overlay |
| `sshrack host add` | Hosts tab + **Add Host overlay** |
| `sshrack host edit <name>` | Hosts tab + **Edit Host overlay** (selection on that name) |
| `sshrack cred add` | Credentials tab + **Add Cred overlay** |
| `sshrack cred edit <name>` | Credentials tab + **Edit Cred overlay** |

---

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, logs, commits.
- **Zero `unsafe`** — never, including tests. Rust 2024 `set_var` is unsafe; tests inject via params/seams.
- **Zero `unwrap()`/`expect()`** in production code — only in `#[cfg(test)]` or `expect("invariant: ...")` for genuinely unreachable states.
- **TDD for pure logic** — RED → GREEN → REFACTOR. `on_key`/decision/router functions are pure.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Passwords are `Zeroizing<String>`** end-to-end; never logged/printed/in errors/argv/`ps`. Keyring mode: main process never materializes keyring plaintext.
- **Never reimplement SSH** — spawn system `ssh`/`scp`.
- **Tests are hermetic** — `cargo test` green in a real shell with `SSHRACK_PASSPHRASE` set; no `env -u` fallback.
- **`sshrack-core` zero-UI invariant** — its `Cargo.toml` never lists `ratatui`/`crossterm`/`nucleo-matcher`/`console`.
- **Dev stage, no compat code** — delete the old `Mode` enum, old full-screen `draw` paths, the `▍` glyph, `bg(DarkGray)` selection, and the removed bindings. No shims.

**Commit style:** `<type>(<scope>): <desc>` (Conventional Commits). Each task ends with a commit.

---

## File Structure (target)

```
src/tui/
├── mod.rs            (modify: EntryMode → (Tab, Option<Overlay>); run() unchanged shape)
├── app.rs            (REWRITE: App fields, on_key 3-layer router, draw shell+panel+overlay; delete Mode)
├── theme.rs          (NEW: color/style tokens)
├── tab.rs            (NEW: Tab enum + pure key→tab-switch decision)
├── shell.rs          (NEW: draw_shell — brand + Tabs + footer bands)
├── dialog.rs         (NEW: Dialog overlay chrome — Clear + centered + titled + footer)
├── panel.rs          (NEW: rank_by_name pure fn; shared row helpers)
├── launcher.rs       (MODIFY: drop own shell/footer; draw search+list only; keep ranking, expose rank_by_name)
├── cred_panel.rs     (NEW: CredPanel — query + selected + ranked; rows; on_key)
├── settings.rs       (NEW: SettingsPanel — one row (storage mode); Enter → store overlay)
├── wizard.rs         (MODIFY: HostForm/CredForm draw() renders inside a Dialog; form logic + on_key unchanged)
├── store.rs          (MODIFY: collapse full-screen StoreView into a store-picker overlay used by Settings)
├── popup.rs          (keep: centered_rect/render_popup still used by password/confirm popups)
├── prompt.rs         (keep: TuiPassphrase, confirm/password/store-pick popups)
├── help.rs           (MODIFY: render inside a Dialog overlay; update keymap text)
└── connect.rs        (keep: connect_host orchestration)
```

---

## Task 1: Design tokens — `src/tui/theme.rs`

**Files:**
- Create: `src/tui/theme.rs`
- Modify: `src/tui/mod.rs` (add `pub mod theme;`)

**Interfaces:**
- Produces: `pub const ACCENT: Color`, `pub const MATCH: Color`, `pub const DANGER: Color`, `pub const OK: Color`; `pub fn accent() -> Style`; `pub fn selected_gutter() -> Span<'static>` (the `▎`); `pub fn brand_span() -> Span<'static>`.

- [ ] **Step 1: Write the failing test**

Create `src/tui/theme.rs` with just the module doc + the test module:

```rust
//! Design tokens for the TUI: a single accent color (Cyan) plus grayscale.
//! Every view draws its colors from here so the palette stays consistent
//! and minimal — no ad-hoc `Color::Foo` scattered across renderers.

#![cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accent_is_cyan() {
        assert_eq!(ACCENT, Color::Cyan);
    }

    #[test]
    fn match_is_yellow_danger_is_red_ok_is_green() {
        assert_eq!(MATCH, Color::Yellow);
        assert_eq!(DANGER, Color::Red);
        assert_eq!(OK, Color::Green);
    }

    #[test]
    fn selected_gutter_is_accented_bar() {
        let span = selected_gutter();
        assert_eq!(span.content.as_ref(), "▎");
    }

    #[test]
    fn brand_span_reads_sshrack() {
        let span = brand_span();
        assert_eq!(span.content.as_ref(), "sshrack");
    }
}
```

- [ ] **Step 2: Run — expect fail (undefined)**

```bash
cargo test -p sshrack --lib tui::theme 2>&1 | tail -5
```
Expected: compile error (`ACCENT` etc. not found).

- [ ] **Step 3: Implement the tokens**

Add above the test module in `src/tui/theme.rs`:

```rust
use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

/// The single accent color: active tab, selected-row gutter, brand, links.
pub const ACCENT: Color = Color::Cyan;
/// Fuzzy-match highlight color.
pub const MATCH: Color = Color::Yellow;
/// Errors, delete confirm, downgrade warning.
pub const DANGER: Color = Color::Red;
/// Transient success messages.
pub const OK: Color = Color::Green;

/// Accent style (fg only). Callers add modifiers as needed.
pub fn accent() -> Style {
    Style::new().fg(ACCENT)
}

/// The leading gutter mark for the selected list row.
pub fn selected_gutter() -> Span<'static> {
    Span::styled("▎", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
}

/// The brand word `sshrack`, accented + bold.
pub fn brand_span() -> Span<'static> {
    Span::styled("sshrack", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
}
```

Then in `src/tui/mod.rs` add `pub mod theme;` alongside the other `pub mod` lines.

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack --lib tui::theme
```
Expected: 4 passed.

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): add centralized design tokens in theme.rs"
```

---

## Task 2: Tab enum + pure tab-switch decision — `src/tui/tab.rs`

**Files:**
- Create: `src/tui/tab.rs`
- Modify: `src/tui/mod.rs` (add `pub mod tab;`)

**Interfaces:**
- Produces: `#[derive(Clone,Copy,PartialEq,Eq)] pub enum Tab { Hosts, Credentials, Settings }`; `pub const TAB_ORDER: &[Tab]`; `impl Tab { pub fn next(self) -> Tab; pub fn prev(self) -> Tab; pub fn idx(self) -> usize; pub fn label(self) -> &'static str }`; `pub enum TabKey { To(Tab), Cycle(i32), None }`; `pub fn tab_key_decision(key: KeyEvent) -> TabKey`.

**Decision rule (pure, TDD):** `Tab` press → `Cycle(1)`; `BackTab` (Shift-Tab) → `Cycle(-1)`; `Ctrl-1` → `To(Hosts)`; `Ctrl-2` → `To(Credentials)`; `Ctrl-3` → `To(Settings)`; anything else → `None`. Bare digits/chars are `None` (they flow into the query).

- [ ] **Step 1: Write the failing test**

```rust
//! The three shell tabs and the pure decision of whether a key switches tabs.
//!
//! The contract: ONLY `Tab` / `Shift-Tab` / `Ctrl-1/2/3` switch tabs. Every
//! printable char returns `TabKey::None` so it reaches the panel search box —
//! this is the fix for the single-character hotkey conflict.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
    }

    #[test]
    fn tab_cycles_forward_backtab_cycles_backward() {
        assert!(matches!(tab_key_decision(press(KeyCode::Tab, KeyModifiers::NONE)), TabKey::Cycle(1)));
        assert!(matches!(tab_key_decision(press(KeyCode::BackTab, KeyModifiers::NONE)), TabKey::Cycle(-1)));
    }

    #[test]
    fn ctrl_digits_jump_to_tabs() {
        assert!(matches!(tab_key_decision(press(KeyCode::Char('1'), KeyModifiers::CONTROL)), TabKey::To(Tab::Hosts)));
        assert!(matches!(tab_key_decision(press(KeyCode::Char('2'), KeyModifiers::CONTROL)), TabKey::To(Tab::Credentials)));
        assert!(matches!(tab_key_decision(press(KeyCode::Char('3'), KeyModifiers::CONTROL)), TabKey::To(Tab::Settings)));
    }

    #[test]
    fn bare_digits_and_chars_do_not_switch_tabs() {
        // The conflict fix: plain '1', '2', '3', 'c', '?' must reach the query.
        for code in [KeyCode::Char('1'), KeyCode::Char('2'), KeyCode::Char('3'),
                     KeyCode::Char('c'), KeyCode::Char('?'), KeyCode::Char('a')] {
            assert!(matches!(tab_key_decision(press(code, KeyModifiers::NONE)), TabKey::None),
                "bare {code:?} must not switch tabs");
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
```

- [ ] **Step 2: Run — expect fail**

```bash
cargo test -p sshrack --lib tui::tab 2>&1 | tail -5
```

- [ ] **Step 3: Implement**

Add above the test module:

```rust
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The three shell tabs. Default is `Hosts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Hosts,
    Credentials,
    Settings,
}

pub const TAB_ORDER: &[Tab] = &[Tab::Hosts, Tab::Credentials, Tab::Settings];

impl Tab {
    pub fn next(self) -> Tab {
        TAB_ORDER[(self.idx() + 1) % TAB_ORDER.len()].idx_to_tab()
    }
    pub fn prev(self) -> Tab {
        let len = TAB_ORDER.len();
        TAB_ORDER[(self.idx() + len - 1) % len].idx_to_tab()
    }
    pub fn idx(self) -> usize {
        TAB_ORDER.iter().position(|t| *t == self).unwrap_or(0)
    }
    pub fn label(self) -> &'static str {
        match self {
            Tab::Hosts => "Hosts",
            Tab::Credentials => "Credentials",
            Tab::Settings => "Settings",
        }
    }
}

trait IdxToTab {
    fn idx_to_tab(self) -> Tab;
}
impl IdxToTab for Tab {
    fn idx_to_tab(self) -> Tab {
        self
    }
}
// (TAB_ORDER stores `Tab` values directly, so indexing already yields a `Tab`;
// the helper above keeps `next`/`prev` readable. If clippy objects, inline it.)
```

If the `IdxToTab` indirection trips clippy, simplify `next`/`prev` to index `TAB_ORDER` directly:
```rust
pub fn next(self) -> Tab { TAB_ORDER[(self.idx() + 1) % TAB_ORDER.len()] }
```

Then the decision function:

```rust
/// Whether a panel-level key switches tabs. Only `Tab`, `Shift-Tab` (BackTab),
/// and `Ctrl-1/2/3` do; everything else is `None` and flows into the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabKey {
    /// Jump directly to a tab (Ctrl-1/2/3).
    To(Tab),
    /// Cycle by `delta` (Tab = +1, BackTab = -1).
    Cycle(i32),
    /// Not a tab key — let the panel handle it (printable chars land here).
    None,
}

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

Add `pub mod tab;` to `src/tui/mod.rs`.

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack --lib tui::tab
```

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): add Tab enum and pure tab-switch key decision"
```

---

## Task 3: Pure `rank_by_name` — generalize ranking — `src/tui/panel.rs`

**Files:**
- Create: `src/tui/panel.rs` (rank helper shared by Hosts + Credentials panels)
- Modify: `src/tui/mod.rs` (add `pub mod panel;`)
- Modify: `src/tui/launcher.rs` — refactor existing `rank_hosts` to delegate to `rank_by_name` (DRY), preserving its public signature `rank_hosts(hosts, frecency, query) -> Vec<RankedHost>`.

**Interfaces:**
- Produces: `pub fn rank_by_name(names: &[String], scores: &[f64], query: &str) -> Vec<usize>` — returns original indices ordered by (non-empty query: nucleo match score desc → `scores` desc → name asc; empty query: `scores` desc → name asc). Non-matches excluded when query non-empty.
- Consumes (launcher refactor): `rank_hosts` builds `names` + `scores` from `hosts`/`frecency` and maps `rank_by_name` results back into `RankedHost`.

- [ ] **Step 1: Write the failing test in `panel.rs`**

```rust
//! Shared ranking helper for the Hosts and Credentials panels: rank a list of
//! names by nucleo fuzzy match (when there's a query) with frecency/name
//! tiebreaks, returning original indices in display order.

use nucleo_matcher::{Config, Matcher, pattern::{Pattern, CaseMatching, Normalization}, Utf32Str};

#[cfg(test)]
mod tests {
    use super::*;

    fn s(xs: &[&str]) -> Vec<String> { xs.iter().map(|x| x.to_string()).collect() }
    fn zero(n: usize) -> Vec<f64> { vec![0.0; n] }

    #[test]
    fn empty_query_orders_by_score_desc_then_name_asc() {
        let names = s(&["beta", "alpha", "gamma"]);
        let scores = vec![1.0, 3.0, 3.0]; // alpha & gamma tie at 3, beta 1
        let order = rank_by_name(&names, &scores, "");
        // alpha before gamma (name asc tiebreak), then beta
        assert_eq!(order, vec![1, 2, 0]);
    }

    #[test]
    fn query_filters_to_matches_only() {
        let names = s(&["web-prod", "db-staging", "web-dev"]);
        let order = rank_by_name(&names, &zero(3), "web");
        let matched: Vec<&str> = order.iter().map(|i| names[*i].as_str()).collect();
        assert_eq!(matched, vec!["web-dev", "web-prod"]); // both match 'web'
    }

    #[test]
    fn query_no_matches_returns_empty() {
        let names = s(&["alpha", "beta"]);
        assert!(rank_by_name(&names, &zero(2), "zzz").is_empty());
    }

    #[test]
    fn query_tiebreaks_by_score_then_name() {
        let names = s(&["web-a", "web-b"]);
        let scores = vec![5.0, 1.0]; // same match score expected; higher frecency first
        let order = rank_by_name(&names, &scores, "web");
        assert_eq!(order, vec![0, 1]);
    }
}
```

- [ ] **Step 2: Run — expect fail**

```bash
cargo test -p sshrack --lib tui::panel 2>&1 | tail -5
```

- [ ] **Step 3: Implement `rank_by_name`**

```rust
/// Rank `names` for display. Empty `query` → frecency `scores` desc then name
/// asc (all returned). Non-empty `query` → only nucleo matches, by match score
/// desc, then `scores` desc, then name asc. Returns original indices.
pub fn rank_by_name(names: &[String], scores: &[f64], query: &str) -> Vec<usize> {
    if query.is_empty() {
        let mut idx: Vec<usize> = (0..names.len()).collect();
        idx.sort_by(|&a, &b| {
            scores[b]
                .partial_cmp(&scores[a])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| names[a].cmp(&names[b]))
        });
        return idx;
    }
    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
    let mut scored: Vec<(usize, u32)> = names
        .iter()
        .enumerate()
        .filter_map(|(i, name)| {
            // nucleo 0.3 `Pattern::score` is 2-arg (no indices buffer); only
            // `Pattern::indices` takes the &mut Vec<u32> (see launcher.rs:521).
            let s = pattern.score(Utf32Str::Ascii(name.as_bytes()), &mut matcher)?;
            Some((i, s))
        })
        .collect();
    scored.sort_by(|&(ia, sa), &(ib, sb)| {
        sb.cmp(&sa)
            .then_with(|| {
                scores[ib]
                    .partial_cmp(&scores[ia])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| names[ia].cmp(&names[ib]))
    });
    scored.into_iter().map(|(i, _)| i).collect()
}
```

> **nucleo 0.3 `Pattern::score` is 2-arg** — `fn score(&self, haystack: Utf32Str, matcher: &mut Matcher) -> Option<u32>`. It does NOT take an indices buffer (only `Pattern::indices` does — see `launcher.rs:521`). `Utf32Str::Ascii(bytes)` needs no scratch buffer (only `Utf32Str::Unicode` does). This is confirmed against the existing code.

- [ ] **Step 4: Refactor `launcher.rs::rank_hosts` to use it**

In `src/tui/launcher.rs`, rewrite the body of `pub fn rank_hosts(hosts: &[Host], frecency: &Frecency, query: &str) -> Vec<RankedHost>` (currently at line 61) to:
1. Build `names: Vec<String> = hosts.iter().map(|h| h.name.clone()).collect()`.
2. Build `scores: Vec<f64> = hosts.iter().map(|h| frecency_score(frecency, h)).collect()` — extract the existing per-host frecency score computation (whatever the current `rank_hosts` uses to compare) into a small `fn frecency_score(frecency, host) -> f64` helper, or inline the same expression. The existing `frecency_cmp`/tier logic tells you the score source; reuse it verbatim.
3. `let order = crate::tui::panel::rank_by_name(&names, &scores, query);`
4. `order.into_iter().map(|i| RankedHost { host_idx: i, score: /* match score or 0 */ }).collect()` — `RankedHost.score` is only used for display tiebreak in tests; set it to `0` if the current callers don't read it, else compute via the same nucleo call. Check call sites first (`rg RankedHost` + `.score`).

Run the **existing** launcher ranking tests; they must still pass unchanged:
```bash
cargo test -p sshrack --lib tui::launcher
```
These tests (`empty_query_orders_by_frecency_score_desc`, `query_filters_to_matches_only`, etc.) are the regression gate for the refactor.

- [ ] **Step 5: Run all panel + launcher tests — pass**

```bash
cargo test -p sshrack --lib tui::panel
cargo test -p sshrack --lib tui::launcher
```

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "refactor(tui): extract rank_by_name; launcher delegates to it"
```

---

## Task 4: Shell renderer — `src/tui/shell.rs`

**Files:**
- Create: `src/tui/shell.rs`
- Modify: `src/tui/mod.rs` (add `pub mod shell;`)

**Interfaces:**
- Produces: `pub fn draw_shell(frame: &mut Frame, area: Rect, active: Tab, footer: &[(&str, &str)]) -> Rect` — renders band 1 (brand + `Tabs` + `F1 help`) and band 3 (the hotkey footer from `footer` pairs), and **returns the band-2 `Rect`** (the panel area) for the caller to fill. `footer` items are `(key, label)` rendered as `key`-accent + `label`-dim, dot-separated.

- [ ] **Step 1: Write the failing test (geometry + no-panic)**

```rust
//! The persistent three-band shell: brand + tab bar on top, the active panel's
//! area in the middle (returned to the caller), and a contextual hotkey footer
//! on the bottom. Pure render — no I/O.

use ratatui::{Frame, layout::Rect};
use crate::tui::tab::Tab;

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn frame_of(w: u16, h: u16) -> Frame<'_> {
        // Draw into a test backend to prove the shell renders without panicking
        // across the three tabs and assorted footer lengths.
        unreachable!("constructed in the test via a Terminal<TestBackend>")
    }

    #[test]
    fn draw_shell_returns_inner_panel_area_and_never_panics() {
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        for active in [Tab::Hosts, Tab::Credentials, Tab::Settings] {
            let mut got = Rect::default();
            term.draw(|f| {
                got = draw_shell(f, f.area(), active,
                    &[("Enter", "connect"), ("^A", "add"), ("F1", "help")]);
            }).unwrap();
            // Inner area is the screen minus the top band (1) and bottom band (1).
            assert_eq!(got.x, 0);
            assert_eq!(got.width, 100);
            assert_eq!(got.height, 30 - 2);
        }
    }

    #[test]
    fn draw_shell_clamps_on_tiny_terminal() {
        let backend = TestBackend::new(20, 3);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| { let _ = draw_shell(f, f.area(), Tab::Hosts, &[]); }).unwrap();
    }
}
```

(Delete the unused `frame_of` stub before committing if clippy flags it; the two `term.draw` tests are the real gate.)

- [ ] **Step 2: Run — expect fail**

```bash
cargo test -p sshrack --lib tui::shell 2>&1 | tail -5
```

- [ ] **Step 3: Implement `draw_shell`**

```rust
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Tabs,
};
use crate::tui::{tab::Tab, theme};

/// Render the brand + tab bar (band 1) and the hotkey footer (band 3), and
/// return the band-2 `Rect` for the active panel to draw into. `footer` is a
/// slice of `(key, label)` pairs joined by ` · ` with keys accented.
pub fn draw_shell(frame: &mut Frame, area: Rect, active: Tab, footer: &[(&str, &str)]) -> Rect {
    let [top, middle, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);

    // ── Band 1: brand · tabs · F1 help ──────────────────────────────────────
    let titles: Vec<Line> = Tab::TAB_ORDER.iter().map(|t| Line::from(t.label())).collect();
    let tabs_index = active.idx();
    let brand_len = 9; // "sshrack"
    let help_text = "F1 help";
    let tabs_area = Rect {
        x: top.x + brand_len + 2,
        width: top.width.saturating_sub((brand_len + 2) + help_text.len() as u16 + 2),
        y: top.y,
        height: 1,
    };
    let tabs = Tabs::new(titles)
        .select(tabs_index)
        .divider(" ")
        .style(Style::new().dim())
        .highlight_style(theme::accent().add_modifier(Modifier::BOLD | Modifier::UNDERLINED));
    frame.render_widget(tabs, tabs_area);
    // Brand on the left.
    frame.render_widget(
        ratatui::widgets::Paragraph::new(Line::from(theme::brand_span())),
        Rect { x: top.x, width: brand_len, y: top.y, height: 1 },
    );
    // Help on the right.
    frame.render_widget(
        ratatui::widgets::Paragraph::new(Line::from(Span::styled(help_text, Style::new().dim())))
            .alignment(Alignment::Right),
        Rect { x: top.x, width: top.width, y: top.y, height: 1 },
    );

    // ── Band 3: contextual footer ───────────────────────────────────────────
    let mut spans: Vec<Span> = Vec::new();
    for (i, (k, label)) in footer.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::new().dim()));
        }
        spans.push(Span::styled(*k, theme::accent().add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {label}"), Style::new().dim()));
    }
    frame.render_widget(
        ratatui::widgets::Paragraph::new(Line::from(spans)),
        bottom,
    );

    middle
}
```

> `Tab::TAB_ORDER` already exists from Task 2. `theme::accent()` and `theme::brand_span()` from Task 1.

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack --lib tui::shell
```

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): add three-band shell renderer (brand, tabs, footer)"
```

---

## Task 5: Dialog overlay chrome — `src/tui/dialog.rs`

**Files:**
- Create: `src/tui/dialog.rs`
- Modify: `src/tui/mod.rs` (add `pub mod dialog;`)

**Interfaces:**
- Produces: `pub fn dialog_area(screen: Rect) -> Rect` (centered, clamped to `min(80, w-4)` × `min(24, h-4)`); `pub fn draw_dialog(frame: &mut Frame, title: &str, body_area_count: u16, footer_hints: &[(&str, &str)]) -> Rect` — clears the dialog area, draws a titled bordered `Block`, a bottom 1-row footer, and **returns the body `Rect`** for the caller (wizard/settings-picker) to fill.

- [ ] **Step 1: Write the failing test (geometry + no-panic)**

```rust
//! Centered dialog overlay chrome: a clear-backed bordered area with a title
//! and its own hotkey footer. The shell stays visible behind it (no dark
//! scrim — terminals can't do translucency). The caller fills the returned
//! body rect.

use ratatui::{Frame, layout::Rect};

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn dialog_area_is_centered_and_clamped() {
        let screen = Rect::new(0, 0, 100, 40);
        let d = dialog_area(screen);
        assert!(d.width <= 80);
        assert!(d.height <= 24);
        // Centered: left margin roughly equals right margin.
        let left = d.x;
        let right = screen.width - (d.x + d.width);
        assert_eq!(left, right);
    }

    #[test]
    fn dialog_area_clamps_on_tiny_screen() {
        let tiny = Rect::new(0, 0, 10, 5);
        let d = dialog_area(tiny);
        assert!(d.width <= tiny.width);
        assert!(d.height <= tiny.height);
    }

    #[test]
    fn draw_dialog_returns_body_area_and_renders_without_panic() {
        let backend = TestBackend::new(100, 40);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let body = draw_dialog(f, " add host ", 5, &[("Tab", "next"), ("^S", "save"), ("Esc", "cancel")]);
            assert!(body.height >= 1);
        }).unwrap();
    }
}
```

- [ ] **Step 2: Run — expect fail**

```bash
cargo test -p sshrack --lib tui::dialog 2>&1 | tail -5
```

- [ ] **Step 3: Implement**

```rust
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear},
};
use crate::tui::theme;

const MAX_W: u16 = 80;
const MAX_H: u16 = 24;

/// Centered, clamped dialog rect inside `screen`.
pub fn dialog_area(screen: Rect) -> Rect {
    let w = MAX_W.min(screen.width.saturating_sub(4));
    let h = MAX_H.min(screen.height.saturating_sub(4));
    if screen.width < 6 || screen.height < 6 {
        return screen;
    }
    let [_, vmid, _] = Layout::vertical([Constraint::Fill(1), Constraint::Length(h), Constraint::Fill(1)]).areas(screen);
    let [_, area, _] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(w), Constraint::Fill(1)]).areas(vmid);
    area
}

/// Clear the dialog area, draw a titled bordered block with a 1-row hotkey
/// footer, and return the body rect for the caller to fill. `body_area_count`
/// is reserved for future use (kept in the signature so callers don't need to
/// change when we size the body explicitly); the body is everything inside the
/// border minus the footer.
pub fn draw_dialog(frame: &mut Frame, title: &str, _body_area_count: u16, footer_hints: &[(&str, &str)]) -> Rect {
    let area = dialog_area(frame.area());
    frame.render_widget(Clear, area);
    let block = Block::new().borders(Borders::ALL).title(format!(" {title} "));
    frame.render_widget(&block, area);
    let inner = block.inner(area);
    let [body, footer] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(inner);

    let mut spans: Vec<Span> = Vec::new();
    for (i, (k, label)) in footer_hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::new().dim()));
        }
        spans.push(Span::styled(*k, theme::accent().add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {label}"), Style::new().dim()));
    }
    frame.render_widget(ratatui::widgets::Paragraph::new(Line::from(spans)), footer);
    body
}
```

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack --lib tui::dialog
```

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): add centered Dialog overlay chrome"
```

---

## Task 6: App model rewrite — `active_tab` + `Overlay`, 3-layer `on_key`, shell `draw`; delete `Mode`

This is the keystone. Tasks 1–5 are its parts; this assembles them. **All persist_* / connect_host I/O functions in `app.rs` stay** — only their call sites move.

**Files:**
- Modify: `src/tui/app.rs` (rewrite `App` fields, `on_key`, `draw`; add `Overlay`; delete `Mode` and `help_prev_mode`)
- Modify: `src/tui/mod.rs` (re-export `Tab`, `Overlay` if needed by `entry_mode`)

**Interfaces:**
- Consumes: `theme`, `tab::{Tab, tab_key_decision, TabKey}`, `shell::draw_shell`, `dialog::draw_dialog`, existing `Launcher`, `HostForm`, `CredForm`, `StoreView`, `connect::connect_host`, all `persist_*` fns (unchanged), `Outcome`.
- Produces:
  - `#[derive(Clone)] pub enum Overlay { Help, HostWizard(HostForm), CredWizard(CredForm), StorePicker, DeleteHost }`
  - `App { active_tab: Tab, overlay: Option<Overlay>, host_panel: Launcher, cred_panel: CredPanel (stub until Task 7; use `Option<CredPanel>` if not ready), settings_panel: SettingsPanel (stub until Task 8), config, config_path, frecency, credential_names, status, pending_connect, pending_delete }`
  - New `Outcome` variants: `OpenOverlay(OverlayKind)`, `CloseOverlay`, `SwitchTab(Tab)`. Keep `ConnectRequested`, `SaveHost`, `SaveCred`, `Cancel`, `SwitchToKeyring/Vault/Plaintext`, `DeleteHost`, `OpenHelp`, `Quit`, `Continue`. (`OpenHelp` can be folded into `OpenOverlay(OverlayKind::Help)` — pick one and be consistent; the loop handles it.)
  - `App::on_key` three layers: (1) global (`Ctrl-C`→Quit, `F1`→toggle Help overlay); (2) if `overlay.is_some()` → route to overlay's `on_key`; (3) else panel layer: `tab_key_decision` first (Tab/BackTab/Ctrl-1/2/3 switch tabs), then `Ctrl-A/E/D` + `Enter` + `Esc`, then the active panel's printable-char/query handling.

> **CredPanel/SettingsPanel don't exist yet.** Use `active_tab` only switching between Hosts (live) and Credentials/Settings (render a centered dim "coming soon" placeholder in Task 6; Tasks 7–8 fill them). This keeps Task 6 self-contained and green.

- [ ] **Step 1: Add the `Overlay` enum and the new `Outcome` variants**

In `src/tui/app.rs`, replace the `Mode` enum (lines ~222–236) with:

```rust
/// An overlay layered on top of the shell. The shell keeps rendering behind it.
#[derive(Clone)]
pub enum Overlay {
    /// The Help keymap reference (F1).
    Help,
    /// Host add/edit wizard.
    HostWizard(HostForm),
    /// Credential add/edit wizard.
    CredWizard(CredForm),
    /// Storage-mode picker (opened from Settings).
    StorePicker,
    /// Delete-current-row confirm (driven via TuiPassphrase::confirm in the loop).
    DeleteHost,
}
```

Extend `Outcome` with:
```rust
    /// Switch the active tab (Tab/Shift-Tab/Ctrl-1/2/3).
    SwitchTab(Tab),
    /// Open an overlay (the variant carries which).
    OpenOverlay(Overlay),
    /// Close the current overlay (Esc / Ctrl-C inside one).
    CloseOverlay,
```

Delete `Outcome::OpenHelp` (replaced by `OpenOverlay(Overlay::Help)`). Update the one place `OpenHelp` was returned (the F1 intercept) and the loop arm.

- [ ] **Step 2: Rewrite `App` fields and constructors**

Replace the `App` struct fields (lines ~286–328) with:

```rust
pub struct App {
    pub should_quit: bool,
    config: SshrackConfig,
    config_path: Option<PathBuf>,
    frecency: Frecency,
    credential_names: CredentialNames,
    active_tab: Tab,
    overlay: Option<Overlay>,
    host_panel: Launcher,
    // Filled by Task 7 / Task 8. Until then the Credentials/Settings tabs render
    // a placeholder; these are Option so construction stays valid now.
    cred_panel: Option<CredPanel>,
    settings_panel: Option<SettingsPanel>,
    status: Status,
    pending_connect: Option<Ulid>,
    pending_delete: Option<Ulid>,
}
```

Update `App::new` to set `active_tab: Tab::Hosts, overlay: None, cred_panel: None, settings_panel: None` and drop `mode`/`help_prev_mode`. Add `pub fn active_tab(&self) -> Tab`, `pub fn overlay(&self) -> Option<&Overlay>` accessors (test-facing).

> `CredPanel` / `SettingsPanel` are forward-declared as empty placeholder types at the bottom of `app.rs` for Task 6 to compile; Tasks 7–8 move them into their own modules:
> ```rust
> // Placeholder until Task 7 (cred_panel.rs) replaces it.
> pub struct CredPanel;
> // Placeholder until Task 8 (settings.rs) replaces it.
> pub struct SettingsPanel;
> ```

- [ ] **Step 3: Rewrite `App::on_key` — the three-layer router (TDD the pure decisions)**

Write the test module additions FIRST (RED) covering: (a) `Ctrl-1/2/3` and `Tab`/`BackTab` switch tabs via `SwitchTab`; (b) a bare `c` / `?` / `1` flows into the host query (the conflict fix); (c) `Ctrl-A` yields `OpenOverlay(Overlay::HostWizard(_))`; (d) `F1` yields `OpenOverlay(Overlay::Help)`; (e) with an overlay open, `Esc` yields `CloseOverlay` and a typed char does NOT touch the query.

Add to the existing `#[cfg(test)] mod tests` in `app.rs`:

```rust
    #[test]
    fn ctrl_digits_and_tab_switch_tab() {
        let mut app = app_with_host("web");
        assert!(matches!(app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)),
                         Outcome::SwitchTab(Tab::Credentials)));
        assert!(matches!(app.on_key(press(KeyCode::Tab, KeyModifiers::NONE)),
                         Outcome::SwitchTab(Tab::Settings)));
    }

    #[test]
    fn bare_chars_c_and_question_and_digit_reach_query() {
        // The conflict fix: these used to be hotkeys (c=?, ?=help). No more.
        let mut app = app_with_host("web");
        for ch in ['c', '?', '1', 'a'] {
            app.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(app.host_panel.query, "c?1a");
    }

    #[test]
    fn ctrl_a_opens_host_wizard_overlay() {
        let mut app = app_with_host("web");
        let out = app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(out, Outcome::OpenOverlay(Overlay::HostWizard(_))));
        assert!(app.overlay.is_some());
    }

    #[test]
    fn f1_opens_help_overlay() {
        let mut app = app_with_host("web");
        let out = app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        assert!(matches!(out, Outcome::OpenOverlay(Overlay::Help)));
    }

    #[test]
    fn esc_inside_overlay_closes_it_and_does_not_touch_query() {
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL)); // open host wizard
        let q_before = app.host_panel.query.clone();
        let out = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(out, Outcome::CloseOverlay));
        assert_eq!(app.host_panel.query, q_before);
    }
```

Then implement `on_key` to make them pass (GREEN):

```rust
pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
    // Layer 1 — global keys (work with or without an overlay).
    if key.kind == KeyEventKind::Press && key.modifiers.contains(KeyModifiers::CONTROL)
        && key.code == KeyCode::Char('c')
    {
        self.should_quit = true;
        return Outcome::Quit;
    }
    if key.kind == KeyEventKind::Press && key.modifiers.is_empty() && key.code == KeyCode::F(1) {
        // Toggle help: open if none, close if Help is up.
        if matches!(self.overlay, Some(Overlay::Help)) {
            self.overlay = None;
            return Outcome::CloseOverlay;
        }
        self.overlay = Some(Overlay::Help);
        return Outcome::OpenOverlay(Overlay::Help);
    }

    // Layer 2 — overlay has focus.
    if let Some(ov) = self.overlay.take() {
        return self.route_overlay(key, ov);
    }

    // Layer 3 — panel/tab layer (no overlay).
    self.route_panel(key)
}
```

`route_overlay`:
```rust
fn route_overlay(&mut self, key: KeyEvent, ov: Overlay) -> Outcome {
    match ov {
        Overlay::Help => {
            if key.kind == KeyEventKind::Press && matches!(key.code, KeyCode::Esc | KeyCode::F(1) | KeyCode::Char('q')) {
                return Outcome::CloseOverlay;
            }
            Outcome::Continue
        }
        Overlay::HostWizard(form) => match form.on_key(key) {
            // HostForm returns SaveHost/Cancel/Continue. Stash the form back
            // unless the wizard signaled a terminal outcome; translate to
            // overlay-aware outcomes.
            Outcome::SaveHost => { self.overlay = Some(Overlay::HostWizard(form)); Outcome::SaveHost }
            Outcome::Cancel => Outcome::CloseOverlay,
            other => { self.overlay = Some(Overlay::HostWizard(form)); other }
        },
        Overlay::CredWizard(form) => match form.on_key(key) {
            Outcome::SaveCred => { self.overlay = Some(Overlay::CredWizard(form)); Outcome::SaveCred }
            Outcome::Cancel => Outcome::CloseOverlay,
            other => { self.overlay = Some(Overlay::CredWizard(form)); other }
        },
        Overlay::StorePicker => {
            // Handled by Settings' StorePicker in Task 8; for now, Esc closes.
            if key.kind == KeyEventKind::Press && key.code == KeyCode::Esc {
                return Outcome::CloseOverlay;
            }
            self.overlay = Some(Overlay::StorePicker);
            Outcome::Continue
        }
        Overlay::DeleteHost => {
            if key.kind == KeyEventKind::Press && key.code == KeyCode::Esc {
                return Outcome::CloseOverlay;
            }
            self.overlay = Some(Overlay::DeleteHost);
            Outcome::Continue
        }
    }
}
```

> **Note on the existing wizard `on_key`:** `HostForm::on_key`/`CredForm::on_key` already return `SaveHost`/`SaveCred`/`Cancel`/`Continue` and manage their own field focus, so they need NO change here. We only re-home them from `Mode`-driven dispatch to `Overlay`-driven dispatch. The form is stored inside the `Overlay` variant between keystrokes.

`route_panel`:
```rust
fn route_panel(&mut self, key: KeyEvent) -> Outcome {
    if key.kind != KeyEventKind::Press {
        return Outcome::Continue;
    }
    // Tab switching first (Tab / BackTab / Ctrl-1/2/3).
    match tab_key_decision(key) {
        TabKey::To(t) => { self.active_tab = t; return Outcome::SwitchTab(t); }
        TabKey::Cycle(d) => {
            let new = if d > 0 { self.active_tab.next() } else { self.active_tab.prev() };
            self.active_tab = new;
            return Outcome::SwitchTab(new);
        }
        TabKey::None => {}
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    // Ctrl-A/E/D act on the current tab's selected row.
    if ctrl && key.code == KeyCode::Char('a') { return self.open_add_overlay(); }
    if ctrl && key.code == KeyCode::Char('e') { return self.open_edit_overlay(); }
    if ctrl && key.code == KeyCode::Char('d') { return self.begin_delete(); }
    // Esc: clear query, or (if empty) quit.
    if key.code == KeyCode::Esc && key.modifiers.is_empty() {
        if self.active_panel_query().is_empty() {
            self.should_quit = true;
            return Outcome::Quit;
        }
        self.clear_active_panel_query();
        return Outcome::Continue;
    }
    // Enter: tab-specific primary action.
    if key.code == KeyCode::Enter && key.modifiers.is_empty() {
        return self.primary_action();
    }
    // Otherwise the active panel consumes it (printable chars → query, arrows → move).
    self.route_active_panel_key(key)
}
```

`open_add_overlay` / `open_edit_overlay` / `begin_delete` / `primary_action` / `route_active_panel_key` / `active_panel_query` / `clear_active_panel_query` are small helpers. For Task 6, only the Hosts branch needs to be real:
```rust
fn open_add_overlay(&mut self) -> Outcome {
    match self.active_tab {
        Tab::Hosts => {
            let names = self.config.credentials.iter().map(|c| c.name.clone()).collect();
            self.overlay = Some(Overlay::HostWizard(HostForm::new_add(names)));
            Outcome::OpenOverlay(self.overlay.clone().unwrap())
        }
        Tab::Credentials => Outcome::Continue, // Task 7
        Tab::Settings => Outcome::Continue,    // Task 8
    }
}
```
(`open_edit_overlay` mirrors it using the host under the cursor via `host_panel.selected_host` and `HostForm::new_edit`, only for `Tab::Hosts` in Task 6. `primary_action` for Hosts delegates to `host_panel.on_key(Enter,...)` to set `pending_connect` and returns `ConnectRequested`; for Creds/Settings it's `Continue` until Tasks 7–8. `route_active_panel_key` for Hosts calls `self.host_panel.on_key(key, &self.config.hosts, &self.frecency)`.)

**Remove** the old `Mode`-based `on_key` body, the `Mode::Launcher` intercepts for `c` / `Shift-C` / `F2` / `?` (these are the conflict sources — their removal is the fix), and the `help_prev_mode` field + `open_help`/`close_help` methods.

- [ ] **Step 4: Rewrite `App::draw` — shell + panel + overlay**

```rust
pub fn draw(&self, frame: &mut Frame) {
    let area = frame.area();
    let footer = self.footer_hints();
    let panel_area = draw_shell(frame, area, self.active_tab, &footer);
    match self.active_tab {
        Tab::Hosts => self.host_panel.draw_in_shell(frame, panel_area, &self.config.hosts,
                                                    &self.frecency, &self.credential_names, &self.status),
        Tab::Credentials => self.draw_placeholder(frame, panel_area, "Credentials"),
        Tab::Settings => self.draw_placeholder(frame, panel_area, "Settings"),
    }
    // Overlay on top.
    if let Some(ov) = &self.overlay {
        self.draw_overlay(frame, ov);
    }
}

fn footer_hints(&self) -> Vec<(&'static str, &'static str)> {
    if self.overlay.is_some() {
        return vec![("Tab", "field"), ("^S", "save"), ("Esc", "cancel")];
    }
    match self.active_tab {
        Tab::Hosts => vec![("Enter", "connect"), ("^A", "add"), ("^E", "edit"), ("^D", "delete"), ("F1", "help")],
        Tab::Credentials => vec![("Enter", "edit"), ("^A", "add"), ("^E", "edit"), ("^D", "delete"), ("F1", "help")],
        Tab::Settings => vec![("Enter", "edit"), ("F1", "help")],
    }
}

fn draw_overlay(&self, frame: &mut Frame, ov: &Overlay) {
    match ov {
        Overlay::Help => crate::tui::help::draw_help_dialog(frame),
        Overlay::HostWizard(form) => {
            let body = draw_dialog(frame, &form.title(), 0, &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")]);
            form.draw_in_dialog(frame, body);
        }
        Overlay::CredWizard(form) => {
            let body = draw_dialog(frame, &form.title(), 0, &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")]);
            form.draw_in_dialog(frame, body);
        }
        Overlay::StorePicker | Overlay::DeleteHost => {
            // Filled by Task 8 / the loop's popup path. Render an empty dialog
            // for now so the overlay shows.
            let _ = draw_dialog(frame, "…", 0, &[("Esc", "cancel")]);
        }
    }
}

fn draw_placeholder(&self, frame: &mut Frame, area: Rect, name: &str) {
    let line = ratatui::text::Line::from(ratatui::text::Span::styled(
        format!("{name} tab — coming soon"), ratatui::style::Style::new().dim(),
    ));
    frame.render_widget(ratatui::widgets::Paragraph::new(line).alignment(ratatui::layout::Alignment::Center), area);
}
```

> `Launcher::draw_in_shell`, `HostForm::draw_in_dialog`, `CredForm::draw_in_dialog`, `help::draw_help_dialog` are NEW thin render entrypoints added in Steps 5–6 below. They adapt the existing render code to the newchrome.

- [ ] **Step 5: Adapt `Launcher` rendering — `draw_in_shell` + `draw_search_row` (real cursor) + bordered-less list**

In `src/tui/launcher.rs`, add `pub fn draw_in_shell(&self, frame, area, hosts, frecency, credential_names, status)` that:
1. Splits `area` into `[search_row(1), list(Fill), status_row(1)]` — **no `Block::bordered`** around anything.
2. `draw_search_row` renders `❯ ` (dim) + query + places the real cursor at the end via `frame.set_cursor_position((area.x + 2 + query_char_count, search_row.y))`.
3. Renders the ranked list with the **selected-row gutter** (`theme::selected_gutter()` + bold) instead of `bg(DarkGray)`. Keep the existing `host_line` / `highlighted_name` / `credential_label` helpers.
4. Renders the status row from `status` (errors red, info normal, empty → dim default hint).

Keep the old `draw_with_status` only if something still calls it; otherwise delete it (grep first). Delete the `▍` cursor glyph (`STATUS_LINE` / `draw_query`'s `▍`).

- [ ] **Step 6: Adapt `HostForm`/`CredForm` rendering — `draw_in_dialog`**

In `src/tui/wizard.rs`, add `pub fn draw_in_dialog(&self, frame, body: Rect)` for both forms. These render the **same field rows** the existing `draw` does (the `render_row`/`cursor_target`/`value_spans` logic is reused verbatim), but into the `body` rect the dialog hands them (no outer `Block::bordered` — the dialog already drew the border + title + footer). Real cursor via `frame.set_cursor_position` exactly as today, offset into `body`. Delete the old full-screen `draw(&self, frame, area)` once nothing calls it (the old `App::draw` did; the new one calls `draw_in_dialog`).

- [ ] **Step 7: Update `run_loop` for the new outcomes**

In `src/tui/app.rs::run_loop`, replace the `Mode`-driven close logic with overlay-aware handling:
- `Outcome::SwitchTab(_) | Outcome::OpenOverlay(_) | Outcome::CloseOverlay | Outcome::Continue` → for `CloseOverlay`, set `app.overlay = None` and a "cancelled"/default status; the others just re-render.
- `Outcome::SaveHost` → `persist_host_save`; on Ok, close the host overlay (`app.overlay = None`) + status "host saved"; on Err, the form is still in the overlay — set its core error (`if let Some(Overlay::HostWizard(w)) = &mut app.overlay { w.set_core_error(...) }`).
- `Outcome::SaveCred` → `fulfill_save_cred` (unchanged), then close the cred overlay on success.
- `Outcome::ConnectRequested` → unchanged (`connect_host`).
- `Outcome::DeleteHost` → unchanged popup path, then `app.overlay = None`.
- `Outcome::SwitchToKeyring/Vault/Plaintext` → `persist_store_switch` (unchanged), then close the StorePicker overlay.
- `Outcome::Quit` → `return None`.

- [ ] **Step 8: Update `apply_entry_mode` + `EntryMode` (minimal)**

In `src/tui/mod.rs`, leave `EntryMode`/`entry_mode_from_cmd` as-is for Task 6 (Task 11 rewires them to tabs+overlays). But `App::apply_entry_mode` must compile against the new model — for now it opens overlays instead of setting `mode`:
```rust
pub fn apply_entry_mode(&mut self, mode: super::EntryMode) {
    match mode {
        super::EntryMode::Launcher => {}
        super::EntryMode::HostWizard { edit_name: None } => { self.open_host_wizard_add_overlay(); }
        super::EntryMode::HostWizard { edit_name: Some(name) } => {
            if !self.open_host_wizard_edit_by_name(&name) {
                self.status = Status::error(format!("host '{name}' not found"));
            }
        }
        super::EntryMode::CredWizard { edit_name: None } => { self.open_cred_wizard_add_overlay(); }
        super::EntryMode::CredWizard { edit_name: Some(name) } => {
            if !self.open_cred_wizard_edit_by_name(&name) {
                self.status = Status::error(format!("credential '{name}' not found"));
            }
        }
    }
}
```
(These `open_*_overlay` helpers set `self.overlay = Some(Overlay::HostWizard(...))` instead of the old `self.mode = Mode::HostWizard`. Keep the existing `open_host_wizard_edit_by_name` lookup logic.)

- [ ] **Step 9: Update the existing app tests**

The existing `#[cfg(test)]` tests in `app.rs` reference `Mode`, `app.mode()`, `app.launcher.status`, `close_host_wizard`, etc. Update them to the new model:
- Tests that asserted `*app.mode() == Mode::HostWizard` now assert `matches!(app.overlay, Some(Overlay::HostWizard(_)))`.
- Tests that called `app.close_host_wizard()` now set `app.overlay = None` (or call a new `app.close_overlay()` helper).
- `app.launcher.status` reads become `app.status` reads (the launcher no longer owns a status line).
- The Esc-clears-query tests stay valid (they already go through `on_key`).

Delete any test that exercised the removed `c`/`Shift-C`/`F2`/`?` bindings — they are obsolete (the conflict fix removes those bindings).

- [ ] **Step 10: Run the full suite — pass**

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 11: Commit**

```bash
git add -A && git commit -m "refactor(tui): rewrite App to active_tab+Overlay with 3-layer on_key; delete Mode"
```

---

## Task 7: Credentials panel — `src/tui/cred_panel.rs`

**Files:**
- Create: `src/tui/cred_panel.rs`
- Modify: `src/tui/mod.rs` (add `pub mod cred_panel;`)
- Modify: `src/tui/app.rs` (replace the `CredPanel` placeholder; wire `Tab::Credentials` panel routing + add/edit/delete/Enter)

**Interfaces:**
- Produces: `pub struct CredPanel { pub query: String, pub selected: usize, pub ranked: Vec<usize> }`; `pub fn rank_credentials(creds: &[Credential], query: &str) -> Vec<usize>` (delegates to `panel::rank_by_name` with zero frecency); `impl CredPanel { pub fn new() -> Self; pub fn recompute(&mut self, creds: &[Credential]); pub fn selected_credential<'a>(&self, creds: &'a [Credential]) -> Option<&'a Credential>; pub fn on_key(&mut self, key: KeyEvent, creds: &[Credential]) -> Outcome; pub fn draw_in_shell(&self, frame, area, creds, status) }`.

**Decision rule:** printable → query + recompute; `Backspace` → pop; `Up/Down`·`Ctrl-N/P` → move (wrap, clamp); `Enter` → `Outcome::OpenOverlay(Overlay::CredWizard(edit))`; `Esc` → handled by App (clear/quit). NO single-char hotkeys. Rows: `▎ name   user · kind` (kind ∈ password/identity/none; never a secret).

- [ ] **Step 1: Write failing tests (ranking + on_key purity)**

```rust
//! The Credentials panel: query + ranked credential list. Mirrors the Hosts
//! panel shape but over credentials, with no frecency (alphabetical when the
//! query is empty). No secret material is ever rendered.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use crate::tui::app::Outcome;

#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::config::schema::{Credential, CredentialBody};

    fn cred(name: &str, user: &str) -> Credential {
        Credential { id: ulid::Ulid::new(), name: name.into(), body: CredentialBody::new(user) }
    }
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    #[test]
    fn empty_query_ranks_alphabetically() {
        let creds = vec![cred("beta", "u"), cred("alpha", "u")];
        let order = rank_credentials(&creds, "");
        assert_eq!(order, vec![1, 0]); // alpha, beta
    }

    #[test]
    fn query_filters_by_name() {
        let creds = vec![cred("web-prod", "u"), cred("db", "u"), cred("web-dev", "u")];
        let order = rank_credentials(&creds, "web");
        let names: Vec<&str> = order.iter().map(|i| creds[*i].name.as_str()).collect();
        assert_eq!(names, vec!["web-dev", "web-prod"]);
    }

    #[test]
    fn printable_chars_enter_query() {
        let mut p = CredPanel::new();
        let creds = vec![cred("c-name", "u")];
        p.on_key(key(KeyCode::Char('c')), &creds); // 'c' must be a query char, not a hotkey
        assert_eq!(p.query, "c");
    }

    #[test]
    fn backspace_pops_query() {
        let mut p = CredPanel::new();
        let creds = vec![cred("a", "u")];
        p.on_key(key(KeyCode::Char('a')), &creds);
        p.on_key(key(KeyCode::Backspace), &creds);
        assert!(p.query.is_empty());
    }

    #[test]
    fn down_then_up_moves_selection_and_wraps() {
        let mut p = CredPanel::new();
        let creds = vec![cred("a", "u"), cred("b", "u"), cred("c", "u")];
        p.recompute(&creds);
        assert_eq!(p.selected, 0);
        p.on_key(key(KeyCode::Down), &creds);
        assert_eq!(p.selected, 1);
        p.on_key(key(KeyCode::Down), &creds);
        p.on_key(key(KeyCode::Down), &creds); // wrap
        assert_eq!(p.selected, 0);
    }
}
```

- [ ] **Step 2: Run — expect fail**

```bash
cargo test -p sshrack --lib tui::cred_panel 2>&1 | tail -5
```

- [ ] **Step 3: Implement `CredPanel`**

```rust
use crate::tui::{app::Outcome, panel::rank_by_name, theme};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListState, Paragraph},
};
use sshrack_core::config::schema::{Credential, SecretKind};

pub struct CredPanel {
    pub query: String,
    pub selected: usize,
    pub ranked: Vec<usize>,
}

impl CredPanel {
    pub fn new() -> Self {
        Self { query: String::new(), selected: 0, ranked: Vec::new() }
    }

    pub fn recompute(&mut self, creds: &[Credential]) {
        self.ranked = rank_credentials(creds, &self.query);
        if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len().saturating_sub(1);
        }
    }

    pub fn selected_credential<'a>(&self, creds: &'a [Credential]) -> Option<&'a Credential> {
        self.ranked.get(self.selected).and_then(|i| creds.get(*i))
    }

    pub fn on_key(&mut self, key: KeyEvent, creds: &[Credential]) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        match key.code {
            KeyCode::Backspace => { self.query.pop(); self.recompute(creds); Outcome::Continue }
            KeyCode::Down if !key.modifiers.contains(KeyModifiers::CONTROL) => { self.move_sel(1); Outcome::Continue }
            KeyCode::Up if !key.modifiers.contains(KeyModifiers::CONTROL) => { self.move_sel(-1); Outcome::Continue }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => { self.move_sel(1); Outcome::Continue }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => { self.move_sel(-1); Outcome::Continue }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.query.push(c); self.recompute(creds); Outcome::Continue
            }
            _ => Outcome::Continue,
        }
    }

    fn move_sel(&mut self, delta: i32) {
        let len = self.ranked.len() as i32;
        if len == 0 { self.selected = 0; return; }
        self.selected = ((self.selected as i32 + delta).rem_euclid(len)) as usize;
    }

    pub fn draw_in_shell(&self, frame: &mut Frame, area: ratatui::layout::Rect, creds: &[Credential], status: &crate::tui::app::Status) {
        // Same search-row + list + status shape as the Hosts panel.
        let [search, list_area, status_area] = Layout::vertical([
            Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1),
        ]).areas(area);
        // Search row with real cursor.
        let mut line = vec![Span::styled("❯ ", Style::new().dim()), Span::raw(self.query.clone())];
        frame.render_widget(Paragraph::new(Line::from(line)), search);
        if let Some(&i) = self.ranked.get(self.selected) {
            let _ = i;
        }
        let qc = self.query.chars().count() as u16;
        frame.set_cursor_position((search.x + 2 + qc, search.y));
        let _ = &mut line; // (keep clippy happy about the vec reuse)

        let items: Vec<Line> = self.ranked.iter().map(|&idx| cred_row(&creds[idx], false)).collect();
        let mut list = List::new(items).highlight_style(Style::new().add_modifier(Modifier::BOLD));
        let _ = &mut list;
        let mut state = ListState::default();
        state.select(Some(self.selected));
        // Render each row manually to get the gutter + dim secondary; the
        // List highlight only bolds. (For the selected gutter, draw via a
        // manual loop if the List widget's highlight doesn't show the ▎ —
        // see Hosts panel's approach and mirror it.)
        frame.render_stateful_widget(list, list_area, &mut state);

        let s = match &status.message {
            Some(msg) => Line::from(vec![
                Span::styled("status: ", Style::new().dim()),
                Span::styled(msg.clone(), if status.is_error { Style::new().fg(crate::tui::theme::DANGER) } else { Style::new() }),
            ]),
            None => Line::from(Span::styled("type to filter credentials · Enter to edit", Style::new().dim())),
        };
        frame.render_widget(Paragraph::new(s), status_area);
    }
}

pub fn rank_credentials(creds: &[Credential], query: &str) -> Vec<usize> {
    let names: Vec<String> = creds.iter().map(|c| c.name.clone()).collect();
    let scores = vec![0.0; creds.len()];
    rank_by_name(&names, &scores, query)
}

fn cred_row(cred: &Credential, _selected: bool) -> Line<'static> {
    let user = cred.body.user.clone();
    let kind = match cred.body.secret_kind() {
        SecretKind::Password | SecretKind::KeyringPassword => "password",
        SecretKind::Key => "identity",
        SecretKind::Default => "none",
    };
    Line::from(vec![
        Span::raw("  "),
        Span::raw(cred.name.clone()),
        Span::raw("   "),
        Span::styled(format!("{user} · {kind}"), Style::new().dim()),
    ])
}
```

> **Mirror the Hosts panel's exact gutter approach.** If Task 6's `Launcher::draw_in_shell` draws the selected gutter by rendering rows manually (not via `List::highlight_style`), do the same here so both panels look identical. Check `CredentialBody::secret_kind` exists in core (`rg 'fn secret_kind' crates/sshrack-core/src/`) — if it's named differently (e.g. a `match self.secret`), adapt `cred_row`. **Never** read `body.password` plaintext into a row.

- [ ] **Step 4: Wire `Tab::Credentials` in `app.rs`**

- Remove the `CredPanel` placeholder; `use crate::tui::cred_panel::CredPanel;`. Change the field to `cred_panel: CredPanel` and set `cred_panel: CredPanel::new()` in `App::new`.
- In `recompute` call sites (after config reload), also call `self.cred_panel.recompute(&self.config.credentials)`.
- In `route_panel`, the printable/arrow keys for `Tab::Credentials` route to `self.cred_panel.on_key(key, &self.config.credentials)`.
- `primary_action` for `Tab::Credentials` → open `Overlay::CredWizard(CredForm::new_edit(selected))` (Enter = edit); if none selected, status hint.
- `open_add_overlay` Credentials branch → `Overlay::CredWizard(CredForm::new_add())`.
- `open_edit_overlay` Credentials branch → edit the selected credential.
- `draw` `Tab::Credentials` → `self.cred_panel.draw_in_shell(frame, panel_area, &self.config.credentials, &self.status)` (drop the placeholder).
- Add `Outcome::SaveCred` loop handling already exists; ensure on success it closes the cred overlay (`app.overlay = None`) and `self.cred_panel.recompute(...)` after reload.

- [ ] **Step 5: Run — pass**

```bash
cargo test -p sshrack --lib tui::cred_panel
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(tui): add Credentials panel (search + ranked list, no secrets rendered)"
```

---

## Task 8: Settings panel + storage-mode overlay — `src/tui/settings.rs`

**Files:**
- Create: `src/tui/settings.rs`
- Modify: `src/tui/mod.rs` (add `pub mod settings;`)
- Modify: `src/tui/app.rs` (replace `SettingsPanel` placeholder; `Enter` on the storage row opens `Overlay::StorePicker`; loop handles `SwitchTo*` from the picker)
- Modify: `src/tui/store.rs` (change `StoreView::draw` to render inside a dialog body — `pub fn draw_in_dialog(&self, frame, body)`; keep `on_key`)

**Interfaces:**
- Produces: `pub struct SettingsPanel { pub selected: usize }` (one row for now); `impl SettingsPanel { pub fn on_key(&mut self, key) -> Outcome; pub fn draw_in_shell(&self, frame, area, current_mode_label, status) }`. `StoreView::draw_in_dialog(frame, body)` renders the three modes list into the dialog body.

**Decision rule:** Settings has no search box. `Up/Down` moves the single row (no-op with one row); `Enter` → `Outcome::OpenOverlay(Overlay::StorePicker)`; `Esc` → App clear/quit. The `StorePicker` overlay reuses the existing `StoreView::on_key` (Up/Down/Enter → `SwitchTo{Keyring,Vault,Plaintext}` / Esc → `Cancel`); the loop's existing `persist_store_switch` does the I/O and closes the overlay.

- [ ] **Step 1: Write failing tests**

```rust
//! The Settings panel. Today it exposes a single row — the password storage
//! mode — which opens the store-picker overlay on Enter.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crate::tui::app::Outcome;

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    #[test]
    fn enter_opens_store_picker_overlay() {
        let mut p = SettingsPanel::new();
        let out = p.on_key(key(KeyCode::Enter));
        assert!(matches!(out, Outcome::OpenOverlay(Overlay::StorePicker)));
    }

    #[test]
    fn arrows_do_not_crash_single_row() {
        let mut p = SettingsPanel::new();
        p.on_key(key(KeyCode::Down));
        p.on_key(key(KeyCode::Up));
        assert_eq!(p.selected, 0);
    }
}
```

(Import `Overlay` from `crate::tui::app`.)

- [ ] **Step 2: Run — expect fail**

```bash
cargo test -p sshrack --lib tui::settings 2>&1 | tail -5
```

- [ ] **Step 3: Implement `SettingsPanel`**

```rust
use crate::tui::{app::{Outcome, Overlay}, theme};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

pub struct SettingsPanel {
    pub selected: usize,
}

impl SettingsPanel {
    pub fn new() -> Self { Self { selected: 0 } }

    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        match key.code {
            KeyCode::Enter => Outcome::OpenOverlay(Overlay::StorePicker),
            _ => Outcome::Continue,
        }
    }

    pub fn draw_in_shell(&self, frame: &mut Frame, area: ratatui::layout::Rect, current_mode: &str, status: &crate::tui::app::Status) {
        // No search row for Settings; just the list + status footer.
        let [list_area, _, status_area] = Layout::vertical([
            Constraint::Length(2), Constraint::Fill(1), Constraint::Length(1),
        ]).areas(area);

        let value_span = if current_mode == "undecided" {
            Span::styled(format!("{current_mode} ▸"), Style::new().fg(theme::DANGER))
        } else {
            Span::styled(format!("{current_mode} ▸"), theme::accent().add_modifier(Modifier::BOLD))
        };
        let row = Line::from(vec![
            theme::selected_gutter(),
            Span::raw(" Storage mode"),
            Span::raw("    "),
            value_span,
        ]);
        frame.render_widget(Paragraph::new(row), list_area);

        let s = match &status.message {
            Some(msg) => Line::from(vec![
                Span::styled("status: ", Style::new().dim()),
                Span::styled(msg.clone(), if status.is_error { Style::new().fg(theme::DANGER) } else { Style::new() }),
            ]),
            None => Line::from(Span::styled("Enter to change a setting", Style::new().dim())),
        };
        frame.render_widget(Paragraph::new(s), status_area);
    }
}
```

- [ ] **Step 4: Change `StoreView` to render inside a dialog**

In `src/tui/store.rs`, add `pub fn draw_in_dialog(&self, frame: &mut Frame, body: ratatui::layout::Rect)` that renders the existing three-mode list (`mode_line`) + active marker into `body`, **without** its own outer `Block::bordered` (the dialog supplies chrome). Keep `StoreView::on_key` unchanged (it returns `SwitchTo{Keyring,Vault,Plaintext}`/`Cancel`). Delete the old full-screen `draw` once `app.rs` no longer calls it.

- [ ] **Step 5: Wire `Tab::Settings` + the `StorePicker` overlay in `app.rs`**

- Replace the `SettingsPanel` placeholder; `settings_panel: SettingsPanel` set in `App::new`.
- `route_panel` for `Tab::Settings` → `self.settings_panel.on_key(key)` (Up/Down/Enter; printable chars are ignored — Settings has no query).
- `draw` `Tab::Settings` → `self.settings_panel.draw_in_shell(frame, panel_area, self.current_store_mode_label(), &self.status)`.
- `draw_overlay` `Overlay::StorePicker` → `let body = draw_dialog(frame, " storage mode ", 0, &[("↑↓", "select"), ("Enter", "switch"), ("Esc", "cancel")]); self.store_view.as_ref().expect("store picker open").draw_in_dialog(frame, body);` (build the `StoreView` when opening the overlay; store it on `App` as it is today).
- Opening: `primary_action`/`Enter` on Settings builds `StoreView::new(Some(self.current_store_mode_label()))`, stashes it, and returns `OpenOverlay(Overlay::StorePicker)`.
- Loop: `Outcome::SwitchToKeyring/Vault/Plaintext` already call `persist_store_switch`; on `Ok(true)` also set `app.overlay = None` (close the picker). On `Ok(false)`/`Err(Interrupted)` keep the picker open with the status.

- [ ] **Step 6: Run — pass**

```bash
cargo test -p sshrack --lib tui::settings
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(tui): add Settings panel with storage-mode picker overlay"
```

---

## Task 9: Polish host/cred wizard rendering inside the dialog

Task 6 added `draw_in_dialog` shims; this task makes them visually correct and removes the old full-screen draw path for good.

**Files:**
- Modify: `src/tui/wizard.rs` — finalize `HostForm::draw_in_dialog` / `CredForm::draw_in_dialog` (real cursor offset into `body`, inline error row, field rows with `theme::accent` focus label); delete the old `pub fn draw(&self, frame, area)`.

**Interfaces:** unchanged signatures from Task 6 (`pub fn draw_in_dialog(&self, frame: &mut Frame, body: Rect)`).

- [ ] **Step 1: Write a no-panic render test (HostForm + CredForm across focus/auth states)**

The existing tests `draw_renders_without_panic_across_focus_and_auth_states` and `cred_draw_renders_without_panic_across_focus_and_secret_states` (wizard.rs) used the old full-screen `draw`. Rewrite them to call `draw_in_dialog` with a body rect from `TestBackend`:

```rust
#[test]
fn draw_in_dialog_renders_without_panic_across_focus_and_auth_states() {
    for focus in Field::ORDER {
        let mut form = complete_form();
        form.focus = *focus;
        for auth in [AuthChoice::Default, AuthChoice::Credential { idx: 0 }, AuthChoice::InlineKey { path: String::from("/k") }] {
            form.auth_choice = auth.clone();
            let backend = ratatui::backend::TestBackend::new(100, 40);
            let mut term = ratatui::Terminal::new(backend).unwrap();
            term.draw(|f| {
                let body = crate::tui::dialog::draw_dialog(f, &form.title(), 0,
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")]);
                form.draw_in_dialog(f, body);
            }).unwrap();
        }
    }
}
```

(Adapt for `CredForm` symmetrically. `AuthChoice` may need `Clone` — add the derive if missing.)

- [ ] **Step 2: Run — expect fail (old draw gone / new shim incomplete)**

```bash
cargo test -p sshrack --lib tui::wizard 2>&1 | tail -10
```

- [ ] **Step 3: Finalize `draw_in_dialog`**

Port the field-row rendering from the old `draw` into `draw_in_dialog`, but:
- No outer `Block::bordered` (the dialog drew it).
- Layout `body` into `[fields(Fill), error(1)]`.
- Focus label uses `theme::accent().add_modifier(BOLD)` instead of `Color::Yellow` (consolidate on the accent token).
- Real cursor via `frame.set_cursor_position((body.x + VALUE_COL + offset, body.y + focus.idx()))`, exactly as today but offset by `body.x`/`body.y`.
- Error row uses `theme::DANGER`.

Delete the old `pub fn draw(&self, frame, area)`.

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack --lib tui::wizard
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor(tui): render host/cred wizards inside Dialog; drop full-screen draw"
```

---

## Task 10: Visual unification — real search cursor, gutter selection, theme sweep

**Files:**
- Modify: `src/tui/launcher.rs` — replace `bg(DarkGray)` selection with `theme::selected_gutter()` + bold; remove the `▍` glyph; ensure `frame.set_cursor_position` on the search row.
- Modify: `src/tui/cred_panel.rs` — same gutter/real-cursor treatment (mirror launcher).
- Modify: `src/tui/app.rs` — `draw_shell` footer already uses theme; verify status row uses `theme::DANGER`/`OK`.
- Audit: grep for `DarkGray`, `▍`, `Color::Yellow` (replace Yellow-as-focus with `theme::accent`; keep Yellow only as `theme::MATCH` for fuzzy highlights), `borders(Borders::ALL` on panels (panels should be borderless; only dialogs and the help overlay keep borders).

- [ ] **Step 1: Add regression tests pinning the new visuals are selector-based**

These are light geometry/no-panic tests (render output isn't asserted byte-for-byte):

```rust
// in launcher.rs tests
#[test]
fn draw_in_shell_renders_without_panic_and_sets_cursor() {
    let backend = ratatui::backend::TestBackend::new(100, 30);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    let mut p = Launcher::new(&[host(0, "web")], &frecency_default());
    p.query = "w".into();
    term.draw(|f| {
        let area = crate::tui::shell::draw_shell(f, f.area(), crate::tui::tab::Tab::Hosts,
            &[("Enter", "connect"), ("^A", "add")]);
        p.draw_in_shell(f, area, &[], &crate::tui::frecency::Frecency::default(),
            &std::collections::HashMap::new(), &crate::tui::app::Status::empty());
    }).unwrap();
    // set_cursor_position was called (no panic, no assert on exact coords here).
}
```

- [ ] **Step 2: Sweep the code**

```bash
rg -n 'DarkGray|▍|Color::Yellow' src/tui/
```
For each hit:
- `DarkGray` (selection bg) → remove; use `theme::selected_gutter()` + bold.
- `▍` (fake cursor) → remove; use `frame.set_cursor_position`.
- `Color::Yellow` as a focus/label color → `theme::accent()`. Keep `Color::Yellow` only behind `theme::MATCH` (fuzzy highlight spans).

- [ ] **Step 3: Run + audit**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
rg -n 'DarkGray|▍' src/tui/ || true   # expect empty
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "style(tui): real search cursor, gutter selection, accent-only focus colors"
```

---

## Task 11: CLI entry routing → tabs + overlays

**Files:**
- Modify: `src/tui/mod.rs` — extend `EntryMode` to carry the target tab; `entry_mode_from_cmd` maps each shape to `(Tab, Option<Overlay-init>)`; `run()` calls `app.apply_entry_mode` which sets `active_tab` + opens the overlay.

- [ ] **Step 1: Update the decision-table tests**

The existing tests `bare_maps_to_launcher`, `host_add_empty_maps_to_host_add_wizard`, etc. (mod.rs) assert `EntryMode` variants. Extend them to also assert the tab: bare → `Tab::Hosts` no overlay; `host add` → `Tab::Hosts` + host-wizard overlay; `cred add` → `Tab::Credentials` + cred-wizard overlay; `host edit <n>` → `Tab::Hosts` + edit overlay; `cred edit <n>` → `Tab::Credentials` + edit overlay.

- [ ] **Step 2: Run — expect fail**

```bash
cargo test -p sshrack --lib tui::tests 2>&1 | tail -10
```

- [ ] **Step 3: Implement**

Extend `EntryMode` (or add a parallel `Entry { tab: Tab, overlay: Option<OverlaySeed> }`) and update `entry_mode_from_cmd` + `App::apply_entry_mode` so the landing tab + overlay match the spec table in the DESIGN SPEC. `apply_entry_mode` sets `self.active_tab` then opens the overlay via the same `open_*_overlay` helpers used by the panel hotkeys.

- [ ] **Step 4: Run — pass**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(tui): route CLI entry to the matching tab + overlay"
```

---

## Task 12: Help overlay update, dev-stage cleanup, docs

**Files:**
- Modify: `src/tui/help.rs` — render inside a dialog (`draw_help_dialog(frame)`); rewrite `help_lines()` for the new keymap (Tab/Shift-Tab/Ctrl-1/2/3 tabs, Ctrl-A/E/D, F1 help; **remove** the old `c`/`Shift-C`/`F2`/`?` entries).
- Audit + delete: any remaining `Mode` references, `open_help`/`close_help`/`help_prev_mode`, old `draw_with_status`, old `StoreView::draw`, the placeholder `CredPanel`/`SettingsPanel` (now real), any dead `#[allow(dead_code)]`.
- Modify: `CLAUDE.md` — update the "TUI keys" table and the TUI architecture bullets (three-band shell, tabs, overlays; remove F2/`?`/`c`/`Shift-C`).

- [ ] **Step 1: Update the help-text test**

In `help.rs`, the test `help_lines_cover_every_surface_and_dismiss_hint` currently asserts phrases like "switch storage mode (keyring…)". Rewrite the asserted phrases to the new keymap: tabs (`Tab`/`Ctrl-1/2/3`), `Ctrl-A` add, `Ctrl-E` edit, `Ctrl-D` delete, `F1` help, and that the removed bindings are absent:
```rust
assert!(joined.contains("cycle tabs"));
assert!(joined.contains("add (current tab)"));
assert!(!joined.contains("switch storage mode (keyring")); // F2 is gone
```

- [ ] **Step 2: Run — expect fail**

```bash
cargo test -p sshrack --lib tui::help 2>&1 | tail -10
```

- [ ] **Step 3: Rewrite help**

`draw_help_dialog(frame)` → `let body = draw_dialog(frame, " help ", 0, &[("F1/Esc", "close")]); Paragraph::new(help_lines()).render into body`. Rewrite `help_lines()` sections: Hosts panel / Credentials panel / Settings panel / Overlays / Everywhere — matching the DESIGN SPEC keymap. Drop the old launcher/wizard/store-mode-specific sections that referenced removed keys.

- [ ] **Step 4: Cleanup sweep**

```bash
rg -n 'Mode|help_prev_mode|open_help|close_help|draw_with_status|▍|DarkGray|F2|Shift-C' src/tui/ CLAUDE.md
```
Expect no stale references (the `rg` for `Mode` should only hit non-`Mode`-enum prose, if any; rename or remove). Remove leftover `#[allow(dead_code)]`. Ensure no placeholder structs remain.

- [ ] **Step 5: Update CLAUDE.md TUI keys + architecture**

Rewrite the "### TUI keys" table to:
```
| Tab / Shift-Tab | cycle tab (Hosts/Credentials/Settings) |
| Ctrl-1/2/3      | jump to Hosts / Credentials / Settings |
| type            | filter the active panel's search box   |
| ↑↓ / ^n ^p      | move selection                         |
| Enter           | Hosts: connect · Creds: edit · Settings: edit |
| ^a / ^e / ^d    | add / edit / delete (current tab)      |
| F1              | help overlay                            |
| Esc             | clear query / close overlay / quit      |
| ^c              | quit                                    |
```
Update the architecture bullets to describe the three-band shell + tabs + overlays, and note wizards/store-picker are now dialogs (not full-screen modes).

- [ ] **Step 6: Final full verification**

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
rg -n 'DarkGray|▍|\bMode\b|F2 ' src/tui/ CLAUDE.md || true
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(tui): dialog help overlay with new keymap; drop legacy bindings and docs"
```

---

## Self-Review (by the planner)

**1. Spec coverage (against the user's requirements):**
- Three-pane shell (brand+tabs / panel / hotkey footer): Task 4 (renderer) + Task 6 (assembly). ✅
- Tabs Hosts/Credentials/Settings, default Hosts, active highlighted: Tasks 2 + 4 + 6. ✅
- Hosts panel = search box + list, default-select first: Task 6 (existing launcher keeps `selected=0`). ✅
- Credentials panel (same shape): Task 7. ✅
- Settings panel = settings list (storage mode only for now): Task 8. ✅
- Ctrl-A / Ctrl-E pop up add/edit overlays (host and cred): Tasks 6 + 7 + 9. ✅
- Non-popup F1 help: Tasks 6 + 12 (Help is an overlay, F1 opens from any panel). ✅
- Settings row popup (storage-mode enum picker): Task 8. ✅
- CLI `sshrack host add` → TUI + Add Host overlay (and the other four shapes): Task 11. ✅
- Single-char conflict fix (`c`/`?`/`1/2/3` reach the query): Tasks 2 + 6 (tests `bare_chars_c_and_question_and_digit_reach_query`). ✅
- Modern/minimal/high-end visuals (single accent, gutter selection, real cursor, no panel borders): Tasks 1 + 4 + 5 + 10. ✅

**2. Placeholder scan:** No "TBD"/"TODO"/"add error handling" in task steps. Two intentional "verify the exact signature" notes (nucleo `Pattern::score` in Task 3; `CredentialBody::secret_kind` in Task 7) — these are real API-verification instructions with a fallback, not placeholders. Task 6's `CredPanel`/`SettingsPanel` placeholders are explicitly typed and removed by Tasks 7–8.

**3. Type consistency:** `Tab` and `tab_key_decision` (Task 2) consumed identically in Tasks 4/6/11. `Overlay` (Task 6) variants referenced consistently in Tasks 7/8/9/12. `rank_by_name` (Task 3) signature matches its use in Task 7 (`rank_credentials`) and Task 3's launcher refactor. `draw_shell` returns `Rect` consumed as `panel_area` in Tasks 6/7/8. `draw_dialog` returns the body `Rect` consumed by `draw_in_dialog` in Tasks 6/8/9/12. `Outcome::OpenOverlay(Overlay)` / `CloseOverlay` / `SwitchTab(Tab)` introduced in Task 6 and handled in `run_loop` (Task 6 Step 7) and produced by Tasks 7/8.

**4. Risk notes for implementers:**
- Task 6 is large (keystone). The reviewer must verify (a) the old `Mode` enum and ALL its dispatch are gone, (b) every removed binding (`c`/`Shift-C`/`F2`/`?`) has a failing-then-passing test proving it now reaches the query, (c) the existing `persist_*`/`connect_host` I/O is untouched in behavior (only call sites moved).
- The nucleo `Pattern::score` arity (Task 3, confirmed **2-arg**) and `CredentialBody::secret_kind` (Task 7, confirmed variants `Password`/`Key`/`KeyringPassword`/`Default`) were verified against source during planning; implementers should still grep to be safe.
- Reentrancy: the `run_loop` borrow-narrowly contract (Critical #1) is unchanged — popups still upgrade the weak handle; Task 6 must not introduce a long-lived `RefMut`.
