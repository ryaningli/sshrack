# In-Wizard Store-Mode Pick + Field Cursor UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two TUI UX papercuts: (1) the credential wizard's save silently fails when no store mode is chosen, kicking the user out to pick one — instead, recover in place via a store-mode pick popup then auto-retry the save; (3) the wizard field cursor sits after the placeholder text, so backspace feels like it should delete the hint — move the cursor to the input start with the placeholder as a dim background.

**Architecture:** Pure-view changes only inside `src/tui/`. Problem 3 is a shared render helper extraction (`value_spans`) used by both `HostForm::render_row` and `CredForm::render_row`, pinning span order with a unit test. Problem 1 adds a self-contained store-pick popup to `src/tui/prompt.rs` (pure key-decision `store_pick_action_from_key` is TDD'd first; the popup I/O mirrors the existing `confirm_popup`), then rewires the `Outcome::SaveCred` arm in `src/tui/app.rs` into a `fulfill_save_cred` helper that catches `StoreModeNotDecided`, drives the popup, calls the existing `persist_store_switch`, and retries `persist_cred_save`. No new data path, no new dependency, no `Mode` change — the popup is synchronous like the other prompts.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, thiserror (core). All work in the root binary crate.

## Global Constraints

Copied verbatim from `CLAUDE.md` hard rules; every task implicitly inherits them:

- **English only** — all source, comments, doc comments, error messages, help text, log output, and commit messages.
- **Zero `unsafe`** — never, including tests. Rust 2024 `set_var` is unsafe; tests inject via params/seams.
- **Zero `unwrap()`/`expect()`** in production code — only in `#[cfg(test)]` or `expect("invariant: ...")` for genuinely unreachable states.
- **TDD for pure logic** — RED → GREEN → REFACTOR.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Passwords are `Zeroizing<String>`** end-to-end; never logged/printed/in errors/argv. (This plan touches no password plumbing, but the store-pick popup must not echo anything secret.)
- **Tests are hermetic** — `cargo test` green in a real shell with `SSHRACK_PASSPHRASE` set; no `env -u` fallback.
- **Dev stage, no compat code** — no shims, no deprecated aliases, no `allow(dead_code)` leftovers. Every new item is wired and used.
- **Public items have `///` doc comments; modules have `//!` doc comments.**

**Commit style:** `<type>(<scope>): <desc>` (Conventional Commits). Scope here is `tui`. Each task ends with one commit.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/tui/wizard.rs` | Host/cred form render + pure state. | Extract shared `value_spans`; both `render_row`s call it; add span-order test (Task 1). |
| `src/tui/prompt.rs` | Inline TUI popups + pure key decisions. | Add `StorePick`, `StorePickAction`, `store_pick_action_from_key` (Task 2); add `prompt_store_pick` + `store_pick_popup` (Task 3). |
| `src/tui/app.rs` | Event loop + persist orchestration. | Add `map_store_pick` + `recover_store_mode_and_retry_cred_save` + `fulfill_save_cred`; `Outcome::SaveCred` arm calls `fulfill_save_cred` (Task 3). |

No new files. `src/tui/store.rs` (the launcher's F2 `StoreView`) is untouched — the popup is a parallel synchronous UI surface, not a reuse of the `Mode::Store` view (that view returns `Outcome`; the popup must return a selection synchronously).

---

## Task 1: Move the wizard field cursor before the placeholder (Problem 3)

Extract one shared `value_spans` helper so `HostForm::render_row` and `CredForm::render_row` (currently duplicated) render the empty state identically: focused cursor `▍` first, then the dim placeholder as a background hint. Non-empty values keep `value + ▍`.

**Files:**
- Modify: `src/tui/wizard.rs` — `HostForm::render_row` (around lines 616-647), `CredForm::render_row` (around lines 1185-1216); add a free `fn value_spans` near the top of the forms section.
- Test: `src/tui/wizard.rs` `#[cfg(test)] mod tests` — add `value_spans_*` tests.

**Interfaces:**
- Produces: `fn value_spans(value: &str, placeholder: Option<&str>, focused: bool) -> Vec<Span<'static>>`. Both `render_row`s consume it.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/tui/wizard.rs` (after the existing `press` helper):

```rust
    // ---- value_spans: empty-state cursor sits BEFORE the placeholder ----

    #[test]
    fn value_spans_empty_focused_puts_cursor_before_placeholder() {
        let spans = value_spans("", Some("e.g. web-prod"), true);
        assert_eq!(spans.len(), 2, "focused empty: cursor + placeholder");
        assert_eq!(&*spans[0].content, "▍", "cursor first (at the input start)");
        assert_eq!(&*spans[1].content, "e.g. web-prod", "placeholder second (background)");
    }

    #[test]
    fn value_spans_empty_unfocused_has_no_cursor() {
        let spans = value_spans("", Some("e.g. web-prod"), false);
        assert_eq!(spans.len(), 1, "unfocused empty: placeholder only, no cursor");
        assert_eq!(&*spans[0].content, "e.g. web-prod");
    }

    #[test]
    fn value_spans_non_empty_puts_cursor_after_value_and_no_placeholder() {
        let spans = value_spans("typed", Some("e.g. web-prod"), true);
        assert_eq!(spans.len(), 2);
        assert_eq!(&*spans[0].content, "typed");
        assert_eq!(&*spans[1].content, "▍");
    }

    #[test]
    fn value_spans_empty_with_no_placeholder_focused_is_cursor_only() {
        let spans = value_spans("", None, true);
        assert_eq!(spans.len(), 1);
        assert_eq!(&*spans[0].content, "▍");
    }
```

- [ ] **Step 2: Run — expect fail (undefined `value_spans`)**

Run: `cargo test -p sshrack --lib tui::wizard::tests::value_spans 2>&1 | head -20`
Expected: compile error `cannot find function 'value_spans'`.

- [ ] **Step 3: Implement the shared helper**

Add this free function in `src/tui/wizard.rs`, just above `impl HostForm` (the `render_row` it serves lives on `HostForm`). Put it after the `use`/`AuthChoice` block, before the `HostForm` struct:

```rust
/// Build the value-area spans for one field row. Shared by [`HostForm`] and
/// [`CredForm`] so both render the empty state identically.
///
/// When the value is empty and the row is focused, the cursor `▍` comes FIRST
/// (at the input start), followed by the dim placeholder as a background hint —
/// so backspace at an empty input is a natural no-op and the placeholder never
/// looks like editable text the cursor is sitting inside. When the value is
/// non-empty, the value renders raw with the cursor trailing it and the
/// placeholder disappears.
fn value_spans(value: &str, placeholder: Option<&str>, focused: bool) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    if value.is_empty() {
        if focused {
            spans.push(Span::styled("▍", Style::new().dim()));
        }
        if let Some(ph) = placeholder {
            spans.push(Span::styled(ph.to_string(), Style::new().dim()));
        }
    } else {
        spans.push(Span::raw(value.to_string()));
        if focused {
            spans.push(Span::styled("▍", Style::new().dim()));
        }
    }
    spans
}
```

- [ ] **Step 4: Rewire `HostForm::render_row` to use it**

In `src/tui/wizard.rs`, replace the body of `HostForm::render_row` (the block from `let (value_str, placeholder) = self.row_value_and_placeholder(field);` through the closing `Line::from(spans)...`) with:

```rust
        let (value_str, placeholder) = self.row_value_and_placeholder(field);

        let mut spans = vec![label_span];
        spans.extend(value_spans(&value_str, placeholder, focused));
        Line::from(spans).alignment(Alignment::Left)
```

(`label_span` and `focused` are already computed at the top of the function — keep those lines; only the value-area assembly changes.)

- [ ] **Step 5: Rewire `CredForm::render_row` to use it**

Apply the identical edit to `CredForm::render_row`: replace its value-area block with `spans.extend(value_spans(&value_str, placeholder, focused));`. The label-span construction (`{cursor}{label:>8}: ` for the cred form) stays unchanged.

- [ ] **Step 6: Run tests — expect pass**

Run: `cargo test -p sshrack --lib tui::wizard 2>&1 | tail -20`
Expected: all green, including the four new `value_spans_*` tests and the existing `draw_renders_without_panic_across_focus_and_auth_states` render smoke (still must not panic).

- [ ] **Step 7: clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/tui/wizard.rs
git commit -m "fix(tui): place field cursor before placeholder as background hint"
```

---

## Task 2: Pure `StorePick` key-decision helper (Problem 1, decision half)

Add the data type and the pure key→action mapping the store-pick popup will need. No I/O yet; TDD the pure function.

**Files:**
- Modify: `src/tui/prompt.rs` — add `StorePick`, `StorePickAction`, `store_pick_action_from_key`; extend the `#[cfg(test)] mod tests` block.

**Interfaces:**
- Produces: `pub enum StorePick { Keyring, Vault, Plaintext }` (with `ORDER` + `label` + `blurb`); `pub enum StorePickAction { Up, Down, Confirm, Cancel, Other }`; `pub fn store_pick_action_from_key(key: KeyCode, mods: KeyModifiers) -> StorePickAction`. Task 3 consumes them.

- [ ] **Step 1: Write the failing tests**

Add to `src/tui/prompt.rs` `#[cfg(test)] mod tests` (the `use super::*;` already imports `KeyCode`):

```rust
    #[test]
    fn store_pick_up_down_navigate() {
        assert_eq!(
            store_pick_action_from_key(KeyCode::Up, KeyModifiers::NONE),
            StorePickAction::Up
        );
        assert_eq!(
            store_pick_action_from_key(KeyCode::Down, KeyModifiers::NONE),
            StorePickAction::Down
        );
    }

    #[test]
    fn store_pick_enter_confirms_esc_cancels() {
        assert_eq!(
            store_pick_action_from_key(KeyCode::Enter, KeyModifiers::NONE),
            StorePickAction::Confirm
        );
        assert_eq!(
            store_pick_action_from_key(KeyCode::Esc, KeyModifiers::NONE),
            StorePickAction::Cancel
        );
    }

    #[test]
    fn store_pick_ctrl_c_cancels() {
        assert_eq!(
            store_pick_action_from_key(
                KeyCode::Char('c'),
                KeyModifiers::CONTROL,
            ),
            StorePickAction::Cancel
        );
    }

    #[test]
    fn store_pick_other_keys_are_other() {
        assert_eq!(
            store_pick_action_from_key(KeyCode::Char('a'), KeyModifiers::NONE),
            StorePickAction::Other
        );
        assert_eq!(
            store_pick_action_from_key(KeyCode::Tab, KeyModifiers::NONE),
            StorePickAction::Other
        );
    }

    #[test]
    fn store_pick_order_and_labels_are_stable() {
        assert_eq!(
            StorePick::ORDER,
            &[StorePick::Keyring, StorePick::Vault, StorePick::Plaintext]
        );
        assert_eq!(StorePick::Keyring.label(), "keyring");
        assert_eq!(StorePick::Vault.label(), "vault");
        assert_eq!(StorePick::Plaintext.label(), "plaintext");
        // blurbs are non-empty one-liners (rendered beside each option).
        for m in StorePick::ORDER {
            assert!(!m.blurb().is_empty());
        }
    }
```

- [ ] **Step 2: Run — expect fail (undefined)**

Run: `cargo test -p sshrack --lib tui::prompt::tests::store_pick 2>&1 | head -20`
Expected: compile error `cannot find type 'StorePick'`.

- [ ] **Step 3: Implement the enum + pure mapping**

Add to `src/tui/prompt.rs`, near the existing `ConfirmAnswer`/`confirm_from_key` block (after `confirm_from_key`, before `MASK`):

```rust
/// A store-mode selection made in the store-pick popup. The popup returns
/// `Option<StorePick>` — `None` when the user cancelled. Distinct from
/// `crate::tui::store::StoreModeChoice` (a `Mode::Store` view that returns
/// `Outcome`) because this popup must return a selection synchronously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePick {
    Keyring,
    Vault,
    Plaintext,
}

impl StorePick {
    /// Render + navigation order shown in the popup.
    pub const ORDER: &'static [StorePick] = &[
        StorePick::Keyring,
        StorePick::Vault,
        StorePick::Plaintext,
    ];

    /// The user-facing label.
    pub fn label(self) -> &'static str {
        match self {
            StorePick::Keyring => "keyring",
            StorePick::Vault => "vault",
            StorePick::Plaintext => "plaintext",
        }
    }

    /// A one-line trade-off blurb shown beside the option in the popup.
    pub fn blurb(self) -> &'static str {
        match self {
            StorePick::Keyring => "OS keyring (recommended); needs a Secret Service daemon",
            StorePick::Vault => "master-passphrase encryption (portable across machines)",
            StorePick::Plaintext => "stored in the clear — a security downgrade",
        }
    }
}

/// The decoded action for one key in the store-pick popup. Mirrors the shape of
/// [`ConfirmAnswer`]: distinguishes "this key does something" from "ignore me".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePickAction {
    /// Move the cursor up (wraps).
    Up,
    /// Move the cursor down (wraps).
    Down,
    /// Enter: confirm the highlighted option.
    Confirm,
    /// Esc / Ctrl-C: cancel the popup.
    Cancel,
    /// Any other key: ignored.
    Other,
}

/// Pure decision for the store-pick popup: which key yields which action. No
/// I/O, so it is unit-testable without a terminal. `Ctrl-C` cancels regardless
/// of the underlying char.
pub fn store_pick_action_from_key(key: KeyCode, mods: KeyModifiers) -> StorePickAction {
    if mods == KeyModifiers::CONTROL && key == KeyCode::Char('c') {
        return StorePickAction::Cancel;
    }
    match key {
        KeyCode::Up => StorePickAction::Up,
        KeyCode::Down => StorePickAction::Down,
        KeyCode::Enter => StorePickAction::Confirm,
        KeyCode::Esc => StorePickAction::Cancel,
        _ => StorePickAction::Other,
    }
}
```

- [ ] **Step 4: Run tests — expect pass**

Run: `cargo test -p sshrack --lib tui::prompt 2>&1 | tail -20`
Expected: green, including the five new `store_pick_*` tests.

- [ ] **Step 5: clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: clean. (If clippy flags `StorePick::ORDER` as unused — it is used by Task 3 — add a one-line `#[allow(dead_code)]` ONLY if Task 3 has not landed yet; remove it in Task 3. Prefer landing Task 3 immediately after so no `allow` is needed.)

- [ ] **Step 6: Commit**

```bash
git add src/tui/prompt.rs
git commit -m "feat(tui): add pure StorePick key-decision helper"
```

---

## Task 3: In-wizard store-pick popup + SaveCred recovery (Problem 1, I/O + wiring)

Add the synchronous store-pick popup (`prompt_store_pick`) that drives a `&mut Tui` like the other prompts, then rewire the `Outcome::SaveCred` arm to catch `StoreModeNotDecided`, offer the popup, switch mode via the existing `persist_store_switch`, and retry `persist_cred_save`.

**Files:**
- Modify: `src/tui/prompt.rs` — add `pub fn prompt_store_pick(handle: &TerminalHandle) -> Result<Option<StorePick>, SshrackError>` + private `fn store_pick_popup(terminal: &mut Tui) -> Result<Option<StorePick>, SshrackError>`.
- Modify: `src/tui/app.rs` — add `fn map_store_pick(StorePick) -> StoreSwitchTarget`, `fn recover_store_mode_and_retry_cred_save(app, handle) -> Result<bool, SshrackError>`, `fn fulfill_save_cred(app, handle)`; change the `Outcome::SaveCred` arm to call `fulfill_save_cred`.
- Test: `src/tui/app.rs` `#[cfg(test)] mod tests` — add `fulfill_save_cred_recovers_to_cancel_when_popup_unavailable` (dead-handle path).

**Interfaces:**
- Consumes: Task 2's `StorePick`/`StorePickAction`/`store_pick_action_from_key`; the existing `persist_store_switch(app, target, handle) -> Result<bool, SshrackError>`, `persist_cred_save(app, handle) -> Result<(), SshrackError>`, `upgrade_terminal`, `popup::render_popup`, `SshrackError::from_prompt_io`.
- Produces: `prompt_store_pick` (called by `recover_store_mode_and_retry_cred_save`); `fulfill_save_cred` (called by the `SaveCred` arm).

- [ ] **Step 1: Write the failing test (dead-handle recovery → cancel, no panic)**

Add to `src/tui/app.rs` `#[cfg(test)] mod tests`, near the existing `cred_add_password_with_store_mode_undecided_errors_not_silent_plaintext` test (around line 2101). Reuse whatever `dead_handle()` / form-builder helpers that test already uses:

```rust
    #[test]
    fn fulfill_save_cred_undecided_with_dead_handle_stays_in_wizard_with_cancel_msg() {
        // SaveCred on a Password cred with store undecided would normally error
        // out. fulfill_save_cred must catch StoreModeNotDecided, try the store
        // pick popup, and — when the popup cannot render (dead handle, as in
        // tests) — surface a cancel message and KEEP the wizard open (no panic,
        // no silent drop, no close).
        let mut app = App::for_test(); // see note below
        // Build an add-cred wizard with a Password secret, mirroring
        // cred_add_password_with_store_mode_undecided_errors_not_silent_plaintext.
        let mut form = CredForm::new_add(/* same args as the existing test */);
        form.secret_kind = SecretChoice::Password;
        form.password = "p".into();
        app.cred_wizard = Some(form);
        // store undecided by default in for_test().
        assert!(app.config.store.is_none());

        fulfill_save_cred(&mut app, &dead_handle());

        // The wizard is still open (recovery failed to get a pick, so we stayed).
        assert!(app.cred_wizard.is_some(), "stayed in wizard on popup cancel");
        let msg = app
            .cred_wizard
            .as_ref()
            .and_then(|w| w.error_text()) // see note below
            .unwrap_or_default();
        assert!(
            msg.to_lowercase().contains("cancel"),
            "recovery should surface a cancel message, got: {msg}"
        );
    }
```

**Note — `for_test()` and `error_text()`:** before writing the test, check how the existing `cred_add_password_with_store_mode_undecided_errors_not_silent_plaintext` test builds `app` and reads the wizard's error. If `App` already has a test constructor, reuse it; otherwise build the `App` the same way that test does (inline). If `CredForm` exposes the error via `set_core_error` only and has no `error_text()` getter, read it through whatever field the existing test inspects (or add a tiny `pub(crate) fn error_text(&self) -> Option<&str>` accessor on `CredForm` — it is test-reachable and avoids `#[allow(dead_code)]`). The assertion target is "the wizard stayed open + its error line mentions cancel".

- [ ] **Step 2: Run — expect fail (undefined `fulfill_save_cred`)**

Run: `cargo test -p sshrack --lib tui::app::tests::fulfill_save_cred 2>&1 | head -20`
Expected: compile error `cannot find function 'fulfill_save_cred'`.

- [ ] **Step 3: Implement the popup I/O in `prompt.rs`**

Add to `src/tui/prompt.rs`, after the `TuiPassphrase` impl block (it uses the same `upgrade_terminal` + `&mut Tui` pattern as `prompt_password`):

```rust
/// Drive the store-mode pick popup on the terminal behind `handle`. Returns
/// `Ok(Some(pick))` when the user chose a mode, `Ok(None)` when they cancelled
/// (Esc / Ctrl-C), or `Err(Interrupted)` when the terminal guard is already
/// gone (a popup after `tui::run` returned — treated as a silent cancel, never
/// a panic). Used by the SaveCred recovery path so the user can choose a store
/// mode without leaving the credential wizard.
pub fn prompt_store_pick(handle: &TerminalHandle) -> Result<Option<StorePick>, SshrackError> {
    let rc = upgrade_terminal(handle)?;
    store_pick_popup(&mut rc.borrow_mut())
}

/// Render the three store modes with a cursor marker and read keys until the
/// user confirms or cancels. Mirrors [`confirm_popup`]'s render/poll/read loop.
fn store_pick_popup(terminal: &mut Tui) -> Result<Option<StorePick>, SshrackError> {
    let mut cursor: usize = 0;
    let len = StorePick::ORDER.len();
    loop {
        let mut lines: Vec<Line> = StorePick::ORDER
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let marker = if i == cursor { "▶ " } else { "  " };
                Line::from(format!("{marker}{} — {}", m.label(), m.blurb()))
            })
            .collect();
        lines.push(Line::from(""));
        lines.push(
            Line::from("[↑/↓] select   [Enter] confirm   [Esc] cancel")
                .style(ratatui::style::Style::new().dim()),
        );
        let body = ratatui::widgets::Paragraph::new(lines).alignment(ratatui::layout::Alignment::Left);
        terminal
            .draw(|f| popup::render_popup(f, "Choose store mode", body))
            .map_err(SshrackError::from_prompt_io)?;

        if !event::poll(std::time::Duration::from_millis(250)).map_err(SshrackError::from_prompt_io)? {
            continue;
        }
        let Event::Key(key) = event::read().map_err(SshrackError::from_prompt_io)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match store_pick_action_from_key(key.code, key.modifiers) {
            StorePickAction::Up => cursor = (cursor + len - 1) % len,
            StorePickAction::Down => cursor = (cursor + 1) % len,
            StorePickAction::Confirm => return Ok(StorePick::ORDER.get(cursor).copied()),
            StorePickAction::Cancel => return Ok(None),
            StorePickAction::Other => {}
        }
    }
}
```

- [ ] **Step 4: Implement the recovery + fulfillment helpers in `app.rs`**

Add a private mapper next to `StoreSwitchTarget` (around line 1351):

```rust
/// Map the popup's selection onto the loop's switch target.
fn map_store_pick(pick: super::prompt::StorePick) -> StoreSwitchTarget {
    match pick {
        super::prompt::StorePick::Keyring => StoreSwitchTarget::Keyring,
        super::prompt::StorePick::Vault => StoreSwitchTarget::Vault,
        super::prompt::StorePick::Plaintext => StoreSwitchTarget::Plaintext,
    }
}
```

Add the recovery helper next to `persist_cred_save` (around line 1344, after it):

```rust
/// Recover from a `StoreModeNotDecided` save: drive the store-pick popup, run
/// the switch via [`persist_store_switch`], then retry the cred save. Returns
/// `Ok(true)` when the retry succeeded; `Ok(false)` when the user cancelled the
/// popup or the switch was refused (reason already in the wizard's core-error
/// line); `Err` propagates a real failure so [`fulfill_save_cred`] can surface
/// it. Called only from [`fulfill_save_cred`].
fn recover_store_mode_and_retry_cred_save(
    app: &mut App,
    handle: &TerminalHandle,
) -> Result<bool, SshrackError> {
    let pick = super::prompt::prompt_store_pick(handle)?;
    let Some(target) = pick.map(map_store_pick) else {
        // User cancelled the popup. Stay in the wizard with a clear reason.
        if let Some(w) = app.cred_wizard.as_mut() {
            w.set_core_error("store selection cancelled".into());
        }
        return Ok(false);
    };
    match persist_store_switch(app, target, handle)? {
        true => {
            // Mode switched + persisted; retry the save. Any error propagates
            // (fulfill_save_cred surfaces it in the wizard's core-error line).
            persist_cred_save(app, handle).map(|_| true)
        }
        false => {
            // Switch refused (keyring daemon down, plaintext declined, ...).
            if let Some(w) = app.cred_wizard.as_mut() {
                w.set_core_error(
                    "could not switch store mode (unavailable or declined); \
                     try Shift-C / F2 in the launcher"
                        .into(),
                );
            }
            Ok(false)
        }
    }
}
```

Add `fulfill_save_cred` (replaces the inline match currently in the `Outcome::SaveCred` arm):

```rust
/// Handle an [`Outcome::SaveCred`] intent end-to-end: persist the cred, and on
/// `StoreModeNotDecided` recover in place via a store-pick popup + switch +
/// retry instead of erroring out of the wizard. All outcomes surface through
/// the wizard's core-error line or a launcher status + wizard close.
fn fulfill_save_cred(app: &mut App, handle: &TerminalHandle) {
    match persist_cred_save(app, handle) {
        Ok(()) => {
            app.set_status("credential saved".to_string());
            app.close_cred_wizard();
        }
        Err(SshrackError::StoreModeNotDecided) => {
            match recover_store_mode_and_retry_cred_save(app, handle) {
                Ok(true) => {
                    app.set_status("credential saved".to_string());
                    app.close_cred_wizard();
                }
                Ok(false) => {} // cancelled or switch refused; reason already in core-error.
                Err(SshrackError::Interrupted) => {
                    if let Some(w) = app.cred_wizard.as_mut() {
                        w.set_core_error("cancelled".into());
                    }
                }
                Err(e) => {
                    if let Some(w) = app.cred_wizard.as_mut() {
                        w.set_core_error(e.to_string());
                    }
                }
            }
        }
        Err(SshrackError::Interrupted) => {
            if let Some(w) = app.cred_wizard.as_mut() {
                w.set_core_error("vault unlock cancelled".into());
            }
        }
        Err(e) => {
            if let Some(w) = app.cred_wizard.as_mut() {
                w.set_core_error(e.to_string());
            }
        }
    }
}
```

- [ ] **Step 5: Rewire the `Outcome::SaveCred` arm**

In `run_loop` (around line 949), replace the entire `Outcome::SaveCred => { ... }` arm body with a single call:

```rust
                Outcome::SaveCred => {
                    fulfill_save_cred(app, &handle);
                }
```

- [ ] **Step 6: Run tests — expect pass**

Run: `cargo test -p sshrack --lib tui::app 2>&1 | tail -25`
Expected: green. The new `fulfill_save_cred_*` test passes (dead handle → popup upgrade fails → `Interrupted` propagates out of `prompt_store_pick` → `recover_store_mode_and_retry_cred_save` returns `Err(Interrupted)` → `fulfill_save_cred`'s `Err(Interrupted)` arm sets "cancelled" + stays). The pre-existing `cred_add_password_with_store_mode_undecided_errors_not_silent_plaintext` still passes (it tests `persist_cred_save` directly, whose behavior is unchanged).

- [ ] **Step 7: clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: clean. If Task 2 left a temporary `#[allow(dead_code)]` on `StorePick::ORDER`, remove it now (it has a real caller).

- [ ] **Step 8: Manual end-to-end smoke**

```bash
cargo build --workspace
# Reset to an undecided store (back up config first if needed):
#   edit ~/.config/sshrack/config.toml so there is no [store] table.
cargo run -q --                       # TUI launcher
# In the launcher: press 'c' to add a credential.
#   name: anything, user: x, secret kind: ←/→ to Password, type a password.
#   Save (Enter on the last field / the wizard's save key).
# Expected: a "Choose store mode" popup appears. ↑/↓ + Enter picks one:
#   - keyring → switches, retry succeeds, wizard closes, "credential saved".
#   - vault   → popup then asks for a double-entry master passphrase.
#   - plaintext → popup confirms the downgrade, then switches.
#   Esc at the popup → "store selection cancelled", stay in wizard (no data lost).
```

- [ ] **Step 9: Commit**

```bash
git add src/tui/prompt.rs src/tui/app.rs
git commit -m "feat(tui): offer in-wizard store-mode pick on undecided save"
```

---

## Self-Review

**1. Spec coverage:**
- Problem 3 (cursor before placeholder) → Task 1 `value_spans` + both `render_row`s. ✅
- Problem 1 (in-place store pick, no leaving the wizard) → Task 2 (pure decision) + Task 3 (popup I/O + SaveCred recovery). ✅ The user stays inside the credential wizard on every branch (cancel, switch-refused, switch-then-retry).
- Problem 2 (host wizard password) is **deliberately out of scope** (user said skip — architecture change, separate effort). Not covered, by decision. ✅
- "Which TUI pages trigger store-undecided?" — only the cred wizard's `persist_cred_save` (the sole `StoreModeNotDecided` producer at `app.rs:1297`). Task 3 wires exactly that one site. No other page needs the popup. ✅

**2. Placeholder scan:** No `TBD`/`TODO`/"add error handling". The one open-ended instruction (Step 1 of Task 3: reuse the existing test's `App`/`CredForm` construction and error accessor) is pinned to a concrete neighboring test (`cred_add_password_with_store_mode_undecided_errors_not_silent_plaintext`) with a concrete fallback (add a `pub(crate) error_text` accessor if none exists) — the implementer is told exactly where to look and what to do if the assumed helper is absent.

**3. Type consistency:**
- `value_spans(&str, Option<&str>, bool) -> Vec<Span<'static>>` — same signature in Task 1's definition and both `render_row` call sites. ✅
- `StorePick`/`StorePickAction`/`store_pick_action_from_key` defined in Task 2, consumed unchanged in Task 3. ✅
- `prompt_store_pick(&TerminalHandle) -> Result<Option<StorePick>, SshrackError>` — definition (Task 3 Step 3) matches the call in `recover_store_mode_and_retry_cred_save` (Task 3 Step 4). ✅
- `map_store_pick(StorePick) -> StoreSwitchTarget` returns the existing private enum; `persist_store_switch(app, target, handle)` already takes it. ✅
- `fulfill_save_cred(&mut App, &TerminalHandle)` matches the `SaveCred` arm call `fulfill_save_cred(app, &handle)`. ✅
- Variant names: `StorePickAction::{Up,Down,Confirm,Cancel,Other}` match between the enum definition, the pure mapping, and the popup match. ✅

No gaps found. Plan is complete.
