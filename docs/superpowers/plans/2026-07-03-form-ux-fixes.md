# Form UX Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Fix seven confirmed wizard-form UX defects reported by the user: (1) text fields cannot move the cursor with ←/→, (2) the field-specific hotkey hint is jammed against the permanent footer and redundantly repeats `^s save`/`Esc cancel`, (NEW) focusing a switch/chooser row lets the underlying launcher search-box cursor bleed through the overlay, (4) the credential form's `Identity` row stays visible under every secret choice instead of being mutually exclusive with `Password`, (5) the `Credential` label overflows the fixed label column by one cell, (6) the `Auth` row shows `Reference: <name>` even though the `Credential` row below already shows the name, (7) switchable chooser values render as bare words instead of `< Label >`.

**Architecture:** This is a TUI-only change (`src/tui/**`); `sshrack-core` is untouched (the core already models the secret as a single mutually-exclusive slot via the shared `CredentialBody`, used identically by `Auth::Inline` and `Credential.body`). The work splits into seven tasks: a pure text-cursor helper module, wiring the cursor into both forms, the cred three-way mutex, the overlay-cursor-bleed fix, the switch-bracket + Auth-suffix rendering, and a final form-rendering-polish task (hint layout + label column width). Tasks 2 and 3 depend on Task 1; the rest are independent. All touch overlapping files (`host.rs`/`cred.rs`), so they run **sequentially** (never parallel implementers).

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, `unicode-width` (already a root dep from the prior content-fit work).

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via params/seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **TDD for pure logic** — RED → GREEN → REFACTOR. Render/process behavior (crossterm key reads, `terminal.draw`) is covered by no-panic `TestBackend` smoke tests and robust before/after comparisons, not pixel assertions.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Passwords are `Zeroizing<String>`** end-to-end; never logged/printed/in errors/argv. The cursor helpers mutate `Zeroizing<String>` via `&mut *self.password` reborrow — the buffer is still zeroized on drop.
- **`sshrack-core` zero-UI invariant** — this plan NEVER touches `crates/sshrack-core/`.
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Dev stage, no compat code** — replace the old behavior outright; keep no parallel path.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`.
- **Avoid unnecessary `cargo clean`.**

**Scope invariant:** All work is in `src/tui/`. No core changes. Two confirmed user reports — Tab escaping the form, and the vault "New passphrase" popup lacking a cursor — were investigated and do **not** reproduce on current main (`9b67496`): Tab is consumed by the overlay (`app.rs:564` `return self.route_overlay`), and `render_password_popup` already calls `set_cursor_position` (`prompt.rs:408`). They are out of scope; do not add speculative fixes for them.

---

## File Structure (target)

```
src/tui/
├── wizard/
│   ├── mod.rs           # +insert_char_at / backspace_at / char_byte_offset / bracketed helpers;
│   │                    #  HOST_LABEL_WIDTH const; SecretChoice::label unchanged (callers wrap)
│   ├── host.rs          # +cursor field; edit_focused_insert/backspace_at; ←/→/Home/End/Ctrl-A/E;
│   │                    #  move_focus resets cursor; cursor_target returns stored cursor;
│   │                    #  Auth value = "< Reference >" / "< Independent >"; Secret value bracketed;
│   │                    #  label format width 9→10; field hint stripped of ^s/Esc
│   └── cred.rs          # same cursor wiring as host; reachable_fields three-way mutex;
│                        #  SecretKind value bracketed; field hint stripped
├── parts.rs             # draw_search_box gains show_cursor param (skip set_cursor_position when false)
├── launcher.rs          # draw_in_shell threads show_cursor (= overlay.is_none()) to draw_search_box
├── cred_panel.rs        # draw_in_shell threads show_cursor to draw_search_box
└── dialog.rs            # draw_dialog inserts one blank row above the footer; dialog_area height +1
```

---

## Task 1: Pure text-cursor edit helpers (`wizard/mod.rs`)

**Files:**
- Modify: `src/tui/wizard/mod.rs` (add three free functions above the existing `SecretChoice` impl or near the column consts at the bottom)

**Interfaces:**
- Produces:
  - `pub(super) fn insert_char_at(s: &mut String, cursor: usize, c: char) -> usize`
  - `pub(super) fn backspace_at(s: &mut String, cursor: usize) -> usize`
  - `fn char_byte_offset(s: &str, idx: usize) -> usize` (private helper)
- Consumes: nothing (pure utilities).

- [ ] **Step 1: Write the failing tests (RED)**

Add to the bottom of `src/tui/wizard/mod.rs` (create a `#[cfg(test)] mod cursor_tests` block, or append to an existing test module — match the file's existing test style):

```rust
#[cfg(test)]
mod cursor_edit_tests {
    use super::{backspace_at, insert_char_at};

    #[test]
    fn insert_at_middle_splits_correctly() {
        let mut s = String::from("abc");
        let cur = insert_char_at(&mut s, 1, 'X');
        assert_eq!(s, "aXbc");
        assert_eq!(cur, 2);
    }

    #[test]
    fn insert_at_end_appends() {
        let mut s = String::from("abc");
        let cur = insert_char_at(&mut s, 3, 'X');
        assert_eq!(s, "abcX");
        assert_eq!(cur, 4);
    }

    #[test]
    fn insert_at_start_prepends() {
        let mut s = String::from("abc");
        let cur = insert_char_at(&mut s, 0, 'X');
        assert_eq!(s, "Xabc");
        assert_eq!(cur, 1);
    }

    #[test]
    fn insert_past_end_behaves_like_append() {
        // idx beyond len clamps to end (char_byte_offset returns s.len()).
        let mut s = String::from("ab");
        let cur = insert_char_at(&mut s, 99, 'X');
        assert_eq!(s, "abX");
        assert_eq!(cur, 3);
    }

    #[test]
    fn backspace_at_middle_removes_prev_char() {
        let mut s = String::from("abc");
        let cur = backspace_at(&mut s, 2);
        assert_eq!(s, "ac");
        assert_eq!(cur, 1);
    }

    #[test]
    fn backspace_at_end_removes_last() {
        let mut s = String::from("abc");
        let cur = backspace_at(&mut s, 3);
        assert_eq!(s, "ab");
        assert_eq!(cur, 2);
    }

    #[test]
    fn backspace_at_zero_is_noop() {
        let mut s = String::from("abc");
        let cur = backspace_at(&mut s, 0);
        assert_eq!(s, "abc");
        assert_eq!(cur, 0);
    }

    #[test]
    fn insert_respects_wide_char_byte_boundaries() {
        // "中文" — each char is 3 bytes. Insert at char idx 1 (byte offset 3).
        let mut s = String::from("中文");
        let cur = insert_char_at(&mut s, 1, 'X');
        assert_eq!(s, "中X文");
        assert_eq!(cur, 2);
    }

    #[test]
    fn backspace_removes_a_wide_char_correctly() {
        let mut s = String::from("中X文");
        // cursor after "中X" (idx 2): backspace removes 'X' (1 byte).
        let cur = backspace_at(&mut s, 2);
        assert_eq!(s, "中文");
        assert_eq!(cur, 1);
        // now backspace at idx 1 removes '中' (3 bytes).
        let cur = backspace_at(&mut s, 1);
        assert_eq!(s, "文");
        assert_eq!(cur, 0);
    }
}
```

- [ ] **Step 2: Run — expect compile failure (RED)**

```bash
cargo test -p sshrack wizard::cursor_edit_tests 2>&1 | head
```
Expected: fails to compile (`cannot find function insert_char_at`).

- [ ] **Step 3: Implement (GREEN)**

Add the three functions to `src/tui/wizard/mod.rs`:

```rust
/// Insert `c` into `s` at the given char index, returning the new char index
/// (one past the inserted char). Wizard text fields use this to type at the
/// cursor rather than always appending. `cursor` beyond `s`'s char count
/// clamps to the end (append). Pure aside from mutating `s`.
pub(super) fn insert_char_at(s: &mut String, cursor: usize, c: char) -> usize {
    let byte = char_byte_offset(s, cursor);
    s.insert(byte, c);
    cursor + 1
}

/// Delete the char immediately before the char-index `cursor` in `s`, returning
/// the new cursor (one less), or the unchanged cursor when already at the
/// start. Pure aside from mutating `s`.
pub(super) fn backspace_at(s: &mut String, cursor: usize) -> usize {
    if cursor == 0 {
        return 0;
    }
    let end = char_byte_offset(s, cursor);
    // Byte offset of the char that ends at `end` (the char just before cursor).
    let start = s[..end]
        .char_indices()
        .next_back()
        .map(|(b, _)| b)
        .unwrap_or(0);
    s.replace_range(start..end, "");
    cursor - 1
}

/// Byte offset of the char at char-index `idx`, or `s.len()` when `idx` is at
/// or past the end (so an insert appends). Pure.
fn char_byte_offset(s: &str, idx: usize) -> usize {
    s.char_indices()
        .nth(idx)
        .map(|(b, _)| b)
        .unwrap_or_else(|| s.len())
}
```

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack wizard::cursor_edit_tests
```
Expected: all 9 tests pass.

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git checkout -b feat/form-ux-fixes
git add -A && git commit -m "feat(tui): pure cursor-aware text edit helpers"
```
(Task 1 creates the feature branch off `main`.)

---

## Task 2: Wire the cursor into `HostForm`

**Files:**
- Modify: `src/tui/wizard/host.rs` (struct field, constructors, `edit_focused_*`, `on_key`, `move_focus`, `cursor_target`, `focused_text_len`)

**Interfaces:**
- Consumes: `super::{insert_char_at, backspace_at}` from Task 1.
- Produces: `HostForm.cursor: usize` (private field); behavior — ←/→/Home/End/Ctrl-A/E move an in-field cursor; typing inserts at the cursor; Backspace deletes before the cursor.

- [ ] **Step 1: Write the failing tests (RED)**

Add to the `#[cfg(test)]` module in `src/tui/wizard/host.rs` (the file already has tests around `:1213`; append near them, using the existing `KeyEvent`/`KeyCode`/`KeyModifiers` imports and `HostForm::new_add` builder the other tests use):

```rust
#[test]
fn left_arrow_moves_cursor_within_a_text_field() {
    let mut form = HostForm::new_add(/* same builder args the sibling tests use */);
    // Type "abc" into Name (focus starts on Name).
    for c in "abc".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    assert_eq!(form.name, "abc");
    assert_eq!(form.cursor, 3);
    // Left moves the cursor back to 2 without changing the text.
    form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    assert_eq!(form.name, "abc");
    assert_eq!(form.cursor, 2);
    // cursor_target reports the stored cursor, not the tail.
    assert_eq!(form.cursor_target(), Some((0, 2)));
}

#[test]
fn typing_inserts_at_cursor_not_tail() {
    let mut form = HostForm::new_add(/* builder */);
    for c in "abc".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    // Move cursor to start, then type 'X' -> "Xabc".
    form.on_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    form.on_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE));
    assert_eq!(form.name, "Xabc");
    assert_eq!(form.cursor, 1);
}

#[test]
fn backspace_deletes_before_cursor_not_tail() {
    let mut form = HostForm::new_add(/* builder */);
    for c in "abc".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    // cursor at end (3). Left twice -> cursor 1. Backspace deletes 'a' -> "bc".
    form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    form.on_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
    assert_eq!(form.name, "bc");
    assert_eq!(form.cursor, 0);
}

#[test]
fn right_arrow_clamps_to_value_length() {
    let mut form = HostForm::new_add(/* builder */);
    for c in "ab".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    // cursor at end (2). Right must not overshoot.
    form.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(form.cursor, 2);
}

#[test]
fn home_and_end_jump_cursor() {
    let mut form = HostForm::new_add(/* builder */);
    for c in "abc".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    form.on_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    assert_eq!(form.cursor, 0);
    form.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    assert_eq!(form.cursor, 3);
}

#[test]
fn ctrl_a_and_ctrl_e_alias_home_and_end() {
    let mut form = HostForm::new_add(/* builder */);
    for c in "abc".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    form.on_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
    assert_eq!(form.cursor, 0);
    form.on_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
    assert_eq!(form.cursor, 3);
}

#[test]
fn move_focus_resets_cursor_to_new_field_end() {
    let mut form = HostForm::new_add(/* builder */);
    for c in "web".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    // Tab to Host (empty field) and back to Name — cursor must land on Name's end.
    form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    form.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
    assert_eq!(form.cursor, 3);
}

#[test]
fn left_right_still_cycle_on_auth_row_not_move_text_cursor() {
    let mut form = HostForm::new_add(/* builder */);
    // Focus Auth, then Left must cycle (to Reference) — cursor stays 0 (chooser).
    form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Name -> Host
    form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Host -> Port
    form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Port -> Auth
    // sanity: focus is Auth
    assert_eq!(form.focus, Field::Auth);
    form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    assert!(matches!(form.auth_choice, AuthChoice::Reference { .. }));
}
```

(If the existing tests construct `HostForm` via a helper rather than `new_add` directly, use the same helper — grep the test module for the established pattern and mirror it. The `/* builder */` placeholder above means "whatever the sibling tests pass to build an add-mode form".)

- [ ] **Step 2: Run — expect RED**

```bash
cargo test -p sshrack wizard::host 2>&1 | head -40
```
Expected: most fail (`cursor` field absent, cursor stays at tail, etc.).

- [ ] **Step 3: Add the `cursor` field + `focused_text_len` helper**

In `src/tui/wizard/host.rs`, add a private field to `HostForm` (near `pub focus: Field`):

```rust
    /// Char-index cursor within the focused text field. Reset to the focused
    /// field's end on focus change; clamped on read by [`cursor_target`].
    pub(super) cursor: usize,
```

Add a helper (near `cursor_target`):

```rust
    /// Char count of the currently focused text field (0 for chooser rows).
    fn focused_text_len(&self) -> usize {
        match self.focus {
            Field::Name => self.name.chars().count(),
            Field::Host => self.host_addr.chars().count(),
            Field::Port => self.port.chars().count(),
            Field::User => self.user.chars().count(),
            Field::Identity => self.identity.chars().count(),
            Field::Password => self.password.chars().count(),
            Field::Auth | Field::Credential | Field::Secret => 0,
        }
    }
```

**Update every `HostForm { ... }` literal** to initialize `cursor`:
```bash
rg -n 'HostForm \{' src/
```
For each construction site add `cursor: 0,` in the struct literal. Then, in the real constructors (`new_add` / `new_edit` / `from_host` — whichever build and return `self`), set the cursor to the initial focused field's end **after** the struct is built:
```rust
    let mut form = HostForm { /* ... */ cursor: 0 };
    form.cursor = form.focused_text_len();
    form
```
(If a constructor returns the literal directly, refactor it to `let mut form = ...; form.cursor = form.focused_text_len(); form`.) Test-support builders that build literals also need `cursor: 0` added.

- [ ] **Step 4: `edit_focused_push` → insert at cursor; `edit_focused_pop` → backspace at cursor**

Rename and rewrite the two methods (currently `src/tui/wizard/host.rs:498` and `:520`):

```rust
    fn edit_focused_insert(&mut self, c: char) {
        match self.focus {
            Field::Name => self.cursor = insert_char_at(&mut self.name, self.cursor, c),
            Field::Host => self.cursor = insert_char_at(&mut self.host_addr, self.cursor, c),
            Field::Port => {
                if c.is_ascii_digit() {
                    self.cursor = insert_char_at(&mut self.port, self.cursor, c);
                }
            }
            Field::User => self.cursor = insert_char_at(&mut self.user, self.cursor, c),
            Field::Identity => self.cursor = insert_char_at(&mut self.identity, self.cursor, c),
            Field::Password if self.secret_kind == SecretChoice::Password => {
                self.cursor = insert_char_at(&mut *self.password, self.cursor, c)
            }
            Field::Auth | Field::Credential | Field::Secret | Field::Password => {}
        }
    }

    fn edit_focused_backspace(&mut self) {
        match self.focus {
            Field::Name => self.cursor = backspace_at(&mut self.name, self.cursor),
            Field::Host => self.cursor = backspace_at(&mut self.host_addr, self.cursor),
            Field::Port => self.cursor = backspace_at(&mut self.port, self.cursor),
            Field::User => self.cursor = backspace_at(&mut self.user, self.cursor),
            Field::Identity => self.cursor = backspace_at(&mut self.identity, self.cursor),
            Field::Password if self.secret_kind == SecretChoice::Password => {
                self.cursor = backspace_at(&mut *self.password, self.cursor)
            }
            Field::Auth | Field::Credential | Field::Secret | Field::Password => {}
        }
    }
```

Note the `&mut *self.password` reborrow — `password: Zeroizing<String>` derefs to `String` via `DerefMut`, so this yields `&mut String` and the buffer is still zeroized on drop.

- [ ] **Step 5: `on_key` — cursor-move arms + rebind Backspace/Char**

In `src/tui/wizard/host.rs:421` `match key.code { ... }`:

1. After the `Char('s') if ctrl => self.attempt_save(),` arm, add Ctrl-A / Ctrl-E:
```rust
            KeyCode::Char('a') if ctrl => {
                self.cursor = 0;
                Outcome::Continue
            }
            KeyCode::Char('e') if ctrl => {
                self.cursor = self.focused_text_len();
                Outcome::Continue
            }
```
2. After the `Secret` ←/→ chooser arms (current `:474-483`), and **before** `Backspace`, add the text-field cursor-move arms. They are reached only when focus is a text field, because the chooser arms above (guarded by `self.focus == Field::Auth|Credential|Secret`) catch those first:
```rust
            // Text fields: ←/→ move the in-field cursor; Home/End jump.
            // (Chooser rows are handled by the arms above.)
            KeyCode::Left if !ctrl => {
                self.cursor = self.cursor.saturating_sub(1);
                Outcome::Continue
            }
            KeyCode::Right if !ctrl => {
                self.cursor = self.cursor.min(self.focused_text_len());
                Outcome::Continue
            }
            KeyCode::Home => {
                self.cursor = 0;
                Outcome::Continue
            }
            KeyCode::End => {
                self.cursor = self.focused_text_len();
                Outcome::Continue
            }
```
3. Replace the `Backspace` arm (`:484-487`) to call the new method:
```rust
            KeyCode::Backspace => {
                self.edit_focused_backspace();
                Outcome::Continue
            }
```
4. Replace the `Char(c) if !ctrl` arm (`:488-491`) to call the new method:
```rust
            KeyCode::Char(c) if !ctrl => {
                self.edit_focused_insert(c);
                Outcome::Continue
            }
```

- [ ] **Step 6: `move_focus` resets the cursor**

In `move_focus` (current `:349-358`), after the focus has been moved to the new field, set the cursor to that field's end. The function currently ends by returning or setting `self.focus`; add at the end before it returns:

```rust
    fn move_focus(&mut self, delta: i32) {
        // ... existing body that updates self.focus ...
        self.cursor = self.focused_text_len();
    }
```
(Read the current `move_focus` body; insert `self.cursor = self.focused_text_len();` as the last statement on every path that changes focus — or simply as the unconditional last line, since for a no-op move it is still a valid clamp.)

- [ ] **Step 7: `cursor_target` returns the stored cursor (clamped)**

Replace `cursor_target` (current `:641-653`):

```rust
    fn cursor_target(&self) -> Option<(usize, usize)> {
        let row = self.focus_idx();
        let offset = match self.focus {
            Field::Name => self.cursor.min(self.name.chars().count()),
            Field::Host => self.cursor.min(self.host_addr.chars().count()),
            Field::Port => self.cursor.min(self.port.chars().count()),
            Field::User => self.cursor.min(self.user.chars().count()),
            Field::Identity => self.cursor.min(self.identity.chars().count()),
            Field::Password => self.cursor.min(self.password.chars().count()),
            Field::Auth | Field::Credential | Field::Secret => return None,
        };
        Some((row, offset))
    }
```

- [ ] **Step 8: Run — pass**

```bash
cargo test -p sshrack wizard::host
```
Expected: all host-form tests pass (new + existing, including the existing `left_right_off_auth_row_are_ignored_for_cycling` / `credential_row_left_right_do_not_fire_off_credential_row` which still hold — chooser ←/→ still cycle; text ←/→ now move the cursor).

- [ ] **Step 9: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): cursor movement within host-form text fields"
```

---

## Task 3: Wire the cursor into `CredForm` (mirror of Task 2)

**Files:**
- Modify: `src/tui/wizard/cred.rs`

**Interfaces:**
- Consumes: `super::{insert_char_at, backspace_at}` from Task 1.
- Produces: `CredForm.cursor: usize` (private); same ←/→/Home/End/Ctrl-A/E behavior as `HostForm`, over the cred text fields `Name`/`User`/`Identity`/`Password`.

- [ ] **Step 1: Write the failing tests (RED)**

Add to the `#[cfg(test)]` module in `src/tui/wizard/cred.rs`, mirroring Task 2's tests over the cred form (text fields: `Name`, `User`, `Identity`, `Password`). The `SecretKind` row is the chooser (←/→ cycles kind) — assert it still cycles and does not move a text cursor:

```rust
#[test]
fn left_arrow_moves_cursor_within_a_cred_text_field() {
    let mut form = CredForm::new_add(/* builder the sibling tests use */);
    for c in "ops".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    assert_eq!(form.name, "ops");
    assert_eq!(form.cursor, 2);
    assert_eq!(form.cursor_target(), Some((0, 2)));
}

#[test]
fn typing_inserts_at_cursor_in_cred_form() {
    let mut form = CredForm::new_add(/* builder */);
    for c in "ab".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    form.on_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    form.on_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE));
    assert_eq!(form.name, "Xab");
}

#[test]
fn backspace_deletes_before_cursor_in_cred_form() {
    let mut form = CredForm::new_add(/* builder */);
    for c in "abc".chars() {
        form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    form.on_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
    assert_eq!(form.name, "bc");
}

#[test]
fn left_right_still_cycle_kind_on_secretkind_row() {
    let mut form = CredForm::new_add(/* builder */);
    // Tab to SecretKind.
    form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Name -> User
    form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // User -> Identity
    form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Identity -> SecretKind
    assert_eq!(form.focus, CredField::SecretKind);
    let before = form.secret_kind;
    form.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    assert_ne!(form.secret_kind, before);
}
```

- [ ] **Step 2: Run — expect RED**

```bash
cargo test -p sshrack wizard::cred 2>&1 | head -40
```

- [ ] **Step 3: Apply the exact same shape as Task 2 to `CredForm`**

- Add `pub(super) cursor: usize;` field.
- Add `focused_text_len` over `Name`/`User`/`Identity`/`Password` (chooser `SecretKind` → 0).
- Update every `CredForm { ... }` literal (`rg -n 'CredForm \{' src/`) to add `cursor: 0`, and set `form.cursor = form.focused_text_len();` in the real constructor before returning.
- `edit_focused_push` (`:262`) → `edit_focused_insert` using `insert_char_at`; `password` arm uses `&mut *self.password`.
- `edit_focused_pop` (`:280`) → `edit_focused_backspace` using `backspace_at`.
- `on_key` (`:198`): add Ctrl-A/Ctrl-E arms after `Char('s') if ctrl`; after the `SecretKind` ←/→ chooser arms (`:238-249`) add the text `Left if !ctrl` / `Right if !ctrl` / `Home` / `End` arms; rebind `Backspace` and `Char(c) if !ctrl` to the new methods. (Note: the cred `on_key` `Tab` arm at `:214` has no `!ctrl` guard — leave that as-is; only add the new arms.)
- `move_focus` (`:166`): append `self.cursor = self.focused_text_len();`.
- `cursor_target` (`:412`): return `self.cursor.min(<field>.chars().count())` for each text field; `SecretKind` → `None`.

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack wizard::cred
```

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): cursor movement within cred-form text fields"
```

---

## Task 4: Credential form three-way secret mutex (TUI-only)

**Files:**
- Modify: `src/tui/wizard/cred.rs` (`reachable_fields`, current `:153-159`)

**Interfaces:** none new.

**Context:** the core already models the secret as a single mutually-exclusive slot (shared `CredentialBody` + `validate()`). The defect is purely that `CredForm::reachable_fields` only hides `Password`, leaving `Identity` visible (and focusable) under every secret choice. The host form's `reachable_fields` (`host.rs:324-342`) is the correct model — this task makes cred match it.

- [ ] **Step 1: Write the failing tests (RED)**

Add to the `#[cfg(test)]` module in `src/tui/wizard/cred.rs`:

```rust
#[test]
fn reachable_under_none_hides_identity_and_password() {
    let mut form = CredForm::new_add(/* builder */);
    form.secret_kind = SecretChoice::None;
    let reachable = form.reachable_fields();
    assert!(!reachable.contains(&CredField::Identity));
    assert!(!reachable.contains(&CredField::Password));
    assert!(reachable.contains(&CredField::SecretKind));
}

#[test]
fn reachable_under_identitykey_shows_identity_not_password() {
    let mut form = CredForm::new_add(/* builder */);
    form.secret_kind = SecretChoice::IdentityKey;
    let reachable = form.reachable_fields();
    assert!(reachable.contains(&CredField::Identity));
    assert!(!reachable.contains(&CredField::Password));
}

#[test]
fn reachable_under_password_shows_password_not_identity() {
    let mut form = CredForm::new_add(/* builder */);
    form.secret_kind = SecretChoice::Password;
    let reachable = form.reachable_fields();
    assert!(reachable.contains(&CredField::Password));
    assert!(!reachable.contains(&CredField::Identity));
}
```
(If `reachable_fields` is private, these tests go in the same `#[cfg(test)] mod tests { use super::*; }` block, so they can call it.)

- [ ] **Step 2: Run — expect RED**

```bash
cargo test -p sshrack wizard::cred 2>&1 | head -30
```
Expected: the `None` and `Password` cases fail (Identity currently always present).

- [ ] **Step 3: Implement — mirror the host form's filter**

Replace `reachable_fields` (current `:153-159`):

```rust
    /// The ordered list of fields the user can navigate to, given the current
    /// secret choice. Mirrors `HostForm::reachable_fields` under the Independent
    /// branch: Identity and Password are mutually exclusive (one secret slot),
    /// and both are hidden when the choice is None. SecretKind (the chooser) is
    /// always reachable.
    fn reachable_fields(&self) -> Vec<CredField> {
        CredField::ORDER
            .iter()
            .copied()
            .filter(|f| match self.secret_kind {
                SecretChoice::None => !matches!(f, CredField::Identity | CredField::Password),
                SecretChoice::IdentityKey => *f != CredField::Password,
                SecretChoice::Password => *f != CredField::Identity,
            })
            .collect()
    }
```

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack wizard::cred
```

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "fix(tui): make credential form secret choice three-way mutually exclusive"
```

---

## Task 5: Stop the launcher search-box cursor bleeding through overlays

**Files:**
- Modify: `src/tui/parts.rs` (`draw_search_box` gains a `show_cursor` param)
- Modify: `src/tui/launcher.rs` (`draw_in_shell` threads `show_cursor`)
- Modify: `src/tui/cred_panel.rs` (`draw_in_shell` threads `show_cursor`)
- Modify: `src/tui/app.rs` (pass `self.overlay.is_none()` at the two panel call sites)
- Modify test call sites: `src/tui/launcher.rs:823` test, `src/tui/cred_panel.rs:572` test

**Root cause:** `App::draw` renders the shell (panels) first, then the overlay. The launcher/cred panel's `draw_search_box` calls `frame.set_cursor_position` every frame (`parts.rs:72`). When the wizard overlay focuses a text field, the wizard's `set_cursor_position` runs later and wins. But when the wizard focuses a chooser row (`Auth`/`Credential`/`Secret`), `cursor_target()` returns `None` so the wizard sets no cursor — and the launcher's search-box cursor from earlier in the same frame persists, visibly bleeding through the overlay. Fix: when an overlay is open, the shell must not emit the search-box cursor; the overlay then fully owns the cursor (text field → cursor in field; chooser → no cursor set anywhere → ratatui hides it).

- [ ] **Step 1: Write the failing test (RED)**

Add to `src/tui/parts.rs` test module (or create one). The assertion is robust to `TestBackend`'s default cursor position by comparing a cursor-on draw against a cursor-off draw:

```rust
#[cfg(test)]
mod search_cursor_tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::draw_search_box;

    #[test]
    fn show_cursor_false_does_not_place_cursor_where_true_does() {
        let mut on = Terminal::new(TestBackend::new(60, 6)).unwrap();
        on.draw(|f| draw_search_box(f, f.area(), "abc", 1, 2, true)).unwrap();
        let on_y = on.backend().cursor_position().unwrap_or((0, 0)).1;

        let mut off = Terminal::new(TestBackend::new(60, 6)).unwrap();
        off.draw(|f| draw_search_box(f, f.area(), "abc", 1, 2, false)).unwrap();
        let off_y = off.backend().cursor_position().unwrap_or((0, 0)).1;

        assert_ne!(
            on_y, off_y,
            "show_cursor=false must NOT place the cursor where show_cursor=true does"
        );
    }
}
```

- [ ] **Step 2: Run — expect RED** (signature mismatch — `draw_search_box` takes 5 args, test passes 6)

```bash
cargo test -p sshrack tui::parts::search_cursor 2>&1 | head
```

- [ ] **Step 3: Add the `show_cursor` param to `draw_search_box`**

In `src/tui/parts.rs:41`, change the signature and gate the cursor call (`:72`):

```rust
pub fn draw_search_box(
    frame: &mut Frame,
    area: Rect,
    query: &str,
    matched: usize,
    total: usize,
    show_cursor: bool,
) {
    // ... existing block + paragraph rendering unchanged ...

    if show_cursor {
        // The terminal cursor sits right after the 2-cell `❯ ` prefix, inside
        // the box's content row. `inner` is already inset by border + padding.
        let cursor_x = inner.x + 2 + query.chars().count() as u16;
        let max_x = inner.x + inner.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), inner.y));
    }
}
```
(Move the two `cursor_x`/`max_x` lines inside the `if`. The comments stay with them.)

- [ ] **Step 4: Thread `show_cursor` through `draw_in_shell`**

`src/tui/launcher.rs:317` — add a `show_cursor: bool` param and pass it to `draw_search_box` (`:333`):
```rust
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        hosts: &[Host],
        frecency: &Frecency,
        credentials: &[Credential],
        status: &Status,
        show_cursor: bool,
    ) {
        // ...
        parts::draw_search_box(
            frame,
            search_band,
            &self.query,
            self.ranked.len(),
            hosts.len(),
            show_cursor,
        );
        // ...
    }
```

`src/tui/cred_panel.rs:169` — same change, passing `show_cursor` to `draw_search_box` at `:183`.

(Settings panel `draw_in_shell` has no search box — leave its signature unchanged.)

- [ ] **Step 5: Pass `self.overlay.is_none()` from `App::draw`**

In `src/tui/app.rs:876` and `:884` (the `Tab::Hosts` / `Tab::Credentials` arms), add the argument:

```rust
            Tab::Hosts => self.launcher.draw_in_shell(
                frame,
                panel_area,
                &self.config.hosts,
                &self.frecency,
                &self.config.credentials,
                &self.status,
                self.overlay.is_none(),
            ),
            Tab::Credentials => self.cred_panel.draw_in_shell(
                frame,
                panel_area,
                &self.config.credentials,
                &self.status,
                self.overlay.is_none(),
            ),
```

- [ ] **Step 6: Update the existing panel test call sites**

`src/tui/launcher.rs:823` test (`draw_in_shell_renders_without_panic_sets_cursor_and_uses_focus_marker`) and `src/tui/cred_panel.rs:572` test: add `true` as the new last argument to their `draw_in_shell(...)` calls (these tests assert the cursor IS set in the no-overlay case, so they pass `true`). Run:
```bash
rg -n 'draw_in_shell\(' src/tui/
```
and update every call site — production (`app.rs`) gets `self.overlay.is_none()`; tests get `true` (or `false` if a test specifically checks the overlay case).

- [ ] **Step 7: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace && cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "fix(tui): keep the search-box cursor from bleeding through overlays"
```

---

## Task 6: Switch-bracket rendering + drop the redundant Auth credential name

**Files:**
- Modify: `src/tui/wizard/mod.rs` (add `bracketed` helper)
- Modify: `src/tui/wizard/host.rs` (`Field::Auth` and `Field::Secret` value formatting in `row_value_and_placeholder`)
- Modify: `src/tui/wizard/cred.rs` (`CredField::SecretKind` value formatting)

**Interfaces:**
- Produces: `pub(super) fn bracketed(label: &str) -> String` in `wizard/mod.rs`.

- [ ] **Step 1: Write the failing tests (RED)**

`src/tui/wizard/mod.rs` test module:
```rust
#[cfg(test)]
mod bracket_tests {
    use super::bracketed;

    #[test]
    fn bracketed_wraps_label_with_spaced_angle_brackets() {
        assert_eq!(bracketed("Independent"), "< Independent >");
        assert_eq!(bracketed("Password"), "< Password >");
    }

    #[test]
    fn bracketed_empty_is_two_spaces() {
        assert_eq!(bracketed(""), "<  >");
    }
}
```

`src/tui/wizard/host.rs` test module:
```rust
    #[test]
    fn auth_reference_value_drops_credential_name_and_is_bracketed() {
        let mut form = HostForm::new_add(/* builder */);
        // cycle Auth to Reference (need at least one credential name to pick)
        form.credential_names = vec!["srv-cred".to_string()];
        form.auth_choice = AuthChoice::Reference { idx: 0 };
        let (value, _placeholder) = form.row_value_and_placeholder(Field::Auth);
        assert_eq!(value, "< Reference >");
    }

    #[test]
    fn auth_independent_value_is_bracketed() {
        let mut form = HostForm::new_add(/* builder */);
        form.auth_choice = AuthChoice::Independent;
        let (value, _placeholder) = form.row_value_and_placeholder(Field::Auth);
        assert_eq!(value, "< Independent >");
    }

    #[test]
    fn secret_value_is_bracketed() {
        let mut form = HostForm::new_add(/* builder */);
        form.auth_choice = AuthChoice::Independent;
        form.secret_kind = SecretChoice::Password;
        let (value, _placeholder) = form.row_value_and_placeholder(Field::Secret);
        assert_eq!(value, "< Password >");
    }
```

`src/tui/wizard/cred.rs` test module:
```rust
    #[test]
    fn secretkind_value_is_bracketed() {
        let mut form = CredForm::new_add(/* builder */);
        form.secret_kind = SecretChoice::IdentityKey;
        let (value, _placeholder) = form.row_value_and_placeholder(CredField::SecretKind);
        assert_eq!(value, "< IdentityKey >");
    }
```

- [ ] **Step 2: Run — expect RED**

```bash
cargo test -p sshrack wizard 2>&1 | head -40
```

- [ ] **Step 3: Add `bracketed` to `wizard/mod.rs`**

```rust
/// Wrap a cycleable chooser's label in `< Label >` so the angle brackets
/// signal to the user that the value can be switched left/right. Used by the
/// Auth (Independent/Reference) and Secret (None/Password/IdentityKey) rows in
/// both forms.
pub(super) fn bracketed(label: &str) -> String {
    format!("< {label} >")
}
```

- [ ] **Step 4: Use it in `HostForm::row_value_and_placeholder`**

Replace the `Field::Auth` arm (`host.rs:725-738`) — drop the credential-name suffix and wrap both branches:

```rust
            Field::Auth => {
                let v = match &self.auth_choice {
                    AuthChoice::Independent => bracketed("Independent"),
                    // The Credential row below already shows the chosen name, so
                    // Auth only shows the mode (no ": <name>" suffix).
                    AuthChoice::Reference { .. } => bracketed("Reference"),
                };
                let ph = match self.auth_choice {
                    AuthChoice::Independent => Some("<- -> cycle to Reference"),
                    AuthChoice::Reference { .. } => Some("<- -> cycle to Independent"),
                };
                (v, ph)
            }
```

Replace the `Field::Secret` arm's value line (`host.rs:756-757`):
```rust
            Field::Secret => {
                let v = bracketed(self.secret_kind.label());
                let ph = match self.secret_kind {
                    SecretChoice::None => Some("<- -> cycle: Password / IdentityKey / None"),
                    SecretChoice::Password => Some("type the password below"),
                    SecretChoice::IdentityKey => Some("type the key path"),
                };
                (v, ph)
            }
```
(`label()` stays as the bare one-word label; `bracketed` wraps it at the call site.)

- [ ] **Step 5: Use it in `CredForm::row_value_and_placeholder`**

Replace the `CredField::SecretKind` arm's value line (`cred.rs:481-482`):
```rust
            CredField::SecretKind => {
                let v = bracketed(self.secret_kind.label());
                let ph = match self.secret_kind {
                    SecretChoice::None => Some("<- -> cycle: Password / IdentityKey / None"),
                    SecretChoice::Password => Some("type the password below"),
                    SecretChoice::IdentityKey => Some("type the key path"),
                };
                (v, ph)
            }
```

- [ ] **Step 6: Run — pass**

```bash
cargo test -p sshrack wizard
```

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): bracket switchable chooser values and drop auth name echo"
```

---

## Task 7: Form rendering polish — field-only hints, blank separator, Credential column width

**Files:**
- Modify: `src/tui/dialog.rs` (`draw_dialog` adds a blank row above the footer; `dialog_area` height +1)
- Modify: `src/tui/wizard/mod.rs` (`HOST_LABEL_WIDTH` const + `HOST_VALUE_COL` uses it; comment fix)
- Modify: `src/tui/wizard/host.rs` (hint strings stripped of `^s`/`Esc`/`Tab`; label format width 9→10)
- Modify: `src/tui/wizard/cred.rs` (hint strings stripped)
- Modify: `src/tui/dialog.rs` test (height assertion +1)

- [ ] **Step 1: Write the failing test (RED) for the label column**

`src/tui/wizard/mod.rs` test module:
```rust
    #[test]
    fn host_label_column_fits_the_longest_label() {
        // "Credential" is 10 chars — the column must be at least that wide so
        // every host row's value starts at the same x.
        assert_eq!("Credential".chars().count(), 10);
        assert!(HOST_LABEL_WIDTH as usize >= 10);
        assert_eq!(HOST_VALUE_COL, 2 + HOST_LABEL_WIDTH + 2);
    }
```

And for the hint content, in `src/tui/wizard/host.rs` test module (a value-level check via the rendered hint string — expose the hint via a tiny pure helper if needed, or assert on the literal returned by extracting the hint logic into a `fn hint_for_focus(&self) -> &'static str` tested directly):
```rust
    #[test]
    fn field_hints_do_not_repeat_save_or_cancel() {
        let form = HostForm::new_add(/* builder */);
        for f in [Field::Auth, Field::Credential, Field::Secret, Field::Name] {
            let hint = form.hint_for_focus(f);
            assert!(!hint.contains("^s"), "field hint must not include ^s save: {hint:?}");
            assert!(!hint.contains("Esc"), "field hint must not include Esc cancel: {hint:?}");
        }
    }
```
(To make this testable, extract the hint `match` in `draw_in_dialog` into `fn hint_for_focus(&self, f: Field) -> &'static str` and call it from the draw site. This is a pure refactor that makes the hint testable — do it as part of Step 3.)

- [ ] **Step 2: Run — expect RED**

```bash
cargo test -p sshrack wizard 2>&1 | head -40
```

- [ ] **Step 3: Fix the Credential label column width**

In `src/tui/wizard/mod.rs` (current `:350-355`), introduce a named width const and use it:

```rust
/// Right-alignment width for a host field label. The longest host label is
/// `Credential` (10 chars), so this is 10; the credential-wizard labels stay
/// 8. Used by [`HostForm::render_row`] and to derive the value column below.
pub(super) const HOST_LABEL_WIDTH: u16 = 10;
pub(super) const CRED_LABEL_WIDTH: u16 = 8;

/// Column where the editable value begins within a rendered field row:
/// `"▶ " (2) + right-aligned label + ": " (2)`.
pub(super) const HOST_VALUE_COL: u16 = 2 + HOST_LABEL_WIDTH + 2;
pub(super) const CRED_VALUE_COL: u16 = 2 + CRED_LABEL_WIDTH + 2;
```

In `src/tui/wizard/host.rs:684`, use the named width in the format string:
```rust
        let label_span = Span::styled(
            format!("{cursor}{label:>WIDTH$}: ", WIDTH = HOST_LABEL_WIDTH as usize),
            if focused { /* ... unchanged ... */ } else { /* ... */ },
        );
```

- [ ] **Step 4: Strip `^s`/`Esc`/`Tab` from the field hints; extract `hint_for_focus`**

In `src/tui/wizard/host.rs`, extract the hint match (`:602-612`) into a method and trim each string to its field-specific hotkeys only:

```rust
    /// The field-specific hotkey hint for `field` (field-specific ONLY — the
    /// permanent footer already shows `Tab field · ^s save · Esc cancel`, so it
    /// is not repeated here). Empty-ish rows get a light navigation hint.
    fn hint_for_focus(&self, f: Field) -> &'static str {
        match f {
            Field::Auth => "  <- -> cycle Independent/Reference",
            Field::Credential => "  <- -> cycle  ·  Enter pick credential",
            Field::Secret => "  <- -> cycle None/Password/IdentityKey",
            _ => "  up/down next field",
        }
    }
```

At the draw site (`:602-612`) replace the inline `match` with:
```rust
        let hint = self.hint_for_focus(self.focus);
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);
```

In `src/tui/wizard/cred.rs:384-389`, do the same trim (extract or inline):
```rust
        let hint = if self.focus == CredField::SecretKind {
            "  <- -> cycle kind"
        } else {
            "  up/down next field"
        };
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);
```

- [ ] **Step 5: Add the blank separator row above the footer in `draw_dialog`**

In `src/tui/dialog.rs`, the footer split (`:84-85`) currently is `[body=Fill, footer=Length(1)]`. Insert a blank row between them, and bump the height accounting in `dialog_area` from `+3` to `+4` (border 2 + blank 1 + footer 1):

```rust
    let [body, blank, footer] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    // `blank` is intentionally left empty — one blank row separates the body
    // (which ends with the field-specific hint) from the permanent footer.
    let _ = blank;
    // ... existing footer span rendering into `footer` ...
    body
```

And in `dialog_area`, change `body_rows.saturating_add(3)` → `body_rows.saturating_add(4)`, and the floor `.max(3)` → `.max(4)`:
```rust
    let outer_h = body_rows
        .saturating_add(4) // border(2) + blank(1) + footer(1)
        .min(MAX_H)
        .min(screen.height.saturating_sub(4));
    let h = outer_h.max(4);
```

- [ ] **Step 6: Update the dialog geometry test**

`src/tui/dialog.rs` test `dialog_area_height_tracks_body_rows_then_clamps_to_max` currently asserts `body 5 → outer = 8`. After the +1, `body 5 → outer = 9` (5 + 4). Update:
```rust
    let d = dialog_area(screen, 5);
    assert_eq!(d.height, 9);
```
And any sibling assertion that hardcoded `+3` — grep `rg -n 'saturating_add\(3\)|height, 8' src/tui/` and update.

- [ ] **Step 7: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace && cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): field-only hints with footer separator and aligned credential label"
```

---

## Manual smoke (deferred to the user — controller has no TTY)

After all seven tasks merge, run `cargo run -q --` and verify:
- Host/cred form: ←/→ moves the cursor within Name/Host/Port/User/Identity/Password; Home/End and Ctrl-A/Ctrl-E jump; Backspace deletes before the cursor; typing inserts at the cursor.
- Host/cred form focused on Auth/Credential/Secret: **no cursor bleeds through** from the launcher search box.
- Host/cred form: a **blank line** sits between the field-specific hint and the permanent footer; the field hint shows only its own hotkeys (no `^s`/`Esc`).
- Credential form: under Secret=None both Identity and Password rows vanish; under IdentityKey only Identity shows; under Password only Password shows.
- Host form: every row's value starts at the same column (the `Credential` row no longer juts right).
- Host form Auth=Reference: the value reads `< Reference >` (no `: name`); Auth=Independent reads `< Independent >`; Secret values read `< None >` / `< Password >` / `< IdentityKey >`.

---

## Self-Review

**1. Spec coverage (all seven confirmed problems):**
- (1) text ←/→ cursor → Tasks 1, 2, 3. ✅
- (2) field hint jammed + repeats ^s/Esc → Task 7 (strip + blank separator). ✅
- (NEW) chooser focus → search-box cursor bleed → Task 5. ✅
- (4) cred Identity/Secret not mutex → Task 4 (TUI-only `reachable_fields`). ✅
- (5) Credential label misaligns → Task 7 (`HOST_LABEL_WIDTH` 9→10). ✅
- (6) Auth Reference echoes the name → Task 6 (drop suffix). ✅
- (7) switch values bare → Task 6 (`bracketed`). ✅
- Out of scope (confirmed non-reproducing): Tab escape; vault passphrase cursor. Documented in Scope invariant. ✅

**2. Placeholder scan:** The `/* builder */` markers in the host/cred test snippets stand for "the same constructor args the sibling tests in that file already use" — the implementer greps the existing test module and mirrors the established pattern (each form's test module already builds add-mode forms). No TBD/TODO. Every impl step shows complete code.

**3. Type consistency:** `insert_char_at(&mut String, usize, char) -> usize` and `backspace_at(&mut String, usize) -> usize` (Task 1) are used identically in Tasks 2 and 3 (with `&mut *self.password` for the `Zeroizing<String>` fields). `bracketed(&str) -> String` (Task 6) used in host Auth/Secret and cred SecretKind. `HOST_LABEL_WIDTH`/`HOST_VALUE_COL` (Task 7) consistent between `mod.rs` and `render_row`. `draw_search_box(..., show_cursor: bool)` (Task 5) consistent at all three call sites. `hint_for_focus(&self, f) -> &'static str` (Task 7) defined once, called from the draw site.
