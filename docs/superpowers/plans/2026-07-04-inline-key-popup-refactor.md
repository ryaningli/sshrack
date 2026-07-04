# Inline-Key Popup Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Replace the inline "expand-below-the-list" textarea editor for inline identity keys (private key + optional certificate) with a modal popup textarea, matching the upstream `ratatui-textarea` `popup_placeholder` example's best practice (`Esc` closes the popup and hands the buffer back; `Enter` is free to be a newline).

**Architecture:** Introduce one new shared sub-state module `src/tui/wizard/key_paste.rs` — a `KeyPaste { kind, textarea }` owned by each form as `Option<KeyPaste>` (mirroring the existing `HostForm.cred_picker: Option<CredPicker>` modal pattern: `on_key` routes every key into it while open, `draw_overlay` paints it after the form). Each form's `inline_private`/`inline_cert` fields change type from `TextArea` to plain `String` buffers (the form body no longer renders a textarea — editing happens only in the popup). The form's `on_key` drops the textarea-input guard and instead opens the popup on `Enter` over the `InlinePrivate`/`InlineCert` trigger rows; `draw_in_dialog` collapses from a 4-split (list/editor/error/hint) back to a 3-split (list/error/hint) and paints the popup on top. `sshrack-core` is untouched (TUI-only).

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, `ratatui-textarea` 0.9 (already a dependency).

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via params/seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **TDD for pure logic** — RED → GREEN → REFACTOR. Process/render behavior is covered by no-panic `TestBackend` smoke tests.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Passwords / key material are `Zeroizing<String>` / `Secret` end-to-end** — never logged, printed, embedded in errors, placed in argv, or echoed back on edit. The inline key text is NEVER prefilled into the popup (it starts empty on every open, including edit).
- **`sshrack-core` zero-UI invariant** — this plan never touches `crates/sshrack-core/`.
- **Tests are hermetic** — `SSHRACK_PASSPHRASE=test cargo test --workspace -- --test-threads=1` must stay green; never use `env -u`.
- **Dev stage, no compat code** — replace the inline-textarea path outright; remove `TEXTAREA_H`, the textarea-input guard, the `editor_area` split, and the `TextArea` buffer fields. No parallel old path.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). **No `Co-Authored-By`.**
- **Run on branch `feat/inline-key-popup`** (branched from `main` at `025d0ea`). Never commit on `main`.

---

## Keymap Contract (the UX this plan delivers)

| Context | Key | Action |
|---|---|---|
| Field row `Privkey` / `Cert` (focused) | `Enter` | Open the paste popup (empty textarea) |
| Inside the popup | `Enter` | Insert newline (textarea default) |
| Inside the popup | `Esc` | **Done** — close; if the buffer is non-blank, write it back to the form field; if blank, leave the form field unchanged (preserves the original on edit) |
| Inside the popup | `Ctrl-C` | **Cancel** — close; discard the popup buffer (form field unchanged) |
| Inside the popup | any other key | Forwarded to the textarea (typing, arrows, `Backspace`, `Tab`=indent, emacs shortcuts) |
| Popup closed | `Ctrl-S` | Save the whole form (unchanged) |
| Popup closed | `Esc` | Cancel the whole form back to the launcher (unchanged) |

The popup is **modal**: while open, every key goes to `KeyPaste::on_key` (routed at the top of the form's `on_key`, before the `Ctrl-C`-cancels-form check — so `Ctrl-C` inside the popup discards the popup, not the form). This mirrors exactly how `HostForm.cred_picker` is routed (`host.rs:594-604`).

---

## File Structure (target)

```
src/tui/wizard/
├── key_paste.rs        # NEW — KeyPaste modal sub-state (kind + TextArea) + PasteKind
│                       #   + PasteOutcome + on_key + draw_overlay. textarea_input_from
│                       #   moves here in Task 4 (it is the only remaining caller).
├── mod.rs              # TEXTAREA_H deleted; textarea_input_from moved out (Task 4);
│                       #   `pub mod key_paste;` + re-exports added (Task 1);
│                       #   CredField/Field/SourceChoice doc comments updated (Task 4).
├── cred.rs             # CredForm.inline_private/inline_cert: TextArea → String;
│                       #   on_key: drop textarea guard, add key_paste modal route +
│                       #   Enter-opens-popup; draw_in_dialog 4→3 split + popup overlay;
│                       #   body_rows drops TEXTAREA_H; Debug + row_value use String.
├── host.rs             # HostForm mirror of cred.rs (Independent branch only;
│                       #   Reference branch + cred_picker untouched).
└── cred_picker.rs      # UNCHANGED (the pattern we copy).
src/tui/popup.rs        # UNCHANGED (centered_rect + render_popup already sufficient;
                       #   KeyPaste::draw_overlay composes its own chrome to add a hint row).
src/tui/app.rs          # UNCHANGED (form owns key_paste; app only calls form.on_key / draw_in_dialog).
CLAUDE.md               # TUI inline-paste wording updated to popup (Task 4).
```

---

## Inventory (current state — the contract this plan rewrites)

- `wizard/mod.rs:49` — `pub(crate) const TEXTAREA_H: u16 = 5;` (the expanded-block height; **delete**).
- `wizard/mod.rs:69-112` — `fn textarea_input_from(key: KeyEvent) -> Input` (the crossterm-0.28 → ratatui-textarea bridge; **move to `key_paste.rs` in Task 4**).
- `wizard/cred.rs:65,69` — `pub inline_private: TextArea<'static>` / `pub inline_cert: TextArea<'static>` (**→ `String`**).
- `wizard/cred.rs:126-127` — Debug shows `inline_private_lines` / `inline_cert_lines` via `.lines().len()` (**→ `String::lines().count()`**).
- `wizard/cred.rs:149-150, 215-216` — `TextArea::default()` in `new_add`/`new_edit` (**→ `String::new()`**).
- `wizard/cred.rs:355-383` — the textarea-input guard in `on_key` (**delete**).
- `wizard/cred.rs:413-424` — `Enter` arm (**add popup trigger for `InlinePrivate`/`InlineCert`**).
- `wizard/cred.rs:601-602` — `build_body` reads `self.inline_private.lines().join("\n")` (**→ `self.inline_private.clone()`**).
- `wizard/cred.rs:635-731` — `draw_in_dialog` 4-split with `editor_area` (**→ 3-split + `key_paste.draw_overlay`**).
- `wizard/cred.rs:789-823` — `body_rows` adds `TEXTAREA_H` when a textarea is focused (**→ drop `textarea_extra`**).
- `wizard/cred.rs:877-897` — `row_value_and_placeholder` inline arms use `.lines().len()` + `lines()[0].is_empty()` (**→ `String`-based summary**).
- `wizard/host.rs:83,87` — `inline_private`/`inline_cert` `TextArea` (**→ `String`**).
- `wizard/host.rs:153-154` — Debug line counts (**→ `String::lines().count()`**).
- `wizard/host.rs:181-182, 278-279` — `TextArea::default()` (**→ `String::new()`**).
- `wizard/host.rs:613-641` — textarea-input guard (**delete**).
- `wizard/host.rs:663-683` — `Enter` arm (**add popup trigger**).
- `wizard/host.rs:378-...` (`build_inline_body`) — reads `.lines().join("\n")` (**→ `String::clone`**).
- `wizard/host.rs:888-...` — `draw_in_dialog` 4-split (**→ 3-split + popup**).
- `wizard/host.rs:1045-1068` — `body_rows` `textarea_extra` (**→ drop**).
- `wizard/host.rs:1172-1197` — `row_value_and_placeholder` inline arms (**→ `String`-based**).

Every test that constructs `f.inline_private = TextArea::new(vec![...])` or calls `f.inline_private.input(...)` / `.lines()` must be updated (Tasks 2 & 3 list them).

---

## Task 1: `src/tui/wizard/key_paste.rs` — the modal paste popup

**Files:**
- Create: `src/tui/wizard/key_paste.rs`
- Modify: `src/tui/wizard/mod.rs` (declare the module + re-export)

**Interfaces:**
- Consumes: `super::textarea_input_from` (still lives in `mod.rs` until Task 4), `crate::tui::popup::centered_rect`, `crate::tui::theme`, `crossterm::event::{KeyEvent, KeyEventKind, KeyModifiers, KeyCode}`.
- Produces (used by Tasks 2 & 3):
  - `pub enum PasteKind { Private, Cert }`
  - `pub enum PasteOutcome { Done(String), Cancel, Pending }`
  - `pub struct KeyPaste { pub kind: PasteKind, textarea: TextArea<'static> }`
  - `impl KeyPaste { pub fn new(kind: PasteKind) -> Self; pub fn on_key(&mut self, key: KeyEvent) -> PasteOutcome; pub fn draw_overlay(&self, frame: &mut Frame); }`

- [ ] **Step 1: Declare the module + re-exports**

In `src/tui/wizard/mod.rs`, next to `pub mod cred_picker;` (around line 32):

```rust
pub mod key_paste;
```

And next to the existing `pub use cred_picker::{CredPicker, PickerOutcome};` (around line 36):

```rust
pub use key_paste::{KeyPaste, PasteKind, PasteOutcome};
```

- [ ] **Step 2: Write the failing tests (RED)**

Create `src/tui/wizard/key_paste.rs` with the module doc, the imports, the three types' definitions (so it compiles), but leave `on_key`/`draw_overlay`/`new` bodies as `todo!()` — then add this test module. (The `todo!()` panic is the RED signal.)

```rust
//! Modal multiline paste popup for inline identity-key material (private key
//! and optional certificate). Owned by [`CredForm`] / [`HostForm`] as
//! `Option<KeyPaste>` and routed exactly like the credential picker:
//! [`KeyPaste::on_key`] decides every key while the popup is open, and
//! [`KeyPaste::draw_overlay`] paints it on top of the form after the form
//! renders itself.
//!
//! The keymap follows the upstream `ratatui-textarea` `popup_placeholder`
//! example: `Enter` inserts a newline (the textarea owns multiline editing),
//! `Esc` closes the popup and hands the buffer back to the caller (which
//! decides whether to write it into the form field), `Ctrl-C` closes and
//! discards. Every other key is forwarded to [`TextArea::input`].
//!
//! The popup textarea is ALWAYS empty on open — existing inline key text is
//! never echoed back (security). The owning form preserves the original key
//! on save when the popup was left empty (see each form's `build_body`).
//!
//! [`CredForm`]: super::cred::CredForm
//! [`HostForm`]: super::host::HostForm
//! [`TextArea::input`]: ratatui_textarea::TextArea::input

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::Style,
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Widget},
};
use ratatui_textarea::TextArea;

/// Which inline-key slot the popup is editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteKind {
    /// The required private key.
    Private,
    /// The optional certificate.
    Cert,
}

/// The pure result of [`KeyPaste::on_key`] handling one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasteOutcome {
    /// `Esc` — close the popup. `text` is the textarea's current contents
    /// (lines joined by `\n`). The caller writes it back to the form field
    /// only when it is non-blank; a blank `text` means "user typed nothing",
    /// which the caller treats as "leave the field unchanged".
    Done(String),
    /// `Ctrl-C` — close the popup and discard its contents. The form field is
    /// left unchanged.
    Cancel,
    /// Any other key (including a key release): keep editing.
    Pending,
}

/// Modal multiline paste popup. `textarea` always starts empty (existing key
/// text is never echoed). See the module docs for the keymap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPaste {
    /// Which slot this popup edits (drives the title + which form field the
    /// `Done` text writes back to).
    pub kind: PasteKind,
    textarea: TextArea<'static>,
}

impl KeyPaste {
    /// Open a fresh popup for `kind` with an empty buffer.
    pub fn new(kind: PasteKind) -> Self {
        Self {
            kind,
            textarea: TextArea::default(),
        }
    }

    /// Pure key decision: `Esc` → [`PasteOutcome::Done`] with the joined
    /// buffer, `Ctrl-C` → [`PasteOutcome::Cancel`], everything else forwarded
    /// to the textarea and → [`PasteOutcome::Pending`]. Performs no I/O.
    pub fn on_key(&mut self, key: KeyEvent) -> PasteOutcome {
        todo!()
    }

    /// Paint the popup as a centered, clear-backed bordered area over the
    /// form: the [`TextArea`] fills the body (it draws its own cursor-line
    /// highlight), with a one-line keymap hint pinned to the bottom. Rendering
    /// only — mutates nothing.
    pub fn draw_overlay(&self, frame: &mut Frame) {
        todo!()
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

    #[test]
    fn new_starts_empty() {
        let p = KeyPaste::new(PasteKind::Private);
        assert_eq!(p.kind, PasteKind::Private);
        assert!(p.textarea.lines().iter().all(|l| l.is_empty()));
    }

    #[test]
    fn esc_with_empty_buffer_returns_done_empty() {
        let mut p = KeyPaste::new(PasteKind::Private);
        let out = p.on_key(press(KeyCode::Esc));
        assert_eq!(out, PasteOutcome::Done(String::new()));
    }

    #[test]
    fn esc_after_typing_returns_done_with_joined_text() {
        let mut p = KeyPaste::new(PasteKind::Cert);
        // Type "lineA", Enter (newline), "lineB".
        for c in "lineA".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        let _ = p.on_key(press(KeyCode::Enter));
        for c in "lineB".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(p.on_key(press(KeyCode::Esc)), PasteOutcome::Done("lineA\nlineB".into()));
    }

    #[test]
    fn ctrl_c_returns_cancel_regardless_of_buffer() {
        let mut p = KeyPaste::new(PasteKind::Private);
        for c in "abc".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(p.on_key(press_ctrl(KeyCode::Char('c'))), PasteOutcome::Cancel);
    }

    #[test]
    fn enter_is_pending_and_inserts_a_newline() {
        // Enter must NOT close the popup (it inserts a newline instead). After
        // Enter + one char, Esc yields two lines.
        let mut p = KeyPaste::new(PasteKind::Private);
        assert!(matches!(p.on_key(press(KeyCode::Enter)), PasteOutcome::Pending));
        let _ = p.on_key(press(KeyCode::Char('x')));
        assert_eq!(p.on_key(press(KeyCode::Esc)), PasteOutcome::Done("\nx".into()));
    }

    #[test]
    fn printable_chars_are_pending_and_accumulate() {
        let mut p = KeyPaste::new(PasteKind::Private);
        for c in "hi".chars() {
            assert!(matches!(p.on_key(press(KeyCode::Char(c))), PasteOutcome::Pending));
        }
        assert_eq!(p.on_key(press(KeyCode::Esc)), PasteOutcome::Done("hi".into()));
    }

    #[test]
    fn key_release_is_pending() {
        let mut p = KeyPaste::new(PasteKind::Private);
        let release = KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        assert!(matches!(p.on_key(release), PasteOutcome::Pending));
    }

    #[test]
    fn draw_overlay_renders_without_panic_private() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut p = KeyPaste::new(PasteKind::Private);
        for c in "x".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }

    #[test]
    fn draw_overlay_renders_without_panic_cert_empty() {
        use ratatui::{Terminal, backend::TestBackend};
        let p = KeyPaste::new(PasteKind::Cert);
        let backend = TestBackend::new(40, 12); // small terminal — must not panic
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }
}
```

- [ ] **Step 3: Run — expect RED (panic at `todo!()`)**

```bash
SSHRACK_PASSPHRASE=test cargo test -p sshrack --lib tui::wizard::key_paste
```
Expected: tests fail (panic `not yet implemented`) at `on_key` / `draw_overlay`.

- [ ] **Step 4: Implement `on_key` (GREEN)**

Replace the `on_key` `todo!()`:

```rust
    pub fn on_key(&mut self, key: KeyEvent) -> PasteOutcome {
        if key.kind != KeyEventKind::Press {
            return PasteOutcome::Pending;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // Esc: close and hand the joined buffer back. The caller decides
        // whether a blank buffer writes back (it does not — preserves the
        // original key on edit).
        if key.code == KeyCode::Esc {
            return PasteOutcome::Done(self.textarea.lines().join("\n"));
        }
        // Ctrl-C: close and discard (the popup buffer never reaches the form).
        if ctrl && key.code == KeyCode::Char('c') {
            return PasteOutcome::Cancel;
        }
        // Everything else (incl. Enter → newline, arrows, Backspace, Tab →
        // indent, emacs shortcuts) is owned by the textarea.
        let _ = self.textarea.input(super::textarea_input_from(key));
        PasteOutcome::Pending
    }
```

- [ ] **Step 5: Implement `draw_overlay` (GREEN)**

Replace the `draw_overlay` `todo!()`. The popup composes its own chrome (not `popup::render_popup`) so it can pin a keymap hint below the textarea:

```rust
    pub fn draw_overlay(&self, frame: &mut Frame) {
        let area = crate::tui::popup::centered_rect(
            frame.area(),
            crate::tui::popup::POPUP_WIDTH,
            crate::tui::popup::POPUP_HEIGHT,
        );
        frame.render_widget(Clear, area);
        let title = match self.kind {
            PasteKind::Private => " private key ",
            PasteKind::Cert => " certificate (optional) ",
        };
        let block = Block::new()
            .borders(Borders::ALL)
            .title(format!(" {title} "))
            .title_style(crate::tui::theme::accent().add_modifier(ratatui::style::Modifier::BOLD));
        frame.render_widget(&block, area);
        let inner = block.inner(area);
        // Textarea fills the body; a one-line hint sits below it. When the
        // terminal is too short for the hint, the textarea still gets the
        // whole inner area (the layout collapses the hint to 0 first).
        let [ta_area, hint_area] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(inner);
        // `&TextArea` implements `Widget` (ratatui-textarea 0.9.2); it draws
        // its own cursor-line highlight. We do NOT call `set_cursor_position`
        // — the highlight is the visual feedback (matches the upstream
        // `popup_placeholder` example and the prior inline editor).
        frame.render_widget(&self.textarea, ta_area);
        let hint = Line::from(" Enter newline · Esc done · Ctrl-C discard ").style(Style::new().dim());
        frame.render_widget(Paragraph::new(hint), hint_area);
    }
```

> Note: `Widget` and `Paragraph` are imported at the top of the file (the use-list in Step 2 already includes `widgets::{Block, Borders, Clear, Paragraph, Widget}`). `Style::new().dim()` needs `use ratatui::style::Style;` (already imported) — `.dim()` comes from `ratatui::style::Stylize`. Add `use ratatui::style::Stylize;` to the imports if the compiler asks for it (it is re-exported by `ratatui::prelude`, but an explicit `use ratatui::style::Stylize;` is the clearest).

- [ ] **Step 6: Run — pass**

```bash
SSHRACK_PASSPHRASE=test cargo test -p sshrack --lib tui::wizard::key_paste
```
Expected: all 10 tests pass.

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add src/tui/wizard/key_paste.rs src/tui/wizard/mod.rs
git commit -m "feat(tui): modal KeyPaste popup for inline key editing"
```

---

## Task 2: `CredForm` — buffer → `String`, popup routing, 3-split draw

**Files:**
- Modify: `src/tui/wizard/cred.rs`

**Interfaces:**
- Consumes (from Task 1): `super::{KeyPaste, PasteKind, PasteOutcome}` (re-exported via `super::` because `mod.rs` re-exports them).
- Produces: an updated `CredForm` whose `inline_private`/`inline_cert` are `String`, whose `on_key` opens a `KeyPaste` on `Enter` over those rows, and whose `draw_in_dialog` paints the popup overlay.

- [ ] **Step 1: Change the buffer field types + Debug**

In `src/tui/wizard/cred.rs`:

1. **Imports.** Add to the existing `use super::{...}` (around line 25) the three new types, and **remove** `textarea_input_from` from that import list (Task 2 stops using it):
   ```rust
   use super::{
       KeyPaste, PasteKind, PasteOutcome, SecretChoice, SourceChoice, backspace_at, bracketed,
       insert_char_at, validate_cred, value_spans, CredField, CredSaveError,
   };
   ```
   (Drop the `textarea_input_from` item. Also drop `TextArea` and `ratatui_textarea::{Input, Key}` imports if they become unused — they do, because the textarea guard is removed. Check `ratatui_textarea` is no longer referenced anywhere in `cred.rs` and remove its `use`.)

2. **Struct fields** (lines ~65, ~69): change
   ```rust
   pub inline_private: TextArea<'static>,
   ```
   to
   ```rust
   pub inline_private: String,
   ```
   and update the doc comment to:
   ```rust
   /// Multiline private-key paste buffer, written back from the [`KeyPaste`]
   /// popup when the user closes it with a non-blank buffer. Always empty on
   /// edit-entry (the existing key text is NEVER echoed back — security;
   /// [`CredForm::build_body`] preserves the original on save when this stays
   /// blank). A plain `String` (not a `TextArea`) because the form body no
   /// longer renders an editor — editing happens only in the popup.
   ```
   Apply the same change to `inline_cert` (line ~69) with the companion doc.

3. **Debug impl** (lines ~126-127): change
   ```rust
   .field("inline_private_lines", &self.inline_private.lines().len())
   .field("inline_cert_lines", &self.inline_cert.lines().len())
   ```
   to
   ```rust
   .field("inline_private_lines", &self.inline_private.lines().count())
   .field("inline_cert_lines", &self.inline_cert.lines().count())
   ```

4. Add a new field to the `CredForm` struct (after `pub orig_key: Option<KeySource>,`):
   ```rust
   /// The modal inline-key paste popup, open while the user edits the
   /// `InlinePrivate` / `InlineCert` slot. `None` when closed. Routed at the
   /// top of [`CredForm::on_key`] (modal — swallows every key while open,
   /// including `Ctrl-S`, like the host wizard's credential picker).
   pub key_paste: Option<KeyPaste>,
   ```

- [ ] **Step 2: Update `new_add` + `new_edit` constructors**

At every `TextArea::default()` for the inline fields (lines ~149-150 in `new_add`, ~215-216 in `new_edit`), replace with `String::new()`. In **both** constructors, also initialize the new field: `key_paste: None,`.

- [ ] **Step 3: Add the modal route + drop the textarea guard in `on_key`**

In `CredForm::on_key` (starts at line 342), **insert** this modal block right after `self.core_error = None;` (line 347) and **before** the `let ctrl = ...` line:

```rust
        // An open paste popup is modal: route every key into it before the
        // form. `take()` so we can write back to `key_paste` / the inline
        // buffers without a borrow conflict; on Pending the still-open popup
        // goes back. Done writes the buffer back only when non-blank (a blank
        // buffer preserves the field — and the original key on edit); Cancel
        // discards. Swallows every key while open, incl Ctrl-S — close
        // (Esc/Ctrl-C) before ^s can save.
        if let Some(mut paste) = self.key_paste.take() {
            let kind = paste.kind;
            match paste.on_key(key) {
                PasteOutcome::Done(text) => {
                    if !text.trim().is_empty() {
                        match kind {
                            PasteKind::Private => self.inline_private = text,
                            PasteKind::Cert => self.inline_cert = text,
                        }
                    }
                }
                PasteOutcome::Cancel => {}
                PasteOutcome::Pending => self.key_paste = Some(paste),
            }
            self.error = None;
            return Outcome::Continue;
        }
```

Then **delete** the entire inline-textarea guard block (lines ~355-383, the `if matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert) && ... { ... return Outcome::Continue; }` block).

Then in the `match key.code { ... }` `Enter` arm (lines ~413-424), **insert** the popup trigger at the very top of the arm (before `if self.is_last_reachable(...)`):

```rust
            KeyCode::Enter => {
                // Trigger rows: InlinePrivate / InlineCert open the paste
                // popup instead of advancing focus or saving. (Enter inside
                // the popup inserts a newline; the popup is modal, so this
                // arm only fires from the field row, never from inside it.)
                match self.focus {
                    CredField::InlinePrivate => {
                        self.key_paste = Some(KeyPaste::new(PasteKind::Private));
                        self.error = None;
                        return Outcome::Continue;
                    }
                    CredField::InlineCert => {
                        self.key_paste = Some(KeyPaste::new(PasteKind::Cert));
                        self.error = None;
                        return Outcome::Continue;
                    }
                    _ => {}
                }
                if self.is_last_reachable(self.focus) {
                    self.attempt_save()
                } else {
                    self.move_focus(1);
                    Outcome::Continue
                }
            }
```

(The old comment block above the `Enter` arm that explains the textarea guard is now stale — delete it.)

- [ ] **Step 4: `build_body` reads the `String` buffers**

At lines ~601-602, change:
```rust
                        let private = self.inline_private.lines().join("\n");
                        let cert = self.inline_cert.lines().join("\n");
```
to:
```rust
                        let private = self.inline_private.clone();
                        let cert = self.inline_cert.clone();
```

- [ ] **Step 5: `draw_in_dialog` — 4-split → 3-split + popup overlay**

Rewrite `draw_in_dialog` (starts at line 635) so the body is a 3-split and the popup is painted on top. Concretely:

- Delete the `let needs_block = ...; let editor_h = ...; let fields_h = body.height.saturating_sub(2 + editor_h) as usize;` lines; replace `fields_h` with:
  ```rust
  let fields_h = body.height.saturating_sub(2) as usize;
  ```
- Keep the `focus_window` + `rows` computation as-is.
- Change the 4-split `Layout::vertical([Length(rows), Length(editor_h), Length(1), Length(1)])` to a 3-split:
  ```rust
  let [list_area, error_area, hint_area] = Layout::vertical([
      Constraint::Length(rows.len() as u16),
      Constraint::Length(1),
      Constraint::Length(1),
  ])
  .areas(body);
  ```
- Keep `frame.render_widget(Paragraph::new(rows), list_area);`.
- **Delete** the entire `if needs_block { ... frame.render_widget(ta, editor_area); }` block (the multiline editor rendering, lines ~669-686).
- Keep the error_line + hint rendering as-is, but update the textarea-focus hint branch (line ~708):
  ```rust
  } else if matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert) {
      "  Enter edit multiline"
  ```
- In the `cursor_target` guard (lines ~722-730), the comment mentions the textarea; the code (`if let Some((row, offset)) = self.cursor_target() { if win.start <= row ... }`) stays — `cursor_target` already returns `None` for these rows (Step 6 keeps that).
- At the very end of `draw_in_dialog`, **add** (mirroring `HostForm`'s `cred_picker` overlay call):
  ```rust
  if let Some(paste) = &self.key_paste {
      paste.draw_overlay(frame);
  }
  ```
- Update the doc comment above `draw_in_dialog` (lines ~620-634) to describe the 3-split (list/error/hint) + the popup overlay painted on top when `key_paste` is open.

- [ ] **Step 6: `body_rows` drops the `TEXTAREA_H` term**

Rewrite `body_rows` (line 789) to remove the focus-aware `textarea_extra`. The new body:
```rust
    pub fn body_rows(&self) -> u16 {
        let mut max_fields = 0usize;
        for secret in [
            SecretChoice::None,
            SecretChoice::Password,
            SecretChoice::IdentityKey,
        ] {
            for source in [SourceChoice::Path, SourceChoice::Inline] {
                let n = CredField::ORDER
                    .iter()
                    .copied()
                    .filter(|&f| Self::field_reachable(f, secret, source))
                    .count();
                max_fields = max_fields.max(n);
            }
        }
        (max_fields + 2) as u16 // + error row + hint row
    }
```
(There is no more `textarea_extra` and no `TEXTAREA_H` reference. `body_rows` is no longer focus-dependent — it is a stable worst-case height.)

- [ ] **Step 7: `row_value_and_placeholder` inline arms use `String`**

Rewrite the `InlinePrivate` arm (lines ~877-888):
```rust
            CredField::InlinePrivate => {
                // One-line summary of the buffer (never echoes key text):
                // blank → placeholder, non-blank → "N line(s)" count. The
                // full editor opens as a popup on Enter (see `on_key`).
                if self.inline_private.trim().is_empty() {
                    (String::new(), Some("paste private key (Enter to edit)"))
                } else {
                    (
                        format!("{} line(s) of private key", self.inline_private.lines().count()),
                        None,
                    )
                }
            }
```
Apply the matching change to `InlineCert` (lines ~889-897):
```rust
            CredField::InlineCert => {
                if self.inline_cert.trim().is_empty() {
                    (String::new(), Some("optional certificate (Enter to edit)"))
                } else {
                    (
                        format!("{} line(s) of certificate", self.inline_cert.lines().count()),
                        None,
                    )
                }
            }
```

- [ ] **Step 8: Update the tests**

In the `#[cfg(test)]` module:

- **`build_body_inline_source_attaches_inline_key`** (line ~1336) and **`build_body_inline_source_multiline_joins_with_newline`** (line ~1354): change
  ```rust
  f.inline_private = TextArea::new(vec!["PRIVATE-KEY-TEXT".into()]);
  f.inline_cert = TextArea::new(vec!["CERT-TEXT".into()]);
  ```
  to
  ```rust
  f.inline_private = "PRIVATE-KEY-TEXT".to_string();
  f.inline_cert = "CERT-TEXT".to_string();
  ```
  and the multiline variant:
  ```rust
  f.inline_private = "line1\nline2\nline3".to_string();
  ```
  (The `join("\n")` assertion on the built body stays valid because `build_body` now uses the string verbatim.)

- **`build_body_inline_blank_on_edit_preserves_original_inline_key`** (line ~1369): change `f.inline_private = TextArea::default();` to `f.inline_private = String::new();`.

- **`typing_into_inline_private_goes_to_the_textarea`** (line ~1860): this test's premise (typing on the focused row feeds the textarea) is gone. **Delete it** and replace with a popup-flow test:
  ```rust
  #[test]
  fn enter_on_inline_private_opens_popup_and_esc_writes_back() {
      let mut f = CredForm::new_add();
      f.secret_kind = SecretChoice::IdentityKey;
      f.source = SourceChoice::Inline;
      f.focus = CredField::InlinePrivate;
      // Enter opens the popup.
      let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
      assert!(f.key_paste.is_some());
      // Typing goes into the popup, not the form field.
      for c in "PRIVATE-KEY-TEXT".chars() {
          let _ = f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
      }
      assert!(f.inline_private.is_empty());
      // Esc closes and writes the non-blank buffer back.
      let _ = f.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
      assert!(f.key_paste.is_none());
      assert_eq!(f.inline_private, "PRIVATE-KEY-TEXT");
  }
  ```
  (Use the file's existing `press` helper; if it is named differently, mirror the surrounding tests' helper.)

- **`ctrl_c_inside_popup_discards_without_writing_back`** (new test, add next to the one above):
  ```rust
  #[test]
  fn ctrl_c_inside_popup_discards_without_writing_back() {
      let mut f = CredForm::new_add();
      f.secret_kind = SecretChoice::IdentityKey;
      f.source = SourceChoice::Inline;
      f.focus = CredField::InlineCert;
      let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
      for c in "ab".chars() {
          let _ = f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
      }
      // Ctrl-C discards.
      let _ = f.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
      assert!(f.key_paste.is_none());
      assert!(f.inline_cert.is_empty(), "discard leaves the field unchanged");
  }
  ```

- **`enter_on_inline_private_then_blank_esc_keeps_field_empty`** (new test):
  ```rust
  #[test]
  fn blank_popup_esc_does_not_write_back() {
      let mut f = CredForm::new_add();
      f.secret_kind = SecretChoice::IdentityKey;
      f.source = SourceChoice::Inline;
      f.focus = CredField::InlinePrivate;
      let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
      // Esc with no typing → blank Done → field stays empty.
      let _ = f.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
      assert!(f.inline_private.is_empty());
  }
  ```

- **`body_rows_grows_when_a_textarea_is_focused`** (line ~2055): the premise (focus-dependent `body_rows`) is gone. **Delete it** and replace with a stability pin:
  ```rust
  #[test]
  fn body_rows_is_stable_across_secret_and_source_states() {
      // body_rows no longer depends on focus (no inline editor block); it is a
      // stable worst-case across every (secret, source) combo.
      for secret in [SecretChoice::None, SecretChoice::Password, SecretChoice::IdentityKey] {
          for source in [SourceChoice::Path, SourceChoice::Inline] {
              let mut f = CredForm::new_add();
              f.secret_kind = secret;
              f.source = source;
              f.focus = CredField::Name;
              let baseline = f.body_rows();
              f.focus = CredField::InlinePrivate;
              assert_eq!(f.body_rows(), baseline, "focus-independent for {secret:?}/{source:?}");
          }
      }
  }
  ```
  (If a test with this exact name already exists from a prior refactor, update it in place rather than duplicating.)

- **`draw_in_dialog_renders_without_panic_across_source_and_focus_states`** (line ~2017) and **`draw_in_dialog_renders_textarea_focus_without_panic_on_short_terminal`** (line ~1639): these still exercise `draw_in_dialog` across states — keep them, but they must no longer rely on the `editor_area`. Verify they still compile (they construct a form and call `draw_in_dialog` via a `TestBackend`); if a now-dead `TEXTAREA_H` reference appears, remove it. The short-terminal test should still pass because the 3-split never overflows.

- **`new_edit_inline_original_defaults_source_to_inline_with_empty_textarea`** (line ~1872) and any test asserting `f.inline_private.lines().join("\n").is_empty()`: change to `f.inline_private.is_empty()`. Rename the test to drop "textarea" (e.g. `..._with_empty_buffer`) only if the file's convention prefers it; otherwise leave the name.

- Any test at line ~1987 that calls `f.inline_private.input(textarea_input_from(...))`: rewrite to set `f.inline_private = "...".to_string();` directly (it was simulating typed input; a direct assignment is the equivalent setup for a `String` buffer).

- If `TEXTAREA_H` is referenced by absolute path in any test (`crate::tui::wizard::TEXTAREA_H` or `super::TEXTAREA_H`), those references must go away in this task (the const is deleted in Task 4, but cred.rs tests must not reference it first).

- [ ] **Step 9: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace
SSHRACK_PASSPHRASE=test cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add src/tui/wizard/cred.rs
git commit -m "refactor(tui): cred wizard inline key via popup, buffer to String"
```
Expected: workspace tests green (the new popup tests replace the deleted textarea-input tests; net count should be ≥ the pre-task count minus deleted plus added). clippy clean (no unused `TextArea`/`textarea_input_from` imports).

---

## Task 3: `HostForm` — mirror Task 2 on the Independent branch

**Files:**
- Modify: `src/tui/wizard/host.rs`

**Interfaces:**
- Consumes (from Task 1): `super::{KeyPaste, PasteKind, PasteOutcome}`.
- Produces: an updated `HostForm` whose Independent-branch inline fields are `String` buffers edited via the popup. The Reference branch, the credential chooser (`cycle_credential`, `cred_picker`, `CredPicker`), and `draw_overlay` for the picker are **byte-for-byte unchanged**.

- [ ] **Step 1: Change the buffer field types + Debug + add `key_paste`**

Mirror Task 2 Step 1 on `HostForm`:

1. **Imports.** Add `KeyPaste, PasteKind, PasteOutcome` to the `use super::{...}`; **remove** `textarea_input_from` and the `ratatui_textarea` imports that become unused (`TextArea`, `Input`, `Key`) after the guard is removed.
2. **Struct fields** (lines ~83, ~87): `pub inline_private: TextArea<'static>` → `pub inline_private: String` (and same doc rewrite as Task 2). Same for `inline_cert`.
3. **Debug impl** (lines ~153-154): `.lines().len()` → `.lines().count()` for both.
4. Add `pub key_paste: Option<KeyPaste>,` to the struct (after `cred_picker` or after `orig_key` — match the surrounding field order).

- [ ] **Step 2: Update `new_add` + `new_edit` constructors**

At every `TextArea::default()` for the inline fields (lines ~181-182 in `new_add`, ~278-279 in `new_edit`), replace with `String::new()`. In **both** constructors add `key_paste: None,`.

- [ ] **Step 3: Add the modal route + drop the textarea guard in `on_key`**

In `HostForm::on_key` (starts at line 580), insert the modal block **after** the existing `cred_picker` modal block (lines 594-604) and **before** `let ctrl = ...` (line 606):

```rust
        // An open paste popup is modal (same shape as the cred picker above):
        // route every key into it before the form. Done writes the buffer
        // back only when non-blank; Cancel discards. Swallows every key while
        // open, incl Ctrl-S.
        if let Some(mut paste) = self.key_paste.take() {
            let kind = paste.kind;
            match paste.on_key(key) {
                PasteOutcome::Done(text) => {
                    if !text.trim().is_empty() {
                        match kind {
                            PasteKind::Private => self.inline_private = text,
                            PasteKind::Cert => self.inline_cert = text,
                        }
                    }
                }
                PasteOutcome::Cancel => {}
                PasteOutcome::Pending => self.key_paste = Some(paste),
            }
            self.error = None;
            return Outcome::Continue;
        }
```

**Delete** the inline-textarea guard block (lines ~613-641).

In the `match key.code { ... }` `Enter` arm (lines ~663-683), the `Credential` trigger already exists (lines 670-676). **Add** the inline trigger right after the `Credential` block (before `if self.is_last_reachable(...)`):

```rust
                // Inline key paste trigger rows: open the popup. (Enter inside
                // the popup inserts a newline; the popup is modal.)
                if matches!(self.focus, Field::InlinePrivate | Field::InlineCert) {
                    self.key_paste = Some(KeyPaste::new(match self.focus {
                        Field::InlinePrivate => PasteKind::Private,
                        Field::InlineCert => PasteKind::Cert,
                        // Guarded by the matches! above.
                        _ => unreachable!("invariant: focus is InlinePrivate/InlineCert"),
                    }));
                    self.error = None;
                    return Outcome::Continue;
                }
```

(Delete the stale comment above the `Enter` arm referencing the textarea guard.)

- [ ] **Step 4: `build_inline_body` reads the `String` buffers**

At lines ~401-402, change `.lines().join("\n")` to `.clone()`:
```rust
                        let private = self.inline_private.clone();
                        let cert = self.inline_cert.clone();
```

- [ ] **Step 5: `draw_in_dialog` — 4-split → 3-split + popup overlay**

Mirror Task 2 Step 5 on `HostForm::draw_in_dialog` (starts at line 888):

- Replace `fields_h = body.height.saturating_sub(2 + editor_h)` with `fields_h = body.height.saturating_sub(2) as usize;`; delete `needs_block` / `editor_h`.
- 4-split → 3-split (`[list_area, error_area, hint_area]`).
- Delete the `if needs_block { ... frame.render_widget(ta, editor_area); }` block (around lines ~920-935).
- Update the textarea-focus hint branch to `"  Enter edit multiline"`.
- **After** the existing `if let Some(picker) = &self.cred_picker { picker.draw_overlay(frame); }` (line ~981), add:
  ```rust
  if let Some(paste) = &self.key_paste {
      paste.draw_overlay(frame);
  }
  ```
  (Both overlays can coexist in code, but only one is open at a time: opening the paste popup requires `focus` on an Inline row, which is unreachable under the Reference branch where the picker opens.)
- Update the `draw_in_dialog` doc comment to describe the 3-split + popup.

- [ ] **Step 6: `body_rows` drops the `TEXTAREA_H` term**

Rewrite `body_rows` (line 1045): remove the `textarea_extra` block (lines ~1062-1066) and the `+ textarea_extra` from the return:
```rust
        (max_fields + 2) as u16 // + error row + hint row
```
(Keep the `for auth in ... for secret in ... for source in ...` sweep as-is.)

- [ ] **Step 7: `row_value_and_placeholder` inline arms use `String`**

Mirror Task 2 Step 7 on the `InlinePrivate` (lines ~1172-1188) and `InlineCert` (lines ~1189-1197) arms:
```rust
            Field::InlinePrivate => {
                if self.inline_private.trim().is_empty() {
                    (String::new(), Some("paste private key (Enter to edit)"))
                } else {
                    (
                        format!("{} line(s) of private key", self.inline_private.lines().count()),
                        None,
                    )
                }
            }
            Field::InlineCert => {
                if self.inline_cert.trim().is_empty() {
                    (String::new(), Some("optional certificate (Enter to edit)"))
                } else {
                    (
                        format!("{} line(s) of certificate", self.inline_cert.lines().count()),
                        None,
                    )
                }
            }
```

- [ ] **Step 8: Update the tests**

Mirror Task 2 Step 8 on `host.rs` tests:

- **`host_typing_into_inline_private_goes_to_the_textarea`** (line ~2338): delete; replace with `host_enter_on_inline_private_opens_popup_and_esc_writes_back` (same body as the cred equivalent, but constructing `HostForm::new_add(vec![])` and setting `auth_choice = AuthChoice::Independent`, `secret_kind = SecretChoice::IdentityKey`, `source = SourceChoice::Inline`, `focus = Field::InlinePrivate`).
- Add `host_ctrl_c_inside_popup_discards_without_writing_back` and `host_blank_popup_esc_does_not_write_back` (Field::InlineCert / Field::InlinePrivate).
- **`body_rows_is_stable_across_auth_secret_and_source_states`** (line ~2196): keep the sweep, but it no longer needs the focus-dependent assertion — it already pins a stable height. If it currently special-cases a focused textarea, drop that. Rename to `..._and_source_states` if a textarea reference is in the name.
- Any test setting `f.inline_private = TextArea::new(...)` (lines ~2495-2496, ~2516, ~2535) or calling `.input(textarea_input_from(...))` (line ~2467): rewrite to direct `f.inline_private = "...".to_string();`.
- Tests asserting `f.inline_private.lines().join("\n") == "..."` (lines ~2347, ~2372, ~2407, ~2430): change to `f.inline_private == "..."`.
- The `dbg.contains("inline_private_lines: 1")` assertion (line ~2482) stays valid because the Debug still surfaces a line count — but the count is now `String::lines().count()`. A single-line string with content (`"PRIVATE-KEY-TEXT"`) has `lines().count() == 1`. ✓
- Add an explicit pin that the Reference branch never opens the paste popup (mirrors the existing `host_reference_branch_keeps_inline_fields_unreachable` test at line ~1686):
  ```rust
  #[test]
  fn reference_branch_never_opens_paste_popup_on_enter() {
      let mut f = HostForm::new_add(vec!["c0".into()]);
      f.auth_choice = AuthChoice::Reference { idx: 0 };
      // Inline fields are unreachable under Reference, so even if focus is
      // forced onto one, Enter must not open a paste popup.
      f.focus = Field::InlinePrivate;
      let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
      assert!(f.key_paste.is_none());
  }
  ```

- [ ] **Step 9: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace
SSHRACK_PASSPHRASE=test cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add src/tui/wizard/host.rs
git commit -m "refactor(tui): host wizard inline key via popup, buffer to String"
```

---

## Task 4: Move `textarea_input_from` into `key_paste.rs`, delete `TEXTAREA_H`, refresh docs

**Files:**
- Modify: `src/tui/wizard/mod.rs`
- Modify: `src/tui/wizard/key_paste.rs` (absorb `textarea_input_from`, make it private)
- Modify: `CLAUDE.md`

**Interfaces:** none new. This task finishes the dev-stage cleanup: after Tasks 2 & 3, `textarea_input_from` in `mod.rs` has exactly one caller (`key_paste.rs`), and `TEXTAREA_H` has zero callers.

- [ ] **Step 1: Move `textarea_input_from` from `mod.rs` to `key_paste.rs`**

In `src/tui/wizard/key_paste.rs`:

- Add the function body (cut from `mod.rs:69-112`) **above** the `KeyPaste` impl, changed to a module-private `fn` (drop any `pub`/`pub(crate)` — only `key_paste.rs` uses it now):
  ```rust
  /// Map sshrack's crossterm-0.28 `KeyEvent` into a [`TextArea`] [`Input`].
  /// (Full doc comment from mod.rs — the crossterm version-skew rationale.)
  ///
  /// [`TextArea`]: ratatui_textarea::TextArea
  /// [`Input`]: ratatui_textarea::Input
  fn textarea_input_from(key: KeyEvent) -> Input {
      // ... identical body to the current mod.rs impl ...
  }
  ```
- Add the needed imports at the top of `key_paste.rs`: `use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};` (KeyCode/KeyEventKind/KeyModifiers are already there; ensure all are present) and `use ratatui_textarea::{Input, Key};`.
- In `KeyPaste::on_key`, change `super::textarea_input_from(key)` → `textarea_input_from(key)`.

In `src/tui/wizard/mod.rs`:

- **Delete** the entire `textarea_input_from` fn (lines ~51-112) **and** its doc comment.
- **Delete** `use ratatui_textarea::{Input, Key};` from the imports (line ~28) — no longer used here.
- **Delete** the `TEXTAREA_H` const (lines ~39-49) and its doc comment.
- Update the module-level `//!` doc and the `CredField` / `Field` / `SourceChoice` doc comments: replace "edited in a multiline area" / "the multiline editor block expanded below the field list" wording with "edited in a popup (`Enter` opens it)" / "the [`KeyPaste`] popup". The `InlinePrivate` / `InlineCert` variant docs on `CredField` (lines ~406-410) and `Field` (lines ~182-187) should now say the slot is a trigger row that opens the popup.

- [ ] **Step 2: Verify the move compiles and no caller is stranded**

```bash
cargo build --workspace
```
Expected: clean. If a stray `use super::textarea_input_from;` survived in `cred.rs`/`host.rs`, remove it (Tasks 2 & 3 should already have dropped it, but confirm). `grep -rn textarea_input_from src/` should show exactly one hit (the definition in `key_paste.rs`).

```bash
grep -rn "TEXTAREA_H" src/
```
Expected: no hits.

- [ ] **Step 3: Refresh `CLAUDE.md`**

Find the TUI section describing inline-key paste (the "**Identity-key source + inline paste**" paragraph). Rewrite the "two multiline paste areas render instead … and expand to a taller block when focused; `Enter` inserts a newline, `Tab`/`Shift-Tab` navigate fields, and `Ctrl-S` saves" sentence to describe the popup:

> … Under `Inline` the Privkey/Cert rows become **trigger rows**: pressing `Enter` on either opens a modal `KeyPaste` popup (a centered `ratatui-textarea`) where the key is pasted. Inside the popup `Enter` inserts a newline, `Esc` closes it (writing the buffer back only if non-blank — a blank close preserves the original key on edit), and `Ctrl-C` discards. The key text is **never echoed**: the popup starts empty on every open (including edit), so the existing inline key is never rendered; if the popup is left blank, the original inline key is preserved unchanged.

Also update the TUI keys table if it enumerates the paste bindings.

- [ ] **Step 4: Full gate + manual smoke**

```bash
cargo build --workspace --release
SSHRACK_PASSPHRASE=test cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
Expected: release build ok; all tests green; clippy clean; fmt clean.

Manual smoke (the controller has no TTY — record this as a follow-up for the human if it cannot run here): `cargo run -q --` → `^a` (add host or credential) → Secret `→` IdentityKey → Source `→` Inline → focus `Privkey` → `Enter` → confirm a centered popup opens with a blinking cursor-line → paste/type → `Esc` closes and the row shows "N line(s) of private key" → reopen, type, `Ctrl-C` discards. Resize the terminal small; the popup clamps and never panics.

- [ ] **Step 5: Commit**

```bash
git add src/tui/wizard/mod.rs src/tui/wizard/key_paste.rs CLAUDE.md
git commit -m "refactor(tui): move textarea bridge into key_paste, drop TEXTAREA_H"
```

Then use the `superpowers:finishing-a-development-branch` skill to merge `feat/inline-key-popup` into `main`.

---

## Self-Review

**1. Spec coverage:**
- Popup opens on `Enter` over Privkey/Cert (both forms) — Task 2 Step 3, Task 3 Step 3. ✅
- `Enter` inside popup = newline (textarea default) — Task 1 Step 4. ✅
- `Esc` = done (blank → preserve, non-blank → write back) — Task 1 Step 4 + Task 2/3 Step 3 modal route. ✅
- `Ctrl-C` inside popup = discard (form field unchanged) — Task 1 Step 4 + modal route. ✅
- Upstream `popup_placeholder` best practice (Esc hands buffer back, textarea owns Enter) — Task 1. ✅
- Buffer `TextArea` → `String` (dev-stage cleanup, no dual-purpose editor) — Task 2/3 Steps 1–4. ✅
- 4-split → 3-split + popup overlay (no dead `editor_area`) — Task 2/3 Step 5. ✅
- `body_rows` no longer focus-dependent — Task 2/3 Step 6. ✅
- Key text never echoed (popup starts empty, including edit) — Task 1 `new` + Task 2/3 constructors leave buffers empty; `orig_key` preserves on blank. ✅
- Thorough dead-code removal (`TEXTAREA_H`, `textarea_input_from` relocation, stale guard/comments, unused imports) — Task 4 + each task's import cleanup. ✅
- Reference branch + `cred_picker` untouched — Task 3 explicitly pins this; Task 3 Step 8 adds a guard test. ✅
- `app.rs` unchanged — confirmed by architecture (form owns `key_paste`). ✅

**2. Placeholder scan:** Every step carries the actual code or a precise "find X, replace with Y" with the new code block. No TBD/TODO. Test bodies are written out. Where a test is "the same shape as the cred equivalent," the cred equivalent is fully written in Task 2 and the host task names the deltas (auth/secret setup) explicitly — this is not "similar to Task N" hand-waving, it is a named construction.

**3. Type consistency:**
- `PasteOutcome::Done(String)` — produced by `KeyPaste::on_key` (Task 1), consumed by both forms' modal routes (Tasks 2/3). The `String` is the joined buffer in both directions. ✅
- `PasteKind::{Private, Cert}` — set in `KeyPaste::new`, read in the modal route to pick the field. ✅
- `inline_private`/`inline_cert`: `String` everywhere after Tasks 2/3 (struct field, Debug, constructors, `build_body`/`build_inline_body`, `row_value_and_placeholder`, tests). ✅
- `key_paste: Option<KeyPaste>` on both forms, `None` in both constructors, routed identically. ✅
- `textarea_input_from`: defined in `mod.rs` for Tasks 1–3 (`super::textarea_input_from`), moved to `key_paste.rs` (private `fn`) in Task 4 — the single naming/scope change is explicit in Task 4 Step 1. ✅
