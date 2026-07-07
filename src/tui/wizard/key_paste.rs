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
//! never echoed back (security). When the field already holds key material,
//! the bottom hint reports its line COUNT only (never the text), so the empty
//! editor on edit reads as "N line(s) saved, paste to replace" — not "my key
//! vanished". The owning form preserves the original key on save when the
//! popup was left empty (see each form's `build_body`).
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
    widgets::{Block, Borders, Clear, Paragraph},
};
use ratatui_textarea::{Input, Key, TextArea};

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
/// text is never echoed — only its line COUNT surfaces in the hint when the
/// field already holds material). See the module docs for the keymap.
///
/// `Debug` is hand-written (NOT derived): `ratatui_textarea::TextArea`'s
/// derived `Debug` prints the `lines: Vec<String>` field, which would leak the
/// pasted private key / certificate to any `dbg!(popup)` / `format!("{:?}", p)`
/// call. The manual impl surfaces only `kind` and the textarea's line COUNT —
/// mirroring the redacting `Debug` impls on `HostForm` and `CredForm`. `Clone`
/// is derived; `PartialEq`/`Eq` are not available (`TextArea` does not impl
/// them), so tests assert on [`PasteOutcome`] (which is `PartialEq`) rather
/// than on `KeyPaste` directly.
#[derive(Clone)]
pub struct KeyPaste {
    /// Which slot this popup edits (drives the title + which form field the
    /// `Done` text writes back to).
    pub kind: PasteKind,
    /// How many lines of inline material already live in the form field (0
    /// when adding fresh). Drives the "N line(s) saved · empty keeps it" hint
    /// so the empty textarea on edit is not read as "my key vanished". The
    /// key text itself is NEVER echoed — only this count.
    existing_lines: usize,
    textarea: TextArea<'static>,
}

impl std::fmt::Debug for KeyPaste {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER surface the textarea directly: its derived Debug prints the
        // `lines: Vec<String>` field, which would leak the pasted private key
        // / certificate to any `dbg!(popup)` / `format!("{:?}", p)` call.
        // Surface ONLY the line count, so a glance at the popup's Debug still
        // tells you whether the user has pasted anything without ever showing
        // what. Mirrors the redacting Debug impls on HostForm and CredForm.
        f.debug_struct("KeyPaste")
            .field("kind", &self.kind)
            .field("lines", &self.textarea.lines().len())
            .finish()
    }
}

/// Map sshrack's `crossterm` 0.28 [`KeyEvent`] into a [`TextArea`] [`Input`].
///
/// `ratatui-textarea` 0.9 pulls crossterm 0.29 transitively (via
/// `ratatui-crossterm`), whose `KeyEvent` is a *different type* than the
/// crossterm 0.28 `KeyEvent` sshrack uses everywhere else — so
/// `textarea.input(key)` won't type-check. Building an [`Input`] directly from
/// the event's components sidesteps the version skew without forcing a
/// workspace-wide crossterm upgrade. The mapping mirrors the textarea's own
/// `From<ratatui_crossterm::crossterm::event::KeyEvent>` impl: a key-release
/// becomes a no-op `Input::default()`; `BackTab` becomes `Tab` + shift;
/// everything else maps its [`KeyCode`] to the textarea's [`Key`] and carries
/// the ctrl/alt/shift modifiers through.
///
/// **Newline normalization (paste fix):** `Enter`, a bare `Char('\n'/'\r')`,
/// and the raw-mode `Ctrl+J` stand-in for a pasted LF byte (crossterm 0.28
/// `parse.rs`, Issue #371) are all re-mapped to a plain modifier-less
/// `Key::Enter`, so a pasted multi-line key keeps every line instead of
/// collapsing to one (the textarea's own keymap binds Ctrl+J to
/// `delete_line_by_head`). See the inline comment at the call site for the
/// full chain.
///
/// Private to this module: the popup is the only consumer of the textarea
/// bridge now that both forms route inline-key editing through it.
///
/// [`TextArea`]: ratatui_textarea::TextArea
fn textarea_input_from(key: KeyEvent) -> Input {
    if key.kind == KeyEventKind::Release {
        return Input::default();
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    // crossterm reports Shift+Tab as BackTab (no SHIFT in modifiers); surface
    // it to the textarea as a shifted Tab so its own shortcut logic matches.
    if key.code == KeyCode::BackTab {
        return Input {
            key: Key::Tab,
            shift: true,
            ctrl,
            alt,
        };
    }
    // Raw-mode paste fix: a terminal without bracketed paste delivers a pasted
    // newline as the raw LF byte (0x0A). crossterm 0.28 (parse.rs, Issue #371)
    // decodes 0x0A in raw mode via the `b'\x01'..=b'\x1A'` arm — i.e. as
    // Ctrl+J (`KeyCode::Char('j')` + CONTROL) — rather than as Enter. The
    // textarea's own keymap binds Ctrl+J to `delete_line_by_head`, so without
    // this rewrite every pasted newline deletes the current line head and a
    // multi-line paste collapses to its last line. Re-map every newline shape
    // — Enter, a bare Char('\n'/'\r'), and the Ctrl+J stand-in — to a plain
    // modifier-less Enter so the textarea inserts a newline (paste-preserving).
    let is_newline = key.code == KeyCode::Enter
        || key.code == KeyCode::Char('\n')
        || key.code == KeyCode::Char('\r')
        || (ctrl && key.code == KeyCode::Char('j'));
    if is_newline {
        return Input {
            key: Key::Enter,
            ctrl: false,
            alt: false,
            shift: false,
        };
    }
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let key_code = match key.code {
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Enter => Key::Enter,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Tab => Key::Tab,
        KeyCode::Delete => Key::Delete,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Esc => Key::Esc,
        KeyCode::F(n) => Key::F(n),
        // Insert / Null / any future variant the textarea does not care about:
        // map to Null, which the textarea treats as a no-op.
        _ => Key::Null,
    };
    Input {
        key: key_code,
        ctrl,
        alt,
        shift,
    }
}

impl KeyPaste {
    /// Line count of already-saved inline material for the popup hint: 0 when
    /// the buffer is blank (adding fresh), else its line count. Pure; the popup
    /// hints only the count ("N line(s) saved"), never the text. Shared by the
    /// host and credential forms so the blank-vs-count rule lives in one place.
    pub fn saved_line_count(buf: &str) -> usize {
        if buf.trim().is_empty() {
            0
        } else {
            buf.lines().count()
        }
    }

    /// Open a fresh popup for `kind` with an empty buffer. `existing_lines` is
    /// the line count already saved in the form field (0 when adding a new
    /// key, e.g. from [`KeyPaste::saved_line_count`]); it only drives the "N
    /// line(s) saved" hint — the text itself is never loaded into the textarea.
    pub fn new(kind: PasteKind, existing_lines: usize) -> Self {
        Self {
            kind,
            existing_lines,
            textarea: TextArea::default(),
        }
    }

    /// Pure key decision: `Esc` → [`PasteOutcome::Done`] with the joined
    /// buffer, `Ctrl-C` → [`PasteOutcome::Cancel`], everything else forwarded
    /// to the textarea and → [`PasteOutcome::Pending`]. Performs no I/O.
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
        let _ = self.textarea.input(textarea_input_from(key));
        PasteOutcome::Pending
    }

    /// Paint the popup as a centered, clear-backed bordered area over the
    /// form: the [`TextArea`] fills the body (it draws its own cursor-line
    /// highlight), with a one-line keymap hint pinned to the bottom. Rendering
    /// only — mutates nothing.
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
        let [ta_area, hint_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(inner);
        // `&TextArea` implements `Widget` (ratatui-textarea 0.9.2); it draws
        // its own cursor-line highlight. We do NOT call `set_cursor_position`
        // — the highlight is the visual feedback (matches the upstream
        // `popup_placeholder` example and the prior inline editor).
        frame.render_widget(&self.textarea, ta_area);
        // When the field already holds key material, say so by line COUNT only
        // — the empty textarea would otherwise read as "my key vanished".
        // Empty keeps the original; pasting replaces it. The text itself is
        // never echoed.
        let hint = if self.existing_lines > 0 {
            Line::from(format!(
                " {} line(s) saved · empty keeps it · Esc done ",
                self.existing_lines
            ))
        } else {
            Line::from(" Enter newline · Esc done · Ctrl-C discard ")
        }
        .style(Style::new().dim());
        frame.render_widget(Paragraph::new(hint), hint_area);
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
        let p = KeyPaste::new(PasteKind::Private, 0);
        assert_eq!(p.kind, PasteKind::Private);
        assert!(p.textarea.lines().iter().all(|l| l.is_empty()));
    }

    #[test]
    fn saved_line_count_is_zero_for_blank_and_counts_for_text() {
        // Blank (incl. whitespace-only) → 0; otherwise the line count. This is
        // the number the popup hints as "N line(s) saved" — never the text.
        assert_eq!(KeyPaste::saved_line_count(""), 0);
        assert_eq!(
            KeyPaste::saved_line_count("   \n  "),
            0,
            "whitespace-only is treated as blank"
        );
        assert_eq!(KeyPaste::saved_line_count("one line"), 1);
        assert_eq!(KeyPaste::saved_line_count("a\nb\nc"), 3);
    }

    #[test]
    fn new_with_existing_lines_keeps_textarea_empty() {
        // The count drives only the hint; the textarea must stay empty so the
        // existing key text is never echoed back into the editor.
        let p = KeyPaste::new(PasteKind::Private, 16);
        assert_eq!(p.existing_lines, 16);
        assert!(
            p.textarea.lines().iter().all(|l| l.is_empty()),
            "textarea must be empty even when existing material is hinted"
        );
    }

    #[test]
    fn draw_overlay_renders_without_panic_with_existing_lines() {
        // The "N line(s) saved" hint branch must render without panic when the
        // field already holds material (existing_lines > 0).
        use ratatui::{Terminal, backend::TestBackend};
        let p = KeyPaste::new(PasteKind::Private, 16);
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }

    #[test]
    fn esc_with_empty_buffer_returns_done_empty() {
        let mut p = KeyPaste::new(PasteKind::Private, 0);
        let out = p.on_key(press(KeyCode::Esc));
        assert_eq!(out, PasteOutcome::Done(String::new()));
    }

    #[test]
    fn esc_after_typing_returns_done_with_joined_text() {
        let mut p = KeyPaste::new(PasteKind::Cert, 0);
        // Type "lineA", Enter (newline), "lineB".
        for c in "lineA".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        let _ = p.on_key(press(KeyCode::Enter));
        for c in "lineB".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(
            p.on_key(press(KeyCode::Esc)),
            PasteOutcome::Done("lineA\nlineB".into())
        );
    }

    #[test]
    fn ctrl_c_returns_cancel_regardless_of_buffer() {
        let mut p = KeyPaste::new(PasteKind::Private, 0);
        for c in "abc".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(
            p.on_key(press_ctrl(KeyCode::Char('c'))),
            PasteOutcome::Cancel
        );
    }

    #[test]
    fn enter_is_pending_and_inserts_a_newline() {
        // Enter must NOT close the popup (it inserts a newline instead). After
        // Enter + one char, Esc yields two lines.
        let mut p = KeyPaste::new(PasteKind::Private, 0);
        assert!(matches!(
            p.on_key(press(KeyCode::Enter)),
            PasteOutcome::Pending
        ));
        let _ = p.on_key(press(KeyCode::Char('x')));
        assert_eq!(
            p.on_key(press(KeyCode::Esc)),
            PasteOutcome::Done("\nx".into())
        );
    }

    #[test]
    fn printable_chars_are_pending_and_accumulate() {
        let mut p = KeyPaste::new(PasteKind::Private, 0);
        for c in "hi".chars() {
            assert!(matches!(
                p.on_key(press(KeyCode::Char(c))),
                PasteOutcome::Pending
            ));
        }
        assert_eq!(
            p.on_key(press(KeyCode::Esc)),
            PasteOutcome::Done("hi".into())
        );
    }

    #[test]
    fn key_release_is_pending() {
        let mut p = KeyPaste::new(PasteKind::Private, 0);
        let release =
            KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        assert!(matches!(p.on_key(release), PasteOutcome::Pending));
    }

    #[test]
    fn draw_overlay_renders_without_panic_private() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut p = KeyPaste::new(PasteKind::Private, 0);
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
        let p = KeyPaste::new(PasteKind::Cert, 0);
        let backend = TestBackend::new(40, 12); // small terminal — must not panic
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }

    #[test]
    fn debug_impl_does_not_leak_textarea_contents() {
        // The hand-written Debug must show only the line COUNT, never the
        // pasted key text. `format!("{:?}", p)` going to logs/errors must not
        // leak "SECRET". Mirrors `host_debug_impl_does_not_leak_textarea_contents`.
        let mut p = KeyPaste::new(PasteKind::Private, 0);
        for c in "SECRET".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        let dbg = format!("{p:?}");
        assert!(
            !dbg.contains("SECRET"),
            "Debug must not leak textarea contents: {dbg}"
        );
        assert!(
            dbg.contains("lines"),
            "Debug must surface the line-count field: {dbg}"
        );
        assert!(dbg.contains("lines: 1"), "expected 1 line: {dbg}");
        assert!(
            dbg.contains("kind"),
            "Debug must surface the kind field: {dbg}"
        );
    }

    // ===============================================================
    // Paste regression: raw-mode terminals without bracketed paste
    // deliver a pasted newline byte (0x0A) as Ctrl+J, not as Enter.
    // crossterm 0.28's parse.rs (Issue #371) maps 0x0A via the
    // `b'\x01'..=b'\x1A'` arm to `KeyCode::Char('j') + CONTROL`. The
    // textarea's own keymap binds Ctrl+J to `delete_line_by_head`, so a
    // pasted multi-line key collapsed to its last line (every newline
    // deleted the line head). The bridge must re-map every newline shape
    // — Enter, bare Char('\n'/'\r'), and the raw-mode Ctrl+J stand-in — to
    // a plain Enter so paste preserves every line.
    // ===============================================================

    #[test]
    fn ctrl_j_is_treated_as_a_newline_so_paste_keeps_lines() {
        let mut p = KeyPaste::new(PasteKind::Private, 0);
        for c in "lineA".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        // A pasted LF byte arrives as Ctrl+J in raw mode (see test doc above).
        let pasted_newline = KeyEvent::new_with_kind(
            KeyCode::Char('j'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert!(matches!(p.on_key(pasted_newline), PasteOutcome::Pending));
        for c in "lineB".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(
            p.on_key(press(KeyCode::Esc)),
            PasteOutcome::Done("lineA\nlineB".into())
        );
    }

    #[test]
    fn textarea_input_from_normalizes_every_newline_shape_to_plain_enter() {
        // Enter, bare Char('\n'), bare Char('\r'), and raw-mode Ctrl+J must all
        // become a modifier-less Key::Enter (so the textarea inserts a newline
        // rather than, in the Ctrl+J case, deleting the line head).
        let cases = [
            (
                "Enter",
                KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Press),
            ),
            (
                "bare LF",
                KeyEvent::new_with_kind(
                    KeyCode::Char('\n'),
                    KeyModifiers::NONE,
                    KeyEventKind::Press,
                ),
            ),
            (
                "bare CR",
                KeyEvent::new_with_kind(
                    KeyCode::Char('\r'),
                    KeyModifiers::NONE,
                    KeyEventKind::Press,
                ),
            ),
            (
                "raw-mode Ctrl+J",
                KeyEvent::new_with_kind(
                    KeyCode::Char('j'),
                    KeyModifiers::CONTROL,
                    KeyEventKind::Press,
                ),
            ),
        ];
        for (label, ev) in cases {
            let inp = textarea_input_from(ev);
            assert_eq!(inp.key, Key::Enter, "{label}: key must normalize to Enter");
            assert!(!inp.ctrl, "{label}: ctrl must be cleared");
            assert!(!inp.alt, "{label}: alt must be cleared");
            assert!(!inp.shift, "{label}: shift must be cleared");
        }
    }
}
