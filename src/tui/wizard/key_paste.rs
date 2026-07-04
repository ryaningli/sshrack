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
    widgets::{Block, Borders, Clear, Paragraph},
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
        let hint =
            Line::from(" Enter newline · Esc done · Ctrl-C discard ").style(Style::new().dim());
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
        assert_eq!(
            p.on_key(press(KeyCode::Esc)),
            PasteOutcome::Done("lineA\nlineB".into())
        );
    }

    #[test]
    fn ctrl_c_returns_cancel_regardless_of_buffer() {
        let mut p = KeyPaste::new(PasteKind::Private);
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
        let mut p = KeyPaste::new(PasteKind::Private);
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
        let mut p = KeyPaste::new(PasteKind::Private);
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
        let mut p = KeyPaste::new(PasteKind::Private);
        let release =
            KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
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

    #[test]
    fn debug_impl_does_not_leak_textarea_contents() {
        // The hand-written Debug must show only the line COUNT, never the
        // pasted key text. `format!("{:?}", p)` going to logs/errors must not
        // leak "SECRET". Mirrors `host_debug_impl_does_not_leak_textarea_contents`.
        let mut p = KeyPaste::new(PasteKind::Private);
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
}
