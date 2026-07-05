//! Credential add/edit wizard form. Pure view state over core's
//! `credential::add_credential` / `credential::apply_patch`; the persist
//! half lives in [`super::super::app`].
//!
//! The password is held as a [`Zeroizing<String>`] so the plaintext is wiped
//! on drop; it is rendered masked (`•`) and never placed in errors or logs.
//! The hand-written [`std::fmt::Debug`] impl redacts the password so
//! `format!("{:?}", form)` / `dbg!(form)` can never leak it.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::super::intent::Outcome;
use super::super::theme;
use super::{
    CRED_LABEL_WIDTH, CRED_VALUE_COL, CredField, CredSaveError, KeyPaste, PasteKind, PasteOutcome,
    SecretChoice, SourceChoice, backspace_at, bracketed, insert_char_at, validate_cred,
    value_spans,
};
use crate::tui::file_picker::{FilePicker, FilePickerOutcome};
use crate::tui::fit::truncate_cells;
use sshrack_core::config::schema::{Credential, CredentialBody, KeySource};
use sshrack_core::dirsource::LocalDirSource;

/// The credential form's editable state. The password is held as a
/// [`Zeroizing<String>`] so the plaintext is wiped on drop; it is rendered
/// masked (`•`) and never placed in errors or logs. The wizard builds this
/// either empty (add mode) or prefilled from an existing [`Credential`] (edit
/// mode).
#[derive(Clone)]
pub struct CredForm {
    /// Editable credential name.
    pub name: String,
    /// Editable login user. Required.
    pub user: String,
    /// Editable identity-key path, edited when the secret choice is
    /// [`SecretChoice::IdentityKey`] AND the source is [`SourceChoice::Path`].
    /// Empty for Password / None choices and under the Inline source (the key
    /// text lives in [`CredForm::inline_private`]).
    pub identity: String,
    /// The selected secret kind, cycled by `←`/`→` on the secret row.
    pub secret_kind: SecretChoice,
    /// Identity-key source (Path | Inline), cycled by `←`/`→` on the Source
    /// row. Relevant only under [`SecretChoice::IdentityKey`]; ignored (and
    /// stays [`SourceChoice::Path`]) for Password / None.
    pub source: SourceChoice,
    /// Multiline private-key paste buffer, written back from the [`KeyPaste`]
    /// popup when the user closes it with a non-blank buffer. Always empty on
    /// edit-entry (the existing key text is NEVER echoed back — security;
    /// [`CredForm::build_body`] preserves the original on save when this stays
    /// blank). A plain `String` because the form body no longer renders an
    /// editor — editing happens only in the popup.
    pub inline_private: String,
    /// Multiline optional certificate paste buffer, written back from the
    /// [`KeyPaste`] popup. Companion to [`CredForm::inline_private`]: same
    /// lifecycle, always empty on edit-entry, edited only under Inline source.
    pub inline_cert: String,
    /// The masked password, edited when the secret choice is
    /// [`SecretChoice::Password`]. `Zeroizing` so it is wiped on drop.
    pub password: Zeroizing<String>,
    /// Currently focused field.
    pub focus: CredField,
    /// Char-index cursor within the focused text field. Reset to the focused
    /// field's end on focus change; clamped on read by [`cursor_target`].
    /// Irrelevant for the Source chooser and the multiline paste fields (the
    /// [`KeyPaste`] popup owns its own cursor while open).
    pub(super) cursor: usize,
    /// A transient validation error to show under the bad field. Cleared on the
    /// next edit to that field.
    pub error: Option<CredSaveError>,
    /// A core-level error surfaced by the loop after a persist attempt failed
    /// (duplicate name, store mode undecided, write error). Cleared on the next
    /// keystroke.
    pub core_error: Option<String>,
    /// Whether the wizard is editing an existing credential (vs adding a new
    /// one). Add mode persists via `credential::add_credential` with a fresh id;
    /// edit mode preserves the original id (keyring-keyed).
    pub editing: bool,
    /// The original credential's id, carried in edit mode so the loop can stamp
    /// it onto the patched credential (preserving the keyring entry). `None` in
    /// add mode.
    pub orig_id: Option<Ulid>,
    /// The original body's [`KeySource`] when the credential carried a key at
    /// edit time. Under the Inline source the paste buffers start EMPTY (the
    /// key text is never echoed); [`CredForm::build_body`] re-attaches this
    /// verbatim when the private field stays blank, so silently dropping it
    /// never destroys the credential's only secret. `None` in add mode and when
    /// the original had no key.
    pub orig_key: Option<KeySource>,
    /// The modal inline-key paste popup, open while the user edits the
    /// `InlinePrivate` / `InlineCert` slot. `None` when closed. Routed at the
    /// top of [`CredForm::on_key`] (modal — swallows every key while open,
    /// including `Ctrl-S`, like the host wizard's credential picker).
    pub key_paste: Option<KeyPaste>,
    /// Modal file picker for the Identity path (Path source). `None` when
    /// closed. Routed at the top of [`CredForm::on_key`] (modal — swallows
    /// every key while open, incl `Ctrl-S`, like the paste popup). The picker
    /// is a reusable component ([`crate::tui::file_picker`]) that does NOT
    /// import this module; it returns the chosen absolute path via
    /// [`FilePickerOutcome::Pick`]. Directory listing is injected via
    /// [`LocalDirSource`] now; a future `SftpDirSource` reuses the picker.
    pub file_picker: Option<FilePicker<LocalDirSource>>,
}

impl std::fmt::Debug for CredForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the password so `format!("{:?}", form)` / `dbg!(form)` can
        // never leak the plaintext to logs or error messages. `Zeroizing<Z>`
        // derives `Debug` by delegating to `Z`, so the derived impl would
        // otherwise print it. Mirrors the redacting Debug on `config::Secret`.
        // `identity` holds a key file *path*, not key material, so it is safe.
        // `orig_key` delegates to `KeySource`'s redacting `Debug`, which
        // surfaces the path but redacts inline key text.
        //
        // The two inline-paste buffers are NEVER surfaced directly: a raw
        // `String` Debug would print the pasted private key / certificate to
        // any `dbg!(form)` / `format!("{form:?}")` call. Surface ONLY their
        // line count, so a glance at the form's Debug still tells you whether
        // the user has pasted anything without ever showing what.
        f.debug_struct("CredForm")
            .field("name", &self.name)
            .field("user", &self.user)
            .field("identity", &self.identity)
            .field("secret_kind", &self.secret_kind)
            .field("source", &self.source)
            .field("inline_private_lines", &self.inline_private.lines().count())
            .field("inline_cert_lines", &self.inline_cert.lines().count())
            .field("password", &"<redacted>")
            .field("focus", &self.focus)
            .field("error", &self.error)
            .field("core_error", &self.core_error)
            .field("editing", &self.editing)
            .field("orig_id", &self.orig_id)
            .field("orig_key", &self.orig_key)
            .field("file_picker", &self.file_picker.is_some())
            .finish()
    }
}

impl CredForm {
    /// Build a fresh add-mode form (all fields blank, focus on name, no
    /// secret, source defaults to [`SourceChoice::Path`]).
    pub fn new_add() -> Self {
        let mut form = Self {
            name: String::new(),
            user: String::new(),
            identity: String::new(),
            secret_kind: SecretChoice::None,
            source: SourceChoice::Path,
            inline_private: String::new(),
            inline_cert: String::new(),
            password: Zeroizing::new(String::new()),
            focus: CredField::Name,
            cursor: 0,
            error: None,
            core_error: None,
            editing: false,
            orig_id: None,
            orig_key: None,
            key_paste: None,
            file_picker: None,
        };
        form.cursor = form.focused_text_len();
        form
    }

    /// Build an edit-mode form prefilled from `cred`. The secret kind is
    /// derived from the body via [`CredentialBody::secret_kind`]; a
    /// keyring-marker body maps to [`SecretChoice::Password`] (the password
    /// itself lives in the keyring and is not surfaced as plaintext here — the
    /// wizard lets the user set a new password to overwrite it, or switch to a
    /// different kind).
    ///
    /// **Source + identity prefill.** Under a `Key` body the source chooser
    /// opens reflecting the original: [`SourceChoice::Path`] with `identity`
    /// prefilled from the path, or [`SourceChoice::Inline`] with `identity`
    /// left blank (the key text is NEVER echoed into the paste buffer —
    /// security). The original [`KeySource`] is carried as `orig_key`
    /// regardless, so [`build_body`](Self::build_body) can re-attach an inline
    /// original verbatim when the user does not paste a new key — silently
    /// dropping it would destroy the credential's only secret. The two inline
    /// buffers always start EMPTY on edit entry, even when the original was
    /// inline material; the user pastes a NEW key (via the [`KeyPaste`] popup)
    /// to replace it, or leaves the private field blank to keep the original.
    pub fn new_edit(cred: &Credential) -> Self {
        use sshrack_core::config::schema::SecretKind;
        let body = &cred.body;
        let orig_key = body.key.clone();
        let (secret_kind, source, identity) = match body.secret_kind() {
            SecretKind::Key => {
                let (source, identity) = match body.key.as_ref() {
                    Some(KeySource::Path(p)) => {
                        (SourceChoice::Path, p.to_string_lossy().into_owned())
                    }
                    // Inline original: default to Inline so the user can paste
                    // a NEW key (the old text is never echoed); orig_key
                    // preserves it on save when the private field stays blank.
                    Some(KeySource::Inline(_)) => (SourceChoice::Inline, String::new()),
                    None => (SourceChoice::Path, String::new()),
                };
                (SecretChoice::IdentityKey, source, identity)
            }
            SecretKind::Password | SecretKind::KeyringPassword => {
                (SecretChoice::Password, SourceChoice::Path, String::new())
            }
            SecretKind::Default => (SecretChoice::None, SourceChoice::Path, String::new()),
        };
        let mut form = Self {
            name: cred.name.clone(),
            user: body.user.clone(),
            identity,
            secret_kind,
            source,
            // Inline buffers ALWAYS start empty on edit entry. An inline
            // original's key text is never echoed back (security); the user
            // pastes a new key to replace it, or leaves the private field
            // blank so build_body re-attaches the original.
            inline_private: String::new(),
            inline_cert: String::new(),
            // Never carry the existing plaintext into the form: a password is
            // not echoed back. The user re-types to set a new one; leaving the
            // field empty on a Password-kind edit keeps the existing secret
            // (handled by the loop at save time).
            password: Zeroizing::new(String::new()),
            focus: CredField::Name,
            cursor: 0,
            error: None,
            core_error: None,
            editing: true,
            orig_id: Some(cred.id),
            orig_key,
            key_paste: None,
            file_picker: None,
        };
        form.cursor = form.focused_text_len();
        form
    }

    /// Set a core-level persist error (from the loop). Cleared on the next
    /// keystroke.
    pub fn set_core_error(&mut self, msg: String) {
        self.core_error = Some(msg);
    }

    /// The ordered list of fields the user can navigate to, given the current
    /// secret + source choices. See [`CredForm::field_reachable`] for the
    /// predicate.
    fn reachable_fields(&self) -> Vec<CredField> {
        CredField::ORDER
            .iter()
            .copied()
            .filter(|&f| Self::field_reachable(f, self.secret_kind, self.source))
            .collect()
    }

    /// Whether `field` is reachable under the given `secret` + `source` state.
    /// Pure (takes no `&self`) so [`body_rows`](CredForm::body_rows) can sweep
    /// every (secret, source) combination to size the dialog to its stable
    /// worst-case height without cloning the form.
    ///
    /// The matrix mirrors the wizard's top-down reading:
    /// - **None** — only Name / User / SecretKind are reachable (no secret
    ///   slot, no Source chooser).
    /// - **Password** — Name / User / SecretKind / Password (no Identity, no
    ///   Source/Inline rows).
    /// - **IdentityKey + Path** — Name / User / SecretKind / Source / Identity
    ///   (the Source chooser appears; the single Identity path-slot is filled).
    /// - **IdentityKey + Inline** — Name / User / SecretKind / Source /
    ///   InlinePrivate / InlineCert (Identity is hidden; the two paste areas
    ///   replace it).
    fn field_reachable(field: CredField, secret: SecretChoice, source: SourceChoice) -> bool {
        match secret {
            SecretChoice::None => !matches!(
                field,
                CredField::Identity
                    | CredField::Password
                    | CredField::Source
                    | CredField::InlinePrivate
                    | CredField::InlineCert
            ),
            SecretChoice::Password => !matches!(
                field,
                CredField::Identity
                    | CredField::Source
                    | CredField::InlinePrivate
                    | CredField::InlineCert
            ),
            SecretChoice::IdentityKey => match source {
                SourceChoice::Path => !matches!(
                    field,
                    CredField::Password | CredField::InlinePrivate | CredField::InlineCert
                ),
                SourceChoice::Inline => !matches!(field, CredField::Password | CredField::Identity),
            },
        }
    }

    fn focus_idx(&self) -> usize {
        let reachable = self.reachable_fields();
        reachable.iter().position(|f| *f == self.focus).unwrap_or(0)
    }

    fn move_focus(&mut self, delta: i32) {
        let reachable = self.reachable_fields();
        if reachable.is_empty() {
            return;
        }
        let cur = self.focus_idx() as i32;
        let next = (cur + delta).rem_euclid(reachable.len() as i32) as usize;
        self.focus = reachable[next];
        self.error = None;
        self.cursor = self.focused_text_len();
    }

    /// True when `field` is the last reachable field (Enter there submits).
    fn is_last_reachable(&self, field: CredField) -> bool {
        let reachable = self.reachable_fields();
        reachable.last().copied() == Some(field)
    }

    /// Pure key decision: mutate form state and return an [`Outcome`]. Performs
    /// **no I/O** — the loop runs persist only when this signals
    /// [`Outcome::SaveCred`]. The `App` routes the cred wizard's intent by the
    /// active [`super::super::intent::Overlay`] (`CredWizard`), so it never collides with
    /// the host wizard's [`Outcome::SaveHost`].
    ///
    /// Bindings mirror [`super::HostForm::on_key`]:
    /// - printable char / `Backspace` → edit the focused text field at the
    ///   in-field cursor (name, user, or password when the choice is Password).
    /// - `←`/`→`/`Home`/`End` (and `Ctrl-A`/`Ctrl-E`) → move the in-field cursor
    ///   on text fields; clamped to the field's char length.
    /// - `Tab` / `↓` → next field; `Shift-Tab` / `↑` → previous field.
    /// - `Enter` → next field, or — on the last reachable field — attempt save;
    ///   on validation error set `error` and move focus to the bad field. On
    ///   the inline-key rows (`InlinePrivate` / `InlineCert`) `Enter` instead
    ///   opens the [`KeyPaste`] popup (modal — see the route at the top); on
    ///   the Identity row `Enter` opens the [`FilePicker`] overlay (modal —
    ///   same shape), which writes the chosen absolute path back to `identity`.
    /// - `Ctrl-S` → attempt save from any field.
    /// - `←`/`→` on the secret row → cycle secret kind.
    /// - `←`/`→` on the Source row (IdentityKey only) → cycle Path / Inline.
    /// - While the [`KeyPaste`] popup or the [`FilePicker`] overlay is open
    ///   every key is routed into it (modal — it swallows `Ctrl-S`, `Tab`,
    ///   etc.); close it with `Esc` (the paste popup writes the buffer back
    ///   when non-blank) or `Ctrl-C` (discard) before the form sees another key.
    /// - `Esc` / `Ctrl-C` → cancel back (when no popup is open).
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        // Any keystroke clears a stale core-level error.
        self.core_error = None;

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

        // An open file picker is modal (same shape as the paste popup above):
        // route every key into it before the form. Pick writes the chosen
        // absolute path back to `identity` and closes; Cancel just closes.
        // Swallows every key while open, incl Ctrl-S.
        if let Some(mut picker) = self.file_picker.take() {
            match picker.on_key(key) {
                FilePickerOutcome::Pick(abs) => {
                    self.identity = abs.to_string_lossy().into_owned();
                    self.cursor = 0;
                }
                FilePickerOutcome::Cancel => {}
                FilePickerOutcome::Pending => self.file_picker = Some(picker),
            }
            self.error = None;
            return Outcome::Continue;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let ctrl_c_only = key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c');

        if ctrl_c_only {
            return Outcome::Cancel;
        }

        match key.code {
            KeyCode::Esc => Outcome::Cancel,
            KeyCode::Char('s') if ctrl => self.attempt_save(),
            // Ctrl-A / Ctrl-E alias Home / End on text fields.
            KeyCode::Char('a') if ctrl => {
                self.cursor = 0;
                Outcome::Continue
            }
            KeyCode::Char('e') if ctrl => {
                self.cursor = self.focused_text_len();
                Outcome::Continue
            }
            KeyCode::Tab => {
                self.move_focus(1);
                Outcome::Continue
            }
            KeyCode::BackTab => {
                self.move_focus(-1);
                Outcome::Continue
            }
            KeyCode::Down if !ctrl => {
                self.move_focus(1);
                Outcome::Continue
            }
            KeyCode::Up if !ctrl => {
                self.move_focus(-1);
                Outcome::Continue
            }
            KeyCode::Enter => {
                // Trigger rows: InlinePrivate / InlineCert open the paste
                // popup instead of advancing focus or saving. Guarded by
                // reachability so a forced focus onto an inline row under a
                // non-IdentityKey secret (or the Path source) never opens the
                // popup — the inline editor is IdentityKey+Inline-only by
                // contract. (Enter inside the popup inserts a newline; the
                // popup is modal, so this arm only fires from the field row,
                // never from inside it.)
                if matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert)
                    && Self::field_reachable(self.focus, self.secret_kind, self.source)
                {
                    self.key_paste = Some(KeyPaste::new(match self.focus {
                        CredField::InlinePrivate => PasteKind::Private,
                        CredField::InlineCert => PasteKind::Cert,
                        _ => unreachable!(
                            "invariant: focus is InlinePrivate/InlineCert (guarded above)"
                        ),
                    }));
                    self.error = None;
                    return Outcome::Continue;
                }
                // Identity row is a trigger (Path source): Enter opens the file
                // picker. Guarded by reachability so it only opens when the
                // Identity path-slot is actually present (IdentityKey + Path).
                // The picker is modal; Enter inside it activates a selection
                // (handled by the modal route above).
                if self.focus == CredField::Identity
                    && Self::field_reachable(self.focus, self.secret_kind, self.source)
                {
                    let mut picker = FilePicker::new(
                        " pick a private key ",
                        Some(self.identity.as_str()),
                        LocalDirSource::new(),
                    );
                    // Front-load the lazy listing so the first render shows
                    // content instead of an empty frame. `new` stays fs-free;
                    // only `ensure_started` touches the (injected) source. The
                    // start candidates fall back to `~`/`/`, so this is also
                    // listable on CI where the identity hint is empty.
                    picker.ensure_started();
                    self.file_picker = Some(picker);
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
            // Secret row: ←/→ cycle None / Password / IdentityKey.
            KeyCode::Left if self.focus == CredField::SecretKind => {
                self.secret_kind = self.secret_kind.prev();
                // Clear an errored password field's focus if it is now
                // unreachable, and clear any field error.
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right if self.focus == CredField::SecretKind => {
                self.secret_kind = self.secret_kind.next();
                self.error = None;
                Outcome::Continue
            }
            // Source row: ←/→ cycle Path / Inline. Only relevant under
            // IdentityKey (Source is unreachable otherwise), but the guard is
            // defensive against a directly-set focus in tests.
            KeyCode::Left
                if self.focus == CredField::Source
                    && self.secret_kind == SecretChoice::IdentityKey =>
            {
                self.source = self.source.prev();
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right
                if self.focus == CredField::Source
                    && self.secret_kind == SecretChoice::IdentityKey =>
            {
                self.source = self.source.next();
                self.error = None;
                Outcome::Continue
            }
            // Text fields: ←/→ move the in-field cursor; Home/End jump.
            // (The SecretKind and Source chooser rows are handled by the arms
            // above. The inline-key rows never reach here for cursor editing:
            // they open the KeyPaste popup on Enter, and ←/→ on them is a
            // no-op cursor move on a non-text field — harmless.)
            KeyCode::Left if !ctrl => {
                self.cursor = self.cursor.saturating_sub(1);
                Outcome::Continue
            }
            KeyCode::Right if !ctrl => {
                // Advance one, clamped to the field's char length (no overshoot
                // past the end). Left mirrors this with a saturating decrement.
                self.cursor = (self.cursor + 1).min(self.focused_text_len());
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
            KeyCode::Backspace => {
                self.edit_focused_backspace();
                Outcome::Continue
            }
            KeyCode::Char(c) if !ctrl => {
                self.edit_focused_insert(c);
                Outcome::Continue
            }
            _ => Outcome::Continue,
        }
    }

    /// Insert `c` at the in-field cursor (advancing it one past the inserted
    /// char). The SecretKind and Source choosers are driven by ←/→; the
    /// Password field only accepts input when secret_kind is Password. The
    /// inline-key rows (InlinePrivate / InlineCert) are NEVER edited through
    /// this char-based path — [`on_key`](Self::on_key) opens the [`KeyPaste`]
    /// popup on `Enter`, and the popup owns the multiline editing — so those
    /// arms are no-ops here, reached only if a future caller bypasses the
    /// popup.
    fn edit_focused_insert(&mut self, c: char) {
        match self.focus {
            CredField::Name => self.cursor = insert_char_at(&mut self.name, self.cursor, c),
            CredField::User => self.cursor = insert_char_at(&mut self.user, self.cursor, c),
            CredField::Password if self.secret_kind == SecretChoice::Password => {
                self.cursor = insert_char_at(&mut self.password, self.cursor, c)
            }
            // No char-based text entry on these rows: SecretKind / Source are
            // ←/→ choosers; InlinePrivate / InlineCert are edited via the
            // KeyPaste popup (opened on Enter in `on_key`); Identity is a
            // trigger row (Enter opens the FilePicker overlay, which writes
            // the chosen path back). None of these ever call this char-based
            // path.
            CredField::Identity
            | CredField::SecretKind
            | CredField::Source
            | CredField::InlinePrivate
            | CredField::InlineCert
            | CredField::Password => {}
        }
        if Some(self.focus) == self.error.map(CredSaveError::field) {
            self.error = None;
        }
    }

    /// Delete the char immediately before the in-field cursor (mirror of
    /// [`edit_focused_insert`]). No-op when the cursor is already at the start.
    /// As with [`edit_focused_insert`], the inline-key rows handle editing via
    /// the [`KeyPaste`] popup; their arms here are unreachable no-ops.
    fn edit_focused_backspace(&mut self) {
        match self.focus {
            CredField::Name => self.cursor = backspace_at(&mut self.name, self.cursor),
            CredField::User => self.cursor = backspace_at(&mut self.user, self.cursor),
            CredField::Password if self.secret_kind == SecretChoice::Password => {
                self.cursor = backspace_at(&mut self.password, self.cursor)
            }
            // See `edit_focused_insert`: the inline-key rows edit via the
            // KeyPaste popup, not char-by-char; Identity edits via the
            // FilePicker overlay.
            CredField::Identity
            | CredField::SecretKind
            | CredField::Source
            | CredField::InlinePrivate
            | CredField::InlineCert
            | CredField::Password => {}
        }
        if Some(self.focus) == self.error.map(CredSaveError::field) {
            self.error = None;
        }
    }

    fn attempt_save(&mut self) -> Outcome {
        match validate_cred(self) {
            Ok(()) => Outcome::SaveCred,
            Err(e) => {
                self.error = Some(e);
                self.focus = e.field();
                Outcome::Continue
            }
        }
    }

    /// Build the core [`CredentialBody`] for this form. Pure: assembles the
    /// body with a plaintext [`Secret::Plain`] password when the choice is
    /// Password and the field is non-empty. The loop seals it per the store
    /// mode after this. An empty password under the Password choice leaves the
    /// password unset (the loop preserves the existing password in edit mode).
    ///
    /// **IdentityKey routing.** The Source chooser picks how the key is
    /// supplied:
    /// - **Path** — `identity` non-empty → `with_key(path)`; blank + an inline
    ///   original → preserve that inline material verbatim (data safety — never
    ///   destroy the credential's only secret just because the path field is
    ///   empty); blank with no inline original → no key.
    /// - **Inline** — the private buffer becomes an inline key via
    ///   [`CredentialBody::with_inline_key`], with the cert buffer attached
    ///   only when non-empty. A blank private field on edit preserves the
    ///   original inline material verbatim (the buffer is NEVER prefilled with
    ///   key text on edit-entry — security; this rule is the only thing
    ///   standing between the user and silently losing their key).
    ///
    /// [`Secret::Plain`]: sshrack_core::config::schema::Secret::Plain
    pub fn build_body(&self) -> CredentialBody {
        use sshrack_core::config::schema::Secret;
        let trimmed_user = self.user.trim().to_string();
        match self.secret_kind {
            SecretChoice::Password => {
                let pw = self.password.as_str();
                if pw.is_empty() {
                    CredentialBody::new(trimmed_user)
                } else {
                    CredentialBody::new(trimmed_user).with_password(pw)
                }
            }
            SecretChoice::IdentityKey => {
                let mut body = CredentialBody::new(trimmed_user);
                match self.source {
                    SourceChoice::Path => {
                        let key = self.identity.trim();
                        if !key.is_empty() {
                            body = body.with_key(key);
                        } else if let Some(KeySource::Inline(ik)) = self.orig_key.clone() {
                            // Field blank AND original was inline: preserve the
                            // inline material verbatim.
                            body.key = Some(KeySource::Inline(ik));
                        }
                    }
                    SourceChoice::Inline => {
                        let private = self.inline_private.clone();
                        let cert = self.inline_cert.clone();
                        if !private.trim().is_empty() {
                            let cert_sec = (!cert.trim().is_empty()).then_some(Secret::Plain(cert));
                            body = body.with_inline_key(Secret::Plain(private), cert_sec);
                        } else if let Some(KeySource::Inline(ik)) = self.orig_key.clone() {
                            // Private blank on edit: preserve the original
                            // inline material verbatim (do not destroy the only
                            // secret).
                            body.key = Some(KeySource::Inline(ik));
                        }
                    }
                }
                body
            }
            SecretChoice::None => CredentialBody::new(trimmed_user),
        }
    }

    /// Render the field rows + error/hint lines into `body` (the rect a
    /// [`crate::tui::dialog::draw_dialog`] hands the form), then — when the
    /// [`KeyPaste`] popup is open — paint it over the form. No outer border —
    /// the dialog already drew the chrome.
    ///
    /// The body is split into three vertical segments: `list_area` holds the
    /// single-line field rows (Length = visible row count), and `error_area`
    /// / `hint_area` are the fixed 1-row tail. The inline-key rows
    /// (`InlinePrivate` / `InlineCert`) are NOT edited in-place — `Enter`
    /// opens the [`KeyPaste`] popup, which is painted last so it sits on top
    /// of the form (modal). [`crate::tui::fit::focus_window`] windows only the
    /// list, so it never scrolls the error/hint rows out of view.
    /// [`Frame::set_cursor_position`] is NOT called for the inline-key rows —
    /// [`cursor_target`](Self::cursor_target) returns `None` for them, and the
    /// popup owns its own cursor while open.
    pub fn draw_in_dialog(&self, frame: &mut Frame, body: ratatui::layout::Rect) {
        let reachable = self.reachable_fields();
        let total = reachable.len();
        // The fields area is `body.height` minus the error(1) + hint(1) rows.
        // When the terminal is too short to fit every field, `focus_window`
        // picks the viewport that keeps the focused one visible.
        let fields_h = body.height.saturating_sub(2) as usize;
        let win = crate::tui::fit::focus_window(total, self.focus_idx(), fields_h);
        let rows: Vec<Line> = reachable[win.clone()]
            .iter()
            .map(|f| self.render_row(*f, body.width))
            .collect();

        // 3-split: the single-line field list, then the 1-row error and hint
        // lines pinned to the body's bottom. `list_area` is `Length` of the
        // rendered row count so it tracks the focus-following viewport exactly.
        let [list_area, error_area, hint_area] = Layout::vertical([
            Constraint::Length(rows.len() as u16),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(body);

        frame.render_widget(Paragraph::new(rows), list_area);

        let error_line = if let Some(msg) = &self.core_error {
            Line::from(vec![
                Span::styled("  ! ", Style::new().fg(theme::DANGER).bold()),
                Span::styled(msg.clone(), Style::new().fg(theme::DANGER)),
            ])
        } else {
            match self.error {
                Some(e) => Line::from(vec![
                    Span::styled("  ! ", Style::new().fg(theme::DANGER).bold()),
                    Span::styled(e.message(), Style::new().fg(theme::DANGER)),
                ]),
                None => Line::raw(""),
            }
        };
        frame.render_widget(error_line, error_area);

        let hint = if self.focus == CredField::SecretKind {
            "  <- -> cycle kind"
        } else if self.focus == CredField::Source {
            "  <- -> cycle source"
        } else if matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert) {
            "  Enter edit multiline"
        } else if self.focus == CredField::Identity {
            "  Enter browse files"
        } else {
            "  up/down next field"
        };
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);

        // Place the real terminal cursor on the focused text field (no drawn
        // glyph — see HostForm::draw_in_dialog). SecretKind / Source are
        // choosers; the inline-key rows return `None` (the KeyPaste popup owns
        // its own cursor while open) — so the guard skips them and we never
        // double-set the cursor over the popup. The row index is translated
        // into the viewport so the cursor never points below the list area
        // when the list scrolls.
        if let Some((row, offset)) = self.cursor_target() {
            if win.start <= row && row < win.end {
                let in_win_row = row - win.start;
                let max_x = list_area.x + list_area.width.saturating_sub(1);
                let x = (list_area.x + CRED_VALUE_COL + offset as u16).min(max_x);
                let y = list_area.y + in_win_row as u16;
                frame.set_cursor_position((x, y));
            }
        }

        // If the inline-key paste popup is open, paint it over the wizard.
        // Drawn last so it sits on top, and after the wizard's own cursor
        // placement so the popup's cursor wins. Mirrors HostForm's
        // cred_picker overlay.
        if let Some(paste) = &self.key_paste {
            paste.draw_overlay(frame);
        }

        // If the file picker is open, paint it over the wizard (last, so it
        // sits on top of the form and the paste popup; only one is open at a
        // time — the picker opens from the Identity row, the paste popup from
        // the Inline rows). Mirrors HostForm's file_picker overlay.
        if let Some(picker) = &self.file_picker {
            picker.draw_overlay(frame);
        }
    }

    /// Char count of the currently focused text field. Returns 0 for the
    /// SecretKind and Source chooser rows (no in-field cursor) and for the
    /// inline-key rows (the [`KeyPaste`] popup owns its own cursor while open,
    /// so this form cursor is irrelevant for them).
    fn focused_text_len(&self) -> usize {
        match self.focus {
            CredField::Name => self.name.chars().count(),
            CredField::User => self.user.chars().count(),
            CredField::Password => self.password.chars().count(),
            // Identity is a trigger row (Enter opens the FilePicker overlay);
            // no in-field cursor. SecretKind/Source are choosers;
            // InlinePrivate/InlineCert edit via the KeyPaste popup.
            CredField::Identity
            | CredField::SecretKind
            | CredField::Source
            | CredField::InlinePrivate
            | CredField::InlineCert => 0,
        }
    }

    /// The `(row, value_offset)` where the terminal cursor should sit for the
    /// focused field, or `None` for the SecretKind / Source choosers and the
    /// inline-key rows. `row` is the index into the reachable rendered rows;
    /// `offset` is the stored char-index cursor, clamped to the field's current
    /// length. Pure; consumed by [`CredForm::draw_in_dialog`] to call
    /// `Frame::set_cursor_position`. The inline-key rows return `None` because
    /// the [`KeyPaste`] popup positions its own cursor internally while open;
    /// the Source row is a chooser like SecretKind.
    fn cursor_target(&self) -> Option<(usize, usize)> {
        let row = self.focus_idx();
        let offset = match self.focus {
            CredField::Name => self.cursor.min(self.name.chars().count()),
            CredField::User => self.cursor.min(self.user.chars().count()),
            CredField::Password => self.cursor.min(self.password.chars().count()),
            // Identity is a trigger row (Enter opens the FilePicker overlay, no
            // in-field cursor — same shape as the host's Credential row);
            // SecretKind/Source are choosers; InlinePrivate/InlineCert's cursor
            // lives in the KeyPaste popup.
            CredField::Identity
            | CredField::SecretKind
            | CredField::Source
            | CredField::InlinePrivate
            | CredField::InlineCert => return None,
        };
        Some((row, offset))
    }

    /// Block title: distinguishes add vs edit mode. Public so the App's overlay
    /// renderer can pass it to [`crate::tui::dialog::draw_dialog`].
    pub fn title(&self) -> String {
        if self.editing {
            " edit credential ".into()
        } else {
            " add credential ".into()
        }
    }

    /// Body row count the dialog sizes to. The count is the **maximum**
    /// reachable field count across every (secret, source) state (so toggling
    /// the Secret or Source chooser changes which rows are filled but never
    /// collapses the dialog box), plus one error row and one hint row. It is
    /// NOT focus-aware: the inline-key rows edit in the [`KeyPaste`] popup (a
    /// modal overlay), so the body never expands an editor block — the dialog
    /// stays a stable height while the form is open. Consumed by the App
    /// overlay layer via [`crate::tui::dialog::draw_dialog`].
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

    /// Render one labeled field row, with the focus highlight + placeholder.
    /// `row_width` is the available cells for the whole row (the dialog body
    /// width); the value column starts at [`CRED_VALUE_COL`] and runs to the
    /// right edge, so an over-wide value/placeholder is passed through
    /// [`truncate_cells`] and ends in `…` instead of running past the border.
    /// Truncation is display-only — the cursor offset in [`cursor_target`]
    /// still uses the stored value's char count.
    fn render_row(&self, field: CredField, row_width: u16) -> Line<'static> {
        let label = field.label();
        let focused = self.focus == field;
        let cursor = if focused { "▶ " } else { "  " };
        let label_span = Span::styled(
            format!(
                "{cursor}{label:>WIDTH$}: ",
                WIDTH = CRED_LABEL_WIDTH as usize
            ),
            if focused {
                theme::accent().add_modifier(Modifier::BOLD)
            } else {
                Style::new().dim()
            },
        );

        let (value_str, placeholder) = self.row_value_and_placeholder(field);
        // Truncate the displayed text (value, else placeholder) to the cells
        // right of the label so it never overflows the dialog border.
        let avail = row_width.saturating_sub(CRED_VALUE_COL) as usize;
        let trunc_value = truncate_cells(&value_str, avail);
        let trunc_ph = placeholder.map(|p| truncate_cells(p, avail));

        let mut spans = vec![label_span];
        spans.extend(value_spans(&trunc_value, trunc_ph.as_deref()));
        Line::from(spans).alignment(Alignment::Left)
    }

    fn row_value_and_placeholder(&self, field: CredField) -> (String, Option<&'static str>) {
        match field {
            CredField::Name => (
                self.name.clone(),
                Some("e.g. ops-prod (no : @ or whitespace)"),
            ),
            CredField::User => (self.user.clone(), Some("e.g. deploy")),
            CredField::Identity => {
                // Trigger row: shows the selected path (if any) or a browse hint.
                // The path is filled by the file picker, never typed.
                if self.identity.is_empty() {
                    (String::new(), Some("Enter to browse for a private key"))
                } else {
                    (self.identity.clone(), Some("Enter to re-browse"))
                }
            }
            CredField::SecretKind => {
                let v = bracketed(self.secret_kind.label());
                let ph = match self.secret_kind {
                    SecretChoice::None => Some("<- -> cycle: Password / IdentityKey / None"),
                    SecretChoice::Password => Some("type the password below"),
                    SecretChoice::IdentityKey => Some("Path or Inline (Source row below)"),
                };
                (v, ph)
            }
            CredField::Source => {
                // Chooser row: bracketed like SecretKind. The placeholder hints
                // the cycle direction.
                let v = bracketed(self.source.label());
                let ph = Some("<- -> cycle: Path / Inline");
                (v, ph)
            }
            CredField::InlinePrivate => {
                // One-line summary of the buffer (never echoes key text):
                // blank → placeholder, non-blank → "N line(s)" count. The
                // full editor opens as a popup on Enter (see `on_key`).
                if self.inline_private.trim().is_empty() {
                    (String::new(), Some("paste private key (Enter to edit)"))
                } else {
                    (
                        format!(
                            "{} line(s) of private key",
                            self.inline_private.lines().count()
                        ),
                        None,
                    )
                }
            }
            CredField::InlineCert => {
                if self.inline_cert.trim().is_empty() {
                    (String::new(), Some("optional certificate (Enter to edit)"))
                } else {
                    (
                        format!(
                            "{} line(s) of certificate",
                            self.inline_cert.lines().count()
                        ),
                        None,
                    )
                }
            }
            CredField::Password => {
                // Masked: one bullet per char. Never echo the plaintext.
                let masked: String =
                    std::iter::repeat_n('•', self.password.chars().count()).collect();
                let ph = if self.editing {
                    Some("leave blank to keep existing")
                } else {
                    Some("type the password")
                };
                (masked, ph)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Pure-logic tests for the credential wizard: `validate_cred` (TDD core),
    //! the form's `on_key` state machine, secret-kind cycling, `build_body`,
    //! the `new_edit` prefill, and a render smoke through the real Dialog
    //! chrome. No terminal and no filesystem are touched.
    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use sshrack_core::config::schema::{Credential, CredentialBody, KeySource, SecretKind};

    fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
    }

    fn blank_cred_form() -> CredForm {
        CredForm::new_add()
    }

    fn form_with(name: &str, user: &str) -> CredForm {
        let mut f = blank_cred_form();
        f.name = name.into();
        f.user = user.into();
        // Keep the cursor consistent with the pre-filled Name (mirrors what
        // move_focus / construction do), so backspace / cursor_target behave as
        // if the user had just typed the value.
        f.cursor = f.focused_text_len();
        f
    }

    fn complete_cred_form() -> CredForm {
        form_with("ops", "deploy")
    }

    // ---- cursor_target ----

    #[test]
    fn cred_cursor_target_name_empty_is_row_zero_offset_zero() {
        let mut f = CredForm::new_add();
        f.focus = CredField::Name;
        assert_eq!(f.cursor_target(), Some((0, 0)));
    }

    #[test]
    fn cred_cursor_target_password_offsets_by_masked_len() {
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::Password;
        f.focus = CredField::Password;
        f.password = Zeroizing::new(String::from("secret1"));
        // Sync the cursor to the end of the pre-filled Password field, as if
        // the user had just typed it — cursor_target then reports that position.
        f.cursor = f.focused_text_len();
        // Password is the 4th reachable field (index 3) when secret_kind == Password.
        assert_eq!(f.cursor_target(), Some((3, 7)));
    }

    #[test]
    fn cred_cursor_target_secret_kind_is_none_chooser() {
        let mut f = CredForm::new_add();
        f.focus = CredField::SecretKind;
        assert_eq!(f.cursor_target(), None);
    }

    // ---- validate_cred (TDD: RED → GREEN) ----

    #[test]
    fn rejects_empty_name_and_user() {
        assert!(matches!(
            validate_cred(&blank_cred_form()),
            Err(CredSaveError::MissingName)
        ));
    }

    #[test]
    fn rejects_name_only_missing_user() {
        let f = form_with("ops", "");
        assert!(matches!(validate_cred(&f), Err(CredSaveError::MissingUser)));
    }

    #[test]
    fn rejects_whitespace_only_name_as_missing() {
        let mut f = complete_cred_form();
        f.name = "   ".into();
        assert!(matches!(validate_cred(&f), Err(CredSaveError::MissingName)));
    }

    #[test]
    fn rejects_forbidden_char_in_name() {
        for bad in ["a:b", "a@b", "a b", "a\tb"] {
            let mut f = complete_cred_form();
            f.name = bad.into();
            assert!(
                matches!(validate_cred(&f), Err(CredSaveError::InvalidName)),
                "expected InvalidName for {bad:?}"
            );
        }
    }

    #[test]
    fn accepts_complete_form() {
        assert!(validate_cred(&complete_cred_form()).is_ok());
    }

    #[test]
    fn accepts_complete_form_with_password_choice() {
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::Password;
        *f.password = "hunter2".into();
        assert!(validate_cred(&f).is_ok());
    }

    #[test]
    fn accepts_complete_form_with_identity_choice() {
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::IdentityKey;
        f.identity = "/home/me/.ssh/id_ed25519".into();
        assert!(validate_cred(&f).is_ok());
    }

    #[test]
    fn cred_save_error_field_maps_to_the_right_field() {
        assert_eq!(CredSaveError::MissingName.field(), CredField::Name);
        assert_eq!(CredSaveError::InvalidName.field(), CredField::Name);
        assert_eq!(CredSaveError::MissingUser.field(), CredField::User);
    }

    // ---- on_key: field editing + navigation ----

    #[test]
    fn typing_appends_to_focused_cred_field() {
        let mut f = blank_cred_form();
        assert_eq!(f.focus, CredField::Name);
        for ch in "ops".chars() {
            f.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(f.name, "ops");
    }

    #[test]
    fn typing_password_masks_state_under_password_choice() {
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::Password;
        // Tab to the Password row (Name→User→SecretKind→Password).
        for _ in 0..3 {
            f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        }
        assert_eq!(f.focus, CredField::Password);
        for ch in "hunter2".chars() {
            f.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(f.password.as_str(), "hunter2");
    }

    #[test]
    fn password_row_is_unreachable_under_non_password_choice() {
        // IdentityKey choice: Tabbing skips the Password row. Under IdentityKey
        // the reachable cycle is Name→User→SecretKind→Source→Identity→(wrap),
        // so Password is never visited. We tab through a full cycle (5 reachable
        // fields under the Path source default) and assert Password never
        // appears, then we land back on Name.
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::IdentityKey;
        for _ in 0..5 {
            assert_ne!(
                f.focus,
                CredField::Password,
                "Password row must be skipped under IdentityKey"
            );
            f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        }
        assert_eq!(f.focus, CredField::Name, "five tabs wrap back to Name");
    }

    #[test]
    fn backspace_pops_focused_cred_field() {
        let mut f = form_with("op", "");
        f.on_key(press(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(f.name, "o");
    }

    #[test]
    fn tab_moves_cred_focus_forward() {
        let mut f = blank_cred_form();
        assert_eq!(f.focus, CredField::Name);
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, CredField::User);
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        // Order is Name→User→SecretKind→(Identity/Password); under None both
        // slot rows are hidden, so Tab lands on SecretKind.
        assert_eq!(f.focus, CredField::SecretKind);
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        // SecretKind is None → no slot row reachable → wrap to Name.
        assert_eq!(f.focus, CredField::Name);
    }

    #[test]
    fn shift_tab_moves_cred_focus_backward() {
        let mut f = blank_cred_form();
        f.focus = CredField::SecretKind;
        f.on_key(press(KeyCode::BackTab, KeyModifiers::SHIFT));
        // Order is Name→User→SecretKind; BackTab from SecretKind lands on User.
        assert_eq!(f.focus, CredField::User);
    }

    #[test]
    fn up_down_move_cred_focus_like_tab() {
        let mut f = blank_cred_form();
        f.on_key(press(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(f.focus, CredField::User);
        f.on_key(press(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(f.focus, CredField::Name);
    }

    #[test]
    fn enter_advances_until_last_field_then_attempts_save() {
        let mut f = complete_cred_form();
        // Under None choice the last reachable field is SecretKind.
        let o = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(o, Outcome::Continue));
        assert_eq!(f.focus, CredField::User);
        // Jump to SecretKind (last reachable under None) and Enter → save.
        f.focus = CredField::SecretKind;
        let o = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(o, Outcome::SaveCred));
    }

    #[test]
    fn enter_on_password_row_attempts_save_when_last() {
        // Under Password choice, the Password row is last; Enter saves.
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::Password;
        f.focus = CredField::Password;
        let o = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(o, Outcome::SaveCred));
    }

    #[test]
    fn ctrl_s_saves_cred_from_any_field() {
        let mut f = complete_cred_form();
        f.focus = CredField::User;
        let o = f.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(matches!(o, Outcome::SaveCred));
    }

    #[test]
    fn save_with_invalid_cred_form_sets_error_and_focuses_bad_field() {
        let mut f = blank_cred_form();
        let o = f.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(matches!(o, Outcome::Continue));
        assert_eq!(f.error, Some(CredSaveError::MissingName));
        assert_eq!(f.focus, CredField::Name);
    }

    #[test]
    fn editing_a_cred_field_clears_its_error() {
        let mut f = blank_cred_form();
        f.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert_eq!(f.error, Some(CredSaveError::MissingName));
        f.on_key(press(KeyCode::Char('o'), KeyModifiers::NONE));
        assert_eq!(f.error, None);
    }

    #[test]
    fn esc_and_ctrl_c_cancel_cred_form() {
        let mut f = complete_cred_form();
        assert!(matches!(
            f.on_key(press(KeyCode::Esc, KeyModifiers::NONE)),
            Outcome::Cancel
        ));
        assert!(matches!(
            f.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Outcome::Cancel
        ));
    }

    #[test]
    fn cred_key_release_is_ignored() {
        let mut f = complete_cred_form();
        let release =
            KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        let o = f.on_key(release);
        assert!(matches!(o, Outcome::Continue));
    }

    // ---- secret chooser cycling ----

    #[test]
    fn right_arrow_on_secret_cycles_none_to_password_to_identitykey() {
        let mut f = complete_cred_form();
        f.focus = CredField::SecretKind;
        assert_eq!(f.secret_kind, SecretChoice::None);
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.secret_kind, SecretChoice::Password);
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.secret_kind, SecretChoice::None);
    }

    #[test]
    fn left_arrow_cycles_secret_backward() {
        let mut f = complete_cred_form();
        f.focus = CredField::SecretKind;
        f.on_key(press(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
    }

    #[test]
    fn left_right_off_secret_row_are_ignored_for_cycling() {
        let mut f = complete_cred_form();
        f.focus = CredField::Name;
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.secret_kind, SecretChoice::None);
    }

    // ---- build_body ----

    #[test]
    fn build_body_none_is_user_only() {
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::None;
        let b = f.build_body();
        assert_eq!(b.user, "deploy");
        assert_eq!(b.secret_kind(), SecretKind::Default);
    }

    #[test]
    fn build_body_identity_attaches_key() {
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::IdentityKey;
        f.identity = "/home/me/.ssh/id_ed25519".into();
        let b = f.build_body();
        assert_eq!(b.secret_kind(), SecretKind::Key);
        assert_eq!(
            b.key.as_ref().and_then(KeySource::as_path),
            Some(std::path::Path::new("/home/me/.ssh/id_ed25519"))
        );
    }

    #[test]
    fn build_body_password_carries_plaintext() {
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::Password;
        *f.password = "hunter2".into();
        let b = f.build_body();
        assert_eq!(b.secret_kind(), SecretKind::Password);
        // The body carries plaintext; sealing (per store mode) is the loop's job.
        assert_eq!(b.password_plain(), Some("hunter2"));
    }

    #[test]
    fn build_body_password_empty_leaves_no_secret() {
        // Empty password under Password choice = no password set (edit mode
        // keeps the existing secret; add mode makes a user-only credential).
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::Password;
        let b = f.build_body();
        assert_eq!(b.secret_kind(), SecretKind::Default);
    }

    // ---- inline-key preservation on edit (data safety) ----
    //
    // The inline textareas are NEVER prefilled with the existing key text on
    // edit-entry (security). Editing a credential whose key is inline material
    // must therefore preserve the original KeySource::Inline verbatim when the
    // private field is left blank — silently dropping it would destroy the
    // credential's only secret. A path original left blank is treated as "user
    // cleared the field".

    #[test]
    fn build_body_preserves_inline_key_when_identity_blank() {
        use sshrack_core::config::schema::{InlineKey, Secret};
        let mut f = complete_cred_form();
        f.editing = true;
        f.secret_kind = SecretChoice::IdentityKey;
        // The identity field renders blank for an inline original (no path to
        // show). orig_key carries the inline material through.
        f.identity = String::new();
        f.orig_key = Some(KeySource::Inline(InlineKey {
            private_key: Some(Secret::Plain("PRIVATE-TEXT".into())),
            certificate: None,
            keyring: false,
        }));
        let b = f.build_body();
        // The inline KeySource survives the build verbatim — never dropped.
        match &b.key {
            Some(KeySource::Inline(ik)) => {
                assert_eq!(
                    ik.private_key.as_ref().and_then(Secret::as_plain),
                    Some("PRIVATE-TEXT"),
                    "inline private key text must be preserved on edit"
                );
            }
            other => panic!("expected Inline preservation, got {other:?}"),
        }
    }

    #[test]
    fn build_body_path_key_blank_drops_the_key() {
        // A path-key original edited to blank is "user cleared the field" —
        // the path is gone, and no inline fallback is synthesised.
        let mut f = complete_cred_form();
        f.editing = true;
        f.secret_kind = SecretChoice::IdentityKey;
        f.identity = String::new();
        f.orig_key = Some(KeySource::Path("/orig/id".into()));
        let b = f.build_body();
        assert!(b.key.is_none(), "blank path field must drop the key");
    }

    // ---- Task 3: build_body routes inline source to with_inline_key (RED -> GREEN) ----
    //
    // Under SourceChoice::Inline the private textarea's joined lines become a
    // KeySource::Inline body via with_inline_key; the cert textarea is attached
    // only when non-empty. A blank private field on edit must preserve the
    // original inline material verbatim (data safety — never destroy the only
    // secret). The Path branch keeps its pre-Plan-2 behavior unchanged.

    #[test]
    fn build_body_inline_source_attaches_inline_key() {
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.inline_private = "PRIVATE-KEY-TEXT".to_string();
        f.inline_cert = "CERT-TEXT".to_string();
        let b = f.build_body();
        assert_eq!(b.secret_kind(), SecretKind::Key);
        match b.key {
            Some(KeySource::Inline(ik)) => {
                assert_eq!(ik.private_key.unwrap().as_plain(), Some("PRIVATE-KEY-TEXT"));
                assert_eq!(ik.certificate.unwrap().as_plain(), Some("CERT-TEXT"));
            }
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    #[test]
    fn build_body_inline_source_multiline_joins_with_newline() {
        // A pasted key has many lines; they must round-trip as one string.
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.inline_private = "line1\nline2\nline3".to_string();
        let b = f.build_body();
        let plain = match b.key {
            Some(KeySource::Inline(ik)) => ik.private_key.unwrap().as_plain().unwrap().to_string(),
            _ => panic!("expected Inline"),
        };
        assert_eq!(plain, "line1\nline2\nline3");
    }

    #[test]
    fn build_body_inline_blank_on_edit_preserves_original_inline_key() {
        use sshrack_core::config::schema::{InlineKey, KeySource, Secret};
        let mut f = complete_cred_form();
        f.editing = true;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.inline_private = String::new(); // empty — user did not re-paste
        f.orig_key = Some(KeySource::Inline(InlineKey {
            private_key: Some(Secret::Plain("ORIGINAL".into())),
            certificate: None,
            keyring: false,
        }));
        let b = f.build_body();
        match b.key {
            Some(KeySource::Inline(ik)) => {
                assert_eq!(ik.private_key.unwrap().as_plain(), Some("ORIGINAL"))
            }
            _ => panic!("original inline key must be preserved when private stays blank"),
        }
    }

    #[test]
    fn build_body_path_source_unchanged_behavior() {
        let mut f = complete_cred_form();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Path;
        f.identity = "/k/id".into();
        assert_eq!(
            f.build_body().key.as_ref().and_then(KeySource::as_path),
            Some(std::path::Path::new("/k/id"))
        );
    }

    // ---- new_edit prefill ----

    #[test]
    fn new_edit_prefills_from_default_credential() {
        let cred = Credential {
            id: Ulid::new(),
            name: "ops".into(),
            body: CredentialBody::new("deploy"),
        };
        let f = CredForm::new_edit(&cred);
        assert!(f.editing);
        assert_eq!(f.orig_id, Some(cred.id));
        assert_eq!(f.name, "ops");
        assert_eq!(f.user, "deploy");
        assert_eq!(f.secret_kind, SecretChoice::None);
    }

    #[test]
    fn new_edit_prefills_from_key_credential() {
        let cred = Credential {
            id: Ulid::new(),
            name: "ops".into(),
            body: CredentialBody::new("deploy").with_key("/k/id"),
        };
        let f = CredForm::new_edit(&cred);
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
        assert_eq!(f.identity, "/k/id");
    }

    #[test]
    fn new_edit_password_credential_does_not_echo_plaintext() {
        // The password is never carried into the form; the user re-types to
        // set a new one. SecretKind maps to Password so the chooser opens
        // on the password row.
        let cred = Credential {
            id: Ulid::new(),
            name: "ops".into(),
            body: CredentialBody::new("deploy").with_password("topsecret"),
        };
        let f = CredForm::new_edit(&cred);
        assert_eq!(f.secret_kind, SecretChoice::Password);
        assert!(
            f.password.is_empty(),
            "existing password must NOT be echoed into the form"
        );
    }

    #[test]
    fn new_edit_keyring_credential_maps_to_password_choice() {
        let cred = Credential {
            id: Ulid::new(),
            name: "ops".into(),
            body: CredentialBody {
                user: "deploy".into(),
                password: None,
                key: None,
                keyring: true,
            },
        };
        let f = CredForm::new_edit(&cred);
        assert_eq!(f.secret_kind, SecretChoice::Password);
        assert!(f.password.is_empty());
    }

    // ---- render smoke ----

    #[test]
    fn cred_draw_in_dialog_renders_without_panic_across_focus_and_secret_states() {
        // Mirrors the host variant: drive every focus field × every secret
        // kind through the real Dialog chrome so the cursor-offset math
        // (body.x + CRED_VALUE_COL + offset, body.y + focus_row) is exercised
        // against a body rect offset from (0,0). Also covers the
        // Password-only focus, a validation error, and a core error row.
        use crate::tui::dialog::draw_dialog;
        use ratatui::{Terminal, backend::TestBackend};
        let mut f = complete_cred_form();
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        for field in [
            CredField::Name,
            CredField::User,
            CredField::Identity,
            CredField::SecretKind,
        ] {
            f.focus = field;
            for kind in [
                SecretChoice::None,
                SecretChoice::Password,
                SecretChoice::IdentityKey,
            ] {
                f.secret_kind = kind;
                *f.password = if kind == SecretChoice::Password {
                    "hunter2".into()
                } else {
                    String::new()
                };
                f.identity = if kind == SecretChoice::IdentityKey {
                    "/k/id".into()
                } else {
                    String::new()
                };
                f.error = None;
                terminal
                    .draw(|fr| {
                        let body = draw_dialog(
                            fr,
                            &f.title(),
                            f.body_rows(),
                            &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                        );
                        f.draw_in_dialog(fr, body);
                    })
                    .unwrap();
            }
        }
        // Also exercise the Password row focus under Password choice.
        f.secret_kind = SecretChoice::Password;
        f.focus = CredField::Password;
        terminal
            .draw(|fr| {
                let body = draw_dialog(
                    fr,
                    &f.title(),
                    f.body_rows(),
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                );
                f.draw_in_dialog(fr, body);
            })
            .unwrap();
        // Exercise the Source chooser + inline textarea rows under
        // IdentityKey, across both Source branches (Path renders Identity;
        // Inline renders InlinePrivate + InlineCert). Drives the new
        // row_value_and_placeholder arms and the Source/textarea hint rows
        // through the real Dialog chrome so any panic surfaces here.
        f.secret_kind = SecretChoice::IdentityKey;
        for source in [SourceChoice::Path, SourceChoice::Inline] {
            f.source = source;
            for field in [
                CredField::Source,
                CredField::InlinePrivate,
                CredField::InlineCert,
            ] {
                f.focus = field;
                terminal
                    .draw(|fr| {
                        let body = draw_dialog(
                            fr,
                            &f.title(),
                            f.body_rows(),
                            &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                        );
                        f.draw_in_dialog(fr, body);
                    })
                    .unwrap();
            }
        }
        // And error / core_error lines.
        f.focus = CredField::Name;
        f.error = Some(CredSaveError::MissingName);
        terminal
            .draw(|fr| {
                let body = draw_dialog(
                    fr,
                    &f.title(),
                    f.body_rows(),
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                );
                f.draw_in_dialog(fr, body);
            })
            .unwrap();
        f.error = None;
        f.set_core_error("store mode not decided".into());
        terminal
            .draw(|fr| {
                let body = draw_dialog(
                    fr,
                    &f.title(),
                    f.body_rows(),
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                );
                f.draw_in_dialog(fr, body);
            })
            .unwrap();
    }

    // ---- small-terminal viewport: focused field stays inside the body rect ----

    #[test]
    fn draw_in_dialog_keeps_focused_cursor_inside_body_when_terminal_short() {
        // Behavior pin mirroring the host variant: with a short terminal the
        // focus-following viewport must scroll the focused field into view.
        // We focus the Password row (the last reachable text field under
        // SecretChoice::Password) and render through a height-11 TestBackend
        // (the dialog's blank-separator + footer + border chrome leaves a
        // 3-row body). Without the viewport the cursor would land at
        // `fields_area.y + 4` (past the body bottom); with it the in-window
        // row index stays inside.
        use crate::tui::dialog::draw_dialog;
        use ratatui::{
            Terminal,
            backend::{Backend, TestBackend},
            layout::Rect,
        };

        let mut form = complete_cred_form();
        form.secret_kind = SecretChoice::Password;
        let last = *form
            .reachable_fields()
            .last()
            .expect("invariant: reachable fields non-empty under Password");
        form.focus = last;

        let mut term = Terminal::new(TestBackend::new(60, 11)).unwrap();
        let mut captured_body = Rect::default();
        term.draw(|f| {
            let body = draw_dialog(
                f,
                &form.title(),
                form.body_rows(),
                &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
            );
            form.draw_in_dialog(f, body);
            captured_body = body;
        })
        .unwrap();

        let cy = term.backend_mut().get_cursor_position().unwrap().y;
        assert!(
            captured_body.y <= cy && cy < captured_body.y + captured_body.height,
            "focused field cursor y={cy} must sit inside body rect y={}..{}",
            captured_body.y,
            captured_body.y + captured_body.height
        );
    }

    // ---- small-terminal viewport: popup-overlay render must not panic ----

    #[test]
    fn draw_in_dialog_renders_popup_overlay_without_panic_on_short_terminal() {
        // Behavior pin for the popup-overlay render path. The body is now a
        // stable 3-split (list/error/hint) regardless of focus, and the
        // multiline editor lives in the modal KeyPaste popup painted on top.
        // On a height-11 terminal the dialog body collapses to ~3 rows, so the
        // `fields_h = body.height.saturating_sub(2)` viewport adjustment must
        // not underflow and the popup's centered_rect must still fit. We cover
        // both inline-key fields with the popup open and closed so both the
        // overlay branch and the plain 3-split branch render without panic.
        use crate::tui::dialog::draw_dialog;
        use ratatui::{Terminal, backend::TestBackend};

        let mut form = complete_cred_form();
        form.secret_kind = SecretChoice::IdentityKey;
        form.source = SourceChoice::Inline;

        for focus in [CredField::InlinePrivate, CredField::InlineCert] {
            form.focus = focus;
            // Popup closed: plain 3-split render on a short terminal.
            form.key_paste = None;
            let mut term = Terminal::new(TestBackend::new(60, 11)).unwrap();
            term.draw(|f| {
                let body = draw_dialog(
                    f,
                    &form.title(),
                    form.body_rows(),
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                );
                form.draw_in_dialog(f, body);
            })
            .unwrap();
            // Popup open: the overlay is painted on top via centered_rect —
            // must not panic even when the terminal is shorter than the popup.
            form.key_paste = Some(KeyPaste::new(match focus {
                CredField::InlinePrivate => PasteKind::Private,
                CredField::InlineCert => PasteKind::Cert,
                _ => unreachable!("focus is one of the two inline rows"),
            }));
            term.draw(|f| {
                let body = draw_dialog(
                    f,
                    &form.title(),
                    form.body_rows(),
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                );
                form.draw_in_dialog(f, body);
            })
            .unwrap();
        }
    }

    // ---- in-field cursor movement (Task 3: RED -> GREEN) ----

    #[test]
    fn left_arrow_moves_cursor_within_a_cred_text_field() {
        let mut form = CredForm::new_add();
        for c in "ops".chars() {
            form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(form.name, "ops");
        assert_eq!(form.cursor, 2);
        assert_eq!(form.cursor_target(), Some((0, 2)));
    }

    #[test]
    fn right_arrow_advances_cursor_within_a_cred_text_field() {
        // Regression pin mirroring the host form: Right must MOVE the cursor
        // forward, not just clamp it. After typing "abc" (cursor at end 3),
        // Left twice lands the cursor at 1; Right then advances to 2.
        let mut form = CredForm::new_add();
        for c in "abc".chars() {
            form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(form.cursor, 1);
        form.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(form.cursor, 2);
        assert_eq!(form.cursor_target(), Some((0, 2)));
    }

    #[test]
    fn typing_inserts_at_cursor_in_cred_form() {
        let mut form = CredForm::new_add();
        for c in "ab".chars() {
            form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        form.on_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        form.on_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE));
        assert_eq!(form.name, "Xab");
    }

    #[test]
    fn backspace_deletes_before_cursor_in_cred_form() {
        let mut form = CredForm::new_add();
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
    fn left_right_still_cycle_kind_on_secretkind_row() {
        let mut form = CredForm::new_add();
        // Tab to SecretKind.
        form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Name -> User
        form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // User -> SecretKind (Identity hidden)
        assert_eq!(form.focus, CredField::SecretKind);
        let before = form.secret_kind;
        form.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_ne!(form.secret_kind, before);
    }

    // ---- three-way secret mutex (Task 4: RED -> GREEN) ----

    #[test]
    fn reachable_under_none_hides_identity_and_password() {
        let mut form = CredForm::new_add();
        form.secret_kind = SecretChoice::None;
        let reachable = form.reachable_fields();
        assert!(!reachable.contains(&CredField::Identity));
        assert!(!reachable.contains(&CredField::Password));
        assert!(reachable.contains(&CredField::SecretKind));
    }

    #[test]
    fn reachable_under_identitykey_shows_identity_not_password() {
        let mut form = CredForm::new_add();
        form.secret_kind = SecretChoice::IdentityKey;
        let reachable = form.reachable_fields();
        assert!(reachable.contains(&CredField::Identity));
        assert!(!reachable.contains(&CredField::Password));
    }

    #[test]
    fn reachable_under_password_shows_password_not_identity() {
        let mut form = CredForm::new_add();
        form.secret_kind = SecretChoice::Password;
        let reachable = form.reachable_fields();
        assert!(reachable.contains(&CredField::Password));
        assert!(!reachable.contains(&CredField::Identity));
    }

    // ---- dialog height stability: body_rows pinned to the worst-case max so
    // the dialog box never resizes when the Secret toggle changes the
    // reachable field count (regression pin) ----

    #[test]
    fn body_rows_is_stable_across_secret_and_source_states() {
        // IdentityKey + Inline exposes the most rows: Name, User, SecretKind,
        // Source, InlinePrivate, InlineCert = 6 fields + error + hint = 8.
        // body_rows() must report this SAME value for every (secret, source)
        // state so the dialog box stays a fixed height while the form is open
        // — toggling Secret or Source changes which rows are filled, not the
        // border size.
        let mut form = CredForm::new_add();
        form.name = "ops".into();
        form.user = "deploy".into();
        let stable = form.body_rows();
        assert_eq!(
            stable, 8,
            "max = IdentityKey+Inline (6 fields) + error + hint"
        );
        for secret in [
            SecretChoice::None,
            SecretChoice::Password,
            SecretChoice::IdentityKey,
        ] {
            for source in [SourceChoice::Path, SourceChoice::Inline] {
                form.secret_kind = secret;
                form.source = source;
                assert_eq!(
                    form.body_rows(),
                    stable,
                    "body_rows must be stable under secret={secret:?} source={source:?}"
                );
            }
        }
    }

    // ---- row_value_and_placeholder: secret-kind value is bracketed (Task 6: RED -> GREEN) ----

    #[test]
    fn secretkind_value_is_bracketed() {
        let mut form = CredForm::new_add();
        form.secret_kind = SecretChoice::IdentityKey;
        let (value, _placeholder) = form.row_value_and_placeholder(CredField::SecretKind);
        assert_eq!(value, "< IdentityKey >");
    }

    // ---- Task 2: Source cycling + inline textarea input (RED -> GREEN) ----

    #[test]
    fn identity_key_shows_source_row_and_path_branch_reaches_identity() {
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Path;
        let r = f.reachable_fields();
        assert!(r.contains(&CredField::Source));
        assert!(r.contains(&CredField::Identity));
        assert!(!r.contains(&CredField::InlinePrivate));
    }

    #[test]
    fn inline_source_hides_identity_and_reaches_inline_rows() {
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        let r = f.reachable_fields();
        assert!(r.contains(&CredField::InlinePrivate));
        assert!(r.contains(&CredField::InlineCert));
        assert!(!r.contains(&CredField::Identity));
    }

    #[test]
    fn right_arrow_on_source_cycles_path_to_inline() {
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.focus = CredField::Source;
        f.source = SourceChoice::Path;
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.source, SourceChoice::Inline);
    }

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
        assert!(
            f.inline_cert.is_empty(),
            "discard leaves the field unchanged"
        );
    }

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

    #[test]
    fn enter_inside_popup_inserts_newline_instead_of_closing() {
        // Enter inside the popup must insert a newline (multiline editing),
        // not close the popup or advance focus. After typing "line1", Enter,
        // "line2", Esc closes and the buffer has two lines.
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = CredField::InlinePrivate;
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(f.key_paste.is_some());
        for c in "line1".chars() {
            let _ = f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
        }
        // Enter inside the popup → still open (Pending).
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            f.key_paste.is_some(),
            "Enter inside popup must not close it"
        );
        for c in "line2".chars() {
            let _ = f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let _ = f.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(f.inline_private, "line1\nline2");
    }

    #[test]
    fn backspace_inside_popup_deletes_within_the_buffer() {
        // Backspace inside the popup deletes inside the popup's buffer; it does
        // NOT call the form's char-based `backspace_at` helper. Type "abc",
        // backspace once, Esc → "ab".
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = CredField::InlineCert;
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        for c in "abc".chars() {
            let _ = f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let _ = f.on_key(press(KeyCode::Backspace, KeyModifiers::NONE));
        let _ = f.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(f.inline_cert, "ab");
    }

    #[test]
    fn new_edit_inline_original_defaults_source_to_inline_with_empty_buffer() {
        // Editing an inline-key owner: Source defaults to Inline, but the key
        // text is NEVER echoed into the buffer (security). build_body must
        // preserve the original on save when the private field stays blank.
        use sshrack_core::config::schema::{KeySource, Secret};
        let cred = Credential {
            id: Ulid::new(),
            name: "ops".into(),
            body: CredentialBody::new("u")
                .with_inline_key(Secret::Plain("SECRET-TEXT".into()), None),
        };
        let f = CredForm::new_edit(&cred);
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
        assert_eq!(f.source, SourceChoice::Inline);
        assert!(f.inline_private.is_empty(), "key text must NOT echo");
        assert!(matches!(f.orig_key, Some(KeySource::Inline(_))));
    }

    #[test]
    fn tab_and_arrows_navigate_between_inline_rows_and_out() {
        // Tab / Up / Down navigate between the inline-key rows and out to the
        // Source row (the popup is closed, so these are form-level navigations).
        // Pins the navigation matrix under IdentityKey + Inline: the reachable
        // cycle is Name→User→SecretKind→Source→InlinePrivate→InlineCert→wrap.
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = CredField::Source;
        // Tab from Source → InlinePrivate.
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, CredField::InlinePrivate);
        // Tab again → InlineCert.
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, CredField::InlineCert);
        // Up from InlineCert → InlinePrivate.
        f.on_key(press(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(f.focus, CredField::InlinePrivate);
        // BackTab from InlinePrivate → Source.
        f.on_key(press(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(f.focus, CredField::Source);
    }

    #[test]
    fn enter_on_inline_private_under_none_secret_does_not_open_popup() {
        // Reachability guard on the Enter trigger: InlinePrivate is unreachable
        // under SecretChoice::None (the inline editor is IdentityKey+Inline-
        // only by contract). Even when focus is forced onto the row, Enter
        // must NOT open the paste popup — symmetric to the host wizard's
        // Reference-branch isolation guard. Pins the cred wizard's trigger
        // guard against a regression that would let a forced focus open the
        // popup from an unreachable state.
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::None; // InlinePrivate unreachable
        f.focus = CredField::InlinePrivate; // forced onto an unreachable row
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            f.key_paste.is_none(),
            "Enter must not open the popup when the row is unreachable"
        );
    }

    #[test]
    fn new_edit_path_original_defaults_source_to_path_with_identity_prefilled() {
        // Counterpart to the inline-original test: a Path original defaults
        // Source to Path with the identity field prefilled (the path IS shown,
        // unlike inline text).
        let cred = Credential {
            id: Ulid::new(),
            name: "ops".into(),
            body: CredentialBody::new("u").with_key("/home/me/.ssh/id_ed25519"),
        };
        let f = CredForm::new_edit(&cred);
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
        assert_eq!(f.source, SourceChoice::Path);
        assert_eq!(f.identity, "/home/me/.ssh/id_ed25519");
        assert!(matches!(f.orig_key, Some(KeySource::Path(_))));
    }

    #[test]
    fn debug_impl_does_not_leak_inline_buffer_contents() {
        // The hand-written Debug must show only the line COUNT, never the
        // pasted key text. `format!("{:?}", form)` going to logs/errors must
        // not leak "PRIVATE-SECRET".
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.inline_private = "PRIVATE-SECRET-TEXT".to_string();
        let dbg = format!("{f:?}");
        assert!(
            !dbg.contains("PRIVATE-SECRET-TEXT"),
            "Debug must not leak inline buffer contents: {dbg}"
        );
        assert!(
            dbg.contains("inline_private_lines"),
            "Debug must surface the line count field: {dbg}"
        );
        assert!(
            dbg.contains("inline_private_lines: 1"),
            "expected 1 line: {dbg}"
        );
    }

    // ---- popup overlay render: draw_in_dialog must not panic for any state ----
    //
    // The inline-key rows are edited in the KeyPaste popup (a modal overlay);
    // the form body itself is a stable 3-split (list/error/hint) regardless of
    // focus. The render must not panic for any (secret, source, focus)
    // combination, and body_rows must be focus-independent.

    #[test]
    fn draw_in_dialog_renders_without_panic_across_source_and_focus_states() {
        use crate::tui::dialog::draw_dialog;
        use ratatui::{Terminal, backend::TestBackend};
        let mut f = complete_cred_form();
        let mut term = Terminal::new(TestBackend::new(100, 40)).unwrap();
        for secret in [
            SecretChoice::None,
            SecretChoice::Password,
            SecretChoice::IdentityKey,
        ] {
            for source in [SourceChoice::Path, SourceChoice::Inline] {
                f.secret_kind = secret;
                f.source = source;
                for focus in [
                    CredField::Name,
                    CredField::SecretKind,
                    CredField::Source,
                    CredField::Identity,
                    CredField::InlinePrivate,
                    CredField::InlineCert,
                ] {
                    f.focus = focus;
                    term.draw(|fr| {
                        let body = draw_dialog(
                            fr,
                            &f.title(),
                            f.body_rows(),
                            &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                        );
                        f.draw_in_dialog(fr, body);
                    })
                    .unwrap();
                }
            }
        }
    }

    #[test]
    fn body_rows_is_independent_of_inline_field_focus() {
        // body_rows no longer depends on focus (the multiline editor lives in
        // the modal KeyPaste popup, not as an in-body block); it is a stable
        // worst-case across every (secret, source) combo. Pins that contract.
        for secret in [
            SecretChoice::None,
            SecretChoice::Password,
            SecretChoice::IdentityKey,
        ] {
            for source in [SourceChoice::Path, SourceChoice::Inline] {
                let mut f = CredForm::new_add();
                f.secret_kind = secret;
                f.source = source;
                f.focus = CredField::Name;
                let baseline = f.body_rows();
                f.focus = CredField::InlinePrivate;
                assert_eq!(
                    f.body_rows(),
                    baseline,
                    "focus-independent for {secret:?}/{source:?}"
                );
            }
        }
    }

    // ---- Task 7: Identity row becomes a trigger row -> opens FilePicker (RED -> GREEN) ----
    //
    // Mirrors the host wizard's Task 6: the Identity path-slot (IdentityKey +
    // Path) is no longer typed in place. It is a trigger row like InlinePrivate
    // / InlineCert: Enter opens the modal FilePicker overlay, which returns an
    // absolute path the form writes back into `identity`. Printable chars /
    // Backspace are no-ops on the row; the cursor never lands on it
    // (cursor_target returns None), so only the picker can change `identity`.

    #[test]
    fn enter_on_identity_opens_file_picker() {
        // IdentityKey + Path -> Identity is reachable.
        let mut form = CredForm::new_add();
        form.secret_kind = SecretChoice::IdentityKey;
        form.source = SourceChoice::Path;
        form.focus = CredField::Identity;
        assert!(form.file_picker.is_none());
        let _ = form.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            form.file_picker.is_some(),
            "Enter on Identity opens the picker"
        );
    }

    #[test]
    fn typing_on_identity_is_a_noop_it_is_a_trigger_row() {
        let mut form = CredForm::new_add();
        form.secret_kind = SecretChoice::IdentityKey;
        form.source = SourceChoice::Path;
        form.focus = CredField::Identity;
        for c in "abc".chars() {
            let _ = form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert!(
            form.identity.is_empty(),
            "Identity must not accept in-place typing"
        );
    }

    #[test]
    fn enter_on_identity_under_non_identitykey_does_not_open_picker() {
        // Identity is unreachable under SecretChoice::None; Enter must not
        // open the picker.
        let mut form = CredForm::new_add();
        form.secret_kind = SecretChoice::None;
        form.focus = CredField::Identity; // forced (unreachable) focus
        let _ = form.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(form.file_picker.is_none());
    }

    #[test]
    fn draw_in_dialog_with_open_picker_renders_without_panic() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut form = CredForm::new_add();
        form.secret_kind = SecretChoice::IdentityKey;
        form.source = SourceChoice::Path;
        form.focus = CredField::Identity;
        let _ = form.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| {
            let body = crate::tui::dialog::draw_dialog(
                f,
                &form.title(),
                form.body_rows(),
                &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
            );
            form.draw_in_dialog(f, body);
        });
    }
}
