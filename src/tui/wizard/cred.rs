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
    CRED_LABEL_WIDTH, CRED_VALUE_COL, CredField, CredSaveError, SecretChoice, SourceChoice,
    backspace_at, bracketed, insert_char_at, validate_cred, value_spans,
};
use crate::tui::fit::truncate_cells;
use ratatui_textarea::{Input, Key, TextArea};
use sshrack_core::config::schema::{Credential, CredentialBody, KeySource};

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
    /// Multiline private-key paste, edited when the secret choice is
    /// [`SecretChoice::IdentityKey`] AND the source is [`SourceChoice::Inline`].
    /// Always empty on edit-entry (the existing key text is NEVER echoed back —
    /// security; [`CredForm::build_body`] preserves the original on save when
    /// this stays blank). [`TextArea`] is not [`PartialEq`] and its [`Debug`]
    /// prints contents, so this field never participates in whole-form equality
    /// (none exists) and the form's hand-written [`Debug`] shows only its line
    /// COUNT.
    ///
    /// [`PartialEq`]: std::cmp::PartialEq
    /// [`Debug`]: std::fmt::Debug
    pub inline_private: TextArea<'static>,
    /// Multiline optional certificate paste, companion to
    /// [`CredForm::inline_private`]. Same lifecycle: always empty on
    /// edit-entry, edited only under Inline source.
    pub inline_cert: TextArea<'static>,
    /// The masked password, edited when the secret choice is
    /// [`SecretChoice::Password`]. `Zeroizing` so it is wiped on drop.
    pub password: Zeroizing<String>,
    /// Currently focused field.
    pub focus: CredField,
    /// Char-index cursor within the focused text field. Reset to the focused
    /// field's end on focus change; clamped on read by [`cursor_target`].
    /// Irrelevant for the Source chooser and the multiline paste fields (the
    /// [`TextArea`] owns its own cursor).
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
    /// edit time. Under the Inline source the textareas start EMPTY (the key
    /// text is never echoed); [`CredForm::build_body`] re-attaches this
    /// verbatim when the private field stays blank, so silently dropping it
    /// never destroys the credential's only secret. `None` in add mode and when
    /// the original had no key.
    pub orig_key: Option<KeySource>,
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
        // The two inline-paste TextAreas are NEVER surfaced directly:
        // `TextArea`'s derived `Debug` prints the `lines: Vec<String>` field,
        // which would leak the pasted private key / certificate to any
        // `dbg!(form)` / `format!("{form:?}")` call. Surface ONLY their line
        // count, so a glance at the form's Debug still tells you whether the
        // user has pasted anything without ever showing what.
        f.debug_struct("CredForm")
            .field("name", &self.name)
            .field("user", &self.user)
            .field("identity", &self.identity)
            .field("secret_kind", &self.secret_kind)
            .field("source", &self.source)
            .field("inline_private_lines", &self.inline_private.lines().len())
            .field("inline_cert_lines", &self.inline_cert.lines().len())
            .field("password", &"<redacted>")
            .field("focus", &self.focus)
            .field("error", &self.error)
            .field("core_error", &self.core_error)
            .field("editing", &self.editing)
            .field("orig_id", &self.orig_id)
            .field("orig_key", &self.orig_key)
            .finish()
    }
}

/// Map sshrack's `crossterm` 0.28 [`KeyEvent`] into a [`TextArea`]
/// [`Input`].
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
            inline_private: TextArea::default(),
            inline_cert: TextArea::default(),
            password: Zeroizing::new(String::new()),
            focus: CredField::Name,
            cursor: 0,
            error: None,
            core_error: None,
            editing: false,
            orig_id: None,
            orig_key: None,
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
    /// left blank (the key text is NEVER echoed into a textarea — security).
    /// The original [`KeySource`] is carried as `orig_key` regardless, so
    /// [`build_body`](Self::build_body) can re-attach an inline original
    /// verbatim when the user does not paste a new key — silently dropping it
    /// would destroy the credential's only secret. The two inline textareas
    /// always start EMPTY on edit entry, even when the original was inline
    /// material; the user pastes a NEW key to replace it, or leaves the
    /// private field blank to keep the original.
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
            // Inline textareas ALWAYS start empty on edit entry. An inline
            // original's key text is never echoed back (security); the user
            // pastes a new key to replace it, or leaves the private field
            // blank so build_body re-attaches the original.
            inline_private: TextArea::default(),
            inline_cert: TextArea::default(),
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
    ///   in-field cursor (name, user, identity, or password when the choice is
    ///   Password).
    /// - `←`/`→`/`Home`/`End` (and `Ctrl-A`/`Ctrl-E`) → move the in-field cursor
    ///   on text fields; clamped to the field's char length.
    /// - `Tab` / `↓` → next field; `Shift-Tab` / `↑` → previous field.
    /// - `Enter` → next field, or — on the last reachable field — attempt save;
    ///   on validation error set `error` and move focus to the bad field.
    ///   Inside an inline textarea, `Enter` instead inserts a newline (the
    ///   textarea owns multiline editing; see the guard below).
    /// - `Ctrl-S` → attempt save from any field.
    /// - `←`/`→` on the secret row → cycle secret kind.
    /// - `←`/`→` on the Source row (IdentityKey only) → cycle Path / Inline.
    /// - When an inline textarea (`InlinePrivate` / `InlineCert`) is focused,
    ///   every text-editing key is forwarded to the textarea so it owns its
    ///   cursor / newlines / backspace. Navigation (`Tab` / `BackTab` / `↑` /
    ///   `↓`), save (`Ctrl-S`), and cancel (`Esc` / `Ctrl-C`) still navigate /
    ///   act globally — only text-editing keys are captured.
    /// - `Esc` / `Ctrl-C` → cancel back.
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        // Any keystroke clears a stale core-level error.
        self.core_error = None;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let ctrl_c_only = key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c');

        if ctrl_c_only {
            return Outcome::Cancel;
        }

        // Inline-paste textareas: the focused TextArea owns all text-editing
        // (chars, Enter→newline, Backspace, arrows, Home/End, and its own
        // Emacs-style Ctrl shortcuts). A bare Enter therefore inserts a newline
        // at the textarea cursor instead of advancing to the next field.
        // Navigation (Tab / BackTab / Up / Down), cancel (Esc), and save
        // (Ctrl-S) bypass this guard so they keep working as field navigation
        // and global actions. (Ctrl-C was already handled above.) The textarea
        // returns whether it modified the buffer; we ignore that — we always
        // `Continue` because there is nothing else to do for a captured key.
        if matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert)
            && !matches!(
                key.code,
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down | KeyCode::Esc
            )
            && !(ctrl && key.code == KeyCode::Char('s'))
        {
            match self.focus {
                CredField::InlinePrivate => {
                    self.inline_private.input(textarea_input_from(key));
                }
                CredField::InlineCert => {
                    self.inline_cert.input(textarea_input_from(key));
                }
                // Guard above restricts to these two variants; the unreachable
                // arms keep the match exhaustive without a wider `_ =>`.
                _ => {}
            }
            return Outcome::Continue;
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
                // The inline textareas never reach this arm: the guard above
                // captures Enter (and every other text-editing key) when one is
                // focused, so Enter there inserts a newline in the textarea.
                // For the chooser/text fields, Enter advances or saves.
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
            // above. The inline textareas never reach here: the guard above
            // captures all their text-editing keys, including ←/→.)
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
    /// inline textareas are NEVER edited through this char-based path —
    /// [`on_key`](Self::on_key)'s textarea guard forwards the original
    /// `KeyEvent` to `TextArea::input` (which owns the cursor / newlines) — so
    /// those arms are no-ops here, reached only if a future caller bypasses the
    /// guard.
    fn edit_focused_insert(&mut self, c: char) {
        match self.focus {
            CredField::Name => self.cursor = insert_char_at(&mut self.name, self.cursor, c),
            CredField::User => self.cursor = insert_char_at(&mut self.user, self.cursor, c),
            CredField::Identity => self.cursor = insert_char_at(&mut self.identity, self.cursor, c),
            CredField::SecretKind => {
                // The chooser is driven by ←/→; no text entry on this row.
            }
            CredField::Password if self.secret_kind == SecretChoice::Password => {
                self.cursor = insert_char_at(&mut self.password, self.cursor, c)
            }
            CredField::Password => {}
            // No char-based text entry on these rows: Source is a ←/→ chooser;
            // InlinePrivate / InlineCert are edited via `TextArea::input` from
            // `on_key`'s textarea guard, which never calls this function.
            CredField::Source | CredField::InlinePrivate | CredField::InlineCert => {}
        }
        if Some(self.focus) == self.error.map(CredSaveError::field) {
            self.error = None;
        }
    }

    /// Delete the char immediately before the in-field cursor (mirror of
    /// [`edit_focused_insert`]). No-op when the cursor is already at the start.
    /// As with [`edit_focused_insert`], the inline textareas handle backspace
    /// themselves via `TextArea::input`; their arms here are unreachable
    /// no-ops.
    fn edit_focused_backspace(&mut self) {
        match self.focus {
            CredField::Name => self.cursor = backspace_at(&mut self.name, self.cursor),
            CredField::User => self.cursor = backspace_at(&mut self.user, self.cursor),
            CredField::Identity => self.cursor = backspace_at(&mut self.identity, self.cursor),
            CredField::SecretKind => {}
            CredField::Password if self.secret_kind == SecretChoice::Password => {
                self.cursor = backspace_at(&mut self.password, self.cursor)
            }
            CredField::Password => {}
            // See `edit_focused_insert`: textareas own their own backspace.
            CredField::Source | CredField::InlinePrivate | CredField::InlineCert => {}
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
    /// - **Inline** — the private textarea's joined lines become an inline key
    ///   via [`CredentialBody::with_inline_key`], with the cert textarea
    ///   attached only when non-empty. A blank private field on edit preserves
    ///   the original inline material verbatim (the textareas are NEVER
    ///   prefilled with key text on edit-entry — security; this rule is the
    ///   only thing standing between the user and silently losing their key).
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
                        let private = self.inline_private.lines().join("\n");
                        let cert = self.inline_cert.lines().join("\n");
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
    /// [`crate::tui::dialog::draw_dialog`] hands the form). No outer border —
    /// the dialog already drew the chrome.
    pub fn draw_in_dialog(&self, frame: &mut Frame, body: ratatui::layout::Rect) {
        let reachable = self.reachable_fields();
        let total = reachable.len();
        // The fields area is `body.height` minus the error(1) + hint(1) rows
        // rendered below. When the terminal is too short to fit every field,
        // `focus_window` picks the viewport that keeps the focused one visible.
        let fields_h = body.height.saturating_sub(2) as usize;
        let win = crate::tui::fit::focus_window(total, self.focus_idx(), fields_h);
        let rows: Vec<Line> = reachable[win.clone()]
            .iter()
            .map(|f| self.render_row(*f, body.width))
            .collect();

        // Fields area is `Fill(1)` so it absorbs the slack between the
        // top-aligned field rows and the error/hint rows pinned to the body's
        // bottom. This keeps the error line + field-specific hint at a FIXED y
        // (just above the dialog footer) regardless of how many fields are
        // reachable — the dialog box is a stable container, content flows in it.
        let [fields_area, error_area, hint_area] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(body);

        frame.render_widget(Paragraph::new(rows), fields_area);

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
            "  Enter=newline  Tab=next field"
        } else {
            "  up/down next field"
        };
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);

        // Place the real terminal cursor on the focused text field (no drawn
        // glyph — see HostForm::draw_in_dialog). SecretKind is a chooser. The
        // row index is translated into the viewport so the cursor never points
        // below the fields area when the list scrolls.
        if let Some((row, offset)) = self.cursor_target() {
            if win.start <= row && row < win.end {
                let in_win_row = row - win.start;
                let max_x = fields_area.x + fields_area.width.saturating_sub(1);
                let x = (fields_area.x + CRED_VALUE_COL + offset as u16).min(max_x);
                let y = fields_area.y + in_win_row as u16;
                frame.set_cursor_position((x, y));
            }
        }
    }

    /// Char count of the currently focused text field. Returns 0 for the
    /// SecretKind and Source chooser rows (no in-field cursor) and for the
    /// inline textareas (the [`TextArea`] owns its own cursor, so this form
    /// cursor is irrelevant for them).
    fn focused_text_len(&self) -> usize {
        match self.focus {
            CredField::Name => self.name.chars().count(),
            CredField::User => self.user.chars().count(),
            CredField::Identity => self.identity.chars().count(),
            CredField::Password => self.password.chars().count(),
            CredField::SecretKind => 0,
            CredField::Source | CredField::InlinePrivate | CredField::InlineCert => 0,
        }
    }

    /// The `(row, value_offset)` where the terminal cursor should sit for the
    /// focused field, or `None` for the SecretKind / Source choosers and the
    /// inline textareas. `row` is the index into the reachable rendered rows;
    /// `offset` is the stored char-index cursor, clamped to the field's current
    /// length. Pure; consumed by [`CredForm::draw_in_dialog`] to call
    /// `Frame::set_cursor_position`. The inline textareas return `None` because
    /// [`TextArea`] positions its own cursor internally; the Source row is a
    /// chooser like SecretKind.
    fn cursor_target(&self) -> Option<(usize, usize)> {
        let row = self.focus_idx();
        let offset = match self.focus {
            CredField::Name => self.cursor.min(self.name.chars().count()),
            CredField::User => self.cursor.min(self.user.chars().count()),
            CredField::Identity => self.cursor.min(self.identity.chars().count()),
            CredField::Password => self.cursor.min(self.password.chars().count()),
            CredField::SecretKind => return None,
            CredField::Source | CredField::InlinePrivate | CredField::InlineCert => return None,
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

    /// Stable body row count the dialog sizes to: the **maximum** reachable
    /// field count across every (secret, source) state, plus one error row and
    /// one hint row. Pinned to the worst case on purpose — toggling the Secret
    /// or Source chooser changes which rows are filled, but the dialog box must
    /// never resize while the form is open, so the unused slot renders blank
    /// instead of the border growing/shrinking. The IdentityKey + Inline state
    /// has the most rows (Name / User / SecretKind / Source / InlinePrivate /
    /// InlineCert = 6). Consumed by the App overlay layer via
    /// [`crate::tui::dialog::draw_dialog`].
    pub fn body_rows(&self) -> u16 {
        let max_fields = [
            SecretChoice::None,
            SecretChoice::Password,
            SecretChoice::IdentityKey,
        ]
        .iter()
        .flat_map(|&secret| {
            [SourceChoice::Path, SourceChoice::Inline]
                .iter()
                .map(move |&source| (secret, source))
        })
        .map(|(secret, source)| {
            CredField::ORDER
                .iter()
                .filter(|&&f| Self::field_reachable(f, secret, source))
                .count()
        })
        .max()
        .unwrap_or(0);
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
            CredField::Identity => (self.identity.clone(), Some("path to a private key")),
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
                // the cycle direction. (Task 4 may refine the render.)
                let v = bracketed(self.source.label());
                let ph = Some("<- -> cycle: Path / Inline");
                (v, ph)
            }
            CredField::InlinePrivate => {
                // Never echo the pasted key text as the row value (security —
                // the textarea renders its own buffer in Task 4; for now the
                // row reads blank with a placeholder). On edit the placeholder
                // reminds the user the original is preserved when this stays
                // empty.
                let ph = if self.editing {
                    Some("paste a NEW key (blank keeps existing)")
                } else {
                    Some("paste the private key")
                };
                (String::new(), ph)
            }
            CredField::InlineCert => {
                let ph = if self.editing {
                    Some("paste a NEW cert (blank keeps existing)")
                } else {
                    Some("paste the certificate (optional)")
                };
                (String::new(), ph)
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

    // ---- inline-key preservation on edit (Plan 1 stopgap) ----
    //
    // The wizard cannot paste-edit inline key text yet (Plan 2). Editing a
    // credential whose key is inline material must therefore preserve the
    // original KeySource::Inline verbatim when the identity field is left
    // blank — silently dropping it would destroy the credential's only secret.
    // A path original left blank is treated as "user cleared the field".

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
        f.inline_private = TextArea::new(vec!["PRIVATE-KEY-TEXT".into()]);
        f.inline_cert = TextArea::new(vec!["CERT-TEXT".into()]);
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
        f.inline_private = TextArea::new(vec!["line1".into(), "line2".into(), "line3".into()]);
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
        f.inline_private = TextArea::default(); // empty — user did not re-paste
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
    fn inline_source_hides_identity_and_reaches_textareas() {
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
    fn typing_into_inline_private_goes_to_the_textarea() {
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = CredField::InlinePrivate;
        for c in "PRIVATE-KEY-TEXT".chars() {
            f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert_eq!(f.inline_private.lines().join("\n"), "PRIVATE-KEY-TEXT");
    }

    #[test]
    fn new_edit_inline_original_defaults_source_to_inline_with_empty_textarea() {
        // Editing an inline-key owner: Source defaults to Inline, but the key
        // text is NEVER echoed into the textarea (security). build_body must
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
        assert!(
            f.inline_private.lines().join("\n").is_empty(),
            "key text must NOT echo"
        );
        assert!(matches!(f.orig_key, Some(KeySource::Inline(_))));
    }

    #[test]
    fn enter_inside_textarea_inserts_newline_instead_of_advancing_field() {
        // A bare Enter in a multiline paste field must insert a newline at the
        // textarea cursor (the textarea's default mapping), NOT advance focus
        // to the next reachable field. Tab still navigates between fields.
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = CredField::InlinePrivate;
        // Type "line1", press Enter, type "line2".
        for c in "line1".chars() {
            f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let focus_before = f.focus;
        f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        // Focus must NOT have advanced.
        assert_eq!(
            f.focus, focus_before,
            "Enter must not advance focus in a textarea"
        );
        for c in "line2".chars() {
            f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert_eq!(f.inline_private.lines().join("\n"), "line1\nline2");
    }

    #[test]
    fn tab_and_arrows_navigate_between_textareas_and_out() {
        // Tab / Up / Down bypass the textarea-input guard, so they still
        // navigate between the inline textareas and out to the Source row.
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
    fn backspace_inside_textarea_deletes_within_the_textarea() {
        // Backspace is forwarded to the textarea (it owns its own cursor), so
        // it deletes inside the pasted buffer rather than calling the form's
        // char-based `backspace_at` helper (which would be a no-op on a
        // textarea anyway). Type "abc", backspace once → "ab".
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = CredField::InlineCert;
        for c in "abc".chars() {
            f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
        }
        f.on_key(press(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(f.inline_cert.lines().join("\n"), "ab");
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
    fn debug_impl_does_not_leak_textarea_contents() {
        // The hand-written Debug must show only the line COUNT, never the
        // pasted key text. `format!("{:?}", form)` going to logs/errors must
        // not leak "PRIVATE-SECRET".
        let mut f = CredForm::new_add();
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = CredField::InlinePrivate;
        for c in "PRIVATE-SECRET-TEXT".chars() {
            f.inline_private.input(textarea_input_from(press(
                KeyCode::Char(c),
                KeyModifiers::NONE,
            )));
        }
        let dbg = format!("{f:?}");
        assert!(
            !dbg.contains("PRIVATE-SECRET-TEXT"),
            "Debug must not leak textarea contents: {dbg}"
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
}
