//! Host & credential add/edit wizards: thin form views over core's
//! `host::add` / `host::edit` and `credential::add` / `credential::edit`.
//!
//! The wizards are a pure view layer — each holds form state and a pure
//! `on_key` that mutates that state and returns an [`Outcome`]. The
//! actual `host::add`/`host::edit` / credential persist call + config
//! persistence happens in the event loop ([`super::app::run_loop`]) after
//! `on_key` signals [`Outcome::SaveHost`] / [`Outcome::SaveCred`], exactly
//! mirroring how the launcher's connect intent is a pure signal the loop
//! acts on. This keeps the wizards unit-testable without a terminal or a
//! filesystem.
//!
//! This module is the shared root for the [`host`] and [`cred`] submodules:
//! it owns the cross-cutting enums/helpers ([`AuthChoice`], [`Field`],
//! [`SaveError`], [`validate`], [`SecretChoice`], [`CredField`],
//! [`CredSaveError`], [`validate_cred`], [`value_spans`]) and re-exports the
//! two forms. External consumers (the App overlay layer) import everything
//! via `super::wizard::{...}` — the paths stay identical to the pre-split
//! single-file layout.
//!
//! [`Outcome`]: super::intent::Outcome
//! [`Outcome::SaveHost`]: super::intent::Outcome::SaveHost
//! [`Outcome::SaveCred`]: super::intent::Outcome::SaveCred

use ratatui::style::Style;
use ratatui::text::Span;
use sshrack_core::host::validate_name_chars;

pub mod cred;
pub mod cred_picker;
pub mod host;

pub use cred::CredForm;
pub use cred_picker::{CredPicker, PickerOutcome};
pub use host::HostForm;

// ===========================================================================
// Host wizard shared shape
// ===========================================================================

/// The selectable auth strategies offered by the host wizard. Two states only:
/// reuse a named `[[credentials]]` entry, or carry an inline (host-own) config.
/// This is the wizard's own input shape — distinct from core's [`Auth`] because
/// the wizard works in *names* (a credential name the user picks) while core
/// stores *ids* (the loop resolves name→id before persist). The inline secret
/// kind is a separate [`SecretChoice`] row that appears only under Independent.
///
/// [`Auth`]: sshrack_core::config::schema::Auth
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthChoice {
    /// Reuse a named `[[credentials]]` entry. `idx` indexes the credential
    /// list the wizard was constructed with; the loop reads the name and
    /// resolves it to an id at save time.
    Reference { idx: usize },
    /// Host-own auth: an inline user plus an optional secret (None / Password /
    /// IdentityKey), chosen on the Secret row.
    Independent,
}

impl AuthChoice {
    /// Display order used by the auth chooser's `←`/`→` cycling. Independent
    /// first: it is the zero-config default (a fresh host with no credential
    /// yet defined should be addable without forcing a detour to the cred tab).
    const ORDER: &'static [AuthKind] = &[AuthKind::Independent, AuthKind::Reference];

    /// Which slot in [`AuthChoice::ORDER`] this variant occupies.
    fn kind(&self) -> AuthKind {
        match self {
            AuthChoice::Reference { .. } => AuthKind::Reference,
            AuthChoice::Independent => AuthKind::Independent,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthKind {
    Independent,
    Reference,
}

/// The focused field in the host form. `Tab`/`↑`/`↓` (and `Enter` to advance)
/// move through the reachable ones in declaration order; the last reachable
/// field's `Enter` triggers a save. `User`/`Secret`/`Identity`/`Password` are
/// reachable only under [`AuthChoice::Independent`] (and `Identity`/`Password`
/// further depend on [`SecretChoice`]); the form filters them at navigation
/// time via [`HostForm::reachable_fields`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Host,
    Port,
    User,
    Auth,
    /// Pick which `[[credentials]]` entry this host reuses (Reference branch
    /// only). A trigger row: `Enter` opens the fuzzy credential picker overlay,
    /// not a text field. Unreachable under Independent.
    Credential,
    Secret,
    Identity,
    Password,
}

impl Field {
    /// Top-to-bottom render + navigation order.
    const ORDER: &'static [Field] = &[
        Field::Name,
        Field::Host,
        Field::Port,
        Field::Auth,
        Field::Credential,
        Field::User,
        Field::Secret,
        Field::Identity,
        Field::Password,
    ];

    /// Human label shown in the form. Capitalized so the add/edit forms read
    /// "Name" / "Host" / ... rather than lowercase.
    fn label(self) -> &'static str {
        match self {
            Field::Name => "Name",
            Field::Host => "Host",
            Field::Port => "Port",
            Field::User => "User",
            Field::Auth => "Auth",
            Field::Credential => "Credential",
            Field::Secret => "Secret",
            Field::Identity => "Identity",
            Field::Password => "Password",
        }
    }
}

/// Validation error from [`validate`]. Pure: decides whether a save attempt is
/// even worth sending to core. Core's own checks (`host::add_host`'s forbidden
/// char reject, duplicate-name check) still run at persist time; this mirrors
/// sshelf's `try_save` so the wizard can focus the bad field *before* the loop
/// does any I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveError {
    /// Name is empty / whitespace-only.
    MissingName,
    /// Name contains a forbidden character (`:` `@` or whitespace).
    InvalidName,
    /// Host address is empty / whitespace-only.
    MissingHost,
}

impl SaveError {
    /// Which field the error belongs to, so the wizard can move focus there.
    pub fn field(self) -> Field {
        match self {
            SaveError::MissingName | SaveError::InvalidName => Field::Name,
            SaveError::MissingHost => Field::Host,
        }
    }

    /// A one-line human message for the error line under the field.
    pub fn message(self) -> &'static str {
        match self {
            SaveError::MissingName => "name is required",
            SaveError::InvalidName => "name contains a forbidden character (:, @, or whitespace)",
            SaveError::MissingHost => "host is required",
        }
    }
}

/// Pure validation of a host form: name non-empty + legal chars, host non-empty.
/// Does NOT check duplicates (core does that at persist time) and does NOT touch
/// the filesystem. Mirrors sshelf's `try_save`.
pub fn validate(form: &HostForm) -> Result<(), SaveError> {
    if form.name.trim().is_empty() {
        return Err(SaveError::MissingName);
    }
    if validate_name_chars(form.name.trim()).is_err() {
        return Err(SaveError::InvalidName);
    }
    if form.host_addr.trim().is_empty() {
        return Err(SaveError::MissingHost);
    }
    Ok(())
}

// ===========================================================================
// Credential wizard shared shape
// ===========================================================================

/// The selectable secret kinds offered by the credential wizard. Cycled by the
/// `←`/`→` chooser on the secret row. Mirrors
/// [`CredentialBody::secret_kind`] but the wizard owns its own copy so the
/// chooser can present three concrete options (Password / IdentityKey / None)
/// the user picks between.
///
/// [`CredentialBody::secret_kind`]: sshrack_core::config::schema::CredentialBody::secret_kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretChoice {
    /// A password (sealed via the configured store mode at save time).
    Password,
    /// An identity key path (entered as a text field).
    IdentityKey,
    /// No explicit secret (rely on ssh default / agent keys).
    None,
}

impl SecretChoice {
    /// Display order used by the chooser's `←`/`→` cycling.
    const ORDER: &'static [SecretChoice] = &[
        SecretChoice::None,
        SecretChoice::Password,
        SecretChoice::IdentityKey,
    ];

    fn idx(self) -> usize {
        Self::ORDER
            .iter()
            .position(|s| *s == self)
            .expect("invariant: every SecretChoice variant is in ORDER")
    }

    fn next(self) -> SecretChoice {
        let i = self.idx();
        Self::ORDER[(i + 1) % Self::ORDER.len()]
    }

    fn prev(self) -> SecretChoice {
        let i = self.idx();
        Self::ORDER[(i + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }

    /// One-word label shown in the chooser row.
    fn label(self) -> &'static str {
        match self {
            SecretChoice::Password => "Password",
            SecretChoice::IdentityKey => "IdentityKey",
            SecretChoice::None => "None",
        }
    }
}

/// The focused field in the credential form. `Tab`/`↑`/`↓` (and `Enter` to
/// advance) move through these in declaration order; the last field's `Enter`
/// triggers a save. The `Password` row is only focusable / editable when the
/// secret choice is [`SecretChoice::Password`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredField {
    Name,
    User,
    Identity,
    SecretKind,
    /// Masked password input; reachable only under [`SecretChoice::Password`].
    Password,
}

impl CredField {
    /// Top-to-bottom render + navigation order. The `Password` slot is skipped
    /// during navigation when the secret choice is not Password (the wizard
    /// filters it out at navigation time).
    const ORDER: &'static [CredField] = &[
        CredField::Name,
        CredField::User,
        CredField::Identity,
        CredField::SecretKind,
        CredField::Password,
    ];

    fn label(self) -> &'static str {
        match self {
            CredField::Name => "Name",
            CredField::User => "User",
            CredField::Identity => "Identity",
            CredField::SecretKind => "Secret",
            CredField::Password => "Password",
        }
    }
}

/// Validation error from [`validate_cred`]. Pure: decides whether a save
/// attempt is worth sending to core. Core's own checks (duplicate-name,
/// forbidden char, body validation) still run at persist time; this lets the
/// wizard focus the bad field *before* the loop does any I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredSaveError {
    /// Name is empty / whitespace-only.
    MissingName,
    /// Name contains a forbidden character (`:` `@` or whitespace).
    InvalidName,
    /// User is empty / whitespace-only.
    MissingUser,
}

impl CredSaveError {
    /// Which field the error belongs to, so the wizard can move focus there.
    pub fn field(self) -> CredField {
        match self {
            CredSaveError::MissingName | CredSaveError::InvalidName => CredField::Name,
            CredSaveError::MissingUser => CredField::User,
        }
    }

    /// A one-line human message for the error line under the field.
    pub fn message(self) -> &'static str {
        match self {
            CredSaveError::MissingName => "name is required",
            CredSaveError::InvalidName => {
                "name contains a forbidden character (:, @, or whitespace)"
            }
            CredSaveError::MissingUser => "user is required",
        }
    }
}

/// Pure validation of a credential form: name non-empty + legal chars, user
/// non-empty. Does NOT check duplicates (core does that at persist time) and
/// does NOT touch the filesystem. Mirrors [`validate`] for hosts.
pub fn validate_cred(form: &CredForm) -> Result<(), CredSaveError> {
    if form.name.trim().is_empty() {
        return Err(CredSaveError::MissingName);
    }
    if validate_name_chars(form.name.trim()).is_err() {
        return Err(CredSaveError::InvalidName);
    }
    if form.user.trim().is_empty() {
        return Err(CredSaveError::MissingUser);
    }
    Ok(())
}

// ===========================================================================
// Shared render helpers (cross-form)
// ===========================================================================

/// Build the value-area spans for one field row. Shared by [`HostForm`] and
/// [`CredForm`] so both render the empty state identically.
///
/// No cursor glyph is drawn here — the real terminal cursor is placed by each
/// form's `draw` via `Frame::set_cursor_position`, so an empty focused field
/// shows just the dim placeholder with the terminal cursor landing on its
/// first char (mirrors sshelf). A non-empty value renders raw; the placeholder
/// disappears.
pub(super) fn value_spans(value: &str, placeholder: Option<&str>) -> Vec<Span<'static>> {
    if value.is_empty() {
        placeholder
            .map(|ph| vec![Span::styled(ph.to_string(), Style::new().dim())])
            .unwrap_or_default()
    } else {
        vec![Span::raw(value.to_string())]
    }
}

/// Column where the editable value begins within a rendered field row:
/// `"▶ " (2) + right-aligned label + ": " (2)`. Host labels are padded to 9
/// (the longest host label is `Credential` = 9); credential-wizard labels stay
/// 8. Used by each form's `draw` to place the terminal cursor.
pub(super) const HOST_VALUE_COL: u16 = 2 + 9 + 2;
pub(super) const CRED_VALUE_COL: u16 = 2 + 8 + 2;

// ===========================================================================
// Cursor-edit helpers
// ===========================================================================

/// Insert `c` into `s` at the given char index, returning the new char index
/// (one past the inserted char). Wizard text fields use this to type at the
/// cursor rather than always appending. `cursor` beyond `s`'s char count
/// clamps to the end (append). Pure aside from mutating `s`.
pub(super) fn insert_char_at(s: &mut String, cursor: usize, c: char) -> usize {
    let original_len = s.chars().count();
    let byte = char_byte_offset(s, cursor);
    s.insert(byte, c);
    // If cursor was at or past the end, we inserted at the end, so the new
    // cursor is one past the original end. Otherwise it's one past the insert.
    cursor.min(original_len) + 1
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

#[cfg(test)]
mod tests {
    //! Shared-helper tests for the value-area span builder. The form-specific
    //! state-machine tests live in [`super::host`] and [`super::cred`].
    use super::*;

    // ---- value_spans: empty-state cursor sits BEFORE the placeholder ----

    #[test]
    fn value_spans_empty_shows_only_placeholder_no_glyph() {
        let spans = value_spans("", Some("e.g. web-prod"));
        assert_eq!(spans.len(), 1, "empty: placeholder only, no drawn cursor");
        assert_eq!(&*spans[0].content, "e.g. web-prod");
    }

    #[test]
    fn value_spans_non_empty_shows_only_value() {
        let spans = value_spans("typed", Some("e.g. web-prod"));
        assert_eq!(spans.len(), 1);
        assert_eq!(&*spans[0].content, "typed");
    }

    #[test]
    fn value_spans_empty_with_no_placeholder_is_empty() {
        let spans = value_spans("", None);
        assert!(spans.is_empty());
    }

    #[test]
    fn value_spans_non_empty_ignores_placeholder() {
        let spans = value_spans("x", Some("e.g. web-prod"));
        assert_eq!(spans.len(), 1);
        assert_eq!(&*spans[0].content, "x");
    }

    // ---- label capitalization: every field/choice label starts uppercase ----

    #[test]
    fn host_field_labels_are_capitalized() {
        // Each returned label must start with an uppercase letter so the
        // add/edit forms read "Name" / "Host" / ... instead of lowercase.
        for f in Field::ORDER {
            let label = f.label();
            let first = label.chars().next().unwrap_or(' ');
            assert!(
                first.is_ascii_uppercase(),
                "Field {:?} label {:?} must start uppercase",
                f,
                label
            );
        }
        // Pin the exact wording so a future edit can't silently regress.
        assert_eq!(Field::Name.label(), "Name");
        assert_eq!(Field::Host.label(), "Host");
        assert_eq!(Field::Port.label(), "Port");
        assert_eq!(Field::User.label(), "User");
        assert_eq!(Field::Auth.label(), "Auth");
        assert_eq!(Field::Credential.label(), "Credential");
        assert_eq!(Field::Secret.label(), "Secret");
        assert_eq!(Field::Identity.label(), "Identity");
        assert_eq!(Field::Password.label(), "Password");
    }

    #[test]
    fn cred_field_labels_are_capitalized() {
        for f in CredField::ORDER {
            let label = f.label();
            let first = label.chars().next().unwrap_or(' ');
            assert!(
                first.is_ascii_uppercase(),
                "CredField {:?} label {:?} must start uppercase",
                f,
                label
            );
        }
        assert_eq!(CredField::Name.label(), "Name");
        assert_eq!(CredField::User.label(), "User");
        assert_eq!(CredField::Identity.label(), "Identity");
        assert_eq!(CredField::SecretKind.label(), "Secret");
        assert_eq!(CredField::Password.label(), "Password");
    }

    #[test]
    fn secret_choice_labels_are_capitalized() {
        for s in SecretChoice::ORDER {
            let label = s.label();
            let first = label.chars().next().unwrap_or(' ');
            assert!(
                first.is_ascii_uppercase(),
                "SecretChoice {:?} label {:?} must start uppercase",
                s,
                label
            );
        }
        assert_eq!(SecretChoice::Password.label(), "Password");
        assert_eq!(SecretChoice::IdentityKey.label(), "IdentityKey");
        assert_eq!(SecretChoice::None.label(), "None");
    }
}

#[cfg(test)]
mod cursor_edit_tests {
    //! Cursor-edit helper tests for insert_char_at / backspace_at.
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
