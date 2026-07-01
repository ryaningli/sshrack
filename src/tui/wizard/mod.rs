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
//! [`Outcome`]: super::app::Outcome
//! [`Outcome::SaveHost`]: super::app::Outcome::SaveHost
//! [`Outcome::SaveCred`]: super::app::Outcome::SaveCred

use ratatui::style::Style;
use ratatui::text::Span;
use sshrack_core::host::validate_name_chars;

pub mod cred;
pub mod host;

pub use cred::CredForm;
pub use host::HostForm;

// ===========================================================================
// Host wizard shared shape
// ===========================================================================

/// The selectable auth methods offered by the host wizard. This is the wizard's
/// own input shape — distinct from core's [`Auth`] because the wizard works in
/// *names* (a credential name the user picks from a chooser) while core stores
/// *ids* (the loop resolves name→id before persisting). Inline password is
/// intentionally absent (see the module docs).
///
/// [`Auth`]: sshrack_core::config::schema::Auth
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthChoice {
    /// Inline user, no secret (rely on the ssh default / agent).
    Default,
    /// Reuse a named `[[credentials]]` entry. `idx` indexes the credential
    /// list the wizard was constructed with; the loop reads the name out of
    /// the form and resolves it to an id at save time.
    Credential { idx: usize },
    /// Inline user + identity key path (entered as a text field).
    InlineKey,
}

impl AuthChoice {
    /// The display order used by the chooser's `←`/`→` cycling. Mirrors the
    /// sshrack CLI's interactive `prompt_auth` menu ordering.
    const ORDER: &'static [AuthKind] =
        &[AuthKind::Default, AuthKind::Credential, AuthKind::InlineKey];

    /// Which slot in [`AuthChoice::ORDER`] this variant occupies.
    fn kind(&self) -> AuthKind {
        match self {
            AuthChoice::Default => AuthKind::Default,
            AuthChoice::Credential { .. } => AuthKind::Credential,
            AuthChoice::InlineKey => AuthKind::InlineKey,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthKind {
    Default,
    Credential,
    InlineKey,
}

/// The focused field in the host form. `Tab`/`↑`/`↓` (and `Enter` to advance)
/// move through these in declaration order; the last field's `Enter` triggers a
/// save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Host,
    Port,
    User,
    Auth,
}

impl Field {
    /// Top-to-bottom render + navigation order.
    const ORDER: &'static [Field] = &[
        Field::Name,
        Field::Host,
        Field::Port,
        Field::User,
        Field::Auth,
    ];

    fn idx(self) -> usize {
        Self::ORDER
            .iter()
            .position(|f| *f == self)
            .expect("invariant: every Field variant is in ORDER")
    }

    fn next(self) -> Field {
        let i = self.idx();
        Self::ORDER[(i + 1) % Self::ORDER.len()]
    }

    fn prev(self) -> Field {
        let i = self.idx();
        Self::ORDER[(i + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }

    /// True when this is the last field in the form (Enter here submits).
    fn is_last(self) -> bool {
        self.idx() == Self::ORDER.len() - 1
    }

    /// Human label shown in the form.
    fn label(self) -> &'static str {
        match self {
            Field::Name => "name",
            Field::Host => "host",
            Field::Port => "port",
            Field::User => "user",
            Field::Auth => "auth",
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
            CredField::Name => "name",
            CredField::User => "user",
            CredField::Identity => "key",
            CredField::SecretKind => "secret",
            CredField::Password => "password",
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
/// `"▶ " (2) + right-aligned label + ": " (2)`. Host labels are padded to 5,
/// credentials to 8. Used by each form's `draw` to place the terminal cursor.
pub(super) const HOST_VALUE_COL: u16 = 2 + 5 + 2;
pub(super) const CRED_VALUE_COL: u16 = 2 + 8 + 2;

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
}
