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

use ratatui::layout::Alignment;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use unicode_width::UnicodeWidthStr;

use crate::tui::fit::truncate_cells;
use crate::tui::theme;
use sshrack_core::config::schema::KeySource;
use sshrack_core::host::validate_name_chars;

pub mod cred;
pub mod cred_picker;
pub mod host;
pub mod key_paste;

pub use cred::CredForm;
pub use cred_picker::{CredPicker, PickerOutcome};
pub use host::HostForm;
pub use key_paste::{KeyPaste, PasteKind, PasteOutcome};

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
    /// Raw ssh option flags for this host (free text; validated at save).
    /// Reachable under every auth mode — it describes the machine's
    /// network/compat, not identity.
    SshArgs,
    User,
    Auth,
    /// Pick which `[[credentials]]` entry this host reuses (Reference branch
    /// only). A trigger row: `Enter` opens the fuzzy credential picker overlay,
    /// not a text field. Unreachable under Independent.
    Credential,
    Secret,
    /// Identity-key source chooser (Path vs Inline). Sits between the
    /// `Secret` chooser and the slot rows so the Independent form reads
    /// top-down: pick the secret kind, then the source, then fill the slot.
    /// Reachable iff auth == [`AuthChoice::Independent`] AND secret ==
    /// [`SecretChoice::IdentityKey`] (see [`HostForm::field_reachable`]).
    Source,
    /// Inline private-key paste trigger row (Inline source only). Reachable iff
    /// Independent + IdentityKey + Inline. `Enter` opens the [`KeyPaste`] popup
    /// (modal); the form row itself holds only the line-count summary.
    InlinePrivate,
    /// Inline optional certificate paste trigger row (Inline source only).
    /// Reachable iff Independent + IdentityKey + Inline. `Enter` opens the
    /// [`KeyPaste`] popup (modal); the form row itself holds only the
    /// line-count summary.
    InlineCert,
    Identity,
    Password,
}

impl Field {
    /// Top-to-bottom render + navigation order. `Secret` precedes the slot
    /// rows it gates so the Independent form reads top-down: pick the kind,
    /// then the source, then fill the slot it exposes. The slot rows are
    /// filtered at navigation time by [`HostForm::reachable_fields`] according
    /// to the (auth, secret, source) matrix.
    const ORDER: &'static [Field] = &[
        Field::Name,
        Field::Host,
        Field::Port,
        Field::SshArgs,
        Field::Auth,
        Field::Credential,
        Field::User,
        Field::Secret,
        Field::Source,
        Field::Identity,
        Field::InlinePrivate,
        Field::InlineCert,
        Field::Password,
    ];

    /// Human label shown in the form. Capitalized so the add/edit forms read
    /// "Name" / "Host" / ... rather than lowercase.
    fn label(self) -> &'static str {
        match self {
            Field::Name => "Name",
            Field::Host => "Host",
            Field::Port => "Port",
            Field::SshArgs => "SSH args",
            Field::User => "User",
            Field::Auth => "Auth",
            Field::Credential => "Credential",
            Field::Secret => "Secret",
            Field::Source => "Source",
            Field::InlinePrivate => "Privkey",
            Field::InlineCert => "Cert",
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
    /// ssh_args failed core validation (control char / unterminated quote /
    /// empty token).
    InvalidSshArgs,
}

impl SaveError {
    /// Which field the error belongs to, so the wizard can move focus there.
    pub fn field(self) -> Field {
        match self {
            SaveError::MissingName | SaveError::InvalidName => Field::Name,
            SaveError::MissingHost => Field::Host,
            SaveError::InvalidSshArgs => Field::SshArgs,
        }
    }

    /// A one-line human message for the error line under the field.
    pub fn message(self) -> &'static str {
        match self {
            SaveError::MissingName => "name is required",
            SaveError::InvalidName => "name contains a forbidden character (:, @, or whitespace)",
            SaveError::MissingHost => "host is required",
            SaveError::InvalidSshArgs => {
                "ssh args are invalid (control character, unterminated quote, or empty argument)"
            }
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
    if sshrack_core::sshargs::validate(&form.ssh_args).is_err() {
        return Err(SaveError::InvalidSshArgs);
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

/// The identity-key source offered under `Secret = IdentityKey`: a file
/// `Path` (typed) or pasted `Inline` contents (edited in the [`KeyPaste`]
/// popup). Cycled by `←`/`→` on the Source row. Mirrors [`SecretChoice`]'s
/// shape. Wired into both forms: [`CredForm`] (cred wizard) and [`HostForm`]
/// (host wizard's Independent branch). The cycling logic is exercised by the
/// unit tests below and by each form's `on_key` Source-cycle arms.
///
/// [`CredForm`]: cred::CredForm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceChoice {
    /// Identity key read from a file path (typed in the Identity row).
    Path,
    /// Identity key pasted as raw contents (edited in the [`KeyPaste`] popup;
    /// the form row is a trigger that opens it on `Enter`).
    Inline,
}

impl SourceChoice {
    /// Display order used by the chooser's `←`/`→` cycling.
    const ORDER: &'static [SourceChoice] = &[SourceChoice::Path, SourceChoice::Inline];

    fn idx(self) -> usize {
        Self::ORDER
            .iter()
            .position(|s| *s == self)
            .expect("invariant: every SourceChoice variant is in ORDER")
    }

    pub(crate) fn next(self) -> Self {
        Self::ORDER[(self.idx() + 1) % Self::ORDER.len()]
    }

    pub(crate) fn prev(self) -> Self {
        Self::ORDER[(self.idx() + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }

    /// One-word label shown in the chooser row.
    fn label(self) -> &'static str {
        match self {
            SourceChoice::Path => "Path",
            SourceChoice::Inline => "Inline",
        }
    }
}

/// The focused field in the credential form. `Tab`/`↑`/`↓` (and `Enter` to
/// advance, except on the inline-key trigger rows where `Enter` opens the
/// [`KeyPaste`] popup, inside which `Enter` inserts a newline) move through the
/// reachable ones in declaration order; the last reachable field's `Enter`
/// triggers a save. The secret row is a three-way mutex gated by
/// [`SecretChoice`]: under [`SecretChoice::None`] both `Identity` and
/// `Password` (and the Source/Inline rows) are hidden; under
/// [`SecretChoice::IdentityKey`] the `Source` chooser appears, and its current
/// value (`Path` vs `Inline`) decides whether `Identity` (Path) or
/// `InlinePrivate`+`InlineCert` (Inline) is reachable; under
/// [`SecretChoice::Password`] only `Password` is reachable. `SecretKind` (the
/// chooser) is always reachable. The form filters the unreachable slots at
/// navigation time via [`CredForm::reachable_fields`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredField {
    Name,
    User,
    Identity,
    SecretKind,
    /// Identity-key source chooser (Path vs Inline). Sits between the
    /// Secret-kind chooser and the slot rows so the form reads top-down:
    /// pick the kind, then the source, then fill the slot it exposes.
    /// Reachable iff secret == [`SecretChoice::IdentityKey`].
    Source,
    /// Inline private-key paste trigger row (Inline source only). Sits below
    /// `Source` and above `Identity` to mirror the Path/Inline slot layout.
    /// `Enter` opens the [`KeyPaste`] popup (modal); the form row itself holds
    /// only the line-count summary.
    InlinePrivate,
    /// Inline optional certificate paste trigger row (Inline source only).
    /// `Enter` opens the [`KeyPaste`] popup (modal); the form row itself holds
    /// only the line-count summary.
    InlineCert,
    /// Masked password input; reachable only under [`SecretChoice::Password`].
    Password,
}

impl CredField {
    /// Top-to-bottom render + navigation order. `SecretKind` (the chooser)
    /// precedes the secret-slot rows it gates so the form reads top-down: pick
    /// the kind, then the source, then fill the slot it exposes — mirroring
    /// [`Field::ORDER`]'s Independent layout, where `Secret` precedes
    /// `Identity` / `Password`. The slot rows are filtered out at navigation
    /// time by [`CredForm::reachable_fields`] according to the
    /// [`SecretChoice`] + [`SourceChoice`] matrix: under `None` everything
    /// below `SecretKind` is hidden, under `IdentityKey` the `Source` row
    /// appears and its value decides whether `Identity` (Path) or
    /// `InlinePrivate`+`InlineCert` (Inline) is reachable, under `Password`
    /// only `Password` shows. `SecretKind` itself is always reachable.
    const ORDER: &'static [CredField] = &[
        CredField::Name,
        CredField::User,
        CredField::SecretKind,
        CredField::Source,
        CredField::Identity,
        CredField::InlinePrivate,
        CredField::InlineCert,
        CredField::Password,
    ];

    fn label(self) -> &'static str {
        match self {
            CredField::Name => "Name",
            CredField::User => "User",
            CredField::Identity => "Identity",
            CredField::SecretKind => "Secret",
            CredField::Source => "Source",
            CredField::InlinePrivate => "Privkey",
            CredField::InlineCert => "Cert",
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
// Field-type affordance (shared row renderer)
// ============================================================================

/// How a wizard field is interacted with, independent of which form owns it.
/// Drives the type-affordance suffix appended by [`render_field_row`] so every
/// field — host or credential — renders through one path and reads the same:
///
/// - [`FieldKind::Text`] / [`FieldKind::Password`]: the terminal cursor (and,
///   for passwords, the `•••` mask) already self-describe "type here".
/// - [`FieldKind::Switch`]: the `< … >` brackets ([`bracketed`]) already
///   self-describe "cycle ←/→".
/// - [`FieldKind::Trigger`]: `Enter` opens a modal (file picker / fuzzy
///   credential picker). The ` ▸` suffix ([`TRIGGER_GLYPH`], accent)
///   advertises that — empty or filled.
/// - [`FieldKind::MultilineTrigger`]: `Enter` opens a multiline editor for
///   secret content never echoed inline. The ` ¶ ▸` suffix ([`MULTILINE_PARA`]
///   dim pilcrow + [`TRIGGER_GLYPH`] accent) says "hidden multi-line content
///   lives here; Enter to open".
///
/// The suffix lives at the right edge of the value column and is always
/// rendered when it fits, so a row's interaction type is visible at a glance
/// without focusing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FieldKind {
    Text,
    Password,
    Switch,
    Trigger,
    MultilineTrigger,
}

/// The triangle half of a trigger suffix: a leading space + a small accent
/// triangle (`U+25B8`). Means "Enter opens a modal". Reused as the trailing
/// half of the multiline-trigger suffix.
const TRIGGER_GLYPH: &str = " \u{25B8}";

/// The pilcrow half of the multiline-trigger suffix: a leading space + a dim
/// pilcrow (`U+00B6`). Means "hidden multi-line content lives here".
const MULTILINE_PARA: &str = " \u{00B6}";

/// Display-cell width a `kind`'s suffix consumes, so the renderer can reserve
/// exact space before truncating the value (the glyph is never clipped).
/// Derived from the same constants [`affordance_suffix`] builds its spans
/// from — single source of truth, pinned in sync by the
/// `affordance_suffix_glyphs_match_width` test.
pub(super) fn affordance_suffix_width(kind: FieldKind) -> usize {
    match kind {
        FieldKind::Text | FieldKind::Password | FieldKind::Switch => 0,
        FieldKind::Trigger => UnicodeWidthStr::width(TRIGGER_GLYPH),
        FieldKind::MultilineTrigger => {
            UnicodeWidthStr::width(MULTILINE_PARA) + UnicodeWidthStr::width(TRIGGER_GLYPH)
        }
    }
}

/// The styled suffix spans for a field kind (empty vec for text/password/
/// switch). Built from [`TRIGGER_GLYPH`] / [`MULTILINE_PARA`] so
/// [`affordance_suffix_width`] and the rendered spans can never disagree.
pub(super) fn affordance_suffix(kind: FieldKind) -> Vec<Span<'static>> {
    match kind {
        FieldKind::Text | FieldKind::Password | FieldKind::Switch => Vec::new(),
        FieldKind::Trigger => vec![Span::styled(TRIGGER_GLYPH.to_string(), theme::accent())],
        FieldKind::MultilineTrigger => vec![
            Span::styled(MULTILINE_PARA.to_string(), Style::new().dim()),
            Span::styled(TRIGGER_GLYPH.to_string(), theme::accent()),
        ],
    }
}

/// Column where the editable value begins within a rendered field row:
/// `"▶ "/"  " (2) + right-aligned label + ": " (2)`. A `const fn` so the
/// per-form value-column constants below derive from one definition.
pub(super) const fn value_col_offset(label_width: u16) -> u16 {
    2 + label_width + 2
}

/// Render one wizard field row through the single shared path: focus marker +
/// right-aligned label + value (or dim placeholder) + type-affordance suffix.
/// Pure; consumed by both [`HostForm::render_row`] and [`CredForm::render_row`]
/// so every field — host or credential — looks identical in shape; only the
/// label width, value/placeholder, and [`FieldKind`] differ.
///
/// The suffix width is reserved *before* truncating the value/placeholder, so
/// the glyph is always the last thing rendered and is never clipped by a long value.
///
/// [`HostForm::render_row`]: host::HostForm::render_row
/// [`CredForm::render_row`]: cred::CredForm::render_row
pub(super) fn render_field_row(
    label: &str,
    focused: bool,
    value: &str,
    placeholder: Option<&str>,
    kind: FieldKind,
    label_width: u16,
    row_width: u16,
) -> Line<'static> {
    let cursor = if focused { "▶ " } else { "  " };
    let label_span = Span::styled(
        format!("{cursor}{label:>WIDTH$}: ", WIDTH = label_width as usize),
        if focused {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            Style::new().dim()
        },
    );

    let suffix = affordance_suffix(kind);
    let value_col = (row_width.saturating_sub(value_col_offset(label_width))) as usize;
    let avail_for_value = value_col.saturating_sub(affordance_suffix_width(kind));
    let trunc_value = truncate_cells(value, avail_for_value);
    let trunc_ph = placeholder.map(|p| truncate_cells(p, avail_for_value));

    let mut spans = vec![label_span];
    spans.extend(value_spans(&trunc_value, trunc_ph.as_deref()));
    spans.extend(suffix);
    Line::from(spans).alignment(Alignment::Left)
}

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

/// Wrap a cycleable chooser's label in `< Label >` so the angle brackets
/// signal to the user that the value can be switched left/right. Used by the
/// Auth (Independent/Reference) and Secret (None/Password/IdentityKey) rows in
/// both forms. The caller passes the bare one-word label ([`SecretChoice::label`]
/// or a fixed `"Independent"` / `"Reference"`); this adds the brackets.
pub(super) fn bracketed(label: &str) -> String {
    format!("< {label} >")
}

/// Right-alignment width for a host field label. The longest host label is
/// `Credential` (10 chars), so this is 10; the credential-wizard labels stay
/// 8 ([`CRED_LABEL_WIDTH`]). Used by [`HostForm::render_row`] and to derive
/// [`HOST_VALUE_COL`] below.
pub(super) const HOST_LABEL_WIDTH: u16 = 10;

/// Right-alignment width for a credential field label. The longest cred label
/// is `Identity` / `Password` (8 chars). Kept narrower than
/// [`HOST_LABEL_WIDTH`] because the cred form has no 10-char `Credential` row.
pub(super) const CRED_LABEL_WIDTH: u16 = 8;

/// Column where the editable value begins within a rendered field row:
/// `"▶ " (2) + right-aligned label + ": " (2)`. Derived from
/// [`HOST_LABEL_WIDTH`] so the value column tracks the longest host label
/// (`Credential` = 10). Used by each form's `draw` to place the terminal
/// cursor and to truncate over-wide values.
pub(super) const HOST_VALUE_COL: u16 = value_col_offset(HOST_LABEL_WIDTH);

/// Credential-wizard counterpart of [`HOST_VALUE_COL`], derived from
/// [`CRED_LABEL_WIDTH`].
pub(super) const CRED_VALUE_COL: u16 = value_col_offset(CRED_LABEL_WIDTH);

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

/// Line count of an inline-key slot from the original (edit-mode) `KeySource`
/// when the secret is readable plaintext. `None` under vault mode (the secret
/// is encrypted and the view layer holds no key to decrypt) or when the slot
/// is absent. Used to echo "N line(s) saved" on the field row in edit mode
/// without ever surfacing the key text — a count-only read over the *original*
/// key, mirroring what `KeyPaste::saved_line_count` does for the live buffer.
pub(super) fn orig_inline_lines(orig: Option<&KeySource>, cert: bool) -> Option<usize> {
    let KeySource::Inline(ik) = orig? else {
        return None;
    };
    let sec = if cert {
        ik.certificate.as_ref()
    } else {
        ik.private_key.as_ref()
    };
    // `as_plain` is None for Encrypted (vault) — the count is only available
    // when the secret sits in plaintext the view can read.
    sec.and_then(|s| s.as_plain().map(|t| t.lines().count()))
}

/// Whether an inline-key slot exists on the original (edit-mode) `KeySource`,
/// regardless of whether it is readable. Drives the "saved · paste to replace"
/// fallback on the field row when [`orig_inline_lines`] is `None` (vault mode)
/// but the key is still there — so edit mode never reads as empty.
pub(super) fn orig_inline_exists(orig: Option<&KeySource>, cert: bool) -> bool {
    let Some(KeySource::Inline(ik)) = orig else {
        return false;
    };
    if cert {
        ik.certificate.is_some()
    } else {
        ik.private_key.is_some()
    }
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
        assert_eq!(Field::SshArgs.label(), "SSH args");
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

    // ---- label column width: derived from the longest host label (Task 7: RED -> GREEN) ----

    #[test]
    fn host_label_column_fits_the_longest_label() {
        // "Credential" is 10 chars — the column must be at least that wide so
        // every host row's value starts at the same x.
        assert_eq!("Credential".chars().count(), 10);
        assert!(HOST_LABEL_WIDTH as usize >= 10);
        assert_eq!(HOST_VALUE_COL, 2 + HOST_LABEL_WIDTH + 2);
        // Cred labels max out at "Identity" / "Password" = 8 chars; pin that
        // the cred column derives the same way and stays 8.
        assert_eq!("Identity".chars().count(), 8);
        assert_eq!(CRED_LABEL_WIDTH, 8);
        assert_eq!(CRED_VALUE_COL, 2 + CRED_LABEL_WIDTH + 2);
    }

    // ---- cred field order: Secret chooser renders ABOVE the slot rows it gates
    // (Task: regression pin) ----

    #[test]
    fn cred_secret_kind_row_precedes_identity_and_password() {
        // The Secret chooser must render above the secret-slot rows it gates, so
        // the form reads top-down: pick the kind, then fill the slot it exposes.
        // Mirrors HostForm's Independent layout, where `Secret` precedes
        // `Identity` / `Password`. Pin the relative order (not absolute index).
        let order = CredField::ORDER;
        let sk = order
            .iter()
            .position(|f| *f == CredField::SecretKind)
            .expect("SecretKind is in ORDER");
        let id = order
            .iter()
            .position(|f| *f == CredField::Identity)
            .expect("Identity is in ORDER");
        let pw = order
            .iter()
            .position(|f| *f == CredField::Password)
            .expect("Password is in ORDER");
        assert!(sk < id, "SecretKind must render above Identity");
        assert!(sk < pw, "SecretKind must render above Password");
    }

    // ---- SourceChoice: Path/Inline cycling + labels (Task 1: RED -> GREEN) ----

    #[test]
    fn source_choice_cycles_path_and_inline() {
        assert_eq!(SourceChoice::Path.next(), SourceChoice::Inline);
        assert_eq!(SourceChoice::Inline.next(), SourceChoice::Path);
        assert_eq!(SourceChoice::Inline.prev(), SourceChoice::Path);
    }

    #[test]
    fn source_choice_labels_are_capitalized() {
        assert_eq!(SourceChoice::Path.label(), "Path");
        assert_eq!(SourceChoice::Inline.label(), "Inline");
    }

    #[test]
    fn cred_field_order_puts_source_above_identity_and_password() {
        let order = CredField::ORDER;
        let src = order
            .iter()
            .position(|f| *f == CredField::Source)
            .expect("Source in ORDER");
        let id = order
            .iter()
            .position(|f| *f == CredField::Identity)
            .expect("Identity in ORDER");
        let privk = order
            .iter()
            .position(|f| *f == CredField::InlinePrivate)
            .expect("InlinePrivate in ORDER");
        assert!(src < id, "Source must render above Identity");
        assert!(src < privk, "Source must render above InlinePrivate");
    }

    // ---- field-type affordance suffix (shared render primitive) ----

    #[test]
    fn affordance_suffix_width_matches_kind() {
        assert_eq!(affordance_suffix_width(FieldKind::Text), 0);
        assert_eq!(affordance_suffix_width(FieldKind::Password), 0);
        assert_eq!(affordance_suffix_width(FieldKind::Switch), 0);
        assert_eq!(affordance_suffix_width(FieldKind::Trigger), 2);
        assert_eq!(affordance_suffix_width(FieldKind::MultilineTrigger), 4);
    }

    #[test]
    fn affordance_suffix_glyphs_match_width() {
        // The rendered spans (concatenated) must equal the width function's
        // accounting — single source of truth (the consts), no desync.
        fn concat(spans: &[Span<'_>]) -> String {
            spans.iter().map(|s| s.content.as_ref()).collect()
        }
        assert_eq!(concat(&affordance_suffix(FieldKind::Text)), "");
        assert_eq!(concat(&affordance_suffix(FieldKind::Password)), "");
        assert_eq!(concat(&affordance_suffix(FieldKind::Switch)), "");
        assert_eq!(concat(&affordance_suffix(FieldKind::Trigger)), " ▸");
        assert_eq!(
            concat(&affordance_suffix(FieldKind::MultilineTrigger)),
            " ¶ ▸"
        );
        // and that concatenated cell-width == affordance_suffix_width
        assert_eq!(
            unicode_width::UnicodeWidthStr::width(
                concat(&affordance_suffix(FieldKind::Trigger)).as_str()
            ),
            affordance_suffix_width(FieldKind::Trigger)
        );
        assert_eq!(
            unicode_width::UnicodeWidthStr::width(
                concat(&affordance_suffix(FieldKind::MultilineTrigger)).as_str()
            ),
            affordance_suffix_width(FieldKind::MultilineTrigger)
        );
    }

    #[test]
    fn value_col_offset_is_marker_plus_label_plus_colon() {
        assert_eq!(value_col_offset(0), 4);
        assert_eq!(value_col_offset(HOST_LABEL_WIDTH), HOST_VALUE_COL);
        assert_eq!(value_col_offset(CRED_LABEL_WIDTH), CRED_VALUE_COL);
    }

    #[test]
    fn render_field_row_text_has_no_suffix() {
        let line = render_field_row(
            "Name",
            true,
            "web",
            None,
            FieldKind::Text,
            HOST_LABEL_WIDTH,
            60,
        );
        // label span + value span only; no affordance suffix appended.
        assert_eq!(line.spans.len(), 2);
        assert_eq!(line.spans[1].content.as_ref(), "web");
    }

    #[test]
    fn render_field_row_switch_has_no_suffix() {
        // Switches self-describe via < … >; the suffix is empty for them.
        let line = render_field_row(
            "Auth",
            true,
            "< Independent >",
            None,
            FieldKind::Switch,
            HOST_LABEL_WIDTH,
            60,
        );
        let last: &str = line
            .spans
            .last()
            .expect("at least the value span")
            .content
            .as_ref();
        assert_eq!(last, "< Independent >");
    }

    #[test]
    fn render_field_row_trigger_appends_accent_triangle() {
        let line = render_field_row(
            "Identity",
            false,
            "/home/me/.ssh/id_ed25519",
            None,
            FieldKind::Trigger,
            HOST_LABEL_WIDTH,
            60,
        );
        let last = line.spans.last().expect("suffix present");
        assert_eq!(last.content.as_ref(), " ▸");
    }

    #[test]
    fn render_field_row_multiline_appends_pilcrow_then_triangle() {
        let line = render_field_row(
            "Privkey",
            false,
            "5 lines",
            None,
            FieldKind::MultilineTrigger,
            HOST_LABEL_WIDTH,
            60,
        );
        let spans = &line.spans;
        // last two spans are " ¶" (dim) and " ▸" (accent), in that order.
        assert_eq!(spans[spans.len() - 2].content.as_ref(), " ¶");
        assert_eq!(spans[spans.len() - 1].content.as_ref(), " ▸");
    }

    #[test]
    fn render_field_row_trigger_empty_value_still_shows_suffix_after_placeholder() {
        // Empty value + a placeholder: the suffix follows the dim placeholder,
        // advertising "this dim row IS interactive — Enter opens a modal".
        let line = render_field_row(
            "Identity",
            false,
            "",
            Some("browse for a private key"),
            FieldKind::Trigger,
            HOST_LABEL_WIDTH,
            60,
        );
        let last = line.spans.last().expect("suffix present");
        assert_eq!(last.content.as_ref(), " ▸");
    }

    #[test]
    fn render_field_row_reserves_suffix_so_long_value_truncates_not_the_glyph() {
        // Tight row_width so the value must truncate; the glyph must survive and
        // the line must never overflow row_width.
        let row_width: u16 = 22; // value_col_offset(10) = 14 → value_col = 8
        let line = render_field_row(
            "Identity",
            false,
            "/home/ryan/.ssh/id_ed25519", // 24 chars, cannot fit in 8 minus 2 suffix
            None,
            FieldKind::Trigger,
            HOST_LABEL_WIDTH,
            row_width,
        );
        let width = line.width();
        assert!(
            width <= row_width as usize,
            "line must not overflow the row: {width} > {row_width}"
        );
        assert_eq!(
            line.spans.last().expect("suffix present").content.as_ref(),
            " ▸",
            "glyph must survive value truncation"
        );
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

#[cfg(test)]
mod bracket_tests {
    //! Tests for the `bracketed` chooser-label wrapper. The Auth (Independent /
    //! Reference) and Secret (None / Password / IdentityKey) rows both render
    //! their current value as `< Label >` so the angle brackets signal that the
    //! value can be switched left/right.
    use super::bracketed;

    #[test]
    fn bracketed_wraps_label_with_spaced_angle_brackets() {
        assert_eq!(bracketed("Independent"), "< Independent >");
        assert_eq!(bracketed("Password"), "< Password >");
    }

    #[test]
    fn bracketed_empty_is_two_spaces() {
        // format!("< {label} >") with an empty label leaves two spaces between
        // the brackets. Pinned so a future refactor doesn't accidentally trim.
        assert_eq!(bracketed(""), "<  >");
    }
}
