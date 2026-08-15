//! Host add/edit wizard form. Pure view state over core's
//! `host::add_host` / `host::finalize_body`; the persist half lives in
//! [`super::super::app`] (`persist_host_save`).
//!
//! Auth strategies supported here:
//! - [`AuthChoice::Reference`] — reuse a `[[credentials]]` entry by name; the
//!   loop resolves the name to its stable [`Ulid`] before persisting
//!   (ref-by-id invariant).
//! - [`AuthChoice::Independent`] — inline (host-own) user plus an optional
//!   secret (None / Password / IdentityKey) chosen on the Secret row. An inline
//!   password is sealed per the configured store mode at save time (mirror of
//!   the credential wizard), so a host can carry its own password without
//!   forcing a detour to the credential tab. Under IdentityKey a Source chooser
//!   (Path / Inline) appears: Path types a key file path; Inline opens a modal
//!   [`KeyPaste`] popup over the form when the user presses `Enter` on the
//!   Privkey / Cert rows — the same inline paste surface the credential wizard
//!   has, mirrored onto the Independent branch. The Reference branch and the
//!   credential picker are untouched by the popup (it is Independent-only).

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::super::intent::Outcome;
use super::super::theme;
use super::{
    AuthChoice, AuthKind, CredPicker, Field, FieldKind, HOST_LABEL_WIDTH, HOST_VALUE_COL, KeyPaste,
    PasteKind, PasteOutcome, PickerOutcome, SaveError, SecretChoice, SourceChoice, backspace_at,
    bracketed, insert_char_at, orig_inline_exists, orig_inline_lines, render_field_row, validate,
};
use crate::tui::file_picker::{FilePicker, FilePickerOutcome};
use sshrack_core::config::schema::{Auth, CredentialBody, Host, KeySource};
use sshrack_core::dirsource::LocalDirSource;

/// The host form's editable state. All text fields are owned `String`s; the
/// password is `Zeroizing` so it is wiped on drop. The wizard builds this empty
/// (add mode) or prefilled from an existing [`Host`] (edit mode).
#[derive(Clone)]
pub struct HostForm {
    /// Editable host name.
    pub name: String,
    /// Editable host address.
    pub host_addr: String,
    /// Editable port (kept as a string so the user can clear / retype it; parsed
    /// at save time). Empty string falls back to the ssh default (22).
    pub port: String,
    /// Inline login user. Used only under Independent (Reference pulls the user
    /// from the referenced credential). Empty falls back to "root" at save.
    pub user: String,
    /// The selected auth strategy + (for Reference) the chosen credential index.
    pub auth_choice: AuthChoice,
    /// Secret kind for the Independent branch (None / Password / IdentityKey).
    /// Ignored under Reference.
    pub secret_kind: SecretChoice,
    /// Identity-key source (Path | Inline), cycled by `←`/`→` on the Source
    /// row. Relevant only under [`AuthChoice::Independent`] +
    /// [`SecretChoice::IdentityKey`]; ignored (and stays
    /// [`SourceChoice::Path`]) under Reference and under Password / None.
    pub source: SourceChoice,
    /// Identity-key path, edited when the secret choice is
    /// [`SecretChoice::IdentityKey`] AND the source is [`SourceChoice::Path`].
    /// Empty under the Inline source (the key text lives in
    /// [`HostForm::inline_private`]).
    pub identity: String,
    /// Multiline private-key paste buffer, written back from the [`KeyPaste`]
    /// popup when the user closes it with a non-blank buffer. Always empty on
    /// edit-entry (the existing key text is NEVER echoed back — security;
    /// [`HostForm::build_inline_body`] preserves the original on save when this
    /// stays blank). A plain `String` because the form body no longer renders an
    /// editor — editing happens only in the popup.
    pub inline_private: String,
    /// Multiline optional certificate paste buffer, written back from the
    /// [`KeyPaste`] popup. Companion to [`HostForm::inline_private`]: same
    /// lifecycle, always empty on edit-entry, edited only under Inline source.
    pub inline_cert: String,
    /// Masked password, edited when secret_kind is Password. `Zeroizing` so it
    /// is wiped on drop; never echoed back from an existing host (edit re-types).
    pub password: Zeroizing<String>,
    /// Currently focused field.
    pub focus: Field,
    /// Char-index cursor within the focused text field. Reset to the focused
    /// field's end on focus change; clamped on read by [`cursor_target`].
    /// Irrelevant for the Auth / Secret / Source choosers and the multiline
    /// paste fields (the [`KeyPaste`] popup owns its own cursor while open).
    pub(super) cursor: usize,
    /// A transient validation error to show under the bad field. Cleared on the
    /// next edit to that field. Set by `on_key` when a save attempt fails
    /// [`validate`](super::validate).
    pub error: Option<SaveError>,
    /// A core-level error surfaced by the loop after a persist attempt failed
    /// (duplicate name, dangling credential, write error). Distinct from
    /// [`error`](Self::error) because pure `validate` already passed by the
    /// time this is set. Cleared on the next keystroke.
    pub core_error: Option<String>,
    /// Whether the wizard is editing an existing host (vs adding a new one). Add
    /// mode persists via `host::add_host` with a fresh id; edit mode preserves
    /// the original id (keyring-keyed) via `host::finalize_body`.
    pub editing: bool,
    /// The original host's id, carried in edit mode so the loop can stamp it
    /// onto the patched host (preserving the keyring entry). `None` in add mode.
    pub orig_id: Option<Ulid>,
    /// The credential names offered by the Reference chooser, in order. The
    /// wizard never resolves these to ids itself — the loop does, at save time.
    pub credential_names: Vec<String>,
    /// Open fuzzy credential picker (Reference branch). `None` when closed.
    /// When open, `on_key` routes every key into the picker before the form,
    /// and `draw_in_dialog` paints the picker overlay over the wizard.
    pub cred_picker: Option<CredPicker>,
    /// The original body's [`KeySource`] when the host's inline auth carried a
    /// key at edit time. Under the Inline source the paste buffers start EMPTY
    /// (the key text is never echoed); [`HostForm::build_inline_body`] re-attaches
    /// this verbatim when the private field stays blank, so silently dropping it
    /// never destroys the host's only secret. `None` in add mode, under
    /// Reference, and when the original had no key.
    pub orig_key: Option<KeySource>,
    /// The modal inline-key paste popup, open while the user edits the
    /// `InlinePrivate` / `InlineCert` slot. `None` when closed. Routed at the
    /// top of [`HostForm::on_key`] (modal — swallows every key while open,
    /// including `Ctrl-S`, like the cred picker above it).
    pub key_paste: Option<KeyPaste>,
    /// Modal file picker for the Identity path (Path source). `None` when
    /// closed. Routed at the top of [`HostForm::on_key`] (modal — swallows
    /// every key while open, incl `Ctrl-S`, like the cred picker / paste
    /// popup). The picker is a reusable component ([`crate::tui::file_picker`])
    /// that does NOT import this module; it returns the chosen absolute path
    /// via [`FilePickerOutcome::Pick`]. Directory listing is injected via
    /// [`LocalDirSource`] now; a future `SftpDirSource` reuses the picker.
    pub file_picker: Option<FilePicker<LocalDirSource>>,
}

impl std::fmt::Debug for HostForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the password — mirrors CredForm's redacting Debug so a
        // format!("{:?}", form) / dbg!(form) can never leak plaintext.
        // `identity` holds a key file *path*, not key material, so it is safe.
        // `orig_key` delegates to `KeySource`'s redacting `Debug`, which
        // surfaces the path but redacts inline key text.
        //
        // The two inline-paste buffers are NEVER surfaced directly: a raw
        // `String` Debug would print the pasted private key / certificate to
        // any `dbg!(form)` / `format!("{form:?}")` call. Surface ONLY their
        // line count, so a glance at the form's Debug still tells you whether
        // the user has pasted anything without ever showing what.
        f.debug_struct("HostForm")
            .field("name", &self.name)
            .field("host_addr", &self.host_addr)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("auth_choice", &self.auth_choice)
            .field("secret_kind", &self.secret_kind)
            .field("source", &self.source)
            .field("identity", &self.identity)
            .field("inline_private_lines", &self.inline_private.lines().count())
            .field("inline_cert_lines", &self.inline_cert.lines().count())
            .field("password", &"<redacted>")
            .field("focus", &self.focus)
            .field("error", &self.error)
            .field("core_error", &self.core_error)
            .field("editing", &self.editing)
            .field("orig_id", &self.orig_id)
            .field("cred_picker", &self.cred_picker)
            .field("credential_names", &self.credential_names)
            .field("orig_key", &self.orig_key)
            .field("file_picker", &self.file_picker.is_some())
            .finish()
    }
}

impl HostForm {
    /// Fresh add-mode form: Independent + None (zero-config default), focus Name.
    /// `credential_names` seeds the Reference chooser.
    pub fn new_add(credential_names: Vec<String>) -> Self {
        let mut form = Self {
            name: String::new(),
            host_addr: String::new(),
            port: String::new(),
            user: String::new(),
            auth_choice: AuthChoice::Independent,
            secret_kind: SecretChoice::None,
            source: SourceChoice::Path,
            identity: String::new(),
            inline_private: String::new(),
            inline_cert: String::new(),
            password: Zeroizing::new(String::new()),
            focus: Field::Name,
            cursor: 0,
            error: None,
            core_error: None,
            editing: false,
            orig_id: None,
            credential_names,
            cred_picker: None,
            orig_key: None,
            key_paste: None,
            file_picker: None,
        };
        form.cursor = form.focused_text_len();
        form
    }

    /// Edit-mode form prefilled from `host`. Reference → `Reference{idx}` (the
    /// chooser prefills the referenced credential's current name); Inline →
    /// Independent + secret_kind derived from the body. The password is NEVER
    /// carried into the form: the user re-types to change it, and leaving the
    /// field empty on a Password-kind edit keeps the existing secret (handled by
    /// the loop at save time, mirroring CredForm).
    ///
    /// **Source + identity prefill.** Under an Inline auth body with a key, the
    /// source chooser opens reflecting the original: [`SourceChoice::Path`] with
    /// `identity` prefilled from the path, or [`SourceChoice::Inline`] with
    /// `identity` left blank (the key text is NEVER echoed into the paste buffer
    /// — security). The original [`KeySource`] is carried as `orig_key`
    /// regardless, so [`build_inline_body`](Self::build_inline_body) can re-attach
    /// an inline original verbatim when the user does not paste a new key —
    /// silently dropping it would destroy the host's only secret. The two inline
    /// paste buffers always start EMPTY on edit entry, even when the original was
    /// inline material; the user pastes a NEW key (via the [`KeyPaste`] popup) to
    /// replace it, or leaves the private field blank to keep the original.
    pub fn new_edit(
        host: &Host,
        credential_names: Vec<String>,
        referenced_credential_name: Option<&str>,
    ) -> Self {
        let (auth_choice, user, secret_kind, source, identity, orig_key) = match &host.auth {
            Auth::Ref { .. } => {
                // Match the referenced credential's current name in the chooser
                // list. unwrap_or(0) only fires when the referenced credential
                // was deleted between sessions (name no longer present).
                let idx = referenced_credential_name
                    .and_then(|name| credential_names.iter().position(|n| n == name))
                    .unwrap_or(0);
                (
                    AuthChoice::Reference { idx },
                    String::new(),
                    SecretChoice::None,
                    SourceChoice::Path,
                    String::new(),
                    None,
                )
            }
            Auth::Inline(body) => {
                use sshrack_core::config::schema::SecretKind;
                let u = body.user.clone();
                let orig_key = body.key.clone();
                let (sk, src, iden) = match body.secret_kind() {
                    SecretKind::Key => {
                        let (src, iden) = match body.key.as_ref() {
                            Some(KeySource::Path(p)) => {
                                (SourceChoice::Path, p.to_string_lossy().into_owned())
                            }
                            // Inline original: default to Inline so the user
                            // can paste a NEW key (the old text is never
                            // echoed); orig_key preserves it on save when the
                            // private field stays blank.
                            Some(KeySource::Inline(_)) => (SourceChoice::Inline, String::new()),
                            None => (SourceChoice::Path, String::new()),
                        };
                        (SecretChoice::IdentityKey, src, iden)
                    }
                    SecretKind::Password | SecretKind::KeyringPassword => {
                        (SecretChoice::Password, SourceChoice::Path, String::new())
                    }
                    SecretKind::Default => (SecretChoice::None, SourceChoice::Path, String::new()),
                };
                (AuthChoice::Independent, u, sk, src, iden, orig_key)
            }
        };
        let mut form = Self {
            name: host.name.clone(),
            host_addr: host.host.clone(),
            port: host.port.to_string(),
            user,
            auth_choice,
            secret_kind,
            source,
            identity,
            // Inline paste buffers ALWAYS start empty on edit entry. An inline
            // original's key text is never echoed back (security); the user
            // pastes a new key to replace it, or leaves the private field blank
            // so build_inline_body re-attaches the original.
            inline_private: String::new(),
            inline_cert: String::new(),
            // Never carry the existing plaintext into the form: a password is
            // not echoed back. The user re-types to set a new one; leaving the
            // field empty on a Password-kind edit keeps the existing secret.
            password: Zeroizing::new(String::new()),
            focus: Field::Name,
            cursor: 0,
            error: None,
            core_error: None,
            editing: true,
            orig_id: Some(host.id),
            credential_names,
            cred_picker: None,
            orig_key,
            key_paste: None,
            file_picker: None,
        };
        form.cursor = form.focused_text_len();
        form
    }

    /// Advance the auth chooser by `delta` (signed), wrapping. Pure. Does not
    /// move focus — a toggle leaves the caller on the Auth row, so the user
    /// drives any further navigation (Tab to Credential, etc.) themselves.
    fn cycle_auth(&mut self, delta: i32) {
        let cur_kind = self.auth_choice.kind();
        let order = AuthChoice::ORDER;
        let cur_pos = order
            .iter()
            .position(|k| *k == cur_kind)
            .expect("invariant: every AuthChoice variant is in ORDER");
        let next_pos = (cur_pos as i32 + delta).rem_euclid(order.len() as i32) as usize;
        let next_kind = order[next_pos];
        self.auth_choice = match next_kind {
            AuthKind::Independent => AuthChoice::Independent,
            AuthKind::Reference => {
                // Keep the existing credential index, clamped to the list.
                let prev_idx = match self.auth_choice {
                    AuthChoice::Reference { idx } => idx,
                    _ => 0,
                };
                let idx = if self.credential_names.is_empty() {
                    0
                } else {
                    prev_idx.min(self.credential_names.len() - 1)
                };
                AuthChoice::Reference { idx }
            }
        };
    }

    /// Advance the credential chooser by `delta` (signed), wrapping around the
    /// credential list. No-op when there are no credentials or the form is not
    /// in the Reference branch. Pure; the loop never reaches this under
    /// Independent (the Credential row is unreachable there).
    fn cycle_credential(&mut self, delta: i32) {
        let AuthChoice::Reference { idx } = self.auth_choice else {
            return;
        };
        let n = self.credential_names.len();
        if n == 0 {
            return;
        }
        let next = (idx as i32 + delta).rem_euclid(n as i32) as usize;
        self.auth_choice = AuthChoice::Reference { idx: next };
    }

    /// The currently-selected credential name, if Reference and idx in range.
    pub fn selected_credential_name(&self) -> Option<&str> {
        match self.auth_choice {
            AuthChoice::Reference { idx } => self.credential_names.get(idx).map(String::as_str),
            _ => None,
        }
    }

    /// The port to persist: the parsed `port` string, or the ssh default (22)
    /// when blank or unparseable. Used by the loop when building the Host.
    pub fn parsed_port(&self) -> u16 {
        self.port.trim().parse::<u16>().unwrap_or(22)
    }

    /// Build the inline [`CredentialBody`] for the Independent branch. Pure.
    /// A non-empty Password field attaches a plaintext password; the loop seals
    /// it per the store mode after this. An empty Password field leaves the body
    /// without a password (the loop preserves the existing password in edit
    /// mode). A None id / empty user falls back to "root".
    ///
    /// **IdentityKey routing.** The Source chooser picks how the key is
    /// supplied (mirror of [`CredForm::build_body`]):
    /// - **Path** — `identity` non-empty → `with_key(path)`; blank + an inline
    ///   original → preserve that inline material verbatim (data safety — never
    ///   destroy the host's only secret just because the path field is empty);
    ///   blank with no inline original → no key.
    /// - **Inline** — the private paste buffer becomes an inline key via
    ///   [`CredentialBody::with_inline_key`], with the cert buffer attached only
    ///   when non-empty. A blank private field on edit preserves the original
    ///   inline material verbatim (the buffer is NEVER prefilled with key text
    ///   on edit-entry — security; this rule is the only thing standing between
    ///   the user and silently losing their key).
    ///
    /// [`CredForm::build_body`]: super::cred::CredForm::build_body
    fn build_inline_body(&self) -> CredentialBody {
        use sshrack_core::config::schema::Secret;
        let user = if self.user.trim().is_empty() {
            "root".to_string()
        } else {
            self.user.clone()
        };
        match self.secret_kind {
            SecretChoice::None => CredentialBody::new(user),
            SecretChoice::IdentityKey => {
                let mut body = CredentialBody::new(user);
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
            SecretChoice::Password => {
                let pw = self.password.as_str();
                if pw.is_empty() {
                    CredentialBody::new(user)
                } else {
                    CredentialBody::new(user).with_password(pw)
                }
            }
        }
    }

    /// Build the core [`Auth`] for this form, given the resolved credential id
    /// (if any). Pure. A None id for a Reference choice falls back to an inline
    /// default body (the loop will have already failed validation before
    /// reaching here in the real path, but this keeps the function total).
    pub fn build_auth(&self, resolved_credential: Option<Ulid>) -> Auth {
        match self.auth_choice {
            AuthChoice::Reference { .. } => match resolved_credential {
                Some(id) => Auth::reference(id),
                None => Auth::inline(CredentialBody::new(if self.user.trim().is_empty() {
                    "root".into()
                } else {
                    self.user.clone()
                })),
            },
            AuthChoice::Independent => Auth::inline(self.build_inline_body()),
        }
    }

    /// Set a core-level persist error (from the loop). Shown in the error line
    /// alongside a pure-validation error; cleared on the next keystroke.
    pub fn set_core_error(&mut self, msg: String) {
        self.core_error = Some(msg);
    }

    /// The ordered list of fields the user can navigate to, given the current
    /// auth + secret + source state. See [`HostForm::field_reachable`] for the
    /// predicate.
    fn reachable_fields(&self) -> Vec<Field> {
        Field::ORDER
            .iter()
            .copied()
            .filter(|&f| Self::field_reachable(f, &self.auth_choice, self.secret_kind, self.source))
            .collect()
    }

    /// Whether `field` is reachable under the given `(auth, secret, source)`
    /// state. Pure (takes no `&self`) so [`body_rows`](HostForm::body_rows) can
    /// sweep every auth×secret×source combination to size the dialog to its
    /// stable worst-case height without cloning the form.
    ///
    /// The matrix mirrors the wizard's top-down reading:
    /// - **Reference** — only Name / Host / Port / Auth / Credential are
    ///   reachable (the user + secret come from the referenced credential). The
    ///   Source / Identity / Inline* / Password rows are all unreachable.
    /// - **Independent + None** — Name / Host / Port / Auth / User / Secret
    ///   (no secret slot, no Source chooser).
    /// - **Independent + Password** — adds Password (no Source / Identity /
    ///   Inline rows).
    /// - **Independent + IdentityKey + Path** — adds Source + Identity (the
    ///   Source chooser appears; the single Identity path-slot is filled).
    /// - **Independent + IdentityKey + Inline** — adds Source + InlinePrivate +
    ///   InlineCert (Identity is hidden; the two paste areas replace it).
    fn field_reachable(
        field: Field,
        auth: &AuthChoice,
        secret: SecretChoice,
        source: SourceChoice,
    ) -> bool {
        match auth {
            AuthChoice::Reference { .. } => matches!(
                field,
                Field::Name | Field::Host | Field::Port | Field::Auth | Field::Credential
            ),
            AuthChoice::Independent => match secret {
                SecretChoice::None => !matches!(
                    field,
                    Field::Credential
                        | Field::Source
                        | Field::Identity
                        | Field::InlinePrivate
                        | Field::InlineCert
                        | Field::Password
                ),
                SecretChoice::Password => !matches!(
                    field,
                    Field::Credential
                        | Field::Source
                        | Field::Identity
                        | Field::InlinePrivate
                        | Field::InlineCert
                ),
                SecretChoice::IdentityKey => match source {
                    SourceChoice::Path => !matches!(
                        field,
                        Field::Credential
                            | Field::Password
                            | Field::InlinePrivate
                            | Field::InlineCert
                    ),
                    SourceChoice::Inline => {
                        !matches!(field, Field::Credential | Field::Password | Field::Identity)
                    }
                },
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
    fn is_last_reachable(&self, field: Field) -> bool {
        self.reachable_fields().last().copied() == Some(field)
    }

    /// Pure key decision: mutate form state and return an [`Outcome`]. Performs
    /// **no I/O** — the loop runs [`validate`] + persist only when this signals
    /// [`Outcome::SaveHost`].
    ///
    /// Bindings:
    /// - printable char / `Backspace` → edit the focused text field at the
    ///   in-field cursor (name, host, port, user, identity when secret_kind is
    ///   IdentityKey + Path, password when secret_kind is Password).
    /// - `←`/`→`/`Home`/`End` (and `Ctrl-A`/`Ctrl-E`) → move the in-field cursor
    ///   on text fields; clamped to the field's char length.
    /// - `Tab` / `↓` → next reachable field; `Shift-Tab` / `↑` → previous.
    /// - `Enter` → next reachable field, or — on the last reachable field —
    ///   attempt save (validate then signal [`Outcome::SaveHost`]); on
    ///   validation error set `error` and move focus to the bad field. On the
    ///   inline-key rows (`InlinePrivate` / `InlineCert`) `Enter` instead opens
    ///   the [`KeyPaste`] popup (modal — see the route at the top).
    /// - `Ctrl-S` → attempt save from any field.
    /// - `←`/`→` on the auth row → cycle Independent / Reference.
    /// - `←`/`→` on the secret row → cycle None / Password / IdentityKey.
    /// - `←`/`→` on the Source row (Independent + IdentityKey only) → cycle
    ///   Path / Inline.
    /// - `Enter` on the Credential row → open the fuzzy credential picker
    ///   (Reference only). While the picker is open it is modal: every key
    ///   routes into it, `Enter` writes the chosen index back to
    ///   `AuthChoice::Reference { idx }`, `Esc`/`Ctrl-C` close without changing
    ///   the selection.
    /// - While the [`KeyPaste`] popup is open every key is routed into it
    ///   (modal — it swallows `Ctrl-S`, `Tab`, etc.); close it with `Esc`
    ///   (writes the buffer back when non-blank) or `Ctrl-C` (discard) before
    ///   the form sees another key.
    /// - `Esc` / `Ctrl-C` → cancel back to the launcher (when no popup is
    ///   open).
    ///
    /// [`validate`]: super::validate
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        // Any keystroke clears a stale core-level error.
        self.core_error = None;

        // An open credential picker is modal: route every key into it before
        // the form. `take()` so we can write back to `cred_picker` /
        // `auth_choice` without fighting the borrow the picker would otherwise
        // hold on `cred_picker`; on Pending the still-open picker goes back.
        // Selected writes the chosen credential index back and closes; Cancel
        // just closes.
        // Swallows every key while open, incl Ctrl-S — close (Esc/Enter) before ^s can save.
        if let Some(mut picker) = self.cred_picker.take() {
            match picker.on_key(key) {
                PickerOutcome::Selected { idx } => {
                    self.auth_choice = AuthChoice::Reference { idx };
                }
                PickerOutcome::Cancel => {}
                PickerOutcome::Pending => self.cred_picker = Some(picker),
            }
            self.error = None;
            return Outcome::Continue;
        }

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

        // An open file picker is modal (same shape as the cred picker / paste
        // popup above): route every key into it before the form. Pick writes the
        // chosen absolute path back to `identity` and closes; Cancel just closes.
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
            KeyCode::Tab | KeyCode::Down if !ctrl => {
                self.move_focus(1);
                Outcome::Continue
            }
            KeyCode::BackTab | KeyCode::Up if !ctrl => {
                self.move_focus(-1);
                Outcome::Continue
            }
            KeyCode::Enter => {
                // The Credential row is a trigger: Enter opens the fuzzy picker
                // (only when there is at least one credential to pick). It never
                // advances focus or saves from here.
                if self.focus == Field::Credential {
                    if !self.credential_names.is_empty() {
                        // Land the cursor on the currently-selected credential
                        // (if any) so re-opening the picker on an existing
                        // reference does not jump back to the first name.
                        let initial = match self.auth_choice {
                            AuthChoice::Reference { idx } => Some(idx),
                            AuthChoice::Independent => None,
                        };
                        self.cred_picker = Some(CredPicker::new(&self.credential_names, initial));
                    }
                    self.error = None;
                    return Outcome::Continue;
                }
                // Inline key paste trigger rows: open the popup. Guarded by
                // reachability so a forced focus onto an Inline row under the
                // Reference branch (where they are unreachable) never opens the
                // popup — the inline editor is Independent-only by contract.
                // (Enter inside the popup inserts a newline; the popup is modal.)
                if matches!(self.focus, Field::InlinePrivate | Field::InlineCert)
                    && Self::field_reachable(
                        self.focus,
                        &self.auth_choice,
                        self.secret_kind,
                        self.source,
                    )
                {
                    let (kind, existing_lines) = match self.focus {
                        Field::InlinePrivate => (
                            PasteKind::Private,
                            KeyPaste::saved_line_count(&self.inline_private),
                        ),
                        Field::InlineCert => (
                            PasteKind::Cert,
                            KeyPaste::saved_line_count(&self.inline_cert),
                        ),
                        // Guarded by the matches! above.
                        _ => unreachable!("invariant: focus is InlinePrivate/InlineCert"),
                    };
                    self.key_paste = Some(KeyPaste::new(kind, existing_lines));
                    self.error = None;
                    return Outcome::Continue;
                }
                // Identity row is a trigger (Path source): Enter opens the file
                // picker. Guarded by reachability so it only opens when the
                // Identity path-slot is actually present (Independent +
                // IdentityKey + Path). The picker is modal; Enter inside it
                // activates a selection (handled by the modal route above).
                if self.focus == Field::Identity
                    && Self::field_reachable(
                        self.focus,
                        &self.auth_choice,
                        self.secret_kind,
                        self.source,
                    )
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
            // Auth row: ←/→ cycle Independent/Reference.
            KeyCode::Left if self.focus == Field::Auth => {
                self.cycle_auth(-1);
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right if self.focus == Field::Auth => {
                self.cycle_auth(1);
                self.error = None;
                Outcome::Continue
            }
            // Credential row: ←/→ cycle the chosen credential inline
            // (Reference); Enter opens the fuzzy picker when there are many.
            KeyCode::Left if self.focus == Field::Credential => {
                self.cycle_credential(-1);
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right if self.focus == Field::Credential => {
                self.cycle_credential(1);
                self.error = None;
                Outcome::Continue
            }
            // Secret row: ←/→ cycle None / Password / IdentityKey (Independent).
            KeyCode::Left if self.focus == Field::Secret => {
                self.secret_kind = self.secret_kind.prev();
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right if self.focus == Field::Secret => {
                self.secret_kind = self.secret_kind.next();
                self.error = None;
                Outcome::Continue
            }
            // Source row: ←/→ cycle Path / Inline. Only relevant under
            // Independent + IdentityKey (Source is unreachable otherwise), but
            // the guard is defensive against a directly-set focus in tests.
            KeyCode::Left
                if self.focus == Field::Source
                    && self.auth_choice == AuthChoice::Independent
                    && self.secret_kind == SecretChoice::IdentityKey =>
            {
                self.source = self.source.prev();
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right
                if self.focus == Field::Source
                    && self.auth_choice == AuthChoice::Independent
                    && self.secret_kind == SecretChoice::IdentityKey =>
            {
                self.source = self.source.next();
                self.error = None;
                Outcome::Continue
            }
            // Text fields: ←/→ move the in-field cursor; Home/End jump.
            // (Chooser rows are handled by the arms above. The inline-key rows
            // never reach here for cursor editing: they open the KeyPaste popup
            // on Enter, and ←/→ on them is a no-op cursor move on a non-text
            // field — harmless.)
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
    /// char). Auth / Credential / Secret / Source are chooser rows driven by
    /// `←`/`→`; the Password field only accepts input when secret_kind is
    /// Password. The inline-key rows (InlinePrivate / InlineCert) are NEVER
    /// edited through this char-based path — [`on_key`](Self::on_key) opens the
    /// [`KeyPaste`] popup on `Enter`, and the popup owns the multiline editing
    /// — so those arms are no-ops here, reached only if a future caller bypasses
    /// the popup.
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
            Field::Password if self.secret_kind == SecretChoice::Password => {
                self.cursor = insert_char_at(&mut self.password, self.cursor, c)
            }
            // No char-based text entry on these rows: Auth / Credential / Secret
            // / Source are ←/→ choosers (Credential also takes Enter for the
            // picker); InlinePrivate / InlineCert are edited via the KeyPaste
            // popup (opened on Enter in `on_key`); Identity is a trigger row
            // (Enter opens the FilePicker overlay, which writes the chosen
            // path back). None of these ever call this char-based path.
            Field::Auth
            | Field::Credential
            | Field::Secret
            | Field::Source
            | Field::Identity
            | Field::InlinePrivate
            | Field::InlineCert
            | Field::Password => {}
        }
        if Some(self.focus) == self.error.map(SaveError::field) {
            self.error = None;
        }
    }

    /// Delete the char immediately before the in-field cursor (mirror of
    /// [`edit_focused_insert`]). No-op when the cursor is already at the start.
    /// As with [`edit_focused_insert`], the inline-key rows handle editing via
    /// the [`KeyPaste`] popup; their arms here are unreachable no-ops.
    fn edit_focused_backspace(&mut self) {
        match self.focus {
            Field::Name => self.cursor = backspace_at(&mut self.name, self.cursor),
            Field::Host => self.cursor = backspace_at(&mut self.host_addr, self.cursor),
            Field::Port => self.cursor = backspace_at(&mut self.port, self.cursor),
            Field::User => self.cursor = backspace_at(&mut self.user, self.cursor),
            Field::Password if self.secret_kind == SecretChoice::Password => {
                self.cursor = backspace_at(&mut self.password, self.cursor)
            }
            // See `edit_focused_insert`: the inline-key rows edit via the
            // KeyPaste popup, not char-by-char; Identity edits via the FilePicker.
            Field::Auth
            | Field::Credential
            | Field::Secret
            | Field::Source
            | Field::Identity
            | Field::InlinePrivate
            | Field::InlineCert
            | Field::Password => {}
        }
        if Some(self.focus) == self.error.map(SaveError::field) {
            self.error = None;
        }
    }

    /// Run [`validate`](super::validate); on success signal save, on failure set
    /// the error and move focus to the bad field.
    fn attempt_save(&mut self) -> Outcome {
        match validate(self) {
            Ok(()) => Outcome::SaveHost,
            Err(e) => {
                self.error = Some(e);
                self.focus = e.field();
                Outcome::Continue
            }
        }
    }

    /// The field-specific hotkey hint for `field`. Field-specific ONLY — the
    /// permanent dialog footer already shows `Tab field · ^s save · Esc
    /// cancel`, so those are intentionally not repeated here. Chooser rows
    /// (Auth / Credential / Secret / Source) advertise their own `←`/`→`
    /// cycling (and `Enter` for the credential picker); the inline-key paste
    /// rows advertise `Enter` opens the multiline popup; other text rows get a
    /// light navigation hint. Pure; extracted from `draw_in_dialog` so the hint
    /// wording is unit-testable.
    fn hint_for_focus(&self, field: Field) -> &'static str {
        match field {
            Field::Auth => "  <- -> cycle Independent/Reference",
            Field::Credential => "  <- -> cycle  ·  Enter pick credential",
            Field::Secret => "  <- -> cycle None/Password/IdentityKey",
            Field::Source => "  <- -> cycle Path/Inline",
            Field::InlinePrivate | Field::InlineCert => "  Enter edit multiline",
            Field::Identity => "  Enter browse files",
            _ => "  up/down next field",
        }
    }

    /// Render the field rows + error/hint lines into `body` (the rect a
    /// [`crate::tui::dialog::draw_dialog`] hands the form), then — when the
    /// [`KeyPaste`] popup is open — paint it over the form. No outer border —
    /// the dialog already drew the chrome.
    ///
    /// The body is split into three vertical segments: `list_area` holds the
    /// single-line field rows (Length = visible row count), and `error_area` /
    /// `hint_area` are the fixed 1-row tail. The inline-key rows
    /// (`InlinePrivate` / `InlineCert`) are NOT edited in-place — `Enter`
    /// opens the [`KeyPaste`] popup, which is painted last so it sits on top of
    /// the form (modal). [`crate::tui::fit::focus_window`] windows only the
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

        let hint = self.hint_for_focus(self.focus);
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);

        // Place the real terminal cursor on the focused text field (no drawn
        // glyph — see CredForm::draw_in_dialog). Auth / Secret / Credential /
        // Source are choosers; the inline-key rows return `None` (the KeyPaste
        // popup owns its own cursor while open) — so the guard skips them and
        // we never double-set the cursor over the popup. The row index is
        // translated into the viewport so the cursor never points below the
        // list area when the list scrolls.
        if let Some((row, offset)) = self.cursor_target()
            && win.start <= row
            && row < win.end
        {
            let in_win_row = row - win.start;
            let max_x = list_area.x + list_area.width.saturating_sub(1);
            let x = (list_area.x + HOST_VALUE_COL + offset as u16).min(max_x);
            let y = list_area.y + in_win_row as u16;
            frame.set_cursor_position((x, y));
        }

        // If the credential picker is open, paint it over the wizard. Drawn last
        // so it sits on top, and after the wizard's own cursor placement so the
        // picker's query-box cursor wins.
        if let Some(picker) = &self.cred_picker {
            picker.draw_overlay(frame);
        }

        // If the inline-key paste popup is open, paint it over the wizard.
        // Drawn after the wizard's own cursor placement so the popup's cursor
        // wins. Both overlays can coexist in code, but only one is open at a
        // time: opening the paste popup requires `focus` on an Inline row,
        // which is unreachable under the Reference branch where the picker
        // opens.
        if let Some(paste) = &self.key_paste {
            paste.draw_overlay(frame);
        }

        // If the file picker is open, paint it over the wizard (last, so it
        // sits on top of the form and any other overlay; only one is open at a
        // time — the picker opens from the Identity row, the cred picker from
        // the Credential row, the paste popup from the Inline rows).
        if let Some(picker) = &self.file_picker {
            picker.draw_overlay(frame);
        }
    }

    /// Char count of the currently focused text field. Returns 0 for the Auth /
    /// Secret / Credential / Source chooser rows (no in-field cursor) and for
    /// the inline-key rows (the [`KeyPaste`] popup owns its own cursor while
    /// open, so this form cursor is irrelevant for them).
    fn focused_text_len(&self) -> usize {
        match self.focus {
            Field::Name => self.name.chars().count(),
            Field::Host => self.host_addr.chars().count(),
            Field::Port => self.port.chars().count(),
            Field::User => self.user.chars().count(),
            Field::Password => self.password.chars().count(),
            // Identity is a trigger row (Enter opens the FilePicker overlay);
            // no in-field cursor. Source/Auth/Credential/Secret are choosers;
            // InlinePrivate/InlineCert edit via the KeyPaste popup.
            Field::Auth
            | Field::Credential
            | Field::Secret
            | Field::Source
            | Field::Identity
            | Field::InlinePrivate
            | Field::InlineCert => 0,
        }
    }

    /// The `(row, value_offset)` where the terminal cursor should sit for the
    /// focused field, or `None` for the Auth / Secret / Credential / Source
    /// chooser rows and the inline-key rows. `row` is the index into the
    /// reachable rendered rows; `offset` is the stored char-index cursor,
    /// clamped to the field's current length. Pure; consumed by
    /// [`HostForm::draw_in_dialog`] to call `Frame::set_cursor_position`. The
    /// inline-key rows return `None` because the [`KeyPaste`] popup positions
    /// its own cursor internally while open; the Source row is a chooser like
    /// Auth / Secret.
    fn cursor_target(&self) -> Option<(usize, usize)> {
        let row = self.focus_idx();
        let offset = match self.focus {
            Field::Name => self.cursor.min(self.name.chars().count()),
            Field::Host => self.cursor.min(self.host_addr.chars().count()),
            Field::Port => self.cursor.min(self.port.chars().count()),
            Field::User => self.cursor.min(self.user.chars().count()),
            Field::Password => self.cursor.min(self.password.chars().count()),
            // Identity is a trigger row (Enter opens the FilePicker overlay, no
            // in-field cursor — same shape as Credential); Source/Auth/Secret
            // are choosers; InlinePrivate/InlineCert's cursor lives in the
            // KeyPaste popup.
            Field::Auth
            | Field::Credential
            | Field::Secret
            | Field::Source
            | Field::Identity
            | Field::InlinePrivate
            | Field::InlineCert => return None,
        };
        Some((row, offset))
    }

    /// Block title: distinguishes add vs edit mode. Public so the App's overlay
    /// renderer can pass it to [`crate::tui::dialog::draw_dialog`].
    pub fn title(&self) -> String {
        if self.editing {
            " edit host ".into()
        } else {
            " add host ".into()
        }
    }

    /// Body row count the dialog sizes to. The count is the **maximum**
    /// reachable field count across every (auth, secret, source) state (so
    /// toggling the Auth/Secret/Source chooser changes which rows are filled but
    /// never collapses the dialog box), plus one error row and one hint row. It
    /// is NOT focus-aware: the inline-key rows edit in the [`KeyPaste`] popup
    /// (a modal overlay), so the body never expands an editor block — the
    /// dialog stays a stable height while the form is open. Consumed by the App
    /// overlay layer via [`crate::tui::dialog::draw_dialog`].
    pub fn body_rows(&self) -> u16 {
        let mut max_fields = 0usize;
        for auth in [AuthChoice::Independent, AuthChoice::Reference { idx: 0 }] {
            for secret in [
                SecretChoice::None,
                SecretChoice::Password,
                SecretChoice::IdentityKey,
            ] {
                for source in [SourceChoice::Path, SourceChoice::Inline] {
                    let n = Field::ORDER
                        .iter()
                        .filter(|&&f| Self::field_reachable(f, &auth, secret, source))
                        .count();
                    max_fields = max_fields.max(n);
                }
            }
        }
        (max_fields + 2) as u16 // + error row + hint row
    }

    /// The interaction type of `field`, which drives its affordance suffix in
    /// [`render_row`]. Text/password/switch self-describe; trigger rows
    /// (Identity file-picker, Credential fuzzy-picker) carry `▸`, and inline
    /// paste rows carry `¶ ▸`. Credential only advertises the pick affordance
    /// when at least one credential exists to pick — otherwise `Enter` opens an
    /// empty picker and the `▸` would promise an action that yields nothing.
    fn field_kind(&self, field: Field) -> FieldKind {
        match field {
            Field::Name | Field::Host | Field::Port | Field::User => FieldKind::Text,
            Field::Password => FieldKind::Password,
            Field::Auth | Field::Secret | Field::Source => FieldKind::Switch,
            Field::Identity => FieldKind::Trigger,
            Field::InlinePrivate | Field::InlineCert => FieldKind::MultilineTrigger,
            Field::Credential => {
                if self.credential_names.is_empty() {
                    FieldKind::Text
                } else {
                    FieldKind::Trigger
                }
            }
        }
    }

    /// Render one labeled field row via the shared [`render_field_row`]
    /// (focus marker + value/placeholder + type-affordance suffix); see there
    /// for truncation and suffix-placement details.
    fn render_row(&self, field: Field, row_width: u16) -> Line<'static> {
        let (value, placeholder) = self.row_value_and_placeholder(field);
        render_field_row(
            field.label(),
            self.focus == field,
            &value,
            placeholder,
            self.field_kind(field),
            HOST_LABEL_WIDTH,
            row_width,
        )
    }

    /// The editable value and its dim placeholder for `field`.
    fn row_value_and_placeholder(&self, field: Field) -> (String, Option<&'static str>) {
        match field {
            Field::Name => (
                self.name.clone(),
                Some("e.g. web-prod (no : @ or whitespace)"),
            ),
            Field::Host => (
                self.host_addr.clone(),
                Some("e.g. 192.168.1.1 or host.example.com"),
            ),
            Field::Port => {
                let v = self.port.clone();
                let ph = if v.is_empty() {
                    Some("22 (default)")
                } else {
                    None
                };
                (v, ph)
            }
            Field::User => (self.user.clone(), Some("root (default)")),
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
            Field::Credential => {
                // Mirror the Auth row's Reference display: the selected name, or
                // a placeholder when none is chosen / none exist.
                let v = match &self.auth_choice {
                    AuthChoice::Reference { idx } => match self.credential_names.get(*idx) {
                        Some(name) => name.clone(),
                        None => "<none>".to_string(),
                    },
                    AuthChoice::Independent => String::new(),
                };
                let ph = if self.credential_names.is_empty() {
                    Some("no credentials defined — add one with the cred wizard")
                } else {
                    Some("pick a credential")
                };
                (v, ph)
            }
            Field::Secret => {
                let v = bracketed(self.secret_kind.label());
                let ph = match self.secret_kind {
                    SecretChoice::None => Some("<- -> cycle: Password / IdentityKey / None"),
                    SecretChoice::Password => Some("type the password below"),
                    SecretChoice::IdentityKey => Some("Path or Inline (Source row below)"),
                };
                (v, ph)
            }
            Field::Source => {
                // Chooser row: bracketed like Secret. The placeholder hints the
                // cycle direction.
                let v = bracketed(self.source.label());
                let ph = Some("<- -> cycle: Path / Inline");
                (v, ph)
            }
            Field::InlinePrivate => {
                // One-line summary, never echoing key text. A freshly-pasted
                // buffer shows its own line count; in edit mode with an empty
                // buffer, fall back to the ORIGINAL inline key — its readable
                // line count (plaintext), else a "saved" hint when it exists
                // but is encrypted (vault). The full editor opens on Enter.
                if !self.inline_private.trim().is_empty() {
                    (
                        format!(
                            "{} line(s) of private key",
                            self.inline_private.lines().count()
                        ),
                        None,
                    )
                } else if let Some(n) = orig_inline_lines(self.orig_key.as_ref(), false) {
                    (format!("{} line(s) of private key", n), None)
                } else if orig_inline_exists(self.orig_key.as_ref(), false) {
                    (String::new(), Some("saved · paste to replace"))
                } else {
                    (String::new(), Some("paste private key"))
                }
            }
            Field::InlineCert => {
                if !self.inline_cert.trim().is_empty() {
                    (
                        format!(
                            "{} line(s) of certificate",
                            self.inline_cert.lines().count()
                        ),
                        None,
                    )
                } else if let Some(n) = orig_inline_lines(self.orig_key.as_ref(), true) {
                    (format!("{} line(s) of certificate", n), None)
                } else if orig_inline_exists(self.orig_key.as_ref(), true) {
                    (String::new(), Some("saved · paste to replace"))
                } else {
                    (String::new(), Some("optional certificate"))
                }
            }
            Field::Identity => {
                // Trigger row: shows the selected path (if any) or a browse hint.
                // The path is filled by the file picker, never typed.
                if self.identity.is_empty() {
                    (String::new(), Some("browse for a private key"))
                } else {
                    (self.identity.clone(), Some("Enter to re-browse"))
                }
            }
            Field::Password => {
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
    //! Purity tests for the host wizard state machine: cursor-target math,
    //! pure `validate`, field navigation, char/backspace editing, the auth and
    //! secret chooser cycling, `build_auth` / `parsed_port`, and the
    //! `new_edit` prefill. Key handling is driven directly (no terminal); the
    //! persist half lives in `app.rs`.
    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use sshrack_core::config::schema::{Secret, SecretKind};

    fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
    }

    fn blank_form() -> HostForm {
        HostForm::new_add(vec![])
    }

    fn form_with(name: &str, host: &str) -> HostForm {
        let mut f = blank_form();
        f.name = name.into();
        f.host_addr = host.into();
        // Keep the cursor consistent with the pre-filled Name (mirrors what
        // move_focus / construction do), so backspace / cursor_target behave as
        // if the user had just typed the value.
        f.cursor = f.focused_text_len();
        f
    }

    fn complete_form() -> HostForm {
        form_with("web", "10.0.0.5")
    }

    // ---- cursor_target: where the terminal cursor sits on the focused field ----

    #[test]
    fn host_cursor_target_name_empty_is_row_zero_offset_zero() {
        let mut f = blank_form();
        f.focus = Field::Name;
        assert_eq!(f.cursor_target(), Some((0, 0)));
    }

    #[test]
    fn host_cursor_target_host_with_typed_value_offsets_by_char_count() {
        let mut f = blank_form();
        f.focus = Field::Host;
        f.host_addr = "10.0.0.5".into();
        // Sync the cursor to the end of the pre-filled Host field, as if the
        // user had just typed it — cursor_target then reports that position.
        f.cursor = f.focused_text_len();
        // Independent + None: reachable rows are Name(0)/Host(1)/Port(2)/Auth(3)/User(4)/Secret(5).
        assert_eq!(f.cursor_target(), Some((1, 8)));
    }

    #[test]
    fn host_cursor_target_auth_is_none_chooser() {
        let mut f = blank_form();
        f.focus = Field::Auth;
        assert_eq!(f.cursor_target(), None);
    }

    #[test]
    fn host_cursor_target_secret_is_none_chooser() {
        let mut f = blank_form();
        f.focus = Field::Secret;
        assert_eq!(f.cursor_target(), None);
    }

    #[test]
    fn host_cursor_target_password_offsets_by_masked_len() {
        let mut f = blank_form();
        f.secret_kind = SecretChoice::Password;
        f.focus = Field::Password;
        f.password = Zeroizing::new("hunter2".into());
        f.cursor = f.focused_text_len();
        // Independent + Password: Name(0)/Host(1)/Port(2)/Auth(3)/User(4)/Secret(5)/Password(6).
        assert_eq!(f.cursor_target(), Some((6, 7)));
    }

    #[test]
    fn host_cursor_target_identity_is_none_trigger_row() {
        // Task 6: Identity is now a trigger row (Enter opens the FilePicker
        // overlay), so it has no in-field cursor — `cursor_target` returns
        // `None` just like the Credential / Auth / Secret choosers. The
        // selected path is filled by the picker, never typed char-by-char.
        let mut f = blank_form();
        f.secret_kind = SecretChoice::IdentityKey;
        f.focus = Field::Identity;
        f.identity = "/k/id".into();
        f.cursor = f.focused_text_len();
        assert_eq!(f.cursor_target(), None);
    }

    // ---- validate (TDD: RED → GREEN) ----

    #[test]
    fn rejects_empty_name_and_host() {
        assert!(matches!(
            validate(&blank_form()),
            Err(SaveError::MissingName)
        ));
    }

    #[test]
    fn rejects_name_only_missing_host() {
        let f = form_with("web", "");
        assert!(matches!(validate(&f), Err(SaveError::MissingHost)));
    }

    #[test]
    fn rejects_whitespace_only_name_as_missing() {
        let mut f = complete_form();
        f.name = "   ".into();
        assert!(matches!(validate(&f), Err(SaveError::MissingName)));
    }

    #[test]
    fn rejects_forbidden_char_in_name() {
        // Each forbidden char surfaces as InvalidName (not MissingName).
        for bad in ["a:b", "a@b", "a b", "a\tb"] {
            let mut f = complete_form();
            f.name = bad.into();
            assert!(
                matches!(validate(&f), Err(SaveError::InvalidName)),
                "expected InvalidName for {bad:?}"
            );
        }
    }

    #[test]
    fn accepts_complete_form() {
        assert!(validate(&complete_form()).is_ok());
    }

    #[test]
    fn accepts_complete_form_with_reference_choice() {
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Reference { idx: 0 };
        f.credential_names = vec!["ops".into()];
        assert!(validate(&f).is_ok());
    }

    #[test]
    fn save_error_field_maps_to_the_right_field() {
        assert_eq!(SaveError::MissingName.field(), Field::Name);
        assert_eq!(SaveError::InvalidName.field(), Field::Name);
        assert_eq!(SaveError::MissingHost.field(), Field::Host);
    }

    // ---- on_key: field editing ----

    #[test]
    fn typing_appends_to_focused_field() {
        let mut f = blank_form();
        assert_eq!(f.focus, Field::Name);
        f.on_key(press(KeyCode::Char('w'), KeyModifiers::NONE));
        f.on_key(press(KeyCode::Char('e'), KeyModifiers::NONE));
        f.on_key(press(KeyCode::Char('b'), KeyModifiers::NONE));
        assert_eq!(f.name, "web");
    }

    #[test]
    fn backspace_pops_focused_field() {
        let mut f = form_with("we", "");
        f.on_key(press(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(f.name, "w");
    }

    #[test]
    fn tab_moves_focus_forward_through_independent_none_rows() {
        // Independent + None: Name→Host→Port→Auth→User→Secret, then wraps.
        let mut f = blank_form();
        assert_eq!(f.focus, Field::Name);
        for next in [
            Field::Host,
            Field::Port,
            Field::Auth,
            Field::User,
            Field::Secret,
        ] {
            f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
            assert_eq!(f.focus, next);
        }
        // Wraps back to Name (Identity/Password are skipped under None).
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::Name);
    }

    #[test]
    fn shift_tab_moves_focus_backward() {
        let mut f = blank_form();
        f.focus = Field::Auth;
        f.on_key(press(KeyCode::BackTab, KeyModifiers::SHIFT));
        // Independent + None order: Name(0)/Host(1)/Port(2)/Auth(3)/User(4)/Secret(5);
        // BackTab from Auth(3) lands on Port(2).
        assert_eq!(f.focus, Field::Port);
    }

    #[test]
    fn up_down_move_focus_like_tab() {
        let mut f = blank_form();
        f.on_key(press(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::Host);
        f.on_key(press(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::Name);
    }

    #[test]
    fn enter_advances_until_last_reachable_then_attempts_save() {
        let mut f = complete_form();
        // Focus starts on Name; Enter should advance, not save.
        let o = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(o, Outcome::Continue));
        assert_eq!(f.focus, Field::Host);
        // Jump to the last reachable field under Independent+None = Secret.
        f.focus = Field::Secret;
        let o = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(o, Outcome::SaveHost));
    }

    #[test]
    fn enter_on_password_row_attempts_save_when_last() {
        // Under Password choice, the Password row is last reachable; Enter saves.
        let mut f = complete_form();
        f.secret_kind = SecretChoice::Password;
        f.focus = Field::Password;
        let o = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(o, Outcome::SaveHost));
    }

    #[test]
    fn ctrl_s_saves_from_any_field() {
        let mut f = complete_form();
        f.focus = Field::Host;
        let o = f.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(matches!(o, Outcome::SaveHost));
    }

    #[test]
    fn save_with_invalid_form_sets_error_and_focuses_bad_field() {
        let mut f = blank_form();
        let o = f.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(matches!(o, Outcome::Continue));
        assert_eq!(f.error, Some(SaveError::MissingName));
        assert_eq!(f.focus, Field::Name);
    }

    #[test]
    fn editing_a_field_clears_its_error() {
        let mut f = blank_form();
        f.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert_eq!(f.error, Some(SaveError::MissingName));
        // Typing into the now-focused Name field clears the error.
        f.on_key(press(KeyCode::Char('w'), KeyModifiers::NONE));
        assert_eq!(f.error, None);
    }

    #[test]
    fn esc_and_ctrl_c_cancel() {
        let mut f = complete_form();
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
    fn key_release_is_ignored() {
        let mut f = complete_form();
        let release =
            KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        let o = f.on_key(release);
        assert!(matches!(o, Outcome::Continue));
    }

    // ---- render smoke: draw_in_dialog must not panic for any focus / state ----

    #[test]
    fn draw_in_dialog_renders_without_panic_across_focus_auth_and_secret_states() {
        // A render smoke through the real Dialog chrome: drive the form through
        // every focus field × every auth kind × every secret kind, plus a
        // validation error and a core error. Routing through `draw_dialog`
        // exercises the cursor offset math against a body rect offset from
        // (0,0). Catches row-render / placeholder / chooser formatting panics.
        use crate::tui::dialog::draw_dialog;
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        for focus in Field::ORDER {
            for auth in [
                AuthChoice::Independent,
                AuthChoice::Reference { idx: 0 },
                AuthChoice::Reference { idx: 1 },
            ] {
                for secret in [
                    SecretChoice::None,
                    SecretChoice::Password,
                    SecretChoice::IdentityKey,
                ] {
                    let mut f = complete_form();
                    f.credential_names = vec!["ops".into(), "team".into()];
                    f.focus = *focus;
                    f.auth_choice = auth.clone();
                    f.secret_kind = secret;
                    f.identity = if secret == SecretChoice::IdentityKey {
                        "/k/path".into()
                    } else {
                        String::new()
                    };
                    *f.password = if secret == SecretChoice::Password {
                        "hunter2".into()
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
        }
        // Validation error row renders in DANGER across the body.
        let mut f = complete_form();
        f.focus = Field::Name;
        f.error = Some(SaveError::MissingName);
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
        // Core-level error row renders in DANGER across the body.
        f.error = None;
        f.set_core_error("duplicate name".into());
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
        // Behavior pin for the focus-following viewport: when the dialog can't
        // fit every reachable field, the focused one must scroll into view so
        // its terminal cursor lands inside the body rect. We focus the LAST
        // reachable field under Independent+Password (a text field — Password —
        // so `cursor_target` returns a real position), and render through a
        // height-11 TestBackend (the dialog's blank-separator + footer + border
        // chrome leaves a 3-row body — tall enough for fields/error/hint, but
        // not for all 7 reachable fields). Without the viewport the cursor
        // would sit at `fields_area.y + last_row` (well past the body bottom);
        // with it the in-window row index lands at the top of the fields area.
        use crate::tui::dialog::draw_dialog;
        use ratatui::{
            Terminal,
            backend::{Backend, TestBackend},
            layout::Rect,
        };

        let mut form = HostForm::new_add(vec![]);
        // A complete-enough form so validate would pass; secret_kind=Password so
        // the Password row (a text field) is the last reachable one.
        form.name = "h".into();
        form.host_addr = "10.0.0.5".into();
        form.secret_kind = SecretChoice::Password;
        let last = *form
            .reachable_fields()
            .last()
            .expect("invariant: reachable fields non-empty under Independent+Password");
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

    // ---- auth chooser cycling ----

    #[test]
    fn right_arrow_on_auth_cycles_independent_to_reference_and_wraps() {
        let mut f = complete_form();
        f.credential_names = vec!["ops".into()];
        f.focus = Field::Auth;
        assert_eq!(f.auth_choice, AuthChoice::Independent);
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert!(matches!(f.auth_choice, AuthChoice::Reference { .. }));
        // A toggle leaves focus on Auth (no auto-jump), so a second Right wraps
        // Reference -> Independent right away.
        assert_eq!(f.focus, Field::Auth);
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.auth_choice, AuthChoice::Independent);
    }

    #[test]
    fn left_arrow_cycles_backward() {
        let mut f = complete_form();
        f.focus = Field::Auth;
        f.on_key(press(KeyCode::Left, KeyModifiers::NONE));
        assert!(matches!(f.auth_choice, AuthChoice::Reference { .. }));
    }

    #[test]
    fn left_right_off_auth_row_are_ignored_for_cycling() {
        // On the Name row, Left/Right do NOT cycle auth.
        let mut f = complete_form();
        f.focus = Field::Name;
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.auth_choice, AuthChoice::Independent);
    }

    // ---- credential picker wiring (Reference branch) ----

    fn ref_form(names: &[&str]) -> HostForm {
        // A Reference-form host: switch Auth to Reference so the Credential row
        // is reachable, then focus it. cycle_auth no longer auto-jumps, so the
        // focus move onto the Credential row is explicit.
        let mut f = HostForm::new_add(names.iter().map(|s| s.to_string()).collect());
        f.name = "h".into();
        f.host_addr = "10.0.0.5".into();
        f.focus = Field::Auth;
        let _ = f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert!(matches!(f.auth_choice, AuthChoice::Reference { .. }));
        assert_eq!(f.focus, Field::Auth, "toggle leaves focus on Auth");
        f.focus = Field::Credential;
        f
    }

    #[test]
    fn credential_row_enter_opens_picker_when_credentials_exist() {
        let mut f = ref_form(&["web-prod", "db"]);
        assert!(f.cred_picker.is_none());
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            f.cred_picker.is_some(),
            "Enter on Credential opened the picker"
        );
    }

    #[test]
    fn credential_row_enter_is_a_noop_when_no_credentials() {
        let mut f = ref_form(&[]);
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            f.cred_picker.is_none(),
            "no picker when there is nothing to pick"
        );
    }

    #[test]
    fn picker_select_writes_back_the_credential_index() {
        let mut f = ref_form(&["web-prod", "db-staging", "web-dev"]);
        // ref_form leaves auth_choice = Reference{idx:0} (web-prod); the picker
        // now opens with the cursor ON web-prod (the current selection), not
        // the top. ranked (name asc) = [1,2,0]; web-prod is at ranked pos 2.
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE)); // open on web-prod
        // Move to db-staging: from pos 2, Down wraps to pos 0 (db-staging).
        let _ = f.on_key(press(KeyCode::Down, KeyModifiers::NONE));
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE)); // select db-staging
        assert!(f.cred_picker.is_none(), "picker closed after selecting");
        assert_eq!(f.selected_credential_name(), Some("db-staging"));
    }

    #[test]
    fn picker_opens_with_cursor_on_currently_selected_credential() {
        // ref_form sets auth_choice = Reference{idx:0} (web-prod). The picker
        // must open with the cursor on web-prod, not the first name in ranked
        // order (db-staging). Pins the fix where re-entering the picker always
        // reset the cursor to the top.
        let mut f = ref_form(&["web-prod", "db-staging", "web-dev"]);
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE)); // open
        let picker = f.cred_picker.as_ref().expect("picker open");
        assert_eq!(
            picker.selected_idx(),
            Some(0),
            "cursor on current selection web-prod (idx 0)"
        );
        // ranked = [1,2,0]; web-prod (idx 0) is at ranked pos 2.
        assert_eq!(picker.selected, 2);
    }

    #[test]
    fn picker_escape_closes_without_changing_selection() {
        let mut f = ref_form(&["web-prod", "db-staging"]);
        // Pre-set an existing reference idx so we can prove Esc leaves it alone.
        f.auth_choice = AuthChoice::Reference { idx: 0 }; // web-prod
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE)); // open
        let _ = f.on_key(press(KeyCode::Down, KeyModifiers::NONE)); // move cursor
        let _ = f.on_key(press(KeyCode::Esc, KeyModifiers::NONE)); // cancel
        assert!(f.cred_picker.is_none());
        assert_eq!(
            f.selected_credential_name(),
            Some("web-prod"),
            "Esc did not change the choice"
        );
    }

    #[test]
    fn credential_row_has_no_text_cursor() {
        let mut f = ref_form(&["web-prod"]);
        f.focus = Field::Credential;
        assert_eq!(f.cursor_target(), None);
    }

    #[test]
    fn independent_branch_never_renders_the_credential_row() {
        // The Independent branch filters with a blacklist, so Credential must
        // be explicitly excluded — pin that across all three secret kinds.
        let mut f = HostForm::new_add(vec!["web-prod".into()]);
        f.name = "h".into();
        f.host_addr = "10.0.0.5".into();
        assert!(
            !f.reachable_fields().contains(&Field::Credential),
            "Independent+None"
        );
        f.secret_kind = SecretChoice::Password;
        assert!(
            !f.reachable_fields().contains(&Field::Credential),
            "Independent+Password"
        );
        f.secret_kind = SecretChoice::IdentityKey;
        assert!(
            !f.reachable_fields().contains(&Field::Credential),
            "Independent+IdentityKey"
        );
    }

    // ---- row_value_and_placeholder: example copy ----

    #[test]
    fn host_address_placeholder_uses_a_private_range_example() {
        let f = blank_form();
        let (_, ph) = f.row_value_and_placeholder(Field::Host);
        assert_eq!(ph, Some("e.g. 192.168.1.1 or host.example.com"));
    }

    // ---- credential row inline cycling (Reference branch) ----

    #[test]
    fn right_arrow_on_credential_row_cycles_forward_and_wraps() {
        let mut f = ref_form(&["alpha", "beta", "gamma"]);
        assert_eq!(f.selected_credential_name(), Some("alpha"));
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.selected_credential_name(), Some("beta"));
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.selected_credential_name(), Some("gamma"));
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.selected_credential_name(), Some("alpha"), "wraps around");
    }

    #[test]
    fn left_arrow_on_credential_row_cycles_backward_and_wraps() {
        let mut f = ref_form(&["alpha", "beta"]);
        assert_eq!(f.selected_credential_name(), Some("alpha"));
        f.on_key(press(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(f.selected_credential_name(), Some("beta"), "wraps backward");
    }

    #[test]
    fn credential_row_cycling_is_noop_with_no_credentials() {
        let mut f = ref_form(&[]);
        // No credentials → cycle stays at idx 0 and never panics.
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert!(matches!(f.auth_choice, AuthChoice::Reference { idx: 0 }));
    }

    #[test]
    fn credential_row_left_right_do_not_fire_off_credential_row() {
        // On the Name row, Left/Right are inert — they neither cycle the
        // credential nor move focus.
        let mut f = ref_form(&["alpha", "beta", "gamma"]);
        f.focus = Field::Name;
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.selected_credential_name(), Some("alpha"), "idx unchanged");
        assert_eq!(f.focus, Field::Name);
    }

    // ---- secret chooser cycling ----

    #[test]
    fn right_arrow_on_secret_cycles_none_to_password_to_identitykey() {
        let mut f = complete_form();
        f.focus = Field::Secret;
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
        let mut f = complete_form();
        f.focus = Field::Secret;
        f.on_key(press(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
    }

    #[test]
    fn secret_cycling_only_happens_on_secret_row() {
        let mut f = complete_form();
        f.focus = Field::User;
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.secret_kind, SecretChoice::None);
    }

    // ---- build_auth / parsed_port ----

    #[test]
    fn parsed_port_defaults_to_22_when_blank() {
        let mut f = complete_form();
        f.port.clear();
        assert_eq!(f.parsed_port(), 22);
    }

    #[test]
    fn parsed_port_defaults_to_22_when_garbage() {
        let mut f = complete_form();
        f.port = "abc".into();
        assert_eq!(f.parsed_port(), 22);
    }

    // ---- build_auth / reachable_fields / new_edit (Reference/Independent) ----
    // TDD pinning the new two-state auth contract.

    fn form_independent(secret: SecretChoice) -> HostForm {
        let mut f = HostForm::new_add(vec![]);
        f.name = "web1".into();
        f.host_addr = "10.0.0.1".into();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = secret;
        f.cursor = f.focused_text_len();
        f
    }

    #[test]
    fn build_auth_independent_none_is_inline_default_body() {
        let f = form_independent(SecretChoice::None);
        let Auth::Inline(body) = f.build_auth(None) else {
            panic!("expected Inline under Independent");
        };
        assert_eq!(body.user, "root"); // empty user falls back to root
        assert_eq!(body.secret_kind(), SecretKind::Default);
    }

    #[test]
    fn build_auth_independent_identity_key_attaches_key() {
        let mut f = form_independent(SecretChoice::IdentityKey);
        f.identity = "/home/u/.ssh/id_ed25519".into();
        let Auth::Inline(body) = f.build_auth(None) else {
            panic!("expected Inline under Independent");
        };
        assert_eq!(body.user, "root");
        assert_eq!(body.secret_kind(), SecretKind::Key);
    }

    #[test]
    fn build_auth_independent_password_attaches_plaintext() {
        let mut f = form_independent(SecretChoice::Password);
        f.password = Zeroizing::new("hunter2".into());
        let Auth::Inline(body) = f.build_auth(None) else {
            panic!("expected Inline under Independent");
        };
        assert_eq!(body.user, "root");
        assert_eq!(body.secret_kind(), SecretKind::Password);
        assert_eq!(
            body.password.as_ref().and_then(Secret::as_plain),
            Some("hunter2")
        );
    }

    #[test]
    fn build_auth_reference_uses_resolved_id() {
        let mut f = HostForm::new_add(vec!["ops".into()]);
        f.name = "web1".into();
        f.host_addr = "10.0.0.1".into();
        f.auth_choice = AuthChoice::Reference { idx: 0 };
        let id = Ulid::new();
        assert!(matches!(
            f.build_auth(Some(id)),
            Auth::Ref { credential } if credential == id
        ));
    }

    #[test]
    fn reachable_fields_reference_skips_user_and_secret_rows() {
        let mut f = form_independent(SecretChoice::None); // baseline
        f.auth_choice = AuthChoice::Reference { idx: 0 };
        let fields = f.reachable_fields();
        assert!(fields.contains(&Field::Auth));
        assert!(!fields.contains(&Field::User));
        assert!(!fields.contains(&Field::Secret));
        assert!(!fields.contains(&Field::Password));
    }

    #[test]
    fn reachable_fields_independent_password_exposes_password_not_identity() {
        let f = form_independent(SecretChoice::Password);
        let fields = f.reachable_fields();
        assert!(fields.contains(&Field::Password));
        assert!(!fields.contains(&Field::Identity));
    }

    #[test]
    fn new_edit_inline_default_round_trips_to_independent_none() {
        let host = Host {
            id: Ulid::new(),
            name: "web".into(),
            host: "10.0.0.5".into(),
            port: 2222,
            ssh_args: None,
            auth: Auth::inline(CredentialBody::new("ops")),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        assert!(f.editing);
        assert_eq!(f.orig_id, Some(host.id));
        assert_eq!(f.name, "web");
        assert_eq!(f.host_addr, "10.0.0.5");
        assert_eq!(f.port, "2222");
        assert_eq!(f.user, "ops");
        assert!(matches!(f.auth_choice, AuthChoice::Independent));
        assert_eq!(f.secret_kind, SecretChoice::None);
    }

    #[test]
    fn new_edit_identitykey_round_trips_to_independent_identitykey() {
        let host = Host {
            id: Ulid::new(),
            name: "gw".into(),
            host: "gw.example.com".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(CredentialBody::new("ops").with_key("/k/id")),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        assert!(matches!(f.auth_choice, AuthChoice::Independent));
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
        assert_eq!(f.identity, "/k/id");
    }

    #[test]
    fn new_edit_inline_password_round_trips_to_independent_password_no_plaintext() {
        let host = Host {
            id: Ulid::new(),
            name: "h".into(),
            host: "1.1.1.1".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(CredentialBody::new("root").with_password("hunter2")),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        assert!(matches!(f.auth_choice, AuthChoice::Independent));
        assert_eq!(f.secret_kind, SecretChoice::Password);
        assert!(
            f.password.is_empty(),
            "plaintext must never be echoed back into the form"
        );
    }

    #[test]
    fn new_edit_credential_ref_prefills_referenced_index() {
        // The referenced credential sits at a NON-zero index; the chooser must
        // prefill that exact index, not 0.
        let host = Host {
            id: Ulid::new(),
            name: "web".into(),
            host: "10.0.0.5".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::reference(Ulid::new()),
        };
        let names = vec!["alpha".to_string(), "ops".to_string(), "team".to_string()];
        let f = HostForm::new_edit(&host, names, Some("ops"));
        assert_eq!(
            f.auth_choice,
            AuthChoice::Reference { idx: 1 },
            "must prefill the referenced credential's index, not 0"
        );
        assert_eq!(f.selected_credential_name(), Some("ops"));
    }

    #[test]
    fn new_edit_credential_ref_falls_back_to_idx0_when_name_missing() {
        // The referenced credential was deleted between sessions: its name is
        // no longer in the chooser list. Graceful fallback → idx 0.
        let host = Host {
            id: Ulid::new(),
            name: "web".into(),
            host: "10.0.0.5".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::reference(Ulid::new()),
        };
        let names = vec!["alpha".to_string(), "team".to_string()];
        let f = HostForm::new_edit(&host, names, Some("ghost"));
        assert_eq!(
            f.auth_choice,
            AuthChoice::Reference { idx: 0 },
            "dangling ref falls back to idx 0"
        );
    }

    // ---- in-field cursor movement (Task 2: RED -> GREEN) ----

    #[test]
    fn left_arrow_moves_cursor_within_a_text_field() {
        let mut form = HostForm::new_add(vec![]);
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
        let mut form = HostForm::new_add(vec![]);
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
        let mut form = HostForm::new_add(vec![]);
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
        let mut form = HostForm::new_add(vec![]);
        for c in "ab".chars() {
            form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        // cursor at end (2). Right must not overshoot.
        form.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(form.cursor, 2);
    }

    #[test]
    fn right_arrow_advances_cursor_within_a_text_field() {
        // Regression pin: Right must MOVE the cursor forward, not just clamp
        // it. After typing "abc" (cursor at end 3), Left twice lands the
        // cursor at 1; Right then advances to 2.
        let mut form = HostForm::new_add(vec![]);
        for c in "abc".chars() {
            form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(form.cursor, 1);
        form.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(form.cursor, 2);
        // cursor_target reports the stored cursor, not the tail.
        assert_eq!(form.cursor_target(), Some((0, 2)));
    }

    #[test]
    fn home_and_end_jump_cursor() {
        let mut form = HostForm::new_add(vec![]);
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
        let mut form = HostForm::new_add(vec![]);
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
        let mut form = HostForm::new_add(vec![]);
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
        let mut form = HostForm::new_add(vec![]);
        // Focus Auth, then Left must cycle (to Reference) — cursor stays 0 (chooser).
        form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Name -> Host
        form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Host -> Port
        form.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)); // Port -> Auth
        // sanity: focus is Auth
        assert_eq!(form.focus, Field::Auth);
        form.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert!(matches!(form.auth_choice, AuthChoice::Reference { .. }));
    }

    // ---- row_value_and_placeholder: chooser values are bracketed (Task 6: RED -> GREEN) ----

    #[test]
    fn auth_reference_value_drops_credential_name_and_is_bracketed() {
        // The dedicated Credential row below already shows the chosen name, so
        // the Auth row only shows the bracketed mode — no ": <name>" suffix.
        let mut form = HostForm::new_add(vec![]);
        form.credential_names = vec!["srv-cred".to_string()];
        form.auth_choice = AuthChoice::Reference { idx: 0 };
        let (value, _placeholder) = form.row_value_and_placeholder(Field::Auth);
        assert_eq!(value, "< Reference >");
    }

    #[test]
    fn auth_independent_value_is_bracketed() {
        let mut form = HostForm::new_add(vec![]);
        form.auth_choice = AuthChoice::Independent;
        let (value, _placeholder) = form.row_value_and_placeholder(Field::Auth);
        assert_eq!(value, "< Independent >");
    }

    #[test]
    fn secret_value_is_bracketed() {
        let mut form = HostForm::new_add(vec![]);
        form.auth_choice = AuthChoice::Independent;
        form.secret_kind = SecretChoice::Password;
        let (value, _placeholder) = form.row_value_and_placeholder(Field::Secret);
        assert_eq!(value, "< Password >");
    }

    // ---- field hints: field-specific ONLY — the permanent dialog footer
    // already shows Tab/^s/Esc, so a field hint must not repeat them.
    // (Task 7: RED -> GREEN) ----

    // ---- dialog height stability: body_rows pinned to the worst-case max so
    // the dialog box never resizes when Auth/Secret toggles change the
    // reachable field count (regression pin) ----

    #[test]
    fn body_rows_is_stable_across_auth_secret_and_source_states() {
        // Independent + IdentityKey + Inline is the widest state (9 reachable
        // fields: Name/Host/Port/Auth/User/Secret/Source/InlinePrivate/InlineCert);
        // Reference is the narrowest (5). body_rows() must report the SAME value
        // for every (auth, secret, source) state — the max (9) + error + hint =
        // 11 — so the dialog box stays a fixed height while the form is open.
        // Toggling Auth/Secret/Source changes which rows are filled, not the
        // border size. body_rows is focus-INDEPENDENT (inline editing lives in
        // the modal KeyPaste popup, so the body never grows an editor block).
        let mut form = HostForm::new_add(vec!["ops".into()]);
        form.name = "h".into();
        form.host_addr = "10.0.0.5".into();
        let stable = form.body_rows();
        assert_eq!(
            stable, 11,
            "max = Independent + IdentityKey + Inline (9) + error + hint"
        );
        for auth in [AuthChoice::Independent, AuthChoice::Reference { idx: 0 }] {
            for secret in [
                SecretChoice::None,
                SecretChoice::Password,
                SecretChoice::IdentityKey,
            ] {
                for source in [SourceChoice::Path, SourceChoice::Inline] {
                    form.auth_choice = auth.clone();
                    form.secret_kind = secret;
                    form.source = source;
                    assert_eq!(
                        form.body_rows(),
                        stable,
                        "body_rows must be stable under auth={auth:?} secret={secret:?} source={source:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn field_hints_do_not_repeat_save_or_cancel() {
        // The permanent dialog footer already shows `Tab field · ^s save · Esc
        // cancel`, so field-specific hints must not repeat ^s / Esc / Tab. The
        // inline-key rows now advertise "Enter edit multiline" (no Tab), so the
        // Tab ban is universal — no field repeats the footer hotkeys.
        let form = HostForm::new_add(vec![]);
        for f in [
            Field::Auth,
            Field::Credential,
            Field::Secret,
            Field::Name,
            Field::Host,
            Field::Port,
            Field::User,
            Field::Identity,
            Field::Password,
            Field::Source,
            Field::InlinePrivate,
            Field::InlineCert,
        ] {
            let hint = form.hint_for_focus(f);
            assert!(
                !hint.contains("^s"),
                "field hint must not include ^s save: {hint:?}"
            );
            assert!(
                !hint.contains("Esc"),
                "field hint must not include Esc cancel: {hint:?}"
            );
            assert!(
                !hint.contains("Tab"),
                "field hint must not include Tab next: {hint:?}"
            );
        }
    }

    // ---- Task 5: Source cycling + inline key popup under Independent (RED -> GREEN) ----
    //
    // Mirrors the cred wizard's Task 2–4 inline-paste surface onto HostForm's
    // Independent + IdentityKey branch. The Reference branch, the credential
    // chooser, and cycle_credential/picker behavior are explicitly untouched —
    // these tests exercise ONLY the Independent path.

    #[test]
    fn host_identity_key_independent_shows_source_row_and_path_branch_reaches_identity() {
        let mut f = blank_form();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Path;
        let r = f.reachable_fields();
        assert!(r.contains(&Field::Source));
        assert!(r.contains(&Field::Identity));
        assert!(!r.contains(&Field::InlinePrivate));
        assert!(!r.contains(&Field::InlineCert));
    }

    #[test]
    fn host_inline_source_independent_hides_identity_and_reaches_inline_rows() {
        let mut f = blank_form();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        let r = f.reachable_fields();
        assert!(r.contains(&Field::InlinePrivate));
        assert!(r.contains(&Field::InlineCert));
        assert!(!r.contains(&Field::Identity));
    }

    #[test]
    fn host_reference_branch_keeps_inline_fields_unreachable() {
        // The Reference branch must never expose the inline-paste rows even when
        // secret/source are set to their inline-friendly values — the inline
        // editor is Independent-only by contract.
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Reference { idx: 0 };
        f.credential_names = vec!["ops".into()];
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        let r = f.reachable_fields();
        assert!(!r.contains(&Field::Source));
        assert!(!r.contains(&Field::InlinePrivate));
        assert!(!r.contains(&Field::InlineCert));
        assert!(!r.contains(&Field::Identity));
        assert!(r.contains(&Field::Credential));
    }

    #[test]
    fn host_right_arrow_on_source_cycles_path_to_inline() {
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.focus = Field::Source;
        f.source = SourceChoice::Path;
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.source, SourceChoice::Inline);
    }

    #[test]
    fn host_enter_on_inline_private_opens_popup_and_esc_writes_back() {
        let mut f = HostForm::new_add(vec![]);
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = Field::InlinePrivate;
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
        assert_eq!(f.inline_private, "PRIVATE-KEY-TEXT\n");
    }

    #[test]
    fn host_ctrl_c_inside_popup_discards_without_writing_back() {
        let mut f = HostForm::new_add(vec![]);
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = Field::InlineCert;
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
    fn host_blank_popup_esc_does_not_write_back() {
        let mut f = HostForm::new_add(vec![]);
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = Field::InlinePrivate;
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        // Esc with no typing → blank Done → field stays empty.
        let _ = f.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(f.inline_private.is_empty());
    }

    #[test]
    fn host_enter_inside_popup_inserts_newline_instead_of_closing() {
        // Enter inside the popup must insert a newline (multiline editing),
        // not close the popup or advance focus. After typing "line1", Enter,
        // "line2", Esc closes and the buffer has two lines.
        let mut f = HostForm::new_add(vec![]);
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = Field::InlinePrivate;
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
        assert_eq!(f.inline_private, "line1\nline2\n");
    }

    #[test]
    fn host_backspace_inside_popup_deletes_within_the_buffer() {
        // Backspace inside the popup deletes inside the popup's buffer; it does
        // NOT call the form's char-based `backspace_at` helper. Type "abc",
        // backspace once, Esc → "ab".
        let mut f = HostForm::new_add(vec![]);
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = Field::InlineCert;
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        for c in "abc".chars() {
            let _ = f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let _ = f.on_key(press(KeyCode::Backspace, KeyModifiers::NONE));
        let _ = f.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(f.inline_cert, "ab\n");
    }

    #[test]
    fn host_tab_and_arrows_navigate_between_inline_rows_and_out() {
        // Tab / Up / Down navigate between the inline-key rows and out to the
        // Source row (the popup is closed, so these are form-level navigations).
        // Pins the navigation matrix under Independent + IdentityKey + Inline:
        // the reachable cycle is
        // Name→Host→Port→Auth→User→Secret→Source→InlinePrivate→InlineCert→wrap.
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = Field::Source;
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::InlinePrivate);
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::InlineCert);
        f.on_key(press(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::InlinePrivate);
        f.on_key(press(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(f.focus, Field::Source);
    }

    #[test]
    fn host_new_edit_inline_original_defaults_source_to_inline_with_empty_buffer() {
        // Editing an inline-key host: Source defaults to Inline, but the key
        // text is NEVER echoed into the paste buffer (security). build_inline_body
        // must preserve the original on save when the private field stays blank.
        use sshrack_core::config::schema::{KeySource, Secret};
        let host = Host {
            id: Ulid::new(),
            name: "h".into(),
            host: "10.0.0.5".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(
                CredentialBody::new("u").with_inline_key(Secret::Plain("SECRET-TEXT".into()), None),
            ),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        assert!(matches!(f.auth_choice, AuthChoice::Independent));
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
        assert_eq!(f.source, SourceChoice::Inline);
        assert!(f.inline_private.is_empty(), "key text must NOT echo");
        assert!(matches!(f.orig_key, Some(KeySource::Inline(_))));
    }

    #[test]
    fn row_value_inline_echoes_original_line_count_in_edit_mode() {
        // REGRESSION (bug 3 follow-up): in edit mode the paste buffer starts
        // empty (key text never echoed), so the field row used to fall through
        // to the "paste private key" placeholder — reading as if no key
        // existed. It must instead echo the ORIGINAL inline key's line count
        // (plaintext secret → readable) so edit mode shows "N line(s)" and
        // never looks empty. row_value_and_placeholder consults orig_key.
        use sshrack_core::config::schema::Secret;
        let host = Host {
            id: Ulid::new(),
            name: "h".into(),
            host: "10.0.0.5".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(
                CredentialBody::new("u").with_inline_key(Secret::Plain("abc\ndef\n".into()), None),
            ),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        let (v, ph) = f.row_value_and_placeholder(Field::InlinePrivate);
        assert_eq!(v, "2 line(s) of private key");
        assert_eq!(ph, None);
        // The buffer itself stays empty — the count comes from orig_key, not a
        // plaintext echo.
        assert!(f.inline_private.is_empty());
    }

    #[test]
    fn row_value_inline_cert_echoes_original_line_count_in_edit_mode() {
        // The cert slot (cert = true path) mirrors the private slot.
        use sshrack_core::config::schema::Secret;
        let host = Host {
            id: Ulid::new(),
            name: "h".into(),
            host: "10.0.0.5".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(CredentialBody::new("u").with_inline_key(
                Secret::Plain("pk".into()),
                Some(Secret::Plain("c1\nc2\nc3\n".into())),
            )),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        let (v, _ph) = f.row_value_and_placeholder(Field::InlineCert);
        assert_eq!(v, "3 line(s) of certificate");
    }

    #[test]
    fn row_value_inline_encrypted_original_falls_back_to_saved_hint() {
        // Under vault mode the original secret is Encrypted — the view layer
        // cannot count its lines (no key to decrypt), so fall back to a "saved"
        // hint that still confirms the key exists. Edit mode must never look
        // empty even when the line count is unreadable.
        use sshrack_core::config::schema::{EncryptedSecret, Secret};
        let enc = Secret::Encrypted(EncryptedSecret {
            nonce: "AAAA".into(),
            cipher: "BBBB".into(),
        });
        let host = Host {
            id: Ulid::new(),
            name: "h".into(),
            host: "10.0.0.5".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(CredentialBody::new("u").with_inline_key(enc, None)),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        let (v, ph) = f.row_value_and_placeholder(Field::InlinePrivate);
        assert!(
            v.is_empty(),
            "encrypted line count is not readable: got {v:?}"
        );
        assert_eq!(ph, Some("saved · paste to replace"));
    }

    #[test]
    fn row_value_inline_add_mode_shows_plain_paste_placeholder() {
        // Add mode: no original key → the plain "paste private key" placeholder,
        // unchanged. Guards against the edit-mode fallback leaking into add.
        let mut f = HostForm::new_add(vec![]);
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        let (v, ph) = f.row_value_and_placeholder(Field::InlinePrivate);
        assert!(v.is_empty());
        assert_eq!(ph, Some("paste private key"));
    }

    #[test]
    fn host_new_edit_path_original_defaults_source_to_path_with_identity_prefilled() {
        // Counterpart to the inline-original test: a Path original defaults
        // Source to Path with the identity field prefilled (the path IS shown,
        // unlike inline text).
        let host = Host {
            id: Ulid::new(),
            name: "h".into(),
            host: "10.0.0.5".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(CredentialBody::new("u").with_key("/home/me/.ssh/id_ed25519")),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        assert!(matches!(f.auth_choice, AuthChoice::Independent));
        assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
        assert_eq!(f.source, SourceChoice::Path);
        assert_eq!(f.identity, "/home/me/.ssh/id_ed25519");
        assert!(matches!(f.orig_key, Some(KeySource::Path(_))));
    }

    #[test]
    fn host_debug_impl_does_not_leak_inline_buffer_contents() {
        // The hand-written Debug must show only the line COUNT, never the pasted
        // key text. `format!("{:?}", form)` going to logs/errors must not leak
        // "PRIVATE-SECRET".
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.focus = Field::InlinePrivate;
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

    // ---- Task 5: build_inline_body routes inline source (RED -> GREEN) ----

    #[test]
    fn host_build_inline_body_inline_source_attaches_inline_key() {
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.inline_private = "PRIVATE-KEY-TEXT".to_string();
        f.inline_cert = "CERT-TEXT".to_string();
        let Auth::Inline(body) = f.build_auth(None) else {
            panic!("expected Inline under Independent");
        };
        assert_eq!(body.secret_kind(), SecretKind::Key);
        match body.key {
            Some(KeySource::Inline(ik)) => {
                assert_eq!(ik.private_key.unwrap().as_plain(), Some("PRIVATE-KEY-TEXT"));
                assert_eq!(ik.certificate.unwrap().as_plain(), Some("CERT-TEXT"));
            }
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    #[test]
    fn host_build_inline_body_inline_source_multiline_round_trips() {
        // A pasted key has many lines; they must round-trip as one string.
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.inline_private = "line1\nline2\nline3".to_string();
        let Auth::Inline(body) = f.build_auth(None) else {
            panic!("expected Inline under Independent");
        };
        let plain = match body.key {
            Some(KeySource::Inline(ik)) => ik.private_key.unwrap().as_plain().unwrap().to_string(),
            _ => panic!("expected Inline"),
        };
        assert_eq!(plain, "line1\nline2\nline3");
    }

    #[test]
    fn host_build_inline_body_inline_blank_on_edit_preserves_original_inline_key() {
        use sshrack_core::config::schema::{InlineKey, KeySource, Secret};
        let mut f = complete_form();
        f.editing = true;
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Inline;
        f.inline_private = String::new(); // empty — user did not re-paste
        f.orig_key = Some(KeySource::Inline(InlineKey {
            private_key: Some(Secret::Plain("ORIGINAL".into())),
            certificate: None,
            keyring: false,
        }));
        let Auth::Inline(body) = f.build_auth(None) else {
            panic!("expected Inline under Independent");
        };
        match body.key {
            Some(KeySource::Inline(ik)) => {
                assert_eq!(ik.private_key.unwrap().as_plain(), Some("ORIGINAL"))
            }
            _ => panic!("original inline key must be preserved when private stays blank"),
        }
    }

    #[test]
    fn host_build_inline_body_path_source_unchanged_behavior() {
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = SecretChoice::IdentityKey;
        f.source = SourceChoice::Path;
        f.identity = "/k/id".into();
        let Auth::Inline(body) = f.build_auth(None) else {
            panic!("expected Inline under Independent");
        };
        assert_eq!(
            body.key.as_ref().and_then(KeySource::as_path),
            Some(std::path::Path::new("/k/id"))
        );
    }

    // ---- popup overlay render: draw_in_dialog + body_rows must not panic for any state ----

    #[test]
    fn host_draw_in_dialog_renders_without_panic_across_source_and_focus_states() {
        // Render smoke through the real Dialog chrome across Independent × both
        // Source branches × every focus field. Exercises the row_value_and_placeholder
        // Source/Inline arms, the stable 3-split Layout, and the focus-following
        // viewport math. Covers both popup-closed and popup-open states.
        use crate::tui::dialog::draw_dialog;
        use ratatui::{Terminal, backend::TestBackend};
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Independent;
        let mut term = Terminal::new(TestBackend::new(100, 40)).unwrap();
        for secret in [
            SecretChoice::None,
            SecretChoice::Password,
            SecretChoice::IdentityKey,
        ] {
            for source in [SourceChoice::Path, SourceChoice::Inline] {
                f.secret_kind = secret;
                f.source = source;
                for focus in Field::ORDER {
                    f.focus = *focus;
                    // Popup closed.
                    f.key_paste = None;
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
                    // Popup open for the inline rows (unreachable for other
                    // fields, but harmless to set — the overlay is painted on
                    // top regardless).
                    f.key_paste = Some(KeyPaste::new(
                        match focus {
                            Field::InlinePrivate => PasteKind::Private,
                            Field::InlineCert => PasteKind::Cert,
                            _ => PasteKind::Private,
                        },
                        0,
                    ));
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
    fn host_body_rows_is_independent_of_inline_field_focus() {
        // body_rows no longer depends on focus (no inline editor block); it is
        // a stable worst-case across every (auth, secret, source) combo. Pins
        // the removal of the focus-aware inline-editor block growth.
        for auth in [AuthChoice::Independent, AuthChoice::Reference { idx: 0 }] {
            for secret in [
                SecretChoice::None,
                SecretChoice::Password,
                SecretChoice::IdentityKey,
            ] {
                for source in [SourceChoice::Path, SourceChoice::Inline] {
                    let mut f = HostForm::new_add(vec![]);
                    f.auth_choice = auth.clone();
                    f.secret_kind = secret;
                    f.source = source;
                    f.focus = Field::Name;
                    let baseline = f.body_rows();
                    f.focus = Field::InlinePrivate;
                    assert_eq!(
                        f.body_rows(),
                        baseline,
                        "focus-independent for {auth:?}/{secret:?}/{source:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn host_draw_in_dialog_renders_popup_overlay_without_panic_on_short_terminal() {
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

        let mut form = complete_form();
        form.auth_choice = AuthChoice::Independent;
        form.secret_kind = SecretChoice::IdentityKey;
        form.source = SourceChoice::Inline;

        for focus in [Field::InlinePrivate, Field::InlineCert] {
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
            form.key_paste = Some(KeyPaste::new(
                match focus {
                    Field::InlinePrivate => PasteKind::Private,
                    Field::InlineCert => PasteKind::Cert,
                    _ => unreachable!("focus is one of the two inline rows"),
                },
                0,
            ));
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

    #[test]
    fn reference_branch_never_opens_paste_popup_on_enter() {
        // The popup only ever opens under Independent + IdentityKey + Inline.
        // Inline rows are unreachable under Reference, so even if focus is
        // forced onto one, Enter must not open a paste popup. Pins the
        // Reference-branch isolation contract.
        let mut f = HostForm::new_add(vec!["c0".into()]);
        f.auth_choice = AuthChoice::Reference { idx: 0 };
        f.focus = Field::InlinePrivate;
        let _ = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(f.key_paste.is_none());
    }

    // ---- Task 6: Identity row becomes a trigger row -> opens FilePicker (RED -> GREEN) ----
    //
    // The Identity path-slot (Independent + IdentityKey + Path) is no longer
    // typed in place. It is a trigger row like Credential / InlinePrivate:
    // Enter opens the modal FilePicker overlay, which returns an absolute path
    // the form writes back into `identity`. Printable chars / Backspace are
    // no-ops on the row; the cursor never lands on it (cursor_target returns
    // None), so only the picker can change `identity`.

    #[test]
    fn enter_on_identity_opens_file_picker() {
        // Independent + IdentityKey + Path -> Identity is reachable.
        let mut form = HostForm::new_add(vec![]);
        form.auth_choice = AuthChoice::Independent;
        form.secret_kind = SecretChoice::IdentityKey;
        form.source = SourceChoice::Path;
        form.focus = Field::Identity;
        assert!(form.file_picker.is_none());
        let _ = form.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            form.file_picker.is_some(),
            "Enter on Identity opens the picker"
        );
    }

    #[test]
    fn typing_on_identity_is_a_noop_it_is_a_trigger_row() {
        let mut form = HostForm::new_add(vec![]);
        form.auth_choice = AuthChoice::Independent;
        form.secret_kind = SecretChoice::IdentityKey;
        form.source = SourceChoice::Path;
        form.focus = Field::Identity;
        for c in "abc".chars() {
            let _ = form.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert!(
            form.identity.is_empty(),
            "Identity must not accept in-place typing"
        );
    }

    #[test]
    fn enter_on_identity_under_reference_does_not_open_picker() {
        // Identity is unreachable under Reference; Enter must not open it.
        let mut form = HostForm::new_add(vec!["ops".into()]);
        form.auth_choice = AuthChoice::Reference { idx: 0 };
        form.focus = Field::Identity; // forced (unreachable) focus
        let _ = form.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(form.file_picker.is_none());
    }

    #[test]
    fn draw_in_dialog_with_open_picker_renders_without_panic() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut form = HostForm::new_add(vec![]);
        form.auth_choice = AuthChoice::Independent;
        form.secret_kind = SecretChoice::IdentityKey;
        form.source = SourceChoice::Path;
        form.focus = Field::Identity;
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

    #[test]
    fn host_field_kind_maps_each_field_to_its_affordance() {
        // `field_kind` does not depend on auth_choice, so a default form is
        // enough. `FieldKind` is in scope unqualified via the test module's
        // `use super::*;` (host.rs imports it from `super`).
        let mut f = HostForm::new_add(vec![]);
        assert_eq!(f.field_kind(Field::Name), FieldKind::Text);
        assert_eq!(f.field_kind(Field::Host), FieldKind::Text);
        assert_eq!(f.field_kind(Field::Port), FieldKind::Text);
        assert_eq!(f.field_kind(Field::User), FieldKind::Text);
        assert_eq!(f.field_kind(Field::Auth), FieldKind::Switch);
        assert_eq!(f.field_kind(Field::Secret), FieldKind::Switch);
        assert_eq!(f.field_kind(Field::Source), FieldKind::Switch);
        assert_eq!(f.field_kind(Field::Identity), FieldKind::Trigger);
        assert_eq!(
            f.field_kind(Field::InlinePrivate),
            FieldKind::MultilineTrigger
        );
        assert_eq!(f.field_kind(Field::InlineCert), FieldKind::MultilineTrigger);
        assert_eq!(f.field_kind(Field::Password), FieldKind::Password);
        // No credentials defined → Credential offers nothing to pick → Text.
        assert_eq!(
            f.field_kind(Field::Credential),
            FieldKind::Text,
            "no creds → no pick affordance"
        );

        // With a credential defined, Credential advertises the pick trigger.
        f.credential_names = vec!["srv".to_string()];
        assert_eq!(f.field_kind(Field::Credential), FieldKind::Trigger);
    }
}
