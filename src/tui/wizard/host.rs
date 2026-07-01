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
//!   forcing a detour to the credential tab.

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

use super::super::app::Outcome;
use super::super::theme;
use super::{
    AuthChoice, AuthKind, Field, HOST_VALUE_COL, SaveError, SecretChoice, validate, value_spans,
};
use sshrack_core::config::schema::{Auth, CredentialBody, Host};

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
    /// Identity-key path, edited when secret_kind is IdentityKey.
    pub identity: String,
    /// Masked password, edited when secret_kind is Password. `Zeroizing` so it
    /// is wiped on drop; never echoed back from an existing host (edit re-types).
    pub password: Zeroizing<String>,
    /// Currently focused field.
    pub focus: Field,
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
}

impl std::fmt::Debug for HostForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the password — mirrors CredForm's redacting Debug so a
        // format!("{:?}", form) / dbg!(form) can never leak plaintext.
        f.debug_struct("HostForm")
            .field("name", &self.name)
            .field("host_addr", &self.host_addr)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("auth_choice", &self.auth_choice)
            .field("secret_kind", &self.secret_kind)
            .field("identity", &self.identity)
            .field("password", &"<redacted>")
            .field("focus", &self.focus)
            .field("error", &self.error)
            .field("core_error", &self.core_error)
            .field("editing", &self.editing)
            .field("orig_id", &self.orig_id)
            .field("credential_names", &self.credential_names)
            .finish()
    }
}

impl HostForm {
    /// Fresh add-mode form: Independent + None (zero-config default), focus Name.
    /// `credential_names` seeds the Reference chooser.
    pub fn new_add(credential_names: Vec<String>) -> Self {
        Self {
            name: String::new(),
            host_addr: String::new(),
            port: String::new(),
            user: String::new(),
            auth_choice: AuthChoice::Independent,
            secret_kind: SecretChoice::None,
            identity: String::new(),
            password: Zeroizing::new(String::new()),
            focus: Field::Name,
            error: None,
            core_error: None,
            editing: false,
            orig_id: None,
            credential_names,
        }
    }

    /// Edit-mode form prefilled from `host`. Reference → `Reference{idx}` (the
    /// chooser prefills the referenced credential's current name); Inline →
    /// Independent + secret_kind derived from the body. The password is NEVER
    /// carried into the form: the user re-types to change it, and leaving the
    /// field empty on a Password-kind edit keeps the existing secret (handled by
    /// the loop at save time, mirroring CredForm).
    pub fn new_edit(
        host: &Host,
        credential_names: Vec<String>,
        referenced_credential_name: Option<&str>,
    ) -> Self {
        let (auth_choice, user, secret_kind, identity) = match &host.auth {
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
                    String::new(),
                )
            }
            Auth::Inline(body) => {
                use sshrack_core::config::schema::SecretKind;
                let u = body.user.clone();
                let (sk, iden) = match body.secret_kind() {
                    SecretKind::Key => (
                        SecretChoice::IdentityKey,
                        body.key
                            .as_ref()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    ),
                    SecretKind::Password | SecretKind::KeyringPassword => {
                        (SecretChoice::Password, String::new())
                    }
                    SecretKind::Default => (SecretChoice::None, String::new()),
                };
                (AuthChoice::Independent, u, sk, iden)
            }
        };
        Self {
            name: host.name.clone(),
            host_addr: host.host.clone(),
            port: host.port.to_string(),
            user,
            auth_choice,
            secret_kind,
            identity,
            // Never carry the existing plaintext into the form: a password is
            // not echoed back. The user re-types to set a new one; leaving the
            // field empty on a Password-kind edit keeps the existing secret.
            password: Zeroizing::new(String::new()),
            focus: Field::Name,
            error: None,
            core_error: None,
            editing: true,
            orig_id: Some(host.id),
            credential_names,
        }
    }

    /// Advance the auth chooser by `delta` (signed), wrapping. Pure.
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

    /// Cycle the credential index within the Reference chooser by `delta`
    /// (signed), wrapping. No-op when there are no credentials.
    fn cycle_credential(&mut self, delta: i32) {
        let n = self.credential_names.len();
        if n == 0 {
            return;
        }
        let cur = match self.auth_choice {
            AuthChoice::Reference { idx } => idx,
            _ => 0,
        };
        let next = (cur as i32 + delta).rem_euclid(n as i32) as usize;
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
    fn build_inline_body(&self) -> CredentialBody {
        let user = if self.user.trim().is_empty() {
            "root".to_string()
        } else {
            self.user.clone()
        };
        match self.secret_kind {
            SecretChoice::None => CredentialBody::new(user),
            SecretChoice::IdentityKey => {
                let key = self.identity.trim();
                let mut body = CredentialBody::new(user);
                if !key.is_empty() {
                    body = body.with_key(key);
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

    /// The ordered list of fields the user can navigate to. Reference shows only
    /// Name/Host/Port/Auth (the user comes from the credential). Independent
    /// always shows User/Auth/Secret, plus Identity (IdentityKey) or Password
    /// (Password) — never both, never neither's secret-specific row.
    fn reachable_fields(&self) -> Vec<Field> {
        Field::ORDER
            .iter()
            .copied()
            .filter(|f| match self.auth_choice {
                AuthChoice::Reference { .. } => {
                    matches!(f, Field::Name | Field::Host | Field::Port | Field::Auth)
                }
                AuthChoice::Independent => match self.secret_kind {
                    SecretChoice::None => !matches!(f, Field::Identity | Field::Password),
                    SecretChoice::IdentityKey => *f != Field::Password,
                    SecretChoice::Password => *f != Field::Identity,
                },
            })
            .collect()
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
    /// - printable char / `Backspace` → edit the focused text field (name, host,
    ///   port, user, identity when secret_kind is IdentityKey, password when
    ///   secret_kind is Password).
    /// - `Tab` / `↓` → next reachable field; `Shift-Tab` / `↑` → previous.
    /// - `Enter` → next reachable field, or — on the last reachable field —
    ///   attempt save (validate then signal [`Outcome::SaveHost`]); on
    ///   validation error set `error` and move focus to the bad field.
    /// - `Ctrl-S` → attempt save from any field.
    /// - `←`/`→` on the auth row → cycle Independent / Reference. `Shift-←`/
    ///   `Shift-→` on the auth row → cycle the credential list (Reference only).
    /// - `←`/`→` on the secret row → cycle None / Password / IdentityKey.
    /// - `Esc` / `Ctrl-C` → cancel back to the launcher.
    ///
    /// [`validate`]: super::validate
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        // Any keystroke clears a stale core-level error.
        self.core_error = None;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let ctrl_c_only = key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c');

        if ctrl_c_only {
            return Outcome::Cancel;
        }

        match key.code {
            KeyCode::Esc => Outcome::Cancel,
            KeyCode::Char('s') if ctrl => self.attempt_save(),
            KeyCode::Tab | KeyCode::Down if !ctrl => {
                self.move_focus(1);
                Outcome::Continue
            }
            KeyCode::BackTab | KeyCode::Up if !ctrl => {
                self.move_focus(-1);
                Outcome::Continue
            }
            KeyCode::Enter => {
                if self.is_last_reachable(self.focus) {
                    self.attempt_save()
                } else {
                    self.move_focus(1);
                    Outcome::Continue
                }
            }
            // Auth row: ←/→ cycle Independent/Reference; Shift-←/→ cycle the
            // credential list (only meaningful under Reference).
            KeyCode::Left if self.focus == Field::Auth && !shift => {
                self.cycle_auth(-1);
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right if self.focus == Field::Auth && !shift => {
                self.cycle_auth(1);
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Left if self.focus == Field::Auth && shift => {
                if matches!(self.auth_choice, AuthChoice::Reference { .. }) {
                    self.cycle_credential(-1);
                }
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right if self.focus == Field::Auth && shift => {
                if matches!(self.auth_choice, AuthChoice::Reference { .. }) {
                    self.cycle_credential(1);
                }
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
            KeyCode::Backspace => {
                self.edit_focused_pop();
                Outcome::Continue
            }
            KeyCode::Char(c) if !ctrl => {
                self.edit_focused_push(c);
                Outcome::Continue
            }
            _ => Outcome::Continue,
        }
    }

    /// Append `c` to the focused text input. Auth / Secret are chooser rows
    /// driven by ←/→; Password only accepts input when secret_kind is Password.
    fn edit_focused_push(&mut self, c: char) {
        match self.focus {
            Field::Name => self.name.push(c),
            Field::Host => self.host_addr.push(c),
            Field::Port => {
                if c.is_ascii_digit() {
                    self.port.push(c);
                }
            }
            Field::User => self.user.push(c),
            Field::Identity => self.identity.push(c),
            Field::Password if self.secret_kind == SecretChoice::Password => self.password.push(c),
            // Auth / Secret are chooser rows driven by ←/→; no text entry.
            Field::Auth | Field::Secret | Field::Password => {}
        }
        if Some(self.focus) == self.error.map(SaveError::field) {
            self.error = None;
        }
    }

    /// Pop one char from the focused text input (mirror of [`edit_focused_push`]).
    fn edit_focused_pop(&mut self) {
        match self.focus {
            Field::Name => {
                self.name.pop();
            }
            Field::Host => {
                self.host_addr.pop();
            }
            Field::Port => {
                self.port.pop();
            }
            Field::User => {
                self.user.pop();
            }
            Field::Identity => {
                self.identity.pop();
            }
            Field::Password if self.secret_kind == SecretChoice::Password => {
                self.password.pop();
            }
            Field::Auth | Field::Secret | Field::Password => {}
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

    /// Render the field rows + error/hint lines into `body` (the rect a
    /// [`crate::tui::dialog::draw_dialog`] hands the form). No outer border —
    /// the dialog already drew the chrome. Places the real terminal cursor on
    /// the focused text field, offset into `body`.
    pub fn draw_in_dialog(&self, frame: &mut Frame, body: ratatui::layout::Rect) {
        let reachable = self.reachable_fields();
        let rows: Vec<Line> = reachable.iter().map(|f| self.render_row(*f)).collect();

        let [fields_area, error_area, hint_area] = Layout::vertical([
            Constraint::Length(reachable.len() as u16),
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

        let hint = match self.focus {
            Field::Auth => {
                "  <- -> cycle Independent/Reference  ·  Shift-<- -> cycle credential  ·  ^s save  ·  Esc cancel"
            }
            Field::Secret => "  <- -> cycle None/Password/IdentityKey  ·  ^s save  ·  Esc cancel",
            _ => "  Tab/up-down next  ·  ^s save  ·  Esc cancel",
        };
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);

        // Place the real terminal cursor on the focused text field (no drawn
        // glyph). Chooser rows (Auth / Secret) return None and get no cursor.
        if let Some((row, offset)) = self.cursor_target() {
            let max_x = fields_area.x + fields_area.width.saturating_sub(1);
            let x = (fields_area.x + HOST_VALUE_COL + offset as u16).min(max_x);
            let y = fields_area.y + row as u16;
            frame.set_cursor_position((x, y));
        }
    }

    /// The `(row, value_offset)` where the terminal cursor should sit for the
    /// focused field, or `None` for the Auth / Secret chooser rows. `row` is the
    /// index into the reachable rendered rows; `offset` is the char count
    /// already typed. Pure; [`HostForm::draw_in_dialog`] consumes it to call
    /// `Frame::set_cursor_position`.
    fn cursor_target(&self) -> Option<(usize, usize)> {
        let row = self.focus_idx();
        let offset = match self.focus {
            Field::Name => self.name.chars().count(),
            Field::Host => self.host_addr.chars().count(),
            Field::Port => self.port.chars().count(),
            Field::User => self.user.chars().count(),
            Field::Identity => self.identity.chars().count(),
            Field::Password => self.password.chars().count(),
            Field::Auth | Field::Secret => return None,
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

    /// Render one labeled field row, with the focus highlight + placeholder.
    fn render_row(&self, field: Field) -> Line<'static> {
        let label = field.label();
        let focused = self.focus == field;
        let cursor = if focused { "▶ " } else { "  " };
        let label_span = Span::styled(
            format!("{cursor}{label:>8}: "),
            if focused {
                theme::accent().add_modifier(Modifier::BOLD)
            } else {
                Style::new().dim()
            },
        );

        let (value_str, placeholder) = self.row_value_and_placeholder(field);

        let mut spans = vec![label_span];
        spans.extend(value_spans(&value_str, placeholder));
        Line::from(spans).alignment(Alignment::Left)
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
                Some("e.g. 10.0.0.5 or host.example.com"),
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
                    AuthChoice::Independent => "Independent".to_string(),
                    AuthChoice::Reference { idx } => match self.credential_names.get(*idx) {
                        Some(name) => format!("Reference: {name}"),
                        None => "Reference: <none defined>".to_string(),
                    },
                };
                let ph = match self.auth_choice {
                    AuthChoice::Independent => Some("<- -> cycle to Reference"),
                    AuthChoice::Reference { .. } => {
                        if self.credential_names.is_empty() {
                            Some("no credentials defined — add one with the cred wizard")
                        } else {
                            Some("Shift-<- -> cycle credential")
                        }
                    }
                };
                (v, ph)
            }
            Field::Secret => {
                let v = self.secret_kind.label().to_string();
                let ph = match self.secret_kind {
                    SecretChoice::None => Some("<- -> cycle: Password / IdentityKey / None"),
                    SecretChoice::Password => Some("type the password below"),
                    SecretChoice::IdentityKey => Some("type the key path"),
                };
                (v, ph)
            }
            Field::Identity => (self.identity.clone(), Some("path to a private key")),
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
        // Independent + None: reachable rows are Name(0)/Host(1)/Port(2)/User(3)/Auth(4)/Secret(5).
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
        // Independent + Password: Name(0)/Host(1)/Port(2)/User(3)/Auth(4)/Secret(5)/Password(6).
        assert_eq!(f.cursor_target(), Some((6, 7)));
    }

    #[test]
    fn host_cursor_target_identity_offsets_path() {
        let mut f = blank_form();
        f.secret_kind = SecretChoice::IdentityKey;
        f.focus = Field::Identity;
        f.identity = "/k/id".into();
        // Independent + IdentityKey: rows end with Identity at index 6.
        assert_eq!(f.cursor_target(), Some((6, 5)));
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
        // Independent + None: Name→Host→Port→User→Auth→Secret, then wraps.
        let mut f = blank_form();
        assert_eq!(f.focus, Field::Name);
        for next in [
            Field::Host,
            Field::Port,
            Field::User,
            Field::Auth,
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
        assert_eq!(f.focus, Field::User);
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
                                0,
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
                    0,
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
                    0,
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                );
                f.draw_in_dialog(fr, body);
            })
            .unwrap();
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
    fn shift_arrow_on_reference_cycles_the_credential_list() {
        // Shift-←/Shift-→ cycle the credential list when the kind is Reference.
        let mut f = complete_form();
        f.credential_names = vec!["a".into(), "b".into(), "c".into()];
        f.focus = Field::Auth;
        f.auth_choice = AuthChoice::Reference { idx: 0 };
        f.on_key(press(KeyCode::Right, KeyModifiers::SHIFT));
        assert_eq!(f.selected_credential_name(), Some("b"));
        f.on_key(press(KeyCode::Right, KeyModifiers::SHIFT));
        assert_eq!(f.selected_credential_name(), Some("c"));
        // Wraps.
        f.on_key(press(KeyCode::Right, KeyModifiers::SHIFT));
        assert_eq!(f.selected_credential_name(), Some("a"));
        f.on_key(press(KeyCode::Left, KeyModifiers::SHIFT));
        assert_eq!(f.selected_credential_name(), Some("c"));
    }

    #[test]
    fn shift_arrow_off_reference_kind_is_a_noop() {
        // Shift-←/Shift-→ on Independent do nothing (no credential to cycle);
        // they must NOT cycle the auth kind.
        let mut f = complete_form();
        f.credential_names = vec!["a".into()];
        f.focus = Field::Auth;
        assert_eq!(f.auth_choice, AuthChoice::Independent);
        f.on_key(press(KeyCode::Right, KeyModifiers::SHIFT));
        assert_eq!(
            f.auth_choice,
            AuthChoice::Independent,
            "shift must not cycle kind"
        );
    }

    #[test]
    fn left_right_off_auth_row_are_ignored_for_cycling() {
        // On the Name row, Left/Right do NOT cycle auth.
        let mut f = complete_form();
        f.focus = Field::Name;
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.auth_choice, AuthChoice::Independent);
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
}
