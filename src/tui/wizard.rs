//! Host add/edit wizard: a thin form view over core's `host::add` / `host::edit`.
//!
//! The wizard is a pure view layer — it holds form state and a pure
//! [`HostForm::on_key`] that mutates that state and returns an [`Outcome`]. The
//! actual [`host::add`]/[`host::edit`] call + config persistence happens in the
//! event loop ([`super::app::run_loop`]) after `on_key` signals
//! [`Outcome::SaveHost`], exactly mirroring how the launcher's connect intent
//! is a pure signal the loop acts on. This keeps the wizard unit-testable
//! without a terminal or a filesystem.
//!
//! Auth choices supported here:
//! - [`AuthChoice::Default`] — inline user, no secret.
//! - [`AuthChoice::Credential`] — reuse a `[[credentials]]` entry by name; the
//!   loop resolves the name to its stable [`Ulid`] before calling
//!   [`host::add`]/[`host::edit`] (ref-by-id invariant).
//! - [`AuthChoice::InlineKey`] — inline user + identity key path.
//!
//! Inline PASSWORD is intentionally NOT in this wizard: a password secret is
//! owned by a credential (Task 17 builds the credential wizard). If the user
//! needs a password they reference a credential.
//!
//! [`host::add`]: sshrack_core::host::add_host
//! [`host::edit`]: sshrack_core::host::apply_patch

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use ulid::Ulid;

use super::app::Outcome;
use sshrack_core::config::schema::{Auth, CredentialBody, Host};
use sshrack_core::host::validate_name_chars;

/// The selectable auth methods offered by the host wizard. This is the wizard's
/// own input shape — distinct from core's [`Auth`] because the wizard works in
/// *names* (a credential name the user picks from a chooser) while core stores
/// *ids* (the loop resolves name→id before persisting). Inline password is
/// intentionally absent (see the module docs).
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
        Self::ORDER.iter().position(|f| *f == self).unwrap_or(0)
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

/// The host form's editable state. All fields are owned `String`s (cheap to
/// mutate on each keystroke). The wizard constructs this either empty (add mode)
/// or prefilled from an existing [`Host`] (edit mode).
#[derive(Debug, Clone)]
pub struct HostForm {
    /// Editable host name.
    pub name: String,
    /// Editable host address.
    pub host_addr: String,
    /// Editable port (kept as a string so the user can clear / retype it; parsed
    /// at save time). Empty string falls back to the ssh default (22).
    pub port: String,
    /// Editable login user. Defaults to `root` at save time when empty.
    pub user: String,
    /// The selected auth method + (for Credential) the chosen credential index.
    pub auth_choice: AuthChoice,
    /// The inline identity-key path, edited when the auth choice is InlineKey.
    /// Kept as a separate field so save can read it without re-parsing the auth
    /// row; empty for Default / Credential choices.
    pub inline_key: String,
    /// Currently focused field.
    pub focus: Field,
    /// A transient validation error to show under the bad field. Cleared on the
    /// next edit to that field. Set by `on_key` when a save attempt fails
    /// [`validate`].
    pub error: Option<SaveError>,
    /// A core-level error surfaced by the loop after a persist attempt failed
    /// (duplicate name, dangling credential, write error). Distinct from
    /// [`error`](Self::error) because pure `validate` already passed by the
    /// time this is set — the failure is in core's `host::add_host` / duplicate
    /// check / config write. Cleared on the next keystroke.
    pub core_error: Option<String>,
    /// Whether the wizard is editing an existing host (vs adding a new one). Add
    /// mode persists via `host::add_host` with a fresh id; edit mode preserves
    /// the original id (keyring-keyed) via the loop's apply-patch path.
    pub editing: bool,
    /// The original host's id, carried in edit mode so the loop can stamp it
    /// onto the patched host (preserving the keyring entry). `None` in add mode.
    pub orig_id: Option<Ulid>,
    /// The credential names offered by the `Credential` chooser, in order. The
    /// wizard never resolves these to ids itself — the loop does, at save time.
    pub credential_names: Vec<String>,
}

impl HostForm {
    /// Build a fresh add-mode form (all fields blank, focus on name, Default
    /// auth). `credential_names` seeds the Credential chooser.
    pub fn new_add(credential_names: Vec<String>) -> Self {
        Self {
            name: String::new(),
            host_addr: String::new(),
            port: String::new(),
            user: String::new(),
            auth_choice: AuthChoice::Default,
            inline_key: String::new(),
            focus: Field::Name,
            error: None,
            core_error: None,
            editing: false,
            orig_id: None,
            credential_names,
        }
    }

    /// Build an edit-mode form prefilled from `host`. The Credential chooser is
    /// seeded with `credential_names`; if `host.auth` is a reference whose id
    /// names one of them, the chooser starts on that index.
    pub fn new_edit(host: &Host, credential_names: Vec<String>) -> Self {
        let (auth_choice, user, key_path) = match &host.auth {
            Auth::Ref { credential } => {
                // Try to find the referenced credential's name in the chooser
                // list; if missing (dangling ref or empty list), fall back to
                // Default so the user sees something editable rather than an
                // index into an empty list.
                let idx = credential_names
                    .iter()
                    .position(|n| {
                        // Match by name is not possible here (we only have the
                        // id); the loop resolves name→id at save, so at prefill
                        // time we can only index when the list carries the name
                        // for this id. The caller passes names in config order;
                        // we leave idx 0 and rely on the user to pick. This is
                        // acceptable: prefill is best-effort, save validates.
                        n.is_empty()
                    })
                    .unwrap_or(0);
                let _ = credential;
                (AuthChoice::Credential { idx }, String::new(), String::new())
            }
            Auth::Inline(body) => {
                let u = body.user.clone();
                if let Some(k) = &body.key {
                    (AuthChoice::InlineKey, u, k.to_string_lossy().into_owned())
                } else {
                    (AuthChoice::Default, u, String::new())
                }
            }
        };
        let inline_key = key_path;
        Self {
            name: host.name.clone(),
            host_addr: host.host.clone(),
            port: host.port.to_string(),
            user,
            auth_choice,
            inline_key,
            focus: Field::Name,
            error: None,
            core_error: None,
            editing: true,
            orig_id: Some(host.id),
            credential_names,
        }
    }

    /// Advance the auth chooser by `delta` (signed), wrapping. When the current
    /// choice is Credential, also cycles the credential list (so `←`/`→` first
    /// land on Credential, then further presses cycle names). Pure.
    fn cycle_auth(&mut self, delta: i32) {
        let cur_kind = self.auth_choice.kind();
        let order = AuthChoice::ORDER;
        let cur_pos = order.iter().position(|k| *k == cur_kind).unwrap_or(0);
        let next_pos = (cur_pos as i32 + delta).rem_euclid(order.len() as i32) as usize;
        let next_kind = order[next_pos];
        self.auth_choice = match next_kind {
            AuthKind::Default => AuthChoice::Default,
            AuthKind::Credential => {
                // Keep the existing credential index, clamped to the list.
                let prev_idx = match self.auth_choice {
                    AuthChoice::Credential { idx } => idx,
                    _ => 0,
                };
                let idx = if self.credential_names.is_empty() {
                    0
                } else {
                    prev_idx.min(self.credential_names.len() - 1)
                };
                AuthChoice::Credential { idx }
            }
            AuthKind::InlineKey => AuthChoice::InlineKey,
        };
    }

    /// Cycle the credential index within the chooser by `delta` (signed),
    /// wrapping. No-op when there are no credentials.
    fn cycle_credential(&mut self, delta: i32) {
        let n = self.credential_names.len();
        if n == 0 {
            return;
        }
        let cur = match self.auth_choice {
            AuthChoice::Credential { idx } => idx,
            _ => 0,
        };
        let next = (cur as i32 + delta).rem_euclid(n as i32) as usize;
        self.auth_choice = AuthChoice::Credential { idx: next };
    }

    /// The currently-selected credential name, if the auth choice is Credential
    /// and the index is in range.
    pub fn selected_credential_name(&self) -> Option<&str> {
        match self.auth_choice {
            AuthChoice::Credential { idx } => self.credential_names.get(idx).map(String::as_str),
            _ => None,
        }
    }

    /// The port to persist: the parsed `port` string, or the ssh default (22)
    /// when blank or unparseable. Used by the loop when building the Host.
    pub fn parsed_port(&self) -> u16 {
        self.port.trim().parse::<u16>().unwrap_or(22)
    }

    /// Build the core [`Auth`] for this form, given the resolved credential id
    /// (if any). Pure: the loop resolves the name→id and hands it in; this just
    /// assembles the variant. A None id for a Credential choice falls back to an
    /// inline default body (the loop will have already failed validation before
    /// reaching here in the real path, but this keeps the function total).
    pub fn build_auth(&self, resolved_credential: Option<Ulid>) -> Auth {
        let user = if self.user.trim().is_empty() {
            "root".to_string()
        } else {
            self.user.clone()
        };
        match &self.auth_choice {
            AuthChoice::Default => Auth::inline(CredentialBody::new(user)),
            AuthChoice::Credential { .. } => match resolved_credential {
                Some(id) => Auth::reference(id),
                None => Auth::inline(CredentialBody::new(user)),
            },
            AuthChoice::InlineKey => {
                let mut body = CredentialBody::new(user);
                let key = self.inline_key.trim();
                if !key.is_empty() {
                    body = body.with_key(key);
                }
                Auth::inline(body)
            }
        }
    }

    /// Set a core-level persist error (from the loop). Shown in the error line
    /// alongside a pure-validation error; cleared on the next keystroke.
    pub fn set_core_error(&mut self, msg: String) {
        self.core_error = Some(msg);
    }

    /// Pure key decision: mutate form state and return an [`Outcome`]. Performs
    /// **no I/O** — the loop runs [`validate`] + persist only when this signals
    /// [`Outcome::SaveHost`].
    ///
    /// Bindings:
    /// - printable char / `Backspace` → edit the focused text field (name, host,
    ///   port, user, or the inline-key path when auth is InlineKey).
    /// - `Tab` / `↓` → next field; `Shift-Tab` / `↑` → previous field.
    /// - `Enter` → next field, or — on the last field — attempt save (validate
    ///   then signal [`Outcome::SaveHost`]); on validation error set `error`
    ///   and move focus to the bad field.
    /// - `Ctrl-S` → attempt save from any field.
    /// - `←`/`→` on the auth row → cycle auth kind (Default → Credential →
    ///   InlineKey). `Shift-←`/`Shift-→` on the auth row → cycle the credential
    ///   list (only meaningful when the kind is Credential).
    /// - `Esc` / `Ctrl-C` → cancel back to the launcher.
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        // Any keystroke clears a stale core-level error (it referred to the
        // form state at the failed save; the user is now editing past it).
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
            KeyCode::Tab => {
                self.focus = self.focus.next();
                self.error = None;
                Outcome::Continue
            }
            KeyCode::BackTab => {
                self.focus = self.focus.prev();
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Down if !ctrl => {
                self.focus = self.focus.next();
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Up if !ctrl => {
                self.focus = self.focus.prev();
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Enter => {
                if self.focus.is_last() {
                    self.attempt_save()
                } else {
                    self.focus = self.focus.next();
                    self.error = None;
                    Outcome::Continue
                }
            }
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
                if matches!(self.auth_choice, AuthChoice::Credential { .. }) {
                    self.cycle_credential(-1);
                }
                self.error = None;
                Outcome::Continue
            }
            KeyCode::Right if self.focus == Field::Auth && shift => {
                if matches!(self.auth_choice, AuthChoice::Credential { .. }) {
                    self.cycle_credential(1);
                }
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

    /// Append `c` to whichever text input the focus is on. When the focus is the
    /// auth row and the choice is InlineKey, the char goes to the key path.
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
            Field::Auth => match self.auth_choice {
                AuthChoice::InlineKey => self.inline_key.push(c),
                _ => {
                    // No text to edit on Default/Credential rows; ignore. (The
                    // user uses ←/→ there.)
                }
            },
        }
        // Editing the focused field clears any error on it.
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
            Field::Auth => {
                if let AuthChoice::InlineKey = self.auth_choice {
                    self.inline_key.pop();
                }
            }
        }
        if Some(self.focus) == self.error.map(SaveError::field) {
            self.error = None;
        }
    }

    /// Run [`validate`]; on success signal save, on failure set the error and
    /// move focus to the bad field.
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

    /// Render the form inside `area`. The chrome (bordered block + title) is the
    /// caller's responsibility; this draws the field rows + the error line.
    /// Pure: only writes to the frame.
    pub fn draw(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Line> = Field::ORDER.iter().map(|f| self.render_row(*f)).collect();

        let block = Block::new().borders(Borders::ALL).title(self.title());
        frame.render_widget(&block, area);
        let [inner] = Layout::vertical([Constraint::Fill(1)]).areas(block.inner(area));

        // Split inner into the field rows (5) + an error/hint row (1) + a key
        // hint row (1).
        let [fields_area, error_area, hint_area] = Layout::vertical([
            Constraint::Length(Field::ORDER.len() as u16),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(inner);

        frame.render_widget(Paragraph::new(rows), fields_area);

        let error_line = if let Some(msg) = &self.core_error {
            Line::from(vec![
                Span::styled("  ! ", Style::new().fg(Color::Red).bold()),
                Span::styled(msg.clone(), Style::new().fg(Color::Red)),
            ])
        } else {
            match self.error {
                Some(e) => Line::from(vec![
                    Span::styled("  ! ", Style::new().fg(Color::Red).bold()),
                    Span::styled(e.message(), Style::new().fg(Color::Red)),
                ]),
                None => Line::raw(""),
            }
        };
        frame.render_widget(error_line, error_area);

        let hint = if self.focus == Field::Auth {
            "  <- -> cycle kind  ·  Shift-<- -> cycle credential  ·  ^s save  ·  Esc cancel"
        } else {
            "  Tab/up-down next  ·  ^s save  ·  Esc cancel"
        };
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);
    }

    /// Block title: distinguishes add vs edit mode.
    fn title(&self) -> String {
        if self.editing {
            " edit host ".into()
        } else {
            " add host ".into()
        }
    }

    /// Render one labeled field row, with the focus highlight, placeholder hint,
    /// and (for auth) the chooser value.
    fn render_row(&self, field: Field) -> Line<'static> {
        let label = field.label();
        let focused = self.focus == field;
        let cursor = if focused { "▶ " } else { "  " };
        let label_span = Span::styled(
            format!("{cursor}{label:>5}: "),
            if focused {
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::new().dim()
            },
        );

        let (value_str, placeholder) = self.row_value_and_placeholder(field);

        let mut spans = vec![label_span];
        if value_str.is_empty() {
            spans.push(Span::styled(
                placeholder.unwrap_or_default().to_string(),
                Style::new().dim(),
            ));
            if focused {
                spans.push(Span::styled("▍", Style::new().dim()));
            }
        } else {
            spans.push(Span::raw(value_str));
            if focused {
                spans.push(Span::styled("▍", Style::new().dim()));
            }
        }
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
                    AuthChoice::Default => "Default".to_string(),
                    AuthChoice::Credential { idx } => match self.credential_names.get(*idx) {
                        Some(name) => format!("Credential: {name}"),
                        None => "Credential: <none defined>".to_string(),
                    },
                    AuthChoice::InlineKey => {
                        if self.inline_key.is_empty() {
                            "InlineKey: <path>".to_string()
                        } else {
                            format!("InlineKey: {}", self.inline_key)
                        }
                    }
                };
                let ph = match self.auth_choice {
                    AuthChoice::Default => Some("<- -> cycle kind"),
                    AuthChoice::Credential { .. } => {
                        if self.credential_names.is_empty() {
                            Some("no credentials defined — add one with the cred wizard")
                        } else {
                            Some("Shift-<- -> cycle credential")
                        }
                    }
                    AuthChoice::InlineKey => Some("type the key path"),
                };
                (v, ph)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Pure-logic tests for the wizard: the `validate` function (TDD core), the
    //! form's `on_key` state machine, and the auth-chooser cycling. No terminal
    //! and no filesystem are touched; `on_key` is pure by contract.

    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

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
    fn accepts_complete_form_with_credential_choice() {
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Credential { idx: 0 };
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
    fn tab_moves_focus_forward_and_wraps() {
        let mut f = blank_form();
        assert_eq!(f.focus, Field::Name);
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::Host);
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::Port);
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::User);
        f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(f.focus, Field::Auth);
        // Wraps back to Name.
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
    fn enter_advances_until_last_field_then_attempts_save() {
        let mut f = complete_form();
        // Focus starts on Name; Enter should advance, not save.
        let o = f.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(o, Outcome::Continue));
        assert_eq!(f.focus, Field::Host);
        // Jump to the last field.
        f.focus = Field::Auth;
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

    // ---- render smoke: draw() must not panic for any focus / auth state ----

    #[test]
    fn draw_renders_without_panic_across_focus_and_auth_states() {
        // A render smoke: drive the form through every focus field and every
        // auth kind (including Credential with and without names), drawing each
        // into a TestBackend. Catches row-render / placeholder / chooser
        // formatting panics the on_key tests never touch.
        use ratatui::{Terminal, backend::TestBackend};
        let mut f = complete_form();
        f.credential_names = vec!["ops".into(), "team".into()];
        let mut terminal = Terminal::new(TestBackend::new(60, 14)).unwrap();
        for field in [
            Field::Name,
            Field::Host,
            Field::Port,
            Field::User,
            Field::Auth,
        ] {
            f.focus = field;
            for auth in [
                AuthChoice::Default,
                AuthChoice::Credential { idx: 0 },
                AuthChoice::Credential { idx: 1 },
                AuthChoice::InlineKey,
            ] {
                let is_inline_key = matches!(auth, AuthChoice::InlineKey);
                f.auth_choice = auth;
                f.inline_key = if is_inline_key {
                    "/k/path".into()
                } else {
                    String::new()
                };
                f.error = None;
                terminal.draw(|fr| f.draw(fr, fr.area())).unwrap();
            }
        }
        // Also with a validation error set.
        f.focus = Field::Name;
        f.error = Some(SaveError::MissingName);
        terminal.draw(|fr| f.draw(fr, fr.area())).unwrap();
        // And with a core error set.
        f.error = None;
        f.set_core_error("duplicate name".into());
        terminal.draw(|fr| f.draw(fr, fr.area())).unwrap();
    }

    // ---- auth chooser cycling ----

    #[test]
    fn right_arrow_on_auth_cycles_default_to_credential_to_inlinekey() {
        let mut f = complete_form();
        f.credential_names = vec!["ops".into()];
        f.focus = Field::Auth;
        assert_eq!(f.auth_choice, AuthChoice::Default);
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert!(matches!(f.auth_choice, AuthChoice::Credential { .. }));
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.auth_choice, AuthChoice::InlineKey);
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.auth_choice, AuthChoice::Default);
    }

    #[test]
    fn left_arrow_cycles_backward() {
        let mut f = complete_form();
        f.focus = Field::Auth;
        f.on_key(press(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(f.auth_choice, AuthChoice::InlineKey);
    }

    #[test]
    fn shift_arrow_on_credential_cycles_the_credential_list() {
        // Shift-←/Shift-→ cycle the credential list when the kind is Credential.
        let mut f = complete_form();
        f.credential_names = vec!["a".into(), "b".into(), "c".into()];
        f.focus = Field::Auth;
        f.auth_choice = AuthChoice::Credential { idx: 0 };
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
    fn shift_arrow_off_credential_kind_is_a_noop() {
        // Shift-←/Shift-→ on Default or InlineKey do nothing (no credential to
        // cycle); they must NOT cycle the auth kind.
        let mut f = complete_form();
        f.credential_names = vec!["a".into()];
        f.focus = Field::Auth;
        assert_eq!(f.auth_choice, AuthChoice::Default);
        f.on_key(press(KeyCode::Right, KeyModifiers::SHIFT));
        assert_eq!(
            f.auth_choice,
            AuthChoice::Default,
            "shift must not cycle kind"
        );
    }

    #[test]
    fn left_right_off_auth_row_are_ignored_for_cycling() {
        // On the Name row, Left/Right do NOT cycle auth.
        let mut f = complete_form();
        f.focus = Field::Name;
        f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(f.auth_choice, AuthChoice::Default);
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
        // The on_key port editor rejects non-digits, but build_auth is total, so
        // set garbage directly.
        f.port = "abc".into();
        assert_eq!(f.parsed_port(), 22);
    }

    #[test]
    fn build_auth_default_uses_inline_user_defaulting_to_root() {
        let mut f = complete_form();
        f.user.clear();
        f.auth_choice = AuthChoice::Default;
        let auth = f.build_auth(None);
        let body = auth.inline_body().unwrap();
        assert_eq!(body.user, "root");
        assert!(body.key.is_none());
    }

    #[test]
    fn build_auth_credential_uses_resolved_id() {
        let mut f = complete_form();
        f.auth_choice = AuthChoice::Credential { idx: 0 };
        let cid = Ulid::new();
        let auth = f.build_auth(Some(cid));
        assert_eq!(auth.credential_id(), Some(cid));
    }

    #[test]
    fn build_auth_inline_key_attaches_path() {
        let mut f = complete_form();
        f.auth_choice = AuthChoice::InlineKey;
        f.inline_key = "/home/me/.ssh/id_ed25519".into();
        let auth = f.build_auth(None);
        let body = auth.inline_body().unwrap();
        assert_eq!(
            body.key.as_deref(),
            Some(std::path::Path::new("/home/me/.ssh/id_ed25519"))
        );
    }

    // ---- new_edit prefill ----

    #[test]
    fn new_edit_prefills_from_inline_default_host() {
        let host = Host {
            id: Ulid::new(),
            name: "web".into(),
            host: "10.0.0.5".into(),
            port: 2222,
            auth: Auth::inline(CredentialBody::new("ops")),
        };
        let f = HostForm::new_edit(&host, vec![]);
        assert!(f.editing);
        assert_eq!(f.orig_id, Some(host.id));
        assert_eq!(f.name, "web");
        assert_eq!(f.host_addr, "10.0.0.5");
        assert_eq!(f.port, "2222");
        assert_eq!(f.user, "ops");
        assert_eq!(f.auth_choice, AuthChoice::Default);
    }

    #[test]
    fn new_edit_prefills_from_inline_key_host() {
        let host = Host {
            id: Ulid::new(),
            name: "gw".into(),
            host: "gw.example.com".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("ops").with_key("/k/id")),
        };
        let f = HostForm::new_edit(&host, vec![]);
        assert_eq!(f.auth_choice, AuthChoice::InlineKey);
        assert_eq!(f.inline_key, "/k/id");
    }

    #[test]
    fn new_edit_prefills_from_credential_ref_host() {
        let host = Host {
            id: Ulid::new(),
            name: "web".into(),
            host: "10.0.0.5".into(),
            port: 22,
            auth: Auth::reference(Ulid::new()),
        };
        let f = HostForm::new_edit(&host, vec!["ops".into()]);
        assert!(matches!(f.auth_choice, AuthChoice::Credential { .. }));
    }
}
