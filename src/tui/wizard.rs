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
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use ulid::Ulid;

use super::app::Outcome;
use super::theme;
use sshrack_core::config::schema::{Auth, Credential, CredentialBody, Host};
use sshrack_core::host::validate_name_chars;
use zeroize::Zeroizing;

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

/// Build the value-area spans for one field row. Shared by [`HostForm`] and
/// [`CredForm`] so both render the empty state identically.
///
/// No cursor glyph is drawn here — the real terminal cursor is placed by each
/// form's `draw` via `Frame::set_cursor_position`, so an empty focused field
/// shows just the dim placeholder with the terminal cursor landing on its
/// first char (mirrors sshelf). A non-empty value renders raw; the placeholder
/// disappears.
fn value_spans(value: &str, placeholder: Option<&str>) -> Vec<Span<'static>> {
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
const HOST_VALUE_COL: u16 = 2 + 5 + 2;
const CRED_VALUE_COL: u16 = 2 + 8 + 2;

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
    /// seeded with `credential_names`; when `host.auth` is a reference, the
    /// caller resolves the referenced credential id → its current name (via the
    /// config) and passes it in as `referenced_credential_name`. The chooser
    /// then starts on that name's index. If the referenced credential was
    /// deleted between sessions (name no longer in the list), the chooser falls
    /// back to index 0 — a defensible last resort; the user must pick a valid
    /// credential (or change the auth kind) before save, and the loop re-validates
    /// the name→id resolution at persist time.
    pub fn new_edit(
        host: &Host,
        credential_names: Vec<String>,
        referenced_credential_name: Option<&str>,
    ) -> Self {
        let (auth_choice, user, key_path) = match &host.auth {
            Auth::Ref { .. } => {
                // Match the referenced credential's current name in the chooser
                // list. unwrap_or(0) only fires when the referenced credential
                // was deleted between sessions (name no longer present); that is
                // a genuine fallback, not the common path.
                let idx = referenced_credential_name
                    .and_then(|name| credential_names.iter().position(|n| n == name))
                    .unwrap_or(0);
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
        let cur_pos = order
            .iter()
            .position(|k| *k == cur_kind)
            .expect("invariant: every AuthChoice variant is in AUTH_ORDER");
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

    /// Render the field rows + error/hint lines into `body` (the rect a
    /// [`crate::tui::dialog::draw_dialog`] hands the form). No outer border —
    /// the dialog already drew the chrome. Places the real terminal cursor on
    /// the focused text field, offset into `body`. Task 9 finalizes the styling;
    /// Task 6 only needs the layout right and no panics.
    pub fn draw_in_dialog(&self, frame: &mut Frame, body: ratatui::layout::Rect) {
        let rows: Vec<Line> = Field::ORDER.iter().map(|f| self.render_row(*f)).collect();

        // Split body into the field rows (5) + an error/hint row (1) + a key
        // hint row (1).
        let [fields_area, error_area, hint_area] = Layout::vertical([
            Constraint::Length(Field::ORDER.len() as u16),
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

        let hint = if self.focus == Field::Auth {
            "  <- -> cycle kind  ·  Shift-<- -> cycle credential  ·  ^s save  ·  Esc cancel"
        } else {
            "  Tab/up-down next  ·  ^s save  ·  Esc cancel"
        };
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);

        // Place the real terminal cursor on the focused text field (no drawn
        // glyph — the terminal highlights the char under the cursor, landing on
        // the placeholder's first char when the field is empty). Chooser fields
        // (Default/Credential auth) return None and get no cursor.
        if let Some((row, offset)) = self.cursor_target() {
            let max_x = fields_area.x + fields_area.width.saturating_sub(1);
            let x = (fields_area.x + HOST_VALUE_COL + offset as u16).min(max_x);
            let y = fields_area.y + row as u16;
            frame.set_cursor_position((x, y));
        }
    }

    /// The `(row, value_offset)` where the terminal cursor should sit for the
    /// focused field, or `None` when the focused field is a chooser (Default /
    /// Credential auth) with no text cursor. `row` is the index into the
    /// rendered rows ([`Field::ORDER`]); `offset` is the char count already
    /// typed. Pure; [`HostForm::draw`] consumes it to call
    /// `Frame::set_cursor_position`.
    fn cursor_target(&self) -> Option<(usize, usize)> {
        let row = self.focus.idx();
        let offset = match self.focus {
            Field::Name => self.name.chars().count(),
            Field::Host => self.host_addr.chars().count(),
            Field::Port => self.port.chars().count(),
            Field::User => self.user.chars().count(),
            Field::Auth => match self.auth_choice {
                AuthChoice::InlineKey => self.inline_key.chars().count(),
                AuthChoice::Default | AuthChoice::Credential { .. } => return None,
            },
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

    /// Render one labeled field row, with the focus highlight, placeholder hint,
    /// and (for auth) the chooser value.
    fn render_row(&self, field: Field) -> Line<'static> {
        let label = field.label();
        let focused = self.focus == field;
        let cursor = if focused { "▶ " } else { "  " };
        let label_span = Span::styled(
            format!("{cursor}{label:>5}: "),
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

// ===========================================================================
// Credential add/edit wizard (CredForm)
// ===========================================================================

/// The selectable secret kinds offered by the credential wizard. Cycled by the
/// `←`/`→` chooser on the secret row. Mirrors [`CredentialBody::secret_kind`]
/// but the wizard owns its own copy so the chooser can present three concrete
/// options (Password / IdentityKey / None) the user picks between.
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

/// The credential form's editable state. The password is held as a
/// [`Zeroizing<String>`] so the plaintext is wiped on drop; it is rendered
/// masked (`•`) and never placed in errors or logs. The wizard builds this
/// either empty (add mode) or prefilled from an existing [`Credential`] (edit
/// mode).
#[derive(Debug, Clone)]
pub struct CredForm {
    /// Editable credential name.
    pub name: String,
    /// Editable login user. Required.
    pub user: String,
    /// Editable identity-key path, edited when the secret choice is
    /// [`SecretChoice::IdentityKey`]. Empty for Password / None choices.
    pub identity: String,
    /// The selected secret kind, cycled by `←`/`→` on the secret row.
    pub secret_kind: SecretChoice,
    /// The masked password, edited when the secret choice is
    /// [`SecretChoice::Password`]. `Zeroizing` so it is wiped on drop.
    pub password: Zeroizing<String>,
    /// Currently focused field.
    pub focus: CredField,
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
}

impl CredForm {
    /// Build a fresh add-mode form (all fields blank, focus on name, no
    /// secret).
    pub fn new_add() -> Self {
        Self {
            name: String::new(),
            user: String::new(),
            identity: String::new(),
            secret_kind: SecretChoice::None,
            password: Zeroizing::new(String::new()),
            focus: CredField::Name,
            error: None,
            core_error: None,
            editing: false,
            orig_id: None,
        }
    }

    /// Build an edit-mode form prefilled from `cred`. The secret kind is
    /// derived from the body via [`CredentialBody::secret_kind`]; a
    /// keyring-marker body maps to [`SecretChoice::Password`] (the password
    /// itself lives in the keyring and is not surfaced as plaintext here — the
    /// wizard lets the user set a new password to overwrite it, or switch to a
    /// different kind).
    pub fn new_edit(cred: &Credential) -> Self {
        use sshrack_core::config::schema::SecretKind;
        let body = &cred.body;
        let (secret_kind, identity) = match body.secret_kind() {
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
        Self {
            name: cred.name.clone(),
            user: body.user.clone(),
            identity,
            secret_kind,
            // Never carry the existing plaintext into the form: a password is
            // not echoed back. The user re-types to set a new one; leaving the
            // field empty on a Password-kind edit keeps the existing secret
            // (handled by the loop at save time).
            password: Zeroizing::new(String::new()),
            focus: CredField::Name,
            error: None,
            core_error: None,
            editing: true,
            orig_id: Some(cred.id),
        }
    }

    /// Set a core-level persist error (from the loop). Cleared on the next
    /// keystroke.
    pub fn set_core_error(&mut self, msg: String) {
        self.core_error = Some(msg);
    }

    /// The ordered list of fields the user can navigate to, given the current
    /// secret choice. The Password row is reachable only under Password.
    fn reachable_fields(&self) -> Vec<CredField> {
        CredField::ORDER
            .iter()
            .copied()
            .filter(|f| *f != CredField::Password || self.secret_kind == SecretChoice::Password)
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
    fn is_last_reachable(&self, field: CredField) -> bool {
        let reachable = self.reachable_fields();
        reachable.last().copied() == Some(field)
    }

    /// Pure key decision: mutate form state and return an [`Outcome`]. Performs
    /// **no I/O** — the loop runs persist only when this signals
    /// [`Outcome::SaveCred`]. The `App` routes the cred wizard's intent by the
    /// active [`super::app::Mode`] (`CredWizard`), so it never collides with
    /// the host wizard's [`Outcome::SaveHost`].
    ///
    /// Bindings mirror [`HostForm::on_key`]:
    /// - printable char / `Backspace` → edit the focused text field (name,
    ///   user, identity, or password when the choice is Password).
    /// - `Tab` / `↓` → next field; `Shift-Tab` / `↑` → previous field.
    /// - `Enter` → next field, or — on the last reachable field — attempt save;
    ///   on validation error set `error` and move focus to the bad field.
    /// - `Ctrl-S` → attempt save from any field.
    /// - `←`/`→` on the secret row → cycle secret kind.
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

        match key.code {
            KeyCode::Esc => Outcome::Cancel,
            KeyCode::Char('s') if ctrl => self.attempt_save(),
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
                if self.is_last_reachable(self.focus) {
                    self.attempt_save()
                } else {
                    self.move_focus(1);
                    Outcome::Continue
                }
            }
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

    fn edit_focused_push(&mut self, c: char) {
        match self.focus {
            CredField::Name => self.name.push(c),
            CredField::User => self.user.push(c),
            CredField::Identity => self.identity.push(c),
            CredField::SecretKind => {
                // The chooser is driven by ←/→; no text entry on this row.
            }
            CredField::Password if self.secret_kind == SecretChoice::Password => {
                self.password.push(c);
            }
            CredField::Password => {}
        }
        if Some(self.focus) == self.error.map(CredSaveError::field) {
            self.error = None;
        }
    }

    fn edit_focused_pop(&mut self) {
        match self.focus {
            CredField::Name => {
                self.name.pop();
            }
            CredField::User => {
                self.user.pop();
            }
            CredField::Identity => {
                self.identity.pop();
            }
            CredField::SecretKind => {}
            CredField::Password if self.secret_kind == SecretChoice::Password => {
                self.password.pop();
            }
            CredField::Password => {}
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
    pub fn build_body(&self) -> CredentialBody {
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
                let key = self.identity.trim();
                let mut body = CredentialBody::new(trimmed_user);
                if !key.is_empty() {
                    body = body.with_key(key);
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

        let hint = if self.focus == CredField::SecretKind {
            "  <- -> cycle kind  ·  ^s save  ·  Esc cancel"
        } else {
            "  Tab/up-down next  ·  ^s save  ·  Esc cancel"
        };
        frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);

        // Place the real terminal cursor on the focused text field (no drawn
        // glyph — see HostForm::draw_in_dialog). SecretKind is a chooser.
        if let Some((row, offset)) = self.cursor_target() {
            let max_x = fields_area.x + fields_area.width.saturating_sub(1);
            let x = (fields_area.x + CRED_VALUE_COL + offset as u16).min(max_x);
            let y = fields_area.y + row as u16;
            frame.set_cursor_position((x, y));
        }
    }

    /// The `(row, value_offset)` where the terminal cursor should sit for the
    /// focused field, or `None` for the SecretKind chooser. `row` is the index
    /// into the reachable rendered rows; `offset` is the char count already
    /// typed (the masked password counts its chars). Pure; [`CredForm::draw`]
    /// consumes it to call `Frame::set_cursor_position`.
    fn cursor_target(&self) -> Option<(usize, usize)> {
        let row = self.focus_idx();
        let offset = match self.focus {
            CredField::Name => self.name.chars().count(),
            CredField::User => self.user.chars().count(),
            CredField::Identity => self.identity.chars().count(),
            CredField::Password => self.password.chars().count(),
            CredField::SecretKind => return None,
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

    fn render_row(&self, field: CredField) -> Line<'static> {
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

    fn row_value_and_placeholder(&self, field: CredField) -> (String, Option<&'static str>) {
        match field {
            CredField::Name => (
                self.name.clone(),
                Some("e.g. ops-prod (no : @ or whitespace)"),
            ),
            CredField::User => (self.user.clone(), Some("e.g. deploy")),
            CredField::Identity => (self.identity.clone(), Some("path to a private key")),
            CredField::SecretKind => {
                let v = self.secret_kind.label().to_string();
                let ph = match self.secret_kind {
                    SecretChoice::None => Some("<- -> cycle: Password / IdentityKey / None"),
                    SecretChoice::Password => Some("type the password below"),
                    SecretChoice::IdentityKey => Some("type the key path"),
                };
                (v, ph)
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
    //! Purity tests for the host/credential wizard state machines: field
    //! navigation, char/backspace editing, pure validation, and the
    //! `build_auth`/`build_body` builders. Key handling is driven directly
    //! (no terminal); the persist half lives in `app.rs`.
    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

    fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
    }

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
        assert_eq!(f.cursor_target(), Some((1, 8)));
    }

    #[test]
    fn host_cursor_target_auth_default_is_none_chooser() {
        let mut f = blank_form();
        f.focus = Field::Auth;
        f.auth_choice = AuthChoice::Default;
        assert_eq!(f.cursor_target(), None);
    }

    #[test]
    fn host_cursor_target_auth_credential_is_none_chooser() {
        let mut f = blank_form();
        f.credential_names = vec!["ops".into()];
        f.focus = Field::Auth;
        f.auth_choice = AuthChoice::Credential { idx: 0 };
        assert_eq!(f.cursor_target(), None);
    }

    #[test]
    fn host_cursor_target_auth_inline_key_offsets_path() {
        let mut f = blank_form();
        f.focus = Field::Auth;
        f.auth_choice = AuthChoice::InlineKey;
        f.inline_key = "/k/id".into();
        assert_eq!(f.cursor_target(), Some((4, 5)));
    }

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
        // Password is the 5th reachable field when secret_kind == Password.
        assert_eq!(f.cursor_target(), Some((4, 7)));
    }

    #[test]
    fn cred_cursor_target_secret_kind_is_none_chooser() {
        let mut f = CredForm::new_add();
        f.focus = CredField::SecretKind;
        assert_eq!(f.cursor_target(), None);
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

    // ---- render smoke: draw_in_dialog must not panic for any focus / auth state ----

    #[test]
    fn draw_in_dialog_renders_without_panic_across_focus_and_auth_states() {
        // A render smoke through the real Dialog chrome: drive the form through
        // every focus field × every auth kind (Default / two Credential indices /
        // InlineKey), plus a validation error and a core error. Routing through
        // `draw_dialog` (not a bare full-screen rect) exercises the cursor
        // offset math against a body rect that is offset from (0,0) by the
        // dialog's centered border — the real path the App's overlay renderer
        // takes. Catches row-render / placeholder / chooser formatting panics
        // the on_key tests never touch.
        use crate::tui::dialog::draw_dialog;
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        for focus in Field::ORDER {
            for auth in [
                AuthChoice::Default,
                AuthChoice::Credential { idx: 0 },
                AuthChoice::Credential { idx: 1 },
                AuthChoice::InlineKey,
            ] {
                let mut f = complete_form();
                f.credential_names = vec!["ops".into(), "team".into()];
                f.focus = *focus;
                f.auth_choice = auth.clone();
                f.inline_key = if matches!(auth, AuthChoice::InlineKey) {
                    String::from("/k/path")
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
        let f = HostForm::new_edit(&host, vec![], None);
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
        let f = HostForm::new_edit(&host, vec![], None);
        assert_eq!(f.auth_choice, AuthChoice::InlineKey);
        assert_eq!(f.inline_key, "/k/id");
    }

    #[test]
    fn new_edit_prefills_from_credential_ref_host() {
        // The referenced credential sits at a NON-zero index; the chooser must
        // prefill that exact index, not 0. (This pins the fix: the old code
        // always prefilled idx 0 because it matched on empty names.)
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
            AuthChoice::Credential { idx: 1 },
            "must prefill the referenced credential's index, not 0"
        );
        assert_eq!(f.selected_credential_name(), Some("ops"));
    }

    #[test]
    fn new_edit_credential_ref_falls_back_to_idx0_when_name_missing() {
        // The referenced credential was deleted between sessions: its name is
        // no longer in the chooser list. Graceful fallback → idx 0 (the user
        // must pick a valid credential before save; the loop re-validates).
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
            AuthChoice::Credential { idx: 0 },
            "dangling ref falls back to idx 0"
        );
    }

    // ===================================================================
    // Credential wizard (CredForm) — pure `validate_cred` + on_key tests.
    // ===================================================================

    mod cred_tests {
        //! Pure-logic tests for the credential wizard: `validate_cred` (TDD
        //! core), the form's `on_key` state machine, secret-kind cycling, and
        //! `build_body`. No terminal and no filesystem are touched.

        use super::*;
        use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
        use sshrack_core::config::schema::{Credential, CredentialBody, SecretKind};

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
            f
        }

        fn complete_cred_form() -> CredForm {
            form_with("ops", "deploy")
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
            // Tab to the Password row (Name→User→Identity→SecretKind→Password).
            for _ in 0..4 {
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
            // IdentityKey choice: Tabbing skips the Password row and wraps Name.
            let mut f = complete_cred_form();
            f.secret_kind = SecretChoice::IdentityKey;
            // Tab through Name→User→Identity→SecretKind, then wrap to Name.
            for _ in 0..4 {
                f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
            }
            assert_eq!(
                f.focus,
                CredField::Name,
                "Password row must be skipped under IdentityKey"
            );
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
            assert_eq!(f.focus, CredField::Identity);
            f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
            assert_eq!(f.focus, CredField::SecretKind);
            f.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
            // SecretKind is None → Password row unreachable → wrap to Name.
            assert_eq!(f.focus, CredField::Name);
        }

        #[test]
        fn shift_tab_moves_cred_focus_backward() {
            let mut f = blank_cred_form();
            f.focus = CredField::SecretKind;
            f.on_key(press(KeyCode::BackTab, KeyModifiers::SHIFT));
            assert_eq!(f.focus, CredField::Identity);
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
                b.key.as_deref(),
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
                                0,
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
                        0,
                        &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                    );
                    f.draw_in_dialog(fr, body);
                })
                .unwrap();
            // And error / core_error lines.
            f.focus = CredField::Name;
            f.error = Some(CredSaveError::MissingName);
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
            f.error = None;
            f.set_core_error("store mode not decided".into());
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
