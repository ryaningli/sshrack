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
use super::{CRED_VALUE_COL, CredField, CredSaveError, SecretChoice, validate_cred, value_spans};
use sshrack_core::config::schema::{Credential, CredentialBody};

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

impl std::fmt::Debug for CredForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the password so `format!("{:?}", form)` / `dbg!(form)` can
        // never leak the plaintext to logs or error messages. `Zeroizing<Z>`
        // derives `Debug` by delegating to `Z`, so the derived impl would
        // otherwise print it. Mirrors the redacting Debug on `config::Secret`.
        // `identity` holds a key file *path*, not key material, so it is safe.
        f.debug_struct("CredForm")
            .field("name", &self.name)
            .field("user", &self.user)
            .field("identity", &self.identity)
            .field("secret_kind", &self.secret_kind)
            .field("password", &"<redacted>")
            .field("focus", &self.focus)
            .field("error", &self.error)
            .field("core_error", &self.core_error)
            .field("editing", &self.editing)
            .field("orig_id", &self.orig_id)
            .finish()
    }
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
    /// active [`super::super::intent::Overlay`] (`CredWizard`), so it never collides with
    /// the host wizard's [`Outcome::SaveHost`].
    ///
    /// Bindings mirror [`super::HostForm::on_key`]:
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
    ///
    /// [`Secret::Plain`]: sshrack_core::config::schema::Secret::Plain
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
    /// typed (the masked password counts its chars). Pure;
    /// [`CredForm::draw_in_dialog`] consumes it to call
    /// `Frame::set_cursor_position`.
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

    /// Content row count the dialog should size to: reachable fields + 1 error
    /// line + 1 hint line. Consumed by the App overlay layer to size the dialog
    /// via [`crate::tui::dialog::draw_dialog`].
    pub fn body_rows(&self) -> u16 {
        self.reachable_fields().len() as u16 + 2
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
    //! Pure-logic tests for the credential wizard: `validate_cred` (TDD core),
    //! the form's `on_key` state machine, secret-kind cycling, `build_body`,
    //! the `new_edit` prefill, and a render smoke through the real Dialog
    //! chrome. No terminal and no filesystem are touched.
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
        // Password is the 5th reachable field when secret_kind == Password.
        assert_eq!(f.cursor_target(), Some((4, 7)));
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
}
