//! The Credentials panel: query + ranked credential list. Mirrors the Hosts
//! panel ([`super::launcher::Launcher`]) but over [`Credential`]s, with **no
//! frecency** — credentials rank alphabetically when the query is empty and by
//! nucleo fuzzy match when one is supplied.
//!
//! This module is the view layer over credentials: [`CredPanel`] holds the
//! query/selection/ranked-list state, [`CredPanel::on_key`] is a **pure**
//! decision function (no I/O — the event loop in [`super::app`] applies its
//! [`Outcome`]), and [`CredPanel::draw_in_shell`] renders into the shell's
//! panel area.
//!
//! Ranking contract (delegated to the shared [`super::panel::rank_by_name`]):
//! - **Empty query** — every credential returned, ordered by name ascending
//!   (frecency scores are all zero on this panel, so the name-ascending
//!   tiebreak is the whole ordering).
//! - **Non-empty query** — credentials fuzzy-matched against their `name` via
//!   nucleo; non-matches excluded. Matches ordered by descending nucleo score,
//!   then name ascending.
//!
//! Security invariant: **no secret material is ever rendered.** Each row shows
//! the credential's `name` plus a dimmed `user · kind` secondary (kind ∈
//! password / identity / none). The [`SecretKind`] mapping never reads
//! `body.password` plaintext.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListState, Paragraph},
};
use sshrack_core::config::schema::{Credential, SecretKind};

use super::app::{Outcome, Status};
use super::panel::rank_by_name;

/// The default status line shown beneath the credential list when no transient
/// message is set. Mirrors the launcher's centralized STATUS_LINE.
const STATUS_LINE: &str = "Enter edit  ·  ^a add  ·  ^e edit  ·  ^d del  ·  F1 help";

/// Interactive credential panel state: the live query, the cursor into the
/// ranked list, and the (recomputed on each keystroke) ranked list of original
/// indices into the source `&[Credential]` slice.
///
/// Like the [`Launcher`](super::launcher::Launcher), the panel holds **no
/// credential data of its own** — it carries only indices into the
/// `&[Credential]` slice owned by [`super::app::App`]. This keeps the view a
/// thin layer over core and avoids copying credentials on every keystroke.
#[derive(Debug, Clone)]
pub struct CredPanel {
    /// The fuzzy query string the user is typing.
    pub query: String,
    /// The selected index into [`CredPanel::ranked`] (clamped to the list).
    pub selected: usize,
    /// The ranked credential list (original indices into the source slice),
    /// recomputed by [`CredPanel::recompute`] on every query change. Empty when
    /// there are no credentials or no matches.
    pub ranked: Vec<usize>,
}

impl CredPanel {
    /// Construct a fresh panel with an empty query and empty ranking. The
    /// caller runs [`CredPanel::recompute`] once the credential slice is
    /// available so the initial alphabetical ranking is ready to render.
    pub fn new() -> Self {
        Self {
            query: String::new(),
            selected: 0,
            ranked: Vec::new(),
        }
    }

    /// Recompute [`CredPanel::ranked`] from the current query and clamp the
    /// selection back into range. Called after every mutation of `query` (and
    /// once after the credential slice is loaded / reloaded). Pure: no I/O.
    pub fn recompute(&mut self, creds: &[Credential]) {
        self.ranked = rank_credentials(creds, &self.query);
        self.clamp_selection();
    }

    /// Clamp [`CredPanel::selected`] into `[0, ranked.len())`. When the list is
    /// empty the selection stays at `0` (the view shows an empty-state line).
    fn clamp_selection(&mut self) {
        if self.ranked.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len() - 1;
        }
    }

    /// Move the selection by `delta` (signed), wrapping at the ends. A no-op
    /// when the list is empty. Pure.
    fn move_selection(&mut self, delta: i32) {
        let len = self.ranked.len();
        if len == 0 {
            return;
        }
        let cur = self.selected as i32;
        // `rem_euclid` yields a non-negative result, so the `as usize` cast is
        // safe.
        let new = (cur + delta).rem_euclid(len as i32) as usize;
        self.selected = new;
    }

    /// The credential currently under the cursor, if any. Returns `None` when
    /// the ranked list is empty (nothing to select).
    pub fn selected_credential<'a>(&self, creds: &'a [Credential]) -> Option<&'a Credential> {
        self.ranked.get(self.selected).and_then(|&i| creds.get(i))
    }

    /// Pure key decision: inspect `key`, mutate query/selection, and return
    /// what the loop should do next. Performs **no I/O**.
    ///
    /// Bindings (mirrors the [`Launcher`](super::launcher::Launcher) panel-key
    /// surface — Ctrl-A/E/D/Enter are handled by [`super::app::App::route_panel`],
    /// NOT here):
    /// - printable char (no Ctrl) → append to query, recompute, clamp
    /// - `Backspace` → pop, recompute
    /// - `Down` / `Ctrl-N` → selection down (wraps); `Up` / `Ctrl-P` → up
    /// - everything else → [`Outcome::Continue`] (the App layer handles Esc,
    ///   Ctrl-C, Ctrl-A/E/D, Enter, F1, Tab before reaching here)
    pub fn on_key(&mut self, key: KeyEvent, creds: &[Credential]) -> Outcome {
        // Only react to Press events; Release/Repeat are ignored (crossterm
        // emits them on some platforms).
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Backspace => {
                self.query.pop();
                self.recompute(creds);
                Outcome::Continue
            }
            KeyCode::Down if !ctrl => {
                self.move_selection(1);
                Outcome::Continue
            }
            KeyCode::Char('n') if ctrl => {
                self.move_selection(1);
                Outcome::Continue
            }
            KeyCode::Up if !ctrl => {
                self.move_selection(-1);
                Outcome::Continue
            }
            KeyCode::Char('p') if ctrl => {
                self.move_selection(-1);
                Outcome::Continue
            }
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute(creds);
                Outcome::Continue
            }
            _ => Outcome::Continue,
        }
    }

    /// Render the panel into the shell's panel area (no outer border — the
    /// shell supplies the brand/tab/footer bands around it). Splits `area` into
    /// `[search(1), list(Fill), status(1)]`, renders the search row + ranked
    /// list + status row. Mirrors
    /// [`Launcher::draw_in_shell`](super::launcher::Launcher::draw_in_shell):
    /// same `bg(DarkGray)` selection + `▍` search-cursor glyph (Task 10 swaps
    /// both to the theme's selected gutter + a pure cursor).
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        creds: &[Credential],
        status: &Status,
    ) {
        let [search_area, list_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        // Search row: `❯ <query>` with the real terminal cursor at the end. The
        // `▍` glyph is retained for now; Task 10 swaps to a pure cursor.
        let search_line = Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(&self.query),
            Span::styled("▍", Style::new().dim()),
        ]);
        frame.render_widget(Paragraph::new(search_line), search_area);
        // Place the terminal cursor right after the query (2-cell `❯ ` prefix).
        let cursor_x = search_area.x + 2 + self.query.chars().count() as u16;
        let max_x = search_area.x + search_area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), search_area.y));

        self.draw_list(frame, list_area, creds);

        // Status row: app status (red on error) > default key-binding hint.
        let line = if let Some(msg) = &status.message {
            let style = if status.is_error {
                Style::new().fg(Color::Red)
            } else {
                Style::new()
            };
            Line::from(vec![
                Span::styled("status: ", Style::new().dim()),
                Span::styled(msg.clone(), style),
            ])
        } else {
            Line::from(STATUS_LINE).style(Style::new().dim())
        };
        frame.render_widget(Paragraph::new(line), status_area);
    }

    /// Render the ranked credential list with selection highlight. Shows an
    /// empty-state line when there is nothing to list. Mirrors the launcher's
    /// `draw_list` shape.
    fn draw_list(&self, frame: &mut Frame, area: ratatui::layout::Rect, creds: &[Credential]) {
        let items: Vec<Line> = self
            .ranked
            .iter()
            .map(|&idx| cred_row(&creds[idx]))
            .collect();

        if items.is_empty() {
            let msg = if creds.is_empty() {
                "No credentials configured. Press ^a to add one."
            } else {
                "No credentials match your query."
            };
            let block = Block::new()
                .borders(Borders::NONE)
                .title(" sshrack — credentials ");
            frame.render_widget(&block, area);
            let [inner] = Layout::vertical([Constraint::Fill(1)]).areas(block.inner(area));
            frame.render_widget(
                Paragraph::new(msg)
                    .style(Style::new().dim())
                    .alignment(Alignment::Center),
                inner,
            );
            return;
        }

        let list = List::new(items)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(" sshrack — credentials "),
            )
            .highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let mut state = ListState::default();
        state.select(Some(self.selected));
        frame.render_stateful_widget(list, area, &mut state);
    }
}

/// Rank credentials for display: empty query → alphabetical (frecency scores are
/// all zero on this panel, so the name-ascending tiebreak is the whole order);
/// non-empty query → only nucleo matches, by match score desc then name asc.
/// Returns the original indices into `creds` in display order.
///
/// Delegates to the shared [`rank_by_name`] helper so host and credential lists
/// rank identically. Pure: no I/O.
pub fn rank_credentials(creds: &[Credential], query: &str) -> Vec<usize> {
    let names: Vec<String> = creds.iter().map(|c| c.name.clone()).collect();
    // Credentials carry no frecency; pass all-zero scores so the name-ascending
    // tiebreak is the only signal on the empty-query branch.
    let scores = vec![0.0_f64; creds.len()];
    rank_by_name(&names, &scores, query)
}

/// Build the display line for one credential: the name, a dimmed secondary
/// `user · kind`. `kind` ∈ password / identity / none; **no secret plaintext is
/// ever read** — only [`CredentialBody::secret_kind`](SecretKind) is consulted.
fn cred_row(cred: &Credential) -> Line<'static> {
    let user = cred.body.user.clone();
    let kind = match cred.body.secret_kind() {
        SecretKind::Password | SecretKind::KeyringPassword => "password",
        SecretKind::Key => "identity",
        SecretKind::Default => "none",
    };
    Line::from(vec![
        Span::raw(cred.name.clone()),
        Span::raw("   "),
        Span::styled(format!("{user} · {kind}"), Style::new().dim()),
    ])
}

#[cfg(test)]
mod tests {
    //! Purity tests for the credential panel's ranking/filter/selection logic:
    //! alphabetical empty-query ranking, the fuzzy-match filter, the cursor,
    //! and that printable chars enter the query (no single-char hotkeys). No
    //! terminal or event source is touched.
    use super::*;
    use crossterm::event::KeyEvent;
    use sshrack_core::config::schema::{Credential, CredentialBody};

    /// Build a default-only credential (user `u`, no secret) named `name`.
    fn cred(name: &str, user: &str) -> Credential {
        Credential {
            id: ulid::Ulid::new(),
            name: name.into(),
            body: CredentialBody::new(user),
        }
    }

    /// A Press KeyEvent with no modifiers and the given code.
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    #[test]
    fn empty_query_ranks_alphabetically() {
        let creds = vec![cred("beta", "u"), cred("alpha", "u")];
        let order = rank_credentials(&creds, "");
        assert_eq!(order, vec![1, 0]); // alpha, beta
    }

    #[test]
    fn query_filters_by_name() {
        let creds = vec![cred("web-prod", "u"), cred("db", "u"), cred("web-dev", "u")];
        let order = rank_credentials(&creds, "web");
        let names: Vec<&str> = order.iter().map(|i| creds[*i].name.as_str()).collect();
        assert_eq!(names, vec!["web-dev", "web-prod"]);
    }

    #[test]
    fn printable_chars_enter_query() {
        let mut p = CredPanel::new();
        let creds = vec![cred("c-name", "u")];
        p.on_key(key(KeyCode::Char('c')), &creds); // 'c' must be a query char, not a hotkey
        assert_eq!(p.query, "c");
    }

    #[test]
    fn backspace_pops_query() {
        let mut p = CredPanel::new();
        let creds = vec![cred("a", "u")];
        p.on_key(key(KeyCode::Char('a')), &creds);
        p.on_key(key(KeyCode::Backspace), &creds);
        assert!(p.query.is_empty());
    }

    #[test]
    fn down_then_up_moves_selection_and_wraps() {
        let mut p = CredPanel::new();
        let creds = vec![cred("a", "u"), cred("b", "u"), cred("c", "u")];
        p.recompute(&creds);
        assert_eq!(p.selected, 0);
        p.on_key(key(KeyCode::Down), &creds);
        assert_eq!(p.selected, 1);
        p.on_key(key(KeyCode::Down), &creds);
        p.on_key(key(KeyCode::Down), &creds); // wrap
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn ctrl_n_ctrl_p_move_selection() {
        let mut p = CredPanel::new();
        let creds = vec![cred("a", "u"), cred("b", "u")];
        p.recompute(&creds);
        p.on_key(
            KeyEvent::new_with_kind(
                KeyCode::Char('n'),
                KeyModifiers::CONTROL,
                KeyEventKind::Press,
            ),
            &creds,
        );
        assert_eq!(p.selected, 1);
        p.on_key(
            KeyEvent::new_with_kind(
                KeyCode::Char('p'),
                KeyModifiers::CONTROL,
                KeyEventKind::Press,
            ),
            &creds,
        );
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn plain_n_is_a_query_char_not_navigation() {
        let mut p = CredPanel::new();
        let creds = vec![cred("n", "u")];
        let outcome = p.on_key(key(KeyCode::Char('n')), &creds);
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(p.query, "n");
    }

    #[test]
    fn selection_clamps_after_filter_shrinks_list() {
        let mut p = CredPanel::new();
        let creds = vec![cred("web1", "u"), cred("web2", "u"), cred("db", "u")];
        p.recompute(&creds);
        // Move selection to index 2 (db), then filter to "web" so the list
        // shrinks to 2 and the old index is out of range.
        p.on_key(key(KeyCode::Down), &creds);
        p.on_key(key(KeyCode::Down), &creds);
        assert_eq!(p.selected, 2);
        p.on_key(key(KeyCode::Char('w')), &creds);
        assert_eq!(p.ranked.len(), 2);
        assert!(p.selected < p.ranked.len(), "selection must clamp");
    }

    #[test]
    fn move_selection_on_empty_list_is_a_noop() {
        let mut p = CredPanel::new();
        let creds: Vec<Credential> = vec![];
        p.on_key(key(KeyCode::Down), &creds);
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn selected_credential_returns_cursor_target() {
        let mut p = CredPanel::new();
        let creds = vec![cred("a", "u"), cred("b", "u")];
        p.recompute(&creds);
        assert_eq!(
            p.selected_credential(&creds).map(|c| c.name.as_str()),
            Some("a")
        );
        p.on_key(key(KeyCode::Down), &creds);
        assert_eq!(
            p.selected_credential(&creds).map(|c| c.name.as_str()),
            Some("b")
        );
    }

    #[test]
    fn selected_credential_none_when_no_credentials() {
        let p = CredPanel::new();
        let creds: Vec<Credential> = vec![];
        assert!(p.selected_credential(&creds).is_none());
    }

    #[test]
    fn key_release_is_ignored() {
        let mut p = CredPanel::new();
        let creds = vec![cred("a", "u")];
        let release =
            KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release);
        let outcome = p.on_key(release, &creds);
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(p.selected, 0, "Release must not move the selection");
    }

    #[test]
    fn kind_label_maps_each_secret_kind_without_plaintext() {
        // Never read body.password; the row only consults secret_kind(). Build
        // one credential per kind and assert the rendered line text.
        use sshrack_core::config::schema::{CredentialBody, Secret};
        use std::path::PathBuf;

        let mk = |name: &str, body: CredentialBody| Credential {
            id: ulid::Ulid::new(),
            name: name.into(),
            body,
        };
        let pw = mk("pw", CredentialBody::new("u").with_password("hunter2"));
        let key = mk(
            "key",
            CredentialBody::new("u").with_key(PathBuf::from("/k")),
        );
        let kr = mk(
            "kr",
            CredentialBody {
                user: "u".into(),
                password: None,
                key: None,
                keyring: true,
            },
        );
        let none = mk("none", CredentialBody::new("u"));

        // Render each row and assert the secondary text contains the right kind
        // label AND never the plaintext password.
        let pw_line = format!("{}", cred_row(&pw));
        assert!(pw_line.contains("password"), "pw_line: {pw_line}");
        assert!(!pw_line.contains("hunter2"), "plaintext leaked: {pw_line}");

        let key_line = format!("{}", cred_row(&key));
        assert!(key_line.contains("identity"), "key_line: {key_line}");

        let kr_line = format!("{}", cred_row(&kr));
        assert!(kr_line.contains("password"), "kr_line: {kr_line}");

        let none_line = format!("{}", cred_row(&none));
        assert!(none_line.contains("none"), "none_line: {none_line}");

        // Touch Secret so the unused import stays meaningful in this test.
        let _ = Secret::Plain("x".into());
    }

    #[test]
    fn query_no_matches_returns_empty_ranking() {
        let creds = vec![cred("alpha", "u"), cred("beta", "u")];
        let mut p = CredPanel::new();
        p.query = "zzz".into();
        p.recompute(&creds);
        assert!(p.ranked.is_empty());
    }

    #[test]
    fn recompute_after_query_change_updates_ranking() {
        let creds = vec![cred("web", "u"), cred("db", "u")];
        let mut p = CredPanel::new();
        p.recompute(&creds);
        assert_eq!(p.ranked.len(), 2);
        // Typing 'w' filters to just "web".
        p.on_key(key(KeyCode::Char('w')), &creds);
        assert_eq!(p.ranked.len(), 1);
        assert_eq!(creds[p.ranked[0]].name, "web");
    }
}
