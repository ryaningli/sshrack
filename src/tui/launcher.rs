//! Host launcher: pure frecency + nucleo fuzzy ranking (data layer) plus the
//! interactive view layer (state, render, key handling).
//!
//! This module has two halves, both pure (no I/O):
//!
//! - **Data** — [`rank_hosts`] ranks a slice of [`Host`]s by frecency (empty
//!   query) or nucleo fuzzy match (non-empty query). Fully unit-testable.
//! - **View** — [`Launcher`] holds the query/selection/ranked-list state and a
//!   [`Launcher::on_key`] decision function. `on_key` performs no I/O; the
//!   event loop in [`super::app`] applies its [`Outcome`].
//!
//! Ranking contract:
//! - **Empty query** — every host is returned, ordered by frecency score
//!   descending with a name-ascending tiebreak (via the shared
//!   [`crate::tui::panel::rank_by_name`] helper over all hosts).
//! - **Non-empty query** — hosts are fuzzy-matched against their `name` via
//!   nucleo; non-matches are excluded. Matches are ordered by descending
//!   nucleo match score, tie-broken by frecency score then name ascending.
//!
//! The returned [`RankedHost`] carries the original slice index (`host_idx`)
//! so the view can render into the source list without copying hosts, plus the
//! nucleo `score` (0 for the empty-query frecency branch).

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListState, Paragraph},
};
use sshrack_core::config::schema::{Auth, Credential, Host};
use sshrack_core::frecency::Frecency;
use ulid::Ulid;

use super::intent::Outcome;
use super::theme;

// NOTE: the launcher no longer carries a status row or a `status` field — the
// shell footer (band 3) is the single status surface. `^a`/`^e`/Enter-no-host
// feedback now flows through `App::status` (set by the App-layer routing that
// intercepts those keys before they reach the launcher).

/// A ranked host: its index into the source `&[Host]` slice plus the match
/// score that placed it there.
///
/// `score` is the nucleo fuzzy match score when a query was supplied, or `0`
/// for the empty-query frecency-only branch (where ordering, not score, is the
/// useful signal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedHost {
    /// Index into the `&[Host]` slice passed to [`rank_hosts`].
    pub host_idx: usize,
    /// nucleo match score (0 on the empty-query branch). Read only by tests
    /// (production callers key off `host_idx` and the list order); kept so the
    /// score survives ranking and is assertable.
    #[allow(dead_code)]
    pub score: u32,
}

/// Rank hosts by frecency (empty query) or nucleo fuzzy match (non-empty).
///
/// Pure: no I/O, no printing, no env access. See the module docs for the full
/// contract.
///
/// Delegates ordering to [`crate::tui::panel::rank_by_name`], the shared
/// helper that the Credentials panel also uses, then re-attaches the nucleo
/// match score (0 on the empty-query branch) that [`RankedHost::score`]
/// carries for callers/tests.
pub fn rank_hosts(hosts: &[Host], frecency: &Frecency, query: &str) -> Vec<RankedHost> {
    // Pair each host with its original slice index and its frecency score —
    // the same score source the previous inlined comparator used
    // (`frecency.score(&id)`). `rank_by_name` consumes parallel slices and
    // returns display-ordered original indices.
    let names: Vec<String> = hosts.iter().map(|h| h.name.clone()).collect();
    let scores: Vec<f64> = hosts.iter().map(|h| frecency.score(&h.id)).collect();
    let order = crate::tui::panel::rank_by_name(&names, &scores, query);

    if query.is_empty() {
        // Empty-query branch reports score 0 (ordering is the signal).
        order
            .into_iter()
            .map(|i| RankedHost {
                host_idx: i,
                score: 0,
            })
            .collect()
    } else {
        // Re-attach the nucleo match score for each matched host. The pattern
        // is deterministic, so re-scoring post-sort yields the same value as
        // the pre-sort score `rank_by_name` used internally.
        let mut matcher = Matcher::new(Config::DEFAULT);
        let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
        order
            .into_iter()
            .map(|i| RankedHost {
                host_idx: i,
                score: pattern
                    .score(Utf32Str::Ascii(hosts[i].name.as_bytes()), &mut matcher)
                    .unwrap_or(0),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// View layer: Launcher state, render, and pure key handling.
// ---------------------------------------------------------------------------

/// A frecency tier label for display. Mirrors core's 4-tier decay so the user
/// sees a meaningful bucket, not a raw float.
fn frecency_tier(score: f64) -> &'static str {
    if score <= 0.0 {
        "—"
    } else if score < 2.0 {
        "low"
    } else if score < 10.0 {
        "mid"
    } else {
        "high"
    }
}

/// Interactive launcher state: the live query, the cursor into the ranked
/// list, the (recomputed on each keystroke) ranked list, and the
/// pending-connect intent set by Enter.
///
/// The launcher holds **no host data of its own** — it carries only indices
/// into the `&[Host]` slice owned by [`super::app::App`]. This keeps the view
/// a thin layer over core and avoids copying hosts on every keystroke.
///
/// `pending_connect` is the pure-intent channel from `on_key` (which does no
/// I/O) to the event loop: Enter sets it, the loop reads and clears it, then
/// runs the I/O-heavy connect orchestration. Keeping the intent here (rather
/// than in the [`Outcome`]) lets the loop also clear `should_quit`-style
/// booleans and lets a future wizard reuse the same pattern.
#[derive(Debug, Clone)]
pub struct Launcher {
    /// The fuzzy query string the user is typing.
    pub query: String,
    /// The selected index into [`Launcher::ranked`] (clamped to the list).
    pub selected: usize,
    /// The ranked host list, recomputed by [`Launcher::recompute`] on every
    /// query change. Empty when there are no hosts or no matches.
    pub ranked: Vec<RankedHost>,
    /// Set by `on_key` when the user presses Enter on a host. The event loop
    /// reads this (clearing it on cancel), then runs connect orchestration.
    /// `on_key` performs NO I/O, so this is the pure bridge to the loop.
    pub pending_connect: Option<Ulid>,
}

impl Launcher {
    /// Construct a fresh launcher over an already-ranked empty query. The
    /// caller passes the full host slice and frecency so the initial ranking
    /// (frecency order, no filter) is ready to render immediately.
    pub fn new(hosts: &[Host], frecency: &Frecency) -> Self {
        let ranked = rank_hosts(hosts, frecency, "");
        Self {
            query: String::new(),
            selected: 0,
            ranked,
            pending_connect: None,
        }
    }

    /// Recompute [`Launcher::ranked`] from the current query and clamp the
    /// selection back into range. Called after every mutation of `query` (and
    /// once at construction). Pure: no I/O.
    pub fn recompute(&mut self, hosts: &[Host], frecency: &Frecency) {
        self.ranked = rank_hosts(hosts, frecency, &self.query);
        self.clamp_selection();
    }

    /// Clamp [`Launcher::selected`] into `[0, ranked.len())`. When the list is
    /// empty the selection stays at `0` (the view shows an empty-state line
    /// rather than indexing into nothing).
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
        // Saturate delta to the list range, then wrap modulo len so a move past
        // the bottom wraps to the top (and vice versa). The `as usize` cast is
        // safe because `new` is non-negative after the wrap.
        let cur = self.selected as i32;
        let new = (cur + delta).rem_euclid(len as i32) as usize;
        self.selected = new;
    }

    /// The host currently under the cursor, if any. Returns `None` when the
    /// ranked list is empty (nothing to select).
    pub fn selected_host<'a>(&self, hosts: &'a [Host]) -> Option<&'a Host> {
        self.ranked.get(self.selected).map(|r| &hosts[r.host_idx])
    }

    /// Pure key decision: inspect `key`, mutate query/selection, and return
    /// what the loop should do next. Performs **no I/O**.
    ///
    /// Bindings:
    /// - printable char → append to query, recompute, clamp
    /// - `Backspace` → pop, recompute
    /// - `Esc` → clear query if non-empty, else [`Outcome::Quit`]
    /// - `Ctrl-C` (exact) → [`Outcome::Quit`]
    /// - `Down` / `Ctrl-N` → selection down; `Up` / `Ctrl-P` → selection up
    /// - `Enter` → set [`Launcher::pending_connect`] and return
    ///   [`Outcome::ConnectRequested`] (pure intent; the loop runs the
    ///   I/O-heavy connect orchestration). When no host is under the cursor,
    ///   returns [`Outcome::Continue`] (the App layer surfaces the "no host
    ///   selected" status via its own `status` channel).
    /// - `^a` / `^e` → [`Outcome::Continue`] (the App-level `on_key` intercepts
    ///   these to open the wizard before reaching here, so these are
    ///   fallbacks); `^d` and `F1`/`?` are intercepted at the App level too
    ///   (delete intent / help overlay).
    ///
    /// The launcher no longer carries a `status` field: the shell footer is
    /// the single status surface, and deferred-action feedback flows through
    /// `App::status` (set by App-layer routing).
    pub fn on_key(&mut self, key: KeyEvent, hosts: &[Host], frecency: &Frecency) -> Outcome {
        // Only react to Press events; Release/Repeat are ignored (crossterm
        // emits them on some platforms).
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // Ctrl-C must be EXACTLY Control+c — `contains` would wrongly treat
        // Ctrl-Shift-C (terminal paste) as quit.
        let ctrl_c_only = key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c');

        if ctrl_c_only {
            return Outcome::Quit;
        }

        match key.code {
            KeyCode::Esc => {
                if self.query.is_empty() {
                    Outcome::Quit
                } else {
                    self.query.clear();
                    self.recompute(hosts, frecency);
                    Outcome::Continue
                }
            }
            KeyCode::Enter => {
                // Pure intent: signal that the user wants to connect to the host
                // under the cursor. We set `pending_connect` and return
                // `ConnectRequested`; the event loop (run_loop) reads the id and
                // runs the I/O-heavy connect orchestration (vault unlock popup,
                // host-key popup, frecency save). on_key itself does NO I/O.
                match self.selected_host(hosts) {
                    Some(h) => {
                        self.pending_connect = Some(h.id);
                        Outcome::ConnectRequested
                    }
                    None => Outcome::Continue,
                }
            }
            KeyCode::Backspace => {
                self.query.pop();
                self.recompute(hosts, frecency);
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
            // Deferred views: App-layer routing intercepts ^a/^e to open the
            // wizard; reaching here is a fallback that simply continues.
            KeyCode::Char('a') if ctrl => Outcome::Continue,
            KeyCode::Char('e') if ctrl => Outcome::Continue,
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute(hosts, frecency);
                Outcome::Continue
            }
            _ => Outcome::Continue,
        }
    }

    /// Render the launcher into the shell's panel area (no outer border — the
    /// shell supplies the brand/tab/footer bands around it, including the
    /// status footer). Splits `area` into `[search(1), list(Fill)]` and renders
    /// the search row + ranked list. Reuses `host_line` / `highlighted_name` /
    /// `host_user` / `frecency_tier`. The search row places the real terminal
    /// cursor at the end of the query via `set_cursor_position`.
    ///
    /// Selection styling: the selected row carries `theme::focus_marker(true)`
    /// (a Cyan `▶ `) as its first span and is rendered `BOLD`; every other row
    /// carries `theme::focus_marker(false)` (two spaces) so the names align
    /// under the marker. There is no dark-background selection bar — the
    /// marker + bold is the whole signal, matching the wizard's focused-field
    /// marker.
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        hosts: &[Host],
        frecency: &Frecency,
        credentials: &[Credential],
    ) {
        let [search_area, list_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);

        // Search row: `❯ <query>` with the real terminal cursor placed right
        // after the query (no fake cursor glyph — the cursor is the terminal's).
        let search_line = Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(&self.query),
        ]);
        frame.render_widget(Paragraph::new(search_line), search_area);
        // Place the terminal cursor right after the query (2-cell `❯ ` prefix).
        let cursor_x = search_area.x + 2 + self.query.chars().count() as u16;
        let max_x = search_area.x + search_area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), search_area.y));

        self.draw_list(frame, list_area, hosts, frecency, credentials);
    }

    /// Render the ranked host list with the selected-row marker and per-host
    /// fuzzy-match highlighting. Shows an empty-state line when there is
    /// nothing to list. No outer border (the shell supplies the chrome).
    fn draw_list(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        hosts: &[Host],
        frecency: &Frecency,
        credentials: &[Credential],
    ) {
        if self.ranked.is_empty() {
            let msg = if hosts.is_empty() {
                "No hosts configured. Press ^a to add one."
            } else {
                "No hosts match your query."
            };
            frame.render_widget(
                Paragraph::new(msg)
                    .style(Style::new().dim())
                    .alignment(Alignment::Center),
                super::parts::vertical_center(area, 1),
            );
            return;
        }

        // Adaptive name column: the widest visible name, capped at
        // NAME_COL_CAP so a single very long name can't squeeze the address
        // column off the row.
        let name_w = self
            .ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.chars().count())
            .max()
            .unwrap_or(0)
            .min(NAME_COL_CAP);

        // Bake the marker into each item: the selected row carries
        // `theme::focus_marker(true)` (Cyan `▶ `); every other row carries
        // `theme::focus_marker(false)` (two spaces) so names align.
        // `highlight_style` then adds BOLD to the whole selected row — no
        // dark-background selection bar.
        let items: Vec<Line> = self
            .ranked
            .iter()
            .enumerate()
            .map(|(i, r)| {
                host_line(
                    &hosts[r.host_idx],
                    &self.query,
                    credentials,
                    frecency,
                    i == self.selected,
                    name_w,
                    area.width,
                )
            })
            .collect();

        let list = List::new(items).highlight_style(Style::new().add_modifier(Modifier::BOLD));

        let mut state = ListState::default();
        state.select(Some(self.selected));
        frame.render_stateful_widget(list, area, &mut state);
    }
}

/// Width cap for the adaptive name column. Names longer than this overflow
/// gracefully into the gap rather than squeezing the address column.
const NAME_COL_CAP: usize = 20;

/// The connect user for a host: the referenced credential's user for
/// [`Auth::Ref`] (resolved from the credential slice), or the inline body's
/// user. Falls back to `?` when there is no resolvable user (dangling ref or
/// empty inline user) so the `user@host:port` line always has a user slot.
fn host_user(host: &Host, credentials: &[Credential]) -> String {
    match &host.auth {
        Auth::Ref { credential } => credentials
            .iter()
            .find(|c| &c.id == credential)
            .map(|c| c.body.user.clone())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "?".into()),
        Auth::Inline(body) => {
            if body.user.is_empty() {
                "?".into()
            } else {
                body.user.clone()
            }
        }
    }
}

/// Build the display line for one host: the focus marker (`▶ ` when selected,
/// two spaces otherwise), the name padded to `name_w` with fuzzy-match
/// highlighting, a dimmed `user@host:port` address column, and the frecency
/// tier right-aligned to `width`. The credential NAME is no longer shown — the
/// user is the load-bearing piece for "who will I connect as".
fn host_line(
    host: &Host,
    query: &str,
    credentials: &[Credential],
    frecency: &Frecency,
    selected: bool,
    name_w: usize,
    width: u16,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::with_capacity(8);
    spans.push(theme::focus_marker(selected));

    // Name column (padded to name_w) with fuzzy-match highlighting.
    spans.extend(highlighted_name(&host.name, query));
    let name_pad = name_w.saturating_sub(host.name.chars().count());
    spans.push(Span::raw(" ".repeat(name_pad)));
    spans.push(Span::raw("  ")); // gap between name and address

    // Address column: user@host:port.
    let user = host_user(host, credentials);
    let addr = format!("{user}@{}:{}", host.host, host.port);
    let addr_len = addr.chars().count();
    spans.push(Span::styled(addr, Style::new().dim()));

    // Tier badge right-aligned to the list area's right edge.
    let tier = frecency_tier(frecency.score(&host.id));
    let tier_str = format!("[{tier}]");
    let used = 2 + name_w + 2 + addr_len;
    let tier_block = format!("  {tier_str}"); // 2 leading spaces + badge
    let fill = (width as usize).saturating_sub(used + tier_block.chars().count());
    spans.push(Span::raw(" ".repeat(fill)));
    spans.push(Span::styled(
        tier_block,
        Style::new().fg(theme::ACCENT).dim(),
    ));

    Line::from(spans)
}

/// Render a host's name as a sequence of spans, with the fuzzy-matched
/// characters (per nucleo) highlighted bold + `theme::MATCH`. When the query
/// is empty the whole name is one plain span.
fn highlighted_name(name: &str, query: &str) -> Vec<Span<'static>> {
    if query.is_empty() {
        return vec![Span::raw(name.to_string())];
    }
    let Some(matched) = match_indices(name, query) else {
        return vec![Span::raw(name.to_string())];
    };
    let highlight = Style::new().add_modifier(Modifier::BOLD).fg(theme::MATCH);
    let mut spans = Vec::with_capacity(matched.len() + 1);
    let mut prev = 0usize;
    for idx in matched {
        // `idx` is a char index; advance to the byte offset. Between `prev`
        // and the byte offset is an unmatched run rendered plain.
        let byte = char_to_byte(name, idx);
        if byte > prev {
            spans.push(Span::raw(name[prev..byte].to_string()));
        }
        // The matched char itself (one char in width).
        let next = byte
            + name[byte..]
                .chars()
                .next()
                .map(|c| c.len_utf8())
                .unwrap_or(0);
        spans.push(Span::styled(name[byte..next].to_string(), highlight));
        prev = next;
    }
    if prev < name.len() {
        spans.push(Span::raw(name[prev..].to_string()));
    }
    spans
}

/// The nucleo match indices for `query` against `name`, as char indices into
/// `name`, deduplicated and sorted. Returns `None` when the query does not
/// match (nucleo `indices` returns `None`). Pure: no I/O.
fn match_indices(name: &str, query: &str) -> Option<Vec<u32>> {
    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
    let mut indices: Vec<u32> = Vec::new();
    let _score = pattern.indices(Utf32Str::Ascii(name.as_bytes()), &mut matcher, &mut indices)?;
    // nucleo appends per-atom indices without dedup/sort (per its docs); sort
    // and dedup so highlighting is monotonic and unique.
    indices.sort_unstable();
    indices.dedup();
    Some(indices)
}

/// Map a char index into `s` to its byte offset. Falls back to `s.len()` for
/// an out-of-range index so a malformed index never panics.
fn char_to_byte(s: &str, char_idx: u32) -> usize {
    s.char_indices()
        .nth(char_idx as usize)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

#[cfg(test)]
mod tests {
    //! Purity tests for the launcher's ranking/filter/selection logic: the
    //! frecency-tier sort, the fuzzy-match filter, and the cursor + Enter →
    //! pending_connect intent. No terminal or event source is touched.
    use super::*;
    use sshrack_core::config::schema::{Credential, CredentialBody, Host};
    use sshrack_core::frecency::Frecency;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use ulid::Ulid;

    /// Build a host with a fixed id (derived from `seed`) and the given name.
    fn host(seed: u128, name: &str) -> Host {
        Host {
            id: Ulid::from_string(&format!("{seed:026X}")).unwrap(),
            name: name.into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        }
    }

    /// A fixed `SystemTime` well after the epoch, for deterministic decay tiers.
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// Build a credential with id derived from `seed`, the given name + user.
    fn host_cred(user: &str, seed: u128) -> Credential {
        Credential {
            id: Ulid::from_string(&format!("{seed:026X}")).unwrap(),
            name: format!("cred-{user}"),
            body: CredentialBody::new(user),
        }
    }

    /// Build a host named `name` whose auth is the given body, with a fixed id.
    fn host_with_auth(auth: Auth) -> Host {
        Host {
            id: Ulid::from_string("01J00000000000000000000001").unwrap(),
            name: "h".into(),
            host: "h".into(),
            port: 22,
            auth,
        }
    }

    /// Build a host that references `cred`, with the given name/host/port.
    fn host_referring(cred: &Credential, name: &str, host: &str, port: u16) -> Host {
        Host {
            id: Ulid::from_string("01J00000000000000000000002").unwrap(),
            name: name.into(),
            host: host.into(),
            port,
            auth: Auth::reference(cred.id),
        }
    }

    // ---- host_user: resolve the connect user ----

    #[test]
    fn host_user_resolves_ref_to_credential_user() {
        let cred = host_cred("ops", 1);
        let host = host_with_auth(Auth::reference(cred.id));
        assert_eq!(host_user(&host, &[cred]), "ops");
    }

    #[test]
    fn host_user_is_question_mark_for_dangling_ref() {
        let host = host_with_auth(Auth::reference(
            Ulid::from_string("01J00000000000000000000000").unwrap(),
        ));
        assert_eq!(host_user(&host, &[]), "?");
    }

    #[test]
    fn host_user_uses_inline_body_or_question_mark_when_empty() {
        let host = host_with_auth(Auth::inline(CredentialBody::new("root")));
        assert_eq!(host_user(&host, &[]), "root");
        let host_empty = host_with_auth(Auth::inline(CredentialBody::new("")));
        assert_eq!(host_user(&host_empty, &[]), "?");
    }

    // ---- host_line: columns + user@host:port ----

    #[test]
    fn host_line_renders_user_at_host_port_and_aligns_columns() {
        let cred = host_cred("root", 1);
        let host = host_referring(&cred, "web1", "1.2.3.4", 22);
        let fr = Frecency::default();
        let line = host_line(&host, "", &[cred], &fr, true, 8, 40);
        let s = format!("{line}");
        assert!(s.contains("root@1.2.3.4:22"), "row text was: {s}");
        // Name column is padded to name_w=8: "web1" + 4 spaces, so the address
        // column starts at the same offset on every row.
        assert!(s.contains("web1    "), "name not padded to width 8: {s}");
    }

    #[test]
    fn host_line_uses_question_mark_when_no_user() {
        let host = host_with_auth(Auth::reference(
            Ulid::from_string("01J00000000000000000000000").unwrap(),
        ));
        let fr = Frecency::default();
        let line = host_line(&host, "", &[], &fr, false, 8, 40);
        assert!(format!("{line}").contains("?@"));
    }

    // ---- empty query: frecency order ----

    #[test]
    fn empty_query_orders_by_frecency_score_desc() {
        let alpha = host(1, "alpha");
        let beta = host(2, "beta");
        let hosts = vec![alpha, beta];
        let mut fr = Frecency::default();
        // beta used twice within an hour → higher score than alpha (used once).
        let t0 = now();
        fr.record_at(&hosts[0].id, t0); // alpha: 1.0
        fr.record_at(&hosts[1].id, t0); // beta: 1.0
        fr.record_at(&hosts[1].id, t0 + Duration::from_secs(60)); // beta: 5.0

        let ranked = rank_hosts(&hosts, &fr, "");
        let names: Vec<&str> = ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.as_str())
            .collect();
        assert_eq!(names, vec!["beta", "alpha"]);
        // Empty-query branch reports score 0 (ordering is the signal).
        assert!(ranked.iter().all(|r| r.score == 0));
    }

    #[test]
    fn empty_query_tiebreaks_by_name_ascending() {
        let bravo = host(1, "bravo");
        let alpha = host(2, "alpha");
        let hosts = vec![bravo, alpha];
        let fr = Frecency::default(); // no records → all tie at score 0.0

        let ranked = rank_hosts(&hosts, &fr, "");
        let names: Vec<&str> = ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "bravo"]);
    }

    #[test]
    fn empty_query_returns_all_hosts() {
        let hosts = vec![host(1, "a"), host(2, "b"), host(3, "c")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "");
        assert_eq!(ranked.len(), hosts.len());
        // Indices are a permutation of 0..len.
        let mut idxs: Vec<usize> = ranked.iter().map(|r| r.host_idx).collect();
        idxs.sort();
        assert_eq!(idxs, vec![0, 1, 2]);
    }

    #[test]
    fn empty_hosts_returns_empty() {
        let fr = Frecency::default();
        let ranked = rank_hosts(&[], &fr, "");
        assert!(ranked.is_empty());
    }

    // ---- non-empty query: fuzzy filter + rank ----

    #[test]
    fn query_filters_to_matches_only() {
        let web_prod = host(1, "web-prod");
        let db_staging = host(2, "db-staging");
        let web_dev = host(3, "web-dev");
        let hosts = vec![web_prod, db_staging, web_dev];
        let fr = Frecency::default();

        let ranked = rank_hosts(&hosts, &fr, "web");
        let names: Vec<&str> = ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.as_str())
            .collect();
        // db-staging excluded; both web-* hosts present.
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"web-prod"));
        assert!(names.contains(&"web-dev"));
        assert!(!names.contains(&"db-staging"));
    }

    #[test]
    fn query_ranks_consecutive_prefix_ahead_of_scattered() {
        // nucleo scores a contiguous prefix match ("web-...") higher than a
        // scattered/gap match, so "web-prod" outranks "web-dev" is not
        // guaranteed by score alone — but both match. The contract is: higher
        // score first. Pin the stronger match at position 0.
        let hosts = vec![host(1, "web-prod"), host(2, "xwyexbz")];
        let fr = Frecency::default();

        let ranked = rank_hosts(&hosts, &fr, "web");
        // "web-prod" has a clean prefix match; "xwyexbz" is a gap-filled fuzzy
        // match with lower score → ranks second.
        assert_eq!(hosts[ranked[0].host_idx].name, "web-prod");
    }

    #[test]
    fn query_tiebreaks_by_frecency_when_scores_equal() {
        // Two identical-prefix hosts: same nucleo score. The one with higher
        // frecency wins.
        let a = host(1, "web-alpha");
        let b = host(2, "web-bravo");
        let hosts = vec![a, b];
        let mut fr = Frecency::default();
        // web-bravo recorded, web-alpha not → web-bravo has higher frecency.
        fr.record_at(&hosts[1].id, now());

        let ranked = rank_hosts(&hosts, &fr, "web-");
        // Both match "web-" with equal score; frecency tiebreak → bravo first.
        assert_eq!(hosts[ranked[0].host_idx].name, "web-bravo");
        assert_eq!(hosts[ranked[1].host_idx].name, "web-alpha");
    }

    #[test]
    fn query_tiebreaks_by_name_when_score_and_frecency_equal() {
        let bravo = host(1, "web-bravo");
        let alpha = host(2, "web-alpha");
        let hosts = vec![bravo, alpha];
        let fr = Frecency::default(); // equal frecency (0.0)

        let ranked = rank_hosts(&hosts, &fr, "web-");
        let names: Vec<&str> = ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.as_str())
            .collect();
        // Equal score, equal frecency → name ascending.
        assert_eq!(names, vec!["web-alpha", "web-bravo"]);
    }

    #[test]
    fn query_no_matches_returns_empty() {
        let hosts = vec![host(1, "alpha"), host(2, "beta")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "zzz");
        assert!(ranked.is_empty());
    }

    #[test]
    fn query_is_case_insensitive_smart_match() {
        let hosts = vec![host(1, "Web-Prod")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "web");
        assert_eq!(ranked.len(), 1);
        assert_eq!(hosts[ranked[0].host_idx].name, "Web-Prod");
    }

    #[test]
    fn ranked_host_score_is_nucleo_match_score_for_query() {
        let hosts = vec![host(1, "web-prod")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "web");
        assert_eq!(ranked.len(), 1);
        // Nucleo match scores are positive for a match.
        assert!(ranked[0].score > 0);
    }

    // ---- view layer: Launcher state, on_key, render helpers ----

    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    /// A Press KeyEvent with the given code and modifiers.
    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
    }

    // ---- Task 4: visual-unification regression (focus marker + real cursor) ----

    /// Render the launcher inside the shell and assert it (a) does not panic,
    /// (b) calls `set_cursor_position` on the search row (the real terminal
    /// cursor — the fake cursor glyph must be gone), and (c) paints the
    /// selected-row focus marker `▶ ` (not the old `▎` gutter, and not a
    /// dark-background selection bar).
    #[test]
    fn draw_in_shell_renders_without_panic_sets_cursor_and_uses_focus_marker() {
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        let hosts = vec![host(1, "web")];
        let frecency = Frecency::default();
        let mut p = Launcher::new(&hosts, &frecency);
        p.query = "w".into();
        p.recompute(&hosts, &frecency);

        term.draw(|f| {
            let area = crate::tui::shell::draw_shell(
                f,
                f.area(),
                crate::tui::tab::Tab::Hosts,
                &[("Enter", "connect"), ("^A", "add")],
                &crate::tui::intent::Status::empty(),
            );
            p.draw_in_shell(f, area, &hosts, &frecency, &empty_creds());
        })
        .unwrap();

        // The fake cursor glyph must no longer be in the rendered buffer.
        let view = buffer_view(term.backend().buffer());
        assert!(
            !view.contains('\u{258d}'),
            "fake cursor glyph leaked: {view}"
        );
        // The selected row carries the focus marker `▶ `; the old `▎` gutter
        // must be gone (replaced by the wizard-style arrow marker).
        assert!(view.contains('▶'), "focus marker missing: {view}");
        assert!(!view.contains('▎'), "old gutter leaked: {view}");
        // The new user@host:port address column renders (user "u" from the
        // inline default, host "h", port 22).
        assert!(view.contains("u@h:22"), "address column missing: {view}");
        // No dark-background selection: the selected host name is present.
        assert!(view.contains("web"), "host name missing: {view}");
    }

    /// Regression for the "two identical hint lines" bug (Task 3): the panel no
    /// longer emits its own status/hint row — only the shell footer (band 3)
    /// carries hints. Render the launcher with an empty status and assert the
    /// hint text appears exactly once in the buffer (it lives only in the shell
    /// footer), not duplicated by a per-panel status row.
    #[test]
    fn draw_in_shell_does_not_emit_a_second_hint_row() {
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        let hosts = vec![host(1, "web")];
        let frecency = Frecency::default();
        let p = Launcher::new(&hosts, &frecency);

        term.draw(|f| {
            let area = crate::tui::shell::draw_shell(
                f,
                f.area(),
                crate::tui::tab::Tab::Hosts,
                &[("Enter", "connect"), ("F1", "help")],
                &crate::tui::intent::Status::empty(),
            );
            p.draw_in_shell(f, area, &hosts, &frecency, &empty_creds());
        })
        .unwrap();

        let view = buffer_view(term.backend().buffer());
        // The hint "connect" should appear exactly once — in the shell footer.
        // The `STATUS_LINE` duplication (a second `connect` from the panel's own
        // status row) must be gone.
        let occurrences = view.matches("connect").count();
        assert_eq!(
            occurrences, 1,
            "hint should appear only in the shell footer, found {occurrences} times:\n{view}"
        );
        // The launcher's own STATUS_LINE text ("^a add", "Esc quit", ...) must
        // not appear anywhere — that was the per-panel status row's content.
        assert!(
            !view.contains("Esc quit"),
            "panel status line leaked into the render:\n{view}"
        );
    }

    fn empty_creds() -> Vec<Credential> {
        Vec::new()
    }

    /// A human-readable stringification of a ratatui `Buffer` (one line per
    /// row) for substring assertions in render regression tests.
    fn buffer_view(buf: &ratatui::buffer::Buffer) -> String {
        let area = buf.area;
        let mut out = String::with_capacity((area.width as usize + 1) * area.height as usize);
        for row in 0..area.height {
            for col in 0..area.width {
                let cell = buf.cell((col, row));
                out.push_str(cell.map(|c| c.symbol()).unwrap_or(" "));
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn launcher_new_ranks_all_hosts_in_frecency_order() {
        let hosts = vec![host(1, "alpha"), host(2, "beta")];
        let fr = Frecency::default();
        let launcher = Launcher::new(&hosts, &fr);
        assert!(launcher.query.is_empty());
        assert_eq!(launcher.selected, 0);
        assert_eq!(launcher.ranked.len(), 2);
    }

    #[test]
    fn on_key_printable_char_appends_to_query_and_filters() {
        let hosts = vec![host(1, "web"), host(2, "db")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        let outcome = launcher.on_key(key(KeyCode::Char('w'), KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(launcher.query, "w");
        // Only "web" matches "w".
        assert_eq!(launcher.ranked.len(), 1);
        assert_eq!(hosts[launcher.ranked[0].host_idx].name, "web");
    }

    #[test]
    fn on_key_backspace_pops_query() {
        let hosts = vec![host(1, "web")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        launcher.on_key(key(KeyCode::Char('w'), KeyModifiers::NONE), &hosts, &fr);
        launcher.on_key(key(KeyCode::Char('x'), KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(launcher.query, "wx");
        // "wx" matches nothing.
        assert!(launcher.ranked.is_empty());
        let outcome = launcher.on_key(key(KeyCode::Backspace, KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(launcher.query, "w");
        assert_eq!(launcher.ranked.len(), 1);
    }

    #[test]
    fn on_key_esc_clears_nonempty_query_then_quits_on_second_press() {
        let hosts = vec![host(1, "web")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        launcher.on_key(key(KeyCode::Char('w'), KeyModifiers::NONE), &hosts, &fr);
        let first = launcher.on_key(key(KeyCode::Esc, KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(first, Outcome::Continue));
        assert!(launcher.query.is_empty());
        let second = launcher.on_key(key(KeyCode::Esc, KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(second, Outcome::Quit));
    }

    #[test]
    fn on_key_esc_on_empty_query_quits_immediately() {
        let hosts = vec![host(1, "web")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        let outcome = launcher.on_key(key(KeyCode::Esc, KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(outcome, Outcome::Quit));
    }

    #[test]
    fn on_key_ctrl_c_quits_regardless_of_query() {
        let hosts = vec![host(1, "web")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        launcher.on_key(key(KeyCode::Char('w'), KeyModifiers::NONE), &hosts, &fr);
        let outcome = launcher.on_key(key(KeyCode::Char('c'), KeyModifiers::CONTROL), &hosts, &fr);
        assert!(matches!(outcome, Outcome::Quit));
    }

    #[test]
    fn on_key_ctrl_shift_c_is_not_quit() {
        let hosts = vec![host(1, "web")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        let outcome = launcher.on_key(
            key(
                KeyCode::Char('c'),
                KeyModifiers::CONTROL | KeyModifiers::SHIFT,
            ),
            &hosts,
            &fr,
        );
        assert!(matches!(outcome, Outcome::Continue));
    }

    #[test]
    fn on_key_down_up_moves_and_wraps_selection() {
        let hosts = vec![host(1, "a"), host(2, "b"), host(3, "c")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        assert_eq!(launcher.selected, 0);
        launcher.on_key(key(KeyCode::Down, KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(launcher.selected, 1);
        launcher.on_key(key(KeyCode::Down, KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(launcher.selected, 2);
        // Down past the end wraps to the top.
        launcher.on_key(key(KeyCode::Down, KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(launcher.selected, 0);
        // Up from the top wraps to the bottom.
        launcher.on_key(key(KeyCode::Up, KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(launcher.selected, 2);
    }

    #[test]
    fn on_key_ctrl_n_ctrl_p_move_selection() {
        let hosts = vec![host(1, "a"), host(2, "b")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        launcher.on_key(key(KeyCode::Char('n'), KeyModifiers::CONTROL), &hosts, &fr);
        assert_eq!(launcher.selected, 1);
        launcher.on_key(key(KeyCode::Char('p'), KeyModifiers::CONTROL), &hosts, &fr);
        assert_eq!(launcher.selected, 0);
    }

    #[test]
    fn on_key_plain_n_is_a_query_char_not_navigation() {
        let hosts = vec![host(1, "n")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        let outcome = launcher.on_key(key(KeyCode::Char('n'), KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(launcher.query, "n");
    }

    #[test]
    fn on_key_enter_signals_connect_intent_with_host_id() {
        // Enter on a host sets pending_connect to that host's id and returns
        // the pure ConnectRequested intent (no I/O happens here). The event
        // loop reads pending_connect to run connect orchestration.
        let hosts = vec![host(1, "web")];
        let expected_id = hosts[0].id;
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        let outcome = launcher.on_key(key(KeyCode::Enter, KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(outcome, Outcome::ConnectRequested));
        assert_eq!(launcher.pending_connect, Some(expected_id));
    }

    #[test]
    fn on_key_enter_with_no_host_continues_without_pending_connect() {
        // Enter with an empty host list cannot select anything: stay Continue
        // and do NOT set a pending_connect. The launcher no longer carries a
        // status field; the "no host selected" feedback now flows through
        // App::status (the App-layer primary_action path).
        let hosts: Vec<Host> = vec![];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        let outcome = launcher.on_key(key(KeyCode::Enter, KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(outcome, Outcome::Continue));
        assert!(launcher.pending_connect.is_none());
    }

    #[test]
    fn on_key_ctrl_a_e_continue_as_app_layer_intercepts() {
        // `^a` and `^e` are intercepted by the App-layer routing to open the
        // host wizard before reaching the launcher; the launcher's fallback is
        // simply Continue (no status field — feedback flows through App::status).
        // Drive the launcher directly to pin the fallback behavior.
        let hosts = vec![host(1, "web")];
        let fr = Frecency::default();
        for k in [
            key(KeyCode::Char('a'), KeyModifiers::CONTROL),
            key(KeyCode::Char('e'), KeyModifiers::CONTROL),
        ] {
            let mut launcher = Launcher::new(&hosts, &fr);
            let outcome = launcher.on_key(k, &hosts, &fr);
            assert!(
                matches!(outcome, Outcome::Continue),
                "deferred key must not quit"
            );
        }
    }

    #[test]
    fn on_key_release_is_ignored() {
        let hosts = vec![host(1, "web")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        let release =
            KeyEvent::new_with_kind(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Release);
        let outcome = launcher.on_key(release, &hosts, &fr);
        assert!(matches!(outcome, Outcome::Continue));
    }

    #[test]
    fn selection_clamps_after_filter_shrinks_list() {
        let hosts = vec![host(1, "web1"), host(2, "web2"), host(3, "db")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        // Move selection to index 2 (db), then filter to "web" so the list
        // shrinks to 2 and the old index is out of range.
        launcher.on_key(key(KeyCode::Down, KeyModifiers::NONE), &hosts, &fr);
        launcher.on_key(key(KeyCode::Down, KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(launcher.selected, 2);
        launcher.on_key(key(KeyCode::Char('w'), KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(launcher.ranked.len(), 2);
        assert!(
            launcher.selected < launcher.ranked.len(),
            "selection must clamp"
        );
    }

    #[test]
    fn move_selection_on_empty_list_is_a_noop() {
        let hosts: Vec<Host> = vec![];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        launcher.on_key(key(KeyCode::Down, KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(launcher.selected, 0);
    }

    #[test]
    fn selected_host_returns_cursor_target() {
        let hosts = vec![host(1, "a"), host(2, "b")];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        assert_eq!(
            launcher.selected_host(&hosts).map(|h| h.name.as_str()),
            Some("a")
        );
        launcher.on_key(key(KeyCode::Down, KeyModifiers::NONE), &hosts, &fr);
        assert_eq!(
            launcher.selected_host(&hosts).map(|h| h.name.as_str()),
            Some("b")
        );
    }

    #[test]
    fn selected_host_none_when_no_hosts() {
        let hosts: Vec<Host> = vec![];
        let fr = Frecency::default();
        let launcher = Launcher::new(&hosts, &fr);
        assert!(launcher.selected_host(&hosts).is_none());
    }

    #[test]
    fn match_indices_returns_char_positions_for_prefix_match() {
        // "web" against "web-prod" should match positions 0,1,2.
        let indices = match_indices("web-prod", "web").unwrap();
        assert_eq!(indices, vec![0, 1, 2]);
    }

    #[test]
    fn match_indices_none_when_no_match() {
        assert!(match_indices("alpha", "zzz").is_none());
    }

    #[test]
    fn match_indices_empty_query_is_handled_by_caller_not_here() {
        // match_indices is only called with a non-empty query (highlighted_name
        // short-circuits on empty). Calling it with an empty query returns
        // Some(all indices) per nucleo's empty-pattern semantics — we don't
        // assert the exact set, only that it doesn't panic.
        let _ = match_indices("abc", "");
    }

    #[test]
    fn char_to_byte_maps_char_index_to_byte_offset() {
        // ASCII: char index == byte offset.
        assert_eq!(char_to_byte("abc", 0), 0);
        assert_eq!(char_to_byte("abc", 2), 2);
    }

    #[test]
    fn char_to_byte_out_of_range_returns_len() {
        assert_eq!(char_to_byte("ab", 9), 2);
    }

    #[test]
    fn char_to_byte_handles_multibyte() {
        // "é" is 2 bytes; the second char "b" sits at byte offset 2.
        assert_eq!(char_to_byte("éb", 1), 2);
    }

    #[test]
    fn frecency_tier_buckets() {
        assert_eq!(frecency_tier(0.0), "—");
        assert_eq!(frecency_tier(1.0), "low");
        assert_eq!(frecency_tier(5.0), "mid");
        assert_eq!(frecency_tier(20.0), "high");
    }
}
