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
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListState, Paragraph},
};
use sshrack_core::config::schema::Host;
use sshrack_core::frecency::Frecency;
use ulid::Ulid;

use super::CredentialNames;
use super::app::Outcome;

/// A ranked host: its index into the source `&[Host]` slice plus the match
/// score that placed it there.
///
/// `score` is the nucleo fuzzy match score when a query was supplied, or `0`
/// for the empty-query frecency-only branch (where ordering, not score, is the
/// useful signal).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct RankedHost {
    /// Index into the `&[Host]` slice passed to [`rank_hosts`].
    pub host_idx: usize,
    /// nucleo match score (0 on the empty-query branch).
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
#[allow(dead_code)]
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

/// The status line shown beneath the host list. Centralized so the launcher
/// and any future view stay in sync.
const STATUS_LINE: &str =
    "Enter connect  ·  ^a add  ·  ^e edit  ·  ^d del  ·  F1 help  ·  Esc quit";

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
/// list, the (recomputed on each keystroke) ranked list, a transient status
/// message, and the pending-connect intent set by Enter.
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
    /// A transient one-line message (e.g. a deferred-action notice). Cleared
    /// on the next query/edit keystroke. `None` shows the default status line.
    pub status: Option<String>,
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
            status: None,
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

    /// Pure key decision: inspect `key`, mutate query/selection/status, and
    /// return what the loop should do next. Performs **no I/O**.
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
    ///   sets a "no host selected" status and returns [`Outcome::Continue`].
    /// - `^a` / `^e` → set a "not yet implemented" status (the App-level
    ///   `on_key` intercepts these to open the wizard before reaching here, so
    ///   these branches are fallbacks); `^d` and `F1`/`?` are intercepted at the
    ///   App level too (delete intent / help overlay)
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
                    self.status = None;
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
                    None => {
                        self.status = Some("no host selected".into());
                        Outcome::Continue
                    }
                }
            }
            KeyCode::Backspace => {
                self.query.pop();
                self.recompute(hosts, frecency);
                self.status = None;
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
            // Deferred views (Tasks 16/19/20): set a status notice, no wizard.
            KeyCode::Char('a') if ctrl => {
                self.status = Some("add host — not yet implemented".into());
                Outcome::Continue
            }
            KeyCode::Char('e') if ctrl => {
                self.status = Some("edit host — not yet implemented".into());
                Outcome::Continue
            }
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute(hosts, frecency);
                self.status = None;
                Outcome::Continue
            }
            _ => Outcome::Continue,
        }
    }

    /// Render the launcher into the shell's panel area (no outer border — the
    /// shell supplies the brand/tab/footer bands around it). Splits `area` into
    /// `[search(1), list(Fill), status(1)]`, renders the search row + ranked
    /// list + status. Reuses `host_line` / `highlighted_name` /
    /// `credential_label` / `frecency_tier`. The search row places the real
    /// terminal cursor at the end of the query.
    ///
    /// Task 6 scope: keep the current selection style (`bg(DarkGray)`) and the
    /// `▍` search cursor glyph for now — Task 10 replaces them with the
    /// theme's selected gutter + a real cursor. Just get the layout right.
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        hosts: &[Host],
        frecency: &Frecency,
        credential_names: &CredentialNames,
        status: &super::app::Status,
    ) {
        let [search_area, list_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        // Search row: `❯ <query>` with the real terminal cursor at the end.
        // The `▍` glyph is retained for Task 6; Task 10 swaps to a pure cursor.
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

        self.draw_list(frame, list_area, hosts, frecency, credential_names);

        // Status row: app status (red on error) > launcher-local hint > default.
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
            match &self.status {
                Some(msg) => Line::from(vec![
                    Span::styled("status: ", Style::new().dim()),
                    Span::raw(msg.clone()),
                ]),
                None => Line::from(STATUS_LINE).style(Style::new().dim()),
            }
        };
        frame.render_widget(Paragraph::new(line), status_area);
    }

    /// Render the ranked host list with selection highlight and per-host fuzzy
    /// match highlighting. Shows an empty-state line when there is nothing to
    /// list.
    fn draw_list(
        &self,
        frame: &mut Frame,
        area: ratatui::layout::Rect,
        hosts: &[Host],
        frecency: &Frecency,
        credential_names: &CredentialNames,
    ) {
        let items: Vec<Line> = self
            .ranked
            .iter()
            .map(|r| host_line(&hosts[r.host_idx], &self.query, frecency, credential_names))
            .collect();

        if items.is_empty() {
            let msg = if hosts.is_empty() {
                "No hosts configured. Press ^a to add one (not yet implemented)."
            } else {
                "No hosts match your query."
            };
            let block = Block::new()
                .borders(Borders::NONE)
                .title(" sshrack — hosts ");
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
                    .title(" sshrack — hosts "),
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

/// Build the display line for one host: the name with fuzzy-matched chars
/// highlighted, the address/port dimmed, the credential name (or inline user)
/// dimmed, and the frecency tier on the right.
fn host_line(
    host: &Host,
    query: &str,
    frecency: &Frecency,
    credential_names: &CredentialNames,
) -> Line<'static> {
    let name_spans = highlighted_name(&host.name, query);
    let addr = format!("  {}:{}", host.host, host.port);
    let cred = credential_label(host, credential_names);
    let tier = frecency_tier(frecency.score(&host.id));

    let mut spans = name_spans;
    spans.push(Span::styled(addr, Style::new().dim()));
    spans.push(Span::styled(format!("  ({cred})"), Style::new().dim()));
    spans.push(Span::styled(
        format!("  [{tier}]"),
        Style::new().fg(Color::Cyan).dim(),
    ));

    Line::from(spans)
}

/// Render a host's name as a sequence of spans, with the fuzzy-matched
/// characters (per nucleo) highlighted bold + accent. When the query is empty
/// the whole name is one plain span.
fn highlighted_name(name: &str, query: &str) -> Vec<Span<'static>> {
    if query.is_empty() {
        return vec![Span::raw(name.to_string())];
    }
    let Some(matched) = match_indices(name, query) else {
        return vec![Span::raw(name.to_string())];
    };
    let highlight = Style::new().add_modifier(Modifier::BOLD).fg(Color::Yellow);
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

/// The display label for a host's auth: the referenced credential's name when
/// it uses `Auth::Ref`, otherwise the inline body's user (falling back to
/// `ssh default` when there is no inline user — though inline bodies always
/// carry a user, this is defensive).
fn credential_label(host: &Host, credential_names: &CredentialNames) -> String {
    match &host.auth {
        sshrack_core::config::schema::Auth::Ref { credential } => credential_names
            .get(credential)
            .cloned()
            .unwrap_or_else(|| "<missing credential>".into()),
        sshrack_core::config::schema::Auth::Inline(body) => {
            format!("@{}", body.user)
        }
    }
}

#[cfg(test)]
mod tests {
    //! Purity tests for the launcher's ranking/filter/selection logic: the
    //! frecency-tier sort, the fuzzy-match filter, and the cursor + Enter →
    //! pending_connect intent. No terminal or event source is touched.
    use super::*;
    use sshrack_core::config::schema::{Auth, CredentialBody, Host};
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
    use std::collections::HashMap;

    /// A Press KeyEvent with the given code and modifiers.
    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
    }

    fn empty_creds() -> CredentialNames {
        HashMap::new()
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
    fn on_key_enter_with_no_host_sets_status_and_continues() {
        // Enter with an empty host list cannot select anything: stay Continue,
        // set a status, and do NOT set a pending_connect.
        let hosts: Vec<Host> = vec![];
        let fr = Frecency::default();
        let mut launcher = Launcher::new(&hosts, &fr);
        let outcome = launcher.on_key(key(KeyCode::Enter, KeyModifiers::NONE), &hosts, &fr);
        assert!(matches!(outcome, Outcome::Continue));
        assert!(launcher.pending_connect.is_none());
        assert_eq!(launcher.status.as_deref(), Some("no host selected"));
    }

    #[test]
    fn on_key_ctrl_a_e_set_not_yet_implemented_status() {
        // `^d` and `F1` are now handled at the App level (delete intent / help
        // overlay), so the launcher only falls back to a "not yet implemented"
        // status for `^a` and `^e` (the App layer normally intercepts these too,
        // but the launcher keeps the fallback). Drive the launcher directly.
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
            assert!(
                launcher
                    .status
                    .as_deref()
                    .unwrap_or("")
                    .contains("not yet implemented"),
                "deferred key should set a not-yet-implemented status"
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

    #[test]
    fn credential_label_uses_credential_name_for_ref_auth() {
        let cid = Ulid::from_string("01HXYZ0000000000000000000Z").unwrap();
        let host = Host {
            id: Ulid::from_string("01HXYZ0000000000000000000A").unwrap(),
            name: "h".into(),
            host: "x".into(),
            port: 22,
            auth: sshrack_core::config::schema::Auth::reference(cid),
        };
        let mut names = empty_creds();
        names.insert(cid, "ops-key".into());
        assert_eq!(credential_label(&host, &names), "ops-key");
    }

    #[test]
    fn credential_label_shows_inline_user_for_inline_auth() {
        let host = Host {
            id: Ulid::from_string("01HXYZ0000000000000000000A").unwrap(),
            name: "h".into(),
            host: "x".into(),
            port: 22,
            auth: sshrack_core::config::schema::Auth::inline(CredentialBody::new("root")),
        };
        assert_eq!(credential_label(&host, &empty_creds()), "@root");
    }

    #[test]
    fn credential_label_missing_credential_shows_placeholder() {
        let cid = Ulid::from_string("01HXYZ0000000000000000000Z").unwrap();
        let host = Host {
            id: Ulid::from_string("01HXYZ0000000000000000000A").unwrap(),
            name: "h".into(),
            host: "x".into(),
            port: 22,
            auth: sshrack_core::config::schema::Auth::reference(cid),
        };
        assert_eq!(
            credential_label(&host, &empty_creds()),
            "<missing credential>"
        );
    }
}
