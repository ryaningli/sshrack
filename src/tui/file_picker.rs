//! Reusable, business-decoupled file-picker overlay. The host/credential
//! wizards open this on the Identity row (`Enter`); it returns the chosen
//! absolute path via [`FilePickerOutcome::Pick`] and the caller writes it back.
//! It imports neither `host` nor `cred`.
//!
//! Listing/classification come from the injected [`DirSource`] (core): local fs
//! now, a future `SftpDirSource` later — the component is unchanged. [`new`]
//! does no IO; the first directory is loaded lazily by [`ensure_started`] so the
//! wizard's pure `on_key` tests never touch the filesystem.
//!
//! [`new`]: FilePicker::new
//! [`ensure_started`]: FilePicker::ensure_started

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;

use sshrack_core::dirsource::{DirEntry, DirSource, LocalDirSource};
use sshrack_core::pathutil::{FilterIntent, parse_filter_intent};

/// The pure result of [`FilePicker::on_key`] handling one key. `Pick` carries
/// an absolute path (the caller writes it into its field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePickerOutcome {
    /// A file was selected (absolute path); the caller writes it back.
    Pick(std::path::PathBuf),
    /// The user cancelled (Esc / Ctrl-C); the caller closes the overlay.
    Cancel,
    /// The key was consumed but the picker is still open.
    Pending,
}

/// Modal file picker. Generic over [`DirSource`] so tests inject a fake and a
/// future sftp source reuses the component. `cwd`/`entries` are `None`/empty
/// until the lazy [`ensure_started`] resolves the start directory.
#[derive(Clone)]
pub struct FilePicker<S: DirSource + Clone = LocalDirSource> {
    /// Overlay title (rendered by `draw_overlay`).
    title: &'static str,
    /// Injected listing/classification capability.
    source: S,
    /// Literal start-directory candidates (`~` not expanded; the source does
    /// that during `resolve_start`). Seeded in [`new`], consumed by
    /// [`ensure_started`].
    candidates: Vec<String>,
    /// Absolute current directory. `None` until `ensure_started` resolves it.
    cwd: Option<std::path::PathBuf>,
    /// Current directory's entries (real children only — dirs first, then
    /// files). Reset by [`load`].
    entries: Vec<DirEntry>,
    /// Current filter-box text. Drives fuzzy ranking via [`recompute`].
    query: String,
    /// Indices into `entries`, fuzzy-ordered for display. `Left` and
    /// empty-`Backspace` navigate up via [`step_up`].
    ranked: Vec<usize>,
    /// Cursor position: index into `ranked`.
    selected: usize,
    /// Transient one-line feedback for the status row (e.g. "no such path").
    status: Option<String>,
    /// Whether [`ensure_started`] has resolved the start directory yet.
    started: bool,
    /// Per-directory cursor memory (ranger-style directory history): maps a
    /// visited dir's absolute path to the absolute path of the entry that was
    /// selected when we last left it. Snapshot/restored only inside [`load`];
    /// never persisted, discarded when the picker closes.
    history: std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>,
}

impl<S: DirSource + Clone> FilePicker<S> {
    /// Open a picker. `identity_hint` seeds the start-directory candidates (its
    /// parent dir leads). NO filesystem access — the first listing is lazy.
    #[must_use]
    pub fn new(title: &'static str, identity_hint: Option<&str>, source: S) -> Self {
        Self {
            title,
            source,
            candidates: sshrack_core::pathutil::start_candidates(identity_hint),
            cwd: None,
            entries: Vec::new(),
            query: String::new(),
            ranked: Vec::new(),
            selected: 0,
            status: None,
            started: false,
            history: std::collections::HashMap::new(),
        }
    }

    /// Number of list rows the overlay renders (drives popup height). Pub so a
    /// future caller can size the popup; the overlay itself uses a fixed cap.
    pub const VISIBLE_ROWS: usize = 16;

    /// Lazily resolve the start directory and list it. Idempotent once it
    /// succeeds. Called at the top of [`on_key`] (after Esc/^C) and
    /// [`draw_overlay`]. Touches fs via the injected source only.
    ///
    /// On an initial list failure `started` stays `false` so the next call
    /// retries — relevant for a future `SftpDirSource` with transient errors.
    pub fn ensure_started(&mut self) {
        if self.started {
            return;
        }
        let cwd = self
            .source
            .resolve_start(&self.candidates)
            .unwrap_or_else(|| std::path::PathBuf::from("/"));
        if self.load(cwd) {
            self.started = true;
        }
        // On failure: `started` stays false, so the next ensure_started retries.
    }

    /// (Re)list `cwd`, reset ranking + query on success, and remember/restore
    /// the per-directory cursor (ranger-style history). Returns `true` on the
    /// `Ok` branch, `false` on `Err`. On error, leaves `cwd`/`entries`/`ranked`
    /// untouched and only sets `status`. Fs via `source`.
    ///
    /// Cursor memory: snapshots the OUTGOING dir's selected-entry path before
    /// `list` swaps `entries`, then on entry to the INCOMING dir restores the
    /// remembered cursor by locating that path in `ranked` (first visit → 0).
    /// `selected` is a ranked index, so the search is over `ranked`, not
    /// `entries`. A remembered path that no longer exists (dir changed) falls
    /// back to 0.
    fn load(&mut self, cwd: std::path::PathBuf) -> bool {
        // Snapshot against the OLD `ranked`/`entries` (before `list` swaps them).
        let prev_cwd = self.cwd.clone();
        let prev_cursor = self.selected_entry().map(|e| e.path.clone());
        match self.source.list(&cwd) {
            Ok(entries) => {
                if let (Some(prev), Some(cursor)) = (prev_cwd, prev_cursor) {
                    self.history.insert(prev, cursor);
                }
                self.cwd = Some(cwd.clone());
                self.entries = entries;
                self.query.clear();
                self.recompute();
                // Restore the incoming dir's remembered cursor by locating the
                // remembered entry path in `ranked`; first visit → 0. `selected`
                // is a ranked index, so search `ranked`, not `entries`.
                self.selected = self
                    .history
                    .get(&cwd)
                    .and_then(|p| {
                        self.ranked
                            .iter()
                            .position(|&i| self.entries.get(i).is_some_and(|e| &e.path == p))
                    })
                    .unwrap_or(0);
                self.status = None;
                true
            }
            Err(msg) => {
                self.status = Some(format!("cannot list: {msg}"));
                false
            }
        }
    }

    /// Recompute `ranked` (indices into `entries`) for the current `query` via
    /// the shared nucleo helper (one-field rows, all-zero scores). Empty query
    /// yields all entries in their sorted order. Pure.
    fn recompute(&mut self) {
        let rows: Vec<Vec<String>> = self.entries.iter().map(|e| vec![e.name.clone()]).collect();
        let scores = vec![0.0f64; self.entries.len()];
        self.ranked = crate::tui::panel::rank_by_fields(&rows, &scores, &self.query);
    }

    /// Clamp the cursor into `ranked` bounds (no-op when empty).
    fn clamp_selected(&mut self) {
        if self.ranked.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len() - 1;
        }
    }

    /// Move the cursor by `delta` with wrap-around. No-op when ranked is empty.
    fn move_cursor(&mut self, delta: i32) {
        if self.ranked.is_empty() {
            return;
        }
        let n = self.ranked.len() as i32;
        self.selected = ((self.selected as i32 + delta).rem_euclid(n)) as usize;
    }

    /// Entry under the cursor, or `None` when the ranked list is empty.
    fn selected_entry(&self) -> Option<&DirEntry> {
        self.ranked
            .get(self.selected)
            .and_then(|&i| self.entries.get(i))
    }

    /// Step into `child` (a dir entry). Reloads its listing.
    fn step_into(&mut self, child: &DirEntry) {
        self.load(child.path.clone());
    }

    /// Step up to the parent of `cwd`. No-op at `/`.
    fn step_up(&mut self) {
        let Some(cwd) = self.cwd.clone() else { return };
        if let Some(parent) = cwd.parent() {
            self.load(parent.to_path_buf());
        }
    }

    /// Pure-ish key decision: Esc / Ctrl-C cancel (no fs); everything else
    /// `ensure_started()` first, then mutates query/cursor/cwd. Returns
    /// [`FilePickerOutcome::Pick`] only on a resolved file selection.
    pub fn on_key(&mut self, key: KeyEvent) -> FilePickerOutcome {
        if key.kind != KeyEventKind::Press {
            return FilePickerOutcome::Pending;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // Esc / Ctrl-C short-circuit BEFORE ensure_started so closing the picker
        // never touches the filesystem (keeps wizard on_key tests fs-free).
        if key.code == KeyCode::Esc {
            return FilePickerOutcome::Cancel;
        }
        if ctrl && key.code == KeyCode::Char('c') {
            return FilePickerOutcome::Cancel;
        }
        self.ensure_started();

        match key.code {
            KeyCode::Up => {
                self.move_cursor(-1);
                FilePickerOutcome::Pending
            }
            KeyCode::Down => {
                self.move_cursor(1);
                FilePickerOutcome::Pending
            }
            KeyCode::Char('p') if ctrl => {
                self.move_cursor(-1);
                FilePickerOutcome::Pending
            }
            KeyCode::Char('n') if ctrl => {
                self.move_cursor(1);
                FilePickerOutcome::Pending
            }
            KeyCode::Left => {
                self.step_up();
                FilePickerOutcome::Pending
            }
            KeyCode::Backspace => {
                if self.query.is_empty() {
                    self.step_up();
                } else {
                    self.query.pop();
                    self.recompute();
                    self.clamp_selected();
                }
                FilePickerOutcome::Pending
            }
            KeyCode::Enter => self.activate_selected(),
            // Right is a pure navigation key: enter the dir under the cursor,
            // or do nothing on a file (Enter is the only select key).
            KeyCode::Right => self.step_into_selected(),
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute();
                self.selected = 0;
                FilePickerOutcome::Pending
            }
            _ => FilePickerOutcome::Pending,
        }
    }

    /// `Right` as a pure navigation key: step into the directory under the
    /// cursor, or do nothing when the cursor is on a file (files cannot be
    /// entered — only [`Self::activate_selected`] / `Enter` selects a file).
    /// Always returns [`FilePickerOutcome::Pending`] (the picker stays open).
    fn step_into_selected(&mut self) -> FilePickerOutcome {
        if let Some(entry) = self.selected_entry().cloned() {
            if entry.is_dir {
                self.step_into(&entry);
            }
        }
        FilePickerOutcome::Pending
    }

    /// Resolve an `Enter`: a PathLike query resolves via the source; a Fuzzy
    /// query activates the entry under the cursor (dir -> step in, file ->
    /// Pick). Sets `status` on a not-found path. Never panics.
    fn activate_selected(&mut self) -> FilePickerOutcome {
        let intent = parse_filter_intent(&self.query);
        match intent {
            FilterIntent::PathLike(raw) => {
                let Some(cwd) = self.cwd.clone() else {
                    return FilePickerOutcome::Pending;
                };
                match self.source.resolve(&raw, &cwd) {
                    sshrack_core::pathutil::ResolvedPath::File(abs) => FilePickerOutcome::Pick(abs),
                    sshrack_core::pathutil::ResolvedPath::Dir(abs) => {
                        self.load(abs);
                        FilePickerOutcome::Pending
                    }
                    sshrack_core::pathutil::ResolvedPath::NotFound => {
                        self.status = Some(format!("no such path: {raw}"));
                        FilePickerOutcome::Pending
                    }
                }
            }
            FilterIntent::Fuzzy(_) => {
                if let Some(entry) = self.selected_entry().cloned() {
                    if entry.is_dir {
                        self.step_into(&entry);
                        FilePickerOutcome::Pending
                    } else {
                        FilePickerOutcome::Pick(entry.path)
                    }
                } else {
                    FilePickerOutcome::Pending
                }
            }
        }
    }

    /// Paint the picker as a centered popup over the wizard. Four vertical
    /// segments: the current dir (left-truncated so the tail survives), a
    /// focus-following windowed list, the query box, and a hint/status line.
    /// The real terminal cursor lands at the end of the query. Private-key
    /// files are highlighted (filename heuristic, plus an on-demand header read
    /// for visible non-matching names). Rendering only — mutates nothing.
    pub fn draw_overlay(&self, frame: &mut Frame) {
        use ratatui::layout::{Alignment, Constraint, Layout};
        use ratatui::style::{Modifier, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};
        use std::io::{BufRead, BufReader};

        let area = crate::tui::popup::centered_rect(
            frame.area(),
            crate::tui::popup::POPUP_WIDTH,
            crate::tui::popup::POPUP_HEIGHT,
        );
        frame.render_widget(Clear, area);
        let block = Block::new()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.title))
            .title_style(crate::tui::theme::accent().add_modifier(Modifier::BOLD));
        frame.render_widget(&block, area);
        let inner = block.inner(area);

        let [cwd_area, list_area, query_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(inner);

        // cwd line, left-truncated (tail wins): keep the trailing dir name
        // (e.g. `…/.ssh`), not the head (`/home/ry…`).
        let cwd_str = self
            .cwd
            .as_deref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/".to_string());
        let avail = inner.width as usize;
        let shown = crate::tui::fit::truncate_cells_head(&format!(" {cwd_str}"), avail);
        frame.render_widget(
            Paragraph::new(shown).style(crate::tui::theme::accent()),
            cwd_area,
        );

        // windowed, highlighted list.
        let total = self.ranked.len();
        let win = crate::tui::fit::focus_window(total, self.selected, Self::VISIBLE_ROWS);
        let mut lines: Vec<Line> = Vec::new();
        if self.ranked.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (empty — type a path with Enter to jump, or Esc to cancel)",
                Style::new().dim(),
            )));
        } else {
            for i in win.start..win.end {
                let Some(&idx) = self.ranked.get(i) else {
                    continue;
                };
                let Some(entry) = self.entries.get(idx) else {
                    continue;
                };
                let is_sel = i == self.selected;
                let marker = if is_sel { "▶ " } else { "  " };
                let base = if is_sel {
                    crate::tui::theme::accent().add_modifier(Modifier::BOLD)
                } else if entry.is_dir {
                    Style::new().add_modifier(Modifier::BOLD)
                } else {
                    Style::new()
                };
                let keyish = sshrack_core::keydetect::looks_like_key_filename(
                    entry.name.trim_end_matches(['/', '@']),
                ) || {
                    // On-demand header read for visible non-dir entries only.
                    !entry.is_dir && {
                        std::fs::File::open(&entry.path)
                            .ok()
                            .and_then(|f| BufReader::new(f).lines().next().and_then(Result::ok))
                            .map(|l| sshrack_core::keydetect::looks_like_private_key_header(&l))
                            .unwrap_or(false)
                    }
                };
                let value_style = if keyish {
                    base.fg(crate::tui::theme::MATCH)
                } else {
                    base
                };
                let mut spans = vec![Span::styled(marker, base)];
                spans.extend(crate::tui::panel::highlighted_spans(
                    &entry.name,
                    &self.query,
                    value_style,
                ));
                lines.push(Line::from(spans).alignment(Alignment::Left));
            }
        }
        frame.render_widget(Paragraph::new(lines), list_area);

        // query box.
        let q = Line::from(vec![
            Span::styled(
                "> ",
                crate::tui::theme::accent().add_modifier(Modifier::BOLD),
            ),
            Span::raw(self.query.clone()),
            Span::styled("_", Style::new().dim()),
        ]);
        frame.render_widget(q, query_area);
        let qx = query_area.x + 2 + self.query.chars().count() as u16;
        let max_x = query_area.x + query_area.width.saturating_sub(1);
        frame.set_cursor_position((qx.min(max_x), query_area.y));

        // status / hint line.
        let line = match &self.status {
            Some(msg) => Line::from(vec![
                Span::styled("  ! ", Style::new().fg(crate::tui::theme::DANGER).bold()),
                Span::styled(msg.clone(), Style::new().fg(crate::tui::theme::DANGER)),
            ]),
            None => Line::from(Span::styled(
                " type: filter · ↑↓ move · ↵ open/select · ← up · esc clear/cancel",
                Style::new().dim(),
            )),
        };
        frame.render_widget(line, status_area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use sshrack_core::dirsource::{DirEntry, DirSource, PathKind};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    /// In-memory DirSource: a map of dir-path -> its child entries. No fs.
    #[derive(Default, Clone)]
    struct FakeSource {
        dirs: HashMap<PathBuf, Vec<DirEntry>>,
        home: Option<PathBuf>,
    }
    impl FakeSource {
        fn entry(name: &str, parent: &Path, is_dir: bool) -> DirEntry {
            let decorate = |raw: &str| -> String {
                if is_dir {
                    format!("{raw}/")
                } else {
                    raw.to_string()
                }
            };
            DirEntry {
                name: decorate(name),
                path: parent.join(name),
                is_dir,
                is_symlink: false,
            }
        }
    }
    impl DirSource for FakeSource {
        fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String> {
            Ok(self.dirs.get(cwd).cloned().unwrap_or_default())
        }
        fn classify(&self, p: &Path) -> PathKind {
            if self.dirs.contains_key(p) {
                PathKind::Dir
            } else if self
                .dirs
                .values()
                .flatten()
                .any(|e| e.path.as_path() == p && !e.is_dir)
            {
                PathKind::File
            } else {
                PathKind::NotFound
            }
        }
        fn home(&self) -> Option<PathBuf> {
            self.home.clone()
        }
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    /// Build a tiny tree: /h/.ssh/{id_ed25519, id_ed25519.pub, config}, /h, /.
    fn tree() -> FakeSource {
        // Clippy-driven: initialize `home` in the struct literal rather than
        // via `Default::default()` + field reassign
        // (clippy::field_reassign_with_default). Behavior unchanged.
        let mut f = FakeSource {
            home: Some(PathBuf::from("/h")),
            ..Default::default()
        };
        let dotssh = PathBuf::from("/h/.ssh");
        f.dirs.insert(
            dotssh.clone(),
            vec![
                FakeSource::entry("id_ed25519", &dotssh, false),
                FakeSource::entry("id_ed25519.pub", &dotssh, false),
                FakeSource::entry("config", &dotssh, false),
            ],
        );
        f.dirs.insert(
            PathBuf::from("/h"),
            vec![DirEntry {
                name: ".ssh/".into(),
                path: dotssh.clone(),
                is_dir: true,
                is_symlink: false,
            }],
        );
        f.dirs.insert(PathBuf::from("/"), vec![]);
        f
    }

    // ---- new: lazy, no fs, cwd unresolved until started ----

    #[test]
    fn new_does_not_touch_fs() {
        // A FakeSource that PANICS on list/classify proves new() is fs-free.
        #[derive(Clone)]
        struct Panic;
        impl DirSource for Panic {
            fn list(&self, _: &Path) -> Result<Vec<DirEntry>, String> {
                panic!("list in new()")
            }
            fn classify(&self, _: &Path) -> PathKind {
                panic!("classify in new()")
            }
            fn home(&self) -> Option<PathBuf> {
                panic!("home in new()")
            }
        }
        let _ = FilePicker::new("pick", Some("/h/.ssh/id_ed25519"), Panic);
    }

    // ---- ensure_started resolves ~/.ssh first ----

    #[test]
    fn started_lands_in_identity_parent_dotssh() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/id_ed25519"), tree());
        p.ensure_started();
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/h/.ssh")));
        assert!(p.entries.iter().any(|e| e.name == "id_ed25519"));
    }

    // ---- fuzzy filter narrows the ranked list ----

    #[test]
    fn typing_fuzzy_filters_current_dir() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        for c in "id_ed".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        // ranked must contain only id_ed25519 + id_ed25519.pub (both fuzzy-match
        // "id_ed"); config drops out.
        let names: Vec<&str> = p
            .ranked
            .iter()
            .map(|&i| p.entries[i].name.as_str())
            .collect();
        assert!(names.iter().all(|n| n.starts_with("id_ed")), "{names:?}");
    }

    // ---- Enter on a file Picks its absolute path ----

    #[test]
    fn enter_on_file_picks_absolute_path() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        // cursor at index 0 of ranked; in /h/.ssh ranked[0] is the first
        // dirs-first/file entry. entries has no subdirs here, so ranked[0] is
        // the alphabetically-first file. Move down to id_ed25519 if needed.
        // Clippy-driven: `Option::is_none_or` (stable since 1.82, MSRV 1.86)
        // replaces `map_or(true, …)`. Behavior unchanged.
        while p
            .ranked
            .get(p.selected)
            .is_none_or(|&i| p.entries[i].name != "id_ed25519")
        {
            let _ = p.on_key(press(KeyCode::Down));
            if p.selected == 0 {
                break;
            }
        }
        let out = p.on_key(press(KeyCode::Enter));
        assert_eq!(
            out,
            FilePickerOutcome::Pick(PathBuf::from("/h/.ssh/id_ed25519"))
        );
    }

    // ---- Enter on a directory steps into it (Pending) ----

    #[test]
    fn enter_on_dir_steps_into_it() {
        let mut p = FilePicker::new("pick", None, tree());
        // start candidates without hint -> ~/.ssh -> /h/.ssh. Step up to /h first.
        let _ = p.on_key(press(KeyCode::Left)); // /h/.ssh -> /h
        // /h has one entry: .ssh/. Enter on it -> back into /h/.ssh.
        let out = p.on_key(press(KeyCode::Enter));
        assert!(matches!(out, FilePickerOutcome::Pending));
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/h/.ssh")));
    }

    // ---- Right is a pure navigation key: enters a dir, but is a no-op on a
    //      file (only Enter selects). Guards against the old Enter|Right merge
    //      that made Right on a file silently Pick it. ----

    #[test]
    fn right_on_file_is_noop_does_not_pick() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        // land the cursor on a file (id_ed25519), same nav as Enter-picks test.
        while p
            .ranked
            .get(p.selected)
            .is_none_or(|&i| p.entries[i].name != "id_ed25519")
        {
            let _ = p.on_key(press(KeyCode::Down));
            if p.selected == 0 {
                break;
            }
        }
        let out = p.on_key(press(KeyCode::Right));
        assert_eq!(
            out,
            FilePickerOutcome::Pending,
            "Right on a file must NOT pick it (Enter is the only select key)"
        );
    }

    #[test]
    fn right_on_dir_still_steps_into_it() {
        let mut p = FilePicker::new("pick", None, tree());
        let _ = p.on_key(press(KeyCode::Left)); // /h/.ssh -> /h
        // /h has one entry: .ssh/ (a dir). Right on it must enter the dir.
        let out = p.on_key(press(KeyCode::Right));
        assert!(
            matches!(out, FilePickerOutcome::Pending),
            "Right on a dir enters it"
        );
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/h/.ssh")));
    }

    // ---- PathLike query: paste an absolute file path, Enter Picks it ----

    #[test]
    fn pathlike_query_pastes_absolute_file_path() {
        let mut p = FilePicker::new("pick", None, tree());
        for c in "/h/.ssh/config".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(
            p.on_key(press(KeyCode::Enter)),
            FilePickerOutcome::Pick(PathBuf::from("/h/.ssh/config"))
        );
    }

    #[test]
    fn pathlike_query_directory_switches_into_it() {
        let mut p = FilePicker::new("pick", None, tree());
        for c in "/h/.ssh".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        let out = p.on_key(press(KeyCode::Enter));
        assert!(matches!(out, FilePickerOutcome::Pending));
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/h/.ssh")));
        assert!(p.query.is_empty(), "query cleared after switching dir");
    }

    #[test]
    fn pathlike_query_notfound_sets_status_and_stays() {
        let mut p = FilePicker::new("pick", None, tree());
        for c in "/no/such".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        let out = p.on_key(press(KeyCode::Enter));
        assert!(matches!(out, FilePickerOutcome::Pending));
        assert!(p.status.as_deref().unwrap_or("").contains("no such path"));
    }

    // ---- Esc / Ctrl-C cancel without fs (no ensure_started) ----

    #[test]
    fn esc_cancels_without_touching_fs() {
        #[derive(Clone)]
        struct Panic;
        impl DirSource for Panic {
            fn list(&self, _: &Path) -> Result<Vec<DirEntry>, String> {
                panic!()
            }
            fn classify(&self, _: &Path) -> PathKind {
                panic!()
            }
            fn home(&self) -> Option<PathBuf> {
                panic!()
            }
        }
        let mut p = FilePicker::new("pick", None, Panic);
        assert_eq!(p.on_key(press(KeyCode::Esc)), FilePickerOutcome::Cancel);
    }

    #[test]
    fn ctrl_c_cancels() {
        let mut p = FilePicker::new("pick", None, tree());
        let cc = KeyEvent::new_with_kind(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert_eq!(p.on_key(cc), FilePickerOutcome::Cancel);
    }

    // ---- Backspace dual: empty query steps up ----

    #[test]
    fn backspace_on_empty_query_steps_up() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        let _ = p.on_key(press(KeyCode::Backspace)); // empty query -> step up to /h
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/h")));
    }

    #[test]
    fn backspace_on_query_pops_a_char() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        for c in "id".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        let _ = p.on_key(press(KeyCode::Backspace));
        // DEV-NOTE: the task-4 brief asserted `p.query.is_empty()` here, but
        // the brief's own impl does `query.pop()` (one char) and the test name
        // is "pops_a_char" (singular). Typing "id" then pressing Backspace once
        // leaves "i" — the brief's `is_empty()` assertion was self-inconsistent.
        // Corrected to assert exactly one char was popped.
        assert_eq!(p.query, "i");
    }

    #[test]
    fn up_down_move_selected_with_wrap() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        // DEV-NOTE: the task-4 brief omitted this `ensure_started()` call, but
        // `new` is fs-free by design (see `new_does_not_touch_fs`) so `ranked`
        // is empty until the first key press. Without this line `n` would be 0
        // and `assert!(n >= 1)` would fail. The wrap-loop semantics below only
        // make sense against real ranked data, which is what `ensure_started`
        // produces.
        p.ensure_started();
        let n = p.ranked.len();
        assert!(n >= 1);
        let _ = p.on_key(press(KeyCode::Down));
        let _ = p.on_key(press(KeyCode::Up));
        // wrap top -> bottom
        for _ in 0..n {
            let _ = p.on_key(press(KeyCode::Down));
        }
        assert!(p.selected < n);
    }

    // ---- draw_overlay: no-panic render over a TestBackend ----

    #[test]
    fn draw_overlay_renders_without_panic_default() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        p.ensure_started();
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }

    #[test]
    fn draw_overlay_renders_without_panic_on_tiny_terminal() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut p = FilePicker::new("pick", None, tree());
        p.ensure_started();
        let backend = TestBackend::new(30, 8); // too short for the full list
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }

    #[test]
    fn draw_overlay_with_status_line_renders_without_panic() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut p = FilePicker::new("pick", None, tree());
        for c in "/no/such".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        let _ = p.on_key(press(KeyCode::Enter)); // sets status
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }

    // ---- M3: ensure_started retries after an initial list failure ----

    #[test]
    fn ensure_started_retries_after_initial_list_failure() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        #[derive(Clone)]
        struct Flaky {
            calls: Arc<AtomicUsize>,
        }
        impl DirSource for Flaky {
            fn list(&self, _: &Path) -> Result<Vec<DirEntry>, String> {
                let n = self.calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err("boom".into())
                } else {
                    Ok(vec![DirEntry {
                        name: "id_ed25519".into(),
                        path: std::path::PathBuf::from("/h/.ssh/id_ed25519"),
                        is_dir: false,
                        is_symlink: false,
                    }])
                }
            }
            fn classify(&self, _: &Path) -> PathKind {
                PathKind::Dir
            } // resolve_start finds a dir
            fn home(&self) -> Option<PathBuf> {
                Some(std::path::PathBuf::from("/h"))
            }
        }
        let mut p = FilePicker::new(
            "pick",
            None,
            Flaky {
                calls: Arc::new(AtomicUsize::new(0)),
            },
        );
        p.ensure_started();
        assert!(!p.started, "first list failed → not started");
        assert!(p.cwd.is_none(), "cwd stays None on failure");
        assert!(p.status.is_some(), "failure surfaced a status");
        p.ensure_started(); // retry
        assert!(p.started, "second list succeeded → started");
        assert!(p.cwd.is_some(), "cwd populated on retry");
        assert!(p.entries.iter().any(|e| e.name == "id_ed25519"));
    }

    /// Multi-level fixture: `/A/{B1/, B2/, B3/}` (subdirs), `/A/B2/{f1, f2}`
    /// (files inside B2), `/A/B1` and `/A/B3` empty. `home` = `/A` so a
    /// no-hint picker starts in `/A`.
    fn multi_dir_tree() -> FakeSource {
        let mut f = FakeSource {
            home: Some(PathBuf::from("/A")),
            ..Default::default()
        };
        let a = PathBuf::from("/A");
        let b2 = PathBuf::from("/A/B2");
        f.dirs.insert(
            a.clone(),
            vec![
                FakeSource::entry("B1", &a, true),
                FakeSource::entry("B2", &a, true),
                FakeSource::entry("B3", &a, true),
            ],
        );
        f.dirs.insert(
            b2.clone(),
            vec![
                FakeSource::entry("f1", &b2, false),
                FakeSource::entry("f2", &b2, false),
            ],
        );
        f.dirs.insert(PathBuf::from("/A/B1"), vec![]);
        f.dirs.insert(PathBuf::from("/A/B3"), vec![]);
        f
    }

    // ---- directory cursor history: re-entering a dir restores the cursor ----

    #[test]
    fn step_into_and_back_restores_cursor() {
        let mut p = FilePicker::new("pick", None, multi_dir_tree());
        p.ensure_started(); // lands in /A
        // land the cursor on B2 by name (order-agnostic vs the ranker)
        for _ in 0..p.ranked.len() {
            if p.selected_entry().is_some_and(|e| e.name == "B2/") {
                break;
            }
            let _ = p.on_key(press(KeyCode::Down));
        }
        assert_eq!(
            p.selected_entry().map(|e| e.name.clone()).as_deref(),
            Some("B2/"),
            "sanity: cursor on B2 before entering"
        );
        let _ = p.on_key(press(KeyCode::Right)); // enter B2
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/A/B2")));
        let _ = p.on_key(press(KeyCode::Left)); // back to /A
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/A")));
        assert_eq!(
            p.selected_entry().map(|e| e.name.clone()).as_deref(),
            Some("B2/"),
            "re-entering a dir must restore the previous cursor (directory history)"
        );
    }

    #[test]
    fn first_visit_lands_on_first_entry() {
        let mut p = FilePicker::new("pick", None, multi_dir_tree());
        p.ensure_started(); // /A, cursor at index 0
        assert_eq!(p.selected, 0, "initial dir → index 0");
        // navigate to B2 and enter it (never visited, non-empty).
        for _ in 0..p.ranked.len() {
            if p.selected_entry().is_some_and(|e| e.name == "B2/") {
                break;
            }
            let _ = p.on_key(press(KeyCode::Down));
        }
        let _ = p.on_key(press(KeyCode::Right)); // enter B2 — first visit
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/A/B2")));
        assert_eq!(
            p.selected, 0,
            "first visit to a dir → index 0 (no history yet)"
        );
    }

    #[test]
    fn remembered_cursor_missing_falls_back_to_zero() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        // Stateful source: the FIRST list of /A returns [B1,B2,B3]; after we
        // enter B2 and come back, the SECOND list of /A returns [B9] only.
        // The remembered B2 path is now gone → the cursor must fall back to 0.
        #[derive(Clone)]
        struct Mutating {
            a_calls: Arc<AtomicUsize>,
        }
        impl DirSource for Mutating {
            fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String> {
                if cwd == std::path::Path::new("/A") {
                    let n = self.a_calls.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        Ok(vec![
                            DirEntry {
                                name: "B1/".into(),
                                path: std::path::PathBuf::from("/A/B1"),
                                is_dir: true,
                                is_symlink: false,
                            },
                            DirEntry {
                                name: "B2/".into(),
                                path: std::path::PathBuf::from("/A/B2"),
                                is_dir: true,
                                is_symlink: false,
                            },
                            DirEntry {
                                name: "B3/".into(),
                                path: std::path::PathBuf::from("/A/B3"),
                                is_dir: true,
                                is_symlink: false,
                            },
                        ])
                    } else {
                        Ok(vec![DirEntry {
                            name: "B9/".into(),
                            path: std::path::PathBuf::from("/A/B9"),
                            is_dir: true,
                            is_symlink: false,
                        }])
                    }
                } else if cwd == std::path::Path::new("/A/B2") {
                    Ok(vec![DirEntry {
                        name: "f1".into(),
                        path: std::path::PathBuf::from("/A/B2/f1"),
                        is_dir: false,
                        is_symlink: false,
                    }])
                } else {
                    Ok(vec![])
                }
            }
            fn classify(&self, p: &Path) -> PathKind {
                match p.to_string_lossy().as_ref() {
                    "/A" | "/A/B2" => PathKind::Dir,
                    _ => PathKind::NotFound,
                }
            }
            fn home(&self) -> Option<PathBuf> {
                Some(std::path::PathBuf::from("/A"))
            }
        }
        let mut p = FilePicker::new(
            "pick",
            None,
            Mutating {
                a_calls: Arc::new(AtomicUsize::new(0)),
            },
        );
        p.ensure_started(); // /A list #0 → [B1,B2,B3]
        // move to B2
        for _ in 0..p.ranked.len() {
            if p.selected_entry().is_some_and(|e| e.name == "B2/") {
                break;
            }
            let _ = p.on_key(press(KeyCode::Down));
        }
        let _ = p.on_key(press(KeyCode::Right)); // enter B2
        let _ = p.on_key(press(KeyCode::Left)); // back to /A → list #1 → [B9]
        assert_eq!(
            p.selected, 0,
            "remembered cursor gone from new listing → fall back to index 0"
        );
        assert_eq!(
            p.selected_entry().map(|e| e.name.clone()).as_deref(),
            Some("B9/")
        );
    }
}
