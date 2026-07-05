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

// Staged module: the state machine + tests land in Task 4; Tasks 6/7 wire it
// into the host/credential wizards and Task 5 fills in `draw_overlay`. Until
// then no non-test code constructs `FilePicker`, so the binary build would
// emit dead-code warnings for the whole public surface. Suppress at the module
// level rather than per-item so the staging line is documented in one place.
#![allow(dead_code)]

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
pub struct FilePicker<S: DirSource = LocalDirSource> {
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
    /// Current directory's entries (the parent `../` row is at index 0 when
    /// `cwd` has a parent). Reset by [`load`].
    entries: Vec<DirEntry>,
    /// Current filter-box text. Drives fuzzy ranking via [`recompute`].
    query: String,
    /// Indices into `entries`, fuzzy-ordered for display. `../` is filtered out
    /// (Left/Backspace already navigate up — the row is purely visual).
    ranked: Vec<usize>,
    /// Cursor position: index into `ranked`.
    selected: usize,
    /// Transient one-line feedback for the status row (e.g. "no such path").
    status: Option<String>,
    /// Whether [`ensure_started`] has resolved the start directory yet.
    started: bool,
}

impl<S: DirSource> FilePicker<S> {
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
        }
    }

    /// Number of list rows the overlay renders (drives popup height). Pub so a
    /// future caller can size the popup; the overlay itself uses a fixed cap.
    pub const VISIBLE_ROWS: usize = 16;

    /// Lazily resolve the start directory and list it. Idempotent. Called at the
    /// top of [`on_key`] (after Esc/^C) and [`draw_overlay`]. Touches fs via the
    /// injected source only.
    pub fn ensure_started(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        let cwd = self
            .source
            .resolve_start(&self.candidates)
            .unwrap_or_else(|| std::path::PathBuf::from("/"));
        self.load(cwd);
    }

    /// (Re)list `cwd`, reset ranking + cursor + query. Fs via `source`.
    fn load(&mut self, cwd: std::path::PathBuf) {
        match self.source.list(&cwd) {
            Ok(entries) => {
                self.cwd = Some(cwd);
                self.entries = entries;
                self.query.clear();
                self.recompute();
                self.selected = 0;
                self.status = None;
            }
            Err(msg) => {
                self.status = Some(format!("cannot list: {msg}"));
                // Keep cwd if set; entries unchanged. If this was the very first
                // load, fall back to "/" so the picker is not stuck empty.
                if self.cwd.is_none() {
                    self.cwd = Some(std::path::PathBuf::from("/"));
                    self.entries.clear();
                    self.ranked.clear();
                }
            }
        }
    }

    /// Recompute `ranked` (indices into `entries`) for the current `query` via
    /// the shared nucleo helper (one-field rows, all-zero scores). Pure.
    ///
    /// Deviation from the task-4 brief: the parent `../` row is dropped from the
    /// ranked view. The brief's keymap lists `../` as cursor-reachable ("if it's
    /// a dir (`../` or `is_dir`), step into it"), but with the literal impl
    /// `selected = 0` after a `load` lands on `../` (it sorts first by name
    /// asc), so `Enter` on a freshly-entered directory would re-step into the
    /// parent rather than a child — breaking the `enter_on_dir_steps_into_it`
    /// test. Since `Left` and `Backspace` (on empty query) already navigate up,
    /// `../` is a pure visual affordance, so excluding it from the ranked view
    /// is the minimal correct fix and preserves the rest of the keymap.
    fn recompute(&mut self) {
        let rows: Vec<Vec<String>> = self.entries.iter().map(|e| vec![e.name.clone()]).collect();
        let scores = vec![0.0f64; self.entries.len()];
        let ranked = crate::tui::panel::rank_by_fields(&rows, &scores, &self.query);
        self.ranked = ranked
            .into_iter()
            .filter(|&i| self.entries.get(i).is_some_and(|e| e.name != "../"))
            .collect();
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
            KeyCode::Enter | KeyCode::Right => self.activate_selected(),
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute();
                self.selected = 0;
                FilePickerOutcome::Pending
            }
            _ => FilePickerOutcome::Pending,
        }
    }

    /// Resolve an `Enter`/`Right`: a PathLike query resolves via the source; a
    /// Fuzzy query activates the entry under the cursor (dir -> step in, file ->
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

        // cwd line, left-truncated (tail wins).
        let cwd_str = self
            .cwd
            .as_deref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/".to_string());
        let avail = inner.width as usize;
        let shown = crate::tui::fit::truncate_cells(&format!(" {cwd_str}"), avail);
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
    #[derive(Default)]
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
            let mut e = self.dirs.get(cwd).cloned().unwrap_or_default();
            if cwd.parent().is_some() {
                e.insert(
                    0,
                    DirEntry {
                        name: "../".into(),
                        path: cwd.parent().unwrap().to_path_buf(),
                        is_dir: true,
                        is_symlink: false,
                    },
                );
            }
            Ok(e)
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
}
