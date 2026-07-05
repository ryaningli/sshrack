# File Picker (Identity Key Path Browser) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Replace the inline-typed Identity-key path field with a modal file-picker overlay: `Enter` on the Identity row opens a browser that fuzzy-filters the current directory, navigates in/out of directories, and also accepts a pasted absolute path in the same filter box (one unified input). Selected paths are written back absolute (expanding `~`), which also fixes the latent OpenSSH `-i` does-not-expand-`~` bug.

**Architecture:** A reusable, business-decoupled `FilePicker<S: DirSource>` overlay component lives in `src/tui/file_picker.rs`. It does NOT import `host`/`cred` — it returns `FilePickerOutcome::Pick(PathBuf)` and the caller decides where to write it. Directory listing + path classification + `~` expansion are injected via a `DirSource` trait in `sshrack-core` (`LocalDirSource` now; a future `SftpDirSource` reuses the whole component). Pure path/string logic (filter-intent parsing, `~` expansion, private-key header detection, entry sorting) lives in core as pure functions (TDD, zero UI deps, zero fs). `FilePicker::new` performs NO fs (it stores unresolved start candidates); the first listing is lazy (`ensure_started`) so the wizard's pure `on_key` tests never touch the filesystem — production `draw`/`on_key` triggers the lazy load through the injected source.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, nucleo-matcher (already a dep), `tempfile` (already a core dev-dep). **Zero new dependencies.**

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via params/seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")` on truly unreachable states.
- **TDD for pure logic** — RED → GREEN → REFACTOR. Process/render behavior is covered by no-panic `TestBackend` smoke tests, not pixel assertions.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **`sshrack-core` zero-UI invariant** — `crates/sshrack-core/Cargo.toml` never lists `ratatui`/`crossterm`/`nucleo-matcher`/`console`. UI crates are root-package deps only. Pure path/key logic goes in core; `nucleo` fuzzy ranking stays in `src/tui/panel.rs` (TUI layer).
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; never `env -u`. Fs-touching core tests use `tempfile::tempdir()`; `FilePicker` state-machine tests inject a fake `DirSource` (no real fs).
- **No duplicate logic (dev-stage rule)** — `~` expansion, path normalization, entry sorting, key-header detection each land in exactly one canonical home (core helpers), never copy-pasted across modules.
- **Decouple for reuse** — `FilePicker` must not import `host`/`cred`. `DirSource` is the seam a future `sshrack sftp` local+remote panes reuse. Do NOT write any sftp code now (YAGNI); just keep the seam clean.
- **Side effects via traits** — `DirSource` mirrors `SecretBackend`/`PassphraseProvider`: defined in core, faked in tests, real impl (`LocalDirSource`) in core using `std::fs`.
- **High performance** — directory listing is single-level `read_dir` (no recursion); fuzzy ranking reuses the existing `panel::rank_by_fields` (nucleo, allocates one matcher per query); private-key detection is on-demand per *visible* entry only (never scans the whole directory).
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`.

---

## File Structure (target)

```
crates/sshrack-core/src/
├── lib.rs                # +pub mod pathutil; +pub mod keydetect; +pub mod dirsource;
├── pathutil.rs           # NEW — pure: parse_filter_intent / expand_tilde / start_candidates / ResolvedPath
├── keydetect.rs          # NEW — pure: looks_like_private_key_header / looks_like_key_filename
└── dirsource.rs          # NEW — PathKind / DirEntry / DirSource trait / LocalDirSource / build_entries

src/tui/
├── mod.rs                # +pub mod file_picker;
├── file_picker.rs        # NEW — FilePicker<S: DirSource> overlay: state machine, on_key, draw_overlay
├── wizard/
│   ├── host.rs           # Identity row → trigger row; +file_picker field; route+mount
│   └── cred.rs           # mirror of host.rs
└── panel.rs              # unchanged (FilePicker reuses rank_by_fields / highlighted_spans)

CLAUDE.md                 # Identity trigger row + FilePicker keymap + DirSource-for-sftp note
```

---

## Task 1: core `pathutil.rs` — pure path-parse helpers (TDD)

**Files:**
- Create: `crates/sshrack-core/src/pathutil.rs`
- Modify: `crates/sshrack-core/src/lib.rs` (add `pub mod pathutil;`)

**Interfaces:**
- Produces (consumed by Task 3 `DirSource::resolve`, Task 4 `FilePicker`, Task 6/7 wizard):
  - `pub enum FilterIntent { Fuzzy(String), PathLike(String) }`
  - `pub fn parse_filter_intent(input: &str) -> FilterIntent`
  - `pub fn expand_tilde(input: &str, home: &Path) -> PathBuf`
  - `pub fn start_candidates(identity_hint: Option<&str>) -> Vec<String>`
  - `pub enum ResolvedPath { Dir(PathBuf), File(PathBuf), NotFound }`

**Semantics (pin these in tests):**
- `parse_filter_intent`: input containing `/` OR starting with `~` → `PathLike(trimmed)`; otherwise → `Fuzzy(raw)`. Empty input → `Fuzzy("")`.
- `expand_tilde`: `~` alone → `home`; `~/x` or `~\\x` → `home/x`; anything else → `input` parsed as a path. Never touches fs.
- `start_candidates`: ordered literal candidates (NOT expanded — `~` stays literal; `DirSource` expands): if `identity_hint` is non-empty and has a parent, its parent dir literal first; then `"~/.ssh"`; then `"~"`; then `"/"`. De-dup consecutive equals.
- `ResolvedPath` is just data; producing it requires fs, so it is returned by `DirSource::resolve` (Task 3), not by a pure fn here.

- [ ] **Step 1: Declare the module**

In `crates/sshrack-core/src/lib.rs`, add `pub mod pathutil;` (e.g. after `pub mod hostkey;`).

- [ ] **Step 2: Write the failing tests (RED)**

Create `crates/sshrack-core/src/pathutil.rs` with only the test module + the type/fn signatures stubbed to compile-but-fail, OR just the tests (compile failure is the RED signal). Use the latter:

```rust
//! Pure path-parse helpers for the file picker: classifying the filter-box
//! input as a fuzzy term vs a path-like string, expanding a leading `~`, and
//! computing the ordered start-directory candidates. None of these touch the
//! filesystem — `home` is always a parameter — so the whole module is unit-
//! testable with no tempdir.

use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // ---- parse_filter_intent ----

    #[test]
    fn plain_name_is_fuzzy() {
        assert!(matches!(parse_filter_intent("id_ed"), FilterIntent::Fuzzy(s) if s == "id_ed"));
    }

    #[test]
    fn empty_is_fuzzy_empty() {
        assert!(matches!(parse_filter_intent(""), FilterIntent::Fuzzy(s) if s.is_empty()));
    }

    #[test]
    fn slash_anywhere_is_pathlike() {
        assert!(matches!(parse_filter_intent("~/x"), FilterIntent::PathLike(_)));
        assert!(matches!(parse_filter_intent("a/b"), FilterIntent::PathLike(_)));
        assert!(matches!(parse_filter_intent("./x"), FilterIntent::PathLike(_)));
        assert!(matches!(parse_filter_intent("/abs"), FilterIntent::PathLike(_)));
        assert!(matches!(parse_filter_intent("trailing/"), FilterIntent::PathLike(_)));
    }

    #[test]
    fn leading_tilde_alone_is_pathlike() {
        assert!(matches!(parse_filter_intent("~"), FilterIntent::PathLike(_)));
    }

    // ---- expand_tilde ----

    #[test]
    fn expand_tilde_alone_is_home() {
        let home = Path::new("/home/ryan");
        assert_eq!(expand_tilde("~", home), PathBuf::from("/home/ryan"));
    }

    #[test]
    fn expand_tilde_slash_path_joins_home() {
        let home = Path::new("/home/ryan");
        assert_eq!(expand_tilde("~/x/y", home), PathBuf::from("/home/ryan/x/y"));
    }

    #[test]
    fn expand_no_tilde_is_passthrough() {
        let home = Path::new("/home/ryan");
        assert_eq!(expand_tilde("/etc/foo", home), PathBuf::from("/etc/foo"));
        assert_eq!(expand_tilde("rel", home), PathBuf::from("rel"));
    }

    // ---- start_candidates ----

    #[test]
    fn start_candidates_with_identity_hint_puts_parent_first() {
        // identity "/home/ryan/.ssh/id_ed25519" → parent "/home/ryan/.ssh" first,
        // then ~/.ssh, ~, /.
        let c = start_candidates(Some("/home/ryan/.ssh/id_ed25519"));
        assert_eq!(c[0], "/home/ryan/.ssh");
        assert!(c.contains(&"~/.ssh".to_string()));
        assert!(c.contains(&"~".to_string()));
        assert!(c.contains(&"/".to_string()));
    }

    #[test]
    fn start_candidates_no_hint_starts_at_dotssh() {
        let c = start_candidates(None);
        assert_eq!(c[0], "~/.ssh");
    }

    #[test]
    fn start_candidates_dedups_when_parent_equals_dotssh() {
        // identity "~/x" has parent "~"; after dedup the second "~" is dropped.
        let c = start_candidates(Some("~/x"));
        let tilde_count = c.iter().filter(|s| s.as_str() == &"~".to_string()).count();
        assert_eq!(tilde_count, 1, "consecutive dup ~ collapsed: {c:?}");
    }
}
```

- [ ] **Step 3: Run — expect compile failure (RED)**

```bash
cargo test -p sshrack-core --lib pathutil 2>&1 | head -20
```
Expected: `cannot find function/type parse_filter_intent / FilterIntent / expand_tilde / start_candidates`.

- [ ] **Step 4: Implement (GREEN)**

Add above the test module in `crates/sshrack-core/src/pathutil.rs`:

```rust
use std::path::{Path, PathBuf};

/// What the filter-box input means. A string with a `/` anywhere, or a lone
/// leading `~`, is treated as a path the user typed/pasted; anything else is a
/// fuzzy filter over the current directory's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterIntent {
    /// Fuzzy-match against the current directory's entry names.
    Fuzzy(String),
    /// A path-like string to resolve (relative to cwd, or `~`-expanded).
    PathLike(String),
}

/// Classify `input`. `~` alone, or any input containing `/`, is [`FilterIntent::PathLike`];
/// everything else (including empty) is [`FilterIntent::Fuzzy`]. Pure.
pub fn parse_filter_intent(input: &str) -> FilterIntent {
    if input == "~" || input.contains('/') {
        FilterIntent::PathLike(input.trim().to_string())
    } else {
        FilterIntent::Fuzzy(input.to_string())
    }
}

/// Expand a leading `~` (`~` alone → `home`; `~/x` → `home/x`). No other input
/// is altered. Never touches the filesystem — `home` is supplied by the caller.
/// Pure.
pub fn expand_tilde(input: &str, home: &Path) -> PathBuf {
    if input == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = input.strip_prefix("~/") {
        return home.join(rest);
    }
    // Also tolerate a backslash form on the off chance (no-op on Unix paths
    // that do not start with `~`).
    if let Some(rest) = input.strip_prefix("~\\") {
        return home.join(rest);
    }
    PathBuf::from(input)
}

/// Ordered start-directory candidates (literals — `~` is NOT expanded here; the
/// `DirSource` resolves and expands). If `identity_hint` has a parent, it goes
/// first so the user lands where their current key lives. Then `~/.ssh`, `~`,
/// `/`. Consecutive duplicates are collapsed. Pure.
pub fn start_candidates(identity_hint: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(hint) = identity_hint {
        let hint = hint.trim();
        if !hint.is_empty() {
            if let Some(parent) = Path::new(hint).parent() {
                let p = parent.to_string_lossy().into_owned();
                if !p.is_empty() {
                    out.push(p);
                }
            }
        }
    }
    for c in ["~/.ssh", "~", "/"] {
        if out.last().map_or(true, |last| last != &c) {
            out.push(c.to_string());
        } else {
            out.push(c.to_string());
        }
    }
    // Collapse consecutive duplicates that arose from the hint parent matching.
    let mut dedup: Vec<String> = Vec::new();
    for s in out {
        if dedup.last().map_or(true, |last| last != &s) {
            dedup.push(s);
        }
    }
    dedup
}

/// Result of resolving a path-like filter input against the filesystem. Produced
/// by `DirSource::resolve` (Task 3); kept here so core path logic + its result
/// type live together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedPath {
    /// The path exists and is a directory — the picker should switch into it.
    Dir(PathBuf),
    /// The path exists and is a file — the picker should select/return it.
    File(PathBuf),
    /// The path does not exist — show "no such path" feedback, stay open.
    NotFound,
}
```

- [ ] **Step 5: Run — pass**

```bash
cargo test -p sshrack-core --lib pathutil
```
Expected: all tests pass.

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy -p sshrack-core --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(core): pure path-parse helpers for the file picker"
```

---

## Task 2: core `keydetect.rs` — private-key detection (TDD, pure)

**Files:**
- Create: `crates/sshrack-core/src/keydetect.rs`
- Modify: `crates/sshrack-core/src/lib.rs` (add `pub mod keydetect;`)

**Interfaces:**
- Produces (consumed by Task 5 rendering for the 🔑 accent):
  - `pub fn looks_like_private_key_header(first_line: &str) -> bool`
  - `pub fn looks_like_key_filename(name: &str) -> bool`

**Semantics:**
- `looks_like_private_key_header`: `true` iff `first_line` starts with `-----BEGIN ` AND ends with ` PRIVATE KEY-----`. Covers RSA/DSA/EC/OpenSSH/PKCS#8/Encrypted. Pure, no fs.
- `looks_like_key_filename`: cheap zero-IO hint — `name == "id_rsa"`, starts with `id_` (e.g. `id_ed25519`, `id_ecdsa`), or ends with `.pem` / `.key`. Used as the fast path before reading the header.

- [ ] **Step 1: Declare the module**

Add `pub mod keydetect;` to `crates/sshrack-core/src/lib.rs`.

- [ ] **Step 2: Write the failing tests (RED)**

Create `crates/sshrack-core/src/keydetect.rs` with only the test module:

```rust
//! Detect SSH private-key files so the file picker can highlight them. Two
//! pure predicates: a header check (read the file's first line elsewhere and
//! pass it here — this fn does no IO) and a cheaper filename heuristic used as
//! the fast path before any file is opened.

#[cfg(test)]
mod tests {
    use super::*;

    // ---- looks_like_private_key_header ----

    #[test]
    fn recognizes_all_mainstream_armor_headers() {
        for line in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ] {
            assert!(looks_like_private_key_header(line), "should recognize: {line}");
        }
    }

    #[test]
    fn rejects_public_key_and_random_lines() {
        assert!(!looks_like_private_key_header("ssh-rsa AAAAB3Nza..."));
        assert!(!looks_like_private_key_header("-----BEGIN PUBLIC KEY-----"));
        assert!(!looks_like_private_key_header("not a key at all"));
        assert!(!looks_like_private_key_header(""));
    }

    // ---- looks_like_key_filename ----

    #[test]
    fn filename_heuristic_flags_common_key_names() {
        assert!(looks_like_key_filename("id_rsa"));
        assert!(looks_like_key_filename("id_ed25519"));
        assert!(looks_like_key_filename("id_ecdsa"));
        assert!(looks_like_key_filename("mykey.pem"));
        assert!(looks_like_key_filename("deploy.key"));
    }

    #[test]
    fn filename_heuristic_skips_non_keys() {
        assert!(!looks_like_key_filename("id_rsa.pub"));
        assert!(!looks_like_key_filename("known_hosts"));
        assert!(!looks_like_key_filename("config"));
        assert!(!looks_like_key_filename("readme.txt"));
    }
}
```

- [ ] **Step 3: Run — expect RED** (`cannot find function looks_like_private_key_header`).

- [ ] **Step 4: Implement (GREEN)**

```rust
/// `true` iff `first_line` is a PEM/OpenSSH private-key armor header
/// (`-----BEGIN … PRIVATE KEY-----`). Covers RSA, DSA, EC, OpenSSH native,
/// PKCS#8 unencrypted, and PKCS#8 encrypted. Pure — the caller reads the file's
/// first line and passes it in; this fn never opens a file.
pub fn looks_like_private_key_header(first_line: &str) -> bool {
    let t = first_line.trim_end();
    t.starts_with("-----BEGIN ") && t.ends_with(" PRIVATE KEY-----")
}

/// Cheap zero-IO hint that `name` looks like a private-key file: exactly
/// `id_rsa`, any `id_*`, or ending `.pem` / `.key`. Excludes `.pub`. Used as the
/// fast path before reading a header; the authoritative check is
/// [`looks_like_private_key_header`] on the file's first line.
pub fn looks_like_key_filename(name: &str) -> bool {
    if name.ends_with(".pub") {
        return false;
    }
    name == "id_rsa" || name.starts_with("id_") || name.ends_with(".pem") || name.ends_with(".key")
}
```

- [ ] **Step 5: Run — pass**

```bash
cargo test -p sshrack-core --lib keydetect
```

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy -p sshrack-core --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(core): pure private-key header/filename detection"
```

---

## Task 3: core `dirsource.rs` — `DirSource` trait + `LocalDirSource` (TDD + tempdir)

**Files:**
- Create: `crates/sshrack-core/src/dirsource.rs`
- Modify: `crates/sshrack-core/src/lib.rs` (add `pub mod dirsource;`)

**Interfaces:**
- Consumes (Task 1): `crate::pathutil::{expand_tilde, start_candidates, ResolvedPath}`.
- Produces (consumed by Task 4 `FilePicker<S>`):
  - `pub enum PathKind { Dir, File, Symlink, NotFound }`
  - `pub struct DirEntry { pub name: String, pub path: std::path::PathBuf, pub is_dir: bool, pub is_symlink: bool }`
  - `pub trait DirSource { fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String>; fn classify(&self, path: &Path) -> PathKind; fn home(&self) -> Option<PathBuf>; fn resolve(&self, raw: &str, cwd: &Path) -> ResolvedPath; fn resolve_start(&self, candidates: &[String]) -> Option<PathBuf> { ... default ... } }`
  - `pub struct LocalDirSource;` and `impl DirSource for LocalDirSource` (real `std::fs`).
  - `pub(crate) fn build_entries(items: Vec<(String, PathBuf, bool, bool)>) -> Vec<DirEntry>` — pure sort/`../` insertion.

**Sorting/entry rules (pure, pinned by `build_entries` tests):**
- Output order: a leading `../` entry (when `cwd` has a parent — but `build_entries` takes already-built items; the `../` insertion + parent check happens in `LocalDirSource::list` which knows `cwd`). To keep `build_entries` pure & cwd-free, `LocalDirSource::list` builds the raw items from `read_dir`, prepends the `../` DirEntry when `cwd.parent().is_some()`, then calls `build_entries` for ordering. Concretely: `build_entries` sorts items dirs-first then case-insensitive name asc, and returns them; the `../` entry is added by `list` AFTER sorting as the very first row (so it always leads).
- Hidden files: **all shown** (`~/.ssh` is all dotfiles; filtering would empty the list).
- Symlink: detected via `symlink_metadata` (`file_type().is_symlink()`); `is_dir` via `metadata().is_dir()` (follows the link). Name gets a trailing `@` for symlinks, dirs get a trailing `/`.

- [ ] **Step 1: Declare the module**

Add `pub mod dirsource;` to `crates/sshrack-core/src/lib.rs`.

- [ ] **Step 2: Write the failing tests (RED)**

Create `crates/sshrack-core/src/dirsource.rs` with the test module. Pure `build_entries` tests + a `tempdir`-based `LocalDirSource` integration test.

```rust
//! Directory-listing capability for the file picker, behind a trait so the
//! picker is testable without a filesystem and so a future `SftpDirSource`
//! (sshrack sftp) can reuse the whole `FilePicker` component unchanged. The
//! real listing (`std::fs::read_dir`, symlink-aware) lives in
//! [`LocalDirSource`]; tests use `tempdir` for it and a hand-written fake in
//! the TUI layer. Pure entry sorting is split into [`build_entries`] so it is
//! unit-testable with no fs.

use std::path::{Path, PathBuf};

use crate::pathutil::{ResolvedPath, expand_tilde};

/// Filesystem classification of one path. `Symlink` is reported independently
/// of whether its target is a dir or file (the picker annotates with `@`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Dir,
    File,
    Symlink,
    NotFound,
}

/// One row in the picker list. `name` carries a trailing `/` for directories
/// and `@` for symlinks (display-ready); `path` is the absolute path to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Directory-listing + path-classification capability. Implementations: real
/// local fs ([`LocalDirSource`]), fake (TUI tests), future sftp.
pub trait DirSource {
    /// List `cwd`'s entries (the picker prepends `../` itself via
    /// [`Self::resolve_start`] / its own state; `list` returns cwd's children
    /// only). IO errors become `Err(message)`.
    fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String>;
    /// Classify a single path (dir / file / symlink / not-found). Used by
    /// [`Self::resolve`] and by the picker's start-directory probe.
    fn classify(&self, path: &Path) -> PathKind;
    /// The user's home directory, if known. `None` disables `~`-expansion.
    fn home(&self) -> Option<PathBuf>;
    /// Resolve a path-like filter string against `cwd` (`~`-expanded). Pure-ish:
    /// touches fs via [`Self::classify`].
    fn resolve(&self, raw: &str, cwd: &Path) -> ResolvedPath {
        let home = self.home();
        let abs = match raw {
            s if s.starts_with('~') => home
                .as_ref()
                .map(|h| expand_tilde(s, h))
                .unwrap_or_else(|| PathBuf::from(s)),
            s if Path::new(s).is_absolute() => PathBuf::from(s),
            s => cwd.join(s),
        };
        match self.classify(&abs) {
            PathKind::Dir | PathKind::Symlink => {
                // A symlink may point at a dir; treat Symlink as selectable but
                // let the picker step into it on Enter (re-list resolves it).
                ResolvedPath::Dir(abs)
            }
            PathKind::File => ResolvedPath::File(abs),
            PathKind::NotFound => ResolvedPath::NotFound,
        }
    }
    /// Pick the first candidate (a literal, possibly `~`-bearing string) that
    /// resolves to an existing directory. Returns the absolute PathBuf, or `None`
    /// when nothing resolves (the picker falls back to `/`). Default uses
    /// [`Self::classify`].
    fn resolve_start(&self, candidates: &[String]) -> Option<PathBuf> {
        let home = self.home();
        for c in candidates {
            let p = if c.starts_with('~') {
                home.as_ref().map(|h| expand_tilde(c, h))
            } else {
                Some(PathBuf::from(c))
            };
            if let Some(p) = p {
                if matches!(self.classify(&p), PathKind::Dir) {
                    return Some(p);
                }
            }
        }
        None
    }
}

/// Local filesystem listing. Zero state — all work goes through `std::fs`.
#[derive(Debug, Clone, Default)]
pub struct LocalDirSource;

impl LocalDirSource {
    pub fn new() -> Self {
        Self
    }
}

impl DirSource for LocalDirSource {
    fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String> {
        let rd = std::fs::read_dir(cwd).map_err(|e| format!("{cwd:?}: {e}"))?;
        let mut items: Vec<(String, PathBuf, bool, bool)> = Vec::new();
        for entry in rd.flatten() {
            let path = entry.path();
            let lmeta = std::fs::symlink_metadata(&path).ok();
            let fameta = std::fs::metadata(&path).ok();
            let is_symlink = lmeta
                .as_ref()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            let is_dir = fameta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let raw_name = entry.file_name().to_string_lossy().into_owned();
            let name = decorate(&raw_name, is_dir, is_symlink);
            items.push((name, path, is_dir, is_symlink));
        }
        let mut entries = build_entries(items);
        // Prepend `../` when cwd has a parent so the user can always step up.
        if cwd.parent().is_some() {
            entries.insert(0, DirEntry {
                name: "../".into(),
                path: cwd.parent().unwrap_or(cwd).to_path_buf(),
                is_dir: true,
                is_symlink: false,
            });
        }
        Ok(entries)
    }

    fn classify(&self, path: &Path) -> PathKind {
        let lmeta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return PathKind::NotFound,
        };
        if lmeta.file_type().is_symlink() {
            return PathKind::Symlink;
        }
        if lmeta.is_dir() {
            PathKind::Dir
        } else {
            PathKind::File
        }
    }

    fn home(&self) -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Decorate a raw entry name: dirs get a trailing `/`, symlinks a trailing
/// `@` (a symlink-to-dir gets `/`). Pure.
fn decorate(raw: &str, is_dir: bool, is_symlink: bool) -> String {
    if is_dir {
        format!("{raw}/")
    } else if is_symlink {
        format!("{raw}@")
    } else {
        raw.to_string()
    }
}

/// Sort raw `(name, path, is_dir, is_symlink)` items into display order:
/// directories first, then files; within each group, case-insensitive name asc.
/// Pure (no fs, no cwd knowledge). `LocalDirSource::list` calls this and then
/// prepends the `../` row.
pub(crate) fn build_entries(items: Vec<(String, PathBuf, bool, bool)>) -> Vec<DirEntry> {
    let mut items = items;
    items.sort_by(|a, b| {
        b.2.cmp(&a.2) // is_dir: true (1) before false (0)
            .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
    });
    items
        .into_iter()
        .map(|(name, path, is_dir, is_symlink)| DirEntry { name, path, is_dir, is_symlink })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- build_entries: dirs-first, case-insensitive ----

    #[test]
    fn build_entries_dirs_first_then_files_case_insensitive() {
        let items = vec![
            ("zfile.txt".into(), PathBuf::from("/d/zfile.txt"), false, false),
            ("Adir".into(), PathBuf::from("/d/Adir"), true, false),
            ("afile.txt".into(), PathBuf::from("/d/afile.txt"), false, false),
            ("Bdir".into(), PathBuf::from("/d/Bdir"), true, false),
        ];
        let e = build_entries(items);
        let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["Adir/", "Bdir/", "afile.txt", "zfile.txt"]);
    }

    #[test]
    fn build_entries_empty_is_empty() {
        assert!(build_entries(Vec::new()).is_empty());
    }

    // ---- LocalDirSource against a real tempdir ----

    #[test]
    fn local_list_prepends_parent_and_decorates() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("id_ed25519"), b"-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        // tmp has a parent, so `../` leads.
        let entries = LocalDirSource::new().list(root).unwrap();
        assert_eq!(entries[0].name, "../");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"sub/"));
        assert!(names.contains(&"id_ed25519"));
        assert!(names.contains(&"readme.txt"));
        // dirs before files: sub/ precedes id_ed25519.
        let sub_i = names.iter().position(|n| *n == "sub/").unwrap();
        let id_i = names.iter().position(|n| *n == "id_ed25519").unwrap();
        assert!(sub_i < id_i);
    }

    #[test]
    fn local_list_shows_hidden_files() {
        // ~/.ssh is all dotfiles; the picker MUST show them.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".hidden"), b"x").unwrap();
        let entries = LocalDirSource::new().list(tmp.path()).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&".hidden"), "hidden file must be shown: {names:?}");
    }

    #[test]
    fn local_classify_dir_file_symlink_notfound() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        let file = tmp.path().join("f");
        let link = tmp.path().join("l");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let s = LocalDirSource::new();
        assert_eq!(s.classify(&dir), PathKind::Dir);
        assert_eq!(s.classify(&file), PathKind::File);
        #[cfg(unix)]
        assert_eq!(s.classify(&link), PathKind::Symlink);
        assert_eq!(s.classify(tmp.path().join("nope")), PathKind::NotFound);
    }

    #[test]
    fn local_list_io_error_is_err_string() {
        let s = LocalDirSource::new();
        assert!(s.list(Path::new("/definitely/not/here/xyz")).is_err());
    }

    // ---- resolve / resolve_start ----

    #[test]
    fn resolve_relative_file_against_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("key.pem");
        std::fs::write(&f, b"x").unwrap();
        struct L(LocalDirSource);
        impl DirSource for L {
            fn list(&self, _: &Path) -> Result<Vec<DirEntry>, String> { self.0.list(Path::new("/")) }
            fn classify(&self, p: &Path) -> PathKind { self.0.classify(p) }
            fn home(&self) -> Option<PathBuf> { self.0.home() }
        }
        let s = L(LocalDirSource::new());
        assert_eq!(s.resolve("key.pem", tmp.path()), ResolvedPath::File(f));
    }

    #[test]
    fn resolve_notfound_is_notfound() {
        let tmp = tempfile::tempdir().unwrap();
        let s = LocalDirSource::new();
        assert_eq!(s.resolve("nope", tmp.path()), ResolvedPath::NotFound);
    }

    #[test]
    fn resolve_start_picks_first_existing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let s = LocalDirSource::new();
        let cands = vec!["/no/such".to_string(), sub.to_string_lossy().into_owned()];
        assert_eq!(s.resolve_start(&cands), Some(sub));
    }

    #[test]
    fn resolve_start_none_when_all_missing() {
        let s = LocalDirSource::new();
        assert_eq!(s.resolve_start(&["/no/such/a".into(), "/no/such/b".into()]), None);
    }
}
```

- [ ] **Step 3: Run — expect RED** (compile errors: missing types). Then Step 4 already provides the impl above the tests; after writing it, RED→GREEN.

```bash
cargo test -p sshrack-core --lib dirsource 2>&1 | head -30
```

- [ ] **Step 4: Implement** — the impl block above is the implementation; place it above the `#[cfg(test)]` module. (The trait, `LocalDirSource`, `build_entries`, and `decorate` are all shown in full above.)

- [ ] **Step 5: Run — pass**

```bash
cargo test -p sshrack-core --lib dirsource
```

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy -p sshrack-core --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(core): DirSource trait + LocalDirSource for the file picker"
```

---

## Task 4: TUI `file_picker.rs` — `FilePicker<S>` state machine + path-aware `on_key` (TDD, fake source)

**Files:**
- Create: `src/tui/file_picker.rs`
- Modify: `src/tui/mod.rs` (add `pub mod file_picker;`)

**Interfaces:**
- Consumes: `sshrack_core::dirsource::{DirSource, DirEntry, LocalDirSource}`, `sshrack_core::pathutil::{parse_filter_intent, start_candidates, ResolvedPath}`, `crate::tui::panel::{rank_by_fields, highlighted_spans}`.
- Produces (consumed by Task 6/7 wizard):
  - `pub enum FilePickerOutcome { Pick(PathBuf), Cancel, Pending }`
  - `pub struct FilePicker<S: DirSource = LocalDirSource> { ... }`
  - `impl<S: DirSource> FilePicker<S> { pub fn new(title: &'static str, identity_hint: Option<&str>, source: S) -> Self; pub fn on_key(&mut self, key: KeyEvent) -> FilePickerOutcome; pub fn draw_overlay(&self, frame: &mut Frame); }`

**Purity / fs boundary (load-bearing):**
- `FilePicker::new` performs NO fs. It stores `start_candidates(identity_hint)` (literals) and `source`.
- `ensure_started(&mut self)` is called lazily at the top of `on_key` (after the Esc/Ctrl-C short-circuit) and at the top of `draw_overlay`. The first call resolves the start directory via `source.resolve_start(&candidates)` (falling back to `/`) and lists it. This keeps the wizard's pure `on_key` tests fs-free: opening the picker (`new`) does not fs, and `Esc` closes before any list.
- All fs goes through `self.source` (the injected `S: DirSource`). Tests inject a fake.

**Keymap (pin in tests):**
- Printable char (no ctrl) → push to `query`, recompute ranking, `selected=0`, `Pending`.
- `Backspace` → if `query` non-empty: pop + recompute; else (empty) step up one dir. `Pending`.
- `Up`/`Down` (or `^p`/`^n`) → move `selected` (wrap). `Pending`.
- `Enter` / `Right` → if `parse_filter_intent(query)` is `PathLike`: `source.resolve(query, cwd)` → `Dir` switch into it (list, clear query, selected=0); `File` → `Pick(abs)`; `NotFound` → set status `"no such path"`. If `Fuzzy`: select the entry under the cursor — if it's a dir (`../` or `is_dir`), step into it; else `Pick(entry.path)`. `Pending` (unless `Pick`).
- `Left` → step up one dir. `Pending`.
- `Esc` → `Cancel`. `^c` → `Cancel`.

- [ ] **Step 1: Declare the module**

In `src/tui/mod.rs`, add `pub mod file_picker;` (next to `pub mod wizard;`).

- [ ] **Step 2: Write the failing tests (RED)**

Create `src/tui/file_picker.rs` with the test module using a `FakeSource` (in-memory dir tree). The fake implements `DirSource` over a `HashMap<PathBuf, Vec<DirEntry>>` so tests need no fs.

```rust
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
    Pick(std::path::PathBuf),
    Cancel,
    Pending,
}

/// Modal file picker. Generic over [`DirSource`] so tests inject a fake and a
/// future sftp source reuses the component. `cwd`/`entries` are `None` until the
/// lazy [`ensure_started`] resolves the start directory.
pub struct FilePicker<S: DirSource = LocalDirSource> {
    title: &'static str,
    source: S,
    candidates: Vec<String>,
    cwd: Option<std::path::PathBuf>,
    entries: Vec<DirEntry>,
    query: String,
    ranked: Vec<usize>, // indices into `entries`, fuzzy-ordered by `query`
    selected: usize,    // index into `ranked`
    status: Option<String>,
    started: bool,
}

impl<S: DirSource> FilePicker<S> {
    /// Open a picker. `identity_hint` seeds the start-directory candidates (its
    /// parent dir leads). NO filesystem access — the first listing is lazy.
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

    // ---- implementation steps below ----
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
                if is_dir { format!("{raw}/") } else { raw.to_string() }
            };
            DirEntry { name: decorate(name), path: parent.join(name), is_dir, is_symlink: false }
        }
    }
    impl DirSource for FakeSource {
        fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String> {
            let mut e = self.dirs.get(cwd).cloned().unwrap_or_default();
            if cwd.parent().is_some() {
                e.insert(0, DirEntry {
                    name: "../".into(),
                    path: cwd.parent().unwrap().to_path_buf(),
                    is_dir: true,
                    is_symlink: false,
                });
            }
            Ok(e)
        }
        fn classify(&self, p: &Path) -> PathKind {
            if self.dirs.contains_key(p) { PathKind::Dir }
            else if self.dirs.values().flatten().any(|e| e.path.as_path() == p && !e.is_dir) {
                PathKind::File
            } else { PathKind::NotFound }
        }
        fn home(&self) -> Option<PathBuf> { self.home.clone() }
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    /// Build a tiny tree: /h/.ssh/{id_ed25519, id_ed25519.pub, config}, /h, /.
    fn tree() -> FakeSource {
        let mut f = FakeSource::default();
        f.home = Some(PathBuf::from("/h"));
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
            vec![DirEntry { name: ".ssh/".into(), path: dotssh.clone(), is_dir: true, is_symlink: false }],
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
            fn list(&self, _: &Path) -> Result<Vec<DirEntry>, String> { panic!("list in new()") }
            fn classify(&self, _: &Path) -> PathKind { panic!("classify in new()") }
            fn home(&self) -> Option<PathBuf> { panic!("home in new()") }
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
        let names: Vec<&str> = p.ranked.iter().map(|&i| p.entries[i].name.as_str()).collect();
        assert!(names.iter().all(|n| n.starts_with("id_ed")), "{names:?}");
    }

    // ---- Enter on a file Picks its absolute path ----

    #[test]
    fn enter_on_file_picks_absolute_path() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        // cursor at index 0 of ranked; in /h/.ssh ranked[0] is the first
        // dirs-first/file entry. entries has no subdirs here, so ranked[0] is
        // the alphabetically-first file. Move down to id_ed25519 if needed.
        while p.ranked.get(p.selected).map_or(true, |&i| p.entries[i].name != "id_ed25519") {
            let _ = p.on_key(press(KeyCode::Down));
            if p.selected == 0 { break; }
        }
        let out = p.on_key(press(KeyCode::Enter));
        assert_eq!(out, FilePickerOutcome::Pick(PathBuf::from("/h/.ssh/id_ed25519")));
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
        assert_eq!(p.on_key(press(KeyCode::Enter)), FilePickerOutcome::Pick(PathBuf::from("/h/.ssh/config")));
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
            fn list(&self, _: &Path) -> Result<Vec<DirEntry>, String> { panic!() }
            fn classify(&self, _: &Path) -> PathKind { panic!() }
            fn home(&self) -> Option<PathBuf> { panic!() }
        }
        let mut p = FilePicker::new("pick", None, Panic);
        assert_eq!(p.on_key(press(KeyCode::Esc)), FilePickerOutcome::Cancel);
    }

    #[test]
    fn ctrl_c_cancels() {
        let mut p = FilePicker::new("pick", None, tree());
        let cc = KeyEvent::new_with_kind(KeyCode::Char('c'), KeyModifiers::CONTROL, KeyEventKind::Press);
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
        for c in "id".chars() { let _ = p.on_key(press(KeyCode::Char(c))); }
        let _ = p.on_key(press(KeyCode::Backspace));
        assert!(p.query.is_empty());
    }

    #[test]
    fn up_down_move_selected_with_wrap() {
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        let n = p.ranked.len();
        assert!(n >= 1);
        let _ = p.on_key(press(KeyCode::Down));
        let _ = p.on_key(press(KeyCode::Up));
        // wrap top -> bottom
        for _ in 0..n { let _ = p.on_key(press(KeyCode::Down)); }
        assert!(p.selected < n);
    }
}
```

- [ ] **Step 3: Run — expect RED** (`ensure_started` / `on_key` missing).

```bash
cargo test --lib tui::file_picker 2>&1 | head -30
```

- [ ] **Step 4: Implement (GREEN)** — add inside `impl<S: DirSource> FilePicker<S>`:

```rust
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
    fn recompute(&mut self) {
        let rows: Vec<Vec<String>> = self.entries.iter().map(|e| vec![e.name.clone()]).collect();
        let scores = vec![0.0f64; self.entries.len()];
        self.ranked = crate::tui::panel::rank_by_fields(&rows, &scores, &self.query);
    }

    fn clamp_selected(&mut self) {
        if self.ranked.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len() - 1;
        }
    }

    fn move_cursor(&mut self, delta: i32) {
        if self.ranked.is_empty() {
            return;
        }
        let n = self.ranked.len() as i32;
        self.selected = ((self.selected as i32 + delta).rem_euclid(n)) as usize;
    }

    /// Entry under the cursor, or `None` when the ranked list is empty.
    fn selected_entry(&self) -> Option<&DirEntry> {
        self.ranked.get(self.selected).and_then(|&i| self.entries.get(i))
    }

    /// Step into `child` (a dir entry) or up to the parent when `child` is None.
    fn step_into(&mut self, child: &DirEntry) {
        self.load(child.path.clone());
    }

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
                let Some(cwd) = self.cwd.clone() else { return FilePickerOutcome::Pending };
                match self.source.resolve(&raw, &cwd) {
                    sshrack_core::pathutil::ResolvedPath::File(abs) => {
                        FilePickerOutcome::Pick(abs)
                    }
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

    /// (draw_overlay is implemented in Task 5.)
    pub fn draw_overlay(&self, _frame: &mut Frame) {
        // Task 5 fills this in.
    }
```

- [ ] **Step 5: Run — pass**

```bash
cargo test --lib tui::file_picker
```
Note: `ensure_started` is called by tests directly; it is `pub`. The state-machine tests now pass.

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): FilePicker state machine with path-aware on_key"
```

---

## Task 5: TUI `file_picker.rs` — `draw_overlay` rendering + key-header highlight on demand

**Files:**
- Modify: `src/tui/file_picker.rs` (replace the Task-4 stub `draw_overlay`).

**Interfaces:**
- Consumes: `crate::tui::popup::{render_popup, POPUP_WIDTH, POPUP_HEIGHT}`, `crate::tui::panel::highlighted_spans`, `crate::tui::fit::{focus_window, truncate_cells}`, `crate::tui::theme`, `sshrack_core::keydetect::{looks_like_private_key_header, looks_like_key_filename}`.

**Layout (popup body):** 4 vertical segments — `cwd` line (left-truncated via `truncate_cells` so the tail — the current dir name — survives), `list` (Fill, windowed via `focus_window`), `query` line (`> {query}_`), `hint`/`status` line (1). Selected row leads with `▶ ` and BOLD; matched chars use `highlighted_spans(query)`; a private-key file (filename heuristic OR header on-demand) gets the accent foreground.

**On-demand key detection:** the visible window is small (≤16 rows); for each *visible* non-dir entry, check `looks_like_key_filename(name)` first (zero IO), and if that is false, read its first line via `std::fs::File` + `BufRead` and call `looks_like_private_key_header`. Wrap the IO in `if let Ok(...)` so unreadable files simply are not highlighted. Local fs only — this is fine because `FilePicker` is only ever constructed with `LocalDirSource` in production; the `draw_overlay` tests use a `TestBackend` with a fake source whose entries' paths need not be readable (the IO guard returns false).

- [ ] **Step 1: Add no-panic render tests (RED-ish)**

Append to `src/tui/file_picker.rs` test module:

```rust
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
        for c in "/no/such".chars() { let _ = p.on_key(press(KeyCode::Char(c))); }
        let _ = p.on_key(press(KeyCode::Enter)); // sets status
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let _ = term.draw(|f| p.draw_overlay(f));
    }
```

- [ ] **Step 2: Run — expect RED/panic** (the stub does nothing; tests pass trivially, so first make the stub actually render — then the tiny-terminal test is the real guard).

- [ ] **Step 3: Implement `draw_overlay`** — replace the stub body:

```rust
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
        let shown = crate::tui::fit::truncate_cells(
            &format!(" {cwd_str}"),
            avail,
        );
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
                let Some(&idx) = self.ranked.get(i) else { continue };
                let Some(entry) = self.entries.get(idx) else { continue };
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
                            .and_then(|f| BufReader::new(f).lines().next().and_then(|r| r.ok()))
                            .map(|l| sshrack_core::keydetect::looks_like_private_key_header(&l))
                            .unwrap_or(false)
                    }
                };
                let value_style = if keyish { base.fg(crate::tui::theme::MATCH) } else { base };
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
            Span::styled("> ", crate::tui::theme::accent().add_modifier(Modifier::BOLD)),
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
```

- [ ] **Step 4: Run — pass**

```bash
cargo test --lib tui::file_picker
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```

- [ ] **Step 5: commit**

```bash
git add -A && git commit -m "feat(tui): render FilePicker overlay with cwd/list/query/status"
```

---

## Task 6: HostForm — Identity row becomes a trigger row + mount `FilePicker`

**Files:**
- Modify: `src/tui/wizard/host.rs` (struct field, Debug impl, `on_key` route + Enter guard, `edit_focused_insert`/`edit_focused_backspace`, `focused_text_len`, `cursor_target`, `row_value_and_placeholder`, `hint_for_focus`, `draw_in_dialog` overlay, `new_add`/`new_edit` construct the field default).
- Modify: `src/tui/wizard/mod.rs` (re-export `FilePicker`/`FilePickerOutcome` if the wizard root re-exports pickers — mirror how `CredPicker`/`PickerOutcome` are re-exported at `wizard/mod.rs:35`).

**Interfaces:**
- Consumes: `crate::tui::file_picker::{FilePicker, FilePickerOutcome}`, `sshrack_core::dirsource::LocalDirSource`.

**The Identity trigger-row contract (host wizard):**
- The Identity row is no longer a text field. It is a trigger row like `Field::Credential`: focus lands on it, `Enter` opens `FilePicker`, printable chars / Backspace / `←`/`→`/Home/End are no-ops on it (the hint says `Enter browse`).
- `self.identity` stays a `String` — it now holds the **selected absolute path** (written back by the picker), never typed char-by-char.
- On `Pick(abs)`: `self.identity = abs.to_string_lossy().into_owned(); self.cursor = 0;`.

- [ ] **Step 1: Add the field + Debug**

In `src/tui/wizard/host.rs`:
- Add `use crate::tui::file_picker::{FilePicker, FilePickerOutcome};` near the other `use` imports (and `use sshrack_core::dirsource::LocalDirSource;`).
- Add a struct field after `pub key_paste: Option<KeyPaste>,` (≈ line 126):

```rust
    /// Modal file picker for the Identity path (Path source). `None` when
    /// closed. Routed at the top of [`HostForm::on_key`] (modal — swallows every
    /// key while open, incl `Ctrl-S`, like the cred picker / paste popup). The
    /// picker is a reusable component (`crate::tui::file_picker`) that does NOT
    /// import this module; it returns the chosen absolute path via
    /// [`FilePickerOutcome::Pick`]. Directory listing is injected via
    /// [`LocalDirSource`] now; a future `SftpDirSource` reuses the picker.
    pub file_picker: Option<FilePicker<LocalDirSource>>,
```

- In the `Debug` impl (≈ line 142), add `.field("file_picker", &self.file_picker.is_some())` before `.finish()` (surface only open/closed, never contents).

- In `new_add` and `new_edit`, initialize `file_picker: None,`.

- [ ] **Step 2: Add the modal route at the top of `on_key`**

In `HostForm::on_key` (≈ line 580), after the `key_paste` modal block (after line 626, before `let ctrl = ...` at line 628), insert:

```rust
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
```

- [ ] **Step 3: Open the picker on `Enter` for the Identity row**

In the `KeyCode::Enter =>` arm (≈ line 655), BEFORE the `is_last_reachable` check (after the InlinePrivate/InlineCert block ending ≈ line 687), insert a new guard:

```rust
                // Identity row is a trigger (Path source): Enter opens the file
                // picker. Guarded by reachability so it only opens when the
                // Identity path-slot is actually present (Independent +
                // IdentityKey + Path). The picker is modal; Enter inside it
                // activates a selection (handled above).
                if self.focus == Field::Identity
                    && Self::field_reachable(
                        self.focus,
                        &self.auth_choice,
                        self.secret_kind,
                        self.source,
                    )
                {
                    self.file_picker = Some(FilePicker::new(
                        " pick a private key ",
                        Some(self.identity.as_str()),
                        LocalDirSource::new(),
                    ));
                    self.error = None;
                    return Outcome::Continue;
                }
```

- [ ] **Step 4: Remove in-place editing on the Identity row**

`Identity` is now a trigger row, so it must NOT accept char/backspace/cursor editing:
- In `edit_focused_insert` (≈ line 793): change the `Field::Identity => self.cursor = insert_char_at(&mut self.identity, self.cursor, c),` arm to a no-op grouped with the other non-text rows. After the change, the `Field::Identity` arm is removed; the text arms are `Name`/`Host`/`Port`/`User`/`Password`.
- In `edit_focused_backspace` (≈ line 829): remove the `Field::Identity` arm likewise.
- In `focused_text_len` (≈ line 984): change `Field::Identity => self.identity.chars().count(),` to `0`, and move `Field::Identity` into the chooser/no-cursor group (return 0).
- In `cursor_target` (≈ line 1008): remove `Field::Identity => self.cursor.min(self.identity.chars().count()),` and add `Field::Identity` to the `return None` group (it's a trigger row like Credential).

- [ ] **Step 5: Update the placeholder + hint for the Identity row**

- In `row_value_and_placeholder` (≈ line 1097), change the `Field::Identity => (self.identity.clone(), Some("path to a private key"))` arm to:

```rust
            Field::Identity => {
                // Trigger row: shows the selected path (if any) or a browse hint.
                // The path is filled by the file picker, never typed.
                if self.identity.is_empty() {
                    (String::new(), Some("Enter to browse for a private key"))
                } else {
                    (self.identity.clone(), Some("Enter to re-browse"))
                }
            }
```

- In `hint_for_focus` (≈ line 875), add an explicit arm:

```rust
            Field::Identity => "  Enter browse files",
```

- [ ] **Step 6: Paint the picker overlay last in `draw_in_dialog`**

In `draw_in_dialog` (≈ line 901), after the `key_paste` overlay block (after line 977), insert:

```rust
        // If the file picker is open, paint it over the wizard (last, so it
        // sits on top of the form and any other overlay; only one is open at a
        // time — the picker opens from the Identity row, the cred picker from
        // the Credential row, the paste popup from the Inline rows).
        if let Some(picker) = &self.file_picker {
            picker.draw_overlay(frame);
        }
```

- [ ] **Step 7: Tests (RED → GREEN)**

Add to the `host.rs` test module:

```rust
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
        assert!(form.file_picker.is_some(), "Enter on Identity opens the picker");
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
        assert!(form.identity.is_empty(), "Identity must not accept in-place typing");
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
            let body = crate::tui::dialog::draw_dialog(f, &form.title(), form.body_rows(), &[]);
            form.draw_in_dialog(f, body);
        });
    }
```

- [ ] **Step 8: Run — pass; update any existing test that assumed Identity typing**

```bash
cargo test --lib tui::wizard::host
```
If any pre-existing test typed into Identity, update it to use the picker (set `form.identity` directly) — search the host test module for `Field::Identity` and `insert_char_at(&mut form.identity`.

- [ ] **Step 9: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): open file picker from the host wizard Identity row"
```

---

## Task 7: CredForm — mirror Task 6 for the credential wizard

**Files:**
- Modify: `src/tui/wizard/cred.rs` (same set of edits as Task 6, against `CredField::Identity`).

**Interfaces:** identical to Task 6.

**Differences from host:**
- `CredField` has no `Credential`/`Auth` rows; the Identity row sits under `SecretKind::IdentityKey` + `Source::Path` (already in `field_reachable`, see `cred.rs:266-291`). The trigger row treatment is otherwise identical.
- The cred wizard's `on_key` has only the `key_paste` modal block above the main match (≈ line 355); insert the `file_picker` modal block right after it (before `let ctrl = ...` at ≈ line 373).
- The cred `on_key` Enter arm is at ≈ line 408; insert the Identity guard after the InlinePrivate/InlineCert block (≈ line 429) and before `is_last_reachable`.
- The cred `draw_in_dialog` paints the paste overlay at ≈ line 721; add the picker overlay after it.
- The cred hint is inline in `draw_in_dialog` (≈ line 689-697), not a separate `hint_for_focus` fn — extend that inline `if/else if` chain with `CredField::Identity => "  Enter browse files"`.

- [ ] **Step 1: Field + Debug + `new_add`/`new_edit`**

Mirror Task 6 Step 1: add `pub file_picker: Option<FilePicker<LocalDirSource>>`, the `use` imports, the Debug field (`.field("file_picker", &self.file_picker.is_some())`), and `file_picker: None` in both constructors.

- [ ] **Step 2: Modal route in `on_key`** — mirror Task 6 Step 2 (insert after the `key_paste` block).

- [ ] **Step 3: Enter guard** — mirror Task 6 Step 3, using `CredField::Identity` and `Self::field_reachable(self.focus, self.secret_kind, self.source)` (cred's `field_reachable` takes `(field, secret, source)` — no auth).

- [ ] **Step 4: Remove in-place editing** — mirror Task 6 Step 4: drop the `CredField::Identity` arms in `edit_focused_insert` (≈ line 516), `edit_focused_backspace` (≈ line 542), `focused_text_len` (≈ line 734, return 0), `cursor_target` (≈ line 754, return None).

- [ ] **Step 5: Placeholder + hint** — in `row_value_and_placeholder` (≈ line 841) replace the `CredField::Identity` arm with the same "Enter to browse" / "Enter to re-browse" logic as Task 6 Step 5. Extend the inline hint chain in `draw_in_dialog` (≈ line 689) with the Identity arm.

- [ ] **Step 6: Paint the overlay** — mirror Task 6 Step 6 (after the `key_paste` overlay at ≈ line 721).

- [ ] **Step 7: Tests** — mirror Task 6 Step 7 (`enter_on_identity_opens_file_picker`, `typing_on_identity_is_a_noop_it_is_a_trigger_row`, `enter_on_identity_under_non_identitykey_does_not_open_picker` with `SecretKind::None`, and a `draw_in_dialog_with_open_picker_renders_without_panic` smoke).

- [ ] **Step 8: Run + update pre-existing Identity-typing tests**

```bash
cargo test --lib tui::wizard::cred
```

- [ ] **Step 9: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): open file picker from the credential wizard Identity row"
```

---

## Task 8: Docs + full gate + manual smoke

**Files:**
- Modify: `CLAUDE.md` (TUI Identity trigger-row wording + FilePicker keymap + `DirSource`-for-sftp note).

- [ ] **Step 1: Update `CLAUDE.md`**

In the TUI section, add a short subsection (mirror the existing wizard/overlay wording):

```markdown
### File picker overlay (Identity key path)

The Identity-key **Path** row is a trigger row in both the host and credential
wizards: `Enter` opens a modal file picker (`src/tui/file_picker.rs`) — it is
NOT typed in place. The picker's single filter box is path-aware:

- typing a plain name → nucleo fuzzy-filter of the current directory's entries;
- typing/pasting a path (anything containing `/` or a leading `~`) → `Enter`
  resolves it: a directory is entered, a file is selected (absolute path written
  back to the Identity row), a missing path shows a red "no such path" line.

Selected paths are written back **absolute** (`~` expanded), which sidesteps the
OpenSSH `-i` quirk of not expanding `~` on the command line. Keys: `↑↓/^p/^n`
move · `Enter`/`→` open dir / select file · `←` up · `Backspace` pops filter or
steps up when empty · `Esc/^c` clear filter or cancel. The picker is a reusable,
business-decoupled component (`FilePicker<S: DirSource>`); directory listing is
injected via the core `DirSource` trait (`LocalDirSource` now, a future
`SftpDirSource` for `sshrack sftp` reuses the whole component unchanged).
```

Also update the "Identity-key source" wizard bullet to note the Path source's Identity row is `Enter`-to-browse (not typed).

- [ ] **Step 2: Full workspace gate**

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
All must pass. (Tests run with `SSHRACK_PASSPHRASE` already set in the shell, per project rule.)

- [ ] **Step 3: Manual smoke** (`cargo run -q -- host add`, then in the wizard):

- Set Auth = Independent, Secret = IdentityKey, Source = Path, focus Identity, `Enter` → picker opens in `~/.ssh/`.
- Type `id_ed` → list narrows; `↑↓` moves; a private key shows the accent color.
- `Enter` on a key file → absolute path written back to Identity; picker closes.
- Re-open, paste `~/.ssh/<name>` into the filter, `Enter` → that file selected.
- Paste a missing path, `Enter` → red "no such path"; picker stays.
- `←` / empty-`Backspace` steps up a dir; `Esc` clears filter then cancels.
- Resize the terminal to ~12 rows with the picker open → list scrolls to keep the selection visible, no panic.
- Repeat in the credential wizard (`cargo run -q -- cred add`).

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "docs(tui): document the file picker overlay and DirSource seam"
```

Then use the `superpowers:finishing-a-development-branch` skill to merge.

---

## Self-Review

**1. Spec coverage:**
- Hand-input + browser + in-browser filter (three-in-one, unified in the picker's path-aware filter box): Tasks 4–7. ✅
- Identity row = trigger row (`Enter` opens picker; no in-place typing): Tasks 6–7 (Step 4 removes in-place editing). ✅
- Path-aware filter (fuzzy vs path-like), `Enter` resolves dir/file/not-found: Task 1 (`parse_filter_intent`/`ResolvedPath`) + Task 4 (`activate_selected`). ✅
- Hidden files shown, symlink-aware, dirs-first sort, `../` prepend: Task 3 (`LocalDirSource`). ✅
- Private-key highlight (filename heuristic + on-demand header): Task 2 + Task 5. ✅
- `~` expansion + absolute write-back (fixes the `-i` quirk): Task 1 (`expand_tilde`) + Task 3 (`resolve`) + Task 6/7 (write-back). ✅
- Decoupled / reusable / `DirSource` seam for sftp: Task 3 trait + Task 4 generic `FilePicker<S>` + Task 6/7 caller writes the field. ✅
- Start-directory heuristic: Task 1 (`start_candidates`) + Task 3 (`resolve_start`) + Task 4 (`ensure_started`). ✅
- High performance (single-level read_dir, one nucleo matcher per query, on-demand key detect over visible rows only): Task 3 + Task 4 (`recompute`) + Task 5. ✅
- Purity boundary (wizard `on_key` tests stay fs-free): Task 4 lazy `ensure_started` + Esc short-circuit, proven by `new_does_not_touch_fs` and `esc_cancels_without_touching_fs`. ✅
- Zero new deps, zero unsafe, zero prod unwrap, hermetic tests, clippy/fmt, English, conventional commits: every task's Step 6/9 + Task 8 gate. ✅

**2. Placeholder scan:** No TBD/TODO. Each step carries the code to write or the exact edit + reference line numbers. The two "mirror Task N" steps (Task 7) repeat the contract explicitly because an implementer may read tasks out of order.

**3. Type consistency:**
- `FilterIntent`/`ResolvedPath` defined Task 1, consumed identically in Task 3 (`resolve`) and Task 4 (`activate_selected`). ✅
- `DirEntry { name, path, is_dir, is_symlink }` defined Task 3, consumed in Task 4 (`selected_entry`) and Task 5 (`entry.name`/`entry.path`/`entry.is_dir`). ✅
- `DirSource::{list, classify, home, resolve, resolve_start}` defined Task 3 (trait), used in Task 4 (`ensure_started`/`load`/`resolve`) with the same names. ✅
- `FilePicker<S = LocalDirSource>` + `FilePickerOutcome::{Pick, Cancel, Pending}` defined Task 4, constructed in Task 6/7 (`FilePicker::new(" pick a private key ", Some(self.identity.as_str()), LocalDirSource::new())`) and matched on the same variants. ✅
- `start_candidates(identity_hint: Option<&str>) -> Vec<String>` (Task 1) is what `FilePicker::new` passes to its internal `candidates` (Task 4) — `&str`/`String` match. ✅
- `ensure_started` is `pub` (Task 4) because tests call it directly; `load`/`recompute`/`step_up`/`activate_selected` are private. Consistent across Task 4/5. ✅
