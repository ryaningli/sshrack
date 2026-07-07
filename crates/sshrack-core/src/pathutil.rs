//! Pure path-parse helpers for the file picker: classifying the filter-box
//! input as a fuzzy term vs a path-like string, expanding a leading `~`, and
//! computing the ordered start-directory candidates. None of these touch the
//! filesystem — `home` is always a parameter — so the whole module is unit-
//! testable with no tempdir.

use std::path::{Component, Path, PathBuf};

/// What the filter-box input means. A string with a `~` prefix OR containing a
/// `/` anywhere is treated as a path the user typed/pasted; anything else is a
/// fuzzy filter over the current directory's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterIntent {
    /// Fuzzy-match against the current directory's entry names.
    Fuzzy(String),
    /// A path-like string to resolve (relative to cwd, or `~`-expanded).
    PathLike(String),
}

/// Classify `input`. A `~` prefix OR any input containing `/` is
/// [`FilterIntent::PathLike`]; everything else (including empty) is
/// [`FilterIntent::Fuzzy`]. Pure.
///
/// Note: the `~user` form classifies as `PathLike` (consistent with `~` and
/// `~/foo`), but [`expand_tilde`] does NOT expand it — it returns the input
/// as-is, which then classifies as `NotFound`, yielding a clear "no such path:
/// ~user" status. Supporting `~user`-expansion would require parsing
/// `/etc/passwd`, which is YAGNI for SSH-key selection.
pub fn parse_filter_intent(input: &str) -> FilterIntent {
    if input.starts_with('~') || input.contains('/') {
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

/// Lexically normalize `path`: resolve `.` and `..` components without
/// touching the filesystem (no symlink resolution). `.` is dropped; `..`
/// pops the preceding normal component, or is dropped at/under a root/prefix
/// (so `/..` stays `/`). Pure — used to identify sftp `ls -la` self-reference
/// rows (`.` as `<cwd>`, `..` as `<cwd>/..`) by comparing to `cwd`/its parent.
pub fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out: Vec<Component<'_>> = Vec::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => match out.last() {
                Some(Component::Normal(_)) => {
                    let _ = out.pop();
                }
                Some(Component::RootDir) | Some(Component::Prefix(_)) => {}
                _ => out.push(c),
            },
            other => out.push(other),
        }
    }
    let mut ret = PathBuf::new();
    for c in &out {
        ret.push(c.as_os_str());
    }
    ret
}

/// Ordered start-directory candidates (literals — `~` is NOT expanded here; the
/// `DirSource` resolves and expands). If `identity_hint` has a parent, it goes
/// first so the user lands where their current key lives. Then `~/.ssh`, `~`,
/// `/`. Duplicates (when the parent hint collides with one of the defaults) are
/// dropped so each candidate appears at most once. Pure.
pub fn start_candidates(identity_hint: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push_unique = |s: String| {
        if !out.iter().any(|e| e == &s) {
            out.push(s);
        }
    };
    if let Some(hint) = identity_hint {
        let hint = hint.trim();
        if !hint.is_empty() {
            if let Some(parent) = Path::new(hint).parent() {
                let p = parent.to_string_lossy().into_owned();
                if !p.is_empty() {
                    push_unique(p);
                }
            }
        }
    }
    for c in ["~/.ssh", "~", "/"] {
        push_unique(c.to_string());
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // ---- normalize_lexical ----

    #[test]
    fn normalize_resolves_parent_dir() {
        assert_eq!(normalize_lexical(Path::new("/tmp/a/..")), Path::new("/tmp"));
    }

    #[test]
    fn normalize_drops_cur_dir() {
        assert_eq!(
            normalize_lexical(Path::new("/tmp/a/.")),
            Path::new("/tmp/a")
        );
    }

    #[test]
    fn normalize_keeps_already_clean() {
        assert_eq!(normalize_lexical(Path::new("/tmp/a")), Path::new("/tmp/a"));
    }

    #[test]
    fn normalize_clamps_at_root() {
        assert_eq!(normalize_lexical(Path::new("/..")), Path::new("/"));
        assert_eq!(normalize_lexical(Path::new("/")), Path::new("/"));
    }

    #[test]
    fn normalize_handles_relative() {
        assert_eq!(normalize_lexical(Path::new("a/../b")), Path::new("b"));
    }

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
        assert!(matches!(
            parse_filter_intent("~/x"),
            FilterIntent::PathLike(_)
        ));
        assert!(matches!(
            parse_filter_intent("a/b"),
            FilterIntent::PathLike(_)
        ));
        assert!(matches!(
            parse_filter_intent("./x"),
            FilterIntent::PathLike(_)
        ));
        assert!(matches!(
            parse_filter_intent("/abs"),
            FilterIntent::PathLike(_)
        ));
        assert!(matches!(
            parse_filter_intent("trailing/"),
            FilterIntent::PathLike(_)
        ));
    }

    #[test]
    fn leading_tilde_alone_is_pathlike() {
        assert!(matches!(
            parse_filter_intent("~"),
            FilterIntent::PathLike(_)
        ));
    }

    #[test]
    fn leading_tilde_without_slash_is_pathlike() {
        // `~foo` (~user form) is PathLike, consistent with `~` and `~/foo`.
        assert!(matches!(
            parse_filter_intent("~foo"),
            FilterIntent::PathLike(_)
        ));
        assert!(matches!(
            parse_filter_intent("~"),
            FilterIntent::PathLike(_)
        ));
        assert!(matches!(
            parse_filter_intent("~/x"),
            FilterIntent::PathLike(_)
        ));
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
    fn start_candidates_dedups_when_parent_equals_tilde() {
        // identity "~/x" has parent "~"; after dedup the second "~" is dropped.
        let c = start_candidates(Some("~/x"));
        let tilde_count = c.iter().filter(|s| s.as_str() == "~").count();
        assert_eq!(tilde_count, 1, "consecutive dup ~ collapsed: {c:?}");
    }

    #[test]
    fn start_candidates_with_identity_hint_exact_order() {
        assert_eq!(
            start_candidates(Some("~/.ssh/id_ed25519")),
            vec!["~/.ssh".to_string(), "~".to_string(), "/".to_string()]
        );
    }
}
