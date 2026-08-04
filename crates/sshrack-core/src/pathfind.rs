//! Path-aware cross-directory find: pure query parsing, segment matching via
//! an injected [`SegmentMatcher`] trait, per-level pruning, ranking, and the
//! streaming [`PathSearch`] traversal (added by later tasks). The TUI injects
//! the nucleo-backed matcher so this core module stays free of UI crates (the
//! zero-UI invariant).

use std::path::{Path, PathBuf};

use crate::pathutil::expand_tilde;

/// A parsed find query: an absolute search `base` plus ordered `segments`.
/// Each segment fuzzy-matches one directory level under `base`; depth at match
/// time equals `segments.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuery {
    /// Absolute directory the search descends from.
    pub base: PathBuf,
    /// Ordered fuzzy segments (`a/b/c` → `["a","b","c"]`).
    pub segments: Vec<String>,
}

/// Parse `raw` into a [`ParsedQuery`] against `cwd` and optional `home`.
pub fn parse_query(raw: &str, cwd: &Path, home: Option<&Path>) -> ParsedQuery {
    let raw = raw.trim();
    let (base, rest) = resolve_base(raw, cwd, home);
    let segments: Vec<String> = rest
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    ParsedQuery { base, segments }
}

/// Split `raw` into `(base, rest_str)` by leading prefix. Pure.
fn resolve_base<'a>(raw: &'a str, cwd: &Path, home: Option<&Path>) -> (PathBuf, &'a str) {
    if let Some(rest) = raw.strip_prefix('~') {
        // Base is HOME (not the full `~/x` path); segments come from `rest`.
        let base = match home {
            Some(h) => expand_tilde("~", h),
            None => cwd.to_path_buf(), // degraded: ~ with no home → cwd
        };
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        return (base, rest);
    }
    if let Some(rest) = raw.strip_prefix("./") {
        return (cwd.to_path_buf(), rest);
    }
    if raw.starts_with('/') {
        let rest = raw.strip_prefix('/').unwrap_or(raw);
        return (PathBuf::from("/"), rest);
    }
    // Count leading "../" to pop cwd that many times.
    let mut pops = 0usize;
    let mut rest = raw;
    while let Some(r) = rest.strip_prefix("../") {
        pops += 1;
        rest = r;
    }
    if rest == ".." {
        pops += 1;
        rest = "";
    }
    let mut base = cwd.to_path_buf();
    for _ in 0..pops {
        base = base.parent().unwrap_or(&base).to_path_buf();
    }
    (base, rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn bare_is_cwd_base_one_segment() {
        let q = parse_query("a", Path::new("/srv"), None);
        assert_eq!(q.base, PathBuf::from("/srv"));
        assert_eq!(q.segments, vec!["a".to_string()]);
    }

    #[test]
    fn dot_slash_equals_bare() {
        let a = parse_query("a", Path::new("/srv"), None);
        let b = parse_query("./a", Path::new("/srv"), None);
        assert_eq!(a.base, b.base);
        assert_eq!(a.segments, b.segments);
    }

    #[test]
    fn multi_segment_relative() {
        let q = parse_query("a/b/c", Path::new("/srv"), None);
        assert_eq!(q.base, PathBuf::from("/srv"));
        assert_eq!(q.segments, vec!["a", "b", "c"]);
    }

    #[test]
    fn absolute_leading_slash_is_root_base() {
        let q = parse_query("/etc/ssh", Path::new("/srv"), None);
        assert_eq!(q.base, PathBuf::from("/"));
        assert_eq!(q.segments, vec!["etc", "ssh"]);
    }

    #[test]
    fn parent_dotdot_pops_cwd() {
        let q = parse_query("../a", Path::new("/srv/x"), None);
        assert_eq!(q.base, PathBuf::from("/srv"));
        assert_eq!(q.segments, vec!["a"]);
    }

    #[test]
    fn two_parents_pop_twice() {
        let q = parse_query("../../a", Path::new("/srv/x/y"), None);
        assert_eq!(q.base, PathBuf::from("/srv"));
        assert_eq!(q.segments, vec!["a"]);
    }

    #[test]
    fn tilde_uses_home_when_present() {
        let q = parse_query("~/proj/a", Path::new("/srv"), Some(Path::new("/home/u")));
        assert_eq!(q.base, PathBuf::from("/home/u"));
        assert_eq!(q.segments, vec!["proj", "a"]);
    }

    #[test]
    fn tilde_alone_is_home_no_segments() {
        let q = parse_query("~", Path::new("/srv"), Some(Path::new("/home/u")));
        assert_eq!(q.base, PathBuf::from("/home/u"));
        assert!(q.segments.is_empty());
    }

    #[test]
    fn tilde_without_home_falls_back_to_cwd() {
        let q = parse_query("~/a", Path::new("/srv"), None);
        assert_eq!(q.base, PathBuf::from("/srv"));
        assert_eq!(q.segments, vec!["a"]);
    }

    #[test]
    fn empty_segment_are_dropped() {
        let q = parse_query("a//b/", Path::new("/srv"), None);
        assert_eq!(q.segments, vec!["a", "b"]);
    }

    #[test]
    fn empty_query_is_cwd_no_segments() {
        let q = parse_query("", Path::new("/srv"), None);
        assert_eq!(q.base, PathBuf::from("/srv"));
        assert!(q.segments.is_empty());
    }
}
