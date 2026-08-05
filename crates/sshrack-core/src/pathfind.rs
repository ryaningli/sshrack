//! Path-aware cross-directory find: pure query parsing, exact-drill descent
//! with leaf-only fuzzy matching (via an injected [`SegmentMatcher`] trait),
//! ranking, and the streaming [`PathSearch`] traversal. The TUI injects the
//! nucleo-backed matcher so this core module stays free of UI crates (the
//! zero-UI invariant).

use std::path::{Path, PathBuf};

use crate::dirsource::DirEntry;
use crate::pathutil::expand_tilde;

/// A parsed find query: an absolute search `base` plus ordered `segments`.
/// Intermediate segments match directory names exactly (one level each); the
/// final segment fuzzy-matches within the resolved directory, or — when
/// [`Self::trailing_slash`] is set — lists that directory's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuery {
    /// Absolute directory the search descends from.
    pub base: PathBuf,
    /// Ordered path segments (`a/b/c` → `["a","b","c"]`). Empty segments are
    /// dropped, so `aaa` and `aaa/` differ only in [`Self::trailing_slash`].
    pub segments: Vec<String>,
    /// `true` iff the trimmed query ended with `/`. A trailing slash makes the
    /// final (empty) segment a "list this directory" leaf instead of a fuzzy
    /// filter — see `walk_levels`.
    pub trailing_slash: bool,
}

/// Parse `raw` into a [`ParsedQuery`] against `cwd` and optional `home`.
pub fn parse_query(raw: &str, cwd: &Path, home: Option<&Path>) -> ParsedQuery {
    let raw = raw.trim();
    let trailing_slash = raw.ends_with('/');
    let (base, rest) = resolve_base(raw, cwd, home);
    let segments: Vec<String> = rest
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    ParsedQuery {
        base,
        segments,
        trailing_slash,
    }
}

/// The base-syntax prefix the user typed to address the search base — the
/// leading `/`, `~/`, or `../` chain — for faithful display of match paths.
/// The renderer prepends this to the matched segments (which carry only the
/// path *relative to the base*), so an absolute query shows `/home/ryan/`
/// instead of `home/ryan/`. Returns `""` for a bare or `./` relative query
/// (the segments already render relative, matching the typed form). Pure.
pub fn base_display_prefix(raw: &str) -> String {
    let raw = raw.trim();
    if raw.starts_with('/') {
        return "/".to_string();
    }
    if raw.starts_with('~') {
        return "~/".to_string();
    }
    if raw.starts_with("./") {
        return String::new();
    }
    // One or more leading `../` — reconstruct the chain verbatim. A bare `..`
    // (no trailing slash) also addresses the parent, so it yields `../`.
    let mut prefix = String::new();
    let mut rest = raw;
    while let Some(r) = rest.strip_prefix("../") {
        prefix.push_str("../");
        rest = r;
    }
    if rest == ".." {
        prefix.push_str("../");
    }
    prefix
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

/// One segment's fuzzy match result against a single name.
#[derive(Debug, Clone)]
pub struct SegmentScore {
    pub score: u32,
    /// Matched char indices within `name` (for highlight rendering).
    pub indices: Vec<u32>,
}

/// Injected fuzzy matcher for one path segment. Core stays free of
/// `nucleo-matcher`; the TUI provides the impl.
pub trait SegmentMatcher: Send + Sync {
    /// `Some` when `seg` fuzzy-matches `name`; an empty `seg` matches all.
    fn match_segment(&self, name: &str, seg: &str) -> Option<SegmentScore>;
}

/// One segment's match along a matched path (name + its score/indices).
#[derive(Debug, Clone)]
pub struct SegMatch {
    pub name: String,
    pub score: u32,
    pub indices: Vec<u32>,
}

/// A fully matched path: one `SegMatch` per query segment, in order.
#[derive(Debug, Clone)]
pub struct PathMatch {
    pub path: PathBuf,
    pub is_dir: bool,
    pub seg_matches: Vec<SegMatch>,
}

impl PathMatch {
    /// Sum of per-segment scores — the primary sort key.
    pub fn total_score(&self) -> u32 {
        self.seg_matches.iter().map(|s| s.score).sum()
    }
}

/// Sort matches: total score desc → fewer path components → lexical. Stable.
pub fn rank_matches(matches: &mut [PathMatch]) {
    matches.sort_by(|a, b| {
        b.total_score()
            .cmp(&a.total_score())
            .then_with(|| {
                let ca = a.path.iter().count();
                let cb = b.path.iter().count();
                ca.cmp(&cb)
            })
            .then_with(|| a.path.cmp(&b.path))
    });
}

// ---------------------------------------------------------------------------
// Streaming traversal (Task 4): PathSearch trait, SearchEvent, the shared
// walk_levels driver, and LocalPathSearch. Task 5's RemotePathSearch reuses
// walk_levels, so it is pub(crate).
// ---------------------------------------------------------------------------

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

use crate::dirsource::{DirSource, LocalDirSource};

/// One event emitted by a streaming path search.
#[derive(Debug, Clone)]
pub enum SearchEventKind {
    /// A fully matched path (one [`SegMatch`] per query segment).
    Match(PathMatch),
    /// The search terminated normally.
    Done,
    /// A recoverable error from one directory listing (the search continues).
    Error(String),
}

/// A tagged event from a [`PathSearch`]: the `gen` lets the run loop ignore
/// results from a stale query that has since been superseded.
#[derive(Debug, Clone)]
pub struct SearchEvent {
    /// Generation tag: the run loop ignores events whose `gen` is stale.
    // `gen` is a reserved keyword in edition 2024 — raw identifier preserves
    // the field name (downstream code uses `.r#gen`).
    pub r#gen: u32,
    pub kind: SearchEventKind,
}

/// Streaming path search. [`PathSearch::launch`] returns quickly; matches
/// arrive on `sink` until a `Done` or `Error` terminator is observed (or the
/// receiver is dropped). Cancel by flipping `cancel`.
pub trait PathSearch: Send + Sync {
    /// Spawn the search; return immediately. Events flow on `sink`.
    fn launch(
        &self,
        query: &ParsedQuery,
        matcher: Arc<dyn SegmentMatcher>,
        r#gen: u32,
        cancel: Arc<AtomicBool>,
        sink: mpsc::Sender<SearchEvent>,
    );
}

/// Drive `query` using `list` to read each directory. Shared by
/// [`LocalPathSearch`] and the remote search. Pure-ish: touches the filesystem
/// only through `list`.
///
/// Two phases. **Phase 1 — exact descent:** the query's non-final segments (or,
/// when [`ParsedQuery::trailing_slash`] is set, *all* segments) must name
/// directories *exactly*; the frontier starts at `query.base` and at each level
/// keeps only entries whose name equals that segment, descending into them. A
/// symlink-loop guard (`visited`) prevents cycles. **Phase 2 — leaf collect:**
/// at every surviving directory, `list` it and either keep every entry (trailing
/// slash / empty query → "list this directory") or keep only entries that
/// fuzzy-match the final segment via `matcher`. Each emitted [`PathMatch`]'s
/// `seg_matches` is the exact-drill ancestor chain (each with empty `indices`)
/// followed by the leaf's match, so the renderer highlights exactly the leaf.
///
/// Stops early when `cancel` is flipped or the receiver is dropped. A listing
/// error for one directory emits [`SearchEventKind::Error`] and the search
/// continues with the rest.
pub(crate) fn walk_levels<L>(
    list: L,
    query: &ParsedQuery,
    matcher: &dyn SegmentMatcher,
    r#gen: u32,
    cancel: &AtomicBool,
    sink: &mpsc::Sender<SearchEvent>,
) where
    L: Fn(&Path) -> Result<Vec<DirEntry>, String>,
{
    let emit = |kind: SearchEventKind, sink: &mpsc::Sender<SearchEvent>| {
        let _ = sink.send(SearchEvent { r#gen, kind });
    };

    // Split the query into exact-drill segments and an optional fuzzy leaf.
    // trailing_slash ⇒ every segment drills exactly; the leaf is "list all".
    // otherwise ⇒ all but the last segment drill exactly; the last is the leaf.
    // An empty segment list (e.g. "/", "~/") drills nothing and lists the base.
    let (drill_count, leaf): (usize, Option<&str>) = if query.trailing_slash {
        (query.segments.len(), None)
    } else {
        match query.segments.split_last() {
            None => (0, None),
            Some((last, drill)) => (drill.len(), Some(last.as_str())),
        }
    };

    // Phase 1 — linear exact descent.
    let mut frontier: Vec<(PathBuf, Vec<SegMatch>)> = vec![(query.base.clone(), Vec::new())];
    let mut visited: HashSet<PathBuf> = HashSet::new();
    for seg_idx in 0..drill_count {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let seg = &query.segments[seg_idx];
        let mut next: Vec<(PathBuf, Vec<SegMatch>)> = Vec::new();
        for (dir, ancestor) in frontier {
            if cancel.load(Ordering::SeqCst) {
                return;
            }
            if !visited.insert(dir.clone()) {
                continue; // symlink-loop guard
            }
            let entries = match list(&dir) {
                Ok(e) => e,
                Err(msg) => {
                    emit(
                        SearchEventKind::Error(format!("{}: {msg}", dir.display())),
                        sink,
                    );
                    continue;
                }
            };
            for e in &entries {
                // Drill segments must name a directory; a file never continues.
                if !e.is_dir {
                    continue;
                }
                let Some(raw) = e.path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if raw == seg {
                    let mut anc = ancestor.clone();
                    // Exact match highlights nothing — the whole name is base-styled.
                    anc.push(SegMatch {
                        name: raw.to_string(),
                        score: 0,
                        indices: Vec::new(),
                    });
                    next.push((e.path.clone(), anc));
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }

    if cancel.load(Ordering::SeqCst) {
        return;
    }

    // Phase 2 — leaf collection at each surviving directory.
    if frontier.is_empty() {
        emit(SearchEventKind::Done, sink);
        return;
    }
    for (dir, ancestor) in &frontier {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let entries = match list(dir) {
            Ok(e) => e,
            Err(msg) => {
                emit(
                    SearchEventKind::Error(format!("{}: {msg}", dir.display())),
                    sink,
                );
                continue;
            }
        };
        for e in &entries {
            let Some(raw) = e.path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let (indices, score) = match leaf {
                None => (Vec::new(), 0),
                Some(pat) => match matcher.match_segment(raw, pat) {
                    Some(s) => (s.indices, s.score),
                    None => continue,
                },
            };
            let mut full = ancestor.clone();
            full.push(SegMatch {
                name: raw.to_string(),
                score,
                indices,
            });
            if sink
                .send(SearchEvent {
                    r#gen,
                    kind: SearchEventKind::Match(PathMatch {
                        path: e.path.clone(),
                        is_dir: e.is_dir,
                        seg_matches: full,
                    }),
                })
                .is_err()
            {
                return; // receiver dropped → cancelled
            }
        }
    }
    emit(SearchEventKind::Done, sink);
}

/// Local-filesystem [`PathSearch`]. The background thread owns its own
/// [`LocalDirSource`] (zero state) and reads via `std::fs`.
#[derive(Debug, Default, Copy, Clone)]
pub struct LocalPathSearch;

impl PathSearch for LocalPathSearch {
    fn launch(
        &self,
        query: &ParsedQuery,
        matcher: Arc<dyn SegmentMatcher>,
        r#gen: u32,
        cancel: Arc<AtomicBool>,
        sink: mpsc::Sender<SearchEvent>,
    ) {
        let query = query.clone();
        std::thread::spawn(move || {
            let src = LocalDirSource::new();
            walk_levels(|p| src.list(p), &query, &*matcher, r#gen, &cancel, &sink);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dirsource::DirEntry;
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
        assert!(q.trailing_slash, "a//b/ ends with / → trailing_slash true");
    }

    #[test]
    fn trailing_slash_detected() {
        // trailing_slash is true iff the trimmed query ends with '/'.
        assert!(!parse_query("a", Path::new("/srv"), None).trailing_slash);
        assert!(parse_query("a/", Path::new("/srv"), None).trailing_slash);
        assert!(parse_query("a/b/", Path::new("/srv"), None).trailing_slash);
        assert!(parse_query("/", Path::new("/srv"), None).trailing_slash);
        assert!(parse_query("~/", Path::new("/srv"), Some(Path::new("/h"))).trailing_slash);
        assert!(!parse_query("a/b", Path::new("/srv"), None).trailing_slash);
        // Trailing whitespace is trimmed first, so "a/ " still counts.
        assert!(parse_query("a/ ", Path::new("/srv"), None).trailing_slash);
    }

    #[test]
    fn empty_query_is_cwd_no_segments() {
        let q = parse_query("", Path::new("/srv"), None);
        assert_eq!(q.base, PathBuf::from("/srv"));
        assert!(q.segments.is_empty());
    }

    #[test]
    fn base_display_prefix_absolute_is_root_slash() {
        // An absolute query's base syntax is the leading `/` — the part of the
        // path NOT carried by seg_matches, which the renderer must re-prepend.
        assert_eq!(base_display_prefix("/home/ryan"), "/");
        assert_eq!(base_display_prefix("/"), "/");
        assert_eq!(base_display_prefix("/a/b/c"), "/");
    }

    #[test]
    fn base_display_prefix_tilde_is_home() {
        assert_eq!(base_display_prefix("~/proj"), "~/");
        assert_eq!(base_display_prefix("~"), "~/");
        assert_eq!(base_display_prefix("~/a/b"), "~/");
    }

    #[test]
    fn base_display_prefix_relative_is_empty() {
        // Bare and `./` relative queries render their segments as-typed (no
        // leading prefix) — the cwd base is intentionally NOT shown.
        assert_eq!(base_display_prefix("a/b"), "");
        assert_eq!(base_display_prefix("a"), "");
        assert_eq!(base_display_prefix("./a"), "");
        assert_eq!(base_display_prefix("./a/b"), "");
    }

    #[test]
    fn base_display_prefix_parent_chain_reconstructed() {
        assert_eq!(base_display_prefix("../a"), "../");
        assert_eq!(base_display_prefix("../../a"), "../../");
        assert_eq!(base_display_prefix(".."), "../");
        assert_eq!(base_display_prefix("../"), "../");
    }

    #[test]
    fn base_display_prefix_trims_whitespace() {
        assert_eq!(base_display_prefix("  /home/ryan  "), "/");
        assert_eq!(base_display_prefix(" ~/x"), "~/");
    }

    #[test]
    fn empty_segment_matches_anything_with_zero_score() {
        let m = AlwaysMatcher;
        let r = m.match_segment("anything", "");
        assert!(r.is_some());
        let s = r.unwrap();
        assert_eq!(s.score, 0);
        assert!(s.indices.is_empty());
    }

    #[test]
    fn path_match_total_score_sums_segments() {
        let pm = PathMatch {
            path: PathBuf::from("/x/a/b"),
            is_dir: false,
            seg_matches: vec![
                SegMatch {
                    name: "a".into(),
                    score: 10,
                    indices: vec![0],
                },
                SegMatch {
                    name: "b".into(),
                    score: 5,
                    indices: vec![0],
                },
            ],
        };
        assert_eq!(pm.total_score(), 15);
    }

    fn entry(name: &str, dir: &str, is_dir: bool) -> DirEntry {
        let path = PathBuf::from(dir).join(name);
        DirEntry {
            name: if is_dir {
                format!("{name}/")
            } else {
                name.to_string()
            },
            path,
            is_dir,
            is_symlink: false,
            size: None,
            modified: None,
        }
    }

    fn query_at(base: &str, segs: &[&str]) -> ParsedQuery {
        ParsedQuery {
            base: PathBuf::from(base),
            segments: segs.iter().map(|s| s.to_string()).collect(),
            trailing_slash: false,
        }
    }

    #[test]
    fn rank_by_score_then_components_then_lexical() {
        let mut ms = vec![
            PathMatch {
                path: PathBuf::from("/x/zz"),
                is_dir: false,
                seg_matches: vec![SegMatch {
                    name: "z".into(),
                    score: 5,
                    indices: vec![],
                }],
            },
            PathMatch {
                path: PathBuf::from("/x/a/b"),
                is_dir: false,
                seg_matches: vec![
                    SegMatch {
                        name: "a".into(),
                        score: 5,
                        indices: vec![],
                    },
                    SegMatch {
                        name: "b".into(),
                        score: 5,
                        indices: vec![],
                    },
                ],
            },
            PathMatch {
                path: PathBuf::from("/x/m"),
                is_dir: false,
                seg_matches: vec![SegMatch {
                    name: "m".into(),
                    score: 9,
                    indices: vec![],
                }],
            },
        ];
        rank_matches(&mut ms);
        // totals: /x/a/b=10, /x/m=9, /x/zz=5
        assert_eq!(ms[0].path, PathBuf::from("/x/a/b"));
        assert_eq!(ms[1].path, PathBuf::from("/x/m"));
        assert_eq!(ms[2].path, PathBuf::from("/x/zz"));
    }

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;

    #[test]
    fn walk_levels_exact_drill_then_fuzzy_leaf() {
        // Exact dir names "a" and "b"; "apath" must NOT descend (exact, not fuzzy).
        //   /srv/a/b/cfile.txt   (leaf "c" fuzzy-matches)
        //   /srv/a/b/zzz.txt     (does not match "c")
        //   /srv/apath/b/...     (pruned: "a" != "apath")
        let mut tree: HashMap<PathBuf, Vec<DirEntry>> = HashMap::new();
        tree.insert(
            PathBuf::from("/srv"),
            vec![entry("a", "/srv", true), entry("apath", "/srv", true)],
        );
        tree.insert(PathBuf::from("/srv/a"), vec![entry("b", "/srv/a", true)]);
        tree.insert(
            PathBuf::from("/srv/apath"),
            vec![entry("b", "/srv/apath", true)],
        );
        tree.insert(
            PathBuf::from("/srv/a/b"),
            vec![
                entry("cfile.txt", "/srv/a/b", false),
                entry("zzz.txt", "/srv/a/b", false),
            ],
        );
        let list = |p: &Path| tree.get(p).cloned().ok_or_else(|| "no dir".to_string());

        // drill "a","b" exact; leaf "c" fuzzy.
        let q = query_at("/srv", &["a", "b", "c"]);
        let (tx, rx) = mpsc::channel();
        let cancel = AtomicBool::new(false);
        walk_levels(list, &q, &AlwaysMatcher, 1, &cancel, &tx);
        drop(tx);

        let mut leaves = vec![];
        let mut done = false;
        for ev in rx.iter() {
            match ev.kind {
                SearchEventKind::Match(m) => leaves.push(m),
                SearchEventKind::Done => done = true,
                SearchEventKind::Error(e) => panic!("unexpected error: {e}"),
            }
        }
        assert!(done);
        assert_eq!(
            leaves.len(),
            1,
            "only cfile.txt matches leaf 'c' under exact a/b"
        );
        assert!(leaves[0].path.ends_with("cfile.txt"));
        assert_eq!(leaves[0].seg_matches.len(), 3, "drill a,b + leaf cfile");
        // Exact drill segments carry no highlight indices; only the leaf does.
        assert!(leaves[0].seg_matches[0].indices.is_empty());
        assert!(leaves[0].seg_matches[1].indices.is_empty());
        assert!(
            !leaves[0].seg_matches[2].indices.is_empty(),
            "leaf 'c' highlighted"
        );
    }

    #[test]
    fn walk_levels_trailing_slash_lists_directory() {
        // query "a/b/" (trailing slash) → exact drill a,b then list /srv/a/b fully.
        let mut tree: HashMap<PathBuf, Vec<DirEntry>> = HashMap::new();
        tree.insert(PathBuf::from("/srv"), vec![entry("a", "/srv", true)]);
        tree.insert(PathBuf::from("/srv/a"), vec![entry("b", "/srv/a", true)]);
        tree.insert(
            PathBuf::from("/srv/a/b"),
            vec![
                entry("one.txt", "/srv/a/b", false),
                entry("two", "/srv/a/b", true),
            ],
        );
        let list = |p: &Path| tree.get(p).cloned().ok_or_else(|| "no dir".to_string());

        let q = ParsedQuery {
            base: PathBuf::from("/srv"),
            segments: vec!["a".into(), "b".into()],
            trailing_slash: true,
        };
        let (tx, rx) = mpsc::channel();
        let cancel = AtomicBool::new(false);
        walk_levels(list, &q, &AlwaysMatcher, 1, &cancel, &tx);
        drop(tx);

        let leaves: Vec<_> = rx
            .iter()
            .filter_map(|ev| match ev.kind {
                SearchEventKind::Match(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(leaves.len(), 2, "trailing slash lists every entry");
        // A listed leaf's own seg_match has empty indices (no fuzzy highlight).
        assert!(
            leaves
                .iter()
                .all(|m| m.seg_matches.last().is_some_and(|s| s.indices.is_empty()))
        );
    }

    #[test]
    fn walk_levels_exact_drill_prunes_non_matching_dir() {
        // query "a/b": "a" exact descends only /srv/a; /srv/zzz is pruned even though
        // it also contains a "bfile" that would fuzzy-match "b".
        let mut tree: HashMap<PathBuf, Vec<DirEntry>> = HashMap::new();
        tree.insert(
            PathBuf::from("/srv"),
            vec![entry("a", "/srv", true), entry("zzz", "/srv", true)],
        );
        tree.insert(
            PathBuf::from("/srv/a"),
            vec![entry("bfile", "/srv/a", false)],
        );
        tree.insert(
            PathBuf::from("/srv/zzz"),
            vec![entry("bfile", "/srv/zzz", false)],
        );
        let list = |p: &Path| tree.get(p).cloned().ok_or_else(|| "no dir".to_string());

        let q = query_at("/srv", &["a", "b"]);
        let (tx, rx) = mpsc::channel();
        let cancel = AtomicBool::new(false);
        walk_levels(list, &q, &AlwaysMatcher, 1, &cancel, &tx);
        drop(tx);

        let paths: Vec<_> = rx
            .iter()
            .filter_map(|ev| match ev.kind {
                SearchEventKind::Match(m) => Some(m.path),
                _ => None,
            })
            .collect();
        assert_eq!(paths.len(), 1, "only the exact 'a' descent contributes");
        assert!(
            paths[0].starts_with("/srv/a/"),
            "pruned sibling /srv/zzz did not contribute: {:?}",
            paths[0]
        );
    }

    #[test]
    fn walk_levels_respects_cancel() {
        // A list closure that flips cancel after the first call → walk stops,
        // emits no Done, no further matches.
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel2 = cancel.clone();
        let list = move |_p: &Path| {
            cancel2.store(true, Ordering::SeqCst);
            Ok(vec![entry("a", "/srv", true)])
        };
        let q = query_at("/srv", &["a", "b"]);
        let (tx, rx) = mpsc::channel();
        walk_levels(list, &q, &AlwaysMatcher, 1, &cancel, &tx);
        drop(tx);
        let evs: Vec<_> = rx.iter().collect();
        assert!(evs.iter().all(|e| !matches!(e.kind, SearchEventKind::Done)));
    }

    /// Trivial matcher used by the core-level unit tests (the real nucleo
    /// impl lives in the TUI, Task 6). Matches iff `name` contains `seg`
    /// (case-insensitive); score = matched length; indices = matched positions.
    #[derive(Debug, Clone, Copy)]
    struct AlwaysMatcher;
    impl SegmentMatcher for AlwaysMatcher {
        fn match_segment(&self, name: &str, seg: &str) -> Option<SegmentScore> {
            if seg.is_empty() {
                return Some(SegmentScore {
                    score: 0,
                    indices: vec![],
                });
            }
            let nl = name.to_ascii_lowercase();
            let sl = seg.to_ascii_lowercase();
            let idx = nl.match_indices(&sl).next()?;
            let indices: Vec<u32> = (0..sl.chars().count() as u32)
                .map(|i| idx.0 as u32 + i)
                .collect();
            Some(SegmentScore {
                score: sl.len() as u32,
                indices,
            })
        }
    }
}
