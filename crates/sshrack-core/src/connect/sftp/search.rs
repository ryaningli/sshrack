//! Remote path-aware find: a [`PathSearch`] whose `list` runs an `sftp ls`
//! batch per directory over the shared ControlMaster via the injected
//! [`SftpRunner`]. It reuses [`pathfind::walk_levels`], so the per-segment
//! pruning algorithm is identical to the local search — only the listing
//! source differs. The background thread builds a fresh [`SftpDirSource`] from
//! the captured target/socket/runner/home; OpenSSH ControlMaster multiplexes
//! this sftp batch concurrently with the transfer worker's, so the search
//! never blocks transfers and vice versa.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;

use crate::connect::sftp::source::{SftpDirSource, SftpRunner};
use crate::dirsource::{DirEntry, DirSource};
use crate::pathfind::{ParsedQuery, PathSearch, SearchEvent, SegmentMatcher, walk_levels};

/// `PathSearch` over an authenticated SFTP ControlMaster. A per-instance
/// [`DirListCache`] amortizes repeated listings across find queries.
pub struct RemotePathSearch {
    target: String,
    sock: PathBuf,
    home: Option<PathBuf>,
    runner: Arc<dyn SftpRunner>,
    cache: Arc<std::sync::Mutex<crate::pathfind::DirListCache>>,
}

impl RemotePathSearch {
    /// Construct from the live worker's connection details + a shared cache.
    /// Production passes a `LocalSftpRunner`; tests pass a fake.
    pub fn new(
        target: String,
        sock: PathBuf,
        home: Option<PathBuf>,
        runner: Arc<dyn SftpRunner>,
        cache: Arc<std::sync::Mutex<crate::pathfind::DirListCache>>,
    ) -> Self {
        Self {
            target,
            sock,
            home,
            runner,
            cache,
        }
    }
}

impl PathSearch for RemotePathSearch {
    fn launch(
        &self,
        query: &ParsedQuery,
        matcher: Arc<dyn SegmentMatcher>,
        r#gen: u32,
        cancel: Arc<AtomicBool>,
        sink: mpsc::Sender<SearchEvent>,
    ) {
        let source = SftpDirSource::new(
            self.target.clone(),
            self.sock.clone(),
            self.runner.clone(),
            self.home.clone(),
        );
        let cache = self.cache.clone();
        let query = query.clone();
        std::thread::spawn(move || {
            let list = |p: &Path| -> Result<Vec<DirEntry>, String> {
                cache
                    .lock()
                    .expect("invariant: dir-list cache mutex not poisoned")
                    .get_or_fetch(p, |x| source.list(x))
            };
            walk_levels(list, &query, &*matcher, r#gen, &cancel, &sink);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pathfind::{ParsedQuery, PathSearch, SearchEventKind, SegmentMatcher, SegmentScore};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, mpsc};

    /// `SegmentMatcher` test double local to this module (the core tests'
    /// `AlwaysMatcher` is private to `pathfind::tests`). Case-insensitive
    /// substring; score = seg length.
    struct SubstrMatcher;
    impl SegmentMatcher for SubstrMatcher {
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

    /// Fake runner returning canned `ls -la` output keyed by the (unquoted)
    /// directory path. Keeps the test hermetic — no real sftp.
    struct MapRunner(HashMap<PathBuf, String>);
    impl SftpRunner for MapRunner {
        fn run_batch(&self, _target: &str, _sock: &Path, batch: &str) -> Result<String, String> {
            // batch looks like `ls -la <maybe-quoted-path>\nquit\n`
            let line = batch.lines().next().unwrap_or("");
            let arg = line.trim_start_matches("ls -la").trim().trim_matches('"');
            let key = PathBuf::from(arg);
            self.0
                .get(&key)
                .cloned()
                .ok_or_else(|| "no canned".to_string())
        }
    }

    #[test]
    fn remote_search_streams_matches_per_level() {
        let mut map = HashMap::new();
        map.insert(
            PathBuf::from("/srv"),
            String::from("drwxr-xr-x 2 u g 4 Jan 1 00:00 /srv/a\n"),
        );
        map.insert(
            PathBuf::from("/srv/a"),
            String::from("-rw-r--r-- 1 u g 4 Jan 1 00:00 /srv/a/bfile\n"),
        );
        let search = RemotePathSearch::new(
            "u@h".into(),
            PathBuf::from("/tmp/sock"),
            Some(PathBuf::from("/home/u")),
            Arc::new(MapRunner(map)),
            Arc::new(std::sync::Mutex::new(
                crate::pathfind::DirListCache::default_with_real_clock(),
            )),
        );
        let q = ParsedQuery {
            base: PathBuf::from("/srv"),
            segments: vec!["a".into(), "b".into()],
            trailing_slash: false,
        };
        let (tx, rx) = mpsc::channel();
        search.launch(
            &q,
            Arc::new(SubstrMatcher),
            7,
            Arc::new(AtomicBool::new(false)),
            tx,
        );
        // `launch` takes `tx` by value and moves it into the spawned search
        // thread; `rx.iter()` blocks until every sender is dropped, which
        // happens when the search thread exits. No explicit `drop(tx)` here.

        let mut leaves = 0u32;
        let mut done = false;
        for ev in rx.iter() {
            match ev.kind {
                SearchEventKind::Match(_) => leaves += 1,
                SearchEventKind::Done => done = true,
                SearchEventKind::Error(e) => panic!("unexpected error: {e}"),
                SearchEventKind::Drilled(_) => {}
            }
        }
        assert!(done);
        assert_eq!(leaves, 1, "only /srv/a/bfile matches drill 'a' + leaf 'b'");
    }

    /// A `SftpRunner` that delegates to a canned map AND counts `run_batch`
    /// calls, so a test can assert the cache prevented a re-list.
    struct CountingRunner {
        map: HashMap<PathBuf, String>,
        calls: Arc<std::sync::atomic::AtomicU32>,
    }
    impl SftpRunner for CountingRunner {
        fn run_batch(&self, _target: &str, _sock: &Path, batch: &str) -> Result<String, String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let line = batch.lines().next().unwrap_or("");
            let arg = line.trim_start_matches("ls -la").trim().trim_matches('"');
            self.map
                .get(Path::new(arg))
                .cloned()
                .ok_or_else(|| "no canned".to_string())
        }
    }

    #[test]
    fn remote_search_caches_listings_across_launches() {
        // Two-directory tree: /srv lists /srv/a; /srv/a lists /srv/a/bfile.
        let mut map = HashMap::new();
        map.insert(
            PathBuf::from("/srv"),
            String::from("drwxr-xr-x 2 u g 4 Jan 1 00:00 /srv/a\n"),
        );
        map.insert(
            PathBuf::from("/srv/a"),
            String::from("-rw-r--r-- 1 u g 4 Jan 1 00:00 /srv/a/bfile\n"),
        );
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let runner = Arc::new(CountingRunner {
            map,
            calls: Arc::clone(&calls),
        });
        let cache = Arc::new(std::sync::Mutex::new(
            crate::pathfind::DirListCache::default_with_real_clock(),
        ));
        let search = RemotePathSearch::new(
            "u@h".into(),
            PathBuf::from("/tmp/sock"),
            Some(PathBuf::from("/home/u")),
            runner,
            cache,
        );
        let q = ParsedQuery {
            base: PathBuf::from("/srv"),
            segments: vec!["a".into(), "b".into()],
            trailing_slash: false,
        };

        let run_once = || {
            let (tx, rx) = mpsc::channel();
            search.launch(
                &q,
                Arc::new(SubstrMatcher),
                7,
                Arc::new(AtomicBool::new(false)),
                tx,
            );
            let mut done = false;
            for ev in rx.iter() {
                match ev.kind {
                    SearchEventKind::Match(_) => {}
                    SearchEventKind::Done => done = true,
                    SearchEventKind::Error(e) => panic!("unexpected error: {e}"),
                    SearchEventKind::Drilled(_) => {}
                }
            }
            assert!(done);
        };

        run_once();
        let after_first = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            after_first >= 2,
            "first run lists /srv and /srv/a: {after_first}"
        );

        run_once();
        let after_second = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            after_second, after_first,
            "second run must hit the cache — no new sftp ls batches"
        );
    }
}
