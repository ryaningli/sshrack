//! TTL + LRU cache for directory listings (`list(Path) -> Vec<DirEntry>`),
//! shared across `PathSearch::launch` invocations so repeated find queries reuse
//! prior listings instead of re-hitting the filesystem / SFTP. Pure logic + an
//! injected clock (hermetic tests). The cache is per-`PathSearch`-instance —
//! local and remote carry independent caches, so a same-named local and remote
//! path never collide.
//!
//! Semantics: a cached listing whose `born_at` is within `ttl` of `now()` is a
//! hit (its `last_used` is refreshed); an expired or absent entry calls `fetch`,
//! caches a successful `Ok`, and returns it. An `Err` is never cached — a
//! transient listing error deserves a retry. When `capacity` is exceeded the
//! least-recently-used entry is evicted. Eviction is O(n) over a bounded map
//! (`capacity` ≤ 128): trivial next to one SFTP `ls` round-trip, and it keeps
//! the implementation dependency-free (no intrusive linked list).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::dirsource::DirEntry;

/// Default TTL: long enough to amortize listings across a burst of find edits
/// (the ~80 ms debounce window plus typing), short enough to observe remote
/// changes within a few seconds.
pub const DEFAULT_TTL: Duration = Duration::from_secs(5);

/// Default capacity: bounds memory. A find touches `segments + 1` directories,
/// so 128 covers a generous browsing working set with room to spare.
pub const DEFAULT_CAPACITY: usize = 128;

/// A wall-clock `now()` returning elapsed since this function was called,
/// packed as a `Send + Sync` closure for [`DirListCache::new`].
pub fn real_clock() -> Box<dyn Fn() -> Duration + Send + Sync> {
    let start = Instant::now();
    Box::new(move || Instant::now().duration_since(start))
}

type Clock = Box<dyn Fn() -> Duration + Send + Sync>;

#[derive(Debug, Clone)]
struct CacheEntry {
    /// Clock reading at insertion — drives TTL expiry.
    born_at: Duration,
    /// Clock reading at last hit/insert — drives LRU eviction.
    last_used: Duration,
    value: Vec<DirEntry>,
}

/// A TTL + LRU cache of directory listings. `now` injects the clock so tests
/// are hermetic; production passes [`real_clock`].
///
/// `fetch` runs under the cache's internal mutex. `walk_levels` calls `list`
/// single-threaded and the transfer worker never touches this cache, so no
/// cross-thread contention serializes on a slow `fetch`; the lock only guards
/// the map against the (cancelled) previous search's final `list`.
pub struct DirListCache {
    ttl: Duration,
    capacity: usize,
    entries: HashMap<PathBuf, CacheEntry>,
    now: Clock,
}

impl DirListCache {
    /// Construct with an explicit config + clock.
    pub fn new(ttl: Duration, capacity: usize, now: Clock) -> Self {
        Self {
            ttl,
            capacity,
            entries: HashMap::new(),
            now,
        }
    }

    /// Default-configured cache with [`real_clock`] — the construction used by
    /// `LocalPathSearch::default` and the remote searcher in `open_transfer`.
    pub fn default_with_real_clock() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_CAPACITY, real_clock())
    }

    /// Number of cached entries (test/diagnostic).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the listing for `path`: a fresh-enough cached copy, or `fetch`'s
    /// result (cached on success). An expired entry is dropped and re-fetched;
    /// an `Err` is returned uncached. Evicts the least-recently-used entry when
    /// at capacity.
    pub fn get_or_fetch(
        &mut self,
        path: &Path,
        fetch: impl FnOnce(&Path) -> Result<Vec<DirEntry>, String>,
    ) -> Result<Vec<DirEntry>, String> {
        let t = (self.now)();
        // Hit: fresh enough → refresh last_used and return the cached clone.
        if let Some(e) = self.entries.get(path) {
            if t.saturating_sub(e.born_at) < self.ttl {
                let e = self
                    .entries
                    .get_mut(path)
                    .expect("invariant: entry just retrieved by key");
                e.last_used = t;
                return Ok(e.value.clone());
            }
            // Expired → drop and re-fetch below.
            self.entries.remove(path);
        }
        let value = fetch(path)?;
        if self.capacity > 0 {
            // Evict LRU entries until there is room for one more.
            while self.entries.len() >= self.capacity {
                let victim = self
                    .entries
                    .iter()
                    .min_by_key(|(_, e)| e.last_used)
                    .map(|(k, _)| k.clone());
                match victim {
                    Some(k) => {
                        self.entries.remove(&k);
                    }
                    None => break,
                }
            }
            self.entries.insert(
                path.to_path_buf(),
                CacheEntry {
                    born_at: t,
                    last_used: t,
                    value: value.clone(),
                },
            );
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    /// A DirEntry whose only load-bearing field here is `path` (and `is_dir`
    /// so tests can distinguish). Kept minimal — cache tests do not care about
    /// names/sizes.
    fn ent(name: &str, is_dir: bool) -> DirEntry {
        DirEntry {
            name: name.to_string(),
            path: PathBuf::from("/t").join(name),
            is_dir,
            is_symlink: false,
            size: None,
            modified: None,
        }
    }

    /// A controllable clock: the test sets the current reading by mutating the
    /// shared value. Returns a closure suitable for `DirListCache::new`.
    fn fake_clock() -> (
        Arc<Mutex<Duration>>,
        Box<dyn Fn() -> Duration + Send + Sync>,
    ) {
        let cell = Arc::new(Mutex::new(Duration::ZERO));
        let c = {
            let cell = Arc::clone(&cell);
            Box::new(move || *cell.lock().unwrap())
        };
        (cell, c)
    }

    /// Counting fetch: returns a one-entry listing and bumps the counter, so a
    /// test can assert whether `fetch` was actually called.
    fn counting_fetch(
        counter: Arc<std::sync::atomic::AtomicU32>,
    ) -> impl Fn(&Path) -> Result<Vec<DirEntry>, String> {
        move |_p| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![ent("a", false)])
        }
    }

    #[test]
    fn miss_populates_and_hit_skips_fetch() {
        let (clock, now) = fake_clock();
        let mut cache = DirListCache::new(DEFAULT_TTL, DEFAULT_CAPACITY, now);
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let path = Path::new("/t");

        let v1 = cache
            .get_or_fetch(path, counting_fetch(Arc::clone(&calls)))
            .unwrap();
        let v2 = cache
            .get_or_fetch(path, counting_fetch(Arc::clone(&calls)))
            .unwrap();

        assert_eq!(v1, v2, "hit returns the cached value");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "second call is a hit — fetch runs once"
        );
        assert_eq!(cache.len(), 1);
        let _ = clock; // keep the clock alive for the test
    }

    #[test]
    fn expired_entry_is_refetched() {
        let (clock, now) = fake_clock();
        let mut cache = DirListCache::new(Duration::from_secs(5), DEFAULT_CAPACITY, now);
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let path = Path::new("/t");

        cache
            .get_or_fetch(path, counting_fetch(Arc::clone(&calls)))
            .unwrap();
        // Advance past the TTL.
        *clock.lock().unwrap() = Duration::from_secs(6);
        cache
            .get_or_fetch(path, counting_fetch(Arc::clone(&calls)))
            .unwrap();

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "expired entry is a miss — fetch runs again"
        );
    }

    #[test]
    fn capacity_evicts_least_recently_used() {
        let (clock, now) = fake_clock();
        // capacity 2: insert a, b (in that order), hit a, then insert c → b evicted.
        let mut cache = DirListCache::new(Duration::from_secs(60), 2, now);
        let pa = Path::new("/a");
        let pb = Path::new("/b");
        let pc = Path::new("/c");

        cache
            .get_or_fetch(pa, counting_fetch(default_count()))
            .unwrap();
        cache
            .get_or_fetch(pb, counting_fetch(default_count()))
            .unwrap();
        // Touch `a` so `b` is the least-recently-used.
        *clock.lock().unwrap() = Duration::from_secs(1);
        cache
            .get_or_fetch(pa, counting_fetch(default_count()))
            .unwrap();
        *clock.lock().unwrap() = Duration::from_secs(2);
        cache
            .get_or_fetch(pc, counting_fetch(default_count()))
            .unwrap();

        // `a` and `c` survive; `b` was evicted. Re-fetching `b` must call fetch
        // (a miss), while re-fetching `a` must not (a hit).
        let calls_a = Arc::new(std::sync::atomic::AtomicU32::new(0));
        cache
            .get_or_fetch(pa, counting_fetch(Arc::clone(&calls_a)))
            .unwrap();
        assert_eq!(
            calls_a.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a is a hit"
        );

        let calls_b = Arc::new(std::sync::atomic::AtomicU32::new(0));
        cache
            .get_or_fetch(pb, counting_fetch(Arc::clone(&calls_b)))
            .unwrap();
        assert_eq!(
            calls_b.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "b was evicted — re-fetch is a miss"
        );
    }

    #[test]
    fn err_is_not_cached() {
        let (_clock, now) = fake_clock();
        let mut cache = DirListCache::new(Duration::from_secs(60), DEFAULT_CAPACITY, now);
        let path = Path::new("/t");
        let err = cache
            .get_or_fetch(path, |_| Err("boom".to_string()))
            .unwrap_err();
        assert_eq!(err, "boom");
        assert!(cache.is_empty(), "an Err must not populate the cache");
    }

    #[test]
    fn capacity_zero_never_caches() {
        let (_clock, now) = fake_clock();
        let mut cache = DirListCache::new(Duration::from_secs(60), 0, now);
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let path = Path::new("/t");
        cache
            .get_or_fetch(path, counting_fetch(Arc::clone(&calls)))
            .unwrap();
        cache
            .get_or_fetch(path, counting_fetch(Arc::clone(&calls)))
            .unwrap();
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "capacity 0 disables caching entirely"
        );
        assert!(cache.is_empty());
    }

    /// Helper: a fresh zeroed counter for tests that do not assert on the count
    /// themselves (the `capacity_evicts_least_recently_used` setup fetches).
    fn default_count() -> Arc<std::sync::atomic::AtomicU32> {
        Arc::new(std::sync::atomic::AtomicU32::new(0))
    }
}
