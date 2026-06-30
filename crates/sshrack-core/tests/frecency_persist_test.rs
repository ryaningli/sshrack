//! End-to-end: frecency `record` -> `save` -> `load` round-trips across a real
//! `frecency.toml` file on disk.
//!
//! Integration test (not a unit test): the unit tests in `frecency::store`
//! already cover the in-memory `record_at` decay and the `save`/`load` mirror
//! in isolation. This test exercises the full pipeline through a temp data dir,
//! multiple records across decay tiers, a real file write + read, and asserts
//! the score and `last_used` survive the round-trip — locking the persistence
//! contract a CLI connect actually relies on (Step 7 of the connect flow saves
//! frecency before launch; the next `host ls --sort frecency` reloads it).

use std::time::{Duration, UNIX_EPOCH};

use sshrack_core::frecency::{Frecency, store};
use ulid::Ulid;

/// A fixed `SystemTime` well after the epoch, so decay tiers are deterministic
/// regardless of the real wall clock.
fn fixed_now() -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// record -> save -> load round-trips the score and last_used for a host
/// recorded across multiple decay tiers, through a real `frecency.toml` file.
#[test]
fn record_save_load_round_trips_score_and_last_used() {
    let dir = tempfile::tempdir().expect("temp dir");
    let id = Ulid::new();
    let t0 = fixed_now();

    let mut frec = Frecency::default();
    // fresh(1.0) -> +30min(×4 -> 5.0) -> +2h(×2 -> 11.0)
    frec.record_at(&id, t0);
    frec.record_at(&id, t0 + Duration::from_secs(30 * 60));
    frec.record_at(&id, t0 + Duration::from_secs(2 * 3600));
    let expected_score = frec.score(&id);
    let expected_last_used = frec.map.get(&id).expect("recorded").last_used;
    assert_eq!(expected_score, 11.0);

    store::save(dir.path(), &frec).expect("save");
    let back = store::load(dir.path()).expect("load");

    assert_eq!(back.score(&id), expected_score);
    assert_eq!(
        back.map.get(&id).expect("recorded").last_used,
        expected_last_used
    );
    // Only the one host was recorded.
    assert_eq!(back.map.len(), 1);
}

/// A second record on the same host after a reload accumulates correctly —
/// the persistence layer must not reset the score on load. This mirrors the
/// real connect flow: each connect does load -> record -> save.
#[test]
fn record_after_load_accumulates_across_persistence_boundary() {
    let dir = tempfile::tempdir().expect("temp dir");
    let id = Ulid::new();
    let t0 = fixed_now();

    // First session: one record, save.
    let mut frec = Frecency::default();
    frec.record_at(&id, t0); // 1.0
    store::save(dir.path(), &frec).expect("save #1");

    // Second session: reload, record again, save. The reload must surface the
    // prior score so the decay multiplier is applied to 1.0, not 0.0.
    let mut frec = store::load(dir.path()).expect("load #1");
    assert_eq!(frec.score(&id), 1.0, "reload must surface the prior score");
    // >1 week later -> else tier, mult 0.25: 1.0 * 0.25 + 1.0 = 1.25
    frec.record_at(&id, t0 + Duration::from_secs(10 * 86_400));
    store::save(dir.path(), &frec).expect("save #2");

    let back = store::load(dir.path()).expect("load #2");
    assert_eq!(back.score(&id), 1.25);
}

/// A fresh data dir (no frecency file) loads as an empty table, and recording
/// into it then saving produces a real file on disk. Mirrors a fresh install.
#[test]
fn fresh_dir_loads_empty_then_save_creates_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("frecency.toml");
    assert!(!path.exists());

    let loaded = store::load(dir.path()).expect("load fresh");
    assert!(loaded.map.is_empty());

    // Record one host and persist; the file must now exist on disk.
    let mut frec = loaded;
    frec.record_at(&Ulid::new(), fixed_now());
    store::save(dir.path(), &frec).expect("save");
    assert!(path.exists(), "frecency.toml should be created on save");

    let back = store::load(dir.path()).expect("load after save");
    assert_eq!(back.map.len(), 1, "the single recorded host round-trips");
}
