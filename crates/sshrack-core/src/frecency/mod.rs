//! frecency (frequency + recency) scoring and machine-local persistence.
//!
//! Machine-local usage scoring that ranks hosts so the most-likely-wanted float
//! to the top. Combines how often a host is used (`frequency`) with how recently
//! it was last used (`recency`) via the zoxide 4-tier decay: a connection within
//! the last hour multiplies the running score by 4, within a day by 2, within a
//! week by 0.5, and older than a week by 0.25 — then adds 1. Keyed by host
//! [`Ulid`] (rename-safe: renaming a host's alias never orphans its score).
//!
//! Persistence lives in [`store`] (atomic 0600 TOML under the data dir).

pub mod store;

use std::collections::HashMap;
use std::time::SystemTime;

use ulid::Ulid;

use crate::config::schema::Host;

/// 1 hour in seconds.
const HOUR: u64 = 3600;
/// 1 day in seconds.
const DAY: u64 = 86_400;
/// 1 week in seconds.
const WEEK: u64 = DAY * 7;

/// Per-host usage state: a running frecency score and the last time the host
/// was connected to. `last_used` is `None` for an entry that has never been
/// recorded (the default).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Entry {
    /// The running frecency score (frequency × recency decay + 1 per use).
    pub score: f64,
    /// When this host was last connected to, or `None` if never recorded.
    pub last_used: Option<SystemTime>,
}

/// The frecency table: a map from host [`Ulid`] to its [`Entry`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Frecency {
    /// The per-host score table.
    pub map: HashMap<Ulid, Entry>,
}

impl Frecency {
    /// Record a connection to `id` at `now`, applying the zoxide 4-tier decay
    /// based on the time since the previous connection. A first connection
    /// (no previous `last_used`) seeds a score of 1.0.
    pub fn record_at(&mut self, id: &Ulid, now: SystemTime) {
        let prev = self.map.get(id).copied().unwrap_or_default();
        let age_secs = prev
            .last_used
            .and_then(|t| now.duration_since(t).ok())
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        let mult = if age_secs < HOUR {
            4.0
        } else if age_secs < DAY {
            2.0
        } else if age_secs < WEEK {
            0.5
        } else {
            0.25
        };
        let next_score = prev.score * mult + 1.0;
        self.map.insert(
            *id,
            Entry {
                score: next_score,
                last_used: Some(now),
            },
        );
    }

    /// Record a connection to `id` using the real wall clock. Tests should
    /// prefer [`Frecency::record_at`] with an explicit `SystemTime` so the
    /// decay tier is deterministic.
    pub fn record(&mut self, id: &Ulid) {
        self.record_at(id, SystemTime::now());
    }

    /// The score for `id`, or `0.0` if it has never been recorded.
    pub fn score(&self, id: &Ulid) -> f64 {
        self.map.get(id).map(|e| e.score).unwrap_or(0.0)
    }
}

/// A host plus its computed frecency score, returned by [`rank`].
#[derive(Debug, Clone)]
pub struct RankedHost<'a> {
    /// The borrowed host.
    pub host: &'a Host,
    /// The host's frecency score (0.0 if never recorded).
    pub score: f64,
}

/// Rank hosts by substring-match presence, then frecency score, then alias.
///
/// Pure. `query` is matched case-insensitively as a substring of the alias
/// (`alias.to_lowercase().contains(query.to_lowercase())`); hosts whose alias
/// contains the query sort ahead of non-matches, then by descending frecency
/// score, then alphabetically by alias to break ties. An empty query matches
/// every host, so the order is purely score-then-alias.
///
/// This is a first-period matcher: substring `contains` only. True fuzzy
/// matching (strsim/nucleo-style) is deferred to the TUI launcher phase.
pub fn rank<'a>(hosts: &'a [&Host], query: &str, frec: &Frecency) -> Vec<RankedHost<'a>> {
    let q = query.to_lowercase();
    let mut out: Vec<RankedHost<'a>> = hosts
        .iter()
        .map(|h| RankedHost {
            host: h,
            score: frec.score(&h.id),
        })
        .collect();
    out.sort_by(|a, b| {
        // Matches first (true > false → descending), so compare b.contains then a.contains.
        let am = a.host.alias.to_lowercase().contains(&q) as u8;
        let bm = b.host.alias.to_lowercase().contains(&q) as u8;
        bm.cmp(&am)
            .then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.host.alias.cmp(&b.host.alias))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Auth, CredentialBody, Host};
    use std::time::{Duration, UNIX_EPOCH};

    /// Build a host with a fixed id and alias for deterministic tests.
    fn host(id: u128, alias: &str) -> Host {
        Host {
            id: Ulid::from_string(&format!("{id:026X}")).unwrap(),
            alias: alias.into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        }
    }

    /// A fixed `SystemTime` well after the epoch, used as a stable "now" in
    /// tests so decay tiers are deterministic regardless of the real clock.
    fn now() -> SystemTime {
        // 2024-01-01T00:00:00Z — comfortably after UNIX_EPOCH.
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    // ---- record / record_at decay tier tests ----

    #[test]
    fn record_on_fresh_entry_seeds_score_of_one() {
        let mut frec = Frecency::default();
        let id = Ulid::new();
        frec.record_at(&id, now());
        assert_eq!(frec.score(&id), 1.0);
        assert_eq!(frec.map.get(&id).unwrap().last_used, Some(now()));
    }

    #[test]
    fn record_again_within_an_hour_multiplies_by_four() {
        let mut frec = Frecency::default();
        let id = Ulid::new();
        let t0 = now();
        frec.record_at(&id, t0);
        // 30 minutes later → <1h tier, mult = 4.0: 1.0 * 4.0 + 1.0 = 5.0
        frec.record_at(&id, t0 + Duration::from_secs(30 * 60));
        assert_eq!(frec.score(&id), 5.0);
    }

    #[test]
    fn record_keeps_score_high_when_back_to_back() {
        // The brief's Step 1: "recording again after no time keeps it high."
        let mut frec = Frecency::default();
        let id = Ulid::new();
        let t0 = now();
        frec.record_at(&id, t0);
        // Immediately again — same instant, still <1h tier.
        frec.record_at(&id, t0);
        // 1.0 * 4.0 + 1.0 = 5.0, which is much higher than the fresh 1.0.
        assert!(frec.score(&id) > 1.0);
        assert_eq!(frec.score(&id), 5.0);
    }

    #[test]
    fn record_within_a_day_multiplies_by_two() {
        let mut frec = Frecency::default();
        let id = Ulid::new();
        let t0 = now();
        frec.record_at(&id, t0);
        // 2 hours later → <1d tier, mult = 2.0: 1.0 * 2.0 + 1.0 = 3.0
        frec.record_at(&id, t0 + Duration::from_secs(2 * HOUR));
        assert_eq!(frec.score(&id), 3.0);
    }

    #[test]
    fn record_within_a_week_halves() {
        let mut frec = Frecency::default();
        let id = Ulid::new();
        let t0 = now();
        frec.record_at(&id, t0);
        // 3 days later → <1w tier, mult = 0.5: 1.0 * 0.5 + 1.0 = 1.5
        frec.record_at(&id, t0 + Duration::from_secs(3 * DAY));
        assert_eq!(frec.score(&id), 1.5);
    }

    #[test]
    fn record_older_than_a_week_quartered() {
        let mut frec = Frecency::default();
        let id = Ulid::new();
        let t0 = now();
        frec.record_at(&id, t0);
        // 10 days later → else tier, mult = 0.25: 1.0 * 0.25 + 1.0 = 1.25
        frec.record_at(&id, t0 + Duration::from_secs(10 * DAY));
        assert_eq!(frec.score(&id), 1.25);
    }

    #[test]
    fn record_accumulates_across_tiers() {
        // fresh(1.0) → +1h(×4) → +2h(×2) → +3d(×0.5)
        let mut frec = Frecency::default();
        let id = Ulid::new();
        let t0 = now();
        frec.record_at(&id, t0); // 1.0
        frec.record_at(&id, t0 + Duration::from_secs(30 * 60)); // 1.0*4+1 = 5.0
        frec.record_at(&id, t0 + Duration::from_secs(2 * HOUR)); // 5.0*2+1 = 11.0
        frec.record_at(&id, t0 + Duration::from_secs(3 * DAY)); // 11.0*0.5+1 = 6.5
        assert_eq!(frec.score(&id), 6.5);
    }

    #[test]
    fn record_uses_real_wall_clock() {
        // Smoke test: record (no explicit time) must set last_used to ~now and
        // seed score 1.0. We only assert the score; last_used is non-deterministic.
        let mut frec = Frecency::default();
        let id = Ulid::new();
        frec.record(&id);
        assert_eq!(frec.score(&id), 1.0);
    }

    #[test]
    fn score_unknown_id_is_zero() {
        let frec = Frecency::default();
        assert_eq!(frec.score(&Ulid::new()), 0.0);
    }

    // ---- rank tests ----

    #[test]
    fn rank_empty_query_orders_by_score_desc_then_alias() {
        let a = host(1, "alpha");
        let b = host(2, "bravo");
        let c = host(3, "charlie");
        let hosts = [&a, &b, &c];
        let mut frec = Frecency::default();
        // bravo used most, alpha and charlie never recorded (tie → alias asc).
        frec.record_at(&b.id, now());

        let ranked = rank(&hosts, "", &frec);
        let aliases: Vec<_> = ranked.iter().map(|r| r.host.alias.as_str()).collect();
        assert_eq!(aliases, vec!["bravo", "alpha", "charlie"]);
        assert_eq!(ranked[0].score, 1.0);
    }

    #[test]
    fn rank_score_desc_with_multiple_recorded_hosts() {
        let a = host(1, "alpha");
        let b = host(2, "bravo");
        let c = host(3, "charlie");
        let hosts = [&a, &b, &c];
        let mut frec = Frecency::default();
        let t0 = now();
        // charlie: 1.0 * 4 + 1 = 5.0 (two uses within an hour)
        frec.record_at(&c.id, t0);
        frec.record_at(&c.id, t0 + Duration::from_secs(60));
        // bravo: 1.0
        frec.record_at(&b.id, t0);
        // alpha: 0.0

        let ranked = rank(&hosts, "", &frec);
        let aliases: Vec<_> = ranked.iter().map(|r| r.host.alias.as_str()).collect();
        assert_eq!(aliases, vec!["charlie", "bravo", "alpha"]);
    }

    #[test]
    fn rank_query_puts_matches_ahead_of_non_matches() {
        // The brief's Step 1: a query puts hosts whose alias contains the query
        // ahead of non-matches — even when a non-match has a higher score.
        let web1 = host(1, "web-prod-1");
        let web2 = host(2, "web-staging");
        let db1 = host(3, "db-prod");
        let hosts = [&web1, &web2, &db1];
        let mut frec = Frecency::default();
        // db1 has the highest score, but it does NOT contain "web".
        let t0 = now();
        frec.record_at(&db1.id, t0);
        frec.record_at(&db1.id, t0 + Duration::from_secs(60)); // 5.0
        frec.record_at(&web1.id, t0); // 1.0

        let ranked = rank(&hosts, "web", &frec);
        // Both web-* hosts match and sort ahead of db1; web1 (score 1.0) > web2 (0.0).
        let aliases: Vec<_> = ranked.iter().map(|r| r.host.alias.as_str()).collect();
        assert_eq!(aliases, vec!["web-prod-1", "web-staging", "db-prod"]);
    }

    #[test]
    fn rank_query_is_case_insensitive() {
        let web1 = host(1, "Web-Prod");
        let db1 = host(2, "db-prod");
        let hosts = [&web1, &db1];
        let frec = Frecency::default();

        let ranked = rank(&hosts, "WEB", &frec);
        assert_eq!(ranked[0].host.alias, "Web-Prod");
    }

    #[test]
    fn rank_query_match_ties_break_by_score_then_alias() {
        let web_b = host(1, "web-bravo");
        let web_a = host(2, "web-alpha");
        let hosts = [&web_b, &web_a];
        let mut frec = Frecency::default();
        // web_b has a higher score → sorts first despite later alias.
        frec.record_at(&web_b.id, now());

        let ranked = rank(&hosts, "web", &frec);
        let aliases: Vec<_> = ranked.iter().map(|r| r.host.alias.as_str()).collect();
        assert_eq!(aliases, vec!["web-bravo", "web-alpha"]);
    }

    #[test]
    fn rank_empty_hosts_returns_empty() {
        let frec = Frecency::default();
        let ranked = rank(&[], "anything", &frec);
        assert!(ranked.is_empty());
    }

    #[test]
    fn rank_no_query_no_match_difference_orders_by_score() {
        // Empty query matches everyone, so it reduces to score-then-alias.
        let a = host(1, "alpha");
        let b = host(2, "bravo");
        let hosts = [&a, &b];
        let mut frec = Frecency::default();
        frec.record_at(&a.id, now());

        let ranked = rank(&hosts, "", &frec);
        assert_eq!(ranked[0].host.alias, "alpha");
        assert_eq!(ranked[1].host.alias, "bravo");
    }
}
