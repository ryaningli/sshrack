//! Host launcher data layer: pure frecency + nucleo fuzzy ranking.
//!
//! This module is the data portion of the launcher view (rendered in a later
//! task). [`rank_hosts`] is a pure function over a slice of [`Host`]s, a
//! [`Frecency`] table, and a query string. It performs no I/O and is fully
//! unit-testable without a terminal.
//!
//! Ranking contract:
//! - **Empty query** — every host is returned, ordered by frecency score
//!   descending with a name-ascending tiebreak (delegated to core's frecency
//!   data via [`frecency::rank`] over all hosts with an empty query).
//! - **Non-empty query** — hosts are fuzzy-matched against their `name` via
//!   nucleo; non-matches are excluded. Matches are ordered by descending
//!   nucleo match score, tie-broken by frecency score then name ascending.
//!
//! The returned [`RankedHost`] carries the original slice index (`host_idx`)
//! so the view can render into the source list without copying hosts, plus the
//! nucleo `score` (0 for the empty-query frecency branch).

use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use sshrack_core::config::schema::Host;
use sshrack_core::frecency::{self, Frecency};

/// A ranked host: its index into the source `&[Host]` slice plus the match
/// score that placed it there.
///
/// `score` is the nucleo fuzzy match score when a query was supplied, or `0`
/// for the empty-query frecency-only branch (where ordering, not score, is the
/// useful signal).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct RankedHost {
    /// Index into the `&[Host]` slice passed to [`rank_hosts`].
    pub host_idx: usize,
    /// nucleo match score (0 on the empty-query branch).
    pub score: u32,
}

/// Rank hosts by frecency (empty query) or nucleo fuzzy match (non-empty).
///
/// Pure: no I/O, no printing, no env access. See the module docs for the full
/// contract.
#[allow(dead_code)]
pub fn rank_hosts(hosts: &[Host], frecency: &Frecency, query: &str) -> Vec<RankedHost> {
    if query.is_empty() {
        // Delegate ordering to core's frecency rank (score-desc, name-asc),
        // then map each ranked host back to its index in the source slice.
        // Core's `rank` with an empty query matches every host, so every host
        // is returned and the order is purely frecency-then-name. We pair each
        // borrowed host with its original index up front so the reverse lookup
        // is a cheap linear scan over the (small) ranked list, not a pointer
        // identity search.
        let indexed: Vec<(&Host, usize)> = hosts.iter().enumerate().map(|(i, h)| (h, i)).collect();
        let refs: Vec<&Host> = indexed.iter().map(|(h, _)| *h).collect();
        let ranked = frecency::rank(&refs, "", frecency);
        ranked
            .into_iter()
            .map(|r| RankedHost {
                host_idx: indexed
                    .iter()
                    .find(|(h, _)| std::ptr::eq(*h, r.host))
                    .map(|(_, i)| *i)
                    .unwrap_or(0),
                score: 0,
            })
            .collect()
    } else {
        let mut matcher = Matcher::new(Config::DEFAULT);
        let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
        let mut scored: Vec<RankedHost> = hosts
            .iter()
            .enumerate()
            .filter_map(|(i, h)| {
                let score = pattern.score(Utf32Str::Ascii(h.name.as_bytes()), &mut matcher)?;
                Some(RankedHost { host_idx: i, score })
            })
            .collect();
        // Descending match score; tiebreak by frecency score descending, then
        // name ascending, so recent/frequent and alphabetically-earlier hosts
        // win ties.
        scored.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| frecency_cmp(hosts, frecency, a.host_idx, b.host_idx))
                .then_with(|| hosts[a.host_idx].name.cmp(&hosts[b.host_idx].name))
        });
        scored
    }
}

/// Order tiebreak: higher frecency score first. Returns an `Ordering` usable
/// directly in a `sort_by` closure (e.g. between elements `a` then `b`):
/// `Less` means `a` should come before `b`, i.e. `a` has the higher score.
fn frecency_cmp(
    hosts: &[Host],
    frecency: &Frecency,
    a_idx: usize,
    b_idx: usize,
) -> std::cmp::Ordering {
    let sa = frecency.score(&hosts[a_idx].id);
    let sb = frecency.score(&hosts[b_idx].id);
    // Descending: higher score first → compare b then a.
    sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::config::schema::{Auth, CredentialBody, Host};
    use sshrack_core::frecency::Frecency;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use ulid::Ulid;

    /// Build a host with a fixed id (derived from `seed`) and the given name.
    fn host(seed: u128, name: &str) -> Host {
        Host {
            id: Ulid::from_string(&format!("{seed:026X}")).unwrap(),
            name: name.into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        }
    }

    /// A fixed `SystemTime` well after the epoch, for deterministic decay tiers.
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    // ---- empty query: frecency order ----

    #[test]
    fn empty_query_orders_by_frecency_score_desc() {
        let alpha = host(1, "alpha");
        let beta = host(2, "beta");
        let hosts = vec![alpha, beta];
        let mut fr = Frecency::default();
        // beta used twice within an hour → higher score than alpha (used once).
        let t0 = now();
        fr.record_at(&hosts[0].id, t0); // alpha: 1.0
        fr.record_at(&hosts[1].id, t0); // beta: 1.0
        fr.record_at(&hosts[1].id, t0 + Duration::from_secs(60)); // beta: 5.0

        let ranked = rank_hosts(&hosts, &fr, "");
        let names: Vec<&str> = ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.as_str())
            .collect();
        assert_eq!(names, vec!["beta", "alpha"]);
        // Empty-query branch reports score 0 (ordering is the signal).
        assert!(ranked.iter().all(|r| r.score == 0));
    }

    #[test]
    fn empty_query_tiebreaks_by_name_ascending() {
        let bravo = host(1, "bravo");
        let alpha = host(2, "alpha");
        let hosts = vec![bravo, alpha];
        let fr = Frecency::default(); // no records → all tie at score 0.0

        let ranked = rank_hosts(&hosts, &fr, "");
        let names: Vec<&str> = ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "bravo"]);
    }

    #[test]
    fn empty_query_returns_all_hosts() {
        let hosts = vec![host(1, "a"), host(2, "b"), host(3, "c")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "");
        assert_eq!(ranked.len(), hosts.len());
        // Indices are a permutation of 0..len.
        let mut idxs: Vec<usize> = ranked.iter().map(|r| r.host_idx).collect();
        idxs.sort();
        assert_eq!(idxs, vec![0, 1, 2]);
    }

    #[test]
    fn empty_hosts_returns_empty() {
        let fr = Frecency::default();
        let ranked = rank_hosts(&[], &fr, "");
        assert!(ranked.is_empty());
    }

    // ---- non-empty query: fuzzy filter + rank ----

    #[test]
    fn query_filters_to_matches_only() {
        let web_prod = host(1, "web-prod");
        let db_staging = host(2, "db-staging");
        let web_dev = host(3, "web-dev");
        let hosts = vec![web_prod, db_staging, web_dev];
        let fr = Frecency::default();

        let ranked = rank_hosts(&hosts, &fr, "web");
        let names: Vec<&str> = ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.as_str())
            .collect();
        // db-staging excluded; both web-* hosts present.
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"web-prod"));
        assert!(names.contains(&"web-dev"));
        assert!(!names.contains(&"db-staging"));
    }

    #[test]
    fn query_ranks_consecutive_prefix_ahead_of_scattered() {
        // nucleo scores a contiguous prefix match ("web-...") higher than a
        // scattered/gap match, so "web-prod" outranks "web-dev" is not
        // guaranteed by score alone — but both match. The contract is: higher
        // score first. Pin the stronger match at position 0.
        let hosts = vec![host(1, "web-prod"), host(2, "xwyexbz")];
        let fr = Frecency::default();

        let ranked = rank_hosts(&hosts, &fr, "web");
        // "web-prod" has a clean prefix match; "xwyexbz" is a gap-filled fuzzy
        // match with lower score → ranks second.
        assert_eq!(hosts[ranked[0].host_idx].name, "web-prod");
    }

    #[test]
    fn query_tiebreaks_by_frecency_when_scores_equal() {
        // Two identical-prefix hosts: same nucleo score. The one with higher
        // frecency wins.
        let a = host(1, "web-alpha");
        let b = host(2, "web-bravo");
        let hosts = vec![a, b];
        let mut fr = Frecency::default();
        // web-bravo recorded, web-alpha not → web-bravo has higher frecency.
        fr.record_at(&hosts[1].id, now());

        let ranked = rank_hosts(&hosts, &fr, "web-");
        // Both match "web-" with equal score; frecency tiebreak → bravo first.
        assert_eq!(hosts[ranked[0].host_idx].name, "web-bravo");
        assert_eq!(hosts[ranked[1].host_idx].name, "web-alpha");
    }

    #[test]
    fn query_tiebreaks_by_name_when_score_and_frecency_equal() {
        let bravo = host(1, "web-bravo");
        let alpha = host(2, "web-alpha");
        let hosts = vec![bravo, alpha];
        let fr = Frecency::default(); // equal frecency (0.0)

        let ranked = rank_hosts(&hosts, &fr, "web-");
        let names: Vec<&str> = ranked
            .iter()
            .map(|r| hosts[r.host_idx].name.as_str())
            .collect();
        // Equal score, equal frecency → name ascending.
        assert_eq!(names, vec!["web-alpha", "web-bravo"]);
    }

    #[test]
    fn query_no_matches_returns_empty() {
        let hosts = vec![host(1, "alpha"), host(2, "beta")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "zzz");
        assert!(ranked.is_empty());
    }

    #[test]
    fn query_is_case_insensitive_smart_match() {
        let hosts = vec![host(1, "Web-Prod")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "web");
        assert_eq!(ranked.len(), 1);
        assert_eq!(hosts[ranked[0].host_idx].name, "Web-Prod");
    }

    #[test]
    fn ranked_host_score_is_nucleo_match_score_for_query() {
        let hosts = vec![host(1, "web-prod")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "web");
        assert_eq!(ranked.len(), 1);
        // Nucleo match scores are positive for a match.
        assert!(ranked[0].score > 0);
    }
}
