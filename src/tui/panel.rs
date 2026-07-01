//! Shared ranking helper for the Hosts and Credentials panels: rank a list of
//! names by nucleo fuzzy match (when there's a query) with frecency/name
//! tiebreaks, returning original indices in display order.
//!
//! Pure: no I/O, no printing, no env access. This is the data-layer core that
//! [`super::launcher::rank_hosts`] delegates to, and that the Credentials panel
//! (later task) will share so host and credential lists rank identically.

use nucleo_matcher::{
    Config, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};

/// Rank `names` for display. Empty `query` → frecency `scores` desc then name
/// asc (all returned). Non-empty `query` → only nucleo matches, by match score
/// desc, then `scores` desc, then name asc. Returns original indices.
///
/// Pure: no I/O, no printing, no env access. `scores.len()` must equal
/// `names.len()`; the caller is responsible for pairing them (each entry's
/// score sits at the same index as its name).
#[allow(dead_code)]
pub fn rank_by_name(names: &[String], scores: &[f64], query: &str) -> Vec<usize> {
    if query.is_empty() {
        let mut idx: Vec<usize> = (0..names.len()).collect();
        idx.sort_by(|&a, &b| {
            scores[b]
                .partial_cmp(&scores[a])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| names[a].cmp(&names[b]))
        });
        return idx;
    }
    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
    let mut scored: Vec<(usize, u32)> = names
        .iter()
        .enumerate()
        .filter_map(|(i, name)| {
            // nucleo 0.3 `Pattern::score` is 2-arg (no indices buffer); only
            // `Pattern::indices` takes the &mut Vec<u32> (see launcher.rs
            // match_indices). `Utf32Str::Ascii` needs no scratch buffer.
            let s = pattern.score(Utf32Str::Ascii(name.as_bytes()), &mut matcher)?;
            Some((i, s))
        })
        .collect();
    scored.sort_by(|&(ia, sa), &(ib, sb)| {
        sb.cmp(&sa)
            .then_with(|| {
                scores[ib]
                    .partial_cmp(&scores[ia])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| names[ia].cmp(&names[ib]))
    });
    scored.into_iter().map(|(i, _)| i).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }
    fn zero(n: usize) -> Vec<f64> {
        vec![0.0; n]
    }

    #[test]
    fn empty_query_orders_by_score_desc_then_name_asc() {
        let names = s(&["beta", "alpha", "gamma"]);
        let scores = vec![1.0, 3.0, 3.0]; // alpha & gamma tie at 3, beta 1
        let order = rank_by_name(&names, &scores, "");
        // alpha before gamma (name asc tiebreak), then beta
        assert_eq!(order, vec![1, 2, 0]);
    }

    #[test]
    fn query_filters_to_matches_only() {
        let names = s(&["web-prod", "db-staging", "web-dev"]);
        let order = rank_by_name(&names, &zero(3), "web");
        let matched: Vec<&str> = order.iter().map(|i| names[*i].as_str()).collect();
        assert_eq!(matched, vec!["web-dev", "web-prod"]); // both match 'web'
    }

    #[test]
    fn query_no_matches_returns_empty() {
        let names = s(&["alpha", "beta"]);
        assert!(rank_by_name(&names, &zero(2), "zzz").is_empty());
    }

    #[test]
    fn query_tiebreaks_by_score_then_name() {
        let names = s(&["web-a", "web-b"]);
        let scores = vec![5.0, 1.0]; // same match score expected; higher frecency first
        let order = rank_by_name(&names, &scores, "web");
        assert_eq!(order, vec![0, 1]);
    }
}
