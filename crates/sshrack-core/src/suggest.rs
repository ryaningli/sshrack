//! "Did you mean" suggestions for misspelled aliases.
//!
//! Pure fuzzy matching: [`closest`] scores each candidate against the input
//! with [`strsim::jaro_winkler`] (the did-you-mean gold standard — sensitive to
//! shared prefixes, which dominates alias similarity) and returns the single
//! best match above [`SUGGESTION_THRESHOLD`]. Borrow-only: returns a reference
//! into the candidate slice so callers pay for a `String` only when they keep
//! the result.

use strsim::jaro_winkler;

/// Minimum Jaro-Winkler similarity (0.0..=1.0) for a candidate to qualify as a
/// suggestion. 0.7 is the conventional git/cargo threshold: below it, a
/// candidate looks unrelated and a hint would be noise.
const SUGGESTION_THRESHOLD: f64 = 0.7;

/// Return the closest candidate to `input` by Jaro-Winkler similarity, if one
/// clears [`SUGGESTION_THRESHOLD`]; otherwise `None`.
///
/// Ties break by first appearance (the order candidates are given, i.e. config
/// order). `None` for empty `input`, empty `candidates`, or when nothing is
/// similar enough. Borrows from `candidates`; the caller owns any conversion to
/// `String`.
///
/// # Examples
///
/// A close typo returns the best match:
///
/// ```
/// use sshrack_core::suggest::closest;
/// assert_eq!(closest(&["ets-pc", "web1"], "ets-pcc"), Some("ets-pc"));
/// ```
///
/// An unrelated input clears no threshold, so there is no suggestion:
///
/// ```
/// use sshrack_core::suggest::closest;
/// assert_eq!(closest(&["web1", "db"], "foobar"), None);
/// ```
pub fn closest<'a>(candidates: &[&'a str], input: &str) -> Option<&'a str> {
    if input.is_empty() || candidates.is_empty() {
        return None;
    }
    candidates
        .iter()
        .map(|candidate| (*candidate, jaro_winkler(input, candidate)))
        .filter(|&(_, score)| score >= SUGGESTION_THRESHOLD)
        // Keep the first maximum on ties: only replace the running best when a
        // later candidate is *strictly* greater, so config order wins ties.
        .fold(None, |best, (candidate, score)| match best {
            Some((_, best_score)) if score <= best_score => best,
            _ => Some((candidate, score)),
        })
        .map(|(candidate, _)| candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_closest_typo() {
        // `ets-pcc` vs `ets-pc`: a single extra char — high Jaro-Winkler score.
        assert_eq!(closest(&["ets-pc"], "ets-pcc"), Some("ets-pc"));
    }

    #[test]
    fn picks_best_of_several() {
        // `web2` is closer to `web1` than `db` is.
        assert_eq!(closest(&["web1", "db"], "web2"), Some("web1"));
    }

    #[test]
    fn unrelated_input_returns_none() {
        assert_eq!(closest(&["web1", "db"], "foobar"), None);
    }

    #[test]
    fn empty_candidates_returns_none() {
        assert_eq!(closest(&[], "web1"), None);
    }

    #[test]
    fn empty_input_returns_none() {
        assert_eq!(closest(&["web1"], ""), None);
    }

    #[test]
    fn ties_break_by_first_appearance() {
        // `abx` is equidistant from `abc` and `abd`; the first candidate wins.
        assert_eq!(closest(&["abc", "abd"], "abx"), Some("abc"));
    }
}
