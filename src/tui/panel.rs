//! Shared ranking + highlight helpers for the Hosts and Credentials panels.
//!
//! - [`rank_by_fields`] ranks a list of candidates by nucleo fuzzy match
//!   across each candidate's searchable fields (name, user, host, …). A row is
//!   kept when at least one field matches; its score is the best (max) field
//!   score. Empty query → frecency-desc then first-field-asc (the canonical
//!   name used for tiebreaks).
//! - [`highlighted_spans`] renders one field's text as styled spans, with the
//!   fuzzy-matched characters (per nucleo) in `base + bold + theme::MATCH` and
//!   the rest in `base`. Shared by both panels so name/user/host highlight
//!   identically against the same query.
//!
//! Pure: no I/O, no printing, no env access. This is the data-layer core that
//! [`super::launcher::rank_hosts`] and [`super::cred_panel::rank_credentials`]
//! delegate to.

use nucleo_matcher::{
    Config, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};
use ratatui::{style::Style, text::Span};

use super::theme;

/// Rank `rows` for display. Each row is one candidate's searchable fields;
/// `rows[i][0]` is the canonical name used for tiebreaks. Empty `query` →
/// every row returned, ordered by `scores` desc then `rows[i][0]` asc.
/// Non-empty `query` → only rows where at least one field nucleo-matches,
/// ordered by best-field match score desc, then `scores` desc, then
/// `rows[i][0]` asc. Returns the original indices.
///
/// Pure: no I/O, no printing, no env access. `scores.len()` must equal
/// `rows.len()`; each entry's frecency score sits at the same index as its row.
pub fn rank_by_fields(rows: &[Vec<String>], scores: &[f64], query: &str) -> Vec<usize> {
    if query.is_empty() {
        let mut idx: Vec<usize> = (0..rows.len()).collect();
        idx.sort_by(|&a, &b| {
            scores[b]
                .partial_cmp(&scores[a])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| rows[a].first().cmp(&rows[b].first()))
        });
        return idx;
    }
    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
    let mut scored: Vec<(usize, u32)> = rows
        .iter()
        .enumerate()
        .filter_map(|(i, fields)| Some((i, score_fields(fields, &pattern, &mut matcher)?)))
        .collect();
    scored.sort_by(|&(ia, sa), &(ib, sb)| {
        sb.cmp(&sa)
            .then_with(|| {
                scores[ib]
                    .partial_cmp(&scores[ia])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| rows[ia].first().cmp(&rows[ib].first()))
    });
    scored.into_iter().map(|(i, _)| i).collect()
}

/// The highest nucleo score of `query` against any single field in `fields`,
/// or `None` when no field matches. Each field is matched independently (a
/// query never spans two fields). Pub(crate) so the host/credential panels can
/// re-attach a match score to each ranked row without re-deriving the fields.
pub(crate) fn best_field_score(fields: &[String], query: &str) -> Option<u32> {
    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
    score_fields(fields, &pattern, &mut matcher)
}

/// Per-field nucleo score, maxed across `fields`. Reuses the caller's matcher
/// and pattern so ranking many rows against one query allocates them once.
fn score_fields(fields: &[String], pattern: &Pattern, matcher: &mut Matcher) -> Option<u32> {
    fields
        .iter()
        .filter_map(|f| pattern.score(Utf32Str::Ascii(f.as_bytes()), matcher))
        .max()
}

/// Render `text` as spans, highlighting the fuzzy-matched characters (per
/// nucleo against `query`) with `base + bold + theme::MATCH`. Unmatched chars
/// use `base`. Empty `query` or no match → a single span of the whole text in
/// `base`. Pure: no I/O. Shared by the host and credential rows so each
/// searchable field highlights the query the same way.
pub fn highlighted_spans(text: &str, query: &str, base: Style) -> Vec<Span<'static>> {
    if query.is_empty() {
        return vec![Span::styled(text.to_string(), base)];
    }
    let Some(matched) = match_indices(text, query) else {
        return vec![Span::styled(text.to_string(), base)];
    };
    let highlight = base
        .add_modifier(ratatui::style::Modifier::BOLD)
        .fg(theme::MATCH);
    let mut spans = Vec::with_capacity(matched.len() + 1);
    let mut prev = 0usize;
    for idx in matched {
        // `idx` is a char index; advance to the byte offset. Between `prev`
        // and the byte offset is an unmatched run rendered in `base`.
        let byte = char_to_byte(text, idx);
        if byte > prev {
            spans.push(Span::styled(text[prev..byte].to_string(), base));
        }
        // The matched char itself (one char in width).
        let next = byte
            + text[byte..]
                .chars()
                .next()
                .map(|c| c.len_utf8())
                .unwrap_or(0);
        spans.push(Span::styled(text[byte..next].to_string(), highlight));
        prev = next;
    }
    if prev < text.len() {
        spans.push(Span::styled(text[prev..].to_string(), base));
    }
    spans
}

/// The nucleo match indices for `query` against `text`, as char indices into
/// `text`, deduplicated and sorted. Returns `None` when the query does not
/// match (nucleo `indices` returns `None`). Pure: no I/O.
fn match_indices(text: &str, query: &str) -> Option<Vec<u32>> {
    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
    let mut indices: Vec<u32> = Vec::new();
    let _score = pattern.indices(Utf32Str::Ascii(text.as_bytes()), &mut matcher, &mut indices)?;
    // nucleo appends per-atom indices without dedup/sort (per its docs); sort
    // and dedup so highlighting is monotonic and unique.
    indices.sort_unstable();
    indices.dedup();
    Some(indices)
}

/// Map a char index into `s` to its byte offset. Falls back to `s.len()` for
/// an out-of-range index so a malformed index never panics.
fn char_to_byte(s: &str, char_idx: u32) -> usize {
    s.char_indices()
        .nth(char_idx as usize)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::{Modifier, Style};

    fn rows(xs: &[&[&str]]) -> Vec<Vec<String>> {
        xs.iter().copied().map(s).collect()
    }
    fn s(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }
    fn zero(n: usize) -> Vec<f64> {
        vec![0.0; n]
    }

    // ---- rank_by_fields ----

    #[test]
    fn empty_query_orders_by_score_desc_then_name_asc() {
        let rows = rows(&[&["beta"], &["alpha"], &["gamma"]]);
        let scores = vec![1.0, 3.0, 3.0]; // alpha & gamma tie at 3, beta 1
        let order = rank_by_fields(&rows, &scores, "");
        // alpha before gamma (name asc tiebreak), then beta
        assert_eq!(order, vec![1, 2, 0]);
    }

    #[test]
    fn query_filters_to_matches_only() {
        let rows = rows(&[&["web-prod"], &["db-staging"], &["web-dev"]]);
        let order = rank_by_fields(&rows, &zero(3), "web");
        let matched: Vec<&str> = order.iter().map(|i| rows[*i][0].as_str()).collect();
        assert_eq!(matched, vec!["web-dev", "web-prod"]); // both match 'web'
    }

    #[test]
    fn query_no_matches_returns_empty() {
        let rows = rows(&[&["alpha"], &["beta"]]);
        assert!(rank_by_fields(&rows, &zero(2), "zzz").is_empty());
    }

    #[test]
    fn query_tiebreaks_by_score_then_name() {
        let rows = rows(&[&["web-a"], &["web-b"]]);
        let scores = vec![5.0, 1.0]; // same match score expected; higher frecency first
        let order = rank_by_fields(&rows, &scores, "web");
        assert_eq!(order, vec![0, 1]);
    }

    #[test]
    fn query_matches_any_field_not_just_name() {
        // name "deploy", user "root", host "web-01": query "web" matches only
        // the host field; the row must still be kept.
        let rows = rows(&[&["deploy", "root", "web-01"], &["unrelated", "u", "h"]]);
        let order = rank_by_fields(&rows, &zero(2), "web");
        assert_eq!(order, vec![0]);
    }

    #[test]
    fn query_matching_user_field_keeps_row() {
        // name/host don't match "alice"; only the user does.
        let rows = rows(&[&["ops", "alice", "10.0.0.1"]]);
        let order = rank_by_fields(&rows, &zero(1), "alice");
        assert_eq!(order, vec![0]);
    }

    #[test]
    fn best_field_score_is_max_across_fields() {
        // "web" matches both name "web" and host "web-01"; the returned score
        // equals the cleaner (shorter) name-only match, i.e. the max.
        let both = best_field_score(&s(&["web", "root", "web-01"]), "web").unwrap();
        let name_only = best_field_score(&s(&["web", "root", "zzz"]), "web").unwrap();
        assert_eq!(both, name_only);
        assert!(both > 0);
    }

    #[test]
    fn best_field_score_none_when_no_field_matches() {
        assert!(best_field_score(&s(&["a", "b", "c"]), "zzz").is_none());
    }

    // ---- highlighted_spans ----

    #[test]
    fn highlight_empty_query_returns_single_base_span() {
        let spans = highlighted_spans("abc", "", Style::new());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), "abc");
    }

    #[test]
    fn highlight_no_match_returns_single_base_span() {
        let spans = highlighted_spans("abc", "zzz", Style::new());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), "abc");
    }

    #[test]
    fn highlight_matched_chars_carry_match_color_and_bold() {
        let spans = highlighted_spans("web-prod", "web", Style::new());
        // w,e,b are highlighted; the "-prod" tail is one plain run → ≥4 spans.
        assert!(spans.len() >= 4, "got {} spans", spans.len());
        // Every span whose text is one of w/e/b is highlighted.
        let hi = spans
            .iter()
            .filter(|s| matches!(s.content.as_ref(), "w" | "e" | "b"));
        for span in hi {
            assert_eq!(span.style.fg, Some(theme::MATCH));
            assert!(span.style.add_modifier.contains(Modifier::BOLD));
        }
    }

    #[test]
    fn highlight_preserves_base_style_on_unmatched_runs() {
        // A dim base must survive onto unmatched text so the address column
        // stays dim where it isn't matched.
        let dim = Style::new().dim();
        let spans = highlighted_spans("root", "ro", dim);
        let tail = spans
            .iter()
            .find(|s| s.content.as_ref() == "ot")
            .expect("ot tail span");
        assert_eq!(tail.style, dim);
    }

    #[test]
    fn highlight_first_char_matched_produces_no_leading_plain_span() {
        // "abc" query "a" → first span is the highlighted 'a' (no empty plain
        // span prepended).
        let spans = highlighted_spans("abc", "a", Style::new());
        assert_eq!(spans[0].content.as_ref(), "a");
        assert_eq!(spans[0].style.fg, Some(theme::MATCH));
    }
}
