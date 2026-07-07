//! Parser for `ls -l` listings produced by `sftp -b -` running `ls -l <path>`.
//!
//! Remote SFTP listings are plain text, so a malicious filename can carry C0
//! control characters (e.g. `foo\x1b[2Jbar`) that would reorder or blank the
//! picker layout. This module turns raw `ls -l` lines into [`RawLsEntry`] rows
//! (dropping junk lines and symlink targets) and then into display-ready
//! [`DirEntry`] rows via [`dirsource::build_entries`], stripping control chars
//! on the way so the resulting names are always layout-safe.
//!
//! All functions here are pure: the caller supplies the reference `now` used
//! to resolve the year for year-less `Mmm DD HH:MM` timestamps (which ls
//! omits).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::dirsource::{DirEntry, build_entries};
use crate::pathutil::normalize_lexical;

/// Raw `(name, path, is_dir, is_symlink, size, modified)` tuple that
/// [`build_entries`] consumes. Matches the Task-1 column contract.
type RawEntry = (
    String,
    std::path::PathBuf,
    bool,
    bool,
    Option<u64>,
    Option<SystemTime>,
);

/// One parsed `ls -l` row. `name` is the raw basename (no decoration);
/// `is_dir`/`is_symlink` are inferred from the mode column's first byte
/// (`d`/`l`/`-`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLsEntry {
    /// Raw basename, no trailing `/` or `@` decoration. May contain C0 control
    /// chars straight from the wire; [`to_dir_entries`] strips them.
    pub name: String,
    /// Whether the mode column started with `d` (directory).
    pub is_dir: bool,
    /// Whether the mode column started with `l` (symbolic link).
    pub is_symlink: bool,
    /// File size in bytes from field 5, or `None` for directories.
    pub size: Option<u64>,
    /// Best-effort mtime parsed from the date fields, or `None` on any
    /// ambiguity (unknown month, non-numeric fields, impossible date).
    pub modified: Option<SystemTime>,
}

/// Parse one `ls -l` line. Returns `None` for blank lines, `total N` summaries,
/// rows with fewer than 9 whitespace fields, and device/socket/pipe/fifo entries
/// (mode first byte not in `-dl`). Names containing spaces are recovered by
/// taking everything after the 9th field. A trailing ` -> target` on symlinks
/// is dropped (only the link name is kept).
///
/// `now` is the caller-supplied reference time used to resolve the year for
/// year-less `Mmm DD HH:MM` timestamps: if the candidate falls later than
/// `now`, the file is treated as last year's (ls only emits the `HH:MM` form
/// for entries within roughly six months). Pure.
pub fn parse_ls_line(line: &str, now: SystemTime) -> Option<RawLsEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let fields: Vec<&str> = trimmed.split_whitespace().collect();
    if fields.len() < 9 {
        return None;
    }
    // `total N` block-summary line (the len check already drops the common form,
    // but guard explicitly for intent + robustness against odd padding).
    if fields[0] == "total" {
        return None;
    }
    let mode = fields[0];
    // split_whitespace never yields empty strings, so indexing [0] on the bytes
    // is safe.
    let mode_first = mode.as_bytes()[0];
    if !matches!(mode_first, b'-' | b'd' | b'l') {
        // b/c/p/s (device / socket / pipe / fifo) — not selectable entries.
        return None;
    }
    let is_dir = mode_first == b'd';
    let is_symlink = mode_first == b'l';

    // Size: field 4. Directories report a meaningless block size, so mirror
    // LocalDirSource and report None for dirs (the size column is for files).
    let size = if is_dir {
        None
    } else {
        fields[4].parse::<u64>().ok()
    };

    // mtime: fields 5 (month), 6 (day), 7 (HH:MM or YYYY).
    let modified = parse_modified(fields[5], fields[6], fields[7], now);

    // Name: everything after the 9th field, so internal spaces survive verbatim.
    let name_raw = remainder_from_field(trimmed, 8)?;
    // For a symlink the name portion is `link -> target`; keep only the link.
    let name = if is_symlink {
        match name_raw.find(" -> ") {
            Some(idx) => name_raw[..idx].to_string(),
            None => name_raw.to_string(),
        }
    } else {
        name_raw.to_string()
    };

    Some(RawLsEntry {
        name,
        is_dir,
        is_symlink,
        size,
        modified,
    })
}

/// Parse a full `ls -l` listing into entries, skipping literal `.`/`..` rows
/// and unparseable lines. `now` is threaded into [`parse_ls_line`] for year
/// inference. Pure.
///
/// Note: sftp `ls -la` also emits `.`/`..` as ABSOLUTE-path names (`<cwd>` /
/// `<cwd>/..`); this filter only sees the raw name and catches the literal
/// forms — the absolute-path self-refs are dropped later in [`to_dir_entries`]
/// by normalized path identity.
pub fn parse_ls_listing(output: &str, now: SystemTime) -> Vec<RawLsEntry> {
    output
        .lines()
        .filter_map(|line| parse_ls_line(line, now))
        .filter(|e| e.name != "." && e.name != "..")
        .collect()
}

/// Convert parsed rows into display-ready [`DirEntry`] rows: strip control
/// chars from each name, attach paths, decorate + sort dirs-first via
/// [`build_entries`]. Pure (takes already-parsed rows; any clock reference
/// was supplied to [`parse_ls_line`] before rows reached here).
///
/// Name shape: `sftp ls -l <abs>` emits ABSOLUTE paths in the name column, so
/// when the cleaned name is absolute we take its basename for display and
/// keep the absolute path for navigation. A relative name still joins under
/// `cwd` (servers that list relatively, or future sources).
pub fn to_dir_entries(rows: Vec<RawLsEntry>, cwd: &Path) -> Vec<DirEntry> {
    // `ls -la` self-reference rows: OpenSSH sftp emits `.`/`..` with absolute-
    // path names (`<cwd>` and `<cwd>/..`), which the literal `.`/`..` filter in
    // `parse_ls_listing` misses. Drop any entry whose normalized path is the
    // cwd itself (the `.` row) or its parent (the `..` row).
    let cwd_norm = normalize_lexical(cwd);
    let parent_norm = cwd.parent().map(normalize_lexical);
    let items: Vec<RawEntry> = rows
        .into_iter()
        .map(|r| {
            let clean = strip_control_chars(&r.name);
            let (display, path) = if std::path::Path::new(&clean).is_absolute() {
                let abs = std::path::PathBuf::from(&clean);
                let base = abs
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or(clean.clone());
                (base, abs)
            } else {
                (clean.clone(), cwd.join(&clean))
            };
            (display, path, r.is_dir, r.is_symlink, r.size, r.modified)
        })
        .filter(|(_, path, _, _, _, _)| {
            let p = normalize_lexical(path);
            p != cwd_norm && Some(p) != parent_norm
        })
        .collect();
    build_entries(items)
}

/// Replace C0 control chars (U+0000–U+001F and U+007F) — except tab and
/// newline, which never appear in a name here — with `?` so a malicious name
/// cannot inject ANSI/control sequences that reorder or blank the layout.
/// Pure.
pub fn strip_control_chars(s: &str) -> String {
    s.chars()
        .map(|c| {
            let code = u32::from(c);
            if (code <= 0x1F || code == 0x7F) && c != '\t' && c != '\n' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Return the slice of `line` starting at whitespace-field index `field_idx`
/// (0-based), preserving any internal spacing. Returns `None` when the line has
/// fewer than `field_idx + 1` fields. Pure.
fn remainder_from_field(line: &str, field_idx: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    for _ in 0..field_idx {
        // Skip whitespace before this token, then the token itself.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
    }
    // Skip whitespace before the target field.
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        None
    } else {
        Some(&line[i..])
    }
}

/// Best-effort parse of the `Mmm DD HH:MM` / `Mmm DD  YYYY` date triple into a
/// [`SystemTime`]. Returns `None` on any ambiguity (unknown month, non-numeric
/// fields, impossible ranges, or a pre-epoch result). The column is
/// informational, never load-bearing.
///
/// For the year-less `HH:MM` form the year is inferred from the caller-supplied
/// `now`: if the candidate `SystemTime` falls later than `now`, the file is
/// treated as last year's (ls only emits the `HH:MM` form for entries within
/// roughly six months, so a `Dec` line seen in January is last December's).
/// Pure.
fn parse_modified(
    month_field: &str,
    day_field: &str,
    rest_field: &str,
    now: SystemTime,
) -> Option<SystemTime> {
    let month = month_name_to_num(month_field)?;
    let day: u32 = day_field.parse().ok()?;
    let (year, hour, minute, has_time) = if let Some(idx) = rest_field.find(':') {
        // `HH:MM` — ls omits the year for recent entries; infer it from `now`.
        let hour: u32 = rest_field[..idx].parse().ok()?;
        let minute: u32 = rest_field[idx + 1..].parse().ok()?;
        (year_from_now(now), hour, minute, true)
    } else {
        // `YYYY` — explicit year, no time.
        let year: i64 = rest_field.parse().ok()?;
        (year, 0, 0, false)
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let candidate = compose_system_time(year, month, day, hour, minute)?;
    if has_time && candidate > now {
        // The candidate falls in the future relative to `now` — the file is
        // from last year's December window (the January-seeing-December case).
        return compose_system_time(year - 1, month, day, hour, minute);
    }
    Some(candidate)
}

/// Compose a [`SystemTime`] from civil date+time components, or `None` on a
/// pre-epoch result or arithmetic overflow. Pure.
fn compose_system_time(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
) -> Option<SystemTime> {
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60;
    if secs < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
}

/// Map a 3-letter month abbreviation to its 1-based number, or `None`. Pure.
fn month_name_to_num(s: &str) -> Option<u32> {
    match s {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

/// Gregorian year (UTC) derived from the caller-supplied `now`. Pure (no system
/// clock is read here; the caller supplies the reference time).
fn year_from_now(now: SystemTime) -> i64 {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    civil_from_days(days).0
}

/// Days since 1970-01-01 for a proleptic-Gregorian (year, month, day).
/// Howard Hinnant's algorithm; valid for any date, no deps. Pure.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * u64::from(if month > 2 { month - 3 } else { month + 9 }) + 2) / 5
        + u64::from(day)
        - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Inverse of [`days_from_civil`]: (year, month, day) in UTC for a day count
/// since 1970-01-01. Howard Hinnant's algorithm. Pure.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Fixed reference time for deterministic year inference: 2025-06-15
    /// 12:00:00 UTC. Mid-year so `Jan`/`Feb` no-year timestamps resolve to
    /// 2025 without triggering the year-boundary rollback.
    fn fixed_now() -> SystemTime {
        let days = u64::try_from(days_from_civil(2025, 6, 15)).unwrap();
        UNIX_EPOCH + Duration::from_secs(days * 86_400 + 43_200)
    }

    /// Re-derive the UTC civil year of a [`SystemTime`] for year-inference
    /// assertions.
    fn year_of(t: SystemTime) -> i64 {
        let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap();
        let days = i64::try_from(secs / 86_400).unwrap();
        civil_from_days(days).0
    }

    // ---- parse_ls_line: the core field model ----

    #[test]
    fn parse_ls_line_regular_file() {
        let line = "-rw-r--r-- 1 u g 1234 Jan 2 03:04 hello.txt";
        let e = parse_ls_line(line, fixed_now()).expect("regular file row parses");
        assert_eq!(e.name, "hello.txt");
        assert!(!e.is_dir);
        assert!(!e.is_symlink);
        assert_eq!(e.size, Some(1234));
        assert!(
            e.modified.is_some(),
            "Jan 2 03:04 should resolve to a SystemTime"
        );
    }

    #[test]
    fn parse_ls_line_directory() {
        let line = "drwxr-xr-x 2 u g 4096 Jan 2 03:04 sub";
        let e = parse_ls_line(line, fixed_now()).expect("directory row parses");
        assert_eq!(e.name, "sub");
        assert!(e.is_dir);
        assert!(
            e.size.is_none(),
            "dirs report None (matches LocalDirSource convention)"
        );
        assert!(e.modified.is_some());
    }

    #[test]
    fn parse_ls_line_symlink_drops_target() {
        let line = "lrwxrwxrwx 1 u g 4 Jan 2 03:04 link -> tgt";
        let e = parse_ls_line(line, fixed_now()).expect("symlink row parses");
        assert!(e.is_symlink);
        assert_eq!(e.name, "link", "only the link name is kept, target dropped");
    }

    #[test]
    fn parse_ls_line_symlink_without_arrow_keeps_name() {
        // Defensive: a symlink row that for some reason lacks ` -> ` keeps its
        // whole name rather than being dropped.
        let line = "lrwxrwxrwx 1 u g 4 Jan 2 03:04 orphanlink";
        let e = parse_ls_line(line, fixed_now()).expect("symlink row without arrow still parses");
        assert!(e.is_symlink);
        assert_eq!(e.name, "orphanlink");
    }

    #[test]
    fn parse_ls_line_preserves_single_spaces_in_name() {
        let line = "-rw-r--r-- 1 u g 5 Jan 2 03:04 a name with spaces.txt";
        let e = parse_ls_line(line, fixed_now()).expect("name with spaces parses");
        assert_eq!(e.name, "a name with spaces.txt");
    }

    #[test]
    fn parse_ls_line_preserves_double_spaces_in_name() {
        // remainder_from_field takes the raw tail, so internal double spacing
        // (which ls emits verbatim) survives.
        let line = "-rw-r--r-- 1 u g 6 Jan 2 03:04 a  b";
        let e = parse_ls_line(line, fixed_now()).expect("name with double spaces parses");
        assert_eq!(e.name, "a  b");
    }

    // ---- parse_ls_line: filtered-out rows ----

    #[test]
    fn parse_ls_line_returns_none_for_blank() {
        let now = fixed_now();
        assert!(parse_ls_line("", now).is_none());
        assert!(parse_ls_line("    ", now).is_none());
        assert!(parse_ls_line("\t\n", now).is_none());
    }

    #[test]
    fn parse_ls_line_returns_none_for_total() {
        assert!(parse_ls_line("total 12", fixed_now()).is_none());
    }

    #[test]
    fn parse_ls_line_returns_none_for_device_socket_pipe_fifo() {
        let now = fixed_now();
        // mode first byte not in `-dl` → filtered (b/c/p/s).
        assert!(parse_ls_line("crw-rw-rw- 1 u g 1,3 Jan 2 03:04 null", now).is_none());
        assert!(parse_ls_line("brw-r--r-- 1 u g 1,2 Jan 2 03:04 sda", now).is_none());
        assert!(parse_ls_line("prw-r--r-- 1 u g 0 Jan 2 03:04 pipe", now).is_none());
        assert!(parse_ls_line("srw-rw-rw- 1 u g 0 Jan 2 03:04 sock", now).is_none());
    }

    #[test]
    fn parse_ls_line_returns_none_for_too_few_fields() {
        let now = fixed_now();
        assert!(parse_ls_line("drwxr-xr-x 2 u g", now).is_none());
        assert!(parse_ls_line("only one", now).is_none());
    }

    #[test]
    fn parse_ls_line_handles_crlf_line() {
        // Some transports tack on a trailing CR; trim() removes it before parse.
        let line = "-rw-r--r-- 1 u g 1234 Jan 2 03:04 hello.txt\r\n";
        let e = parse_ls_line(line, fixed_now()).expect("CRLF-trimmed row parses");
        assert_eq!(e.name, "hello.txt");
    }

    // ---- modified parsing edge cases ----

    #[test]
    fn parse_ls_line_modified_year_format_is_some() {
        let line = "-rw-r--r-- 1 u g 1234 Jan 2  2020 hello.txt";
        let e = parse_ls_line(line, fixed_now()).expect("row with explicit year parses");
        assert!(e.modified.is_some(), "Jan 2 2020 should resolve");
    }

    #[test]
    fn parse_ls_line_modified_bad_month_is_none_entry_kept() {
        let line = "-rw-r--r-- 1 u g 1234 Xyz 2 03:04 hello.txt";
        let e = parse_ls_line(line, fixed_now()).expect("entry still parses despite bad month");
        assert!(e.modified.is_none(), "unknown month → None");
        assert_eq!(e.size, Some(1234));
    }

    #[test]
    fn parse_ls_line_modified_non_numeric_day_is_none() {
        let line = "-rw-r--r-- 1 u g 1234 Jan ab 03:04 hello.txt";
        let e = parse_ls_line(line, fixed_now()).expect("entry still parses despite bad day");
        assert!(e.modified.is_none(), "non-numeric day → None");
    }

    #[test]
    fn parse_ls_line_modified_impossible_range_is_none() {
        let line = "-rw-r--r-- 1 u g 1234 Jan 32 03:04 hello.txt";
        let e = parse_ls_line(line, fixed_now()).expect("entry still parses despite bad day range");
        assert!(e.modified.is_none(), "day=32 is out of range → None");
    }

    #[test]
    fn parse_ls_line_size_non_numeric_is_none() {
        // A weird size column (shouldn't happen for files, but be defensive):
        // entry still parses, size is None.
        let line = "-rw-r--r-- 1 u g abc Jan 2 03:04 hello.txt";
        let e = parse_ls_line(line, fixed_now()).expect("entry parses with unparseable size");
        assert!(e.size.is_none());
    }

    // ---- year inference (no-year HH:MM form) ----

    #[test]
    fn parse_ls_line_no_year_timestamp_uses_inferred_year() {
        // `Jan 2 03:04` with now = 2025-06-15 infers year 2025: the candidate
        // 2025-01-02 is earlier than `now`, so no rollback fires.
        let line = "-rw-r--r-- 1 u g 1234 Jan 2 03:04 hello.txt";
        let e = parse_ls_line(line, fixed_now()).expect("row parses");
        assert_eq!(
            year_of(e.modified.expect("modified resolves")),
            2025,
            "no-year Jan timestamp with mid-year now resolves to current year"
        );
    }

    #[test]
    fn parse_ls_line_year_rolls_back_when_december_seen_in_january() {
        // Regression: ls only emits the `HH:MM` form for entries within ~6
        // months. A `Dec 31 23:59` line parsed with now = 2026-01-01 must land
        // in the PREVIOUS year (2025-12-31), not 2026-12-31 (which would put
        // the file ~11 months in the future).
        let now = {
            let days = u64::try_from(days_from_civil(2026, 1, 1)).unwrap();
            UNIX_EPOCH + Duration::from_secs(days * 86_400)
        };
        let line = "-rw-r--r-- 1 u g 1234 Dec 31 23:59 old.txt";
        let e = parse_ls_line(line, now).expect("year-boundary row parses");
        assert_eq!(
            year_of(e.modified.expect("modified resolves")),
            2025,
            "Dec 31 seen in January must land in the previous year"
        );
    }

    // ---- remainder_from_field ----

    #[test]
    fn remainder_from_field_returns_none_when_too_few_fields() {
        assert!(remainder_from_field("a b c", 3).is_none());
        assert!(remainder_from_field("", 0).is_none());
    }

    #[test]
    fn remainder_from_field_preserves_internal_spacing() {
        let line = "a b  c   d";
        // field 1 = "b", remainder from field 1 = "b  c   d".
        assert_eq!(remainder_from_field(line, 1), Some("b  c   d"));
        assert_eq!(remainder_from_field(line, 2), Some("c   d"));
    }

    // ---- strip_control_chars ----

    #[test]
    fn strip_control_chars_replaces_c0_except_tab_newline() {
        // \x1b (ESC), \x07 (BEL), \x00 (NUL), \x7f (DEL) → '?';
        // \t and \n are preserved.
        let input = "a\x1bb\x07c\x00d\x7fe\tf\ng";
        assert_eq!(strip_control_chars(input), "a?b?c?d?e\tf\ng");
    }

    #[test]
    fn strip_control_chars_leaves_plain_text_untouched() {
        assert_eq!(strip_control_chars("hello world.txt"), "hello world.txt");
    }

    #[test]
    fn strip_control_chars_empty_is_empty() {
        assert_eq!(strip_control_chars(""), "");
    }

    // ---- parse_ls_listing ----

    #[test]
    fn parse_ls_listing_drops_dot_and_dotdot() {
        let listing = "\
drwxr-xr-x 2 u g 4096 Jan 2 03:04 .
drwxr-xr-x 3 u g 4096 Jan 2 03:04 ..
-rw-r--r-- 1 u g 5 Jan 2 03:04 keep.txt
total 12
";
        let rows = parse_ls_listing(listing, fixed_now());
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["keep.txt"]);
    }

    #[test]
    fn parse_ls_listing_drops_unparseable_and_keeps_rest() {
        let listing = "\
-rw-r--r-- 1 u g 5 Jan 2 03:04 a.txt

total 8
crw-rw-rw- 1 u g 1,3 Jan 2 03:04 null
not a real line
drwxr-xr-x 2 u g 4096 Jan 2 03:04 sub
";
        let rows = parse_ls_listing(listing, fixed_now());
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "sub"]);
    }

    #[test]
    fn parse_ls_listing_empty_input_is_empty() {
        assert!(parse_ls_listing("", fixed_now()).is_empty());
    }

    // ---- to_dir_entries ----

    #[test]
    fn to_dir_entries_sorts_dirs_first_then_files_case_insensitive() {
        let rows = vec![
            raw("zfile.txt", false, false),
            raw("Adir", true, false),
            raw("afile.txt", false, false),
            raw("Bdir", true, false),
        ];
        let cwd = Path::new("/srv");
        let entries = to_dir_entries(rows, cwd);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Adir/", "Bdir/", "afile.txt", "zfile.txt"]);
    }

    #[test]
    fn to_dir_entries_attaches_path_under_cwd_with_raw_name() {
        let rows = vec![raw("Adir", true, false)];
        let cwd = Path::new("/srv");
        let entries = to_dir_entries(rows, cwd);
        assert_eq!(entries.len(), 1);
        // Path uses the RAW (undecorated) name so navigation resolves.
        assert_eq!(entries[0].path, PathBuf::from("/srv/Adir"));
        // Display name is decorated.
        assert_eq!(entries[0].name, "Adir/");
    }

    #[test]
    fn to_dir_entries_decorates_symlink_with_at() {
        let rows = vec![raw("link", false, true)];
        let entries = to_dir_entries(rows, Path::new("/srv"));
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_symlink);
        assert_eq!(entries[0].name, "link@");
        assert_eq!(entries[0].path, PathBuf::from("/srv/link"));
    }

    #[test]
    fn to_dir_entries_strips_control_chars_from_name() {
        // A name arriving with an ESC byte (ANSI injection attempt) is cleaned
        // before it reaches the DirEntry so it cannot reorder the layout.
        let rows = vec![raw("foo\x1bbar", false, false)];
        let entries = to_dir_entries(rows, Path::new("/srv"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "foo?bar");
        assert!(
            !entries[0].name.contains('\x1b'),
            "no C0 control char may survive into DirEntry.name"
        );
        // Path is also built from the cleaned name.
        assert_eq!(entries[0].path, PathBuf::from("/srv/foo?bar"));
    }

    #[test]
    fn to_dir_entries_carries_size_and_modified_for_files() {
        let rows = vec![RawLsEntry {
            name: "f.txt".into(),
            is_dir: false,
            is_symlink: false,
            size: Some(42),
            modified: Some(UNIX_EPOCH + Duration::from_secs(1_000_000)),
        }];
        let entries = to_dir_entries(rows, Path::new("/srv"));
        assert_eq!(entries[0].size, Some(42));
        assert!(entries[0].modified.is_some());
    }

    #[test]
    fn to_dir_entries_empty_is_empty() {
        assert!(to_dir_entries(Vec::new(), Path::new("/srv")).is_empty());
    }

    #[test]
    fn to_dir_entries_strips_absolute_prefix_to_basename() {
        // sftp `ls -l /srv` emits rows with ABSOLUTE paths in the name column
        // (because the argument is absolute). The display name must be the
        // basename; the navigation path stays absolute.
        let rows = vec![
            RawLsEntry {
                name: "/srv/sub".into(),
                is_dir: true,
                is_symlink: false,
                size: None,
                modified: None,
            },
            RawLsEntry {
                name: "/srv/afile.txt".into(),
                is_dir: false,
                is_symlink: false,
                size: Some(1234),
                modified: None,
            },
        ];
        let entries = to_dir_entries(rows, Path::new("/srv"));
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["sub/", "afile.txt"],
            "dirs first, decorated; basename only"
        );
        assert_eq!(
            entries[0].path,
            PathBuf::from("/srv/sub"),
            "dir path stays absolute"
        );
        let afile = entries
            .iter()
            .find(|e| e.name == "afile.txt")
            .expect("file entry present");
        assert_eq!(
            afile.path,
            PathBuf::from("/srv/afile.txt"),
            "file path stays absolute"
        );
    }

    #[test]
    fn to_dir_entries_relative_name_still_joins_cwd() {
        // A relative (basename) name — e.g. a server that lists relatively —
        // still joins under cwd (the legacy behavior), so both forms work.
        let rows = vec![RawLsEntry {
            name: "rel.txt".into(),
            is_dir: false,
            is_symlink: false,
            size: None,
            modified: None,
        }];
        let entries = to_dir_entries(rows, Path::new("/srv"));
        assert_eq!(entries[0].name, "rel.txt");
        assert_eq!(entries[0].path, PathBuf::from("/srv/rel.txt"));
    }

    // ---- date helper spot checks ----

    #[test]
    fn days_from_civil_epoch_is_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn civil_from_days_round_trips_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2020-01-01 is 18262 days after epoch.
        assert_eq!(civil_from_days(18_262), (2020, 1, 1));
    }

    /// Helper: build a [`RawLsEntry`] with sane defaults for sort/decoration
    /// tests (no size/modified).
    fn raw(name: &str, is_dir: bool, is_symlink: bool) -> RawLsEntry {
        RawLsEntry {
            name: name.into(),
            is_dir,
            is_symlink,
            size: None,
            modified: None,
        }
    }
}
