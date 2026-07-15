//! Aligned-text table rendering for `host ls`/`cred ls`/`store status`.
//!
//! Extracted from `cmd::shared` so the table helper is reusable by the TUI
//! later. Only the renderer lives here; row construction and field selection
//! stay in the command handlers.

use std::io::Write;

/// Per-column width = max(header field len, body cell lens) for each column,
/// computed independently. With an empty body each width collapses to the
/// header field length. Extracted from `print_text_table` so the width rule
/// is directly testable without locking stdout.
fn col_widths(fields: &[&str], body: &[Vec<String>]) -> Vec<usize> {
    (0..fields.len())
        .map(|col| {
            fields[col]
                .len()
                .max(body.iter().map(|r| r[col].len()).max().unwrap_or(0))
        })
        .collect()
}

/// Render the aligned-text table. `cell_fn` produces the value for one
/// (field, row) pair.
pub(crate) fn print_text_table<T, F>(rows: &[&T], fields: &[&str], cell_fn: F)
where
    F: Fn(&str, &T) -> String,
{
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| fields.iter().map(|f| cell_fn(f, r)).collect())
        .collect();
    let widths = col_widths(fields, &body);
    let header_row: Vec<String> = fields.iter().map(|f| f.to_uppercase()).collect();
    let mut out = std::io::stdout().lock();
    let _ = write_row(&mut out, &header_row, &widths);
    for r in &body {
        let _ = write_row(&mut out, r, &widths);
    }
}

fn write_row<W: Write>(w: &mut W, row: &[String], widths: &[usize]) -> std::io::Result<()> {
    for (cell, w_) in row.iter().zip(widths) {
        write!(w, "{:<width$}  ", cell, width = w_)?;
    }
    writeln!(w)
}

#[cfg(test)]
mod tests {
    //! Column-width / alignment tests for `write_row`, the pure rendering
    //! primitive that `print_text_table` drives against `stdout`. `print_text_table`
    //! itself locks stdout, so the table-width rule (`width = max(header len, body
    //! cell lens)`) is reproduced here to drive `write_row` into a `Vec<u8>`; the
    //! observable contract — how a row renders at given widths — is what these
    //! tests pin. All sample data is ASCII, so byte length, char count, and display
    //! width coincide.

    use super::*;

    /// Write `row` at `widths` into a fresh buffer and decode it.
    fn render(row: &[String], widths: &[usize]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_row(&mut buf, row, widths).expect("invariant: Vec<u8> write never fails");
        String::from_utf8(buf).expect("invariant: test data is ASCII")
    }

    #[test]
    fn write_row_single_column_at_width_emits_cell_two_spaces_newline() {
        // Cell length == column width ⇒ no padding, just the documented two-space
        // suffix and the trailing newline. Covers the single-column case.
        let out = render(&["alpha".to_string()], &[5]);
        assert_eq!(out, "alpha  \n");
    }

    #[test]
    fn write_row_pads_narrow_cell_left_justified_to_column_width() {
        // "{:<width$}" left-justifies: the cell sits at the column start and trailing
        // spaces fill to the width, then the two-space separator follows.
        let out = render(&["a".to_string()], &[4]);
        // "a" + 3 pad spaces (to width 4) + 2 separator spaces + newline.
        let pad = " ".repeat(3);
        let sep = " ".repeat(2);
        assert_eq!(out, format!("a{pad}{sep}\n"));
    }

    #[test]
    fn write_row_empty_cell_fills_column_with_spaces() {
        // An empty body cell still consumes the full column width (all spaces) plus
        // the separator, so the next column starts at the same offset.
        let out = render(&[String::new()], &[3]);
        // 3 pad spaces (to width 3) + 2 separator spaces + newline.
        assert_eq!(out, format!("{}\n", " ".repeat(5)));
    }

    #[test]
    fn write_row_multi_column_pads_each_column_independently() {
        // Mixed wide/narrow columns: each column is sized independently, so the
        // second column's start offset depends only on the first column's width.
        let out = render(&["short".to_string(), "x".to_string()], &[8, 3]);
        // col0: "short" + 3 pad (to 8) + 2 sep ; col1: "x" + 2 pad (to 3) + 2 sep.
        let col0 = format!("short{}", " ".repeat(3 + 2));
        let col1 = format!("x{}", " ".repeat(2 + 2));
        assert_eq!(out, format!("{col0}{col1}\n"));
        // The second column begins right after col0's width + the two-space separator.
        assert_eq!(out.find('x'), Some(8 + 2));
    }

    #[test]
    fn write_row_renders_uppercased_header_joined_by_two_spaces() {
        // The header row is `fields` uppercased; with an empty body the per-column
        // width collapses to the header length (4 for "name"/"host"), so the header
        // needs no padding and the fields are joined by exactly two spaces.
        let header = ["NAME".to_string(), "HOST".to_string()];
        let out = render(&header, &[4, 4]);
        assert_eq!(out, "NAME  HOST  \n");
        // The header line — minus the trailing two-space suffix — is the two
        // uppercased fields joined by exactly two spaces.
        assert_eq!(out.trim_end(), "NAME  HOST");
    }

    #[test]
    fn write_row_aligned_columns_when_widths_are_per_column_max() {
        // End-to-end alignment contract between `print_text_table`'s width rule
        // (width = max(header len, body cell lens)) and `write_row`'s formatting.
        // Widths are derived by hand from the data below — not by calling prod — so
        // the assertion stays independent of the code under test.
        let header = ["NAME".to_string(), "AGE".to_string()];
        let body_rows = vec![
            vec!["alice".to_string(), "30".to_string()],
            vec!["bob".to_string(), "999".to_string()],
        ];
        // col0: max(4, 5, 3) = 5 ; col1: max(3, 2, 3) = 3.
        let widths = [5usize, 3];
        // Documented invariant: header width ≥ every body cell in that column.
        for (col, &w) in widths.iter().enumerate() {
            assert!(header[col].len() <= w);
            assert!(body_rows.iter().all(|r| r[col].len() <= w));
        }

        let mut buf: Vec<u8> = Vec::new();
        write_row(&mut buf, &header, &widths).expect("invariant: Vec<u8> write");
        for r in &body_rows {
            write_row(&mut buf, r, &widths).expect("invariant: Vec<u8> write");
        }
        let rendered = String::from_utf8(buf).expect("invariant: ASCII");
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);

        // Column 1 begins after col0's width + the two-space separator, in every row.
        let col1_start = widths[0] + 2;
        let col0_cells = ["NAME", "alice", "bob"];
        let col1_cells = ["AGE", "30", "999"];
        for (i, line) in lines.iter().enumerate() {
            assert_eq!(
                line[..widths[0]].trim(),
                col0_cells[i],
                "col0 misaligned on line {i}"
            );
            assert_eq!(
                line[col1_start..col1_start + widths[1]].trim(),
                col1_cells[i],
                "col1 misaligned on line {i}"
            );
        }
    }

    #[test]
    fn col_widths_empty_body_yields_header_lens() {
        // With no body rows the per-column width collapses to the header field
        // length — the floor in `print_text_table`'s width rule.
        let fields = ["name", "host"];
        let body: Vec<Vec<String>> = vec![];
        assert_eq!(col_widths(&fields, &body), vec![4, 4]);
    }

    #[test]
    fn col_widths_mixed_wide_narrow_yields_per_column_max() {
        // Width = max(header len, body cell lens) per column, computed
        // independently. col0: max(1, "xxxx".len()=4, "z".len()=1) = 4 ;
        // col1: max(2, "y".len()=1, "wwww".len()=4) = 4.
        let fields = ["a", "bb"];
        let body = vec![
            vec!["xxxx".to_string(), "y".to_string()],
            vec!["z".to_string(), "wwww".to_string()],
        ];
        assert_eq!(col_widths(&fields, &body), vec![4, 4]);
    }
}
