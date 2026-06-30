//! Aligned-text table rendering for `host ls`/`cred ls`/`store status`.
//!
//! Extracted from `cmd::shared` so the table helper is reusable by the TUI
//! later. Only the renderer lives here; row construction and field selection
//! stay in the command handlers.

use std::io::Write;

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
    let widths: Vec<usize> = (0..fields.len())
        .map(|col| {
            fields[col]
                .len()
                .max(body.iter().map(|r| r[col].len()).max().unwrap_or(0))
        })
        .collect();
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
