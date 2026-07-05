//! Dual-pane transfer screen for `sshrack sftp`. Each side of the screen —
//! local and remote — is driven by one [`pane::Pane`]; [`screen::TransferScreen`]
//! owns the layout, the in-flight [`Progress`], the pending transfer queue, and
//! the consolidated [`Status`] line, while [`pane::Pane`] owns the per-pane
//! pure state (cwd, entries, fuzzy query, cursor, per-directory marks).
//!
//! Architectural red line: a [`pane::Pane`] holds no data path. Its
//! [`pane::Pane::on_key`] is pure (no I/O) and returns a [`pane::PaneOutcome`]
//! intent the screen acts on; entries reach a pane only via
//! [`pane::Pane::set_entries`], whether they come from a synchronous
//! `LocalDirSource::list` (local side) or a worker event (remote side).
//! [`screen::TransferScreen::draw`] is render-only (no I/O);
//! [`screen::TransferScreen::on_key`] is the pure key router; Task 10 wires the
//! worker and the `sshrack sftp` event loop.
//!
//! Staging note: Task 8 shipped the pure render path; Task 9 added the pure
//! `on_key` router + queue-advance helpers; Task 10 wires the worker and the
//! live event loop. Until Task 10 lands the screen is constructed only by
//! tests, so methods/fields with no test caller carry scoped
//! `#[allow(dead_code)]` with the Task-10 consumer named in the doc comment —
//! no blanket module-level allow is in use.
//!
//! [`Progress`]: sshrack_core::connect::sftp::proto::Progress
//! [`Status`]: crate::tui::intent::Status

pub mod overwrite;
pub mod pane;
pub mod render;
pub mod screen;

/// Re-exported so the Task-10 sftp event loop can match on it after calling
/// `TransferScreen::on_key` without reaching into the `screen` submodule.
#[allow(dead_code, unused_imports)] // Task 10 wires the sftp event loop that consumes this.
pub use screen::ScreenOutcome;

// No further re-exports yet: TransferScreen / Pane / PaneOutcome live under
// `screen::` / `pane::` and the rest of the binary has not been wired to
// dispatch `sshrack sftp` (Task 10). Broader re-exports here would just trip
// unused-import warnings in the prod binary.
