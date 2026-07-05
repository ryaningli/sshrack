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
//! [`screen::TransferScreen::draw`] is render-only (no I/O); key handling
//! (`on_key`) and worker wiring land in later tasks.
//!
//! Staging note: Task 8 ships the pure render path; Task 9 wires `on_key` and
//! the `sshrack sftp` event loop, Task 10 wires the worker. Until those land
//! the screen is constructed only by tests, so methods/fields with no test
//! caller carry scoped `#[allow(dead_code)]` (mirroring `intent.rs`, `theme.rs`,
//! `launcher.rs`). Each allow drops automatically once Task 9/10 starts driving
//! it — no blanket module-level allow is in use.
//!
//! [`Progress`]: sshrack_core::connect::sftp::proto::Progress
//! [`Status`]: crate::tui::intent::Status

pub mod pane;
pub mod render;
pub mod screen;

// No `pub use` re-exports yet: TransferScreen lives under `screen::` and the
// rest of the binary has not been wired to dispatch `sshrack sftp` (Task 9).
// Re-exports here would just trip unused-import warnings in the prod binary.
