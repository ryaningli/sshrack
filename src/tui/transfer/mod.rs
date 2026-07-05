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
//! Task 10 wires the live paths: [`open::open_transfer`] mirrors
//! `connect_host`'s auth/hostkey steps then opens the SFTP worker and seeds a
//! fresh `TransferScreen`; the TUI's `run_loop` drains worker events each 250 ms
//! tick. The pure pieces (screen, pane, overwrite) are still unit-tested
//! without a terminal or network; the real-worker path (master open, live
//! transfer) is a manual smoke for Task 12.
//!
//! [`Progress`]: sshrack_core::connect::sftp::proto::Progress
//! [`Status`]: crate::tui::intent::Status

pub mod open;
pub mod overwrite;
pub mod pane;
pub mod render;
pub mod screen;
