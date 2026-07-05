//! Dual-pane transfer screen for `sshrack sftp` (in progress). Each side of
//! the screen — local and remote — is driven by one [`pane::Pane`]; the
//! screen-level code (a later task) owns the layout, the SFTP worker, the
//! focus switch, and transfer enqueue, while this module owns the per-pane
//! pure state: cwd, entries, fuzzy query, cursor, and per-directory marks.
//!
//! Architectural red line: a [`pane::Pane`] holds no data path. Its
//! [`pane::Pane::on_key`] is pure (no I/O) and returns a [`pane::PaneOutcome`]
//! intent the screen acts on; entries reach a pane only via
//! [`pane::Pane::set_entries`], whether they come from a synchronous
//! `LocalDirSource::list` (local side) or a worker event (remote side).
//!
//! This module is staged ahead of the transfer screen; the re-exports are
//! unused until that screen lands, so module-local `unused_imports` silencing
//! applies. Scoped to this file so newly-unused imports elsewhere still flag.

// Scoped silence: see the module doc — the transfer screen lands in a later
// task and will consume these re-exports.
#![allow(unused_imports)]

pub mod pane;

pub use pane::{Pane, PaneOutcome, Side};
