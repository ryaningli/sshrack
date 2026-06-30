//! Stable process exit codes. The CLI maps domain errors to these so scripts
//! and automation can branch on them.
//!
//! Most constants are not referenced until the command handlers land (Tasks
//! 19–20); they are declared up front so the mapping is stable from the first
//! shipped CLI.

/// Successful execution.
pub const SUCCESS: i32 = 0;

/// Invalid command-line usage (e.g. missing required argument, unknown flag).
pub const USAGE: i32 = 2;

/// A referenced host, credential, or resource was not found.
pub const NOT_FOUND: i32 = 4;

/// A name collision blocked a create/rename (e.g. alias already exists).
pub const DUPLICATE: i32 = 5;

/// Input failed validation (e.g. bad port, malformed alias).
pub const VALIDATION: i32 = 6;

/// A connection or remote operation failed.
pub const CONNECT: i32 = 7;

/// A storage-mode operation failed (e.g. keyring unavailable, rekey error).
pub const STORE: i32 = 8;
