//! Pure overwrite-resolution for the dual-pane transfer screen. Given the
//! user's batch-level [`OverwritePolicy`] and whether this one destination
//! already exists, [`decide`] returns the [`OverwriteChoice`] the worker
//! should apply. No I/O; the popup that surfaces a single conflict (Task 10)
//! calls into here, as does the batch loop before each transfer.
//!
//! Naming note: [`OverwriteChoice::Cancel`] is what the popup returns on `Esc`
//! — [`decide`] itself never produces `Cancel`. `Cancel` lives in the enum so
//! the popup can return the same type the batch loop consumes; the pure table
//! only knows "go" (`Overwrite`/`OverwriteAll`) and "skip" (`Skip`/`SkipAll`).

use sshrack_core::connect::sftp::proto::OverwritePolicy;

/// The action the worker should take for one destination path. Returned by
/// [`decide`] for the four batch policies; the conflict popup (Task 10) also
/// emits [`Cancel`](Self::Cancel) on `Esc` to abort the whole batch.
///
/// Reachability: Task 10's sftp event loop consumes this (the overwrite popup
/// + the batch loop call `decide` before each transfer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwriteChoice {
    /// Overwrite this one destination. Emitted by `Overwrite` and `OverwriteAll`
    /// (the latter applies to every subsequent conflict too).
    Overwrite,
    /// Skip this one destination. Emitted by `Skip` and `SkipAll` (the latter
    /// applies to every subsequent conflict too). Skipping a non-existent
    /// destination is a no-op transfer — there is nothing to skip, the source
    /// is simply not copied.
    Skip,
    /// Overwrite every conflict in this batch from now on. Emitted by
    /// [`OverwritePolicy::OverwriteAll`].
    OverwriteAll,
    /// Skip every conflict in this batch from now on. Emitted by
    /// [`OverwritePolicy::SkipAll`].
    SkipAll,
    /// Abort the batch. Produced by the conflict popup's `Esc` handler, never
    /// by [`decide`] itself.
    Cancel,
}

/// Decide what to do for one conflicting destination. Pure given the user's
/// batch-level `policy` + whether this destination already exists.
///
/// Semantics:
/// - `OverwriteAll` → always [`Overwrite`](OverwriteChoice::Overwrite), whether
///   or not the destination exists (no conflict still overwrites — the user
///   asked for "all").
/// - `SkipAll` → always [`Skip`](OverwriteChoice::Skip).
/// - `Overwrite` → [`Overwrite`](OverwriteChoice::Overwrite) (the single-shot
///   policy is set by the popup right before re-issuing the transfer, so it
///   always means "go").
/// - `Skip` → [`Skip`](OverwriteChoice::Skip).
///
/// `dest_exists` is taken as a parameter for symmetry with the popup's
/// decision shape (a future caller may pass it for the single-shot policies
/// too); for the current table the single-shot policies are decisive either
/// way and the `*All` policies are decisive either way, so `dest_exists` does
/// not change the result. It is part of the signature so callers and tests
/// document the no-conflict case explicitly.
/// Reachability: Task 10's sftp event loop + overwrite popup call this.
#[must_use]
pub fn decide(policy: OverwritePolicy, _dest_exists: bool) -> OverwriteChoice {
    match policy {
        OverwritePolicy::Overwrite => OverwriteChoice::Overwrite,
        OverwritePolicy::Skip => OverwriteChoice::Skip,
        OverwritePolicy::OverwriteAll => OverwriteChoice::Overwrite,
        OverwritePolicy::SkipAll => OverwriteChoice::Skip,
    }
}

#[cfg(test)]
mod tests {
    //! Truth table for [`decide`] across all 4 policies × both dest_exists
    //! values. The pure table is decisive either way (the policies encode the
    //! user's intent regardless of whether this one path clashes); the table
    //! pins that so a future caller cannot drift the behavior.
    use super::*;

    #[test]
    fn overwrite_with_existing_dest_overwrites() {
        assert_eq!(
            decide(OverwritePolicy::Overwrite, true),
            OverwriteChoice::Overwrite
        );
    }

    #[test]
    fn overwrite_without_existing_dest_still_overwrites() {
        // No conflict → still "go": the single-shot Overwrite policy is set
        // right before re-issuing the transfer, so it always means overwrite.
        assert_eq!(
            decide(OverwritePolicy::Overwrite, false),
            OverwriteChoice::Overwrite
        );
    }

    #[test]
    fn skip_with_existing_dest_skips() {
        assert_eq!(decide(OverwritePolicy::Skip, true), OverwriteChoice::Skip);
    }

    #[test]
    fn skip_without_existing_dest_skips() {
        // Skipping a non-existent destination is a no-op transfer (nothing to
        // skip) — the table is still `Skip` because the policy is decisive.
        assert_eq!(decide(OverwritePolicy::Skip, false), OverwriteChoice::Skip);
    }

    #[test]
    fn overwrite_all_with_existing_dest_overwrites() {
        assert_eq!(
            decide(OverwritePolicy::OverwriteAll, true),
            OverwriteChoice::Overwrite
        );
    }

    #[test]
    fn overwrite_all_without_existing_dest_still_overwrites() {
        // "Overwrite all" applies even when there is no conflict — the user
        // asked for all, so a no-conflict file is still copied.
        assert_eq!(
            decide(OverwritePolicy::OverwriteAll, false),
            OverwriteChoice::Overwrite
        );
    }

    #[test]
    fn skip_all_with_existing_dest_skips() {
        assert_eq!(
            decide(OverwritePolicy::SkipAll, true),
            OverwriteChoice::Skip
        );
    }

    #[test]
    fn skip_all_without_existing_dest_skips() {
        assert_eq!(
            decide(OverwritePolicy::SkipAll, false),
            OverwriteChoice::Skip
        );
    }

    #[test]
    fn decide_never_returns_cancel() {
        // Pin the contract: `decide` is the pure batch-policy table; only the
        // popup's Esc handler emits Cancel.
        for policy in [
            OverwritePolicy::Overwrite,
            OverwritePolicy::Skip,
            OverwritePolicy::OverwriteAll,
            OverwritePolicy::SkipAll,
        ] {
            for dest_exists in [false, true] {
                assert_ne!(
                    decide(policy, dest_exists),
                    OverwriteChoice::Cancel,
                    "decide({policy:?}, {dest_exists}) must not be Cancel"
                );
            }
        }
    }
}
