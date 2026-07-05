//! SFTP-over-ControlMaster argv builders.
//!
//! SFTP transfer reuses the system `ssh` + `sftp` binaries over a single
//! shared [`ControlMaster`] connection — no SSH protocol reimplementation
//! (sshrack never sits in the data stream). This module assembles the argv for
//! the three processes that cooperate:
//!
//! 1. **Master** (`[`argv::master_argv`]`) — `ssh -N` with `ControlMaster=yes`
//!    plus the same connection options (`-l/-p/-i`) as an interactive `ssh`,
//!    holding the muxed connection open in the background.
//! 2. **sftp client** (`[`argv::sftp_batch_argv`]`) — `sftp -b -` mounting the
//!    master via `ControlPath` only. It carries NO `-P/-i/-J`: the master
//!    already negotiated port and identity, and this sidesteps the ssh `-p` vs
//!    sftp `-P` flag clash.
//! 3. **Control messages** (`[`argv::control_check_argv`]` / `[`argv::control_exit_argv`]`)
//!    — `ssh -O check|exit` for readiness poll and teardown.
//!
//! The control socket lives under `$XDG_RUNTIME_DIR` (falling back to the std
//! temp dir), never `/tmp`, and is unique per process/session via a pid + an
//! in-process counter so concurrent sshrack sftp sessions never collide.
//!
//! [`ControlMaster`]: https://www.openssh.com/cgi-bin/man.cgi?q=ssh_config#ControlMaster

pub mod argv;
pub use argv::{
    control_check_argv, control_exit_argv, control_socket_path, master_argv, runtime_dir,
    sftp_batch_argv, sftp_target, shell_quote,
};

pub mod parse;
pub use parse::{RawLsEntry, parse_ls_line, parse_ls_listing, strip_control_chars, to_dir_entries};
