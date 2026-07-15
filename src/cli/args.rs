//! Command-line surface: clap structs for the sshrack CLI.
//!
//! sshrack never sits in the ssh data stream. It resolves a host, optionally
//! stages a password for ssh's SSH_ASKPASS hook, spawns ssh (or scp) with
//! inherited stdio, and waits. Argument parsing is fully delegated to clap.
//!
//! The top level has these groups:
//! - `ssh` — explicit connect: `sshrack ssh <name> [command...]`.
//! - `scp` — file transfer with `name:path` expansion.
//! - `host` — resource group for `add`/`ls`/`show`/`edit`/`rm`/`cp`.
//! - `cred` — resource group for managing reusable credentials.
//! - `store` — password storage-mode management
//!   (`use`/`status`/`rekey`/`lock`/`unlock`/`config`); see [`Command::Store`].
//!
//! The `<name>` shorthand (`sshrack <name> [command...]`) is an equivalent of
//! `sshrack ssh <name>`: clap's `external_subcommand` collects the name plus
//! the verbatim remote command in [`Command::Connect`], so flags after the
//! name reach ssh, not sshrack (the pass-through contract). A bare `sshrack`
//! (no subcommand) prints help — there is no TUI in this phase.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Per-connection `user`/`port`/`identity` for the `ssh`/`scp`/`<name>`
/// routes. Flattened into the top-level [`Cli`] (for the `sshrack <name>`
/// shorthand) and into the `ssh`/`scp` subcommands, so the flags surface only
/// where a connection actually happens; each overlays the resolved config for
/// that one connection. A value given after the subcommand token overlays one
/// given at the top level.
#[derive(Debug, Clone, Default, Args)]
pub struct ConnectOptions {
    /// Login user for this connection only (overlays the resolved config user).
    #[arg(short = 'l', long = "user")]
    pub user: Option<String>,

    /// Port for this connection only (overlays the resolved config port).
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    /// Identity file for this connection only (overlays the resolved config key).
    #[arg(short = 'i', long = "identity")]
    pub identity: Option<PathBuf>,

    /// Reuse a `[[credentials]]` entry for this connection only (overlays the
    /// resolved auth). For an ad-hoc target this is the identity source.
    /// Resolved from name to id by the CLI layer, not by clap.
    #[arg(short = 'c', long = "credential")]
    pub credential: Option<String>,

    /// Treat the target as a literal address, not a config name. The only way
    /// to reach an IP/host that is not a configured name.
    #[arg(long = "ad-hoc")]
    pub ad_hoc: bool,

    /// Accept a host key seen for the first time (like ssh's `accept-new`).
    /// Default refuses unknown keys. Changed keys are always rejected (ssh
    /// upstream handles that). The only non-interactive way to accept a new
    /// key.
    #[arg(long = "accept-new")]
    pub accept_new: bool,
}

impl ConnectOptions {
    /// Overlay `self` on `base`: a field set here wins; otherwise fall back to
    /// `base`. Merges top-level flags with those given after the `ssh`/`scp`
    /// token, so `sshrack --port 9 ssh web1` and `sshrack ssh --port 9 web1`
    /// behave the same.
    pub fn overlay(self, base: &ConnectOptions) -> ConnectOptions {
        ConnectOptions {
            user: self.user.or_else(|| base.user.clone()),
            port: self.port.or(base.port),
            identity: self.identity.or_else(|| base.identity.clone()),
            credential: self.credential.or_else(|| base.credential.clone()),
            // Either level opting into ad-hoc / accept-new is enough (OR).
            ad_hoc: self.ad_hoc || base.ad_hoc,
            accept_new: self.accept_new || base.accept_new,
        }
    }
}

/// Output format for machine-readable command results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable aligned text (default).
    Text,
    /// Structured JSON for scripting and automation.
    Json,
}

/// Sort order for `host ls`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SortMode {
    /// Sort by frecency (frequency + recency of use).
    Frecency,
    /// Sort alphabetically by name.
    Name,
    /// Sort by most recently used.
    Recent,
}

/// sshrack — terminal-native remote server management.
#[derive(Debug, Parser)]
#[command(name = "sshrack", version, about)]
pub struct Cli {
    /// Path to the config file (default: ~/.config/sshrack/config.toml).
    #[arg(long, global = true, display_order = 100)]
    pub config: Option<PathBuf>,

    /// Verbose output (never prints passwords).
    /// Parsed for future use; Phase 1 tracing is driven by RUST_LOG.
    #[arg(short, long, global = true, display_order = 100)]
    pub verbose: bool,

    /// Output format for list/show commands.
    #[arg(
        long = "format",
        global = true,
        display_order = 101,
        default_value = "text",
        value_enum
    )]
    pub format: OutputFormat,

    /// Per-connection `user`/`port`/`identity` for the `ssh`/`scp`/`<name>`
    /// routes. Flattened here so `sshrack --port <name>` (and `--user`/
    /// `--identity`) work; consulted only on the connect arms.
    #[command(flatten)]
    pub connect_opts: ConnectOptions,

    /// Subcommand selects the action. An unknown first token (e.g. a host
    /// name) falls through to [`Command::Connect`] via `external_subcommand`.
    /// Omitting it prints help.
    #[command(subcommand)]
    pub cmd: Option<Command>,
}

/// The action selected by the first positional token.
///
/// `Ssh`/`Scp` are operations; `Host`/`Cred`/`Store` are resource groups (each
/// with its own sub-action). The catch-all [`Command::Connect`] handles
/// `sshrack <name> [remote command...]` — the shorthand for `ssh`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Connect to a host: `sshrack ssh <name> [command...]`. Everything after
    /// the name reaches `ssh` verbatim (flags after the name are not sshrack
    /// flags). Equivalent to the `sshrack <name>` shorthand.
    Ssh {
        /// Per-connection flags given after the `ssh` token (overlay the
        /// top-level ones); must precede the name.
        #[command(flatten)]
        opts: ConnectOptions,
        /// `<name> [remote command...]` — the host name followed by any
        /// command handed to ssh verbatim. Flags after the name are not
        /// sshrack flags.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// File transfer with `name:path` expansion. All scp flags pass through
    /// verbatim; sshrack only rewrites `name:` operands and injects the
    /// matched host's port/identity.
    Scp {
        /// Per-connection flags given after the `scp` token (overlay the
        /// top-level ones); must precede the first operand.
        #[command(flatten)]
        opts: ConnectOptions,
        /// scp operands and flags. Remotes use `name:path`; sshrack rewrites
        /// known names and passes `user@host:path` through verbatim. An
        /// unknown `name:path` is rejected — use `--ad-hoc` or
        /// `user@host:path` for a host that is not a registered name.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Interactive SFTP transfer screen: `sshrack sftp <name>`. Opens the
    /// dual-pane view (system `sftp` over ControlMaster). Non-interactive
    /// transfer remains `sshrack scp`.
    Sftp {
        /// Per-connection flags given after the `sftp` token (overlay the
        /// top-level ones); must precede the name.
        #[command(flatten)]
        opts: ConnectOptions,
        /// Host name to open the transfer screen for (required).
        name: String,
    },

    /// Manage configured hosts (`add`/`ls`/`show`/`edit`/`rm`/`cp`).
    Host {
        #[command(subcommand)]
        action: HostAction,
    },

    /// Manage reusable credentials (user + password/key) referenced by hosts.
    Cred {
        #[command(subcommand)]
        action: CredAction,
    },

    /// Manage password storage mode (`use`/`status`/`rekey`/`lock`/`unlock`/`config`).
    Store {
        #[command(subcommand)]
        action: StoreAction,
    },

    /// Catch-all: `sshrack <name> [command...]` — the shorthand for `ssh`.
    /// clap's `external_subcommand` collects the name plus the verbatim
    /// remote command, so flags after the name reach ssh, not sshrack.
    #[command(external_subcommand)]
    Connect(
        /// `<name> [remote command...]`.
        Vec<String>,
    ),
}

/// Sub-actions of `sshrack host …`.
#[derive(Debug, Subcommand)]
pub enum HostAction {
    /// Add a host. All required fields must come from flags (missing `--host`
    /// errors); the interactive wizard lives in the TUI.
    ///
    /// Two auth modes: **Reference** (`--credential <name>`, reusing a
    /// `[[credentials]]` entry) or **Independent** (`--user`/`--identity`,
    /// self-contained). With no auth flag the host is Independent with the
    /// default user `root`. A password cannot be set here — passwords never
    /// enter argv; use the TUI for a password host.
    ///
    /// Identity sources (Independent only, mutually exclusive): `--identity
    /// <path>` keeps the key on disk and stores the path; `--identity-stdin`
    /// / `--identity-file <path>` read the key **contents** into the config
    /// (sealed per the store mode) so the file can be deleted afterward. An
    /// optional `--certificate-stdin` / `--certificate-file <path>` pairs with
    /// an inline identity (a path identity auto-loads its `-cert.pub` sibling).
    /// Key contents never enter argv.
    Add {
        /// Host name to add (or overwrite when --force is set). Required.
        name: Option<String>,
        /// Remote hostname or IP. Required.
        #[arg(long)]
        host: Option<String>,
        /// Login user for independent auth (defaults to `root` when no auth
        /// flag is given). Ignored when `--credential` is set.
        #[arg(long)]
        user: Option<String>,
        /// SSH port (defaults to `22`).
        #[arg(long)]
        port: Option<u16>,
        /// Path to a private key for independent auth. Ignored when
        /// `--credential` is set.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Read the private key **contents** from stdin (mutually exclusive
        /// with `--identity` / `--identity-file`). The contents are stored
        /// inline (encrypted under vault, or plaintext) — never passed on argv.
        #[arg(long, conflicts_with_all = ["identity", "identity_file"])]
        identity_stdin: bool,
        /// Read the private key **contents** from this file (mutually exclusive
        /// with `--identity` / `--identity-stdin`). The file is read once at
        /// add time; its contents are stored inline, so the file may be deleted
        /// afterward.
        #[arg(long, conflicts_with_all = ["identity", "identity_stdin"])]
        identity_file: Option<PathBuf>,
        /// Read an SSH **certificate** from stdin (optional; requires
        /// `--identity-file`, NOT `--identity-stdin` — the private key and
        /// certificate cannot share one stdin stream). Ignored when the
        /// identity is a path reference.
        #[arg(long, conflicts_with_all = ["certificate_file", "identity_stdin", "identity"])]
        certificate_stdin: bool,
        /// Read an SSH **certificate** from this file (optional; pairs with
        /// `--identity-stdin` / `--identity-file`).
        #[arg(long, conflicts_with_all = ["certificate_stdin", "identity"])]
        certificate_file: Option<PathBuf>,
        /// Reference a [[credentials]] entry by name (Reference mode, mutually
        /// exclusive with the independent flags `--user`/`--identity` and the
        /// inline-import flags `--identity-stdin`/`--identity-file`).
        /// Resolved from name to id by the CLI layer, not by clap.
        #[arg(long, conflicts_with_all = ["identity_stdin", "identity_file"])]
        credential: Option<String>,
        /// Overwrite an existing name.
        #[arg(long)]
        force: bool,
    },

    /// List all configured hosts as an aligned table. `--fields` selects a
    /// comma-separated column subset (e.g. `name,host`); omit for all columns.
    /// `--sort` selects the ordering (default: config order).
    Ls {
        /// Comma-separated column subset (e.g. `name,host`); omit for all.
        #[arg(long)]
        fields: Option<String>,
        /// Sort order: `frecency` | `name` | `recent`.
        #[arg(long, value_enum)]
        sort: Option<SortMode>,
    },

    /// Print a single host's details. `--reveal` prints the stored password in
    /// plaintext (decrypts it in encrypted mode); default masks it.
    Show {
        /// Host name to show.
        name: String,
        /// Print the stored password in plaintext.
        #[arg(long)]
        reveal: bool,
    },

    /// Edit an existing host's fields. Patch-only: only flagged fields change.
    /// With no flags, prints "no changes". The full edit wizard lives in the TUI.
    ///
    /// Auth-mode switches: `--credential <name>` switches to **Reference** mode;
    /// `--clear-credential` drops a reference and reverts to **Independent**
    /// auth (default user `root`). `--user`/`--identity` only patch an existing
    /// Independent host (a Reference host is left untouched by them).
    Edit {
        /// Host name to edit. Required.
        name: Option<String>,
        /// New remote hostname or IP.
        #[arg(long)]
        host: Option<String>,
        /// New login user (Independent hosts only; ignored on a Reference host).
        #[arg(long)]
        user: Option<String>,
        /// New SSH port.
        #[arg(long)]
        port: Option<u16>,
        /// New identity file path (Independent hosts only).
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Read the new private key **contents** from stdin (Independent hosts
        /// only; mutually exclusive with `--identity` / `--identity-file`).
        /// The contents are stored inline (encrypted under vault, or
        /// plaintext) — never passed on argv.
        #[arg(long, conflicts_with_all = ["identity", "identity_file"])]
        identity_stdin: bool,
        /// Read the new private key **contents** from this file (Independent
        /// hosts only; mutually exclusive with `--identity` /
        /// `--identity-stdin`). The file is read once at edit time; its
        /// contents are stored inline, so the file may be deleted afterward.
        #[arg(long, conflicts_with_all = ["identity", "identity_stdin"])]
        identity_file: Option<PathBuf>,
        /// Read an SSH **certificate** from stdin (optional; requires
        /// `--identity-file`, NOT `--identity-stdin` — the private key and
        /// certificate cannot share one stdin stream).
        #[arg(long, conflicts_with_all = ["certificate_file", "identity_stdin", "identity"])]
        certificate_stdin: bool,
        /// Read an SSH **certificate** from this file (optional; pairs with
        /// `--identity-stdin` / `--identity-file`).
        #[arg(long, conflicts_with_all = ["certificate_stdin", "identity"])]
        certificate_file: Option<PathBuf>,
        /// Rename the host to this new name.
        #[arg(long)]
        rename: Option<String>,
        /// Switch to Reference auth, pointing at this [[credentials]] entry by
        /// name (sets `Auth::Ref`). Mutually exclusive with --clear-credential
        /// and the inline-import flags `--identity-stdin`/`--identity-file`.
        #[arg(long, conflicts_with_all = ["clear_credential", "identity_stdin", "identity_file"])]
        credential: Option<String>,
        /// Remove the identity file (set key_path to none).
        #[arg(long, conflicts_with = "identity")]
        clear_identity: bool,
        /// Remove the stored password.
        #[arg(long)]
        clear_password: bool,
        /// Drop the credential reference, reverting to Independent auth (user
        /// defaults to `root`, or the value of `--user` if given).
        #[arg(long)]
        clear_credential: bool,
    },

    /// Remove a host from the config. Requires `--yes` (the destructive
    /// confirmation). Interactive confirmation lives in the TUI.
    Rm {
        /// Host name to remove. Required.
        name: Option<String>,
        /// Required: confirm the destructive removal.
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Copy a host's config to a new name. Both `<src>` and `<dst>` are
    /// required. The destination must be globally unique (no overwrite).
    /// The interactive source picker lives in the TUI.
    Cp {
        /// Source host name. Required.
        src: Option<String>,
        /// Destination name. Required.
        dst: Option<String>,
    },
}

/// Subcommands of `sshrack cred …`.
#[derive(Debug, Subcommand)]
pub enum CredAction {
    /// Add a reusable credential. `--user` (and the name) are required; a
    /// password credential cannot be created from the CLI (passwords never
    /// enter argv) — use the TUI for that.
    ///
    /// Identity sources (mutually exclusive): `--identity <path>` keeps the
    /// key on disk and stores the path; `--identity-stdin` / `--identity-file
    /// <path>` read the key **contents** into the config (sealed per the store
    /// mode) so the file can be deleted afterward. An optional
    /// `--certificate-stdin` / `--certificate-file <path>` pairs with an inline
    /// identity. Key contents never enter argv.
    Add {
        /// Credential name to add (or overwrite when --force is set). Required.
        name: Option<String>,
        /// Login user. Required.
        #[arg(long)]
        user: Option<String>,
        /// Path to a private key file.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Read the private key **contents** from stdin (mutually exclusive
        /// with `--identity` / `--identity-file`). The contents are stored
        /// inline (encrypted under vault, or plaintext) — never passed on argv.
        #[arg(long, conflicts_with_all = ["identity", "identity_file"])]
        identity_stdin: bool,
        /// Read the private key **contents** from this file (mutually exclusive
        /// with `--identity` / `--identity-stdin`). The file is read once at
        /// add time; its contents are stored inline, so the file may be deleted
        /// afterward.
        #[arg(long, conflicts_with_all = ["identity", "identity_stdin"])]
        identity_file: Option<PathBuf>,
        /// Read an SSH **certificate** from stdin (optional; requires
        /// `--identity-file`, NOT `--identity-stdin` — the private key and
        /// certificate cannot share one stdin stream).
        #[arg(long, conflicts_with_all = ["certificate_file", "identity_stdin", "identity"])]
        certificate_stdin: bool,
        /// Read an SSH **certificate** from this file (optional; pairs with
        /// `--identity-stdin` / `--identity-file`).
        #[arg(long, conflicts_with_all = ["certificate_stdin", "identity"])]
        certificate_file: Option<PathBuf>,
        /// Overwrite an existing credential name.
        #[arg(long)]
        force: bool,
    },
    /// Edit an existing credential. Patch-only: only flagged fields change.
    /// With no flags, prints "no changes". The full edit wizard lives in the TUI.
    Edit {
        /// Credential name to edit. Required.
        name: Option<String>,
        /// New login user.
        #[arg(long)]
        user: Option<String>,
        /// New identity file path.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Read the new private key **contents** from stdin (mutually exclusive
        /// with `--identity` / `--identity-file`). The contents are stored
        /// inline (encrypted under vault, or plaintext) — never passed on argv.
        #[arg(long, conflicts_with_all = ["identity", "identity_file"])]
        identity_stdin: bool,
        /// Read the new private key **contents** from this file (mutually
        /// exclusive with `--identity` / `--identity-stdin`). The file is read
        /// once at edit time; its contents are stored inline, so the file may
        /// be deleted afterward.
        #[arg(long, conflicts_with_all = ["identity", "identity_stdin"])]
        identity_file: Option<PathBuf>,
        /// Read an SSH **certificate** from stdin (optional; requires
        /// `--identity-file`, NOT `--identity-stdin` — the private key and
        /// certificate cannot share one stdin stream).
        #[arg(long, conflicts_with_all = ["certificate_file", "identity_stdin", "identity"])]
        certificate_stdin: bool,
        /// Read an SSH **certificate** from this file (optional; pairs with
        /// `--identity-stdin` / `--identity-file`).
        #[arg(long, conflicts_with_all = ["certificate_stdin", "identity"])]
        certificate_file: Option<PathBuf>,
        /// Remove the identity file.
        #[arg(long, conflicts_with = "identity")]
        clear_identity: bool,
        /// Rename the credential to this new name.
        #[arg(long)]
        rename: Option<String>,
    },
    /// Remove a credential. Requires `--yes`. Interactive confirmation lives in
    /// the TUI.
    Rm {
        /// Credential name to remove. Required.
        name: Option<String>,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// List all credentials (password masked). `--fields` selects a
    /// comma-separated column subset (e.g. `name,user`); omit for all columns.
    Ls {
        #[arg(long)]
        fields: Option<String>,
    },
    /// Print one credential's details. `--reveal` prints the stored password
    /// in plaintext (decrypts it in encrypted mode); default masks it.
    Show {
        /// Credential name to show.
        name: String,
        /// Print the stored password in plaintext.
        #[arg(long)]
        reveal: bool,
    },
}

/// Sub-actions of `sshrack store config …` (read/write non-secret vault runtime config).
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Show every tunable vault config value.
    Show,
    /// Print a single config value.
    Get {
        /// Field name (kebab-case), e.g. `cache-ttl-secs`.
        field: String,
    },
    /// Set a single config value.
    Set {
        /// Field name (kebab-case), e.g. `cache-ttl-secs`.
        field: String,
        /// The new value.
        value: String,
    },
}

/// A password storage mode selectable by `sshrack store use <mode>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StoreMode {
    /// Store passwords as plaintext in `config.toml` (least secure).
    Plaintext,
    /// Encrypt passwords inline with a master passphrase.
    Vault,
    /// Store passwords in the OS keyring (recommended).
    Keyring,
}

/// Subcommands for `sshrack store …` (password storage-mode management).
#[derive(Debug, Subcommand)]
pub enum StoreAction {
    /// Show the active storage mode and password counts.
    Status,
    /// Switch storage mode and migrate all passwords: `plaintext` | `vault` | `keyring`.
    Use {
        /// Target mode.
        #[arg(value_enum)]
        mode: StoreMode,
        /// Initial master-key cache TTL in seconds (vault mode only). `0`
        /// disables caching; defaults to 30 minutes when omitted.
        #[arg(long)]
        cache_ttl_secs: Option<u64>,
        /// Skip the confirmation prompt (plaintext mode only).
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Change the master passphrase; re-encrypts all passwords (vault mode only).
    Rekey,
    /// Drop the cached master key so the next connect re-prompts (vault mode only).
    Lock,
    /// Resolve and cache the master key ahead of a non-interactive session
    /// (vault mode only).
    Unlock,
    /// Read or write non-secret vault runtime config (e.g. cache TTL).
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

#[cfg(test)]
mod tests {
    //! Argument-parsing contracts that the CLI relies on for correctness. These
    //! pin clap-level invariants the handlers assume; the handlers themselves
    //! never re-check them.

    use super::*;
    use clap::error::ErrorKind;

    // `--identity-stdin --certificate-stdin` would read the same stdin handle
    // twice: the first read consumes the whole stream into the private key; the
    // second hits EOF and yields an empty certificate — silently corrupting the
    // key. clap rejects the combo at parse time on all four surfaces so the
    // user gets a clear conflict error instead. A certificate via stdin must
    // pair with `--identity-file <path>` (a separate stream for the key).

    #[test]
    fn cred_add_rejects_identity_stdin_with_certificate_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "cred",
            "add",
            "--user",
            "u",
            "--identity-stdin",
            "--certificate-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn cred_edit_rejects_identity_stdin_with_certificate_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "cred",
            "edit",
            "somename",
            "--identity-stdin",
            "--certificate-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn host_add_rejects_identity_stdin_with_certificate_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "host",
            "add",
            "--host",
            "h",
            "--identity-stdin",
            "--certificate-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn host_edit_rejects_identity_stdin_with_certificate_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "host",
            "edit",
            "somename",
            "--identity-stdin",
            "--certificate-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    // M1: --certificate-stdin / --certificate-file are unreachable when the
    // identity source is `--identity <path>` (a path identity auto-loads its
    // own `-cert.pub` sibling). The cert flag would be silently swallowed.
    // clap now rejects the combo at parse time on all four surfaces.

    #[test]
    fn cred_add_rejects_identity_path_with_certificate_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "cred",
            "add",
            "--user",
            "u",
            "--identity",
            "/p",
            "--certificate-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn cred_add_rejects_identity_path_with_certificate_file() {
        let err = Cli::try_parse_from([
            "sshrack",
            "cred",
            "add",
            "--user",
            "u",
            "--identity",
            "/p",
            "--certificate-file",
            "/c",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn cred_edit_rejects_identity_path_with_certificate_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "cred",
            "edit",
            "somename",
            "--identity",
            "/p",
            "--certificate-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn host_add_rejects_identity_path_with_certificate_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "host",
            "add",
            "--host",
            "h",
            "--identity",
            "/p",
            "--certificate-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn host_edit_rejects_identity_path_with_certificate_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "host",
            "edit",
            "somename",
            "--identity",
            "/p",
            "--certificate-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    // `sshrack sftp <name>` parses to Command::Sftp with the host name. A bare
    // `sshrack sftp` is a clap usage error (name: String is non-optional).

    #[test]
    fn sftp_parses_name_positional() {
        let cli = Cli::try_parse_from(["sshrack", "sftp", "web1"]).unwrap();
        match cli.cmd {
            Some(Command::Sftp { name, .. }) => assert_eq!(name, "web1"),
            other => panic!("expected Command::Sftp, got {other:?}"),
        }
    }

    // M2: --credential is Reference auth; the inline-import flags
    // (--identity-stdin / --identity-file) rebuild an Inline body, so --credential
    // is silently ignored alongside them. clap now rejects the combo on host
    // add/edit.

    #[test]
    fn host_add_rejects_credential_with_identity_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "host",
            "add",
            "--host",
            "h",
            "--credential",
            "team",
            "--identity-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn host_add_rejects_credential_with_identity_file() {
        let err = Cli::try_parse_from([
            "sshrack",
            "host",
            "add",
            "--host",
            "h",
            "--credential",
            "team",
            "--identity-file",
            "/k",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn host_edit_rejects_credential_with_identity_stdin() {
        let err = Cli::try_parse_from([
            "sshrack",
            "host",
            "edit",
            "somename",
            "--credential",
            "team",
            "--identity-stdin",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn host_edit_rejects_credential_with_identity_file() {
        let err = Cli::try_parse_from([
            "sshrack",
            "host",
            "edit",
            "somename",
            "--credential",
            "team",
            "--identity-file",
            "/k",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    // ---- ConnectOptions::overlay: top-level flags merge with subcommand ones ----
    //
    // `overlay` merges two ConnectOptions layers (the flattened top-level one
    // and the per-subcommand one) so `sshrack --port 9 ssh web1` and
    // `sshrack ssh --port 9 web1` behave the same. For user/port/identity/
    // credential the subcommand (self) value wins when set and falls back to
    // the top-level (base) otherwise; ad_hoc and accept_new are OR (either
    // level opting in is enough).

    #[test]
    fn overlay_self_set_field_wins_over_base() {
        // Every option field set on both layers → self wins per field.
        let base = ConnectOptions {
            user: Some("base-user".into()),
            port: Some(22),
            identity: Some(PathBuf::from("/base/key")),
            credential: Some("base-cred".into()),
            ad_hoc: false,
            accept_new: false,
        };
        let inner = ConnectOptions {
            user: Some("inner-user".into()),
            port: Some(2222),
            identity: Some(PathBuf::from("/inner/key")),
            credential: Some("inner-cred".into()),
            ad_hoc: false,
            accept_new: false,
        };
        let out = inner.overlay(&base);
        assert_eq!(out.user.as_deref(), Some("inner-user"));
        assert_eq!(out.port, Some(2222));
        assert_eq!(
            out.identity.as_deref(),
            Some(std::path::Path::new("/inner/key"))
        );
        assert_eq!(out.credential.as_deref(), Some("inner-cred"));
    }

    #[test]
    fn overlay_self_unset_field_inherits_base() {
        // self (subcommand) omits every option → base (top-level) is inherited.
        let base = ConnectOptions {
            user: Some("base-user".into()),
            port: Some(22),
            identity: Some(PathBuf::from("/base/key")),
            credential: Some("base-cred".into()),
            ad_hoc: false,
            accept_new: false,
        };
        let out = ConnectOptions::default().overlay(&base);
        assert_eq!(out.user.as_deref(), Some("base-user"));
        assert_eq!(out.port, Some(22));
        assert_eq!(
            out.identity.as_deref(),
            Some(std::path::Path::new("/base/key"))
        );
        assert_eq!(out.credential.as_deref(), Some("base-cred"));
    }

    #[test]
    fn overlay_subcommand_port_overrides_top_level() {
        // The documented motivation: a subcommand `--port` overrides a
        // top-level `--port` (self wins).
        let base = ConnectOptions {
            port: Some(22),
            ..ConnectOptions::default()
        };
        let inner = ConnectOptions {
            port: Some(2222),
            ..ConnectOptions::default()
        };
        assert_eq!(inner.overlay(&base).port, Some(2222));
    }

    #[test]
    fn overlay_accept_new_ors_top_level_with_subcommand() {
        // accept_new is OR: top-level --accept-new propagates when the
        // subcommand omits it; a subcommand flag also turns it on; neither
        // leaves it off.
        let top_level_only = ConnectOptions {
            accept_new: true,
            ..ConnectOptions::default()
        };
        assert!(
            ConnectOptions::default()
                .overlay(&top_level_only)
                .accept_new,
            "top-level accept_new must propagate to an omitting subcommand"
        );

        let subcommand_only = ConnectOptions {
            accept_new: true,
            ..ConnectOptions::default()
        };
        assert!(
            subcommand_only
                .overlay(&ConnectOptions::default())
                .accept_new,
            "subcommand accept_new must win through"
        );

        assert!(
            !ConnectOptions::default()
                .overlay(&ConnectOptions::default())
                .accept_new,
            "neither level opting in → false"
        );
    }

    #[test]
    fn overlay_ad_hoc_ors_across_levels() {
        // ad_hoc is OR across both layers, mirroring accept_new.
        let base_on = ConnectOptions {
            ad_hoc: true,
            ..ConnectOptions::default()
        };
        assert!(
            ConnectOptions::default().overlay(&base_on).ad_hoc,
            "base-only ad_hoc true → true"
        );

        let self_on = ConnectOptions {
            ad_hoc: true,
            ..ConnectOptions::default()
        };
        assert!(
            self_on.overlay(&ConnectOptions::default()).ad_hoc,
            "self-only ad_hoc true → true"
        );

        assert!(
            !ConnectOptions::default()
                .overlay(&ConnectOptions::default())
                .ad_hoc,
            "both false → false"
        );
    }
}
