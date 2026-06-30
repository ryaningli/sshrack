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
            // Either level opting into ad-hoc is enough (OR, not override).
            ad_hoc: self.ad_hoc || base.ad_hoc,
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

    /// Non-interactive: never prompt. Required fields must come from flags.
    #[arg(long, global = true, display_order = 101)]
    pub no_input: bool,

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
    /// Add a host (interactive by default; --no-input for scripts).
    Add {
        /// Host name to add (or overwrite when --force is set). Omit for
        /// interactive mode (you'll be prompted for a fresh name).
        name: Option<String>,
        /// Remote hostname or IP.
        #[arg(long)]
        host: Option<String>,
        /// Login user (defaults to `root`).
        #[arg(long)]
        user: Option<String>,
        /// SSH port (defaults to `22`).
        #[arg(long)]
        port: Option<u16>,
        /// Path to a private key file.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Reference a [[credentials]] entry by name instead of inline user/key.
        /// Resolved from name to id by the CLI layer, not by clap.
        #[arg(long)]
        credential: Option<String>,
        /// Non-interactive: all required fields must come from flags (a
        /// password host cannot be created in this mode).
        #[arg(long = "no-input")]
        no_input: bool,
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

    /// Edit an existing host's fields (patch via flags; interactive pre-fill
    /// when no flags are given).
    Edit {
        /// Host name to edit. Omit for interactive mode (pick from a menu).
        name: Option<String>,
        /// New remote hostname or IP.
        #[arg(long)]
        host: Option<String>,
        /// New login user.
        #[arg(long)]
        user: Option<String>,
        /// New SSH port.
        #[arg(long)]
        port: Option<u16>,
        /// New identity file path.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Rename the host to this new name.
        #[arg(long)]
        rename: Option<String>,
        /// Switch auth to a credential reference (sets `Auth::Ref`). Mutually
        /// exclusive with --clear-credential.
        #[arg(long, conflicts_with = "clear_credential")]
        credential: Option<String>,
        /// Remove the identity file (set key_path to none).
        #[arg(long, conflicts_with = "identity")]
        clear_identity: bool,
        /// Remove the stored password.
        #[arg(long)]
        clear_password: bool,
        /// Drop any credential reference, falling back to inline default user.
        #[arg(long)]
        clear_credential: bool,
        /// Non-interactive: only apply flags; never prompt.
        #[arg(long = "no-input")]
        no_input: bool,
    },

    /// Remove a host from the config (prompts unless --yes).
    Rm {
        /// Host name to remove. Omit for interactive mode (pick from a menu).
        name: Option<String>,
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Copy a host's config to a new name. Two args = non-interactive copy;
    /// no args = pick the source from a menu and type the new name. The
    /// destination must be globally unique (no overwrite).
    Cp {
        /// Source host name (omit both for interactive mode).
        src: Option<String>,
        /// Destination name (omit both for interactive mode).
        dst: Option<String>,
    },
}

/// Subcommands of `sshrack cred …`.
#[derive(Debug, Subcommand)]
pub enum CredAction {
    /// Add a reusable credential (interactive by default; --no-input for scripts).
    Add {
        /// Credential name to add (or overwrite when --force is set). Omit
        /// for interactive mode (you'll be prompted for a fresh name).
        name: Option<String>,
        /// Login user (required in --no-input mode).
        #[arg(long)]
        user: Option<String>,
        /// Path to a private key file.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Non-interactive: fields must come from flags (a password credential
        /// cannot be created in this mode).
        #[arg(long = "no-input")]
        no_input: bool,
        /// Overwrite an existing credential name.
        #[arg(long)]
        force: bool,
    },
    /// Edit an existing credential (patch via flags; interactive when none given).
    Edit {
        /// Credential name to edit. Omit for interactive mode (pick from a menu).
        name: Option<String>,
        /// New login user.
        #[arg(long)]
        user: Option<String>,
        /// New identity file path.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Remove the identity file.
        #[arg(long, conflicts_with = "identity")]
        clear_identity: bool,
        /// Rename the credential to this new name.
        #[arg(long)]
        rename: Option<String>,
        /// Non-interactive: only apply flags; never prompt.
        #[arg(long = "no-input")]
        no_input: bool,
    },
    /// Remove a credential (prompts unless --yes).
    Rm {
        /// Credential name to remove. Omit for interactive mode (pick from a menu).
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
