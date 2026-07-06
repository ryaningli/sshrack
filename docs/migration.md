# Migration from `sshrack-old`

Recorded for migration off the predecessor `sshrack-old`; this project is
pre-1.0 and carries no compat shim (per the dev-stage rule). Split out of
`CLAUDE.md` for length — consult this when porting an old setup.

- **Identifier rename `alias` → `name`.** JSON output keys `alias`→`name` and `credential_alias`→`credential_name`; TOML key `alias`→`name` in hosts and credentials. `--credential` accepts a name.
- **`--no-input` removed.** The CLI is non-interactive by construction; there is no flag to toggle. Missing required flags now error directly.
- **`host rm` / `cred rm` require `--yes`.** Plain-text store downgrade (`store use plaintext`) also requires `--yes`.
- **`store use vault` / `store rekey` are env-only on the CLI path.** The vault passphrase must come from `SSHRACK_PASSPHRASE`; there is no CLI passphrase prompt. Use the TUI for an interactive prompt.
- **Workspace collapsed to one member crate.** `sshrack-cli` and `sshrack-tui` no longer exist as separate crates — their sources moved into the root `src/{cli,tui,shared}` of the single `sshrack` binary. Only `sshrack-core` remains as a workspace member.
