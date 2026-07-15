# Migration from `sshrack-old`

Recorded for migration off the predecessor `sshrack-old`; this project is
pre-1.0 and carries no compat shim (per the dev-stage rule). Split out of
`CLAUDE.md` for length — consult this when porting an old setup.

- **Identifier rename `alias` → `name`.** JSON output keys `alias`→`name` and `credential_alias`→`credential_name`; TOML key `alias`→`name` in hosts and credentials. `--credential` accepts a name.
- **`--no-input` removed (still absent).** The CLI now defaults to interactive on a tty (host-key / passphrase / destructive confirms), with per-scenario escape hatches (`--accept-new`, `--yes`, `SSHRACK_PASSPHRASE`). There is no global non-interactive toggle. Missing required *config* flags still error directly.
- **`host rm` / `cred rm` require `--yes`.** Plain-text store downgrade (`store use plaintext`) also requires `--yes`.
- **`store use vault` / `store rekey` passphrase.** The passphrase comes from `SSHRACK_PASSPHRASE` when set, otherwise a tty prompt on the CLI; without either it errors `STORE`.
- **Workspace collapsed to one member crate.** `sshrack-cli` and `sshrack-tui` no longer exist as separate crates — their sources moved into the root `src/{cli,tui,shared}` of the single `sshrack` binary. Only `sshrack-core` remains as a workspace member.
