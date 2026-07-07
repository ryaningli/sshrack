# Dependency Policy & Rust Skills

Reference for adding/evaluating crates and the Rust-skill routing convention.
Split out of `CLAUDE.md` for length; the **Banned** list is duplicated in
`CLAUDE.md` because it is a hard, frequently-relevant constraint.

## Principles

- **Don't reinvent the wheel** — check crates.io before writing custom implementations.
- **Prefer established, actively maintained crates** — evaluate download counts, recent activity, issue responsiveness.
- **Minimize dependency count** — every crate is a maintenance burden.

## Adding Dependencies

Use `cargo add -p <crate>` instead of editing `Cargo.toml` directly.

```bash
cargo add serde -p sshrack-core --features derive
cargo add serde_json -p sshrack                # the root binary package
cargo add -D proptest                         # Dev dependency
```

## Evaluating a Crate

Clone to a temp directory and inspect: commit history, open issues, test coverage, MSRV, `unsafe` usage, transitive dependencies, documentation.

**Banned** for this project: SSH protocol libraries (`russh`, `ssh2`, `russh-sftp`), `age`, `ssh2-config` (keeps MSRV at 1.88 and the surface small).

## MSRV Policy

- **Current MSRV: 1.88** (set in `workspace.package.rust-version`, inherited by both packages).
- The MSRV tracks the minimum required by the primary UI dependency tree — the `ratatui` 0.30 ecosystem (`ratatui-core` / `ratatui-crossterm` / `ratatui-widgets`). Re-evaluate on each `ratatui` minor bump or at an annual review.
- `resolver = "3"` is MSRV-aware: `cargo install` and `cargo build` select the highest dependency version that still satisfies `rust-version`. Bumping the MSRV floats every dependency to its latest same-major patch (e.g. `ratatui` 0.30.0 → 0.30.2); it does **not** cross a major version, because `Cargo.toml` pins each direct dep by major version.
- Cross-major upgrades (`keyring` 3 → 4, `crossterm` 0.28 → 0.29, `chacha20poly1305` 0.10 → 0.11) are independent decisions evaluated on their own API/behavior merits — never bundled into an MSRV bump.
- The MSRV is a live, binding value. Historical mentions of an older MSRV in `docs/superpowers/plans/` and `docs/superpowers/specs/` are timestamped design records and are intentionally left as-is when the MSRV moves.

## Rust Skills

Use Rust Skills for development guidance. Route via meta-cognition:

**Layer 1** (language mechanics): `m01-ownership`, `m02-resource`, `m03-mutability`, `m04-zero-cost`, `m05-type-driven`, `m06-error-handling`, `m07-concurrency`, `m10-performance`, `m11-ecosystem`, `m15-anti-pattern`.

**Layer 3** (domain constraints): `domain-cli` (primary — this is a CLI tool).
