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

**Banned** for this project: SSH protocol libraries (`russh`, `ssh2`, `russh-sftp`), `age`, `ssh2-config` (keeps MSRV at 1.86 and the surface small).

## Rust Skills

Use Rust Skills for development guidance. Route via meta-cognition:

**Layer 1** (language mechanics): `m01-ownership`, `m02-resource`, `m03-mutability`, `m04-zero-cost`, `m05-type-driven`, `m06-error-handling`, `m07-concurrency`, `m10-performance`, `m11-ecosystem`, `m15-anti-pattern`.

**Layer 3** (domain constraints): `domain-cli` (primary — this is a CLI tool).
