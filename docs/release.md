# Version Release Runbook

Used only when cutting a release; split out of `AGENTS.md` for length. When
asked to release without a specific version, auto-increment PATCH
(e.g. `0.1.0` → `0.1.1`).

Publishing is **automatic**: pushing a `v*` tag triggers the `publish` job in
`.github/workflows/ci.yml`, which runs `cargo publish` on a GitHub runner
(reaching crates.io directly). **Do not `cargo publish` locally** — the CN
cargo mirror (aliyun) lags behind crates.io, so a just-published
`sshrack-core` is not resolvable yet and the binary publish stalls; the runner
has no such problem. The job ships `sshrack-core` first, then `sshrack` (it
tolerates "already exists" on core, so re-running a tag is safe).

## Steps

```bash
# 1. Update version in Cargo.toml (workspace.package.version)
vim Cargo.toml

# 2. Sync Cargo.lock
cargo check

# 3. Generate CHANGELOG (overwrites full file)
git cliff --tag v0.1.1 > CHANGELOG.md

# 4. Commit version bump
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): prepare for v0.1.1"

# 5. Create annotated tag
changelog=$(git cliff --unreleased --strip all)
git tag -a v0.1.1 -m "Release v0.1.1" -m "$changelog"

# 6. Push the tag — the publish job auto-publishes both crates to crates.io.
git push origin v0.1.1
```

## Notes

- `git cliff --tag <version> > CHANGELOG.md`: full CHANGELOG, overwrite.
- `git cliff --unreleased --strip all`: concise summary for the tag message.
- Tag format: `v<semver>` with `git tag -a` (annotated).
- `chore(release):` commits are excluded from CHANGELOG via cliff.toml skip rules.
- The `publish` job (`needs: check`, `if: refs/tags/v*`) runs only on a tag
  push, after `check` (fmt/clippy/test) is green. PRs and plain `main` pushes
  run `check` only.
- `CRATES_IO_TOKEN` repo secret (Settings → Secrets → Actions) →
  `CARGO_REGISTRY_TOKEN` env in the job. If publish fails with
  unauthorized/forbidden, the secret is missing or the token lacks the
  `publish-new` scope.
