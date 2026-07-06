# Version Release Runbook

Used only when cutting a release; split out of `CLAUDE.md` for length. When
asked to release without a specific version, auto-increment PATCH
(e.g. `0.1.0` → `0.1.1`).

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
```

## Notes

- `git cliff --tag <version> > CHANGELOG.md`: full CHANGELOG, overwrite.
- `git cliff --unreleased --strip all`: concise summary for tag message.
- Tag format: `v<semver>` with `git tag -a` (annotated).
- `chore(release):` commits are excluded from CHANGELOG via cliff.toml skip rules.
