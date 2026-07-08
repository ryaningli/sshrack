# Hermetic CI + Snapshot Coverage (Phase 0 + Phase A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a CI pipeline (so the whole suite runs on a standardized machine) and extend insta snapshot coverage from the help-dialog pilot to the shell chrome, the host launcher list, and the SFTP pane — every test hermetic (identical output on any machine).

**Architecture:** Two phases. **Phase 0** adds a GitHub Actions workflow running `cargo fmt --check` + `cargo clippy -D warnings` + `cargo test --workspace` on `ubuntu-latest`; the runner is the proof of hermeticity (green there ⇒ green anywhere). **Phase A** adds one snapshot test per surface, each using `ratatui::TestBackend` (in-memory render — no terminal/PTY), deterministic fixtures (fixed ULIDs, `Frecency::default()`, `modified: None`), and `insta::assert_snapshot!(term.backend())`. Dynamic content is handled by fixing the input, never by touching the real environment.

**Tech Stack:** Rust (edition 2024, MSRV 1.88), ratatui 0.30 `TestBackend`, `insta` 1.x (already a dev-dep from the pilot), GitHub Actions (checkout + dtolnay/rust-toolchain + Swatinem/rust-cache).

## Global Constraints

Copied verbatim from the project's binding requirements + this plan's hermeticity mandate. Every step implicitly obeys these:

- **Hermeticity (this plan's core mandate):** every test must produce identical output on any machine. No network, no `PATH`/`HOME` dependency, no real `ssh`/`sshd`, no real wall-clock time, no randomness inside a snapshot. Use `TestBackend` (in-memory render), fixed fixtures (fixed ULIDs via `Ulid::from_string`, `Frecency::default()`, `modified: None`), and `tempfile` for any on-disk config. The CI runner is the proof.
- **English only** — all source, comments, commit messages.
- **MSRV 1.88**, **edition 2024**, `resolver = "3"`.
- **Zero `unsafe`** anywhere (including tests).
- **Zero `unwrap()` / `expect()` in production code** — tests may use them.
- **`cargo clippy --workspace --all-targets -- -D warnings`** green before every commit.
- **`cargo fmt`** green before every commit (CI uses `cargo fmt --all -- --check`).
- **Conventional Commits** — `<type>(<scope>): <description>`, **no `Co-Authored-By` trailer**.
- **Explicit `git add <paths>`** — never `git add -A` / `git add .` / `git add -u`.
- **Tests stay hermetic under `cargo test` with no env vars.** `INSTA_UPDATE=always` is used **exactly once per baseline** to seed a `.snap`; the committed `.snap` then makes plain `cargo test` green.
- **`crates/sshrack-core/` stays zero-UI** (snapshots live in the binary crate's TUI; this plan does not touch core).
- The existing `#[ignore]`'d `sftp_e2e.rs` (needs a real local sshd) is **not** run by CI — `cargo test --workspace` skips ignored tests by default, which is exactly what we want.

### How insta snapshot tests work (recap)

First run with no baseline → test fails and writes a `.snap.new`. Seed the baseline once with `INSTA_UPDATE=always cargo test <name>` (promotes `.snap.new` to committed `.snap`). After that, plain `cargo test <name>` with no env is green. See the pilot plan `docs/superpowers/plans/2026-07-07-insta-snapshot-pilot.md` for the worked example.

---

## File Structure

- **Create** `.github/workflows/ci.yml` — the CI pipeline (Phase 0).
- **Modify** `src/tui/shell.rs` — add one snapshot test to its `#[cfg(test)] mod tests` (Phase A, shell chrome).
- **Modify** `src/tui/launcher.rs` — add one snapshot test to its `#[cfg(test)] mod tests` (Phase A, host list).
- **Modify** `src/tui/transfer/render.rs` — add one snapshot test to its `#[cfg(test)] mod tests` (Phase A, SFTP pane truncation).
- **Create** snapshot baselines under `src/tui/snapshots/` (shell, launcher) and `src/tui/transfer/snapshots/` (`render.rs` — insta's per-module default) — generated during baseline seeding; committed.

Each snapshot test is self-contained (function-local `use` statements) so it does not depend on the module's existing imports.

---

### Task 1: CI pipeline (Phase 0)

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing (greenfield workflow).
- Produces: a CI check that runs on every push to `main` and every PR. Downstream tasks rely on it only conceptually (it is where hermeticity is proven).

**Hermeticity note:** `cargo test --workspace` runs `connect_flow_test` (fake `ssh` shim — hermetic, no network) and skips `sftp_e2e` (`#[ignore]`). No test in the suite touches the network or the runner's `~/.ssh`, so the job needs no services containers.

- [ ] **Step 1: Create the workflow file**

Create `.github/workflows/ci.yml` with exactly this content:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - name: Format check
        run: cargo fmt --all -- --check
      - name: Clippy (warnings as errors)
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Test
        run: cargo test --workspace
```

- [ ] **Step 2: Verify the three commands pass locally (the CI will run the same ones)**

Run: `cargo fmt --all -- --check`
Expected: exit 0, no output (no formatting drift).

Run: `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -3`
Expected: `Finished` with no warnings.

Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -12`
Expected: every `test result:` line shows `0 failed`; no `FAILED`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add format, clippy, and test workflow"
```

(Note: the workflow actually runs only after it is pushed to GitHub. Steps 1-2 prove the commands it runs are green locally; the first push will surface any CI-only issue.)

---

### Task 2: Shell-chrome and host-list snapshots (Phase A)

**Files:**
- Modify: `src/tui/shell.rs` (its `#[cfg(test)] mod tests` — add one test).
- Modify: `src/tui/launcher.rs` (its `#[cfg(test)] mod tests` — add one test).
- Create: two `.snap` files under `src/tui/snapshots/` (generated, then committed).

**Interfaces:**
- Consumes: `draw_shell(frame, area, active: Tab, footer: &[(&str, &str)]) -> Rect` (`src/tui/shell.rs:28`); `Launcher::new(hosts, credentials, frecency)` (`src/tui/launcher.rs:176`) and `Launcher::draw_in_shell(&self, frame, area, hosts, frecency, credentials, status: &Status, show_cursor: bool)` (`src/tui/launcher.rs:346`); `Status::empty()` (`src/tui/intent.rs:212`); `Auth::inline(CredentialBody::new(user))` (existing test helper pattern).
- Produces: two committed `.snap` baselines locking the shell chrome and the host-list rendering.

**Why these two are hermetic:** `draw_shell` is pure render. The host-list test fixes everything dynamic — `Frecency::default()` makes every host score 0 so `rank_hosts` tie-breaks by name ascending (deterministic order); the ULIDs only feed `frecency.score`, they are never rendered, so their values cannot affect the snapshot (fixed values are used anyway, defensively).

- [ ] **Step 1: Add the shell-chrome snapshot test**

In `src/tui/shell.rs`, inside the existing `#[cfg(test)] mod tests { ... }`, add this test function (the module already imports `Terminal`/`TestBackend` and `draw_shell`/`Tab` via `use super::*` and existing test imports — the function-local `use` below is belt-and-suspenders):

```rust
    #[test]
    fn shell_chrome_snapshots_tabs_border_and_footer() {
        // Snapshot the three-band shell chrome (tabs / bordered middle / footer)
        // on the Hosts tab. Locks tab order, the bordered middle panel area, and
        // footer hint wording — any keymap/footer/chrome change surfaces as a
        // diff. Pure TestBackend render: no terminal, PATH, or env dependency,
        // identical output on any machine.
        use ratatui::{Terminal, backend::TestBackend};
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let _ = draw_shell(
                f,
                f.area(),
                Tab::Hosts,
                &[("Ctrl-A", "add"), ("Ctrl-E", "edit"), ("F1", "help")],
            );
        })
        .unwrap();
        insta::assert_snapshot!(term.backend());
    }
```

- [ ] **Step 2: Add the host-list snapshot test**

In `src/tui/launcher.rs`, inside its `#[cfg(test)] mod tests { ... }`, add this test function. It is fully self-contained (function-local `use`), so it does not matter what the module currently imports:

```rust
    #[test]
    fn host_list_snapshots_two_hosts_in_name_order_with_empty_frecency() {
        // Snapshot the launcher list with two hosts and an EMPTY frecency. All
        // hosts score 0, so rank_hosts tie-breaks by name ascending — the order
        // is deterministic and hermetic (ULIDs only feed frecency.score, they
        // are never rendered; no network, no real time). Locks row layout, the
        // selection marker, the cwd/search-box chrome, and the status row.
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::config::schema::{Auth, CredentialBody, Host};
        use sshrack_core::frecency::Frecency;
        use ulid::Ulid;

        use crate::tui::intent::Status;
        use crate::tui::launcher::Launcher;

        let hosts = vec![
            Host {
                id: Ulid::from_string("01KWAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
                name: "web-prod".into(),
                host: "10.0.0.1".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("deploy")),
            },
            Host {
                id: Ulid::from_string("01KWBBBBBBBBBBBBBBBBBBBBBB").unwrap(),
                name: "db-staging".into(),
                host: "10.0.0.2".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("root")),
            },
        ];
        let launcher = Launcher::new(&hosts, &[], &Frecency::default());
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            launcher.draw_in_shell(
                f,
                f.area(),
                &hosts,
                &Frecency::default(),
                &[],
                &Status::empty(),
                false,
            );
        })
        .unwrap();
        insta::assert_snapshot!(term.backend());
    }
```

- [ ] **Step 3: Verify both tests FAIL (RED — missing baselines)**

Run: `cargo test --package sshrack --bin sshrack shell_chrome_snapshots host_list_snapshots 2>&1 | tail -20`
Expected: both tests **fail** (insta writes `.snap.new` files; this is the RED state for a first run). Do not commit yet.

- [ ] **Step 4: Seed the two baselines**

Run: `INSTA_UPDATE=always cargo test --package sshrack --bin sshrack shell_chrome_snapshots host_list_snapshots 2>&1 | tail -12`
Expected: both tests **pass**, and insta writes two committed `.snap` files under `src/tui/snapshots/`. (`INSTA_UPDATE` is used only this once to create the baselines.)

- [ ] **Step 5: Sanity-check the baselines**

Run: `git status --porcelain`
Expected: two new untracked `.snap` files under `src/tui/snapshots/`.

Open each `.snap` and confirm it is meaningful (not empty/garbled):
- The shell-chrome snapshot shows the tab bar, a bordered middle panel, and the footer hints.
- The host-list snapshot shows both host rows (`web-prod`, `db-staging`), the selection marker on the first row, the search box, and the status row.

If either is empty or garbled, **stop** — something is wrong with the draw; do not commit a broken baseline.

- [ ] **Step 6: Verify hermetic GREEN (no env)**

Run: `cargo test --package sshrack --bin sshrack shell_chrome_snapshots host_list_snapshots 2>&1 | grep "test result"`
Expected: a `test result:` line with `2 passed; 0 failed`, with no `INSTA_UPDATE` set.

- [ ] **Step 7: fmt + clippy**

Run: `cargo fmt`
Run: `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -3`
Expected: both green.

- [ ] **Step 8: Commit**

```bash
git add src/tui/shell.rs src/tui/launcher.rs src/tui/snapshots/
git commit -m "test(tui): snapshot the shell chrome and host launcher list"
```

---

### Task 3: SFTP pane truncation snapshot (Phase A)

**Files:**
- Modify: `src/tui/transfer/render.rs` (its `#[cfg(test)] mod tests` — add one test).
- Create: one `.snap` file under `src/tui/snapshots/` (generated, then committed).

**Interfaces:**
- Consumes: `draw_pane(frame, area, pane: &Pane, focused: bool, title: &str)` (`src/tui/transfer/render.rs:49`); `Pane::new(cwd: PathBuf)` (`src/tui/transfer/pane.rs:76`); `Pane::set_entries(entries: Vec<DirEntry>)` (`src/tui/transfer/pane.rs:86`); `DirEntry { name, path, is_dir, is_symlink, size, modified }` (`crates/sshrack-core/src/dirsource.rs:40`).
- Produces: one committed `.snap` baseline locking the long-filename truncation behavior.

**Hermeticity note:** `modified: None` removes the only time-varying field from `DirEntry`; the name/path/size are fixed strings. No real filesystem is listed (`set_entries` injects entries directly), no network, in-memory `TestBackend`. This is the test that would have caught the long-filename rendering concerns directly.

- [ ] **Step 1: Add the snapshot test**

In `src/tui/transfer/render.rs`, inside its `#[cfg(test)] mod tests { ... }`, add this test function. It is fully self-contained (function-local `use`). The module already has many `draw_pane_row_*` tests that construct `Pane` + `DirEntry` + `TestBackend`, so the patterns are proven; mirror them.

```rust
    #[test]
    fn draw_pane_truncates_a_very_long_filename_snapshot() {
        // Snapshot a focused pane carrying one entry whose filename is far
        // wider than the pane. Locks the truncation behavior: the name is cut
        // to fit, and the marker/cursor glyphs are not pushed off the row.
        // Hermetic: modified: None (no real time), fixed name/path/size,
        // in-memory TestBackend — identical output on any machine.
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::dirsource::DirEntry;

        use crate::tui::transfer::pane::Pane;

        let long = "this-is-an-extremely-long-filename-that-overflows-the-pane-width.tar.gz";
        let mut pane = Pane::new(std::path::PathBuf::from("/home/u/project"));
        pane.set_entries(vec![DirEntry {
            name: long.to_string(),
            path: std::path::PathBuf::from(format!("/home/u/project/{long}")),
            is_dir: false,
            is_symlink: false,
            size: Some(1024),
            modified: None,
        }]);
        let backend = TestBackend::new(40, 10);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_pane(f, f.area(), &pane, true, "local")).unwrap();
        insta::assert_snapshot!(term.backend());
    }
```

- [ ] **Step 2: Verify it FAILS (RED — missing baseline)**

Run: `cargo test --package sshrack --bin sshrack draw_pane_truncates_a_very_long_filename_snapshot 2>&1 | tail -15`
Expected: test **fails**, insta writes a `.snap.new`. Do not commit yet.

- [ ] **Step 3: Seed the baseline**

Run: `INSTA_UPDATE=always cargo test --package sshrack --bin sshrack draw_pane_truncates_a_very_long_filename_snapshot 2>&1 | tail -10`
Expected: test **passes**, insta writes the committed `.snap` under `src/tui/snapshots/`.

- [ ] **Step 4: Sanity-check the baseline**

Run: `git status --porcelain`
Expected: one new untracked `.snap` under `src/tui/snapshots/`.

Open the `.snap` and confirm the long filename is **truncated** (cut with an ellipsis or hard-cut to fit the 40-wide pane) and the pane border + `local` title + cwd row render. If the name is NOT truncated (overflows the border) or the snapshot is empty, **stop** — that is a real rendering bug to investigate, not a baseline to commit blindly.

- [ ] **Step 5: Verify hermetic GREEN (no env)**

Run: `cargo test --package sshrack --bin sshrack draw_pane_truncates_a_very_long_filename_snapshot 2>&1 | grep "test result"`
Expected: `1 passed; 0 failed`, no `INSTA_UPDATE` set.

- [ ] **Step 6: fmt + clippy + full suite**

Run: `cargo fmt`
Run: `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -3`
Run: `cargo test --workspace 2>&1 | grep -E "test result|FAILED" | tail -12`
Expected: fmt green; clippy green; every `test result:` line `0 failed`, no `FAILED`.

- [ ] **Step 7: Commit**

```bash
git add src/tui/transfer/render.rs src/tui/snapshots/
git commit -m "test(tui): snapshot sftp pane long-filename truncation"
```

---

## Out of scope (future plans)

These are deliberately excluded from this plan — each is a separate subsystem (per the writing-plans scope rule) and some need a product-code decision before they are testable:

- **Wizard / overlay snapshots** (host form, cred form, queue manager, file picker, password prompt) — same one-line pattern as Tasks 2-3; mechanical follow-up once the pattern is proven here.
- **`assert_cmd` migration + exit-code matrix** — migrate the two existing `tests/*_test.rs` to `assert_cmd`/`assert_fs`/`predicates` and add the exit-code (0/2/4/5/6/7/8) and error-path matrix.
- **scp-path fake-ssh shim** — extend the `connect_flow_test.rs` fake-shim pattern to the scp launch path (hermetic; needs confirming the scp launch seam is `pub` like `connect::launch`).
- **host-key flow hermetic** — requires adding a `known_hosts` path-injection seam + fake `ssh-keyscan`/`ssh-keygen` to core (product-code change + security review). Needs an explicit go-ahead.
- **L5 PTY smoke tests** — deliberately excluded: PTY tests are the least hermetic layer (terminal size / locale / crossterm-version sensitive, flake-prone on CI). The render snapshots (this plan) + the existing state-transition unit tests cover the same ground more reliably for sshrack's needs.

## Implementation record (2026-07-07, controller log)

Landed via subagent-driven-development (one implementer across all three tasks, then review). Final commits (base `8638cae`):
- `48ae2f0` — `ci: add format, clippy, and test workflow`
- `5c0ae6e` — `test(tui): snapshot the shell chrome and host launcher list`
- `9bc5e14` — `test(tui): snapshot sftp pane long-filename truncation`

Two deviations from the plan draft, both controller-resolved after the implementer flagged them:
1. **ULID length (plan typo).** The first fixture ULID in Task 2 was written 28 chars; ULIDs are 26. `Ulid::from_string(...).unwrap()` panicked at runtime (`InvalidLength`). The implementer trimmed it to 26 chars (`01KWAAAAAAAAAAAAAAAAAAAAAA`). Harmless to the snapshot — ULIDs only feed `frecency.score`, never rendered. Plan code block updated to match.
2. **SFTP snapshot path.** insta places `render.rs`'s snapshot at `src/tui/transfer/snapshots/` (per-module default, since the file lives under `transfer/`), not `src/tui/snapshots/`. The other three stay at `src/tui/snapshots/`. Both are insta's standard layout.

Gate: `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo test --workspace` = **1285 passed / 0 failed / 2 ignored** (the 2 ignored are the `#[ignore]`'d `sftp_e2e`, skipped by CI). Hermetic verified — every snapshot is green under plain `cargo test` with no env. Baselines: `src/tui/snapshots/sshrack__tui__{shell,launcher}__tests__*.snap` and `src/tui/transfer/snapshots/sshrack__tui__transfer__render__tests__draw_pane_truncates_a_very_long_filename_snapshot.snap`.

Sanity checks (the load-bearing part): the host-list snapshot shows both rows in name-ascending order (`db-staging` before `web-prod`) with the `▶` selection marker and the `[—]` frecency-tier glyph; the SFTP snapshot shows the 71-char filename hard-truncated to fit the 40-wide pane without overflowing the border. Both confirm the hermeticity claim (fixed input ⇒ deterministic output).

## Notes for the reviewer / user after execution

- **What "hermetic, runs anywhere" means here:** every test added uses `TestBackend` (in-memory), fixed fixtures, and `modified: None`. The Task 1 CI job is the proof — if it is green on `ubuntu-latest`, the same `cargo test --workspace` is green on your laptop and any contributor's laptop with no setup.
- **Snapshot discipline:** future render changes show up as diffs; accept intentional ones with `cargo insta review` (install once: `cargo install cargo-insta`) or, for this pilot-style workflow, `INSTA_UPDATE=always cargo test <name>` then review the `.snap` diff in the commit.
- **Reverting** any task is a single `git revert` — none of these tasks touch production code paths.
