# TUI app.rs Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Split the 4017-line `src/tui/app.rs` into focused, single-responsibility files (terminal guard, intent/state types, App state machine, persistence side-effects, event loop) without changing any behavior — every one of the ~330 existing TUI tests must stay green after each task.

**Architecture:** This is a pure structural refactor (move code, adjust imports, widen visibility), not a feature. `app.rs` currently holds five unrelated responsibilities; each becomes its own file under `src/tui/`. The decomposition follows the seam that already exists in the code: `on_key` is pure (state machine) and returns an `Outcome`; the loop applies side effects by calling free `persist_*` functions; the terminal is owned by an RAII `TerminalGuard`. Tasks are ordered risk-first (most independent first), each leaves the workspace compiling and tests green, and each ends with a commit.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28. No new dependencies.

## Global Constraints

Every task implicitly inherits these (from `CLAUDE.md` hard rules — verbatim values):

- **English only** — all source, comments, doc comments, errors, commits.
- **Zero `unsafe`** — never, including tests.
- **Zero `unwrap()`/`expect()`** in production code — only in `#[cfg(test)]` or `expect("invariant: ...")`.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Dev stage, no compat code** — move code cleanly; do not leave behind re-export shims, dead aliases, or widened `pub` "just in case." Narrow visibility to the tightest level that compiles.
- **Zero behavior change** — this is a refactor. The ~330 existing `cargo test --bin sshrack` tests are the spec. No test's meaning may change; tests move with the code they test. If a test would need a behavioral edit to pass, STOP — that is a bug in the refactor, not the test.
- **`cargo test --bin sshrack`** (NOT `--lib` — sshrack is a binary crate, no lib target). Tests must be hermetic: green in a real shell with `SSHRACK_PASSPHRASE` set.
- **Symbol-name anchors, not line numbers** — the reference line numbers below are from baseline `4f5ba1c` and WILL drift as earlier tasks land. Always locate a block by its symbol name (`fn persist_host_save`, `pub enum Outcome`, etc.) with ripgrep before moving it.

### Target structure (after all tasks)

```
src/tui/
├── mod.rs            # run() + EntryMode + ConnectRequest + CredentialNames; pub use adjusted
├── term.rs      (NEW)# Tui, TerminalHandle, TerminalGuard — terminal RAII (~100 lines)
├── intent.rs   (NEW) # Outcome, Overlay, Status — pure intent/state types (~190 lines)
├── app.rs            # App struct + impl App (state machine: accessors, overlay lifecycle,
│                     #   entry routing, on_key pure routing, draw) + its tests (~880 lines)
├── persist.rs  (NEW) # persist_host_save/delete, persist_cred_save/delete, persist_store_switch,
│                     #   StoreSwitchTarget + helpers + its tests (~600 lines)
├── run_loop.rs (NEW) # enter_press + run_loop (event orchestration) + borrow-regression tests
│                     #   (~300 lines)
├── test_support.rs (NEW, #[cfg(test)]) # shared test helpers (app_with_*, press, dead_handle)
└── ... (shell.rs, launcher.rs, cred_panel.rs, settings.rs, store.rs, connect.rs, prompt.rs,
        dialog.rs, help.rs, popup.rs, panel.rs, tab.rs, theme.rs, wizard/ — UNCHANGED)
```

### Visibility rules (apply consistently across all tasks)

These are locked decisions — do not second-guess them per task:

1. **Types that cross file boundaries within `tui`** (`Tui`, `TerminalHandle`, `TerminalGuard`, `Outcome`, `Overlay`, `Status`) → keep their **existing** visibility. At baseline they are all `pub`; they stay `pub` in their new home file. (`mod.rs` re-exports the ones the rest of the crate already reaches via `crate::tui::…`.)
2. **Free functions that cross file boundaries** (`persist_*`, `fulfill_save_cred`, `enter_press`) → `pub(crate)`. They are called only within `tui`, never from `cli`/`main`. (`run_loop` is `pub` because `mod.rs` re-exports it; leave that as-is.)
3. **`App` private fields/methods that `persist.rs` / `run_loop.rs` must reach** → `pub(super)`. This means "visible to `crate::tui`" — exactly the sibling modules that need them, and explicitly NOT `cli`/`main`. The full list, promoted once in Task 4:
   - fields: `config`, `config_path`, `overlay`, `store_view`, `pending_delete`, `pending_delete_cred`
   - method: `recompute_panels`
   - (`launcher`, `should_quit` are already `pub`; `set_config`/`set_status`/`set_status_error`/`close_*` are already `pub` methods — leave them.)

### Shared cross-task contract (what each task hands to the next)

- **Task 2 produces:** `crate::tui::term::{Tui, TerminalHandle, TerminalGuard}` (all `pub`).
- **Task 3 produces:** `crate::tui::intent::{Outcome, Overlay, Status}` (all `pub`). All external `use …::app::{Outcome,Overlay,Status}` paths are rewritten to `…::intent::…`.
- **Task 4 produces:** `crate::tui::persist::{persist_host_save, persist_host_delete, persist_cred_delete, persist_cred_save, persist_store_switch, fulfill_save_cred, map_store_pick, recover_store_mode_and_retry_cred_save, persist_and_reload, set_store_status, target_label, StoreSwitchTarget}` (all `pub(crate)`); and the `App` fields/methods above are `pub(super)`.
- **Task 5 consumes:** term, intent, persist, and the `pub(super)` App fields. **Produces:** `crate::tui::run_loop::run_loop` (`pub`) and `enter_press` (`pub(crate)`).

---

## Task 1: Extract shared test helpers into `test_support.rs`

This task touches **test code only** — zero production change. It builds the shared helper module that later tasks' migrated tests will `use`, so the helper definitions are not duplicated across five files (DRY). Doing it first means every later task can move tests without re-deriving helpers.

**Files:**
- Create: `src/tui/test_support.rs`
- Modify: `src/tui/mod.rs` (add `#[cfg(test)] mod test_support;`)
- Modify: `src/tui/app.rs` (the `#[cfg(test)] mod tests` block: delete the shared helper definitions, replace with `use crate::tui::test_support::*;`)

**Interfaces:**
- Produces: `crate::tui::test_support::{app_with_host, app_with_credential, app_with_named_host, app_with_named_cred, press, dead_handle}` (all `pub(crate) fn`).

- [ ] **Step 1: Inventory the existing helpers and their call sites**

Run (do not edit yet):
```bash
rg -n 'fn (app_with_host|app_with_credential|app_with_named_host|app_with_named_cred|press|dead_handle|stdout_tui)\b' src/tui/app.rs
```
There are multiple `#[cfg(test)] mod tests { … }` blocks in `app.rs` (the top-level `mod tests` at ~line 2095, plus smaller inline `mod tests` inside some `impl`/fn blocks). The same helper name (e.g. `app_with_host`) may be defined more than once in different sub-blocks. **Read each definition.** If two definitions build the same shape of `App`, they are the same helper — merge into one. If they differ (e.g. one seeds a credential, one does not), keep both under distinct, descriptive names.

Note: `stdout_tui` returns a `Tui` and is only used by the terminal-borrow regression tests — leave it in `app.rs` for now; it moves in Task 5 with those tests (it depends on term types that have not moved yet).

- [ ] **Step 2: Create `src/tui/test_support.rs`**

Write the file with the merged helpers. Exact bodies come from the definitions you read in Step 1 (copy them verbatim, then adjust the `use` lines at the top to reach `App`, `KeyEvent`, etc.). The skeleton:

```rust
//! Shared test helpers for the TUI test modules (`app`, `persist`, `run_loop`).
//!
//! Pulled out of `app.rs`'s test blocks so each file split off by the
//! app.rs-decomposition plan can migrate its tests without re-deriving these
//! constructors. Compiled only under `--test` via the `#[cfg(test)]` mod
//! declaration in [`crate::tui`].

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::tui::app::App;
// dead_handle returns a TerminalHandle; at this point in the plan that type
// still lives in app.rs. Task 2 (term extraction) will rewrite this path to
// crate::tui::term::TerminalHandle.
use crate::tui::app::TerminalHandle;

/// An `App` seeded with a single host named `name`, ready for launcher/wizard
/// tests. (Body copied verbatim from the app_with_host definition found above.)
pub(crate) fn app_with_host(name: &str) -> App {
    todo!("paste the verbatim body from Step 1")
}

pub(crate) fn app_with_credential(name: &str, user: &str) -> App {
    todo!("paste the verbatim body from Step 1")
}

pub(crate) fn app_with_named_host(name: &str) -> App {
    todo!("paste the verbatim body from Step 1 — or delete if it duplicates app_with_host")
}

pub(crate) fn app_with_named_cred(name: &str) -> App {
    todo!("paste the verbatim body from Step 1 — or delete if it duplicates app_with_credential")
}

/// A `KeyEvent` Press of `code` + `mods` (the shape crossterm 0.28 emits that
/// the TUI actually reacts to).
pub(crate) fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
    KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
}

/// A dead weak terminal handle — `Weak::upgrade` returns `None`. Used by tests
/// that exercise a save/delete path through a `TerminalHandle` without a live
/// terminal (the popup path then treats it as a silent cancel).
pub(crate) fn dead_handle() -> TerminalHandle {
    todo!("paste the verbatim body from Step 1")
}
```

**Replace every `todo!(…)` with the verbatim body** you copied from `app.rs` in Step 1. A `todo!` left in this file is a plan failure — every helper has a concrete existing body to paste. If a helper name turned out to be a duplicate in Step 1, delete that function from the skeleton entirely (do not leave a stub).

- [ ] **Step 3: Register the module in `mod.rs`**

In `src/tui/mod.rs`, alongside the other `pub mod …;` declarations, add (placement: after the `pub mod` block, before `pub use`):

```rust
#[cfg(test)]
mod test_support;
```

- [ ] **Step 4: Rewire `app.rs` test blocks to use the shared helpers**

In `src/tui/app.rs`, inside **each** `#[cfg(test)] mod tests { … }` block that defined one of the moved helpers:
1. Delete the helper's `fn app_with_host(…) { … }` / `fn press(…) { … }` / etc. definition.
2. Add to that `mod tests`'s `use` block: `use crate::tui::test_support::{app_with_host, app_with_credential, app_with_named_host, app_with_named_cred, press, dead_handle};` — list only the helpers that block actually calls (run `rg -n '\b(app_with_host|app_with_credential|app_with_named_host|app_with_named_cred|press|dead_handle)\(' src/tui/app.rs` scoped to that block to see which).

Leave `stdout_tui` where it is (still defined and used inside `app.rs` tests for now).

- [ ] **Step 5: Build + test (must be fully green — no behavior change)**

```bash
cargo build --workspace
cargo test --bin sshrack
```
Expected: the same number of tests pass as at baseline (the test count must not drop — no test was deleted, only helper definitions moved). If a test fails to compile, a block is importing a helper it doesn't use, or missing one it does — fix the `use` list.

- [ ] **Step 6: clippy + fmt**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```

- [ ] **Step 7: Commit**

```bash
git add src/tui/test_support.rs src/tui/mod.rs src/tui/app.rs
git commit -m "refactor(tui): extract shared test helpers into test_support module"
```

---

## Task 2: Extract terminal RAII into `term.rs`

Move `Tui`, `TerminalHandle`, and `TerminalGuard` (the terminal ownership layer) into their own file. These have zero dependency on `App` — they are the most independent block, so they move first.

**Reference locations (baseline `4f5ba1c`, locate by symbol before moving):**
- `pub type Tui` — app.rs line 46
- `pub type TerminalHandle` — app.rs line 57
- `pub struct TerminalGuard` + `impl TerminalGuard` + `impl Drop for TerminalGuard` — app.rs lines 59–132

**Files:**
- Create: `src/tui/term.rs`
- Modify: `src/tui/app.rs` (delete the moved items + their now-unused imports)
- Modify: `src/tui/mod.rs` (register `pub mod term;`; change the `TerminalGuard` re-export source from `app` to `term`; add `Tui`/`TerminalHandle` re-exports so consumers can keep using `crate::tui::…`)
- Modify: `src/tui/test_support.rs` (rewrite the `TerminalHandle` import path)

**Interfaces:**
- Produces: `crate::tui::term::{Tui, TerminalHandle, TerminalGuard}` (all `pub`, unchanged visibility).
- Consumes (in term.rs): `std::cell::RefCell`, `std::io::{self, Stdout}`, `std::rc::{Rc, Weak}`, `crossterm::{execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}}`, `ratatui::{Terminal, backend::CrosstermBackend}`, `sshrack_core::error::SshrackError` (referenced in `TerminalHandle` doc).

- [ ] **Step 1: Locate the exact span**

```bash
rg -n 'pub type Tui =|pub type TerminalHandle =|pub struct TerminalGuard|impl TerminalGuard|impl Drop for TerminalGuard' src/tui/app.rs
```
The block to move runs from the `pub type Tui` line through the end of `impl Drop for TerminalGuard { … }`.

- [ ] **Step 2: Create `src/tui/term.rs`**

Start the file with a focused module doc + the imports it needs, then paste the three items verbatim (including all doc comments and the `impl Drop` body):

```rust
//! Terminal ownership for the TUI.
//!
//! [`TerminalGuard`] is RAII: it enters raw mode + the alternate screen on
//! construction and restores the terminal in [`Drop`]. Because `Drop` always
//! runs, the terminal is restored even when the event loop returns early (e.g.
//! on a connect request that later errors in `main`).
//!
//! The guard owns the [`Tui`] behind an `Rc<RefCell<…>>` and hands out two
//! ways to reach it: [`TerminalGuard::terminal`] returns the `Rc` (the loop
//! `borrow_mut()`s it for one narrow draw at a time), and
//! [`TerminalGuard::handle`] returns a weak [`TerminalHandle`] the prompt layer
//! upgrades at popup time. The reentrancy contract (narrow borrows only) is
//! documented on [`TerminalGuard`].

use std::cell::RefCell;
use std::io::{self, Stdout};
use std::rc::{Rc, Weak};

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

// (paste `pub type Tui`, `pub type TerminalHandle`, `pub struct TerminalGuard`,
//  `impl TerminalGuard`, and `impl Drop for TerminalGuard` verbatim from app.rs,
//  preserving every doc comment.)
```

- [ ] **Step 3: Delete the moved items from `app.rs`**

Remove the three items (and the long "TUI application state, key handling, terminal guard…" module-doc lines at the top of app.rs that describe the terminal guard — see Step 5 for the replacement doc). Then remove imports `app.rs` no longer uses after the move:
```bash
cargo build --workspace 2>&1 | rg 'warning: unused import'
```
Expect unused-import warnings for `std::cell::RefCell`, `std::io::{self, Stdout}`, `std::rc::{Rc, Weak}` (and possibly `crossterm::{execute, terminal::…}` and `ratatui::{Terminal, backend::CrosstermBackend}`) — remove exactly those from `app.rs`'s top `use` block. **Keep** `std::rc::Rc` and `std::cell::RefCell` IF `run_loop` (still in app.rs until Task 5) references `Rc<RefCell<Tui>>` in its signature — check its signature before deleting. `event`, `Event`, `KeyEvent`, `Frame` stay (used by `on_key`/`draw`/`run_loop`).

- [ ] **Step 4: Rewire `app.rs` to import the term types**

`app.rs` still references `Tui` (in `run_loop`'s signature) and `TerminalHandle` (in `persist_*` signatures, until Task 4 moves them). Add to `app.rs`'s `use` block:

```rust
use super::term::{TerminalHandle, Tui};
```

- [ ] **Step 5: Update `mod.rs` re-exports and module doc**

In `src/tui/mod.rs`:
1. Add `pub mod term;` to the module declarations.
2. Change the re-export line from
   ```rust
   pub use app::{App, TerminalGuard, run_loop};
   ```
   to
   ```rust
   pub use app::{App, run_loop};
   pub use term::{TerminalGuard, TerminalHandle, Tui};
   ```
   (Adding `TerminalHandle`/`Tui` re-exports keeps the canonical path `crate::tui::TerminalHandle` stable for consumers, regardless of which file the type lives in.)
3. The `mod.rs` top-of-file `//!` doc mentions "Task 11 shipped the foundation (App, event loop, RAII terminal guard…)" — leave historical prose unchanged (it is accurate history). No edit needed here.

- [ ] **Step 6: Rewrite the `TerminalHandle` import in `test_support.rs`**

In `src/tui/test_support.rs`, change:
```rust
use crate::tui::app::TerminalHandle;
```
to:
```rust
use crate::tui::TerminalHandle;
```
(via the `mod.rs` re-export added in Step 5 — the stable path.)

- [ ] **Step 7: Build + test + clippy + fmt**

```bash
cargo build --workspace && cargo test --bin sshrack
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```
Expected: green, same test count as after Task 1. If `app.rs` still warns on an unused import, re-run the `cargo build | rg 'unused import'` loop until clean.

- [ ] **Step 8: Commit**

```bash
git add src/tui/term.rs src/tui/app.rs src/tui/mod.rs src/tui/test_support.rs
git commit -m "refactor(tui): extract TerminalGuard and terminal types into term module"
```

---

## Task 3: Extract intent/state types into `intent.rs`

Move the three pure types that describe "what should happen" and "what the status bar shows": `Outcome`, `Overlay`, `Status`. These are referenced across half the TUI, so this task also rewrites every external import path.

**Reference locations (baseline `4f5ba1c`, locate by symbol before moving):**
- `pub enum Outcome` — app.rs line 147 (includes the `#[allow(clippy::large_enum_variant)]` attribute at line 146 and the long doc comment)
- `pub enum Overlay` — app.rs line 267
- `pub struct Status` + `impl Status` — app.rs lines 286–329

**External import sites to rewrite (verified by ripgrep at baseline):**
- `src/tui/settings.rs:25` `use super::app::Outcome;` → `use super::intent::Outcome;`
- `src/tui/settings.rs:62` `super::app::Overlay::StorePicker` → `super::intent::Overlay::StorePicker`
- `src/tui/settings.rs:126` `super::super::app::Overlay::StorePicker` → `super::super::intent::Overlay::StorePicker`
- `src/tui/cred_panel.rs:35` `use super::app::Outcome;` → `use super::intent::Outcome;`
- `src/tui/cred_panel.rs:579` `crate::tui::app::Status::empty()` → `crate::tui::intent::Status::empty()`
- `src/tui/wizard/host.rs:26` `use super::super::app::Outcome;` → `use super::super::intent::Outcome;`
- `src/tui/shell.rs:19` `use crate::tui::app::Status;` → `use crate::tui::intent::Status;`
- `src/tui/launcher.rs:836` and `:878` `crate::tui::app::Status::empty()` → `crate::tui::intent::Status::empty()`

**Files:**
- Create: `src/tui/intent.rs`
- Modify: `src/tui/app.rs` (delete moved types + re-import them; move the `Status` round-trip test)
- Modify: `src/tui/mod.rs` (register `pub mod intent;` + re-export)
- Modify: `src/tui/{settings,cred_panel,launcher,shell}.rs`, `src/tui/wizard/host.rs` (rewrite import paths above)

**Interfaces:**
- Produces: `crate::tui::intent::{Outcome, Overlay, Status}` (all `pub`).

- [ ] **Step 1: Confirm the full set of import sites has not drifted**

```bash
rg -n 'app::(Outcome|Overlay|Status)\b|tui::app::(Outcome|Overlay|Status)\b' src/
```
Every hit must be on the rewrite list above (or in `app.rs` itself, which Step 4 handles). If a new site appeared since baseline, add it to the list.

- [ ] **Step 2: Create `src/tui/intent.rs`**

```rust
//! Pure intent and status types shared across the TUI.
//!
//! [`Outcome`] is what [`crate::tui::app::App::on_key`] returns: a description
//! of what the event loop should do next, with no I/O performed. Keeping it
//! separate from `App` makes the state-machine boundary explicit — `on_key` is
//! pure, side effects happen in the loop. [`Overlay`] enumerates the one-at-a-
//! time dialogs layered on the shell. [`Status`] is the consolidated status-bar
//! message (info or error) shown in the footer.

// (paste `pub enum Outcome { … }` INCLUDING its `#[allow(clippy::large_enum_variant)]`
//  attribute and full doc comment,
//  then `pub enum Overlay { … }`,
//  then `pub struct Status { … }` + `impl Status { … }`,
//  all verbatim from app.rs.)
```

`Outcome`/`Overlay` reference types from elsewhere (`Tab` from `super::tab`, `HostForm`/`CredForm` from `super::wizard`, `Ulid`). Add the needed `use` lines at the top of `intent.rs`:
```rust
use ulid::Ulid;

use super::tab::Tab;
use super::wizard::{CredForm, HostForm};
```
(Confirm against the actual variant bodies you pasted — add exactly the types the variants name.)

- [ ] **Step 3: Delete the moved types from `app.rs`**

Remove `pub enum Outcome`, `pub enum Overlay`, `pub struct Status` + `impl Status`. Add to `app.rs`'s `use` block so its own `impl App` (returning `Outcome`, reading `Overlay`, holding `status: Status`) still compiles:
```rust
use super::intent::{Outcome, Overlay, Status};
```

- [ ] **Step 4: Rewrite every external import site**

Apply the eight rewrites listed in the task header (settings.rs ×3, cred_panel.rs ×2, wizard/host.rs ×1, shell.rs ×1, launcher.rs ×2). Do them with Edit (each old path → new path). After editing, verify none remain:
```bash
rg -n 'app::(Outcome|Overlay|Status)\b|tui::app::(Outcome|Overlay|Status)\b' src/
```
Expected: zero hits.

- [ ] **Step 5: Register + re-export in `mod.rs`**

In `src/tui/mod.rs`:
1. Add `pub mod intent;` to the module declarations.
2. Add to the re-exports:
   ```rust
   pub use intent::{Outcome, Overlay, Status};
   ```
   (Keeps `crate::tui::Status` etc. reachable on the stable path; shell.rs/launcher.rs may then shorten `crate::tui::intent::Status` → `crate::tui::Status` — optional, do it only if `cargo fmt`/readability prefers; the long path is also fine.)

- [ ] **Step 6: Move the `Status` round-trip test to `intent.rs`**

The test `fn set_status_and_set_status_error_round_trip` (baseline app.rs ~line 3483) exercises `App::set_status`/`set_status_error` + `Status` — it stays an `App` test (it calls App methods), so it **remains in `app.rs`**. Do not move it. (If on inspection it only constructs `Status::info(...)`/`Status::error(...)` directly without an `App`, move it into `intent.rs`'s `#[cfg(test)] mod tests`. Read it first; default: leave in `app.rs`.)

- [ ] **Step 7: Build + test + clippy + fmt**

```bash
cargo build --workspace && cargo test --bin sshrack
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```
Expected: green, same test count.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(tui): extract Outcome/Overlay/Status into intent module"
```

---

## Task 4: Extract persistence side-effects into `persist.rs`

The largest task. Move every free `persist_*` function and its helpers, and **promote the `App` fields/methods they touch to `pub(super)`** so the moved code still compiles. `run_loop` (still in `app.rs` until Task 5) is the only caller of these functions today; after the move it reaches them via `use super::persist::…`.

**Symbols to move (locate each by name):**
- `enum StoreSwitchTarget` (baseline app.rs ~line 1940)
- `fn map_store_pick` (~1847)
- `fn persist_host_save` (~1510)
- `fn persist_host_delete` (~1666)
- `fn persist_cred_delete` (~1700)
- `fn persist_cred_save` (~1737)
- `fn recover_store_mode_and_retry_cred_save` (~1861)
- `fn fulfill_save_cred` (~1897)
- `fn persist_store_switch` (~1959)
- `fn persist_and_reload` (~2066)
- `fn set_store_status` (~2079)
- `fn target_label` (~2086)

**Files:**
- Create: `src/tui/persist.rs`
- Modify: `src/tui/app.rs` (delete moved fns; widen visibility on the App fields/method below; update `run_loop`'s references to `use super::persist::…`)
- Modify: `src/tui/mod.rs` (register `pub mod persist;`)

**Interfaces:**
- Consumes: `App` (with newly `pub(super)` fields), `Outcome`/`Overlay`/`Status` (from intent), `TerminalHandle` (from term), `TuiPassphrase` (from super::prompt), core types (`host`, `credential`, `secret::{OsKeyring, vault, PassphraseProvider, SecretBackend}`, `config::schema::{Auth, Credential, CredentialBody, SecretKind, SecretStore, Host, SshrackConfig}`, `id::OwnerKind`, `error::SshrackError`).
- Produces: all moved fns as `pub(crate)` (so `run_loop` in the sibling module can call them); `StoreSwitchTarget` as `pub(crate)`.

- [ ] **Step 1: Widen `App` visibility FIRST (so the moved fns compile on arrival)**

In `src/tui/app.rs`, change these `App` members from private to `pub(super)`:
- fields: `config`, `config_path`, `overlay`, `store_view`, `pending_delete`, `pending_delete_cred`
- method: `fn recompute_panels` → `pub(super) fn recompute_panels`

`pub(super)` from `app`'s frame means "visible to `crate::tui`" — exactly `persist` and `run_loop`, and not `cli`/`main`. Leave the already-`pub` members (`launcher`, `should_quit`, `set_config`, `set_status`, `set_status_error`, `close_host_wizard`, `close_cred_wizard`, `close_overlay`, `close_store_view`, `config()`, `config_path()`, …) as they are.

Build to confirm the visibility change alone compiles:
```bash
cargo build --workspace
```

- [ ] **Step 2: Create `src/tui/persist.rs`**

```rust
//! Persistence side-effects for the TUI event loop.
//!
//! [`crate::tui::app::App::on_key`] is pure — it only mutates in-memory state and
//! returns an [`crate::tui::intent::Outcome`]. The loop calls the free functions
//! in this module to actually write to disk: add/edit/delete a host or
//! credential, switch the global storage mode, and reload the config + re-rank
//! the panels afterward. Each fn takes `&mut App` (and the `TerminalHandle`
//! where a popup may be needed) so it stays a leaf of the loop, not a method on
//! `App` — keeping `App` itself free of I/O.

use sshrack_core::error::SshrackError;

use super::app::App;
use super::intent::Overlay;
use super::term::TerminalHandle;
// (add any further `use` lines the pasted bodies require — see Step 3)

// (paste, verbatim and in dependency order: enum StoreSwitchTarget, fn map_store_pick,
//  fn persist_host_save, fn persist_host_delete, fn persist_cred_delete,
//  fn persist_cred_save, fn recover_store_mode_and_retry_cred_save, fn fulfill_save_cred,
//  fn persist_store_switch, fn persist_and_reload, fn set_store_status, fn target_label.)
```

- [ ] **Step 3: Widen each moved fn to `pub(crate)` and resolve imports**

For each pasted function, change `fn foo(` → `pub(crate) fn foo(` (and `enum StoreSwitchTarget` → `pub(crate) enum StoreSwitchTarget`). Then drive the import list from compiler errors:
```bash
cargo build --workspace 2>&1 | rg 'cannot find|expected'
```
Add `use` lines for every unresolved name. The pasted bodies contained inline `use sshrack_core::host;` / `use sshrack_core::secret::OsKeyring;` etc. at the top of some fns (baseline showed per-fn `use` blocks) — hoist those into the module-level `use` list (DRY: one import per crate path, not repeated per fn). Remove any now-redundant per-fn `use` blocks.

- [ ] **Step 4: Delete the moved fns from `app.rs` and point `run_loop` at the new module**

In `src/tui/app.rs`:
1. Delete all twelve moved items.
2. `run_loop` references `persist_host_save`, `persist_host_delete`, `persist_cred_delete`, `persist_store_switch`, `fulfill_save_cred`, `StoreSwitchTarget`. Add to `app.rs`'s `use` block:
   ```rust
   use super::persist::{
       StoreSwitchTarget, fulfill_save_cred, persist_cred_delete, persist_host_delete,
       persist_host_save, persist_store_switch,
   };
   ```
3. Build and fix unused-import warnings in `app.rs` (the moved fns took their inline `use sshrack_core::host;` etc. with them; `app.rs` may no longer need some core imports — but `run_loop` still uses `SshrackError`, `connect_host`, `TuiPassphrase`; keep those).

- [ ] **Step 5: Register the module in `mod.rs`**

Add `pub mod persist;` to `src/tui/mod.rs`. (No re-export needed — these fns are `pub(crate)`, used only inside `tui`.)

- [ ] **Step 6: Move the persist tests into `persist.rs`**

Move these tests out of `app.rs`'s `#[cfg(test)] mod tests` into a new `#[cfg(test)] mod tests` at the bottom of `persist.rs` (they test the moved fns directly). Locate each by name; move the `fn …` body verbatim:
`persist_host_save_add_appends_and_reloads`, `persist_host_save_edit_preserves_id_and_persists`, `persist_host_save_add_rejects_duplicate_name`, `persist_host_save_credential_choice_resolves_name_to_id`, `persist_host_save_credential_choice_unknown_name_errors`, `persist_host_save_independent_password_seals_under_plaintext`, `persist_host_save_independent_password_seals_under_keyring`, `persist_host_delete_removes_host_and_persists`, `persist_host_delete_unknown_host_errors`, `persist_cred_save_reranks_cred_panel_after_reload`, `persist_cred_delete_removes_credential_and_reranks_panel`, `persist_cred_delete_unknown_credential_errors`, `persist_store_switch_already_in_target_is_noop_status`, `persist_store_switch_keyring_unavailable_when_no_daemon_returns_ok_false`, `fulfill_save_cred_undecided_with_dead_handle_stays_in_wizard_with_cancel_msg`, and any `cred_add_*`/`cred_edit_*` test that asserts on the persisted config (those call `persist_cred_save` via `fulfill_save_cred` or directly — read each: if it calls a fn now in `persist.rs`, move it; if it drives `on_key` then checks state, it is an `App` test and stays in `app.rs`).

In the moved test block, add:
```rust
use crate::tui::test_support::{app_with_host, app_with_credential, app_with_named_host, app_with_named_cred, dead_handle};
use crate::tui::app::App;
use crate::tui::intent::Overlay;
// plus the core-schema/ulid imports the assertions use — copy them from the
// app.rs test block's `use` list.
```
List only the helpers/imports the moved tests actually reference.

- [ ] **Step 7: Build + test + clippy + fmt**

```bash
cargo build --workspace && cargo test --bin sshrack
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```
Expected: green. **The test count must equal the post-Task-3 count** — tests moved, none deleted. If the count dropped, a test was lost in the move; find and move it.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(tui): extract persist_* side-effects into persist module"
```

---

## Task 5: Extract the event loop into `run_loop.rs`

Move `run_loop` and `enter_press`. After this, `app.rs` contains only the `App` state machine (struct + impl: accessors, overlay lifecycle, entry routing, `on_key`, `draw`).

**Symbols to move (locate by name):**
- `fn enter_press` (baseline app.rs ~line 1199)
- `pub fn run_loop` (~1235, signature: `fn run_loop(terminal: &Rc<RefCell<Tui>>, app: &mut App, handle: TerminalHandle, data_dir: Option<&std::path::Path>) -> Option<ConnectRequest>`)

**Files:**
- Create: `src/tui/run_loop.rs`
- Modify: `src/tui/app.rs` (delete the two moved fns + their now-unused imports)
- Modify: `src/tui/mod.rs` (register `pub mod run_loop;`; change the `run_loop` re-export source from `app` to `run_loop`)
- Modify: `src/tui/test_support.rs` (move `stdout_tui` here, since the borrow-regression tests move with it and it is shared infrastructure)

**Interfaces:**
- Consumes: `App` (pub(super) fields from Task 4: `pending_delete`, `pending_delete_cred`, `overlay`, `store_view`; plus pub fields/methods `launcher`, `should_quit`, `set_status`, `set_status_error`, `close_host_wizard`, `close_store_view`, `close_overlay`, `on_key`, `draw`), `Outcome`/`Overlay` (intent), `Tui`/`TerminalHandle` (term), `connect_host` (super::connect), the six `persist::*` fns + `StoreSwitchTarget` (super::persist), `TuiPassphrase` (super::prompt), `SshrackError`, `ConnectRequest`.
- Produces: `crate::tui::run_loop::{run_loop}` (`pub`) and `enter_press` (`pub(crate)`).

- [ ] **Step 1: Create `src/tui/run_loop.rs`**

```rust
//! The blocking TUI event loop.
//!
//! Renders [`App`] via a narrow `borrow_mut()` on the shared terminal, polls
//! crossterm for key events, and dispatches each key through
//! [`App::on_key`]. When `on_key` returns a side-effecting
//! [`Outcome`][super::intent::Outcome] (save/delete/store-switch/connect), the
//! loop calls the relevant free function in [`super::persist`] or
//! [`super::connect::connect_host`]. Returns `Some(ConnectRequest)` when the
//! user connects (the loop exits and `main` execs ssh after the terminal is
//! restored), or `None` on quit.
//!
//! # Reentrancy-safe borrow (load-bearing)
//!
//! The loop borrows the terminal mutably ONLY for each `draw(…)` call — the
//! `RefMut` is dropped before any key read or side effect. The popup paths
//! (`connect_host`, `TuiPassphrase::confirm`, the store-switch popups) re-borrow
//! the terminal via the weak handle; because the loop's `RefMut` is already
//! released, their `borrow_mut()` succeeds instead of panicking.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEvent};
use sshrack_core::error::SshrackError;

use super::app::App;
use super::connect::connect_host;
use super::intent::{Outcome, Overlay};
use super::persist::{
    StoreSwitchTarget, fulfill_save_cred, persist_cred_delete, persist_host_delete,
    persist_host_save, persist_store_switch,
};
use super::prompt::TuiPassphrase;
use super::term::{TerminalHandle, Tui};
use super::ConnectRequest;

// (paste `fn enter_press` verbatim, widened to `pub(crate) fn enter_press`,
//  and `pub fn run_loop` verbatim, keeping the full doc comment.)
```

- [ ] **Step 2: Delete the moved fns from `app.rs`; clean imports**

Remove `enter_press` and `run_loop` from `src/tui/app.rs`. Re-run the unused-import sweep:
```bash
cargo build --workspace 2>&1 | rg 'warning: unused import'
```
After this task `app.rs` should no longer need `std::rc::Rc`, `std::cell::RefCell`, `std::time::Duration`, `crossterm::event::{event, Event}`, `super::term::{TerminalHandle, Tui}` (unless `impl App` still references `TerminalHandle` — e.g. some methods may take it; check before deleting each), `super::connect::connect_host`, or the `super::persist::*` block Task 4 added. Remove exactly the warnings the compiler reports — do not guess.

- [ ] **Step 3: Register + re-export in `mod.rs`**

In `src/tui/mod.rs`:
1. Add `pub mod run_loop;` to the declarations.
2. Change
   ```rust
   pub use app::{App, run_loop};
   ```
   to
   ```rust
   pub use app::App;
   pub use run_loop::run_loop;
   ```

- [ ] **Step 4: Move `stdout_tui` to `test_support.rs`**

The helper `fn stdout_tui -> Tui` is still defined inside `app.rs`'s test block. Move it to `src/tui/test_support.rs` as `pub(crate) fn stdout_tui() -> Tui` (with `use crate::tui::Tui;` via the mod.rs re-export), and delete the definition from `app.rs`. Add `stdout_tui` to the `use crate::tui::test_support::{…}` list in any `app.rs` test block that calls it.

- [ ] **Step 5: Move the borrow-regression tests into `run_loop.rs`**

These tests pin the reentrancy contract documented on `run_loop`, so they live with it. Move them verbatim into a `#[cfg(test)] mod tests` at the bottom of `run_loop.rs`:
- `popup_borrow_after_narrow_draw_borrow_does_not_panic`
- `wide_outer_borrow_then_popup_borrow_panics_regression_pin`

In that test block:
```rust
use crate::tui::test_support::{stdout_tui, dead_handle};
```
(plus whatever `use` lines the assertion bodies need — copy from the app.rs test block).

- [ ] **Step 6: Build + test + clippy + fmt**

```bash
cargo build --workspace && cargo test --bin sshrack
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```
Expected: green, same total test count as after Task 4.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(tui): extract event loop into run_loop module"
```

---

## Task 6: Finalize docs and verify the split

No code moves. Update the architecture docs to describe the new file layout, confirm every file is under the soft cap, and run the full gate.

**Files:**
- Modify: `CLAUDE.md` (the TUI module tree in the Architecture section + the "TUI (delivered)" section's file list)
- Modify: `src/tui/app.rs` (top-of-file `//!` doc — narrow it to describe only the App state machine now that terminal/event-loop/persist live elsewhere)
- Verify: all `src/tui/*.rs` file sizes.

- [ ] **Step 1: Rewrite `app.rs` module doc**

The current `//!` at the top of `app.rs` (lines 1–11 at baseline) says "TUI application state, key handling, terminal guard, and event loop." That now overstates the file's scope. Replace it with a doc focused on what remains:

```rust
//! The TUI state machine: [`App`] and its pure key-routing logic.
//!
//! [`App::on_key`] inspects a [`crossterm::event::KeyEvent`] and returns an
//! [`Outcome`][super::intent::Outcome] describing what should happen next — it
//! performs NO I/O, so the key logic is unit-testable without a terminal or
//! event source. Side effects (persist, connect, terminal ownership) live in
//! sibling modules: [`super::run_loop`] drives the loop, [`super::persist`]
//! holds the disk-writing functions, and [`super::term`] owns the RAII terminal
//! guard. [`App::draw`] renders the current state into a frame.
```

- [ ] **Step 2: Update the CLAUDE.md TUI module tree**

In `CLAUDE.md`'s Architecture section, the `src/tui/` tree currently lists `app.rs # top-level App: …`. Replace that block's `app.rs` line and add the four new modules so the tree matches reality. Update the one-line responsibility for `app.rs` to "App state machine + on_key (pure) + draw" and add lines for `term.rs`, `intent.rs`, `persist.rs`, `run_loop.rs` with their one-line responsibilities (copy the descriptions from this plan's "Target structure" section).

Also update the "TUI (delivered)" prose section if it describes `app.rs` as holding the terminal guard / event loop / persist — reword to "split across `term`/`intent`/`app`/`persist`/`run_loop`."

- [ ] **Step 3: Verify file sizes are under the 800-line soft cap**

```bash
wc -l src/tui/*.rs src/tui/wizard/*.rs | sort -rn
```
Expected: `app.rs` is now ~880 lines (the `impl App` block is large but single-purpose; this is acceptable — it is one cohesive type). `term.rs` ~100, `intent.rs` ~190, `persist.rs` ~600, `run_loop.rs` ~300, `test_support.rs` ~60. The pre-existing over-800 files (`launcher.rs` 1203, `wizard/host.rs` 1314, `wizard/cred.rs` 974) are OUT OF SCOPE — do not touch them.

If `app.rs` came out over ~950, the `impl App` block can be further split (draw vs routing) in a future plan — note it in the commit message but do NOT do it here (scope creep).

- [ ] **Step 4: Final full gate**

```bash
cargo build --workspace --release
cargo test --bin sshrack
cargo test -p sshrack-core
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green. Compare the `cargo test --bin sshrack` pass count to the baseline (capture baseline count at the start of Task 1) — it must be identical. Run `cargo test --bin sshrack -- --nocapture 2>&1 | tail` if unsure of the count.

- [ ] **Step 5: Behavior diff sanity check**

Confirm the refactor changed no behavior:
```bash
git diff main...HEAD --stat
```
The diff should be dominated by file additions/moves (`term.rs`, `intent.rs`, `persist.rs`, `run_loop.rs`, `test_support.rs` new; `app.rs` shrunk) and import-path rewrites. Spot-check that no function body logic changed:
```bash
git diff main...HEAD -- src/tui/app.rs | rg '^[+-]' | rg -v '^[+-]\s*use |^[+-]\s*//|^[+-]\s*$|^[+-]\s*///|^[+-]pub(super)|^[+-]pub\(crate\)'
```
The residual lines (after filtering out imports, comments, blank lines, and the visibility-only changes) should be near-empty — just block-delete/move artifacts. If a real logic line appears, investigate.

- [ ] **Step 6: Commit + branch finish**

```bash
git add -A
git commit -m "docs(tui): document app.rs split into term/intent/persist/run_loop modules"
```
Then use the `finishing-a-development-branch` skill to merge to `main` (fast-forward if possible).

---

## Self-Review (completed by planner)

- **Spec coverage:** The user's request was "split app.rs (~3800 lines, actually 4017)." Every line of `app.rs` is accounted for: terminal RAII → Task 2; `Outcome`/`Overlay`/`Status` → Task 3; `App` struct + `impl App` → stays in `app.rs`; `run_loop` + `enter_press` → Task 5; all `persist_*` + `StoreSwitchTarget` + helpers → Task 4; the ~1922-line test block → distributed to the file that owns the code under test (Tasks 4/5/6) via the shared `test_support` (Task 1). No line is orphaned.
- **Placeholder scan:** No "TBD"/"add error handling". `todo!(…)` appears in Task 1 Step 2 ONLY as a marker for "paste the verbatim body you copied from app.rs in Step 1" — each has a concrete source body to paste, and the step explicitly says a leftover `todo!` is a plan failure. No other placeholders.
- **Type consistency:** The cross-task contract block pins the exact module path and visibility of every type/fn (`crate::tui::term::Tui`, `crate::tui::intent::{Outcome,Overlay,Status}`, `crate::tui::persist::{persist_host_save,…}` all `pub`/`pub(crate)`; `App` fields `pub(super)`). Task 5's `use` list imports exactly the names Task 4 produces. `run_loop`'s signature is quoted verbatim. The eight `Status`/`Outcome`/`Overlay` import rewrites in Task 3 are enumerated file:line from a baseline ripgrep.
- **Risk note for the implementer:** Task 4 is the keystone — it widens `App` visibility AND moves the most code. If Task 4's "test count unchanged" check fails, the cause is almost always a `cred_add_*`/`cred_edit_*` test mis-classified as a persist test when it actually drives `on_key` (an App test). The step calls this out explicitly.
