# Context-Sensitive Help Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `F1` open a **context-sensitive** help overlay (the bindings of the surface the user is on, plus a shared "Everywhere" section — lazygit's `?` model), reachable from **every** surface (launcher / SFTP / wizard / picker / queue), by lifting Help out of the at-most-one `Overlay` enum into an independent global layer.

**Architecture:** Today `help.rs::help_lines()` is one static list covering only the launcher, and `Overlay::Help` sits in the `Overlay` enum (`intent.rs`) which is (a) toggled from `on_key` Layer 1 — so it never fires on the transfer screen (Layer 0 takes every key → `F1` is a dead key during SFTP), and (b) at-most-one, so pressing `F1` while a wizard is open **overwrites and drops the wizard form**. The fix: Help becomes `App::help: Option<HelpState>` where `HelpState { context: HelpContext, scroll: u16 }` — an independent global layer rendered on top of whatever is underneath. `F1` is handled at the very top of `on_key` (before Layer 0), so it is reachable everywhere and toggling it never touches the screen/overlay underneath. `help_lines(ctx)` returns one binding set per `HelpContext` (`Launcher{tab}` / `Sftp` / `WizardForm` / `FilePicker` / `StorePicker` / `QueueManager`).

**Tech Stack:** Rust 2024 (MSRV 1.88), ratatui 0.30 / crossterm, sshrack-core. Tests use the existing `app_with_host` harness + `TestBackend`/`insta` snapshots in `src/tui/help.rs` and the `on_key` purity tests in `src/tui/app.rs`.

## Global Constraints

- **English only** — all source, comments, doc comments, errors, help text, and commit messages.
- **Zero `unsafe`**; **zero `unwrap()`/`expect()` in production** (test-only is fine; the harness's `.expect("…")` are inside `#[test]`).
- **Clippy strict**: `cargo clippy --workspace --all-targets -- -D warnings` green before every commit.
- **Format**: `cargo fmt` green before every commit.
- **TDD**: write the failing test first, watch it RED, implement, watch it GREEN.
- **Hermetic tests**: no env mutation. CI runs tests under a pty (`script -qec "cargo test --workspace" /dev/null`); reproduce locally under a pty if a tty-backed test misbehaves.
- **No compatibility / ugly code** (dev stage): delete the old static `help_lines()`/`max_scroll(body)`/`draw_help_dialog(frame, scroll)` and the `Overlay::Help` variant in the same task that introduces the replacement — do not leave dual implementations or `#[allow(dead_code)]` stubs.
- **Conventional Commits**: `<type>(<scope>): <description>` with scope `tui` (or `docs` for Task 3's doc edit), **no `Co-Authored-By` trailer**, author `ryaningli`. Stage explicit paths (`git add <files>`).
- **F1 is a true global**: its handler lives at the very top of `App::on_key`, BEFORE the `self.transfer.take()` Layer-0 branch, so the transfer screen can no longer swallow it.
- **Help is modal**: while `self.help` is `Some`, scroll/dismiss keys are consumed at the top of `on_key` and every other key is swallowed (`Outcome::Continue`) — the surface underneath is frozen. This matches the old Help behavior and lazygit's `?`.
- **Launcher content is tab-aware**: `HelpContext::Launcher { tab }` drives the `Enter` noun and whether add/edit/delete rows appear (Settings has only `Enter`).
- **Never reimplement SSH**: this change is pure TUI state + render; it must not touch any `ssh`/`scp`/`sftp` spawning.

---

## File Structure

- `src/tui/help.rs` — **rewrite**: add `HelpContext`, `HelpState`, and ctx-parameterised `help_lines(ctx)` / `max_scroll(body, ctx)` / `draw_help_dialog(frame, ctx, scroll)`. Delete the old static `help_lines()` / `max_scroll(body)` / `draw_help_dialog(frame, scroll)`. (Task 1)
- `src/tui/intent.rs` — remove the `Help` variant from `Overlay`; update the enum doc. (Task 2)
- `src/tui/app.rs` — add `current_help_context()` (Task 1); replace `help_scroll: u16` with `help: Option<HelpState>`; move `F1` + Help-scroll handling to the top of `on_key` (global layer); delete the old Layer-1 `F1` block, the Layer-1.5 Help-scroll block, and the `Overlay::Help` arm of `route_overlay`; render Help at the top of `draw` (over both transfer and launcher); delete the `Overlay::Help` arm of `draw_overlay`. Update the `#[cfg(test)]` suite. (Tasks 1 + 2)
- `src/tui/transfer/screen.rs` — add `("F1", "help")` to `draw_footer`. (Task 3)
- `docs/tui.md` — update the Overlays / F1 description. (Task 3)

---

## Task 1: help.rs — context-sensitive content + `current_help_context`

Make `help_lines` carry a `HelpContext`, render the right bindings per surface, and have `App` compute that context. After this task Help content is fully context-correct on every surface where `F1` currently fires (launcher + overlays-over-launcher). The transfer-screen dead key and the wizard-overwrite hazard are fixed in Task 2 (architecture), not here.

**Files:**
- Modify: `src/tui/help.rs` (rewrite the public fns + tests).
- Modify: `src/tui/app.rs` — add `current_help_context()`; point the existing Help render + scroll-clamp call sites at it.

**Interfaces:**
- Consumes: `super::tab::Tab` (already `pub`); `App.overlay` / `App.transfer` / `App.active_tab` (all already `pub`/`pub(super)`); `HostForm.file_picker` / `CredForm.file_picker` / `TransferScreen.queue_overlay` (all already `pub`).
- Produces:
  - `pub enum HelpContext { Launcher{tab: Tab}, Sftp, WizardForm, FilePicker, StorePicker, QueueManager }`
  - `pub(crate) struct HelpState { pub(crate) context: HelpContext, pub(crate) scroll: u16 }` (Task 2 stores this on `App`; declared here in Task 1 so the type exists.)
  - `pub fn help_lines(ctx: &HelpContext) -> Vec<Line<'static>>`
  - `pub fn max_scroll(body_height: u16, ctx: &HelpContext) -> u16`
  - `pub fn draw_help_dialog(frame: &mut Frame, ctx: &HelpContext, scroll: u16)`
  - `App::current_help_context(&self) -> HelpContext`

- [ ] **Step 1: Rewrite `src/tui/help.rs`**

Replace the entire file body (keep it the only producer of Help text). Use this verbatim:

```rust
//! Help overlay (`F1`): a centered dialog with a **context-sensitive**
//! keybinding reference. The bindings follow the surface the user opened Help
//! from (launcher tab / SFTP / wizard / picker / queue) plus a shared
//! "Everywhere" section — the lazygit `?` model, not one static list. Dismiss
//! and scroll handling live in [`super::app::App::on_key`]'s global Help layer.
//!
//! The text is static per context (no live state beyond which surface is open),
//! so this module is pure render + a pure context→lines table.

use ratatui::{
    Frame,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::dialog::draw_dialog;
use super::tab::Tab;

/// Which surface the user is on when they open Help (`F1`). Help is
/// context-sensitive: each surface shows its own bindings plus the shared
/// "Everywhere" section, instead of one static list that is wrong for most
/// surfaces. Snapshotted at open time ([`App::current_help_context`]) so
/// scrolling does not re-read live state.
///
/// [`App::current_help_context`]: super::app::App::current_help_context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpContext {
    /// The launcher shell. `tab` picks the `Enter` noun and whether
    /// add/edit/delete apply (Settings has only `Enter`).
    Launcher { tab: Tab },
    /// The full-screen SFTP transfer view (dual pane).
    Sftp,
    /// A host/credential wizard form (add/edit overlay).
    WizardForm,
    /// The identity-key path picker (nested inside a wizard form).
    FilePicker,
    /// The storage-mode picker (Settings → Enter).
    StorePicker,
    /// The transfer queue-manager overlay (`Ctrl-Q` inside the SFTP screen).
    QueueManager,
}

/// The live Help overlay: which surface it documents + how far it has scrolled.
/// An independent global layer on `App` (NOT inside the at-most-one `Overlay`
/// enum), so opening Help never disturbs the screen/overlay underneath and
/// `F1` is reachable from every surface.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HelpState {
    pub(crate) context: HelpContext,
    pub(crate) scroll: u16,
}

/// Bold section heading.
fn section(heading: &'static str) -> Line<'static> {
    Line::from(vec![Span::styled(
        heading,
        Style::new().add_modifier(Modifier::BOLD),
    )])
}

/// One keybinding row: `  <key padded to 14>` + description. Bare letters and
/// digits never appear as a binding key here — they reach the search box.
fn binding(k: &'static str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {k:<14}"), Style::new()),
        Span::raw(desc.to_string()),
    ])
}

/// The shared footer: keys available on every surface.
fn everywhere_section() -> Vec<Line<'static>> {
    vec![
        Line::from(""),
        section("Everywhere"),
        binding("F1", "open / close this help"),
    ]
}

/// Launcher bindings. `Enter` and the add/edit/delete nouns follow `tab`;
/// Settings has only `Enter`.
fn launcher_lines(tab: Tab) -> Vec<Line<'static>> {
    let (enter, noun) = match tab {
        Tab::Hosts => ("connect to the selected host", "host"),
        Tab::Credentials => ("edit the selected credential", "credential"),
        Tab::Settings => ("edit the storage-mode row", ""),
    };
    let mut v = vec![
        section("Tabs"),
        binding("Tab / Shift-Tab", "cycle tabs (Hosts / Credentials / Settings)"),
        binding("type", "filter the active panel's search box"),
        binding("Up / Down", "move selection (wraps)"),
        binding("Ctrl-N / Ctrl-P", "move selection (wraps)"),
        Line::from(""),
        section(match tab {
            Tab::Hosts => "Hosts panel",
            Tab::Credentials => "Credentials panel",
            Tab::Settings => "Settings panel",
        }),
        binding("Enter", enter),
    ];
    if !noun.is_empty() {
        v.push(binding("Ctrl-A", &format!("add a {noun}")));
        v.push(binding("Ctrl-E", &format!("edit the selected {noun}")));
        v.push(binding("Ctrl-D", &format!("delete the selected {noun} (confirm)")));
    }
    v
}

fn sftp_lines() -> Vec<Line<'static>> {
    vec![
        section("SFTP transfer"),
        binding("Tab", "switch pane (focus = direction)"),
        binding("Up / Down", "move selection"),
        binding("Left", "up to the parent directory"),
        binding("Right", "open the selected directory"),
        binding("Space", "mark entry (batch, single-shot)"),
        binding("Ctrl-S", "transfer marked/selected (dirs recurse)"),
        binding("Enter", "file: enqueue · directory: enter"),
        binding("Ctrl-Q", "queue manager (retry / remove / cancel)"),
        binding("Esc", "cancel in-flight transfer · close"),
        binding("Ctrl-C", "close"),
    ]
}

fn wizard_lines() -> Vec<Line<'static>> {
    vec![
        section("Form wizard"),
        binding("Tab / Shift-Tab", "next / previous field"),
        binding("Up / Down", "cycle a chooser field's options"),
        binding("type", "edit the focused text field"),
        binding("Ctrl-S", "save (validates first)"),
        binding("Esc / Ctrl-C", "cancel, return to the tab"),
        Line::from(""),
        section("Field hints"),
        binding("▸", "trigger (chooser / picker / password)"),
        binding("¶▸", "multi-line text (paste large values)"),
    ]
}

fn file_picker_lines() -> Vec<Line<'static>> {
    vec![
        section("File picker"),
        binding("Up / Down", "move selection"),
        binding("type", "filter the path list"),
        binding("Right", "enter the selected directory"),
        binding("Enter", "resolve path (dir enters · file picks)"),
        binding("Esc / Ctrl-C", "cancel, return to the form"),
    ]
}

fn store_picker_lines() -> Vec<Line<'static>> {
    vec![
        section("Storage mode"),
        binding("Up / Down", "select a mode"),
        binding("Enter", "switch to the selected mode"),
        binding("Esc / Ctrl-C", "cancel"),
    ]
}

fn queue_manager_lines() -> Vec<Line<'static>> {
    vec![
        section("Queue manager"),
        binding("Tab / Shift-Tab", "cycle view (Active / Failed / Done)"),
        binding("Up / Down · j / k", "move selection"),
        binding("Enter · r", "retry the selected task"),
        binding("d · Delete", "remove the selected task"),
        binding("c", "cancel the in-flight task"),
        binding("Esc", "close"),
    ]
}

/// The full keybinding reference for `ctx`, ending with the shared "Everywhere"
/// section. Pure: the context→lines table is static.
pub fn help_lines(ctx: &HelpContext) -> Vec<Line<'static>> {
    let mut body = match ctx {
        HelpContext::Launcher { tab } => launcher_lines(*tab),
        HelpContext::Sftp => sftp_lines(),
        HelpContext::WizardForm => wizard_lines(),
        HelpContext::FilePicker => file_picker_lines(),
        HelpContext::StorePicker => store_picker_lines(),
        HelpContext::QueueManager => queue_manager_lines(),
    };
    body.append(&mut everywhere_section());
    body
}

/// Max scroll offset that still shows the last line for `ctx`, given the body
/// height the dialog actually got. Returns 0 when the body fits every line;
/// otherwise the number of lines hidden past the bottom. Pure.
pub fn max_scroll(body_height: u16, ctx: &HelpContext) -> u16 {
    let lines = help_lines(ctx).len() as u16;
    lines.saturating_sub(body_height)
}

/// Render the Help overlay for `ctx` as a centered dialog: titled bordered
/// area + `↑↓ scroll` / `F1/Esc close` footer, bindings left-aligned in the
/// body, scrolled by `scroll` rows (clamped to [`max_scroll`] of the rendered
/// body height so it never scrolls past the last line). Pure render.
pub fn draw_help_dialog(frame: &mut Frame, ctx: &HelpContext, scroll: u16) {
    let lines = help_lines(ctx);
    let body = draw_dialog(
        frame,
        " help ",
        lines.len() as u16,
        &[("↑↓", "scroll"), ("F1/Esc", "close")],
    );
    let clamped = scroll.min(max_scroll(body.height, ctx));
    frame.render_widget(Paragraph::new(lines).scroll((clamped, 0)), body);
}

#[cfg(test)]
mod tests {
    //! The overlay is pure render; pin that each context documents its own
    //! key surface, that the "Everywhere" footer and the dismiss hint are
    //! always present, that the removed single-char hotkeys never reappear,
    //! and that `max_scroll` + `draw_help_dialog` clamp scroll without panicking.

    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn joined(ctx: &HelpContext) -> String {
        help_lines(ctx)
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn launcher_help_follows_the_active_tab() {
        let hosts = joined(&HelpContext::Launcher { tab: Tab::Hosts });
        assert!(hosts.contains("connect to the selected host"));
        assert!(hosts.contains("add a host") && hosts.contains("delete the selected host (confirm)"));

        let creds = joined(&HelpContext::Launcher {
            tab: Tab::Credentials,
        });
        assert!(creds.contains("edit the selected credential"));
        assert!(creds.contains("add a credential"));

        let settings = joined(&HelpContext::Launcher {
            tab: Tab::Settings,
        });
        assert!(settings.contains("edit the storage-mode row"));
        // Settings has no add/edit/delete — those nouns must not leak in.
        assert!(!settings.contains("add a host"));
        assert!(!settings.contains("add a credential"));
    }

    #[test]
    fn sftp_help_documents_the_transfer_bindings() {
        let s = joined(&HelpContext::Sftp);
        assert!(s.contains("switch pane (focus = direction)"));
        assert!(s.contains("transfer marked/selected (dirs recurse)"));
        assert!(s.contains("queue manager"));
    }

    #[test]
    fn wizard_help_documents_save_and_field_hints() {
        let w = joined(&HelpContext::WizardForm);
        assert!(w.contains("save (validates first)"));
        assert!(w.contains("multi-line text"));
    }

    #[test]
    fn each_overlay_context_has_its_own_bindings() {
        assert!(joined(&HelpContext::FilePicker).contains("filter the path list"));
        assert!(joined(&HelpContext::StorePicker).contains("switch to the selected mode"));
        assert!(joined(&HelpContext::QueueManager).contains("retry the selected task"));
    }

    #[test]
    fn every_context_carries_the_everywhere_footer_and_dismiss_hint() {
        for ctx in [
            HelpContext::Launcher { tab: Tab::Hosts },
            HelpContext::Sftp,
            HelpContext::WizardForm,
            HelpContext::FilePicker,
            HelpContext::StorePicker,
            HelpContext::QueueManager,
        ] {
            let j = joined(&ctx);
            assert!(j.contains("Everywhere"), "{ctx:?} missing Everywhere section");
            assert!(
                j.contains("open / close this help"),
                "{ctx:?} missing F1 dismiss hint"
            );
        }
    }

    #[test]
    fn help_keeps_bare_chars_out_of_bindings() {
        // The no-bare-hotkey invariant: `c`, `?`, `F2`, `Shift-C` never appear
        // as standalone binding keys (they reach the search box).
        let j = joined(&HelpContext::Launcher {
            tab: Tab::Hosts,
        });
        assert!(!j.contains("Shift-C"));
        assert!(!j.contains("\n  c             "));
    }

    #[test]
    fn max_scroll_is_zero_when_body_fits_all_lines() {
        let ctx = HelpContext::Launcher { tab: Tab::Hosts };
        assert_eq!(max_scroll(200, &ctx), 0);
    }

    #[test]
    fn max_scroll_is_excess_lines_when_body_too_short() {
        let ctx = HelpContext::Launcher { tab: Tab::Hosts };
        let lines = help_lines(&ctx).len() as u16;
        assert_eq!(max_scroll(lines - 5, &ctx), 5);
    }

    #[test]
    fn draw_help_dialog_renders_without_panic_for_every_context() {
        for ctx in [
            HelpContext::Launcher { tab: Tab::Hosts },
            HelpContext::Sftp,
            HelpContext::WizardForm,
            HelpContext::FilePicker,
            HelpContext::StorePicker,
            HelpContext::QueueManager,
        ] {
            let backend = TestBackend::new(100, 40);
            let mut term = Terminal::new(backend).unwrap();
            term.draw(|f| {
                draw_help_dialog(f, &ctx, 0);
                draw_help_dialog(f, &ctx, 999);
            })
            .unwrap();
        }
    }
}
```

- [ ] **Step 2: Add `App::current_help_context` and wire the existing call sites**

In `src/tui/app.rs`:

(a) Ensure the help imports cover the new items. Find the existing `use super::help::…` line (the file already imports `draw_help_dialog`) and make it:

```rust
use super::help::{HelpContext, draw_help_dialog, help_lines, max_scroll};
```

(b) Add this method on `impl App` (place it next to `active_tab`, around line 215):

```rust
    /// Snapshot which surface the user is on, so `F1` can show the right
    /// keybinding set. Read once when Help opens and carried inside
    /// [`HelpState`][super::help::HelpState] so scrolling does not re-read
    /// live state. Order matters: the queue overlay is a child of the transfer
    /// screen, and the file picker is a child of a wizard form.
    pub(super) fn current_help_context(&self) -> HelpContext {
        use super::intent::Overlay;
        if let Some(screen) = self.transfer.as_ref() {
            if screen.queue_overlay.is_some() {
                return HelpContext::QueueManager;
            }
            return HelpContext::Sftp;
        }
        if let Some(ov) = &self.overlay {
            return match ov {
                Overlay::HostWizard(f) if f.file_picker.is_some() => HelpContext::FilePicker,
                Overlay::CredWizard(f) if f.file_picker.is_some() => HelpContext::FilePicker,
                Overlay::HostWizard(_) | Overlay::CredWizard(_) => HelpContext::WizardForm,
                Overlay::StorePicker => HelpContext::StorePicker,
            };
        }
        HelpContext::Launcher {
            tab: self.active_tab,
        }
    }
```

> Note: `Overlay` is already imported at the top of `app.rs`; the inline `use super::intent::Overlay;` is a safety net — if the file already imports `Overlay` in scope, drop the inline `use` to avoid an unused-import warning. Prefer matching the file's existing idiom.

(c) Point the two existing static-`help_lines()` call sites at the context. In `draw_overlay`'s `Overlay::Help` arm (around line 1144):

```rust
            Overlay::Help => draw_help_dialog(frame, &self.current_help_context(), self.help_scroll),
```

And in the Layer-1.5 scroll clamp (around line 667):

```rust
            let m = help_lines(&self.current_help_context()).len() as u16;
```

- [ ] **Step 3: Run the new help.rs tests (GREEN) and the workspace build**

Run: `cargo test -p sshrack help::`
Expected: the 9 new tests pass.

Run: `cargo build --workspace`
Expected: clean build (the old static `help_lines()`/`max_scroll`/`draw_help_dialog` are gone; every call site now passes a `HelpContext`).

- [ ] **Step 4: Update the `app.rs` Help tests that referenced the old shape**

The `#[cfg(test)]` suite in `app.rs` calls the old `help_lines()` (no args) in a few spots (e.g. around the scroll tests near line 1945+). Change every such call to `help_lines(&HelpContext::Launcher { tab: Tab::Hosts })` (import `HelpContext` and `Tab` in the test module — `Tab` is already in scope via `super::*`; add `use crate::tui::help::HelpContext;`). The tests that assert on `Overlay::Help` / `help_scroll` still work after Task 1 (those symbols still exist) — only the `help_lines()` call sites change here. Leave the `Overlay::Help` assertions in place; Task 2 rewrites them.

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 5: Lint + format**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings.

Run: `cargo fmt`
Expected: no diff (or apply it).

- [ ] **Step 6: Commit**

```bash
git add src/tui/help.rs src/tui/app.rs
git commit -m "refactor(tui): make help content context-sensitive

help_lines/max_scroll/draw_help_dialog now take a HelpContext (Launcher{tab}
/ Sftp / WizardForm / FilePicker / StorePicker / QueueManager) and render that
surface's bindings plus a shared 'Everywhere' section — the lazygit '?' model,
not one static launcher-only list. App::current_help_context snapshots the
active surface (transfer → Sftp, queue overlay → QueueManager, wizard with a
file picker → FilePicker, etc.). The Help overlay is still toggled from the old
Layer-1 path for now; Task 2 lifts it to a true global layer and fixes the
SFTP dead key + the wizard-overwrite hazard."
```

---

## Task 2: Lift Help to an independent global layer (fix the SFTP dead key + the wizard-overwrite hazard)

Remove `Overlay::Help`, store Help as `App::help: Option<HelpState>`, handle `F1` + Help scrolling at the very top of `on_key` (reachable from every surface), and render Help at the top of `draw` over both the transfer screen and the launcher. This is an atomic refactor: the enum variant, the field, the route arms, the render arm, and the tests all change in one commit because removing `Overlay::Help` breaks every reference at once.

**Files:**
- Modify: `src/tui/intent.rs` — drop `Help` from `Overlay`.
- Modify: `src/tui/app.rs` — field, `new()`, `on_key` top-of-function global Help layer, delete the old Layer-1 `F1` block + Layer-1.5 scroll block + `route_overlay` Help arm + `draw_overlay` Help arm, render Help at top of `draw`, rewrite the Help tests + add new ones.
- Modify: `src/tui/transfer/screen.rs` — no change here in Task 2 (the global handler lives in `App::on_key`, before the screen sees the key).

**Interfaces:**
- Consumes: `help::{HelpContext, HelpState, draw_help_dialog, help_lines, max_scroll}` (from Task 1), `App::current_help_context` (from Task 1).
- Produces: `App::help: Option<HelpState>` (`pub(super)`); the new global Help behavior.

- [ ] **Step 1: Write the failing tests for the new global Help behavior**

Add these tests to the `#[cfg(test)]` module in `src/tui/app.rs` (near the existing Help tests around line 1880+). They use the existing `app_with_host` / `press` helpers and `TransferScreen::new` (already used in `run_loop.rs` tests — import via `use crate::tui::transfer::screen::TransferScreen;` and `use std::path::PathBuf;` in the test module).

```rust
    #[test]
    fn f1_opens_help_with_launcher_context_on_hosts_tab() {
        let mut app = app_with_host("web");
        assert!(app.help.is_none(), "Help starts closed");
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        let help = app
            .help
            .as_ref()
            .expect("F1 must open Help from the launcher");
        assert_eq!(
            help.context,
            crate::tui::help::HelpContext::Launcher {
                tab: crate::tui::tab::Tab::Hosts
            }
        );
        assert_eq!(help.scroll, 0, "Help opens at the top");
    }

    #[test]
    fn f1_toggles_help_closed_on_a_second_press() {
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        assert!(app.help.is_some());
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        assert!(app.help.is_none(), "a second F1 closes Help");
    }

    #[test]
    fn f1_opens_help_from_the_transfer_screen_fixing_the_dead_key() {
        // The transfer screen takes every key in Layer 0; before this task F1
        // never reached the global handler, so it was a dead key during SFTP.
        let mut app = app_with_host("web");
        let screen =
            TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote"));
        app.transfer = Some(screen);
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        let help = app
            .help
            .as_ref()
            .expect("F1 must open Help from the transfer screen");
        assert_eq!(
            help.context,
            crate::tui::help::HelpContext::Sftp,
            "Help on the transfer screen must document SFTP bindings"
        );
        // The transfer screen must still be intact underneath.
        assert!(app.transfer.is_some(), "opening Help must not close transfer");
    }

    #[test]
    fn f1_does_not_disturb_an_open_wizard() {
        // Before this task, F1 sat in the at-most-one Overlay enum, so pressing
        // it with a wizard open OVERWROTE and dropped the form. Help is now an
        // independent layer, so the wizard survives.
        let mut app = app_with_host("web");
        app.open_host_wizard_add();
        assert!(app.overlay.is_some(), "fixture: wizard is open");
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        assert!(app.help.is_some(), "F1 opens Help");
        assert!(
            app.overlay.is_some(),
            "the wizard must still be open underneath Help"
        );
        assert_eq!(
            app.help.as_ref().unwrap().context,
            crate::tui::help::HelpContext::WizardForm,
            "Help over a wizard must document the wizard form"
        );
    }

    #[test]
    fn help_is_modal_unknown_keys_are_swallowed() {
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        // A random printable while Help is up must NOT reach the launcher query.
        let before = app.launcher_query().to_string();
        app.on_key(press(KeyCode::Char('x'), KeyModifiers::NONE));
        assert_eq!(app.launcher_query(), before, "Help is modal: 'x' is swallowed");
        assert!(app.help.is_some(), "unknown key does not close Help");
    }

    #[test]
    fn help_dismiss_keys_are_f1_esc_q_and_ctrl_c() {
        let dismiss = |code: KeyCode, mods: KeyModifiers| {
            let mut app = app_with_host("web");
            app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
            assert!(app.help.is_some());
            app.on_key(press(code, mods));
            assert!(app.help.is_none(), "{code:?} must close Help");
        };
        dismiss(KeyCode::F(1), KeyModifiers::NONE);
        dismiss(KeyCode::Esc, KeyModifiers::NONE);
        dismiss(KeyCode::Char('q'), KeyModifiers::NONE);
        dismiss(KeyCode::Char('c'), KeyModifiers::CONTROL);
    }

    #[test]
    fn help_scroll_keys_bump_help_state_scroll() {
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        app.on_key(press(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.help.as_ref().unwrap().scroll, 1);
        app.on_key(press(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.help.as_ref().unwrap().scroll, 0, "Up saturates at 0");
    }
```

> The `app.launcher_query()` helper may not exist by that name. If not, read the query via the existing accessor used elsewhere in the test module (search for how other tests inspect the launcher query string, e.g. `active_panel_query` is private — instead assert via a panel accessor that already exists, or add a tiny `pub(super) fn launcher_query(&self) -> &str` accessor next to `active_panel_query` and use it). Keep the assertion intent (the modal swallows the key).

- [ ] **Step 2: Run the new tests to verify they FAIL (RED)**

Run: `cargo test --workspace f1_opens_help_from_the_transfer_screen f1_does_not_disturb_an_open_wizard help_is_modal_unknown_keys`
Expected: FAIL — `app.help` does not exist yet (compile error) is acceptable RED; once the field compiles, the transfer/wizard/modal assertions fail because the old Layer-1 path still can't reach the transfer screen and still overwrites the wizard.

- [ ] **Step 3: Remove `Help` from the `Overlay` enum**

In `src/tui/intent.rs`, delete the `Help` variant and update the enum doc. The enum becomes:

```rust
/// An overlay layered on top of the shell. The shell keeps rendering behind it
/// (no dark scrim — terminals cannot do translucency; [`draw_dialog`] clears
/// the dialog area instead). At most one overlay is open at a time.
///
/// Help is NOT here: it is an independent global layer (`App::help`) so `F1`
/// can overlay ANY surface (launcher, transfer, even this overlay) without
/// disturbing it, and so `F1` is reachable from the transfer screen.
///
/// `Clone`: `on_key` `take()`s the overlay to route a key into it without a
/// borrow conflict, then stashes it back unless the overlay signaled a
/// terminal outcome (save / cancel). Carrying the wizard forms inside their
/// variants keeps the form state alive across keystrokes without a separate
/// `Option<HostForm>` field.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum Overlay {
    /// Host add/edit wizard. The form lives inside the overlay so its state
    /// survives across keystrokes.
    HostWizard(HostForm),
    /// Credential add/edit wizard.
    CredWizard(CredForm),
    /// Storage-mode picker (opened from Settings).
    StorePicker,
}
```

- [ ] **Step 4: Replace the `help_scroll` field with `help: Option<HelpState>`**

In `src/tui/app.rs`:

(a) Update the `use super::help::…` import to include `HelpState`:

```rust
use super::help::{HelpContext, HelpState, draw_help_dialog, help_lines, max_scroll};
```

(b) In the `App` struct (around line 100-107), replace the `help_scroll` field and its doc comment with:

```rust
    /// The independent global Help overlay (`F1`), layered on top of whatever
    /// surface is underneath (launcher, transfer, or another overlay). `None`
    /// when Help is closed. Carrying the context here means scrolling does not
    /// re-read live state; opening Help snapshots the surface via
    /// [`current_help_context`](Self::current_help_context).
    pub(super) help: Option<HelpState>,
```

(c) In `App::new` (around line 185), replace `help_scroll: 0,` with `help: None,`.

- [ ] **Step 5: Add the global Help layer at the top of `on_key`**

In `src/tui/app.rs`, insert this block immediately AFTER the existing `use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};` line at the top of `pub fn on_key` (app.rs:591) and BEFORE the `if let Some(screen) = self.transfer.take()` Layer-0 branch (app.rs:599). Do NOT add a second `use` — `KeyCode`/`KeyEventKind`/`KeyModifiers` are already in scope from the line above. Then delete the old Layer-1 `F1` block (the `if key.kind == KeyEventKind::Press && key.modifiers.is_empty() && key.code == KeyCode::F(1)` block around lines 637-649) and the entire Layer-1.5 Help-scroll block (the `if … matches!(o, Overlay::Help) { … }` block around lines 651-687).

```rust
        // Global Help layer — independent of the screen/overlay stack. F1
        // toggles it from EVERY surface (launcher, transfer, overlays); while
        // open, Help is modal — scroll/dismiss keys are consumed here and all
        // other keys are swallowed so the surface underneath is frozen. This
        // block sits above Layer 0 (transfer) so the transfer screen can no
        // longer swallow F1 (the old SFTP dead key), and Help is stored on
        // `self.help` (not in the at-most-one Overlay enum) so opening it never
        // disturbs what is underneath (the old wizard-overwrite hazard).
        if let Some(h) = self.help.as_mut() {
            if key.kind != KeyEventKind::Press {
                return Outcome::Continue;
            }
            let ctrl_c = key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c');
            match key.code {
                KeyCode::F(1) | KeyCode::Esc | KeyCode::Char('q')
                    if key.modifiers.is_empty() =>
                {
                    self.help = None;
                    return Outcome::Continue;
                }
                KeyCode::Char('c') if ctrl_c => {
                    self.help = None;
                    return Outcome::Continue;
                }
                KeyCode::Down | KeyCode::Char('j') if key.modifiers.is_empty() => {
                    let m = help_lines(&h.context).len() as u16;
                    h.scroll = h.scroll.saturating_add(1).min(m);
                    return Outcome::Continue;
                }
                KeyCode::Up | KeyCode::Char('k') if key.modifiers.is_empty() => {
                    h.scroll = h.scroll.saturating_sub(1);
                    return Outcome::Continue;
                }
                KeyCode::PageDown if key.modifiers.is_empty() => {
                    let m = help_lines(&h.context).len() as u16;
                    h.scroll = h.scroll.saturating_add(5).min(m);
                    return Outcome::Continue;
                }
                KeyCode::PageUp if key.modifiers.is_empty() => {
                    h.scroll = h.scroll.saturating_sub(5);
                    return Outcome::Continue;
                }
                _ => return Outcome::Continue, // modal: swallow every other key
            }
        }
        // F1 opens Help (none open yet) — from any surface. Snapshot the
        // active surface so the right binding set shows.
        if key.kind == KeyEventKind::Press && key.modifiers.is_empty() && key.code == KeyCode::F(1)
        {
            self.help = Some(HelpState {
                context: self.current_help_context(),
                scroll: 0,
            });
            return Outcome::Continue;
        }
```

Leave the rest of `on_key` (Layer 0 transfer, the Ctrl-C / Ctrl-T globals — now without the deleted F1 block, Layer 2 overlay, Layer 3 panel) unchanged.

- [ ] **Step 6: Delete the `Overlay::Help` arm from `route_overlay`**

In `src/tui/app.rs` `route_overlay` (around line 707-726), remove the `Overlay::Help => { … }` arm entirely. The remaining arms are `HostWizard`, `CredWizard`, `StorePicker`.

- [ ] **Step 7: Render Help at the top of `draw`; drop the `Overlay::Help` render arm**

In `src/tui/app.rs`:

(a) `App::draw` (around line 1071): change the transfer branch from an early `return` to an `else`, and render Help after both branches. The new shape:

```rust
    pub fn draw(&self, frame: &mut Frame) {
        if let Some(screen) = self.transfer.as_ref() {
            screen.draw(frame, frame.area());
        } else {
            let area = frame.area();
            let footer = self.footer_hints();
            let panel_area = draw_shell(frame, area, self.active_tab, &footer);
            match self.active_tab {
                Tab::Hosts => self.launcher.draw_in_shell(
                    frame,
                    panel_area,
                    &self.config.hosts,
                    &self.frecency,
                    &self.config.credentials,
                    &self.status,
                    self.overlay.is_none(),
                ),
                Tab::Credentials => self.cred_panel.draw_in_shell(
                    frame,
                    panel_area,
                    &self.config.credentials,
                    &self.status,
                    self.overlay.is_none(),
                ),
                Tab::Settings => self.settings_panel.draw_in_shell(
                    frame,
                    panel_area,
                    self.current_store_mode_label(),
                    &self.status,
                ),
            }
            if let Some(ov) = &self.overlay {
                self.draw_overlay(frame, ov);
            }
        }
        // Help is a global layer over EVERYTHING (launcher, transfer, overlays).
        if let Some(h) = &self.help {
            draw_help_dialog(frame, &h.context, h.scroll);
        }
    }
```

(b) `draw_overlay` (around line 1142): delete the `Overlay::Help => draw_help_dialog(...)` arm. The remaining arms are `HostWizard`, `CredWizard`, `StorePicker`.

- [ ] **Step 8: Update the `footer_hints` doc / no behavior change, but verify `F1` is still advertised**

`footer_hints` already lists `("F1", "help")` for every launcher tab. Leave it. (Task 3 adds the same hint to the transfer footer.)

- [ ] **Step 9: Rewrite the old Help tests in `app.rs`**

The existing Help tests assert on `Overlay::Help` and `help_scroll`. Rewrite them to the new model (assert on `app.help`). Specifically:

- `ctrl_c_in_help_overlay_closes_it_instead_of_quitting` → rename to `ctrl_c_in_help_closes_it_instead_of_quitting`: open Help with `F1`, press `Ctrl-C`, assert `app.help.is_none()` and that the app did not quit (`should_quit` false / outcome `Continue`).
- `help_dismiss_keys_are_f1_esc_and_q` → replaced by the new `help_dismiss_keys_are_f1_esc_q_and_ctrl_c` from Step 1 (delete the old one to avoid duplication).
- `help_other_keys_continue_without_dismissing` → rename to `help_is_modal_unknown_keys_are_swallowed` (the new Step 1 test covers this; delete the old).
- `help_release_events_are_ignored` → keep, but open Help via `F1` and assert a Release event leaves `app.help` `Some` and scroll unchanged.
- The scroll tests (`help_down_increments_scroll_and_keeps_overlay_open`, `help_j_increments_scroll_like_down`, `help_up_at_zero_saturates_to_zero`, `help_k_after_j_decrements_scroll_like_up`, `help_page_down_jumps_five_then_clamps_to_max`, `help_page_up_after_page_down_decrements_five_saturating`, `help_down_does_not_clamp_below_page_down_cap`, `help_scroll_reaches_past_old_cap_of_ten`, `help_scroll_keys_ignore_modifier_combos`, `help_scroll_keys_do_not_dismiss_overlay`, `help_esc_still_closes_after_scrolling`, `help_q_still_closes_after_scrolling`) → rewrite each to open Help with `F1`, then assert on `app.help.as_ref().unwrap().scroll` (and `app.help.is_some()` for the "keeps open" / "does not dismiss" checks) instead of `app.help_scroll` / `matches!(app.overlay(), Some(Overlay::Help))`.
- Every assertion of the form `matches!(app.overlay(), Some(Overlay::Help))` or `matches!(outcome, Outcome::OpenOverlay(Overlay::Help))` (around lines 1281, 1800, 1826-1827, 1873-1874, 1947) → replace with `app.help.is_some()` (F1 no longer returns an `OpenOverlay` outcome; it sets `self.help` and returns `Continue`).

For each rewritten test, open Help with `app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));` instead of the old direct overlay setup.

- [ ] **Step 10: Run the full Help test set (GREEN)**

Run: `cargo test --workspace` (the `f1_*` / `help_*` tests plus the rewritten ones).
Expected: all pass.

- [ ] **Step 11: Lint + format**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings (in particular no `dead_code` for the removed `Overlay::Help`).

Run: `cargo fmt`
Expected: no diff (or apply it).

- [ ] **Step 12: Full workspace suite under a pty**

Run: `script -qec "cargo test --workspace" /dev/null`
Expected: all green, 0 failed. The single pre-existing ignored test is `sftp_round_trip_local_sshd` (needs a live sshd) — unchanged.

- [ ] **Step 13: Commit**

```bash
git add src/tui/intent.rs src/tui/app.rs
git commit -m "fix(tui): make F1 a true global Help layer over every surface

Help leaves the at-most-one Overlay enum and becomes App::help:
Option<HelpState>, an independent global layer. F1 is now handled at the very
top of on_key — BEFORE the transfer screen's Layer-0 key grab — so it is
reachable from the SFTP screen (previously a dead key), and opening Help no
longer overwrites an open wizard form (previously dropped the form, because
Help sat in the same at-most-one enum). Help renders on top of whatever is
underneath (launcher, transfer, overlay). While open it is modal: scroll and
dismiss keys are consumed, all other keys are swallowed."
```

---

## Task 3: Advertise `F1` in the SFTP footer + update the docs

The transfer footer never mentioned Help, so the new global `F1` is invisible there. Add the hint, and bring `docs/tui.md` in line with the context-sensitive, global-Help model.

**Files:**
- Modify: `src/tui/transfer/screen.rs` — `draw_footer` hints.
- Modify: `docs/tui.md` — the Overlays paragraph.

**Interfaces:**
- Consumes: nothing new.
- Produces: a footer hint row; current docs.

- [ ] **Step 1: Add the `F1` hint to the transfer footer**

In `src/tui/transfer/screen.rs` `draw_footer` (around line 528), append `("F1", "help")` to the `hints` slice:

```rust
        let hints: &[(&str, &str)] = &[
            ("Tab", "switch"),
            ("↑↓", "move"),
            ("←", "up"),
            ("→", "open"),
            ("Space", "mark"),
            ("^S", "transfer"),
            ("^Q", "queue"),
            ("Esc", "cancel"),
            ("^C", "close"),
            ("F1", "help"),
        ];
```

- [ ] **Step 2: Write / update the footer test**

If `draw_footer` has an existing snapshot or content test, update its baseline. If not, add a small test in `screen.rs`'s `#[cfg(test)]` module (or assert via a `TestBackend` draw) that the rendered footer contains the `F1` hint. Simplest hermetic form — render the screen and assert the footer paragraph text contains `"F1"`:

```rust
    #[test]
    fn transfer_footer_advertises_f1_help() {
        use ratatui::{Terminal, backend::TestBackend};
        let backend = TestBackend::new(120, 24);
        let mut term = Terminal::new(backend).unwrap();
        let screen = TransferScreen::new(
            std::path::PathBuf::from("/local"),
            std::path::PathBuf::from("/remote"),
        );
        term.draw(|f| screen.draw(f, f.area())).unwrap();
        // The footer is the last row; scan the whole buffer for the hint.
        let buf = term.backend().buffer().clone();
        let text: String = (0..buf.area.height)
            .flat_map(|y| {
                (0..buf.area.width).map(move |x| buf[(x, y)].symbol().to_string())
            })
            .collect();
        assert!(text.contains("F1"), "footer must advertise F1 help, got: {text}");
    }
```

> If `TransferScreen::new` is not accessible from the test module or the buffer-cell iteration differs from the helper used elsewhere in `screen.rs` tests, follow the file's existing footer/render test idiom instead — the assertion intent (the footer now shows `F1`) is what must be pinned.

- [ ] **Step 3: Update `docs/tui.md`**

In the `## Overlays` paragraph, update the sentence that describes the F1 help reference so it reflects the new model. Replace the clause that calls Help a static keymap reference with:

```markdown
`Overlay` enum (at most one open at a time): host add/edit wizard, credential add/edit wizard, and the store-mode picker are all **dialogs** (`dialog.rs` chrome: titled bordered area + hotkey footer, no dark scrim) layered on top of the shell — not full-screen modes. The **F1 help reference is NOT an `Overlay`**: it is an independent global layer (`App::help: Option<HelpState>`) so `F1` is reachable from every surface (launcher, SFTP transfer, even over a wizard) and so opening it never disturbs what is underneath. Its content is **context-sensitive** — it shows the bindings of the surface it was opened from (launcher tab / SFTP / wizard / file picker / store picker / queue manager) plus a shared "Everywhere" section (lazygit's `?` model). While open it is modal: `↑↓/j/k/PgUp/PgDn` scroll, `F1`/`Esc`/`q`/`Ctrl-C` close, every other key is swallowed. `Esc`/`Ctrl-C` inside an overlay closes it; the shell keeps rendering behind it.
```

- [ ] **Step 4: Run the new footer test + lint + format**

Run: `cargo test --workspace transfer_footer_advertises_f1_help`
Expected: PASS.

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: clean.

- [ ] **Step 5: Full workspace suite under a pty**

Run: `script -qec "cargo test --workspace" /dev/null`
Expected: all green, 0 failed.

- [ ] **Step 6: Commit**

```bash
git add src/tui/transfer/screen.rs docs/tui.md
git commit -m "feat(tui): advertise F1 help in the SFTP footer and document the model

The transfer footer never mentioned Help, so the new global F1 was invisible
on the SFTP screen. Add an 'F1 help' hint (matching the launcher footers) and
update docs/tui.md to describe Help as the independent, context-sensitive
global layer it now is."
```

---

## Notes for the implementer

- **Atomicity of Task 2**: removing `Overlay::Help` breaks every reference at once (the Layer-1 toggle, the Layer-1.5 scroll clamp, `route_overlay`, `draw_overlay`, and ~15 test assertions). That is why Task 2 is one commit — do not split it. Steps 3-9 must all land before the workspace compiles.
- **`current_help_context` field access**: `TransferScreen.queue_overlay`, `HostForm.file_picker`, and `CredForm.file_picker` are all `pub`, so `App` can read them without new accessors.
- **Help scroll clamp uses line count, not body height**: the route-side scroll clamp uses `help_lines(&ctx).len()` as the upper bound (the largest value `max_scroll` can return across all body sizes), exactly as the old Layer-1.5 code did; `draw_help_dialog` re-clamps to the real rendered body height per frame. Keep this two-stage clamp.
- **No new dependencies, no SSH changes**: this is pure TUI state + render. Do not touch `connect/`, `sftp/` worker code, or `Cargo.toml`.
- **Launcher `Enter` noun**: the launcher content is the only place that varies within a context (tab-driven). All other contexts are static.
