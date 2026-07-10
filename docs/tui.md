# TUI Design

The interactive shell (`src/tui/`) is a **three-band shell + tabs + overlays**.
The high-frequency keymap lives in `CLAUDE.md` (`## TUI Keys`); this file holds
the structural design: shell, tabs, panels, overlays, wizards, file picker, and
event routing.

## Shell, Tabs, Panels

- **Shell (`shell.rs`):** a three-band layout — top band is the brand word + tab bar; the middle band is the active panel's area (each panel renders its own one-line status row at the bottom of this band); the bottom band is hotkey hints, always shown. `draw_shell` returns the middle `Rect` for the panel to render into.
- **Tabs (`tab.rs` + `Tab` enum):** Hosts / Credentials / Settings, default Hosts. `Tab`/`Shift-Tab` cycle. The active tab is the only routing state (`App::active_tab`); the old full-screen `Mode` enum is gone.
- **Panels:** Hosts panel (`launcher.rs`, frecency-tiered host list + nucleo fuzzy filter + search box), Credentials panel (`cred_panel.rs`, same shape, no secrets rendered), Settings panel (`settings.rs`, storage-mode row).

## Overlays

`Overlay` enum (at most one open at a time): host add/edit wizard, credential add/edit wizard, and the store-mode picker are all **dialogs** (`dialog.rs` chrome: titled bordered area + hotkey footer, no dark scrim) layered on top of the shell — not full-screen modes. The **F1 help reference is NOT an `Overlay`**: it is an independent global layer (`App::help: Option<HelpState>`) so `F1` is reachable from every surface (launcher, SFTP transfer, even over a wizard) and so opening it never disturbs what is underneath. Its content is **context-sensitive** — it shows the bindings of the surface it was opened from (launcher tab / SFTP / wizard / file picker / store picker / queue manager) plus a shared "Everywhere" section (lazygit's `?` model). While open it is modal: `↑↓/j/k/PgUp/PgDn` scroll, `F1`/`Esc`/`q`/`Ctrl-C` close, every other key is swallowed. `Esc`/`Ctrl-C` inside an overlay closes it; the shell keeps rendering behind it.

## Host Wizard Auth

The Auth row cycles `Independent ↔ Reference` with `←`/`→`. Under Reference a dedicated **Credential** row appears; `Enter` there opens a fuzzy credential-picker overlay (type to filter, `↑`/`↓` to move, `Enter` to select, `Esc` to cancel) — replacing the old in-place `Shift-←/→` cycle so a host can reuse a credential even when dozens exist. Under Independent the `Secret` row cycles `None / Password / IdentityKey` as before.

## Identity-key Source + Inline Paste (host and credential add-edit wizards)

When `Secret = IdentityKey`, a **Source** row appears that cycles `Path ↔ Inline` with `←`/`→`. Under `Path` the Identity row is itself a **trigger row** — `Enter` opens the modal file picker described below (it is not typed in place). Under `Inline` the Privkey/Cert rows both become **trigger rows**: pressing `Enter` on either opens a modal `KeyPaste` popup (a centered `ratatui-textarea`) where the key is pasted. Inside the popup `Enter` inserts a newline, `Esc` closes it (writing the buffer back only if non-blank — a blank close preserves the original key on edit), and `Ctrl-C` discards. The key text is **never echoed**: the popup starts empty on every open (including edit), so the existing inline key is never rendered; if the popup is left blank, the original inline key is preserved unchanged (only a non-blank paste overwrites it).

## File Picker Overlay (Identity-key Path)

The Identity trigger row (above) opens a modal file picker (`src/tui/file_picker.rs`) in `~/.ssh/` first, falling back through the identity hint's parent and `~`. The picker's single filter box is path-aware: typing a plain name nucleo-fuzzy-filters the current directory's entries; typing/pasting a path (anything containing `/` or a leading `~`) and pressing `Enter` resolves it — a directory is entered, a file is selected (absolute path written back to the Identity row), a missing path shows a red "no such path" line. Selected paths are written back **absolute** (`~` expanded), which sidesteps the OpenSSH `-i` quirk of not expanding `~` on the command line.

Keys: `↑↓/^p/^n` move · `Enter`/`→` open dir or select file · `←` up · `Backspace` pops the filter or steps up when empty · `Esc/^c` clear filter then cancel.

The picker is a reusable, business-decoupled component (`FilePicker<S: DirSource>`); directory listing is injected via the core `DirSource` trait (`LocalDirSource` here; `SftpDirSource` is implemented in `connect/sftp/source.rs` but is driven by the SFTP WORKER, not by this picker). The SFTP transfer screen (`tui/transfer/`) has its own `Pane` and does NOT reuse the `FilePicker` component — different UI paradigm (single-select modal vs dual-pane multi-select). What IS shared is the `DirSource` trait plus the pure navigation/filter/window helpers (`fit`/`panel`/`pathutil`); the picker component itself stays single-purpose.

## Event Routing (split across `app` / `intent` / `persist` / `run_loop` / `term`)

`App::on_key` (in `app.rs`) returns a pure-intent `Outcome` (`SwitchTab` / `OpenOverlay` / `CloseOverlay` / `SaveHost` / `DeleteHost` / `ConnectRequested` / `Quit` / …) declared in `intent.rs`; `run_loop.rs` drives the blocking loop and applies the I/O via the free functions in `persist.rs` (host/cred CRUD, keyring cleanup, store switch) and `connect::connect_host` (confirm popups via `TuiPassphrase`, connect orchestration with delayed exec — the terminal owned by `term.rs`'s `TerminalGuard` is restored before `ssh` inherits it). Each panel surfaces a one-line status row at the bottom of its own area; the status is a transient per-action hint that auto-clears on the next panel keypress.

## Entry

Reached by a bare `sshrack`, or by `host`/`cred` `add`/`edit` with no content flags. CLI entry (`host add`, `cred add`, etc.) routes straight to the matching tab + overlay.
