# SFTP Transfer Panes: Titled Borders (sshelf-style)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Give the `sshrack sftp` dual-pane transfer screen per-pane titles and borders like sshelf: each pane is a bordered `Block` whose title reads `local` / `<user>@<host>` (focused = accent border + bold title, unfocused = dim), so the two sides are visually distinct without reading the cwd line.

**Architecture:** Two small TUI-only changes, one per task. (1) Plumb a `remote_title: String` onto `TransferScreen` (default `"remote"`, set to `user@host` in `open_transfer` BEFORE `resolved_auth` is moved into `SftpWorker::open`) — a new field with a setter, NOT a `new()` signature change, so the ~30 test call sites of `TransferScreen::new` stay untouched. (2) `render::draw_pane` gains a `title: &str` param and wraps the whole pane in a titled bordered `Block`; the interior filter changes from the shared 3-row bordered `parts::draw_search_box` to a new borderless 1-row `draw_filter_row` so there is no double border and the list loses no vertical room (border costs 2 rows, filter shrinks 3→1, net zero). The shared `draw_search_box` stays as-is for launcher/cred_panel.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28. **No new dependencies. No `sshrack-core` changes** (the user/host are already resolved in `open_transfer`).

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`. Prefer `unwrap_or` / `saturating_sub`.
- **Render code is covered by no-panic `TestBackend` smoke tests, not pixel assertions** (CLAUDE.md: "Process/PTY-dependent behavior is covered by integration tests"). Pure helpers still get TDD.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Dev stage, no compat code** — replace the old borderless render outright; no parallel path.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`. Staging is explicit (`git add <paths>`), never `git add -A`.
- **`sshrack-core` zero-UI invariant** — this plan never touches `crates/sshrack-core/`.

**Scope invariant:** All work is in `src/tui/` (transfer screen + render + open). `render::draw_pane`'s only caller is `TransferScreen::draw` (`screen.rs:404-405`); updating the title param there is the whole call-site surface (render tests exercise `draw_pane_row`, not `draw_pane`).

---

## Inventory (the contract this plan must satisfy)

- `TransferScreen` (`src/tui/transfer/screen.rs:78-117`) is a `#[derive(Clone)]` struct of public fields; `new(local_cwd, remote_cwd)` (`:128-140`) constructs it. A new public field defaults cleanly without a signature change. Its `draw` (`:389-409`) calls `render::draw_pane(frame, local_area, &self.local, self.focus == Side::Local)` and the remote analogue at `:404-405` — the two call sites that gain a title argument.
- `render::draw_pane` (`src/tui/transfer/render.rs:48-78`) splits `area` into cwd(1) / search(3) / list(Fill), renders the cwd row, calls `parts::draw_search_box(..., focused)` at `:58-65` (the 3-row bordered box), then the list. It is the sole consumer of `draw_search_box` in the transfer layer; launcher/cred_panel keep using it unchanged.
- `parts::draw_search_box` (`src/tui/parts.rs:43-88`) renders a bordered `Block` with `❯ <query>` left + `count_label(matched, total)` right + a terminal cursor after the query when `show_cursor`. `parts::count_label` (`:32-34`, pure, already unit-tested) is reused by the new borderless filter row.
- `draw_cwd_row` (`render.rs:84-107`) and `draw_pane_list` (`render.rs:114-164`) stay as-is; only the search-box call between them is replaced.
- `open_transfer` (`src/tui/transfer/open.rs`): `resolved_auth` is built at `:101`, `resolved_host.host` is read at `:113` (`let host_str = resolved_host.host.as_str()`), `resolved_auth` is MOVED into `SftpWorker::open` at `:126-133`, the screen is built at `:142`. So `resolved_auth.user` must be read BEFORE `:126`. `ResolvedAuth.user: String` is public (`crates/sshrack-core/src/credential.rs:107`).
- render.rs imports (`render.rs:14-30`): `ratatui::{Frame, layout::{Alignment, Constraint, Layout, Rect}, style::{Modifier, Style}, text::{Line, Span}, widgets::{Gauge, Paragraph}}`. `Block`/`Borders` must be added to the `widgets` import. `parts` (`crate::tui::parts`) is imported and stays (still used for `vertical_center` + now `count_label`).
- theme (`src/tui/theme.rs`): `ACCENT: Color = Cyan`, `accent() -> Style`, `DANGER`. No gray constant — non-focused surfaces use `Style::new().dim()` (the existing search-box border at `parts.rs:53` and every non-focused span in `render.rs` already do this).

---

## Task 1: Plumb `remote_title` onto `TransferScreen`

**Files:**
- Modify: `src/tui/transfer/screen.rs` (struct field + `new` default)
- Modify: `src/tui/transfer/open.rs` (capture `user@host` before the move, set the field)
- Test: `src/tui/transfer/screen_tests.rs` (one default-value test)

**Interfaces:**
- Produces: `pub remote_title: String` on `TransferScreen` (default `"remote"`, set to `user@host` by `open_transfer`). No signature change to `new`.
- Consumes: `ResolvedAuth.user` (`sshrack_core::credential`) + `Host.host` — both already in scope in `open_transfer`.

- [ ] **Step 1: Write the failing test (RED)**

In `src/tui/transfer/screen_tests.rs`, append:

```rust
#[test]
fn new_screen_remote_title_defaults_to_remote() {
    // open_transfer overrides this with "<user>@<host>"; the default keeps the
    // title meaningful in tests (which construct the screen directly) and on
    // any path that does not set it, so the bordered title is never blank.
    let s = n(PathBuf::from("/l"), PathBuf::from("/r"));
    assert_eq!(s.remote_title, "remote");
}
```

- [ ] **Step 2: Run — expect RED (field absent)**

```bash
cargo test --bin sshrack transfer::screen_tests::new_screen_remote_title_defaults_to_remote 2>&1 | tail -15
```

Expected: fails to compile (`no field `remote_title``).

- [ ] **Step 3: Add the field + default**

In `src/tui/transfer/screen.rs`, add the field to the `TransferScreen` struct right after `pub remote: Pane,` (`:83`):

```rust
    /// Title for the remote pane's bordered block. Defaults to `"remote"`;
    /// [`open_transfer`](super::open::open_transfer) sets it to `"<user>@<host>"`
    /// once auth resolves. The local pane's title is the literal `"local"`
    /// (passed at the render call site, not stored).
    pub remote_title: String,
```

Initialize it in `TransferScreen::new` (`:128-140`), next to `status: Status::empty(),`:

```rust
            remote_title: "remote".to_string(),
```

- [ ] **Step 4: Run — GREEN**

```bash
cargo test --bin sshrack transfer::screen_tests::new_screen_remote_title_defaults_to_remote 2>&1 | tail -10
```

Expected: passes.

- [ ] **Step 5: Set the title in `open_transfer`**

In `src/tui/transfer/open.rs`, capture the title from `resolved_auth.user` + `resolved_host.host` BEFORE `resolved_auth` is moved into `SftpWorker::open`. Immediately after the `let host_str = resolved_host.host.as_str();` line (`:113`), add:

```rust
    // Capture the remote pane title before `resolved_auth` is moved into
    // SftpWorker::open below — the bordered block renders "<user>@<host>" so
    // the two panes are visually distinct without reading the cwd line.
    let remote_title = format!("{}@{}", resolved_auth.user, resolved_host.host);
```

Then after the screen is constructed (`:142`, `let mut screen = TransferScreen::new(local_cwd.clone(), home.clone());`), set the field before the local-pane seed block:

```rust
    screen.remote_title = remote_title;
```

- [ ] **Step 6: Build + clippy + fmt + commit**

```bash
cargo build --workspace
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
git add src/tui/transfer/screen.rs src/tui/transfer/open.rs src/tui/transfer/screen_tests.rs
git commit -m "feat(tui): carry a remote pane title on the transfer screen" -m "TransferScreen gains a remote_title field (default \"remote\") set by open_transfer to \"<user>@<host>\" from the resolved auth + host. Read before resolved_auth is moved into SftpWorker::open. The render layer consumes it in the next commit to title the bordered remote pane; the local pane title is the literal \"local\" (no field needed). No new() signature change, so the ~30 test call sites stay untouched."
```

---

## Task 2: Bordered titled panes + borderless filter row

**Files:**
- Modify: `src/tui/transfer/render.rs` (`draw_pane` signature + body, new `draw_filter_row`, imports)
- Modify: `src/tui/transfer/screen.rs` (`draw` passes the titles)
- Test: `src/tui/transfer/render.rs` (one no-panic `TestBackend` smoke for `draw_pane` focused + unfocused)

**Interfaces:**
- Produces: `pub fn draw_pane(frame: &mut Frame, area: Rect, pane: &Pane, focused: bool, title: &str)` (new `title` param — last position). Private `fn draw_filter_row(frame: &mut Frame, area: Rect, query: &str, matched: usize, total: usize, focused: bool)`.
- Consumes: `TransferScreen::remote_title` (Task 1), `parts::count_label`, `theme::accent`.

- [ ] **Step 1: Write the failing render smoke (RED)**

In `src/tui/transfer/render.rs` test module, append. The existing `draw_pane_row` tests return a `Line`; this one drives `draw_pane` through a `TestBackend` (no-panic + cursor-within-bounds, mirroring the screen render smokes):

```rust
    // ---- draw_pane: titled bordered block, no panic on a short terminal ----

    #[test]
    fn draw_pane_focused_renders_without_panic_and_keeps_cursor_on_screen() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut pane = Pane::new(std::path::PathBuf::from("/x"));
        pane.set_entries(vec![
            entry("alpha.txt", false, Some(1024)),
            entry("betadir", true, None),
        ]);
        let backend = TestBackend::new(40, 12);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_pane(f, f.area(), &pane, true, "local"))
            .expect("focused titled pane must render without panic");
        let (cx, cy) = term.backend().cursor_position().unwrap_or((0, 0));
        assert!(
            cx < 40 && cy < 12,
            "focused filter cursor must stay on-screen (got ({cx},{cy}))"
        );
    }

    #[test]
    fn draw_pane_unfocused_renders_without_panic() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut pane = Pane::new(std::path::PathBuf::from("/x"));
        pane.set_entries(vec![entry("alpha.txt", false, Some(1024))]);
        let backend = TestBackend::new(40, 12);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_pane(f, f.area(), &pane, false, "u@h"))
            .expect("unfocused titled pane must render without panic");
        // Non-focused pane suppresses the terminal cursor: cursor_position is
        // either (0,0) default or unset — assert no panic is the contract.
    }
```

(`Pane::new` and `entry` are in scope via `super::*`; `entry(name, is_dir, size)` already exists at `render.rs:522`. `Pane::set_entries` is `pub`.)

- [ ] **Step 2: Run — expect RED (signature mismatch)**

```bash
cargo test --bin sshrack transfer::render::tests::draw_pane_focused_renders_without_panic_and_keeps_cursor_on_screen 2>&1 | tail -15
```

Expected: fails to compile (`this function takes 4 arguments but 5 were supplied` — the `title` param is not there yet).

- [ ] **Step 3: Add `Block`/`Borders` to the imports**

In `src/tui/transfer/render.rs:19`, change the `widgets` import:

```rust
    widgets::{Block, Borders, Gauge, Paragraph},
```

- [ ] **Step 4: Rewrite `draw_pane` to wrap a titled bordered block**

Replace the whole `draw_pane` body (`render.rs:48-78`) so it wraps `area` in a titled bordered `Block` and splits `block.inner(area)` into cwd(1) / filter(1) / list(Fill):

```rust
/// Paint one pane into `area` as a titled bordered block: focus = accent
/// border + bold title, non-focus = dim border + dim title (mirrors sshelf and
/// keeps sshrack's dim-the-non-focused-pane language). Inside the block: a
/// 1-row cwd line, a borderless 1-row filter prompt ([`draw_filter_row`]), and
/// a Fill list windowed by [`Pane::visible_window`].
///
/// The filter is a 1-row prompt rather than the shared 3-row bordered
/// [`parts::draw_search_box`] so the pane has exactly one border (no box-in-box)
/// and the list loses no vertical room (the border costs 2 rows, the filter
/// shrinks 3→1, net zero).
pub fn draw_pane(frame: &mut Frame, area: Rect, pane: &Pane, focused: bool, title: &str) {
    let border_style = if focused {
        theme::accent()
    } else {
        Style::new().dim()
    };
    let title_style = if focused {
        theme::accent().add_modifier(Modifier::BOLD)
    } else {
        Style::new().dim()
    };
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(format!(" {title} "), title_style));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [cwd_area, filter_area, list_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(inner);

    draw_cwd_row(frame, cwd_area, pane, focused);
    draw_filter_row(
        frame,
        filter_area,
        &pane.query,
        pane.matched_count(),
        pane.entries.len(),
        focused,
    );

    if pane.loading {
        frame.render_widget(
            Paragraph::new("loading…")
                .style(Style::new().dim())
                .alignment(Alignment::Center),
            parts::vertical_center(list_area, 1),
        );
        return;
    }

    draw_pane_list(frame, list_area, pane, focused);
}
```

- [ ] **Step 5: Add the borderless `draw_filter_row`**

Add this private helper right after `draw_cwd_row` (before `draw_pane_list`, `render.rs:109`). It is the 1-row analogue of `parts::draw_search_box`: `❯ <query>` left, `count_label` right, terminal cursor after the query only on the focused pane.

```rust
/// Render the filter row (interior of the bordered pane): a dim `❯ ` prefix +
/// the query on the left, the right-aligned `matched/total` [`count_label`] on
/// the right, and — only when `focused` — the terminal cursor right after the
/// query. Borderless (the pane `Block` already draws the surrounding border).
fn draw_filter_row(
    frame: &mut Frame,
    area: Rect,
    query: &str,
    matched: usize,
    total: usize,
    focused: bool,
) {
    let label = parts::count_label(matched, total);
    let label_w = label.chars().count() as u16;
    let [prompt_area, count_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(label_w)]).areas(area);

    let query_style = if focused { Style::new() } else { Style::new().dim() };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::styled(query.to_string(), query_style),
        ])),
        prompt_area,
    );
    frame.render_widget(
        Paragraph::new(label)
            .alignment(Alignment::Right)
            .style(Style::new().dim()),
        count_area,
    );

    // Place the terminal cursor right after the 2-cell `❯ ` prefix, only on the
    // focused pane (the non-focused pane must not fight the focused pane's
    // cursor). Clamp to the row's last cell.
    if focused {
        let cursor_x = area.x + 2 + query.chars().count() as u16;
        let max_x = area.x + area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), area.y));
    }
}
```

- [ ] **Step 6: Pass the titles from `TransferScreen::draw`**

In `src/tui/transfer/screen.rs`, update the two `render::draw_pane` calls in `draw` (`:404-405`):

```rust
        render::draw_pane(frame, local_area, &self.local, self.focus == Side::Local, "local");
        render::draw_pane(
            frame,
            remote_area,
            &self.remote,
            self.focus == Side::Remote,
            &self.remote_title,
        );
```

- [ ] **Step 7: Run — GREEN**

```bash
cargo test --bin sshrack transfer::render 2>&1 | tail -15
cargo test --bin sshrack transfer::screen 2>&1 | tail -15
```

Expected: the two new `draw_pane` smokes pass, and every existing render/screen test stays green (the render change is visual; existing `draw_pane_row` / routing tests are unaffected).

- [ ] **Step 8: Full workspace regression + clippy + fmt**

```bash
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
```

Expected: every `test result:` ok / `0 failed`; clippy clean; `FMT_OK`.

- [ ] **Step 9: Commit**

```bash
git add src/tui/transfer/render.rs src/tui/transfer/screen.rs
git commit -m "feat(tui): title and border each sftp transfer pane" -m "Each pane is now a bordered Block titled \"local\" / \"<user>@<host>\" (focused = accent border + bold title, unfocused = dim), matching sshelf so the two sides are visually distinct without reading the cwd line. draw_pane wraps its area in the titled block and splits block.inner into cwd(1) / filter(1) / list(Fill). The interior filter switches from the shared 3-row bordered draw_search_box to a new borderless 1-row draw_filter_row so the pane has exactly one border and the list loses no vertical room (border costs 2 rows, filter shrinks 3->1). draw_search_box stays for launcher/cred_panel. TransferScreen::draw passes \"local\" and self.remote_title."
```

---

## Final smoke + docs (after both tasks land)

```bash
cargo build --release
# From a dir with files, against a real host:
./target/release/sshrack    # launcher, then Ctrl-T on a host
```

Verify:
1. Both panes render as **bordered blocks**. The local pane's border title is `local`; the remote pane's is `<user>@<host>`.
2. The **focused** pane has an accent (cyan) border + bold title; the **non-focused** pane has a dim border + dim title. `Tab` flips focus and the border styling follows.
3. The filter row is a single `❯ <query>` line with the right-aligned `matched/total`; typing filters and the terminal cursor sits at the end of the query on the focused pane only.
4. The list area is no shorter than before (border +2 rows, filter −2 rows).

Docs: add one line to the SFTP transfer section of `docs/sftp.md` noting each pane is a titled bordered block (`local` / `<user>@<host>`, focus = accent border). Do not re-architect the doc.

If a host is not available, at minimum re-run the full gate:

```bash
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt --check && echo FMT_OK
```

Then use the `superpowers:finishing-a-development-branch` skill to merge.

---

## Self-Review

**1. Spec coverage:**
- "缺少了左右两个 pane 的标题（local 和 远程名字）" → Task 2 (`draw_pane` titled border + `draw_filter_row`) with the remote title plumbed by Task 1. ✅
- "标题 + sshelf 式边框" (chosen scope) → bordered `Block` per pane, title on the border, focus = accent border + bold title, unfocused = dim — matches sshelf's `ui/transfer.rs:84-107`. ✅

**2. Placeholder scan:** No TBD/TODO. Every step has runnable code or an exact command. The two non-pure changes (the field add and the render rewrite) carry TestBackend smoke / default-value tests per CLAUDE.md's "no-panic smoke, not pixel assertions" rule for render code.

**3. Type consistency:**
- `draw_pane(frame, area, pane, focused, title: &str)` — Task 2 Step 4 signature matches the Task 2 Step 1 test call (`draw_pane(f, f.area(), &pane, true, "local")`) and the Step 6 `TransferScreen::draw` calls (`"local"` literal, `&self.remote_title` where `remote_title: String` → `&String` coerces to `&str`). ✅
- `draw_filter_row(frame, area, query: &str, matched: usize, total: usize, focused: bool)` — Step 5 signature matches the Step 4 call (`&pane.query` is `&String` → `&str`; `pane.matched_count()` / `pane.entries.len()` are `usize`; `focused` is `bool`). ✅
- `TransferScreen::remote_title: String` (Task 1 Step 3) — default `"remote".to_string()` in `new` (Step 3), set to `format!("{}@{}", resolved_auth.user, resolved_host.host)` in `open_transfer` (Step 5; both `user: String` and `host: String` → `format!` takes them by ref via display). Read BEFORE the `:126` move of `resolved_auth`. ✅
- `Block::new().borders(Borders::ALL).border_style(Style).title(Span::styled(...))` — valid ratatui 0.30 builder; `Span::styled(String, Style)` matches the sshelf reference and the existing `draw_cwd_row` span construction. ✅

**4. Purity / invariants:**
- Render changes stay render-only (no I/O, no env) — `draw_pane` / `draw_filter_row` push spans into the frame, same as before. ✅
- No new `unsafe` / `unwrap` / `expect` in prod (`saturating_sub`, `unwrap_or` only; the `Terminal::new(backend).unwrap()` and `.cursor_position().unwrap_or((0,0))` are inside `#[cfg(test)]`). ✅
- `sshrack-core` untouched — the zero-UI invariant holds. ✅
- `draw_search_box` is NOT removed (launcher/cred_panel still use it) — only the transfer pane stops calling it. ✅
- The ~30 `TransferScreen::new` test call sites are NOT touched (field + setter, not a signature change). ✅
