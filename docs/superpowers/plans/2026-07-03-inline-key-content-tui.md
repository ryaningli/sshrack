# Inline Key Content (TUI paste) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Let the user paste a private key's CONTENTS directly in the cred/host add-edit wizards (not just type a file path), completing the inline-key feature's TUI experience loop.

**Architecture:** Add a `Source: < Path > / < Inline >` chooser row that appears under `Secret = IdentityKey`. Under `Inline`, the form holds two `ratatui_textarea::TextArea` widgets (private key required, certificate optional); when one is focused, the dialog expands a multiline editor block at the bottom of the field area (collapsed to a one-line summary otherwise), so the single-line field layout is preserved. `build_body` routes Inline to `CredentialBody::with_inline_key(Secret::Plain(private), Some(Secret::Plain(cert)))`. Editing an existing inline-key owner defaults Source to Inline with empty textareas (key text is never echoed back) and preserves the original `KeySource::Inline` verbatim on save when the private field is left blank — same data-safety rule Plan 1 established.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm, **`ratatui-textarea` v0.9.2 (new dep, root package only — verified `cargo add --dry-run` resolves it against ratatui 0.30 with the `crossterm` feature)**.

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, error messages, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via params/seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: …")`.
- **TDD for pure logic** — RED → GREEN → REFACTOR. Render/PTY behavior covered by no-panic `TestBackend` smoke tests, not pixel assertions.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Key material as sensitive as a password** — never echoed in the wizard (textareas start EMPTY on edit; the original inline key is preserved on save, not loaded into the textarea), masked/redacted in Debug, never in logs/errors.
- **`sshrack-core` zero-UI invariant** — this plan touches ONLY `src/tui/` (+ root `Cargo.toml` for the dep). Core is unchanged.
- **Tests hermetic** — `cargo test --workspace` green with `SSHRACK_PASSPHRASE` set, serial (`--test-threads=1`) for the pre-existing parallel flake; no `env -u`.
- **Dev stage, no compat code** — replace the Plan-1 `orig_key` placeholder behavior with real paste-editing; remove the "Plan 2 will add real paste-editing" comment.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`.

**Scope invariant:** All work is in `src/tui/` (wizard `mod.rs` + `cred.rs` + `host.rs`) + root `Cargo.toml`. `KeySource`/`with_inline_key`/`materialize_inline_key` (Plan 1, merged to main) are consumed as-is — do not change core.

---

## Inventory (the contract this plan must satisfy)

| Surface | Today (main `917ec30`) | After |
|---|---|---|
| `CredField` enum (`wizard/mod.rs`) | Name/User/Identity/SecretKind/Password | + Source, InlinePrivate, InlineCert |
| `Field` enum (host, `wizard/mod.rs`) | …/Auth/Credential/User/Secret/Identity/Password | + Source, InlinePrivate, InlineCert |
| `SecretChoice` | None/Password/IdentityKey | unchanged |
| **NEW** `SourceChoice` | — | Path/Inline, `←`/`→` cycle, `bracketed` label |
| `CredForm` state | identity(String), orig_key | + source, inline_private(TextArea), inline_cert(TextArea) |
| `CredForm::field_reachable` | secret-gated Identity/Password | + Source under IdentityKey; Identity under Path; InlinePrivate/Cert under Inline |
| `CredForm::on_key` | identity edits via insert_char_at | + Source ←/→ cycle; InlinePrivate/Cert → textarea.input(key) |
| `CredForm::build_body` | identity path or preserve orig inline | + Source::Inline → with_inline_key(private, cert) |
| `CredForm::draw_in_dialog` | single-line rows | + focused textarea expands a multiline block |
| `CredForm::body_rows` | fixed worst-case | dynamic: +TEXTAREA_H when a textarea is focused |
| `HostForm` | mirrors CredForm under Independent | same set of changes via `build_inline_body` |

`TextArea` API (`ratatui-textarea` v0.9.2, crossterm feature) — the implementer MUST confirm exact signatures against `docs.rs/ratatui-textarea` for the resolved version, but the expected shape is: `TextArea::default()` / `TextArea::new(Vec<String>)`; `textarea.input(KeyEvent) -> bool` (handles typing/newlines/backspace/navigation itself); `textarea.lines() -> &[String]`; render via `frame.render_widget(&textarea, area)` (WidgetRef in ratatui 0.30). A `TextArea` owns its text + cursor + viewport, so the form only forwards keys when the field is focused.

---

## Task 1: `SourceChoice` + extend `CredField`/`Field` enums (shared types)

**Files:**
- Modify: `Cargo.toml` (root package) — add `ratatui-textarea = "0.9"` (default features include crossterm).
- Modify: `src/tui/wizard/mod.rs` — add `SourceChoice`; extend `CredField` and `Field` with `Source` / `InlinePrivate` / `InlineCert` (+ `ORDER` + `label()`); add `CRED_LABEL_WIDTH`/`HOST_LABEL_WIDTH` bump if the new labels exceed the current column (they don't — `Source`/`Inline...` ≤ 8/10 — but verify).

**Interfaces:**
- Produces:
  - `pub enum SourceChoice { Path, Inline }` with `const ORDER`, `fn idx/next/prev` (mirror `SecretChoice`), `fn label() -> &'static str` (`"Path"` / `"Inline"`).
  - `CredField::Source`, `CredField::InlinePrivate`, `CredField::InlineCert` (+ added to `CredField::ORDER` AFTER `SecretKind` and BEFORE `Identity`/`Password` so the chooser reads top-down: Secret → Source → slot).
  - `Field::Source`, `Field::InlinePrivate`, `Field::InlineCert` (same placement under `Secret`).
- Consumes: `bracketed` (existing helper) for the Source row value.

- [ ] **Step 1: Add the dependency**

```bash
cargo add ratatui-textarea@0.9
```
Confirm `cargo build -p sshrack` succeeds (the dep resolves against ratatui 0.30). If the resolved version's render API differs from `frame.render_widget(&textarea, area)`, note it for Task 3/4 — do not change core.

- [ ] **Step 2: Write the failing tests (RED)** in `src/tui/wizard/mod.rs` `#[cfg(test)]`:

```rust
#[test]
fn source_choice_cycles_path_and_inline() {
    assert_eq!(SourceChoice::Path.next(), SourceChoice::Inline);
    assert_eq!(SourceChoice::Inline.next(), SourceChoice::Path);
    assert_eq!(SourceChoice::Inline.prev(), SourceChoice::Path);
}

#[test]
fn source_choice_labels_are_capitalized() {
    assert_eq!(SourceChoice::Path.label(), "Path");
    assert_eq!(SourceChoice::Inline.label(), "Inline");
}

#[test]
fn cred_field_order_puts_source_above_identity_and_password() {
    let order = CredField::ORDER;
    let src = order.iter().position(|f| *f == CredField::Source).expect("Source in ORDER");
    let id = order.iter().position(|f| *f == CredField::Identity).expect("Identity in ORDER");
    let privk = order.iter().position(|f| *f == CredField::InlinePrivate).expect("InlinePrivate in ORDER");
    assert!(src < id, "Source must render above Identity");
    assert!(src < privk, "Source must render above InlinePrivate");
}
```

- [ ] **Step 3: Run — expect RED** (`SourceChoice` / new `CredField` variants missing).

- [ ] **Step 4: Implement** in `src/tui/wizard/mod.rs`:

```rust
/// The identity-key source offered under `Secret = IdentityKey`: a file
/// `Path` (typed) or pasted `Inline` contents (edited in a multiline area).
/// Cycled by `←`/`→` on the Source row. Mirrors [`SecretChoice`]'s shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceChoice {
    Path,
    Inline,
}

impl SourceChoice {
    const ORDER: &'static [SourceChoice] = &[SourceChoice::Path, SourceChoice::Inline];
    fn idx(self) -> usize {
        Self::ORDER.iter().position(|s| *s == self)
            .expect("invariant: every SourceChoice variant is in ORDER")
    }
    pub(crate) fn next(self) -> Self {
        Self::ORDER[(self.idx() + 1) % Self::ORDER.len()]
    }
    pub(crate) fn prev(self) -> Self {
        Self::ORDER[(self.idx() + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }
    fn label(self) -> &'static str {
        match self {
            SourceChoice::Path => "Path",
            SourceChoice::Inline => "Inline",
        }
    }
}
```

Extend `CredField`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredField {
    Name,
    User,
    SecretKind,
    Source,          // identity-key source chooser (IdentityKey only)
    Identity,        // path text (Path source only)
    InlinePrivate,   // multiline private-key paste (Inline source only)
    InlineCert,      // multiline optional certificate paste (Inline source only)
    Password,
}

impl CredField {
    const ORDER: &'static [CredField] = &[
        CredField::Name,
        CredField::User,
        CredField::SecretKind,
        CredField::Source,
        CredField::Identity,
        CredField::InlinePrivate,
        CredField::InlineCert,
        CredField::Password,
    ];
    fn label(self) -> &'static str {
        match self {
            CredField::Name => "Name",
            CredField::User => "User",
            CredField::Identity => "Identity",
            CredField::SecretKind => "Secret",
            CredField::Source => "Source",
            CredField::InlinePrivate => "Privkey",
            CredField::InlineCert => "Cert",
            CredField::Password => "Password",
        }
    }
}
```

Extend `Field` (host) with the same three variants in the same relative position (after `Secret`, before `Identity`): `Field::Source`, `Field::InlinePrivate`, `Field::InlineCert`, with labels (`"Source"`, `"Privkey"`, `"Cert"`). Add them to `Field::ORDER` and `Field::label()`.

**Compile-fix the existing `field_reachable` matches that are now non-exhaustive** (they match on `CredField`/`Field`) — for Task 1, make the new variants UNREACHABLE everywhere (return `false` in `field_reachable`, no-op in `on_key` edit arms) so the form compiles and all existing tests stay green. (Tasks 2/4 wire them in.) This is intentional staging removed by Tasks 2/4 — drop the staging there.

- [ ] **Step 5: Run — pass; clippy + fmt + commit**

```bash
cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): SourceChoice + Source/Inline fields for inline key wizard"
```

---

## Task 2: `CredForm` state + on_key (source cycling + textarea input)

**Files:**
- Modify: `src/tui/wizard/cred.rs` (struct, `new_add`, `new_edit`, `field_reachable`, `reachable_fields`, `focused_text_len`, `cursor_target`, `on_key`, `move_focus`).

**Interfaces:**
- Consumes: Task 1's `SourceChoice`, `CredField::{Source, InlinePrivate, InlineCert}`; `ratatui_textarea::TextArea`; `sshrack_core::config::schema::{KeySource, Secret, SecretKind}`; `with_inline_key` (Task 1/Plan 1).
- Produces: a `CredForm` carrying `source: SourceChoice`, `inline_private: TextArea<'static>`, `inline_cert: TextArea<'static>`; `on_key` routes `←`/`→` on Source to cycle, and forwards keys to the focused textarea for `InlinePrivate`/`InlineCert`.

- [ ] **Step 1: Write the failing tests (RED)** in `cred.rs` `#[cfg(test)]`:

```rust
#[test]
fn identity_key_shows_source_row_and_path_branch_reaches_identity() {
    let mut f = CredForm::new_add();
    f.secret_kind = SecretChoice::IdentityKey;
    f.source = SourceChoice::Path;
    let r = f.reachable_fields();
    assert!(r.contains(&CredField::Source));
    assert!(r.contains(&CredField::Identity));
    assert!(!r.contains(&CredField::InlinePrivate));
}

#[test]
fn inline_source_hides_identity_and_reaches_textareas() {
    let mut f = CredForm::new_add();
    f.secret_kind = SecretChoice::IdentityKey;
    f.source = SourceChoice::Inline;
    let r = f.reachable_fields();
    assert!(r.contains(&CredField::InlinePrivate));
    assert!(r.contains(&CredField::InlineCert));
    assert!(!r.contains(&CredField::Identity));
}

#[test]
fn right_arrow_on_source_cycles_path_to_inline() {
    let mut f = CredForm::new_add();
    f.secret_kind = SecretChoice::IdentityKey;
    f.focus = CredField::Source;
    f.source = SourceChoice::Path;
    f.on_key(press(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(f.source, SourceChoice::Inline);
}

#[test]
fn typing_into_inline_private_goes_to_the_textarea() {
    let mut f = CredForm::new_add();
    f.secret_kind = SecretChoice::IdentityKey;
    f.source = SourceChoice::Inline;
    f.focus = CredField::InlinePrivate;
    for c in "PRIVATE-KEY-TEXT".chars() {
        f.on_key(press(KeyCode::Char(c), KeyModifiers::NONE));
    }
    assert_eq!(f.inline_private.lines().join("\n"), "PRIVATE-KEY-TEXT");
}

#[test]
fn new_edit_inline_original_defaults_source_to_inline_with_empty_textarea() {
    // Editing an inline-key owner: Source defaults to Inline, but the key
    // text is NEVER echoed into the textarea (security). build_body must
    // preserve the original on save when the private field stays empty.
    use sshrack_core::config::schema::{InlineKey, KeySource, Secret};
    let cred = Credential {
        id: Ulid::new(), name: "ops".into(),
        body: CredentialBody::new("u")
            .with_inline_key(Secret::Plain("SECRET-TEXT".into()), None),
    };
    let f = CredForm::new_edit(&cred);
    assert_eq!(f.secret_kind, SecretChoice::IdentityKey);
    assert_eq!(f.source, SourceChoice::Inline);
    assert!(f.inline_private.lines().join("\n").is_empty(), "key text must NOT echo");
    assert!(matches!(f.orig_key, Some(KeySource::Inline(_))));
}
```
(Note: `with_inline_key` already exists from Plan 1. `TextArea::default()` must be inserted into the form struct; if `TextArea` is not `PartialEq`, the form's derived `PartialEq` (if any) must be dropped or the field excluded — see Step 3.)

- [ ] **Step 2: Run — expect RED** (no `source`/`inline_*` fields; `Source`/`Inline*` unreachable).

- [ ] **Step 3: Implement** — add fields to `CredForm`:

```rust
use ratatui_textarea::TextArea;

pub struct CredForm {
    pub name: String,
    pub user: String,
    pub identity: String,
    pub secret_kind: SecretChoice,
    /// Identity-key source (Path | Inline). Relevant only under IdentityKey.
    pub source: SourceChoice,
    /// Multiline private-key paste, edited when source == Inline.
    pub inline_private: TextArea<'static>,
    /// Multiline optional certificate paste, edited when source == Inline.
    pub inline_cert: TextArea<'static>,
    pub password: Zeroizing<String>,
    pub focus: CredField,
    pub cursor: usize,
    pub error: Option<CredSaveError>,
    pub core_error: Option<String>,
    pub editing: bool,
    pub orig_id: Option<Ulid>,
    pub orig_key: Option<KeySource>,
}
```
(`TextArea` is not `PartialEq`; if `CredForm` derives `PartialEq`, drop the derive and adjust the one or two tests that compare whole forms to compare field-by-field. Mirror how the codebase already handles non-`PartialEq` fields. Keep the redacting manual `Debug` — add `source` and the two textareas; for the textareas in Debug, show only their line COUNT, never contents: `.field("inline_private_lines", &self.inline_private.lines().len())`.)

`new_add`: initialize `source: SourceChoice::Path`, `inline_private: TextArea::default()`, `inline_cert: TextArea::default()`.

`new_edit`: after computing `secret_kind`, set
```rust
let (source, identity) = match body.secret_kind() {
    SecretKind::Key => match body.key.as_ref() {
        Some(KeySource::Path(p)) => (SourceChoice::Path, p.to_string_lossy().into_owned()),
        // Inline original: default to Inline so the user can paste a NEW key
        // (the old text is never echoed); orig_key preserves it on save.
        Some(KeySource::Inline(_)) => (SourceChoice::Inline, String::new()),
        None => (SourceChoice::Path, String::new()),
    },
    _ => (SourceChoice::Path, String::new()),
};
```
with `inline_private: TextArea::default()` / `inline_cert: TextArea::default()` (always empty on edit — never preload key text).

`field_reachable` (now takes secret + source):
```rust
fn field_reachable(field: CredField, secret: SecretChoice, source: SourceChoice) -> bool {
    match secret {
        SecretChoice::None => !matches!(field, CredField::Identity | CredField::Password
            | CredField::Source | CredField::InlinePrivate | CredField::InlineCert),
        SecretChoice::Password => !matches!(field, CredField::Identity | CredField::Source
            | CredField::InlinePrivate | CredField::InlineCert),
        SecretChoice::IdentityKey => match source {
            SourceChoice::Path => !matches!(field, CredField::Password
                | CredField::InlinePrivate | CredField::InlineCert),
            SourceChoice::Inline => !matches!(field, CredField::Password
                | CredField::Identity),
        },
    }
}
```
Update `reachable_fields` to pass `self.source`. `Source` is reachable iff secret == IdentityKey.

`on_key` — add, in the `match key.code` (after the existing `SecretKind` ←/→ arms):
```rust
KeyCode::Left if self.focus == CredField::Source && self.secret_kind == SecretChoice::IdentityKey => {
    self.source = self.source.prev();
    self.error = None;
    Outcome::Continue
}
KeyCode::Right if self.focus == CredField::Source && self.secret_kind == SecretChoice::IdentityKey => {
    self.source = self.source.next();
    self.error = None;
    Outcome::Continue
}
// Multiline paste fields: forward every key to the focused TextArea. The
// textarea owns its cursor/newlines/backspace; Tab/Enter-on-last-field are
// handled below BEFORE reaching here so navigation still works.
KeyCode::Tab if matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert) => {
    self.move_focus(1);
    Outcome::Continue
}
KeyCode::BackTab if matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert) => {
    self.move_focus(-1);
    Outcome::Continue
}
```
And in the catch-all text-input arm (`KeyCode::Char(c) if !ctrl` / `Backspace` / `Left`/`Right`/`Home`/`End`), BEFORE the existing `match self.focus` insert/backspace, add:
```rust
if let CredField::InlinePrivate = self.focus {
    let _ = self.inline_private.input(key);
    return Outcome::Continue;
}
if let CredField::InlineCert = self.focus {
    let _ = self.inline_cert.input(key);
    return Outcome::Continue;
}
```
(`TextArea::input` takes the `KeyEvent` directly and returns `bool`; the return is irrelevant here — we always `Continue`. IMPORTANT: a bare `KeyCode::Enter` inside a textarea must insert a newline, NOT advance the field — so guard the existing `KeyCode::Enter` advance logic to skip when the focus is a textarea, letting the textarea-input path above handle it. Verify the existing `Enter` arm runs `move_focus`/`attempt_save` only for non-textarea fields.)

`focused_text_len` / `cursor_target`: return `0` / `None` for `Source`/`InlinePrivate`/`InlineCert` (the textarea manages its own cursor; the Source row is a chooser). `move_focus`'s `self.cursor = self.focused_text_len()` stays correct (0 for these).

- [ ] **Step 4: Run — pass; clippy + fmt + commit**

```bash
cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): cred wizard Source cycling + inline textarea input"
```

---

## Task 3: `CredForm::build_body` Inline routing + data safety

**Files:**
- Modify: `src/tui/wizard/cred.rs` (`build_body`).

**Interfaces:**
- Consumes: `with_inline_key(Secret, Option<Secret>)`, `Secret::Plain`, `KeySource::Inline`.
- Produces: `build_body` returns a body carrying `KeySource::Inline` when `source == Inline` and the private field is non-empty; preserves `orig_key` Inline when the private field is empty on edit; routes Path as before.

- [ ] **Step 1: Write the failing tests (RED)**:

```rust
#[test]
fn build_body_inline_source_attaches_inline_key() {
    let mut f = complete_cred_form();
    f.secret_kind = SecretChoice::IdentityKey;
    f.source = SourceChoice::Inline;
    f.inline_private = TextArea::new(vec!["PRIVATE-KEY-TEXT".into()]);
    f.inline_cert = TextArea::new(vec!["CERT-TEXT".into()]);
    let b = f.build_body();
    assert_eq!(b.secret_kind(), SecretKind::Key);
    match b.key {
        Some(KeySource::Inline(ik)) => {
            assert_eq!(ik.private_key.unwrap().as_plain(), Some("PRIVATE-KEY-TEXT"));
            assert_eq!(ik.certificate.unwrap().as_plain(), Some("CERT-TEXT"));
        }
        other => panic!("expected Inline, got {other:?}"),
    }
}

#[test]
fn build_body_inline_source_multiline_joins_with_newline() {
    // A pasted key has many lines; they must round-trip as one string.
    let mut f = complete_cred_form();
    f.secret_kind = SecretChoice::IdentityKey;
    f.source = SourceChoice::Inline;
    f.inline_private = TextArea::new(vec!["line1".into(), "line2".into(), "line3".into()]);
    let b = f.build_body();
    let plain = match b.key {
        Some(KeySource::Inline(ik)) => ik.private_key.unwrap().as_plain().unwrap().to_string(),
        _ => panic!("expected Inline"),
    };
    assert_eq!(plain, "line1\nline2\nline3");
}

#[test]
fn build_body_inline_blank_on_edit_preserves_original_inline_key() {
    use sshrack_core::config::schema::{InlineKey, KeySource, Secret};
    let mut f = complete_cred_form();
    f.editing = true;
    f.secret_kind = SecretChoice::IdentityKey;
    f.source = SourceChoice::Inline;
    f.inline_private = TextArea::default(); // empty — user did not re-paste
    f.orig_key = Some(KeySource::Inline(InlineKey {
        private_key: Some(Secret::Plain("ORIGINAL".into())), certificate: None, keyring: false,
    }));
    let b = f.build_body();
    match b.key {
        Some(KeySource::Inline(ik)) => assert_eq!(ik.private_key.unwrap().as_plain(), Some("ORIGINAL")),
        _ => panic!("original inline key must be preserved when private stays blank"),
    }
}

#[test]
fn build_body_path_source_unchanged_behavior() {
    let mut f = complete_cred_form();
    f.secret_kind = SecretChoice::IdentityKey;
    f.source = SourceChoice::Path;
    f.identity = "/k/id".into();
    assert_eq!(f.build_body().key.as_ref().and_then(KeySource::as_path),
        Some(std::path::Path::new("/k/id")));
}
```
(`TextArea::new(vec![...])` constructs a prefilled textarea — confirm the exact constructor name in docs.rs for v0.9.2; if it differs, adapt.)

- [ ] **Step 2: Run — expect RED** (build_body still routes only via `identity`).

- [ ] **Step 3: Implement** — replace the `SecretChoice::IdentityKey` arm of `build_body`:

```rust
            SecretChoice::IdentityKey => {
                let mut body = CredentialBody::new(trimmed_user);
                match self.source {
                    SourceChoice::Path => {
                        let key = self.identity.trim();
                        if !key.is_empty() {
                            body = body.with_key(key);
                        } else if let Some(KeySource::Inline(ik)) = self.orig_key.clone() {
                            body.key = Some(KeySource::Inline(ik));
                        }
                    }
                    SourceChoice::Inline => {
                        let private = self.inline_private.lines().join("\n");
                        let cert = self.inline_cert.lines().join("\n");
                        if !private.trim().is_empty() {
                            let cert_sec = (!cert.trim().is_empty())
                                .then(|| Secret::Plain(cert));
                            body = body.with_inline_key(Secret::Plain(private), cert_sec);
                        } else if let Some(KeySource::Inline(ik)) = self.orig_key.clone() {
                            // Private blank on edit: preserve the original inline
                            // material verbatim (do not destroy the only secret).
                            body.key = Some(KeySource::Inline(ik));
                        }
                    }
                }
                body
            }
```
Remove the stale "Plan 2 will add real paste-editing" comment from the prior placeholder branch.

- [ ] **Step 4: Run — pass; clippy + fmt + commit**

```bash
cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): build_body routes inline source to with_inline_key"
```

---

## Task 4: `CredForm` rendering — multiline textarea block + dynamic body_rows + cursor

**Files:**
- Modify: `src/tui/wizard/cred.rs` (`render_row`, `row_value_and_placeholder`, `draw_in_dialog`, `body_rows`).

**Interfaces:**
- Consumes: Task 2/3 state; `fit::focus_window`; `TextArea` render.
- Produces: Source row renders `bracketed(source.label())`; InlinePrivate/Cert render a one-line SUMMARY when not focused (`"<private key: N lines>"` / placeholder) and a multiline editor block when focused; `body_rows` grows by `TEXTAREA_H` (5) when a textarea is focused.

- [ ] **Step 1: Write the failing tests (RED)** — render-smoke (no pixel asserts):

```rust
#[test]
fn draw_in_dialog_renders_without_panic_across_source_and_focus_states() {
    use crate::tui::dialog::draw_dialog;
    use ratatui::{Terminal, backend::TestBackend};
    let mut f = complete_cred_form();
    let mut term = Terminal::new(TestBackend::new(100, 40)).unwrap();
    for secret in [SecretChoice::None, SecretChoice::Password, SecretChoice::IdentityKey] {
        for source in [SourceChoice::Path, SourceChoice::Inline] {
            f.secret_kind = secret;
            f.source = source;
            for focus in [CredField::Name, CredField::SecretKind, CredField::Source,
                          CredField::Identity, CredField::InlinePrivate, CredField::InlineCert] {
                f.focus = focus;
                term.draw(|fr| {
                    let body = draw_dialog(fr, &f.title(), f.body_rows(),
                        &[("Tab","field"),("^S","save"),("Esc","cancel")]);
                    f.draw_in_dialog(fr, body);
                }).unwrap();
            }
        }
    }
}

#[test]
fn body_rows_grows_when_a_textarea_is_focused() {
    let mut f = complete_cred_form();
    f.secret_kind = SecretChoice::IdentityKey;
    f.source = SourceChoice::Inline;
    f.focus = CredField::Name;
    let collapsed = f.body_rows();
    f.focus = CredField::InlinePrivate;
    let expanded = f.body_rows();
    assert!(expanded > collapsed, "focused textarea must grow the dialog");
    assert_eq!(expanded - collapsed, crate::tui::wizard::cred::TEXTAREA_H);
}
```

- [ ] **Step 2: Run — expect RED** (`Source`/`Inline*` not in `render_row`; `body_rows` static).

- [ ] **Step 3: Implement**

Add a module constant: `pub(crate) const TEXTAREA_H: u16 = 5;` (the multiline editor block height; dialog must fit it).

`row_value_and_placeholder` — add arms:
```rust
            CredField::Source => {
                (bracketed(self.source.label()),
                 Some("<- -> cycle: Path / Inline"))
            }
            CredField::InlinePrivate => {
                let n = self.inline_private.lines().len();
                if n == 1 && self.inline_private.lines()[0].is_empty() {
                    (String::new(), Some("paste private key (focus to edit multiline)"))
                } else {
                    (format!("{} line(s) of private key", n), None)
                }
            }
            CredField::InlineCert => {
                let n = self.inline_cert.lines().len();
                if n == 1 && self.inline_cert.lines()[0].is_empty() {
                    (String::new(), Some("optional certificate (focus to edit)"))
                } else {
                    (format!("{} line(s) of certificate", n), None)
                }
            }
```
(`render_row` already routes through `row_value_and_placeholder`, so Source/InlinePrivate/InlineCert rows render as single lines with no extra work — they only differ when FOCUSED, handled in `draw_in_dialog`.)

`body_rows` — make it focus-aware:
```rust
    pub fn body_rows(&self) -> u16 {
        let max_fields = [SecretChoice::None, SecretChoice::Password, SecretChoice::IdentityKey]
            .iter()
            .map(|&secret| {
                let max_source = if secret == SecretChoice::IdentityKey {
                    [SourceChoice::Path, SourceChoice::Inline].iter()
                        .map(|&s| CredField::ORDER.iter()
                            .filter(|&&f| Self::field_reachable(f, secret, s)).count())
                        .max().unwrap_or(0)
                } else {
                    CredField::ORDER.iter()
                        .filter(|&&f| Self::field_reachable(f, secret, SourceChoice::Path)).count()
                };
                max_source
            }).max().unwrap_or(0);
        let textarea_extra = if matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert)
            { TEXTAREA_H } else { 0 };
        (max_fields + textarea_extra + 2) as u16 // + error + hint
    }
```

`draw_in_dialog` — after rendering the field rows into `fields_area` (unchanged) and BEFORE the error/hint rows, insert the focused-textarea block:
```rust
        // If a multiline paste field is focused, expand a TEXTAREA_H editor
        // block right below the field rows (inside fields_area's slack). The
        // block holds the live TextArea; the field row above shows the summary.
        let needs_block = matches!(self.focus, CredField::InlinePrivate | CredField::InlineCert);
        let [list_area, editor_area, error_area, hint_area] = Layout::vertical([
            Constraint::Length(rows.len() as u16),
            Constraint::Length(if needs_block { TEXTAREA_H } else { 0 }),
            Constraint::Length(1),
            Constraint::Length(1),
        ]).areas(fields_area);
```
(replace the prior `[fields_area, error_area, hint_area]` 3-split; the field list now goes in `list_area`, the textarea block in `editor_area`, error/hint unchanged.) Render the list into `list_area`, then:
```rust
        if needs_block {
            let ta: &TextArea = match self.focus {
                CredField::InlinePrivate => &self.inline_private,
                CredField::InlineCert => &self.inline_cert,
                _ => unreachable!("guarded by needs_block"),
            };
            frame.render_widget(ta, editor_area);
        }
```
(Confirm against docs.rs whether `frame.render_widget(&textarea, area)` is the v0.9.2 call or whether the textarea exposes `WidgetRef::render_ref`; use whichever compiles. The textarea draws its own cursor, so do NOT call `set_cursor_position` for the textarea fields — extend the existing `cursor_target`/`set_cursor_position` guard to skip `InlinePrivate`/`InlineCert`/`Source`, which Task 2 already returns `None` for.) `focus_window` still operates on the field list only; the editor block is separate so it never scrolls away.

- [ ] **Step 4: Run — pass; clippy + fmt + commit**

```bash
cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): render inline-key multiline editor block in cred wizard"
```

---

## Task 5: Mirror the same changes on `HostForm` (Independent branch)

**Files:**
- Modify: `src/tui/wizard/host.rs` (struct, `new_add`, `new_edit`/`from_host`, `field_reachable`, `reachable_fields`, `on_key`, `build_inline_body`, `focused_text_len`, `cursor_target`, `render_row`/`row_value_and_placeholder`, `draw_in_dialog`, `body_rows`).

**Interfaces:** identical shape to Tasks 2–4 but on the host form's Independent branch (the `Field` enum, `AuthChoice::Independent`). `build_inline_body` plays the role of CredForm's `build_body` for the inline auth body.

- [ ] **Step 1: Write failing tests (RED)** mirroring the cred tests under `HostForm`: reachable-fields under Independent + Path/Inline; Source ←/→ cycle; typing into InlinePrivate goes to the textarea; `build_inline_body` under Inline + non-empty private produces `Auth::Inline` with `KeySource::Inline`; blank private on edit preserves the original inline key; multiline join with `\n`; render smoke across Independent × Path/Inline × focus states; `body_rows` grows when a textarea is focused. Reuse the exact assertions from Tasks 2–4 adapted to `HostForm`/`Field`/`AuthChoice::Independent`.

- [ ] **Step 2: Run — expect RED.**

- [ ] **Step 3: Implement** — apply the same edits as Tasks 2–4 to `HostForm`:
  - add `source: SourceChoice`, `inline_private: TextArea`, `inline_cert: TextArea` (Independent branch only; Reference branch ignores them);
  - `new_add`/`from_host` initialize them (orig Inline → Source::Inline, empty textareas; orig Path → Source::Path + `identity` prefilled);
  - `field_reachable(field, auth, secret, source)` — under `AuthChoice::Independent` + `SecretChoice::IdentityKey`, the same Source/Identity/InlinePrivate/InlineCert gating as CredForm; under Reference, the inline fields stay unreachable;
  - `on_key` Source ←/→ cycle (only when Independent + IdentityKey) and textarea-input forwarding for `InlinePrivate`/`InlineCert`;
  - `build_inline_body` — the same `match self.source { Path => …, Inline => with_inline_key … }` plus the blank-preserves-orig rule;
  - render: `row_value_and_placeholder` Source/InlinePrivate/InlineCert arms (copy from Task 4); `draw_in_dialog` textarea block (copy the Layout split from Task 4); `body_rows` focus-aware (Independent + textarea focus → +TEXTAREA_H).

  Because the host form already gates Identity/Password under Independent + Secret, the diff is mechanical once Task 4's cred shape is settled. Do NOT touch the Reference branch or `cycle_credential`/picker behavior.

- [ ] **Step 4: Run — pass; clippy + fmt + commit**

```bash
cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): inline-key multiline editor in host wizard (Independent)"
```

---

## Task 6: Docs + full gate + smoke

**Files:**
- Modify: `CLAUDE.md` (TUI section: document the Source chooser + inline paste; remove any "TUI paste deferred to Plan 2" note Plan 1 may have left).

- [ ] **Step 1: Update CLAUDE.md** — in the TUI / Identity & Config Model section, note: under the host/cred wizard's `Secret = IdentityKey`, a `Source` row cycles `Path ↔ Inline`; `Inline` shows two multiline paste areas (private key required, certificate optional) that expand when focused; key text is never echoed on edit (the original inline key is preserved when the private area is left blank). Remove Plan 1's "TUI paste-editing is Plan 2" placeholder wording now that it ships.

- [ ] **Step 2: Full gate**

```bash
cargo build --workspace --release
SSHRACK_PASSPHRASE=test cargo test --workspace -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 3: Manual smoke (controller has no TTY — document the steps for the user)** — the wizard is interactive; the controller cannot drive it. Document for the user: `cargo run -q --` → `^a` (add credential) → Tab to Secret → `→` to IdentityKey → Tab to Source → `→` to Inline → Tab to Privkey → paste a private key → `^S` → `cred show <name>` shows `key: <inline>`. Note this is deferred to the user for live verification.

- [ ] **Step 4: Commit + finish**

```bash
git add -A && git commit -m "docs(tui): inline-key Source chooser + multiline paste in wizards"
```
Then use `superpowers:finishing-a-development-branch` to merge.

---

## Self-Review

**1. Spec coverage:**
- Source chooser Path/Inline under IdentityKey — Task 1 (types) + Tasks 2/5 (state). ✅
- Multiline paste private (required) + cert (optional) — Tasks 2/5 (TextArea state/input) + Task 4 (render block). ✅
- Inline → with_inline_key, multiline join — Tasks 3/5 (build). ✅
- Data safety: edit preserves orig inline when private blank; key text never echoed — Tasks 2/5 (new_edit) + Tasks 3/5 (build_body). ✅
- Both cred and host wizards — Tasks 2–4 (cred) + Task 5 (host mirror). ✅
- Dynamic dialog height (textarea focus) — Task 4 (body_rows + Layout). ✅
- No core change — all tasks are `src/tui/` + root Cargo.toml. ✅
- Remove Plan 1 placeholder — Tasks 3/5 (drop "Plan 2 will add" comment) + Task 6 (CLAUDE.md). ✅

**2. Placeholder scan:** No TBD/TODO. Where the exact `ratatui-textarea` v0.9.2 call signature could differ (`TextArea::new(Vec<String>)`, `frame.render_widget(&textarea, area)`), the plan names the expected form AND instructs the implementer to confirm against docs.rs for the resolved version — the integration points (forward keys via `textarea.input(key)`, read text via `textarea.lines()`, render into a rect) are fixed regardless.

**3. Type consistency:** `SourceChoice` (Task 1) consumed identically in Tasks 2–5. `CredField`/`Field` new variants (Task 1) used in `field_reachable`/`on_key`/`render_row` (Tasks 2–5). `TEXTAREA_H` (Task 4) referenced in Task 5's `body_rows`. `with_inline_key(Secret, Option<Secret>)` signature (Plan 1) matches Tasks 3/5. `build_body`/`build_inline_body` both branch on `self.source` with the same Path/Inline + preserve-orig semantics.
