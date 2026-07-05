# Field-Type Affordance Suffix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Give every wizard field a self-describing type signal at the right edge of the value column — ` ▸` (accent) on trigger rows (`Enter` opens a modal: file picker, fuzzy credential picker) and ` ¶ ▸` (dim pilcrow + accent triangle) on multiline-trigger rows (inline private-key/certificate paste) — so a user can tell at a glance, without focusing or reading help, how each row is interacted with. Text / password / switch rows already self-describe (cursor / `•••` mask / `< >` brackets) and gain no suffix.

**Architecture:** Introduce one shared pure render primitive, `render_field_row(...)`, plus a `FieldKind` enum and an `affordance_suffix` builder, in `wizard/mod.rs`. Both `HostForm::render_row` and `CredForm::render_row` — which today hold byte-identical bodies differing only in label width — collapse into thin delegates to this one function. Each form contributes only a `field_kind(field) -> FieldKind` mapping (which it owns, since the field enums differ) and its existing `row_value_and_placeholder`. The suffix width is reserved before truncating the value, so the glyph is never clipped by a long value or a narrow terminal. This is a TUI-only, pure-rendering change: `sshrack-core` is untouched, no state machine or `on_key` changes, no new dependencies (`unicode-width` is already a root dep).

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, `unicode-width` 0.2 (already present). **No new dependencies.**

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`. Prefer `unwrap_or` / `is_some_and`.
- **TDD for pure logic** — RED → GREEN → REFACTOR. All new logic here is pure (no fs, no terminal).
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Dev stage, no compat code** — replace the old `render_row` bodies outright; do not keep a parallel path.
- **`sshrack-core` zero-UI invariant** — this plan never touches `crates/sshrack-core/`.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`.
- **Root package is a binary, not a lib** — run wizard tests with `cargo test --bin sshrack tui::wizard`, NOT `-p sshrack --lib` (that errors with "no library targets").

**Scope invariant:** Only `src/tui/wizard/mod.rs`, `src/tui/wizard/host.rs`, `src/tui/wizard/cred.rs` change.

---

## Inventory (the contract this plan must satisfy)

- The two `render_row` bodies are **byte-identical in shape** (`host.rs:1149-1175`, `cred.rs:887-913`): build a `label_span` (`"▶ "/"  " + right-aligned label + ": "`, accent+bold when focused else dim), then `truncate_cells(value, avail)` / `truncate_cells(placeholder, avail)` where `avail = row_width - VALUE_COL`, then `value_spans(...)`, then `Line::from(spans).alignment(Left)`. Only `label_width` (10 vs 8) and the value source differ. This is the DRY extraction point.
- `value_spans(value, placeholder)` (`mod.rs:449`) and `bracketed(label)` (`mod.rs:464`) already live in `mod.rs`; `render_field_row` reuses both.
- `truncate_cells` is `crate::tui::fit::truncate_cells` (`fit.rs:74`); `theme::accent() -> Style` (`theme.rs:33`); `unicode-width = "0.2"` is already in the root `Cargo.toml`.
- `HOST_VALUE_COL = 2 + HOST_LABEL_WIDTH + 2` and `CRED_VALUE_COL = 2 + CRED_LABEL_WIDTH + 2` (`mod.rs:484/488`) duplicate the value-column formula; this plan DRYs them through a new `value_col_offset` `const fn`. The existing test `HOST_VALUE_COL == 2 + HOST_LABEL_WIDTH + 2` (`mod.rs:641`) stays green.
- Existing render-output tests assert on **`row_value_and_placeholder`** (the value *string*, e.g. `"< Reference >"`), NOT on `render_row` spans (`host.rs:2245-2270`, `cred.rs:1901`). This plan does not change `row_value_and_placeholder`'s contract (still returns bracketed strings for switches), so those tests stay green. The only `row_value_and_placeholder` edits are shortening the trigger/multiline **placeholder hint strings** (the `Option<&'static str>`), which those tests ignore.
- `cursor_target` is unchanged (still `Some` only for Name/Host/Port/User/Password; `None` for choosers and trigger rows). No terminal-cursor logic moves.

**Placeholder copy changes** (the verbal `"(Enter to edit)"` / `"Enter to browse"` / `"Enter pick"` hints become redundant once `▸` advertises "Enter opens a modal", so they are shortened for `简洁`):

| Field | Branch | Old placeholder | New placeholder |
|---|---|---|---|
| `Field::Identity` | empty | `"Enter to browse for a private key"` | `"browse for a private key"` |
| `Field::Credential` | empty, has creds | `"<- -> cycle  ·  Enter pick"` | `"pick a credential"` |
| `Field::InlinePrivate` | empty | `"paste private key (Enter to edit)"` | `"paste private key"` |
| `Field::InlineCert` | empty | `"optional certificate (Enter to edit)"` | `"optional certificate"` |
| `CredField::Identity` | empty | `"Enter to browse for a private key"` | `"browse for a private key"` |
| `CredField::InlinePrivate` | empty | `"paste private key (Enter to edit)"` | `"paste private key"` |
| `CredField::InlineCert` | empty | `"optional certificate (Enter to edit)"` | `"optional certificate"` |

Switch placeholders (`Auth`/`Secret`/`Source`/`SecretKind`) are **unchanged** (they describe the cycle mechanic, not redundant with `▸`). `Field::Credential` empty-with-no-creds (`"no credentials defined — …"`) is unchanged (its `field_kind` is `Text`, so no `▸` shows there — see Task 1).

---

## File Structure

```
src/tui/wizard/
├── mod.rs              # MODIFY — add FieldKind + affordance_suffix{,_width} + value_col_offset
│                       #          + render_field_row (the single shared row renderer);
│                       #          DRY HOST_VALUE_COL/CRED_VALUE_COL through value_col_offset;
│                       #          add pure TDD tests for the new primitives
├── host.rs             # MODIFY — add HostForm::field_kind; render_row → delegate to
│                       #          render_field_row; shorten 4 placeholder hints; drop now-unused
│                       #          imports (truncate_cells/value_spans) per clippy; + field_kind test
└── cred.rs             # MODIFY — add CredForm::field_kind; render_row → delegate; shorten 3
                        #          placeholder hints; drop now-unused imports; + field_kind test
```

No new modules, no new files, no public-API change visible outside `wizard` (everything is `pub(super)`).

---

## Task 1: shared affordance primitive in `wizard/mod.rs` + HostForm wiring

**Files:**
- Modify: `src/tui/wizard/mod.rs` (new `FieldKind` + 2 consts + 3 fns + DRY the value-col consts + tests + imports)
- Modify: `src/tui/wizard/host.rs` (add `field_kind`; delegate `render_row`; shorten placeholders; clean imports; + mapping test)

**Interfaces:**
- Produces (in `mod.rs`, all `pub(super)`):
  - `enum FieldKind { Text, Password, Switch, Trigger, MultilineTrigger }`
  - `const TRIGGER_GLYPH: &str = " \u{25B8}";`
  - `const MULTILINE_PARA: &str = " \u{00B6}";`
  - `fn affordance_suffix_width(kind: FieldKind) -> usize`
  - `fn affordance_suffix(kind: FieldKind) -> Vec<Span<'static>>`
  - `const fn value_col_offset(label_width: u16) -> u16`
  - `fn render_field_row(label: &str, focused: bool, value: &str, placeholder: Option<&str>, kind: FieldKind, label_width: u16, row_width: u16) -> Line<'static>`
- Produces (in `host.rs`):
  - `fn HostForm::field_kind(&self, field: Field) -> FieldKind`
- Consumes: `crate::tui::fit::truncate_cells`, `crate::tui::theme::accent`, existing `value_spans` / `bracketed`, `unicode_width::UnicodeWidthStr`.

- [ ] **Step 1: Add the imports to `mod.rs`**

The file currently has `use ratatui::style::Style;` and `use ratatui::text::Span;` (lines 25-26). Add the rest needed by the new code, right after them:

```rust
use ratatui::layout::Alignment;
use ratatui::style::Modifier;
use ratatui::text::Line;
use unicode_width::UnicodeWidthStr;

use crate::tui::fit::truncate_cells;
use crate::tui::theme;
```

(Keep the existing `use ratatui::style::Style;` and `use ratatui::text::Span;` lines; these are additions.)

- [ ] **Step 2: Write the failing tests (RED)**

In the existing `#[cfg(test)] mod tests` block in `mod.rs` (which already holds the `bracketed_*` tests around line 797-813), append these tests. They reference `FieldKind`, `affordance_suffix`, `affordance_suffix_width`, `render_field_row`, `value_col_offset`, and `HOST_LABEL_WIDTH` — none of which exist yet — so the test build fails to compile (the RED signal):

```rust
    // ---- field-type affordance suffix (shared render primitive) ----

    #[test]
    fn affordance_suffix_width_matches_kind() {
        assert_eq!(affordance_suffix_width(FieldKind::Text), 0);
        assert_eq!(affordance_suffix_width(FieldKind::Password), 0);
        assert_eq!(affordance_suffix_width(FieldKind::Switch), 0);
        assert_eq!(affordance_suffix_width(FieldKind::Trigger), 2);
        assert_eq!(affordance_suffix_width(FieldKind::MultilineTrigger), 4);
    }

    #[test]
    fn affordance_suffix_glyphs_match_width() {
        // The rendered spans (concatenated) must equal the width function's
        // accounting — single source of truth (the consts), no desync.
        fn concat(spans: &[Span<'_>]) -> String {
            spans.iter().map(|s| s.content.as_ref()).collect()
        }
        assert_eq!(concat(&affordance_suffix(FieldKind::Text)), "");
        assert_eq!(concat(&affordance_suffix(FieldKind::Password)), "");
        assert_eq!(concat(&affordance_suffix(FieldKind::Switch)), "");
        assert_eq!(concat(&affordance_suffix(FieldKind::Trigger)), " ▸");
        assert_eq!(
            concat(&affordance_suffix(FieldKind::MultilineTrigger)),
            " ¶ ▸"
        );
        // and that concatenated cell-width == affordance_suffix_width
        assert_eq!(
            unicode_width::UnicodeWidthStr::width(concat(&affordance_suffix(FieldKind::Trigger)).as_str()),
            affordance_suffix_width(FieldKind::Trigger)
        );
        assert_eq!(
            unicode_width::UnicodeWidthStr::width(
                concat(&affordance_suffix(FieldKind::MultilineTrigger)).as_str()
            ),
            affordance_suffix_width(FieldKind::MultilineTrigger)
        );
    }

    #[test]
    fn value_col_offset_is_marker_plus_label_plus_colon() {
        assert_eq!(value_col_offset(0), 4);
        assert_eq!(value_col_offset(HOST_LABEL_WIDTH), HOST_VALUE_COL);
        assert_eq!(value_col_offset(CRED_LABEL_WIDTH), CRED_VALUE_COL);
    }

    #[test]
    fn render_field_row_text_has_no_suffix() {
        let line = render_field_row(
            "Name", true, "web", None, FieldKind::Text, HOST_LABEL_WIDTH, 60,
        );
        // label span + value span only; no affordance suffix appended.
        assert_eq!(line.spans.len(), 2);
        assert_eq!(line.spans[1].content.as_ref(), "web");
    }

    #[test]
    fn render_field_row_switch_has_no_suffix() {
        // Switches self-describe via < … >; the suffix is empty for them.
        let line = render_field_row(
            "Auth", true, "< Independent >", None, FieldKind::Switch, HOST_LABEL_WIDTH, 60,
        );
        let last: &str = line.spans.last().expect("at least the value span").content.as_ref();
        assert_eq!(last, "< Independent >");
    }

    #[test]
    fn render_field_row_trigger_appends_accent_triangle() {
        let line = render_field_row(
            "Identity", false, "/home/me/.ssh/id_ed25519", None,
            FieldKind::Trigger, HOST_LABEL_WIDTH, 60,
        );
        let last = line.spans.last().expect("suffix present");
        assert_eq!(last.content.as_ref(), " ▸");
    }

    #[test]
    fn render_field_row_multiline_appends_pilcrow_then_triangle() {
        let line = render_field_row(
            "Privkey", false, "5 lines", None,
            FieldKind::MultilineTrigger, HOST_LABEL_WIDTH, 60,
        );
        let spans = &line.spans;
        // last two spans are " ¶" (dim) and " ▸" (accent), in that order.
        assert_eq!(spans[spans.len() - 2].content.as_ref(), " ¶");
        assert_eq!(spans[spans.len() - 1].content.as_ref(), " ▸");
    }

    #[test]
    fn render_field_row_trigger_empty_value_still_shows_suffix_after_placeholder() {
        // Empty value + a placeholder: the suffix follows the dim placeholder,
        // advertising "this dim row IS interactive — Enter opens a modal".
        let line = render_field_row(
            "Identity", false, "", Some("browse for a private key"),
            FieldKind::Trigger, HOST_LABEL_WIDTH, 60,
        );
        let last = line.spans.last().expect("suffix present");
        assert_eq!(last.content.as_ref(), " ▸");
    }

    #[test]
    fn render_field_row_reserves_suffix_so_long_value_truncates_not_the_glyph() {
        // Tight row_width so the value must truncate; the glyph must survive and
        // the line must never overflow row_width.
        let row_width: u16 = 22; // value_col_offset(10) = 14 → value_col = 8
        let line = render_field_row(
            "Identity", false,
            "/home/ryan/.ssh/id_ed25519", // 24 chars, cannot fit in 8 minus 2 suffix
            None, FieldKind::Trigger, HOST_LABEL_WIDTH, row_width,
        );
        let width = line.width();
        assert!(
            width <= row_width as usize,
            "line must not overflow the row: {width} > {row_width}"
        );
        assert_eq!(
            line.spans.last().expect("suffix present").content.as_ref(),
            " ▸",
            "glyph must survive value truncation"
        );
    }
```

- [ ] **Step 3: Run — expect RED (compile failure)**

```bash
cargo test --bin sshrack tui::wizard::tests 2>&1 | tail -20
```
Expected: fails to compile (`cannot find function/value affordance_suffix` / `FieldKind` / `render_field_row` / `value_col_offset`).

- [ ] **Step 4: Implement the shared primitive + DRY the value-col consts**

Add the following block in `mod.rs`, immediately **before** the existing `pub(super) fn value_spans` definition (around line 449) — i.e. as a new section in the shared-helpers area:

```rust
// ===========================================================================
// Field-type affordance (shared row renderer)
// ===========================================================================

/// How a wizard field is interacted with, independent of which form owns it.
/// Drives the type-affordance suffix appended by [`render_field_row`] so every
/// field — host or credential — renders through one path and reads the same:
///
/// - [`FieldKind::Text`] / [`FieldKind::Password`]: the terminal cursor (and,
///   for passwords, the `•••` mask) already self-describe "type here".
/// - [`FieldKind::Switch`]: the `< … >` brackets ([`bracketed`]) already
///   self-describe "cycle ←/→".
/// - [`FieldKind::Trigger`]: `Enter` opens a modal (file picker / fuzzy
///   credential picker). The ` ▸` suffix ([`TRIGGER_GLYPH`], accent)
///   advertises that — empty or filled.
/// - [`FieldKind::MultilineTrigger`]: `Enter` opens a multiline editor for
///   secret content never echoed inline. The ` ¶ ▸` suffix ([`MULTILINE_PARA`]
///   dim pilcrow + [`TRIGGER_GLYPH`] accent) says "hidden multi-line content
///   lives here; Enter to open".
///
/// The suffix lives at the right edge of the value column and is always
/// rendered when it fits, so a row's interaction type is visible at a glance
/// without focusing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FieldKind {
    Text,
    Password,
    Switch,
    Trigger,
    MultilineTrigger,
}

/// The triangle half of a trigger suffix: a leading space + a small accent
/// triangle (`U+25B8`). Means "Enter opens a modal". Reused as the trailing
/// half of the multiline-trigger suffix.
const TRIGGER_GLYPH: &str = " \u{25B8}";

/// The pilcrow half of the multiline-trigger suffix: a leading space + a dim
/// pilcrow (`U+00B6`). Means "hidden multi-line content lives here".
const MULTILINE_PARA: &str = " \u{00B6}";

/// Display-cell width a `kind`'s suffix consumes, so the renderer can reserve
/// exact space before truncating the value (the glyph is never clipped).
/// Derived from the same constants [`affordance_suffix`] builds its spans
/// from — single source of truth, pinned in sync by the
/// `affordance_suffix_glyphs_match_width` test.
pub(super) fn affordance_suffix_width(kind: FieldKind) -> usize {
    match kind {
        FieldKind::Text | FieldKind::Password | FieldKind::Switch => 0,
        FieldKind::Trigger => UnicodeWidthStr::width(TRIGGER_GLYPH),
        FieldKind::MultilineTrigger => {
            UnicodeWidthStr::width(MULTILINE_PARA) + UnicodeWidthStr::width(TRIGGER_GLYPH)
        }
    }
}

/// The styled suffix spans for a field kind (empty vec for text/password/
/// switch). Built from [`TRIGGER_GLYPH`] / [`MULTILINE_PARA`] so
/// [`affordance_suffix_width`] and the rendered spans can never disagree.
pub(super) fn affordance_suffix(kind: FieldKind) -> Vec<Span<'static>> {
    match kind {
        FieldKind::Text | FieldKind::Password | FieldKind::Switch => Vec::new(),
        FieldKind::Trigger => vec![Span::styled(TRIGGER_GLYPH.to_string(), theme::accent())],
        FieldKind::MultilineTrigger => vec![
            Span::styled(MULTILINE_PARA.to_string(), Style::new().dim()),
            Span::styled(TRIGGER_GLYPH.to_string(), theme::accent()),
        ],
    }
}

/// Column where the editable value begins within a rendered field row:
/// `"▶ "/"  " (2) + right-aligned label + ": " (2)`. A `const fn` so the
/// per-form value-column constants below derive from one definition.
pub(super) const fn value_col_offset(label_width: u16) -> u16 {
    2 + label_width + 2
}

/// Render one wizard field row through the single shared path: focus marker +
/// right-aligned label + value (or dim placeholder) + type-affordance suffix.
/// Pure; consumed by both [`HostForm::render_row`] and [`CredForm::render_row`]
/// so every field — host or credential — looks identical in shape; only the
/// label width, value/placeholder, and [`FieldKind`] differ.
///
/// The suffix width is reserved *before* truncating the value/placeholder, so
/// the glyph is always the last thing rendered and is never clipped by a long
/// value or a narrow terminal.
///
/// [`HostForm::render_row`]: host::HostForm::render_row
/// [`CredForm::render_row`]: cred::CredForm::render_row
pub(super) fn render_field_row(
    label: &str,
    focused: bool,
    value: &str,
    placeholder: Option<&str>,
    kind: FieldKind,
    label_width: u16,
    row_width: u16,
) -> Line<'static> {
    let cursor = if focused { "▶ " } else { "  " };
    let label_span = Span::styled(
        format!("{cursor}{label:>WIDTH$}: ", WIDTH = label_width as usize),
        if focused {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            Style::new().dim()
        },
    );

    let suffix = affordance_suffix(kind);
    let value_col = (row_width.saturating_sub(value_col_offset(label_width))) as usize;
    let avail_for_value = value_col.saturating_sub(affordance_suffix_width(kind));
    let trunc_value = truncate_cells(value, avail_for_value);
    let trunc_ph = placeholder.map(|p| truncate_cells(p, avail_for_value));

    let mut spans = vec![label_span];
    spans.extend(value_spans(&trunc_value, trunc_ph.as_deref()));
    spans.extend(suffix);
    Line::from(spans).alignment(Alignment::Left)
}
```

Then **DRY the two value-col constants**. Replace these two lines (currently at `mod.rs:484` and `:488`):

```rust
pub(super) const HOST_VALUE_COL: u16 = 2 + HOST_LABEL_WIDTH + 2;
```
and
```rust
pub(super) const CRED_VALUE_COL: u16 = 2 + CRED_LABEL_WIDTH + 2;
```

with:

```rust
pub(super) const HOST_VALUE_COL: u16 = value_col_offset(HOST_LABEL_WIDTH);
```
and
```rust
pub(super) const CRED_VALUE_COL: u16 = value_col_offset(CRED_LABEL_WIDTH);
```

(Leave their surrounding doc comments as-is; the derivation is now just routed through `value_col_offset`.)

- [ ] **Step 5: Run the new tests — expect GREEN**

```bash
cargo test --bin sshrack tui::wizard::tests 2>&1 | tail -20
```
Expected: all `affordance_suffix_*`, `value_col_offset_*`, and `render_field_row_*` tests pass.

- [ ] **Step 6: Wire HostForm — add `field_kind` and delegate `render_row`**

In `src/tui/wizard/host.rs`:

(a) Add `FieldKind` and `render_field_row` to the `use super::{...}` import (lines 33-37). The import becomes:

```rust
use super::{
    AuthChoice, AuthKind, CredPicker, Field, FieldKind, HOST_LABEL_WIDTH, HOST_VALUE_COL, KeyPaste,
    PasteKind, PasteOutcome, PickerOutcome, SaveError, SecretChoice, SourceChoice, backspace_at,
    bracketed, insert_char_at, render_field_row, validate, value_spans,
};
```

(b) Add a `field_kind` method on `HostForm` (place it next to `render_row`, ~line 1149):

```rust
    /// The interaction type of `field`, which drives its affordance suffix in
    /// [`render_row`]. Text/password/switch self-describe; trigger rows
    /// (Identity file-picker, Credential fuzzy-picker) carry `▸`, and inline
    /// paste rows carry `¶ ▸`. Credential only advertises the pick affordance
    /// when at least one credential exists to pick — otherwise `Enter` opens an
    /// empty picker and the `▸` would promise an action that yields nothing.
    fn field_kind(&self, field: Field) -> FieldKind {
        match field {
            Field::Name | Field::Host | Field::Port | Field::User => FieldKind::Text,
            Field::Password => FieldKind::Password,
            Field::Auth | Field::Secret | Field::Source => FieldKind::Switch,
            Field::Identity => FieldKind::Trigger,
            Field::InlinePrivate | Field::InlineCert => FieldKind::MultilineTrigger,
            Field::Credential => {
                if self.credential_names.is_empty() {
                    FieldKind::Text
                } else {
                    FieldKind::Trigger
                }
            }
        }
    }
```

(c) Replace the body of `render_row` (`host.rs:1149-1175`) with a thin delegate:

```rust
    fn render_row(&self, field: Field, row_width: u16) -> Line<'static> {
        let (value, placeholder) = self.row_value_and_placeholder(field);
        render_field_row(
            field.label(),
            self.focus == field,
            &value,
            placeholder,
            self.field_kind(field),
            HOST_LABEL_WIDTH,
            row_width,
        )
    }
```

- [ ] **Step 7: Shorten the four host placeholder hints**

In `HostForm::row_value_and_placeholder` (`host.rs:1178+`), make exactly these replacements (placeholder strings only — leave the value branches untouched):

- `Field::Identity` empty branch: change
  ```rust
  (String::new(), Some("Enter to browse for a private key"))
  ```
  to
  ```rust
  (String::new(), Some("browse for a private key"))
  ```

- `Field::Credential` placeholder when credentials exist: change
  ```rust
  Some("<- -> cycle  ·  Enter pick")
  ```
  to
  ```rust
  Some("pick a credential")
  ```

- `Field::InlinePrivate` empty branch: change
  ```rust
  (String::new(), Some("paste private key (Enter to edit)"))
  ```
  to
  ```rust
  (String::new(), Some("paste private key"))
  ```

- `Field::InlineCert` empty branch: change
  ```rust
  (String::new(), Some("optional certificate (Enter to edit)"))
  ```
  to
  ```rust
  (String::new(), Some("optional certificate"))
  ```

Leave `Field::Credential`'s no-credentials placeholder (`"no credentials defined — add one with the cred wizard"`) and `Field::Identity`'s filled placeholder (`"Enter to re-browse"`, never shown — value is non-empty) unchanged.

- [ ] **Step 8: Drop now-unused imports in `host.rs` (clippy-driven)**

After delegating, `host.rs` no longer references `truncate_cells` or `value_spans` directly in `render_row`. Run clippy; if it flags `truncate_cells` (line 39) and/or `value_spans` (in the `use super::{...}`) as unused, remove them. **Do not remove `bracketed`** (still used by `row_value_and_placeholder` for `Auth`/`Secret`/`Source`). Keep `HOST_VALUE_COL` if still referenced by `cursor_target`; remove only what clippy reports unused.

```bash
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 9: Add a HostForm `field_kind` mapping test**

In `host.rs`'s `#[cfg(test)] mod tests`, add:

```rust
    #[test]
    fn host_field_kind_maps_each_field_to_its_affordance() {
        // `field_kind` does not depend on auth_choice, so a default form is
        // enough. `FieldKind` is in scope unqualified via the test module's
        // `use super::*;` (host.rs imports it from `super`).
        let mut f = HostForm::new_add(vec![]);
        assert_eq!(f.field_kind(Field::Name), FieldKind::Text);
        assert_eq!(f.field_kind(Field::Host), FieldKind::Text);
        assert_eq!(f.field_kind(Field::Port), FieldKind::Text);
        assert_eq!(f.field_kind(Field::User), FieldKind::Text);
        assert_eq!(f.field_kind(Field::Auth), FieldKind::Switch);
        assert_eq!(f.field_kind(Field::Secret), FieldKind::Switch);
        assert_eq!(f.field_kind(Field::Source), FieldKind::Switch);
        assert_eq!(f.field_kind(Field::Identity), FieldKind::Trigger);
        assert_eq!(f.field_kind(Field::InlinePrivate), FieldKind::MultilineTrigger);
        assert_eq!(f.field_kind(Field::InlineCert), FieldKind::MultilineTrigger);
        assert_eq!(f.field_kind(Field::Password), FieldKind::Password);
        // No credentials defined → Credential offers nothing to pick → Text.
        assert_eq!(
            f.field_kind(Field::Credential),
            FieldKind::Text,
            "no creds → no pick affordance"
        );

        // With a credential defined, Credential advertises the pick trigger.
        f.credential_names = vec!["srv".to_string()];
        assert_eq!(f.field_kind(Field::Credential), FieldKind::Trigger);
    }
```

- [ ] **Step 10: Build + full workspace test + clippy + fmt + commit**

```bash
cargo build --workspace
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -10
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
```
Expected: build clean; every `test result:` line `ok`/`0 failed`; clippy clean; `FMT_OK`.

```bash
git add src/tui/wizard/mod.rs src/tui/wizard/host.rs
git commit -m "feat(tui): unified field-type affordance suffixes in host wizard" -m "Trigger rows (Identity file-picker, Credential fuzzy-picker) now carry a trailing accent triangle and multiline paste rows (Privkey/Cert) carry a dim pilcrow plus the triangle, so a row's interaction type is visible at a glance without focusing. Add one shared render_field_row in wizard/mod.rs and route both forms through it; the suffix width is reserved before value truncation so the glyph is never clipped. Text/password/switch rows are unchanged (cursor / mask / < > already self-describe). Shorten the now-redundant Enter-to-edit/browse placeholder hints. DRY HOST/CRED_VALUE_COL through a const value_col_offset. Pure-logic TDD coverage for the new primitives plus a HostForm field_kind mapping test."
```

---

## Task 2: apply the same affordance to the credential wizard

**Files:**
- Modify: `src/tui/wizard/cred.rs` (add `field_kind`; delegate `render_row`; shorten 3 placeholders; clean imports; + mapping test)

**Interfaces:**
- Consumes (from Task 1): `super::{FieldKind, render_field_row, CRED_LABEL_WIDTH}`.
- Produces: `fn CredForm::field_kind(&self, field: CredField) -> FieldKind`.

- [ ] **Step 1: Update the `use super::{...}` import in `cred.rs`**

Lines 23-27 become:

```rust
use super::{
    CRED_LABEL_WIDTH, CRED_VALUE_COL, CredField, CredSaveError, FieldKind, KeyPaste, PasteKind,
    PasteOutcome, SecretChoice, SourceChoice, backspace_at, bracketed, insert_char_at,
    render_field_row, validate_cred, value_spans,
};
```

- [ ] **Step 2: Add `field_kind` + delegate `render_row`**

In `src/tui/wizard/cred.rs`, add a `field_kind` method on `CredForm` (next to `render_row`, ~line 887):

```rust
    /// The interaction type of `field`, which drives its affordance suffix in
    /// [`render_row`]. Mirrors [`HostForm::field_kind`] minus the host-only
    /// rows. The credential wizard has no Reference/Credential row, so there is
    /// no "nothing to pick" suppression here.
    ///
    /// [`HostForm::field_kind`]: super::host::HostForm::field_kind
    fn field_kind(&self, field: CredField) -> FieldKind {
        match field {
            CredField::Name | CredField::User => FieldKind::Text,
            CredField::Password => FieldKind::Password,
            CredField::SecretKind | CredField::Source => FieldKind::Switch,
            CredField::Identity => FieldKind::Trigger,
            CredField::InlinePrivate | CredField::InlineCert => FieldKind::MultilineTrigger,
        }
    }
```

Replace the body of `render_row` (`cred.rs:887-913`) with the delegate:

```rust
    fn render_row(&self, field: CredField, row_width: u16) -> Line<'static> {
        let (value, placeholder) = self.row_value_and_placeholder(field);
        render_field_row(
            field.label(),
            self.focus == field,
            &value,
            placeholder,
            self.field_kind(field),
            CRED_LABEL_WIDTH,
            row_width,
        )
    }
```

- [ ] **Step 3: Shorten the three cred placeholder hints**

In `CredForm::row_value_and_placeholder` (`cred.rs:915+`):

- `CredField::Identity` empty branch: change
  ```rust
  (String::new(), Some("Enter to browse for a private key"))
  ```
  to
  ```rust
  (String::new(), Some("browse for a private key"))
  ```

- `CredField::InlinePrivate` empty branch: change
  ```rust
  (String::new(), Some("paste private key (Enter to edit)"))
  ```
  to
  ```rust
  (String::new(), Some("paste private key"))
  ```

- `CredField::InlineCert` empty branch: change
  ```rust
  (String::new(), Some("optional certificate (Enter to edit)"))
  ```
  to
  ```rust
  (String::new(), Some("optional certificate"))
  ```

- [ ] **Step 4: Drop now-unused imports in `cred.rs` (clippy-driven)**

Same as Task 1 Step 8: after delegating, `truncate_cells` (line 29) and `value_spans` (in the `use super::{...}`) may become unused. Run clippy and remove only what it flags. Keep `bracketed` (still used by `SecretKind`/`Source` branches) and `CRED_VALUE_COL` (still used by `cursor_target`).

```bash
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -20
```

- [ ] **Step 5: Add a CredForm `field_kind` mapping test**

In `cred.rs`'s `#[cfg(test)] mod tests`, add:

```rust
    #[test]
    fn cred_field_kind_maps_each_field_to_its_affordance() {
        // `FieldKind` is in scope unqualified via the test module's
        // `use super::*;` (cred.rs imports it from `super`).
        let f = CredForm::new_add();
        assert_eq!(f.field_kind(CredField::Name), FieldKind::Text);
        assert_eq!(f.field_kind(CredField::User), FieldKind::Text);
        assert_eq!(f.field_kind(CredField::SecretKind), FieldKind::Switch);
        assert_eq!(f.field_kind(CredField::Source), FieldKind::Switch);
        assert_eq!(f.field_kind(CredField::Identity), FieldKind::Trigger);
        assert_eq!(
            f.field_kind(CredField::InlinePrivate),
            FieldKind::MultilineTrigger
        );
        assert_eq!(
            f.field_kind(CredField::InlineCert),
            FieldKind::MultilineTrigger
        );
        assert_eq!(f.field_kind(CredField::Password), FieldKind::Password);
    }
```

- [ ] **Step 6: Build + full workspace test + clippy + fmt + commit**

```bash
cargo build --workspace
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -10
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
```
Expected: build clean; every `test result:` line `ok`/`0 failed`; clippy clean; `FMT_OK`.

```bash
git add src/tui/wizard/cred.rs
git commit -m "feat(tui): apply unified field-type affordance suffixes to cred wizard" -m "Route CredForm::render_row through the shared render_field_row and add CredForm::field_kind so the credential wizard gains the same trailing affordance glyphs (▸ on the Identity file-picker row, ¶ ▸ on the Privkey/Cert inline-paste rows) as the host wizard. Shorten the matching placeholder hints to match. Adds a field_kind mapping test."
```

---

## Self-Review

**1. Spec coverage:**
- "Trigger rows show `▸`" → `FieldKind::Trigger` + `affordance_suffix` + Identity (host Task 1 + cred Task 2) and Credential (host Task 1). ✅
- "Multiline rows show `¶ ▸`" → `FieldKind::MultilineTrigger` + InlinePrivate/InlineCert (host Task 1 + cred Task 2). ✅
- "统一 / unified across all places" → both forms delegate to one `render_field_row`; the only per-form input is `field_kind` + label width + value. ✅
- "代码严谨、解耦、简洁" → `FieldKind` + suffix consts are the single source of truth; width and spans derive from the same consts; `value_col_offset` DRYs the value-column formula; no compat code (old `render_row` bodies deleted). ✅
- "Glyph never clipped / survives truncation" → `render_field_row_reserves_suffix_so_long_value_truncates_not_the_glyph` test. ✅
- "Empty trigger rows still advertise" → `render_field_row_trigger_empty_value_still_shows_suffix_after_placeholder` test. ✅
- "Placeholder redundancy removed" → both tasks shorten the listed hints; switches untouched. ✅
- TDD for pure logic → all new logic is pure; tests written first (RED), then impl (GREEN), with mapping tests for each form. ✅

**2. Placeholder scan:** No TBD/TODO/"add appropriate". Every step has runnable code or an exact command. The two "use whichever path the compiler accepts / mirror the helper the surrounding tests use" notes are concrete disambiguations, not gaps — they tell the implementer exactly which to pick by trying the shorter form first.

**3. Type consistency:**
- `FieldKind` variants referenced identically in Task 1 (`field_kind` impl + tests) and Task 2 (`field_kind` impl + test): `Text`/`Password`/`Switch`/`Trigger`/`MultilineTrigger`. ✅
- `affordance_suffix(kind) -> Vec<Span<'static>>` and `affordance_suffix_width(kind) -> usize` both take `FieldKind` by value (it's `Copy`); `render_field_row` takes `kind: FieldKind` by value. Consistent. ✅
- `render_field_row(label, focused, value, placeholder, kind, label_width, row_width)` signature is identical between Task 1's definition and both call sites (host Task 1 Step 6, cred Task 2 Step 2): value/placeholder come from `row_value_and_placeholder` returning `(String, Option<&'static str>)` — `&value` is `&String`→`&str` via the `value: &str` param, `placeholder` is `Option<&str>` directly. ✅
- `value_col_offset: const fn` used by both the new `HOST_VALUE_COL`/`CRED_VALUE_COL` definitions and `render_field_row`. ✅
- Glyph consts `TRIGGER_GLYPH` (`" \u{25B8}"`) and `MULTILINE_PARA` (`" \u{00B6}"`) used identically by `affordance_suffix` and `affordance_suffix_width`. ✅
