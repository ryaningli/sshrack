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
        binding(
            "Tab / Shift-Tab",
            "cycle tabs (Hosts / Credentials / Settings)",
        ),
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
        v.push(binding(
            "Ctrl-D",
            &format!("delete the selected {noun} (confirm)"),
        ));
    }
    v
}

fn sftp_lines() -> Vec<Line<'static>> {
    vec![
        section("SFTP transfer"),
        binding(
            "Tab",
            "complete highlighted (dir → next level) · else switch pane (filter mode)",
        ),
        binding("Shift-Tab", "switch pane (focus = direction)"),
        binding("Up / Down", "move selection"),
        binding("Left", "up to the parent directory"),
        binding("Right", "open the selected directory"),
        binding(
            "type a/b/c",
            "drill exact dirs · fuzzy last seg · a/ lists dir (Enter · Space · ^S · Esc)",
        ),
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
        binding("← / →", "cycle a chooser field's options"),
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
        binding("Left", "up to the parent directory"),
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
        binding("p", "pause / resume the queue"),
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
        assert!(
            hosts.contains("add a host") && hosts.contains("delete the selected host (confirm)")
        );

        let creds = joined(&HelpContext::Launcher {
            tab: Tab::Credentials,
        });
        assert!(creds.contains("edit the selected credential"));
        assert!(creds.contains("add a credential"));

        let settings = joined(&HelpContext::Launcher { tab: Tab::Settings });
        assert!(settings.contains("edit the storage-mode row"));
        // Settings has no add/edit/delete — those nouns must not leak in.
        assert!(!settings.contains("add a host"));
        assert!(!settings.contains("add a credential"));
    }

    #[test]
    fn sftp_help_documents_the_transfer_bindings() {
        let s = joined(&HelpContext::Sftp);
        assert!(s.contains("switch pane (focus = direction)"));
        assert!(
            s.contains("complete highlighted"),
            "help documents Tab completion: {s:?}"
        );
        assert!(
            s.contains("Shift-Tab"),
            "help documents Shift-Tab pane switch: {s:?}"
        );
        assert!(s.contains("transfer marked/selected (dirs recurse)"));
        assert!(s.contains("queue manager"));
        assert!(
            s.contains("drill exact dirs"),
            "sftp help must document path-aware find: {s}"
        );
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
            assert!(
                j.contains("Everywhere"),
                "{ctx:?} missing Everywhere section"
            );
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
        let j = joined(&HelpContext::Launcher { tab: Tab::Hosts });
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
