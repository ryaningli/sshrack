//! Shared test helpers for the TUI test modules (`app`, `persist`, `run_loop`).
//!
//! Pulled out of `app.rs`'s test blocks so each file split off by the
//! app.rs-decomposition plan can migrate its tests without re-deriving these
//! constructors. Compiled only under `--test` via the `#[cfg(test)]` mod
//! declaration in [`crate::tui`].

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use sshrack_core::config::schema::{Auth, Credential, CredentialBody, Host, SshrackConfig};
use sshrack_core::frecency::Frecency;
use ulid::Ulid;

use crate::tui::app::{App, TerminalHandle};
// `TerminalHandle` still lives in app.rs at this point in the plan. Task 2
// (term extraction) will rewrite this path to `crate::tui::term::TerminalHandle`.

/// A one-host `App` with no frecency and no named credentials. Enough to drive
/// the launcher's quit/navigation branches without a config file.
pub(crate) fn app_with_host(name: &str) -> App {
    let host = Host {
        id: Ulid::new(),
        name: name.into(),
        host: "h".into(),
        port: 22,
        auth: Auth::inline(CredentialBody::new("u")),
    };
    let cfg = SshrackConfig {
        hosts: vec![host],
        ..SshrackConfig::default()
    };
    App::new(cfg, None, Frecency::default(), HashMap::new())
}

/// A one-credential `App`. Enough to exercise the Credentials panel without a
/// config file.
pub(crate) fn app_with_credential(name: &str, user: &str) -> App {
    let cred = Credential {
        id: Ulid::new(),
        name: name.into(),
        body: CredentialBody::new(user),
    };
    let cfg = SshrackConfig {
        credentials: vec![cred],
        ..SshrackConfig::default()
    };
    App::new(cfg, None, Frecency::default(), HashMap::new())
}

/// An `App` seeded with one named credential (user hardcoded to `"deploy"`).
/// Used by entry-routing tests that target the Credentials tab.
pub(crate) fn app_with_named_cred(name: &str) -> App {
    let cfg = SshrackConfig {
        credentials: vec![Credential {
            id: Ulid::new(),
            name: name.into(),
            body: CredentialBody::new("deploy"),
        }],
        ..SshrackConfig::default()
    };
    App::new(cfg, None, Frecency::default(), HashMap::new())
}

/// A `KeyEvent` Press of `code` + `mods` — the shape crossterm 0.28 emits that
/// the TUI actually reacts to. crossterm distinguishes Press/Release/Repeat;
/// `on_key` only acts on Press, so tests construct Press keys to exercise the
/// binding.
pub(crate) fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
    KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
}

/// A dead weak terminal handle — `Weak::upgrade` returns `None`. Used by tests
/// that exercise a save/delete path through a `TerminalHandle` without a live
/// terminal (the popup path then treats it as a silent cancel).
pub(crate) fn dead_handle() -> TerminalHandle {
    std::rc::Weak::new()
}
