//! Command handlers (connect, host, cred).
//!
//! `connect` runs the ssh/connect path. `host` and `cred` are the resource
//! groups (CRUD). `scp` and `store` are stubbed inline in `main.rs` until
//! Part C wires them; they do not yet warrant their own modules.

pub mod connect;
pub mod cred;
pub mod host;
pub mod shared;
