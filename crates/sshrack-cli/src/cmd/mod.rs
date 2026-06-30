//! Command handlers (connect, scp, host, cred, store).
//!
//! Only the `connect` handler is wired in this task. `scp`, `host`, `cred`,
//! and `store` land in Task 20.

pub mod connect;
