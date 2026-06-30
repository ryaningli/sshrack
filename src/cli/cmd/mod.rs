//! Command handlers (connect, scp, host, cred, store).
//!
//! `connect` runs the ssh/connect path. `scp` runs the file-transfer path.
//! `host` and `cred` are the resource groups (CRUD). `store` manages the
//! password storage mode.

pub mod connect;
pub mod cred;
pub mod host;
pub mod scp;
pub mod shared;
pub mod store;
