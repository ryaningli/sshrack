//! Capability core for sshrack.
//!
//! Pure and IO capabilities for host/credential management, secret storage,
//! connection, and transfer. This crate has no UI dependencies: front-ends
//! (CLI, TUI) inject side effects via the traits defined here.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod askpass;
pub mod config;
pub mod connect;
pub mod credential;
pub mod error;
pub mod frecency;
pub mod fsutil;
pub mod host;
pub mod hostkey;
pub mod id;
pub mod pathutil;
pub mod secret;
pub mod suggest;
