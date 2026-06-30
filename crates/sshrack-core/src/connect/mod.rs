//! Connection: ssh/scp argv assembly and the zero-copy launcher.
//!
//! The launcher itself (spawn + inherited stdio + askpass env wiring) is added
//! in Task 11.

pub mod scp;
pub mod ssh;
