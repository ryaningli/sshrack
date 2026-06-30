//! Crate-wide error type. Populated in a later task.
#[derive(Debug, thiserror::Error)]
pub enum SshrackError {
    #[error("placeholder")]
    Placeholder,
}
