#[derive(Debug, thiserror::Error)]
pub enum ImtLookupError {
    #[error("IMT key not found")]
    KeyNotFound,
    #[error("IMT predecessor not found")]
    PredecessorNotFound,
}
