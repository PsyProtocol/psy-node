use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("graph has cycle")]
    CycleGraph,
    #[error("{0}")]
    Message(String),
}

pub type Result<T> = std::result::Result<T, Error>;
