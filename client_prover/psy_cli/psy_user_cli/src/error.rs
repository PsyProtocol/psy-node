use anyhow::Error as AnyhowError;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Anyhow Error: `{0:?}`")]
    AnyhowError(#[from] AnyhowError),
}
