use jsonrpsee::{
    core::RpcResult as JsonRpcResult,
    types::{
        error::{
            INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE, METHOD_NOT_FOUND_CODE,
            UNKNOWN_ERROR_CODE,
        },
        ErrorObject, ErrorObjectOwned,
    },
};
use tracing::error;

pub const ROLLBACK_IN_PROGRESS_ERROR_CODE: i32 = -32010;

// Define error enum
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("ROLLBACK_IN_PROGRESS:{0}")]
    RollbackInProgress(String),
    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    // ... more
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::InvalidInput(msg) => ErrorObject::owned(INVALID_PARAMS_CODE, msg, None::<()>),
            RpcError::NotFound(msg) => ErrorObject::owned(METHOD_NOT_FOUND_CODE, msg, None::<()>),
            RpcError::PermissionDenied => {
                ErrorObject::owned(INVALID_REQUEST_CODE, "Permission denied", None::<()>)
            }
            RpcError::Internal(msg) => ErrorObject::owned(INTERNAL_ERROR_CODE, msg, None::<()>),
            RpcError::RollbackInProgress(phase) => ErrorObject::owned(
                ROLLBACK_IN_PROGRESS_ERROR_CODE,
                "ROLLBACK_IN_PROGRESS",
                Some(phase),
            ),
            RpcError::Anyhow(msg) => {
                ErrorObject::owned(UNKNOWN_ERROR_CODE, msg.to_string(), None::<()>)
            }
        }
    }
}

fn to_rpc_error<T>(err: RpcError) -> JsonRpcResult<T> {
    error!("{}", err);
    Err(err.into())
}

impl<T> From<RpcError> for JsonRpcResult<T> {
    fn from(err: RpcError) -> Self {
        to_rpc_error(err)
    }
}

pub type Result<T, E = RpcError> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_in_progress_has_stable_server_code_and_phase_data() {
        let error: ErrorObjectOwned =
            RpcError::RollbackInProgress("PENDING".to_owned()).into();
        assert_eq!(error.code(), ROLLBACK_IN_PROGRESS_ERROR_CODE);
        assert_eq!(error.message(), "ROLLBACK_IN_PROGRESS");
        assert_eq!(error.data().unwrap().get(), "\"PENDING\"");
    }
}
