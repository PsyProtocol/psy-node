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