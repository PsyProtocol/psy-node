use jsonrpsee::{
    core::RpcResult as JsonRpcResult,
    types::{
        error::{
            INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE, METHOD_NOT_FOUND_CODE,
            SERVER_IS_BUSY_CODE, UNKNOWN_ERROR_CODE,
        },
        ErrorObject, ErrorObjectOwned,
    },
};
use tracing::error;

use crate::p2p::guta_submit::GutaSubmitError;

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
    #[error(transparent)]
    GutaSubmit(#[from] GutaSubmitError),
    #[error(transparent)]
    EndCapSubmit(#[from] EndCapSubmitError),
    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

/// Typed realm-edge end-cap submission failures. Constructed only at the
/// validation sites so both the RPC surface and the P2P rejection reply can
/// be derived from one classification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EndCapSubmitError {
    #[error("end cap for user_id {user_id} at unique_pending_id {unique_pending_id} has already been submitted")]
    AlreadySubmitted { user_id: u64, unique_pending_id: u64 },
    #[error("invalid end cap submission: {0}")]
    Invalid(String),
    #[error("end cap submitter is busy: {0}")]
    Busy(String),
}

impl EndCapSubmitError {
    /// Classify an arbitrary submission error chain into the wire reason set.
    pub fn from_error_chain(error: &anyhow::Error) -> Option<Self> {
        error.chain().find_map(|cause| cause.downcast_ref::<Self>()).cloned()
    }
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
            RpcError::GutaSubmit(submit) => ErrorObject::owned(
                submit.rpc_code(),
                submit.message().to_string(),
                Some(serde_json::json!({ "reason": submit.reason() as u8 })),
            ),
            RpcError::EndCapSubmit(EndCapSubmitError::AlreadySubmitted { .. }) => {
                // The relayer's duplicate-recovery parser matches on
                // ServerError(-32001), the canonical message, and no data.
                ErrorObject::owned(UNKNOWN_ERROR_CODE, err.to_string(), None::<()>)
            }
            RpcError::EndCapSubmit(EndCapSubmitError::Invalid(msg)) => {
                ErrorObject::owned(INTERNAL_ERROR_CODE, msg, None::<()>)
            }
            RpcError::EndCapSubmit(EndCapSubmitError::Busy(msg)) => {
                ErrorObject::owned(SERVER_IS_BUSY_CODE, msg, None::<()>)
            }
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
