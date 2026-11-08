use jsonrpsee::types::ErrorObjectOwned;
use psy_data::p2p::RealmFinalizeSubmitCode;
use serde::Deserialize;

pub const GUTA_SUBMIT_RETRYABLE_CODE: i32 = -32020;
pub const GUTA_SUBMIT_ILLEGAL_CODE: i32 = -32021;
pub const GUTA_SUBMIT_INTERNAL_CODE: i32 = -32022;

/// A copy accepted at committed checkpoint c can commit at c + 1 or c + 2,
/// or never commit. The third checkpoint provides a safety margin before resubmission.
pub const GUTA_IN_FLIGHT_WINDOW_CHECKPOINTS: u64 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GutaSubmitKind {
    Retryable,
    Illegal,
    Internal,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum GutaSubmitError {
    #[error("retryable GUTA submit reason={reason} {message}")]
    Retryable {
        reason: RealmFinalizeSubmitCode,
        message: String,
        open_from_checkpoint_id: Option<u64>,
    },
    #[error("illegal GUTA submit reason={reason} {message}")]
    Illegal {
        reason: RealmFinalizeSubmitCode,
        message: String,
    },
    #[error("internal GUTA submit {message}")]
    Internal { message: String },
}

#[derive(Deserialize)]
struct GutaSubmitErrorData {
    reason: u8,
    #[serde(default)]
    open_from_checkpoint_id: Option<u64>,
}

impl GutaSubmitError {
    pub fn retryable(reason: RealmFinalizeSubmitCode, message: impl Into<String>) -> Self {
        Self::Retryable {
            reason,
            message: message.into(),
            open_from_checkpoint_id: None,
        }
    }

    pub fn retryable_in_flight(message: impl Into<String>, open_from_checkpoint_id: u64) -> Self {
        Self::Retryable {
            reason: RealmFinalizeSubmitCode::AlreadyClaimed,
            message: message.into(),
            open_from_checkpoint_id: Some(open_from_checkpoint_id),
        }
    }

    pub fn open_from_checkpoint_id(&self) -> Option<u64> {
        match self {
            Self::Retryable { reason: RealmFinalizeSubmitCode::AlreadyClaimed, open_from_checkpoint_id, .. } => *open_from_checkpoint_id,
            _ => None,
        }
    }

    pub fn illegal(reason: RealmFinalizeSubmitCode, message: impl Into<String>) -> Self {
        Self::Illegal {
            reason,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    pub fn kind(&self) -> GutaSubmitKind {
        match self {
            Self::Retryable { .. } => GutaSubmitKind::Retryable,
            Self::Illegal { .. } => GutaSubmitKind::Illegal,
            Self::Internal { .. } => GutaSubmitKind::Internal,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable { .. })
    }

    pub fn reason(&self) -> RealmFinalizeSubmitCode {
        match self {
            Self::Retryable { reason, .. } | Self::Illegal { reason, .. } => *reason,
            Self::Internal { .. } => RealmFinalizeSubmitCode::Internal,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Retryable { message, .. } | Self::Illegal { message, .. } | Self::Internal { message } => message,
        }
    }

    pub fn rpc_code(&self) -> i32 {
        match self.kind() {
            GutaSubmitKind::Retryable => GUTA_SUBMIT_RETRYABLE_CODE,
            GutaSubmitKind::Illegal => GUTA_SUBMIT_ILLEGAL_CODE,
            GutaSubmitKind::Internal => GUTA_SUBMIT_INTERNAL_CODE,
        }
    }

    pub fn from_error_object(object: &ErrorObjectOwned) -> Option<Self> {
        let data = object
            .data()
            .and_then(|raw| serde_json::from_str::<GutaSubmitErrorData>(raw.get()).ok());
        let reason = data.as_ref()
            .and_then(|data| RealmFinalizeSubmitCode::from_u8(data.reason).ok())
            .unwrap_or(RealmFinalizeSubmitCode::Internal);
        match object.code() {
            GUTA_SUBMIT_RETRYABLE_CODE => Some(Self::Retryable { reason, message: object.message().to_string(), open_from_checkpoint_id: data.and_then(|data| data.open_from_checkpoint_id) }),
            GUTA_SUBMIT_ILLEGAL_CODE => Some(Self::illegal(reason, object.message().to_string())),
            GUTA_SUBMIT_INTERNAL_CODE => Some(Self::internal(object.message().to_string())),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for GutaSubmitError {
    fn from(error: anyhow::Error) -> Self {
        match error.downcast::<GutaSubmitError>() {
            Ok(submit) => submit,
            Err(error) => Self::internal(format!("{error:#}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm::edge::error::RpcError;

    #[test]
    fn in_flight_checkpoint_round_trips_through_rpc_error() {
        let wire: ErrorObjectOwned = RpcError::GutaSubmit(GutaSubmitError::retryable_in_flight("in flight", 5)).into();
        assert_eq!(wire.code(), GUTA_SUBMIT_RETRYABLE_CODE);
        let decoded = GutaSubmitError::from_error_object(&wire).unwrap();
        assert_eq!(decoded.reason(), RealmFinalizeSubmitCode::AlreadyClaimed);
        assert_eq!(decoded.open_from_checkpoint_id(), Some(5));
        let legacy = ErrorObjectOwned::owned(GUTA_SUBMIT_RETRYABLE_CODE, "retry", Some(serde_json::json!({"reason": RealmFinalizeSubmitCode::AlreadyClaimed as u8})));
        assert_eq!(GutaSubmitError::from_error_object(&legacy).unwrap().open_from_checkpoint_id(), None);
    }
}
