use jsonrpsee::types::ErrorObjectOwned;
use psy_data::p2p::RealmFinalizeSubmitCode;
use serde::Deserialize;

pub const GUTA_SUBMIT_RETRYABLE_CODE: i32 = -32020;
pub const GUTA_SUBMIT_ILLEGAL_CODE: i32 = -32021;
pub const GUTA_SUBMIT_INTERNAL_CODE: i32 = -32022;

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
}

impl GutaSubmitError {
    pub fn retryable(reason: RealmFinalizeSubmitCode, message: impl Into<String>) -> Self {
        Self::Retryable {
            reason,
            message: message.into(),
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
        let reason = object
            .data()
            .and_then(|raw| serde_json::from_str::<GutaSubmitErrorData>(raw.get()).ok())
            .and_then(|data| RealmFinalizeSubmitCode::from_u8(data.reason).ok())
            .unwrap_or(RealmFinalizeSubmitCode::Internal);
        match object.code() {
            GUTA_SUBMIT_RETRYABLE_CODE => Some(Self::retryable(reason, object.message().to_string())),
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
