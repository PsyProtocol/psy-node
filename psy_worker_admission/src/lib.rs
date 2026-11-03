//! Worker PoW admission. This first rollout exposes an explicitly observe-only
//! protocol; it does not claim to enforce task leases or replace legacy scores.
pub mod lease;
pub mod protocol;
pub mod redis_store;
pub mod rpc;
pub mod service;
pub mod store;

pub use protocol::*;
pub use lease::LeaseService;
pub use service::AdmissionService;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    #[error("INVALID_REQUEST")]
    InvalidRequest,
    #[error("INVALID_SIGNATURE")]
    InvalidSignature,
    #[error("REQUEST_EXPIRED")]
    RequestExpired,
    #[error("ADMISSION_STALE")]
    AdmissionStale,
    #[error("POW_REQUIRED")]
    PowRequired,
    #[error("ALREADY_ACTIVE")]
    AlreadyActive,
    #[error("POW_COOLDOWN")]
    Cooldown { retry_after_ms: u64 },
    #[error("CHALLENGE_STALE")]
    ChallengeStale,
    #[error("CHALLENGE_EXPIRED")]
    ChallengeExpired,
    #[error("INVALID_POW")]
    InvalidPow,
    #[error("RATE_LIMITED")]
    RateLimited { retry_after_ms: u64 },
    #[error("REQUEST_CONFLICT")]
    RequestConflict,
    #[error("ADMISSION_STORE_UNAVAILABLE")]
    StoreUnavailable,
    #[error("ADMISSION_STATE_CORRUPT")]
    StateCorrupt,
    #[error("ADMISSION_CONFIG_MISMATCH")]
    ConfigMismatch,
    #[error("ADMISSION_CAPACITY")]
    Capacity,
    #[error("UNSUPPORTED_PROTOCOL")]
    UnsupportedProtocol,
    /// The lease is gone, reassigned, expired or owned by someone else. Never
    /// a reason to punish the submitter.
    #[error("LEASE_STALE")]
    LeaseStale,
    /// The job is held by a live lease, or a different submission is being verified.
    #[error("LEASE_BUSY")]
    LeaseBusy,
    #[error("INFLIGHT_LIMIT")]
    InflightLimit,
    #[error("JOB_ALREADY_ACCEPTED")]
    JobAlreadyAccepted,
}

pub type Result<T> = std::result::Result<T, AdmissionError>;
