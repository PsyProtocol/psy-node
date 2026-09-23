//! Transport-agnostic endpoint pool: scoring, quarantine and failover policy.
//! Adapters own the client type, request execution and outcome classification.

mod health;
mod pool;
mod select;

pub use health::CallOutcome;
pub use pool::{
    PoolBuildError, PoolConfig, PoolError, ProviderPool, ProviderSnapshot, ProviderSpec, RetryPolicy,
    DEFAULT_PRIORITY_WEIGHT,
};
