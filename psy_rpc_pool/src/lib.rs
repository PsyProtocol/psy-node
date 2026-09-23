//! Transport-agnostic endpoint pool: scoring, quarantine and failover policy.
//! Adapters own the client type, request execution and outcome classification.

mod health;

pub use health::CallOutcome;
