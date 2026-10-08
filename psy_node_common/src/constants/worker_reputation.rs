pub use psy_node_core::psy_temp_db::{INITIAL_WORKER_REPUTATION, MAX_WORKER_REPUTATION};

/// Reward for a verified proof submitted within the worker lease.
pub const REPUTATION_ON_TIME_REWARD: u64 = 1;
/// Charged to a claimant whose lease ran out without a submit, when the job is claimed again.
pub const REPUTATION_LEASE_EXPIRY_PENALTY: u64 = 1;
/// Clock skew between worker and Edge tolerated past a signed request's `valid_until`.
pub const WORKER_REQUEST_CLOCK_SKEW_MS: u64 = 120_000;
/// Cooldown after the first strike at zero; each further strike doubles it.
pub const REPUTATION_COOLDOWN_BASE_MS: u64 = 120_000;
pub const REPUTATION_COOLDOWN_MAX_MS: u64 = 3_600_000;
/// Consecutive on-time successes that clear the strikes.
pub const REPUTATION_STRIKE_RESET_STREAK: u8 = 5;
/// Compare-and-set attempts before a reputation update is abandoned.
pub const REPUTATION_CAS_ATTEMPTS: usize = 8;
