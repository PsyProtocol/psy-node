
// if a realm proof is older than 600_000 checkpoints from the latest finalized checkpoint, it is considered stale
pub const STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF: u64 = 600_000;

// if a user proof is older than 
pub const STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF: u64 = 2_880_000;