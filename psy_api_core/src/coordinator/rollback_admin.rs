//! Stable JSON-RPC envelopes for the Coordinator rollback inbox handoff.
//!
//! `ACCEPTED` means that the command was durably queued.  It does not mean
//! preflight passed, the canonical control changed, or rollback execution
//! started.

use psy_data::protocol::canonical_chain::CanonicalChainRef;
use serde::{Deserialize, Serialize};

pub const ROLLBACK_ADMIN_START_REQUEST_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RollbackAdminExecutionMode {
    InPlace,
    SnapshotReplay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackAdminStartRequest<Hash> {
    pub request_version: u16,
    pub expected_revision: u64,
    pub expected_canonical_ref: CanonicalChainRef<Hash>,
    pub target_checkpoint_id: u64,
    pub target_checkpoint_hash: Hash,
    pub orphan_write_max_timestamp_us: i64,
    pub delete_fence_timestamp_us: i64,
    pub new_branch_write_timestamp_us: i64,
    pub execution_mode: RollbackAdminExecutionMode,
    /// Lower-case or upper-case, optional `0x` prefix; exactly 32 bytes.
    pub plan_digest_hex: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RollbackAdminPhase {
    Idle,
    Pending,
    Active,
    Stale,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RollbackAdminStartDisposition {
    Accepted,
    Idempotent,
    RollbackAdminDisabled,
    RollbackAlreadyInProgress,
    HeadMismatch,
    RollbackAdmissionConflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackAdminRequestSummary<Hash> {
    pub requested_checkpoint_id: u64,
    pub requested_checkpoint_hash: Hash,
    pub target_checkpoint_id: u64,
    pub target_checkpoint_hash: Hash,
    pub execution_mode: RollbackAdminExecutionMode,
    pub plan_digest_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackAdminStatus<Hash> {
    pub admin_rpc_enabled: bool,
    pub phase: RollbackAdminPhase,
    pub canonical_revision: u64,
    pub canonical_ref: CanonicalChainRef<Hash>,
    pub inbox_revision: u64,
    pub request: Option<RollbackAdminRequestSummary<Hash>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackAdminStartResponse<Hash> {
    pub disposition: RollbackAdminStartDisposition,
    pub status: RollbackAdminStatus<Hash>,
}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
        NetworkId,
    };

    use super::*;

    fn request() -> RollbackAdminStartRequest<PHash> {
        let network = NetworkId::try_from_chain_id(0x6979_7350).unwrap();
        RollbackAdminStartRequest {
            request_version: ROLLBACK_ADMIN_START_REQUEST_VERSION,
            expected_revision: 7,
            expected_canonical_ref: CanonicalChainRef::new(
                network,
                ChainEpoch::new(2),
                CheckpointRef::new(
                    CheckpointId::new(100),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4)),
                ),
            ),
            target_checkpoint_id: 90,
            target_checkpoint_hash: PHash::from_values(5, 6, 7, 8),
            orphan_write_max_timestamp_us: 1_000,
            delete_fence_timestamp_us: 1_001,
            new_branch_write_timestamp_us: 1_002,
            execution_mode: RollbackAdminExecutionMode::InPlace,
            plan_digest_hex: "a5".repeat(32),
        }
    }

    #[test]
    fn start_request_json_is_named_versioned_and_round_trips() {
        let request = request();
        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(encoded["request_version"], 1);
        assert_eq!(encoded["execution_mode"], "IN_PLACE");
        assert_eq!(encoded["expected_canonical_ref"]["checkpoint_id"], 100);
        assert_eq!(
            serde_json::from_value::<RollbackAdminStartRequest<PHash>>(encoded).unwrap(),
            request
        );
    }

    #[test]
    fn unknown_request_fields_fail_closed() {
        let mut encoded = serde_json::to_value(request()).unwrap();
        encoded["unexpected"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<RollbackAdminStartRequest<PHash>>(encoded).is_err()
        );
    }

    #[test]
    fn stable_wire_codes_are_explicit() {
        assert_eq!(
            serde_json::to_string(&RollbackAdminStartDisposition::RollbackAlreadyInProgress)
                .unwrap(),
            "\"ROLLBACK_ALREADY_IN_PROGRESS\""
        );
        assert_eq!(
            serde_json::to_string(&RollbackAdminPhase::Stale).unwrap(),
            "\"STALE\""
        );
    }
}
