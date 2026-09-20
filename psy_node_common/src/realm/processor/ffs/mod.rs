//! Historical proposal verification and baseline FFS replay.

use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_data::prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointIdentity {
    pub checkpoint_id: u64,
    pub checkpoint_leaf_hash: [u8; 32],
}

pub struct BaselineReplayRequest<Hash: Q256BitHash> {
    pub previous_checkpoint_id: u64,
    pub updates: PsyPreparedRealmBlockStateUpdates<Hash>,
    pub reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
}

pub struct VerifiedHistoryCandidate<F: QFelt64, Hash: Q256BitHash> {
    pub updates: PsyPreparedRealmBlockStateUpdates<Hash>,
    pub state_updates: Vec<u8>,
    pub coordinator_update: PsyRealmCoordinatorUpdate<F, Hash>,
}

fn history_error(kind: &str, checkpoint_id: u64, detail: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{kind} at C={checkpoint_id}: {detail}")
}

/// Why one history transition failed to verify: local material is absent or
/// stale (wait and retry), or the fetched candidate failed validation (prune
/// it and try the next candidate).
#[derive(Debug, thiserror::Error)]
pub(crate) enum RecoveryError {
    #[error("{reason}")]
    MissingLocalState {
        #[source]
        reason: anyhow::Error,
    },
    #[error("{reason}")]
    InvalidCandidate {
        proposal_id: [u8; 32],
        #[source]
        reason: anyhow::Error,
    },
}

pub(crate) fn invalid_candidate_id(error: &anyhow::Error) -> Option<[u8; 32]> {
    match error.downcast_ref::<RecoveryError>()? {
        RecoveryError::InvalidCandidate { proposal_id, .. } => Some(*proposal_id),
        RecoveryError::MissingLocalState { .. } => None,
    }
}

fn missing_local_state(checkpoint_id: u64, detail: impl std::fmt::Display) -> RecoveryError {
    RecoveryError::MissingLocalState {
        reason: history_error("MissingHistoryProof", checkpoint_id, detail),
    }
}

pub(crate) mod layout;
pub(crate) mod baseline_replay;
mod verify;
mod adopt;

use layout::{
    decode_double_id_node_ffs, double_id_leaves_at_level, gut_local_key,
    replay_double_id_nodes_from_leaves, require_imt_leaf_ffs_consistency, require_width,
    seed_tree_from_merkle_proof,
};
use baseline_replay::{
    load_previous_contract_heights, replay_state_updates_into_tree,
    require_previous_contract_height,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm::processor::proposal_backup::ProposalBackup;
    use psy_data::p2p::Proposal;

    fn build_proposal_with_body(old_root: [u8; 32], new_root: [u8; 32], salt: u8) -> (psy_data::p2p::Proposal, Vec<u8>) {
        build_proposal_with_body_at_checkpoint(old_root, new_root, salt, 99, 1)
    }

    fn build_proposal_with_body_at_checkpoint(
        old_root: [u8; 32],
        new_root: [u8; 32],
        salt: u8,
        base_checkpoint_id: u64,
        proposer_sub_id: u16,
    ) -> (psy_data::p2p::Proposal, Vec<u8>) {
        let output = vec![salt; psy_data::p2p::MAX_FINALIZER_OUTPUT_BYTES];
        let proof = vec![0xABu8; 32];
        let mut state_updates = vec![0u8; 40 + 64 + 20];
        state_updates[40..72].copy_from_slice(&old_root);
        state_updates[72..104].copy_from_slice(&new_root);
        let worker_tag = [0x11u8; 32];
        let body = psy_data::p2p::encode_proposal_body(&output, &proof, &state_updates, &worker_tag).unwrap();
        let proposal = psy_data::p2p::proposal_from_parts(
            1,
            0,
            base_checkpoint_id,
            proposer_sub_id,
            [salt; 32],
            psy_data::p2p::sha256(&output),
            psy_data::p2p::sha256(&proof),
            psy_data::p2p::sha256(&state_updates),
            psy_data::p2p::sha256(&body),
        );
        (proposal, body)
    }

    #[tokio::test]
    async fn history_ready_loads_retained_proposal() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (proposal, body) = build_proposal_with_body([1u8; 32], [2u8; 32], 1);
        proposal_backup.save_proposal(&proposal, &body).await.unwrap();
        let found = proposal_backup.lookup_transition(&[1u8; 32], &[2u8; 32]).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].proposal_id, proposal.proposal_id);
        let loaded = proposal_backup
            .load_proposal(&[1u8; 32], &[2u8; 32])
            .await
            .unwrap()
            .expect("slot holds the retained transition");
        assert_eq!(loaded.0.proposal_id, proposal.proposal_id);
        assert_eq!(loaded.1, body);
    }

    #[tokio::test]
    async fn history_ready_single_body_per_transition() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (first, first_body) = build_proposal_with_body([9u8; 32], [8u8; 32], 3);
        let (second, second_body) = build_proposal_with_body([9u8; 32], [8u8; 32], 4);
        proposal_backup.save_proposal(&first, &first_body).await.unwrap();
        proposal_backup.save_proposal(&second, &second_body).await.unwrap();
        let found = proposal_backup.lookup_transition(&[9u8; 32], &[8u8; 32]).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].proposal_id, second.proposal_id);
        let found = proposal_backup.lookup_transition(&[9u8; 32], &[8u8; 32]).await.unwrap();
        assert_eq!(found[0].proposal_id, second.proposal_id);
    }

    #[tokio::test]
    async fn history_invalid_candidate_ab() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (candidate_b, body_b) = build_proposal_with_body([10u8; 32], [11u8; 32], 40);
        let (mut candidate_x, body_x) = build_proposal_with_body([10u8; 32], [12u8; 32], 41);
        candidate_x.base_checkpoint_id = candidate_b.base_checkpoint_id;
        proposal_backup.save_proposal(&candidate_b, &body_b).await.unwrap();
        proposal_backup.save_proposal(&candidate_x, &body_x).await.unwrap();
        let found = proposal_backup.lookup_transition(&[10u8; 32], &[12u8; 32]).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].proposal_id, candidate_x.proposal_id);
        let sibling = proposal_backup.lookup_transition(&[10u8; 32], &[11u8; 32]).await.unwrap();
        assert_eq!(sibling[0].proposal_id, candidate_b.proposal_id);
        let absent = proposal_backup.lookup_transition(&[11u8; 32], &[10u8; 32]).await.unwrap();
        assert!(absent.is_empty());
        assert!(dir
            .path()
            .join("bodies")
            .join(format!("{}_{}", hex::encode([10u8; 32]), hex::encode([11u8; 32])))
            .exists());
    }
}
