//! Typed input boundary for Realm state commits.
//!
//! A normal block owns an exact prepared update, GUTA submission, proof and
//! Coordinator inclusion response.  Genesis and startup recovery do not have
//! that live proof evidence and must use explicit, ineligible origins instead
//! of smuggling an empty proof through the normal path.

use std::{error::Error, fmt};

use parth_core::{
    QCoreProcCheckpointUniqueId,
    felt::QFelt64,
    protocol::core_types::Q256BitHash,
};
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
    prepared_block::realm::{
        PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RealmCommitOriginKind {
    LiveProof,
    Genesis,
    StartupRecovery,
}

#[derive(Clone, Copy, Debug)]
struct RealmLiveProofInput<'a, F, Hash> {
    submission: &'a GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash>,
    proof_bytes: &'a [u8],
}

/// Exact live evidence view required by the future durable PREPARED assembler.
/// Recovery and genesis requests cannot produce this value.
#[derive(Clone, Copy, Debug)]
pub(super) struct RealmLiveCommitEvidenceInputs<'a, F, Hash> {
    prepared: &'a PsyPreparedRealmBlockStateUpdates<Hash>,
    submission: &'a GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash>,
    proof_bytes: &'a [u8],
    coordinator: &'a PsyRealmCoordinatorUpdate<F, Hash>,
}

impl<'a, F, Hash> RealmLiveCommitEvidenceInputs<'a, F, Hash> {
    pub(super) const fn prepared(
        &self,
    ) -> &'a PsyPreparedRealmBlockStateUpdates<Hash> {
        self.prepared
    }

    pub(super) const fn submission(
        &self,
    ) -> &'a GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash> {
        self.submission
    }

    pub(super) const fn proof_bytes(&self) -> &'a [u8] {
        self.proof_bytes
    }

    pub(super) const fn coordinator(
        &self,
    ) -> &'a PsyRealmCoordinatorUpdate<F, Hash> {
        self.coordinator
    }
}

#[derive(Clone, Copy, Debug)]
enum RealmCommitOrigin<'a, F, Hash> {
    LiveProof(RealmLiveProofInput<'a, F, Hash>),
    Genesis,
    StartupRecovery,
}

/// One indivisible request passed from the Realm block/recovery flow to the
/// persistence boundary.  The fields are private so normal work cannot omit
/// its submission or proof and recovery cannot be mistaken for live evidence.
#[derive(Clone, Copy, Debug)]
pub(super) struct RealmCommitInput<'a, F, Hash> {
    coordinator: &'a PsyRealmCoordinatorUpdate<F, Hash>,
    prepared: &'a PsyPreparedRealmBlockStateUpdates<Hash>,
    origin: RealmCommitOrigin<'a, F, Hash>,
}

impl<'a, F: QFelt64, Hash: Q256BitHash> RealmCommitInput<'a, F, Hash> {
    pub(super) fn try_live_proof(
        coordinator: &'a PsyRealmCoordinatorUpdate<F, Hash>,
        prepared: &'a PsyPreparedRealmBlockStateUpdates<Hash>,
        submission: &'a GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash>,
        proof_bytes: &'a [u8],
    ) -> Result<Self, RealmCommitInputError> {
        validate_common(coordinator, prepared)?;
        if proof_bytes.is_empty() {
            return Err(RealmCommitInputError::EmptyLiveProof);
        }
        if prepared.old_realm_root == prepared.new_realm_root {
            return Err(RealmCommitInputError::ChangedRealmStateRequired);
        }
        let transition = submission.header.header.state_transition;
        if transition.node_index.to_u64_value() != prepared.realm_id {
            return Err(RealmCommitInputError::SubmissionRealmIndexMismatch);
        }
        if transition.old_node_value != prepared.old_realm_root {
            return Err(RealmCommitInputError::SubmissionOldRootMismatch);
        }
        if transition.new_node_value != prepared.new_realm_root {
            return Err(RealmCommitInputError::SubmissionNewRootMismatch);
        }
        Ok(Self {
            coordinator,
            prepared,
            origin: RealmCommitOrigin::LiveProof(RealmLiveProofInput {
                submission,
                proof_bytes,
            }),
        })
    }

    pub(super) fn try_genesis(
        coordinator: &'a PsyRealmCoordinatorUpdate<F, Hash>,
        prepared: &'a PsyPreparedRealmBlockStateUpdates<Hash>,
    ) -> Result<Self, RealmCommitInputError> {
        validate_common(coordinator, prepared)?;
        if coordinator.checkpoint_sync_info.checkpoint_id != 0 {
            return Err(RealmCommitInputError::GenesisCheckpointRequired);
        }
        Ok(Self {
            coordinator,
            prepared,
            origin: RealmCommitOrigin::Genesis,
        })
    }

    pub(super) fn try_startup_recovery(
        coordinator: &'a PsyRealmCoordinatorUpdate<F, Hash>,
        prepared: &'a PsyPreparedRealmBlockStateUpdates<Hash>,
    ) -> Result<Self, RealmCommitInputError> {
        validate_common(coordinator, prepared)?;
        Ok(Self {
            coordinator,
            prepared,
            origin: RealmCommitOrigin::StartupRecovery,
        })
    }

    pub(super) const fn coordinator(
        &self,
    ) -> &'a PsyRealmCoordinatorUpdate<F, Hash> {
        self.coordinator
    }

    pub(super) const fn prepared(
        &self,
    ) -> &'a PsyPreparedRealmBlockStateUpdates<Hash> {
        self.prepared
    }

    pub(super) const fn origin_kind(&self) -> RealmCommitOriginKind {
        match self.origin {
            RealmCommitOrigin::LiveProof(_) => RealmCommitOriginKind::LiveProof,
            RealmCommitOrigin::Genesis => RealmCommitOriginKind::Genesis,
            RealmCommitOrigin::StartupRecovery => {
                RealmCommitOriginKind::StartupRecovery
            }
        }
    }

    pub(super) const fn checkpoint_tree_was_pre_synced(&self) -> bool {
        matches!(self.origin, RealmCommitOrigin::StartupRecovery)
    }

    pub(super) fn require_live_evidence(
        &self,
    ) -> Result<RealmLiveCommitEvidenceInputs<'a, F, Hash>, RealmCommitInputError>
    {
        match self.origin {
            RealmCommitOrigin::LiveProof(live) => {
                Ok(RealmLiveCommitEvidenceInputs {
                    prepared: self.prepared,
                    submission: live.submission,
                    proof_bytes: live.proof_bytes,
                    coordinator: self.coordinator,
                })
            }
            RealmCommitOrigin::Genesis | RealmCommitOrigin::StartupRecovery => {
                Err(RealmCommitInputError::LiveEvidenceUnavailable {
                    origin: self.origin_kind(),
                })
            }
        }
    }

    /// Bind a live request to the Processor state that is about to be written.
    /// Genesis/recovery remain explicitly outside the durable live-proof path.
    pub(super) fn validate_processing_context(
        &self,
        realm_id: u64,
        realm_sub_id: u64,
        unique_pending_id: u64,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
        last_committed_realm_root: Hash,
    ) -> Result<(), RealmCommitInputError> {
        if self.origin_kind() != RealmCommitOriginKind::LiveProof {
            return Ok(());
        }
        if self.prepared.realm_id != realm_id
            || self.prepared.realm_sub_id != realm_sub_id
        {
            return Err(RealmCommitInputError::ProcessingAuthorityMismatch);
        }
        if self.prepared.unique_pending_id != unique_pending_id
            || self.prepared.proc_checkpoint_unique_id
                != proc_checkpoint_unique_id
        {
            return Err(RealmCommitInputError::ProcessingPendingContextMismatch);
        }
        if self.prepared.old_realm_root != last_committed_realm_root {
            return Err(RealmCommitInputError::ProcessingPredecessorRootMismatch);
        }
        Ok(())
    }
}

fn validate_common<F, Hash: Q256BitHash>(
    coordinator: &PsyRealmCoordinatorUpdate<F, Hash>,
    prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
) -> Result<(), RealmCommitInputError> {
    let sync_checkpoint = coordinator.checkpoint_sync_info.checkpoint_id;
    if coordinator
        .canonical_chain_ref
        .checkpoint()
        .checkpoint_id()
        .get()
        != sync_checkpoint
    {
        return Err(RealmCommitInputError::CanonicalCheckpointMismatch);
    }
    if coordinator.merkle_proof_to_realm_root.value != prepared.new_realm_root {
        return Err(RealmCommitInputError::CoordinatorRealmRootMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmCommitInputError {
    CanonicalCheckpointMismatch,
    CoordinatorRealmRootMismatch,
    EmptyLiveProof,
    ChangedRealmStateRequired,
    SubmissionRealmIndexMismatch,
    SubmissionOldRootMismatch,
    SubmissionNewRootMismatch,
    GenesisCheckpointRequired,
    LiveEvidenceUnavailable { origin: RealmCommitOriginKind },
    ProcessingAuthorityMismatch,
    ProcessingPendingContextMismatch,
    ProcessingPredecessorRootMismatch,
}

impl fmt::Display for RealmCommitInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmCommitInputError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        PHash, PF,
        crypto::hash::{
            merkle_proof::MerkleProofCore,
        },
        felt::FromPrimitiveValuesFelt,
        protocol::core_types::Q256BitHash,
    };
    use psy_core::job::job_id::ProvingJobCircuitType;
    use psy_data::{
        guta::{
            header::GlobalUserTreeAggregatorHeader,
            header_extended::{
                GlobalUserTreeAggregatorHeaderWithTagValue,
                GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
            },
            stats::GUTAStats,
            sub_tree_transition::SubTreeNodeStateTransition,
        },
        prepared_block::realm::{
            PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate,
        },
        protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        v1::qdata::{
            checkpoint::{
                PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf,
                PQEDCheckpointLeafStats, QEDL2BlockState,
            },
            checkpoint_sync::PQEDCheckpointSyncInfoCompact,
        },
    };

    use super::{
        RealmCommitInput, RealmCommitInputError, RealmCommitOriginKind,
    };

    const REALM_ID: u64 = 3;
    const REALM_SUB_ID: u64 = 2;
    const PENDING_ID: u64 = 11;
    const PROC_ID: u128 = 17;

    struct Fixture {
        prepared: PsyPreparedRealmBlockStateUpdates<PHash>,
        submission:
            GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<PF, PHash>,
        coordinator: PsyRealmCoordinatorUpdate<PF, PHash>,
        proof: Vec<u8>,
    }

    fn hash(seed: u8) -> PHash {
        PHash::from_owned_32bytes([seed; 32])
    }

    fn fixture(checkpoint_id: u64, changed: bool) -> Fixture {
        let old_root = hash(1);
        let new_root = if changed { hash(2) } else { old_root };
        let prepared = PsyPreparedRealmBlockStateUpdates {
            realm_id: REALM_ID,
            realm_sub_id: REALM_SUB_ID,
            unique_pending_id: PENDING_ID,
            proc_checkpoint_unique_id: PROC_ID,
            old_realm_root: old_root,
            new_realm_root: new_root,
            update_global_user_tree_nodes_ffs: vec![3],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            update_contract_state_imt_leaves_ffs: vec![],
        };
        let submission =
            GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
                header: GlobalUserTreeAggregatorHeaderWithTagValue {
                    header: GlobalUserTreeAggregatorHeader {
                        guta_circuit_whitelist: hash(4),
                        checkpoint_tree_root: hash(5),
                        state_transition: SubTreeNodeStateTransition {
                            old_node_value: old_root,
                            new_node_value: new_root,
                            node_index: PF::from_u64_value(REALM_ID),
                            node_level: PF::from_u64_value(4),
                        },
                        stats: GUTAStats::get_zero_value(),
                        total_aggregation_proofs_generated:
                            PF::from_u64_value(1),
                    },
                    new_tag_tree_node_value: hash(6),
                },
                job_type_u32: ProvingJobCircuitType::GUTASingleEndCap as u32,
            };
        let state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: hash(7),
            deposit_tree_root: hash(8),
            user_tree_root: hash(9),
            withdrawal_tree_root: hash(10),
            user_registration_tree_root: hash(11),
        };
        let checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root: hash(12),
            stats: PQEDCheckpointLeafStats::<PF, PHash>::get_empty_stats(),
        };
        let mut block_state = QEDL2BlockState::get_genesis_value();
        block_state.checkpoint_id = checkpoint_id;
        let coordinator = PsyRealmCoordinatorUpdate {
            canonical_chain_ref: CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(7),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint_id),
                    CheckpointHash::from_proof_public_inputs_hash(hash(13)),
                ),
            ),
            checkpoint_sync_info: PQEDCheckpointSyncInfoCompact {
                checkpoint_id,
                coordinator_id: 0,
                coordinator_sub_id: 0,
                coordinator_unique_pending_id: 80,
                block_state,
                state_roots,
                checkpoint_leaf,
                checkpoint_leaf_hash: hash(14),
                checkpoint_tree_root: hash(15),
            },
            merkle_proof_to_realm_root: MerkleProofCore {
                root: hash(9),
                value: new_root,
                index: REALM_ID,
                siblings: vec![],
            },
            reward_tree_top_proof:
                parth_core::crypto::hash::tag_tree::TagTreeMerkleProof::new_empty(),
        };
        Fixture {
            prepared,
            submission,
            coordinator,
            proof: vec![16; 32],
        }
    }

    #[test]
    fn live_request_retains_all_exact_inputs_and_binds_processing_context() {
        let fixture = fixture(42, true);
        let input = RealmCommitInput::try_live_proof(
            &fixture.coordinator,
            &fixture.prepared,
            &fixture.submission,
            &fixture.proof,
        )
        .unwrap();

        assert_eq!(input.origin_kind(), RealmCommitOriginKind::LiveProof);
        assert!(!input.checkpoint_tree_was_pre_synced());
        let evidence = input.require_live_evidence().unwrap();
        assert!(std::ptr::eq(evidence.prepared(), &fixture.prepared));
        assert!(std::ptr::eq(evidence.submission(), &fixture.submission));
        assert_eq!(evidence.proof_bytes(), fixture.proof.as_slice());
        assert!(std::ptr::eq(evidence.coordinator(), &fixture.coordinator));
        input
            .validate_processing_context(
                REALM_ID,
                REALM_SUB_ID,
                PENDING_ID,
                PROC_ID,
                fixture.prepared.old_realm_root,
            )
            .unwrap();
    }

    #[test]
    fn live_request_rejects_missing_or_substituted_exact_inputs() {
        let fixture = fixture(42, true);
        assert_eq!(
            RealmCommitInput::try_live_proof(
                &fixture.coordinator,
                &fixture.prepared,
                &fixture.submission,
                &[],
            )
            .unwrap_err(),
            RealmCommitInputError::EmptyLiveProof
        );

        let mut wrong_submission = fixture.submission;
        wrong_submission.header.header.state_transition.new_node_value = hash(99);
        assert_eq!(
            RealmCommitInput::try_live_proof(
                &fixture.coordinator,
                &fixture.prepared,
                &wrong_submission,
                &fixture.proof,
            )
            .unwrap_err(),
            RealmCommitInputError::SubmissionNewRootMismatch
        );

        let mut wrong_coordinator = fixture.coordinator.clone();
        wrong_coordinator.merkle_proof_to_realm_root.value = hash(98);
        assert_eq!(
            RealmCommitInput::try_live_proof(
                &wrong_coordinator,
                &fixture.prepared,
                &fixture.submission,
                &fixture.proof,
            )
            .unwrap_err(),
            RealmCommitInputError::CoordinatorRealmRootMismatch
        );
    }

    #[test]
    fn live_request_rejects_wrong_processor_authority_pending_or_predecessor() {
        let fixture = fixture(42, true);
        let input = RealmCommitInput::try_live_proof(
            &fixture.coordinator,
            &fixture.prepared,
            &fixture.submission,
            &fixture.proof,
        )
        .unwrap();

        assert_eq!(
            input
                .validate_processing_context(
                    REALM_ID + 1,
                    REALM_SUB_ID,
                    PENDING_ID,
                    PROC_ID,
                    fixture.prepared.old_realm_root,
                )
                .unwrap_err(),
            RealmCommitInputError::ProcessingAuthorityMismatch
        );
        assert_eq!(
            input
                .validate_processing_context(
                    REALM_ID,
                    REALM_SUB_ID,
                    PENDING_ID + 1,
                    PROC_ID,
                    fixture.prepared.old_realm_root,
                )
                .unwrap_err(),
            RealmCommitInputError::ProcessingPendingContextMismatch
        );
        assert_eq!(
            input
                .validate_processing_context(
                    REALM_ID,
                    REALM_SUB_ID,
                    PENDING_ID,
                    PROC_ID,
                    hash(97),
                )
                .unwrap_err(),
            RealmCommitInputError::ProcessingPredecessorRootMismatch
        );
    }

    #[test]
    fn genesis_and_recovery_cannot_mint_live_evidence() {
        let genesis_fixture = fixture(0, false);
        let genesis = RealmCommitInput::try_genesis(
            &genesis_fixture.coordinator,
            &genesis_fixture.prepared,
        )
        .unwrap();
        assert_eq!(genesis.origin_kind(), RealmCommitOriginKind::Genesis);
        assert!(!genesis.checkpoint_tree_was_pre_synced());
        assert_eq!(
            genesis.require_live_evidence().unwrap_err(),
            RealmCommitInputError::LiveEvidenceUnavailable {
                origin: RealmCommitOriginKind::Genesis,
            }
        );

        let recovery_fixture = fixture(42, true);
        let recovery = RealmCommitInput::try_startup_recovery(
            &recovery_fixture.coordinator,
            &recovery_fixture.prepared,
        )
        .unwrap();
        assert_eq!(
            recovery.origin_kind(),
            RealmCommitOriginKind::StartupRecovery
        );
        assert!(recovery.checkpoint_tree_was_pre_synced());
        assert_eq!(
            recovery.require_live_evidence().unwrap_err(),
            RealmCommitInputError::LiveEvidenceUnavailable {
                origin: RealmCommitOriginKind::StartupRecovery,
            }
        );
    }

    #[test]
    fn nonzero_checkpoint_cannot_enter_genesis_path() {
        let fixture = fixture(1, false);
        assert_eq!(
            RealmCommitInput::try_genesis(
                &fixture.coordinator,
                &fixture.prepared,
            )
            .unwrap_err(),
            RealmCommitInputError::GenesisCheckpointRequired
        );
    }

    #[test]
    fn production_callsites_keep_typed_origins_and_do_not_restore_dummy_proof_args() {
        let process_block = include_str!("core/process_block.rs");
        assert!(process_block.contains("RealmCommitInput::try_live_proof("));
        assert!(process_block.contains("&submission_header,"));
        assert!(process_block.contains("&root_job_proof,"));

        let commit = include_str!("db/commit.rs");
        assert!(commit.contains("commit_input.require_live_evidence()?"));
        assert!(!commit.contains("_zk_proof"));
        assert!(!commit.contains("_state_transition_circuit_type"));
        assert!(!commit.contains("skip_checkpoint_root_check: bool"));

        let init = include_str!("db/init.rs");
        assert_eq!(init.matches("RealmCommitInput::try_genesis(").count(), 2);
        assert_eq!(
            init.matches("RealmCommitInput::try_startup_recovery(")
                .count(),
            2
        );
        assert!(!init.contains("ProvingJobCircuitType::GUTANoChange"));
    }
}
