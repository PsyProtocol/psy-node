use std::sync::Arc;

use tokio::task;
use parth_core::{
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath, crypto::hash::{merkle_proof::MerkleProofCore, tag_tree::TagTreeMerkleProof, traits::QFieldHashable}, data::{hash::merkle_node_key::SimpleMerkleNodeKey, queue::queue_key::QPBaseQueueType}, felt::ToU64Value, node::realm_identifier::QRealmIdentifier, protocol::core_types::{Q256BitHash, QNetworkTypesConfig, QZKProofVerifier}
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_crypto::hash::tx_hash::{compute_deploy_contract_content_hash, hash_to_hex};
use psy_api_core::{
    CheckpointJobStats,
    coordinator::rollback_admin::{
        ROLLBACK_ADMIN_ABORT_REQUEST_VERSION, ROLLBACK_ADMIN_START_REQUEST_VERSION,
        RollbackAdminAbortDisposition, RollbackAdminAbortRequest,
        RollbackAdminAbortResponse, RollbackAdminExecutionMode, RollbackAdminPhase,
        RollbackAdminRequestSummary, RollbackAdminStartDisposition,
        RollbackAdminStartRequest, RollbackAdminStartResponse, RollbackAdminStatus,
    },
};
use psy_data::{
    guta::header_extended::{GlobalUserTreeAggregatorHeaderWithTagValueAndJobID, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType}, prepared_block::realm::PsyRealmCoordinatorUpdate,
    protocol::canonical_chain::{
        checkpoint_hash_from_saved_proof_bytes, genesis_checkpoint_hash,
        CanonicalChainRef, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
    }, v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::PQEDCheckpointGlobalStateRoots, checkpoint_sync::PQEDCheckpointSyncInfoCompact, contract::{DashMapContractHeightCache, PQBCDeployContract, PsyDeployContractQueueItem}, public_key::PZKPublicKeyInfo
        },
    }
};
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorEdgeAPIStoreReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::{
        CoordinatorGutaSubmissionClaimOutcome, CoordinatorGutaSubmissionDigest,
        StandardEdgeAPITempDBStoreBase,
    },
    queue::{
        coordinator_guta_durable_submission::{
            CoordinatorGutaDurableSubmission, CoordinatorGutaQueueItem,
            CoordinatorGutaDurableSubmissionStore,
        },
        ephemeral::QStandardEphemeralQueuePublisher,
        worker_queue::QStandardWorkerQueueSubscriber,
    },
    store::{
        canonical_head::{CanonicalHeadReadState, CanonicalHeadRevision, CoordinatorCanonicalHeadReader},
        rollback_admin::{
            CoordinatorRollbackAdminInbox, RollbackAdminInboxAccess,
            RollbackAdminInboxPhase, RollbackAdminInboxStatus,
            RollbackAdminAbortDisposition as CoreRollbackAdminAbortDisposition,
            RollbackAdminAbortIntent,
            RollbackAdminStartDisposition as CoreRollbackAdminStartDisposition,
            RollbackAdminPlannedStartIntent,
        },
        rollback_control::{
            RollbackAbortReasonCode, RollbackExecutionMode, RollbackPlanDigest,
            RollbackRequest,
        },
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    },
    store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore},
};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle};

use crate::coordinator::queue_key::{CoordinatorDeployContractQueueKey, CoordinatorRegisterUserPublicKeyQueueKey, CoordinatorSubmitRealmGUTAUpdateQueueKey};

fn map_admin_disposition(
    disposition: CoreRollbackAdminStartDisposition,
) -> RollbackAdminStartDisposition {
    match disposition {
        CoreRollbackAdminStartDisposition::Accepted => RollbackAdminStartDisposition::Accepted,
        CoreRollbackAdminStartDisposition::Idempotent => {
            RollbackAdminStartDisposition::Idempotent
        }
        CoreRollbackAdminStartDisposition::Disabled => {
            RollbackAdminStartDisposition::RollbackAdminDisabled
        }
        CoreRollbackAdminStartDisposition::AlreadyActive => {
            RollbackAdminStartDisposition::RollbackAlreadyInProgress
        }
        CoreRollbackAdminStartDisposition::HeadMismatch => {
            RollbackAdminStartDisposition::HeadMismatch
        }
        CoreRollbackAdminStartDisposition::Conflict => {
            RollbackAdminStartDisposition::RollbackAdmissionConflict
        }
    }
}

fn map_admin_abort_disposition(
    disposition: CoreRollbackAdminAbortDisposition,
) -> RollbackAdminAbortDisposition {
    match disposition {
        CoreRollbackAdminAbortDisposition::Accepted => RollbackAdminAbortDisposition::Accepted,
        CoreRollbackAdminAbortDisposition::Idempotent => {
            RollbackAdminAbortDisposition::Idempotent
        }
        CoreRollbackAdminAbortDisposition::Disabled => {
            RollbackAdminAbortDisposition::RollbackAdminDisabled
        }
        CoreRollbackAdminAbortDisposition::NoActiveRollback => {
            RollbackAdminAbortDisposition::NoActiveRollback
        }
        CoreRollbackAdminAbortDisposition::HeadMismatch => {
            RollbackAdminAbortDisposition::HeadMismatch
        }
        CoreRollbackAdminAbortDisposition::PointOfNoReturn => {
            RollbackAdminAbortDisposition::RollbackPointOfNoReturn
        }
        CoreRollbackAdminAbortDisposition::Conflict => {
            RollbackAdminAbortDisposition::RollbackAdmissionConflict
        }
    }
}

fn realm_sync_canonical_ref<Hash: Copy + Eq>(
    head: CanonicalChainRef<Hash>,
    checkpoint_id: u64,
    checkpoint_hash: CheckpointHash<Hash>,
) -> anyhow::Result<CanonicalChainRef<Hash>> {
    let head_checkpoint_id = head.checkpoint().checkpoint_id().get();
    if checkpoint_id > head_checkpoint_id {
        anyhow::bail!(
            "REALM_SYNC_CHECKPOINT_AHEAD_OF_CANONICAL_HEAD:requested={},head={}",
            checkpoint_id,
            head_checkpoint_id
        );
    }
    if checkpoint_id == head_checkpoint_id
        && head.checkpoint().checkpoint_hash() != &checkpoint_hash
    {
        anyhow::bail!(
            "REALM_SYNC_HEAD_HASH_MISMATCH:checkpoint_id={}",
            checkpoint_id
        );
    }

    Ok(CanonicalChainRef::new(
        head.network_id(),
        head.chain_epoch(),
        CheckpointRef::new(CheckpointId::new(checkpoint_id), checkpoint_hash),
    ))
}

#[cfg(test)]
mod rollback_admin_tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
        NetworkId,
    };

    use super::*;

    #[test]
    fn mutating_edge_operation_inventory_is_explicit_and_complete() {
        assert_eq!(CoordinatorMutatingEdgeOperation::ALL.len(), 6);
        assert_eq!(
            CoordinatorMutatingEdgeOperation::ALL.map(|operation| operation.as_str()),
            [
                "register_user",
                "deploy_contract",
                "submit_guta",
                "get_proving_work",
                "get_proving_work_with_child_proofs",
                "submit_proof_raw",
            ]
        );
    }

    #[test]
    fn every_known_mutating_edge_entrypoint_invokes_the_gate() {
        fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
            let marker = format!("pub async fn {name}");
            let start = source.find(&marker).expect("entrypoint must exist");
            let rest = &source[start + marker.len()..];
            let end = rest.find("\n    pub async fn ").unwrap_or(rest.len());
            &rest[..end]
        }

        let handler = include_str!("handler.rs");
        let worker = include_str!("worker_handler.rs");
        for (source, name, operation) in [
            (handler, "register_user_internal", "RegisterUser"),
            (handler, "deploy_contract_internal", "DeployContract"),
            (handler, "submit_guta_internal", "SubmitGuta"),
            (worker, "get_proving_work_internal", "GetProvingWork"),
            (
                worker,
                "get_proving_work_with_child_proofs_internal",
                "GetProvingWorkWithChildProofs",
            ),
            (worker, "submit_proof_raw_internal", "SubmitProofRaw"),
        ] {
            let body = function_body(source, name);
            assert!(
                body.contains("require_mutating_service_available_internal"),
                "{name} must invoke the maintenance gate"
            );
            assert!(
                body.contains(&format!("CoordinatorMutatingEdgeOperation::{operation}")),
                "{name} must identify its typed operation"
            );
        }

        for name in [
            "admin_start_rollback_internal",
            "admin_abort_rollback_internal",
            "admin_get_rollback_status_internal",
            "get_canonical_chain_ref_internal",
        ] {
            assert!(
                !function_body(handler, name)
                    .contains("require_mutating_service_available_internal"),
                "{name} must remain available for control-plane observation"
            );
        }
    }

    #[test]
    fn coordinator_guta_submission_uses_content_claim_exact_proof_and_acked_publish_order() {
        let source = include_str!("handler.rs");
        let submit_marker = ["pub async fn ", "submit_guta_internal"].concat();
        let next_marker = [
            "\n    async fn ",
            "ensure_guta_matches_current_coordinator_state",
        ]
        .concat();
        let start = source
            .find(&submit_marker)
            .expect("submit_guta_internal must exist");
        let body = &source[start..source[start..]
            .find(&next_marker)
            .map(|end| start + end)
            .unwrap_or(source.len())];

        assert!(!body.contains("rand::random"));
        assert!(!body.contains("set_submitted_status_for_pending"));
        let legacy_claim_precheck = body
            .find("get_coordinator_guta_submission_claim")
            .expect("legacy selection must be checked before durable migration");
        let durable_persist = body
            .find("persist_and_readback")
            .expect("durable submission must be persisted before cache projection");
        let claim = body
            .find("claim_coordinator_guta_submission")
            .expect("content-bound atomic claim must exist");
        let proof = body
            .find("put_proof_bytes_exact")
            .expect("exact proof persistence must exist");
        let readback = body
            .rfind("get_proof_bytes_exact")
            .expect("exact proof readback must exist");
        let claim_revalidation = body
            .rfind("get_coordinator_guta_submission_claim")
            .expect("claim must be revalidated before publish");
        let durable_revalidation = body
            .find("read_selected")
            .expect("durable submission must be revalidated before publish");
        let publish = body
            .find("publish_ephemeral_queue_item_owned")
            .expect("Coordinator queue publish must exist");
        assert!(legacy_claim_precheck < durable_persist);
        assert!(durable_persist < claim);
        assert!(claim < proof);
        assert!(proof < readback);
        assert!(readback < durable_revalidation);
        assert!(readback < claim_revalidation);
        assert!(durable_revalidation < publish);
        assert!(claim_revalidation < publish);
    }

    fn request() -> RollbackAdminStartRequest<PHash> {
        RollbackAdminStartRequest {
            request_version: ROLLBACK_ADMIN_START_REQUEST_VERSION,
            expected_revision: 7,
            expected_canonical_ref: CanonicalChainRef::new(
                NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
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
            topology_revision: 3,
            topology_digest_hex: format!("0x{}", "a5".repeat(32)),
        }
    }

    #[test]
    fn valid_wire_request_becomes_typed_intent() {
        let intent = parse_rollback_admin_intent(request()).unwrap();
        assert_eq!(intent.expected_revision().get(), 7);
        assert_eq!(intent.target().checkpoint_id().get(), 90);
        assert_eq!(intent.fence_window().delete_fence().as_i64(), 1_001);
        assert_eq!(intent.topology_revision(), 3);
        assert_eq!(intent.topology_digest(), &[0xA5; 32]);
    }

    #[test]
    fn version_digest_and_timestamp_errors_fail_closed() {
        let mut invalid = request();
        invalid.request_version += 1;
        assert!(
            parse_rollback_admin_intent(invalid)
                .unwrap_err()
                .to_string()
                .contains("ROLLBACK_ADMIN_UNSUPPORTED_REQUEST_VERSION")
        );

        let mut invalid = request();
        invalid.topology_digest_hex = "00".repeat(31);
        assert!(
            parse_rollback_admin_intent(invalid)
                .unwrap_err()
                .to_string()
                .contains("ROLLBACK_ADMIN_INVALID_TOPOLOGY_DIGEST_LENGTH")
        );

        let mut invalid = request();
        invalid.execution_mode = RollbackAdminExecutionMode::SnapshotReplay;
        assert!(parse_rollback_admin_intent(invalid)
            .unwrap_err()
            .to_string()
            .contains("ROLLBACK_ADMIN_IN_PLACE_ONLY"));

        let mut invalid = request();
        invalid.delete_fence_timestamp_us = invalid.orphan_write_max_timestamp_us;
        assert!(parse_rollback_admin_intent(invalid).is_err());
    }

    #[test]
    fn abort_wire_request_binds_exact_active_identity_and_rejects_zero_reason() {
        let request = RollbackAdminAbortRequest {
            request_version: ROLLBACK_ADMIN_ABORT_REQUEST_VERSION,
            expected_revision: 12,
            expected_chain_epoch: 3,
            expected_plan_digest_hex: format!("0x{}", "a5".repeat(32)),
            reason_code: 19,
        };
        let intent = parse_rollback_admin_abort_intent(request.clone()).unwrap();
        assert_eq!(intent.expected_revision().get(), 12);
        assert_eq!(intent.expected_chain_epoch(), 3);
        assert_eq!(intent.expected_plan_digest().as_bytes(), &[0xA5; 32]);
        assert_eq!(intent.reason_code().get(), 19);

        let mut invalid = request.clone();
        invalid.reason_code = 0;
        assert!(parse_rollback_admin_abort_intent(invalid).is_err());
        let mut invalid = request.clone();
        invalid.request_version += 1;
        assert!(parse_rollback_admin_abort_intent(invalid)
            .unwrap_err()
            .to_string()
            .contains("ROLLBACK_ADMIN_UNSUPPORTED_ABORT_REQUEST_VERSION"));
        let mut invalid = request;
        invalid.expected_plan_digest_hex = "aa".repeat(31);
        assert!(parse_rollback_admin_abort_intent(invalid)
            .unwrap_err()
            .to_string()
            .contains("ROLLBACK_ADMIN_INVALID_PLAN_DIGEST_LENGTH"));
    }

    fn chain_ref(checkpoint_id: u64, hash_seed: u64) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
            ChainEpoch::new(9),
            CheckpointRef::new(
                CheckpointId::new(checkpoint_id),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    hash_seed,
                    hash_seed + 1,
                    hash_seed + 2,
                    hash_seed + 3,
                )),
            ),
        )
    }

    #[test]
    fn historical_realm_sync_ref_preserves_current_network_and_epoch() {
        let head = chain_ref(100, 1000);
        let historical_hash =
            CheckpointHash::from_last_chain_hash(PHash::from_values(90, 91, 92, 93));

        let observed = realm_sync_canonical_ref(head, 90, historical_hash).unwrap();

        assert_eq!(observed.network_id(), head.network_id());
        assert_eq!(observed.chain_epoch(), head.chain_epoch());
        assert_eq!(observed.checkpoint().checkpoint_id().get(), 90);
        assert_eq!(observed.checkpoint().checkpoint_hash(), &historical_hash);
    }

    #[test]
    fn realm_sync_ref_rejects_future_checkpoint() {
        let error = realm_sync_canonical_ref(
            chain_ref(100, 1000),
            101,
            CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4)),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("REALM_SYNC_CHECKPOINT_AHEAD_OF_CANONICAL_HEAD")
        );
    }

    #[test]
    fn realm_sync_ref_rejects_wrong_hash_at_current_head() {
        let error = realm_sync_canonical_ref(
            chain_ref(100, 1000),
            100,
            CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4)),
        )
        .unwrap_err();

        assert!(error.to_string().contains("REALM_SYNC_HEAD_HASH_MISMATCH"));
    }
}

fn map_admin_request<Hash: Copy>(
    request: &RollbackRequest<Hash>,
) -> RollbackAdminRequestSummary<Hash> {
    RollbackAdminRequestSummary {
        requested_checkpoint_id: request.requested_head().checkpoint_id().get(),
        requested_checkpoint_hash: *request.requested_head().checkpoint_hash().as_inner(),
        target_checkpoint_id: request.target().checkpoint_id().get(),
        target_checkpoint_hash: *request.target().checkpoint_hash().as_inner(),
        execution_mode: match request.execution_mode() {
            RollbackExecutionMode::InPlace => RollbackAdminExecutionMode::InPlace,
            RollbackExecutionMode::SnapshotReplay => {
                RollbackAdminExecutionMode::SnapshotReplay
            }
        },
        plan_digest_hex: hex::encode(request.plan_digest().as_bytes()),
    }
}

fn parse_rollback_admin_intent<Hash: Q256BitHash>(
    request: RollbackAdminStartRequest<Hash>,
) -> anyhow::Result<RollbackAdminPlannedStartIntent<Hash>> {
    if request.request_version != ROLLBACK_ADMIN_START_REQUEST_VERSION {
        anyhow::bail!(
            "ROLLBACK_ADMIN_UNSUPPORTED_REQUEST_VERSION:{}",
            request.request_version
        );
    }
    let digest_hex = request
        .topology_digest_hex
        .strip_prefix("0x")
        .or_else(|| request.topology_digest_hex.strip_prefix("0X"))
        .unwrap_or(&request.topology_digest_hex);
    let digest_bytes = hex::decode(digest_hex)
        .map_err(|error| anyhow::anyhow!("ROLLBACK_ADMIN_INVALID_TOPOLOGY_DIGEST:{error}"))?;
    let digest: [u8; 32] = digest_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "ROLLBACK_ADMIN_INVALID_TOPOLOGY_DIGEST_LENGTH:{}",
            bytes.len()
        )
    })?;
    if request.execution_mode != RollbackAdminExecutionMode::InPlace {
        anyhow::bail!("ROLLBACK_ADMIN_IN_PLACE_ONLY");
    }
    let orphan_write_max = CommitWriteTimestampUs::try_from_i128(i128::from(
        request.orphan_write_max_timestamp_us,
    ))?;
    let fence_window = TimestampFenceWindow::try_new(
        orphan_write_max,
        i128::from(request.delete_fence_timestamp_us),
        i128::from(request.new_branch_write_timestamp_us),
    )?;
    Ok(RollbackAdminPlannedStartIntent::new(
        CanonicalHeadRevision::try_new(request.expected_revision)?,
        request.expected_canonical_ref,
        CheckpointRef::new(
            CheckpointId::new(request.target_checkpoint_id),
            CheckpointHash::from_last_chain_hash(request.target_checkpoint_hash),
        ),
        fence_window,
        request.topology_revision,
        digest,
    ))
}

fn parse_rollback_admin_abort_intent(
    request: RollbackAdminAbortRequest,
) -> anyhow::Result<RollbackAdminAbortIntent> {
    if request.request_version != ROLLBACK_ADMIN_ABORT_REQUEST_VERSION {
        anyhow::bail!(
            "ROLLBACK_ADMIN_UNSUPPORTED_ABORT_REQUEST_VERSION:{}",
            request.request_version
        );
    }
    let digest_hex = request
        .expected_plan_digest_hex
        .strip_prefix("0x")
        .or_else(|| request.expected_plan_digest_hex.strip_prefix("0X"))
        .unwrap_or(&request.expected_plan_digest_hex);
    let digest_bytes = hex::decode(digest_hex)
        .map_err(|error| anyhow::anyhow!("ROLLBACK_ADMIN_INVALID_PLAN_DIGEST:{error}"))?;
    let digest: [u8; 32] = digest_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "ROLLBACK_ADMIN_INVALID_PLAN_DIGEST_LENGTH:{}",
            bytes.len()
        )
    })?;
    Ok(RollbackAdminAbortIntent::new(
        CanonicalHeadRevision::try_new(request.expected_revision)?,
        request.expected_chain_epoch,
        RollbackPlanDigest::try_new(digest)?,
        RollbackAbortReasonCode::try_new(request.reason_code)?,
    ))
}

// const END_CAP_PROOF_CIRCUIT_TYPE_U32: u32 = ProvingJobCircuitType::UserEndCap as u32;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorMutatingEdgeOperation {
    RegisterUser,
    DeployContract,
    SubmitGuta,
    GetProvingWork,
    GetProvingWorkWithChildProofs,
    SubmitProofRaw,
}

impl CoordinatorMutatingEdgeOperation {
    pub const ALL: [Self; 6] = [
        Self::RegisterUser,
        Self::DeployContract,
        Self::SubmitGuta,
        Self::GetProvingWork,
        Self::GetProvingWorkWithChildProofs,
        Self::SubmitProofRaw,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegisterUser => "register_user",
            Self::DeployContract => "deploy_contract",
            Self::SubmitGuta => "submit_guta",
            Self::GetProvingWork => "get_proving_work",
            Self::GetProvingWorkWithChildProofs => "get_proving_work_with_child_proofs",
            Self::SubmitProofRaw => "submit_proof_raw",
        }
    }
}

pub struct CoordinatorEdgeHandler<
    N: QNetworkTypesConfig,
    S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueuePublisher,
    RegisterUserQueue: QStandardEphemeralQueuePublisher,
    DeployContractQueue: QStandardEphemeralQueuePublisher,
    GetProofWorkQueue: QStandardWorkerQueueSubscriber,
    TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
> {
    pub db_reader: Arc<S>,
    pub canonical_head_reader: Arc<dyn CoordinatorCanonicalHeadReader<N::QHash>>,
    pub rollback_admin_inbox: Arc<CoordinatorRollbackAdminInbox<N::QHash>>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,
    durable_guta_submissions:
        Option<Arc<dyn CoordinatorGutaDurableSubmissionStore<N::QHash>>>,

    pub guta_update_queue: Arc<GUTAUpdateQueue>,
    pub register_user_queue: Arc<RegisterUserQueue>,
    pub deploy_contract_queue: Arc<DeployContractQueue>,
    pub get_proof_work_queue: Arc<GetProofWorkQueue>,

    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,

    pub proof_verifier: Arc<N::ZKVerifier>,
    pub contract_state_tree_height_cache: Arc<DashMapContractHeightCache<N::QHash>>,

    pub checkpoint_state_transition_circuit_fingerprint: N::QHash,
    pub genesis_checkpoint_state_transition_fingerprint: N::QHash,
    pub network_id: NetworkId,
}
impl<
        N: QNetworkTypesConfig,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher,
        RegisterUserQueue: QStandardEphemeralQueuePublisher,
        DeployContractQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    > Clone
    for CoordinatorEdgeHandler<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >
{
    fn clone(&self) -> Self {
        Self {
            db_reader: self.db_reader.clone(),
            canonical_head_reader: self.canonical_head_reader.clone(),
            rollback_admin_inbox: self.rollback_admin_inbox.clone(),
            tag_tree_rewards_store: self.tag_tree_rewards_store.clone(),
            temp_db: self.temp_db.clone(),
            proof_store: self.proof_store.clone(),
            durable_guta_submissions: self.durable_guta_submissions.clone(),
            guta_update_queue: self.guta_update_queue.clone(),
            register_user_queue: self.register_user_queue.clone(),
            deploy_contract_queue: self.deploy_contract_queue.clone(),
            get_proof_work_queue: self.get_proof_work_queue.clone(),
            realm_identifier: self.realm_identifier.clone(),
            realm_id_u64: self.realm_id_u64.clone(),
            realm_sub_id_u64: self.realm_sub_id_u64.clone(),
            proof_verifier: self.proof_verifier.clone(),
            contract_state_tree_height_cache: self.contract_state_tree_height_cache.clone(),
            checkpoint_state_transition_circuit_fingerprint: self.checkpoint_state_transition_circuit_fingerprint.clone(),
            genesis_checkpoint_state_transition_fingerprint: self.genesis_checkpoint_state_transition_fingerprint.clone(),
            network_id: self.network_id,
        }
    }
}
impl<
        N: QNetworkTypesConfig,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher,
        RegisterUserQueue: QStandardEphemeralQueuePublisher,
        DeployContractQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    >
    CoordinatorEdgeHandler<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >
{
    pub fn new(
        db: Arc<S>,
        canonical_head_reader: Arc<dyn CoordinatorCanonicalHeadReader<N::QHash>>,
        rollback_admin_inbox: Arc<CoordinatorRollbackAdminInbox<N::QHash>>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        guta_update_queue: Arc<GUTAUpdateQueue>,
        register_user_queue: Arc<RegisterUserQueue>,
        deploy_contract_queue: Arc<DeployContractQueue>,
        get_proof_work_queue: Arc<GetProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        proof_verifier: Arc<N::ZKVerifier>,
        checkpoint_state_transition_circuit_fingerprint: N::QHash,
        genesis_checkpoint_state_transition_fingerprint: N::QHash,
        network_id: NetworkId,
    ) -> Self {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;
        Self {
            db_reader: db,
            canonical_head_reader,
            rollback_admin_inbox,
            tag_tree_rewards_store,
            temp_db,
            proof_store,
            durable_guta_submissions: None,
            guta_update_queue,
            register_user_queue,
            deploy_contract_queue,
            get_proof_work_queue,
            realm_identifier,
            realm_id_u64,
            realm_sub_id_u64,
            proof_verifier,
            contract_state_tree_height_cache: Arc::new(DashMapContractHeightCache::new()),
            checkpoint_state_transition_circuit_fingerprint,
            genesis_checkpoint_state_transition_fingerprint,
            network_id,
        }
    }

    /// Install the Coordinator-scoped v16 durable selection store. Legacy
    /// construction remains default-off; an installed store is the authority
    /// and Redis becomes only an exactly reconstructed proof projection.
    pub fn install_durable_guta_submissions(
        mut self,
        store: Arc<dyn CoordinatorGutaDurableSubmissionStore<N::QHash>>,
    ) -> anyhow::Result<Self> {
        if store.network() != self.network_id
            || store.authority() != psy_data::protocol::chain_context::AuthorityScope::Coordinator
            || store.readiness_digest() == [0; 32]
        {
            anyhow::bail!("Coordinator GUTA durable store identity does not match Handler");
        }
        self.durable_guta_submissions = Some(store);
        Ok(self)
    }

    pub async fn admin_start_rollback_internal(
        &self,
        request: RollbackAdminStartRequest<N::QHash>,
    ) -> anyhow::Result<RollbackAdminStartResponse<N::QHash>> {
        let intent = parse_rollback_admin_intent(request)?;
        let receipt = self.rollback_admin_inbox.start_planned(intent).await?;
        Ok(RollbackAdminStartResponse {
            disposition: map_admin_disposition(receipt.disposition()),
            status: self.map_admin_status(receipt.status()),
        })
    }

    pub async fn admin_abort_rollback_internal(
        &self,
        request: RollbackAdminAbortRequest,
    ) -> anyhow::Result<RollbackAdminAbortResponse<N::QHash>> {
        let intent = parse_rollback_admin_abort_intent(request)?;
        let receipt = self.rollback_admin_inbox.abort(intent).await?;
        Ok(RollbackAdminAbortResponse {
            disposition: map_admin_abort_disposition(receipt.disposition()),
            status: self.map_admin_status(receipt.status()),
        })
    }

    pub async fn admin_get_rollback_status_internal(
        &self,
    ) -> anyhow::Result<RollbackAdminStatus<N::QHash>> {
        let status = self.rollback_admin_inbox.status().await?;
        Ok(self.map_admin_status(&status))
    }

    /// Admission boundary for operations that create work or mutate
    /// Coordinator-owned state. The returned permit is intentionally consumed
    /// here: it is evidence of an idle observation, not a cross-store lease.
    pub async fn require_mutating_service_available_internal(
        &self,
        operation: CoordinatorMutatingEdgeOperation,
    ) -> anyhow::Result<()> {
        let permit = self.rollback_admin_inbox
            .require_service_available()
            .await?;
        tracing::trace!(
            operation = operation.as_str(),
            canonical_revision = permit.canonical_head().revision().get(),
            inbox_revision = permit.inbox_revision().get(),
            "coordinator mutating edge operation admitted"
        );
        Ok(())
    }

    fn map_admin_status(
        &self,
        status: &RollbackAdminInboxStatus<N::QHash>,
    ) -> RollbackAdminStatus<N::QHash> {
        let request = status
            .canonical_head()
            .rollback_control()
            .requested()
            .or_else(|| {
                status
                    .admission_slot()
                    .state()
                    .pending()
                    .map(|command| command.request())
            })
            .map(map_admin_request);
        RollbackAdminStatus {
            admin_rpc_enabled: self.rollback_admin_inbox.access()
                == RollbackAdminInboxAccess::ManualPreflight,
            phase: match status.phase() {
                RollbackAdminInboxPhase::Idle => RollbackAdminPhase::Idle,
                RollbackAdminInboxPhase::Pending => RollbackAdminPhase::Pending,
                RollbackAdminInboxPhase::Active => RollbackAdminPhase::Active,
                RollbackAdminInboxPhase::Stale => RollbackAdminPhase::Stale,
            },
            canonical_revision: status.canonical_head().revision().get(),
            canonical_ref: *status.canonical_head().canonical_ref(),
            inbox_revision: status.admission_slot().revision().get(),
            request,
        }
    }
    pub async fn get_checkpoint_leaves_batch_raw_internal(&self, start_checkpoint_id: u64, count: u32) -> anyhow::Result<Vec<u8>>{
        let latest_checkpoint_id = self.get_latest_checkpoint_id_internal().await?;
        if count > 10000 {
            anyhow::bail!("requested count {} exceeds maximum of 10000", count);
        }
        let end_checkpoint = std::cmp::min(start_checkpoint_id + count as u64 - 1, latest_checkpoint_id);
        let mut keys = Vec::with_capacity((end_checkpoint - start_checkpoint_id + 1) as usize);
        for cid in start_checkpoint_id..=end_checkpoint {
            keys.push(SimpleMerkleNodeKey{
                level: N::CHECKPOINT_TREE_HEIGHT,
                index: cid,
            });
        }
        let results: Vec<N::QHash> = self.db_reader.checkpoint_tree_get_nodes(latest_checkpoint_id, &keys).await?;

        Ok(N::QHash::psy_ser_serialize_vec_of_self(results, false))

    }

    pub async fn get_realm_sync_info_internal(&self, realm_id: u64, checkpoint_id: u64) -> anyhow::Result<PsyRealmCoordinatorUpdate<N::F, N::QHash>> {
        // This response becomes Realm's durable local branch observation.  It
        // must therefore be read inside a stable IDLE control-plane window,
        // rather than combining a historical DB row with a remote "latest"
        // head observed at another time.
        let before = self.rollback_admin_inbox.status().await?;
        if before.phase() != RollbackAdminInboxPhase::Idle {
            anyhow::bail!("ROLLBACK_MAINTENANCE:{:?}", before.phase());
        }
        let head = before.canonical_head();

        let l2_block_state = self.db_reader.get_l2_block_state(checkpoint_id).await?;
        let checkpoint_leaf = self.db_reader.get_checkpoint_leaf_data(checkpoint_id).await?;
        let state_roots:PQEDCheckpointGlobalStateRoots<N::QHash> = self.db_reader.get_checkpoint_global_state_roots(checkpoint_id).await?;
        let checkpoint_tree_proof: MerkleProofCore<N::QHash> = self.db_reader.checkpoint_tree_get_merkle_proof(checkpoint_id, checkpoint_id).await?;

        let upd: Option<(u64, u128)> = self.db_reader.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await?;
        if upd.is_none() {
            anyhow::bail!("no unique pending id found for checkpoint id {}", checkpoint_id);
        }
        let (unique_pending_id, _) = upd.unwrap();

        let merkle_proof_to_realm_root = self.db_reader.global_user_tree_get_merkle_proof_sub_tree(checkpoint_id, 0, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, realm_id).await?;


        let reward_tree_top_proof_key: Option<SimpleMerkleNodeKey> = self.db_reader.get_realm_guta_reward_tree_node_key(unique_pending_id, realm_id).await?;

        let reward_tree_top_proof = if let Some(proof_key) = reward_tree_top_proof_key {
            let mut res = self.tag_tree_rewards_store.rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(unique_pending_id, &vec![proof_key]).await?;
            if res.len() == 0 {
                anyhow::bail!("no reward tree top proof found for realm id {} at checkpoint id {}", realm_id, checkpoint_id);
            }
            res.pop().unwrap()
        } else {
            TagTreeMerkleProof::<N::QHash>::new_empty()
        };

        let stored_transition = self
            .db_reader
            .get_verifiable_checkpoint_state_transition_and_zkp(checkpoint_id)
            .await?;
        let checkpoint_hash = if checkpoint_id == 0 && stored_transition.zk_proof.is_empty() {
            let transition = &stored_transition.info.state_transition.checkpoint_transition;
            genesis_checkpoint_hash::<_, N::HasherBase>(
                transition.new_checkpoint_tree_root,
                transition.new_checkpoint_leaf_hash,
                self.genesis_checkpoint_state_transition_fingerprint,
            )
        } else {
            let computed_checkpoint_hash = stored_transition
                .get_computed_public_inputs_hash::<N::HasherBase>();
            let extracted = checkpoint_hash_from_saved_proof_bytes::<
                N::QHash,
                N::ZKProof,
                N::ZKVerifier,
            >(&stored_transition.zk_proof)?;
            if extracted.as_inner() != &computed_checkpoint_hash {
                anyhow::bail!(
                    "REALM_SYNC_CHECKPOINT_PROOF_HASH_MISMATCH:checkpoint_id={}",
                    checkpoint_id
                );
            }
            extracted
        };

        let canonical_chain_ref =
            realm_sync_canonical_ref(*head.canonical_ref(), checkpoint_id, checkpoint_hash)?;

        let after = self.rollback_admin_inbox.status().await?;
        if after.phase() != RollbackAdminInboxPhase::Idle || before != after {
            anyhow::bail!("REALM_SYNC_CANONICAL_OBSERVATION_UNSTABLE");
        }

        Ok(PsyRealmCoordinatorUpdate {
            canonical_chain_ref,
            checkpoint_sync_info: PQEDCheckpointSyncInfoCompact {
                checkpoint_tree_root: checkpoint_tree_proof.root,
                checkpoint_leaf_hash: checkpoint_tree_proof.value,
                checkpoint_leaf: checkpoint_leaf,
                state_roots: state_roots,
                checkpoint_id,
                coordinator_id: self.realm_id_u64,
                coordinator_sub_id: self.realm_sub_id_u64,
                coordinator_unique_pending_id: unique_pending_id,
                block_state: l2_block_state,
            },
            merkle_proof_to_realm_root,
            reward_tree_top_proof,
        })



        //self.db_reader.get_realm_coordinator_update_at_checkpoint_id(self.realm_id_u64 as u32, checkpoint_id).await
    }
    pub async fn get_latest_checkpoint_id_internal(&self) -> anyhow::Result<u64> {
        self.db_reader.get_latest_checkpoint_id().await
    }
    pub async fn get_canonical_chain_ref_internal(&self) -> anyhow::Result<CanonicalChainRef<N::QHash>> {
        match self
            .canonical_head_reader
            .read_canonical_head(self.network_id)
            .await?
        {
            CanonicalHeadReadState::Current(current) => Ok(*current.canonical_ref()),
            CanonicalHeadReadState::Uninitialized => {
                anyhow::bail!("CANONICAL_HEAD_UNINITIALIZED")
            }
        }
    }
    pub async fn get_job_stats_internal(&self, checkpoint_id: u64) -> anyhow::Result<CheckpointJobStats> {
        let (unique_pending_id, _) = self
            .db_reader
            .get_unique_pending_id_for_checkpoint_id(checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("no unique pending id found for checkpoint id {}", checkpoint_id))?;
        let stats = self
            .temp_db
            .get_job_stats(&self.realm_identifier, unique_pending_id)
            .await?
            .unwrap_or_default();

        Ok(CheckpointJobStats {
            unique_pending_id,
            total_completed: stats.total_completed,
            total_duration_ms: stats.total_duration_ms,
            min_duration_ms: stats.min_duration_ms,
            max_duration_ms: stats.max_duration_ms,
        })
    }
    pub async fn get_checkpoint_id_for_unique_pending_id_internal(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>> {
        self.db_reader.get_checkpoint_id_for_unique_pending_id(unique_pending_id).await
    }
    pub async fn get_current_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.temp_db.get_unique_pending_ids(&self.realm_identifier).await
    }
    pub async fn get_current_gathering_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.temp_db.get_gathering_unique_pending_ids(&self.realm_identifier).await
    }
    pub async fn ensure_realm_has_not_submitted(&self, realm_id: u64, unique_pending_id: u64) -> anyhow::Result<()> {
        let submitted_status = self
            .temp_db
            .get_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, realm_id)
            .await?;
        if submitted_status != 0 {
            anyhow::bail!(
                "end cap for realm_id {} at unique_pending_id {} has already been submitted",
                realm_id,
                unique_pending_id
            );
        }

        Ok(())
    }

    pub async fn generate_batch_proof_miner_reward_proofs_internal(
        &self,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath<N::JobId>>,
    ) -> anyhow::Result<Vec<PsyProoffMinerRewardProof<N::QHash, N::JobId>>> {
        //let top_proof =
        // self.db_reader.
        // get_top_global_user_rewards_tree_proof_to_realm_at_unique_pending_id(unique_pending_id).
        // await?;

        //let (unique_pending_id, proc_checkpoint_id) =
        // self.temp_db.get_unique_pending_ids(&self.realm_identifier).await?;
        let merkle_node_keys = job_ids
            .iter()
            .map(|job_id_with_path| SimpleMerkleNodeKey::from_reward_path_info(job_id_with_path.reward_path_info))
            .collect::<Vec<_>>();

        self.tag_tree_rewards_store
            .rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(unique_pending_id, &merkle_node_keys)
            .await?
            .into_iter()
            .zip(job_ids.iter())
            .map(|(proof, job_id_with_path)| {
                Ok(PsyProoffMinerRewardProof {
                    job_id: job_id_with_path.job_data_id.clone(),
                    tag_tree_proof: proof,
                })
            })
            .collect()
    }
}

impl<
        N: QNetworkTypesConfig,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher,
        RegisterUserQueue: QStandardEphemeralQueuePublisher,
        DeployContractQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    >
    CoordinatorEdgeHandler<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >
{
    pub async fn get_register_user_queue_key(
        &self,
    ) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId, CoordinatorRegisterUserPublicKeyQueueKey<N::QHash>)> {
        let (unique_pending_id, unique_proc_checkpoint_id) = self.temp_db.get_gathering_unique_pending_ids(&self.realm_identifier).await?;
        println!("got gathering unique pending id {} and gathering proc checkpoint id {}", unique_pending_id, unique_proc_checkpoint_id);

        Ok((
            unique_pending_id,
            unique_proc_checkpoint_id,
            CoordinatorRegisterUserPublicKeyQueueKey::<N::QHash> {
                realm_id: self.realm_id_u64,
                realm_sub_id: self.realm_sub_id_u64,
                unique_id: unique_proc_checkpoint_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            },
        ))
    }
    pub async fn get_deploy_contract_queue_key(
        &self,
    ) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId, CoordinatorDeployContractQueueKey<N::F, N::QHash>)> {
        let (unique_pending_id, unique_proc_checkpoint_id) = self.temp_db.get_gathering_unique_pending_ids(&self.realm_identifier).await?;

        println!("got gathering unique pending id {} and gathering proc checkpoint id {}", unique_pending_id, unique_proc_checkpoint_id);
        Ok((
            unique_pending_id,
            unique_proc_checkpoint_id,
            CoordinatorDeployContractQueueKey {
                realm_id: self.realm_id_u64,
                realm_sub_id: self.realm_sub_id_u64,
                unique_id: unique_proc_checkpoint_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            },
        ))
    }

    pub async fn register_user_internal(&self, public_key: PZKPublicKeyInfo<N::QHash>) -> anyhow::Result<String>
    where
        N::ZKVerifier: 'static,
    {
        self.require_mutating_service_available_internal(CoordinatorMutatingEdgeOperation::RegisterUser).await?;
        let (_, unique_proc_checkpoint_id, queue_key) = self.get_register_user_queue_key().await?;
        self.require_mutating_service_available_internal(CoordinatorMutatingEdgeOperation::RegisterUser).await?;
        self.register_user_queue
            .publish_ephemeral_queue_item_owned_bytes(
                &queue_key,
                self.realm_id_u64,
                self.realm_sub_id_u64,
                unique_proc_checkpoint_id,
                0,
                public_key.psy_ser_into_bytes_vec()?,
            )
            .await?;

        Ok("ok".to_string())
    }
    pub async fn deploy_contract_internal(&self, deploy_contract: PQBCDeployContract<N::QHash>) -> anyhow::Result<String> {
        self.require_mutating_service_available_internal(CoordinatorMutatingEdgeOperation::DeployContract).await?;
        if deploy_contract.code_definition.functions.len() == 0 {
            anyhow::bail!("contracts with no functions are not supported");
        } else if deploy_contract.code_definition.functions.len() > (1usize << N::CONTRACT_FUNCTION_TREE_HEIGHT) {
            anyhow::bail!("contract has too many functions defined");
        }

        let (unique_pending_id, unique_proc_checkpoint_id, queue_key) = self.get_deploy_contract_queue_key().await?;

        let (deployer, code_definition, function_leaves, code_root) = deploy_contract.split_into_tuple();
        let queue_item = PsyDeployContractQueueItem::<N::F, N::QHash>::new_from_leaves_and_deployer::<N::HasherBase>(
            deployer,
            code_definition.state_tree_height,
            function_leaves,
            code_root,
            N::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE,
        )?;
        let deploy_content_hash = compute_deploy_contract_content_hash(
            &queue_item.contract_leaf.deployer.into_owned_32bytes(),
            &queue_item.contract_leaf.function_tree_root.into_owned_32bytes(),
            code_definition.state_tree_height as u64,
        );
        let deploy_content_hash_hex = hash_to_hex(&deploy_content_hash);

        self.require_mutating_service_available_internal(CoordinatorMutatingEdgeOperation::DeployContract).await?;
        self.temp_db
            .set_deploy_contract_code_definition_raw(
                &self.realm_identifier,
                unique_pending_id,
                &queue_item.rand_key_id,
                code_definition.psy_ser_into_bytes_vec()?,
            )
            .await?;
        tracing::info!("Stored deploy contract code definition raw in temp DB for pending id {} with rand key {:?}", unique_pending_id, &queue_item.rand_key_id);

        self.deploy_contract_queue
            .publish_ephemeral_queue_item_owned_bytes(
                &queue_key,
                self.realm_id_u64,
                self.realm_sub_id_u64,
                unique_proc_checkpoint_id,
                0,
                queue_item.psy_ser_into_bytes_vec()?,
            )
            .await?;

        Ok(deploy_content_hash_hex)
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher,
        RegisterUserQueue: QStandardEphemeralQueuePublisher,
        DeployContractQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore + QCanonicalProofStoreV2,
    >
    CoordinatorEdgeHandler<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >
{
    pub async fn submit_guta_internal(
        &self,
        input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()>
    where
        N::ZKVerifier: 'static,
    {
        self.require_mutating_service_available_internal(CoordinatorMutatingEdgeOperation::SubmitGuta).await?;
        let realm_id_u64 = input.header.header.state_transition.node_index.to_u64_value();
        println!("Submitting GUTA for realm_id {}\n{:?}", realm_id_u64, input);

        let realm_level_u64 = input.header.header.state_transition.node_level.to_u64_value();
        if realm_level_u64 != N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as u64 {
            anyhow::bail!(
                "invalid realm level {}, expected {}",
                realm_level_u64,
                N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT
            );
        }

        let realm_level = realm_level_u64 as u8;
        if realm_id_u64 >= (1u64 << realm_level) || realm_id_u64 > u32::MAX as u64 {
            anyhow::bail!("invalid realm id {}", realm_id_u64);
        }

        let realm_id = realm_id_u64 as u32;
        let proving_circuit_type = ProvingJobCircuitType::try_from_u32(input.job_type_u32)?;
        let proof_bytes = Arc::new(proof_bytes);

        let (unique_pending_id, proc_checkpoint_id) = self.get_current_gathering_unique_pending_id_internal().await?;
        let pending_context = self
            .temp_db
            .require_pending_context_for_pending_id(
                &self.realm_identifier,
                unique_pending_id,
            )
            .await?;
        if pending_context.proc_checkpoint_unique_id().as_u128() != proc_checkpoint_id {
            anyhow::bail!(
                "current pending context proc ID {} does not match gathering proc ID {}",
                pending_context.proc_checkpoint_unique_id().as_u128(),
                proc_checkpoint_id,
            );
        }
        self.ensure_guta_matches_current_coordinator_state(realm_id_u64, &input).await?;

        let output_proof_job_id = QProvingJobDataID::try_get_coordinator_edge_proof_store_output_proof_id_for_realm_submit(
            realm_id,
            realm_level,
            unique_pending_id,
            proving_circuit_type,
        )?;

        let expected_public_inputs_hash = input.qfhash::<N::HasherBase>();
        let proof_verifier = self.proof_verifier.clone();
        task::spawn_blocking({
            let proof_bytes = proof_bytes.clone();
            move || {
                proof_verifier.verify_zk_proof_from_slice_check_public_inputs_hash(input.job_type_u32, &proof_bytes, expected_public_inputs_hash)
            }
        }).await??;
        self.require_mutating_service_available_internal(CoordinatorMutatingEdgeOperation::SubmitGuta).await?;
        let current_context = self
            .temp_db
            .get_current_pending_context(&self.realm_identifier)
            .await?
            .ok_or_else(|| anyhow::anyhow!("current pending context disappeared during GUTA verification"))?;
        if current_context != pending_context {
            anyhow::bail!("pending context changed during GUTA verification");
        }

        let canonical_input = input.psy_ser_to_bytes_vec()?;
        let submission_digest = CoordinatorGutaSubmissionDigest::from_submission(
            realm_id_u64,
            &canonical_input,
            proof_bytes.as_slice(),
        )?;
        let proof_address = self
            .proof_store
            .resolve_proof_address(&pending_context, &output_proof_job_id)?;
        if self.durable_guta_submissions.is_some() {
            if let Some(existing) = self
                .temp_db
                .get_coordinator_guta_submission_claim(
                    &self.realm_identifier,
                    &pending_context,
                    realm_id_u64,
                )
                .await?
            {
                if existing != submission_digest {
                    anyhow::bail!(
                        "legacy Coordinator GUTA selection conflicts with durable candidate for realm {}",
                        realm_id,
                    );
                }
            }
            if let Some(existing) = self.proof_store.get_proof_bytes_exact(&proof_address).await? {
                if existing.as_slice() != proof_bytes.as_slice() {
                    anyhow::bail!(
                        "legacy Coordinator GUTA proof projection conflicts with durable candidate"
                    );
                }
            }
        }
        let queue_item = GlobalUserTreeAggregatorHeaderWithTagValueAndJobID {
            header: input.header,
            job_id: output_proof_job_id,
        };
        let queue_item_bytes = queue_item.psy_ser_to_bytes_vec()?;
        let durable_submission = if let Some(store) = &self.durable_guta_submissions {
            let durable_submission = CoordinatorGutaDurableSubmission::try_new(
                pending_context,
                realm_id_u64,
                canonical_input,
                proof_bytes.as_slice().to_vec(),
                queue_item_bytes,
            )?;
            let persisted = store
                .persist_and_readback(durable_submission.clone())
                .await?;
            if persisted != durable_submission {
                anyhow::bail!("Coordinator GUTA durable readback changed the selected submission");
            }
            Some(durable_submission)
        } else {
            None
        };
        match self
            .temp_db
            .claim_coordinator_guta_submission(
                &self.realm_identifier,
                &pending_context,
                realm_id_u64,
                submission_digest,
            )
            .await?
        {
            CoordinatorGutaSubmissionClaimOutcome::Applied
            | CoordinatorGutaSubmissionClaimOutcome::Idempotent => {}
            CoordinatorGutaSubmissionClaimOutcome::Conflict { .. } => {
                anyhow::bail!(
                    "conflicting GUTA for realm_id {} at exact pending generation {}",
                    realm_id,
                    unique_pending_id,
                );
            }
        }
        match self.proof_store.get_proof_bytes_exact(&proof_address).await? {
            Some(current) if current.as_slice() != proof_bytes.as_slice() => {
                anyhow::bail!("exact Coordinator GUTA proof address contains conflicting bytes");
            }
            Some(_) => {}
            None => {
                self.proof_store
                    .put_proof_bytes_exact(&proof_address, &proof_bytes)
                    .await?;
            }
        }
        let persisted_proof = self
            .proof_store
            .get_proof_bytes_exact(&proof_address)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Coordinator GUTA proof disappeared after write"))?;
        if persisted_proof.as_slice() != proof_bytes.as_slice() {
            anyhow::bail!("Coordinator GUTA proof readback does not match claimed submission");
        }

        let publish_context = self
            .temp_db
            .get_current_pending_context(&self.realm_identifier)
            .await?
            .ok_or_else(|| anyhow::anyhow!("current pending context disappeared before GUTA publish"))?;
        if publish_context != pending_context {
            anyhow::bail!("pending context changed before GUTA publish");
        }
        if let Some(store) = &self.durable_guta_submissions {
            let durable_submission = durable_submission.as_ref().ok_or_else(|| {
                anyhow::anyhow!("Coordinator GUTA durable submission was not retained")
            })?;
            if store.read_selected(durable_submission.slot()).await?
                != Some(durable_submission.clone())
            {
                anyhow::bail!("Coordinator GUTA durable submission changed before publish");
            }
        } else if self
            .temp_db
            .get_coordinator_guta_submission_claim(
                &self.realm_identifier,
                &pending_context,
                realm_id_u64,
            )
            .await?
            != Some(submission_digest)
        {
            anyhow::bail!("Coordinator GUTA submission claim changed before publish");
        }

        let queue_key = CoordinatorSubmitRealmGUTAUpdateQueueKey::<N::F, N::QHash> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: proc_checkpoint_id,
            task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let queue_item = match durable_submission.as_ref() {
            Some(submission) => CoordinatorGutaQueueItem::durable(submission, queue_item)?,
            None => CoordinatorGutaQueueItem::legacy(queue_item),
        };

        self.guta_update_queue
            .publish_ephemeral_queue_item_owned(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, proc_checkpoint_id, 0, queue_item)
            .await?;

        Ok(())
    }

    async fn ensure_guta_matches_current_coordinator_state(
        &self,
        realm_id: u64,
        input: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        let latest_checkpoint_id = self.get_latest_checkpoint_id_internal().await?;
        let realm_key = SimpleMerkleNodeKey {
            level: N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            index: realm_id,
        };
        let current_realm_root = self
            .db_reader
            .global_user_tree_get_node_and_checkpoint_id_max_checkpoint(latest_checkpoint_id, &realm_key)
            .await?;
        let submitted_old_realm_root = input.header.header.state_transition.old_node_value;

        if current_realm_root.value != submitted_old_realm_root {
            anyhow::bail!(
                "stale GUTA update rejected at coordinator edge: realm_id {} latest_checkpoint_id {} realm_last_modified_checkpoint_id {} submitted_old_realm_root {:?} current_realm_root {:?} submitted_new_realm_root {:?} submitted_checkpoint_tree_root {:?}",
                realm_id,
                latest_checkpoint_id,
                current_realm_root.checkpoint_id,
                submitted_old_realm_root,
                current_realm_root.value,
                input.header.header.state_transition.new_node_value,
                input.header.header.checkpoint_tree_root,
            );
        }

        Ok(())
    }
}
