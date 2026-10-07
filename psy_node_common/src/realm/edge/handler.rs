use std::{sync::Arc, u64};
use std::future::Future;
use tokio::task;
use futures::stream::{self, StreamExt};

use async_trait::async_trait;
use cf_utils::timer::DebugTimer;
use jsonrpsee::core::RpcResult;
use parth_core::{
    QProvingJobDataIDWithRewardPath, crypto::{
        hash::{
            merkle_proof::MerkleProofCore,
            tag_tree::TagTreeMerkleProof,
            traits::{HashTo4Felts, MerkleZeroHasher, QFieldHashable, ZeroableHash},
        },
        secp256k1::{QEDCompressedSecp256K1Signature, SimpleTimedRequest},
    }, data::{hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_store_key::{QMerkleStoreDoubleIdKeyWithHeight, QMerkleStoreSingleIdKey}}, queue::queue_key::QPBaseQueueType}, felt::ToU64Value, node::realm_identifier::QRealmIdentifier, protocol::core_types::{QNetworkTypesConfig, QZKProofPublicInputsHasherReader, QZKProofVerifier}
};
use psy_api_core::{
    realm::standard_edge_rpc::{
        RealmContractSlotUpdates, RealmEdgeRpcServer, RealmEndCapSlotUpdates, RealmSlotUpdate,
    },
    worker::standard_worker_rpc::NodeEdgeWorkerRpcServer,
    CheckpointJobStats,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    node::node_proving_state::PsyNodeProvingState, proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput, queue_items::realm_user_update::PsyRealmUserUpdateQueueItem, v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{DashMapContractHeightCache, IMTContractStateLeaf, IMTMembershipProof,
                IMTNonMembershipProof, IMTPredecessorResult, PSimpleContractHeightCache},
            user::PQEDUserLeaf,
        },
    }, worker::api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse}
};
use psy_node_core::{
    p2p::validator_lookup::load_realm_validators_from_tree,
    psy_core_db::traits::full::{
        PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
        PsyRealmEdgeAPIStoreReader,
    },
    psy_temp_db::{GatheringGeneration, StandardEdgeAPITempDBStoreBase},
    qblob::structs::common::blob_metadata_header::QBlobWriterContextMetadataHeader,
    queue::{
        ephemeral::QStandardEphemeralQueuePublisher,
        worker_queue::QStandardWorkerQueueSubscriber,
    },
    store::traits::proof_store::QParthProofStore,
};

use crate::realm::{
    edge::{
        error::{EndCapSubmitError, RpcError},
        utils::end_cap::validate_end_cap_and_generate_node_data_for_edge,
    },
    processor::gatherers::realm_end_cap_gatherer::validator_user_tree_proofs,
    queue_key::RealmUserUpdateQueueKey,
};
use std::collections::{HashMap, HashSet};

use crate::realm::network::RealmNetworkCommands;
use parth_common::realm_rotation::RealmRotationConfig;
use psy_config::CHECKPOINTS_PER_EPOCH;
use psy_data::p2p::{
    compute_end_cap_id, sha256, EndCapForwardHeader, EndCapForwardResponse, EndCapRejectReason,
    NodeId,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use crate::worker_whitelist::WhiteListCache;

const END_CAP_PROOF_CIRCUIT_TYPE_U32: u32 = ProvingJobCircuitType::UserEndCap as u32;

fn ensure_end_cap_generation_unchanged(
    stored: GatheringGeneration,
    gathering: GatheringGeneration,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        stored == gathering,
        "EndCap gathering generation changed during storage/delivery: stored {:?}, current {:?}; delivery is not confirmed",
        stored,
        gathering,
    );
    Ok(())
}

async fn with_end_cap_gathering_generation<Read, ReadFuture, Submit, SubmitFuture>(
    generation: GatheringGeneration,
    mut read_generation: Read,
    submit: Submit,
) -> anyhow::Result<()>
where
    Read: FnMut() -> ReadFuture,
    ReadFuture: Future<Output = anyhow::Result<GatheringGeneration>>,
    Submit: FnOnce(GatheringGeneration) -> SubmitFuture,
    SubmitFuture: Future<Output = anyhow::Result<()>>,
{
    ensure_end_cap_generation_unchanged(generation, read_generation().await?)?;
    submit(generation).await?;
    // A stale ephemeral publish may succeed after its gatherer has retired.
    ensure_end_cap_generation_unchanged(generation, read_generation().await?)
}

fn end_cap_generation_target(generation: GatheringGeneration) -> anyhow::Result<u64> {
    generation.checkpoint_id.checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("gathering checkpoint ID overflow at EndCap routing"))
}

fn ensure_forwarded_end_cap_target(header_checkpoint_id: u64, generation: GatheringGeneration) -> anyhow::Result<u64> {
    let target = end_cap_generation_target(generation)?;
    anyhow::ensure!(header_checkpoint_id == target, "forwarded EndCap checkpoint {} is not the admissible target {}", header_checkpoint_id, target);
    Ok(target)
}


/// Sparse subtree reads are only safe inside the realm half of the user tree.
/// Requests with `root_level` above the authenticated spine would otherwise
/// return max-vintage stale siblings for coordinator levels.
pub(crate) fn ensure_user_subtree_request_within_realm(
    root_level: u8,
    leaf_level: u8,
    coordinator_global_user_tree_height: u8,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        root_level >= coordinator_global_user_tree_height,
        "user-tree subtree root_level {} crosses authenticated spine boundary {}",
        root_level,
        coordinator_global_user_tree_height
    );
    anyhow::ensure!(
        leaf_level >= root_level,
        "user-tree subtree leaf_level {} is above root_level {}",
        leaf_level,
        root_level
    );
    Ok(())
}
pub struct RealmEdgeHandler<
    N: QNetworkTypesConfig,
    S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    UserUpdateQueue: QStandardEphemeralQueuePublisher,
    GetProofWorkQueue: QStandardWorkerQueueSubscriber,
    TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
> {
    pub db_reader: Arc<S>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,

    pub user_update_queue: Arc<UserUpdateQueue>,
    pub get_proof_work_queue: Arc<GetProofWorkQueue>,
    pub worker_whitelist: WhiteListCache,

    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub chain_id: u64,
    pub node_id: u32,

    pub proof_verifier: Arc<N::ZKVerifier>,
    pub contract_state_tree_height_cache: Arc<DashMapContractHeightCache<N::QHash>>,

    pub p2p: Option<RealmNetworkCommands>,
    pub proposer_edge_node_ids: Option<HashMap<u16, NodeId>>,
    pub realm_edge_node_ids: Option<HashSet<NodeId>>,
}
impl<
        N: QNetworkTypesConfig,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        UserUpdateQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    > Clone for RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    fn clone(&self) -> Self {
        Self {
            db_reader: self.db_reader.clone(),
            tag_tree_rewards_store: self.tag_tree_rewards_store.clone(),
            temp_db: self.temp_db.clone(),
            proof_store: self.proof_store.clone(),
            user_update_queue: self.user_update_queue.clone(),
            get_proof_work_queue: self.get_proof_work_queue.clone(),
            worker_whitelist: self.worker_whitelist.clone(),
            realm_identifier: self.realm_identifier.clone(),
            realm_id_u64: self.realm_id_u64.clone(),
            realm_sub_id_u64: self.realm_sub_id_u64.clone(),
            chain_id: self.chain_id.clone(),
            node_id: self.node_id.clone(),
            proof_verifier: self.proof_verifier.clone(),
            contract_state_tree_height_cache: self.contract_state_tree_height_cache.clone(),
            p2p: self.p2p.clone(),
            proposer_edge_node_ids: self.proposer_edge_node_ids.clone(),
            realm_edge_node_ids: self.realm_edge_node_ids.clone(),
        }
    }
}
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        UserUpdateQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    > RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    pub fn new(
        db: Arc<S>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        user_update_queue: Arc<UserUpdateQueue>,
        get_proof_work_queue: Arc<GetProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        worker_whitelist: WhiteListCache,
        chain_id: u64,
        node_id: u32,
        proof_verifier: Arc<N::ZKVerifier>,
    ) -> Self {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;
        Self {
            db_reader: db,
            tag_tree_rewards_store,
            temp_db,
            proof_store,
            user_update_queue,
            get_proof_work_queue,
            worker_whitelist,
            realm_identifier,
            realm_id_u64,
            realm_sub_id_u64,
            chain_id,
            node_id,
            proof_verifier,
            contract_state_tree_height_cache: Arc::new(DashMapContractHeightCache::new()),
            p2p: None,
            proposer_edge_node_ids: None,
            realm_edge_node_ids: None,
        }
    }
    pub fn set_realm_p2p(
        &mut self,
        commands: RealmNetworkCommands,
        proposer_edge_node_ids: HashMap<u16, NodeId>,
        realm_edge_node_ids: HashSet<NodeId>,
    ) {
        self.p2p = Some(commands);
        self.proposer_edge_node_ids = Some(proposer_edge_node_ids);
        self.realm_edge_node_ids = Some(realm_edge_node_ids);
    }
    pub async fn handle_p2p_end_cap_received(
        &self,
        source: NodeId,
        header: EndCapForwardHeader,
        input: Vec<u8>,
        proof: Vec<u8>,
    ) -> EndCapForwardResponse
    where
        N::ZKVerifier: 'static,
        N::ZKProof: 'static,
    {
        let checkpoint_id = header.checkpoint_id;
        match self.accept_forwarded_end_cap(source, header, input, proof).await {
            Ok(end_cap_id) => {
                tracing::info!(
                    "realm P2P EndCap accepted end_cap_id={} checkpoint={}",
                    hex::encode(end_cap_id),
                    checkpoint_id
                );
                EndCapForwardResponse::accepted()
            }
            Err(error) => {
                tracing::warn!(
                    "realm P2P EndCap rejected checkpoint={} error={}",
                    checkpoint_id,
                    error
                );
                match EndCapSubmitError::from_error_chain(&error) {
                    Some(EndCapSubmitError::AlreadySubmitted {
                        user_id,
                        unique_pending_id,
                    }) => EndCapForwardResponse::already_submitted(user_id, unique_pending_id),
                    Some(EndCapSubmitError::Busy(_)) => {
                        EndCapForwardResponse::rejected(EndCapRejectReason::Busy)
                    }
                    Some(EndCapSubmitError::Invalid(_)) | None => {
                        EndCapForwardResponse::rejected(EndCapRejectReason::Invalid)
                    }
                }
            }
        }
    }

    /// None = local edge is the scheduled proposer's primary edge, or P2P is unconfigured.
    async fn scheduled_proposer_dest(&self, target_checkpoint_id: u64) -> anyhow::Result<Option<(u16, NodeId)>> {
        let (Some(cmds), Some(proposer_edge_node_ids)) =
            (&self.p2p, &self.proposer_edge_node_ids)
        else {
            return Ok(None);
        };
        let base_checkpoint_id = target_checkpoint_id
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("EndCap target checkpoint must be positive"))?;
        let roots = self
            .db_reader
            .get_checkpoint_global_state_roots(base_checkpoint_id)
            .await?;
        let (validator_sub_ids, _, _, _) = load_realm_validators_from_tree::<N::HasherBase, N::QHash, _>(
            self.db_reader.as_ref(),
            self.chain_id,
            base_checkpoint_id,
            self.realm_id_u64 as u32,
            &roots.validator_tree_root,
        )
        .await?;
        let rotation = RealmRotationConfig {
            checkpoints_per_epoch: CHECKPOINTS_PER_EPOCH,
            validator_sub_ids,
        };
        let epoch = parth_common::realm_rotation::epoch(target_checkpoint_id, CHECKPOINTS_PER_EPOCH);
        let anchor_id = parth_common::realm_rotation::anchor_checkpoint_id(epoch, CHECKPOINTS_PER_EPOCH);
        let leaf = self.db_reader.get_checkpoint_leaf_data(anchor_id).await?;
        let felts = leaf.stats.random_seed.to_4_felts();
        let seed = [
            felts[0].to_u64_value(),
            felts[1].to_u64_value(),
            felts[2].to_u64_value(),
            felts[3].to_u64_value(),
        ];
        resolve_end_cap_forward_dest(
            self.realm_id_u64 as u32,
            cmds.local_node_id(),
            target_checkpoint_id,
            seed,
            &rotation,
            proposer_edge_node_ids,
        )
    }

    async fn ensure_local_is_scheduled_end_cap_receiver(&self, header_checkpoint_id: u64, generation: GatheringGeneration) -> anyhow::Result<()> {
        let admissible_target = ensure_forwarded_end_cap_target(header_checkpoint_id, generation)?;
        if self.p2p.is_none() {
            return Ok(());
        }
        self.proposer_edge_node_ids
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Realm edge proposer identities are missing"))?;
        if let Some((proposer, _)) = self.scheduled_proposer_dest(admissible_target).await? {
            anyhow::bail!(
                "forwarded EndCap rejected: local edge is not primary for scheduled proposer {proposer} at target {admissible_target}"
            );
        }
        Ok(())
    }
    async fn accept_forwarded_end_cap(
        &self,
        source: NodeId,
        header: EndCapForwardHeader,
        input: Vec<u8>,
        proof: Vec<u8>,
    ) -> anyhow::Result<[u8; 32]>
    where
        N::ZKVerifier: 'static,
        N::ZKProof: 'static,
    {
        let realm_edge_node_ids = self
            .realm_edge_node_ids
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("forwarded EndCap Realm edge identities are missing"))?;
        validate_forwarded_end_cap(
            source,
            &header,
            &input,
            &proof,
            self.chain_id,
            self.realm_id_u64 as u32,
            realm_edge_node_ids,
        )?;
        let user_end_cap_input =
            SubmitUserEndCapNonProofInput::<N::F, N::QHash>::psy_ser_from_slice(&input)?;
        self.handle_user_end_cap_proof_submission(user_end_cap_input, proof, Some(header.checkpoint_id))
            .await?;
        Ok(header.end_cap_id)
    }

    pub fn user_belongs_to_realm(&self, user_id: u64) -> bool {
        let users_per_realm = 1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;
        let min_user_id = self.realm_id_u64 * users_per_realm;
        let max_user_id = min_user_id + users_per_realm;
        user_id >= min_user_id && user_id < max_user_id
    }
    pub async fn get_latest_checkpoint_id(&self) -> anyhow::Result<u64> {
        self.db_reader.get_latest_checkpoint_id().await
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

    pub async fn get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id_internal(&self, checkpoint_id: u64) -> anyhow::Result<TagTreeMerkleProof<N::QHash>> {
        // Checkpoint and pending-ID namespaces share one numeric column; resolve mapping first.
        self.db_reader.get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(checkpoint_id).await
    }
    pub async fn ensure_user_has_not_submitted(&self, user_id: u64, unique_pending_id: u64) -> anyhow::Result<()> {
        let submitted_status = self
            .temp_db
            .get_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, user_id)
            .await?;
        if submitted_status != 0 {
            // Typed so the P2P reply and the RPC surface (-32001) share one
            // classification; the relayer's duplicate recovery parses this
            // exact message.
            return Err(anyhow::Error::new(EndCapSubmitError::AlreadySubmitted {
                user_id,
                unique_pending_id,
            }));
        }

        Ok(())
    }

    pub async fn generate_batch_proof_miner_reward_proofs_internal(
        &self,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath<N::JobId>>,
    ) -> anyhow::Result<Vec<PsyProoffMinerRewardProof<N::QHash, N::JobId>>> {
        let merkle_node_keys = job_ids
            .iter()
            .map(|job_id_with_path| SimpleMerkleNodeKey::from_reward_path_info(job_id_with_path.reward_path_info))
            .collect::<Vec<_>>();

        let mut tag_proofs = self.tag_tree_rewards_store
            .rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(unique_pending_id, &merkle_node_keys).await?;

        // Merge the realm-local reward proof with the coordinator-level proof so
        // the final root matches the checkpoint's global rewards root. The realm
        // processor persists this top proof keyed by unique_pending_id.
        let top_proof = self
            .db_reader
            .get_top_global_user_rewards_tree_proof_to_realm_at_unique_pending_id(unique_pending_id)
            .await?;
        for proof in &mut tag_proofs {
            anyhow::ensure!(
                proof.root == top_proof.leaf.get_node_hash::<N::HasherBase>(),
                "Realm rewards local root does not match top proof leaf at unique_pending_id {}",
                unique_pending_id
            );
            let local_proof_height = proof.siblings.len();
            proof.siblings.extend(top_proof.siblings.clone());
            proof.root = top_proof.root;
            proof.index |= top_proof.index << local_proof_height;
        }

        // Wrap into PsyProoffMinerRewardProof
        let miner_proofs = job_ids.into_iter().zip(tag_proofs.into_iter()).map(|(job_id_with_path, tag_proof)| {
            PsyProoffMinerRewardProof {
                job_id: job_id_with_path.job_data_id,
                tag_tree_proof: tag_proof,
            }
        }).collect::<Vec<_>>();

        Ok(miner_proofs)
    }
}

/// Pure validation for a forwarded EndCap header against the local Realm
/// identity: the source must be a validator NodeId, chain/realm must
/// match the local instance, input/proof lengths must match the header, and
/// the header `end_cap_id` must equal the canonical hash of the payload.
/// Returns the validated `end_cap_id` on success.
fn validate_forwarded_end_cap(
    source: NodeId,
    header: &EndCapForwardHeader,
    input: &[u8],
    proof: &[u8],
    local_chain_id: u64,
    local_realm_id: u32,
    realm_edge_node_ids: &HashSet<NodeId>,
) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        realm_edge_node_ids.contains(&source),
        "forwarded EndCap source NodeId {source} is not a Realm edge identity"
    );
    if header.chain_id != local_chain_id {
        anyhow::bail!(
            "forwarded EndCap chain_id {} does not match local {}",
            header.chain_id,
            local_chain_id
        );
    }
    if header.realm_id != local_realm_id {
        anyhow::bail!(
            "forwarded EndCap realm_id {} does not match local {}",
            header.realm_id,
            local_realm_id
        );
    }
    if header.end_cap_input_len as usize != input.len() {
        anyhow::bail!(
            "forwarded EndCap input length {} does not match header {}",
            input.len(),
            header.end_cap_input_len
        );
    }
    if header.proof_len as usize != proof.len() {
        anyhow::bail!(
            "forwarded EndCap proof length {} does not match header {}",
            proof.len(),
            header.proof_len
        );
    }
    let input_hash = sha256(input);
    let proof_hash = sha256(proof);
    let expected_end_cap_id = compute_end_cap_id(
        local_chain_id,
        local_realm_id,
        header.checkpoint_id,
        &input_hash,
        &proof_hash,
    );
    if expected_end_cap_id != header.end_cap_id {
        anyhow::bail!("forwarded EndCap id does not match canonical hash");
    }
    Ok(header.end_cap_id)
}

/// Pure equality check of the EndCap `start_user_leaf_hash` against the
/// expected current user leaf hash. Preserves the production log/error text.
fn ensure_start_user_leaf_hash<QHash: PartialEq + std::fmt::Debug>(
    supplied: &QHash,
    expected: &QHash,
) -> anyhow::Result<()> {
    if supplied != expected {
        tracing::error!(
            "Invalid start_user_leaf_hash, left: {:?}, right: {:?}",
            supplied,
            expected
        );
        anyhow::bail!(
            "Invalid start_user_leaf_hash, left: {:?}, right: {:?}",
            supplied,
            expected
        );
    }
    Ok(())
}

/// Pure Realm P2P EndCap forward routing for a target checkpoint. Intake stays
/// local only on the scheduled validator's primary edge.
fn resolve_end_cap_forward_dest(
    realm_id: u32,
    local_edge_node_id: NodeId,
    target_checkpoint_id: u64,
    anchor_seed: parth_common::realm_rotation::RotationAnchorSeed,
    rotation: &RealmRotationConfig,
    proposer_edge_node_ids: &HashMap<u16, NodeId>,
) -> anyhow::Result<Option<(u16, NodeId)>> {
    if !rotation.is_enabled() {
        return Ok(None);
    }
    let proposer = rotation
        .proposer_sub_id(realm_id, target_checkpoint_id, anchor_seed)?
        .ok_or_else(|| anyhow::anyhow!(
            "rotation enabled but proposer_sub_id returned None for realm {} target {}",
            realm_id,
            target_checkpoint_id,
        ))?;
    let dest = proposer_edge_node_ids
        .get(&proposer)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("no edge NodeId for scheduled proposer sub_id {proposer}"))?;
    if dest == local_edge_node_id {
        return Ok(None);
    }
    Ok(Some((proposer, dest)))
}


impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        UserUpdateQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync,
        ProofStore: QParthProofStore,
    > RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    pub async fn ensure_contract_heights_in_cache(&self, contract_ids: &[u32]) -> anyhow::Result<()> {
        // TODO: make this actually work in the db
        let mut contract_heights_to_fetch = Vec::new();
        for &contract_id in contract_ids {
            let cached_height = self
                .contract_state_tree_height_cache
                .mapping
                .get(&contract_id)
                .map(|entry| entry.value().0);
            if cached_height.is_none() || cached_height == Some(0) {
                contract_heights_to_fetch.push(contract_id as u64);
            }
        }
        if contract_heights_to_fetch.is_empty() {
            return Ok(());
        } else {
            let height = self
                .db_reader
                .get_contract_tree_heights(MAX_CHECKPOINT_ID, &contract_heights_to_fetch)
                .await?;

            for (&height, &contract_id) in height.iter().zip(contract_heights_to_fetch.iter()) {
                anyhow::ensure!(
                    height > 0,
                    "contract {} state tree height metadata is not available in Realm DB yet",
                    contract_id
                );
                self.contract_state_tree_height_cache
                    .add_contract(contract_id as u32, height, N::HasherBase::get_zero_hash(height as usize));
            }
        }
        Ok(())
    }

    pub async fn contract_state_tree_height(&self, contract_id: u32) -> anyhow::Result<u8> {
        self.ensure_contract_heights_in_cache(&[contract_id]).await?;
        self.contract_state_tree_height_cache.get_contract_height(contract_id)
    }

    fn build_user_end_cap_slot_updates(
        &self,
        unique_pending_id: u64,
        user_id: u64,
        user_end_cap_input: &SubmitUserEndCapNonProofInput<N::F, N::QHash>,
    ) -> anyhow::Result<RealmEndCapSlotUpdates> {
        let contracts = user_end_cap_input
            .get_slot_updates()?
            .into_iter()
            .map(|contract| RealmContractSlotUpdates {
                contract_id: contract.contract_id,
                slot_updates: contract
                    .slot_updates
                    .into_iter()
                    .map(|slot_update| RealmSlotUpdate {
                        slot: slot_update.slot,
                        old_value: slot_update.old_value.to_u64_value(),
                        new_value: slot_update.new_value.to_u64_value(),
                    })
                    .collect(),
            })
            .filter(|contract| !contract.slot_updates.is_empty())
            .collect();

        let accepted_user_leaf_hash = user_end_cap_input
            .core
            .new_user_leaf
            .qfhash::<N::HasherBase>()
            .to_4_felts()
            .map(|felt| felt.to_u64_value());
        Ok(RealmEndCapSlotUpdates {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_pending_id,
            user_id,
            contracts,
            accepted_user_leaf_hash: Some(accepted_user_leaf_hash),
        })
    }

    pub async fn get_user_end_cap_slot_updates_internal(
        &self,
        unique_pending_id: u64,
        user_id: u64,
    ) -> anyhow::Result<Option<RealmEndCapSlotUpdates>> {
        let Some(bytes) = self
            .temp_db
            .get_user_end_cap_slot_updates(&self.realm_identifier, unique_pending_id, user_id)
            .await?
        else {
            return Ok(None);
        };

        let payload = bincode::deserialize(&bytes)?;
        Ok(Some(payload))
    }

    pub async fn handle_user_end_cap_proof_submission(
        &self,
        user_end_cap_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>,
        proof_bytes: Vec<u8>,
        forwarded_target: Option<u64>,
    ) -> anyhow::Result<()>
    where
        N::ZKVerifier: 'static,
        N::ZKProof: 'static,
    {
        let mut timer = DebugTimer::new("handle_user_end_cap_proof_submission");
        let generation = self.temp_db.get_gathering_generation(&self.realm_identifier).await?;
        let target = end_cap_generation_target(generation)?;
        let destination = if let Some(header_target) = forwarded_target {
            self.ensure_local_is_scheduled_end_cap_receiver(header_target, generation).await?;
            None
        } else {
            self.scheduled_proposer_dest(target).await?
        };
        match destination {
            Some((proposer, dest)) => {
                self.forward_end_cap_to_scheduled_proposer(&user_end_cap_input, proof_bytes, proposer, dest, target).await
            }
            None => self.verify_and_persist_end_cap(user_end_cap_input, proof_bytes, generation, &mut timer).await,
        }
    }

    async fn verify_and_persist_end_cap(
        &self,
        user_end_cap_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>,
        proof_bytes: Vec<u8>,
        generation: GatheringGeneration,
        timer: &mut DebugTimer,
    ) -> anyhow::Result<()>
    where
        N::ZKVerifier: 'static,
        N::ZKProof: 'static,
    {

        let end_cap_checkpoint_id = user_end_cap_input.core.checkpoint_id.to_u64_value();

        let secondary_end_cap_checkpoint_id = user_end_cap_input.core.new_user_leaf.last_checkpoint_id.to_u64_value();
        if end_cap_checkpoint_id != secondary_end_cap_checkpoint_id {
            anyhow::bail!(
                "end cap checkpoint id {} does not match new_user_leaf last_checkpoint_id {}",
                end_cap_checkpoint_id,
                secondary_end_cap_checkpoint_id
            );
        }
        let user_id: u64 = user_end_cap_input.core.state_transition.user_id.to_u64_value();
        if !self.user_belongs_to_realm(user_id) {
            anyhow::bail!("user_id {} does not belong to this realm", user_id);
        }
        if user_end_cap_input.contract_state_updates.is_empty() {
            anyhow::bail!("invalid end cap updates: contract_state_updates cannot be empty");
        }

        let unique_pending_id = generation.unique_pending_id;
        timer.lap_micros("get_gathering_generation");
        self.ensure_user_has_not_submitted(user_id, unique_pending_id).await?;
        timer.lap_micros("ensure_user_has_not_submitted");

        let current_checkpoint_id = generation.checkpoint_id;
        let global_user_tree_proof = self.db_reader.global_user_tree_get_merkle_proof(current_checkpoint_id, user_id).await?;

        timer.lap_micros("global_user_tree_get_merkle_proof_at_gathering_checkpoint");
        let old_user_leaf = self.get_user_leaf_data_internal(current_checkpoint_id, user_id).await?;
        timer.lap_micros("get_user_leaf_data_internal");
        let user_last_checkpoint_id = old_user_leaf.last_checkpoint_id.to_u64_value();

        if user_last_checkpoint_id!= 0 && user_last_checkpoint_id > secondary_end_cap_checkpoint_id {
            anyhow::bail!(
                "Submitted end cap for checkpoint {}, but user's last checkpoint is {}",
                end_cap_checkpoint_id,
                user_last_checkpoint_id
            );
        }

        if end_cap_checkpoint_id > current_checkpoint_id {
            anyhow::bail!(
                "Submitted end cap for checkpoint {}, but current checkpoint is {}",
                end_cap_checkpoint_id,
                current_checkpoint_id
            );
        }

        let old_leaf_hash = if 
            global_user_tree_proof.value == N::QHash::get_zero_value()
        {
            N::QHash::get_zero_value()
        }else{
            old_user_leaf.qfhash::<N::HasherBase>()
        };
        
        ensure_start_user_leaf_hash(
            &user_end_cap_input.core.state_transition.start_user_leaf_hash,
            &old_leaf_hash,
        )?;

        let checkpoint_tree_proof: MerkleProofCore<N::QHash> = self
            .db_reader
            .checkpoint_tree_get_merkle_proof(current_checkpoint_id, end_cap_checkpoint_id)
            .await?;
        timer.lap_micros("checkpoint_tree_get_merkle_proof");

        let historical_root = checkpoint_tree_proof.get_append_root::<N::HasherBase>();
        if historical_root != user_end_cap_input.core.state_transition.checkpoint_tree_root_hash {
            anyhow::bail!(
                "Invalid checkpoint tree proof historical root, left: {:?}, right: {:?}",
                historical_root,
                user_end_cap_input.core.state_transition.checkpoint_tree_root_hash
            );
        }

        self.ensure_user_has_not_submitted(user_id, unique_pending_id).await?;
        timer.lap_micros("ensure_user_has_not_submitted (2)");

        let expected_public_inputs_hash: N::QHash = user_end_cap_input
            .core
            .get_proof_public_inputs_hash::<N::HasherBase>(N::GLOBAL_USER_TREE_HEIGHT);
        let proof = N::ZKVerifier::try_proof_from_slice(&proof_bytes)?;

        let public_inputs = N::ZKVerifier::get_proof_public_inputs_hash(&proof)?;
        if public_inputs != expected_public_inputs_hash {
            anyhow::bail!(
                "Public inputs hash mismatch: expected {:?}, got {:?}",
                expected_public_inputs_hash,
                public_inputs
            );
        }
        let mut contract_ids = user_end_cap_input
            .contract_state_updates
            .iter()
            .map(|x| x.user_contract_tree_update_proof.index as u32)
            .collect::<Vec<u32>>();
        contract_ids.sort_unstable();
        contract_ids.dedup();
        self.ensure_contract_heights_in_cache(&contract_ids).await?;
        timer.lap_micros("ensure_contract_heights_in_cache");

        user_end_cap_input.ensure_simple_self_consistent::<N::HasherBase, _>(
            &old_user_leaf,
            public_inputs,
            &self.contract_state_tree_height_cache,
            N::GLOBAL_USER_TREE_HEIGHT,
            N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
        )?;
        timer.lap_micros("ensure_simple_self_consistent");

        let proof_verifier = self.proof_verifier.clone();
        task::spawn_blocking(move || {
            proof_verifier.verify_zk_proof(END_CAP_PROOF_CIRCUIT_TYPE_U32, &proof)
        }).await??;
        timer.lap_micros("verify_zk_proof");

        // Verification may span rotations; never persist into a generation other
        // than the one whose scheduled proposer admitted this EndCap.
        with_end_cap_gathering_generation(
            generation,
            || self.temp_db.get_gathering_generation(&self.realm_identifier),
            |generation| async move {
                self.store_end_cap_for_processing(
                    timer,
                    user_end_cap_input,
                    proof_bytes,
                    user_id,
                    old_leaf_hash,
                    generation,
                )
                .await
            },
        )
        .await
    }

    async fn forward_end_cap_to_scheduled_proposer(
        &self,
        user_end_cap_input: &SubmitUserEndCapNonProofInput<N::F, N::QHash>,
        proof_bytes: Vec<u8>,
        proposer: u16,
        dest: NodeId,
        target: u64,
    ) -> anyhow::Result<()> {
        let cmds = self
            .p2p
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Realm edge P2P commands are missing"))?;
        let input = user_end_cap_input.psy_ser_to_bytes_vec()?;
        let input_hash = sha256(&input);
        let proof_hash = sha256(&proof_bytes);
        let end_cap_id = compute_end_cap_id(
            self.chain_id,
            self.realm_id_u64 as u32,
            target,
            &input_hash,
            &proof_hash,
        );
        let header = EndCapForwardHeader {
            chain_id: self.chain_id,
            realm_id: self.realm_id_u64 as u32,
            checkpoint_id: target,
            end_cap_id,
            end_cap_input_len: input.len() as u32,
            proof_len: proof_bytes.len() as u32,
        };
        let resp = cmds
            .forward_end_cap(dest, header.clone(), input, proof_bytes)
            .await
            .map_err(|e| anyhow::anyhow!("EndCap forward to proposer {proposer} failed: {e}"))?;
        if !resp.is_accepted() {
            return Err(match resp.reject_reason() {
                // Re-raise the exact -32001 surface the direct submission path
                // produces, so provider-side duplicate recovery downcasts.
                EndCapRejectReason::AlreadySubmitted => {
                    let (user_id, unique_pending_id) = resp.identity();
                    anyhow::Error::new(EndCapSubmitError::AlreadySubmitted {
                        user_id,
                        unique_pending_id,
                    })
                }
                reason => anyhow::anyhow!(
                    "EndCap forward rejected by proposer {proposer} (reason {reason:?})"
                ),
            });
        }
        tracing::info!(
            "realm P2P EndCap forwarded end_cap_id={} proposer_sub_id={} dest={:?}",
            hex::encode(header.end_cap_id),
            proposer,
            dest
        );
        Ok(())
    }

    async fn store_end_cap_for_processing(
        &self,
        timer: &mut DebugTimer,
        user_end_cap_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>,
        proof_bytes: Vec<u8>,
        user_id: u64,
        old_leaf_hash: N::QHash,
        generation: GatheringGeneration,
    ) -> anyhow::Result<()> {
        let GatheringGeneration { unique_pending_id, proc_checkpoint_unique_id: proc_checkpoint_id, .. } = generation;
        let job_id = QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            user_id, N::GLOBAL_USER_TREE_HEIGHT, unique_pending_id,
        )?;
        // Only fills the QBlob context checkpoint placeholder (not a real checkpoint).
        let submission_token = rand::random::<u64>();
        let context = QBlobWriterContextMetadataHeader::new_at_now(
            self.chain_id,
            self.node_id,
            self.realm_id_u64,
            self.realm_sub_id_u64,
            unique_pending_id,
            submission_token,
            user_id,
        );
        let contract_update_data_for_user =
            validate_end_cap_and_generate_node_data_for_edge::<N::F, N::QHash, N::HasherBase>(&context, user_id, &user_end_cap_input)?;
        if !self
            .temp_db
            .put_submitted_status_if_absent(
                &self.realm_identifier,
                unique_pending_id,
                user_id,
                submission_token,
            )
            .await?
        {
            return Err(anyhow::Error::new(EndCapSubmitError::AlreadySubmitted {
                user_id,
                unique_pending_id,
            }));
        }
        timer.lap_micros("put_submitted_status_if_absent");

        self.proof_store
            .put_proof_bytes_for_job_id(job_id, unique_pending_id, &proof_bytes)
            .await?;
        timer.lap_micros("put_proof_bytes_for_job_id");

        let slot_updates_payload = match self.build_user_end_cap_slot_updates(
            unique_pending_id,
            user_id,
            &user_end_cap_input,
        ) {
            Ok(payload) => Some(payload),
            Err(err) => {
                tracing::warn!(
                    user_id,
                    unique_pending_id,
                    error = ?err,
                    "Failed to extract user end-cap slot updates"
                );
                None
            }
        };

        self.temp_db
            .set_contract_updates_for_user(&self.realm_identifier, unique_pending_id, user_id, contract_update_data_for_user)
            .await?;
        timer.lap_micros("set_contract_updates_for_user");

        if let Some(slot_updates_payload) = slot_updates_payload {
            if !slot_updates_payload.contracts.is_empty() {
                match bincode::serialize(&slot_updates_payload) {
                    Ok(bytes) => {
                        if let Err(err) = self
                            .temp_db
                            .set_user_end_cap_slot_updates(
                                &self.realm_identifier,
                                unique_pending_id,
                                user_id,
                                bytes,
                            )
                            .await
                        {
                            tracing::warn!(
                                user_id,
                                unique_pending_id,
                                error = ?err,
                                "Failed to store user end-cap slot updates"
                            );
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            user_id,
                            unique_pending_id,
                            error = ?err,
                            "Failed to serialize user end-cap slot updates"
                        );
                    }
                }
            }
        }
        timer.lap_micros("set_user_end_cap_slot_updates");

        let queue_key = RealmUserUpdateQueueKey {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: proc_checkpoint_id,
            task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let new_user_leaf = user_end_cap_input.core.new_user_leaf.clone();
        let new_user_leaf_hash = new_user_leaf.qfhash::<N::HasherBase>();

        let queue_item = PsyRealmUserUpdateQueueItem {
            job_id: job_id,
            submission_nonce: submission_token,
            old_user_leaf_hash: old_leaf_hash,
            new_user_leaf_hash,
            new_user_leaf,
            stats: user_end_cap_input.core.stats,
            events: user_end_cap_input.events,
        };

        self.user_update_queue.ensure_consumer(
            &queue_key,
            self.realm_id_u64,
            self.realm_sub_id_u64,
            proc_checkpoint_id,
            0,
        ).await?;

        ensure_end_cap_generation_unchanged(
            generation,
            self.temp_db.get_gathering_generation(&self.realm_identifier).await?,
        )?;

        self.user_update_queue
            .publish_ephemeral_queue_item_owned(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, proc_checkpoint_id, 0, queue_item)
            .await?;
        timer.lap_micros("publish_ephemeral_queue_item_owned");
        timer.lap_group("handle_user_end_cap_proof_submission total");

        Ok(())
    }

}
type QRpcResult<T> = RpcResult<T>;

fn res<T>(data: anyhow::Result<T>) -> QRpcResult<T> {
    Ok(data.map_err(RpcError::Anyhow)?)
}

const MAX_CHECKPOINT_ID: u64 = i64::MAX as u64;

#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        UserUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
    > RealmEdgeRpcServer<N::F, N::QHash, N::JobId, N::ZKProof>
    for RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    /// Check if a user id belongs to this realm

    async fn get_latest_checkpoint_id(&self) -> RpcResult<u64> {
        res(self.get_latest_checkpoint_id().await)
    }
    async fn get_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> RpcResult<Option<u64>> {
        res(self.get_checkpoint_id_for_unique_pending_id_internal(unique_pending_id).await)
    }
    async fn get_unique_pending_id_for_checkpoint_id(&self, checkpoint_id: u64) -> RpcResult<Option<(u64, u128)>> {
        res(self.db_reader.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await)
    }
    async fn get_user_end_cap_slot_updates(
        &self,
        unique_pending_id: u64,
        user_id: u64,
    ) -> RpcResult<Option<RealmEndCapSlotUpdates>> {
        res(self
            .get_user_end_cap_slot_updates_internal(unique_pending_id, user_id)
            .await)
    }
    async fn get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(&self, checkpoint_id: u64) -> RpcResult<TagTreeMerkleProof<N::QHash>> {
        res(self.get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id_internal(checkpoint_id).await)
    }
    async fn get_contract_tree_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> RpcResult<Vec<u8>>{
        let result = self
            .db_reader
            .get_contract_tree_heights(checkpoint_id, &contract_ids)
            .await;
        if result.is_err() {
            tracing::error!("Error getting contract tree state heights");

        } else {
            //println!("Got contract tree state heights for checkpoint_id {}: {:?}", checkpoint_id, result.as_ref().unwrap());
            //tracing::info!("Got contract tree state heights for checkpoint_id {}", checkpoint_id);
        }
        res(result)

    }
    async fn check_user_id_in_realm(&self, user_id: u64) -> QRpcResult<bool> {
        let users_per_realm = 1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;
        let min_user_id = self.realm_id_u64 * users_per_realm;
        let max_user_id = min_user_id + users_per_realm;
        Ok(user_id >= min_user_id && user_id < max_user_id)
    }

    /// Submit user end cap proof

    async fn get_user_contract_state_tree_nodes(
        &self,
        checkpoint_id: u64,
        keys: Vec<QMerkleStoreDoubleIdKeyWithHeight>,
    ) -> RpcResult<Vec<N::QHash>>{
        res(self
            .db_reader
            .contract_state_tree_get_nodes(checkpoint_id, &keys)
            .await  )
    }

    async fn get_user_contract_tree_nodes(
        &self,
        checkpoint_id: u64,
        keys: Vec<QMerkleStoreSingleIdKey>,
    ) -> RpcResult<Vec<N::QHash>>{
        res(self
            .db_reader
            .user_contract_tree_get_nodes(checkpoint_id, &keys)
            .await
        )

    }

    async fn submit_user_end_cap(&self, user_ec_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>, proof: Vec<u8>) -> QRpcResult<String> {
        res(self.handle_user_end_cap_proof_submission(user_ec_input, proof, None).await)?;
        Ok("ok".to_string())
    }

    async fn submit_user_end_cap_batch(
        &self,
        requests: Vec<(SubmitUserEndCapNonProofInput<N::F, N::QHash>, Vec<u8>)>,
    ) -> QRpcResult<(Vec<u64>, Vec<u64>)> {
        let results: Vec<(u64, bool)> = stream::iter(requests.into_iter().map(|(user_ec_input, proof)| async move {
            let user_id: u64 = user_ec_input.core.state_transition.user_id.to_u64_value();
            match self.handle_user_end_cap_proof_submission(user_ec_input, proof, None).await {
                Ok(_) => (user_id, true),
                Err(err) => {
                    tracing::warn!("Failed to handle user end cap proof submission for user_id {}: {}", user_id, err);
                    (user_id, false)
                }
            }
        }))
        .buffered(16)
        .collect()
        .await;

        let mut failed_user_ids = vec![];
        let mut success_user_ids = vec![];
        for (user_id, success) in results {
            if success {
                success_user_ids.push(user_id);
            } else {
                failed_user_ids.push(user_id);
            }
        }
        Ok((success_user_ids, failed_user_ids))
    }

    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> QRpcResult<PQEDCheckpointLeaf<N::F, N::QHash>> {
        res(self.db_reader.get_checkpoint_leaf_data(checkpoint_id).await)
    }

    async fn get_job_stats(&self, checkpoint_id: u64) -> QRpcResult<CheckpointJobStats> {
        res(self.get_job_stats_internal(checkpoint_id).await)
    }

    async fn get_latest_l2_block_state(&self) -> QRpcResult<QEDL2BlockState> {
        res(self.db_reader.get_latest_l2_block_state().await)
    }

    async fn get_l2_block_state(&self, checkpoint_id: u64) -> QRpcResult<QEDL2BlockState> {
        res(self.db_reader.get_l2_block_state(checkpoint_id).await)
    }

    async fn get_latest_checkpoint_tree_root(&self) -> QRpcResult<N::QHash> {
        res(self.db_reader.checkpoint_tree_get_root_hash(MAX_CHECKPOINT_ID).await)
    }

    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.checkpoint_tree_get_root_hash(checkpoint_id).await)
    }

    async fn get_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.checkpoint_tree_get_leaf_hash(checkpoint_id, leaf_checkpoint_id).await)
    }

    async fn get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self.db_reader.checkpoint_tree_get_merkle_proof(checkpoint_id, leaf_checkpoint_id).await)
    }

    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> QRpcResult<PQEDCheckpointGlobalStateRoots<N::QHash>> {
        res(self.db_reader.get_checkpoint_global_state_roots(checkpoint_id).await)
    }

    async fn get_user_leaf_data(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<PQEDUserLeaf<N::F, N::QHash>> {
        res(self.get_user_leaf_data_internal(checkpoint_id, user_id).await)
    }
    async fn get_user_leaves_batch(
        &self,
        checkpoint_id: u64,
        user_ids: Vec<u64>,
    ) -> RpcResult<Vec<PQEDUserLeaf<N::F, N::QHash>>>{
        res(self.get_user_leaves_data_internal(checkpoint_id, &user_ids).await)
    }
    async fn get_user_tree_leaf_hashes(
        &self,
        checkpoint_id: u64,
        user_ids: Vec<u64>,
    ) -> RpcResult<Vec<N::QHash>>{
        res(self
            .db_reader
            .global_user_tree_get_nodes(checkpoint_id, &user_ids.into_iter().map(|id| SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, id)).collect::<Vec<_>>())
            .await)
    }
    async fn get_user_contract_state_tree_root(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> QRpcResult<N::QHash> {
        let height = self.contract_state_tree_height(contract_id).await.map_err(RpcError::Anyhow)?;
        res(self
            .db_reader
            .contract_state_tree_get_root_hash(checkpoint_id, user_id, contract_id as u64, height)
            .await)
    }

    async fn get_user_contract_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        leaf_id: u64,
    ) -> QRpcResult<N::QHash> {
        let height = res(self.contract_state_tree_height(contract_id).await)?;
        res(self
            .db_reader
            .contract_state_tree_get_leaf_hash(checkpoint_id, user_id, contract_id as u64, height, leaf_id)
            .await)
    }

    async fn get_user_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        leaf_id: u64,
    ) -> QRpcResult<MerkleProofCore<N::QHash>> {
        let height = res(self.contract_state_tree_height(contract_id).await)?;
        tracing::warn!(
            checkpoint_id,
            user_id,
            contract_id,
            height,
            leaf_id,
            "[CONTRACT_HEIGHT_DEBUG] serving user contract state proof"
        );
        res(self
            .db_reader
            .contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64, height, leaf_id)
            .await)
    }

    async fn get_user_contract_tree_root(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.user_contract_tree_get_root_hash(checkpoint_id, user_id).await)
    }

    async fn get_user_contract_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> QRpcResult<N::QHash> {
        res(self
            .db_reader
            .user_contract_tree_get_leaf_hash(checkpoint_id, user_id, contract_id as u64)
            .await)
    }

    async fn get_user_contract_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .user_contract_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64)
            .await)
    }

    async fn get_user_tree_root(&self, checkpoint_id: u64) -> QRpcResult<N::QHash> {
        // Exact checkpoint spine / metadata root — never sparse global_user_tree max-lookup.
        res(async {
            let top = self
                .db_reader
                .get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(checkpoint_id)
                .await?;
            Ok(top.root)
        }
        .await)
    }

    async fn get_user_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.global_user_tree_get_leaf_hash(checkpoint_id, user_id).await)
    }

    async fn get_user_bottom_tree_merkle_proof(&self, root_level: u8, checkpoint_id: u64, user_id: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(async {
            ensure_user_subtree_request_within_realm(
                root_level,
                N::GLOBAL_USER_TREE_HEIGHT,
                N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            )?;
            self.db_reader
                .global_user_tree_get_merkle_proof_sub_tree(checkpoint_id, root_level, N::GLOBAL_USER_TREE_HEIGHT, user_id)
                .await
        }
        .await)
    }

    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(async {
            ensure_user_subtree_request_within_realm(
                root_level,
                leaf_level,
                N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            )?;
            self.db_reader
                .global_user_tree_get_merkle_proof_sub_tree(checkpoint_id, root_level, leaf_level, leaf_index)
                .await
        }
        .await)
    }

    async fn get_user_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        // Compose local sparse subtree + exact authenticated top spine (aaed92d6 pattern).
        res(async {
            let (proof, _) =
                validator_user_tree_proofs::<N, _>(self.db_reader.as_ref(), checkpoint_id, user_id, self.realm_id_u64).await?;
            Ok(proof)
        }
        .await)
    }

    async fn generate_batch_proof_miner_reward_proofs(
        &self,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath<N::JobId>>,
    ) -> QRpcResult<Vec<PsyProoffMinerRewardProof<N::QHash, N::JobId>>> {
        res(self.generate_batch_proof_miner_reward_proofs_internal(unique_pending_id, job_ids).await)
    }

    // IMT endpoints

    async fn get_imt_leaf_preimage(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        leaf_index: u64,
    ) -> QRpcResult<IMTContractStateLeaf<N::F, N::QHash>> {
        res(res(self
            .db_reader
            .contract_state_imt_get_leaf_preimage(checkpoint_id, user_id, contract_id as u64, leaf_index)
            .await.transpose().ok_or(anyhow::format_err!("Leaf preimage not found at index {}", leaf_index)))?)
    }

    async fn get_imt_leaf_index_for_key(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: N::QHash,
    ) -> QRpcResult<u64> {
        res(res(self
            .db_reader
            .contract_state_imt_get_leaf_index_for_key(checkpoint_id, user_id, contract_id as u64, &key)
            .await.transpose().ok_or(anyhow::format_err!("Key not found in IMT")))?)
    }

    async fn get_imt_membership_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: N::QHash,
        state_slot_base: u64,
        capacity: u64,
    ) -> QRpcResult<IMTMembershipProof<N::F, N::QHash>> {
        let height = self.contract_state_tree_height(contract_id).await.map_err(RpcError::Anyhow)?;
        let min = state_slot_base.checked_add(1).ok_or_else(|| RpcError::Anyhow(anyhow::anyhow!("IMT range overflow")))?;
        let max = state_slot_base.checked_add(capacity).ok_or_else(|| RpcError::Anyhow(anyhow::anyhow!("IMT range overflow")))?;
        if capacity == 0 || height < 64 && max >= (1u64 << height) {
            return Err(RpcError::Anyhow(anyhow::anyhow!("IMT map outside contract state tree")).into());
        }
        // Get the leaf index for the key
        let leaf_index = self
            .db_reader
            .contract_state_imt_get_leaf_index_for_key(checkpoint_id, user_id, contract_id as u64, &key)
            .await
            .map_err(RpcError::Anyhow)?
            .ok_or_else(|| RpcError::Anyhow(anyhow::anyhow!("Key not found in IMT")))?;
        if !(min..=max).contains(&leaf_index) {
            return Err(RpcError::Anyhow(anyhow::anyhow!("IMT membership leaf outside requested map")).into());
        }

        // Get the leaf preimage
        let leaf = self
            .db_reader
            .contract_state_imt_get_leaf_preimage(checkpoint_id, user_id, contract_id as u64, leaf_index)
            .await
            .map_err(RpcError::Anyhow)?
            .ok_or_else(|| RpcError::Anyhow(anyhow::anyhow!("Leaf preimage not found at index {}", leaf_index)))?;
        let next_index = leaf.next_index.to_u64_value();
        if leaf.key != key || next_index != 0 && !(min..=max).contains(&next_index) {
            return Err(RpcError::Anyhow(anyhow::anyhow!("IMT key or successor outside requested map")).into());
        }

        // Get the merkle proof for the leaf's position in the tree
        let merkle_proof = self
            .db_reader
            .contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64, height, leaf_index)
            .await
            .map_err(RpcError::Anyhow)?;
        if merkle_proof.index != leaf_index {
            return Err(RpcError::Anyhow(anyhow::anyhow!("IMT membership proof index mismatch")).into());
        }

        Ok(IMTMembershipProof {
            leaf,
            merkle_proof,
        })
    }

    async fn get_imt_non_membership_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: N::QHash,
    ) -> QRpcResult<IMTNonMembershipProof<N::F, N::QHash>> {
        let height = self.contract_state_tree_height(contract_id).await.map_err(RpcError::Anyhow)?;
        // Find the predecessor leaf
        let (predecessor_index, predecessor_leaf) = self
            .db_reader
            .contract_state_imt_find_predecessor(checkpoint_id, user_id, contract_id as u64, &key)
            .await
            .map_err(RpcError::Anyhow)?;

        // Get the merkle proof for the predecessor's position
        let merkle_proof = self
            .db_reader
            .contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64, height, predecessor_index)
            .await
            .map_err(RpcError::Anyhow)?;

        Ok(IMTNonMembershipProof {
            predecessor_leaf,
            merkle_proof,
        })
    }

    async fn get_imt_predecessor_info(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: N::QHash,
    ) -> QRpcResult<IMTPredecessorResult<N::F, N::QHash>> {
        let height = self.contract_state_tree_height(contract_id).await.map_err(RpcError::Anyhow)?;
        // Find predecessor leaf
        let (predecessor_index, predecessor_leaf) = self
            .db_reader
            .contract_state_imt_find_predecessor(checkpoint_id, user_id, contract_id as u64, &key)
            .await
            .map_err(RpcError::Anyhow)?;

        // Get merkle proof for predecessor
        let predecessor_merkle_proof = self
            .db_reader
            .contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64, height, predecessor_index)
            .await
            .map_err(RpcError::Anyhow)?;

        // Get next append index
        let next_append_index = self
            .db_reader
            .contract_state_imt_get_next_append_index(user_id, contract_id as u64)
            .await
            .map_err(RpcError::Anyhow)?;

        Ok(IMTPredecessorResult {
            predecessor_leaf_index: predecessor_index,
            predecessor_leaf,
            predecessor_merkle_proof,
            next_append_index,
        })
    }

    async fn find_imt_predecessor(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: N::QHash,
    ) -> QRpcResult<(u64, IMTContractStateLeaf<N::F, N::QHash>)> {
        res(self
            .db_reader
            .contract_state_imt_find_predecessor(checkpoint_id, user_id, contract_id as u64, &key)
            .await)
    }

    async fn get_imt_next_append_index(&self, user_id: u64, contract_id: u64) -> QRpcResult<u64> {
        res(self
            .db_reader
            .contract_state_imt_get_next_append_index(user_id, contract_id as u64)
            .await)
    }
}

#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + Send + Sync + 'static,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        UserUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
    > NodeEdgeWorkerRpcServer<N::QHash, N::JobId>
    for RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    async fn get_proving_work(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> RpcResult<PsyWorkerGetProvingWorkAPIResponse<N::QHash, N::JobId>> {
        res(self.get_proving_work_internal(signature, request).await)
    }
    async fn get_proving_work_with_child_proofs(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> RpcResult<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<N::QHash, N::JobId>> {
        res(self.get_proving_work_with_child_proofs_internal(signature, request).await)
    }
    async fn submit_proof_raw(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
        job_id: N::JobId,
        tag: N::QHash,
        proof: Vec<u8>,
    ) -> RpcResult<()> {
        res(self.submit_proof_raw_internal(signature, request, job_id, tag, proof).await)
    }
    async fn get_realm_identifier_worker_api(&self) -> RpcResult<QRealmIdentifier> {
        Ok(self.realm_identifier.clone())
    }

    async fn get_node_proving_state(&self) -> RpcResult<PsyNodeProvingState>{
        res(self.temp_db.get_psy_node_proving_state(&self.realm_identifier).await)
    }

    async fn get_worker_reputation(&self, public_key: Vec<u8>) -> RpcResult<u64> {
        let key: [u8; 33] = public_key
            .try_into()
            .map_err(|_| RpcError::InvalidInput("public_key must be 33 bytes (compressed secp256k1)".to_string()))?;
        res(self.get_worker_reputation_internal(&key).await)
    }
}

#[cfg(test)]
mod inline_tests {
    use super::*;
    use libp2p_identity::Keypair;
    use parth_core::PHash;

    /// The localhost network magic, sourced from the network config via the
    /// psy_core build-time constants. A full u64 that does not fit in u32, so
    /// any u32 truncation would break these tests.
    const TEST_CHAIN_ID: u64 = psy_core::constants::chain_id::PSY_CHAIN_ID_LOCAL_DEVNET;
    const TEST_REALM_ID: u32 = 3;

    fn generation() -> GatheringGeneration {
        GatheringGeneration {
            checkpoint_id: 24,
            unique_pending_id: 42,
            proc_checkpoint_unique_id: parth_core::QCoreProcCheckpointUniqueId::from(97u128),
        }
    }

    #[tokio::test]
    async fn end_cap_rotation_between_verification_and_store_rejects_before_writes() {
        use std::cell::Cell;
        let admitted = generation();
        let rotated = GatheringGeneration { checkpoint_id: 25, ..admitted };
        let wrote = Cell::new(false);
        let result = with_end_cap_gathering_generation(
            admitted,
            || std::future::ready(Ok(rotated)),
            |_| async { wrote.set(true); Ok(()) },
        ).await;
        assert!(result.is_err());
        assert!(!wrote.get());
    }

    #[tokio::test]
    async fn end_cap_checkpoint_only_rotation_inside_publish_rejects_delivery() {
        use std::cell::Cell;
        let admitted = generation();
        let gathering = Cell::new(admitted);
        let result = with_end_cap_gathering_generation(
            admitted,
            || std::future::ready(Ok(gathering.get())),
            |_| async {
                gathering.set(GatheringGeneration { checkpoint_id: 25, ..admitted });
                Ok(())
            },
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn end_cap_store_publish_failure_is_not_acknowledged() {
        let admitted = generation();
        let result = with_end_cap_gathering_generation(
            admitted,
            || std::future::ready(Ok(admitted)),
            |_| async { anyhow::bail!("consumer unavailable") },
        ).await;
        assert!(result.is_err());
    }

    #[test]
    fn end_cap_generation_compares_every_identity_field() {
        let stored = generation();
        ensure_end_cap_generation_unchanged(stored, stored).unwrap();
        for rotated in [
            GatheringGeneration { checkpoint_id: 25, ..stored },
            GatheringGeneration { unique_pending_id: 43, ..stored },
            GatheringGeneration { proc_checkpoint_unique_id: parth_core::QCoreProcCheckpointUniqueId::from(103u128), ..stored },
        ] {
            assert!(ensure_end_cap_generation_unchanged(stored, rotated).is_err());
        }
    }

    #[test]
    fn forwarded_header_must_match_current_generation_target() {
        let current = generation();
        assert_eq!(ensure_forwarded_end_cap_target(25, current).unwrap(), 25);
        assert!(ensure_forwarded_end_cap_target(24, current).is_err());
        assert!(ensure_forwarded_end_cap_target(26, current).is_err());
        assert!(ensure_forwarded_end_cap_target(25, GatheringGeneration { checkpoint_id: 25, ..current }).is_err());
        assert!(end_cap_generation_target(GatheringGeneration { checkpoint_id: u64::MAX, ..current }).is_err());
    }

    /// Deterministic Ed25519 NodeId per seed byte.
    fn test_node(seed: u8) -> NodeId {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        let kp = Keypair::ed25519_from_bytes(&mut ikm)
            .expect("32-byte seed yields Ed25519 Keypair");
        NodeId::from_keypair(&kp).expect("ed25519 keypair yields NodeId")
    }

    fn build_validators(sub_ids: &[u16]) -> HashMap<u16, NodeId> {
        sub_ids
            .iter()
            .enumerate()
            .map(|(i, &sub_id)| (sub_id, test_node((i + 1) as u8)))
            .collect()
    }

    fn build_edge_identities(sub_ids: &[u16]) -> (HashMap<u16, NodeId>, HashSet<NodeId>) {
        let by_sub_id = build_validators(sub_ids);
        let all = by_sub_id.values().copied().collect();
        (by_sub_id, all)
    }

    fn end_cap_header(
        chain_id: u64,
        realm_id: u32,
        checkpoint_id: u64,
        input: &[u8],
        proof: &[u8],
    ) -> EndCapForwardHeader {
        let input_hash = sha256(input);
        let proof_hash = sha256(proof);
        EndCapForwardHeader {
            chain_id,
            realm_id,
            checkpoint_id,
            end_cap_id: compute_end_cap_id(chain_id, realm_id, checkpoint_id, &input_hash, &proof_hash),
            end_cap_input_len: input.len() as u32,
            proof_len: proof.len() as u32,
        }
    }

    fn sample_input_and_proof() -> (Vec<u8>, Vec<u8>) {
        (vec![0x11u8; 64], vec![0xABu8; 128])
    }

    #[test]
    fn validate_forwarded_end_cap_accepts_validator_source_with_matching_header() {
        let (validators, realm_edge_node_ids) = build_edge_identities(&[1, 2, 3]);
        let (input, proof) = sample_input_and_proof();
        let header = end_cap_header(TEST_CHAIN_ID, TEST_REALM_ID, 25, &input, &proof);
        let validated = validate_forwarded_end_cap(
            validators[&1],
            &header,
            &input,
            &proof,
            TEST_CHAIN_ID,
            TEST_REALM_ID,
            &realm_edge_node_ids,
        )
        .expect("validator source with matching header is accepted");
        assert_eq!(validated, header.end_cap_id);
    }

    #[test]
    fn compute_end_cap_id_round_trips_u64_chain_magic() {
        let (validators, realm_edge_node_ids) = build_edge_identities(&[1, 2, 3]);
        let (input, proof) = sample_input_and_proof();
        assert!(
            TEST_CHAIN_ID > u32::MAX as u64,
            "test magic must exercise the full u64 range"
        );
        // Round-trip: an EndCap id computed from the full u64 magic validates
        // against the same magic.
        let header = end_cap_header(TEST_CHAIN_ID, TEST_REALM_ID, 25, &input, &proof);
        let validated = validate_forwarded_end_cap(
            validators[&1],
            &header,
            &input,
            &proof,
            TEST_CHAIN_ID,
            TEST_REALM_ID,
            &realm_edge_node_ids,
        )
        .expect("u64 chain magic round-trips through compute_end_cap_id");
        assert_eq!(validated, header.end_cap_id);
        // The id must depend on the full u64: the magic truncated to u32
        // yields a different canonical hash.
        let truncated = compute_end_cap_id(
            TEST_CHAIN_ID as u32 as u64,
            TEST_REALM_ID,
            25,
            &sha256(&input),
            &sha256(&proof),
        );
        assert_ne!(header.end_cap_id, truncated);
    }

    #[test]
    fn validate_forwarded_end_cap_rejects_source_outside_validators() {
        let (_, realm_edge_node_ids) = build_edge_identities(&[1, 2, 3]);
        let (input, proof) = sample_input_and_proof();
        let header = end_cap_header(TEST_CHAIN_ID, TEST_REALM_ID, 25, &input, &proof);
        let forged = test_node(99);
        let err = validate_forwarded_end_cap(
            forged,
            &header,
            &input,
            &proof,
            TEST_CHAIN_ID,
            TEST_REALM_ID,
            &realm_edge_node_ids,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("forwarded EndCap source NodeId {forged} is not a Realm edge identity")
        );
    }

    #[test]
    fn validate_forwarded_end_cap_rejects_chain_id_mismatch() {
        let (validators, realm_edge_node_ids) = build_edge_identities(&[1, 2, 3]);
        let (input, proof) = sample_input_and_proof();
        // Keep the header internally consistent (end_cap_id over chain 8) so
        // only the chain_id check can fail.
        let header = end_cap_header(TEST_CHAIN_ID + 1, TEST_REALM_ID, 25, &input, &proof);
        let err = validate_forwarded_end_cap(
            validators[&1],
            &header,
            &input,
            &proof,
            TEST_CHAIN_ID,
            TEST_REALM_ID,
            &realm_edge_node_ids,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "forwarded EndCap chain_id {} does not match local {}",
                TEST_CHAIN_ID + 1,
                TEST_CHAIN_ID
            )
        );
    }

    #[test]
    fn validate_forwarded_end_cap_rejects_realm_id_mismatch() {
        let (validators, realm_edge_node_ids) = build_edge_identities(&[1, 2, 3]);
        let (input, proof) = sample_input_and_proof();
        let header = end_cap_header(TEST_CHAIN_ID, TEST_REALM_ID + 1, 25, &input, &proof);
        let err = validate_forwarded_end_cap(
            validators[&1],
            &header,
            &input,
            &proof,
            TEST_CHAIN_ID,
            TEST_REALM_ID,
            &realm_edge_node_ids,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "forwarded EndCap realm_id {} does not match local {}",
                TEST_REALM_ID + 1,
                TEST_REALM_ID
            )
        );
    }

    #[test]
    fn validate_forwarded_end_cap_rejects_input_length_mismatch() {
        let (validators, realm_edge_node_ids) = build_edge_identities(&[1, 2, 3]);
        let (input, proof) = sample_input_and_proof();
        let header = end_cap_header(TEST_CHAIN_ID, TEST_REALM_ID, 25, &input, &proof);
        let mut padded = input.clone();
        padded.push(0xEE);
        let err = validate_forwarded_end_cap(
            validators[&1],
            &header,
            &padded,
            &proof,
            TEST_CHAIN_ID,
            TEST_REALM_ID,
            &realm_edge_node_ids,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "forwarded EndCap input length {} does not match header {}",
                padded.len(),
                header.end_cap_input_len
            )
        );
    }

    #[test]
    fn validate_forwarded_end_cap_rejects_proof_length_mismatch() {
        let (validators, realm_edge_node_ids) = build_edge_identities(&[1, 2, 3]);
        let (input, proof) = sample_input_and_proof();
        let header = end_cap_header(TEST_CHAIN_ID, TEST_REALM_ID, 25, &input, &proof);
        let truncated = proof[..proof.len() - 1].to_vec();
        let err = validate_forwarded_end_cap(
            validators[&1],
            &header,
            &input,
            &truncated,
            TEST_CHAIN_ID,
            TEST_REALM_ID,
            &realm_edge_node_ids,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "forwarded EndCap proof length {} does not match header {}",
                truncated.len(),
                header.proof_len
            )
        );
    }

    #[test]
    fn validate_forwarded_end_cap_rejects_end_cap_id_mismatch() {
        let (validators, realm_edge_node_ids) = build_edge_identities(&[1, 2, 3]);
        let (input, proof) = sample_input_and_proof();
        let mut header = end_cap_header(TEST_CHAIN_ID, TEST_REALM_ID, 25, &input, &proof);
        header.end_cap_id = [0xFF; 32];
        let err = validate_forwarded_end_cap(
            validators[&1],
            &header,
            &input,
            &proof,
            TEST_CHAIN_ID,
            TEST_REALM_ID,
            &realm_edge_node_ids,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "forwarded EndCap id does not match canonical hash"
        );
    }

    #[test]
    fn ensure_start_user_leaf_hash_accepts_matching_hash() {
        let hash = PHash::ZERO;
        ensure_start_user_leaf_hash(&hash, &hash)
            .expect("matching start_user_leaf_hash is accepted");
    }

    #[test]
    fn ensure_start_user_leaf_hash_rejects_mismatch() {
        let supplied = PHash::ZERO;
        let expected = PHash::from_values(1, 2, 3, 4);
        let err = ensure_start_user_leaf_hash(&supplied, &expected).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("Invalid start_user_leaf_hash, left: {supplied:?}, right: {expected:?}")
        );
    }

    /// Rotation over sub-ids {1, 2, 3}; the scheduled proposer is whatever the
    /// canonical schedule picks for the given realm/checkpoint/seed.
    fn rotation_config() -> RealmRotationConfig {
        RealmRotationConfig {
            checkpoints_per_epoch: 10,
            validator_sub_ids: vec![1, 2, 3],
        }
    }

    fn scheduled_proposer(rotation: &RealmRotationConfig, target: u64) -> u16 {
        rotation
            .proposer_sub_id(TEST_REALM_ID, target, [1, 2, 3, 4])
            .expect("schedule")
            .expect("enabled rotation always schedules a proposer")
    }

    #[test]
    fn resolve_forward_dest_local_is_scheduled_proposer_does_not_forward() {
        let rotation = rotation_config();
        let validators = build_validators(&[1, 2, 3]);
        let proposer = scheduled_proposer(&rotation, 25);
        let dest = resolve_end_cap_forward_dest(
            TEST_REALM_ID,
            validators[&proposer],
            25,
            [1, 2, 3, 4],
            &rotation,
            &validators,
        )
        .expect("routing decision");
        assert!(
            dest.is_none(),
            "local instance is the scheduled proposer: keep local intake"
        );
    }

    #[test]
    fn resolve_forward_dest_non_proposer_routes_to_scheduled_proposer_node_id() {
        let rotation = rotation_config();
        let validators = build_validators(&[1, 2, 3]);
        let proposer = scheduled_proposer(&rotation, 25);
        let local_sub_id = rotation
            .validator_sub_ids
            .iter()
            .copied()
            .find(|&s| s != proposer)
            .expect("at least one other validator sub id");
        let dest = resolve_end_cap_forward_dest(
            TEST_REALM_ID,
            validators[&local_sub_id],
            25,
            [1, 2, 3, 4],
            &rotation,
            &validators,
        )
        .expect("routing decision");
        assert_eq!(dest, Some((proposer, validators[&proposer])));
    }

    #[test]
    fn resolve_forward_dest_missing_dest_node_id_rejects() {
        let rotation = rotation_config();
        let proposer = scheduled_proposer(&rotation, 25);
        let other_sub_ids: Vec<u16> = rotation
            .validator_sub_ids
            .iter()
            .copied()
            .filter(|&s| s != proposer)
            .collect();
        let validators = build_validators(&other_sub_ids);
        let err = resolve_end_cap_forward_dest(
            TEST_REALM_ID,
            validators[&other_sub_ids[0]],
            25,
            [1, 2, 3, 4],
            &rotation,
            &validators,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("no edge NodeId for scheduled proposer sub_id {proposer}")
        );
    }

    #[test]
    fn resolve_forward_dest_rotation_disabled_does_not_forward() {
        let rotation = RealmRotationConfig {
            checkpoints_per_epoch: 0,
            validator_sub_ids: vec![1, 2, 3],
        };
        let validators = build_validators(&[1, 2, 3]);
        let dest = resolve_end_cap_forward_dest(
            TEST_REALM_ID,
            validators[&1],
            25,
            [1, 2, 3, 4],
            &rotation,
            &validators,
        )
        .expect("routing decision");
        assert!(
            dest.is_none(),
            "rotation disabled: local intake"
        );
    }


    #[test]
    fn scheduled_validator_secondary_edge_routes_to_primary() {
        let rotation = rotation_config();
        let proposer_edge_node_ids = build_validators(&[1, 2, 3]);
        let proposer = scheduled_proposer(&rotation, 25);
        let secondary_edge = test_node(99);
        let dest = resolve_end_cap_forward_dest(
            TEST_REALM_ID,
            secondary_edge,
            25,
            [1, 2, 3, 4],
            &rotation,
            &proposer_edge_node_ids,
        )
        .expect("secondary edge routing");
        assert_eq!(dest, Some((proposer, proposer_edge_node_ids[&proposer])));
    }

    #[test]
    fn scheduled_dest_means_forward_only_local_means_store() {
        let rotation = rotation_config();
        let validators = build_validators(&[1, 2, 3]);
        let proposer = scheduled_proposer(&rotation, 25);
        let other = rotation
            .validator_sub_ids
            .iter()
            .copied()
            .find(|&sub_id| sub_id != proposer)
            .expect("other validator");
        let forwarded = resolve_end_cap_forward_dest(
            TEST_REALM_ID,
            validators[&other],
            25,
            [1, 2, 3, 4],
            &rotation,
            &validators,
        )
        .expect("routing");
        assert!(forwarded.is_some(), "non-proposer must forward and skip store/NATS");
        let local = resolve_end_cap_forward_dest(
            TEST_REALM_ID,
            validators[&proposer],
            25,
            [1, 2, 3, 4],
            &rotation,
            &validators,
        )
        .expect("routing");
        assert!(local.is_none(), "scheduled proposer must store and publish locally");
    }


    #[test]
    fn user_subtree_request_rejects_spine_crossing_root_level_zero() {
        const COORDINATOR_HEIGHT: u8 = 12;
        const GLOBAL_HEIGHT: u8 = 32;
        let err = ensure_user_subtree_request_within_realm(0, GLOBAL_HEIGHT, COORDINATOR_HEIGHT).unwrap_err();
        assert!(
            err.to_string().contains("crosses authenticated spine"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn user_subtree_request_accepts_realm_boundary_root_level() {
        const COORDINATOR_HEIGHT: u8 = 12;
        const GLOBAL_HEIGHT: u8 = 32;
        ensure_user_subtree_request_within_realm(COORDINATOR_HEIGHT, GLOBAL_HEIGHT, COORDINATOR_HEIGHT)
            .expect("realm-boundary subtree request must be allowed");
        ensure_user_subtree_request_within_realm(COORDINATOR_HEIGHT, COORDINATOR_HEIGHT, COORDINATOR_HEIGHT)
            .expect("zero-height realm-boundary request must be allowed");
    }

    #[test]
    fn user_subtree_request_rejects_leaf_above_root() {
        const COORDINATOR_HEIGHT: u8 = 12;
        let err = ensure_user_subtree_request_within_realm(COORDINATOR_HEIGHT + 1, COORDINATOR_HEIGHT, COORDINATOR_HEIGHT)
            .unwrap_err();
        assert!(
            err.to_string().contains("leaf_level"),
            "unexpected error: {err}"
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_common::{
        create_test_unified_db, FakeEphemeralQueuePublisher, FakeWorkerQueueSubscriber, TestNetworkConfig,
        TestUnifiedDatabaseStore, TestZKVerifier,
    };
    use parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
    use parth_core::{
        crypto::hash::tag_tree::{TagTreeMerkleProof, TagTreeNodePreimage, TagTreeProofNode},
        data::queue::queue_key::PCoreQueueItemBase,
        felt::{FromPrimitiveValuesFelt, ZeroableFelt},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{
            Q256BitHash, QNetworkHashTypes, QNetworkTreeCircuitSpecificConstants, QNetworkTreeConstants,
            QNetworkZKTypes,
        },
        utils::QPGenRandom,
        PF, PHash,
    };
    use psy_data::{
        guta::stats::GUTAStats,
        proof_input::guta::{
            end_cap_input::{ContractStateUpdate, ContractStateUpdateHistory},
            SubmitUserEndCapNonProofCoreInput,
        },
        queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
        v1::qdata::user_end_cap_result::PUPSEndCapResultCompact,
    };
    use psy_node_core::{
        psy_core_db::traits::full::{
            PsyNodeCheckpointObjectDatabaseWriter, PsyNodeCheckpointTreeDatabaseReader,
            PsyNodeCoreDatabaseBasicContractInfoStoreWriter, PsyNodeCoreDatabaseUserStoreWriter,
        },
        psy_temp_db::{
            QTempDBJobStatsStore, QTempDBPendingIdWriter, QTempDBSubmitStatusWriter,
            QTempDBUserEndCapSlotUpdatesWriter,
        },
        store::traits::proof_store::QParthProofStoreReader,
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    pub(crate) type N = TestNetworkConfig;

    pub(crate) const TEST_CHAIN_ID: u32 = 9;
    pub(crate) const TEST_NODE_ID: u32 = 4;
    pub(crate) const TEST_REALM_ID: u64 = 1;
    pub(crate) const TEST_REALM_SUB_ID: u64 = 2;
    /// A user id that lives inside realm 1 (user ids are partitioned by
    /// `realm_id * (1 << REALM_GLOBAL_USER_TREE_HEIGHT)`).
    pub(crate) const REALM_USER_ID: u64 = (1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT) + 42;
    /// A user id that lives inside the next realm (realm 2).
    const OTHER_REALM_USER_ID: u64 = (2u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT) + 42;
    const CONTRACT_COUNT: usize = 5;
    /// All contract state trees and the user contract tree live at the global
    /// contract tree height, so an untouched UCT leaf (zero hash at that height)
    /// equals the empty-root of a fresh contract state tree.
    const CONTRACT_TREE_HEIGHT: u8 = N::GLOBAL_CONTRACT_TREE_HEIGHT;

    pub(crate) fn zh(level: usize) -> PHash {
        PoseidonHasher::get_zero_hash(level)
    }

    pub(crate) fn test_realm_identifier() -> QRealmIdentifier {
        QRealmIdentifier::new(TEST_REALM_ID as u32, TEST_REALM_SUB_ID as u16)
    }

    /// A ZK "verifier" whose proof type is the public-inputs hash itself: proofs
    /// are the 32-byte hash, and reading the public inputs echoes the proof back.
    /// This lets the end-cap submission happy path carry a genuinely matching
    /// public-inputs hash without any real proving, while staying fully
    /// deterministic and parallel-safe (no shared mutable state).
    pub(crate) struct EndCapEchoVerifier {}

    impl QZKProofPublicInputsHasherReader<PHash, PHash> for EndCapEchoVerifier {
        fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
            Ok(*proof)
        }
        fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
            Ok(PHash::from_ref_32bytes(&bytes.try_into()?))
        }
    }

    impl QZKProofVerifier<PHash, PHash> for EndCapEchoVerifier {
        fn verify_zk_proof(&self, _circuit_type: u32, _proof: &PHash) -> anyhow::Result<PHash> {
            Ok(PoseidonHasher::get_zero_hash(1))
        }
        fn verify_zk_proof_from_slice_check_public_inputs_hash(
            &self,
            _circuit_type: u32,
            _proof_bytes: &[u8],
            _expected_public_inputs_hash: PHash,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Network config identical to TestNetworkConfig except the ZK verifier is
    /// the echo verifier above; used for the end-cap submission paths that check
    /// the public-inputs hash of the submitted proof.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct EndCapTestNetworkConfig {}

    impl QNetworkTreeCircuitSpecificConstants for EndCapTestNetworkConfig {
        const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;
        const MAX_USERS_TO_REGISTER_PER_PROOF: usize = 32;
        const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize = 64;
        const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize = 8;
        const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize = 4;
        const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;

        const DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4: [u64; 4] =
            [3896366420105793420, 17410332186442776169, 7329967984378645716, 6310665049578686403];

        const END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4: [u64; 4] =
            [1412692327731855940, 17963365021580141687, 10532510199226356508, 3943799806037696098];
    }

    impl QNetworkTreeConstants for EndCapTestNetworkConfig {
        const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
        const CHECKPOINT_TREE_HEIGHT: u8 = Self::CHECKPOINT_TREE_HEIGHT_USIZE as u8;

        const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 32;
        const GLOBAL_USER_TREE_HEIGHT: u8 = Self::GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

        const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
        const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = Self::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE as u8;

        const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
        const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = Self::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE as u8;

        const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 12;
        const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

        const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 20;
        const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = Self::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

        const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize = 32;
        const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = Self::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE as u8;

        const GROUP_REALM_HEIGHT: u8 = 1;

        const MAX_USERS: u64 = 1 << Self::GLOBAL_USER_TREE_HEIGHT;

        const MAX_REALMS: u32 = 1 << Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT;

        const MAX_USERS_PER_REALM: u32 = 1 << Self::REALM_GLOBAL_USER_TREE_HEIGHT;
    }

    impl QNetworkHashTypes for EndCapTestNetworkConfig {
        type QHash = PHash;
        type HasherBase = PoseidonHasher;
        type F = PF;
    }

    impl QNetworkZKTypes for EndCapTestNetworkConfig {
        type ZKProof = PHash;
        type ZKVerifier = EndCapEchoVerifier;
    }

    impl QNetworkTypesConfig for EndCapTestNetworkConfig {
        type JobId = QProvingJobDataID;
    }

    pub(crate) type RealmEdgeHandlerFor<N> = RealmEdgeHandler<
        N,
        TestUnifiedDatabaseStore,
        TestUnifiedDatabaseStore,
        FakeEphemeralQueuePublisher,
        FakeWorkerQueueSubscriber,
        InMemoryTempStore,
        InMemoryTempStore,
    >;

    /// Realm edge handler wired to a fresh in-memory database, temp/proof store
    /// and fake queues, mirroring how `server.rs` builds the production handler.
    /// The hash/field types are pinned to the in-memory store's config, so any
    /// network config sharing them (TestNetworkConfig, the echo config) fits.
    pub(crate) struct RealmEdgeTestEnv<N>
    where
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + QNetworkHashTypes<F = PF, QHash = PHash>,
    {
        pub(crate) handler: RealmEdgeHandlerFor<N>,
        pub(crate) db: Arc<TestUnifiedDatabaseStore>,
        pub(crate) temp_db: Arc<InMemoryTempStore>,
        pub(crate) user_update_queue: Arc<FakeEphemeralQueuePublisher>,
        pub(crate) work_queue: Arc<FakeWorkerQueueSubscriber>,
    }

    impl<N> RealmEdgeTestEnv<N>
    where
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + QNetworkHashTypes<F = PF, QHash = PHash>,
    {
        pub(crate) async fn create(proof_verifier: Arc<N::ZKVerifier>) -> anyhow::Result<Self> {
            let db = Arc::new(create_test_unified_db().await?);
            let tag_tree_rewards_store = Arc::clone(&db);
            let temp_db = Arc::new(InMemoryTempStore::new("realm_edge_test".to_string(), 1, 2));
            let proof_store = Arc::clone(&temp_db);
            let user_update_queue = Arc::new(FakeEphemeralQueuePublisher::new());
            let work_queue = Arc::new(FakeWorkerQueueSubscriber::new());
            let handler = RealmEdgeHandler::new(
                Arc::clone(&db),
                tag_tree_rewards_store,
                Arc::clone(&temp_db),
                proof_store,
                Arc::clone(&user_update_queue),
                Arc::clone(&work_queue),
                test_realm_identifier(),
                TEST_CHAIN_ID,
                TEST_NODE_ID,
                proof_verifier,
            );
            // A fresh InMemoryTempStore errors on pending-id reads; seed both
            // counters so handler reads behave like production (ids at 0).
            let rid = test_realm_identifier();
            temp_db.set_unique_pending_ids(&rid, 0, 0).await?;
            temp_db.set_gathering_unique_pending_ids(&rid, 0, 0).await?;
            Ok(Self { handler, db, temp_db, user_update_queue, work_queue })
        }
    }

    pub(crate) type StandardEnv = RealmEdgeTestEnv<TestNetworkConfig>;
    pub(crate) type EndCapEnv = RealmEdgeTestEnv<EndCapTestNetworkConfig>;

    async fn end_cap_env() -> anyhow::Result<EndCapEnv> {
        RealmEdgeTestEnv::create(Arc::new(EndCapEchoVerifier {})).await
    }

    /// Seeds contract state tree height metadata for contracts 0..CONTRACT_COUNT
    /// at checkpoint 0 (reads use max-checkpoint semantics, so this is visible
    /// at MAX_CHECKPOINT_ID).
    async fn seed_contract_heights(env: &EndCapEnv) -> anyhow::Result<()> {
        let heights = (0..CONTRACT_COUNT as u64).map(|id| (id, CONTRACT_TREE_HEIGHT)).collect::<Vec<_>>();
        env.db.set_contract_tree_heights(0, &heights).await
    }

    /// The append root the handler will compute for the checkpoint-tree proof of
    /// leaf 0 (the only committed checkpoint on a fresh database is 0).
    pub(crate) async fn checkpoint_tree_append_root_zero(db: &TestUnifiedDatabaseStore) -> anyhow::Result<PHash> {
        let proof = db.checkpoint_tree_get_merkle_proof(u64::MAX - 0xFFFF, 0).await?;
        Ok(proof.get_append_root::<PoseidonHasher>())
    }

    /// Builds a self-consistent end-cap submission input for `user_id` whose
    /// every gate matches a fresh realm database:
    /// - the user has no committed leaf, so the start hash is the zero value
    ///   (the handler derives the same from the empty global user tree);
    /// - the user contract tree starts empty (root = zero hash at the contract
    ///   tree height), matching the handler's fallback zero user leaf;
    /// - checkpoint ids are 0 on both sides.
    fn gen_end_cap_input(user_id: u64, checkpoint_tree_root: PHash) -> SubmitUserEndCapNonProofInput<PF, PHash> {
        type Hasher = PoseidonHasher;
        let mut user_contract_tree = SimpleMemoryMerkleStoreV3::<Hasher, PHash>::new(CONTRACT_TREE_HEIGHT);
        let mut contract_state_updates = Vec::with_capacity(CONTRACT_COUNT);
        for contract_id in 0..CONTRACT_COUNT as u64 {
            let mut contract_state_tree = SimpleMemoryMerkleStoreV3::<Hasher, PHash>::new(CONTRACT_TREE_HEIGHT);
            // deterministic per-contract leaf writes: distinct slots per contract
            let updates = (0..8u64)
                .map(|i| {
                    let leaf_id = contract_id * 16 + i;
                    let value = PHash::from_values(1000 + contract_id * 10 + i, 0, 0, 0);
                    contract_state_tree.set_leaf(leaf_id, value)
                })
                .collect::<Vec<_>>();
            let end_root = contract_state_tree.get_root();
            let user_contract_tree_update_proof = user_contract_tree.set_leaf(contract_id, end_root);
            contract_state_updates.push(ContractStateUpdateHistory {
                user_contract_tree_update_proof,
                updates: updates
                    .into_iter()
                    .map(|delta_proof| ContractStateUpdate::Positional { delta_proof })
                    .collect(),
            });
        }
        let new_user_contract_tree_root = user_contract_tree.get_root();

        let user_id_f = PF::from_u64_value(user_id);
        // exactly the fallback leaf the handler serves for a missing user
        let old_user_leaf = PQEDUserLeaf {
            public_key: PHash::get_zero_value(),
            user_state_tree_root: zh(CONTRACT_TREE_HEIGHT as usize),
            balance: PF::ZERO_VALUE,
            nonce: PF::ZERO_VALUE,
            last_checkpoint_id: PF::ZERO_VALUE,
            event_index: PF::ZERO_VALUE,
            user_id: user_id_f,
        };
        assert!(old_user_leaf.is_first_transaction_old_user_leaf());

        let new_user_leaf = PQEDUserLeaf {
            user_id: user_id_f,
            last_checkpoint_id: PF::ZERO_VALUE,
            user_state_tree_root: new_user_contract_tree_root,
            public_key: PHash::from_values(user_id, 7, 8, 9),
            balance: PF::from_u64_value(1_000_000),
            nonce: PF::from_u64_value(1),
            event_index: PF::from_u64_value(1),
        };
        let state_transition = PUPSEndCapResultCompact {
            start_user_leaf_hash: PHash::get_zero_value(),
            end_user_leaf_hash: new_user_leaf.qfhash::<Hasher>(),
            checkpoint_tree_root_hash: checkpoint_tree_root,
            user_id: user_id_f,
        };
        let stats = GUTAStats {
            guta_fees_collected: PF::from_u64_value(1000),
            da_fees_collected: PF::from_u64_value(1000 * 8 * CONTRACT_COUNT as u64),
            user_ops_processed: PF::from_u64_value(1),
            total_transactions: PF::from_u64_value(CONTRACT_COUNT as u64),
            slots_modified: PF::from_u64_value(8 * CONTRACT_COUNT as u64),
        };
        let core = SubmitUserEndCapNonProofCoreInput {
            checkpoint_id: PF::ZERO_VALUE,
            state_transition,
            new_user_leaf,
            stats,
        };
        SubmitUserEndCapNonProofInput { core, contract_state_updates, events: vec![] }
    }

    /// A submission input + proof bytes pair that passes every gate of
    /// `handle_user_end_cap_proof_submission` on the given fresh env.
    async fn valid_end_cap_submission(env: &EndCapEnv) -> anyhow::Result<(SubmitUserEndCapNonProofInput<PF, PHash>, Vec<u8>)> {
        let checkpoint_root = checkpoint_tree_append_root_zero(&env.db).await?;
        let input = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        let expected_hash = input
            .core
            .get_proof_public_inputs_hash::<PoseidonHasher>(EndCapTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT);
        let proof_bytes = expected_hash.into_owned_32bytes().to_vec();
        Ok((input, proof_bytes))
    }

    #[tokio::test]
    async fn user_belongs_to_realm_partitions_ids_by_realm_prefix() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;
        let users_per_realm = 1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;

        // realm 1 owns [1 * users_per_realm, 2 * users_per_realm)
        assert!(!handler.user_belongs_to_realm(users_per_realm - 1));
        assert!(handler.user_belongs_to_realm(users_per_realm));
        assert!(handler.user_belongs_to_realm(REALM_USER_ID));
        assert!(handler.user_belongs_to_realm(2 * users_per_realm - 1));
        assert!(!handler.user_belongs_to_realm(2 * users_per_realm));
        assert!(!handler.user_belongs_to_realm(OTHER_REALM_USER_ID));

        // the RPC mirror computes the same partition
        assert!(RealmEdgeRpcServer::check_user_id_in_realm(handler, REALM_USER_ID).await?);
        assert!(!RealmEdgeRpcServer::check_user_id_in_realm(handler, OTHER_REALM_USER_ID).await?);
        Ok(())
    }

    #[tokio::test]
    async fn pending_id_mappings_and_submit_guard() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // no mappings exist on a fresh database
        assert_eq!(handler.get_checkpoint_id_for_unique_pending_id_internal(0).await?, None);
        assert_eq!(
            RealmEdgeRpcServer::get_unique_pending_id_for_checkpoint_id(handler, 0).await?,
            None
        );

        // seed both directions of the mapping
        env.db.set_unique_pending_id_checkpoint_id_mapping(7, 3).await?;
        env.db.set_checkpoint_id_to_unique_pending_id_mapping(3, 7, &11u128).await?;
        assert_eq!(handler.get_checkpoint_id_for_unique_pending_id_internal(7).await?, Some(3));
        assert_eq!(
            RealmEdgeRpcServer::get_unique_pending_id_for_checkpoint_id(handler, 3).await?,
            Some((7, 11u128))
        );

        // the submit guard passes while no status is recorded, then rejects
        handler.ensure_user_has_not_submitted(REALM_USER_ID, 0).await?;
        env.temp_db
            .set_submitted_status_for_pending(&handler.realm_identifier, 0, REALM_USER_ID, 5)
            .await?;
        let err = handler
            .ensure_user_has_not_submitted(REALM_USER_ID, 0)
            .await
            .expect_err("a submitted user must be rejected");
        assert!(err.to_string().contains("already been submitted"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn job_stats_require_pending_mapping_and_aggregate_durations() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // no pending-id mapping exists on a fresh database
        let err = handler
            .get_job_stats_internal(0)
            .await
            .expect_err("stats for a checkpoint without pending mapping must fail");
        assert!(err.to_string().contains("no unique pending id"), "unexpected error: {err}");

        // map checkpoint 3 to pending id 7 in both directions; stats default to zero
        env.db.set_unique_pending_id_checkpoint_id_mapping(7, 3).await?;
        env.db.set_checkpoint_id_to_unique_pending_id_mapping(3, 7, &11u128).await?;
        let stats = handler.get_job_stats_internal(3).await?;
        assert_eq!(stats.unique_pending_id, 7);
        assert_eq!(stats.total_completed, 0);
        assert_eq!(stats.total_duration_ms, 0);
        assert_eq!(stats.min_duration_ms, None);
        assert_eq!(stats.max_duration_ms, None);

        // recorded job durations aggregate through the temp db
        env.temp_db.increment_job_stats(&handler.realm_identifier, 7, 25).await?;
        env.temp_db.increment_job_stats(&handler.realm_identifier, 7, 40).await?;
        let stats = RealmEdgeRpcServer::get_job_stats(handler, 3).await?;
        assert_eq!(stats.unique_pending_id, 7);
        assert_eq!(stats.total_completed, 2);
        assert_eq!(stats.total_duration_ms, 65);
        assert_eq!(stats.min_duration_ms, Some(25));
        assert_eq!(stats.max_duration_ms, Some(40));
        Ok(())
    }

    #[tokio::test]
    async fn contract_height_cache_fetches_from_db_and_gates_unknown_contracts() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // unknown contract: no height metadata in the realm db yet
        let err = handler
            .contract_state_tree_height(0)
            .await
            .expect_err("missing height metadata must be rejected");
        assert!(
            err.to_string().contains("contract 0 state tree height metadata is not available"),
            "unexpected error: {err}"
        );

        // seed heights for contracts 0..5 at checkpoint 0; the fetch reads at
        // MAX_CHECKPOINT_ID but max-checkpoint semantics finds them
        let heights = (0..CONTRACT_COUNT as u64).map(|id| (id, CONTRACT_TREE_HEIGHT)).collect::<Vec<_>>();
        env.db.set_contract_tree_heights(0, &heights).await?;
        handler.ensure_contract_heights_in_cache(&[0, 2, 4]).await?;
        assert_eq!(handler.contract_state_tree_height(0).await?, CONTRACT_TREE_HEIGHT);
        assert!(handler.contract_state_tree_height_cache.mapping.get(&2).is_some());

        // heights already cached are not re-fetched, so an unknown id beside a
        // cached one is only rejected when it actually misses the cache
        let err = handler
            .contract_state_tree_height(9)
            .await
            .expect_err("unknown contract id must still be rejected");
        assert!(
            err.to_string().contains("contract 9 state tree height metadata is not available"),
            "unexpected error: {err}"
        );

        // RPC surface: raw heights from the db and a height-dependent root read
        let raw = RealmEdgeRpcServer::get_contract_tree_state_heights(handler, 0, vec![0, 2]).await?;
        assert_eq!(raw, vec![CONTRACT_TREE_HEIGHT; 2]);
        let root = RealmEdgeRpcServer::get_user_contract_state_tree_root(handler, 0, REALM_USER_ID, 0).await?;
        assert_eq!(root, zh(CONTRACT_TREE_HEIGHT as usize));
        Ok(())
    }

    #[tokio::test]
    async fn user_end_cap_slot_updates_round_trip_through_temp_db() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // nothing stored yet
        assert!(handler.get_user_end_cap_slot_updates_internal(0, REALM_USER_ID).await?.is_none());

        let payload = RealmEndCapSlotUpdates {
            realm_id: TEST_REALM_ID,
            realm_sub_id: TEST_REALM_SUB_ID,
            unique_pending_id: 3,
            user_id: REALM_USER_ID,
            contracts: vec![RealmContractSlotUpdates {
                contract_id: 1,
                slot_updates: vec![RealmSlotUpdate { slot: 5, old_value: 0, new_value: 7 }],
            }],
        };
        env.temp_db
            .set_user_end_cap_slot_updates(
                &handler.realm_identifier,
                3,
                REALM_USER_ID,
                bincode::serialize(&payload)?,
            )
            .await?;
        // the structs are not PartialEq, so compare through the bincode bytes
        // the handler round-trips
        let read_back = handler
            .get_user_end_cap_slot_updates_internal(3, REALM_USER_ID)
            .await?
            .expect("stored slot updates must be readable");
        assert_eq!(bincode::serialize(&read_back)?, bincode::serialize(&payload)?);
        let rpc_read = RealmEdgeRpcServer::get_user_end_cap_slot_updates(handler, 3, REALM_USER_ID)
            .await?
            .expect("stored slot updates must be readable via RPC");
        assert_eq!(bincode::serialize(&rpc_read)?, bincode::serialize(&payload)?);
        Ok(())
    }

    #[tokio::test]
    async fn submit_user_end_cap_rejects_invalid_submissions() -> anyhow::Result<()> {
        let env = end_cap_env().await?;
        seed_contract_heights(&env).await?;
        let handler = &env.handler;
        let checkpoint_root = checkpoint_tree_append_root_zero(&env.db).await?;

        // checkpoint id must match the new user leaf's last checkpoint id
        let mut mismatch = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        mismatch.core.new_user_leaf.last_checkpoint_id = PF::from_u64_value(1);
        let err = handler
            .handle_user_end_cap_proof_submission(mismatch, vec![])
            .await
            .expect_err("checkpoint mismatch must fail");
        assert!(
            err.to_string().contains("does not match new_user_leaf last_checkpoint_id"),
            "unexpected error: {err}"
        );

        // user from another realm
        let foreign = gen_end_cap_input(OTHER_REALM_USER_ID, checkpoint_root);
        let err = handler
            .handle_user_end_cap_proof_submission(foreign, vec![])
            .await
            .expect_err("user outside the realm must fail");
        assert!(err.to_string().contains("does not belong to this realm"), "unexpected error: {err}");

        // empty contract state updates
        let mut empty = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        empty.contract_state_updates = vec![];
        let err = handler
            .handle_user_end_cap_proof_submission(empty, vec![])
            .await
            .expect_err("empty updates must fail");
        assert!(err.to_string().contains("contract_state_updates cannot be empty"), "unexpected error: {err}");

        // end-cap checkpoint ahead of the node's current checkpoint
        let mut future = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        future.core.checkpoint_id = PF::from_u64_value(1);
        future.core.new_user_leaf.last_checkpoint_id = PF::from_u64_value(1);
        let err = handler
            .handle_user_end_cap_proof_submission(future, vec![])
            .await
            .expect_err("future checkpoint must fail");
        assert!(err.to_string().contains("but current checkpoint is"), "unexpected error: {err}");

        // stale start leaf hash
        let mut bad_start = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        bad_start.core.state_transition.start_user_leaf_hash = PHash::from_values(4242, 0, 0, 0);
        let err = handler
            .handle_user_end_cap_proof_submission(bad_start, vec![])
            .await
            .expect_err("wrong start hash must fail");
        assert!(err.to_string().contains("Invalid start_user_leaf_hash"), "unexpected error: {err}");

        // wrong checkpoint tree root
        let bad_root = gen_end_cap_input(REALM_USER_ID, PHash::from_values(777, 0, 0, 0));
        let proof_bytes = bad_root
            .core
            .get_proof_public_inputs_hash::<PoseidonHasher>(EndCapTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT)
            .into_owned_32bytes()
            .to_vec();
        let err = handler
            .handle_user_end_cap_proof_submission(bad_root, proof_bytes)
            .await
            .expect_err("wrong checkpoint tree root must fail");
        assert!(
            err.to_string().contains("Invalid checkpoint tree proof historical root"),
            "unexpected error: {err}"
        );

        // proof bytes that decode to a different public-inputs hash
        let (input, _) = valid_end_cap_submission(&env).await?;
        let err = handler
            .handle_user_end_cap_proof_submission(input, PHash::get_zero_value().into_owned_32bytes().to_vec())
            .await
            .expect_err("mismatched public inputs hash must fail");
        assert!(err.to_string().contains("Public inputs hash mismatch"), "unexpected error: {err}");

        // inconsistent new user leaf (end hash does not hash to the new leaf)
        let mut bad_leaf = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        bad_leaf.core.state_transition.end_user_leaf_hash = PHash::from_values(8888, 0, 0, 0);
        let proof_bytes = bad_leaf
            .core
            .get_proof_public_inputs_hash::<PoseidonHasher>(EndCapTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT)
            .into_owned_32bytes()
            .to_vec();
        let err = handler
            .handle_user_end_cap_proof_submission(bad_leaf, proof_bytes)
            .await
            .expect_err("inconsistent new user leaf must fail");
        assert!(err.to_string().contains("invalid new_user_leaf"), "unexpected error: {err}");

        // user whose committed leaf is already at a later checkpoint
        env.db
            .set_user_leaf(
                0,
                &PQEDUserLeaf {
                    public_key: PHash::from_values(77, 0, 0, 0),
                    user_state_tree_root: zh(CONTRACT_TREE_HEIGHT as usize),
                    balance: PF::from_u64_value(1),
                    nonce: PF::ZERO_VALUE,
                    last_checkpoint_id: PF::from_u64_value(5),
                    event_index: PF::ZERO_VALUE,
                    user_id: PF::from_u64_value(REALM_USER_ID),
                },
            )
            .await?;
        let stale = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        let err = handler
            .handle_user_end_cap_proof_submission(stale, vec![])
            .await
            .expect_err("stale user checkpoint must fail");
        assert!(err.to_string().contains("but user's last checkpoint is 5"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn submit_user_end_cap_happy_path_publishes_and_stores() -> anyhow::Result<()> {
        let env = end_cap_env().await?;
        seed_contract_heights(&env).await?;
        let handler = &env.handler;
        let (input, proof_bytes) = valid_end_cap_submission(&env).await?;
        let new_user_leaf = input.core.new_user_leaf.clone();

        handler.handle_user_end_cap_proof_submission(input, proof_bytes.clone()).await?;

        // the end-cap queue item was published under the live proc id
        assert_eq!(env.user_update_queue.published_count(), 1);
        let published = env.user_update_queue.published_bytes_for(0);
        assert_eq!(published.len(), 1);
        let queue_item = PsyRealmUserUpdateQueueItem::<PF, PHash>::decode_queue_item_ref(&published[0])?;
        assert_eq!(queue_item.job_id.circuit_type, ProvingJobCircuitType::UserEndCap);
        assert_eq!(queue_item.job_id.task_index, REALM_USER_ID as u32);
        assert_eq!(queue_item.job_id.goal_id, 0);
        assert_eq!(queue_item.new_user_leaf.user_id, new_user_leaf.user_id);
        assert_eq!(queue_item.new_user_leaf.user_state_tree_root, new_user_leaf.user_state_tree_root);
        assert_eq!(queue_item.new_user_leaf.balance, new_user_leaf.balance);
        assert_eq!(queue_item.old_user_leaf_hash, PHash::get_zero_value());
        assert_eq!(queue_item.new_user_leaf_hash, new_user_leaf.qfhash::<PoseidonHasher>());

        // the proof is stored under the derived end-cap job id
        let job_id = QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            REALM_USER_ID,
            N::GLOBAL_USER_TREE_HEIGHT,
            0,
        )?;
        assert!(env.temp_db.contains_proof_for_job_id(job_id, 0).await?);

        // the slot updates payload is stored and readable back
        let slot_updates = handler.get_user_end_cap_slot_updates_internal(0, REALM_USER_ID).await?;
        let slot_updates = slot_updates.expect("slot updates must be stored");
        assert_eq!(slot_updates.realm_id, TEST_REALM_ID);
        assert_eq!(slot_updates.realm_sub_id, TEST_REALM_SUB_ID);
        assert_eq!(slot_updates.unique_pending_id, 0);
        assert_eq!(slot_updates.user_id, REALM_USER_ID);
        assert_eq!(slot_updates.contracts.len(), CONTRACT_COUNT);
        for (index, contract) in slot_updates.contracts.iter().enumerate() {
            assert_eq!(contract.contract_id, index as u32);
            assert!(!contract.slot_updates.is_empty());
        }

        // a second submission for the same user is rejected by the status guard
        let (second, second_proof) = valid_end_cap_submission(&env).await?;
        let err = handler
            .handle_user_end_cap_proof_submission(second, second_proof)
            .await
            .expect_err("double submission must fail");
        assert!(err.to_string().contains("already been submitted"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn submit_user_end_cap_batch_splits_success_and_failure() -> anyhow::Result<()> {
        let env = end_cap_env().await?;
        seed_contract_heights(&env).await?;
        let handler = &env.handler;

        let (valid, valid_proof) = valid_end_cap_submission(&env).await?;
        let checkpoint_root = checkpoint_tree_append_root_zero(&env.db).await?;
        let invalid = gen_end_cap_input(OTHER_REALM_USER_ID, checkpoint_root);

        let (success, failed) = RealmEdgeRpcServer::submit_user_end_cap_batch(
            handler,
            vec![(valid, valid_proof), (invalid, vec![])],
        )
        .await?;
        assert_eq!(success, vec![REALM_USER_ID]);
        assert_eq!(failed, vec![OTHER_REALM_USER_ID]);
        // exactly the valid submission reached the queue
        assert_eq!(env.user_update_queue.published_count(), 1);

        // the single-submit RPC wrapper reports "ok" for a fresh valid user
        let (again, again_proof) = {
            let checkpoint_root = checkpoint_tree_append_root_zero(&env.db).await?;
            let input = gen_end_cap_input(REALM_USER_ID + 1, checkpoint_root);
            let expected_hash = input
                .core
                .get_proof_public_inputs_hash::<PoseidonHasher>(EndCapTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT);
            (input, expected_hash.into_owned_32bytes().to_vec())
        };
        let result = RealmEdgeRpcServer::submit_user_end_cap(handler, again, again_proof).await?;
        assert_eq!(result, "ok");
        Ok(())
    }

    #[tokio::test]
    async fn batch_reward_proofs_merge_top_proof_root() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // the coordinator-level top proof must exist for the pending id
        let err = handler
            .generate_batch_proof_miner_reward_proofs_internal(0, vec![])
            .await
            .expect_err("missing top proof must fail");
        assert!(err.to_string().contains("Rewards tree proof not found"), "unexpected error: {err}");

        // seed one rewards tag tree node and a non-trivial top proof
        let root_key = SimpleMerkleNodeKey::new_root();
        env.db.rewards_tag_tree_set_node_tag(0, root_key, zh(40), zh(41)).await?;
        let top_proof = TagTreeMerkleProof {
            root: zh(50),
            leaf: TagTreeNodePreimage {
                left: zh(51),
                right: zh(52),
                tag: zh(53),
            },
            index: 1,
            siblings: vec![TagTreeProofNode { sibling: zh(54), parent_tag: zh(55) }],
        };
        env.db.set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(0, &top_proof).await?;

        // capture the realm-local proof before the merge
        let local = env
            .db
            .rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(0, &[root_key])
            .await?;
        assert_eq!(local.len(), 1);

        // empty request: no proofs
        let empty = handler.generate_batch_proof_miner_reward_proofs_internal(0, vec![]).await?;
        assert!(empty.is_empty());

        let job_ids = vec![QProvingJobDataIDWithRewardPath::new(
            QProvingJobDataID::qp_rand_gen(),
            root_key.to_reward_path_info(),
        )];
        let proofs = handler.generate_batch_proof_miner_reward_proofs_internal(0, job_ids).await?;
        assert_eq!(proofs.len(), 1);
        // the merged proof is re-rooted at the top proof with the merged index
        assert_eq!(proofs[0].tag_tree_proof.root, top_proof.root);
        assert_eq!(
            proofs[0].tag_tree_proof.index,
            local[0].index | (top_proof.index << local[0].siblings.len())
        );
        assert_eq!(
            proofs[0].tag_tree_proof.siblings.len(),
            local[0].siblings.len() + top_proof.siblings.len()
        );
        Ok(())
    }

    #[tokio::test]
    async fn rpc_reader_wrappers_serve_fresh_database_state() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // fresh database: latest checkpoint id is 0 and tree reads succeed
        assert_eq!(RealmEdgeRpcServer::get_latest_checkpoint_id(handler).await?, 0);
        let root = RealmEdgeRpcServer::get_latest_checkpoint_tree_root(handler).await?;
        assert_eq!(root, RealmEdgeRpcServer::get_checkpoint_tree_root(handler, 0).await?);
        assert_eq!(root, zh(N::CHECKPOINT_TREE_HEIGHT_USIZE));
        let user_root = RealmEdgeRpcServer::get_user_tree_root(handler, 0).await?;
        assert_eq!(user_root, zh(N::GLOBAL_USER_TREE_HEIGHT_USIZE));
        assert_eq!(
            RealmEdgeRpcServer::get_user_tree_leaf_hash(handler, 0, REALM_USER_ID).await?,
            PHash::get_zero_value()
        );

        // batch user leaf reads validate the id list
        let err = RealmEdgeRpcServer::get_user_leaves_batch(handler, 0, vec![])
            .await
            .expect_err("empty user id list must fail");
        assert!(err.to_string().contains("user_ids cannot be empty"), "unexpected error: {err}");

        // the top rewards-tree proof for a checkpoint that has none must fail
        let err = RealmEdgeRpcServer::get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(handler, 0)
            .await
            .expect_err("missing rewards tree proof must fail");
        assert!(err.to_string().contains("Rewards tree proof not found"), "unexpected error: {err}");

        // IMT endpoints report missing leaves and keys
        let err = RealmEdgeRpcServer::get_imt_leaf_preimage(handler, 0, REALM_USER_ID, 0, 0)
            .await
            .expect_err("missing IMT leaf must fail");
        assert!(err.to_string().contains("Leaf preimage not found at index 0"), "unexpected error: {err}");
        let err = RealmEdgeRpcServer::get_imt_leaf_index_for_key(handler, 0, REALM_USER_ID, 0, zh(1))
            .await
            .expect_err("missing IMT key must fail");
        assert!(err.to_string().contains("Key not found in IMT"), "unexpected error: {err}");

        // membership proofs first resolve the contract height, which is unknown
        let err = RealmEdgeRpcServer::get_imt_membership_proof(handler, 0, REALM_USER_ID, 9, zh(1))
            .await
            .expect_err("unknown contract height must fail");
        assert!(
            err.to_string().contains("contract 9 state tree height metadata is not available"),
            "unexpected error: {err}"
        );
        Ok(())
    }
}
