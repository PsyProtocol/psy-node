use std::sync::Arc;

use tokio::task;
use parth_core::{
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath, crypto::hash::{merkle_proof::MerkleProofCore, tag_tree::TagTreeMerkleProof, traits::{HashTo4Felts, QFieldHashable}}, data::{hash::merkle_node_key::SimpleMerkleNodeKey, queue::queue_key::QPBaseQueueType}, felt::ToU64Value, node::realm_identifier::QRealmIdentifier, protocol::core_types::{Q256BitHash, QNetworkTypesConfig, QZKProofVerifier}
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_crypto::hash::tx_hash::{compute_deploy_contract_content_hash, hash_to_hex};
use psy_api_core::CheckpointJobStats;
use psy_data::{
    guta::{
        header_extended::{GlobalUserTreeAggregatorHeaderWithTagValueAndJobID, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType},
        realm_finalize::protocol_encode_finalize_output,
    },
    p2p::{sha256, Certificate, Proposal, RealmFinalizeSubmitCode},
    prepared_block::realm::PsyRealmCoordinatorUpdate,
    v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::PQEDCheckpointGlobalStateRoots, checkpoint_sync::PQEDCheckpointSyncInfoCompact, contract::{DashMapContractHeightCache, PQBCDeployContract, PsyDeployContractQueueItem}, public_key::PZKPublicKeyInfo
        },
    },
};
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorEdgeAPIStoreReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardEdgeAPITempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber},
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle};

use crate::{
    coordinator::queue_key::{CoordinatorDeployContractQueueKey, CoordinatorRegisterUserPublicKeyQueueKey, CoordinatorSubmitRealmGUTAUpdateQueueKey},
    p2p::guta_submit::GutaSubmitError,
    realm::processor::consensus::{
        build_bound_finalize_output, certificate_includes_proposer, inclusion_lag_within_limit,
        require_nonzero_validator_tree_root, validate_certificate, validator_tree_root_matches_proof_base,
        votes_meet_wait,
    },
};

// const END_CAP_PROOF_CIRCUIT_TYPE_U32: u32 = ProvingJobCircuitType::UserEndCap as u32;
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
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,

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
    pub chain_id: u32,
    pub validator_roster: Option<(crate::coordinator::validator_registry::ValidatorRegistry, u64)>,
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
            tag_tree_rewards_store: self.tag_tree_rewards_store.clone(),
            temp_db: self.temp_db.clone(),
            proof_store: self.proof_store.clone(),
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
            chain_id: self.chain_id,
            validator_roster: self.validator_roster.clone(),
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
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        guta_update_queue: Arc<GUTAUpdateQueue>,
        register_user_queue: Arc<RegisterUserQueue>,
        deploy_contract_queue: Arc<DeployContractQueue>,
        get_proof_work_queue: Arc<GetProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        chain_id: u32,
        proof_verifier: Arc<N::ZKVerifier>,
        checkpoint_state_transition_circuit_fingerprint: N::QHash,
    ) -> Self {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;
        Self {
            db_reader: db,
            tag_tree_rewards_store,
            temp_db,
            proof_store,
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
            chain_id,
            validator_roster: None,
        }
    }
    pub fn set_validator_roster(
        &mut self,
        registry: crate::coordinator::validator_registry::ValidatorRegistry,
        checkpoints_per_epoch: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!registry.is_empty(), "P2P validator roster must not be empty");
        anyhow::ensure!(checkpoints_per_epoch > 0, "P2P checkpoints_per_epoch must be greater than zero");
        self.validator_roster = Some((registry, checkpoints_per_epoch));
        Ok(())
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
        //let checkpoint_id = self.get_latest_checkpoint_id_internal().await?;
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
        Ok(PsyRealmCoordinatorUpdate {
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
        let (_, unique_proc_checkpoint_id, queue_key) = self.get_register_user_queue_key().await?;
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
    pub async fn submit_guta_internal(
        &self,
        input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
        proof_bytes: Vec<u8>,
        proposal_bytes: Option<Vec<u8>>,
        certificate_bytes: Option<Vec<u8>>,
    ) -> anyhow::Result<()>
    where
        N::ZKVerifier: 'static,
    {
        let realm_id_u64 = input.header.header.state_transition.node_index.to_u64_value();
        println!("Submitting GUTA for realm_id {}\n{:?}", realm_id_u64, input);

        let realm_level_u64 = input.header.header.state_transition.node_level.to_u64_value();
        if realm_level_u64 != N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as u64 {
            return Err(GutaSubmitError::illegal(
                RealmFinalizeSubmitCode::InvalidOutput,
                format!(
                    "invalid realm level {}, expected {}",
                    realm_level_u64,
                    N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT
                ),
            ).into());
        }

        let realm_level = realm_level_u64 as u8;
        if realm_id_u64 > (1u64 << realm_level) || realm_id_u64 > u32::MAX as u64 {
            return Err(GutaSubmitError::illegal(
                RealmFinalizeSubmitCode::InvalidOutput,
                format!("invalid realm id {}", realm_id_u64),
            ).into());
        }

        let realm_id = realm_id_u64 as u32;
        let proving_circuit_type = ProvingJobCircuitType::try_from_u32(input.job_type_u32)?;
        let proof_bytes = Arc::new(proof_bytes);

        let (unique_pending_id, proc_checkpoint_id) = self.get_current_gathering_unique_pending_id_internal().await?;
        self.ensure_guta_matches_current_coordinator_state(realm_id_u64, &input).await?;

        let output_proof_job_id = QProvingJobDataID::try_get_coordinator_edge_proof_store_output_proof_id_for_realm_submit(
            realm_id,
            realm_level,
            unique_pending_id,
            proving_circuit_type,
        )?;
        self.verify_optional_guta_certificate(
            realm_id,
            &input,
            &proof_bytes,
            proposal_bytes.as_deref(),
            certificate_bytes.as_deref(),
        )
        .await?;
        let expected_public_inputs_hash = input.qfhash::<N::HasherBase>();
        let proof_verifier = self.proof_verifier.clone();
        task::spawn_blocking({
            let proof_bytes = proof_bytes.clone();
            move || {
                proof_verifier.verify_zk_proof_from_slice_check_public_inputs_hash(input.job_type_u32, &proof_bytes, expected_public_inputs_hash)
            }
        }).await??;

        let status = (rand::random::<u64>() & 0x0fff_ffff_ffff_ffff).max(1);
        if !self
            .temp_db
            .put_submitted_status_if_absent(&self.realm_identifier, unique_pending_id, realm_id_u64, status)
            .await?
        {
            return Err(GutaSubmitError::retryable(
                RealmFinalizeSubmitCode::AlreadyClaimed,
                format!(
                    "GUTA for realm_id {} at unique_pending_id {} has already been submitted",
                    realm_id,
                    unique_pending_id
                ),
            ).into());
        }
        self.proof_store
            .put_proof_bytes_for_job_id(&output_proof_job_id, unique_pending_id, &proof_bytes)
            .await?;

        let queue_item = GlobalUserTreeAggregatorHeaderWithTagValueAndJobID {
            header: input.header,
            job_id: output_proof_job_id,
        };

        let queue_key = CoordinatorSubmitRealmGUTAUpdateQueueKey::<N::F, N::QHash> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: proc_checkpoint_id,
            task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral,
            _phantom_queue_item: std::marker::PhantomData,
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
            return Err(GutaSubmitError::retryable(
                RealmFinalizeSubmitCode::CheckpointUnavailable,
                format!(
                    "stale GUTA update rejected at coordinator edge: realm_id {} latest_checkpoint_id {} realm_last_modified_checkpoint_id {} submitted_old_realm_root {:?} current_realm_root {:?} submitted_new_realm_root {:?} submitted_checkpoint_tree_root {:?}",
                    realm_id,
                    latest_checkpoint_id,
                    current_realm_root.checkpoint_id,
                    submitted_old_realm_root,
                    current_realm_root.value,
                    input.header.header.state_transition.new_node_value,
                    input.header.header.checkpoint_tree_root,
                ),
            ).into());
        }

        Ok(())
    }

    async fn verify_optional_guta_certificate(
        &self,
        realm_id: u32,
        input: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
        proof_bytes: &[u8],
        proposal_bytes: Option<&[u8]>,
        certificate_bytes: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let Some((registry, checkpoints_per_epoch)) = self.validator_roster.as_ref() else {
            anyhow::ensure!(
                proposal_bytes.is_none() && certificate_bytes.is_none(),
                "GUTA Proposal/Certificate supplied but coordinator has no validator roster"
            );
            return Ok(());
        };
        let (occupied, keys) =
            crate::coordinator::validator_registry::realm_certificate_roster(realm_id, registry)?;
        anyhow::ensure!(
            !occupied.is_empty(),
            "configured validator roster has no validators for realm {realm_id}"
        );
        let proposal = Proposal::decode_exact(proposal_bytes.ok_or_else(|| {
            anyhow::anyhow!("rotation enabled but GUTA Proposal missing for realm {realm_id}")
        })?)
        .map_err(|error| anyhow::anyhow!("invalid GUTA Proposal for realm {realm_id}: {error}"))?;
        let certificate = Certificate::decode_exact(certificate_bytes.ok_or_else(|| {
            anyhow::anyhow!("rotation enabled but GUTA Certificate missing for realm {realm_id}")
        })?)
        .map_err(|error| anyhow::anyhow!("invalid GUTA Certificate for realm {realm_id}: {error}"))?;
        anyhow::ensure!(proposal.compute_proposal_id() == proposal.proposal_id, "GUTA proposal_id mismatch");
        anyhow::ensure!(proposal.chain_id == self.chain_id, "GUTA Proposal chain_id mismatch");
        anyhow::ensure!(proposal.realm_id == realm_id, "GUTA Proposal realm mismatch");
        anyhow::ensure!(proposal.finalizer_proof_hash == sha256(proof_bytes), "GUTA Proposal proof hash mismatch");

        let canonical_base_checkpoint_id = self
            .db_reader
            .get_checkpoint_id_for_checkpoint_root_hash(input.header.header.checkpoint_tree_root)
            .await?
            .ok_or_else(|| anyhow::anyhow!("GUTA checkpoint tree root has no canonical checkpoint ID"))?;
        anyhow::ensure!(
            proposal.base_checkpoint_id == canonical_base_checkpoint_id,
            "GUTA Proposal proof-base checkpoint does not match submitted checkpoint tree root"
        );
        let proof_base_roots = self
            .db_reader
            .get_checkpoint_global_state_roots(proposal.base_checkpoint_id)
            .await?;
        let proof_base_validator_tree_root = proof_base_roots.validator_tree_root.into_owned_32bytes();
        require_nonzero_validator_tree_root(&proposal.validator_tree_root)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        require_nonzero_validator_tree_root(&proof_base_validator_tree_root)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        anyhow::ensure!(
            validator_tree_root_matches_proof_base(
                &proposal.validator_tree_root,
                &proof_base_validator_tree_root,
            ),
            "GUTA Proposal validator_tree_root does not match proof-base checkpoint"
        );
        let inclusion_checkpoint_id = self
            .get_latest_checkpoint_id_internal()
            .await?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("latest checkpoint ID overflow at GUTA admission"))?;
        let inclusion_lag = inclusion_lag_within_limit(
            proposal.base_checkpoint_id,
            inclusion_checkpoint_id,
        )
            .ok_or_else(|| {
                GutaSubmitError::retryable(
                    RealmFinalizeSubmitCode::InvalidProposal,
                    format!(
                        "GUTA Proposal proof-base checkpoint {} is not within the maximum inclusion lag {} at inclusion checkpoint {}",
                        proposal.base_checkpoint_id,
                        psy_data::p2p::MAX_INCLUSION_LAG_CHECKPOINTS,
                        inclusion_checkpoint_id
                    ),
                )
            })?;
        let _ = inclusion_lag;
        let target_checkpoint_id = proposal
            .base_checkpoint_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("GUTA Proposal proof-base checkpoint overflow"))?;
        let rotation = parth_common::realm_rotation::RealmRotationConfig {
            checkpoints_per_epoch: *checkpoints_per_epoch,
            validator_sub_ids: occupied.clone(),
        };
        let epoch = parth_common::realm_rotation::epoch(target_checkpoint_id, *checkpoints_per_epoch);
        let anchor_checkpoint_id = parth_common::realm_rotation::anchor_checkpoint_id(epoch, *checkpoints_per_epoch);
        let anchor_leaf = self.db_reader.get_checkpoint_leaf_data(anchor_checkpoint_id).await?;
        let anchor_felts = anchor_leaf.stats.random_seed.to_4_felts();
        let anchor_seed = [
            anchor_felts[0].to_u64_value(),
            anchor_felts[1].to_u64_value(),
            anchor_felts[2].to_u64_value(),
            anchor_felts[3].to_u64_value(),
        ];
        let scheduled_proposer = rotation
            .proposer_sub_id(realm_id, target_checkpoint_id, anchor_seed)?
            .ok_or_else(|| anyhow::anyhow!("rotation enabled without a scheduled proposer"))?;
        if proposal.proposer_sub_id != scheduled_proposer {
            return Err(GutaSubmitError::retryable(
                RealmFinalizeSubmitCode::NotScheduledProposer,
                format!(
                    "GUTA Proposal proposer {} is not scheduled proposer {} for target {}",
                    proposal.proposer_sub_id,
                    scheduled_proposer,
                    target_checkpoint_id
                ),
            ).into());
        }
        let proposer = registry
            .get(&(realm_id, proposal.proposer_sub_id))
            .ok_or_else(|| anyhow::anyhow!("GUTA proposer sub_id {} is not occupied", proposal.proposer_sub_id))?;
        let output = build_bound_finalize_output::<N>(
            proposal.chain_id,
            proposal.realm_id,
            proposal.proposer_sub_id,
            proposer.validator_user_id,
            proof_base_roots.validator_tree_root,
            input,
        );
        let output_bytes = protocol_encode_finalize_output(&output)?;
        anyhow::ensure!(proposal.public_output_hash == sha256(&output_bytes), "GUTA Proposal public output hash mismatch");
        validate_certificate(&proposal, &certificate, &occupied, &keys).map_err(|error| {
            GutaSubmitError::illegal(
                RealmFinalizeSubmitCode::InvalidCertificate,
                format!("invalid GUTA Certificate for realm {realm_id}: {error}"),
            )
        })?;
        anyhow::ensure!(
            votes_meet_wait(occupied.len(), proposal.proposer_sub_id, &certificate.signer_sub_ids()),
            "GUTA Certificate for realm {realm_id} below replication wait"
        );
        anyhow::ensure!(
            certificate_includes_proposer(&certificate, proposal.proposer_sub_id),
            "GUTA Certificate for realm {realm_id} does not include proposer sub_id {}",
            proposal.proposer_sub_id
        );
        tracing::info!(
            "realm P2P certificate admitted realm={} inclusion_checkpoint_id={} signers={}",
            realm_id,
            inclusion_checkpoint_id,
            certificate.popcount()
        );
        Ok(())
    }

}
