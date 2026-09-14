use std::sync::Arc;

use tokio::task;
use parth_core::{
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath, crypto::hash::{merkle_proof::MerkleProofCore, tag_tree::TagTreeMerkleProof, traits::QFieldHashable}, data::{hash::merkle_node_key::SimpleMerkleNodeKey, queue::queue_key::QPBaseQueueType}, felt::ToU64Value, node::realm_identifier::QRealmIdentifier, protocol::core_types::{Q256BitHash, QNetworkTypesConfig, QZKProofVerifier}
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_crypto::hash::tx_hash::{compute_deploy_contract_content_hash, compute_update_contract_content_hash, hash_to_hex};
use psy_api_core::CheckpointJobStats;
use psy_data::{
    guta::header_extended::{GlobalUserTreeAggregatorHeaderWithTagValueAndJobID, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType}, prepared_block::realm::PsyRealmCoordinatorUpdate, v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::PQEDCheckpointGlobalStateRoots, checkpoint_sync::PQEDCheckpointSyncInfoCompact, contract::{DashMapContractHeightCache, PQBCDeployContractV2, PQBCUpdateContract, PsyDeployContractQueueItemV2, PsyUpdateContractQueueItem}, public_key::PZKPublicKeyInfo
        },
    }
};
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorEdgeAPIStoreReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardEdgeAPITempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber},
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle};

use crate::coordinator::queue_key::{CoordinatorDeployContractQueueKey, CoordinatorRegisterUserPublicKeyQueueKey, CoordinatorSubmitRealmGUTAUpdateQueueKey, CoordinatorUpdateContractQueueKey};

pub type CanonicalLayoutProofVerifier =
    dyn Fn(&[u8]) -> anyhow::Result<()> + Send + Sync;

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
    pub contract_queue: Arc<DeployContractQueue>,
    pub get_proof_work_queue: Arc<GetProofWorkQueue>,

    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,

    pub proof_verifier: Arc<N::ZKVerifier>,
    pub contract_state_tree_height_cache: Arc<DashMapContractHeightCache<N::QHash>>,

    pub checkpoint_state_transition_circuit_fingerprint: N::QHash,
    pub canonical_layout_verifier_fingerprint: N::QHash,
    pub canonical_layout_proof_verifier: Arc<CanonicalLayoutProofVerifier>,
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
            contract_queue: self.contract_queue.clone(),
            get_proof_work_queue: self.get_proof_work_queue.clone(),
            realm_identifier: self.realm_identifier.clone(),
            realm_id_u64: self.realm_id_u64.clone(),
            realm_sub_id_u64: self.realm_sub_id_u64.clone(),
            proof_verifier: self.proof_verifier.clone(),
            contract_state_tree_height_cache: self.contract_state_tree_height_cache.clone(),
            checkpoint_state_transition_circuit_fingerprint: self.checkpoint_state_transition_circuit_fingerprint.clone(),
            canonical_layout_verifier_fingerprint: self.canonical_layout_verifier_fingerprint,
            canonical_layout_proof_verifier: self.canonical_layout_proof_verifier.clone(),
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
        contract_queue: Arc<DeployContractQueue>,
        get_proof_work_queue: Arc<GetProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        proof_verifier: Arc<N::ZKVerifier>,
        checkpoint_state_transition_circuit_fingerprint: N::QHash,
        canonical_layout_verifier_fingerprint: N::QHash,
        canonical_layout_proof_verifier: Arc<CanonicalLayoutProofVerifier>,
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
            contract_queue,
            get_proof_work_queue,
            realm_identifier,
            realm_id_u64,
            realm_sub_id_u64,
            proof_verifier,
            contract_state_tree_height_cache: Arc::new(DashMapContractHeightCache::new()),
            checkpoint_state_transition_circuit_fingerprint,
            canonical_layout_verifier_fingerprint,
            canonical_layout_proof_verifier,
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

    pub async fn get_update_contract_queue_key(
        &self,
    ) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId, CoordinatorUpdateContractQueueKey<N::F, N::QHash>)> {
        let (unique_pending_id, unique_proc_checkpoint_id) = self.temp_db.get_gathering_unique_pending_ids(&self.realm_identifier).await?;

        Ok((
            unique_pending_id,
            unique_proc_checkpoint_id,
            CoordinatorUpdateContractQueueKey {
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

    async fn validate_canonical_layout_proof(
        &self,
        claimed_fingerprint: N::QHash,
        proof: &[u8],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            claimed_fingerprint == self.canonical_layout_verifier_fingerprint,
            "canonical layout verifier fingerprint mismatch"
        );

        let verifier = self.canonical_layout_proof_verifier.clone();
        let proof = proof.to_vec();
        task::spawn_blocking(move || verifier(&proof))
            .await?
            .map_err(|error| {
                anyhow::anyhow!("canonical layout proof verification failed: {error}")
            })
    }

    pub async fn deploy_contract_internal(
        &self,
        deploy_contract: PQBCDeployContractV2<N::QHash>,
    ) -> anyhow::Result<String> {
        deploy_contract.validate_shape()?;

        let function_count = deploy_contract
            .deploy_contract
            .code_definition
            .functions
            .len();
        anyhow::ensure!(
            function_count != 0,
            "contracts with no functions are not supported"
        );
        anyhow::ensure!(
            function_count <= (1usize << N::CONTRACT_FUNCTION_TREE_HEIGHT),
            "contract has too many functions defined"
        );

        self.validate_canonical_layout_proof(
            deploy_contract.canonical_layout_verifier_fingerprint,
            &deploy_contract.canonical_layout_proof,
        )
        .await?;

        let PQBCDeployContractV2 {
            deploy_contract,
            layout_protocol_version,
            state_layout_root,
            state_layout_field_count,
            state_layout_slot_count,
            canonical_layout_verifier_fingerprint,
            canonical_layout_proof,
        } = deploy_contract;
        let (deployer, code_definition, function_leaves, code_root) =
            deploy_contract.split_into_tuple();
        let queue_item =
            PsyDeployContractQueueItemV2::<N::F, N::QHash>::
                new_from_layout_endpoint::<N::HasherBase>(
                    deployer,
                    code_definition.state_tree_height,
                    function_leaves,
                    code_root,
                    N::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE,
                    layout_protocol_version,
                    state_layout_root,
                    state_layout_field_count,
                    state_layout_slot_count,
                    canonical_layout_verifier_fingerprint,
                    canonical_layout_proof,
                )?;

        let (unique_pending_id, unique_proc_checkpoint_id, queue_key) =
            self.get_deploy_contract_queue_key().await?;
        let deploy_content_hash = compute_deploy_contract_content_hash(
            &queue_item.contract_leaf.deployer.into_owned_32bytes(),
            &queue_item
                .contract_leaf
                .function_tree_root
                .into_owned_32bytes(),
            code_definition.state_tree_height as u64,
        );
        self.temp_db
            .set_deploy_contract_code_definition_raw(
                &self.realm_identifier,
                unique_pending_id,
                &queue_item.rand_key_id,
                code_definition.psy_ser_into_bytes_vec()?,
            )
            .await?;
        self.contract_queue
            .publish_ephemeral_queue_item_owned_bytes(
                &queue_key,
                self.realm_id_u64,
                self.realm_sub_id_u64,
                unique_proc_checkpoint_id,
                0,
                queue_item.psy_ser_into_bytes_vec()?,
            )
            .await?;
        Ok(hash_to_hex(&deploy_content_hash))
    }

    pub async fn update_contract_internal(&self, update_contract: PQBCUpdateContract<N::QHash>) -> anyhow::Result<String> {
        update_contract.validate_shape()?;
        if update_contract.code_definition.functions.len() == 0 {
            anyhow::bail!("contracts with no functions are not supported");
        } else if update_contract.code_definition.functions.len() > (1usize << N::CONTRACT_FUNCTION_TREE_HEIGHT) {
            anyhow::bail!("contract has too many functions defined");
        }

        if update_contract.contract_id == 0 {
            anyhow::bail!("contract id 0 is reserved and cannot be updated");
        }

        // Auth check: the contract must already exist on chain and the caller must
        // be the original deployer. NOTE: db_reader reflects the last committed
        // checkpoint state; updates gathered in the current pending block are not
        // visible here, so the gatherer must re-validate against its in-memory
        // global contract tree (TODO in the update contract gatherer phase).
        let latest_checkpoint_id =
            self.get_latest_checkpoint_id_internal().await?;
        let existing_leaf = self
            .db_reader
            .get_contract_leaf(
                latest_checkpoint_id,
                update_contract.contract_id,
            )
            .await
            .map_err(|_| anyhow::anyhow!("contract with id {} does not exist", update_contract.contract_id))?;

        if existing_leaf.deployer != update_contract.deployer {
            anyhow::bail!(
                "only the original deployer can update contract {}",
                update_contract.contract_id
            );
        }
        anyhow::ensure!(
            existing_leaf.state_tree_height.to_u64_value()
                == update_contract.code_definition.state_tree_height as u64,
            "contract state tree height is immutable"
        );

        self.validate_canonical_layout_proof(
            update_contract.canonical_layout_verifier_fingerprint,
            &update_contract.canonical_layout_proof,
        )
        .await?;

        let (unique_pending_id, unique_proc_checkpoint_id, queue_key) = self.get_update_contract_queue_key().await?;

        let PQBCUpdateContract {
            contract_id,
            deployer,
            code_definition,
            function_whitelist: function_leaves,
            code_root,
            layout_protocol_version,
            state_layout_root,
            state_layout_field_count,
            state_layout_slot_count,
            canonical_layout_verifier_fingerprint,
            canonical_layout_proof,
        } = update_contract;
        let queue_item = PsyUpdateContractQueueItem::<N::F, N::QHash>::new_from_leaves_and_deployer::<N::HasherBase>(
            contract_id,
            deployer,
            // state tree height is immutable: always reuse the on-chain value
            existing_leaf.state_tree_height.to_u64_value() as u16,
            state_layout_root,
            state_layout_field_count,
            state_layout_slot_count,
            layout_protocol_version,
            canonical_layout_verifier_fingerprint,
            canonical_layout_proof,
            function_leaves,
            code_root,
            N::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE,
        )?;
        let update_content_hash = compute_update_contract_content_hash(
            contract_id,
            &queue_item.contract_leaf.deployer.into_owned_32bytes(),
            &queue_item.contract_leaf.function_tree_root.into_owned_32bytes(),
            queue_item.contract_leaf.state_tree_height.to_u64_value(),
        );
        let update_content_hash_hex = hash_to_hex(&update_content_hash);

        // reuse the deploy contract code definition temp db storage (keyed by
        // realm + unique_pending_id + rand_key_id) to keep changes minimal
        self.temp_db
            .set_deploy_contract_code_definition_raw(
                &self.realm_identifier,
                unique_pending_id,
                &queue_item.rand_key_id,
                code_definition.psy_ser_into_bytes_vec()?,
            )
            .await?;
        tracing::info!("Stored update contract code definition raw in temp DB for pending id {} with rand key {:?}", unique_pending_id, &queue_item.rand_key_id);

        self.contract_queue
            .publish_ephemeral_queue_item_owned_bytes(
                &queue_key,
                self.realm_id_u64,
                self.realm_sub_id_u64,
                unique_proc_checkpoint_id,
                0,
                queue_item.psy_ser_into_bytes_vec()?,
            )
            .await?;

        Ok(update_content_hash_hex)
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
    ) -> anyhow::Result<()>
    where
        N::ZKVerifier: 'static,
    {
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
        self.ensure_guta_matches_current_coordinator_state(realm_id_u64, &input).await?;

        let status = rand::random::<u64>() & 0x0fff_ffff_ffff_ffff;
        if self
            .temp_db
            .get_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, realm_id_u64)
            .await?
            != 0
        {
            anyhow::bail!(
                "GUTA for realm_id {} at unique_pending_id {} has already been submitted",
                realm_id,
                unique_pending_id
            );
        }
        self.temp_db
            .set_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, realm_id_u64, status)
            .await?;

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
        if self
            .temp_db
            .get_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, realm_id_u64)
            .await?
            != status
        {
            anyhow::bail!(
                "RACE: GUTA for realm_id {} at unique_pending_id {} has already been submitted",
                realm_id,
                unique_pending_id
            );
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::coordinator::processor::db::PsyCoordinatorDatabaseProcessor;
    use crate::test_common::{
        create_test_unified_db, FakeEphemeralQueuePublisher, FakeEphemeralQueueSubscriber,
        FakeWorkerQueuePublisher, FakeWorkerQueueSubscriber, TestNetworkConfig,
        TestUnifiedDatabaseStore,
    };
    use parth_core::{
        crypto::hash::traits::MerkleZeroHasher,
        felt::{FromPrimitiveValuesFelt, ToU64Value},
        node::realm_identifier::QRealmIdentifier,
        protocol::core_types::QNetworkTreeConstants,
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::{
        config::network_config::PsyNodeCircuitFingerprintConfig,
        genesis::genesis_block_setup::PsyGenesisBlockSetupData,
        v1::qdata::{
            checkpoint::PQEDCheckpointLeafStats,
            contract::{
                ContractCodeDefinition, ContractFunctionCodeDefinition, PQBCDeployContract,
                PQEDContractLeafV2,
            },
        },
    };
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
        psy_core_db::traits::full::{
            PsyNodeCheckpointObjectDatabaseReader, PsyNodeCoreDatabaseContractObjectStoreReader,
            PsyNodeCoreDatabaseContractObjectStoreWriter, PsyNodeCoreRewardsTagTreeStoreWriter,
            PsyNodeGlobalUserTreeDatabaseReader, PsyNodeGlobalUserTreeDatabaseWriter,
        },
        psy_temp_db::{
            QTempDBPendingIdWriter, QTempDBSubmitStatusReader, QTempDBSubmitStatusWriter,
        },
        store::traits::proof_store::QParthProofStoreReader,
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    type N = TestNetworkConfig;

    type TestHandler = CoordinatorEdgeHandler<
        N,
        TestUnifiedDatabaseStore,
        TestUnifiedDatabaseStore,
        FakeEphemeralQueuePublisher,
        FakeEphemeralQueuePublisher,
        FakeEphemeralQueuePublisher,
        FakeWorkerQueueSubscriber,
        InMemoryTempStore,
        InMemoryTempStore,
    >;

    type TestProcessor = PsyCoordinatorDatabaseProcessor<
        N,
        TestUnifiedDatabaseStore,
        TestUnifiedDatabaseStore,
        FakeEphemeralQueueSubscriber,
        FakeEphemeralQueueSubscriber,
        FakeEphemeralQueueSubscriber,
        FakeWorkerQueuePublisher,
        InMemoryTempStore,
        InMemoryTempStore,
        SimpleMockMemoryFileSystem,
    >;

    fn zh(level: usize) -> PHash {
        parth_core::pgoldilocks::PoseidonHasher::get_zero_hash(level)
    }

    fn fingerprint_config() -> PsyNodeCircuitFingerprintConfig<PHash> {
        PsyNodeCircuitFingerprintConfig {
            guta_circuit_whitelist_root: zh(21),
            register_users_circuit_whitelist_root: zh(22),
            deploy_contracts_circuit_whitelist_root: zh(23),
            update_contracts_circuit_whitelist_root: zh(24),
            checkpoint_state_transition_circuit_fingerprint: zh(25),
            genesis_checkpoint_state_transition_fingerprint: zh(26),
        }
    }

    fn genesis_setup_data() -> PsyGenesisBlockSetupData<PF, PHash> {
        let contract = PQBCDeployContract::new(
            PHash::from_values(1, 0, 0, 0),
            ContractCodeDefinition { state_tree_height: 8, functions: vec![] },
            vec![PHash::from_values(2, 0, 0, 0)],
            PHash::from_values(3, 0, 0, 0),
        );
        PsyGenesisBlockSetupData {
            contracts: vec![contract],
            users: vec![],
            checkpoint_stats: PQEDCheckpointLeafStats::qp_rand_gen(),
            deposit_tree_root: PHash::from_values(4, 0, 0, 0),
            withdrawal_tree_root: PHash::from_values(5, 0, 0, 0),
        }
    }

    /// Handler wired to a fresh in-memory database; `commit_genesis` optionally
    /// drives the real genesis commit through the database processor so the
    /// handler reads committed state.
    pub(crate) struct EdgeTestEnv {
        pub(crate) handler: TestHandler,
        pub(crate) db: Arc<TestUnifiedDatabaseStore>,
        pub(crate) guta_queue: Arc<FakeEphemeralQueuePublisher>,
        pub(crate) register_queue: Arc<FakeEphemeralQueuePublisher>,
        pub(crate) contract_queue: Arc<FakeEphemeralQueuePublisher>,
        pub(crate) work_queue: Arc<FakeWorkerQueueSubscriber>,
        pub(crate) temp_db: Arc<InMemoryTempStore>,
    }

    impl EdgeTestEnv {
        pub(crate) async fn create() -> anyhow::Result<Self> {
            let db = Arc::new(create_test_unified_db().await?);
            let tag_tree = Arc::clone(&db);
            let temp_db = Arc::new(InMemoryTempStore::new("coord_edge_test".to_string(), 1, 2));
            let proof_store = Arc::clone(&temp_db);
            let guta_queue = Arc::new(FakeEphemeralQueuePublisher::new());
            let register_queue = Arc::new(FakeEphemeralQueuePublisher::new());
            let contract_queue = Arc::new(FakeEphemeralQueuePublisher::new());
            let work_queue = Arc::new(FakeWorkerQueueSubscriber::new());
            let handler = CoordinatorEdgeHandler::new(
                Arc::clone(&db),
                tag_tree,
                Arc::clone(&temp_db),
                proof_store,
                Arc::clone(&guta_queue),
                Arc::clone(&register_queue),
                Arc::clone(&contract_queue),
                Arc::clone(&work_queue),
                QRealmIdentifier::new(1, 2),
                Arc::new(crate::test_common::TestZKVerifier {}),
                zh(25),
                PHash::from_values(7, 0, 0, 0),
                Arc::new(|proof| {
                    anyhow::ensure!(
                        proof == [1, 2, 3, 4] || proof == [5, 6, 7, 8],
                        "test canonical layout proof is invalid"
                    );
                    Ok(())
                }),
            );
            // A fresh InMemoryTempStore errors on pending-id reads ("Unique
            // pending ids not found") while the unified db answers (0, 0);
            // seed both counters so handler reads behave like production.
            let rid = QRealmIdentifier::new(1, 2);
            temp_db.set_unique_pending_ids(&rid, 0, 0).await?;
            temp_db.set_gathering_unique_pending_ids(&rid, 0, 0).await?;
            Ok(Self { handler, db, guta_queue, register_queue, contract_queue, work_queue, temp_db })
        }

        /// Commits genesis through a real database processor sharing the same
        /// underlying unified store, then returns the processor for inspection.
        pub(crate) async fn commit_genesis(&self) -> anyhow::Result<TestProcessor> {
            let guta_sub = Arc::new(FakeEphemeralQueueSubscriber::new());
            let register_sub = Arc::new(FakeEphemeralQueueSubscriber::new());
            let deploy_sub = Arc::new(FakeEphemeralQueueSubscriber::new());
            let proof_pub = Arc::new(FakeWorkerQueuePublisher::new());
            let file_system = Arc::new(SimpleMockMemoryFileSystem::new());
            let genesis_data = genesis_setup_data();
            let fp_config = fingerprint_config();
            let (genesis_transition, genesis_block_update) =
                GenesisDatabaseDataBuilder::<PF, PHash>::setup_for_coordinator::<
                    parth_core::pgoldilocks::PoseidonHasher,
                    N,
                >(&genesis_data, fp_config.checkpoint_state_transition_circuit_fingerprint)?;
            let mut processor = TestProcessor::new_init(
                Arc::clone(&self.db),
                Arc::clone(&self.db),
                Arc::new(InMemoryTempStore::new("coord_edge_genesis".to_string(), 1, 2)),
                Arc::new(InMemoryTempStore::new("coord_edge_genesis".to_string(), 1, 2)),
                guta_sub,
                register_sub,
                deploy_sub,
                proof_pub,
                QRealmIdentifier::new(1, 2),
                fp_config,
                genesis_transition,
                file_system,
                "checkpoint_tree_backup.bin".to_string(),
            )
            .await?;
            processor
                .commit_state(
                    genesis_block_update,
                    psy_core::job::job_id::ProvingJobCircuitType::GenesisBlockCheckpointStateTransition,
                    vec![],
                )
                .await?;
            Ok(processor)
        }
    }

    #[tokio::test]
    async fn queue_key_helpers_reflect_gathering_ids_and_realm() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;
        let handler = &env.handler;

        let (pending, proc_id, register_key) = handler.get_register_user_queue_key().await?;
        assert_eq!((pending, proc_id), (0, 0));
        assert_eq!(register_key.realm_id, 1);
        assert_eq!(register_key.realm_sub_id, 2);
        assert_eq!(register_key.unique_id, proc_id);
        assert_eq!(register_key.task_group, 0);

        let (_, _, deploy_key) = handler.get_deploy_contract_queue_key().await?;
        assert_eq!(deploy_key.realm_id, 1);
        assert_eq!(deploy_key.realm_sub_id, 2);

        let (_, _, update_key) = handler.get_update_contract_queue_key().await?;
        assert_eq!(update_key.realm_id, 1);
        assert_eq!(update_key.realm_sub_id, 2);
        Ok(())
    }

    #[tokio::test]
    async fn register_user_publishes_public_key_to_queue() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;
        let public_key = PZKPublicKeyInfo::<PHash>::qp_rand_gen();

        let result = env.handler.register_user_internal(public_key.clone()).await?;
        assert_eq!(result, "ok");
        assert_eq!(env.register_queue.published_count(), 1);
        let published = env.register_queue.published_bytes_for(0);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0], public_key.psy_ser_into_bytes_vec()?);
        Ok(())
    }

    #[tokio::test]
    async fn checkpoint_leaves_batch_raw_validates_count_and_serializes() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;

        let err = env
            .handler
            .get_checkpoint_leaves_batch_raw_internal(0, 20001)
            .await
            .expect_err("count above the maximum must be rejected");
        assert!(err.to_string().contains("exceeds maximum"), "unexpected error: {err}");

        // on a fresh database the latest checkpoint is 0, so only the genesis
        // leaf node comes back even when more are requested
        let raw = env.handler.get_checkpoint_leaves_batch_raw_internal(0, 5).await?;
        assert!(!raw.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn job_stats_require_pending_mapping_and_default_to_zero() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;

        // no pending-id mapping exists on a fresh database
        let err = env
            .handler
            .get_job_stats_internal(0)
            .await
            .expect_err("stats for a checkpoint without pending mapping must fail");
        assert!(err.to_string().contains("no unique pending id"), "unexpected error: {err}");

        env.commit_genesis().await?;
        let stats = env.handler.get_job_stats_internal(0).await?;
        assert_eq!(stats.unique_pending_id, 0);
        assert_eq!(stats.total_completed, 0);
        assert_eq!(stats.total_duration_ms, 0);
        Ok(())
    }

    #[tokio::test]
    async fn pending_id_accessors_and_submit_guard() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;
        let handler = &env.handler;

        assert_eq!(handler.get_current_unique_pending_id_internal().await?, (0, 0));
        assert_eq!(handler.get_current_gathering_unique_pending_id_internal().await?, (0, 0));
        // no pending-id mapping exists on a fresh database
        assert_eq!(handler.get_checkpoint_id_for_unique_pending_id_internal(0).await?, None);
        // genesis commit records pending id 0 -> checkpoint 0
        env.commit_genesis().await?;
        assert_eq!(handler.get_checkpoint_id_for_unique_pending_id_internal(0).await?, Some(0));

        // nothing submitted yet: guard passes, then fails once a status is set
        handler.ensure_realm_has_not_submitted(0, 0).await?;
        env.temp_db
            .set_submitted_status_for_pending(&QRealmIdentifier::new(1, 2), 0, 0, 7)
            .await?;
        let err = handler
            .ensure_realm_has_not_submitted(0, 0)
            .await
            .expect_err("a submitted realm must be rejected");
        assert!(err.to_string().contains("already been submitted"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn realm_sync_info_reads_committed_genesis_state() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;
        let processor = env.commit_genesis().await?;

        let update = env.handler.get_realm_sync_info_internal(0, 0).await?;
        assert_eq!(update.checkpoint_sync_info.checkpoint_id, 0);
        assert_eq!(update.checkpoint_sync_info.coordinator_id, 1);
        assert_eq!(update.checkpoint_sync_info.coordinator_sub_id, 2);
        assert_eq!(update.checkpoint_sync_info.coordinator_unique_pending_id, 0);
        assert_eq!(update.checkpoint_sync_info.checkpoint_leaf, processor.last_committed.checkpoint_leaf);
        assert_eq!(update.checkpoint_sync_info.state_roots, processor.last_committed.checkpoint_state_roots);
        assert_eq!(update.checkpoint_sync_info.block_state, processor.last_committed.l2_state);
        // no reward tree node key exists at genesis: the proof is the empty one
        assert!(update.reward_tree_top_proof.is_empty());

        // a checkpoint that was never committed must fail
        assert!(env.handler.get_realm_sync_info_internal(0, 9).await.is_err());
        Ok(())
    }

    fn valid_deploy_contract_v2() -> PQBCDeployContractV2<PHash> {
        let deploy_contract = PQBCDeployContract::new(
            PHash::from_values(9, 0, 0, 0),
            ContractCodeDefinition {
                state_tree_height: 8,
                functions: vec![ContractFunctionCodeDefinition::qp_rand_gen()],
            },
            vec![PHash::from_values(2, 0, 0, 0)],
            PHash::from_values(3, 0, 0, 0),
        );
        PQBCDeployContractV2 {
            deploy_contract,
            layout_protocol_version: 1,
            state_layout_root: PHash::from_values(6, 0, 0, 0),
            state_layout_field_count: 1,
            state_layout_slot_count: 4,
            canonical_layout_verifier_fingerprint: PHash::from_values(7, 0, 0, 0),
            canonical_layout_proof: vec![1, 2, 3, 4],
        }
    }

    #[tokio::test]
    async fn deploy_contract_publishes_queue_item_and_content_hash() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;

        let hex = env.handler.deploy_contract_internal(valid_deploy_contract_v2()).await?;
        assert_eq!(hex.len(), 64, "content hash must be a 64-char hex string");
        assert_eq!(env.contract_queue.published_count(), 1);

        // shape validation: zero layout protocol version is rejected before publishing
        let mut bad = valid_deploy_contract_v2();
        bad.layout_protocol_version = 0;
        let err = env.handler.deploy_contract_internal(bad).await.expect_err("invalid shape must fail");
        assert!(err.to_string().contains("layout protocol version"), "unexpected error: {err}");
        assert_eq!(env.contract_queue.published_count(), 1);

        // The claimed verifier fingerprint must match the verifier configured
        // by the node before the request can reach the queue.
        let mut bad_fingerprint = valid_deploy_contract_v2();
        bad_fingerprint.canonical_layout_verifier_fingerprint =
            PHash::from_values(8, 0, 0, 0);
        let err = env
            .handler
            .deploy_contract_internal(bad_fingerprint)
            .await
            .expect_err("wrong canonical layout verifier fingerprint must fail");
        assert!(err.to_string().contains("fingerprint mismatch"), "unexpected error: {err}");
        assert_eq!(env.contract_queue.published_count(), 1);

        // Matching metadata is insufficient: the proof bytes themselves must
        // verify against the node's canonical layout circuit.
        let mut bad_proof = valid_deploy_contract_v2();
        bad_proof.canonical_layout_proof = vec![4, 3, 2, 1];
        let err = env
            .handler
            .deploy_contract_internal(bad_proof)
            .await
            .expect_err("invalid canonical layout proof must fail");
        assert!(err.to_string().contains("proof verification failed"), "unexpected error: {err}");
        assert_eq!(env.contract_queue.published_count(), 1);

        // contracts without functions are rejected
        let mut no_functions = valid_deploy_contract_v2();
        no_functions.deploy_contract = PQBCDeployContract::new(
            PHash::from_values(9, 0, 0, 0),
            ContractCodeDefinition { state_tree_height: 8, functions: vec![] },
            vec![PHash::from_values(2, 0, 0, 0)],
            PHash::from_values(3, 0, 0, 0),
        );
        let err = env.handler.deploy_contract_internal(no_functions).await.expect_err("empty contract must fail");
        assert!(err.to_string().contains("no functions"), "unexpected error: {err}");
        assert_eq!(env.contract_queue.published_count(), 1);
        Ok(())
    }

    async fn seed_contract(db: &TestUnifiedDatabaseStore) -> anyhow::Result<()> {
        let leaf = PQEDContractLeafV2::<PF, PHash> {
            deployer: PHash::from_values(11, 0, 0, 0),
            function_tree_root: PHash::from_values(12, 0, 0, 0),
            code_root: PHash::from_values(13, 0, 0, 0),
            state_tree_height: PF::from_u64_value(8),
            state_layout_root: PHash::from_values(14, 0, 0, 0),
            state_layout_field_count: PF::from_u64_value(1),
            state_layout_slot_count: PF::from_u64_value(4),
        };
        db.set_contract_leaf(0, 1, &leaf).await?;
        Ok(())
    }

    fn valid_update_contract() -> PQBCUpdateContract<PHash> {
        PQBCUpdateContract {
            contract_id: 1,
            deployer: PHash::from_values(11, 0, 0, 0),
            code_definition: ContractCodeDefinition {
                state_tree_height: 8,
                functions: vec![ContractFunctionCodeDefinition::qp_rand_gen()],
            },
            function_whitelist: vec![PHash::from_values(15, 0, 0, 0)],
            code_root: PHash::from_values(16, 0, 0, 0),
            layout_protocol_version: 1,
            state_layout_root: PHash::from_values(17, 0, 0, 0),
            state_layout_field_count: 1,
            state_layout_slot_count: 4,
            canonical_layout_verifier_fingerprint: PHash::from_values(7, 0, 0, 0),
            canonical_layout_proof: vec![5, 6, 7, 8],
        }
    }

    #[tokio::test]
    async fn update_contract_validates_against_committed_state() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;
        seed_contract(&env.db).await?;
        let handler = &env.handler;

        // happy path: original deployer, immutable height kept as committed
        let hex = handler.update_contract_internal(valid_update_contract()).await?;
        assert_eq!(hex.len(), 64);
        assert_eq!(env.contract_queue.published_count(), 1);

        let mut bad_fingerprint = valid_update_contract();
        bad_fingerprint.canonical_layout_verifier_fingerprint =
            PHash::from_values(18, 0, 0, 0);
        let err = handler
            .update_contract_internal(bad_fingerprint)
            .await
            .expect_err("wrong canonical layout verifier fingerprint must fail");
        assert!(err.to_string().contains("fingerprint mismatch"), "unexpected error: {err}");
        assert_eq!(env.contract_queue.published_count(), 1);

        let mut bad_proof = valid_update_contract();
        bad_proof.canonical_layout_proof = vec![8, 7, 6, 5];
        let err = handler
            .update_contract_internal(bad_proof)
            .await
            .expect_err("invalid canonical layout proof must fail");
        assert!(err.to_string().contains("proof verification failed"), "unexpected error: {err}");
        assert_eq!(env.contract_queue.published_count(), 1);

        // reserved contract id 0
        let mut bad = valid_update_contract();
        bad.contract_id = 0;
        let err = handler.update_contract_internal(bad).await.expect_err("contract id 0 must be rejected");
        assert!(err.to_string().contains("non-zero"), "unexpected error: {err}");

        // unknown contract id
        let mut unknown = valid_update_contract();
        unknown.contract_id = 9;
        let err = handler.update_contract_internal(unknown).await.expect_err("unknown contract must be rejected");
        assert!(err.to_string().contains("does not exist"), "unexpected error: {err}");

        // wrong deployer
        let mut other_deployer = valid_update_contract();
        other_deployer.deployer = PHash::from_values(99, 0, 0, 0);
        let err = handler.update_contract_internal(other_deployer).await.expect_err("wrong deployer must be rejected");
        assert!(err.to_string().contains("only the original deployer"), "unexpected error: {err}");

        // state tree height is immutable
        let mut other_height = valid_update_contract();
        other_height.code_definition = ContractCodeDefinition {
            state_tree_height: 9,
            functions: vec![ContractFunctionCodeDefinition::qp_rand_gen()],
        };
        let err = handler.update_contract_internal(other_height).await.expect_err("height change must be rejected");
        assert!(err.to_string().contains("immutable"), "unexpected error: {err}");

        // no functions
        let mut no_functions = valid_update_contract();
        no_functions.code_definition.functions = vec![];
        let err = handler.update_contract_internal(no_functions).await.expect_err("empty contract must be rejected");
        assert!(err.to_string().contains("no functions"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn batch_reward_proofs_empty_and_seeded() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;

        // no jobs requested: no proofs
        let empty = env.handler.generate_batch_proof_miner_reward_proofs_internal(0, vec![]).await?;
        assert!(empty.is_empty());

        // seed one node in the rewards tag tree and request its proof
        let root_key = parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey::new_root();
        env.db
            .rewards_tag_tree_set_node_tag(0, root_key, zh(40), zh(41))
            .await?;
        let job_id = QProvingJobDataIDWithRewardPath::new(
            QProvingJobDataID::qp_rand_gen(),
            root_key.to_reward_path_info(),
        );
        let proofs = env
            .handler
            .generate_batch_proof_miner_reward_proofs_internal(0, vec![job_id])
            .await?;
        assert_eq!(proofs.len(), 1);
        Ok(())
    }

    fn guta_input() -> GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<PF, PHash> {
        let mut input = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType::<PF, PHash>::qp_rand_gen();
        input.header.header.state_transition.node_level = PF::from_u64_value(
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as u64,
        );
        input.header.header.state_transition.node_index = PF::from_u64_value(0);
        input.job_type_u32 = psy_core::job::job_id::ProvingJobCircuitType::GUTANoChange as u32;
        input
    }

    #[tokio::test]
    async fn submit_guta_rejects_invalid_headers() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;
        let handler = &env.handler;

        // wrong node level
        let mut bad_level = guta_input();
        bad_level.header.header.state_transition.node_level = PF::from_u64_value(5);
        let err = handler.submit_guta_internal(bad_level, vec![]).await.expect_err("wrong level must fail");
        assert!(err.to_string().contains("invalid realm level"), "unexpected error: {err}");

        // realm id beyond the coordinator tree capacity
        let mut bad_realm = guta_input();
        bad_realm.header.header.state_transition.node_index =
            PF::from_u64_value((1u64 << N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT) + 1);
        let err = handler.submit_guta_internal(bad_realm, vec![]).await.expect_err("invalid realm id must fail");
        assert!(err.to_string().contains("invalid realm id"), "unexpected error: {err}");

        // unknown circuit type
        let mut bad_type = guta_input();
        bad_type.job_type_u32 = 999_999;
        assert!(handler.submit_guta_internal(bad_type, vec![]).await.is_err());

        // stale realm root
        let mut stale = guta_input();
        stale.header.header.state_transition.old_node_value = PHash::from_values(123, 0, 0, 0);
        let err = handler.submit_guta_internal(stale, vec![]).await.expect_err("stale root must fail");
        assert!(err.to_string().contains("stale GUTA update rejected"), "unexpected error: {err}");

        // double submission for the same realm + pending id
        let mut input = guta_input();
        let realm_key = parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey {
            level: N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            index: 0,
        };
        let current_root = env
            .db
            .global_user_tree_get_node_and_checkpoint_id_max_checkpoint(0, &realm_key)
            .await?;
        input.header.header.state_transition.old_node_value = current_root.value;
        env.temp_db
            .set_submitted_status_for_pending(&QRealmIdentifier::new(1, 2), 0, 0, 1)
            .await?;
        let err = handler.submit_guta_internal(input, vec![]).await.expect_err("double submit must fail");
        assert!(err.to_string().contains("already been submitted"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn submit_guta_rejects_realm_id_at_tree_capacity() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;
        let handler = &env.handler;
        let mut input = guta_input();
        input.header.header.state_transition.node_index =
            PF::from_u64_value(1u64 << N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);

        let err = handler
            .submit_guta_internal(input, vec![])
            .await
            .expect_err("realm id equal to tree capacity must fail");
        assert!(err.to_string().contains("invalid realm id"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn submit_guta_happy_path_stores_proof_and_publishes() -> anyhow::Result<()> {
        let env = EdgeTestEnv::create().await?;
        let handler = &env.handler;

        let mut input = guta_input();
        let realm_key = parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey {
            level: N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            index: 0,
        };
        let current_root = env
            .db
            .global_user_tree_get_node_and_checkpoint_id_max_checkpoint(0, &realm_key)
            .await?;
        input.header.header.state_transition.old_node_value = current_root.value;

        handler.submit_guta_internal(input, vec![]).await?;

        // the queue item was published and the proof stored for the derived job id
        assert_eq!(env.guta_queue.published_count(), 1);
        let job_id = QProvingJobDataID::try_get_coordinator_edge_proof_store_output_proof_id_for_realm_submit(
            0,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            0,
            psy_core::job::job_id::ProvingJobCircuitType::GUTANoChange,
        )?;
        assert!(env.temp_db.contains_proof_for_job_id(job_id, 0).await?);

        // a second submission for the same realm is rejected by the status guard
        let mut second = guta_input();
        second.header.header.state_transition.old_node_value = current_root.value;
        let err = handler.submit_guta_internal(second, vec![]).await.expect_err("double submit must fail");
        assert!(err.to_string().contains("already been submitted"), "unexpected error: {err}");
        Ok(())
    }
}
