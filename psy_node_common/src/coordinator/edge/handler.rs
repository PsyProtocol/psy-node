use std::sync::Arc;

use parth_core::{
    crypto::hash::traits::QFieldHashable,
    data::{hash::merkle_node_key::SimpleMerkleNodeKey, queue::queue_key::QPBaseQueueType},
    felt::ToU64Value,
    node::{realm_identifier::QRealmIdentifier, traits::realm},
    protocol::core_types::{QNetworkTypesConfig, QZKProofVerifier},
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::header_extended::{GlobalUserTreeAggregatorHeaderWithTagValueAndJobID, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType},
    v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            contract::{DashMapContractHeightCache, PQBCDeployContract, PsyDeployContractQueueItem},
            public_key::PZKPublicKeyInfo,
        },
    },
};
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorEdgeAPIStoreReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::{QTempDBPendingIdReader, StandardEdgeAPITempDBStoreBase},
    queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber},
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::coordinator::queue_key::{
    CoordinatorDeployContractQueueKey, CoordinatorRegisterUserPublicKeyQueueKey, CoordinatorSubmitRealmGUTAUpdateQueueKey,
};

const END_CAP_PROOF_CIRCUIT_TYPE_U32: u32 = ProvingJobCircuitType::UserEndCap as u32;
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
        }
    }
    pub async fn get_latest_checkpoint_id_internal(&self) -> anyhow::Result<u64> {
        self.db_reader.get_latest_checkpoint_id().await
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

    pub async fn register_user_internal(&self, public_key: PZKPublicKeyInfo<N::QHash>) -> anyhow::Result<String> {
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

        let (deployer, code_definition, function_leaves) = deploy_contract.split_into_tuple();
        let queue_item = PsyDeployContractQueueItem::<N::F, N::QHash>::new_from_leaves_and_deployer::<N::HasherBase>(
            deployer,
            code_definition.state_tree_height,
            function_leaves,
            N::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE,
        )?;

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

        Ok("ok".to_string())
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
    ) -> anyhow::Result<()> {
        let realm_level_u64 = input.header.header.state_transition.node_level.to_u64_value();
        if realm_level_u64 != N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as u64 {
            anyhow::bail!(
                "invalid realm level {}, expected {}",
                realm_level_u64,
                N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT
            );
        }
        let realm_id_u64 = input.header.header.state_transition.node_index.to_u64_value();

        let realm_level = realm_level_u64 as u8;
        if realm_id_u64 > (1u64 << realm_level) || realm_id_u64 > u32::MAX as u64 {
            anyhow::bail!("invalid realm id {}", realm_id_u64);
        }

        let realm_id = realm_id_u64 as u32;
        let proving_circuit_type = ProvingJobCircuitType::try_from_u32(input.job_type_u32)?;

        let (unique_pending_id, proc_checkpoint_id) = self.get_current_gathering_unique_pending_id_internal().await?;

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
        self.proof_verifier
            .verify_zk_proof_from_slice_check_public_inputs_hash(input.job_type_u32, &proof_bytes, expected_public_inputs_hash)?;
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
        self.proof_store.put_proof_bytes_for_job_id(&output_proof_job_id, &proof_bytes).await?;

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
}
