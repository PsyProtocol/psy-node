use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use jsonrpsee::core::RpcResult;
use parth_core::{
    crypto::hash::{
        merkle_proof::{compute_historical_and_current_merkle_roots_core_gt, MerkleProofCore},
        traits::{MerkleZeroHasher, QFieldHashable},
    },
    data::{hash::merkle_node_key::SimpleMerkleNodeKey, queue::queue_key::QPBaseQueueType},
    felt::ToU64Value,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{QHasherBase, QNetworkDatabaseTypes, QNetworkTypesConfig, QZKProofVerifier},
    store::tag_tree_store,
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath,
};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_data::{
    proof_input::guta::{end_cap_input::SubmitUserEndCapNonProofInput, SubmitGUTARealmResultAPINoProofInput},
    v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{ContractCodeDefinition, DashMapContractHeightCache, PQBCDeployContract, PQEDContractLeaf, PSimpleContractHeightCache},
            public_key::PZKPublicKeyInfo,
            user::{self, PQEDUserLeaf},
        },
    },
};
use psy_node_core::{
    api::{coordinator::standard_edge_rpc::CoordinatorEdgeRpcServer, realm::standard_edge_rpc::RealmEdgeRpcServer},
    psy_core_db::{
        traits::full::{
            PsyCoordinatorEdgeAPIStoreReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmEdgeAPIStoreReader,
        },
        v3_implementation::full::PsyUnifiedCoreDatabaseStore,
    },
    psy_temp_db::{QTempDBPendingIdReader, StandardEdgeAPITempDBStoreBase},
    queue::{
        ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
        worker_queue::QStandardWorkerQueueSubscriber,
    },
    store::traits::{
        core_db::{CoreDatabaseStoreComboImpl, CoreDatabaseTableConfig},
        proof_store::QParthProofStore,
    },
};
use psy_serialize::{FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseSingle};

use crate::{coordinator::queue_key::CoordinatorRegisterUserPublicKeyQueueKey, realm::edge::error::RpcError};

const END_CAP_PROOF_CIRCUIT_TYPE_U32: u32 = ProvingJobCircuitType::UserEndCap as u32;
#[derive(Clone)]
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
        }
    }
    pub async fn get_latest_checkpoint_id_internal(&self) -> anyhow::Result<u64> {
        self.db_reader.get_latest_checkpoint_id().await
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
        let (unique_pending_id, unique_proc_checkpoint_id) = self.temp_db.get_unique_pending_ids(&self.realm_identifier).await?;

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

            Ok("test".to_string())
    }
    pub async fn deploy_contract_internal(&self, deploy_contract: PQBCDeployContract<N::QHash>) -> anyhow::Result<String> {
        todo!("todo")
    }
    pub async fn submit_guta_internal(
        &self,
        input: SubmitGUTARealmResultAPINoProofInput<N::F, N::QHash>,
        proof: N::ZKProof,
        realm_id: u64,
    ) -> anyhow::Result<String> {
        todo!("aa")
    }
}
