use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use parth_core::{
    QProvingJobDataIDWithRewardPath, crypto::{hash::
        merkle_proof::MerkleProofCore, secp256k1::{QEDCompressedSecp256K1Signature, SimpleTimedRequest}}, data::hash::merkle_node_key::SimpleMerkleNodeKey, protocol::core_types::QNetworkTypesConfig
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType, proof_input::guta::SubmitGUTARealmResultAPINoProofInput, v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{ContractCodeDefinition, PQBCDeployContract, PQEDContractLeaf},
            public_key::PZKPublicKeyInfo,
            user::PQEDUserLeaf,
        },
    }, worker::api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse}
};
use psy_node_core::{
    api::{coordinator::standard_edge_rpc::CoordinatorEdgeRpcServer, worker::standard_worker_rpc::NodeEdgeWorkerRpcServer},
    psy_core_db::
        traits::full::{
            PsyCoordinatorEdgeAPIStoreReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
        }
    ,
    psy_temp_db::StandardEdgeAPITempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueuePublisher,
        worker_queue::QStandardWorkerQueueSubscriber,
    },
    store::traits::
        proof_store::QParthProofStore
    ,
};

use crate::{coordinator::edge::handler::CoordinatorEdgeHandler, realm::edge::error::RpcError};


type QRpcResult<T> = RpcResult<T>;

fn res<T>(data: anyhow::Result<T>) -> QRpcResult<T> {
    Ok(data.map_err(RpcError::Anyhow)?)
}

const MAX_CHECKPOINT_ID: u64 = i64::MAX as u64;

#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId =  QProvingJobDataID> + Send + Sync + 'static,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + std::marker::Sync + std::marker::Send + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
    > CoordinatorEdgeRpcServer<N::F, N::QHash, N::JobId, N::ZKProof>
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
    
    async fn register_user(&self, public_key: PZKPublicKeyInfo<N::QHash>) -> QRpcResult<String> {
        res(self.register_user_internal(public_key).await)
    }
    async fn deploy_contract(&self, deploy_contract: PQBCDeployContract<N::QHash>) -> QRpcResult<String> {
        res(self.deploy_contract_internal(deploy_contract).await)
    }
    async fn submit_guta(&self, input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>, proof: Vec<u8>, _realm_id: u64) -> QRpcResult<String> {
        res(self.submit_guta_internal(input, proof).await)?;
        Ok("ok".to_string())
    }
    async fn get_user_ids_for_public_key(&self, public_key: N::QHash, start_user_id: u64, count: u32) -> QRpcResult<Vec<u64>> {
        res(self
            .db_reader
            .get_user_ids_for_public_key(public_key, start_user_id, count as usize)
            .await)
    }

    async fn get_contract_code_definition(&self, contract_id: u64) -> QRpcResult<ContractCodeDefinition> {
        res(self.db_reader.get_contract_code_definition(MAX_CHECKPOINT_ID, contract_id).await)
    }
    async fn get_latest_checkpoint_id(&self) -> QRpcResult<u64> {
        res(self.get_latest_checkpoint_id_internal().await)
    }
    async fn get_contract_leaf_data(&self, contract_id: u64) -> QRpcResult<PQEDContractLeaf<N::F, N::QHash>> {
        res(self.db_reader.get_contract_leaf(MAX_CHECKPOINT_ID, contract_id).await)
    }

    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> QRpcResult<PQEDCheckpointLeaf<N::F, N::QHash>> {
        res(self.db_reader.get_checkpoint_leaf_data(checkpoint_id).await)
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
        res(self.db_reader.get_user_leaf(checkpoint_id, user_id).await)
    }

    async fn get_user_tree_root(&self, checkpoint_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.global_user_tree_get_root_hash(checkpoint_id).await)
    }

    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .global_user_tree_get_merkle_proof_sub_tree(checkpoint_id, root_level, leaf_level, leaf_index)
            .await)
    }

    async fn get_user_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self.db_reader.global_user_tree_get_merkle_proof(checkpoint_id, user_id).await)
    }

    async fn generate_batch_proof_miner_reward_proofs(
        &self,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath<N::JobId>>,
    ) -> QRpcResult<Vec<PsyProoffMinerRewardProof<N::QHash, N::JobId>>> {
        res(self.generate_batch_proof_miner_reward_proofs_internal(unique_pending_id, job_ids).await)
    }

    async fn get_contract_function_tree_root(&self, checkpoint_id: u64, contract_id: u32) -> QRpcResult<N::QHash> {
        res(self
            .db_reader
            .contract_function_tree_get_root_hash(checkpoint_id, contract_id as u64)
            .await)
    }

    async fn get_contract_function_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32, function_id: u32) -> QRpcResult<N::QHash> {
        res(self
            .db_reader
            .contract_function_tree_get_leaf_hash(checkpoint_id, contract_id as u64, function_id as u64)
            .await)
    }

    async fn get_contract_function_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
        function_id: u32,
    ) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .contract_function_tree_get_merkle_proof(checkpoint_id, contract_id as u64, function_id as u64)
            .await)
    }

    async fn get_contract_tree_root(&self, checkpoint_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.global_contract_tree_get_root_hash(checkpoint_id).await)
    }

    async fn get_contract_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32) -> QRpcResult<N::QHash> {
        res(self.db_reader.global_contract_tree_get_leaf_hash(checkpoint_id, contract_id as u64).await)
    }

    async fn get_contract_tree_merkle_proof(&self, checkpoint_id: u64, contract_id: u32) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .global_contract_tree_get_merkle_proof(checkpoint_id, contract_id as u64)
            .await)
    }

    async fn get_user_top_tree_merkle_proof(&self, checkpoint_id: u64, leaf_level: u8, leaf_index: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .global_user_tree_get_merkle_proof_sub_tree(checkpoint_id, 0, leaf_level, leaf_index)
            .await)
    }

    async fn get_user_top_tree_cap_root(&self, checkpoint_id: u64, cap_level: u8, cap_index: u64) -> QRpcResult<N::QHash> {
        res(self
            .db_reader
            .global_user_tree_get_node(
                checkpoint_id,
                SimpleMerkleNodeKey {
                    level: cap_level,
                    index: cap_index,
                },
            )
            .await)
    }

    async fn get_user_latest_top_tree_cap_root(&self, cap_level: u8, cap_index: u64) -> QRpcResult<N::QHash> {
        let latest_checkpoint_id = self.get_latest_checkpoint_id().await?;

        res(self
            .db_reader
            .global_user_tree_get_node(
                latest_checkpoint_id,
                SimpleMerkleNodeKey {
                    level: cap_level,
                    index: cap_index,
                },
            )
            .await)
    }

    async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.user_registration_tree_get_root_hash(checkpoint_id).await)
    }

    async fn get_user_registration_tree_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.user_registration_tree_get_leaf_hash(checkpoint_id, leaf_index).await)
    }

    async fn get_user_registration_tree_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self.db_reader.user_registration_tree_get_merkle_proof(checkpoint_id, leaf_index).await)
    }
}


#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId =  QProvingJobDataID> + Send + Sync + 'static,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + std::marker::Sync + std::marker::Send + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
    > NodeEdgeWorkerRpcServer<N::QHash, N::JobId>
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
    async fn get_proving_work(&self, signature:  QEDCompressedSecp256K1Signature, request: SimpleTimedRequest) -> RpcResult<PsyWorkerGetProvingWorkAPIResponse<N::QHash, N::JobId>>{
        res(self.get_proving_work_internal(signature, request).await)
    }
    async fn get_proving_work_with_child_proofs(&self, signature:  QEDCompressedSecp256K1Signature, request: SimpleTimedRequest) -> RpcResult<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<N::QHash, N::JobId>>{
        res(self.get_proving_work_with_child_proofs_internal(signature, request).await)
    }
    async fn submit_proof_raw(&self, job_id: N::JobId, tag: N::QHash, proof: Vec<u8>) -> RpcResult<()>{
        res(self.submit_proof_raw_internal(job_id, tag, proof).await)
    }
}

