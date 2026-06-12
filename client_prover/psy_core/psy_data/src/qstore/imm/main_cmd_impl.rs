use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::core::MerkleProofCore;

use super::{
    cmd::{
        QSRCmdGetBlockState, QSRCmdGetCheckpointLeafData, QSRCmdGetContractCodeDefinition, QSRCmdGetContractLeafData, QSRCmdGetUserLeafData,
        QSRHashCmd, QSRMerkleCmd,
    },
    cmd_processor::{PsyReadCommandBatchInput, PsyReadCommandBatchOutput, PsyReadCommandProcessorSync},
};
use crate::{
    qdata::{
        checkpoint::{PsyBlockState, PsyCheckpointLeaf},
        contract::{ContractCodeDefinition, PsyContractLeaf},
        user::PsyUserLeaf,
    },
    traits::qdatastore::qtreedata::PsyComboDataStoreReaderSync,
};

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<F: RichField, R: PsyComboDataStoreReaderSync<F> + Sync> PsyReadCommandProcessorSync<F> for R {
    async fn resolve_batch(&self, input: &PsyReadCommandBatchInput) -> anyhow::Result<PsyReadCommandBatchOutput<F>> {
        let mut get_user_leaf = Vec::new();
        for x in &input.get_user_leaf {
            get_user_leaf.push(self.resolve_get_user_leaf(x).await?);
        }
        let mut get_contract_leaf = Vec::new();
        for x in &input.get_contract_leaf {
            get_contract_leaf.push(self.resolve_get_contract_leaf(x).await?);
        }
        let mut get_contract_code = Vec::new();
        for x in &input.get_contract_code {
            get_contract_code.push(self.resolve_get_contract_code(x).await?);
        }
        let mut get_checkpoint_leaf = Vec::new();
        for x in &input.get_checkpoint_leaf {
            get_checkpoint_leaf.push(self.resolve_get_checkpoint_leaf(x).await?);
        }
        let mut get_block_state = Vec::new();
        for x in &input.get_block_state {
            get_block_state.push(self.resolve_get_block_state(x).await?);
        }
        let mut get_merkle_proof = Vec::new();
        for x in &input.get_merkle_proof {
            get_merkle_proof.push(self.resolve_get_merkle_proof(x).await?);
        }
        let mut get_hash = Vec::new();
        for x in &input.get_hash {
            get_hash.push(self.resolve_get_hash(x).await?);
        }
        Ok(PsyReadCommandBatchOutput {
            get_user_leaf: get_user_leaf,
            get_contract_leaf: get_contract_leaf,
            get_contract_code: get_contract_code,
            get_checkpoint_leaf: get_checkpoint_leaf,
            get_block_state: get_block_state,
            get_merkle_proof: get_merkle_proof,
            get_hash: get_hash,
        })
    }

    async fn resolve_get_hash(&self, input: &QSRHashCmd) -> anyhow::Result<QHashOut<F>> {
        match input {
            QSRHashCmd::GetUserContractStateTreeRoot(c) => self.get_user_contract_tree_root(c.checkpoint_id, c.user_id).await,
            QSRHashCmd::GetUserContractStateTreeLeafHash(c) => {
                self.get_user_contract_state_tree_leaf_hash(c.checkpoint_id, c.user_id, c.contract_id, c.height, c.leaf_id)
                    .await
            }
            QSRHashCmd::GetUserContractTreeRoot(c) => self.get_user_contract_tree_root(c.checkpoint_id, c.user_id).await,
            QSRHashCmd::GetUserContractTreeLeafHash(c) => self.get_user_contract_tree_leaf_hash(c.checkpoint_id, c.user_id, c.contract_id).await,
            QSRHashCmd::GetUserTreeRoot(c) => self.get_user_tree_root(c.checkpoint_id).await,
            QSRHashCmd::GetUserTreeLeafHash(c) => self.get_user_tree_leaf_hash(c.checkpoint_id, c.user_id).await,
            QSRHashCmd::GetContractFunctionTreeRoot(c) => self.get_contract_function_tree_root(c.checkpoint_id, c.contract_id).await,
            QSRHashCmd::GetContractFunctionTreeLeafHash(c) => {
                self.get_contract_function_tree_leaf_hash(c.checkpoint_id, c.contract_id, c.function_id)
                    .await
            }
            QSRHashCmd::GetContractTreeRoot(c) => self.get_contract_tree_root(c.checkpoint_id).await,
            QSRHashCmd::GetContractTreeLeafHash(c) => self.get_contract_tree_leaf_hash(c.checkpoint_id, c.contract_id).await,
            QSRHashCmd::GetWithdrawalTreeRoot(c) => self.get_withdrawal_tree_root(c.checkpoint_id).await,
            QSRHashCmd::GetCheckpointTreeRoot(c) => self.get_checkpoint_tree_root(c.checkpoint_id).await,
            QSRHashCmd::GetCheckpointTreeLeafHash(c) => self.get_checkpoint_tree_leaf_hash(c.checkpoint_id, c.leaf_checkpoint_id).await,
            QSRHashCmd::GetUserRegistrationTreeRoot(c) => self.get_user_registration_tree_root(c.checkpoint_id).await,
            QSRHashCmd::GetUserRegistrationTreeLeafHash(c) => self.get_user_registration_tree_leaf_hash(c.checkpoint_id, c.leaf_index).await,
        }
    }

    async fn resolve_get_merkle_proof(&self, input: &QSRMerkleCmd) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        match input {
            QSRMerkleCmd::GetUserContractStateTreeMerkleProof(c) => {
                self.get_user_contract_state_tree_merkle_proof(c.checkpoint_id, c.user_id, c.contract_id, c.height, c.leaf_id)
                    .await
            }
            QSRMerkleCmd::GetUserContractTreeMerkleProof(c) => {
                self.get_user_contract_tree_merkle_proof(c.checkpoint_id, c.user_id, c.contract_id).await
            }
            QSRMerkleCmd::GetUserTreeMerkleProof(c) => self.get_user_tree_merkle_proof(c.checkpoint_id, c.user_id).await,
            QSRMerkleCmd::GetContractFunctionTreeMerkleProof(c) => {
                self.get_contract_function_tree_merkle_proof(c.checkpoint_id, c.contract_id, c.function_id)
                    .await
            }
            QSRMerkleCmd::GetContractTreeMerkleProof(c) => self.get_contract_tree_merkle_proof(c.checkpoint_id, c.contract_id).await,
            QSRMerkleCmd::GetCheckpointTreeMerkleProof(c) => self.get_checkpoint_tree_merkle_proof(c.checkpoint_id, c.leaf_checkpoint_id).await,
            QSRMerkleCmd::GetUserRegistrationTreeMerkleProof(c) => self.get_user_registration_tree_merkle_proof(c.checkpoint_id, c.leaf_index).await,
        }
    }

    async fn resolve_get_user_leaf(&self, input: &QSRCmdGetUserLeafData) -> anyhow::Result<PsyUserLeaf<F>> {
        self.get_user_leaf_data(input.checkpoint_id, input.user_id).await
    }

    async fn resolve_get_contract_leaf(&self, input: &QSRCmdGetContractLeafData) -> anyhow::Result<PsyContractLeaf<F>> {
        self.get_contract_leaf_data(input.contract_id).await
    }

    async fn resolve_get_contract_code(&self, input: &QSRCmdGetContractCodeDefinition) -> anyhow::Result<ContractCodeDefinition> {
        self.get_contract_code_definition(input.contract_id).await
    }

    async fn resolve_get_checkpoint_leaf(&self, input: &QSRCmdGetCheckpointLeafData) -> anyhow::Result<PsyCheckpointLeaf<F>> {
        self.get_checkpoint_leaf_data(input.checkpoint_id).await
    }

    async fn resolve_get_block_state(&self, input: &QSRCmdGetBlockState) -> anyhow::Result<PsyBlockState> {
        self.get_block_state(input.checkpoint_id).await
    }

    async fn resolve_get_latest_block_state(&self) -> anyhow::Result<PsyBlockState> {
        self.get_latest_block_state().await
    }

    async fn resolve_contract_state_imt_get_leaf_preimage(
        &self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage,
    ) -> anyhow::Result<crate::qdata::imt_contract_state::IMTContractStateLeaf<F>> {
        self.contract_state_imt_get_leaf_preimage(input.checkpoint_id, input.user_id, input.contract_id as u64, input.leaf_index)
            .await
    }

    async fn resolve_contract_state_imt_get_leaf_index_for_key(
        &self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey,
    ) -> anyhow::Result<u64> {
        self.contract_state_imt_get_leaf_index_for_key(
            input.checkpoint_id,
            input.user_id,
            input.contract_id as u64,
            &QHashOut::from_values(input.key[0], input.key[1], input.key[2], input.key[3]),
        )
        .await
    }

    async fn resolve_contract_state_imt_find_predecessor(
        &self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdFindPredecessor,
    ) -> anyhow::Result<(u64, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>)> {
        self.contract_state_imt_find_predecessor(
            input.checkpoint_id,
            input.user_id,
            input.contract_id as u64,
            &QHashOut::from_values(input.key[0], input.key[1], input.key[2], input.key[3]),
        )
        .await
    }

    async fn resolve_contract_state_imt_get_next_append_index(
        &self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetNextAppendIndex,
    ) -> anyhow::Result<u64> {
        self.contract_state_imt_get_next_append_index(input.user_id, input.contract_id as u64)
            .await
    }
}
