use std::collections::HashMap;

use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_config::network_constants::{DEFAULT_CALLER_CONTRACT_ID_U64, MAX_CONTRACT_STATE_TREE_HEIGHT};
use psy_crypto::hash::merkle::core::MerkleProofCore;

use super::{
    cmd::{
        QSRCmdGetBlockState, QSRCmdGetCheckpointLeafData, QSRCmdGetContractCodeDefinition, QSRCmdGetContractLeafData, QSRCmdGetUserLeafData,
        QSRHashCmd, QSRMerkleCmd,
    },
    cmd_processor::{
        PsyReadCommandBatchInput, PsyReadCommandBatchOutput, PsyReadCommandProcessorSync, PsyReadCommandProcessorSyncMut, QUserIdManager,
    },
};
use crate::qdata::{
    checkpoint::{PsyBlockState, PsyCheckpointLeaf},
    contract::{ContractCodeDefinition, PsyContractLeaf},
    user::PsyUserLeaf,
};

#[derive(Clone, Debug)]
pub struct PsyCmdDataStoreCache<F: RichField> {
    pub user_leaf_cache: HashMap<QSRCmdGetUserLeafData, PsyUserLeaf<F>>,
    pub contract_leaf_cache: HashMap<u64, PsyContractLeaf<F>>,
    pub checkpoint_leaf_cache: HashMap<u64, PsyCheckpointLeaf<F>>,
    pub contract_code_definition_cache: HashMap<u64, ContractCodeDefinition>,
    pub block_state_cache: HashMap<u64, PsyBlockState>,
    pub hash_cmd_cache: HashMap<QSRHashCmd, QHashOut<F>>,
    pub merkle_cmd_cache: HashMap<QSRMerkleCmd, MerkleProofCore<QHashOut<F>>>,

    pub imt_leaf_preimage_cache: HashMap<super::cmd::QSRIMTCmdGetLeafPreimage, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>>,
    pub imt_predecessor_cache: HashMap<super::cmd::QSRIMTCmdFindPredecessor, (u64, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>)>,
    pub imt_index_cache: HashMap<super::cmd::QSRIMTCmdGetLeafIndexForKey, u64>,
    pub imt_next_append_index_cache: HashMap<super::cmd::QSRIMTCmdGetNextAppendIndex, u64>,
}
impl<F: RichField> PsyCmdDataStoreCache<F> {
    pub fn new() -> Self {
        Self {
            user_leaf_cache: HashMap::new(),
            contract_leaf_cache: HashMap::new(),
            checkpoint_leaf_cache: HashMap::new(),
            contract_code_definition_cache: HashMap::new(),
            block_state_cache: HashMap::new(),
            hash_cmd_cache: HashMap::new(),
            merkle_cmd_cache: HashMap::new(),
            imt_leaf_preimage_cache: HashMap::new(),
            imt_predecessor_cache: HashMap::new(),
            imt_index_cache: HashMap::new(),
            imt_next_append_index_cache: HashMap::new(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct PsyCmdStoreWithCache<F: RichField, S: PsyReadCommandProcessorSync<F> + QUserIdManager> {
    pub last_checkpoint: F,
    pub last_checkpoint_u64: u64,
    pub cache: PsyCmdDataStoreCache<F>,
    pub read_store: S,
}

impl<F: RichField, S: PsyReadCommandProcessorSync<F> + QUserIdManager> PsyCmdStoreWithCache<F, S> {
    pub fn new(last_checkpoint_u64: u64, read_store: S) -> Self {
        Self {
            last_checkpoint: F::from_noncanonical_u64(last_checkpoint_u64),
            last_checkpoint_u64,
            cache: PsyCmdDataStoreCache::new(),
            read_store,
        }
    }
    pub fn clear_cache_mut(&mut self) {
        self.cache = PsyCmdDataStoreCache::new();
    }

    pub fn clear_imt_caches_mut(&mut self) {
        self.cache.imt_leaf_preimage_cache.clear();
        self.cache.imt_predecessor_cache.clear();
        self.cache.imt_index_cache.clear();
        self.cache.imt_next_append_index_cache.clear();
    }

    pub fn set_user_id(&mut self, user_id: u64) {
        self.read_store.set_user_id(user_id);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<F: RichField, S: PsyReadCommandProcessorSync<F> + QUserIdManager + Send> PsyReadCommandProcessorSyncMut<F> for PsyCmdStoreWithCache<F, S> {
    async fn resolve_batch_mut(&mut self, input: &PsyReadCommandBatchInput) -> anyhow::Result<PsyReadCommandBatchOutput<F>> {
        let filtered_get = PsyReadCommandBatchInput {
            get_user_leaf: input
                .get_user_leaf
                .iter()
                .filter(|x| !self.cache.user_leaf_cache.contains_key(x))
                .cloned()
                .collect(),
            get_contract_leaf: input
                .get_contract_leaf
                .iter()
                .filter(|x| !self.cache.contract_leaf_cache.contains_key(&x.contract_id))
                .cloned()
                .collect(),
            get_checkpoint_leaf: input
                .get_checkpoint_leaf
                .iter()
                .filter(|x| !self.cache.checkpoint_leaf_cache.contains_key(&x.checkpoint_id))
                .cloned()
                .collect(),
            get_contract_code: input
                .get_contract_code
                .iter()
                .filter(|x| !self.cache.contract_code_definition_cache.contains_key(&x.contract_id))
                .cloned()
                .collect(),
            get_block_state: input
                .get_block_state
                .iter()
                .filter(|x| !self.cache.block_state_cache.contains_key(&x.checkpoint_id))
                .cloned()
                .collect(),
            get_hash: input
                .get_hash
                .iter()
                .filter(|x| !self.cache.hash_cmd_cache.contains_key(x))
                .cloned()
                .collect(),
            get_merkle_proof: input
                .get_merkle_proof
                .iter()
                .filter(|x| !self.cache.merkle_cmd_cache.contains_key(x))
                .cloned()
                .collect(),
        };
        let base_output = self.read_store.resolve_batch(&filtered_get).await?;
        self.cache.user_leaf_cache.extend(
            filtered_get
                .get_user_leaf
                .iter()
                .zip(base_output.get_user_leaf.iter())
                .map(|(i, x)| (i.clone(), x.clone())),
        );
        self.cache.contract_leaf_cache.extend(
            filtered_get
                .get_contract_leaf
                .iter()
                .map(|x| x.contract_id)
                .zip(base_output.get_contract_leaf.clone()),
        );
        self.cache.checkpoint_leaf_cache.extend(
            filtered_get
                .get_checkpoint_leaf
                .iter()
                .map(|x| x.checkpoint_id)
                .zip(base_output.get_checkpoint_leaf.clone()),
        );
        self.cache.contract_code_definition_cache.extend(
            filtered_get
                .get_contract_code
                .iter()
                .map(|x| x.contract_id)
                .zip(base_output.get_contract_code.clone()),
        );
        self.cache.block_state_cache.extend(
            filtered_get
                .get_block_state
                .iter()
                .map(|x| x.checkpoint_id)
                .zip(base_output.get_block_state.clone()),
        );

        self.cache.hash_cmd_cache.extend(
            filtered_get
                .get_hash
                .iter()
                .zip(base_output.get_hash.iter())
                .map(|(i, x)| (i.clone(), x.clone())),
        );
        self.cache.merkle_cmd_cache.extend(
            filtered_get
                .get_merkle_proof
                .iter()
                .zip(base_output.get_merkle_proof.iter())
                .map(|(i, x)| (i.clone(), x.clone())),
        );

        Ok(PsyReadCommandBatchOutput {
            get_user_leaf: input
                .get_user_leaf
                .iter()
                .map(|x| self.cache.user_leaf_cache.get(x).unwrap().clone())
                .collect(),
            get_contract_leaf: input
                .get_contract_leaf
                .iter()
                .map(|x| self.cache.contract_leaf_cache.get(&x.contract_id).unwrap().clone())
                .collect(),
            get_checkpoint_leaf: input
                .get_checkpoint_leaf
                .iter()
                .map(|x| self.cache.checkpoint_leaf_cache.get(&x.checkpoint_id).unwrap().clone())
                .collect(),
            get_contract_code: input
                .get_contract_code
                .iter()
                .map(|x| self.cache.contract_code_definition_cache.get(&x.contract_id).unwrap().clone())
                .collect(),
            get_block_state: input
                .get_block_state
                .iter()
                .map(|x| self.cache.block_state_cache.get(&x.checkpoint_id).unwrap().clone())
                .collect(),
            get_hash: input.get_hash.iter().map(|x| self.cache.hash_cmd_cache.get(x).unwrap().clone()).collect(),
            get_merkle_proof: input
                .get_merkle_proof
                .iter()
                .map(|x| self.cache.merkle_cmd_cache.get(x).unwrap().clone())
                .collect(),
        })
    }

    async fn resolve_get_hash_mut(&mut self, input: &QSRHashCmd) -> anyhow::Result<QHashOut<F>> {
        if self.cache.hash_cmd_cache.contains_key(input) {
            Ok(self.cache.hash_cmd_cache.get(input).unwrap().clone())
        } else {
            let result = self.read_store.resolve_get_hash(input).await?;
            self.cache.hash_cmd_cache.insert(input.clone(), result.clone());
            Ok(result)
        }
    }

    async fn resolve_get_merkle_proof_mut(&mut self, input: &QSRMerkleCmd) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        if self.cache.merkle_cmd_cache.contains_key(input) {
            Ok(self.cache.merkle_cmd_cache.get(input).unwrap().clone())
        } else {
            let result = self.read_store.resolve_get_merkle_proof(input).await?;
            self.cache.merkle_cmd_cache.insert(input.clone(), result.clone());
            Ok(result)
        }
    }

    async fn resolve_get_user_leaf_mut(&mut self, input: &QSRCmdGetUserLeafData) -> anyhow::Result<PsyUserLeaf<F>> {
        if self.cache.user_leaf_cache.contains_key(input) {
            Ok(self.cache.user_leaf_cache.get(input).unwrap().clone())
        } else {
            let result = self.read_store.resolve_get_user_leaf(input).await?;
            self.cache.user_leaf_cache.insert(input.clone(), result.clone());
            Ok(result)
        }
    }

    async fn resolve_get_contract_leaf_mut(&mut self, input: &QSRCmdGetContractLeafData) -> anyhow::Result<PsyContractLeaf<F>> {
        if input.contract_id == DEFAULT_CALLER_CONTRACT_ID_U64 {
            return Ok(PsyContractLeaf {
                deployer: QHashOut::default(),
                function_tree_root: QHashOut::default(),
                code_root: QHashOut::default(),
                state_tree_height: F::from_canonical_u8(MAX_CONTRACT_STATE_TREE_HEIGHT),
            });
        }
        if self.cache.contract_leaf_cache.contains_key(&input.contract_id) {
            Ok(self.cache.contract_leaf_cache.get(&input.contract_id).unwrap().clone())
        } else {
            let result = self.read_store.resolve_get_contract_leaf(input).await?;
            self.cache.contract_leaf_cache.insert(input.contract_id, result.clone());
            Ok(result)
        }
    }

    async fn resolve_get_contract_code_mut(&mut self, input: &QSRCmdGetContractCodeDefinition) -> anyhow::Result<ContractCodeDefinition> {
        if self.cache.contract_code_definition_cache.contains_key(&input.contract_id) {
            Ok(self.cache.contract_code_definition_cache.get(&input.contract_id).unwrap().clone())
        } else {
            let result = self.read_store.resolve_get_contract_code(input).await?;
            self.cache.contract_code_definition_cache.insert(input.contract_id, result.clone());
            Ok(result)
        }
    }

    async fn resolve_get_checkpoint_leaf_mut(&mut self, input: &QSRCmdGetCheckpointLeafData) -> anyhow::Result<PsyCheckpointLeaf<F>> {
        if self.cache.checkpoint_leaf_cache.contains_key(&input.checkpoint_id) {
            Ok(self.cache.checkpoint_leaf_cache.get(&input.checkpoint_id).unwrap().clone())
        } else {
            let result = self.read_store.resolve_get_checkpoint_leaf(input).await?;
            self.cache.checkpoint_leaf_cache.insert(input.checkpoint_id, result.clone());
            Ok(result)
        }
    }

    async fn resolve_get_block_state_mut(&mut self, input: &QSRCmdGetBlockState) -> anyhow::Result<PsyBlockState> {
        if self.cache.block_state_cache.contains_key(&input.checkpoint_id) {
            Ok(self.cache.block_state_cache.get(&input.checkpoint_id).unwrap().clone())
        } else {
            let result = self.read_store.resolve_get_block_state(input).await?;
            self.cache.block_state_cache.insert(input.checkpoint_id, result.clone());
            Ok(result)
        }
    }

    async fn resolve_get_latest_block_state_mut(&mut self) -> anyhow::Result<PsyBlockState> {
        self.read_store.resolve_get_latest_block_state().await
    }

    async fn resolve_contract_state_imt_get_leaf_preimage_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage,
    ) -> anyhow::Result<crate::qdata::imt_contract_state::IMTContractStateLeaf<F>> {
        if self.cache.imt_leaf_preimage_cache.contains_key(&input) {
            Ok(self.cache.imt_leaf_preimage_cache.get(&input).unwrap().clone())
        } else {
            let result = self.read_store.resolve_contract_state_imt_get_leaf_preimage(input).await?;
            self.cache.imt_leaf_preimage_cache.insert(*input, result);
            Ok(result)
        }
    }

    async fn resolve_contract_state_imt_get_leaf_index_for_key_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey,
    ) -> anyhow::Result<u64> {
        if self.cache.imt_index_cache.contains_key(&input) {
            Ok(self.cache.imt_index_cache.get(&input).unwrap().clone())
        } else {
            let result = self.read_store.resolve_contract_state_imt_get_leaf_index_for_key(input).await?;
            self.cache.imt_index_cache.insert(*input, result);
            Ok(result)
        }
    }

    async fn resolve_contract_state_imt_find_predecessor_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdFindPredecessor,
    ) -> anyhow::Result<(u64, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>)> {
        if self.cache.imt_predecessor_cache.contains_key(&input) {
            Ok(self.cache.imt_predecessor_cache.get(&input).unwrap().clone())
        } else {
            let result = self.read_store.resolve_contract_state_imt_find_predecessor(input).await?;
            self.cache.imt_predecessor_cache.insert(*input, result);
            Ok(result)
        }
    }

    async fn resolve_contract_state_imt_get_next_append_index_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetNextAppendIndex,
    ) -> anyhow::Result<u64> {
        // Never cache: imt_next_append_index has no checkpoint_id and changes as
        // transactions commit. A stale cached value causes "slot not empty" errors
        // when another session commits between our session start and VM execution.
        self.read_store.resolve_contract_state_imt_get_next_append_index(input).await
    }
}
