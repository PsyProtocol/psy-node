use hashbrown::HashMap;
use kvq::{
    memory::simple::KVQSimpleMemoryBackingStore,
    traits::{KVQBinaryStore, KVQPair, KVQSerializable},
};
use plonky2::{field::types::PrimeField64, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_config::network_constants::{
    DEFAULT_CALLER_CONTRACT_ID_U64, DEFERRED_TRANSACTION_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, INLINE_TRANSACTION_TREE_HEIGHT,
    MAX_CONTRACT_STATE_TREE_HEIGHT,
};
use psy_crypto::{
    common::user_id::get_registration_id_from_user_id,
    hash::{
        merkle::{
            core::{DeltaMerkleProofCore, MerkleProofCore},
            utils::simple_merkle_tree::SimpleMerkleTree,
        },
        traits::{
            hasher::{FieldQHasher, MerkleHasher, MerkleZeroHasherWithMarkedLeaf},
            qhashable::QFieldHashable,
        },
        utils::safe_hash_fixed_length,
    },
};

use super::{
    session_store::{config::LPS_DEFERRED_TRANSACTION_TREE_ID, tx_tree::TransactionDebtTreeRef},
    state_tracker::{PsyLocalStateTracker, PsyStateOperation},
};
use crate::{
    config::store_config::{PsyHasher, UserContractTreeStore, USER_CONTRACT_STATE_TREE_TABLE_TYPE, USER_CONTRACT_TREE_TABLE_TYPE},
    dpn::{
        cfc_context_input::{DapenCFCProvingSessionStartContext, DapenCFCUserTransactionCallStartContext},
        event::PsyUserEventRecord,
        proving_session::{
            DPNProvingSessionCompactMethodCall, DPNProvingSessionSignableMethodCall, DPNProvingSessionSimpleMethodCall, DPNTransactionDebtItem,
            PsyLocalTransactionRecord,
        },
    },
    guta::api::{ContractStateUpdate, PsyContractStateUpdateHistory},
    models::{
        kvq_merkle::key::KVQMerkleNodeKey,
        kvq_merkle::model::{KVQMerkleTreeModelCore, KVQSemiFixedConfigMerkleTreeModelCore, KVQSemiFixedConfigMerkleTreeModelReaderCore},
        user::contract_state_tree::UserContractStateTreeId,
    },
    qdata::{
        checkpoint::{PsyBlockState, PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
        contract::{ContractCodeDefinition, PsyContractLeaf},
        contract_inclusion::{PsyContractFunctionInclusionProof, PsyContractInclusionProof},
        imt_contract_state::IMTContractStateLeaf,
        user::PsyUserLeaf,
    },
    qstore::{
        controllers::register_helpers::get_new_empty_user_leaf,
        imm::{
            cache::PsyCmdStoreWithCache,
            cmd::{
                QSRCmdGetBlockState, QSRCmdGetCheckpointLeafData, QSRCmdGetContractCodeDefinition, QSRCmdGetContractLeafData, QSRCmdGetUserLeafData,
                QSRHashCmd, QSRHashCmdGetCheckpointTreeRoot, QSRHashCmdGetContractTreeRoot, QSRHashCmdGetUserRegistrationTreeRoot,
                QSRHashCmdGetUserTreeRoot, QSRHashCmdGetWithdrawalTreeRoot, QSRMerkleCmd, QSRMerkleCmdGetContractFunctionTreeMerkleProof,
                QSRMerkleCmdGetContractTreeMerkleProof, QSRMerkleCmdGetUserContractStateTreeMerkleProof, QSRMerkleCmdGetUserContractTreeMerkleProof,
                QSRMerkleCmdGetUserRegistrationTreeMerkleProof, QSRMerkleCmdGetUserTreeMerkleProof,
            },
            cmd_processor::{
                DPNReadOtherUserLeafMerkleProof, PsyReadCommandBatchInput, PsyReadCommandBatchOutput, PsyReadCommandProcessorSync,
                PsyReadCommandProcessorSyncMut, QUserIdManager,
            },
        },
    },
    traits::qdatastore::qmetadata::QMetaDataStoreReaderSync,
    ups::{ups_context_input::UserProvingSessionStartContext, ups_standard_cfc_input::UPSCFCStandardStateDeltaInput},
};

pub trait PsyReadLocalProvingSessionStore<F: RichField> {
    fn get_current_contract_id(&self) -> F;
    fn get_current_caller_contract_id(&self) -> F;
    fn get_start_contract_state_roots(&self) -> Vec<(u64, QHashOut<F>)>;
    fn get_total_slots_modified(&self) -> F;
    fn get_total_imt_keys_modified(&self) -> F;
    fn get_current_method_id(&self) -> F;
    fn get_current_user_id(&self) -> F;
    fn get_current_user_id_64(&self) -> u64;
    fn get_current_start_checkpoint_id(&self) -> F;
    fn get_current_start_checkpoint_id_u64(&self) -> u64;
    fn get_current_write_checkpoint_id(&self) -> F;
    fn get_current_write_checkpoint_id_u64(&self) -> u64;
    fn get_nonce(&self) -> F;
    fn get_nonce_u64(&self) -> u64;
    fn get_q_recursion_proof_tree_height(&self) -> usize;
    fn get_q_recursion_proof_tree_root(&self) -> QHashOut<F>;
    fn get_latest_deferred_tx_item(&self) -> Option<&DPNTransactionDebtItem<DPNProvingSessionSimpleMethodCall<F>, F>>;
    fn get_local_state_tracker(&self) -> &PsyLocalStateTracker<F>;
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PsyReadLocalProvingSessionStoreMut<F: RichField + PrimeField64>: PsyReadLocalProvingSessionStore<F> {
    type Hasher: FieldQHasher<F> + MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + Send;

    async fn init_transaction(&mut self, call_data: DPNProvingSessionSimpleMethodCall<F>) -> anyhow::Result<()>;
    async fn get_fresh_start_ctx_for_user(&mut self, user: F) -> anyhow::Result<DapenCFCProvingSessionStartContext<F>>;
    async fn get_call_start_data(&mut self, contract_id: F, method_id: F, inputs: &[F])
        -> anyhow::Result<DapenCFCUserTransactionCallStartContext<F>>;
    async fn get_contract_state_slot(&mut self, contract: F, slot: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    fn get_latest_deferred_tx_leaf(&self) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn finalize_transaction(&mut self) -> anyhow::Result<()>;
}

pub trait PsyEventsStore<F: RichField> {
    fn set_start_event_index(&mut self, event_index: F);
    fn get_event_index(&self) -> F;

    fn write_events(&mut self, events: Vec<PsyUserEventRecord<F>>);
    fn read_events(&self) -> Vec<PsyUserEventRecord<F>>;
}

pub struct PsyLocalProvingSessionStore<
    F: RichField + PrimeField64,
    R: PsyReadCommandProcessorSync<F> + QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + Send = PsyHasher,
> {
    cmd_store: PsyCmdStoreWithCache<F, R>,
    state_tree_store: KVQSimpleMemoryBackingStore,
    active_tx_session_data_store: KVQSimpleMemoryBackingStore,
    transaction_records: Vec<PsyLocalTransactionRecord<F>>,

    events: Vec<PsyUserEventRecord<F>>,
    start_event_index: F,

    deferred_tx_debt_store: TransactionDebtTreeRef<
        DEFERRED_TRANSACTION_TREE_HEIGHT,
        LPS_DEFERRED_TRANSACTION_TREE_ID,
        KVQSimpleMemoryBackingStore,
        DPNProvingSessionSimpleMethodCall<F>,
        F,
        H,
    >,

    local_state_tracker: PsyLocalStateTracker<F>,
    start_checkpoint: F,
    write_checkpoint: F,
    start_checkpoint_u64: u64,
    write_checkpoint_u64: u64,
    user_id: F,
    user_id_u64: u64,
    nonce: F,
    pub user_balance: Option<F>,
    session_proof_tree_root: QHashOut<F>,

    session_proof_tree_height: usize,
    is_new_user: bool,
    _phantom_h: std::marker::PhantomData<H>,
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<
        F: RichField,
        H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + Send,
        R: PsyReadCommandProcessorSync<F> + QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    > PsyReadLocalProvingSessionStore<F> for PsyLocalProvingSessionStore<F, R, H>
{
    fn get_current_contract_id(&self) -> F {
        self.last_transaction_record().call_data.call_data.contract_id
    }

    fn get_current_caller_contract_id(&self) -> F {
        self.last_transaction_record().call_data.call_data.caller_contract_id
    }

    fn get_start_contract_state_roots(&self) -> Vec<(u64, QHashOut<F>)> {
        let mut mapping = HashMap::<u64, QHashOut<F>>::new();
        for t in self.transaction_records.iter() {
            let c_id = t.user_contract_tree_update_proof.index;
            if !mapping.contains_key(&c_id) {
                mapping.insert(c_id, t.user_contract_tree_update_proof.old_value);
            }
        }

        mapping.into_iter().map(|(k, v)| (k, v)).collect()
    }

    fn get_total_slots_modified(&self) -> F {
        F::from_canonical_u32(self.local_state_tracker.total_slots_modified + self.local_state_tracker.get_total_keys_modified())
    }

    fn get_total_imt_keys_modified(&self) -> F {
        F::from_canonical_u32(self.local_state_tracker.get_total_keys_modified())
    }

    fn get_current_method_id(&self) -> F {
        self.last_transaction_record().call_data.call_data.method_id
    }

    fn get_current_user_id(&self) -> F {
        self.user_id
    }

    fn get_current_user_id_64(&self) -> u64 {
        self.user_id.to_canonical_u64()
    }

    fn get_current_start_checkpoint_id(&self) -> F {
        self.start_checkpoint
    }

    fn get_current_start_checkpoint_id_u64(&self) -> u64 {
        self.start_checkpoint_u64
    }

    fn get_current_write_checkpoint_id(&self) -> F {
        self.write_checkpoint
    }

    fn get_current_write_checkpoint_id_u64(&self) -> u64 {
        self.write_checkpoint_u64
    }

    fn get_nonce(&self) -> F {
        self.nonce
    }

    fn get_nonce_u64(&self) -> u64 {
        self.nonce.to_canonical_u64()
    }

    fn get_q_recursion_proof_tree_height(&self) -> usize {
        self.session_proof_tree_height
    }

    fn get_q_recursion_proof_tree_root(&self) -> QHashOut<F> {
        self.session_proof_tree_root
    }

    fn get_latest_deferred_tx_item(&self) -> Option<&DPNTransactionDebtItem<DPNProvingSessionSimpleMethodCall<F>, F>> {
        self.deferred_tx_debt_store.get_latest_proof_debt_item()
    }

    fn get_local_state_tracker(&self) -> &PsyLocalStateTracker<F> {
        &self.local_state_tracker
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<
        F: RichField,
        H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + Send,
        R: PsyReadCommandProcessorSync<F> + QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    > PsyReadCommandProcessorSyncMut<F> for PsyLocalProvingSessionStore<F, R, H>
{
    async fn resolve_batch_mut(&mut self, input: &PsyReadCommandBatchInput) -> anyhow::Result<PsyReadCommandBatchOutput<F>> {
        self.cmd_store.resolve_batch_mut(input).await
    }

    async fn resolve_get_hash_mut(&mut self, input: &QSRHashCmd) -> anyhow::Result<QHashOut<F>> {
        self.cmd_store.resolve_get_hash_mut(input).await
    }

    async fn resolve_get_merkle_proof_mut(&mut self, input: &QSRMerkleCmd) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        self.cmd_store.resolve_get_merkle_proof_mut(input).await
    }

    async fn resolve_get_user_leaf_mut(&mut self, input: &QSRCmdGetUserLeafData) -> anyhow::Result<PsyUserLeaf<F>> {
        self.cmd_store.resolve_get_user_leaf_mut(input).await
    }

    async fn resolve_get_contract_leaf_mut(&mut self, input: &QSRCmdGetContractLeafData) -> anyhow::Result<PsyContractLeaf<F>> {
        self.cmd_store.resolve_get_contract_leaf_mut(input).await
    }

    async fn resolve_get_contract_code_mut(&mut self, input: &QSRCmdGetContractCodeDefinition) -> anyhow::Result<ContractCodeDefinition> {
        self.cmd_store.resolve_get_contract_code_mut(input).await
    }

    async fn resolve_get_checkpoint_leaf_mut(&mut self, input: &QSRCmdGetCheckpointLeafData) -> anyhow::Result<PsyCheckpointLeaf<F>> {
        self.cmd_store.resolve_get_checkpoint_leaf_mut(input).await
    }

    async fn resolve_get_block_state_mut(&mut self, input: &QSRCmdGetBlockState) -> anyhow::Result<PsyBlockState> {
        self.cmd_store.resolve_get_block_state_mut(input).await
    }

    async fn resolve_get_latest_block_state_mut(&mut self) -> anyhow::Result<PsyBlockState> {
        self.cmd_store.resolve_get_latest_block_state_mut().await
    }

    async fn resolve_contract_state_imt_get_leaf_preimage_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage,
    ) -> anyhow::Result<crate::qdata::imt_contract_state::IMTContractStateLeaf<F>> {
        if input.user_id != self.user_id_u64 || input.checkpoint_id != self.start_checkpoint_u64 {
            return self.cmd_store.resolve_contract_state_imt_get_leaf_preimage_mut(input).await;
        }
        let contract_id = input.contract_id as u64;
        if let Some(local_leaf) = self
            .local_state_tracker
            .get_imt_leaf_preimage_by_leaf_index(contract_id, input.leaf_index)
        {
            return Ok(local_leaf);
        }
        self.cmd_store.resolve_contract_state_imt_get_leaf_preimage_mut(input).await
    }

    async fn resolve_contract_state_imt_get_leaf_index_for_key_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey,
    ) -> anyhow::Result<u64> {
        if input.user_id != self.user_id_u64 || input.checkpoint_id != self.start_checkpoint_u64 {
            return self.cmd_store.resolve_contract_state_imt_get_leaf_index_for_key_mut(input).await;
        }
        let key = QHashOut::from_values(input.key[0], input.key[1], input.key[2], input.key[3]);
        let contract_id = input.contract_id as u64;

        if let Some(leaf_index) = self
            .local_state_tracker
            .get_imt_leaf_index_for_key(contract_id, input.state_slot_base, input.capacity, &key)
        {
            return Ok(leaf_index);
        }
        self.cmd_store.resolve_contract_state_imt_get_leaf_index_for_key_mut(input).await
    }

    async fn resolve_contract_state_imt_find_predecessor_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdFindPredecessor,
    ) -> anyhow::Result<Option<(u64, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>)>> {
        use crate::qdata::imt_contract_state::compare_qhashout_keys;
        if input.user_id != self.user_id_u64 || input.checkpoint_id != self.start_checkpoint_u64 {
            return self.cmd_store.resolve_contract_state_imt_find_predecessor_mut(input).await;
        }

        let key = QHashOut::from_values(input.key[0], input.key[1], input.key[2], input.key[3]);
        let contract_id = input.contract_id as u64;

        let local_pred = self
            .local_state_tracker
            .find_imt_predecessor(contract_id, input.state_slot_base, input.capacity, &key);
        let remote_pred = self.cmd_store.resolve_contract_state_imt_find_predecessor_mut(input).await?;

        // Merge local and remote predecessors. Equal keys must prefer local because
        // local carries the latest preimage after earlier writes in this proof.
        let result = match (local_pred, remote_pred) {
            (Some((local_idx, local_leaf)), Some((remote_idx, remote_leaf))) => match compare_qhashout_keys(&local_leaf.key, &remote_leaf.key) {
                std::cmp::Ordering::Greater | std::cmp::Ordering::Equal => (local_idx, local_leaf),
                std::cmp::Ordering::Less => (remote_idx, remote_leaf),
            },
            (Some(local), None) => local,
            (None, Some(remote)) => remote,
            (None, None) => return Ok(None),
        };

        tracing::info!(
            "IMT predecessor raw response: leaf_index={}, leaf.key={}, leaf.next_index={}, leaf.next_key={}, state_slot_base={}, capacity={}",
            result.0,
            result.1.key,
            result.1.next_index.to_canonical_u64(),
            result.1.next_key,
            input.state_slot_base,
            input.capacity,
        );

        Ok(Some(result))
    }

    async fn resolve_contract_state_imt_get_next_append_index_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetNextAppendIndex,
    ) -> anyhow::Result<u64> {
        if input.user_id != self.user_id_u64 {
            return self.cmd_store.resolve_contract_state_imt_get_next_append_index_mut(input).await;
        }
        let contract_id = input.contract_id as u64;
        let remote_next = self.cmd_store.resolve_contract_state_imt_get_next_append_index_mut(input).await?;
        let local_next = self
            .local_state_tracker
            .get_imt_next_append_index(contract_id, input.state_slot_base, input.capacity)
            .unwrap_or(0);
        Ok(remote_next.max(local_next))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<
        F: RichField + PrimeField64,
        H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F> + Send,
        R: PsyReadCommandProcessorSync<F> + QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    > PsyReadLocalProvingSessionStoreMut<F> for PsyLocalProvingSessionStore<F, R, H>
{
    type Hasher = H;

    async fn init_transaction(&mut self, call_data: DPNProvingSessionSimpleMethodCall<F>) -> anyhow::Result<()> {
        PsyLocalProvingSessionStore::init_transaction(self, call_data).await
    }

    async fn get_fresh_start_ctx_for_user(&mut self, user: F) -> anyhow::Result<DapenCFCProvingSessionStartContext<F>> {
        PsyLocalProvingSessionStore::get_fresh_start_ctx_for_user(self, user).await
    }

    async fn get_call_start_data(
        &mut self,
        contract_id: F,
        method_id: F,
        inputs: &[F],
    ) -> anyhow::Result<DapenCFCUserTransactionCallStartContext<F>> {
        PsyLocalProvingSessionStore::get_call_start_data(self, contract_id, method_id, inputs).await
    }

    async fn get_contract_state_slot(&mut self, contract: F, slot: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        PsyLocalProvingSessionStore::get_contract_state_slot(self, contract, slot).await
    }

    fn get_latest_deferred_tx_leaf(&self) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        PsyLocalProvingSessionStore::get_latest_deferred_tx_leaf(self)
    }

    async fn finalize_transaction(&mut self) -> anyhow::Result<()> {
        PsyLocalProvingSessionStore::finalize_transaction(self).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<
        F: RichField,
        H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + Send,
        R: PsyReadCommandProcessorSync<F> + QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    > PsyLocalProvingSessionStore<F, R, H>
{
    pub fn new_at(read_store: R, start_checkpoint: F, user_id: F, nonce: F, start_event_index: F, q_recursion_tree_height: usize) -> Self {
        let cmd_store = PsyCmdStoreWithCache::new(start_checkpoint.to_canonical_u64(), read_store);

        Self::new_at_with_cmd_store(cmd_store, start_checkpoint, user_id, nonce, start_event_index, q_recursion_tree_height)
    }
    pub fn new_at_with_cmd_store(
        cmd_store: PsyCmdStoreWithCache<F, R>,
        start_checkpoint: F,
        user_id: F,
        nonce: F,
        start_event_index: F,
        q_recursion_tree_height: usize,
    ) -> Self {
        Self {
            cmd_store,
            state_tree_store: KVQSimpleMemoryBackingStore::new(),
            active_tx_session_data_store: KVQSimpleMemoryBackingStore::new(),
            events: Vec::new(),
            start_event_index,
            local_state_tracker: PsyLocalStateTracker::new(),
            deferred_tx_debt_store: TransactionDebtTreeRef::new(start_checkpoint.to_canonical_u64()),
            transaction_records: Vec::new(),
            start_checkpoint: start_checkpoint,
            write_checkpoint: start_checkpoint + F::ONE,
            user_id,
            start_checkpoint_u64: start_checkpoint.to_canonical_u64(),
            write_checkpoint_u64: start_checkpoint.to_canonical_u64() + 1,
            user_id_u64: user_id.to_canonical_u64(),
            nonce,
            user_balance: None,
            session_proof_tree_height: q_recursion_tree_height,
            session_proof_tree_root: QHashOut::ZERO,
            is_new_user: false,
            _phantom_h: std::marker::PhantomData,
        }
    }
    pub fn into_cmd_store(self) -> PsyCmdStoreWithCache<F, R> {
        self.cmd_store
    }
    pub async fn into_clean_for_user(mut self, user_id: F) -> anyhow::Result<Self> {
        let blk_state = self.cmd_store.resolve_get_latest_block_state_mut().await?;

        let start_checkpoint = F::from_canonical_u64(blk_state.checkpoint_id);
        let user_tree_proof: MerkleProofCore<QHashOut<F>> = self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserTreeMerkleProof(QSRMerkleCmdGetUserTreeMerkleProof {
                checkpoint_id: blk_state.checkpoint_id,
                user_id: user_id.to_canonical_u64(),
            }))
            .await?;

        let (nonce, start_event_index, is_new_user) = if user_tree_proof.value == QHashOut::ZERO {
            (F::ONE, F::ZERO, true)
        } else {
            let user_leaf = self
                .cmd_store
                .resolve_get_user_leaf_mut(&QSRCmdGetUserLeafData {
                    checkpoint_id: blk_state.checkpoint_id,
                    user_id: user_id.to_canonical_u64(),
                })
                .await?;
            (user_leaf.nonce + F::ONE, user_leaf.event_index, false)
        };

        let mut result = self.into_clean_for_user_at_checkpoint(user_id, nonce, start_event_index, start_checkpoint);
        result.set_is_new_user(is_new_user);
        Ok(result)
    }
    pub fn into_clean_for_user_at_checkpoint(self, user_id: F, nonce: F, start_event_index: F, start_checkpoint: F) -> Self {
        let q_recursion_tree_height = self.session_proof_tree_height;
        let mut cmd_store = self.into_cmd_store();
        cmd_store.set_user_id(user_id.to_canonical_u64());
        // IMT resolution caches are time-sensitive and must not cross session
        // boundaries. Keep generic caches, but force fresh IMT reads for next
        // session/tx.
        cmd_store.clear_imt_caches_mut();

        Self::new_at_with_cmd_store(cmd_store, start_checkpoint, user_id, nonce, start_event_index, q_recursion_tree_height)
    }

    pub fn set_is_new_user(&mut self, is_new_user: bool) {
        self.is_new_user = is_new_user;
    }

    pub fn is_new_user(&self) -> bool {
        self.is_new_user
    }
    pub fn set_proof_tree_root(&mut self, session_proof_tree_root: QHashOut<F>) {
        self.session_proof_tree_root = session_proof_tree_root;
    }

    pub async fn new_at_head(read_store: R, user_id: F, nonce: F, start_event_index: F, q_recursion_tree_height: usize) -> anyhow::Result<Self> {
        let start_checkpoint = read_store.resolve_get_latest_block_state().await?;

        Ok(Self::new_at(
            read_store,
            F::from_noncanonical_u64(start_checkpoint.checkpoint_id),
            user_id,
            nonce,
            start_event_index,
            q_recursion_tree_height,
        ))
    }
    pub fn clear(&mut self) {
        self.cmd_store.clear_cache_mut();
        self.state_tree_store.clear();
        self.write_checkpoint = self.start_checkpoint + F::ONE;
        self.write_checkpoint_u64 = self.start_checkpoint_u64 + 1;
    }

    pub fn get_cmd_store(&self) -> &PsyCmdStoreWithCache<F, R>
    where
        R: Clone,
    {
        &self.cmd_store
    }

    pub fn get_state_tree_store(&self) -> &KVQSimpleMemoryBackingStore {
        &self.state_tree_store
    }

    pub fn get_read_store(&self) -> &R {
        &self.cmd_store.read_store
    }

    pub fn last_transaction_record_mut(&mut self) -> &mut PsyLocalTransactionRecord<F> {
        self.transaction_records.last_mut().expect("transaction_records should not be empty")
    }

    pub fn last_transaction_record(&self) -> &PsyLocalTransactionRecord<F> {
        self.transaction_records.last().expect("transaction_records should not be empty")
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<
        F: RichField,
        H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F> + Send,
        R: PsyReadCommandProcessorSync<F> + QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    > PsyLocalProvingSessionStore<F, R, H>
{
    pub fn get_deferred_tx_debt_latest_index(&self) -> u64 {
        self.deferred_tx_debt_store.get_latest_index()
    }
    pub fn get_deferred_tx_debt_next_index(&self) -> u64 {
        self.deferred_tx_debt_store.get_next_index()
    }
    pub fn get_inline_tx_debt_latest_index(&self) -> u64 {
        0
    }
    pub fn get_inline_tx_debt_next_index(&self) -> u64 {
        0
    }
    pub fn get_deferred_tx_tree_leaf(&self, leaf_index: u64) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        self.deferred_tx_debt_store
            .get_tx_debt_leaf(&self.active_tx_session_data_store, leaf_index)
    }
    pub fn get_inline_tx_tree_leaf(&self, leaf_index: u64) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        Ok(SimpleMerkleTree::<H, QHashOut<F>>::new(INLINE_TRANSACTION_TREE_HEIGHT).get_leaf(leaf_index))
    }
    pub async fn init_transaction(&mut self, call_data: DPNProvingSessionSimpleMethodCall<F>) -> anyhow::Result<()> {
        let uct_proof = self
            .get_self_user_contract_tree_leaf(call_data.contract_id)
            .await?
            .to_delta_merkle_proof_inplace();
        tracing::debug!("init_transaction.uct_proof: {}", serde_json::to_string_pretty(&uct_proof).unwrap());

        let record = PsyLocalTransactionRecord {
            start_checkpoint: self.start_checkpoint,
            write_checkpoint: self.write_checkpoint,
            call_data: DPNProvingSessionSignableMethodCall {
                checkpoint_id: self.start_checkpoint,
                user_id: self.user_id,
                call_data,
            },
            user_contract_tree_update_proof: uct_proof,
            added_deferred_tx_items: Vec::new(),
        };

        self.transaction_records.push(record);

        Ok(())
    }

    pub async fn get_call_start_data(
        &mut self,
        contract_id: F,
        method_id: F,
        inputs: &[F],
    ) -> anyhow::Result<DapenCFCUserTransactionCallStartContext<F>> {
        let contract_state_root_proof = self.get_self_user_contract_tree_leaf(contract_id).await?;

        let start_user_contract_tree_root = if self.transaction_records.len() > 1 {
            self.transaction_records[self.transaction_records.len() - 2]
                .user_contract_tree_update_proof
                .new_root
        } else {
            contract_state_root_proof.root
        };
        let start_contract_state_tree_root = if let Some(tracker) = self.local_state_tracker.contracts.get(&contract_id.to_canonical_u64()) {
            tracker.end_state_root
        } else if contract_state_root_proof.value.eq(&QHashOut::ZERO) {
            let state_tree_height = if contract_id == F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64) {
                tracing::debug!("use default contract state tree root");
                MAX_CONTRACT_STATE_TREE_HEIGHT as usize
            } else {
                tracing::debug!("use contract state tree root from contract leaf");
                let state_tree_height = self
                    .cmd_store
                    .resolve_get_contract_leaf_mut(&QSRCmdGetContractLeafData {
                        contract_id: contract_id.to_canonical_u64(),
                    })
                    .await?
                    .state_tree_height
                    .to_canonical_u64() as usize;
                self.set_contract_state_slot(contract_id, F::ZERO, QHashOut::ZERO).await?;
                state_tree_height
            };
            H::get_zero_hash(state_tree_height)
        } else {
            contract_state_root_proof.value
        };

        let caller_contract_id = self.last_transaction_record().call_data.call_data.caller_contract_id;

        tracing::debug!("get_call_start_data.caller_contract_id: {}", caller_contract_id);
        let call_data = DPNProvingSessionCompactMethodCall {
            caller_contract_id,
            contract_id,
            method_id,
            inputs_length: F::from_canonical_u64(inputs.len() as u64),
            inputs_hash: safe_hash_fixed_length::<H, F>(inputs),
        };
        tracing::debug!("get_call_start_data.call_data: {}", serde_json::to_string_pretty(&call_data).unwrap());
        let start_deferred_tx_debt_tree_root = self.get_latest_deferred_tx_leaf()?.root;
        let start_user_balance = match self.user_balance {
            Some(balance) => balance,
            None => self.get_fresh_start_ctx_for_user(self.user_id).await?.start_session_user_leaf.balance,
        };
        let start_user_event_index = self.get_event_index();
        tracing::debug!(
            "get_call_start_data.start_deferred_tx_debt_tree_root: {}",
            start_deferred_tx_debt_tree_root
        );

        Ok(DapenCFCUserTransactionCallStartContext {
            start_user_contract_tree_root,
            start_contract_state_tree_root,
            call_data,
            start_deferred_tx_debt_tree_root,
            start_user_balance,
            start_user_event_index,
        })
    }
    pub async fn get_global_state_tree_roots(&mut self, checkpoint_id: u64) -> anyhow::Result<PsyCheckpointGlobalStateRoots<F>> {
        self.cmd_store.read_store.get_checkpoint_global_state_roots(checkpoint_id).await
    }
    pub async fn get_fresh_start_ctx_for_user(&mut self, user: F) -> anyhow::Result<DapenCFCProvingSessionStartContext<F>> {
        let checkpoint_id = self.start_checkpoint_u64;
        let checkpoint_leaf = self
            .cmd_store
            .resolve_get_checkpoint_leaf_mut(&QSRCmdGetCheckpointLeafData { checkpoint_id })
            .await?;
        let checkpoint_tree_root = self
            .cmd_store
            .resolve_get_hash_mut(&QSRHashCmd::GetCheckpointTreeRoot(QSRHashCmdGetCheckpointTreeRoot { checkpoint_id }))
            .await?;
        let state_roots = self.get_global_state_tree_roots(checkpoint_id).await?;

        let user_leaf = if user == self.user_id && self.is_new_user {
            let user_registration_tree_proof: MerkleProofCore<QHashOut<F>> = self
                .cmd_store
                .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserRegistrationTreeMerkleProof(
                    QSRMerkleCmdGetUserRegistrationTreeMerkleProof {
                        checkpoint_id: self.start_checkpoint_u64,
                        leaf_index: get_registration_id_from_user_id(user.to_canonical_u64()),
                    },
                ))
                .await?;
            get_new_empty_user_leaf(user, user_registration_tree_proof.value)
        } else {
            self.cmd_store
                .resolve_get_user_leaf_mut(&QSRCmdGetUserLeafData {
                    checkpoint_id: self.start_checkpoint_u64,
                    user_id: user.to_canonical_u64(),
                })
                .await?
        };

        if user_leaf.last_checkpoint_id.to_canonical_u64() > checkpoint_id {
            anyhow::bail!(
                "the user's checkpoint is ahead of the proving session (user sync'd to {}, proving session on checkpoint {})",
                user_leaf.last_checkpoint_id.to_canonical_u64(),
                checkpoint_id
            );
        }

        let res = DapenCFCProvingSessionStartContext {
            checkpoint_id: F::from_canonical_u64(checkpoint_id),
            checkpoint_tree_root,
            checkpoint_leaf,
            state_roots,
            start_session_user_leaf: user_leaf,
        };

        tracing::debug!("DapenCFCProvingSessionStartContext: {}", serde_json::to_string_pretty(&res).unwrap());

        Ok(res)
    }
    async fn set_contract_state_slot_inner(&mut self, contract: F, slot: F, value: QHashOut<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        tracing::debug!("set_contract_state_slot_inner.contract: {}", contract);
        let state_tree_height = self
            .cmd_store
            .resolve_get_contract_leaf_mut(&QSRCmdGetContractLeafData {
                contract_id: contract.to_canonical_u64(),
            })
            .await?
            .state_tree_height
            .to_canonical_u64() as u8;
        let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore, F, H>::new(
            self.user_id_u64,
            contract.to_canonical_u64() as u32,
            state_tree_height,
        );
        let base_mp = self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                    checkpoint_id: self.start_checkpoint_u64,
                    user_id: self.user_id_u64,
                    contract_id: contract.to_canonical_u64() as u32,
                    height: state_tree_height,
                    leaf_id: slot.to_canonical_u64(),
                },
            ))
            .await?;
        // Seed the immutable base path at start_checkpoint. `set_leaf` reads
        // old proofs with fuzzy checkpoint lookup, so a first write at
        // write_checkpoint will naturally fall back to this base state, while
        // subsequent writes will see the latest write-checkpoint state.
        id.injest_merkle_proof_ucs(&mut self.state_tree_store, self.start_checkpoint_u64, &base_mp)?;
        let dmp = id.set_leaf_ucs(&mut self.state_tree_store, self.write_checkpoint_u64, slot.to_canonical_u64(), value)?;

        Ok(dmp)
    }
    pub async fn set_contract_state_slot(&mut self, contract: F, slot: F, value: QHashOut<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        tracing::debug!("Proving session - slot: {}, value: {}", slot, value);
        let result = self.set_contract_state_slot_inner(contract, slot, value).await?;
        self.local_state_tracker.notify_update_slot_dmp(contract.to_canonical_u64(), &result);
        Ok(result)
    }
    pub async fn set_contract_state_imt_update(
        &mut self,
        contract: F,
        leaf_index: u64,
        slot: F,
        key: QHashOut<F>,
        old_leaf: IMTContractStateLeaf<F>,
        new_leaf: IMTContractStateLeaf<F>,
        state_slot_base: u64,
        capacity: u64,
        sentinel_preimage: IMTContractStateLeaf<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        let sentinel = self.get_contract_state_slot_for_staging(contract, state_slot_base).await?;
        let count = Self::validate_imt_sentinel(&sentinel, sentinel_preimage, state_slot_base, capacity)?;
        anyhow::ensure!(count > 0 && slot.to_canonical_u64() == leaf_index && leaf_index > state_slot_base
            && leaf_index <= state_slot_base + count, "IMT update outside allocated range");
        anyhow::ensure!(key != QHashOut::ZERO && old_leaf.key == key && new_leaf.key == key
            && old_leaf.next_key == new_leaf.next_key && old_leaf.next_index == new_leaf.next_index,
            "IMT update changes key or successor");
        Self::validate_imt_successor(old_leaf, state_slot_base, count)?;
        let proof = self.get_contract_state_slot_for_staging(contract, leaf_index).await?;
        anyhow::ensure!(proof.root == sentinel.root && proof.value == old_leaf.qfhash::<H>(), "IMT update preimage mismatch");
        let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore, F, H>::new(
            self.user_id_u64, u32::try_from(contract.to_canonical_u64())?, proof.siblings.len() as u8,
        );
        let scratch = KVQSimpleMemoryBackingStore::new();
        id.injest_merkle_proof_ucs(&scratch, self.write_checkpoint_u64, &proof)?;
        let result = id.set_leaf_ucs(&scratch, self.write_checkpoint_u64, leaf_index, new_leaf.qfhash::<H>())?;
        self.validate_imt_tracker(contract.to_canonical_u64(), &[&result])?;
        let entries = self.get_staged_contract_entries(scratch, &id)?;
        self.state_tree_store.set_many_vec(entries)?;
        self.local_state_tracker.notify_imt_update(contract.to_canonical_u64(), key, leaf_index, old_leaf, new_leaf, state_slot_base, capacity);
        self.local_state_tracker.note_contract_state_root_transition(contract.to_canonical_u64(), result.old_root, result.new_root);
        Ok(result)
    }

    pub async fn set_contract_state_imt_insert(
        &mut self,
        contract: F,
        predecessor_leaf_index: u64,
        predecessor_slot: F,
        predecessor_old_leaf: IMTContractStateLeaf<F>,
        predecessor_new_leaf: IMTContractStateLeaf<F>,
        new_leaf_index: u64,
        new_leaf_slot: F,
        new_leaf_preimage: IMTContractStateLeaf<F>,
        state_slot_base: u64,
        capacity: u64,
        sentinel_preimage: IMTContractStateLeaf<F>,
    ) -> anyhow::Result<(DeltaMerkleProofCore<QHashOut<F>>, DeltaMerkleProofCore<QHashOut<F>>, DeltaMerkleProofCore<QHashOut<F>>)> {
        use crate::qdata::imt_contract_state::compare_qhashout_keys;
        let sentinel = self.get_contract_state_slot_for_staging(contract, state_slot_base).await?;
        let count = Self::validate_imt_sentinel(&sentinel, sentinel_preimage, state_slot_base, capacity)?;
        anyhow::ensure!(count < capacity && new_leaf_index == state_slot_base + count + 1
            && new_leaf_slot.to_canonical_u64() == new_leaf_index
            && predecessor_slot.to_canonical_u64() == predecessor_leaf_index,
            "invalid IMT insertion allocation");
        anyhow::ensure!(predecessor_leaf_index >= state_slot_base && predecessor_leaf_index <= state_slot_base + count,
            "IMT predecessor outside allocated range");
        anyhow::ensure!(new_leaf_preimage.key != QHashOut::ZERO
            && compare_qhashout_keys(&predecessor_old_leaf.key, &new_leaf_preimage.key).is_lt()
            && (predecessor_old_leaf.next_key == QHashOut::ZERO
                || compare_qhashout_keys(&new_leaf_preimage.key, &predecessor_old_leaf.next_key).is_lt()),
            "invalid IMT predecessor ordering");
        Self::validate_imt_successor(predecessor_old_leaf, state_slot_base, count)?;
        anyhow::ensure!(predecessor_new_leaf == predecessor_old_leaf.with_new_next(new_leaf_preimage.key, F::from_canonical_u64(new_leaf_index))
            && new_leaf_preimage.next_key == predecessor_old_leaf.next_key
            && new_leaf_preimage.next_index == predecessor_old_leaf.next_index, "invalid IMT splice");
        let predecessor = if predecessor_leaf_index == state_slot_base {
            anyhow::ensure!(predecessor_old_leaf == sentinel_preimage, "IMT predecessor sentinel mismatch");
            sentinel.clone()
        } else {
            anyhow::ensure!(predecessor_old_leaf.key != QHashOut::ZERO, "zero member key");
            self.get_contract_state_slot_for_staging(contract, predecessor_leaf_index).await?
        };
        let member = self.get_contract_state_slot_for_staging(contract, new_leaf_index).await?;
        let predecessor_hash = if count == 0 { QHashOut::ZERO } else { predecessor_old_leaf.qfhash::<H>() };
        anyhow::ensure!(predecessor.root == sentinel.root && member.root == sentinel.root
            && predecessor.value == predecessor_hash && member.value == QHashOut::ZERO, "invalid IMT insertion paths");
        let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore, F, H>::new(
            self.user_id_u64, u32::try_from(contract.to_canonical_u64())?, sentinel.siblings.len() as u8,
        );
        let scratch = KVQSimpleMemoryBackingStore::new();
        for proof in [&predecessor, &member, &sentinel] {
            let preparation = KVQSimpleMemoryBackingStore::new();
            id.injest_merkle_proof_ucs(&preparation, self.write_checkpoint_u64, proof)?;
            Self::seed_current_path(&scratch, preparation)?;
        }
        let predecessor_dmp = id.set_leaf_ucs(&scratch, self.write_checkpoint_u64, predecessor_leaf_index, predecessor_new_leaf.qfhash::<H>())?;
        let member_dmp = id.set_leaf_ucs(&scratch, self.write_checkpoint_u64, new_leaf_index, new_leaf_preimage.qfhash::<H>())?;
        let sentinel_old_leaf = if predecessor_leaf_index == state_slot_base { predecessor_new_leaf } else { sentinel_preimage };
        let sentinel_new_leaf = sentinel_old_leaf.with_new_value(QHashOut::from_values(count + 1, 0, 0, 0));
        let sentinel_dmp = id.set_leaf_ucs(&scratch, self.write_checkpoint_u64, state_slot_base, sentinel_new_leaf.qfhash::<H>())?;
        anyhow::ensure!(sentinel_dmp.old_value == sentinel_old_leaf.qfhash::<H>(), "invalid transient sentinel hash");
        self.validate_imt_tracker(contract.to_canonical_u64(), &[&predecessor_dmp, &member_dmp, &sentinel_dmp])?;
        let entries = self.get_staged_contract_entries(scratch, &id)?;
        self.state_tree_store.set_many_vec(entries)?;
        self.local_state_tracker.notify_imt_insert(
            contract.to_canonical_u64(), predecessor_leaf_index, predecessor_old_leaf, predecessor_new_leaf,
            new_leaf_index, new_leaf_preimage, predecessor_dmp.old_value, member_dmp.old_value,
            state_slot_base, capacity, sentinel_old_leaf, sentinel_new_leaf,
        );
        self.local_state_tracker.note_contract_state_root_transition(contract.to_canonical_u64(), predecessor_dmp.old_root, sentinel_dmp.new_root);
        Ok((predecessor_dmp, member_dmp, sentinel_dmp))
    }

    fn validate_imt_successor(leaf: IMTContractStateLeaf<F>, base: u64, count: u64) -> anyhow::Result<()> {
        let next = leaf.next_index.to_canonical_u64();
        anyhow::ensure!((next == 0 && leaf.next_key == QHashOut::ZERO)
            || (next > base && next <= base + count && leaf.next_key != QHashOut::ZERO), "invalid IMT successor");
        Ok(())
    }

    fn validate_imt_sentinel(proof: &MerkleProofCore<QHashOut<F>>, leaf: IMTContractStateLeaf<F>, base: u64, capacity: u64) -> anyhow::Result<u64> {
        let end = base.checked_add(capacity).ok_or_else(|| anyhow::anyhow!("IMT range overflow"))?;
        anyhow::ensure!(capacity > 0 && proof.siblings.len() < 64 && end < (1u64 << proof.siblings.len())
            && proof.index == base && proof.verify::<H>(), "invalid IMT sentinel path");
        let count = leaf.value.0.elements[0].to_canonical_u64();
        anyhow::ensure!(leaf.key == QHashOut::ZERO && leaf.value.0.elements[1..].iter().all(|v| *v == F::ZERO)
            && count <= capacity, "invalid IMT sentinel count");
        if count == 0 {
            anyhow::ensure!(leaf == IMTContractStateLeaf::default() && proof.value == QHashOut::ZERO, "invalid virgin sentinel");
        } else {
            anyhow::ensure!(proof.value == leaf.qfhash::<H>() && leaf.next_key != QHashOut::ZERO, "invalid initialized sentinel");
            Self::validate_imt_successor(leaf, base, count)?;
        }
        Ok(count)
    }

    fn validate_imt_tracker(&self, contract_id: u64, deltas: &[&DeltaMerkleProofCore<QHashOut<F>>]) -> anyhow::Result<()> {
        let tracker = self.local_state_tracker.contracts.get(&contract_id);
        let mut versions = HashMap::new();
        let mut root = tracker.map(|t| t.end_state_root).unwrap_or(deltas[0].old_root);
        for delta in deltas {
            anyhow::ensure!(delta.old_root == root && delta.verify::<H>(), "invalid IMT delta chain");
            let current = versions.get(&delta.index).copied().or_else(|| tracker.and_then(|t| t.slots.get(&delta.index)).and_then(|v| v.last()).copied());
            anyhow::ensure!(current.map_or(true, |value| value == delta.old_value), "IMT tracker version mismatch");
            versions.insert(delta.index, delta.new_value);
            root = delta.new_root;
        }
        if let Some(tracker) = tracker {
            anyhow::ensure!(tracker.next_op_seq < u64::MAX && tracker.total_keys_modified <= u32::MAX - 3, "IMT tracker counter overflow");
            for delta in deltas {
                anyhow::ensure!(tracker.slots.get(&delta.index).map_or(true, |v| !v.is_empty() && v.len() <= u32::MAX as usize - deltas.len()), "invalid IMT version chain length");
            }
        }
        anyhow::ensure!(self.local_state_tracker.total_keys_modified <= u32::MAX - 3, "IMT total counter overflow");
        Ok(())
    }

    fn get_staged_contract_entries(&self, scratch: KVQSimpleMemoryBackingStore, id: &UserContractStateTreeId<KVQSimpleMemoryBackingStore, F, H>) -> anyhow::Result<Vec<KVQPair<Vec<u8>, Vec<u8>>>> {
        let entries = scratch.into_entries()?;
        let identity = id.get_leaf_key(self.write_checkpoint_u64, 0);
        for entry in &entries {
            anyhow::ensure!(entry.key.len() == 32, "invalid staged node key length");
            let key = KVQMerkleNodeKey::<USER_CONTRACT_STATE_TREE_TABLE_TYPE>::from_bytes(&entry.key)?;
            anyhow::ensure!(key.to_bytes()? == entry.key && key.belongs_to_same_tree(&identity)
                && key.checkpoint_id == self.write_checkpoint_u64 && key.level <= id.height
                && key.index < (1u64 << key.level), "invalid staged contract node");
            QHashOut::<F>::from_bytes(&entry.value)?;
        }
        Ok(entries)
    }
    pub async fn get_contract_state_slot(&mut self, contract: F, slot: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        self.get_contract_state_slot_for_staging(contract, slot.to_canonical_u64()).await
    }

    fn build_current_path<const TABLE: u16>(
        &self,
        preparation: KVQSimpleMemoryBackingStore,
        identity: KVQMerkleNodeKey<TABLE>,
    ) -> anyhow::Result<KVQSimpleMemoryBackingStore> {
        let assembly = KVQSimpleMemoryBackingStore::new();
        let mut entries = preparation.into_entries()?;
        for entry in &mut entries {
            anyhow::ensure!(entry.key.len() == 32, "invalid immutable node key length");
            let key = KVQMerkleNodeKey::<TABLE>::from_bytes(&entry.key)?;
            anyhow::ensure!(key.to_bytes()? == entry.key && key.belongs_to_same_tree(&identity)
                && key.checkpoint_id == self.start_checkpoint_u64, "invalid immutable node identity");
            let current_key = key.at_checkpoint(self.write_checkpoint_u64);
            entry.key = current_key.to_bytes()?;
            if let Some(current) = self.state_tree_store.get_leq_kv(&entry.key, 8)? {
                anyhow::ensure!(current.key.len() == 32, "invalid live node key length");
                let found = KVQMerkleNodeKey::<TABLE>::from_bytes(&current.key)?;
                anyhow::ensure!(found.to_bytes()? == current.key && found.is_same_node_location(&current_key)
                    && found.checkpoint_id >= self.start_checkpoint_u64
                    && found.checkpoint_id <= self.write_checkpoint_u64, "invalid live node version");
                QHashOut::<F>::from_bytes(&current.value)?;
                entry.value = current.value;
            }
        }
        assembly.set_many_vec(entries)?;
        Ok(assembly)
    }

    fn seed_current_path(scratch: &KVQSimpleMemoryBackingStore, preparation: KVQSimpleMemoryBackingStore) -> anyhow::Result<()> {
        let entries = preparation.into_entries()?;
        for entry in &entries {
            if let Some(value) = scratch.get_exact_if_exists(&entry.key)? {
                anyhow::ensure!(value == entry.value, "overlapping current paths disagree");
            }
        }
        scratch.set_many_vec(entries)
    }

    async fn get_contract_state_slot_for_staging(&mut self, contract: F, slot: u64) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        if contract == F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64) {
            anyhow::ensure!(slot < (1u64 << MAX_CONTRACT_STATE_TREE_HEIGHT), "invalid local contract state position");
            let base = SimpleMerkleTree::<H, QHashOut<F>>::new(MAX_CONTRACT_STATE_TREE_HEIGHT).get_leaf(slot);
            let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore, F, H>::new(
                self.user_id_u64, u32::try_from(DEFAULT_CALLER_CONTRACT_ID_U64)?, MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
            );
            let preparation = KVQSimpleMemoryBackingStore::new();
            id.injest_merkle_proof_ucs(&preparation, self.start_checkpoint_u64, &base)?;
            let assembly = self.build_current_path(preparation, id.get_leaf_key(self.start_checkpoint_u64, slot))?;
            let proof = id.get_leaf_ucs(&assembly, self.write_checkpoint_u64, slot)?;
            let expected = self.local_state_tracker.contracts.get(&DEFAULT_CALLER_CONTRACT_ID_U64)
                .map(|tracker| tracker.end_state_root).unwrap_or(base.root);
            anyhow::ensure!(proof.root == expected && proof.verify::<H>(), "invalid current local contract state proof");
            return Ok(proof);
        }
        let contract_id = u32::try_from(contract.to_canonical_u64())?;
        let height = self.get_contract_inclusion_proof(contract_id).await?.contract_leaf.state_tree_height.to_canonical_u64();
        anyhow::ensure!(height < 64 && slot < (1u64 << height), "invalid contract state position");
        let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore, F, H>::new(self.user_id_u64, contract_id, height as u8);
        let base = self.cmd_store.resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
            QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                checkpoint_id: self.start_checkpoint_u64, user_id: self.user_id_u64,
                contract_id, height: height as u8, leaf_id: slot,
            },
        )).await?;
        let upper = self.get_immutable_user_contract_tree_leaf(contract_id).await?;
        let start_root = if upper.value == QHashOut::ZERO { H::get_zero_hash(height as usize) } else { upper.value };
        anyhow::ensure!(base.index == slot && base.siblings.len() == height as usize
            && base.root == start_root && base.verify::<H>(), "invalid immutable contract state proof");
        let preparation = KVQSimpleMemoryBackingStore::new();
        id.injest_merkle_proof_ucs(&preparation, self.start_checkpoint_u64, &base)?;
        let assembly = self.build_current_path(preparation, id.get_leaf_key(self.start_checkpoint_u64, slot))?;
        let proof = id.get_leaf_ucs(&assembly, self.write_checkpoint_u64, slot)?;
        let expected = self.local_state_tracker.contracts.get(&(contract_id as u64))
            .map(|tracker| tracker.end_state_root).unwrap_or(start_root);
        anyhow::ensure!(proof.root == expected && proof.verify::<H>(), "invalid current contract state proof");
        Ok(proof)
    }

    async fn get_immutable_user_contract_tree_leaf(&mut self, contract_id: u32) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        let proof = self.cmd_store.resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractTreeMerkleProof(
            QSRMerkleCmdGetUserContractTreeMerkleProof {
                checkpoint_id: self.start_checkpoint_u64, user_id: self.user_id_u64, contract_id,
            },
        )).await?;
        let user = if self.is_new_user {
            self.get_fresh_start_ctx_for_user(self.user_id).await?.start_session_user_leaf
        } else {
            self.cmd_store.resolve_get_user_leaf_mut(&QSRCmdGetUserLeafData {
                checkpoint_id: self.start_checkpoint_u64, user_id: self.user_id_u64,
            }).await?
        };
        anyhow::ensure!(proof.index == contract_id as u64 && proof.siblings.len() == usize::from(GLOBAL_CONTRACT_TREE_HEIGHT)
            && proof.root == user.user_state_tree_root && proof.verify::<H>(), "invalid immutable user contract proof");
        Ok(proof)
    }

    pub async fn get_self_user_contract_tree_leaf(&mut self, contract_id: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        self.get_self_user_contract_tree_leaf_for_staging(u32::try_from(contract_id.to_canonical_u64())?).await
    }

    async fn get_self_user_contract_tree_leaf_for_staging(&mut self, contract_id: u32) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        let base = self.get_immutable_user_contract_tree_leaf(contract_id).await?;
        let preparation = KVQSimpleMemoryBackingStore::new();
        UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::injest_merkle_proof_sfc(
            &preparation, self.user_id_u64, self.start_checkpoint_u64, &base,
        )?;
        let identity = UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::new_leaf_key_sfc(
            self.start_checkpoint_u64, self.user_id_u64, contract_id as u64,
        );
        let assembly = self.build_current_path(preparation, identity)?;
        let proof = UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::get_leaf_sfc(
            &assembly, self.write_checkpoint_u64, self.user_id_u64, contract_id as u64,
        )?;
        let expected = match self.state_tree_store.get_leq_kv(&identity.root().at_checkpoint(self.write_checkpoint_u64).to_bytes()?, 8)? {
            Some(entry) => QHashOut::<F>::from_bytes(&entry.value)?,
            None => base.root,
        };
        anyhow::ensure!(proof.root == expected && proof.verify::<H>(), "invalid current user contract proof");
        Ok(proof)
    }

    fn set_user_contract_tree_leaf_from_old_proof(
        &mut self,
        contract_id: u64,
        old_proof: &MerkleProofCore<QHashOut<F>>,
        new_value: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        let mut current_key =
            UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::new_leaf_key_sfc(self.write_checkpoint_u64, self.user_id_u64, contract_id);
        let mut current_value = new_value;
        let mut updates: Vec<KVQPair<_, _>> = Vec::with_capacity((current_key.level as usize) + 1);
        let height = current_key.level as usize;
        if height > 0 {
            let new_key = current_key.parent();
            let index = current_key.index;
            updates.push(KVQPair {
                key: current_key,
                value: current_value,
            });
            current_value = if index & 1 == 0 {
                <H as MerkleHasher<QHashOut<F>>>::two_to_one(&current_value, &old_proof.siblings[0])
            } else {
                <H as MerkleHasher<QHashOut<F>>>::two_to_one(&old_proof.siblings[0], &current_value)
            };
            current_key = new_key;
        }
        for i in 1..height {
            let new_key = current_key.parent();
            let index = current_key.index;
            updates.push(KVQPair {
                key: current_key,
                value: current_value,
            });
            current_value = if index & 1 == 0 {
                <H as MerkleHasher<QHashOut<F>>>::two_to_one(&current_value, &old_proof.siblings[i])
            } else {
                <H as MerkleHasher<QHashOut<F>>>::two_to_one(&old_proof.siblings[i], &current_value)
            };
            current_key = new_key;
        }
        updates.push(KVQPair {
            key: current_key,
            value: current_value,
        });
        UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::set_nodes(&mut self.state_tree_store, &updates)?;
        tracing::info!(
            "DEBUG set_user_contract_tree_leaf_from_old_proof contract_id={} old_root={} old_value={} new_value={} new_root={}",
            contract_id,
            old_proof.root,
            old_proof.value,
            new_value,
            current_value
        );
        Ok(DeltaMerkleProofCore {
            old_root: old_proof.root,
            old_value: old_proof.value,
            new_root: current_value,
            new_value,
            index: old_proof.index,
            siblings: old_proof.siblings.clone(),
        })
    }

    async fn update_contract_state_root_in_user_contract_tree(&mut self, contract_id: F) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        if contract_id == F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64) {
            let empty_tree = SimpleMerkleTree::<H, QHashOut<F>>::new(MAX_CONTRACT_STATE_TREE_HEIGHT);
            return Ok(empty_tree.get_leaf(DEFAULT_CALLER_CONTRACT_ID_U64).to_delta_merkle_proof());
        }
        let contract_id_u64 = contract_id.to_canonical_u64();
        let latest_root = if let Some(tracker) = self.local_state_tracker.contracts.get(&contract_id_u64) {
            tracker.end_state_root
        } else {
            self.get_contract_state_slot(contract_id, F::ZERO).await?.root
        };
        // Use the same local-overlay-aware leaf reader as get_call_start_data
        // to ensure the DMP old_value matches the CFC witness's
        // start_contract_state_tree_root.  Previously this fetched a fresh
        // merkle proof from the coordinator, which could diverge from the
        let old_leaf_proof = self.get_self_user_contract_tree_leaf(contract_id).await?;
        tracing::info!(
            "DEBUG update_contract_state_root_in_user_contract_tree contract_id={} old_leaf_proof: root={} value={} latest_root={}",
            contract_id_u64,
            old_leaf_proof.root,
            old_leaf_proof.value,
            latest_root
        );
        self.set_user_contract_tree_leaf_from_old_proof(contract_id_u64, &old_leaf_proof, latest_root)
    }
    pub async fn get_external_user_leaf_proof(&mut self, user_id: F) -> anyhow::Result<DPNReadOtherUserLeafMerkleProof<F>> {
        let user_tree_proof = self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserTreeMerkleProof(QSRMerkleCmdGetUserTreeMerkleProof {
                checkpoint_id: self.start_checkpoint_u64,
                user_id: user_id.to_canonical_u64(),
            }))
            .await?;
        let user_leaf = if user_id == self.user_id && self.is_new_user {
            let user_registration_tree_proof: MerkleProofCore<QHashOut<F>> = self
                .cmd_store
                .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserRegistrationTreeMerkleProof(
                    QSRMerkleCmdGetUserRegistrationTreeMerkleProof {
                        checkpoint_id: self.start_checkpoint_u64,
                        leaf_index: get_registration_id_from_user_id(user_id.to_canonical_u64()),
                    },
                ))
                .await?;
            get_new_empty_user_leaf(user_id, user_registration_tree_proof.value)
        } else {
            self.cmd_store
                .resolve_get_user_leaf_mut(&QSRCmdGetUserLeafData {
                    checkpoint_id: self.start_checkpoint_u64,
                    user_id: user_id.to_canonical_u64(),
                })
                .await?
        };
        Ok(DPNReadOtherUserLeafMerkleProof { user_tree_proof, user_leaf })
    }
    pub fn add_deferred_tx_to_debt(&mut self, tx: DPNProvingSessionSimpleMethodCall<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        let insertion_result = self.deferred_tx_debt_store.add_tx_debt(&mut self.active_tx_session_data_store, tx)?;
        let tx_debt_item = self.deferred_tx_debt_store.get_latest_proof_debt_item().unwrap().to_owned();
        self.last_transaction_record_mut().add_deferred_tx_item(tx_debt_item);

        Ok(insertion_result)
    }
    pub fn get_deferred_tx_leaf(&self, leaf_index: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        self.deferred_tx_debt_store
            .get_tx_debt_leaf(&self.active_tx_session_data_store, leaf_index.to_canonical_u64())
    }
    pub fn get_latest_deferred_tx_leaf(&self) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        self.deferred_tx_debt_store.get_latest_tx_debt_leaf(&self.active_tx_session_data_store)
    }
    pub fn repay_deferred_tx_debt(
        &mut self,
        tree_leaf_index: u64,
    ) -> anyhow::Result<(
        DPNTransactionDebtItem<DPNProvingSessionSimpleMethodCall<F>, F>,
        DeltaMerkleProofCore<QHashOut<F>>,
    )> {
        self.deferred_tx_debt_store
            .repay_tx_debt(&mut self.active_tx_session_data_store, tree_leaf_index)
    }

    pub async fn finalize_transaction(&mut self) -> anyhow::Result<()> {
        let contract_id = self.last_transaction_record().call_data.call_data.contract_id;

        let uct_proof = self.update_contract_state_root_in_user_contract_tree(contract_id).await?;
        tracing::debug!("finalize_transaction.uct_proof: {}", serde_json::to_string_pretty(&uct_proof).unwrap());
        self.last_transaction_record_mut().set_uct_proof(uct_proof);

        Ok(())
    }
    pub async fn get_ups_start_ctx(&mut self) -> anyhow::Result<UserProvingSessionStartContext<F>> {
        let checkpoint_id = self.start_checkpoint_u64;
        let checkpoint_leaf = self
            .cmd_store
            .resolve_get_checkpoint_leaf_mut(&QSRCmdGetCheckpointLeafData { checkpoint_id })
            .await?;
        let checkpoint_tree_root = self
            .cmd_store
            .resolve_get_hash_mut(&QSRHashCmd::GetCheckpointTreeRoot(QSRHashCmdGetCheckpointTreeRoot { checkpoint_id }))
            .await?;
        let user_leaf = if self.is_new_user {
            let user_registration_tree_proof: MerkleProofCore<QHashOut<F>> = self
                .cmd_store
                .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserRegistrationTreeMerkleProof(
                    QSRMerkleCmdGetUserRegistrationTreeMerkleProof {
                        checkpoint_id: self.start_checkpoint_u64,
                        leaf_index: get_registration_id_from_user_id(self.user_id.to_canonical_u64()),
                    },
                ))
                .await?;
            get_new_empty_user_leaf(self.user_id, user_registration_tree_proof.value)
        } else {
            self.cmd_store
                .resolve_get_user_leaf_mut(&QSRCmdGetUserLeafData {
                    checkpoint_id: self.start_checkpoint_u64,
                    user_id: self.user_id.to_canonical_u64(),
                })
                .await?
        };
        let start_ctx = UserProvingSessionStartContext::<F> {
            checkpoint_id: self.start_checkpoint,
            checkpoint_tree_root,
            checkpoint_leaf_hash: checkpoint_leaf.qfhash::<H>(),
            start_session_user_leaf: user_leaf,
        };
        tracing::debug!("ups_start_ctx: {}", serde_json::to_string_pretty(&start_ctx).unwrap());
        Ok(start_ctx)
    }

    pub async fn get_contract_inclusion_proof(&mut self, contract_id: u32) -> anyhow::Result<PsyContractInclusionProof<F>> {
        tracing::debug!("get_contract_inclusion_proof.contract_id: {}", contract_id);
        let contract_leaf = self
            .cmd_store
            .resolve_get_contract_leaf_mut(&QSRCmdGetContractLeafData {
                contract_id: contract_id as u64,
            })
            .await?;
        let contract_tree_merkle_proof = self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetContractTreeMerkleProof(QSRMerkleCmdGetContractTreeMerkleProof {
                checkpoint_id: self.start_checkpoint_u64,
                contract_id: contract_id,
            }))
            .await?;
        let contract_leaf_hash = contract_leaf.qfhash::<H>();
        let checkpoint_contract_tree_root = self.get_global_state_tree_roots(self.start_checkpoint_u64).await?.contract_tree_root;

        anyhow::ensure!(
            contract_tree_merkle_proof.verify::<H>(),
            "invalid contract tree Merkle proof at checkpoint {} for contract {}: proof_root={}, proof_value={}",
            self.start_checkpoint_u64,
            contract_id,
            contract_tree_merkle_proof.root,
            contract_tree_merkle_proof.value,
        );
        anyhow::ensure!(
            contract_tree_merkle_proof.value == contract_leaf_hash,
            "contract leaf/proof checkpoint mismatch for contract {}: session_checkpoint={}, proof_value={}, latest_contract_leaf_hash={}",
            contract_id,
            self.start_checkpoint_u64,
            contract_tree_merkle_proof.value,
            contract_leaf_hash,
        );
        anyhow::ensure!(
            contract_tree_merkle_proof.root == checkpoint_contract_tree_root,
            "contract tree root/checkpoint mismatch for contract {}: session_checkpoint={}, proof_root={}, checkpoint_contract_tree_root={}",
            contract_id,
            self.start_checkpoint_u64,
            contract_tree_merkle_proof.root,
            checkpoint_contract_tree_root,
        );

        Ok(PsyContractInclusionProof {
            contract_leaf,
            contract_tree_merkle_proof,
        })
    }

    pub async fn get_contract_function_inclusion_proof(
        &mut self,
        contract_id: u32,
        function_id: u32,
    ) -> anyhow::Result<PsyContractFunctionInclusionProof<F>> {
        let fingerprint_leaf_index = function_id.checked_mul(2)
            .ok_or_else(|| anyhow::anyhow!("contract function fingerprint leaf index overflow"))?;
        let contract_inclusion_proof = self.get_contract_inclusion_proof(contract_id).await?;
        let contract_function_merkle_proof = self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetContractFunctionTreeMerkleProof(
                QSRMerkleCmdGetContractFunctionTreeMerkleProof {
                    checkpoint_id: self.start_checkpoint_u64,
                    contract_id,
                    function_id: fingerprint_leaf_index,
                },
            ))
            .await?;

        Ok(PsyContractFunctionInclusionProof {
            contract_inclusion_proof,
            contract_function_merkle_proof,
        })
    }

    pub async fn get_all_state_updates(&mut self) -> anyhow::Result<(Vec<PsyContractStateUpdateHistory<F>>, u32)> {
        use crate::qdata::imt_proof::IMTContractStateUpdate;

        let total_modified = self.local_state_tracker.total_slots_modified
            .checked_add(self.local_state_tracker.get_total_keys_modified())
            .ok_or_else(|| anyhow::anyhow!("modified slot accounting overflow"))?;
        let tracker_results: Vec<_> = self.local_state_tracker.contracts.values().cloned().collect();
        let scratch = KVQSimpleMemoryBackingStore::new();
        let mut identities = Vec::with_capacity(tracker_results.len());
        let mut sentinel_preimages = HashMap::new();
        let mut upper_root = None;
        // Seed every historical path before any write, so no later contract can
        // restore a sibling already changed by replay.
        for tracker in &tracker_results {
            let contract_id = u32::try_from(tracker.contract_id)?;
            let height = self.get_contract_inclusion_proof(contract_id).await?.contract_leaf.state_tree_height.to_canonical_u64();
            anyhow::ensure!(height < 64, "invalid replay tree height");
            let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore, F, H>::new(self.user_id_u64, contract_id, height as u8);
            let upper = self.get_immutable_user_contract_tree_leaf(contract_id).await?;
            anyhow::ensure!(upper_root.map_or(true, |root| root == upper.root), "historical UCON roots disagree");
            upper_root = Some(upper.root);
            let start_root = if upper.value == QHashOut::ZERO { H::get_zero_hash(height as usize) } else { upper.value };
            anyhow::ensure!(start_root == tracker.start_state_root, "historical CSTATE root mismatch");
            let preparation = KVQSimpleMemoryBackingStore::new();
            UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::injest_merkle_proof_sfc(
                &preparation, self.user_id_u64, self.write_checkpoint_u64, &upper,
            )?;
            Self::seed_current_path(&scratch, preparation)?;
            for (&slot, versions) in &tracker.slots {
                anyhow::ensure!(slot < (1u64 << height), "invalid replay slot");
                let base = self.cmd_store.resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                    QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                        checkpoint_id: self.start_checkpoint_u64, user_id: self.user_id_u64,
                        contract_id, height: height as u8, leaf_id: slot,
                    },
                )).await?;
                anyhow::ensure!(base.index == slot && base.siblings.len() == height as usize && base.root == start_root
                    && base.verify::<H>() && versions.first() == Some(&base.value), "invalid historical CSTATE path");
                let preparation = KVQSimpleMemoryBackingStore::new();
                id.injest_merkle_proof_ucs(&preparation, self.write_checkpoint_u64, &base)?;
                Self::seed_current_path(&scratch, preparation)?;
            }
            for op in &tracker.ops {
                if let PsyStateOperation::IMTUpdate { state_slot_base, capacity, .. } = op {
                    if tracker.slots.contains_key(state_slot_base) || sentinel_preimages.contains_key(&(tracker.contract_id, *state_slot_base)) {
                        continue;
                    }
                    let base = self.cmd_store.resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                        QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                            checkpoint_id: self.start_checkpoint_u64, user_id: self.user_id_u64,
                            contract_id, height: height as u8, leaf_id: *state_slot_base,
                        },
                    )).await?;
                    let leaf = self.cmd_store.resolve_contract_state_imt_get_leaf_preimage_mut(
                        &crate::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                            checkpoint_id: self.start_checkpoint_u64, user_id: self.user_id_u64,
                            contract_id, leaf_index: *state_slot_base,
                        },
                    ).await?;
                    anyhow::ensure!(base.root == start_root && base.siblings.len() == height as usize, "historical sentinel root mismatch");
                    Self::validate_imt_sentinel(&base, leaf, *state_slot_base, *capacity)?;
                    let preparation = KVQSimpleMemoryBackingStore::new();
                    id.injest_merkle_proof_ucs(&preparation, self.write_checkpoint_u64, &base)?;
                    Self::seed_current_path(&scratch, preparation)?;
                    sentinel_preimages.insert((tracker.contract_id, *state_slot_base), leaf);
                }
            }
            identities.push(id);
        }

        let mut update_results = Vec::with_capacity(tracker_results.len());
        for (tracker, id) in tracker_results.iter().zip(&identities) {
            let mut root = tracker.start_state_root;
            let mut contract_state_tree_updates = Vec::with_capacity(tracker.ops.len());
            let slot_hash = |slot: u64, version: u32| -> anyhow::Result<QHashOut<F>> {
                tracker.slots.get(&slot).and_then(|versions| versions.get(version as usize)).copied()
                    .ok_or_else(|| anyhow::anyhow!("invalid replay slot version"))
            };
            let preimage = |hash: QHashOut<F>| -> anyhow::Result<IMTContractStateLeaf<F>> {
                if hash == QHashOut::ZERO { return Ok(IMTContractStateLeaf::default()); }
                let leaf = tracker.imt_preimages.get(&hash).copied().ok_or_else(|| anyhow::anyhow!("missing replay IMT preimage"))?;
                anyhow::ensure!(leaf.qfhash::<H>() == hash, "invalid replay IMT preimage");
                Ok(leaf)
            };
            let mut apply = |slot: u64, from: u32, to: u32| -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
                anyhow::ensure!(from.checked_add(1) == Some(to), "nonconsecutive replay versions");
                let delta = id.set_leaf_ucs(&scratch, self.write_checkpoint_u64, slot, slot_hash(slot, to)?)?;
                anyhow::ensure!(delta.old_root == root && delta.old_value == slot_hash(slot, from)?
                    && delta.verify::<H>(), "invalid replay delta");
                root = delta.new_root;
                Ok(delta)
            };
            for (sequence, op) in tracker.ops.iter().enumerate() {
                match op {
                    PsyStateOperation::IMTUpdate { op_seq, leaf_index, from_version, to_version, state_slot_base, capacity, .. } => {
                        anyhow::ensure!(*op_seq == sequence as u64, "invalid replay operation order");
                        let old_preimage = preimage(slot_hash(*leaf_index, *from_version)?)?;
                        let new_preimage = preimage(slot_hash(*leaf_index, *to_version)?)?;
                        let sentinel_path = id.get_leaf_ucs(&scratch, self.write_checkpoint_u64, *state_slot_base)?;
                        let sentinel_leaf = match sentinel_preimages.get(&(tracker.contract_id, *state_slot_base)) {
                            Some(leaf) => *leaf,
                            None => preimage(sentinel_path.value)?,
                        };
                        let count = Self::validate_imt_sentinel(&sentinel_path, sentinel_leaf, *state_slot_base, *capacity)?;
                        anyhow::ensure!(*leaf_index > *state_slot_base && *leaf_index <= state_slot_base + count, "replay member outside allocation");
                        Self::validate_imt_successor(old_preimage, *state_slot_base, count)?;
                        anyhow::ensure!(old_preimage.key != QHashOut::ZERO && old_preimage.key == new_preimage.key
                            && old_preimage.next_key == new_preimage.next_key && old_preimage.next_index == new_preimage.next_index,
                            "invalid replay IMT update");
                        let delta_proof = apply(*leaf_index, *from_version, *to_version)?;
                        contract_state_tree_updates.push(ContractStateUpdate::IMT {
                            update: IMTContractStateUpdate::Update { old_preimage, new_preimage, delta_proof },
                        });
                    }
                    PsyStateOperation::IMTInsert {
                        op_seq, predecessor_leaf_index, predecessor_from_version, predecessor_to_version,
                        new_leaf_index, new_leaf_from_version, new_leaf_to_version,
                        state_slot_base, capacity, sentinel_from_version, sentinel_to_version, ..
                    } => {
                        anyhow::ensure!(*op_seq == sequence as u64, "invalid replay operation order");
                        let predecessor_old_preimage = preimage(slot_hash(*predecessor_leaf_index, *predecessor_from_version)?)?;
                        let predecessor_new_preimage = preimage(slot_hash(*predecessor_leaf_index, *predecessor_to_version)?)?;
                        let new_leaf_preimage = preimage(slot_hash(*new_leaf_index, *new_leaf_to_version)?)?;
                        let sentinel_old_preimage = preimage(slot_hash(*state_slot_base, *sentinel_from_version)?)?;
                        let sentinel_new_preimage = preimage(slot_hash(*state_slot_base, *sentinel_to_version)?)?;
                        let starting_sentinel = if predecessor_leaf_index == state_slot_base { predecessor_old_preimage } else { sentinel_old_preimage };
                        let sentinel_path = id.get_leaf_ucs(&scratch, self.write_checkpoint_u64, *state_slot_base)?;
                        let count = Self::validate_imt_sentinel(&sentinel_path, starting_sentinel, *state_slot_base, *capacity)?;
                        anyhow::ensure!(count < *capacity && *new_leaf_index == state_slot_base + count + 1
                            && slot_hash(*new_leaf_index, *new_leaf_from_version)? == QHashOut::ZERO
                            && sentinel_new_preimage == sentinel_old_preimage.with_new_value(QHashOut::from_values(count + 1, 0, 0, 0))
                            && sentinel_old_preimage == if predecessor_leaf_index == state_slot_base { predecessor_new_preimage } else { starting_sentinel },
                            "invalid replay insertion count");
                        use crate::qdata::imt_contract_state::compare_qhashout_keys;
                        anyhow::ensure!(*predecessor_leaf_index >= *state_slot_base && *predecessor_leaf_index <= state_slot_base + count
                            && new_leaf_preimage.key != QHashOut::ZERO
                            && compare_qhashout_keys(&predecessor_old_preimage.key, &new_leaf_preimage.key).is_lt()
                            && (predecessor_old_preimage.next_key == QHashOut::ZERO
                                || compare_qhashout_keys(&new_leaf_preimage.key, &predecessor_old_preimage.next_key).is_lt())
                            && predecessor_new_preimage == predecessor_old_preimage.with_new_next(new_leaf_preimage.key, F::from_canonical_u64(*new_leaf_index))
                            && new_leaf_preimage.next_key == predecessor_old_preimage.next_key
                            && new_leaf_preimage.next_index == predecessor_old_preimage.next_index,
                            "invalid replay predecessor splice");
                        Self::validate_imt_successor(predecessor_old_preimage, *state_slot_base, count)?;
                        let predecessor_delta_proof = apply(*predecessor_leaf_index, *predecessor_from_version, *predecessor_to_version)?;
                        let new_leaf_delta_proof = apply(*new_leaf_index, *new_leaf_from_version, *new_leaf_to_version)?;
                        let sentinel_delta_proof = apply(*state_slot_base, *sentinel_from_version, *sentinel_to_version)?;
                        contract_state_tree_updates.push(ContractStateUpdate::IMT {
                            update: IMTContractStateUpdate::Insert {
                                predecessor_old_preimage, predecessor_new_preimage, new_leaf_preimage,
                                predecessor_delta_proof, new_leaf_delta_proof,
                                sentinel_old_preimage, sentinel_new_preimage, sentinel_delta_proof,
                            },
                        });
                    }
                    PsyStateOperation::PositionalWrite { op_seq, contract_id, slot, from_version, to_version } => {
                        anyhow::ensure!(*op_seq == sequence as u64 && *contract_id == tracker.contract_id, "invalid replay positional operation");
                        let delta_proof = apply(*slot, *from_version, *to_version)?;
                        contract_state_tree_updates.push(ContractStateUpdate::Positional { delta_proof });
                    }
                }
            }
            anyhow::ensure!(root == tracker.end_state_root, "replay final CSTATE root mismatch");
            let upper = UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::get_leaf_sfc(
                &scratch, self.write_checkpoint_u64, self.user_id_u64, tracker.contract_id,
            )?;
            anyhow::ensure!(Some(upper.root) == upper_root && upper.verify::<H>(), "replay UCON path mismatch");
            let user_contract_tree_update_proof = UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::set_leaf_sfc(
                &scratch, self.write_checkpoint_u64, self.user_id_u64, tracker.contract_id, root,
            )?;
            anyhow::ensure!(user_contract_tree_update_proof.verify::<H>(), "invalid replay UCON delta");
            upper_root = Some(user_contract_tree_update_proof.new_root);
            update_results.push(PsyContractStateUpdateHistory { user_contract_tree_update_proof, contract_state_tree_updates });
        }
        for history in &update_results {
            for update in &history.contract_state_tree_updates {
                if let ContractStateUpdate::IMT { update } = update {
                    update.validate_imt_update()?;
                }
            }
        }
        bincode::serialize_into(std::io::sink(), &update_results)?;
        let entries = scratch.into_entries()?;
        for entry in &entries {
            anyhow::ensure!(entry.key.len() == 32, "invalid replay node key length");
            let state_key = KVQMerkleNodeKey::<USER_CONTRACT_STATE_TREE_TABLE_TYPE>::from_bytes(&entry.key)?;
            let upper_key = KVQMerkleNodeKey::<USER_CONTRACT_TREE_TABLE_TYPE>::from_bytes(&entry.key)?;
            let valid_state = state_key.to_bytes()? == entry.key && identities.iter().any(|id| {
                state_key.belongs_to_same_tree(&id.get_leaf_key(self.write_checkpoint_u64, 0))
                    && state_key.level <= id.height && state_key.index < (1u64 << state_key.level)
            });
            let upper_identity = UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::new_leaf_key_sfc(self.write_checkpoint_u64, self.user_id_u64, 0);
            let valid_upper = upper_key.to_bytes()? == entry.key && upper_key.belongs_to_same_tree(&upper_identity)
                && upper_key.level <= upper_identity.level && upper_key.index < (1u64 << upper_key.level);
            anyhow::ensure!((valid_state || valid_upper) && state_key.checkpoint_id == self.write_checkpoint_u64, "invalid replay output node");
            QHashOut::<F>::from_bytes(&entry.value)?;
        }
        self.state_tree_store.set_many_vec(entries)?;
        Ok((update_results, total_modified))
    }

    pub fn get_total_modified_slots_for_fee(&self) -> u32 {
        self.local_state_tracker.total_slots_modified + self.local_state_tracker.get_total_keys_modified()
    }

    pub fn has_positional_slot_update(&self, contract_id: u64, slot: u64) -> bool {
        self.local_state_tracker
            .contracts
            .get(&contract_id)
            .and_then(|tracker| tracker.slots.get(&slot))
            .map(|versions| !versions.is_empty() && versions.first() != versions.last())
            .unwrap_or(false)
    }

    pub async fn get_checkpoint_state_roots(&mut self, checkpoint_id: u64) -> anyhow::Result<PsyCheckpointGlobalStateRoots<F>> {
        self.cmd_store.read_store.get_checkpoint_global_state_roots(checkpoint_id).await
    }

    pub async fn notify_clear_entire_tree(&mut self, contract_id: u64) -> anyhow::Result<()> {
        if let Some(contract_result) = self.local_state_tracker.get_contract_result(contract_id) {
            for (slot_index, _) in contract_result.slots.iter() {
                self.set_contract_state_slot(F::from_canonical_u64(contract_id), F::from_canonical_u64(*slot_index), QHashOut::ZERO)
                    .await?;
            }
        }
        Ok(())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<
        F: RichField,
        H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F> + Send,
        R: PsyReadCommandProcessorSync<F> + QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    > PsyEventsStore<F> for PsyLocalProvingSessionStore<F, R, H>
{
    fn set_start_event_index(&mut self, event_index: F) {
        self.start_event_index = event_index;
    }

    fn write_events(&mut self, events: Vec<PsyUserEventRecord<F>>) {
        self.start_event_index += F::from_canonical_usize(events.len());
        self.events.extend(events);
    }

    fn read_events(&self) -> Vec<PsyUserEventRecord<F>> {
        self.events.clone()
    }

    fn get_event_index(&self) -> F {
        self.start_event_index
    }
}

#[cfg(all(test, feature = "is_sync"))]
mod function_inclusion_tests {
    use super::*;
    use plonky2::field::types::Field;
    use crate::{config::store_config::{PsyFelt, PsyHasher}, qdata::contract::PsyContractLeaf, traits::qdatastore::{qmetadata::QMetaDataStoreWriterSync, qtreedata::{QTreeDataStoreReaderSync, QTreeDataStoreWriterSync}}};

    #[test]
    fn nonzero_function_inclusion_uses_fingerprint_not_neighboring_leaves() -> anyhow::Result<()> {
        let store = KVQSimpleMemoryBackingStore::new();
        let leaves: Vec<_> = (0..6).map(|index| QHashOut::<PsyFelt>::from_values(100 + index, 0, 0, 0)).collect();
        let root = store.set_contract_function_whitelist(1, 6, &leaves)?;
        let contract = PsyContractLeaf { function_tree_root: root, ..Default::default() };
        store.set_contract_leaf_data(1, 6, &contract)?;
        store.set_contract_tree_leaf_hash(1, 6, contract.qfhash::<PsyHasher>())?;
        let mut session = PsyLocalProvingSessionStore::<PsyFelt, _, PsyHasher>::new_at(store.clone(), PsyFelt::ONE, PsyFelt::ZERO, PsyFelt::ONE, PsyFelt::ZERO, 16);
        let inclusion = session.get_contract_function_inclusion_proof(6, 1)?;
        assert_eq!(inclusion.contract_function_merkle_proof.index, 2);
        assert_eq!(inclusion.get_function_verifier_fingerprint(), leaves[2]);
        assert_eq!(inclusion.contract_function_merkle_proof.root, root);
        assert!(inclusion.verify::<PsyHasher>());
        for index in [2u32, 3, 4] {
            let physical = store.get_contract_function_tree_merkle_proof(1, 6, index)?;
            assert_eq!(physical.index, index as u64);
            assert_eq!(physical.value, leaves[index as usize]);
            assert_eq!(physical.root, root);
            assert!(physical.verify::<PsyHasher>());
        }
        assert!(session.get_contract_function_inclusion_proof(6, 1u32 << 31).is_err());
        Ok(())
    }

}

#[cfg(all(test, feature = "is_sync"))]
mod imt_atomic_tests {
    use super::*;
    use plonky2::field::types::Field;
    use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
    use crate::{config::store_config::PsyFelt, traits::qdatastore::{qmetadata::QMetaDataStoreWriterSync, qtreedata::QTreeDataStoreWriterSync}};

    type Session = PsyLocalProvingSessionStore<PsyFelt, KVQSimpleMemoryBackingStore, PsyHasher>;

    fn session() -> anyhow::Result<Session> {
        let store = KVQSimpleMemoryBackingStore::new();
        let contract = PsyContractLeaf { state_tree_height: PsyFelt::from_canonical_u64(5), ..Default::default() };
        store.set_contract_leaf_data(1, 6, &contract)?;
        store.set_contract_tree_leaf_hash(1, 6, contract.qfhash::<PsyHasher>())?;
        let upper = store.set_user_contract_tree_leaf_hash(1, 7, 6, PsyHasher::get_zero_hash(5))?;
        let user = PsyUserLeaf { user_id: PsyFelt::from_canonical_u64(7), user_state_tree_root: upper.new_root, ..Default::default() };
        store.set_user_leaf_data(1, &user)?;
        Ok(Session::new_at(store, PsyFelt::ONE, user.user_id, PsyFelt::ONE, PsyFelt::ZERO, 16))
    }

    fn insert(session: &mut Session, predecessor_index: u64, predecessor: IMTContractStateLeaf<PsyFelt>, sentinel: IMTContractStateLeaf<PsyFelt>, key: u64)
        -> anyhow::Result<(DeltaMerkleProofCore<QHashOut<PsyFelt>>, DeltaMerkleProofCore<QHashOut<PsyFelt>>, DeltaMerkleProofCore<QHashOut<PsyFelt>>)> {
        let index = 5 + sentinel.value.0.elements[0].to_canonical_u64();
        let member = IMTContractStateLeaf::new(QHashOut::from_values(key, 0, 0, 0), QHashOut::from_values(9, 0, 0, 0), predecessor.next_key, predecessor.next_index);
        session.set_contract_state_imt_insert(PsyFelt::from_canonical_u64(6), predecessor_index, PsyFelt::from_canonical_u64(predecessor_index),
            predecessor, predecessor.with_new_next(member.key, PsyFelt::from_canonical_u64(index)), index, PsyFelt::from_canonical_u64(index), member, 4, 3, sentinel)
    }

    #[test]
    fn successive_insertions_and_update_replay_three_writes() -> anyhow::Result<()> {
        let mut session = session()?;
        let (first, member, count) = insert(&mut session, 4, IMTContractStateLeaf::default(), IMTContractStateLeaf::default(), 10)?;
        assert_eq!(first.old_value, QHashOut::ZERO);
        assert_eq!(first.new_root, member.old_root);
        assert_eq!(member.new_root, count.old_root);
        assert_eq!(count.old_value, first.new_value);
        let mut sentinel = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::from_values(1, 0, 0, 0), QHashOut::from_values(10, 0, 0, 0), PsyFelt::from_canonical_u64(5));
        let first_member = IMTContractStateLeaf::new(sentinel.next_key, QHashOut::from_values(9, 0, 0, 0), QHashOut::ZERO, PsyFelt::ZERO);
        let (_, _, second_count) = insert(&mut session, 5, first_member, sentinel, 20)?;
        sentinel.value = QHashOut::from_values(2, 0, 0, 0);
        let (_, _, third_count) = insert(&mut session, 4, sentinel, sentinel, 5)?;
        assert_ne!(second_count.new_root, third_count.new_root);
        sentinel.value = QHashOut::from_values(3, 0, 0, 0);
        sentinel.next_key = QHashOut::from_values(5, 0, 0, 0);
        sentinel.next_index = PsyFelt::from_canonical_u64(7);
        let old_member = IMTContractStateLeaf::new(QHashOut::from_values(20, 0, 0, 0), QHashOut::from_values(9, 0, 0, 0), QHashOut::ZERO, PsyFelt::ZERO);
        let delta = session.set_contract_state_imt_update(PsyFelt::from_canonical_u64(6), 6, PsyFelt::from_canonical_u64(6), old_member.key,
            old_member, old_member.with_new_value(QHashOut::from_values(12, 0, 0, 0)), 4, 3, sentinel)?;
        let tracker = session.local_state_tracker.contracts.clone();
        assert!(insert(&mut session, 4, sentinel, sentinel, 3).is_err());
        assert_eq!(session.local_state_tracker.contracts, tracker);
        assert_eq!(session.get_contract_state_slot(PsyFelt::from_canonical_u64(6), PsyFelt::from_canonical_u64(4))?.root, delta.new_root);
        let (history, _) = session.get_all_state_updates()?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].contract_state_tree_updates.len(), 4);
        assert_eq!(history[0].user_contract_tree_update_proof.new_value, delta.new_root);
        assert_eq!(session.local_state_tracker.contracts, tracker);
        Ok(())
    }

    #[test]
    fn failed_preparation_and_replay_leave_live_nodes_unchanged() -> anyhow::Result<()> {
        let mut session = session()?;
        let (_, _, count) = insert(&mut session, 4, IMTContractStateLeaf::default(), IMTContractStateLeaf::default(), 10)?;
        let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore, PsyFelt, PsyHasher>::new(7, 6, 5);
        let root_key = id.get_leaf_key(2, 0).root().to_bytes()?;
        let before = session.state_tree_store.get_exact(&root_key)?;
        let tracker = session.local_state_tracker.contracts.clone();
        assert!(insert(&mut session, 4, IMTContractStateLeaf::default(), IMTContractStateLeaf::default(), 20).is_err());
        assert_eq!(session.state_tree_store.get_exact(&root_key)?, before);
        assert_eq!(session.local_state_tracker.contracts, tracker);
        let sentinel = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::from_values(1, 0, 0, 0), QHashOut::from_values(10, 0, 0, 0), PsyFelt::from_canonical_u64(5));
        session.local_state_tracker.contracts.get_mut(&6).unwrap().slots.get_mut(&4).unwrap().push(QHashOut::ZERO);
        let mismatched = session.local_state_tracker.contracts.clone();
        assert!(insert(&mut session, 4, sentinel, sentinel, 5).is_err());
        assert_eq!(session.state_tree_store.get_exact(&root_key)?, before);
        assert_eq!(session.local_state_tracker.contracts, mismatched);
        session.local_state_tracker.contracts = tracker;
        session.local_state_tracker.contracts.get_mut(&6).unwrap().slots.get_mut(&5).unwrap()[0] = QHashOut::from_values(999, 0, 0, 0);
        let corrupted = session.local_state_tracker.contracts.clone();
        assert!(session.get_all_state_updates().is_err());
        assert_eq!(session.state_tree_store.get_exact(&root_key)?, before);
        assert_eq!(session.local_state_tracker.contracts, corrupted);
        assert_eq!(id.get_root(&session.state_tree_store, 2)?, count.new_root);
        Ok(())
    }

    #[test]
    fn current_path_uses_live_versions_without_seeding_live_storage() -> anyhow::Result<()> {
        let session = session()?;
        let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore, PsyFelt, PsyHasher>::new(7, 6, 5);
        let immutable = SimpleMerkleTree::<PsyHasher, QHashOut<PsyFelt>>::new(5).get_leaf(4);
        let preparation = KVQSimpleMemoryBackingStore::new();
        id.injest_merkle_proof_ucs(&preparation, 1, &immutable)?;
        let current = id.set_leaf_ucs(&session.state_tree_store, 2, 5, QHashOut::from_values(9, 0, 0, 0))?;
        let assembly = session.build_current_path(preparation, id.get_leaf_key(1, 4))?;
        let proof = id.get_leaf_ucs(&assembly, 2, 4)?;
        assert_eq!(proof.root, current.new_root);
        assert!(proof.verify::<PsyHasher>());
        assert!(session.state_tree_store.get_exact_if_exists(&id.get_leaf_key(1, 4).to_bytes()?)?.is_none());
        let preparation = KVQSimpleMemoryBackingStore::new();
        id.injest_merkle_proof_ucs(&preparation, 1, &immutable)?;
        session.state_tree_store.set(id.get_leaf_key(0, 4).to_bytes()?, QHashOut::<PsyFelt>::ZERO.to_bytes()?)?;
        assert!(session.build_current_path(preparation, id.get_leaf_key(1, 4)).is_err());
        Ok(())
    }
}

#[cfg(all(test, feature = "is_sync"))]
mod imt_path_conflict_tests {
    use super::*;
    use crate::config::store_config::PsyFelt;

    #[test]
    fn conflicting_seed_does_not_modify_destination() -> anyhow::Result<()> {
        let scratch = KVQSimpleMemoryBackingStore::new();
        scratch.set(vec![1], vec![2])?;
        let preparation = KVQSimpleMemoryBackingStore::new();
        preparation.set(vec![0], vec![4])?;
        preparation.set(vec![1], vec![3])?;
        assert!(PsyLocalProvingSessionStore::<PsyFelt, KVQSimpleMemoryBackingStore, PsyHasher>::seed_current_path(&scratch, preparation).is_err());
        assert_eq!(scratch.get_exact(&vec![1])?, vec![2]);
        assert!(scratch.get_exact_if_exists(&vec![0])?.is_none());
        Ok(())
    }
}

#[cfg(all(test, feature = "is_sync"))]
mod imt_sentinel_validation_tests {
    use super::*;
    use crate::config::store_config::PsyFelt;
    type Session = PsyLocalProvingSessionStore<PsyFelt, KVQSimpleMemoryBackingStore, PsyHasher>;

    #[test]
    fn malformed_count_root_and_range_are_rejected() {
        let proof = SimpleMerkleTree::<PsyHasher, QHashOut<PsyFelt>>::new(5).get_leaf(4);
        let leaf = IMTContractStateLeaf::default();
        assert_eq!(Session::validate_imt_sentinel(&proof, leaf, 4, 3).unwrap(), 0);
        assert!(Session::validate_imt_sentinel(&proof, leaf, 4, 0).is_err());
        assert!(Session::validate_imt_sentinel(&proof, leaf, 4, u64::MAX).is_err());
        assert!(Session::validate_imt_sentinel(&proof, leaf, 4, 28).is_err());
        assert!(Session::validate_imt_sentinel(&proof, leaf.with_new_value(QHashOut::from_values(4, 0, 0, 0)), 4, 3).is_err());
        assert!(Session::validate_imt_sentinel(&proof, leaf.with_new_value(QHashOut::from_values(0, 1, 0, 0)), 4, 3).is_err());
        let mut invalid = proof;
        invalid.root = QHashOut::ZERO;
        assert!(Session::validate_imt_sentinel(&invalid, leaf, 4, 3).is_err());
    }
}

#[cfg(all(test, feature = "is_sync"))]
mod imt_overlay_scope_tests {
    use super::*;
    use crate::{config::store_config::PsyFelt, qstore::imm::cmd::{QSRIMTCmdFindPredecessor, QSRIMTCmdGetLeafIndexForKey, QSRIMTCmdGetLeafPreimage, QSRIMTCmdGetNextAppendIndex}};
    use plonky2::field::types::Field;

    type Session = PsyLocalProvingSessionStore<PsyFelt, KVQSimpleMemoryBackingStore, PsyHasher>;

    fn session() -> Session {
        Session::new_at(KVQSimpleMemoryBackingStore::new(), PsyFelt::ONE, PsyFelt::from_canonical_u64(7), PsyFelt::ONE, PsyFelt::ZERO, 16)
    }

    fn leaf(value: u64) -> IMTContractStateLeaf<PsyFelt> {
        IMTContractStateLeaf::new(QHashOut::from_values(10, 0, 0, 0), QHashOut::from_values(value, 0, 0, 0), QHashOut::ZERO, PsyFelt::ZERO)
    }

    #[test]
    fn predecessor_overlay_and_cache_do_not_cross_scope() -> anyhow::Result<()> {
        let mut session = session();
        session.local_state_tracker.notify_imt_update(6, leaf(1).key, 5, leaf(1), leaf(2), 4, 3);
        let query = QSRIMTCmdFindPredecessor { checkpoint_id: 1, user_id: 7, contract_id: 6, state_slot_base: 4, capacity: 3, key: [20, 0, 0, 0] };
        session.cmd_store.cache.imt_predecessor_cache.insert(query, Some((5, leaf(1))));
        assert_eq!(session.resolve_contract_state_imt_find_predecessor_mut(&query)?, Some((5, leaf(2))));
        let other_scopes = [
            QSRIMTCmdFindPredecessor { user_id: 8, ..query },
            QSRIMTCmdFindPredecessor { checkpoint_id: 2, ..query },
            QSRIMTCmdFindPredecessor { contract_id: 9, ..query },
            QSRIMTCmdFindPredecessor { state_slot_base: 12, ..query },
            QSRIMTCmdFindPredecessor { capacity: 2, ..query },
        ];
        for (i, other) in other_scopes.iter().enumerate() {
            session.cmd_store.cache.imt_predecessor_cache.insert(*other, Some((100 + i as u64, leaf(100 + i as u64))));
        }
        for (i, other) in other_scopes.iter().enumerate() {
            assert_eq!(session.resolve_contract_state_imt_find_predecessor_mut(other)?, Some((100 + i as u64, leaf(100 + i as u64))));
        }
        let absent = QSRIMTCmdFindPredecessor { key: [30, 0, 0, 0], ..other_scopes[0] };
        session.cmd_store.cache.imt_predecessor_cache.insert(absent, None);
        assert_eq!(session.resolve_contract_state_imt_find_predecessor_mut(&absent)?, None);
        assert_eq!(session.cmd_store.cache.imt_predecessor_cache.get(&absent), Some(&None));
        session.cmd_store.cache.imt_predecessor_cache.insert(query, None);
        assert_eq!(session.resolve_contract_state_imt_find_predecessor_mut(&query)?, Some((5, leaf(2))));
        Ok(())
    }

    #[test]
    fn index_overlay_and_cache_do_not_cross_scope() -> anyhow::Result<()> {
        let mut session = session();
        session.local_state_tracker.notify_imt_update(6, leaf(1).key, 5, leaf(1), leaf(2), 4, 3);
        let query = QSRIMTCmdGetLeafIndexForKey { checkpoint_id: 1, user_id: 7, contract_id: 6, state_slot_base: 4, capacity: 3, key: [10, 0, 0, 0] };
        session.cmd_store.cache.imt_index_cache.insert(query, 99);
        assert_eq!(session.resolve_contract_state_imt_get_leaf_index_for_key_mut(&query)?, 5);
        let other_scopes = [
            QSRIMTCmdGetLeafIndexForKey { user_id: 8, ..query },
            QSRIMTCmdGetLeafIndexForKey { checkpoint_id: 2, ..query },
            QSRIMTCmdGetLeafIndexForKey { contract_id: 9, ..query },
            QSRIMTCmdGetLeafIndexForKey { state_slot_base: 12, ..query },
            QSRIMTCmdGetLeafIndexForKey { capacity: 2, ..query },
            QSRIMTCmdGetLeafIndexForKey { key: [11, 0, 0, 0], ..query },
        ];
        for (i, other) in other_scopes.iter().enumerate() {
            session.cmd_store.cache.imt_index_cache.insert(*other, 100 + i as u64);
        }
        for (i, other) in other_scopes.iter().enumerate() {
            assert_eq!(session.resolve_contract_state_imt_get_leaf_index_for_key_mut(other)?, 100 + i as u64);
        }
        assert_eq!(session.cmd_store.cache.imt_index_cache.get(&query), Some(&99));
        Ok(())
    }

    #[test]
    fn preimage_overlay_and_cache_do_not_cross_identity() -> anyhow::Result<()> {
        let mut session = session();
        session.local_state_tracker.notify_imt_update(6, leaf(1).key, 5, leaf(1), leaf(2), 4, 3);
        let query = QSRIMTCmdGetLeafPreimage { checkpoint_id: 1, user_id: 7, contract_id: 6, leaf_index: 5 };
        session.cmd_store.cache.imt_leaf_preimage_cache.insert(query, leaf(1));
        assert_eq!(session.resolve_contract_state_imt_get_leaf_preimage_mut(&query)?, leaf(2));
        let other_scopes = [
            QSRIMTCmdGetLeafPreimage { user_id: 8, ..query },
            QSRIMTCmdGetLeafPreimage { checkpoint_id: 2, ..query },
            QSRIMTCmdGetLeafPreimage { contract_id: 9, ..query },
            QSRIMTCmdGetLeafPreimage { leaf_index: 13, ..query },
        ];
        for (i, other) in other_scopes.iter().enumerate() {
            session.cmd_store.cache.imt_leaf_preimage_cache.insert(*other, leaf(100 + i as u64));
        }
        for (i, other) in other_scopes.iter().enumerate() {
            assert_eq!(session.resolve_contract_state_imt_get_leaf_preimage_mut(other)?, leaf(100 + i as u64));
        }
        assert_eq!(session.cmd_store.cache.imt_leaf_preimage_cache.get(&query), Some(&leaf(1)));
        Ok(())
    }

    #[test]
    fn append_hint_overlay_does_not_cross_user_or_map() -> anyhow::Result<()> {
        let mut session = session();
        let sentinel = IMTContractStateLeaf::default();
        let spliced = sentinel.with_new_next(leaf(1).key, PsyFelt::from_canonical_u64(5));
        session.local_state_tracker.notify_imt_insert(6, 4, sentinel, spliced, 5, leaf(1), QHashOut::ZERO, QHashOut::ZERO, 4, 3,
            spliced, spliced.with_new_value(QHashOut::from_values(1, 0, 0, 0)));
        let query = QSRIMTCmdGetNextAppendIndex { user_id: 7, contract_id: 6, state_slot_base: 4, capacity: 3 };
        assert_eq!(session.resolve_contract_state_imt_get_next_append_index_mut(&query)?, 6);
        for other in [
            QSRIMTCmdGetNextAppendIndex { user_id: 8, ..query },
            QSRIMTCmdGetNextAppendIndex { contract_id: 9, ..query },
            QSRIMTCmdGetNextAppendIndex { state_slot_base: 12, ..query },
            QSRIMTCmdGetNextAppendIndex { capacity: 2, ..query },
        ] {
            assert_eq!(session.resolve_contract_state_imt_get_next_append_index_mut(&other)?, 0);
        }
        Ok(())
    }
}
