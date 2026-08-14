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
    config::store_config::{PsyHasher, UserContractTreeStore},
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
    ) -> anyhow::Result<(u64, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>)> {
        use crate::qdata::imt_contract_state::compare_qhashout_keys;

        let key = QHashOut::from_values(input.key[0], input.key[1], input.key[2], input.key[3]);
        let contract_id = input.contract_id as u64;

        let local_pred = self
            .local_state_tracker
            .find_imt_predecessor(contract_id, input.state_slot_base, input.capacity, &key);
        let remote_pred = self.cmd_store.resolve_contract_state_imt_find_predecessor_mut(input).await.ok();

        // Merge local and remote predecessors. Equal keys must prefer local because
        // local carries the latest preimage after earlier writes in this proof.
        let result = match (local_pred, remote_pred) {
            (Some((local_idx, local_leaf)), Some((remote_idx, remote_leaf))) => match compare_qhashout_keys(&local_leaf.key, &remote_leaf.key) {
                std::cmp::Ordering::Greater | std::cmp::Ordering::Equal => (local_idx, local_leaf),
                std::cmp::Ordering::Less => (remote_idx, remote_leaf),
            },
            (Some(local), None) => local,
            (None, Some(remote)) => remote,
            (None, None) => return Err(anyhow::anyhow!("No predecessor found")),
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

        Ok(result)
    }

    async fn resolve_contract_state_imt_get_next_append_index_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetNextAppendIndex,
    ) -> anyhow::Result<u64> {
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
        let start_user_balance = F::ZERO;
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
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        tracing::debug!("Proving session - imt slot: {}, key: {}", slot, key);
        let new_leaf_hash = new_leaf.qfhash::<H>();
        let result = self.set_contract_state_slot_inner(contract, slot, new_leaf_hash).await?;
        self.local_state_tracker
            .notify_imt_update(contract.to_canonical_u64(), key, leaf_index, old_leaf, new_leaf);
        self.local_state_tracker
            .note_contract_state_root_transition(contract.to_canonical_u64(), result.old_root, result.new_root);
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
    ) -> anyhow::Result<(DeltaMerkleProofCore<QHashOut<F>>, DeltaMerkleProofCore<QHashOut<F>>)> {
        let predecessor_hash = predecessor_new_leaf.qfhash::<H>();
        let predecessor_dmp = self.set_contract_state_slot_inner(contract, predecessor_slot, predecessor_hash).await?;

        let new_leaf_hash = new_leaf_preimage.qfhash::<H>();
        let new_leaf_dmp = self.set_contract_state_slot_inner(contract, new_leaf_slot, new_leaf_hash).await?;

        self.local_state_tracker.notify_imt_insert(
            contract.to_canonical_u64(),
            predecessor_leaf_index,
            predecessor_old_leaf,
            predecessor_new_leaf,
            new_leaf_index,
            new_leaf_preimage,
            predecessor_dmp.old_value,
            new_leaf_dmp.old_value,
        );
        self.local_state_tracker
            .note_contract_state_root_transition(contract.to_canonical_u64(), predecessor_dmp.old_root, new_leaf_dmp.new_root);

        Ok((predecessor_dmp, new_leaf_dmp))
    }
    pub async fn get_contract_state_slot(&mut self, contract: F, slot: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        tracing::debug!("Proving session - slot: {}", slot);
        if contract == F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64) {
            tracing::debug!("use default empty contract state tree for local contract");
            let empty_tree = SimpleMerkleTree::<H, QHashOut<F>>::new(MAX_CONTRACT_STATE_TREE_HEIGHT);
            return Ok(empty_tree.get_leaf(slot.to_canonical_u64()));
        }

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
        tracing::info!(
            "DEBUG get_contract_state_slot RPC result: contract={} slot={} checkpoint={} value={}",
            contract,
            slot,
            self.start_checkpoint_u64,
            base_mp.value
        );
        id.injest_merkle_proof_ucs(&mut self.state_tree_store, self.start_checkpoint_u64, &base_mp)?;
        let contract_id_u64 = contract.to_canonical_u64();
        let slot_u64 = slot.to_canonical_u64();
        if self.local_state_tracker.contracts.contains_key(&contract_id_u64) {
            let result = id.get_leaf_ucs(&self.state_tree_store, self.write_checkpoint_u64, slot_u64)?;
            tracing::info!(
                "DEBUG get_contract_state_slot write_checkpoint proof: contract={} slot={} value={} root={}",
                contract,
                slot,
                result.value,
                result.root
            );
            return Ok(result);
        }
        tracing::info!(
            "DEBUG get_contract_state_slot start_checkpoint fallback: contract={} slot={} value={} root={}",
            contract,
            slot,
            base_mp.value,
            base_mp.root
        );
        id.get_leaf_ucs(&self.state_tree_store, self.start_checkpoint_u64, slot_u64)
    }

    pub async fn get_self_user_contract_tree_leaf(&mut self, contract_id: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        let is_default_contract = contract_id == F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64);
        let contract_id_u64 = contract_id.to_canonical_u64();

        let write_leaf_key = UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::new_leaf_key_sfc(
            self.write_checkpoint_u64,
            self.user_id_u64,
            contract_id_u64,
        );
        if self.state_tree_store.get_exact(&write_leaf_key.to_bytes()?).is_ok() {
            return UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::get_leaf_sfc(
                &self.state_tree_store,
                self.write_checkpoint_u64,
                self.user_id_u64,
                contract_id_u64,
            );
        }

        let old_upper_merkle_proof = match self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractTreeMerkleProof(
                QSRMerkleCmdGetUserContractTreeMerkleProof {
                    checkpoint_id: self.start_checkpoint_u64,
                    user_id: self.user_id_u64,
                    contract_id: contract_id.to_canonical_u64() as u32,
                },
            ))
            .await
        {
            Ok(proof) => proof,
            Err(e) if is_default_contract => {
                tracing::debug!("use default empty user contract tree for local contract: {}", e);
                let empty_tree = SimpleMerkleTree::<H, QHashOut<F>>::new(GLOBAL_CONTRACT_TREE_HEIGHT);
                return Ok(empty_tree.get_leaf(contract_id.to_canonical_u64()));
            }
            Err(e) => return Err(e),
        };

        UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::injest_merkle_proof_sfc(
            &mut self.state_tree_store,
            self.user_id_u64,
            self.start_checkpoint_u64,
            &old_upper_merkle_proof,
        )?;
        // Return the leaf proof at the current write-checkpoint, not the immutable
        // start-checkpoint. Other leaves in this user contract tree may already
        // have been updated in this session, so deferred children must see the
        // latest user-tree root while untouched leaves still fall back to the
        // seeded base path from start-checkpoint.
        UserContractTreeStore::<KVQSimpleMemoryBackingStore, F, H>::get_leaf_sfc(
            &self.state_tree_store,
            self.write_checkpoint_u64,
            self.user_id_u64,
            contract_id_u64,
        )
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
    async fn set_user_contract_tree_leaf(&mut self, contract_id: F, leaf: QHashOut<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        let old_upper_merkle_proof = self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractTreeMerkleProof(
                QSRMerkleCmdGetUserContractTreeMerkleProof {
                    checkpoint_id: self.start_checkpoint_u64,
                    user_id: self.user_id_u64,
                    contract_id: contract_id.to_canonical_u64() as u32,
                },
            ))
            .await?;
        self.set_user_contract_tree_leaf_from_old_proof(contract_id.to_canonical_u64(), &old_upper_merkle_proof, leaf)
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
        let contract_inclusion_proof = self.get_contract_inclusion_proof(contract_id).await?;
        let contract_function_merkle_proof = self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetContractFunctionTreeMerkleProof(
                QSRMerkleCmdGetContractFunctionTreeMerkleProof {
                    checkpoint_id: self.start_checkpoint_u64,
                    contract_id,
                    function_id: function_id * 2,
                },
            ))
            .await?;

        Ok(PsyContractFunctionInclusionProof {
            contract_inclusion_proof,
            contract_function_merkle_proof,
        })
    }

    pub async fn get_all_state_updates(&mut self) -> anyhow::Result<(Vec<PsyContractStateUpdateHistory<F>>, u32)> {
        use crate::qdata::{imt_contract_state::IMTContractStateLeaf, imt_proof::IMTContractStateUpdate};

        let total_slots_modified = self.local_state_tracker.total_slots_modified;
        let total_keys_modified = self.local_state_tracker.get_total_keys_modified();
        let tracker_results: Vec<_> = self.local_state_tracker.contracts.values().cloned().collect();

        for r in tracker_results.iter() {
            let c = F::from_canonical_u64(r.contract_id);
            for (slot_index, versions) in r.slots.iter() {
                if let Some(start_value) = versions.first().copied() {
                    self.set_contract_state_slot_inner(c, F::from_canonical_u64(*slot_index), start_value)
                        .await?;
                }
            }
            self.update_contract_state_root_in_user_contract_tree(c).await?;
            let resolve_slot_hash = |slot_index: u64, version: u32| -> anyhow::Result<QHashOut<F>> {
                let versions = r.slots.get(&slot_index).ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing IMT slot version chain for contract_id={}, slot={}, version={}",
                        r.contract_id,
                        slot_index,
                        version
                    )
                })?;
                versions.get(version as usize).copied().ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid IMT slot version for contract_id={}, slot={}, version={}, versions_len={}",
                        r.contract_id,
                        slot_index,
                        version,
                        versions.len()
                    )
                })
            };

            let mut reset_slots: HashMap<u64, QHashOut<F>> = HashMap::new();
            for op in r.ops.iter() {
                match op {
                    PsyStateOperation::IMTUpdate {
                        leaf_index, from_version, ..
                    } => {
                        let reset_hash = resolve_slot_hash(*leaf_index, *from_version)?;
                        reset_slots.entry(*leaf_index).or_insert(reset_hash);
                    }
                    PsyStateOperation::IMTInsert {
                        predecessor_leaf_index,
                        predecessor_from_version,
                        new_leaf_index,
                        new_leaf_from_version,
                        ..
                    } => {
                        let predecessor_reset_hash = resolve_slot_hash(*predecessor_leaf_index, *predecessor_from_version)?;
                        let new_leaf_reset_hash = resolve_slot_hash(*new_leaf_index, *new_leaf_from_version)?;
                        reset_slots.entry(*predecessor_leaf_index).or_insert(predecessor_reset_hash);
                        reset_slots.entry(*new_leaf_index).or_insert(new_leaf_reset_hash);
                    }
                    PsyStateOperation::PositionalWrite { .. } => {}
                }
            }
            for (slot_index, reset_value) in reset_slots.into_iter() {
                self.set_contract_state_slot_inner(c, F::from_canonical_u64(slot_index), reset_value)
                    .await?;
            }
            self.update_contract_state_root_in_user_contract_tree(c).await?;
        }

        let start_state_roots = self.get_start_contract_state_roots();
        for (c, h) in start_state_roots.into_iter() {
            self.set_user_contract_tree_leaf(F::from_canonical_u64(c), h).await?;
        }

        self.state_tree_store = KVQSimpleMemoryBackingStore::new();

        let mut update_results = Vec::with_capacity(tracker_results.len());

        for r in tracker_results.iter() {
            let c = F::from_canonical_u64(r.contract_id);
            let mut contract_state_tree_updates: Vec<ContractStateUpdate<F>> = Vec::with_capacity(r.ops.len());

            {
                let resolve_slot_hash = |slot_index: u64, version: u32| -> anyhow::Result<QHashOut<F>> {
                    let versions = r.slots.get(&slot_index).ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing IMT slot version chain for contract_id={}, slot={}, version={}",
                            r.contract_id,
                            slot_index,
                            version
                        )
                    })?;
                    versions.get(version as usize).copied().ok_or_else(|| {
                        anyhow::anyhow!(
                            "invalid IMT slot version for contract_id={}, slot={}, version={}, versions_len={}",
                            r.contract_id,
                            slot_index,
                            version,
                            versions.len()
                        )
                    })
                };
                let resolve_preimage_from_hash = |hash: QHashOut<F>| -> anyhow::Result<IMTContractStateLeaf<F>> {
                    if hash == QHashOut::ZERO {
                        return Ok(IMTContractStateLeaf::default());
                    }
                    r.imt_preimages
                        .get(&hash)
                        .copied()
                        .ok_or_else(|| anyhow::anyhow!("missing IMT preimage for contract_id={}, hash={}", r.contract_id, hash))
                };
                for op in r.ops.iter() {
                    match op {
                        PsyStateOperation::IMTUpdate {
                            leaf_index,
                            from_version,
                            to_version,
                            ..
                        } => {
                            let old_hash = resolve_slot_hash(*leaf_index, *from_version)?;
                            let new_hash = resolve_slot_hash(*leaf_index, *to_version)?;
                            let old_preimage = resolve_preimage_from_hash(old_hash)?;
                            let new_preimage = resolve_preimage_from_hash(new_hash)?;
                            let delta_proof = self
                                .set_contract_state_slot_inner(c, F::from_canonical_u64(*leaf_index), new_hash)
                                .await?;
                            contract_state_tree_updates.push(ContractStateUpdate::IMT {
                                update: IMTContractStateUpdate::Update {
                                    old_preimage,
                                    new_preimage,
                                    delta_proof,
                                },
                            });
                        }
                        PsyStateOperation::IMTInsert {
                            predecessor_leaf_index,
                            predecessor_from_version,
                            predecessor_to_version,
                            new_leaf_index,
                            new_leaf_to_version,
                            ..
                        } => {
                            let predecessor_old_hash = resolve_slot_hash(*predecessor_leaf_index, *predecessor_from_version)?;
                            let predecessor_new_hash = resolve_slot_hash(*predecessor_leaf_index, *predecessor_to_version)?;
                            let new_leaf_new_hash = resolve_slot_hash(*new_leaf_index, *new_leaf_to_version)?;
                            let predecessor_old_preimage = resolve_preimage_from_hash(predecessor_old_hash)?;
                            let predecessor_new_preimage = resolve_preimage_from_hash(predecessor_new_hash)?;
                            let new_leaf_preimage = resolve_preimage_from_hash(new_leaf_new_hash)?;

                            let predecessor_delta_proof = self
                                .set_contract_state_slot_inner(c, F::from_canonical_u64(*predecessor_leaf_index), predecessor_new_hash)
                                .await?;
                            let new_leaf_delta_proof = self
                                .set_contract_state_slot_inner(c, F::from_canonical_u64(*new_leaf_index), new_leaf_new_hash)
                                .await?;
                            contract_state_tree_updates.push(ContractStateUpdate::IMT {
                                update: IMTContractStateUpdate::Insert {
                                    predecessor_old_preimage,
                                    predecessor_new_preimage,
                                    new_leaf_preimage,
                                    predecessor_delta_proof,
                                    new_leaf_delta_proof,
                                },
                            });
                        }
                        PsyStateOperation::PositionalWrite { .. } => {}
                    }
                }
            }

            let mut compact_slot_ops: HashMap<u64, (u64, u32)> = HashMap::new();
            for op in r.ops.iter() {
                if let PsyStateOperation::PositionalWrite {
                    slot, op_seq, to_version, ..
                } = op
                {
                    match compact_slot_ops.get_mut(slot) {
                        Some((last_op_seq, last_to_version)) => {
                            if *op_seq > *last_op_seq {
                                *last_op_seq = *op_seq;
                                *last_to_version = *to_version;
                            }
                        }
                        None => {
                            compact_slot_ops.insert(*slot, (*op_seq, *to_version));
                        }
                    }
                }
            }
            let mut slot_ops: Vec<(u64, u64, u32)> = compact_slot_ops
                .into_iter()
                .map(|(slot, (op_seq, to_version))| (slot, op_seq, to_version))
                .collect();
            slot_ops.sort_by_key(|(_, op_seq, _)| *op_seq);
            for (slot, op_seq, to_version) in slot_ops.iter() {
                let versions = r.slots.get(slot).ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing slot version chain for contract_id={}, slot={}, op_seq={}",
                        r.contract_id,
                        slot,
                        op_seq
                    )
                })?;
                let to_idx = *to_version as usize;
                let new_value = *versions.get(to_idx).ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid to_version for contract_id={}, slot={}, op_seq={}, to_version={}, versions_len={}",
                        r.contract_id,
                        slot,
                        op_seq,
                        to_version,
                        versions.len()
                    )
                })?;

                let delta_proof = self.set_contract_state_slot_inner(c, F::from_canonical_u64(*slot), new_value).await?;
                contract_state_tree_updates.push(ContractStateUpdate::Positional { delta_proof });
            }

            let user_contract_tree_update_proof = self.update_contract_state_root_in_user_contract_tree(c).await?;
            tracing::info!(
                "DEBUG get_all_state_updates result contract_id={} old_root={} old_value={} new_root={} new_value={} cst_updates={}",
                r.contract_id,
                user_contract_tree_update_proof.old_root,
                user_contract_tree_update_proof.old_value,
                user_contract_tree_update_proof.new_root,
                user_contract_tree_update_proof.new_value,
                contract_state_tree_updates.len(),
            );
            update_results.push(PsyContractStateUpdateHistory {
                user_contract_tree_update_proof,
                contract_state_tree_updates,
            });
        }

        Ok((update_results, total_slots_modified + total_keys_modified))
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
