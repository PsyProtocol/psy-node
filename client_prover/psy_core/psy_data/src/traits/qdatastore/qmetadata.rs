use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;

//use psy_config::network_constants::PsyTreeConfig;
use crate::{
    dpn::event::PsyUserEventRecord,
    qdata::{
        checkpoint::{PsyBlockState, PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
        contract::{ContractCodeDefinition, PsyContractLeaf},
        user::PsyUserLeaf,
    },
};

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait QMetaDataStoreReaderSync<F: RichField>: Send + Sync {
    async fn get_user_leaf_data(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PsyUserLeaf<F>>;
    async fn get_user_leaf_data_f(&self, checkpoint_id: F, user_id: F) -> anyhow::Result<PsyUserLeaf<F>> {
        <Self as QMetaDataStoreReaderSync<F>>::get_user_leaf_data(self, checkpoint_id.to_canonical_u64(), user_id.to_canonical_u64()).await
    }

    async fn get_contract_leaf_data(&self, contract_id: u64) -> anyhow::Result<PsyContractLeaf<F>>;
    async fn get_contract_leaf_data_f(&self, contract_id: F) -> anyhow::Result<PsyContractLeaf<F>> {
        <Self as QMetaDataStoreReaderSync<F>>::get_contract_leaf_data(self, contract_id.to_canonical_u64()).await
    }

    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> anyhow::Result<PsyCheckpointLeaf<F>>;
    async fn get_checkpoint_leaf_data_f(&self, checkpoint_id: F) -> anyhow::Result<PsyCheckpointLeaf<F>> {
        <Self as QMetaDataStoreReaderSync<F>>::get_checkpoint_leaf_data(self, checkpoint_id.to_canonical_u64()).await
    }

    async fn get_contract_code_definition(&self, contract_id: u64) -> anyhow::Result<ContractCodeDefinition>;
    async fn get_contract_code_definition_f(&self, contract_id: F) -> anyhow::Result<ContractCodeDefinition> {
        <Self as QMetaDataStoreReaderSync<F>>::get_contract_code_definition(self, contract_id.to_canonical_u64()).await
    }

    async fn get_latest_block_state(&self) -> anyhow::Result<PsyBlockState>;

    async fn get_block_state(&self, checkpoint_id: u64) -> anyhow::Result<PsyBlockState>;
    async fn get_block_state_f(&self, checkpoint_id: F) -> anyhow::Result<PsyBlockState> {
        <Self as QMetaDataStoreReaderSync<F>>::get_block_state(self, checkpoint_id.to_canonical_u64()).await
    }

    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> anyhow::Result<PsyCheckpointGlobalStateRoots<F>>;

    async fn get_user_event_data(&self, user_id: u64, checkpoint_id: u64, event_index: u64) -> anyhow::Result<PsyUserEventRecord<F>>;
    async fn get_user_event_data_f(&self, checkpoint_id: F, user_id: F, event_index: F) -> anyhow::Result<PsyUserEventRecord<F>> {
        <Self as QMetaDataStoreReaderSync<F>>::get_user_event_data(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            event_index.to_canonical_u64(),
        )
        .await
    }

    async fn contract_state_imt_get_leaf_preimage(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        leaf_index: u64,
    ) -> anyhow::Result<crate::qdata::imt_contract_state::IMTContractStateLeaf<F>>;

    async fn contract_state_imt_get_leaf_index_for_key(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: &QHashOut<F>,
    ) -> anyhow::Result<u64>;

    async fn contract_state_imt_find_predecessor(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: &QHashOut<F>,
    ) -> anyhow::Result<(u64, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>)>;

    async fn contract_state_imt_get_next_append_index(&self, user_id: u64, contract_id: u64) -> anyhow::Result<u64>;
}

pub trait QMetaDataStoreWriterSync<F: RichField> {
    fn set_user_leaf_data(&self, checkpoint_id: u64, leaf_data: &PsyUserLeaf<F>) -> anyhow::Result<()>;

    fn set_contract_leaf_data(&self, checkpoint_id: u64, contract_id: u64, leaf_data: &PsyContractLeaf<F>) -> anyhow::Result<()>;
    fn set_contract_leaf_data_f(&self, checkpoint_id: F, contract_id: F, leaf_data: &PsyContractLeaf<F>) -> anyhow::Result<()> {
        <Self as QMetaDataStoreWriterSync<F>>::set_contract_leaf_data(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64(),
            leaf_data,
        )
    }

    fn set_checkpoint_leaf_data(&self, checkpoint_id: u64, leaf_data: &PsyCheckpointLeaf<F>) -> anyhow::Result<()>;
    fn set_checkpoint_leaf_data_f(&self, checkpoint_id: F, leaf_data: &PsyCheckpointLeaf<F>) -> anyhow::Result<()> {
        <Self as QMetaDataStoreWriterSync<F>>::set_checkpoint_leaf_data(self, checkpoint_id.to_canonical_u64(), leaf_data)
    }

    fn set_contract_code_definition(&self, checkpoint_id: u64, contract_id: u64, definition: &ContractCodeDefinition) -> anyhow::Result<()>;
    fn set_contract_code_definition_f(&self, checkpoint_id: F, contract_id: F, definition: &ContractCodeDefinition) -> anyhow::Result<()> {
        <Self as QMetaDataStoreWriterSync<F>>::set_contract_code_definition(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64(),
            definition,
        )
    }

    fn set_block_state(&self, block_state: &PsyBlockState) -> anyhow::Result<()>;

    fn set_user_event(&self, checkpoint_id: u64, user_id: u64, event_index: u64, event: &PsyUserEventRecord<F>) -> anyhow::Result<()>;
}
