use std::{
    marker::PhantomData,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use plonky2::hash::hash_types::RichField;

use super::cmd_processor::PsyReadCommandProcessorSyncMut;

#[derive(Clone)]
pub struct PsyReadCommandProcessorArcImmutableWrapper<F: RichField, P: PsyReadCommandProcessorSyncMut<F>> {
    inner: Arc<RwLock<P>>,
    _phantom: PhantomData<F>,
}

impl<F: RichField, P: PsyReadCommandProcessorSyncMut<F>> PsyReadCommandProcessorArcImmutableWrapper<F, P> {
    pub fn new(inner: P) -> Self {
        Self {
            inner: Arc::new(RwLock::new(inner)),
            _phantom: PhantomData::default(),
        }
    }

    pub fn write(&self) -> anyhow::Result<RwLockWriteGuard<'_, P>> {
        self.inner
            .try_write()
            .map_err(|err| anyhow::anyhow!("Error writing to immutable store: {:?}", err))
    }
    pub fn read(&self) -> anyhow::Result<RwLockReadGuard<'_, P>> {
        self.inner
            .try_read()
            .map_err(|err| anyhow::anyhow!("Error reading from immutable store: {:?}", err))
    }
}
/*
impl<F: RichField, P: PsyReadCommandProcessorSyncMut<F>> PsyReadCommandProcessorSync<F> for PsyReadCommandProcessorArcImmutableWrapper<F, P> {
    fn resolve_batch(&self, input: &PsyReadCommandBatchInput) -> anyhow::Result<PsyReadCommandBatchOutput<F>> {
        self.write()?.resolve_batch_mut(input)
    }

    fn resolve_get_hash(&self, input: &QSRHashCmd) -> anyhow::Result<QHashOut<F>> {
        self.write()?.resolve_get_hash_mut(input)
    }

    fn resolve_get_merkle_proof(&self, input: &QSRMerkleCmd) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        self.write()?.resolve_get_merkle_proof_mut(input)
    }

    fn resolve_get_user_leaf(&self, input: &QSRCmdGetUserLeafData) -> anyhow::Result<PsyUserLeaf<F>> {
        self.write()?.resolve_get_user_leaf_mut(input)
    }

    fn resolve_get_contract_leaf(&self, input: &QSRCmdGetContractLeafData) -> anyhow::Result<PsyContractLeaf<F>> {
        self.write()?.resolve_get_contract_leaf_mut(input)
    }

    fn resolve_get_contract_code(&self, input: &QSRCmdGetContractCodeDefinition) -> anyhow::Result<ContractCodeDefinition> {
        self.write()?.resolve_get_contract_code_mut(input)
    }

    fn resolve_get_checkpoint_leaf(&self, input: &QSRCmdGetCheckpointLeafData) -> anyhow::Result<PsyCheckpointLeaf<F>> {
        self.write()?.resolve_get_checkpoint_leaf_mut(input)
    }

    fn resolve_get_block_state(&self, input: &QSRCmdGetBlockState) -> anyhow::Result<PsyBlockState> {
        self.write()?.resolve_get_block_state_mut(input)
    }
}
    */
