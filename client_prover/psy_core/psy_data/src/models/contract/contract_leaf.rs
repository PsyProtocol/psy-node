use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};
use plonky2::hash::hash_types::RichField;

use crate::{
    models::kvq_merkle::model::CHECKPOINT_ID_FUZZY_SIZE,
    qdata::{checkpoint_id_key::CheckpointTableIdKey, contract::PsyContractLeaf},
};

pub trait ContractLeafModelReaderCore<
    const CONTRACT_LEAF_TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapterReader<S, CheckpointTableIdKey<CONTRACT_LEAF_TABLE_TYPE>, PsyContractLeaf<F>>,
>
{
    fn get_contract_by_id(store: &S, checkpoint_id: u64, contract_id: u64) -> anyhow::Result<PsyContractLeaf<F>> {
        IDKVA::get_leq(store, &CheckpointTableIdKey::new(checkpoint_id, contract_id), CHECKPOINT_ID_FUZZY_SIZE)?
            .ok_or_else(|| anyhow::anyhow!("Contract not found"))
    }
    fn get_contracts_by_id(store: &S, checkpoint_id: u64, contract_ids: &[u64]) -> anyhow::Result<Vec<PsyContractLeaf<F>>> {
        let keys = contract_ids
            .iter()
            .map(|id| CheckpointTableIdKey::new(checkpoint_id, *id))
            .collect::<Vec<_>>();
        IDKVA::get_many_leq_u(store, &keys, CHECKPOINT_ID_FUZZY_SIZE)
    }
}

pub trait ContractLeafModelCore<
    const CONTRACT_LEAF_TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapter<S, CheckpointTableIdKey<CONTRACT_LEAF_TABLE_TYPE>, PsyContractLeaf<F>>,
>: ContractLeafModelReaderCore<CONTRACT_LEAF_TABLE_TYPE, S, F, IDKVA>
{
    fn set_contract(store: &S, checkpoint_id: u64, contract_id: u64, contract: PsyContractLeaf<F>) -> anyhow::Result<()> {
        let key_id = CheckpointTableIdKey::new(checkpoint_id, contract_id);
        IDKVA::set(store, key_id, contract)?;
        Ok(())
    }
    fn set_contract_ref(store: &S, checkpoint_id: u64, contract_id: u64, contract: &PsyContractLeaf<F>) -> anyhow::Result<()> {
        let key_id = CheckpointTableIdKey::new(checkpoint_id, contract_id);
        IDKVA::set_ref(store, &key_id, contract)?;
        Ok(())
    }
    fn set_contracts(store: &S, checkpoint_id: u64, contract_ids: &[u64], contracts: &[PsyContractLeaf<F>]) -> anyhow::Result<()> {
        let key_ids = contract_ids
            .iter()
            .map(|c| CheckpointTableIdKey::<CONTRACT_LEAF_TABLE_TYPE>::new(checkpoint_id, *c))
            .collect::<Vec<_>>();
        IDKVA::set_many_split_ref(store, &key_ids, contracts)?;
        Ok(())
    }
}

pub struct ContractLeafModel<const CONTRACT_LEAF_TABLE_TYPE: u16, S, F: RichField, IDKVA> {
    _idkva: IDKVA,
    _store: S,
    _phantom: std::marker::PhantomData<F>,
}

impl<
        const CONTRACT_LEAF_TABLE_TYPE: u16,
        S,
        F: RichField,
        IDKVA: KVQStoreAdapterReader<S, CheckpointTableIdKey<CONTRACT_LEAF_TABLE_TYPE>, PsyContractLeaf<F>>,
    > ContractLeafModelReaderCore<CONTRACT_LEAF_TABLE_TYPE, S, F, IDKVA> for ContractLeafModel<CONTRACT_LEAF_TABLE_TYPE, S, F, IDKVA>
{
}
impl<
        const CONTRACT_LEAF_TABLE_TYPE: u16,
        S,
        F: RichField,
        IDKVA: KVQStoreAdapter<S, CheckpointTableIdKey<CONTRACT_LEAF_TABLE_TYPE>, PsyContractLeaf<F>>,
    > ContractLeafModelCore<CONTRACT_LEAF_TABLE_TYPE, S, F, IDKVA> for ContractLeafModel<CONTRACT_LEAF_TABLE_TYPE, S, F, IDKVA>
{
}
