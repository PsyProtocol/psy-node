use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};

use crate::{
    models::kvq_merkle::model::CHECKPOINT_ID_FUZZY_SIZE,
    qdata::{checkpoint_id_key::CheckpointTableIdKey, contract::ContractCodeDefinition},
};

pub trait ContractCodeModelReaderCore<
    const CONTRACT_CODE_TABLE_TYPE: u16,
    S,
    IDKVA: KVQStoreAdapterReader<S, CheckpointTableIdKey<CONTRACT_CODE_TABLE_TYPE>, ContractCodeDefinition>,
>
{
    fn get_contract_code_by_id(store: &S, checkpoint_id: u64, contract_id: u64) -> anyhow::Result<ContractCodeDefinition> {
        IDKVA::get_leq(store, &CheckpointTableIdKey::new(checkpoint_id, contract_id), CHECKPOINT_ID_FUZZY_SIZE)?
            .ok_or_else(|| anyhow::anyhow!("Contract Code not found"))
    }
    fn get_contract_codess_by_id(store: &S, checkpoint_id: u64, contract_ids: &[u64]) -> anyhow::Result<Vec<ContractCodeDefinition>> {
        let keys = contract_ids
            .iter()
            .map(|id| CheckpointTableIdKey::new(checkpoint_id, *id))
            .collect::<Vec<_>>();
        IDKVA::get_many_leq_u(store, &keys, CHECKPOINT_ID_FUZZY_SIZE)
    }
}

pub trait ContractCodeModelCore<
    const CONTRACT_CODE_TABLE_TYPE: u16,
    S,
    IDKVA: KVQStoreAdapter<S, CheckpointTableIdKey<CONTRACT_CODE_TABLE_TYPE>, ContractCodeDefinition>,
>: ContractCodeModelReaderCore<CONTRACT_CODE_TABLE_TYPE, S, IDKVA>
{
    fn set_contract_code(store: &S, checkpoint_id: u64, contract_id: u64, contract: ContractCodeDefinition) -> anyhow::Result<()> {
        let key_id = CheckpointTableIdKey::new(checkpoint_id, contract_id);
        IDKVA::set(store, key_id, contract)?;
        Ok(())
    }
    fn set_contract_code_ref(store: &S, checkpoint_id: u64, contract_id: u64, contract: &ContractCodeDefinition) -> anyhow::Result<()> {
        let key_id = CheckpointTableIdKey::new(checkpoint_id, contract_id);
        IDKVA::set_ref(store, &key_id, contract)?;
        Ok(())
    }
    fn set_contract_codes(store: &S, checkpoint_id: u64, contract_ids: &[u64], contracts: &[ContractCodeDefinition]) -> anyhow::Result<()> {
        let key_ids = contract_ids
            .iter()
            .map(|c| CheckpointTableIdKey::<CONTRACT_CODE_TABLE_TYPE>::new(checkpoint_id, *c))
            .collect::<Vec<_>>();
        IDKVA::set_many_split_ref(store, &key_ids, contracts)?;
        Ok(())
    }
}

pub struct ContractCodeModel<const CONTRACT_CODE_TABLE_TYPE: u16, S, IDKVA> {
    _idkva: IDKVA,
    _store: S,
}

impl<
        const CONTRACT_CODE_TABLE_TYPE: u16,
        S,
        IDKVA: KVQStoreAdapterReader<S, CheckpointTableIdKey<CONTRACT_CODE_TABLE_TYPE>, ContractCodeDefinition>,
    > ContractCodeModelReaderCore<CONTRACT_CODE_TABLE_TYPE, S, IDKVA> for ContractCodeModel<CONTRACT_CODE_TABLE_TYPE, S, IDKVA>
{
}
impl<const CONTRACT_CODE_TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapter<S, CheckpointTableIdKey<CONTRACT_CODE_TABLE_TYPE>, ContractCodeDefinition>>
    ContractCodeModelCore<CONTRACT_CODE_TABLE_TYPE, S, IDKVA> for ContractCodeModel<CONTRACT_CODE_TABLE_TYPE, S, IDKVA>
{
}
