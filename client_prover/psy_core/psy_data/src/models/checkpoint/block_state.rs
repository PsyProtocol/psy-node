use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};

use crate::{
    models::kvq_merkle::model::CHECKPOINT_ID_FUZZY_SIZE,
    qdata::{checkpoint::PsyBlockState, u64_key::U64TableKey},
};

pub trait BlockStatesModelReaderCore<
    const CHECKPOINT_BLOCK_STATE_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapterReader<S, U64TableKey<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>, PsyBlockState>,
>
{
    fn get_block_state_by_id(store: &S, checkpoint_id: u64) -> anyhow::Result<PsyBlockState> {
        //tracing::info!("get block state: {}", checkpoint_id);
        KVA::get_exact(store, &U64TableKey(checkpoint_id))
    }
    fn get_latest_block_state(store: &S) -> anyhow::Result<PsyBlockState> {
        // Try to get the highest checkpoint ID using get_leq
        KVA::get_leq(store, &U64TableKey(0xffffffffffffffu64), CHECKPOINT_ID_FUZZY_SIZE)?
            .ok_or_else(|| anyhow::anyhow!("error getting latest block state"))
    }
    fn get_block_states_by_id(store: &S, checkpoint_ids: &[u64]) -> anyhow::Result<Vec<PsyBlockState>> {
        let keys = checkpoint_ids.iter().map(|id| U64TableKey(*id)).collect::<Vec<_>>();
        KVA::get_many_exact(store, &keys)
    }
}
pub trait BlockStatesModelCore<
    const CHECKPOINT_BLOCK_STATE_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapter<S, U64TableKey<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>, PsyBlockState>,
>: BlockStatesModelReaderCore<CHECKPOINT_BLOCK_STATE_TABLE_TYPE, S, KVA>
{
    fn delete_block_state_by_id(store: &S, checkpoint_id: u64) -> anyhow::Result<Option<PsyBlockState>> {
        let key_id = U64TableKey::<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>(checkpoint_id);
        let current = KVA::get_exact_if_exists(store, &key_id)?;
        if current.is_some() {
            let deposit = current.unwrap();
            KVA::delete(store, &key_id)?;
            Ok(Some(deposit))
        } else {
            Ok(None)
        }
    }
    fn set_block_state(store: &S, block_state: PsyBlockState) -> anyhow::Result<()> {
        let key_id = U64TableKey::<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>(block_state.checkpoint_id);
        KVA::set(store, key_id, block_state)?;
        Ok(())
    }
    fn set_block_state_ref(store: &S, block_state: &PsyBlockState) -> anyhow::Result<()> {
        let key_id = U64TableKey::<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>(block_state.checkpoint_id);
        KVA::set_ref(store, &key_id, &block_state)?;
        Ok(())
    }
    fn set_block_states(store: &S, block_states: &[PsyBlockState]) -> anyhow::Result<()> {
        let key_ids = block_states
            .iter()
            .map(|s| U64TableKey::<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>(s.checkpoint_id))
            .collect::<Vec<_>>();
        KVA::set_many_split_ref(store, &key_ids, block_states)?;

        Ok(())
    }
}
pub struct BlockStatesModel<const CHECKPOINT_BLOCK_STATE_TABLE_TYPE: u16, S, KVA> {
    _store: S,
    _kva: KVA,
}

impl<
        const CHECKPOINT_BLOCK_STATE_TABLE_TYPE: u16,
        S,
        KVA: KVQStoreAdapterReader<S, U64TableKey<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>, PsyBlockState>,
    > BlockStatesModelReaderCore<CHECKPOINT_BLOCK_STATE_TABLE_TYPE, S, KVA> for BlockStatesModel<CHECKPOINT_BLOCK_STATE_TABLE_TYPE, S, KVA>
{
}
impl<const CHECKPOINT_BLOCK_STATE_TABLE_TYPE: u16, S, KVA: KVQStoreAdapter<S, U64TableKey<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>, PsyBlockState>>
    BlockStatesModelCore<CHECKPOINT_BLOCK_STATE_TABLE_TYPE, S, KVA> for BlockStatesModel<CHECKPOINT_BLOCK_STATE_TABLE_TYPE, S, KVA>
{
}
