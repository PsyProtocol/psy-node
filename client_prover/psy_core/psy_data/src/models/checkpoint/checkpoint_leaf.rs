use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};

use crate::{config::store_config::QCheckpointLeaf, models::kvq_merkle::model::CHECKPOINT_ID_FUZZY_SIZE, qdata::u64_key::U64TableKey};

pub trait PsyCheckpointLeafModelReaderCore<
    const CHECKPOINT_LEAF_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapterReader<S, U64TableKey<CHECKPOINT_LEAF_TABLE_TYPE>, QCheckpointLeaf>,
>
{
    fn get_checkpoint_leaf_by_id(store: &S, checkpoint_id: u64) -> anyhow::Result<QCheckpointLeaf> {
        //tracing::info!("get block state: {}", checkpoint_id);
        KVA::get_exact(store, &U64TableKey(checkpoint_id))
    }
    fn get_latest_checkpoint_leaf(store: &S) -> anyhow::Result<QCheckpointLeaf> {
        let result = KVA::get_leq(store, &U64TableKey(0xffffffffffffffu64), CHECKPOINT_ID_FUZZY_SIZE)?;
        if result.is_some() {
            Ok(result.unwrap())
        } else {
            anyhow::bail!("error getting latest block state")
        }
    }
    fn get_checkpoint_leafs_by_id(store: &S, checkpoint_ids: &[u64]) -> anyhow::Result<Vec<QCheckpointLeaf>> {
        let keys = checkpoint_ids.iter().map(|id| U64TableKey(*id)).collect::<Vec<_>>();
        KVA::get_many_exact(store, &keys)
    }
}
pub trait PsyCheckpointLeafModelCore<
    const CHECKPOINT_LEAF_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapter<S, U64TableKey<CHECKPOINT_LEAF_TABLE_TYPE>, QCheckpointLeaf>,
>: PsyCheckpointLeafModelReaderCore<CHECKPOINT_LEAF_TABLE_TYPE, S, KVA>
{
    fn delete_checkpoint_leaf_by_id(store: &mut S, checkpoint_id: u64) -> anyhow::Result<Option<QCheckpointLeaf>> {
        let key_id = U64TableKey::<CHECKPOINT_LEAF_TABLE_TYPE>(checkpoint_id);
        let current = KVA::get_exact_if_exists(store, &key_id)?;
        if current.is_some() {
            let deposit = current.unwrap();
            KVA::delete(store, &key_id)?;
            Ok(Some(deposit))
        } else {
            Ok(None)
        }
    }
    fn set_checkpoint_leaf(store: &S, checkpoint_id: u64, checkpoint_leaf: QCheckpointLeaf) -> anyhow::Result<()> {
        let key_id = U64TableKey::<CHECKPOINT_LEAF_TABLE_TYPE>(checkpoint_id);
        KVA::set(store, key_id, checkpoint_leaf)?;
        Ok(())
    }
    fn set_checkpoint_leaf_ref(store: &S, checkpoint_id: u64, checkpoint_leaf: &QCheckpointLeaf) -> anyhow::Result<()> {
        let key_id = U64TableKey::<CHECKPOINT_LEAF_TABLE_TYPE>(checkpoint_id);
        KVA::set_ref(store, &key_id, &checkpoint_leaf)?;
        Ok(())
    }
}
pub struct PsyCheckpointLeafModel<const CHECKPOINT_LEAF_TABLE_TYPE: u16, S, KVA> {
    _store: S,
    _kva: KVA,
}

impl<const CHECKPOINT_LEAF_TABLE_TYPE: u16, S, KVA: KVQStoreAdapterReader<S, U64TableKey<CHECKPOINT_LEAF_TABLE_TYPE>, QCheckpointLeaf>>
    PsyCheckpointLeafModelReaderCore<CHECKPOINT_LEAF_TABLE_TYPE, S, KVA> for PsyCheckpointLeafModel<CHECKPOINT_LEAF_TABLE_TYPE, S, KVA>
{
}
impl<const CHECKPOINT_LEAF_TABLE_TYPE: u16, S, KVA: KVQStoreAdapter<S, U64TableKey<CHECKPOINT_LEAF_TABLE_TYPE>, QCheckpointLeaf>>
    PsyCheckpointLeafModelCore<CHECKPOINT_LEAF_TABLE_TYPE, S, KVA> for PsyCheckpointLeafModel<CHECKPOINT_LEAF_TABLE_TYPE, S, KVA>
{
}
