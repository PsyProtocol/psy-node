use kvq::traits::{KVQPair, KVQStoreAdapter, KVQStoreAdapterReader};

use crate::{
    config::store_config::PsyHash,
    qdata::{hash_cache_result::PsyHashHelperResult, hash_key::Hash4x64Key},
};

pub trait PsyCheckpointHashHelperModelReaderCore<
    const CHECKPOINT_HASH_HELPER_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapterReader<S, Hash4x64Key<CHECKPOINT_HASH_HELPER_TABLE_TYPE>, PsyHashHelperResult>,
>
{
    fn get_checkpoint_hash_helper_info(store: &S, hash: PsyHash) -> anyhow::Result<PsyHashHelperResult> {
        //tracing::info!("get block state: {}", checkpoint_id);
        KVA::get_exact(store, &hash.into())
    }
    fn get_checkpoint_hash_helper_info_if_exists(store: &S, hash: PsyHash) -> anyhow::Result<Option<PsyHashHelperResult>> {
        //tracing::info!("get block state: {}", checkpoint_id);
        KVA::get_exact_if_exists(store, &hash.into())
    }
}
pub trait PsyCheckpointHashHelperModelCore<
    const CHECKPOINT_HASH_HELPER_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapter<S, Hash4x64Key<CHECKPOINT_HASH_HELPER_TABLE_TYPE>, PsyHashHelperResult>,
>: PsyCheckpointHashHelperModelReaderCore<CHECKPOINT_HASH_HELPER_TABLE_TYPE, S, KVA>
{
    fn delete_checkpoint_hash_helper_info(store: &mut S, hash: PsyHash) -> anyhow::Result<Option<PsyHashHelperResult>> {
        let current = KVA::get_exact_if_exists(store, &hash.into())?;
        if current.is_some() {
            let deposit = current.unwrap();
            KVA::delete(store, &hash.into())?;
            Ok(Some(deposit))
        } else {
            Ok(None)
        }
    }
    fn set_checkpoint_hash_helper_info(
        store: &S,
        checkpoint_id: u64,
        checkpoint_leaf_hash: PsyHash,
        checkpoint_tree_root_hash: PsyHash,
    ) -> anyhow::Result<()> {
        KVA::set_many(
            store,
            &[
                KVQPair {
                    key: checkpoint_leaf_hash.into(),
                    value: PsyHashHelperResult::new_checkpoint_leaf_hash(checkpoint_id),
                },
                KVQPair {
                    key: checkpoint_tree_root_hash.into(),
                    value: PsyHashHelperResult::new_checkpoint_tree_root_hash(checkpoint_id),
                },
            ],
        )?;
        Ok(())
    }
}
pub struct PsyCheckpointHashHelperModel<const CHECKPOINT_HASH_HELPER_TABLE_TYPE: u16, S, KVA> {
    _store: S,
    _kva: KVA,
}

impl<
        const CHECKPOINT_HASH_HELPER_TABLE_TYPE: u16,
        S,
        KVA: KVQStoreAdapterReader<S, Hash4x64Key<CHECKPOINT_HASH_HELPER_TABLE_TYPE>, PsyHashHelperResult>,
    > PsyCheckpointHashHelperModelReaderCore<CHECKPOINT_HASH_HELPER_TABLE_TYPE, S, KVA>
    for PsyCheckpointHashHelperModel<CHECKPOINT_HASH_HELPER_TABLE_TYPE, S, KVA>
{
}
impl<
        const CHECKPOINT_HASH_HELPER_TABLE_TYPE: u16,
        S,
        KVA: KVQStoreAdapter<S, Hash4x64Key<CHECKPOINT_HASH_HELPER_TABLE_TYPE>, PsyHashHelperResult>,
    > PsyCheckpointHashHelperModelCore<CHECKPOINT_HASH_HELPER_TABLE_TYPE, S, KVA>
    for PsyCheckpointHashHelperModel<CHECKPOINT_HASH_HELPER_TABLE_TYPE, S, KVA>
{
}
