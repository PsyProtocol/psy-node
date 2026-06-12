use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};

use crate::{config::store_config::QCheckpointSyncInfoCompact, models::kvq_merkle::model::CHECKPOINT_ID_FUZZY_SIZE, qdata::u64_key::U64TableKey};

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub trait PsyCheckpointSyncInfoModelReaderCore<
    const CHECKPOINT_SYNC_INFO_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapterReader<S, U64TableKey<CHECKPOINT_SYNC_INFO_TABLE_TYPE>, QCheckpointSyncInfoCompact>,
>
{
    fn get_checkpoint_sync_info_compact(store: &S, checkpoint_id: u64) -> anyhow::Result<QCheckpointSyncInfoCompact> {
        //tracing::info!("get block state: {}", checkpoint_id);
        KVA::get_exact(store, &U64TableKey(checkpoint_id))
    }
    fn get_checkpoint_sync_info_compact_or_latest(store: &S, checkpoint_id: u64) -> anyhow::Result<QCheckpointSyncInfoCompact> {
        //tracing::info!("get block state: {}", checkpoint_id);
        let result = KVA::get_leq(store, &U64TableKey(checkpoint_id), CHECKPOINT_ID_FUZZY_SIZE)?;
        if result.is_some() {
            Ok(result.unwrap())
        } else {
            Err(CheckpointError::NotFound.into())
        }
    }
    fn get_latest_checkpoint_sync_info_compact(store: &S) -> anyhow::Result<QCheckpointSyncInfoCompact> {
        let result = KVA::get_leq(store, &U64TableKey(0xffffffffffffffffu64), CHECKPOINT_ID_FUZZY_SIZE)?;
        if result.is_some() {
            Ok(result.unwrap())
        } else {
            Err(CheckpointError::NotFound.into())
        }
    }
    fn get_checkpoint_sync_info_batch(store: &S, checkpoint_ids: &[u64]) -> anyhow::Result<Vec<QCheckpointSyncInfoCompact>> {
        let keys = checkpoint_ids.iter().map(|id| U64TableKey(*id)).collect::<Vec<_>>();
        KVA::get_many_exact(store, &keys)
    }
    fn get_checkpoint_sync_info_range(
        store: &S,
        start_checkpoint_id: u64,
        max_results: Option<usize>,
    ) -> anyhow::Result<Vec<QCheckpointSyncInfoCompact>> {
        let latest = Self::get_latest_checkpoint_sync_info_compact(store)?;
        if latest.block_state.checkpoint_id < start_checkpoint_id {
            return Ok(Vec::new());
        } else if latest.block_state.checkpoint_id == start_checkpoint_id {
            return Ok(vec![latest]);
        }

        let end_checkpoint_id = match max_results {
            Some(x) => start_checkpoint_id + x as u64,
            None => latest.block_state.checkpoint_id + 1,
        }
        .min(latest.block_state.checkpoint_id + 1);

        if end_checkpoint_id == (latest.block_state.checkpoint_id + 1) {
            let mut res = KVA::get_many_exact(
                store,
                &(start_checkpoint_id..latest.block_state.checkpoint_id)
                    .map(|id| U64TableKey(id))
                    .collect::<Vec<_>>(),
            )?;

            res.push(latest);

            Ok(res)
        } else {
            KVA::get_many_exact(
                store,
                &(start_checkpoint_id..end_checkpoint_id).map(|id| U64TableKey(id)).collect::<Vec<_>>(),
            )
        }
    }
}
pub trait PsyCheckpointSyncInfoModelCore<
    const CHECKPOINT_SYNC_INFO_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapter<S, U64TableKey<CHECKPOINT_SYNC_INFO_TABLE_TYPE>, QCheckpointSyncInfoCompact>,
>: PsyCheckpointSyncInfoModelReaderCore<CHECKPOINT_SYNC_INFO_TABLE_TYPE, S, KVA>
{
    fn delete_checkpoint_sync_info_by_id(store: &mut S, checkpoint_id: u64) -> anyhow::Result<Option<QCheckpointSyncInfoCompact>> {
        let key_id = U64TableKey::<CHECKPOINT_SYNC_INFO_TABLE_TYPE>(checkpoint_id);
        let current = KVA::get_exact_if_exists(store, &key_id)?;
        if current.is_some() {
            let deposit = current.unwrap();
            KVA::delete(store, &key_id)?;
            Ok(Some(deposit))
        } else {
            Ok(None)
        }
    }
    fn set_checkpoint_sync_info(store: &S, checkpoint_sync_info: QCheckpointSyncInfoCompact) -> anyhow::Result<()> {
        let key_id = U64TableKey::<CHECKPOINT_SYNC_INFO_TABLE_TYPE>(checkpoint_sync_info.block_state.checkpoint_id);
        KVA::set(store, key_id, checkpoint_sync_info)?;
        Ok(())
    }
    fn set_checkpoint_sync_info_ref(store: &S, checkpoint_sync_info: &QCheckpointSyncInfoCompact) -> anyhow::Result<()> {
        let key_id = U64TableKey::<CHECKPOINT_SYNC_INFO_TABLE_TYPE>(checkpoint_sync_info.block_state.checkpoint_id);
        KVA::set_ref(store, &key_id, &checkpoint_sync_info)?;
        Ok(())
    }
}
pub struct PsyCheckpointSyncInfoModel<const CHECKPOINT_SYNC_INFO_TABLE_TYPE: u16, S, KVA> {
    _store: S,
    _kva: KVA,
}

impl<
        const CHECKPOINT_SYNC_INFO_TABLE_TYPE: u16,
        S,
        KVA: KVQStoreAdapterReader<S, U64TableKey<CHECKPOINT_SYNC_INFO_TABLE_TYPE>, QCheckpointSyncInfoCompact>,
    > PsyCheckpointSyncInfoModelReaderCore<CHECKPOINT_SYNC_INFO_TABLE_TYPE, S, KVA>
    for PsyCheckpointSyncInfoModel<CHECKPOINT_SYNC_INFO_TABLE_TYPE, S, KVA>
{
}
impl<
        const CHECKPOINT_SYNC_INFO_TABLE_TYPE: u16,
        S,
        KVA: KVQStoreAdapter<S, U64TableKey<CHECKPOINT_SYNC_INFO_TABLE_TYPE>, QCheckpointSyncInfoCompact>,
    > PsyCheckpointSyncInfoModelCore<CHECKPOINT_SYNC_INFO_TABLE_TYPE, S, KVA>
    for PsyCheckpointSyncInfoModel<CHECKPOINT_SYNC_INFO_TABLE_TYPE, S, KVA>
{
}
