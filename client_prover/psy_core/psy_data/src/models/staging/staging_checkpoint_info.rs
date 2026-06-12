use kvq::traits::{KVQBinaryStore, KVQSerializable, KVQStoreAdapterReader};

use crate::{
    models::kvq_merkle::model::CHECKPOINT_ID_FUZZY_SIZE,
    qdata::{staging_checkpoint_info::StagingCheckpointInfo, staging_checkpoint_key::StagingCheckpointKey},
};

pub const UUID_FUZZY_SIZE: usize = 16;

pub struct StagingCheckpointInfoModel<const TABLE_TYPE: u16, S, IDKVA> {
    _idkva: IDKVA,
    _store: S,
}

impl<const TABLE_TYPE: u16, S, IDKVA> StagingCheckpointInfoModel<TABLE_TYPE, S, IDKVA> {
    pub fn set_checkpoint_info<Store: KVQBinaryStore>(
        store: &Store,
        uuid: u128,
        checkpoint_id: u64,
        info: &StagingCheckpointInfo,
    ) -> anyhow::Result<()> {
        let key = StagingCheckpointKey::<TABLE_TYPE>::new(uuid, checkpoint_id);
        let value_bytes = bincode::serialize(info)?;
        store.set(key.to_bytes()?, value_bytes)?;
        Ok(())
    }

    pub fn get_checkpoint_info<Store: KVQBinaryStore>(
        store: &Store,
        uuid: u128,
        checkpoint_id: u64,
    ) -> anyhow::Result<Option<StagingCheckpointInfo>> {
        let key = StagingCheckpointKey::<TABLE_TYPE>::new(uuid, checkpoint_id);
        if let Some(value_bytes) = store.get_exact_if_exists(&key.to_bytes()?)? {
            let info: StagingCheckpointInfo = bincode::deserialize(&value_bytes)?;
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    pub fn delete_checkpoint_info<Store: KVQBinaryStore>(store: &Store, uuid: u128, checkpoint_id: u64) -> anyhow::Result<()> {
        let key = StagingCheckpointKey::<TABLE_TYPE>::new(uuid, checkpoint_id);
        store.delete(&key.to_bytes()?)?;
        Ok(())
    }

    pub fn get_latest_checkpoint_info_with_uuid(store: &S) -> anyhow::Result<Option<(u128, u64, StagingCheckpointInfo)>>
    where
        IDKVA: KVQStoreAdapterReader<S, StagingCheckpointKey<TABLE_TYPE>, StagingCheckpointInfo>,
    {
        if let Some(kv_pair) = IDKVA::get_leq_kv(
            store,
            &StagingCheckpointKey::<TABLE_TYPE>::new(0xffffffffffffffffffffffffffffffff_u128, 0xffffffffffffffff_u64),
            CHECKPOINT_ID_FUZZY_SIZE + UUID_FUZZY_SIZE,
        )? {
            Ok(Some((kv_pair.key.uuid, kv_pair.key.checkpoint_id, kv_pair.value)))
        } else {
            Ok(None)
        }
    }
}
