use std::marker::PhantomData;

use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};
use plonky2::hash::hash_types::RichField;

use crate::qdata::{checkpoint_id_key::CheckpointTableIdKey, user_endcap_metadata::UserEndCapMetaData, uuid::TxHash};

pub trait UserEndcapMetaDataModelReaderCore<
    const TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapterReader<S, CheckpointTableIdKey<TABLE_TYPE>, UserEndCapMetaData<F>>,
>
{
    fn get_user_endcap_metadata_by_id(store: &S, tx_hash: TxHash) -> anyhow::Result<UserEndCapMetaData<F>> {
        IDKVA::get_exact(store, &tx_hash.into())
            .map_err(|e| anyhow::format_err!("UserEndcap {} Metadata not found, {}", tx_hash.to_string(), e.to_string()))
    }
    fn get_user_endcap_metadatas_by_id(store: &S, tx_hashs: &[TxHash]) -> anyhow::Result<Vec<UserEndCapMetaData<F>>> {
        let keys: Vec<CheckpointTableIdKey<TABLE_TYPE>> = tx_hashs.iter().map(|id| (*id).into()).collect::<Vec<_>>();
        IDKVA::get_many_exact(store, &keys).map_err(|e| {
            anyhow::format_err!(
                "UserEndcap Metadata {} not found, {}",
                tx_hashs.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(","),
                e.to_string()
            )
        })
    }
}

pub trait UserEndcapMetaDataModelCore<
    const TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapter<S, CheckpointTableIdKey<TABLE_TYPE>, UserEndCapMetaData<F>>,
>: UserEndcapMetaDataModelReaderCore<TABLE_TYPE, S, F, IDKVA>
{
    fn set_user_endcap_metadata(store: &S, tx_hash: TxHash, user_endcap_metadata: UserEndCapMetaData<F>) -> anyhow::Result<()> {
        let key_id = tx_hash.into();
        IDKVA::set(store, key_id, user_endcap_metadata)?;
        Ok(())
    }
    fn set_user_endcap_metadatas(store: &S, tx_hashs: &[TxHash], user_endcap_metadatas: &[UserEndCapMetaData<F>]) -> anyhow::Result<()> {
        let keys: Vec<CheckpointTableIdKey<TABLE_TYPE>> = tx_hashs.iter().map(|id| (*id).into()).collect::<Vec<_>>();
        IDKVA::set_many_split_ref(store, &keys, user_endcap_metadatas)?;
        Ok(())
    }
}

pub struct UserEndcapMetaDataModel<const TABLE_TYPE: u16, S, F: RichField, IDKVA> {
    _idkva: IDKVA,
    _store: S,
    _phantom_data: PhantomData<F>,
}

impl<const TABLE_TYPE: u16, F: RichField, S, IDKVA: KVQStoreAdapterReader<S, CheckpointTableIdKey<TABLE_TYPE>, UserEndCapMetaData<F>>>
    UserEndcapMetaDataModelReaderCore<TABLE_TYPE, S, F, IDKVA> for UserEndcapMetaDataModel<TABLE_TYPE, S, F, IDKVA>
{
}
impl<const TABLE_TYPE: u16, F: RichField, S, IDKVA: KVQStoreAdapter<S, CheckpointTableIdKey<TABLE_TYPE>, UserEndCapMetaData<F>>>
    UserEndcapMetaDataModelCore<TABLE_TYPE, S, F, IDKVA> for UserEndcapMetaDataModel<TABLE_TYPE, S, F, IDKVA>
{
}
