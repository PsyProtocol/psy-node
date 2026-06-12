use std::marker::PhantomData;

use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};
use plonky2::hash::hash_types::RichField;

use crate::qdata::{checkpoint_id_key::CheckpointTableIdKey, register_user_metadata::RegisterUserMetaData, uuid::RegisterUserUUID};

pub trait RegisterUserMetaDataModelReaderCore<
    const TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapterReader<S, CheckpointTableIdKey<TABLE_TYPE>, RegisterUserMetaData<F>>,
>
{
    fn get_register_user_metadata_by_id(store: &S, register_user_uuid: RegisterUserUUID) -> anyhow::Result<RegisterUserMetaData<F>> {
        IDKVA::get_exact(store, &register_user_uuid.into())
            .map_err(|e| anyhow::format_err!("RegisterUser {} Metadata not found, {}", register_user_uuid.to_string(), e.to_string()))
    }
    fn get_register_user_metadatas_by_id(store: &S, register_user_uuids: &[RegisterUserUUID]) -> anyhow::Result<Vec<RegisterUserMetaData<F>>> {
        let keys: Vec<CheckpointTableIdKey<TABLE_TYPE>> = register_user_uuids.iter().map(|id| (*id).into()).collect::<Vec<_>>();
        IDKVA::get_many_exact(store, &keys).map_err(|e| {
            anyhow::format_err!(
                "Contract Metadata {} not found, {}",
                register_user_uuids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(","),
                e.to_string()
            )
        })
    }
}

pub trait RegisterUserMetaDataModelCore<
    const TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapter<S, CheckpointTableIdKey<TABLE_TYPE>, RegisterUserMetaData<F>>,
>: RegisterUserMetaDataModelReaderCore<TABLE_TYPE, S, F, IDKVA>
{
    fn set_register_user_metadata(
        store: &S,
        register_user_uuid: RegisterUserUUID,
        register_user_metadata: RegisterUserMetaData<F>,
    ) -> anyhow::Result<()> {
        let key_id = register_user_uuid.into();
        IDKVA::set(store, key_id, register_user_metadata)?;
        Ok(())
    }
    fn set_register_user_metadatas(
        store: &S,
        register_user_uuids: &[RegisterUserUUID],
        register_user_metadatas: &[RegisterUserMetaData<F>],
    ) -> anyhow::Result<()> {
        let keys: Vec<CheckpointTableIdKey<TABLE_TYPE>> = register_user_uuids.iter().map(|id| (*id).into()).collect::<Vec<_>>();
        IDKVA::set_many_split_ref(store, &keys, register_user_metadatas)?;
        Ok(())
    }
}

pub struct RegisterUserMetaDataModel<const TABLE_TYPE: u16, S, F: RichField, IDKVA> {
    _idkva: IDKVA,
    _store: S,
    _phantom_data: PhantomData<F>,
}

impl<const TABLE_TYPE: u16, F: RichField, S, IDKVA: KVQStoreAdapterReader<S, CheckpointTableIdKey<TABLE_TYPE>, RegisterUserMetaData<F>>>
    RegisterUserMetaDataModelReaderCore<TABLE_TYPE, S, F, IDKVA> for RegisterUserMetaDataModel<TABLE_TYPE, S, F, IDKVA>
{
}
impl<const TABLE_TYPE: u16, F: RichField, S, IDKVA: KVQStoreAdapter<S, CheckpointTableIdKey<TABLE_TYPE>, RegisterUserMetaData<F>>>
    RegisterUserMetaDataModelCore<TABLE_TYPE, S, F, IDKVA> for RegisterUserMetaDataModel<TABLE_TYPE, S, F, IDKVA>
{
}
