use std::marker::PhantomData;

use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};
use plonky2::hash::hash_types::RichField;

use crate::qdata::{realm_id_key::RealmTableIdKey, realm_status::BasicRealmStatus};

pub trait RealmStatusModelReaderCore<
    const TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapterReader<S, RealmTableIdKey<TABLE_TYPE>, BasicRealmStatus<F>>,
>
{
    fn get_realm_status_by_id(store: &S, realm_id: u64) -> anyhow::Result<BasicRealmStatus<F>> {
        IDKVA::get_exact(store, &RealmTableIdKey::new(realm_id))
            .map_err(|e| anyhow::format_err!("Realm {} Status not found, {}", realm_id, e.to_string()))
    }
    fn get_realm_statuses_by_id(store: &S, realmd_ids: &[u64]) -> anyhow::Result<Vec<BasicRealmStatus<F>>> {
        let keys: Vec<RealmTableIdKey<TABLE_TYPE>> = realmd_ids.iter().map(|id| RealmTableIdKey::new(*id)).collect::<Vec<_>>();
        IDKVA::get_many_exact(store, &keys)
    }
}

pub trait RealmStatusModelCore<const TABLE_TYPE: u16, S, F: RichField, IDKVA: KVQStoreAdapter<S, RealmTableIdKey<TABLE_TYPE>, BasicRealmStatus<F>>>:
    RealmStatusModelReaderCore<TABLE_TYPE, S, F, IDKVA>
{
    fn set_realm_status(store: &S, realm_id: u64, realm_status: BasicRealmStatus<F>) -> anyhow::Result<()> {
        let key_id = RealmTableIdKey::new(realm_id);
        IDKVA::set(store, key_id, realm_status)?;
        Ok(())
    }
    fn set_realm_statuses(store: &S, realm_ids: &[u64], realm_statuses: &[BasicRealmStatus<F>]) -> anyhow::Result<()> {
        let keys: Vec<RealmTableIdKey<TABLE_TYPE>> = realm_ids.iter().map(|id| RealmTableIdKey::new(*id)).collect::<Vec<_>>();
        IDKVA::set_many_split_ref(store, &keys, realm_statuses)?;
        Ok(())
    }
}

pub struct RealmStatusModel<const TABLE_TYPE: u16, S, F: RichField, IDKVA> {
    _idkva: IDKVA,
    _store: S,
    _phantom_data: PhantomData<F>,
}

impl<const TABLE_TYPE: u16, S, F: RichField, IDKVA: KVQStoreAdapterReader<S, RealmTableIdKey<TABLE_TYPE>, BasicRealmStatus<F>>>
    RealmStatusModelReaderCore<TABLE_TYPE, S, F, IDKVA> for RealmStatusModel<TABLE_TYPE, S, F, IDKVA>
{
}
impl<const TABLE_TYPE: u16, S, F: RichField, IDKVA: KVQStoreAdapter<S, RealmTableIdKey<TABLE_TYPE>, BasicRealmStatus<F>>>
    RealmStatusModelCore<TABLE_TYPE, S, F, IDKVA> for RealmStatusModel<TABLE_TYPE, S, F, IDKVA>
{
}
