use std::marker::PhantomData;

use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;

use crate::qdata::hash_key::Hash4x64Key;

/// Reader trait for realm root version model
pub trait RealmRootVersionModelReaderCore<const TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapterReader<S, Hash4x64Key<TABLE_TYPE>, u64>> {
    fn get_realm_root_version(store: &S, realm_root: QHashOut<GoldilocksField>) -> anyhow::Result<u64> {
        let key = Hash4x64Key::from(realm_root);
        IDKVA::get_exact(store, &key).map_err(|e| anyhow::format_err!("Realm root version for {} not found: {}", realm_root, e))
    }

    fn get_realm_root_version_if_exists(store: &S, realm_root: QHashOut<GoldilocksField>) -> anyhow::Result<Option<u64>> {
        let key = Hash4x64Key::from(realm_root);
        IDKVA::get_exact_if_exists(store, &key)
    }
}

/// Writer trait for realm root version model
pub trait RealmRootVersionModelCore<const TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapter<S, Hash4x64Key<TABLE_TYPE>, u64>>:
    RealmRootVersionModelReaderCore<TABLE_TYPE, S, IDKVA>
{
    fn set_realm_root_version(store: &S, realm_root: QHashOut<GoldilocksField>, version: u64) -> anyhow::Result<()> {
        let key = Hash4x64Key::from(realm_root);
        IDKVA::set(store, key, version)?;
        Ok(())
    }
}

/// Realm root version model struct
pub struct RealmRootVersionModel<const TABLE_TYPE: u16, S, IDKVA> {
    _idkva: PhantomData<IDKVA>,
    _store: PhantomData<S>,
}

impl<const TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapterReader<S, Hash4x64Key<TABLE_TYPE>, u64>> RealmRootVersionModelReaderCore<TABLE_TYPE, S, IDKVA>
    for RealmRootVersionModel<TABLE_TYPE, S, IDKVA>
{
}

impl<const TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapter<S, Hash4x64Key<TABLE_TYPE>, u64>> RealmRootVersionModelCore<TABLE_TYPE, S, IDKVA>
    for RealmRootVersionModel<TABLE_TYPE, S, IDKVA>
{
}
