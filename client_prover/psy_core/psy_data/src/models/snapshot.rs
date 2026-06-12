use std::marker::PhantomData;

use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;

use crate::qdata::realm_snapshot_key::RealmSnapshotKey;

/// Reader trait for realm snapshot model
pub trait RealmSnapshotModelReaderCore<const TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapterReader<S, RealmSnapshotKey<TABLE_TYPE>, Vec<u8>>> {
    fn get_realm_snapshot(store: &S, realm_root: QHashOut<GoldilocksField>, version: u64) -> anyhow::Result<Vec<u8>> {
        IDKVA::get_exact(store, &RealmSnapshotKey::new(realm_root, version))
            .map_err(|e| anyhow::format_err!("Realm snapshot for root {} version {} not found: {}", realm_root, version, e))
    }
}

/// Writer trait for realm snapshot model
pub trait RealmSnapshotModelCore<const TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapter<S, RealmSnapshotKey<TABLE_TYPE>, Vec<u8>>>:
    RealmSnapshotModelReaderCore<TABLE_TYPE, S, IDKVA>
{
    fn set_realm_snapshot(store: &S, realm_root: QHashOut<GoldilocksField>, version: u64, snapshot: Vec<u8>) -> anyhow::Result<()> {
        let key = RealmSnapshotKey::new(realm_root, version);
        IDKVA::set(store, key, snapshot)?;
        Ok(())
    }
}

/// Realm snapshot model struct
pub struct RealmSnapshotModel<const TABLE_TYPE: u16, S, IDKVA> {
    _idkva: PhantomData<IDKVA>,
    _store: PhantomData<S>,
}

impl<const TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapterReader<S, RealmSnapshotKey<TABLE_TYPE>, Vec<u8>>>
    RealmSnapshotModelReaderCore<TABLE_TYPE, S, IDKVA> for RealmSnapshotModel<TABLE_TYPE, S, IDKVA>
{
}

impl<const TABLE_TYPE: u16, S, IDKVA: KVQStoreAdapter<S, RealmSnapshotKey<TABLE_TYPE>, Vec<u8>>> RealmSnapshotModelCore<TABLE_TYPE, S, IDKVA>
    for RealmSnapshotModel<TABLE_TYPE, S, IDKVA>
{
}
