use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};
use psy_client_common::utils::math::ceil_div_usize;
use psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT;
use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::zk::data::ZKPublicKeyInfo};

use crate::{
    config::store_config::{PsyHash, PsyHasher, QUserPublicKeyRecord},
    qdata::hash_key_with_id::Hash4x64KeyWithId,
};

pub trait PsyUserPublicKeyHelperModelReaderCore<
    const USER_PUBLIC_KEY_HELPER_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapterReader<S, Hash4x64KeyWithId<USER_PUBLIC_KEY_HELPER_TABLE_TYPE>, QUserPublicKeyRecord>,
>
{
    fn get_first_user_for_public_key_hash_if_exists(store: &S, public_key: PsyHash) -> anyhow::Result<Option<QUserPublicKeyRecord>> {
        let max_user_id = (1u64 << (GLOBAL_USER_TREE_HEIGHT as u64)) - 1;
        let user_id_bytes = ceil_div_usize(GLOBAL_USER_TREE_HEIGHT as usize, 8).min(8);

        KVA::get_leq(store, &Hash4x64KeyWithId::new(public_key, max_user_id), user_id_bytes)
    }
    fn get_users_for_public_key_hash_if_exists(
        store: &S,
        public_key: PsyHash,
        start_user_id: Option<u64>,
    ) -> anyhow::Result<Vec<QUserPublicKeyRecord>> {
        let real_max_user_id = (1u64 << (GLOBAL_USER_TREE_HEIGHT as u64)) - 1;
        let max_user_id = start_user_id.unwrap_or(real_max_user_id).min(real_max_user_id);
        let user_id_bytes = ceil_div_usize(GLOBAL_USER_TREE_HEIGHT as usize, 8).min(8);

        Ok(
            KVA::get_fuzzy_range_leq_kv(store, &Hash4x64KeyWithId::new(public_key, max_user_id), user_id_bytes)?
                .into_iter()
                .map(|x| x.value)
                .filter(|record| record.public_key == public_key)
                .collect(),
        )
    }
}
pub trait PsyUserPublicKeyHelperModelCore<
    const USER_PUBLIC_KEY_HELPER_TABLE_TYPE: u16,
    S,
    KVA: KVQStoreAdapter<S, Hash4x64KeyWithId<USER_PUBLIC_KEY_HELPER_TABLE_TYPE>, QUserPublicKeyRecord>,
>: PsyUserPublicKeyHelperModelReaderCore<USER_PUBLIC_KEY_HELPER_TABLE_TYPE, S, KVA>
{
    fn delete_user_public_key_record(store: &mut S, user_id: u64, public_key: PsyHash) -> anyhow::Result<Option<QUserPublicKeyRecord>> {
        let current = KVA::get_exact_if_exists(store, &Hash4x64KeyWithId::new(public_key, user_id))?;
        if current.is_some() {
            let deposit = current.unwrap();
            KVA::delete(store, &Hash4x64KeyWithId::new(public_key, user_id))?;
            Ok(Some(deposit))
        } else {
            Ok(None)
        }
    }
    fn set_user_public_key_record(store: &S, record: QUserPublicKeyRecord) -> anyhow::Result<()> {
        KVA::set(store, Hash4x64KeyWithId::new(record.public_key, record.user_id), record)
    }
    fn set_user_public_key_records(store: &S, records: &[QUserPublicKeyRecord]) -> anyhow::Result<()> {
        let keys = records
            .iter()
            .map(|x| Hash4x64KeyWithId::new(x.public_key, x.user_id))
            .collect::<Vec<_>>();
        KVA::set_many_split_ref(store, &keys, records)
    }
    fn set_user_public_key_record_params(
        store: &S,
        checkpoint_id: u64,
        user_id: u64,
        public_key_param: PsyHash,
        fingerprint: PsyHash,
    ) -> anyhow::Result<()> {
        let public_key = ZKPublicKeyInfo {
            public_key_param,
            fingerprint,
        }
        .qfhash::<PsyHasher>();
        let record = QUserPublicKeyRecord {
            public_key_param,
            fingerprint,
            public_key,
            user_id,
            checkpoint_id,
        };
        Self::set_user_public_key_record(store, record)
    }
}
pub struct PsyUserPublicKeyHelperModel<const USER_PUBLIC_KEY_HELPER_TABLE_TYPE: u16, S, KVA> {
    _store: S,
    _kva: KVA,
}

impl<
        const USER_PUBLIC_KEY_HELPER_TABLE_TYPE: u16,
        S,
        KVA: KVQStoreAdapterReader<S, Hash4x64KeyWithId<USER_PUBLIC_KEY_HELPER_TABLE_TYPE>, QUserPublicKeyRecord>,
    > PsyUserPublicKeyHelperModelReaderCore<USER_PUBLIC_KEY_HELPER_TABLE_TYPE, S, KVA>
    for PsyUserPublicKeyHelperModel<USER_PUBLIC_KEY_HELPER_TABLE_TYPE, S, KVA>
{
}
impl<
        const USER_PUBLIC_KEY_HELPER_TABLE_TYPE: u16,
        S,
        KVA: KVQStoreAdapter<S, Hash4x64KeyWithId<USER_PUBLIC_KEY_HELPER_TABLE_TYPE>, QUserPublicKeyRecord>,
    > PsyUserPublicKeyHelperModelCore<USER_PUBLIC_KEY_HELPER_TABLE_TYPE, S, KVA>
    for PsyUserPublicKeyHelperModel<USER_PUBLIC_KEY_HELPER_TABLE_TYPE, S, KVA>
{
}
