use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher, QFieldHashable},
    data::{queue::queue_key::PCoreQueueItemBase, serializable::QPDSerializable},
    felt::QFelt64,
    impl_qpd_serialize_params,
    protocol::core_types::{Q256BitHash, QFHashBase, QHashBase},
    utils::QPGenRandom,
};
use pser::{QBytesDeserialize, QBytesSerialize};
use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};

use crate::v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY;

#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "ZKPublicKeyInfo")]
pub struct PZKPublicKeyInfo<Hash> {
    pub fingerprint: Hash,
    pub public_key_param: Hash,
}
impl<Hash: QPGenRandom> QPGenRandom for PZKPublicKeyInfo<Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            fingerprint: Hash::qp_rand_gen(),
            public_key_param: Hash::qp_rand_gen(),
        }
    }
}

impl<Hash: QHashBase> PZKPublicKeyInfo<Hash> {
    pub fn to_hash<H: MerkleHasher<Hash>>(&self) -> Hash {
        H::two_to_one(&self.fingerprint, &self.public_key_param)
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for PZKPublicKeyInfo<Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        H::q_two_to_one(self.fingerprint, self.public_key_param)
    }
}
#[inline(always)]
fn split_64_bytes_to_two_32_byte_hashes(data: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let first: [u8; 32] = data[0..32].try_into().unwrap();
    let second: [u8; 32] = data[32..64].try_into().unwrap();
    (first, second)
}

pser::impl_bytemuck_ffs_tests!(
    PZKPublicKeyInfo,
    // Note the use of concrete types here
    { parth_core::PHash },
    64
);

// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_USER_LEAF matches the FFS implementation
fn _ensure_compile_time_size_match() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY] =
        PZKPublicKeyInfo::<parth_core::data::hash::hash256::Hash256>::qp_rand_gen().ffs_into_bytes();
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY] = PZKPublicKeyInfo::<parth_core::PHash>::qp_rand_gen().ffs_into_bytes();
}
impl_qpd_serialize_params!(PZKPublicKeyInfo, { Hash: QHashBase } => { Hash });

// todo, just implement this with bytemuck
impl<Hash: Q256BitHash> FastFixedSerializable<64> for PZKPublicKeyInfo<Hash> {
    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; 64]) -> Self {
        let (fingerprint_bytes, public_key_param_bytes) = split_64_bytes_to_two_32_byte_hashes(data);
        Self {
            fingerprint: Hash::from_owned_32bytes(fingerprint_bytes),
            public_key_param: Hash::from_owned_32bytes(public_key_param_bytes),
        }
    }
    #[inline(always)]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != 64 {
            panic!("Invalid data length for PZKPublicKeyInfo");
        }
        let data_array: [u8; 64] = data.try_into().unwrap();
        Self::ffs_from_owned_bytes(data_array)
    }
    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 64 {
            anyhow::bail!("Invalid data length for PZKPublicKeyInfo");
        }
        Ok(Self {
            fingerprint: Hash::from_slice_32bytes(&data[0..32]).unwrap(),
            public_key_param: Hash::from_slice_32bytes(&data[32..64]).unwrap(),
        })
    }
    #[inline(always)]
    fn ffs_to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.fingerprint.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.public_key_param.into_owned_32bytes());
        bytes
    }
    #[inline(always)]
    fn ffs_into_bytes(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.fingerprint.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.public_key_param.into_owned_32bytes());
        bytes
    }
}

impl<Hash: Q256BitHash> PCoreQueueItemBase for PZKPublicKeyInfo<Hash> {
    fn is_queue_item(data: &[u8]) -> bool {
        data.len() == PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY
    }

    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        Self::ffs_try_from_slice(data)
    }

    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.ffs_to_bytes().to_vec())
    }

    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.ffs_to_bytes().to_vec()
    }

    fn get_size_hint() -> usize {
        64
    }

    fn has_fixed_size() -> bool {
        true
    }
}
impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PZKPublicKeyInfo<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 64;
}
impl<Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<64> for PZKPublicKeyInfo<Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    PZKPublicKeyInfo,
    {Hash: Q256BitHash} => {Hash},
    64
);

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::traits::{FieldQHasher, FromU64x4, MerkleHasher, QFieldHashable, ZeroableHash},
        data::queue::queue_key::PCoreQueueItemBase,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::Q256BitHash,
        PHash,
    };
    use psy_serialize::FastFixedSerializable;

    use super::PZKPublicKeyInfo;

    type TargetType = PZKPublicKeyInfo<PHash>;

    fn sample() -> TargetType {
        PZKPublicKeyInfo {
            fingerprint: PHash::from_u64x4([1, 2, 3, 4]),
            public_key_param: PHash::from_u64x4([5, 6, 7, 8]),
        }
    }

    #[test]
    fn to_hash_and_qfhash_match_direct_hasher_calls() {
        let info = sample();
        assert_eq!(info.to_hash::<PoseidonHasher>(), PoseidonHasher::two_to_one(&info.fingerprint, &info.public_key_param));
        assert_eq!(info.qfhash::<PoseidonHasher>(), PoseidonHasher::q_two_to_one(info.fingerprint, info.public_key_param));
        assert_ne!(info.to_hash::<PoseidonHasher>(), PHash::get_zero_value());
    }

    #[test]
    fn ffs_round_trip_preserves_both_halves() {
        let info = sample();
        let bytes = info.ffs_to_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(TargetType::ffs_from_owned_bytes(info.ffs_into_bytes()), info);
        assert_eq!(TargetType::ffs_from_slice_or_panic(&bytes), info);
        let restored = TargetType::ffs_try_from_slice(&bytes).unwrap();
        assert_eq!(restored, info);
        // each hash occupies one half of the fixed byte layout
        assert_eq!(bytes[0..32].to_vec(), info.fingerprint.into_owned_32bytes().to_vec());
        assert_eq!(bytes[32..64].to_vec(), info.public_key_param.into_owned_32bytes().to_vec());
    }

    #[test]
    fn ffs_try_from_slice_rejects_wrong_lengths() {
        assert!(TargetType::ffs_try_from_slice(&[0u8; 63]).is_err());
        assert!(TargetType::ffs_try_from_slice(&[0u8; 65]).is_err());
        assert!(TargetType::ffs_try_from_slice(&[]).is_err());
    }

    #[test]
    #[should_panic(expected = "Invalid data length for PZKPublicKeyInfo")]
    fn ffs_from_slice_or_panic_panics_on_wrong_length() {
        let _ = TargetType::ffs_from_slice_or_panic(&[0u8; 63]);
    }

    #[test]
    fn queue_item_helpers_round_trip_and_validate_length() {
        let info = sample();
        let bytes = info.encode_queue_item_vec().unwrap();
        assert_eq!(bytes.len(), 64);
        assert!(TargetType::is_queue_item(&bytes));
        assert!(!TargetType::is_queue_item(&bytes[..63]));
        assert!(!TargetType::is_queue_item(&[]));

        let decoded = TargetType::decode_queue_item_ref(&bytes).unwrap();
        assert_eq!(decoded, info);
        assert!(TargetType::decode_queue_item_ref(&bytes[..63]).is_err());

        assert_eq!(info.get_restorable_job_id(), bytes);
        assert_eq!(TargetType::get_size_hint(), 64);
        assert!(TargetType::has_fixed_size());
    }
}
