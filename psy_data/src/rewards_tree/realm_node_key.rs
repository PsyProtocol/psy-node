use parth_core::{data::hash::merkle_node_key::SimpleMerkleNodeKey, utils::QPGenRandom};
use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};


pub const PSY_OBJECT_FFS_SIZE_REALM_REWARDS_NODE_KEY: usize = 17;
#[pderive::serialize_copy_default_no_ord]
#[repr(C)]
pub struct RealmRewardsTreeNodeKey {
    pub realm_id: u64,
    pub node_key: SimpleMerkleNodeKey,
}
impl QPGenRandom for RealmRewardsTreeNodeKey {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            realm_id: rand::random::<u64>(),
            node_key: SimpleMerkleNodeKey::qp_rand_gen(),
        }
    }
}


impl FastFixedSerializable<17> for RealmRewardsTreeNodeKey {
    fn ffs_from_owned_bytes(data: [u8; 17]) -> Self {
        Self {
            realm_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            node_key: SimpleMerkleNodeKey::ffs_from_owned_bytes(data[8..17].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            realm_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            node_key: SimpleMerkleNodeKey::ffs_from_slice_or_panic(&data[8..17]),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 17 {
            anyhow::bail!("invalid length for RealmRewardsTreeNodeKey, expected 17 bytes, got {}", data.len());
        }
        Ok(Self {
            realm_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            node_key: SimpleMerkleNodeKey::ffs_from_slice_or_panic(&data[8..17]),
        })
    }
    fn ffs_to_bytes(&self) -> [u8; 17] {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.realm_id.to_le_bytes());
        data[8..17].copy_from_slice(&self.node_key.ffs_to_bytes());
        data
    }
    fn ffs_into_bytes(self) -> [u8; 17] {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.realm_id.to_le_bytes());
        data[8..17].copy_from_slice(&self.node_key.ffs_to_bytes());
        data
    }
}

impl PsyCanonicalSerializeMetadata for RealmRewardsTreeNodeKey {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 17;
}
impl AutoDatabaseSerializationUseFastFixedSerialize<17> for RealmRewardsTreeNodeKey {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(RealmRewardsTreeNodeKey, 17);

pser::impl_bytemuck_pod_and_zeroable!(RealmRewardsTreeNodeKey);

// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF matches the FFS implementation
fn _ensure_compile_time_size_match_key() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_REALM_REWARDS_NODE_KEY] = RealmRewardsTreeNodeKey::qp_rand_gen().ffs_into_bytes();
}



pser::impl_bytemuck_ffs_tests!(
    RealmRewardsTreeNodeKey,
    // Note the use of concrete types here
    { },
    17
);

#[cfg(test)]
mod tests {
    use psy_serialize::{PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle};

    use super::*;

    fn key(realm_id: u64, level: u8, index: u64) -> RealmRewardsTreeNodeKey {
        RealmRewardsTreeNodeKey {
            realm_id,
            node_key: SimpleMerkleNodeKey { level, index },
        }
    }

    #[test]
    fn ffs_encoding_lays_out_realm_id_then_node_key() {
        let original = key(0x0102_0304_0506_0708, 9, 0x0a0b_0c0d_0e0f_1011);
        let bytes = original.ffs_to_bytes();
        assert_eq!(bytes.len(), PSY_OBJECT_FFS_SIZE_REALM_REWARDS_NODE_KEY);
        assert_eq!(&bytes[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(bytes[8], 9);
        assert_eq!(&bytes[9..17], &0x0a0b_0c0d_0e0f_1011u64.to_le_bytes());

        assert_eq!(RealmRewardsTreeNodeKey::ffs_from_owned_bytes(original.ffs_into_bytes()), original);
        assert_eq!(RealmRewardsTreeNodeKey::ffs_from_slice_or_panic(&bytes), original);
        assert_eq!(RealmRewardsTreeNodeKey::ffs_try_from_slice(&bytes).unwrap(), original);
    }

    #[test]
    fn ffs_try_from_slice_rejects_wrong_lengths() {
        let bytes = key(1, 2, 3).ffs_to_bytes();

        let short = &bytes[..bytes.len() - 1];
        let err = RealmRewardsTreeNodeKey::ffs_try_from_slice(short).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("expected 17 bytes"), "unexpected error message: {}", message);
        assert!(message.contains("got 16"), "unexpected error message: {}", message);

        let long = [bytes.as_slice(), &[0u8]].concat();
        assert!(RealmRewardsTreeNodeKey::ffs_try_from_slice(&long).is_err());
    }

    #[test]
    fn canonical_serialization_roundtrips_single_items_and_vectors() {
        let original = key(5, 6, 7);
        let serialized = original.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(serialized.len(), PSY_OBJECT_FFS_SIZE_REALM_REWARDS_NODE_KEY);
        assert_eq!(RealmRewardsTreeNodeKey::psy_ser_from_slice(&serialized).unwrap(), original);
        assert_eq!(
            RealmRewardsTreeNodeKey::psy_ser_from_owned_bytes_vec(serialized.clone()).unwrap(),
            original
        );

        let many = vec![original, key(8, 9, 10)];
        let vec_bytes = RealmRewardsTreeNodeKey::psy_ser_serialize_vec_of_self_ref(&many, true);
        assert_eq!(
            RealmRewardsTreeNodeKey::psy_ser_deserialize_vec_of_self(&vec_bytes, true).unwrap(),
            many
        );
    }

    #[test]
    fn keys_hash_and_compare_by_value() {
        let original = key(1, 2, 3);
        let same = key(1, 2, 3);
        let other_realm = key(2, 2, 3);
        let other_index = key(1, 2, 4);
        assert_eq!(original, same);
        assert_ne!(original, other_realm);
        assert_ne!(original, other_index);

        let mut set = std::collections::HashSet::new();
        assert!(set.insert(original));
        assert!(!set.insert(same));
        assert!(set.insert(other_realm));
        assert!(set.insert(other_index));
        assert_eq!(set.len(), 3);
    }

    #[cfg(feature = "rand_gen")]
    #[test]
    fn random_keys_roundtrip_through_ffs() {
        let original = RealmRewardsTreeNodeKey::qp_rand_gen();
        assert_eq!(RealmRewardsTreeNodeKey::ffs_from_owned_bytes(original.ffs_into_bytes()), original);
        assert_eq!(RealmRewardsTreeNodeKey::ffs_try_from_slice(&original.ffs_to_bytes()).unwrap(), original);
    }
}

