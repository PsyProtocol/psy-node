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

