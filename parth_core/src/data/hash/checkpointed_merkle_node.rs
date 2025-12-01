use std::cmp::Ordering;

use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};

use crate::{protocol::core_types::Q256BitHash, utils::QPGenRandom};

pub const PSY_OBJECT_FFS_SIZE_CHECKPOINTED_MERKLE_HASH: usize = 40;

#[pderive::serialize_copy_no_ord]
#[repr(C)]
pub struct CheckpointedMerkleHash<Hash> {
    pub checkpoint_id: u64,
    pub value: Hash,
}

impl<Hash: PartialOrd> PartialOrd for CheckpointedMerkleHash<Hash> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.checkpoint_id != other.checkpoint_id {
            self.checkpoint_id.partial_cmp(&other.checkpoint_id)
        } else {
            self.value.partial_cmp(&other.value)
        }
    }
}
impl<Hash: Ord> Ord for CheckpointedMerkleHash<Hash> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.checkpoint_id != other.checkpoint_id {
            self.checkpoint_id.cmp(&other.checkpoint_id)
        } else {
            self.value.cmp(&other.value)
        }
    }
}

impl<Hash: Q256BitHash> FastFixedSerializable<40> for CheckpointedMerkleHash<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 40]) -> Self {
        Self {
            checkpoint_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            value: Hash::from_ref_32bytes(data[8..40].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            checkpoint_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            value: Hash::from_ref_32bytes(data[8..40].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 40 {
            anyhow::bail!("invalid length for CheckpointedMerkleHash, expected 40 bytes, got {}", data.len());
        }
        Ok(Self {
            checkpoint_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            value: Hash::from_slice_32bytes(&data[8..40])?,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 40] {
        let mut data: [u8; 40] = [0u8; 40];
        data[0..8].copy_from_slice(&self.checkpoint_id.to_le_bytes());
        data[8..40].copy_from_slice(&self.value.into_owned_32bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 40] {
        let mut data: [u8; 40] = [0u8; 40];
        data[0..8].copy_from_slice(&self.checkpoint_id.to_le_bytes());
        data[8..40].copy_from_slice(&self.value.into_owned_32bytes());
        data
    }
}

pser::impl_bytemuck_pod_and_zeroable!(CheckpointedMerkleHash, Hash);

pser::impl_bytemuck_ffs_tests!(CheckpointedMerkleHash, { crate::PHash }, 40, true);

// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF matches the FFS implementation
fn _ensure_compile_time_size_match_node() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_CHECKPOINTED_MERKLE_HASH] =
        CheckpointedMerkleHash::<crate::data::hash::hash256::Hash256>::qp_rand_gen().ffs_into_bytes();
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_CHECKPOINTED_MERKLE_HASH] = CheckpointedMerkleHash::<crate::PHash>::qp_rand_gen().ffs_into_bytes();
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for CheckpointedMerkleHash<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 40;
}
impl<Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<40> for CheckpointedMerkleHash<Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    CheckpointedMerkleHash,
    {Hash: Q256BitHash} => {Hash},
    40
);

impl<Hash: QPGenRandom> QPGenRandom for CheckpointedMerkleHash<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            checkpoint_id: u64::qp_rand_gen(),
            value: Hash::qp_rand_gen(),
        }
    }
}