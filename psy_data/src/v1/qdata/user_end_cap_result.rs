use parth_core::{crypto::hash::traits::FieldQHasher, data::serializable::{QPDSerializable}, felt::{QFelt, QFelt64, QFeltSized}, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}, utils::QPGenRandom};
use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};

use crate::v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT;


#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "UPSEndCapResultCompact")]
pub struct PUPSEndCapResultCompact<F, Hash> {
    pub start_user_leaf_hash: Hash,
    pub end_user_leaf_hash: Hash,
    pub checkpoint_tree_root_hash: Hash,
    pub user_id: F,
}

impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PUPSEndCapResultCompact<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: Hash::qp_rand_gen(),
            end_user_leaf_hash: Hash::qp_rand_gen(),
            checkpoint_tree_root_hash: Hash::qp_rand_gen(),
            user_id: F::qp_rand_gen(),
        }
    }
}
pser::impl_bytemuck_pod_and_zeroable!(PUPSEndCapResultCompact, F, Hash);


pser::impl_bytemuck_ffs!(
    PUPSEndCapResultCompact,
    { F: QFelt64, Hash: Q256BitHash },
    104
);


pser::impl_bytemuck_ffs_tests!(
    PUPSEndCapResultCompact,
    // Note the use of concrete types here
    { parth_core::PF, parth_core::PHash },
    104
);

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PUPSEndCapResultCompact<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 104;
}
impl<F: QFelt64, Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<104> for PUPSEndCapResultCompact<F, Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    PUPSEndCapResultCompact, 
    {F: QFelt64, Hash: Q256BitHash} => {F, Hash}, 
    104
);

// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT matches the FFS implementation
fn _ensure_compile_time_size_match() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT] = PUPSEndCapResultCompact::<u64, parth_core::data::hash::hash256::Hash256>::qp_rand_gen().ffs_into_bytes();
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT] = PUPSEndCapResultCompact::<parth_core::PF, parth_core::PHash>::qp_rand_gen().ffs_into_bytes();
}


impl<F: QFelt, Hash: QHashBase> QPDSerializable for PUPSEndCapResultCompact<F, Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: QFelt, Hash: QHashBase> QFeltSized for PUPSEndCapResultCompact<F, Hash> {
    fn q_felt_size() -> usize {
        13
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> PUPSEndCapResultCompact<F, Hash> {
    pub fn qfhash_with_guta_height<H: FieldQHasher<F, Hash>>(&self, global_user_tree_height: u8) -> Hash {
        let start_user_leaf_hash = self.start_user_leaf_hash.to_4_felts();
        let end_user_leaf_hash = self.end_user_leaf_hash.to_4_felts();

        let user_leaf_change_combo_with_user_id = H::q_hash_many(&[
            self.user_id,

            start_user_leaf_hash[0],
            start_user_leaf_hash[1],
            start_user_leaf_hash[2],
            start_user_leaf_hash[3],

            end_user_leaf_hash[0],
            end_user_leaf_hash[1],
            end_user_leaf_hash[2],
            end_user_leaf_hash[3],

            F::from_u8_value(global_user_tree_height),
        ]);

        let end_cap_result_hash = H::q_two_to_one(
            self.checkpoint_tree_root_hash,
            user_leaf_change_combo_with_user_id,
        );
        end_cap_result_hash
    }
}


// fallback for big endian platforms, not zero copy
#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]
impl<F: QFelt64, Hash: Q256BitHash> FastFixedSerializable<104> for PUPSEndCapResultCompact<F, Hash> {
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT]) -> Self {
        let start_user_leaf_hash = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let end_user_leaf_hash = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let checkpoint_tree_root_hash = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let user_id = F::from_u64_value(u64::from_le_bytes(data[96..104].try_into().unwrap()));
        
        PUPSEndCapResultCompact {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            user_id,
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT {
            panic!("Invalid number of bytes for PQEDContractLeaf");
        }
        let start_user_leaf_hash = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let end_user_leaf_hash = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let checkpoint_tree_root_hash = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let user_id = F::from_u64_value(u64::from_le_bytes(data[96..104].try_into().unwrap()));
        
        PUPSEndCapResultCompact {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            user_id,
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT {
            anyhow::bail!("Invalid number of bytes for PUPSEndCapResultCompact");
        }

        let start_user_leaf_hash = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let end_user_leaf_hash = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let checkpoint_tree_root_hash = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let user_id = F::from_u64_value(u64::from_le_bytes(data[96..104].try_into().unwrap()));

        Ok(Self{
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            user_id,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT];
        bytes[0..32].copy_from_slice(&self.start_user_leaf_hash.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.end_user_leaf_hash.into_owned_32bytes());
        bytes[64..96].copy_from_slice(&self.checkpoint_tree_root_hash.into_owned_32bytes());
        bytes[96..104].copy_from_slice(&self.user_id.to_u64_value().to_le_bytes());
        bytes
    }

    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT];
        bytes[0..32].copy_from_slice(&self.start_user_leaf_hash.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.end_user_leaf_hash.into_owned_32bytes());
        bytes[64..96].copy_from_slice(&self.checkpoint_tree_root_hash.into_owned_32bytes());
        bytes[96..104].copy_from_slice(&self.user_id.to_u64_value().to_le_bytes());
        bytes
    }
}

