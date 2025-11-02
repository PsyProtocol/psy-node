use parth_core::{crypto::hash::traits::FieldQHasher, data::{hash::merkle_node_key::SimpleMerkleNodeKey, serializable::QPDSerializable}, felt::{QFelt, QFelt64, QFeltSized}, impl_qpd_serialize_params, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FallbackPsySerializeCanonical, FastFixedSerializable, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{guta::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats}, v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT};

use pser::{QBytesDeserialize, QBytesSerialize};

#[pderive::serialize_copy_f_hash]
#[repr(C)]
pub struct PsyGUTANodeUpdate<F, Hash> {

    pub guta_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub start_node_value_hash: Hash,
    pub end_node_value_hash: Hash,
    pub reward_tag: Hash,
    pub reward_inner_value: Hash,
    pub guta_stats: GUTAStats<F>,
    pub node_key: SimpleMerkleNodeKey,
}
// 128+32+9 = 169 bytes

impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyGUTANodeUpdate<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        PsyGUTANodeUpdate {
            start_node_value_hash: Hash::qp_rand_gen(),
            end_node_value_hash: Hash::qp_rand_gen(),
            reward_tag: Hash::qp_rand_gen(),
            reward_inner_value: Hash::qp_rand_gen(),
            guta_stats: GUTAStats::qp_rand_gen(),
            node_key: SimpleMerkleNodeKey::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyGUTANodeUpdate<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyGUTANodeUpdate<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32*4 + 32 + 9
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.start_node_value_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.end_node_value_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.reward_tag.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.reward_inner_value.into_owned_32bytes())?;
        self.guta_stats.pio_write_to_io(writer)?;
        self.node_key.pio_write_to_io(writer)
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let start_node_value_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let end_node_value_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let reward_tag = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let reward_inner_value = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);

        let guta_stats = GUTAStats::<F>::pio_read_from_io(reader)?;
        let node_key = SimpleMerkleNodeKey::pio_read_from_io(reader)?;
        Ok(Self {
            start_node_value_hash,
            end_node_value_hash,
            reward_tag,
            reward_inner_value,
            guta_stats,
            node_key,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyGUTANodeUpdate,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyGUTANodeUpdate<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    PsyGUTANodeUpdate,
    { parth_core::PF, parth_core::PHash },
    psy_guta_node_update
);
impl_qpd_serialize_params!(
    PsyGUTANodeUpdate,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

impl<F: QFelt, Hash: QHashBase> QFeltSized for PsyGUTANodeUpdate<F, Hash> {
    fn q_felt_size() -> usize {
        4*4 + 4 + 2
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> PsyGUTANodeUpdate<F, Hash> {
    pub fn qfhash_with_guta_height<H: FieldQHasher<F, Hash>>(&self, global_user_tree_height: u8) -> Hash {
        let start_node_value_hash = self.start_node_value_hash.to_4_felts();
        let end_node_value_hash = self.end_node_value_hash.to_4_felts();

        let user_leaf_change_combo_with_user_id = H::q_hash_many(&[
            F::from_owned_u64(self.node_key.index),

            start_node_value_hash[0],
            start_node_value_hash[1],
            start_node_value_hash[2],
            start_node_value_hash[3],

            end_node_value_hash[0],
            end_node_value_hash[1],
            end_node_value_hash[2],
            end_node_value_hash[3],

            F::from_u8_value(self.node_key.level),
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

