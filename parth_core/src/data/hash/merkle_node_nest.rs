
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{protocol::core_types::Q256BitHash, utils::QPGenRandom};


// ============================================================================
// Struct: MerkleLeafNode
// ============================================================================

#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct MerkleLeafNode<Hash> {
    pub index: u64,
    pub value: Hash,
}

impl<Hash: QPGenRandom> QPGenRandom for MerkleLeafNode<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            index: u64::qp_rand_gen(),
            value: Hash::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for MerkleLeafNode<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 8 + 32; // u64 (8) + Hash (32)
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for MerkleLeafNode<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.index)?;
        writer.psy_write_bytes_fixed(&self.value.into_owned_32bytes())?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let index = reader.psy_read_u64()?;
        let value_bytes = reader.psy_read_bytes_32()?;
        let value = Hash::from_owned_32bytes(value_bytes);
        Ok(Self { index, value })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    MerkleLeafNode,
    { Hash: Q256BitHash } => { Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for MerkleLeafNode<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    MerkleLeafNode,
    { crate::PHash },
    merkle_node_leaf_tests,
    true
);

// ============================================================================
// Struct: MerkleNodeNest
// ============================================================================

#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct MerkleNodeNest<Hash> {
    pub parent_index: u64,
    pub children: Vec<MerkleLeafNode<Hash>>,
}


impl<Hash: QPGenRandom> QPGenRandom for MerkleNodeNest<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            parent_index: u64::qp_rand_gen(),
            children: QPGenRandom::qp_rand_gen_vec(4),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for MerkleNodeNest<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for MerkleNodeNest<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        // u64 (8) + Vec len (4) + children size
        // Since MerkleLeafNode is fixed size, we can calculate strictly:
        // 8 + 4 + (len * MerkleLeafNode::FIXED_SIZE)
        8 + 4 + (self.children.len() * MerkleLeafNode::<Hash>::FIXED_SIZE)
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.parent_index)?;
        writer.psy_write_vec_length(self.children.len())?;
        for child in &self.children {
            child.pio_write_to_io(writer)?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let parent_index = reader.psy_read_u64()?;
        let children_len = reader.psy_read_vec_length()?;
        let mut children = Vec::with_capacity(children_len);
        for _ in 0..children_len {
            children.push(MerkleLeafNode::<Hash>::pio_read_from_io(reader)?);
        }
        Ok(Self {
            parent_index,
            children,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    MerkleNodeNest,
    { Hash: Q256BitHash } => { Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for MerkleNodeNest<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    MerkleNodeNest,
    { crate::PHash },
    merkle_node_nest_tests,
    true
);
