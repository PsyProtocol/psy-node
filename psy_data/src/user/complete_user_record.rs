use parth_core::{data::hash::merkle_node_nest::MerkleNodeNest, protocol::core_types::Q256BitHash};
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::v1::qdata::public_key::PZKPublicKeyInfo;
#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct PsyCompactUserDefinition<Hash> {
    pub public_key_info: PZKPublicKeyInfo<Hash>,
    pub balance: u64,
    pub nonce: u64,
    pub last_checkpoint_id: u64,
    pub event_index: u64,
    pub constract_state_tree_records: Vec<MerkleNodeNest<Hash>>,
}




#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for PsyCompactUserDefinition<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            public_key_info: PZKPublicKeyInfo::qp_rand_gen(),
            balance: u64::qp_rand_gen(),
            nonce: u64::qp_rand_gen(),
            last_checkpoint_id: u64::qp_rand_gen(),
            event_index: u64::qp_rand_gen(),
            constract_state_tree_records: QPGenRandom::qp_rand_gen_vec_in_range(0, 16),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyCompactUserDefinition<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyCompactUserDefinition<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        let mut size = self.public_key_info.pio_serialized_size();
        // balance(8) + nonce(8) + last_checkpoint_id(8) + event_index(8)
        size += 8 * 4; 
        // constract_state_tree_records: length prefix (4) + items
        size += 4 + self.constract_state_tree_records.iter().map(|r| r.pio_serialized_size()).sum::<usize>();
        size
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.public_key_info.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.balance)?;
        writer.psy_write_u64(self.nonce)?;
        writer.psy_write_u64(self.last_checkpoint_id)?;
        writer.psy_write_u64(self.event_index)?;
        
        writer.psy_write_vec_length(self.constract_state_tree_records.len())?;
        for record in &self.constract_state_tree_records {
            record.pio_write_to_io(writer)?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let public_key_info = PZKPublicKeyInfo::<Hash>::pio_read_from_io(reader)?;
        let balance = reader.psy_read_u64()?;
        let nonce = reader.psy_read_u64()?;
        let last_checkpoint_id = reader.psy_read_u64()?;
        let event_index = reader.psy_read_u64()?;

        let records_len = reader.psy_read_vec_length()?;
        let mut constract_state_tree_records = Vec::with_capacity(records_len);
        for _ in 0..records_len {
            constract_state_tree_records.push(MerkleNodeNest::<Hash>::pio_read_from_io(reader)?);
        }

        Ok(Self {
            public_key_info,
            balance,
            nonce,
            last_checkpoint_id,
            event_index,
            constract_state_tree_records,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyCompactUserDefinition,
    { Hash: Q256BitHash } => { Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyCompactUserDefinition<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyCompactUserDefinition,
    { parth_core::PHash },
    psy_compact_user_definition_tests
);