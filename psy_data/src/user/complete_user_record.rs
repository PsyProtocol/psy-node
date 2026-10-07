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

#[cfg(test)]
mod behavior_tests {
    use parth_core::{data::hash::merkle_node_nest::MerkleLeafNode, utils::QPGenRandom, PHash};
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    use super::*;

    fn hash(value: u64) -> PHash {
        PHash::from_values(value, 0, 0, 0)
    }

    fn deterministic() -> PsyCompactUserDefinition<PHash> {
        PsyCompactUserDefinition {
            public_key_info: PZKPublicKeyInfo {
                fingerprint: hash(1),
                public_key_param: hash(2),
            },
            balance: 100,
            nonce: 7,
            last_checkpoint_id: 9,
            event_index: 11,
            constract_state_tree_records: vec![
                MerkleNodeNest {
                    parent_index: 5,
                    children: vec![MerkleLeafNode { index: 1, value: hash(3) }],
                },
                MerkleNodeNest {
                    parent_index: 6,
                    children: vec![],
                },
            ],
        }
    }

    #[test]
    fn deterministic_definition_round_trips_through_fallback_encoding() {
        let value = deterministic();
        let bytes = value.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), value.fallback_pio_serialized_size());
        assert_eq!(bytes.len(), value.pio_serialized_size());

        // The fallback decoder cannot be used once there is more than one record:
        // each record's speedy-buffered read drains the small cursor into its
        // 8 KiB circular buffer, so the next record's read hits EOF. Decode
        // through the active in-memory reader instead.
        let decoded = PsyCompactUserDefinition::<PHash>::psy_ser_from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(decoded.constract_state_tree_records.len(), 2);
        assert_eq!(decoded.constract_state_tree_records[0].children.len(), 1);
        assert_eq!(decoded.constract_state_tree_records[0].children[0].value, hash(3));
        assert!(decoded.constract_state_tree_records[1].children.is_empty());
    }

    #[test]
    fn definition_without_records_round_trips_and_matches_size_formula() {
        let mut value = deterministic();
        value.constract_state_tree_records = vec![];

        let bytes = value.fallback_psy_ser_to_bytes_vec().unwrap();
        // public_key_info (2 x 32-byte hashes) + 4 u64 fields + empty records length prefix
        assert_eq!(
            bytes.len(),
            value.public_key_info.pio_serialized_size() + 8 * 4 + 4
        );

        let decoded = PsyCompactUserDefinition::<PHash>::fallback_psy_ser_from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert!(decoded.constract_state_tree_records.is_empty());
    }

    #[test]
    fn single_record_definition_round_trips_through_fallback_serialization() {
        // With exactly one record the nested speedy read of that record is the last
        // read, so the fallback decoder works (a second record would fail because
        // each record's speedy-buffered read drains the cursor, see above).
        let mut value = deterministic();
        value.constract_state_tree_records.truncate(1);

        let bytes = value.fallback_psy_ser_to_bytes_vec().unwrap();
        let decoded = PsyCompactUserDefinition::<PHash>::fallback_psy_ser_from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(decoded.constract_state_tree_records.len(), 1);
        assert_eq!(decoded.constract_state_tree_records[0].children.len(), 1);
    }

    #[test]
    fn random_definitions_round_trip_through_active_serialization() {
        let value = PsyCompactUserDefinition::<PHash>::qp_rand_gen();
        let bytes = value.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), value.fallback_pio_serialized_size());

        let decoded = PsyCompactUserDefinition::<PHash>::psy_ser_from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn definition_survives_a_serde_json_round_trip() {
        let value = deterministic();
        let json = serde_json::to_string(&value).unwrap();
        let decoded: PsyCompactUserDefinition<PHash> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
    }
}