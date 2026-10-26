use parth_core::{
    data::queue::queue_key::PCoreQueueItemBase, felt::QFelt64, protocol::core_types::Q256BitHash, utils::QPGenRandom, QJOB_ID_SERIALIZED_SIZE,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{guta::stats::GUTAStats, proof_input::guta::end_cap_input::PsyUserEventRecord, v1::qdata::user::PQEDUserLeaf};

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyRealmUserUpdateQueueItem<F, Hash> {
    pub job_id: QProvingJobDataID,
    pub expected_fake_checkpoint_id: u64,
    pub old_user_leaf_hash: Hash,
    pub new_user_leaf_hash: Hash,
    pub new_user_leaf: PQEDUserLeaf<F, Hash>,
    pub stats: GUTAStats<F>,
    pub events: Vec<PsyUserEventRecord<F>>,
}

impl<F, Hash> PsyRealmUserUpdateQueueItem<F, Hash> {
    pub fn new(
        job_id: QProvingJobDataID,
        expected_fake_checkpoint_id: u64,
        old_user_leaf_hash: Hash,
        new_user_leaf_hash: Hash,
        new_user_leaf: PQEDUserLeaf<F, Hash>,
        stats: GUTAStats<F>,
        events: Vec<PsyUserEventRecord<F>>,
    ) -> Self {
        Self {
            job_id,
            expected_fake_checkpoint_id,
            old_user_leaf_hash,
            new_user_leaf_hash,
            new_user_leaf,
            stats,
            events,
        }
    }
}

impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyRealmUserUpdateQueueItem<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        PsyRealmUserUpdateQueueItem {
            job_id: QProvingJobDataID::qp_rand_gen(),
            expected_fake_checkpoint_id: u64::qp_rand_gen(),
            old_user_leaf_hash: Hash::qp_rand_gen(),
            new_user_leaf_hash: Hash::qp_rand_gen(),
            new_user_leaf: PQEDUserLeaf::qp_rand_gen(),
            stats: GUTAStats::qp_rand_gen(),
            events: vec![],
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyRealmUserUpdateQueueItem<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyRealmUserUpdateQueueItem<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        QJOB_ID_SERIALIZED_SIZE
            + 8
            + 32
            + 32
            + PQEDUserLeaf::<F, Hash>::FIXED_SIZE
            + GUTAStats::<F>::FIXED_SIZE
            + 4
            + self.events.iter().map(|e| e.pio_serialized_size()).sum::<usize>()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.job_id.to_fixed_bytes())?;
        writer.psy_write_u64(self.expected_fake_checkpoint_id)?;
        writer.psy_write_bytes_fixed(&self.old_user_leaf_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_user_leaf_hash.into_owned_32bytes())?;
        self.new_user_leaf.pio_write_to_io(writer)?;
        self.stats.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.events.len())?;
        for event in &self.events {
            event.pio_write_to_io(writer)?;
        }

        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let job_id = QProvingJobDataID::try_from_byte_vec(&reader.psy_read_bytes_fixed::<QJOB_ID_SERIALIZED_SIZE>()?)?;
        let expected_fake_checkpoint_id = reader.psy_read_u64()?;
        let old_user_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let new_user_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let new_user_leaf = PQEDUserLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let stats = GUTAStats::<F>::pio_read_from_io(reader)?;
        let events_len = reader.psy_read_vec_length()?;
        let mut events = Vec::with_capacity(events_len);
        for _ in 0..events_len {
            events.push(PsyUserEventRecord::pio_read_from_io(reader)?);
        }
        Ok(Self {
            job_id,
            expected_fake_checkpoint_id,
            old_user_leaf_hash,
            new_user_leaf_hash,
            new_user_leaf,
            stats,
            events,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyRealmUserUpdateQueueItem,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyRealmUserUpdateQueueItem<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyRealmUserUpdateQueueItem,
    { parth_core::PF, parth_core::PHash },
    global_user_tree_agg_header_with_tag_value_and_job_id_tests
);

impl<F: QFelt64, Hash: Q256BitHash> PCoreQueueItemBase for PsyRealmUserUpdateQueueItem<F, Hash> {
    fn is_queue_item(data: &[u8]) -> bool {
        // Variable-length payload:
        // fixed prefix = job_id + expected_fake_checkpoint_id + 2*hash + user_leaf + stats + events_len(u32)
        let min_size = QJOB_ID_SERIALIZED_SIZE
            + 8
            + 32
            + 32
            + PQEDUserLeaf::<F, Hash>::FIXED_SIZE
            + GUTAStats::<F>::FIXED_SIZE
            + 4;
        data.len() >= min_size
    }

    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        Self::psy_ser_from_slice(data)
    }

    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
        self.psy_ser_to_bytes_vec()
    }

    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.job_id.to_fixed_bytes().to_vec()
    }

    fn get_size_hint() -> usize {
        // Conservative estimate: fixed prefix (job_id + checkpoint_id + 2x hash + user_leaf + stats + events_len)
        // Actual serialized size varies depending on events count.
        QJOB_ID_SERIALIZED_SIZE
            + 8
            + 32
            + 32
            + PQEDUserLeaf::<F, Hash>::FIXED_SIZE
            + GUTAStats::<F>::FIXED_SIZE
            + 4
    }

    fn has_fixed_size() -> bool {
        Self::IS_FIXED_SIZE
    }
}

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{data::queue::queue_key::PCoreQueueItemBase, PF, PHash};
    use psy_core::job::job_id::ProvingJobCircuitType;

    #[test]
    fn queue_item_round_trips_and_enforces_its_fixed_prefix() {
        let item = PsyRealmUserUpdateQueueItem::<PF, PHash>::qp_rand_gen();
        let encoded = item.encode_queue_item_vec().unwrap();
        let min_size = PsyRealmUserUpdateQueueItem::<PF, PHash>::get_size_hint();

        assert!(PsyRealmUserUpdateQueueItem::<PF, PHash>::is_queue_item(&encoded));
        assert!(!PsyRealmUserUpdateQueueItem::<PF, PHash>::is_queue_item(&encoded[..min_size - 1]));
        assert!(!PsyRealmUserUpdateQueueItem::<PF, PHash>::has_fixed_size());
        assert_eq!(item.get_restorable_job_id().len(), QJOB_ID_SERIALIZED_SIZE);

        let decoded = PsyRealmUserUpdateQueueItem::<PF, PHash>::decode_queue_item_ref(&encoded).unwrap();
        assert_eq!(decoded.job_id, item.job_id);
        assert_eq!(decoded.expected_fake_checkpoint_id, item.expected_fake_checkpoint_id);
        assert_eq!(decoded.old_user_leaf_hash, item.old_user_leaf_hash);
        assert_eq!(decoded.new_user_leaf_hash, item.new_user_leaf_hash);
        assert_eq!(decoded.events, item.events);
    }

    fn felt(value: u64) -> PF {
        use parth_core::felt::FromPrimitiveValuesFelt;
        PF::from_u64_value(value)
    }

    fn event(checkpoint_id: u64, event_index: u64) -> PsyUserEventRecord<PF> {
        PsyUserEventRecord {
            checkpoint_id: felt(checkpoint_id),
            user_id: felt(1),
            contract_id: felt(2),
            method_id: felt(3),
            event_index: felt(event_index),
            data: vec![felt(4), felt(5)],
        }
    }

    #[test]
    fn constructor_round_trips_items_with_events_and_matches_size_formula() {
        let item = PsyRealmUserUpdateQueueItem::<PF, PHash>::new(
            QProvingJobDataID::new_proof_job_id(7, 1, ProvingJobCircuitType::UserEndCap, 0, 3),
            42,
            PHash::from_values(1, 0, 0, 0),
            PHash::from_values(2, 0, 0, 0),
            PQEDUserLeaf::new(
                PHash::from_values(3, 0, 0, 0),
                PHash::from_values(4, 0, 0, 0),
                felt(100),
                felt(7),
                felt(9),
                felt(11),
                felt(13),
            ),
            GUTAStats {
                guta_fees_collected: felt(1),
                da_fees_collected: felt(2),
                user_ops_processed: felt(3),
                total_transactions: felt(4),
                slots_modified: felt(5),
            },
            vec![event(100, 0), event(101, 1)],
        );

        assert_eq!(item.events.len(), 2);
        assert_eq!(item.expected_fake_checkpoint_id, 42);

        let encoded = item.encode_queue_item_vec().unwrap();
        assert_eq!(
            encoded.len(),
            QJOB_ID_SERIALIZED_SIZE
                + 8
                + 32
                + 32
                + PQEDUserLeaf::<PF, PHash>::FIXED_SIZE
                + GUTAStats::<PF>::FIXED_SIZE
                + 4
                + item.events.iter().map(|e| e.pio_serialized_size()).sum::<usize>()
        );
        assert!(PsyRealmUserUpdateQueueItem::<PF, PHash>::is_queue_item(&encoded));

        let decoded = PsyRealmUserUpdateQueueItem::<PF, PHash>::decode_queue_item_ref(&encoded).unwrap();
        assert_eq!(decoded, item);
        assert_eq!(decoded.events, item.events);
        assert_eq!(decoded.new_user_leaf.user_id, felt(13));
        assert_eq!(decoded.stats.total_transactions, felt(4));
    }
}
