use parth_core::{QJOB_ID_SERIALIZED_SIZE, data::queue::queue_key::PCoreQueueItemBase, felt::QFelt64, protocol::core_types::Q256BitHash, utils::QPGenRandom};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::v1::qdata::user::PQEDUserLeaf;

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyRealmUserUpdatQueueItem<F, Hash> {
    pub job_id: QProvingJobDataID,
    pub expected_fake_checkpoint_id: u64,
    pub old_user_leaf_hash: Hash,
    pub new_user_leaf_hash: Hash,
    pub new_user_leaf: PQEDUserLeaf<F, Hash>,
}

impl<F, Hash> PsyRealmUserUpdatQueueItem<F, Hash> {
    pub fn new(
        job_id: QProvingJobDataID,
        expected_fake_checkpoint_id: u64,
        old_user_leaf_hash: Hash,
        new_user_leaf_hash: Hash,
        new_user_leaf: PQEDUserLeaf<F, Hash>,
    ) -> Self {
        Self {
            job_id,
            expected_fake_checkpoint_id,
            old_user_leaf_hash,
            new_user_leaf_hash,
            new_user_leaf,
        }
    }
}





impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyRealmUserUpdatQueueItem<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        PsyRealmUserUpdatQueueItem {
            job_id: QProvingJobDataID::qp_rand_gen(),
            expected_fake_checkpoint_id: u64::qp_rand_gen(),
            old_user_leaf_hash: Hash::qp_rand_gen(),
            new_user_leaf_hash: Hash::qp_rand_gen(),
            new_user_leaf: PQEDUserLeaf::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyRealmUserUpdatQueueItem<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = QJOB_ID_SERIALIZED_SIZE + 8 + 32 + 32 + PQEDUserLeaf::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyRealmUserUpdatQueueItem<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
            PsyRealmUserUpdatQueueItem::<F, Hash>::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.job_id.to_fixed_bytes())?;
        writer.psy_write_u64(self.expected_fake_checkpoint_id)?;
        writer.psy_write_bytes_fixed(&self.old_user_leaf_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_user_leaf_hash.into_owned_32bytes())?;
        self.new_user_leaf.pio_write_to_io(writer)?;

        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let job_id = QProvingJobDataID::try_from_byte_vec(&reader.psy_read_bytes_fixed::<QJOB_ID_SERIALIZED_SIZE>()?)?;
        let expected_fake_checkpoint_id = reader.psy_read_u64()?;
        let old_user_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let new_user_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let new_user_leaf = PQEDUserLeaf::<F, Hash>::pio_read_from_io(reader)?;
        Ok(Self {
            job_id,
            expected_fake_checkpoint_id,
            old_user_leaf_hash,
            new_user_leaf_hash,
            new_user_leaf,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyRealmUserUpdatQueueItem,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyRealmUserUpdatQueueItem<F, Hash> {}



pser::impl_psy_ser_basic_tests_fallback!(
    PsyRealmUserUpdatQueueItem,
    { parth_core::PF, parth_core::PHash },
    global_user_tree_agg_header_with_tag_value_and_job_id_tests
);

impl<F: QFelt64, Hash: Q256BitHash> PCoreQueueItemBase for PsyRealmUserUpdatQueueItem<F, Hash> {
    fn is_queue_item(data: &[u8]) -> bool {
        data.len() == Self::FIXED_SIZE
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
        Self::FIXED_SIZE
    }

    fn has_fixed_size() -> bool {
        true
    }
}