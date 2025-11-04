use parth_core::{
    QJOB_ID_SERIALIZED_SIZE, QJobIdBase, data::{hash::merkle_node_key::SimpleMerkleNodeKey, queue::queue_key::PCoreQueueItemBase}, protocol::core_types::Q256BitHash, utils::QPGenRandom
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::worker::metadata::PsyProvingJobMetadata;


#[pderive::serialize_clone_hash_job_id_ts]
#[ts(export, concrete(Hash = parth_core::PHash, JobId = QProvingJobDataID))]
#[repr(C)]
pub struct PsyProvingJobMetadataWithJobId<Hash, JobId> {
    pub job_id: JobId,
    pub metadata: PsyProvingJobMetadata<Hash, JobId>,
}

impl<Hash, JobId> PsyProvingJobMetadataWithJobId<Hash, JobId> {
    pub fn get_reward_tree_node_key(&self) -> SimpleMerkleNodeKey {
        self.metadata.get_reward_tree_node_key()
    }
}
impl<Hash: QPGenRandom, JobId: QPGenRandom> QPGenRandom for PsyProvingJobMetadataWithJobId<Hash, JobId> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            job_id: JobId::qp_rand_gen(),
            metadata: PsyProvingJobMetadata::qp_rand_gen(),
        }
    }
}


impl<Hash: Q256BitHash, JobId: QJobIdBase> PsyCanonicalSerializeMetadata for PsyProvingJobMetadataWithJobId<Hash, JobId> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> FallbackPsySerializeCanonical for PsyProvingJobMetadataWithJobId<Hash, JobId> {
    fn fallback_pio_serialized_size(&self) -> usize {
        QJOB_ID_SERIALIZED_SIZE + self.metadata.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.job_id.to_bytes_fixed())?;
        self.metadata.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let job_id = JobId::from_bytes_fixed(&reader.psy_read_bytes_fixed()?)?;
        let metadata = PsyProvingJobMetadata::<Hash, JobId>::pio_read_from_io(reader)?;
        Ok(Self {
            job_id,
            metadata,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyProvingJobMetadataWithJobId,
    { Hash: Q256BitHash, JobId: QJobIdBase } => { Hash, JobId }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash, JobId: QJobIdBase> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyProvingJobMetadataWithJobId<Hash, JobId>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyProvingJobMetadataWithJobId,
    { parth_core::PHash, psy_core::job::job_id::QProvingJobDataID },
    psy_proving_job_metadata_with_job_id_tests
);




impl<Hash: Q256BitHash, JobId: QJobIdBase> PCoreQueueItemBase for PsyProvingJobMetadataWithJobId<Hash, JobId> {
    fn is_queue_item(data: &[u8]) -> bool {
        data.len() >= (   32 + 8 + (1 + 1 + 2) + 4 + QJOB_ID_SERIALIZED_SIZE)
    }

    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        Self::psy_ser_from_slice(data)
    }

    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
       self.psy_ser_to_bytes_vec()
    }

    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.job_id.to_bytes_fixed().to_vec()
    }

    fn get_size_hint() -> usize {
        32 + 8 + (1 + 1 + 2) + 4 + QJOB_ID_SERIALIZED_SIZE*3
    }

    fn has_fixed_size() -> bool {
        false
    }
}