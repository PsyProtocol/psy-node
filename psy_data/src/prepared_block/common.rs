#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{v1::qdata::{checkpoint::QEDL2BlockState, populated_checkpoint::PsyCheckpointLeafPopulated}, worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId};


#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyCoordinatorPendingCheckpointBase<F, Hash> {
    pub block_state: QEDL2BlockState,
    pub checkpoint_leaf: PsyCheckpointLeafPopulated<F, Hash>,
    pub checkpoint_leaf_hash: Hash,
    pub checkpoint_tree_root: Hash,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyCoordinatorPendingCheckpointBase<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            block_state: QEDL2BlockState::qp_rand_gen(),
            checkpoint_leaf: PsyCheckpointLeafPopulated::qp_rand_gen(),
            checkpoint_leaf_hash: Hash::qp_rand_gen(),
            checkpoint_tree_root: Hash::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyCoordinatorPendingCheckpointBase<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 
        QEDL2BlockState::FIXED_SIZE +
        PsyCheckpointLeafPopulated::<F, Hash>::FIXED_SIZE +
        32 + // checkpoint_leaf_hash
        32;  // checkpoint_tree_root
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyCoordinatorPendingCheckpointBase<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.block_state.pio_write_to_io(writer)?;
        self.checkpoint_leaf.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.checkpoint_leaf_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let block_state = QEDL2BlockState::pio_read_from_io(reader)?;
        let checkpoint_leaf = PsyCheckpointLeafPopulated::<F, Hash>::pio_read_from_io(reader)?;
        let checkpoint_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);

        Ok(Self {
            block_state,
            checkpoint_leaf,
            checkpoint_leaf_hash,
            checkpoint_tree_root,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyCoordinatorPendingCheckpointBase,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyCoordinatorPendingCheckpointBase<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyCoordinatorPendingCheckpointBase,
    { parth_core::PF, parth_core::PHash },
    psy_coordinator_pending_checkpoint_base_tests
);



#[derive(Clone)]
pub struct PsyGathererPreparedResult<R, Hash, JobId> {
    pub result: R,
    pub job_ids: Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>,
}

impl<R, Hash, JobId> PsyGathererPreparedResult<R, Hash, JobId> {
    pub fn new(result: R, job_ids: Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>) -> Self {
        Self { result, job_ids }
    }
}