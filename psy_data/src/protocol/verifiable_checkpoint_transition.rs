#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{
    crypto::hash::traits::FieldQHasher,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{
    protocol::checkpoint_transition_hash::CheckpointStateTransitionPublicInputs, v1::qdata::populated_checkpoint::PsyCheckpointLeafPopulated,
};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyVerifiableCheckpointTransition<F, Hash> {
    pub state_transition: CheckpointStateTransitionPublicInputs<Hash>,
    pub checkpoint_leaf: PsyCheckpointLeafPopulated<F, Hash>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyVerifiableCheckpointTransition<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            state_transition: CheckpointStateTransitionPublicInputs::qp_rand_gen(),
            checkpoint_leaf: PsyCheckpointLeafPopulated::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyVerifiableCheckpointTransition<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = CheckpointStateTransitionPublicInputs::<Hash>::FIXED_SIZE + PsyCheckpointLeafPopulated::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyVerifiableCheckpointTransition<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.state_transition.pio_write_to_io(writer)?;
        self.checkpoint_leaf.pio_write_to_io(writer)
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let state_transition = CheckpointStateTransitionPublicInputs::pio_read_from_io(reader)?;
        let checkpoint_leaf = PsyCheckpointLeafPopulated::<F, Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            state_transition,
            checkpoint_leaf,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyVerifiableCheckpointTransition,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyCheckpointLeafPopulated<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyVerifiableCheckpointTransition,
    { parth_core::PF, parth_core::PHash },
    psy_verifiable_checkpoint_transition_ser_tests
);

impl<F: QFelt64, Hash: QFHashBase<F>> PsyVerifiableCheckpointTransition<F, Hash> {
    pub fn get_public_inputs_hash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.state_transition.get_public_inputs_hash_no_rewards_tag::<H>()
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyVerifiableCheckpointTransitionWithProof<F, Hash> {
    pub info: PsyVerifiableCheckpointTransition<F, Hash>,
    pub circuit_type: u32,
    pub zk_proof: Vec<u8>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyVerifiableCheckpointTransitionWithProof<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            info: PsyVerifiableCheckpointTransition::qp_rand_gen(),
            circuit_type: u32::qp_rand_gen(),
            zk_proof: u8::qp_rand_gen_vec_in_range(0, 1000),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyVerifiableCheckpointTransitionWithProof<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyVerifiableCheckpointTransitionWithProof<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.info.pio_serialized_size() + 4 + 4 + self.zk_proof.len()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.info.pio_write_to_io(writer)?;
        writer.psy_write_u32(self.circuit_type)?;
        writer.psy_write_bytes_vec(&self.zk_proof)
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let info = PsyVerifiableCheckpointTransition::pio_read_from_io(reader)?;
        let circuit_type = reader.psy_read_u32()?;
        let zk_proof = reader.psy_read_bytes_vec_with_max_length(Self::MAX_VEC_LENGTH)?;

        Ok(Self {
            info,
            circuit_type,
            zk_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyVerifiableCheckpointTransitionWithProof,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyVerifiableCheckpointTransitionWithProof<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyVerifiableCheckpointTransitionWithProof,
    { parth_core::PF, parth_core::PHash },
    psy_verifiable_checkpoint_transition_with_proof_tests
);

impl<F: QFelt64, Hash: QFHashBase<F>> PsyVerifiableCheckpointTransitionWithProof<F, Hash> {
    pub fn get_computed_public_inputs_hash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.info.state_transition.get_public_inputs_hash_no_rewards_tag::<H>()
    }
}
