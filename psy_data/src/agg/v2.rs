#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, HashTo4Felts},
    felt::QFelt64,
    protocol::core_types::Q256BitHash,
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::agg::{AggStateTrackableInput, AggStateTransition, AggStateTransitionInput, WithDummyStateTransition};

pub trait AggStateWitnessV2<F, Hash> {
    fn get_public_inputs_hash_no_tag_tree<H: FieldQHasher<F, Hash>>(&self, allowed_circuit_hashes_root: Hash) -> Hash;
}
#[pderive::serialize_copy_hash]
pub struct AggStateTransitionWithStats<Hash> {
    pub state_transition_start: Hash,
    pub state_transition_end: Hash,
    pub total_proofs_generated: u64,
}

impl<Hash: Copy> WithDummyStateTransition<Hash> for AggStateTransitionWithStats<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            state_transition_start: state_root,
            state_transition_end: state_root,
            total_proofs_generated: 0,
        }
    }
}

#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for AggStateTransitionWithStats<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            state_transition_start: Hash::qp_rand_gen(),
            state_transition_end: Hash::qp_rand_gen(),
            total_proofs_generated: rand::random(),
        }
    }
}

impl<Hash: Copy> AggStateTransitionWithStats<Hash> {
    pub fn get_public_inputs_hash_no_tag_tree<H: FieldQHasher<F, Hash>, F: QFelt64>(&self, whitelist_root: Hash) -> Hash
    where
        Hash: HashTo4Felts<F>,
    {
        let transition_hash = H::q_two_to_one(self.state_transition_start, self.state_transition_end);
        let allowed_and_state_transition_hash = H::q_two_to_one(whitelist_root, transition_hash);

        let allowed_and_state_transition_hash_felts = allowed_and_state_transition_hash.to_4_felts();

        let public_inputs_without_reward_tag = H::q_hash_many(&[
            allowed_and_state_transition_hash_felts[0],
            allowed_and_state_transition_hash_felts[1],
            allowed_and_state_transition_hash_felts[2],
            allowed_and_state_transition_hash_felts[3],
            F::from_u64_value(self.total_proofs_generated),
        ]);
        public_inputs_without_reward_tag
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for AggStateTransitionWithStats<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32 * 2 + 8;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for AggStateTransitionWithStats<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32 * 2 + 8
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.state_transition_start.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.state_transition_end.into_owned_32bytes())?;
        writer.psy_write_u64(self.total_proofs_generated)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let state_transition_start_bytes = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let state_transition_end_bytes = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let total_proofs_generated = reader.psy_read_u64()?;
        Ok(Self {
            state_transition_start: state_transition_start_bytes,
            state_transition_end: state_transition_end_bytes,
            total_proofs_generated,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    AggStateTransitionWithStats,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for AggStateTransitionWithStats<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    AggStateTransitionWithStats,
    // Note the use of concrete types here
    { parth_core::PHash },
    agg_state_transition_with_stats_basic_ser_tests
);

#[pderive::serialize_copy_hash]
pub struct AggStateTransitionInputV2<Hash> {
    pub left_input: AggStateTransitionWithStats<Hash>,
    pub right_input: AggStateTransitionWithStats<Hash>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}
impl<Hash: Copy> WithDummyStateTransition<Hash> for AggStateTransitionInputV2<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            left_input: AggStateTransitionWithStats::<Hash>::get_dummy_value(state_root),
            right_input: AggStateTransitionWithStats::<Hash>::get_dummy_value(state_root),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}
impl<Hash: Copy> AggStateTrackableInput<Hash> for AggStateTransitionInputV2<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
        }
    }
}

impl<F: QFelt64, Hash: Copy + HashTo4Felts<F>> AggStateWitnessV2<F, Hash> for AggStateTransitionInputV2<Hash> {
    fn get_public_inputs_hash_no_tag_tree<H: FieldQHasher<F, Hash>>(&self, allowed_circuit_hashes_root: Hash) -> Hash {
        self.condense().get_public_inputs_hash_no_tag_tree::<H, F>(allowed_circuit_hashes_root)
    }
}
impl<Hash: Copy> AggStateTransitionInputV2<Hash> {
    pub fn condense(&self) -> AggStateTransitionWithStats<Hash> {
        AggStateTransitionWithStats {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
            total_proofs_generated: self.left_input.total_proofs_generated + self.right_input.total_proofs_generated,
        }
    }
    pub fn to_v1_input(&self) -> AggStateTransitionInput<Hash> {
        AggStateTransitionInput {
            left_input: AggStateTransition {
                state_transition_start: self.left_input.state_transition_start,
                state_transition_end: self.left_input.state_transition_end,
            },
            right_input: AggStateTransition {
                state_transition_start: self.right_input.state_transition_start,
                state_transition_end: self.right_input.state_transition_end,
            },
            left_proof_is_leaf: self.left_proof_is_leaf,
            right_proof_is_leaf: self.right_proof_is_leaf,
        }
    }
}

#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for AggStateTransitionInputV2<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_input: AggStateTransitionWithStats::<Hash>::qp_rand_gen(),
            right_input: AggStateTransitionWithStats::<Hash>::qp_rand_gen(),
            left_proof_is_leaf: rand::random(),
            right_proof_is_leaf: rand::random(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for AggStateTransitionInputV2<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = AggStateTransitionWithStats::<Hash>::FIXED_SIZE * 2 + 2;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for AggStateTransitionInputV2<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_input.pio_write_to_io(writer)?;
        self.right_input.pio_write_to_io(writer)?;
        writer.psy_write_u8(self.left_proof_is_leaf as u8)?;
        writer.psy_write_u8(self.right_proof_is_leaf as u8)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_input = AggStateTransitionWithStats::<Hash>::pio_read_from_io(reader)?;
        let right_input = AggStateTransitionWithStats::<Hash>::pio_read_from_io(reader)?;
        let left_proof_is_leaf = reader.psy_read_u8()? != 0;
        let right_proof_is_leaf = reader.psy_read_u8()? != 0;
        Ok(Self {
            left_input,
            right_input,
            left_proof_is_leaf,
            right_proof_is_leaf,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    AggStateTransitionInputV2,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for AggStateTransitionInputV2<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    AggStateTransitionInputV2,
    // Note the use of concrete types here
    { parth_core::PHash },
    agg_state_transition_input_v2_basic_ser_tests
);
