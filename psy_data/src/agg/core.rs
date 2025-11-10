use parth_core::crypto::hash::traits::{FieldQHasher, MerkleHasher, PCircuitWitness, ZeroableHash};
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
use parth_core::protocol::core_types::Q256BitHash;
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};


pub trait WithDummyStateTransition<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self;
}
pub trait StateTransitionTrackable<Hash> {
    fn get_start_root(&self) -> Hash;
    fn get_end_root(&self) -> Hash;
}
pub trait StateTransitionTrackableWithEvents<Hash>: StateTransitionTrackable<Hash> {
    fn get_events_hash(&self) -> Hash;
}
pub trait AggStateTrackableInput<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash>;
}

#[pderive::serialize_copy_hash]
pub struct AggStateTransition<Hash> {
    pub state_transition_start: Hash,
    pub state_transition_end: Hash,
}



#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for AggStateTransition<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            state_transition_start: Hash::qp_rand_gen(),
            state_transition_end: Hash::qp_rand_gen(),
        }
    }
}




impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for AggStateTransition<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32*2;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for AggStateTransition<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32*2

    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.state_transition_start.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.state_transition_end.into_owned_32bytes())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let state_transition_start_bytes = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let state_transition_end_bytes = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        Ok(Self {
            state_transition_start: state_transition_start_bytes,
            state_transition_end: state_transition_end_bytes,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    AggStateTransition,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for AggStateTransition<Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    AggStateTransition,
    // Note the use of concrete types here
    {  parth_core::PHash },
    agg_state_transition_basic_ser_tests
);




impl<Hash> AggStateTransition<Hash> {
    pub fn new(state_transition_start: Hash, state_transition_end: Hash) -> Self {
        Self {
            state_transition_start,
            state_transition_end,
        }
    }
    pub fn get_combined_hash<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        Hasher::two_to_one(&self.state_transition_start, &self.state_transition_end)
    }
}
impl<Hash: Default> Default for AggStateTransition<Hash> {
    fn default() -> Self {
        Self {
            state_transition_start: Default::default(),
            state_transition_end: Default::default(),
        }
    }
}
impl<Hash: Copy> AggStateTrackableInput<Hash> for AggStateTransition<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        *self
    }
}
impl<Hash, T: AggStateTrackableInput<Hash>> StateTransitionTrackable<Hash> for T {
    fn get_start_root(&self) -> Hash {
        self.get_state_transition().state_transition_start
    }

    fn get_end_root(&self) -> Hash {
        self.get_state_transition().state_transition_end
    }
}

impl<Hash: Copy> WithDummyStateTransition<Hash> for AggStateTransition<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            state_transition_start: state_root,
            state_transition_end: state_root,
        }
    }
}

#[pderive::serialize_copy_hash]
pub struct AggStateTransitionInput<Hash> {
    pub left_input: AggStateTransition<Hash>,
    pub right_input: AggStateTransition<Hash>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}
impl<Hash: Copy> WithDummyStateTransition<Hash> for AggStateTransitionInput<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            left_input: AggStateTransition::<Hash>::get_dummy_value(state_root),
            right_input: AggStateTransition::<Hash>::get_dummy_value(state_root),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}
impl<Hash: Copy> AggStateTrackableInput<Hash> for AggStateTransitionInput<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        self.condense()
    }
}
impl<Hash: Copy> AggStateTransitionInput<Hash> {
    pub fn condense(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
        }
    }
    pub fn combine_with_right_leaf<T: AggStateTrackableInput<Hash>>(&self, right: &T) -> Self {
        Self {
            left_input: self.condense(),
            right_input: right.get_state_transition(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }
    pub fn combine_with_left_leaf<T: AggStateTrackableInput<Hash>>(&self, left: &T) -> Self {
        Self {
            left_input: left.get_state_transition(),
            right_input: self.condense(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }
}

#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for AggStateTransitionInput<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            left_input: AggStateTransition::<Hash>::qp_rand_gen(),
            right_input: AggStateTransition::<Hash>::qp_rand_gen(),
            left_proof_is_leaf: rand::random(),
            right_proof_is_leaf: rand::random(),
        }
    }
}

impl<F, Hash> PCircuitWitness<F, Hash> for AggStateTransitionInput<Hash> {
    fn get_expected_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let left_hash = self.left_input.get_combined_hash::<Hasher>();
        let right_hash = self.right_input.get_combined_hash::<Hasher>();

        Hasher::two_to_one(
            &left_hash,
            &right_hash,
        )
    }
}



impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for AggStateTransitionInput<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = AggStateTransition::<Hash>::FIXED_SIZE * 2 + 2;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for AggStateTransitionInput<Hash> {
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
        let left_input = AggStateTransition::<Hash>::pio_read_from_io(reader)?;
        let right_input = AggStateTransition::<Hash>::pio_read_from_io(reader)?;
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
    AggStateTransitionInput,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for AggStateTransitionInput<Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    AggStateTransitionInput,
    // Note the use of concrete types here
    {  parth_core::PHash },
    agg_state_transition_input_basic_ser_tests
);


pub trait AggStateTrackableWithEventsInput<Hash> {
    fn get_state_transition_with_events<Hasher: MerkleHasher<Hash>>(&self) -> AggStateTransitionWithEvents<Hash>;
}


#[pderive::serialize_copy_hash]
pub struct AggStateTransitionWithEvents<Hash> {
    pub state_transition_start: Hash,
    pub state_transition_end: Hash,
    pub event_hash: Hash,
}
impl<Hash: Default> Default for AggStateTransitionWithEvents<Hash> {
    fn default() -> Self {
        Self {
            state_transition_start: Default::default(),
            state_transition_end: Default::default(),
            event_hash: Default::default(),
        }
    }
}
impl<Hash: Copy> AggStateTrackableInput<Hash> for AggStateTransitionWithEvents<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.state_transition_start,
            state_transition_end: self.state_transition_end,
        }
    }
}
impl<Hash: Copy + ZeroableHash> WithDummyStateTransition<Hash> for AggStateTransitionWithEvents<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            state_transition_start: state_root,
            state_transition_end: state_root,
            event_hash: Hash::get_zero_value(),
        }
    }
}


#[pderive::serialize_copy_hash]
pub struct AggStateTransitionWithEventsInput<Hash> {
    pub left_input: AggStateTransitionWithEvents<Hash>,
    pub right_input: AggStateTransitionWithEvents<Hash>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}

impl<Hash: Copy + ZeroableHash> AggStateTrackableWithEventsInput<Hash> for AggStateTransitionWithEventsInput<Hash> {
    fn get_state_transition_with_events<Hasher: MerkleHasher<Hash>>(&self) -> AggStateTransitionWithEvents<Hash> {
        self.condense::<Hasher>()
    }
}
impl<Hash: ZeroableHash, T: AggStateTrackableInput<Hash>> StateTransitionTrackableWithEvents<Hash> for T {
    fn get_events_hash(&self) -> Hash {
        Hash::get_zero_value()
    }
}
impl<Hash: Copy + ZeroableHash> WithDummyStateTransition<Hash> for AggStateTransitionWithEventsInput<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            left_input: AggStateTransitionWithEvents::<Hash>::get_dummy_value(state_root),
            right_input: AggStateTransitionWithEvents::<Hash>::get_dummy_value(state_root),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}
impl<Hash: Copy + ZeroableHash> AggStateTransitionWithEventsInput<Hash> {
    pub fn condense<Hasher: MerkleHasher<Hash>>(&self) -> AggStateTransitionWithEvents<Hash> {
        AggStateTransitionWithEvents {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
            event_hash: Hasher::two_to_one(&self.left_input.event_hash, &self.right_input.event_hash),
        }
    }
    pub fn combine_with_right_leaf<Hasher: MerkleHasher<Hash>, T: AggStateTrackableWithEventsInput<Hash>>(
        &self,
        right: &T,
    ) -> Self {
        Self {
            left_input: self.condense::<Hasher>(),
            right_input: right.get_state_transition_with_events::<Hasher>(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }
    pub fn combine_with_left_leaf<Hasher: MerkleHasher<Hash>, T: AggStateTrackableWithEventsInput<Hash>>(&self, left: &T) -> Self {
        Self {
            left_input: left.get_state_transition_with_events::<Hasher>(),
            right_input: self.condense::<Hasher>(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }
}