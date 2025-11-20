use parth_core::{crypto::hash::traits::{FieldQHasher, MerkleHasher, QFieldHashable}, protocol::core_types::Q256BitHash};
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};


#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]

pub struct PsyCheckpointStateTransitionGenesisCircuitInput<Hash> {
    pub genesis_checkpoint_state_transition_hash: Hash,
    pub checkpoint_state_transition_circuit_fingerprint: Hash,
}


impl<Hash> PsyCheckpointStateTransitionGenesisCircuitInput<Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: MerkleHasher<Hash>>(
        &self, 
    ) -> Hash {        
        /*
        public inputs are:
        hash(genesis_checkpoint_state_transition_hash, hash(genesis_checkpoint_state_transition_hash, checkpoint_state_transition_circuit_fingerprint))
        */
        let config_hash = Hasher::two_to_one(&self.genesis_checkpoint_state_transition_hash, &self.checkpoint_state_transition_circuit_fingerprint);
        Hasher::two_to_one(&self.genesis_checkpoint_state_transition_hash, &config_hash)
    }
}
impl<Hash: Copy, F> QFieldHashable<F, Hash> for PsyCheckpointStateTransitionGenesisCircuitInput<Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.get_public_inputs_hash_no_rewards_tag::<H>()
    }
}
#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for PsyCheckpointStateTransitionGenesisCircuitInput<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            genesis_checkpoint_state_transition_hash: Hash::qp_rand_gen(),
            checkpoint_state_transition_circuit_fingerprint: Hash::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyCheckpointStateTransitionGenesisCircuitInput<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32*2;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyCheckpointStateTransitionGenesisCircuitInput<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.genesis_checkpoint_state_transition_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.checkpoint_state_transition_circuit_fingerprint.into_owned_32bytes())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let genesis_checkpoint_state_transition_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let checkpoint_state_transition_circuit_fingerprint = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        Ok(Self {
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyCheckpointStateTransitionGenesisCircuitInput,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyCheckpointStateTransitionGenesisCircuitInput<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyCheckpointStateTransitionGenesisCircuitInput,
    { parth_core::PHash },
    psy_checkpoint_state_transition_genesis_circuit_input_tests
);