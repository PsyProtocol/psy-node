use parth_core::{crypto::hash::traits::{FieldQHasher, PCircuitWitness}, protocol::core_types::Q256BitHash};
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};


#[pderive::serialize_copy_hash]
pub struct DummyAggStateTransition<Hash> {
    pub unmodified_state_tree_root: Hash,
    pub allowed_circuit_hashes_root: Hash,
    pub is_deploy_contracts: bool,
    pub is_register_users: bool,
}

#[pderive::serialize_copy_hash]
pub struct DummyAggStateTransitionWithEvents<Hash> {
    pub unmodified_state_tree_root: Hash,
    pub event_transition_hash: Hash,
    pub allowed_circuit_hashes_root: Hash,
}



#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for DummyAggStateTransition<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            unmodified_state_tree_root: Hash::qp_rand_gen(),
            allowed_circuit_hashes_root: Hash::qp_rand_gen(),
            is_deploy_contracts: rand::random(),
            is_register_users: rand::random(),
        }
    }
}



impl<F, Hash> PCircuitWitness<F, Hash> for DummyAggStateTransition<Hash> {
    fn get_expected_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        Hasher::two_to_one(
            &self.allowed_circuit_hashes_root,
            &self.unmodified_state_tree_root,
        )
    }
}



impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for DummyAggStateTransition<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32*2 + 2;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for DummyAggStateTransition<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32*2 + 2

    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.unmodified_state_tree_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.allowed_circuit_hashes_root.into_owned_32bytes())?;
        writer.psy_write_u8(self.is_deploy_contracts as u8)?;
        writer.psy_write_u8(self.is_register_users as u8)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let unmodified_state_tree_root_bytes = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let allowed_circuit_hashes_root_bytes = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let is_deploy_contracts = reader.psy_read_u8()? != 0;
        let is_register_users = reader.psy_read_u8()? != 0;
        Ok(Self {
            unmodified_state_tree_root: unmodified_state_tree_root_bytes,
            allowed_circuit_hashes_root: allowed_circuit_hashes_root_bytes,
            is_deploy_contracts,
            is_register_users,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    DummyAggStateTransition,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for DummyAggStateTransition<Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    DummyAggStateTransition,
    // Note the use of concrete types here
    {  parth_core::PHash },
    dummy_agg_state_transition_basic_ser_tests
);
