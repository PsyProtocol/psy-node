use parth_core::{crypto::hash::{spiderman::SpidermanUpdateProof, traits::{FieldQHasher, PCircuitWitness}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::agg::{AggStateTrackableInput, AggStateTransition, AggStateWitnessV2};






#[pderive::serialize_clone_hash]
pub struct QCAppendUserRegistrationTreeCircuitInput<Hash> {
    pub register_users_circuit_whitelist: Hash,
    pub spiderman_append_proofs: Vec<SpidermanUpdateProof<Hash>>,
}

impl<Hash: Copy> AggStateTrackableInput<Hash> for QCAppendUserRegistrationTreeCircuitInput<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.spiderman_append_proofs[0].top_line_proof.old_root,
            state_transition_end: self.spiderman_append_proofs[self.spiderman_append_proofs.len()-1].top_line_proof.new_root,
        }
    }
}





impl<Hash: QPGenRandom> QPGenRandom for QCAppendUserRegistrationTreeCircuitInput<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            register_users_circuit_whitelist: Hash::qp_rand_gen(),
            spiderman_append_proofs: SpidermanUpdateProof::qp_rand_gen_vec(rand::random::<u8>() as usize),
        }
    }
}


impl<F: QFelt64, Hash: QFHashBase<F>> PCircuitWitness<F, Hash>
    for QCAppendUserRegistrationTreeCircuitInput<Hash>
{
    fn get_expected_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let state_transition_hash = self.get_state_transition().get_combined_hash::<Hasher>();
        Hasher::two_to_one(
            &self.register_users_circuit_whitelist,
            &state_transition_hash,
        )
    }
}



impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QCAppendUserRegistrationTreeCircuitInput<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for QCAppendUserRegistrationTreeCircuitInput<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + 4 + self.spiderman_append_proofs.iter().map(|proof| proof.fallback_pio_serialized_size()).sum::<usize>()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.register_users_circuit_whitelist.into_owned_32bytes())?;
        writer.psy_write_vec_length(self.spiderman_append_proofs.len())?;
        for proof in &self.spiderman_append_proofs {
            proof.pio_write_to_io(writer)?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let whitelist_bytes = reader.psy_read_bytes_fixed::<32>()?;
        let register_users_circuit_whitelist = Hash::from_owned_32bytes(whitelist_bytes);
        let proofs_len = reader.psy_read_vec_length()? as usize;
        let mut spiderman_append_proofs = Vec::with_capacity(proofs_len);
        for _ in 0..proofs_len {
            let proof = SpidermanUpdateProof::pio_read_from_io(reader)?;
            spiderman_append_proofs.push(proof);
        }
        Ok(Self {
            register_users_circuit_whitelist,
            spiderman_append_proofs,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    QCAppendUserRegistrationTreeCircuitInput,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for QCAppendUserRegistrationTreeCircuitInput<Hash> {}


pser::impl_psy_ser_basic_tests!(
    QCAppendUserRegistrationTreeCircuitInput,
    // Note the use of concrete types here
    {  parth_core::PHash },
    qc_append_user_registration_tree_circuit_input_basic_ser_tests,
);
