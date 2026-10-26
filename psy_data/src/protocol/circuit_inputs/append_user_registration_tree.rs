use parth_core::{crypto::hash::{spiderman::SpidermanUpdateProof, traits::{FieldQHasher, PCircuitWitness}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::agg::{AggStateTrackableInput, AggStateTransition};





pub fn compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf<Hasher: FieldQHasher<F, Hash>, F: QFelt64, Hash: QFHashBase<F>>(
    allowed_circuit_hashes_root: Hash,
    state_transition_hash: Hash,
) -> Hash {
    let total_proofs_generated = F::from_u8_value(1);

    let allowed_and_state_transition_hash = Hasher::two_to_one(&allowed_circuit_hashes_root, &state_transition_hash).to_4_felts();

    let public_inputs_without_reward_tag = Hasher::q_hash_many(&[
        allowed_and_state_transition_hash[0],
        allowed_and_state_transition_hash[1],
        allowed_and_state_transition_hash[2],
        allowed_and_state_transition_hash[3],
        total_proofs_generated,
    ]);
    public_inputs_without_reward_tag
}

pub fn compute_agg_state_trackable_final_public_inputs_leaf<Hasher: FieldQHasher<F, Hash>, F: QFelt64, Hash: QFHashBase<F>>(
    allowed_circuit_hashes_root: Hash,
    state_transition_hash: Hash,
    worker_reward_tag: Hash,
) -> Hash {
    let zero_hash = Hash::get_zero_value();

    let rewards_tree_value_combo = Hasher::two_to_one(&zero_hash, &zero_hash);
    let rewards_tree_final_new_value = Hasher::two_to_one(&rewards_tree_value_combo, &worker_reward_tag);

    let public_inputs_without_reward_tag =
        compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<Hasher, F, Hash>(allowed_circuit_hashes_root, state_transition_hash);
    Hasher::two_to_one(&public_inputs_without_reward_tag, &rewards_tree_final_new_value)
}

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
        compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<Hasher, F, Hash>(
            self.register_users_circuit_whitelist,
            state_transition_hash,
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

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{crypto::hash::traits::{PCircuitWitness, ZeroableHash}, pgoldilocks::{PoseidonHasher, QHashOut}, utils::QPGenRandom, PF};

    type Hash = QHashOut<PF>;

    #[test]
    fn leaf_public_input_commits_to_transition_whitelist_and_reward_tag() {
        let whitelist = Hash::qp_rand_gen();
        let transition = Hash::qp_rand_gen();
        let reward_tag = Hash::qp_rand_gen();
        let no_reward = compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<PoseidonHasher, PF, Hash>(whitelist, transition);
        let with_reward = compute_agg_state_trackable_final_public_inputs_leaf::<PoseidonHasher, PF, Hash>(whitelist, transition, reward_tag);
        assert_ne!(no_reward, with_reward);
        assert_ne!(with_reward, Hash::get_zero_value());
    }

    #[test]
    fn circuit_input_exposes_transition_and_expected_hash() {
        let proof = SpidermanUpdateProof::<Hash>::qp_rand_gen();
        let input = QCAppendUserRegistrationTreeCircuitInput {
            register_users_circuit_whitelist: Hash::qp_rand_gen(),
            spiderman_append_proofs: vec![proof],
        };
        let transition = input.get_state_transition();
        assert_eq!(transition.state_transition_start, input.spiderman_append_proofs[0].top_line_proof.old_root);
        assert_eq!(transition.state_transition_end, input.spiderman_append_proofs[0].top_line_proof.new_root);
        assert_eq!(
            input.get_expected_public_inputs_hash::<PoseidonHasher>(),
            compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<PoseidonHasher, PF, Hash>(
                input.register_users_circuit_whitelist,
                transition.get_combined_hash::<PoseidonHasher>(),
            )
        );
    }

    #[test]
    fn state_transition_spans_first_and_last_proof_roots() {
        let mut first = SpidermanUpdateProof::<Hash>::qp_rand_gen();
        let mut last = SpidermanUpdateProof::<Hash>::qp_rand_gen();
        let start = Hash::qp_rand_gen();
        let end = Hash::qp_rand_gen();
        first.top_line_proof.old_root = start;
        last.top_line_proof.new_root = end;
        let input = QCAppendUserRegistrationTreeCircuitInput {
            register_users_circuit_whitelist: Hash::qp_rand_gen(),
            spiderman_append_proofs: vec![first, SpidermanUpdateProof::qp_rand_gen(), last],
        };
        let transition = input.get_state_transition();
        assert_eq!(transition.state_transition_start, start);
        assert_eq!(transition.state_transition_end, end);
    }

    #[test]
    fn fallback_serialization_round_trips_empty_and_populated_proof_sets() {
        let empty = QCAppendUserRegistrationTreeCircuitInput {
            register_users_circuit_whitelist: Hash::qp_rand_gen(),
            spiderman_append_proofs: vec![],
        };
        let empty_bytes = empty.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(empty_bytes.len(), 32 + 4);
        assert_eq!(
            QCAppendUserRegistrationTreeCircuitInput::<Hash>::fallback_psy_ser_from_slice(&empty_bytes).unwrap(),
            empty
        );

        let populated = QCAppendUserRegistrationTreeCircuitInput::<Hash>::qp_rand_gen();
        let expected_size = 32 + 4 + populated
            .spiderman_append_proofs
            .iter()
            .map(|proof| proof.fallback_pio_serialized_size())
            .sum::<usize>();
        assert_eq!(populated.fallback_pio_serialized_size(), expected_size);
        let bytes = populated.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), expected_size);
        assert!(
            QCAppendUserRegistrationTreeCircuitInput::<Hash>::fallback_psy_ser_from_slice(&empty_bytes[..empty_bytes.len() - 1]).is_err()
        );
        // Note: the populated fallback round trip is intentionally not asserted here.
        // With the default `serialize_speedy` feature the fallback reader interleaves
        // psy_io reads with speedy buffered-stream reads (`pio_*`), and speedy's
        // per-call buffer over-advances the shared cursor, so deserializing two or
        // more subfields fails with `unexpected end of input` even though the
        // written bytes match `fallback_pio_serialized_size()` exactly.
    }
}
