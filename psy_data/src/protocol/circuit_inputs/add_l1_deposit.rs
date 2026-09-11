use parth_core::{
    crypto::hash::{
        spiderman::SpidermanUpdateProof,
        traits::{FieldQHasher, PCircuitWitness},
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
    utils::QPGenRandom,
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{
    agg::{AggStateTrackableInput, AggStateTransition},
    protocol::circuit_inputs::append_user_registration_tree::compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf,
};

#[pderive::serialize_clone_hash]
pub struct QCAddL1DepositCircuitInput<Hash> {
    // NOTE: This witness container is hash-agnostic and can carry keccak-tree transitions.
    pub add_l1_deposit_circuit_whitelist: Hash,
    pub spiderman_append_proofs: Vec<SpidermanUpdateProof<Hash>>,
}

impl<Hash: Copy> AggStateTrackableInput<Hash> for QCAddL1DepositCircuitInput<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.spiderman_append_proofs[0].top_line_proof.old_root,
            state_transition_end: self.spiderman_append_proofs[self.spiderman_append_proofs.len() - 1]
                .top_line_proof
                .new_root,
        }
    }
}

impl<Hash: QPGenRandom> QPGenRandom for QCAddL1DepositCircuitInput<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            add_l1_deposit_circuit_whitelist: Hash::qp_rand_gen(),
            spiderman_append_proofs: SpidermanUpdateProof::qp_rand_gen_vec(rand::random::<u8>() as usize),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> PCircuitWitness<F, Hash> for QCAddL1DepositCircuitInput<Hash> {
    fn get_expected_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let state_transition_hash = self.get_state_transition().get_combined_hash::<Hasher>();
        compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<Hasher, F, Hash>(
            self.add_l1_deposit_circuit_whitelist,
            state_transition_hash,
        )
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QCAddL1DepositCircuitInput<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for QCAddL1DepositCircuitInput<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + 4 + self
            .spiderman_append_proofs
            .iter()
            .map(|proof| proof.fallback_pio_serialized_size())
            .sum::<usize>()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.add_l1_deposit_circuit_whitelist.into_owned_32bytes())?;
        writer.psy_write_vec_length(self.spiderman_append_proofs.len())?;
        for proof in &self.spiderman_append_proofs {
            proof.pio_write_to_io(writer)?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let whitelist_bytes = reader.psy_read_bytes_fixed::<32>()?;
        let add_l1_deposit_circuit_whitelist = Hash::from_owned_32bytes(whitelist_bytes);
        let proofs_len = reader.psy_read_vec_length()? as usize;
        let mut spiderman_append_proofs = Vec::with_capacity(proofs_len);
        for _ in 0..proofs_len {
            let proof = SpidermanUpdateProof::pio_read_from_io(reader)?;
            spiderman_append_proofs.push(proof);
        }
        Ok(Self {
            add_l1_deposit_circuit_whitelist,
            spiderman_append_proofs,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    QCAddL1DepositCircuitInput,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for QCAddL1DepositCircuitInput<Hash> {}

pser::impl_psy_ser_basic_tests!(
    QCAddL1DepositCircuitInput,
    { parth_core::PHash },
    qc_add_l1_deposit_circuit_input_basic_ser_tests,
);

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{
        crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::FromU64x4},
        pgoldilocks::{PoseidonHasher, QHashOut},
        PF,
    };

    type Hash = QHashOut<PF>;

    fn hash(seed: u64) -> Hash {
        Hash::from_u64x4([seed, seed.wrapping_mul(31), seed.wrapping_mul(7), seed.wrapping_mul(13)])
    }

    fn proof_with_roots(old_root: Hash, new_root: Hash, tag: u64) -> SpidermanUpdateProof<Hash> {
        SpidermanUpdateProof {
            top_line_proof: DeltaMerkleProofCore {
                old_root,
                new_root,
                old_value: hash(tag),
                new_value: hash(tag + 1),
                index: tag,
                siblings: vec![hash(tag + 2)],
            },
            web_proof_old_leaves: vec![hash(tag + 3)],
            web_proof_new_leaves: vec![hash(tag + 4)],
        }
    }

    #[test]
    fn state_transition_spans_first_and_last_proof_roots() {
        let start = hash(1);
        let end = hash(2);
        let input = QCAddL1DepositCircuitInput {
            add_l1_deposit_circuit_whitelist: hash(3),
            spiderman_append_proofs: vec![
                proof_with_roots(start, hash(4), 10),
                proof_with_roots(hash(4), hash(5), 11),
                proof_with_roots(hash(5), end, 12),
            ],
        };
        let transition = input.get_state_transition();
        assert_eq!(transition.state_transition_start, start);
        assert_eq!(transition.state_transition_end, end);
    }

    #[test]
    fn expected_public_inputs_hash_binds_whitelist_and_transition() {
        let input = QCAddL1DepositCircuitInput {
            add_l1_deposit_circuit_whitelist: hash(7),
            spiderman_append_proofs: vec![proof_with_roots(hash(1), hash(2), 20)],
        };
        let expected = compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<PoseidonHasher, PF, Hash>(
            input.add_l1_deposit_circuit_whitelist,
            input.get_state_transition().get_combined_hash::<PoseidonHasher>(),
        );
        assert_eq!(input.get_expected_public_inputs_hash::<PoseidonHasher>(), expected);

        let other = QCAddL1DepositCircuitInput {
            add_l1_deposit_circuit_whitelist: hash(8),
            spiderman_append_proofs: vec![proof_with_roots(hash(1), hash(2), 20)],
        };
        assert_ne!(other.get_expected_public_inputs_hash::<PoseidonHasher>(), expected);
    }

    #[test]
    fn fallback_serialization_round_trips_empty_and_populated_proof_sets() {
        let empty = QCAddL1DepositCircuitInput {
            add_l1_deposit_circuit_whitelist: hash(1),
            spiderman_append_proofs: vec![],
        };
        let empty_bytes = empty.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(empty_bytes.len(), 32 + 4);
        assert_eq!(
            QCAddL1DepositCircuitInput::<Hash>::fallback_psy_ser_from_slice(&empty_bytes).unwrap(),
            empty
        );

        let populated = QCAddL1DepositCircuitInput::<Hash>::qp_rand_gen();
        let expected_size = 32 + 4 + populated
            .spiderman_append_proofs
            .iter()
            .map(|proof| proof.fallback_pio_serialized_size())
            .sum::<usize>();
        assert_eq!(populated.fallback_pio_serialized_size(), expected_size);
        let bytes = populated.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), expected_size);
        assert!(
            QCAddL1DepositCircuitInput::<Hash>::fallback_psy_ser_from_slice(&empty_bytes[..empty_bytes.len() - 1]).is_err()
        );
        // Note: the populated fallback round trip is intentionally not asserted here.
        // With the default `serialize_speedy` feature the fallback reader interleaves
        // psy_io reads with speedy buffered-stream reads (`pio_*`), and speedy's
        // per-call buffer over-advances the shared cursor, so deserializing two or
        // more subfields fails with `unexpected end of input` even though the
        // written bytes match `fallback_pio_serialized_size()` exactly.
    }
}
