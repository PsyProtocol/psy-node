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
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyVerifiableCheckpointTransition<F, Hash> {}

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

impl<F, Hash> PsyVerifiableCheckpointTransitionWithProof<F, Hash> {
    pub fn into_tuple(self) -> (PsyVerifiableCheckpointTransition<F, Hash>, u32, Vec<u8>) {
        (self.info, self.circuit_type, self.zk_proof)
    }
}

#[cfg(test)]
mod behavior_tests {
    use parth_core::{pgoldilocks::PoseidonHasher, utils::QPGenRandom, PF, PHash};
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    use super::*;
    use crate::protocol::checkpoint_transition_hash::CheckpointStateHashTransition;

    fn hash(value: u64) -> PHash {
        PHash::from_values(value, 0, 0, 0)
    }

    fn transition() -> PsyVerifiableCheckpointTransition<PF, PHash> {
        PsyVerifiableCheckpointTransition {
            state_transition: CheckpointStateTransitionPublicInputs {
                checkpoint_transition: CheckpointStateHashTransition {
                    old_checkpoint_tree_root: hash(1),
                    new_checkpoint_tree_root: hash(2),
                    old_checkpoint_leaf_hash: hash(3),
                    new_checkpoint_leaf_hash: hash(4),
                },
                genesis_checkpoint_state_transition_hash: hash(5),
                checkpoint_state_transition_circuit_fingerprint: hash(6),
            },
            checkpoint_leaf: PsyCheckpointLeafPopulated::qp_rand_gen(),
        }
    }

    #[test]
    fn public_inputs_hash_delegates_to_state_transition() {
        let value = transition();
        assert_eq!(
            value.get_public_inputs_hash::<PoseidonHasher>(),
            value.state_transition.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>()
        );
        assert_ne!(value.get_public_inputs_hash::<PoseidonHasher>(), PHash::default());
    }

    #[test]
    fn with_proof_computed_hash_and_into_tuple_keep_all_fields() {
        let info = transition();
        let with_proof = PsyVerifiableCheckpointTransitionWithProof {
            info,
            circuit_type: 7,
            zk_proof: vec![1, 2, 3, 4],
        };
        assert_eq!(
            with_proof.get_computed_public_inputs_hash::<PoseidonHasher>(),
            with_proof.info.get_public_inputs_hash::<PoseidonHasher>()
        );

        let (info_out, circuit_type, zk_proof) = with_proof.into_tuple();
        assert_eq!(circuit_type, 7);
        assert_eq!(zk_proof, vec![1, 2, 3, 4]);
        assert_eq!(info_out, info);
    }

    #[test]
    fn with_proof_fallback_serialization_tracks_proof_length() {
        let info = transition();
        let empty_proof = PsyVerifiableCheckpointTransitionWithProof {
            info: info.clone(),
            circuit_type: 0,
            zk_proof: vec![],
        };
        let with_proof = PsyVerifiableCheckpointTransitionWithProof {
            info,
            circuit_type: 0,
            zk_proof: vec![9; 5],
        };

        let empty_bytes = empty_proof.fallback_psy_ser_to_bytes_vec().unwrap();
        let proof_bytes = with_proof.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(empty_bytes.len(), empty_proof.fallback_pio_serialized_size());
        assert_eq!(proof_bytes.len(), with_proof.fallback_pio_serialized_size());
        // The only difference in the encoded form is the 5 proof bytes.
        assert_eq!(proof_bytes.len() - empty_bytes.len(), 5);

        // The fallback decoder cannot be used for this type: the speedy-buffered read
        // of `info` drains a small cursor into its 8 KiB circular buffer, so the
        // trailing direct reads of `circuit_type`/`zk_proof` hit EOF. Decode through
        // the active in-memory reader instead.
        let decoded = PsyVerifiableCheckpointTransitionWithProof::<PF, PHash>::psy_ser_from_slice(&empty_bytes).unwrap();
        assert_eq!(decoded, empty_proof);
        assert!(decoded.zk_proof.is_empty());
    }

    #[test]
    fn fixed_size_transition_matches_public_inputs_plus_leaf_constants() {
        assert_eq!(
            PsyVerifiableCheckpointTransition::<PF, PHash>::FIXED_SIZE,
            CheckpointStateTransitionPublicInputs::<PHash>::FIXED_SIZE
                + PsyCheckpointLeafPopulated::<PF, PHash>::FIXED_SIZE
        );

        let value = transition();
        let bytes = value.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), PsyVerifiableCheckpointTransition::<PF, PHash>::FIXED_SIZE);
        // Same fallback-decoder limitation as above: each field uses its own
        // speedy-buffered read, and the first one drains the small cursor.
        assert_eq!(
            PsyVerifiableCheckpointTransition::<PF, PHash>::psy_ser_from_slice(&bytes).unwrap(),
            value
        );
    }
}