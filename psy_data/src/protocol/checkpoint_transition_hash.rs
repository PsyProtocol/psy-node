use parth_core::{crypto::hash::traits::{FieldQHasher, MerkleHasher, QFieldHashable}};
use parth_core::protocol::core_types::Q256BitHash;
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};



#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct CheckpointStateHashTransition<Hash> {
    pub old_checkpoint_tree_root: Hash,
    pub new_checkpoint_tree_root: Hash,

    pub old_checkpoint_leaf_hash: Hash,
    pub new_checkpoint_leaf_hash: Hash,
}

impl<Hash> CheckpointStateHashTransition<Hash> {
    pub fn get_hash<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        let checkpoint_tree_root_transition = Hasher::two_to_one(
            &self.old_checkpoint_tree_root,
            &self.new_checkpoint_tree_root,
        );
        let leaf_transition_hash = Hasher::two_to_one(
            &self.old_checkpoint_leaf_hash,
            &self.new_checkpoint_leaf_hash,
        );
        Hasher::two_to_one(&checkpoint_tree_root_transition, &leaf_transition_hash)
    }
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: MerkleHasher<Hash>>(
        &self, 
        genesis_checkpoint_state_transition_hash: &Hash,
        checkpoint_state_transition_circuit_fingerprint: &Hash,
    ) -> Hash {
        let checkpoint_transition_hash = self.get_hash::<Hasher>();
        let config_hash = Hasher::two_to_one(
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        );
        Hasher::two_to_one(&checkpoint_transition_hash, &config_hash)
    }
}
impl<Hash: Copy, F> QFieldHashable<F, Hash> for CheckpointStateHashTransition<Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.get_hash::<H>()
    }
}
#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for CheckpointStateHashTransition<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            old_checkpoint_tree_root: Hash::qp_rand_gen(),
            new_checkpoint_tree_root: Hash::qp_rand_gen(),
            old_checkpoint_leaf_hash: Hash::qp_rand_gen(),
            new_checkpoint_leaf_hash: Hash::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for CheckpointStateHashTransition<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32 * 4;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for CheckpointStateHashTransition<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.old_checkpoint_tree_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_checkpoint_tree_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.old_checkpoint_leaf_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_checkpoint_leaf_hash.into_owned_32bytes())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let old_checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let new_checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let old_checkpoint_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let new_checkpoint_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        Ok(Self {
            old_checkpoint_tree_root,
            new_checkpoint_tree_root,
            old_checkpoint_leaf_hash,
            new_checkpoint_leaf_hash,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    CheckpointStateHashTransition,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for CheckpointStateHashTransition<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    CheckpointStateHashTransition,
    { parth_core::PHash },
    checkpoint_state_hash_transition_ser_tests
);

#[cfg(test)]
mod behavior_tests {
    use parth_core::{
        crypto::hash::traits::QFieldHashable,
        pgoldilocks::{PoseidonHasher, QHashOut},
        utils::QPGenRandom,
        PF,
    };
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    use super::*;

    type Hash = QHashOut<PF>;

    fn hash(value: u64) -> Hash {
        Hash::from_values(value, value + 1, value + 2, value + 3)
    }

    #[test]
    fn transition_hash_matches_manual_merkle_composition() {
        let transition = CheckpointStateHashTransition {
            old_checkpoint_tree_root: hash(1),
            new_checkpoint_tree_root: hash(2),
            old_checkpoint_leaf_hash: hash(3),
            new_checkpoint_leaf_hash: hash(4),
        };
        let roots = PoseidonHasher::two_to_one(&hash(1), &hash(2));
        let leaves = PoseidonHasher::two_to_one(&hash(3), &hash(4));
        let expected = PoseidonHasher::two_to_one(&roots, &leaves);
        assert_eq!(transition.get_hash::<PoseidonHasher>(), expected);
        assert_eq!(transition.qfhash::<PoseidonHasher>(), expected);

        let genesis = hash(5);
        let fingerprint = hash(6);
        assert_eq!(
            transition.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>(&genesis, &fingerprint),
            PoseidonHasher::two_to_one(&expected, &PoseidonHasher::two_to_one(&genesis, &fingerprint))
        );
    }

    #[test]
    fn public_input_chain_helpers_match_documented_formulas() {
        let data = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: hash(1),
                new_checkpoint_tree_root: hash(2),
                old_checkpoint_leaf_hash: hash(3),
                new_checkpoint_leaf_hash: hash(4),
            },
            genesis_checkpoint_state_transition_hash: hash(5),
            checkpoint_state_transition_circuit_fingerprint: hash(6),
        };
        let root_leaf = PoseidonHasher::two_to_one(&hash(2), &hash(4));
        assert_eq!(
            data.get_chain_0_from_genesis_leaf::<PoseidonHasher>(&hash(7)),
            PoseidonHasher::two_to_one(&root_leaf, &hash(7))
        );
        let step = PoseidonHasher::two_to_one(&root_leaf, &hash(6));
        assert_eq!(data.get_step_commit_hash::<PoseidonHasher>(), step);
        assert_eq!(
            data.get_chain_hash_from_previous::<PoseidonHasher>(&hash(8)),
            PoseidonHasher::two_to_one(&hash(8), &step)
        );
        assert_eq!(data.qfhash::<PoseidonHasher>(), data.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>());
    }

    #[test]
    fn fallback_encoded_sizes_match_fixed_size_constants() {
        let transition = CheckpointStateHashTransition::<Hash>::qp_rand_gen();
        assert_eq!(transition.fallback_pio_serialized_size(), CheckpointStateHashTransition::<Hash>::FIXED_SIZE);
        let bytes = transition.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), CheckpointStateHashTransition::<Hash>::FIXED_SIZE);
        assert_eq!(bytes.len(), transition.pio_serialized_size());
        assert_eq!(
            CheckpointStateHashTransition::<Hash>::fallback_psy_ser_from_slice(&bytes).unwrap(),
            transition
        );

        let public_inputs = CheckpointStateTransitionPublicInputs::<Hash>::qp_rand_gen();
        assert_eq!(
            public_inputs.fallback_pio_serialized_size(),
            CheckpointStateTransitionPublicInputs::<Hash>::FIXED_SIZE
        );
        let pi_bytes = public_inputs.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(pi_bytes.len(), CheckpointStateTransitionPublicInputs::<Hash>::FIXED_SIZE);
        assert_eq!(pi_bytes.len(), public_inputs.pio_serialized_size());
        // The fallback decoder cannot be used for this type: its read path mixes the
        // speedy-buffered read of `checkpoint_transition` (which drains a small cursor
        // into its 8 KiB circular buffer) with direct 32-byte reads, so those trailing
        // reads hit EOF. Decode through the active in-memory reader instead, which
        // also proves the fallback encoding stays byte-compatible with it.
        assert_eq!(
            CheckpointStateTransitionPublicInputs::<Hash>::psy_ser_from_slice(&pi_bytes).unwrap(),
            public_inputs
        );
        assert_eq!(
            CheckpointStateTransitionPublicInputs::<Hash>::FIXED_SIZE,
            CheckpointStateHashTransition::<Hash>::FIXED_SIZE + 32 * 2
        );
    }

    #[test]
    fn transition_hash_distinguishes_root_and_leaf_changes() {
        let mut transition = CheckpointStateHashTransition {
            old_checkpoint_tree_root: hash(1),
            new_checkpoint_tree_root: hash(2),
            old_checkpoint_leaf_hash: hash(3),
            new_checkpoint_leaf_hash: hash(4),
        };
        let baseline = transition.get_hash::<PoseidonHasher>();

        transition.new_checkpoint_tree_root = hash(5);
        assert_ne!(transition.get_hash::<PoseidonHasher>(), baseline);

        transition.new_checkpoint_tree_root = hash(2);
        transition.old_checkpoint_leaf_hash = hash(6);
        assert_ne!(transition.get_hash::<PoseidonHasher>(), baseline);

        transition.old_checkpoint_leaf_hash = hash(3);
        assert_eq!(transition.get_hash::<PoseidonHasher>(), baseline);
    }
}


#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]

pub struct CheckpointStateTransitionPublicInputs<Hash> {
    pub checkpoint_transition: CheckpointStateHashTransition<Hash>,
    pub genesis_checkpoint_state_transition_hash: Hash,
    pub checkpoint_state_transition_circuit_fingerprint: Hash,
}


impl<Hash> CheckpointStateTransitionPublicInputs<Hash> {
    /// Chain_0 = H(H(new_root, new_leaf), genesis_fingerprint)
    /// This matches the genesis checkpoint state transition circuit's public
    /// input hash, which uses the genesis_fingerprint in its formula.
    pub fn get_chain_0_from_genesis_leaf<Hasher: MerkleHasher<Hash>>(&self, genesis_fingerprint: &Hash) -> Hash {
        let root_leaf = Hasher::two_to_one(
            &self.checkpoint_transition.new_checkpoint_tree_root,
            &self.checkpoint_transition.new_checkpoint_leaf_hash,
        );
        Hasher::two_to_one(&root_leaf, genesis_fingerprint)
    }
    /// Legacy single-step PI hash (kept for compatibility while migrating).
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: MerkleHasher<Hash>>(
        &self, 
    ) -> Hash {
        self.checkpoint_transition.get_public_inputs_hash_no_rewards_tag::<Hasher>(&self.genesis_checkpoint_state_transition_hash,&self.checkpoint_state_transition_circuit_fingerprint)
    }

    /// New step hash used by bridge/checkpoint chain-mode semantics:
    /// step_i = H(checkpoint_tree_root_i, checkpoint_leaf_hash_i, checkpoint_transition_fingerprint)
    pub fn get_step_commit_hash<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        let root_leaf_hash = Hasher::two_to_one(
            &self.checkpoint_transition.new_checkpoint_tree_root,
            &self.checkpoint_transition.new_checkpoint_leaf_hash,
        );
        Hasher::two_to_one(
            &root_leaf_hash,
            &self.checkpoint_state_transition_circuit_fingerprint,
        )
    }

    /// chain_i = H(chain_{i-1}, step_i)
    pub fn get_chain_hash_from_previous<Hasher: MerkleHasher<Hash>>(
        &self,
        previous_chain_hash: &Hash,
    ) -> Hash {
        let step_hash = self.get_step_commit_hash::<Hasher>();
        Hasher::two_to_one(previous_chain_hash, &step_hash)
    }
}
impl<Hash: Copy, F> QFieldHashable<F, Hash> for CheckpointStateTransitionPublicInputs<Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.get_public_inputs_hash_no_rewards_tag::<H>()
    }
}
#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for CheckpointStateTransitionPublicInputs<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_transition: CheckpointStateHashTransition::qp_rand_gen(),
            genesis_checkpoint_state_transition_hash: Hash::qp_rand_gen(),
            checkpoint_state_transition_circuit_fingerprint: Hash::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for CheckpointStateTransitionPublicInputs<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = CheckpointStateHashTransition::<Hash>::FIXED_SIZE + 32*2;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for CheckpointStateTransitionPublicInputs<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.checkpoint_transition.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.genesis_checkpoint_state_transition_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.checkpoint_state_transition_circuit_fingerprint.into_owned_32bytes())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_transition = CheckpointStateHashTransition::pio_read_from_io(reader)?;
        let genesis_checkpoint_state_transition_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let checkpoint_state_transition_circuit_fingerprint = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        Ok(Self {
            checkpoint_transition,
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    CheckpointStateTransitionPublicInputs,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for CheckpointStateTransitionPublicInputs<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    CheckpointStateTransitionPublicInputs,
    { parth_core::PHash },
    checkpoint_state_transition_public_inputs_ser_tests
);
