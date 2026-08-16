
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore, compute_root_merkle_proof_generic}, traits::{FieldQHasher, MerkleHasher, QFieldHashable}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}};
use psy_core::constants::protocol::{DA_CHALLENGE_WINDOW, TODO_DEPOSIT_TREE_HEIGHT, TODO_WITHDRAWAL_TREE_HEIGHT};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{guta::realm_finalize::VALIDATOR_TREE_HEIGHT, protocol::checkpoint_transition_hash::{CheckpointStateHashTransition, CheckpointStateTransitionPublicInputs}, v1::qdata::{checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats}, pm_jobs_completed_stats::PPMJobsCompletedStats, pm_rewards_commitment::PPMRewardCommitment}};

use super::agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput;


#[pderive::serialize_clone_f_hash]
pub struct QCQEDCheckpointStateTransitionInputPartial<F, Hash> {
    pub part_1_header: QCAggUserRegistartionDeployContractsGUTAInput<F, Hash>,
    pub old_stats: PQEDCheckpointLeafStats<F, Hash>,
    pub block_time: F,
    pub final_random_seed_contribution: Hash,
    pub pm_jobs_completed: PPMJobsCompletedStats<F>,
    pub validator_tree_root: Hash,
}
#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for QCQEDCheckpointStateTransitionInputPartial<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            part_1_header: QCAggUserRegistartionDeployContractsGUTAInput::qp_rand_gen(),
            old_stats: PQEDCheckpointLeafStats::qp_rand_gen(),
            block_time: F::qp_rand_gen(),
            final_random_seed_contribution: Hash::qp_rand_gen(),
            pm_jobs_completed: PPMJobsCompletedStats::qp_rand_gen(),
            validator_tree_root: Hash::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QCQEDCheckpointStateTransitionInputPartial<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = QCAggUserRegistartionDeployContractsGUTAInput::<F, Hash>::FIXED_SIZE
        + PQEDCheckpointLeafStats::<F, Hash>::FIXED_SIZE
        + 8 // block_time
        + 32 // final_random_seed_contribution
        + PPMJobsCompletedStats::<F>::FIXED_SIZE
        + 32; // validator_tree_root
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for QCQEDCheckpointStateTransitionInputPartial<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.part_1_header.pio_write_to_io(writer)?;
        self.old_stats.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.block_time.to_u64_value())?;
        writer.psy_write_bytes_fixed(&self.final_random_seed_contribution.into_owned_32bytes())?;
        self.pm_jobs_completed.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.validator_tree_root.into_owned_32bytes())?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let part_1_header = QCAggUserRegistartionDeployContractsGUTAInput::pio_read_from_io(reader)?;
        let old_stats = PQEDCheckpointLeafStats::pio_read_from_io(reader)?;
        let block_time = F::from_u64_value(reader.psy_read_u64()?);
        let final_random_seed_contribution = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let pm_jobs_completed = PPMJobsCompletedStats::pio_read_from_io(reader)?;
        let validator_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        Ok(Self {
            part_1_header,
            old_stats,
            block_time,
            final_random_seed_contribution,
            pm_jobs_completed,
            validator_tree_root,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    QCQEDCheckpointStateTransitionInputPartial,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for QCQEDCheckpointStateTransitionInputPartial<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    QCQEDCheckpointStateTransitionInputPartial,
    { parth_core::PF, parth_core::PHash },
    qc_qed_checkpoint_state_transition_input_partial_ser_tests
);

#[pderive::serialize_clone_f_hash]
pub struct QCQEDCheckpointStateTransitionInput<F, Hash> {
    pub partial: QCQEDCheckpointStateTransitionInputPartial<F, Hash>,
    pub append_checkpoint_tree_proof: DeltaMerkleProofCore<Hash>,
    pub previous_checkpoint_proof: MerkleProofCore<Hash>,
    pub genesis_checkpoint_state_transition_hash: Hash,

    // two blocks ago, what was the last leaf hash and root hash of the old checkpoint tree
    // block 1, this is the genesis checkpoint tree leaf and root hash
    pub last_old_checkpoint_tree_leaf_hash: Hash,
    pub last_old_checkpoint_tree_root_hash: Hash,
    pub previous_chain_hash: Hash,
    pub checkpoint_state_transition_circuit_fingerprint: Hash,
}
impl<F: QFelt64, Hash: QFHashBase<F>> QCQEDCheckpointStateTransitionInput<F, Hash> {
    pub fn update_with_new_reward_tree_root<Hasher: FieldQHasher<F, Hash>>(&mut self, reward_tree_root: Hash) {
        let checkpoint_leaf = self.partial.get_new_checkpoint_leaf::<Hasher>(reward_tree_root);
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<Hasher>();
        self.append_checkpoint_tree_proof.new_value = checkpoint_leaf_hash;
        let new_checkpoint_tree_root = compute_root_merkle_proof_generic::<Hash, Hasher>(checkpoint_leaf_hash, self.append_checkpoint_tree_proof.index, &self.append_checkpoint_tree_proof.siblings);
        self.append_checkpoint_tree_proof.new_root = new_checkpoint_tree_root;
    }
    pub fn update_for_prover<Hasher: FieldQHasher<F, Hash>>(&mut self, reward_tree_root: Hash) {
        let checkpoint_leaf = self.partial.get_new_checkpoint_leaf::<Hasher>(reward_tree_root);
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<Hasher>();
        self.append_checkpoint_tree_proof.new_value = checkpoint_leaf_hash;
        let new_checkpoint_tree_root = compute_root_merkle_proof_generic::<Hash, Hasher>(checkpoint_leaf_hash, self.append_checkpoint_tree_proof.index, &self.append_checkpoint_tree_proof.siblings);
        self.append_checkpoint_tree_proof.new_root = new_checkpoint_tree_root;
    }
}
#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for QCQEDCheckpointStateTransitionInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            partial: QCQEDCheckpointStateTransitionInputPartial::qp_rand_gen(),
            append_checkpoint_tree_proof: DeltaMerkleProofCore::qp_rand_gen(),
            previous_checkpoint_proof: MerkleProofCore::qp_rand_gen(),
            genesis_checkpoint_state_transition_hash: Hash::qp_rand_gen(),
            last_old_checkpoint_tree_leaf_hash: Hash::qp_rand_gen(),
            last_old_checkpoint_tree_root_hash: Hash::qp_rand_gen(),
            previous_chain_hash: Hash::qp_rand_gen(),
            checkpoint_state_transition_circuit_fingerprint: Hash::qp_rand_gen(),
        }
    }
}
impl<F, Hash: Copy> QCQEDCheckpointStateTransitionInput<F, Hash> {
    /// New chain-mode step hash for current checkpoint i:
    /// step_i = H(checkpoint_tree_root_i, checkpoint_leaf_hash_i, checkpoint_transition_fingerprint)
    pub fn get_step_commit_hash_with_fingerprint<Hasher: MerkleHasher<Hash>>(
        &self,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> Hash {
        let checkpoint_transition = CheckpointStateHashTransition {
            old_checkpoint_tree_root: self.append_checkpoint_tree_proof.old_root,
            new_checkpoint_tree_root: self.append_checkpoint_tree_proof.new_root,
            old_checkpoint_leaf_hash: self.previous_checkpoint_proof.value,
            new_checkpoint_leaf_hash: self.append_checkpoint_tree_proof.new_value,
        };
        let data = CheckpointStateTransitionPublicInputs {
            checkpoint_transition,
            genesis_checkpoint_state_transition_hash: self.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        };
        data.get_step_commit_hash::<Hasher>()
    }

    /// New chain-mode public input:
    /// chain_i = H(chain_{i-1}, step_i)
    pub fn get_chain_hash_from_previous_with_fingerprint<Hasher: MerkleHasher<Hash>>(
        &self,
        previous_chain_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> Hash {
        let checkpoint_transition = CheckpointStateHashTransition {
            old_checkpoint_tree_root: self.append_checkpoint_tree_proof.old_root,
            new_checkpoint_tree_root: self.append_checkpoint_tree_proof.new_root,
            old_checkpoint_leaf_hash: self.previous_checkpoint_proof.value,
            new_checkpoint_leaf_hash: self.append_checkpoint_tree_proof.new_value,
        };
        let data = CheckpointStateTransitionPublicInputs {
            checkpoint_transition,
            genesis_checkpoint_state_transition_hash: self.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        };
        data.get_chain_hash_from_previous::<Hasher>(&previous_chain_hash)
    }

    pub fn get_chain_hash_with_fingerprint_from_previous<Hasher: MerkleHasher<Hash>>(
        &self,
        previous_chain_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> Hash {
        self.get_chain_hash_from_previous_with_fingerprint::<Hasher>(
            previous_chain_hash,
            checkpoint_state_transition_circuit_fingerprint,
        )
    }
}

impl<F: QFelt64, Hash: Q256BitHash + QHashBase + QFHashBase<F>> QCQEDCheckpointStateTransitionInput<F, Hash> {
    pub fn get_chain_hash_with_fingerprint_and_reward_root<Hasher: FieldQHasher<F, Hash>>(
        &self,
        previous_chain_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
        reward_root: Hash,
    ) -> Hash {
        let mut modified = self.clone();
        modified.update_with_new_reward_tree_root::<Hasher>(reward_root);
        modified.get_chain_hash_with_fingerprint_from_previous::<Hasher>(
            previous_chain_hash,
            checkpoint_state_transition_circuit_fingerprint,
        )
    }
}
impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QCQEDCheckpointStateTransitionInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for QCQEDCheckpointStateTransitionInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.partial.pio_serialized_size()
        + self.append_checkpoint_tree_proof.pio_serialized_size()
        + self.previous_checkpoint_proof.pio_serialized_size() + 32*5
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.partial.pio_write_to_io(writer)?;
        self.append_checkpoint_tree_proof.pio_write_to_io(writer)?;
        self.previous_checkpoint_proof.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.genesis_checkpoint_state_transition_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.last_old_checkpoint_tree_leaf_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.last_old_checkpoint_tree_root_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.previous_chain_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.checkpoint_state_transition_circuit_fingerprint.into_owned_32bytes())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let partial = QCQEDCheckpointStateTransitionInputPartial::pio_read_from_io(reader)?;
        let append_checkpoint_tree_proof = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        let previous_checkpoint_proof = MerkleProofCore::pio_read_from_io(reader)?;
        let genesis_checkpoint_state_transition_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let last_old_checkpoint_tree_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let last_old_checkpoint_tree_root_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let previous_chain_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let checkpoint_state_transition_circuit_fingerprint = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        Ok(Self {
            partial,
            append_checkpoint_tree_proof,
            previous_checkpoint_proof,
            genesis_checkpoint_state_transition_hash,
            last_old_checkpoint_tree_leaf_hash,
            last_old_checkpoint_tree_root_hash,
            previous_chain_hash,
            checkpoint_state_transition_circuit_fingerprint,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    QCQEDCheckpointStateTransitionInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for QCQEDCheckpointStateTransitionInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    QCQEDCheckpointStateTransitionInput,
    { parth_core::PF, parth_core::PHash },
    qc_qed_checkpoint_state_transition_input_ser_tests
);

impl<F: QFelt64, Hash: QFHashBase<F>> QCQEDCheckpointStateTransitionInputPartial<F, Hash> {
    pub fn get_new_checkpoint_leaf<Hasher: FieldQHasher<F, Hash>>(&self, reward_tree_root: Hash) -> PQEDCheckpointLeaf<F, Hash> {
        let new_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: self.part_1_header.deploy_contracts_state_transition.state_transition_end,
            deposit_tree_root: Hasher::get_zero_hash(TODO_DEPOSIT_TREE_HEIGHT as usize),
            user_tree_root: self.part_1_header.guta_proof_header.state_transition.new_node_value,
            withdrawal_tree_root:Hasher::get_zero_hash(TODO_WITHDRAWAL_TREE_HEIGHT as usize),
            user_registration_tree_root: self.part_1_header.register_users_state_transition.state_transition_end,
            validator_tree_root: self.validator_tree_root,
        };
        PQEDCheckpointLeaf {
            global_chain_root: new_state_roots.qfhash::<Hasher>(),
            stats: PQEDCheckpointLeafStats {
                guta_fees_collected: self.part_1_header.guta_proof_header.stats.guta_fees_collected,
                da_fees_collected: self.part_1_header.guta_proof_header.stats.da_fees_collected,
                user_ops_processed: self.part_1_header.guta_proof_header.stats.user_ops_processed,
                total_transactions: self.part_1_header.guta_proof_header.stats.total_transactions,
                slots_modified: self.part_1_header.guta_proof_header.stats.slots_modified,
                pm_jobs_completed: self.pm_jobs_completed,
                block_time: self.block_time,
                random_seed: self.final_random_seed_contribution,//Hasher::two_to_one(&self.old_stats.random_seed, &self.final_random_seed_contribution),
                pm_rewards_commitment: PPMRewardCommitment {
                    register_users_root: reward_tree_root,
                    gutas_root: reward_tree_root,
                    deploy_contracts_root: reward_tree_root,
                },
                da_challenges_claimed: [F::ZERO_VALUE; DA_CHALLENGE_WINDOW],
            },
        }

    }
    pub fn get_old_checkpoint_leaf<Hasher: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointLeaf<F, Hash> {
        PQEDCheckpointLeaf {
            global_chain_root: self.get_old_state_roots::<Hasher>().qfhash::<Hasher>(),
            stats: self.old_stats,
        }
    }

    pub fn get_old_state_roots<Hasher: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointGlobalStateRoots<Hash> {
        let old_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: self.part_1_header.deploy_contracts_state_transition.state_transition_start,
            deposit_tree_root: Hasher::get_zero_hash(TODO_DEPOSIT_TREE_HEIGHT as usize),
            user_tree_root: self.part_1_header.guta_proof_header.state_transition.old_node_value,
            withdrawal_tree_root: Hasher::get_zero_hash(TODO_WITHDRAWAL_TREE_HEIGHT as usize),
            user_registration_tree_root: self.part_1_header.register_users_state_transition.state_transition_start,
            validator_tree_root: self.validator_tree_root,
        };
        old_state_roots
    }
}
