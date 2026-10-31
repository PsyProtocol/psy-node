use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::{HashOut, RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_config::network_constants::DA_CHALLENGE_WINDOW;
use psy_crypto::hash::{
    merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
    traits::{
        hasher::{FieldQHasher, MerkleZeroHasher},
        qhashable::QFieldHashable,
    },
};
use serde::{Deserialize, Serialize};

use super::agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput;
use crate::qdata::{
    checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf, PsyCheckpointLeafStats},
    pm_jobs_completed_stats::PMJobsCompletedStats,
    pm_reward_commitment::PMRewardCommitment,
};

pub const CHECKPOINT_RANDOM_SEED_DOMAIN: u64 = u64::from_le_bytes(*b"PSYSEED1");

pub fn derive_checkpoint_random_seed<F: RichField, H: FieldQHasher<F>>(old_seed: QHashOut<F>, new_state_roots_hash: QHashOut<F>) -> QHashOut<F> {
    let old = old_seed.0.elements;
    let roots = new_state_roots_hash.0.elements;
    H::q_hash_many(&[F::from_canonical_u64(CHECKPOINT_RANDOM_SEED_DOMAIN), old[0], old[1], old[2], old[3], roots[0], roots[1], roots[2], roots[3]])
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QCPsyCheckpointStateTransitionInputPartial<F: RichField> {
    pub part_1_header: QCAggUserRegistartionDeployContractsGUTAInput<F>,
    pub old_stats: PsyCheckpointLeafStats<F>,
    pub block_time: F,
    pub pm_rewards_commitment: PMRewardCommitment<F>,
    pub pm_jobs_completed: PMJobsCompletedStats<F>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QCPsyCheckpointStateTransitionInput<F: RichField> {
    pub partial: QCPsyCheckpointStateTransitionInputPartial<F>,
    pub append_checkpoint_tree_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub previous_checkpoint_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for QCPsyCheckpointStateTransitionInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QCPsyCheckpointStateTransitionInputPartial<F> {
    // Divergence from the node twin (psy_data QCQEDCheckpointStateTransitionInputPartial):
    // the contract end is read from `deploy_contracts_state_transition` (node: `update_contracts_state_transition`)
    // and the validator tree root is pinned to the empty-tree zero hash (node: witnessed
    // `validator_tree_root`). Full parity requires adding those fields to this client wire struct;
    // today they agree in the honest domain where the validator tree is empty and both
    // transitions end at the same contract root.
    pub fn get_new_checkpoint_leaf<H: FieldQHasher<F> + MerkleZeroHasher<QHashOut<F>>>(&self) -> PsyCheckpointLeaf<F> {
        let new_state_roots = PsyCheckpointGlobalStateRoots {
            contract_tree_root: self.part_1_header.deploy_contracts_state_transition.state_transition_end,
            deposit_tree_root: QHashOut(HashOut {
                elements: [
                    F::from_canonical_u64(16463394126558395459),
                    F::from_canonical_u64(12818610997234032270),
                    F::from_canonical_u64(2968763245313636978),
                    F::from_canonical_u64(15445927884703223427),
                ],
            }),
            user_tree_root: self.part_1_header.guta_proof_header.state_transition.new_node_value,
            withdrawal_tree_root: QHashOut(HashOut {
                elements: [
                    F::from_canonical_u64(16463394126558395459),
                    F::from_canonical_u64(12818610997234032270),
                    F::from_canonical_u64(2968763245313636978),
                    F::from_canonical_u64(15445927884703223427),
                ],
            }),
            user_registration_tree_root: self.part_1_header.register_users_state_transition.state_transition_end,
            validator_tree_root: H::get_zero_hash(crate::qdata::checkpoint::VALIDATOR_TREE_HEIGHT),
        };
        let new_state_roots_hash = new_state_roots.qfhash::<H>();
        PsyCheckpointLeaf {
            global_chain_root: new_state_roots_hash,
            stats: PsyCheckpointLeafStats {
                guta_fees_collected: self.part_1_header.guta_proof_header.stats.guta_fees_collected,
                da_fees_collected: self.part_1_header.guta_proof_header.stats.da_fees_collected,
                user_ops_processed: self.part_1_header.guta_proof_header.stats.user_ops_processed,
                total_transactions: self.part_1_header.guta_proof_header.stats.total_transactions,
                slots_modified: self.part_1_header.guta_proof_header.stats.slots_modified,
                pm_jobs_completed: self.pm_jobs_completed,
                block_time: self.block_time,
                random_seed: derive_checkpoint_random_seed::<F, H>(self.old_stats.random_seed, new_state_roots_hash),
                pm_rewards_commitment: self.pm_rewards_commitment.clone(),
                da_challenges_claimed: [F::ZERO; DA_CHALLENGE_WINDOW],
            },
        }
    }

    pub fn get_old_checkpoint_leaf<H: FieldQHasher<F> + MerkleZeroHasher<QHashOut<F>>>(&self) -> PsyCheckpointLeaf<F> {
        PsyCheckpointLeaf {
            global_chain_root: self.get_old_state_roots::<H>().qfhash::<H>(),
            stats: self.old_stats,
        }
    }

    pub fn get_old_state_roots<H: FieldQHasher<F> + MerkleZeroHasher<QHashOut<F>>>(&self) -> PsyCheckpointGlobalStateRoots<F> {
        let old_state_roots = PsyCheckpointGlobalStateRoots {
            contract_tree_root: self.part_1_header.deploy_contracts_state_transition.state_transition_start,
            deposit_tree_root: QHashOut(HashOut {
                elements: [
                    F::from_canonical_u64(16463394126558395459),
                    F::from_canonical_u64(12818610997234032270),
                    F::from_canonical_u64(2968763245313636978),
                    F::from_canonical_u64(15445927884703223427),
                ],
            }),
            user_tree_root: self.part_1_header.guta_proof_header.state_transition.old_node_value,
            withdrawal_tree_root: QHashOut(HashOut {
                elements: [
                    F::from_canonical_u64(16463394126558395459),
                    F::from_canonical_u64(12818610997234032270),
                    F::from_canonical_u64(2968763245313636978),
                    F::from_canonical_u64(15445927884703223427),
                ],
            }),
            user_registration_tree_root: self.part_1_header.register_users_state_transition.state_transition_start,
            validator_tree_root: H::get_zero_hash(crate::qdata::checkpoint::VALIDATOR_TREE_HEIGHT),
        };
        old_state_roots
    }
}

#[cfg(test)]
mod random_seed_tests {
    use super::*;
    use plonky2::{field::{goldilocks_field::GoldilocksField, types::Field}, hash::poseidon::PoseidonHash};

    #[test]
    fn random_seed_is_independent_of_time_and_rewards() {
        type F = GoldilocksField;
        let mut input = QCPsyCheckpointStateTransitionInputPartial::<F>::default();
        let original = input.get_new_checkpoint_leaf::<PoseidonHash>();
        input.block_time = F::from_canonical_u64(123);
        input.pm_jobs_completed.deploy_contracts_completed = F::ONE;
        input.pm_rewards_commitment.register_users_root = QHashOut(HashOut { elements: [F::ONE; 4] });
        input.part_1_header.guta_proof_header.stats.guta_fees_collected = F::ONE;
        input.part_1_header.guta_proof_header.stats.da_fees_collected = F::ONE;
        let changed = input.get_new_checkpoint_leaf::<PoseidonHash>();
        assert_eq!(original.global_chain_root, changed.global_chain_root);
        assert_eq!(original.stats.random_seed, changed.stats.random_seed);
    }
}
