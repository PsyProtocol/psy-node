use parth_core::{crypto::hash::{tag_tree::hash_tag_tree_node_single, traits::{MerkleHasher, QFieldHashable}}, protocol::core_types::Q256BitHash};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    protocol::{checkpoint_transition_hash::{CheckpointStateHashTransition, CheckpointStateTransitionPublicInputs}, circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInput}, v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf}, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse
};

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::{
        gadgets::coordinator::checkpoint::{construct_new_checkpoint_leaf, verify_checkpoint_transition_core},
        utils::connect::jtmb_connect_ref,
    },
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_reward_tags_ensure_expected_child_proof_count, proof_serialization::deserialize_jtmb_proof
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct QEDCheckpointStateTransitionCircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
    
    pub checkpoint_tree_height: usize,
    pub known_part_1_fingerprint: C::Hash,
    pub known_genesis_fingerprint: C::Hash,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for QEDCheckpointStateTransitionCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GenerateRollupStateTransitionProof
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> QEDCheckpointStateTransitionCircuit<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        checkpoint_tree_height: usize,
        known_part_1_fingerprint: C::Hash,
        known_genesis_fingerprint: C::Hash,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::GenerateRollupStateTransitionProof;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(
            circuit_type as u32,
            [0u8; 32],
            &private_key.get_public_key(),
        );
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
            checkpoint_tree_height,
            known_part_1_fingerprint,
            known_genesis_fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        input: &QCQEDCheckpointStateTransitionInput<C::F, C::Hash>,
        part_1_reward_root: C::Hash,
        part_1_proof: &PsyTestJTMBProof<C::Hash>,
        part_1_verifier_data: &PsyTestJTMBProofVerifierData,
        previous_checkpoint_proof: &PsyTestJTMBProof<C::Hash>,
        previous_checkpoint_verifier_data: &PsyTestJTMBProofVerifierData,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        
        let dummy_root = C::Hash::from_owned_32bytes(
            hex_literal::hex!("43fcc336bbb979e48ede0c3cc9dae4b172ba2743712a3329834e093a93f55ad6")
        );

        let old_state_roots = psy_data::v1::qdata::checkpoint::PQEDCheckpointGlobalStateRoots {
            contract_tree_root: input.partial.part_1_header.deploy_contracts_state_transition.state_transition_start,
            deposit_tree_root: dummy_root,
            user_tree_root: input.partial.part_1_header.guta_proof_header.state_transition.old_node_value,
            withdrawal_tree_root: dummy_root,
            user_registration_tree_root: input.partial.part_1_header.register_users_state_transition.state_transition_start,
        };

        let new_state_roots = psy_data::v1::qdata::checkpoint::PQEDCheckpointGlobalStateRoots {
            contract_tree_root: input.partial.part_1_header.deploy_contracts_state_transition.state_transition_end,
            deposit_tree_root: dummy_root,
            user_tree_root: input.partial.part_1_header.guta_proof_header.state_transition.new_node_value,
            withdrawal_tree_root: dummy_root,
            user_registration_tree_root: input.partial.part_1_header.register_users_state_transition.state_transition_end,
        };

        let previous_transition = CheckpointStateHashTransition {
            old_checkpoint_tree_root: input.last_old_checkpoint_tree_root_hash,
            new_checkpoint_tree_root: input.previous_checkpoint_proof.root,
            old_checkpoint_leaf_hash: input.last_old_checkpoint_tree_leaf_hash,
            new_checkpoint_leaf_hash: input.previous_checkpoint_proof.value,
        };
        let prev_pi_struct = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: previous_transition,
            genesis_checkpoint_state_transition_hash: input.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint: self.fingerprint, 
        };

        let expected_prev_pi = prev_pi_struct.get_public_inputs_hash_no_rewards_tag::<C::Hasher>();
        
        // 1. Verify Part 1 Proof
        part_1_verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(part_1_proof)?;
        let p1_fp = part_1_verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        jtmb_connect_ref(&p1_fp, &self.known_part_1_fingerprint, "Part 1 proof fingerprint mismatch")?;

        // 2. Verify Previous Checkpoint Proof
        let is_genesis_prev = input.append_checkpoint_tree_proof.index == 1;
        
        previous_checkpoint_verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(previous_checkpoint_proof)?;
        let prev_fp = previous_checkpoint_verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        
        if is_genesis_prev {
            jtmb_connect_ref(&prev_fp, &self.known_genesis_fingerprint, "Previous proof (Genesis) fingerprint mismatch")?;
            let config_hash = C::Hasher::two_to_one(&input.genesis_checkpoint_state_transition_hash, &self.fingerprint);
            let expected_genesis_pi = C::Hasher::two_to_one(&input.genesis_checkpoint_state_transition_hash, &config_hash);
            jtmb_connect_ref(&expected_genesis_pi, &previous_checkpoint_proof.public_inputs_hash, "Genesis proof public inputs mismatch")?;
        } else {
            jtmb_connect_ref(&prev_fp, &self.fingerprint, "Previous proof (Recursive) fingerprint mismatch")?;
            jtmb_connect_ref(&expected_prev_pi, &previous_checkpoint_proof.public_inputs_hash, "Previous proof public inputs mismatch")?;
        }

        println!("old_state_roots: {:?}", old_state_roots);
        println!("old_state_roots hash: {:?}", old_state_roots.qfhash::<C::Hasher>());
        println!("old stats: {:?}", input.partial.old_stats);


        let old_leaf_obj = psy_data::v1::qdata::checkpoint::PQEDCheckpointLeaf {
            global_chain_root: old_state_roots.qfhash::<C::Hasher>(),
            stats: input.partial.old_stats.clone(),
        };
        let computed_old_leaf_hash = old_leaf_obj.qfhash::<C::Hasher>();
        jtmb_connect_ref(&computed_old_leaf_hash, &input.previous_checkpoint_proof.value, "computed old leaf hash mismatch")?;

        let new_leaf_obj = construct_new_checkpoint_leaf::<C>(
            &new_state_roots,
            part_1_reward_root,
            worker_reward_tag,
            input.partial.part_1_header.guta_proof_header.stats.guta_fees_collected,
            input.partial.part_1_header.guta_proof_header.stats.da_fees_collected,
            input.partial.part_1_header.guta_proof_header.stats.user_ops_processed,
            input.partial.part_1_header.guta_proof_header.stats.total_transactions,
            input.partial.part_1_header.guta_proof_header.stats.slots_modified,
            input.partial.pm_jobs_completed.clone(),
            input.partial.block_time,
            input.partial.final_random_seed_contribution,
        );
        let computed_new_leaf_hash = new_leaf_obj.qfhash::<C::Hasher>();
        
        verify_checkpoint_transition_core::<C>(
            &input.append_checkpoint_tree_proof,
            &input.previous_checkpoint_proof,
            self.checkpoint_tree_height,
        )?;
        
        jtmb_connect_ref(&input.append_checkpoint_tree_proof.new_value, &computed_new_leaf_hash, "append proof new value mismatch")?;

        let current_transition = CheckpointStateHashTransition {
            old_checkpoint_tree_root: input.previous_checkpoint_proof.root,
            new_checkpoint_tree_root: input.append_checkpoint_tree_proof.new_root,
            old_checkpoint_leaf_hash: input.previous_checkpoint_proof.value,
            new_checkpoint_leaf_hash: input.append_checkpoint_tree_proof.new_value,
        };
        
        let current_pi_struct = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: current_transition,
            genesis_checkpoint_state_transition_hash: input.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint: self.fingerprint,
        };
        
        let public_inputs_hash = current_pi_struct.get_public_inputs_hash_no_rewards_tag::<C::Hasher>();

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            public_inputs_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for QEDCheckpointStateTransitionCircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let rewards = get_reward_tags_ensure_expected_child_proof_count(2, &input)?;
        let mut witness = QCQEDCheckpointStateTransitionInput::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        let part_1_proof = deserialize_jtmb_proof::<C::Hash>(&input.input_proofs[0])?;
        let part_1_type = input.base.job.metadata.dependencies[0].circuit_type;
        let part_1_verifier_data = library.get_verifier_data(part_1_type)?;
        let part_1_worker_reward_tree_value = rewards[0];
        let prev_checkpoint_proof = deserialize_jtmb_proof::<C::Hash>(&input.input_proofs[1])?;
        let prev_type = input.base.job.metadata.dependencies[1].circuit_type;
        let prev_verifier_data = library.get_verifier_data(prev_type)?;

        let reward_tree_root = hash_tag_tree_node_single::<C::Hash, C::Hasher>(&part_1_worker_reward_tree_value, &worker_reward_tag);
        witness.update_for_prover::<C::Hasher>(reward_tree_root);

        //println!("dmp: {:?}", witness.append_checkpoint_tree_proof);



        // TODO: add deposits and withdrawals, for now just leave with constant hashes
        let todo_add_deposits_root = C::Hash::from_owned_32bytes(
            hex_literal::hex!("43fcc336bbb979e48ede0c3cc9dae4b172ba2743712a3329834e093a93f55ad6"),
        );
        let todo_add_withdrawals_root = C::Hash::from_owned_32bytes(
            hex_literal::hex!("43fcc336bbb979e48ede0c3cc9dae4b172ba2743712a3329834e093a93f55ad6"),
        );
        let old_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: witness.partial.part_1_header.deploy_contracts_state_transition.state_transition_start,
            deposit_tree_root: todo_add_deposits_root,
            user_tree_root: witness.partial.part_1_header.guta_proof_header.state_transition.old_node_value,
            withdrawal_tree_root: todo_add_withdrawals_root,
            user_registration_tree_root: witness.partial.part_1_header.register_users_state_transition.state_transition_start,
        };
        /*let new_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: witness.partial.part_1_header.deploy_contracts_state_transition.state_transition_end,
            deposit_tree_root: todo_add_deposits_root,
            user_tree_root: witness.partial.part_1_header.guta_proof_header.state_transition.new_node_value,
            withdrawal_tree_root: todo_add_withdrawals_root,
            user_registration_tree_root: witness.partial.part_1_header.register_users_state_transition.state_transition_end,
        };*/

        //println!("old_state_roots: {:#?}", old_state_roots);

        //println!("new_state_roots: {:#?}", new_state_roots);

        let old_global_chain_root = old_state_roots.qfhash::<C::Hasher>();
        //let new_global_chain_root = new_state_roots.qfhash::<C::Hasher>();
        //println!("old_global_chain_root: {:?} ({})", old_global_chain_root.0.elements, hex::encode(&old_global_chain_root.into_owned_32bytes()));
        //println!("new_global_chain_root: {:?} ({})", new_global_chain_root.0.elements, hex::encode(&new_global_chain_root.into_owned_32bytes()));
        let old_stats = witness.partial.old_stats.clone();
        let old_checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root: old_global_chain_root,
            stats: old_stats,
        };

        let old_checkpoint_leaf_hash = old_checkpoint_leaf.qfhash::<C::Hasher>();

        if old_checkpoint_leaf_hash != witness.previous_checkpoint_proof.value {
            tracing::error!("Error: old_checkpoint_leaf_hash does not match previous_checkpoint_proof value:\n old_checkpoint_leaf_hash: {:?} ({})\n  previous_checkpoint_proof.value: {:?} ({})\nExpected Old Checkpoint Leaf: {:#?}",
                old_checkpoint_leaf_hash, hex::encode(&old_checkpoint_leaf_hash.into_owned_32bytes()),
                witness.previous_checkpoint_proof.value, hex::encode(&witness.previous_checkpoint_proof.value.into_owned_32bytes()),
                old_checkpoint_leaf,
            );
        }

        let expected_old_public_inputs = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: witness.last_old_checkpoint_tree_root_hash,
                new_checkpoint_tree_root: witness.previous_checkpoint_proof.root,
                old_checkpoint_leaf_hash: witness.last_old_checkpoint_tree_leaf_hash,
                new_checkpoint_leaf_hash: witness.previous_checkpoint_proof.value
            },

            genesis_checkpoint_state_transition_hash: witness.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint: self.get_fingerprint()
        };

        let expected_new_public_inputs = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: witness.previous_checkpoint_proof.root,
                new_checkpoint_tree_root: witness.append_checkpoint_tree_proof.new_root,
                old_checkpoint_leaf_hash: witness.previous_checkpoint_proof.value,
                new_checkpoint_leaf_hash: witness.append_checkpoint_tree_proof.new_value
            },

            genesis_checkpoint_state_transition_hash: witness.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint: self.get_fingerprint()
        };
        println!("expected_old_public_inputs_preimage: {:#?}", expected_old_public_inputs);
        println!("expected_new_public_inputs_preimage: {:#?}", expected_new_public_inputs);
        let expected_old_public_inputs_hash = expected_old_public_inputs.qfhash::<C::Hasher>();
        //let expected_new_public_inputs_hash = expected_new_public_inputs.qfhash::<C::Hasher>();
        let actual_old_public_inputs_hash = prev_checkpoint_proof.public_inputs_hash;
        //println!("old_checkpoint_leaf: {:#?}", old_checkpoint_leaf);
        println!("expected public inputs for the last checkpoint transition proof:\n{:?} ({})", prev_checkpoint_proof.public_inputs_hash, hex::encode(&expected_old_public_inputs_hash.into_owned_32bytes()));
        if expected_old_public_inputs_hash != actual_old_public_inputs_hash {
            tracing::error!("Error: expected_old_public_inputs does not match previous_checkpoint_state_transition_proof public inputs:\n expected_old_public_inputs: {:?} ({})\n  previous_checkpoint_state_transition_proof.public_inputs: {:?} ({})\nExpected Old Checkpoint Leaf: {:#?}",
                expected_old_public_inputs_hash, hex::encode(&expected_old_public_inputs_hash.into_owned_32bytes()),
                actual_old_public_inputs_hash, hex::encode(&actual_old_public_inputs_hash.into_owned_32bytes()),
                old_checkpoint_leaf,
            );
        }

        self.prove_base(
            worker_reward_tag,
            &witness,
            part_1_worker_reward_tree_value,
            &part_1_proof,
            &part_1_verifier_data,
            &prev_checkpoint_proof,
            &prev_verifier_data,
        )
    }
}