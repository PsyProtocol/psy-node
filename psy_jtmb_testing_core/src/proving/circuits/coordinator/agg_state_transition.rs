use anyhow::Ok;
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;
use parth_core::{
    crypto::hash::{tag_tree::hash_tag_tree_node, traits::MerkleHasher},
    felt::FromPrimitiveValuesFelt,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{agg::{AggStateTransitionInputV2, AggStateWitnessV2}, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::{
        gadgets::coordinator::agg_state::{compute_agg_public_inputs, verify_agg_state_transition},
        utils::connect::jtmb_connect_ref,
    },
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary,
        jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase},
        proof_serialization::deserialize_jtmb_proof,
    },
};

#[derive(Debug, Clone)]
pub struct AggStateTransitionCircuitV2<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for AggStateTransitionCircuitV2<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        // use this for both AppendUserRegistrationTreeAggregate and
        // BatchDeployContractsAggregate
        ProvingJobCircuitType::AppendUserRegistrationTreeAggregate
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> AggStateTransitionCircuitV2<C> {
    pub fn new(private_key: &MemorySecp256K1SinglePrivateKeyWallet) -> Self {
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate as u32,
            [0u8; 32],
            &private_key.get_public_key(),
        );
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        input: &AggStateTransitionInputV2<C::Hash>,
        left_proof: &PsyTestJTMBProof<C::Hash>,
        left_verifier_data: &PsyTestJTMBProofVerifierData,
        left_rewards: C::Hash,
        right_proof: &PsyTestJTMBProof<C::Hash>,
        right_verifier_data: &PsyTestJTMBProofVerifierData,
        right_rewards: C::Hash,
        agg_fingerprint: C::Hash,
        leaf_fingerprint: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let whitelist_root = C::Hasher::two_to_one(&leaf_fingerprint, &agg_fingerprint);

        // 1. Verify Children Proofs Public Inputs & Signatures
        let left_trans = input.left_input.get_agg_state_transition();
        let left_proofs_count = C::F::from_u64_value(input.left_input.total_proofs_generated);
        let expected_left_pi = compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(whitelist_root, &left_trans, left_proofs_count, left_rewards);
        jtmb_connect_ref(&expected_left_pi, &left_proof.public_inputs_hash, "left child public inputs mismatch")?;
        left_verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(left_proof)?;

        let right_trans = input.right_input.get_agg_state_transition();
        let right_proofs_count = C::F::from_u64_value(input.right_input.total_proofs_generated);
        let expected_right_pi =
            compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(whitelist_root, &right_trans, right_proofs_count, right_rewards);
        jtmb_connect_ref(&expected_right_pi, &right_proof.public_inputs_hash, "right child public inputs mismatch")?;
        right_verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(right_proof)?;

        // Check fingerprints
        let left_fp = left_verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        if left_fp != agg_fingerprint && left_fp != leaf_fingerprint {
            anyhow::bail!("left child fingerprint mismatch (not leaf or agg)");
        }
        let right_fp = right_verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        if right_fp != agg_fingerprint && right_fp != leaf_fingerprint {
            anyhow::bail!("right child fingerprint mismatch (not leaf or agg)");
        }

        // 2. Verify Agg Logic
        let new_trans = verify_agg_state_transition::<C::Hash, C::F, C::Hasher>(&left_trans, &right_trans)?;

        // 3. Compute New Public Inputs
        let combined_rewards = hash_tag_tree_node::<C::Hash, C::Hasher>(&left_rewards, &right_rewards, &worker_reward_tag);
        let one = C::F::from_u64_value(1);
        let total_proofs = left_proofs_count + right_proofs_count + one;

        let final_pi_hash = compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(whitelist_root, &new_trans, total_proofs, combined_rewards);

        self.verifier_data
            .generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(final_pi_hash, &self.private_key)
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for AggStateTransitionCircuitV2<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {

        let leaf_fingerprint = library.get_fingerprint(input.base.job.job_id.circuit_type.get_agg_leaf_circuit_type_or_err()?)?;
        let agg_fingerprint = self.get_fingerprint();

        if input.input_proofs.len() != 2 {
            anyhow::bail!("invalid child proof tag values count in two end guta input");
        }
        if input.base.child_proof_tag_values.len() != 2 {
            anyhow::bail!("invalid child proof tag values count in two end guta input");
        }

        let left_proof = deserialize_jtmb_proof::<C::Hash>(&input.input_proofs[0])?;
        let right_proof = deserialize_jtmb_proof::<C::Hash>(&input.input_proofs[1])?;

        let left_verifier_data = library.get_verifier_data(input.base.job.metadata.dependencies[0].circuit_type)?;
        let right_verifier_data = library.get_verifier_data(input.base.job.metadata.dependencies[1].circuit_type)?;
        let left_proving_rewards_tag_value = input.base.child_proof_tag_values[0];
        let right_proving_rewards_tag_value = input.base.child_proof_tag_values[1];

        let witness = AggStateTransitionInputV2::<C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        let new_rewards_root =
            hash_tag_tree_node::<C::Hash, C::Hasher>(&left_proving_rewards_tag_value, &right_proving_rewards_tag_value, &worker_reward_tag);

        println!("witness: {:#?}", witness);

        let whitelist = C::Hasher::two_to_one(&leaf_fingerprint, &agg_fingerprint);

        let agg_state_transition_combined = witness.condense_add_one();
        println!("agg_state_transition_combined: {:#?}", agg_state_transition_combined);

        let expected_public_inputs_hash_before_reward_tag = witness.get_public_inputs_hash_no_tag_tree::<C::Hasher>(whitelist);
        println!(
            "expected_public_inputs_hash_before_reward_tag: {:#?}",
            expected_public_inputs_hash_before_reward_tag
        );
        let metadata_expected_public_inputs_hash_before_reward_tag = input.base.job.metadata.expected_public_inputs_hash;
        println!(
            "metadata_expected_public_inputs_hash_before_reward_tag: {:#?}",
            metadata_expected_public_inputs_hash_before_reward_tag
        );
        if expected_public_inputs_hash_before_reward_tag != metadata_expected_public_inputs_hash_before_reward_tag {
            tracing::error!(
                "expected_public_inputs_hash_before_reward_tag does not match metadata! expected: {:#?}, got: {:#?}",
                metadata_expected_public_inputs_hash_before_reward_tag,
                expected_public_inputs_hash_before_reward_tag
            );
        }
        println!("new_rewards_root: {:#?}", new_rewards_root);
        let expected_public_inputs_hash = C::Hasher::two_to_one(&expected_public_inputs_hash_before_reward_tag, &new_rewards_root);
        println!("expected_public_inputs_hash: {:#?}", expected_public_inputs_hash);
        let result = self.prove_base(
            worker_reward_tag,
            &witness,
            &left_proof,
            
            &left_verifier_data,
            left_proving_rewards_tag_value,
            &right_proof,
            &right_verifier_data,
            right_proving_rewards_tag_value,
            agg_fingerprint,
            leaf_fingerprint,
        )?;

        println!("got_public_inputs: {:#?}", result.public_inputs_hash);
        Ok(result)
    }
}
