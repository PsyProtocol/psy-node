use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{
    hash::hash_types::RichField,
    plonk::{circuit_data::VerifierOnlyCircuitData, config::GenericConfig, proof::ProofWithPublicInputs},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibrary;

use crate::utils::proof_serialization::deserialize_plonky2_proof;

pub struct PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<C: GenericConfig<D>, const D: usize> {
    pub circuit_type: ProvingJobCircuitType,
    pub job_id: QProvingJobDataID,
    pub whitelist_inclusion_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verifier_data: VerifierOnlyCircuitData<C, D>,
    pub zk_proof: ProofWithPublicInputs<C::F, C, D>,
    pub reward_tag_tree_value: QHashOut<C::F>,
}

pub fn get_reward_tags_ensure_expected_child_proof_count<F: RichField>(
    expected_child_proof_count: usize,
    input: &PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<F>, QProvingJobDataID>,
) -> anyhow::Result<Vec<QHashOut<F>>> {
    input.ensure_expected_child_proof_count(expected_child_proof_count)?;
    let input_circuit_types = input.get_child_proof_circuit_types();
    if input_circuit_types.len() != expected_child_proof_count {
        anyhow::bail!(
            "invalid child proof circuit types in API response: expected {} circuit types, got {} circuit types",
            expected_child_proof_count,
            input_circuit_types.len()
        );
    }
    let mut child_reward_tag_values_array_counter = 0;
    let mut child_reward_values = Vec::with_capacity(expected_child_proof_count);
    let actual_tags_length = input.base.child_proof_tag_values.len();
    for circuit_type in input_circuit_types {
        if circuit_type == ProvingJobCircuitType::UserEndCap || circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof || circuit_type == ProvingJobCircuitType::GenesisBlockCheckpointStateTransition {
            child_reward_values.push(QHashOut::ZERO);
        } else {
            if child_reward_tag_values_array_counter >= actual_tags_length {
                anyhow::bail!("not enough tags in API response for expected child proof count");
            }
            child_reward_values.push(input.base.child_proof_tag_values[child_reward_tag_values_array_counter]);
            child_reward_tag_values_array_counter += 1;
        }
    }
    Ok(child_reward_values)
}

pub fn get_proof_results_for_api_response_with_inclusion_proof<L: CircuitInfoLibrary<C, D>, C: GenericConfig<D>, const D: usize>(
    library: &L,
    expected_child_proof_count: usize,
    input: &PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
) -> anyhow::Result<Vec<PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<C, D>>> {
    let child_proof_reward_tag_values = get_reward_tags_ensure_expected_child_proof_count::<C::F>(expected_child_proof_count, &input)?;

    let mut results = Vec::with_capacity(expected_child_proof_count);
    let parent_circuit_type = input.base.job.job_id.circuit_type;
    for i in 0..expected_child_proof_count {
        let child_circuit_type = input.base.job.metadata.dependencies[i].circuit_type;
        let job_id = input.base.job.metadata.dependencies[i];
        let whitelist_inclusion_proof = if child_circuit_type == ProvingJobCircuitType::UserEndCap || child_circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof || child_circuit_type == ProvingJobCircuitType::GenesisBlockCheckpointStateTransition {
            MerkleProofCore{
                siblings: vec![],
                value: QHashOut::ZERO,
                index: 0,
                root: QHashOut::ZERO,
            }
        } else {
            library.get_group_inclusion_proof(parent_circuit_type, child_circuit_type)?
        };
        let verifier_data = library.get_verifier_data(child_circuit_type)?;
        let zk_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[i])?;
        results.push(PsyWorkerProofResultForCircuitWithWhitelistInclusionProof {
            circuit_type: child_circuit_type,
            job_id,
            whitelist_inclusion_proof,
            verifier_data,
            zk_proof,
            reward_tag_tree_value: child_proof_reward_tag_values[i],
        });
    }
    Ok(results)
}

pub fn get_single_child_proof_for_api_response_with_inclusion_proof<
    L: CircuitInfoLibrary<C, D>,
    C: GenericConfig<D>,
    const D: usize,
>(
    library: &L,
    input: &PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
) -> anyhow::Result<PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<C, D>> {
    let proof_results = get_proof_results_for_api_response_with_inclusion_proof::<L, C, D>(library, 1, &input)?;
    Ok(proof_results.into_iter().next().unwrap())
}

pub fn get_two_child_proofs_for_api_response_with_inclusion_proof<L: CircuitInfoLibrary<C, D>, C: GenericConfig<D>, const D: usize>(
    library: &L,
    input: &PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
) -> anyhow::Result<(
    PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<C, D>,
    PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<C, D>,
)> {
    let mut proof_results = get_proof_results_for_api_response_with_inclusion_proof::<L, C, D>(library, 2, &input)?;
    let second_child = proof_results.pop().unwrap();
    let first_child = proof_results.pop().unwrap();
    Ok((first_child, second_child))
}

