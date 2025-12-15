use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{MerkleZeroHasher, ZeroableHash},
    },
    protocol::core_types::Q256BitHash,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    utils::{circuit_info_library::PsyJTMBCircuitInfoLibrary, proof_serialization::deserialize_jtmb_proof},
};

pub struct PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<Hash> {
    pub circuit_type: ProvingJobCircuitType,
    pub job_id: QProvingJobDataID,
    pub whitelist_inclusion_proof: MerkleProofCore<Hash>,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub zk_proof: PsyTestJTMBProof<Hash>,
    pub reward_tag_tree_value: Hash,
}

pub fn get_reward_tags_ensure_expected_child_proof_count<Hash: PartialEq + Copy + ZeroableHash>(
    expected_child_proof_count: usize,
    input: &PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>,
) -> anyhow::Result<Vec<Hash>> {
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
        if circuit_type == ProvingJobCircuitType::UserEndCap
            || circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof
            || circuit_type == ProvingJobCircuitType::GenesisBlockCheckpointStateTransition
        {
            child_reward_values.push(Hash::get_zero_value());
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

pub fn get_proof_results_for_api_response_with_inclusion_proof<
    L: PsyJTMBCircuitInfoLibrary<Hash>,
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Q256BitHash + ZeroableHash,
>(
    library: &L,
    expected_child_proof_count: usize,
    input: &PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>,
) -> anyhow::Result<Vec<PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<Hash>>> {
    let child_proof_reward_tag_values = get_reward_tags_ensure_expected_child_proof_count::<Hash>(expected_child_proof_count, &input)?;

    let mut results = Vec::with_capacity(expected_child_proof_count);
    let parent_circuit_type = input.base.job.job_id.circuit_type;
    for i in 0..expected_child_proof_count {
        let child_circuit_type = input.base.job.metadata.dependencies[i].circuit_type;
        let job_id = input.base.job.metadata.dependencies[i];
        let whitelist_inclusion_proof = if child_circuit_type == ProvingJobCircuitType::UserEndCap
            || child_circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof
            || child_circuit_type == ProvingJobCircuitType::GenesisBlockCheckpointStateTransition
        {
            MerkleProofCore {
                siblings: vec![],
                value: Hash::get_zero_value(),
                index: 0,
                root: Hash::get_zero_value(),
            }
        } else {
            library.get_group_inclusion_proof(parent_circuit_type, child_circuit_type)?
        };
        let verifier_data = library.get_verifier_data(child_circuit_type)?;
        let zk_proof = deserialize_jtmb_proof::<Hash>(&input.input_proofs[i])?;
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
    L: PsyJTMBCircuitInfoLibrary<Hash>,
    Hash: Q256BitHash + ZeroableHash,
    Hasher: MerkleZeroHasher<Hash>,
>(
    library: &L,
    input: &PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>,
) -> anyhow::Result<PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<Hash>> {
    let proof_results = get_proof_results_for_api_response_with_inclusion_proof::<L, Hasher, _>(library, 1, &input)?;
    Ok(proof_results.into_iter().next().unwrap())
}

pub fn get_two_child_proofs_for_api_response_with_inclusion_proof<
    L: PsyJTMBCircuitInfoLibrary<Hash>,
    Hash: Q256BitHash + ZeroableHash,
    Hasher: MerkleZeroHasher<Hash>,
>(
    library: &L,
    input: &PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>,
) -> anyhow::Result<(
    PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<Hash>,
    PsyWorkerProofResultForCircuitWithWhitelistInclusionProof<Hash>,
)> {
    let mut proof_results = get_proof_results_for_api_response_with_inclusion_proof::<L, Hasher, _>(library, 2, &input)?;
    let second_child = proof_results.pop().unwrap();
    let first_child = proof_results.pop().unwrap();
    Ok((first_child, second_child))
}