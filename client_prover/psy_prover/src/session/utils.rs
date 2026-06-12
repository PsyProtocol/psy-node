use maybe_async::maybe_async;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::{args::ContractCallArgs, data::qhashout::QHashOut};
use psy_config::network_constants::MINING_REWARDS_CONTRACT_ID;
use psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProofWithRewardPreimage;
use serde::{Deserialize, Serialize};

pub const LAST_CLAIMED_CHECKPOINT_SLOT: u64 = 0;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofWithCheckpointV2 {
    pub checkpoint_id: u64,
    pub proof: TagTreeMerkleProofWithRewardPreimage<QHashOut<GoldilocksField>>,
    pub proposed_reward: u64,
}

#[maybe_async]
pub async fn build_claim_calls_for_multi_checkpoints_v2(all_proofs: &[ProofWithCheckpointV2]) -> Vec<ContractCallArgs> {
    let mut contract_call_args = Vec::new();

    let total_proofs = all_proofs.len();
    let mut proof_index = 0;

    let count_10s = total_proofs / 10;
    let mut remaining = total_proofs % 10;

    for _ in 0..count_10s {
        let chunk = &all_proofs[proof_index..proof_index + 10];
        let mut batch_inputs = Vec::new();

        for proof_with_checkpoint in chunk {
            batch_inputs.push(proof_with_checkpoint.checkpoint_id);
        }

        for proof_with_checkpoint in chunk {
            serialize_proof_to_inputs_v2(&proof_with_checkpoint.proof, &mut batch_inputs).await;
        }

        for proof_with_checkpoint in chunk {
            batch_inputs.push(proof_with_checkpoint.proposed_reward);
        }

        contract_call_args.push(ContractCallArgs {
            contract_id: MINING_REWARDS_CONTRACT_ID as u64,
            method_name: "claim_guta_rewards_10".to_string(),
            inputs: batch_inputs,
        });

        proof_index += 10;
    }

    let count_5s = remaining / 5;
    remaining = remaining % 5;
    for _ in 0..count_5s {
        let chunk = &all_proofs[proof_index..proof_index + 5];
        let mut batch_inputs = Vec::new();

        for proof_with_checkpoint in chunk {
            batch_inputs.push(proof_with_checkpoint.checkpoint_id);
        }

        for proof_with_checkpoint in chunk {
            serialize_proof_to_inputs_v2(&proof_with_checkpoint.proof, &mut batch_inputs).await;
        }

        for proof_with_checkpoint in chunk {
            batch_inputs.push(proof_with_checkpoint.proposed_reward);
        }

        contract_call_args.push(ContractCallArgs {
            contract_id: MINING_REWARDS_CONTRACT_ID as u64,
            method_name: "claim_guta_rewards_5".to_string(),
            inputs: batch_inputs,
        });

        proof_index += 5;
    }

    let count_2s = remaining / 2;
    remaining = remaining % 2;
    for _ in 0..count_2s {
        let chunk = &all_proofs[proof_index..proof_index + 2];
        let mut batch_inputs = Vec::new();

        for proof_with_checkpoint in chunk {
            batch_inputs.push(proof_with_checkpoint.checkpoint_id);
        }

        for proof_with_checkpoint in chunk {
            serialize_proof_to_inputs_v2(&proof_with_checkpoint.proof, &mut batch_inputs).await;
        }

        for proof_with_checkpoint in chunk {
            batch_inputs.push(proof_with_checkpoint.proposed_reward);
        }

        contract_call_args.push(ContractCallArgs {
            contract_id: MINING_REWARDS_CONTRACT_ID as u64,
            method_name: "claim_guta_rewards_2".to_string(),
            inputs: batch_inputs,
        });

        proof_index += 2;
    }

    if remaining > 0 {
        let proof_with_checkpoint = &all_proofs[proof_index];
        let mut proof_inputs = Vec::new();

        serialize_proof_to_inputs_v2(&proof_with_checkpoint.proof, &mut proof_inputs).await;

        let mut batch_inputs = vec![proof_with_checkpoint.checkpoint_id];
        batch_inputs.extend(proof_inputs);
        batch_inputs.push(proof_with_checkpoint.proposed_reward);

        contract_call_args.push(ContractCallArgs {
            contract_id: MINING_REWARDS_CONTRACT_ID as u64,
            method_name: "claim_guta_rewards_1".to_string(),
            inputs: batch_inputs,
        });
    }

    contract_call_args
}

#[maybe_async]
pub async fn serialize_proof_to_inputs_v2(proof: &TagTreeMerkleProofWithRewardPreimage<QHashOut<GoldilocksField>>, inputs: &mut Vec<u64>) {
    tracing::debug!("🔍 Serializing proof: {}", serde_json::to_string_pretty(proof).unwrap());

    let inner = &proof.inner;

    // root: 4 elements
    for i in 0..4 {
        inputs.push(inner.root.0.elements[i].0);
    }

    // leaf: left_hash (4) + right_hash (4) + tag_hash (4) = 12 elements
    for i in 0..4 {
        inputs.push(inner.leaf.left.0.elements[i].0);
    }
    for i in 0..4 {
        inputs.push(inner.leaf.right.0.elements[i].0);
    }
    for i in 0..4 {
        inputs.push(inner.leaf.tag.0.elements[i].0);
    }

    // index: 1 element
    inputs.push(inner.index);

    // proof_height: 1 element
    inputs.push(proof.proof_height);

    // reward_tree_tag_preimage: 4 elements
    for i in 0..4 {
        inputs.push(proof.reward_tree_tag_preimage.0.elements[i].0);
    }

    // siblings (already padded)
    for sibling in &inner.siblings {
        for i in 0..4 {
            inputs.push(sibling.sibling.0.elements[i].0);
        }
        for i in 0..4 {
            inputs.push(sibling.parent_tag.0.elements[i].0);
        }
    }
}
