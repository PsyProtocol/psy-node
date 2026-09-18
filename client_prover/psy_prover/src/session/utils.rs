use maybe_async::maybe_async;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::{args::ContractCallArgs, data::qhashout::QHashOut};
use psy_config::network_constants::MINING_REWARDS_CONTRACT_ID;
use psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProofWithRewardPreimage;
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use plonky2::{field::types::Field, hash::hash_types::HashOut};
    use psy_crypto::hash::merkle::tag_tree::{TagTreeNodePreimage, TagTreeProofNode};

    use super::*;

    fn hash(values: [u64; 4]) -> QHashOut<GoldilocksField> {
        QHashOut(HashOut {
            elements: values.map(GoldilocksField::from_canonical_u64),
        })
    }

    fn proof_with_one_sibling() -> TagTreeMerkleProofWithRewardPreimage<QHashOut<GoldilocksField>> {
        TagTreeMerkleProofWithRewardPreimage {
            inner: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof {
                root: hash([1, 2, 3, 4]),
                leaf: TagTreeNodePreimage {
                    left: hash([5, 6, 7, 8]),
                    right: hash([9, 10, 11, 12]),
                    tag: hash([13, 14, 15, 16]),
                },
                index: 17,
                siblings: vec![TagTreeProofNode {
                    sibling: hash([23, 24, 25, 26]),
                    parent_tag: hash([27, 28, 29, 30]),
                }],
            },
            proof_height: 18,
            reward_tree_tag_preimage: hash([19, 20, 21, 22]),
        }
    }

    #[tokio::test]
    async fn serializes_proof_fields_in_contract_order() {
        let mut inputs = vec![99];

        serialize_proof_to_inputs_v2(&proof_with_one_sibling(), &mut inputs).await;

        assert_eq!(
            inputs,
            vec![99, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,]
        );
    }

    #[tokio::test]
    async fn empty_proof_list_produces_no_calls() {
        assert!(build_claim_calls_for_multi_checkpoints_v2(&[]).await.is_empty());
    }

    #[tokio::test]
    async fn batches_claims_greedily_as_ten_five_two_and_one() {
        let proof = TagTreeMerkleProofWithRewardPreimage::new(psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(), QHashOut::ZERO);
        let proofs = (0..18)
            .map(|index| ProofWithCheckpointV2 {
                checkpoint_id: 100 + index,
                proof: proof.clone(),
                proposed_reward: 1_000 + index,
            })
            .collect::<Vec<_>>();

        let calls = build_claim_calls_for_multi_checkpoints_v2(&proofs).await;

        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls.iter().map(|call| call.method_name.as_str()).collect::<Vec<_>>(),
            vec![
                "claim_guta_rewards_10",
                "claim_guta_rewards_5",
                "claim_guta_rewards_2",
                "claim_guta_rewards_1"
            ]
        );
        for (call, batch_size) in calls.iter().zip([10usize, 5, 2, 1]) {
            assert_eq!(call.contract_id, MINING_REWARDS_CONTRACT_ID as u64);
            assert_eq!(call.inputs.len(), batch_size * 24);
        }
        assert_eq!(&calls[0].inputs[..10], &(100..110).collect::<Vec<_>>());
        assert_eq!(&calls[0].inputs[calls[0].inputs.len() - 10..], &(1_000..1_010).collect::<Vec<_>>());
        assert_eq!(calls[3].inputs[0], 117);
        assert_eq!(*calls[3].inputs.last().unwrap(), 1_017);
    }

    #[tokio::test]
    async fn batching_boundaries_choose_expected_contract_methods() {
        let proof = TagTreeMerkleProofWithRewardPreimage::new(psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(), QHashOut::ZERO);
        let cases: &[(usize, &[&str])] = &[
            (1, &["claim_guta_rewards_1"]),
            (2, &["claim_guta_rewards_2"]),
            (3, &["claim_guta_rewards_2", "claim_guta_rewards_1"]),
            (5, &["claim_guta_rewards_5"]),
            (6, &["claim_guta_rewards_5", "claim_guta_rewards_1"]),
            (10, &["claim_guta_rewards_10"]),
            (11, &["claim_guta_rewards_10", "claim_guta_rewards_1"]),
            (20, &["claim_guta_rewards_10", "claim_guta_rewards_10"]),
            (
                23,
                &[
                    "claim_guta_rewards_10",
                    "claim_guta_rewards_10",
                    "claim_guta_rewards_2",
                    "claim_guta_rewards_1",
                ],
            ),
        ];

        for (count, expected_methods) in cases {
            let proofs = (0..*count)
                .map(|index| ProofWithCheckpointV2 {
                    checkpoint_id: index as u64,
                    proof: proof.clone(),
                    proposed_reward: 100 + index as u64,
                })
                .collect::<Vec<_>>();
            let calls = build_claim_calls_for_multi_checkpoints_v2(&proofs).await;
            assert_eq!(
                calls.iter().map(|call| call.method_name.as_str()).collect::<Vec<_>>(),
                *expected_methods,
                "unexpected batching for {count} proofs"
            );
        }
    }
}
