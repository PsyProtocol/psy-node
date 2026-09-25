//! Connection test for the fixed batch path: a `RewardBatchJobCircuit` leaf
//! and the closing `RewardBatchUserCircuit` are proven using only a
//! `UserRewardFinalCircuit` proof plus canonical job witnesses (checkpoint
//! upgrade + spent update). No `RewardClaimLeafCircuit` proof is created here.
//! The batch recursion verifiers must come from the protocol-fixed whitelist.

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField as F,
        types::Field,
    },
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::PoseidonGoldilocksConfig,
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::checkpoint::PsyCheckpointLeaf;
use psy_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic;
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_crypto::hash::{
    merkle::{
        core::{compute_root_merkle_proof_generic, MerkleProofCore},
        tag_tree::{TagTreeMerkleProof, TagTreeMerkleProofWithRewardPreimage, TagTreeNodePreimage, TagTreeProofNode},
        utils::simple_merkle_tree::SimpleMerkleTree,
    },
    traits::{
        hasher::{FieldQHasher, MerkleHasher},
        qhashable::QFieldHashable,
    },
};
use psy_network_circuit::circuits::{
    claim_rewards_l1_batch_job::{spent_key, RewardBatchJobCircuit, RewardBatchJobInput, SPENT_TREE_HEIGHT},
    claim_rewards_l1_batch_job_tree::{BATCH_JOB_CIRCUIT_WHITELIST_HEIGHT, RewardBatchJobCircuitSet},
    claim_rewards_l1_batch_tree::RewardBatchCircuitSet,
    claim_rewards_l1_final::{RewardBatchFinalCircuit, UserRewardFinalCircuit},
    claim_rewards_l1_user_leaf::UserRewardLeafInput,
    claim_rewards_l1_user_tree_set::UserRewardTreeCircuitSet,
};

type C = PoseidonGoldilocksConfig;
type Proof = plonky2::plonk::proof::ProofWithPublicInputs<F, C, 2>;
const D: usize = 2;
const REWARDS: usize = 2;
const HEIGHT: usize = 1;
const AMOUNT: u64 = 10;
const USER_ID: u64 = 41;
const RECIPIENT: u32 = 0x1234;

fn hash(a: u64, b: u64) -> QHashOut<F> {
    QHashOut(HashOut {
        elements: [F::from_canonical_u64(a), F::from_canonical_u64(b), F::ZERO, F::ZERO],
    })
}

struct BatchContext {
    user_final_circuit: UserRewardFinalCircuit<C, D>,
    checkpoint_leaf_hash: QHashOut<F>,
    checkpoint_siblings: Vec<QHashOut<F>>,
    anchor: QHashOut<F>,
}

/// Proves the fixed batch path for one user final proof and one amount per
/// job. Returns the closing user proof, the job set and the batch set.
fn prove_batch_user(
    ctx: &BatchContext,
    user_final: &Proof,
    spent: &mut SimpleMerkleTree<PoseidonHash, QHashOut<F>>,
    amounts: &[u64],
    job_set: &RewardBatchJobCircuitSet<C, D>,
    batch_set: &RewardBatchCircuitSet<C, D>,
) -> anyhow::Result<Proof> {
    let batch_job_circuit = &job_set.leaf;
    let mut previous_root = None;
    let mut job_proofs = Vec::new();
    for (index, amount) in amounts.iter().enumerate() {
        let reward_path_info = (HEIGHT as u64) << 56 | index as u64;
        let checkpoint_upgrade = MerkleProofCore::new_from_params::<PoseidonHash>(
            0,
            ctx.checkpoint_leaf_hash,
            ctx.checkpoint_siblings.clone(),
        );
        let spent_update = spent.set_leaf(spent_key(0, reward_path_info)?, hash(1, 0));
        let input = RewardBatchJobInput {
            checkpoint_id: 0,
            reward_path_info,
            amount: *amount,
            checkpoint_upgrade,
            spent_update,
        };
        let proof = batch_job_circuit.prove(user_final, &input, job_set.whitelist_root)?;
        batch_job_circuit.circuit_data().verify(proof.clone())?;
        if let Some(root) = previous_root {
            assert_eq!(proof.public_inputs[4], root, "spent transition is not linear");
        }
        previous_root = Some(proof.public_inputs[8]);
        job_proofs.push(proof);
    }

    let (left, right) = (&job_proofs[0], &job_proofs[1]);
    let jobs_proof = job_set.tree.prove(
        (left, &job_set.leaf.circuit_data().verifier_only, &job_set.leaf_inclusion),
        (right, &job_set.leaf.circuit_data().verifier_only, &job_set.leaf_inclusion),
    )?;
    job_set.tree.circuit_data().verify(jobs_proof.clone())?;
    assert_eq!(&jobs_proof.public_inputs[..4], &ctx.anchor.0.elements);

    let batch_user_proof = batch_set.user.prove(&jobs_proof, &job_set.tree.circuit_data().verifier_only, user_final, &job_set.tree_inclusion, batch_set.whitelist_root)?;
    batch_set.user.circuit_data().verify(batch_user_proof.clone())?;
    Ok(batch_user_proof)
}

#[test]
fn user_final_proof_connects_to_fixed_batch_job_and_user_circuits() -> anyhow::Result<()> {
    let zero = QHashOut::<F>::ZERO;
    let preimages = (0..REWARDS)
        .map(|index| hash(USER_ID, index as u64 + 1))
        .collect::<Vec<_>>();
    let nodes = preimages
        .iter()
        .map(|preimage| TagTreeNodePreimage {
            left: zero,
            right: zero,
            tag: PoseidonHash::q_two_to_one(*preimage, *preimage),
        })
        .collect::<Vec<_>>();
    // One unused leaf keeps the tree at HEIGHT with zero parent tags.
    let level = nodes
        .iter()
        .map(|node| node.get_node_hash::<PoseidonHash>())
        .chain(std::iter::once(zero))
        .collect::<Vec<_>>();
    let reward_root = <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&level[0], &level[1]);
    let reward_root = <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&reward_root, &zero);
    let reward_proofs = (0..REWARDS)
        .map(|index| {
            let siblings = (0..HEIGHT)
                .map(|l| TagTreeProofNode {
                    sibling: level[(index >> l) ^ 1],
                    parent_tag: zero,
                })
                .collect();
            let proof = TagTreeMerkleProof::new_from_params::<PoseidonHash>(index as u64, nodes[index].clone(), siblings);
            assert_eq!(proof.root, reward_root);
            TagTreeMerkleProofWithRewardPreimage::new(proof, preimages[index])
        })
        .collect::<Vec<_>>();

    let mut checkpoint = PsyCheckpointLeaf::<F>::default();
    checkpoint.stats.guta_fees_collected = F::from_canonical_u64(REWARDS as u64 * AMOUNT);
    checkpoint.stats.pm_jobs_completed.gutas_completed = F::from_canonical_usize(REWARDS);
    checkpoint.stats.pm_rewards_commitment.gutas_root = reward_root;
    let checkpoint_siblings = vec![zero; CHECKPOINT_TREE_HEIGHT as usize];
    let checkpoint_leaf_hash = checkpoint.qfhash::<PoseidonHash>();
    let anchor = compute_root_merkle_proof_generic::<_, PoseidonHash>(checkpoint_leaf_hash, 0, &checkpoint_siblings);

    // Fixed user path: two reward leaves -> fixed user tree -> user final.
    let fixed_user_set = UserRewardTreeCircuitSet::<C, D>::new();
    let user_final_circuit = UserRewardFinalCircuit::<C, D>::new(
        &fixed_user_set.two_leaf.circuit_data().common,
        fixed_user_set.two_leaf.circuit_data().verifier_only.constants_sigmas_cap.height(),
        fixed_user_set.inclusions.root,
    );
    let leaf_inputs = (0..REWARDS)
        .map(|index| UserRewardLeafInput {
            anchor_root: anchor,
            checkpoint_id: 0,
            checkpoint_leaf: checkpoint,
            checkpoint_siblings: checkpoint_siblings.clone(),
            reward_proof: reward_proofs[index].clone(),
            user_id: USER_ID,
            l1_recipient: [RECIPIENT, 0, 0, 0, 0, 0, 0, 0],
            amount: AMOUNT,
            remainder: 0,
        })
        .collect::<Vec<_>>();
    let fixed_result = fixed_user_set.prove(&leaf_inputs)?;
    fixed_user_set.verify(&fixed_result)?;
    let (root_verifier, root_inclusion) = fixed_user_set.aggregate_parts(fixed_result.kind);
    let user_final = user_final_circuit.prove(&fixed_result.proof, root_verifier, root_inclusion, &fixed_result.header)?;
    user_final_circuit.circuit_data().verify(user_final.clone())?;
    assert_eq!(user_final.public_inputs[13], F::from_canonical_u64(REWARDS as u64 * AMOUNT));
    assert_eq!(user_final.public_inputs[14], F::from_canonical_usize(REWARDS));

    let ctx = BatchContext {
        user_final_circuit,
        checkpoint_leaf_hash,
        checkpoint_siblings: checkpoint_siblings.clone(),
        anchor,
    };

    // Fixed batch circuit sets with the protocol-fixed verifier whitelists.
    let job_set = RewardBatchJobCircuitSet::<C, D>::new(ctx.user_final_circuit.circuit_data());
    let batch_set = RewardBatchCircuitSet::<C, D>::new(
        job_set.tree.circuit_data(),
        ctx.user_final_circuit.circuit_data(),
        job_set.whitelist_root,
    );

    // Fixed batch path from the user final proof and canonical job witnesses.
    let mut spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    let amounts = vec![AMOUNT; REWARDS];
    let batch_user_proof = prove_batch_user(&ctx, &user_final, &mut spent, &amounts, &job_set, &batch_set)?;
    assert_eq!(&batch_user_proof.public_inputs[..4], &anchor.0.elements);
    assert_eq!(&batch_user_proof.public_inputs[8..12], &spent.get_root().0.elements);
    assert_eq!(batch_user_proof.public_inputs[20], F::from_canonical_u64(REWARDS as u64 * AMOUNT));
    assert_eq!(
        HashOut {
            elements: batch_user_proof.public_inputs[21..25].try_into().unwrap(),
        },
        batch_set.whitelist_root.0
    );
    let batch_final = RewardBatchFinalCircuit::<C, D>::new(
        &batch_set.tree.circuit_data().common,
        batch_set.tree.circuit_data().verifier_only.constants_sigmas_cap.height(),
        batch_set.whitelist_root,
    );
    let batch_final_proof = batch_final.prove(
        &batch_user_proof,
        &batch_set.user.circuit_data().verifier_only,
        &batch_set.user_inclusion,
    )?;
    batch_final.circuit_data().verify(batch_final_proof.clone())?;
    assert_eq!(batch_final_proof.public_inputs[20], F::from_canonical_u64(REWARDS as u64 * AMOUNT));
    // Swapping in the aggregator fingerprint for the user-closing proof is rejected.
    assert!(batch_final
        .prove(&batch_user_proof, &batch_set.user.circuit_data().verifier_only, &batch_set.tree_inclusion)
        .is_err());

    // A batcher-side amount change breaks the per-job commitment, so the job
    // tree no longer closes against the user's final jobs_commitment.
    let mut tampered_spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    let mut wrong_amounts = amounts.clone();
    wrong_amounts[0] += 1;
    assert!(prove_batch_user(&ctx, &user_final, &mut tampered_spent, &wrong_amounts, &job_set, &batch_set).is_err());

    // A self-built job whitelist that omits the leaf circuit fingerprint is a
    // different root; proofs from that circuit set cannot close here.
    let mut evil_whitelist = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(BATCH_JOB_CIRCUIT_WHITELIST_HEIGHT as u8);
    evil_whitelist.set_leaf(0, QHashOut(get_circuit_fingerprint_generic(&job_set.tree.circuit_data().verifier_only)));
    let evil_root = evil_whitelist.get_root();
    assert_ne!(evil_root, job_set.whitelist_root);
    let evil_batch_set = RewardBatchCircuitSet::<C, D>::new(
        job_set.tree.circuit_data(),
        ctx.user_final_circuit.circuit_data(),
        evil_root,
    );
    let mut evil_spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    assert!(prove_batch_user(&ctx, &user_final, &mut evil_spent, &amounts, &job_set, &evil_batch_set).is_err());

    // Job leaves proven against a different user final verifier (a malicious
    // stand-in) are not in the fixed job whitelist either.
    let mut shifted_user_root = fixed_user_set.inclusions.root;
    shifted_user_root.0.elements[0] += F::ONE;
    let shifted_user_final = UserRewardFinalCircuit::<C, D>::new(
        &fixed_user_set.two_leaf.circuit_data().common,
        fixed_user_set.two_leaf.circuit_data().verifier_only.constants_sigmas_cap.height(),
        shifted_user_root,
    );
    assert_ne!(
        get_circuit_fingerprint_generic(&shifted_user_final.circuit_data().verifier_only),
        get_circuit_fingerprint_generic(&ctx.user_final_circuit.circuit_data().verifier_only)
    );
    let evil_ctx = BatchContext {
        user_final_circuit: shifted_user_final,
        checkpoint_leaf_hash: ctx.checkpoint_leaf_hash,
        checkpoint_siblings: ctx.checkpoint_siblings.clone(),
        anchor: ctx.anchor,
    };
    let evil_job_set = RewardBatchJobCircuitSet::<C, D>::new(evil_ctx.user_final_circuit.circuit_data());
    let evil_job_batch_set = RewardBatchCircuitSet::<C, D>::new(
        evil_job_set.tree.circuit_data(),
        ctx.user_final_circuit.circuit_data(),
        job_set.whitelist_root,
    );
    let mut shifted_spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    assert!(prove_batch_user(&evil_ctx, &user_final, &mut shifted_spent, &amounts, &evil_job_set, &evil_job_batch_set).is_err());

    // A wrong jobs inclusion proof for an otherwise valid batch is rejected.
    let mut retry_spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    let retry_amounts = amounts.clone();
    let batch_job_circuit = RewardBatchJobCircuit::new(ctx.user_final_circuit.circuit_data());
    let mut job_proofs = Vec::new();
    for (index, amount) in retry_amounts.iter().enumerate() {
        let reward_path_info = (HEIGHT as u64) << 56 | index as u64;
        let input = RewardBatchJobInput {
            checkpoint_id: 0,
            reward_path_info,
            amount: *amount,
            checkpoint_upgrade: MerkleProofCore::new_from_params::<PoseidonHash>(
                0,
                ctx.checkpoint_leaf_hash,
                ctx.checkpoint_siblings.clone(),
            ),
            spent_update: retry_spent.set_leaf(spent_key(0, reward_path_info)?, hash(1, 0)),
        };
        job_proofs.push(batch_job_circuit.prove(&user_final, &input, job_set.whitelist_root)?);
    }
    let jobs_proof = job_set.tree.prove(
        (&job_proofs[0], &job_set.leaf.circuit_data().verifier_only, &job_set.leaf_inclusion),
        (&job_proofs[1], &job_set.leaf.circuit_data().verifier_only, &job_set.leaf_inclusion),
    )?;
    // The aggregator fingerprint cannot stand in for the leaf whitelist slot.
    assert!(batch_set
        .user
        .prove(&jobs_proof, &job_set.tree.circuit_data().verifier_only, &user_final, &job_set.leaf_inclusion, batch_set.whitelist_root)
        .is_err());
    Ok(())
}

#[test]
fn single_reward_user_connects_to_single_job_batch_final() -> anyhow::Result<()> {
    let zero = QHashOut::<F>::ZERO;
    let preimage = hash(USER_ID, 1);
    let node = TagTreeNodePreimage {
        left: zero,
        right: zero,
        tag: PoseidonHash::q_two_to_one(preimage, preimage),
    };
    let leaf_hash = node.get_node_hash::<PoseidonHash>();
    // One reward at index 0 in a height-1 tree with zero parent tags.
    let pair = <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&leaf_hash, &zero);
    let reward_root = <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&pair, &zero);
    let proof = TagTreeMerkleProof::new_from_params::<PoseidonHash>(
        0,
        node,
        vec![TagTreeProofNode { sibling: zero, parent_tag: zero }],
    );
    assert_eq!(proof.root, reward_root);
    let reward_proof = TagTreeMerkleProofWithRewardPreimage::new(proof, preimage);

    let mut checkpoint = PsyCheckpointLeaf::<F>::default();
    checkpoint.stats.guta_fees_collected = F::from_canonical_u64(AMOUNT);
    checkpoint.stats.pm_jobs_completed.gutas_completed = F::ONE;
    checkpoint.stats.pm_rewards_commitment.gutas_root = reward_root;
    let checkpoint_siblings = vec![zero; CHECKPOINT_TREE_HEIGHT as usize];
    let checkpoint_leaf_hash = checkpoint.qfhash::<PoseidonHash>();
    let anchor = compute_root_merkle_proof_generic::<_, PoseidonHash>(checkpoint_leaf_hash, 0, &checkpoint_siblings);

    // Single-reward user: fixed SingleLeaf wrapper into the same final
    // verifier as larger user trees.
    let fixed_user_set = UserRewardTreeCircuitSet::<C, D>::new();
    let user_final_circuit = UserRewardFinalCircuit::<C, D>::new(
        &fixed_user_set.two_leaf.circuit_data().common,
        fixed_user_set.two_leaf.circuit_data().verifier_only.constants_sigmas_cap.height(),
        fixed_user_set.inclusions.root,
    );
    let leaf_input = UserRewardLeafInput {
        anchor_root: anchor,
        checkpoint_id: 0,
        checkpoint_leaf: checkpoint,
        checkpoint_siblings: checkpoint_siblings.clone(),
        reward_proof,
        user_id: USER_ID,
        l1_recipient: [RECIPIENT, 0, 0, 0, 0, 0, 0, 0],
        amount: AMOUNT,
        remainder: 0,
    };
    let fixed_result = fixed_user_set.prove(&[leaf_input])?;
    fixed_user_set.verify(&fixed_result)?;
    assert_eq!(fixed_result.header.fields[14], F::ONE);
    let (root_verifier, root_inclusion) = fixed_user_set.aggregate_parts(fixed_result.kind);
    let user_final = user_final_circuit.prove(&fixed_result.proof, root_verifier, root_inclusion, &fixed_result.header)?;
    user_final_circuit.circuit_data().verify(user_final.clone())?;

    // Single-user batch: one job leaf closes directly against the user final
    // proof, then the batch final closes the user proof itself.
    let job_set = RewardBatchJobCircuitSet::<C, D>::new(user_final_circuit.circuit_data());
    let batch_set = RewardBatchCircuitSet::<C, D>::new(
        job_set.tree.circuit_data(),
        user_final_circuit.circuit_data(),
        job_set.whitelist_root,
    );
    let reward_path_info = (HEIGHT as u64) << 56;
    let mut spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    let job_input = RewardBatchJobInput {
        checkpoint_id: 0,
        reward_path_info,
        amount: AMOUNT,
        checkpoint_upgrade: MerkleProofCore::new_from_params::<PoseidonHash>(
            0,
            checkpoint_leaf_hash,
            checkpoint_siblings.clone(),
        ),
        spent_update: spent.set_leaf(spent_key(0, reward_path_info)?, hash(1, 0)),
    };
    let job_proof = job_set.leaf.prove(&user_final, &job_input, job_set.whitelist_root)?;
    job_set.leaf.circuit_data().verify(job_proof.clone())?;

    let batch_user_proof = batch_set.user.prove(&job_proof, &job_set.leaf.circuit_data().verifier_only, &user_final, &job_set.leaf_inclusion, batch_set.whitelist_root)?;
    batch_set.user.circuit_data().verify(batch_user_proof.clone())?;
    assert_eq!(batch_user_proof.public_inputs[20], F::from_canonical_u64(AMOUNT));

    let batch_final = RewardBatchFinalCircuit::<C, D>::new(
        &batch_set.tree.circuit_data().common,
        batch_set.tree.circuit_data().verifier_only.constants_sigmas_cap.height(),
        batch_set.whitelist_root,
    );
    let batch_final_proof = batch_final.prove(
        &batch_user_proof,
        &batch_set.user.circuit_data().verifier_only,
        &batch_set.user_inclusion,
    )?;
    batch_final.circuit_data().verify(batch_final_proof.clone())?;
    assert_eq!(&batch_final_proof.public_inputs[..4], &anchor.0.elements);
    assert_eq!(&batch_final_proof.public_inputs[8..12], &spent.get_root().0.elements);
    assert_eq!(batch_final_proof.public_inputs[20], F::from_canonical_u64(AMOUNT));
    Ok(())
}
