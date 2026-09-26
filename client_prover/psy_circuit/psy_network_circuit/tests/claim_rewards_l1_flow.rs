//! End-to-end fixed-path test: five users with 1/3/5/7/9 rewards each prove
//! through the fixed user tree set, and the batcher assembles fixed batch job
//! leaves, job trees, per-user closings, and the fixed batch tree plus final.
//! No legacy claim-leaf or dynamic batch circuit is used.

use std::{fs, time::Instant};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField as F,
        types::{Field, PrimeField64},
    },
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::{circuit_data::VerifierOnlyCircuitData, config::{Hasher, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs},
};
use psy_client_common::data::qhashout::QHashOut;
use parth_core::pgoldilocks::QHashOut as ParthQHashOut;
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
    claim_rewards_l1_batch_job::{spent_key, RewardBatchJobInput, SPENT_TREE_HEIGHT},
    claim_rewards_l1_batch_job_tree::RewardBatchJobCircuitSet,
    claim_rewards_l1_batch_tree::RewardBatchCircuitSet,
    claim_rewards_l1_final::{RewardBatchFinalCircuit, UserRewardFinalCircuit},
    claim_rewards_l1_user_leaf::UserRewardLeafInput,
    claim_rewards_l1_user_tree_set::UserRewardTreeCircuitSet,
};
use psy_plonky2_circuits::bridge::circuits::bridge_wrap::{
    RewardBatchL1Input, RewardBatchUserInput, RewardBatchWrapCircuit,
};

type C = PoseidonGoldilocksConfig;
type Proof = ProofWithPublicInputs<F, C, 2>;
type Verifier = VerifierOnlyCircuitData<C, 2>;
type Inclusion = MerkleProofCore<QHashOut<F>>;
const D: usize = 2;
const COUNTS: [usize; 5] = [1, 3, 5, 7, 9];
const JOBS: usize = 25;
const HEIGHT: usize = 5;
const AMOUNT: u64 = 10;

fn aggregate_commitments(mut nodes: Vec<HashOut<F>>) -> HashOut<F> {
    while nodes.len() > 1 {
        let mut next = Vec::with_capacity((nodes.len() + 1) / 2);
        let mut it = nodes.into_iter();
        while let Some(left) = it.next() {
            next.push(match it.next() {
                Some(right) => <PoseidonHash as Hasher<F>>::two_to_one(left, right),
                None => left,
            });
        }
        nodes = next;
    }
    nodes.pop().expect("nonempty batch")
}

fn l1_reward_commitment(user_id: u64, recipient: u32, amount: u64) -> HashOut<F> {
    let mut fields = [F::ZERO; 10];
    fields[0] = F::from_canonical_u64(user_id);
    fields[1] = F::from_canonical_u32(recipient);
    fields[9] = F::from_canonical_u64(amount);
    PoseidonHash::hash_no_pad(&fields)
}

fn hash(a: u64, b: u64) -> QHashOut<F> {
    QHashOut(HashOut {
        elements: [F::from_canonical_u64(a), F::from_canonical_u64(b), F::ZERO, F::ZERO],
    })
}

/// Canonical job tree shape: pair up left to right each layer; a leftover
/// odd node is promoted unchanged (leaf and aggregator share circuit shape).
fn aggregate_jobs(job_set: &RewardBatchJobCircuitSet<C, D>, leaves: Vec<Proof>) -> anyhow::Result<(Proof, Verifier, Inclusion)> {
    let leaf_vd = job_set.leaf.circuit_data().verifier_only.clone();
    let mut nodes: Vec<(Proof, Verifier, Inclusion)> = leaves
        .into_iter()
        .map(|proof| (proof, leaf_vd.clone(), job_set.leaf_inclusion.clone()))
        .collect();
    while nodes.len() > 1 {
        let mut next = Vec::with_capacity((nodes.len() + 1) / 2);
        let mut it = nodes.into_iter();
        while let Some(left) = it.next() {
            let Some(right) = it.next() else {
                next.push(left);
                break;
            };
            let proof = job_set.tree.prove((&left.0, &left.1, &left.2), (&right.0, &right.1, &right.2))?;
            job_set.tree.circuit_data().verify(proof.clone())?;
            next.push((proof, job_set.tree.circuit_data().verifier_only.clone(), job_set.tree_inclusion.clone()));
        }
        nodes = next;
    }
    Ok(nodes.pop().unwrap())
}

/// Canonical user tree shape over per-user closing proofs.
fn aggregate_users(batch_set: &RewardBatchCircuitSet<C, D>, users: Vec<Proof>) -> anyhow::Result<(Proof, Verifier, Inclusion)> {
    let user_vd = batch_set.user.circuit_data().verifier_only.clone();
    let mut nodes: Vec<(Proof, Verifier, Inclusion)> = users
        .into_iter()
        .map(|proof| (proof, user_vd.clone(), batch_set.user_inclusion.clone()))
        .collect();
    let mut level = 0;
    while nodes.len() > 1 {
        let started = Instant::now();
        let input_count = nodes.len();
        let mut next = Vec::with_capacity((nodes.len() + 1) / 2);
        let mut it = nodes.into_iter();
        while let Some(left) = it.next() {
            let Some(right) = it.next() else {
                next.push(left);
                break;
            };
            let proof = batch_set.tree.prove((&left.0, &left.1, &left.2), (&right.0, &right.1, &right.2))?;
            batch_set.tree.circuit_data().verify(proof.clone())?;
            next.push((proof, batch_set.tree.circuit_data().verifier_only.clone(), batch_set.tree_inclusion.clone()));
        }
        nodes = next;
        println!("batch user tree level {} prove+verify: {} -> {} nodes, elapsed {:?}", level, input_count, nodes.len(), started.elapsed());
        level += 1;
    }
    Ok(nodes.pop().unwrap())
}

struct BatchFixture {
    checkpoint: PsyCheckpointLeaf<F>,
    checkpoint_siblings: Vec<QHashOut<F>>,
    checkpoint_leaf_hash: QHashOut<F>,
    anchor: QHashOut<F>,
    reward_proofs: Vec<TagTreeMerkleProofWithRewardPreimage<QHashOut<F>>>,
}

fn build_fixture() -> BatchFixture {
    let user_ids = [41u64, 42, 43, 44, 45];
    let zero = QHashOut::<F>::ZERO;
    let preimages = (0..JOBS)
        .map(|index| {
            let user = COUNTS
                .iter()
                .scan(0, |end, count| {
                    *end += count;
                    Some(*end)
                })
                .position(|end| index < end)
                .unwrap();
            hash(user_ids[user], index as u64 + 1)
        })
        .collect::<Vec<_>>();
    let nodes = preimages
        .iter()
        .map(|preimage| TagTreeNodePreimage {
            left: zero,
            right: zero,
            tag: PoseidonHash::q_two_to_one(*preimage, *preimage),
        })
        .collect::<Vec<_>>();
    // Pad the reward tree to 2^HEIGHT leaves. Each parent has a zero tag.
    let mut levels = vec![nodes
        .iter()
        .map(|node| node.get_node_hash::<PoseidonHash>())
        .chain(std::iter::repeat(zero).take((1 << HEIGHT) - JOBS))
        .collect::<Vec<_>>()];
    for _ in 0..HEIGHT {
        let previous = levels.last().unwrap();
        let next = previous
            .chunks_exact(2)
            .map(|pair| {
                let children = <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&pair[0], &pair[1]);
                <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&children, &zero)
            })
            .collect();
        levels.push(next);
    }
    let reward_root = levels[HEIGHT][0];
    let reward_proofs = (0..JOBS)
        .map(|index| {
            let siblings = (0..HEIGHT)
                .map(|level| TagTreeProofNode {
                    sibling: levels[level][(index >> level) ^ 1],
                    parent_tag: zero,
                })
                .collect();
            let proof = TagTreeMerkleProof::new_from_params::<PoseidonHash>(index as u64, nodes[index].clone(), siblings);
            assert_eq!(proof.root, reward_root);
            TagTreeMerkleProofWithRewardPreimage::new(proof, preimages[index])
        })
        .collect::<Vec<_>>();

    let mut checkpoint = PsyCheckpointLeaf::<F>::default();
    checkpoint.stats.guta_fees_collected = F::from_canonical_u64(JOBS as u64 * AMOUNT);
    checkpoint.stats.pm_jobs_completed.gutas_completed = F::from_canonical_usize(JOBS);
    checkpoint.stats.pm_rewards_commitment.gutas_root = reward_root;
    // The same checkpoint leaf is appended at IDs 0 and 1 in this fixture,
    // giving two checkpoint IDs under one selected current anchor.
    let mut checkpoint_siblings = vec![zero; CHECKPOINT_TREE_HEIGHT as usize];
    let checkpoint_leaf_hash = checkpoint.qfhash::<PoseidonHash>();
    checkpoint_siblings[0] = checkpoint_leaf_hash;
    let anchor = compute_root_merkle_proof_generic::<_, PoseidonHash>(checkpoint_leaf_hash, 0, &checkpoint_siblings);
    BatchFixture { checkpoint, checkpoint_siblings, checkpoint_leaf_hash, anchor, reward_proofs }
}

/// One job witness: checkpoint upgrade under the batch anchor plus the spent
/// update for this job's reward path.
fn job_witness(
    fixture: &BatchFixture,
    checkpoint_id: u32,
    job_index: usize,
    spent: &mut SimpleMerkleTree<PoseidonHash, QHashOut<F>>,
) -> anyhow::Result<RewardBatchJobInput<F>> {
    let reward_path_info = (HEIGHT as u64) << 56 | job_index as u64;
    Ok(RewardBatchJobInput {
        checkpoint_id,
        reward_path_info,
        amount: AMOUNT,
        checkpoint_upgrade: MerkleProofCore::new_from_params::<PoseidonHash>(
            checkpoint_id as u64,
            fixture.checkpoint_leaf_hash,
            fixture.checkpoint_siblings.clone(),
        ),
        spent_update: spent.set_leaf(spent_key(checkpoint_id, reward_path_info)?, hash(1, 0)),
    })
}

#[test]
fn five_users_with_one_three_five_seven_nine_rewards_then_batch() -> anyhow::Result<()> {
    let fixture = build_fixture();
    let user_ids = [41u64, 42, 43, 44, 45];
    let recipients = [0x1234u32, 0x5678, 0x9abc, 0xdef0, 0x1357];

    let fixed_user_set = UserRewardTreeCircuitSet::<C, D>::new();
    let user_final_circuit = UserRewardFinalCircuit::<C, D>::new(
        &fixed_user_set.two_leaf.circuit_data().common,
        fixed_user_set.two_leaf.circuit_data().verifier_only.constants_sigmas_cap.height(),
        fixed_user_set.inclusions.root,
    );
    let job_set = RewardBatchJobCircuitSet::<C, D>::new(user_final_circuit.circuit_data());
    let batch_set = RewardBatchCircuitSet::<C, D>::new(
        job_set.tree.circuit_data(),
        user_final_circuit.circuit_data(),
        job_set.whitelist_root,
    );
    let batch_final = RewardBatchFinalCircuit::<C, D>::new(
        &batch_set.tree.circuit_data().common,
        batch_set.tree.circuit_data().verifier_only.constants_sigmas_cap.height(),
        batch_set.whitelist_root,
    );
    let batch_degrees = [
        ("batch job leaf", job_set.leaf.circuit_data().common.degree_bits()),
        ("batch job tree", job_set.tree.circuit_data().common.degree_bits()),
        ("batch user closing", batch_set.user.circuit_data().common.degree_bits()),
        ("batch user tree", batch_set.tree.circuit_data().common.degree_bits()),
    ];
    for (name, degree_bits) in batch_degrees {
        println!("{} degree_bits: {}", name, degree_bits);
    }

    // A single reward uses the fixed SingleLeaf wrapper and the same final
    // verifier as larger user reward trees.
    let single_input = UserRewardLeafInput {
        anchor_root: fixture.anchor,
        checkpoint_id: 0,
        checkpoint_leaf: fixture.checkpoint,
        checkpoint_siblings: fixture.checkpoint_siblings.clone(),
        reward_proof: fixture.reward_proofs[0].clone(),
        user_id: user_ids[0],
        l1_recipient: [recipients[0], 0, 0, 0, 0, 0, 0, 0],
        amount: AMOUNT,
        remainder: 0,
    };
    let started = Instant::now();
    let single_result = fixed_user_set.prove(&[single_input])?;
    println!("single reward user tree prove: elapsed {:?}", started.elapsed());
    fixed_user_set.verify(&single_result)?;
    assert_eq!(&single_result.proof.public_inputs[4..8], &fixed_user_set.inclusions.root.0.elements);
    assert_eq!(&single_result.header.fields[..4], &fixture.anchor.0.elements);
    assert_eq!(single_result.header.fields[13], F::from_canonical_u64(AMOUNT));
    assert_eq!(single_result.header.fields[14], F::ONE);
    let (single_verifier, single_inclusion) = fixed_user_set.aggregate_parts(single_result.kind);
    let mut wrong_single_header = single_result.header.clone();
    wrong_single_header.fields[13] += F::ONE;
    assert!(user_final_circuit
        .prove(&single_result.proof, single_verifier, single_inclusion, &wrong_single_header)
        .is_err());
    let single_final = user_final_circuit.prove(
        &single_result.proof,
        single_verifier,
        single_inclusion,
        &single_result.header,
    )?;
    user_final_circuit.circuit_data().verify(single_final)?;

    // Fixed user path per user: reward leaves -> fixed user tree -> user final.
    let mut user_finals = Vec::new();
    let mut next_job = 0;
    for user in 0..COUNTS.len() {
        let leaf_inputs = (0..COUNTS[user])
            .map(|_| {
                let job_index = next_job;
                let checkpoint_id = (job_index % 2) as u64;
                next_job += 1;
                Ok(UserRewardLeafInput {
                    anchor_root: fixture.anchor,
                    checkpoint_id,
                    checkpoint_leaf: fixture.checkpoint,
                    checkpoint_siblings: fixture.checkpoint_siblings.clone(),
                    reward_proof: fixture.reward_proofs[job_index].clone(),
                    user_id: user_ids[user],
                    l1_recipient: [recipients[user], 0, 0, 0, 0, 0, 0, 0],
                    amount: AMOUNT,
                    remainder: 0,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let started = Instant::now();
        let fixed_result = fixed_user_set.prove(&leaf_inputs)?;
        println!("user {} fixed tree prove: elapsed {:?}", user, started.elapsed());
        fixed_user_set.verify(&fixed_result)?;
        assert_eq!(fixed_result.header.fields[13], F::from_canonical_usize(COUNTS[user] * AMOUNT as usize));
        assert_eq!(fixed_result.header.fields[14], F::from_canonical_usize(COUNTS[user]));
        let (root_verifier, root_inclusion) = fixed_user_set.aggregate_parts(fixed_result.kind);
        let fixed_final = user_final_circuit.prove(
            &fixed_result.proof,
            root_verifier,
            root_inclusion,
            &fixed_result.header,
        )?;
        user_final_circuit.circuit_data().verify(fixed_final.clone())?;
        assert_eq!(fixed_final.public_inputs[13], F::from_canonical_usize(COUNTS[user] * AMOUNT as usize));
        assert_eq!(fixed_final.public_inputs[14], F::from_canonical_usize(COUNTS[user]));
        user_finals.push(fixed_final);
    }
    assert_eq!(next_job, JOBS);

    // Batcher side: one fixed job leaf per reward, aggregated per user, then
    // closed against that user's final proof. Spent updates chain linearly
    // across all jobs in canonical job order.
    let mut spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    let initial_spent_root = spent.get_root();
    let mut next_job = 0;
    let mut user_closings = Vec::new();
    let mut user_job_roots: Vec<(Proof, Verifier, Inclusion)> = Vec::new();
    for user in 0..COUNTS.len() {
        let user_started = Instant::now();
        let job_witnesses = (0..COUNTS[user])
            .map(|_| {
                let job_index = next_job;
                let checkpoint_id = (job_index % 2) as u32;
                next_job += 1;
                job_witness(&fixture, checkpoint_id, job_index, &mut spent)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        println!("batcher user {} job witnesses: {} jobs, elapsed {:?}", user, COUNTS[user], user_started.elapsed());
        let started = Instant::now();
        let leaves = job_witnesses
            .iter()
            .map(|input| job_set.leaf.prove(&user_finals[user], input, job_set.whitelist_root))
            .collect::<anyhow::Result<Vec<_>>>()?;
        for proof in &leaves {
            job_set.leaf.circuit_data().verify(proof.clone())?;
        }
        println!("batcher user {} job leaves prove+verify: elapsed {:?}", user, started.elapsed());
        if user == 1 {
            let started = Instant::now();
            let mut evil = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(2);
            evil.set_leaf(0, QHashOut(get_circuit_fingerprint_generic(&job_set.leaf.circuit_data().verifier_only)));
            evil.set_leaf(1, QHashOut(get_circuit_fingerprint_generic(&job_set.tree.circuit_data().verifier_only)));
            evil.set_leaf(2, hash(777, 778));
            let evil_root = evil.get_root();
            assert_ne!(evil_root, job_set.whitelist_root);
            let evil_left = job_set.leaf.prove(&user_finals[user], &job_witnesses[0], evil_root)?;
            let evil_right = job_set.leaf.prove(&user_finals[user], &job_witnesses[1], evil_root)?;
            let evil_pair = job_set.tree.prove(
                (&evil_left, &job_set.leaf.circuit_data().verifier_only, &evil.get_leaf(0)),
                (&evil_right, &job_set.leaf.circuit_data().verifier_only, &evil.get_leaf(0)),
            )?;
            job_set.tree.circuit_data().verify(evil_pair.clone())?;
            assert!(job_set.tree.prove(
                (&evil_pair, &job_set.tree.circuit_data().verifier_only, &job_set.tree_inclusion),
                (&leaves[2], &job_set.leaf.circuit_data().verifier_only, &job_set.leaf_inclusion),
            ).is_err(), "a deep job subtree with a self-built whitelist must be rejected");
            println!("batcher deep job whitelist rejection: elapsed {:?}", started.elapsed());
        }
        let started = Instant::now();
        let (jobs_root, jobs_vd, jobs_inclusion) = aggregate_jobs(&job_set, leaves)?;
        println!("batcher user {} job tree prove+verify: elapsed {:?}", user, started.elapsed());
        let started = Instant::now();
        let closing = batch_set
            .user
            .prove(&jobs_root, &jobs_vd, &user_finals[user], &jobs_inclusion, batch_set.whitelist_root)?;
        batch_set.user.circuit_data().verify(closing.clone())?;
        println!("batcher user {} closing prove+verify: elapsed {:?}; total {:?}", user, started.elapsed(), user_started.elapsed());
        user_job_roots.push((jobs_root, jobs_vd, jobs_inclusion));
        user_closings.push(closing);
    }
    assert_eq!(next_job, JOBS);

    let started = Instant::now();
    let mut evil_batch = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(2);
    evil_batch.set_leaf(0, QHashOut(get_circuit_fingerprint_generic(&batch_set.user.circuit_data().verifier_only)));
    evil_batch.set_leaf(1, QHashOut(get_circuit_fingerprint_generic(&batch_set.tree.circuit_data().verifier_only)));
    evil_batch.set_leaf(2, hash(779, 780));
    let evil_batch_root = evil_batch.get_root();
    assert_ne!(evil_batch_root, batch_set.whitelist_root);
    let evil_users = (0..2).map(|user| batch_set.user.prove(
        &user_job_roots[user].0,
        &user_job_roots[user].1,
        &user_finals[user],
        &user_job_roots[user].2,
        evil_batch_root,
    )).collect::<anyhow::Result<Vec<_>>>()?;
    let evil_pair = batch_set.tree.prove(
        (&evil_users[0], &batch_set.user.circuit_data().verifier_only, &evil_batch.get_leaf(0)),
        (&evil_users[1], &batch_set.user.circuit_data().verifier_only, &evil_batch.get_leaf(0)),
    )?;
    batch_set.tree.circuit_data().verify(evil_pair.clone())?;
    assert!(batch_set.tree.prove(
        (&evil_pair, &batch_set.tree.circuit_data().verifier_only, &batch_set.tree_inclusion),
        (&user_closings[2], &batch_set.user.circuit_data().verifier_only, &batch_set.user_inclusion),
    ).is_err(), "a deep batch subtree with a self-built whitelist must be rejected");
    println!("batcher deep batch whitelist rejection: elapsed {:?}", started.elapsed());

    // Negative: a batcher-side amount change breaks the per-job commitment,
    // so the user's job tree no longer closes against the final jobs_commitment.
    let started = Instant::now();
    let mut tampered_spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    let mut wrong_witnesses = (0..COUNTS[1])
        .map(|offset| {
            let job_index = COUNTS[0] + offset;
            job_witness(&fixture, (job_index % 2) as u32, job_index, &mut tampered_spent)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    wrong_witnesses[0].amount += 1;
    let wrong_leaves = wrong_witnesses
        .iter()
        .map(|input| job_set.leaf.prove(&user_finals[1], input, job_set.whitelist_root))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let (wrong_jobs_root, wrong_vd, wrong_inclusion) = aggregate_jobs(&job_set, wrong_leaves)?;
    assert!(batch_set
        .user
        .prove(&wrong_jobs_root, &wrong_vd, &user_finals[1], &wrong_inclusion, batch_set.whitelist_root)
        .is_err());
    println!("batch close with wrong amount rejected after {:?}", started.elapsed());

    // Negative: re-anchoring against a checkpoint tree where checkpoint 0's
    // leaf was replaced. Upgrade proofs still share the anchor root, but the
    // job commitment no longer matches the user's final jobs_commitment.
    let replaced_leaf_hash = hash(777, 778);
    let mut replaced_spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    let replaced_witnesses = (0..COUNTS[1])
        .map(|offset| {
            let job_index = COUNTS[0] + offset;
            let checkpoint_id = (job_index % 2) as u32;
            let mut input = job_witness(&fixture, checkpoint_id, job_index, &mut replaced_spent)?;
            // Replace checkpoint 0's leaf at the target root: checkpoint 0
            // opens the replaced leaf, checkpoint 1 opens the original leaf
            // against the replaced sibling, so every upgrade resolves to one
            // common root that is not the anchor the user proved against.
            let value = if checkpoint_id == 0 { replaced_leaf_hash } else { fixture.checkpoint_leaf_hash };
            let mut siblings = fixture.checkpoint_siblings.clone();
            siblings[0] = if checkpoint_id == 0 {
                fixture.checkpoint_leaf_hash
            } else {
                replaced_leaf_hash
            };
            input.checkpoint_upgrade =
                MerkleProofCore::new_from_params::<PoseidonHash>(checkpoint_id as u64, value, siblings);
            Ok(input)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    assert_eq!(
        replaced_witnesses[0].checkpoint_upgrade.root,
        replaced_witnesses[1].checkpoint_upgrade.root
    );
    assert_ne!(
        replaced_witnesses[0].checkpoint_upgrade.root, fixture.anchor,
        "replaced-leaf upgrades resolve to a different checkpoint root"
    );
    // The batch job leaf rejects the foreign anchor before any aggregation.
    let replaced_result = replaced_witnesses
        .iter()
        .map(|input| job_set.leaf.prove(&user_finals[1], input, job_set.whitelist_root))
        .collect::<anyhow::Result<Vec<_>>>();
    assert!(replaced_result.is_err());

    // Negative: a repeated job in one batch leaves the spent leaf already one.
    let mut double_spent = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(SPENT_TREE_HEIGHT as u8);
    let first = job_witness(&fixture, 0, 0, &mut double_spent)?;
    assert!(job_set.leaf.prove(&user_finals[0], &first, job_set.whitelist_root).is_ok());
    let repeat = RewardBatchJobInput {
        spent_update: double_spent.set_leaf(spent_key(0, first.reward_path_info)?, hash(1, 0)),
        ..first.clone()
    };
    assert!(job_set.leaf.prove(&user_finals[0], &repeat, job_set.whitelist_root).is_err());

    // Reconstruct the L1 rewards calldata from the proved user finals. The
    // closing proof hashes user_id, recipient[8], and amount into rewardsRoot.
    let l1_rewards = user_finals.iter().enumerate().map(|(user, proof)| {
        assert_eq!(proof.public_inputs[4], F::from_canonical_u64(user_ids[user]));
        assert_eq!(proof.public_inputs[5], F::from_canonical_u32(recipients[user]));
        assert!(proof.public_inputs[6..13].iter().all(|limb| *limb == F::ZERO));
        let amount = (COUNTS[user] as u64) * AMOUNT;
        assert_eq!(proof.public_inputs[13], F::from_canonical_u64(amount));
        (recipients[user], amount)
    }).collect::<Vec<_>>();
    assert_eq!(l1_rewards.len(), COUNTS.len());
    assert!(l1_rewards.iter().all(|(recipient, amount)| *recipient != 0 && *amount != 0));
    for i in 0..l1_rewards.len() {
        assert!(!l1_rewards[..i].iter().any(|(recipient, _)| *recipient == l1_rewards[i].0));
    }
    let calldata_total: u64 = l1_rewards.iter().map(|(_, amount)| amount).sum();
    let rewards_root = aggregate_commitments(l1_rewards.iter().enumerate().map(|(user, &(recipient, amount))| {
        let commitment = l1_reward_commitment(user_ids[user], recipient, amount);
        assert_eq!(commitment, PoseidonHash::hash_no_pad(&user_finals[user].public_inputs[4..14]));
        commitment
    }).collect());
    let jobs_root = aggregate_commitments(user_closings.iter().map(|proof| {
        HashOut { elements: proof.public_inputs[16..20].try_into().unwrap() }
    }).collect());

    // Fixed batch tree over the five per-user closings, then the final.
    let (batch_root, batch_vd, batch_inclusion) = aggregate_users(&batch_set, user_closings)?;
    let started = Instant::now();
    let batch_proof = batch_final.prove(&batch_root, &batch_vd, &batch_inclusion)?;
    println!("batch final prove: {} users, {} jobs, elapsed {:?}", COUNTS.len(), JOBS, started.elapsed());
    batch_final.circuit_data().verify(batch_proof.clone())?;
    assert_eq!(&batch_proof.public_inputs[..4], &fixture.anchor.0.elements);
    assert_eq!(&batch_proof.public_inputs[4..8], &initial_spent_root.0.elements);
    assert_eq!(&batch_proof.public_inputs[8..12], &spent.get_root().0.elements);
    assert_eq!(&batch_proof.public_inputs[12..16], &rewards_root.elements);
    assert_eq!(&batch_proof.public_inputs[16..20], &jobs_root.elements);
    assert_eq!(batch_proof.public_inputs[20], F::from_canonical_u64(calldata_total));
    assert_eq!(calldata_total, JOBS as u64 * AMOUNT);

    // The Groth16-facing wrapper must open the final Poseidon rewards root
    // against exactly the user list that the L1 call will encode.
    let wrap = RewardBatchWrapCircuit::new(
        &batch_final.circuit_data().common,
        ParthQHashOut(get_circuit_fingerprint_generic(&batch_final.circuit_data().verifier_only)),
        batch_final.circuit_data().verifier_only.constants_sigmas_cap.height(),
    );
    let ledger_address_hex = std::env::var("PSY_CLAIM_L1_LEDGER_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000001234".to_string());
    let address_hex = ledger_address_hex.trim_start_matches("0x");
    anyhow::ensure!(address_hex.len() == 40, "L1 ledger address must be 20 bytes");
    let mut ledger_address = [0u32; 5];
    for (limb, target) in ledger_address.iter_mut().enumerate() {
        let end = 40 - limb * 8;
        *target = u32::from_str_radix(&address_hex[end - 8..end], 16)?;
    }
    let l1_input = RewardBatchL1Input {
        chain_id: 31337,
        ledger_address,
        batch_id: 0,
        users: l1_rewards.iter().enumerate().map(|(user, &(recipient, amount))| RewardBatchUserInput {
            user_id: user_ids[user], recipient: [recipient, 0, 0, 0, 0], amount,
        }).collect(),
    };
    let wrapped = wrap.prove_wrapper(&batch_final.circuit_data().verifier_only, &batch_proof, &l1_input)?;
    wrap.circuit_data.verify(wrapped.clone())?;
    let wrapper_digest = l1_input.digest(&batch_proof.public_inputs)?;
    let mut changed_l1 = l1_input.clone();
    changed_l1.users[0].amount += 1;
    assert!(wrap.prove_wrapper(&batch_final.circuit_data().verifier_only, &batch_proof, &changed_l1).is_err());

    changed_l1 = l1_input.clone();
    changed_l1.users[0].recipient[0] += 1;
    assert!(wrap.prove_wrapper(&batch_final.circuit_data().verifier_only, &batch_proof, &changed_l1).is_err());

    let mut groth16_calldata = None;
    if let Ok(path) = std::env::var("PSY_CLAIM_L1_GROTH16_KEYSTORE") {
        let keystore = std::path::Path::new(&path);
        fs::create_dir_all(keystore)?;
        if std::env::var("PSY_CLAIM_L1_REGENERATE_GROTH16").as_deref() == Ok("1") {
            for name in ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"] {
                let file = keystore.join(name);
                if file.exists() {
                    fs::remove_file(file)?;
                }
            }
        }
        let shared = wrap.into_shared_groth16_wrapper(format!("{}/", keystore.display()));
        let groth16 = shared.prove_groth16(&wrapped, None)?;
        let expected_hi = u128::from_be_bytes(wrapper_digest[..16].try_into()?);
        let expected_lo = u128::from_be_bytes(wrapper_digest[16..].try_into()?);
        assert_eq!(u128::from_str_radix(&groth16.public_inputs[0], 16)?, expected_hi);
        assert_eq!(u128::from_str_radix(&groth16.public_inputs[1], 16)?, expected_lo);
        groth16_calldata = Some([
            &groth16.pi_a[0], &groth16.pi_a[1],
            &groth16.pi_b[0][1], &groth16.pi_b[0][0],
            &groth16.pi_b[1][1], &groth16.pi_b[1][0],
            &groth16.pi_c[0], &groth16.pi_c[1],
        ].map(|value| format!("0x{value}")));
        for name in ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"] {
            assert!(keystore.join(name).is_file(), "missing {name}");
        }
        println!("reward batch Groth16 keystore: {}", keystore.display());
    }

    // A different calldata amount or recipient changes rewardsRoot. The
    // wrapper also rejects both changes against the proved rewardsRoot above.
    for tampered in [(l1_rewards[0].0, l1_rewards[0].1 + 1), (l1_rewards[0].0 + 1, l1_rewards[0].1)] {
        let mut changed_rewards = l1_rewards.clone();
        changed_rewards[0] = tampered;
        let changed_root = aggregate_commitments(changed_rewards.iter().enumerate().map(|(user, &(recipient, amount))| {
            l1_reward_commitment(user_ids[user], recipient, amount)
        }).collect());
        assert_ne!(changed_root, rewards_root);
    }

    if let Ok(path) = std::env::var("PSY_CLAIM_L1_FIXTURE") {
        let jobs = COUNTS
            .iter()
            .enumerate()
            .flat_map(|(user_index, count)| {
                (0..*count).map(move |offset| {
                    let index = COUNTS[..user_index].iter().sum::<usize>() + offset;
                    serde_json::json!({
                        "checkpointId": (index % 2) as u32,
                        "jobIndex": ((HEIGHT as u64) << 56 | index as u64).to_string(),
                        "userIndex": user_index,
                    })
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(jobs.len(), JOBS);
        let rewards = COUNTS
            .iter()
            .enumerate()
            .map(|(user, count)| {
                serde_json::json!({
                    "userId": user_ids[user],
                    "user": format!("0x{:040x}", recipients[user]),
                    "amount": count * AMOUNT as usize,
                })
            })
            .collect::<Vec<_>>();
        let fixture = serde_json::json!({
            "publicInputs": batch_proof.public_inputs.iter().map(|field| field.to_canonical_u64().to_string()).collect::<Vec<_>>(),
            "jobs": jobs,
            "rewards": rewards,
            "wrapperDigest": format!("0x{}", wrapper_digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()),
            "l1LedgerAddress": ledger_address_hex,
            "groth16Proof": groth16_calldata,
        });
        fs::write(path, serde_json::to_vec_pretty(&fixture)?)?;
    }
    Ok(())
}
