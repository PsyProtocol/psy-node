//! Production A/B regression. Execution is gated by independent static review.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::Context;
use parth_core::{
    crypto::hash::{
        merkle_proof::{compute_root_merkle_proof_generic, DeltaMerkleProofCore, MerkleProofCore},
        tag_tree::{hash_tag_tree_node, hash_tag_tree_node_four, hash_tag_tree_node_single},
        traits::{FieldQHasher, MerkleHasher, MerkleLeafHasher, MerkleZeroHasher, QFieldHashable},
    },
    pgoldilocks::{PoseidonHasher, QHashOut},
};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::{
        config::{Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_data::bridge_aggregate::{
    chain_ends_hash, deposit_record_path, deposit_record_tree, domain_hash, AOpening, BOpening,
    ChainConfig, ChainEnd, ChainStart, DepositLeaf, DepositRecordRange, DepositTransition, Domain,
    NetworkConfig, RewardLeaf, WithdrawalLeaf,
};
use psy_core::{
    constants::chain_id::PsyChainNetworkType,
    network_config::PsyNetworkLocalDevnetConstants,
};
use psy_data::{
    agg::AggStateTransitionWithStats,
    guta::{
        header::GlobalUserTreeAggregatorHeader, realm_finalize::VALIDATOR_TREE_HEIGHT,
        stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition,
    },
    protocol::circuit_inputs::{
        agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput,
        checkpoint_transition::{QCQEDCheckpointStateTransitionInput, QCQEDCheckpointStateTransitionInputPartial},
    },
    v1::qdata::{
        checkpoint::{
            PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafCompact,
            PQEDCheckpointLeafCompactWithStateRoots, PQEDCheckpointLeafStats,
        },
        pm_jobs_completed_stats::PPMJobsCompletedStats,
        user::PQEDUserLeaf,
    },
};
use psy_plonky2_circuits::{
    bridge::{
        aggregate_circuits::{AggregateCircuitHeights, AggregateCircuits},
        circuits::{
            bridge_agg_chain::{BridgeAggChainBoundary, BridgeAggChainCircuit},
            bridge_agg_final::BridgeAggFinalSlotWitness,
            chain_aggregate::{ChainContext, ChainRow, DepositRangeEndpoints},
            checkpoint_end::{CheckpointEndChainWitness, CheckpointEndWitness},
            checkpoint_range::CheckpointRangeWitness,
            checkpoint_identity::CheckpointIdentityWitness,
            record_batch::{BatchContext, BatchRecords, RewardBatchRecord, WithdrawalBatchRecord, WithdrawalEndWitness},
            reward_inclusion::{RewardTagWitness, RewardWitness},
        },
        gadgets::{tree_root_in_contract_state::TreeRootInContractStateWitnessInput,
            slot_value_in_contract_state::SlotValueInContractStateWitnessInput},
    },
    circuit_library::get_plonky2_circuit_library_and_prover_for_network,
    coordinator::coordinator_helper::QEDCoordinatorCircuitManager,
    qstandard::QStandardCircuit,
};
use psy_plonky2_common_circuits::bridge::{
    deposit_spiderman_append::DepositSpidermanAppendInputs,
    withdrawal_inclusion::{WithdrawalInclusionInputs, WithdrawalWitness, WITHDRAWAL_TREE_HEIGHT},
};
use tiny_keccak::{Hasher as _, Keccak};
use parth_core::crypto::hash::spiderman::SpidermanUpdateProof;
use psy_crypto::signature::zk::wallet::SimplePsyPrivateKey;
use psy_ups_circuit::signature::reward_authorization::{RewardAuthorizationContext, RewardAuthorizationInput};
use psy_vm::reward_authorization::RewardAuthorizationWitness;

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

/// `PsyNetworkLocalDevnetConstants::CHECKPOINT_TREE_HEIGHT_USIZE`.
const CHECKPOINT_TREE_HEIGHT: usize = 32;
/// `PsyNetworkLocalDevnetConstants::GLOBAL_USER_TREE_HEIGHT_USIZE`.
const GLOBAL_USER_TREE_HEIGHT: usize = 32;
/// `PsyNetworkLocalDevnetConstants::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE`.
const GLOBAL_CONTRACT_TREE_HEIGHT: usize = 24;
/// `psy-genesis/genesis_contracts.json`: `deposit_tree.code_definition.state_tree_height`.
const DEPOSIT_STATE_TREE_HEIGHT: usize = 21;
/// `psy-genesis/genesis_contracts.json`: `withdrawal_tree.code_definition.state_tree_height`.
const WITHDRAWAL_STATE_TREE_HEIGHT: usize = 15;
/// `psy_client_data::bridge_aggregate::BRIDGE_USER_ID`.
const BRIDGE_USER_ID: u64 = 524_288;
const CHAIN_COUNT: usize = 3;

fn circuits() -> anyhow::Result<&'static (QEDCoordinatorCircuitManager<C, D>, AggregateCircuits)> {
    static CACHE: LazyLock<anyhow::Result<(QEDCoordinatorCircuitManager<C, D>, AggregateCircuits)>> = LazyLock::new(|| {
        let (_, coordinator) = get_plonky2_circuit_library_and_prover_for_network::<C, D>(PsyChainNetworkType::LocalDevnet)?;
        let circuits = AggregateCircuits::build::<PsyNetworkLocalDevnetConstants>(CHAIN_COUNT, &coordinator, AggregateCircuitHeights {
            deposit_state_tree: DEPOSIT_STATE_TREE_HEIGHT,
            withdrawal_state_tree: WITHDRAWAL_STATE_TREE_HEIGHT,
        })?;
        Ok((coordinator, circuits))
    });
    CACHE.as_ref().map_err(|error| anyhow::anyhow!("circuit construction: {error:#}"))
}


fn qhash(seed: u64) -> QHashOut<F> {
    QHashOut(PoseidonHash::hash_no_pad(&[F::from_canonical_u64(seed)]))
}


fn hash_two(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F> {
    QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(left.0, right.0))
}

fn zero_siblings(height: usize) -> Vec<QHashOut<F>> {
    let mut siblings = Vec::with_capacity(height);
    let mut current = QHashOut::ZERO;
    for _ in 0..height {
        siblings.push(current);
        current = hash_two(current, current);
    }
    siblings
}

fn append_siblings_after_first_leaf(first_leaf_hash: QHashOut<F>, height: usize) -> Vec<QHashOut<F>> {
    let mut siblings = zero_siblings(height);
    if let Some(first) = siblings.first_mut() {
        *first = first_leaf_hash;
    }
    siblings
}

/// Sparse Merkle proof over a set of populated leaves, with zero-hash padding.
fn path(leaves: &[(u64, QHashOut<F>)], index: u64, height: usize) -> MerkleProofCore<QHashOut<F>> {
    let mut nodes = leaves.iter().copied().collect::<BTreeMap<_, _>>();
    let value = nodes.get(&index).copied().unwrap_or(QHashOut::ZERO);
    let mut position = index;
    let mut siblings = Vec::with_capacity(height);
    for level in 0..height {
        let zero = <PoseidonHasher as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(level);
        siblings.push(nodes.get(&(position ^ 1)).copied().unwrap_or(zero));
        let mut parents = BTreeMap::new();
        for &child in nodes.keys() {
            let left = nodes.get(&(child & !1)).copied().unwrap_or(zero);
            let right = nodes.get(&(child | 1)).copied().unwrap_or(zero);
            parents.insert(child >> 1, PoseidonHasher::two_to_one(&left, &right));
        }
        nodes = parents;
        position >>= 1;
    }
    MerkleProofCore {
        root: nodes[&0],
        value,
        index,
        siblings,
    }
}

/// `PQEDUserLeaf` hash, matching `QEDUserLeafGadget::to_hash` field for field.
fn user_leaf_hash(user: &PQEDUserLeaf<F, QHashOut<F>>) -> QHashOut<F> {
    let mut values = Vec::with_capacity(13);
    values.extend_from_slice(&user.public_key.0.elements);
    values.extend_from_slice(&user.user_state_tree_root.0.elements);
    values.extend_from_slice(&[
        user.balance,
        user.nonce,
        user.last_checkpoint_id,
        user.event_index,
        user.user_id,
    ]);
    QHashOut(PoseidonHash::hash_no_pad(&values))
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut digest = [0; 32];
    hasher.finalize(&mut digest);
    digest
}

/// 32-byte big-endian word, matching `psy_client_data::bridge_aggregate`'s `word`.
fn word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Canonical statement words as they appear in the artifact public inputs.
fn pi_bytes(pi: &[F]) -> Vec<u8> {
    pi.iter()
        .flat_map(|value| (value.to_canonical_u64() as u32).to_be_bytes())
        .collect()
}

fn rejects(run: impl FnOnce() -> anyhow::Result<()>) {
    // Endpoint rejection includes host validation; an unexpected panic fails the test.
    assert!(run().is_err(), "tampered aggregation statement proved");
}

struct BridgeState {
    deposit: TreeRootInContractStateWitnessInput<F>,
    withdrawal: TreeRootInContractStateWitnessInput<F>,
    roots: PQEDCheckpointGlobalStateRoots<QHashOut<F>>,
    chains: Vec<CheckpointEndChainWitness>,
}

fn root_slots(root: QHashOut<F>) -> [QHashOut<F>; 2] {
    let limbs = hash4(root);
    std::array::from_fn(|slot| QHashOut(HashOut { elements: std::array::from_fn(|i| {
        let word = slot * 4 + i;
        F::from_canonical_u32((limbs[word / 2] >> (32 * (word % 2))) as u32)
    }) }))
}

fn bridge_state(ends: &[ChainEnd], public_key: QHashOut<F>) -> BridgeState {
    let leaves: [Vec<_>; 2] = std::array::from_fn(|contract| {
        let mut leaves = vec![(0, QHashOut::ZERO), (1, QHashOut::ZERO)];
        let mut counts = QHashOut::ZERO;
        for end in ends {
            counts.0.elements[end.chain_index as usize] = F::from_canonical_u32(if contract == 0 { end.deposit_count } else { 1 });
            let root = if contract == 0 { end.deposit_root } else { end.withdrawal_root };
            let slots = root_slots(QHashOut(HashOut { elements: root.map(F::from_canonical_u64) }));
            let index = 16_451 + 2 * u64::from(end.chain_index);
            leaves.extend([(index, slots[0]), (index + 1, slots[1])]);
        }
        leaves.push((16_386, counts));
        leaves
    });
    let heights = [DEPOSIT_STATE_TREE_HEIGHT, WITHDRAWAL_STATE_TREE_HEIGHT];
    let state_roots = std::array::from_fn::<_, 2, _>(|i| path(&leaves[i], 0, heights[i]).root);
    let contracts = [(2, state_roots[0]), (3, state_roots[1])];
    let contract_paths = [path(&contracts, 2, GLOBAL_CONTRACT_TREE_HEIGHT), path(&contracts, 3, GLOBAL_CONTRACT_TREE_HEIGHT)];
    let user = PQEDUserLeaf::new(public_key, contract_paths[0].root, F::ONE, F::ZERO, F::ZERO, F::ZERO, F::from_canonical_u64(BRIDGE_USER_ID));
    let user_path = path(&[(BRIDGE_USER_ID, user_leaf_hash(&user))], BRIDGE_USER_ID, GLOBAL_USER_TREE_HEIGHT);
    let roots = PQEDCheckpointGlobalStateRoots {
        contract_tree_root: contract_paths[0].root,
        deposit_tree_root: PoseidonHasher::get_zero_hash(32),
        withdrawal_tree_root: PoseidonHasher::get_zero_hash(32),
        user_tree_root: user_path.root,
        user_registration_tree_root: qhash(9_000),
        validator_tree_root: PoseidonHasher::get_zero_hash(VALIDATOR_TREE_HEIGHT),
    };
    let tree = |i: usize| TreeRootInContractStateWitnessInput {
        owner_user_id: BRIDGE_USER_ID, contract_id: i as u64 + 2, user_leaf: user,
        slot0_proof: path(&leaves[i], 0, heights[i]), slot1_proof: path(&leaves[i], 1, heights[i]),
        contract_proof: contract_paths[i].clone(), user_tree_proof: user_path.clone(),
    };
    let chains = ends.iter().map(|end| {
        let slots = |contract: usize| [16_386, 16_451 + 2 * u64::from(end.chain_index), 16_452 + 2 * u64::from(end.chain_index)].map(|slot_index| SlotValueInContractStateWitnessInput {
            sender_user_id: BRIDGE_USER_ID, contract_id: contract as u64 + 2, slot_index,
            user_leaf: user, slot_proof: path(&leaves[contract], slot_index, heights[contract]),
            contract_proof: contract_paths[contract].clone(), user_tree_proof: user_path.clone(),
        });
        CheckpointEndChainWitness { deposit: slots(0), withdrawal: slots(1) }
    }).collect();
    BridgeState { deposit: tree(0), withdrawal: tree(1), roots, chains }
}

/// The real checkpoint-1 transition of the source coordinator graph, together with every
/// value the bridge children need to bind to it.
struct CheckpointOne {
    proof: ProofWithPublicInputs<F, C, D>,
    append: DeltaMerkleProofCore<QHashOut<F>>,
    genesis_chain_hash: QHashOut<F>,
    genesis_tree_root: QHashOut<F>,
    genesis_leaf_hash: QHashOut<F>,
    tree_root: QHashOut<F>,
    new_leaf: PQEDCheckpointLeaf<F, QHashOut<F>>,
    new_leaf_compact: PQEDCheckpointLeafCompact<QHashOut<F>>,
    state: BridgeState,
    reward_tag: RewardTagWitness,
}

fn checkpoint(coordinator: &QEDCoordinatorCircuitManager<C, D>, state: BridgeState) -> anyhow::Result<CheckpointOne> {
    let tag_preimage = QHashOut::from_values(BRIDGE_USER_ID, 11, 22, 33);
    let worker_rewards_tree_tag = hash_two(tag_preimage, tag_preimage);
    let global_roots = state.roots;
    let register_users_root = global_roots.user_registration_tree_root;
    let contract_root = global_roots.contract_tree_root;
    let user_root = global_roots.user_tree_root;
    let register_whitelist = PoseidonHash::q_two_to_one(
        coordinator.append_user_registration_tree.get_fingerprint(),
        coordinator.agg_state_transition.get_fingerprint(),
    );
    let deploy_whitelist = PoseidonHash::q_two_to_one(
        coordinator.state_layout_circuits.batch_deploy_contracts.get_fingerprint(),
        coordinator.agg_state_transition.get_fingerprint(),
    );
    let update_whitelist = PoseidonHash::q_two_to_one(
        coordinator.state_layout_circuits.batch_update_contracts.get_fingerprint(),
        coordinator.agg_state_transition.get_fingerprint(),
    );
    let reward = |value| hash_tag_tree_node_single::<QHashOut<F>, PoseidonHash>(value, &worker_rewards_tree_tag);
    let register_reward = reward(&QHashOut::ZERO);
    let deploy_reward = reward(&QHashOut::ZERO);
    let update_reward = reward(&QHashOut::ZERO);
    let guta_reward = reward(&QHashOut::ZERO);
    let register_proof = coordinator.dummy_agg_state_transition.prove_base(register_whitelist, register_users_root, worker_rewards_tree_tag)?;
    let deploy_proof = coordinator.dummy_agg_state_transition.prove_base(deploy_whitelist, contract_root, worker_rewards_tree_tag)?;
    let update_proof = coordinator.dummy_agg_state_transition.prove_base(update_whitelist, contract_root, worker_rewards_tree_tag)?;
    let genesis_stats = PQEDCheckpointLeafStats::<F, QHashOut<F>>::get_empty_stats();
    let genesis_leaf = PQEDCheckpointLeaf { global_chain_root: global_roots.qfhash::<PoseidonHash>(), stats: genesis_stats };
    let genesis_leaf_hash = genesis_leaf.qfhash::<PoseidonHash>();
    let genesis_tree = MerkleProofCore {
        root: compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(genesis_leaf_hash, 0, &zero_siblings(CHECKPOINT_TREE_HEIGHT)),
        value: genesis_leaf_hash, index: 0, siblings: zero_siblings(CHECKPOINT_TREE_HEIGHT),
    };
    let genesis_proof = coordinator.genesis_checkpoint_root_transition.prove_base(genesis_tree.root, genesis_leaf_hash, coordinator.genesis_checkpoint_root_transition.get_fingerprint())?;
    let genesis_chain_hash = QHashOut::<F>::from_felt_slice(&genesis_proof.public_inputs);
    let compact = PQEDCheckpointLeafCompactWithStateRoots {
        global_state_roots: global_roots,
        checkpoint_leaf: PQEDCheckpointLeafCompact { global_chain_root: genesis_leaf.global_chain_root, stats_hash: genesis_stats.qfhash::<PoseidonHash>() },
    };
    let guta_path = MerkleProofCore { root: genesis_tree.root, value: compact.qfhash::<PoseidonHash>(), index: 0, siblings: zero_siblings(CHECKPOINT_TREE_HEIGHT) };
    let guta_proof = coordinator.guta_circuits.no_change.prove_base(worker_rewards_tree_tag, coordinator.guta_circuits.guta_circuit_whitelist_root, &guta_path, &compact)?;
    let transition = |root| AggStateTransitionWithStats { state_transition_start: root, state_transition_end: root, total_proofs_generated: 1 };
    let header = QCAggUserRegistartionDeployContractsGUTAInput {
        register_users_state_transition: transition(register_users_root),
        deploy_contracts_state_transition: transition(contract_root),
        update_contracts_state_transition: transition(contract_root),
        guta_proof_header: GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: coordinator.guta_circuits.guta_circuit_whitelist_root,
            checkpoint_tree_root: genesis_tree.root,
            state_transition: SubTreeNodeStateTransition { old_node_value: user_root, new_node_value: user_root, node_index: F::ZERO, node_level: F::ZERO },
            stats: GUTAStats::get_zero_value(),
            total_aggregation_proofs_generated: F::ONE,
        },
    };
    let part_reward = hash_tag_tree_node_four::<QHashOut<F>, PoseidonHash>(&guta_reward, &register_reward, &deploy_reward, &update_reward, &worker_rewards_tree_tag);
    let verifier = coordinator.dummy_agg_state_transition.get_verifier_config_ref();
    let part_proof = coordinator.agg_user_register_deploy_contracts_guta.prove_base(
        worker_rewards_tree_tag,
        &header.register_users_state_transition.get_agg_state_transition(), &register_proof, verifier, register_reward, F::ONE,
        &header.deploy_contracts_state_transition.get_agg_state_transition(), &deploy_proof, verifier, deploy_reward, F::ONE,
        &header.update_contracts_state_transition.get_agg_state_transition(), &update_proof, verifier, update_reward, F::ONE,
        &coordinator.guta_circuits.no_change_whitelist_proof, &header.guta_proof_header, &guta_proof,
        coordinator.guta_circuits.no_change.get_verifier_config_ref(), guta_reward,
    )?;
    let append = DeltaMerkleProofCore {
        old_root: genesis_tree.root, old_value: QHashOut::ZERO, new_root: genesis_tree.root, new_value: QHashOut::ZERO, index: 1,
        siblings: append_siblings_after_first_leaf(genesis_leaf_hash, CHECKPOINT_TREE_HEIGHT),
    };
    let partial = QCQEDCheckpointStateTransitionInputPartial {
        part_1_header: header, old_stats: genesis_stats, block_time: F::ONE, final_random_seed_contribution: qhash(400),
        pm_jobs_completed: PPMJobsCompletedStats { deploy_contracts_completed: F::ONE, register_users_completed: F::ONE, gutas_completed: F::ONE },
        validator_tree_root: <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(VALIDATOR_TREE_HEIGHT),
    };
    let reward_root = hash_tag_tree_node_single::<QHashOut<F>, PoseidonHash>(&part_reward, &worker_rewards_tree_tag);
    let new_leaf = partial.get_new_checkpoint_leaf::<PoseidonHash>(reward_root);
    let mut input = QCQEDCheckpointStateTransitionInput {
        partial, append_checkpoint_tree_proof: append.clone(), previous_checkpoint_proof: genesis_tree.clone(),
        genesis_checkpoint_state_transition_hash: genesis_chain_hash, last_old_checkpoint_tree_leaf_hash: QHashOut::ZERO,
        last_old_checkpoint_tree_root_hash: QHashOut::ZERO, previous_chain_hash: genesis_chain_hash,
        checkpoint_state_transition_circuit_fingerprint: coordinator.checkpoint_root_transition.get_fingerprint(),
    };
    input.update_for_prover::<PoseidonHash>(reward_root);
    let proof = coordinator.checkpoint_root_transition.prove_base(
        worker_rewards_tree_tag, &input, part_reward, &part_proof,
        coordinator.agg_user_register_deploy_contracts_guta.get_verifier_config_ref(),
        &genesis_proof, coordinator.genesis_checkpoint_root_transition.get_verifier_config_ref(),
    )?;
    let chain_hash = QHashOut::<F>::from_felt_slice(&proof.public_inputs);
    let mut reward_tag = RewardTagWitness {
        tag_preimage, leaf_left: QHashOut::ZERO, leaf_right: QHashOut::ZERO,
        leaf_tag: worker_rewards_tree_tag, siblings: [QHashOut::ZERO; 21], parent_tags: [QHashOut::ZERO; 21],
    };
    reward_tag.siblings[0] = hash_tag_tree_node::<QHashOut<F>, PoseidonHash>(&register_reward,
        &hash_tag_tree_node::<QHashOut<F>, PoseidonHash>(&deploy_reward, &update_reward, &worker_rewards_tree_tag), &worker_rewards_tree_tag);
    reward_tag.parent_tags[..2].fill(worker_rewards_tree_tag);
    anyhow::ensure!(chain_hash != genesis_chain_hash, "checkpoint did not advance");
    Ok(CheckpointOne {
        proof, append: input.append_checkpoint_tree_proof.clone(), genesis_chain_hash,
        genesis_tree_root: genesis_tree.root, genesis_leaf_hash, tree_root: input.append_checkpoint_tree_proof.new_root,
        new_leaf, new_leaf_compact: PQEDCheckpointLeafCompact { global_chain_root: new_leaf.global_chain_root, stats_hash: new_leaf.stats.qfhash::<PoseidonHash>() },
        state, reward_tag,
    })
}

fn hash4(value: QHashOut<F>) -> [u64; 4] {
    value.0.elements.map(|element| element.to_canonical_u64())
}

fn deposit_hash(leaf: &DepositLeaf) -> QHashOut<F> {
    let mut bytes = Vec::with_capacity(164);
    bytes.extend(leaf.shield_address);
    bytes.extend([0; 12]);
    bytes.extend(leaf.token);
    bytes.extend(leaf.l2_token_contract_id);
    bytes.extend(leaf.amount);
    bytes.extend(u32::from(leaf.chain_index).to_be_bytes());
    bytes.extend(leaf.note_commitment);
    source_hash(&bytes)
}

fn withdrawal_hash(leaf: &WithdrawalLeaf) -> QHashOut<F> {
    let mut bytes = Vec::with_capacity(136);
    bytes.extend(leaf.sender_user_id.to_be_bytes());
    for address in [leaf.recipient, leaf.token] { bytes.extend([0; 12]); bytes.extend(address); }
    bytes.extend(leaf.amount);
    bytes.extend(leaf.nonce);
    bytes.extend(u32::from(leaf.chain_index).to_be_bytes());
    source_hash(&bytes)
}

fn source_hash(bytes: &[u8]) -> QHashOut<F> {
    let words: Vec<_> = bytes.chunks_exact(4).map(|bytes| F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))).collect();
    QHashOut(PoseidonHash::hash_no_pad(&words))
}

fn end_paths(ends: &[ChainEnd]) -> anyhow::Result<Vec<WithdrawalEndWitness>> {
    let mut tree = vec![[0; 32]; 511];
    for ordinal in 0..256 {
        let mut bytes = Vec::new();
        bytes.extend(domain_hash(if ordinal < ends.len() { Domain::Leaf } else { Domain::Empty }));
        bytes.extend(word(6)); bytes.extend(word(ends.len() as u64)); bytes.extend(word(ordinal as u64));
        if let Some(end) = ends.get(ordinal) { bytes.extend(end.encode()?); }
        tree[255 + ordinal] = keccak(&bytes);
    }
    for level in 1..=8 {
        let start = (1 << (8 - level)) - 1;
        for index in start..2 * start + 1 {
            tree[index] = keccak(&[domain_hash(Domain::Node).as_slice(), &word(6), &word(level), &tree[2 * index + 1], &tree[2 * index + 2]].concat());
        }
    }
    assert_eq!(tree[0], chain_ends_hash(ends)?);
    Ok(ends.iter().enumerate().map(|(ordinal, end)| {
        let mut index = 255 + ordinal;
        let siblings = std::array::from_fn(|_| {
            let sibling = tree[if index % 2 == 0 { index - 1 } else { index + 1 }];
            index = (index - 1) / 2;
            sibling
        });
        WithdrawalEndWitness { ordinal: ordinal as u8, end: end.clone(), siblings }
    }).collect())
}

fn client_value<T: serde::de::DeserializeOwned>(value: &impl serde::Serialize) -> anyhow::Result<T> {
    Ok(serde_json::from_value(serde_json::to_value(value)?)?)
}

fn assert_statement(proof: &ProofWithPublicInputs<F, C, D>, variant: u32, digest: [u8; 32]) {
    assert_eq!(proof.public_inputs.len(), 12);
    assert_eq!(&proof.public_inputs[..4], &[1, 11, variant, 0].map(F::from_canonical_u32));
    assert_eq!(pi_bytes(&proof.public_inputs[4..12]), digest);
}

fn chain_proofs(circuits: &AggregateCircuits, config: &NetworkConfig, b: &BOpening,
    webs: &[Vec<ProofWithPublicInputs<F, C, D>>], tree: &[[u8; 32]],
) -> anyhow::Result<[ProofWithPublicInputs<F, C, D>; 2]> {
    let a = &b.a;
    let context = ChainContext { config_hash: a.config_hash, end_checkpoint_id: a.end_checkpoint_id,
        end_checkpoint_root: a.end_checkpoint_root, global_deposit_record_root: tree[0], global_deposit_count: a.deposit_leaves.len() as u32 };
    let mut roots = Vec::new();
    for variant in 0..2 {
        let mut first = 0;
        let mut rows = Vec::new();
        let mut proofs = Vec::new();
        for ordinal in 0..CHAIN_COUNT {
            let range = DepositRecordRange { first_record: first, record_count: a.deposits[ordinal].new_count - a.deposits[ordinal].old_count };
            first += range.record_count;
            let endpoints = DepositRangeEndpoints::from_tree(&a.deposit_leaves, tree, &range)?;
            let row = if variant == 0 { ChainRow::A { start: a.starts[ordinal].clone(), transition: a.deposits[ordinal].clone(), range } }
                else { ChainRow::B { start: a.starts[ordinal].clone(), transition: a.deposits[ordinal].clone(), end: b.ends[ordinal].clone(), range } };
            proofs.push(circuits.chains[variant].real.prove(config, &context, ordinal as u32, Some(&row),
                if variant == 0 { &webs[ordinal] } else { &[] }, if variant == 1 { Some(&endpoints) } else { None })?);
            rows.push(row);
        }
        proofs.push(circuits.chains[variant].empty.prove(config, &context, 3, None, &[], None)?);
        let left = circuits.chain_levels[variant][0].prove(config, &context, 0, &rows[..2], &proofs[0], &proofs[1])?;
        let right = circuits.chain_levels[variant][0].prove(config, &context, 2, &rows[2..], &proofs[2], &proofs[3])?;
        roots.push(circuits.chain_levels[variant][1].prove(config, &context, 0, &rows, &left, &right)?);
    }
    Ok(roots.try_into().unwrap())
}

#[test]
fn real_multichain_artifacts_bind_nonempty_complete_openings() -> anyhow::Result<()> {
    let (coordinator, circuits) = circuits()?;
    let private_key: QHashOut<F> = QHashOut::from_values(11, 22, 33, 44);
    let identity = circuits.entries().iter().find(|entry| (entry.family, entry.variant) == (4, 0)).context("missing ZK authorization pin")?.identity_fingerprint;
    let param = SimplePsyPrivateKey::new(client_value(&private_key)?).get_public_key_param::<PoseidonHash>();
    let public_key = hash_two(QHashOut(HashOut { elements: identity.map(F::from_canonical_u64) }), QHashOut(param.0));
    let deposits: Vec<_> = [(0, 31), (0, 32), (1, 0)].into_iter().map(|(chain_index, absolute_index)| DepositLeaf {
        chain_index, absolute_index, shield_address: word(11), token: [5; 20], l2_token_contract_id: word(12),
        amount: word(13), note_commitment: word(14 + u64::from(absolute_index)),
    }).collect();
    let withdrawals: Vec<_> = (0..3).map(|chain_index| WithdrawalLeaf {
        chain_index, sender_user_id: 1000, recipient: [8; 20], token: [5; 20], amount: word(7), nonce: word(u64::from(chain_index) + 1),
    }).collect();
    let withdrawal_paths: Vec<_> = withdrawals.iter().map(|leaf| path(&[(0, withdrawal_hash(leaf))], 0, WITHDRAWAL_TREE_HEIGHT)).collect();
    let mut custody: Vec<Vec<(u64, QHashOut<F>)>> = vec![(0..31).map(|i| (i, qhash(i + 1))).collect(), Vec::new(), Vec::new()];
    let empty_root = PoseidonHasher::get_zero_hash(32);
    let old_roots = [path(&custody[0], 0, 32).root, empty_root, empty_root];
    let mut append_proofs = Vec::new();
    for leaf in &deposits {
        let chain = leaf.chain_index as usize;
        let base = u64::from(leaf.absolute_index / 32) * 32;
        let old_path = path(&custody[chain].iter().copied().chain([(u64::from(leaf.absolute_index), QHashOut::ZERO)]).collect::<Vec<_>>(), u64::from(leaf.absolute_index), 32);
        let old_leaves: Vec<_> = (base..base + 32).map(|index| custody[chain].iter().find(|(i, _)| *i == index).map_or(QHashOut::ZERO, |(_, hash)| *hash)).collect();
        let mut new_leaves = old_leaves.clone();
        new_leaves[leaf.absolute_index as usize % 32] = deposit_hash(leaf);
        append_proofs.push(SpidermanUpdateProof {
            top_line_proof: DeltaMerkleProofCore::from_params::<PoseidonHasher>(base / 32,
                PoseidonHasher::compute_root_from_leaves(&old_leaves).context("old web")?,
                PoseidonHasher::compute_root_from_leaves(&new_leaves).context("new web")?, old_path.siblings[5..].to_vec()),
            web_proof_old_leaves: old_leaves, web_proof_new_leaves: new_leaves,
        });
        custody[chain].push((u64::from(leaf.absolute_index), deposit_hash(leaf)));
    }
    let ends: Vec<_> = (0..3).map(|chain| ChainEnd {
        chain_index: chain as u8, deposit_root: hash4(if chain == 2 { empty_root } else { path(&custody[chain], 0, 32).root }),
        deposit_count: [33, 1, 0][chain], withdrawal_root: hash4(withdrawal_paths[chain].root),
    }).collect();
    let checkpoint = checkpoint(coordinator, bridge_state(&ends, public_key))?;
    let config = NetworkConfig {
        version: 1, network_magic: 0, bridge_user_id: BRIDGE_USER_ID as u32,
        circuit_set_hash: circuits.circuit_set_hash(),
        chains: (0..3).map(|chain_index| ChainConfig { chain_index, chain_id: word(u64::from(chain_index) + 1), bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: hash4(checkpoint.genesis_tree_root) }).collect(),
        ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: word(1), reward_token_decimals: 18,
        reward_cutover: 0, reward_end_exclusive: 2, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
    };
    let mut a = AOpening {
        config_hash: config.config_hash()?, window_id: [0; 32], end_checkpoint_id: 1, end_checkpoint_root: hash4(checkpoint.tree_root),
        starts: (0..3).map(|chain_index| ChainStart { chain_index, start_checkpoint_id: if chain_index == 2 { 1 } else { 0 }, start_checkpoint_root: hash4(if chain_index == 2 { checkpoint.tree_root } else { checkpoint.genesis_tree_root }) }).collect(),
        deposits: ends.iter().enumerate().map(|(i, end)| DepositTransition { chain_index: end.chain_index, old_root: hash4(old_roots[i]), new_root: end.deposit_root, old_count: [31, 0, 0][i], new_count: end.deposit_count }).collect(), deposit_leaves: deposits,
    };
    a.window_id = a.window_id()?;
    let reward = RewardLeaf { claim_checkpoint_id: 1, user_id: BRIDGE_USER_ID as u32, height: 2, path_index: 0, nullifier_index: 3, recipient: [9; 20] };
    let b = BOpening { a: a.clone(), ends, withdrawals, rewards: vec![reward.clone()] };
    a.validate(&config)?; b.validate(&config)?;
    let tree = deposit_record_tree(&a.deposit_leaves.iter().map(DepositLeaf::record_commit).collect::<Result<Vec<_>, _>>()?)?;
    let web_inputs: Vec<_> = a.deposit_leaves.iter().enumerate().map(|(i, leaf)| Ok(DepositSpidermanAppendInputs {
        config_hash: a.config_hash, end_checkpoint_id: 1, end_checkpoint_root: checkpoint.tree_root, chain_index: leaf.chain_index,
        old_count: leaf.absolute_index, first_record: i as u32, global_deposit_record_root: tree[0], global_deposit_count: 3,
        record_paths: vec![deposit_record_path(&tree, 3, i as u32)?], deposits: vec![leaf.clone()], append_proof: append_proofs[i].clone(),
    })).collect::<anyhow::Result<_>>()?;
    let mut webs = vec![Vec::new(), Vec::new(), Vec::new()];
    for input in &web_inputs { webs[input.chain_index as usize].push(circuits.deposit.prove(input)?); }
    let chains = chain_proofs(circuits, &config, &b, &webs, &tree)?;
    let context = BatchContext { config_hash: a.config_hash, end_id: 1, end_root: a.end_checkpoint_root, chain_ends_hash: [0; 32] };
    let deposit_batch = circuits.batches[0].real.prove(&context, 0, 0, Some(&BatchRecords::Deposit(&a.deposit_leaves)))?;
    let proof_a = circuits.prove_a(&config, &a, &deposit_batch, &chains[0])?;
    circuits.deposit_aggregate.circuit_data.verify(proof_a.clone())?;
    assert_statement(&proof_a, 1, a.statement_digest(&config)?);

    let end_path = MerkleProofCore { root: checkpoint.tree_root, value: checkpoint.append.new_value, index: 1, siblings: checkpoint.append.siblings.clone() };
    let end_witness = CheckpointEndWitness { config: config.clone(), end_id: 1, end_root: checkpoint.tree_root,
        end_leaf: checkpoint.new_leaf, end_path: end_path.clone(), global_state_roots: checkpoint.state.roots,
        user_leaf: checkpoint.state.deposit.user_leaf, user_path: checkpoint.state.deposit.user_tree_proof.clone(), chains: checkpoint.state.chains.clone() };
    let end = circuits.checkpoint_end.prove(&end_witness)?;
    let source_chain = BridgeAggChainCircuit::<C, D>::new(coordinator.checkpoint_root_transition.get_fingerprint(), CHECKPOINT_TREE_HEIGHT);
    let source_base = source_chain.prove_base(BridgeAggChainBoundary { chain_hash: checkpoint.genesis_chain_hash,
        checkpoint_tree_root: checkpoint.genesis_tree_root, checkpoint_leaf_hash: checkpoint.genesis_leaf_hash, checkpoint_index: 0 }, &checkpoint.append)?;
    let final_proof = circuits.checkpoint_final.prove_base(&source_base, source_chain.get_verifier_config_ref(),
        &[BridgeAggFinalSlotWitness { checkpoint_delta_merkle_proof: &checkpoint.append }], &checkpoint.proof,
        coordinator.checkpoint_root_transition.get_verifier_config_ref(), &checkpoint.new_leaf_compact, &checkpoint.state.roots,
        &checkpoint.state.deposit, &checkpoint.state.withdrawal)?;
    let config_words = std::array::from_fn(|i| u32::from_be_bytes(a.config_hash[i * 4..i * 4 + 4].try_into().unwrap()));
    let positive = circuits.checkpoint_positive.prove(&CheckpointRangeWitness { range_proof: &final_proof,
        config_hash: config_words, start_id: 0, end_leaf: checkpoint.new_leaf, end_path: end_path.clone() })?;
    let identity_witness = CheckpointIdentityWitness { config_hash: config_words, start_id: 1, end_id: 1,
        start_root: checkpoint.tree_root, end_root: checkpoint.tree_root, end_leaf: checkpoint.new_leaf, end_path: end_path.clone() };
    let identity = circuits.checkpoint_identity.prove(&identity_witness)?;
    let ranges = [positive, identity];
    let withdrawal_inputs: Vec<_> = b.withdrawals.iter().zip(&withdrawal_paths).map(|(leaf, path)| WithdrawalInclusionInputs {
        config_hash: a.config_hash, end_checkpoint_id: 1, end_checkpoint_root: a.end_checkpoint_root,
        withdrawal_root: hash4(path.root), leaf: leaf.clone(), witness: WithdrawalWitness { leaf_index: 0, siblings: std::array::from_fn(|i| hash4(path.siblings[i])) },
    }).collect();
    let withdrawal_proofs = withdrawal_inputs.iter().map(|input| circuits.withdrawal.generate_proof(input)).collect::<anyhow::Result<Vec<_>>>()?;
    let ends = end_paths(&b.ends)?;
    let withdrawal_records: Vec<_> = b.withdrawals.iter().zip(&withdrawal_proofs).zip(&ends).map(|((record, proof), end)| WithdrawalBatchRecord { record, proof, end }).collect();
    let withdrawal_context = BatchContext { chain_ends_hash: chain_ends_hash(&b.ends)?, ..context.clone() };
    let withdrawal_batch = circuits.batches[1].real.prove(&withdrawal_context, 0, 0, Some(&BatchRecords::Withdrawal { config: &config, records: &withdrawal_records }))?;
    let reward_input = RewardWitness { config: config.clone(), tag: checkpoint.reward_tag.clone(), authorization: RewardAuthorizationInput {
        context: RewardAuthorizationContext {
        config_hash: a.config_hash, end_checkpoint_id: 1, end_checkpoint_root: a.end_checkpoint_root, reward,
        claim_checkpoint_leaf: client_value(&checkpoint.new_leaf)?, claim_checkpoint_path: client_value(&end_path.siblings)?,
        end_checkpoint_leaf: client_value(&checkpoint.new_leaf)?, end_checkpoint_path: client_value(&end_path.siblings)?,
        end_global_state_roots: client_value(&checkpoint.state.roots)?, authorization_user_leaf: client_value(&checkpoint.state.deposit.user_leaf)?,
        authorization_user_path: client_value(&checkpoint.state.deposit.user_tree_proof.siblings)?,
        },
        authorization: RewardAuthorizationWitness::Zk { private_key: client_value(&private_key)? },
    } };
    let reward_proof = circuits.reward.prove(&reward_input)?;
    let reward_batch = circuits.batches[2].real.prove(&context, 0, 0, Some(&BatchRecords::Reward(&[RewardBatchRecord { record: &b.rewards[0], proof: &reward_proof }])))?;
    let prove_b = |opening: &BOpening| circuits.prove_b(&config, opening, &withdrawal_batch, &reward_batch, &chains[1], &end, &ranges);
    let proof_b = prove_b(&b)?;
    circuits.checkpoint_aggregate.circuit_data.verify(proof_b.clone())?;
    assert_statement(&proof_b, 2, b.statement_digest(&config)?);

    // These exercise endpoint contracts, including canonical-opening host validation.
    for mutation in 0..6 {
        let mut changed = a.clone();
        match mutation {
            0 => changed.deposit_leaves[0].amount = word(99),
            1 => { changed.deposit_leaves.pop(); },
            2 => changed.deposit_leaves.swap(0, 1),
            3 => changed.starts[0].start_checkpoint_root[0] ^= 1,
            4 => changed.deposits[0].new_count += 1,
            _ => { changed.starts.pop(); changed.deposits.pop(); },
        }
        rejects(|| circuits.prove_a(&config, &changed, &deposit_batch, &chains[0]).map(|_| ()));
    }
    for mutation in 0..8 {
        let mut changed = b.clone();
        match mutation {
            0 => { changed.withdrawals.pop(); },
            1 => changed.rewards.clear(),
            2 => changed.withdrawals[0].recipient[0] ^= 1,
            3 => changed.withdrawals[0].nonce = word(100),
            4 => changed.rewards[0].recipient[0] ^= 1,
            5 => changed.ends[0].withdrawal_root[0] ^= 1,
            6 => changed.ends[0].deposit_count += 1,
            _ => changed.a.deposit_leaves[2].chain_index = 255,
        }
        rejects(|| prove_b(&changed).map(|_| ()));
    }
    // Witness assignment must succeed here: only the prover may reject these constraints.
    for mutation in 0..4 {
        let original = &web_inputs[0];
        let mut changed = DepositSpidermanAppendInputs {
            config_hash: original.config_hash, end_checkpoint_id: original.end_checkpoint_id,
            end_checkpoint_root: original.end_checkpoint_root, chain_index: original.chain_index,
            old_count: original.old_count, first_record: original.first_record,
            global_deposit_record_root: original.global_deposit_record_root, global_deposit_count: original.global_deposit_count,
            record_paths: original.record_paths.clone(), deposits: original.deposits.clone(), append_proof: original.append_proof.clone(),
        };
        match mutation {
            0 => changed.record_paths[0][0][0] ^= 1,
            1 => changed.first_record = 1,
            2 => changed.append_proof.web_proof_old_leaves[31] = qhash(999),
            _ => changed.deposits[0].absolute_index += 1,
        }
        let mut witness = plonky2::iop::witness::PartialWitness::new();
        circuits.deposit.set_witness(&mut witness, &changed)?;
        assert!(circuits.deposit.circuit_data.prove(witness).is_err(), "invalid web constraints proved");
    }
    // Endpoint negatives: missing chains and substituted slot indices fail host checks.
    for mutation in 0..4 {
        let mut changed = end_witness.clone();
        match mutation {
            0 => changed.chains[0].deposit[0].slot_proof.value.0.elements[0] += F::ONE,
            1 => changed.chains[0].deposit[1] = changed.chains[1].deposit[1].clone(),
            2 => changed.chains[0].withdrawal[1].slot_proof.siblings[0] = qhash(999),
            _ => { changed.chains.pop(); },
        }
        rejects(|| circuits.checkpoint_end.prove(&changed).map(|_| ()));
    }
    // Endpoint negatives: the non-GU index fails RewardLeaf::validate before proving.
    for mutation in 0..4 {
        let mut changed = RewardWitness { config: reward_input.config.clone(), authorization: reward_input.authorization.clone(), tag: reward_input.tag.clone() };
        match mutation {
            0 => changed.tag.siblings[0] = qhash(999),
            1 => changed.authorization.context.reward.path_index = 2,
            2 => changed.authorization.context.authorization_user_leaf.last_checkpoint_id = F::from_canonical_u32(2),
            _ => changed.authorization.authorization = RewardAuthorizationWitness::Zk { private_key: client_value(&qhash(999))? },
        }
        rejects(|| circuits.reward.prove(&changed).map(|_| ()));
    }
    let mut fabricated = withdrawal_inputs[0].clone();
    fabricated.leaf.amount = word(999);
    fabricated.withdrawal_root = hash4(path(&[(0, withdrawal_hash(&fabricated.leaf))], 0, 32).root);
    let fabricated_proof = circuits.withdrawal.generate_proof(&fabricated)?;
    circuits.withdrawal.circuit_data.verify(fabricated_proof.clone())?;
    let mut witness = plonky2::iop::witness::PartialWitness::new();
    circuits.batches[1].real.set_witness(&mut witness, &withdrawal_context, 0, 0, Some(&BatchRecords::Withdrawal {
        config: &config, records: &[WithdrawalBatchRecord { record: &fabricated.leaf, proof: &fabricated_proof, end: &ends[0] }],
    }))?;
    assert!(circuits.batches[1].real.circuit_data.prove(witness).is_err(), "fabricated withdrawal root joined authenticated end");
    let mut wrong_end = ends[0].clone(); wrong_end.siblings[0][0] ^= 1;
    let mut witness = plonky2::iop::witness::PartialWitness::new();
    circuits.batches[1].real.set_witness(&mut witness, &withdrawal_context, 0, 0, Some(&BatchRecords::Withdrawal {
        config: &config, records: &[WithdrawalBatchRecord { record: &b.withdrawals[0], proof: &withdrawal_proofs[0], end: &wrong_end }],
    }))?;
    assert!(circuits.batches[1].real.circuit_data.prove(witness).is_err(), "changed end sibling proved");
    let empty_withdrawal = circuits.batches[1].empty.prove(&withdrawal_context, 0, 0, None)?;
    let empty_reward = circuits.batches[2].empty.prove(&context, 0, 0, None)?;
    rejects(|| circuits.prove_b(&config, &b, &empty_withdrawal, &reward_batch, &chains[1], &end, &ranges).map(|_| ()));
    rejects(|| circuits.prove_b(&config, &b, &withdrawal_batch, &empty_reward, &chains[1], &end, &ranges).map(|_| ()));
    let mut empty_claims = b.clone(); empty_claims.withdrawals.clear(); empty_claims.rewards.clear();
    let empty_b = circuits.prove_b(&config, &empty_claims, &empty_withdrawal, &empty_reward, &chains[1], &end, &ranges)?;
    circuits.checkpoint_aggregate.circuit_data.verify(empty_b.clone())?;
    assert_statement(&empty_b, 2, empty_claims.statement_digest(&config)?);
    let mut wrong_identity = identity_witness;
    wrong_identity.start_root = checkpoint.genesis_tree_root;
    rejects(|| circuits.checkpoint_identity.prove(&wrong_identity).map(|_| ()));
    rejects(|| circuits.prove_b(&config, &b, &withdrawal_batch, &reward_batch, &chains[1], &end, &ranges[..1]).map(|_| ()));
    let mut wrong_config = config.clone(); wrong_config.circuit_set_hash[0] ^= 1;
    rejects(|| circuits.prove_a(&wrong_config, &a, &deposit_batch, &chains[0]).map(|_| ()));
    circuits.validate_entries(circuits.entries())?;
    let mut changed_pin = circuits.entries().to_vec();
    changed_pin[0].verifier_digest[0] ^= 1;
    psy_client_data::bridge_aggregate::circuit_set_hash(&changed_pin)?;
    assert!(circuits.validate_entries(&changed_pin).is_err());
    let mut shorter_graph = circuits.entries().to_vec();
    shorter_graph.retain(|entry| entry.family != 10 || entry.level <= 1);
    psy_client_data::bridge_aggregate::circuit_set_hash(&shorter_graph)?;
    assert!(circuits.validate_entries(&shorter_graph).is_err());
    let mut four_chains = config.clone();
    let mut fourth = four_chains.chains[2].clone();
    fourth.chain_index = 3;
    fourth.chain_id = word(4);
    four_chains.chains.push(fourth);
    four_chains.validate()?;
    assert!(circuits.validate_config(&four_chains).is_err());
    let mut tampered = proof_a.clone(); tampered.public_inputs[4] += F::ONE;
    assert!(circuits.deposit_aggregate.circuit_data.verify(tampered).is_err());
    Ok(())
}
