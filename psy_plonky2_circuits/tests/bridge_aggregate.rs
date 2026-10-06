//! Native finalize/A/W/R regression. Execution is gated by independent static review.

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
use psy_client_data::{
    bridge_aggregate::{
        bind_claim_tree, deposit_leaf_path, deposit_leaf_tree, DepositAggregateOpening,
        ChainConfig, ChainStart, DepositLeaf, DepositLeafRange, DepositTransition,
        InclusionAggregateHeader, NetworkConfig, RewardSessionProofFields, SourceCheckpointRewardLeaf,
        SourceCheckpointRewardOpening, WithdrawalAggregateOpening, WithdrawalLeaf,
        INCLUSION_AGGREGATE_CAPACITIES, REWARD_PUBLICATION_FAMILY, WITHDRAWAL_PUBLICATION_FAMILY,
    },
    qdata::{checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf}, user::PsyUserLeaf},
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
            bridge_agg_final::{BridgeAggFinalSlotWitness, BridgeAggFinalEndpointWitness},
            chain_aggregate::{ChainContext, ChainRow},
            inclusion_aggregate::{AggregateWindow, RewardLedgerFinalProof, SourceCheckpointRewardAggregateLeaf, WithdrawalAggregateLeaf, withdrawal_root_paths, AGGREGATE_PI_LEN},
            reward_inclusion::RewardTagWitness,
            reward_session::{RewardLedgerStateValues, RewardSessionJobWitness, RewardSessionWitness},
        },
        gadgets::{
            tree_root_in_contract_state::TreeRootInContractStateWitnessInput,
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
const CHAIN_INDICES: [u8; 3] = [0, 1, 2];

fn circuits() -> anyhow::Result<&'static (QEDCoordinatorCircuitManager<C, D>, AggregateCircuits)> {
    static CACHE: LazyLock<anyhow::Result<(QEDCoordinatorCircuitManager<C, D>, AggregateCircuits)>> = LazyLock::new(|| {
        let (_, coordinator) = get_plonky2_circuit_library_and_prover_for_network::<C, D>(PsyChainNetworkType::LocalDevnet)?;
        let circuits = AggregateCircuits::build::<PsyNetworkLocalDevnetConstants>(&CHAIN_INDICES, &coordinator, AggregateCircuitHeights {
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
    chains: [Vec<[SlotValueInContractStateWitnessInput<F>; 3]>; 2],
}

fn root_slots(root: QHashOut<F>) -> [QHashOut<F>; 2] {
    let limbs = hash4(root);
    std::array::from_fn(|slot| QHashOut(HashOut { elements: std::array::from_fn(|i| {
        let word = slot * 4 + i;
        F::from_canonical_u32((limbs[word / 2] >> (32 * (word % 2))) as u32)
    }) }))
}

struct ChainState {
    chain_index: u8,
    deposit_root: [u64; 4],
    deposit_count: u32,
    withdrawal_root: [u64; 4],
}

fn bridge_state(ends: &[ChainState], public_key: QHashOut<F>) -> BridgeState {
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
    let chains = std::array::from_fn(|contract| ends.iter().map(|end| {
        [16_386, 16_451 + 2 * u64::from(end.chain_index), 16_452 + 2 * u64::from(end.chain_index)].map(|slot_index| SlotValueInContractStateWitnessInput {
            sender_user_id: BRIDGE_USER_ID, contract_id: contract as u64 + 2, slot_index,
            user_leaf: user, slot_proof: path(&leaves[contract], slot_index, heights[contract]),
            contract_proof: contract_paths[contract].clone(), user_tree_proof: user_path.clone(),
        })
    }).collect());
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

fn withdrawal_paths_for(config: &NetworkConfig, ends: &[ChainState]) -> anyhow::Result<Vec<psy_plonky2_circuits::bridge::circuits::inclusion_aggregate::WithdrawalRootPath>> {
    withdrawal_root_paths(config, &ends.iter().map(|end| end.withdrawal_root).collect::<Vec<_>>())
}

fn client_value<T: serde::de::DeserializeOwned>(value: &impl serde::Serialize) -> anyhow::Result<T> {
    Ok(serde_json::from_value(serde_json::to_value(value)?)?)
}

fn assert_opening_digest(proof: &ProofWithPublicInputs<F, C, D>, family: u32, variant: u32, digest: [u8; 32]) {
    assert_eq!(proof.public_inputs.len(), 12);
    assert_eq!(&proof.public_inputs[..4], &[1, family, variant, 0].map(F::from_canonical_u32));
    assert_eq!(pi_bytes(&proof.public_inputs[4..12]), digest);
}

fn assert_withdrawal_publication(proof: &ProofWithPublicInputs<F, C, D>, header: &InclusionAggregateHeader) {
    let words = header.publication_words().expect("withdrawal publication words");
    assert_eq!(words.len(), AGGREGATE_PI_LEN);
    assert_eq!(proof.public_inputs, words.map(F::from_canonical_u32));
    assert_eq!(&proof.public_inputs[..4], &[1, 7, WITHDRAWAL_PUBLICATION_FAMILY as u32, 0].map(F::from_canonical_u32));
    assert_eq!(pi_bytes(&proof.public_inputs[4..12]), header.opening_digest);
    assert_eq!(pi_bytes(&proof.public_inputs[12..20]), header.claim_tree_root);
    assert_eq!(pi_bytes(&proof.public_inputs[20..28]), header.header_digest().expect("withdrawal header digest"));
}

fn withdrawal_publication_header(config: &NetworkConfig, opening: &WithdrawalAggregateOpening) -> anyhow::Result<InclusionAggregateHeader> {
    let count = u32::try_from(opening.withdrawals.len()).context("withdrawal publication count exceeds u32")?;
    anyhow::ensure!(count <= INCLUSION_AGGREGATE_CAPACITIES[0], "manager withdrawal publication capacity is 1024");
    let mut header = InclusionAggregateHeader {
        family: WITHDRAWAL_PUBLICATION_FAMILY,
        config_hash: opening.config_hash,
        window_id: opening.window_id,
        end_checkpoint_id: opening.end_checkpoint_id,
        end_checkpoint_root: opening.end_checkpoint_root,
        aggregate_capacity: INCLUSION_AGGREGATE_CAPACITIES[0],
        total_count: count,
        segment_count: u32::from(count != 0),
        segment_index: 0,
        first_ordinal: 0,
        count,
        withdrawal_roots: opening.withdrawal_roots.clone(),
        old_ledger_state_root: None,
        new_ledger_state_root: None,
        opening_digest: if count == 0 { [0; 32] } else { opening.opening_digest(config)? },
        claim_tree_root: [0; 32],
    };
    if count != 0 {
        let commits = opening.withdrawals.iter().map(|leaf| leaf.leaf_commit()).collect::<Result<Vec<_>, _>>()?;
        bind_claim_tree(&mut header, &commits)?;
    }
    header.validate()?;
    Ok(header)
}
fn poseidon_bytes(bytes: &[u8]) -> [u64; 4] {
    hash4(QHashOut(PoseidonHash::hash_no_pad(&bytes.iter().copied().map(F::from_canonical_u8).collect::<Vec<_>>())))
}

fn append_u32(bytes: &mut Vec<u8>, value: u32) { bytes.extend_from_slice(&value.to_le_bytes()); }

fn append_hash(bytes: &mut Vec<u8>, value: [u64; 4]) {
    for limb in value { bytes.extend_from_slice(&limb.to_le_bytes()); }
}

fn empty_root(height: usize) -> [u64; 4] {
    hash4(<PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(height))
}

fn empty_summary_root() -> [u64; 4] {
    let mut root = poseidon_bytes(b"PsyRewardLedger/Empty/1");
    for height in 1..=32u8 {
        let mut bytes = b"PsyRewardLedger/Node/1".to_vec();
        bytes.push(height);
        append_hash(&mut bytes, root);
        append_hash(&mut bytes, root);
        root = poseidon_bytes(&bytes);
    }
    root
}

fn summary_path(user_id: u32, value: [u64; 4], siblings: &[[u64; 4]; 32]) -> [u64; 4] {
    let mut root = value;
    for (height, sibling) in siblings.iter().enumerate() {
        let (left, right) = if user_id & (1 << height) == 0 { (root, *sibling) } else { (*sibling, root) };
        let mut bytes = b"PsyRewardLedger/Node/1".to_vec();
        bytes.push((height + 1) as u8);
        append_hash(&mut bytes, left);
        append_hash(&mut bytes, right);
        root = poseidon_bytes(&bytes);
    }
    root
}

fn verifier_hash(circuits: &AggregateCircuits) -> [u64; 4] {
    let verifier = &circuits.reward_session.circuit_data.verifier_only;
    let mut bytes = b"PsyRewardLedger/Verifier/1".to_vec();
    append_hash(&mut bytes, hash4(QHashOut(verifier.circuit_digest)));
    append_u32(&mut bytes, verifier.constants_sigmas_cap.0.len() as u32);
    for hash in &verifier.constants_sigmas_cap.0 { append_hash(&mut bytes, hash4(QHashOut(*hash))); }
    poseidon_bytes(&bytes)
}

fn ledger_window_hash(config_hash: [u8; 32], economic_domain: [u8; 32], window_id: [u8; 32],
    end_checkpoint_id: u32, checkpoint_root: [u64; 4], start_root: [u64; 4], verifier: [u64; 4]) -> [u64; 4]
{
    let mut bytes = b"PsyRewardLedger/Window/1".to_vec();
    bytes.extend(config_hash);
    bytes.extend(economic_domain);
    bytes.extend(window_id);
    append_u32(&mut bytes, end_checkpoint_id);
    for hash in [checkpoint_root, start_root, verifier] { append_hash(&mut bytes, hash); }
    poseidon_bytes(&bytes)
}

fn ledger_state_root(state: &RewardLedgerStateValues) -> [u64; 4] {
    let mut bytes = b"PsyRewardLedger/State/1".to_vec();
    for hash in [state.ledger_window_hash, state.ledger_root, state.user_root] { append_hash(&mut bytes, hash); }
    append_u32(&mut bytes, state.session_count);
    append_u32(&mut bytes, state.unfinished_session_count);
    poseidon_bytes(&bytes)
}

fn reward_publication_header(opening: &SourceCheckpointRewardOpening, old_ledger_state_root: [u64; 4], new_ledger_state_root: [u64; 4]) -> anyhow::Result<InclusionAggregateHeader> {
    let count = u32::try_from(opening.leaves.len()).context("reward publication count exceeds u32")?;
    anyhow::ensure!(count <= INCLUSION_AGGREGATE_CAPACITIES[0], "manager reward publication capacity is 1024");
    let mut header = InclusionAggregateHeader {
        family: REWARD_PUBLICATION_FAMILY, config_hash: opening.config_hash, window_id: opening.window_id,
        end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root: opening.end_checkpoint_root,
        aggregate_capacity: INCLUSION_AGGREGATE_CAPACITIES[0], total_count: count, segment_count: u32::from(count != 0),
        segment_index: 0, first_ordinal: 0, count, withdrawal_roots: Vec::new(),
        old_ledger_state_root: Some(old_ledger_state_root), new_ledger_state_root: Some(new_ledger_state_root),
        opening_digest: if count == 0 { [0; 32] } else { opening.opening_digest()? }, claim_tree_root: [0; 32],
    };
    if count != 0 {
        bind_claim_tree(&mut header, &opening.leaves.iter().map(|leaf| leaf.leaf_commit()).collect::<Result<Vec<_>, _>>()?)?;
    }
    header.validate()?;
    Ok(header)
}

struct RewardSessionFixture<'a> {
    opening: SourceCheckpointRewardOpening,
    header: InclusionAggregateHeader,
    witness: RewardSessionWitness<'a>,
    old_state: RewardLedgerStateValues,
    new_state: RewardLedgerStateValues,
    source_checkpoint_id: u32,
    source_siblings: [[u64; 4]; 32],
    summary_siblings: [[u64; 4]; 32],
    session_root: [u64; 4],
    statement: RewardSessionProofFields,
}


fn reward_session_fixture<'a>(circuits: &AggregateCircuits, config: &'a NetworkConfig, window_id: [u8; 32], checkpoint: &CheckpointOne, private_key: QHashOut<F>, authorization: &'a RewardAuthorizationWitness, jobs: &'a [RewardSessionJobWitness]) -> anyhow::Result<RewardSessionFixture<'a>> {
    let economic_domain = [6u8; 32];
    let source_checkpoint_id = 1u32;
    let end_checkpoint_id = 1u32;
    let checkpoint_tree_root = hash4(checkpoint.tree_root);
    let source_leaf: PsyCheckpointLeaf<F> = client_value(&checkpoint.new_leaf)?;
    let source_leaf_hash = hash4(source_leaf.qfhash::<PoseidonHash>());
    let end_leaf = source_leaf.clone();
    let end_roots: PsyCheckpointGlobalStateRoots<F> = client_value(&checkpoint.state.roots)?;
    let user_leaf: PsyUserLeaf<F> = client_value(&checkpoint.state.deposit.user_leaf)?;
    let user_id = user_leaf.user_id.to_canonical_u64() as u32;
    let recipient = [0x01020304u32, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314];
    let amount = {
        let mut amount = [0u32; 8];
        for (index, chunk) in config.reward_per_claim.chunks_exact(4).rev().enumerate() {
            amount[index] = u32::from_be_bytes(chunk.try_into()?);
        }
        amount
    };
    let mut seed_bytes = b"PsyRewardJobs/Session/1".to_vec();
    seed_bytes.extend(economic_domain);
    append_u32(&mut seed_bytes, source_checkpoint_id);
    append_u32(&mut seed_bytes, user_id);
    for word in recipient { append_u32(&mut seed_bytes, word); }
    append_hash(&mut seed_bytes, checkpoint_tree_root);
    append_hash(&mut seed_bytes, source_leaf_hash);
    let seed = poseidon_bytes(&seed_bytes);
    let tag = &jobs[0].tag;
    let leaf_tag = tag.leaf_tag;
    let nullifier_key = (u64::from(source_checkpoint_id) << 31) | (u64::from(jobs[0].height) << 26) | u64::from(jobs[0].path_index);
    let occupied = QHashOut(HashOut { elements: [F::ONE, F::ZERO, F::ZERO, F::ZERO] });
    let session_root = hash4(DeltaMerkleProofCore::from_params::<PoseidonHash>(nullifier_key, QHashOut::ZERO, occupied, jobs[0].nullifier_siblings.iter().copied().map(|sibling| QHashOut(HashOut { elements: sibling.map(F::from_canonical_u64) })).collect()).new_root);
    let public_key_param = hash4(SimplePsyPrivateKey::new(client_value(&private_key)?).get_public_key_param::<PoseidonHash>());
    let mut record = Vec::new();
    append_u32(&mut record, source_checkpoint_id);
    record.push(jobs[0].height);
    append_u32(&mut record, jobs[0].path_index);
    append_u32(&mut record, (1u32 << jobs[0].height) - 1 + jobs[0].path_index);
    append_u32(&mut record, user_id);
    for word in amount { append_u32(&mut record, word); }
    append_hash(&mut record, hash4(leaf_tag));
    record.extend([0, 1]);
    let mut jobs_bytes = b"PsyRewardJobs/Step/1".to_vec();
    append_hash(&mut jobs_bytes, seed);
    for count in [0u32, 1, 1] { append_u32(&mut jobs_bytes, count); }
    jobs_bytes.extend(record);
    let jobs_commitment = poseidon_bytes(&jobs_bytes);
    let verifier = verifier_hash(circuits);
    let start_root = empty_root(64);
    let window_hash = ledger_window_hash(config.config_hash()?, economic_domain, window_id, end_checkpoint_id, checkpoint_tree_root, start_root, verifier);
    let old_state = RewardLedgerStateValues { ledger_window_hash: [0; 4], ledger_root: empty_root(64), user_root: empty_summary_root(), session_count: 0, unfinished_session_count: 0 };
    let summary_siblings = empty_summary_siblings();
    let mut statement_prefix = [0u64; 30];
    statement_prefix[..4].copy_from_slice(&checkpoint_tree_root);
    statement_prefix[4] = u64::from(user_id);
    for (index, word) in recipient.into_iter().enumerate() { statement_prefix[5 + index] = u64::from(word); }
    for (index, word) in amount.into_iter().enumerate() { statement_prefix[13 + index] = u64::from(word); }
    statement_prefix[21] = 1;
    statement_prefix[22..26].copy_from_slice(&jobs_commitment);
    statement_prefix[26..30].copy_from_slice(&ledger_state_root(&old_state));
    let mut summary_bytes = b"PsyRewardSession/Summary/1".to_vec();
    for value in statement_prefix { summary_bytes.extend_from_slice(&value.to_le_bytes()); }
    append_hash(&mut summary_bytes, seed);
    append_hash(&mut summary_bytes, session_root);
    summary_bytes.push(1);
    let summary = poseidon_bytes(&summary_bytes);
    let user_root = summary_path(user_id, summary, &summary_siblings);
    let ledger_key = u64::from(user_id) | (u64::from(source_checkpoint_id) << 32);
    let mut issued = b"PsyRewardLedger/Issued/1".to_vec();
    issued.extend(economic_domain);
    append_u32(&mut issued, source_checkpoint_id);
    append_u32(&mut issued, user_id);
    for word in amount.into_iter().chain(recipient) { append_u32(&mut issued, word); }
    append_hash(&mut issued, jobs_commitment);
    append_hash(&mut issued, window_hash);
    let ledger_siblings = array_siblings(&[], ledger_key, 64);
    let ledger_root = hash4(compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(QHashOut(HashOut { elements: poseidon_bytes(&issued).map(F::from_canonical_u64) }), ledger_key, &ledger_siblings.iter().copied().map(|sibling| QHashOut(HashOut { elements: sibling.map(F::from_canonical_u64) })).collect::<Vec<_>>()));
    let new_state = RewardLedgerStateValues { ledger_window_hash: window_hash, ledger_root, user_root, session_count: 1, unfinished_session_count: 0 };
    let statement = RewardSessionProofFields {
        checkpoint_tree_root, user_id, recipient: [recipient[0], recipient[1], recipient[2], recipient[3], recipient[4], 0, 0, 0],
        total_amount: amount, count: 1, jobs_commitment, old_ledger_state_root: ledger_state_root(&old_state), new_ledger_state_root: ledger_state_root(&new_state),
    };
    let source_siblings = array_siblings(&[(1, hash4(checkpoint.new_leaf.qfhash::<PoseidonHash>()))], 1, 32);
    let user_path = path(&[(u64::from(user_id), user_leaf_hash(&checkpoint.state.deposit.user_leaf))], u64::from(user_id), GLOBAL_USER_TREE_HEIGHT).siblings.iter().map(|sibling| hash4(*sibling)).collect();
    let leaf = SourceCheckpointRewardLeaf { economic_domain, source_checkpoint_id: u64::from(source_checkpoint_id), user_id, amount, recipient: recipient_address(recipient), initialized: true };
    let opening = SourceCheckpointRewardOpening { config_hash: config.config_hash()?, window_id, end_checkpoint_id: u64::from(end_checkpoint_id), end_checkpoint_root: checkpoint_tree_root, leaves: vec![leaf] };
    let header = reward_publication_header(&opening, statement.old_ledger_state_root, statement.new_ledger_state_root)?;
    let witness = RewardSessionWitness {
        statement, config: config.clone(), economic_domain, window_id, start_root, source_checkpoint_id, end_checkpoint_id,
        source_leaf: source_leaf.clone(), source_path: source_siblings, old_state: copy_state(&old_state), new_state: copy_state(&new_state),
        own_state: copy_state(&old_state), old_summary: poseidon_bytes(b"PsyRewardLedger/Empty/1"), old_session_root: empty_root(63),
        session_siblings: summary_siblings, own_siblings: summary_siblings, ledger_siblings, own_previous: None, global_previous: None,
        jobs, is_final_step: true, end_leaf, end_path: source_siblings, end_roots, user_leaf, user_path, public_key_param,
        authorization: Some(authorization),
    };
    Ok(RewardSessionFixture { opening, header, witness, old_state, new_state, source_checkpoint_id, source_siblings, summary_siblings, session_root, statement })
}
fn copy_state(state: &RewardLedgerStateValues) -> RewardLedgerStateValues {
    RewardLedgerStateValues { ledger_window_hash: state.ledger_window_hash, ledger_root: state.ledger_root, user_root: state.user_root, session_count: state.session_count, unfinished_session_count: state.unfinished_session_count }
}
fn session_job(user_id: u32, source_checkpoint_id: u32) -> anyhow::Result<RewardSessionJobWitness> {
    let tag_preimage = QHashOut(HashOut { elements: [F::from_canonical_u32(user_id), F::from_canonical_u64(11), F::from_canonical_u64(22), F::from_canonical_u64(33)] });
    let leaf_tag = hash_two(tag_preimage, tag_preimage);
    let leaf_node = hash_tag_tree_node::<QHashOut<F>, PoseidonHash>(&QHashOut::ZERO, &QHashOut::ZERO, &leaf_tag);
    let mut tag = RewardTagWitness { tag_preimage, leaf_left: QHashOut::ZERO, leaf_right: QHashOut::ZERO, leaf_tag, siblings: [QHashOut::ZERO; 21], parent_tags: [QHashOut::ZERO; 21] };
    tag.siblings[0] = hash_two(leaf_node, leaf_node);
    tag.siblings[1] = hash_two(tag.siblings[0], tag.siblings[0]);
    tag.parent_tags[0] = leaf_tag;
    tag.parent_tags[1] = leaf_tag;
    let nullifier_key = (u64::from(source_checkpoint_id) << 31) | (2u64 << 26);
    Ok(RewardSessionJobWitness { height: 2, path_index: 0, tag, nullifier_siblings: array_siblings(&[], nullifier_key, 63) })
}




fn recipient_address(words: [u32; 5]) -> [u8; 20] {
    let mut address = [0u8; 20];
    for (index, word) in words.into_iter().enumerate() { address[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes()); }
    address
}

fn empty_summary_siblings() -> [[u64; 4]; 32] {
    let mut current = poseidon_bytes(b"PsyRewardLedger/Empty/1");
    std::array::from_fn(|height| {
        let sibling = current;
        let mut bytes = b"PsyRewardLedger/Node/1".to_vec();
        bytes.push((height + 1) as u8);
        append_hash(&mut bytes, current);
        append_hash(&mut bytes, current);
        current = poseidon_bytes(&bytes);
        sibling
    })
}

fn array_siblings<const HEIGHT: usize>(leaves: &[(u64, [u64; 4])], index: u64, height: usize) -> [[u64; 4]; HEIGHT] {
    siblings_from_known_leaves(leaves, index, height).try_into().expect("reward path height")
}



fn chain_proofs(circuits: &AggregateCircuits, config: &NetworkConfig, a: &DepositAggregateOpening,
    webs: &[Vec<ProofWithPublicInputs<F, C, D>>], tree: &[[u8; 32]],
) -> anyhow::Result<Vec<ProofWithPublicInputs<F, C, D>>> {
    let context = ChainContext { config_hash: a.config_hash, end_checkpoint_id: a.end_checkpoint_id,
        end_checkpoint_root: a.end_checkpoint_root, global_deposit_leaf_root: tree[0], global_deposit_count: a.deposit_leaves.len() as u32 };
    let mut first = 0;
    (0..CHAIN_INDICES.len()).map(|ordinal| {
        let range = DepositLeafRange { first_leaf: first, leaf_count: a.deposits[ordinal].new_count - a.deposits[ordinal].old_count };
        first += range.leaf_count;
        let row = ChainRow { start: a.starts[ordinal].clone(), transition: a.deposits[ordinal].clone(), range };
        circuits.chains.prove(config, &context, ordinal as u32, &row, &webs[ordinal])
    }).collect()
}

#[test]
fn real_multichain_artifacts_bind_nonempty_complete_openings() -> anyhow::Result<()> {
    let (coordinator, circuits) = circuits()?;
    let private_key: QHashOut<F> = QHashOut::from_values(11, 22, 33, 44);
    let identity = circuits.reward_session.identity_fingerprint_for_scheme(0)?;
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
    let ends: Vec<_> = (0..3).map(|chain| ChainState {
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
    let mut a = DepositAggregateOpening {
        config_hash: config.config_hash()?, window_id: [0; 32], end_checkpoint_id: 1, end_checkpoint_root: hash4(checkpoint.tree_root),
        starts: (0..3).map(|chain_index| ChainStart { chain_index, start_checkpoint_id: if chain_index == 2 { 1 } else { 0 }, start_checkpoint_root: hash4(if chain_index == 2 { checkpoint.tree_root } else { checkpoint.genesis_tree_root }) }).collect(),
        deposits: ends.iter().enumerate().map(|(i, end)| DepositTransition { chain_index: end.chain_index, old_root: hash4(old_roots[i]), new_root: end.deposit_root, old_count: [31, 0, 0][i], new_count: end.deposit_count }).collect(), deposit_leaves: deposits,
    };
    a.window_id = a.window_id()?;
    let withdrawals_opening = WithdrawalAggregateOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: 1, end_checkpoint_root: a.end_checkpoint_root, withdrawal_roots: ends.iter().map(|end| end.withdrawal_root).collect(), withdrawals: withdrawals.clone() };
    let reward_authorization = RewardAuthorizationWitness::Zk { private_key: client_value(&private_key)? };
    let reward_jobs = [session_job(BRIDGE_USER_ID as u32, 1)?];
    let reward_session = reward_session_fixture(circuits, &config, a.window_id, &checkpoint, private_key, &reward_authorization, &reward_jobs)?;
    let rewards_opening = reward_session.opening.clone();
    a.validate(&config)?; withdrawals_opening.validate(&config)?; rewards_opening.encode()?;
    let tree = deposit_leaf_tree(&a.deposit_leaves.iter().map(DepositLeaf::leaf_commit).collect::<Result<Vec<_>, _>>()?)?;
    let web_inputs: Vec<_> = a.deposit_leaves.iter().enumerate().map(|(i, leaf)| Ok(DepositSpidermanAppendInputs {
        config_hash: a.config_hash, end_checkpoint_id: 1, end_checkpoint_root: checkpoint.tree_root, chain_index: leaf.chain_index,
        old_count: leaf.absolute_index, first_leaf: i as u32, global_deposit_leaf_root: tree[0], global_deposit_count: 3,
        leaf_paths: vec![deposit_leaf_path(&tree, 3, i as u32)?], deposits: vec![leaf.clone()], append_proof: append_proofs[i].clone(),
    })).collect::<anyhow::Result<_>>()?;
    let mut webs = vec![Vec::new(), Vec::new(), Vec::new()];
    for input in &web_inputs { webs[input.chain_index as usize].push(circuits.deposit.prove(input)?); }
    let chains = chain_proofs(circuits, &config, &a, &webs, &tree)?;
    let proof_a = circuits.prove_deposit_aggregate(&config, &a, &chains)?;
    circuits.deposit_aggregate.circuit_data.verify(proof_a.clone())?;
    assert_opening_digest(&proof_a, 11, 1, a.opening_digest(&config)?);

    let endpoints = ends.iter().enumerate().map(|(ordinal, end)| {
        let root = |contract: usize| TreeRootInContractStateWitnessInput {
            slot0_proof: checkpoint.state.chains[contract][ordinal][1].slot_proof.clone(),
            slot1_proof: checkpoint.state.chains[contract][ordinal][2].slot_proof.clone(),
            ..if contract == 0 { checkpoint.state.deposit.clone() } else { checkpoint.state.withdrawal.clone() }
        };
        BridgeAggFinalEndpointWitness { chain_index: end.chain_index,
            deposit_root: root(0), deposit_count: checkpoint.state.chains[0][ordinal][0].clone(),
            withdrawal_root: root(1), withdrawal_count: checkpoint.state.chains[1][ordinal][0].clone() }
    }).collect::<Vec<_>>();
    let source_chain = BridgeAggChainCircuit::<C, D>::new(coordinator.checkpoint_root_transition.get_fingerprint(), CHECKPOINT_TREE_HEIGHT);
    let source_base = source_chain.prove_base(BridgeAggChainBoundary { chain_hash: checkpoint.genesis_chain_hash,
        checkpoint_tree_root: checkpoint.genesis_tree_root, checkpoint_leaf_hash: checkpoint.genesis_leaf_hash, checkpoint_index: 0 }, &checkpoint.append)?;
    let final_proof = circuits.checkpoint_final.prove_base(&source_base, source_chain.get_verifier_config_ref(),
        &[BridgeAggFinalSlotWitness { checkpoint_delta_merkle_proof: &checkpoint.append }], &checkpoint.proof,
        coordinator.checkpoint_root_transition.get_verifier_config_ref(), &checkpoint.new_leaf_compact, &checkpoint.state.roots,
        &checkpoint.state.deposit, &checkpoint.state.withdrawal, &endpoints)?;
    circuits.checkpoint_final.circuit_data.verify(final_proof.clone())?;
    for (ordinal, end) in ends.iter().enumerate() {
        let offset = 26 + 9 * ordinal;
        assert_eq!(final_proof.public_inputs[offset..offset + 4], end.deposit_root.map(F::from_canonical_u64));
        assert_eq!(final_proof.public_inputs[offset + 4], F::from_canonical_u32(end.deposit_count));
        assert_eq!(final_proof.public_inputs[offset + 5..offset + 9], end.withdrawal_root.map(F::from_canonical_u64));
    }
    let withdrawal_inputs: Vec<_> = withdrawals.iter().zip(&withdrawal_paths).map(|(leaf, path)| WithdrawalInclusionInputs {
        config_hash: a.config_hash, end_checkpoint_id: 1, end_checkpoint_root: a.end_checkpoint_root,
        withdrawal_root: hash4(path.root), leaf: leaf.clone(), witness: WithdrawalWitness { leaf_index: 0, siblings: std::array::from_fn(|i| hash4(path.siblings[i])) },
    }).collect();
    let withdrawal_proofs = withdrawal_inputs.iter().map(|input| circuits.withdrawal.generate_proof(input)).collect::<anyhow::Result<Vec<_>>>()?;
    let root_paths = withdrawal_paths_for(&config, &ends)?;
    let withdrawal_leaves: Vec<_> = withdrawals.iter().zip(&withdrawal_proofs).zip(&root_paths).map(|((leaf, proof), path)| WithdrawalAggregateLeaf { leaf, proof, path }).collect();
    let withdrawal_header = withdrawal_publication_header(&config, &withdrawals_opening)?;
    let proof_w = circuits.prove_withdrawal_aggregate(&config, &withdrawals_opening, &withdrawal_header, &withdrawal_leaves)?;
    circuits.withdrawal_aggregate.circuit_data.verify(proof_w.clone())?;
    assert_withdrawal_publication(&proof_w, &withdrawal_header);
    let mut flat_preimage = keccak(b"PsyBridge/TwoArtifact/1/WithdrawalBatch").to_vec();
    let encoded_w = withdrawals_opening.encode()?;
    assert_eq!(encoded_w.len(), 288 + 128 * CHAIN_INDICES.len() + 192 * withdrawals.len());
    flat_preimage.extend(encoded_w);
    assert_eq!(withdrawal_header.opening_digest, keccak(&flat_preimage));
    let reward_proof = circuits.reward_session.prove(&reward_session.witness)?;
    circuits.reward_session.circuit_data.verify(reward_proof.clone())?;
    let tip = RewardLedgerFinalProof { proof: &reward_proof, state: &reward_session.new_state };
    let reward_leaves = [SourceCheckpointRewardAggregateLeaf {
        leaf: &rewards_opening.leaves[0], proof: &reward_proof, state: &reward_session.new_state,
        source_checkpoint_id: reward_session.source_checkpoint_id, source_leaf: &reward_session.witness.source_leaf,
        source_siblings: &reward_session.source_siblings, session_root: reward_session.session_root,
        summary_siblings: &reward_session.summary_siblings,
    }];
    let reward_header = reward_session.header.clone();
    let proof_r = circuits.prove_reward_aggregate(&config, &rewards_opening, &reward_header, &tip, &reward_leaves)?;
    circuits.reward_aggregate.circuit_data.verify(proof_r.clone())?;
    assert_eq!(proof_r.public_inputs, reward_header.publication_words()?.map(F::from_canonical_u32));

    // Opening mutations must fail canonical validation before proving.
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
        rejects(|| circuits.prove_deposit_aggregate(&config, &changed, &chains).map(|_| ()));
    }
    for mutation in 0..9 {
        let mut changed = withdrawals_opening.clone();
        match mutation {
            0 => { changed.withdrawals.pop(); },
            1 => changed.withdrawals[0].recipient[0] ^= 1,
            2 => changed.withdrawals[0].nonce = word(100),
            3 => changed.end_checkpoint_root[0] ^= 1,
            4 => changed.withdrawals[0].chain_index = 255,
            5 => changed.withdrawal_roots[0][0] ^= 1,
            6 => changed.withdrawal_roots.swap(0, 1),
            7 => { changed.withdrawal_roots.pop(); },
            _ => changed.end_checkpoint_id += 1,
        }
        let changed_header = withdrawal_publication_header(&config, &changed);
        rejects(|| changed_header.and_then(|header| circuits.prove_withdrawal_aggregate(&config, &changed, &header, &withdrawal_leaves).map(|_| ())));
    }
    for mutation in 0..5 {
        let mut changed = rewards_opening.clone();
        match mutation {
            0 => changed.leaves.clear(),
            1 => changed.leaves[0].recipient[0] ^= 1,
            2 => changed.leaves[0].source_checkpoint_id = 2,
            3 => changed.end_checkpoint_id = 2,
            _ => changed.leaves[0].user_id = 1,
        }
        let changed_header = reward_publication_header(&changed, reward_session.statement.old_ledger_state_root, reward_session.statement.new_ledger_state_root);
        rejects(|| changed_header.and_then(|header| circuits.prove_reward_aggregate(&config, &changed, &header, &tip, &reward_leaves).map(|_| ())));
    }
    // Witness assignment must succeed here: only the prover may reject these constraints.
    for mutation in 0..4 {
        let original = &web_inputs[0];
        let mut changed = DepositSpidermanAppendInputs {
            config_hash: original.config_hash, end_checkpoint_id: original.end_checkpoint_id,
            end_checkpoint_root: original.end_checkpoint_root, chain_index: original.chain_index,
            old_count: original.old_count, first_leaf: original.first_leaf,
            global_deposit_leaf_root: original.global_deposit_leaf_root, global_deposit_count: original.global_deposit_count,
            leaf_paths: original.leaf_paths.clone(), deposits: original.deposits.clone(), append_proof: original.append_proof.clone(),
        };
        match mutation {
            0 => changed.leaf_paths[0][0][0] ^= 1,
            1 => changed.first_leaf = 1,
            2 => changed.append_proof.web_proof_old_leaves[31] = qhash(999),
            _ => changed.deposits[0].absolute_index += 1,
        }
        let mut witness = plonky2::iop::witness::PartialWitness::new();
        circuits.deposit.set_witness(&mut witness, &changed)?;
        assert!(circuits.deposit.circuit_data.prove(witness).is_err(), "invalid web constraints proved");
    }
    // Endpoint storage authentication now belongs exclusively to the finalizer.
    for mutation in 0..4 {
        let mut changed = endpoints.clone();
        match mutation {
            0 => changed[0].deposit_count.slot_proof.value.0.elements[0] += F::ONE,
            1 => changed[0].deposit_root = changed[1].deposit_root.clone(),
            2 => changed[0].withdrawal_root.slot0_proof.siblings[0] = qhash(999),
            _ => { changed.pop(); },
        }
        rejects(|| circuits.checkpoint_final.prove_base(&source_base, source_chain.get_verifier_config_ref(),
            &[BridgeAggFinalSlotWitness { checkpoint_delta_merkle_proof: &checkpoint.append }], &checkpoint.proof,
            coordinator.checkpoint_root_transition.get_verifier_config_ref(), &checkpoint.new_leaf_compact, &checkpoint.state.roots,
            &checkpoint.state.deposit, &checkpoint.state.withdrawal, &changed).map(|_| ()));
    }
    // Session authentication mutations must fail before producing the terminal session proof.
    for mutation in 0..4 {
        let base = &reward_session.witness;
        let (jobs, authorization, user_leaf) = match mutation {
            0 => { let mut jobs = reward_jobs.clone(); jobs[0].tag.siblings[0] = qhash(999); (jobs, reward_authorization.clone(), base.user_leaf) },
            1 => { let mut jobs = reward_jobs.clone(); jobs[0].path_index = 2; (jobs, reward_authorization.clone(), base.user_leaf) },
            2 => { let mut user_leaf = base.user_leaf; user_leaf.last_checkpoint_id = F::from_canonical_u32(2); (reward_jobs.clone(), reward_authorization.clone(), user_leaf) },
            _ => (reward_jobs.clone(), RewardAuthorizationWitness::Zk { private_key: client_value(&qhash(999))? }, base.user_leaf),
        };
        let changed = RewardSessionWitness {
            statement: base.statement, config: config.clone(), economic_domain: base.economic_domain, window_id: base.window_id,
            start_root: base.start_root, source_checkpoint_id: base.source_checkpoint_id, end_checkpoint_id: base.end_checkpoint_id,
            source_leaf: base.source_leaf.clone(), source_path: base.source_path, old_state: copy_state(&base.old_state),
            new_state: copy_state(&base.new_state), own_state: copy_state(&base.own_state), old_summary: base.old_summary,
            old_session_root: base.old_session_root, session_siblings: base.session_siblings, own_siblings: base.own_siblings,
            ledger_siblings: base.ledger_siblings, own_previous: None, global_previous: None, jobs: &jobs, is_final_step: true,
            end_leaf: base.end_leaf.clone(), end_path: base.end_path, end_roots: base.end_roots, user_leaf, user_path: base.user_path.clone(),
            public_key_param: base.public_key_param, authorization: Some(&authorization),
        };
        rejects(|| circuits.reward_session.prove(&changed).map(|_| ()));
    }
    let mut fabricated = withdrawal_inputs[0].clone();
    fabricated.leaf.amount = word(999);
    fabricated.withdrawal_root = hash4(path(&[(0, withdrawal_hash(&fabricated.leaf))], 0, 32).root);
    let fabricated_proof = circuits.withdrawal.generate_proof(&fabricated)?;
    circuits.withdrawal.circuit_data.verify(fabricated_proof.clone())?;
    let mut fabricated_opening = withdrawals_opening.clone();
    fabricated_opening.withdrawals[0] = fabricated.leaf.clone();
    let fabricated_header = withdrawal_publication_header(&config, &fabricated_opening)?;
    let changed_leaves = [
        WithdrawalAggregateLeaf { leaf: &fabricated.leaf, proof: &fabricated_proof, path: &root_paths[0] },
        WithdrawalAggregateLeaf { leaf: &withdrawals[1], proof: &withdrawal_proofs[1], path: &root_paths[1] },
        WithdrawalAggregateLeaf { leaf: &withdrawals[2], proof: &withdrawal_proofs[2], path: &root_paths[2] },
    ];
    let mut witness = plonky2::iop::witness::PartialWitness::new();
    circuits.withdrawal_aggregate.set_witness(&mut witness, &config, &AggregateWindow { config_hash: a.config_hash, window_id: a.window_id, end_id: 1, end_root: a.end_checkpoint_root }, &fabricated_header, &changed_leaves)?;
    assert!(circuits.withdrawal_aggregate.circuit_data.prove(witness).is_err(), "fabricated withdrawal root joined digest-bound vector");
    let one_opening = WithdrawalAggregateOpening { withdrawals: vec![withdrawals[0].clone()], ..withdrawals_opening.clone() };
    let one_header = withdrawal_publication_header(&config, &one_opening)?;
    let mut wrong_path = root_paths[0].clone(); wrong_path.siblings[0][0] ^= 1;
    let mut witness = plonky2::iop::witness::PartialWitness::new();
    circuits.withdrawal_aggregate.set_witness(&mut witness, &config, &AggregateWindow { config_hash: a.config_hash, window_id: a.window_id, end_id: 1, end_root: a.end_checkpoint_root }, &one_header, &[WithdrawalAggregateLeaf { leaf: &withdrawals[0], proof: &withdrawal_proofs[0], path: &wrong_path }])?;
    assert!(circuits.withdrawal_aggregate.circuit_data.prove(witness).is_err(), "changed withdrawal-root sibling proved");
    let empty_withdrawals = WithdrawalAggregateOpening { withdrawals: Vec::new(), ..withdrawals_opening.clone() };
    let empty_header = withdrawal_publication_header(&config, &empty_withdrawals)?;
    assert_eq!(empty_header.count, 0);
    assert_eq!(empty_header.opening_digest, [0; 32]);
    assert_eq!(empty_header.claim_tree_root, [0; 32]);
    assert_eq!(empty_header.withdrawal_roots, withdrawals_opening.withdrawal_roots);
    let empty_rewards = SourceCheckpointRewardOpening { leaves: Vec::new(), ..rewards_opening.clone() };
    let empty_reward_header = reward_publication_header(&empty_rewards, reward_session.statement.old_ledger_state_root, reward_session.statement.old_ledger_state_root)?;
    assert_eq!(empty_reward_header.count, 0);
    assert_eq!(empty_reward_header.opening_digest, [0; 32]);
    for mutation in 0..2 {
        let mut changed = empty_withdrawals.clone();
        if mutation == 0 { changed.withdrawal_roots[2][0] ^= 1; }
        else { changed.window_id[0] ^= 1; }
        let changed_header = withdrawal_publication_header(&config, &changed)?;
        assert_ne!(changed_header.encode()?, empty_header.encode()?, "empty W omitted its roots or context");
        assert_eq!(changed_header.opening_digest, [0; 32]);
        assert_eq!(changed_header.claim_tree_root, [0; 32]);
    }
    rejects(|| circuits.prove_withdrawal_aggregate(&config, &withdrawals_opening, &withdrawal_header, &[]).map(|_| ()));
    let mut wrong_pin = withdrawal_header.clone();
    wrong_pin.opening_digest[31] ^= 1;
    rejects(|| circuits.prove_withdrawal_aggregate(&config, &withdrawals_opening, &wrong_pin, &withdrawal_leaves).map(|_| ()));
    let mut wrong_root = withdrawal_header.clone();
    wrong_root.claim_tree_root[31] ^= 1;
    rejects(|| circuits.prove_withdrawal_aggregate(&config, &withdrawals_opening, &wrong_root, &withdrawal_leaves).map(|_| ()));
    rejects(|| circuits.prove_reward_aggregate(&config, &rewards_opening, &reward_header, &tip, &[]).map(|_| ()));
    let mut wrong_source = *reward_leaves[0].source_siblings;
    wrong_source[0][0] ^= 1;
    let wrong_source_leaf = SourceCheckpointRewardAggregateLeaf { source_siblings: &wrong_source, ..reward_leaves[0] };
    rejects(|| circuits.prove_reward_aggregate(&config, &rewards_opening, &reward_header, &tip, &[wrong_source_leaf]).map(|_| ()));
    let mut forked_recipient = rewards_opening.leaves[0].clone();
    forked_recipient.recipient[0] ^= 1;
    let forked_opening = SourceCheckpointRewardOpening { leaves: vec![forked_recipient.clone()], ..rewards_opening.clone() };
    let forked_header = reward_publication_header(&forked_opening, reward_session.statement.old_ledger_state_root, reward_session.statement.new_ledger_state_root)?;
    let forked_leaf = SourceCheckpointRewardAggregateLeaf { leaf: &forked_recipient, ..reward_leaves[0] };
    rejects(|| circuits.prove_reward_aggregate(&config, &forked_opening, &forked_header, &tip, &[forked_leaf]).map(|_| ()));
    let mut wrong_reward_root = reward_header.clone();
    wrong_reward_root.claim_tree_root[31] ^= 1;
    rejects(|| circuits.prove_reward_aggregate(&config, &rewards_opening, &wrong_reward_root, &tip, &reward_leaves).map(|_| ()));
    let mut forked_tip_state = copy_state(&reward_session.new_state);
    forked_tip_state.ledger_root[0] ^= 1;
    let forked_tip = RewardLedgerFinalProof { proof: &reward_proof, state: &forked_tip_state };
    rejects(|| circuits.prove_reward_aggregate(&config, &rewards_opening, &reward_header, &forked_tip, &reward_leaves).map(|_| ()));

    let mut wrong_config = config.clone(); wrong_config.circuit_set_hash[0] ^= 1;
    rejects(|| circuits.prove_deposit_aggregate(&wrong_config, &a, &chains).map(|_| ()));
    circuits.validate_registrations(circuits.registrations())?;
    let mut changed_pin = circuits.registrations().to_vec();
    changed_pin[0].verifier_digest[0] ^= 1;
    psy_client_data::bridge_aggregate::circuit_set_hash(&changed_pin)?;
    assert!(circuits.validate_registrations(&changed_pin).is_err());
    let mut removed_family = circuits.registrations().to_vec();
    removed_family.retain(|entry| entry.family != 11);
    assert!(psy_client_data::bridge_aggregate::circuit_set_hash(&removed_family).is_err());
    assert!(circuits.validate_registrations(&removed_family).is_err());
    let mut four_chains = config.clone();
    let mut fourth = four_chains.chains[2].clone();
    fourth.chain_index = 3;
    fourth.chain_id = word(4);
    four_chains.chains.push(fourth);
    four_chains.validate()?;
    assert!(circuits.validate_config(&four_chains).is_err());
    let mut different_indices = config.clone();
    different_indices.chains[2].chain_index = 3;
    different_indices.validate()?;
    assert!(circuits.validate_config(&different_indices).is_err());
    let mut tampered = proof_a.clone(); tampered.public_inputs[4] += F::ONE;
    assert!(circuits.deposit_aggregate.circuit_data.verify(tampered).is_err());
    Ok(())
}
