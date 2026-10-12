//! Authenticated child-proof fixtures for the bridge claim circuits.
//!
//! Every accepted proof is produced through `BridgeWithdrawalClaimCircuit::prove`
//! or `BridgeRewardClaimCircuit::prove`. Rejected cases use the same witness API.
//! No proof is replaced by a dummy and no computed target is overwritten.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use parth_core::{
    crypto::hash::merkle_proof::{compute_historical_and_current_merkle_roots_core_gt, MerkleProofCore},
    pgoldilocks::QHashOut as CircuitHash,
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::{config::{Hasher, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs},
};
use psy_client_common::data::qhashout::QHashOut as ClientHash;
use psy_client_data::qdata::{
    checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
    contract::PsyContractLeaf,
    imt_contract_state::IMTContractStateLeaf,
    user::PsyUserLeaf,
    user_contract_state::UserContractState,
};
use psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit;
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT};
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_plonky2_circuits::{
    bridge::{
        circuits::{
            bridge_claim::{
                BridgeRewardClaimCircuit, BridgeRewardClaimInput, BridgeRewardClaimWitness,
                BridgeTokenPolicy, BridgeWithdrawalClaimCircuit, BridgeWithdrawalClaimInput,
                BridgeWithdrawalClaimWitness, BRIDGE_CLAIM_CAPACITY, BRIDGE_REWARD_CLAIM_STATEMENT_LEN,
                BRIDGE_REWARD_CLAIM_WORDS, BRIDGE_REWARD_CONTRACT_ID, BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN,
                BRIDGE_WITHDRAWAL_CLAIM_WORDS,
            },
            reward_chain::{
                AuthenticatedJobWitness, RewardMergeCircuit, RewardMergeWitness, RewardRootCircuit,
                RewardRootWitness, RewardSegmentCircuit, RewardSegmentSourceWitness, RewardSegmentWitness,
                RewardTagWitness, REWARD_MERGE_STATEMENT_LEN, REWARD_ROOT_STATEMENT_LEN, REWARD_SEGMENT_STATEMENT_LEN,
            },
            reward_claim_batch::{RewardClaimBatchCircuit, RewardClaimBatchMode, RewardClaimBatchWitness, REWARD_CLAIM_BATCH_STATEMENT_LEN},
        },
        gadgets::reward_nullifier::{RewardNullifierSourceWitness, INNER_EMPTY_ROOT, REWARD_NULLIFIER_EMPTY_LEAF, REWARD_NULLIFIER_INNER_HEIGHT, REWARD_NULLIFIER_OCCUPIED_LEAF, REWARD_NULLIFIER_OUTER_HEIGHT},
    },
    qstandard::QStandardCircuit,
};
use psy_ups_circuit::signature::software_defined::get_sdc_public_key_param;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type Leaves = BTreeMap<u64, HashOut<F>>;

const STATE_HEIGHT: usize = 32;
const KIND_WITHDRAWAL: u32 = 1;
const KIND_REWARD: u32 = 2;
const WITHDRAWAL_NAMESPACE: u64 = 6;
const USER_HEIGHT: usize = GLOBAL_USER_TREE_HEIGHT as usize;
const CONTRACT_HEIGHT: usize = GLOBAL_CONTRACT_TREE_HEIGHT as usize;
const CHECKPOINT_HEIGHT: usize = CHECKPOINT_TREE_HEIGHT as usize;
const REWARD_JOB_HEIGHT: usize = 6;


fn sparse_path<const HEIGHT: usize>(leaves: &Leaves, mut index: u64, mut empty: HashOut<F>) -> ([HashOut<F>; HEIGHT], HashOut<F>) {
    let mut nodes = leaves.clone();
    let siblings = std::array::from_fn(|_| {
        let sibling = nodes.get(&(index ^ 1)).copied().unwrap_or(empty);
        let mut parents = BTreeMap::new();
        let positions = nodes.keys().copied().chain([index]).map(|position| position >> 1).collect::<Vec<_>>();
        for parent in positions {
            let left = parent << 1;
            parents.insert(parent, PoseidonHash::two_to_one(
                nodes.get(&left).copied().unwrap_or(empty),
                nodes.get(&(left + 1)).copied().unwrap_or(empty),
            ));
        }
        nodes = parents;
        empty = PoseidonHash::two_to_one(empty, empty);
        index >>= 1;
        sibling
    });
    (siblings, nodes.get(&0).copied().unwrap_or(empty))
}

fn tagged(left: HashOut<F>, right: HashOut<F>, tag: HashOut<F>) -> HashOut<F> {
    PoseidonHash::two_to_one(PoseidonHash::two_to_one(left, right), tag)
}

fn limb(output: &[F], slot: usize, opening_word: usize, limb: usize) -> F {
    output[14 + slot * BRIDGE_WITHDRAWAL_CLAIM_WORDS * 8 + opening_word * 8 + limb]
}

fn reward_limb(output: &[F], slot: usize, opening_word: usize, limb: usize) -> F {
    output[6 + slot * BRIDGE_REWARD_CLAIM_WORDS * 8 + opening_word * 8 + limb]
}

fn policy(chain_index: u8, token_contract_id: u32, token: u32, map_base: u32, capacity: u32) -> BridgeTokenPolicy {
    BridgeTokenPolicy {
        chain_index,
        token_contract_id,
        token_address: [0, 0, 0, token, token + 1, token + 2, token + 3, token + 4],
        approved_leaf: PsyContractLeaf {
            deployer: F::from_canonical_u32(u32::from(chain_index) * 100 + token_contract_id),
            function_tree_root: ClientHash(HashOut::from_partial(&[F::from_canonical_u32(token_contract_id + 1)])),
            code_root: ClientHash(HashOut::from_partial(&[F::from_canonical_u32(token_contract_id + 2)])),
            state_tree_height: F::from_canonical_usize(STATE_HEIGHT),
            state_layout_root: ClientHash(HashOut::from_partial(&[F::from_canonical_u32(token_contract_id + 3)])),
            state_layout_field_count: F::from_canonical_u32(9),
            state_layout_slot_count: F::from_canonical_u32(11),
        },
        map_base,
        capacity,
    }
}

struct WithdrawalTree {
    state: Leaves,
    sentinel: IMTContractStateLeaf<F>,
    sentinel_siblings: [HashOut<F>; STATE_HEIGHT],
    state_root: HashOut<F>,
    contract_siblings: [HashOut<F>; CONTRACT_HEIGHT],
    contract_root: HashOut<F>,
    gcon: HashOut<F>,
}

fn withdrawal_tree(token: &BridgeTokenPolicy, members: &[(u32, IMTContractStateLeaf<F>)]) -> WithdrawalTree {
    let mut state = Leaves::new();
    let sentinel = IMTContractStateLeaf {
        key: ClientHash::ZERO,
        value: ClientHash::from_values(members.len() as u64, 0, 0, 0),
        next_key: members.first().map(|(index, member)| if *index == token.map_base + 1 { member.key } else { ClientHash::ZERO }).unwrap_or(ClientHash::ZERO),
        next_index: F::from_canonical_u32(members.first().map(|(index, _)| *index).unwrap_or(0)),
    };
    state.insert(u64::from(token.map_base), sentinel.qfhash::<PoseidonHash>().0);
    for (index, member) in members {
        state.insert(u64::from(*index), member.qfhash::<PoseidonHash>().0);
    }
    let (sentinel_siblings, state_root) = sparse_path::<STATE_HEIGHT>(&state, u64::from(token.map_base), HashOut::ZERO);
    let contracts = Leaves::from([(u64::from(token.token_contract_id), state_root)]);
    let (contract_siblings, contract_root) = sparse_path::<CONTRACT_HEIGHT>(&contracts, u64::from(token.token_contract_id), HashOut::ZERO);
    let definitions = Leaves::from([(u64::from(token.token_contract_id), token.approved_leaf.qfhash::<PoseidonHash>().0)]);
    let (_, gcon) = sparse_path::<CONTRACT_HEIGHT>(&definitions, u64::from(token.token_contract_id), HashOut::ZERO);
    WithdrawalTree { state, sentinel, sentinel_siblings, state_root, contract_siblings, contract_root, gcon }
}

fn burn(sender: u32, token: &BridgeTokenPolicy, recipient: [u32; 8], amount: [u32; 8], nonce: [u32; 8]) -> (ClientHash<F>, ClientHash<F>) {
    let nonce_hash = PoseidonHash::hash_no_pad(&nonce.map(F::from_canonical_u32));
    let mut key_inputs = vec![F::from_canonical_u64(WITHDRAWAL_NAMESPACE)];
    key_inputs.extend(nonce_hash.elements);
    let key = ClientHash(PoseidonHash::hash_no_pad(&key_inputs));
    let mut value_inputs = vec![F::from_canonical_u32(sender)];
    for word in [recipient, token.token_address, amount, nonce] {
        value_inputs.extend(word.map(F::from_canonical_u32));
    }
    value_inputs.push(F::from_canonical_u8(token.chain_index));
    (key, ClientHash(PoseidonHash::hash_no_pad(&value_inputs)))
}

struct WithdrawalClaimSpec {
    policy_ordinal: u8,
    sender: u32,
    member_index: u32,
    member: IMTContractStateLeaf<F>,
    recipient: [u32; 8],
    amount: [u32; 8],
    nonce: [u32; 8],
}

fn withdrawal_input(
    policies: &[BridgeTokenPolicy],
    trees: &[WithdrawalTree],
    claims: &[WithdrawalClaimSpec],
    end_checkpoint_id: u32,
    end_checkpoint_root: HashOut<F>,
) -> BridgeWithdrawalClaimInput {
    let mut users = Leaves::new();
    let mut prepared = Vec::new();
    for claim in claims {
        let tree = &trees[claim.policy_ordinal as usize];
        let user_leaf = PsyUserLeaf {
            user_id: F::from_canonical_u32(claim.sender),
            user_state_tree_root: ClientHash(tree.contract_root),
            ..PsyUserLeaf::default()
        };
        users.insert(u64::from(claim.sender), user_leaf.alghash::<PoseidonHash>().0);
        prepared.push((claim, user_leaf));
    }
    let mut witnesses = Vec::new();
    let mut gusr = HashOut::ZERO;
    for (claim, user_leaf) in prepared {
        let tree = &trees[claim.policy_ordinal as usize];
        let token = &policies[claim.policy_ordinal as usize];
        let (user_siblings, root) = sparse_path::<USER_HEIGHT>(&users, u64::from(claim.sender), HashOut::ZERO);
        gusr = root;
        let (member_siblings, member_root) = sparse_path::<STATE_HEIGHT>(&tree.state, u64::from(claim.member_index), HashOut::ZERO);
        assert_eq!(member_root, tree.state_root);
        witnesses.push(BridgeWithdrawalClaimWitness {
            policy_ordinal: claim.policy_ordinal,
            user_contract: UserContractState {
                checkpoint_tree_root: ClientHash::default(),
                user_leaf,
                start_contract_state_root: ClientHash(tree.state_root),
                contract_id: F::from_canonical_u32(token.token_contract_id),
                checkpoint_id: F::from_canonical_u8(token.chain_index),
            },
            user_siblings,
            contract_siblings: tree.contract_siblings,
            global_contract_siblings: [HashOut::ZERO; CONTRACT_HEIGHT],
            member_index: claim.member_index,
            member: claim.member,
            member_siblings,
            sentinel: tree.sentinel,
            sentinel_siblings: tree.sentinel_siblings,
            recipient: claim.recipient,
            token_address: token.token_address,
            amount: claim.amount,
            nonce: claim.nonce,
        });
    }
    let mut definitions = Leaves::new();
    for token in policies {
        definitions.insert(u64::from(token.token_contract_id), token.approved_leaf.qfhash::<PoseidonHash>().0);
    }
    let mut gcon = HashOut::ZERO;
    for witness in &mut witnesses {
        let token = &policies[witness.policy_ordinal as usize];
        let (siblings, root) = sparse_path::<CONTRACT_HEIGHT>(&definitions, u64::from(token.token_contract_id), HashOut::ZERO);
        gcon = root;
        witness.global_contract_siblings = siblings;
    }
    BridgeWithdrawalClaimInput {
        end_checkpoint_id,
        end_checkpoint_root,
        end_gusr: gusr,
        end_gcon: gcon,
        claims: witnesses,
    }
}

fn one_member(token: &BridgeTokenPolicy, sender: u32, nonce_word: u32) -> WithdrawalClaimSpec {
    let recipient = [0, 0, 0, nonce_word, 8, 7, 6, 5];
    let amount = [0, 0, 0, 0, 0, 0, 0, 1];
    let nonce = [nonce_word, 2, 3, 4, 5, 6, 7, 8];
    let (key, value) = burn(sender, token, recipient, amount, nonce);
    let member = IMTContractStateLeaf { key, value, next_key: ClientHash::ZERO, next_index: F::ZERO };
    WithdrawalClaimSpec { policy_ordinal: 0, sender, member_index: token.map_base + 1, member, recipient, amount, nonce }
}

struct RewardWorld {
    segment: RewardSegmentCircuit,
    merge: RewardMergeCircuit,
    root: RewardRootCircuit,
    batch: RewardClaimBatchCircuit,
    checkpoints: Leaves,
    anchor_id: u32,
    source_id: u32,
    source_leaf: PsyCheckpointLeaf<F>,
    anchor_hash: HashOut<F>,
    anchor_siblings: [HashOut<F>; CHECKPOINT_HEIGHT],
    levels: Vec<Vec<HashOut<F>>>,
    owners: BTreeMap<u32, (CircuitHash<F>, HashOut<F>)>,
}

fn owner_tag(user_id: u32) -> (CircuitHash<F>, HashOut<F>) {
    let preimage = CircuitHash::from_values(u64::from(user_id), 1, 0, 0);
    (preimage, PoseidonHash::two_to_one(preimage.0, preimage.0))
}

fn reward_world() -> RewardWorld {
    let segment = RewardSegmentCircuit::new();
    let merge = RewardMergeCircuit::new(&segment);
    let root = RewardRootCircuit::new(&merge);
    let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
    let anchor_id = 12u32;
    let source_id = 10u32;
    let users = [7u32, 11];
    let owners = users.into_iter().map(|user| (user, owner_tag(user))).collect::<BTreeMap<_, _>>();
    let mut levels = vec![(0..64).map(|index| {
        let owner = owners[&users[index % users.len()]].1;
        tagged(CircuitHash::from_values(index as u64, 0, 0, 0).0, HashOut::ZERO, owner)
    }).collect::<Vec<_>>()];
    for level in 0..REWARD_JOB_HEIGHT {
        levels.push(levels[level].chunks_exact(2).map(|pair| tagged(pair[0], pair[1], HashOut::ZERO)).collect());
    }
    let mut source_leaf = PsyCheckpointLeaf::default();
    source_leaf.stats.pm_rewards_commitment.gutas_root = ClientHash(levels[REWARD_JOB_HEIGHT][0]);
    source_leaf.stats.pm_jobs_completed.gutas_completed = F::from_canonical_u32(64);
    source_leaf.stats.guta_fees_collected = F::from_canonical_u32(640);
    let mut user_leaves = Leaves::new();
    for user_id in users {
        let private_key = ClientHash::from_values(u64::from(user_id), 23, 31, 47);
        let param = get_sdc_public_key_param(&private_key);
        let identity = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
        let user_leaf = PsyUserLeaf {
            user_id: F::from_canonical_u32(user_id),
            public_key: ClientHash(PoseidonHash::two_to_one(identity, param.0)),
            ..PsyUserLeaf::default()
        };
        user_leaves.insert(u64::from(user_id), user_leaf.alghash::<PoseidonHash>().0);
    }
    let user_root = sparse_path::<USER_HEIGHT>(&user_leaves, 0, HashOut::ZERO).1;
    let mut global_roots = PsyCheckpointGlobalStateRoots::default();
    global_roots.user_tree_root = ClientHash(user_root);
    let mut anchor_leaf = PsyCheckpointLeaf::default();
    anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
    let anchor_hash = anchor_leaf.qfhash::<PoseidonHash>().0;
    let mut checkpoints = Leaves::from([(u64::from(source_id), source_leaf.qfhash::<PoseidonHash>().0)]);
    checkpoints.insert(u64::from(anchor_id), anchor_hash);
    let anchor_siblings = sparse_path::<CHECKPOINT_HEIGHT>(&checkpoints, u64::from(anchor_id), HashOut::ZERO).0;
    RewardWorld {
        segment, merge, root, batch, checkpoints, anchor_id, source_id, source_leaf,
        anchor_hash, anchor_siblings, levels, owners,
    }
}

static REWARD: LazyLock<RewardWorld> = LazyLock::new(reward_world);

fn reward_job(user_id: u32, path_index: u32) -> AuthenticatedJobWitness {
    let (preimage, owner) = REWARD.owners[&user_id];
    let index = path_index as usize;
    assert_eq!(tagged(CircuitHash::from_values(u64::from(path_index), 0, 0, 0).0, HashOut::ZERO, owner), REWARD.levels[0][index]);
    assert_eq!(REWARD.levels[REWARD_JOB_HEIGHT][0], REWARD.source_leaf.stats.pm_rewards_commitment.gutas_root.0);
    AuthenticatedJobWitness {
        source_checkpoint_id: REWARD.source_id,
        height: REWARD_JOB_HEIGHT as u8,
        path_index,
        tag: RewardTagWitness {
            tag_preimage: preimage,
            leaf_left: CircuitHash::from_values(u64::from(path_index), 0, 0, 0),
            leaf_right: CircuitHash::ZERO,
            leaf_tag: CircuitHash(owner),
            siblings: std::array::from_fn(|level| if level < REWARD_JOB_HEIGHT { CircuitHash(REWARD.levels[level][index >> level ^ 1]) } else { CircuitHash::ZERO }),
            parent_tags: [CircuitHash::ZERO; 21],
        },
    }
}

struct RewardTip {
    proof: ProofWithPublicInputs<F, C, D>,
    user_id: u32,
}

fn reward_tip(user_id: u32, recipient_low: u32, path_index: u32) -> RewardTip {
    let job = reward_job(user_id, path_index);
    let coordinate = ((1u64 << REWARD_JOB_HEIGHT) - 1) + u64::from(path_index);
    let inner = Leaves::new();
    let (inner_siblings, old_inner_root) = sparse_path::<REWARD_NULLIFIER_INNER_HEIGHT>(&inner, coordinate, REWARD_NULLIFIER_EMPTY_LEAF);
    let occupied = inner.into_iter().chain([(coordinate, REWARD_NULLIFIER_OCCUPIED_LEAF)]).collect();
    let new_inner_root = sparse_path::<REWARD_NULLIFIER_INNER_HEIGHT>(&occupied, coordinate, REWARD_NULLIFIER_EMPTY_LEAF).1;
    let outer = Leaves::new();
    let (outer_siblings, old_nullifier_root) = sparse_path::<REWARD_NULLIFIER_OUTER_HEIGHT>(&outer, u64::from(REWARD.source_id), *INNER_EMPTY_ROOT);
    let private_key = ClientHash::from_values(u64::from(user_id), 23, 31, 47);
    let param = get_sdc_public_key_param(&private_key);
    let identity = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
    let user_leaf = PsyUserLeaf {
        user_id: F::from_canonical_u32(user_id),
        public_key: ClientHash(PoseidonHash::two_to_one(identity, param.0)),
        ..PsyUserLeaf::default()
    };
    let users = [7u32, 11].into_iter().map(|user| {
        let key = ClientHash::from_values(u64::from(user), 23, 31, 47);
        let user_param = get_sdc_public_key_param(&key);
        let leaf = PsyUserLeaf {
            user_id: F::from_canonical_u32(user),
            public_key: ClientHash(PoseidonHash::two_to_one(identity, user_param.0)),
            ..PsyUserLeaf::default()
        };
        (u64::from(user), leaf.alghash::<PoseidonHash>().0)
    }).collect();
    let (user_siblings, user_root) = sparse_path::<USER_HEIGHT>(&users, u64::from(user_id), HashOut::ZERO);
    let mut global_roots = PsyCheckpointGlobalStateRoots::default();
    global_roots.user_tree_root = ClientHash(user_root);
    let mut anchor_leaf = PsyCheckpointLeaf::default();
    anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
    assert_eq!(anchor_leaf.qfhash::<PoseidonHash>().0, REWARD.anchor_hash);
    let checkpoint_siblings = sparse_path::<CHECKPOINT_HEIGHT>(&REWARD.checkpoints, u64::from(REWARD.source_id), HashOut::ZERO).0;
    let checkpoint_tree_root = sparse_path::<CHECKPOINT_HEIGHT>(&REWARD.checkpoints, u64::from(REWARD.anchor_id), HashOut::ZERO).1;
    let segment_proof = REWARD.segment.prove(&RewardSegmentWitness {
        user_id,
        anchor_checkpoint_id: REWARD.anchor_id,
        checkpoint_tree_root,
        old_nullifier_root,
        source: RewardSegmentSourceWitness {
            source_checkpoint_id: REWARD.source_id,
            checkpoint_leaf: REWARD.source_leaf.clone(),
            checkpoint_siblings,
            amount_limbs: [10, 0],
            jobs: vec![job],
            nullifier: RewardNullifierSourceWitness { old_inner_root, outer_siblings, inner_siblings: vec![inner_siblings] },
        },
    }).expect("authenticated reward segment");
    assert_eq!(segment_proof.public_inputs.len(), REWARD_SEGMENT_STATEMENT_LEN);
    let mut occupied_outer = outer;
    occupied_outer.insert(u64::from(REWARD.source_id), new_inner_root);
    let new_nullifier_root = sparse_path::<REWARD_NULLIFIER_OUTER_HEIGHT>(&occupied_outer, u64::from(REWARD.source_id), *INNER_EMPTY_ROOT).1;
    assert_eq!(&segment_proof.public_inputs[5..9], &old_nullifier_root.elements);
    assert_eq!(&segment_proof.public_inputs[9..13], &new_nullifier_root.elements);
    let merge_proof = REWARD.merge.prove(&RewardMergeWitness::Leaf { segment: segment_proof }).expect("authenticated reward merge leaf");
    let proof = REWARD.root.prove(&RewardRootWitness {
        recipient: [recipient_low, 0x0506_0708, 0x090a_0b0c, 0x0d0e_0f10, 0x1112_1314, 0, 0, 0],
        anchor_checkpoint_id: REWARD.anchor_id,
        anchor_leaf,
        anchor_siblings: REWARD.anchor_siblings,
        global_roots,
        user_leaf,
        user_siblings,
        private_key: private_key.0,
        merge_proof,
    }).expect("authenticated reward root");
    assert_eq!(&proof.public_inputs[26..30], &checkpoint_tree_root.elements);
    RewardTip { proof, user_id }
}

fn statement_of(proof: &ProofWithPublicInputs<F, C, D>) -> [F; REWARD_ROOT_STATEMENT_LEN] {
    proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().expect("root statement width")
}

fn batch_leaf(root_proof: ProofWithPublicInputs<F, C, D>) -> ProofWithPublicInputs<F, C, D> {
    let statement = statement_of(&root_proof);
    REWARD.batch.prove(&RewardClaimBatchWitness {
        mode: RewardClaimBatchMode::Leaf,
        statements: vec![statement],
        tip: Some(root_proof),
        children: None,
    }).expect("authenticated reward batch leaf")
}

fn reward_claim(index: u32, anchor_siblings: [HashOut<F>; CHECKPOINT_HEIGHT]) -> BridgeRewardClaimWitness {
    BridgeRewardClaimWitness {
        statement_index: index,
        anchor_checkpoint_id: REWARD.anchor_id,
        anchor_leaf: REWARD.anchor_hash,
        anchor_siblings,
    }
}

fn shared_end(end_id: u32) -> (HashOut<F>, HashOut<F>, [HashOut<F>; CHECKPOINT_HEIGHT]) {
    let mut checkpoints = REWARD.checkpoints.clone();
    if end_id != REWARD.anchor_id {
        let mut later = PsyCheckpointLeaf::default();
        later.global_chain_root = ClientHash(HashOut::from_partial(&[F::from_canonical_u32(end_id)]));
        checkpoints.insert(u64::from(end_id), later.qfhash::<PoseidonHash>().0);
    }
    let (anchor_siblings, tree_root) = sparse_path::<CHECKPOINT_HEIGHT>(&checkpoints, u64::from(REWARD.anchor_id), HashOut::ZERO);
    let proof = MerkleProofCore {
        root: HashOut::ZERO,
        value: REWARD.anchor_hash,
        index: u64::from(REWARD.anchor_id),
        siblings: anchor_siblings.to_vec(),
    };
    let (anchor_root, end_root) = compute_historical_and_current_merkle_roots_core_gt::<HashOut<F>, PoseidonHash>(&proof);
    let tip = MerkleProofCore {
        root: HashOut::ZERO,
        value: REWARD.anchor_hash,
        index: u64::from(REWARD.anchor_id),
        siblings: REWARD.anchor_siblings.to_vec(),
    };
    assert_eq!(anchor_root, compute_historical_and_current_merkle_roots_core_gt::<HashOut<F>, PoseidonHash>(&tip).0);
    assert_eq!(end_root, tree_root);
    (anchor_root, end_root, anchor_siblings)
}


#[test]
fn withdrawal_statement_projects_ten_words_and_capacity_boundary() {
    let token = policy(1, 7, 40, 8, 2);
    let claim = one_member(&token, 11, 1);
    let tree = withdrawal_tree(&token, &[(claim.member_index, claim.member)]);
    let endpoint = HashOut::from_partial(&[F::from_canonical_u64(12)]);
    let circuit = BridgeWithdrawalClaimCircuit::new(vec![token.clone()]).unwrap();
    assert_eq!(circuit.circuit_data.common.num_public_inputs, BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN);
    assert_eq!(BRIDGE_CLAIM_CAPACITY, 32);
    assert_eq!(BRIDGE_WITHDRAWAL_CLAIM_WORDS, 10);
    let input = withdrawal_input(std::slice::from_ref(&token), std::slice::from_ref(&tree), std::slice::from_ref(&claim), 12, endpoint);
    let output = circuit.prove(&input).unwrap();
    circuit.circuit_data.verify(output.clone()).unwrap();
    assert_eq!(output.public_inputs[0], F::ONE);
    assert_eq!(output.public_inputs[1], F::from_canonical_u32(12));
    assert_eq!(&output.public_inputs[2..6], &endpoint.elements);
    assert_eq!(&output.public_inputs[6..10], &input.end_gusr.elements);
    assert_eq!(&output.public_inputs[10..14], &input.end_gcon.elements);
    let fields = [
        (0, KIND_WITHDRAWAL),
        (1, u32::from(token.chain_index)),
        (2, claim.sender),
        (3, token.token_contract_id),
    ];
    for (opening_word, value) in fields {
        for index in 0..7 {
            assert_eq!(limb(&output.public_inputs, 0, opening_word, index), F::ZERO);
        }
        assert_eq!(limb(&output.public_inputs, 0, opening_word, 7), F::from_canonical_u32(value));
    }
    for (opening_word, value) in [(4, claim.nonce), (8, claim.recipient), (9, claim.amount)] {
        for index in 0..8 {
            assert_eq!(limb(&output.public_inputs, 0, opening_word, index), F::from_canonical_u32(value[index]));
        }
    }
    for opening_word in [5, 6, 7] {
        for index in 0..8 {
            assert_eq!(limb(&output.public_inputs, 0, opening_word, index), F::ZERO, "reserved word {opening_word}");
        }
    }
    for slot in 1..BRIDGE_CLAIM_CAPACITY {
        for opening_word in 0..BRIDGE_WITHDRAWAL_CLAIM_WORDS {
            for index in 0..8 {
                assert_eq!(limb(&output.public_inputs, slot, opening_word, index), F::ZERO);
            }
        }
    }

    let mut overflow = input.clone();
    overflow.claims = vec![overflow.claims[0].clone(); BRIDGE_CLAIM_CAPACITY + 1];
    assert!(circuit.prove(&overflow).is_err(), "capacity 33 must be rejected before proving");
}

#[test]
fn withdrawal_rejects_zero_amount_map_overflow_and_foreign_burn() {
    let token = policy(1, 7, 40, 8, 2);
    let claim = one_member(&token, 11, 1);
    let tree = withdrawal_tree(&token, &[(claim.member_index, claim.member)]);
    let circuit = BridgeWithdrawalClaimCircuit::new(vec![token.clone()]).unwrap();
    let input = withdrawal_input(std::slice::from_ref(&token), std::slice::from_ref(&tree), std::slice::from_ref(&claim), 12, HashOut::ZERO);
    circuit.prove(&input).unwrap();

    let mut zero_amount = claim;
    zero_amount.amount = [0; 8];
    let (key, value) = burn(zero_amount.sender, &token, zero_amount.recipient, zero_amount.amount, zero_amount.nonce);
    zero_amount.member.key = key;
    zero_amount.member.value = value;
    let zero_tree = withdrawal_tree(&token, &[(zero_amount.member_index, zero_amount.member)]);
    let zero_input = withdrawal_input(std::slice::from_ref(&token), std::slice::from_ref(&zero_tree), std::slice::from_ref(&zero_amount), 12, HashOut::ZERO);
    assert!(circuit.prove(&zero_input).is_err(), "zero amount");

    let mut high_amount = one_member(&token, 11, 1);
    high_amount.amount[5] = 1;
    let (key, value) = burn(high_amount.sender, &token, high_amount.recipient, high_amount.amount, high_amount.nonce);
    high_amount.member.key = key;
    high_amount.member.value = value;
    let high_tree = withdrawal_tree(&token, &[(high_amount.member_index, high_amount.member)]);
    let high_input = withdrawal_input(std::slice::from_ref(&token), std::slice::from_ref(&high_tree), std::slice::from_ref(&high_amount), 12, HashOut::ZERO);
    assert!(circuit.prove(&high_input).is_err(), "amount above two low limbs");

    let mut beyond_map = one_member(&token, 11, 1);
    beyond_map.member_index = token.map_base + token.capacity + 1;
    let mut beyond_tree = withdrawal_tree(&token, &[(beyond_map.member_index, beyond_map.member)]);
    beyond_tree.sentinel.value = ClientHash::from_values(u64::from(token.capacity + 1), 0, 0, 0);
    let mut state = beyond_tree.state.clone();
    state.insert(u64::from(token.map_base), beyond_tree.sentinel.qfhash::<PoseidonHash>().0);
    let (siblings, root) = sparse_path::<STATE_HEIGHT>(&state, u64::from(token.map_base), HashOut::ZERO);
    let (member_siblings, member_root) = sparse_path::<STATE_HEIGHT>(&state, u64::from(beyond_map.member_index), HashOut::ZERO);
    assert_eq!(member_root, root);
    beyond_tree.sentinel_siblings = siblings;
    beyond_tree.state_root = root;
    let contracts = Leaves::from([(u64::from(token.token_contract_id), root)]);
    let (contract_siblings, contract_root) = sparse_path::<CONTRACT_HEIGHT>(&contracts, u64::from(token.token_contract_id), HashOut::ZERO);
    beyond_tree.contract_siblings = contract_siblings;
    beyond_tree.contract_root = contract_root;
    beyond_tree.state = state;
    let beyond_input = withdrawal_input(std::slice::from_ref(&token), std::slice::from_ref(&beyond_tree), std::slice::from_ref(&beyond_map), 12, HashOut::ZERO);
    assert!(circuit.prove(&beyond_input).is_err(), "member past map base plus capacity");

    let mut foreign_burn = one_member(&token, 11, 1);
    foreign_burn.member.key.0.elements[0] += F::ONE;
    let foreign_tree = withdrawal_tree(&token, &[(foreign_burn.member_index, foreign_burn.member)]);
    let foreign_input = withdrawal_input(std::slice::from_ref(&token), std::slice::from_ref(&foreign_tree), std::slice::from_ref(&foreign_burn), 12, HashOut::ZERO);
    assert!(circuit.prove(&foreign_input).is_err(), "leaf key is not the namespace-6 burn");

    let other = policy(2, 9, 80, 20, 2);
    let other_claim = one_member(&other, 15, 3);
    let other_tree = withdrawal_tree(&other, &[(other_claim.member_index, other_claim.member)]);
    let mut swapped = input;
    swapped.claims[0].contract_siblings = other_tree.contract_siblings;
    swapped.claims[0].user_contract.start_contract_state_root = ClientHash(other_tree.state_root);
    swapped.claims[0].user_contract.user_leaf.user_state_tree_root = ClientHash(other_tree.contract_root);
    let users = Leaves::from([(11, swapped.claims[0].user_contract.user_leaf.alghash::<PoseidonHash>().0)]);
    let (siblings, root) = sparse_path::<USER_HEIGHT>(&users, 11, HashOut::ZERO);
    swapped.claims[0].user_siblings = siblings;
    swapped.end_gusr = root;
    assert!(circuit.prove(&swapped).is_err(), "another token tree cannot authenticate this burn");
}

#[test]
fn withdrawal_two_policies_select_distinct_payments_and_reject_each_swap() {
    let first = policy(1, 7, 40, 8, 2);
    let second = policy(2, 9, 80, 20, 2);
    let mut low = one_member(&first, 4, 1);
    low.policy_ordinal = 0;
    let mut high = one_member(&second, 9, 2);
    high.policy_ordinal = 1;
    high.member_index = second.map_base + 1;
    let first_tree = withdrawal_tree(&first, &[(low.member_index, low.member)]);
    let second_tree = withdrawal_tree(&second, &[(high.member_index, high.member)]);
    let policies = vec![first.clone(), second.clone()];
    let circuit = BridgeWithdrawalClaimCircuit::new(policies.clone()).unwrap();
    let input = withdrawal_input(&policies, &[first_tree, second_tree], &[low, high], 30, HashOut::from_partial(&[F::from_canonical_u64(30)]));
    let output = circuit.prove(&input).unwrap();
    circuit.circuit_data.verify(output.clone()).unwrap();
    assert_eq!(output.public_inputs[0], F::from_canonical_u64(2));
    assert_eq!(limb(&output.public_inputs, 0, 1, 7), F::from_canonical_u32(1));
    assert_eq!(limb(&output.public_inputs, 1, 1, 7), F::from_canonical_u32(2));
    assert_eq!(limb(&output.public_inputs, 0, 3, 7), F::from_canonical_u32(first.token_contract_id));
    assert_eq!(limb(&output.public_inputs, 1, 3, 7), F::from_canonical_u32(second.token_contract_id));
    assert_eq!(limb(&output.public_inputs, 0, 9, 7), F::ONE);
    assert_eq!(limb(&output.public_inputs, 1, 9, 7), F::ONE);

    let mut crossed = input.clone();
    crossed.claims.swap(0, 1);
    assert!(circuit.prove(&crossed).is_err(), "policy order is not the opening sort");
    let mut wrong_ordinal = input;
    wrong_ordinal.claims[0].policy_ordinal = 1;
    assert!(circuit.prove(&wrong_ordinal).is_err(), "ordinal selects a different installed token");
}

#[test]
fn reward_pair_projects_fifteen_words_and_rejects_replay_and_stale_anchor() {
    let low = reward_tip(7, 0x0102_0304, 0);
    let high_user = reward_tip(11, 0x2122_2324, 1);
    let low_statement = statement_of(&low.proof);
    let high_statement = statement_of(&high_user.proof);
    assert!(low_statement[0].to_canonical_u64() < high_statement[0].to_canonical_u64());
    let left = batch_leaf(low.proof);
    let right = batch_leaf(high_user.proof);
    let parent = REWARD.batch.prove(&RewardClaimBatchWitness {
        mode: RewardClaimBatchMode::Pair,
        statements: vec![low_statement, high_statement],
        tip: None,
        children: Some([left, right]),
    }).expect("authenticated pair batch");
    assert_eq!(parent.public_inputs.len() >= REWARD_CLAIM_BATCH_STATEMENT_LEN, true);
    let (anchor_root, end_root, anchor_siblings) = shared_end(40);
    let claim = BridgeRewardClaimCircuit::new(REWARD.batch.get_common_circuit_data_ref(), REWARD.batch.get_verifier_config_ref(), 5);
    assert_eq!(claim.circuit_data.common.num_public_inputs, BRIDGE_REWARD_CLAIM_STATEMENT_LEN);
    assert_eq!(BRIDGE_REWARD_CLAIM_WORDS, 15);
    let input = BridgeRewardClaimInput {
        end_checkpoint_id: 40,
        end_checkpoint_root: end_root,
        claims: vec![
            reward_claim(0, anchor_siblings),
            reward_claim(1, anchor_siblings),
        ],
        batch_proof: parent,
    };
    let output = claim.prove(&input).unwrap();
    claim.circuit_data.verify(output.clone()).unwrap();
    assert_eq!(output.public_inputs[0], F::from_canonical_u64(2));
    assert_eq!(output.public_inputs[1], F::from_canonical_u32(40));
    assert_eq!(&output.public_inputs[2..6], &end_root.elements);
    assert_ne!(end_root, anchor_root, "an older anchor must not be substituted for the end root");
    for slot in 0..2 {
        let statement = if slot == 0 { low_statement } else { high_statement };
        for index in 0..7 {
            assert_eq!(reward_limb(&output.public_inputs, slot, 0, index), F::ZERO);
            assert_eq!(reward_limb(&output.public_inputs, slot, 1, index), F::ZERO);
            assert_eq!(reward_limb(&output.public_inputs, slot, 3, index), F::ZERO);
        }
        assert_eq!(reward_limb(&output.public_inputs, slot, 0, 7), F::from_canonical_u32(KIND_REWARD));
        assert_eq!(reward_limb(&output.public_inputs, slot, 1, 7), F::from_canonical_u32(5));
        assert_eq!(reward_limb(&output.public_inputs, slot, 2, 7), statement[0]);
        assert_eq!(reward_limb(&output.public_inputs, slot, 3, 7), F::from_canonical_u64(BRIDGE_REWARD_CONTRACT_ID));
        for word in 0..4 {
            let value = statement[9 + word].to_canonical_u64();
            assert_eq!(reward_limb(&output.public_inputs, slot, 4 + word, 6), F::from_canonical_u32((value >> 32) as u32));
            assert_eq!(reward_limb(&output.public_inputs, slot, 4 + word, 7), F::from_canonical_u32(value as u32));
            let next = statement[13 + word].to_canonical_u64();
            assert_eq!(reward_limb(&output.public_inputs, slot, 8 + word, 6), F::from_canonical_u32((next >> 32) as u32));
            assert_eq!(reward_limb(&output.public_inputs, slot, 8 + word, 7), F::from_canonical_u32(next as u32));
        }
        assert_eq!(reward_limb(&output.public_inputs, slot, 12, 7), statement[17]);
        for index in 0..8 {
            assert_eq!(reward_limb(&output.public_inputs, slot, 13, index), statement[1 + (7 - index)]);
            assert_eq!(reward_limb(&output.public_inputs, slot, 14, index), statement[18 + (7 - index)]);
        }
    }

    let mut replay = input.clone();
    replay.claims[1].statement_index = 0;
    assert!(claim.prove(&replay).is_err(), "one batch statement cannot pay twice");
    let mut stale = input.clone();
    stale.end_checkpoint_id = REWARD.anchor_id - 1;
    assert!(claim.prove(&stale).is_err(), "anchor newer than the end checkpoint");
    let mut reordered = input;
    reordered.claims.swap(0, 1);
    claim.prove(&reordered).expect("reversed reward user order is accepted");
}

#[test]
fn empty_batches_preserve_distinct_endpoints_and_reject_a_dangling_claim() {
    let token = policy(1, 7, 40, 8, 2);
    let withdrawal = BridgeWithdrawalClaimCircuit::new(vec![token]).unwrap();
    let endpoint = HashOut::from_partial(&[F::from_canonical_u64(77)]);
    let empty = BridgeWithdrawalClaimInput {
        end_checkpoint_id: u32::MAX,
        end_checkpoint_root: endpoint,
        end_gusr: HashOut::from_partial(&[F::from_canonical_u64(3)]),
        end_gcon: HashOut::from_partial(&[F::from_canonical_u64(4)]),
        claims: Vec::new(),
    };
    let output = withdrawal.prove(&empty).unwrap();
    assert_eq!(output.public_inputs[0], F::ZERO);
    assert_eq!(output.public_inputs[1], F::from_canonical_u64(u64::from(u32::MAX)));
    assert_eq!(&output.public_inputs[2..6], &endpoint.elements);
    assert_eq!(&output.public_inputs[6..10], &empty.end_gusr.elements);
    assert_eq!(&output.public_inputs[10..14], &empty.end_gcon.elements);

    let empty_batch = REWARD.batch.prove(&RewardClaimBatchWitness {
        mode: RewardClaimBatchMode::Empty,
        statements: Vec::new(),
        tip: None,
        children: None,
    }).unwrap();
    let reward = BridgeRewardClaimCircuit::new(REWARD.batch.get_common_circuit_data_ref(), REWARD.batch.get_verifier_config_ref(), 5);
    let reward_input = BridgeRewardClaimInput {
        end_checkpoint_id: 40,
        end_checkpoint_root: endpoint,
        claims: Vec::new(),
        batch_proof: empty_batch,
    };
    let reward_output = reward.prove(&reward_input).unwrap();
    assert_eq!(reward_output.public_inputs[0], F::ZERO);
    assert_eq!(&reward_output.public_inputs[2..6], &endpoint.elements);
    let mut dangling = reward_input;
    dangling.claims.push(reward_claim(0, REWARD.anchor_siblings));
    assert!(reward.prove(&dangling).is_err(), "empty batch cannot carry a claim");
}
