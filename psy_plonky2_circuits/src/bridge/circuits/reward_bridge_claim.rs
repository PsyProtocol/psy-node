use parth_core::crypto::hash::traits::MerkleZeroHasher;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{Hasher, PoseidonGoldilocksConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_common_circuit::{
    builder::comparison::CircuitBuilderComparison,
    u32::arithmetic_u32::{CircuitBuilderU32, U32Target},
};
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_plonky2_basic_helpers::builder::pad_circuit::CircuitBuilderQEDCommonGates;

use super::reward_chain::REWARD_ROOT_STATEMENT_LEN;
use super::reward_claim_batch::REWARD_CLAIM_BATCH_STATEMENT_LEN;
use crate::{
    bridge::gadgets::anchor_to_end::AnchorToEndTarget,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub const BRIDGE_CLAIM_CAPACITY: usize = 32;
pub const BRIDGE_REWARD_CLAIM_WORDS: usize = 15;
pub const BRIDGE_REWARD_CLAIM_STATEMENT_LEN: usize =
    6 + BRIDGE_CLAIM_CAPACITY * BRIDGE_REWARD_CLAIM_WORDS * 8;
pub const BRIDGE_REWARD_CONTRACT_ID: u64 = 7;
pub const BRIDGE_CLAIM_DEGREE_BITS: usize = 16;

const KIND_REWARD: u32 = 2;

#[derive(Clone, Debug)]
pub struct BridgeRewardClaimWitness {
    pub statement_index: u32,
    pub anchor_checkpoint_id: u32,
    pub anchor_leaf: HashOut<F>,
    pub anchor_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize],
}

#[derive(Clone, Debug)]
pub struct BridgeRewardClaimInput {
    pub end_checkpoint_id: u32,
    pub end_checkpoint_root: HashOut<F>,
    pub claims: Vec<BridgeRewardClaimWitness>,
    pub batch_proof: ProofWithPublicInputs<F, C, D>,
}

pub struct BridgeRewardClaimTargets {
    pub count: Target,
    pub end_checkpoint_id: Target,
    pub end_checkpoint_root: HashOutTarget,
    pub claims: [[[U32Target; 8]; BRIDGE_REWARD_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY],
    pub indices: [Target; BRIDGE_CLAIM_CAPACITY],
    pub anchors: [AnchorToEndTarget; BRIDGE_CLAIM_CAPACITY],
    pub batch_proof: ProofWithPublicInputsTarget<D>,
}

pub struct BridgeRewardClaimCircuit {
    pub targets: BridgeRewardClaimTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: parth_core::pgoldilocks::QHashOut<F>,
}

fn words(builder: &mut CircuitBuilder<F, D>) -> [U32Target; 8] {
    std::array::from_fn(|_| builder.add_virtual_u32_target())
}

fn word_targets(word: [U32Target; 8]) -> [Target; 8] {
    word.map(|limb| limb.0)
}

fn bounded(builder: &mut CircuitBuilder<F, D>, value: Target, bits: usize) -> [U32Target; 8] {
    builder.range_check(value, bits);
    let mut word = [builder.zero_u32(); 8];
    word[7] = U32Target(value);
    word
}

fn canonical_root_word(builder: &mut CircuitBuilder<F, D>, limb: Target) -> [U32Target; 8] {
    let (low, high) = builder.split_low_high(limb, 32, 64);
    let maximum = builder.constant(F::from_canonical_u32(u32::MAX));
    let high_maximum = builder.is_equal(high, maximum);
    let noncanonical = builder.mul(high_maximum.target, low);
    builder.assert_zero(noncanonical);
    let mut word = [builder.zero_u32(); 8];
    word[6] = U32Target(high);
    word[7] = U32Target(low);
    word
}

fn select_word(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    value: [U32Target; 8],
) -> [U32Target; 8] {
    let zero = builder.zero_u32();
    std::array::from_fn(|index| builder.select_u32(active, value[index], zero))
}

fn active_flag(builder: &mut CircuitBuilder<F, D>, index: Target, count: Target) -> BoolTarget {
    builder.is_less_than(6, index, count)
}

fn connect_if(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    left: Target,
    right: Target,
) {
    let selected = builder.select(active, right, left);
    builder.connect(left, selected);
}

fn connect_hash_if(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    left: HashOutTarget,
    right: HashOutTarget,
) {
    for index in 0..4 {
        connect_if(builder, active, left.elements[index], right.elements[index]);
    }
}

fn reward_word(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    statement: &[Target],
    offset: usize,
    little_endian: bool,
) -> [U32Target; 8] {
    let mut word = [builder.zero_u32(); 8];
    let zero = builder.zero();
    for index in 0..8 {
        let source = if little_endian { 7 - index } else { index };
        word[index] = U32Target(builder.select(active, statement[offset + source], zero));
        builder.range_check(word[index].0, 32);
    }
    word
}

fn build_reward(
    batch_common: &CommonCircuitData<F, D>,
    batch_verifier: &VerifierOnlyCircuitData<C, D>,
    ethereum_index: u8,
) -> BridgeRewardClaimCircuit {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    builder.add_qed_type_d_common_gates();
    let zero = builder.zero();
    let one = builder.one();
    let proof = builder.add_virtual_proof_with_pis(batch_common);
    let verifier = builder.constant_verifier_data(batch_verifier);
    builder.verify_proof::<C>(&proof, &verifier, batch_common);
    let suffix = proof.public_inputs.len() - REWARD_CLAIM_BATCH_STATEMENT_LEN;
    assert_eq!(suffix, 4 + 4 * verifier.constants_sigmas_cap.0.len());
    for index in 0..4 {
        builder.connect(
            proof.public_inputs[REWARD_CLAIM_BATCH_STATEMENT_LEN + index],
            verifier.circuit_digest.elements[index],
        );
    }
    for (index, cap) in verifier.constants_sigmas_cap.0.iter().enumerate() {
        for limb in 0..4 {
            builder.connect(
                proof.public_inputs[REWARD_CLAIM_BATCH_STATEMENT_LEN + 4 + 4 * index + limb],
                cap.elements[limb],
            );
        }
    }
    let batch_count = proof.public_inputs[0];
    builder.range_check(batch_count, 6);
    let maximum_count = builder.constant(F::from_canonical_usize(BRIDGE_CLAIM_CAPACITY));
    builder.ensure_is_less_than_or_equal(6, batch_count, maximum_count);
    let end_checkpoint_id = builder.add_virtual_target();
    builder.range_check(end_checkpoint_id, 32);
    let mut claims = [[[builder.zero_u32(); 8]; BRIDGE_REWARD_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY];
    let mut indices = Vec::new();
    let mut anchors = Vec::new();
    let end_checkpoint_root = builder.add_virtual_hash();
    for slot in 0..BRIDGE_CLAIM_CAPACITY {
        let slot_target = builder.constant(F::from_canonical_usize(slot));
        let active = active_flag(&mut builder, slot_target, batch_count);
        let index = builder.add_virtual_target();
        builder.range_check(index, 6);
        let inactive = builder.not(active);
        connect_if(&mut builder, inactive, index, zero);
        let index_bound = builder.select(active, batch_count, one);
        builder.ensure_is_less_than(6, index, index_bound);
        for earlier in &indices {
            let same = builder.is_equal(index, *earlier);
            let duplicate = builder.and(active, same);
            builder.connect(duplicate.target, zero);
        }
        let mut selected = vec![builder.zero(); REWARD_ROOT_STATEMENT_LEN];
        for statement_slot in 0..BRIDGE_CLAIM_CAPACITY {
            let start = 1 + statement_slot * REWARD_ROOT_STATEMENT_LEN;
            let statement_slot = builder.constant(F::from_canonical_usize(statement_slot));
            let matches = builder.is_equal(index, statement_slot);
            for field in 0..REWARD_ROOT_STATEMENT_LEN {
                selected[field] = builder.select(matches, proof.public_inputs[start + field], selected[field]);
            }
        }
        let anchor = AnchorToEndTarget::add_virtual(&mut builder);
        let internal_end = builder.select(active, end_checkpoint_id, zero);
        builder.connect(anchor.end_checkpoint_id, internal_end);
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let internal_leaf = HashOutTarget { elements: std::array::from_fn(|limb| builder.select(active, anchor.historical.current_value.elements[limb], zero_hash.elements[limb])) };
        builder.connect_hashes(anchor.historical.current_value, internal_leaf);
        for (level, sibling) in anchor.historical.siblings.iter().enumerate() {
            let empty = builder.constant_hash(<PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(level));
            let selected = HashOutTarget { elements: std::array::from_fn(|limb| builder.select(active, sibling.elements[limb], empty.elements[limb])) };
            builder.connect_hashes(*sibling, selected);
        }
        let anchor_root = HashOutTarget { elements: std::array::from_fn(|limb| selected[26 + limb]) };
        connect_hash_if(&mut builder, active, anchor.anchor_root, anchor_root);
        connect_hash_if(&mut builder, active, anchor.end_root, end_checkpoint_root);
        let kind = builder.constant(F::from_canonical_u32(KIND_REWARD));
        let chain = builder.constant(F::from_canonical_u32(u32::from(ethereum_index)));
        let contract = builder.constant(F::from_canonical_u64(BRIDGE_REWARD_CONTRACT_ID));
        for (word, value, bits) in [(0, kind, 8), (1, chain, 8), (2, selected[0], 32), (3, contract, 24)] {
            let value = bounded(&mut builder, value, bits);
            claims[slot][word] = select_word(&mut builder, active, value);
        }
        for root in 0..4 {
            let old_root = builder.select(active, selected[9 + root], zero);
            let new_root = builder.select(active, selected[13 + root], zero);
            claims[slot][4 + root] = canonical_root_word(&mut builder, old_root);
            claims[slot][8 + root] = canonical_root_word(&mut builder, new_root);
        }
        let claim_count = bounded(&mut builder, selected[17], 32);
        claims[slot][12] = select_word(&mut builder, active, claim_count);
        claims[slot][13] = reward_word(&mut builder, active, &selected, 1, true);
        claims[slot][14] = reward_word(&mut builder, active, &selected, 18, true);
        indices.push(index);
        anchors.push(anchor);
    }
    let mut statement = vec![batch_count, end_checkpoint_id];
    statement.extend(end_checkpoint_root.elements);
    for claim in &claims {
        for word in claim { statement.extend(word_targets(*word)); }
    }
    assert_eq!(statement.len(), BRIDGE_REWARD_CLAIM_STATEMENT_LEN);
    builder.register_public_inputs(&statement);
    while builder.num_gates() < 1 << BRIDGE_CLAIM_DEGREE_BITS {
        builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
    }
    let circuit_data = builder.build::<C>();
    BridgeRewardClaimCircuit {
        targets: BridgeRewardClaimTargets {
            count: batch_count, end_checkpoint_id, end_checkpoint_root, claims,
            indices: indices.try_into().unwrap(), anchors: anchors.try_into().unwrap(), batch_proof: proof,
        },
        fingerprint: parth_core::pgoldilocks::QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only)),
        circuit_data,
    }
}


impl BridgeRewardClaimCircuit {
    pub fn new(batch_common: &CommonCircuitData<F, D>, batch_verifier: &VerifierOnlyCircuitData<C, D>, ethereum_index: u8) -> Self {
        build_reward(batch_common, batch_verifier, ethereum_index)
    }

    pub fn prove(&self, input: &BridgeRewardClaimInput) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data.prove(self.set_witness(input)?)
    }

    pub fn set_witness(&self, input: &BridgeRewardClaimInput) -> anyhow::Result<PartialWitness<F>> {
        anyhow::ensure!(input.batch_proof.public_inputs.len() >= REWARD_CLAIM_BATCH_STATEMENT_LEN, "batch statement missing");
        let count = input.batch_proof.public_inputs[0].to_canonical_u64() as usize;
        anyhow::ensure!(input.claims.len() == count, "claim count must equal batch count");
        anyhow::ensure!(count <= BRIDGE_CLAIM_CAPACITY, "too many reward claims");
        let mut witness = PartialWitness::new();
        witness.set_target(self.targets.end_checkpoint_id, F::from_canonical_u32(input.end_checkpoint_id))?;
        witness.set_hash_target(self.targets.end_checkpoint_root, input.end_checkpoint_root)?;
        witness.set_proof_with_pis_target(&self.targets.batch_proof, &input.batch_proof)?;
        for slot in 0..BRIDGE_CLAIM_CAPACITY {
            if let Some(claim) = input.claims.get(slot) {
                witness.set_target(self.targets.indices[slot], F::from_canonical_u32(claim.statement_index))?;
                self.targets.anchors[slot].set_witness(&mut witness, F::from_canonical_u32(claim.anchor_checkpoint_id), F::from_canonical_u32(input.end_checkpoint_id), claim.anchor_leaf, &claim.anchor_siblings)?;
            } else {
                witness.set_target(self.targets.indices[slot], F::ZERO)?;
                self.targets.anchors[slot].set_witness_empty_tree(&mut witness)?;
            }
        }
        Ok(witness)
    }
}

impl QStandardCircuit<C, D> for BridgeRewardClaimCircuit {
    fn get_fingerprint(&self) -> parth_core::pgoldilocks::QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    use psy_client_data::qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf};
    use psy_client_data::qdata::user::PsyUserLeaf;
    use psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT;
    use psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit;
    use psy_common_circuit::u32::witness::WitnessU32;
    use crate::bridge::{
        circuits::{reward_chain::*, reward_claim_batch::*},
        gadgets::reward_nullifier::RewardNullifierSourceWitness,
    };

    type Leaves = BTreeMap<u64, HashOut<F>>;
    fn zero_hash(level: usize) -> HashOut<F> { <PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(level) }
    fn sparse_path<const HEIGHT: usize>(leaves: &Leaves, index: u64) -> ([HashOut<F>; HEIGHT], HashOut<F>) {
        let mut layer = leaves.clone();
        let mut siblings = [HashOut::ZERO; HEIGHT];
        let mut cursor = index;
        for level in 0..HEIGHT {
            siblings[level] = layer.get(&(cursor ^ 1)).copied().unwrap_or_else(|| zero_hash(level));
            let mut parents = BTreeMap::new();
            for position in layer.keys().copied().chain([cursor]) {
                let parent = position >> 1;
                let left = parent << 1;
                let left_hash = layer.get(&left).copied().unwrap_or_else(|| zero_hash(level));
                let right_hash = layer.get(&(left + 1)).copied().unwrap_or_else(|| zero_hash(level));
                parents.insert(parent, PoseidonHash::two_to_one(left_hash, right_hash));
            }
            layer = parents;
            cursor >>= 1;
        }
        (siblings, layer.get(&0).copied().unwrap_or_else(|| zero_hash(HEIGHT)))
    }
    fn tagged(left: HashOut<F>, right: HashOut<F>, tag: HashOut<F>) -> HashOut<F> { PoseidonHash::two_to_one(PoseidonHash::two_to_one(left, right), tag) }
    fn reward_tip(user_id: u32) -> (RewardSegmentCircuit, RewardMergeCircuit, RewardRootCircuit, RewardRootProof, HashOut<F>, [HashOut<F>; 32]) {
        use parth_core::pgoldilocks::QHashOut;
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let root = RewardRootCircuit::new(&merge);
        // The imported nonzero-hash guard requires every preimage limb to be nonzero.
        let preimage = QHashOut::from_values(u64::from(user_id), 1, 2, 3);
        let tag = PoseidonHash::two_to_one(preimage.0, preimage.0);
        let mut levels = vec![(0..64).map(|index| tagged(QHashOut::from_values(index, 0, 0, 0).0, HashOut::ZERO, tag)).collect::<Vec<_>>()];
        for level in 0..6 { levels.push(levels[level].chunks_exact(2).map(|pair| tagged(pair[0], pair[1], HashOut::ZERO)).collect()); }
        let mut checkpoint = PsyCheckpointLeaf::default();
        checkpoint.stats.pm_rewards_commitment.gutas_root.0 = levels[6][0];
        checkpoint.stats.pm_jobs_completed.gutas_completed = F::from_canonical_u32(64);
        checkpoint.stats.guta_fees_collected = F::from_canonical_u32(640);
        let hash = checkpoint.qfhash::<PoseidonHash>().0;
        let private_key = psy_client_common::data::qhashout::QHashOut::from_values(17, 23, 31, 47);
        let param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&private_key);
        let identity = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
        let user_leaf = PsyUserLeaf {
            user_id: F::from_canonical_u32(user_id),
            public_key: psy_client_common::data::qhashout::QHashOut(PoseidonHash::two_to_one(identity, param.0)),
            ..PsyUserLeaf::default()
        };
        let users = Leaves::from([(u64::from(user_id), user_leaf.alghash::<PoseidonHash>().0)]);
        let (user_siblings, user_root) = sparse_path::<{ GLOBAL_USER_TREE_HEIGHT as usize }>(&users, u64::from(user_id));
        let global_roots = PsyCheckpointGlobalStateRoots { user_tree_root: psy_client_common::data::qhashout::QHashOut(user_root), ..Default::default() };
        let mut anchor_leaf = PsyCheckpointLeaf::default();
        anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
        let checkpoints = Leaves::from([(1024, hash), (1025, anchor_leaf.qfhash::<PoseidonHash>().0)]);
        let source = 1024u32;
        let old_inner_root = zero_hash(22);
        let outer_siblings = std::array::from_fn(|level| zero_hash(22 + level));
        let old_nullifier_root = zero_hash(54);
        let inner_siblings = vec![sparse_path::<22>(&Leaves::new(), 63).0];
        let (checkpoint_siblings, checkpoint_tree_root) = sparse_path::<32>(&checkpoints, source as u64);
        let segment_proof = segment.prove(&RewardSegmentWitness {
            user_id, anchor_checkpoint_id: 1025, checkpoint_tree_root, old_nullifier_root,
            source: RewardSegmentSourceWitness {
                source_checkpoint_id: source, checkpoint_leaf: checkpoint, checkpoint_siblings,
                amount_limbs: [10, 0], nullifier: RewardNullifierSourceWitness { old_inner_root, outer_siblings, inner_siblings },
                jobs: vec![AuthenticatedJobWitness {
                    source_checkpoint_id: source, height: 6, path_index: 0,
                    tag: RewardTagWitness { tag_preimage: preimage, leaf_left: QHashOut::from_values(0, 0, 0, 0), leaf_right: QHashOut::ZERO, leaf_tag: QHashOut(tag), siblings: std::array::from_fn(|level| if level < 6 { QHashOut(levels[level][1]) } else { QHashOut::ZERO }), parent_tags: [QHashOut::ZERO; 21] },
                }],
            },
        }).unwrap();
        let merge_proof = merge.prove(&RewardMergeWitness::Leaf { segment: segment_proof }).unwrap();
        let (anchor_siblings, _anchor_root) = sparse_path::<32>(&checkpoints, 1025);
        let root_proof = root.prove(&RewardRootWitness {
            recipient: [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0, 0, 0],
            anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings, global_roots,
            user_leaf, user_siblings, private_key: private_key.0, merge_proof,
        }).unwrap();
        (segment, merge, root, root_proof, anchor_leaf.qfhash::<PoseidonHash>().0, anchor_siblings)
    }

    #[test]
    fn reward_uses_real_batch_and_rejects_index_and_anchor_changes() {
        let (_segment, _merge, root, root_proof, anchor_leaf, anchor_siblings) = reward_tip(7);
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let statement: [F; REWARD_ROOT_STATEMENT_LEN] = root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![statement], tip: Some(root_proof), children: None }).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let input = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof, claims: vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings }] };
        claim.prove(&input).unwrap();
        let mut bad = input.clone();
        bad.claims[0].statement_index = 1;
        assert!(claim.prove(&bad).is_err());
        bad = input.clone();
        bad.claims[0].anchor_siblings[0].elements[0] += F::ONE;
        assert!(claim.prove(&bad).is_err());
        bad = input.clone();
        bad.end_checkpoint_root.elements[0] += F::ONE;
        assert!(claim.prove(&bad).is_err(), "active anchor must bind the supplied endpoint root");
    }
    #[test]
    fn reward_claim_binds_statement_words_and_rejects_foreign_batch() {
        let (_segment, _merge, root, root_proof, anchor_leaf, anchor_siblings) = reward_tip(7);
        let recipient = [0x01020304u32, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0, 0, 0];
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let statement: [F; REWARD_ROOT_STATEMENT_LEN] = root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![statement], tip: Some(root_proof), children: None }).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let input = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof: batch_proof.clone(), claims: vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings }] };
        let output = claim.prove(&input).unwrap();
        let word = |word: usize, limb: usize| output.public_inputs[6 + word * 8 + limb];
        for limb in 0..7 { assert_eq!(word(0, limb), F::ZERO, "kind limb {limb}"); }
        assert_eq!(word(0, 7), F::from_canonical_u32(KIND_REWARD));
        for limb in 0..8 { assert_eq!(word(13, limb), F::from_canonical_u32(recipient[7 - limb]), "recipient limb {limb}"); }
        for limb in 0..7 { assert_eq!(word(14, limb), F::ZERO, "amount limb {limb}"); }
        assert_eq!(word(14, 7), F::from_canonical_u32(10));
        for (word_index, field) in (4..8).zip(9..13).chain((8..12).zip(13..17)) {
            let value = statement[field].to_canonical_u64();
            assert_eq!(word(word_index, 6), F::from_canonical_u32((value >> 32) as u32), "root word {word_index} high");
            assert_eq!(word(word_index, 7), F::from_canonical_u32(value as u32), "root word {word_index} low");
        }
        claim.circuit_data.verify(output).unwrap();

        let mut foreign_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let marker = foreign_builder.add_virtual_target();
        let marker_value = foreign_builder.constant(F::from_canonical_u64(0xF001));
        foreign_builder.connect(marker, marker_value);
        let foreign_statement: [Target; REWARD_ROOT_STATEMENT_LEN] = std::array::from_fn(|_| foreign_builder.add_virtual_target());
        foreign_builder.register_public_inputs(&foreign_statement);
        let foreign_root = foreign_builder.build::<C>();
        assert_ne!(get_circuit_fingerprint_generic(&foreign_root.verifier_only), root.get_fingerprint().0, "foreign root verifier must differ");
        let foreign_batch = RewardClaimBatchCircuit::new(&foreign_root.common, &foreign_root.verifier_only);
        assert_ne!(foreign_batch.get_fingerprint(), batch.get_fingerprint(), "foreign batch verifier must differ");
        let foreign_batch_proof = foreign_batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Empty, statements: Vec::new(), tip: None, children: None }).unwrap();
        foreign_batch.circuit_data.verify(foreign_batch_proof.clone()).unwrap();
        let mut foreign = input;
        foreign.claims.clear();
        foreign.batch_proof = foreign_batch_proof;
        assert!(claim.prove(&foreign).is_err(), "a batch proof from another verifier was accepted");
    }
    #[test]
    fn empty_reward_batch_preserves_nonempty_endpoint_and_zeroed_claims() {
        let (_segment, _merge, root, root_proof, _, _) = reward_tip(7);
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        assert_ne!(end_checkpoint_root, zero_hash(CHECKPOINT_TREE_HEIGHT as usize));
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Empty, statements: Vec::new(), tip: None, children: None }).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let input = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof, claims: Vec::new() };
        let output = claim.prove(&input).unwrap();
        assert_eq!(output.public_inputs[0], F::ZERO);
        assert_eq!(&output.public_inputs[2..6], &end_checkpoint_root.elements);
        for slot in 0..BRIDGE_CLAIM_CAPACITY {
            for word in 0..BRIDGE_REWARD_CLAIM_WORDS {
                for limb in 0..8 {
                    let position = 6 + slot * BRIDGE_REWARD_CLAIM_WORDS * 8 + word * 8 + limb;
                    assert_eq!(output.public_inputs[position], F::ZERO, "slot {slot} word {word} limb {limb}");
                }
            }
        }
    }

    #[test]
    fn reward_consumer_rejects_same_family_decoy_suffix() {
        let (_segment, _merge, root, root_proof, anchor_leaf, anchor_siblings) = reward_tip(7);
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let statement: [F; REWARD_ROOT_STATEMENT_LEN] = root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let empty = RewardClaimBatchWitness { mode: RewardClaimBatchMode::Empty, statements: Vec::new(), tip: None, children: None };
        let leaf = RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![statement], tip: Some(root_proof), children: None };
        let genuine_empty = batch.prove(&empty).unwrap();
        let genuine_leaf = batch.prove(&leaf).unwrap();
        batch.circuit_data.verify(genuine_empty.clone()).unwrap();
        batch.circuit_data.verify(genuine_leaf.clone()).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let claim_for = |batch_proof, claims| BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof, claims };
        claim.prove(&claim_for(genuine_empty.clone(), Vec::new())).unwrap();
        claim.prove(&claim_for(genuine_leaf.clone(), vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings }])).unwrap();
        let carried = |input: &RewardClaimBatchWitness, digest: bool, cap: bool| {
            let mut verifier = batch.get_verifier_config_ref().clone();
            if digest { verifier.circuit_digest.elements[0] += F::ONE; }
            if cap { verifier.constants_sigmas_cap.0[0].elements[0] += F::ONE; }
            let witness = batch.set_witness_with_verifier(input, &verifier).unwrap();
            batch.circuit_data.prove(witness).unwrap()
        };
        for (label, input, source) in [("empty", &empty, &genuine_empty), ("leaf", &leaf, &genuine_leaf)] {
            for (name, digest, cap) in [("digest", true, false), ("cap", false, true)] {
                let proof = carried(input, digest, cap);
                assert_eq!(&proof.public_inputs[..REWARD_CLAIM_BATCH_STATEMENT_LEN], &source.public_inputs[..REWARD_CLAIM_BATCH_STATEMENT_LEN], "{label} {name} changed the business statement");
                assert_ne!(&proof.public_inputs[REWARD_CLAIM_BATCH_STATEMENT_LEN..], &source.public_inputs[REWARD_CLAIM_BATCH_STATEMENT_LEN..], "{label} {name} did not change the carried suffix");
                batch.circuit_data.verify(proof.clone()).unwrap();
                assert!(claim.prove(&claim_for(proof, Vec::new())).is_err(), "reward consumer accepted an unbound {label} {name} suffix");
            }
        }
    }
    #[test]
    fn reward_words_follow_installed_ethereum_index_and_unsigned_user() {
        let (_segment, _merge, root, root_proof, anchor_leaf, anchor_siblings) = reward_tip(11);
        let end_checkpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let statement: [F; REWARD_ROOT_STATEMENT_LEN] = root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![statement], tip: Some(root_proof), children: None }).unwrap();
        for ethereum_index in [0u8, 5] {
            let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), ethereum_index);
            let input = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof: batch_proof.clone(), claims: vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings }] };
            let output = claim.prove(&input).unwrap();
            let word = |word: usize, limb: usize| output.public_inputs[6 + word * 8 + limb];
            for limb in 0..7 { assert_eq!(word(1, limb), F::ZERO, "chain limb {limb}"); }
            assert_eq!(word(1, 7), F::from_canonical_u32(u32::from(ethereum_index)));
            for limb in 0..7 { assert_eq!(word(2, limb), F::ZERO, "user limb {limb}"); }
            assert_eq!(word(2, 7), F::from_canonical_u32(11));
            for limb in 0..7 { assert_eq!(word(3, limb), F::ZERO); }
            assert_eq!(word(3, 7), F::from_canonical_u64(BRIDGE_REWARD_CONTRACT_ID));
        }
    }

    #[test]
    fn reward_consumer_rejects_duplicate_index_and_accepts_identical_statements() {
        let (_segment, _merge, root, first_proof, anchor_leaf, anchor_siblings) = reward_tip(7);
        let batch = RewardClaimBatchCircuit::new(root.get_common_circuit_data_ref(), root.get_verifier_config_ref());
        let first: [F; REWARD_ROOT_STATEMENT_LEN] = first_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        let end_checkpoint_root = HashOut { elements: first_proof.public_inputs[26..30].try_into().unwrap() };
        let first_leaf = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![first], tip: Some(first_proof.clone()), children: None }).unwrap();
        let repeated_leaf = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![first], tip: Some(first_proof), children: None }).unwrap();
        let duplicate = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Pair, statements: vec![first, first], tip: None, children: Some([first_leaf, repeated_leaf]) }).unwrap();
        batch.circuit_data.verify(duplicate.clone()).unwrap();
        let claim = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), 0);
        let witness = |statement_index| BridgeRewardClaimWitness { statement_index, anchor_checkpoint_id: 1025, anchor_leaf, anchor_siblings };
        let repeated = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof: duplicate.clone(), claims: vec![witness(0), witness(0)] };
        assert!(claim.prove(&repeated).is_err(), "reward consumer accepted a repeated statement index");
        // The same authenticated statements and endpoint must succeed when only indices differ.
        let accepted = BridgeRewardClaimInput { end_checkpoint_id: 1025, end_checkpoint_root, batch_proof: duplicate, claims: vec![witness(1), witness(0)] };
        let output = claim.prove(&accepted).unwrap();
        assert_eq!(output.public_inputs[0], F::TWO);
        let claim_width = BRIDGE_REWARD_CLAIM_WORDS * 8;
        assert_eq!(&output.public_inputs[6..6 + claim_width], &output.public_inputs[6 + claim_width..6 + 2 * claim_width]);
        claim.circuit_data.verify(output).unwrap();
    }
    #[test]
    fn reward_reversed_user_order_has_no_claim_circuit_constraint() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let count = builder.add_virtual_target();
        let claims: [[[U32Target; 8]; BRIDGE_REWARD_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY] =
            std::array::from_fn(|_| std::array::from_fn(|_| words(&mut builder)));
        let _ = (count, claims);
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        witness.set_target(count, F::from_canonical_u32(2)).unwrap();
        for (slot, claim) in claims.iter().enumerate() {
            for (word, limbs) in claim.iter().enumerate() {
                for (limb, target) in limbs.iter().enumerate() {
                    let value = if slot < 2 && word == 2 && limb == 7 { if slot == 0 { 11 } else { 7 } } else { 0 };
                    witness.set_u32_target(*target, value).unwrap();
                }
            }
        }
        assert!(data.prove(witness).is_ok(), "reversed reward user order is not a claim-circuit constraint");
    }
}
