use hashbrown::HashMap;

use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    gates::noop::NoopGate,
    iop::target::{BoolTarget, Target},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, PoseidonGoldilocksConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data,
        dummy_circuit::{cyclic_base_proof, dummy_proof},
    },
};
use psy_common_circuit::{
    builder::comparison::CircuitBuilderComparison,
    u32::arithmetic_u32::{CircuitBuilderU32, U32Target},
};
use psy_plonky2_basic_helpers::builder::pad_circuit::CircuitBuilderQEDCommonGates;

use super::reward_chain::REWARD_ROOT_STATEMENT_LEN;
use crate::{
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub const REWARD_CLAIM_BATCH_CAPACITY: usize = 32;

pub const REWARD_CLAIM_BATCH_STATEMENT_LEN: usize =
    1 + REWARD_CLAIM_BATCH_CAPACITY * REWARD_ROOT_STATEMENT_LEN;

pub const REWARD_CLAIM_BATCH_DEGREE_BITS: usize = 16;

pub type RewardClaimBatchProof = ProofWithPublicInputs<F, C, D>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewardClaimBatchMode {
    Empty,
    Leaf,
    Pair,
}

#[derive(Clone, Debug)]
pub struct RewardClaimBatchWitness {
    pub mode: RewardClaimBatchMode,
    pub statements: Vec<[F; REWARD_ROOT_STATEMENT_LEN]>,
    pub tip: Option<ProofWithPublicInputs<F, C, D>>,
    pub children: Option<[RewardClaimBatchProof; 2]>,
}

pub struct RewardClaimBatchTargets {
    pub count: Target,
    pub statements: [[Target; REWARD_ROOT_STATEMENT_LEN]; REWARD_CLAIM_BATCH_CAPACITY],
    pub is_empty: BoolTarget,
    pub is_leaf: BoolTarget,
    pub is_pair: BoolTarget,
    pub root_proof: ProofWithPublicInputsTarget<D>,
    pub child_proofs: [ProofWithPublicInputsTarget<D>; 2],
    pub inactive_root_proof: ProofWithPublicInputsTarget<D>,
    pub pinned_root: VerifierCircuitTarget,
    pub pinned_batch: VerifierCircuitTarget,
}

pub struct RewardClaimBatchCircuit {
    pub targets: RewardClaimBatchTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
    root_verifier: VerifierOnlyCircuitData<C, D>,
    dummy_root_proof: ProofWithPublicInputs<F, C, D>,
}

fn batch_seed(builder: &mut CircuitBuilder<F, D>, root_common: &CommonCircuitData<F, D>) {
    builder.add_qed_type_d_common_gates();
    let zero = builder.zero();
    let _ = builder.is_less_than_or_equal(6, zero, zero);
    let left = U32Target(builder.add_virtual_target());
    let right = U32Target(builder.add_virtual_target());
    builder.connect(left.0, zero);
    builder.connect(right.0, zero);
    let (sum, carry) = builder.add_u32(left, right);
    builder.assert_zero_u32(carry);
    builder.connect(sum.0, left.0);
    let _ = builder.add_virtual_proof_with_pis(root_common);
}

fn batch_common_data(root_common: &CommonCircuitData<F, D>) -> CommonCircuitData<F, D> {
    let config = CircuitConfig::standard_recursion_config();
    let mut stage = CircuitBuilder::<F, D>::new(config.clone());
    batch_seed(&mut stage, root_common);
    let data = stage.build::<C>();

    let mut stage = CircuitBuilder::<F, D>::new(config.clone());
    batch_seed(&mut stage, root_common);
    let proof = stage.add_virtual_proof_with_pis(&data.common);
    let verifier = stage.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    stage.verify_proof::<C>(&proof, &verifier, &data.common);
    let data = stage.build::<C>();

    let mut stage = CircuitBuilder::<F, D>::new(config);
    batch_seed(&mut stage, root_common);
    let proof = stage.add_virtual_proof_with_pis(&data.common);
    let verifier = stage.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    stage.verify_proof::<C>(&proof, &verifier, &data.common);
    while stage.num_gates() < 1 << REWARD_CLAIM_BATCH_DEGREE_BITS {
        stage.add_gate(NoopGate, vec![]);
    }
    let common = stage.build::<C>().common;
    let verifier_len = 4 + 4 * common.config.fri_config.num_cap_elements();
    let mut child_common = common.clone();
    child_common.num_public_inputs = REWARD_CLAIM_BATCH_STATEMENT_LEN + verifier_len;
    child_common
}

fn selected_field(
    builder: &mut CircuitBuilder<F, D>,
    index: Target,
    proof: &ProofWithPublicInputsTarget<D>,
    field: usize,
) -> Target {
    let zero = builder.zero();
    (0..REWARD_CLAIM_BATCH_CAPACITY).fold(zero, |selected, slot| {
        let position = builder.constant(F::from_canonical_usize(slot));
        let value = proof.public_inputs[1 + slot * REWARD_ROOT_STATEMENT_LEN + field];
        let matches = builder.is_equal(index, position);
        builder.select(matches, value, selected)
    })
}

fn build_batch(
    root_common: &CommonCircuitData<F, D>,
    root_verifier: &VerifierOnlyCircuitData<C, D>,
) -> RewardClaimBatchCircuit {
    let child_common = batch_common_data(root_common);
    let root_dummy_data = plonky2::recursion::dummy_circuit::dummy_circuit::<F, C, D>(root_common);
    let dummy_root_proof = dummy_proof::<F, C, D>(&root_dummy_data, HashMap::new()).expect("reward claim batch root dummy");
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    batch_seed(&mut builder, root_common);
    let zero = builder.zero();
    let one = builder.one();
    let is_empty = builder.add_virtual_bool_target_safe();
    let is_leaf = builder.add_virtual_bool_target_safe();
    let is_pair = builder.add_virtual_bool_target_safe();
    let mode_sum = builder.add_many([is_empty.target, is_leaf.target, is_pair.target]);
    builder.connect(mode_sum, one);

    let count = builder.add_virtual_target();
    builder.range_check(count, 6);
    let capacity = builder.constant(F::from_canonical_usize(REWARD_CLAIM_BATCH_CAPACITY));
    let within_capacity = builder.is_less_than_or_equal(6, count, capacity);
    builder.connect(within_capacity.target, one);
    let count_is_zero = builder.is_equal(count, zero);
    builder.connect(is_empty.target, count_is_zero.target);
    let count_is_one = builder.is_equal(count, one);
    builder.connect(is_leaf.target, count_is_one.target);
    let statements: [[Target; REWARD_ROOT_STATEMENT_LEN]; REWARD_CLAIM_BATCH_CAPACITY] =
        std::array::from_fn(|_| std::array::from_fn(|_| builder.add_virtual_target()));

    let root_proof = builder.add_virtual_proof_with_pis(root_common);
    let pinned_root = builder.constant_verifier_data(root_verifier);
    let (inactive_root_proof, inactive_root_verifier) = builder
        .dummy_proof_and_constant_vk_no_generator::<C>(root_common)
        .expect("reward claim batch inactive root proof");
    builder.conditionally_verify_proof::<C>(
        is_leaf, &root_proof, &pinned_root, &inactive_root_proof, &inactive_root_verifier,
        root_common,
    );

    let child_proofs = [
        builder.add_virtual_proof_with_pis(&child_common),
        builder.add_virtual_proof_with_pis(&child_common),
    ];
    let mut public_inputs = vec![count];
    for statement in &statements {
        public_inputs.extend(statement);
    }
    assert_eq!(public_inputs.len(), REWARD_CLAIM_BATCH_STATEMENT_LEN);
    builder.register_public_inputs(&public_inputs);
    let pinned_batch = builder.add_verifier_data_public_inputs();
    for child in &child_proofs {
        builder.conditionally_verify_cyclic_proof_or_dummy::<C>(is_pair, child, &child_common)
            .expect("reward claim batch cyclic verifier");
    }

    let tip = &root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN];
    let left_count = builder.select(is_pair, child_proofs[0].public_inputs[0], zero);
    let right_count = builder.select(is_pair, child_proofs[1].public_inputs[0], zero);
    let (sum, carry) = builder.add_u32(U32Target(left_count), U32Target(right_count));
    let gated_carry = builder.select(is_pair, carry.0, zero);
    builder.connect(gated_carry, zero);
    let gated_count = builder.select(is_pair, count, sum.0);
    builder.connect(gated_count, sum.0);
    let left_positive = builder.is_not_equal(left_count, zero);
    let right_positive = builder.is_not_equal(right_count, zero);
    let both_positive = builder.and(left_positive, right_positive);
    let gated_children = builder.select(is_pair, both_positive.target, one);
    builder.connect(gated_children, one);

    for slot in 0..REWARD_CLAIM_BATCH_CAPACITY {
        let position = builder.constant(F::from_canonical_usize(slot));
        let in_left = builder.is_less_than(6, position, left_count);
        let left_offset = builder.select(in_left, zero, left_count);
        let after_left = builder.sub(position, left_offset);
        let after_left_open = builder.not(in_left);
        let within_right = builder.is_less_than(6, after_left, right_count);
        let in_right = builder.and(after_left_open, within_right);
        for field in 0..REWARD_ROOT_STATEMENT_LEN {
            let left_value = selected_field(&mut builder, position, &child_proofs[0], field);
            let left_field = builder.select(in_left, left_value, zero);
            let right_value = selected_field(&mut builder, after_left, &child_proofs[1], field);
            let right_field = builder.select(in_right, right_value, zero);
            let joined = builder.add(left_field, right_field);
            let paired = builder.select(is_pair, joined, zero);
            let from_tip = if slot == 0 { builder.select(is_leaf, tip[field], zero) } else { zero };
            let bound = builder.add(paired, from_tip);
            builder.connect(statements[slot][field], bound);
        }
    }

    while builder.num_gates() < 1 << REWARD_CLAIM_BATCH_DEGREE_BITS {
        builder.add_gate(NoopGate, vec![]);
    }
    let (circuit_data, matches) = builder.try_build_with_options::<C>(true);
    assert!(matches, "reward claim batch common data mismatch");
    RewardClaimBatchCircuit {
        targets: RewardClaimBatchTargets {
            count, statements, is_empty, is_leaf, is_pair, root_proof, child_proofs,
            inactive_root_proof, pinned_root, pinned_batch,
        },
        fingerprint: QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only)),
        circuit_data,
        root_verifier: root_verifier.clone(),
        dummy_root_proof,
    }
}

fn zero_statement() -> [F; REWARD_ROOT_STATEMENT_LEN] { [F::ZERO; REWARD_ROOT_STATEMENT_LEN] }

fn mode_flags(mode: RewardClaimBatchMode) -> (bool, bool, bool) {
    match mode {
        RewardClaimBatchMode::Empty => (true, false, false),
        RewardClaimBatchMode::Leaf => (false, true, false),
        RewardClaimBatchMode::Pair => (false, false, true),
    }
}

fn child_count(proof: &RewardClaimBatchProof) -> anyhow::Result<usize> {
    anyhow::ensure!(proof.public_inputs.len() >= REWARD_CLAIM_BATCH_STATEMENT_LEN, "batch child statement is shorter than the fixed width");
    let count = proof.public_inputs[0].to_canonical_u64() as usize;
    anyhow::ensure!(count <= REWARD_CLAIM_BATCH_CAPACITY, "batch child count exceeds 32");
    Ok(count)
}

fn child_statements(proof: &RewardClaimBatchProof) -> anyhow::Result<[[F; REWARD_ROOT_STATEMENT_LEN]; REWARD_CLAIM_BATCH_CAPACITY]> {
    let _ = child_count(proof)?;
    Ok(std::array::from_fn(|slot| {
        let start = 1 + slot * REWARD_ROOT_STATEMENT_LEN;
        proof.public_inputs[start..start + REWARD_ROOT_STATEMENT_LEN].try_into().expect("statement width")
    }))
}

fn validate_witness(input: &RewardClaimBatchWitness) -> anyhow::Result<()> {
    let count = input.statements.len();
    anyhow::ensure!(count <= REWARD_CLAIM_BATCH_CAPACITY, "reward claim batch exceeds 32");
    let (empty, leaf, pair) = mode_flags(input.mode);
    anyhow::ensure!(empty == (count == 0) && leaf == (count == 1) && pair == (count >= 2), "batch mode does not match its statement count");
    anyhow::ensure!(input.tip.is_some() == leaf && input.children.is_some() == pair, "batch mode does not match its proofs");
    if empty {
        anyhow::ensure!(input.statements.is_empty(), "empty mode requires the all-zero statement");
    }
    if let Some(tip) = &input.tip {
        anyhow::ensure!(tip.public_inputs.len() >= REWARD_ROOT_STATEMENT_LEN && tip.public_inputs[..REWARD_ROOT_STATEMENT_LEN] == input.statements[0], "leaf slot0 does not bind the root statement");
    }
    if let Some(children) = &input.children {
        let (left_count, right_count) = (child_count(&children[0])?, child_count(&children[1])?);
        anyhow::ensure!(left_count > 0 && right_count > 0 && left_count + right_count == count, "pair children are not positive prefixes of the parent");
        let (left, right) = (child_statements(&children[0])?, child_statements(&children[1])?);
        anyhow::ensure!(input.statements[..left_count] == left[..left_count] && input.statements[left_count..] == right[..right_count], "pair slots are not the concatenated child prefixes");
    }
    Ok(())
}

impl RewardClaimBatchCircuit {
    pub fn new(root_common: &CommonCircuitData<F, D>, root_verifier: &VerifierOnlyCircuitData<C, D>) -> Self {
        build_batch(root_common, root_verifier)
    }

    fn set_witness(&self, input: &RewardClaimBatchWitness) -> anyhow::Result<PartialWitness<F>> {
        self.set_witness_with_verifier(input, &self.circuit_data.verifier_only)
    }

    pub(crate) fn set_witness_with_verifier(&self, input: &RewardClaimBatchWitness, verifier: &VerifierOnlyCircuitData<C, D>) -> anyhow::Result<PartialWitness<F>> {
        validate_witness(input)?;
        let (empty, leaf, pair) = mode_flags(input.mode);
        let mut witness = PartialWitness::new();
        witness.set_bool_target(self.targets.is_empty, empty)?;
        witness.set_bool_target(self.targets.is_leaf, leaf)?;
        witness.set_bool_target(self.targets.is_pair, pair)?;
        witness.set_target(self.targets.count, F::from_canonical_usize(input.statements.len()))?;
        witness.set_verifier_data_target(&self.targets.pinned_batch, verifier)?;
        for slot in 0..REWARD_CLAIM_BATCH_CAPACITY {
            let statement = input.statements.get(slot).copied().unwrap_or_else(zero_statement);
            for field in 0..REWARD_ROOT_STATEMENT_LEN {
                witness.set_target(self.targets.statements[slot][field], statement[field])?;
            }
        }
        witness.set_proof_with_pis_target(&self.targets.root_proof, input.tip.as_ref().unwrap_or(&self.dummy_root_proof))?;
        witness.set_proof_with_pis_target(&self.targets.inactive_root_proof, &self.dummy_root_proof)?;
        let identity = cyclic_base_proof(&self.circuit_data.common, verifier, HashMap::new());
        let left = input.children.as_ref().map(|children| &children[0]).unwrap_or(&identity);
        let right = input.children.as_ref().map(|children| &children[1]).unwrap_or(&identity);
        witness.set_proof_with_pis_target(&self.targets.child_proofs[0], left)?;
        witness.set_proof_with_pis_target(&self.targets.child_proofs[1], right)?;

        Ok(witness)
    }

    pub fn prove(&self, input: &RewardClaimBatchWitness) -> anyhow::Result<RewardClaimBatchProof> {
        let proof = self.circuit_data.prove(self.set_witness(input)?)?;
        check_cyclic_proof_verifier_data(&proof, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
        Ok(proof)
    }
}

impl QStandardCircuit<C, D> for RewardClaimBatchCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::circuits::reward_chain::{RewardMergeCircuit, RewardMergeWitness, RewardRootCircuit, RewardSegmentCircuit};
    use super::super::reward_chain::tests::{reward_root, Fixture};

    struct Claim {
        user: u64,
        statement: [F; REWARD_ROOT_STATEMENT_LEN],
        proof: ProofWithPublicInputs<F, C, D>,
    }

    fn claim(segment: &RewardSegmentCircuit, merge: &RewardMergeCircuit, root: &RewardRootCircuit, user: u64, source: u32, recipient: u64) -> Claim {
        // Keep the user-authenticating anchor distinct from the reward source inserted below.
        let anchor = source.max(11) + 1;
        let mut fixture = Fixture::for_user(user as u32, anchor);
        if source != 10 {
            let source_leaf = fixture.checkpoints.get(&10).copied().unwrap();
            fixture.checkpoints.insert(u64::from(source), source_leaf);
        }
        let node = fixture.node(source, 0..1);
        let segment_proof = segment.prove(&node).unwrap();
        let merge_proof = merge.prove(&RewardMergeWitness::Leaf { segment: segment_proof }).unwrap();
        let proved = reward_root(root, &fixture, recipient, merge_proof);
        root.circuit_data.verify(proved.clone()).unwrap();
        let statement = proved.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap();
        Claim { user, statement, proof: proved }
    }

    fn claims() -> (RewardSegmentCircuit, RewardMergeCircuit, RewardRootCircuit, [Claim; 32]) {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let root = RewardRootCircuit::new(&merge);
        let built = std::array::from_fn(|ordinal| {
            let user = if ordinal < 31 { 1 } else { 2 };
            let source = if ordinal == 0 { 10u32 } else { 1024 + ordinal as u32 };
            let recipient = if ordinal == 1 { 9 } else { 1 };
            claim(&segment, &merge, &root, user, source, recipient)
        });
        (segment, merge, root, built)
    }

    fn user_first_claims(segment: &RewardSegmentCircuit, merge: &RewardMergeCircuit, root: &RewardRootCircuit) -> [Claim; 2] {
        [
            claim(segment, merge, root, 1, 2048, 1),
            claim(segment, merge, root, 2, 10, 1),
        ]
    }

    fn input(mode: RewardClaimBatchMode, statements: Vec<[F; REWARD_ROOT_STATEMENT_LEN]>, tip: Option<ProofWithPublicInputs<F, C, D>>, children: Option<[RewardClaimBatchProof; 2]>) -> RewardClaimBatchWitness {
        RewardClaimBatchWitness { mode, statements, tip, children }
    }

    fn overlay(base: &mut PartialWitness<F>, values: PartialWitness<F>) {
        for (target, value) in values.target_values { base.target_values.insert(target, value); }
    }

    fn fold(batch: &RewardClaimBatchCircuit, statements: &[[F; REWARD_ROOT_STATEMENT_LEN]], leaves: &[RewardClaimBatchProof]) -> RewardClaimBatchProof {
        assert_eq!(statements.len(), leaves.len());
        let mut folded = leaves[0].clone();
        for index in 1..statements.len() {
            folded = batch.prove(&input(RewardClaimBatchMode::Pair, statements[..=index].to_vec(), None, Some([folded, leaves[index].clone()]))).unwrap();
        }
        folded
    }

    #[test]
    fn mode_statement_and_sum_constraints_reject_their_named_violations() {
        let (_segment, _merge, root, claims) = claims();
        let batch = RewardClaimBatchCircuit::new(&root.circuit_data.common, &root.circuit_data.verifier_only);
        assert!(batch.prove(&input(RewardClaimBatchMode::Empty, Vec::new(), None, None)).is_ok());
        let mut empty_active = batch.set_witness(&input(RewardClaimBatchMode::Empty, Vec::new(), None, None)).unwrap();
        empty_active.target_values.insert(batch.targets.statements[0][0], F::ONE);
        assert!(batch.circuit_data.prove(empty_active).is_err(), "empty mode accepted an active statement");

        let first = &claims[0];
        assert!(batch.prove(&input(RewardClaimBatchMode::Leaf, vec![first.statement], Some(first.proof.clone()), None)).is_ok());
        let mut wrong_count = batch.set_witness(&input(RewardClaimBatchMode::Leaf, vec![first.statement], Some(first.proof.clone()), None)).unwrap();
        wrong_count.target_values.insert(batch.targets.count, F::from_canonical_usize(2));
        assert!(batch.circuit_data.prove(wrong_count).is_err(), "leaf count other than one was accepted");
        let mut suffixed = batch.set_witness(&input(RewardClaimBatchMode::Leaf, vec![first.statement], Some(first.proof.clone()), None)).unwrap();
        suffixed.target_values.insert(batch.targets.statements[1][0], F::TWO);
        assert!(batch.circuit_data.prove(suffixed).is_err(), "nonzero suffix was accepted");

        let left = batch.prove(&input(RewardClaimBatchMode::Leaf, vec![first.statement], Some(first.proof.clone()), None)).unwrap();
        let second = &claims[1];
        assert_eq!(second.user, first.user);
        let right = batch.prove(&input(RewardClaimBatchMode::Leaf, vec![second.statement], Some(second.proof.clone()), None)).unwrap();
        let mut count_mismatch = batch.set_witness(&input(RewardClaimBatchMode::Pair, vec![first.statement, second.statement], None, Some([left.clone(), right.clone()]))).unwrap();
        count_mismatch.target_values.insert(batch.targets.count, F::from_canonical_usize(3));
        assert!(batch.circuit_data.prove(count_mismatch).is_err(), "pair count mismatch was accepted");
        let mut omitted = batch.set_witness(&input(RewardClaimBatchMode::Pair, vec![first.statement, second.statement], None, Some([left.clone(), right.clone()]))).unwrap();
        omitted.target_values.insert(batch.targets.statements[1][0], F::ZERO);
        assert!(batch.circuit_data.prove(omitted).is_err(), "omitted active statement was accepted");
        let pair_two = batch.prove(&input(RewardClaimBatchMode::Pair, vec![first.statement, second.statement], None, Some([left.clone(), right.clone()]))).unwrap();
        let empty = batch.prove(&input(RewardClaimBatchMode::Empty, Vec::new(), None, None)).unwrap();
        assert_eq!(&child_statements(&pair_two).unwrap()[..2], &[first.statement, second.statement]);
        let mut right_empty = batch.set_witness(&input(RewardClaimBatchMode::Pair, vec![first.statement, second.statement], None, Some([left.clone(), right.clone()]))).unwrap();
        let mut right_swap = PartialWitness::new();
        right_swap.set_proof_with_pis_target(&batch.targets.child_proofs[0], &pair_two).unwrap();
        right_swap.set_proof_with_pis_target(&batch.targets.child_proofs[1], &empty).unwrap();
        overlay(&mut right_empty, right_swap);
        assert!(batch.circuit_data.prove(right_empty).is_err(), "positive pair accepted an empty right child");
        let mut left_empty = batch.set_witness(&input(RewardClaimBatchMode::Pair, vec![first.statement, second.statement], None, Some([left.clone(), right.clone()]))).unwrap();
        let mut left_swap = PartialWitness::new();
        left_swap.set_proof_with_pis_target(&batch.targets.child_proofs[0], &empty).unwrap();
        left_swap.set_proof_with_pis_target(&batch.targets.child_proofs[1], &pair_two).unwrap();
        overlay(&mut left_empty, left_swap);
        assert!(batch.circuit_data.prove(left_empty).is_err(), "positive pair accepted an empty left child");
        assert!(batch.prove(&input(RewardClaimBatchMode::Pair, vec![first.statement, second.statement], None, Some([left, right]))).is_ok());
    }

    #[test]
    fn pair_sum_over_capacity_is_rejected() {
        let (_segment, _merge, root, claims) = claims();
        let batch = RewardClaimBatchCircuit::new(&root.circuit_data.common, &root.circuit_data.verifier_only);
        let leaves: Vec<_> = claims.iter().map(|claim| batch.prove(&input(RewardClaimBatchMode::Leaf, vec![claim.statement], Some(claim.proof.clone()), None)).unwrap()).collect();
        let statement_list = |slice: &[Claim]| -> Vec<[F; REWARD_ROOT_STATEMENT_LEN]> { slice.iter().map(|claim| claim.statement).collect() };
        let left = fold(&batch, &statement_list(&claims[..20]), &leaves[..20]);
        let right_base = fold(&batch, &statement_list(&claims[20..]), &leaves[20..]);
        let mut over_statements = statement_list(&claims[20..]);
        over_statements.push(claims[0].statement);
        let mut over_leaves = leaves[20..].to_vec();
        over_leaves.push(leaves[0].clone());
        let right_large = fold(&batch, &over_statements, &over_leaves);
        assert_eq!(child_count(&left).unwrap(), 20);
        assert_eq!(child_count(&right_base).unwrap(), 12);
        assert_eq!(child_count(&right_large).unwrap(), 13);
        assert_eq!(&child_statements(&right_large).unwrap()[..12], &statement_list(&claims[20..])[..]);
        let mut witness = batch.set_witness(&input(
            RewardClaimBatchMode::Pair, statement_list(&claims), None, Some([left, right_base]),
        )).unwrap();
        let mut oversized = PartialWitness::new();
        oversized.set_target(batch.targets.count, F::from_canonical_usize(33)).unwrap();
        oversized.set_proof_with_pis_target(&batch.targets.child_proofs[1], &right_large).unwrap();
        overlay(&mut witness, oversized);
        assert!(batch.circuit_data.prove(witness).is_err(), "pair count sum over 32 was accepted");
    }

    #[test]
    fn reversed_user_order_is_accepted_without_in_circuit_ordering() {
        let segment = RewardSegmentCircuit::new();
        let merge = RewardMergeCircuit::new(&segment);
        let root = RewardRootCircuit::new(&merge);
        let batch = RewardClaimBatchCircuit::new(&root.circuit_data.common, &root.circuit_data.verifier_only);
        let [low, high] = user_first_claims(&segment, &merge, &root);
        assert!(low.user < high.user);
        let low_leaf = batch.prove(&input(RewardClaimBatchMode::Leaf, vec![low.statement], Some(low.proof.clone()), None)).unwrap();
        let high_leaf = batch.prove(&input(RewardClaimBatchMode::Leaf, vec![high.statement], Some(high.proof.clone()), None)).unwrap();
        let ascending = batch.prove(&input(
            RewardClaimBatchMode::Pair, vec![low.statement, high.statement], None, Some([low_leaf.clone(), high_leaf.clone()]),
        )).unwrap();
        assert_eq!(child_count(&ascending).unwrap(), 2);
        batch.circuit_data.verify(ascending).unwrap();
        let reversed = batch.prove(&input(
            RewardClaimBatchMode::Pair, vec![high.statement, low.statement], None, Some([high_leaf, low_leaf]),
        )).unwrap();
        assert_eq!(child_count(&reversed).unwrap(), 2);
        for (slot, statement) in [&high.statement, &low.statement].iter().enumerate() {
            assert_eq!(
                &reversed.public_inputs[1 + slot * REWARD_ROOT_STATEMENT_LEN..1 + (slot + 1) * REWARD_ROOT_STATEMENT_LEN],
                &statement[..],
                "reversed parent slot {slot} does not match its child statement",
            );
        }
        batch.circuit_data.verify(reversed).unwrap();
    }

    #[test]
    fn pair_counts_cover_1_through_32_with_irregular_splits() {
        let (_segment, _merge, root, claims) = claims();
        let batch = RewardClaimBatchCircuit::new(&root.circuit_data.common, &root.circuit_data.verifier_only);
        let leaves: Vec<_> = claims.iter().map(|claim| batch.prove(&input(RewardClaimBatchMode::Leaf, vec![claim.statement], Some(claim.proof.clone()), None)).unwrap()).collect();
        for count in 1..=32 {
            if count == 1 {
                assert_eq!(child_count(&leaves[0]).unwrap(), 1);
                continue;
            }
            let left_count = (count / 3).max(1);
            let mut left = leaves[0].clone();
            for index in 1..left_count {
                let statements = claims[..=index].iter().map(|claim| claim.statement).collect();
                left = batch.prove(&input(RewardClaimBatchMode::Pair, statements, None, Some([left, leaves[index].clone()]))).unwrap();
            }
            let mut right = leaves[left_count].clone();
            for index in left_count + 1..count {
                let statements = claims[left_count..=index].iter().map(|claim| claim.statement).collect();
                right = batch.prove(&input(RewardClaimBatchMode::Pair, statements, None, Some([right, leaves[index].clone()]))).unwrap();
            }
            let statements = claims[..count].iter().map(|claim| claim.statement).collect();
            let parent = batch.prove(&input(RewardClaimBatchMode::Pair, statements, None, Some([left, right]))).unwrap();
            assert_eq!(child_count(&parent).unwrap(), count);
            if count != 2 { assert_ne!(left_count, count - left_count); }
        }
    }

    #[test]
    fn selectors_reject_unpinned_verifier_and_dummy_business_proof() {
        let (_segment, _merge, root, claims) = claims();
        let batch = RewardClaimBatchCircuit::new(&root.circuit_data.common, &root.circuit_data.verifier_only);
        let mut witness = batch.set_witness(&input(RewardClaimBatchMode::Empty, Vec::new(), None, None)).unwrap();
        let mut verifier = PartialWitness::new();
        verifier.set_verifier_data_target(&batch.targets.pinned_batch, &batch.root_verifier).unwrap();
        overlay(&mut witness, verifier);
        assert!(batch.circuit_data.prove(witness).is_err(), "unpinned verifier was accepted");
        assert!(batch.prove(&input(RewardClaimBatchMode::Leaf, vec![claims[0].statement], Some(batch.dummy_root_proof.clone()), None)).is_err(), "dummy proof was accepted as a business proof");
    }
}
