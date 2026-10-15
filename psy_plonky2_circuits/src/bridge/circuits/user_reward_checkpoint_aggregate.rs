//! Binary checkpoint recursion with complete public IDs and checked payout sums.
//! Layout and the single capacity hypothesis belong to
//! docs/src/dev/checkpoint-claim-cutover.md; construction fails on common-data mismatch.
use hashbrown::HashMap;
use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    gates::noop::NoopGate,
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::{cyclic_base_proof, dummy_circuit, dummy_proof}},
};
use psy_common_circuit::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_basic_helpers::builder::pad_circuit::CircuitBuilderQEDCommonGates;
use crate::{proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::QStandardCircuit};
use super::user_reward_tree::{UserRewardRootCircuit, UserRewardRootProof, USER_REWARD_ROOT_PUBLIC_INPUT_COUNT};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;
/// Single artifact sizing hypothesis; real construction/proving measurement is required.
pub const REWARD_CLAIM_MAX_CHECKPOINTS: usize = 64;
pub const USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT: usize = 15 + REWARD_CLAIM_MAX_CHECKPOINTS;
pub const USER_REWARD_CHECKPOINT_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT: usize = 68;
pub const USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT: usize =
    USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_CHECKPOINT_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT;
// Real Root construction measured 19,822 unpadded gates and degree 15.
// Build adds PI/constant gates after this floor, yielding degree 15; this is
// shared with bootstrap construction, not an upper degree limit.
const CHECKPOINT_AGGREGATE_PADDING_FLOOR: usize = 1 << 14;
pub type UserRewardCheckpointAggregateProof = ProofWithPublicInputs<F, C, D>;

#[derive(Clone, Debug)]
pub enum UserRewardCheckpointAggregateWitness {
    Root { root: UserRewardRootProof },
    Pair { left: UserRewardCheckpointAggregateProof, right: UserRewardCheckpointAggregateProof },
}

pub struct UserRewardCheckpointAggregateTargets {
    pub is_root: BoolTarget,
    pub public_inputs: [Target; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT],
    root: ProofWithPublicInputsTarget<D>,
    inactive_root: ProofWithPublicInputsTarget<D>,
    children: [ProofWithPublicInputsTarget<D>; 2],
    verifier: VerifierCircuitTarget,
}

pub struct UserRewardCheckpointAggregateCircuit {
    pub targets: UserRewardCheckpointAggregateTargets,
    pub circuit_data: CircuitData<F, C, D>,
    pub fingerprint: QHashOut<F>,
    /// Actual builder gate count before padding; populated only by construction.
    pub unpadded_gate_count: usize,
    dummy_root: UserRewardRootProof,
}

fn equal_if(builder: &mut CircuitBuilder<F, D>, active: BoolTarget, a: Target, b: Target) {
    let selected = builder.select(active, a, b);
    builder.connect(selected, b);
}

fn positive_if(builder: &mut CircuitBuilder<F, D>, active: BoolTarget, limbs: &[Target]) {
    // A bounded address or amount has at most five u32 limbs; no field wrap.
    let sum = builder.add_many(limbs.iter().copied());
    let one = builder.one();
    let selected = builder.select(active, sum, one);
    builder.assert_non_zero(selected);
}

fn checked_add<const N: usize>(builder: &mut CircuitBuilder<F, D>, a: &[Target], b: &[Target]) -> [Target; N] {
    let mut carry = builder.zero();
    let result = std::array::from_fn(|i| {
        builder.range_check(a[i], 32);
        builder.range_check(b[i], 32);
        let sum = builder.add_many([a[i], b[i], carry]);
        let bits = builder.split_le(sum, 33);
        carry = bits[32].target;
        builder.le_sum(bits[..32].iter())
    });
    builder.assert_zero(carry);
    result
}

fn constrain_list(builder: &mut CircuitBuilder<F, D>, fields: &[Target], active: BoolTarget) {
    let zero = builder.zero();
    let one = builder.one();
    for (i, &value) in fields.iter().enumerate() {
        if !(6..10).contains(&i) { builder.range_check(value, 32); }
    }
    positive_if(builder, active, &fields[10..11]);
    positive_if(builder, active, &fields[11..15]);
    positive_if(builder, active, &fields[1..6]);
    let limit = builder.constant(F::from_canonical_usize(REWARD_CLAIM_MAX_CHECKPOINTS + 1));
    let bounded = builder.is_less_than(32, fields[10], limit);
    builder.connect(bounded.target, one);
    for i in 0..REWARD_CLAIM_MAX_CHECKPOINTS {
        let index = builder.constant(F::from_canonical_usize(i));
        let present = builder.is_less_than(32, index, fields[10]);
        let absent = builder.not(present);
        equal_if(builder, absent, fields[15 + i], zero);
        if i > 0 {
            let ordered = builder.is_less_than(32, fields[14 + i], fields[15 + i]);
            equal_if(builder, present, ordered.target, one);
        }
    }
}

fn statement(builder: &mut CircuitBuilder<F, D>, is_root: BoolTarget, root: &[Target], left: &[Target], right: &[Target]) -> [Target; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT] {
    let is_pair = builder.not(is_root);
    let zero = builder.zero();
    let one = builder.one();
    // Mask every inactive business PI before any range check or arithmetic.
    let root: [Target; USER_REWARD_ROOT_PUBLIC_INPUT_COUNT] = std::array::from_fn(|i| builder.select(is_root, root[i], zero));
    let left: [Target; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT] = std::array::from_fn(|i| builder.select(is_pair, left[i], zero));
    let right: [Target; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT] = std::array::from_fn(|i| builder.select(is_pair, right[i], zero));
    for &value in &root[..19] { builder.range_check(value, 32); }
    for &value in root[6..9].iter().chain(&root[13..19]) { builder.assert_zero(value); }
    positive_if(builder, is_root, &root[1..6]);
    positive_if(builder, is_root, &root[10..11]);
    positive_if(builder, is_root, &root[11..13]);
    for child in [&left, &right] { constrain_list(builder, child, is_pair); }
    for i in 0..10 { equal_if(builder, is_pair, left[i], right[i]); }
    let count = checked_add::<1>(builder, &left[10..11], &right[10..11])[0];
    let amount = checked_add::<4>(builder, &left[11..15], &right[11..15]);
    // Pair's positive right count and checked parent bound imply left count < K.
    // The Root branch selects zero before the k-bit decomposition.
    let shift = builder.select(is_pair, left[10], zero);
    let shift_bits = builder.split_le(shift, REWARD_CLAIM_MAX_CHECKPOINTS.trailing_zeros() as usize);
    let mut shifted: [Target; REWARD_CLAIM_MAX_CHECKPOINTS] = right[15..].try_into().unwrap();
    for (s, bit) in shift_bits.into_iter().enumerate() {
        let distance = 1 << s;
        shifted = std::array::from_fn(|i| {
            let moved = if i >= distance { shifted[i - distance] } else { zero };
            builder.select(bit, moved, shifted[i])
        });
    }
    let mut fields = [zero; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT];
    for i in 0..6 { fields[i] = builder.select(is_root, root[i], left[i]); }
    for i in 0..4 { fields[6 + i] = builder.select(is_root, root[19 + i], left[6 + i]); }
    fields[10] = builder.select(is_root, one, count);
    for i in 0..4 {
        let root_amount = if i < 2 { root[11 + i] } else { zero };
        fields[11 + i] = builder.select(is_root, root_amount, amount[i]);
    }
    for i in 0..REWARD_CLAIM_MAX_CHECKPOINTS {
        let concatenated = builder.add(left[15 + i], shifted[i]);
        let singleton = if i == 0 { root[9] } else { zero };
        fields[15 + i] = builder.select(is_root, singleton, concatenated);
    }
    let always = builder.constant_bool(true);
    constrain_list(builder, &fields, always);
    fields
}

fn common_data(root: &CircuitData<F, C, D>) -> CommonCircuitData<F, D> {
    // Follow the job aggregate's three verifier bootstrap stages, using the
    // same gate set and padding floor as the final cyclic circuit.
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    builder.add_qed_type_d_common_gates();
    for gate in &root.common.gates { builder.add_gate_to_gate_set(gate.clone()); }
    let mode = builder.add_virtual_bool_target_safe();
    let r = builder.add_virtual_targets(USER_REWARD_ROOT_PUBLIC_INPUT_COUNT);
    let l = builder.add_virtual_targets(USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT);
    let b = builder.add_virtual_targets(USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT);
    statement(&mut builder, mode, &r, &l, &b);
    let statement_gates = builder.build::<C>().common.gates;
    let mut common = root.common.clone();
    for stage in 0..3 {
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        for gate in &statement_gates { builder.add_gate_to_gate_set(gate.clone()); }
        for gate in &common.gates { builder.add_gate_to_gate_set(gate.clone()); }
        let proof = builder.add_virtual_proof_with_pis(&common);
        let verifier = builder.add_virtual_verifier_data(common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof, &verifier, &common);
        if stage == 2 {
            while builder.num_gates() < CHECKPOINT_AGGREGATE_PADDING_FLOOR {
                builder.add_gate(NoopGate, vec![]);
            }
        }
        common = builder.build::<C>().common;
    }
    assert_eq!(common.config.fri_config.cap_height, 4);
    common.num_public_inputs = USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT;
    common
}

impl UserRewardCheckpointAggregateCircuit {
    pub fn new(root: &UserRewardRootCircuit) -> Self { Self::build(&root.circuit_data) }

    fn build(root: &CircuitData<F, C, D>) -> Self {
        assert_eq!(root.common.num_public_inputs, USER_REWARD_ROOT_PUBLIC_INPUT_COUNT);
        assert!(REWARD_CLAIM_MAX_CHECKPOINTS.is_power_of_two());
        assert!((2..=1usize << 31).contains(&REWARD_CLAIM_MAX_CHECKPOINTS));
        let common = common_data(root);
        let dummy = dummy_circuit::<F, C, D>(&root.common);
        let dummy_root = dummy_proof::<F, C, D>(&dummy, HashMap::new()).expect("checkpoint inactive Root proof");
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        for gate in &common.gates { builder.add_gate_to_gate_set(gate.clone()); }
        let is_root = builder.add_virtual_bool_target_safe();
        let is_pair = builder.not(is_root);
        let root_proof = builder.add_virtual_proof_with_pis(&root.common);
        let pinned_root = builder.constant_verifier_data(&root.verifier_only);
        let (inactive_root, inactive_verifier) = builder.dummy_proof_and_constant_vk_no_generator::<C>(&root.common)
            .expect("checkpoint inactive Root verifier");
        builder.conditionally_verify_proof::<C>(is_root, &root_proof, &pinned_root, &inactive_root, &inactive_verifier, &root.common);
        let children: [ProofWithPublicInputsTarget<D>; 2] = std::array::from_fn(|_| builder.add_virtual_proof_with_pis(&common));
        let public_inputs = statement(&mut builder, is_root, &root_proof.public_inputs, &children[0].public_inputs, &children[1].public_inputs);
        builder.register_public_inputs(&public_inputs);
        let verifier = builder.add_verifier_data_public_inputs();
        assert_eq!(verifier.constants_sigmas_cap.0.len(), 16);
        for child in &children {
            builder.conditionally_verify_cyclic_proof_or_dummy::<C>(is_pair, child, &common).expect("checkpoint cyclic verifier");
        }
        let unpadded_gate_count = builder.num_gates();
        eprintln!("checkpoint aggregate: unpadded_gates={unpadded_gate_count}, application_foreign_hashes=0");
        while builder.num_gates() < CHECKPOINT_AGGREGATE_PADDING_FLOOR { builder.add_gate(NoopGate, vec![]); }
        let (circuit_data, matches) = builder.try_build_with_options::<C>(true);
        eprintln!("checkpoint aggregate: degree_bits={}, common_data_matches={matches}", circuit_data.common.degree_bits());
        if !matches {
            // Diagnose fields without changing the expected recursive common data.
            let actual = &circuit_data.common;
            macro_rules! report_difference {
                ($($field:ident),+ $(,)?) => { $(
                    if actual.$field != common.$field {
                        eprintln!("checkpoint aggregate common mismatch: {}", stringify!($field));
                    }
                )+ };
            }
            report_difference!(config, fri_params, gates, selectors_info,
                quotient_degree_factor, num_gate_constraints, num_constants,
                num_public_inputs, k_is, num_partial_products, num_lookup_polys,
                num_lookup_selectors, luts);
            eprintln!("checkpoint aggregate common degrees: expected={}, actual={}",
                common.degree_bits(), actual.degree_bits());
        }
        assert!(matches, "checkpoint aggregate common data mismatch");
        assert_eq!(circuit_data.common, common, "checkpoint aggregate recursive common data mismatch");
        assert_eq!(circuit_data.common.num_public_inputs,
            USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_CHECKPOINT_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT);
        assert_eq!(circuit_data.common.num_public_inputs, USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT);
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self { targets: UserRewardCheckpointAggregateTargets { is_root, public_inputs, root: root_proof, inactive_root, children, verifier },
            circuit_data, fingerprint, unpadded_gate_count, dummy_root }
    }

    fn set_witness(&self, input: &UserRewardCheckpointAggregateWitness) -> anyhow::Result<PartialWitness<F>> {
        let mut witness = PartialWitness::new();
        let base;
        let (is_root, root, left, right) = match input {
            UserRewardCheckpointAggregateWitness::Root { root } => {
                anyhow::ensure!(root.public_inputs.len() == USER_REWARD_ROOT_PUBLIC_INPUT_COUNT, "checkpoint Root statement width mismatch");
                base = cyclic_base_proof(&self.circuit_data.common, &self.circuit_data.verifier_only, HashMap::new());
                (true, root, &base, &base)
            }
            UserRewardCheckpointAggregateWitness::Pair { left, right } => {
                for child in [left, right] {
                    anyhow::ensure!(child.public_inputs.len() == USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT, "checkpoint aggregate statement width mismatch");
                    check_cyclic_proof_verifier_data(child, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
                }
                (false, &self.dummy_root, left, right)
            }
        };
        witness.set_bool_target(self.targets.is_root, is_root)?;
        witness.set_verifier_data_target(&self.targets.verifier, &self.circuit_data.verifier_only)?;
        witness.set_proof_with_pis_target(&self.targets.root, root)?;
        witness.set_proof_with_pis_target(&self.targets.inactive_root, &self.dummy_root)?;
        witness.set_proof_with_pis_target(&self.targets.children[0], left)?;
        witness.set_proof_with_pis_target(&self.targets.children[1], right)?;
        Ok(witness)
    }

    pub fn prove(&self, input: &UserRewardCheckpointAggregateWitness) -> anyhow::Result<UserRewardCheckpointAggregateProof> {
        let proof = self.circuit_data.prove(self.set_witness(input)?)?;
        check_cyclic_proof_verifier_data(&proof, &self.circuit_data.verifier_only, &self.circuit_data.common)?;
        Ok(proof)
    }
}

impl QStandardCircuit<C, D> for UserRewardCheckpointAggregateCircuit {
    fn get_fingerprint(&self) -> QHashOut<F> { self.fingerprint }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> { &self.circuit_data.verifier_only }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<F, D> { &self.circuit_data.common }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::user_reward_tree::{UserRewardAggregateCircuit, UserRewardLeafCircuit};

    type Fields = [F; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT];

    // Statement-only tests isolate the relation, not recursive proof provenance.
    struct Relation {
        circuit: CircuitData<F, C, D>, mode: BoolTarget,
        root: Vec<Target>, left: Vec<Target>, right: Vec<Target>, output: Vec<Target>,
    }

    impl Relation {
        fn new() -> Self {
            let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
            let mode = builder.add_virtual_bool_target_safe();
            let root = builder.add_virtual_targets(USER_REWARD_ROOT_PUBLIC_INPUT_COUNT);
            let left = builder.add_virtual_targets(USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT);
            let right = builder.add_virtual_targets(USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT);
            let fields = statement(&mut builder, mode, &root, &left, &right);
            let output = builder.add_virtual_targets(USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT);
            for (&target, value) in output.iter().zip(fields) { builder.connect(target, value); }
            builder.register_public_inputs(&output);
            Self { circuit: builder.build::<C>(), mode, root, left, right, output }
        }

        fn prove_output(&self, is_root: bool, root: &[F; 23], left: &Fields, right: &Fields, expected: Option<&Fields>) -> anyhow::Result<Fields> {
            let mut witness = PartialWitness::new();
            witness.set_bool_target(self.mode, is_root)?;
            for (targets, values) in [(&self.root, root.as_slice()), (&self.left, left.as_slice()), (&self.right, right.as_slice())] {
                for (&target, &value) in targets.iter().zip(values) { witness.set_target(target, value)?; }
            }
            if let Some(expected) = expected {
                for (&target, &value) in self.output.iter().zip(expected) { witness.set_target(target, value)?; }
            }
            let proof = self.circuit.prove(witness)?;
            let fields = proof.public_inputs.as_slice().try_into().unwrap();
            self.circuit.verify(proof)?;
            Ok(fields)
        }

        fn prove(&self, is_root: bool, root: &[F; 23], left: &Fields, right: &Fields) -> anyhow::Result<Fields> {
            self.prove_output(is_root, root, left, right, None)
        }
    }

    fn root_fields(id: u32) -> [F; 23] {
        let mut fields = [F::ZERO; 23];
        for (i, value) in [(0, 7), (1, 0x12345678), (5, 9), (9, id), (10, 3), (11, 5), (19, 13)] {
            fields[i] = F::from_canonical_u32(value);
        }
        fields
    }

    fn list_fields(ids: &[u32]) -> Fields {
        let root = root_fields(0);
        let mut fields = [F::ZERO; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT];
        fields[..6].copy_from_slice(&root[..6]);
        fields[6..10].copy_from_slice(&root[19..23]);
        fields[10] = F::from_canonical_usize(ids.len());
        fields[11] = F::from_canonical_usize(5 * ids.len());
        for (slot, &id) in fields[15..].iter_mut().zip(ids) { *slot = F::from_canonical_u32(id); }
        fields
    }

    #[test]
    fn singleton_zero_odd_lists_and_inactive_masking() {
        let relation = Relation::new();
        let dummy = [F::NEG_ONE; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT];
        let dummy_root = [F::NEG_ONE; 23];
        let mut leaves = Vec::new();
        for id in [0, 4, 9, 17, 25] {
            let output = relation.prove(true, &root_fields(id), &dummy, &dummy).unwrap();
            assert_eq!(output, list_fields(&[id]));
            leaves.push(output);
        }
        let pair = relation.prove(false, &dummy_root, &leaves[0], &leaves[1]).unwrap();
        let three = relation.prove(false, &dummy_root, &pair, &leaves[2]).unwrap();
        assert_eq!(three, list_fields(&[0, 4, 9]));
        let other_pair = relation.prove(false, &dummy_root, &leaves[3], &leaves[4]).unwrap();
        let five = relation.prove(false, &dummy_root, &three, &other_pair).unwrap();
        assert_eq!(five, list_fields(&[0, 4, 9, 17, 25]));
        // No power-of-two subtree-size restriction: singleton + pair is valid.
        let right_pair = relation.prove(false, &dummy_root, &leaves[1], &leaves[2]).unwrap();
        assert_eq!(relation.prove(false, &dummy_root, &leaves[0], &right_pair).unwrap(), three);
    }

    #[test]
    fn capacity_routing_and_checked_integer_totals() {
        let relation = Relation::new();
        let root = [F::NEG_ONE; 23];
        let ids: Vec<_> = (0..REWARD_CLAIM_MAX_CHECKPOINTS as u32).collect();
        // Every barrel-shift offset, including non-power-of-two splits.
        for split in 1..REWARD_CLAIM_MAX_CHECKPOINTS {
            let left = list_fields(&ids[..split]);
            let right = list_fields(&ids[split..]);
            assert_eq!(relation.prove(false, &root, &left, &right).unwrap(), list_fields(&ids));
        }
        let full = list_fields(&ids);
        let next = list_fields(&[REWARD_CLAIM_MAX_CHECKPOINTS as u32]);
        assert!(relation.prove(false, &root, &full, &next).is_err());
        let mut left = list_fields(&[0]);
        let right = list_fields(&[1]);
        left[11..15].fill(F::from_canonical_u32(u32::MAX));
        assert!(relation.prove(false, &root, &left, &right).is_err(), "u128 final carry");
        left[11..15].fill(F::ZERO);
        left[11] = F::from_canonical_u64(1 << 32);
        assert!(relation.prove(false, &root, &left, &right).is_err(), "unbounded amount limb");
        left = list_fields(&[0]);
        left[11] = F::from_canonical_u32(u32::MAX);
        let output = relation.prove(false, &root, &left, &right).unwrap();
        assert_eq!(output[11], F::from_canonical_u32(4));
        assert_eq!(output[12], F::ONE);
        for count in [0, 65, u32::MAX] {
            left = list_fields(&[0]);
            left[10] = F::from_canonical_u32(count);
            assert!(relation.prove(false, &root, &left, &right).is_err());
        }
        assert!(relation.prove(false, &root, &list_fields(&[]), &list_fields(&[])).is_err());
    }

    #[test]
    fn rejects_duplicates_malicious_lists_and_identity_changes() {
        let relation = Relation::new();
        let root = [F::NEG_ONE; 23];
        let left = list_fields(&[0, 4]);
        let right = list_fields(&[9, 17]);
        for bad in [list_fields(&[4, 9]), list_fields(&[9, 9]), list_fields(&[17, 9])] {
            assert!(relation.prove(false, &root, &left, &bad).is_err());
        }
        let mut bad_padding = right;
        bad_padding[17] = F::ONE;
        assert!(relation.prove(false, &root, &left, &bad_padding).is_err());
        let mut bad_range = right;
        bad_range[15] = F::from_canonical_u64(1 << 32);
        assert!(relation.prove(false, &root, &left, &bad_range).is_err());
        for index in 0..10 {
            let mut wrong = right;
            wrong[index] += F::ONE;
            assert!(relation.prove(false, &root, &left, &wrong).is_err(), "common field {index}");
        }
        let expected = list_fields(&[0, 4, 9, 17]);
        // A sorted substituted list is still invalid: output must be exact concatenation.
        for index in [10, 11, 15, 16, 17, 18, 19] {
            let mut wrong = expected;
            wrong[index] += F::ONE;
            assert!(relation.prove_output(false, &root, &left, &right, Some(&wrong)).is_err(), "output field {index}");
        }
        let zero = [F::ZERO; USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT];
        for index in [6, 7, 8, 13, 14, 15, 16, 17, 18] {
            let mut wrong = root_fields(1);
            wrong[index] = F::ONE;
            assert!(relation.prove(true, &wrong, &zero, &zero).is_err(), "Root padding {index}");
        }
        for range in [1..6, 10..11, 11..13] {
            let mut wrong = root_fields(1);
            wrong[range].fill(F::ZERO);
            assert!(relation.prove(true, &wrong, &zero, &zero).is_err());
        }
    }

    #[test]
    #[ignore = "full real construction measurement; Main QA only after independent review"]
    fn measure_checkpoint_aggregate_gates_and_degree() {
        let leaf = UserRewardLeafCircuit::new();
        let jobs = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&jobs);
        let aggregate = UserRewardCheckpointAggregateCircuit::new(&root);
        assert_eq!(aggregate.circuit_data.common.num_public_inputs, 147);
        assert_eq!(aggregate.targets.public_inputs.len(), 79);
        eprintln!("checkpoint capacity={}, unpadded_gates={}, degree_bits={}",
            REWARD_CLAIM_MAX_CHECKPOINTS, aggregate.unpadded_gate_count, aggregate.circuit_data.common.degree_bits());
    }

    #[test]
    #[ignore = "real recursive checkpoint proofs and wrapper bits; Main runs after independent review"]
    fn two_and_three_real_roots_aggregate_canonical_ids_and_wrap_public_bits() {
        use plonky2::field::types::PrimeField64;
        use plonky2::hash::{hash_types::HashOut, poseidon::PoseidonHash};
        use plonky2::plonk::config::Hasher;
        use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        use super::super::reward_claim_wrap::{RewardClaimWrapCircuit, RewardClaimWrapWitness};
        use super::super::user_reward_tree::{
            UserRewardAggregateCircuit, UserRewardAggregateWitness, UserRewardLeafCircuit, UserRewardRootCircuit,
        };
        use super::super::user_reward_tree::tests::{path, registration_membership, reward_root, Fixture};

        let leaf = UserRewardLeafCircuit::new();
        let jobs = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&jobs);
        let aggregate = UserRewardCheckpointAggregateCircuit::new(&root);
        let registration_index = psy_crypto::common::user_id::get_registration_id_from_user_id(7);
        let sources = [10u32, 11, 1024];
        let mut fixtures: Vec<_> = sources.into_iter().map(|_| Fixture::for_user(7, 4096)).collect();
        let common_root = path::<32>(&fixtures[0].checkpoints, 10, HashOut::ZERO).1;
        for fixture in &fixtures[1..] {
            assert_eq!(fixture.checkpoints, fixtures[0].checkpoints);
            assert_eq!(path::<32>(&fixture.checkpoints, 10, HashOut::ZERO).1, common_root);
        }
        let roots: Vec<_> = fixtures.iter_mut().zip(sources).map(|(fixture, source)| {
            let input = fixture.node(source, 0);
            let proved_leaf = leaf.prove(&input).unwrap();
            leaf.circuit_data.verify(proved_leaf.clone()).unwrap();
            let lifted = jobs.prove(&UserRewardAggregateWitness::Leaf { leaf: proved_leaf }).unwrap();
            jobs.circuit_data.verify(lifted.clone()).unwrap();
            let proved = reward_root(&root, fixture, 1, lifted);
            root.circuit_data.verify(proved.clone()).unwrap();
            proved
        }).collect();

        let mut nodes = fixtures[0].checkpoints.clone();
        let mut empty = HashOut::ZERO;
        for level in 0..32 {
            assert_eq!(empty, <PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(level), "checkpoint empty hash diverges at level {level}");
            let mut parents = std::collections::BTreeMap::new();
            for &index in nodes.keys() {
                parents.insert(index >> 1, PoseidonHash::two_to_one(
                    nodes.get(&(index & !1)).copied().unwrap_or(empty),
                    nodes.get(&(index | 1)).copied().unwrap_or(empty),
                ));
            }
            nodes = parents;
            empty = PoseidonHash::two_to_one(empty, empty);
        }
        assert_eq!(nodes[&0], common_root, "independently folded checkpoint root differs");
        let anchor_global_hash = fixtures[0].anchor_leaf.global_chain_root;

        let mut payout = 0u128;
        let (registration_leaf, _, registration_siblings, global_roots) = registration_membership(7);
        for ((proved, source), fixture) in roots.iter().zip(sources).zip(&fixtures) {
            let inputs = &proved.public_inputs;
            assert_eq!(inputs.len(), USER_REWARD_ROOT_PUBLIC_INPUT_COUNT);
            assert_eq!(inputs[0].to_canonical_u64(), 7);
            assert_eq!(inputs[9].to_canonical_u64(), u64::from(source));
            assert_eq!(inputs[10].to_canonical_u64(), 1);
            assert_eq!(&inputs[19..23], &common_root.elements);
            payout += inputs[11].to_canonical_u64() as u128;
            assert_ne!(registration_index, 7);
            assert_eq!(global_roots.qfhash::<PoseidonHash>(), anchor_global_hash);
            assert_eq!(fixture.anchor_leaf.qfhash::<PoseidonHash>().0, fixture.checkpoints[&4096]);
            assert_eq!(path::<32>(&fixture.checkpoints, u64::from(source), HashOut::ZERO).1, common_root);
            assert_eq!(path::<32>(&fixture.checkpoints, 4096, HashOut::ZERO).1, common_root);
        }

        let prove_checkpoint = |input: UserRewardCheckpointAggregateWitness| {
            let proved = aggregate.prove(&input).unwrap();
            aggregate.circuit_data.verify(proved.clone()).unwrap();
            proved
        };
        let singleton = |proof| prove_checkpoint(UserRewardCheckpointAggregateWitness::Root { root: proof });
        let leaves: Vec<_> = roots.iter().cloned().map(singleton).collect();
        let pair = prove_checkpoint(UserRewardCheckpointAggregateWitness::Pair { left: leaves[0].clone(), right: leaves[1].clone() });
        let triple = prove_checkpoint(UserRewardCheckpointAggregateWitness::Pair { left: pair.clone(), right: leaves[2].clone() });

        let expect = |proof: &UserRewardCheckpointAggregateProof, ids: &[u32], amount: u128| {
            let inputs = &proof.public_inputs;
            assert_eq!(inputs.len(), USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT);
            assert_eq!(inputs[0].to_canonical_u64(), 7);
            assert_eq!(&inputs[6..10], &common_root.elements);
            assert_eq!(inputs[10].to_canonical_u64(), ids.len() as u64);
            let mut total = 0u128;
            for index in 0..4 { total += (inputs[11 + index].to_canonical_u64() as u128) << (32 * index); }
            assert_eq!(total, amount);
            for (slot, value) in inputs[15..15 + REWARD_CLAIM_MAX_CHECKPOINTS].iter().zip(ids.iter().copied().chain(std::iter::repeat(0))) {
                assert_eq!(slot.to_canonical_u64(), u64::from(value));
            }
        };
        let one = roots[0].public_inputs[11].to_canonical_u64() as u128;
        expect(&pair, &[10, 11], one * 2);
        expect(&triple, &[10, 11, 1024], payout);
        assert_eq!(one * 3, payout);

        let wrapper = RewardClaimWrapCircuit::new(aggregate.get_common_circuit_data_ref(), aggregate.fingerprint, 4);
        let anchor_siblings = path::<32>(&fixtures[0].checkpoints, 4096, HashOut::ZERO).0;
        let auth = RewardClaimWrapWitness {
            state_manager: [0x43u8; 20], token: [0x45u8; 20], anchor_checkpoint_id: 4096,
            anchor_leaf: fixtures[0].anchor_leaf.clone(), anchor_siblings, global_roots,
            registration_leaf, registration_index, registration_siblings,
            private_key: QHashOut::from_values(17, 23, 31, 47).0,
        };
        let wrapped = wrapper.prove(aggregate.get_verifier_config_ref(), &triple, &auth).unwrap();
        wrapper.circuit_data.verify(wrapped.clone()).unwrap();
        assert_eq!(wrapped.public_inputs.len(), 256 * (8 + REWARD_CLAIM_MAX_CHECKPOINTS));
        let recovered = wrapped.public_inputs.chunks(64).flat_map(|group| {
            (0..8).map(move |byte| group[(7 - byte) * 8..(8 - byte) * 8].iter().enumerate()
                .fold(0u8, |accumulator, (index, bit)| accumulator + ((bit.to_canonical_u64() as u8) << index)))
        }).collect::<Vec<_>>();
        let word = |value: u64| { let mut bytes = [0u8; 32]; bytes[24..].copy_from_slice(&value.to_be_bytes()); bytes };
        let address = |value: [u8; 20]| { let mut bytes = [0u8; 32]; bytes[12..].copy_from_slice(&value); bytes };
        let mut hasher = tiny_keccak::Keccak::v256();
        let mut domain = [0u8; 32];
        tiny_keccak::Hasher::update(&mut hasher, b"PsyReward/TokenCheckpointClaim/1");
        tiny_keccak::Hasher::finalize(hasher, &mut domain);
        let mut expected = Vec::new();
        expected.extend(domain);
        expected.extend(address(auth.token));
        expected.extend(address(auth.state_manager));
        expected.extend(word(7));
        expected.extend([0u8; 12]);
        for limb in [5u32, 4, 3, 2, 1] { expected.extend(limb.to_be_bytes()); }
        for limb in common_root.elements.into_iter().rev() { expected.extend(limb.to_canonical_u64().to_be_bytes()); }
        expected.extend(word(3));
        expected.extend([0u8; 16]);
        expected.extend(payout.to_be_bytes());
        for index in 0..REWARD_CLAIM_MAX_CHECKPOINTS {
            expected.extend(word(if index < 3 { u64::from(sources[index]) } else { 0 }));
        }
        assert_eq!(recovered, expected);
    }
}
