use plonky2::{
    field::{extension::Extendable, interpolation::barycentric_weights},
    gates::{
        arithmetic_base::ArithmeticGate, arithmetic_extension::ArithmeticExtensionGate, base_sum::BaseSumGate, constant::ConstantGate,
        coset_interpolation::CosetInterpolationGate, gate::GateRef, multiplication_extension::MulExtensionGate, noop::NoopGate,
        poseidon::PoseidonGate, poseidon_mds::PoseidonMdsGate, random_access::RandomAccessGate, reducing::ReducingGate,
        reducing_extension::ReducingExtensionGate,
    },
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::u32::gates::comparison::ComparisonGate;

/*
[Common Gate Types List]
======================================
Identifier: **Type A**
NOTE: TYPE A IS DEPRECATED FOR NEW USE, MAKE A NEW TYPE INSTEAD OF USING TYPE A
<description>
Circuits which need to have the same common circuit data as:
    - a circuit that recursively verifies other proofs
</description>
======================================
Identifier: **Type B**
<description>
Circuits which need to have the same common circuit data as:
    - A Psy ZK Signature3 Circuit
</description>
======================================
Identifier: **Type C**
<description>
Circuits which need to have the same common circuit data as:
    [
        GUTALeftGUTARightEndCap,
        GUTATwoEndCap,
        GUTAVerifyToCap,
        GUTALeftEndCapRightGUTA,
        GUTATwoGUTA,
        GUTAOnlyRegisterUsers,
        GUTASingleEndCap,
        GUTANoChange,
        GUTARegisterUsers,
        GUTATwoGUTAWithCheckpointUpgrade,
        GUTAVerifyToCapWithCheckpointUpgrade,
    ]
</description>
======================================
Identifier: **Type D**
<description>
Circuits which need to have the same common circuit data as:
    [
        BatchDeployContractsAggregate,
        BatchDeployContracts,
        DummyBatchDeployContractsAggregate,
        GenerateRollupStateTransitionProof,
        DummyAppendUserRegistrationTreeAggregate,
        AppendUserRegistrationTreeAggregate,
        AppendUserRegistrationTree,
    ]
</description>
======================================
Identifier: **Type E**
<description>
Circuits which need to have the same common circuit data as:
    [
        UserEndCap,
    ]
</description>
======================================
Identifier: **Type F**
<description>
Circuits which need to have the same common circuit data as:
    [
        AggUserRegisterDeployContractsGUTA,
    ]
</description>
======================================
*/

pub fn new_coset_gate_with_max_degree<F: RichField + Extendable<D>, const D: usize>(
    subgroup_bits: usize,
    max_degree: usize,
) -> CosetInterpolationGate<F, D> {
    let mut base_gate = CosetInterpolationGate::<F, D>::default();

    assert!(max_degree > 1, "need at least quadratic constraints");

    let n_points = 1 << subgroup_bits;

    // Number of intermediate values required to compute interpolation with degree
    // bound
    let n_intermediates = (n_points - 2) / (max_degree - 1);

    // Find minimum degree such that (n_points - 2) / (degree - 1) < n_intermediates
    // + 1 Minimizing the degree this way allows the gate to be in a larger
    // selector group
    let degree = (n_points - 2) / (n_intermediates + 1) + 2;

    let barycentric_weights = barycentric_weights(&F::two_adic_subgroup(subgroup_bits).into_iter().map(|x| (x, F::ZERO)).collect::<Vec<_>>());
    base_gate.subgroup_bits = subgroup_bits;
    base_gate.degree = degree;
    base_gate.barycentric_weights = barycentric_weights;
    base_gate
}

pub fn pad_circuit_degree<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, target_degree: usize) {
    while builder.num_gates() < (1u64 << (target_degree as u64)) as usize {
        builder.add_gate(NoopGate, vec![]);
    }
}

pub trait CircuitBuilderPsyCommonGates<F: RichField + Extendable<D>, const D: usize> {
    fn add_psy_type_a_common_gates(&mut self, coset_gate: Option<GateRef<F, D>>);
    fn add_psy_type_a_common_gates_with_coset(&mut self, subgroup_bits: usize, max_degree: usize);
    fn add_psy_type_b_common_gates(&mut self);
    fn add_psy_type_c_common_gates(&mut self);
    fn add_psy_type_d_common_gates(&mut self);
    fn add_psy_type_e_common_gates(&mut self);
    fn add_psy_type_f_common_gates(&mut self);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderPsyCommonGates<F, D> for CircuitBuilder<F, D> {
    fn add_psy_type_a_common_gates(&mut self, coset_gate: Option<GateRef<F, D>>) {
        self.add_gate_to_gate_set(GateRef::new(ConstantGate::new(self.config.num_constants)));
        self.add_gate_to_gate_set(GateRef::new(ComparisonGate::new(32, 16)));
        self.add_gate_to_gate_set(GateRef::new(RandomAccessGate::new_from_config(&self.config, 4)));
        self.add_gate_to_gate_set(GateRef::new(PoseidonGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(PoseidonMdsGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(ReducingGate::<D>::new(43)));
        self.add_gate_to_gate_set(GateRef::new(ReducingExtensionGate::<D>::new(32)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(MulExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(BaseSumGate::<2>::new_from_config::<F>(&self.config)));
        if coset_gate.is_some() {
            self.add_gate_to_gate_set(coset_gate.unwrap());
        }
    }

    fn add_psy_type_a_common_gates_with_coset(&mut self, subgroup_bits: usize, max_degree: usize) {
        let coset_gate = GateRef::new(new_coset_gate_with_max_degree::<F, D>(subgroup_bits, max_degree));
        self.add_psy_type_a_common_gates(Some(coset_gate));
    }

    fn add_psy_type_b_common_gates(&mut self) {
        self.add_gate_to_gate_set(GateRef::new(ConstantGate::new(self.config.num_constants)));
        self.add_gate_to_gate_set(GateRef::new(ComparisonGate::new(32, 16)));
        self.add_gate_to_gate_set(GateRef::new(RandomAccessGate::new_from_config(&self.config, 4)));

        let coset_gate = GateRef::new(new_coset_gate_with_max_degree::<F, D>(4, 8));
        self.add_gate_to_gate_set(coset_gate);

        self.add_gate_to_gate_set(GateRef::new(PoseidonGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(PoseidonMdsGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(ReducingGate::<D>::new(43)));
        self.add_gate_to_gate_set(GateRef::new(ReducingExtensionGate::<D>::new(32)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(MulExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(BaseSumGate::<2>::new_from_config::<F>(&self.config)));
    }

    fn add_psy_type_c_common_gates(&mut self) {
        self.add_gate_to_gate_set(GateRef::new(ConstantGate::new(self.config.num_constants)));
        self.add_gate_to_gate_set(GateRef::new(RandomAccessGate::new_from_config(&self.config, 4)));

        let coset_gate = GateRef::new(new_coset_gate_with_max_degree::<F, D>(4, 8));
        self.add_gate_to_gate_set(coset_gate);

        self.add_gate_to_gate_set(GateRef::new(PoseidonGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(PoseidonMdsGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(ReducingGate::<D>::new(43)));
        self.add_gate_to_gate_set(GateRef::new(ReducingExtensionGate::<D>::new(32)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(MulExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(BaseSumGate::<2>::new_from_config::<F>(&self.config)));
    }

    fn add_psy_type_d_common_gates(&mut self) {
        self.add_gate_to_gate_set(GateRef::new(ConstantGate::new(self.config.num_constants)));
        self.add_gate_to_gate_set(GateRef::new(ComparisonGate::new(32, 16)));
        self.add_gate_to_gate_set(GateRef::new(RandomAccessGate::new_from_config(&self.config, 4)));

        let coset_gate = GateRef::new(new_coset_gate_with_max_degree::<F, D>(4, 8));
        self.add_gate_to_gate_set(coset_gate);

        self.add_gate_to_gate_set(GateRef::new(PoseidonGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(PoseidonMdsGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(ReducingGate::<D>::new(43)));
        self.add_gate_to_gate_set(GateRef::new(ReducingExtensionGate::<D>::new(32)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(MulExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(BaseSumGate::<2>::new_from_config::<F>(&self.config)));
    }

    fn add_psy_type_e_common_gates(&mut self) {
        self.add_gate_to_gate_set(GateRef::new(ConstantGate::new(self.config.num_constants)));
        self.add_gate_to_gate_set(GateRef::new(RandomAccessGate::new_from_config(&self.config, 4)));

        let coset_gate = GateRef::new(new_coset_gate_with_max_degree::<F, D>(4, 8));
        self.add_gate_to_gate_set(coset_gate);

        self.add_gate_to_gate_set(GateRef::new(PoseidonGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(PoseidonMdsGate::<F, D>::new()));
        self.add_gate_to_gate_set(GateRef::new(ReducingGate::<D>::new(43)));
        self.add_gate_to_gate_set(GateRef::new(ReducingExtensionGate::<D>::new(32)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(ArithmeticExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(MulExtensionGate::new_from_config(&self.config)));
        self.add_gate_to_gate_set(GateRef::new(BaseSumGate::<2>::new_from_config::<F>(&self.config)));
    }

    fn add_psy_type_f_common_gates(&mut self) {
        self.add_psy_type_e_common_gates();
    }
}
