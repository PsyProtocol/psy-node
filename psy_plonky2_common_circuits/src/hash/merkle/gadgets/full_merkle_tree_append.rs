use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::BoolTarget, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers,
    hash::core::CircuitBuilderHashCore,
};

#[derive(Debug, Clone)]
pub struct FullMerkleTreeAppendGadget {
    // need witness
    pub old_leaves: Vec<HashOutTarget>,
    pub new_leaves: Vec<HashOutTarget>,

    // computed
    pub added_leaves: Vec<BoolTarget>,
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
}

impl FullMerkleTreeAppendGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let num_leaves = 1usize << height;

        let mut old_leaves = Vec::with_capacity(num_leaves);
        let mut new_leaves = Vec::with_capacity(num_leaves);
        let mut added_leaves = Vec::with_capacity(num_leaves);

        let mut leaf_must_be_zero = builder._false();

        for _ in 0..num_leaves {
            let old_leaf = builder.add_virtual_hash();
            let new_leaf = builder.add_virtual_hash();

            let is_old_leaf_zero = builder.is_zero_hash(old_leaf);
            let is_new_leaf_zero = builder.is_zero_hash(new_leaf);
            let is_new_leaf_not_zero = builder.not(is_new_leaf_zero);
            let is_added_leaf = builder.and(is_old_leaf_zero, is_new_leaf_not_zero);

            // if the old leaf is non-zero, it is not allowed to be changed
            builder.connect_hashes_if_false(is_old_leaf_zero, old_leaf, new_leaf);

            // after we hit the first skipped hash, all future hashes should be zero
            let encountered_end_of_results = builder.and(is_old_leaf_zero, is_new_leaf_zero);

            // once we find a zero new leaf, all future new/old leaves must be zero
            leaf_must_be_zero = builder.or(leaf_must_be_zero, encountered_end_of_results);

            builder.connect_zero_if_true(leaf_must_be_zero, new_leaf.elements[0]);
            builder.connect_zero_if_true(leaf_must_be_zero, new_leaf.elements[1]);
            builder.connect_zero_if_true(leaf_must_be_zero, new_leaf.elements[2]);
            builder.connect_zero_if_true(leaf_must_be_zero, new_leaf.elements[3]);

            builder.connect_zero_if_true(leaf_must_be_zero, old_leaf.elements[0]);
            builder.connect_zero_if_true(leaf_must_be_zero, old_leaf.elements[1]);
            builder.connect_zero_if_true(leaf_must_be_zero, old_leaf.elements[2]);
            builder.connect_zero_if_true(leaf_must_be_zero, old_leaf.elements[3]);

            old_leaves.push(old_leaf);
            new_leaves.push(new_leaf);
            added_leaves.push(is_added_leaf);
        }

        let mut current_level_old_leaves = old_leaves.clone();
        let mut current_level_new_leaves = new_leaves.clone();

        let mut nodes_in_level = current_level_new_leaves.len();

        while nodes_in_level > 1 {
            let half = nodes_in_level / 2;
            current_level_old_leaves = (0..half)
                .map(|i| {
                    builder.hash_two_to_one::<H>(
                        current_level_old_leaves[i * 2],
                        current_level_old_leaves[i * 2 + 1],
                    )
                })
                .collect::<Vec<_>>();
            current_level_new_leaves = (0..half)
                .map(|i| {
                    builder.hash_two_to_one::<H>(
                        current_level_new_leaves[i * 2],
                        current_level_new_leaves[i * 2 + 1],
                    )
                })
                .collect::<Vec<_>>();
            nodes_in_level = half;
        }

        let old_root = current_level_old_leaves[0];
        let new_root = current_level_new_leaves[0];
        Self {
            old_leaves,
            new_leaves,
            added_leaves,
            old_root,
            new_root,
        }
    }
    pub fn set_witness<W: Witness<F>, F: Field>(
        &self,
        witness: &mut W,
        old_leaves: &[QHashOut<F>],
        new_leaves: &[QHashOut<F>],
    ) -> anyhow::Result<()> {
        if old_leaves.len() != self.old_leaves.len() {
            anyhow::bail!(
                "invalid number of old leaves provided to set_witness: expected {}, got {}",
                self.old_leaves.len(),
                old_leaves.len()
            );
        }
        if new_leaves.len() != self.new_leaves.len() {
            anyhow::bail!(
                "invalid number of old leaves provided to set_witness: expected {}, got {}",
                self.old_leaves.len(),
                old_leaves.len()
            );
        }

        for (target, value) in self.old_leaves.iter().zip(old_leaves.iter()) {
            witness.set_hash_target(*target, value.0)?;
        }

        for (target, value) in self.new_leaves.iter().zip(new_leaves.iter()) {
            witness.set_hash_target(*target, value.0)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use parth_core::crypto::hash::merkle_proof::compute_partial_merkle_root_from_leaves;
    use plonky2::field::types::Field;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use parth_core::pgoldilocks::{PoseidonHasher, QHashOut};

    use rand::{thread_rng, Rng};

    use super::FullMerkleTreeAppendGadget;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    struct TestFullMerkleTreeAppendCircuit {
        pub update_gadget: FullMerkleTreeAppendGadget,
        pub circuit_data: CircuitData<F, C, D>,
    }

    impl TestFullMerkleTreeAppendCircuit {
        pub fn new(height: usize) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let update_gadget = FullMerkleTreeAppendGadget::add_virtual_to::<PoseidonHash, F, D>(
                &mut builder,
                height,
            );

            builder.register_public_inputs(&update_gadget.old_root.elements);
            builder.register_public_inputs(&update_gadget.new_root.elements);
            builder.register_public_inputs(
                &update_gadget
                    .added_leaves
                    .iter()
                    .map(|x| x.target)
                    .collect::<Vec<_>>(),
            );

            let circuit_data = builder.build::<C>();
            Self {
                update_gadget,
                circuit_data,
            }
        }
        pub fn prove(
            &self,
            old_leaves: &[QHashOut<F>],
            new_leaves: &[QHashOut<F>],
        ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::new();
            self.update_gadget
                .set_witness(&mut pw, old_leaves, new_leaves)?;
            self.circuit_data.prove(pw)
        }
    }
    #[derive(Clone, Debug)]
    struct FullMerkleTreeAppendTestCase {
        start_append_leaf_index: usize,
        append_count: usize,

        old_leaves: Vec<QHashOut<F>>,
        new_leaves: Vec<QHashOut<F>>,
        added_leaves: Vec<bool>,
        should_fail: bool,
    }

    impl FullMerkleTreeAppendTestCase {
        pub fn get_old_root(&self) -> QHashOut<F> {
            compute_partial_merkle_root_from_leaves::<
                QHashOut<F>,
                PoseidonHasher,
            >(
                &self.old_leaves,
            )
        }
        pub fn get_new_root(&self) -> QHashOut<F> {
            compute_partial_merkle_root_from_leaves::<
                QHashOut<F>,
                PoseidonHasher,
            >(
                &self.new_leaves,
            )
        }
        pub fn gen_valid_for_height(
            height: usize,
            start_append_leaf_index: usize,
            append_count: usize,
        ) -> Self {
            let total_leaves = 1usize << height;
            let mut old_leaves = Vec::with_capacity(total_leaves);
            let mut new_leaves = Vec::with_capacity(total_leaves);
            let mut added_leaves = Vec::with_capacity(total_leaves);
            let append_limit_index = start_append_leaf_index + append_count;
            for i in 0..total_leaves {
                if i < start_append_leaf_index {
                    let value = QHashOut::<F>::rand();
                    old_leaves.push(value);
                    new_leaves.push(value);
                    added_leaves.push(false);
                } else if i < append_limit_index {
                    let value = QHashOut::<F>::rand();
                    old_leaves.push(QHashOut::ZERO);
                    new_leaves.push(value);
                    added_leaves.push(true);
                } else {
                    old_leaves.push(QHashOut::ZERO);
                    new_leaves.push(QHashOut::ZERO);
                    added_leaves.push(false);
                }
            }

            Self {
                old_leaves,
                new_leaves,
                added_leaves,
                should_fail: false,
                start_append_leaf_index,
                append_count,
            }
        }

        pub fn make_invalid_with_zero_hash_mutation(&self) -> Self {
            let mut new_bad = self.to_owned();
            assert!(
                self.append_count > 1,
                "cannot generate an invalid zero hash insertion when append count is 0 or 1"
            );

            let mutate_index = thread_rng().gen_range(0..(self.append_count - 1));

            // add a zero hash before an updated leaf
            new_bad.new_leaves[self.start_append_leaf_index + mutate_index] = QHashOut::ZERO;

            new_bad
        }

        pub fn gen_invalid_for_height_with_old_leaf_mutation(
            height: usize,
            start_append_leaf_index: usize,
            append_count: usize,
        ) -> Self {
            assert_ne!(
                append_count, 0,
                "cannot generate an invalid insertion when append count is 0"
            );
            assert_ne!(
                start_append_leaf_index, 0,
                "cannot generate an invalid old leaf update when the start index is 0"
            );
            let mut new_bad =
                Self::gen_valid_for_height(height, start_append_leaf_index, append_count);

            let mutate_index = thread_rng().gen_range(0..(start_append_leaf_index));

            new_bad.new_leaves[mutate_index] = QHashOut::rand();
            new_bad
        }

        pub fn gen_invalid_for_height_with_old_leaf_mutation_and_zero_hash(
            height: usize,
            start_append_leaf_index: usize,
            append_count: usize,
        ) -> Self {
            assert_ne!(
                append_count, 0,
                "cannot generate an invalid insertion when append count is 0"
            );
            assert_ne!(
                start_append_leaf_index, 0,
                "cannot generate an invalid old leaf update when the start index is 0"
            );
            let mut new_bad =
                Self::gen_valid_for_height(height, start_append_leaf_index, append_count)
                    .make_invalid_with_zero_hash_mutation();

            let mutate_index = thread_rng().gen_range(0..(start_append_leaf_index));

            new_bad.new_leaves[mutate_index] = QHashOut::rand();
            new_bad
        }

        pub fn check_against_public_inputs(&self, public_inputs: &[F]) -> anyhow::Result<()> {
            if self.should_fail {
                anyhow::bail!("expected failure but circuit proved successfully, the gadget incorrectly or under constrained");
            }

            if self.get_old_root().0.elements.to_vec() != public_inputs[0..4].to_vec() {
                anyhow::bail!("incorrect old root");
            }

            if self.get_new_root().0.elements.to_vec() != public_inputs[4..8].to_vec() {
                anyhow::bail!("incorrect new root");
            }

            let proof_added_leaves = public_inputs[8..]
                .iter()
                .map(|x| !x.is_zero())
                .collect::<Vec<_>>();
            if self.added_leaves != proof_added_leaves {
                anyhow::bail!("incorrect added_leaves");
            }

            Ok(())
        }
    }

    fn test_working_merkle_tree_append_circuit_for_height(height: usize) {
        let circuit = TestFullMerkleTreeAppendCircuit::new(height);
        let total_leaves = 1usize << height;
        //let mut test_cases: Vec<FullMerkleTreeAppendTestCase> = Vec::new();

        // prove valids
        for start_leaf_ind in 0..(total_leaves + 1) {
            for append_count in 0..(total_leaves - start_leaf_ind + 1) {
                let tc = FullMerkleTreeAppendTestCase::gen_valid_for_height(
                    height,
                    start_leaf_ind,
                    append_count,
                );
                let public_inputs = circuit
                    .prove(&tc.old_leaves, &tc.new_leaves)
                    .unwrap()
                    .public_inputs;
                tc.check_against_public_inputs(&public_inputs).unwrap();

                if append_count != 0 {
                    if append_count > 1 {
                        let zh_tc = tc.make_invalid_with_zero_hash_mutation();
                        let proof_result = circuit.prove(&zh_tc.old_leaves, &zh_tc.new_leaves);

                        assert!(proof_result.is_err(), "expected proving to fail after inserting an invalid zero hash mutation, circuit/gadget is underconstrained");
                    }
                    if start_leaf_ind != 0 {
                        let ol_tc = FullMerkleTreeAppendTestCase::gen_invalid_for_height_with_old_leaf_mutation(height, start_leaf_ind, append_count);
                        let proof_result = circuit.prove(&ol_tc.old_leaves, &ol_tc.new_leaves);
                        assert!(proof_result.is_err(), "expected proving to fail after updating an old leaf, circuit/gadget is underconstrained");

                        if append_count > 1 {
                            let ol_zh_tc = FullMerkleTreeAppendTestCase::gen_invalid_for_height_with_old_leaf_mutation_and_zero_hash(height, start_leaf_ind, append_count);
                            let proof_result =
                                circuit.prove(&ol_zh_tc.old_leaves, &ol_zh_tc.new_leaves);
                            assert!(proof_result.is_err(), "expected proving to fail after updating an old leaf and inserting a zero_hash, circuit/gadget is underconstrained");
                        }
                    }
                }
            }
        }
    }

    fn test_working_merkle_tree_append_circuit_for_height_random_max_count(
        height: usize,
        max_count: usize,
    ) {
        let circuit = TestFullMerkleTreeAppendCircuit::new(height);
        let total_leaves = 1usize << height;

        for _ in 0..max_count {
            let start_leaf_ind = thread_rng().gen_range(0..(total_leaves + 1));
            let append_count = thread_rng().gen_range(0..(total_leaves - start_leaf_ind + 1));

            //let mut timer = DebugTimer::new("full_merkle_append_prover");
            let tc = FullMerkleTreeAppendTestCase::gen_valid_for_height(
                height,
                start_leaf_ind,
                append_count,
            );
            //timer.lap("generated witness");
            let public_inputs = circuit
                .prove(&tc.old_leaves, &tc.new_leaves)
                .unwrap()
                .public_inputs;
            //timer.lap("proved");
            tc.check_against_public_inputs(&public_inputs).unwrap();

            if append_count != 0 {
                if append_count > 1 {
                    let zh_tc = tc.make_invalid_with_zero_hash_mutation();
                    let proof_result = circuit.prove(&zh_tc.old_leaves, &zh_tc.new_leaves);

                    assert!(proof_result.is_err(), "expected proving to fail after inserting an invalid zero hash mutation, circuit/gadget is underconstrained");
                }
                if start_leaf_ind != 0 {
                    let ol_tc =
                        FullMerkleTreeAppendTestCase::gen_invalid_for_height_with_old_leaf_mutation(
                            height,
                            start_leaf_ind,
                            append_count,
                        );
                    let proof_result = circuit.prove(&ol_tc.old_leaves, &ol_tc.new_leaves);
                    assert!(proof_result.is_err(), "expected proving to fail after updating an old leaf, circuit/gadget is underconstrained");

                    if append_count > 1 {
                        let ol_zh_tc = FullMerkleTreeAppendTestCase::gen_invalid_for_height_with_old_leaf_mutation_and_zero_hash(height, start_leaf_ind, append_count);
                        let proof_result =
                            circuit.prove(&ol_zh_tc.old_leaves, &ol_zh_tc.new_leaves);
                        assert!(proof_result.is_err(), "expected proving to fail after updating an old leaf and inserting a zero_hash, circuit/gadget is underconstrained");
                    }
                }
            }
        }
    }
    #[test]
    fn test_full_merkle_tree_append_height_0_to_5_all_combos() {
        for height in 0..=5 {
            test_working_merkle_tree_append_circuit_for_height(height);
        }
    }

    #[test]
    fn test_full_merkle_tree_append_fuzz_large_trees() {
        for height in 6..=9{
            test_working_merkle_tree_append_circuit_for_height_random_max_count(height, 16);
        }
    }
}
