use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{common::witnesses::qrecursion::proof_data::QStandardBinaryTreeCircuitType, hash::traits::hasher::MerkleZeroHasher};

use crate::{
    circuits::traits::qstandard::QStandardCircuit,
    treeprover::qrecursion::standard::circuits::{
        prove_2_agg::QRecursionStandardTwoAggCircuit, prove_2_leaves::QRecursionStandardTwoLeafCircuit,
        prove_left_agg_right_leaf::QRecursionStandardLeftAggRightLeafCircuit, prove_left_leaf_right_agg::QRecursionStandardLeftLeafRightAggCircuit,
        prove_single_leaf::QRecursionStandardSingleLeafCircuit,
    },
};

#[derive(Debug)]
pub struct QStandardBinaryRecursionTreeCircuitSet<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub single_leaf_circuit: QRecursionStandardSingleLeafCircuit<C, D>,
    pub two_leaf_circuit: QRecursionStandardTwoLeafCircuit<C, D>,
    pub two_agg_circuit: QRecursionStandardTwoAggCircuit<C, D>,
    pub left_leaf_right_agg_circuit: QRecursionStandardLeftLeafRightAggCircuit<C, D>,
    pub left_agg_right_leaf_circuit: QRecursionStandardLeftAggRightLeafCircuit<C, D>,
    pub leaf_circuit_config_id: u64,
    pub leaf_verifier_data_cap_height: usize,
    pub agg_verifier_data_cap_height: usize,
}

impl<C: GenericConfig<D>, const D: usize> QStandardBinaryRecursionTreeCircuitSet<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        q_recursion_tree_height: usize,
        leaf_circuit_config_id: u64,
        leaf_verifier_data_cap_height: usize,
        leaf_child_common_data: &CommonCircuitData<C::F, D>,
    ) -> Self {
        let single_leaf_circuit =
            QRecursionStandardSingleLeafCircuit::<C, D>::new(q_recursion_tree_height, leaf_verifier_data_cap_height, leaf_child_common_data);
        let two_leaf_circuit =
            QRecursionStandardTwoLeafCircuit::<C, D>::new(q_recursion_tree_height, leaf_verifier_data_cap_height, leaf_child_common_data);

        let agg_verifier_data_cap_height = two_leaf_circuit.get_verifier_config_ref().constants_sigmas_cap.height();

        let left_leaf_right_agg_circuit = QRecursionStandardLeftLeafRightAggCircuit::<C, D>::new_multi(
            q_recursion_tree_height,
            leaf_verifier_data_cap_height,
            leaf_child_common_data,
            agg_verifier_data_cap_height,
            two_leaf_circuit.get_common_circuit_data_ref(),
        );
        let left_agg_right_leaf_circuit = QRecursionStandardLeftAggRightLeafCircuit::<C, D>::new_multi(
            q_recursion_tree_height,
            leaf_verifier_data_cap_height,
            leaf_child_common_data,
            agg_verifier_data_cap_height,
            two_leaf_circuit.get_common_circuit_data_ref(),
        );

        let two_agg_circuit =
            QRecursionStandardTwoAggCircuit::<C, D>::new(agg_verifier_data_cap_height, two_leaf_circuit.get_common_circuit_data_ref());
        Self {
            single_leaf_circuit,
            two_leaf_circuit,
            two_agg_circuit,
            left_leaf_right_agg_circuit,
            left_agg_right_leaf_circuit,
            leaf_circuit_config_id,
            leaf_verifier_data_cap_height,
            agg_verifier_data_cap_height,
        }
    }

    pub fn print_common_data(&self) {
        println!(
            "\n\n\n\n[single_leaf_circuit -> height = {}]:\n{:?}\n\n\n\n",
            self.single_leaf_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
            self.single_leaf_circuit.get_common_circuit_data_ref()
        );
        println!(
            "\n\n\n\n[two_leaf_circuit -> height = {}]:\n{:?}\n\n\n\n",
            self.two_leaf_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
            self.two_leaf_circuit.get_common_circuit_data_ref()
        );
        println!(
            "\n\n\n\n[two_agg_circuit -> height = {}]:\n{:?}\n\n\n\n",
            self.two_agg_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
            self.two_agg_circuit.get_common_circuit_data_ref()
        );
        println!(
            "\n\n\n\n[left_leaf_right_agg_circuit -> height = {}]:\n{:?}\n\n\n\n",
            self.left_leaf_right_agg_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
            self.left_leaf_right_agg_circuit.get_common_circuit_data_ref()
        );
        println!(
            "\n\n\n\n[left_agg_right_leaf_circuit -> height = {}]:\n{:?}\n\n\n\n",
            self.left_agg_right_leaf_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
            self.left_agg_right_leaf_circuit.get_common_circuit_data_ref()
        );
    }

    pub fn get_fingerprint_by_type(&self, circuit_type: QStandardBinaryTreeCircuitType) -> QHashOut<C::F> {
        match circuit_type {
            QStandardBinaryTreeCircuitType::None => {
                panic!("tried to get fingerprint for a circuit with type None")
            }
            QStandardBinaryTreeCircuitType::SingleLeaf => self.single_leaf_circuit.get_fingerprint(),
            QStandardBinaryTreeCircuitType::TwoLeaf => self.two_leaf_circuit.get_fingerprint(),
            QStandardBinaryTreeCircuitType::TwoAgg => self.two_agg_circuit.get_fingerprint(),
            QStandardBinaryTreeCircuitType::LeftLeafRightAgg => self.left_leaf_right_agg_circuit.get_fingerprint(),
            QStandardBinaryTreeCircuitType::LeftAggRightLeaf => self.left_agg_right_leaf_circuit.get_fingerprint(),
            QStandardBinaryTreeCircuitType::Root => {
                panic!("tried to get fingerprint for a circuit with type Root")
            }
        }
    }

    pub fn get_verifier_data_by_type(&self, circuit_type: QStandardBinaryTreeCircuitType) -> &VerifierOnlyCircuitData<C, D> {
        match circuit_type {
            QStandardBinaryTreeCircuitType::None => {
                panic!("tried to get verifier data for a circuit with type None")
            }
            QStandardBinaryTreeCircuitType::SingleLeaf => self.single_leaf_circuit.get_verifier_config_ref(),
            QStandardBinaryTreeCircuitType::TwoLeaf => self.two_leaf_circuit.get_verifier_config_ref(),
            QStandardBinaryTreeCircuitType::TwoAgg => self.two_agg_circuit.get_verifier_config_ref(),
            QStandardBinaryTreeCircuitType::LeftLeafRightAgg => self.left_leaf_right_agg_circuit.get_verifier_config_ref(),
            QStandardBinaryTreeCircuitType::LeftAggRightLeaf => self.left_agg_right_leaf_circuit.get_verifier_config_ref(),
            QStandardBinaryTreeCircuitType::Root => {
                panic!("tried to get verifier data for a circuit with type Root")
            }
        }
    }
}
