use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::{BoolTarget, Target}, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_plonky2_basic_helpers::builder::{
    hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers
};

use crate::hash::merkle::gadgets::{
    delta_merkle_proof::{DeltaMerkleProofGadget, DeltaMerkleProofGadgetOptionFlags}, variable_height_delta_merkle_proof_index::VariableHeightMerkleProofIndexBitInfoGadget}
;

#[derive(Debug, Clone)]
pub struct DualVariableHeightDeltaMerkleProofGadget {
    pub bit_info: VariableHeightMerkleProofIndexBitInfoGadget,
    pub height: Target,
    pub left_proof: DeltaMerkleProofGadget,
    pub right_proof: DeltaMerkleProofGadget,

    // computed
    pub old_root: HashOutTarget,
    pub intermediate_root: HashOutTarget,
    pub new_root: HashOutTarget,
    pub parent_index: Target,
    pub left_proof_index_bits: Vec<BoolTarget>,
    pub right_proof_index_bits: Vec<BoolTarget>,
    pub left_proof_witness_flags: DeltaMerkleProofGadgetOptionFlags,
    pub right_proof_witness_flags: DeltaMerkleProofGadgetOptionFlags,
    pub has_known_height: bool,
}
fn compute_merkle_root<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf_value: HashOutTarget,
    siblings: &[HashOutTarget],
    index_bits: &[BoolTarget],
    is_bit_not_within_height: &[BoolTarget],
) -> HashOutTarget {
    assert_eq!(
        index_bits.len(),
        is_bit_not_within_height.len(),
        "index bits length must equal is_bit_not_within_height length"
    );
    assert!(
        index_bits.len() >= siblings.len(),
        "index bits length must be greater than or equal to siblings length"
    );
    let mut current_hash = leaf_value;
    for i in 0..siblings.len() {
        let hash = builder.two_to_one_swapped::<H>(current_hash, siblings[i], index_bits[i]);
        current_hash = builder.select_hash(is_bit_not_within_height[i], current_hash, hash);
    }
    current_hash
}
impl DualVariableHeightDeltaMerkleProofGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_merkle_proof_height: usize,
        tree_height: usize,
        known_height_target: Option<Target>,

        known_left_old_value: Option<HashOutTarget>,
        known_left_new_value: Option<HashOutTarget>,
        known_left_index: Option<Target>,

        known_right_old_value: Option<HashOutTarget>,
        known_right_new_value: Option<HashOutTarget>,
        known_right_index: Option<Target>,
    ) -> Self {
        let left_index = known_left_index.unwrap_or_else(|| builder.add_virtual_target());
        let left_old_value = known_left_old_value.unwrap_or_else(|| builder.add_virtual_hash());
        let left_new_value = known_left_new_value.unwrap_or_else(|| builder.add_virtual_hash());
        let left_siblings = (0..max_merkle_proof_height).map(|_| builder.add_virtual_hash()).collect::<Vec<_>>();

        let right_index = known_right_index.unwrap_or_else(|| builder.add_virtual_target());
        let right_old_value = known_right_old_value.unwrap_or_else(|| builder.add_virtual_hash());
        let right_new_value = known_right_new_value.unwrap_or_else(|| builder.add_virtual_hash());
        let right_siblings = (0..max_merkle_proof_height).map(|_| builder.add_virtual_hash()).collect::<Vec<_>>();

        let left_proof_witness_flags = {
            let mut flags = DeltaMerkleProofGadgetOptionFlags::empty();
            if known_left_old_value.is_some() {
                flags |= DeltaMerkleProofGadgetOptionFlags::old_value;
            }
            if known_left_new_value.is_some() {
                flags |= DeltaMerkleProofGadgetOptionFlags::new_value;
            }
            if known_left_index.is_some() {
                flags |= DeltaMerkleProofGadgetOptionFlags::index;
            }

            flags
        };
        let right_proof_witness_flags = {
            let mut flags = DeltaMerkleProofGadgetOptionFlags::empty();
            if known_right_old_value.is_some() {
                flags |= DeltaMerkleProofGadgetOptionFlags::old_value;
            }
            if known_right_new_value.is_some() {
                flags |= DeltaMerkleProofGadgetOptionFlags::new_value;
            }
            if known_right_index.is_some() {
                flags |= DeltaMerkleProofGadgetOptionFlags::index;
            }

            flags
        };

        let has_known_height = known_height_target.is_some();
        let height = if let Some(h) = known_height_target {
            h
        } else {
            builder.add_virtual_target()
        };

        let left_index_bits = builder.split_le(left_index, tree_height);
        let right_index_bits = builder.split_le(right_index, tree_height);

        let bit_info = VariableHeightMerkleProofIndexBitInfoGadget::add_virtual_to::<H, F, D>(
            builder,
            max_merkle_proof_height,
            tree_height,
            height,
            &left_index_bits,
            &right_index_bits,
        );

        let left_old_root = compute_merkle_root::<H, F, D>(
            builder,
            left_old_value,
            &left_siblings,
            &left_index_bits,
            &bit_info.is_bit_not_within_height,
        );
        let left_new_root = compute_merkle_root::<H, F, D>(
            builder,
            left_new_value,
            &left_siblings,
            &left_index_bits,
            &bit_info.is_bit_not_within_height,
        );
        let right_old_root = compute_merkle_root::<H, F, D>(
            builder,
            right_old_value,
            &right_siblings,
            &right_index_bits,
            &bit_info.is_bit_not_within_height,
        );
        let right_new_root = compute_merkle_root::<H, F, D>(
            builder,
            right_new_value,
            &right_siblings,
            &right_index_bits,
            &bit_info.is_bit_not_within_height,
        );
        // ensure the delta merkle proofs are back to back, ie. left transition occurs
        // and then right transition occurs
        builder.connect_hashes(left_new_root, right_old_root);

        let intermediate_root = right_old_root;
        let old_root = left_old_root;
        let new_root = right_new_root;

        let left_proof = DeltaMerkleProofGadget {
            old_value: left_old_value,
            old_root: left_old_root,
            new_value: left_new_value,
            new_root: left_new_root,
            index: left_index,
            siblings: left_siblings,
            option_flags: left_proof_witness_flags,
        };
        let right_proof = DeltaMerkleProofGadget {
            old_value: right_old_value,
            new_value: right_new_value,
            old_root: right_old_root,
            new_root: right_new_root,
            index: right_index,
            siblings: right_siblings,
            option_flags: right_proof_witness_flags,
        };

        Self {
            parent_index: bit_info.parent_index,
            bit_info,
            height,
            left_proof,
            right_proof,
            old_root,
            intermediate_root,
            new_root,
            left_proof_index_bits: left_index_bits,
            right_proof_index_bits: right_index_bits,
            left_proof_witness_flags,
            right_proof_witness_flags,
            has_known_height,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        left_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        right_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        println!("left_proof: {:?}", left_proof);
        println!("right_proof: {:?}", right_proof);
        println!("left_proof_height: {}", left_proof.siblings.len());
        if left_proof.siblings.len() != right_proof.siblings.len() {
            return Err(anyhow::anyhow!(
                "Left and right proof sibling lengths do not match"
            ));
        }
        if left_proof.new_root != right_proof.old_root {
            return Err(anyhow::anyhow!(
                "Left proof new root does not match right proof old root"
            ));
        }
        self.left_proof.set_witness_pad_siblings(witness, F::from_noncanonical_u64(left_proof.index), left_proof.old_value, left_proof.new_value, &left_proof.siblings)?;
        self.right_proof.set_witness_pad_siblings(witness, F::from_noncanonical_u64(right_proof.index), right_proof.old_value, right_proof.new_value, &right_proof.siblings)?;
        
        if !self.has_known_height {
            witness.set_target(self.height, F::from_canonical_usize(left_proof.siblings.len()))?;
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use cf_utils::timer::DebugTimer;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{data::hash::merkle_node_key::SimpleMerkleNodeKey, pgoldilocks::PoseidonHasher};
    use plonky2::{field::goldilocks_field::GoldilocksField, iop::witness::PartialWitness, plonk::{circuit_data::{CircuitConfig, CircuitData}, config::{GenericConfig, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs}};
    use psy_plonky2_basic_helpers::builder::pad_circuit::PsyCircuitBuilderGateCountPrinter;

    

    use super::*;



    struct SimpleDualVariableHeightDeltaMerkleProofCircuitPublicInputsResult<F: RichField> {
        pub parent_index: F,
        pub height: F,
        pub old_root: QHashOut<F>,
        pub intermediate_root: QHashOut<F>,
        pub new_root: QHashOut<F>,
        pub is_bit_not_within_height: Vec<bool>,
    }
    fn felts_to_bool_vec<F: RichField>(felts: &[F]) -> Vec<bool> {
        felts.iter().map(|&f| {
            if f == F::ZERO {
                false
            } else if f == F::ONE {
                true
            }else{
                panic!("Felt is not boolean");
            }
        }).collect()
    }
    impl<F: RichField> SimpleDualVariableHeightDeltaMerkleProofCircuitPublicInputsResult<F> {
        pub fn from_public_inputs(public_inputs: &[F], tree_height: usize, max_merkle_proof_height: usize) -> Self {
            println!("public_inputs len: {}", public_inputs.len());
            println!("public_inputs: {:?}", public_inputs);
            let parent_index = public_inputs[0];
            let height = public_inputs[1];
            let old_root = QHashOut::from_felt_slice(&public_inputs[2..6]);
            let intermediate_root = QHashOut::from_felt_slice(&public_inputs[6..10]);
            let new_root = QHashOut::from_felt_slice(&public_inputs[10..14]);
            let is_bit_not_within_height = felts_to_bool_vec(&public_inputs[14..14 + tree_height]);
            println!("is_bit_not_within_height: {:?}", is_bit_not_within_height.iter().map(|x|if *x { 1 } else { 0 }).collect::<Vec<_>>());
            println!("height: {}", height);
            println!("max_merkle_proof_height: {}", max_merkle_proof_height);
            Self {
                parent_index,
                height,
                old_root,
                intermediate_root,
                new_root,
                is_bit_not_within_height,
            }
        }
        pub fn validate_from_inputs(&self, left_proof: &DeltaMerkleProofCore<QHashOut<F>>, right_proof: &DeltaMerkleProofCore<QHashOut<F>>, tree_height: usize, _max_merkle_proof_height: usize) {
            assert_eq!(self.old_root, left_proof.old_root, "Old root does not match left proof old root");
            assert_eq!(self.intermediate_root, left_proof.new_root, "Intermediate root does not match left proof new root");
            assert_eq!(self.new_root, right_proof.new_root, "New root does not match right proof new root");

            assert_eq!(self.height, F::from_noncanonical_u64(left_proof.siblings.len() as u64), "Height does not match left proof height");
            let expected_parent_index = left_proof.index >> (left_proof.siblings.len());
            let expected_parent_index_right = right_proof.index >> (right_proof.siblings.len());
            assert_eq!(expected_parent_index, expected_parent_index_right, "Expected parent index from left and right proofs do not match");
            assert_eq!(F::from_noncanonical_u64(expected_parent_index), self.parent_index, "Parent index does not match expected parent index");
            
            let left_index_bits = (0..tree_height).map(|i| {
                ((left_proof.index >> i) & 1) == 1
            }).collect::<Vec<_>>();
            let right_index_bits = (0..tree_height).map(|i| {
                ((right_proof.index >> i) & 1) == 1
            }).collect::<Vec<_>>();

            for i in 0..self.is_bit_not_within_height.len() {
                if i >= left_proof.siblings.len() {
                    // at tree height, ensure bits are equal
                    assert_eq!(left_index_bits[i], right_index_bits[i], "Index bits do not match at tree height index {}", i);
                    assert_eq!(self.is_bit_not_within_height[i], true, "is_bit_not_within_height does not match at index {}", i);
                }else{
                    assert_eq!(self.is_bit_not_within_height[i], false, "is_bit_not_within_height does not match at index {}", i);
                }
            }
        }
    }

    struct SimpleDualVariableHeightDeltaMerkleProofCircuit<C: GenericConfig<D>, const D: usize>
    where
        C::Hasher: AlgebraicHasher<C::F>,
    {
        pub gadget: DualVariableHeightDeltaMerkleProofGadget,
        pub circuit_data: CircuitData<C::F, C, D>,
        pub tree_height: usize,
        pub max_merkle_proof_height: usize,
    }
    impl<C: GenericConfig<D>, const D: usize> SimpleDualVariableHeightDeltaMerkleProofCircuit<C, D>
    where
        C::Hasher: AlgebraicHasher<C::F>,
    {
        pub fn new(
            max_merkle_proof_height: usize,
            tree_height: usize,
        ) -> Self {
            let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());

            let gadget = DualVariableHeightDeltaMerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                max_merkle_proof_height,
                tree_height,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );
            let public_inputs = [
                vec![gadget.parent_index, gadget.height],
                gadget.old_root.elements.to_vec(),
                gadget.intermediate_root.elements.to_vec(),
                gadget.new_root.elements.to_vec(),
                gadget.bit_info.is_bit_not_within_height.iter().map(|b| b.target).collect::<Vec<_>>(),
            ].concat();
            builder.register_public_inputs(&public_inputs);
            builder.print_gate_counts_with_message("num gates");
            let circuit_data = builder.build::<C>();
            Self {
                gadget,
                circuit_data,
                tree_height,
                max_merkle_proof_height,
            }
        }

        pub fn prove_base(
            &self,
            left_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
            right_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
            let mut debug_timer = DebugTimer::new("SimpleDualVariableHeightDeltaMerkleProofCircuit");

            let mut pw = PartialWitness::new();
            self.gadget.set_witness(&mut pw, left_proof, right_proof)?;
            debug_timer.lap("set_witness");
            let proof = self.circuit_data.prove(pw)?;
            debug_timer.lap("prove");
            let cloned_proof = proof.clone();
            debug_timer.lap("clone_proof");
            self.circuit_data.verify(cloned_proof)?;
            debug_timer.lap("verify");
            Ok(proof)
        }
        pub fn prove_and_check_outputs(
            &self,
            left_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
            right_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        ) -> anyhow::Result<SimpleDualVariableHeightDeltaMerkleProofCircuitPublicInputsResult<C::F>> {
            let proof = self.prove_base(left_proof, right_proof)?;
            let res = SimpleDualVariableHeightDeltaMerkleProofCircuitPublicInputsResult::from_public_inputs(
                &proof.public_inputs,
                self.tree_height,
                self.max_merkle_proof_height,
            );
            res.validate_from_inputs(left_proof, right_proof, self.tree_height, self.max_merkle_proof_height);
            Ok(res)
        }
    }
    fn get_tree_proofs(
        tree_height: usize,
        root_level: u8,
        left_index: u64,
        right_index: u64,
        left_value: QHashOut<GoldilocksField>,
        right_value: QHashOut<GoldilocksField>,
    ) -> (
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        SimpleMemoryMerkleRecorderStore<PoseidonHasher, QHashOut<GoldilocksField>>,
    ) {
        type F = GoldilocksField;
        type Hash = QHashOut<F>;
        type Hasher = PoseidonHasher;

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height as u8);

        for _ in 0..(1000u64.min(1u64<<tree_height)) {
            let index = rand::random::<u64>() % (1u64 << tree_height);
            let value = QHashOut::rand();
            tree.set_leaf_no_proof(index, value);
        }
        let left_proof_mp_start = tree.get_leaf_in_subtree(root_level as u8, tree_height as u8, left_index);
        tree.set_leaf_no_proof(left_index, left_value);
        let left_proof_mp_end = tree.get_leaf_in_subtree(root_level as u8, tree_height as u8, left_index);
        let left_proof = DeltaMerkleProofCore {
            old_root: left_proof_mp_start.root,
            old_value: left_proof_mp_start.value,
            new_root: left_proof_mp_end.root,
            new_value: left_proof_mp_end.value,
            index: left_index,
            siblings: left_proof_mp_start.siblings,
        };
        let right_proof_mp_start = tree.get_leaf_in_subtree(root_level as u8, tree_height as u8, right_index);
        tree.set_leaf_no_proof(right_index, right_value);
        let right_proof_mp_end = tree.get_leaf_in_subtree(root_level as u8, tree_height as u8, right_index);

        let right_proof = DeltaMerkleProofCore {
            old_root: right_proof_mp_start.root,
            old_value: right_proof_mp_start.value,
            new_root: right_proof_mp_end.root,
            new_value: right_proof_mp_end.value,
            index: right_index,
            siblings: right_proof_mp_start.siblings,
        };

        (left_proof, right_proof, tree)
    }

    fn get_tree_proofs_advanced(
        tree_height: usize,
        root_level_left: u8,
        root_level_right: u8,
        leaf_level_left: u8,
        leaf_level_right: u8,
        left_index: u64,
        right_index: u64,
        left_value: QHashOut<GoldilocksField>,
        right_value: QHashOut<GoldilocksField>,
    ) -> (
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        SimpleMemoryMerkleRecorderStore<PoseidonHasher, QHashOut<GoldilocksField>>,
    ) {
        type F = GoldilocksField;
        type Hash = QHashOut<F>;
        type Hasher = PoseidonHasher;

        if leaf_level_left != leaf_level_right {
            panic!("Leaf levels must be equal for both proofs");
        }
        if root_level_left != root_level_right {
            panic!("Root levels must be equal for both proofs");
        }

        

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height as u8);

        /*for _ in 0..(1000u64.min(1u64<<tree_height)) {
            let index = rand::random::<u64>() % (1u64 << tree_height);
            let value = QHashOut::rand();
            tree.set_leaf_no_proof(index, value);
        }*/
        let left_proof_mp_start = tree.get_leaf_in_subtree(root_level_left, leaf_level_left, left_index);
        tree.set_node_value(SimpleMerkleNodeKey::new(leaf_level_left, left_index), left_value);
        tree.rehash_from_node_to_level(SimpleMerkleNodeKey::new(leaf_level_left, left_index), root_level_left);
        let left_proof_mp_end = tree.get_leaf_in_subtree(root_level_left, leaf_level_left, left_index);
        let left_proof = DeltaMerkleProofCore {
            old_root: left_proof_mp_start.root,
            old_value: left_proof_mp_start.value,
            new_root: left_proof_mp_end.root,
            new_value: left_proof_mp_end.value,
            index: left_index,
            siblings: left_proof_mp_start.siblings,
        };
        let right_proof_mp_start = tree.get_leaf_in_subtree(root_level_right, leaf_level_right, right_index);
        println!("left_proof_mp_end.root: {:?}", left_proof_mp_end.root);
        println!("right_proof_mp_start.root: {:?}", right_proof_mp_start.root);
        

        tree.set_node_value(SimpleMerkleNodeKey::new(leaf_level_right, right_index), right_value);
        tree.rehash_from_node_to_level(SimpleMerkleNodeKey::new(leaf_level_right, right_index), root_level_right);
        let right_proof_mp_end = tree.get_leaf_in_subtree(root_level_right, leaf_level_right, right_index);
        let right_proof = DeltaMerkleProofCore {
            old_root: right_proof_mp_start.root,
            old_value: right_proof_mp_start.value,
            new_root: right_proof_mp_end.root,
            new_value: right_proof_mp_end.value,
            index: right_index,
            siblings: right_proof_mp_start.siblings,
        };

        (left_proof, right_proof, tree)
    }


    fn get_tree_proofs_advanced_good(
        tree_height: usize,
        root_level: u8,
        leaf_level: u8,
        left_index: u64,
        right_index: u64,
        left_value: QHashOut<GoldilocksField>,
        right_value: QHashOut<GoldilocksField>,
    ) -> (
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        SimpleMemoryMerkleRecorderStore<PoseidonHasher, QHashOut<GoldilocksField>>,
    ) {
        type F = GoldilocksField;
        type Hash = QHashOut<F>;
        type Hasher = PoseidonHasher;

        assert!(leaf_level> root_level, "Leaf level must be greater than root level");
        assert!(leaf_level <= tree_height as u8, "Leaf level must be less than or equal to tree height");
        let level_difference = leaf_level - root_level;
        let expected_parent_index_left = left_index >> level_difference;
        let expected_parent_index_right = right_index >> level_difference;
        assert_eq!(expected_parent_index_left, expected_parent_index_right, "Expected parent index from left and right proofs do not match");

        

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height as u8);

        /*for _ in 0..(1000u64.min(1u64<<tree_height)) {
            let index = rand::random::<u64>() % (1u64 << tree_height);
            let value = QHashOut::rand();
            tree.set_leaf_no_proof(index, value);
        }*/

        let left_key = SimpleMerkleNodeKey::new(leaf_level, left_index);
        let right_key = SimpleMerkleNodeKey::new(leaf_level, right_index);
        let left_proof_mp_start = tree.get_leaf_in_subtree(root_level, leaf_level, left_index);
        tree.set_node_value(left_key, left_value);
        tree.rehash_from_node_to_level(left_key, root_level);
        let left_proof_mp_end = tree.get_leaf_in_subtree(root_level, leaf_level, left_index);
        let left_proof = DeltaMerkleProofCore {
            old_root: left_proof_mp_start.root,
            old_value: left_proof_mp_start.value,
            new_root: left_proof_mp_end.root,
            new_value: left_proof_mp_end.value,
            index: left_index,
            siblings: left_proof_mp_start.siblings,
        };
        let right_proof_mp_start = tree.get_leaf_in_subtree(root_level, leaf_level, right_index);
        println!("left_proof_mp_end.root: {:?}", left_proof_mp_end.root);
        println!("right_proof_mp_start.root: {:?}", right_proof_mp_start.root);
        

        tree.set_node_value(right_key, right_value);
        tree.rehash_from_node_to_level(right_key, root_level);
        let right_proof_mp_end = tree.get_leaf_in_subtree(root_level, leaf_level, right_index);
        let right_proof = DeltaMerkleProofCore {
            old_root: right_proof_mp_start.root,
            old_value: right_proof_mp_start.value,
            new_root: right_proof_mp_end.root,
            new_value: right_proof_mp_end.value,
            index: right_index,
            siblings: right_proof_mp_start.siblings,
        };

        (left_proof, right_proof, tree)
    }



    #[test]
    fn test_basic_delta_merkle_proof() -> anyhow::Result<()> {
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let tree_height = 32;
        let max_merkle_proof_height = 24;
        let circuit = SimpleDualVariableHeightDeltaMerkleProofCircuit::<C, D>::new(
            max_merkle_proof_height,
            tree_height,
        );

        let (left_proof, right_proof, _tree) = get_tree_proofs(
            tree_height, 
            8,
            5, 
            9,
            QHashOut::rand(), 
            QHashOut::rand()
        );
        
        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;

        let (left_proof, right_proof, _tree) = get_tree_proofs(
            tree_height, 
            8,
            100, 
            99999,
            QHashOut::rand(), 
            QHashOut::rand()
        );
        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;

        let (left_proof, right_proof, _tree) = get_tree_proofs(
            tree_height, 
            10,
            100, 
            101,
            QHashOut::rand(), 
            QHashOut::rand()
        );
        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;

        let (left_proof, right_proof, _tree) = get_tree_proofs(
            tree_height, 
            16,
            0, 
            (1u64 << 16) - 1,
            QHashOut::rand(), 
            QHashOut::rand()
        );

        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;

        let (left_proof, right_proof, _tree) = get_tree_proofs(
            tree_height, 
            9,
            1 << 20, 
            1 << 20 + 1,
            QHashOut::rand(), 
            QHashOut::rand()
        );

        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;


        let (left_proof, right_proof, _tree) = get_tree_proofs(
            tree_height, 
            30,
            0, 
            0,
            QHashOut::rand(), 
            QHashOut::rand()
        );
        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;

        let (left_proof, right_proof, _tree) = get_tree_proofs(
            tree_height, 
            15,
            (1u64 << 16) - 1, 
            (1u64 << 16) - 1,
            QHashOut::rand(), 
            QHashOut::rand()
        );
        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;

        let (left_proof, right_proof, _tree) = get_tree_proofs_advanced(
            tree_height, 
            2,
            2,
            22,
            22,
            123456,
            234567,
            QHashOut::rand(), 
            QHashOut::rand()
        );
        
        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;

        let (left_proof, right_proof, _tree) = get_tree_proofs_advanced_good(
            tree_height, 
            8, // root level (10 - 2 = 8)
            10, // leaf level
            4, // left_index
            5, // right_index
            QHashOut::rand(), 
            QHashOut::rand()
        );
        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;
        println!("Passed test case with left_index 3 and right_index 4");
        // root_level = 8, leaf_level = 10. Height = 2.
        // Index 4. 4 >> 2 = 1.
        let (left_proof, right_proof, _tree) = get_tree_proofs_advanced_good(
            tree_height, 
            8, // root level (10 - 2 = 8)
            10, // leaf level
            4, // left_index
            4, // right_index
            QHashOut::rand(), 
            QHashOut::rand()
        );
        let _res = circuit.prove_and_check_outputs(&left_proof, &right_proof)?;
        Ok(())
    }
}