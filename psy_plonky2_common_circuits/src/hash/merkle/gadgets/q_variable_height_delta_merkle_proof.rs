use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut, utils::math::log2_ceil};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_plonky2_basic_helpers::builder::{hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers};

use crate::hash::merkle::gadgets::{
    delta_merkle_proof::{DeltaMerkleProofGadget, DeltaMerkleProofGadgetOptionFlags},
    variable_height_delta_merkle_proof_index::VariableHeightMerkleProofIndexBitInfoGadget,
};

#[derive(Debug, Clone)]
pub struct QVariableHeightDeltaMerkleProofGadget {
    pub bit_info: VariableHeightMerkleProofIndexBitInfoGadget,
    pub height: Target,
    pub delta_merkle_proof: DeltaMerkleProofGadget,

    // computed
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
    pub parent_index: Target,
    pub index_bits: Vec<BoolTarget>,
    pub delta_merkle_proof_witness_flags: DeltaMerkleProofGadgetOptionFlags,
    pub has_known_height: bool,
    tree_height: usize,
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
impl QVariableHeightDeltaMerkleProofGadget {
    pub fn get_parent_level<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        child_level: Target,
    ) -> Target {
        // parent_level = child_level - height, we use the convention root is on level 0
        let parent_level = builder.sub(child_level, self.height);
        // range check to ensure parent level doesn't undeflow
        builder.range_check(parent_level, log2_ceil(self.tree_height));
        parent_level
    }
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_merkle_proof_height: usize,
        tree_height: usize,
        known_height_target: Option<Target>,

        known_old_value: Option<HashOutTarget>,
        known_new_value: Option<HashOutTarget>,
        known_index: Option<Target>,
    ) -> Self {
        let index = known_index.unwrap_or_else(|| builder.add_virtual_target());
        let old_value = known_old_value.unwrap_or_else(|| builder.add_virtual_hash());
        let new_value = known_new_value.unwrap_or_else(|| builder.add_virtual_hash());
        let siblings = (0..max_merkle_proof_height).map(|_| builder.add_virtual_hash()).collect::<Vec<_>>();

        let delta_merkle_proof_witness_flags = {
            let mut flags = DeltaMerkleProofGadgetOptionFlags::empty();
            if known_old_value.is_some() {
                flags |= DeltaMerkleProofGadgetOptionFlags::old_value;
            }
            if known_new_value.is_some() {
                flags |= DeltaMerkleProofGadgetOptionFlags::new_value;
            }
            if known_index.is_some() {
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

        let index_bits = builder.split_le(index, tree_height);

        let bit_info = VariableHeightMerkleProofIndexBitInfoGadget::add_virtual_to_single::<H, F, D>(
            builder,
            max_merkle_proof_height,
            tree_height,
            height,
            &index_bits,
        );

        let old_root = compute_merkle_root::<H, F, D>(builder, old_value, &siblings, &index_bits, &bit_info.is_bit_not_within_height);
        let new_root = compute_merkle_root::<H, F, D>(builder, new_value, &siblings, &index_bits, &bit_info.is_bit_not_within_height);

        let delta_merkle_proof = DeltaMerkleProofGadget {
            old_value: old_value,
            old_root: old_root,
            new_value: new_value,
            new_root: new_root,
            index: index,
            siblings: siblings,
            option_flags: delta_merkle_proof_witness_flags,
        };

        Self {
            parent_index: bit_info.parent_index,
            bit_info,
            height,
            delta_merkle_proof,
            old_root,
            new_root,
            index_bits: index_bits,
            delta_merkle_proof_witness_flags,
            has_known_height,
            tree_height,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.delta_merkle_proof.set_witness_pad_siblings(
            witness,
            F::from_noncanonical_u64(delta_merkle_proof.index),
            delta_merkle_proof.old_value,
            delta_merkle_proof.new_value,
            &delta_merkle_proof.siblings,
        )?;

        if !self.has_known_height {
            witness.set_target(self.height, F::from_canonical_usize(delta_merkle_proof.siblings.len()))?;
        }

        Ok(())
    }
    pub fn set_witness_siblings<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        siblings: &[QHashOut<F>],
    ) -> anyhow::Result<()> {
        if self.delta_merkle_proof.option_flags != DeltaMerkleProofGadgetOptionFlags::siblings {
            return Err(anyhow::anyhow!("DeltaMerkleProofGadget was not created with only siblings as unknown"));
        }
        for (i, s) in self.delta_merkle_proof.siblings.iter().enumerate() {
            if i < siblings.len() {
                witness.set_hash_target(
                    *s,
                    siblings[i].0,
                )?;
            } else {
                witness.set_hash_target(
                    *s,
                    HashOut::ZERO
                )?;
            }
        }
        if !self.has_known_height {
            witness.set_target(self.height, F::from_canonical_usize(siblings.len()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cf_utils::timer::DebugTimer;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{data::hash::merkle_node_key::SimpleMerkleNodeKey, pgoldilocks::PoseidonHasher};
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
        },
    };
    use psy_plonky2_basic_helpers::builder::pad_circuit::PsyCircuitBuilderGateCountPrinter;

    use super::*;

    struct SimpleSingleVariableHeightDeltaMerkleProofCircuitPublicInputsResult<F: RichField> {
        pub parent_index: F,
        pub height: F,
        pub old_root: QHashOut<F>,
        pub new_root: QHashOut<F>,
        pub is_bit_not_within_height: Vec<bool>,
    }
    fn felts_to_bool_vec<F: RichField>(felts: &[F]) -> Vec<bool> {
        felts
            .iter()
            .map(|&f| {
                if f == F::ZERO {
                    false
                } else if f == F::ONE {
                    true
                } else {
                    panic!("Felt is not boolean");
                }
            })
            .collect()
    }
    impl<F: RichField> SimpleSingleVariableHeightDeltaMerkleProofCircuitPublicInputsResult<F> {
        pub fn from_public_inputs(public_inputs: &[F], tree_height: usize, max_merkle_proof_height: usize) -> Self {
            println!("public_inputs len: {}", public_inputs.len());
            println!("public_inputs: {:?}", public_inputs);
            let parent_index = public_inputs[0];
            let height = public_inputs[1];
            let old_root = QHashOut::from_felt_slice(&public_inputs[2..6]);
            let new_root = QHashOut::from_felt_slice(&public_inputs[6..10]);
            let is_bit_not_within_height = felts_to_bool_vec(&public_inputs[10..10 + tree_height]);
            println!(
                "is_bit_not_within_height: {:?}",
                is_bit_not_within_height.iter().map(|x| if *x { 1 } else { 0 }).collect::<Vec<_>>()
            );
            println!("height: {}", height);
            println!("max_merkle_proof_height: {}", max_merkle_proof_height);
            Self {
                parent_index,
                height,
                old_root,
                new_root,
                is_bit_not_within_height,
            }
        }
        pub fn validate_from_inputs(
            &self,
            delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
            _tree_height: usize,
            _max_merkle_proof_height: usize,
        ) {
            assert_eq!(
                self.old_root, delta_merkle_proof.old_root,
                "Old root does not match delta_merkle_proof old root"
            );
            assert_eq!(
                self.new_root, delta_merkle_proof.new_root,
                "New root does not match delta_merkle_proof new root"
            );

            assert_eq!(
                self.height,
                F::from_noncanonical_u64(delta_merkle_proof.siblings.len() as u64),
                "Height does not match delta_merkle_proof height"
            );
            let expected_parent_index = delta_merkle_proof.index >> (delta_merkle_proof.siblings.len());
            assert_eq!(
                F::from_noncanonical_u64(expected_parent_index),
                self.parent_index,
                "Parent index does not match expected parent index"
            );

            for i in 0..self.is_bit_not_within_height.len() {
                if i >= delta_merkle_proof.siblings.len() {
                    // at tree height, ensure bits are equal
                    assert_eq!(
                        self.is_bit_not_within_height[i], true,
                        "is_bit_not_within_height does not match at index {}",
                        i
                    );
                } else {
                    assert_eq!(
                        self.is_bit_not_within_height[i], false,
                        "is_bit_not_within_height does not match at index {}",
                        i
                    );
                }
            }
        }
    }

    struct SimpleSingleVariableHeightDeltaMerkleProofCircuit<C: GenericConfig<D>, const D: usize>
    where
        C::Hasher: AlgebraicHasher<C::F>,
    {
        pub gadget: QVariableHeightDeltaMerkleProofGadget,
        pub circuit_data: CircuitData<C::F, C, D>,
        pub tree_height: usize,
        pub max_merkle_proof_height: usize,
    }
    impl<C: GenericConfig<D>, const D: usize> SimpleSingleVariableHeightDeltaMerkleProofCircuit<C, D>
    where
        C::Hasher: AlgebraicHasher<C::F>,
    {
        pub fn new(max_merkle_proof_height: usize, tree_height: usize) -> Self {
            let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());

            let gadget = QVariableHeightDeltaMerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                max_merkle_proof_height,
                tree_height,
                None,
                None,
                None,
                None,
            );
            builder.print_gate_counts_with_message("after QVariableHeightDeltaMerkleProofGadget");
            let public_inputs = [
                vec![gadget.parent_index, gadget.height],
                gadget.old_root.elements.to_vec(),
                gadget.new_root.elements.to_vec(),
                gadget.bit_info.is_bit_not_within_height.iter().map(|b| b.target).collect::<Vec<_>>(),
            ]
            .concat();
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

        pub fn prove_base(&self, delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<C::F>>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
            let mut debug_timer = DebugTimer::new("SimpleSingleVariableHeightDeltaMerkleProofCircuit");

            let mut pw = PartialWitness::new();
            self.gadget.set_witness(&mut pw, delta_merkle_proof)?;
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
            delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        ) -> anyhow::Result<SimpleSingleVariableHeightDeltaMerkleProofCircuitPublicInputsResult<C::F>> {
            let proof = self.prove_base(delta_merkle_proof)?;
            let res = SimpleSingleVariableHeightDeltaMerkleProofCircuitPublicInputsResult::from_public_inputs(
                &proof.public_inputs,
                self.tree_height,
                self.max_merkle_proof_height,
            );
            res.validate_from_inputs(delta_merkle_proof, self.tree_height, self.max_merkle_proof_height);
            Ok(res)
        }
    }
    fn get_tree_proofs(
        tree_height: usize,
        root_level: u8,
        index: u64,
        value: QHashOut<GoldilocksField>,
    ) -> (
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        SimpleMemoryMerkleRecorderStore<PoseidonHasher, QHashOut<GoldilocksField>>,
    ) {
        type F = GoldilocksField;
        type Hash = QHashOut<F>;
        type Hasher = PoseidonHasher;

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height as u8);

        for _ in 0..(1000u64.min(1u64 << tree_height)) {
            let index = rand::random::<u64>() % (1u64 << tree_height);
            let value = QHashOut::rand();
            tree.set_leaf_no_proof(index, value);
        }
        let proof_mp_start = tree.get_leaf_in_subtree(root_level as u8, tree_height as u8, index);
        tree.set_leaf_no_proof(index, value);
        let proof_mp_end = tree.get_leaf_in_subtree(root_level as u8, tree_height as u8, index);
        let delta_merkle_proof = DeltaMerkleProofCore {
            old_root: proof_mp_start.root,
            old_value: proof_mp_start.value,
            new_root: proof_mp_end.root,
            new_value: proof_mp_end.value,
            index: index,
            siblings: proof_mp_start.siblings,
        };

        (delta_merkle_proof, tree)
    }

    fn get_tree_proofs_advanced(
        tree_height: usize,
        root_level: u8,
        leaf_level: u8,
        index: u64,
        value: QHashOut<GoldilocksField>,
    ) -> (
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        SimpleMemoryMerkleRecorderStore<PoseidonHasher, QHashOut<GoldilocksField>>,
    ) {
        type F = GoldilocksField;
        type Hash = QHashOut<F>;
        type Hasher = PoseidonHasher;

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height as u8);

        /*for _ in 0..(1000u64.min(1u64<<tree_height)) {
            let index = rand::random::<u64>() % (1u64 << tree_height);
            let value = QHashOut::rand();
            tree.set_leaf_no_proof(index, value);
        }*/
        let proof_mp_start = tree.get_leaf_in_subtree(root_level, leaf_level, index);
        tree.set_node_value(SimpleMerkleNodeKey::new(leaf_level, index), value);
        tree.rehash_from_node_to_level(SimpleMerkleNodeKey::new(leaf_level, index), root_level);
        let proof_mp_end = tree.get_leaf_in_subtree(root_level, leaf_level, index);
        let proof = DeltaMerkleProofCore {
            old_root: proof_mp_start.root,
            old_value: proof_mp_start.value,
            new_root: proof_mp_end.root,
            new_value: proof_mp_end.value,
            index: index,
            siblings: proof_mp_start.siblings,
        };
        (proof, tree)
    }

    fn get_tree_proofs_advanced_good(
        tree_height: usize,
        root_level: u8,
        leaf_level: u8,
        index: u64,
        value: QHashOut<GoldilocksField>,
    ) -> (
        DeltaMerkleProofCore<QHashOut<GoldilocksField>>,
        SimpleMemoryMerkleRecorderStore<PoseidonHasher, QHashOut<GoldilocksField>>,
    ) {
        type F = GoldilocksField;
        type Hash = QHashOut<F>;
        type Hasher = PoseidonHasher;

        assert!(leaf_level > root_level, "Leaf level must be greater than root level");
        assert!(leaf_level <= tree_height as u8, "Leaf level must be less than or equal to tree height");

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height as u8);

        for _ in 0..(1000u64.min(1u64 << tree_height)) {
            let index = rand::random::<u64>() % (1u64 << tree_height);
            let value = QHashOut::rand();
            tree.set_leaf_no_proof(index, value);
        }
        let key = SimpleMerkleNodeKey::new(leaf_level, index);
        let proof_mp_start = tree.get_leaf_in_subtree(root_level, leaf_level, index);
        tree.set_node_value(key, value);
        tree.rehash_from_node_to_level(key, root_level);
        let proof_mp_end = tree.get_leaf_in_subtree(root_level, leaf_level, index);
        let proof = DeltaMerkleProofCore {
            old_root: proof_mp_start.root,
            old_value: proof_mp_start.value,
            new_root: proof_mp_end.root,
            new_value: proof_mp_end.value,
            index: index,
            siblings: proof_mp_start.siblings,
        };
        (proof, tree)
    }

    #[test]
    fn test_basic_delta_merkle_proof() -> anyhow::Result<()> {
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let tree_height = 32;
        let max_merkle_proof_height = 24;
        let circuit = SimpleSingleVariableHeightDeltaMerkleProofCircuit::<C, D>::new(max_merkle_proof_height, tree_height);

        let (proof, _tree) = get_tree_proofs(tree_height, 8, 9, QHashOut::rand());

        let _res = circuit.prove_and_check_outputs(&proof)?;

        let (proof, _tree) = get_tree_proofs(tree_height, 8, 99999, QHashOut::rand());
        let _res = circuit.prove_and_check_outputs(&proof)?;

        let (proof, _tree) = get_tree_proofs(tree_height, 10, 101, QHashOut::rand());
        let _res = circuit.prove_and_check_outputs(&proof)?;

        let (proof, _tree) = get_tree_proofs(tree_height, 16, (1u64 << 16) - 1, QHashOut::rand());

        let _res = circuit.prove_and_check_outputs(&proof)?;

        let (proof, _tree) = get_tree_proofs(tree_height, 9, 1 << 20, QHashOut::rand());

        let _res = circuit.prove_and_check_outputs(&proof)?;

        let (proof, _tree) = get_tree_proofs(tree_height, 30, 0, QHashOut::rand());
        let _res = circuit.prove_and_check_outputs(&proof)?;

        let (proof, _tree) = get_tree_proofs(tree_height, 15, (1u64 << 16) - 1, QHashOut::rand());
        let _res = circuit.prove_and_check_outputs(&proof)?;

        let (proof, _tree) = get_tree_proofs_advanced(tree_height, 2, 22, 234567, QHashOut::rand());

        let _res = circuit.prove_and_check_outputs(&proof)?;

        let (proof, _tree) = get_tree_proofs_advanced_good(
            tree_height,
            8,  // root level (10 - 2 = 8)
            10, // leaf level
            4,  // index
            QHashOut::rand(),
        );
        let _res = circuit.prove_and_check_outputs(&proof)?;
        println!("Passed test case with index 3 and right_index 4");
        // root_level = 8, leaf_level = 10. Height = 2.
        // Index 4. 4 >> 2 = 1.
        let (proof, _tree) = get_tree_proofs_advanced_good(
            tree_height,
            8,  // root level (10 - 2 = 8)
            10, // leaf level
            4,  // index
            QHashOut::rand(),
        );
        let _res = circuit.prove_and_check_outputs(&proof)?;
        Ok(())
    }
}
