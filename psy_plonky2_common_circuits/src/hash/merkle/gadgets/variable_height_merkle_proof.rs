use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore, math::core::CircuitBuilderCoreMathHelpers, select::CircuitBuilderSelectHelpers};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, Witness},
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::QHashOut};

#[derive(Debug, Clone)]
pub struct VariableHeightMerkleProofGadget {
    pub root: HashOutTarget,
    pub value: HashOutTarget,
    pub index: Target,
    pub siblings: Vec<HashOutTarget>,
    pub height: Target,

    // computed
    pub sub_tree_root_index: Option<Target>,
    pub sub_tree_root_path_direction: Option<BoolTarget>,
    pub sub_tree_root_direct_child_in_path_value: Option<HashOutTarget>,
    max_height: usize,
    has_witness_height: bool,
}
impl VariableHeightMerkleProofGadget {
    pub fn add_virtual_to_full<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_height: usize,
        input_height_target: Option<Target>,
    ) -> Self {
        let index = builder.add_virtual_target();
        let value = builder.add_virtual_hash();
        let siblings = (0..max_height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();

        let has_witness_height = input_height_target.is_none();
        let height = match input_height_target {
            Some(v) => v,
            None => builder.add_virtual_target(),
        };

        let root = Self::compute_root::<H,F,D>(
            builder, 
            index, 
            value, 
            &siblings, 
            height
        );
        
        Self {
            root,
            value,
            index,
            siblings,
            max_height,
            has_witness_height,
            sub_tree_root_index: None,
            sub_tree_root_direct_child_in_path_value: None,
            height,
            sub_tree_root_path_direction: None,
        }
    }
    pub fn add_virtual_to_full_with_subtree_root_index<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_height: usize,
        input_height_target: Option<Target>,
    ) -> Self {
        let index = builder.add_virtual_target();
        let value = builder.add_virtual_hash();
        let siblings = (0..max_height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();

        let has_witness_height = input_height_target.is_none();
        let height = match input_height_target {
            Some(v) => v,
            None => builder.add_virtual_target(),
        };
        let zero_target = builder.zero();
        builder.ensure_not_equal(height, zero_target);

        let (
            root,
            sub_tree_root_index,
            sub_tree_root_path_direction,
            sub_tree_root_direct_child_in_path_value,
        ) = Self::compute_root_and_subtree_root_index::<H,F,D>(
            builder, 
            index, 
            value, 
            &siblings, 
            height
        );
        
        Self {
            root,
            value,
            index,
            siblings,
            max_height,
            has_witness_height,
            sub_tree_root_index: Some(sub_tree_root_index),
            
            height,
            sub_tree_root_path_direction: Some(sub_tree_root_path_direction),
            sub_tree_root_direct_child_in_path_value: Some(sub_tree_root_direct_child_in_path_value),
        }
    }
    pub fn compute_root<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
        value: HashOutTarget,
        siblings: &[HashOutTarget],
        height_target: Target,
    ) -> HashOutTarget {
        let height = siblings.len();
        builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);

        Self::compute_root_bits::<H, F, D>(builder, &index_bits, value, siblings, height_target)
    }
    pub fn compute_root_and_subtree_root_index<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
        value: HashOutTarget,
        siblings: &[HashOutTarget],
        height_target: Target,
    ) -> (HashOutTarget, Target, BoolTarget, HashOutTarget) {
        let height = siblings.len();
        builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);

        Self::compute_root_bits_and_subtree_root_index_new::<H, F, D>(builder, &index_bits, value, siblings, height_target)
    }
    pub fn compute_root_bits<
        H:AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        index_bits: &[BoolTarget],
        value: HashOutTarget,
        siblings: &[HashOutTarget],
        height: Target,
    ) -> HashOutTarget {
        //let zero = builder.zero();
        let mut state: HashOutTarget = value;
        //debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELEMENTS);

        let one_target = builder.one();
        let mut remaining_levels = height;
        let mut is_remaining_levels_zero = builder.is_zero(remaining_levels);
        //let mut is_remaining_levels_not_zero = builder.not(is_remaining_levels_zero);

        for (&bit, &sibling) in index_bits.iter().zip(siblings) {

            //let left = builder.select_hash(bit, sibling, state);
            //let right = builder.select_hash(bit, state, sibling);
            let proposed_state = builder.two_to_one_swapped::<H>(
                state,
                sibling,
                bit
            );

            state = builder.select_hash(is_remaining_levels_zero, state, proposed_state);

            remaining_levels = builder.sub(remaining_levels, one_target);
            let is_cur_remaining_levels_zero = builder.is_zero(remaining_levels);
            is_remaining_levels_zero = builder.or(
                is_remaining_levels_zero,
                is_cur_remaining_levels_zero,
            );
        }
        state
    }
    pub fn compute_root_bits_and_subtree_root_index_new<
        H:AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        index_bits: &[BoolTarget],
        value: HashOutTarget,
        siblings: &[HashOutTarget],
        height: Target,
    ) -> (HashOutTarget, Target, BoolTarget, HashOutTarget) {
        //let zero = builder.zero();
        let mut state: HashOutTarget = value;
        //debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELEMENTS);

        let one_target = builder.one();
        let mut remaining_levels = height;
        let mut is_remaining_levels_zero = builder.is_zero(remaining_levels);
        //let mut is_remaining_levels_not_zero = builder.not(is_remaining_levels_zero);

        let mut sub_root_index = builder.zero();
        let mut sub_root_bit = is_remaining_levels_zero.target;

        let mut last_hash = value;

        let mut last_bit = builder._false();

        for (&bit, &sibling) in index_bits.iter().zip(siblings) {

            let add_indicator = builder.mul(bit.target, sub_root_bit);
            sub_root_index = builder.add(add_indicator, sub_root_index);
            sub_root_bit = builder.add(sub_root_bit, sub_root_bit);

            last_hash = builder.select_hash(is_remaining_levels_zero, last_hash, state);
            last_bit = BoolTarget::new_unsafe(builder.select(is_remaining_levels_zero, last_bit.target, bit.target));

            let left = builder.select_hash(bit, sibling, state);
            let right = builder.select_hash(bit, state, sibling);
            let proposed_state = builder.hash_two_to_one::<H>(
                left,
                right,
            );

            state = builder.select_hash(is_remaining_levels_zero, state, proposed_state);

            remaining_levels = builder.sub(remaining_levels, one_target);
            let is_cur_remaining_levels_zero = builder.is_zero(remaining_levels);
            let new_is_remaining_levels_zero = builder.or(
                is_remaining_levels_zero,
                is_cur_remaining_levels_zero,
            );
            //let is_not_change_state = builder.is_equal(new_is_remaining_levels_zero.target, is_remaining_levels_zero.target);
            //let is_change_state = builder.not(is_not_change_state);
            let is_change_state = builder.xor_bit(new_is_remaining_levels_zero, is_remaining_levels_zero);
            sub_root_bit = builder.select(is_change_state, one_target, sub_root_bit);

            is_remaining_levels_zero = new_is_remaining_levels_zero;
        }
        (state, sub_root_index, last_bit, last_hash)

    }
    /*
    pub fn compute_root_bits_and_subtree_root_index<
        H:AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        index_bits: &[BoolTarget],
        value: HashOutTarget,
        siblings: &[HashOutTarget],
        height: Target,
    ) -> (HashOutTarget, Target) {
        //let zero = builder.zero();
        let mut state: HashOutTarget = value;
        //debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELEMENTS);

        let one_target = builder.one();
        let two_target = builder.two();
        let mut remaining_levels = height;
        let mut is_remaining_levels_zero = builder.is_zero(remaining_levels);
        let mut sub_root_index_bit_shifted = is_remaining_levels_zero.target;

        let mut sub_tree_root_index = builder.zero();
        //let mut is_remaining_levels_not_zero = builder.not(is_remaining_levels_zero);

        for (&bit, &sibling) in index_bits.iter().zip(siblings) {
            let index_bit_if_remaining_level_zero = builder.mul(bit.target, is_remaining_levels_zero.target);
            sub_tree_root_index = builder.mul_add(sub_tree_root_index, sub_root_index_bit_shifted, index_bit_if_remaining_level_zero);

            let left = builder.select_hash(bit, sibling, state);
            let right = builder.select_hash(bit, state, sibling);
            let proposed_state = builder.hash_two_to_one::<H>(
                left,
                right,
            );

            state = builder.select_hash(is_remaining_levels_zero, state, proposed_state);

            remaining_levels = builder.sub(remaining_levels, one_target);
            let is_cur_remaining_levels_zero = builder.is_zero(remaining_levels);
            
            let new_is_remaining_levels_zero = builder.or(
                is_remaining_levels_zero,
                is_cur_remaining_levels_zero,
            );

            let should_initialize_shift_bit = builder.xor_bit(is_remaining_levels_zero, new_is_remaining_levels_zero);
            sub_root_index_bit_shifted = builder.mul(sub_root_index_bit_shifted, two_target);
            sub_root_index_bit_shifted = builder.select(should_initialize_shift_bit, one_target, sub_root_index_bit_shifted);
            is_remaining_levels_zero = new_is_remaining_levels_zero; 
        }
        (state, sub_tree_root_index)
    }*/
    pub fn set_witness_generic<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        index: F,
        value: QHashOut<F>,
        siblings: &[QHashOut<F>],
    ) -> anyhow::Result<()> {
            witness.set_target(self.index, index)?;
            witness.set_hash_target(self.value, value.0)?;
            if self.has_witness_height {
                witness.set_target(self.height, F::from_canonical_usize(siblings.len()))?;
            }
            for i in 0..siblings.len() {
                witness.set_hash_target(self.siblings[i], siblings[i].0)?;
            }
            for i in siblings.len()..self.max_height {
                witness.set_hash_target(self.siblings[i], HashOut::ZERO)?;
            }
            Ok(())
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        index: F,
        value: QHashOut<F>,
        siblings: &[QHashOut<F>],
    ) -> anyhow::Result<()> {
        self.set_witness_generic(witness, index, value, siblings)
    }
    pub fn set_witness_core_proof_q_generic<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.set_witness_generic(
            witness,
            F::from_noncanonical_u64(input.index),
            input.value,
            &input.siblings,
        )
    }
    pub fn set_witness_core_proof_q<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        input: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.set_witness(
            witness,
            F::from_noncanonical_u64(input.index),
            input.value,
            &input.siblings,
        )
    }
}

#[cfg(test)]
mod tests {
    use parth_core::crypto::hash::merkle_proof::MerkleProofCore;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use parth_core::pgoldilocks::{PoseidonHasher, QHashOut};
    use parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey;
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use rand::rngs::ThreadRng;
    use rand::Rng;

    use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
    use super::VariableHeightMerkleProofGadget;


    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    struct TestVariableHeightMerkleProofCircuit {
        pub variable_merkle_proof_gadget: VariableHeightMerkleProofGadget,
        pub height: Target,
        pub circuit_data: CircuitData<F, C, D>,
    }

    impl TestVariableHeightMerkleProofCircuit {
        pub fn new(max_height: usize) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let height = builder.add_virtual_target();
            let variable_merkle_proof_gadget = VariableHeightMerkleProofGadget::add_virtual_to_full::<PoseidonHash, F, D>(
                &mut builder,
                max_height,
                Some(height),
            );
    
            builder.register_public_inputs(&variable_merkle_proof_gadget.root.elements);
            let circuit_data = builder.build::<C>();
            Self {
                variable_merkle_proof_gadget,
                height,
                circuit_data,
            }
        }
        pub fn prove(&self, height: usize, merkle_proof: &MerkleProofCore<QHashOut<F>>) -> anyhow::Result<ProofWithPublicInputs<F,C,D>> {
            let mut pw = PartialWitness::new();
            pw.set_target(self.height, F::from_canonical_usize(height))?;
            self.variable_merkle_proof_gadget.set_witness_core_proof_q_generic(
                &mut pw,
                merkle_proof,
            )?;
            self.circuit_data.prove(pw)
        }
    }

    struct TestVariableHeightSubRootMerkleProofCircuit {
        pub variable_merkle_proof_gadget_a: VariableHeightMerkleProofGadget,
        pub variable_merkle_proof_gadget_b: VariableHeightMerkleProofGadget,
        pub level_a: Target,
        pub level_b: Target,
        pub sub_root_level: Target,
        pub circuit_data: CircuitData<F, C, D>,
    }

    impl TestVariableHeightSubRootMerkleProofCircuit {
        pub fn new(max_height: usize) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let level_a = builder.add_virtual_target();
            let level_b = builder.add_virtual_target();
            let sub_root_level = builder.add_virtual_target();

            builder.ensure_is_less_than(8, sub_root_level, level_a);
            builder.ensure_is_less_than(8, sub_root_level, level_b);

            let height_a = builder.sub(level_a, sub_root_level);
            let height_b = builder.sub(level_b, sub_root_level);
            
            let variable_merkle_proof_gadget_a = VariableHeightMerkleProofGadget::add_virtual_to_full_with_subtree_root_index::<PoseidonHash, F, D>(
                &mut builder,
                max_height,
                Some(height_a),
            );
            
            let variable_merkle_proof_gadget_b = VariableHeightMerkleProofGadget::add_virtual_to_full_with_subtree_root_index::<PoseidonHash, F, D>(
                &mut builder,
                max_height,
                Some(height_b),
            );

            builder.connect(
                variable_merkle_proof_gadget_a.sub_tree_root_index.unwrap(),
                variable_merkle_proof_gadget_b.sub_tree_root_index.unwrap(),
            );

            builder.connect_hashes(
                variable_merkle_proof_gadget_a.root,
                variable_merkle_proof_gadget_b.root,
            );
    
            builder.register_public_inputs(&vec![
                vec![
                    sub_root_level,
                    variable_merkle_proof_gadget_a.sub_tree_root_index.unwrap()
                    ],
                variable_merkle_proof_gadget_a.root.elements.to_vec()
            ].concat());
            let circuit_data = builder.build::<C>();
            Self {
                variable_merkle_proof_gadget_a,
                variable_merkle_proof_gadget_b,
                level_a,
                level_b,
                sub_root_level,
                circuit_data,
            }
        }
        pub fn prove(
            &self,
            sub_root_level: u8,
            merkle_proof_a: &MerkleProofCore<QHashOut<F>>,
            merkle_proof_b: &MerkleProofCore<QHashOut<F>>,
        ) -> anyhow::Result<ProofWithPublicInputs<F,C,D>> {
            let level_a = (merkle_proof_a.siblings.len() as u8 +sub_root_level) as u8;
            let level_b = (merkle_proof_b.siblings.len() as u8 +sub_root_level) as u8;

            let mut pw = PartialWitness::new();
            pw.set_target(self.sub_root_level, F::from_canonical_u8(sub_root_level))?;
            pw.set_target(self.level_a, F::from_canonical_u8(level_a))?;
            pw.set_target(self.level_b, F::from_canonical_u8(level_b))?;
            
            self.variable_merkle_proof_gadget_a.set_witness_core_proof_q_generic(
                &mut pw,
                merkle_proof_a,
            )?;
            self.variable_merkle_proof_gadget_b.set_witness_core_proof_q_generic(
                &mut pw,
                merkle_proof_b,
            )?;
            self.circuit_data.prove(pw)
        }
    }

    fn rand_non_root_key(rng: &mut ThreadRng, height: usize) -> SimpleMerkleNodeKey {
        let node_level = (rng.gen_range(0..height)+1) as u64;
        let node_index_mask = (1u64<<node_level)-1u64;
        let node_index = rng.gen::<u64>()&node_index_mask;
        SimpleMerkleNodeKey{
            level: node_level as u8,
            index: node_index,
        }
    }
    pub fn generate_random_sub_tree_merkle_proofs_at_height(height: usize, rand_leaf_count: usize) -> (SimpleMerkleNodeKey, MerkleProofCore<QHashOut<F>>, SimpleMerkleNodeKey, MerkleProofCore<QHashOut<F>>) {
        let max_leaf_index_mask = (1u64<<(height as u64))-1u64;
        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(height as u8);
        // add some random leaves
        for _ in 0..rand_leaf_count {
            let rand_index = QHashOut::<F>::rand().0.elements[0].to_canonical_u64()&max_leaf_index_mask;
            tree.set_leaf(rand_index, QHashOut::rand());
        }
        
        let (leaf_key_a, leaf_key_b) = if height == 1 {
            (
                SimpleMerkleNodeKey::new(1, 0),
                SimpleMerkleNodeKey::new(1, 1)
            )
        }else{    
            let mut rng = rand::thread_rng();
            let leaf_key_a = rand_non_root_key(&mut rng, height);
            let mut leaf_key_b = rand_non_root_key(&mut rng, height);
            let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);
            if nearest_common_ancestor.level == 0 { 
                leaf_key_b = rand_non_root_key(&mut rng, height);
            }
            let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);
            if nearest_common_ancestor.level == 0 { 
                leaf_key_b = rand_non_root_key(&mut rng, height);
            }

            while leaf_key_a.eq(&leaf_key_b) || (leaf_key_a.level < leaf_key_b.level && leaf_key_b.parent_at_level(leaf_key_a.level).eq(&leaf_key_a)) ||(leaf_key_b.level < leaf_key_a.level && leaf_key_a.parent_at_level(leaf_key_b.level).eq(&leaf_key_b)) {
                leaf_key_b = rand_non_root_key(&mut rng, height);
            }
            (leaf_key_a, leaf_key_b)
        };

        let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);

        let proof_a = tree.get_subtree_merkle_proof(nearest_common_ancestor.level, leaf_key_a);
        let proof_b = tree.get_subtree_merkle_proof(nearest_common_ancestor.level, leaf_key_b);
        

        (leaf_key_a, proof_a, leaf_key_b, proof_b)
    }
    #[test]
    fn test_variable_merkle_proof_sub_tree_circuit2() {

        let circuit = TestVariableHeightSubRootMerkleProofCircuit::new(32);
        let height = 32;
        let rand_leaf_count = 500;
        let max_leaf_index_mask = (1u64<<(height as u64))-1u64;
        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(height as u8);
        // add some random leaves
        for _ in 0..rand_leaf_count {
            let rand_index = QHashOut::<F>::rand().0.elements[0].to_canonical_u64()&max_leaf_index_mask;
            tree.set_leaf(rand_index, QHashOut::rand());
        }
        

        let leaf_key_a = SimpleMerkleNodeKey::new(3, 5);
        let leaf_key_b = SimpleMerkleNodeKey::new(2,3);
        
        let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);
        println!("nearest_common_ancestor: {:?}",nearest_common_ancestor);

        let proof_a = tree.get_subtree_merkle_proof(nearest_common_ancestor.level, leaf_key_a);
        let proof_b = tree.get_subtree_merkle_proof(nearest_common_ancestor.level, leaf_key_b);
        assert!(proof_a.verify::<PoseidonHasher>(), "proof_a valid");
        assert!(proof_b.verify::<PoseidonHasher>(), "proof_b valid");
        


        println!("proof_a: {}", serde_json::to_string_pretty(&proof_a).unwrap());
        println!("proof_a: {:?}", &proof_a);
        
        println!("proof_b: {}", serde_json::to_string_pretty(&proof_b).unwrap());
        println!("proof_b: {:?}", &proof_b);
        
        
        let proof = circuit.prove(
            nearest_common_ancestor.level,
            &proof_a,
            &proof_b,
        ).unwrap();

        println!("pubs: {:?}",&proof.public_inputs);


    }
    #[test]
    fn test_variable_merkle_proof_sub_tree_circuit() {
        let circuit = TestVariableHeightSubRootMerkleProofCircuit::new(32);




        let merkle_proofs = (1..32).map(|level| {
            generate_random_sub_tree_merkle_proofs_at_height(level, level*100)
        }).collect::<Vec<_>>();

        for  (leaf_key_a, proof_a, leaf_key_b, proof_b) in merkle_proofs.iter() {
            println!("leaf_key_a: {:?}",leaf_key_a);
            println!("leaf_key_b: {:?}",leaf_key_b);
            let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);
            println!("nearest_common_ancestor: {:?}",nearest_common_ancestor);
            let proof = circuit.prove(
                nearest_common_ancestor.level,
                proof_a,
                proof_b,
            ).unwrap();
            let proof_nearest_common_ancestor_level = proof.public_inputs[0].to_canonical_u64() as u8;
            let proof_nearest_common_ancestor_index = proof.public_inputs[1].to_canonical_u64();
            
            assert_eq!(proof_nearest_common_ancestor_level, nearest_common_ancestor.level, "nearest_common_ancestor_level should match expected");
            assert_eq!(proof_nearest_common_ancestor_index, nearest_common_ancestor.index, "nearest_common_ancestor_level should match expected");
            circuit.circuit_data.verify(proof).unwrap();
        }
    }


    pub fn generate_random_merkle_proofs_at_height(height: usize, count: usize) -> Vec<MerkleProofCore<QHashOut<F>>> {
        let max_leaf_index_mask = (1u64<<(height as u64))-1u64;
        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(height as u8);
        // add some random leaves
        for _ in 0..(count*2) {
            let rand_index = QHashOut::<F>::rand().0.elements[0].to_canonical_u64()&max_leaf_index_mask;
            tree.set_leaf(rand_index, QHashOut::rand());
        }
        (0..count).map(|_|{
            let rand_index = QHashOut::<F>::rand().0.elements[0].to_canonical_u64()&max_leaf_index_mask;
            tree.set_leaf(rand_index, QHashOut::rand());
            tree.get_leaf(rand_index)
        }).collect()
    }

    #[test]
    fn test_variable_merkle_proof_circuit() {
        let circuit = TestVariableHeightMerkleProofCircuit::new(32);
        let merkle_proofs = (1..32).map(|level| {
            generate_random_merkle_proofs_at_height(level, 2)
        }).flatten().collect::<Vec<_>>();

        for mp in merkle_proofs.iter() {
            let proof = circuit.prove(mp.siblings.len(), mp).unwrap();
            assert_eq!(proof.public_inputs, mp.root.0.elements.to_vec(), "roots should match proof");
            circuit.circuit_data.verify(proof).unwrap();
        }
    }

    #[test]
    #[should_panic]
    fn test_variable_merkle_proof_circuit_incorrect_height() {
        let circuit = TestVariableHeightMerkleProofCircuit::new(32);
        let merkle_proofs = (1..32).map(|level| {
            generate_random_merkle_proofs_at_height(level, 2)
        }).flatten().collect::<Vec<_>>();

        for mp in merkle_proofs.iter() {
            let proof = circuit.prove(mp.siblings.len()+1, mp).unwrap();
            assert_eq!(proof.public_inputs, mp.root.0.elements.to_vec(), "roots should match proof");
            circuit.circuit_data.verify(proof).unwrap();
        }
    }
}
