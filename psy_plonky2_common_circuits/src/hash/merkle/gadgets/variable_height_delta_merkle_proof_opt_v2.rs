use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore, math::core::CircuitBuilderCoreMathHelpers, select::CircuitBuilderSelectHelpers};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut};

pub struct BitsHelper {
    pub index_bits: Vec<BoolTarget>,
    pub low_bits_mask: Vec<BoolTarget>,
    pub high_bits_mask: Vec<BoolTarget>,
}


#[derive(Debug, Clone)]
pub struct VariableHeightBitInfo {
    pub index_bits: Vec<BoolTarget>,
    pub is_bit_not_within_height: Vec<BoolTarget>,
    pub is_first_bit_outside_height: Vec<BoolTarget>,

}

impl VariableHeightBitInfo {
    pub fn is_right_child<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        let mut base = builder.zero();

        for (a,b) in  self.index_bits.iter().zip(self.is_first_bit_outside_height.iter()) {
            let combo = builder.and(*a, *b);
            base = builder.add(combo.target, base);
        }
        BoolTarget::new_unsafe(base)

    }
    pub fn get_root_parent_index<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {

        let mut sub_root_bit = builder.zero();
        let mut sub_root_index = builder.zero();
        let one = builder.one();
        for i in 1..self.index_bits.len() {
            let is_change = self.is_first_bit_outside_height[i-1];
            sub_root_bit = builder.select(is_change, one, sub_root_bit);

            let add_indicator = builder.mul(self.index_bits[i].target, sub_root_bit);
            sub_root_index = builder.add(add_indicator, sub_root_index);


            sub_root_bit = builder.add(sub_root_bit, sub_root_bit);

        }

        sub_root_index
    }

}

#[derive(Debug, Clone)]
pub struct VariableHeightDeltaMerkleProofOptV2Gadget {
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
    pub old_value: HashOutTarget,
    pub new_value: HashOutTarget,
    pub index: Target,
    pub siblings: Vec<HashOutTarget>,
    pub height: Target,

    // computed
    pub bit_info: VariableHeightBitInfo,
    pub max_height: usize,
    pub has_witness_height: bool,
}
impl VariableHeightDeltaMerkleProofOptV2Gadget {
    pub fn add_virtual_to_full<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_height: usize,
        input_height_target: Option<Target>,
    ) -> Self {
        Self::add_virtual_to_full_with_subtree_root_index::<H,F,D>(builder,max_height,input_height_target)
    }
    pub fn add_virtual_to_full_with_subtree_root_index<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_height: usize,
        input_height_target: Option<Target>,
    ) -> Self {
        let index = builder.add_virtual_target();
        let old_value = builder.add_virtual_hash();
        let new_value = builder.add_virtual_hash();
        let siblings = (0..max_height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();

        let has_witness_height = input_height_target.is_none();
        let height = match input_height_target {
            Some(v) => v,
            None => builder.add_virtual_target(),
        };
        /*
        let zero_target = builder.zero();
        builder.ensure_not_equal(height, zero_target);*/

        let (
            old_root,
            new_root,
            bit_info,
        ) = Self::compute_roots::<H,F,D>(
            builder, 
            index,
            old_value, 
            new_value,
            &siblings, 
            height
        );
        
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            max_height,
            has_witness_height,
            height,
            bit_info,
        }
    }
    pub fn add_virtual_to_full_with_subtree_root_index_known<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_height: usize,
        input_height_target: Option<Target>,
        index: Target,
        old_value: HashOutTarget,
        new_value: HashOutTarget,
    ) -> Self {
        let siblings = (0..max_height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();

        let has_witness_height = input_height_target.is_none();
        let height = match input_height_target {
            Some(v) => v,
            None => builder.add_virtual_target(),
        };
        /*
        let zero_target = builder.zero();
        builder.ensure_not_equal(height, zero_target);*/

        let (
            old_root,
            new_root,
            bit_info,
        ) = Self::compute_roots::<H,F,D>(
            builder, 
            index,
            old_value, 
            new_value,
            &siblings, 
            height
        );
        
        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
            max_height,
            has_witness_height,
            height,
            bit_info,
        }
    }
    pub fn compute_roots<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
        old_value: HashOutTarget,
        new_value: HashOutTarget,
        siblings: &[HashOutTarget],
        height_target: Target,
    ) -> (HashOutTarget, HashOutTarget, VariableHeightBitInfo) {
        let height = siblings.len();
        builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);

        Self::compute_root_bits::<H, F, D>(builder, index_bits, old_value, new_value, siblings, height_target)
    }
    pub fn compute_root_bits<
        H:AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        index_bits: Vec<BoolTarget>,
        old_value: HashOutTarget,
        new_value: HashOutTarget,
        siblings: &[HashOutTarget],
        height: Target,
    ) -> (HashOutTarget, HashOutTarget, VariableHeightBitInfo) {
        //let zero = builder.zero();
        let mut old_state: HashOutTarget = old_value;
        let mut new_state: HashOutTarget = new_value;
        //debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELEMENTS);

        let one_target = builder.one();
        let mut remaining_levels = height;
        let mut is_remaining_levels_zero = builder.is_zero(remaining_levels);
        //let mut is_remaining_levels_not_zero = builder.not(is_remaining_levels_zero);

        //let zero_target = builder.zero();

        let mut is_bit_not_within_height = Vec::with_capacity(index_bits.len());
        //let mut is_last_bit_within_height = Vec::with_capacity(index_bits.len());
        let mut is_first_bit_outside_height = Vec::with_capacity(index_bits.len());
        is_first_bit_outside_height.push(is_remaining_levels_zero);
        for (ind, (&bit, &sibling)) in index_bits.iter().zip(siblings).enumerate() {
            is_bit_not_within_height.push(is_remaining_levels_zero);


            // ensure the index does not have any unused bits
            /*let is_remaining_levels_zero_and_non_zero_bit = builder.and(is_remaining_levels_zero, bit);
            builder.connect(
                is_remaining_levels_zero_and_non_zero_bit.target,
                zero_target
            );*/



            let old_proposed_state = builder.two_to_one_swapped::<H>(
                old_state,
                sibling,
                bit,
            );

            old_state = builder.select_hash(is_remaining_levels_zero, old_state, old_proposed_state);

            let new_proposed_state = builder.two_to_one_swapped::<H>(
                new_state,
                sibling,
                bit,
            );

            new_state = builder.select_hash(is_remaining_levels_zero, new_state, new_proposed_state);

            remaining_levels = builder.sub(remaining_levels, one_target);
            let is_cur_remaining_levels_zero = builder.is_zero(remaining_levels);
            let new_is_remaining_levels_zero = builder.or(
                is_remaining_levels_zero,
                is_cur_remaining_levels_zero,
            );
            //let is_not_change_state = builder.is_equal(new_is_remaining_levels_zero.target, is_remaining_levels_zero.target);
            //let is_change_state = builder.not(is_not_change_state);
            if ind < (index_bits.len()-1) {
                let is_change_state = builder.xor_bit(new_is_remaining_levels_zero, is_remaining_levels_zero);
                is_first_bit_outside_height.push(is_change_state);
            }

            is_remaining_levels_zero = new_is_remaining_levels_zero;
        }

        (old_state, new_state, VariableHeightBitInfo{
            index_bits,
            is_bit_not_within_height,
            is_first_bit_outside_height,
        })
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        index: F,
        old_value: QHashOut<F>,
        new_value: QHashOut<F>,
        siblings: &[QHashOut<F>],
    )  -> anyhow::Result<()> {
            witness.set_target(self.index, index)?;
            witness.set_hash_target(self.old_value, old_value.0)?;
            witness.set_hash_target(self.new_value, new_value.0)?;
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
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &DeltaMerkleProofCore<QHashOut<F>>,
    )  -> anyhow::Result<()> {
        self.set_witness_params(
            witness,
            F::from_noncanonical_u64(input.index),
            input.old_value,
            input.new_value,
            &input.siblings,
        )
    }
}

#[cfg(test)]
mod tests {
    use parth_core::crypto::hash::merkle_proof::DeltaMerkleProofCore;
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
    use psy_plonky2_basic_helpers::builder::hash::core::CircuitBuilderHashCore;

    use super::VariableHeightDeltaMerkleProofOptV2Gadget;


    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    struct TestVariableHeightDeltaMerkleProofCircuit {
        pub variable_delta_merkle_proof_gadget: VariableHeightDeltaMerkleProofOptV2Gadget,
        pub height: Target,
        pub circuit_data: CircuitData<F, C, D>,
    }

    impl TestVariableHeightDeltaMerkleProofCircuit {
        pub fn new(max_height: usize) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let height = builder.add_virtual_target();
            let variable_delta_merkle_proof_gadget = VariableHeightDeltaMerkleProofOptV2Gadget::add_virtual_to_full::<PoseidonHash, F, D>(
                &mut builder,
                max_height,
                Some(height),
            );
    
            builder.register_public_inputs(&variable_delta_merkle_proof_gadget.old_root.elements);
            builder.register_public_inputs(&variable_delta_merkle_proof_gadget.new_root.elements);
            let circuit_data = builder.build::<C>();
            Self {
                variable_delta_merkle_proof_gadget,
                height,
                circuit_data,
            }
        }
        pub fn prove(&self, height: usize, merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>) -> anyhow::Result<ProofWithPublicInputs<F,C,D>> {
            let mut pw = PartialWitness::new();
            pw.set_target(self.height, F::from_canonical_usize(height))?;
            self.variable_delta_merkle_proof_gadget.set_witness(
                &mut pw,
                merkle_proof,
            )?;
            self.circuit_data.prove(pw)
        }
    }

    struct TestVariableHeightSubRootMerkleProofCircuit {
        pub variable_dmp_gadget_a: VariableHeightDeltaMerkleProofOptV2Gadget,
        pub variable_dmp_gadget_b: VariableHeightDeltaMerkleProofOptV2Gadget,
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
            let one = builder.one();
            let sub_root_level_plus_1 = builder.add(sub_root_level, one);

            builder.ensure_is_less_than_or_equal(8, sub_root_level_plus_1, level_a);
            builder.ensure_is_less_than_or_equal(8, sub_root_level_plus_1, level_b);

            let height_a = builder.sub(level_a, sub_root_level_plus_1);
            let height_b = builder.sub(level_b, sub_root_level_plus_1);
            
            let variable_dmp_gadget_a = VariableHeightDeltaMerkleProofOptV2Gadget::add_virtual_to_full_with_subtree_root_index::<PoseidonHash, F, D>(
                &mut builder,
                max_height,
                Some(height_a),
            );
            
            let variable_dmp_gadget_b = VariableHeightDeltaMerkleProofOptV2Gadget::add_virtual_to_full_with_subtree_root_index::<PoseidonHash, F, D>(
                &mut builder,
                max_height,
                Some(height_b),
            );

            let computed_root_index_a = variable_dmp_gadget_a.bit_info.get_root_parent_index(&mut builder);
            let computed_root_index_b = variable_dmp_gadget_b.bit_info.get_root_parent_index(&mut builder);

            builder.connect(
                computed_root_index_a,
                computed_root_index_b
            );

            let variable_dmp_gadget_a_is_right = variable_dmp_gadget_a.bit_info.is_right_child(&mut builder);
            let variable_dmp_gadget_b_is_right = variable_dmp_gadget_b.bit_info.is_right_child(&mut builder);

            let direction_sanity_check = builder.add(
                variable_dmp_gadget_a_is_right.target,
                variable_dmp_gadget_b_is_right.target,
            );

            builder.connect(
                direction_sanity_check,
                one
            );

            let computed_old_root = builder.two_to_one_swapped::<PoseidonHash>(
                variable_dmp_gadget_a.old_root,
                variable_dmp_gadget_b.old_root,
                variable_dmp_gadget_a_is_right,
            );
            let computed_new_root = builder.two_to_one_swapped::<PoseidonHash>(
                variable_dmp_gadget_a.new_root,
                variable_dmp_gadget_b.new_root,
                variable_dmp_gadget_a_is_right,
            );
    
            builder.register_public_inputs(&vec![
                vec![
                    sub_root_level,
                    computed_root_index_a,
                    ],
                    computed_old_root.elements.to_vec(),
                    computed_new_root.elements.to_vec(),
            ].concat());
            let circuit_data = builder.build::<C>();
            Self {
                variable_dmp_gadget_a,
                variable_dmp_gadget_b,
                level_a,
                level_b,
                sub_root_level,
                circuit_data,
            }
        }
        pub fn prove(
            &self,
            sub_root_level: u8,
            delta_merkle_proof_a: &DeltaMerkleProofCore<QHashOut<F>>,
            delta_merkle_proof_b: &DeltaMerkleProofCore<QHashOut<F>>,
        ) -> anyhow::Result<ProofWithPublicInputs<F,C,D>> {


            //println!("delta_merkle_proof_a: {:?}",&delta_merkle_proof_a);
            //println!("delta_merkle_proof_b: {:?}",&delta_merkle_proof_b);
            let level_a = (delta_merkle_proof_a.siblings.len() as u8 +sub_root_level+1) as u8;
            let level_b = (delta_merkle_proof_b.siblings.len() as u8 +sub_root_level+1) as u8;

            let mut pw = PartialWitness::new();
            pw.set_target(self.sub_root_level, F::from_canonical_u8(sub_root_level))?;
            pw.set_target(self.level_a, F::from_canonical_u8(level_a))?;
            pw.set_target(self.level_b, F::from_canonical_u8(level_b))?;
            
            self.variable_dmp_gadget_a.set_witness(
                &mut pw,
                delta_merkle_proof_a,
            )?;
            self.variable_dmp_gadget_b.set_witness(
                &mut pw,
                delta_merkle_proof_b,
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
    pub fn generate_random_sub_tree_delta_merkle_proofs_at_height(height: usize, rand_leaf_count: usize) -> (SimpleMerkleNodeKey, DeltaMerkleProofCore<QHashOut<F>>, SimpleMerkleNodeKey, DeltaMerkleProofCore<QHashOut<F>>, QHashOut<F>, QHashOut<F>,) {
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
        /*
        println!("height = {}",height);
        println!("leaf_key_a: {:?}",leaf_key_a);
        println!("leaf_key_b: {:?}",leaf_key_b);
        println!("nearest_common_ancestor: {:?}",nearest_common_ancestor);
        */


        let old_proof_a = tree.get_subtree_merkle_proof(nearest_common_ancestor.level+1, leaf_key_a);
        let old_proof_b = tree.get_subtree_merkle_proof(nearest_common_ancestor.level+1, leaf_key_b);

        assert!(old_proof_a.verify::<PoseidonHasher>(), "old_proof_a invalid: {:?}", old_proof_a);
        assert!(old_proof_b.verify::<PoseidonHasher>(), "old_proof_b invalid: {:?}", old_proof_b);


        let old_root = tree.get_node_value(&nearest_common_ancestor);

        let leaf_a_index = leaf_key_a.first_leaf_for_height(height as u8).index;
        let leaf_b_index = leaf_key_b.first_leaf_for_height(height as u8).index;

        tree.set_leaf(leaf_a_index, QHashOut::rand());
        tree.set_leaf(leaf_b_index, QHashOut::rand());

        /*
        println!("leaf_a_index: {:?}",leaf_a_index);
        println!("leaf_b_index: {:?}",leaf_b_index);
        */

        let new_proof_a = tree.get_subtree_merkle_proof(nearest_common_ancestor.level+1, leaf_key_a);
        let new_proof_b = tree.get_subtree_merkle_proof(nearest_common_ancestor.level+1, leaf_key_b);
        let new_root = tree.get_node_value(&nearest_common_ancestor);
        assert!(new_proof_a.verify::<PoseidonHasher>(), "new_proof_a invalid: {:?}", new_proof_a);
        assert!(new_proof_b.verify::<PoseidonHasher>(), "new_proof_b invalid: {:?}", new_proof_b);

        assert_eq!(old_proof_a.siblings, new_proof_a.siblings, "siblings changed for a");
        assert_eq!(old_proof_b.siblings, new_proof_b.siblings, "siblings changed for b");
        
        

        let dmp_a = DeltaMerkleProofCore {
            old_root: old_proof_a.root,
            old_value: old_proof_a.value,
            new_root: new_proof_a.root,
            new_value: new_proof_a.value,
            index: old_proof_a.index,
            // technically the last sibling changed
            siblings: old_proof_a.siblings,
        };
        let dmp_b = DeltaMerkleProofCore {
            old_root: old_proof_b.root,
            old_value: old_proof_b.value,
            new_root: new_proof_b.root,
            new_value: new_proof_b.value,
            index: old_proof_b.index,
            // technically the last sibling changed
            siblings: old_proof_b.siblings,
        };
        

        (leaf_key_a, dmp_a, leaf_key_b, dmp_b, old_root, new_root)
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
        

        let leaf_key_a = SimpleMerkleNodeKey::new(4, 13);
        let leaf_key_b = SimpleMerkleNodeKey::new(5,6);
        
        let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);
        println!("nearest_common_ancestor: {:?}",nearest_common_ancestor);

        let old_proof_a = tree.get_subtree_merkle_proof(nearest_common_ancestor.level+1, leaf_key_a);
        let old_proof_b = tree.get_subtree_merkle_proof(nearest_common_ancestor.level+1, leaf_key_b);

        assert!(old_proof_a.verify::<PoseidonHasher>(), "old_proof_a invalid: {:?}", old_proof_a);
        assert!(old_proof_b.verify::<PoseidonHasher>(), "old_proof_b invalid: {:?}", old_proof_b);

        let leaf_a_index = leaf_key_a.first_leaf_for_height(height as u8).index;
        let leaf_b_index = leaf_key_b.first_leaf_for_height(height as u8).index;

        tree.set_leaf(leaf_a_index, QHashOut::rand());
        tree.set_leaf(leaf_b_index, QHashOut::rand());


        let new_proof_a = tree.get_subtree_merkle_proof(nearest_common_ancestor.level+1, leaf_key_a);
        let new_proof_b = tree.get_subtree_merkle_proof(nearest_common_ancestor.level+1, leaf_key_b);
        assert!(new_proof_a.verify::<PoseidonHasher>(), "new_proof_a invalid: {:?}", new_proof_a);
        assert!(new_proof_b.verify::<PoseidonHasher>(), "new_proof_b invalid: {:?}", new_proof_b);
        

        let dmp_a = DeltaMerkleProofCore {
            old_root: old_proof_a.root,
            old_value: old_proof_a.value,
            new_root: new_proof_a.root,
            new_value: new_proof_a.value,
            index: old_proof_a.index,
            // technically the last sibling changed
            siblings: old_proof_a.siblings,
        };
        let dmp_b = DeltaMerkleProofCore {
            old_root: old_proof_b.root,
            old_value: old_proof_b.value,
            new_root: new_proof_b.root,
            new_value: new_proof_b.value,
            index: old_proof_b.index,
            // technically the last sibling changed
            siblings: old_proof_b.siblings,
        };
        

        
        
        let proof = circuit.prove(
            nearest_common_ancestor.level,
            &dmp_a,
            &dmp_b,
        ).unwrap();

        println!("pubs: {:?}",&proof.public_inputs);


    }
    #[test]
    fn test_variable_merkle_proof_sub_tree_circuit() {
        let circuit = TestVariableHeightSubRootMerkleProofCircuit::new(32);




        let merkle_proofs = (1..32).map(|level| {
            (0..20).map(|_| generate_random_sub_tree_delta_merkle_proofs_at_height(level, level*100)).collect::<Vec<_>>()
        }).flatten().collect::<Vec<_>>();

        for  (leaf_key_a, proof_a, leaf_key_b, proof_b, expected_old_root, expected_new_root) in merkle_proofs.iter() {
            //println!("leaf_key_a: {:?}",leaf_key_a);
            //println!("leaf_key_b: {:?}",leaf_key_b);

            //println!("expected_old_root: {:?}", expected_old_root);
            //println!("expected_new_root: {:?}", expected_new_root);

            assert!(proof_a.verify::<PoseidonHash>(), "proof_a invalid {:?}",proof_a);
            assert!(proof_b.verify::<PoseidonHash>(), "proof_b invalid {:?}",proof_b);

            /* 
            let expected_old_root = if leaf_key_a.is_on_the_right_of(leaf_key_b) {
                PoseidonHasher::q_two_to_one(proof_a.old_root, proof_b.old_root)
            }else{
                PoseidonHasher::q_two_to_one(proof_b.old_root, proof_a.old_root)
            };
            let expected_new_root = if leaf_key_a.is_on_the_right_of(leaf_key_b) {
                PoseidonHasher::q_two_to_one(proof_a.new_root, proof_b.new_root)
            }else{
                PoseidonHasher::q_two_to_one(proof_b.new_root, proof_a.new_root)
            };*/
            let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);
            //println!("nearest_common_ancestor: {:?}",nearest_common_ancestor);
            let proof = circuit.prove(
                nearest_common_ancestor.level,
                proof_a,
                proof_b,
            ).unwrap();
            let proof_nearest_common_ancestor_level = proof.public_inputs[0].to_canonical_u64() as u8;
            let proof_nearest_common_ancestor_index = proof.public_inputs[1].to_canonical_u64();
            //println!("public_inputs: {:?}", &proof.public_inputs);
            
            assert_eq!(proof_nearest_common_ancestor_level, nearest_common_ancestor.level, "nearest_common_ancestor_level should match expected");
            assert_eq!(proof_nearest_common_ancestor_index, nearest_common_ancestor.index, "nearest_common_ancestor_level should match expected");
            assert_eq!(proof.public_inputs[2..6].to_vec(), expected_old_root.0.elements.to_vec(), "old roots should match proof");
            assert_eq!(proof.public_inputs[6..10].to_vec(), expected_new_root.0.elements.to_vec(), "new roots should match proof");
            
            circuit.circuit_data.verify(proof).unwrap();
        }
    }


    pub fn generate_random_delta_merkle_proofs_at_height(height: usize, count: usize) -> Vec<DeltaMerkleProofCore<QHashOut<F>>> {
        let max_leaf_index_mask = (1u64<<(height as u64))-1u64;
        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(height as u8);
        // add some random leaves
        for _ in 0..(count*2) {
            let rand_index = QHashOut::<F>::rand().0.elements[0].to_canonical_u64()&max_leaf_index_mask;
            tree.set_leaf(rand_index, QHashOut::rand());
        }
        (0..count).map(|_|{
            let rand_index = QHashOut::<F>::rand().0.elements[0].to_canonical_u64()&max_leaf_index_mask;
            tree.set_leaf(rand_index, QHashOut::rand())
        }).collect()
    }

    #[test]
    fn test_variable_delta_merkle_proof_circuit() {
        let circuit = TestVariableHeightDeltaMerkleProofCircuit::new(32);
        let merkle_proofs = (1..32).map(|level| {
            generate_random_delta_merkle_proofs_at_height(level, 20)
        }).flatten().collect::<Vec<_>>();

        for mp in merkle_proofs.iter() {
            let proof = circuit.prove(mp.siblings.len(), mp).unwrap();
            assert_eq!(proof.public_inputs[0..4].to_vec(), mp.old_root.0.elements.to_vec(), "old roots should match proof");
            assert_eq!(proof.public_inputs[4..8].to_vec(), mp.new_root.0.elements.to_vec(), "new roots should match proof");
            circuit.circuit_data.verify(proof).unwrap();
        }
    }

    #[test]
    #[should_panic]
    fn test_variable_merkle_proof_circuit_incorrect_height() {
        let circuit = TestVariableHeightDeltaMerkleProofCircuit::new(32);
        let merkle_proofs = (1..32).map(|level| {
            generate_random_delta_merkle_proofs_at_height(level, 2)
        }).flatten().collect::<Vec<_>>();

        for mp in merkle_proofs.iter() {
            let proof = circuit.prove(mp.siblings.len()+1, mp).unwrap();
            assert_eq!(proof.public_inputs[0..4].to_vec(), mp.old_root.0.elements.to_vec(), "old roots should match proof");
            assert_eq!(proof.public_inputs[4..8].to_vec(), mp.new_root.0.elements.to_vec(), "new roots should match proof");
            circuit.circuit_data.verify(proof).unwrap();
        }
    }
}
