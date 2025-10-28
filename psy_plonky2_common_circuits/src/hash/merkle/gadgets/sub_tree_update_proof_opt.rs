use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore, math::core::CircuitBuilderCoreMathHelpers}
;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::Witness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}, util::log2_ceil,
};
use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, nca::nca_proof::{PartialUpdateNearestCommonAncestorProof, UpdateNearestCommonAncestorProof}}, pgoldilocks::QHashOut};

use super::variable_height_delta_merkle_proof_opt::VariableHeightDeltaMerkleProofOptGadget;

#[derive(Debug, Clone)]
pub struct UpdateNearestCommonAncestorProofOptGadget {
    pub child_a: VariableHeightDeltaMerkleProofOptGadget,
    pub child_b: VariableHeightDeltaMerkleProofOptGadget,

    pub nearest_common_ancestor_level: Target,
    pub height_a: Target,
    pub height_b: Target,
    // computed
    pub nearest_common_ancestor_index: Target,
    pub old_nearest_common_ancestor_value: HashOutTarget,
    pub new_nearest_common_ancestor_value: HashOutTarget,
    pub max_height: usize,
    pub level_a: Target,
    pub level_b: Target,
    has_witness_nearest_common_ancestor_level: bool,
    has_witness_height_a: bool,
    has_witness_height_b: bool,
}
impl UpdateNearestCommonAncestorProofOptGadget {
    pub fn add_virtual_to_full<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        max_height: usize,
    ) -> Self {
        let height_a = builder.add_virtual_target();
        let height_b = builder.add_virtual_target();
        let nearest_common_ancestor_level = builder.add_virtual_target();

        let mut gadget = Self::add_virtual_to_full_with_params::<H, F, D>(
            builder,
            max_height,
            height_a,
            height_b,
            nearest_common_ancestor_level,
        );
        gadget.has_witness_height_a = true;
        gadget.has_witness_height_b = true;
        gadget.has_witness_nearest_common_ancestor_level = true;
        gadget
    }
    fn add_virtual_to_full_with_params<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        max_height: usize,
        height_a: Target,
        height_b: Target,
        nearest_common_ancestor_level: Target,
    ) -> Self {
        let one = builder.one();

        let level_a = builder.add_virtual_target();
        let level_b = builder.add_virtual_target();
        let level_a_diff  = builder.sub(level_a, nearest_common_ancestor_level);
        let level_b_diff  = builder.sub(level_b, nearest_common_ancestor_level);
        builder.range_check(level_a, log2_ceil(max_height));
        builder.range_check(level_b, log2_ceil(max_height));
        builder.range_check(nearest_common_ancestor_level, log2_ceil(max_height));



        let child_a =
            VariableHeightDeltaMerkleProofOptGadget::add_virtual_to_full_with_subtree_root_index::<
                H,
                F,
                D,
            >(builder, max_height, Some(height_a));

        let child_b =
        VariableHeightDeltaMerkleProofOptGadget::add_virtual_to_full_with_subtree_root_index::<
                H,
                F,
                D,
            >(builder, max_height, Some(height_b));

        let solo_mask = builder.is_not_equal_hash(child_a.new_root, child_b.new_root);
        let level_a_diff_sub_solo = builder.sub(level_a_diff, solo_mask.target);
        let level_b_diff_sub_solo = builder.sub(level_b_diff, solo_mask.target);

        tracing::debug!("📏 level_a_diff_sub_solo: {:?}, height_a: {:?}, level_b_diff_sub_solo: {:?}, height_b: {:?}",
            level_a_diff_sub_solo, height_a, level_b_diff_sub_solo, height_b);

        builder.connect(level_a_diff_sub_solo, height_a);
        builder.connect(level_b_diff_sub_solo, height_b);

        let computed_child_index_a = child_a.bit_info.get_root_parent_index(builder);
        let computed_root_index_a = builder.div_rem(computed_child_index_a, 1).0;
        let computed_child_index_b = child_b.bit_info.get_root_parent_index(builder);
        let computed_root_index_b = builder.div_rem(computed_child_index_b, 1).0;

        tracing::debug!("🔢 computed_root_index_a: {:?}, computed_root_index_b: {:?}",
            computed_root_index_a, computed_root_index_b);

        builder.connect(computed_root_index_a, computed_root_index_b);

        let variable_dmp_gadget_a_is_right = child_a.bit_info.is_right_child(builder);
        let variable_dmp_gadget_b_is_right = child_b.bit_info.is_right_child(builder);

        let direction_sanity_check = builder.add(
            variable_dmp_gadget_a_is_right.target,
            variable_dmp_gadget_b_is_right.target,
        );

        builder.connect(direction_sanity_check, one);

        let computed_old_root = builder.two_to_one_swapped::<H>(
            child_a.old_root,
            child_b.old_root,
            variable_dmp_gadget_a_is_right,
        );
        let computed_new_root = builder.two_to_one_swapped::<H>(
            child_a.new_root,
            child_b.new_root,
            variable_dmp_gadget_a_is_right,
        );

        tracing::debug!("🌳 computed_old_root: {:?}, computed_new_root: {:?}",
            computed_old_root, computed_new_root);

        Self {
            child_a,
            child_b,
            nearest_common_ancestor_level,
            level_a,
            level_b,
            height_a,
            height_b,
            nearest_common_ancestor_index: computed_root_index_a,
            old_nearest_common_ancestor_value: computed_old_root,
            new_nearest_common_ancestor_value: computed_new_root,
            max_height,
            has_witness_nearest_common_ancestor_level: false,
            has_witness_height_a: false,
            has_witness_height_b: false,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        child_a: &DeltaMerkleProofCore<QHashOut<F>>,
        child_b: &DeltaMerkleProofCore<QHashOut<F>>,
        nearest_common_ancestor_level: u8

    ) -> anyhow::Result<()> {
        self.child_a.set_witness(witness, child_a)?;
        self.child_b.set_witness(witness, child_b)?;

        if self.has_witness_nearest_common_ancestor_level {
            witness.set_target(
                self.nearest_common_ancestor_level,
                F::from_canonical_u8(nearest_common_ancestor_level),
            )?;
        }
        if self.has_witness_height_a {
            witness.set_target(
                self.height_a,
                F::from_canonical_u8(
                    child_a.siblings.len() as u8
                ),
            )?;
        }
        if self.has_witness_height_b {
            witness.set_target(
                self.height_b,
                F::from_canonical_u8(
                    child_b.siblings.len() as u8
                ),
            )?;
        }
        Ok(())
    }
    pub fn set_witness_partial<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.set_witness_params(
            witness,
            &input.child_a,
            &input.child_b,
            input.nearest_common_ancestor_level,
        )
    }
    pub fn set_witness_full<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &UpdateNearestCommonAncestorProof<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.set_witness_params(
            witness,
            &input.child_a,
            &input.child_b,
            input.nearest_common_ancestor_level,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use parth_core::crypto::hash::nca::nca_proof::{PartialUpdateNearestCommonAncestorProof, UpdateNCAWithAdditionalLink};
    use parth_core::crypto::hash::traits::MerkleZeroHasher;
    use parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey;
    use plonky2::field::types::PrimeField64;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use parth_core::pgoldilocks::{PoseidonHasher, QHashOut};
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use rand::{thread_rng, Rng, RngCore};


    use super::UpdateNearestCommonAncestorProofOptGadget;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    struct TestUpdateNearestCommonAncestorProofCircuit {
        pub update_nca_gadget: UpdateNearestCommonAncestorProofOptGadget,
        pub circuit_data: CircuitData<F, C, D>,
    }

    impl TestUpdateNearestCommonAncestorProofCircuit {
        pub fn new(max_height: usize) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let update_nca_gadget =
            UpdateNearestCommonAncestorProofOptGadget::add_virtual_to_full::<PoseidonHash, F, D>(
                    &mut builder,
                    max_height,
                );

                builder.register_public_inputs(&[
                    update_nca_gadget.nearest_common_ancestor_level,
                    update_nca_gadget.nearest_common_ancestor_index,
                ]);
                builder.register_public_inputs(&update_nca_gadget.old_nearest_common_ancestor_value.elements);
                builder.register_public_inputs(&update_nca_gadget.new_nearest_common_ancestor_value.elements);
            let circuit_data = builder.build::<C>();
            Self {
                update_nca_gadget,
                circuit_data,
            }
        }
        pub fn prove(
            &self,
            nca_proof: &PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
        ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::new();
            self.update_nca_gadget.set_witness_partial(&mut pw, nca_proof)?;
            self.circuit_data.prove(pw)
        }
    }
    /*fn rand_non_root_key(rng: &mut ThreadRng, height: usize) -> SimpleMerkleNodeKey {
        let node_level = (rng.gen_range(0..height) + 1) as u64;
        let node_index_mask = (1u64 << node_level) - 1u64;
        let node_index = rng.gen::<u64>() & node_index_mask;
        SimpleMerkleNodeKey {
            level: node_level as u8,
            index: node_index,
        }
    }*/
    type QEDHash = QHashOut<F>;
    type H = PoseidonHasher;

    fn _rand_leaf_node_key<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default+ Debug>(
        tree: &SimpleMerkleTree<Hasher, Hash>,
    ) -> SimpleMerkleNodeKey {
        let index = thread_rng().gen::<u64>() & tree.get_max_leaf_index();
        SimpleMerkleNodeKey {
            level: tree.get_height(),
            index,
        }
    }
    fn rand_leaf_pair_no_collisions(tree_height: u8) -> (SimpleMerkleNodeKey, SimpleMerkleNodeKey) {
        let max_node_index = (1u64 << (tree_height as u64)) - 1u64;

        if tree_height == 1 {
            (
                SimpleMerkleNodeKey {
                    level: tree_height,
                    index: 0,
                },
                SimpleMerkleNodeKey {
                    level: tree_height,
                    index: 1,
                },
            )
        } else {
            let a = SimpleMerkleNodeKey {
                level: tree_height,
                index: thread_rng().gen::<u64>() & max_node_index,
            };

            let mut b = SimpleMerkleNodeKey {
                level: tree_height,
                index: thread_rng().gen::<u64>() & max_node_index,
            };
            while a.eq(&b) {
                b = SimpleMerkleNodeKey {
                    level: tree_height,
                    index: thread_rng().gen::<u64>() & max_node_index,
                };
            }
            (a, b)
        }
    }
    fn _rand_leaves_no_collisions(tree_height: u8, count: usize) -> Vec<SimpleMerkleNodeKey> {
        let max_node_index = (1u64 << (tree_height as u64)) - 1u64;
        let max_leaves = (max_node_index + 1) as usize;
        if count == max_leaves {
            return (0..(max_leaves as u64))
                .map(|i| SimpleMerkleNodeKey {
                    level: tree_height,
                    index: i,
                })
                .collect::<Vec<_>>();
        }
        let inds = if count > max_leaves {
            panic!(
                "tried to generate {} unique leaf indicies for a tree of height {}",
                count, tree_height
            );
        } else if count < 100 || count < (max_leaves - count) {
            let mut existing_inds = Vec::with_capacity(count);
            let mut found = 0;
            while found < count {
                let v = thread_rng().next_u64() & max_node_index;
                if !existing_inds.contains(&v) {
                    found += 1;
                    existing_inds.push(v);
                }
            }
            existing_inds
        } else {
            // find the leaves that are not in here
            let comp_size = max_leaves - count;
            let mut existing_inds = Vec::with_capacity(comp_size);
            let mut found = 0;
            while found < count {
                let v = thread_rng().next_u64() & max_node_index;
                if !existing_inds.contains(&v) {
                    found += 1;
                    existing_inds.push(v);
                }
            }
            let mut results = Vec::with_capacity(count);
            let c64 = count as u64;
            for index in 0..c64 {
                if !existing_inds.contains(&index) {
                    results.push(index)
                }
            }
            results
        };

        inds.into_iter()
            .map(|index| SimpleMerkleNodeKey {
                level: tree_height,
                index,
            })
            .collect::<Vec<_>>()
    }

    fn _gen_random_update_nca_with_additioanl_link_for_tree(
        tree: &mut SimpleMerkleTree<H, QEDHash>,
    ) -> UpdateNCAWithAdditionalLink<QEDHash> {
        let (leaf_a, leaf_b) = rand_leaf_pair_no_collisions(tree.get_height());

        let dmp_a = tree.set_leaf(leaf_a.index, QHashOut::rand());
        let dmp_b = tree.set_leaf(leaf_b.index, QHashOut::rand());

        UpdateNCAWithAdditionalLink::from_delta_merkle_proof_pair::<H>(&dmp_a, &dmp_b)
    }


    pub fn _generate_partial_nca_proof(
        tree: &mut SimpleMerkleTree<H, QEDHash>,
    ) -> PartialUpdateNearestCommonAncestorProof<QHashOut<F>>{
        let (leaf_a, leaf_b) = rand_leaf_pair_no_collisions(tree.get_height());

        let dmp_a = tree.set_leaf(leaf_a.index, QHashOut::rand());
        let dmp_b = tree.set_leaf(leaf_b.index, QHashOut::rand());
        PartialUpdateNearestCommonAncestorProof::from_delta_merkle_proof_pair::<H>(&dmp_a, &dmp_b)
    }



    pub fn generate_partial_nca_proof_multi_level_b(
        tree: &mut SimpleMerkleTree<H, QEDHash>,
    ) -> PartialUpdateNearestCommonAncestorProof<QHashOut<F>>{
        let (leaf_a, leaf_b) = rand_leaf_pair_no_collisions(tree.get_height());

        let dmp_a = tree.set_leaf(leaf_a.index, QHashOut::rand());
        let dmp_b = tree.set_leaf(leaf_b.index, QHashOut::rand());


        let mut base = PartialUpdateNearestCommonAncestorProof::from_delta_merkle_proof_pair::<H>(&dmp_a, &dmp_b);

        let base_height = base.child_a.siblings.len() as u8;
        if base_height>2 {
            let new_height_a = (thread_rng().gen::<u8>() % (base_height+1)) as usize;
            let new_height_b = (thread_rng().gen::<u8>() % base_height) as usize + 1;

            base.child_a = base.child_a.with_shortened_height_from_bottom::<H>(new_height_a);
            base.child_b = base.child_b.with_shortened_height_from_bottom::<H>(new_height_b);
        }
        base

    }

/*
    pub fn _generate_partial_nca_proof_multi_level(
        height: usize,
        rand_leaf_count: usize,
    ) -> PartialUpdateNearestCommonAncestorProof<QHashOut<F>>{
        let max_leaf_index_mask = (1u64 << (height as u64)) - 1u64;
        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(height as u8);
        // add some random leaves
        for _ in 0..rand_leaf_count {
            let rand_index =
                QHashOut::<F>::rand().0.elements[0].to_canonical_u64() & max_leaf_index_mask;
            tree.set_leaf(rand_index, QHashOut::rand());
        }

        let (leaf_key_a, leaf_key_b) = if height == 1 {
            (
                SimpleMerkleNodeKey::new(1, 0),
                SimpleMerkleNodeKey::new(1, 1),
            )
        } else {
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

            while leaf_key_a.eq(&leaf_key_b)
                || (leaf_key_a.level < leaf_key_b.level
                    && leaf_key_b.parent_at_level(leaf_key_a.level).eq(&leaf_key_a))
                || (leaf_key_b.level < leaf_key_a.level
                    && leaf_key_a.parent_at_level(leaf_key_b.level).eq(&leaf_key_b))
            {
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

        let old_proof_a =
            tree.get_subtree_merkle_proof(nearest_common_ancestor.level + 1, leaf_key_a);
        let old_proof_b =
            tree.get_subtree_merkle_proof(nearest_common_ancestor.level + 1, leaf_key_b);

        assert!(
            old_proof_a.verify::<PoseidonHasher>(),
            "old_proof_a invalid: {:?}",
            old_proof_a
        );
        assert!(
            old_proof_b.verify::<PoseidonHasher>(),
            "old_proof_b invalid: {:?}",
            old_proof_b
        );

        //let old_root = tree.get_node_value(&nearest_common_ancestor);

        let leaf_a_index = leaf_key_a.first_leaf_for_height(height as u8).index;
        let leaf_b_index = leaf_key_b.first_leaf_for_height(height as u8).index;

        tree.set_leaf(leaf_a_index, QHashOut::rand());
        tree.set_leaf(leaf_b_index, QHashOut::rand());

        /*
        println!("leaf_a_index: {:?}",leaf_a_index);
        println!("leaf_b_index: {:?}",leaf_b_index);
        */

        let new_proof_a =
            tree.get_subtree_merkle_proof(nearest_common_ancestor.level + 1, leaf_key_a);
        let new_proof_b =
            tree.get_subtree_merkle_proof(nearest_common_ancestor.level + 1, leaf_key_b);
        let new_root = tree.get_node_value(&nearest_common_ancestor);
        assert!(
            new_proof_a.verify::<PoseidonHasher>(),
            "new_proof_a invalid: {:?}",
            new_proof_a
        );
        assert!(
            new_proof_b.verify::<PoseidonHasher>(),
            "new_proof_b invalid: {:?}",
            new_proof_b
        );

        assert_eq!(
            old_proof_a.siblings, new_proof_a.siblings,
            "siblings changed for a"
        );
        assert_eq!(
            old_proof_b.siblings, new_proof_b.siblings,
            "siblings changed for b"
        );

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

        PartialUpdateNearestCommonAncestorProof {
            child_a: dmp_a,
            child_b: dmp_b,
            nearest_common_ancestor_level:nearest_common_ancestor.level,
        }
    }*/
    #[test]
    fn test_variable_merkle_proof_sub_tree_circuit() {
        let circuit = TestUpdateNearestCommonAncestorProofCircuit::new(32);
        let nca_proofs = (1..32)
            .map(|level| {
                let mut tree =SimpleMerkleTree::new(level);

                (0..20)
                    .map(|_| {
                        generate_partial_nca_proof_multi_level_b(&mut tree)
                    })
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>();

        for nca_proof in nca_proofs.iter()
        {
            //println!("leaf_key_a: {:?}",leaf_key_a);
            //println!("leaf_key_b: {:?}",leaf_key_b);

            //println!("expected_old_root: {:?}", expected_old_root);
            //println!("expected_new_root: {:?}", expected_new_root);

            //println!("nca_proof: {:?}",nca_proof.to_full_proof::<H>());
            //println!("nca_proof: {}",serde_json::to_string_pretty(&nca_proof.to_full_proof::<H>()).unwrap());

            assert!(
                nca_proof.to_full_proof::<H>().verify::<H>(),
                "proof_a invalid {:?}",
                nca_proof
            );
            //println!("nearest_common_ancestor: {:?}",nearest_common_ancestor);
            let proof = circuit
                .prove(&nca_proof)
                .unwrap();

            //println!("pubs: {:?}", &proof.public_inputs);

            let proof_nearest_common_ancestor_level =
                proof.public_inputs[0].to_canonical_u64() as u8;
            let proof_nearest_common_ancestor_index = proof.public_inputs[1].to_canonical_u64();
            //println!("public_inputs: {:?}", &proof.public_inputs);

            assert_eq!(
                proof_nearest_common_ancestor_level, nca_proof.nearest_common_ancestor_level,
                "nearest_common_ancestor_level should match expected"
            );
            assert_eq!(
                proof_nearest_common_ancestor_index, nca_proof.get_nca_index(),
                "nearest_common_ancestor_level should match expected"
            );

            assert_eq!(
                proof.public_inputs[2..6].to_vec(),
                nca_proof.compute_old_nca_value::<H>().0.elements.to_vec(),
                "old roots should match proof"
            );
            assert_eq!(
                proof.public_inputs[6..10].to_vec(),
                nca_proof.compute_new_nca_value::<H>().0.elements.to_vec(),
                "new roots should match proof"
            );

            circuit.circuit_data.verify(proof).unwrap();
        }
    }

}
