use plonky2::{field::{extension::Extendable, types::Field}, hash::hash_types::{HashOutTarget, RichField}, iop::{target::BoolTarget, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, spiderman::SpidermanUpdateProof}, pgoldilocks::QHashOut};

use super::{delta_merkle_proof::DeltaMerkleProofGadget, full_merkle_tree_append::FullMerkleTreeAppendGadget};


#[derive(Debug, Clone)]
pub struct SpidermanAppendProofGadget {
    pub top_line_proof: DeltaMerkleProofGadget,
    pub web_proof: FullMerkleTreeAppendGadget,

    
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
}


impl SpidermanAppendProofGadget {
    pub fn get_added_leaves(&self) -> &Vec<BoolTarget> {
        &self.web_proof.added_leaves
    }
    pub fn add_virtual_to<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        top_line_height: usize,
        web_tree_height: usize,
    ) -> Self {

        let top_line_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, top_line_height);
        let web_proof = FullMerkleTreeAppendGadget::add_virtual_to::<H, F, D>(builder, web_tree_height);
        
        // connect the node at the bottom of the top line to the root of the subtree
        builder.connect_hashes(top_line_proof.old_value, web_proof.old_root);
        builder.connect_hashes(top_line_proof.new_value, web_proof.new_root);


        let old_root = top_line_proof.old_root;
        let new_root = top_line_proof.new_root;

        Self {
            top_line_proof,
            web_proof,
            old_root,
            new_root,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: Field>(
        &self,
        witness: &mut W,
        top_line_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        old_leaves: &[QHashOut<F>],
        new_leaves: &[QHashOut<F>],
    ) -> anyhow::Result<()> {
        self.top_line_proof.set_witness_core_proof_q(witness, top_line_proof)?;
        self.web_proof.set_witness(witness, old_leaves, new_leaves)
    }

    pub fn set_witness<W: Witness<F>, F: Field>(
        &self,
        witness: &mut W,
        proof: &SpidermanUpdateProof<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.set_witness_params(
            witness,
            &proof.top_line_proof,
            &proof.web_proof_old_leaves,
            &proof.web_proof_new_leaves,
        )
    }
}



#[cfg(test)]
mod tests {
    use parth_core::crypto::hash::spiderman::SpidermanUpdateProof;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use parth_core::pgoldilocks::{PoseidonHasher, QHashOut};

    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    

    use super::SpidermanAppendProofGadget;


    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    struct TestSpidermanAppendCircuit {
        pub update_gadget: SpidermanAppendProofGadget,
        pub circuit_data: CircuitData<F, C, D>,
    }

    impl TestSpidermanAppendCircuit {
        pub fn new(            
            top_line_height: usize,
            web_tree_height: usize,
        ) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let update_gadget = SpidermanAppendProofGadget::add_virtual_to::<PoseidonHash, F, D>(
                &mut builder,
                top_line_height,
                web_tree_height,
            );

            builder.register_public_inputs(&update_gadget.old_root.elements);
            builder.register_public_inputs(&update_gadget.new_root.elements);
            builder.register_public_inputs(
                &update_gadget
                    .get_added_leaves()
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
            proof: &SpidermanUpdateProof<QHashOut<F>>,
        ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::new();
            self.update_gadget
                .set_witness(&mut pw, proof)?;
            self.circuit_data.prove(pw)
        }
    }
    

    fn test_spiderman_tree_basic(
        top_line_height: usize,
        web_tree_height: usize,
        append_leaf_ct: usize,
        start_index: usize,
    ) {
        let circuit = TestSpidermanAppendCircuit::new(top_line_height, web_tree_height);

        let total_height = top_line_height+web_tree_height;

        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(total_height as u8);

        for i in 0..start_index{
            tree.set_leaf(i as u64, QHashOut::rand());
        }
        let test_leaves = (0..append_leaf_ct).map(|_|{
            QHashOut::rand()
        }).collect::<Vec<_>>();

        let spiderman_proofs = tree.append_leaves_spider_man(web_tree_height as u8, &test_leaves).unwrap();
        for p in spiderman_proofs.iter() {
            assert!(p.verify::<PoseidonHasher>(), "invalid spiderman proof");
            let pubs = circuit.prove(p).unwrap().public_inputs;
            assert_eq!(pubs[0..4].to_vec(), p.top_line_proof.old_root.0.elements.to_vec());
            assert_eq!(pubs[4..8].to_vec(), p.top_line_proof.new_root.0.elements.to_vec());

        }
        
    }
    #[test]
    fn test_spiderman_tree_basic_small() {
        test_spiderman_tree_basic(12, 4, 5, 0);
        test_spiderman_tree_basic(12, 4, 50, 1);
        test_spiderman_tree_basic(3, 3, 9, 2);
        test_spiderman_tree_basic(8, 4, 1, 125);
    }

}
