use std::collections::VecDeque;

use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        circuit_data::CommonCircuitData,
        config::{AlgebraicHasher, GenericConfig, Hasher},
    },
};
use psy_client_common::{data::qhashout::QHashOut, utils::debug_timer::DebugTimer};
use psy_crypto::{
    common::witnesses::qrecursion::{
        header::QRecursionAggStandardHeader,
        proof_data::{InputLeafProof, LeafProofRecord},
    },
    hash::{
        merkle::{
            core::MerkleProofCore,
            utils::simple_merkle_tree::SimpleMerkleTree,
        },
        traits::hasher::MerkleZeroHasher,
    },
};

use crate::{
    circuits::traits::qstandard::QStandardCircuit,
    treeprover::qrecursion::standard::{
        circuits::prove_root::QRecursionStandardRootCircuit, config::QRECURSION_CIRCUIT_WHITELIST_HEIGHT, manager::leaf_circuit_set::QStandardBinaryRecursionTreeCircuitSet
    },
};

use psy_crypto::common::witnesses::qrecursion::proof_data::{
    AggProofRecord, QStandardBinaryTreeCircuitType, SimpleQTreeRecursionManagerInclusionProofs,
};

pub struct SimpleQTreeRecursionManager<C: GenericConfig<D>, const D: usize>
where
    C::Hasher:
       AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
{
    pub root_circuit: QRecursionStandardRootCircuit<C,D>,
    pub circuit_set: QStandardBinaryRecursionTreeCircuitSet<C, D>,
    pub circuit_inclusion_proofs: SimpleQTreeRecursionManagerInclusionProofs<C::F>,

    pub proof_tree: SimpleMerkleTree<C::Hasher, QHashOut<C::F>>,
    pub agg_proofs: Vec<AggProofRecord<C, D>>,
    pub leaf_proofs: VecDeque<LeafProofRecord<C, D>>,
    pub root_history: Vec<QHashOut<C::F>>,

    leaf_to_index_map: hashbrown::HashMap<QHashOut<C::F>, u64>,

    next_proof_index: u64,
    max_proofs_in_tree: u64,
    q_recursion_tree_height: usize,
}

impl<C: GenericConfig<D>, const D: usize> SimpleQTreeRecursionManager<C, D>
where
    C::Hasher:
       AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
{
    pub fn new(
        q_recursion_tree_height: usize,
        leaf_circuit_config_id: u64,
        leaf_verifier_data_cap_height: usize,
        leaf_child_common_data: &CommonCircuitData<C::F, D>,
    ) -> Self {
        let circuit_set = QStandardBinaryRecursionTreeCircuitSet::<C, D>::new(
            q_recursion_tree_height,
            leaf_circuit_config_id,
            leaf_verifier_data_cap_height,
            leaf_child_common_data,
        );
        let mut tmp_circuit_whitelist_tree = SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(
            QRECURSION_CIRCUIT_WHITELIST_HEIGHT as u8,
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::SingleLeaf.into(),
            circuit_set.single_leaf_circuit.get_fingerprint(),
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::TwoLeaf.into(),
            circuit_set.two_leaf_circuit.get_fingerprint(),
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::TwoAgg.into(),
            circuit_set.two_agg_circuit.get_fingerprint(),
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::LeftAggRightLeaf.into(),
            circuit_set.left_agg_right_leaf_circuit.get_fingerprint(),
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::LeftLeafRightAgg.into(),
            circuit_set.left_leaf_right_agg_circuit.get_fingerprint(),
        );

        let circuit_inclusion_proofs = SimpleQTreeRecursionManagerInclusionProofs {
            single_leaf_circuit_merkle_proof: tmp_circuit_whitelist_tree
                .get_leaf(QStandardBinaryTreeCircuitType::SingleLeaf.into()),
            two_leaf_circuit_merkle_proof: tmp_circuit_whitelist_tree
                .get_leaf(QStandardBinaryTreeCircuitType::TwoLeaf.into()),
            two_agg_circuit_merkle_proof: tmp_circuit_whitelist_tree
                .get_leaf(QStandardBinaryTreeCircuitType::TwoAgg.into()),
            left_leaf_right_agg_circuit_merkle_proof: tmp_circuit_whitelist_tree
                .get_leaf(QStandardBinaryTreeCircuitType::LeftLeafRightAgg.into()),
            left_agg_right_leaf_circuit_merkle_proof: tmp_circuit_whitelist_tree
                .get_leaf(QStandardBinaryTreeCircuitType::LeftAggRightLeaf.into()),
            circuit_whitelist_tree_root: tmp_circuit_whitelist_tree.get_root(),
        };
        let root_circuit = QRecursionStandardRootCircuit::<C,D>::new_with_minifier(
            circuit_set.two_agg_circuit.get_common_circuit_data_ref(),
            circuit_set.two_agg_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
            circuit_inclusion_proofs.circuit_whitelist_tree_root,
        );

        let proof_tree =
            SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(q_recursion_tree_height as u8);
        let max_proofs_in_tree = 1u64 << (q_recursion_tree_height as u64);
        let next_proof_index = 0;

        Self {
            root_circuit,
            circuit_set,
            circuit_inclusion_proofs,
            proof_tree,
            leaf_to_index_map: hashbrown::HashMap::new(),
            root_history: Vec::new(),
            agg_proofs: Vec::new(),
            leaf_proofs: VecDeque::new(),
            next_proof_index,
            max_proofs_in_tree,
            q_recursion_tree_height,
        }
    }
    pub fn get_proof_tree_height(&self) -> usize {
        self.q_recursion_tree_height
    }
    pub fn get_proof_tree_height_u8(&self) -> u8 {
        self.q_recursion_tree_height as u8
    }
    pub fn get_proof_tree_root(&self) -> QHashOut<C::F> {
        self.proof_tree.get_root()
    }
    pub fn get_leaf_merkle_proof(&self, index: u64) -> MerkleProofCore<QHashOut<C::F>> {
        self.proof_tree.get_leaf(index)
    }
    pub fn find_zero_hash_proof_for_historical_root(
        &self,
        root_hash: QHashOut<C::F>,
    ) -> Option<MerkleProofCore<QHashOut<C::F>>> {
        let index = if root_hash.eq(&self.proof_tree.get_root()) {
            Some(self.next_proof_index as usize)
        } else {
            self.root_history.iter().position(|x| x.eq(&root_hash))
        };

        match index {
            Some(v) => {
                let result = self.proof_tree.get_leaf(v as u64);

                Some(result)
            }
            None => None,
        }
    }
    /*
    fn generate_dmps_for_proofs(
        &mut self,
        leaf_proofs: &[(
            &ProofWithPublicInputs<C::F, C, D>,
            QHashOut<C::F>,
            &VerifierOnlyCircuitData<C, D>,
        )],
    ) -> Vec<DeltaMerkleProofCore<QHashOut<C::F>>> {
        let mut witnesses = Vec::with_capacity(leaf_proofs.len());
        for (p, fingerprint, _) in leaf_proofs.iter() {
            let index = self.next_proof_index;
            let public_inputs_hash = QHashOut(HashOut {
                elements: [
                    p.public_inputs[0],
                    p.public_inputs[1],
                    p.public_inputs[2],
                    p.public_inputs[3],
                ],
            });

            let value = C::Hasher::q_two_to_one(*fingerprint, public_inputs_hash);
            witnesses.push(self.proof_tree.set_leaf(index, value));
            self.next_proof_index += 1;
        }
        witnesses
    }*/
    pub fn injest_single_leaf_proof(&mut self, leaf_proof: InputLeafProof<C, D>) -> u64 {
        let index = self.next_proof_index;
        let public_inputs_hash = QHashOut(HashOut {
            elements: [
                leaf_proof.proof.public_inputs[0],
                leaf_proof.proof.public_inputs[1],
                leaf_proof.proof.public_inputs[2],
                leaf_proof.proof.public_inputs[3],
            ],
        });

        let value = QHashOut(<C::Hasher as Hasher<C::F>>::two_to_one(leaf_proof.fingerprint.0, public_inputs_hash.0));
        self.leaf_to_index_map.insert(value, index);
        let insertion_proof = self.proof_tree.set_leaf(index, value);
        self.root_history.push(insertion_proof.old_root);
        let record = LeafProofRecord {
            leaf_circuit_type: leaf_proof.leaf_circuit_type,
            fingerprint: leaf_proof.fingerprint,
            proof: leaf_proof.proof,
            verifier_data: leaf_proof.verifier_data,
            insertion_proof,
        };
        self.leaf_proofs.push_back(record);
        self.next_proof_index += 1;
        assert!(self.next_proof_index < self.max_proofs_in_tree, "added more proofs than the tree has capacity for");
        index
    }

    /*fn prove_simple_serial_even_pairs(
        &mut self,
        leaf_proofs: &[(
            &ProofWithPublicInputs<C::F, C, D>,
            QHashOut<C::F>,
            &VerifierOnlyCircuitData<C, D>,
        )],
        insertion_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>],
    ) -> Vec<AggProofRecord<C, D>> {
        assert!(
            (leaf_proofs.len() & 1) == 0,
            "prove_simple_serial_even_pairs called with an odd number of proofs"
        );
        assert_eq!(leaf_proofs.len(), insertion_proofs.len(), "prove_simple_serial_even_pairs called a different number of leaf proofs and insertion proofs");
        let half_len = leaf_proofs.len() / 2;
        let mut two_leaf_proofs = Vec::with_capacity(half_len);
        let agg_circuit_whitelist_root = self.circuit_inclusion_proofs.circuit_whitelist_tree_root;
        for i in 0..half_len {
            let index = i * 2;
            let proof = self.circuit_set.two_leaf_circuit.prove_base(
                agg_circuit_whitelist_root,
                &insertion_proofs[index],
                leaf_proofs[index].0,
                leaf_proofs[index].2,
                &insertion_proofs[index + 1],
                leaf_proofs[index + 1].0,
                leaf_proofs[index + 1].2,
            );
            let record = AggProofRecord {
                circuit_type: QStandardBinaryTreeCircuitType::TwoLeaf,
                fingerprint: self.circuit_set.two_leaf_circuit.get_fingerprint(),
                agg_header: QRecursionAggStandardHeader {
                    state_transition_start: insertion_proofs[index].old_root,
                    state_transition_end: insertion_proofs[index + 1].new_root,
                    agg_circuit_whitelist_root,
                },
                proof,
            };
            two_leaf_proofs.push(record);
        }
        two_leaf_proofs
    }*/
    fn prove_single_leaf(&self, leaf: &LeafProofRecord<C, D>) -> AggProofRecord<C, D> {
        let agg_circuit_whitelist_root = self.circuit_inclusion_proofs.circuit_whitelist_tree_root;

        let proof = self.circuit_set.single_leaf_circuit.prove_base(
            agg_circuit_whitelist_root,
            &leaf.insertion_proof,
            &leaf.proof,
            &leaf.verifier_data,
        );

        let record = AggProofRecord {
            circuit_type: QStandardBinaryTreeCircuitType::SingleLeaf,
            fingerprint: self.circuit_set.single_leaf_circuit.get_fingerprint(),
            agg_header: QRecursionAggStandardHeader {
                state_transition_start: leaf.insertion_proof.old_root,
                state_transition_end: leaf.insertion_proof.new_root,
                agg_circuit_whitelist_root,
            },
            proof,
        };

        record
    }

    fn prove_left_agg_right_leaf(
        &self,
        left: &AggProofRecord<C, D>,
        right: &LeafProofRecord<C, D>,
    ) -> AggProofRecord<C, D> {
        let proof = self.circuit_set.left_agg_right_leaf_circuit.prove_base(
            self.circuit_inclusion_proofs
                .get_inclusion_proof_for_type(left.circuit_type),
            &left.agg_header,
            &left.proof,
            self.circuit_set
                .get_verifier_data_by_type(left.circuit_type).await,
            &right.insertion_proof,
            &right.proof,
            &right.verifier_data,
        );
        let agg_circuit_whitelist_root = self.circuit_inclusion_proofs.circuit_whitelist_tree_root;

        let record = AggProofRecord {
            circuit_type: QStandardBinaryTreeCircuitType::LeftAggRightLeaf,
            fingerprint: self.circuit_set.left_agg_right_leaf_circuit.get_fingerprint(),
            agg_header: QRecursionAggStandardHeader {
                state_transition_start: left.agg_header.state_transition_start,
                state_transition_end: right.insertion_proof.new_root,
                agg_circuit_whitelist_root,
            },
            proof,
        };

        record
    }

    pub fn prove_two_leaf(
        &self,
        left: &LeafProofRecord<C, D>,
        right: &LeafProofRecord<C, D>,
    ) -> AggProofRecord<C, D> {
        let agg_circuit_whitelist_root = self.circuit_inclusion_proofs.circuit_whitelist_tree_root;

        let proof = self.circuit_set.two_leaf_circuit.prove_base(
            agg_circuit_whitelist_root,
            &left.insertion_proof,
            &left.proof,
            &left.verifier_data,
            &right.insertion_proof,
            &right.proof,
            &right.verifier_data,
        );
        let record = AggProofRecord {
            circuit_type: QStandardBinaryTreeCircuitType::TwoLeaf,
            fingerprint: self.circuit_set.two_leaf_circuit.get_fingerprint(),
            agg_header: QRecursionAggStandardHeader {
                state_transition_start: left.insertion_proof.old_root,
                state_transition_end: right.insertion_proof.new_root,
                agg_circuit_whitelist_root,
            },
            proof,
        };

        record
    }

    fn prove_two_agg(
        &self,
        left: &AggProofRecord<C, D>,
        right: &AggProofRecord<C, D>,
    ) -> AggProofRecord<C, D> {
        let agg_circuit_whitelist_root = self.circuit_inclusion_proofs.circuit_whitelist_tree_root;

        let proof = self.circuit_set.two_agg_circuit.prove_base(
            self.circuit_inclusion_proofs
                .get_inclusion_proof_for_type(left.circuit_type),
            &left.agg_header,
            &left.proof,
            self.circuit_set
                .get_verifier_data_by_type(left.circuit_type).await,

            self.circuit_inclusion_proofs
                .get_inclusion_proof_for_type(right.circuit_type),
            &right.agg_header,
            &right.proof,
            self.circuit_set
                .get_verifier_data_by_type(right.circuit_type).await,
        );
        let record = AggProofRecord {
            circuit_type: QStandardBinaryTreeCircuitType::TwoAgg,
            fingerprint: self.circuit_set.two_agg_circuit.get_fingerprint(),
            agg_header: QRecursionAggStandardHeader {
                state_transition_start: left.agg_header.state_transition_start,
                state_transition_end: right.agg_header.state_transition_end,
                agg_circuit_whitelist_root,
            },
            proof,
        };

        record
    }

    pub fn prove_one_step_simple_serial(&mut self) -> bool {
        let mut timer = DebugTimer::new("prove_one_step_simple_serial");
        timer.lap("start: prove_one_step_simple_serial");
        let leaf_proofs_len = self.leaf_proofs.len();
        let agg_proofs_len = self.agg_proofs.len();

        let result = if leaf_proofs_len >= 2 {
            let left = self.leaf_proofs.pop_front().unwrap();
            let right = self.leaf_proofs.pop_front().unwrap();
            let record = self.prove_two_leaf(&left, &right);
            self.agg_proofs.push(record);
            true
        } else if agg_proofs_len >= 2 {
            let right = self.agg_proofs.pop().unwrap();
            let left = self.agg_proofs.pop().unwrap();
            let record = self.prove_two_agg(&left, &right);
            self.agg_proofs.push(record);
            true
        } else if agg_proofs_len != 0 && leaf_proofs_len != 0 {
            let left_agg = self.agg_proofs.pop().unwrap();
            let right_leaf = self.leaf_proofs.pop_front().unwrap();
            let record = self.prove_left_agg_right_leaf(&left_agg, &right_leaf);
            self.agg_proofs.push(record);
            true
        } else {
            false
        };

        timer.lap("finished");


        result
    }

    pub fn add_leaf_proofs(&mut self, leaf_proofs: Vec<InputLeafProof<C, D>>) -> Vec<u64> {
        let mut inds = Vec::with_capacity(leaf_proofs.len());

        self.leaf_proofs.reserve(leaf_proofs.len());
        for lp in leaf_proofs.into_iter() {
            inds.push(self.injest_single_leaf_proof(lp))
        }
        inds
    }

    pub fn finalize_tree(&mut self) -> anyhow::Result<()> {
        while self.prove_one_step_simple_serial() {
            // prove remaining tasks (if any)
        }

        // handle the case where there is one leaf proof
        let leaf_proofs_len = self.leaf_proofs.len();
        if leaf_proofs_len != 0 {
            assert_eq!(leaf_proofs_len, 1, "the only way leaf_proofs_len!=0 after while self.prove_one_step_simple_serial() should be if agg_proofs is empty and there is a single leaf proof");
            assert!(self.agg_proofs.is_empty(), "agg proofs should be empty if there is still a leaf proof in the queue after while self.prove_one_step_simple_serial()");
            let dangling_leaf = self.leaf_proofs.pop_front().unwrap();
            println!("prove_single_leaf");

            let record = self.prove_single_leaf(&dangling_leaf);
            self.agg_proofs.push(record);
        }



        Ok(())
    }
}
