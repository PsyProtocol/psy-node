use std::collections::VecDeque;

use plonky2::{
    hash::hash_types::HashOut,
    plonk::config::{AlgebraicHasher, GenericConfig, Hasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{
    common::witnesses::qrecursion::{
        header::QRecursionAggStandardHeader,
        proof_data::{AggProofRecord, InputLeafProof, LeafProofRecord, QStandardBinaryTreeCircuitType},
    },
    hash::{
        merkle::{
            core::{DeltaMerkleProofCore, MerkleProofCore},
            utils::simple_merkle_tree::SimpleMerkleTree,
        },
        traits::hasher::MerkleZeroHasherWithMarkedLeaf,
    },
};
use psy_vm::ups::circuit_manager::PortableQTreeRecursion;

#[derive(Clone, Debug)]
pub struct PortableQTreeRecursionManager<C: GenericConfig<D>, const D: usize> {
    pub proof_tree: SimpleMerkleTree<C::Hasher, QHashOut<C::F>>,
    pub agg_proofs: Vec<AggProofRecord<C, D>>,
    pub leaf_proofs: VecDeque<LeafProofRecord<C, D>>,
    pub root_history: Vec<QHashOut<C::F>>,

    leaf_to_index_map: hashbrown::HashMap<QHashOut<C::F>, u64>,

    next_proof_index: u64,
    max_proofs_in_tree: u64,
    q_recursion_tree_height: usize,
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub async fn new(q_recursion_tree_height: usize) -> Self {
        let proof_tree = SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(q_recursion_tree_height as u8);
        let max_proofs_in_tree = 1u64 << (q_recursion_tree_height as u64);
        let next_proof_index = 0;

        Self {
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
    pub async fn get_proof_tree_height(&self) -> usize {
        self.q_recursion_tree_height
    }

    /// Get the next proof leaf index (for ProofTreeMeta serialization).
    pub fn next_proof_index(&self) -> u64 {
        self.next_proof_index
    }

    /// Get the q_recursion_tree_height (for ProofTreeMeta serialization).
    pub fn q_recursion_tree_height(&self) -> usize {
        self.q_recursion_tree_height
    }

    /// Restore the manager's tree snapshot from externally-serialized state.
    ///
    /// This is used by step-by-step proving across process / WASM restarts:
    /// `ProofTreeMeta` reconstructs a `SimpleMerkleTree`, then this method
    /// replaces the live manager state with that snapshot.
    pub fn restore_snapshot(
        &mut self,
        proof_tree: SimpleMerkleTree<C::Hasher, QHashOut<C::F>>,
        root_history: Vec<QHashOut<C::F>>,
        next_proof_index: u64,
    ) {
        self.proof_tree = proof_tree;
        self.root_history = root_history;
        self.next_proof_index = next_proof_index;
        self.leaf_to_index_map.clear();
    }
    pub async fn get_proof_tree_height_u8(&self) -> u8 {
        self.q_recursion_tree_height as u8
    }
    pub async fn get_proof_tree_root(&self) -> QHashOut<C::F> {
        self.proof_tree.get_root()
    }
    pub async fn get_leaf_merkle_proof(&self, index: u64) -> MerkleProofCore<QHashOut<C::F>> {
        self.proof_tree.get_leaf(index)
    }
    pub async fn find_zero_hash_proof_for_historical_root(&self, root_hash: QHashOut<C::F>) -> Option<MerkleProofCore<QHashOut<C::F>>> {
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
    pub async fn injest_single_leaf_proof(&mut self, leaf_proof: InputLeafProof<C, D>) -> u64 {
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
        //println!("root_history.push({:?})",&insertion_proof.old_root);
        let record = LeafProofRecord {
            leaf_circuit_type: leaf_proof.leaf_circuit_type,
            fingerprint: leaf_proof.fingerprint,
            proof: leaf_proof.proof,
            verifier_data: leaf_proof.verifier_data,
            insertion_proof,
        };
        self.leaf_proofs.push_back(record);
        self.next_proof_index += 1;
        assert!(
            self.next_proof_index < self.max_proofs_in_tree,
            "added more proofs than the tree has capacity for"
        );
        index
    }
    /// Mirror a leaf value into the proof tree without storing a proof.
    /// This advances the proof tree root exactly like
    /// `injest_single_leaf_proof` would, so it can be used during
    /// `generate_tx_trace` to keep the proof tree in sync with the real
    /// prove path — without generating the actual proof.
    pub async fn injest_single_leaf_value(
        &mut self,
        fingerprint: QHashOut<C::F>,
        session_proof_tree_root: QHashOut<C::F>,
        inner_public_inputs_hash: QHashOut<C::F>,
    ) -> u64 {
        let index = self.next_proof_index;
        let public_inputs_hash = QHashOut(<C::Hasher as Hasher<C::F>>::two_to_one(
            session_proof_tree_root.0,
            inner_public_inputs_hash.0,
        ));
        let value = QHashOut(<C::Hasher as Hasher<C::F>>::two_to_one(fingerprint.0, public_inputs_hash.0));
        self.leaf_to_index_map.insert(value, index);
        let insertion_proof = self.proof_tree.set_leaf(index, value);
        self.root_history.push(insertion_proof.old_root);
        self.next_proof_index += 1;
        assert!(
            self.next_proof_index < self.max_proofs_in_tree,
            "added more proofs than the tree has capacity for"
        );
        index
    }

    /// Mirror a leaf proof whose public input is already the final public input
    /// hash. Unlike `injest_single_leaf_value`, this does not mix in the
    /// session proof-tree root before hashing with the fingerprint.
    pub async fn injest_single_leaf_public_inputs_hash(&mut self, fingerprint: QHashOut<C::F>, public_inputs_hash: QHashOut<C::F>) -> u64 {
        let index = self.next_proof_index;
        let value = QHashOut(<C::Hasher as Hasher<C::F>>::two_to_one(fingerprint.0, public_inputs_hash.0));
        self.leaf_to_index_map.insert(value, index);
        let insertion_proof = self.proof_tree.set_leaf(index, value);
        self.root_history.push(insertion_proof.old_root);
        self.next_proof_index += 1;
        assert!(
            self.next_proof_index < self.max_proofs_in_tree,
            "added more proofs than the tree has capacity for"
        );
        index
    }

    async fn prove_single_leaf<T: PortableQTreeRecursion<C, D> + ?Sized>(
        &self,
        circuit_mgr: &T,
        leaf: &LeafProofRecord<C, D>,
    ) -> anyhow::Result<AggProofRecord<C, D>> {
        let agg_circuit_whitelist_root = circuit_mgr.circuit_inclusion_proofs().await.circuit_whitelist_tree_root;

        let proof = circuit_mgr
            .prove_single_leaf_circuit(agg_circuit_whitelist_root, &leaf.insertion_proof, &leaf.proof, &leaf.verifier_data)
            .await?;

        let record = AggProofRecord {
            circuit_type: QStandardBinaryTreeCircuitType::SingleLeaf,
            fingerprint: circuit_mgr.single_leaf_circuit_fingerprint().await,
            agg_header: QRecursionAggStandardHeader {
                state_transition_start: leaf.insertion_proof.old_root,
                state_transition_end: leaf.insertion_proof.new_root,
                agg_circuit_whitelist_root,
            },
            proof,
        };

        Ok(record)
    }

    async fn prove_left_agg_right_leaf<T: PortableQTreeRecursion<C, D> + ?Sized>(
        &self,
        circuit_mgr: &T,
        left: &AggProofRecord<C, D>,
        right: &LeafProofRecord<C, D>,
    ) -> anyhow::Result<AggProofRecord<C, D>> {
        let proof = circuit_mgr
            .prove_left_agg_right_leaf_circuit(
                circuit_mgr
                    .circuit_inclusion_proofs()
                    .await
                    .get_inclusion_proof_for_type(left.circuit_type),
                &left.agg_header,
                &left.proof,
                &circuit_mgr.get_verifier_data_by_type(left.circuit_type).await,
                &right.insertion_proof,
                &right.proof,
                &right.verifier_data,
            )
            .await?;
        let agg_circuit_whitelist_root = circuit_mgr.circuit_inclusion_proofs().await.circuit_whitelist_tree_root;

        let record = AggProofRecord {
            circuit_type: QStandardBinaryTreeCircuitType::LeftAggRightLeaf,
            fingerprint: circuit_mgr.left_agg_right_leaf_circuit_fingerprint().await,
            agg_header: QRecursionAggStandardHeader {
                state_transition_start: left.agg_header.state_transition_start,
                state_transition_end: right.insertion_proof.new_root,
                agg_circuit_whitelist_root,
            },
            proof,
        };

        Ok(record)
    }

    pub async fn prove_two_leaf<T: PortableQTreeRecursion<C, D> + ?Sized>(
        &self,
        circuit_mgr: &T,
        left: &LeafProofRecord<C, D>,
        right: &LeafProofRecord<C, D>,
    ) -> anyhow::Result<AggProofRecord<C, D>> {
        let agg_circuit_whitelist_root = circuit_mgr.circuit_inclusion_proofs().await.circuit_whitelist_tree_root;

        let proof = circuit_mgr
            .prove_two_leaf_circuit(
                agg_circuit_whitelist_root,
                &left.insertion_proof,
                &left.proof,
                &left.verifier_data,
                &right.insertion_proof,
                &right.proof,
                &right.verifier_data,
            )
            .await?;
        let record = AggProofRecord {
            circuit_type: QStandardBinaryTreeCircuitType::TwoLeaf,
            fingerprint: circuit_mgr.two_leaf_circuit_fingerprint().await,
            agg_header: QRecursionAggStandardHeader {
                state_transition_start: left.insertion_proof.old_root,
                state_transition_end: right.insertion_proof.new_root,
                agg_circuit_whitelist_root,
            },
            proof,
        };

        Ok(record)
    }

    async fn prove_two_agg<T: PortableQTreeRecursion<C, D> + ?Sized>(
        &self,
        circuit_mgr: &T,
        left: &AggProofRecord<C, D>,
        right: &AggProofRecord<C, D>,
    ) -> anyhow::Result<AggProofRecord<C, D>> {
        let agg_circuit_whitelist_root = circuit_mgr.circuit_inclusion_proofs().await.circuit_whitelist_tree_root;

        let proof = circuit_mgr
            .prove_two_agg_circuit(
                circuit_mgr
                    .circuit_inclusion_proofs()
                    .await
                    .get_inclusion_proof_for_type(left.circuit_type),
                &left.agg_header,
                &left.proof,
                &circuit_mgr.get_verifier_data_by_type(left.circuit_type).await,
                circuit_mgr
                    .circuit_inclusion_proofs()
                    .await
                    .get_inclusion_proof_for_type(right.circuit_type),
                &right.agg_header,
                &right.proof,
                &circuit_mgr.get_verifier_data_by_type(right.circuit_type).await,
            )
            .await?;
        let record = AggProofRecord {
            circuit_type: QStandardBinaryTreeCircuitType::TwoAgg,
            fingerprint: circuit_mgr.two_agg_circuit_fingerprint().await,
            agg_header: QRecursionAggStandardHeader {
                state_transition_start: left.agg_header.state_transition_start,
                state_transition_end: right.agg_header.state_transition_end,
                agg_circuit_whitelist_root,
            },
            proof,
        };

        Ok(record)
    }

    pub async fn prove_one_step_simple_serial<T: PortableQTreeRecursion<C, D> + ?Sized>(&mut self, circuit_mgr: &T) -> anyhow::Result<bool> {
        let leaf_proofs_len = self.leaf_proofs.len();
        let agg_proofs_len = self.agg_proofs.len();

        let result = if leaf_proofs_len >= 2 {
            let left = self.leaf_proofs.pop_front().unwrap();
            let right = self.leaf_proofs.pop_front().unwrap();
            let record = self.prove_two_leaf(circuit_mgr, &left, &right).await?;
            self.agg_proofs.push(record);
            true
        } else if agg_proofs_len >= 2 {
            let right = self.agg_proofs.pop().unwrap();
            let left = self.agg_proofs.pop().unwrap();
            let record = self.prove_two_agg(circuit_mgr, &left, &right).await?;
            self.agg_proofs.push(record);
            true
        } else if agg_proofs_len != 0 && leaf_proofs_len != 0 {
            let left_agg = self.agg_proofs.pop().unwrap();
            let right_leaf = self.leaf_proofs.pop_front().unwrap();
            let record = self.prove_left_agg_right_leaf(circuit_mgr, &left_agg, &right_leaf).await?;
            self.agg_proofs.push(record);
            true
        } else {
            false
        };

        Ok(result)
    }

    pub async fn add_leaf_proofs(&mut self, leaf_proofs: Vec<InputLeafProof<C, D>>) -> Vec<u64> {
        let mut inds = Vec::with_capacity(leaf_proofs.len());

        self.leaf_proofs.reserve(leaf_proofs.len());
        for lp in leaf_proofs.into_iter() {
            inds.push(self.injest_single_leaf_proof(lp).await)
        }
        inds
    }

    /// Extract leaf metadata (everything except proof blob and verifier_data).
    ///
    /// Returns per-leaf: leaf_circuit_type, fingerprint, insertion_proof.
    /// Combined with proof blobs (from trace) and verifier_data (from circuit
    /// manager), these are sufficient to reconstruct `LeafProofRecord` at
    /// finalize time without serializing the full proof + verifier_data per
    /// step.
    pub fn extract_leaf_metadata(&self) -> Vec<(u64, QHashOut<C::F>, DeltaMerkleProofCore<QHashOut<C::F>>)> {
        self.leaf_proofs
            .iter()
            .map(|r| (r.leaf_circuit_type, r.fingerprint, r.insertion_proof.clone()))
            .collect()
    }

    /// Restore leaf proofs from pre-built records (no serialization).
    /// The caller has already reconstructed the full `LeafProofRecord` from
    /// leaf metadata + proof blobs + verifier_data.
    pub fn restore_leaf_proofs_from_records(&mut self, records: Vec<LeafProofRecord<C, D>>) {
        self.leaf_proofs.clear();
        self.agg_proofs.clear();
        for r in records {
            self.leaf_proofs.push_back(r);
        }
    }

    pub async fn finalize_tree<T: PortableQTreeRecursion<C, D> + ?Sized>(&mut self, circuit_mgr: &T) -> anyhow::Result<()> {
        while self.prove_one_step_simple_serial(circuit_mgr).await? {
            // prove remaining tasks (if any)
        }

        // handle the case where there is one leaf proof
        let leaf_proofs_len = self.leaf_proofs.len();
        if leaf_proofs_len != 0 {
            assert_eq!(leaf_proofs_len, 1, "the only way leaf_proofs_len!=0 after while self.prove_one_step_simple_serial() should be if agg_proofs is empty and there is a single leaf proof");
            assert!(
                self.agg_proofs.is_empty(),
                "agg proofs should be empty if there is still a leaf proof in the queue after while self.prove_one_step_simple_serial()"
            );
            let dangling_leaf = self.leaf_proofs.pop_front().unwrap();
            println!("prove_single_leaf");

            let record = self.prove_single_leaf(circuit_mgr, &dangling_leaf).await?;
            self.agg_proofs.push(record);
        }

        Ok(())
    }
    /*
        pub fn get_root_verified_proof(&self, circuit_mgr: &PortableQTreeRecursionCircuits<C, D>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{

            if self.leaf_proofs.len() != 0 || self.agg_proofs.len() != 1 {
                anyhow::bail!("proof tree not yet finalized");
            }
            match self.agg_proofs.last() {
                Some(x) => {
                    circuit_mgr.root_circuit.prove_base(
                        circuit_mgr.circuit_inclusion_proofs.get_inclusion_proof_for_type(x.circuit_type),
                        &x.agg_header,
                        &x.proof,
                        circuit_mgr.circuit_set.get_verifier_data_by_type(x.circuit_type).await
                    )

                },
                None =>  anyhow::bail!("proof tree not yet finalized"),
            }
        }
    */
    pub async fn get_finalized_proot_tree_record(&self) -> anyhow::Result<&AggProofRecord<C, D>> {
        if self.leaf_proofs.len() != 0 || self.agg_proofs.len() != 1 {
            anyhow::bail!("proof tree not yet finalized");
        }
        match self.agg_proofs.last() {
            Some(x) => Ok(x),
            None => anyhow::bail!("proof tree not yet finalized"),
        }
    }
}
