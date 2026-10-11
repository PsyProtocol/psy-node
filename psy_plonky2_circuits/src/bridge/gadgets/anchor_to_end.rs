use parth_core::crypto::hash::traits::MerkleZeroHasher;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_common_circuits::hash::merkle::gadgets::historical_root_merkle_proof::HistoricalRootMerkleProofGadget;

#[derive(Debug)]
pub struct AnchorToEndTarget {
    pub historical: HistoricalRootMerkleProofGadget,
    pub anchor_root: HashOutTarget,
    pub end_root: HashOutTarget,
    pub anchor_checkpoint_id: Target,
    pub end_checkpoint_id: Target,
}

impl AnchorToEndTarget {
    pub fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        PoseidonHash: MerkleZeroHasher<HashOut<F>>,
    {
        let historical = HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<PoseidonHash, F, D>(
            builder,
            CHECKPOINT_TREE_HEIGHT as usize,
        );
        let end_checkpoint_id = builder.add_virtual_target();
        builder.range_check(end_checkpoint_id, CHECKPOINT_TREE_HEIGHT as usize);
        builder.ensure_is_less_than_or_equal(32, historical.index, end_checkpoint_id);
        let anchor_root = historical.historical_root;
        let end_root = historical.current_root;
        let anchor_checkpoint_id = historical.index;
        Self {
            historical,
            anchor_root,
            end_root,
            anchor_checkpoint_id,
            end_checkpoint_id,
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        anchor_checkpoint_id: F,
        end_checkpoint_id: F,
        anchor_leaf: HashOut<F>,
        siblings: &[HashOut<F>],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            siblings.len() == CHECKPOINT_TREE_HEIGHT as usize,
            "anchor-to-end path needs exactly {} siblings, got {}",
            CHECKPOINT_TREE_HEIGHT,
            siblings.len()
        );
        witness.set_target(self.historical.index, anchor_checkpoint_id)?;
        witness.set_target(self.end_checkpoint_id, end_checkpoint_id)?;
        witness.set_hash_target(self.historical.current_value, anchor_leaf)?;
        for (target, sibling) in self.historical.siblings.iter().zip(siblings) {
            witness.set_hash_target(*target, *sibling)?;
        }
        Ok(())
    }

    /// Empty ids fold both roots to `PoseidonHash::get_zero_hash(CHECKPOINT_TREE_HEIGHT)`, never `HashOut::ZERO`.
    pub fn set_witness_empty_tree<W: Witness<F>, F: RichField>(&self, witness: &mut W) -> anyhow::Result<()>
    where
        PoseidonHash: MerkleZeroHasher<HashOut<F>>,
    {
        self.set_witness(
            witness,
            F::ZERO,
            F::ZERO,
            HashOut::ZERO,
            &(0..CHECKPOINT_TREE_HEIGHT as usize)
                .map(|level| <PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(level))
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use parth_core::{
        crypto::hash::merkle_proof::{compute_historical_and_current_merkle_roots_core_gt, MerkleProofCore},
        pgoldilocks::QHashOut,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    fn anchor_to_end_circuit() -> (CircuitData<F, C, D>, AnchorToEndTarget) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = AnchorToEndTarget::add_virtual::<F, D>(&mut builder);
        builder.register_public_inputs(&targets.anchor_root.elements);
        builder.register_public_inputs(&targets.end_root.elements);
        let data = builder.build::<C>();
        (data, targets)
    }

    fn tree_with_leaves(count: u64) -> SimpleMerkleTree<PoseidonHash, QHashOut<F>> {
        let mut tree = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(CHECKPOINT_TREE_HEIGHT as u8);
        for i in 0..count {
            tree.set_leaf(i, QHashOut::from_values(1000 + i, 5, 16, i));
        }
        tree
    }

    fn truncated_checkpoint_root(tree: &SimpleMerkleTree<PoseidonHash, QHashOut<F>>, anchor: u64) -> QHashOut<F> {
        let mut truncated = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(CHECKPOINT_TREE_HEIGHT as u8);
        for index in 0..=anchor {
            truncated.set_leaf(index, tree.get_leaf_value(index));
        }
        truncated.get_root()
    }

    fn checkpoint_roots(
        tree: &SimpleMerkleTree<PoseidonHash, QHashOut<F>>,
        proof: &MerkleProofCore<QHashOut<F>>,
    ) -> (QHashOut<F>, QHashOut<F>) {
        let anchor_root = truncated_checkpoint_root(tree, proof.index);
        let end_root = tree.get_root();
        let folded = compute_historical_and_current_merkle_roots_core_gt::<QHashOut<F>, PoseidonHash>(proof);
        assert_eq!(folded.0, anchor_root, "host twin must match the checkpoint tree truncated after the anchor leaf");
        assert_eq!(folded.1, end_root, "host twin must match the finalized checkpoint tree");
        assert_eq!(proof.root, end_root, "membership proof must carry the finalized checkpoint root");
        (anchor_root, end_root)
    }

    fn sibling_hashes(proof: &MerkleProofCore<QHashOut<F>>, tamper: Option<usize>) -> Vec<HashOut<F>> {
        proof
            .siblings
            .iter()
            .enumerate()
            .map(|(i, sibling)| {
                let mut elements = sibling.0.elements;
                if Some(i) == tamper {
                    elements[0] = elements[0] + F::ONE;
                }
                HashOut { elements }
            })
            .collect()
    }

    fn anchor_leaf(proof: &MerkleProofCore<QHashOut<F>>, tamper: bool) -> HashOut<F> {
        let mut leaf = proof.value.0;
        if tamper {
            leaf.elements[0] = leaf.elements[0] + F::ONE;
        }
        leaf
    }

    fn rejects(data: &CircuitData<F, C, D>, witness: PartialWitness<F>) -> bool {
        match data.prove(witness) {
            Ok(proof) => data.verify(proof).is_err(),
            Err(_) => true,
        }
    }

    #[test]
    fn valid_anchor_to_end_upgrade_accepts() {
        let end_id: u64 = 4;
        let anchor_id: u64 = 1;
        let tree = tree_with_leaves(end_id + 1);
        let proof = tree.get_leaf(anchor_id);
        let (expected_anchor_root, expected_end_root) = checkpoint_roots(&tree, &proof);
        assert_ne!(
            expected_anchor_root, expected_end_root,
            "anchor strictly older than end must truncate the tree"
        );

        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets
            .set_witness(
                &mut witness,
                F::from_canonical_u64(anchor_id),
                F::from_canonical_u64(end_id),
                anchor_leaf(&proof, false),
                &sibling_hashes(&proof, None),
            )
            .unwrap();
        let proved = data.prove(witness).unwrap();
        assert_eq!(proved.public_inputs[0..4], expected_anchor_root.0.elements);
        assert_eq!(proved.public_inputs[4..8], expected_end_root.0.elements);
        data.verify(proved).unwrap();
    }

    #[test]
    fn anchor_equal_to_end_boundary_accepts() {
        let id: u64 = 3;
        let tree = tree_with_leaves(id + 1);
        let proof = tree.get_leaf(id);
        let (expected_anchor_root, expected_end_root) = checkpoint_roots(&tree, &proof);
        assert_eq!(
            expected_anchor_root, expected_end_root,
            "truncating at the last leaf keeps the full root"
        );

        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets
            .set_witness(
                &mut witness,
                F::from_canonical_u64(id),
                F::from_canonical_u64(id),
                anchor_leaf(&proof, false),
                &sibling_hashes(&proof, None),
            )
            .unwrap();
        let proved = data.prove(witness).unwrap();
        assert_eq!(proved.public_inputs[0..4], expected_end_root.0.elements);
        data.verify(proved).unwrap();
    }

    #[test]
    fn forked_end_root_rejects() {
        let end_id: u64 = 4;
        let anchor_id: u64 = 1;
        let tree = tree_with_leaves(end_id + 1);
        let proof = tree.get_leaf(anchor_id);
        let (expected_anchor_root, _expected_end_root) = checkpoint_roots(&tree, &proof);

        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets
            .set_witness(
                &mut witness,
                F::from_canonical_u64(anchor_id),
                F::from_canonical_u64(end_id),
                anchor_leaf(&proof, false),
                &sibling_hashes(&proof, None),
            )
            .unwrap();
        witness.set_hash_target(targets.end_root, expected_anchor_root.0).unwrap();
        assert!(rejects(&data, witness), "forked end root must be rejected");
    }

    #[test]
    fn forked_anchor_root_rejects() {
        let end_id: u64 = 4;
        let anchor_id: u64 = 1;
        let tree = tree_with_leaves(end_id + 1);
        let proof = tree.get_leaf(anchor_id);
        let (_expected_anchor_root, expected_end_root) = checkpoint_roots(&tree, &proof);

        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets
            .set_witness(
                &mut witness,
                F::from_canonical_u64(anchor_id),
                F::from_canonical_u64(end_id),
                anchor_leaf(&proof, false),
                &sibling_hashes(&proof, None),
            )
            .unwrap();
        witness.set_hash_target(targets.anchor_root, expected_end_root.0).unwrap();
        assert!(rejects(&data, witness), "forked anchor root must be rejected");
    }

    #[test]
    fn shifted_anchor_index_rejects() {
        let end_id: u64 = 4;
        let anchor_id: u64 = 1;
        let tree = tree_with_leaves(end_id + 1);
        let proof = tree.get_leaf(anchor_id);
        let (expected_anchor_root, expected_end_root) = checkpoint_roots(&tree, &proof);

        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets
            .set_witness(
                &mut witness,
                F::from_canonical_u64(anchor_id + 1),
                F::from_canonical_u64(end_id),
                anchor_leaf(&proof, false),
                &sibling_hashes(&proof, None),
            )
            .unwrap();
        witness.set_hash_target(targets.anchor_root, expected_anchor_root.0).unwrap();
        witness.set_hash_target(targets.end_root, expected_end_root.0).unwrap();
        assert!(rejects(&data, witness), "shifted anchor index must be rejected");
    }

    #[test]
    fn tampered_anchor_leaf_and_path_rejects() {
        let end_id: u64 = 4;
        let anchor_id: u64 = 1;
        let tree = tree_with_leaves(end_id + 1);
        let proof = tree.get_leaf(anchor_id);
        let (expected_anchor_root, expected_end_root) = checkpoint_roots(&tree, &proof);

        for mutation in 0..2 {
            let (data, targets) = anchor_to_end_circuit();
            let mut witness = PartialWitness::new();
            targets
                .set_witness(
                    &mut witness,
                    F::from_canonical_u64(anchor_id),
                    F::from_canonical_u64(end_id),
                    anchor_leaf(&proof, mutation == 0),
                    &sibling_hashes(&proof, if mutation == 0 { None } else { Some(0) }),
                )
                .unwrap();
            witness.set_hash_target(targets.anchor_root, expected_anchor_root.0).unwrap();
            witness.set_hash_target(targets.end_root, expected_end_root.0).unwrap();
            assert!(
                rejects(&data, witness),
                "tampered anchor-to-end witness mutation {mutation} must be rejected"
            );
        }
    }

    #[test]
    fn anchor_not_older_than_end_and_overflow_reject() {
        let end_id: u64 = 4;
        let anchor_id: u64 = 1;
        let tree = tree_with_leaves(end_id + 1);
        let proof = tree.get_leaf(anchor_id);

        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets
            .set_witness(
                &mut witness,
                F::from_canonical_u64(end_id + 1),
                F::from_canonical_u64(end_id),
                anchor_leaf(&proof, false),
                &sibling_hashes(&proof, None),
            )
            .unwrap();
        assert!(rejects(&data, witness), "anchor newer than end must be rejected");

        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets
            .set_witness(
                &mut witness,
                F::from_canonical_u64(anchor_id),
                F::from_canonical_u64(1u64 << 32),
                anchor_leaf(&proof, false),
                &sibling_hashes(&proof, None),
            )
            .unwrap();
        assert!(rejects(&data, witness), "end id above 32 bits must be rejected");
    }

    #[test]
    fn missing_witness_fails_closed_against_authenticated_roots() {
        let end_id: u64 = 4;
        let anchor_id: u64 = 1;
        let tree = tree_with_leaves(end_id + 1);
        let proof = tree.get_leaf(anchor_id);
        let (expected_anchor_root, expected_end_root) = checkpoint_roots(&tree, &proof);

        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        witness.set_hash_target(targets.anchor_root, expected_anchor_root.0).unwrap();
        witness.set_hash_target(targets.end_root, expected_end_root.0).unwrap();
        assert!(rejects(&data, witness), "missing anchor-to-end witness must fail closed");
    }

    #[test]
    fn inactive_empty_tree_encoding_folds_both_roots_to_empty_checkpoint_root() {
        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets.set_witness_empty_tree(&mut witness).unwrap();
        let proved = data.prove(witness).unwrap();
        let empty_root = <PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(CHECKPOINT_TREE_HEIGHT as usize);
        let empty_tree = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(CHECKPOINT_TREE_HEIGHT as u8);
        assert_eq!(empty_tree.get_root().0, empty_root, "inactive anchor must be the empty checkpoint tree");
        assert_ne!(empty_root, HashOut::ZERO, "level-specific empty siblings must not collapse to the zero word");
        assert_eq!(proved.public_inputs[0..4], empty_root.elements);
        assert_eq!(proved.public_inputs[4..8], empty_root.elements);
        data.verify(proved).unwrap();
    }
    #[test]
    fn zero_siblings_do_not_authenticate_the_empty_checkpoint_tree() {
        let empty_root = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(CHECKPOINT_TREE_HEIGHT as u8).get_root();
        let (data, targets) = anchor_to_end_circuit();
        let mut witness = PartialWitness::new();
        targets
            .set_witness(
                &mut witness,
                F::ZERO,
                F::ZERO,
                HashOut::ZERO,
                &vec![HashOut::ZERO; CHECKPOINT_TREE_HEIGHT as usize],
            )
            .unwrap();
        witness.set_hash_target(targets.anchor_root, empty_root.0).unwrap();
        witness.set_hash_target(targets.end_root, empty_root.0).unwrap();
        assert!(
            rejects(&data, witness),
            "zero-word siblings must not authenticate the empty checkpoint tree"
        );
    }

}
