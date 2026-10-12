use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher},
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_plonky2_circuits::bridge::gadgets::anchor_to_end::AnchorToEndTarget;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type CheckpointTree = SimpleMerkleTree<PoseidonHash, QHashOut<F>>;

fn circuit() -> (CircuitData<F, C, D>, AnchorToEndTarget) {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = AnchorToEndTarget::add_virtual(&mut builder);
    builder.register_public_inputs(&targets.anchor_root.elements);
    builder.register_public_inputs(&targets.end_root.elements);
    (builder.build::<C>(), targets)
}

fn leaf(index: u64) -> QHashOut<F> {
    QHashOut::from_values(1000 + index, 5, 16, index)
}

fn siblings(proof: &MerkleProofCore<QHashOut<F>>) -> Vec<HashOut<F>> {
    assert_eq!(proof.siblings.len(), CHECKPOINT_TREE_HEIGHT as usize);
    proof.siblings.iter().map(|sibling| sibling.0).collect()
}

fn extend_after(tree: &mut CheckpointTree, anchor: u64, end: u64) -> (QHashOut<F>, QHashOut<F>) {
    for index in 0..=anchor {
        tree.set_leaf(index, leaf(index));
    }
    let anchor_root = tree.get_root();
    for index in (anchor + 1)..=end {
        tree.set_leaf(index, leaf(index));
    }
    (anchor_root, tree.get_root())
}

fn rejects(data: &CircuitData<F, C, D>, witness: PartialWitness<F>) -> bool {
    match data.prove(witness) {
        Ok(proof) => data.verify(proof).is_err(),
        Err(_) => true,
    }
}

fn publishes(
    data: &CircuitData<F, C, D>,
    targets: &AnchorToEndTarget,
    anchor_id: u64,
    end_id: u64,
    proof: &MerkleProofCore<QHashOut<F>>,
    anchor_root: QHashOut<F>,
    end_root: QHashOut<F>,
) {
    let mut witness = PartialWitness::new();
    targets
        .set_witness(
            &mut witness,
            F::from_canonical_u64(anchor_id),
            F::from_canonical_u64(end_id),
            proof.value.0,
            &siblings(proof),
        )
        .unwrap();
    let proved = data.prove(witness).unwrap();
    assert_eq!(proved.public_inputs[0..4], anchor_root.0.elements, "anchor root");
    assert_eq!(proved.public_inputs[4..8], end_root.0.elements, "end root");
    data.verify(proved).unwrap();
}

fn pinned(
    targets: &AnchorToEndTarget,
    anchor_id: u64,
    end_id: u64,
    anchor_leaf: HashOut<F>,
    siblings: &[HashOut<F>],
    anchor_root: QHashOut<F>,
    end_root: QHashOut<F>,
) -> PartialWitness<F> {
    let mut witness = PartialWitness::new();
    targets
        .set_witness(
            &mut witness,
            F::from_canonical_u64(anchor_id),
            F::from_canonical_u64(end_id),
            anchor_leaf,
            siblings,
        )
        .unwrap();
    witness.set_hash_target(targets.anchor_root, anchor_root.0).unwrap();
    witness.set_hash_target(targets.end_root, end_root.0).unwrap();
    witness
}

#[test]
fn checkpoint_snapshots_bind_anchor_membership_and_end_update() {
    let (data, targets) = circuit();
    let empty_root = CheckpointTree::new(CHECKPOINT_TREE_HEIGHT as u8).get_root();

    // The greater-than truncation keeps leaf 0. A greater-than-or-equal fold would
    // publish the empty checkpoint root instead of the snapshot taken after that leaf.
    let mut tree = CheckpointTree::new(CHECKPOINT_TREE_HEIGHT as u8);
    let (anchor_root, end_root) = extend_after(&mut tree, 0, 4);
    assert_ne!(anchor_root, empty_root, "anchor leaf 0 must remain in the truncated tree");
    assert_ne!(anchor_root, end_root, "later checkpoints must move only the end root");
    publishes(&data, &targets, 0, 4, &tree.get_leaf(0), anchor_root, end_root);

    let mut tree = CheckpointTree::new(CHECKPOINT_TREE_HEIGHT as u8);
    let (anchor_root, end_root) = extend_after(&mut tree, 1, 4);
    assert_ne!(anchor_root, end_root);
    publishes(&data, &targets, 1, 4, &tree.get_leaf(1), anchor_root, end_root);

    let mut tree = CheckpointTree::new(CHECKPOINT_TREE_HEIGHT as u8);
    let (anchor_root, end_root) = extend_after(&mut tree, 3, 3);
    assert_eq!(anchor_root, end_root, "truncating at the last leaf keeps the finalized root");
    publishes(&data, &targets, 3, 3, &tree.get_leaf(3), anchor_root, end_root);
}

#[test]
fn inactive_anchor_binds_the_empty_checkpoint_tree_not_zero_siblings() {
    let empty_root = CheckpointTree::new(CHECKPOINT_TREE_HEIGHT as u8).get_root();
    assert_ne!(empty_root.0, HashOut::ZERO);
    assert_eq!(
        empty_root.0,
        <PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(CHECKPOINT_TREE_HEIGHT as usize),
    );
    let (data, targets) = circuit();
    let mut witness = PartialWitness::new();
    targets.set_witness_empty_tree(&mut witness).unwrap();
    let proved = data.prove(witness).unwrap();
    assert_eq!(proved.public_inputs[0..4], empty_root.0.elements);
    assert_eq!(proved.public_inputs[4..8], empty_root.0.elements);
    data.verify(proved).unwrap();

    let witness = pinned(
        &targets,
        0,
        0,
        HashOut::ZERO,
        &vec![HashOut::ZERO; CHECKPOINT_TREE_HEIGHT as usize],
        empty_root,
        empty_root,
    );
    assert!(rejects(&data, witness), "zero-word siblings must not authenticate the empty checkpoint tree");
}

#[test]
fn forked_stale_and_tampered_anchor_paths_reject() {
    let mut tree = CheckpointTree::new(CHECKPOINT_TREE_HEIGHT as u8);
    let (anchor_root, end_root) = extend_after(&mut tree, 1, 4);
    let fresh = tree.get_leaf(1);
    let mut stale_tree = CheckpointTree::new(CHECKPOINT_TREE_HEIGHT as u8);
    stale_tree.set_leaf(0, leaf(0));
    stale_tree.set_leaf(1, leaf(1));
    let stale = stale_tree.get_leaf(1);
    assert_eq!(stale_tree.get_root(), anchor_root);
    assert_ne!(anchor_root, end_root);
    let (data, targets) = circuit();

    assert!(
        rejects(&data, pinned(&targets, 1, 4, fresh.value.0, &siblings(&fresh), anchor_root, anchor_root)),
        "forked end root must be rejected",
    );
    assert!(
        rejects(&data, pinned(&targets, 1, 4, fresh.value.0, &siblings(&fresh), end_root, end_root)),
        "forked anchor root must be rejected",
    );
    assert!(
        rejects(&data, pinned(&targets, 1, 4, stale.value.0, &siblings(&stale), anchor_root, end_root)),
        "path from the truncated tree must not authenticate the later end root",
    );
    assert!(
        rejects(&data, pinned(&targets, 2, 4, fresh.value.0, &siblings(&fresh), anchor_root, end_root)),
        "shifted anchor checkpoint must be rejected",
    );

    let mut tampered_leaf = fresh.value.0;
    tampered_leaf.elements[0] += F::ONE;
    assert!(
        rejects(&data, pinned(&targets, 1, 4, tampered_leaf, &siblings(&fresh), anchor_root, end_root)),
        "tampered anchor leaf must be rejected",
    );
    for level in [0usize, CHECKPOINT_TREE_HEIGHT as usize - 1] {
        let mut path = siblings(&fresh);
        path[level].elements[0] += F::ONE;
        assert!(
            rejects(&data, pinned(&targets, 1, 4, fresh.value.0, &path, anchor_root, end_root)),
            "tampered sibling at level {level} must be rejected",
        );
    }
}

#[test]
fn anchor_bounds_and_missing_path_fail_closed() {
    let mut tree = CheckpointTree::new(CHECKPOINT_TREE_HEIGHT as u8);
    let (anchor_root, end_root) = extend_after(&mut tree, 1, 4);
    let proof = tree.get_leaf(1);
    let (data, targets) = circuit();

    assert!(
        rejects(&data, pinned(&targets, 5, 4, proof.value.0, &siblings(&proof), anchor_root, end_root)),
        "anchor newer than end must be rejected",
    );
    assert!(
        rejects(
            &data,
            pinned(&targets, 1, 1u64 << 32, proof.value.0, &siblings(&proof), anchor_root, end_root),
        ),
        "end id above 32 bits must be rejected",
    );

    let mut witness = PartialWitness::new();
    witness.set_hash_target(targets.anchor_root, anchor_root.0).unwrap();
    witness.set_hash_target(targets.end_root, end_root.0).unwrap();
    assert!(rejects(&data, witness), "missing anchor-to-end path must fail closed");
}
