//! Circuit gadgets for Indexed Merkle Tree (IMT) contract state operations.
//!
//! Provides:
//! - [`IMTLeafTargets`]: Circuit targets for an IMT leaf's 13 field elements
//! - [`is_qhashout_lte`] / [`is_qhashout_lt`]: MSL-first 256-bit key comparison
//!   in-circuit
//! - [`IMTUpdateGadget`]: Verifies a value-only update (1 delta merkle proof)
//! - [`IMTInsertGadget`]: Verifies a key insertion (2 delta merkle proofs + key
//!   ordering)
//! - [`verify_imt_non_membership`]: Standalone non-membership verification

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf;
use psy_crypto::hash::merkle::core::DeltaMerkleProofCore;

use super::delta_merkle_proof::{DeltaMerkleProofGadget, OptionalDeltaMerkleProofGadget};
use crate::builder::comparison::CircuitBuilderComparison;

// ---------------------------------------------------------------------------
// IMT leaf targets
// ---------------------------------------------------------------------------

/// Circuit targets for an IMT leaf preimage (13 field elements).
///
/// Layout matches [`IMTContractStateLeaf`]:
/// - `key`: 4 field elements (256-bit storage key)
/// - `value`: 4 field elements (256-bit storage value)
/// - `next_key`: 4 field elements (successor key in sorted linked list)
/// - `next_index`: 1 field element (successor leaf index)
#[derive(Debug, Clone)]
pub struct IMTLeafTargets {
    pub key: HashOutTarget,
    pub value: HashOutTarget,
    pub next_key: HashOutTarget,
    pub next_index: Target,
}

impl IMTLeafTargets {
    /// Create virtual (unconstrained) circuit targets for an IMT leaf.
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            key: builder.add_virtual_hash(),
            value: builder.add_virtual_hash(),
            next_key: builder.add_virtual_hash(),
            next_index: builder.add_virtual_target(),
        }
    }

    /// Compute the leaf hash in-circuit.
    ///
    /// Uses `hash_n_to_hash_no_pad` on the 13 field elements:
    /// `key[0..4] || value[0..4] || next_key[0..4] || next_index`
    ///
    /// This matches [`IMTContractStateLeaf::qfhash`] which calls
    /// `H::q_hash_many()` (i.e., `hash_no_pad`) on the same 13 elements.
    pub fn hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(vec![
            self.key.elements[0],
            self.key.elements[1],
            self.key.elements[2],
            self.key.elements[3],
            self.value.elements[0],
            self.value.elements[1],
            self.value.elements[2],
            self.value.elements[3],
            self.next_key.elements[0],
            self.next_key.elements[1],
            self.next_key.elements[2],
            self.next_key.elements[3],
            self.next_index,
        ])
    }

    /// Set witness values from an [`IMTContractStateLeaf`].
    pub fn set_witness<W: Witness<F>, F: RichField>(&self, witness: &mut W, leaf: &IMTContractStateLeaf<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.key, leaf.key.0)?;
        witness.set_hash_target(self.value, leaf.value.0)?;
        witness.set_hash_target(self.next_key, leaf.next_key.0)?;
        witness.set_target(self.next_index, leaf.next_index)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 256-bit key comparison (MSL-first)
// ---------------------------------------------------------------------------

/// Compare two `QHashOut` values in-circuit: returns `a <= b` using MSL-first
/// ordering.
///
/// Most-significant-limb-first means `elements[3]` is compared first. If equal,
/// `elements[2]` breaks the tie, and so on down to `elements[0]`.
///
/// Implementation processes from least-significant element (0) to
/// most-significant (3). Each iteration: if elements are equal, carry the
/// previous result; otherwise, use this element's comparison. The last
/// non-equal element (most significant) determines the final outcome.
///
/// This matches
/// [`compare_qhashout_keys`](psy_client_data::qdata::imt_contract_state::compare_qhashout_keys).
///
pub fn is_qhashout_lte<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: HashOutTarget,
    b: HashOutTarget,
) -> BoolTarget {
    let mut result = builder._true();
    for i in 0..4 {
        let a_lte_b = builder.is_less_than_or_equal(64, a.elements[i], b.elements[i]);
        let equal = builder.is_equal(a.elements[i], b.elements[i]);
        let result_target = builder.select(equal, result.target, a_lte_b.target);
        result = BoolTarget::new_unsafe(result_target);
    }
    result
}

/// Compare two `QHashOut` values in-circuit: returns `a < b` (strict) using
/// MSL-first ordering.
pub fn is_qhashout_lt<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: HashOutTarget,
    b: HashOutTarget,
) -> BoolTarget {
    let is_lte = is_qhashout_lte(builder, a, b);
    let is_eq = builder.is_equal_hash(a, b);
    let is_not_eq = builder.not(is_eq);
    builder.and(is_lte, is_not_eq)
}

// ---------------------------------------------------------------------------
// IMT update gadget
// ---------------------------------------------------------------------------

/// Gadget for verifying an IMT value-only update in-circuit.
///
/// Proves that a leaf's value changed while its key and linked-list pointers
/// remained the same. Uses one [`DeltaMerkleProofGadget`].
///
/// Constraints enforced:
/// 1. `old_leaf.key == new_leaf.key`
/// 2. `old_leaf.next_key == new_leaf.next_key`
/// 3. `old_leaf.next_index == new_leaf.next_index`
/// 4. `delta_proof.old_value == hash(old_leaf)`
/// 5. `delta_proof.new_value == hash(new_leaf)`
#[derive(Debug, Clone)]
pub struct IMTUpdateGadget {
    pub old_leaf: IMTLeafTargets,
    pub new_leaf: IMTLeafTargets,
    pub delta_proof: DeltaMerkleProofGadget,
}

impl IMTUpdateGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        tree_height: usize,
    ) -> Self {
        let old_leaf = IMTLeafTargets::add_virtual_to(builder);
        let new_leaf = IMTLeafTargets::add_virtual_to(builder);

        // Compute leaf hashes in-circuit
        let old_leaf_hash = old_leaf.hash::<H, F, D>(builder);
        let new_leaf_hash = new_leaf.hash::<H, F, D>(builder);

        // Create delta merkle proof with pre-connected leaf hash values
        let delta_proof = DeltaMerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            tree_height,
            OptionalDeltaMerkleProofGadget {
                old_root: None,
                old_value: Some(old_leaf_hash),
                new_root: None,
                new_value: Some(new_leaf_hash),
                index: None,
                siblings: None,
            },
        );

        // Key must not change
        builder.connect_hashes(old_leaf.key, new_leaf.key);
        // Linked-list pointers must not change
        builder.connect_hashes(old_leaf.next_key, new_leaf.next_key);
        builder.connect(old_leaf.next_index, new_leaf.next_index);

        Self {
            old_leaf,
            new_leaf,
            delta_proof,
        }
    }

    /// Set witness values for an IMT update verification.
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        old_leaf: &IMTContractStateLeaf<F>,
        new_leaf: &IMTContractStateLeaf<F>,
        proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.old_leaf.set_witness(witness, old_leaf)?;
        self.new_leaf.set_witness(witness, new_leaf)?;
        self.delta_proof.set_witness_core_proof_q(witness, proof)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IMT insert gadget
// ---------------------------------------------------------------------------

/// Gadget for verifying an IMT key insertion in-circuit.
///
/// Proves that a new key was inserted with correct linked-list pointer updates.
/// Uses two [`DeltaMerkleProofGadget`]s: one for the predecessor update and one
/// for the new leaf append.
///
/// Constraints enforced:
/// 1. Predecessor key unchanged: `predecessor_old.key == predecessor_new.key`
/// 2. Predecessor value unchanged: `predecessor_old.value ==
///    predecessor_new.value`
/// 3. New leaf inherits predecessor's old next: `new_leaf.next_key ==
///    predecessor_old.next_key`
/// 4. `new_leaf.next_index == predecessor_old.next_index`
/// 5. Predecessor now points to new leaf: `predecessor_new.next_key ==
///    new_leaf.key`
/// 6. `predecessor_new.next_index == new_leaf_index`
/// 7. Key ordering: `predecessor_old.key < new_leaf.key`
/// 8. Key ordering: `new_leaf.key < predecessor_old.next_key` OR `next_key ==
///    0` (end of list)
/// 9. New leaf slot was empty: old_value in the new-leaf proof is zero
/// 10. Proof chaining: `predecessor_proof.new_root == new_leaf_proof.old_root`
#[derive(Debug, Clone)]
pub struct IMTInsertGadget {
    pub predecessor_old_leaf: IMTLeafTargets,
    pub predecessor_new_leaf: IMTLeafTargets,
    pub new_leaf: IMTLeafTargets,
    pub new_leaf_index: Target,
    pub predecessor_delta_proof: DeltaMerkleProofGadget,
    pub new_leaf_delta_proof: DeltaMerkleProofGadget,
}

impl IMTInsertGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        tree_height: usize,
    ) -> Self {
        let predecessor_old_leaf = IMTLeafTargets::add_virtual_to(builder);
        let predecessor_new_leaf = IMTLeafTargets::add_virtual_to(builder);
        let new_leaf = IMTLeafTargets::add_virtual_to(builder);
        let new_leaf_index = builder.add_virtual_target();

        // Compute leaf hashes
        let pred_old_hash = predecessor_old_leaf.hash::<H, F, D>(builder);
        let pred_new_hash = predecessor_new_leaf.hash::<H, F, D>(builder);
        let new_leaf_hash = new_leaf.hash::<H, F, D>(builder);
        let zero_hash = builder.constant_hash(HashOut::ZERO);

        // Predecessor delta proof
        let predecessor_delta_proof = DeltaMerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            tree_height,
            OptionalDeltaMerkleProofGadget {
                old_root: None,
                old_value: Some(pred_old_hash),
                new_root: None,
                new_value: Some(pred_new_hash),
                index: None,
                siblings: None,
            },
        );

        // New leaf delta proof (chained from predecessor, append into empty slot)
        let new_leaf_delta_proof = DeltaMerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            tree_height,
            OptionalDeltaMerkleProofGadget {
                old_root: Some(predecessor_delta_proof.new_root), // chain
                old_value: Some(zero_hash),                       // slot was empty
                new_root: None,
                new_value: Some(new_leaf_hash),
                index: Some(new_leaf_index),
                siblings: None,
            },
        );

        // --- Linked-list pointer constraints ---

        // Predecessor key unchanged
        builder.connect_hashes(predecessor_old_leaf.key, predecessor_new_leaf.key);
        // Predecessor value unchanged
        builder.connect_hashes(predecessor_old_leaf.value, predecessor_new_leaf.value);

        // New leaf inherits predecessor's old next pointer
        builder.connect_hashes(new_leaf.next_key, predecessor_old_leaf.next_key);
        builder.connect(new_leaf.next_index, predecessor_old_leaf.next_index);

        // Predecessor now points to new leaf
        builder.connect_hashes(predecessor_new_leaf.next_key, new_leaf.key);
        builder.connect(predecessor_new_leaf.next_index, new_leaf_index);

        // --- Key ordering constraints ---

        // predecessor.key < new_leaf.key
        let pred_lt_new = is_qhashout_lt::<F, D>(builder, predecessor_old_leaf.key, new_leaf.key);
        let true_target = builder._true();
        builder.connect(pred_lt_new.target, true_target.target);

        // new_leaf.key < predecessor.next_key OR predecessor.next_key == 0 (end of
        // list)
        let next_key_is_zero = builder.is_zero_hash(predecessor_old_leaf.next_key);
        let new_lt_next = is_qhashout_lt::<F, D>(builder, new_leaf.key, predecessor_old_leaf.next_key);
        let ordering_valid = builder.or(next_key_is_zero, new_lt_next);
        builder.connect(ordering_valid.target, true_target.target);

        Self {
            predecessor_old_leaf,
            predecessor_new_leaf,
            new_leaf,
            new_leaf_index,
            predecessor_delta_proof,
            new_leaf_delta_proof,
        }
    }

    /// Set witness values for an IMT insert verification.
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        predecessor_old_leaf: &IMTContractStateLeaf<F>,
        predecessor_new_leaf: &IMTContractStateLeaf<F>,
        new_leaf: &IMTContractStateLeaf<F>,
        new_leaf_index: u64,
        predecessor_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        new_leaf_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.predecessor_old_leaf.set_witness(witness, predecessor_old_leaf)?;
        self.predecessor_new_leaf.set_witness(witness, predecessor_new_leaf)?;
        self.new_leaf.set_witness(witness, new_leaf)?;
        witness.set_target(self.new_leaf_index, F::from_canonical_u64(new_leaf_index))?;
        self.predecessor_delta_proof.set_witness_core_proof_q(witness, predecessor_proof)?;
        self.new_leaf_delta_proof.set_witness_core_proof_q(witness, new_leaf_proof)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Non-membership verification (standalone)
// ---------------------------------------------------------------------------

/// Verify an IMT non-membership proof in circuit.
///
/// Given a predecessor leaf and a target key, enforces:
/// 1. `predecessor_leaf.key < new_key`
/// 2. `new_key < predecessor_leaf.next_key` OR `predecessor_leaf.next_key == 0`
///    (end of list)
///
/// This proves that `new_key` does not exist in the IMT: the predecessor leaf's
/// position in the sorted linked list means there is no leaf between
/// `predecessor_leaf.key` and `predecessor_leaf.next_key`.
///
/// Note: the caller is responsible for also verifying a merkle proof that the
/// predecessor leaf actually exists in the tree at the claimed root.
pub fn verify_imt_non_membership<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    predecessor_leaf: &IMTLeafTargets,
    new_key: HashOutTarget,
) {
    // Verify predecessor.key < new_key
    let pred_lt_new = is_qhashout_lt::<F, D>(builder, predecessor_leaf.key, new_key);
    let one = builder._true();
    builder.connect(pred_lt_new.target, one.target);

    // Verify new_key < predecessor.next_key OR predecessor.next_key == 0 (last in
    // list)
    let next_key_zero = builder.is_zero_hash(predecessor_leaf.next_key);
    let new_lt_next = is_qhashout_lt::<F, D>(builder, new_key, predecessor_leaf.next_key);
    let valid = builder.or(next_key_zero, new_lt_next);
    builder.connect(valid.target, one.target);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use kvq::memory::simple::KVQSimpleMemoryBackingStore;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::poseidon::{PoseidonHash, PoseidonHash as PsyHasher},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use psy_client_data::{models::imt::IndexedMerkleTree, qdata::imt_proof::IMTContractStateUpdate};
    use psy_crypto::hash::traits::{hasher::PoseidonHasher, qhashable::QFieldHashable};

    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Store = KVQSimpleMemoryBackingStore;
    type IMT = IndexedMerkleTree<Store, F, PsyHasher>;

    const TEST_TREE_HEIGHT: usize = 8; // small height for fast tests

    #[test]
    fn test_imt_leaf_hash_matches_native() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf_targets = IMTLeafTargets::add_virtual_to(&mut builder);
        let hash_target = leaf_targets.hash::<PoseidonHash, F, D>(&mut builder);

        // Expose hash as public output
        builder.register_public_inputs(&hash_target.elements);

        let data = builder.build::<C>();

        // Create a test leaf and compute its native hash
        let leaf = IMTContractStateLeaf::<F>::new(
            QHashOut::from_values(1, 2, 3, 4),
            QHashOut::from_values(5, 6, 7, 8),
            QHashOut::from_values(9, 10, 11, 12),
            F::from_canonical_u64(42),
        );
        let native_hash = leaf.qfhash::<PoseidonHasher>();

        let mut pw = PartialWitness::new();
        leaf_targets.set_witness(&mut pw, &leaf).unwrap();
        let proof = data.prove(pw).unwrap();

        // Verify circuit hash matches native hash
        assert_eq!(proof.public_inputs[0], native_hash.0.elements[0]);
        assert_eq!(proof.public_inputs[1], native_hash.0.elements[1]);
        assert_eq!(proof.public_inputs[2], native_hash.0.elements[2]);
        assert_eq!(proof.public_inputs[3], native_hash.0.elements[3]);

        data.verify(proof).unwrap();
    }

    #[test]
    fn test_qhashout_comparison_less_than() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.add_virtual_hash();
        let b = builder.add_virtual_hash();

        let lt_result = is_qhashout_lt::<F, D>(&mut builder, a, b);
        builder.register_public_input(lt_result.target);

        let data = builder.build::<C>();

        // Case 1: a < b (MSL differs)
        let val_a = QHashOut::<F>::from_values(999, 999, 999, 1);
        let val_b = QHashOut::<F>::from_values(0, 0, 0, 2);

        let mut pw = PartialWitness::new();
        pw.set_hash_target(a, val_a.0).unwrap();
        pw.set_hash_target(b, val_b.0).unwrap();
        let proof = data.prove(pw).unwrap();
        assert_eq!(proof.public_inputs[0], F::ONE); // a < b => true
        data.verify(proof).unwrap();

        // Case 2: a > b (MSL differs)
        let val_a = QHashOut::<F>::from_values(0, 0, 0, 2);
        let val_b = QHashOut::<F>::from_values(999, 999, 999, 1);

        let mut pw = PartialWitness::new();
        pw.set_hash_target(a, val_a.0).unwrap();
        pw.set_hash_target(b, val_b.0).unwrap();
        let proof = data.prove(pw).unwrap();
        assert_eq!(proof.public_inputs[0], F::ZERO); // a > b => false
        data.verify(proof).unwrap();

        // Case 3: a == b
        let val = QHashOut::<F>::from_values(1, 2, 3, 4);

        let mut pw = PartialWitness::new();
        pw.set_hash_target(a, val.0).unwrap();
        pw.set_hash_target(b, val.0).unwrap();
        let proof = data.prove(pw).unwrap();
        assert_eq!(proof.public_inputs[0], F::ZERO); // a == b => false (strict)
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_qhashout_comparison_lsl_tiebreak() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.add_virtual_hash();
        let b = builder.add_virtual_hash();

        let lt_result = is_qhashout_lt::<F, D>(&mut builder, a, b);
        builder.register_public_input(lt_result.target);

        let data = builder.build::<C>();

        // LSL tiebreak: elements[3..1] equal, elements[0] differs
        let val_a = QHashOut::<F>::from_values(1, 5, 5, 5);
        let val_b = QHashOut::<F>::from_values(2, 5, 5, 5);

        let mut pw = PartialWitness::new();
        pw.set_hash_target(a, val_a.0).unwrap();
        pw.set_hash_target(b, val_b.0).unwrap();
        let proof = data.prove(pw).unwrap();
        assert_eq!(proof.public_inputs[0], F::ONE); // a < b
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_imt_update_gadget() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let key = QHashOut::from_values(10, 0, 0, 0);
        let val1 = QHashOut::from_values(100, 0, 0, 0);
        let val2 = QHashOut::from_values(200, 0, 0, 0);

        imt.insert(&store, key, val1).unwrap();
        let update = imt.update(&store, key, val2).unwrap();

        let (old_leaf, new_leaf, delta_proof) = match update {
            IMTContractStateUpdate::Update {
                old_preimage,
                new_preimage,
                delta_proof,
            } => (old_preimage, new_preimage, delta_proof),
            _ => panic!("expected update"),
        };

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let gadget = IMTUpdateGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, TEST_TREE_HEIGHT);

        // Expose roots as public outputs for verification
        builder.register_public_inputs(&gadget.delta_proof.old_root.elements);
        builder.register_public_inputs(&gadget.delta_proof.new_root.elements);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        gadget.set_witness(&mut pw, &old_leaf, &new_leaf, &delta_proof).unwrap();

        let proof = data.prove(pw).unwrap();

        // Verify circuit-computed roots match the actual proof roots
        assert_eq!(proof.public_inputs[0], delta_proof.old_root.0.elements[0]);
        assert_eq!(proof.public_inputs[4], delta_proof.new_root.0.elements[0]);

        data.verify(proof).unwrap();
    }

    #[test]
    fn test_imt_insert_gadget() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let key = QHashOut::from_values(10, 0, 0, 0);
        let value = QHashOut::from_values(100, 200, 300, 400);

        let update = imt.insert(&store, key, value).unwrap();

        let (predecessor_old_leaf, predecessor_new_leaf, new_leaf, predecessor_delta_proof, new_leaf_delta_proof) = match update {
            IMTContractStateUpdate::Insert {
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            } => (
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            ),
            _ => panic!("expected insert"),
        };

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let gadget = IMTInsertGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, TEST_TREE_HEIGHT);

        // Expose start/end roots
        builder.register_public_inputs(&gadget.predecessor_delta_proof.old_root.elements);
        builder.register_public_inputs(&gadget.new_leaf_delta_proof.new_root.elements);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        gadget
            .set_witness(
                &mut pw,
                &predecessor_old_leaf,
                &predecessor_new_leaf,
                &new_leaf,
                new_leaf_delta_proof.index,
                &predecessor_delta_proof,
                &new_leaf_delta_proof,
            )
            .unwrap();

        let proof = data.prove(pw).unwrap();

        // Verify roots
        assert_eq!(proof.public_inputs[0], predecessor_delta_proof.old_root.0.elements[0]);
        assert_eq!(proof.public_inputs[4], new_leaf_delta_proof.new_root.0.elements[0]);

        data.verify(proof).unwrap();
    }

    #[test]
    fn test_imt_insert_middle_of_list() {
        // Insert keys out of order: 30, then 10 (between sentinel and 30)
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let key_30 = QHashOut::from_values(30, 0, 0, 0);
        let key_10 = QHashOut::from_values(10, 0, 0, 0);
        let val = QHashOut::from_values(1, 0, 0, 0);

        imt.insert(&store, key_30, val).unwrap();
        let update = imt.insert(&store, key_10, val).unwrap();

        let (predecessor_old_leaf, predecessor_new_leaf, new_leaf, predecessor_delta_proof, new_leaf_delta_proof) = match update {
            IMTContractStateUpdate::Insert {
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            } => (
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            ),
            _ => panic!("expected insert"),
        };

        // The predecessor should be sentinel (key=0), and new_leaf.next_key should be
        // 30
        assert_eq!(predecessor_old_leaf.key, QHashOut::ZERO);
        assert_eq!(new_leaf.next_key, key_30);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let gadget = IMTInsertGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, TEST_TREE_HEIGHT);
        builder.register_public_inputs(&gadget.predecessor_delta_proof.old_root.elements);
        builder.register_public_inputs(&gadget.new_leaf_delta_proof.new_root.elements);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        gadget
            .set_witness(
                &mut pw,
                &predecessor_old_leaf,
                &predecessor_new_leaf,
                &new_leaf,
                new_leaf_delta_proof.index,
                &predecessor_delta_proof,
                &new_leaf_delta_proof,
            )
            .unwrap();

        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
