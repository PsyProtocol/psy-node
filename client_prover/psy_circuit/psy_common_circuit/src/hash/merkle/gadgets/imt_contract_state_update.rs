//! Circuit gadgets for Indexed Merkle Tree (IMT) contract state operations.
//!
//! Provides:
//! - [`IMTLeafTargets`]: Circuit targets for an IMT leaf's 13 field elements
//! - [`is_qhashout_lte`] / [`is_qhashout_lt`]: MSL-first 256-bit key comparison
//!   in-circuit
//! - [`IMTUpdateGadget`]: Verifies a value-only update (1 delta merkle proof)
//! - [`IMTInsertGadget`]: Verifies a counted insertion (predecessor, member,
//!   and sentinel-count delta proofs)
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
use psy_crypto::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};

use super::{
    delta_merkle_proof::{DeltaMerkleProofGadget, OptionalDeltaMerkleProofGadget},
    merkle_proof::MerkleProofGadget,
};
use crate::builder::{
    comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, math::core::CircuitBuilderCoreMathHelpers,
};

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

/// Gadget for verifying one counted IMT insertion.
///
/// Root order is mandatory: predecessor splice R0->R1, member insertion
/// R1->R2, then sentinel count R2->R3. The sentinel delta's new root is the
/// insertion's final root. Stable virgin state is physical zero and is never
/// treated as the hash of the transient count-zero sentinel.
#[derive(Debug, Clone)]
pub struct IMTInsertGadget {
    pub state_slot_base: Target,
    pub capacity: Target,
    pub predecessor_old_leaf: IMTLeafTargets,
    pub predecessor_new_leaf: IMTLeafTargets,
    pub new_leaf: IMTLeafTargets,
    pub new_leaf_index: Target,
    pub predecessor_delta_proof: DeltaMerkleProofGadget,
    pub new_leaf_delta_proof: DeltaMerkleProofGadget,
    pub sentinel_preimage: IMTLeafTargets,
    pub sentinel_merkle_proof: MerkleProofGadget,
    pub sentinel_old_leaf: IMTLeafTargets,
    pub sentinel_new_leaf: IMTLeafTargets,
    pub sentinel_delta_proof: DeltaMerkleProofGadget,
}

impl IMTInsertGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        tree_height: usize,
    ) -> Self {
        let state_slot_base = builder.add_virtual_target();
        let capacity = builder.add_virtual_target();
        let height = builder.constant(F::from_canonical_usize(tree_height));
        let (physical_base, map_capacity) = Self::verify_map_bounds(builder, state_slot_base, capacity, height);

        let predecessor_old_leaf = IMTLeafTargets::add_virtual_to(builder);
        let predecessor_new_leaf = IMTLeafTargets::add_virtual_to(builder);
        let new_leaf = IMTLeafTargets::add_virtual_to(builder);
        let sentinel_preimage = IMTLeafTargets::add_virtual_to(builder);
        let sentinel_old_leaf = IMTLeafTargets::add_virtual_to(builder);
        let sentinel_new_leaf = IMTLeafTargets::add_virtual_to(builder);

        let pred_old_hash = predecessor_old_leaf.hash::<H, F, D>(builder);
        let pred_new_hash = predecessor_new_leaf.hash::<H, F, D>(builder);
        let new_leaf_hash = new_leaf.hash::<H, F, D>(builder);
        let sentinel_old_hash = sentinel_old_leaf.hash::<H, F, D>(builder);
        let sentinel_new_hash = sentinel_new_leaf.hash::<H, F, D>(builder);
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let one = builder.one();
        let true_target = builder._true();

        let sentinel_merkle_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, tree_height);
        let (sentinel_virgin, starting_count) = Self::authenticate_sentinel::<H, F, D>(
            builder,
            physical_base,
            map_capacity,
            &sentinel_preimage,
            &sentinel_merkle_proof,
        );

        let predecessor_delta_proof = DeltaMerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            tree_height,
            OptionalDeltaMerkleProofGadget {
                old_root: Some(sentinel_merkle_proof.root),
                old_value: None,
                new_root: None,
                new_value: Some(pred_new_hash),
                index: None,
                siblings: None,
            },
        );
        let room = builder.is_less_than(32, starting_count, map_capacity);
        builder.connect(room.target, true_target.target);
        let new_leaf_index = builder.add(builder.add(physical_base, starting_count), one);
        let new_leaf_delta_proof = DeltaMerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            tree_height,
            OptionalDeltaMerkleProofGadget {
                old_root: Some(predecessor_delta_proof.new_root),
                old_value: Some(zero_hash),
                new_root: None,
                new_value: Some(new_leaf_hash),
                index: Some(new_leaf_index),
                siblings: None,
            },
        );
        let sentinel_delta_proof = DeltaMerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            tree_height,
            OptionalDeltaMerkleProofGadget {
                old_root: Some(new_leaf_delta_proof.new_root),
                old_value: Some(sentinel_old_hash),
                new_root: None,
                new_value: Some(sentinel_new_hash),
                index: Some(physical_base),
                siblings: None,
            },
        );

        let predecessor_is_sentinel = builder.is_equal(predecessor_delta_proof.index, physical_base);
        let member_predecessor = builder.not(predecessor_is_sentinel);
        let initialized_member = builder.and(builder.not(sentinel_virgin), member_predecessor);
        let authenticated_old_hash = builder.select_hash(sentinel_virgin, zero_hash, pred_old_hash);
        let old_hash = builder.select_hash(initialized_member, pred_old_hash, authenticated_old_hash);
        builder.connect_hashes(predecessor_delta_proof.old_value, old_hash);
        let predecessor_differs = builder.is_not_equal(predecessor_delta_proof.index, new_leaf_index);
        builder.connect(predecessor_differs.target, true_target.target);
        Self::connect_query_nonzero(builder, new_leaf.key);
        Self::connect_predecessor_role(builder, &predecessor_old_leaf, predecessor_delta_proof.index, physical_base, starting_count);

        let sentinel_predecessor = predecessor_is_sentinel;
        builder.connect_hashes_if_true(sentinel_predecessor, predecessor_old_leaf.key, sentinel_preimage.key);
        builder.connect_hashes_if_true(sentinel_predecessor, predecessor_old_leaf.value, sentinel_preimage.value);
        builder.connect_hashes_if_true(sentinel_predecessor, predecessor_old_leaf.next_key, sentinel_preimage.next_key);
        builder.connect_if_true(sentinel_predecessor, predecessor_old_leaf.next_index, sentinel_preimage.next_index);
        builder.connect_if_true(sentinel_virgin, sentinel_predecessor.target, true_target.target);
        Self::connect_leaf_zero_if_true(builder, sentinel_virgin, &predecessor_old_leaf);

        builder.connect_hashes_if_true(member_predecessor, predecessor_old_leaf.key, predecessor_new_leaf.key);
        builder.connect_hashes_if_true(member_predecessor, predecessor_old_leaf.value, predecessor_new_leaf.value);
        builder.connect_hashes_if_true(sentinel_predecessor, predecessor_new_leaf.key, sentinel_preimage.key);
        for limb in 1..4 {
            builder.connect_if_true(sentinel_predecessor, predecessor_new_leaf.value.elements[limb], sentinel_preimage.value.elements[limb]);
        }
        builder.connect_if_true(sentinel_predecessor, predecessor_new_leaf.value.elements[0], starting_count);
        builder.connect_hashes(new_leaf.next_key, predecessor_old_leaf.next_key);
        builder.connect(new_leaf.next_index, predecessor_old_leaf.next_index);
        builder.connect_hashes(predecessor_new_leaf.next_key, new_leaf.key);
        builder.connect(predecessor_new_leaf.next_index, new_leaf_index);
        Self::connect_successor_pair(builder, new_leaf.next_key, new_leaf.next_index, physical_base, starting_count);

        let before_query = is_qhashout_lt::<F, D>(builder, predecessor_old_leaf.key, new_leaf.key);
        let successor_absent = builder.is_zero_hash(predecessor_old_leaf.next_key);
        let before_successor = is_qhashout_lt::<F, D>(builder, new_leaf.key, predecessor_old_leaf.next_key);
        let gap = builder.or(successor_absent, before_successor);
        builder.connect(builder.and(before_query, gap).target, true_target.target);

        let transient_old_hash = builder.select_hash(sentinel_virgin, pred_new_hash, sentinel_old_hash);
        builder.connect_hashes(sentinel_delta_proof.old_value, transient_old_hash);
        builder.connect_hashes(sentinel_old_leaf.key, sentinel_preimage.key);
        builder.connect_hashes(sentinel_new_leaf.key, sentinel_preimage.key);
        for limb in 1..4 {
            builder.connect(sentinel_old_leaf.value.elements[limb], sentinel_preimage.value.elements[limb]);
            builder.connect(sentinel_new_leaf.value.elements[limb], sentinel_preimage.value.elements[limb]);
        }
        builder.connect(sentinel_old_leaf.value.elements[0], starting_count);
        builder.connect(sentinel_new_leaf.value.elements[0], builder.add(starting_count, one));
        builder.connect_hashes_if_true(member_predecessor, sentinel_old_leaf.next_key, sentinel_preimage.next_key);
        builder.connect_if_true(member_predecessor, sentinel_old_leaf.next_index, sentinel_preimage.next_index);
        builder.connect_hashes_if_true(sentinel_predecessor, sentinel_old_leaf.next_key, new_leaf.key);
        builder.connect_if_true(sentinel_predecessor, sentinel_old_leaf.next_index, new_leaf_index);
        builder.connect_hashes(sentinel_new_leaf.next_key, sentinel_old_leaf.next_key);
        builder.connect(sentinel_new_leaf.next_index, sentinel_old_leaf.next_index);
        let final_successor_present = builder.and(
            builder.not(builder.is_zero_hash(sentinel_new_leaf.next_key)),
            builder.not(builder.is_zero(sentinel_new_leaf.next_index)),
        );
        Self::connect_index_in_open_interval(
            builder,
            final_successor_present,
            sentinel_new_leaf.next_index,
            physical_base,
            builder.add(starting_count, one),
        );

        Self {
            state_slot_base,
            capacity,
            predecessor_old_leaf,
            predecessor_new_leaf,
            new_leaf,
            new_leaf_index,
            predecessor_delta_proof,
            new_leaf_delta_proof,
            sentinel_preimage,
            sentinel_merkle_proof,
            sentinel_old_leaf,
            sentinel_new_leaf,
            sentinel_delta_proof,
        }
    }

    fn verify_map_bounds<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        base_offset: Target,
        capacity: Target,
        height_bits: Target,
    ) -> (Target, Target) {
        let (quotient, remainder) = builder.div_rem4(base_offset);
        let physical_base = builder.add(quotient, builder.is_not_zero(remainder).target);
        builder.range_check(physical_base, 32);
        builder.range_check(capacity, 32);
        let positive = builder.is_less_than(32, builder.zero(), capacity);
        builder.connect(positive.target, builder.one());
        let occupied = builder.add(physical_base, capacity);
        let mut tree_size = builder.one();
        for bits in 1..=32usize {
            tree_size = builder.add(tree_size, tree_size);
            let is_height = builder.is_equal(height_bits, builder.constant(F::from_canonical_usize(bits)));
            let within = builder.is_less_than(33, occupied, tree_size);
            builder.connect(builder.select(is_height, within.target, builder.one()), builder.one());
        }
        (physical_base, capacity)
    }

    fn authenticate_sentinel<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        physical_base: Target,
        capacity: Target,
        sentinel: &IMTLeafTargets,
        proof: &MerkleProofGadget,
    ) -> (BoolTarget, Target) {
        let sentinel_hash = sentinel.hash::<H, F, D>(builder);
        let count = sentinel.value.elements[0];
        builder.connect(proof.index, physical_base);
        for limb in 0..4 {
            builder.connect(sentinel.key.elements[limb], builder.zero());
            if limb != 0 {
                builder.connect(sentinel.value.elements[limb], builder.zero());
            }
        }
        builder.range_check(count, 32);
        let within = builder.is_less_than_or_equal(32, count, capacity);
        builder.connect(within.target, builder.one());
        let virgin = builder.is_zero_hash(proof.value);
        builder.connect_hashes_if_true(builder.not(virgin), sentinel_hash, proof.value);
        Self::connect_leaf_zero_if_true(builder, virgin, sentinel);
        let positive = builder.is_less_than(32, builder.zero(), count);
        builder.connect_if_true(builder.not(virgin), positive.target, builder.one());
        let linked = builder.and(builder.not(builder.is_zero_hash(sentinel.next_key)), builder.is_not_zero(sentinel.next_index));
        builder.connect_if_true(builder.not(virgin), linked.target, builder.one());
        Self::connect_index_in_open_interval(builder, builder.not(virgin), sentinel.next_index, physical_base, count);
        let absent = builder.and(builder.is_zero_hash(sentinel.next_key), builder.is_zero(sentinel.next_index));
        builder.connect_if_true(virgin, absent.target, builder.one());
        (virgin, count)
    }

    fn connect_leaf_zero_if_true<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        leaf: &IMTLeafTargets,
    ) {
        for limb in 0..4 {
            builder.connect_zero_if_true(condition, leaf.key.elements[limb]);
            builder.connect_zero_if_true(condition, leaf.value.elements[limb]);
            builder.connect_zero_if_true(condition, leaf.next_key.elements[limb]);
        }
        builder.connect_zero_if_true(condition, leaf.next_index);
    }

    fn connect_index_in_open_interval<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        active: BoolTarget,
        index: Target,
        physical_base: Target,
        count: Target,
    ) {
        let first = builder.add(physical_base, builder.one());
        let last = builder.add(physical_base, count);
        let low = builder.is_less_than_or_equal(33, first, index);
        let high = builder.is_less_than_or_equal(33, index, last);
        builder.connect_if_true(active, builder.and(low, high).target, builder.one());
    }

    fn connect_query_nonzero<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, key: HashOutTarget) {
        builder.connect(builder.not(builder.is_zero_hash(key)).target, builder.one());
    }

    fn connect_predecessor_role<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        predecessor: &IMTLeafTargets,
        index: Target,
        physical_base: Target,
        count: Target,
    ) {
        let at_sentinel = builder.is_equal(index, physical_base);
        for limb in 0..4 {
            builder.connect_zero_if_true(at_sentinel, predecessor.key.elements[limb]);
        }
        let member = builder.not(at_sentinel);
        let first = builder.add(physical_base, builder.one());
        let last = builder.add(physical_base, count);
        let low = builder.is_less_than_or_equal(33, first, index);
        let high = builder.is_less_than_or_equal(33, index, last);
        builder.connect_if_true(member, builder.and(low, high).target, builder.one());
        builder.connect_if_true(member, builder.not(builder.is_zero_hash(predecessor.key)).target, builder.one());
        Self::connect_successor_pair(builder, predecessor.next_key, predecessor.next_index, physical_base, count);
    }

    fn connect_successor_pair<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        next_key: HashOutTarget,
        next_index: Target,
        physical_base: Target,
        count: Target,
    ) {
        let absent = builder.and(builder.is_zero_hash(next_key), builder.is_zero(next_index));
        let present = builder.and(builder.not(builder.is_zero_hash(next_key)), builder.not(builder.is_zero(next_index)));
        builder.connect(builder.or(absent, present).target, builder.one());
        let first = builder.add(physical_base, builder.one());
        let last = builder.add(physical_base, count);
        let low = builder.is_less_than_or_equal(33, first, next_index);
        let high = builder.is_less_than_or_equal(33, next_index, last);
        builder.connect_if_true(present, builder.and(low, high).target, builder.one());
    }

    /// Set the authenticated insertion witness, including both sentinel versions.
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        state_slot_base: u64,
        capacity: u64,
        predecessor_old_leaf: &IMTContractStateLeaf<F>,
        predecessor_new_leaf: &IMTContractStateLeaf<F>,
        new_leaf: &IMTContractStateLeaf<F>,
        new_leaf_index: u64,
        predecessor_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        new_leaf_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        sentinel_preimage: &IMTContractStateLeaf<F>,
        sentinel_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        sentinel_old_preimage: &IMTContractStateLeaf<F>,
        sentinel_new_preimage: &IMTContractStateLeaf<F>,
        sentinel_delta_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_target(self.state_slot_base, F::from_canonical_u64(state_slot_base))?;
        witness.set_target(self.capacity, F::from_canonical_u64(capacity))?;
        self.predecessor_old_leaf.set_witness(witness, predecessor_old_leaf)?;
        self.predecessor_new_leaf.set_witness(witness, predecessor_new_leaf)?;
        self.new_leaf.set_witness(witness, new_leaf)?;
        witness.set_target(self.new_leaf_index, F::from_canonical_u64(new_leaf_index))?;
        self.predecessor_delta_proof.set_witness_core_proof_q(witness, predecessor_proof)?;
        self.new_leaf_delta_proof.set_witness_core_proof_q(witness, new_leaf_proof)?;
        self.sentinel_preimage.set_witness(witness, sentinel_preimage)?;
        self.sentinel_merkle_proof.set_witness_core_proof_q_generic(witness, sentinel_merkle_proof)?;
        self.sentinel_old_leaf.set_witness(witness, sentinel_old_preimage)?;
        self.sentinel_new_leaf.set_witness(witness, sentinel_new_preimage)?;
        self.sentinel_delta_proof.set_witness_core_proof_q(witness, sentinel_delta_proof)?;
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
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100, 4, 8).unwrap();
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
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100, 4, 8).unwrap();
        let root_before = imt.get_root(&store).unwrap();
        let sentinel_proof = imt.tree_id.get_leaf_ucs(&store, 100, 4).unwrap();
        let update = imt.insert(&store, QHashOut::from_values(10, 0, 0, 0), QHashOut::from_values(100, 200, 300, 400)).unwrap();
        let final_root = update.new_root();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let gadget = IMTInsertGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, TEST_TREE_HEIGHT);
        builder.register_public_inputs(&gadget.predecessor_delta_proof.old_root.elements);
        builder.register_public_inputs(&gadget.sentinel_delta_proof.new_root.elements);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let IMTContractStateUpdate::Insert {
            predecessor_old_preimage,
            predecessor_new_preimage,
            new_leaf_preimage,
            predecessor_delta_proof,
            new_leaf_delta_proof,
            sentinel_old_preimage,
            sentinel_new_preimage,
            sentinel_delta_proof,
        } = update
        else {
            panic!("expected insert");
        };
        assert_eq!(predecessor_delta_proof.old_value, QHashOut::ZERO);
        assert_ne!(sentinel_delta_proof.old_value, QHashOut::ZERO);
        assert_eq!(sentinel_delta_proof.new_root, final_root);
        gadget
            .set_witness(
                &mut pw,
                4,
                8,
                &predecessor_old_preimage,
                &predecessor_new_preimage,
                &new_leaf_preimage,
                new_leaf_delta_proof.index,
                &predecessor_delta_proof,
                &new_leaf_delta_proof,
                &predecessor_old_preimage,
                &sentinel_proof,
                &sentinel_old_preimage,
                &sentinel_new_preimage,
                &sentinel_delta_proof,
            )
            .unwrap();
        let proof = data.prove(pw).unwrap();
        assert_eq!(proof.public_inputs[0], root_before.0.elements[0]);
        assert_eq!(proof.public_inputs[4], final_root.0.elements[0]);
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_imt_insert_middle_of_list() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100, 4, 8).unwrap();
        let key_30 = QHashOut::from_values(30, 0, 0, 0);
        let key_10 = QHashOut::from_values(10, 0, 0, 0);
        let value = QHashOut::from_values(1, 0, 0, 0);
        imt.insert(&store, key_30, value).unwrap();
        let sentinel_proof = imt.tree_id.get_leaf_ucs(&store, 100, 4).unwrap();
        let update = imt.insert(&store, key_10, value).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let gadget = IMTInsertGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, TEST_TREE_HEIGHT);
        builder.register_public_inputs(&gadget.sentinel_delta_proof.new_root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        let IMTContractStateUpdate::Insert {
            predecessor_old_preimage,
            predecessor_new_preimage,
            new_leaf_preimage,
            predecessor_delta_proof,
            new_leaf_delta_proof,
            sentinel_old_preimage,
            sentinel_new_preimage,
            sentinel_delta_proof,
        } = update
        else {
            panic!("expected insert");
        };
        assert_ne!(predecessor_delta_proof.index, 4);
        assert_eq!(new_leaf_preimage.next_key, key_30);
        assert_eq!(sentinel_old_preimage.next_key, key_30);
        gadget
            .set_witness(
                &mut pw,
                4,
                8,
                &predecessor_old_preimage,
                &predecessor_new_preimage,
                &new_leaf_preimage,
                new_leaf_delta_proof.index,
                &predecessor_delta_proof,
                &new_leaf_delta_proof,
                &IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::from_values(1, 0, 0, 0), key_30, F::from_canonical_u64(5)),
                &sentinel_proof,
                &sentinel_old_preimage,
                &sentinel_new_preimage,
                &sentinel_delta_proof,
            )
            .unwrap();
        let proof = data.prove(pw).unwrap();
        assert_eq!(proof.public_inputs[0], sentinel_delta_proof.new_root.0.elements[0]);
        data.verify(proof).unwrap();
    }
}
