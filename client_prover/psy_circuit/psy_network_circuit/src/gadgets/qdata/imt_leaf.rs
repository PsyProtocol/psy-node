//! Network-level circuit gadget for IMT contract state leaves.
//!
//! Re-exports and wraps the common circuit IMT leaf targets and comparison
//! functions for use in network-level proof circuits.
//!
//! The canonical implementation lives in
//! [`psy_common_circuit::hash::merkle::gadgets::imt_contract_state_update`].

// ---------------------------------------------------------------------------
// Re-exports from psy_common_circuit
// ---------------------------------------------------------------------------
pub use imt_contract_state_update::{
    is_qhashout_lt, is_qhashout_lte, verify_imt_non_membership, IMTInsertGadget as IMTContractStateInsertGadget,
    IMTLeafTargets as IMTContractStateLeafTargets, IMTUpdateGadget as IMTContractStateUpdateGadget,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf;
use psy_common_circuit::{
    builder::comparison::CircuitBuilderComparison,
    hash::merkle::gadgets::imt_contract_state_update::{self, IMTLeafTargets},
    traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor},
};

// ---------------------------------------------------------------------------
// IMTContractStateLeafGadget: network-level wrapper
// ---------------------------------------------------------------------------

/// Network-level circuit gadget for an IMT contract state leaf.
///
/// This wraps [`IMTLeafTargets`] from the common circuit crate and implements
/// the standard circuit gadget traits (`CreatableTarget`, `ToTargets`,
/// `FromTargets`, `AlgebraicHashableTarget`, `WitnessValueFor`).
///
/// Layout: key[4] + value[4] + next_key[4] + next_index[1] = 13 field elements.
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct IMTContractStateLeafGadget {
    pub key: HashOutTarget,
    pub value: HashOutTarget,
    pub next_key: HashOutTarget,
    pub next_index: Target,
}

impl IMTContractStateLeafGadget {
    /// Set witness values from an [`IMTContractStateLeaf`].
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, leaf: &IMTContractStateLeaf<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.key, leaf.key.0)?;
        witness.set_hash_target(self.value, leaf.value.0)?;
        witness.set_hash_target(self.next_key, leaf.next_key.0)?;
        witness.set_target(self.next_index, leaf.next_index)
    }

    /// Compute the hash of this leaf: hash(key[4] ++ value[4] ++ next_key[4] ++
    /// next_index[1])
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_targets())
    }

    /// Check whether this leaf is a sentinel (key == ZERO_HASH).
    pub fn is_sentinel<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        builder.is_zero_hash(self.key)
    }

    /// Check whether this leaf is the last in the linked list (next_key == ZERO
    /// && next_index == 0).
    pub fn is_last<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let next_key_zero = builder.is_zero_hash(self.next_key);
        let next_index_zero = builder.is_zero(self.next_index);
        builder.and(next_key_zero, next_index_zero)
    }

    /// Convert to the common circuit [`IMTLeafTargets`] representation.
    pub fn to_imt_leaf_targets(&self) -> IMTLeafTargets {
        IMTLeafTargets {
            key: self.key,
            value: self.value,
            next_key: self.next_key,
            next_index: self.next_index,
        }
    }

    /// Create from the common circuit [`IMTLeafTargets`] representation.
    pub fn from_imt_leaf_targets(targets: &IMTLeafTargets) -> Self {
        Self {
            key: targets.key,
            value: targets.value,
            next_key: targets.next_key,
            next_index: targets.next_index,
        }
    }
}

impl AlgebraicHashableTarget for IMTContractStateLeafGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}

impl CreatableTarget for IMTContractStateLeafGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let key = builder.add_virtual_hash();
        let value = builder.add_virtual_hash();
        let next_key = builder.add_virtual_hash();
        let next_index = builder.add_virtual_target();
        Self {
            key,
            value,
            next_key,
            next_index,
        }
    }
}

impl ToTargets for IMTContractStateLeafGadget {
    fn to_targets(&self) -> Vec<Target> {
        vec![
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
        ]
    }
}

impl FromTargets for IMTContractStateLeafGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 13 {
            panic!("tried to create IMTContractStateLeafGadget from {} targets, expected 13", targets.len());
        }
        let key = HashOutTarget {
            elements: [targets[0], targets[1], targets[2], targets[3]],
        };
        let value = HashOutTarget {
            elements: [targets[4], targets[5], targets[6], targets[7]],
        };
        let next_key = HashOutTarget {
            elements: [targets[8], targets[9], targets[10], targets[11]],
        };
        let next_index = targets[12];
        Self {
            key,
            value,
            next_key,
            next_index,
        }
    }
}

impl<F: RichField> WitnessValueFor<IMTContractStateLeafGadget, F, true> for IMTContractStateLeaf<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &IMTContractStateLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<IMTContractStateLeafGadget, F, false> for IMTContractStateLeaf<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &IMTContractStateLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

/// Compare two 256-bit IMT keys in circuit.
/// Returns true if a < b (MSL-first comparison: [3] > [2] > [1] > [0]).
///
/// This is a network-level alias for [`is_qhashout_lt`] that uses the same
/// MSL-first lexicographic comparison from the common circuit crate.
pub fn imt_key_less_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: HashOutTarget,
    b: HashOutTarget,
) -> BoolTarget {
    is_qhashout_lt(builder, a, b)
}
