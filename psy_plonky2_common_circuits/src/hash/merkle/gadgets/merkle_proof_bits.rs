use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::target::{BoolTarget, Target}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};

use psy_plonky2_basic_helpers::builder::{hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers};


// all the inputs for a merkle proof you need to do some fun stuff
#[derive(Debug, Clone)]
pub struct MerkleProofInputWithIndexBitsGadget {
    pub value: HashOutTarget,
    pub index: Target,
    pub siblings: Vec<HashOutTarget>,

    // computed
    pub index_bits: Vec<BoolTarget>,
}


impl MerkleProofInputWithIndexBitsGadget {

    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);
        Self {
            value,
            index,
            siblings,
            index_bits,
        }
    }
    pub fn compute_root<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {

        //let zero = builder.zero();
        let mut state: HashOutTarget = self.value;
        //debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELEMENTS);

        for (&bit, &sibling) in self.index_bits.iter().zip(self.siblings.iter()) {

            let left = builder.select_hash(bit, sibling, state);
            let right = builder.select_hash(bit, state, sibling);
            state = builder.hash_two_to_one::<H>(left, right);
        }
        state

    }
}