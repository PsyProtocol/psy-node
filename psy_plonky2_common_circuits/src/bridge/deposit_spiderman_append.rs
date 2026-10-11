use parth_core::{crypto::hash::spiderman::SpidermanUpdateProof, pgoldilocks::QHashOut};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use crate::hash::merkle::gadgets::spiderman_append_proof::SpidermanAppendProofGadget;

pub const DEPOSIT_SPIDERMAN_WEB_SIZE: usize = 32;
pub const DEPOSIT_SPIDERMAN_TOP_HEIGHT: usize = 27;
pub const DEPOSIT_SPIDERMAN_PAGE_CAPACITY: usize = 16;

#[derive(Clone)]
pub struct DepositSpidermanAppendInputs {
    pub chain_index: u8,
    pub old_count: u32,
    pub first_leaf: u32,
    pub leaf_count: u32,
    pub append_proof: SpidermanUpdateProof<QHashOut<GoldilocksField>>,
}

/// Private page in the global deposit relation; never a separately proved circuit.
pub struct DepositSpidermanAppendTarget {
    pub append: SpidermanAppendProofGadget,
    pub chain_index: Target,
    pub old_count: Target,
    pub new_count: Target,
    pub first_leaf: Target,
    pub leaf_count: Target,
    pub offset: Target,
    pub active: BoolTarget,
}

impl DepositSpidermanAppendTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let append = SpidermanAppendProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, DEPOSIT_SPIDERMAN_TOP_HEIGHT, 5);
        let chain_index = builder.add_virtual_target();
        let old_count = builder.add_virtual_target();
        let first_leaf = builder.add_virtual_target();
        let leaf_count = builder.add_virtual_target();
        builder.range_check(chain_index, 8);
        builder.range_check(first_leaf, 6);
        builder.range_check(leaf_count, 6);
        let zero = builder.zero();
        let inactive = builder.is_equal(leaf_count, zero);
        let active = builder.not(inactive);
        let bits = builder.split_le(old_count, 32);
        let offset = builder.le_sum(bits[..5].iter());
        let top_index = builder.le_sum(bits[5..].iter());
        builder.connect(append.top_line_proof.index, top_index);
        let end = builder.add(offset, leaf_count);
        let width = builder.constant(F::from_canonical_usize(DEPOSIT_SPIDERMAN_WEB_SIZE));
        builder.ensure_is_less_than_or_equal(7, end, width);
        let new_count = builder.add(old_count, leaf_count);
        builder.range_check(new_count, 32);
        for target in [chain_index, old_count, first_leaf] { builder.connect_zero_if_true(inactive, target); }
        for sibling in &append.top_line_proof.siblings {
            for limb in sibling.elements { builder.connect_zero_if_true(inactive, limb); }
        }
        for position in 0..DEPOSIT_SPIDERMAN_WEB_SIZE {
            let index = builder.constant(F::from_canonical_usize(position));
            let existing = builder.is_less_than(6, index, offset);
            let before_end = builder.is_less_than(7, index, end);
            let not_existing = builder.not(existing);
            let added = builder.and(not_existing, before_end);
            let after_end = builder.not(before_end);
            builder.connect(append.web_proof.added_leaves[position].target, added.target);
            // Occupied prefix is full, not merely an unconstrained subtree root.
            let old_zero = builder.is_zero_hash(append.web_proof.old_leaves[position]);
            builder.connect_zero_if_true(existing, old_zero.target);
            for limb in 0..4 {
                builder.connect_zero_if_true(not_existing, append.web_proof.old_leaves[position].elements[limb]);
                builder.connect_zero_if_true(after_end, append.web_proof.new_leaves[position].elements[limb]);
            }
        }
        Self { append, chain_index, old_count, new_count, first_leaf, leaf_count, offset, active }
    }

    pub fn set_witness(&self, witness: &mut PartialWitness<GoldilocksField>, inputs: Option<&DepositSpidermanAppendInputs>) -> anyhow::Result<()> {
        type F = GoldilocksField;
        if let Some(inputs) = inputs {
            anyhow::ensure!((1..=32).contains(&inputs.leaf_count), "invalid page leaf count");
            anyhow::ensure!(inputs.old_count.checked_add(inputs.leaf_count).is_some(), "deposit count overflow");
            anyhow::ensure!(inputs.old_count % 32 + inputs.leaf_count <= 32, "deposit page crossing");
            anyhow::ensure!(inputs.append_proof.top_line_proof.index == u64::from(inputs.old_count / 32), "deposit top index mismatch");
            anyhow::ensure!(inputs.append_proof.top_line_proof.siblings.len() == 27, "deposit top path length");
            anyhow::ensure!(inputs.append_proof.web_proof_old_leaves.len() == 32 && inputs.append_proof.web_proof_new_leaves.len() == 32, "deposit page width");
            for (target, value) in [(self.chain_index, u32::from(inputs.chain_index)), (self.old_count, inputs.old_count), (self.first_leaf, inputs.first_leaf), (self.leaf_count, inputs.leaf_count)] {
                witness.set_target(target, F::from_canonical_u32(value))?;
            }
            self.append.set_witness(witness, &inputs.append_proof)?;
            witness.set_hash_target(self.append.old_root, inputs.append_proof.top_line_proof.old_root.0)?;
            witness.set_hash_target(self.append.new_root, inputs.append_proof.top_line_proof.new_root.0)?;
        } else {
            for target in [self.chain_index, self.old_count, self.first_leaf, self.leaf_count, self.append.top_line_proof.index] {
                witness.set_target(target, F::ZERO)?;
            }
            // Derived roots are deliberately not zeroed: ordinary hashing computes them.
            for hash in self.append.web_proof.old_leaves.iter().chain(&self.append.web_proof.new_leaves).chain(&self.append.top_line_proof.siblings) {
                for limb in hash.elements { witness.set_target(limb, F::ZERO)?; }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::{MerkleLeafHasher, MerkleZeroHasher}}, pgoldilocks::PoseidonHasher};
    use plonky2::{hash::hash_types::HashOut, plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig}};

    type F = GoldilocksField;

    fn fixture(old_count: u32, leaf_count: u32) -> DepositSpidermanAppendInputs {
        let offset = (old_count % 32) as usize;
        let zero = QHashOut(HashOut { elements: [F::ZERO; 4] });
        let mut old_leaves = vec![zero; 32];
        for (index, leaf) in old_leaves[..offset].iter_mut().enumerate() {
            *leaf = QHashOut(HashOut { elements: [F::from_canonical_usize(index + 1); 4] });
        }
        let mut new_leaves = old_leaves.clone();
        for (index, leaf) in new_leaves[offset..offset + leaf_count as usize].iter_mut().enumerate() {
            *leaf = QHashOut(HashOut { elements: [F::from_canonical_usize(index + 40); 4] });
        }
        let top_line_proof = DeltaMerkleProofCore::from_params::<PoseidonHasher>(u64::from(old_count / 32),
            PoseidonHasher::compute_root_from_leaves(&old_leaves).unwrap(), PoseidonHasher::compute_root_from_leaves(&new_leaves).unwrap(),
            (5..32).map(PoseidonHasher::get_zero_hash).collect());
        DepositSpidermanAppendInputs { chain_index: 0, old_count, first_leaf: 0, leaf_count,
            append_proof: SpidermanUpdateProof { top_line_proof, web_proof_old_leaves: old_leaves, web_proof_new_leaves: new_leaves } }
    }

    #[test]
    fn ordinary_page_accepts_zero_and_unaligned_but_rejects_u32_overflow() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let page = DepositSpidermanAppendTarget::new(&mut builder);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        for (old_count, leaf_count) in [(0, 32), (1, 31), (31, 1), (u32::MAX - 1, 1)] {
            let inputs = fixture(old_count, leaf_count);
            let mut witness = PartialWitness::new();
            page.set_witness(&mut witness, Some(&inputs)).unwrap();
            data.verify(data.prove(witness).unwrap()).unwrap();
        }
        let mut witness = PartialWitness::new();
        page.set_witness(&mut witness, None).unwrap();
        data.verify(data.prove(witness).unwrap()).unwrap();

        // Bypass the native overflow guard to exercise the circuit's exact u32 sum.
        let inputs = fixture(u32::MAX, 1);
        let mut witness = PartialWitness::new();
        page.append.set_witness(&mut witness, &inputs.append_proof).unwrap();
        for (target, value) in [(page.chain_index, 0), (page.old_count, u32::MAX), (page.first_leaf, 0), (page.leaf_count, 1)] {
            witness.set_target(target, F::from_canonical_u32(value)).unwrap();
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(witness)));
        assert!(!matches!(result, Ok(Ok(_))));
    }

    #[test]
    fn full_old_page_rejects_holes_overwrites_and_hidden_additions() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let page = DepositSpidermanAppendTarget::new(&mut builder);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let inputs = fixture(1, 2);
        for (target, value) in [
            (page.append.web_proof.old_leaves[0].elements[0], F::ZERO),
            (page.append.web_proof.new_leaves[0].elements[0], F::from_canonical_u32(99)),
            (page.append.web_proof.old_leaves[1].elements[0], F::ONE),
            (page.append.web_proof.new_leaves[3].elements[0], F::ONE),
            (page.leaf_count, F::ONE),
            (page.append.top_line_proof.index, F::ONE),
        ] {
            let mut witness = PartialWitness::new();
            page.set_witness(&mut witness, Some(&inputs)).unwrap();
            witness.target_values.insert(target, value);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(witness)));
            assert!(!matches!(result, Ok(Ok(_))));
        }
        let mut witness = PartialWitness::new();
        page.set_witness(&mut witness, Some(&inputs)).unwrap();
        for limb in page.append.web_proof.old_leaves[0].elements { witness.target_values.insert(limb, F::ZERO); }
        for limb in page.append.web_proof.new_leaves[0].elements { witness.target_values.insert(limb, F::ZERO); }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(witness)));
        assert!(!matches!(result, Ok(Ok(_))));
    }
}
