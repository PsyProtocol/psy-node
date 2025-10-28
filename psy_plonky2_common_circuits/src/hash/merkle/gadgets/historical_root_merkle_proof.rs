use psy_plonky2_basic_helpers::builder::{hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, Witness},
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};

/*
this gadget helps you prove that an append only merkle tree with a current root `current_root` once had a root of `historical_root`
another way to think of this gadget is that it proves that, if you take a tree with root X and set all the leaves with index >= `gadget.index` to zero, the tree will have a new root Y
*/
#[derive(Debug, Clone)]
pub struct HistoricalRootMerkleProofGadget {
    pub current_root: HashOutTarget,
    pub historical_root: HashOutTarget,
    pub current_value: HashOutTarget,
    pub index: Target,
    pub siblings: Vec<HashOutTarget>,
}
impl HistoricalRootMerkleProofGadget {
    // calculate the normal merkle root + a historical merkle root where all the leaves with index >= `gadget.index` set to zero
    pub fn add_virtual_to_zero_gte<
        H: MerkleZeroHasher<HashOut<F>> +AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let current_value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let (historical_root, current_root) = Self::compute_root_historical_root_with_historical_state::<H, F, D>(
            builder,
            index,
            current_value,
            &siblings,
            zero_hash
        );
        Self {
            current_root,
            current_value,
            index,
            siblings,
            historical_root,
        }
    }
    // calculate the normal merkle root + a historical merkle root where all the leaves with index > `gadget.index` set to zero
    pub fn add_virtual_to_zero_gt<
        H: MerkleZeroHasher<HashOut<F>> +AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let current_value = builder.add_virtual_hash();
        let siblings = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();

        let (historical_root, current_root) = Self::compute_root_historical_root_with_historical_state::<H, F, D>(
            builder,
            index,
            current_value,
            &siblings,
            current_value
        );
        Self {
            current_root,
            current_value,
            index,
            siblings,
            historical_root,
        }
    }
    fn compute_root_historical_root_with_historical_state<
        H: MerkleZeroHasher<HashOut<F>> +AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
        value: HashOutTarget,
        siblings: &[HashOutTarget],
        start_historical_state: HashOutTarget,
    ) -> (HashOutTarget, HashOutTarget) {

        let height = siblings.len();
        builder.range_check(index, height);
        let index_bits = builder.split_le(index, height);
        Self::compute_root_historical_root_bits_with_historical_state::<H,F,D>(
            builder,
            &index_bits,
            value,
            siblings,
            start_historical_state
        )

    }
    fn compute_root_historical_root_bits_with_historical_state<
        H: MerkleZeroHasher<HashOut<F>> +AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        index_bits: &[BoolTarget],
        value: HashOutTarget,
        siblings: &[HashOutTarget],
        start_historical_state: HashOutTarget,
    ) -> (HashOutTarget, HashOutTarget) {
        //let zero = builder.zero();
        let mut state: HashOutTarget = value;
        let mut historical_state: HashOutTarget = start_historical_state;
        //debug_assert_eq!(state.elements.len(), NUM_HASH_OUT_ELEMENTS);

        tracing::debug!("🔍 Historical Merkle Proof - initial state: {:?}, historical_state: {:?}, value: {:?}",
            state, historical_state, value);

        let mut level = 0;

        for (&bit, &sibling) in index_bits.iter().zip(siblings) {
            //let left = builder.select_hash(bit, sibling, state);
            //let right = builder.select_hash(bit, state, sibling);
            state = builder.two_to_one_swapped::<H>(state, sibling, bit);

            let level_zero_hash = builder.constant_hash(H::get_zero_hash(level));
            // if the right node is not on the path, then it should historically be a zero hash
            let historical_left = builder.select_hash(bit, sibling, historical_state);
            let historical_right = builder.select_hash(bit, historical_state, level_zero_hash);
            historical_state = builder.hash_two_to_one::<H>(historical_left, historical_right);
            level += 1;
        }
        (historical_state, state)
    }
    pub fn set_witness_generic<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        index: F,
        value: QHashOut<F>,
        siblings: &[QHashOut<F>],
    )  -> anyhow::Result<()> {
        witness.set_target(self.index, index)?;

        witness.set_hash_target(self.current_value, value.0)?;

        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash_target(*sibling, siblings[i].0)?;
        }
        Ok(())
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut PartialWitness<F>,
        index: F,
        value: QHashOut<F>,
        siblings: &[QHashOut<F>],
    )  -> anyhow::Result<()>{
        self.set_witness_generic(witness, index, value, siblings)
    }
    pub fn set_witness_proof_core<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        proof: &MerkleProofCore<QHashOut<F>>,
    )  -> anyhow::Result<()> {
        tracing::debug!("🔍 Historical Merkle Proof set_witness - index: {}, value: {}, siblings_len: {}",
            proof.index, proof.value, proof.siblings.len());

        self.set_witness_generic::<W, F>(
            witness,
            F::from_noncanonical_u64(proof.index),
            proof.value,
            &proof.siblings,
        )
    }
}



#[cfg(test)]
mod tests {
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use parth_core::crypto::hash::merkle_proof::{compute_historical_and_current_merkle_roots_core, MerkleProofCore};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use parth_core::pgoldilocks::QHashOut;

    use crate::hash::merkle::gadgets::historical_root_merkle_proof::HistoricalRootMerkleProofGadget;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;



    fn create_historical_mp_circuit_for_proof_a(mp: &MerkleProofCore<QHashOut<F>>) -> QHashOut<F> {

        assert!(mp.verify::<PoseidonHash>(), "invalid proof passed to create_historical_mp_circuit_for_proof_a");

        let (expected_historical_root, expected_current_root) = compute_historical_and_current_merkle_roots_core::<QHashOut<F>, PoseidonHash>(
            mp,
        );

        // this should never happpen if mp.root and compute_historical_and_current_merkle_roots_core is correct
        assert_eq!(expected_current_root, mp.root, "compute_historical_and_current_merkle_roots_core computed a root which doesn't match merkle_proof.root");

        let tree_height = mp.siblings.len();

        // start building the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let historical_gadget= HistoricalRootMerkleProofGadget::add_virtual_to_zero_gte::<PoseidonHash, F, D>(
            &mut builder,
            tree_height,
        );
        builder.register_public_inputs(&historical_gadget.historical_root.elements);
        builder.register_public_inputs(&historical_gadget.current_root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        historical_gadget.set_witness_proof_core(&mut pw, mp).unwrap();

        let proof = data.prove(pw).unwrap();
        assert_eq!(proof.public_inputs[0..4], expected_historical_root.0.elements, "expected_historical_root does not match proof output");
        assert_eq!(proof.public_inputs[4..8], expected_current_root.0.elements, "expected_current_root does not match proof output");
        assert!(data.verify(proof).is_ok(), "generated proof not valid");

        expected_historical_root
    }


    #[test]
    fn test_historical_merkle_proof_gadget_simple() {

        let mut merkle_tree = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(16);
        let mut historical_roots = Vec::new();
        for i in 0..128 {
            historical_roots.push(
                merkle_tree.set_leaf(i, QHashOut::from_values(100+i, 5, 16, i)).old_root
            );
        }

        for (i, historical_root) in historical_roots.into_iter().enumerate() {
            let merkle_proof = merkle_tree.get_leaf(i as u64);
            let computed_historical_root = create_historical_mp_circuit_for_proof_a(
                &merkle_proof
            );
            assert_eq!(historical_root, computed_historical_root, "historical_root != computed_historical_root");
        }
    }

    #[test]
    fn test_historical_merkle_proof_gadget_instructive() {

        let mut merkle_tree = SimpleMerkleTree::<PoseidonHash, QHashOut<F>>::new(2);
        let mut historical_roots = Vec::new();
        for i in 0..4 {
            historical_roots.push(
                merkle_tree.set_leaf(i, QHashOut::from_values(100+i, 5, 16, i)).old_root
            );
        }

        for (i, historical_root) in historical_roots.into_iter().enumerate() {
            let merkle_proof = merkle_tree.get_leaf(i as u64);
            let computed_historical_root = create_historical_mp_circuit_for_proof_a(
                &merkle_proof
            );
            assert_eq!(historical_root, computed_historical_root, "historical_root != computed_historical_root");
        }
    }

}
