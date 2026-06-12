use parth_core::{
    crypto::hash::{
        traits::{MerkleHasher, MerkleZeroHasher},
    },
    pgoldilocks::{PoseidonHasher, QHashOut},
};
use plonky2::{
    field::extension::Extendable,
    hash::poseidon::PoseidonHash,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::{AlgebraicHasher, Hasher}},
};
use psy_plonky2_basic_helpers::builder::{
    hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers,
};

use super::merkle_proof::MerkleProofGadget;

#[derive(Debug, Clone)]
pub struct FrontierAppendGadget {
    pub old_frontier: Vec<HashOutTarget>,
    pub new_frontier: Vec<HashOutTarget>,
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
    pub leaf_hash: HashOutTarget,
    pub index: Target,
}

impl FrontierAppendGadget {
    pub fn add_virtual_to<
        H: AlgebraicHasher<F>,
        Z: MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let index = builder.add_virtual_target();
        let leaf_hash = builder.add_virtual_hash();
        let old_frontier = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        let new_frontier = (0..height)
            .map(|_| builder.add_virtual_hash())
            .collect::<Vec<_>>();
        let index_bits = builder.split_le(index, height);
        let zero_leaf = builder.constant_hash(HashOut::ZERO);

        let siblings = (0..height)
            .map(|level| {
                let zero_hash = builder.constant_hash(Z::get_zero_hash(level));
                builder.ensure_hash_not_equal_if(index_bits[level], old_frontier[level], zero_hash);
                builder.select_hash(index_bits[level], old_frontier[level], zero_hash)
            })
            .collect::<Vec<_>>();

        let old_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            zero_leaf,
            &siblings,
        );
        let new_root = MerkleProofGadget::compute_root_bits::<H, F, D>(
            builder,
            &index_bits,
            leaf_hash,
            &siblings,
        );

        let mut current = leaf_hash;
        for level in 0..height {
            let zero_hash = builder.constant_hash(Z::get_zero_hash(level));
            let expected_frontier = builder.select_hash(index_bits[level], old_frontier[level], current);
            builder.connect_hashes(new_frontier[level], expected_frontier);

            let next_if_left = builder.hash_two_to_one::<H>(current, zero_hash);
            let next_if_right = builder.hash_two_to_one::<H>(old_frontier[level], current);
            current = builder.select_hash(index_bits[level], next_if_right, next_if_left);
        }

        Self {
            old_frontier,
            new_frontier,
            old_root,
            new_root,
            leaf_hash,
            index,
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        frontier: &[QHashOut<F>],
        index: u64,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<()>
    where
        PoseidonHasher: MerkleZeroHasher<QHashOut<F>> + MerkleHasher<QHashOut<F>>,
    {
        if frontier.len() != self.old_frontier.len() {
            anyhow::bail!(
                "invalid frontier length provided to set_witness: expected {}, got {}",
                self.old_frontier.len(),
                frontier.len()
            );
        }

        witness.set_target(self.index, F::from_noncanonical_u64(index))?;
        witness.set_hash_target(self.leaf_hash, leaf_hash.0)?;

        for (target, value) in self.old_frontier.iter().zip(frontier.iter()) {
            witness.set_hash_target(*target, value.0)?;
        }

        let next_frontier = compute_new_frontier_poseidon(frontier, index, leaf_hash);
        for (target, value) in self.new_frontier.iter().zip(next_frontier.iter()) {
            witness.set_hash_target(*target, value.0)?;
        }

        Ok(())
    }
}

pub fn derive_frontier_siblings<Hash: Copy, H: MerkleZeroHasher<Hash>>(
    frontier: &[Hash],
    index: u64,
) -> Vec<Hash> {
    frontier
        .iter()
        .enumerate()
        .map(|(level, frontier_hash)| {
            if ((index >> level) & 1) == 1 {
                *frontier_hash
            } else {
                H::get_zero_hash(level)
            }
        })
        .collect()
}

pub fn compute_new_frontier<Hash: Copy, H: MerkleZeroHasher<Hash>>(
    frontier: &[Hash],
    index: u64,
    leaf_hash: Hash,
) -> Vec<Hash> {
    let mut next_frontier = frontier.to_vec();
    let mut current = leaf_hash;

    for (level, slot) in next_frontier.iter_mut().enumerate() {
        if ((index >> level) & 1) == 0 {
            *slot = current;
            current = H::two_to_one(&current, &H::get_zero_hash(level));
        } else {
            current = H::two_to_one(slot, &current);
        }
    }

    next_frontier
}

fn compute_new_frontier_poseidon<F: RichField>(
    frontier: &[QHashOut<F>],
    index: u64,
    leaf_hash: QHashOut<F>,
) -> Vec<QHashOut<F>>
where
    PoseidonHasher: MerkleZeroHasher<QHashOut<F>> + MerkleHasher<QHashOut<F>>,
{
    let mut next_frontier = frontier.to_vec();
    let mut current = leaf_hash;

    for (level, slot) in next_frontier.iter_mut().enumerate() {
        if ((index >> level) & 1) == 0 {
            *slot = current;
            current = PoseidonHasher::two_to_one(&current, &PoseidonHasher::get_zero_hash(level));
        } else {
            current = PoseidonHasher::two_to_one(slot, &current);
        }
    }

    next_frontier
}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::{
            merkle_proof::compute_root_merkle_proof_generic,
            traits::MerkleZeroHasher,
        },
        pgoldilocks::{PoseidonHasher, QHashOut},
    };
    use plonky2::{
        field::types::Field,
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
        },
    };

    use super::{compute_new_frontier, derive_frontier_siblings, FrontierAppendGadget};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    struct TestFrontierAppendCircuit {
        gadget: FrontierAppendGadget,
        circuit_data: CircuitData<F, C, D>,
    }

    impl TestFrontierAppendCircuit {
        fn new(height: usize, expected_old_root: QHashOut<F>, expected_new_root: QHashOut<F>) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let gadget = FrontierAppendGadget::add_virtual_to::<PoseidonHash, PoseidonHasher, F, D>(&mut builder, height);

            let expected_old_root = builder.constant_hash(expected_old_root.0);
            let expected_new_root = builder.constant_hash(expected_new_root.0);
            builder.connect_hashes(gadget.old_root, expected_old_root);
            builder.connect_hashes(gadget.new_root, expected_new_root);

            builder.register_public_inputs(&gadget.old_root.elements);
            builder.register_public_inputs(&gadget.new_root.elements);

            Self {
                gadget,
                circuit_data: builder.build::<C>(),
            }
        }

        fn prove(
            &self,
            frontier: &[QHashOut<F>],
            index: u64,
            leaf_hash: QHashOut<F>,
        ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::new();
            self.gadget.set_witness(&mut pw, frontier, index, leaf_hash)?;
            self.circuit_data.prove(pw)
        }
    }

    fn sample_leaf(seed: u64) -> QHashOut<F> {
        QHashOut(HashOut {
            elements: [
                F::from_noncanonical_u64(seed + 1),
                F::from_noncanonical_u64(seed + 2),
                F::from_noncanonical_u64(seed + 3),
                F::from_noncanonical_u64(seed + 4),
            ],
        })
    }

    #[test]
    fn test_frontier_to_siblings_index_5() {
        let frontier = (0..8)
            .map(|i| sample_leaf((i as u64) * 10))
            .collect::<Vec<_>>();
        let siblings = derive_frontier_siblings::<QHashOut<F>, PoseidonHash>(&frontier, 5);

        assert_eq!(siblings[0], frontier[0]);
        assert_eq!(siblings[1], PoseidonHash::get_zero_hash(1));
        assert_eq!(siblings[2], frontier[2]);
        assert_eq!(siblings[3], PoseidonHash::get_zero_hash(3));
    }

    #[test]
    fn test_frontier_update_sequential_32() {
        let height = 8;
        let mut frontier = vec![QHashOut::ZERO; height];
        let mut current_root = PoseidonHash::get_zero_hash(height);

        for index in 0..32u64 {
            let leaf_hash = sample_leaf(index + 100);
            let siblings = derive_frontier_siblings::<QHashOut<F>, PoseidonHash>(&frontier, index);
            let old_root =
                compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(QHashOut::ZERO, index, &siblings);
            let new_root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(
                leaf_hash,
                index,
                &siblings,
            );

            assert_eq!(old_root, current_root);

            frontier = compute_new_frontier::<QHashOut<F>, PoseidonHash>(&frontier, index, leaf_hash);
            current_root = new_root;
        }
    }

    #[test]
    fn test_frontier_gadget_valid_proof() {
        let height = 8;
        let mut frontier = vec![QHashOut::ZERO; height];
        let mut current_root = PoseidonHash::get_zero_hash(height);

        for index in 0..5u64 {
            let leaf_hash = sample_leaf(index + 200);
            let siblings = derive_frontier_siblings::<QHashOut<F>, PoseidonHash>(&frontier, index);
            current_root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(
                leaf_hash,
                index,
                &siblings,
            );
            frontier = compute_new_frontier::<QHashOut<F>, PoseidonHash>(&frontier, index, leaf_hash);
        }

        let index = 5u64;
        let leaf_hash = sample_leaf(999);
        let siblings = derive_frontier_siblings::<QHashOut<F>, PoseidonHash>(&frontier, index);
        let old_root =
            compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(QHashOut::ZERO, index, &siblings);
        let new_root =
            compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(leaf_hash, index, &siblings);

        assert_eq!(old_root, current_root);

        let circuit = TestFrontierAppendCircuit::new(height, old_root, new_root);
        let proof = circuit.prove(&frontier, index, leaf_hash).unwrap();
        assert_eq!(proof.public_inputs[0..4], old_root.0.elements);
        assert_eq!(proof.public_inputs[4..8], new_root.0.elements);
        assert!(circuit.circuit_data.verify(proof).is_ok());
    }

    #[test]
    #[should_panic]
    fn test_frontier_gadget_wrong_frontier() {
        let height = 8;
        let mut frontier = vec![QHashOut::ZERO; height];
        let mut current_root = PoseidonHash::get_zero_hash(height);

        for index in 0..5u64 {
            let leaf_hash = sample_leaf(index + 300);
            let siblings = derive_frontier_siblings::<QHashOut<F>, PoseidonHash>(&frontier, index);
            current_root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(
                leaf_hash,
                index,
                &siblings,
            );
            frontier = compute_new_frontier::<QHashOut<F>, PoseidonHash>(&frontier, index, leaf_hash);
        }

        let index = 5u64;
        let leaf_hash = sample_leaf(1234);
        let siblings = derive_frontier_siblings::<QHashOut<F>, PoseidonHash>(&frontier, index);
        let old_root =
            compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(QHashOut::ZERO, index, &siblings);
        let new_root =
            compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(leaf_hash, index, &siblings);
        assert_eq!(old_root, current_root);

        let circuit = TestFrontierAppendCircuit::new(height, old_root, new_root);
        let mut bad_frontier = frontier.clone();
        bad_frontier[2] = QHashOut::rand();

        circuit.prove(&bad_frontier, index, leaf_hash).unwrap();
    }
}
