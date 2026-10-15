use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::{HashOutTarget, RichField}, poseidon::PoseidonHash},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_network_circuit::gadgets::qdata::checkpoint::PsyCheckpointLeafGadget;
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;

pub const HISTORICAL_MERKLE_PROOF_HEIGHT: usize = CHECKPOINT_TREE_HEIGHT as usize;

pub struct HistoricalMerkleProofTarget {
    pub checkpoint_id: [Target; 2],
    pub checkpoint_leaf: PsyCheckpointLeafGadget,
    pub checkpoint_leaf_hash: HashOutTarget,
    pub path: MerkleProofGadget,
    pub end_checkpoint_id: [Target; 2],
    pub checkpoint_tree_root: HashOutTarget,
}

pub fn historical_merkle_proof<F: RichField + Extendable<2>>(
    builder: &mut CircuitBuilder<F, 2>,
    checkpoint_id: [Target; 2],
    checkpoint_leaf: &PsyCheckpointLeafGadget,
    end_checkpoint_id: [Target; 2],
    checkpoint_tree_root: HashOutTarget,
) -> HistoricalMerkleProofTarget {
    builder.assert_zero(checkpoint_id[1]);
    builder.assert_zero(end_checkpoint_id[1]);
    builder.range_check(checkpoint_id[0], HISTORICAL_MERKLE_PROOF_HEIGHT);
    builder.range_check(end_checkpoint_id[0], HISTORICAL_MERKLE_PROOF_HEIGHT);
    let checkpoint_leaf_hash = checkpoint_leaf.to_hash::<PoseidonHash, F, 2>(builder);
    let path = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, 2>(
        builder,
        HISTORICAL_MERKLE_PROOF_HEIGHT,
        psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::OptionalMerkleProofGadget {
            root: Some(checkpoint_tree_root),
            value: Some(checkpoint_leaf_hash),
            index: Some(checkpoint_id[0]),
            siblings: None,
        },
    );
    builder.ensure_is_less_than_or_equal(32, checkpoint_id[0], end_checkpoint_id[0]);
    HistoricalMerkleProofTarget {
        checkpoint_id,
        checkpoint_leaf: checkpoint_leaf.clone(),
        checkpoint_leaf_hash,
        path,
        end_checkpoint_id,
        checkpoint_tree_root,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use psy_common_circuit::traits::{CreatableTarget, ToTargets};

    #[test]
    fn historical_membership_binds_leaf_path_index_and_checkpoint_boundary() {
        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let checkpoint_id = builder.add_virtual_targets(2);
        let end_id = builder.add_virtual_targets(2);
        let root = builder.add_virtual_hash();
        let leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
        let proof = historical_merkle_proof(
            &mut builder, [checkpoint_id[0], checkpoint_id[1]], &leaf,
            [end_id[0], end_id[1]], root,
        );
        builder.register_public_inputs(&root.elements);
        let data = builder.build::<C>();
        let witness = |mutation: usize, pinned_root: Option<HashOut<F>>| {
            let mut witness = PartialWitness::new();
            witness.set_target(checkpoint_id[0], F::from_canonical_u32(if mutation == 3 { 2 } else { 1 })).unwrap();
            witness.set_target(checkpoint_id[1], if mutation == 4 { F::ONE } else { F::ZERO }).unwrap();
            witness.set_target(end_id[0], F::from_canonical_u32(if mutation == 5 { 0 } else { 3 })).unwrap();
            witness.set_target(end_id[1], if mutation == 6 { F::ONE } else { F::ZERO }).unwrap();
            for (index, target) in leaf.to_targets().into_iter().enumerate() {
                let value = if mutation == 1 && index == 0 { F::ONE } else { F::ZERO };
                witness.set_target(target, value).unwrap();
            }
            for (index, sibling) in proof.path.siblings.iter().enumerate() {
                let value = if mutation == 2 && index == 0 { F::ONE } else { F::ZERO };
                witness.set_hash_target(*sibling, HashOut { elements: [value; 4] }).unwrap();
            }
            if let Some(root_value) = pinned_root {
                witness.set_hash_target(root, root_value).unwrap();
            }
            witness
        };
        let valid = data.prove(witness(0, None)).unwrap();
        data.verify(valid.clone()).unwrap();
        let pinned_root = HashOut { elements: valid.public_inputs[..4].try_into().unwrap() };
        for mutation in 1..=6 {
            let rejected = match data.prove(witness(mutation, Some(pinned_root))) {
                Ok(proof) => data.verify(proof).is_err(),
                Err(_) => true,
            };
            assert!(rejected, "accepted historical membership mutation {mutation}");
        }
    }
}
