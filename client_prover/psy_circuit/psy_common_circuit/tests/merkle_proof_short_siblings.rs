use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::hash::merkle::gadgets::{
    delta_merkle_proof::{DeltaMerkleProofGadget, OptionalDeltaMerkleProofGadget},
    sha256_truncated::merkle_proof::MerkleProofTruncatedSha256Gadget,
};

type F = GoldilocksField;

#[test]
fn delta_merkle_proof_short_siblings() {
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let gadget = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, 2>(&mut builder, 2);
    let zero = QHashOut(HashOut::ZERO);
    for length in [0, 1, 3] {
        let mut witness = PartialWitness::new();
        let error = gadget.set_witness(&mut witness, F::ZERO, zero, zero, &vec![zero; length]).unwrap_err();
        assert!(error.to_string().contains("siblings length mismatch"));
        assert!(witness.target_values.is_empty());
    }
    gadget.set_witness(&mut PartialWitness::new(), F::ZERO, zero, zero, &[zero; 2]).unwrap();
}

#[test]
fn delta_merkle_proof_hash_out_short_siblings() {
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let gadget = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, 2>(&mut builder, 2);
    let zero = HashOut::ZERO;
    for length in [0, 1, 3] {
        let mut witness = PartialWitness::new();
        let error = gadget.set_witness_hash_out(&mut witness, F::ZERO, zero, zero, &vec![zero; length]).unwrap_err();
        assert!(error.to_string().contains("siblings length mismatch"));
        assert!(witness.target_values.is_empty());
    }
    gadget.set_witness_hash_out(&mut PartialWitness::new(), F::ZERO, zero, zero, &[zero; 2]).unwrap();
}

#[test]
fn sha256_merkle_proof_short_siblings() {
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let gadget = MerkleProofTruncatedSha256Gadget::add_virtual_to(&mut builder, 2);
    for length in [0, 1, 3] {
        let mut witness = PartialWitness::<F>::new();
        let error = gadget.set_witness(&mut witness, 0, &[0; 24], &vec![[0; 24]; length]).unwrap_err();
        assert!(error.to_string().contains("siblings length mismatch"));
        assert!(witness.target_values.is_empty());
    }
    gadget.set_witness(&mut PartialWitness::<F>::new(), 0, &[0; 24], &[[0; 24]; 2]).unwrap();
}

#[test]
fn delta_merkle_proof_fixed_siblings_ignore_unused_input() {
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let siblings = vec![builder.constant_hash(HashOut::ZERO); 2];
    let gadget = DeltaMerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, 2>(
        &mut builder,
        2,
        OptionalDeltaMerkleProofGadget {
            old_root: None, old_value: None, new_root: None, new_value: None,
            index: None, siblings: Some(siblings),
        },
    );
    let zero = HashOut::ZERO;
    for length in [0, 1, 3] {
        gadget.set_witness(&mut PartialWitness::new(), F::ZERO, QHashOut(zero), QHashOut(zero), &vec![QHashOut(zero); length]).unwrap();
        gadget.set_witness_hash_out(&mut PartialWitness::new(), F::ZERO, zero, zero, &vec![zero; length]).unwrap();
    }
}
