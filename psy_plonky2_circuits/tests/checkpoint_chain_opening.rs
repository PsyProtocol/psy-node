use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOut,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
};
use psy_plonky2_circuits::{
    coordinator::{
        circuits::{checkpoint_state_transition::QEDCheckpointStateTransitionCircuit, checkpoint_state_transition_genesis::QEDCheckpointStateTransitionGenesisCircuit},
        gadgets::{checkpoint_state_transition::CheckpointStateTransitionPublicInputsGadget,
            recursive_checkpoint_state_transition_verify::VerifyRecursiveCheckpointStateTransitionProofGadget},
    },
    qstandard::QStandardCircuit,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
};
use psy_plonky2_basic_helpers::builder::pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates};

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

fn hash(seed: u64) -> HashOut<F> {
    HashOut { elements: std::array::from_fn(|i| F::from_canonical_u64(seed + i as u64)) }
}

// Keep the existing four-felt cumulative PI. Open the verified predecessor's
// last hash layer using a witness for the older chain hash, not another proof.
#[test]
fn verified_predecessor_chain_hash_binds_its_last_state_via_opening() {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let prefix = builder.add_virtual_hash();
    let state = CheckpointStateTransitionPublicInputsGadget::add_virtual_to::<plonky2::hash::poseidon::PoseidonHash, F, D>(&mut builder);
    let chain = state.get_chain_hash_from_previous::<plonky2::hash::poseidon::PoseidonHash, F, D>(&mut builder, prefix);
    builder.register_public_inputs(&chain.elements);
    builder.add_qed_type_e_common_gates();
    pad_circuit_degree(&mut builder, 11);
    let predecessor = builder.build::<C>();
    let predecessor_fingerprint = QHashOut(get_circuit_fingerprint_generic(&predecessor.verifier_only));
    let mut witness = PartialWitness::new();
    witness.set_hash_target(prefix, hash(10)).unwrap();
    witness.set_hash_target(state.checkpoint_transition.new_checkpoint_tree_root, hash(20)).unwrap();
    witness.set_hash_target(state.checkpoint_transition.new_checkpoint_leaf_hash, hash(30)).unwrap();
    witness.set_hash_target(state.checkpoint_state_transition_circuit_fingerprint, predecessor_fingerprint.0).unwrap();
    let proof = predecessor.prove(witness).unwrap();
    predecessor.verify(proof.clone()).unwrap();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let current = CheckpointStateTransitionPublicInputsGadget::add_virtual_to::<plonky2::hash::poseidon::PoseidonHash, F, D>(&mut builder);
    let checkpoint_id = builder.constant(F::from_canonical_u64(2));
    let verifier = VerifyRecursiveCheckpointStateTransitionProofGadget::<D>::add_virtual_to::<C, F>(
        &mut builder, &predecessor.common, predecessor.verifier_only.constants_sigmas_cap.height(),
        QHashOut(hash(90)), current, checkpoint_id,
    );
    builder.register_public_inputs(&verifier.previous_chain_hash.elements);
    let successor = builder.build::<C>();

    for (root, leaf, prefix_value, valid) in [
        (hash(20), hash(30), hash(10), true),
        (hash(21), hash(30), hash(10), false),
        (hash(20), hash(31), hash(10), false),
        (hash(20), hash(30), hash(11), false),
    ] {
        let mut witness = PartialWitness::new();
        verifier.set_witness_params::<C, F>(&mut witness, QHashOut(hash(80)), QHashOut(hash(81)), QHashOut(prefix_value), &proof, &predecessor.verifier_only).unwrap();
        witness.set_hash_target(current.checkpoint_state_transition_circuit_fingerprint, predecessor_fingerprint.0).unwrap();
        witness.set_hash_target(current.checkpoint_transition.old_checkpoint_tree_root, root).unwrap();
        witness.set_hash_target(current.checkpoint_transition.old_checkpoint_leaf_hash, leaf).unwrap();
        let result = successor.prove(witness);
        if valid {
            successor.verify(result.unwrap()).unwrap();
        } else {
            assert!(result.is_err(), "tampered opening must fail");
        }
    }
}

#[test]
fn transition_minifier_common_data_matches_genesis_in_constructor_fixture() {
    let genesis = QEDCheckpointStateTransitionGenesisCircuit::<C, D>::new();
    let cap_height = genesis.circuit_data.verifier_only.constants_sigmas_cap.height();
    // Use the same part_1 stand-in as the existing transition constructor tests.
    // This checks the actual transition/minifier constructors, not a live coordinator.
    let transition = QEDCheckpointStateTransitionCircuit::<C, D>::new(
        &genesis.circuit_data.common, cap_height, genesis.fingerprint,
        &genesis.circuit_data.common, cap_height, genesis.fingerprint, 32,
    );
    let common = transition.get_common_circuit_data_ref();
    eprintln!("genesis degree={} gates={} PI={}; transition final degree={} gates={} PI={}; equal={}",
        genesis.circuit_data.common.degree_bits(), genesis.circuit_data.common.gates.len(), genesis.circuit_data.common.num_public_inputs,
        common.degree_bits(), common.gates.len(), common.num_public_inputs, *common == genesis.circuit_data.common);
    eprintln!("transition base degree={}", transition.base_circuit_data.common.degree_bits());
    for (i, minifier) in transition.minifier_chain.as_ref().unwrap().minifiers.iter().enumerate() {
        eprintln!("minifier {i} degree={} gates={}", minifier.circuit_data.common.degree_bits(), minifier.circuit_data.common.gates.len());
    }
    assert_eq!(*common, genesis.circuit_data.common, "final minifier must match the common data used by the predecessor verifier");
}

/// Real checkpoint base + both minifiers, with an explicit mock part_1 producer.
/// This exercises recursive checkpoint 2, not the full GUTA production pipeline.
#[test]
fn input_genesis_anchor_requires_edge_validation_and_two_minified_transitions() {
    use parth_core::{crypto::hash::{tag_tree::hash_tag_tree_node_single, traits::{MerkleHasher, QFieldHashable}}, pgoldilocks::PoseidonHasher, utils::QPGenRandom};
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use psy_data::{protocol::circuit_inputs::checkpoint_transition::{QCQEDCheckpointStateTransitionInput, QCQEDCheckpointStateTransitionInputPartial}, v1::qdata::checkpoint::PQEDCheckpointLeafStats};
    type Hash = QHashOut<F>;
    let genesis = QEDCheckpointStateTransitionGenesisCircuit::<C, D>::new();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let part1_pi = builder.add_virtual_hash();
    builder.register_public_inputs(&part1_pi.elements);
    builder.add_qed_type_e_common_gates();
    pad_circuit_degree(&mut builder, 11);
    let part1 = builder.build::<C>();
    let part1_fp = QHashOut(get_circuit_fingerprint_generic(&part1.verifier_only));
    let mut partial = QCQEDCheckpointStateTransitionInputPartial::<F, Hash>::qp_rand_gen();
    // Valid bridge state inclusion paths, committed by the actual checkpoint.
    let mut deposit_slots = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(2);
    deposit_slots.set_leaf(0, QHashOut(hash(201))); deposit_slots.set_leaf(1, QHashOut(hash(211)));
    let mut withdrawal_slots = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(2);
    withdrawal_slots.set_leaf(0, QHashOut(hash(221))); withdrawal_slots.set_leaf(1, QHashOut(hash(231)));
    let mut contracts = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(2);
    contracts.set_leaf(2, deposit_slots.get_root()); contracts.set_leaf(3, withdrawal_slots.get_root());
    let owner = psy_data::v1::qdata::user::PQEDUserLeaf::new(QHashOut(hash(241)), contracts.get_root(), F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::from_canonical_u64(524_288));
    let mut users = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(20);
    users.set_leaf(524_288, owner.qfhash::<PoseidonHasher>());
    let deposit = psy_plonky2_circuits::bridge::gadgets::tree_root_in_contract_state::TreeRootInContractStateWitnessInput {
        owner_user_id: 524_288, contract_id: 2, user_leaf: owner.clone(), slot0_proof: deposit_slots.get_leaf(0), slot1_proof: deposit_slots.get_leaf(1), contract_proof: contracts.get_leaf(2), user_tree_proof: users.get_leaf(524_288),
    };
    let withdrawal = psy_plonky2_circuits::bridge::gadgets::tree_root_in_contract_state::TreeRootInContractStateWitnessInput {
        owner_user_id: 524_288, contract_id: 3, user_leaf: owner, slot0_proof: withdrawal_slots.get_leaf(0), slot1_proof: withdrawal_slots.get_leaf(1), contract_proof: contracts.get_leaf(3), user_tree_proof: users.get_leaf(524_288),
    };
    partial.part_1_header.guta_proof_header.state_transition.new_node_value = users.get_root();
    partial.old_stats = PQEDCheckpointLeafStats::new_empty();
    partial.block_time = F::ONE;
    partial.pm_jobs_completed.deploy_contracts_completed = F::from_noncanonical_u64(partial.part_1_header.deploy_contracts_state_transition.total_proofs_generated);
    partial.pm_jobs_completed.register_users_completed = F::from_noncanonical_u64(partial.part_1_header.register_users_state_transition.total_proofs_generated);
    partial.pm_jobs_completed.gutas_completed = partial.part_1_header.guta_proof_header.total_aggregation_proofs_generated;
    let genesis_leaf = partial.get_old_checkpoint_leaf::<PoseidonHasher>().qfhash::<PoseidonHasher>();
    let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(32);
    let genesis_delta = tree.set_leaf(0, genesis_leaf);
    let genesis_root = tree.get_root();
    let circuit = QEDCheckpointStateTransitionCircuit::<C, D>::new(
        &part1.common, part1.verifier_only.constants_sigmas_cap.height(), part1_fp,
        &genesis.circuit_data.common, genesis.circuit_data.verifier_only.constants_sigmas_cap.height(), genesis.fingerprint,
        32,
    );
    assert_ne!(circuit.base_fingerprint, circuit.get_fingerprint());
    assert_eq!(circuit.get_common_circuit_data_ref(), &genesis.circuit_data.common);
    let genesis_proof = genesis.prove_base(genesis_root, genesis_leaf, genesis.fingerprint).unwrap();
    let c0 = Hash::from_felt_slice(&genesis_proof.public_inputs);
    let reward = QHashOut(hash(71));
    let tag = QHashOut(hash(81));
    let reward_root = hash_tag_tree_node_single::<Hash, PoseidonHasher>(&reward, &tag);
    let build_input = |mut partial: QCQEDCheckpointStateTransitionInputPartial<F, Hash>, tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, Hash>, index, previous, older| {
        partial.part_1_header.guta_proof_header.checkpoint_tree_root = tree.get_root();
        let previous_checkpoint_proof = tree.get_leaf(index - 1);
        assert_eq!(partial.get_old_checkpoint_leaf::<PoseidonHasher>().qfhash::<PoseidonHasher>(), previous_checkpoint_proof.value);
        let new_leaf = partial.get_new_checkpoint_leaf::<PoseidonHasher>(reward_root).qfhash::<PoseidonHasher>();
        let append_checkpoint_tree_proof = tree.set_leaf(index, new_leaf);
        let mut witness = QCQEDCheckpointStateTransitionInput::<F, Hash>::qp_rand_gen();
        witness.partial = partial;
        witness.previous_checkpoint_proof = previous_checkpoint_proof;
        witness.append_checkpoint_tree_proof = append_checkpoint_tree_proof;
        witness.previous_chain_hash = previous;
        witness.start_chain_hash = older;
        witness.checkpoint_state_transition_circuit_fingerprint = circuit.get_fingerprint();
        let pi = PoseidonHasher::two_to_one(&witness.partial.part_1_header.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>(), &reward);
        let mut pw = PartialWitness::new();
        pw.set_hash_target(part1_pi, pi.0).unwrap();
        (witness, part1.prove(pw).unwrap())
    };
    let (w1, p1) = build_input(partial.clone(), &mut tree, 1, c0, QHashOut(hash(91)));
    let proof1 = circuit.prove_base(tag, &w1, reward, &p1, &part1.verifier_only, &genesis_proof, &genesis.circuit_data.verifier_only).unwrap();
    circuit.minifier_chain.as_ref().unwrap().minifiers.last().unwrap().circuit_data.verify(proof1.clone()).unwrap();
    let c1 = Hash::from_felt_slice(&proof1.public_inputs);
    assert_eq!(c1, w1.get_chain_hash_from_previous_with_fingerprint::<PoseidonHasher>(c0, circuit.get_fingerprint()));
    partial.old_stats = w1.partial.get_new_checkpoint_leaf::<PoseidonHasher>(reward_root).stats;
    partial.block_time = F::from_canonical_u64(2);
    partial.part_1_header.deploy_contracts_state_transition.state_transition_start = w1.partial.part_1_header.update_contracts_state_transition.state_transition_end;
    partial.part_1_header.register_users_state_transition.state_transition_start = w1.partial.part_1_header.register_users_state_transition.state_transition_end;
    partial.part_1_header.guta_proof_header.state_transition.old_node_value = w1.partial.part_1_header.guta_proof_header.state_transition.new_node_value;
    let (w2, p2) = build_input(partial, &mut tree, 2, c1, c0);
    let proof2 = circuit.prove_base(tag, &w2, reward, &p2, &part1.verifier_only, &proof1, circuit.get_verifier_config_ref()).unwrap();
    circuit.minifier_chain.as_ref().unwrap().minifiers.last().unwrap().circuit_data.verify(proof2.clone()).unwrap();
    assert_eq!(Hash::from_felt_slice(&proof2.public_inputs), w2.get_chain_hash_from_previous_with_fingerprint::<PoseidonHasher>(c1, circuit.get_fingerprint()));
    let mut wrong_older = w2.clone();
    wrong_older.start_chain_hash = QHashOut(hash(99));
    assert!(circuit.prove_base(tag, &wrong_older, reward, &p2, &part1.verifier_only, &proof1, circuit.get_verifier_config_ref()).is_err());

    // Another genesis is internally valid and has a matching old leaf/header.
    // The transition circuit accepts it under the QED mainnet-beta trust model;
    // the coordinator edge must reject it against its canonical checkpoint 0.
    let mut foreign_partial = w1.partial.clone();
    foreign_partial.old_stats.random_seed = QHashOut(hash(111));
    let foreign_leaf = foreign_partial.get_old_checkpoint_leaf::<PoseidonHasher>().qfhash::<PoseidonHasher>();
    let mut foreign_tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(32);
    foreign_tree.set_leaf(0, foreign_leaf);
    let foreign_genesis = genesis.prove_base(foreign_tree.get_root(), foreign_leaf, genesis.fingerprint).unwrap();
    genesis.circuit_data.verify(foreign_genesis.clone()).unwrap();
    let (foreign_input, foreign_part1) = build_input(foreign_partial, &mut foreign_tree, 1, Hash::from_felt_slice(&foreign_genesis.public_inputs), c0);
    let foreign_proof = circuit.prove_base(tag, &foreign_input, reward, &foreign_part1, &part1.verifier_only, &foreign_genesis, &genesis.circuit_data.verifier_only).unwrap();
    circuit.minifier_chain.as_ref().unwrap().minifiers.last().unwrap().circuit_data.verify(foreign_proof).unwrap();

    let final_leaf = w2.partial.get_new_checkpoint_leaf::<PoseidonHasher>(reward_root);
    let global_roots = psy_data::v1::qdata::checkpoint::PQEDCheckpointGlobalStateRoots {
        contract_tree_root: w2.partial.part_1_header.update_contracts_state_transition.state_transition_end,
        user_tree_root: users.get_root(),
        user_registration_tree_root: w2.partial.part_1_header.register_users_state_transition.state_transition_end,
        deposit_tree_root: <PoseidonHasher as parth_core::crypto::hash::traits::MerkleZeroHasher<Hash>>::get_zero_hash(32),
        withdrawal_tree_root: <PoseidonHasher as parth_core::crypto::hash::traits::MerkleZeroHasher<Hash>>::get_zero_hash(32),
    };
    let compact = psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafCompact { global_chain_root: final_leaf.global_chain_root, stats_hash: final_leaf.stats.qfhash::<PoseidonHasher>() };
    let aggregated = psy_plonky2_circuits::bridge::circuits::bridge_agg_final::BridgeAggFinalCircuit::<C, D>::prove_range(
        1, 2, c0, circuit.get_common_circuit_data_ref(), circuit.get_verifier_config_ref().constants_sigmas_cap.height(), circuit.get_fingerprint(), circuit.get_fingerprint(),
        &proof2, circuit.get_verifier_config_ref(), &[w1.append_checkpoint_tree_proof.clone(), w2.append_checkpoint_tree_proof.clone()],
        &[genesis_delta, w1.append_checkpoint_tree_proof.clone()], &compact, &global_roots, &deposit, &withdrawal, 32, 20, 2, 2, 2,
    ).unwrap();
    plonky2::plonk::circuit_data::VerifierCircuitData { verifier_only: aggregated.verifier_data, common: aggregated.common_data }.verify(aggregated.proof).unwrap();

    // Exercise the actual bridge checkpoint-verifier gadget with the new proof.
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let bridge = psy_plonky2_circuits::bridge::gadgets::verify_checkpoint_state_transition::VerifyBridgeCheckpointStateTransitionProofGadget::<D>::add_virtual_to::<C, F>(
        &mut builder, circuit.get_common_circuit_data_ref(), circuit.get_verifier_config_ref().constants_sigmas_cap.height(), circuit.get_fingerprint());
    builder.register_public_inputs(&bridge.public_inputs_hash.elements);
    let verifier = builder.build::<C>();
    let mut pw = PartialWitness::new();
    bridge.set_witness::<C, F>(&mut pw, &proof2, circuit.get_verifier_config_ref()).unwrap();
    verifier.verify(verifier.prove(pw).unwrap()).unwrap();
}

#[test]
fn bridge_checkpoint_verifier_rejects_wrong_fingerprint_and_invalid_proof() {
    use psy_plonky2_circuits::bridge::gadgets::verify_checkpoint_state_transition::VerifyBridgeCheckpointStateTransitionProofGadget;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let pi = builder.add_virtual_hash();
    builder.register_public_inputs(&pi.elements);
    let predecessor = builder.build::<C>();
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&predecessor.verifier_only));
    let mut witness = PartialWitness::new();
    witness.set_hash_target(pi, hash(10)).unwrap();
    let proof = predecessor.prove(witness).unwrap();
    for (expected, corrupt, valid) in [(fingerprint, false, true), (QHashOut(hash(90)), false, false), (fingerprint, true, false)] {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let verifier = VerifyBridgeCheckpointStateTransitionProofGadget::<D>::add_virtual_to::<C, F>(
            &mut builder, &predecessor.common, predecessor.verifier_only.constants_sigmas_cap.height(), expected);
        let data = builder.build::<C>();
        let mut supplied = proof.clone();
        if corrupt { supplied.public_inputs[0] += F::ONE; }
        let mut witness = PartialWitness::new();
        verifier.set_witness::<C, F>(&mut witness, &supplied, &predecessor.verifier_only).unwrap();
        // Invalid recursive inputs may fail inside a Plonky2 witness generator.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(witness)));
        if valid {
            data.verify(result.unwrap().unwrap()).unwrap();
        } else {
            assert!(!matches!(result, Ok(Ok(_))), "invalid proof or verifier identity must be rejected");
        }
    }
}
