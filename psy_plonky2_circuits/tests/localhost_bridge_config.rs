use std::{env, fs, path::PathBuf};

use anyhow::Context;
use parth_core::pgoldilocks::PoseidonHasher;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{circuit_data::CircuitData, config::PoseidonGoldilocksConfig}};
use psy_client_data::bridge_aggregate::{CircuitSetRegistration, REWARD_SESSION_PROOF_FIELD_COUNT};
use psy_common_circuit::serialization::PsyGateSerializer;
use psy_core::{constants::chain_id::PsyChainNetworkType, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::{config::network_config::PsyNodeCircuitFingerprintConfigProvider, genesis::genesis_block_setup::PsyGenesisBlockSetupDataProvider};
use psy_node_core::genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder;
use psy_plonky2_circuits::{
    bridge::{
        aggregate_circuits::{circuit_set_registration, AggregateCircuitHeights, AggregateCircuits},
        circuits::reward_session::{RewardSessionCircuit, REWARD_SESSION_STEP_CAPACITY},
    },
    circuit_library::get_plonky2_circuit_library_and_prover_for_network,
    node::config::networks::resolver::PsyPlonky2NodeConfigResolver,
};
use psy_plonky2_common_circuits::bridge::{
    deposit_spiderman_append::{DepositSpidermanAppendCircuit, DEPOSIT_SPIDERMAN_PI_WORDS},
    withdrawal_inclusion::{WithdrawalInclusionCircuit, WITHDRAWAL_INCLUSION_PUBLIC_INPUTS},
};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;

fn print_registration(phase: &str, registration: &CircuitSetRegistration) -> anyhow::Result<()> {
    println!("{phase}_registration={}", hex::encode(registration.encode()?));
    Ok(())
}

fn save_common_verifier(name: &str, data: &CircuitData<GoldilocksField, C, D>) -> anyhow::Result<()> {
    let Some(directory) = env::var_os("LEAF_OUTPUT_DIR") else { return Ok(()) };
    let directory = PathBuf::from(directory).join(name);
    fs::create_dir_all(&directory).with_context(|| format!("create {name} output directory"))?;
    let common = data.common.to_bytes(&PsyGateSerializer).map_err(|error| anyhow::anyhow!("common serialization: {error:?}"))?;
    let verifier = data.verifier_only.to_bytes().map_err(|error| anyhow::anyhow!("verifier serialization: {error:?}"))?;
    fs::write(directory.join("common.bin"), common).context("write common circuit data")?;
    fs::write(directory.join("verifier.bin"), verifier).context("write verifier circuit data")?;
    Ok(())
}

#[test]
#[ignore = "builds the deposit spiderman append leaf"]
fn print_deposit_spiderman_append() -> anyhow::Result<()> {
    println!("deposit_spiderman_append=before");
    let deposit = DepositSpidermanAppendCircuit::<C, D>::build();
    let registration = circuit_set_registration(1, 0, 0, DEPOSIT_SPIDERMAN_PI_WORDS, &deposit.circuit_data, [0; 4])?;
    print_registration("deposit_spiderman_append", &registration)?;
    save_common_verifier("deposit_spiderman_append", &deposit.circuit_data)?;
    println!("deposit_spiderman_append=after");
    drop(deposit);
    Ok(())
}

#[test]
#[ignore = "builds the withdrawal inclusion leaf"]
fn print_withdrawal_inclusion() -> anyhow::Result<()> {
    println!("withdrawal_inclusion=before");
    let withdrawal = WithdrawalInclusionCircuit::<C, D>::build();
    let registration = circuit_set_registration(2, 0, 0, WITHDRAWAL_INCLUSION_PUBLIC_INPUTS, &withdrawal.circuit_data, [0; 4])?;
    print_registration("withdrawal_inclusion", &registration)?;
    save_common_verifier("withdrawal_inclusion", &withdrawal.circuit_data)?;
    println!("withdrawal_inclusion=after");
    drop(withdrawal);
    Ok(())
}

#[test]
#[ignore = "builds the reward session leaf"]
fn print_reward_session() -> anyhow::Result<()> {
    println!("reward_session=before");
    let reward_session = RewardSessionCircuit::new(REWARD_SESSION_STEP_CAPACITY, 1)?;
    let common = &reward_session.circuit_data.common;
    for gate in &common.gates {
        let mut bytes = Vec::new();
        if plonky2::util::serialization::GateSerializer::write_gate(&PsyGateSerializer, &mut bytes, gate, common).is_err() {
            eprintln!("unsupported_gate={}", gate.0.id());
        }
    }
    let registration = circuit_set_registration(3, 0, 0, REWARD_SESSION_PROOF_FIELD_COUNT, &reward_session.circuit_data, [0; 4])?;
    print_registration("reward_session", &registration)?;
    save_common_verifier("reward_session", &reward_session.circuit_data)?;
    println!("reward_session=after");
    drop(reward_session);
    Ok(())
}

#[test]
#[ignore = "loads the local genesis artifact"]
fn print_checkpoint_zero_root() -> anyhow::Result<()> {
    let genesis_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../genesis.json");
    let resolver = PsyPlonky2NodeConfigResolver::new();
    let genesis = resolver.get_genesis_block_setup_data_for_network(
        PsyChainNetworkType::LocalDevnet,
        Some(genesis_path.to_str().context("genesis path is not UTF-8")?.to_owned()),
    )?;
    let fingerprints = resolver.get_circuit_fingerprint_config_for_network(PsyChainNetworkType::LocalDevnet)?;
    let chain_id = PsyChainNetworkType::LocalDevnet.get_chain_id();
    let (transition, _) = GenesisDatabaseDataBuilder::<parth_core::PF, parth_core::PHash>::setup_for_coordinator::<PoseidonHasher, PsyNetworkLocalDevnetConstants>(
        &genesis,
        chain_id,
        fingerprints.checkpoint_state_transition_circuit_fingerprint,
    )?;
    drop(genesis);
    println!("checkpoint_0_root={}", transition.state_transition.checkpoint_transition.new_checkpoint_tree_root);
    drop(transition);
    Ok(())
}

#[test]
#[ignore = "builds the full aggregate circuit graph"]
fn print_circuit_set_hash() -> anyhow::Result<()> {
    let (_, coordinator) = get_plonky2_circuit_library_and_prover_for_network::<C, D>(PsyChainNetworkType::LocalDevnet)?;
    let circuits = AggregateCircuits::build::<PsyNetworkLocalDevnetConstants>(
        &[0],
        &coordinator,
        AggregateCircuitHeights {
            deposit_state_tree: psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
            withdrawal_state_tree: psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
        },
    )?;
    println!("circuit_set_hash={}", hex::encode(circuits.circuit_set_hash()));
    Ok(())
}
