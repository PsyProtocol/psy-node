//! Standalone provisioning generator for the bridge aggregate setup.
//!
//! - `AggregateCircuits::build_circuit_set_registrations` (psy_plonky2_circuits) for the
//!   current circuit set hash and registrations over the actually configured chain
//!   indices, built sequentially so each proving graph drops before the next.
//! - `GenesisDatabaseDataBuilder` (psy_node_core) over the regenerated genesis
//!   data for the checkpoint-0 tree root (mirrors the coordinator seeding order
//!   in psy_node_common/src/coordinator/processor/create.rs:74-78 and
//!   psy_node_common/src/coordinator/db.rs:525-528).
//! - `NetworkConfig` (psy_client_data::bridge_aggregate) for the canonical
//!   lowercase-hex encoding consumed by `AggregateSetupConfig`
//!   (psy_cli/psy_relayer_cli/src/bridge/regen_groth16_keystore.rs:61-76).
//!
//! L1 addresses are required fail-closed arguments carrying the real
//! precommitted atomic-deploy addresses; this generator never invents,
//! defaults, or fabricates them.

use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

use anyhow::{ensure, Context};
use clap::Parser;
use parth_core::{
    crypto::hash::traits::{FromU64x4, ToU64x4},
    pgoldilocks::{PoseidonHasher, QHashOut},
    protocol::core_types::QNetworkTreeConstants,
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::circuit_data::CommonCircuitData};
use psy_client_data::bridge_aggregate::{circuit_set_hash, ChainConfig, NetworkConfig, BRIDGE_USER_ID, DEPOSIT_RECORD_CAPACITY};
use psy_core::{
    constants::chain_id::PsyChainNetworkType,
    constants::protocol::{
        get_default_worker_rewards_tree_tag, STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
        STATE_LAYOUT_MAX_AGGREGATION_DEPTH, STATE_LAYOUT_TREE_HEIGHT,
    },
    network_config::{get_circuit_config_for_network, PsyNetworkLocalDevnetConstants},
};
use psy_data::{
    agg::TPAltCircuitFingerprintConfig,
    config::network_config::load_realm_rotation_config,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    guta::realm_finalize::realm_finalize_guta_chain_domain,
};
use psy_node_core::genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder;
use psy_plonky2_basic_helpers::lookalike::standard::get_end_cap_type_e_common_data;
use psy_plonky2_circuits::{
    agg::v2::{core::AggStateTransitionCircuitV2, dummy::AggStateTransitionDummyCircuitV2},
    bridge::aggregate_circuits::{AggregateCircuitHeights, AggregateCircuits},
    circuit_library::end_cap_verifier_data::get_end_cap_alt_verifier_data_for_network,
    coordinator::circuits::{
        agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTACircuit,
        batch_append_user_registration_tree::BatchAppendUserRegistrationTreeCircuit,
        checkpoint_state_transition::QEDCheckpointStateTransitionCircuit,
        checkpoint_state_transition_genesis::QEDCheckpointStateTransitionGenesisCircuit,
    },
    coordinator::state_layout_helper::StateLayoutCircuitManager,
    guta::guta_helper::QEDGUTACircuitManager,
    proof_minifier::pm_core::get_circuit_fingerprint_generic_q,
    qstandard::QStandardCircuit,
};
use psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsSources;

type F = GoldilocksField;
type Hash = QHashOut<F>;
type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
const D: usize = 2;

#[derive(Parser, Debug)]
#[command(name = "aggregate_setup_config")]
struct Args {
    /// Regenerated genesis data JSON (post validator injection; the launcher
    /// rewrites it in place via injectGenesisValidators).
    #[arg(long, default_value = "genesis.json")]
    genesis_data_path: PathBuf,

    /// Psy runtime network config JSON providing networks.localhost.magic.
    #[arg(long, default_value = "psy-genesis/config.json")]
    psy_config_path: PathBuf,

    /// L2 chain id used for the validator tree seeding; must equal the value
    /// the coordinator processor passes to setup_for_coordinator.
    #[arg(long)]
    l2_chain_id: u64,

    /// Configured L1 cohort, repeatable, strictly increasing:
    /// INDEX=CHAIN_ID:BRIDGE_0XHEX:STATE_MANAGER_0XHEX
    #[arg(long = "chain", required = true)]
    chains: Vec<String>,

    /// Index of the ethereum chain inside --chain.
    #[arg(long, default_value_t = 0)]
    ethereum_index: u8,

    /// Reward payer 0x-address (EthereumRewardPayer on the ethereum chain).
    #[arg(long = "reward-payer")]
    reward_payer: String,

    /// Reward token 0x-address (PsyToken on the ethereum chain).
    #[arg(long = "reward-token")]
    reward_token: String,

    /// Reward per claim in base units (authorized: 1e9 = 1 PSY at 9 decimals).
    #[arg(long, default_value_t = 1_000_000_000)]
    reward_per_claim: u128,

    /// Reward token decimals (authorized: 9).
    #[arg(long, default_value_t = 9)]
    reward_token_decimals: u8,


    /// Protocol withdrawal window capacity (authorized N32).
    #[arg(long, default_value_t = 32)]
    max_withdrawals: u32,

    /// Protocol reward window capacity (authorized N32).
    #[arg(long, default_value_t = 32)]
    max_rewards: u32,

    /// Use local:<SHA-256> of reviewed source snapshots for this dirty-worktree run;
    /// node and circuit wrapper share the node snapshot, native uses the native prover, Plonky2 its resolved source.
    #[arg(long = "source-node")]
    source_node: String,
    #[arg(long = "source-native")]
    source_native: String,
    #[arg(long = "source-plonky2")]
    source_plonky2: String,
    #[arg(long = "source-wrapper")]
    source_wrapper: String,
    /// Approved setup JSON. Its withdrawal_policies construct the record circuit.
    #[arg(long = "approved-setup", required = true)]
    approved_setup: PathBuf,


    /// Output AggregateSetupConfig JSON; must not exist. Omit for print-only.
    #[arg(long)]
    out: Option<PathBuf>,
}

fn parse_address(value: &str, name: &str) -> anyhow::Result<[u8; 20]> {
    let hex_str = value.strip_prefix("0x").unwrap_or(value);
    ensure!(hex_str.len() == 40, "{name} must be 20 bytes of hex");
    let bytes = hex::decode(hex_str).with_context(|| format!("parsing {name}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    ensure!(out != [0u8; 20], "{name} must not be zero");
    Ok(out)
}

fn parse_chain(spec: &str) -> anyhow::Result<(u8, ChainConfig)> {
    let parts: Vec<&str> = spec.split(':').collect();
    ensure!(parts.len() == 3, "chain spec must be INDEX=CHAIN_ID:BRIDGE:STATE_MANAGER");
    let mut head = parts[0].split('=');
    let chain_index: u8 = head.next().context("chain index")?.parse().context("chain index")?;
    let chain_id: u64 = head.next().context("chain id")?.parse().context("chain id")?;
    ensure!(head.next().is_none(), "chain spec head must be INDEX=CHAIN_ID");
    let bridge = parse_address(parts[1], "chain bridge")?;
    let state_manager = parse_address(parts[2], "chain state manager")?;
    let mut id_bytes = [0u8; 32];
    id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
    Ok((chain_index, ChainConfig {
        chain_index,
        chain_id: id_bytes,
        bridge,
        state_manager,
        bootstrap_id: 0,
        bootstrap_root: [0; 4],
    }))
}

fn parse_source(value: &str, name: &str) -> anyhow::Result<String> {
    DigestBitsSources {
        node_source: value.to_string(),
        native_source: String::new(),
        plonky2_source: String::new(),
        wrapper_source: String::new(),
    }
    .validate()
    .with_context(|| format!("invalid {name} source identity"))?;
    Ok(value.to_string())
}

fn hash4_hex(value: [u64; 4]) -> String {
    let mut bytes = [0u8; 32];
    for (index, limb) in value.into_iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    format!("0x{}", hex::encode(bytes))
}

/// Builds the checkpoint state-transition verifier inputs by constructing only the
/// coordinator chain that `QEDCheckpointStateTransitionCircuit` consumes, dropping each
/// full proving graph after extracting its compact
/// (common data, verifier cap height, fingerprint). Mirrors
/// `get_plonky2_circuit_library_and_prover_for_network`
/// (psy_plonky2_circuits/src/circuit_library/core.rs:10-184) and
/// `QEDCoordinatorCircuitManager::new_with_guta`
/// (psy_plonky2_circuits/src/coordinator/coordinator_helper.rs:116-244) argument for
/// argument, so the fingerprint stays a genuine construction measurement; it is
/// cross-checked against the cached library inside
/// `AggregateCircuits::build_circuit_set_registrations`.
fn build_checkpoint_state_transition_verifier_inputs() -> anyhow::Result<(CommonCircuitData<F, 2>, usize, QHashOut<F>)> {
    let network = PsyChainNetworkType::LocalDevnet;
    let circuit_config = get_circuit_config_for_network(network);
    let rotation = load_realm_rotation_config(network)?;

    let end_cap_common_data = get_end_cap_type_e_common_data::<C, D>();
    let end_cap_verifier_data = get_end_cap_alt_verifier_data_for_network(network)?.to_verifier_data::<C, D>();
    let end_cap_cap_height = end_cap_verifier_data.constants_sigmas_cap.height();
    let end_cap_fingerprint = get_circuit_fingerprint_generic_q::<D, F, C>(&end_cap_verifier_data);
    drop(end_cap_verifier_data);

    // Existing GUTA manager construction; the manager holds all twelve GUTA graphs and
    // drops after the three compact inputs below are extracted.
    let guta_circuits = QEDGUTACircuitManager::<C, D>::new_with_config_and_chain_domain(
        &end_cap_common_data,
        end_cap_cap_height,
        circuit_config.global_user_tree_realm_height,
        circuit_config.global_user_tree_height,
        circuit_config.guta_circuit_whitelist_tree_height,
        circuit_config.checkpoint_tree_height,
        circuit_config.group_realm_height,
        circuit_config.max_users_to_register_per_proof,
        circuit_config.only_register_max_users_per_proof,
        end_cap_fingerprint,
        QHashOut::from_u64x4(circuit_config.default_user_state_tree_root_hash_u64_x4),
        get_default_worker_rewards_tree_tag::<QHashOut<F>>(),
        realm_finalize_guta_chain_domain::<F, QHashOut<F>, PoseidonHasher>(network.get_chain_id()),
        rotation.checkpoints_per_epoch,
        rotation.validator_sub_ids,
    );
    let verify_two_guta_common = guta_circuits.verify_two_guta.get_common_circuit_data_ref().clone();
    let verify_two_guta_cap_height = guta_circuits.verify_two_guta.get_verifier_config_ref().constants_sigmas_cap.height();
    let guta_circuit_whitelist_root = guta_circuits.guta_circuit_whitelist_root;
    drop(guta_circuits);

    let append_user_registration_tree = BatchAppendUserRegistrationTreeCircuit::<C, D>::new(
        circuit_config.global_user_tree_height,
        circuit_config.batch_user_registration_sub_tree_height,
        circuit_config.batch_user_registration_max_sub_trees,
    );
    let append_common = append_user_registration_tree.get_common_circuit_data_ref().clone();
    let append_cap_height = append_user_registration_tree.get_verifier_config_ref().constants_sigmas_cap.height();
    let append_fingerprint = append_user_registration_tree.get_fingerprint();
    drop(append_user_registration_tree);

    // Existing state-layout manager construction (layout chain plus both batch
    // circuits); drops after the two compact batch extractions below.
    let state_layout_circuits = StateLayoutCircuitManager::<C, D>::new(
        STATE_LAYOUT_TREE_HEIGHT - STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
        STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
        circuit_config.global_contract_tree_height,
        circuit_config.batch_deploy_contract_sub_tree_height,
        STATE_LAYOUT_TREE_HEIGHT,
        circuit_config.max_contract_state_tree_height,
        STATE_LAYOUT_MAX_AGGREGATION_DEPTH,
    );
    let batch_deploy_common = state_layout_circuits.batch_deploy_contracts.get_common_circuit_data_ref().clone();
    let batch_deploy_cap_height = state_layout_circuits.batch_deploy_contracts.get_verifier_config_ref().constants_sigmas_cap.height();
    let batch_deploy_fingerprint = state_layout_circuits.batch_deploy_contracts.get_fingerprint();
    let batch_update_common = state_layout_circuits.batch_update_contracts.get_common_circuit_data_ref().clone();
    let batch_update_cap_height = state_layout_circuits.batch_update_contracts.get_verifier_config_ref().constants_sigmas_cap.height();
    let batch_update_fingerprint = state_layout_circuits.batch_update_contracts.get_fingerprint();
    drop(state_layout_circuits);

    let dummy_fingerprint = AggStateTransitionDummyCircuitV2::<C, D>::new().get_fingerprint();
    let user_reg_transition_circuit_config = TPAltCircuitFingerprintConfig {
        leaf_fingerprint: append_fingerprint,
        aggregator_fingerprint: AggStateTransitionCircuitV2::<C, D>::new(&append_common, append_cap_height).get_fingerprint(),
        dummy_fingerprint,
        verifier_data_cap_height: append_cap_height,
    };
    let deploy_contracts_transition_circuit_config = TPAltCircuitFingerprintConfig {
        leaf_fingerprint: batch_deploy_fingerprint,
        aggregator_fingerprint: AggStateTransitionCircuitV2::<C, D>::new(&batch_deploy_common, batch_deploy_cap_height).get_fingerprint(),
        dummy_fingerprint,
        verifier_data_cap_height: batch_deploy_cap_height,
    };
    let update_contracts_transition_circuit_config = TPAltCircuitFingerprintConfig {
        leaf_fingerprint: batch_update_fingerprint,
        aggregator_fingerprint: AggStateTransitionCircuitV2::<C, D>::new(&batch_update_common, batch_update_cap_height).get_fingerprint(),
        dummy_fingerprint,
        verifier_data_cap_height: batch_update_cap_height,
    };

    let agg_user_register_deploy_contracts_guta = VerifyAggUserRegistartionDeployContractsGUTACircuit::<C, D>::new(
        &append_common,
        &user_reg_transition_circuit_config,
        &batch_deploy_common,
        &deploy_contracts_transition_circuit_config,
        &batch_update_common,
        &update_contracts_transition_circuit_config,
        &verify_two_guta_common,
        verify_two_guta_cap_height,
        circuit_config.guta_circuit_whitelist_tree_height,
        guta_circuit_whitelist_root,
    );
    let part1_common = agg_user_register_deploy_contracts_guta.get_common_circuit_data_ref().clone();
    let part1_cap_height = agg_user_register_deploy_contracts_guta.get_verifier_config_ref().constants_sigmas_cap.height();
    let part1_fingerprint = agg_user_register_deploy_contracts_guta.get_fingerprint();
    drop(agg_user_register_deploy_contracts_guta);

    let genesis_checkpoint_root_transition = QEDCheckpointStateTransitionGenesisCircuit::<C, D>::new();
    let genesis_common = genesis_checkpoint_root_transition.get_common_circuit_data_ref().clone();
    let genesis_cap_height = genesis_checkpoint_root_transition.get_verifier_config_ref().constants_sigmas_cap.height();
    let genesis_fingerprint = genesis_checkpoint_root_transition.get_fingerprint();
    drop(genesis_checkpoint_root_transition);

    let checkpoint_root_transition = QEDCheckpointStateTransitionCircuit::<C, D>::new(
        &part1_common,
        part1_cap_height,
        part1_fingerprint,
        &genesis_common,
        genesis_cap_height,
        genesis_fingerprint,
        circuit_config.checkpoint_tree_height,
    );
    let checkpoint_common_data = checkpoint_root_transition.get_common_circuit_data_ref().clone();
    let checkpoint_cap_height = checkpoint_root_transition.get_verifier_config_ref().constants_sigmas_cap.height();
    let checkpoint_fingerprint = checkpoint_root_transition.get_fingerprint();
    drop(checkpoint_root_transition);
    Ok((checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 1. Checkpoint-0 derivation from the regenerated genesis artifacts. The genesis bytes,
    //    decoded setup data, and database builder are scoped to this block and released once the
    //    bootstrap root is derived.
    let bootstrap_root: [u64; 4] = {
        let genesis_bytes = fs::read(&args.genesis_data_path)
            .with_context(|| format!("reading {}", args.genesis_data_path.display()))?;
        let genesis: PsyGenesisBlockSetupData<F, Hash> = serde_json::from_slice(&genesis_bytes)
            .context("decoding genesis setup data")?;
        let mut builder = GenesisDatabaseDataBuilder::<F, Hash>::new(
            genesis.deposit_tree_root,
            genesis.withdrawal_tree_root,
            genesis.checkpoint_stats.clone(),
        );
        builder.setup_contracts::<PoseidonHasher, PsyNetworkLocalDevnetConstants>(&genesis, true)?;
        builder.setup_users::<PoseidonHasher, PsyNetworkLocalDevnetConstants>(&genesis, None, true, false)?;
        builder.setup_validators::<PoseidonHasher>(
            &genesis,
            args.l2_chain_id,
            PsyNetworkLocalDevnetConstants::REALM_GLOBAL_USER_TREE_HEIGHT,
        )?;
        let checkpoint_base = builder.get_coordinator_pending_checkpoint_base::<PoseidonHasher>(
            PsyNetworkLocalDevnetConstants::CHECKPOINT_TREE_HEIGHT,
        );
        checkpoint_base.checkpoint_tree_root.to_u64x4()
    };

    // 2. Current circuit set over the actually configured chain cohort.
    let mut chains: Vec<(u8, ChainConfig)> = args
        .chains
        .iter()
        .map(|spec| parse_chain(spec))
        .collect::<anyhow::Result<Vec<_>>>()?;
    chains.sort_by_key(|(index, _)| *index);
    ensure!(
        chains.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "chain indices must be strictly increasing"
    );
    let chain_indices: Vec<u8> = chains.iter().map(|(index, _)| *index).collect();
    ensure!(
        chains.iter().any(|(index, _)| *index == args.ethereum_index),
        "ethereum_index must name a configured chain"
    );

    // Only the checkpoint state-transition verifier inputs are constructed here: the full
    // coordinator prover graph dominated peak memory (the cancelled run reached 114.9 GB
    // RSS inside get_plonky2_circuit_library_and_prover_for_network before any aggregate
    // construction). Each coordinator graph drops after yielding its compact inputs, and
    // the measured fingerprint is cross-checked against the cached library inside
    // build_circuit_set_registrations.
    let approved = psy_plonky2_circuits::bridge::aggregate_circuits::load_aggregate_setup_config(&args.approved_setup)?;
    let (checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint) =
        build_checkpoint_state_transition_verifier_inputs()?;
    let registrations = AggregateCircuits::build_circuit_set_registrations::<PsyNetworkLocalDevnetConstants>(
        &chain_indices,
        &checkpoint_common_data,
        checkpoint_cap_height,
        checkpoint_fingerprint,
        AggregateCircuitHeights {
            deposit_state_tree: psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
        },
        approved.withdrawal_policies.clone(),
        args.ethereum_index,
    )?;
    let circuit_set_hash = circuit_set_hash(&registrations).context("hashing the circuit set registrations")?;

    // 3. Canonical NetworkConfig encoding.
    let psy_config: serde_json::Value = serde_json::from_slice(&fs::read(&args.psy_config_path)?)
        .with_context(|| format!("reading {}", args.psy_config_path.display()))?;
    let magic_text = psy_config
        .pointer("/networks/localhost/magic")
        .and_then(|value| value.as_str())
        .context("psy config networks.localhost.magic missing")?;
    let network_magic = u64::from_str_radix(magic_text.trim_start_matches("0x"), 16)
        .with_context(|| format!("parsing network magic {magic_text}"))?;

    let reward_payer = parse_address(&args.reward_payer, "reward payer")?;
    let reward_token = parse_address(&args.reward_token, "reward token")?;
    let mut reward_per_claim = [0u8; 32];
    reward_per_claim[16..].copy_from_slice(&args.reward_per_claim.to_be_bytes());

    let network = NetworkConfig {
        version: 1,
        network_magic,
        bridge_user_id: BRIDGE_USER_ID,
        circuit_set_hash,
        chains: chains
            .into_iter()
            .map(|(index, mut chain)| {
                chain.bootstrap_root = bootstrap_root;
                let _ = index;
                chain
            })
            .collect(),
        ethereum_index: args.ethereum_index,
        reward_payer,
        reward_token,
        reward_per_claim,
        reward_token_decimals: args.reward_token_decimals,
        max_withdrawals: args.max_withdrawals,
        max_rewards: args.max_rewards,
    };
    let encoded = network.encode().context("encoding network config")?;
    let network_hex = hex::encode(&encoded);
    NetworkConfig::decode(&encoded).context("re-decoding encoded network config")?;

    let sources = DigestBitsSources {
        node_source: parse_source(&args.source_node, "node")?,
        native_source: parse_source(&args.source_native, "native")?,
        plonky2_source: parse_source(&args.source_plonky2, "plonky2")?,
        wrapper_source: parse_source(&args.source_wrapper, "wrapper")?,
    };
    sources.validate()?;

    // 4. Report; optionally write exactly {network_config, sources}.
    let chain_count = network.chains.len() as u64;
    let n32_budget = 2116 + 992 * chain_count + 224 * DEPOSIT_RECORD_CAPACITY as u64
        + 192 * u64::from(args.max_withdrawals) + 168 * u64::from(args.max_rewards);
    println!("circuit_set_hash       0x{}", hex::encode(circuit_set_hash));
    println!("checkpoint0_root_limbs {:?} bytes {}", bootstrap_root, hash4_hex(bootstrap_root));
    println!("config_hash            0x{}", hex::encode(network.config_hash()?));
    println!("network_magic          {network_magic} (0x{network_magic:016X})");
    println!("chains                 {:?}", chain_indices);
    ensure!(registrations.len() == 10, "bridge registry is not the closed ten-entry set");
    ensure!(
        registrations.iter().any(|registration| (registration.family, registration.level, registration.variant, registration.pi_words) == (14, 0, 1, 22))
            && registrations.iter().any(|registration| (registration.family, registration.level, registration.variant, registration.pi_words) == (14, 0, 0, 90))
            && registrations.iter().any(|registration| (registration.family, registration.level, registration.variant, registration.pi_words) == (15, 0, 0, 30)),
        "reward segment, merge, or root registration differs from the closed set",
    );
    println!("registrations          {}", registrations.len());
    for registration in &registrations {
        println!(
            "  family {} level {} variant {} pi_words {} fingerprint {:?}",
            registration.family, registration.level, registration.variant, registration.pi_words, registration.fingerprint
        );
    }
    println!("n32_window_calldata_budget {n32_budget} bytes (operator max_window_calldata_bytes lower bound)");

    if let Some(out) = &args.out {
        let setup = serde_json::json!({
            "network_config": network_hex,
            "sources": {
                "node_source": sources.node_source,
                "native_source": sources.native_source,
                "plonky2_source": sources.plonky2_source,
                "wrapper_source": sources.wrapper_source,
            },
            "withdrawal_policies": approved.withdrawal_policies,
        });
        let mut text = serde_json::to_vec_pretty(&setup)?;
        text.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out)
            .with_context(|| format!("creating {} (must not exist)", out.display()))?;
        file.write_all(&text)
            .with_context(|| format!("writing {}", out.display()))?;
        println!("wrote {}", out.display());
    } else {
        println!("network_config_hex_len {} (print-only; pass --out to write)", network_hex.len());
    }
    Ok(())
}
