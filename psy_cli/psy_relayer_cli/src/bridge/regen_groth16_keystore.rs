use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::Args;
use parth_core::{
    crypto::hash::{
        merkle_proof::{compute_root_merkle_proof_generic, DeltaMerkleProofCore, MerkleProofCore},
        tag_tree::{hash_tag_tree_node_four, hash_tag_tree_node_single},
        traits::{FieldQHasher as ParthFieldQHasher, MerkleZeroHasher, QFieldHashable as ParthQFieldHashable},
    },
    pgoldilocks::QHashOut,
    protocol::core_types::QNetworkTreeConstants,
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::{Hasher, PoseidonGoldilocksConfig},
};
use psy_core::{
    constants::protocol::get_default_worker_rewards_tree_tag,
    job::job_id::ProvingJobCircuitType,
    network_config::PsyNetworkLocalDevnetConstants,
};
use psy_data::{
    agg::AggStateTransitionWithStats,
    guta::{
        header::GlobalUserTreeAggregatorHeader,
        realm_finalize::VALIDATOR_TREE_HEIGHT,
        stats::GUTAStats,
        sub_tree_transition::SubTreeNodeStateTransition,
    },
    protocol::circuit_inputs::{
        agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput,
        checkpoint_transition::{QCQEDCheckpointStateTransitionInput, QCQEDCheckpointStateTransitionInputPartial},
    },
    v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafCompact, PQEDCheckpointLeafCompactWithStateRoots, PQEDCheckpointLeafStats},
        pm_jobs_completed_stats::PPMJobsCompletedStats,
        user::PQEDUserLeaf,
    },
};
use psy_client_common::data::qhashout::QHashOut as ClientQHashOut;
use psy_client_data::qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf};
use psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit;
use psy_crypto::{common::user_id::get_registration_id_from_user_id, hash::traits::qhashable::QFieldHashable};
use psy_plonky2_circuits::{
    bridge::{
        circuits::{
            bridge_agg_final::BridgeAggFinalCircuit,
            bridge_wrap::{BridgeWrapCircuit, DepositBatchWrapCircuit, SharedGroth16Wrapper, WithdrawalClaimWrapCircuit},
            reward_claim_wrap::{RewardClaimWrapCircuit, RewardClaimWrapWitness, REWARD_CLAIM_PUBLIC_INPUT_BITS},
            user_reward_checkpoint_aggregate::{UserRewardCheckpointAggregateCircuit, UserRewardCheckpointAggregateWitness},
            user_reward_tree::{
                UserRewardAggregateCircuit, UserRewardAggregateWitness, UserRewardJobWitness, UserRewardLeafCircuit, UserRewardLeafWitness,
                UserRewardRootCircuit, UserRewardRootProof, UserRewardRootWitness, UserRewardTagWitness,
            },
        },
        gadgets::{
            reward_nullifier::{nullifier_job_index, REWARD_NULLIFIER_HEIGHT},
            tree_root_in_contract_state::TreeRootInContractStateWitnessInput,
        },
    },
    proof_minifier::pm_chain::QEDProofMinifierChain,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibraryCore;
use psy_plonky2_common_circuits::bridge::{
    deposit_batch_append_circuit::{BatchAppendInputs, DepositBatchAppendCircuit, DepositLeafData, MAX_DEPOSIT_BATCH_SIZE},
    withdrawal_batch_claim_circuit::{WithdrawalBatchClaimCircuit, WithdrawalBatchClaimInputs, WithdrawalBatchClaimSlotInputs},
};

use crate::bridge::{
    constants::{BRIDGE_USER_ID_U32, BRIDGE_USER_ID_U64, DEPOSIT_TREE_CONTRACT_ID, WITHDRAWAL_TREE_CONTRACT_ID},
    prove_bridge::cached_bridge_coordinator_circuits,
};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

const DEPOSIT_BATCH_TREE_HEIGHT: usize = 32;
const WITHDRAWAL_TREE_HEIGHT: usize = 32;
const CHECKPOINT_TREE_HEIGHT: usize = PsyNetworkLocalDevnetConstants::CHECKPOINT_TREE_HEIGHT_USIZE;
const GLOBAL_USER_TREE_HEIGHT: usize = PsyNetworkLocalDevnetConstants::GLOBAL_USER_TREE_HEIGHT_USIZE;
const GLOBAL_CONTRACT_TREE_HEIGHT: usize = PsyNetworkLocalDevnetConstants::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE;
const DEPOSIT_CONTRACT_STATE_TREE_HEIGHT: usize =
    psy_config::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize;
const WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT: usize =
    psy_config::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize;
const GROTH16_FILES: [&str; 3] = ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"];
const REWARD_CLAIM_DIR: &str = "reward_claim";
const REWARD_USER_ID: u32 = 7;
const REWARD_SOURCE_CHECKPOINT_ID: u32 = 10;
const REWARD_ANCHOR_CHECKPOINT_ID: u32 = 12;
const REWARD_JOB_HEIGHT: u8 = 6;
const REWARD_PRIVATE_KEY: [u64; 4] = [17, 23, 31, 47];
const REWARD_RECIPIENT: [u32; 8] = [1, 2, 3, 4, 5, 0, 0, 0];

#[derive(Debug, Clone, Args)]
pub struct RegenerateGroth16KeystoreArgs {
    /// Keystore root directory. Defaults to ~/.psy/keystore.
    #[arg(long)]
    pub keystore_dir: Option<PathBuf>,
    /// Do not regenerate deposit_append.
    #[arg(long, default_value_t = false)]
    pub skip_deposit_append: bool,
    /// Do not regenerate withdrawal_claim.
    #[arg(long, default_value_t = false)]
    pub skip_withdrawal_claim: bool,
    /// Do not regenerate bridge_agg.
    #[arg(long, default_value_t = false)]
    pub skip_bridge_agg: bool,
    /// Do not regenerate reward_claim.
    #[arg(long, default_value_t = false)]
    pub skip_reward_claim: bool,
}

pub fn run(args: RegenerateGroth16KeystoreArgs) -> anyhow::Result<()> {
    let keystore_dir = args.keystore_dir.unwrap_or_else(default_keystore_dir);
    fs::create_dir_all(&keystore_dir)
        .with_context(|| format!("failed to create keystore dir: {}", keystore_dir.display()))?;

    if !args.skip_deposit_append {
        regenerate_deposit_append(&keystore_dir)?;
    }
    if !args.skip_withdrawal_claim {
        regenerate_withdrawal_claim(&keystore_dir)?;
    }
    if !args.skip_bridge_agg {
        regenerate_bridge_agg(&keystore_dir)?;
    }
    if !args.skip_reward_claim {
        regenerate_reward_claim(&keystore_dir)?;
    }

    println!("regenerated local Groth16 keystore files under {}", keystore_dir.display());
    Ok(())
}

fn regenerate_bridge_agg(keystore_dir: &Path) -> anyhow::Result<()> {
    clear_groth16_files(keystore_dir)?;

    println!("building bridge agg final circuit...");
    let coordinator_circuits = cached_bridge_coordinator_circuits()?;
    let worker_rewards_tree_tag = get_default_worker_rewards_tree_tag::<QHashOut<F>>();
    let checkpoint_common_data = coordinator_circuits
        .checkpoint_root_transition
        .get_common_circuit_data_ref();
    let checkpoint_verifier_data = coordinator_circuits
        .checkpoint_root_transition
        .get_verifier_config_ref();
    let checkpoint_cap_height = checkpoint_verifier_data.constants_sigmas_cap.height();
    let checkpoint_fingerprint = coordinator_circuits.checkpoint_root_transition.get_fingerprint();
    let cached_lib =
        psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library::<F>();
    let checkpoint_step_commit_fingerprint = cached_lib
        .get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
        .context("GenerateRollupStateTransitionProof not found in cached circuit library")?;

    let (deposit_witness, withdrawal_witness, checkpoint_global_state_roots) =
        bridge_state_witnesses()?;
    let register_users_state_root = checkpoint_global_state_roots.user_registration_tree_root;
    let deploy_contracts_state_root = checkpoint_global_state_roots.contract_tree_root;
    let user_tree_root = checkpoint_global_state_roots.user_tree_root;
    let register_users_whitelist = PoseidonHash::q_two_to_one(
        coordinator_circuits.append_user_registration_tree.get_fingerprint(),
        coordinator_circuits.agg_state_transition.get_fingerprint(),
    );
    let deploy_contracts_whitelist = PoseidonHash::q_two_to_one(
        coordinator_circuits
            .state_layout_circuits
            .batch_deploy_contracts
            .get_fingerprint(),
        coordinator_circuits.agg_state_transition.get_fingerprint(),
    );
    let update_contracts_whitelist = PoseidonHash::q_two_to_one(
        coordinator_circuits
            .state_layout_circuits
            .batch_update_contracts
            .get_fingerprint(),
        coordinator_circuits.agg_state_transition.get_fingerprint(),
    );
    let register_users_reward =
        hash_tag_tree_node_single::<QHashOut<F>, PoseidonHash>(&QHashOut::ZERO, &worker_rewards_tree_tag);
    let deploy_contracts_reward =
        hash_tag_tree_node_single::<QHashOut<F>, PoseidonHash>(&QHashOut::ZERO, &worker_rewards_tree_tag);
    let update_contracts_reward =
        hash_tag_tree_node_single::<QHashOut<F>, PoseidonHash>(&QHashOut::ZERO, &worker_rewards_tree_tag);
    let guta_reward =
        hash_tag_tree_node_single::<QHashOut<F>, PoseidonHash>(&QHashOut::ZERO, &worker_rewards_tree_tag);

    let register_users_proof = coordinator_circuits.dummy_agg_state_transition.prove_base(
        register_users_whitelist,
        register_users_state_root,
        worker_rewards_tree_tag,
    ).context("failed to generate dummy register-users aggregate proof")?;
    let deploy_contracts_proof = coordinator_circuits.dummy_agg_state_transition.prove_base(
        deploy_contracts_whitelist,
        deploy_contracts_state_root,
        worker_rewards_tree_tag,
    ).context("failed to generate dummy deploy-contracts aggregate proof")?;
    let update_contracts_proof = coordinator_circuits.dummy_agg_state_transition.prove_base(
        update_contracts_whitelist,
        deploy_contracts_state_root,
        worker_rewards_tree_tag,
    ).context("failed to generate dummy update-contracts aggregate proof")?;

    let genesis_stats = PQEDCheckpointLeafStats::<F, QHashOut<F>>::new_empty();
    let genesis_roots = checkpoint_global_state_roots;
    let genesis_leaf = PQEDCheckpointLeaf {
        global_chain_root: genesis_roots.qfhash::<PoseidonHash>(),
        stats: genesis_stats,
    };
    let genesis_leaf_hash = genesis_leaf.qfhash::<PoseidonHash>();
    let genesis_tree_proof = MerkleProofCore {
        root: compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(
            genesis_leaf_hash,
            0,
            &zero_siblings(CHECKPOINT_TREE_HEIGHT),
        ),
        value: genesis_leaf_hash,
        index: 0,
        siblings: zero_siblings(CHECKPOINT_TREE_HEIGHT),
    };
    let genesis_proof = coordinator_circuits.genesis_checkpoint_root_transition.prove_base(
        genesis_tree_proof.root,
        genesis_leaf_hash,
        coordinator_circuits.genesis_checkpoint_root_transition.get_fingerprint(),
    ).context("failed to generate genesis checkpoint proof")?;
    let genesis_chain_hash = QHashOut::<F>::from_felt_slice(&genesis_proof.public_inputs);

    let checkpoint_leaf_with_roots = PQEDCheckpointLeafCompactWithStateRoots {
        global_state_roots: genesis_roots,
        checkpoint_leaf: PQEDCheckpointLeafCompact {
            global_chain_root: genesis_leaf.global_chain_root,
            stats_hash: genesis_stats.qfhash::<PoseidonHash>(),
        },
    };
    let guta_checkpoint_proof = MerkleProofCore {
        root: genesis_tree_proof.root,
        value: checkpoint_leaf_with_roots.qfhash::<PoseidonHash>(),
        index: 0,
        siblings: zero_siblings(CHECKPOINT_TREE_HEIGHT),
    };
    let guta_proof = coordinator_circuits.guta_circuits.no_change.prove_base(
        worker_rewards_tree_tag,
        coordinator_circuits.guta_circuits.guta_circuit_whitelist_root,
        &guta_checkpoint_proof,
        &checkpoint_leaf_with_roots,
    ).context("failed to generate GUTA no-change proof")?;
    let guta_header = GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: coordinator_circuits.guta_circuits.guta_circuit_whitelist_root,
        checkpoint_tree_root: genesis_tree_proof.root,
        state_transition: SubTreeNodeStateTransition {
            old_node_value: user_tree_root,
            new_node_value: user_tree_root,
            node_index: F::ZERO,
            node_level: F::ZERO,
        },
        stats: GUTAStats::get_zero_value(),
        total_aggregation_proofs_generated: F::ONE,
    };
    let register_users_transition = AggStateTransitionWithStats {
        state_transition_start: register_users_state_root,
        state_transition_end: register_users_state_root,
        total_proofs_generated: 1,
    };
    let deploy_contracts_transition = AggStateTransitionWithStats {
        state_transition_start: deploy_contracts_state_root,
        state_transition_end: deploy_contracts_state_root,
        total_proofs_generated: 1,
    };
    // no-op update contracts transition (start == end == deploy end root)
    let update_contracts_transition = AggStateTransitionWithStats {
        state_transition_start: deploy_contracts_state_root,
        state_transition_end: deploy_contracts_state_root,
        total_proofs_generated: 1,
    };
    let part_1_header = QCAggUserRegistartionDeployContractsGUTAInput {
        register_users_state_transition: register_users_transition,
        deploy_contracts_state_transition: deploy_contracts_transition,
        update_contracts_state_transition: update_contracts_transition,
        guta_proof_header: guta_header,
    };
    let part_1_reward = hash_tag_tree_node_four::<QHashOut<F>, PoseidonHash>(
        &guta_reward,
        &register_users_reward,
        &deploy_contracts_reward,
        &update_contracts_reward,
        &worker_rewards_tree_tag,
    );
    let part_1_proof = coordinator_circuits.agg_user_register_deploy_contracts_guta.prove_base(
        worker_rewards_tree_tag,
        &part_1_header.register_users_state_transition.get_agg_state_transition(),
        &register_users_proof,
        coordinator_circuits.dummy_agg_state_transition.get_verifier_config_ref(),
        register_users_reward,
        F::ONE,
        &part_1_header.deploy_contracts_state_transition.get_agg_state_transition(),
        &deploy_contracts_proof,
        coordinator_circuits.dummy_agg_state_transition.get_verifier_config_ref(),
        deploy_contracts_reward,
        F::ONE,
        &part_1_header.update_contracts_state_transition.get_agg_state_transition(),
        &update_contracts_proof,
        coordinator_circuits.dummy_agg_state_transition.get_verifier_config_ref(),
        update_contracts_reward,
        F::ONE,
        &coordinator_circuits.guta_circuits.no_change_whitelist_proof,
        &part_1_header.guta_proof_header,
        &guta_proof,
        coordinator_circuits.guta_circuits.no_change.get_verifier_config_ref(),
        guta_reward,
    ).context("failed to generate coordinator part-1 proof")?;

    let append_delta = DeltaMerkleProofCore {
        old_root: genesis_tree_proof.root,
        old_value: QHashOut::ZERO,
        new_root: genesis_tree_proof.root,
        new_value: QHashOut::ZERO,
        index: 1,
        siblings: append_siblings_after_first_leaf(genesis_leaf_hash, CHECKPOINT_TREE_HEIGHT),
    };
    let checkpoint_input_partial = QCQEDCheckpointStateTransitionInputPartial {
        part_1_header,
        old_stats: genesis_stats,
        block_time: F::ONE,
        final_random_seed_contribution: qhash(400),
        pm_jobs_completed: PPMJobsCompletedStats {
            deploy_contracts_completed: F::ONE,
            register_users_completed: F::ONE,
            gutas_completed: F::ONE,
        },
        validator_tree_root: <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(
            VALIDATOR_TREE_HEIGHT,
        ),
    };
    let checkpoint_reward_root =
        hash_tag_tree_node_single::<QHashOut<F>, PoseidonHash>(&part_1_reward, &worker_rewards_tree_tag);
    let final_checkpoint_leaf_full =
        checkpoint_input_partial.get_new_checkpoint_leaf::<PoseidonHash>(checkpoint_reward_root);
    let final_checkpoint_leaf = PQEDCheckpointLeafCompact {
        global_chain_root: final_checkpoint_leaf_full.global_chain_root,
        stats_hash: final_checkpoint_leaf_full.stats.qfhash::<PoseidonHash>(),
    };
    let mut checkpoint_input = QCQEDCheckpointStateTransitionInput {
        partial: checkpoint_input_partial,
        append_checkpoint_tree_proof: append_delta,
        previous_checkpoint_proof: genesis_tree_proof,
        genesis_checkpoint_state_transition_hash: genesis_chain_hash,
        last_old_checkpoint_tree_leaf_hash: QHashOut::ZERO,
        last_old_checkpoint_tree_root_hash: QHashOut::ZERO,
        previous_chain_hash: genesis_chain_hash,
        checkpoint_state_transition_circuit_fingerprint: checkpoint_fingerprint,
    };
    checkpoint_input.update_for_prover::<PoseidonHash>(checkpoint_reward_root);

    let part_1_actual_public_inputs = QHashOut::<F>::from_felt_slice(&part_1_proof.public_inputs);
    let part_1_expected_public_inputs = PoseidonHash::q_two_to_one(
        checkpoint_input
            .partial
            .part_1_header
            .get_public_inputs_hash_no_rewards_tag::<PoseidonHash>(),
        part_1_reward,
    );
    anyhow::ensure!(
        part_1_actual_public_inputs == part_1_expected_public_inputs,
        "part-1 public inputs mismatch: actual={:?}, expected={:?}",
        part_1_actual_public_inputs,
        part_1_expected_public_inputs,
    );

    let expected_old_checkpoint_leaf = checkpoint_input
        .partial
        .get_old_checkpoint_leaf::<PoseidonHash>()
        .qfhash::<PoseidonHash>();
    anyhow::ensure!(
        checkpoint_input.previous_checkpoint_proof.value == expected_old_checkpoint_leaf,
        "previous checkpoint leaf mismatch: proof={:?}, expected={:?}",
        checkpoint_input.previous_checkpoint_proof.value,
        expected_old_checkpoint_leaf,
    );
    anyhow::ensure!(
        checkpoint_input.previous_checkpoint_proof.root
            == checkpoint_input.append_checkpoint_tree_proof.old_root,
        "checkpoint Merkle roots are not contiguous",
    );
    anyhow::ensure!(
        checkpoint_input.append_checkpoint_tree_proof.new_value
            == final_checkpoint_leaf_full.qfhash::<PoseidonHash>(),
        "new checkpoint leaf does not match append proof",
    );

    let final_checkpoint_proof = coordinator_circuits.checkpoint_root_transition.prove_base(
        worker_rewards_tree_tag,
        &checkpoint_input,
        part_1_reward,
        &part_1_proof,
        coordinator_circuits.agg_user_register_deploy_contracts_guta.get_verifier_config_ref(),
        &genesis_proof,
        coordinator_circuits.genesis_checkpoint_root_transition.get_verifier_config_ref(),
    ).context("failed to generate checkpoint transition proof")?;

    let delta_merkle_proofs = vec![checkpoint_input.append_checkpoint_tree_proof.clone()];
    let pre_delta_merkle_proofs = vec![DeltaMerkleProofCore {
        new_value: genesis_leaf_hash,
        ..checkpoint_input.append_checkpoint_tree_proof.clone()
    }];

    anyhow::ensure!(
        checkpoint_step_commit_fingerprint == checkpoint_fingerprint,
        "cached checkpoint fingerprint does not match coordinator circuit: cached={:?}, coordinator={:?}",
        checkpoint_step_commit_fingerprint,
        checkpoint_fingerprint,
    );
    let checkpoint_root_and_leaf = hash_two(
        checkpoint_input.append_checkpoint_tree_proof.new_root,
        checkpoint_input.append_checkpoint_tree_proof.new_value,
    );
    let expected_checkpoint_chain_hash = hash_two(
        genesis_chain_hash,
        hash_two(checkpoint_root_and_leaf, checkpoint_step_commit_fingerprint),
    );
    let actual_checkpoint_chain_hash =
        QHashOut::<F>::from_felt_slice(&final_checkpoint_proof.public_inputs);
    anyhow::ensure!(
        actual_checkpoint_chain_hash == expected_checkpoint_chain_hash,
        "checkpoint chain hash mismatch before bridge final: proof={:?}, expected={:?}",
        actual_checkpoint_chain_hash,
        expected_checkpoint_chain_hash,
    );
    anyhow::ensure!(
        checkpoint_global_state_roots.qfhash::<PoseidonHash>()
            == final_checkpoint_leaf.global_chain_root,
        "checkpoint global state roots do not match final checkpoint leaf",
    );
    anyhow::ensure!(
        deposit_witness.user_tree_proof.root == checkpoint_global_state_roots.user_tree_root
            && withdrawal_witness.user_tree_proof.root
                == checkpoint_global_state_roots.user_tree_root,
        "bridge witnesses do not match checkpoint user tree root",
    );

    let result = BridgeAggFinalCircuit::<C, D>::prove_range(
        1,
        1,
        genesis_chain_hash,
        checkpoint_common_data,
        checkpoint_cap_height,
        checkpoint_fingerprint,
        checkpoint_step_commit_fingerprint,
        &final_checkpoint_proof,
        checkpoint_verifier_data,
        &delta_merkle_proofs,
        &pre_delta_merkle_proofs,
        &final_checkpoint_leaf,
        &checkpoint_global_state_roots,
        &deposit_witness,
        &withdrawal_witness,
        CHECKPOINT_TREE_HEIGHT,
        GLOBAL_USER_TREE_HEIGHT,
        GLOBAL_CONTRACT_TREE_HEIGHT,
        DEPOSIT_CONTRACT_STATE_TREE_HEIGHT,
        WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT,
    ).context("failed to generate bridge aggregation final proof")?;

    println!(
        "bridge_agg final fingerprint: {:?}, wrapper keystore: {}",
        result.fingerprint,
        keystore_dir.display()
    );
    let wrap = BridgeWrapCircuit::new(
        &result.common_data,
        result.fingerprint,
        result.verifier_data.constants_sigmas_cap.height(),
    );
    let shared_wrapper = BridgeWrapCircuit::new(
        &result.common_data,
        result.fingerprint,
        result.verifier_data.constants_sigmas_cap.height(),
    )
    .into_shared_groth16_wrapper(format!("{}/", keystore_dir.display()));
    println!("generating bridge_agg Groth16 setup/proof...");
    wrap.prove_groth16_with_shared_wrapper(&shared_wrapper, &result.verifier_data, &result.proof)?;
    require_groth16_files(keystore_dir)?;
    println!("updated {}", keystore_dir.display());
    Ok(())
}

fn regenerate_deposit_append(keystore_dir: &Path) -> anyhow::Result<()> {
    let out_dir = keystore_dir.join("deposit_append");
    clear_groth16_files(&out_dir)?;

    println!("building deposit append circuit...");
    let circuit =
        DepositBatchAppendCircuit::<C, D>::build(MAX_DEPOSIT_BATCH_SIZE, DEPOSIT_BATCH_TREE_HEIGHT);
    let inputs = BatchAppendInputs {
        frontier: [QHashOut::ZERO; DEPOSIT_BATCH_TREE_HEIGHT],
        from_index: 0,
        deposits: vec![sample_deposit()],
        bridge_user_id: BRIDGE_USER_ID_U64 as u32,
    };
    let proof = circuit.generate_proof(&inputs)?;
    let minifier =
        QEDProofMinifierChain::<D, F, C>::new(&circuit.circuit_data.verifier_only, &circuit.circuit_data.common, 2);
    let minified_proof = minifier.prove(&proof)?;
    let fingerprint = QHashOut(minifier.get_fingerprint());
    println!(
        "deposit_append inner fingerprint: {:?}, keystore: {}",
        fingerprint,
        out_dir.display()
    );
    let wrap = DepositBatchWrapCircuit::new(
        minifier.get_common_data(),
        fingerprint,
        minifier.get_verifier_data().constants_sigmas_cap.height(),
    );
    let shared_wrapper = DepositBatchWrapCircuit::new(
        minifier.get_common_data(),
        fingerprint,
        minifier.get_verifier_data().constants_sigmas_cap.height(),
    )
    .into_shared_groth16_wrapper(format!("{}/", out_dir.display()));
    println!("generating deposit_append Groth16 setup/proof...");
    wrap.prove_groth16_with_shared_wrapper(
        &shared_wrapper,
        minifier.get_verifier_data(),
        &minified_proof,
    )?;
    require_groth16_files(&out_dir)?;
    println!("updated {}", out_dir.display());
    Ok(())
}

fn regenerate_withdrawal_claim(keystore_dir: &Path) -> anyhow::Result<()> {
    let out_dir = keystore_dir.join("withdrawal_claim");
    clear_groth16_files(&out_dir)?;

    println!("building withdrawal claim circuit...");
    let circuit = WithdrawalBatchClaimCircuit::<C, D>::build(WITHDRAWAL_TREE_HEIGHT);
    let withdrawal = sample_withdrawal();
    let withdrawal_root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(
        sample_withdrawal_leaf_hash(),
        withdrawal.leaf_index as u64,
        &withdrawal.siblings,
    );
    let inputs = WithdrawalBatchClaimInputs::<F> {
        withdrawal_root,
        bridge_user_id: BRIDGE_USER_ID_U32,
        withdrawals: vec![withdrawal],
    };
    let proof = circuit.generate_proof(&inputs)?;
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit.circuit_data.verifier_only));
    println!(
        "withdrawal_claim inner fingerprint: {:?}, keystore: {}",
        fingerprint,
        out_dir.display()
    );
    let wrap = WithdrawalClaimWrapCircuit::new(
        &circuit.circuit_data.common,
        fingerprint,
        circuit.circuit_data.verifier_only.constants_sigmas_cap.height(),
    );
    let shared_wrapper = WithdrawalClaimWrapCircuit::new(
        &circuit.circuit_data.common,
        fingerprint,
        circuit.circuit_data.verifier_only.constants_sigmas_cap.height(),
    )
    .into_shared_groth16_wrapper(format!("{}/", out_dir.display()));
    println!("generating withdrawal_claim Groth16 setup/proof...");
    wrap.prove_groth16_with_shared_wrapper(
        &shared_wrapper,
        &circuit.circuit_data.verifier_only,
        &proof,
    )?;
    require_groth16_files(&out_dir)?;
    println!("updated {}", out_dir.display());
    Ok(())
}

fn regenerate_reward_claim(keystore_dir: &Path) -> anyhow::Result<()> {
    let out_dir = keystore_dir.join(REWARD_CLAIM_DIR);
    clear_groth16_files(&out_dir)?;

    println!("building reward claim circuits...");
    let leaf = UserRewardLeafCircuit::new();
    let job_aggregate = UserRewardAggregateCircuit::new(&leaf);
    let root = UserRewardRootCircuit::new(&job_aggregate);
    let checkpoint_aggregate = UserRewardCheckpointAggregateCircuit::new(&root);
    let generated = generated_reward_checkpoints()?;
    let root_proof = prove_keyless_reward_root(&leaf, &job_aggregate, &root, &generated)?;
    let checkpoint_proof = checkpoint_aggregate
        .prove(&UserRewardCheckpointAggregateWitness::Root { root: root_proof.clone() })
        .context("failed to prove reward checkpoint aggregate")?;
    checkpoint_aggregate.circuit_data.verify(checkpoint_proof.clone())
        .context("reward checkpoint aggregate proof failed verification")?;
    let witness = reward_claim_wrap_witness(&root_proof, &generated)?;
    let wrap = RewardClaimWrapCircuit::new(
        &checkpoint_aggregate.circuit_data.common,
        checkpoint_aggregate.fingerprint,
        checkpoint_aggregate.circuit_data.verifier_only.constants_sigmas_cap.height(),
    );
    let wrapper_proof = wrap.prove(&checkpoint_aggregate.circuit_data.verifier_only, &checkpoint_proof, &witness)
        .context("failed to prove local reward claim wrapper")?;
    anyhow::ensure!(wrapper_proof.public_inputs.len() == REWARD_CLAIM_PUBLIC_INPUT_BITS, "reward wrapper public input width drifted");
    wrap.circuit_data.verify(wrapper_proof.clone()).context("local reward wrapper proof failed verification")?;
    println!(
        "reward_claim aggregate fingerprint: {:?}, wrapper public inputs: {}, keystore: {}",
        checkpoint_aggregate.fingerprint, wrapper_proof.public_inputs.len(), out_dir.display()
    );
    let shared_circuit = RewardClaimWrapCircuit::new(
        &checkpoint_aggregate.circuit_data.common,
        checkpoint_aggregate.fingerprint,
        checkpoint_aggregate.circuit_data.verifier_only.constants_sigmas_cap.height(),
    );
    let shared_wrapper = SharedGroth16Wrapper::new(shared_circuit.circuit_data, format!("{}/", out_dir.display()));
    println!("generating reward_claim Groth16 setup/proof...");
    shared_wrapper.prove_groth16(&wrapper_proof, None).context("failed to generate reward_claim Groth16 setup/proof")?;
    require_groth16_files(&out_dir)?;
    println!("updated {}", out_dir.display());
    Ok(())
}

struct GeneratedRewardCheckpoints {
    source_leaf: PsyCheckpointLeaf<F>,
    anchor_leaf: PsyCheckpointLeaf<F>,
    global_roots: PsyCheckpointGlobalStateRoots<F>,
    checkpoint_tree_root: HashOut<F>,
    checkpoint_siblings: [HashOut<F>; 32],
    anchor_siblings: [HashOut<F>; 32],
    registration_leaf: HashOut<F>,
    registration_index: u64,
    registration_siblings: [HashOut<F>; psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize],
    private_key: HashOut<F>,
}

fn generated_reward_checkpoints() -> anyhow::Result<GeneratedRewardCheckpoints> {
    let private_key = HashOut { elements: REWARD_PRIVATE_KEY.map(F::from_canonical_u64) };
    let (registration_leaf, registration_index, registration_siblings, registration_root) = registration_membership(REWARD_USER_ID, private_key);
    let mut global_roots = PsyCheckpointGlobalStateRoots::default();
    global_roots.user_registration_tree_root = ClientQHashOut(registration_root);
    let mut source_leaf = PsyCheckpointLeaf::default();
    source_leaf.stats.pm_rewards_commitment.gutas_root = ClientQHashOut::from(reward_job_root(REWARD_USER_ID).0);
    source_leaf.stats.pm_jobs_completed.gutas_completed = F::from_canonical_u32(64);
    source_leaf.stats.guta_fees_collected = F::from_canonical_u32(640);
    let mut anchor_leaf = PsyCheckpointLeaf::default();
    anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
    let mut checkpoints = BTreeMap::new();
    checkpoints.insert(u64::from(REWARD_SOURCE_CHECKPOINT_ID), source_leaf.qfhash::<PoseidonHash>().0);
    checkpoints.insert(u64::from(REWARD_ANCHOR_CHECKPOINT_ID), anchor_leaf.qfhash::<PoseidonHash>().0);
    let (checkpoint_siblings, checkpoint_tree_root) = merkle_path::<32>(&checkpoints, u64::from(REWARD_SOURCE_CHECKPOINT_ID));
    let (anchor_siblings, anchor_root) = merkle_path::<32>(&checkpoints, u64::from(REWARD_ANCHOR_CHECKPOINT_ID));
    anyhow::ensure!(anchor_root == checkpoint_tree_root, "reward source and anchor roots differ");
    Ok(GeneratedRewardCheckpoints { source_leaf, anchor_leaf, global_roots, checkpoint_tree_root, checkpoint_siblings, anchor_siblings, registration_leaf, registration_index, registration_siblings, private_key })
}

fn reward_claim_wrap_witness(root_proof: &UserRewardRootProof, generated: &GeneratedRewardCheckpoints) -> anyhow::Result<RewardClaimWrapWitness> {
    let root_root = HashOut { elements: root_proof.public_inputs[19..23].try_into().map_err(|_| anyhow::anyhow!("reward root statement has no checkpoint root"))? };
    anyhow::ensure!(root_root == generated.checkpoint_tree_root, "reward root proof is not bound to the generated checkpoint tree");
    Ok(RewardClaimWrapWitness {
        token: address_bytes(0x22), state_manager: address_bytes(0x11), anchor_checkpoint_id: REWARD_ANCHOR_CHECKPOINT_ID,
        anchor_leaf: generated.anchor_leaf.clone(), anchor_siblings: generated.anchor_siblings, global_roots: generated.global_roots,
        registration_leaf: generated.registration_leaf, registration_index: generated.registration_index,
        registration_siblings: generated.registration_siblings, private_key: generated.private_key,
    })
}

fn address_bytes(byte: u8) -> [u8; 20] { [byte; 20] }

fn prove_keyless_reward_root(
    leaf: &UserRewardLeafCircuit, job_aggregate: &UserRewardAggregateCircuit, root: &UserRewardRootCircuit, generated: &GeneratedRewardCheckpoints,
) -> anyhow::Result<UserRewardRootProof> {
    let leaf_proof = leaf.prove(&reward_leaf_witness(REWARD_USER_ID, REWARD_SOURCE_CHECKPOINT_ID, &generated.source_leaf)).context("failed to prove reward leaf")?;
    leaf.circuit_data.verify(leaf_proof.clone()).context("reward leaf proof failed verification")?;
    let job_proof = job_aggregate.prove(&UserRewardAggregateWitness::Leaf { leaf: leaf_proof }).context("failed to prove reward job aggregate")?;
    job_aggregate.circuit_data.verify(job_proof.clone()).context("reward job aggregate proof failed verification")?;
    let root_proof = root.prove(&UserRewardRootWitness {
        recipient: REWARD_RECIPIENT, checkpoint_tree_root: generated.checkpoint_tree_root, checkpoint_leaf: generated.source_leaf.clone(),
        checkpoint_siblings: generated.checkpoint_siblings, aggregate_proof: job_proof,
    }).context("failed to prove keyless reward root")?;
    root.circuit_data.verify(root_proof.clone()).context("reward root proof failed verification")?;
    Ok(root_proof)
}

fn reward_leaf_witness(user_id: u32, source_checkpoint_id: u32, checkpoint_leaf: &PsyCheckpointLeaf<F>) -> UserRewardLeafWitness {
    let path_index = 0;
    let coordinate = u64::from(nullifier_job_index(REWARD_JOB_HEIGHT, path_index).expect("reward generation coordinate"));
    let (nullifier_siblings, old_nullifier_root) = merkle_path::<REWARD_NULLIFIER_HEIGHT>(&BTreeMap::new(), coordinate);
    UserRewardLeafWitness {
        user_id, old_nullifier_root,
        job: UserRewardJobWitness { source_checkpoint_id, height: REWARD_JOB_HEIGHT, path_index, tag: reward_job_tag(user_id, path_index) },
        checkpoint_leaf: checkpoint_leaf.clone(), nullifier_siblings,
    }
}

fn reward_job_root(user_id: u32) -> QHashOut<F> {
    let preimage = QHashOut::from_values(u64::from(user_id), 0, 4, 8);
    let owner = PoseidonHash::two_to_one(preimage.0, preimage.0);
    let mut level = (0..64u64).map(|index| tagged_node(QHashOut::from_values(index, 0, 0, 0).0, HashOut::ZERO, owner)).collect::<Vec<_>>();
    for _ in 0..6 { level = level.chunks_exact(2).map(|pair| tagged_node(pair[0], pair[1], HashOut::ZERO)).collect(); }
    QHashOut(level[0])
}

fn reward_job_tag(user_id: u32, path_index: u32) -> UserRewardTagWitness {
    let preimage = QHashOut::from_values(u64::from(user_id), 0, 4, 8);
    let owner = PoseidonHash::two_to_one(preimage.0, preimage.0);
    let mut levels = vec![(0..64u64).map(|index| tagged_node(QHashOut::from_values(index, 0, 0, 0).0, HashOut::ZERO, owner)).collect::<Vec<_>>()];
    for level in 0..6 { levels.push(levels[level].chunks_exact(2).map(|pair| tagged_node(pair[0], pair[1], HashOut::ZERO)).collect()); }
    UserRewardTagWitness {
        tag_preimage: preimage, leaf_left: QHashOut::from_values(u64::from(path_index), 0, 0, 0), leaf_right: QHashOut::ZERO, leaf_tag: QHashOut(owner),
        siblings: std::array::from_fn(|level| if level < 6 { QHashOut(levels[level][usize::try_from(path_index).expect("reward path") >> level ^ 1]) } else { QHashOut::ZERO }),
        parent_tags: [QHashOut::ZERO; 21],
    }
}

fn tagged_node(left: HashOut<F>, right: HashOut<F>, tag: HashOut<F>) -> HashOut<F> {
    PoseidonHash::two_to_one(PoseidonHash::two_to_one(left, right), tag)
}

fn registration_membership(
    user_id: u32, private_key: HashOut<F>,
) -> (HashOut<F>, u64, [HashOut<F>; psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize], HashOut<F>) {
    let public_key_param = psy_ups_circuit::signature::sd_key_plonky2::get_sdc_public_key_param(&ClientQHashOut(private_key));
    let fingerprint = PsyBasicZKSignatureCircuit::<C, D>::new().fingerprint.0;
    let registration_leaf = PoseidonHash::two_to_one(fingerprint, public_key_param.0);
    let registration_index = get_registration_id_from_user_id(u64::from(user_id));
    let (registration_siblings, registration_root) = merkle_path::<{ psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize }>(
        &BTreeMap::from([(registration_index, registration_leaf)]), registration_index,
    );
    (registration_leaf, registration_index, registration_siblings, registration_root)
}

fn merkle_path<const HEIGHT: usize>(leaves: &BTreeMap<u64, HashOut<F>>, index: u64) -> ([HashOut<F>; HEIGHT], HashOut<F>) {
    let mut nodes = leaves.clone();
    let mut position = index;
    let mut empty = HashOut::ZERO;
    let siblings = std::array::from_fn(|_| {
        let sibling = nodes.get(&(position ^ 1)).copied().unwrap_or(empty);
        let mut parents = BTreeMap::new();
        for &child in nodes.keys() {
            parents.insert(child >> 1, PoseidonHash::two_to_one(nodes.get(&(child & !1)).copied().unwrap_or(empty), nodes.get(&(child | 1)).copied().unwrap_or(empty)));
        }
        nodes = parents;
        empty = PoseidonHash::two_to_one(empty, empty);
        position >>= 1;
        sibling
    });
    (siblings, nodes.get(&0).copied().unwrap_or(empty))
}

fn default_keystore_dir() -> PathBuf {
    home::home_dir()
        .expect("HOME is required to resolve default Groth16 keystore path")
        .join(".psy")
        .join("keystore")
}

fn clear_groth16_files(dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create Groth16 keystore dir: {}", dir.display()))?;
    for name in GROTH16_FILES {
        let path = dir.join(name);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("failed to remove {}", path.display())),
        }
    }
    Ok(())
}

fn require_groth16_files(dir: &Path) -> anyhow::Result<()> {
    for name in GROTH16_FILES {
        let path = dir.join(name);
        anyhow::ensure!(path.exists(), "expected generated file missing: {}", path.display());
    }
    Ok(())
}

fn sample_deposit() -> DepositLeafData {
    DepositLeafData {
        shield_address: sample_words(1),
        token: sample_words(11),
        l2_token_contract_id: sample_words(21),
        amount: sample_words(31),
        chain_index: 0,
        note_commitment: sample_words(41),
    }
}

fn sample_withdrawal() -> WithdrawalBatchClaimSlotInputs<F> {
    WithdrawalBatchClaimSlotInputs {
        sender_user_id: 7,
        recipient: sample_words(101),
        token: sample_words(111),
        amount: sample_words(121),
        nonce: sample_words(131),
        destination_chain_index: 0,
        leaf_index: 0,
        siblings: zero_siblings(WITHDRAWAL_TREE_HEIGHT),
    }
}

fn sample_words(seed: u32) -> [u32; 8] {
    [
        seed,
        seed + 1,
        seed + 2,
        seed + 3,
        seed + 4,
        seed + 5,
        seed + 6,
        seed + 7,
    ]
}

fn qhash(seed: u64) -> QHashOut<F> {
    QHashOut(PoseidonHash::hash_no_pad(&[F::from_canonical_u64(seed)]))
}

fn slot_value(seed: u64) -> QHashOut<F> {
    QHashOut::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn hash_two(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F> {
    QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(left.0, right.0))
}

fn zero_siblings(height: usize) -> Vec<QHashOut<F>> {
    let mut siblings = Vec::with_capacity(height);
    let mut current = QHashOut::ZERO;
    for _ in 0..height {
        siblings.push(current);
        current = hash_two(current, current);
    }
    siblings
}

fn append_siblings_after_first_leaf(first_leaf_hash: QHashOut<F>, height: usize) -> Vec<QHashOut<F>> {
    let mut siblings = zero_siblings(height);
    if let Some(first) = siblings.first_mut() {
        *first = first_leaf_hash;
    }
    siblings
}

fn sample_withdrawal_leaf_hash() -> QHashOut<F> {
    let withdrawal = sample_withdrawal();
    let felts = std::iter::once(withdrawal.sender_user_id as u64)
        .chain(withdrawal.recipient.into_iter().map(u64::from))
        .chain(withdrawal.token.into_iter().map(u64::from))
        .chain(withdrawal.amount.into_iter().map(u64::from))
        .chain(withdrawal.nonce.into_iter().map(u64::from))
        .chain(std::iter::once(withdrawal.destination_chain_index as u64))
        .map(F::from_noncanonical_u64)
        .collect::<Vec<_>>();
    QHashOut(PoseidonHash::hash_no_pad(&felts))
}

fn user_leaf_hash(user: &PQEDUserLeaf<F, QHashOut<F>>) -> QHashOut<F> {
    let mut values = Vec::with_capacity(13);
    values.extend_from_slice(&user.public_key.0.elements);
    values.extend_from_slice(&user.user_state_tree_root.0.elements);
    values.extend_from_slice(&[
        user.balance,
        user.nonce,
        user.last_checkpoint_id,
        user.event_index,
        user.user_id,
    ]);
    QHashOut(PoseidonHash::hash_no_pad(&values))
}

fn sparse_merkle_proof(
    leaves: &HashMap<u64, QHashOut<F>>,
    index: u64,
    height: usize,
) -> MerkleProofCore<QHashOut<F>> {
    let mut layer = leaves.clone();
    let value = layer.get(&index).copied().unwrap_or(QHashOut::ZERO);
    let mut siblings = Vec::with_capacity(height);
    let mut cur = index;
    for level in 0..height {
        let sibling_idx = cur ^ 1;
        let sibling = layer
            .get(&sibling_idx)
            .copied()
            .unwrap_or_else(|| <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(level));
        siblings.push(sibling);

        let mut parents = HashSet::new();
        for &k in layer.keys() {
            parents.insert(k >> 1);
        }
        parents.insert(cur >> 1);
        let mut next = HashMap::new();
        for p in parents {
            let left_i = p << 1;
            let right_i = left_i + 1;
            let left = layer
                .get(&left_i)
                .copied()
                .unwrap_or_else(|| <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(level));
            let right = layer
                .get(&right_i)
                .copied()
                .unwrap_or_else(|| <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(level));
            next.insert(p, hash_two(left, right));
        }
        layer = next;
        cur >>= 1;
    }
    MerkleProofCore {
        root: layer.get(&0).copied().unwrap_or_else(|| <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(height)),
        value,
        index,
        siblings,
    }
}

fn bridge_state_witnesses() -> anyhow::Result<(
    TreeRootInContractStateWitnessInput<F>,
    TreeRootInContractStateWitnessInput<F>,
    PQEDCheckpointGlobalStateRoots<QHashOut<F>>,
)> {
    let deposit_slot0 = slot_value(1_000);
    let deposit_slot1 = slot_value(2_000);
    let withdrawal_slot0 = slot_value(3_000);
    let withdrawal_slot1 = slot_value(4_000);

    let mut deposit_leaves = HashMap::new();
    deposit_leaves.insert(0, deposit_slot0);
    deposit_leaves.insert(1, deposit_slot1);
    let deposit_slot0_proof = sparse_merkle_proof(&deposit_leaves, 0, DEPOSIT_CONTRACT_STATE_TREE_HEIGHT);
    let deposit_slot1_proof = sparse_merkle_proof(&deposit_leaves, 1, DEPOSIT_CONTRACT_STATE_TREE_HEIGHT);
    let deposit_state_root = deposit_slot0_proof.root;
    anyhow::ensure!(deposit_slot1_proof.root == deposit_state_root, "deposit state roots mismatch");

    let mut withdrawal_leaves = HashMap::new();
    withdrawal_leaves.insert(0, withdrawal_slot0);
    withdrawal_leaves.insert(1, withdrawal_slot1);
    let withdrawal_slot0_proof = sparse_merkle_proof(&withdrawal_leaves, 0, WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT);
    let withdrawal_slot1_proof = sparse_merkle_proof(&withdrawal_leaves, 1, WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT);
    let withdrawal_state_root = withdrawal_slot0_proof.root;
    anyhow::ensure!(withdrawal_slot1_proof.root == withdrawal_state_root, "withdrawal state roots mismatch");

    let mut contract_leaves = HashMap::new();
    contract_leaves.insert(DEPOSIT_TREE_CONTRACT_ID as u64, deposit_state_root);
    contract_leaves.insert(WITHDRAWAL_TREE_CONTRACT_ID as u64, withdrawal_state_root);
    let deposit_contract_proof =
        sparse_merkle_proof(&contract_leaves, DEPOSIT_TREE_CONTRACT_ID as u64, GLOBAL_CONTRACT_TREE_HEIGHT);
    let withdrawal_contract_proof =
        sparse_merkle_proof(&contract_leaves, WITHDRAWAL_TREE_CONTRACT_ID as u64, GLOBAL_CONTRACT_TREE_HEIGHT);
    anyhow::ensure!(
        deposit_contract_proof.root == withdrawal_contract_proof.root,
        "contract tree roots mismatch"
    );

    let user_leaf = PQEDUserLeaf::new(
        qhash(5_000),
        deposit_contract_proof.root,
        F::ONE,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::from_canonical_u64(BRIDGE_USER_ID_U64),
    );
    let user_hash = user_leaf_hash(&user_leaf);
    let mut user_leaves = HashMap::new();
    user_leaves.insert(BRIDGE_USER_ID_U64, user_hash);
    let user_tree_proof = sparse_merkle_proof(&user_leaves, BRIDGE_USER_ID_U64, GLOBAL_USER_TREE_HEIGHT);

    let global_roots = PQEDCheckpointGlobalStateRoots {
        contract_tree_root: deposit_contract_proof.root,
        deposit_tree_root: <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(32),
        user_tree_root: user_tree_proof.root,
        withdrawal_tree_root: <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(32),
        user_registration_tree_root: qhash(9_000),
        validator_tree_root: <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(
            VALIDATOR_TREE_HEIGHT,
        ),
    };

    let deposit = TreeRootInContractStateWitnessInput {
        owner_user_id: BRIDGE_USER_ID_U64,
        contract_id: DEPOSIT_TREE_CONTRACT_ID as u64,
        user_leaf: user_leaf.clone(),
        slot0_proof: deposit_slot0_proof,
        slot1_proof: deposit_slot1_proof,
        contract_proof: deposit_contract_proof,
        user_tree_proof: user_tree_proof.clone(),
    };
    let withdrawal = TreeRootInContractStateWitnessInput {
        owner_user_id: BRIDGE_USER_ID_U64,
        contract_id: WITHDRAWAL_TREE_CONTRACT_ID as u64,
        user_leaf,
        slot0_proof: withdrawal_slot0_proof,
        slot1_proof: withdrawal_slot1_proof,
        contract_proof: withdrawal_contract_proof,
        user_tree_proof,
    };
    Ok((deposit, withdrawal, global_roots))
}

#[cfg(test)]
mod tests {
    use super::RegenerateGroth16KeystoreArgs;
    use clap::Parser;

    #[derive(Parser)]
    struct Selector {
        #[command(flatten)]
        args: RegenerateGroth16KeystoreArgs,
    }

    fn parsed(argv: &[&str]) -> RegenerateGroth16KeystoreArgs {
        Selector::try_parse_from(std::iter::once("psy_relayer_cli").chain(argv.iter().copied()))
            .unwrap_or_else(|error| panic!("{error}"))
            .args
    }

    #[test]
    fn no_flags_selects_all_four_cohorts() {
        let args = parsed(&[]);
        assert!(!args.skip_deposit_append);
        assert!(!args.skip_withdrawal_claim);
        assert!(!args.skip_bridge_agg);
        assert!(!args.skip_reward_claim);
        assert!(args.keystore_dir.is_none());
    }

    #[test]
    fn skip_flags_select_one_cohort_and_keystore_dir() {
        let reward_only = parsed(&["--skip-deposit-append", "--skip-withdrawal-claim", "--skip-bridge-agg", "--keystore-dir", "target/reward-keystore"]);
        assert!(reward_only.skip_deposit_append);
        assert!(reward_only.skip_withdrawal_claim);
        assert!(reward_only.skip_bridge_agg);
        assert!(!reward_only.skip_reward_claim);
        assert_eq!(reward_only.keystore_dir.unwrap().as_os_str(), "target/reward-keystore");

        let bridge_only = parsed(&["--skip-deposit-append", "--skip-withdrawal-claim", "--skip-reward-claim"]);
        assert!(bridge_only.skip_deposit_append);
        assert!(bridge_only.skip_withdrawal_claim);
        assert!(!bridge_only.skip_bridge_agg);
        assert!(bridge_only.skip_reward_claim);
    }
}
