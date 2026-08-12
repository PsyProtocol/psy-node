use std::{fs::File, io::prelude::*, path::PathBuf};

use parth_core::{crypto::hash::traits::ToU64x4, pgoldilocks::QHashOut, protocol::core_types::QNetworkCircuitConstants};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use psy_core::{
    constants::{chain_id::PsyChainNetworkType, protocol::get_default_worker_rewards_tree_tag}, job::job_id::ProvingJobCircuitType, network_config::PsyNetworkLocalDevnetConstants,
};
use psy_plonky2_basic_helpers::{
    lookalike::standard::{
        get_agg_state_transition_type_d_common_data, get_agg_user_registration_deploy_guta_type_f_common_data, get_end_cap_type_e_common_data,
        get_guta_type_c_common_data,
    },
    verifier::generic_circuit_library::GenericCircuitVerifier,
};
use psy_plonky2_circuits::{
    circuit_library::end_cap_verifier_data::get_end_cap_alt_verifier_data_for_network, coordinator::coordinator_helper::QEDCoordinatorCircuitManager, guta::guta_helper::QEDGUTACircuitManager,
    proof_minifier::pm_core::get_circuit_fingerprint_generic_q, qstandard::QStandardCircuit,
};
/*

cargo run --release --package psy_plonky2_circuits --example config_gen_v2

*/

/*


pub trait QNetworkTreeConstants: Sized + Send + Sync + Copy + Clone {

    const CHECKPOINT_TREE_HEIGHT_USIZE: usize;
    const CHECKPOINT_TREE_HEIGHT: u8;

    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const GLOBAL_USER_TREE_HEIGHT: u8;

    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8;

    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8;

    // the height of the global user tree stored in the coordinator (ie. the upper half of the merkle tree)
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8;

     // the height of the global user tree stored in each realm (ie. the height of the sub-trees stored in each realm == GLOBAL_USER_TREE_HEIGHT - COORDINATOR_GLOBAL_USER_TREE_HEIGHT)
    const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8;


    const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize;
    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8;


    const GROUP_REALM_HEIGHT: u8;// 1, for user ids
    const MAX_USERS: u64; // = 2**GLOBAL_USER_TREE_HEIGHT
    const MAX_REALMS: u32; // = 2**COORDINATOR_GLOBAL_USER_TREE_HEIGHT
    const MAX_USERS_PER_REALM: u32; // = 2**REALM_GLOBAL_USER_TREE_HEIGHT



}

pub trait QNetworkTreeCircuitSpecificConstants: Sized + Send + Sync + Copy + Clone {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize;
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize;
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize;
}
*/

fn write_file(path: PathBuf, content: &str) -> anyhow::Result<()> {
    let mut file = File::create(path).map_err(|e| anyhow::anyhow!("{}", e))?;

    file.write(content.as_bytes())?;
    Ok(())
}
fn run_gen_config<N: QNetworkCircuitConstants>() -> anyhow::Result<(String, String)> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    let mut gcv = GenericCircuitVerifier::<C, D>::new();

    /*
    let ups_end_cap = QEDUPSStepCircuitManager::<C, D>::new_with_config(QED_NETWORK_MAGIC_REGTEST).ups_end_cap;
    let end_cap_alt_verifier_data: AltVerifierOnlyCircuitData<F> = ups_end_cap.get_verifier_triplet().1.into();
    let end_cap_alt_verifier_data_serialized = serde_json::to_string(&end_cap_alt_verifier_data)?;
    println!("end_cap_alt_verifier_data_serialized: {}", end_cap_alt_verifier_data_serialized);
    */

    let end_cap_alt_verifier_data = get_end_cap_alt_verifier_data_for_network(PsyChainNetworkType::LocalDevnet)?;

    let end_cap_verifier_data = end_cap_alt_verifier_data.to_verifier_data::<C, D>();
    let end_cap_fingerprint = get_circuit_fingerprint_generic_q::<D, F, C>(&end_cap_verifier_data);

    println!("end_cap_fingerprint: {}", end_cap_fingerprint);
    println!("end_cap_fingerprint_u64x4: {:?}", end_cap_fingerprint.to_u64x4());
    if end_cap_fingerprint.to_u64x4() != N::END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4 {
        anyhow::bail!("Warning: end cap fingerprint does not match network constant!");
    }

    let default_user_state_tree_root = N::get_default_user_state_tree_root::<QHashOut<F>>();
    //let end_cap_common_circuit_data =
    // ups_end_cap.get_common_circuit_data_ref().clone();
    let end_cap_common_data = get_end_cap_type_e_common_data::<C, D>();

    let end_cap_verifier_triplet = (&end_cap_common_data, &end_cap_verifier_data, end_cap_fingerprint);

    gcv.common
        .insert_common_data(ProvingJobCircuitType::TypeC, get_guta_type_c_common_data::<C, D>());
    gcv.common
        .insert_common_data(ProvingJobCircuitType::TypeD, get_agg_state_transition_type_d_common_data::<C, D>());
    gcv.common.insert_common_data(ProvingJobCircuitType::TypeE, end_cap_common_data.clone());
    gcv.common.insert_common_data(
        ProvingJobCircuitType::TypeF,
        get_agg_user_registration_deploy_guta_type_f_common_data::<C, D>(),
    );

    gcv.register_circuit_triplet(ProvingJobCircuitType::UserEndCap, end_cap_verifier_triplet);

    let guta_circuits = QEDGUTACircuitManager::<C, D>::new_with_config(
        &end_cap_common_data,
        end_cap_verifier_data.constants_sigmas_cap.height(),
        N::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE,
        N::GLOBAL_USER_TREE_HEIGHT_USIZE,
        N::GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT,
        N::CHECKPOINT_TREE_HEIGHT_USIZE,
        N::GROUP_REALM_HEIGHT as usize,
        N::MAX_USERS_TO_REGISTER_PER_PROOF,
        N::ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF,
        end_cap_fingerprint,
        default_user_state_tree_root,
        get_default_worker_rewards_tree_tag::<QHashOut<F>>(),
    );

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTASingleEndCap,
        guta_circuits.verify_single_end_cap.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTATwoEndCap,
        guta_circuits.verify_two_end_cap.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(ProvingJobCircuitType::GUTATwoGUTA, guta_circuits.verify_two_guta.get_verifier_triplet());

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
        guta_circuits.verify_two_guta_upgrade_checkpoint.get_verifier_triplet(),
    );

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade,
        guta_circuits.verify_guta_to_cap_upgrade_checkpoint.get_verifier_triplet(),
    );

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTALeftGUTARightEndCap,
        guta_circuits.verify_left_guta_right_end_cap.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTATwoGUTALinear,
        guta_circuits.verify_two_guta_linear_transition.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint,
        guta_circuits.verify_two_guta_linear_transition_upgrade_checkpoint.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTAVerifyToCap,
        guta_circuits.verify_guta_to_cap.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint,
        guta_circuits.verify_guta_left_linear_right_leaf_upgrade_checkpoint.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(ProvingJobCircuitType::GUTANoChange, guta_circuits.no_change.get_verifier_triplet());
    let coordinator_circuits = QEDCoordinatorCircuitManager::<C, D>::new_with_guta(
        guta_circuits,
        N::GLOBAL_USER_TREE_HEIGHT_USIZE,
        N::BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT,
        N::BATCH_USER_REGISTRATION_MAX_SUB_TREES,
        N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
        N::BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT,
        N::GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT,
        N::CHECKPOINT_TREE_HEIGHT_USIZE,
        N::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE,
        get_default_worker_rewards_tree_tag::<QHashOut<F>>(),
    );

    coordinator_circuits.register_library(&mut gcv.library);

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::AppendUserRegistrationTree,
        coordinator_circuits.append_user_registration_tree.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
        coordinator_circuits.agg_state_transition.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
        coordinator_circuits.dummy_agg_state_transition.get_verifier_triplet(),
    );

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::BatchDeployContracts,
        coordinator_circuits.batch_deploy_contracts.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::BatchDeployContractsAggregate,
        coordinator_circuits.agg_state_transition.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
        coordinator_circuits.dummy_agg_state_transition.get_verifier_triplet(),
    );

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA,
        coordinator_circuits.agg_user_register_deploy_contracts_guta.get_verifier_triplet(),
    );

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GenerateRollupStateTransitionProof,
        coordinator_circuits.checkpoint_root_transition.get_verifier_triplet(),
    );

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GenesisBlockCheckpointStateTransition,
        coordinator_circuits.genesis_checkpoint_root_transition.get_verifier_triplet(),
    );

    gcv.common.print_common();

    // Generate Groth16 setup for bridge wrap circuit
    #[cfg(feature = "gnark-wrap")]
    generate_groth16_setup::<N>(&coordinator_circuits)?;
    let gcv_ser = gcv.to_serialized();

    let library_data = serde_json::to_string(&gcv_ser.library)?;
    let common_info_data = serde_json::to_string(&gcv_ser.common)?;
    println!("[START: cached_circuit_library.rs]");
    let cached_circuit_library = format!(
        r#"// AUTOGENERATED - DO NOT MODIFY
use plonky2::hash::hash_types::RichField;
use psy_plonky2_basic_helpers::verifier::simple_circuit_library::{{SerializableSimpleCircuitLibrary, SimpleCircuitLibrary}};

pub fn get_cached_circuit_library<F: RichField>() -> SimpleCircuitLibrary<F> {{
    SimpleCircuitLibrary::from_serialized(
        serde_json::from_str::<SerializableSimpleCircuitLibrary<F>>(
            r{}"{}"{}
        ).unwrap()
    )
}}
"#,
        "#", library_data, "#"
    );
    println!("[END: cached_circuit_library.rs]");

    println!("[START: cached_common_data.rs]");
    let cached_common_data = format!(
        r#"// AUTOGENERATED - DO NOT MODIFY
use plonky2::plonk::config::{{AlgebraicHasher, GenericConfig}};
use psy_plonky2_basic_helpers::{{lookalike::standard::{{get_agg_state_transition_type_d_common_data, get_agg_user_registration_deploy_guta_type_f_common_data, get_end_cap_type_e_common_data, get_guta_type_c_common_data}}, verifier::generic_circuit_library::{{GenericCircuitCommonDataLibrary, SerializedGenericCircuitCommonDataLibraryInfo}}}};


pub fn get_cached_common_data_library<C: GenericConfig<D>, const D: usize>(
) -> GenericCircuitCommonDataLibrary<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{{
    let serialized_library =
        serde_json::from_str::<SerializedGenericCircuitCommonDataLibraryInfo>(
            r{}"{}"{}
        ).unwrap();

    GenericCircuitCommonDataLibrary::<C, D>::from_serialized(
        &serialized_library,
        vec![
            get_guta_type_c_common_data::<C, D>(),
            get_agg_state_transition_type_d_common_data::<C, D>(),
            get_end_cap_type_e_common_data::<C, D>(),
            get_agg_user_registration_deploy_guta_type_f_common_data::<C, D>(),
        ],
    )
    .unwrap()
}}
"#,
        "#", common_info_data, "#"
    );
    println!("[END: cached_common_data.rs]");

    Ok((cached_circuit_library, cached_common_data))
}

#[cfg(feature = "gnark-wrap")]
fn generate_groth16_setup<N: QNetworkCircuitConstants>(
    coordinator_circuits: &QEDCoordinatorCircuitManager<plonky2::plonk::config::PoseidonGoldilocksConfig, 2>,
) -> anyhow::Result<()> {
    use psy_plonky2_circuits::{
        bridge::circuits::{bridge_agg_final::BridgeAggFinalCircuit, bridge_wrap::BridgeWrapCircuit},
    };

    type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
    const D: usize = 2;
    type F = plonky2::field::goldilocks_field::GoldilocksField;

    let checkpoint_circuit = &coordinator_circuits.checkpoint_root_transition;
    let checkpoint_common = checkpoint_circuit.get_common_circuit_data_ref();
    let checkpoint_fp = checkpoint_circuit.get_fingerprint();
    let checkpoint_cap_height = checkpoint_circuit.get_verifier_config_ref().constants_sigmas_cap.height();

    println!("[Groth16Setup] Building BridgeAggFinalCircuit...");
    let final_circuit = BridgeAggFinalCircuit::<C, D>::prebuild_final_circuit(
        checkpoint_common,
        checkpoint_cap_height,
        checkpoint_fp,
        checkpoint_fp,
        N::CHECKPOINT_TREE_HEIGHT_USIZE,
        N::GLOBAL_USER_TREE_HEIGHT_USIZE,
        N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
        N::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE,
        N::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE,
    );

    let bridge_agg_common = &final_circuit.circuit_data.common;
    let bridge_agg_fp = final_circuit.get_fingerprint();
    let bridge_agg_verifier = &final_circuit.circuit_data.verifier_only;
    let bridge_agg_cap_height = bridge_agg_verifier.constants_sigmas_cap.height();

    println!("[Groth16Setup] Building BridgeWrapCircuit + SharedGroth16Wrapper...");
    let bridge_wrap = BridgeWrapCircuit::new(bridge_agg_common, bridge_agg_fp, bridge_agg_cap_height);
    let keystore = std::env::var("HOME")
        .map(|h| format!("{h}/.psy/keystore"))
        .unwrap_or_else(|_| "/tmp/psy-keystore".to_string());
    std::fs::create_dir_all(&keystore)?;

    let shared_wrapper = bridge_wrap.into_shared_groth16_wrapper(keystore.clone());
    let wrapper_circuit_data = &shared_wrapper.wrapped_circuit.wrapper_circuit.data;

    println!("[Groth16Setup] Serializing wrapper circuit data...");
    let common_json = serde_json::to_string(&wrapper_circuit_data.common)?;
    let verifier_json = serde_json::to_string(&wrapper_circuit_data.verifier_only)?;
    let n_pi = wrapper_circuit_data.common.num_public_inputs;
    println!("[Groth16Setup] Wrapper circuit num_public_inputs = {n_pi}");

    // The WrappedCircuit (Groth16WrapperParameters) has a fixed config regardless of the inner
    // circuit, so the proof structure (cap sizes, FRI params) is the same across checkpoint
    // fingerprint changes. We reuse an existing wrapper proof from /tmp/plonky2_proof/ for
    // generate_groth16_proof will run groth16.Setup after stale keys are removed.
    // only the JSON structure (array sizes, public_inputs count) matters.
    let proof_json = match find_existing_wrapper_proof(n_pi) {
        Some(json) => {
            println!("[Groth16Setup] Reusing existing wrapper proof from /tmp/plonky2_proof/");
            json
        }
        None => {
            println!("[Groth16Setup] No existing wrapper proof found with {n_pi} public inputs.");
            println!("[Groth16Setup] Skipping groth16 setup — run a devnet prove cycle first to");
            println!("[Groth16Setup] generate a wrapper proof in /tmp/plonky2_proof/, then re-run.");
            return Ok(());
        }
    };

    // Remove stale keys so setup does not skip.
    for fname in ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"] {
        let p = format!("{keystore}/{fname}");
        if std::path::Path::new(&p).exists() {
            println!("[Groth16Setup] Removing stale {p}");
            std::fs::remove_file(&p)?;
        }
    }

    println!("[Groth16Setup] Calling generate_groth16_proof to force setup...");
    let (proof_result, vk_result) =
        gnark_plonky2_verifier_ffi::generate_groth16_proof(&common_json, &proof_json, &verifier_json, &keystore);
    if proof_result.starts_with("error:") {
        anyhow::bail!("generate_groth16_proof failed: {proof_result}");
    }
    if vk_result.starts_with("error:") {
        anyhow::bail!("generate_groth16_proof failed: {vk_result}");
    }
    println!("[Groth16Setup] Groth16 setup written to {keystore}");

    println!("[Groth16Setup] Exporting Solidity verifier...");
    let sol = gnark_plonky2_verifier_ffi::export_solidity_verifier(&keystore);
    if sol.starts_with("error:") {
        anyhow::bail!("export_solidity_verifier failed: {sol}");
    }
    let sol_path = "psy-contracts/src/GnarkGroth16Verifier.sol";
    std::fs::write(sol_path, &sol)?;
    println!("[Groth16Setup] Solidity verifier written to {sol_path}");

    Ok(())
}

#[cfg(feature = "gnark-wrap")]
/// Search /tmp/plonky2_proof/ for a wrapper proof JSON with the expected number of public inputs.
/// The WrappedCircuit (Groth16WrapperParameters) has a fixed config, so any existing wrapper proof
/// has the correct JSON structure (cap sizes, FRI params) for setup — only the public_inputs
/// count must match.
fn find_existing_wrapper_proof(expected_num_pi: usize) -> Option<String> {
    let proof_dir = "/tmp/plonky2_proof";
    let entries = std::fs::read_dir(proof_dir).ok()?;
    for entry in entries.flatten() {
        let proof_path = entry.path().join("proof_with_public_inputs.json");
        if !proof_path.exists() {
            continue;
        }
        let content = match std::fs::read_to_string(&proof_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // Quick check: does the public_inputs array length match?
        if let Ok(proof_val) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(pi) = proof_val.get("public_inputs").and_then(|v| v.as_array()) {
                if pi.len() == expected_num_pi {
                    return Some(content);
                }
            }
        }
    }
    None
}

fn gen_write_config() -> anyhow::Result<()> {
    let (cached_circuit_library, cached_common_data) = run_gen_config::<PsyNetworkLocalDevnetConstants>()?;
    let current_cached_circuit_library = std::fs::read_to_string(PathBuf::from_iter([
        "psy_plonky2_circuits",
        "src",
        "generated",
        "cached_circuit_library.rs",
    ]))?;
    let current_cached_common_data =
        std::fs::read_to_string(PathBuf::from_iter(["psy_plonky2_circuits", "src", "generated", "cached_common_data.rs"]))?;

    if current_cached_circuit_library != cached_circuit_library {
        write_file(
            PathBuf::from_iter(["psy_plonky2_circuits", "src", "generated", "cached_circuit_library.rs"]),
            &cached_circuit_library,
        )?;
    }else{
        println!("cached_circuit_library.rs is up to date.");
    }
    if current_cached_common_data != cached_common_data {
        write_file(
            PathBuf::from_iter(["psy_plonky2_circuits", "src", "generated", "cached_common_data.rs"]),
            &cached_common_data,
        )?;
    }else{
        println!("cached_common_data.rs is up to date.");
    }

    Ok(())
}
fn main() {
    gen_write_config().unwrap();
}
