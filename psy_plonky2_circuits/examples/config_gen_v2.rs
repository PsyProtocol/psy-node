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

    let network = psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet;
    let rotation = psy_data::config::network_config::load_realm_rotation_config(network)?;
    let guta_circuits = QEDGUTACircuitManager::<C, D>::new_with_config_and_chain_domain(
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
        psy_data::guta::realm_finalize::realm_finalize_guta_chain_domain::<F, QHashOut<F>, <C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(network.get_chain_id()),
        rotation.checkpoints_per_epoch,
        rotation.validator_sub_ids,
    );
    gcv.register_circuit_triplet(ProvingJobCircuitType::RealmFinalizeGUTA, guta_circuits.realm_finalize_guta.get_verifier_triplet());

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
        coordinator_circuits.state_layout_circuits.batch_deploy_contracts.get_verifier_triplet(),
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
        ProvingJobCircuitType::BatchUpdateContracts,
        coordinator_circuits.state_layout_circuits.batch_update_contracts.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::BatchUpdateContractsAggregate,
        coordinator_circuits.update_agg_state_transition.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::DummyBatchUpdateContractsAggregate,
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

fn inspect_bridge_registry() -> anyhow::Result<()> {
    use parth_core::crypto::hash::traits::FromU64x4;
    use anyhow::Context;
    use psy_client_data::bridge_aggregate::CircuitSetRegistration;
    use psy_plonky2_circuits::{bridge::aggregate_circuits::{AggregateCircuitHeights, AggregateCircuits}, circuit_library::get_plonky2_circuit_library_and_prover_for_network};
    let (_, coordinator) = get_plonky2_circuit_library_and_prover_for_network::<PoseidonGoldilocksConfig, 2>(PsyChainNetworkType::LocalDevnet)?;
    let (checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint) = {
        let checkpoint = &coordinator.checkpoint_root_transition;
        (checkpoint.get_common_circuit_data_ref(), checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(), checkpoint.get_fingerprint())
    };
    let circuits = AggregateCircuits::build::<PsyNetworkLocalDevnetConstants>(&[0], checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint, AggregateCircuitHeights {
        deposit_state_tree: psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
    }, vec![psy_plonky2_circuits::bridge::circuits::bridge_claim::BridgeTokenPolicy {
        chain_index: 0, token_contract_id: 7, token_address: [0, 0, 0, 4, 5, 6, 7, 8],
        approved_leaf: psy_client_data::qdata::contract::PsyContractLeaf { state_tree_height: GoldilocksField::from_canonical_usize(32), ..Default::default() },
        map_base: 8, capacity: 4,
    }], 0)?;
    let registrations = circuits.registrations();
    anyhow::ensure!(registrations.len() == 10, "bridge registry is not the closed ten-entry set");
    let pin = |family: u16, level: u8, variant: u8| registrations.iter().find(|registration|
        (registration.family, registration.level, registration.variant) == (family, level, variant));
    let fingerprint = |registration: &CircuitSetRegistration| QHashOut::<GoldilocksField>::from_u64x4(registration.fingerprint).to_string();
    for registration in registrations {
        anyhow::ensure!(registration.identity_fingerprint == [0; 4] && registration.fingerprint != [0; 4], "bridge registration pin is missing or carries an identity");
        println!("bridge-registration family={} level={} variant={} pi={} fingerprint={}",
            registration.family, registration.level, registration.variant, registration.pi_words, fingerprint(registration));
    }
    let deposit = pin(11, 0, 1).context("deposit aggregate registration missing")?;
    let reward_merge = pin(14, 0, 0).context("reward merge registration missing")?;
    let reward_segment = pin(14, 0, 1).context("reward segment registration missing")?;
    let reward_root = pin(15, 0, 0).context("reward root registration missing")?;
    let reward_batch = pin(16, 0, 0).context("reward batch registration missing")?;
    let withdrawal_claim = pin(17, 0, 0).context("withdrawal claim registration missing")?;
    let reward_claim = pin(18, 0, 0).context("reward claim registration missing")?;
    let checkpoint_final = pin(19, 0, 1).context("checkpoint final registration missing")?;
    let checkpoint_membership = pin(19, 0, 2).context("checkpoint membership registration missing")?;
    let bridge_aggregate = pin(20, 0, 0).context("bridge aggregate registration missing")?;
    anyhow::ensure!(
        registrations.first().map(|registration| (registration.family, registration.level, registration.variant)) == Some((11, 0, 1))
            && pin(1, 0, 0).is_none() && pin(1, 0, 1).is_none()
            && pin(3, 0, 0).is_none() && pin(7, 0, 3).is_none() && pin(9, 0, 1).is_none() && pin(9, 0, 2).is_none()
            && pin(12, 0, 2).is_none() && pin(13, 0, 3).is_none()
            && deposit.pi_words as usize == psy_client_data::bridge_aggregate::deposit_aggregate_pi_len(1)
            && circuits.deposit_aggregate.circuit_data.common.num_public_inputs == deposit.pi_words as usize
            && circuits.reward_merge.circuit_data.common.num_public_inputs == reward_merge.pi_words as usize
            && circuits.reward_segment.circuit_data.common.num_public_inputs == reward_segment.pi_words as usize
            && circuits.reward_root.circuit_data.common.num_public_inputs == reward_root.pi_words as usize,
        "closed set starts at family 11 and constructed widths match the registrations",
    );
    anyhow::ensure!(
        reward_merge.pi_words == 90 && reward_segment.pi_words == 22 && reward_root.pi_words == 30
            && reward_batch.pi_words == 1_029 && withdrawal_claim.pi_words == 2_574 && reward_claim.pi_words == 3_846
            && checkpoint_final.pi_words as usize == 18 + 5 && checkpoint_membership.pi_words == checkpoint_final.pi_words
            && bridge_aggregate.pi_words as usize == 8_316 + 128,
        "bridge registration width mismatch",
    );
    Ok(())
}
fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--inspect-bridge-registry") { return inspect_bridge_registry(); }
    gen_write_config()
}
