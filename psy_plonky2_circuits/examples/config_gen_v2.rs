use std::{fs::File, io::prelude::*, path::PathBuf};

use parth_core::{crypto::hash::traits::ToU64x4, pgoldilocks::QHashOut, protocol::core_types::QNetworkCircuitConstants};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use psy_core::{
    constants::protocol::get_default_worker_rewards_tree_tag, job::job_id::ProvingJobCircuitType, network_config::PsyNetworkLocalDevnetConstants,
};
use psy_plonky2_basic_helpers::{
    lookalike::standard::{
        get_agg_state_transition_type_d_common_data, get_agg_user_registration_deploy_guta_type_f_common_data, get_end_cap_type_e_common_data,
        get_guta_type_c_common_data,
    },
    verifier::{alt::AltVerifierOnlyCircuitData, generic_circuit_library::GenericCircuitVerifier},
};
use psy_plonky2_circuits::{
    coordinator::coordinator_helper::QEDCoordinatorCircuitManager, guta::guta_helper::QEDGUTACircuitManager,
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

    let end_cap_alt_verifier_data_serialized = r#"{"constants_sigmas_cap":["1b5856de6801c92bb0ad2fd11368056a9a5d0dad82aff9945c5bae6897565b27","1d244fedb2f6501cb68a99df5790ead882cd9dbf00dc10f01014a19878e5f13d","a91d9395232831406551ea542996f10df9323493bb9a622ca172f9a08b33420d","ddec529e5c0eda0802893f88ee339b4ddbe91159054d7cc452087d96a25a720d","b1fe8e8aa32f722753a7138fa7c50ddc131e3f69e794df655e72ab05c27132b6","24d48a0e67b1379268ff20367f208ceaf2050f4ac0d71539b79528e7ed21d816","b0a24455f824e7521022f21da1ed16678ad4b0e4f38223fb3029e2e70df9f1f8","f4ee0801387a8601ebd6cf9fa1286f323cea556be58203be1e03a4cb789fa2db","906d34ee2421a469caabd07ba347ab60879ecb2e2fe6792a41b46ffdf5cbece0","1ba3bb0b9afff4cd09899de1fd4143fca5f2a20ef452a8dfd13e0588c5991c61","0537f4536348db599b5b7ff80d30ab511a7cfb11d7e6b9279a479f02e3a184a0","3ed832defddf3cc38d484ee6f9e8349330b5784d54fae75b92e30bcda9552634","1f1fa9c1c3a517fc172488989d0102ba7ef1ed6504922ef3f2a927c14b8cf353","85bf989c4979c5fe13ff5c771d643a0a761a350189eb402223abfffacdb4bc82","8081f52d148499ddb3c33fa96af8dd8144fa03178cea5c0c63bacb27f66f9254","edc979c7efa9df07e9084d01e4e5b4e5d585f0987495c12e29913ba26ce5de68"],"circuit_digest":"c81b3e7dd47fc105d031515c373a22ef4876723c41781fe5849f76a6614aa25f"}"#;


    // use dummy for now
    let end_cap_alt_verifier_data: AltVerifierOnlyCircuitData<F> = serde_json::from_str(&end_cap_alt_verifier_data_serialized)?;

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
fn main() {
    gen_write_config().unwrap();
}
