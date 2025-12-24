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

    let end_cap_alt_verifier_data_serialized = r#"{"constants_sigmas_cap":["c86feb99f7013eaf5cfb4d178892b7df183d74c0af163cbd48028a597b133e5e","3910ee84260433475e3e055664564d06122ed21670e2f235198867c3270485bb","dd08659e9e52007ea764ee06fabffd375503644b9a51c809d877c52e96e3b325","7aef7a37da269361317d9eceded48469c8b92eba19a374b4619a564f93ea22d2","4de0352b66dcd547cc3c988807bc1f845cdcf19390f1347a8704bab9cfc0a23a","4c1c44648ae179bcdf7bba3d8175d5f9841784ae6825a8cda21bb25ea14dfae7","a6eb5354db416d4cf48bcb08e095cb01de3da6fcfd9f3ec0fb5cce80d93bc150","0379560f3a0e67d9ac362961cf033abd5e7cd6532eb840062e78f9db55374adf","be9bf7caf78fe71bada854c0bb43f490c24f528c8960908663fd3773bd1efb32","40f476af4456e8a3a7090f6a18200b57ed83300603388c9be77b798c98350374","955be7904428c2be491b9206ea2459047e789c2fc3b11348fc8aeffc7c346dde","5aad1eb4b5716f84b71c586199cb8328957f7a6ccdfa6141574ba551e35ea733","068736cea601a05cd5ce668e8f9eef7cbd26c957653b841c79c4a76da9a3c523","10d56b20b27a183c878454013e715746a3b3b8e63ffb79db71f0196502ec4314","37ff0ae51043275985ab52e5cae4dd18e1955a559d9160c4442e55f47ad5c8fc","4f7e206d1e4f1be201835c87470473fe9dea4393d654a93871ad9449121a57ea"],"circuit_digest":"c09f99a1e061591b41396e72144e5b27b8fe4419fb8695f8245bc86bc70b2635"}"#;

    let _dummy_end_cap_alt_verifier_data_serialized = r#" {"constants_sigmas_cap":["75e43fe3eb30167fcb5157afc75aa867b15e1dac6d784c55aa2a4c812a9e72de","18fe157043baa32efbadbc217ec0d381b457928e5b6a7d32cc629510c9d5c13a","ee8fe8d2e3923fee800d92d4bbfbe1be2c9ff3ebcbd642c386423be697d2e3f8","d73d5b79305d2aa63dea475fbda5b29dee6751fe602790e734e3c68f979afbca","66aa5e48ad2156357ab6397e1f8034806af2b9dd4294fa3150c76234141942cb","5f6c5d092df067f37024da90aa3f242481046097d0b295ba75245b4998391714","46e42a956d05e63ec8bba968dedc01f501534f683f42c392a9d84c03362846da","47b09cf057e7a9ba847649248f5dae5c44eb7ca021fc7f0d1eb0e0708a3b1476","7d2701e51e8c699e07652745851f59304f5e7363b8e47808ff958cfd0fca8dda","ae8ad8c909f4bcd321cf72cd7253b36a26d8bcd6fbe8bcf2cd075e8629ccc148","41160fd3e15c02f8ea4c2624a817cc15a902a4fb3c40d8fa672ee0dc7afa6cfa","f8b46aa81046dfb300e663753c7c8ec7260183ed4bb531a30a294967ab262597","65b63a76bf11b1b655de3538594ec5127fe145e1abacf206cb53aa0c5e81d207","31039274aa406e48e75155a7e05d2698dee5f1f239718d20910dae3faae59794","3fd615f34dc310728c36e590d93e6261d5674cb2a83ed69a5415070d3cda0151","4cbe726f1aa6ed74f0ae58455902feb18ee2ead5631f04286bd392f26f77860b"],"circuit_digest":"b2947f9dc3f006c6a26242b11ea186e8443a2243955a648e53075346be800782"}"#;

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
