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

    let end_cap_alt_verifier_data_serialized = r#"{"constants_sigmas_cap":["cd194e038a19a9058b0f5462260b74584daae9b8aba0e6f1b49313b980616adb","80ec73267ec0bddeec66221274f92801da7e80f2984e16330dbdeafd5605fd82","29a443aea0875ca3ed5f0adcb25b34a2bc01ae46eb81d8136b1f8c81bdfc33db","9ead31e4ab43be71044d19da10dedbaed62675486766766874d7a0bed84d927a","140559150290cee35527f6f69c7bfc4c3505e9450eb9845694cceca036519236","33474f7e42581132a329de3aaee232c1a7799401612dcb6ebdc479325fa92c99","c48e4c2ee0b8f7cb6b5664c1b6265f0472fc52606653c8e00704e5dd456d0a50","971fa3b12d6c909e2b1b4e5a06aad6200aa2614226e231b1b0f52df623e04619","eae3ffee472f4d8ebe06ec0c69d2939fd18cc554c87a5891e708e873349446ad","b8fa4c24ae570cdd2f4d30dec6f9268ac56f7ae798afd9ec020d57a56f1c2cf6","905e3ce84bc221cd2eef47912dec70ff6867a2e228f3cb65509f1c7f10c28972","c3a82f831cafd00183163ebc1c2c2013151ed9678c48f2c6e56b0912de93077f","36e5c47286325b53a1d43536f89a08d2b358fba957827c75fac3197a3db5e9a1","80e93a965a9f29093e646990018d248a7eee04f1a739029450e11cd72b87d610","08464c24ffe1773686a08df6e10610bdd3d93bae13366e7b3296bcb8f1870466","7b92b1b16268c694e149849e561953e6e083012ab286fadb1b7434f05db0c326"],"circuit_digest":"bacd8005c7bc6ad9cb4d6e9b03e991f0f2964fd56dd7d96a154e1fc1a194ab76"}"#;

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
