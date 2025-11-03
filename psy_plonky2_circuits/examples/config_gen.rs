use parth_core::pgoldilocks::QHashOut;
use parth_core::protocol::core_types::{QNetworkCircuitConstants, QNetworkTreeCircuitConstants, QNetworkTreeConstants};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_core::constants::protocol::get_default_worker_public_key;
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_plonky2_basic_helpers::lookalike::standard::{get_agg_state_transition_type_d_common_data, get_agg_user_registration_deploy_guta_type_f_common_data, get_end_cap_type_e_common_data, get_guta_type_c_common_data};
use psy_plonky2_basic_helpers::verifier::alt::AltVerifierOnlyCircuitData;
use psy_plonky2_basic_helpers::verifier::generic_circuit_library::GenericCircuitVerifier;
use psy_plonky2_circuits::coordinator::coordinator_helper::QEDCoordinatorCircuitManager;
use psy_plonky2_circuits::guta::guta_helper::QEDGUTACircuitManager;
use psy_plonky2_circuits::qstandard::QStandardCircuit;
use std::{fs::File, path::PathBuf};
use std::io::prelude::*;
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

pub trait QNetworkTreeCircuitConstants: Sized + Send + Sync + Copy + Clone {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize;
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize;
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize;
}
*/
#[derive(Debug, Copy, Clone)]
pub struct QPsyRegtestNetworkConstants;
impl QNetworkTreeCircuitConstants for QPsyRegtestNetworkConstants {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize = 32;
    const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize = 64;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize = 8; 
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize = 4; 
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;
    const CHAIN_ID: u32 = 0;
}

impl QNetworkTreeConstants for QPsyRegtestNetworkConstants {
    const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
    const CHECKPOINT_TREE_HEIGHT: u8 = Self::CHECKPOINT_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 24;
    const GLOBAL_USER_TREE_HEIGHT: u8 = Self::GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = Self::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE as u8;

    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = Self::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE as u8;

    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 4;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 20;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = Self::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize = 32;
    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = Self::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE as u8;

    const GROUP_REALM_HEIGHT: u8 = 1;

    const MAX_USERS: u64 = 1 << Self::GLOBAL_USER_TREE_HEIGHT;

    const MAX_REALMS: u32 = 1 << Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT;

    const MAX_USERS_PER_REALM: u32 = 1 << Self::REALM_GLOBAL_USER_TREE_HEIGHT;

}

pub const DEFAULT_USER_STATE_TREE_ROOT: QHashOut<GoldilocksField> = QHashOut::<GoldilocksField>(
    HashOut {
        elements: [
            GoldilocksField(3896366420105793420),
            GoldilocksField(17410332186442776169),
            GoldilocksField(7329967984378645716),
            GoldilocksField(6310665049578686403),
        ],
    }
);
fn write_file(path: PathBuf, content: &str) -> anyhow::Result<()> {
    let mut file = File::create(path).map_err(|e| anyhow::anyhow!("{}",e))?;

    file.write(content.as_bytes())?;
    Ok(())
}
fn run_gen_config<N: QNetworkCircuitConstants>(default_user_state_tree_root: QHashOut<GoldilocksField>) -> anyhow::Result<(String, String)> {

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    let mut gcv = GenericCircuitVerifier::<C,D>::new();
    //let ups_end_cap = QEDUPSStepCircuitManager::<C, D>::new_with_config(QED_NETWORK_MAGIC_REGTEST).ups_end_cap;    

    



    //let end_cap_alt_verifier_data: AltVerifierOnlyCircuitData<F> = ups_end_cap.get_verifier_triplet().1.into();
    //let end_cap_fingerprint = ups_end_cap.get_verifier_triplet().2;

    //let end_cap_alt_verifier_data_serialized = serde_json::to_string(&end_cap_alt_verifier_data)?;
    let end_cap_alt_verifier_data_serialized = r#"{"constants_sigmas_cap":["525b6e059fae0223643cd1f7a77a7f4f81d315463f8b71eb53e277348cbcb790","2adba52bd14623c0713dc1160badb22727abe0ff05a663978b679797b6f2c5f0","f07493d44b443b558122332465cc23dd5eecd14c72543ebed54847362131eab2","831798dc845ad63594b90475ac496d0a43a243c20a222ffa9f38c07cfaddcb2c","74b4af284ee4d48a90eb6c61884116cc0875b6256e3f36baedf312e104e7fee5","99f3594451eba8c66f6b553491ccc32ccfa4fbec04d5e102cc79d2e3737148bd","4c5362ff9fbeaad4addc80d51828eec5614c4601e2c3183c3e9ba7b2d457548e","a321639f5241a6c3a79d8c83712ad07cb7cbd98ed10c670a17bdb62930c7b00f","d87f431257071a7ff869fa1d62694fa11f4893aefdd7e3c535e9152ea69b5468","86e7bca4bbfde06b7fd52e04d774bc43cf6e7bb301567da4b15926dd797550ed","f2656c41f04e755b18fe1d166837c2fa10f0278d683afc3691bc23da0858c1e0","16709179a87677524c274c00ca0d0149495b6465a1a76961f9b031743dcef350","5c45a6d741c9718df7dfeffeae517bd6d0a7e0800df3bc445b835b8401b61054","b767d5c6b3e462fb7446238ea2fb4779af36c52e6228c0d95e23d5a1dee9798b","40a3d76ae5ef3d6a9937524066653f5b55a4c1295b90374fa4a4854da28f0301","04a41de70f1df51e9a5833fd36355235afa7603b0378b54d21f839f299f07e7f"],"circuit_digest":"3430186537e4b1b21a532e0589e212de584caf66b84ae2e80e64936c651a9793"}"#;
    //let end_cap_fingerprint_serialized = serde_json::to_string(&end_cap_fingerprint)?;
    let end_cap_fingerprint_serialized = r#""5944cd3dbd0eb2246547ece6f2fdd2ff0b0a1e448826cd910b8b4ea53a1fc05e""#;

    println!("end_cap_alt_verifier_data: {}", end_cap_alt_verifier_data_serialized);
    let end_cap_alt_verifier_data: AltVerifierOnlyCircuitData<F> = serde_json::from_str(&end_cap_alt_verifier_data_serialized)?;
    
    println!("end_cap_fingerprint: {}", end_cap_fingerprint_serialized);
    let end_cap_fingerprint: QHashOut<F> = serde_json::from_str(&end_cap_fingerprint_serialized)?;


    // for dummy end cap testing
    let dummy_end_cap_fingerprint = "\"2ab5786249b4f4f739207b25a2254a27400329fe7eae8199b101da6948267d92\"";
    let dummy_end_cap_alt_verifier_data_serialized = r#" {"constants_sigmas_cap":["75e43fe3eb30167fcb5157afc75aa867b15e1dac6d784c55aa2a4c812a9e72de","18fe157043baa32efbadbc217ec0d381b457928e5b6a7d32cc629510c9d5c13a","ee8fe8d2e3923fee800d92d4bbfbe1be2c9ff3ebcbd642c386423be697d2e3f8","d73d5b79305d2aa63dea475fbda5b29dee6751fe602790e734e3c68f979afbca","66aa5e48ad2156357ab6397e1f8034806af2b9dd4294fa3150c76234141942cb","5f6c5d092df067f37024da90aa3f242481046097d0b295ba75245b4998391714","46e42a956d05e63ec8bba968dedc01f501534f683f42c392a9d84c03362846da","47b09cf057e7a9ba847649248f5dae5c44eb7ca021fc7f0d1eb0e0708a3b1476","7d2701e51e8c699e07652745851f59304f5e7363b8e47808ff958cfd0fca8dda","ae8ad8c909f4bcd321cf72cd7253b36a26d8bcd6fbe8bcf2cd075e8629ccc148","41160fd3e15c02f8ea4c2624a817cc15a902a4fb3c40d8fa672ee0dc7afa6cfa","f8b46aa81046dfb300e663753c7c8ec7260183ed4bb531a30a294967ab262597","65b63a76bf11b1b655de3538594ec5127fe145e1abacf206cb53aa0c5e81d207","31039274aa406e48e75155a7e05d2698dee5f1f239718d20910dae3faae59794","3fd615f34dc310728c36e590d93e6261d5674cb2a83ed69a5415070d3cda0151","4cbe726f1aa6ed74f0ae58455902feb18ee2ead5631f04286bd392f26f77860b"],"circuit_digest":"b2947f9dc3f006c6a26242b11ea186e8443a2243955a648e53075346be800782"}"#;
    let dummy_end_cap_fingerprint: QHashOut<F> = serde_json::from_str(&dummy_end_cap_fingerprint)?;
    let dummy_end_cap_alt_verifier_data: AltVerifierOnlyCircuitData<F> = serde_json::from_str(&dummy_end_cap_alt_verifier_data_serialized)?;
    let end_cap_fingerprint = dummy_end_cap_fingerprint;
    let end_cap_alt_verifier_data = dummy_end_cap_alt_verifier_data;


    //let end_cap_common_circuit_data = ups_end_cap.get_common_circuit_data_ref().clone();
    let end_cap_common_data = get_end_cap_type_e_common_data::<C,D>();

    let end_cap_verifier_data = end_cap_alt_verifier_data.to_verifier_data::<C, D>();
    let end_cap_verifier_triplet = (
        &end_cap_common_data,
        &end_cap_verifier_data,
        end_cap_fingerprint,
    );


    gcv.common.insert_common_data(ProvingJobCircuitType::TypeC, get_guta_type_c_common_data::<C,D>());
    gcv.common.insert_common_data(ProvingJobCircuitType::TypeD, get_agg_state_transition_type_d_common_data::<C,D>());
    gcv.common.insert_common_data(ProvingJobCircuitType::TypeE, end_cap_common_data.clone());
    gcv.common.insert_common_data(ProvingJobCircuitType::TypeF, get_agg_user_registration_deploy_guta_type_f_common_data::<C,D>());


    gcv.register_circuit_triplet(
        ProvingJobCircuitType::UserEndCap,
        end_cap_verifier_triplet,
    );


    let guta_circuits = QEDGUTACircuitManager::<C,D>::new_with_config(
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
        get_default_worker_public_key::<QHashOut<F>>(),

    );

    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTASingleEndCap,
        guta_circuits.verify_single_end_cap.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTATwoEndCap,
        guta_circuits.verify_two_end_cap.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTATwoGUTA,
        guta_circuits.verify_two_guta.get_verifier_triplet(),
    );

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
        ProvingJobCircuitType::GUTALeftEndCapRightGUTA,
        guta_circuits.verify_left_end_cap_right_guta.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTARegisterUsers,
        guta_circuits.verify_guta_register_users.get_verifier_triplet(),

    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTAVerifyToCap,
        guta_circuits.verify_guta_to_cap.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTAOnlyRegisterUsers,
        guta_circuits.only_register_users.get_verifier_triplet(),
    );
    gcv.register_circuit_triplet(
        ProvingJobCircuitType::GUTANoChange,
        guta_circuits.no_change.get_verifier_triplet(),
    );
    let coordinator_circuits = QEDCoordinatorCircuitManager::<C,D>::new_with_guta(
        guta_circuits, 
        N::GLOBAL_USER_TREE_HEIGHT_USIZE,
        N::BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT,
        N::BATCH_USER_REGISTRATION_MAX_SUB_TREES,
        N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
        N::BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT,
        N::GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT,
        N::CHECKPOINT_TREE_HEIGHT_USIZE,
        N::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE,

        get_default_worker_public_key::<QHashOut<F>>()
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


    gcv.common.print_common();


    let gcv_ser = gcv.to_serialized();

    let library_data = serde_json::to_string(&gcv_ser.library)?;
    let common_info_data = serde_json::to_string(&gcv_ser.common)?;
    println!("[START: cached_circuit_library.rs]");
    let cached_circuit_library = format!(r#"// AUTOGENERATED - DO NOT MODIFY
use plonky2::hash::hash_types::RichField;
use psy_plonky2_basic_helpers::verifier::simple_circuit_library::{{SerializableSimpleCircuitLibrary, SimpleCircuitLibrary}};

pub fn get_cached_circuit_library<F: RichField>() -> SimpleCircuitLibrary<F> {{
    SimpleCircuitLibrary::from_serialized(
        serde_json::from_str::<SerializableSimpleCircuitLibrary<F>>(
            r{}"{}"{}
        ).unwrap()
    )
}}
"#,"#",library_data,"#");
println!("[END: cached_circuit_library.rs]");

println!("[START: cached_common_data.rs]");
let cached_common_data = format!(r#"// AUTOGENERATED - DO NOT MODIFY
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
"#,"#",common_info_data,"#");
println!("[END: cached_common_data.rs]");


    Ok((cached_circuit_library, cached_common_data))
}

fn gen_write_config() -> anyhow::Result<()> {
    let (cached_circuit_library, cached_common_data) = run_gen_config::<QPsyRegtestNetworkConstants>(DEFAULT_USER_STATE_TREE_ROOT)?;


    write_file(PathBuf::from_iter(["psy_plonky2_circuits","src","generated","cached_circuit_library.rs"]), &cached_circuit_library)?;
    write_file(PathBuf::from_iter(["psy_plonky2_circuits", "src", "generated" ,"cached_common_data.rs"]), &cached_common_data)?;


    Ok(())


}
fn main() {
    gen_write_config().unwrap();
}
