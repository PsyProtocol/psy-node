use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;
use psy_core::{constants::chain_id::PsyChainNetworkType, network_config::get_circuit_config_for_network};

use crate::{
    proving::{circuits::dummy_end_cap::DummyUPSStandardEndCapCircuit, coordinator_helper::QEDCoordinatorCircuitManager},
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibraryBuilder, generic_circuit_library::JTMBGenericCircuitVerifier,
        jtmb_standard_circuit::JTMBCircuitConfig,
    },
};

/// Deterministic key for the "Circuit Authority" in testing mode.
pub fn get_test_circuit_authority_key(network: PsyChainNetworkType) -> MemorySecp256K1SinglePrivateKeyWallet {
    let seed_str = format!("JTMB_CIRCUIT_AUTHORITY_{:?}", network);
    let seed = parth_crypto::hash::sha256::CoreSha256Hasher::hash_bytes(seed_str.as_bytes());
    MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&seed.0).expect("Failed to create authority wallet")
}

pub fn get_jtmb_circuit_library_and_prover_for_network<C: JTMBCircuitConfig>(
    network: PsyChainNetworkType,
) -> anyhow::Result<(JTMBGenericCircuitVerifier<C>, QEDCoordinatorCircuitManager<C>)> {
    let circuit_config = get_circuit_config_for_network(network);
    let authority_key = get_test_circuit_authority_key(network);

    let mut verifier = JTMBGenericCircuitVerifier::<C>::new();

    let end_cap = DummyUPSStandardEndCapCircuit::<C>::new(&authority_key);
    verifier.library.register_circuit(
        psy_core::job::job_id::ProvingJobCircuitType::UserEndCap,
        end_cap.fingerprint,
        end_cap.verifier_data,
    );

    let manager = QEDCoordinatorCircuitManager::<C>::new(
        &authority_key,
        circuit_config.global_user_tree_realm_height,
        circuit_config.global_user_tree_height,
        circuit_config.guta_circuit_whitelist_tree_height,
        circuit_config.checkpoint_tree_height,
        circuit_config.group_realm_height,
        circuit_config.max_users_to_register_per_proof,
        circuit_config.only_register_max_users_per_proof,
        circuit_config.batch_user_registration_sub_tree_height,
        circuit_config.batch_user_registration_max_sub_trees,
        circuit_config.global_contract_tree_height,
        circuit_config.batch_deploy_contract_sub_tree_height,
        circuit_config.max_contract_state_tree_height,
    );

    manager.register_library(&mut verifier.library);

    Ok((verifier, manager))
}
