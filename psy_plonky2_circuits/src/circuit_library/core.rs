use parth_core::{crypto::hash::traits::{FromU64x4, MerkleZeroHasher}, pgoldilocks::{QHashOut, QRichField}};
use plonky2::{hash::hash_types::{HashOut, RichField}, plonk::config::{AlgebraicHasher, GenericConfig}};
use psy_core::{constants::{chain_id::PsyChainNetworkType, protocol::get_default_worker_rewards_tree_tag}, job::job_id::ProvingJobCircuitType, network_config::get_circuit_config_for_network};
use psy_plonky2_basic_helpers::{lookalike::standard::{get_agg_state_transition_type_d_common_data, get_agg_user_registration_deploy_guta_type_f_common_data, get_end_cap_type_e_common_data, get_guta_type_c_common_data}, verifier::{alt::AltVerifierOnlyCircuitData, generic_circuit_library::GenericCircuitVerifier}};

use crate::{circuit_library::end_cap_verifier_data::get_end_cap_alt_verifier_data_for_network, coordinator::coordinator_helper::QEDCoordinatorCircuitManager, guta::guta_helper::QEDGUTACircuitManager, proof_minifier::pm_core::get_circuit_fingerprint_generic_q, qstandard::QStandardCircuit};



pub fn get_plonky2_circuit_library_and_prover_for_network<C: GenericConfig<D> + 'static, const D: usize>(
    network: PsyChainNetworkType,
) -> anyhow::Result<(GenericCircuitVerifier<C, D>, QEDCoordinatorCircuitManager<C, D>)> 
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>, C::F: RichField + QRichField,{

    let mut gcv = GenericCircuitVerifier::<C, D>::new();

    // use dummy for now
    let end_cap_alt_verifier_data: AltVerifierOnlyCircuitData<C::F> = get_end_cap_alt_verifier_data_for_network(network)?;

    
    let end_cap_verifier_data = end_cap_alt_verifier_data.to_verifier_data::<C, D>();
    let end_cap_fingerprint = get_circuit_fingerprint_generic_q::<D, C::F, C>(&end_cap_verifier_data);



    let circuit_config = get_circuit_config_for_network(network);

    let default_user_state_tree_root = QHashOut::<C::F>::from_u64x4(circuit_config.default_user_state_tree_root_hash_u64_x4);

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
        circuit_config.global_user_tree_realm_height,
        circuit_config.global_user_tree_height,
        circuit_config.guta_circuit_whitelist_tree_height,
        circuit_config.checkpoint_tree_height,
        circuit_config.group_realm_height,
        circuit_config.max_users_to_register_per_proof,
        circuit_config.only_register_max_users_per_proof,
        end_cap_fingerprint,
        default_user_state_tree_root,
        get_default_worker_rewards_tree_tag::<QHashOut<C::F>>(),
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
        circuit_config.global_user_tree_height,
        circuit_config.batch_user_registration_sub_tree_height,
        circuit_config.batch_user_registration_max_sub_trees,
        circuit_config.global_contract_tree_height,
        circuit_config.batch_deploy_contract_sub_tree_height,
        circuit_config.guta_circuit_whitelist_tree_height,
        circuit_config.checkpoint_tree_height,
        circuit_config.max_contract_state_tree_height,
        
        get_default_worker_rewards_tree_tag::<QHashOut<C::F>>(),
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

    Ok((gcv, coordinator_circuits))
}

