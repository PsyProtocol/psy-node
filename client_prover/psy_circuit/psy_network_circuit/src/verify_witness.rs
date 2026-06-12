use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use psy_client_common::{
    data::qhashout::QHashOut,
    job::{
        id::{ProvingJobCircuitType, QProvingJobDataID},
        traits::QProofStoreAsyncImm,
    },
};
use psy_config::network_constants::{COORDINATOR_USER_TREE_HEIGHT, REALM_USER_TREE_HEIGHT};
use psy_crypto::{
    common::{circuit_library::CircuitInfoLibraryCore, generic_circuit_verifier::GenericCircuitVerifier},
    hash::{
        merkle::treeprover::{
            data::CircuitInputWithDependencies, subtree::SubTreeNodeStateTransition, AggStateTransitionInput, DummyAggStateTransition,
        },
        traits::{
            hasher::{FieldQHasher, MerkleZeroHasher, MerkleZeroHasherWithMarkedLeaf},
            qhashable::QFieldHashable,
        },
    },
};
use psy_client_data::{
    config::store_config::PsyHasher,
    guta::{
        header::GlobalUserTreeAggregatorHeader,
        proof_input::{
            GUTANoChangeFullInput, GUTAOnlyRegisterUsersInput, VerifyGUTARegisterUsersCircuitInputSimple, VerifyGUTAToCapCircuitInputSimple,
            VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple, VerifyLeftEndCapRightGUTAInputSimple, VerifyLeftGUTARightEndCapInputSimple,
            VerifySingleEndCapInput, VerifyTwoEndCapCircuitInput, VerifyTwoGUTAProofGadgetStandardInputSimple,
            VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple,
        },
        stats::GUTAStats,
    },
    protocol::circuit_inputs::{
        agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput, checkpoint_transition::QCPsyCheckpointStateTransitionInput,
        deploy_contracts::QCBatchDeployContractsCircuitInput,
    },
};

pub type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
pub const D: usize = 2;
pub type F = psy_client_data::config::store_config::PsyFelt;

pub async fn verify_witness_and_proof<PS: QProofStoreAsyncImm>(
    proof_verifier: &GenericCircuitVerifier<C, D>,
    job_id: QProvingJobDataID,
    proof_store: &PS,
    proof: &ProofWithPublicInputs<F, C, D>,
) -> anyhow::Result<()> {
    proof_verifier.verify_proof_of_type(job_id.circuit_type, &proof)?;
    match job_id.circuit_type {
        ProvingJobCircuitType::AppendUserRegistrationTree => {
            tracing::info!("verify append user registration: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 19 {
                anyhow::bail!("invalid public input length");
            }
            use psy_client_data::protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput;
            let input: QCAppendUserRegistrationTreeCircuitInput<F> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?)?;

            let register_users_circuit_whitelist = input.register_users_circuit_whitelist;
            if register_users_circuit_whitelist.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid register users circuit whitelist");
            }
            let old_root = input.spiderman_append_proofs[0].top_line_proof.old_root;
            let new_root = input.spiderman_append_proofs[input.spiderman_append_proofs.len() - 1]
                .top_line_proof
                .new_root;

            let state_transition_hash = PsyHasher::q_two_to_one(old_root, new_root);
            if proof.public_inputs[15..19] != state_transition_hash.0.elements {
                anyhow::bail!("invalid state transition hash");
            }
        }
        ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => {
            tracing::info!("verify append user registration aggregate: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 19 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<AggStateTransitionInput<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 2 {
                anyhow::bail!("invalid dependency count in two end guta input");
            }

            let leaf_fingerprint = proof_verifier
                .library
                .get_fingerprint(job_id.circuit_type.get_agg_leaf_circuit_type_or_err()?)?;
            let agg_fingerprint = proof_verifier
                .library
                .get_fingerprint(ProvingJobCircuitType::AppendUserRegistrationTreeAggregate)?;
            let allowed_circuit_hashes_root = PsyHasher::q_two_to_one(leaf_fingerprint, agg_fingerprint);

            if proof.public_inputs[11..15] != allowed_circuit_hashes_root.0.elements {
                anyhow::bail!("invalid allowed circuit hashes root");
            }

            let left_state_transition_start = r.input.left_input.state_transition_start;
            let right_state_transition_end = r.input.right_input.state_transition_end;
            let state_transition_hash = PsyHasher::q_two_to_one(left_state_transition_start, right_state_transition_end);
            if proof.public_inputs[15..19] != state_transition_hash.0.elements {
                anyhow::bail!("invalid state transition hash");
            }
        }
        ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate => {
            tracing::info!("verify dummy append user registration aggregate: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 19 {
                anyhow::bail!("invalid public input length");
            }

            let input: DummyAggStateTransition<F> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;

            let transition = PsyHasher::q_two_to_one(input.state_transition_hash, input.state_transition_hash);

            if input.allowed_circuit_hashes_root.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid allowed circuit hashes root");
            }
            if transition.0.elements != proof.public_inputs[15..19] {
                anyhow::bail!("invalid transition");
            }
        }

        ProvingJobCircuitType::BatchDeployContracts => {
            tracing::info!("verify batch deploy contracts: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 19 {
                anyhow::bail!("invalid public input length");
            }

            let input: QCBatchDeployContractsCircuitInput<F> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;

            let state_transition_hash = PsyHasher::q_two_to_one(
                input.spiderman_append_proof.top_line_proof.old_root,
                input.spiderman_append_proof.top_line_proof.new_root,
            );

            if proof.public_inputs[11..15] != input.deploy_contract_circuit_whitelist.0.elements {
                anyhow::bail!("invalid deploy contract circuit whitelist");
            }
            if proof.public_inputs[15..19] != state_transition_hash.0.elements {
                anyhow::bail!("invalid state transition hash");
            }
        }
        ProvingJobCircuitType::BatchDeployContractsAggregate => {
            tracing::info!("verify batch deploy contracts aggregate: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 19 {
                anyhow::bail!("invalid public input length");
            }

            let r: CircuitInputWithDependencies<AggStateTransitionInput<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 2 {
                anyhow::bail!("invalid dependency count in two end guta input");
            }

            let leaf_fingerprint = proof_verifier
                .library
                .get_fingerprint(job_id.circuit_type.get_agg_leaf_circuit_type_or_err()?)?;
            let agg_fingerprint = proof_verifier
                .library
                .get_fingerprint(ProvingJobCircuitType::BatchDeployContractsAggregate)?;
            let allowed_circuit_hashes_root = PsyHasher::q_two_to_one(leaf_fingerprint, agg_fingerprint);

            if proof.public_inputs[11..15] != allowed_circuit_hashes_root.0.elements {
                anyhow::bail!("invalid allowed circuit hashes root");
            }

            let left_state_transition_start = r.input.left_input.state_transition_start;
            let right_state_transition_end = r.input.right_input.state_transition_end;
            let state_transition_hash = PsyHasher::q_two_to_one(left_state_transition_start, right_state_transition_end);
            if proof.public_inputs[15..19] != state_transition_hash.0.elements {
                anyhow::bail!("invalid state transition hash");
            }
        }
        ProvingJobCircuitType::DummyBatchDeployContractsAggregate => {
            tracing::info!("verify dummy batch deploy contracts aggregate: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 19 {
                anyhow::bail!("invalid public input length");
            }

            let input: DummyAggStateTransition<F> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;

            let transition = PsyHasher::q_two_to_one(input.state_transition_hash, input.state_transition_hash);

            if proof.public_inputs[11..15] != input.allowed_circuit_hashes_root.0.elements {
                anyhow::bail!("invalid allowed circuit hashes root");
            }
            if transition.0.elements != proof.public_inputs[15..19] {
                anyhow::bail!("invalid transition");
            }
        }

        ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA => {
            tracing::info!("verify agg user registration deploy contracts: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 19 {
                anyhow::bail!("invalid public input length");
            }

            let r: CircuitInputWithDependencies<QCAggUserRegistartionDeployContractsGUTAInput<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;

            if r.dependencies.len() != 3 {
                anyhow::bail!("expected 3 dependencies");
            }

            let register_users_state_transition = r.input.register_users_state_transition;
            let deploy_contracts_state_transition = r.input.deploy_contracts_state_transition;
            let guta_proof_header = r.input.guta_proof_header;

            let user_regsitration_deploy_contract_start = PsyHasher::q_two_to_one(
                register_users_state_transition.state_transition_start,
                deploy_contracts_state_transition.state_transition_start,
            );
            let user_regsitration_deploy_contract_end = PsyHasher::q_two_to_one(
                register_users_state_transition.state_transition_end,
                deploy_contracts_state_transition.state_transition_end,
            );
            let user_regsitration_deploy_contract_combo =
                PsyHasher::q_two_to_one(user_regsitration_deploy_contract_start, user_regsitration_deploy_contract_end);

            let guta_hash = guta_proof_header.qfhash::<PsyHasher>();

            let state_transition_hash = PsyHasher::q_two_to_one(user_regsitration_deploy_contract_combo, guta_hash);

            let user_registration_proof: ProofWithPublicInputs<F, C, D> = proof_store.get_proof_by_id(r.dependencies[0]).await?;
            let deploy_contracts_proof: ProofWithPublicInputs<F, C, D> = proof_store.get_proof_by_id(r.dependencies[1]).await?;
            let guta_proof: ProofWithPublicInputs<F, C, D> = proof_store.get_proof_by_id(r.dependencies[2]).await?;

            if state_transition_hash.0.elements != proof.public_inputs[0..4] {
                anyhow::bail!("invalid state transition hash");
            }
            // Verify that hash(child_commitment, child_worker_public_key) equals parent's
            // expected value
            let user_registration_commitment = QHashOut::from_felt_slice(&user_registration_proof.public_inputs[0..4]);
            let user_registration_worker_pk = QHashOut::from_felt_slice(&user_registration_proof.public_inputs[4..8]);
            let user_registration_final = PsyHasher::q_two_to_one(user_registration_commitment, user_registration_worker_pk);
            if user_registration_final.0.elements != proof.public_inputs[4..8] {
                anyhow::bail!("invalid user registration proof");
            }

            let deploy_contracts_commitment = QHashOut::from_felt_slice(&deploy_contracts_proof.public_inputs[0..4]);
            let deploy_contracts_worker_pk = QHashOut::from_felt_slice(&deploy_contracts_proof.public_inputs[4..8]);
            let deploy_contracts_final = PsyHasher::q_two_to_one(deploy_contracts_commitment, deploy_contracts_worker_pk);
            if deploy_contracts_final.0.elements != proof.public_inputs[8..12] {
                anyhow::bail!("invalid deploy contracts proof");
            }

            let guta_commitment = QHashOut::from_felt_slice(&guta_proof.public_inputs[0..4]);
            let guta_worker_pk = QHashOut::from_felt_slice(&guta_proof.public_inputs[4..8]);
            let guta_final = PsyHasher::q_two_to_one(guta_commitment, guta_worker_pk);
            if guta_final.0.elements != proof.public_inputs[12..16] {
                anyhow::bail!("invalid guta proof");
            }
        }
        ProvingJobCircuitType::GenerateRollupStateTransitionProof => {
            tracing::info!("verify rollup state transition aggregate: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 19 {
                anyhow::bail!("invalid rollup state transition proof");
            }

            let r: CircuitInputWithDependencies<QCPsyCheckpointStateTransitionInput<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?)?;

            if r.dependencies.len() != 1 {
                anyhow::bail!("expected 1 dependencies");
            }

            let old_checkpoint_tree_root = r.input.previous_checkpoint_proof.root;
            let new_checkpoint_tree_root = r.input.append_checkpoint_tree_proof.new_root;

            if old_checkpoint_tree_root.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid old checkpoint tree root");
            }
            if new_checkpoint_tree_root.0.elements != proof.public_inputs[15..19] {
                anyhow::bail!("invalid new checkpoint tree root");
            }
        }

        ProvingJobCircuitType::GUTASingleEndCap => {
            tracing::info!("verify single_end_cap: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifySingleEndCapInput<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 1 {
                anyhow::bail!("invalid dependency count in two end guta input");
            }

            use psy_crypto::hash::traits::qhashable::QFieldHashable;
            let guta_header = r.input.get_new_guta_header();

            let guta_header_hash = guta_header.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_hash);
            if guta_header_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        ProvingJobCircuitType::GUTATwoEndCap => {
            tracing::info!("verify two_end_cap: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifyTwoEndCapCircuitInput<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 2 {
                anyhow::bail!("invalid dependency count in two end cap input");
            }

            let guta_header_combine = r.input.get_new_guta_header::<PsyHasher>();
            let guta_header_combine_hash = guta_header_combine.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_combine_hash);
            if guta_header_combine_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }

        ProvingJobCircuitType::GUTATwoGUTA => {
            tracing::info!("verify two_guta: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifyTwoGUTAProofGadgetStandardInputSimple<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 2 {
                anyhow::bail!("invalid dependency count in two guta input");
            }

            let guta_whitelist_root = proof_verifier
                .library
                .get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?
                .root;

            let nearest_common_ancestor_level = r.input.nca_proof.nearest_common_ancestor_level;
            let nearest_common_ancestor_index = r.input.nca_proof.get_nca_index();
            let old_nca_value = r.input.nca_proof.compute_old_nca_value::<PsyHasher>();
            let new_nca_value = r.input.nca_proof.compute_new_nca_value::<PsyHasher>();

            let combine_stats = r.input.stats_a.combine_with(&r.input.stats_b);
            let guta_header_combine = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: guta_whitelist_root,
                checkpoint_tree_root: r.input.checkpoint_tree_root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: old_nca_value,
                    new_node_value: new_nca_value,
                    node_index: F::from_canonical_u64(nearest_common_ancestor_index),
                    node_level: F::from_canonical_u8(nearest_common_ancestor_level),
                },
                stats: combine_stats,
            };

            let guta_header_combine_hash = guta_header_combine.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_combine_hash);
            if guta_header_combine_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        // GUTA_CHECKPOINT_UPGRADE-TODO: Add the new circuits here
        ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade => {
            tracing::info!("verify two_guta_with_checkpoint_update: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 1 {
                anyhow::bail!("invalid dependency count in guta to cap input");
            }

            let guta_header_combine = r.input.get_new_guta_header::<PsyHasher>();

            let guta_header_combine_hash = guta_header_combine.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_combine_hash);
            if guta_header_combine_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade => {
            tracing::info!("verify two_guta_with_checkpoint_update: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 2 {
                anyhow::bail!("invalid dependency count in two guta input");
            }

            let guta_whitelist_root = proof_verifier
                .library
                .get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?
                .root;

            let nearest_common_ancestor_level = r.input.nca_proof.nearest_common_ancestor_level;
            let nearest_common_ancestor_index = r.input.nca_proof.get_nca_index();
            let old_nca_value = r.input.nca_proof.compute_old_nca_value::<PsyHasher>();
            let new_nca_value = r.input.nca_proof.compute_new_nca_value::<PsyHasher>();

            anyhow::ensure!(
                r.input.historical_checkpoint_proof_a.root == r.input.historical_checkpoint_proof_b.root,
                "historical checkpoint proof root is zero"
            );

            let combine_stats = r.input.stats_a.combine_with(&r.input.stats_b);
            let guta_header_combine = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: guta_whitelist_root,
                checkpoint_tree_root: r.input.historical_checkpoint_proof_a.root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: old_nca_value,
                    new_node_value: new_nca_value,
                    node_index: F::from_canonical_u64(nearest_common_ancestor_index),
                    node_level: F::from_canonical_u8(nearest_common_ancestor_level),
                },
                stats: combine_stats,
            };

            let guta_header_combine_hash = guta_header_combine.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_combine_hash);
            if guta_header_combine_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        ProvingJobCircuitType::GUTALeftGUTARightEndCap => {
            tracing::info!("verify left guta right end cap: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifyLeftGUTARightEndCapInputSimple<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 2 {
                anyhow::bail!("invalid dependency count in two end guta input");
            }

            let guta_whitelist_root = proof_verifier
                .library
                .get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?
                .root;

            let nearest_common_ancestor_level = r.input.nca_proof.nearest_common_ancestor_level;
            let nearest_common_ancestor_index = r.input.nca_proof.get_nca_index();
            let old_nca_value = r.input.nca_proof.compute_old_nca_value::<PsyHasher>();
            let new_nca_value = r.input.nca_proof.compute_new_nca_value::<PsyHasher>();

            anyhow::ensure!(
                r.input.b_end_cap.checkpoint_historical_merkle_proof.root == r.input.checkpoint_tree_root,
                "right endcap historical merkle proof root not equal to left guta checkpoint tree root"
            );

            let combine_stats = r.input.stats_a.combine_with(&r.input.b_end_cap.guta_stats);
            let guta_header_combine = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: guta_whitelist_root,
                checkpoint_tree_root: r.input.b_end_cap.checkpoint_historical_merkle_proof.root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: old_nca_value,
                    new_node_value: new_nca_value,
                    node_index: F::from_canonical_u64(nearest_common_ancestor_index),
                    node_level: F::from_canonical_u8(nearest_common_ancestor_level),
                },
                stats: combine_stats,
            };

            let guta_header_combine_hash = guta_header_combine.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_combine_hash);
            if guta_header_combine_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        ProvingJobCircuitType::GUTALeftEndCapRightGUTA => {
            tracing::info!("verify left end cap right guta: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifyLeftEndCapRightGUTAInputSimple<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 2 {
                anyhow::bail!("invalid dependency count in two end guta input");
            }

            let guta_whitelist_root = proof_verifier
                .library
                .get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?
                .root;

            let nearest_common_ancestor_level = r.input.nca_proof.nearest_common_ancestor_level;
            let nearest_common_ancestor_index = r.input.nca_proof.get_nca_index();
            let old_nca_value = r.input.nca_proof.compute_old_nca_value::<PsyHasher>();
            let new_nca_value = r.input.nca_proof.compute_new_nca_value::<PsyHasher>();

            let combine_stats = r.input.a_end_cap.guta_stats.combine_with(&r.input.stats_b);

            anyhow::ensure!(
                r.input.a_end_cap.checkpoint_historical_merkle_proof.root == r.input.checkpoint_tree_root,
                "left endcap historical merkle proof root not equal to right guta checkpoint tree root"
            );
            let guta_header_combine = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: guta_whitelist_root,
                checkpoint_tree_root: r.input.a_end_cap.checkpoint_historical_merkle_proof.root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: old_nca_value,
                    new_node_value: new_nca_value,
                    node_index: F::from_canonical_u64(nearest_common_ancestor_index),
                    node_level: F::from_canonical_u8(nearest_common_ancestor_level),
                },
                stats: combine_stats,
            };

            let guta_header_combine_hash = guta_header_combine.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_combine_hash);
            if guta_header_combine_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        ProvingJobCircuitType::GUTARegisterUsers => {
            tracing::info!("verify guta register users: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifyGUTARegisterUsersCircuitInputSimple<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 1 {
                anyhow::bail!("invalid dependency count in two end guta input");
            }

            let verify_to_cap_input = VerifyGUTAToCapCircuitInputSimple {
                guta_proof_header: r.input.guta_proof_header.clone(),
                top_line_siblings: r.input.top_line_siblings.clone(),
            };
            let new_g = verify_to_cap_input.get_new_guta_header::<PsyHasher>();

            let guta_header = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: new_g.guta_circuit_whitelist,
                checkpoint_tree_root: new_g.checkpoint_tree_root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: new_g.state_transition.old_node_value,
                    new_node_value: r
                        .input
                        .guta_register_user_inputs
                        .last()
                        .as_ref()
                        .unwrap()
                        .global_user_tree_update_proof
                        .new_root,
                    node_index: new_g.state_transition.node_index,
                    node_level: new_g.state_transition.node_level,
                },
                stats: new_g.stats,
            };
            println!("new_guta_header: {:?}", guta_header);
            let guta_header_hash = guta_header.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_hash);
            if guta_header_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        ProvingJobCircuitType::GUTAOnlyRegisterUsers => {
            tracing::info!("verify only register users: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: GUTAOnlyRegisterUsersInput<F> = bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?)?;

            let guta_whitelist_root: QHashOut<F> = proof_verifier
                .library
                .get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?
                .root;

            let user_id = r.guta_register_user_inputs[0].global_user_tree_update_proof.index;
            let realm_id = user_id >> REALM_USER_TREE_HEIGHT;

            let guta_header = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: guta_whitelist_root,
                checkpoint_tree_root: r.checkpoint_tree_root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: r.guta_register_user_inputs[0].global_user_tree_update_proof.old_root,
                    new_node_value: r.guta_register_user_inputs[r.guta_register_user_inputs.len() - 1]
                        .global_user_tree_update_proof
                        .new_root,
                    node_index: F::from_canonical_u64(realm_id),
                    node_level: F::from_canonical_u8(COORDINATOR_USER_TREE_HEIGHT),
                },
                stats: GUTAStats::default(),
            };
            println!("new_guta_header: {:?}", guta_header);
            let guta_header_hash = guta_header.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_hash);
            if guta_header_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        ProvingJobCircuitType::GUTAVerifyToCap => {
            tracing::info!("verify guta to cap: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: CircuitInputWithDependencies<VerifyGUTAToCapCircuitInputSimple<F>> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
            if r.dependencies.len() != 1 {
                anyhow::bail!("invalid dependency count in two end guta input");
            }

            let guta_header = r.input.get_new_guta_header::<PsyHasher>();
            let guta_header_hash = guta_header.qfhash::<PsyHasher>();

            tracing::info!("guta_header_hash: {:?}", guta_header_hash);
            if guta_header_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        ProvingJobCircuitType::GUTANoChange => {
            tracing::info!("verify guta no change: {:?}", proof.public_inputs);
            if proof.public_inputs.len() != 15 {
                anyhow::bail!("invalid public input length");
            }
            let r: GUTANoChangeFullInput<F> =
                bincode::deserialize(&proof_store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;

            let guta_whitelist_root: QHashOut<F> = proof_verifier
                .library
                .get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?
                .root;

            let new_guta_header = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: guta_whitelist_root,
                checkpoint_tree_root: r.checkpoint_tree_proof.root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: r.checkpoint_leaf.global_state_roots.user_tree_root,
                    new_node_value: r.checkpoint_leaf.global_state_roots.user_tree_root,
                    node_index: F::ZERO,
                    node_level: F::ZERO,
                },
                stats: GUTAStats::default(),
            };

            let public_inputs_hash = new_guta_header.qfhash::<PsyHasher>();
            tracing::info!("guta_no_change public_inputs_hash: {:?}", public_inputs_hash);
            if public_inputs_hash.0.elements != proof.public_inputs[11..15] {
                anyhow::bail!("invalid guta header hash");
            }
        }
        _ => {
            tracing::warn!("unsupported circuit: {:?}", job_id.circuit_type);
        }
    }
    Ok(())
}
