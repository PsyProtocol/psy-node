use async_trait::async_trait;
use parth_core::{crypto::hash::traits::{MerkleHasher, MerkleZeroHasher}, pgoldilocks::{QHashOut, QRichField}};
use plonky2::{hash::hash_types::HashOut, plonk::{config::{AlgebraicHasher, GenericConfig}, proof::ProofWithPublicInputs}};
use psy_core::{job::job_id::{ProvingJobCircuitType, QProvingJobDataID}, worker::traits::QNextGenWorkerGenericInfo};
use psy_data::agg::TPAltCircuitFingerprintConfig;
use psy_plonky2_basic_helpers::verifier::circuit_library::{CircuitInfoLibrary, CircuitInfoLibraryBuilder};

use crate::{agg::circuits::{core::AggStateTransitionCircuit, dummy::AggStateTransitionDummyCircuit}, guta::guta_helper::QEDGUTACircuitManager, qstandard::{proof_store::QProofStoreReaderAsync, prover::QNextGenWorkerGenericProverAsyncMut, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync}};

use super::circuits::{agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTACircuit, batch_append_user_registration_tree::BatchAppendUserRegistrationTreeCircuit, batch_deploy_contract::BatchDeployContractsCircuit, checkpoint_state_transition::QEDCheckpointStateTransitionCircuit};


#[derive(Debug)]
pub struct QEDCoordinatorCircuitManager<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher:
        AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
{
    pub append_user_registration_tree: BatchAppendUserRegistrationTreeCircuit<C, D>,
    pub append_register_users_circuit_whitelist: QHashOut<C::F>,
    pub batch_deploy_contracts: BatchDeployContractsCircuit<C, D>,
    pub batch_deploy_contracts_circuit_whitelist: QHashOut<C::F>,

    pub agg_state_transition: AggStateTransitionCircuit<C, D>,
    pub dummy_agg_state_transition: AggStateTransitionDummyCircuit<C, D>,
    pub agg_user_register_deploy_contracts_guta: VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D>,
    pub guta_circuits: QEDGUTACircuitManager<C,D>,
    pub checkpoint_root_transition: QEDCheckpointStateTransitionCircuit<C,D>,
    pub public_key: QHashOut<C::F>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> QEDCoordinatorCircuitManager<C, D>
where
    C::Hasher:
        AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>, C::F: QRichField,
{
    pub fn new_with_library<T: CircuitInfoLibrary<C,D>>(library: &T,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        group_realm_height: usize,
        max_users_to_register_per_proof: usize,
                only_register_max_users_per_proof: usize,
        default_user_state_tree_root: QHashOut<C::F>,
        
        batch_user_registration_sub_tree_height: usize,
        batch_user_registration_max_sub_trees: usize,
        global_contract_tree_height: usize,
        batch_deploy_contract_sub_tree_height: usize,
        max_contract_state_tree_height: usize,
        public_key: QHashOut<C::F>
    ) -> Self {
        let guta_circuits = QEDGUTACircuitManager::<C,D>::new_with_library(library,
            global_user_tree_realm_height,
            global_user_tree_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
            group_realm_height,
            max_users_to_register_per_proof,
            only_register_max_users_per_proof,
            default_user_state_tree_root,
            public_key
        );
        Self::new_with_guta(guta_circuits,
        global_user_tree_height,
        batch_user_registration_sub_tree_height,
        batch_user_registration_max_sub_trees,
        global_contract_tree_height,
        batch_deploy_contract_sub_tree_height,
        guta_circuit_whitelist_tree_height,
        checkpoint_tree_height,
        max_contract_state_tree_height,
        public_key
    )
}
pub fn new_with_guta(
    guta_circuits: QEDGUTACircuitManager<C,D>,
        global_user_tree_height: usize,
        batch_user_registration_sub_tree_height: usize,
        batch_user_registration_max_sub_trees: usize,
        global_contract_tree_height: usize,
        batch_deploy_contract_sub_tree_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        max_contract_state_tree_height: usize,
        
        public_key: QHashOut<C::F>,
    ) -> Self {
        let append_user_registration_tree = BatchAppendUserRegistrationTreeCircuit::new(
            global_user_tree_height,
            batch_user_registration_sub_tree_height,
            batch_user_registration_max_sub_trees,
        );
        let batch_deploy_contracts = BatchDeployContractsCircuit::new(
            global_contract_tree_height,
            batch_deploy_contract_sub_tree_height,
            max_contract_state_tree_height
        );


        let agg_state_transition = AggStateTransitionCircuit::new(
            &append_user_registration_tree.get_common_circuit_data_ref(),
            append_user_registration_tree.get_verifier_config_ref().constants_sigmas_cap.height(),
        );

        let dummy_agg_state_transition = AggStateTransitionDummyCircuit::new();


        let append_register_users_circuit_whitelist = C::Hasher::two_to_one(
            &append_user_registration_tree.get_fingerprint(),
            &agg_state_transition.get_fingerprint(),
        );

        let batch_deploy_contracts_circuit_whitelist = C::Hasher::two_to_one(
            &batch_deploy_contracts.get_fingerprint(),
            &agg_state_transition.get_fingerprint(),
        );

        let user_reg_transition_circuit_config = TPAltCircuitFingerprintConfig{
            leaf_fingerprint: append_user_registration_tree.get_fingerprint(),
            aggregator_fingerprint: agg_state_transition.get_fingerprint(),
            dummy_fingerprint: dummy_agg_state_transition.get_fingerprint(),
            verifier_data_cap_height: append_user_registration_tree.get_verifier_config_ref().constants_sigmas_cap.height(),
        };
        let deploy_contracts_transition_circuit_config = TPAltCircuitFingerprintConfig{
            leaf_fingerprint: batch_deploy_contracts.get_fingerprint(),
            aggregator_fingerprint: agg_state_transition.get_fingerprint(),
            dummy_fingerprint: dummy_agg_state_transition.get_fingerprint(),
            verifier_data_cap_height: batch_deploy_contracts.get_verifier_config_ref().constants_sigmas_cap.height(),
        };
        let agg_user_register_deploy_contracts_guta = VerifyAggUserRegistartionDeployContractsGUTACircuit::<C, D>::new(
            append_user_registration_tree.get_common_circuit_data_ref(),
            &user_reg_transition_circuit_config,
            batch_deploy_contracts.get_common_circuit_data_ref(),
            &deploy_contracts_transition_circuit_config,
            guta_circuits.verify_two_guta.get_common_circuit_data_ref(),
            guta_circuits.verify_two_guta.get_verifier_config_ref().constants_sigmas_cap.height(),
            guta_circuit_whitelist_tree_height,
            guta_circuits.guta_circuit_whitelist_root,
        );

        let checkpoint_root_transition = QEDCheckpointStateTransitionCircuit::<C,D>::new(
            agg_user_register_deploy_contracts_guta.get_common_circuit_data_ref(),
            agg_user_register_deploy_contracts_guta.get_verifier_config_ref().constants_sigmas_cap.height(),
            agg_user_register_deploy_contracts_guta.get_fingerprint(),
            checkpoint_tree_height,
        );

        Self {
            append_user_registration_tree,
            batch_deploy_contracts,
            agg_state_transition,
            dummy_agg_state_transition,
            guta_circuits,
            checkpoint_root_transition,
            agg_user_register_deploy_contracts_guta,
            append_register_users_circuit_whitelist,
            batch_deploy_contracts_circuit_whitelist,
            public_key,
        }
    }

    pub fn print_common_config(&self) {
        println!(
            "\n\n\n\n================================\n[append_user_registration_tree.common]:\n{:?}",
            self.append_user_registration_tree.get_common_circuit_data_ref()
        );
        println!(
            "\n\n\n\n================================\n[batch_deploy_contracts.common]:\n{:?}",
            self.batch_deploy_contracts.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[agg_state_transition.common]:\n{:?}",
            self.agg_state_transition.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[dummy_agg_state_transition.common]:\n{:?}",
            self.dummy_agg_state_transition.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[agg_user_register_deploy_contracts_guta.common]:\n{:?}",
            self.agg_user_register_deploy_contracts_guta.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[checkpoint_root_transition.common]:\n{:?}",
            self.checkpoint_root_transition.get_common_circuit_data_ref()
        );
        println!("===============================\n\n\n\n");
        self.guta_circuits.print_common_config();
    }
    pub fn register_library<T: CircuitInfoLibraryBuilder<C::F>>(&self, library: &mut T) {

        library.register_circuit(
            ProvingJobCircuitType::AppendUserRegistrationTree.into(),
            self.append_user_registration_tree.get_fingerprint(),
            self.append_user_registration_tree.get_verifier_config_ref().into()
        );
        library.register_circuit(
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate.into(),
            self.agg_state_transition.get_fingerprint(),
            self.agg_state_transition.get_verifier_config_ref().into()
        );
        library.register_circuit(
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate.into(),
            self.dummy_agg_state_transition.get_fingerprint(),
            self.dummy_agg_state_transition.get_verifier_config_ref().into()
        );

        library.register_circuit(
            ProvingJobCircuitType::BatchDeployContracts.into(),
            self.batch_deploy_contracts.get_fingerprint(),
            self.batch_deploy_contracts.get_verifier_config_ref().into()
        );
        library.register_circuit(
            ProvingJobCircuitType::BatchDeployContractsAggregate.into(),
            self.agg_state_transition.get_fingerprint(),
            self.agg_state_transition.get_verifier_config_ref().into()
        );
        library.register_circuit(
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate.into(),
            self.dummy_agg_state_transition.get_fingerprint(),
            self.dummy_agg_state_transition.get_verifier_config_ref().into()
        );


        library.register_circuit(
            ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA,
            self.agg_user_register_deploy_contracts_guta.get_fingerprint(),
            self.agg_user_register_deploy_contracts_guta.get_verifier_config_ref().into()
        );
        library.register_circuit(
            ProvingJobCircuitType::GenerateRollupStateTransitionProof,
            self.checkpoint_root_transition.get_fingerprint(),
            self.checkpoint_root_transition.get_verifier_config_ref().into()
        );


        self.guta_circuits.register_library(library);
    }
}


impl<
        C: GenericConfig<D> + 'static,
        const D: usize,
> QNextGenWorkerGenericInfo<QProvingJobDataID> for QEDCoordinatorCircuitManager<C, D>
where
    C::Hasher:
        AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,{

    fn can_process_job(&self, job_id: QProvingJobDataID) -> bool {
        match job_id.circuit_type {
            ProvingJobCircuitType::AppendUserRegistrationTree => true,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => true,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate => true,
            ProvingJobCircuitType::BatchDeployContracts => true,
            ProvingJobCircuitType::BatchDeployContractsAggregate => true,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate => true,
            ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA => true,
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => true,
            _ => self.guta_circuits.can_process_job(job_id),
        }
    }
}
#[async_trait]
impl<
        S: QProofStoreReaderAsync + Send + Sync,
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QNextGenWorkerGenericProverAsyncMut<S, L, C, D> for QEDCoordinatorCircuitManager<C, D>
where
    C::Hasher:
        AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>, C::F: QRichField,
{
    async fn worker_prove_mut_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        match job_id.circuit_type {
            ProvingJobCircuitType::AppendUserRegistrationTree => self.append_user_registration_tree.prove_with_proof_store_async(store, library, job_id, self.public_key).await,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => self.agg_state_transition.prove_with_proof_store_async(store, library, job_id, self.public_key).await,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate => self.dummy_agg_state_transition.prove_with_proof_store_async(store, library, job_id, self.public_key).await,


            ProvingJobCircuitType::BatchDeployContracts => self.batch_deploy_contracts.prove_with_proof_store_async(store, library, job_id, self.public_key).await,
            ProvingJobCircuitType::BatchDeployContractsAggregate => self.agg_state_transition.prove_with_proof_store_async(store, library, job_id, self.public_key).await,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate => self.dummy_agg_state_transition.prove_with_proof_store_async(store, library, job_id, self.public_key).await,


            ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA => self.agg_user_register_deploy_contracts_guta.prove_with_proof_store_async(store, library, job_id, self.public_key).await,
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => self.checkpoint_root_transition.prove_with_proof_store_async(store, library, job_id, self.public_key).await,

            _ => self.guta_circuits.worker_prove_mut_async(store, library, job_id).await,
        }
    }
}
