use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;
use parth_core::
    crypto::hash::traits::MerkleHasher
;
use psy_core::{
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
    worker::traits::QNextGenWorkerGenericInfo,
};
use psy_data::{
    agg::TPAltCircuitFingerprintConfig,
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_worker_core::worker::prover_trait::{PsyWorkerGenericLibraryProver, PsyWorkerGenericLibraryProverInfoProvider};

use crate::{
    proving::{
        circuits::coordinator::{
            agg_state_transition::AggStateTransitionCircuitV2,
            agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTACircuit,
            batch_append_user_registration_tree::BatchAppendUserRegistrationTreeCircuit,
            batch_deploy_contract::BatchDeployContractsCircuit,
            checkpoint_state_transition::QEDCheckpointStateTransitionCircuit,
            checkpoint_state_transition_genesis::QEDCheckpointStateTransitionGenesisCircuit,
        },
        guta_helper::QEDGUTACircuitManager,
    },
    utils::{
        circuit_info_library::{PsyJTMBCircuitInfoLibrary, PsyJTMBCircuitInfoLibraryBuilder},
        jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase},
        proof_serialization::serialize_jtmb_proof,
    },
};

pub struct QEDCoordinatorCircuitManager<C: JTMBCircuitConfig> {
    pub append_user_registration_tree: BatchAppendUserRegistrationTreeCircuit<C>,
    pub batch_deploy_contracts: BatchDeployContractsCircuit<C>,
    pub agg_state_transition: AggStateTransitionCircuitV2<C>,
    pub dummy_agg_state_transition: AggStateTransitionCircuitV2<C>,
    pub agg_user_register_deploy_contracts_guta: VerifyAggUserRegistartionDeployContractsGUTACircuit<C>,
    pub checkpoint_root_transition: QEDCheckpointStateTransitionCircuit<C>,
    pub genesis_checkpoint_root_transition: QEDCheckpointStateTransitionGenesisCircuit<C>,
    pub guta_circuits: QEDGUTACircuitManager<C>,
    pub append_register_users_circuit_whitelist: C::Hash,
    pub batch_deploy_contracts_circuit_whitelist: C::Hash,
}

impl<C: JTMBCircuitConfig> QEDCoordinatorCircuitManager<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        _group_realm_height: usize,
        _max_users_to_register_per_proof: usize,
        _only_register_max_users_per_proof: usize,
        
        batch_user_registration_sub_tree_height: usize,
        batch_user_registration_max_sub_trees: usize,
        global_contract_tree_height: usize,
        batch_deploy_contract_sub_tree_height: usize,
        max_contract_state_tree_height: usize,
    ) -> Self {
        let max_guta_nca_merkle_proof_height = global_user_tree_height - global_user_tree_realm_height;

        let guta_circuits = QEDGUTACircuitManager::new(
            private_key,
            global_user_tree_height,
            global_user_tree_realm_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
            max_guta_nca_merkle_proof_height,
        );

        let append_user_registration_tree = BatchAppendUserRegistrationTreeCircuit::new(
            private_key,
            global_user_tree_height,
            batch_user_registration_sub_tree_height,
            batch_user_registration_max_sub_trees,
        );

        let batch_deploy_contracts = BatchDeployContractsCircuit::new(
            private_key,
            global_contract_tree_height,
            batch_deploy_contract_sub_tree_height,
            max_contract_state_tree_height,
        );

        let agg_state_transition = AggStateTransitionCircuitV2::new(
            private_key,
            false,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
        );

        let dummy_agg_state_transition = AggStateTransitionCircuitV2::new(
            private_key,
            true,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
        );

        let user_reg_conf = TPAltCircuitFingerprintConfig {
            leaf_fingerprint: append_user_registration_tree.get_fingerprint(),
            aggregator_fingerprint: agg_state_transition.get_fingerprint(),
            dummy_fingerprint: dummy_agg_state_transition.get_fingerprint(),
            verifier_data_cap_height: 3,
        };

        let deploy_conf = TPAltCircuitFingerprintConfig {
            leaf_fingerprint: batch_deploy_contracts.get_fingerprint(),
            aggregator_fingerprint: agg_state_transition.get_fingerprint(),
            dummy_fingerprint: dummy_agg_state_transition.get_fingerprint(),
            verifier_data_cap_height: 3,
        };

        let agg_user_register_deploy_contracts_guta = VerifyAggUserRegistartionDeployContractsGUTACircuit::new(
            private_key,
            user_reg_conf,
            deploy_conf,
            guta_circuits.guta_circuit_whitelist_root,
            guta_circuit_whitelist_tree_height,
        );

        let genesis_checkpoint_root_transition = QEDCheckpointStateTransitionGenesisCircuit::new(private_key);

        let checkpoint_root_transition = QEDCheckpointStateTransitionCircuit::new(
            private_key,
            checkpoint_tree_height,
            agg_user_register_deploy_contracts_guta.get_fingerprint(),
            genesis_checkpoint_root_transition.get_fingerprint(),
        );
        
        let append_register_users_circuit_whitelist = C::Hasher::two_to_one(
            &append_user_registration_tree.get_fingerprint(),
            &agg_state_transition.get_fingerprint()
        );
        
        let batch_deploy_contracts_circuit_whitelist = C::Hasher::two_to_one(
            &batch_deploy_contracts.get_fingerprint(),
            &agg_state_transition.get_fingerprint()
        );

        Self {
            append_user_registration_tree,
            batch_deploy_contracts,
            agg_state_transition,
            dummy_agg_state_transition,
            agg_user_register_deploy_contracts_guta,
            checkpoint_root_transition,
            genesis_checkpoint_root_transition,
            guta_circuits,
            append_register_users_circuit_whitelist,
            batch_deploy_contracts_circuit_whitelist,
        }
    }

    pub fn register_library<L: PsyJTMBCircuitInfoLibraryBuilder<C::Hash>>(&self, library: &mut L) {
        let circuits: Vec<&dyn QJTMBProofCircuitBase<C::Hash>> = vec![
            &self.append_user_registration_tree,
            &self.batch_deploy_contracts,
            &self.agg_state_transition,
            &self.dummy_agg_state_transition,
            &self.agg_user_register_deploy_contracts_guta,
            &self.checkpoint_root_transition,
            &self.genesis_checkpoint_root_transition,
        ];

        for c in circuits {
            library.register_circuit(c.get_circuit_type(), c.get_fingerprint(), c.get_verifier_data().clone());
        }

        library.register_circuit(ProvingJobCircuitType::BatchDeployContractsAggregate, self.agg_state_transition.get_fingerprint(), self.agg_state_transition.get_verifier_data().clone());
        library.register_circuit(ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate, self.dummy_agg_state_transition.get_fingerprint(), self.dummy_agg_state_transition.get_verifier_data().clone());

        self.guta_circuits.register_library(library);
    }
}

impl<C: JTMBCircuitConfig> QNextGenWorkerGenericInfo<QProvingJobDataID> for QEDCoordinatorCircuitManager<C> {
    fn can_process_job(&self, job_id: QProvingJobDataID) -> bool {
        match job_id.circuit_type {
            ProvingJobCircuitType::AppendUserRegistrationTree
            | ProvingJobCircuitType::BatchDeployContracts
            | ProvingJobCircuitType::AppendUserRegistrationTreeAggregate
            | ProvingJobCircuitType::BatchDeployContractsAggregate
            | ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate
            | ProvingJobCircuitType::DummyBatchDeployContractsAggregate
            | ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA
            | ProvingJobCircuitType::GenerateRollupStateTransitionProof
            | ProvingJobCircuitType::GenesisBlockCheckpointStateTransition => true,
            _ => self.guta_circuits.can_process_job(job_id),
        }
    }
}

impl<C: JTMBCircuitConfig> PsyWorkerGenericLibraryProverInfoProvider<QProvingJobDataID> for QEDCoordinatorCircuitManager<C> {
    fn prover_can_process_job(&self, job_id: QProvingJobDataID) -> bool {
        self.can_process_job(job_id)
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> PsyWorkerGenericLibraryProver<C::Hash, QProvingJobDataID,L> for QEDCoordinatorCircuitManager<C> {
    fn prove_job_from_api(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<Vec<u8>> {
        let proof = match input.base.job.job_id.circuit_type {
            ProvingJobCircuitType::AppendUserRegistrationTree => {
                self.append_user_registration_tree.jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            },
            ProvingJobCircuitType::BatchDeployContracts => self.batch_deploy_contracts.jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate | ProvingJobCircuitType::BatchDeployContractsAggregate => {
                self.agg_state_transition.jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            },
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate | ProvingJobCircuitType::DummyBatchDeployContractsAggregate => {
                self.dummy_agg_state_transition.jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            },
            ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA => self.agg_user_register_deploy_contracts_guta.jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => self.checkpoint_root_transition.jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            ProvingJobCircuitType::GenesisBlockCheckpointStateTransition => self.genesis_checkpoint_root_transition.jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            _ => return self.guta_circuits.prove_job_from_api(library, input, worker_reward_tag),
        };
        serialize_jtmb_proof(&proof)
    }
}