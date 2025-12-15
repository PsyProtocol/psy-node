use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{protocol::circuit_inputs::deploy_contracts::QCBatchDeployContractsCircuitInput, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use parth_core::{crypto::hash::traits::{MerkleHasher, ZeroableHash}, felt::FromPrimitiveValuesFelt};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::gadgets::coordinator::{agg_state::compute_agg_public_inputs, batch_deploy::verify_batch_deploy},
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct BatchDeployContractsCircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
    
    pub contract_tree_height: usize,
    pub batch_sub_tree_height: usize,
    pub max_contract_state_tree_height: usize,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for BatchDeployContractsCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::BatchDeployContracts
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> BatchDeployContractsCircuit<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        contract_tree_height: usize,
        batch_sub_tree_height: usize,
        max_contract_state_tree_height: usize,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::BatchDeployContracts;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(circuit_type as u32, [0u8; 32], &private_key.get_public_key());
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
            contract_tree_height,
            batch_sub_tree_height,
            max_contract_state_tree_height,
        }
    }

    pub fn prove_base(
        &self,
        deploy_contract_circuit_whitelist: C::Hash,
        worker_reward_tag: C::Hash,
        input: &QCBatchDeployContractsCircuitInput<C::F, C::Hash>,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        verify_batch_deploy::<C::Hash, C::F, C::Hasher>(
            &input.spiderman_append_proof,
            &input.contract_leaves,
            self.contract_tree_height,
            self.batch_sub_tree_height,
        )?;

        let state_transition = psy_data::agg::AggStateTransition {
            state_transition_start: input.spiderman_append_proof.top_line_proof.old_root,
            state_transition_end: input.spiderman_append_proof.top_line_proof.new_root,
        };
        
        let one = C::F::from_u64_value(1);
        let zero = C::Hash::get_zero_value();
        let combo = C::Hasher::two_to_one(&zero, &zero);
        let leaf_rewards_val = C::Hasher::two_to_one(&combo, &worker_reward_tag);
        
        let final_pi_hash = compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(
            deploy_contract_circuit_whitelist,
            &state_transition,
            one,
            leaf_rewards_val,
        );

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            final_pi_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for BatchDeployContractsCircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let witness = QCBatchDeployContractsCircuitInput::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(
            witness.deploy_contract_circuit_whitelist,
            worker_reward_tag,
            &witness,
        )
    }
}