use parth_core::{crypto::hash::traits::{MerkleHasher, ZeroableHash}, felt::FromPrimitiveValuesFelt, protocol::core_types::QZKProofPublicInputsHasherReader};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::gadgets::coordinator::{agg_state::compute_agg_public_inputs, batch_append::verify_batch_append},
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct BatchAppendUserRegistrationTreeCircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
    
    pub user_registration_tree_height: usize,
    pub batch_sub_tree_height: usize,
    pub max_sub_trees: usize,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for BatchAppendUserRegistrationTreeCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::AppendUserRegistrationTree
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> BatchAppendUserRegistrationTreeCircuit<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        user_registration_tree_height: usize,
        batch_sub_tree_height: usize,
        max_sub_trees: usize,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::AppendUserRegistrationTree;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(circuit_type as u32, [0u8; 32], &private_key.get_public_key());
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
            user_registration_tree_height,
            batch_sub_tree_height,
            max_sub_trees,
        }
    }

    pub fn prove_base(
        &self,
        register_users_circuit_whitelist: C::Hash,
        worker_reward_tag: C::Hash,
        input: &QCAppendUserRegistrationTreeCircuitInput<C::Hash>,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let result = verify_batch_append::<C::Hash, C::F, C::Hasher>(
            &input.spiderman_append_proofs,
            self.user_registration_tree_height,
            self.batch_sub_tree_height,
            self.max_sub_trees,
        )?;

        let state_transition = psy_data::agg::AggStateTransition {
            state_transition_start: result.old_root,
            state_transition_end: result.new_root,
        };
        
        let one = C::F::from_u64_value(1);
        let zero = C::Hash::get_zero_value();
        let combo = C::Hasher::two_to_one(&zero, &zero);
        let leaf_rewards_val = C::Hasher::two_to_one(&combo, &worker_reward_tag);
        
        let final_pi_hash = compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(
            register_users_circuit_whitelist,
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

impl<L: QZKProofPublicInputsHasherReader<C::Hash, PsyTestJTMBProof<C::Hash>> + PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for BatchAppendUserRegistrationTreeCircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let witness = QCAppendUserRegistrationTreeCircuitInput::<C::Hash>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(
            witness.register_users_circuit_whitelist,
            worker_reward_tag,
            &witness,
        )
    }
}