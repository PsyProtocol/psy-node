
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;
use parth_core::{
    crypto::hash::{tag_tree::hash_tag_tree_node, traits::{FieldQHasher, HashTo4Felts, MerkleHasher, PCircuitWitness, ZeroableHash}},
    felt::FromPrimitiveValuesFelt, protocol::core_types::Q256BitHash,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{agg::DummyAggStateTransition, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary,
        jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase},
    },
};

#[derive(Debug, Clone)]
pub struct AggStateTransitionDummyCircuitV2<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for AggStateTransitionDummyCircuitV2<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        // use this for both DummyAppendUserRegistrationTreeAggregate and
        // DummyBatchDeployContractsAggregate
        ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}
fn compute_agg_state_trackable_final_public_inputs_leaf<C: JTMBCircuitConfig>(
    allowed_circuit_hashes_root: C::Hash,
    state_transition_hash: C::Hash,
    worker_reward_tag: C::Hash,
) -> C::Hash {
    let total_proofs_generated = C::F::from_u64_value(1);

    let zero_hash = C::Hash::get_zero_value();

    let rewards_tree_value_combo = C::Hasher::two_to_one(&zero_hash, &zero_hash);
    let rewards_tree_final_new_value = C::Hasher::two_to_one(&rewards_tree_value_combo, &worker_reward_tag);

    let allowed_and_state_transition_hash =
        C::Hasher::two_to_one(&allowed_circuit_hashes_root, &state_transition_hash).to_4_felts();
    let public_inputs_without_reward_tag = C::Hasher::q_hash_many(&[
        allowed_and_state_transition_hash[0],
        allowed_and_state_transition_hash[1],
        allowed_and_state_transition_hash[2],
        allowed_and_state_transition_hash[3],
        total_proofs_generated,
    ]);
    C::Hasher::two_to_one(&public_inputs_without_reward_tag, &rewards_tree_final_new_value)
}
impl<C: JTMBCircuitConfig> AggStateTransitionDummyCircuitV2<C> {
    pub fn new(private_key: &MemorySecp256K1SinglePrivateKeyWallet) -> Self {
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate as u32,
            [0u8; 32],
            &private_key.get_public_key(),
        );
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        allowed_circuit_hashes_root: C::Hash,
        unmodified_state_root: C::Hash,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {

        let state_transition_hash = C::Hasher::two_to_one(&unmodified_state_root, &unmodified_state_root);

        let public_inputs_hash = compute_agg_state_trackable_final_public_inputs_leaf::<C>(
            allowed_circuit_hashes_root,
            state_transition_hash,
            worker_reward_tag,
        );
        self.verifier_data
            .generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(public_inputs_hash, &self.private_key)
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for AggStateTransitionDummyCircuitV2<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let witness = DummyAggStateTransition::<C::Hash>::psy_ser_from_slice(&input.base.witness)?;
        let hash = witness.get_expected_public_inputs_hash::<C::Hasher>();
        println!("DummyAggStateTransition expected public inputs hash: {:?}", hex::encode(&hash.into_owned_32bytes()));

        let reward_hash = hash_tag_tree_node::<C::Hash, C::Hasher>(&C::Hash::get_zero_value(), &C::Hash::get_zero_value(), &worker_reward_tag);
        let computed_public_inputs_hash = <C::Hasher as MerkleHasher<C::Hash>>::two_to_one(&hash, &reward_hash);
        println!("Computed public inputs hash with worker reward tag: {:?}", hex::encode(&computed_public_inputs_hash.into_owned_32bytes()));

        let proof = self.prove_base(witness.allowed_circuit_hashes_root, witness.unmodified_state_tree_root, worker_reward_tag)?;
        let public_input_hash = C::Hash::from_4_felts_slice(&proof.public_inputs_hash.to_4_felts());
        println!("Proof public inputs hash: {:?}", hex::encode(&public_input_hash.to_vec_32bytes()));
        

        self.prove_base(
            witness.allowed_circuit_hashes_root,
            witness.unmodified_state_tree_root,
            worker_reward_tag,
        )
    }
}
