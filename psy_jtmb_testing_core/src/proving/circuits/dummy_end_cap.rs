use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;
use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::FromPrimitiveValuesFelt};

use psy_core::job::job_id::ProvingJobCircuitType;
use psy_data::{guta::stats::GUTAStats, proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput, v1::qdata::{user::PQEDUserLeaf, user_end_cap_result::PUPSEndCapResultCompact}};
use psy_dummy_prover::traits::DummyUPSProver;

use crate::{proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData}, utils::{jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuitBase}, proof_serialization::serialize_jtmb_proof}};

#[derive(Debug, Clone)]
pub struct DummyUPSStandardEndCapCircuit<C: JTMBCircuitConfig>
{
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for DummyUPSStandardEndCapCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::UserEndCap
    }
    
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> DummyUPSStandardEndCapCircuit<C>{
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::UserEndCap;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(circuit_type as u32, [0u8; 32], &private_key.get_public_key());
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,        
        dummy_public_inputs: C::Hash,

    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(dummy_public_inputs, &self.private_key)
    }

    pub fn verify_proof(&self, proof_with_pis: &PsyTestJTMBProof<C::Hash>) -> anyhow::Result<()> {
        self.verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(proof_with_pis)
    }

    pub fn generate_proof_for_inputs(
        &self,
        start_user_leaf: &PQEDUserLeaf<C::F, C::Hash>,
        new_user_state_root: C::Hash,
        new_checkpoint_id: u64,
        new_checkpoint_root: C::Hash,
        number_of_transactions: u64,
        slots_modified: u64,
        global_user_tree_height: u8,
    ) -> anyhow::Result<(PQEDUserLeaf<C::F, C::Hash>, C::Hash, GUTAStats<C::F>, PUPSEndCapResultCompact<C::F, C::Hash>,PsyTestJTMBProof<C::Hash>)> {

        let old_user_leaf_hash = start_user_leaf.qfhash::<C::Hasher>();
        let mut new_user_leaf = start_user_leaf.clone();
        new_user_leaf.last_checkpoint_id = C::F::from_u64_value(new_checkpoint_id);
        new_user_leaf.nonce = new_user_leaf.nonce + C::F::from_u64_value(1);
        new_user_leaf.user_state_tree_root = new_user_state_root;
        let new_user_leaf_hash = new_user_leaf.qfhash::<C::Hasher>();
        let guta_stats = GUTAStats{
            fees_collected: C::F::from_u64_value(1000),
            user_ops_processed: C::F::from_u64_value(1),
            total_transactions: C::F::from_u64_value(number_of_transactions),
            slots_modified: C::F::from_u64_value(slots_modified),
        };


        let end_cap_result = PUPSEndCapResultCompact {
            start_user_leaf_hash: old_user_leaf_hash,
            end_user_leaf_hash: new_user_leaf_hash,
            checkpoint_tree_root_hash: new_checkpoint_root,
            user_id: new_user_leaf.user_id,
        };

        let guta_hash = end_cap_result.qfhash_with_guta_height::<C::Hasher>(global_user_tree_height);
        let public_inputs_expected = C::Hasher::q_two_to_one(guta_hash, guta_stats.qfhash::<C::Hasher>());
        let proof = self.prove_base(
            public_inputs_expected,
        )?;
        Ok((new_user_leaf, public_inputs_expected, guta_stats, end_cap_result, proof))

    }
}


impl<C: JTMBCircuitConfig> DummyUPSProver<C::F, C::Hash> for DummyUPSStandardEndCapCircuit<C>
{
    fn prove_end_cap_dummy_ups(
        &self,
        global_user_tree_height: u8,
        input: &SubmitUserEndCapNonProofInput<C::F, C::Hash>,
    ) -> anyhow::Result<Vec<u8>> {
        //println!("DummyUPSStandardEndCapCircuit::prove_end_cap_dummy_ups - input: {:#?}", input);
                let guta_hash = input.core.state_transition.qfhash_with_guta_height::<C::Hasher>(global_user_tree_height);

                let dummy_public_inputs = C::Hasher::q_two_to_one(
            guta_hash,
            input.core.stats.qfhash::<C::Hasher>(),
        );

        //println!("DummyUPSStandardEndCapCircuit::prove_end_cap_dummy_ups - dummy_public_inputs: {:#?}", dummy_public_inputs);

        let proof = self.prove_base(
            dummy_public_inputs,
        )?;
        //println!("DummyUPSStandardEndCapCircuit::prove_end_cap_dummy_ups - proof: {:#?}", proof);
        let result = serialize_jtmb_proof(&proof)?;
        //println!("DummyUPSStandardEndCapCircuit::prove_end_cap_dummy_ups - serialized proof: {:?}", hex::encode(&result));
        Ok(result)
    }
}