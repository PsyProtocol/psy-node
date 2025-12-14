use parth_core::{crypto::hash::traits::{QFieldHashable, ZeroableHash}, felt::FromPrimitiveValuesFelt};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{guta::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition}, proof_input::guta::GUTANoChangeFullInput, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::{
        gadgets::guta::guta_header::compute_guta_public_inputs_hash_two_children,
        utils::connect::jtmb_connect_ref,
    },
    utils::{circuit_info_library::PsyJTMBCircuitInfoLibrary, 
        jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}}
    ,
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct GUTANoChangeCircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
    pub checkpoint_tree_height: usize,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for GUTANoChangeCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTANoChange
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> GUTANoChangeCircuit<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        checkpoint_tree_height: usize,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::GUTANoChange;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(circuit_type as u32, [0u8; 32], &private_key.get_public_key());
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
            checkpoint_tree_height,
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        guta_circuit_whitelist: C::Hash,
        input: &GUTANoChangeFullInput<C::Hash>,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        
        if input.checkpoint_tree_proof.siblings.len() != self.checkpoint_tree_height {
            anyhow::bail!("checkpoint tree proof height mismatch");
        }
        if !input.checkpoint_tree_proof.verify::<C::Hasher>() {
            anyhow::bail!("checkpoint tree proof verification failed");
        }

        let computed_chain_root = input.checkpoint_leaf.global_state_roots.qfhash::<C::Hasher>();
        jtmb_connect_ref(&computed_chain_root, &input.checkpoint_leaf.checkpoint_leaf.global_chain_root, "computed chain root mismatch")?;
        
        let computed_leaf_hash = input.checkpoint_leaf.checkpoint_leaf.qfhash::<C::Hasher>();
        jtmb_connect_ref(&computed_leaf_hash, &input.checkpoint_tree_proof.value, "checkpoint proof value mismatch")?;

        let zero = C::F::from_u64_value(0);
        let one = C::F::from_u64_value(1);
        let zero_hash = C::Hash::get_zero_value();

        let new_header = GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist,
            checkpoint_tree_root: input.checkpoint_tree_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: input.checkpoint_leaf.global_state_roots.user_tree_root,
                new_node_value: input.checkpoint_leaf.global_state_roots.user_tree_root,
                node_index: zero,
                node_level: zero,
            },
            stats: GUTAStats {
                fees_collected: zero,
                user_ops_processed: zero,
                total_transactions: zero,
                slots_modified: zero,
            },
            total_aggregation_proofs_generated: one,
        };

        let public_inputs_hash = compute_guta_public_inputs_hash_two_children::<C::F, C::Hash, C::Hasher>(
            &new_header,
            zero_hash,
            zero_hash,
            worker_reward_tag,
        );

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            public_inputs_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for GUTANoChangeCircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let guta_whitelist_root=
            library.get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?.root;
        let witness = GUTANoChangeFullInput::<C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        self.prove_base(
            worker_reward_tag,
            guta_whitelist_root,
            &witness,
        )
    }
}