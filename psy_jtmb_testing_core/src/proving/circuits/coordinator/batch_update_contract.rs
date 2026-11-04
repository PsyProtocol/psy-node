use psy_core::{job::job_id::{ProvingJobCircuitType, QProvingJobDataID}, constants::protocol::{STATE_LAYOUT_TREE_HEIGHT, STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT, STATE_LAYOUT_MAX_AGGREGATION_DEPTH}};
use psy_data::{protocol::circuit_inputs::update_contracts::QCBatchUpdateContractsCircuitInput, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use parth_core::{crypto::hash::traits::{FieldQHasher, FromU64x4, MerkleHasher, ZeroableHash}, felt::{FromPrimitiveValuesFelt, ToU64Value}, protocol::core_types::Q256BitHash};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_plonky2_circuits::coordinator::state_layout_helper::CanonicalLayoutProofVerifier;
use psy_data::v1::qdata::contract::{LayoutAppendPublicInputs, STATE_LAYOUT_VERSION, validate_contract_layout_transition};

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::gadgets::coordinator::{agg_state::compute_agg_public_inputs, batch_update::verify_batch_update},
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct BatchUpdateContractsCircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,

    pub contract_tree_height: usize,
    pub batch_sub_tree_height: usize,
    pub max_contract_state_tree_height: usize,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for BatchUpdateContractsCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::BatchUpdateContracts
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> BatchUpdateContractsCircuit<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        contract_tree_height: usize,
        batch_sub_tree_height: usize,
        max_contract_state_tree_height: usize,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::BatchUpdateContracts;
        // Version the strengthened witness checks and bind the tree/layout
        // configuration so older permissive test proofs are not reusable.
        let config_hash = C::Hasher::q_hash_many(&[
            1, contract_tree_height as u64, batch_sub_tree_height as u64,
            max_contract_state_tree_height as u64, STATE_LAYOUT_VERSION as u64,
            STATE_LAYOUT_TREE_HEIGHT as u64, STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT as u64,
            STATE_LAYOUT_MAX_AGGREGATION_DEPTH as u64,
        ].map(C::F::from_u64_value));
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(circuit_type as u32, config_hash.into_owned_32bytes(), &private_key.get_public_key());
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
        update_contract_circuit_whitelist: C::Hash,
        worker_reward_tag: C::Hash,
        input: &QCBatchUpdateContractsCircuitInput<C::F, C::Hash>,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        verify_batch_update::<C::Hash, C::F, C::Hasher>(
            input,
            self.contract_tree_height,
            self.batch_sub_tree_height,
        )?;
        anyhow::ensure!(update_contract_circuit_whitelist == input.update_contract_circuit_whitelist, "contract update whitelist mismatch");
        for (index, proof_bytes) in input.layout_update_proofs.iter().enumerate() {
            let old_leaf = &input.old_contract_leaves[index];
            let new_leaf = &input.new_contract_leaves[index];
            anyhow::ensure!(old_leaf.state_tree_height.to_u64_value() <= self.max_contract_state_tree_height as u64,
                "contract state tree height exceeds configured maximum");
            // Layout proofs have the same canonical Plonky2 format on JTMB
            // and Plonky2 networks. Reject malformed encodings before building
            // the cached verifier, then verify against the fixed circuit.
            psy_plonky2_circuits::utils::proof_serialization::deserialize_plonky2_proof::<PoseidonGoldilocksConfig, 2>(proof_bytes)?;
            static VERIFIER: std::sync::OnceLock<CanonicalLayoutProofVerifier<PoseidonGoldilocksConfig, 2>> = std::sync::OnceLock::new();
            let verifier = VERIFIER.get_or_init(|| CanonicalLayoutProofVerifier::new(
                STATE_LAYOUT_TREE_HEIGHT - STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
                STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT, STATE_LAYOUT_MAX_AGGREGATION_DEPTH));
            let public_inputs = verifier.verify_serialized_proof(proof_bytes)?;
            let transition = LayoutAppendPublicInputs {
                contract_id: public_inputs[0],
                layout_version: u16::try_from(public_inputs[1])?,
                old_layout_root: C::Hash::from_u64x4(public_inputs[2..6].try_into()?),
                old_layout_field_count: public_inputs[6], old_layout_slot_count: public_inputs[7],
                new_layout_root: C::Hash::from_u64x4(public_inputs[8..12].try_into()?),
                new_layout_field_count: public_inputs[12], new_layout_slot_count: public_inputs[13],
                appended_field_count: public_inputs[14],
                appended_fields_commitment: C::Hash::from_u64x4(public_inputs[15..19].try_into()?),
            };
            validate_contract_layout_transition(input.updated_contract_ids[index], old_leaf, new_leaf, &transition)?;
        }

        let state_transition = psy_data::agg::AggStateTransition {
            state_transition_start: input.spiderman_update_proof.top_line_proof.old_root,
            state_transition_end: input.spiderman_update_proof.top_line_proof.new_root,
        };

        let one = C::F::from_u64_value(1);
        let zero = C::Hash::get_zero_value();
        let combo = C::Hasher::two_to_one(&zero, &zero);
        let leaf_rewards_val = C::Hasher::two_to_one(&combo, &worker_reward_tag);

        let final_pi_hash = compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(
            update_contract_circuit_whitelist,
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

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for BatchUpdateContractsCircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let witness = QCBatchUpdateContractsCircuitInput::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(
            witness.update_contract_circuit_whitelist,
            worker_reward_tag,
            &witness,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{PF, PHash, pgoldilocks::PoseidonHasher, crypto::hash::{merkle_proof::DeltaMerkleProofCore, spiderman::SpidermanUpdateProof, traits::{MerkleLeafHasher, QFieldHashable}}};
    use psy_data::v1::qdata::contract::PQEDContractLeafV2;
    use crate::protocol_types::JTMBPoseidonGoldilocksConfig;

    type Input = QCBatchUpdateContractsCircuitInput<PF, PHash>;
    type Circuit = BatchUpdateContractsCircuit<JTMBPoseidonGoldilocksConfig>;

    fn input(contract_id: u64) -> Input {
        let old_leaf = PQEDContractLeafV2::<PF, PHash>::default();
        let mut new_leaf = old_leaf.clone();
        new_leaf.code_root = PHash::from_values(1, 2, 3, 4);
        let mut input = Input {
            update_contract_circuit_whitelist: PHash::default(),
            spiderman_update_proof: SpidermanUpdateProof {
                top_line_proof: DeltaMerkleProofCore::from_params::<PoseidonHasher>(0, PHash::default(), PHash::default(), vec![]),
                web_proof_old_leaves: vec![], web_proof_new_leaves: vec![],
            },
            updated_contract_ids: vec![contract_id], old_contract_leaves: vec![old_leaf],
            new_contract_leaves: vec![new_leaf], layout_update_proofs: vec![vec![1]],
        };
        update_proof(&mut input);
        input
    }

    fn update_proof(input: &mut Input) {
        let old_hash = input.old_contract_leaves[0].qfhash::<PoseidonHasher>();
        let old = vec![old_hash; 4];
        let mut new = old.clone();
        new[(input.updated_contract_ids[0] % 4) as usize] = input.new_contract_leaves[0].qfhash::<PoseidonHasher>();
        input.spiderman_update_proof = proof(input.updated_contract_ids[0] / 4, old, new);
    }

    fn proof(index: u64, old: Vec<PHash>, new: Vec<PHash>) -> SpidermanUpdateProof<PHash> {
        SpidermanUpdateProof {
            top_line_proof: DeltaMerkleProofCore::from_params::<PoseidonHasher>(index,
                PoseidonHasher::compute_root_from_leaves(&old).unwrap(),
                PoseidonHasher::compute_root_from_leaves(&new).unwrap(), vec![PHash::default()]),
            web_proof_old_leaves: old, web_proof_new_leaves: new,
        }
    }

    fn circuit() -> Circuit {
        Circuit::new(&MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[7; 32]).unwrap(), 3, 2, 32)
    }

    #[test]
    fn batch_update_checks_global_window_and_all_changes() {
        let valid = input(5);
        assert!(verify_batch_update::<PHash, PF, PoseidonHasher>(&valid, 3, 2).is_ok());
        let mut invalid = input(1);
        let old = invalid.spiderman_update_proof.web_proof_old_leaves.clone();
        let mut new = invalid.spiderman_update_proof.web_proof_new_leaves.clone();
        new[2] = new[1];
        invalid.spiderman_update_proof = proof(0, old, new);
        assert!(verify_batch_update::<PHash, PF, PoseidonHasher>(&invalid, 3, 2).unwrap_err().to_string().contains("changed leaf count"));
        let mut invalid = input(5);
        invalid.new_contract_leaves.clear();
        assert!(verify_batch_update::<PHash, PF, PoseidonHasher>(&invalid, 3, 2).is_err());
        let invalid = input(9);
        assert!(verify_batch_update::<PHash, PF, PoseidonHasher>(&invalid, 3, 2).is_err());
        assert!(verify_batch_update::<PHash, PF, PoseidonHasher>(&valid, 1, 2).is_err());
    }

    #[test]
    fn batch_update_rejects_malformed_layout_and_versions_fingerprint() {
        let input = input(5);
        let circuit = circuit();
        assert!(circuit.prove_base(input.update_contract_circuit_whitelist, PHash::default(), &input).is_err());
        let key = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[7; 32]).unwrap();
        let legacy = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(ProvingJobCircuitType::BatchUpdateContracts as u32, [0; 32], &key.get_public_key());
        assert_ne!(circuit.get_fingerprint(), legacy.get_fingerprint::<PHash, PoseidonHasher, PF>());
        assert_ne!(circuit.get_fingerprint(), Circuit::new(&key, 4, 2, 32).get_fingerprint());
    }

    #[test]
    fn batch_update_verifies_real_layout_proof_and_binds_endpoints() -> anyhow::Result<()> {
        use psy_data::v1::qdata::contract::canonical_layout_manifest_from_compiler_abi_json;
        use psy_plonky2_circuits::coordinator::state_layout_helper::StateLayoutCircuitManager;
        let manifest = canonical_layout_manifest_from_compiler_abi_json::<PoseidonHasher, PF, PHash>(r#"{
            "contract": {"state_tree_height": 4, "state_layout": {
                "layout_version": 1, "encoding_version": 1, "field_count": 1, "slot_count": 1,
                "fields": [{"field_id": 1, "type": {"kind": "primitive", "name": "Felt"}, "start_slot": 0, "slot_count": 1}]
            }}, "types": []
        }"#, STATE_LAYOUT_TREE_HEIGHT, 2)?;
        let manager = StateLayoutCircuitManager::<PoseidonGoldilocksConfig, 2>::new_layout_only(
            STATE_LAYOUT_TREE_HEIGHT - STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
            STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT, STATE_LAYOUT_MAX_AGGREGATION_DEPTH);
        let layout_proof = manager.prove_layout_no_change(5, &manifest)?;
        let mut input = input(5);
        let layout = &manifest.layout.contract_layout;
        for leaf in [&mut input.old_contract_leaves[0], &mut input.new_contract_leaves[0]] {
            leaf.state_tree_height = PF::from_u64_value(4);
            leaf.state_layout_root = layout.state_layout_root;
            leaf.state_layout_field_count = PF::from_u64_value(layout.state_layout_field_count);
            leaf.state_layout_slot_count = PF::from_u64_value(layout.state_layout_slot_count);
        }
        input.layout_update_proofs[0] = layout_proof.canonical_proof;
        update_proof(&mut input);
        let circuit = circuit();
        let proved = circuit.prove_base(input.update_contract_circuit_whitelist, PHash::default(), &input)?;
        circuit.get_verifier_data().verify_proof::<PoseidonHasher, PHash, PF>(&proved)?;

        for mutate in [
            (|w: &mut Input| w.updated_contract_ids[0] = 6) as fn(&mut Input),
            |w| w.new_contract_leaves[0].state_layout_root = PHash::default(),
            |w| w.new_contract_leaves[0].deployer = PF::from_u64_value(1),
            |w| w.new_contract_leaves[0].state_tree_height = PF::from_u64_value(5),
            |w| w.new_contract_leaves[0].state_layout_field_count = PF::from_u64_value(2),
        ] {
            let mut invalid = input.clone(); mutate(&mut invalid); update_proof(&mut invalid);
            assert!(circuit.prove_base(invalid.update_contract_circuit_whitelist, PHash::default(), &invalid).is_err());
        }
        let mut invalid = input.clone();
        let bytes = &mut invalid.layout_update_proofs[0];
        let last = bytes.len() - 1; bytes[last] ^= 1;
        assert!(circuit.prove_base(invalid.update_contract_circuit_whitelist, PHash::default(), &invalid).is_err());
        Ok(())
    }
}
