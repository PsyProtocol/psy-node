use std::fmt::Debug;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    gates::gate::GateRef,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    proof_minifier::pm_chain::PsyProofMinifierChain,
    traits::CreatableTarget,
    u32::gates::comparison::ComparisonGate,
};
use psy_config::network_constants::PSY_NETWORK_MAGIC;
use psy_crypto::{hash::traits::hasher::MerkleZeroHasher, signature::zk::wallet::PRIVATE_KEY_CONSTANTS};
use psy_dpn_circuit::vm::compile::PsyContractFunctionBuilderGadget;
use psy_network_circuit::gadgets::qdata::{
    user::PsyUserLeafGadget,
    user_contract_state::SignContextGadget,
};
use psy_network_circuit::ups::gadgets::ups_signature_data::PsyUserProvingSessionSignatureDataCompactGadget;
use psy_vm::{
    dpn::vm::def::DPNFunctionCircuitDefinition,
    ups::signature::{
        DPNSoftwareDefinedSignatureInput, Plonky2SoftwareDefinedSignatureInput, SoftwareDefinedSessionSigBinding,
    },
};

use crate::signature::state_reader::StateReaderGadget;

type C = PoseidonGoldilocksConfig;
type GF = GoldilocksField;
const D: usize = 2;

fn set_session_sig_witness(
    pw: &mut PartialWitness<GF>,
    sig_data: &PsyUserProvingSessionSignatureDataCompactGadget,
    sign_context: &SignContextGadget,
    nonce: Target,
    start_user_leaf: &PsyUserLeafGadget,
    binding: &SoftwareDefinedSessionSigBinding,
    start_leaf: &psy_client_data::qdata::user::PsyUserLeaf<GF>,
) -> anyhow::Result<()> {
    sig_data.set_witness(pw, &binding.sig_data)?;
    pw.set_hash_target(sign_context.checkpoint_tree_root, binding.sign_context.checkpoint_tree_root.0)?;
    sign_context.user_leaf.set_witness(pw, &binding.sign_context.user_leaf)?;
    pw.set_target(nonce, binding.nonce)?;
    start_user_leaf.set_witness(pw, start_leaf)?;
    Ok(())
}

/// Bind EndCap-equivalent sighash: compute `sig_hash` from session fields and pin policy anchors.
fn enforce_session_sighash_binding(
    builder: &mut CircuitBuilder<GF, D>,
    sig_data: &PsyUserProvingSessionSignatureDataCompactGadget,
    sign_context: &SignContextGadget,
    start_user_leaf: &PsyUserLeafGadget,
    nonce: Target,
) -> HashOutTarget {
    // start leaf hash must match the leaf we witness
    let start_hash = start_user_leaf.to_hash::<PoseidonHash, GF, D>(builder);
    builder.connect_hashes(start_hash, sig_data.start_user_leaf_hash);

    // EndCap: current.nonce == start.nonce before bump; same user_id / public_key
    builder.connect(start_user_leaf.nonce, sign_context.user_leaf.nonce);
    builder.connect(start_user_leaf.user_id, sign_context.user_leaf.user_id);
    builder.connect_hashes(start_user_leaf.public_key, sign_context.user_leaf.public_key);

    // end_user_leaf_hash = hash(current leaf with nonce := final nonce)
    let mut end_user_leaf = sign_context.user_leaf;
    end_user_leaf.nonce = nonce;
    let end_hash = end_user_leaf.to_hash::<PoseidonHash, GF, D>(builder);
    builder.connect_hashes(end_hash, sig_data.end_user_leaf_hash);

    sig_data
        .get_sig_action_with_user_info::<PoseidonHash, GF, D>(
            builder,
            PSY_NETWORK_MAGIC,
            sign_context.user_leaf.user_id,
            nonce,
            sign_context,
        )
        .sig_action_hash
}

#[derive(Debug)]
pub struct DPNSoftwareDefinedSignatureGadget {
    pub fn_builder_gadget: PsyContractFunctionBuilderGadget,
    pub fn_def: DPNFunctionCircuitDefinition,
    pub contract_id: u64,
    pub contract_state_tree_height: u8,
    pub session_proof_tree_height: u8,
    pub force_four_align: bool,
    pub circuit_inputs: Vec<Target>,
    pub private_key: HashOutTarget,
    pub sig_hash: HashOutTarget,
    pub sig_data: PsyUserProvingSessionSignatureDataCompactGadget,
    pub sign_context: SignContextGadget,
    pub start_user_leaf: PsyUserLeafGadget,
    pub nonce: Target,
    pub circuit_data: Option<CircuitData<GF, C, D>>,
    pub minifier_chain: Option<PsyProofMinifierChain<D, GF, C>>,
}

impl DPNSoftwareDefinedSignatureGadget {
    pub fn add_virtual_to(
        builder: &mut CircuitBuilder<GF, D>,
        fn_def: &DPNFunctionCircuitDefinition,
        contract_id: u64,
        contract_state_tree_height: u8,
        session_proof_tree_height: u8,
        force_four_align: bool,
    ) -> Self {
        let private_key = builder.add_virtual_hash();
        let circuit_inputs = builder.add_virtual_targets(fn_def.circuit_inputs.len());

        let fn_builder_gadget = PsyContractFunctionBuilderGadget::add_virtual_to::<PoseidonHash, GF, D>(
            builder,
            fn_def,
            contract_state_tree_height as usize,
            session_proof_tree_height as usize,
            circuit_inputs.clone(),
            force_four_align,
        );

        let start_contract_state_tree_root = fn_builder_gadget.tx_ctx_header.transaction_call_start_ctx.start_contract_state_tree_root;
        let end_contract_state_tree_root = fn_builder_gadget.tx_ctx_header.transaction_end_ctx.end_contract_state_tree_root;
        builder.connect_hashes(start_contract_state_tree_root, end_contract_state_tree_root);

        let sig_data = PsyUserProvingSessionSignatureDataCompactGadget::add_virtual_to(builder);
        let sign_context = SignContextGadget::add_virtual_to(builder);
        let start_user_leaf = PsyUserLeafGadget::create_virtual(builder);
        let nonce = builder.add_virtual_target();

        let session_start = &fn_builder_gadget.tx_ctx_header.proving_session_start_ctx;
        let call_start = &fn_builder_gadget.tx_ctx_header.transaction_call_start_ctx;

        // Policy CFC session anchors ≡ signed session
        builder.connect_hashes(session_start.checkpoint_tree_root, sign_context.checkpoint_tree_root);
        let checkpoint_leaf_hash = session_start.checkpoint_leaf.to_hash::<PoseidonHash, GF, D>(builder);
        builder.connect_hashes(checkpoint_leaf_hash, sig_data.checkpoint_leaf_hash);
        session_start
            .start_session_user_leaf
            .connect_to_other(builder, start_user_leaf);
        builder.connect_hashes(call_start.start_user_contract_tree_root, sign_context.user_leaf.user_state_tree_root);
        builder.connect(call_start.start_user_balance, sign_context.user_leaf.balance);
        builder.connect(call_start.start_user_event_index, sign_context.user_leaf.event_index);
        builder.connect(session_start.checkpoint_id, sign_context.user_leaf.last_checkpoint_id);

        let sig_hash = enforce_session_sighash_binding(builder, &sig_data, &sign_context, &start_user_leaf, nonce);

        let public_key_param = get_zk_public_key_param::<C, D>(builder, &private_key);
        let public_inputs_hash = builder.hash_two_to_one::<PoseidonHash>(sig_hash, public_key_param);
        builder.register_public_inputs(&public_inputs_hash.elements);

        Self {
            fn_builder_gadget,
            fn_def: fn_def.clone(),
            contract_id,
            contract_state_tree_height,
            session_proof_tree_height,
            force_four_align,
            circuit_inputs,
            private_key,
            sig_hash,
            sig_data,
            sign_context,
            start_user_leaf,
            nonce,
            circuit_data: None,
            minifier_chain: None,
        }
    }

    pub fn build_circuit(&mut self, builder: CircuitBuilder<GF, D>) -> anyhow::Result<()> {
        let mut builder = builder;
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<GF, D>(&mut builder, 11);

        let circuit_data = builder.build::<C>();
        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];
        let minifier_chain =
            PsyProofMinifierChain::<D, GF, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));

        self.circuit_data = Some(circuit_data);
        self.minifier_chain = Some(minifier_chain);
        Ok(())
    }

    pub async fn prove(
        &mut self,
        private_key: QHashOut<GF>,
        signature_input: &DPNSoftwareDefinedSignatureInput,
        sig_hash: QHashOut<GF>,
    ) -> anyhow::Result<ProofWithPublicInputs<GF, C, D>> {
        let circuit_data = self.circuit_data.as_ref().ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;
        let minifier_chain = self
            .minifier_chain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Minifier chain not initialized"))?;

        let expected = signature_input
            .session_sig
            .sig_data
            .get_sig_action_for_user::<PoseidonHash>(
                PSY_NETWORK_MAGIC,
                signature_input.session_sig.sign_context.user_leaf.user_id,
                signature_input.session_sig.nonce,
                signature_input.session_sig.sign_context.clone(),
            )
            .get_qhash::<PoseidonHash>();
        anyhow::ensure!(
            expected == sig_hash,
            "SD prove sighash mismatch: host {} vs session binding {}",
            sig_hash,
            expected
        );

        let mut pw = PartialWitness::<GF>::new();
        pw.set_hash_target(self.private_key, private_key.0)?;
        pw.set_target_arr(&self.circuit_inputs, &signature_input.cfc_input.inputs)?;
        set_session_sig_witness(
            &mut pw,
            &self.sig_data,
            &self.sign_context,
            self.nonce,
            &self.start_user_leaf,
            &signature_input.session_sig,
            &signature_input.session_sig.start_session_user_leaf,
        )?;

        pw.set_hash_target(
            self.fn_builder_gadget.session_proof_tree_root,
            signature_input.cfc_input.session_proof_tree_root.0,
        )?;
        self.fn_builder_gadget
            .tx_ctx_header
            .set_witness(&mut pw, &signature_input.cfc_input.tx_input_ctx)?;
        self.fn_builder_gadget
            .state_reader
            .set_witness(&mut pw, &signature_input.cfc_input, &self.fn_def)?;

        let inner_proof = circuit_data.prove(pw)?;
        let minified_proof = minifier_chain.prove(&inner_proof)?;
        Ok(minified_proof)
    }

    pub fn get_fingerprint(&self) -> QHashOut<GF> {
        self.minifier_chain
            .as_ref()
            .map(|chain| QHashOut(chain.get_fingerprint()))
            .unwrap_or_default()
    }

    pub fn get_verifier_config_ref(&self) -> Option<&VerifierOnlyCircuitData<C, D>> {
        self.minifier_chain.as_ref().map(|chain| chain.get_verifier_data())
    }
}

#[derive(Debug)]
pub struct Plonky2SoftwareDefinedSignatureGadget {
    pub state_reader_gadget: StateReaderGadget<GF, D>,
    pub contract_state_tree_height: u8,
    pub input_len: usize,
    pub circuit_inputs: Vec<Target>,
    pub private_key: HashOutTarget,
    pub sig_hash: HashOutTarget,
    pub sig_data: PsyUserProvingSessionSignatureDataCompactGadget,
    pub sign_context: SignContextGadget,
    pub start_user_leaf: PsyUserLeafGadget,
    pub nonce: Target,
    pub circuit_data: Option<CircuitData<GF, C, D>>,
    pub minifier_chain: Option<PsyProofMinifierChain<D, GF, C>>,
}

impl Plonky2SoftwareDefinedSignatureGadget {
    pub fn add_virtual_to(builder: &mut CircuitBuilder<GF, D>, contract_state_tree_height: u8, input_len: usize) -> Self {
        let private_key = builder.add_virtual_hash();
        let circuit_inputs = builder.add_virtual_targets(input_len);
        let state_reader_gadget = StateReaderGadget::new(builder, contract_state_tree_height);

        let sig_data = PsyUserProvingSessionSignatureDataCompactGadget::add_virtual_to(builder);
        let start_user_leaf = PsyUserLeafGadget::create_virtual(builder);
        let nonce = builder.add_virtual_target();

        // Policy StateReader anchors are the signed SignContext (same targets).
        let sign_context = SignContextGadget {
            checkpoint_tree_root: state_reader_gadget.state.checkpoint_tree_root,
            user_leaf: state_reader_gadget.state.user_leaf,
        };

        let sig_hash = enforce_session_sighash_binding(builder, &sig_data, &sign_context, &start_user_leaf, nonce);

        let public_key_param = get_zk_public_key_param::<C, D>(builder, &private_key);
        let public_inputs_hash = builder.hash_two_to_one::<PoseidonHash>(sig_hash, public_key_param);
        builder.register_public_inputs(&public_inputs_hash.elements);

        Self {
            state_reader_gadget,
            contract_state_tree_height,
            input_len,
            circuit_inputs,
            private_key,
            sig_hash,
            sig_data,
            sign_context,
            start_user_leaf,
            nonce,
            circuit_data: None,
            minifier_chain: None,
        }
    }

    pub fn add_custom_constraints<F>(&mut self, builder: &mut CircuitBuilder<GF, D>, constraints_fn: F)
    where
        F: FnOnce(&mut CircuitBuilder<GF, D>, &mut StateReaderGadget<GF, D>, &[Target]),
    {
        constraints_fn(builder, &mut self.state_reader_gadget, &self.circuit_inputs);
    }

    pub fn build_circuit(&mut self, builder: CircuitBuilder<GF, D>) -> anyhow::Result<()> {
        let mut builder = builder;
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<GF, D>(&mut builder, 11);

        let circuit_data = builder.build::<C>();
        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];
        let minifier_chain =
            PsyProofMinifierChain::<D, GF, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));

        self.circuit_data = Some(circuit_data);
        self.minifier_chain = Some(minifier_chain);
        Ok(())
    }

    pub async fn prove(
        &mut self,
        private_key: QHashOut<GF>,
        input: &Plonky2SoftwareDefinedSignatureInput,
        sig_hash: QHashOut<GF>,
    ) -> anyhow::Result<ProofWithPublicInputs<GF, C, D>> {
        let circuit_data = self.circuit_data.as_ref().ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;
        let minifier_chain = self
            .minifier_chain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Minifier chain not initialized"))?;

        let expected = input
            .session_sig
            .sig_data
            .get_sig_action_for_user::<PoseidonHash>(
                PSY_NETWORK_MAGIC,
                input.session_sig.sign_context.user_leaf.user_id,
                input.session_sig.nonce,
                input.session_sig.sign_context.clone(),
            )
            .get_qhash::<PoseidonHash>();
        anyhow::ensure!(
            expected == sig_hash,
            "SD prove sighash mismatch: host {} vs session binding {}",
            sig_hash,
            expected
        );

        anyhow::ensure!(
            input.state_reader_results.state.user_leaf == input.session_sig.sign_context.user_leaf,
            "Plonky2 SD StateReader user_leaf must equal signed SignContext user_leaf"
        );
        anyhow::ensure!(
            input.state_reader_results.state.checkpoint_tree_root == input.session_sig.sign_context.checkpoint_tree_root,
            "Plonky2 SD StateReader checkpoint_tree_root must equal signed SignContext"
        );

        let mut pw = PartialWitness::<GF>::new();
        pw.set_hash_target(self.private_key, private_key.0)?;
        pw.set_target_arr(&self.circuit_inputs, &input.circuit_inputs)?;
        self.state_reader_gadget.set_witness(&mut pw, &input.state_reader_results)?;
        set_session_sig_witness(
            &mut pw,
            &self.sig_data,
            &self.sign_context,
            self.nonce,
            &self.start_user_leaf,
            &input.session_sig,
            &input.session_sig.start_session_user_leaf,
        )?;

        let inner_proof = circuit_data.prove(pw)?;
        let minified_proof = minifier_chain.prove(&inner_proof)?;
        Ok(minified_proof)
    }

    pub fn get_fingerprint(&self) -> QHashOut<GF> {
        self.minifier_chain
            .as_ref()
            .map(|chain| QHashOut(chain.get_fingerprint()))
            .unwrap_or_default()
    }

    pub fn get_verifier_config_ref(&self) -> Option<&VerifierOnlyCircuitData<C, D>> {
        self.minifier_chain.as_ref().map(|chain| chain.get_verifier_data())
    }
}

pub fn get_zk_public_key_param<C: GenericConfig<D>, const D: usize>(
    builder: &mut CircuitBuilder<C::F, D>,
    private_key: &HashOutTarget,
) -> HashOutTarget
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    let private_key_constants = PRIVATE_KEY_CONSTANTS
        .iter()
        .map(|c| builder.constant(C::F::from_canonical_u64(*c)))
        .collect::<Vec<_>>();
    builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
        private_key_constants[0],
        private_key_constants[1],
        private_key_constants[2],
        private_key_constants[19],
        private_key.elements[1],
        private_key_constants[1],
        private_key_constants[2],
        private_key_constants[3],
        private_key_constants[4],
        private_key_constants[5],
        private_key_constants[6],
        private_key.elements[0],
        private_key_constants[7],
        private_key.elements[2],
        private_key_constants[8],
        private_key_constants[9],
        private_key_constants[10],
        private_key_constants[11],
        private_key_constants[12],
        private_key.elements[3],
        private_key_constants[13],
        private_key_constants[14],
        private_key_constants[15],
        private_key_constants[16],
        private_key_constants[17],
        private_key_constants[18],
    ])
}

pub fn get_sdc_public_key_param<F: RichField>(private_key: &QHashOut<F>) -> QHashOut<F> {
    let private_key_constants = PRIVATE_KEY_CONSTANTS.iter().map(|c| F::from_canonical_u64(*c)).collect::<Vec<_>>();
    QHashOut(PoseidonHash::hash_no_pad(&[
        private_key_constants[0],
        private_key_constants[1],
        private_key_constants[2],
        private_key_constants[19],
        private_key.0.elements[1],
        private_key_constants[1],
        private_key_constants[2],
        private_key_constants[3],
        private_key_constants[4],
        private_key_constants[5],
        private_key_constants[6],
        private_key.0.elements[0],
        private_key_constants[7],
        private_key.0.elements[2],
        private_key_constants[8],
        private_key_constants[9],
        private_key_constants[10],
        private_key_constants[11],
        private_key_constants[12],
        private_key.0.elements[3],
        private_key_constants[13],
        private_key_constants[14],
        private_key_constants[15],
        private_key_constants[16],
        private_key_constants[17],
        private_key_constants[18],
    ]))
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    };
    use psy_client_common::data::qhashout::QHashOut;
    use psy_client_data::qdata::{
        ups_signature::PsyUserProvingSessionSignatureDataCompact, user::PsyUserLeaf, user_contract_state::SignContext,
        user_contract_state::UserContractState,
    };
    use psy_config::network_constants::PSY_NETWORK_MAGIC;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    use psy_vm::ups::signature::{Plonky2SoftwareDefinedSignatureInput, SoftwareDefinedSessionSigBinding};
    use psy_vm::ups::state_reader::StateReaderResults;

    use super::Plonky2SoftwareDefinedSignatureGadget;

    type F = GoldilocksField;
    const D: usize = 2;

    fn qh(a: u64, b: u64, c: u64, d: u64) -> QHashOut<F> {
        QHashOut(HashOut {
            elements: [
                F::from_canonical_u64(a),
                F::from_canonical_u64(b),
                F::from_canonical_u64(c),
                F::from_canonical_u64(d),
            ],
        })
    }

    fn sample_leaf(user_id: u64, nonce: u64) -> PsyUserLeaf<F> {
        PsyUserLeaf {
            public_key: qh(1, 2, 3, 4),
            user_state_tree_root: qh(5, 6, 7, 8),
            balance: F::from_canonical_u64(100),
            nonce: F::from_canonical_u64(nonce),
            last_checkpoint_id: F::from_canonical_u64(1),
            event_index: F::ZERO,
            user_id: F::from_canonical_u64(user_id),
        }
    }

    fn sample_binding(user_id: u64, nonce: u64) -> SoftwareDefinedSessionSigBinding {
        let start = sample_leaf(user_id, nonce);
        let current = start;
        let mut end = current;
        let final_nonce = F::from_canonical_u64(nonce + 1);
        end.nonce = final_nonce;

        let sig_data = PsyUserProvingSessionSignatureDataCompact {
            start_user_leaf_hash: start.qfhash::<PoseidonHash>(),
            end_user_leaf_hash: end.qfhash::<PoseidonHash>(),
            checkpoint_leaf_hash: qh(9, 10, 11, 12),
            tx_stack_hash: QHashOut::ZERO,
            tx_count: F::ZERO,
        };
        let sign_context = SignContext {
            checkpoint_tree_root: qh(13, 14, 15, 16),
            user_leaf: current,
        };
        SoftwareDefinedSessionSigBinding {
            sig_data,
            sign_context,
            start_session_user_leaf: start,
            nonce: final_nonce,
        }
    }

    #[test]
    fn plonky2_sd_wires_session_sighash_not_free_hash() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let gadget = Plonky2SoftwareDefinedSignatureGadget::add_virtual_to(&mut builder, 1, 0);
        assert_eq!(
            gadget.state_reader_gadget.state.user_leaf.user_id,
            gadget.sign_context.user_leaf.user_id
        );
        assert_eq!(
            gadget.state_reader_gadget.state.checkpoint_tree_root.elements[0],
            gadget.sign_context.checkpoint_tree_root.elements[0]
        );
    }

    #[tokio::test]
    async fn plonky2_sd_prove_rejects_policy_session_mismatch() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut gadget = Plonky2SoftwareDefinedSignatureGadget::add_virtual_to(&mut builder, 1, 0);
        gadget.build_circuit(builder).expect("build");

        let binding = sample_binding(7, 0);
        let mismatched_state = UserContractState::new(
            binding.sign_context.checkpoint_tree_root,
            sample_leaf(99, 0),
            QHashOut::ZERO,
            F::from_canonical_u64(0),
            F::from_canonical_u64(1),
        );

        let input = Plonky2SoftwareDefinedSignatureInput {
            state_reader_results: StateReaderResults {
                state: mismatched_state,
                user_tree_root: QHashOut::ZERO,
                aux_user_leaves: vec![],
                state_cmds: vec![],
                merkel_proofs: vec![],
            },
            circuit_inputs: vec![],
            session_sig: binding.clone(),
        };

        let sighash = binding
            .sig_data
            .get_sig_action_for_user::<PoseidonHash>(
                PSY_NETWORK_MAGIC,
                binding.sign_context.user_leaf.user_id,
                binding.nonce,
                binding.sign_context,
            )
            .get_qhash::<PoseidonHash>();

        let err = gadget
            .prove(QHashOut::ZERO, &input, sighash)
            .await
            .expect_err("mismatched StateReader vs SignContext must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("StateReader user_leaf must equal signed SignContext"),
            "unexpected error: {msg}"
        );
    }
}
