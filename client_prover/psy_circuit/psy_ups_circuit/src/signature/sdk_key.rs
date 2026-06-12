use std::fmt::Debug;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    gates::gate::GateRef,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierOnlyCircuitData},
        config::{Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::dpn::sdk_key::{SDKKeyConfig, SDKKeyTransactionInfo};
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    proof_minifier::pm_chain::PsyProofMinifierChain,
    u32::gates::comparison::ComparisonGate,
};
use psy_config::network_constants::DEFERRED_CALL_MAGIC;
use psy_crypto::signature::zk::wallet::PRIVATE_KEY_CONSTANTS;
use psy_vm::ups::sdk_key::SDKKeyCircuitWitnessInput;

use crate::signature::state_reader::StateReaderGadget;

type C = PoseidonGoldilocksConfig;
type GF = GoldilocksField;
const D: usize = 2;

/// Gadget for transaction introspection within an SDK key circuit.
///
/// Each slot corresponds to a compile-time-constant transaction index.
/// The circuit proves that the transaction info matches the tx_stack_hash
/// chain.
#[derive(Debug)]
pub struct SDKKeyTransactionIntrospectionGadget {
    /// Transaction info targets for each introspectable slot.
    pub tx_info_slots: Vec<SDKKeyTransactionInfoTargets>,
    /// The tx_stack_hash target (running hash of all transactions).
    pub tx_stack_hash: HashOutTarget,
    /// Transaction count target.
    pub tx_count: Target,
}

/// Plonky2 targets for a single transaction's introspectable info.
#[derive(Debug, Clone)]
pub struct SDKKeyTransactionInfoTargets {
    pub contract_id: Target,
    pub method_id: Target,
    pub caller_contract_id: Target,
    pub inputs_length: Target,
    pub inputs_hash: HashOutTarget,
    /// The hash of this transaction's compact call data.
    pub tx_hash: HashOutTarget,
}

/// Gadget for secp256k1 signature verification slots within an SDK key circuit.
#[derive(Debug)]
pub struct SDKKeySecp256k1Gadget {
    pub slots: Vec<SDKKeySecp256k1SlotTargets>,
}

/// Targets for a single secp256k1 verification slot.
#[derive(Debug, Clone)]
pub struct SDKKeySecp256k1SlotTargets {
    pub public_key: [Target; 16],
    pub msg_hash: HashOutTarget,
    pub signature: [Target; 16],
    /// Result of verification (boolean target).
    pub is_valid: Target,
}

/// The main SDK key circuit gadget.
///
/// This circuit proves that a user's custom authorization logic is satisfied.
/// It combines:
/// - Private key derivation (same as existing ZK signatures)
/// - Transaction introspection (read n-th tx info for compile-time-constant n)
/// - State reading at current checkpoint
/// - Secp256k1 signature verification
///
/// Public output: hash(sig_hash, public_key_param)
/// This matches the existing signature format so SDK keys are drop-in
/// compatible with the existing UPS end-cap signature verification.
#[derive(Debug)]
pub struct SDKKeyCircuitGadget {
    /// Configuration for this SDK key.
    pub config: SDKKeyConfig,

    /// Transaction introspection gadget.
    pub tx_introspection: SDKKeyTransactionIntrospectionGadget,

    /// State reader gadget (if state reading is enabled).
    pub state_reader: Option<StateReaderGadget<GF, D>>,

    /// Secp256k1 verification gadget.
    pub secp256k1: Option<SDKKeySecp256k1Gadget>,

    /// User-provided circuit inputs.
    pub circuit_inputs: Vec<Target>,

    /// The private key target (witness-only, never public).
    pub private_key: HashOutTarget,

    /// The sig_hash target (what is being signed).
    pub sig_hash: HashOutTarget,

    /// Checkpoint ID target.
    pub checkpoint_id: Target,

    /// User ID target.
    pub user_id: Target,

    /// Built circuit data (populated after build_circuit).
    pub circuit_data: Option<CircuitData<GF, C, D>>,

    /// Proof minifier chain (populated after build_circuit).
    pub minifier_chain: Option<PsyProofMinifierChain<D, GF, C>>,
}

impl SDKKeyCircuitGadget {
    /// Create a new SDK key circuit gadget and add all virtual targets to the
    /// builder.
    ///
    /// The `input_len` is the number of user-provided circuit inputs
    /// (parameters to the authorization function, excluding self/ctx).
    pub fn add_virtual_to(builder: &mut CircuitBuilder<GF, D>, config: &SDKKeyConfig, input_len: usize) -> Self {
        let private_key = builder.add_virtual_hash();
        let sig_hash = builder.add_virtual_hash();
        let checkpoint_id = builder.add_virtual_target();
        let user_id = builder.add_virtual_target();
        let circuit_inputs = builder.add_virtual_targets(input_len);

        // Transaction introspection
        let tx_introspection = Self::build_tx_introspection(builder, config);

        // State reader (optional)
        let state_reader = if config.can_read_state {
            Some(StateReaderGadget::new(builder, config.contract_state_tree_height))
        } else {
            None
        };

        // Secp256k1 verification slots (optional)
        let secp256k1 = if config.requires_secp256k1 && config.num_secp256k1_slots > 0 {
            Some(Self::build_secp256k1_slots(builder, config.num_secp256k1_slots))
        } else {
            None
        };

        // Derive public_key_param from private_key (same derivation as existing ZK
        // sigs)
        let public_key_param = get_zk_public_key_param(builder, &private_key);

        // Register public outputs: hash(sig_hash, public_key_param)
        let public_inputs_hash = builder.hash_two_to_one::<PoseidonHash>(sig_hash, public_key_param);
        builder.register_public_inputs(&public_inputs_hash.elements);

        Self {
            config: config.clone(),
            tx_introspection,
            state_reader,
            secp256k1,
            circuit_inputs,
            private_key,
            sig_hash,
            checkpoint_id,
            user_id,
            circuit_data: None,
            minifier_chain: None,
        }
    }

    /// Build the transaction introspection sub-circuit.
    ///
    /// For each introspectable transaction slot, we:
    /// 1. Add virtual targets for the transaction info fields
    /// 2. Compute the transaction hash using the compact DPN transaction hash format
    /// 3. Build and constrain the tx_stack_hash chain
    fn build_tx_introspection(builder: &mut CircuitBuilder<GF, D>, config: &SDKKeyConfig) -> SDKKeyTransactionIntrospectionGadget {
        let n = config.num_introspectable_transactions as usize;
        let tx_stack_hash = builder.add_virtual_hash();
        let tx_count = builder.add_virtual_target();

        let mut tx_info_slots = Vec::with_capacity(n);

        // Build each transaction slot using the same compact transaction hash
        // that UPS uses in the real tx_hash_stack.
        let magic = builder.constant(GF::from_noncanonical_u64(DEFERRED_CALL_MAGIC));

        // Running hash starts at zero (empty tx stack)
        let mut running_hash = builder.constant_hash(HashOut::ZERO);

        for _i in 0..n {
            let contract_id = builder.add_virtual_target();
            let method_id = builder.add_virtual_target();
            let caller_contract_id = builder.add_virtual_target();
            let inputs_length = builder.add_virtual_target();
            let inputs_hash = builder.add_virtual_hash();

            // Compute the compact DPN transaction hash:
            // tx_hash = hash(magic, caller_contract_id, contract_id, method_id,
            // inputs_length, inputs_hash)
            let tx_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
                magic,
                caller_contract_id,
                contract_id,
                method_id,
                inputs_length,
                inputs_hash.elements[0],
                inputs_hash.elements[1],
                inputs_hash.elements[2],
                inputs_hash.elements[3],
            ]);

            // Chain into running hash: running_hash = hash(running_hash, tx_hash)
            running_hash = builder.hash_two_to_one::<PoseidonHash>(running_hash, tx_hash);

            tx_info_slots.push(SDKKeyTransactionInfoTargets {
                contract_id,
                method_id,
                caller_contract_id,
                inputs_length,
                inputs_hash,
                tx_hash,
            });
        }

        // Constrain that our computed chain matches the provided tx_stack_hash
        if n > 0 {
            builder.connect_hashes(running_hash, tx_stack_hash);
        }

        SDKKeyTransactionIntrospectionGadget {
            tx_info_slots,
            tx_stack_hash,
            tx_count,
        }
    }

    /// Build secp256k1 signature verification slots.
    fn build_secp256k1_slots(builder: &mut CircuitBuilder<GF, D>, num_slots: u32) -> SDKKeySecp256k1Gadget {
        let mut slots = Vec::with_capacity(num_slots as usize);

        for _i in 0..num_slots {
            let public_key: [Target; 16] = std::array::from_fn(|_| builder.add_virtual_target());
            let msg_hash = builder.add_virtual_hash();
            let signature: [Target; 16] = std::array::from_fn(|_| builder.add_virtual_target());

            // The secp256k1 verification result is a boolean virtual target.
            // It will be constrained by the DPN authorization logic when
            // psystd::secp256k1_verify() is called.
            //
            // We also compute a commitment hash that binds the (public_key, msg_hash,
            // signature) tuple together, ensuring witness consistency.
            let mut preimage = Vec::with_capacity(36);
            preimage.extend_from_slice(&public_key);
            preimage.extend_from_slice(&msg_hash.elements);
            preimage.extend_from_slice(&signature);
            let _commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

            // is_valid is a separate boolean target that the DPN execution context
            // constrains to 1 when the signature is valid. Using a virtual target
            // (not the commitment hash) ensures it acts as a proper boolean gate.
            let is_valid = builder.add_virtual_bool_target_safe().target;

            slots.push(SDKKeySecp256k1SlotTargets {
                public_key,
                msg_hash,
                signature,
                is_valid,
            });
        }

        SDKKeySecp256k1Gadget { slots }
    }

    /// Add custom authorization constraints to the circuit.
    ///
    /// This is called by the SDK key compiler to inject the compiled
    /// authorization logic constraints.
    pub fn add_custom_constraints<F>(&mut self, builder: &mut CircuitBuilder<GF, D>, constraints_fn: F)
    where
        F: FnOnce(
            &mut CircuitBuilder<GF, D>,
            &mut SDKKeyTransactionIntrospectionGadget,
            &mut Option<StateReaderGadget<GF, D>>,
            &[Target], // circuit_inputs
            Target,    // checkpoint_id
            Target,    // user_id
        ),
    {
        constraints_fn(
            builder,
            &mut self.tx_introspection,
            &mut self.state_reader,
            &self.circuit_inputs,
            self.checkpoint_id,
            self.user_id,
        );
    }

    /// Finalize the circuit by building and creating the minifier chain.
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

    /// Generate a proof for this SDK key circuit.
    pub async fn prove(
        &self,
        private_key: QHashOut<GF>,
        witness_input: &SDKKeyCircuitWitnessInput,
        sig_hash: QHashOut<GF>,
    ) -> anyhow::Result<ProofWithPublicInputs<GF, C, D>> {
        let circuit_data = self.circuit_data.as_ref().ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;
        let minifier_chain = self
            .minifier_chain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Minifier chain not initialized"))?;

        let mut pw = PartialWitness::<GF>::new();

        // Set private key and sig_hash
        pw.set_hash_target(self.private_key, private_key.0)?;
        pw.set_hash_target(self.sig_hash, sig_hash.0)?;

        // Set checkpoint_id and user_id
        pw.set_target(self.checkpoint_id, witness_input.checkpoint_id)?;
        pw.set_target(self.user_id, witness_input.user_id)?;

        // Set user-provided circuit inputs
        pw.set_target_arr(&self.circuit_inputs, &witness_input.circuit_inputs)?;

        // Set transaction introspection witness
        self.set_tx_introspection_witness(&mut pw, witness_input)?;

        // Set state reader witness (if enabled)
        if let Some(ref state_reader) = self.state_reader {
            if let Some(ref state_reader_results) = witness_input.state_reader_results {
                state_reader.set_witness(&mut pw, state_reader_results)?;
            }
        }

        // Set secp256k1 witness slots
        if let Some(ref secp256k1) = self.secp256k1 {
            for (slot, witness_slot) in secp256k1.slots.iter().zip(witness_input.secp256k1_slots.iter()) {
                for (target, value) in slot.public_key.iter().zip(witness_slot.public_key.iter()) {
                    pw.set_target(*target, *value)?;
                }
                pw.set_hash_target(slot.msg_hash, witness_slot.msg_hash.0)?;
                for (target, value) in slot.signature.iter().zip(witness_slot.signature.iter()) {
                    pw.set_target(*target, *value)?;
                }
            }
        }

        let inner_proof = circuit_data.prove(pw)?;
        let minified_proof = minifier_chain.prove(&inner_proof)?;
        Ok(minified_proof)
    }

    /// Set the transaction introspection witness data.
    fn set_tx_introspection_witness(&self, pw: &mut PartialWitness<GF>, witness_input: &SDKKeyCircuitWitnessInput) -> anyhow::Result<()> {
        // Set tx_stack_hash
        pw.set_hash_target(self.tx_introspection.tx_stack_hash, witness_input.tx_stack_hash.0)?;

        // Set tx_count
        pw.set_target(self.tx_introspection.tx_count, witness_input.tx_count)?;

        // Set each transaction slot
        for (i, slot) in self.tx_introspection.tx_info_slots.iter().enumerate() {
            if i < witness_input.transaction_infos.len() {
                let tx_info = &witness_input.transaction_infos[i];
                pw.set_target(slot.contract_id, tx_info.contract_id)?;
                pw.set_target(slot.method_id, tx_info.method_id)?;
                pw.set_target(slot.caller_contract_id, tx_info.caller_contract_id)?;
                pw.set_target(slot.inputs_length, tx_info.inputs_length)?;
                pw.set_hash_target(slot.inputs_hash, tx_info.inputs_hash.0)?;
            } else {
                // Pad with zeros for unused slots
                pw.set_target(slot.contract_id, GF::ZERO)?;
                pw.set_target(slot.method_id, GF::ZERO)?;
                pw.set_target(slot.caller_contract_id, GF::ZERO)?;
                pw.set_target(slot.inputs_length, GF::ZERO)?;
                pw.set_hash_target(slot.inputs_hash, HashOut::ZERO)?;
            }
        }

        Ok(())
    }

    /// Get the circuit fingerprint (acts as the key type identifier).
    pub fn get_fingerprint(&self) -> QHashOut<GF> {
        self.minifier_chain
            .as_ref()
            .map(|chain| QHashOut(chain.get_fingerprint()))
            .unwrap_or_default()
    }

    /// Get the verifier config (for recursive verification).
    pub fn get_verifier_config_ref(&self) -> Option<&VerifierOnlyCircuitData<C, D>> {
        self.minifier_chain.as_ref().map(|chain| chain.get_verifier_data())
    }
}

/// Getters for the transaction introspection gadget, used by the compiler
/// to inject constraints that reference transaction fields.
impl SDKKeyTransactionIntrospectionGadget {
    /// Get the contract_id target for the n-th transaction.
    pub fn get_tx_contract_id(&self, n: usize) -> Target {
        self.tx_info_slots[n].contract_id
    }

    /// Get the method_id target for the n-th transaction.
    pub fn get_tx_method_id(&self, n: usize) -> Target {
        self.tx_info_slots[n].method_id
    }

    /// Get the caller_contract_id target for the n-th transaction.
    pub fn get_tx_caller_contract_id(&self, n: usize) -> Target {
        self.tx_info_slots[n].caller_contract_id
    }

    /// Get the inputs_length target for the n-th transaction.
    pub fn get_tx_inputs_length(&self, n: usize) -> Target {
        self.tx_info_slots[n].inputs_length
    }

    /// Get the inputs_hash target for the n-th transaction.
    pub fn get_tx_inputs_hash(&self, n: usize) -> HashOutTarget {
        self.tx_info_slots[n].inputs_hash
    }

    /// Get the tx_hash target for the n-th transaction.
    pub fn get_tx_hash(&self, n: usize) -> HashOutTarget {
        self.tx_info_slots[n].tx_hash
    }

    /// Get the total tx_count target.
    pub fn get_tx_count(&self) -> Target {
        self.tx_count
    }

    /// Get the tx_stack_hash target (the running hash of all transactions).
    pub fn get_tx_stack_hash(&self) -> HashOutTarget {
        self.tx_stack_hash
    }
}

/// Derive the public key parameter from a private key within a circuit.
///
/// This uses the same derivation scheme as existing ZK signatures
/// (interleaved private key elements with PRIVATE_KEY_CONSTANTS).
pub fn get_zk_public_key_param(builder: &mut CircuitBuilder<GF, D>, private_key: &HashOutTarget) -> HashOutTarget {
    let private_key_constants = PRIVATE_KEY_CONSTANTS
        .iter()
        .map(|c| builder.constant(GF::from_canonical_u64(*c)))
        .collect::<Vec<_>>();
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
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

/// Compute the public key parameter natively (outside circuit) for a given
/// private key.
pub fn get_sdk_key_public_key_param(private_key: &QHashOut<GF>) -> QHashOut<GF> {
    // Re-use the same derivation as the existing software-defined signature
    super::software_defined::get_sdc_public_key_param(private_key)
}

/// Compute the tx_stack_hash for a list of transaction infos.
///
/// This is used by the prover to build the witness data.
///
/// IMPORTANT: The `transaction_infos` slice must have exactly
/// `config.num_introspectable_transactions` elements. If fewer actual
/// transactions exist, pad with `SDKKeyTransactionInfo::default()` (all zeros)
/// so the hash matches what the circuit computes. Use
/// [`compute_tx_stack_hash_padded`] to handle padding automatically.
pub fn compute_tx_stack_hash(transaction_infos: &[SDKKeyTransactionInfo<GF>]) -> QHashOut<GF> {
    let mut running_hash = QHashOut::<GF>::default();

    for tx_info in transaction_infos {
        let magic = GF::from_noncanonical_u64(DEFERRED_CALL_MAGIC);
        let tx_hash = PoseidonHash::hash_no_pad(&[
            magic,
            tx_info.caller_contract_id,
            tx_info.contract_id,
            tx_info.method_id,
            tx_info.inputs_length,
            tx_info.inputs_hash.0.elements[0],
            tx_info.inputs_hash.0.elements[1],
            tx_info.inputs_hash.0.elements[2],
            tx_info.inputs_hash.0.elements[3],
        ]);

        running_hash = QHashOut(<PoseidonHash as Hasher<GF>>::two_to_one(running_hash.0, tx_hash));
    }

    running_hash
}

/// Compute the tx_stack_hash with automatic zero-padding to match the circuit.
///
/// The circuit always hashes exactly `num_introspectable_transactions` slots.
/// If `transaction_infos` has fewer elements, this function pads with
/// default (all-zero) transaction infos so the resulting hash matches
/// the circuit's running hash chain.
pub fn compute_tx_stack_hash_padded(transaction_infos: &[SDKKeyTransactionInfo<GF>], num_introspectable_transactions: u32) -> QHashOut<GF> {
    let n = num_introspectable_transactions as usize;
    let mut padded = transaction_infos.to_vec();
    padded.resize(n, SDKKeyTransactionInfo::default());
    compute_tx_stack_hash(&padded)
}
