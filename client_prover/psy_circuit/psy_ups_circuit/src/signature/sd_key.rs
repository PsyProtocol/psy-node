use std::fmt::Debug;

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
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
use psy_client_data::{
    dpn::sd_key::{SDKeyConfig, SDKeyTransactionInfo, SDKEY_MAX_CALLDATA_WORDS, MAX_INTROSPECTABLE_TRANSACTIONS},
    qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeafStats},
};
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
        select::CircuitBuilderSelectHelpers,
    },
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
    proof_minifier::pm_chain::PsyProofMinifierChain,
    traits::{AlgebraicHashableTarget, CreatableTarget},
    u32::gates::comparison::ComparisonGate,
};
use psy_config::network_constants::{DEFAULT_CALLER_CONTRACT_ID_U64, DEFERRED_CALL_MAGIC, GLOBAL_CONTRACT_TREE_HEIGHT, PSY_NETWORK_MAGIC};
use psy_crypto::signature::zk::wallet::PRIVATE_KEY_CONSTANTS;
use psy_dpn_circuit::vm::{
    compile::execute_dpn_function,
    gadgets::state_readers::StateReaderGadget as DPNStateReaderGadget,
    ops::{DPNTransactionContextTargets, DPNTransactionEntryTargets, SimpleDPNBuilder},
};
use psy_network_circuit::{
    gadgets::qdata::{
        checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget, checkpoint_stats::PsyCheckpointLeafStatsGadget, user::PsyUserLeafGadget,
        user_contract_state::SignContextGadget,
    },
    ups::gadgets::ups_signature_data::PsyUserProvingSessionSignatureDataCompactGadget,
};
use psy_vm::{
    dpn::{ops::state_cmd::data::DPNStateCmd, vm::def::DPNFunctionCircuitDefinition},
    ups::sd_key::{SDKeyCircuitWitnessInput, SDKeyDPNStateReaderContext},
};

use crate::signature::state_reader::StateReaderGadget;

type C = PoseidonGoldilocksConfig;
type GF = GoldilocksField;
const D: usize = 2;

/// Gadget for transaction introspection within an SD key circuit.
///
/// Each slot corresponds to a compile-time-constant transaction index.
/// The circuit proves that the transaction info matches the tx_stack_hash
/// chain.
#[derive(Debug)]
pub struct SDKeyTransactionIntrospectionGadget {
    /// Transaction info targets for each introspectable slot.
    pub tx_info_slots: Vec<SDKeyTransactionInfoTargets>,
    /// The tx_stack_hash target (running hash of all transactions).
    pub tx_stack_hash: HashOutTarget,
    /// Transaction count target.
    pub tx_count: Target,
}

/// Plonky2 targets for a single transaction's introspectable info.
#[derive(Debug, Clone)]
pub struct SDKeyTransactionInfoTargets {
    pub contract_id: Target,
    pub method_id: Target,
    pub caller_contract_id: Target,
    pub inputs_length: Target,
    pub inputs_hash: HashOutTarget,
    /// The hash of this transaction's compact call data.
    pub tx_hash: HashOutTarget,
    /// Raw input field elements for this transaction, up to
    /// `max_inputs_per_tx`. These are bound to `inputs_hash` by the circuit.
    pub inputs: Vec<Target>,
}

/// Gadget for secp256k1 signature verification slots within an SD key circuit.
#[derive(Debug)]
pub struct SDKeySecp256k1Gadget {
    pub slots: Vec<SDKeySecp256k1SlotTargets>,
}

/// Targets for a single secp256k1 verification slot.
#[derive(Debug, Clone)]
pub struct SDKeySecp256k1SlotTargets {
    pub public_key: [Target; 16],
    pub msg_hash: HashOutTarget,
    pub signature: [Target; 16],
    /// Result of verification (boolean target).
    pub is_valid: Target,
}

#[derive(Debug, Clone)]
pub struct SDKeyDPNStateReaderContextTargets {
    pub user_contract_tree_state_root: HashOutTarget,
    pub deferred_tx_tree_root: HashOutTarget,
    pub session_proof_tree_root: HashOutTarget,
    pub checkpoint_tree_root: HashOutTarget,
    pub chain_state_roots: PsyCheckpointGlobalStateRootsGadget,
    pub checkpoint_stats: PsyCheckpointLeafStatsGadget,
}

#[derive(Debug, Clone)]
pub struct SDKeySignatureContextTargets {
    pub signature_data: PsyUserProvingSessionSignatureDataCompactGadget,
    pub current_user_leaf: PsyUserLeafGadget,
    pub nonce: Target,
    pub checkpoint_tree_root: HashOutTarget,
}

/// The main SD key circuit gadget.
///
/// This circuit proves that a user's custom authorization logic is satisfied.
/// It combines:
/// - Private key derivation (same as existing ZK signatures)
/// - Transaction introspection (read n-th tx info for compile-time-constant n)
/// - State reading at current checkpoint
/// - Secp256k1 signature verification
///
/// Public output: hash(sig_hash, public_key_param)
/// This matches the existing signature format so SD keys are drop-in
/// compatible with the existing UPS end-cap signature verification.
#[derive(Debug)]
pub struct SDKeyCircuitGadget {
    /// Configuration for this SD key.
    pub config: SDKeyConfig,

    /// Transaction introspection gadget.
    pub tx_introspection: SDKeyTransactionIntrospectionGadget,

    /// Legacy fixed-policy SDKey reader. Programmable SDKeys force
    /// `can_read_state = false` before `add_virtual_to` and therefore never
    /// instantiate this together with `dpn_state_reader`.
    pub state_reader: Option<StateReaderGadget<GF, D>>,

    /// DPN VM state reader used exclusively by programmable SDKey functions.
    pub dpn_state_reader: Option<DPNStateReaderGadget>,

    /// Definition used to order and decode DPN state command witnesses.
    pub dpn_state_reader_definition: Option<DPNFunctionCircuitDefinition>,

    pub dpn_state_reader_context: Option<SDKeyDPNStateReaderContextTargets>,

    /// UPS signature preimage targets used to anchor programmable state reads.
    pub signature_context: Option<SDKeySignatureContextTargets>,

    /// Authenticates start_contract_state_root in the signed user contract
    /// tree.
    pub contract_state_root_proof: Option<MerkleProofGadget>,

    /// Secp256k1 verification gadget.
    pub secp256k1: Option<SDKeySecp256k1Gadget>,

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

    /// Start contract state tree root target (meaningful when state reading is
    /// enabled).
    pub start_contract_state_root: HashOutTarget,

    /// Maximum number of input field elements per transaction that are placed
    /// in the witness and bound to `inputs_hash`.
    pub max_inputs_per_tx: u32,

    /// Built circuit data (populated after build_circuit).
    pub circuit_data: Option<CircuitData<GF, C, D>>,

    /// Proof minifier chain (populated after build_circuit).
    pub minifier_chain: Option<PsyProofMinifierChain<D, GF, C>>,
}

impl SDKeyCircuitGadget {
    /// Create a new SD key circuit gadget and add all virtual targets to the
    /// builder.
    ///
    /// The `input_len` is the number of user-provided circuit inputs
    /// (parameters to the authorization function, excluding self/ctx).
    ///
    /// `max_inputs_per_tx` controls how many calldata field elements are
    /// available to a programmable DPN authorization function.
    pub fn add_virtual_to(builder: &mut CircuitBuilder<GF, D>, config: &SDKeyConfig, input_len: usize, max_inputs_per_tx: u32) -> Self {
        let max_inputs_per_tx = max_inputs_per_tx.min(SDKEY_MAX_CALLDATA_WORDS);
        let private_key = builder.add_virtual_hash();
        let sig_hash = builder.add_virtual_hash();
        let checkpoint_id = builder.add_virtual_target();
        let user_id = builder.add_virtual_target();
        let circuit_inputs = builder.add_virtual_targets(input_len);

        // Transaction introspection
        let tx_introspection = Self::build_tx_introspection(builder, config, max_inputs_per_tx);

        // State reader (optional)
        let (state_reader, start_contract_state_root) = if config.can_read_state {
            let reader = StateReaderGadget::new(builder, config.contract_state_tree_height);

            // Bind the state reader's identity fields to the circuit's existing
            // targets so the witness cannot inject an arbitrary state root.
            builder.connect(reader.state.checkpoint_id, checkpoint_id);
            builder.connect(reader.state.user_leaf.user_id, user_id);
            let expected_contract_id = builder.constant(GF::from_canonical_u64(config.contract_id));
            builder.connect(reader.state.contract_id, expected_contract_id);

            let start_contract_state_root = reader.state.start_contract_state_root;

            (Some(reader), start_contract_state_root)
        } else {
            let zero_root = builder.add_virtual_hash();
            (None, zero_root)
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
            dpn_state_reader: None,
            dpn_state_reader_definition: None,
            dpn_state_reader_context: None,
            signature_context: None,
            contract_state_root_proof: None,
            secp256k1,
            circuit_inputs,
            private_key,
            sig_hash,
            checkpoint_id,
            user_id,
            start_contract_state_root,
            max_inputs_per_tx,
            circuit_data: None,
            minifier_chain: None,
        }
    }

    /// Build the transaction introspection sub-circuit.
    ///
    /// For each introspectable transaction slot, we:
    /// 1. Add virtual targets for the transaction info fields
    /// 2. Compute the transaction hash using the compact DPN transaction hash
    ///    format
    /// 3. Build and constrain the tx_stack_hash chain
    /// 4. Optionally expose and bind the raw input elements for parameter
    ///    constraints.
    fn build_tx_introspection(
        builder: &mut CircuitBuilder<GF, D>,
        config: &SDKeyConfig,
        max_inputs_per_tx: u32,
    ) -> SDKeyTransactionIntrospectionGadget {
        assert!(
            config.num_introspectable_transactions <= MAX_INTROSPECTABLE_TRANSACTIONS,
            "SDKey transaction count exceeds MAX_TX_COUNT"
        );
        let n = config.num_introspectable_transactions as usize;
        let max_inputs = max_inputs_per_tx.min(SDKEY_MAX_CALLDATA_WORDS) as usize;
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
            let inputs = builder.add_virtual_targets(max_inputs);

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

            // Bind inputs_hash to the actual input witness. This lets the
            // circuit enforce business-level constraints on individual input
            // fields while still proving they belong to the signed tx_stack.
            if max_inputs > 0 {
                Self::bind_inputs_hash_to_inputs(builder, inputs_length, &inputs, inputs_hash);
            }

            tx_info_slots.push(SDKeyTransactionInfoTargets {
                contract_id,
                method_id,
                caller_contract_id,
                inputs_length,
                inputs_hash,
                tx_hash,
                inputs,
            });
        }

        // Constrain that our computed chain matches the provided tx_stack_hash
        if n > 0 {
            builder.connect_hashes(running_hash, tx_stack_hash);
        }

        SDKeyTransactionIntrospectionGadget {
            tx_info_slots,
            tx_stack_hash,
            tx_count,
        }
    }

    /// Bind a transaction's `inputs_hash` to the provided raw `inputs` witness.
    ///
    /// The DPN `safe_hash_fixed_length` is `hash(len, input[0..len], len)`.
    /// Because `len` is a witness, we precompute the hash for every possible
    /// length `0..=max_inputs` and use a multiplexer to select the one matching
    /// `inputs_length`. We additionally constrain `inputs_length` to be exactly
    /// one of those values.
    fn bind_inputs_hash_to_inputs(builder: &mut CircuitBuilder<GF, D>, inputs_length: Target, inputs: &[Target], inputs_hash: HashOutTarget) {
        let max_inputs = inputs.len();
        let zero = builder.zero();

        // Precompute candidate hashes for every allowed length.
        let mut candidates = Vec::with_capacity(max_inputs + 1);
        for len in 0..=max_inputs {
            let len_target = builder.constant(GF::from_canonical_u64(len as u64));
            let mut preimage = Vec::with_capacity(len + 2);
            preimage.push(len_target);
            preimage.extend_from_slice(&inputs[..len]);
            preimage.push(len_target);
            candidates.push(builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage));
        }

        // Build a one-hot selector from inputs_length.
        let mut selected_hash = candidates[0];
        let mut any_match = builder._false();
        let mut weighted_sum = zero;

        for len in 0..=max_inputs {
            let len_target = builder.constant(GF::from_canonical_u64(len as u64));
            let is_len = builder.is_equal(inputs_length, len_target);
            selected_hash = builder.select_hash(is_len, candidates[len], selected_hash);
            any_match = builder.or(any_match, is_len);
            let product = builder.mul(len_target, is_len.target);
            weighted_sum = builder.add(weighted_sum, product);
        }

        builder.assert_one(any_match.target);
        builder.connect(weighted_sum, inputs_length);
        builder.connect_hashes(selected_hash, inputs_hash);
    }

    /// Build secp256k1 signature verification slots.
    fn build_secp256k1_slots(builder: &mut CircuitBuilder<GF, D>, num_slots: u32) -> SDKeySecp256k1Gadget {
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

            slots.push(SDKeySecp256k1SlotTargets {
                public_key,
                msg_hash,
                signature,
                is_valid,
            });
        }

        SDKeySecp256k1Gadget { slots }
    }

    /// Add custom authorization constraints to the circuit.
    ///
    /// This is called by the SD key compiler to inject the compiled
    /// authorization logic constraints.
    pub fn add_custom_constraints<F>(&mut self, builder: &mut CircuitBuilder<GF, D>, constraints_fn: F)
    where
        F: FnOnce(
            &mut CircuitBuilder<GF, D>,
            &mut SDKeyTransactionIntrospectionGadget,
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

    /// Build an SD key circuit from a compiled DPN view function.
    ///
    /// The DPN function's inputs are wired from the SDKey `circuit_inputs`
    /// vector. Its boolean outputs are constrained to be true. Write state
    /// commands are rejected because SD keys are read-only authorization
    /// circuits.
    pub fn build_from_dpn_function(definition: &DPNFunctionCircuitDefinition, sd_config: &SDKeyConfig) -> anyhow::Result<Self> {
        definition.validate_sd_key_read_only()?;
        for def in &definition.definitions {
            // The standard UPS endcap sighash does not commit to the pre-sign
            // proof-tree root. Keep this opcode unavailable until that root is
            // added to the endcap signature protocol (or recursively bound).
            anyhow::ensure!(
                !matches!(
                    def.op_type,
                    psy_vm::dpn::ops::op_types::DPNOpType::GetSessionProofTreeRoot
                ),
                "programmable SDKey does not expose an authenticated value for {:?}; use transaction introspection opcodes or signed SDKey context fields",
                def.op_type
            );
        }

        anyhow::ensure!(
            sd_config.num_introspectable_transactions <= MAX_INTROSPECTABLE_TRANSACTIONS,
            "SDKey transaction count {} exceeds MAX_TX_COUNT {}",
            sd_config.num_introspectable_transactions,
            MAX_INTROSPECTABLE_TRANSACTIONS
        );

        let input_len = definition.circuit_inputs.iter().max().map(|idx| *idx as usize + 1).unwrap_or(0);
        let uses_nonce = definition
            .definitions
            .iter()
            .any(|definition| definition.op_type == psy_vm::dpn::ops::op_types::DPNOpType::GetNonce);

        let mut effective_sd_config = sd_config.clone();
        // Programmable DPN functions use the VM StateReaderGadget below, not
        // the fixed-policy reader owned by add_virtual_to.
        effective_sd_config.can_read_state = false;
        if !definition.state_commands.is_empty() && effective_sd_config.contract_state_tree_height == 0 {
            anyhow::bail!("SDKey DPN authorization function has state reads but contract_state_tree_height is 0");
        }

        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<GF, D>::new(config);

        // Programmable DPN authorization functions can inspect the complete
        // bounded calldata of every preceding transaction.
        let mut gadget = Self::add_virtual_to(&mut builder, &effective_sd_config, input_len, SDKEY_MAX_CALLDATA_WORDS);

        if definition.state_commands.is_empty() && !uses_nonce {
            let nonce = builder.zero();
            gadget.add_dpn_function_constraints_shared(&mut builder, definition, None, nonce)?;
            gadget.build_circuit(builder)?;
            return Ok(gadget);
        }

        let context_targets = (!definition.state_commands.is_empty()).then(|| SDKeyDPNStateReaderContextTargets {
            chain_state_roots: PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder),
            user_contract_tree_state_root: builder.add_virtual_hash(),
            deferred_tx_tree_root: builder.add_virtual_hash(),
            session_proof_tree_root: builder.add_virtual_hash(),
            checkpoint_stats: PsyCheckpointLeafStatsGadget::create_virtual(&mut builder),
            checkpoint_tree_root: builder.add_virtual_hash(),
        });
        let current_user_leaf = PsyUserLeafGadget::create_virtual(&mut builder);
        let nonce = builder.add_virtual_target();
        builder.connect(current_user_leaf.nonce, nonce);
        builder.connect(current_user_leaf.user_id, gadget.user_id);
        if let Some(context_targets) = context_targets.as_ref() {
            builder.connect_hashes(current_user_leaf.user_state_tree_root, context_targets.user_contract_tree_state_root);
            let contract_state_root_proof =
                MerkleProofGadget::add_virtual_to::<PoseidonHash, GF, D>(&mut builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
            builder.connect_hashes(contract_state_root_proof.root, context_targets.user_contract_tree_state_root);
            builder.connect_hashes(contract_state_root_proof.value, gadget.start_contract_state_root);
            let configured_contract_id = builder.constant(GF::from_canonical_u64(sd_config.contract_id));
            builder.connect(contract_state_root_proof.index, configured_contract_id);
            gadget.contract_state_root_proof = Some(contract_state_root_proof);
        }

        let signature_data = PsyUserProvingSessionSignatureDataCompactGadget::new_from_known(
            builder.add_virtual_hash(),
            current_user_leaf.to_hash::<PoseidonHash, GF, D>(&mut builder),
            builder.add_virtual_hash(),
            gadget.tx_introspection.tx_stack_hash,
            gadget.tx_introspection.tx_count,
        );
        if let Some(context_targets) = context_targets.as_ref() {
            let state_roots_hash = context_targets.chain_state_roots.to_hash_target::<PoseidonHash, GF, D>(&mut builder);
            let checkpoint_stats_hash = context_targets.checkpoint_stats.to_hash_target::<PoseidonHash, GF, D>(&mut builder);
            let checkpoint_leaf_hash = builder.hash_two_to_one::<PoseidonHash>(state_roots_hash, checkpoint_stats_hash);
            builder.connect_hashes(signature_data.checkpoint_leaf_hash, checkpoint_leaf_hash);
        }
        let checkpoint_tree_root = context_targets
            .as_ref()
            .map(|context| context.checkpoint_tree_root)
            .unwrap_or_else(|| builder.add_virtual_hash());
        let sign_context = SignContextGadget {
            checkpoint_tree_root,
            user_leaf: current_user_leaf,
        };
        let bound_sighash = signature_data
            .get_sig_action_with_user_info::<PoseidonHash, GF, D>(&mut builder, PSY_NETWORK_MAGIC, gadget.user_id, nonce, &sign_context)
            .sig_action_hash;
        builder.connect_hashes(bound_sighash, gadget.sig_hash);
        gadget.signature_context = Some(SDKeySignatureContextTargets {
            signature_data,
            current_user_leaf,
            nonce,
            checkpoint_tree_root,
        });
        if let Some(context_targets) = context_targets {
            let mut dpn_state_reader = DPNStateReaderGadget::new(
                context_targets.chain_state_roots,
                context_targets.user_contract_tree_state_root,
                context_targets.deferred_tx_tree_root,
                gadget.start_contract_state_root,
                effective_sd_config.contract_state_tree_height as usize,
                context_targets.session_proof_tree_root,
                0,
                false,
                context_targets.checkpoint_stats,
                context_targets.checkpoint_tree_root,
            );
            gadget.dpn_state_reader_context = Some(context_targets);
            gadget.add_dpn_function_constraints_shared(&mut builder, definition, Some(&mut dpn_state_reader), nonce)?;
            gadget.dpn_state_reader = Some(dpn_state_reader);
            gadget.dpn_state_reader_definition = Some(definition.clone());
        } else {
            gadget.add_dpn_function_constraints_shared(&mut builder, definition, None, nonce)?;
        }
        gadget.build_circuit(builder)?;
        Ok(gadget)
    }

    /// Add constraints for a compiled DPN authorization function.
    ///
    /// Stateless DPN definitions use the exact VM definition executor shared
    /// with normal CFC circuits. This keeps operation ordering and assertion
    /// semantics identical across the two circuit families.
    fn add_dpn_function_constraints_shared(
        &mut self,
        builder: &mut CircuitBuilder<GF, D>,
        definition: &DPNFunctionCircuitDefinition,
        state_reader: Option<&mut DPNStateReaderGadget>,
        nonce: Target,
    ) -> anyhow::Result<()> {
        let public_key_param = get_zk_public_key_param(builder, &self.private_key);
        let contract_id = builder.constant(GF::from_canonical_u64(self.config.contract_id));
        let caller_contract_id = builder.constant(GF::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64));
        let session_proof_tree_root = self
            .dpn_state_reader_context
            .as_ref()
            .map(|context| context.session_proof_tree_root)
            .unwrap_or_else(|| builder.add_virtual_hash());
        let mut dpn = SimpleDPNBuilder::<GF, D>::new_with_contract_ctx(
            self.circuit_inputs.clone(),
            self.user_id,
            contract_id,
            caller_contract_id,
            self.checkpoint_id,
            nonce,
            public_key_param,
            session_proof_tree_root,
        );
        dpn.set_transaction_context(DPNTransactionContextTargets {
            tx_count: self.tx_introspection.tx_count,
            tx_stack_hash: self.tx_introspection.tx_stack_hash,
            entries: self
                .tx_introspection
                .tx_info_slots
                .iter()
                .map(|slot| DPNTransactionEntryTargets {
                    caller_contract_id: slot.caller_contract_id,
                    contract_id: slot.contract_id,
                    method_id: slot.method_id,
                    inputs_length: slot.inputs_length,
                    inputs_hash: slot.inputs_hash,
                    inputs: slot.inputs.clone(),
                })
                .collect(),
        });

        let _ = execute_dpn_function::<PoseidonHash, GF, D>(builder, definition, &mut dpn, state_reader)?;
        for output_id in &definition.circuit_outputs {
            let output = dpn.resolve_bool(builder, *output_id);
            builder.assert_one(output.target);
        }
        Ok(())
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

    /// Generate a proof for this SD key circuit.
    pub async fn prove(
        &self,
        private_key: QHashOut<GF>,
        witness_input: &SDKeyCircuitWitnessInput,
        sig_hash: QHashOut<GF>,
    ) -> anyhow::Result<ProofWithPublicInputs<GF, C, D>> {
        let circuit_data = self.circuit_data.as_ref().ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;
        let minifier_chain = self
            .minifier_chain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Minifier chain not initialized"))?;

        tracing::debug!(
            target: "sd_key_witness",
            circuit_input_count = witness_input.circuit_inputs.len(),
            tx_count = witness_input.tx_count.to_canonical_u64(),
            state_command_count = witness_input.dpn_state_command_witnesses.len(),
            has_state_context = witness_input.dpn_state_reader_context.is_some(),
            "SDKey witness summary"
        );

        let mut pw = PartialWitness::<GF>::new();

        // Set private key and sig_hash
        pw.set_hash_target(self.private_key, private_key.0)?;
        pw.set_hash_target(self.sig_hash, sig_hash.0)?;

        // Set checkpoint_id and user_id
        pw.set_target(self.checkpoint_id, witness_input.checkpoint_id)?;
        pw.set_target(self.user_id, witness_input.user_id)?;

        // Set start contract state tree root
        pw.set_hash_target(self.start_contract_state_root, witness_input.start_contract_state_root.0)?;

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

        if let Some(ref dpn_state_reader) = self.dpn_state_reader {
            let context = witness_input.dpn_state_reader_context.clone().unwrap_or(SDKeyDPNStateReaderContext {
                user_contract_tree_state_root: QHashOut::ZERO,
                deferred_tx_tree_root: QHashOut::ZERO,
                session_proof_tree_root: QHashOut::ZERO,
                checkpoint_tree_root: QHashOut::ZERO,
                chain_state_roots: PsyCheckpointGlobalStateRoots::default(),
                checkpoint_stats: PsyCheckpointLeafStats::default(),
            });
            let context_targets = self
                .dpn_state_reader_context
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing DPN state reader context targets"))?;
            pw.set_hash_target(context_targets.user_contract_tree_state_root, context.user_contract_tree_state_root.0)?;
            pw.set_hash_target(context_targets.deferred_tx_tree_root, context.deferred_tx_tree_root.0)?;
            pw.set_hash_target(context_targets.session_proof_tree_root, context.session_proof_tree_root.0)?;
            pw.set_hash_target(context_targets.checkpoint_tree_root, context.checkpoint_tree_root.0)?;
            context_targets.chain_state_roots.set_witness(&mut pw, &context.chain_state_roots)?;
            context_targets.checkpoint_stats.set_witness(&mut pw, &context.checkpoint_stats)?;
            let contract_state_root_proof = witness_input
                .contract_state_root_proof
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing programmable SDKey contract-state-root inclusion proof"))?;
            self.contract_state_root_proof
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing programmable SDKey contract-state-root proof targets"))?
                .set_witness_core_proof_q_generic(&mut pw, contract_state_root_proof)?;
            let fn_def = self
                .dpn_state_reader_definition
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing DPN state reader definition"))?;
            let fallback_witnesses;
            let command_witnesses = if witness_input.dpn_state_command_witnesses.is_empty() {
                let Some(results) = witness_input.state_reader_results.as_ref() else {
                    anyhow::bail!("missing DPN state command witnesses");
                };
                if results.merkel_proofs.len() != fn_def.state_commands.len()
                    || !fn_def.state_commands.iter().all(|cmd| {
                        matches!(
                            cmd,
                            DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(_) | DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(_)
                        )
                    })
                {
                    anyhow::bail!("DPN state reader requires VM command witnesses for this state command set");
                }
                fallback_witnesses = fn_def
                    .state_commands
                    .iter()
                    .zip(results.merkel_proofs.iter())
                    .map(|(state_cmd, proof)| psy_vm::vm::exec::PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness: psy_client_data::qstore::imm::cmd_processor::DPNStateCmdWitness::MerkleProof(proof.clone()),
                        result: vec![],
                    })
                    .collect::<Vec<_>>();
                &fallback_witnesses
            } else {
                &witness_input.dpn_state_command_witnesses
            };
            dpn_state_reader.set_command_witnesses(&mut pw, command_witnesses, fn_def)?;
        }

        if let Some(signature_targets) = self.signature_context.as_ref() {
            let signature_context = witness_input
                .signature_context
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing signature context for programmable SDKey"))?;
            signature_targets.signature_data.set_witness(&mut pw, &signature_context.signature_data)?;
            signature_targets
                .current_user_leaf
                .set_witness(&mut pw, &signature_context.current_user_leaf)?;
            pw.set_target(signature_targets.nonce, signature_context.nonce)?;
            pw.set_hash_target(signature_targets.checkpoint_tree_root, signature_context.checkpoint_tree_root.0)?;
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
    fn set_tx_introspection_witness(&self, pw: &mut PartialWitness<GF>, witness_input: &SDKeyCircuitWitnessInput) -> anyhow::Result<()> {
        let expected_count = self.tx_introspection.tx_info_slots.len();
        anyhow::ensure!(
            witness_input.transaction_infos.len() == expected_count,
            "SDKey circuit expects {} transaction infos, witness has {}",
            expected_count,
            witness_input.transaction_infos.len()
        );
        anyhow::ensure!(
            witness_input.transaction_inputs.len() == expected_count,
            "SDKey circuit expects {} transaction input vectors, witness has {}",
            expected_count,
            witness_input.transaction_inputs.len()
        );
        anyhow::ensure!(
            witness_input.tx_count.to_canonical_u64() == expected_count as u64,
            "SDKey circuit expects tx_count {}, witness has {}",
            expected_count,
            witness_input.tx_count.to_canonical_u64()
        );
        // Set tx_stack_hash
        pw.set_hash_target(self.tx_introspection.tx_stack_hash, witness_input.tx_stack_hash.0)?;

        // Set tx_count
        pw.set_target(self.tx_introspection.tx_count, witness_input.tx_count)?;

        // Set each transaction slot
        for (i, slot) in self.tx_introspection.tx_info_slots.iter().enumerate() {
            let tx_info = &witness_input.transaction_infos[i];
            pw.set_target(slot.contract_id, tx_info.contract_id)?;
            pw.set_target(slot.method_id, tx_info.method_id)?;
            pw.set_target(slot.caller_contract_id, tx_info.caller_contract_id)?;
            pw.set_target(slot.inputs_length, tx_info.inputs_length)?;
            pw.set_hash_target(slot.inputs_hash, tx_info.inputs_hash.0)?;

            // Set raw input witnesses, padding with zeros if fewer than the
            // circuit capacity are provided.
            let provided_inputs = witness_input.transaction_inputs[i].as_slice();
            let declared_length = tx_info.inputs_length.to_canonical_u64() as usize;
            if declared_length > SDKEY_MAX_CALLDATA_WORDS as usize || provided_inputs.len() != declared_length {
                anyhow::bail!("transaction {} calldata length does not match inputs_length or MAX_CALLDATA_WORDS", i);
            }
            for (j, input_target) in slot.inputs.iter().enumerate() {
                let value = provided_inputs.get(j).copied().unwrap_or(GF::ZERO);
                pw.set_target(*input_target, value)?;
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
impl SDKeyTransactionIntrospectionGadget {
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

    /// Get the raw input target at `(tx_index, input_index)`.
    pub fn get_tx_input(&self, tx_index: usize, input_index: usize) -> Option<Target> {
        self.tx_info_slots.get(tx_index).and_then(|slot| slot.inputs.get(input_index)).copied()
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
pub fn get_sd_key_public_key_param(private_key: &QHashOut<GF>) -> QHashOut<GF> {
    // Re-use the same derivation as the existing software-defined signature
    super::software_defined::get_sdc_public_key_param(private_key)
}

/// Compute the tx_stack_hash for a list of transaction infos.
///
/// This is used by the prover to build the witness data.
///
/// The slice must contain exactly the transactions configured for the circuit;
/// unused/padded transaction slots are not part of the SDKey stack semantics.
pub fn compute_tx_stack_hash(transaction_infos: &[SDKeyTransactionInfo<GF>]) -> QHashOut<GF> {
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use plonky2::field::types::Field;
    use psy_client_common::data::qhashout::QHashOut;
    use psy_client_data::{
        dpn::sd_key::SDKeyTransactionInfo,
        qdata::{
            checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeafStats},
            ups_signature::PsyUserProvingSessionSignatureDataCompact,
            user::PsyUserLeaf,
            user_contract_state::{SignContext, UserContractState},
        },
    };
    use psy_crypto::hash::{
        merkle::utils::simple_merkle_tree::SimpleMerkleTree,
        traits::{
            hasher::{FieldQHasher, PoseidonHasher},
            qhashable::QFieldHashable,
        },
        utils::safe_hash_fixed_length,
    };
    use psy_vm::{
        dpn::{
            ops::{
                op_types::{encode_indexed_op_id, DPNAssertEqInfoIndexed, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType},
                state_cmd::data::{
                    DPNStateCmd, DPNStateCmdGetSelfUserCurrentContractStateSlotHash, DPNStateCmdGetSelfUserCurrentContractStateSlotSingle,
                },
            },
            vm::def::DPNFunctionCircuitDefinition,
        },
        ups::{
            sd_key::{SDKeyCircuitWitnessInput, SDKeyDPNStateReaderContext, SDKeySignatureContext},
            state_reader::StateReaderResults,
        },
    };

    use super::{
        compute_tx_stack_hash, SDKeyCircuitGadget, SDKeyConfig, DEFAULT_CALLER_CONTRACT_ID_U64, GLOBAL_CONTRACT_TREE_HEIGHT, PSY_NETWORK_MAGIC,
        SDKEY_MAX_CALLDATA_WORDS, MAX_INTROSPECTABLE_TRANSACTIONS,
    };

    type GF = plonky2::field::goldilocks_field::GoldilocksField;

    fn make_tx_info(contract_id: u64, method_id: u32, inputs: &[u64]) -> (SDKeyTransactionInfo<GF>, Vec<GF>) {
        let input_felts = inputs.iter().map(|v| GF::from_noncanonical_u64(*v)).collect::<Vec<_>>();
        let inputs_hash = safe_hash_fixed_length::<psy_crypto::hash::traits::hasher::PoseidonHasher, GF>(&input_felts);
        (
            SDKeyTransactionInfo {
                contract_id: GF::from_canonical_u64(contract_id),
                method_id: GF::from_canonical_u32(method_id),
                caller_contract_id: GF::ZERO,
                inputs_length: GF::from_canonical_u64(inputs.len() as u64),
                inputs_hash,
            },
            input_felts,
        )
    }

    fn build_witness(
        transaction_infos: Vec<SDKeyTransactionInfo<GF>>,
        transaction_inputs: Vec<Vec<GF>>,
        num_introspectable_transactions: u32,
    ) -> SDKeyCircuitWitnessInput {
        build_witness_with_state(
            transaction_infos,
            transaction_inputs,
            num_introspectable_transactions,
            None,
            QHashOut::default(),
        )
    }

    fn build_witness_with_state(
        transaction_infos: Vec<SDKeyTransactionInfo<GF>>,
        transaction_inputs: Vec<Vec<GF>>,
        num_introspectable_transactions: u32,
        state_reader_results: Option<StateReaderResults<GF>>,
        start_contract_state_root: QHashOut<GF>,
    ) -> SDKeyCircuitWitnessInput {
        assert_eq!(transaction_infos.len(), num_introspectable_transactions as usize);
        let tx_stack_hash = compute_tx_stack_hash(&transaction_infos);
        let (checkpoint_id, user_id) = state_reader_results
            .as_ref()
            .map_or((GF::ZERO, GF::ZERO), |r| (r.state.checkpoint_id, r.state.user_leaf.user_id));
        SDKeyCircuitWitnessInput {
            circuit_inputs: vec![],
            transaction_infos,
            transaction_inputs,
            tx_stack_hash,
            tx_count: GF::from_canonical_u64(num_introspectable_transactions as u64),
            state_reader_results,
            dpn_state_command_witnesses: vec![],
            dpn_state_reader_context: None,
            signature_context: None,
            contract_state_root_proof: None,
            start_contract_state_root,
            secp256k1_slots: vec![],
            checkpoint_id,
            user_id,
        }
    }

    fn make_state_reader_results(
        contract_id: u64,
        contract_state_tree_height: u8,
        checkpoint_id: u64,
        user_id: u64,
        slot_values: &[(u64, u64)],
    ) -> StateReaderResults<GF> {
        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<GF>>::new(contract_state_tree_height);

        let slot_indices: HashSet<u64> = slot_values.iter().map(|(sub, _)| sub / 4).collect();
        for slot_index in slot_indices {
            tree.set_leaf(slot_index, QHashOut::default());
        }
        for (sub_slot_index, value) in slot_values {
            let slot_index = sub_slot_index / 4;
            let offset = (sub_slot_index % 4) as usize;
            let mut current = tree.get_leaf_value(slot_index);
            current.0.elements[offset] = GF::from_noncanonical_u64(*value);
            tree.set_leaf(slot_index, current);
        }

        let root = tree.get_root();
        let user_leaf = PsyUserLeaf::new_user_default(GF::from_canonical_u64(user_id), QHashOut::default(), root);
        let state = UserContractState::new(
            QHashOut::default(),
            user_leaf,
            root,
            GF::from_canonical_u64(contract_id),
            GF::from_canonical_u64(checkpoint_id),
        );

        let mut merkel_proofs = Vec::new();
        let mut state_cmds = Vec::new();
        for (sub_slot_index, _) in slot_values {
            let slot_index = sub_slot_index / 4;
            let proof = tree.get_leaf(slot_index);
            merkel_proofs.push(proof);
            state_cmds.push(DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(
                DPNStateCmdGetSelfUserCurrentContractStateSlotHash {
                    slot_index: GF::from_canonical_u64(slot_index),
                },
            ));
        }

        StateReaderResults {
            state,
            state_cmds,
            merkel_proofs,
        }
    }

    fn dummy_private_key() -> QHashOut<GF> {
        QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                GF::from_canonical_u64(0x1234567890abcdef),
                GF::from_canonical_u64(0xfedcba0987654321),
                GF::from_canonical_u64(0xaabbccdd11223344),
                GF::from_canonical_u64(0x55667788ddeeff00),
            ],
        })
    }

    fn dummy_sighash() -> QHashOut<GF> {
        QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                GF::from_canonical_u64(0x1111111111111111),
                GF::from_canonical_u64(0x2222222222222222),
                GF::from_canonical_u64(0x3333333333333333),
                GF::from_canonical_u64(0x4444444444444444),
            ],
        })
    }

    fn build_dpn_greater_than_100_function() -> DPNFunctionCircuitDefinition {
        let input_target_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 0);
        let constant_100_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 1);
        let result_bool_id = encode_indexed_op_id(DPNBuiltInDataType::Bool, 0);

        DPNFunctionCircuitDefinition {
            name: "greater_than_100".to_string(),
            method_id: 0,
            circuit_inputs: vec![0],
            circuit_outputs: vec![result_bool_id],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            definitions: vec![
                // input[0] -> target[0]
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 0,
                    op_type: DPNOpType::InputTarget,
                    inputs: vec![0],
                },
                // constant 100 -> target[1]
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 1,
                    op_type: DPNOpType::Constant,
                    inputs: vec![100],
                },
                // target[0] > target[1] -> bool[0]
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Bool,
                    index: 0,
                    op_type: DPNOpType::Gt,
                    inputs: vec![input_target_id, constant_100_id],
                },
            ],
            events: vec![],
        }
    }

    fn build_dpn_witness(circuit_inputs: Vec<GF>) -> SDKeyCircuitWitnessInput {
        SDKeyCircuitWitnessInput {
            circuit_inputs,
            transaction_infos: vec![],
            transaction_inputs: vec![],
            tx_stack_hash: QHashOut::default(),
            tx_count: GF::ZERO,
            state_reader_results: None,
            dpn_state_command_witnesses: vec![],
            dpn_state_reader_context: None,
            signature_context: None,
            contract_state_root_proof: None,
            start_contract_state_root: QHashOut::default(),
            secp256k1_slots: vec![],
            checkpoint_id: GF::ZERO,
            user_id: GF::ZERO,
        }
    }

    #[test]
    fn dpn_function_rejects_session_proof_tree_root_introspection() {
        let definition = DPNFunctionCircuitDefinition {
            name: "session_proof_tree_root_is_not_authenticated".to_string(),
            method_id: 0,
            circuit_inputs: vec![],
            circuit_outputs: vec![],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            definitions: vec![DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::HashOut,
                index: 0,
                op_type: DPNOpType::GetSessionProofTreeRoot,
                inputs: vec![],
            }],
            events: vec![],
        };
        let config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 0,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 0,
        };

        let error = SDKeyCircuitGadget::build_from_dpn_function(&definition, &config).unwrap_err();
        assert!(error.to_string().contains("GetSessionProofTreeRoot"));
    }

    #[tokio::test]
    async fn dpn_function_uses_authenticated_contract_caller_and_nonce() {
        let contract_id = 42;
        let nonce = 7;
        let definition = DPNFunctionCircuitDefinition {
            name: "authenticated_sdkey_context".to_string(),
            method_id: 0,
            circuit_inputs: vec![],
            circuit_outputs: vec![],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![
                DPNAssertEqInfoIndexed {
                    left: encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
                    right: encode_indexed_op_id(DPNBuiltInDataType::Target, 3),
                    message: "contract id mismatch".to_string(),
                },
                DPNAssertEqInfoIndexed {
                    left: encode_indexed_op_id(DPNBuiltInDataType::Target, 1),
                    right: encode_indexed_op_id(DPNBuiltInDataType::Target, 4),
                    message: "caller contract id mismatch".to_string(),
                },
                DPNAssertEqInfoIndexed {
                    left: encode_indexed_op_id(DPNBuiltInDataType::Target, 2),
                    right: encode_indexed_op_id(DPNBuiltInDataType::Target, 5),
                    message: "nonce mismatch".to_string(),
                },
            ],
            definitions: vec![
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 0,
                    op_type: DPNOpType::GetContractId,
                    inputs: vec![],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 1,
                    op_type: DPNOpType::GetCallerContractId,
                    inputs: vec![],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 2,
                    op_type: DPNOpType::GetNonce,
                    inputs: vec![],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 3,
                    op_type: DPNOpType::Constant,
                    inputs: vec![contract_id],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 4,
                    op_type: DPNOpType::Constant,
                    inputs: vec![DEFAULT_CALLER_CONTRACT_ID_U64],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 5,
                    op_type: DPNOpType::Constant,
                    inputs: vec![nonce],
                },
            ],
            events: vec![],
        };
        let config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 0,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id,
        };
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&definition, &config).unwrap();
        let mut witness = build_dpn_witness(vec![]);
        let mut current_user_leaf = PsyUserLeaf::default();
        current_user_leaf.nonce = GF::from_canonical_u64(nonce);
        let signature_data = PsyUserProvingSessionSignatureDataCompact {
            start_user_leaf_hash: QHashOut::ZERO,
            end_user_leaf_hash: current_user_leaf.qfhash::<PoseidonHasher>(),
            checkpoint_leaf_hash: QHashOut::ZERO,
            tx_stack_hash: QHashOut::ZERO,
            tx_count: GF::ZERO,
        };
        witness.signature_context = Some(SDKeySignatureContext {
            signature_data,
            current_user_leaf,
            nonce: GF::from_canonical_u64(nonce),
            checkpoint_tree_root: QHashOut::ZERO,
        });
        let sighash = signature_data
            .get_sig_action_for_user::<PoseidonHasher>(
                PSY_NETWORK_MAGIC,
                GF::ZERO,
                GF::from_canonical_u64(nonce),
                SignContext {
                    checkpoint_tree_root: QHashOut::ZERO,
                    user_leaf: current_user_leaf,
                },
            )
            .get_qhash::<PoseidonHasher>();

        gadget.prove(dummy_private_key(), &witness, sighash).await.unwrap();
    }

    #[tokio::test]
    async fn dpn_function_accepts_value_greater_than_100() {
        let dpn_def = build_dpn_greater_than_100_function();
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 0,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 0,
        };
        let sd_config = sd_config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let witness = build_dpn_witness(vec![GF::from_noncanonical_u64(200)]);
        gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.unwrap();
    }

    #[tokio::test]
    async fn dpn_function_rejects_value_not_greater_than_100() {
        let dpn_def = build_dpn_greater_than_100_function();
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 0,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 0,
        };
        let sd_config = sd_config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let witness = build_dpn_witness(vec![GF::from_noncanonical_u64(50)]);
        assert!(gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.is_err());
    }

    /// Build the smallest programmable SDKey function that authenticates the
    /// method id of transaction 0 in the preceding transaction log.
    fn build_dpn_transaction_method_id_function(expected_method_id: u64) -> DPNFunctionCircuitDefinition {
        let tx_index_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 0);
        let method_id_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 1);
        let expected_method_id_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 2);

        DPNFunctionCircuitDefinition {
            name: "transaction_method_id_check".to_string(),
            method_id: 0,
            circuit_inputs: vec![],
            circuit_outputs: vec![],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![DPNAssertEqInfoIndexed {
                left: method_id_id,
                right: expected_method_id_id,
                message: "transaction 0 method_id mismatch".to_string(),
            }],
            definitions: vec![
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 0,
                    op_type: DPNOpType::Constant,
                    inputs: vec![0],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 1,
                    op_type: DPNOpType::GetTransactionMethodId,
                    inputs: vec![tx_index_id],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 2,
                    op_type: DPNOpType::Constant,
                    inputs: vec![expected_method_id],
                },
            ],
            events: vec![],
        }
    }

    #[tokio::test]
    async fn dpn_function_transaction_method_id_accepts_matching_value() {
        let expected_method_id = 42;
        let dpn_def = build_dpn_transaction_method_id_function(expected_method_id);
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 1,
            can_read_state: false,
            contract_state_tree_height: 0,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 0,
        };
        let sd_config = sd_config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let (tx_info, inputs) = make_tx_info(5, expected_method_id as u32, &[7]);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);
        gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.unwrap();
    }

    #[tokio::test]
    async fn dpn_function_transaction_method_id_rejects_mismatched_value() {
        let expected_method_id = 42;
        let dpn_def = build_dpn_transaction_method_id_function(expected_method_id);
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 1,
            can_read_state: false,
            contract_state_tree_height: 0,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 0,
        };
        let sd_config = sd_config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let (tx_info, inputs) = make_tx_info(5, 41, &[7]);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);
        assert!(gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.is_err());
    }

    /// Build a programmable SDKey function that reads one calldata word from
    /// a preceding transaction and requires it to equal `expected_word`.
    fn build_dpn_transaction_input_word_function(tx_index: u64, word_index: u64, expected_word: u64) -> DPNFunctionCircuitDefinition {
        let tx_index_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 0);
        let word_index_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 1);
        let input_word_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 2);
        let expected_word_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 3);

        DPNFunctionCircuitDefinition {
            name: "transaction_input_word_check".to_string(),
            method_id: 0,
            circuit_inputs: vec![],
            circuit_outputs: vec![],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![DPNAssertEqInfoIndexed {
                left: input_word_id,
                right: expected_word_id,
                message: "transaction calldata word mismatch".to_string(),
            }],
            definitions: vec![
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 0,
                    op_type: DPNOpType::Constant,
                    inputs: vec![tx_index],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 1,
                    op_type: DPNOpType::Constant,
                    inputs: vec![word_index],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 2,
                    op_type: DPNOpType::GetTransactionInputWord,
                    inputs: vec![tx_index_id, word_index_id],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 3,
                    op_type: DPNOpType::Constant,
                    inputs: vec![expected_word],
                },
            ],
            events: vec![],
        }
    }

    fn one_transaction_sd_key_config() -> SDKeyConfig {
        SDKeyConfig {
            num_introspectable_transactions: 1,
            can_read_state: false,
            contract_state_tree_height: 0,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 0,
        }
    }

    #[tokio::test]
    async fn dpn_function_transaction_input_word_accepts_authenticated_calldata() {
        let dpn_def = build_dpn_transaction_input_word_function(0, 1, 22);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let (tx_info, inputs) = make_tx_info(5, 42, &[11, 22]);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);
        gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.unwrap();
    }

    #[tokio::test]
    async fn dpn_function_transaction_input_word_rejects_tampered_calldata_with_original_hash() {
        // The policy deliberately expects the tampered word. If calldata were
        // not authenticated against `inputs_hash`, this witness would pass.
        let dpn_def = build_dpn_transaction_input_word_function(0, 1, 23);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let (tx_info, mut inputs) = make_tx_info(5, 42, &[11, 22]);
        inputs[1] = GF::from_canonical_u64(23);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);
        assert!(
            gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.is_err(),
            "tampered calldata must fail its inputs_hash binding"
        );
    }

    #[tokio::test]
    async fn dpn_function_transaction_input_word_rejects_transaction_index_equal_to_tx_count() {
        let dpn_def = build_dpn_transaction_input_word_function(1, 0, 11);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let (tx_info, inputs) = make_tx_info(5, 42, &[11]);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);
        assert!(
            gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.is_err(),
            "transaction index equal to tx_count must be out of range"
        );
    }

    #[tokio::test]
    async fn transaction_witness_rejects_missing_slots_instead_of_padding() {
        let dpn_def = build_dpn_transaction_input_word_function(0, 0, 0);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();
        let witness = build_witness(vec![], vec![], 0);
        let error = gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.unwrap_err();
        assert!(error.to_string().contains("expects 1 transaction infos"));
    }

    #[tokio::test]
    async fn transaction_witness_rejects_underreported_tx_count() {
        let dpn_def = build_dpn_transaction_input_word_function(0, 0, 11);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();
        let (tx_info, inputs) = make_tx_info(5, 42, &[11]);
        let mut witness = build_witness(vec![tx_info], vec![inputs], 1);
        witness.tx_count = GF::ZERO;

        let error = gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.unwrap_err();
        assert!(error.to_string().contains("expects tx_count 1"));
    }

    #[tokio::test]
    async fn dpn_function_transaction_input_word_rejects_calldata_over_128_felts() {
        let dpn_def = build_dpn_transaction_input_word_function(0, 0, 11);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let oversized_inputs = vec![11; SDKEY_MAX_CALLDATA_WORDS as usize + 1];
        let (tx_info, inputs) = make_tx_info(5, 42, &oversized_inputs);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);
        let error = gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.unwrap_err();
        assert!(
            error.to_string().contains("MAX_CALLDATA_WORDS"),
            "unexpected oversized calldata error: {error:#}"
        );
    }

    #[tokio::test]
    async fn dpn_function_transaction_input_word_accepts_exactly_128_felts() {
        let dpn_def = build_dpn_transaction_input_word_function(0, SDKEY_MAX_CALLDATA_WORDS as u64 - 1, 127);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let calldata = (0..SDKEY_MAX_CALLDATA_WORDS as u64).collect::<Vec<_>>();
        let (tx_info, inputs) = make_tx_info(5, 42, &calldata);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);
        gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.unwrap();
    }

    #[tokio::test]
    async fn dpn_function_transaction_input_word_rejects_empty_calldata_read() {
        let dpn_def = build_dpn_transaction_input_word_function(0, 0, 0);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let (tx_info, inputs) = make_tx_info(5, 42, &[]);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);
        assert!(
            gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.is_err(),
            "word zero is outside an empty calldata value"
        );
    }

    #[tokio::test]
    async fn dpn_function_transaction_input_word_rejects_padded_tail_witness() {
        // The regular witness writer pads this target with zero. Before the
        // inputs_length bound, this policy would therefore prove successfully.
        let dpn_def = build_dpn_transaction_input_word_function(0, 1, 0);
        let sd_config = one_transaction_sd_key_config();
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();
        let (tx_info, inputs) = make_tx_info(5, 42, &[11]);
        let witness = build_witness(vec![tx_info], vec![inputs], 1);

        assert!(
            gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.is_err(),
            "a padded calldata target must not be readable as an arbitrary witness value"
        );
    }

    /// Explicit capacity/performance test for the protocol maximum. This is
    /// ignored by default because constructing 32 slots with 128 calldata
    /// targets each is intentionally expensive.
    #[tokio::test]
    #[ignore = "resource-intensive 32 transaction SDKey capacity test"]
    async fn dpn_function_transaction_input_word_accepts_transaction_index_31_at_max_count() {
        let dpn_def = build_dpn_transaction_input_word_function(MAX_INTROSPECTABLE_TRANSACTIONS as u64 - 1, 0, 31);
        let mut config = one_transaction_sd_key_config();
        config.num_introspectable_transactions = MAX_INTROSPECTABLE_TRANSACTIONS;
        let sd_config = config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let mut transaction_infos = Vec::with_capacity(MAX_INTROSPECTABLE_TRANSACTIONS as usize);
        let mut transaction_inputs = Vec::with_capacity(MAX_INTROSPECTABLE_TRANSACTIONS as usize);
        for index in 0..MAX_INTROSPECTABLE_TRANSACTIONS as u64 {
            let (tx_info, inputs) = make_tx_info(5, 42, &[index]);
            transaction_infos.push(tx_info);
            transaction_inputs.push(inputs);
        }
        let witness = build_witness(transaction_infos, transaction_inputs, MAX_INTROSPECTABLE_TRANSACTIONS);
        gadget.prove(dummy_private_key(), &witness, dummy_sighash()).await.unwrap();
    }

    #[test]
    fn dpn_function_definition_rejects_more_than_32_transactions_without_panicking() {
        let dpn_def = build_dpn_transaction_input_word_function(0, 0, 11);
        let mut config = one_transaction_sd_key_config();
        config.num_introspectable_transactions = MAX_INTROSPECTABLE_TRANSACTIONS + 1;
        let error = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &config).unwrap_err();
        assert!(
            error.to_string().contains("MAX_TX_COUNT"),
            "unexpected transaction-count error: {error:#}"
        );
    }

    /// Build a DPN view function that reads self current contract slot 0 and
    /// checks it is greater than 100.
    fn build_dpn_state_read_greater_than_100_function() -> DPNFunctionCircuitDefinition {
        let state_slot_index_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 0);
        let state_read_target_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 1);
        let constant_100_id = encode_indexed_op_id(DPNBuiltInDataType::Target, 2);
        let result_bool_id = encode_indexed_op_id(DPNBuiltInDataType::Bool, 0);

        DPNFunctionCircuitDefinition {
            name: "state_read_greater_than_100".to_string(),
            method_id: 0,
            circuit_inputs: vec![],
            circuit_outputs: vec![result_bool_id],
            state_commands: vec![DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(
                DPNStateCmdGetSelfUserCurrentContractStateSlotSingle {
                    sub_slot_index: state_slot_index_id,
                },
            )],
            state_command_resolution_indices: vec![1],
            assertions: vec![],
            definitions: vec![
                // constant slot index 0 -> target[0]
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 0,
                    op_type: DPNOpType::Constant,
                    inputs: vec![0],
                },
                // state_commands[0] single result -> target[1]
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 1,
                    op_type: DPNOpType::GetStateCommandResultSingle,
                    inputs: vec![0],
                },
                // constant 100 -> target[2]
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 2,
                    op_type: DPNOpType::Constant,
                    inputs: vec![100],
                },
                // target[1] > target[2] -> bool[0]
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Bool,
                    index: 0,
                    op_type: DPNOpType::Gt,
                    inputs: vec![state_read_target_id, constant_100_id],
                },
            ],
            events: vec![],
        }
    }

    fn build_dpn_witness_with_state(circuit_inputs: Vec<GF>, state_reader_results: StateReaderResults<GF>) -> SDKeyCircuitWitnessInput {
        let start_contract_state_root = state_reader_results.state.start_contract_state_root;
        let checkpoint_id = state_reader_results.state.checkpoint_id;
        let user_id = state_reader_results.state.user_leaf.user_id;
        let nonce = state_reader_results.state.user_leaf.nonce;
        let mut current_user_leaf = state_reader_results.state.user_leaf;
        let mut user_contract_tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<GF>>::new(GLOBAL_CONTRACT_TREE_HEIGHT);
        user_contract_tree.set_leaf(5, start_contract_state_root);
        let contract_state_root_proof = user_contract_tree.get_leaf(5);
        current_user_leaf.user_state_tree_root = user_contract_tree.get_root();
        let chain_state_roots = PsyCheckpointGlobalStateRoots::default();
        let checkpoint_stats = PsyCheckpointLeafStats::default();
        let checkpoint_leaf_hash =
            PoseidonHasher::q_two_to_one(chain_state_roots.qfhash::<PoseidonHasher>(), checkpoint_stats.qfhash::<PoseidonHasher>());
        let signature_data = PsyUserProvingSessionSignatureDataCompact {
            start_user_leaf_hash: QHashOut::ZERO,
            end_user_leaf_hash: current_user_leaf.qfhash::<PoseidonHasher>(),
            checkpoint_leaf_hash,
            tx_stack_hash: QHashOut::ZERO,
            tx_count: GF::ZERO,
        };
        SDKeyCircuitWitnessInput {
            circuit_inputs,
            transaction_infos: vec![],
            transaction_inputs: vec![],
            tx_stack_hash: QHashOut::default(),
            tx_count: GF::ZERO,
            state_reader_results: Some(state_reader_results),
            dpn_state_command_witnesses: vec![],
            dpn_state_reader_context: Some(SDKeyDPNStateReaderContext {
                user_contract_tree_state_root: current_user_leaf.user_state_tree_root,
                deferred_tx_tree_root: QHashOut::ZERO,
                session_proof_tree_root: QHashOut::ZERO,
                checkpoint_tree_root: QHashOut::ZERO,
                chain_state_roots: PsyCheckpointGlobalStateRoots::default(),
                checkpoint_stats: PsyCheckpointLeafStats::default(),
            }),
            signature_context: Some(SDKeySignatureContext {
                signature_data,
                current_user_leaf,
                nonce,
                checkpoint_tree_root: QHashOut::ZERO,
            }),
            contract_state_root_proof: Some(contract_state_root_proof),
            start_contract_state_root,
            secp256k1_slots: vec![],
            checkpoint_id,
            user_id,
        }
    }

    fn stateful_witness_sighash(witness: &SDKeyCircuitWitnessInput) -> QHashOut<GF> {
        let context = witness.signature_context.as_ref().unwrap();
        context
            .signature_data
            .get_sig_action_for_user::<PoseidonHasher>(
                PSY_NETWORK_MAGIC,
                witness.user_id,
                context.nonce,
                SignContext {
                    checkpoint_tree_root: QHashOut::ZERO,
                    user_leaf: context.current_user_leaf,
                },
            )
            .get_qhash::<PoseidonHasher>()
    }

    #[tokio::test]
    async fn dpn_function_state_read_accepts_value_greater_than_100() {
        let dpn_def = build_dpn_state_read_greater_than_100_function();
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 4,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 5,
        };
        let sd_config = sd_config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let state_reader_results = make_state_reader_results(5, 4, 7, 11, &[(0, 200)]);
        let witness = build_dpn_witness_with_state(vec![], state_reader_results);
        gadget
            .prove(dummy_private_key(), &witness, stateful_witness_sighash(&witness))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dpn_function_state_read_rejects_value_not_greater_than_100() {
        let dpn_def = build_dpn_state_read_greater_than_100_function();
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 4,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 5,
        };
        let sd_config = sd_config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let state_reader_results = make_state_reader_results(5, 4, 7, 11, &[(0, 50)]);
        let witness = build_dpn_witness_with_state(vec![], state_reader_results);
        assert!(gadget
            .prove(dummy_private_key(), &witness, stateful_witness_sighash(&witness))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn dpn_function_state_read_rejects_tampered_merkle_value_that_still_satisfies_policy() {
        let dpn_def = build_dpn_state_read_greater_than_100_function();
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 4,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 5,
        };
        let sd_config = sd_config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let mut state_reader_results = make_state_reader_results(5, 4, 7, 11, &[(0, 200)]);
        // 201 still satisfies `value > 100`, so rejection demonstrates that
        // the value is authenticated by the unchanged Merkle root.
        state_reader_results.merkel_proofs[0].value.0.elements[0] = GF::from_canonical_u64(201);
        let witness = build_dpn_witness_with_state(vec![], state_reader_results);
        assert!(
            gadget
                .prove(dummy_private_key(), &witness, stateful_witness_sighash(&witness))
                .await
                .is_err(),
            "tampered state value must fail its Merkle-root binding"
        );
    }

    #[tokio::test]
    async fn dpn_function_state_read_rejects_tampered_start_contract_state_root() {
        let dpn_def = build_dpn_state_read_greater_than_100_function();
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 4,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 5,
        };
        let sd_config = sd_config;
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();

        let state_reader_results = make_state_reader_results(5, 4, 7, 11, &[(0, 200)]);
        let mut witness = build_dpn_witness_with_state(vec![], state_reader_results);
        witness.start_contract_state_root.0.elements[0] += GF::ONE;
        assert!(
            gadget
                .prove(dummy_private_key(), &witness, stateful_witness_sighash(&witness))
                .await
                .is_err(),
            "tampered start_contract_state_root must fail the state-proof binding"
        );
    }

    #[tokio::test]
    async fn dpn_function_state_read_rejects_checkpoint_root_not_committed_by_sighash() {
        let dpn_def = build_dpn_state_read_greater_than_100_function();
        let sd_config = SDKeyConfig {
            num_introspectable_transactions: 0,
            can_read_state: false,
            contract_state_tree_height: 4,
            requires_secp256k1: false,
            num_secp256k1_slots: 0,
            contract_id: 5,
        };
        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&dpn_def, &sd_config).unwrap();
        let state_reader_results = make_state_reader_results(5, 4, 7, 11, &[(0, 200)]);
        let mut witness = build_dpn_witness_with_state(vec![], state_reader_results);
        let committed_sighash = stateful_witness_sighash(&witness);
        witness.dpn_state_reader_context = Some(SDKeyDPNStateReaderContext {
            user_contract_tree_state_root: QHashOut::ZERO,
            deferred_tx_tree_root: QHashOut::ZERO,
            session_proof_tree_root: QHashOut::ZERO,
            checkpoint_tree_root: QHashOut(plonky2::hash::hash_types::HashOut {
                elements: [GF::ONE, GF::ZERO, GF::ZERO, GF::ZERO],
            }),
            chain_state_roots: PsyCheckpointGlobalStateRoots::default(),
            checkpoint_stats: PsyCheckpointLeafStats::default(),
        });

        assert!(
            gadget.prove(dummy_private_key(), &witness, committed_sighash).await.is_err(),
            "state roots not committed by the signed UPS context must be rejected"
        );
    }
}
