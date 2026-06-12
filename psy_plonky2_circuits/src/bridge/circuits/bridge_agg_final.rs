use std::array;

use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleZeroHasher},
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_data::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafCompact};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison,
    core::CircuitBuilderHelpersCore,
    hash::core::CircuitBuilderHashCore,
    pad_circuit::CircuitBuilderQEDCommonGates,
    verify::CircuitBuilderVerifyProofHelpers,
};
use psy_plonky2_common_circuits::{
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
    traits::CreatableTarget,
};

use crate::{
    bridge::{
        circuits::bridge_agg_chain::{
            BridgeAggChainCircuit, BridgeAggChainSlotWitness, BRIDGE_AGG_CHAIN_MAX_SLOTS,
        },
        gadgets::{
            tree_root_in_contract_state::{
                TreeRootInContractStateGadget, TreeRootInContractStateWitnessInput,
            },
        },
    },
    gadgets::qdata::{
        checkpoint::QEDCheckpointLeafCompactGadget,
        checkpoint_state_roots::QEDCheckpointGlobalStateRootsGadget,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

/// BridgeAggFinalCircuit: terminal bridge circuit.
///
/// Consumes one verified BridgeAggChainCircuit proof (pure hash chain, 21-felt PI),
/// verifies the delta merkle proof for the last checkpoint, extracts
/// deposit/withdrawal tree roots from the final checkpoint's contract state,
/// and outputs 26 felts for L1.
///
/// ## Verification flow
/// 1. Verifies the chain proof (21-felt PI)
/// 2. Pins chain circuit fingerprint
/// 3. Verifies delta merkle proof against chain PI's end_checkpoint_tree_root
/// 4. Verifies final checkpoint leaf hash matches chain PI's end_checkpoint_leaf_hash
/// 5. Extracts deposit/withdrawal roots from contract state via merkle proofs
/// 6. Outputs 26 felts for L1 settlement
///
/// ## Public inputs (26 felts)
///   [0..4)   start_checkpoint_tree_root (from chain PI[8..12) for single-chunk, or witnessed for multi-chunk)
///   [4..12)  deposit_tree_root
///   [12..20) withdrawal_tree_root
///   [20..24) end_checkpoint_tree_root (from chain PI[12..16))
///   [24]     bridge_user_id
///   [25]     total_num_checkpoints_aggregated (from chain PI[20] for single-chunk, or witnessed for multi-chunk)
#[derive(Debug)]
pub struct BridgeAggFinalCircuit<C: GenericConfig<D>, const D: usize> {
    // ── Chain proof targets ──
    pub chain_proof_target: ProofWithPublicInputsTarget<D>,
    pub chain_verifier_target: VerifierCircuitTarget,

    // ── Chain proof PI targets (21 felts extracted from verified chain proof) ──
    pub chain_start_chain_hash: HashOutTarget,
    pub chain_end_chain_hash: HashOutTarget,
    pub chain_start_checkpoint_tree_root: HashOutTarget,
    pub chain_end_checkpoint_tree_root: HashOutTarget,
    pub chain_end_checkpoint_leaf_hash: HashOutTarget,
    pub chain_num_checkpoints: Target,
    pub total_start_checkpoint_tree_root: HashOutTarget,
    pub total_num_checkpoints: Target,

    // ── Checkpoint fingerprint constant ──
    pub checkpoint_base_fingerprint_target: HashOutTarget,

    // ── Global state roots from checkpoint leaf (provides user_tree_root binding) ──
    pub checkpoint_global_state_roots: QEDCheckpointGlobalStateRootsGadget,

    // ── Terminal verification gadgets ──
    pub checkpoint_delta_merkle_proof: DeltaMerkleProofGadget,
    pub final_checkpoint_leaf: QEDCheckpointLeafCompactGadget,
    pub deposit_root_gadget: TreeRootInContractStateGadget,
    pub withdrawal_root_gadget: TreeRootInContractStateGadget,
    pub checkpoint_tree_height: usize,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> BridgeAggFinalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<plonky2::hash::hash_types::HashOut<C::F>>,
    C::F: RichField + Extendable<D>,
{
    /// Build the BridgeAggFinalCircuit.
    ///
    /// Parameters:
    /// - `chain_common_data`: CommonCircuitData for BridgeAggChainCircuit
    /// - `chain_cap_height`: verifier cap height for chain circuit
    /// - `chain_fingerprint`: fingerprint of BridgeAggChainCircuit
    /// - `known_checkpoint_base_fingerprint`: BASE fingerprint of checkpoint transition circuit
    /// - `checkpoint_tree_height`: height of the checkpoint tree
    /// - `global_user_tree_height`, `global_contract_tree_height`, `contract_state_tree_height`
    pub fn new(
        chain_common_data: &CommonCircuitData<C::F, D>,
        chain_cap_height: usize,
        chain_fingerprint: QHashOut<C::F>,
        _known_checkpoint_fingerprint: QHashOut<C::F>,
        known_checkpoint_base_fingerprint: QHashOut<C::F>,
        checkpoint_tree_height: usize,
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        // ── Circuit-level constants ──
        let one = builder.one();
        let max_slots = builder.constant_u64(BRIDGE_AGG_CHAIN_MAX_SLOTS as u64);
        // Base fingerprint for reference (kept for circuit consistency, not used in constraints)
        let _cp_base_fingerprint = builder.constant_qhash(known_checkpoint_base_fingerprint);

        // ── Phase 1: Verify chain proof and extract its PI ──
        let chain_verifier_target = builder.add_virtual_verifier_data(chain_cap_height);
        let chain_proof_target = builder.add_virtual_proof_with_pis(chain_common_data);
        builder.verify_proof::<C>(&chain_proof_target, &chain_verifier_target, chain_common_data);

        // Pin chain circuit fingerprint
        let actual_chain_fp = builder.get_circuit_fingerprint::<C::Hasher>(&chain_verifier_target);
        let expected_chain_fp = builder.constant_qhash(chain_fingerprint);
        builder.connect_hashes(actual_chain_fp, expected_chain_fp);

        // Extract chain proof PI (21 felts, pure hash chain)
        let chain_pi: Vec<Target> = chain_proof_target
            .public_inputs
            .iter()
            .copied()
            .collect();
        // BridgeAggChainCircuit pure hash chain outputs 21 public inputs:
        //   [0..4)   start_chain_hash
        //   [4..8)   end_chain_hash
        //   [8..12)  start_checkpoint_tree_root
        //   [12..16) end_checkpoint_tree_root
        //   [16..20) end_checkpoint_leaf_hash
        //   [20]     num_checkpoints (active_len)
        assert!(
            chain_pi.len() >= 21,
            "chain proof must have at least 21 public inputs, got {}",
            chain_pi.len()
        );

        // helper: extract HashOutTarget from chain PI at given felt offset
        let pi_hash = |start: usize| -> HashOutTarget {
            HashOutTarget {
                elements: [
                    chain_pi[start],
                    chain_pi[start + 1],
                    chain_pi[start + 2],
                    chain_pi[start + 3],
                ],
            }
        };

        let chain_start_chain_hash = pi_hash(0);
        let chain_end_chain_hash = pi_hash(4);
        let chain_start_checkpoint_tree_root = pi_hash(8);
        let chain_end_checkpoint_tree_root = pi_hash(12);
        let chain_end_checkpoint_leaf_hash = pi_hash(16);
        let chain_num_checkpoints = chain_pi[20];
        let total_start_checkpoint_tree_root = builder.add_virtual_hash();
        let total_num_checkpoints = builder.add_virtual_target();

        // ── Constrain total_start for single-chunk: total_num == chain_num → total_start == chain_PI[8..12) ──
        // For multi-chunk (total_num > chain_num), total_start is externally witnessed
        // but indirectly constrained by the first chunk's first checkpoint proof's old_root,
        // which is verified inside the first chain proof.
        let is_single_chunk = builder.is_equal(total_num_checkpoints, chain_num_checkpoints);
        for j in 0..4 {
            let diff = builder.sub(total_start_checkpoint_tree_root.elements[j], chain_start_checkpoint_tree_root.elements[j]);
            let constrained = builder.mul(is_single_chunk.target, diff);
            builder.assert_zero(constrained);
        }

        // ── Active length: num_checkpoints = number of active slots ──
        let active_len = chain_num_checkpoints;
        let active_ge_one = builder.is_less_than_or_equal(16, one, active_len);
        builder.assert_one(active_ge_one.target);
        let active_le_max = builder.is_less_than_or_equal(16, active_len, max_slots);
        builder.assert_one(active_le_max.target);

        // ── Phase 2: Terminal verification ──

        // Delta merkle proof for the last checkpoint
        let checkpoint_delta_merkle_proof =
            DeltaMerkleProofGadget::add_virtual_to_append_only::<C::Hasher, C::F, D>(&mut builder, checkpoint_tree_height);

        // Connect delta merkle proof new_root to chain PI's end_checkpoint_tree_root
        builder.connect_hashes(checkpoint_delta_merkle_proof.new_root, chain_end_checkpoint_tree_root);

        // Final checkpoint leaf
        let final_checkpoint_leaf = QEDCheckpointLeafCompactGadget::create_virtual(&mut builder);
        let final_checkpoint_leaf_hash = final_checkpoint_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);
        builder.connect_hashes(final_checkpoint_leaf_hash, checkpoint_delta_merkle_proof.new_value);

        // Also connect final leaf hash to chain PI's end_checkpoint_leaf_hash
        builder.connect_hashes(final_checkpoint_leaf_hash, chain_end_checkpoint_leaf_hash);

        // ── Global state roots: bind user_tree_root to checkpoint leaf ──
        let checkpoint_global_state_roots =
            QEDCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        // Recompute global_chain_root from state roots and pin it to leaf's value
        let computed_global_chain_root =
            checkpoint_global_state_roots.to_hash::<C::Hasher, C::F, D>(&mut builder);
        builder.connect_hashes(computed_global_chain_root, final_checkpoint_leaf.global_chain_root);

        // Deposit root extraction
        let deposit_root_gadget = TreeRootInContractStateGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
        );

        // Withdrawal root extraction
        let withdrawal_root_gadget = TreeRootInContractStateGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
        );
        builder.connect_hashes(withdrawal_root_gadget.user_tree_root, deposit_root_gadget.user_tree_root);
        builder.connect(withdrawal_root_gadget.slot0.sender_user_id, deposit_root_gadget.slot0.sender_user_id);

        // 🛡 Bind the deposit/withdrawal gadget's user_tree_root to the checkpoint leaf's
        // global_state_roots.user_tree_root. This ensures the Merkle proof chain
        // (user_tree → contract → slot values) is anchored in the verified checkpoint.
        builder.connect_hashes(
            deposit_root_gadget.user_tree_root,
            checkpoint_global_state_roots.user_tree_root,
        );

        // ── Register public inputs (26 felts) ──
        // [0..4) start_checkpoint_tree_root (from outer prove_range)
        builder.register_public_inputs(&total_start_checkpoint_tree_root.elements);
        // [4..12) deposit_tree_root
        builder.register_public_inputs(&deposit_root_gadget.tree_root[0].elements);
        builder.register_public_inputs(&deposit_root_gadget.tree_root[1].elements);
        // [12..20) withdrawal_tree_root
        builder.register_public_inputs(&withdrawal_root_gadget.tree_root[0].elements);
        builder.register_public_inputs(&withdrawal_root_gadget.tree_root[1].elements);
        // [20..24) end_checkpoint_tree_root (from chain PI)
        builder.register_public_inputs(&chain_pi[12..16]);
        // [24] bridge user id
        builder.register_public_input(deposit_root_gadget.slot0.sender_user_id);
        // [25] total_num_checkpoints_aggregated (from outer prove_range)
        builder.register_public_input(total_num_checkpoints);

        builder.add_qed_type_d_common_gates();
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            chain_proof_target,
            chain_verifier_target,
            chain_start_chain_hash,
            chain_end_chain_hash,
            chain_start_checkpoint_tree_root,
            chain_end_checkpoint_tree_root,
            chain_end_checkpoint_leaf_hash,
            chain_num_checkpoints,
            total_start_checkpoint_tree_root,
            total_num_checkpoints,
            checkpoint_base_fingerprint_target: _cp_base_fingerprint,
            checkpoint_global_state_roots,
            checkpoint_delta_merkle_proof,
            final_checkpoint_leaf,
            deposit_root_gadget,
            withdrawal_root_gadget,
            checkpoint_tree_height,
            circuit_data,
            fingerprint,
        }
    }

    /// Generate a BridgeAggFinalCircuit proof.
    ///
    /// Parameters:
    /// - `chain_proof`: BridgeAggChainCircuit proof (21-felt PI)
    /// - `chain_verifier_data`: verifier data for BridgeAggChainCircuit
    /// - `checkpoint_delta_merkle_proof`: delta proof for the last checkpoint
    /// - `final_checkpoint_leaf`: checkpoint leaf for the last checkpoint
    /// - `checkpoint_global_state_roots`: global state roots for the checkpoint
    /// - `deposit_root_witness`: witness for deposit tree root in contract state
    /// - `withdrawal_root_witness`: witness for withdrawal tree root in contract state
    pub fn prove_base(
        &self,
        chain_proof: &ProofWithPublicInputs<C::F, C, D>,
        chain_verifier_data: &VerifierOnlyCircuitData<C, D>,
        total_start_checkpoint_tree_root: QHashOut<C::F>,
        total_num_checkpoints: u64,
        checkpoint_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        final_checkpoint_leaf: &PQEDCheckpointLeafCompact<QHashOut<C::F>>,
        checkpoint_global_state_roots: &PQEDCheckpointGlobalStateRoots<QHashOut<C::F>>,
        deposit_root_witness: &TreeRootInContractStateWitnessInput<C::F>,
        withdrawal_root_witness: &TreeRootInContractStateWitnessInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(
            chain_proof.public_inputs.len() >= 21,
            "chain proof must have at least 21 public inputs, got {}",
            chain_proof.public_inputs.len()
        );

        let mut pw = PartialWitness::<C::F>::new();

        // Set chain proof witness
        pw.set_verifier_data_target::<C, D>(&self.chain_verifier_target, chain_verifier_data)?;
        pw.set_proof_with_pis_target::<C, D>(&self.chain_proof_target, chain_proof)?;
        pw.set_hash_target(
            self.total_start_checkpoint_tree_root,
            total_start_checkpoint_tree_root.0,
        )?;
        pw.set_target(
            self.total_num_checkpoints,
            C::F::from_canonical_u64(total_num_checkpoints),
        )?;

        // Set terminal verification witnesses
        self.checkpoint_delta_merkle_proof
            .set_witness_core_proof_q(&mut pw, checkpoint_delta_merkle_proof)?;
        self.final_checkpoint_leaf.set_witness(&mut pw, final_checkpoint_leaf)?;
        self.checkpoint_global_state_roots
            .set_witness(&mut pw, checkpoint_global_state_roots)?;
        self.deposit_root_gadget.set_witness(&mut pw, deposit_root_witness)?;
        self.withdrawal_root_gadget.set_witness(&mut pw, withdrawal_root_witness)?;

        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for BridgeAggFinalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

/// Result of a full bridge aggregation prove_range call.
pub struct BridgeAggProveResult<C: GenericConfig<D>, const D: usize> {
    pub proof: ProofWithPublicInputs<C::F, C, D>,
    pub common_data: CommonCircuitData<C::F, D>,
    pub fingerprint: QHashOut<C::F>,
    pub verifier_data: VerifierOnlyCircuitData<C, D>,
}

impl<C: GenericConfig<D>, const D: usize> BridgeAggFinalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<plonky2::hash::hash_types::HashOut<C::F>>,
    C::F: RichField + Extendable<D>,
{
    /// Pre-build the final circuit (no proving) using a temporary chain circuit.
    /// Used for pre-building Groth16 wrapper at startup.
    pub fn prebuild_final_circuit(
        checkpoint_common_data: &CommonCircuitData<C::F, D>,
        checkpoint_cap_height: usize,
        checkpoint_fingerprint: QHashOut<C::F>,
        checkpoint_base_fingerprint: QHashOut<C::F>,
        checkpoint_tree_height: usize,
        user_tree_height: usize,
        contract_tree_height: usize,
        contract_state_tree_height: usize,
    ) -> Self {
        let chain_circuit = BridgeAggChainCircuit::<C, D>::new(
            checkpoint_common_data,
            checkpoint_cap_height,
            checkpoint_fingerprint,
            checkpoint_base_fingerprint,
        );
        let chain_common = chain_circuit.get_common_circuit_data_ref();
        let chain_cap = chain_circuit.get_verifier_config_ref().constants_sigmas_cap.height();
        let chain_fp = chain_circuit.get_fingerprint();
        Self::new(
            chain_common,
            chain_cap,
            chain_fp,
            checkpoint_fingerprint,
            checkpoint_base_fingerprint,
            checkpoint_tree_height,
            user_tree_height,
            contract_tree_height,
            contract_state_tree_height,
        )
    }

    /// Prove a range of checkpoints in a single call.
    ///
    /// Internally builds a temporary BridgeAggChainCircuit, generates the chain proof,
    /// builds the final circuit, and generates the final 26-felt proof.
    ///
    /// Returns the final proof plus the final circuit's data (common, fingerprint, verifier)
    /// needed for subsequent Groth16 wrapping.
    pub fn prove_range(
        from_checkpoint: u64,
        to_checkpoint: u64,
        start_chain_hash: QHashOut<C::F>,
        checkpoint_common_data: &CommonCircuitData<C::F, D>,
        checkpoint_cap_height: usize,
        checkpoint_fingerprint: QHashOut<C::F>,
        checkpoint_base_fingerprint: QHashOut<C::F>,
        _checkpoint_proofs: &[ProofWithPublicInputs<C::F, C, D>],
        _checkpoint_verifier_data: &VerifierOnlyCircuitData<C, D>,
        delta_merkle_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>],
        pre_delta_merkle_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>],
        final_checkpoint_leaf: &PQEDCheckpointLeafCompact<QHashOut<C::F>>,
        checkpoint_global_state_roots: &PQEDCheckpointGlobalStateRoots<QHashOut<C::F>>,
        deposit_witness: &TreeRootInContractStateWitnessInput<C::F>,
        withdrawal_witness: &TreeRootInContractStateWitnessInput<C::F>,
        checkpoint_tree_height: usize,
        user_tree_height: usize,
        contract_tree_height: usize,
        contract_state_tree_height: usize,
    ) -> anyhow::Result<BridgeAggProveResult<C, D>> {
        anyhow::ensure!(
            from_checkpoint <= to_checkpoint,
            "from_checkpoint must be <= to_checkpoint"
        );
        let num_checkpoints = to_checkpoint - from_checkpoint + 1;
        anyhow::ensure!(
            num_checkpoints >= 1,
            "bridge aggregation requires at least 1 checkpoint, got {} (from={} to={})",
            num_checkpoints,
            from_checkpoint,
            to_checkpoint
        );
        // Allow ranges larger than BRIDGE_AGG_CHAIN_MAX_SLOTS:
        // Multi-chunk handled internally by building one chain proof per chunk
        // and chaining end_chain_hash at host level.
        // Each chunk is limited to BRIDGE_AGG_CHAIN_MAX_SLOTS active checkpoints.
        // NOTE: Host-level chaining means the final circuit only verifies the last
        // chain proof. The total_start_checkpoint_tree_root and total_num_checkpoints
        // are witnessed externally (indirectly constrained by the first checkpoint
        // proof's old_root, which is verified inside the first chain proof).

        let total = num_checkpoints as usize;
        anyhow::ensure!(
            delta_merkle_proofs.len() >= total,
            "delta_merkle_proofs length {} < num_checkpoints {}",
            delta_merkle_proofs.len(),
            total
        );
        anyhow::ensure!(
            pre_delta_merkle_proofs.len() >= total,
            "pre_delta_merkle_proofs length {} < num_checkpoints {}",
            pre_delta_merkle_proofs.len(),
            total
        );

        tracing::info!(
            from_checkpoint, to_checkpoint, num_checkpoints = total,
            "BridgeAggFinalCircuit::prove_range starting"
        );

        // ── Helper: prove one 32-slot chain chunk ──
        let prove_chain_chunk = |
            chunk_start_cp: u64,
            chunk_n: usize,
            cur_start_chain_hash: QHashOut<C::F>,
            delta_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>],
            pre_delta_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>],
        | -> anyhow::Result<(
            BridgeAggChainCircuit<C, D>,
            ProofWithPublicInputs<C::F, C, D>,
        )> {
            let chain_circuit = BridgeAggChainCircuit::<C, D>::new(
                checkpoint_common_data,
                checkpoint_cap_height,
                checkpoint_fingerprint,
                checkpoint_base_fingerprint,
            );

            let mut chain_slots = Vec::with_capacity(BRIDGE_AGG_CHAIN_MAX_SLOTS);
            for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
                if i < chunk_n {
                    chain_slots.push(BridgeAggChainSlotWitness {
                        old_checkpoint_tree_root: delta_proofs[i].old_root,
                        new_checkpoint_tree_root: delta_proofs[i].new_root,
                        new_checkpoint_leaf_hash: delta_proofs[i].new_value,
                    });
                } else {
                    chain_slots.push(BridgeAggChainSlotWitness {
                        old_checkpoint_tree_root: QHashOut::ZERO,
                        new_checkpoint_tree_root: QHashOut::ZERO,
                        new_checkpoint_leaf_hash: QHashOut::ZERO,
                    });
                }
            }

            let proof = chain_circuit.prove_base(chunk_n as u64, cur_start_chain_hash, &chain_slots)
                .map_err(|e| anyhow::anyhow!("BridgeAggChainCircuit chunk {chunk_start_cp} FAILED: {:#}", e))?;
            tracing::info!(
                "BridgeAggChainCircuit chunk from={} n={} PI len: {}",
                chunk_start_cp, chunk_n, proof.public_inputs.len()
            );
            Ok((chain_circuit, proof))
        };

        // ── Iterate chunks: all but the last only build chain proofs ──
        let max = BRIDGE_AGG_CHAIN_MAX_SLOTS;
        let mut cur_hash = start_chain_hash;
        let mut last_chain_circuit: Option<BridgeAggChainCircuit<C, D>> = None;
        let mut last_chain_proof: Option<ProofWithPublicInputs<C::F, C, D>> = None;
        let mut last_chunk_n: usize = 0;
        let mut last_chunk_start: u64 = from_checkpoint;

        let mut offset = 0usize;
        while offset < total {
            let chunk_n = std::cmp::min(max, total - offset);
            let chunk_start = from_checkpoint + offset as u64;

            let (chain_circuit, chain_proof) = prove_chain_chunk(
                chunk_start,
                chunk_n,
                cur_hash,
                &delta_merkle_proofs[offset..offset + chunk_n],
                &pre_delta_merkle_proofs[offset..offset + chunk_n],
            )?;

            // Extract end_chain_hash from chain proof PI [4..8)
            cur_hash = QHashOut::<C::F>::try_from(&chain_proof.public_inputs[4..8])
                .map_err(|e| anyhow::anyhow!("failed to parse end_chain_hash from chain proof PI: {:?}", e))?;

            last_chain_circuit = Some(chain_circuit);
            last_chain_proof = Some(chain_proof);
            last_chunk_n = chunk_n;
            last_chunk_start = chunk_start;

            offset += chunk_n;
        }

        // ── Phase 2: Build final circuit wrapping the LAST chain chunk ──
        let chain_circuit = last_chain_circuit.unwrap();
        let chain_proof = last_chain_proof.unwrap();
        let n = last_chunk_n;

        let chain_common = chain_circuit.get_common_circuit_data_ref();
        let chain_cap = chain_circuit.get_verifier_config_ref().constants_sigmas_cap.height();
        let chain_fp = chain_circuit.get_fingerprint();

        let final_circuit = Self::new(
            chain_common,
            chain_cap,
            chain_fp,
            checkpoint_fingerprint,
            checkpoint_base_fingerprint,
            checkpoint_tree_height,
            user_tree_height,
            contract_tree_height,
            contract_state_tree_height,
        );

        tracing::info!(
            "Building BridgeAggFinalCircuit proof for last chunk from={} n={}",
            last_chunk_start, n
        );

        let last_global_idx = total - 1;
        let last_delta = &delta_merkle_proofs[last_global_idx];
        let chain_verifier = chain_circuit.get_verifier_config_ref();

        // Compute the original start_checkpoint_tree_root from the FIRST checkpoint
        let total_start_root = delta_merkle_proofs[0].old_root;

        let proof = final_circuit.prove_base(
            &chain_proof,
            chain_verifier,
            total_start_root,
            num_checkpoints,
            last_delta,
            final_checkpoint_leaf,
            checkpoint_global_state_roots,
            deposit_witness,
            withdrawal_witness,
        )?;

        tracing::info!(
            "BridgeAggFinalCircuit proof generated, public_inputs_len: {}",
            proof.public_inputs.len()
        );

        anyhow::ensure!(
            proof.public_inputs.len() >= 26,
            "BridgeAgg proof public inputs too short: {}",
            proof.public_inputs.len()
        );

        Ok(BridgeAggProveResult {
            proof,
            common_data: final_circuit.circuit_data.common,
            fingerprint: final_circuit.fingerprint,
            verifier_data: final_circuit.circuit_data.verifier_only,
        })
    }
}
