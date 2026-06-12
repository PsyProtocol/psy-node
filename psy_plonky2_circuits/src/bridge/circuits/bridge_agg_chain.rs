use std::array;

use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::extension::Extendable,
    field::types::Field,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison,
    core::CircuitBuilderHelpersCore,
    hash::core::CircuitBuilderHashCore,
    pad_circuit::CircuitBuilderQEDCommonGates,
    select::CircuitBuilderSelectHelpers,
};

use crate::{
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

/// Number of fixed slots in BridgeAggChainCircuit.
pub const BRIDGE_AGG_CHAIN_MAX_SLOTS: usize = 32;

/// BridgeAggChainCircuit public input length (21 felts):
///   [0..4)   start_chain_hash
///   [4..8)   end_chain_hash
///   [8..12)  start_checkpoint_tree_root
///   [12..16) end_checkpoint_tree_root
///   [16..20) end_checkpoint_leaf_hash
///   [20]     num_checkpoints_aggregated
pub const BRIDGE_AGG_CHAIN_PI_LEN: usize = 21;

/// Per-slot witness data for BridgeAggChainCircuit.
///
/// Each active slot requires the root/leaf values of the checkpoint state
/// transition. The chain circuit uses only new_root and new_leaf to compute
/// step_commit = H(H(new_root, new_leaf), base_fingerprint). old_root is
/// only needed for start_checkpoint_tree_root tracking.
pub struct BridgeAggChainSlotWitness<F: Field> {
    pub old_checkpoint_tree_root: QHashOut<F>,
    pub new_checkpoint_tree_root: QHashOut<F>,
    pub new_checkpoint_leaf_hash: QHashOut<F>,
}

/// BridgeAggChainCircuit: pure hash-chain checkpoint aggregation circuit.
///
/// Has BRIDGE_AGG_CHAIN_MAX_SLOTS (32) slots. The first `active_len` slots
/// are real checkpoint steps; the rest are padding (no ZERO constraints on
/// preimages — FinalCircuit handles padding).
///
/// ## Constraint model
/// Each active slot:
/// 1. Computes `step_commit = H(H(new_root_i, new_leaf_i), base_fingerprint)`
/// 2. Advances chain: `chain_{i+1} = H(chain_i, step_commit_i)`
/// 3. Tracks first old_root as `start_checkpoint_tree_root`
/// 4. Tracks last new_root/new_leaf as terminal values
///
/// Inactive slots are simply selected away — no constraint on their witness
/// values (they can be arbitrary, the circuit just doesn't use them).
///
/// ## Public inputs (21 felts)
///   [0..4)   start_chain_hash
///   [4..8)   end_chain_hash
///   [8..12)  start_checkpoint_tree_root
///   [12..16) end_checkpoint_tree_root
///   [16..20) end_checkpoint_leaf_hash
///   [20]     num_checkpoints_aggregated
#[derive(Debug)]
pub struct BridgeAggChainCircuit<C: GenericConfig<D>, const D: usize> {
    pub active_len: Target,

    // Per-slot targets
    pub old_roots: Vec<HashOutTarget>,
    pub new_roots: Vec<HashOutTarget>,
    pub new_leafs: Vec<HashOutTarget>,
    pub is_active_flags: Vec<BoolTarget>,

    // Public input targets
    pub start_chain_hash: HashOutTarget,
    pub end_chain_hash: HashOutTarget,
    pub start_checkpoint_tree_root: HashOutTarget,
    pub end_checkpoint_tree_root: HashOutTarget,
    pub end_checkpoint_leaf_hash: HashOutTarget,
    pub num_checkpoints_aggregated: Target,

    // Base fingerprint for step_commit computation
    pub base_fingerprint_val: QHashOut<C::F>,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> BridgeAggChainCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: RichField + Extendable<D>,
{
    /// Build the pure hash-chain BridgeAggChainCircuit.
    ///
    /// Parameters:
    /// - `known_base_fingerprint`: fingerprint of the checkpoint state transition circuit
    ///   used in step_commit hash computation: `step_commit = H(H(new_root, new_leaf), base_fingerprint)`
    pub fn new(
        _checkpoint_state_transition_common_data: &CommonCircuitData<C::F, D>,
        _checkpoint_state_transition_cap_height: usize,
        _known_checkpoint_state_transition_fingerprint: QHashOut<C::F>,
        known_base_fingerprint: QHashOut<C::F>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        // ── Circuit-level constants ──
        let base_fingerprint_target = builder.constant_qhash(known_base_fingerprint);
        let zero_hash = builder.constant_qhash(QHashOut::ZERO);
        let zero = builder.zero();
        let one = builder.one();
        let max_slots = builder.constant_u64(BRIDGE_AGG_CHAIN_MAX_SLOTS as u64);

        // ── Active length (witness, 1 <= active_len <= 32) ──
        let active_len = builder.add_virtual_target();
        let ge_one = builder.is_less_than_or_equal(16, one, active_len);
        builder.assert_one(ge_one.target);
        let le_max = builder.is_less_than_or_equal(16, active_len, max_slots);
        builder.assert_one(le_max.target);

        // ── Create per-slot hash targets ──
        let mut old_roots = Vec::with_capacity(BRIDGE_AGG_CHAIN_MAX_SLOTS);
        let mut new_roots = Vec::with_capacity(BRIDGE_AGG_CHAIN_MAX_SLOTS);
        let mut new_leafs = Vec::with_capacity(BRIDGE_AGG_CHAIN_MAX_SLOTS);
        let mut is_active_flags = Vec::with_capacity(BRIDGE_AGG_CHAIN_MAX_SLOTS);

        for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
            let slot_idx = builder.constant_u64((i + 1) as u64);
            let is_active = builder.is_less_than_or_equal(16, slot_idx, active_len);
            old_roots.push(builder.add_virtual_hash());
            new_roots.push(builder.add_virtual_hash());
            new_leafs.push(builder.add_virtual_hash());
            is_active_flags.push(is_active);
        }

        // ── Build constraints ──
        let start_chain_hash_target = builder.add_virtual_hash();
        let mut chain_in = start_chain_hash_target;
        let mut rolling_new_root = zero_hash;
        let mut rolling_new_leaf = zero_hash;
        let mut rolling_count = zero;
        let mut seen_first = zero;
        let mut start_root = zero_hash;

        for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
            let is_active_t = is_active_flags[i].target;

            // step_commit = H(H(new_root, new_leaf), base_fingerprint)
            let root_leaf_pair = builder.hash_two_to_one::<C::Hasher>(new_roots[i], new_leafs[i]);
            let step_commit = builder.hash_two_to_one::<C::Hasher>(root_leaf_pair, base_fingerprint_target);

            // chain_{i+1} = is_active ? H(chain_i, step_commit) : chain_i
            let active_chain = builder.hash_two_to_one::<C::Hasher>(chain_in, step_commit);
            let chain_out = builder.select_hash(is_active_flags[i], active_chain, chain_in);

            // Rolling terminal state (track last active slot's new_root/new_leaf)
            let next_rolling_root = select_hash_elemwise(
                &mut builder, is_active_flags[i], new_roots[i], rolling_new_root,
            );
            let next_rolling_leaf = select_hash_elemwise(
                &mut builder, is_active_flags[i], new_leafs[i], rolling_new_leaf,
            );

            // Rolling count
            let count_inc = builder.add(rolling_count, is_active_t);
            let next_rolling_count = builder.select(is_active_flags[i], count_inc, rolling_count);

            // Track first active slot's old_root as start_checkpoint_tree_root
            let not_seen = builder.sub(one, seen_first);
            let just_seen = builder.mul(is_active_t, not_seen);
            let next_start_root = select_hash_elemwise_mul(
                &mut builder, just_seen, old_roots[i], start_root,
            );
            // Update seen_first: if we just saw the first active, set to 1
            let ac = is_active_t;
            let m = builder.mul(seen_first, ac);
            let sub = builder.sub(ac, m);
            seen_first = builder.add(seen_first, sub);

            chain_in = chain_out;
            rolling_new_root = next_rolling_root;
            rolling_new_leaf = next_rolling_leaf;
            rolling_count = next_rolling_count;
            start_root = next_start_root;
        }

        // ── Register public inputs (21 felts) ──
        // [0..4)  start_chain_hash
        builder.register_public_inputs(&start_chain_hash_target.elements);
        // [4..8)  end_chain_hash
        builder.register_public_inputs(&chain_in.elements);
        // [8..12) start_checkpoint_tree_root
        builder.register_public_inputs(&start_root.elements);
        // [12..16) end_checkpoint_tree_root
        builder.register_public_inputs(&rolling_new_root.elements);
        // [16..20) end_checkpoint_leaf_hash
        builder.register_public_inputs(&rolling_new_leaf.elements);
        // [20] num_checkpoints_aggregated
        builder.register_public_input(rolling_count);

        builder.add_qed_type_d_common_gates();
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            active_len,
            old_roots,
            new_roots,
            new_leafs,
            is_active_flags,
            start_chain_hash: start_chain_hash_target,
            end_chain_hash: chain_in,
            start_checkpoint_tree_root: start_root,
            end_checkpoint_tree_root: rolling_new_root,
            end_checkpoint_leaf_hash: rolling_new_leaf,
            num_checkpoints_aggregated: rolling_count,
            base_fingerprint_val: known_base_fingerprint,
            circuit_data,
            fingerprint,
        }
    }

    /// Generate a BridgeAggChainCircuit proof.
    ///
    /// `active_len`: number of active checkpoint slots (1..=32).
    /// `start_chain_hash`: the chain hash BEFORE the first slot.
    ///                     If aggregating from checkpoint 1, use the genesis chain hash = H(H(root_0, leaf_0), genesis_fingerprint).
    ///                     If aggregating from checkpoint N>1, use checkpoint (N-1)'s proof public-input hash.
    /// `slots`: exactly BRIDGE_AGG_CHAIN_MAX_SLOTS entries; only the first
    ///          `active_len` are used as active slots.
    pub fn prove_base(
        &self,
        active_len: u64,
        start_chain_hash: QHashOut<C::F>,
        slots: &[BridgeAggChainSlotWitness<C::F>],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(
            slots.len() == BRIDGE_AGG_CHAIN_MAX_SLOTS,
            "slots must be exactly {} entries, got {}",
            BRIDGE_AGG_CHAIN_MAX_SLOTS,
            slots.len()
        );
        anyhow::ensure!(
            active_len >= 1 && active_len <= BRIDGE_AGG_CHAIN_MAX_SLOTS as u64,
            "active_len must be in [1, {}], got {}",
            BRIDGE_AGG_CHAIN_MAX_SLOTS,
            active_len
        );

        let mut pw = PartialWitness::<C::F>::new();
        pw.set_target(self.active_len, C::F::from_canonical_u64(active_len))?;
        pw.set_hash_target(self.start_chain_hash, start_chain_hash.0)?;

        for (i, slot) in slots.iter().enumerate() {
            pw.set_hash_target(self.old_roots[i], slot.old_checkpoint_tree_root.0)?;
            pw.set_hash_target(self.new_roots[i], slot.new_checkpoint_tree_root.0)?;
            pw.set_hash_target(self.new_leafs[i], slot.new_checkpoint_leaf_hash.0)?;
        }

        self.circuit_data.prove(pw)
    }
}

/// Element-wise hash select: condition ? true_val : false_val using BoolTarget.
fn select_hash_elemwise<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    cond: BoolTarget,
    true_val: HashOutTarget,
    false_val: HashOutTarget,
) -> HashOutTarget {
    HashOutTarget {
        elements: array::from_fn(|j| builder.select(cond, true_val.elements[j], false_val.elements[j])),
    }
}

/// Element-wise hash select using a plain 0/1 Target (not BoolTarget).
fn select_hash_elemwise_mul<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    cond: Target,
    true_val: HashOutTarget,
    false_val: HashOutTarget,
) -> HashOutTarget {
    let one = builder.one();
    let not_cond = builder.sub(one, cond);
    HashOutTarget {
        elements: array::from_fn(|j| {
            let t = builder.mul(cond, true_val.elements[j]);
            let f = builder.mul(not_cond, false_val.elements[j]);
            builder.add(t, f)
        }),
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for BridgeAggChainCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(
        &self,
    ) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(
        &self,
    ) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}
