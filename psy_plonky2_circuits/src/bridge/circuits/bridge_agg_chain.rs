use hashbrown::HashMap;

use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleZeroHasher},
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    gates::noop::NoopGate,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data,
        dummy_circuit::cyclic_base_proof,
    },
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison,
    core::CircuitBuilderHelpersCore,
    hash::core::CircuitBuilderHashCore,
    pad_circuit::CircuitBuilderQEDCommonGates,
    select::CircuitBuilderSelectHelpers,
};
use psy_plonky2_common_circuits::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;

use crate::{
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

/// Number of checkpoint-data slots appended by one positive-length chain proof.
pub const BRIDGE_AGG_CHAIN_MAX_SLOTS: usize = 32;

/// Stable bridge business-public-input prefix length.
///
/// Cyclic verifier-data public inputs follow this prefix.
pub const BRIDGE_AGG_CHAIN_PI_LEN: usize = 23;
const BRIDGE_AGG_CHAIN_CYCLIC_DEGREE_BITS: usize = 13;
/// Goldilocks modulus; checkpoint indices must be canonical field elements.
pub(super) const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

#[derive(Debug, Clone, Copy)]
pub struct BridgeAggChainBoundary<F: Field> {
    pub chain_hash: QHashOut<F>,
    pub checkpoint_tree_root: QHashOut<F>,
    pub checkpoint_leaf_hash: QHashOut<F>,
    /// Checkpoint index immediately before the aggregated range starts.
    pub checkpoint_index: u64,
}

pub struct BridgeAggChainSlotWitness<'a, F: Field> {
    pub checkpoint_delta_merkle_proof: &'a DeltaMerkleProofCore<QHashOut<F>>,
}

/// One cyclic circuit represents both the zero-step identity proof and every
/// positive-length recursive Chain proof.
///
/// Business public inputs:
///   [0..4)   start_chain_hash
///   [4..8)   end_chain_hash
///   [8..12)  start_checkpoint_tree_root
///   [12..16) end_checkpoint_tree_root
///   [16..20) end_checkpoint_leaf_hash
///   [20]     cumulative num_checkpoints_aggregated
///   [21]     start_checkpoint_index (the index immediately before the range)
///   [22]     end_checkpoint_index
///   [23..]   cyclic verifier data
#[derive(Debug)]
pub struct BridgeAggChainCircuit<C: GenericConfig<D>, const D: usize> {
    pub active_len: Target,
    pub previous_chain_proof_target: ProofWithPublicInputsTarget<D>,
    pub cyclic_verifier_data_target: VerifierCircuitTarget,
    pub checkpoint_delta_merkle_proofs: Vec<DeltaMerkleProofGadget>,
    pub is_active_flags: Vec<BoolTarget>,
    pub base_chain_hash: HashOutTarget,
    pub base_checkpoint_tree_root: HashOutTarget,
    pub base_checkpoint_leaf_hash: HashOutTarget,
    pub base_checkpoint_index: Target,
    pub start_chain_hash: HashOutTarget,
    pub end_chain_hash: HashOutTarget,
    pub start_checkpoint_tree_root: HashOutTarget,
    pub end_checkpoint_tree_root: HashOutTarget,
    pub end_checkpoint_leaf_hash: HashOutTarget,
    pub num_checkpoints_aggregated: Target,
    pub start_checkpoint_index: Target,
    pub end_checkpoint_index: Target,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> BridgeAggChainCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: RichField + Extendable<D>,
{
    pub fn new(
        known_base_fingerprint: QHashOut<C::F>,
        checkpoint_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let zero = builder.zero();
        let one = builder.one();
        let max_slots = builder.constant_u64(BRIDGE_AGG_CHAIN_MAX_SLOTS as u64);
        let base_fingerprint_target = builder.constant_qhash(known_base_fingerprint);

        let active_len = builder.add_virtual_target();
        let active_len_in_range = builder.is_less_than_or_equal(16, active_len, max_slots);
        builder.assert_one(active_len_in_range.target);
        let is_base = builder.is_equal(active_len, zero);
        let has_previous = builder.not(is_base);

        let base_chain_hash = builder.add_virtual_hash();
        let base_checkpoint_tree_root = builder.add_virtual_hash();
        let base_checkpoint_leaf_hash = builder.add_virtual_hash();
        let base_checkpoint_index = builder.add_virtual_target();

        let mut checkpoint_delta_merkle_proofs =
            Vec::with_capacity(BRIDGE_AGG_CHAIN_MAX_SLOTS);
        let mut is_active_flags = Vec::with_capacity(BRIDGE_AGG_CHAIN_MAX_SLOTS);
        for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
            let slot_index = builder.constant_u64(i as u64);
            let is_active = builder.is_less_than(16, slot_index, active_len);
            checkpoint_delta_merkle_proofs.push(
                DeltaMerkleProofGadget::add_virtual_to_append_only::<C::Hasher, C::F, D>(
                    &mut builder,
                    checkpoint_tree_height,
                ),
            );
            is_active_flags.push(is_active);
        }

        builder.add_qed_type_d_common_gates();

        let mut cyclic_common_data = cyclic_common_data::<C, D>(checkpoint_tree_height);
        let cyclic_verifier_pi_len =
            4 + 4 * cyclic_common_data.config.fri_config.num_cap_elements();
        cyclic_common_data.num_public_inputs =
            BRIDGE_AGG_CHAIN_PI_LEN + cyclic_verifier_pi_len;
        let previous_chain_proof_target = builder.add_virtual_proof_with_pis(&cyclic_common_data);
        let previous_pis = &previous_chain_proof_target.public_inputs;

        let previous_start_chain_hash = pi_hash(previous_pis, 0);
        let previous_end_chain_hash = pi_hash(previous_pis, 4);
        let previous_start_checkpoint_tree_root = pi_hash(previous_pis, 8);
        let previous_end_checkpoint_tree_root = pi_hash(previous_pis, 12);
        let previous_end_checkpoint_leaf_hash = pi_hash(previous_pis, 16);
        let previous_count = previous_pis[20];
        let previous_start_checkpoint_index = previous_pis[21];
        let previous_end_checkpoint_index = previous_pis[22];

        let start_chain_hash = builder.select_hash(
            has_previous,
            previous_start_chain_hash,
            base_chain_hash,
        );
        let mut rolling_chain_hash = builder.select_hash(
            has_previous,
            previous_end_chain_hash,
            base_chain_hash,
        );
        let start_checkpoint_tree_root = builder.select_hash(
            has_previous,
            previous_start_checkpoint_tree_root,
            base_checkpoint_tree_root,
        );
        let mut rolling_checkpoint_tree_root = builder.select_hash(
            has_previous,
            previous_end_checkpoint_tree_root,
            base_checkpoint_tree_root,
        );
        let mut rolling_checkpoint_leaf_hash = builder.select_hash(
            has_previous,
            previous_end_checkpoint_leaf_hash,
            base_checkpoint_leaf_hash,
        );
        let mut rolling_count = builder.select(has_previous, previous_count, zero);
        let start_checkpoint_index = builder.select(
            has_previous,
            previous_start_checkpoint_index,
            base_checkpoint_index,
        );
        let mut rolling_checkpoint_index = builder.select(
            has_previous,
            previous_end_checkpoint_index,
            base_checkpoint_index,
        );

        for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
            let is_active = is_active_flags[i];
            let delta = &checkpoint_delta_merkle_proofs[i];

            for j in 0..4 {
                let root_diff = builder.sub(
                    delta.old_root.elements[j],
                    rolling_checkpoint_tree_root.elements[j],
                );
                let active_root_diff = builder.mul(is_active.target, root_diff);
                builder.assert_zero(active_root_diff);
            }

            let expected_index = builder.add(rolling_checkpoint_index, one);
            let index_diff = builder.sub(delta.index, expected_index);
            let active_index_diff = builder.mul(is_active.target, index_diff);
            builder.assert_zero(active_index_diff);

            let root_leaf =
                builder.hash_two_to_one::<C::Hasher>(delta.new_root, delta.new_value);
            let step_commit =
                builder.hash_two_to_one::<C::Hasher>(root_leaf, base_fingerprint_target);
            let advanced_chain =
                builder.hash_two_to_one::<C::Hasher>(rolling_chain_hash, step_commit);

            rolling_chain_hash =
                builder.select_hash(is_active, advanced_chain, rolling_chain_hash);
            rolling_checkpoint_tree_root = builder.select_hash(
                is_active,
                delta.new_root,
                rolling_checkpoint_tree_root,
            );
            rolling_checkpoint_leaf_hash = builder.select_hash(
                is_active,
                delta.new_value,
                rolling_checkpoint_leaf_hash,
            );
            let incremented_count = builder.add(rolling_count, is_active.target);
            rolling_count = builder.select(is_active, incremented_count, rolling_count);
            rolling_checkpoint_index =
                builder.select(is_active, delta.index, rolling_checkpoint_index);
        }

        let index_span = builder.sub(rolling_checkpoint_index, start_checkpoint_index);
        builder.connect(index_span, rolling_count);

        builder.register_public_inputs(&start_chain_hash.elements);
        builder.register_public_inputs(&rolling_chain_hash.elements);
        builder.register_public_inputs(&start_checkpoint_tree_root.elements);
        builder.register_public_inputs(&rolling_checkpoint_tree_root.elements);
        builder.register_public_inputs(&rolling_checkpoint_leaf_hash.elements);
        builder.register_public_input(rolling_count);
        builder.register_public_input(start_checkpoint_index);
        builder.register_public_input(rolling_checkpoint_index);
        let cyclic_verifier_data_target = builder.add_verifier_data_public_inputs();
        assert_eq!(
            builder.num_public_inputs(),
            cyclic_common_data.num_public_inputs,
            "unexpected cyclic Chain PI layout"
        );

        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                has_previous,
                &previous_chain_proof_target,
                &cyclic_common_data,
            )
            .expect("failed to build cyclic BridgeAggChain verifier");

        // Pad to match cyclic_common_data degree
        while builder.num_gates() < 1 << BRIDGE_AGG_CHAIN_CYCLIC_DEGREE_BITS {
            builder.add_gate(NoopGate, vec![]);
        }
        let (circuit_data, common_data_matches) = builder.try_build_with_options::<C>(true);
        assert!(common_data_matches, "cyclic BridgeAggChain common data mismatch");
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            active_len,
            previous_chain_proof_target,
            cyclic_verifier_data_target,
            checkpoint_delta_merkle_proofs,
            is_active_flags,
            base_chain_hash,
            base_checkpoint_tree_root,
            base_checkpoint_leaf_hash,
            base_checkpoint_index,
            start_chain_hash,
            end_chain_hash: rolling_chain_hash,
            start_checkpoint_tree_root,
            end_checkpoint_tree_root: rolling_checkpoint_tree_root,
            end_checkpoint_leaf_hash: rolling_checkpoint_leaf_hash,
            num_checkpoints_aggregated: rolling_count,
            start_checkpoint_index,
            end_checkpoint_index: rolling_checkpoint_index,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove(
        &self,
        active_len: u64,
        base_boundary: BridgeAggChainBoundary<C::F>,
        slots: &[BridgeAggChainSlotWitness<'_, C::F>],
        previous_chain_proof: Option<&ProofWithPublicInputs<C::F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(
            base_boundary.checkpoint_index < GOLDILOCKS_MODULUS,
            "checkpoint_index must be smaller than the Goldilocks modulus"
        );
        anyhow::ensure!(
            active_len <= BRIDGE_AGG_CHAIN_MAX_SLOTS as u64,
            "active_len must be in [0, {}], got {}",
            BRIDGE_AGG_CHAIN_MAX_SLOTS,
            active_len
        );
        anyhow::ensure!(
            !slots.is_empty(),
            "at least one valid delta witness is required for fixed-slot padding"
        );
        anyhow::ensure!(
            slots.len() <= BRIDGE_AGG_CHAIN_MAX_SLOTS,
            "at most {} delta witnesses are accepted, got {}",
            BRIDGE_AGG_CHAIN_MAX_SLOTS,
            slots.len()
        );
        anyhow::ensure!(
            slots.len() >= active_len as usize,
            "delta witness length {} is smaller than active_len {}",
            slots.len(),
            active_len
        );
        anyhow::ensure!(
            (active_len == 0 && previous_chain_proof.is_none())
                || (active_len > 0 && previous_chain_proof.is_some()),
            "base mode requires no predecessor; positive-length mode requires one predecessor"
        );

        let mut pw = PartialWitness::<C::F>::new();
        pw.set_target(self.active_len, C::F::from_canonical_u64(active_len))?;
        pw.set_hash_target(self.base_chain_hash, base_boundary.chain_hash.0)?;
        pw.set_hash_target(
            self.base_checkpoint_tree_root,
            base_boundary.checkpoint_tree_root.0,
        )?;
        pw.set_hash_target(
            self.base_checkpoint_leaf_hash,
            base_boundary.checkpoint_leaf_hash.0,
        )?;
        pw.set_target(
            self.base_checkpoint_index,
            C::F::from_canonical_u64(base_boundary.checkpoint_index),
        )?;
        pw.set_verifier_data_target(
            &self.cyclic_verifier_data_target,
            &self.circuit_data.verifier_only,
        )?;

        let cyclic_predecessor = match previous_chain_proof {
            Some(proof) => proof.clone(),
            None => cyclic_base_proof(
                &self.circuit_data.common,
                &self.circuit_data.verifier_only,
                HashMap::new(),
            ),
        };
        pw.set_proof_with_pis_target(&self.previous_chain_proof_target, &cyclic_predecessor)?;

        let padding_slot = slots.last().expect("slots checked non-empty");
        for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
            let slot = slots.get(i).unwrap_or(padding_slot);
            self.checkpoint_delta_merkle_proofs[i]
                .set_witness_core_proof_q(&mut pw, slot.checkpoint_delta_merkle_proof)?;
        }

        let proof = self.circuit_data.prove(pw)?;
        check_cyclic_proof_verifier_data(
            &proof,
            &self.circuit_data.verifier_only,
            &self.circuit_data.common,
        )?;
        Ok(proof)
    }

    pub fn prove_base(
        &self,
        boundary: BridgeAggChainBoundary<C::F>,
        padding_delta: &DeltaMerkleProofCore<QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove(
            0,
            boundary,
            &[BridgeAggChainSlotWitness {
                checkpoint_delta_merkle_proof: padding_delta,
            }],
            None,
        )
    }

    #[cfg(test)]
    fn prove_with_witness_override(
        &self,
        active_len: u64,
        base_boundary: BridgeAggChainBoundary<C::F>,
        slots: &[BridgeAggChainSlotWitness<'_, C::F>],
        previous_chain_proof: Option<&ProofWithPublicInputs<C::F, C, D>>,
        end_chain_hash_override: Option<QHashOut<C::F>>,
        end_root_override: Option<QHashOut<C::F>>,
        end_leaf_override: Option<QHashOut<C::F>>,
        count_override: Option<u64>,
        end_index_override: Option<u64>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(!slots.is_empty(), "test slots must be non-empty");
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_target(self.active_len, C::F::from_canonical_u64(active_len))?;
        pw.set_hash_target(self.base_chain_hash, base_boundary.chain_hash.0)?;
        pw.set_hash_target(self.base_checkpoint_tree_root, base_boundary.checkpoint_tree_root.0)?;
        pw.set_hash_target(self.base_checkpoint_leaf_hash, base_boundary.checkpoint_leaf_hash.0)?;
        pw.set_target(self.base_checkpoint_index, C::F::from_canonical_u64(base_boundary.checkpoint_index))?;
        pw.set_verifier_data_target(&self.cyclic_verifier_data_target, &self.circuit_data.verifier_only)?;
        let predecessor = previous_chain_proof.cloned().unwrap_or_else(|| cyclic_base_proof(
            &self.circuit_data.common,
            &self.circuit_data.verifier_only,
            HashMap::new(),
        ));
        pw.set_proof_with_pis_target(&self.previous_chain_proof_target, &predecessor)?;
        let padding = slots.last().unwrap();
        for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
            let slot = slots.get(i).unwrap_or(padding);
            self.checkpoint_delta_merkle_proofs[i]
                .set_witness_core_proof_q(&mut pw, slot.checkpoint_delta_merkle_proof)?;
        }
        if let Some(value) = end_chain_hash_override {
            pw.set_hash_target(self.end_chain_hash, value.0)?;
        }
        if let Some(value) = end_root_override {
            pw.set_hash_target(self.end_checkpoint_tree_root, value.0)?;
        }
        if let Some(value) = end_leaf_override {
            pw.set_hash_target(self.end_checkpoint_leaf_hash, value.0)?;
        }
        if let Some(value) = count_override {
            pw.set_target(self.num_checkpoints_aggregated, C::F::from_canonical_u64(value))?;
        }
        if let Some(value) = end_index_override {
            pw.set_target(self.end_checkpoint_index, C::F::from_canonical_u64(value))?;
        }
        self.circuit_data.prove(pw)
    }
}

fn cyclic_common_data<C: GenericConfig<D>, const D: usize>(
    checkpoint_tree_height: usize,
) -> CommonCircuitData<C::F, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: RichField + Extendable<D>,
{
    use psy_plonky2_common_circuits::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;

    // Stage 1: seed every gate type the Chain circuit uses
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<C::F, D>::new(config);
    builder.add_qed_type_d_common_gates();
    let zero = builder.zero();
    let _ = builder.is_less_than_or_equal(16, zero, zero);
    let _ = DeltaMerkleProofGadget::add_virtual_to_append_only::<C::Hasher, C::F, D>(
        &mut builder, checkpoint_tree_height,
    );
    let h0 = builder.add_virtual_hash();
    let h1 = builder.add_virtual_hash();
    let sel = builder.add_virtual_bool_target_safe();
    let _ = builder.select_hash(sel, h0, h1);
    let _ = builder.hash_two_to_one::<C::Hasher>(h0, h1);
    let one = builder.one();
    let _ = builder.sub(h0.elements[0], one);
    let _ = builder.mul(sel.target, h0.elements[0]);
    let _ = builder.add(h0.elements[0], h1.elements[0]);
    let data = builder.build::<C>();

    // Stage 2: verify a proof from stage 1
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<C::F, D>::new(config);
    builder.add_qed_type_d_common_gates();
    let zero = builder.zero();
    let _ = builder.is_less_than_or_equal(16, zero, zero);
    let _ = DeltaMerkleProofGadget::add_virtual_to_append_only::<C::Hasher, C::F, D>(
        &mut builder, checkpoint_tree_height,
    );
    let h0 = builder.add_virtual_hash();
    let h1 = builder.add_virtual_hash();
    let sel = builder.add_virtual_bool_target_safe();
    let _ = builder.select_hash(sel, h0, h1);
    let _ = builder.hash_two_to_one::<C::Hasher>(h0, h1);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    // Stage 3: final + padding
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<C::F, D>::new(config);
    builder.add_qed_type_d_common_gates();
    let zero = builder.zero();
    let _ = builder.is_less_than_or_equal(16, zero, zero);
    let _ = DeltaMerkleProofGadget::add_virtual_to_append_only::<C::Hasher, C::F, D>(
        &mut builder, checkpoint_tree_height,
    );
    let h0 = builder.add_virtual_hash();
    let h1 = builder.add_virtual_hash();
    let sel = builder.add_virtual_bool_target_safe();
    let _ = builder.select_hash(sel, h0, h1);
    let _ = builder.hash_two_to_one::<C::Hasher>(h0, h1);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << BRIDGE_AGG_CHAIN_CYCLIC_DEGREE_BITS {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

fn pi_hash(pis: &[Target], start: usize) -> HashOutTarget {
    HashOutTarget {
        elements: [pis[start], pis[start + 1], pis[start + 2], pis[start + 3]],
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

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::crypto::hash::{
        merkle_proof::compute_root_merkle_proof_generic,
        traits::{MerkleHasher, MerkleZeroHasher},
    };
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, PrimeField64},
        },
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
        plonk::config::{Hasher, PoseidonGoldilocksConfig},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    fn qhash(seed: u64) -> QHashOut<F> {
        QHashOut(HashOut {
            elements: [
                F::from_canonical_u64(seed),
                F::from_canonical_u64(seed + 1),
                F::from_canonical_u64(seed + 2),
                F::from_canonical_u64(seed + 3),
            ],
        })
    }

    fn merkle_root(leaves: &[QHashOut<F>]) -> QHashOut<F> {
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = level
                .chunks_exact(2)
                .map(|pair| {
                    <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&pair[0], &pair[1])
                })
                .collect();
        }
        level[0]
    }

    fn merkle_siblings(leaves: &[QHashOut<F>], index: usize) -> Vec<QHashOut<F>> {
        let mut level = leaves.to_vec();
        let mut cursor = index;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            siblings.push(level[cursor ^ 1]);
            level = level
                .chunks_exact(2)
                .map(|pair| {
                    <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&pair[0], &pair[1])
                })
                .collect();
            cursor >>= 1;
        }
        siblings
    }

    fn append_at(
        leaves: &mut [QHashOut<F>],
        index: usize,
        new_value: QHashOut<F>,
    ) -> DeltaMerkleProofCore<QHashOut<F>> {
        let old_root = merkle_root(leaves);
        let siblings = merkle_siblings(leaves, index);
        leaves[index] = new_value;
        let new_root = merkle_root(leaves);
        DeltaMerkleProofCore {
            old_root,
            old_value: QHashOut::ZERO,
            new_root,
            new_value,
            index: index as u64,
            siblings,
        }
    }

    fn sequential_deltas(
        start_index: usize,
        count: usize,
        height: usize,
    ) -> Vec<DeltaMerkleProofCore<QHashOut<F>>> {
        let mut leaves = vec![QHashOut::ZERO; 1 << height];
        let mut deltas = Vec::with_capacity(count);
        for index in 0..start_index {
            let _ = append_at(&mut leaves, index, qhash(1_000 + index as u64 * 10));
        }
        for index in start_index..start_index + count {
            deltas.push(append_at(
                &mut leaves,
                index,
                qhash(10_000 + index as u64 * 10),
            ));
        }
        deltas
    }

    fn boundary(
        checkpoint_tree_root: QHashOut<F>,
        checkpoint_index: u64,
    ) -> BridgeAggChainBoundary<F> {
        BridgeAggChainBoundary {
            chain_hash: qhash(10),
            checkpoint_tree_root,
            checkpoint_leaf_hash: qhash(30),
            checkpoint_index,
        }
    }

    fn business_hash(proof: &ProofWithPublicInputs<F, C, D>, start: usize) -> QHashOut<F> {
        QHashOut(HashOut {
            elements: proof.public_inputs[start..start + 4].try_into().unwrap(),
        })
    }

    fn fold_chain(
        mut chain: QHashOut<F>,
        deltas: &[DeltaMerkleProofCore<QHashOut<F>>],
        base_fingerprint: QHashOut<F>,
    ) -> QHashOut<F> {
        for delta in deltas {
            let root_leaf = QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(
                delta.new_root.0,
                delta.new_value.0,
            ));
            let step_commit = QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(
                root_leaf.0,
                base_fingerprint.0,
            ));
            chain = QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(
                chain.0,
                step_commit.0,
            ));
        }
        chain
    }
    fn make_base(
        circuit: &BridgeAggChainCircuit<C, D>,
        deltas: &[DeltaMerkleProofCore<QHashOut<F>>],
        checkpoint_index: u64,
    ) -> (BridgeAggChainBoundary<F>, ProofWithPublicInputs<F, C, D>) {
        let boundary = boundary(deltas[0].old_root, checkpoint_index);
        let proof = circuit.prove_base(boundary, &deltas[0]).unwrap();
        (boundary, proof)
    }

    fn slot_witnesses(
        deltas: &[DeltaMerkleProofCore<QHashOut<F>>],
    ) -> Vec<BridgeAggChainSlotWitness<'_, F>> {
        deltas
            .iter()
            .map(|checkpoint_delta_merkle_proof| BridgeAggChainSlotWitness {
                checkpoint_delta_merkle_proof,
            })
            .collect()
    }

    fn assert_business_pis(
        proof: &ProofWithPublicInputs<F, C, D>,
        expected_start_chain: QHashOut<F>,
        expected_end_chain: QHashOut<F>,
        expected_start_root: QHashOut<F>,
        expected_end_root: QHashOut<F>,
        expected_end_leaf: QHashOut<F>,
        expected_count: u64,
        expected_start_index: u64,
        expected_end_index: u64,
    ) {
        assert_eq!(business_hash(proof, 0), expected_start_chain);
        assert_eq!(business_hash(proof, 4), expected_end_chain);
        assert_eq!(business_hash(proof, 8), expected_start_root);
        assert_eq!(business_hash(proof, 12), expected_end_root);
        assert_eq!(business_hash(proof, 16), expected_end_leaf);
        assert_eq!(proof.public_inputs[20].to_canonical_u64(), expected_count);
        assert_eq!(proof.public_inputs[21].to_canonical_u64(), expected_start_index);
        assert_eq!(proof.public_inputs[22].to_canonical_u64(), expected_end_index);
    }

    #[test]
    fn chain_base_mode_emits_same_circuit_identity_proof() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 2);
        let padding = sequential_deltas(1, 1, 2).remove(0);
        let boundary = boundary(padding.old_root, 7);
        let proof = circuit.prove_base(boundary, &padding).unwrap();

        circuit.circuit_data.verify(proof.clone()).unwrap();
        assert_eq!(BRIDGE_AGG_CHAIN_PI_LEN, 23);
        assert_eq!(business_hash(&proof, 0), boundary.chain_hash);
        assert_eq!(business_hash(&proof, 4), boundary.chain_hash);
        assert_eq!(business_hash(&proof, 8), boundary.checkpoint_tree_root);
        assert_eq!(business_hash(&proof, 12), boundary.checkpoint_tree_root);
        assert_eq!(business_hash(&proof, 16), boundary.checkpoint_leaf_hash);
        assert_eq!(proof.public_inputs[20].to_canonical_u64(), 0);
        assert_eq!(proof.public_inputs[21].to_canonical_u64(), 7);
        assert_eq!(proof.public_inputs[22].to_canonical_u64(), 7);
        check_cyclic_proof_verifier_data(
            &proof,
            &circuit.circuit_data.verifier_only,
            &circuit.circuit_data.common,
        )
        .unwrap();
    }

    #[test]
    fn chain_recursive_tracks_contiguous_indices_and_count() {
        let height = 3;
        let base_fingerprint = qhash(900);
        let circuit = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, height);
        let deltas = sequential_deltas(1, 2, height);
        let boundary = boundary(deltas[0].old_root, 0);
        let base = circuit.prove_base(boundary, &deltas[0]).unwrap();
        let slots = deltas
            .iter()
            .map(|checkpoint_delta_merkle_proof| BridgeAggChainSlotWitness {
                checkpoint_delta_merkle_proof,
            })
            .collect::<Vec<_>>();
        let proof = circuit.prove(2, boundary, &slots, Some(&base)).unwrap();

        circuit.circuit_data.verify(proof.clone()).unwrap();
        assert_eq!(
            business_hash(&proof, 4),
            fold_chain(boundary.chain_hash, &deltas, base_fingerprint)
        );
        assert_eq!(proof.public_inputs[20].to_canonical_u64(), 2);
        assert_eq!(proof.public_inputs[21].to_canonical_u64(), 0);
        assert_eq!(proof.public_inputs[22].to_canonical_u64(), 2);
    }

    #[test]
    fn chain_recursive_rejects_skipped_checkpoint_index() {
        let height = 3;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let mut leaves = vec![QHashOut::ZERO; 1 << height];
        let _prior = append_at(&mut leaves, 0, qhash(50));
        let first = append_at(&mut leaves, 1, qhash(100));
        let skipped = append_at(&mut leaves, 3, qhash(300));
        let boundary = boundary(first.old_root, 0);
        let base = circuit.prove_base(boundary, &first).unwrap();
        let slots = [
            BridgeAggChainSlotWitness {
                checkpoint_delta_merkle_proof: &first,
            },
            BridgeAggChainSlotWitness {
                checkpoint_delta_merkle_proof: &skipped,
            },
        ];

        assert!(circuit.prove(2, boundary, &slots, Some(&base)).is_err());
    }

    #[test]
    fn chain_recursive_rejects_first_index_gap_after_previous_chunk() {
        let height = 3;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let mut leaves = vec![QHashOut::ZERO; 1 << height];
        let _prior = append_at(&mut leaves, 0, qhash(50));
        let first = append_at(&mut leaves, 1, qhash(100));
        let skipped = append_at(&mut leaves, 3, qhash(300));
        let boundary = boundary(first.old_root, 0);
        let base = circuit.prove_base(boundary, &first).unwrap();
        let first_proof = circuit
            .prove(
                1,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &first,
                }],
                Some(&base),
            )
            .unwrap();

        assert!(circuit
            .prove(
                1,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &skipped,
                }],
                Some(&first_proof),
            )
            .is_err());
    }

    #[test]
    fn chain_recursive_accepts_next_index_after_previous_chunk() {
        let height = 3;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let deltas = sequential_deltas(1, 2, height);
        let boundary = boundary(deltas[0].old_root, 0);
        let base = circuit.prove_base(boundary, &deltas[0]).unwrap();
        let first = circuit
            .prove(
                1,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &deltas[0],
                }],
                Some(&base),
            )
            .unwrap();
        let second = circuit
            .prove(
                1,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &deltas[1],
                }],
                Some(&first),
            )
            .unwrap();

        assert_eq!(second.public_inputs[20].to_canonical_u64(), 2);
        assert_eq!(second.public_inputs[21].to_canonical_u64(), 0);
        assert_eq!(second.public_inputs[22].to_canonical_u64(), 2);
    }

    #[test]
    fn chain_recursive_inactive_suffix_does_not_advance_index() {
        let height = 3;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let deltas = sequential_deltas(1, 2, height);
        let boundary = boundary(deltas[0].old_root, 0);
        let base = circuit.prove_base(boundary, &deltas[0]).unwrap();
        let slots = [
            BridgeAggChainSlotWitness {
                checkpoint_delta_merkle_proof: &deltas[0],
            },
            BridgeAggChainSlotWitness {
                checkpoint_delta_merkle_proof: &deltas[1],
            },
        ];
        let proof = circuit.prove(1, boundary, &slots, Some(&base)).unwrap();

        assert_eq!(proof.public_inputs[20].to_canonical_u64(), 1);
        assert_eq!(proof.public_inputs[21].to_canonical_u64(), 0);
        assert_eq!(proof.public_inputs[22].to_canonical_u64(), 1);
    }

    #[test]
    fn chain_rejects_noncanonical_base_checkpoint_index() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 1);
        let old_value = QHashOut::ZERO;
        let siblings = vec![QHashOut::ZERO];
        let padding = DeltaMerkleProofCore {
            old_root: compute_root_merkle_proof_generic::<_, PoseidonHash>(old_value, 0, &siblings),
            old_value,
            new_root: compute_root_merkle_proof_generic::<_, PoseidonHash>(qhash(200), 0, &siblings),
            new_value: qhash(200),
            index: 0,
            siblings,
        };
        let boundary = boundary(padding.old_root, GOLDILOCKS_MODULUS);
        let error = circuit.prove_base(boundary, &padding).unwrap_err();

        assert!(error.to_string().contains("Goldilocks modulus"));
    }

    #[test]
    fn chain_base_mode_accepts_zero_and_rejects_positive_count() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 2);
        let delta = sequential_deltas(1, 1, 2).remove(0);
        let boundary = boundary(delta.old_root, 7);

        circuit.prove_base(boundary, &delta).unwrap();
        assert!(circuit
            .prove_with_witness_override(
                0,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &delta,
                }],
                None,
                None,
                None,
                None,
                Some(1),
                None,
            )
            .is_err());
    }

    #[test]
    fn chain_base_mode_rejects_unequal_chain_boundaries() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 2);
        let delta = sequential_deltas(1, 1, 2).remove(0);
        let boundary = boundary(delta.old_root, 7);

        assert!(circuit
            .prove_with_witness_override(
                0,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &delta,
                }],
                None,
                Some(qhash(80_000)),
                None,
                None,
                None,
                None,
            )
            .is_err());
    }

    #[test]
    fn chain_base_mode_rejects_unequal_root_boundaries() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 2);
        let delta = sequential_deltas(1, 1, 2).remove(0);
        let boundary = boundary(delta.old_root, 7);

        assert!(circuit
            .prove_with_witness_override(
                0,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &delta,
                }],
                None,
                None,
                Some(qhash(81_000)),
                None,
                None,
                None,
            )
            .is_err());
    }

    #[test]
    fn chain_base_mode_rejects_inconsistent_boundary_leaf() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 2);
        let delta = sequential_deltas(1, 1, 2).remove(0);
        let boundary = boundary(delta.old_root, 7);

        assert!(circuit
            .prove_with_witness_override(
                0,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &delta,
                }],
                None,
                None,
                None,
                Some(qhash(82_000)),
                None,
                None,
            )
            .is_err());
    }

    #[test]
    fn chain_base_mode_inactive_delta_witness_cannot_change_pis() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 3);
        let first = sequential_deltas(1, 1, 3).remove(0);
        let second = sequential_deltas(4, 1, 3).remove(0);
        let boundary = boundary(first.old_root, 17);
        let first_proof = circuit.prove_base(boundary, &first).unwrap();
        let second_proof = circuit.prove_base(boundary, &second).unwrap();

        assert_eq!(
            &first_proof.public_inputs[..BRIDGE_AGG_CHAIN_PI_LEN],
            &second_proof.public_inputs[..BRIDGE_AGG_CHAIN_PI_LEN]
        );
    }

    #[test]
    fn chain_recursive_one_step_consumes_base_proof() {
        let height = 2;
        let base_fingerprint = qhash(900);
        let circuit = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, height);
        let deltas = sequential_deltas(1, 1, height);
        let (boundary, base) = make_base(&circuit, &deltas, 0);
        let proof = circuit
            .prove(1, boundary, &slot_witnesses(&deltas), Some(&base))
            .unwrap();

        circuit.circuit_data.verify(proof.clone()).unwrap();
        assert_business_pis(
            &proof,
            boundary.chain_hash,
            fold_chain(boundary.chain_hash, &deltas, base_fingerprint),
            boundary.checkpoint_tree_root,
            deltas[0].new_root,
            deltas[0].new_value,
            1,
            0,
            1,
        );
    }

    #[test]
    fn chain_recursive_32_steps_consumes_base_proof() {
        let height = 6;
        let base_fingerprint = qhash(900);
        let circuit = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, height);
        let deltas = sequential_deltas(1, 32, height);
        let (boundary, base) = make_base(&circuit, &deltas, 0);
        let proof = circuit
            .prove(32, boundary, &slot_witnesses(&deltas), Some(&base))
            .unwrap();

        circuit.circuit_data.verify(proof.clone()).unwrap();
        assert_business_pis(
            &proof,
            boundary.chain_hash,
            fold_chain(boundary.chain_hash, &deltas, base_fingerprint),
            boundary.checkpoint_tree_root,
            deltas[31].new_root,
            deltas[31].new_value,
            32,
            0,
            32,
        );
    }

    #[test]
    fn chain_recursive_consumes_previous_recursive_proof() {
        let height = 7;
        let base_fingerprint = qhash(900);
        let circuit = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, height);
        let deltas = sequential_deltas(1, 64, height);
        let (boundary, base) = make_base(&circuit, &deltas, 0);
        let first = circuit
            .prove(32, boundary, &slot_witnesses(&deltas[..32]), Some(&base))
            .unwrap();
        let second = circuit
            .prove(32, boundary, &slot_witnesses(&deltas[32..]), Some(&first))
            .unwrap();

        circuit.circuit_data.verify(second.clone()).unwrap();
        assert_business_pis(
            &second,
            boundary.chain_hash,
            fold_chain(boundary.chain_hash, &deltas, base_fingerprint),
            boundary.checkpoint_tree_root,
            deltas[63].new_root,
            deltas[63].new_value,
            64,
            0,
            64,
        );
    }

    #[test]
    fn chain_recursive_rejects_active_len_above_32() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 2);
        let delta = sequential_deltas(1, 1, 2).remove(0);
        let (boundary, base) = make_base(&circuit, std::slice::from_ref(&delta), 0);
        let error = circuit
            .prove(
                33,
                boundary,
                &[BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof: &delta,
                }],
                Some(&base),
            )
            .unwrap_err();

        assert!(error.to_string().contains("active_len"));
    }

    #[test]
    fn chain_recursive_rejects_foreign_predecessor_circuit() {
        let height = 2;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let foreign = BridgeAggChainCircuit::<C, D>::new(qhash(901), height);
        let deltas = sequential_deltas(1, 1, height);
        let (boundary, _) = make_base(&circuit, &deltas, 0);
        let foreign_base = foreign.prove_base(boundary, &deltas[0]).unwrap();

        assert!(circuit
            .prove(
                1,
                boundary,
                &slot_witnesses(&deltas),
                Some(&foreign_base),
            )
            .is_err());
    }

    #[test]
    fn chain_recursive_rejects_tampered_predecessor_vk_pis() {
        let height = 2;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let deltas = sequential_deltas(1, 1, height);
        let (boundary, mut base) = make_base(&circuit, &deltas, 0);
        base.public_inputs[BRIDGE_AGG_CHAIN_PI_LEN] += F::ONE;

        assert!(circuit
            .prove(1, boundary, &slot_witnesses(&deltas), Some(&base))
            .is_err());
    }

    #[test]
    fn chain_recursive_rejects_wrong_predecessor_end_chain_hash() {
        let height = 2;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let deltas = sequential_deltas(1, 1, height);
        let (boundary, mut base) = make_base(&circuit, &deltas, 0);
        base.public_inputs[4] += F::ONE;

        assert!(circuit
            .prove(1, boundary, &slot_witnesses(&deltas), Some(&base))
            .is_err());
    }

    #[test]
    fn chain_recursive_rejects_wrong_predecessor_end_root() {
        let height = 2;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let deltas = sequential_deltas(1, 1, height);
        let (boundary, mut base) = make_base(&circuit, &deltas, 0);
        base.public_inputs[12] += F::ONE;

        assert!(circuit
            .prove(1, boundary, &slot_witnesses(&deltas), Some(&base))
            .is_err());
    }

    #[test]
    fn chain_recursive_rejects_non_contiguous_internal_roots() {
        let height = 3;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let mut deltas = sequential_deltas(1, 2, height);
        let (boundary, base) = make_base(&circuit, &deltas, 0);
        deltas[1].siblings[0] = qhash(90_000);

        assert!(circuit
            .prove(2, boundary, &slot_witnesses(&deltas), Some(&base))
            .is_err());
    }

    #[test]
    fn chain_recursive_rejects_invalid_delta_merkle_proof() {
        let height = 2;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let mut deltas = sequential_deltas(1, 1, height);
        let (boundary, base) = make_base(&circuit, &deltas, 0);
        deltas[0].siblings[0] = qhash(91_000);

        assert!(circuit
            .prove(1, boundary, &slot_witnesses(&deltas), Some(&base))
            .is_err());
    }

    #[test]
    fn chain_recursive_rejects_wrong_step_leaf_or_root() {
        let height = 2;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let deltas = sequential_deltas(1, 1, height);
        let (boundary, base) = make_base(&circuit, &deltas, 0);

        assert!(circuit
            .prove_with_witness_override(
                1,
                boundary,
                &slot_witnesses(&deltas),
                Some(&base),
                Some(qhash(92_000)),
                None,
                None,
                None,
                None,
            )
            .is_err());
    }

    #[test]
    fn chain_business_pi_prefix_is_stable() {
        let height = 2;
        let base_fingerprint = qhash(900);
        let circuit = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, height);
        let deltas = sequential_deltas(1, 1, height);
        let (boundary, base) = make_base(&circuit, &deltas, 0);
        let proof = circuit
            .prove(1, boundary, &slot_witnesses(&deltas), Some(&base))
            .unwrap();

        assert_eq!(BRIDGE_AGG_CHAIN_PI_LEN, 23);
        assert_business_pis(
            &proof,
            boundary.chain_hash,
            fold_chain(boundary.chain_hash, &deltas, base_fingerprint),
            boundary.checkpoint_tree_root,
            deltas[0].new_root,
            deltas[0].new_value,
            1,
            0,
            1,
        );
    }

    #[test]
    fn chain_cyclic_vk_suffix_matches_verifier_data() {
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), 2);
        let delta = sequential_deltas(1, 1, 2).remove(0);
        let boundary = boundary(delta.old_root, 0);
        let proof = circuit.prove_base(boundary, &delta).unwrap();

        check_cyclic_proof_verifier_data(
            &proof,
            &circuit.circuit_data.verifier_only,
            &circuit.circuit_data.common,
        )
        .unwrap();
        assert_eq!(
            &proof.public_inputs[BRIDGE_AGG_CHAIN_PI_LEN..BRIDGE_AGG_CHAIN_PI_LEN + 4],
            &circuit.circuit_data.verifier_only.circuit_digest.elements,
        );
    }

    #[test]
    fn chain_base_and_recursive_proofs_share_common_and_verifier_data() {
        let height = 2;
        let circuit = BridgeAggChainCircuit::<C, D>::new(qhash(900), height);
        let deltas = sequential_deltas(1, 2, height);
        let (boundary, base) = make_base(&circuit, &deltas, 0);
        let first = circuit
            .prove(1, boundary, &slot_witnesses(&deltas[..1]), Some(&base))
            .unwrap();
        let second = circuit
            .prove(1, boundary, &slot_witnesses(&deltas[1..]), Some(&first))
            .unwrap();

        for proof in [base, first, second] {
            circuit.circuit_data.verify(proof.clone()).unwrap();
            check_cyclic_proof_verifier_data(
                &proof,
                &circuit.circuit_data.verifier_only,
                &circuit.circuit_data.common,
            )
            .unwrap();
        }
        assert_eq!(
            circuit.get_fingerprint(),
            QHashOut(get_circuit_fingerprint_generic(
                &circuit.circuit_data.verifier_only
            ))
        );
    }
    fn height32_zero_siblings() -> Vec<QHashOut<F>> {
        (0..32)
            .map(|i| <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(i))
            .collect::<Vec<_>>()
    }

    // Append the first leaf (index 0) into an all-zero tree of height 32.
    fn append_index0_height32(new_value: QHashOut<F>) -> DeltaMerkleProofCore<QHashOut<F>> {
        let siblings = height32_zero_siblings();
        DeltaMerkleProofCore {
            old_root: compute_root_merkle_proof_generic::<_, PoseidonHash>(QHashOut::ZERO, 0, &siblings),
            old_value: QHashOut::ZERO,
            new_root: compute_root_merkle_proof_generic::<_, PoseidonHash>(new_value, 0, &siblings),
            new_value,
            index: 0,
            siblings,
        }
    }

    // Append the next leaf (index 1) after index 0 was set to first_value.
    fn append_index1_height32(
        first_value: QHashOut<F>,
        new_value: QHashOut<F>,
    ) -> DeltaMerkleProofCore<QHashOut<F>> {
        let mut siblings = Vec::with_capacity(32);
        siblings.push(first_value);
        for i in 1..32 {
            siblings.push(<PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(i));
        }
        DeltaMerkleProofCore {
            old_root: compute_root_merkle_proof_generic::<_, PoseidonHash>(QHashOut::ZERO, 1, &siblings),
            old_value: QHashOut::ZERO,
            new_root: compute_root_merkle_proof_generic::<_, PoseidonHash>(new_value, 1, &siblings),
            new_value,
            index: 1,
            siblings,
        }
    }

    #[test]
    fn chain_height32_recursive_one_step() {
        let height = 32;
        let base_fingerprint = qhash(900);
        eprintln!("[repro] building BridgeAggChainCircuit at height={height} ...");
        let circuit = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, height);
        eprintln!(
            "[repro] circuit built OK; degree_bits={}, gate_types={}",
            circuit.circuit_data.common.degree_bits(),
            circuit.circuit_data.common.gates.len()
        );
        // Pre-fill index 0 (committed checkpoint before the range), then the chain
        // appends index 1 as its first active slot.
        let v0 = qhash(1000);
        let delta_pad = append_index0_height32(v0); // root0 = delta_pad.new_root
        let boundary = boundary(delta_pad.new_root, 0); // checkpoint_index=0 -> range starts at 1
        eprintln!("[repro] proving base ...");
        let base = circuit.prove_base(boundary, &delta_pad).expect("prove_base failed");
        circuit.circuit_data.verify(base.clone()).expect("verify base failed");
        eprintln!("[repro] base VERIFIED; proving 1 recursive step (append index 1) ...");
        let delta1 = append_index1_height32(v0, qhash(201));
        assert_eq!(delta1.old_root, delta_pad.new_root, "step1 old_root must equal root0");
        let slots = [BridgeAggChainSlotWitness { checkpoint_delta_merkle_proof: &delta1 }];
        let proof = circuit.prove(1, boundary, &slots, Some(&base));
        match proof {
            Ok(p) => {
                eprintln!("[repro] 1-step proof generated, verifying ...");
                circuit.circuit_data.verify(p.clone()).expect("verify 1-step failed");
                check_cyclic_proof_verifier_data(&p, &circuit.circuit_data.verifier_only, &circuit.circuit_data.common).unwrap();
                eprintln!("[repro] 1-step proof VERIFIED OK; no FRI error reproduced");
            }
            Err(e) => {
                eprintln!("[repro] 1-step prove FAILED: {:#}", e);
                panic!("height=32 1-step prove failed: {e}");
            }
        }
    }

    #[test]
    fn chain_height32_base_only() {
        let height = 32;
        let base_fingerprint = qhash(900);
        eprintln!("[repro] building BridgeAggChainCircuit at height={height} ...");
        let circuit = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, height);
        eprintln!(
            "[repro] circuit built OK; degree_bits={}, gate_types={}",
            circuit.circuit_data.common.degree_bits(),
            circuit.circuit_data.common.gates.len()
        );
        let delta = append_index0_height32(qhash(200));
        let boundary = boundary(delta.old_root, 0);
        eprintln!("[repro] proving base (zero-step identity) ...");
        let base = circuit.prove_base(boundary, &delta).expect("prove_base failed");
        eprintln!("[repro] base proof generated, verifying ...");
        circuit.circuit_data.verify(base.clone()).expect("verify base failed");
        eprintln!("[repro] base proof VERIFIED OK");
    }

    /// Sparse append-only merkle tree of height 32 that never materializes 2^32 leaves.
    /// Maintains only the filled nodes in a map keyed by (level, position_within_level).
    struct SparseAppendTree {
        height: usize,
        // node hash at (level, position); absent => get_zero_hash(level)
        nodes: std::collections::HashMap<(usize, u64), QHashOut<F>>,
    }

    impl SparseAppendTree {
        fn new(height: usize) -> Self {
            Self { height, nodes: std::collections::HashMap::new() }
        }
        fn node_or_zero(&self, level: usize, pos: u64) -> QHashOut<F> {
            self.nodes
                .get(&(level, pos))
                .copied()
                .unwrap_or_else(|| <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(level))
        }
        /// Append `new_value` at the next sequential index `idx`. Returns the delta proof.
        /// `old_value` must be ZERO (the leaf was empty). Siblings are derived from the
        /// current tree state (filled nodes or zero hashes).
        fn append(&mut self, idx: u64, new_value: QHashOut<F>) -> DeltaMerkleProofCore<QHashOut<F>> {
            assert_eq!(self.nodes.get(&(0, idx)), None, "index already filled");
            // Siblings along the path from leaf `idx` up to the root.
            let mut siblings = Vec::with_capacity(self.height);
            for level in 0..self.height {
                let pos = idx >> level;
                let sibling_pos = pos ^ 1;
                siblings.push(self.node_or_zero(level, sibling_pos));
            }
            let old_root = compute_root_merkle_proof_generic::<_, PoseidonHash>(QHashOut::ZERO, idx, &siblings);
            let new_root = compute_root_merkle_proof_generic::<_, PoseidonHash>(new_value, idx, &siblings);
            // Now insert the new leaf and recompute ancestors.
            self.nodes.insert((0, idx), new_value);
            let mut current = new_value;
            for level in 0..self.height {
                let pos = idx >> level;
                let left = self.node_or_zero(level, pos & !1);
                let right = self.node_or_zero(level, pos | 1);
                current = <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&left, &right);
                self.nodes.insert((level + 1, pos >> 1), current);
            }
            DeltaMerkleProofCore {
                old_root,
                old_value: QHashOut::ZERO,
                new_root,
                new_value,
                index: idx,
                siblings,
            }
        }
        fn root(&self) -> QHashOut<F> {
            self.node_or_zero(self.height, 0)
        }
    }

    #[test]
    fn chain_height32_full_32_active_slots() {
        let height = 32;
        let base_fingerprint = qhash(900);
        eprintln!("[repro32] building BridgeAggChainCircuit at height={height} ...");
        let circuit = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, height);
        eprintln!(
            "[repro32] circuit built OK; degree_bits={}, gate_types={}",
            circuit.circuit_data.common.degree_bits(),
            circuit.circuit_data.common.gates.len()
        );
        // Pre-fill index 0 (the committed checkpoint before the range), then append
        // indices 1..=32 as the 32 active slots of one full chunk proof.
        let mut tree = SparseAppendTree::new(height);
        let delta_pad = tree.append(0, qhash(1000)); // pre-fill index 0
        let boundary = boundary(delta_pad.new_root, 0); // checkpoint_index=0 -> range starts at 1
        eprintln!("[repro32] proving base ...");
        let base = circuit.prove_base(boundary, &delta_pad).expect("prove_base failed");
        circuit.circuit_data.verify(base.clone()).expect("verify base failed");
        eprintln!("[repro32] base VERIFIED; building 32 sequential deltas (indices 1..=32) ...");
        let deltas = (1..=32).map(|i| tree.append(i, qhash(10_000 + i as u64 * 10))).collect::<Vec<_>>();
        let slots = deltas
            .iter()
            .map(|d| BridgeAggChainSlotWitness { checkpoint_delta_merkle_proof: d })
            .collect::<Vec<_>>();
        eprintln!("[repro32] proving full chunk (active_len=32) ...");
        let proof = circuit.prove(32, boundary, &slots, Some(&base));
        match proof {
            Ok(p) => {
                eprintln!("[repro32] full-chunk proof generated, verifying ...");
                circuit.circuit_data.verify(p.clone()).expect("verify full-chunk failed");
                check_cyclic_proof_verifier_data(&p, &circuit.circuit_data.verifier_only, &circuit.circuit_data.common).unwrap();
                assert_eq!(p.public_inputs[20].to_canonical_u64(), 32, "num_checkpoints_aggregated must be 32");
                assert_eq!(p.public_inputs[21].to_canonical_u64(), 0, "start_checkpoint_index must be 0");
                assert_eq!(p.public_inputs[22].to_canonical_u64(), 32, "end_checkpoint_index must be 32");
                eprintln!("[repro32] full-chunk proof VERIFIED OK; no FRI error reproduced");
            }
            Err(e) => {
                eprintln!("[repro32] full-chunk prove FAILED: {:#}", e);
                panic!("height=32 full-chunk prove failed: {e}");
            }
        }
    }
}
