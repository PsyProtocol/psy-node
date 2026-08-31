use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleZeroHasher},
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
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
use psy_data::v1::qdata::checkpoint::{
    PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafCompact,
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison,
    core::CircuitBuilderHelpersCore,
    hash::core::CircuitBuilderHashCore,
    pad_circuit::CircuitBuilderQEDCommonGates,
    select::CircuitBuilderSelectHelpers,
    verify::CircuitBuilderVerifyProofHelpers,
};
use psy_plonky2_common_circuits::{
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
    traits::CreatableTarget,
};

use crate::{
    bridge::{
        circuits::bridge_agg_chain::{
            BridgeAggChainBoundary, BridgeAggChainCircuit, BridgeAggChainSlotWitness,
            BRIDGE_AGG_CHAIN_MAX_SLOTS, BRIDGE_AGG_CHAIN_PI_LEN, GOLDILOCKS_MODULUS,
        },
        gadgets::{
            tree_root_in_contract_state::{
                TreeRootInContractStateGadget, TreeRootInContractStateWitnessInput,
            },
            verify_checkpoint_state_transition::VerifyBridgeCheckpointStateTransitionProofGadget,
        },
    },
    gadgets::qdata::{
        checkpoint::QEDCheckpointLeafCompactGadget,
        checkpoint_state_roots::QEDCheckpointGlobalStateRootsGadget,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

const BRIDGE_USER_ID: u64 = 524_288;
const DEPOSIT_TREE_CONTRACT_ID: u64 = 2;
const WITHDRAWAL_TREE_CONTRACT_ID: u64 = 3;
/// BridgeAgg Final public-input width:
/// [0..4) start root, [4..12) deposit root, [12..20) withdrawal root,
/// [20..24) end root, [24] end checkpoint index, [25] num checkpoints.
pub const BRIDGE_AGG_FINAL_PI_LEN: usize = 26;

pub struct BridgeAggFinalSlotWitness<'a, F: Field> {
    pub checkpoint_delta_merkle_proof: &'a DeltaMerkleProofCore<QHashOut<F>>,
}

/// Final verifies one recursively accumulated Chain proof, appends the terminal
/// 1..=32 checkpoint-data slots, verifies the single final checkpoint proof,
/// extracts the bridge roots for L1.
pub struct BridgeAggFinalCircuit<C: GenericConfig<D>, const D: usize> {
    pub chain_proof_target: ProofWithPublicInputsTarget<D>,
    pub chain_verifier_target: VerifierCircuitTarget,
    pub active_len: Target,
    pub checkpoint_delta_merkle_proofs: Vec<DeltaMerkleProofGadget>,
    pub is_active_flags: Vec<BoolTarget>,
    pub final_checkpoint_proof_gadget: VerifyBridgeCheckpointStateTransitionProofGadget<D>,
    pub total_start_checkpoint_tree_root: HashOutTarget,
    pub total_num_checkpoints: Target,
    pub final_checkpoint_index: Target,
    pub final_checkpoint_tree_root: HashOutTarget,
    pub final_checkpoint_leaf_hash: HashOutTarget,
    pub checkpoint_global_state_roots: QEDCheckpointGlobalStateRootsGadget,
    pub final_checkpoint_leaf: QEDCheckpointLeafCompactGadget,
    pub deposit_root_gadget: TreeRootInContractStateGadget,
    pub withdrawal_root_gadget: TreeRootInContractStateGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> BridgeAggFinalCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: RichField + Extendable<D>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_common_data: &CommonCircuitData<C::F, D>,
        chain_cap_height: usize,
        chain_fingerprint: QHashOut<C::F>,
        checkpoint_common_data: &CommonCircuitData<C::F, D>,
        checkpoint_cap_height: usize,
        checkpoint_fingerprint: QHashOut<C::F>,
        checkpoint_base_fingerprint: QHashOut<C::F>,
        checkpoint_tree_height: usize,
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        deposit_contract_state_tree_height: usize,
        withdrawal_contract_state_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let one = builder.one();
        let max_slots = builder.constant_u64(BRIDGE_AGG_CHAIN_MAX_SLOTS as u64);

        let chain_verifier_target = builder.add_virtual_verifier_data(chain_cap_height);
        let chain_proof_target = builder.add_virtual_proof_with_pis(chain_common_data);
        builder.verify_proof::<C>(
            &chain_proof_target,
            &chain_verifier_target,
            chain_common_data,
        );
        let actual_chain_fingerprint =
            builder.get_circuit_fingerprint::<C::Hasher>(&chain_verifier_target);
        let expected_chain_fingerprint = builder.constant_qhash(chain_fingerprint);
        builder.connect_hashes(actual_chain_fingerprint, expected_chain_fingerprint);
        // The Chain proof is cyclic: its public inputs are the 23 business
        // prefix followed by the cyclic verifier-data suffix
        // ([circuit_digest] ++ [cap_elem * num_cap_elements], 4 felts each).
        // verify_proof + fingerprint pin `chain_verifier_target`, but the proof's
        // own cyclic suffix is a free witness unless we explicitly connect it.
        // Without this binding, a Chain proof whose suffix points at a foreign
        // VK (same common-data, different fingerprint) verifies under the real
        // VK and is accepted by Final, letting a forged predecessor propagate
        // business PI (start root, count) into Final's public outputs.
        let chain_num_cap_elements = chain_common_data.config.fri_config.num_cap_elements();
        let chain_cyclic_suffix_len = 4 + 4 * chain_num_cap_elements;
        let expected_chain_pi_len = BRIDGE_AGG_CHAIN_PI_LEN + chain_cyclic_suffix_len;
        assert_eq!(
            chain_proof_target.public_inputs.len(),
            expected_chain_pi_len,
            "Chain proof PI length must be exactly business prefix + cyclic verifier-data suffix"
        );

        let chain_pis = &chain_proof_target.public_inputs;
        // Connect the proof's cyclic circuit_digest suffix to the pinned target.
        for i in 0..4 {
            builder.connect(
                chain_pis[BRIDGE_AGG_CHAIN_PI_LEN + i],
                chain_verifier_target.circuit_digest.elements[i],
            );
        }
        // Connect each constants-sigmas cap element of the proof suffix to the
        // pinned target, element-wise.
        for cap_index in 0..chain_num_cap_elements {
            let suffix_start = BRIDGE_AGG_CHAIN_PI_LEN + 4 + 4 * cap_index;
            for i in 0..4 {
                builder.connect(
                    chain_pis[suffix_start + i],
                    chain_verifier_target.constants_sigmas_cap.0[cap_index].elements[i],
                );
            }
        }

        let predecessor_start_root = pi_hash(chain_pis, 8);
        let predecessor_end_chain_hash = pi_hash(chain_pis, 4);
        let predecessor_end_root = pi_hash(chain_pis, 12);
        let predecessor_count = chain_pis[20];
        let predecessor_start_checkpoint_index = chain_pis[21];
        let predecessor_end_checkpoint_index = chain_pis[22];

        let active_len = builder.add_virtual_target();
        let ge_one = builder.is_less_than_or_equal(16, one, active_len);
        let le_max = builder.is_less_than_or_equal(16, active_len, max_slots);
        builder.assert_one(ge_one.target);
        builder.assert_one(le_max.target);

        let base_fingerprint_target = builder.constant_qhash(checkpoint_base_fingerprint);
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

        let mut rolling_chain_hash = predecessor_end_chain_hash;
        let mut rolling_root = predecessor_end_root;
        let mut rolling_leaf = builder.constant_qhash(QHashOut::ZERO);
        let mut rolling_checkpoint_index = predecessor_end_checkpoint_index;
        for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
            let is_active = is_active_flags[i];
            let delta = &checkpoint_delta_merkle_proofs[i];
            for j in 0..4 {
                let diff = builder.sub(delta.old_root.elements[j], rolling_root.elements[j]);
                let active_diff = builder.mul(is_active.target, diff);
                builder.assert_zero(active_diff);
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
            rolling_root = builder.select_hash(is_active, delta.new_root, rolling_root);
            rolling_leaf = builder.select_hash(is_active, delta.new_value, rolling_leaf);
            rolling_checkpoint_index =
                builder.select(is_active, delta.index, rolling_checkpoint_index);
        }

        let final_checkpoint_proof_gadget =
            VerifyBridgeCheckpointStateTransitionProofGadget::add_virtual_to::<C, C::F>(
                &mut builder,
                checkpoint_common_data,
                checkpoint_cap_height,
                checkpoint_fingerprint,
            );
        builder.connect_hashes(
            rolling_chain_hash,
            final_checkpoint_proof_gadget.public_inputs_hash,
        );

        let final_checkpoint_leaf = QEDCheckpointLeafCompactGadget::create_virtual(&mut builder);
        let final_checkpoint_leaf_hash =
            final_checkpoint_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);
        builder.connect_hashes(final_checkpoint_leaf_hash, rolling_leaf);

        let checkpoint_global_state_roots =
            QEDCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let computed_global_chain_root =
            checkpoint_global_state_roots.to_hash::<C::Hasher, C::F, D>(&mut builder);
        builder.connect_hashes(
            computed_global_chain_root,
            final_checkpoint_leaf.global_chain_root,
        );

        let deposit_root_gadget =
            TreeRootInContractStateGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                global_user_tree_height,
                global_contract_tree_height,
                deposit_contract_state_tree_height,
            );
        let withdrawal_root_gadget =
            TreeRootInContractStateGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                global_user_tree_height,
                global_contract_tree_height,
                withdrawal_contract_state_tree_height,
            );
        builder.connect_hashes(
            withdrawal_root_gadget.user_tree_root,
            deposit_root_gadget.user_tree_root,
        );
        builder.connect_hashes(
            deposit_root_gadget.user_tree_root,
            checkpoint_global_state_roots.user_tree_root,
        );

        let bridge_user_id = builder.constant_u64(BRIDGE_USER_ID);
        let deposit_contract_id = builder.constant_u64(DEPOSIT_TREE_CONTRACT_ID);
        let withdrawal_contract_id = builder.constant_u64(WITHDRAWAL_TREE_CONTRACT_ID);
        for slot in [&deposit_root_gadget.slot0, &deposit_root_gadget.slot1] {
            builder.connect(slot.sender_user_id, bridge_user_id);
            builder.connect(slot.contract_id, deposit_contract_id);
        }
        for slot in [
            &withdrawal_root_gadget.slot0,
            &withdrawal_root_gadget.slot1,
        ] {
            builder.connect(slot.sender_user_id, bridge_user_id);
            builder.connect(slot.contract_id, withdrawal_contract_id);
        }


        let total_num_checkpoints = builder.add(predecessor_count, active_len);
        let total_index_span =
            builder.sub(rolling_checkpoint_index, predecessor_start_checkpoint_index);
        builder.connect(total_index_span, total_num_checkpoints);
        builder.register_public_inputs(&predecessor_start_root.elements);
        builder.register_public_inputs(&deposit_root_gadget.tree_root[0].elements);
        builder.register_public_inputs(&deposit_root_gadget.tree_root[1].elements);
        builder.register_public_inputs(&withdrawal_root_gadget.tree_root[0].elements);
        builder.register_public_inputs(&withdrawal_root_gadget.tree_root[1].elements);
        builder.register_public_inputs(&rolling_root.elements);
        builder.register_public_input(rolling_checkpoint_index);
        builder.register_public_input(total_num_checkpoints);

        builder.add_qed_type_d_common_gates();
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            chain_proof_target,
            chain_verifier_target,
            active_len,
            checkpoint_delta_merkle_proofs,
            is_active_flags,
            final_checkpoint_proof_gadget,
            total_start_checkpoint_tree_root: predecessor_start_root,
            total_num_checkpoints,
            final_checkpoint_index: rolling_checkpoint_index,
            final_checkpoint_tree_root: rolling_root,
            final_checkpoint_leaf_hash: rolling_leaf,
            checkpoint_global_state_roots,
            final_checkpoint_leaf,
            deposit_root_gadget,
            withdrawal_root_gadget,
            circuit_data,
            fingerprint,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove_base(
        &self,
        chain_proof: &ProofWithPublicInputs<C::F, C, D>,
        chain_verifier_data: &VerifierOnlyCircuitData<C, D>,
        terminal_slots: &[BridgeAggFinalSlotWitness<'_, C::F>],
        final_checkpoint_proof: &ProofWithPublicInputs<C::F, C, D>,
        checkpoint_verifier_data: &VerifierOnlyCircuitData<C, D>,
        final_checkpoint_leaf: &PQEDCheckpointLeafCompact<QHashOut<C::F>>,
        checkpoint_global_state_roots: &PQEDCheckpointGlobalStateRoots<QHashOut<C::F>>,
        deposit_root_witness: &TreeRootInContractStateWitnessInput<C::F>,
        withdrawal_root_witness: &TreeRootInContractStateWitnessInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(
            !terminal_slots.is_empty() && terminal_slots.len() <= BRIDGE_AGG_CHAIN_MAX_SLOTS,
            "Final requires 1..={} terminal checkpoint slots, got {}",
            BRIDGE_AGG_CHAIN_MAX_SLOTS,
            terminal_slots.len()
        );

        let mut pw = PartialWitness::<C::F>::new();
        pw.set_verifier_data_target(&self.chain_verifier_target, chain_verifier_data)?;
        pw.set_proof_with_pis_target(&self.chain_proof_target, chain_proof)?;
        pw.set_target(
            self.active_len,
            C::F::from_canonical_usize(terminal_slots.len()),
        )?;

        let padding = terminal_slots.last().expect("checked non-empty");
        for i in 0..BRIDGE_AGG_CHAIN_MAX_SLOTS {
            let slot = terminal_slots.get(i).unwrap_or(padding);
            self.checkpoint_delta_merkle_proofs[i]
                .set_witness_core_proof_q(&mut pw, slot.checkpoint_delta_merkle_proof)?;
        }
        self.final_checkpoint_proof_gadget.set_witness::<C, C::F>(
            &mut pw,
            final_checkpoint_proof,
            checkpoint_verifier_data,
        )?;
        self.final_checkpoint_leaf
            .set_witness(&mut pw, final_checkpoint_leaf)?;
        self.checkpoint_global_state_roots
            .set_witness(&mut pw, checkpoint_global_state_roots)?;
        self.deposit_root_gadget
            .set_witness(&mut pw, deposit_root_witness)?;
        self.withdrawal_root_gadget
            .set_witness(&mut pw, withdrawal_root_witness)?;
        self.circuit_data.prove(pw)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prebuild_final_circuit(
        checkpoint_common_data: &CommonCircuitData<C::F, D>,
        checkpoint_cap_height: usize,
        checkpoint_fingerprint: QHashOut<C::F>,
        checkpoint_base_fingerprint: QHashOut<C::F>,
        checkpoint_tree_height: usize,
        user_tree_height: usize,
        contract_tree_height: usize,
        deposit_contract_state_tree_height: usize,
        withdrawal_contract_state_tree_height: usize,
    ) -> Self {
        let chain_circuit = BridgeAggChainCircuit::<C, D>::new(
            checkpoint_base_fingerprint,
            checkpoint_tree_height,
        );
        Self::new(
            chain_circuit.get_common_circuit_data_ref(),
            chain_circuit
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
            chain_circuit.get_fingerprint(),
            checkpoint_common_data,
            checkpoint_cap_height,
            checkpoint_fingerprint,
            checkpoint_base_fingerprint,
            checkpoint_tree_height,
            user_tree_height,
            contract_tree_height,
            deposit_contract_state_tree_height,
            withdrawal_contract_state_tree_height,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove_range(
        from_checkpoint: u64,
        to_checkpoint: u64,
        start_chain_hash: QHashOut<C::F>,
        checkpoint_common_data: &CommonCircuitData<C::F, D>,
        checkpoint_cap_height: usize,
        checkpoint_fingerprint: QHashOut<C::F>,
        checkpoint_base_fingerprint: QHashOut<C::F>,
        final_checkpoint_proof: &ProofWithPublicInputs<C::F, C, D>,
        checkpoint_verifier_data: &VerifierOnlyCircuitData<C, D>,
        delta_merkle_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>],
        pre_delta_merkle_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>],
        final_checkpoint_leaf: &PQEDCheckpointLeafCompact<QHashOut<C::F>>,
        checkpoint_global_state_roots: &PQEDCheckpointGlobalStateRoots<QHashOut<C::F>>,
        deposit_witness: &TreeRootInContractStateWitnessInput<C::F>,
        withdrawal_witness: &TreeRootInContractStateWitnessInput<C::F>,
        checkpoint_tree_height: usize,
        user_tree_height: usize,
        contract_tree_height: usize,
        deposit_contract_state_tree_height: usize,
        withdrawal_contract_state_tree_height: usize,
    ) -> anyhow::Result<BridgeAggProveResult<C, D>> {
        anyhow::ensure!(
            from_checkpoint <= to_checkpoint,
            "from_checkpoint must be <= to_checkpoint"
        );
        anyhow::ensure!(from_checkpoint > 0, "from_checkpoint must be at least 1");
        anyhow::ensure!(
            to_checkpoint < 0xffff_ffff_0000_0001,
            "to_checkpoint must be smaller than the Goldilocks modulus"
        );
        let total = (to_checkpoint - from_checkpoint + 1) as usize;
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

        let (prefix_len, final_len) = bridge_agg_partition(total);
        let chain_circuit = BridgeAggChainCircuit::<C, D>::new(
            checkpoint_base_fingerprint,
            checkpoint_tree_height,
        );
        let boundary = BridgeAggChainBoundary {
            chain_hash: start_chain_hash,
            checkpoint_tree_root: delta_merkle_proofs[0].old_root,
            checkpoint_leaf_hash: pre_delta_merkle_proofs[0].new_value,
            checkpoint_index: from_checkpoint - 1,
        };
        let mut chain_proof = chain_circuit.prove_base(boundary, &delta_merkle_proofs[0])?;
        let mut offset = 0usize;
        let mut positive_chain_proofs = 0usize;
        while offset < prefix_len {
            let chunk = &delta_merkle_proofs[offset..offset + BRIDGE_AGG_CHAIN_MAX_SLOTS];
            let slots = chunk
                .iter()
                .map(|checkpoint_delta_merkle_proof| BridgeAggChainSlotWitness {
                    checkpoint_delta_merkle_proof,
                })
                .collect::<Vec<_>>();
            chain_proof = chain_circuit.prove(
                BRIDGE_AGG_CHAIN_MAX_SLOTS as u64,
                boundary,
                &slots,
                Some(&chain_proof),
            )?;
            positive_chain_proofs += 1;
            offset += BRIDGE_AGG_CHAIN_MAX_SLOTS;
        }

        let final_circuit = Self::new(
            chain_circuit.get_common_circuit_data_ref(),
            chain_circuit
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
            chain_circuit.get_fingerprint(),
            checkpoint_common_data,
            checkpoint_cap_height,
            checkpoint_fingerprint,
            checkpoint_base_fingerprint,
            checkpoint_tree_height,
            user_tree_height,
            contract_tree_height,
            deposit_contract_state_tree_height,
            withdrawal_contract_state_tree_height,
        );
        let terminal_slots = delta_merkle_proofs[prefix_len..total]
            .iter()
            .map(|checkpoint_delta_merkle_proof| BridgeAggFinalSlotWitness {
                checkpoint_delta_merkle_proof,
            })
            .collect::<Vec<_>>();
        let proof = final_circuit.prove_base(
            &chain_proof,
            chain_circuit.get_verifier_config_ref(),
            &terminal_slots,
            final_checkpoint_proof,
            checkpoint_verifier_data,
            final_checkpoint_leaf,
            checkpoint_global_state_roots,
            deposit_witness,
            withdrawal_witness,
        )?;
        anyhow::ensure!(
            proof.public_inputs.len() == BRIDGE_AGG_FINAL_PI_LEN,
            "Final public input width must be {}, got {}",
            BRIDGE_AGG_FINAL_PI_LEN,
            proof.public_inputs.len()
        );
        anyhow::ensure!(
            proof.public_inputs[24] == C::F::from_canonical_u64(to_checkpoint),
            "Final end checkpoint index does not match to_checkpoint"
        );
        anyhow::ensure!(
            proof.public_inputs[25] == C::F::from_canonical_usize(total),
            "Final checkpoint count does not match requested range"
        );

        Ok(BridgeAggProveResult {
            proof,
            common_data: final_circuit.circuit_data.common,
            fingerprint: final_circuit.fingerprint,
            verifier_data: final_circuit.circuit_data.verifier_only,
            positive_chain_proofs,
            final_active_len: final_len,
        })
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

pub struct BridgeAggProveResult<C: GenericConfig<D>, const D: usize> {
    pub proof: ProofWithPublicInputs<C::F, C, D>,
    pub common_data: CommonCircuitData<C::F, D>,
    pub fingerprint: QHashOut<C::F>,
    pub verifier_data: VerifierOnlyCircuitData<C, D>,
    pub positive_chain_proofs: usize,
    pub final_active_len: usize,
}

fn pi_hash(pis: &[Target], start: usize) -> HashOutTarget {
    HashOutTarget {
        elements: [pis[start], pis[start + 1], pis[start + 2], pis[start + 3]],
    }
}

fn bridge_agg_partition(total: usize) -> (usize, usize) {
    assert!(total > 0, "bridge aggregation range must be non-empty");
    let final_len = (total - 1) % BRIDGE_AGG_CHAIN_MAX_SLOTS + 1;
    (total - final_len, final_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashMap;
    use parth_core::crypto::hash::{
        merkle_proof::{compute_root_merkle_proof_generic, DeltaMerkleProofCore, MerkleProofCore},
        traits::{MerkleHasher, MerkleZeroHasher},
    };
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, PrimeField64},
        },
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
            config::{Hasher, PoseidonGoldilocksConfig},
        },
    };
    use plonky2::recursion::dummy_circuit::cyclic_base_proof;
    use psy_data::v1::qdata::user::PQEDUserLeaf;
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

    fn checkpoint_proof_circuit() -> (CircuitData<F, C, D>, QHashOut<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let public_inputs = builder.add_virtual_targets(4);
        builder.register_public_inputs(&public_inputs);
        builder.add_qed_type_d_common_gates();
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));
        (circuit_data, fingerprint)
    }

    fn hash_two(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F> {
        QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(left.0, right.0))
    }

    fn append_delta(new_value: QHashOut<F>) -> DeltaMerkleProofCore<QHashOut<F>> {
        let old_value = QHashOut::ZERO;
        let siblings = vec![QHashOut::ZERO];
        DeltaMerkleProofCore {
            old_root: compute_root_merkle_proof_generic::<_, PoseidonHash>(old_value, 0, &siblings),
            old_value,
            new_root: compute_root_merkle_proof_generic::<_, PoseidonHash>(new_value, 0, &siblings),
            new_value,
            index: 0,
            siblings,
        }
    }

    fn merkle_proof(
        value: QHashOut<F>,
        index: u64,
        siblings: Vec<QHashOut<F>>,
    ) -> MerkleProofCore<QHashOut<F>> {
        MerkleProofCore {
            root: compute_root_merkle_proof_generic::<_, PoseidonHash>(value, index, &siblings),
            value,
            index,
            siblings,
        }
    }

    fn merkle_root(leaves: &[QHashOut<F>]) -> QHashOut<F> {
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = level.chunks_exact(2)
                .map(|pair| <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&pair[0], &pair[1]))
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
            level = level.chunks_exact(2)
                .map(|pair| <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&pair[0], &pair[1]))
                .collect();
            cursor >>= 1;
        }
        siblings
    }

    fn sequential_deltas(values: &[QHashOut<F>], height: usize) -> Vec<DeltaMerkleProofCore<QHashOut<F>>> {
        let mut leaves = vec![QHashOut::ZERO; 1 << height];
        let mut proofs = Vec::with_capacity(values.len());
        for (index, new_value) in values.iter().copied().enumerate() {
            let siblings = merkle_siblings(&leaves, index);
            let old_root = merkle_root(&leaves);
            leaves[index] = new_value;
            let new_root = merkle_root(&leaves);
            proofs.push(DeltaMerkleProofCore {
                old_root,
                old_value: QHashOut::ZERO,
                new_root,
                new_value,
                index: index as u64,
                siblings,
            });
        }
        proofs
    }

    fn sequential_append_only_deltas(
        values: &[QHashOut<F>],
        height: usize,
    ) -> Vec<DeltaMerkleProofCore<QHashOut<F>>> {
        // Pre-fill position 0 so append-only siblings at index >= 1 are non-zero.
        // Position 0 represents checkpoint_index = from_checkpoint - 1 = 0 (before the range).
        let mut leaves = vec![QHashOut::ZERO; 1 << height];
        leaves[0] = qhash(99_999);
        let mut proofs = Vec::with_capacity(values.len());
        for (offset, new_value) in values.iter().copied().enumerate() {
            let index = offset + 1;
            let siblings = merkle_siblings(&leaves, index);
            let old_root = merkle_root(&leaves);
            leaves[index] = new_value;
            proofs.push(DeltaMerkleProofCore {
                old_root,
                old_value: QHashOut::ZERO,
                new_root: merkle_root(&leaves),
                new_value,
                index: index as u64,
                siblings,
            });
        }
        proofs
    }

    fn user_leaf_hash(user: &PQEDUserLeaf<F, QHashOut<F>>) -> QHashOut<F> {
        let mut values = Vec::with_capacity(13);
        values.extend_from_slice(&user.public_key.0.elements);
        values.extend_from_slice(&user.user_state_tree_root.0.elements);
        values.extend_from_slice(&[
            user.balance,
            user.nonce,
            user.last_checkpoint_id,
            user.event_index,
            user.user_id,
        ]);
        QHashOut(PoseidonHash::hash_no_pad(&values))
    }

    fn global_roots_hash(roots: &PQEDCheckpointGlobalStateRoots<QHashOut<F>>) -> QHashOut<F> {
        let contract_and_deposit = hash_two(roots.contract_tree_root, roots.deposit_tree_root);
        let user_and_withdrawal = hash_two(roots.user_tree_root, roots.withdrawal_tree_root);
        hash_two(
            hash_two(contract_and_deposit, user_and_withdrawal),
            roots.user_registration_tree_root,
        )
    }

    fn zero_hash(level: usize) -> QHashOut<F> {
        <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(level)
    }

    /// Sparse merkle proof over a partially-filled tree of `height`.
    /// Absent leaves/nodes are treated as the Poseidon zero-hash at that level.
    fn sparse_merkle_proof(
        leaves: &std::collections::HashMap<u64, QHashOut<F>>,
        index: u64,
        height: usize,
    ) -> MerkleProofCore<QHashOut<F>> {
        let mut layer = leaves.clone();
        let value = layer.get(&index).copied().unwrap_or(QHashOut::ZERO);
        let mut siblings = Vec::with_capacity(height);
        let mut cur = index;
        for level in 0..height {
            let sibling_idx = cur ^ 1;
            let sibling = layer
                .get(&sibling_idx)
                .copied()
                .unwrap_or_else(|| zero_hash(level));
            siblings.push(sibling);

            let mut parents = std::collections::HashSet::new();
            for &k in layer.keys() {
                parents.insert(k >> 1);
            }
            parents.insert(cur >> 1);
            let mut next = std::collections::HashMap::new();
            for p in parents {
                let left_i = p << 1;
                let right_i = left_i + 1;
                let left = layer
                    .get(&left_i)
                    .copied()
                    .unwrap_or_else(|| zero_hash(level));
                let right = layer
                    .get(&right_i)
                    .copied()
                    .unwrap_or_else(|| zero_hash(level));
                next.insert(
                    p,
                    <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&left, &right),
                );
            }
            layer = next;
            cur >>= 1;
        }
        let root = layer
            .get(&0)
            .copied()
            .unwrap_or_else(|| zero_hash(height));
        MerkleProofCore {
            root,
            value,
            index,
            siblings,
        }
    }

    const TEST_CONTRACT_STATE_TREE_HEIGHT: usize = 15;

    fn bridge_state_witnesses() -> (
        TreeRootInContractStateWitnessInput<F>,
        TreeRootInContractStateWitnessInput<F>,
        PQEDCheckpointGlobalStateRoots<QHashOut<F>>,
    ) {
        let deposit_slot0 = qhash(1_000);
        let deposit_slot1 = qhash(2_000);
        let withdrawal_slot0 = qhash(3_000);
        let withdrawal_slot1 = qhash(4_000);

        let mut deposit_leaves = std::collections::HashMap::new();
        deposit_leaves.insert(0, deposit_slot0);
        deposit_leaves.insert(1, deposit_slot1);
        let deposit_slot0_proof =
            sparse_merkle_proof(&deposit_leaves, 0, TEST_CONTRACT_STATE_TREE_HEIGHT);
        let deposit_slot1_proof =
            sparse_merkle_proof(&deposit_leaves, 1, TEST_CONTRACT_STATE_TREE_HEIGHT);
        let deposit_state_root = deposit_slot0_proof.root;
        assert_eq!(deposit_slot1_proof.root, deposit_state_root);

        let mut withdrawal_leaves = std::collections::HashMap::new();
        withdrawal_leaves.insert(0, withdrawal_slot0);
        withdrawal_leaves.insert(1, withdrawal_slot1);
        let withdrawal_slot0_proof =
            sparse_merkle_proof(&withdrawal_leaves, 0, TEST_CONTRACT_STATE_TREE_HEIGHT);
        let withdrawal_slot1_proof =
            sparse_merkle_proof(&withdrawal_leaves, 1, TEST_CONTRACT_STATE_TREE_HEIGHT);
        let withdrawal_state_root = withdrawal_slot0_proof.root;

        let empty_contract_pair = hash_two(QHashOut::ZERO, QHashOut::ZERO);
        let contract_tree_root = hash_two(
            empty_contract_pair,
            hash_two(deposit_state_root, withdrawal_state_root),
        );

        let user_leaf = PQEDUserLeaf::new(
            qhash(5_000),
            contract_tree_root,
            F::ONE,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::from_canonical_u64(BRIDGE_USER_ID),
        );
        let user_hash = user_leaf_hash(&user_leaf);
        let user_tree_siblings = vec![QHashOut::ZERO; 20];
        let user_tree_proof = merkle_proof(user_hash, BRIDGE_USER_ID, user_tree_siblings);

        let deposit = TreeRootInContractStateWitnessInput {
            owner_user_id: BRIDGE_USER_ID,
            contract_id: DEPOSIT_TREE_CONTRACT_ID,
            user_leaf: user_leaf.clone(),
            slot0_proof: deposit_slot0_proof,
            slot1_proof: deposit_slot1_proof,
            contract_proof: merkle_proof(
                deposit_state_root,
                DEPOSIT_TREE_CONTRACT_ID,
                vec![withdrawal_state_root, empty_contract_pair],
            ),
            user_tree_proof: user_tree_proof.clone(),
        };
        let withdrawal = TreeRootInContractStateWitnessInput {
            owner_user_id: BRIDGE_USER_ID,
            contract_id: WITHDRAWAL_TREE_CONTRACT_ID,
            user_leaf: user_leaf.clone(),
            slot0_proof: withdrawal_slot0_proof,
            slot1_proof: withdrawal_slot1_proof,
            contract_proof: merkle_proof(
                withdrawal_state_root,
                WITHDRAWAL_TREE_CONTRACT_ID,
                vec![deposit_state_root, empty_contract_pair],
            ),
            user_tree_proof: user_tree_proof.clone(),
        };

        let global_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: qhash(6_000),
            deposit_tree_root: qhash(7_000),
            user_tree_root: user_tree_proof.root,
            withdrawal_tree_root: qhash(8_000),
            user_registration_tree_root: qhash(9_000),
            validator_tree_root: qhash(10_000),
        };
        (deposit, withdrawal, global_roots)
    }

    fn prove_checkpoint(
        circuit: &CircuitData<F, C, D>,
        chain_hash: QHashOut<F>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let mut pw = PartialWitness::new();
        for (target, value) in circuit
            .prover_only
            .public_inputs
            .iter()
            .zip(chain_hash.0.elements)
        {
            pw.set_target(*target, value).unwrap();
        }
        circuit.prove(pw).unwrap()
    }

    fn fold_chain(
        mut chain: QHashOut<F>,
        deltas: &[DeltaMerkleProofCore<QHashOut<F>>],
        base_fingerprint: QHashOut<F>,
    ) -> QHashOut<F> {
        for delta in deltas {
            chain = hash_two(
                chain,
                hash_two(
                    hash_two(delta.new_root, delta.new_value),
                    base_fingerprint,
                ),
            );
        }
        chain
    }

    fn final_circuit(
        chain: &BridgeAggChainCircuit<C, D>,
        checkpoint: &CircuitData<F, C, D>,
        checkpoint_fingerprint: QHashOut<F>,
        base_fingerprint: QHashOut<F>,
        checkpoint_tree_height: usize,
    ) -> BridgeAggFinalCircuit<C, D> {
        BridgeAggFinalCircuit::<C, D>::new(
            chain.get_common_circuit_data_ref(),
            chain
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
            chain.get_fingerprint(),
            &checkpoint.common,
            checkpoint.verifier_only.constants_sigmas_cap.height(),
            checkpoint_fingerprint,
            base_fingerprint,
            checkpoint_tree_height,
            20,
            2,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
        )
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

    struct ProveRangeFixture {
        checkpoint: CircuitData<F, C, D>,
        checkpoint_fingerprint: QHashOut<F>,
        base_fingerprint: QHashOut<F>,
        start_chain_hash: QHashOut<F>,
        checkpoint_tree_height: usize,
        deposit: TreeRootInContractStateWitnessInput<F>,
        withdrawal: TreeRootInContractStateWitnessInput<F>,
        global_roots: PQEDCheckpointGlobalStateRoots<QHashOut<F>>,
        final_leaf: PQEDCheckpointLeafCompact<QHashOut<F>>,
        delta_merkle_proofs: Vec<DeltaMerkleProofCore<QHashOut<F>>>,
        pre_delta_merkle_proofs: Vec<DeltaMerkleProofCore<QHashOut<F>>>,
        expected_chain_hashes: Vec<QHashOut<F>>,
    }

    impl ProveRangeFixture {
        fn new(max_total: usize) -> Self {
            let checkpoint_tree_height = 7;
            let base_fingerprint = qhash(700);
            let start_chain_hash = qhash(10);
            let (checkpoint, checkpoint_fingerprint) = checkpoint_proof_circuit();
            let (deposit, withdrawal, global_roots) =
                bridge_state_witnesses();
            let final_leaf = PQEDCheckpointLeafCompact {
                global_chain_root: global_roots_hash(&global_roots),
                stats_hash: qhash(12_000),
            };
            let final_leaf_hash = hash_two(final_leaf.global_chain_root, final_leaf.stats_hash);
            let mut values = (0..max_total)
                .map(|index| qhash(20_000 + index as u64 * 10))
                .collect::<Vec<_>>();
            values[max_total - 1] = final_leaf_hash;
            let delta_merkle_proofs =
                sequential_append_only_deltas(&values, checkpoint_tree_height);
            let mut pre_delta_merkle_proofs = delta_merkle_proofs.clone();
            // pre_delta[0].new_value is the leaf at checkpoint_index = 0, which was pre-filled.
            pre_delta_merkle_proofs[0].new_value = qhash(99_999);
            let mut expected_chain_hashes = Vec::with_capacity(max_total);
            let mut rolling_chain_hash = start_chain_hash;
            for delta in &delta_merkle_proofs {
                rolling_chain_hash = fold_chain(
                    rolling_chain_hash,
                    std::slice::from_ref(delta),
                    base_fingerprint,
                );
                expected_chain_hashes.push(rolling_chain_hash);
            }

            Self {
                checkpoint,
                checkpoint_fingerprint,
                base_fingerprint,
                start_chain_hash,
                checkpoint_tree_height,
                deposit,
                withdrawal,
                global_roots,
                final_leaf,
                delta_merkle_proofs,
                pre_delta_merkle_proofs,
                expected_chain_hashes,
            }
        }

        fn prove_range(&self, total: usize) -> anyhow::Result<BridgeAggProveResult<C, D>> {
            let final_checkpoint_proof =
                prove_checkpoint(&self.checkpoint, self.expected_chain_hashes[total - 1]);
            BridgeAggFinalCircuit::<C, D>::prove_range(
                1,
                total as u64,
                self.start_chain_hash,
                &self.checkpoint.common,
                self.checkpoint
                    .verifier_only
                    .constants_sigmas_cap
                    .height(),
                self.checkpoint_fingerprint,
                self.base_fingerprint,
                &final_checkpoint_proof,
                &self.checkpoint.verifier_only,
                &self.delta_merkle_proofs[..total],
                &self.pre_delta_merkle_proofs[..total],
                &self.final_leaf,
                &self.global_roots,
                &self.deposit,
                &self.withdrawal,
                self.checkpoint_tree_height,
                20,
                2,
                TEST_CONTRACT_STATE_TREE_HEIGHT,
                TEST_CONTRACT_STATE_TREE_HEIGHT,
            )
        }
    }

    fn assert_prove_range_case(total: usize, positive_chain_proofs: usize, final_active_len: usize) {
        let fixture = ProveRangeFixture::new(total);
        let result = fixture.prove_range(total).unwrap();
        VerifierCircuitData {
            verifier_only: result.verifier_data.clone(),
            common: result.common_data.clone(),
        }
        .verify(result.proof.clone())
        .unwrap();

        assert_eq!(result.positive_chain_proofs, positive_chain_proofs);
        assert_eq!(result.final_active_len, final_active_len);
        assert_eq!(result.proof.public_inputs.len(), BRIDGE_AGG_FINAL_PI_LEN);
        assert_eq!(result.proof.public_inputs[24].to_canonical_u64(), total as u64);
        assert_eq!(result.proof.public_inputs[25].to_canonical_u64(), total as u64);
        assert_eq!(
            &result.proof.public_inputs[0..4],
            &fixture.delta_merkle_proofs[0].old_root.0.elements
        );
        assert_eq!(
            &result.proof.public_inputs[20..24],
            &fixture.delta_merkle_proofs[total - 1].new_root.0.elements
        );
        assert_eq!(
            &result.proof.public_inputs[4..8],
            &fixture.deposit.slot0_proof.value.0.elements
        );
        assert_eq!(
            &result.proof.public_inputs[8..12],
            &fixture.deposit.slot1_proof.value.0.elements
        );
        assert_eq!(
            &result.proof.public_inputs[12..16],
            &fixture.withdrawal.slot0_proof.value.0.elements
        );
        assert_eq!(
            &result.proof.public_inputs[16..20],
            &fixture.withdrawal.slot1_proof.value.0.elements
        );
    }

    #[test]
    fn prove_range_n1_uses_base_plus_final() {
        assert_prove_range_case(1, 0, 1);
    }

    #[test]
    fn prove_range_n31_uses_base_plus_final() {
        assert_prove_range_case(31, 0, 31);
    }

    #[test]
    fn prove_range_n32_uses_base_plus_final() {
        assert_prove_range_case(32, 0, 32);
    }

    #[test]
    fn prove_range_n33_uses_one_chain_then_final() {
        assert_prove_range_case(33, 1, 1);
    }

    #[test]
    fn prove_range_n63_uses_one_chain_then_final() {
        assert_prove_range_case(63, 1, 31);
    }

    #[test]
    fn prove_range_n64_uses_one_chain_then_final() {
        assert_prove_range_case(64, 1, 32);
    }

    #[test]
    fn prove_range_n65_uses_two_chains_then_final() {
        assert_prove_range_case(65, 2, 1);
    }
    #[test]
    fn prove_range_n95_uses_two_chains_then_final() {
        assert_prove_range_case(95, 2, 31);
    }

    #[test]
    fn prove_range_n96_uses_two_chains_then_final() {
        assert_prove_range_case(96, 2, 32);
    }

    #[test]
    fn prove_range_n97_uses_three_chains_then_final() {
        assert_prove_range_case(97, 3, 1);
    }

    #[test]
    fn prove_range_has_no_64_checkpoint_limit() {
        assert_prove_range_case(65, 2, 1);
        assert_prove_range_case(97, 3, 1);
    }

    #[test]
    fn prove_range_passes_only_last_checkpoint_proof_to_final() {
        let fixture = ProveRangeFixture::new(33);
        let final_checkpoint_proof =
            prove_checkpoint(&fixture.checkpoint, fixture.expected_chain_hashes[32]);
        let result = BridgeAggFinalCircuit::<C, D>::prove_range(
            1,
            33,
            fixture.start_chain_hash,
            &fixture.checkpoint.common,
            fixture
                .checkpoint
                .verifier_only
                .constants_sigmas_cap
                .height(),
            fixture.checkpoint_fingerprint,
            fixture.base_fingerprint,
            &final_checkpoint_proof,
            &fixture.checkpoint.verifier_only,
            &fixture.delta_merkle_proofs,
            &fixture.pre_delta_merkle_proofs,
            &fixture.final_leaf,
            &fixture.global_roots,
            &fixture.deposit,
            &fixture.withdrawal,
            fixture.checkpoint_tree_height,
            20,
            2,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
        )
        .unwrap();

        assert_eq!(result.positive_chain_proofs, 1);
        assert_eq!(result.final_active_len, 1);
        assert_eq!(result.proof.public_inputs[25].to_canonical_u64(), 33);
    }

    #[test]
    fn prove_range_rejects_empty_range() {
        let fixture = ProveRangeFixture::new(1);
        let final_checkpoint_proof =
            prove_checkpoint(&fixture.checkpoint, fixture.expected_chain_hashes[0]);
        let error = match BridgeAggFinalCircuit::<C, D>::prove_range(
            2,
            1,
            fixture.start_chain_hash,
            &fixture.checkpoint.common,
            fixture
                .checkpoint
                .verifier_only
                .constants_sigmas_cap
                .height(),
            fixture.checkpoint_fingerprint,
            fixture.base_fingerprint,
            &final_checkpoint_proof,
            &fixture.checkpoint.verifier_only,
            &fixture.delta_merkle_proofs,
            &fixture.pre_delta_merkle_proofs,
            &fixture.final_leaf,
            &fixture.global_roots,
            &fixture.deposit,
            &fixture.withdrawal,
            fixture.checkpoint_tree_height,
            20,
            2,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
        ) {
            Ok(_) => panic!("empty range unexpectedly proved"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("from_checkpoint"));
    }

    #[test]
    fn prove_range_rejects_mismatched_input_lengths() {
        let fixture = ProveRangeFixture::new(2);
        let final_checkpoint_proof =
            prove_checkpoint(&fixture.checkpoint, fixture.expected_chain_hashes[1]);
        let call = |deltas: &[DeltaMerkleProofCore<QHashOut<F>>],
                    pre_deltas: &[DeltaMerkleProofCore<QHashOut<F>>]| {
            BridgeAggFinalCircuit::<C, D>::prove_range(
                1,
                2,
                fixture.start_chain_hash,
                &fixture.checkpoint.common,
                fixture
                    .checkpoint
                    .verifier_only
                    .constants_sigmas_cap
                    .height(),
                fixture.checkpoint_fingerprint,
                fixture.base_fingerprint,
                &final_checkpoint_proof,
                &fixture.checkpoint.verifier_only,
                deltas,
                pre_deltas,
                &fixture.final_leaf,
                &fixture.global_roots,
                &fixture.deposit,
                &fixture.withdrawal,
                fixture.checkpoint_tree_height,
                20,
                2,
                TEST_CONTRACT_STATE_TREE_HEIGHT,
                TEST_CONTRACT_STATE_TREE_HEIGHT,
            )
        };

        let delta_error = match call(
            &fixture.delta_merkle_proofs[..1],
            &fixture.pre_delta_merkle_proofs,
        ) {
            Ok(_) => panic!("short delta input unexpectedly proved"),
            Err(error) => error,
        };
        assert!(delta_error.to_string().contains("delta_merkle_proofs"));

        let pre_delta_error = match call(
            &fixture.delta_merkle_proofs,
            &fixture.pre_delta_merkle_proofs[..1],
        ) {
            Ok(_) => panic!("short pre-delta input unexpectedly proved"),
            Err(error) => error,
        };
        assert!(pre_delta_error
            .to_string()
            .contains("pre_delta_merkle_proofs"));
    }

    fn prove_chain_base_with_verifier_data_suffix(
        chain: &BridgeAggChainCircuit<C, D>,
        suffix_verifier_data: &VerifierOnlyCircuitData<C, D>,
        boundary: BridgeAggChainBoundary<F>,
        padding_delta: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let mut pw = PartialWitness::new();
        pw.set_target(chain.active_len, F::ZERO).unwrap();
        pw.set_hash_target(chain.base_chain_hash, boundary.chain_hash.0)
            .unwrap();
        pw.set_hash_target(
            chain.base_checkpoint_tree_root,
            boundary.checkpoint_tree_root.0,
        )
        .unwrap();
        pw.set_hash_target(
            chain.base_checkpoint_leaf_hash,
            boundary.checkpoint_leaf_hash.0,
        )
        .unwrap();
        pw.set_target(
            chain.base_checkpoint_index,
            F::from_canonical_u64(boundary.checkpoint_index),
        )
        .unwrap();
        pw.set_verifier_data_target(
            &chain.cyclic_verifier_data_target,
            suffix_verifier_data,
        )
        .unwrap();
        let predecessor = cyclic_base_proof(
            &chain.circuit_data.common,
            suffix_verifier_data,
            HashMap::new(),
        );
        pw.set_proof_with_pis_target(&chain.previous_chain_proof_target, &predecessor)
            .unwrap();
        for delta_target in &chain.checkpoint_delta_merkle_proofs {
            delta_target
                .set_witness_core_proof_q(&mut pw, padding_delta)
                .unwrap();
        }
        chain.circuit_data.prove(pw).unwrap()
    }

    #[test]
    fn final_builds_with_cyclic_chain_pi_suffix() {
        let checkpoint_tree_height = 1;
        let base_fingerprint = qhash(700);
        let chain = BridgeAggChainCircuit::<C, D>::new(
            base_fingerprint,
            checkpoint_tree_height,
        );
        let (checkpoint, checkpoint_fingerprint) = checkpoint_proof_circuit();

        let final_circuit = BridgeAggFinalCircuit::<C, D>::new(
            chain.get_common_circuit_data_ref(),
            chain
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
            chain.get_fingerprint(),
            &checkpoint.common,
            checkpoint.verifier_only.constants_sigmas_cap.height(),
            checkpoint_fingerprint,
            base_fingerprint,
            checkpoint_tree_height,
            1,
            1,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
        );

        assert_eq!(final_circuit.circuit_data.common.num_public_inputs, BRIDGE_AGG_FINAL_PI_LEN);
        assert!(chain.circuit_data.common.num_public_inputs > BRIDGE_AGG_CHAIN_PI_LEN);
    }

    fn prove_single_final(
    ) -> (
        BridgeAggFinalCircuit<C, D>,
        ProofWithPublicInputs<F, C, D>,
        DeltaMerkleProofCore<QHashOut<F>>,
        TreeRootInContractStateWitnessInput<F>,
        TreeRootInContractStateWitnessInput<F>,
    ) {
        let checkpoint_tree_height = 1;
        let base_fingerprint = qhash(700);
        let start_chain_hash = qhash(10);
        let chain = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, checkpoint_tree_height);
        let (checkpoint, checkpoint_fingerprint) = checkpoint_proof_circuit();
        let (deposit, withdrawal, global_roots) = bridge_state_witnesses();
        let final_leaf = PQEDCheckpointLeafCompact {
            global_chain_root: global_roots_hash(&global_roots),
            stats_hash: qhash(12_000),
        };
        let terminal_delta =
            append_delta(hash_two(final_leaf.global_chain_root, final_leaf.stats_hash));
        let boundary = BridgeAggChainBoundary {
            chain_hash: start_chain_hash,
            checkpoint_tree_root: terminal_delta.old_root,
            checkpoint_leaf_hash: qhash(50),
            checkpoint_index: GOLDILOCKS_MODULUS - 1,
        };
        let base_proof = chain.prove_base(boundary, &terminal_delta).unwrap();
        let root_leaf = hash_two(terminal_delta.new_root, terminal_delta.new_value);
        let final_chain_hash = hash_two(start_chain_hash, hash_two(root_leaf, base_fingerprint));
        let checkpoint_proof = prove_checkpoint(&checkpoint, final_chain_hash);
        let final_circuit = BridgeAggFinalCircuit::<C, D>::new(
            chain.get_common_circuit_data_ref(),
            chain.get_verifier_config_ref().constants_sigmas_cap.height(),
            chain.get_fingerprint(),
            &checkpoint.common,
            checkpoint.verifier_only.constants_sigmas_cap.height(),
            checkpoint_fingerprint,
            base_fingerprint,
            checkpoint_tree_height,
            20,
            2,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
            TEST_CONTRACT_STATE_TREE_HEIGHT,
        );
        let proof = final_circuit
            .prove_base(
                &base_proof,
                chain.get_verifier_config_ref(),
                &[BridgeAggFinalSlotWitness {
                    checkpoint_delta_merkle_proof: &terminal_delta,
                }],
                &checkpoint_proof,
                &checkpoint.verifier_only,
                &final_leaf,
                &global_roots,
                &deposit,
                &withdrawal,
            )
            .unwrap();

        (final_circuit, proof, terminal_delta, deposit, withdrawal)
    }

    #[test]
    fn final_accepts_same_circuit_base_proof_for_one_checkpoint() {
        let (final_circuit, proof, terminal_delta, deposit, withdrawal) =
            prove_single_final();

        final_circuit.circuit_data.verify(proof.clone()).unwrap();
        assert_eq!(&proof.public_inputs[0..4], &terminal_delta.old_root.0.elements);
        assert_eq!(&proof.public_inputs[4..8], &deposit.slot0_proof.value.0.elements);
        assert_eq!(&proof.public_inputs[8..12], &deposit.slot1_proof.value.0.elements);
        assert_eq!(&proof.public_inputs[12..16], &withdrawal.slot0_proof.value.0.elements);
        assert_eq!(&proof.public_inputs[16..20], &withdrawal.slot1_proof.value.0.elements);
        assert_eq!(&proof.public_inputs[20..24], &terminal_delta.new_root.0.elements);
        assert_eq!(proof.public_inputs[24].to_canonical_u64(), 0);
        assert_eq!(proof.public_inputs[25].to_canonical_u64(), 1);
        assert_eq!(proof.public_inputs.len(), BRIDGE_AGG_FINAL_PI_LEN);
    }

    #[test]
    fn final_rejects_zero_terminal_active_len() {
        let checkpoint_tree_height = 1;
        let base_fingerprint = qhash(700);
        let chain = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, checkpoint_tree_height);
        let (checkpoint, checkpoint_fingerprint) = checkpoint_proof_circuit();
        let (deposit, withdrawal, global_roots) = bridge_state_witnesses();
        let final_leaf = PQEDCheckpointLeafCompact {
            global_chain_root: global_roots_hash(&global_roots),
            stats_hash: qhash(12_000),
        };
        let delta = append_delta(hash_two(final_leaf.global_chain_root, final_leaf.stats_hash));
        let boundary = BridgeAggChainBoundary {
            chain_hash: qhash(10),
            checkpoint_tree_root: delta.old_root,
            checkpoint_leaf_hash: qhash(50),
            checkpoint_index: GOLDILOCKS_MODULUS - 1,
        };
        let base = chain.prove_base(boundary, &delta).unwrap();
        let final_circuit = final_circuit(
            &chain,
            &checkpoint,
            checkpoint_fingerprint,
            base_fingerprint,
            checkpoint_tree_height,
        );
        let checkpoint_proof = prove_checkpoint(&checkpoint, qhash(99_000));
        assert!(final_circuit
            .prove_base(
                &base,
                chain.get_verifier_config_ref(),
                &[],
                &checkpoint_proof,
                &checkpoint.verifier_only,
                &final_leaf,
                &global_roots,
                &deposit,
                &withdrawal,
            )
            .is_err());
    }

    #[test]
    fn final_rejects_terminal_active_len_above_32() {
        let checkpoint_tree_height = 1;
        let base_fingerprint = qhash(700);
        let chain = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, checkpoint_tree_height);
        let (checkpoint, checkpoint_fingerprint) = checkpoint_proof_circuit();
        let (deposit, withdrawal, global_roots) = bridge_state_witnesses();
        let final_leaf = PQEDCheckpointLeafCompact {
            global_chain_root: global_roots_hash(&global_roots),
            stats_hash: qhash(12_000),
        };
        let delta = append_delta(hash_two(final_leaf.global_chain_root, final_leaf.stats_hash));
        let boundary = BridgeAggChainBoundary {
            chain_hash: qhash(10),
            checkpoint_tree_root: delta.old_root,
            checkpoint_leaf_hash: qhash(50),
            checkpoint_index: GOLDILOCKS_MODULUS - 1,
        };
        let base = chain.prove_base(boundary, &delta).unwrap();
        let final_circuit = final_circuit(
            &chain,
            &checkpoint,
            checkpoint_fingerprint,
            base_fingerprint,
            checkpoint_tree_height,
        );
        let checkpoint_proof = prove_checkpoint(&checkpoint, qhash(99_000));
        let slots = (0..33)
            .map(|_| BridgeAggFinalSlotWitness {
                checkpoint_delta_merkle_proof: &delta,
            })
            .collect::<Vec<_>>();
        assert!(final_circuit
            .prove_base(
                &base,
                chain.get_verifier_config_ref(),
                &slots,
                &checkpoint_proof,
                &checkpoint.verifier_only,
                &final_leaf,
                &global_roots,
                &deposit,
                &withdrawal,
            )
            .is_err());
    }

    #[test]
    fn final_pins_deposit_contract_id() {
        let checkpoint_tree_height = 1;
        let base_fingerprint = qhash(700);
        let chain = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, checkpoint_tree_height);
        let (checkpoint, checkpoint_fingerprint) = checkpoint_proof_circuit();
        let (mut deposit, withdrawal, global_roots) = bridge_state_witnesses();
        deposit.contract_id = 9;
        let final_leaf = PQEDCheckpointLeafCompact {
            global_chain_root: global_roots_hash(&global_roots),
            stats_hash: qhash(12_000),
        };
        let delta = append_delta(hash_two(final_leaf.global_chain_root, final_leaf.stats_hash));
        let boundary = BridgeAggChainBoundary {
            chain_hash: qhash(10),
            checkpoint_tree_root: delta.old_root,
            checkpoint_leaf_hash: qhash(50),
            checkpoint_index: GOLDILOCKS_MODULUS - 1,
        };
        let base = chain.prove_base(boundary, &delta).unwrap();
        let final_circuit = final_circuit(
            &chain,
            &checkpoint,
            checkpoint_fingerprint,
            base_fingerprint,
            checkpoint_tree_height,
        );
        let checkpoint_proof = prove_checkpoint(&checkpoint, qhash(99_000));
        assert!(final_circuit
            .prove_base(
                &base,
                chain.get_verifier_config_ref(),
                &[BridgeAggFinalSlotWitness {
                    checkpoint_delta_merkle_proof: &delta,
                }],
                &checkpoint_proof,
                &checkpoint.verifier_only,
                &final_leaf,
                &global_roots,
                &deposit,
                &withdrawal,
            )
            .is_err());
    }

    #[test]
    fn final_pins_withdrawal_contract_id() {
        let checkpoint_tree_height = 1;
        let base_fingerprint = qhash(700);
        let chain = BridgeAggChainCircuit::<C, D>::new(base_fingerprint, checkpoint_tree_height);
        let (checkpoint, checkpoint_fingerprint) = checkpoint_proof_circuit();
        let (deposit, mut withdrawal, global_roots) = bridge_state_witnesses();
        withdrawal.contract_id = 9;
        let final_leaf = PQEDCheckpointLeafCompact {
            global_chain_root: global_roots_hash(&global_roots),
            stats_hash: qhash(12_000),
        };
        let delta = append_delta(hash_two(final_leaf.global_chain_root, final_leaf.stats_hash));
        let boundary = BridgeAggChainBoundary {
            chain_hash: qhash(10),
            checkpoint_tree_root: delta.old_root,
            checkpoint_leaf_hash: qhash(50),
            checkpoint_index: GOLDILOCKS_MODULUS - 1,
        };
        let base = chain.prove_base(boundary, &delta).unwrap();
        let final_circuit = final_circuit(
            &chain,
            &checkpoint,
            checkpoint_fingerprint,
            base_fingerprint,
            checkpoint_tree_height,
        );
        let checkpoint_proof = prove_checkpoint(&checkpoint, qhash(99_000));
        assert!(final_circuit
            .prove_base(
                &base,
                chain.get_verifier_config_ref(),
                &[BridgeAggFinalSlotWitness {
                    checkpoint_delta_merkle_proof: &delta,
                }],
                &checkpoint_proof,
                &checkpoint.verifier_only,
                &final_leaf,
                &global_roots,
                &deposit,
                &withdrawal,
            )
            .is_err());
    }

    #[test]
    fn prove_range_partition_boundaries_match_terminal_chunk_contract() {
        let cases = [
            (1usize, 0usize, 1usize),
            (31, 0, 31),
            (32, 0, 32),
            (33, 1, 1),
            (63, 1, 31),
            (64, 1, 32),
            (65, 2, 1),
            (95, 2, 31),
            (96, 2, 32),
            (97, 3, 1),
        ];

        for (total, expected_chain_proofs, expected_final_len) in cases {
            let (prefix_len, final_len) = bridge_agg_partition(total);
            assert_eq!(prefix_len / BRIDGE_AGG_CHAIN_MAX_SLOTS, expected_chain_proofs);
            assert_eq!(final_len, expected_final_len);
        }
    }
}
