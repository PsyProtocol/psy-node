use parth_core::{
    crypto::hash::spiderman::SpidermanUpdateProof,
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOutTarget,
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_data::v1::qdata::contract::{
    PQEDContractLeafV2, STATE_LAYOUT_DEPLOY_CONTRACT_ID,
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison,
    connect::CircuitBuilderConnectHelpers,
    core::CircuitBuilderHelpersCore,
    hash::core::CircuitBuilderHashCore,
};
use psy_plonky2_common_circuits::hash::merkle::gadgets::spiderman_append_proof::SpidermanAppendProofGadget;

use crate::gadgets::qdata::state_layout::{
    LayoutAppendPublicInputsGadget, QEDContractLeafV2Gadget,
};

/// Deploys contract leaves and binds every new leaf to a verified initial
/// layout transition from the canonical empty layout tree.
#[derive(Debug, Clone)]
pub struct BatchDeployContractsGadget<const D: usize> {
    pub spiderman: SpidermanAppendProofGadget,
    pub contract_leaves: Vec<QEDContractLeafV2Gadget>,
    pub contract_ids: Vec<Target>,
    pub layout_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    pub empty_layout_root: HashOutTarget,
}

impl<const D: usize> BatchDeployContractsGadget<D> {
    pub fn add_virtual_to<C>(
        builder: &mut CircuitBuilder<C::F, D>,
        contract_tree_height: usize,
        batch_sub_tree_height: usize,
        state_layout_tree_height: usize,
        max_contract_state_tree_height: usize,
        layout_common_data: &CommonCircuitData<C::F, D>,
        layout_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        assert_eq!(
            layout_common_data.num_public_inputs,
            LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT,
            "layout deploy proof has an incompatible public interface"
        );
        assert!(
            contract_tree_height >= batch_sub_tree_height,
            "deploy subtree exceeds contract tree"
        );
        assert!(
            max_contract_state_tree_height < 63,
            "state capacity comparison requires height < 63"
        );

        let top_line_height =
            contract_tree_height - batch_sub_tree_height;
        let spiderman =
            SpidermanAppendProofGadget::add_virtual_to_allow_existing::<
                C::Hasher,
                C::F,
                D,
            >(builder, top_line_height, batch_sub_tree_height);
        let window_size = 1usize << batch_sub_tree_height;
        let contract_leaves = (0..window_size)
            .map(|_| QEDContractLeafV2Gadget::add_virtual_to(builder))
            .collect::<Vec<_>>();
        let contract_ids = (0..window_size)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<_>>();

        let verifier =
            builder.constant_verifier_data(layout_verifier_data);
        let mut layout_proofs = Vec::with_capacity(window_size);
        for index in 0..window_size {
            let proof_target_start_row = builder.num_gates();
            let proof = builder.add_virtual_proof_with_pis(layout_common_data);
            let verify_start_row = builder.num_gates();
            builder.verify_proof::<C>(
                &proof,
                &verifier,
                layout_common_data,
            );
            eprintln!(
                "[BatchDeployContracts/build] slot={} segment=layout_proof_target rows=[{}, {}) segment=layout_verify rows=[{}, {}) public_input_targets={:?}",
                index, proof_target_start_row, verify_start_row,
                verify_start_row, builder.num_gates(), proof.public_inputs,
            );
            layout_proofs.push(proof);
        }

        let zero = builder.zero();
        let one = builder.one();
        let deploy_layout_contract_id =
            builder.constant_u64(STATE_LAYOUT_DEPLOY_CONTRACT_ID);
        let mut empty_layout_root = HashOutTarget {
            elements: [zero; 4],
        };
        for _ in 0..state_layout_tree_height {
            empty_layout_root =
                builder.hash_two_to_one::<C::Hasher>(
                    empty_layout_root,
                    empty_layout_root,
                );
        }

        let window_size_target =
            builder.constant_u64(window_size as u64);
        let window_start = builder.mul(
            spiderman.top_line_proof.index,
            window_size_target,
        );
        for index in 0..window_size {
            let is_added = spiderman.get_added_leaves()[index];
            let leaf_hash = contract_leaves[index]
                .to_hash::<C::Hasher, C::F, D>(builder);
            builder.connect_hashes_if_true(
                is_added,
                leaf_hash,
                spiderman.web_proof.new_leaves[index],
            );

            let offset = builder.constant_u64(index as u64);
            let expected_contract_id =
                builder.add(window_start, offset);
            builder.connect_if_true(
                is_added,
                contract_ids[index],
                expected_contract_id,
            );
            let inactive = builder.not(is_added);
            builder.connect_if_true(
                inactive,
                contract_ids[index],
                zero,
            );

            let layout = LayoutAppendPublicInputsGadget::from_public_inputs(
                &layout_proofs[index].public_inputs,
            );
            layout.enforce_shape(builder);
            builder.connect_if_true(
                is_added,
                layout.contract_id,
                deploy_layout_contract_id,
            );
            builder.connect_hashes_if_true(
                is_added,
                layout.old_layout_root,
                empty_layout_root,
            );
            builder.connect_if_true(
                is_added,
                layout.old_layout_field_count,
                zero,
            );
            builder.connect_if_true(
                is_added,
                layout.old_layout_slot_count,
                zero,
            );
            builder.connect_hashes_if_true(
                is_added,
                layout.new_layout_root,
                contract_leaves[index].state_layout_root,
            );
            builder.connect_if_true(
                is_added,
                layout.new_layout_field_count,
                contract_leaves[index].state_layout_field_count,
            );
            builder.connect_if_true(
                is_added,
                layout.new_layout_slot_count,
                contract_leaves[index].state_layout_slot_count,
            );

            let mut selected_capacity = zero;
            let mut valid_height = zero;
            for height in 1..=max_contract_state_tree_height {
                let height_target =
                    builder.constant_u64(height as u64);
                let is_height = builder.is_equal(
                    contract_leaves[index].state_tree_height,
                    height_target,
                );
                valid_height =
                    builder.add(valid_height, is_height.target);
                // `state_layout_slot_count` is measured in felts, while each
                // state-tree leaf stores one Hash (four felts). Keep this
                // capacity calculation consistent with the protocol-side
                // layout validation in psy_data.
                let capacity =
                    builder.constant_u64((1u64 << height) * 4);
                let selected =
                    builder.mul(is_height.target, capacity);
                selected_capacity =
                    builder.add(selected_capacity, selected);
            }
            builder.connect_if_true(is_added, valid_height, one);
            let within_capacity = builder.is_less_than_or_equal(
                max_contract_state_tree_height + 1,
                contract_leaves[index].state_layout_slot_count,
                selected_capacity,
            );
            builder.connect_if_true(
                is_added,
                within_capacity.target,
                one,
            );
        }

        Self {
            spiderman,
            contract_leaves,
            contract_ids,
            layout_proofs,
            empty_layout_root,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_witness<C>(
        &self,
        witness: &mut impl Witness<C::F>,
        spiderman_proof: &SpidermanUpdateProof<QHashOut<C::F>>,
        contract_ids: &[u64],
        contract_leaves: &[PQEDContractLeafV2<C::F, QHashOut<C::F>>],
        layout_proofs: &[ProofWithPublicInputs<C::F, C, D>],
    ) -> anyhow::Result<()>
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        anyhow::ensure!(
            contract_ids.len() == contract_leaves.len()
                && contract_leaves.len() == layout_proofs.len()
                && !layout_proofs.is_empty(),
            "deploy witness vectors have different lengths"
        );
        let padding_layout_proof = &layout_proofs[0];
        eprintln!(
            "[BatchDeployContracts/debug] stage=spiderman begin top_line_index={} old_root={:?} new_root={:?} old_leaves={:?} new_leaves={:?}",
            spiderman_proof.top_line_proof.index,
            spiderman_proof.top_line_proof.old_root,
            spiderman_proof.top_line_proof.new_root,
            spiderman_proof.web_proof_old_leaves,
            spiderman_proof.web_proof_new_leaves,
        );
        self.spiderman
            .set_witness(witness, spiderman_proof)
            .map_err(|err| anyhow::anyhow!(
                "BatchDeployContracts stage=spiderman witness failed: {err:#}"
            ))?;
        eprintln!("[BatchDeployContracts/debug] stage=spiderman ok");
        let empty_leaf = PQEDContractLeafV2::default();
        let mut added_index = 0usize;
        for index in 0..self.contract_leaves.len() {
            let old_leaf = spiderman_proof.web_proof_old_leaves[index];
            let new_leaf = spiderman_proof.web_proof_new_leaves[index];
            let is_added = spiderman_proof.web_proof_old_leaves[index]
                == QHashOut::ZERO
                && spiderman_proof.web_proof_new_leaves[index]
                    != QHashOut::ZERO;
            eprintln!(
                "[BatchDeployContracts/debug] slot={index} is_added={is_added} old_leaf={old_leaf:?} new_leaf={new_leaf:?} added_index={added_index} supplied_contracts={} window_slots={}",
                contract_leaves.len(),
                self.contract_leaves.len(),
            );
            if is_added {
                let contract_id =
                    *contract_ids.get(added_index).ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing deploy contract id"
                        )
                    })?;
                let leaf =
                    contract_leaves.get(added_index).ok_or_else(|| {
                        anyhow::anyhow!("missing deploy leaf")
                    })?;
                let proof =
                    layout_proofs.get(added_index).ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing deploy layout proof"
                        )
                    })?;
                let pis = &proof.public_inputs;
                eprintln!(
                    "[BatchDeployContracts/debug] active slot={index} contract_id={contract_id} leaf={{deployer:{:?}, function_tree_root:{:?}, code_root:{:?}, state_tree_height:{:?}, state_layout_root:{:?}, state_layout_field_count:{:?}, state_layout_slot_count:{:?}}}",
                    leaf.deployer,
                    leaf.function_tree_root,
                    leaf.code_root,
                    leaf.state_tree_height,
                    leaf.state_layout_root,
                    leaf.state_layout_field_count,
                    leaf.state_layout_slot_count,
                );
                eprintln!(
                    "[BatchDeployContracts/debug] active slot={index} layout_pis_len={} layout_pis={pis:?}",
                    pis.len(),
                );
                if pis.len() >= LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT {
                    eprintln!(
                        "[BatchDeployContracts/debug] active slot={index} layout={{contract_id:{:?}, version:{:?}, old_root:{:?}, old_field_count:{:?}, old_slot_count:{:?}, new_root:{:?}, new_field_count:{:?}, new_slot_count:{:?}, appended_field_count:{:?}, commitment:{:?}}}",
                        pis[0], pis[1], &pis[2..6], pis[6], pis[7],
                        &pis[8..12], pis[12], pis[13], pis[14], &pis[15..19],
                    );
                }
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=contract_id begin value={contract_id} target={:?}",
                    self.contract_ids[index],
                );
                witness
                    .set_target(
                        self.contract_ids[index],
                        C::F::from_canonical_u64(contract_id),
                    )
                    .map_err(|err| anyhow::anyhow!(
                        "BatchDeployContracts slot={index} stage=contract_id value={contract_id} failed: {err:#}"
                    ))?;
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=contract_id ok"
                );
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=contract_leaf begin"
                );
                self.contract_leaves[index]
                    .set_witness(witness, leaf)
                    .map_err(|err| anyhow::anyhow!(
                        "BatchDeployContracts slot={index} stage=contract_leaf failed: {err:#}"
                    ))?;
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=contract_leaf ok"
                );
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=layout_proof begin proof_target={:?}",
                    self.layout_proofs[index],
                );
                witness
                    .set_proof_with_pis_target(
                        &self.layout_proofs[index],
                        proof,
                    )
                    .map_err(|err| anyhow::anyhow!(
                        "BatchDeployContracts slot={index} stage=layout_proof failed: {err:#}"
                    ))?;
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=layout_proof ok"
                );
                added_index += 1;
            } else {
                eprintln!(
                    "[BatchDeployContracts/debug] inactive slot={index} using empty contract leaf and padding layout proof pis={:?}",
                    padding_layout_proof.public_inputs,
                );
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=padding_contract_id begin target={:?}",
                    self.contract_ids[index],
                );
                witness
                    .set_target(self.contract_ids[index], C::F::ZERO)
                    .map_err(|err| anyhow::anyhow!(
                        "BatchDeployContracts slot={index} stage=padding_contract_id failed: {err:#}"
                    ))?;
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=padding_contract_id ok"
                );
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=padding_contract_leaf begin value={empty_leaf:?}"
                );
                self.contract_leaves[index]
                    .set_witness(witness, &empty_leaf)
                    .map_err(|err| anyhow::anyhow!(
                        "BatchDeployContracts slot={index} stage=padding_contract_leaf failed: {err:#}"
                    ))?;
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=padding_contract_leaf ok"
                );
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=padding_layout_proof begin proof_target={:?}",
                    self.layout_proofs[index],
                );
                witness
                    .set_proof_with_pis_target(
                        &self.layout_proofs[index],
                        padding_layout_proof,
                    )
                    .map_err(|err| anyhow::anyhow!(
                        "BatchDeployContracts slot={index} stage=padding_layout_proof failed: {err:#}"
                    ))?;
                eprintln!(
                    "[BatchDeployContracts/debug] slot={index} stage=padding_layout_proof ok"
                );
            }
        }
        eprintln!(
            "[BatchDeployContracts/debug] stage=all_slots_complete consumed_contracts={added_index} supplied_contracts={}",
            contract_leaves.len(),
        );
        anyhow::ensure!(
            added_index == contract_leaves.len(),
            "unused deploy witnesses were supplied"
        );
        Ok(())
    }
}
