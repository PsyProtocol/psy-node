use parth_core::{
    crypto::hash::spiderman::SpidermanUpdateProof,
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::Witness,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_data::v1::qdata::contract::PQEDContractLeafV2;
use psy_plonky2_basic_helpers::builder::{
    connect::CircuitBuilderConnectHelpers,
    core::CircuitBuilderHelpersCore,
};
use psy_plonky2_common_circuits::hash::merkle::gadgets::spiderman_append_proof::SpidermanAppendProofGadget;

use crate::gadgets::qdata::state_layout::{
    LayoutAppendPublicInputsGadget, QEDContractLeafV2Gadget,
};

/// Layout-aware contract update gadget.
///
/// The outer Spiderman proof retains overwrite semantics for contract code
/// updates. Every changed contract position additionally carries a verified
/// layout proof whose old/new endpoints are bound to the corresponding V2
/// contract leaf. Unchanged positions use a valid padding proof; its public
/// inputs are deliberately ignored.
#[derive(Debug, Clone)]
pub struct BatchUpdateContractsGadget<const D: usize> {
    pub spiderman: SpidermanAppendProofGadget,
    pub old_contract_leaves: Vec<QEDContractLeafV2Gadget>,
    pub new_contract_leaves: Vec<QEDContractLeafV2Gadget>,
    pub updated_contract_ids: Vec<Target>,
    pub layout_proofs: Vec<ProofWithPublicInputsTarget<D>>,
}

impl<const D: usize> BatchUpdateContractsGadget<D> {
    pub fn add_virtual_to<C>(
        builder: &mut CircuitBuilder<C::F, D>,
        contract_tree_height: usize,
        batch_sub_tree_height: usize,
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
            "layout child circuit has an incompatible public interface"
        );
        let top_line_height =
            contract_tree_height - batch_sub_tree_height;
        let spiderman =
            SpidermanAppendProofGadget::add_virtual_to_allow_overwrite::<
                C::Hasher,
                C::F,
                D,
            >(builder, top_line_height, batch_sub_tree_height);
        let window_size = 1usize << batch_sub_tree_height;
        let old_contract_leaves = (0..window_size)
            .map(|_| QEDContractLeafV2Gadget::add_virtual_to(builder))
            .collect::<Vec<_>>();
        let new_contract_leaves = (0..window_size)
            .map(|_| QEDContractLeafV2Gadget::add_virtual_to(builder))
            .collect::<Vec<_>>();
        let updated_contract_ids = (0..window_size)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<_>>();

        let layout_verifier_target =
            builder.constant_verifier_data(layout_verifier_data);
        let layout_proofs = (0..window_size)
            .map(|_| {
                let proof =
                    builder.add_virtual_proof_with_pis(layout_common_data);
                builder.verify_proof::<C>(
                    &proof,
                    &layout_verifier_target,
                    layout_common_data,
                );
                proof
            })
            .collect::<Vec<_>>();

        let zero = builder.zero();
        let window_size_target =
            builder.constant_u64(window_size as u64);
        let window_start = builder.mul(
            spiderman.top_line_proof.index,
            window_size_target,
        );
        for index in 0..window_size {
            let is_updated = spiderman.get_added_leaves()[index];
            let old_leaf_hash =
                old_contract_leaves[index].to_hash::<C::Hasher, C::F, D>(
                    builder,
                );
            let new_leaf_hash =
                new_contract_leaves[index].to_hash::<C::Hasher, C::F, D>(
                    builder,
                );
            builder.connect_hashes_if_true(
                is_updated,
                old_leaf_hash,
                spiderman.web_proof.old_leaves[index],
            );
            builder.connect_hashes_if_true(
                is_updated,
                new_leaf_hash,
                spiderman.web_proof.new_leaves[index],
            );

            let window_offset = builder.constant_u64(index as u64);
            let expected_contract_id =
                builder.add(window_start, window_offset);
            builder.connect_if_true(
                is_updated,
                updated_contract_ids[index],
                expected_contract_id,
            );
            let is_unchanged = builder.not(is_updated);
            builder.connect_if_true(
                is_unchanged,
                updated_contract_ids[index],
                zero,
            );

            let layout = LayoutAppendPublicInputsGadget::from_public_inputs(
                &layout_proofs[index].public_inputs,
            );
            layout.enforce_shape(builder);
            builder.connect_if_true(
                is_updated,
                layout.contract_id,
                expected_contract_id,
            );
            builder.connect_hashes_if_true(
                is_updated,
                layout.old_layout_root,
                old_contract_leaves[index].state_layout_root,
            );
            builder.connect_hashes_if_true(
                is_updated,
                layout.new_layout_root,
                new_contract_leaves[index].state_layout_root,
            );
            builder.connect_if_true(
                is_updated,
                layout.old_layout_field_count,
                old_contract_leaves[index].state_layout_field_count,
            );
            builder.connect_if_true(
                is_updated,
                layout.new_layout_field_count,
                new_contract_leaves[index].state_layout_field_count,
            );
            builder.connect_if_true(
                is_updated,
                layout.old_layout_slot_count,
                old_contract_leaves[index].state_layout_slot_count,
            );
            builder.connect_if_true(
                is_updated,
                layout.new_layout_slot_count,
                new_contract_leaves[index].state_layout_slot_count,
            );
            builder.connect_hashes_if_true(
                is_updated,
                old_contract_leaves[index].deployer,
                new_contract_leaves[index].deployer,
            );
            builder.connect_if_true(
                is_updated,
                old_contract_leaves[index].state_tree_height,
                new_contract_leaves[index].state_tree_height,
            );
        }

        Self {
            spiderman,
            old_contract_leaves,
            new_contract_leaves,
            updated_contract_ids,
            layout_proofs,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_witness<C>(
        &self,
        witness: &mut impl Witness<C::F>,
        spiderman_proof: &SpidermanUpdateProof<QHashOut<C::F>>,
        old_contract_leaves: &[PQEDContractLeafV2<C::F, QHashOut<C::F>>],
        new_contract_leaves: &[PQEDContractLeafV2<C::F, QHashOut<C::F>>],
        updated_contract_ids: &[u64],
        changed_layout_proofs: &[ProofWithPublicInputs<C::F, C, D>],
    ) -> anyhow::Result<()>
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        anyhow::ensure!(
            old_contract_leaves.len() == new_contract_leaves.len()
                && old_contract_leaves.len() == updated_contract_ids.len()
                && old_contract_leaves.len() == changed_layout_proofs.len()
                && !changed_layout_proofs.is_empty(),
            "changed contract leaves, ids, and layout proofs must have equal lengths"
        );
        let padding_layout_proof = &changed_layout_proofs[0];
        anyhow::ensure!(
            spiderman_proof.web_proof_old_leaves.len()
                == self.old_contract_leaves.len()
                && spiderman_proof.web_proof_new_leaves.len()
                    == self.new_contract_leaves.len(),
            "contract Spiderman proof window has the wrong size"
        );
        self.spiderman.set_witness(witness, spiderman_proof)?;

        let empty = PQEDContractLeafV2::default();
        let mut changed_index = 0usize;
        for index in 0..self.old_contract_leaves.len() {
            let changed = spiderman_proof.web_proof_old_leaves[index]
                != spiderman_proof.web_proof_new_leaves[index];
            if changed {
                let old_leaf = old_contract_leaves
                    .get(changed_index)
                    .ok_or_else(|| anyhow::anyhow!(
                        "missing changed old contract leaf"
                    ))?;
                let new_leaf = new_contract_leaves
                    .get(changed_index)
                    .ok_or_else(|| anyhow::anyhow!(
                        "missing changed new contract leaf"
                    ))?;
                self.old_contract_leaves[index]
                    .set_witness(witness, old_leaf)?;
                self.new_contract_leaves[index]
                    .set_witness(witness, new_leaf)?;
                witness.set_target(
                    self.updated_contract_ids[index],
                    C::F::from_canonical_u64(
                        updated_contract_ids[changed_index],
                    ),
                )?;
                witness.set_proof_with_pis_target(
                    &self.layout_proofs[index],
                    &changed_layout_proofs[changed_index],
                )?;
                changed_index += 1;
            } else {
                self.old_contract_leaves[index]
                    .set_witness(witness, &empty)?;
                self.new_contract_leaves[index]
                    .set_witness(witness, &empty)?;
                witness
                    .set_target(self.updated_contract_ids[index], C::F::ZERO)?;
                witness.set_proof_with_pis_target(
                    &self.layout_proofs[index],
                    padding_layout_proof,
                )?;
            }
        }
        anyhow::ensure!(
            changed_index == old_contract_leaves.len(),
            "too many changed contract witnesses supplied"
        );
        Ok(())
    }
}
