use parth_core::{
    crypto::hash::spiderman::SpidermanUpdateProof,
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_data::v1::qdata::contract::{
    StateFieldLayoutLeaf, StateTypeLayoutWitness,
};

use crate::{
    gadgets::qdata::state_layout::{
        LayoutAppendPublicInputsGadget,
        StateLayoutAppendWithTypeProofsGadget,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

/// Canonical base proof for one fixed Spiderman state-layout append window.
///
/// This is the production entry point: unlike the legacy inline gadget, every
/// position verifies a canonical recursive type proof.
#[derive(Debug)]
pub struct StateLayoutAppendCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub contract_id: Target,
    pub append: StateLayoutAppendWithTypeProofsGadget<D>,
    pub output: LayoutAppendPublicInputsGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use parth_core::{
        pgoldilocks::{PoseidonHasher, QHashOut},
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    };
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
    };
    use psy_data::v1::qdata::contract::{
        fixed_array_type_layout, primitive_type_layout, struct_type_layout,
        CanonicalTypeLayoutDag, CanonicalTypeLayoutNode,
        StateFieldLayoutLeaf, StatePrimitiveTypeTag,
        StateTypeLayoutWitness, STATE_LAYOUT_DEPLOY_CONTRACT_ID,
    };

    use super::*;
    use crate::coordinator::circuits::{
        canonical_type_layout::CanonicalTypeLayoutCircuit,
        type_layout::{
            TypeLayoutProofPublicInputsGadget,
            VerifiedTypeLayoutProofGadget,
        },
    };
    use crate::gadgets::qdata::state_layout::StateLayoutAppendGadget;
    use psy_plonky2_common_circuits::hash::merkle::gadgets::
        spiderman_append_proof::SpidermanAppendProofGadget;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    fn dummy_canonical_type_circuit() -> CircuitData<
        <C as GenericConfig<D>>::F,
        C,
        D,
    > {
        let mut builder = CircuitBuilder::new(
            CircuitConfig::standard_recursion_config(),
        );
        for _ in
            0..TypeLayoutProofPublicInputsGadget::PUBLIC_INPUT_COUNT
        {
            builder.add_virtual_public_input();
        }
        builder.build::<C>()
    }

    #[test]
    fn builds_v2_layout_base_circuit_with_type_proofs() {
        let canonical_type = dummy_canonical_type_circuit();
        let circuit = StateLayoutAppendCircuit::<C, D>::new(
            2,
            1,
            &canonical_type.common,
            &canonical_type.verifier_only,
        );

        assert_eq!(circuit.append.type_proofs.len(), 2);
        assert_eq!(
            circuit.circuit_data.common.num_public_inputs,
            LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT
        );
    }

    fn prove_single_layout_append(
        dag: CanonicalTypeLayoutDag,
        field: StateFieldLayoutLeaf<QHashOut<F>>,
        type_witness: StateTypeLayoutWitness<QHashOut<F>>,
        top_line_height: usize,
        web_tree_height: usize,
    ) -> anyhow::Result<()> {
        let canonical_type = CanonicalTypeLayoutCircuit::<C, D>::new();
        let append = StateLayoutAppendCircuit::<C, D>::new(
            top_line_height,
            web_tree_height,
            canonical_type.get_common_circuit_data_ref(),
            canonical_type.get_verifier_config_ref(),
        );
        let type_proof = canonical_type.prove(&dag)?;
        canonical_type.circuit_data.verify(type_proof.clone())?;
        let padding_dag = CanonicalTypeLayoutDag {
            nodes: vec![CanonicalTypeLayoutNode::Primitive {
                type_tag: StatePrimitiveTypeTag::Felt,
            }],
            root: 0,
        };
        let padding_type_proof = canonical_type.prove(&padding_dag)?;
        canonical_type.circuit_data.verify(padding_type_proof.clone())?;
        anyhow::ensure!(
            type_proof.public_inputs[..4]
                == field.type_layout_hash.0.elements,
            "canonical type proof hash does not match field hash"
        );
        anyhow::ensure!(
            type_proof.public_inputs[4].to_canonical_u64()
                == field.slot_count,
            "canonical type proof slot count does not match field"
        );
        let field_hash = field.hash::<PoseidonHasher, F>()?;
        let mut tree =
            SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(
                (top_line_height + web_tree_height) as u8,
            );
        let proofs = tree.append_leaves_spider_man(web_tree_height as u8, &[field_hash])?;
        assert_eq!(proofs.len(), 1);
        let slot_count = field.slot_count;
        append.prove(
            STATE_LAYOUT_DEPLOY_CONTRACT_ID,
            &proofs[0],
            &[field],
            &[type_witness],
            &[type_proof.clone()],
            &padding_type_proof,
            0,
            1,
            0,
            slot_count,
        )?;
        Ok(())
    }

    #[test]
    fn proves_struct_layout_append() -> anyhow::Result<()> {
        let felt =
            primitive_type_layout::<PoseidonHasher, F, QHashOut<F>>(
                StatePrimitiveTypeTag::Felt,
                1,
            )?;
        let u32_layout =
            primitive_type_layout::<PoseidonHasher, F, QHashOut<F>>(
                StatePrimitiveTypeTag::U32,
                1,
            )?;
        let account = struct_type_layout::<
            PoseidonHasher,
            F,
            QHashOut<F>,
        >(&[felt, u32_layout], 5)?;
        let field = StateFieldLayoutLeaf::new(0, 0, account.summary)?;
        let type_witness =
            StateTypeLayoutWitness::Struct {
                member_count: 2,
                total_slot_count: account.summary.total_slot_count,
                members_root: account.members_root,
            };
        let dag = CanonicalTypeLayoutDag {
            nodes: vec![
                CanonicalTypeLayoutNode::Primitive {
                    type_tag: StatePrimitiveTypeTag::Felt,
                },
                CanonicalTypeLayoutNode::Primitive {
                    type_tag: StatePrimitiveTypeTag::U32,
                },
                CanonicalTypeLayoutNode::Struct {
                    members: vec![0, 1],
                    members_tree_height: 5,
                },
            ],
            root: 2,
        };
        prove_single_layout_append(dag, field, type_witness, 3, 4)
    }

    #[test]
    fn proves_fixed_array_layout_append() -> anyhow::Result<()> {
        let felt =
            primitive_type_layout::<PoseidonHasher, F, QHashOut<F>>(
                StatePrimitiveTypeTag::Felt,
                1,
            )?;
        let history =
            fixed_array_type_layout::<PoseidonHasher, F, QHashOut<F>>(
                felt, 32,
            )?;
        let field = StateFieldLayoutLeaf::new(0, 0, history)?;
        let type_witness = StateTypeLayoutWitness::FixedArray {
            element_type_hash: felt.type_layout_hash,
            element_slot_count: felt.total_slot_count,
            array_length: 32,
        };
        let dag = CanonicalTypeLayoutDag {
            nodes: vec![
                CanonicalTypeLayoutNode::Primitive {
                    type_tag: StatePrimitiveTypeTag::Felt,
                },
                CanonicalTypeLayoutNode::FixedArray {
                    element: 0,
                    length: 32,
                },
            ],
            root: 1,
        };
        prove_single_layout_append(dag, field, type_witness, 3, 0)
    }

    #[test]
    fn proves_real_batch_primitive_with_recursive_type_proof() -> anyhow::Result<()> {
        let canonical_type = CanonicalTypeLayoutCircuit::<C, D>::new();
        let felt = primitive_type_layout::<PoseidonHasher, F, QHashOut<F>>(
            StatePrimitiveTypeTag::Felt,
            1,
        )?;
        let field = StateFieldLayoutLeaf::new(0, 0, felt)?;
        let dag = CanonicalTypeLayoutDag {
            nodes: vec![CanonicalTypeLayoutNode::Primitive {
                type_tag: StatePrimitiveTypeTag::Felt,
            }],
            root: 0,
        };
        let proof = canonical_type.prove(&dag)?;
        assert_eq!(
            proof.public_inputs[..4],
            field.type_layout_hash.0.elements,
            "fixed-array recursive proof hash endpoint mismatch"
        );
        assert_eq!(
            proof.public_inputs[4].to_canonical_u64(),
            field.slot_count,
            "fixed-array recursive proof slot endpoint mismatch"
        );
        canonical_type.circuit_data.verify(proof.clone())?;
        prove_single_layout_append(
            dag,
            field,
            StateTypeLayoutWitness::Primitive {
                type_tag: StatePrimitiveTypeTag::Felt,
            },
            3,
            4,
        )
    }

    #[test]
    fn verifies_fixed_array_proof_and_connects_field() -> anyhow::Result<()> {
        let canonical_type = CanonicalTypeLayoutCircuit::<C, D>::new();
        let felt = primitive_type_layout::<PoseidonHasher, F, QHashOut<F>>(
            StatePrimitiveTypeTag::Felt,
            1,
        )?;
        let history = fixed_array_type_layout::<PoseidonHasher, F, QHashOut<F>>(
            felt,
            32,
        )?;
        let field = StateFieldLayoutLeaf::new(0, 0, history)?;
        let dag = CanonicalTypeLayoutDag {
            nodes: vec![
                CanonicalTypeLayoutNode::Primitive {
                    type_tag: StatePrimitiveTypeTag::Felt,
                },
                CanonicalTypeLayoutNode::FixedArray {
                    element: 0,
                    length: 32,
                },
            ],
            root: 1,
        };
        let proof = canonical_type.prove(&dag)?;
        assert_eq!(proof.public_inputs[..4], field.type_layout_hash.0.elements);
        assert_eq!(proof.public_inputs[4].to_canonical_u64(), field.slot_count);
        let mut builder = CircuitBuilder::<F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let verified = VerifiedTypeLayoutProofGadget::add_virtual_to::<C>(
            &mut builder,
            canonical_type.get_common_circuit_data_ref(),
            canonical_type.get_verifier_config_ref(),
        );
        let circuit = builder.build::<C>();
        let mut witness = plonky2::iop::witness::PartialWitness::new();
        verified.set_witness::<C>(&mut witness, &proof)?;
        circuit.prove(witness)?;
        Ok(())
    }

    #[test]
    fn canonical_type_proof_is_recursively_verifiable(
    ) -> anyhow::Result<()> {
        let canonical_type = CanonicalTypeLayoutCircuit::<C, D>::new();
        let felt =
            primitive_type_layout::<PoseidonHasher, F, QHashOut<F>>(
                StatePrimitiveTypeTag::Felt,
                1,
            )?;
        let field = StateFieldLayoutLeaf::new(0, 0, felt)?;
        let dag = CanonicalTypeLayoutDag {
            nodes: vec![CanonicalTypeLayoutNode::Primitive {
                type_tag: StatePrimitiveTypeTag::Felt,
            }],
            root: 0,
        };
        let proof = canonical_type.prove(&dag)?;
        canonical_type.circuit_data.verify(proof.clone())?;

        let mut builder = CircuitBuilder::<F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let verified = VerifiedTypeLayoutProofGadget::add_virtual_to::<C>(
            &mut builder,
            canonical_type.get_common_circuit_data_ref(),
            canonical_type.get_verifier_config_ref(),
        );
        let field_target =
            crate::gadgets::qdata::state_layout::
                StateFieldLayoutLeafGadget::add_virtual_to(&mut builder);
        let active = builder._true();
        verified.connect_field(&mut builder, &field_target, active);
        let outer = builder.build::<C>();

        let mut witness = plonky2::iop::witness::PartialWitness::new();
        verified.set_witness::<C>(&mut witness, &proof)?;
        field_target.set_witness(&mut witness, &field)?;
        outer.prove(witness)?;
        Ok(())
    }

    fn single_felt_field_and_proof() -> anyhow::Result<(
        StateFieldLayoutLeaf<QHashOut<F>>,
        StateTypeLayoutWitness<QHashOut<F>>,
        parth_core::crypto::hash::spiderman::SpidermanUpdateProof<
            QHashOut<F>,
        >,
    )> {
        let felt =
            primitive_type_layout::<PoseidonHasher, F, QHashOut<F>>(
                StatePrimitiveTypeTag::Felt,
                1,
            )?;
        let field = StateFieldLayoutLeaf::new(0, 0, felt)?;
        let field_hash = field.hash::<PoseidonHasher, F>()?;
        let mut tree =
            SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(4);
        let mut proofs =
            tree.append_leaves_spider_man(1, &[field_hash])?;
        Ok((
            field,
            StateTypeLayoutWitness::Primitive {
                type_tag: StatePrimitiveTypeTag::Felt,
            },
            proofs.remove(0),
        ))
    }

    #[test]
    fn spiderman_layout_proof_alone_is_satisfiable(
    ) -> anyhow::Result<()> {
        let (_, _, proof) = single_felt_field_and_proof()?;
        let mut builder = CircuitBuilder::<F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let gadget =
            SpidermanAppendProofGadget::add_virtual_to::<
                plonky2::hash::poseidon::PoseidonHash,
                F,
                D,
            >(&mut builder, 3, 1);
        let circuit = builder.build::<C>();
        let mut witness = plonky2::iop::witness::PartialWitness::new();
        gadget.set_witness(&mut witness, &proof)?;
        circuit.prove(witness)?;
        Ok(())
    }

    #[test]
    fn spiderman_real_layout_batch_is_satisfiable() -> anyhow::Result<()> {
        let leaves = vec![QHashOut::rand(), QHashOut::rand()];
        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(7);
        let proofs = tree.append_leaves_spider_man(4, &leaves)?;
        assert_eq!(proofs.len(), 1);
        assert!(proofs[0].verify::<PoseidonHasher>());
        let mut builder = CircuitBuilder::<F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let gadget = SpidermanAppendProofGadget::add_virtual_to::<
            plonky2::hash::poseidon::PoseidonHash,
            F,
            D,
        >(&mut builder, 3, 4);
        let circuit = builder.build::<C>();
        let mut witness = plonky2::iop::witness::PartialWitness::new();
        gadget.set_witness(&mut witness, &proofs[0])?;
        circuit.prove(witness)?;
        Ok(())
    }

    #[test]
    fn layout_frontiers_without_recursive_type_proof_are_satisfiable(
    ) -> anyhow::Result<()> {
        let (field, type_witness, proof) =
            single_felt_field_and_proof()?;
        let mut builder = CircuitBuilder::<F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let gadget = StateLayoutAppendGadget::add_virtual_to::<
            plonky2::hash::poseidon::PoseidonHash,
            F,
            D,
        >(&mut builder, 3, 1);
        let circuit = builder.build::<C>();
        let mut witness = plonky2::iop::witness::PartialWitness::new();
        gadget.set_witness(
            &mut witness,
            &proof,
            &[field],
            &[type_witness],
            0,
            1,
            0,
            1,
        )?;
        circuit.prove(witness)?;
        Ok(())
    }

    #[test]
    fn layout_real_batch_without_recursive_type_proof_is_satisfiable(
    ) -> anyhow::Result<()> {
        let (field, type_witness, _) = single_felt_field_and_proof()?;
        let field_hash = field.hash::<PoseidonHasher, F>()?;
        let mut tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(7);
        let mut proofs = tree.append_leaves_spider_man(4, &[field_hash])?;
        let proof = proofs.remove(0);
        let mut builder = CircuitBuilder::<F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let gadget = StateLayoutAppendGadget::add_virtual_to::<
            plonky2::hash::poseidon::PoseidonHash,
            F,
            D,
        >(&mut builder, 3, 4);
        let circuit = builder.build::<C>();
        let mut witness = plonky2::iop::witness::PartialWitness::new();
        gadget.set_witness(
            &mut witness,
            &proof,
            &[field],
            &[type_witness],
            0,
            1,
            0,
            1,
        )?;
        circuit.prove(witness)?;
        Ok(())
    }
}

impl<C: GenericConfig<D>, const D: usize>
    StateLayoutAppendCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        top_line_height: usize,
        web_tree_height: usize,
        canonical_type_common: &CommonCircuitData<C::F, D>,
        canonical_type_verifier: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let contract_id = builder.add_virtual_target();
        let append =
            StateLayoutAppendWithTypeProofsGadget::add_virtual_to::<C>(
                &mut builder,
                top_line_height,
                web_tree_height,
                canonical_type_common,
                canonical_type_verifier,
            );
        let output = append
            .append
            .to_public_inputs::<C::Hasher, C::F, D>(
                &mut builder,
                contract_id,
            );
        output.register_public_inputs(&mut builder);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(
            get_circuit_fingerprint_generic(
                &circuit_data.verifier_only,
            ),
        );
        Self {
            contract_id,
            append,
            output,
            circuit_data,
            fingerprint,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        &self,
        contract_id: u64,
        spiderman_proof: &SpidermanUpdateProof<QHashOut<C::F>>,
        appended_fields: &[StateFieldLayoutLeaf<QHashOut<C::F>>],
        appended_type_layouts: &[
            StateTypeLayoutWitness<QHashOut<C::F>>
        ],
        appended_type_proofs: &[ProofWithPublicInputs<C::F, C, D>],
        padding_type_proof: &ProofWithPublicInputs<C::F, C, D>,
        old_layout_field_count: u64,
        new_layout_field_count: u64,
        old_layout_slot_count: u64,
        new_layout_slot_count: u64,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut witness = PartialWitness::new();
        witness.set_target(
            self.contract_id,
            C::F::from_canonical_u64(contract_id),
        )?;
        self.append.set_witness::<C>(
            &mut witness,
            spiderman_proof,
            appended_fields,
            appended_type_layouts,
            appended_type_proofs,
            padding_type_proof,
            old_layout_field_count,
            new_layout_field_count,
            old_layout_slot_count,
            new_layout_slot_count,
        )?;
        self.circuit_data.prove(witness)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for StateLayoutAppendCircuit<C, D>
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
