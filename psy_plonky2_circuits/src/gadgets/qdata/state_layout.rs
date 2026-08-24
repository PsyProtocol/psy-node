use parth_core::{
    crypto::hash::spiderman::SpidermanUpdateProof,
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_data::v1::qdata::contract::{
    LayoutAppendPublicInputs, PQEDContractLeafV2, StateFieldLayoutLeaf,
    StateMapKind, StatePrimitiveTypeTag, StateTypeLayoutWitness,
    CONTRACT_LEAF_DOMAIN, FIXED_ARRAY_TYPE_LAYOUT_DOMAIN,
    FIXED_MAP_TYPE_LAYOUT_DOMAIN, PRIMITIVE_TYPE_LAYOUT_DOMAIN,
    STATE_LAYOUT_APPEND_AGG_DOMAIN,
    STATE_LAYOUT_APPEND_BATCH_DOMAIN, STATE_LAYOUT_ENCODING_VERSION,
    STATE_LAYOUT_VERSION, STATE_FIELD_LAYOUT_DOMAIN,
    STRUCT_TYPE_LAYOUT_DOMAIN,
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison,
    connect::CircuitBuilderConnectHelpers,
    core::CircuitBuilderHelpersCore,
    select::CircuitBuilderSelectHelpers,
};
use psy_plonky2_common_circuits::hash::merkle::gadgets::spiderman_append_proof::SpidermanAppendProofGadget;

use crate::coordinator::circuits::type_layout::VerifiedTypeLayoutProofGadget;

#[derive(Debug, Clone)]
pub struct StateFieldLayoutLeafGadget {
    pub field_id: Target,
    pub start_slot: Target,
    pub payload_offset: Target,
    pub slot_count: Target,
    pub type_layout_hash: HashOutTarget,
    pub encoding_version: Target,
}

#[derive(Debug, Clone)]
pub struct StateTypeLayoutWitnessGadget {
    /// 1=primitive, 2=fixed array, 3=struct, 4=fixed map.
    pub kind: Target,
    pub primitive_tag: Target,
    pub child_type_hash: HashOutTarget,
    pub child_slot_count: Target,
    pub array_length: Target,
    pub member_count: Target,
    pub struct_slot_count: Target,
    pub members_root: HashOutTarget,
    pub map_kind: Target,
    pub key_type_hash: HashOutTarget,
    pub key_slot_count: Target,
    pub value_type_hash: HashOutTarget,
    pub value_slot_count: Target,
    pub map_capacity: Target,
    pub map_alignment: Target,
    /// Quotient witnessing that the aligned payload start is a multiple of
    /// `map_alignment`.
    pub map_aligned_start_quotient: Target,
}

#[derive(Debug, Clone)]
pub struct QEDContractLeafV2Gadget {
    pub deployer: HashOutTarget,
    pub function_tree_root: HashOutTarget,
    pub code_root: HashOutTarget,
    pub state_tree_height: Target,
    pub state_layout_root: HashOutTarget,
    pub state_layout_field_count: Target,
    pub state_layout_slot_count: Target,
}

#[derive(Debug, Clone)]
pub struct LayoutAppendPublicInputsGadget {
    pub contract_id: Target,
    pub layout_version: Target,
    pub old_layout_root: HashOutTarget,
    pub old_layout_field_count: Target,
    pub old_layout_slot_count: Target,
    pub new_layout_root: HashOutTarget,
    pub new_layout_field_count: Target,
    pub new_layout_slot_count: Target,
    pub appended_field_count: Target,
    pub appended_fields_commitment: HashOutTarget,
}

#[derive(Debug, Clone)]
pub struct LayoutAppendProofAggregationGadget<const D: usize> {
    pub left_proof: ProofWithPublicInputsTarget<D>,
    pub right_proof: ProofWithPublicInputsTarget<D>,
    pub output: LayoutAppendPublicInputsGadget,
}

impl LayoutAppendPublicInputsGadget {
    pub const PUBLIC_INPUT_COUNT: usize = 19;

    pub fn from_public_inputs(public_inputs: &[Target]) -> Self {
        assert_eq!(
            public_inputs.len(),
            Self::PUBLIC_INPUT_COUNT,
            "layout proof public input length mismatch"
        );
        Self {
            contract_id: public_inputs[0],
            layout_version: public_inputs[1],
            old_layout_root: HashOutTarget {
                elements: public_inputs[2..6].try_into().unwrap(),
            },
            old_layout_field_count: public_inputs[6],
            old_layout_slot_count: public_inputs[7],
            new_layout_root: HashOutTarget {
                elements: public_inputs[8..12].try_into().unwrap(),
            },
            new_layout_field_count: public_inputs[12],
            new_layout_slot_count: public_inputs[13],
            appended_field_count: public_inputs[14],
            appended_fields_commitment: HashOutTarget {
                elements: public_inputs[15..19].try_into().unwrap(),
            },
        }
    }

    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            contract_id: builder.add_virtual_target(),
            layout_version: builder.add_virtual_target(),
            old_layout_root: builder.add_virtual_hash(),
            old_layout_field_count: builder.add_virtual_target(),
            old_layout_slot_count: builder.add_virtual_target(),
            new_layout_root: builder.add_virtual_hash(),
            new_layout_field_count: builder.add_virtual_target(),
            new_layout_slot_count: builder.add_virtual_target(),
            appended_field_count: builder.add_virtual_target(),
            appended_fields_commitment: builder.add_virtual_hash(),
        }
    }

    pub fn enforce_shape<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let version = builder.constant_u64(STATE_LAYOUT_VERSION as u64);
        builder.connect(self.layout_version, version);
        let expected_new_count =
            builder.add(self.old_layout_field_count, self.appended_field_count);
        builder.connect(self.new_layout_field_count, expected_new_count);
    }

    pub fn aggregate<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self,
        right: &Self,
    ) -> Self {
        left.enforce_shape(builder);
        right.enforce_shape(builder);
        builder.connect(left.contract_id, right.contract_id);
        builder.connect(left.layout_version, right.layout_version);
        builder.connect_hashes(left.new_layout_root, right.old_layout_root);
        builder.connect(
            left.new_layout_field_count,
            right.old_layout_field_count,
        );
        builder.connect(
            left.new_layout_slot_count,
            right.old_layout_slot_count,
        );

        let appended_field_count =
            builder.add(left.appended_field_count, right.appended_field_count);
        let domain = builder.constant_u64(STATE_LAYOUT_APPEND_AGG_DOMAIN);
        let appended_fields_commitment =
            builder.hash_n_to_hash_no_pad::<H>(vec![
                domain,
                left.appended_fields_commitment.elements[0],
                left.appended_fields_commitment.elements[1],
                left.appended_fields_commitment.elements[2],
                left.appended_fields_commitment.elements[3],
                left.appended_field_count,
                right.appended_fields_commitment.elements[0],
                right.appended_fields_commitment.elements[1],
                right.appended_fields_commitment.elements[2],
                right.appended_fields_commitment.elements[3],
                right.appended_field_count,
            ]);

        Self {
            contract_id: left.contract_id,
            layout_version: left.layout_version,
            old_layout_root: left.old_layout_root,
            old_layout_field_count: left.old_layout_field_count,
            old_layout_slot_count: left.old_layout_slot_count,
            new_layout_root: right.new_layout_root,
            new_layout_field_count: right.new_layout_field_count,
            new_layout_slot_count: right.new_layout_slot_count,
            appended_field_count,
            appended_fields_commitment,
        }
    }

    pub fn register_public_inputs<
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        builder.register_public_input(self.contract_id);
        builder.register_public_input(self.layout_version);
        builder.register_public_inputs(&self.old_layout_root.elements);
        builder.register_public_input(self.old_layout_field_count);
        builder.register_public_input(self.old_layout_slot_count);
        builder.register_public_inputs(&self.new_layout_root.elements);
        builder.register_public_input(self.new_layout_field_count);
        builder.register_public_input(self.new_layout_slot_count);
        builder.register_public_input(self.appended_field_count);
        builder.register_public_inputs(
            &self.appended_fields_commitment.elements,
        );
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        value: &LayoutAppendPublicInputs<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_target(
            self.contract_id,
            F::from_canonical_u64(value.contract_id),
        )?;
        witness.set_target(
            self.layout_version,
            F::from_canonical_u64(value.layout_version as u64),
        )?;
        witness.set_hash_target(self.old_layout_root, value.old_layout_root.0)?;
        witness.set_target(
            self.old_layout_field_count,
            F::from_canonical_u64(value.old_layout_field_count),
        )?;
        witness.set_target(
            self.old_layout_slot_count,
            F::from_canonical_u64(value.old_layout_slot_count),
        )?;
        witness.set_hash_target(self.new_layout_root, value.new_layout_root.0)?;
        witness.set_target(
            self.new_layout_field_count,
            F::from_canonical_u64(value.new_layout_field_count),
        )?;
        witness.set_target(
            self.new_layout_slot_count,
            F::from_canonical_u64(value.new_layout_slot_count),
        )?;
        witness.set_target(
            self.appended_field_count,
            F::from_canonical_u64(value.appended_field_count),
        )?;
        witness.set_hash_target(
            self.appended_fields_commitment,
            value.appended_fields_commitment.0,
        )?;
        Ok(())
    }
}

impl<const D: usize> LayoutAppendProofAggregationGadget<D> {
    /// Verify two proofs from the same child circuit and aggregate their
    /// authenticated transition interfaces in left-to-right order.
    ///
    /// Higher levels may use the same constructor with the preceding
    /// aggregation level's common/verifier data, yielding a deterministic
    /// pairwise tree for arbitrarily large appends.
    pub fn add_virtual_to<C>(
        builder: &mut CircuitBuilder<C::F, D>,
        child_common_data: &CommonCircuitData<C::F, D>,
        child_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        let verifier_data = builder.constant_verifier_data(child_verifier_data);
        let left_proof =
            builder.add_virtual_proof_with_pis(child_common_data);
        let right_proof =
            builder.add_virtual_proof_with_pis(child_common_data);
        builder.verify_proof::<C>(
            &left_proof,
            &verifier_data,
            child_common_data,
        );
        builder.verify_proof::<C>(
            &right_proof,
            &verifier_data,
            child_common_data,
        );

        let left = LayoutAppendPublicInputsGadget::from_public_inputs(
            &left_proof.public_inputs,
        );
        let right = LayoutAppendPublicInputsGadget::from_public_inputs(
            &right_proof.public_inputs,
        );
        let output = LayoutAppendPublicInputsGadget::aggregate::<
            C::Hasher,
            C::F,
            D,
        >(builder, &left, &right);
        output.register_public_inputs(builder);
        Self {
            left_proof,
            right_proof,
            output,
        }
    }

    pub fn set_witness<C>(
        &self,
        witness: &mut impl WitnessWrite<C::F>,
        left: &ProofWithPublicInputs<C::F, C, D>,
        right: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        witness.set_proof_with_pis_target(&self.left_proof, left)?;
        witness.set_proof_with_pis_target(&self.right_proof, right)?;
        Ok(())
    }
}

impl QEDContractLeafV2Gadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            deployer: builder.add_virtual_hash(),
            function_tree_root: builder.add_virtual_hash(),
            code_root: builder.add_virtual_hash(),
            state_tree_height: builder.add_virtual_target(),
            state_layout_root: builder.add_virtual_hash(),
            state_layout_field_count: builder.add_virtual_target(),
            state_layout_slot_count: builder.add_virtual_target(),
        }
    }

    pub fn to_hash<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let domain = builder.constant_u64(CONTRACT_LEAF_DOMAIN);
        builder.hash_n_to_hash_no_pad::<H>(vec![
            domain,
            self.deployer.elements[0],
            self.deployer.elements[1],
            self.deployer.elements[2],
            self.deployer.elements[3],
            self.function_tree_root.elements[0],
            self.function_tree_root.elements[1],
            self.function_tree_root.elements[2],
            self.function_tree_root.elements[3],
            self.code_root.elements[0],
            self.code_root.elements[1],
            self.code_root.elements[2],
            self.code_root.elements[3],
            self.state_tree_height,
            self.state_layout_root.elements[0],
            self.state_layout_root.elements[1],
            self.state_layout_root.elements[2],
            self.state_layout_root.elements[3],
            self.state_layout_field_count,
            self.state_layout_slot_count,
        ])
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        value: &PQEDContractLeafV2<F, QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.deployer, value.deployer.0)?;
        witness.set_hash_target(
            self.function_tree_root,
            value.function_tree_root.0,
        )?;
        witness.set_hash_target(self.code_root, value.code_root.0)?;
        witness.set_target(
            self.state_tree_height,
            value.state_tree_height,
        )?;
        witness.set_hash_target(
            self.state_layout_root,
            value.state_layout_root.0,
        )?;
        witness.set_target(
            self.state_layout_field_count,
            value.state_layout_field_count,
        )?;
        witness.set_target(
            self.state_layout_slot_count,
            value.state_layout_slot_count,
        )?;
        Ok(())
    }
}

impl StateTypeLayoutWitnessGadget {
    const PRIMITIVE_KIND: u64 = 1;
    const FIXED_ARRAY_KIND: u64 = 2;
    const STRUCT_KIND: u64 = 3;
    const FIXED_MAP_KIND: u64 = 4;
    const MAX_MAP_ALIGNMENT_LOG2: usize = 16;

    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            kind: builder.add_virtual_target(),
            primitive_tag: builder.add_virtual_target(),
            child_type_hash: builder.add_virtual_hash(),
            child_slot_count: builder.add_virtual_target(),
            array_length: builder.add_virtual_target(),
            member_count: builder.add_virtual_target(),
            struct_slot_count: builder.add_virtual_target(),
            members_root: builder.add_virtual_hash(),
            map_kind: builder.add_virtual_target(),
            key_type_hash: builder.add_virtual_hash(),
            key_slot_count: builder.add_virtual_target(),
            value_type_hash: builder.add_virtual_hash(),
            value_slot_count: builder.add_virtual_target(),
            map_capacity: builder.add_virtual_target(),
            map_alignment: builder.add_virtual_target(),
            map_aligned_start_quotient: builder.add_virtual_target(),
        }
    }

    pub fn constrain_field<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        field: &StateFieldLayoutLeafGadget,
        is_added: plonky2::iop::target::BoolTarget,
    ) {
        let zero = builder.zero();
        let one = builder.one();
        let encoding = builder
            .constant_u64(STATE_LAYOUT_ENCODING_VERSION as u64);

        let primitive_kind = builder.constant_u64(Self::PRIMITIVE_KIND);
        let array_kind = builder.constant_u64(Self::FIXED_ARRAY_KIND);
        let struct_kind = builder.constant_u64(Self::STRUCT_KIND);
        let map_kind = builder.constant_u64(Self::FIXED_MAP_KIND);
        let is_primitive = builder.is_equal(self.kind, primitive_kind);
        let is_array = builder.is_equal(self.kind, array_kind);
        let is_struct = builder.is_equal(self.kind, struct_kind);
        let is_map = builder.is_equal(self.kind, map_kind);
        let valid_kind = builder.add_many([
            is_primitive.target,
            is_array.target,
            is_struct.target,
            is_map.target,
        ]);
        builder.connect(valid_kind, one);

        let primitive_domain =
            builder.constant_u64(PRIMITIVE_TYPE_LAYOUT_DOMAIN);
        let primitive_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            primitive_domain,
            self.primitive_tag,
            encoding,
        ]);
        let mut valid_primitive_tag = zero;
        let mut primitive_slot_count = zero;
        for (tag, width) in [
            (StatePrimitiveTypeTag::Felt, 1u64),
            (StatePrimitiveTypeTag::Bool, 1),
            (StatePrimitiveTypeTag::U32, 1),
            (StatePrimitiveTypeTag::U64, 1),
            (StatePrimitiveTypeTag::U128, 2),
            (StatePrimitiveTypeTag::Hash, 4),
            (StatePrimitiveTypeTag::Bytes32, 4),
        ] {
            let tag_target = builder.constant_u64(tag as u16 as u64);
            let is_tag =
                builder.is_equal(self.primitive_tag, tag_target);
            valid_primitive_tag =
                builder.add(valid_primitive_tag, is_tag.target);
            let width_target = builder.constant_u64(width);
            let selected_width =
                builder.mul(is_tag.target, width_target);
            primitive_slot_count =
                builder.add(primitive_slot_count, selected_width);
        }
        let active_primitive = builder.and(is_added, is_primitive);
        builder.connect_if_true(
            active_primitive,
            valid_primitive_tag,
            one,
        );

        let array_total =
            builder.mul(self.child_slot_count, self.array_length);
        let array_domain =
            builder.constant_u64(FIXED_ARRAY_TYPE_LAYOUT_DOMAIN);
        let array_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            array_domain,
            self.child_type_hash.elements[0],
            self.child_type_hash.elements[1],
            self.child_type_hash.elements[2],
            self.child_type_hash.elements[3],
            self.array_length,
            self.child_slot_count,
            array_total,
            encoding,
        ]);

        let struct_domain =
            builder.constant_u64(STRUCT_TYPE_LAYOUT_DOMAIN);
        let struct_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            struct_domain,
            self.member_count,
            self.struct_slot_count,
            self.members_root.elements[0],
            self.members_root.elements[1],
            self.members_root.elements[2],
            self.members_root.elements[3],
            encoding,
        ]);

        let map_total =
            builder.mul(self.map_capacity, self.value_slot_count);
        let map_domain =
            builder.constant_u64(FIXED_MAP_TYPE_LAYOUT_DOMAIN);
        let map_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            map_domain,
            self.map_kind,
            self.key_type_hash.elements[0],
            self.key_type_hash.elements[1],
            self.key_type_hash.elements[2],
            self.key_type_hash.elements[3],
            self.key_slot_count,
            self.value_type_hash.elements[0],
            self.value_type_hash.elements[1],
            self.value_type_hash.elements[2],
            self.value_type_hash.elements[3],
            self.value_slot_count,
            self.map_capacity,
            self.map_alignment,
            map_total,
            encoding,
        ]);

        let mut valid_map_kind = zero;
        for map_kind in [
            StateMapKind::ContractHashMap,
            StateMapKind::Map,
            StateMapKind::NamespacedMap,
        ] {
            let map_kind_target =
                builder.constant_u64(map_kind as u16 as u64);
            let is_kind =
                builder.is_equal(self.map_kind, map_kind_target);
            valid_map_kind =
                builder.add(valid_map_kind, is_kind.target);
        }
        let active_map = builder.and(is_added, is_map);
        builder.connect_if_true(active_map, valid_map_kind, one);

        let mut valid_alignment = zero;
        for log2 in 0..=Self::MAX_MAP_ALIGNMENT_LOG2 {
            let alignment = 1u64 << log2;
            let alignment_target = builder.constant_u64(alignment);
            let is_alignment =
                builder.is_equal(self.map_alignment, alignment_target);
            valid_alignment =
                builder.add(valid_alignment, is_alignment.target);
        }
        builder.connect_if_true(active_map, valid_alignment, one);

        let selected_hash = builder.select_hash(
            is_array,
            array_hash,
            primitive_hash,
        );
        let selected_hash =
            builder.select_hash(is_struct, struct_hash, selected_hash);
        let selected_hash =
            builder.select_hash(is_map, map_hash, selected_hash);
        builder.connect_hashes_if_true(
            is_added,
            field.type_layout_hash,
            selected_hash,
        );

        let selected_payload_slots = builder.select(
            is_array,
            array_total,
            primitive_slot_count,
        );
        let selected_payload_slots = builder.select(
            is_struct,
            self.struct_slot_count,
            selected_payload_slots,
        );
        let selected_payload_slots =
            builder.select(is_map, map_total, selected_payload_slots);
        let expected_owned_slots =
            builder.add(field.payload_offset, selected_payload_slots);
        builder.connect_if_true(
            is_added,
            field.slot_count,
            expected_owned_slots,
        );

        let is_not_map = builder.not(is_map);
        let active_non_map = builder.and(is_added, is_not_map);
        builder.connect_if_true(
            active_non_map,
            field.payload_offset,
            zero,
        );

        let payload_start =
            builder.add(field.start_slot, field.payload_offset);
        let aligned_start = builder.mul(
            self.map_aligned_start_quotient,
            self.map_alignment,
        );
        builder.connect_if_true(active_map, payload_start, aligned_start);
        let offset_is_less_than_alignment = builder.is_less_than(
            63,
            field.payload_offset,
            self.map_alignment,
        );
        builder.connect_if_true(
            active_map,
            offset_is_less_than_alignment.target,
            one,
        );

        for non_zero_target in [
            self.child_slot_count,
            self.array_length,
            self.member_count,
            self.struct_slot_count,
            self.key_slot_count,
            self.value_slot_count,
            self.map_capacity,
        ] {
            let is_zero = builder.is_equal(non_zero_target, zero);
            let relevant = if non_zero_target == self.child_slot_count
                || non_zero_target == self.array_length
            {
                builder.and(is_added, is_array)
            } else if non_zero_target == self.member_count
                || non_zero_target == self.struct_slot_count
            {
                builder.and(is_added, is_struct)
            } else {
                active_map
            };
            let invalid = builder.and(relevant, is_zero);
            builder.connect(invalid.target, zero);
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        field: &StateFieldLayoutLeaf<QHashOut<F>>,
        value: &StateTypeLayoutWitness<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        let zero_hash = QHashOut::ZERO;
        let (
            kind,
            primitive_tag,
            child_type_hash,
            child_slot_count,
            array_length,
            member_count,
            struct_slot_count,
            members_root,
            map_kind,
            key_type_hash,
            key_slot_count,
            value_type_hash,
            value_slot_count,
            map_capacity,
            map_alignment,
        ) = match *value {
            StateTypeLayoutWitness::Primitive { type_tag } => (
                Self::PRIMITIVE_KIND,
                type_tag as u16 as u64,
                zero_hash,
                0,
                0,
                0,
                0,
                zero_hash,
                0,
                zero_hash,
                0,
                zero_hash,
                0,
                0,
                1,
            ),
            StateTypeLayoutWitness::FixedArray {
                element_type_hash,
                element_slot_count,
                array_length,
            } => (
                Self::FIXED_ARRAY_KIND,
                StatePrimitiveTypeTag::Felt as u16 as u64,
                element_type_hash,
                element_slot_count,
                array_length,
                0,
                0,
                zero_hash,
                0,
                zero_hash,
                0,
                zero_hash,
                0,
                0,
                1,
            ),
            StateTypeLayoutWitness::Struct {
                member_count,
                total_slot_count,
                members_root,
            } => (
                Self::STRUCT_KIND,
                StatePrimitiveTypeTag::Felt as u16 as u64,
                zero_hash,
                0,
                0,
                member_count,
                total_slot_count,
                members_root,
                0,
                zero_hash,
                0,
                zero_hash,
                0,
                0,
                1,
            ),
            StateTypeLayoutWitness::FixedMap {
                map_kind,
                key_type_hash,
                key_slot_count,
                value_type_hash,
                value_slot_count,
                capacity,
                alignment_slots,
            } => (
                Self::FIXED_MAP_KIND,
                StatePrimitiveTypeTag::Felt as u16 as u64,
                zero_hash,
                0,
                0,
                0,
                0,
                zero_hash,
                map_kind as u16 as u64,
                key_type_hash,
                key_slot_count,
                value_type_hash,
                value_slot_count,
                capacity,
                alignment_slots,
            ),
        };
        let aligned_start = field
            .start_slot
            .checked_add(field.payload_offset)
            .ok_or_else(|| anyhow::anyhow!("aligned map start overflow"))?;
        anyhow::ensure!(map_alignment > 0, "map alignment must be non-zero");

        witness.set_target(self.kind, F::from_canonical_u64(kind))?;
        witness.set_target(
            self.primitive_tag,
            F::from_canonical_u64(primitive_tag),
        )?;
        witness.set_hash_target(self.child_type_hash, child_type_hash.0)?;
        witness.set_target(
            self.child_slot_count,
            F::from_canonical_u64(child_slot_count),
        )?;
        witness.set_target(
            self.array_length,
            F::from_canonical_u64(array_length),
        )?;
        witness.set_target(
            self.member_count,
            F::from_canonical_u64(member_count),
        )?;
        witness.set_target(
            self.struct_slot_count,
            F::from_canonical_u64(struct_slot_count),
        )?;
        witness.set_hash_target(self.members_root, members_root.0)?;
        witness.set_target(self.map_kind, F::from_canonical_u64(map_kind))?;
        witness.set_hash_target(self.key_type_hash, key_type_hash.0)?;
        witness.set_target(
            self.key_slot_count,
            F::from_canonical_u64(key_slot_count),
        )?;
        witness.set_hash_target(self.value_type_hash, value_type_hash.0)?;
        witness.set_target(
            self.value_slot_count,
            F::from_canonical_u64(value_slot_count),
        )?;
        witness.set_target(
            self.map_capacity,
            F::from_canonical_u64(map_capacity),
        )?;
        witness.set_target(
            self.map_alignment,
            F::from_canonical_u64(map_alignment),
        )?;
        witness.set_target(
            self.map_aligned_start_quotient,
            F::from_canonical_u64(aligned_start / map_alignment),
        )?;
        Ok(())
    }
}

impl StateFieldLayoutLeafGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            field_id: builder.add_virtual_target(),
            start_slot: builder.add_virtual_target(),
            payload_offset: builder.add_virtual_target(),
            slot_count: builder.add_virtual_target(),
            type_layout_hash: builder.add_virtual_hash(),
            encoding_version: builder.add_virtual_target(),
        }
    }

    pub fn to_hash<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let domain = builder.constant_u64(STATE_FIELD_LAYOUT_DOMAIN);
        builder.hash_n_to_hash_no_pad::<H>(vec![
            domain,
            self.field_id,
            self.start_slot,
            self.payload_offset,
            self.slot_count,
            self.type_layout_hash.elements[0],
            self.type_layout_hash.elements[1],
            self.type_layout_hash.elements[2],
            self.type_layout_hash.elements[3],
            self.encoding_version,
        ])
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        value: &StateFieldLayoutLeaf<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_target(self.field_id, F::from_canonical_u64(value.field_id))?;
        witness.set_target(self.start_slot, F::from_canonical_u64(value.start_slot))?;
        witness.set_target(
            self.payload_offset,
            F::from_canonical_u64(value.payload_offset),
        )?;
        witness.set_target(self.slot_count, F::from_canonical_u64(value.slot_count))?;
        witness.set_hash_target(self.type_layout_hash, value.type_layout_hash.0)?;
        witness.set_target(
            self.encoding_version,
            F::from_canonical_u64(value.encoding_version as u64),
        )?;
        Ok(())
    }
}

/// Strict field-oriented layout append wrapper around Spiderman.
///
/// Besides the local append semantics already enforced by Spiderman, this
/// gadget binds the selected web window to the global field-count frontier
/// and binds physical slot ranges to a second, contiguous frontier.
#[derive(Debug, Clone)]
pub struct StateLayoutAppendGadget {
    pub spiderman: SpidermanAppendProofGadget,
    pub field_leaves: Vec<StateFieldLayoutLeafGadget>,
    pub field_type_layouts: Vec<StateTypeLayoutWitnessGadget>,

    pub old_layout_field_count: Target,
    pub new_layout_field_count: Target,
    pub old_layout_slot_count: Target,
    pub new_layout_slot_count: Target,
    pub appended_field_count: Target,
}

/// Production append gadget that requires one canonical recursive type proof
/// for every Spiderman web position.
///
/// Inactive positions are still verified and therefore must use a real
/// canonical padding proof. This keeps the circuit shape fixed and prevents
/// an invalid proof from being hidden behind `is_added = false`.
#[derive(Debug, Clone)]
pub struct StateLayoutAppendWithTypeProofsGadget<const D: usize> {
    pub append: StateLayoutAppendGadget,
    pub type_proofs: Vec<VerifiedTypeLayoutProofGadget<D>>,
}

impl<const D: usize> StateLayoutAppendWithTypeProofsGadget<D> {
    pub fn add_virtual_to<C>(
        builder: &mut CircuitBuilder<C::F, D>,
        top_line_height: usize,
        web_tree_height: usize,
        canonical_type_common: &CommonCircuitData<C::F, D>,
        canonical_type_verifier: &VerifierOnlyCircuitData<C, D>,
    ) -> Self
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        let append = StateLayoutAppendGadget::add_virtual_to::<
            C::Hasher,
            C::F,
            D,
        >(builder, top_line_height, web_tree_height);
        let type_proofs = append
            .field_leaves
            .iter()
            .zip(append.spiderman.get_added_leaves())
            .map(|(field, is_added)| {
                let proof = VerifiedTypeLayoutProofGadget::add_virtual_to::<C>(
                    builder,
                    canonical_type_common,
                    canonical_type_verifier,
                );
                proof.connect_field(builder, field, *is_added);
                proof
            })
            .collect();
        Self {
            append,
            type_proofs,
        }
    }

    pub fn set_witness<C>(
        &self,
        witness: &mut impl Witness<C::F>,
        spiderman_proof: &SpidermanUpdateProof<QHashOut<C::F>>,
        appended_fields: &[StateFieldLayoutLeaf<QHashOut<C::F>>],
        appended_type_layouts: &[StateTypeLayoutWitness<QHashOut<C::F>>],
        appended_type_proofs: &[ProofWithPublicInputs<C::F, C, D>],
        padding_type_proof: &ProofWithPublicInputs<C::F, C, D>,
        old_layout_field_count: u64,
        new_layout_field_count: u64,
        old_layout_slot_count: u64,
        new_layout_slot_count: u64,
    ) -> anyhow::Result<()>
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        anyhow::ensure!(
            appended_type_proofs.len() == appended_fields.len(),
            "every appended field must have one canonical type proof"
        );
        self.append.set_witness(
            witness,
            spiderman_proof,
            appended_fields,
            appended_type_layouts,
            old_layout_field_count,
            new_layout_field_count,
            old_layout_slot_count,
            new_layout_slot_count,
        )?;
        let mut appended_index = 0usize;
        for (index, proof_target) in self.type_proofs.iter().enumerate() {
            let is_added = spiderman_proof.web_proof_old_leaves[index]
                == QHashOut::ZERO
                && spiderman_proof.web_proof_new_leaves[index]
                    != QHashOut::ZERO;
            let proof = if is_added {
                let proof = appended_type_proofs
                    .get(appended_index)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing canonical type proof for appended field"
                        )
                    })?;
                appended_index += 1;
                proof
            } else {
                padding_type_proof
            };
            proof_target.set_witness::<C>(witness, proof)?;
        }
        anyhow::ensure!(
            appended_index == appended_type_proofs.len(),
            "unused canonical type proofs were supplied"
        );
        Ok(())
    }
}

impl StateLayoutAppendGadget {
    /// Build and constrain the base proof's public transition interface.
    ///
    /// Every web position contributes either its newly added field hash or
    /// zero to the ordered batch commitment. This binds aggregation to the
    /// exact appended field preimages, not merely to the resulting root.
    pub fn to_public_inputs<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        contract_id: Target,
    ) -> LayoutAppendPublicInputsGadget {
        let zero = builder.zero();
        let zero_hash = HashOutTarget {
            elements: [zero; 4],
        };
        let mut commitment_preimage =
            Vec::with_capacity(5 + self.field_leaves.len() * 4);
        commitment_preimage.push(
            builder.constant_u64(STATE_LAYOUT_APPEND_BATCH_DOMAIN),
        );
        commitment_preimage.push(contract_id);
        commitment_preimage.push(self.old_layout_field_count);
        commitment_preimage.push(self.old_layout_slot_count);
        commitment_preimage.push(self.appended_field_count);

        for (index, field) in self.field_leaves.iter().enumerate() {
            let field_hash = field.to_hash::<H, F, D>(builder);
            let committed_hash = builder.select_hash(
                self.spiderman.get_added_leaves()[index],
                field_hash,
                zero_hash,
            );
            commitment_preimage.extend(committed_hash.elements);
        }

        LayoutAppendPublicInputsGadget {
            contract_id,
            layout_version: builder
                .constant_u64(STATE_LAYOUT_VERSION as u64),
            old_layout_root: self.spiderman.old_root,
            old_layout_field_count: self.old_layout_field_count,
            old_layout_slot_count: self.old_layout_slot_count,
            new_layout_root: self.spiderman.new_root,
            new_layout_field_count: self.new_layout_field_count,
            new_layout_slot_count: self.new_layout_slot_count,
            appended_field_count: self.appended_field_count,
            appended_fields_commitment: builder
                .hash_n_to_hash_no_pad::<H>(commitment_preimage),
        }
    }

    pub fn connect_contract_leaf_endpoints<
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        old_leaf: &QEDContractLeafV2Gadget,
        new_leaf: &QEDContractLeafV2Gadget,
        max_state_tree_height: usize,
    ) {
        assert!(
            max_state_tree_height < 63,
            "state layout capacity comparison requires height < 63"
        );
        builder.connect_hashes(
            self.spiderman.old_root,
            old_leaf.state_layout_root,
        );
        builder.connect_hashes(
            self.spiderman.new_root,
            new_leaf.state_layout_root,
        );
        builder.connect(
            self.old_layout_field_count,
            old_leaf.state_layout_field_count,
        );
        builder.connect(
            self.new_layout_field_count,
            new_leaf.state_layout_field_count,
        );
        builder.connect(
            self.old_layout_slot_count,
            old_leaf.state_layout_slot_count,
        );
        builder.connect(
            self.new_layout_slot_count,
            new_leaf.state_layout_slot_count,
        );

        // Existing update invariants remain immutable across V2 updates.
        builder.connect_hashes(old_leaf.deployer, new_leaf.deployer);
        builder.connect(
            old_leaf.state_tree_height,
            new_leaf.state_tree_height,
        );

        // Select 2^height from the allowed range. This both range-checks the
        // leaf's height and constrains the appended slot frontier to the
        // physical state-tree capacity.
        let zero = builder.zero();
        let one = builder.one();
        let mut selected_capacity = zero;
        let mut valid_height = zero;
        for height in 1..=max_state_tree_height {
            let height_target = builder.constant_u64(height as u64);
            let is_height =
                builder.is_equal(old_leaf.state_tree_height, height_target);
            valid_height = builder.add(valid_height, is_height.target);
            let capacity_target = builder.constant_u64(1u64 << height);
            let selected =
                builder.mul(is_height.target, capacity_target);
            selected_capacity = builder.add(selected_capacity, selected);
        }
        builder.connect(valid_height, one);
        builder.ensure_is_less_than_or_equal(
            max_state_tree_height + 1,
            self.new_layout_slot_count,
            selected_capacity,
        );
    }

    pub fn add_virtual_to<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        top_line_height: usize,
        web_tree_height: usize,
    ) -> Self {
        let spiderman = SpidermanAppendProofGadget::add_virtual_to::<H, F, D>(
            builder,
            top_line_height,
            web_tree_height,
        );
        let web_size = 1usize << web_tree_height;
        let field_leaves = (0..web_size)
            .map(|_| StateFieldLayoutLeafGadget::add_virtual_to(builder))
            .collect::<Vec<_>>();
        let field_type_layouts = (0..web_size)
            .map(|_| StateTypeLayoutWitnessGadget::add_virtual_to(builder))
            .collect::<Vec<_>>();

        let old_layout_field_count = builder.add_virtual_target();
        let new_layout_field_count = builder.add_virtual_target();
        let old_layout_slot_count = builder.add_virtual_target();
        let new_layout_slot_count = builder.add_virtual_target();

        let web_size_target = builder.constant_u64(web_size as u64);
        let window_start =
            builder.mul(spiderman.top_line_proof.index, web_size_target);
        let zero = builder.zero();
        let one = builder.one();
        let encoding_v1 =
            builder.constant_u64(STATE_LAYOUT_ENCODING_VERSION as u64);

        let mut old_prefix_count = zero;
        let mut new_prefix_count = zero;
        let mut appended_field_count = zero;
        let mut next_slot = old_layout_slot_count;

        for i in 0..web_size {
            let old_is_zero =
                builder.is_zero_hash(spiderman.web_proof.old_leaves[i]);
            let new_is_zero =
                builder.is_zero_hash(spiderman.web_proof.new_leaves[i]);
            let old_is_non_zero = builder.not(old_is_zero);
            let new_is_non_zero = builder.not(new_is_zero);
            old_prefix_count =
                builder.add(old_prefix_count, old_is_non_zero.target);
            new_prefix_count =
                builder.add(new_prefix_count, new_is_non_zero.target);

            let is_added = spiderman.get_added_leaves()[i];
            appended_field_count =
                builder.add(appended_field_count, is_added.target);

            let field_hash = field_leaves[i].to_hash::<H, F, D>(builder);
            builder.connect_hashes_if_true(
                is_added,
                field_hash,
                spiderman.web_proof.new_leaves[i],
            );
            field_type_layouts[i].constrain_field::<H, F, D>(
                builder,
                &field_leaves[i],
                is_added,
            );

            let window_offset = builder.constant_u64(i as u64);
            let global_field_index =
                builder.add(window_start, window_offset);
            let expected_field_id = builder.add(global_field_index, one);
            builder.connect_if_true(
                is_added,
                field_leaves[i].field_id,
                expected_field_id,
            );
            builder.connect_if_true(
                is_added,
                field_leaves[i].encoding_version,
                encoding_v1,
            );
            builder.connect_if_true(
                is_added,
                field_leaves[i].start_slot,
                next_slot,
            );

            let slot_count_is_zero =
                builder.is_equal(field_leaves[i].slot_count, zero);
            let invalid_zero_slot_count =
                builder.and(is_added, slot_count_is_zero);
            builder.connect(invalid_zero_slot_count.target, zero);
            let payload_inside_range = builder.is_less_than(
                63,
                field_leaves[i].payload_offset,
                field_leaves[i].slot_count,
            );
            builder.connect_if_true(
                is_added,
                payload_inside_range.target,
                one,
            );

            let slot_after_field =
                builder.add(next_slot, field_leaves[i].slot_count);
            next_slot =
                builder.select(is_added, slot_after_field, next_slot);
        }

        let expected_old_field_count =
            builder.add(window_start, old_prefix_count);
        let expected_new_field_count =
            builder.add(window_start, new_prefix_count);
        builder.connect(
            old_layout_field_count,
            expected_old_field_count,
        );
        builder.connect(
            new_layout_field_count,
            expected_new_field_count,
        );
        builder.connect(new_layout_slot_count, next_slot);

        let expected_new_field_count_from_adds =
            builder.add(old_layout_field_count, appended_field_count);
        builder.connect(
            new_layout_field_count,
            expected_new_field_count_from_adds,
        );

        Self {
            spiderman,
            field_leaves,
            field_type_layouts,
            old_layout_field_count,
            new_layout_field_count,
            old_layout_slot_count,
            new_layout_slot_count,
            appended_field_count,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        spiderman_proof: &SpidermanUpdateProof<QHashOut<F>>,
        appended_fields: &[StateFieldLayoutLeaf<QHashOut<F>>],
        appended_type_layouts: &[StateTypeLayoutWitness<QHashOut<F>>],
        old_layout_field_count: u64,
        new_layout_field_count: u64,
        old_layout_slot_count: u64,
        new_layout_slot_count: u64,
    ) -> anyhow::Result<()> {
        self.spiderman.set_witness(witness, spiderman_proof)?;
        anyhow::ensure!(
            appended_fields.len() == appended_type_layouts.len(),
            "every appended field must have one canonical type-layout witness"
        );
        witness.set_target(
            self.old_layout_field_count,
            F::from_canonical_u64(old_layout_field_count),
        )?;
        witness.set_target(
            self.new_layout_field_count,
            F::from_canonical_u64(new_layout_field_count),
        )?;
        witness.set_target(
            self.old_layout_slot_count,
            F::from_canonical_u64(old_layout_slot_count),
        )?;
        witness.set_target(
            self.new_layout_slot_count,
            F::from_canonical_u64(new_layout_slot_count),
        )?;

        let empty = StateFieldLayoutLeaf {
            field_id: 0,
            start_slot: 0,
            payload_offset: 0,
            slot_count: 0,
            type_layout_hash: QHashOut::ZERO,
            encoding_version: 0,
        };
        let mut appended_index = 0usize;
        for i in 0..self.field_leaves.len() {
            let is_added = spiderman_proof.web_proof_old_leaves[i]
                == QHashOut::ZERO
                && spiderman_proof.web_proof_new_leaves[i] != QHashOut::ZERO;
            if is_added {
                let field = appended_fields.get(appended_index).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Spiderman proof contains more appended fields than supplied preimages"
                    )
                })?;
                self.field_leaves[i].set_witness(witness, field)?;
                self.field_type_layouts[i].set_witness(
                    witness,
                    field,
                    &appended_type_layouts[appended_index],
                )?;
                appended_index += 1;
            } else {
                self.field_leaves[i].set_witness(witness, &empty)?;
                self.field_type_layouts[i].set_witness(
                    witness,
                    &empty,
                    &StateTypeLayoutWitness::Primitive {
                        type_tag: StatePrimitiveTypeTag::Felt,
                    },
                )?;
            }
        }
        anyhow::ensure!(
            appended_index == appended_fields.len(),
            "supplied {} appended field preimages but proof contains {} additions",
            appended_fields.len(),
            appended_index
        );
        Ok(())
    }
}

#[cfg(test)]
mod type_witness_consistency_tests {
    use parth_core::{
        pgoldilocks::{PoseidonHasher, QHashOut},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        hash::poseidon::PoseidonHash,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use psy_data::v1::qdata::contract::{
        StateFieldLayoutLeaf, StateTypeLayoutWitness,
    };

    use super::{
        StateFieldLayoutLeafGadget, StateTypeLayoutWitnessGadget,
    };

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn prove_type_witness_consistency(
        type_witness: StateTypeLayoutWitness<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        let summary = type_witness.summary::<PoseidonHasher, F>()?;
        let field = StateFieldLayoutLeaf::new(0, 0, summary)?;

        let mut builder = CircuitBuilder::<F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let field_target =
            StateFieldLayoutLeafGadget::add_virtual_to(&mut builder);
        let type_target =
            StateTypeLayoutWitnessGadget::add_virtual_to(&mut builder);
        let is_added = builder._true();
        type_target.constrain_field::<PoseidonHash, F, D>(
            &mut builder,
            &field_target,
            is_added,
        );
        let circuit = builder.build::<C>();

        let mut witness = PartialWitness::new();
        field_target.set_witness(&mut witness, &field)?;
        type_target.set_witness(&mut witness, &field, &type_witness)?;
        circuit.prove(witness)?;
        Ok(())
    }

    #[test]
    fn struct_type_witness_matches_native_summary() -> anyhow::Result<()> {
        prove_type_witness_consistency(StateTypeLayoutWitness::Struct {
            member_count: 2,
            total_slot_count: 2,
            members_root: QHashOut::from_values(11, 22, 33, 44),
        })
    }

    #[test]
    fn fixed_array_type_witness_matches_native_summary(
    ) -> anyhow::Result<()> {
        let element = StateTypeLayoutWitness::Primitive {
            type_tag:
                psy_data::v1::qdata::contract::StatePrimitiveTypeTag::Felt,
        }
        .summary::<PoseidonHasher, F>()?;
        prove_type_witness_consistency(StateTypeLayoutWitness::FixedArray {
            element_type_hash: element.type_layout_hash,
            element_slot_count: element.total_slot_count,
            array_length: 32,
        })
    }

    #[test]
    fn field_leaf_hash_matches_native_hash() -> anyhow::Result<()> {
        let type_summary = StateTypeLayoutWitness::Struct {
            member_count: 2,
            total_slot_count: 2,
            members_root: QHashOut::from_values(11, 22, 33, 44),
        }
        .summary::<PoseidonHasher, F>()?;
        let field = StateFieldLayoutLeaf::new(0, 0, type_summary)?;
        let expected = field.hash::<PoseidonHasher, F>()?;

        let mut builder = CircuitBuilder::<F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let field_target =
            StateFieldLayoutLeafGadget::add_virtual_to(&mut builder);
        let actual =
            field_target.to_hash::<PoseidonHash, F, D>(&mut builder);
        let expected_target = builder.constant_hash(expected.0);
        builder.connect_hashes(actual, expected_target);
        let circuit = builder.build::<C>();

        let mut witness = PartialWitness::new();
        field_target.set_witness(&mut witness, &field)?;
        circuit.prove(witness)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use parth_core::{
        felt::FromPrimitiveValuesFelt,
        pgoldilocks::{PoseidonHasher, QHashOut},
        PF,
    };
    use plonky2::{
        hash::poseidon::PoseidonHash,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use psy_data::v1::qdata::contract::{
        aggregate_layout_transitions, contract_state_layout,
        fixed_array_type_layout, fixed_map_type_layout,
        primitive_type_layout,
        StatePrimitiveTypeTag, STATE_LAYOUT_VERSION,
    };

    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    struct TestCircuit {
        gadget: StateLayoutAppendGadget,
        data: CircuitData<F, C, D>,
    }

    impl TestCircuit {
        fn new(top_line_height: usize, web_tree_height: usize) -> Self {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let gadget = StateLayoutAppendGadget::add_virtual_to::<
                PoseidonHash,
                F,
                D,
            >(
                &mut builder,
                top_line_height,
                web_tree_height,
            );
            builder.register_public_inputs(&gadget.spiderman.old_root.elements);
            builder.register_public_inputs(&gadget.spiderman.new_root.elements);
            builder.register_public_input(gadget.old_layout_field_count);
            builder.register_public_input(gadget.new_layout_field_count);
            builder.register_public_input(gadget.old_layout_slot_count);
            builder.register_public_input(gadget.new_layout_slot_count);
            let data = builder.build::<C>();
            Self { gadget, data }
        }
    }

    #[test]
    fn proves_global_field_and_slot_frontiers() -> anyhow::Result<()> {
        let top_line_height = 3;
        let web_tree_height = 2;
        let total_height = top_line_height + web_tree_height;
        let u64_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::U64,
                1,
            )?;
        let old_layout = contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
            &[u64_layout, u64_layout],
            total_height,
            total_height,
        )?;
        let new_layout = contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
            &[u64_layout, u64_layout, u64_layout, u64_layout],
            total_height,
            total_height,
        )?;

        let mut tree =
            SimpleMerkleTree::<PoseidonHasher, QHashOut<PF>>::new(total_height as u8);
        for (index, field) in old_layout.fields.iter().enumerate() {
            tree.set_leaf(
                index as u64,
                field.hash::<PoseidonHasher, PF>()?,
            );
        }
        let appended_fields = &new_layout.fields[old_layout.fields.len()..];
        let appended_hashes = appended_fields
            .iter()
            .map(|field| field.hash::<PoseidonHasher, PF>())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let proofs =
            tree.append_leaves_spider_man(web_tree_height as u8, &appended_hashes)?;
        assert_eq!(proofs.len(), 1);

        let circuit = TestCircuit::new(top_line_height, web_tree_height);
        let mut witness = PartialWitness::new();
        let appended_type_layouts = vec![
            StateTypeLayoutWitness::Primitive {
                type_tag: StatePrimitiveTypeTag::U64,
            };
            appended_fields.len()
        ];
        circuit.gadget.set_witness(
            &mut witness,
            &proofs[0],
            appended_fields,
            &appended_type_layouts,
            old_layout.state_layout_field_count,
            new_layout.state_layout_field_count,
            old_layout.state_layout_slot_count,
            new_layout.state_layout_slot_count,
        )?;
        circuit.data.prove(witness)?;
        Ok(())
    }

    #[test]
    fn rejects_incorrect_global_field_frontier() -> anyhow::Result<()> {
        let top_line_height = 3;
        let web_tree_height = 2;
        let total_height = top_line_height + web_tree_height;
        let u64_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::U64,
                1,
            )?;
        let old_layout = contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
            &[u64_layout],
            total_height,
            total_height,
        )?;
        let new_layout = contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
            &[u64_layout, u64_layout],
            total_height,
            total_height,
        )?;

        let mut tree =
            SimpleMerkleTree::<PoseidonHasher, QHashOut<PF>>::new(total_height as u8);
        tree.set_leaf(
            0,
            old_layout.fields[0].hash::<PoseidonHasher, PF>()?,
        );
        let appended_fields = &new_layout.fields[1..];
        let appended_hashes = vec![
            appended_fields[0].hash::<PoseidonHasher, PF>()?,
        ];
        let proof =
            tree.append_leaves_spider_man(web_tree_height as u8, &appended_hashes)?
                .remove(0);

        let circuit = TestCircuit::new(top_line_height, web_tree_height);
        let mut witness = PartialWitness::new();
        let appended_type_layouts =
            [StateTypeLayoutWitness::Primitive {
                type_tag: StatePrimitiveTypeTag::U64,
            }];
        circuit.gadget.set_witness(
            &mut witness,
            &proof,
            appended_fields,
            &appended_type_layouts,
            // Deliberately claim a frontier not authenticated by the web.
            old_layout.state_layout_field_count + 1,
            new_layout.state_layout_field_count + 1,
            old_layout.state_layout_slot_count,
            new_layout.state_layout_slot_count,
        )?;
        assert!(circuit.data.prove(witness).is_err());
        Ok(())
    }

    #[test]
    fn rejects_layout_slot_frontier_beyond_state_capacity(
    ) -> anyhow::Result<()> {
        let top_line_height = 3;
        let web_tree_height = 2;
        let total_height = top_line_height + web_tree_height;
        let u64_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::U64,
                1,
            )?;
        let two_slots = fixed_array_type_layout::<
            PoseidonHasher,
            PF,
            QHashOut<PF>,
        >(u64_layout, 2)?;
        let seven_slots = fixed_array_type_layout::<
            PoseidonHasher,
            PF,
            QHashOut<PF>,
        >(u64_layout, 7)?;
        let old_layout =
            contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                &[two_slots],
                total_height,
                total_height,
            )?;
        let new_layout =
            contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                &[two_slots, seven_slots],
                total_height,
                total_height,
            )?;
        let mut tree =
            SimpleMerkleTree::<PoseidonHasher, QHashOut<PF>>::new(
                total_height as u8,
            );
        tree.set_leaf(
            0,
            old_layout.fields[0].hash::<PoseidonHasher, PF>()?,
        );
        let appended_fields = &new_layout.fields[1..];
        let proof = tree
            .append_leaves_spider_man(
                web_tree_height as u8,
                &[appended_fields[0].hash::<PoseidonHasher, PF>()?],
            )?
            .remove(0);

        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let gadget = StateLayoutAppendGadget::add_virtual_to::<
            PoseidonHash,
            F,
            D,
        >(
            &mut builder,
            top_line_height,
            web_tree_height,
        );
        let old_leaf_target =
            QEDContractLeafV2Gadget::add_virtual_to(&mut builder);
        let new_leaf_target =
            QEDContractLeafV2Gadget::add_virtual_to(&mut builder);
        gadget.connect_contract_leaf_endpoints(
            &mut builder,
            &old_leaf_target,
            &new_leaf_target,
            8,
        );
        let data = builder.build::<C>();

        let deployer = QHashOut::rand();
        let old_leaf = PQEDContractLeafV2 {
            deployer,
            function_tree_root: QHashOut::rand(),
            code_root: QHashOut::rand(),
            state_tree_height: PF::from_u64_value(3),
            state_layout_root: old_layout.state_layout_root,
            state_layout_field_count: PF::from_u64_value(1),
            state_layout_slot_count: PF::from_u64_value(2),
        };
        let new_leaf = PQEDContractLeafV2 {
            deployer,
            function_tree_root: QHashOut::rand(),
            code_root: QHashOut::rand(),
            state_tree_height: PF::from_u64_value(3),
            state_layout_root: new_layout.state_layout_root,
            state_layout_field_count: PF::from_u64_value(2),
            state_layout_slot_count: PF::from_u64_value(9),
        };
        let mut witness = PartialWitness::new();
        let appended_type_layouts =
            [StateTypeLayoutWitness::FixedArray {
                element_type_hash: u64_layout.type_layout_hash,
                element_slot_count: 1,
                array_length: 7,
            }];
        gadget.set_witness(
            &mut witness,
            &proof,
            appended_fields,
            &appended_type_layouts,
            1,
            2,
            2,
            9,
        )?;
        old_leaf_target.set_witness(&mut witness, &old_leaf)?;
        new_leaf_target.set_witness(&mut witness, &new_leaf)?;
        assert!(data.prove(witness).is_err());
        Ok(())
    }

    #[test]
    fn rejects_fixed_map_with_incorrect_alignment_padding(
    ) -> anyhow::Result<()> {
        let top_line_height = 3;
        let web_tree_height = 2;
        let total_height = top_line_height + web_tree_height;
        let felt_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::Felt,
                1,
            )?;
        let map_layout =
            fixed_map_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StateMapKind::Map,
                felt_layout,
                felt_layout,
                2,
                4,
            )?;
        let old_layout =
            contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                &[felt_layout, felt_layout, felt_layout],
                total_height,
                total_height,
            )?;

        // At start slot 3 and alignment 4, the only canonical padding is 1.
        // This malicious leaf claims padding 2 while keeping the authentic
        // fixed-map type hash.
        let malicious_field =
            StateFieldLayoutLeaf::new_with_payload_offset(
                3,
                3,
                2,
                map_layout,
            )?;
        let malicious_hash =
            malicious_field.hash::<PoseidonHasher, PF>()?;
        let mut tree =
            SimpleMerkleTree::<PoseidonHasher, QHashOut<PF>>::new(
                total_height as u8,
            );
        for (index, field) in old_layout.fields.iter().enumerate() {
            tree.set_leaf(
                index as u64,
                field.hash::<PoseidonHasher, PF>()?,
            );
        }
        let proof = tree
            .append_leaves_spider_man(
                web_tree_height as u8,
                &[malicious_hash],
            )?
            .remove(0);
        let map_witness = [StateTypeLayoutWitness::FixedMap {
            map_kind: StateMapKind::Map,
            key_type_hash: felt_layout.type_layout_hash,
            key_slot_count: 1,
            value_type_hash: felt_layout.type_layout_hash,
            value_slot_count: 1,
            capacity: 2,
            alignment_slots: 4,
        }];

        let circuit = TestCircuit::new(top_line_height, web_tree_height);
        let mut witness = PartialWitness::new();
        circuit.gadget.set_witness(
            &mut witness,
            &proof,
            &[malicious_field],
            &map_witness,
            3,
            4,
            3,
            7,
        )?;
        assert!(circuit.data.prove(witness).is_err());
        Ok(())
    }

    #[test]
    fn aggregate_gadget_matches_native_transition() -> anyhow::Result<()> {
        let root0 = QHashOut::rand();
        let root1 = QHashOut::rand();
        let root2 = QHashOut::rand();
        let left = LayoutAppendPublicInputs {
            contract_id: 9,
            layout_version: STATE_LAYOUT_VERSION,
            old_layout_root: root0,
            old_layout_field_count: 1,
            old_layout_slot_count: 2,
            new_layout_root: root1,
            new_layout_field_count: 2,
            new_layout_slot_count: 5,
            appended_field_count: 1,
            appended_fields_commitment: QHashOut::rand(),
        };
        let right = LayoutAppendPublicInputs {
            contract_id: 9,
            layout_version: STATE_LAYOUT_VERSION,
            old_layout_root: root1,
            old_layout_field_count: 2,
            old_layout_slot_count: 5,
            new_layout_root: root2,
            new_layout_field_count: 4,
            new_layout_slot_count: 8,
            appended_field_count: 2,
            appended_fields_commitment: QHashOut::rand(),
        };
        let expected =
            aggregate_layout_transitions::<PoseidonHasher, F, QHashOut<F>>(
                left, right,
            )?;

        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let left_target =
            LayoutAppendPublicInputsGadget::add_virtual_to(&mut builder);
        let right_target =
            LayoutAppendPublicInputsGadget::add_virtual_to(&mut builder);
        let parent = LayoutAppendPublicInputsGadget::aggregate::<
            PoseidonHash,
            F,
            D,
        >(&mut builder, &left_target, &right_target);
        parent.register_public_inputs(&mut builder);
        let data = builder.build::<C>();

        let mut witness = PartialWitness::new();
        left_target.set_witness(&mut witness, &left)?;
        right_target.set_witness(&mut witness, &right)?;
        let proof = data.prove(witness)?;
        assert_eq!(&proof.public_inputs[0], &F::from_u64_value(9));
        assert_eq!(
            &proof.public_inputs[15..19],
            &expected.appended_fields_commitment.0.elements
        );
        Ok(())
    }

    #[test]
    fn recursively_verifies_and_aggregates_two_layout_proofs(
    ) -> anyhow::Result<()> {
        let mut child_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let child_pi =
            LayoutAppendPublicInputsGadget::add_virtual_to(&mut child_builder);
        child_pi.enforce_shape(&mut child_builder);
        child_pi.register_public_inputs(&mut child_builder);
        let child_data = child_builder.build::<C>();

        let root0 = QHashOut::rand();
        let root1 = QHashOut::rand();
        let root2 = QHashOut::rand();
        let left = LayoutAppendPublicInputs {
            contract_id: 23,
            layout_version: STATE_LAYOUT_VERSION,
            old_layout_root: root0,
            old_layout_field_count: 0,
            old_layout_slot_count: 0,
            new_layout_root: root1,
            new_layout_field_count: 1,
            new_layout_slot_count: 2,
            appended_field_count: 1,
            appended_fields_commitment: QHashOut::rand(),
        };
        let right = LayoutAppendPublicInputs {
            contract_id: 23,
            layout_version: STATE_LAYOUT_VERSION,
            old_layout_root: root1,
            old_layout_field_count: 1,
            old_layout_slot_count: 2,
            new_layout_root: root2,
            new_layout_field_count: 3,
            new_layout_slot_count: 7,
            appended_field_count: 2,
            appended_fields_commitment: QHashOut::rand(),
        };
        let mut left_witness = PartialWitness::new();
        child_pi.set_witness(&mut left_witness, &left)?;
        let left_proof = child_data.prove(left_witness)?;
        let mut right_witness = PartialWitness::new();
        child_pi.set_witness(&mut right_witness, &right)?;
        let right_proof = child_data.prove(right_witness)?;

        let mut aggregate_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let aggregate_gadget =
            LayoutAppendProofAggregationGadget::add_virtual_to::<C>(
                &mut aggregate_builder,
                &child_data.common,
                &child_data.verifier_only,
            );
        let aggregate_data = aggregate_builder.build::<C>();
        let mut aggregate_witness = PartialWitness::new();
        aggregate_gadget.set_witness::<C>(
            &mut aggregate_witness,
            &left_proof,
            &right_proof,
        )?;
        let proof = aggregate_data.prove(aggregate_witness)?;

        let expected =
            aggregate_layout_transitions::<PoseidonHasher, PF, QHashOut<PF>>(
                left, right,
            )?;
        assert_eq!(proof.public_inputs.len(), 19);
        assert_eq!(
            &proof.public_inputs[15..19],
            &expected.appended_fields_commitment.0.elements
        );
        assert_eq!(proof.public_inputs[6], PF::from_u64_value(0));
        assert_eq!(proof.public_inputs[12], PF::from_u64_value(3));
        Ok(())
    }
}
