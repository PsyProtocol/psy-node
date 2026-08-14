use plonky2::{
    field::types::Field,
    hash::hash_types::HashOutTarget,
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
use parth_core::pgoldilocks::QHashOut;
use psy_data::v1::qdata::contract::{
    CanonicalTypeLayoutDag, CanonicalTypeLayoutNode,
    CANONICAL_TYPE_LAYOUT_MAX_NODES,
    CANONICAL_TYPE_LAYOUT_MAX_STRUCT_MEMBERS,
    CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT,
    FIXED_ARRAY_TYPE_LAYOUT_DOMAIN, FIXED_MAP_TYPE_LAYOUT_DOMAIN,
    PRIMITIVE_TYPE_LAYOUT_DOMAIN, STATE_LAYOUT_ENCODING_VERSION,
    STRUCT_MEMBER_LAYOUT_DOMAIN, STRUCT_TYPE_LAYOUT_DOMAIN,
};
use crate::{
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison,
    connect::CircuitBuilderConnectHelpers,
    core::CircuitBuilderHelpersCore,
    hash::core::CircuitBuilderHashCore,
    select::CircuitBuilderSelectHelpers,
};

use super::type_layout::TypeLayoutProofPublicInputsGadget;

const KIND_PRIMITIVE: u64 = 1;
const KIND_FIXED_ARRAY: u64 = 2;
const KIND_FIXED_MAP: u64 = 3;
const KIND_STRUCT: u64 = 4;

#[derive(Debug, Clone)]
pub struct CanonicalTypeLayoutNodeTarget {
    pub kind: Target,
    pub args: [Target; 5],
    pub members: Vec<Target>,
}

#[derive(Debug)]
pub struct CanonicalTypeLayoutCircuit<C: GenericConfig<D>, const D: usize> {
    pub node_count: Target,
    pub nodes: Vec<CanonicalTypeLayoutNodeTarget>,
    pub output: TypeLayoutProofPublicInputsGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

fn random_access_hash<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    index: Target,
    values: &[HashOutTarget],
) -> HashOutTarget
where
    F: plonky2::hash::hash_types::RichField
        + plonky2::field::extension::Extendable<D>,
{
    HashOutTarget {
        elements: core::array::from_fn(|element| {
            select_table(builder, index, &values.iter().map(|value| value.elements[element]).collect::<Vec<_>>())
        }),
    }
}

fn random_access_target<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    index: Target,
    values: &[Target],
) -> Target
where
    F: plonky2::hash::hash_types::RichField
        + plonky2::field::extension::Extendable<D>,
{
    select_table(builder, index, values)
}

/// Select from a power-of-two table using a routable random-access gate.
fn select_table<F, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    index: Target,
    values: &[Target],
) -> Target
where
    F: plonky2::hash::hash_types::RichField
        + plonky2::field::extension::Extendable<D>,
{
    assert!(values.len().is_power_of_two() && !values.is_empty());
    if values.len() <= 16 {
        let routed_values = values
            .iter()
            .copied()
            .map(|target| {
                if target.is_routable(&builder.config) {
                    target
                } else {
                    let routed = builder.add_virtual_target();
                    builder.connect(routed, target);
                    routed
                }
            })
            .collect();
        let routed_index = if index.is_routable(&builder.config) {
            index
        } else {
            let routed = builder.add_virtual_target();
            builder.connect(routed, index);
            routed
        };
        return builder.random_access(routed_index, routed_values);
    }
    let bits = values.len().ilog2() as usize;
    let index_bits = builder.split_le(index, bits);
    let mut offset = builder.zero();
    for bit in index_bits[..4].iter().rev() {
        offset = builder.mul_const_add(F::TWO, offset, bit.target);
    }
    let mut chunks = values
        .chunks_exact(16)
        .map(|chunk| select_table(builder, offset, chunk))
        .collect::<Vec<_>>();
    for bit in &index_bits[4..] {
        chunks = chunks
            .chunks_exact(2)
            .map(|pair| builder.select(*bit, pair[1], pair[0]))
            .collect();
    }
    chunks[0]
}

impl<C: GenericConfig<D>, const D: usize>
    CanonicalTypeLayoutCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        assert_eq!(CANONICAL_TYPE_LAYOUT_MAX_NODES, 16);
        assert_eq!(CANONICAL_TYPE_LAYOUT_MAX_STRUCT_MEMBERS, 32);
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let zero = builder.zero();
        let one = builder.one();
        // Keep dedicated virtual padding targets constrained to zero for all
        // selectable tables. The selector below uses a binary select tree.
        let routable_zero = builder.add_virtual_target();
        builder.connect(routable_zero, zero);
        let zero_hash = HashOutTarget {
            elements: [
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
            ],
        };
        for element in zero_hash.elements {
            builder.connect(element, zero);
        }
        let node_count = builder.add_virtual_target();
        builder.range_check(node_count, 8);
        let count_non_zero = builder.is_not_equal(node_count, zero);
        builder.connect(count_non_zero.target, one);
        let max_nodes =
            builder.constant_u64(CANONICAL_TYPE_LAYOUT_MAX_NODES as u64);
        let count_in_range =
            builder.is_less_than_or_equal(8, node_count, max_nodes);
        builder.connect(count_in_range.target, one);

        let encoding =
            builder.constant_u64(STATE_LAYOUT_ENCODING_VERSION as u64);
        let primitive_kind = builder.constant_u64(KIND_PRIMITIVE);
        let array_kind = builder.constant_u64(KIND_FIXED_ARRAY);
        let map_kind = builder.constant_u64(KIND_FIXED_MAP);
        let struct_kind = builder.constant_u64(KIND_STRUCT);
        let primitive_domain =
            builder.constant_u64(PRIMITIVE_TYPE_LAYOUT_DOMAIN);
        let array_domain =
            builder.constant_u64(FIXED_ARRAY_TYPE_LAYOUT_DOMAIN);
        let map_domain =
            builder.constant_u64(FIXED_MAP_TYPE_LAYOUT_DOMAIN);
        let struct_member_domain =
            builder.constant_u64(STRUCT_MEMBER_LAYOUT_DOMAIN);
        let struct_domain =
            builder.constant_u64(STRUCT_TYPE_LAYOUT_DOMAIN);
        let mut nodes = Vec::with_capacity(CANONICAL_TYPE_LAYOUT_MAX_NODES);
        let mut output_hashes =
            Vec::with_capacity(CANONICAL_TYPE_LAYOUT_MAX_NODES);
        let mut output_slots =
            Vec::with_capacity(CANONICAL_TYPE_LAYOUT_MAX_NODES);
        let mut output_contains_map =
            Vec::with_capacity(CANONICAL_TYPE_LAYOUT_MAX_NODES);

        for node_index in 0..CANONICAL_TYPE_LAYOUT_MAX_NODES {
            let kind = builder.add_virtual_target();
            let args = core::array::from_fn(|_| {
                let target = builder.add_virtual_target();
                builder.range_check(target, 31);
                target
            });
            let members = (0..CANONICAL_TYPE_LAYOUT_MAX_STRUCT_MEMBERS)
                .map(|_| {
                    let target = builder.add_virtual_target();
                    builder.range_check(target, 7);
                    target
                })
                .collect::<Vec<_>>();
            let index_target = builder.constant_u64(node_index as u64);
            let is_active =
                builder.is_less_than(8, index_target, node_count);
            let is_primitive = builder.is_equal(kind, primitive_kind);
            let is_array = builder.is_equal(kind, array_kind);
            let is_map = builder.is_equal(kind, map_kind);
            let is_struct = builder.is_equal(kind, struct_kind);
            let valid_kind = builder.add_many([
                is_primitive.target,
                is_array.target,
                is_map.target,
                is_struct.target,
            ]);
            builder.connect(valid_kind, is_active.target);

            let mut selectable_hashes = output_hashes.clone();
            selectable_hashes.resize(
                CANONICAL_TYPE_LAYOUT_MAX_NODES,
                zero_hash,
            );
            let mut selectable_slots = output_slots.clone();
            selectable_slots.resize(
                CANONICAL_TYPE_LAYOUT_MAX_NODES,
                routable_zero,
            );
            let mut selectable_contains_map =
                output_contains_map.clone();
            selectable_contains_map
                .resize(
                    CANONICAL_TYPE_LAYOUT_MAX_NODES,
                    routable_zero,
                );
            let select_summary =
                |builder: &mut CircuitBuilder<C::F, D>, child: Target| {
                    (
                        random_access_hash(builder, child, &selectable_hashes),
                        random_access_target(&mut *builder, child, &selectable_slots),
                    )
                };

            let (array_child_hash, array_child_slots) =
                select_summary(&mut builder, args[0]);
            let array_child_before =
                builder.is_less_than(7, args[0], index_target);
            builder.connect_if_true(
                is_array,
                array_child_before.target,
                one,
            );
            let array_length_non_zero =
                builder.is_not_equal(args[2], zero);
            builder.connect_if_true(
                is_array,
                array_length_non_zero.target,
                one,
            );
            let array_child_slots_non_zero =
                builder.is_not_equal(array_child_slots, zero);
            builder.connect_if_true(
                is_array,
                array_child_slots_non_zero.target,
                one,
            );
            let array_child_contains_map = random_access_target(
                &mut builder,
                args[0],
                &selectable_contains_map,
            );
            builder.connect_if_true(
                is_array,
                array_child_contains_map,
                zero,
            );
            let array_total = builder.mul(array_child_slots, args[2]);
            builder.range_check(array_total, 32);
            let array_hash =
                builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                    array_domain,
                    array_child_hash.elements[0],
                    array_child_hash.elements[1],
                    array_child_hash.elements[2],
                    array_child_hash.elements[3],
                    args[2],
                    array_child_slots,
                    array_total,
                    encoding,
                ]);

            let (key_hash, key_slots) =
                select_summary(&mut builder, args[0]);
            let (value_hash, value_slots) =
                select_summary(&mut builder, args[1]);
            for child in [args[0], args[1]] {
                let child_before =
                    builder.is_less_than(7, child, index_target);
                builder.connect_if_true(
                    is_map,
                    child_before.target,
                    one,
                );
            }
            let mut valid_map_kind = zero;
            for kind in [1, 2, 3] {
                let kind_target = builder.constant_u64(kind);
                let is_kind = builder.is_equal(args[4], kind_target);
                valid_map_kind =
                    builder.add(valid_map_kind, is_kind.target);
            }
            builder.connect_if_true(is_map, valid_map_kind, one);
            let mut valid_alignment = zero;
            for log2 in 0..=16 {
                let alignment = builder.constant_u64(1u64 << log2);
                let is_alignment =
                    builder.is_equal(args[3], alignment);
                valid_alignment =
                    builder.add(valid_alignment, is_alignment.target);
            }
            builder.connect_if_true(is_map, valid_alignment, one);
            for required in [key_slots, value_slots, args[2]] {
                let non_zero = builder.is_not_equal(required, zero);
                builder.connect_if_true(is_map, non_zero.target, one);
            }
            for child in [args[0], args[1]] {
                let child_contains_map = random_access_target(
                    &mut builder,
                    child,
                    &selectable_contains_map,
                );
                builder.connect_if_true(
                    is_map,
                    child_contains_map,
                    zero,
                );
            }
            let map_total = builder.mul(value_slots, args[2]);
            builder.range_check(map_total, 32);
            let map_hash =
                builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                    map_domain,
                    args[4],
                    key_hash.elements[0],
                    key_hash.elements[1],
                    key_hash.elements[2],
                    key_hash.elements[3],
                    key_slots,
                    value_hash.elements[0],
                    value_hash.elements[1],
                    value_hash.elements[2],
                    value_hash.elements[3],
                    value_slots,
                    args[2],
                    args[3],
                    map_total,
                    encoding,
                ]);

            let mut primitive_width = zero;
            let mut valid_primitive = zero;
            for (tag, width) in [(1, 1), (2, 1), (3, 1), (4, 1), (5, 2), (6, 4), (7, 4)] {
                let tag_target = builder.constant_u64(tag);
                let width_target = builder.constant_u64(width);
                let is_tag = builder.is_equal(args[0], tag_target);
                valid_primitive =
                    builder.add(valid_primitive, is_tag.target);
                primitive_width = builder.mul_add(
                    is_tag.target,
                    width_target,
                    primitive_width,
                );
            }
            builder.connect_if_true(
                is_primitive,
                valid_primitive,
                one,
            );
            let primitive_hash =
                builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                    primitive_domain,
                    args[0],
                    encoding,
                ]);

            let member_count = args[0];
            let members_height = args[1];
            let struct_count_non_zero =
                builder.is_not_equal(member_count, zero);
            builder.connect_if_true(
                is_struct,
                struct_count_non_zero.target,
                one,
            );
            let max_members = builder.constant_u64(
                CANONICAL_TYPE_LAYOUT_MAX_STRUCT_MEMBERS as u64,
            );
            let struct_count_in_range = builder.is_less_than_or_equal(
                7,
                member_count,
                max_members,
            );
            builder.connect_if_true(
                is_struct,
                struct_count_in_range.target,
                one,
            );
            let max_struct_height =
                builder.constant_u64(
                    CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT as u64,
                );
            let struct_height_in_range = builder.is_less_than_or_equal(
                3,
                members_height,
                max_struct_height,
            );
            builder.connect_if_true(
                is_struct,
                struct_height_in_range.target,
                one,
            );
            let mut selected_capacity = zero;
            for height in
                0..=CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT
            {
                let height_target = builder.constant_u64(height as u64);
                let capacity_target = builder.constant_u64(1u64 << height);
                let is_height =
                    builder.is_equal(members_height, height_target);
                selected_capacity = builder.mul_add(
                    is_height.target,
                    capacity_target,
                    selected_capacity,
                );
            }
            let count_fits_height = builder.is_less_than_or_equal(
                7,
                member_count,
                selected_capacity,
            );
            builder.connect_if_true(
                is_struct,
                count_fits_height.target,
                one,
            );
            let mut member_offset = zero;
            let mut member_hashes =
                Vec::with_capacity(CANONICAL_TYPE_LAYOUT_MAX_STRUCT_MEMBERS);
            for (member_index, child) in members.iter().copied().enumerate() {
                let member_index_target =
                    builder.constant_u64(member_index as u64);
                let member_active = builder.is_less_than(
                    7,
                    member_index_target,
                    member_count,
                );
                let child_before =
                    builder.is_less_than(7, child, index_target);
                let active_struct_member =
                    builder.and(is_struct, member_active);
                builder.connect_if_true(
                    active_struct_member,
                    child_before.target,
                    one,
                );
                let (child_hash, child_slots) =
                    select_summary(&mut builder, child);
                let child_slots_non_zero =
                    builder.is_not_equal(child_slots, zero);
                builder.connect_if_true(
                    active_struct_member,
                    child_slots_non_zero.target,
                    one,
                );
                let child_contains_map = random_access_target(
                    &mut builder,
                    child,
                    &selectable_contains_map,
                );
                builder.connect_if_true(
                    active_struct_member,
                    child_contains_map,
                    zero,
                );
                let member_id =
                    builder.constant_u64((member_index + 1) as u64);
                let member_hash =
                    builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                        struct_member_domain,
                        member_id,
                        member_offset,
                        child_slots,
                        child_hash.elements[0],
                        child_hash.elements[1],
                        child_hash.elements[2],
                        child_hash.elements[3],
                        encoding,
                    ]);
                member_hashes.push(builder.select_hash(
                    member_active,
                    member_hash,
                    zero_hash,
                ));
                let active_slots =
                    builder.mul(member_active.target, child_slots);
                member_offset =
                    builder.add(member_offset, active_slots);
                builder.range_check(member_offset, 32);
            }
            let mut roots = Vec::with_capacity(
                CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT + 1,
            );
            roots.push(member_hashes[0]);
            let mut level = member_hashes;
            for _ in 0..CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT {
                level = level
                    .chunks_exact(2)
                    .map(|pair| {
                        builder.hash_two_to_one::<C::Hasher>(
                            pair[0], pair[1],
                        )
                    })
                    .collect();
                roots.push(level[0]);
            }
            roots.resize(
                (CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT + 2)
                    .next_power_of_two(),
                zero_hash,
            );
            let members_root =
                random_access_hash(&mut builder, members_height, &roots);
            let struct_hash =
                builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                    struct_domain,
                    member_count,
                    member_offset,
                    members_root.elements[0],
                    members_root.elements[1],
                    members_root.elements[2],
                    members_root.elements[3],
                    encoding,
                ]);

            let mut selected_hash = builder.select_hash(
                is_array,
                array_hash,
                primitive_hash,
            );
            selected_hash =
                builder.select_hash(is_map, map_hash, selected_hash);
            selected_hash =
                builder.select_hash(is_struct, struct_hash, selected_hash);
            selected_hash =
                builder.select_hash(is_active, selected_hash, zero_hash);
            let mut selected_slots =
                builder.select(is_array, array_total, primitive_width);
            selected_slots =
                builder.select(is_map, map_total, selected_slots);
            selected_slots =
                builder.select(is_struct, member_offset, selected_slots);
            selected_slots =
                builder.mul(is_active.target, selected_slots);
            output_hashes.push(selected_hash);
            output_slots.push(selected_slots);
            output_contains_map.push(is_map.target);
            nodes.push(CanonicalTypeLayoutNodeTarget {
                kind,
                args,
                members,
            });
        }

        let root_index = builder.sub(node_count, one);
        let output = TypeLayoutProofPublicInputsGadget {
            type_layout_hash:
                random_access_hash(&mut builder, root_index, &output_hashes),
            total_slot_count:
                random_access_target(&mut builder, root_index, &output_slots),
        };
        output.register_public_inputs(&mut builder);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));
        Self {
            node_count,
            nodes,
            output,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove(
        &self,
        dag: &CanonicalTypeLayoutDag,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        dag.validate_shape()?;
        let mut witness = PartialWitness::new();
        witness.set_target(
            self.node_count,
            C::F::from_canonical_usize(dag.nodes.len()),
        )?;
        for (node_index, targets) in self.nodes.iter().enumerate() {
            let mut args = [0u64; 5];
            let mut members = Vec::new();
            let kind = if let Some(node) = dag.nodes.get(node_index) {
                match node {
                    CanonicalTypeLayoutNode::Primitive { type_tag } => {
                        args[0] = *type_tag as u16 as u64;
                        KIND_PRIMITIVE
                    }
                    CanonicalTypeLayoutNode::FixedArray {
                        element,
                        length,
                    } => {
                        args[0] = *element as u64;
                        args[1] = 0;
                        args[2] = *length;
                        KIND_FIXED_ARRAY
                    }
                    CanonicalTypeLayoutNode::FixedMap {
                        map_kind,
                        key,
                        value,
                        capacity,
                        alignment_slots,
                    } => {
                        args[0] = *key as u64;
                        args[1] = *value as u64;
                        args[2] = *capacity;
                        args[3] = *alignment_slots;
                        args[4] = *map_kind as u16 as u64;
                        KIND_FIXED_MAP
                    }
                    CanonicalTypeLayoutNode::Struct {
                        members: node_members,
                        members_tree_height,
                    } => {
                        args[0] = node_members.len() as u64;
                        args[1] = *members_tree_height as u64;
                        members = node_members.clone();
                        KIND_STRUCT
                    }
                }
            } else {
                0
            };
            witness.set_target(
                targets.kind,
                C::F::from_canonical_u64(kind),
            )?;
            for (target, value) in targets.args.iter().zip(args) {
                witness.set_target(
                    *target,
                    C::F::from_canonical_u64(value),
                )?;
            }
            for (member_index, target) in targets.members.iter().enumerate() {
                let value = members.get(member_index).copied().unwrap_or(0);
                witness.set_target(
                    *target,
                    C::F::from_canonical_u64(value as u64),
                )?;
            }
        }
        self.circuit_data.prove(witness)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for CanonicalTypeLayoutCircuit<C, D>
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
