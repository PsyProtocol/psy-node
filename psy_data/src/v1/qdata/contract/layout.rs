use parth_core::{
    crypto::hash::{
        spiderman::SpidermanUpdateProof,
        traits::{
            FieldQHasher, MerkleHasher, MerkleLeafHasher, QFieldHashable,
        },
    },
    felt::{QFelt, QFelt64, QFeltSized, ToQFelts},
    protocol::core_types::{Q256BitHash, QFHashBase, QHashBase},
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{
    AutoImplementFallbackPsySerializeCanonical, FallbackPsySerializeCanonical,
    PsyCanonicalSerializeMetadata,
};

use super::abi::{QContractABI, StructAbiSpec, TypeAbiSpec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use ts_rs::TS;

/// Consensus version of the field-oriented state-layout format.
pub const STATE_LAYOUT_VERSION: u16 = 1;
pub const STATE_LAYOUT_ENCODING_VERSION: u16 = 1;
/// Contract id committed by a layout proof created before deployment.
///
/// Contract id zero is reserved and cannot be updated, so this domain cannot
/// be confused with a proof authorizing an existing-contract update.
pub const STATE_LAYOUT_DEPLOY_CONTRACT_ID: u64 = 0;

// These are protocol domain separators, encoded as field elements before
// hashing. Once deployed, their values must never be reused for another type.
pub const STATE_FIELD_LAYOUT_DOMAIN: u64 = 0x5354_464c_5631; 
pub const STRUCT_MEMBER_LAYOUT_DOMAIN: u64 = 0x5354_4d4c_5631; 
pub const STRUCT_TYPE_LAYOUT_DOMAIN: u64 = 0x5354_5459_5631; 
pub const PRIMITIVE_TYPE_LAYOUT_DOMAIN: u64 = 0x5052_5459_5631; 
pub const FIXED_ARRAY_TYPE_LAYOUT_DOMAIN: u64 = 0x4152_5459_5631; 
pub const FIXED_MAP_TYPE_LAYOUT_DOMAIN: u64 = 0x4d50_5459_5631; 
pub const CONTRACT_LEAF_DOMAIN: u64 = 0x434c_5632; 
pub const STATE_LAYOUT_APPEND_BATCH_DOMAIN: u64 = 0x534c_4241_5631; 
pub const STATE_LAYOUT_APPEND_AGG_DOMAIN: u64 = 0x534c_4147_5631; 
pub const CONTRACT_LEAF_FELT_SIZE: usize = 19;
pub const CONTRACT_LEAF_SERIALIZED_SIZE: usize = 152;

/// Minimal queryable metadata carried by a layout-aware contract leaf.
///
/// The protocol version is intentionally returned as a protocol constant:
/// the leaf format is canonical for this API, while the root and capacities
/// come from the authenticated leaf itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractLayoutMetadata<Hash> {
    pub protocol_version: u16,
    pub state_layout_root: Hash,
    pub field_count: u64,
    pub slot_count: u64,
    pub state_tree_height: u64,
}

/// Versioned contract leaf used by the layout-aware update path.
///
/// It is intentionally a distinct type so old 104-byte records
/// cannot be silently decoded as the canonical layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, TS)]
#[ts(concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDContractLeafV2")]
#[repr(C)]
pub struct PQEDContractLeafV2<F, Hash> {
    pub deployer: Hash,
    pub function_tree_root: Hash,
    pub code_root: Hash,
    pub state_tree_height: F,
    pub state_layout_root: Hash,
    pub state_layout_field_count: F,
    pub state_layout_slot_count: F,
}

impl<F: QFelt64, Hash: QHashBase> PQEDContractLeafV2<F, Hash> {
    pub fn layout_metadata(&self) -> ContractLayoutMetadata<Hash> {
        ContractLayoutMetadata {
            protocol_version: STATE_LAYOUT_VERSION,
            state_layout_root: self.state_layout_root,
            field_count: self.state_layout_field_count.to_u64_value(),
            slot_count: self.state_layout_slot_count.to_u64_value(),
            state_tree_height: self.state_tree_height.to_u64_value(),
        }
    }
}

impl<F: Default, Hash: Default> Default for PQEDContractLeafV2<F, Hash> {
    fn default() -> Self {
        Self {
            deployer: Hash::default(),
            function_tree_root: Hash::default(),
            code_root: Hash::default(),
            state_tree_height: F::default(),
            state_layout_root: Hash::default(),
            state_layout_field_count: F::default(),
            state_layout_slot_count: F::default(),
        }
    }
}

impl<F: QFelt, Hash: parth_core::protocol::core_types::QHashBase> QFeltSized
    for PQEDContractLeafV2<F, Hash>
{
    fn q_felt_size() -> usize {
        CONTRACT_LEAF_FELT_SIZE
    }

    fn self_qsize(&self) -> usize {
        Self::q_felt_size()
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F>
    for PQEDContractLeafV2<F, Hash>
{
    fn to_qfelts(&self) -> Vec<F> {
        let deployer = self.deployer.to_4_felts();
        let function_tree_root = self.function_tree_root.to_4_felts();
        let code_root = self.code_root.to_4_felts();
        let state_layout_root = self.state_layout_root.to_4_felts();
        vec![
            deployer[0],
            deployer[1],
            deployer[2],
            deployer[3],
            function_tree_root[0],
            function_tree_root[1],
            function_tree_root[2],
            function_tree_root[3],
            code_root[0],
            code_root[1],
            code_root[2],
            code_root[3],
            self.state_tree_height,
            state_layout_root[0],
            state_layout_root[1],
            state_layout_root[2],
            state_layout_root[3],
            self.state_layout_field_count,
            self.state_layout_slot_count,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        assert_eq!(
            felts.len(),
            CONTRACT_LEAF_FELT_SIZE,
            "invalid number of contract leaf felts"
        );
        Self {
            deployer: Hash::from_4_felts_slice(&felts[0..4]),
            function_tree_root: Hash::from_4_felts_slice(&felts[4..8]),
            code_root: Hash::from_4_felts_slice(&felts[8..12]),
            state_tree_height: felts[12],
            state_layout_root: Hash::from_4_felts_slice(&felts[13..17]),
            state_layout_field_count: felts[17],
            state_layout_slot_count: felts[18],
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash>
    for PQEDContractLeafV2<F, Hash>
{
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let mut felts = Vec::with_capacity(CONTRACT_LEAF_FELT_SIZE + 1);
        felts.push(F::from_u64_value(CONTRACT_LEAF_DOMAIN));
        felts.extend(<Self as ToQFelts<F>>::to_qfelts(self));
        H::q_hash_many(&felts)
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata
    for PQEDContractLeafV2<F, Hash>
{
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = CONTRACT_LEAF_SERIALIZED_SIZE;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical
    for PQEDContractLeafV2<F, Hash>
{
    fn fallback_pio_serialized_size(&self) -> usize {
        CONTRACT_LEAF_SERIALIZED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(
        &self,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.deployer.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(
            &self.function_tree_root.into_owned_32bytes(),
        )?;
        writer.psy_write_bytes_fixed(&self.code_root.into_owned_32bytes())?;
        writer.psy_write_u64(self.state_tree_height.to_u64_value())?;
        writer.psy_write_bytes_fixed(
            &self.state_layout_root.into_owned_32bytes(),
        )?;
        writer.psy_write_u64(self.state_layout_field_count.to_u64_value())?;
        writer.psy_write_u64(self.state_layout_slot_count.to_u64_value())?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(
        reader: &mut R,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            deployer: Hash::from_owned_32bytes(
                reader.psy_read_bytes_fixed::<32>()?,
            ),
            function_tree_root: Hash::from_owned_32bytes(
                reader.psy_read_bytes_fixed::<32>()?,
            ),
            code_root: Hash::from_owned_32bytes(
                reader.psy_read_bytes_fixed::<32>()?,
            ),
            state_tree_height: F::from_u64_value(reader.psy_read_u64()?),
            state_layout_root: Hash::from_owned_32bytes(
                reader.psy_read_bytes_fixed::<32>()?,
            ),
            state_layout_field_count: F::from_u64_value(
                reader.psy_read_u64()?,
            ),
            state_layout_slot_count: F::from_u64_value(
                reader.psy_read_u64()?,
            ),
        })
    }
}

impl<F: QFelt64, Hash: Q256BitHash>
    AutoImplementFallbackPsySerializeCanonical for PQEDContractLeafV2<F, Hash>
{
}

/// Primitive tags committed by layout protocol.
///
/// Slot widths are supplied by the VM's authoritative encoding table; the
/// layout hashing code intentionally does not guess them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum StatePrimitiveTypeTag {
    Felt = 1,
    Bool = 2,
    U32 = 3,
    U64 = 4,
    U128 = 5,
    Hash = 6,
    Bytes32 = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum StateMapKind {
    ContractHashMap = 1,
    Map = 2,
    NamespacedMap = 3,
}

/// The verified output of any canonical type-layout construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTypeLayoutSummary<Hash> {
    pub type_layout_hash: Hash,
    pub total_slot_count: u64,
}

/// Canonical preimage needed to verify one type-layout summary.
///
/// Child type hashes and struct member roots are separate authenticated
/// commitments. A recursive type-layout proof can verify those commitments
/// without making the top-level append circuit depend on type nesting depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StateTypeLayoutWitness<Hash> {
    Primitive {
        type_tag: StatePrimitiveTypeTag,
    },
    FixedArray {
        element_type_hash: Hash,
        element_slot_count: u64,
        array_length: u64,
    },
    Struct {
        member_count: u64,
        total_slot_count: u64,
        members_root: Hash,
    },
    FixedMap {
        map_kind: StateMapKind,
        key_type_hash: Hash,
        key_slot_count: u64,
        value_type_hash: Hash,
        value_slot_count: u64,
        capacity: u64,
        alignment_slots: u64,
    },
}

pub const CANONICAL_TYPE_LAYOUT_MAX_NODES: usize = 16;
pub const CANONICAL_TYPE_LAYOUT_MAX_STRUCT_MEMBERS: usize = 32;
pub const CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT: usize = 5;

/// One node in the canonical, topologically ordered type-layout DAG.
///
/// Child indices must point to earlier nodes. This representation gives every
/// contract the same bounded circuit shape and therefore one protocol
/// verifier, independent of the concrete struct fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonicalTypeLayoutNode {
    Primitive {
        type_tag: StatePrimitiveTypeTag,
    },
    FixedArray {
        element: u16,
        length: u64,
    },
    FixedMap {
        map_kind: StateMapKind,
        key: u16,
        value: u16,
        capacity: u64,
        alignment_slots: u64,
    },
    Struct {
        members: Vec<u16>,
        members_tree_height: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalTypeLayoutDag {
    pub nodes: Vec<CanonicalTypeLayoutNode>,
    pub root: u16,
}

impl CanonicalTypeLayoutDag {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        const MAX_ARGUMENT: u64 = (1u64 << 31) - 1;
        const MAX_SLOT_COUNT: u64 = (1u64 << 32) - 1;
        anyhow::ensure!(!self.nodes.is_empty(), "type-layout DAG is empty");
        anyhow::ensure!(
            self.nodes.len() <= CANONICAL_TYPE_LAYOUT_MAX_NODES,
            "type-layout DAG has {} nodes, maximum is {}",
            self.nodes.len(),
            CANONICAL_TYPE_LAYOUT_MAX_NODES
        );
        anyhow::ensure!(
            self.root as usize == self.nodes.len() - 1,
            "type-layout DAG root must be its final node"
        );
        let mut slot_counts: Vec<u64> =
            Vec::with_capacity(self.nodes.len());
        let mut contains_map: Vec<bool> =
            Vec::with_capacity(self.nodes.len());
        for (node_index, node) in self.nodes.iter().enumerate() {
            let ensure_child = |child: u16| -> anyhow::Result<()> {
                anyhow::ensure!(
                    (child as usize) < node_index,
                    "type-layout node {node_index} has non-topological child {child}"
                );
                Ok(())
            };
            let (slot_count, node_contains_map) = match node {
                CanonicalTypeLayoutNode::Primitive { type_tag } => {
                    (canonical_primitive_slot_width(*type_tag), false)
                }
                CanonicalTypeLayoutNode::FixedArray { element, length } => {
                    ensure_child(*element)?;
                    anyhow::ensure!(*length > 0, "fixed array length is zero");
                    anyhow::ensure!(
                        *length <= MAX_ARGUMENT,
                        "fixed array length exceeds canonical circuit range"
                    );
                    anyhow::ensure!(
                        !contains_map[*element as usize],
                        "fixed map cannot be nested in an array"
                    );
                    (
                        slot_counts[*element as usize]
                            .checked_mul(*length)
                            .filter(|slots| *slots <= MAX_SLOT_COUNT)
                            .ok_or_else(|| anyhow::anyhow!(
                                "fixed array slot count exceeds canonical circuit range"
                            ))?,
                        false,
                    )
                }
                CanonicalTypeLayoutNode::FixedMap {
                    key,
                    value,
                    capacity,
                    alignment_slots,
                    ..
                } => {
                    ensure_child(*key)?;
                    ensure_child(*value)?;
                    anyhow::ensure!(*capacity > 0, "fixed map capacity is zero");
                    anyhow::ensure!(
                        *capacity <= MAX_ARGUMENT,
                        "fixed map capacity exceeds canonical circuit range"
                    );
                    anyhow::ensure!(
                        *alignment_slots > 0
                            && alignment_slots.is_power_of_two()
                            && *alignment_slots <= (1 << 16),
                        "fixed map alignment must be a power of two no greater than 65536"
                    );
                    anyhow::ensure!(
                        !contains_map[*key as usize]
                            && !contains_map[*value as usize],
                        "fixed map cannot contain another fixed map"
                    );
                    (
                        slot_counts[*value as usize]
                            .checked_mul(*capacity)
                            .filter(|slots| *slots <= MAX_SLOT_COUNT)
                            .ok_or_else(|| anyhow::anyhow!(
                                "fixed map slot count exceeds canonical circuit range"
                            ))?,
                        true,
                    )
                }
                CanonicalTypeLayoutNode::Struct {
                    members,
                    members_tree_height,
                } => {
                    anyhow::ensure!(!members.is_empty(), "empty structs are not supported");
                    anyhow::ensure!(
                        members.len() <= CANONICAL_TYPE_LAYOUT_MAX_STRUCT_MEMBERS,
                        "struct has {} members, maximum is {}",
                        members.len(),
                        CANONICAL_TYPE_LAYOUT_MAX_STRUCT_MEMBERS
                    );
                    anyhow::ensure!(
                        members.len() <= checked_capacity(*members_tree_height as usize)?,
                        "struct members exceed members-tree capacity"
                    );
                    for child in members {
                        ensure_child(*child)?;
                        anyhow::ensure!(
                            !contains_map[*child as usize],
                            "fixed map cannot be nested in a struct"
                        );
                    }
                    (
                        members.iter().try_fold(0u64, |total, child| {
                            total
                                .checked_add(slot_counts[*child as usize])
                                .filter(|slots| *slots <= MAX_SLOT_COUNT)
                                .ok_or_else(|| anyhow::anyhow!(
                                    "struct slot count exceeds canonical circuit range"
                                ))
                        })?,
                        false,
                    )
                }
            };
            slot_counts.push(slot_count);
            contains_map.push(node_contains_map);
        }
        Ok(())
    }

    pub fn evaluate<Hasher, F, Hash>(
        &self,
    ) -> anyhow::Result<StateTypeLayoutSummary<Hash>>
    where
        Hasher: FieldQHasher<F, Hash>,
        F: QFelt64,
        Hash: QFHashBase<F> + Copy + Default + PartialEq,
    {
        self.validate_shape()?;
        let mut summaries = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let summary = match node {
                CanonicalTypeLayoutNode::Primitive { type_tag } => {
                    primitive_type_layout::<Hasher, F, Hash>(
                        *type_tag,
                        canonical_primitive_slot_width(*type_tag),
                    )?
                }
                CanonicalTypeLayoutNode::FixedArray { element, length } => {
                    fixed_array_type_layout::<Hasher, F, Hash>(
                        summaries[*element as usize],
                        *length,
                    )?
                }
                CanonicalTypeLayoutNode::FixedMap {
                    map_kind,
                    key,
                    value,
                    capacity,
                    alignment_slots,
                } => fixed_map_type_layout::<Hasher, F, Hash>(
                    *map_kind,
                    summaries[*key as usize],
                    summaries[*value as usize],
                    *capacity,
                    *alignment_slots,
                )?,
                CanonicalTypeLayoutNode::Struct {
                    members,
                    members_tree_height,
                } => {
                    let member_types = members
                        .iter()
                        .map(|index| summaries[*index as usize])
                        .collect::<Vec<_>>();
                    struct_type_layout::<Hasher, F, Hash>(
                        &member_types,
                        *members_tree_height as usize,
                    )?
                    .summary
                }
            };
            summaries.push(summary);
        }
        Ok(summaries[self.root as usize])
    }
}

impl<Hash: Copy> StateTypeLayoutWitness<Hash> {
    pub fn summary<Hasher, F>(
        &self,
    ) -> anyhow::Result<StateTypeLayoutSummary<Hash>>
    where
        Hasher: FieldQHasher<F, Hash>,
        F: QFelt64,
        Hash: QFHashBase<F> + Default + PartialEq,
    {
        match *self {
            Self::Primitive { type_tag } => {
                primitive_type_layout::<Hasher, F, Hash>(
                    type_tag,
                    canonical_primitive_slot_width(type_tag),
                )
            }
            Self::FixedArray {
                element_type_hash,
                element_slot_count,
                array_length,
            } => fixed_array_type_layout::<Hasher, F, Hash>(
                StateTypeLayoutSummary {
                    type_layout_hash: element_type_hash,
                    total_slot_count: element_slot_count,
                },
                array_length,
            ),
            Self::Struct {
                member_count,
                total_slot_count,
                members_root,
            } => {
                anyhow::ensure!(
                    member_count > 0 && total_slot_count > 0,
                    "struct type witness must be non-empty"
                );
                let root = members_root.to_4_felts();
                let type_layout_hash = Hasher::q_hash_many(&[
                    F::from_u64_value(STRUCT_TYPE_LAYOUT_DOMAIN),
                    F::from_u64_value(member_count),
                    F::from_u64_value(total_slot_count),
                    root[0],
                    root[1],
                    root[2],
                    root[3],
                    F::from_u64_value(
                        STATE_LAYOUT_ENCODING_VERSION as u64,
                    ),
                ]);
                anyhow::ensure!(
                    type_layout_hash != Hash::default(),
                    "struct type hashes to zero"
                );
                Ok(StateTypeLayoutSummary {
                    type_layout_hash,
                    total_slot_count,
                })
            }
            Self::FixedMap {
                map_kind,
                key_type_hash,
                key_slot_count,
                value_type_hash,
                value_slot_count,
                capacity,
                alignment_slots,
            } => fixed_map_type_layout::<Hasher, F, Hash>(
                map_kind,
                StateTypeLayoutSummary {
                    type_layout_hash: key_type_hash,
                    total_slot_count: key_slot_count,
                },
                StateTypeLayoutSummary {
                    type_layout_hash: value_type_hash,
                    total_slot_count: value_slot_count,
                },
                capacity,
                alignment_slots,
            ),
        }
    }

    pub fn validate_field<Hasher, F>(
        &self,
        field: &StateFieldLayoutLeaf<Hash>,
    ) -> anyhow::Result<()>
    where
        Hasher: FieldQHasher<F, Hash>,
        F: QFelt64,
        Hash: QFHashBase<F> + Default + PartialEq,
    {
        let summary = self.summary::<Hasher, F>()?;
        anyhow::ensure!(
            field.type_layout_hash == summary.type_layout_hash,
            "field type-layout hash does not match its canonical preimage"
        );
        let expected_payload_offset = match *self {
            Self::FixedMap {
                alignment_slots, ..
            } => {
                (alignment_slots - field.start_slot % alignment_slots)
                    % alignment_slots
            }
            _ => 0,
        };
        anyhow::ensure!(
            field.payload_offset == expected_payload_offset,
            "field payload offset is not canonical for its type"
        );
        anyhow::ensure!(
            field.slot_count
                == expected_payload_offset
                    .checked_add(summary.total_slot_count)
                    .ok_or_else(|| anyhow::anyhow!(
                        "field owned slot count overflow"
                    ))?,
            "field owned slot count does not match its type and padding"
        );
        Ok(())
    }
}

pub fn canonical_primitive_slot_width(
    type_tag: StatePrimitiveTypeTag,
) -> u64 {
    match type_tag {
        StatePrimitiveTypeTag::Felt
        | StatePrimitiveTypeTag::Bool
        | StatePrimitiveTypeTag::U32
        | StatePrimitiveTypeTag::U64 => 1,
        StatePrimitiveTypeTag::U128 => 2,
        StatePrimitiveTypeTag::Hash | StatePrimitiveTypeTag::Bytes32 => 4,
    }
}

/// One direct field of the top-level `ContractState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFieldLayoutLeaf<Hash> {
    /// One-based field-tree position.
    pub field_id: u64,
    pub start_slot: u64,
    /// Leading slots owned by this field before its aligned payload.
    pub payload_offset: u64,
    pub slot_count: u64,
    pub type_layout_hash: Hash,
    pub encoding_version: u16,
}

impl<Hash> StateFieldLayoutLeaf<Hash> {
    pub fn new(
        field_index: usize,
        start_slot: u64,
        type_layout: StateTypeLayoutSummary<Hash>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            type_layout.total_slot_count > 0,
            "state field at index {field_index} must occupy at least one slot"
        );
        let field_id = u64::try_from(field_index)?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("state field id overflow"))?;
        Ok(Self {
            field_id,
            start_slot,
            payload_offset: 0,
            slot_count: type_layout.total_slot_count,
            type_layout_hash: type_layout.type_layout_hash,
            encoding_version: STATE_LAYOUT_ENCODING_VERSION,
        })
    }

    pub fn new_with_payload_offset(
        field_index: usize,
        start_slot: u64,
        payload_offset: u64,
        type_layout: StateTypeLayoutSummary<Hash>,
    ) -> anyhow::Result<Self> {
        let mut leaf = Self::new(field_index, start_slot, type_layout)?;
        leaf.payload_offset = payload_offset;
        leaf.slot_count = leaf
            .slot_count
            .checked_add(payload_offset)
            .ok_or_else(|| anyhow::anyhow!(
                "state field slot count overflow"
            ))?;
        Ok(leaf)
    }
}

impl<Hash: Copy> StateFieldLayoutLeaf<Hash> {
    pub fn hash<Hasher, F>(&self) -> anyhow::Result<Hash>
    where
        Hasher: FieldQHasher<F, Hash>,
        F: QFelt64,
        Hash: QFHashBase<F> + Default + PartialEq,
    {
        anyhow::ensure!(self.field_id > 0, "state field id must be non-zero");
        anyhow::ensure!(self.slot_count > 0, "state field slot count must be non-zero");
        anyhow::ensure!(
            self.payload_offset < self.slot_count,
            "state field payload offset is outside its owned slot range"
        );
        anyhow::ensure!(
            self.encoding_version == STATE_LAYOUT_ENCODING_VERSION,
            "unsupported state field encoding version {}",
            self.encoding_version
        );
        let type_hash = self.type_layout_hash.to_4_felts();
        let hash = Hasher::q_hash_many(&[
            F::from_u64_value(STATE_FIELD_LAYOUT_DOMAIN),
            F::from_u64_value(self.field_id),
            F::from_u64_value(self.start_slot),
            F::from_u64_value(self.payload_offset),
            F::from_u64_value(self.slot_count),
            type_hash[0],
            type_hash[1],
            type_hash[2],
            type_hash[3],
            F::from_u64_value(self.encoding_version as u64),
        ]);
        anyhow::ensure!(hash != Hash::default(), "occupied state field leaf hashes to zero");
        Ok(hash)
    }
}

/// One direct member of a fixed-size struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructMemberLayout<Hash> {
    /// One-based member-tree position.
    pub member_id: u64,
    pub slot_offset: u64,
    pub slot_count: u64,
    pub member_type_hash: Hash,
    pub encoding_version: u16,
}

impl<Hash> StructMemberLayout<Hash> {
    pub fn new(
        member_index: usize,
        slot_offset: u64,
        type_layout: StateTypeLayoutSummary<Hash>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            type_layout.total_slot_count > 0,
            "struct member at index {member_index} must occupy at least one slot"
        );
        let member_id = u64::try_from(member_index)?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("struct member id overflow"))?;
        Ok(Self {
            member_id,
            slot_offset,
            slot_count: type_layout.total_slot_count,
            member_type_hash: type_layout.type_layout_hash,
            encoding_version: STATE_LAYOUT_ENCODING_VERSION,
        })
    }
}

impl<Hash: Copy> StructMemberLayout<Hash> {
    pub fn hash<Hasher, F>(&self) -> anyhow::Result<Hash>
    where
        Hasher: FieldQHasher<F, Hash>,
        F: QFelt64,
        Hash: QFHashBase<F> + Default + PartialEq,
    {
        anyhow::ensure!(self.member_id > 0, "struct member id must be non-zero");
        anyhow::ensure!(self.slot_count > 0, "struct member slot count must be non-zero");
        anyhow::ensure!(
            self.encoding_version == STATE_LAYOUT_ENCODING_VERSION,
            "unsupported struct member encoding version {}",
            self.encoding_version
        );
        let type_hash = self.member_type_hash.to_4_felts();
        let hash = Hasher::q_hash_many(&[
            F::from_u64_value(STRUCT_MEMBER_LAYOUT_DOMAIN),
            F::from_u64_value(self.member_id),
            F::from_u64_value(self.slot_offset),
            F::from_u64_value(self.slot_count),
            type_hash[0],
            type_hash[1],
            type_hash[2],
            type_hash[3],
            F::from_u64_value(self.encoding_version as u64),
        ]);
        anyhow::ensure!(hash != Hash::default(), "occupied struct member leaf hashes to zero");
        Ok(hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructTypeLayout<Hash> {
    pub members: Vec<StructMemberLayout<Hash>>,
    pub members_root: Hash,
    pub summary: StateTypeLayoutSummary<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractStateLayout<Hash> {
    pub fields: Vec<StateFieldLayoutLeaf<Hash>>,
    pub state_layout_root: Hash,
    pub state_layout_field_count: u64,
    pub state_layout_slot_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalContractStateLayout<Hash> {
    pub contract_layout: ContractStateLayout<Hash>,
    /// Canonical preimages for the top-level fields, in field order.
    pub field_type_layouts: Vec<StateTypeLayoutWitness<Hash>>,
    /// Canonical type descriptors archived by source ABI type name.
    pub struct_layouts: BTreeMap<String, StructTypeLayout<Hash>>,
}

/// Complete, compiler-independent input consumed by the local layout prover.
///
/// ABI parsing and source-language type resolution happen before this
/// boundary. The prover receives only consensus types and commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalLayoutManifest<Hash> {
    pub layout_version: u16,
    pub state_tree_height: u16,
    pub layout: CanonicalContractStateLayout<Hash>,
    pub field_type_dags: Vec<CanonicalTypeLayoutDag>,
}

#[derive(Debug, Deserialize)]
struct CompilerAbiDocument {
    contract: CompilerAbiContract,
    types: Vec<CompilerAbiStruct>,
}

#[derive(Debug, Deserialize)]
struct CompilerAbiContract {
    state_tree_height: u16,
    state_layout: CompilerAbiStateLayout,
}

#[derive(Debug, Deserialize)]
struct CompilerAbiStateLayout {
    layout_version: u16,
    encoding_version: u16,
    field_count: u64,
    slot_count: u64,
    fields: Vec<CompilerAbiLayoutField>,
}

#[derive(Debug, Deserialize)]
struct CompilerAbiLayoutField {
    field_id: u64,
    #[serde(rename = "type")]
    ty: CompilerAbiTypeRef,
    start_slot: u64,
    #[serde(default)]
    payload_offset: u64,
    slot_count: u64,
}

#[derive(Debug, Deserialize)]
struct CompilerAbiStruct {
    name: String,
    fields: Vec<CompilerAbiStructField>,
}

#[derive(Debug, Deserialize)]
struct CompilerAbiStructField {
    #[serde(rename = "type")]
    ty: CompilerAbiTypeRef,
    offset_within_parent: u64,
    felt_size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CompilerAbiTypeRef {
    Primitive {
        name: CompilerAbiPrimitive,
    },
    Struct {
        name: String,
    },
    Array {
        item: Box<CompilerAbiTypeRef>,
        length: u32,
        item_felt_size: u64,
    },
    Map {
        map_kind: CompilerAbiMapKind,
        key: Box<CompilerAbiTypeRef>,
        value: Box<CompilerAbiTypeRef>,
        capacity: usize,
        value_felt_size: usize,
        alignment_felts: u32,
    },
}

#[derive(Debug, Deserialize)]
enum CompilerAbiPrimitive {
    Felt,
    Bool,
    U32,
    Hash,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CompilerAbiMapKind {
    ContractHashMap,
    Map,
    NamespacedMap,
}

/// Common public transition interface shared by a base layout batch and a
/// recursively aggregated layout proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutAppendPublicInputs<Hash> {
    pub contract_id: u64,
    pub layout_version: u16,
    pub old_layout_root: Hash,
    pub old_layout_field_count: u64,
    pub old_layout_slot_count: u64,
    pub new_layout_root: Hash,
    pub new_layout_field_count: u64,
    pub new_layout_slot_count: u64,
    pub appended_field_count: u64,
    pub appended_fields_commitment: Hash,
}

/// Public endpoint shared by every recursively composable type-layout proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeLayoutProofPublicInputs<Hash> {
    pub type_layout_hash: Hash,
    pub total_slot_count: u64,
}

/// Witness for one fixed-size Spiderman append window.
///
/// `appended_fields` contains only the newly occupied suffix entries. The
/// remaining positions are reconstructed as zero leaves and committed by the
/// proof, so a sudden large append is represented as several such batches and
/// then aggregated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutAppendBatchWitness<Hash> {
    pub spiderman_update_proof: SpidermanUpdateProof<Hash>,
    pub appended_fields: Vec<StateFieldLayoutLeaf<Hash>>,
    pub appended_type_layouts: Vec<StateTypeLayoutWitness<Hash>>,
    /// Serialized canonical wrapper proofs, one per appended field. Proof
    /// decoding is circuit-config specific and is performed by the prover
    /// boundary before setting `StateLayoutAppendWithTypeProofsGadget`.
    pub canonical_type_proofs: Vec<Vec<u8>>,
    pub public_inputs: LayoutAppendPublicInputs<Hash>,
}

impl<Hash: Copy> LayoutAppendBatchWitness<Hash> {
    pub fn validate<Hasher, F>(&self) -> anyhow::Result<()>
    where
        Hasher: FieldQHasher<F, Hash> + MerkleHasher<Hash>,
        F: QFelt64,
        Hash: QFHashBase<F> + Default + PartialEq,
    {
        self.public_inputs.validate_shape()?;
        anyhow::ensure!(
            self.spiderman_update_proof.verify::<Hasher>(),
            "invalid layout Spiderman update proof"
        );

        let old_leaves = &self.spiderman_update_proof.web_proof_old_leaves;
        let new_leaves = &self.spiderman_update_proof.web_proof_new_leaves;
        anyhow::ensure!(
            old_leaves.len() == new_leaves.len()
                && !old_leaves.is_empty()
                && old_leaves.len().is_power_of_two(),
            "layout append window must be a non-empty power of two"
        );
        anyhow::ensure!(
            self.appended_fields.len() as u64
                == self.public_inputs.appended_field_count,
            "appended field witness length does not match public inputs"
        );
        anyhow::ensure!(
            self.appended_fields.len() == self.appended_type_layouts.len(),
            "every appended field must have one canonical type-layout witness"
        );
        anyhow::ensure!(
            self.appended_fields.len() == self.canonical_type_proofs.len(),
            "every appended field must have one canonical type proof"
        );
        anyhow::ensure!(
            self.canonical_type_proofs
                .iter()
                .all(|proof| !proof.is_empty()),
            "canonical type proof bytes cannot be empty"
        );

        let old_prefix_len = old_leaves
            .iter()
            .take_while(|hash| **hash != Hash::default())
            .count();
        let window_start = self
            .spiderman_update_proof
            .top_line_proof
            .index
            .checked_mul(old_leaves.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("layout window index overflow"))?;
        anyhow::ensure!(
            self.public_inputs.old_layout_field_count
                == window_start
                    .checked_add(old_prefix_len as u64)
                    .ok_or_else(|| anyhow::anyhow!(
                        "layout field frontier overflow"
                    ))?,
            "old layout field count is not the selected append frontier"
        );

        let mut next_slot = self.public_inputs.old_layout_slot_count;
        let mut fixed_batch_hashes = vec![Hash::default(); old_leaves.len()];
        for (index, (&old_hash, &new_hash)) in
            old_leaves.iter().zip(new_leaves).enumerate()
        {
            if index < old_prefix_len {
                anyhow::ensure!(
                    old_hash == new_hash,
                    "existing layout field {index} was modified"
                );
                continue;
            }

            let appended_index = index - old_prefix_len;
            if let Some(field) = self.appended_fields.get(appended_index) {
                self.appended_type_layouts[appended_index]
                    .validate_field::<Hasher, F>(field)?;
                anyhow::ensure!(
                    old_hash == Hash::default(),
                    "append position {index} was already occupied"
                );
                let expected_field_id = window_start
                    .checked_add(index as u64)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| anyhow::anyhow!(
                        "layout field id overflow"
                    ))?;
                anyhow::ensure!(
                    field.field_id == expected_field_id,
                    "appended field id is not contiguous"
                );
                anyhow::ensure!(
                    field.start_slot == next_slot,
                    "appended field slot range is not contiguous"
                );
                let field_hash = field.hash::<Hasher, F>()?;
                anyhow::ensure!(
                    new_hash == field_hash,
                    "new layout leaf does not match appended field"
                );
                fixed_batch_hashes[index] = field_hash;
                next_slot = next_slot
                    .checked_add(field.slot_count)
                    .ok_or_else(|| anyhow::anyhow!(
                        "layout slot frontier overflow"
                    ))?;
            } else {
                anyhow::ensure!(
                    old_hash == Hash::default()
                        && new_hash == Hash::default(),
                    "layout append has an uncommitted changed position"
                );
            }
        }

        anyhow::ensure!(
            self.public_inputs.old_layout_root
                == self.spiderman_update_proof.top_line_proof.old_root
                && self.public_inputs.new_layout_root
                    == self.spiderman_update_proof.top_line_proof.new_root,
            "layout roots do not match Spiderman proof"
        );
        anyhow::ensure!(
            self.public_inputs.new_layout_slot_count == next_slot,
            "new layout slot count does not match appended fields"
        );
        let expected_commitment =
            compute_layout_batch_commitment::<Hasher, F, Hash>(
                self.public_inputs.contract_id,
                self.public_inputs.old_layout_field_count,
                self.public_inputs.old_layout_slot_count,
                self.appended_fields.len(),
                &fixed_batch_hashes,
            )?;
        anyhow::ensure!(
            self.public_inputs.appended_fields_commitment
                == expected_commitment,
            "appended fields commitment mismatch"
        );
        Ok(())
    }
}

impl<Hash: PartialEq> LayoutAppendPublicInputs<Hash> {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.layout_version == STATE_LAYOUT_VERSION,
            "unsupported layout version {}",
            self.layout_version
        );
        anyhow::ensure!(
            self.new_layout_field_count
                == self
                    .old_layout_field_count
                    .checked_add(self.appended_field_count)
                    .ok_or_else(|| anyhow::anyhow!(
                        "layout field count overflow"
                    ))?,
            "layout field-count transition does not match appended count"
        );
        anyhow::ensure!(
            self.new_layout_slot_count >= self.old_layout_slot_count,
            "layout slot count cannot decrease"
        );
        if self.appended_field_count == 0 {
            anyhow::ensure!(
                self.old_layout_root == self.new_layout_root,
                "identity layout transition must preserve the root"
            );
            anyhow::ensure!(
                self.old_layout_slot_count == self.new_layout_slot_count,
                "identity layout transition must preserve slot count"
            );
        }
        Ok(())
    }
}

pub fn compute_layout_batch_commitment<Hasher, F, Hash>(
    contract_id: u64,
    old_layout_field_count: u64,
    old_layout_slot_count: u64,
    appended_field_count: usize,
    fixed_batch_field_hashes: &[Hash],
) -> anyhow::Result<Hash>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    anyhow::ensure!(
        appended_field_count <= fixed_batch_field_hashes.len(),
        "appended field count exceeds fixed batch size"
    );
    let committed_field_count = fixed_batch_field_hashes
        .iter()
        .filter(|hash| **hash != Hash::default())
        .count();
    anyhow::ensure!(
        committed_field_count == appended_field_count,
        "batch commitment contains {committed_field_count} non-zero field hashes, expected {appended_field_count}"
    );
    let mut felts =
        Vec::with_capacity(5 + fixed_batch_field_hashes.len() * 4);
    felts.push(F::from_u64_value(STATE_LAYOUT_APPEND_BATCH_DOMAIN));
    felts.push(F::from_u64_value(contract_id));
    felts.push(F::from_u64_value(old_layout_field_count));
    felts.push(F::from_u64_value(old_layout_slot_count));
    felts.push(F::from_u64_value(appended_field_count as u64));
    for hash in fixed_batch_field_hashes {
        felts.extend(hash.to_4_felts());
    }
    Ok(Hasher::q_hash_many(&felts))
}

pub fn aggregate_layout_transitions<Hasher, F, Hash>(
    left: LayoutAppendPublicInputs<Hash>,
    right: LayoutAppendPublicInputs<Hash>,
) -> anyhow::Result<LayoutAppendPublicInputs<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    left.validate_shape()?;
    right.validate_shape()?;
    anyhow::ensure!(
        left.contract_id == right.contract_id,
        "cannot aggregate layout proofs for different contracts"
    );
    anyhow::ensure!(
        left.layout_version == right.layout_version,
        "cannot aggregate different layout versions"
    );
    anyhow::ensure!(
        left.new_layout_root == right.old_layout_root,
        "layout roots are not continuous"
    );
    anyhow::ensure!(
        left.new_layout_field_count == right.old_layout_field_count,
        "layout field counts are not continuous"
    );
    anyhow::ensure!(
        left.new_layout_slot_count == right.old_layout_slot_count,
        "layout slot counts are not continuous"
    );
    let appended_field_count = left
        .appended_field_count
        .checked_add(right.appended_field_count)
        .ok_or_else(|| anyhow::anyhow!("aggregated field count overflow"))?;
    let left_commitment = left.appended_fields_commitment.to_4_felts();
    let right_commitment = right.appended_fields_commitment.to_4_felts();
    let appended_fields_commitment = Hasher::q_hash_many(&[
        F::from_u64_value(STATE_LAYOUT_APPEND_AGG_DOMAIN),
        left_commitment[0],
        left_commitment[1],
        left_commitment[2],
        left_commitment[3],
        F::from_u64_value(left.appended_field_count),
        right_commitment[0],
        right_commitment[1],
        right_commitment[2],
        right_commitment[3],
        F::from_u64_value(right.appended_field_count),
    ]);
    let parent = LayoutAppendPublicInputs {
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
    };
    parent.validate_shape()?;
    Ok(parent)
}

/// Bind a verified (possibly recursively aggregated) layout transition to the
/// old and new contract leaves that are committed by the contract tree.
///
/// Code and function roots are intentionally not compared here: changing
/// those roots is the purpose of a contract update. The deployer and storage
/// tree height remain immutable, while every layout endpoint must exactly
/// match the proof's public inputs.
pub fn validate_contract_layout_transition<F, Hash>(
    contract_id: u64,
    old_leaf: &PQEDContractLeafV2<F, Hash>,
    new_leaf: &PQEDContractLeafV2<F, Hash>,
    transition: &LayoutAppendPublicInputs<Hash>,
) -> anyhow::Result<()>
where
    F: QFelt64,
    Hash: Copy + PartialEq,
{
    transition.validate_shape()?;
    anyhow::ensure!(
        transition.contract_id == contract_id,
        "layout transition belongs to contract {}, expected {contract_id}",
        transition.contract_id
    );
    anyhow::ensure!(
        old_leaf.deployer == new_leaf.deployer,
        "contract deployer cannot change during update"
    );
    anyhow::ensure!(
        old_leaf.state_tree_height == new_leaf.state_tree_height,
        "contract state tree height cannot change during update"
    );
    anyhow::ensure!(
        old_leaf.state_layout_root == transition.old_layout_root
            && new_leaf.state_layout_root == transition.new_layout_root,
        "contract leaf layout roots do not match transition endpoints"
    );
    anyhow::ensure!(
        old_leaf.state_layout_field_count.to_u64_value()
            == transition.old_layout_field_count
            && new_leaf.state_layout_field_count.to_u64_value()
                == transition.new_layout_field_count,
        "contract leaf layout field counts do not match transition endpoints"
    );
    anyhow::ensure!(
        old_leaf.state_layout_slot_count.to_u64_value()
            == transition.old_layout_slot_count
            && new_leaf.state_layout_slot_count.to_u64_value()
                == transition.new_layout_slot_count,
        "contract leaf layout slot counts do not match transition endpoints"
    );

    let state_tree_height = old_leaf.state_tree_height.to_u64_value();
    if state_tree_height < u64::BITS as u64 {
        // Each state-tree leaf stores four felts (a Hash).
        let capacity = (1u64 << state_tree_height) * 4;
        anyhow::ensure!(
            transition.new_layout_slot_count <= capacity,
            "layout uses {} slots but state tree height {} has capacity {}",
            transition.new_layout_slot_count,
            state_tree_height,
            capacity
        );
    }
    Ok(())
}

fn checked_capacity(tree_height: usize) -> anyhow::Result<usize> {
    1usize
        .checked_shl(u32::try_from(tree_height)?)
        .ok_or_else(|| anyhow::anyhow!("layout tree height {tree_height} exceeds usize capacity"))
}

fn padded_merkle_root<Hasher, Hash>(
    occupied_leaves: &[Hash],
    tree_height: usize,
) -> anyhow::Result<Hash>
where
    Hasher: MerkleLeafHasher<Hash>,
    Hash: Copy + Default,
{
    let capacity = checked_capacity(tree_height)?;
    anyhow::ensure!(
        occupied_leaves.len() <= capacity,
        "{} occupied leaves exceed tree capacity {}",
        occupied_leaves.len(),
        capacity
    );
    let mut leaves = vec![Hash::default(); capacity];
    leaves[..occupied_leaves.len()].copy_from_slice(occupied_leaves);
    Hasher::compute_root_from_leaves(&leaves)
}

pub fn primitive_type_layout<Hasher, F, Hash>(
    type_tag: StatePrimitiveTypeTag,
    canonical_slot_width: u64,
) -> anyhow::Result<StateTypeLayoutSummary<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: Copy + Default + PartialEq,
{
    let expected_slot_width = canonical_primitive_slot_width(type_tag);
    anyhow::ensure!(
        canonical_slot_width == expected_slot_width,
        "primitive {:?} occupies {} slots, not {}",
        type_tag,
        expected_slot_width,
        canonical_slot_width
    );
    let type_layout_hash = Hasher::q_hash_many(&[
        F::from_u64_value(PRIMITIVE_TYPE_LAYOUT_DOMAIN),
        F::from_u64_value(type_tag as u16 as u64),
        F::from_u64_value(STATE_LAYOUT_ENCODING_VERSION as u64),
    ]);
    anyhow::ensure!(type_layout_hash != Hash::default(), "primitive type hashes to zero");
    Ok(StateTypeLayoutSummary {
        type_layout_hash,
        total_slot_count: canonical_slot_width,
    })
}

pub fn fixed_array_type_layout<Hasher, F, Hash>(
    element: StateTypeLayoutSummary<Hash>,
    array_length: u64,
) -> anyhow::Result<StateTypeLayoutSummary<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    anyhow::ensure!(array_length > 0, "fixed array length must be non-zero");
    anyhow::ensure!(element.total_slot_count > 0, "fixed array element must occupy slots");
    let total_slot_count = array_length
        .checked_mul(element.total_slot_count)
        .ok_or_else(|| anyhow::anyhow!("fixed array slot count overflow"))?;
    let element_hash = element.type_layout_hash.to_4_felts();
    let type_layout_hash = Hasher::q_hash_many(&[
        F::from_u64_value(FIXED_ARRAY_TYPE_LAYOUT_DOMAIN),
        element_hash[0],
        element_hash[1],
        element_hash[2],
        element_hash[3],
        F::from_u64_value(array_length),
        F::from_u64_value(element.total_slot_count),
        F::from_u64_value(total_slot_count),
        F::from_u64_value(STATE_LAYOUT_ENCODING_VERSION as u64),
    ]);
    anyhow::ensure!(type_layout_hash != Hash::default(), "fixed array type hashes to zero");
    Ok(StateTypeLayoutSummary {
        type_layout_hash,
        total_slot_count,
    })
}

pub fn fixed_map_type_layout<Hasher, F, Hash>(
    map_kind: StateMapKind,
    key: StateTypeLayoutSummary<Hash>,
    value: StateTypeLayoutSummary<Hash>,
    capacity: u64,
    alignment_slots: u64,
) -> anyhow::Result<StateTypeLayoutSummary<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    anyhow::ensure!(capacity > 0, "fixed map capacity must be non-zero");
    anyhow::ensure!(
        alignment_slots > 0 && alignment_slots.is_power_of_two(),
        "fixed map alignment must be a non-zero power of two"
    );
    let total_slot_count = capacity
        .checked_mul(value.total_slot_count)
        .ok_or_else(|| anyhow::anyhow!("fixed map slot count overflow"))?;
    let key_hash = key.type_layout_hash.to_4_felts();
    let value_hash = value.type_layout_hash.to_4_felts();
    let type_layout_hash = Hasher::q_hash_many(&[
        F::from_u64_value(FIXED_MAP_TYPE_LAYOUT_DOMAIN),
        F::from_u64_value(map_kind as u16 as u64),
        key_hash[0],
        key_hash[1],
        key_hash[2],
        key_hash[3],
        F::from_u64_value(key.total_slot_count),
        value_hash[0],
        value_hash[1],
        value_hash[2],
        value_hash[3],
        F::from_u64_value(value.total_slot_count),
        F::from_u64_value(capacity),
        F::from_u64_value(alignment_slots),
        F::from_u64_value(total_slot_count),
        F::from_u64_value(STATE_LAYOUT_ENCODING_VERSION as u64),
    ]);
    anyhow::ensure!(
        type_layout_hash != Hash::default(),
        "fixed map type hashes to zero"
    );
    Ok(StateTypeLayoutSummary {
        type_layout_hash,
        total_slot_count,
    })
}

pub fn struct_type_layout<Hasher, F, Hash>(
    member_types: &[StateTypeLayoutSummary<Hash>],
    members_tree_height: usize,
) -> anyhow::Result<StructTypeLayout<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    anyhow::ensure!(!member_types.is_empty(), "empty structs are not supported");
    let capacity = checked_capacity(members_tree_height)?;
    anyhow::ensure!(
        member_types.len() <= capacity,
        "{} struct members exceed members-tree capacity {}",
        member_types.len(),
        capacity
    );

    let mut slot_offset = 0u64;
    let mut members = Vec::with_capacity(member_types.len());
    let mut hashes = Vec::with_capacity(member_types.len());
    for (index, member_type) in member_types.iter().copied().enumerate() {
        let member = StructMemberLayout::new(index, slot_offset, member_type)?;
        hashes.push(member.hash::<Hasher, F>()?);
        slot_offset = slot_offset
            .checked_add(member.slot_count)
            .ok_or_else(|| anyhow::anyhow!("struct slot count overflow"))?;
        members.push(member);
    }

    let members_root = padded_merkle_root::<Hasher, Hash>(&hashes, members_tree_height)?;
    let members_root_felts = members_root.to_4_felts();
    let type_layout_hash = Hasher::q_hash_many(&[
        F::from_u64_value(STRUCT_TYPE_LAYOUT_DOMAIN),
        F::from_u64_value(members.len() as u64),
        F::from_u64_value(slot_offset),
        members_root_felts[0],
        members_root_felts[1],
        members_root_felts[2],
        members_root_felts[3],
        F::from_u64_value(STATE_LAYOUT_ENCODING_VERSION as u64),
    ]);
    anyhow::ensure!(type_layout_hash != Hash::default(), "struct type hashes to zero");

    Ok(StructTypeLayout {
        members,
        members_root,
        summary: StateTypeLayoutSummary {
            type_layout_hash,
            total_slot_count: slot_offset,
        },
    })
}

pub fn contract_state_layout<Hasher, F, Hash>(
    field_types: &[StateTypeLayoutSummary<Hash>],
    state_layout_tree_height: usize,
    state_tree_height: usize,
) -> anyhow::Result<ContractStateLayout<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    contract_state_layout_with_payload_offsets::<Hasher, F, Hash>(
        field_types,
        &vec![0; field_types.len()],
        state_layout_tree_height,
        state_tree_height,
    )
}

pub fn contract_state_layout_with_payload_offsets<Hasher, F, Hash>(
    field_types: &[StateTypeLayoutSummary<Hash>],
    payload_offsets: &[u64],
    state_layout_tree_height: usize,
    state_tree_height: usize,
) -> anyhow::Result<ContractStateLayout<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    anyhow::ensure!(
        field_types.len() == payload_offsets.len(),
        "field types and payload offsets length mismatch"
    );
    // Each state-tree leaf stores four felts (a Hash), so capacity in
    // sub-slots is 4 * 2^height.
    let state_capacity = (1u128
        .checked_shl(u32::try_from(state_tree_height)?)
        .ok_or_else(|| anyhow::anyhow!("state tree height {state_tree_height} exceeds u128 capacity"))?)
        .checked_mul(4)
        .ok_or_else(|| anyhow::anyhow!("contract state capacity overflow"))?;

    let mut start_slot = 0u64;
    let mut fields = Vec::with_capacity(field_types.len());
    let mut hashes = Vec::with_capacity(field_types.len());
    for (index, (field_type, payload_offset)) in field_types
        .iter()
        .copied()
        .zip(payload_offsets.iter().copied())
        .enumerate()
    {
        let field = StateFieldLayoutLeaf::new_with_payload_offset(
            index,
            start_slot,
            payload_offset,
            field_type,
        )?;
        hashes.push(field.hash::<Hasher, F>()?);
        start_slot = start_slot
            .checked_add(field.slot_count)
            .ok_or_else(|| anyhow::anyhow!("contract state slot count overflow"))?;
        fields.push(field);
    }
    anyhow::ensure!(
        u128::from(start_slot) <= state_capacity,
        "contract layout uses {} slots but state tree capacity is {}",
        start_slot,
        state_capacity
    );

    let state_layout_root =
        padded_merkle_root::<Hasher, Hash>(&hashes, state_layout_tree_height)?;
    Ok(ContractStateLayout {
        fields,
        state_layout_root,
        state_layout_field_count: u64::try_from(field_types.len())?,
        state_layout_slot_count: start_slot,
    })
}

fn primitive_from_abi_name<Hasher, F, Hash>(
    name: &str,
) -> anyhow::Result<Option<StateTypeLayoutSummary<Hash>>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: Copy + Default + PartialEq,
{
    let tag = match name {
        "Felt" => StatePrimitiveTypeTag::Felt,
        "Bool" | "bool" => StatePrimitiveTypeTag::Bool,
        "U32" | "u32" => StatePrimitiveTypeTag::U32,
        "Hash" => {
            return Ok(Some(primitive_type_layout::<Hasher, F, Hash>(
                StatePrimitiveTypeTag::Hash,
                4,
            )?));
        }
        _ => return Ok(None),
    };
    Ok(Some(primitive_type_layout::<Hasher, F, Hash>(
        tag, 1,
    )?))
}

fn find_abi_struct<'a>(
    abi: &'a QContractABI,
    name: &str,
) -> anyhow::Result<&'a StructAbiSpec> {
    abi.structs
        .iter()
        .find(|item| item.name == name)
        .ok_or_else(|| anyhow::anyhow!("ABI struct '{name}' not found"))
}

fn build_abi_type_layout<Hasher, F, Hash>(
    abi: &QContractABI,
    type_spec: &TypeAbiSpec,
    members_tree_height: usize,
    cache: &mut BTreeMap<String, StructTypeLayout<Hash>>,
    visiting: &mut HashSet<String>,
) -> anyhow::Result<StateTypeLayoutSummary<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    match type_spec {
        TypeAbiSpec::Basic(name) => {
            if let Some(primitive) =
                primitive_from_abi_name::<Hasher, F, Hash>(name)?
            {
                return Ok(primitive);
            }
            if let Some(cached) = cache.get(name) {
                return Ok(cached.summary);
            }
            anyhow::ensure!(
                visiting.insert(name.clone()),
                "recursive inline ABI type '{name}' is not supported"
            );
            let struct_spec = find_abi_struct(abi, name)?;
            let member_types = struct_spec
                .fields
                .iter()
                .map(|field| {
                    build_abi_type_layout::<Hasher, F, Hash>(
                        abi,
                        &field.field_type,
                        members_tree_height,
                        cache,
                        visiting,
                    )
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let layout = struct_type_layout::<Hasher, F, Hash>(
                &member_types,
                members_tree_height,
            )?;
            visiting.remove(name);
            cache.insert(name.clone(), layout.clone());
            Ok(layout.summary)
        }
        TypeAbiSpec::Array {
            inner_type,
            length,
            ..
        } => {
            let element = build_abi_type_layout::<Hasher, F, Hash>(
                abi,
                &TypeAbiSpec::Basic(inner_type.clone()),
                members_tree_height,
                cache,
                visiting,
            )?;
            fixed_array_type_layout::<Hasher, F, Hash>(
                element,
                u64::from(*length),
            )
        }
    }
}

fn abi_type_layout_witness<Hasher, F, Hash>(
    abi: &QContractABI,
    type_spec: &TypeAbiSpec,
    members_tree_height: usize,
    cache: &mut BTreeMap<String, StructTypeLayout<Hash>>,
) -> anyhow::Result<StateTypeLayoutWitness<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    match type_spec {
        TypeAbiSpec::Basic(name) => {
            let primitive_tag = match name.as_str() {
                "Felt" => Some(StatePrimitiveTypeTag::Felt),
                "Bool" | "bool" => Some(StatePrimitiveTypeTag::Bool),
                "U32" | "u32" => Some(StatePrimitiveTypeTag::U32),
                "Hash" => Some(StatePrimitiveTypeTag::Hash),
                _ => None,
            };
            if let Some(type_tag) = primitive_tag {
                return Ok(StateTypeLayoutWitness::Primitive { type_tag });
            }
            if !cache.contains_key(name) {
                build_abi_type_layout::<Hasher, F, Hash>(
                    abi,
                    type_spec,
                    members_tree_height,
                    cache,
                    &mut HashSet::new(),
                )?;
            }
            let layout = cache.get(name).ok_or_else(|| {
                anyhow::anyhow!("ABI struct layout '{name}' was not built")
            })?;
            Ok(StateTypeLayoutWitness::Struct {
                member_count: u64::try_from(layout.members.len())?,
                total_slot_count: layout.summary.total_slot_count,
                members_root: layout.members_root,
            })
        }
        TypeAbiSpec::Array {
            inner_type,
            length,
            ..
        } => {
            let element_spec = TypeAbiSpec::Basic(inner_type.clone());
            let mut visiting = HashSet::new();
            let element =
                build_abi_type_layout::<Hasher, F, Hash>(
                    abi,
                    &element_spec,
                    members_tree_height,
                    cache,
                    &mut visiting,
                )?;
            Ok(StateTypeLayoutWitness::FixedArray {
                element_type_hash: element.type_layout_hash,
                element_slot_count: element.total_slot_count,
                array_length: u64::from(*length),
            })
        }
    }
}

/// Deterministically derives the consensus field-oriented layout from the
/// existing compiler ABI representation.
pub fn contract_state_layout_from_abi<Hasher, F, Hash>(
    abi: &QContractABI,
    state_layout_tree_height: usize,
    members_tree_height: usize,
    state_tree_height: usize,
) -> anyhow::Result<CanonicalContractStateLayout<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    let contract = abi.get_contract_struct()?;
    let mut cache = BTreeMap::new();
    let mut visiting = HashSet::new();
    visiting.insert(contract.name.clone());
    let field_types = contract
        .fields
        .iter()
        .map(|field| {
            build_abi_type_layout::<Hasher, F, Hash>(
                abi,
                &field.field_type,
                members_tree_height,
                &mut cache,
                &mut visiting,
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    visiting.remove(&contract.name);

    // Archive the contract struct's own members root as well as nested types.
    let contract_struct_layout = struct_type_layout::<Hasher, F, Hash>(
        &field_types,
        members_tree_height,
    )?;
    cache.insert(contract.name.clone(), contract_struct_layout);

    let contract_layout = contract_state_layout::<Hasher, F, Hash>(
        &field_types,
        state_layout_tree_height,
        state_tree_height,
    )?;
    let field_type_layouts = contract
        .fields
        .iter()
        .map(|field| {
            abi_type_layout_witness::<Hasher, F, Hash>(
                abi,
                &field.field_type,
                members_tree_height,
                &mut cache,
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(CanonicalContractStateLayout {
        contract_layout,
        field_type_layouts,
        struct_layouts: cache,
    })
}

fn build_compiler_abi_type_layout<Hasher, F, Hash>(
    ty: &CompilerAbiTypeRef,
    definitions: &BTreeMap<String, &CompilerAbiStruct>,
    members_tree_height: usize,
    cache: &mut BTreeMap<String, StructTypeLayout<Hash>>,
    visiting: &mut HashSet<String>,
) -> anyhow::Result<StateTypeLayoutSummary<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    match ty {
        CompilerAbiTypeRef::Primitive { name } => {
            let (tag, width) = match name {
                CompilerAbiPrimitive::Felt => {
                    (StatePrimitiveTypeTag::Felt, 1)
                }
                CompilerAbiPrimitive::Bool => {
                    (StatePrimitiveTypeTag::Bool, 1)
                }
                CompilerAbiPrimitive::U32 => {
                    (StatePrimitiveTypeTag::U32, 1)
                }
                CompilerAbiPrimitive::Hash => {
                    (StatePrimitiveTypeTag::Hash, 4)
                }
            };
            primitive_type_layout::<Hasher, F, Hash>(tag, width)
        }
        CompilerAbiTypeRef::Struct { name } => {
            if let Some(layout) = cache.get(name) {
                return Ok(layout.summary);
            }
            anyhow::ensure!(
                visiting.insert(name.clone()),
                "recursive compiler ABI struct '{name}' is not supported"
            );
            let definition = definitions.get(name).ok_or_else(|| {
                anyhow::anyhow!("compiler ABI struct '{name}' not found")
            })?;
            let mut member_types =
                Vec::with_capacity(definition.fields.len());
            let mut next_offset = 0u64;
            for member in &definition.fields {
                anyhow::ensure!(
                    member.offset_within_parent == next_offset,
                    "compiler ABI struct '{name}' has a non-contiguous member offset"
                );
                let member_type =
                    build_compiler_abi_type_layout::<Hasher, F, Hash>(
                        &member.ty,
                        definitions,
                        members_tree_height,
                        cache,
                        visiting,
                    )?;
                anyhow::ensure!(
                    member_type.total_slot_count == member.felt_size,
                    "compiler ABI struct '{name}' member size does not match its type"
                );
                next_offset = next_offset
                    .checked_add(member.felt_size)
                    .ok_or_else(|| anyhow::anyhow!(
                        "compiler ABI struct slot count overflow"
                    ))?;
                member_types.push(member_type);
            }
            let layout = struct_type_layout::<Hasher, F, Hash>(
                &member_types,
                members_tree_height,
            )?;
            visiting.remove(name);
            cache.insert(name.clone(), layout.clone());
            Ok(layout.summary)
        }
        CompilerAbiTypeRef::Array {
            item,
            length,
            item_felt_size,
        } => {
            let item_layout =
                build_compiler_abi_type_layout::<Hasher, F, Hash>(
                    item,
                    definitions,
                    members_tree_height,
                    cache,
                    visiting,
                )?;
            anyhow::ensure!(
                item_layout.total_slot_count == *item_felt_size,
                "compiler ABI array item size does not match its type"
            );
            fixed_array_type_layout::<Hasher, F, Hash>(
                item_layout,
                u64::from(*length),
            )
        }
        CompilerAbiTypeRef::Map {
            map_kind,
            key,
            value,
            capacity,
            value_felt_size,
            alignment_felts,
        } => {
            let key_layout =
                build_compiler_abi_type_layout::<Hasher, F, Hash>(
                    key,
                    definitions,
                    members_tree_height,
                    cache,
                    visiting,
                )?;
            let value_layout =
                build_compiler_abi_type_layout::<Hasher, F, Hash>(
                    value,
                    definitions,
                    members_tree_height,
                    cache,
                    visiting,
                )?;
            anyhow::ensure!(
                value_layout.total_slot_count
                    == u64::try_from(*value_felt_size)?,
                "compiler ABI map value size does not match its type"
            );
            let kind = match map_kind {
                CompilerAbiMapKind::ContractHashMap => {
                    StateMapKind::ContractHashMap
                }
                CompilerAbiMapKind::Map => StateMapKind::Map,
                CompilerAbiMapKind::NamespacedMap => {
                    StateMapKind::NamespacedMap
                }
            };
            fixed_map_type_layout::<Hasher, F, Hash>(
                kind,
                key_layout,
                value_layout,
                u64::try_from(*capacity)?,
                u64::from(*alignment_felts),
            )
        }
    }
}

fn compiler_abi_type_layout_witness<Hasher, F, Hash>(
    ty: &CompilerAbiTypeRef,
    definitions: &BTreeMap<String, &CompilerAbiStruct>,
    members_tree_height: usize,
    cache: &mut BTreeMap<String, StructTypeLayout<Hash>>,
) -> anyhow::Result<StateTypeLayoutWitness<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    match ty {
        CompilerAbiTypeRef::Primitive { name } => {
            let type_tag = match name {
                CompilerAbiPrimitive::Felt => StatePrimitiveTypeTag::Felt,
                CompilerAbiPrimitive::Bool => StatePrimitiveTypeTag::Bool,
                CompilerAbiPrimitive::U32 => StatePrimitiveTypeTag::U32,
                CompilerAbiPrimitive::Hash => StatePrimitiveTypeTag::Hash,
            };
            Ok(StateTypeLayoutWitness::Primitive { type_tag })
        }
        CompilerAbiTypeRef::Struct { name } => {
            if !cache.contains_key(name) {
                build_compiler_abi_type_layout::<Hasher, F, Hash>(
                    ty,
                    definitions,
                    members_tree_height,
                    cache,
                    &mut HashSet::new(),
                )?;
            }
            let layout = cache.get(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "compiler ABI struct layout '{name}' was not built"
                )
            })?;
            Ok(StateTypeLayoutWitness::Struct {
                member_count: u64::try_from(layout.members.len())?,
                total_slot_count: layout.summary.total_slot_count,
                members_root: layout.members_root,
            })
        }
        CompilerAbiTypeRef::Array { item, length, .. } => {
            let element =
                build_compiler_abi_type_layout::<Hasher, F, Hash>(
                    item,
                    definitions,
                    members_tree_height,
                    cache,
                    &mut HashSet::new(),
                )?;
            Ok(StateTypeLayoutWitness::FixedArray {
                element_type_hash: element.type_layout_hash,
                element_slot_count: element.total_slot_count,
                array_length: u64::from(*length),
            })
        }
        CompilerAbiTypeRef::Map {
            map_kind,
            key,
            value,
            capacity,
            alignment_felts,
            ..
        } => {
            let key_layout =
                build_compiler_abi_type_layout::<Hasher, F, Hash>(
                    key,
                    definitions,
                    members_tree_height,
                    cache,
                    &mut HashSet::new(),
                )?;
            let value_layout =
                build_compiler_abi_type_layout::<Hasher, F, Hash>(
                    value,
                    definitions,
                    members_tree_height,
                    cache,
                    &mut HashSet::new(),
                )?;
            let map_kind = match map_kind {
                CompilerAbiMapKind::ContractHashMap => {
                    StateMapKind::ContractHashMap
                }
                CompilerAbiMapKind::Map => StateMapKind::Map,
                CompilerAbiMapKind::NamespacedMap => {
                    StateMapKind::NamespacedMap
                }
            };
            Ok(StateTypeLayoutWitness::FixedMap {
                map_kind,
                key_type_hash: key_layout.type_layout_hash,
                key_slot_count: key_layout.total_slot_count,
                value_type_hash: value_layout.type_layout_hash,
                value_slot_count: value_layout.total_slot_count,
                capacity: u64::try_from(*capacity)?,
                alignment_slots: u64::from(*alignment_felts),
            })
        }
    }
}

fn compiler_abi_type_contains_map(
    ty: &CompilerAbiTypeRef,
    definitions: &BTreeMap<String, &CompilerAbiStruct>,
    visiting: &mut HashSet<String>,
) -> anyhow::Result<bool> {
    Ok(match ty {
        CompilerAbiTypeRef::Map { .. } => true,
        CompilerAbiTypeRef::Array { item, .. } => {
            compiler_abi_type_contains_map(item, definitions, visiting)?
        }
        CompilerAbiTypeRef::Struct { name } => {
            anyhow::ensure!(
                visiting.insert(name.clone()),
                "recursive compiler ABI struct '{name}' is not supported"
            );
            let definition = definitions.get(name).ok_or_else(|| {
                anyhow::anyhow!("compiler ABI struct '{name}' not found")
            })?;
            let contains = definition
                .fields
                .iter()
                .map(|member| {
                    compiler_abi_type_contains_map(
                        &member.ty,
                        definitions,
                        visiting,
                    )
                })
                .collect::<anyhow::Result<Vec<_>>>()?
                .into_iter()
                .any(|contains| contains);
            visiting.remove(name);
            contains
        }
        CompilerAbiTypeRef::Primitive { .. } => false,
    })
}

/// Consume the compiler's canonical ABI JSON and construct the consensus
/// layout commitments. Every compiler-supplied offset and slot count is
/// recomputed from the type graph before any root is returned.
pub fn contract_state_layout_from_compiler_abi_json<Hasher, F, Hash>(
    abi_json: &str,
    state_layout_tree_height: usize,
    members_tree_height: usize,
) -> anyhow::Result<CanonicalContractStateLayout<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    let abi: CompilerAbiDocument = serde_json::from_str(abi_json)?;
    let manifest = &abi.contract.state_layout;
    anyhow::ensure!(
        manifest.layout_version == STATE_LAYOUT_VERSION,
        "unsupported compiler state layout version {}",
        manifest.layout_version
    );
    anyhow::ensure!(
        manifest.encoding_version == STATE_LAYOUT_ENCODING_VERSION,
        "unsupported compiler state layout encoding {}",
        manifest.encoding_version
    );
    anyhow::ensure!(
        manifest.field_count == manifest.fields.len() as u64,
        "compiler state layout field count mismatch"
    );

    let definitions = abi
        .types
        .iter()
        .map(|definition| (definition.name.clone(), definition))
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        definitions.len() == abi.types.len(),
        "compiler ABI contains duplicate struct type names"
    );
    let mut cache = BTreeMap::new();
    let mut visiting = HashSet::new();
    let mut field_types = Vec::with_capacity(manifest.fields.len());
    let mut field_type_layouts =
        Vec::with_capacity(manifest.fields.len());
    let mut payload_offsets = Vec::with_capacity(manifest.fields.len());
    let mut next_slot = 0u64;
    for (index, field) in manifest.fields.iter().enumerate() {
        anyhow::ensure!(
            field.field_id == index as u64 + 1,
            "compiler layout field ids are not contiguous"
        );
        anyhow::ensure!(
            field.start_slot == next_slot,
            "compiler layout field slot ranges are not contiguous"
        );
        if !matches!(&field.ty, CompilerAbiTypeRef::Map { .. }) {
            anyhow::ensure!(
                !compiler_abi_type_contains_map(
                    &field.ty,
                    &definitions,
                    &mut HashSet::new(),
                )?,
                "state-layout protocol forbids aligned Map below a top-level field"
            );
        }
        let alignment = match &field.ty {
            CompilerAbiTypeRef::Map {
                alignment_felts, ..
            } => u64::from(*alignment_felts),
            _ => 1,
        };
        anyhow::ensure!(
            alignment > 0 && alignment.is_power_of_two(),
            "compiler layout field alignment is invalid"
        );
        let expected_payload_offset =
            (alignment - (field.start_slot % alignment)) % alignment;
        anyhow::ensure!(
            field.payload_offset == expected_payload_offset,
            "compiler layout field {} has incorrect alignment padding",
            field.field_id
        );
        let field_type =
            build_compiler_abi_type_layout::<Hasher, F, Hash>(
                &field.ty,
                &definitions,
                members_tree_height,
                &mut cache,
                &mut visiting,
            )?;
        let field_type_layout =
            compiler_abi_type_layout_witness::<Hasher, F, Hash>(
                &field.ty,
                &definitions,
                members_tree_height,
                &mut cache,
            )?;
        anyhow::ensure!(
            field_type
                .total_slot_count
                .checked_add(field.payload_offset)
                == Some(field.slot_count),
            "compiler layout field {} slot count does not match its type",
            field.field_id
        );
        next_slot = next_slot
            .checked_add(field.slot_count)
            .ok_or_else(|| anyhow::anyhow!(
                "compiler layout slot count overflow"
            ))?;
        field_types.push(field_type);
        field_type_layouts.push(field_type_layout);
        payload_offsets.push(field.payload_offset);
    }
    anyhow::ensure!(
        next_slot == manifest.slot_count,
        "compiler layout total slot count mismatch"
    );
    let contract_layout =
        contract_state_layout_with_payload_offsets::<Hasher, F, Hash>(
        &field_types,
        &payload_offsets,
        state_layout_tree_height,
        usize::from(abi.contract.state_tree_height),
    )?;
    anyhow::ensure!(
        contract_layout.state_layout_field_count == manifest.field_count
            && contract_layout.state_layout_slot_count
                == manifest.slot_count,
        "computed consensus layout does not match compiler manifest counts"
    );
    Ok(CanonicalContractStateLayout {
        contract_layout,
        field_type_layouts,
        struct_layouts: cache,
    })
}

fn append_compiler_abi_type_dag_node(
    ty: &CompilerAbiTypeRef,
    definitions: &BTreeMap<String, &CompilerAbiStruct>,
    members_tree_height: usize,
    visiting: &mut HashSet<String>,
    nodes: &mut Vec<CanonicalTypeLayoutNode>,
) -> anyhow::Result<u16> {
    let node = match ty {
        CompilerAbiTypeRef::Primitive { name } => {
            let type_tag = match name {
                CompilerAbiPrimitive::Felt => StatePrimitiveTypeTag::Felt,
                CompilerAbiPrimitive::Bool => StatePrimitiveTypeTag::Bool,
                CompilerAbiPrimitive::U32 => StatePrimitiveTypeTag::U32,
                CompilerAbiPrimitive::Hash => StatePrimitiveTypeTag::Hash,
            };
            CanonicalTypeLayoutNode::Primitive { type_tag }
        }
        CompilerAbiTypeRef::Array { item, length, .. } => {
            let element = append_compiler_abi_type_dag_node(
                item,
                definitions,
                members_tree_height,
                visiting,
                nodes,
            )?;
            CanonicalTypeLayoutNode::FixedArray {
                element,
                length: u64::from(*length),
            }
        }
        CompilerAbiTypeRef::Map {
            map_kind,
            key,
            value,
            capacity,
            alignment_felts,
            ..
        } => {
            let key = append_compiler_abi_type_dag_node(
                key,
                definitions,
                members_tree_height,
                visiting,
                nodes,
            )?;
            let value = append_compiler_abi_type_dag_node(
                value,
                definitions,
                members_tree_height,
                visiting,
                nodes,
            )?;
            let map_kind = match map_kind {
                CompilerAbiMapKind::ContractHashMap => {
                    StateMapKind::ContractHashMap
                }
                CompilerAbiMapKind::Map => StateMapKind::Map,
                CompilerAbiMapKind::NamespacedMap => {
                    StateMapKind::NamespacedMap
                }
            };
            CanonicalTypeLayoutNode::FixedMap {
                map_kind,
                key,
                value,
                capacity: u64::try_from(*capacity)?,
                alignment_slots: u64::from(*alignment_felts),
            }
        }
        CompilerAbiTypeRef::Struct { name } => {
            anyhow::ensure!(
                visiting.insert(name.clone()),
                "recursive compiler ABI struct '{name}' is not supported"
            );
            let definition = definitions.get(name).ok_or_else(|| {
                anyhow::anyhow!("compiler ABI struct '{name}' not found")
            })?;
            let members = definition
                .fields
                .iter()
                .map(|member| {
                    append_compiler_abi_type_dag_node(
                        &member.ty,
                        definitions,
                        members_tree_height,
                        visiting,
                        nodes,
                    )
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            visiting.remove(name);
            CanonicalTypeLayoutNode::Struct {
                members,
                members_tree_height: u8::try_from(
                    members_tree_height,
                )?,
            }
        }
    };
    let node_index = u16::try_from(nodes.len())?;
    nodes.push(node);
    Ok(node_index)
}

/// Converts the compiler ABI into one canonical type-layout DAG per
/// top-level state field.
///
/// Each DAG is self-contained and topologically ordered. Its evaluated
/// endpoint must match the corresponding field type summary returned by
/// [`contract_state_layout_from_compiler_abi_json`].
pub fn canonical_type_layout_dags_from_compiler_abi_json(
    abi_json: &str,
    members_tree_height: usize,
) -> anyhow::Result<Vec<CanonicalTypeLayoutDag>> {
    let abi: CompilerAbiDocument = serde_json::from_str(abi_json)?;
    let definitions = abi
        .types
        .iter()
        .map(|definition| (definition.name.clone(), definition))
        .collect::<BTreeMap<_, _>>();
    anyhow::ensure!(
        definitions.len() == abi.types.len(),
        "compiler ABI contains duplicate struct type names"
    );
    abi.contract
        .state_layout
        .fields
        .iter()
        .map(|field| {
            let mut nodes = Vec::new();
            let root = append_compiler_abi_type_dag_node(
                &field.ty,
                &definitions,
                members_tree_height,
                &mut HashSet::new(),
                &mut nodes,
            )?;
            let dag = CanonicalTypeLayoutDag { nodes, root };
            dag.validate_shape()?;
            Ok(dag)
        })
        .collect()
}

pub fn canonical_layout_manifest_from_compiler_abi_json<
    Hasher,
    F,
    Hash,
>(
    abi_json: &str,
    state_layout_tree_height: usize,
    members_tree_height: usize,
) -> anyhow::Result<CanonicalLayoutManifest<Hash>>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    let abi: CompilerAbiDocument = serde_json::from_str(abi_json)?;
    let layout =
        contract_state_layout_from_compiler_abi_json::<Hasher, F, Hash>(
            abi_json,
            state_layout_tree_height,
            members_tree_height,
        )?;
    let field_type_dags =
        canonical_type_layout_dags_from_compiler_abi_json(
            abi_json,
            members_tree_height,
        )?;
    anyhow::ensure!(
        field_type_dags.len() == layout.contract_layout.fields.len(),
        "canonical type DAG count does not match layout field count"
    );
    Ok(CanonicalLayoutManifest {
        layout_version: STATE_LAYOUT_VERSION,
        state_tree_height: abi.contract.state_tree_height,
        layout,
        field_type_dags,
    })
}

/// Recomputes and validates an append-only compiler ABI transition.
///
/// Existing field leaves, their physical slot ranges, and the contract state
/// tree height are immutable. Only a contiguous suffix may be introduced.
pub fn contract_state_layout_update_from_compiler_abi_json<
    Hasher,
    F,
    Hash,
>(
    old_abi_json: &str,
    new_abi_json: &str,
    state_layout_tree_height: usize,
    members_tree_height: usize,
) -> anyhow::Result<(
    CanonicalContractStateLayout<Hash>,
    CanonicalContractStateLayout<Hash>,
)>
where
    Hasher: FieldQHasher<F, Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + Default + PartialEq,
{
    let old_abi: CompilerAbiDocument =
        serde_json::from_str(old_abi_json)?;
    let new_abi: CompilerAbiDocument =
        serde_json::from_str(new_abi_json)?;
    anyhow::ensure!(
        old_abi.contract.state_tree_height
            == new_abi.contract.state_tree_height,
        "contract state tree height cannot change during layout update"
    );
    let old_layout =
        contract_state_layout_from_compiler_abi_json::<Hasher, F, Hash>(
            old_abi_json,
            state_layout_tree_height,
            members_tree_height,
        )?;
    let new_layout =
        contract_state_layout_from_compiler_abi_json::<Hasher, F, Hash>(
            new_abi_json,
            state_layout_tree_height,
            members_tree_height,
        )?;
    anyhow::ensure!(
        new_layout.contract_layout.fields.len()
            >= old_layout.contract_layout.fields.len(),
        "state layout fields cannot be removed"
    );
    anyhow::ensure!(
        new_layout.contract_layout.fields
            [..old_layout.contract_layout.fields.len()]
            == old_layout.contract_layout.fields,
        "existing state layout fields were modified or reordered"
    );
    anyhow::ensure!(
        new_layout.contract_layout.state_layout_slot_count
            >= old_layout.contract_layout.state_layout_slot_count,
        "state layout slot count cannot decrease"
    );
    Ok((old_layout, new_layout))
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use parth_core::{
        felt::FromPrimitiveValuesFelt,
        pgoldilocks::{PoseidonHasher, QHashOut},
        PF,
    };

    use super::*;

    #[test]
    fn builds_nested_field_oriented_layout() -> anyhow::Result<()> {
        let u64_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::U64,
                1,
            )?;
        let hash_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::Hash,
                4,
            )?;
        let account = struct_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
            &[u64_layout, u64_layout],
            2,
        )?;
        assert_eq!(account.members[0].slot_offset, 0);
        assert_eq!(account.members[1].slot_offset, 1);
        assert_eq!(account.summary.total_slot_count, 2);

        let history = fixed_array_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
            account.summary,
            8,
        )?;
        assert_eq!(history.total_slot_count, 16);

        let layout = contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
            &[hash_layout, account.summary, history],
            2,
            5,
        )?;
        assert_eq!(layout.state_layout_field_count, 3);
        assert_eq!(layout.state_layout_slot_count, 22);
        assert_eq!(layout.fields[0].start_slot, 0);
        assert_eq!(layout.fields[1].start_slot, 4);
        assert_eq!(layout.fields[2].start_slot, 6);
        Ok(())
    }

    #[test]
    fn rejects_layout_over_state_capacity() -> anyhow::Result<()> {
        let u64_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::U64,
                1,
            )?;
        let huge =
            fixed_array_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(u64_layout, 9)?;
        let error = contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
            &[huge],
            1,
            3,
        )
        .unwrap_err();
        assert!(error.to_string().contains("state tree capacity"));
        Ok(())
    }

    #[test]
    fn rejects_fixed_array_slot_overflow() -> anyhow::Result<()> {
        let u128_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::U128,
                2,
            )?;
        assert!(
            fixed_array_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                u128_layout,
                u64::MAX,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn v2_contract_leaf_felt_round_trip() {
        let leaf = PQEDContractLeafV2::<PF, QHashOut<PF>> {
            deployer: QHashOut::rand(),
            function_tree_root: QHashOut::rand(),
            code_root: QHashOut::rand(),
            state_tree_height: PF::from_u64_value(16),
            state_layout_root: QHashOut::rand(),
            state_layout_field_count: PF::from_u64_value(3),
            state_layout_slot_count: PF::from_u64_value(22),
        };
        let encoded: Vec<PF> =
            <PQEDContractLeafV2<PF, QHashOut<PF>> as ToQFelts<PF>>::to_qfelts(
                &leaf,
            );
        assert_eq!(encoded.len(), CONTRACT_LEAF_FELT_SIZE);
        assert_eq!(
            <PQEDContractLeafV2<PF, QHashOut<PF>> as ToQFelts<PF>>::from_qfelts(
                &encoded,
            ),
            leaf
        );

        let bytes = leaf.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), CONTRACT_LEAF_SERIALIZED_SIZE);
        assert_eq!(
            PQEDContractLeafV2::<PF, QHashOut<PF>>::
                fallback_psy_ser_from_slice(&bytes)
                .unwrap(),
            leaf
        );
    }

    #[test]
    fn aggregates_only_continuous_layout_transitions() -> anyhow::Result<()> {
        let root0 = QHashOut::rand();
        let root1 = QHashOut::rand();
        let root2 = QHashOut::rand();
        let left = LayoutAppendPublicInputs {
            contract_id: 7,
            layout_version: STATE_LAYOUT_VERSION,
            old_layout_root: root0,
            old_layout_field_count: 2,
            old_layout_slot_count: 5,
            new_layout_root: root1,
            new_layout_field_count: 3,
            new_layout_slot_count: 9,
            appended_field_count: 1,
            appended_fields_commitment: QHashOut::rand(),
        };
        let right = LayoutAppendPublicInputs {
            contract_id: 7,
            layout_version: STATE_LAYOUT_VERSION,
            old_layout_root: root1,
            old_layout_field_count: 3,
            old_layout_slot_count: 9,
            new_layout_root: root2,
            new_layout_field_count: 5,
            new_layout_slot_count: 12,
            appended_field_count: 2,
            appended_fields_commitment: QHashOut::rand(),
        };
        let parent =
            aggregate_layout_transitions::<PoseidonHasher, PF, QHashOut<PF>>(
                left, right,
            )?;
        assert_eq!(parent.old_layout_root, root0);
        assert_eq!(parent.new_layout_root, root2);
        assert_eq!(parent.appended_field_count, 3);

        let mut discontinuous = right;
        discontinuous.old_layout_field_count = 4;
        assert!(
            aggregate_layout_transitions::<PoseidonHasher, PF, QHashOut<PF>>(
                left,
                discontinuous,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn binds_transition_to_v2_leaf_endpoints_and_capacity(
    ) -> anyhow::Result<()> {
        let deployer: QHashOut<PF> = QHashOut::rand();
        let old_root = QHashOut::rand();
        let new_root = QHashOut::rand();
        let old_leaf = PQEDContractLeafV2 {
            deployer,
            function_tree_root: QHashOut::rand(),
            code_root: QHashOut::rand(),
            state_tree_height: PF::from_u64_value(3),
            state_layout_root: old_root,
            state_layout_field_count: PF::from_u64_value(1),
            state_layout_slot_count: PF::from_u64_value(2),
        };
        let mut new_leaf = PQEDContractLeafV2 {
            deployer,
            function_tree_root: QHashOut::rand(),
            code_root: QHashOut::rand(),
            state_tree_height: PF::from_u64_value(3),
            state_layout_root: new_root,
            state_layout_field_count: PF::from_u64_value(2),
            state_layout_slot_count: PF::from_u64_value(8),
        };
        let transition = LayoutAppendPublicInputs {
            contract_id: 11,
            layout_version: STATE_LAYOUT_VERSION,
            old_layout_root: old_root,
            old_layout_field_count: 1,
            old_layout_slot_count: 2,
            new_layout_root: new_root,
            new_layout_field_count: 2,
            new_layout_slot_count: 8,
            appended_field_count: 1,
            appended_fields_commitment: QHashOut::rand(),
        };
        validate_contract_layout_transition(
            11,
            &old_leaf,
            &new_leaf,
            &transition,
        )?;

        new_leaf.state_layout_slot_count = PF::from_u64_value(9);
        let mut oversized = transition;
        oversized.new_layout_slot_count = 9;
        assert!(
            validate_contract_layout_transition(
                11, &old_leaf, &new_leaf, &oversized,
            )
            .unwrap_err()
            .to_string()
            .contains("capacity")
        );
        Ok(())
    }

    #[test]
    fn validates_strict_layout_append_batch() -> anyhow::Result<()> {
        let tree_height = 5;
        let web_tree_height = 2;
        let u64_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::U64,
                1,
            )?;
        let old_layout =
            contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                &[u64_layout, u64_layout],
                tree_height,
                tree_height,
            )?;
        let new_layout =
            contract_state_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                &[u64_layout, u64_layout, u64_layout],
                tree_height,
                tree_height,
            )?;
        let mut tree =
            SimpleMerkleTree::<PoseidonHasher, QHashOut<PF>>::new(
                tree_height as u8,
            );
        for (index, field) in old_layout.fields.iter().enumerate() {
            tree.set_leaf(
                index as u64,
                field.hash::<PoseidonHasher, PF>()?,
            );
        }
        let appended_fields = new_layout.fields[2..].to_vec();
        let proof = tree
            .append_leaves_spider_man(
                web_tree_height,
                &[appended_fields[0].hash::<PoseidonHasher, PF>()?],
            )?
            .remove(0);
        let mut committed_hashes =
            vec![QHashOut::ZERO; proof.web_proof_new_leaves.len()];
        committed_hashes[2] =
            appended_fields[0].hash::<PoseidonHasher, PF>()?;
        let commitment =
            compute_layout_batch_commitment::<PoseidonHasher, PF, _>(
                19,
                old_layout.state_layout_field_count,
                old_layout.state_layout_slot_count,
                appended_fields.len(),
                &committed_hashes,
            )?;
        let witness = LayoutAppendBatchWitness {
            public_inputs: LayoutAppendPublicInputs {
                contract_id: 19,
                layout_version: STATE_LAYOUT_VERSION,
                old_layout_root: old_layout.state_layout_root,
                old_layout_field_count: 2,
                old_layout_slot_count: 2,
                new_layout_root: new_layout.state_layout_root,
                new_layout_field_count: 3,
                new_layout_slot_count: 3,
                appended_field_count: 1,
                appended_fields_commitment: commitment,
            },
            spiderman_update_proof: proof,
            appended_fields,
            appended_type_layouts: vec![
                StateTypeLayoutWitness::Primitive {
                    type_tag: StatePrimitiveTypeTag::U64,
                },
            ],
            canonical_type_proofs: vec![vec![1]],
        };
        witness.validate::<PoseidonHasher, PF>()?;

        let mut forged = witness;
        forged.appended_fields[0].start_slot = 7;
        assert!(forged.validate::<PoseidonHasher, PF>().is_err());
        Ok(())
    }

    #[test]
    fn derives_layout_from_existing_contract_abi() -> anyhow::Result<()> {
        let abi: QContractABI = serde_json::from_str(
            r#"{
                "version": "1.0.0",
                "structs": [
                    {
                        "name": "Account",
                        "is_contract": false,
                        "fields": [
                            {"name": "balance", "type": "Felt"},
                            {"name": "nonce", "type": "U32"}
                        ]
                    },
                    {
                        "name": "Example",
                        "is_contract": true,
                        "fields": [
                            {"name": "owner", "type": "Hash"},
                            {"name": "account", "type": "Account"},
                            {
                                "name": "flags",
                                "type": {
                                    "type": "Array",
                                    "inner_type": "Bool",
                                    "length": 4
                                }
                            }
                        ]
                    }
                ]
            }"#,
        )?;
        let result =
            contract_state_layout_from_abi::<PoseidonHasher, PF, QHashOut<PF>>(
                &abi, 2, 2, 4,
            )?;
        assert_eq!(result.contract_layout.state_layout_field_count, 3);
        assert_eq!(result.contract_layout.state_layout_slot_count, 10);
        assert_eq!(result.contract_layout.fields[0].start_slot, 0);
        assert_eq!(result.contract_layout.fields[1].start_slot, 4);
        assert_eq!(result.contract_layout.fields[2].start_slot, 6);
        assert_eq!(
            result
                .struct_layouts
                .get("Account")
                .unwrap()
                .summary
                .total_slot_count,
            2
        );
        Ok(())
    }

    #[test]
    fn derives_consensus_layout_from_compiler_manifest(
    ) -> anyhow::Result<()> {
        let json = r#"{
            "contract": {
                "state_tree_height": 4,
                "state_layout": {
                    "layout_version": 1,
                    "encoding_version": 1,
                    "field_count": 3,
                    "slot_count": 9,
                    "fields": [
                        {
                            "field_id": 1,
                            "name": "owner",
                            "type": {
                                "kind": "primitive",
                                "name": "Hash"
                            },
                            "start_slot": 0,
                            "slot_count": 4
                        },
                        {
                            "field_id": 2,
                            "name": "account",
                            "type": {
                                "kind": "struct",
                                "name": "Account"
                            },
                            "start_slot": 4,
                            "slot_count": 2
                        },
                        {
                            "field_id": 3,
                            "name": "flags",
                            "type": {
                                "kind": "array",
                                "item": {
                                    "kind": "primitive",
                                    "name": "Bool"
                                },
                                "length": 3,
                                "item_felt_size": 1
                            },
                            "start_slot": 6,
                            "slot_count": 3
                        }
                    ]
                }
            },
            "types": [
                {
                    "kind": "struct",
                    "name": "Account",
                    "felt_size": 2,
                    "fields": [
                        {
                            "name": "balance",
                            "type": {
                                "kind": "primitive",
                                "name": "Felt"
                            },
                            "offset_within_parent": 0,
                            "felt_size": 1
                        },
                        {
                            "name": "nonce",
                            "type": {
                                "kind": "primitive",
                                "name": "U32"
                            },
                            "offset_within_parent": 1,
                            "felt_size": 1
                        }
                    ]
                }
            ]
        }"#;
        let result = contract_state_layout_from_compiler_abi_json::<
            PoseidonHasher,
            PF,
            QHashOut<PF>,
        >(json, 2, 2)?;
        assert_eq!(result.contract_layout.state_layout_field_count, 3);
        assert_eq!(result.contract_layout.state_layout_slot_count, 9);
        assert_eq!(
            result
                .struct_layouts
                .get("Account")
                .unwrap()
                .summary
                .total_slot_count,
            2
        );
        let dags =
            canonical_type_layout_dags_from_compiler_abi_json(json, 2)?;
        assert_eq!(dags.len(), result.contract_layout.fields.len());
        for (dag, field) in
            dags.iter().zip(&result.contract_layout.fields)
        {
            let summary =
                dag.evaluate::<PoseidonHasher, PF, QHashOut<PF>>()?;
            assert_eq!(summary.type_layout_hash, field.type_layout_hash);
            assert_eq!(
                summary.total_slot_count + field.payload_offset,
                field.slot_count
            );
        }
        let manifest =
            canonical_layout_manifest_from_compiler_abi_json::<
                PoseidonHasher,
                PF,
                QHashOut<PF>,
            >(json, 2, 2)?;
        assert_eq!(manifest.layout_version, STATE_LAYOUT_VERSION);
        assert_eq!(manifest.state_tree_height, 4);
        assert_eq!(manifest.field_type_dags, dags);
        assert_eq!(manifest.layout, result);

        let forged = json.replace("\"slot_count\": 2", "\"slot_count\": 3");
        assert!(
            contract_state_layout_from_compiler_abi_json::<
                PoseidonHasher,
                PF,
                QHashOut<PF>,
            >(&forged, 2, 2)
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn commits_fixed_map_alignment_padding() -> anyhow::Result<()> {
        let json = r#"{
            "contract": {
                "state_tree_height": 6,
                "state_layout": {
                    "layout_version": 1,
                    "encoding_version": 1,
                    "field_count": 2,
                    "slot_count": 36,
                    "fields": [
                        {
                            "field_id": 1,
                            "type": {"kind": "primitive", "name": "Felt"},
                            "start_slot": 0,
                            "payload_offset": 0,
                            "slot_count": 1
                        },
                        {
                            "field_id": 2,
                            "type": {
                                "kind": "map",
                                "map_kind": "contract_hash_map",
                                "key": {"kind": "primitive", "name": "Hash"},
                                "value": {"kind": "primitive", "name": "Hash"},
                                "capacity": 8,
                                "value_felt_size": 4,
                                "alignment_felts": 4
                            },
                            "start_slot": 1,
                            "payload_offset": 3,
                            "slot_count": 35
                        }
                    ]
                }
            },
            "types": []
        }"#;
        let result = contract_state_layout_from_compiler_abi_json::<
            PoseidonHasher,
            PF,
            QHashOut<PF>,
        >(json, 1, 1)?;
        assert_eq!(result.contract_layout.state_layout_slot_count, 36);
        assert_eq!(result.contract_layout.fields[1].start_slot, 1);
        assert_eq!(result.contract_layout.fields[1].payload_offset, 3);
        assert_eq!(result.contract_layout.fields[1].slot_count, 35);
        Ok(())
    }

    #[test]
    fn rejects_recursive_inline_abi_structs() -> anyhow::Result<()> {
        let abi: QContractABI = serde_json::from_str(
            r#"{
                "version": "1.0.0",
                "structs": [
                    {
                        "name": "Recursive",
                        "is_contract": true,
                        "fields": [
                            {"name": "next", "type": "Recursive"}
                        ]
                    }
                ]
            }"#,
        )?;
        let error =
            contract_state_layout_from_abi::<PoseidonHasher, PF, QHashOut<PF>>(
                &abi, 1, 1, 4,
            )
            .unwrap_err();
        assert!(error.to_string().contains("recursive inline ABI type"));
        Ok(())
    }

    #[test]
    fn canonical_type_layout_dag_matches_native_nested_layout() -> anyhow::Result<()> {
        let dag = CanonicalTypeLayoutDag {
            nodes: vec![
                CanonicalTypeLayoutNode::Primitive {
                    type_tag: StatePrimitiveTypeTag::U64,
                },
                CanonicalTypeLayoutNode::FixedArray {
                    element: 0,
                    length: 3,
                },
                CanonicalTypeLayoutNode::Primitive {
                    type_tag: StatePrimitiveTypeTag::Hash,
                },
                CanonicalTypeLayoutNode::Struct {
                    members: vec![1, 2],
                    members_tree_height: 1,
                },
            ],
            root: 3,
        };
        let actual =
            dag.evaluate::<PoseidonHasher, PF, QHashOut<PF>>()?;
        let u64_layout = primitive_type_layout::<
            PoseidonHasher,
            PF,
            QHashOut<PF>,
        >(StatePrimitiveTypeTag::U64, 1)?;
        let array_layout = fixed_array_type_layout::<
            PoseidonHasher,
            PF,
            QHashOut<PF>,
        >(u64_layout, 3)?;
        let hash_layout = primitive_type_layout::<
            PoseidonHasher,
            PF,
            QHashOut<PF>,
        >(StatePrimitiveTypeTag::Hash, 4)?;
        let expected = struct_type_layout::<
            PoseidonHasher,
            PF,
            QHashOut<PF>,
        >(&[array_layout, hash_layout], 1)?
        .summary;
        assert_eq!(actual, expected);
        Ok(())
    }
}
