use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::types::{
    checker::{compute_method_id, CheckedMethod, CheckedProgram},
    layout::*,
    resolver::ResolvedParamType,
};

// ---------------------------------------------------------------------------
// ABI types — the single source-of-truth ABI shape.
// ---------------------------------------------------------------------------

/// Top-level ABI shape — the single ABI emitted by the compiler.
#[derive(Debug, Clone, Serialize)]
pub struct Abi {
    pub schema_version: String,
    pub contract: AbiContract,
    pub types: Vec<AbiStructType>,
}

impl<'de> Deserialize<'de> for Abi {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AbiContractHelper {
            name: String,
            state_tree_height: u16,
            state: Vec<AbiStateField>,
            #[serde(default)]
            state_layout: Option<AbiStateLayout>,
            methods: Vec<AbiMethod>,
        }

        #[derive(Deserialize)]
        struct AbiHelper {
            schema_version: String,
            contract: AbiContractHelper,
            types: Vec<AbiStructType>,
        }

        let helper = AbiHelper::deserialize(deserializer)?;
        let state_layout = match helper.contract.state_layout {
            Some(layout) => layout,
            None => AbiStateLayout::from_state_fields_and_types(&helper.contract.state, &helper.types)
                .map_err(serde::de::Error::custom)?,
        };

        Ok(Abi {
            schema_version: helper.schema_version,
            contract: AbiContract {
                name: helper.contract.name,
                state_tree_height: helper.contract.state_tree_height,
                state: helper.contract.state,
                state_layout,
                methods: helper.contract.methods,
            },
            types: helper.types,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiContract {
    pub name: String,
    pub state_tree_height: u16,
    pub state: Vec<AbiStateField>,
    /// Canonical, field-oriented storage manifest consumed by deployment and
    /// contract-update tooling. Hashes are intentionally computed downstream
    /// with the protocol hasher; the compiler owns declaration order, type
    /// shape, and physical slot ranges.
    pub state_layout: AbiStateLayout,
    pub methods: Vec<AbiMethod>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiStateLayout {
    pub layout_version: u16,
    pub encoding_version: u16,
    pub field_count: u64,
    pub slot_count: u64,
    pub fields: Vec<AbiLayoutField>,
    /// Deterministic, deduplicated jobs used by the prover to construct the
    /// recursive type-layout proof tree.
    pub type_proof_plan: AbiTypeProofPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiTypeProofPlan {
    pub protocol_version: u16,
    pub nodes: Vec<AbiTypeProofNode>,
    /// Node id for each top-level field, in field order.
    pub field_nodes: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiTypeProofNode {
    pub node_id: u32,
    /// Stable structural descriptor used for deterministic DAG deduplication.
    pub type_key: String,
    pub circuit_kind: AbiTypeProofCircuitKind,
    pub dependencies: Vec<u32>,
    /// The proving layer combines this material with the deployed circuit
    /// fingerprint; fingerprints intentionally do not come from source code.
    pub cache_key_material: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiTypeProofCircuitKind {
    Primitive,
    FixedArray,
    FixedMap,
    Struct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiLayoutField {
    /// One-based position in the top-level layout tree.
    pub field_id: u64,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeRef,
    pub start_slot: u64,
    pub payload_offset: u64,
    pub slot_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiStateField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeRef,
    pub offset: usize,
    pub felt_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiMethod {
    pub name: String,
    pub method_id: u32,
    pub state_mutability: StateMutability,
    pub inputs: Vec<AbiParam>,
    pub outputs: Vec<AbiParam>,
    pub input_felt_count: usize,
    pub output_felt_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateMutability {
    View,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeRef,
    pub felt_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiStructType {
    pub kind: AbiTypeKind,
    pub name: String,
    pub felt_size: usize,
    pub fields: Vec<AbiStructField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiTypeKind {
    Struct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiStructField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeRef,
    pub offset_within_parent: usize,
    pub felt_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeRef {
    Primitive {
        name: PrimitiveTypeName,
    },
    Struct {
        name: String,
    },
    Array {
        item: Box<TypeRef>,
        length: u32,
        item_felt_size: usize,
    },
    Map {
        map_kind: MapKind,
        key: Box<TypeRef>,
        value: Box<TypeRef>,
        capacity: usize,
        value_felt_size: usize,
        alignment_felts: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrimitiveTypeName {
    Felt,
    Bool,
    U32,
    Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapKind {
    ContractHashMap,
    Map,
    NamespacedMap,
}

impl Abi {
    pub fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| anyhow::anyhow!(e))
    }
}

impl AbiStateLayout {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.layout_version == 1, "unsupported state layout version {}", self.layout_version);
        anyhow::ensure!(
            self.encoding_version == 1,
            "unsupported state layout encoding version {}",
            self.encoding_version
        );
        anyhow::ensure!(
            self.field_count == self.fields.len() as u64,
            "state layout field_count does not match fields length"
        );
        anyhow::ensure!(
            self.type_proof_plan.protocol_version == self.layout_version,
            "type proof plan protocol version does not match layout version"
        );
        anyhow::ensure!(
            self.type_proof_plan.field_nodes.len() == self.fields.len(),
            "type proof plan must contain one endpoint per field"
        );
        for (index, node) in self.type_proof_plan.nodes.iter().enumerate() {
            anyhow::ensure!(node.node_id == index as u32, "type proof plan node ids must be contiguous");
            anyhow::ensure!(
                node.dependencies.iter().all(|dependency| *dependency < node.node_id),
                "type proof plan dependencies must precede their parent"
            );
        }
        anyhow::ensure!(
            self.type_proof_plan
                .field_nodes
                .iter()
                .all(|node| (*node as usize) < self.type_proof_plan.nodes.len()),
            "type proof plan contains an invalid field endpoint"
        );
        let mut next_slot = 0u64;
        for (index, field) in self.fields.iter().enumerate() {
            anyhow::ensure!(
                field.field_id == index as u64 + 1,
                "state layout field ids must be contiguous and one-based"
            );
            anyhow::ensure!(field.slot_count > 0, "state layout field '{}' occupies zero slots", field.name);
            anyhow::ensure!(field.start_slot == next_slot, "state layout field '{}' is not contiguous", field.name);
            anyhow::ensure!(
                field.payload_offset < field.slot_count,
                "state layout field '{}' payload is outside its owned range",
                field.name
            );
            let alignment = match &field.ty {
                TypeRef::Map { alignment_felts, .. } => u64::from(*alignment_felts),
                _ => 1,
            };
            anyhow::ensure!(
                alignment > 0 && alignment.is_power_of_two(),
                "state layout field '{}' has invalid alignment",
                field.name
            );
            let expected_payload_offset = (alignment - (field.start_slot % alignment)) % alignment;
            anyhow::ensure!(
                field.payload_offset == expected_payload_offset,
                "state layout field '{}' has incorrect alignment padding",
                field.name
            );
            next_slot = next_slot
                .checked_add(field.slot_count)
                .ok_or_else(|| anyhow::anyhow!("state layout slot count overflow"))?;
        }
        anyhow::ensure!(self.slot_count == next_slot, "state layout slot_count does not match field ranges");
        Ok(())
    }

    pub fn validate_append_only_from(&self, old: &Self) -> anyhow::Result<()> {
        old.validate()?;
        self.validate()?;
        anyhow::ensure!(
            self.layout_version == old.layout_version && self.encoding_version == old.encoding_version,
            "state layout version or encoding cannot change"
        );
        anyhow::ensure!(self.fields.len() >= old.fields.len(), "state layout fields cannot be removed");
        anyhow::ensure!(
            self.fields[..old.fields.len()] == old.fields,
            "existing state layout fields were modified or reordered"
        );
        anyhow::ensure!(self.slot_count >= old.slot_count, "state layout slot count cannot decrease");
        Ok(())
    }

    /// Reconstruct a canonical state layout from legacy ABI state fields and
    /// struct definitions. Used for backward compatibility with ABI JSONs that
    /// predate the compiler emitting `state_layout`.
    pub fn from_state_fields_and_types(
        state: &[AbiStateField],
        types: &[AbiStructType],
    ) -> anyhow::Result<Self> {
        let mut layout_frontier = 0u64;
        let fields = state
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let payload_start = field.offset as u64;
                let payload_offset = payload_start
                    .checked_sub(layout_frontier)
                    .ok_or_else(|| anyhow::anyhow!("legacy ABI field offset {} moves before frontier {}", payload_start, layout_frontier))?;
                let slot_count = payload_offset
                    .checked_add(field.felt_size as u64)
                    .ok_or_else(|| anyhow::anyhow!("legacy ABI field slot count overflow"))?;
                let result = AbiLayoutField {
                    field_id: index as u64 + 1,
                    name: field.name.clone(),
                    ty: field.ty.clone(),
                    start_slot: layout_frontier,
                    payload_offset,
                    slot_count,
                };
                layout_frontier = layout_frontier
                    .checked_add(slot_count)
                    .ok_or_else(|| anyhow::anyhow!("legacy ABI state layout frontier overflow"))?;
                Ok(result)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            layout_version: 1,
            encoding_version: 1,
            field_count: fields.len() as u64,
            slot_count: layout_frontier,
            fields,
            type_proof_plan: AbiTypeProofPlan::from_fields(state, types)?,
        })
    }
}

impl Abi {
    /// Validate the compiler artifacts before building an update layout proof.
    ///
    /// Existing top-level fields and every previously declared struct type are
    /// immutable. New struct definitions are allowed only under new names and
    /// can be referenced by newly appended top-level fields.
    pub fn validate_layout_update_from(&self, old: &Self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.contract.name == old.contract.name,
            "contract identity cannot change during layout update"
        );
        anyhow::ensure!(
            self.contract.state_tree_height == old.contract.state_tree_height,
            "contract state tree height cannot change"
        );
        self.contract.state_layout.validate_append_only_from(&old.contract.state_layout)?;
        for old_type in &old.types {
            let new_type = self
                .types
                .iter()
                .find(|candidate| candidate.name == old_type.name)
                .ok_or_else(|| anyhow::anyhow!("existing ABI type '{}' was removed", old_type.name))?;
            anyhow::ensure!(new_type == old_type, "existing ABI type '{}' was modified", old_type.name);
        }
        Ok(())
    }
}

impl Abi {
    /// Build the ABI from a checked program.
    pub fn from_checked_program(checked: &CheckedProgram) -> Self {
        let layout = &checked.contract_layout;

        // --- Types table: non-contract structs, sorted by name for
        // deterministic output (matching legacy spec ABI ordering). ---
        let mut types: Vec<AbiStructType> = checked
            .struct_layouts
            .values()
            .map(|sl| AbiStructType {
                kind: AbiTypeKind::Struct,
                name: sl.name.clone(),
                felt_size: sl.felt_size,
                fields: sl
                    .fields
                    .iter()
                    .map(|f| AbiStructField {
                        name: f.name.clone(),
                        ty: TypeRef::from_resolved_type(&f.ty, &checked.struct_layouts),
                        offset_within_parent: f.offset,
                        felt_size: f.felt_size,
                    })
                    .collect(),
            })
            .collect();
        types.sort_by(|a, b| a.name.cmp(&b.name));

        // --- State layout ---
        let state: Vec<AbiStateField> = layout
            .fields
            .iter()
            .map(|f| AbiStateField {
                name: f.name.clone(),
                ty: TypeRef::from_resolved_type(&f.ty, &checked.struct_layouts),
                offset: f.base_offset,
                felt_size: f.felt_size,
            })
            .collect();
        let mut layout_frontier = 0u64;
        let state_layout_fields = layout
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let payload_start = field.base_offset as u64;
                let payload_offset = payload_start
                    .checked_sub(layout_frontier)
                    .expect("compiler field offsets cannot move backwards");
                let slot_count = payload_offset
                    .checked_add(field.felt_size as u64)
                    .expect("compiler state layout slot count overflow");
                let result = AbiLayoutField {
                    field_id: index as u64 + 1,
                    name: field.name.clone(),
                    ty: TypeRef::from_resolved_type(&field.ty, &checked.struct_layouts),
                    start_slot: layout_frontier,
                    payload_offset,
                    slot_count,
                };
                layout_frontier = layout_frontier.checked_add(slot_count).expect("compiler state layout frontier overflow");
                result
            })
            .collect::<Vec<_>>();
        let state_layout = AbiStateLayout {
            layout_version: 1,
            encoding_version: 1,
            field_count: state_layout_fields.len() as u64,
            slot_count: layout.total_virtual_size as u64,
            fields: state_layout_fields,
            type_proof_plan: AbiTypeProofPlan::from_fields(&state, &types).expect("checked ABI types must form a valid proof DAG"),
        };

        // --- Methods ---
        let methods: Vec<AbiMethod> = checked
            .methods
            .iter()
            .filter(|m| m.is_contract_method)
            .map(|m| AbiMethod::from_checked_method(m, &checked.contract_name, &checked.struct_layouts))
            .collect();

        Abi {
            schema_version: "2.0.0".to_string(),
            contract: AbiContract {
                name: checked.contract_name.clone(),
                state_tree_height: layout.state_tree_height,
                state,
                state_layout,
                methods,
            },
            types,
        }
    }
}

impl AbiMethod {
    fn from_checked_method(method: &CheckedMethod, contract_name: &str, struct_layouts: &HashMap<String, StructLayout>) -> Self {
        let method_id = compute_method_id(contract_name, &method.name, &method.params);
        let inputs: Vec<AbiParam> = method
            .params
            .iter()
            .filter_map(|p| match &p.ty {
                ResolvedParamType::SelfRef { .. } => None,
                ResolvedParamType::Typed { ty, .. } if *ty == ResolvedType::Struct("ChainContext".to_string()) => None,
                ResolvedParamType::Typed { ty, .. } => {
                    let felt_size = ty.felt_size(struct_layouts).unwrap_or(1);
                    Some(AbiParam {
                        name: p.name.clone(),
                        ty: TypeRef::from_resolved_type(ty, struct_layouts),
                        felt_size,
                    })
                }
            })
            .collect();
        let input_felt_count: usize = inputs.iter().map(|p| p.felt_size).sum();
        let outputs: Vec<AbiParam> = method
            .return_type
            .as_ref()
            .map(|ty| {
                let felt_size = ty.felt_size(struct_layouts).unwrap_or(1);
                vec![AbiParam {
                    name: "return".to_string(),
                    ty: TypeRef::from_resolved_type(ty, struct_layouts),
                    felt_size,
                }]
            })
            .unwrap_or_default();
        let output_felt_count: usize = outputs.iter().map(|p| p.felt_size).sum();
        AbiMethod {
            name: method.name.clone(),
            method_id,
            state_mutability: StateMutability::External, // No view tracking yet in compiler
            inputs,
            outputs,
            input_felt_count,
            output_felt_count,
            vm_type: None,
        }
    }
}

impl TypeRef {
    /// Convert a `ResolvedType` to a `TypeRef`.
    fn from_resolved_type(ty: &ResolvedType, struct_layouts: &HashMap<String, StructLayout>) -> Self {
        match ty {
            ResolvedType::Felt => TypeRef::Primitive {
                name: PrimitiveTypeName::Felt,
            },
            ResolvedType::Bool => TypeRef::Primitive {
                name: PrimitiveTypeName::Bool,
            },
            ResolvedType::U32 => TypeRef::Primitive {
                name: PrimitiveTypeName::U32,
            },
            ResolvedType::Hash => TypeRef::Primitive {
                name: PrimitiveTypeName::Hash,
            },
            ResolvedType::Struct(name) => TypeRef::Struct { name: name.clone() },
            ResolvedType::Array { element, count } => {
                let item = Box::new(Self::from_resolved_type(element, struct_layouts));
                let item_felt_size = element.felt_size(struct_layouts).unwrap_or(0);
                TypeRef::Array {
                    item,
                    length: (*count).try_into().unwrap_or(u32::MAX),
                    item_felt_size,
                }
            }
            ResolvedType::ContractStateArray { element, count } => {
                let item = Box::new(Self::from_resolved_type(element, struct_layouts));
                let item_felt_size = element.felt_size(struct_layouts).unwrap_or(0);
                TypeRef::Array {
                    item,
                    length: (*count).try_into().unwrap_or(u32::MAX),
                    item_felt_size,
                }
            }
            ResolvedType::ContractHashMap { key, value, capacity } => {
                let key_ref = Box::new(Self::from_resolved_type(key, struct_layouts));
                let value_ref = Box::new(Self::from_resolved_type(value, struct_layouts));
                let value_felt_size = value.felt_size(struct_layouts).unwrap_or(4);
                TypeRef::Map {
                    map_kind: MapKind::ContractHashMap,
                    key: key_ref,
                    value: value_ref,
                    capacity: *capacity,
                    value_felt_size,
                    alignment_felts: 4,
                }
            }
        }
    }
}

impl AbiTypeProofPlan {
    pub fn from_fields(fields: &[AbiStateField], types: &[AbiStructType]) -> anyhow::Result<Self> {
        let definitions = types
            .iter()
            .map(|definition| (definition.name.as_str(), definition))
            .collect::<BTreeMap<_, _>>();
        let mut by_key = BTreeMap::<String, u32>::new();
        let mut nodes = Vec::new();
        let mut visiting = Vec::new();
        let field_nodes = fields
            .iter()
            .map(|field| Self::intern_type(&field.ty, &definitions, &mut by_key, &mut nodes, &mut visiting))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            protocol_version: 1,
            nodes,
            field_nodes,
        })
    }

    fn intern_type(
        ty: &TypeRef,
        definitions: &BTreeMap<&str, &AbiStructType>,
        by_key: &mut BTreeMap<String, u32>,
        nodes: &mut Vec<AbiTypeProofNode>,
        visiting: &mut Vec<String>,
    ) -> anyhow::Result<u32> {
        let (type_key, circuit_kind, dependencies) = match ty {
            TypeRef::Primitive { name } => (format!("primitive:{name:?}"), AbiTypeProofCircuitKind::Primitive, Vec::new()),
            TypeRef::Array { item, length, .. } => {
                let child = Self::intern_type(item, definitions, by_key, nodes, visiting)?;
                let child_key = &nodes[child as usize].type_key;
                (format!("array:{length}:{child_key}"), AbiTypeProofCircuitKind::FixedArray, vec![child])
            }
            TypeRef::Map {
                map_kind,
                key,
                value,
                capacity,
                alignment_felts,
                ..
            } => {
                let key_node = Self::intern_type(key, definitions, by_key, nodes, visiting)?;
                let value_node = Self::intern_type(value, definitions, by_key, nodes, visiting)?;
                (
                    format!(
                        "map:{map_kind:?}:{capacity}:{alignment_felts}:{}:{}",
                        nodes[key_node as usize].type_key, nodes[value_node as usize].type_key
                    ),
                    AbiTypeProofCircuitKind::FixedMap,
                    vec![key_node, value_node],
                )
            }
            TypeRef::Struct { name } => {
                anyhow::ensure!(!visiting.contains(name), "recursive ABI struct '{name}' is not supported");
                let definition = definitions
                    .get(name.as_str())
                    .ok_or_else(|| anyhow::anyhow!("ABI struct '{name}' not found"))?;
                visiting.push(name.clone());
                let dependencies = definition
                    .fields
                    .iter()
                    .map(|member| Self::intern_type(&member.ty, definitions, by_key, nodes, visiting))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                visiting.pop();
                let member_keys = dependencies
                    .iter()
                    .map(|node| nodes[*node as usize].type_key.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                (format!("struct:{name}:[{member_keys}]"), AbiTypeProofCircuitKind::Struct, dependencies)
            }
        };
        if let Some(node_id) = by_key.get(&type_key) {
            return Ok(*node_id);
        }
        let node_id = u32::try_from(nodes.len())?;
        nodes.push(AbiTypeProofNode {
            node_id,
            cache_key_material: format!("state-layout:v1:{circuit_kind:?}:{type_key}"),
            type_key: type_key.clone(),
            circuit_kind,
            dependencies,
        });
        by_key.insert(type_key, node_id);
        Ok(node_id)
    }
}
