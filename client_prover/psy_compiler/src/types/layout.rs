use std::collections::HashMap;

use anyhow::{bail, Result};

use crate::parse::ast::{ArrayLen, PrimitiveType, Type};

/// Computed layout for a FeltSized struct.
#[derive(Debug, Clone)]
pub struct StructLayout {
    pub name: String,
    pub felt_size: usize,
    pub fields: Vec<FieldLayout>,
}

/// Layout of a single field within a struct.
#[derive(Debug, Clone)]
pub struct FieldLayout {
    pub name: String,
    pub ty: ResolvedType,
    pub offset: usize,
    pub felt_size: usize,
}

/// A fully resolved type with all sizes known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedType {
    Felt,
    Bool,
    U32,
    Hash,
    Array {
        element: Box<ResolvedType>,
        count: usize,
    },
    Struct(String),
    ContractStateArray {
        count: usize,
        element: Box<ResolvedType>,
    },
    /// IMT map: key and value types for indexed merkle tree key-value storage.
    /// Both key and value must be exactly 4 felts (256-bit).
    ContractHashMap {
        key: Box<ResolvedType>,
        value: Box<ResolvedType>,
        capacity: usize,
    },
}

impl ResolvedType {
    /// Get the felt size of this type.
    pub fn felt_size(&self, structs: &HashMap<String, StructLayout>) -> Result<usize> {
        match self {
            ResolvedType::Felt => Ok(1),
            ResolvedType::Bool => Ok(1),
            ResolvedType::U32 => Ok(1),
            ResolvedType::Hash => Ok(4),
            ResolvedType::Array { element, count } => Ok(element.felt_size(structs)? * count),
            ResolvedType::Struct(name) => {
                let layout = structs.get(name).ok_or_else(|| anyhow::anyhow!("Unknown struct: {}", name))?;
                Ok(layout.felt_size)
            }
            ResolvedType::ContractStateArray { count, element } => {
                // Virtual array: total_felts = count * element_size
                // (used for state_tree_height calculation, not actual allocation)
                Ok(*count * element.felt_size(structs)?)
            }
            ResolvedType::ContractHashMap { .. } => {
                // IMT maps don't occupy positional slots in the linear state tree.
                // They use a separate indexed merkle tree. Size is 0 in the inline layout.
                Ok(0)
            }
        }
    }

    /// Check if this type is a ContractStateArray.
    pub fn is_contract_state_array(&self) -> bool {
        matches!(self, ResolvedType::ContractStateArray { .. })
    }

    /// Check if this type is a ContractHashMap.
    pub fn is_imt_map(&self) -> bool {
        matches!(self, ResolvedType::ContractHashMap { .. })
    }
}

/// Contract state layout — maps fields to state tree slots.
#[derive(Debug, Clone)]
pub struct ContractStateLayout {
    pub contract_name: String,
    pub state_tree_height: u16,
    pub inline_felt_size: usize,
    pub total_virtual_size: usize,
    pub fields: Vec<ContractFieldLayout>,
    pub struct_layouts: HashMap<String, StructLayout>,
    /// True if this contract has any ContractHashMap field.
    pub has_imt_map: bool,
    /// Name of the first IMT map field, if any.
    pub imt_map_field_name: Vec<String>,
}

/// A field in the contract state.
#[derive(Debug, Clone)]
pub struct ContractFieldLayout {
    pub name: String,
    pub ty: ResolvedType,
    pub base_offset: usize,
    pub felt_size: usize,
    pub is_array: bool,
    pub array_count: Option<usize>,
    pub element_felt_size: Option<usize>,
    /// True if this field uses an indexed merkle tree (IMT) for key-value
    /// storage.
    pub is_imt_map: bool,
    /// Virtual capacity reserved for this IMT field.
    pub imt_capacity: Option<usize>,
}

fn count_imt_maps_in_type(ty: &ResolvedType, structs: &HashMap<String, StructLayout>) -> Result<usize> {
    match ty {
        ResolvedType::ContractHashMap { .. } => Ok(1),
        ResolvedType::Array { element, .. } | ResolvedType::ContractStateArray { element, .. } => count_imt_maps_in_type(element, structs),
        ResolvedType::Struct(name) => {
            let layout = structs.get(name).ok_or_else(|| anyhow::anyhow!("Unknown struct: {}", name))?;
            let mut total = 0usize;
            for field in &layout.fields {
                total += count_imt_maps_in_type(&field.ty, structs)?;
            }
            Ok(total)
        }
        _ => Ok(0),
    }
}

fn contains_imt_map(ty: &ResolvedType, structs: &HashMap<String, StructLayout>) -> Result<bool> {
    Ok(match ty {
        ResolvedType::ContractHashMap { .. } => true,
        ResolvedType::Array { element, .. } | ResolvedType::ContractStateArray { element, .. } => contains_imt_map(element, structs)?,
        ResolvedType::Struct(name) => {
            let layout = structs.get(name).ok_or_else(|| anyhow::anyhow!("Unknown struct: {}", name))?;
            layout
                .fields
                .iter()
                .map(|field| contains_imt_map(&field.ty, structs))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .any(|contains| contains)
        }
        _ => false,
    })
}

/// Compute struct layout from its fields.
pub fn compute_struct_layout(name: &str, fields: &[(String, ResolvedType)], structs: &HashMap<String, StructLayout>) -> Result<StructLayout> {
    let mut offset = 0;
    let mut field_layouts = Vec::new();

    for (fname, fty) in fields {
        if contains_imt_map(fty, structs)? {
            bail!(
                "state-layout V1 forbids ContractHashMap inside struct '{}.{}'; aligned maps must be direct top-level contract fields",
                name,
                fname
            );
        }
        let size = fty.felt_size(structs)?;
        field_layouts.push(FieldLayout {
            name: fname.clone(),
            ty: fty.clone(),
            offset,
            felt_size: size,
        });
        offset += size;
    }

    Ok(StructLayout {
        name: name.to_string(),
        felt_size: offset,
        fields: field_layouts,
    })
}

/// Compute the contract state layout.
pub fn compute_contract_layout(
    contract_name: &str,
    fields: &[(String, ResolvedType)],
    structs: &HashMap<String, StructLayout>,
) -> Result<ContractStateLayout> {
    let mut total_imt_maps = 0usize;
    for (_fname, fty) in fields {
        if !matches!(fty, ResolvedType::ContractHashMap { .. }) && contains_imt_map(fty, structs)? {
            bail!("state-layout V1 forbids ContractHashMap nested in arrays or structs; aligned maps must be direct top-level contract fields");
        }
        total_imt_maps += count_imt_maps_in_type(fty, structs)?;
    }
    if total_imt_maps > 1 {
        bail!(
            "Only one ContractHashMap is currently supported per contract. Found {} IMT maps in contract '{}'",
            total_imt_maps,
            contract_name
        );
    }

    let mut offset = 0;
    let mut field_layouts = Vec::new();
    let mut inline_size = 0;
    let mut has_imt_map = false;
    let mut imt_map_field_name = Vec::new();

    for (fname, fty) in fields {
        match fty {
            ResolvedType::ContractStateArray { count, element } => {
                let elem_size = element.felt_size(structs)?;
                field_layouts.push(ContractFieldLayout {
                    name: fname.clone(),
                    ty: fty.clone(),
                    base_offset: offset,
                    felt_size: count * elem_size,
                    is_array: true,
                    array_count: Some(*count),
                    element_felt_size: Some(elem_size),
                    is_imt_map: false,
                    imt_capacity: None,
                });
                offset += count * elem_size;
            }
            ResolvedType::ContractHashMap { key, value, capacity } => {
                let key_size = key.felt_size(structs)?;
                let value_size = value.felt_size(structs)?;
                if key_size != 4 {
                    bail!("ContractHashMap key type must be exactly 4 felts (256-bit), got {} felts", key_size);
                }
                if value_size != 4 {
                    bail!("ContractHashMap value type must be exactly 4 felts (256-bit), got {} felts", value_size);
                }
                has_imt_map = true;
                imt_map_field_name.push(fname.clone());

                // IMT maps reserve a virtual contiguous region in contract state slots.
                // Actual key lookup still goes through IMT index resolution in VM.
                let base_offset = (offset + 3) & !3;
                field_layouts.push(ContractFieldLayout {
                    name: fname.clone(),
                    ty: fty.clone(),
                    base_offset,
                    felt_size: *capacity * value_size,
                    is_array: false,
                    array_count: None,
                    element_felt_size: Some(value_size),
                    is_imt_map: true,
                    imt_capacity: Some(*capacity),
                });
                offset = base_offset + *capacity * value_size;
            }
            _ => {
                let size = fty.felt_size(structs)?;
                field_layouts.push(ContractFieldLayout {
                    name: fname.clone(),
                    ty: fty.clone(),
                    base_offset: offset,
                    felt_size: size,
                    is_array: false,
                    array_count: None,
                    element_felt_size: None,
                    is_imt_map: false,
                    imt_capacity: None,
                });
                offset += size;
                inline_size += size;
            }
        }
    }

    // Compute state tree height
    let total_virtual_size = offset;
    let state_tree_height = if total_virtual_size <= 1 {
        1
    } else {
        (total_virtual_size as f64).log2().ceil() as u16
    };

    Ok(ContractStateLayout {
        contract_name: contract_name.to_string(),
        state_tree_height,
        inline_felt_size: inline_size,
        total_virtual_size,
        fields: field_layouts,
        struct_layouts: structs.clone(),
        has_imt_map,
        imt_map_field_name,
    })
}

/// Resolve an AST Type to a ResolvedType, given known constants.
pub fn resolve_type(
    ty: &Type,
    constants: &HashMap<String, u64>,
    struct_names: &HashMap<String, bool>, // name -> is_defined
) -> Result<ResolvedType> {
    match ty {
        Type::Primitive(PrimitiveType::Felt) => Ok(ResolvedType::Felt),
        Type::Primitive(PrimitiveType::Bool) => Ok(ResolvedType::Bool),
        Type::Primitive(PrimitiveType::U32) => Ok(ResolvedType::U32),
        Type::Primitive(PrimitiveType::Hash) => Ok(ResolvedType::Hash),
        Type::Array(inner, len) => {
            let resolved_inner = resolve_type(inner, constants, struct_names)?;
            let count = resolve_array_len(len, constants)?;
            Ok(ResolvedType::Array {
                element: Box::new(resolved_inner),
                count,
            })
        }
        Type::ContractStateArray { count, element_type } => {
            let resolved_element = resolve_type(element_type, constants, struct_names)?;
            let count_val = resolve_array_len(count, constants)?;
            Ok(ResolvedType::ContractStateArray {
                count: count_val,
                element: Box::new(resolved_element),
            })
        }
        Type::ContractHashMap {
            key_type,
            value_type,
            capacity,
        } => {
            let resolved_key = resolve_type(key_type, constants, struct_names)?;
            let resolved_value = resolve_type(value_type, constants, struct_names)?;
            let resolved_capacity = resolve_array_len(capacity, constants)?;
            if resolved_capacity == 0 {
                bail!("ContractHashMap capacity must be > 0");
            }
            Ok(ResolvedType::ContractHashMap {
                key: Box::new(resolved_key),
                value: Box::new(resolved_value),
                capacity: resolved_capacity,
            })
        }
        Type::Named(name) => {
            if name == "ChainContext" || name == "Self" {
                Ok(ResolvedType::Struct(name.clone()))
            } else if struct_names.contains_key(name) {
                Ok(ResolvedType::Struct(name.clone()))
            } else {
                bail!("Unknown type: {}", name)
            }
        }
        Type::Usize => Ok(ResolvedType::U32), // usize only used in const declarations
        Type::Ref { inner, .. } => resolve_type(inner, constants, struct_names),
        Type::StaticRef(inner) => resolve_type(inner, constants, struct_names),
    }
}

fn resolve_array_len(len: &ArrayLen, constants: &HashMap<String, u64>) -> Result<usize> {
    match len {
        ArrayLen::Literal(n) => Ok(*n),
        ArrayLen::Named(name) => constants
            .get(name)
            .map(|v| *v as usize)
            .ok_or_else(|| anyhow::anyhow!("Unknown constant: {}", name)),
    }
}

impl ContractStateLayout {
    /// Get field layout by name.
    pub fn get_field(&self, name: &str) -> Option<&ContractFieldLayout> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Get the offset for a field within a struct type.
    pub fn get_struct_field_offset(&self, struct_name: &str, field_name: &str) -> Option<usize> {
        self.struct_layouts
            .get(struct_name)
            .and_then(|layout| layout.fields.iter().find(|f| f.name == field_name))
            .map(|f| f.offset)
    }
}
