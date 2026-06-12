use serde::{Deserialize, Serialize};

use crate::types::{
    checker::{compute_method_id, CheckedMethod, CheckedProgram},
    layout::*,
    resolver::ResolvedParamType,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecCompliantAbi {
    pub version: String,
    pub structs: Vec<StructAbiSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructAbiSpec {
    pub name: String,
    pub is_contract: bool,
    pub fields: Vec<FieldAbiSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<FunctionAbiSpec>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAbiSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: TypeAbiSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAbiSpec {
    pub name: String,
    pub params: Vec<ParamAbiSpec>,
    #[serde(rename = "return")]
    pub return_type: Vec<TypeAbiSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamAbiSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: TypeAbiSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypeAbiSpec {
    Basic(String),
    Array {
        #[serde(rename = "type")]
        type_name: String,
        inner_type: String,
        length: u32,
    },
}

/// Contract ABI — describes the contract's state layout and public methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractABI {
    pub contract_name: String,
    pub state_tree_height: u16,
    pub state_layout: Vec<ABIStateField>,
    pub methods: Vec<ABIMethod>,
}

/// A field in the contract state for ABI purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIStateField {
    pub name: String,
    pub field_type: String,
    pub offset: usize,
    pub felt_size: usize,
    pub is_array: bool,
    pub array_count: Option<usize>,
    pub element_type: Option<String>,
    pub element_felt_size: Option<usize>,
    /// Sub-field info for struct-typed fields (and array elements).
    /// Each entry is (field_name, felt_offset_within_struct, felt_size).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_fields: Option<Vec<ABISubField>>,
    /// True if this field is a ContractHashMap (backed by indexed merkle tree).
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_imt_map: bool,
    /// Key type for ContractHashMap fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imt_key_type: Option<String>,
    /// Value type for ContractHashMap fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imt_value_type: Option<String>,
    /// Capacity for ContractHashMap fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imt_capacity: Option<usize>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// A sub-field within a struct-typed state field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABISubField {
    pub name: String,
    pub offset: usize,
    pub felt_size: usize,
}

/// A public contract method for ABI purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIMethod {
    pub name: String,
    pub method_id: u32,
    pub params: Vec<ABIParam>,
    pub is_view: bool,
}

/// A method parameter for ABI purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIParam {
    pub name: String,
    pub param_type: String,
    pub felt_size: usize,
}

impl ContractABI {
    /// Build the ABI from a checked program.
    pub fn from_checked_program(checked: &CheckedProgram) -> Self {
        let layout = &checked.contract_layout;

        let state_layout: Vec<ABIStateField> = layout
            .fields
            .iter()
            .map(|f| {
                // Resolve sub-fields for struct types (inline or array elements)
                let sub_fields = Self::resolve_sub_fields(&f.ty, &checked.struct_layouts);

                let (imt_key_type, imt_value_type, imt_capacity) = match &f.ty {
                    ResolvedType::ContractHashMap { key, value, capacity } => {
                        (Some(format!("{:?}", key)), Some(format!("{:?}", value)), Some(*capacity))
                    }
                    _ => (None, None, None),
                };

                ABIStateField {
                    name: f.name.clone(),
                    field_type: format!("{:?}", f.ty),
                    offset: f.base_offset,
                    felt_size: f.felt_size,
                    is_array: f.is_array,
                    array_count: f.array_count,
                    element_type: f.ty.contract_state_array_element().map(|e| format!("{:?}", e)),
                    element_felt_size: f.element_felt_size,
                    sub_fields,
                    is_imt_map: f.is_imt_map,
                    imt_key_type,
                    imt_value_type,
                    imt_capacity,
                }
            })
            .collect();

        let methods: Vec<ABIMethod> = checked
            .methods
            .iter()
            .filter(|m| m.is_contract_method)
            .map(|m| Self::method_to_abi(m, &checked.contract_name, &checked.struct_layouts))
            .collect();

        ContractABI {
            contract_name: checked.contract_name.clone(),
            state_tree_height: layout.state_tree_height,
            state_layout,
            methods,
        }
    }

    /// Resolve sub-field names for a type. Returns `Some(sub_fields)` if
    /// the type (or the array element type) is a struct with named fields.
    fn resolve_sub_fields(ty: &ResolvedType, struct_layouts: &std::collections::HashMap<String, StructLayout>) -> Option<Vec<ABISubField>> {
        match ty {
            ResolvedType::Struct(name) => {
                if let Some(layout) = struct_layouts.get(name) {
                    if layout.fields.len() > 1 || layout.felt_size > 1 {
                        return Some(
                            layout
                                .fields
                                .iter()
                                .map(|f| ABISubField {
                                    name: f.name.clone(),
                                    offset: f.offset,
                                    felt_size: f.felt_size,
                                })
                                .collect(),
                        );
                    }
                }
                None
            }
            ResolvedType::ContractStateArray { element, .. } => Self::resolve_sub_fields(element, struct_layouts),
            _ => None,
        }
    }

    fn method_to_abi(method: &CheckedMethod, contract_name: &str, struct_layouts: &std::collections::HashMap<String, StructLayout>) -> ABIMethod {
        let method_id = compute_method_id(contract_name, &method.name, &method.params);

        let params: Vec<ABIParam> = method
            .params
            .iter()
            .filter_map(|p| match &p.ty {
                ResolvedParamType::SelfRef { .. } => None,
                ResolvedParamType::Typed { ty, .. } => {
                    if *ty == ResolvedType::Struct("ChainContext".to_string()) {
                        None
                    } else {
                        let felt_size = ty.felt_size(struct_layouts).unwrap_or(1);
                        Some(ABIParam {
                            name: p.name.clone(),
                            param_type: format!("{:?}", ty),
                            felt_size,
                        })
                    }
                }
            })
            .collect();

        ABIMethod {
            name: method.name.clone(),
            method_id,
            params,
            is_view: false, // Determined after compilation
        }
    }
}

impl SpecCompliantAbi {
    pub fn from_checked_program(checked: &CheckedProgram) -> Self {
        let mut structs: Vec<StructAbiSpec> = checked
            .struct_layouts
            .values()
            .map(|layout| StructAbiSpec {
                name: layout.name.clone(),
                is_contract: false,
                fields: layout
                    .fields
                    .iter()
                    .map(|field| FieldAbiSpec {
                        name: field.name.clone(),
                        field_type: TypeAbiSpec::from_resolved_type(&field.ty),
                    })
                    .collect(),
                functions: None,
            })
            .collect();
        structs.sort_by(|left, right| left.name.cmp(&right.name));

        let contract_fields = checked
            .contract_layout
            .fields
            .iter()
            .map(|field| FieldAbiSpec {
                name: field.name.clone(),
                field_type: TypeAbiSpec::from_resolved_type(&field.ty),
            })
            .collect();

        let contract_functions: Vec<FunctionAbiSpec> = checked
            .methods
            .iter()
            .filter(|method| method.is_contract_method)
            .map(FunctionAbiSpec::from_checked_method)
            .collect();

        structs.push(StructAbiSpec {
            name: checked.contract_name.clone(),
            is_contract: true,
            fields: contract_fields,
            functions: Some(contract_functions),
        });

        Self {
            version: "1.0.0".to_string(),
            structs,
        }
    }

    pub fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).map_err(|error| anyhow::anyhow!(error))
    }
}

impl FunctionAbiSpec {
    fn from_checked_method(method: &CheckedMethod) -> Self {
        let params = method
            .params
            .iter()
            .filter_map(|param| match &param.ty {
                ResolvedParamType::SelfRef { .. } => None,
                ResolvedParamType::Typed { ty, .. } if *ty == ResolvedType::Struct("ChainContext".to_string()) => None,
                ResolvedParamType::Typed { ty, .. } => Some(ParamAbiSpec {
                    name: param.name.clone(),
                    param_type: TypeAbiSpec::from_resolved_type(ty),
                }),
            })
            .collect();

        let return_type = method
            .return_type
            .as_ref()
            .map(|ty| vec![TypeAbiSpec::from_resolved_type(ty)])
            .unwrap_or_default();

        Self {
            name: method.name.clone(),
            params,
            return_type,
        }
    }
}

impl TypeAbiSpec {
    fn from_resolved_type(ty: &ResolvedType) -> Self {
        match ty {
            ResolvedType::Felt => TypeAbiSpec::Basic("Felt".to_string()),
            ResolvedType::Bool => TypeAbiSpec::Basic("Bool".to_string()),
            ResolvedType::U32 => TypeAbiSpec::Basic("U32".to_string()),
            ResolvedType::Hash => TypeAbiSpec::Basic("Hash".to_string()),
            ResolvedType::Struct(name) => TypeAbiSpec::Basic(name.clone()),
            ResolvedType::Array { element, count } | ResolvedType::ContractStateArray { element, count } => {
                let inner_type = match Self::from_resolved_type(element) {
                    TypeAbiSpec::Basic(name) => name,
                    TypeAbiSpec::Array { inner_type, .. } => inner_type,
                };
                TypeAbiSpec::Array {
                    type_name: "Array".to_string(),
                    inner_type,
                    length: (*count).try_into().unwrap_or(u32::MAX),
                }
            }
            ResolvedType::ContractHashMap { key, value, .. } => {
                let key_type = Self::from_resolved_type(key).type_name();
                let value_type = Self::from_resolved_type(value).type_name();
                TypeAbiSpec::Basic(format!("ContractHashMap<{key_type}, {value_type}>"))
            }
        }
    }

    fn type_name(self) -> String {
        match self {
            TypeAbiSpec::Basic(name) => name,
            TypeAbiSpec::Array {
                type_name,
                inner_type,
                length,
            } => format!("{type_name}<{inner_type}; {length}>"),
        }
    }
}

/// Extension trait for ResolvedType to extract ContractStateArray element info.
impl ResolvedType {
    pub fn contract_state_array_element(&self) -> Option<&ResolvedType> {
        match self {
            ResolvedType::ContractStateArray { element, .. } => Some(element),
            _ => None,
        }
    }
}
