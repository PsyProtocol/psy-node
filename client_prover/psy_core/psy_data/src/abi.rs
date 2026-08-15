use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ABI wire types — the canonical, compiler-independent ABI shape.
//
// These are pure serde data types. They define the single JSON ABI surface
// emitted by the PSY compiler (and re-exported by standalone `psy-abi`).
// No compiler internals are referenced here; the builder logic that turns a
// checked program into an `Abi` lives in the compiler / standalone extractor.
// ---------------------------------------------------------------------------

/// Top-level ABI shape — the single ABI emitted by the compiler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Abi {
    pub schema_version: String,
    pub contract: AbiContract,
    pub types: Vec<AbiStructType>,
}

/// Contract-level metadata + state layout + methods.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbiContract {
    pub name: String,
    pub state_tree_height: u16,
    pub state: Vec<AbiStateField>,
    pub methods: Vec<AbiMethod>,
}

/// A state field with its absolute slot offset and felt footprint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbiStateField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeRef,
    pub offset: usize,
    pub felt_size: usize,
}

/// A method with explicit compiler-owned metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// View vs. external mutability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateMutability {
    View,
    External,
}

impl StateMutability {
    pub fn is_view(&self) -> bool {
        matches!(self, StateMutability::View)
    }
}

/// A typed parameter (input or output).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeRef,
    pub felt_size: usize,
}

/// A named struct type entry in the `types[]` table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbiStructType {
    pub kind: AbiTypeKind,
    pub name: String,
    pub felt_size: usize,
    pub fields: Vec<AbiStructField>,
}

/// Marker for the type-table entry kind. Currently only `struct`, but
/// reserved for future `enum` / `alias` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiTypeKind {
    Struct,
}

/// A field within an `AbiStructType`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbiStructField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeRef,
    pub offset_within_parent: usize,
    pub felt_size: usize,
}

/// Recursive type reference — the type model used by state, params,
/// and struct fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// The set of primitive type names the compiler actually emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrimitiveTypeName {
    Felt,
    Bool,
    U32,
    Hash,
}

/// Source-level map type family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapKind {
    ContractHashMap,
    Map,
    NamespacedMap,
}

impl Abi {
    /// Serialize the ABI to pretty JSON (primary output).
    pub fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| anyhow::anyhow!(e))
    }
}
