use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroUsize,
    sync::RwLock,
};

use lru::LruCache;

#[derive(Clone, Debug)]
struct CacheWrapper(LruCache<u64, String>);

impl CacheWrapper {
    fn new() -> Self {
        Self(LruCache::new(NonZeroUsize::new(1024).unwrap()))
    }

    fn get(&mut self, slot: &u64) -> Option<&String> {
        self.0.get(slot)
    }

    fn put(&mut self, slot: u64, value: String) {
        self.0.put(slot, value);
    }
}

impl Default for CacheWrapper {
    fn default() -> Self {
        Self::new()
    }
}
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct QContractMetadata {
    pub contract_id: Option<u64>,
    pub deployer: String,
    pub state_tree_height: u16,
    pub function_count: usize,
    pub function_whitelist_root: String,
    pub functions: Vec<QFunctionMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct QFunctionMetadata {
    pub method_id: u32,
    pub name: String,
    pub num_inputs: u32,
    pub num_outputs: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
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

impl TypeAbiSpec {
    pub fn is_array(&self) -> bool {
        matches!(self, TypeAbiSpec::Array { .. })
    }

    pub fn get_type_name(&self) -> &str {
        match self {
            TypeAbiSpec::Basic(type_name) => type_name,
            TypeAbiSpec::Array { type_name, .. } => type_name,
        }
    }

    pub fn is_basic_type(&self) -> bool {
        matches!(self.get_type_name(), "Felt" | "u32" | "bool")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
pub struct ParamAbiSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: TypeAbiSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
pub struct FieldAbiSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: TypeAbiSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
pub struct FunctionAbiSpec {
    pub name: String,
    pub params: Vec<ParamAbiSpec>,
    #[serde(rename = "return")]
    pub return_type: Vec<TypeAbiSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
pub struct StructAbiSpec {
    pub name: String,
    pub is_contract: bool,
    pub fields: Vec<FieldAbiSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<FunctionAbiSpec>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
pub struct QContractABI {
    pub version: String,
    pub structs: Vec<StructAbiSpec>,
}

impl QContractABI {
    pub fn get_contract_struct(&self) -> anyhow::Result<StructAbiSpec> {
        let contract_structs: Vec<_> = self.structs.iter().filter(|s| s.is_contract).collect();
        match contract_structs.len() {
            0 => Err(anyhow::format_err!("contract struct not found")),
            1 => Ok(contract_structs[0].clone()),
            _ => Err(anyhow::format_err!(
                "multiple contract structs found: {}",
                contract_structs.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(", ")
            )),
        }
    }
}

#[pderive::serialize_clone_f_ts]
#[ts(export, concrete(F = parth_core::PF))]
pub struct PsySlotUpdate<F> {
    pub slot: u64,
    pub old_value: F,
    pub new_value: F,
}

#[pderive::serialize_clone_f_ts]
#[ts(export, concrete(F = parth_core::PF))]
pub struct PsyContractSlotUpdates<F> {
    pub contract_id: u32,
    pub slot_updates: Vec<PsySlotUpdate<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, TS)]
pub struct FieldSlotRange {
    pub field_name: String,
    pub field_type: TypeAbiSpec,
    pub start_slot: u64,
    pub end_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, TS)]
pub struct StructSlotRange {
    pub struct_name: String,
    pub fields: BTreeMap<u64, FieldSlotRange>,
}

impl StructSlotRange {
    pub fn new(struct_name: String) -> Self {
        Self {
            struct_name,
            fields: BTreeMap::new(),
        }
    }

    pub fn add_field(&mut self, field: FieldSlotRange) {
        self.fields.insert(field.start_slot, field);
    }

    pub fn get_field_by_slot(&self, slot: u64) -> anyhow::Result<&FieldSlotRange> {
        self.fields
            .range(..=slot)
            .next_back()
            .and_then(|(_, field)| if slot <= field.end_slot { Some(field) } else { None })
            .ok_or_else(|| anyhow::format_err!("slot {} not within any field range", slot))
    }
}

#[derive(Debug, Serialize, Deserialize, TS)]
pub struct ABISlotAnalyzer {
    abi: QContractABI,
    contract_name: String,
    struct_ranges: HashMap<String, StructSlotRange>,
    #[serde(skip, default)]
    cache: RwLock<CacheWrapper>,
}

impl Clone for ABISlotAnalyzer {
    fn clone(&self) -> Self {
        Self {
            abi: self.abi.clone(),
            contract_name: self.contract_name.clone(),
            struct_ranges: self.struct_ranges.clone(),
            cache: RwLock::new(CacheWrapper::default()),
        }
    }
}

impl Default for ABISlotAnalyzer {
    fn default() -> Self {
        Self {
            abi: QContractABI {
                version: String::new(),
                structs: Vec::new(),
            },
            contract_name: String::new(),
            struct_ranges: HashMap::new(),
            cache: RwLock::new(CacheWrapper::default()),
        }
    }
}

impl ABISlotAnalyzer {
    pub fn new(abi: QContractABI) -> anyhow::Result<Self> {
        let contract_name = abi.get_contract_struct()?.name;
        Ok(Self {
            abi,
            contract_name,
            struct_ranges: HashMap::new(),
            cache: RwLock::new(CacheWrapper::default()),
        })
    }

    pub fn new_with_analyze(abi: QContractABI) -> anyhow::Result<Self> {
        let mut analyzer = Self::new(abi)?;
        analyzer.struct_ranges = analyzer.calculate_all_structs_field_slots()?;
        Ok(analyzer)
    }

    fn find_struct(&self, struct_name: &str) -> anyhow::Result<&StructAbiSpec> {
        self.abi
            .structs
            .iter()
            .find(|s| s.name == struct_name)
            .ok_or_else(|| anyhow::format_err!("struct '{}' not found in ABI", struct_name))
    }

    pub fn calculate_struct_total_slots(&self, struct_name: &str) -> anyhow::Result<u64> {
        let struct_spec = self.find_struct(struct_name)?;
        let total = struct_spec
            .fields
            .iter()
            .map(|field| self.calculate_type_slot_count(&field.field_type))
            .sum::<anyhow::Result<u64>>()?;
        Ok(total)
    }

    pub fn calculate_type_slot_count(&self, type_spec: &TypeAbiSpec) -> anyhow::Result<u64> {
        if type_spec.is_basic_type() {
            return Ok(1);
        }
        match type_spec {
            TypeAbiSpec::Basic(inner_type) => self.calculate_struct_total_slots(inner_type),
            TypeAbiSpec::Array { inner_type, length, .. } => {
                let elem_slot_count = self.calculate_struct_total_slots(inner_type)?;
                Ok(elem_slot_count * (*length as u64))
            }
        }
    }

    pub fn calculate_struct_field_slots(&self, struct_name: &str) -> anyhow::Result<StructSlotRange> {
        let struct_spec = self.find_struct(struct_name)?;

        let mut struct_range = StructSlotRange::new(struct_spec.name.clone());
        let mut current_slot = 0u64;

        for field in &struct_spec.fields {
            let slot_count = self.calculate_type_slot_count(&field.field_type)?;
            let end_slot = current_slot + slot_count - 1;

            struct_range.add_field(FieldSlotRange {
                field_name: field.name.clone(),
                field_type: field.field_type.clone(),
                start_slot: current_slot,
                end_slot,
            });

            current_slot = end_slot + 1;
        }

        Ok(struct_range)
    }

    pub fn calculate_all_structs_field_slots(&self) -> anyhow::Result<HashMap<String, StructSlotRange>> {
        let mut struct_ranges = HashMap::with_capacity(self.abi.structs.len());
        for struct_spec in &self.abi.structs {
            let struct_name = &struct_spec.name;
            if !struct_ranges.contains_key(struct_name) {
                struct_ranges.insert(struct_name.to_string(), self.calculate_struct_field_slots(struct_name)?);
            }
        }
        Ok(struct_ranges)
    }

    pub fn get_struct_range(&self, struct_name: &str) -> anyhow::Result<&StructSlotRange> {
        self.struct_ranges
            .get(struct_name)
            .ok_or_else(|| anyhow::format_err!("struct '{}' not found", struct_name))
    }

    fn get_field_by_slot_inner(&self, type_spec: &TypeAbiSpec, slot: u64, current_path: &mut String) -> anyhow::Result<()> {
        if type_spec.is_basic_type() {
            return Ok(());
        }
        match type_spec {
            TypeAbiSpec::Basic(inner_type) => {
                let struct_range = self.get_struct_range(&inner_type)?;
                let field_range = struct_range.get_field_by_slot(slot)?;
                current_path.push_str(&format!(".{}", field_range.field_name));

                self.get_field_by_slot_inner(&field_range.field_type, slot - field_range.start_slot, current_path)?;
            }
            TypeAbiSpec::Array {
                type_name,
                inner_type,
                length,
            } => {
                if matches!(inner_type.as_str(), "Felt" | "u32" | "bool") {
                    current_path.push_str(&format!("[{}]", slot));
                    return Ok(());
                }
                let elem_type_spec = TypeAbiSpec::Basic(inner_type.clone());
                let array_elem_slot_count = self.calculate_type_slot_count(&elem_type_spec)?;
                let array_index = slot / array_elem_slot_count;
                let elem_slot = slot % array_elem_slot_count;
                current_path.push_str(&format!("[{}]", array_index));

                self.get_field_by_slot_inner(&elem_type_spec, elem_slot, current_path)?;
            }
        }

        Ok(())
    }

    pub fn get_field_by_slot(&self, slot: u64) -> anyhow::Result<String> {
        {
            let mut cache = self.cache.write().map_err(|e| anyhow::format_err!("cache lock poisoned: {}", e))?;
            if let Some(cached) = cache.get(&slot) {
                tracing::debug!("cache hit: {} -> {}", slot, cached);
                return Ok(cached.clone());
            }
        }

        let mut slot_path = self.contract_name.to_string();
        self.get_field_by_slot_inner(&TypeAbiSpec::Basic(self.contract_name.to_string()), slot, &mut slot_path)?;

        let mut cache = self.cache.write().map_err(|e| anyhow::format_err!("cache lock poisoned: {}", e))?;
        cache.put(slot, slot_path.clone());
        Ok(slot_path)
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_qcontract_abi_serialization_and_analyze() -> anyhow::Result<()> {
        let abi_str = r#"{
            "version": "1.0.0",
            "structs": [
                {
                    "name": "PsyTokenContract",
                    "is_contract": true,
                    "fields": [
                        {
                            "name": "balance",
                            "type": "Felt"
                        },
                        {
                            "name": "last_claimed_pow_rewards_checkpoint_id",
                            "type": "Felt"
                        },
                        {
                            "name": "claimed_rewards",
                            "type": "Felt"
                        },
                        {
                            "name": "other_user_info",
                            "type": {
                                "type": "Array",
                                "inner_type": "OtherUserInfo",
                                "length": 16777216
                            }
                        }
                    ],
                    "functions": [
                        {
                            "name": "simple_mint",
                            "params": [
                                {
                                    "name": "amount",
                                    "type": "Felt"
                                }
                            ],
                            "return": []
                        }
                    ]
                },
                {
                    "name": "OtherUserInfo",
                    "is_contract": false,
                    "fields": [
                        {
                            "name": "amount_sent",
                            "type": "Felt"
                        },
                        {
                            "name": "amount_claimed",
                            "type": "Felt"
                        }
                    ]
                }
            ]
        }"#;

        let deserialized: QContractABI = serde_json::from_str(&abi_str)?;
        let serialized = serde_json::to_string_pretty(&deserialized)?;

        let deserialized2: QContractABI = serde_json::from_str(&serialized)?;

        assert_eq!(deserialized, deserialized2);

        let analyzer = ABISlotAnalyzer::new_with_analyze(deserialized2)?;

        assert_eq!(analyzer.get_field_by_slot(0)?, "PsyTokenContract.balance");
        assert_eq!(analyzer.get_field_by_slot(0)?, "PsyTokenContract.balance");
        assert_eq!(analyzer.get_field_by_slot(1)?, "PsyTokenContract.last_claimed_pow_rewards_checkpoint_id");
        assert_eq!(analyzer.get_field_by_slot(2)?, "PsyTokenContract.claimed_rewards");
        assert_eq!(analyzer.get_field_by_slot(3)?, "PsyTokenContract.other_user_info[0].amount_sent");
        assert_eq!(analyzer.get_field_by_slot(4)?, "PsyTokenContract.other_user_info[0].amount_claimed");
        assert_eq!(analyzer.get_field_by_slot(6666)?, "PsyTokenContract.other_user_info[3331].amount_claimed");
        assert_eq!(analyzer.get_field_by_slot(6667)?, "PsyTokenContract.other_user_info[3332].amount_sent");

        Ok(())
    }
}
