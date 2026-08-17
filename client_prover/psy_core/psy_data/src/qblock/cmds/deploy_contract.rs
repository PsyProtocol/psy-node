use std::collections::{BTreeMap, HashMap};

use anyhow::ensure;
use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT;
use psy_crypto::hash::{merkle::utils::simple_merkle_tree::SimpleMerkleTree, traits::hasher::MerkleZeroHasherWithMarkedLeaf};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::qdata::contract::ContractCodeDefinition;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QBCDeployContract<F: RichField> {
    pub deployer: QHashOut<F>,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<QHashOut<F>>,
    pub code_root: QHashOut<F>,
}

impl<F: RichField> QBCDeployContract<F> {
    pub fn new(deployer: QHashOut<F>, code_definition: ContractCodeDefinition, function_whitelist: Vec<QHashOut<F>>, code_root: QHashOut<F>) -> Self {
        Self {
            deployer,
            code_definition,
            function_whitelist,
            code_root,
        }
    }
    pub fn into_with_whitelist_root<H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>>>(self) -> anyhow::Result<QBCDeployContractWithRoot<F>> {
        QBCDeployContractWithRoot::<F>::new::<H>(self.deployer, self.code_definition, self.function_whitelist, self.code_root)
    }
}

pub fn get_code_root_by_code_hashes<F: RichField, Hasher: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>>>(
    code_hashes: &[QHashOut<F>],
    function_code_tree_height: u8,
) -> QHashOut<F> {
    let mut t = SimpleMerkleTree::<Hasher, QHashOut<F>>::new(function_code_tree_height);
    for (i, l) in code_hashes.iter().enumerate() {
        t.set_leaf(i as u64, *l);
    }
    t.get_root()
}

impl<F: RichField> KVQSerializable for QBCDeployContract<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QBCDeployContractWithRoot<F: RichField> {
    pub deployer: QHashOut<F>,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<QHashOut<F>>,
    pub function_whitelist_root: QHashOut<F>,
    pub code_root: QHashOut<F>,
}

impl<F: RichField> QBCDeployContractWithRoot<F> {
    pub fn new<H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>>>(
        deployer: QHashOut<F>,
        code_definition: ContractCodeDefinition,
        function_whitelist: Vec<QHashOut<F>>,
        code_root: QHashOut<F>,
    ) -> anyhow::Result<Self> {
        ensure!(
            function_whitelist.len() == code_definition.functions.len() * 2,
            "function_whitelist must contain two entries per function"
        );
        // let zero = QHashOut::from_values(0, 0, 0, 0);
        // for i in 0..code_definition.functions.len() {
        //     let base = i * 2;
        //     ensure!(function_whitelist[base + 1] == zero, "function whitelist
        // placeholder must be zero"); }
        let mut whitelist_tree = SimpleMerkleTree::<H, QHashOut<F>>::new(CONTRACT_FUNCTION_TREE_HEIGHT);
        for (i, leaf) in function_whitelist.iter().enumerate() {
            whitelist_tree.set_leaf(i as u64, *leaf);
        }
        let function_whitelist_root = whitelist_tree.get_root();

        Ok(Self {
            deployer,
            code_definition,
            function_whitelist,
            function_whitelist_root,
            code_root,
        })
    }
}

impl<F: RichField> KVQSerializable for QBCDeployContractWithRoot<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Layout-aware deploy command. Wraps the base [`QBCDeployContract`] with the
/// canonical state-layout proof required by the realm-side deploy gatherer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QBCDeployContractV2<F: RichField> {
    pub deploy_contract: QBCDeployContract<F>,
    pub layout_protocol_version: u16,
    pub state_layout_root: QHashOut<F>,
    pub state_layout_field_count: u64,
    pub state_layout_slot_count: u64,
    pub canonical_layout_verifier_fingerprint: QHashOut<F>,
    #[ts(skip)]
    pub canonical_layout_proof: Vec<u8>,
}

impl<F: RichField> QBCDeployContractV2<F> {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.layout_protocol_version != 0, "layout protocol version must be non-zero");
        anyhow::ensure!(!self.canonical_layout_proof.is_empty(), "canonical layout proof is empty");
        anyhow::ensure!(
            self.state_layout_field_count <= self.state_layout_slot_count,
            "layout field count exceeds slot count"
        );
        let state_tree_height = self.deploy_contract.code_definition.state_tree_height;
        anyhow::ensure!(state_tree_height < 64, "contract state tree height is unsupported");
        anyhow::ensure!(
            self.state_layout_slot_count <= (1u64 << state_tree_height) * 4,
            "layout slot count exceeds contract state capacity"
        );
        Ok(())
    }
}

/// Layout-aware contract code update command.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QBCUpdateContract<F: RichField> {
    pub contract_id: u64,
    pub deployer: QHashOut<F>,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<QHashOut<F>>,
    pub code_root: QHashOut<F>,
    pub layout_protocol_version: u16,
    pub state_layout_root: QHashOut<F>,
    pub state_layout_field_count: u64,
    pub state_layout_slot_count: u64,
    pub canonical_layout_verifier_fingerprint: QHashOut<F>,
    #[ts(skip)]
    pub canonical_layout_proof: Vec<u8>,
}

impl<F: RichField> QBCUpdateContract<F> {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.contract_id != 0, "update contract id must be non-zero");
        anyhow::ensure!(self.layout_protocol_version != 0, "layout protocol version must be non-zero");
        anyhow::ensure!(!self.canonical_layout_proof.is_empty(), "canonical layout proof is empty");
        anyhow::ensure!(
            self.state_layout_field_count <= self.state_layout_slot_count,
            "layout field count exceeds slot count"
        );
        let state_tree_height = self.code_definition.state_tree_height;
        anyhow::ensure!(state_tree_height < 64, "contract state tree height is unsupported");
        anyhow::ensure!(
            self.state_layout_slot_count <= (1u64 << state_tree_height) * 4,
            "layout slot count exceeds contract state capacity"
        );
        Ok(())
    }

    pub fn into_with_whitelist_root<H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>>>(
        self,
    ) -> anyhow::Result<QBCUpdateContractWithRoot<F>> {
        QBCUpdateContractWithRoot::<F>::new::<H>(
            self.contract_id,
            self.deployer,
            self.code_definition,
            self.function_whitelist,
            self.code_root,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QBCUpdateContractWithRoot<F: RichField> {
    pub contract_id: u64,
    pub deployer: QHashOut<F>,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<QHashOut<F>>,
    pub function_whitelist_root: QHashOut<F>,
    pub code_root: QHashOut<F>,
}

impl<F: RichField> QBCUpdateContractWithRoot<F> {
    pub fn new<H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>>>(
        contract_id: u64,
        deployer: QHashOut<F>,
        code_definition: ContractCodeDefinition,
        function_whitelist: Vec<QHashOut<F>>,
        code_root: QHashOut<F>,
    ) -> anyhow::Result<Self> {
        ensure!(contract_id != 0, "update contract id must be non-zero");
        ensure!(
            function_whitelist.len() == code_definition.functions.len() * 2,
            "function_whitelist must contain two entries per function"
        );
        let mut whitelist_tree = SimpleMerkleTree::<H, QHashOut<F>>::new(CONTRACT_FUNCTION_TREE_HEIGHT);
        for (i, leaf) in function_whitelist.iter().enumerate() {
            whitelist_tree.set_leaf(i as u64, *leaf);
        }
        let function_whitelist_root = whitelist_tree.get_root();

        Ok(Self {
            contract_id,
            deployer,
            code_definition,
            function_whitelist,
            function_whitelist_root,
            code_root,
        })
    }
}

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
    #[ts(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<FunctionAbiSpec>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
pub struct QContractABI {
    pub version: String,
    pub structs: Vec<StructAbiSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct PsySlotUpdate<F: RichField> {
    pub slot: u64,
    pub old_value: F,
    pub new_value: F,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct PsyContractSlotUpdates<F: RichField> {
    pub contract_id: u32,
    pub slot_updates: Vec<PsySlotUpdate<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct PsyIMTSlotUpdate<F: RichField> {
    pub key: QHashOut<F>,
    pub old_value: QHashOut<F>,
    pub new_value: QHashOut<F>,
    pub is_insert: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct PsyIMTContractSlotUpdates<F: RichField> {
    pub contract_id: u32,
    pub slot_updates: Vec<PsyIMTSlotUpdate<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, TS)]
pub struct FieldSlotRange {
    pub field_name: String,
    pub field_type: TypeAbiSpec,
    pub start_slot: usize,
    pub end_slot: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, TS)]
pub struct StructSlotRange {
    pub struct_name: String,
    pub fields: BTreeMap<usize, FieldSlotRange>,
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

    pub fn get_field_by_slot(&self, slot: usize) -> anyhow::Result<&FieldSlotRange> {
        self.fields
            .range(..=slot)
            .next_back()
            .and_then(|(_, field)| if slot <= field.end_slot { Some(field) } else { None })
            .ok_or_else(|| anyhow::format_err!("slot {} not within any field range", slot))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, TS)]
pub struct ABISlotAnalyzer {
    abi: QContractABI,
    struct_ranges: HashMap<String, StructSlotRange>,
}

impl ABISlotAnalyzer {
    pub fn new(abi: QContractABI) -> Self {
        Self {
            abi,
            struct_ranges: HashMap::new(),
        }
    }

    pub fn new_with_analyze(abi: QContractABI) -> anyhow::Result<Self> {
        let mut analyzer = Self::new(abi);
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

    pub fn calculate_struct_total_slots(&self, struct_name: &str) -> anyhow::Result<usize> {
        let struct_spec = self.find_struct(struct_name)?;
        let total = struct_spec
            .fields
            .iter()
            .map(|field| self.calculate_type_slot_count(&field.field_type))
            .sum::<anyhow::Result<usize>>()?;
        Ok(total)
    }

    pub fn calculate_type_slot_count(&self, type_spec: &TypeAbiSpec) -> anyhow::Result<usize> {
        if type_spec.is_basic_type() {
            return Ok(1);
        }
        match type_spec {
            TypeAbiSpec::Basic(inner_type) => self.calculate_struct_total_slots(inner_type),
            TypeAbiSpec::Array { inner_type, length, .. } => {
                let elem_slot_count = self.calculate_struct_total_slots(inner_type)?;
                Ok(elem_slot_count * (*length as usize))
            }
        }
    }

    pub fn calculate_struct_field_slots(&self, struct_name: &str) -> anyhow::Result<StructSlotRange> {
        let struct_spec = self.find_struct(struct_name)?;

        let mut struct_range = StructSlotRange::new(struct_spec.name.clone());
        let mut current_slot = 0;

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

    fn get_field_by_slot_inner(&self, type_spec: &TypeAbiSpec, slot: usize, current_path: &mut String) -> anyhow::Result<()> {
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
                type_name: _,
                inner_type,
                length: _,
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

    pub fn get_field_by_slot(&self, struct_name: &str, slot: usize) -> anyhow::Result<String> {
        let mut slot_path = struct_name.to_string();
        self.get_field_by_slot_inner(&TypeAbiSpec::Basic(struct_name.to_string()), slot, &mut slot_path)?;
        Ok(slot_path)
    }
}

mod tests {

    #[test]
    fn test_qcontract_abi_serialization_and_analyze() -> anyhow::Result<()> {
        use crate::qblock::cmds::deploy_contract::{ABISlotAnalyzer, QContractABI};

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

        let token_contract_name = "PsyTokenContract";

        assert_eq!(analyzer.get_field_by_slot(token_contract_name, 0)?, "PsyTokenContract.balance");
        assert_eq!(
            analyzer.get_field_by_slot(token_contract_name, 1)?,
            "PsyTokenContract.last_claimed_pow_rewards_checkpoint_id"
        );
        assert_eq!(analyzer.get_field_by_slot(token_contract_name, 2)?, "PsyTokenContract.claimed_rewards");
        assert_eq!(
            analyzer.get_field_by_slot(token_contract_name, 3)?,
            "PsyTokenContract.other_user_info[0].amount_sent"
        );
        assert_eq!(
            analyzer.get_field_by_slot(token_contract_name, 4)?,
            "PsyTokenContract.other_user_info[0].amount_claimed"
        );
        assert_eq!(
            analyzer.get_field_by_slot(token_contract_name, 6666)?,
            "PsyTokenContract.other_user_info[3331].amount_claimed"
        );
        assert_eq!(
            analyzer.get_field_by_slot(token_contract_name, 6667)?,
            "PsyTokenContract.other_user_info[3332].amount_sent"
        );

        Ok(())
    }
}
