use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::{
    data::qhashout::QHashOut,
    traits::to_qfelts::{QFeltSized, ToQFelts},
};
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyContractLeaf<F: RichField> {
    pub deployer: QHashOut<F>,
    pub function_tree_root: QHashOut<F>,
    pub code_root: QHashOut<F>,
    pub state_tree_height: F,
    pub state_layout_root: QHashOut<F>,
    pub state_layout_field_count: F,
    pub state_layout_slot_count: F,
}

impl<F: RichField> KVQSerializable for PsyContractLeaf<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for PsyContractLeaf<F> {
    fn q_felt_size() -> usize {
        19
    }
}
impl<F: RichField> ToQFelts<F> for PsyContractLeaf<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![
            self.deployer.0.elements[0],
            self.deployer.0.elements[1],
            self.deployer.0.elements[2],
            self.deployer.0.elements[3],
            self.function_tree_root.0.elements[0],
            self.function_tree_root.0.elements[1],
            self.function_tree_root.0.elements[2],
            self.function_tree_root.0.elements[3],
            self.code_root.0.elements[0],
            self.code_root.0.elements[1],
            self.code_root.0.elements[2],
            self.code_root.0.elements[3],
            self.state_tree_height,
            self.state_layout_root.0.elements[0],
            self.state_layout_root.0.elements[1],
            self.state_layout_root.0.elements[2],
            self.state_layout_root.0.elements[3],
            self.state_layout_field_count,
            self.state_layout_slot_count,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 13 {
            panic!("Invalid number of elements for PsyContractLeaf");
        }
        let deployer = QHashOut::from_qfelts(&felts[0..4]);
        let function_tree_root = QHashOut::from_qfelts(&felts[4..8]);
        let code_root = QHashOut::from_qfelts(&felts[8..12]);
        let state_tree_height = felts[12];
        PsyContractLeaf {
            deployer,
            function_tree_root,
            code_root,
            state_tree_height,
            state_layout_root: QHashOut::from_qfelts(&felts[13..17]),
            state_layout_field_count: felts[17],
            state_layout_slot_count: felts[18],
        }
    }
}

impl<F: RichField> QFieldHashable<F> for PsyContractLeaf<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_hash_many(&[
            F::from_canonical_u64(0x434c_5632),
            self.deployer.0.elements[0],
            self.deployer.0.elements[1],
            self.deployer.0.elements[2],
            self.deployer.0.elements[3],
            self.function_tree_root.0.elements[0],
            self.function_tree_root.0.elements[1],
            self.function_tree_root.0.elements[2],
            self.function_tree_root.0.elements[3],
            self.code_root.0.elements[0],
            self.code_root.0.elements[1],
            self.code_root.0.elements[2],
            self.code_root.0.elements[3],
            self.state_tree_height,
            self.state_layout_root.0.elements[0],
            self.state_layout_root.0.elements[1],
            self.state_layout_root.0.elements[2],
            self.state_layout_root.0.elements[3],
            self.state_layout_field_count,
            self.state_layout_slot_count,
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[ts(export)]
pub struct ContractFunctionCodeDefinition {
    // TODO: in the future method id = sha256(functionName(arg0[arg0_size],arg1[arg1_size]))&0xffffffff
    // CURRENT: sha256(functionName + "-|-" + args_count)&0xffffffff
    pub method_id: u32,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub vm_type: u32,
    pub code: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[ts(export)]
pub struct SimpleContractFunctionCodeDefinition {
    pub method_id: u32,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub vm_type: u32,
}

impl KVQSerializable for ContractFunctionCodeDefinition {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub struct ContractCodeDefinition {
    pub state_tree_height: u16,
    pub functions: Vec<ContractFunctionCodeDefinition>,
}

impl KVQSerializable for ContractCodeDefinition {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub struct SimpleContractCodeDefinition {
    pub state_tree_height: u16,
    pub functions: Vec<SimpleContractFunctionCodeDefinition>,
}

impl From<&ContractCodeDefinition> for SimpleContractCodeDefinition {
    fn from(value: &ContractCodeDefinition) -> Self {
        Self {
            state_tree_height: value.state_tree_height,
            functions: value
                .functions
                .clone()
                .into_iter()
                .map(|f| SimpleContractFunctionCodeDefinition {
                    method_id: f.method_id,
                    num_inputs: f.num_inputs,
                    num_outputs: f.num_outputs,
                    vm_type: f.vm_type,
                })
                .collect(),
        }
    }
}
