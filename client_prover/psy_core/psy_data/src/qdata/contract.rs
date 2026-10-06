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
    pub deployer: F,
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
        16
    }
}
impl<F: RichField> ToQFelts<F> for PsyContractLeaf<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![
            self.deployer,
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
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for PsyContractLeaf");
        }
        let deployer = felts[0];
        let function_tree_root = QHashOut::from_qfelts(&felts[1..5]);
        let code_root = QHashOut::from_qfelts(&felts[5..9]);
        let state_tree_height = felts[9];
        PsyContractLeaf {
            deployer,
            function_tree_root,
            code_root,
            state_tree_height,
            state_layout_root: QHashOut::from_qfelts(&felts[10..14]),
            state_layout_field_count: felts[14],
            state_layout_slot_count: felts[15],
        }
    }
}

impl<F: RichField> QFieldHashable<F> for PsyContractLeaf<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_hash_many(&[
            F::from_canonical_u64(0x434c_5633),
            self.deployer,
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

#[cfg(test)]
mod tests {
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
    use psy_client_common::{data::qhashout::QHashOut, traits::to_qfelts::{QFeltSized, ToQFelts}};

    use super::PsyContractLeaf;

    type F = GoldilocksField;

    fn distinct_leaf() -> PsyContractLeaf<F> {
        PsyContractLeaf {
            deployer: F::from_canonical_u64(1),
            function_tree_root: QHashOut::from_values(5, 6, 7, 8),
            code_root: QHashOut::from_values(9, 10, 11, 12),
            state_tree_height: F::from_canonical_u64(16),
            state_layout_root: QHashOut::from_values(13, 14, 15, 16),
            state_layout_field_count: F::from_canonical_u64(3),
            state_layout_slot_count: F::from_canonical_u64(8),
        }
    }

    #[test]
    fn nonzero_distinct_fields_roundtrip_preserves_all_fields() {
        let leaf = distinct_leaf();
        let felts = leaf.to_qfelts();
        assert_eq!(felts.len(), PsyContractLeaf::<F>::q_felt_size());
        assert_eq!(felts.len(), 16);
        let recovered = PsyContractLeaf::<F>::from_qfelts(&felts);
        assert_eq!(recovered, leaf);
    }
}
