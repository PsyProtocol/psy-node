use parth_common::memory_stores::simple_memory_merkle_store::SimpleMemoryMerkleStore;
use parth_core::{crypto::hash::traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable}, data::serializable::{FastFixedSerializable, QPDSerializable}, felt::{QFelt, QFelt64, QFeltSized, ToQFelts}, impl_qpd_serialize_params, impl_qpq_serialize_bincode, protocol::core_types::{QFHashBase, QHashBase}};
use serde::Serialize;
use ts_rs::TS;
use pser::{QBytesDeserialize, QBytesSerialize};

#[pderive::serialize_clone]
#[derive(TS)]
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
impl_qpq_serialize_bincode!(ContractFunctionCodeDefinition);

#[pderive::serialize_copy]
#[derive(TS)]
#[ts(export)]
pub struct SimpleContractFunctionCodeDefinition {
    pub method_id: u32,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub vm_type: u32,
}
impl_qpq_serialize_bincode!(SimpleContractFunctionCodeDefinition);


#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct ContractCodeDefinition {
    pub state_tree_height: u16,
    pub functions: Vec<ContractFunctionCodeDefinition>,
}
impl_qpq_serialize_bincode!(ContractCodeDefinition);


#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct SimpleContractCodeDefinition {
    pub state_tree_height: u16,
    pub functions: Vec<SimpleContractFunctionCodeDefinition>,
}
impl_qpq_serialize_bincode!(SimpleContractCodeDefinition);

impl From<&ContractCodeDefinition> for SimpleContractCodeDefinition {
    fn from(value: &ContractCodeDefinition) -> Self {
        Self {
            state_tree_height: value.state_tree_height,
            functions: value.functions.clone().into_iter().map(|f| SimpleContractFunctionCodeDefinition {
                method_id: f.method_id,
                num_inputs: f.num_inputs,
                num_outputs: f.num_outputs,
                vm_type: f.vm_type,
            }).collect(),
        }
    }
}
#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct RootConfig {
    pub genesis: GenesisConfig,
}

#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct GenesisConfig {
    pub precompiles: Vec<ContractConfig>,
}

#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct PrecompileConfig {
    pub contracts: Vec<ContractConfig>,
}

#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct ContractConfig {
    pub name: String,
    pub path: String,
    pub contract_name: String,
    pub method_names: Vec<String>,
}
impl_qpq_serialize_bincode!(RootConfig);
impl_qpq_serialize_bincode!(GenesisConfig);
impl_qpq_serialize_bincode!(PrecompileConfig);
impl_qpq_serialize_bincode!(ContractConfig);



#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "QBCDeployContract")]
pub struct PQBCDeployContract<Hash: Copy + PartialEq + Serialize> {
    pub deployer: Hash,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<Hash>,

}

impl<Hash: QHashBase> PQBCDeployContract<Hash> {
    pub fn new(deployer: Hash, code_definition: ContractCodeDefinition, function_whitelist: Vec<Hash>) -> Self {
        Self {
            deployer,
            code_definition,
            function_whitelist,
        }
    }
    pub fn into_with_whitelist_root<H: MerkleZeroHasher<Hash>>(self, contract_function_tree_height: u8) -> anyhow::Result<PQBCDeployContractWithRoot<Hash>>{
        PQBCDeployContractWithRoot::<Hash>::new::<H>(self.deployer, self.code_definition, self.function_whitelist, contract_function_tree_height)

    }
}




#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "QBCDeployContractWithRoot")]
pub struct PQBCDeployContractWithRoot<Hash> {
    pub deployer: Hash,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<Hash>,
    pub function_whitelist_root: Hash,
    

}

impl<Hash: QHashBase> PQBCDeployContractWithRoot<Hash> {
    pub fn new<H: MerkleZeroHasher<Hash>>(deployer: Hash, code_definition: ContractCodeDefinition, function_whitelist: Vec<Hash>, contract_function_tree_height: u8) -> anyhow::Result<Self> {
            let mut t = SimpleMemoryMerkleStore::<H, Hash>::new(contract_function_tree_height);
            for (i,l) in function_whitelist.iter().enumerate() {
                t.set_leaf(i as u64, *l);
            }
            let function_whitelist_root = t.get_root();

            

        Ok(Self {
            deployer,
            code_definition,
            function_whitelist,
            function_whitelist_root,
        })
    }
}

