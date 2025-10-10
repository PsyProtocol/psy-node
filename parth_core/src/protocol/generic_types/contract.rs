use serde::{Deserialize, Serialize};

use crate::{crypto::hash::traits::MerkleZeroHasher, protocol::core_types::QHashBase};


// QBCDeployContract
#[pderive::serialize_clone]
#[serde(bound = "for<'de2> Hash: Deserialize<'de2>, for<'de3> QContractCodeDefinition: Deserialize<'de3>")]
pub struct QPBCDeployContract<Hash: QHashBase, QContractCodeDefinition: Serialize + Clone> {
    pub deployer: Hash,
    pub code_definition: QContractCodeDefinition,
    pub function_whitelist: Vec<Hash>,
}


// QBCDeployContractWithRoot
#[pderive::serialize_clone]
#[serde(bound = "for<'de2> Hash: Deserialize<'de2>, for<'de3> QContractCodeDefinition: Deserialize<'de3>")]
pub struct QBCDeployContractWithRoot<Hash: QHashBase, QContractCodeDefinition: Serialize + Clone> {
    pub deployer: Hash,
    pub function_whitelist_root: Hash,
    pub code_definition: QContractCodeDefinition,
    pub function_whitelist: Vec<Hash>,
}





impl<Hash: QHashBase, QContractCodeDefinition: Serialize + Clone> QBCDeployContractWithRoot<Hash, QContractCodeDefinition> {
    pub fn new(deployer: Hash, code_definition: QContractCodeDefinition, function_whitelist: Vec<Hash>, function_whitelist_root: Hash) -> anyhow::Result<Self> {
        Ok(Self {
            deployer,
            code_definition,
            function_whitelist,
            function_whitelist_root,
        })
    }
}

