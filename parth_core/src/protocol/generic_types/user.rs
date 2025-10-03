use serde::{Deserialize, Serialize};

use crate::protocol::core_types::QHashBase;


// ZKPublicKeyInfo
#[derive(
    Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash
)]
#[serde(bound = "for<'de2> Hash: Deserialize<'de2>")]
pub struct QPUserPublicKeyInfo<Hash: QHashBase> {
    pub fingerprint: Hash,
    pub public_key_param: Hash,
}

// QBCDeployContract
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> Hash: Deserialize<'de2>, for<'de3> QContractCodeDefinition: Deserialize<'de3>")]
pub struct QPDeployContract<Hash: QHashBase, QContractCodeDefinition: Serialize + Clone> {
    pub deployer: Hash,
    pub code_definition: QContractCodeDefinition,
    pub function_whitelist: Vec<Hash>,
}



#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> Hash: Deserialize<'de2>, for<'de3> QContractCodeDefinition: Deserialize<'de3>")]
pub struct QBCDeployContractWithRoot<Hash: QHashBase, QContractCodeDefinition: Serialize + Clone> {
    pub deployer: Hash,
    pub function_whitelist_root: Hash,
    pub code_definition: QContractCodeDefinition,
    pub function_whitelist: Vec<Hash>,
}

