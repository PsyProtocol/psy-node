use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::qblock::cmds::deploy_contract::QBCDeployContract;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyAPIDeployContractRequest<F: RichField> {
    pub deploy_cmd: QBCDeployContract<F>,
}

impl<F: RichField> PsyAPIDeployContractRequest<F> {
    pub fn new(deploy_cmd: QBCDeployContract<F>) -> Self {
        Self { deploy_cmd }
    }
}

impl<F: RichField> KVQSerializable for PsyAPIDeployContractRequest<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
