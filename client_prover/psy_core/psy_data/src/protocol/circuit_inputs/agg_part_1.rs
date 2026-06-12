use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_crypto::hash::merkle::treeprover::AggStateTransition;
use serde::{Deserialize, Serialize};

use crate::guta::header::GlobalUserTreeAggregatorHeader;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QCAggUserRegistartionDeployContractsGUTAInput<F: RichField> {
    pub register_users_state_transition: AggStateTransition<F>,
    pub deploy_contracts_state_transition: AggStateTransition<F>,
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F>,
}

impl<F: RichField> KVQSerializable for QCAggUserRegistartionDeployContractsGUTAInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
