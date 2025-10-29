use crate::{agg::AggStateTransition, guta::header::GlobalUserTreeAggregatorHeader};




#[pderive::serialize_copy_f_hash]
pub struct QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    pub register_users_state_transition: AggStateTransition<Hash>,
    pub deploy_contracts_state_transition: AggStateTransition<Hash>,
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
}
