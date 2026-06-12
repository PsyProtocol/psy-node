mod pending_id;
mod submit_status;
mod witness;
mod expected_public_inputs;
mod user_contract_tree_updates;
mod user_end_cap_slot_updates;
mod deploy_contract_data;
mod proof_metadata;
mod rewards_tree;
mod node_proving_state;
mod job_claim_info;
mod worker_reputation;

use parth_core::{protocol::core_types::QDBHashBase, QJobIdBase};
pub use proof_metadata::*;
pub use expected_public_inputs::*;
pub use pending_id::*;
pub use submit_status::*;
pub use witness::*;
pub use user_contract_tree_updates::*;
pub use user_end_cap_slot_updates::*;
pub use deploy_contract_data::*;
pub use rewards_tree::*;
pub use node_proving_state::*;
pub use job_claim_info::*;
pub use worker_reputation::*;


pub trait StandardEdgeAPITempDBStoreBase<JobId: QJobIdBase, Hash: QDBHashBase>: 
    QTempDBPendingIdStore + 
    QTempDBSubmitStatusStore + 
    QTempDBProofWitnessStore<JobId> +
    QTempDBUserContractUpdatesStore + 
    QTempDBUserEndCapSlotUpdatesStore +
    QTempDBProvingJobMetadataStore<Hash, JobId> +
    QTempDBRewardsTreeStore<Hash, JobId> +
    QTempDBDeployContractDataStore + 
    QTempDBNodeProvingStateStore +
    QTempDBJobClaimInfoStore<JobId> +
    QTempDBWorkerReputationStore
{

}
impl<

    JobId: QJobIdBase,
    Hash: QDBHashBase,
    T: 
    QTempDBPendingIdStore + 
    QTempDBSubmitStatusStore + 
    QTempDBProofWitnessStore<JobId> +
    QTempDBUserContractUpdatesStore + 
    QTempDBUserEndCapSlotUpdatesStore +
    QTempDBProvingJobMetadataStore<Hash, JobId> +
    QTempDBRewardsTreeStore<Hash, JobId> +
    QTempDBDeployContractDataStore +
    QTempDBNodeProvingStateStore +
    QTempDBJobClaimInfoStore<JobId> +
    QTempDBWorkerReputationStore,
> StandardEdgeAPITempDBStoreBase<JobId, Hash> for T {
}


pub trait StandardProcessorTempDBStoreBase<JobId: QJobIdBase, Hash: QDBHashBase>: 
    QTempDBPendingIdStore + 
    QTempDBSubmitStatusStore + 
    QTempDBProofWitnessStore<JobId> +
    QTempDBUserContractUpdatesStore +
    QTempDBUserEndCapSlotUpdatesStore +
    QTempDBProvingJobMetadataStore<Hash, JobId> +
    QTempDBRewardsTreeStore<Hash, JobId> +
    QTempDBDeployContractDataStore +
    QTempDBNodeProvingStateStore +
    QTempDBJobClaimInfoStore<JobId> +
    QTempDBWorkerReputationStore
{

}
impl<

    JobId: QJobIdBase,
    Hash: QDBHashBase,
    T: 
    QTempDBPendingIdStore + 
    QTempDBSubmitStatusStore + 
    QTempDBProofWitnessStore<JobId> +
    QTempDBUserContractUpdatesStore +
    QTempDBUserEndCapSlotUpdatesStore +
    QTempDBProvingJobMetadataStore<Hash, JobId> +
    QTempDBRewardsTreeStore<Hash, JobId> +
    QTempDBDeployContractDataStore +
    QTempDBNodeProvingStateStore +
    QTempDBJobClaimInfoStore<JobId> +
    QTempDBWorkerReputationStore,
> StandardProcessorTempDBStoreBase<JobId, Hash> for T {
}
