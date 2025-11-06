mod pending_id;
mod submit_status;
mod witness;
mod expected_public_inputs;
mod user_contract_tree_updates;
mod deploy_contract_data;
mod proof_metadata;
mod rewards_tree;


use parth_core::{protocol::core_types::QDBHashBase, QJobIdBase};
pub use proof_metadata::*;
pub use expected_public_inputs::*;
pub use pending_id::*;
pub use submit_status::*;
pub use witness::*;
pub use user_contract_tree_updates::*;
pub use deploy_contract_data::*;
pub use rewards_tree::*;

use crate::psy_temp_db::traits::rewards_tree::QTempDBRewardsTreeStore;

pub trait StandardEdgeAPITempDBStoreBase<JobId: QJobIdBase, Hash: QDBHashBase>: 
    QTempDBPendingIdStore + 
    QTempDBSubmitStatusStore + 
    QTempDBProofWitnessStore<JobId> +
    QTempDBUserContractUpdatesStore + 
    QTempDBProvingJobMetadataStore<Hash, JobId> +
    QTempDBRewardsTreeStore<Hash, JobId> +
    QTempDBDeployContractDataStore
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
    QTempDBProvingJobMetadataStore<Hash, JobId> +
    QTempDBRewardsTreeStore<Hash, JobId> +
    QTempDBDeployContractDataStore,
> StandardEdgeAPITempDBStoreBase<JobId, Hash> for T {
}


pub trait StandardProcessorTempDBStoreBase<JobId: QJobIdBase, Hash: QDBHashBase>: 
    QTempDBPendingIdStore + 
    QTempDBSubmitStatusStore + 
    QTempDBProofWitnessStore<JobId> +
    QTempDBUserContractUpdatesStore + 
    QTempDBProvingJobMetadataStore<Hash, JobId> +
    QTempDBRewardsTreeStore<Hash, JobId> +
    QTempDBDeployContractDataStore
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
    QTempDBProvingJobMetadataStore<Hash, JobId> +
    QTempDBRewardsTreeStore<Hash, JobId> +
    QTempDBDeployContractDataStore,
> StandardProcessorTempDBStoreBase<JobId, Hash> for T {
}

