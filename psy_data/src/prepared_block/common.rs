use parth_core::{JobIDWithRewardPathSerializable, QProvingJobDataIDWithRewardPathResolver};

use crate::{v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState}, worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId};


#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyCoordinatorPendingCheckpointBase<F, Hash> {
    pub block_state: QEDL2BlockState,
    pub state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub checkpoint_leaf_hash: Hash,
    pub checkpoint_tree_root: Hash,
}

#[derive(Clone)]
pub struct PsyGathererPreparedResult<R, Hash, JobId> {
    pub result: R,
    pub job_ids: Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>,
}

impl<R, Hash, JobId> PsyGathererPreparedResult<R, Hash, JobId> {
    pub fn new(result: R, job_ids: Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>) -> Self {
        Self { result, job_ids }
    }
}