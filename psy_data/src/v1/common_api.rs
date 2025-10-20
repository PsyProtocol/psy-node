use parth_core::crypto::hash::tag_tree::TagTreeMerkleProof;
use psy_core::job::job_id::QProvingJobDataID;


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Copy)]
pub struct APILatestCheckpointResponse {
    pub checkpoint_id: u64,
}


#[pderive::serialize_clone_hash_job_id_ts]
#[ts(export, concrete(Hash = parth_core::PHash, JobId = QProvingJobDataID))]
pub struct PsyProoffMinerRewardProof<Hash, JobId> {
    pub job_id: JobId,
    pub tag_tree_proof: TagTreeMerkleProof<Hash>,
}