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

#[cfg(test)]
mod tests {
    use parth_core::{utils::QPGenRandom, PHash};
    use psy_core::job::job_id::QProvingJobDataID;

    use super::{APILatestCheckpointResponse, PsyProoffMinerRewardProof};

    #[test]
    fn latest_checkpoint_response_serde_and_debug_round_trip() {
        let response = APILatestCheckpointResponse { checkpoint_id: 42 };
        let json = serde_json::to_string(&response).unwrap();
        let restored = serde_json::from_str::<APILatestCheckpointResponse>(&json).unwrap();
        assert_eq!(restored.checkpoint_id, response.checkpoint_id);
        assert_eq!(response.checkpoint_id, 42);
        assert!(format!("{:?}", response).contains("checkpoint_id"));

        let zero = APILatestCheckpointResponse { checkpoint_id: 0 };
        let restored_zero = serde_json::from_str::<APILatestCheckpointResponse>(&serde_json::to_string(&zero).unwrap()).unwrap();
        assert_eq!(restored_zero.checkpoint_id, 0);
    }

    #[test]
    fn miner_reward_proof_serde_clone_and_debug() {
        let value = PsyProoffMinerRewardProof::<PHash, QProvingJobDataID> {
            job_id: QProvingJobDataID::qp_rand_gen(),
            tag_tree_proof: parth_core::crypto::hash::tag_tree::TagTreeMerkleProof::qp_rand_gen(),
        };
        let cloned = value.clone();
        assert_eq!(cloned, value);

        let json = serde_json::to_string(&value).unwrap();
        let restored = serde_json::from_str::<PsyProoffMinerRewardProof<PHash, QProvingJobDataID>>(&json).unwrap();
        assert_eq!(restored.job_id, value.job_id);
        assert_eq!(restored.tag_tree_proof, value.tag_tree_proof);
        assert!(format!("{:?}", value).contains("PsyProoffMinerRewardProof"));
    }
}