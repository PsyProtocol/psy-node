use std::fmt::Display;

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use async_trait::async_trait;
use crate::{common::{data::protocol::job::QPWorkerJobDataID, traits::serializable::QPDSerializable}, impl_qpq_serialize_bincode};


#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum QPRequestJobFailedReason {
    Success = 0, // requesting the proof was successful
    NoJobsPending = 1,
    WorkerReputationScoreTooLow = 2,
}
impl QPRequestJobFailedReason {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<QPRequestJobFailedReason> for u8 {
    fn from(value: QPRequestJobFailedReason) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for QPRequestJobFailedReason {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QPRequestJobFailedReason::Success),
            1 => Ok(QPRequestJobFailedReason::NoJobsPending),
            2 => Ok(QPRequestJobFailedReason::WorkerReputationScoreTooLow),
            _ => Err(anyhow::format_err!("Invalid QPRequestJobFailedReason value: {}", value)),
        }
    }
}
impl Display for QPRequestJobFailedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QPRequestJobFailedReason::Success => write!(f, "Success"),
            QPRequestJobFailedReason::NoJobsPending => write!(f, "NoJobsPending"),
            QPRequestJobFailedReason::WorkerReputationScoreTooLow => write!(f, "WorkerReputationScoreTooLow"),
        }
    }
}


// the unique key for storing a random number when a user submits the data to a realm to prevent double submissions in a block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct QPJobManagerRequestJobResponse{
    // helps tell us where the data is stored
    pub job_id: QPWorkerJobDataID,
    pub failed_reason: QPRequestJobFailedReason,
}


impl_qpq_serialize_bincode!(QPJobManagerRequestJobResponse);

#[async_trait]
pub trait QPJobManagerProcessor {

    // the methods below are used by the processor to add jobs to the queue
    // adds new jobs to the queue
    async fn enqueue_new_jobs(&self, job_ids: &[QPWorkerJobDataID]) -> anyhow::Result<()>;
    // used by processors to wait for jobs to be completed
    async fn wait_for_all_jobs_to_be_completed(&self) -> anyhow::Result<()>;
    

}

#[async_trait]
pub trait QPJobManagerEdge {

    // the methods below are used by the realm/coordinator edge nodes
    // requests to dequeue a job for the worker id, if there are no jobs pending or the worker's reputation score is too low, it returns an error. 
    // It also sets the max time out time the worker has to submit the job, if the worker does not submit the job by then, it will be re-enqueued for another worker to pick up and the worker's reputation score will be decreased
    async fn request_job_id_for_worker_id(&self, worker_id: u64, max_timeout_time: u64) -> anyhow::Result<QPJobManagerRequestJobResponse>;
    async fn get_reputation_score_for_worker_id(&self, worker_id: u64) -> anyhow::Result<i64>;
    // returns true if the job was submitted in time and successfully, false if the job was not found or the job was already submitted or the job timed out
    async fn submit_job_result(&self, worker_id: u64, job_id: QPWorkerJobDataID) -> anyhow::Result<bool>;
    

}


pub trait QPJobManager: QPJobManagerEdge + QPJobManagerProcessor {}
impl<T: QPJobManagerEdge + QPJobManagerProcessor> QPJobManager for T {}
