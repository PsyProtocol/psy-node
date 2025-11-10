use parth_core::{QJOB_ID_SERIALIZED_SIZE, QJobIdBase};
use psy_core::job::job_id::QProvingJobDataID;

use crate::worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId;

#[pderive::serialize_clone_hash_job_id_ts]
#[ts(export, concrete(Hash = parth_core::PHash, JobId = QProvingJobDataID))]
pub struct PsyWorkerGetProvingWorkAPIResponse<Hash, JobId> {
    pub job: PsyProvingJobMetadataWithJobId<Hash, JobId>,
    pub child_proof_tag_values: Vec<Hash>,
    pub witness: Vec<u8>,
}


#[pderive::serialize_clone_ts_export]
pub struct PsyRawProofWithJobId<JobId> {
    pub job_id: JobId,
    pub proof: Vec<u8>,
}



#[pderive::serialize_clone_hash_job_id_ts]
#[ts(export, concrete(Hash = parth_core::PHash, JobId = QProvingJobDataID))]
pub struct PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId> {
    pub base: PsyWorkerGetProvingWorkAPIResponse<Hash, JobId>,
    pub input_proofs: Vec<Vec<u8>>,
}
 
pub fn encode_expected_public_inputs_hash_and_dependencies<JobId: QJobIdBase>(hash: &[u8; 32], dependencies: &[JobId]) -> Vec<u8> {
    let mut result = Vec::with_capacity(32 + 4 + dependencies.len() * QJOB_ID_SERIALIZED_SIZE);
    let dependencies_len_u32 = dependencies.len() as u32;
    result.extend_from_slice(hash);
    result.extend_from_slice(&dependencies_len_u32.to_le_bytes());
    for dep in dependencies {
        result.extend_from_slice(&dep.to_bytes_fixed());
    }
    result
}


pub fn decode_expected_public_inputs_hash_and_dependencies<JobId: QJobIdBase>(data: &[u8]) -> anyhow::Result<([u8; 32], Vec<JobId>)> {
    if data.len() < 36 {
        anyhow::bail!("data too short to contain expected public inputs hash and dependencies length");
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[0..32]);
    let dependencies_len = u32::from_le_bytes(data[32..36].try_into().unwrap()) as usize;
    let expected_len = 32 + 4 + dependencies_len * QJOB_ID_SERIALIZED_SIZE;
    if data.len() != expected_len {
        anyhow::bail!("data length mismatch: expected {}, got {}", expected_len, data.len());
    }
    let mut dependencies = Vec::with_capacity(dependencies_len);
    for i in 0..dependencies_len {
        let start = 36 + i * QJOB_ID_SERIALIZED_SIZE;
        let end = start + QJOB_ID_SERIALIZED_SIZE;
        let job_id = JobId::from_bytes(&data[start..end])?;
        dependencies.push(job_id);
    }
    Ok((hash, dependencies))
}