#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{QJOB_ID_SERIALIZED_SIZE, QJobIdBase, protocol::core_types::Q256BitHash};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId;

pub const PROVING_JOB_NODE_TYPE_REALM: u8 = 1;
pub const PROVING_JOB_NODE_TYPE_COORDINATOR: u8 = 2;

#[pderive::serialize_clone_hash_job_id_ts]
#[ts(export, concrete(Hash = parth_core::PHash, JobId = QProvingJobDataID))]
pub struct PsyWorkerGetProvingWorkAPIResponse<Hash, JobId> {
    pub job: PsyProvingJobMetadataWithJobId<Hash, JobId>,
    pub child_proof_tag_values: Vec<Hash>,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_pending_id: u64,
    pub node_type: u8,
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

impl<Hash, JobId> PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId> {
    pub fn ensure_expected_child_proof_count_with_tags(&self, expected_child_proof_count: usize) -> anyhow::Result<()> {
        if self.input_proofs.len() != expected_child_proof_count {
            anyhow::bail!("invalid input_proofs in API response: expected {} proofs, got {} proofs", expected_child_proof_count, self.input_proofs.len());
        }
        if self.base.child_proof_tag_values.len() != expected_child_proof_count {
            anyhow::bail!("invalid child_proof_tag_values in API response: expected {} tags, got {} tags", expected_child_proof_count, self.base.child_proof_tag_values.len());
        }
        if self.base.job.metadata.dependencies.len() != expected_child_proof_count {
            anyhow::bail!("invalid dependencies in job metadata from API response: expected {} dependencies, got {} dependencies", expected_child_proof_count, self.base.job.metadata.dependencies.len());
        }
        Ok(())
    }
    pub fn ensure_expected_child_proof_count(&self, expected_child_proof_count: usize) -> anyhow::Result<()> {
        if self.input_proofs.len() != expected_child_proof_count {
            anyhow::bail!("invalid input_proofs in API response: expected {} proofs, got {} proofs", expected_child_proof_count, self.input_proofs.len());
        }
        if self.base.job.metadata.dependencies.len() != expected_child_proof_count {
            anyhow::bail!("invalid dependencies in job metadata from API response: expected {} dependencies, got {} dependencies", expected_child_proof_count, self.base.job.metadata.dependencies.len());
        }
        Ok(())
    }
}

impl<Hash> PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID> {

    pub fn ensure_expected_child_proof_circuit_types_with_tags(&self, expected_circuit_types: &[ProvingJobCircuitType]) -> anyhow::Result<()> {
        let expected_child_proof_count = expected_circuit_types.len();
        self.ensure_expected_child_proof_count_with_tags(expected_child_proof_count)?;
        for (i, expected_circuit_type) in expected_circuit_types.iter().enumerate() {
            let actual_circuit_type = self.base.job.metadata.dependencies[i].circuit_type;
            if &actual_circuit_type != expected_circuit_type {
                anyhow::bail!("invalid circuit type for dependency {} in job metadata from API response: expected {:?}, got {:?}", i, expected_circuit_type, actual_circuit_type);
            }
        }
        Ok(())
    }
    pub fn get_child_proof_circuit_type(&self, index: usize) -> anyhow::Result<ProvingJobCircuitType> {
        if index >= self.base.job.metadata.dependencies.len() {
            anyhow::bail!("index {} out of bounds for dependencies in job metadata from API response (len = {})", index, self.base.job.metadata.dependencies.len());
        }
        Ok(self.base.job.metadata.dependencies[index].circuit_type)
    }
    pub fn get_child_proof_circuit_types(&self) -> Vec<ProvingJobCircuitType> {
        self.base.job.metadata.dependencies.iter().map(|d| d.circuit_type).collect()
    }
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


// ================================================================================================
// PsyWorkerGetProvingWorkAPIResponse
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom, JobId: QPGenRandom> QPGenRandom for PsyWorkerGetProvingWorkAPIResponse<Hash, JobId> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            job: PsyProvingJobMetadataWithJobId::qp_rand_gen(),
            child_proof_tag_values: QPGenRandom::qp_rand_gen_vec_in_range(0, 5),
            realm_id: u64::qp_rand_gen(),
            realm_sub_id: u64::qp_rand_gen(),
            unique_pending_id: u64::qp_rand_gen(),
            node_type: u8::qp_rand_gen(),
            witness: QPGenRandom::qp_rand_gen_vec_in_range(0, 32),
        }
    }
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> PsyCanonicalSerializeMetadata for PsyWorkerGetProvingWorkAPIResponse<Hash, JobId> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> FallbackPsySerializeCanonical for PsyWorkerGetProvingWorkAPIResponse<Hash, JobId> {
    fn fallback_pio_serialized_size(&self) -> usize {
        let mut size = self.job.pio_serialized_size();
        // child_proof_tag_values: vec len (4) + items * 32
        size += 4 + (self.child_proof_tag_values.len() * 32);
        // realm_id (8) + realm_sub_id (8) + unique_pending_id (8) + node_type (1)
        size += 8 + 8 + 8 + 1;
        // witness: vec len (4) + bytes
        size += 4 + self.witness.len();
        size
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.job.pio_write_to_io(writer)?;
        
        writer.psy_write_vec_length(self.child_proof_tag_values.len())?;
        for hash in &self.child_proof_tag_values {
            writer.psy_write_bytes_fixed(&hash.into_owned_32bytes())?;
        }

        writer.psy_write_u64(self.realm_id)?;
        writer.psy_write_u64(self.realm_sub_id)?;
        writer.psy_write_u64(self.unique_pending_id)?;
        writer.psy_write_u8(self.node_type)?;
        
        writer.psy_write_bytes_vec(&self.witness)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let job = PsyProvingJobMetadataWithJobId::<Hash, JobId>::pio_read_from_io(reader)?;

        let child_proof_len = reader.psy_read_vec_length()?;
        let mut child_proof_tag_values = Vec::with_capacity(child_proof_len);
        for _ in 0..child_proof_len {
            let hash_bytes = reader.psy_read_bytes_32()?;
            child_proof_tag_values.push(Hash::from_owned_32bytes(hash_bytes));
        }

        let realm_id = reader.psy_read_u64()?;
        let realm_sub_id = reader.psy_read_u64()?;
        let unique_pending_id = reader.psy_read_u64()?;
        let node_type = reader.psy_read_u8()?;
        let witness = reader.psy_read_bytes_vec()?;

        Ok(Self {
            job,
            child_proof_tag_values,
            realm_id,
            realm_sub_id,
            unique_pending_id,
            node_type,
            witness,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyWorkerGetProvingWorkAPIResponse,
    { Hash: Q256BitHash, JobId: QJobIdBase } => { Hash, JobId }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash, JobId: QJobIdBase> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyWorkerGetProvingWorkAPIResponse<Hash, JobId>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyWorkerGetProvingWorkAPIResponse,
    { parth_core::PHash, psy_core::job::job_id::QProvingJobDataID },
    psy_worker_get_proving_work_api_response_tests
);


// ================================================================================================
// PsyWorkerGetProvingWorkWithChildProofsAPIResponse
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom, JobId: QPGenRandom> QPGenRandom for PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        // Generate a few random proofs for the vec<vec<u8>>
        let mut input_proofs = Vec::new();
        let vec_len = u8::qp_rand_gen() as usize % 5; // limit to max 5 proofs
        for _ in 0..vec_len {
            input_proofs.push(QPGenRandom::qp_rand_gen_vec_in_range(0,32));
        }

        Self {
            base: PsyWorkerGetProvingWorkAPIResponse::qp_rand_gen(),
            input_proofs,
        }
    }
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> PsyCanonicalSerializeMetadata for PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> FallbackPsySerializeCanonical for PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId> {
    fn fallback_pio_serialized_size(&self) -> usize {
        let mut size = self.base.pio_serialized_size();
        // input_proofs: vec length (4)
        size += 4;
        // each proof: vec length (4) + bytes
        for proof in &self.input_proofs {
            size += 4 + proof.len();
        }
        size
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.base.pio_write_to_io(writer)?;
        
        writer.psy_write_vec_length(self.input_proofs.len())?;
        for proof in &self.input_proofs {
            writer.psy_write_bytes_vec(proof)?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let base = PsyWorkerGetProvingWorkAPIResponse::<Hash, JobId>::pio_read_from_io(reader)?;

        let proofs_len = reader.psy_read_vec_length()?;
        let mut input_proofs = Vec::with_capacity(proofs_len);
        for _ in 0..proofs_len {
            input_proofs.push(reader.psy_read_bytes_vec()?);
        }

        Ok(Self {
            base,
            input_proofs,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
    { Hash: Q256BitHash, JobId: QJobIdBase } => { Hash, JobId }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash, JobId: QJobIdBase> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
    { parth_core::PHash, psy_core::job::job_id::QProvingJobDataID },
    psy_worker_get_proving_work_with_child_proofs_api_response_tests
);