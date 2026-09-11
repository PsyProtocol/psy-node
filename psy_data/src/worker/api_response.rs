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

#[cfg(test)]
mod behavior_tests {
    use parth_core::pgoldilocks::QHashOut;
    use parth_core::PF;
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    use super::*;
    use crate::worker::metadata::PsyProvingJobMetadata;

    type Hash = QHashOut<PF>;

    fn job(circuit_type: ProvingJobCircuitType, task: u32) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(7, 1, circuit_type, 0, task)
    }

    fn response(dependencies: Vec<QProvingJobDataID>) -> PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID> {
        let count = dependencies.len();
        PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base: PsyWorkerGetProvingWorkAPIResponse {
                job: PsyProvingJobMetadataWithJobId {
                    job_id: job(ProvingJobCircuitType::Unknown, 99),
                    metadata: PsyProvingJobMetadata {
                        expected_public_inputs_hash: Hash::default(),
                        reward_tree_node_index: 0,
                        reward_tree_node_level: 0,
                        reward_tree_hash_mode: 0,
                        reward_tree_node_children: count as u16,
                        dependencies,
                    },
                },
                child_proof_tag_values: vec![Hash::default(); count],
                realm_id: 1,
                realm_sub_id: 2,
                unique_pending_id: 3,
                node_type: PROVING_JOB_NODE_TYPE_REALM,
                witness: vec![4, 5],
            },
            input_proofs: vec![vec![6]; count],
        }
    }

    #[test]
    fn expected_hash_dependency_encoding_round_trips_and_rejects_bad_data() {
        let hash = [42u8; 32];
        let dependencies = vec![
            job(ProvingJobCircuitType::UserEndCap, 1),
            job(ProvingJobCircuitType::GUTATwoGUTA, 2),
        ];
        let encoded = encode_expected_public_inputs_hash_and_dependencies(&hash, &dependencies);
        let (decoded_hash, decoded_dependencies) =
            decode_expected_public_inputs_hash_and_dependencies::<QProvingJobDataID>(&encoded).unwrap();
        assert_eq!(decoded_hash, hash);
        assert_eq!(decoded_dependencies, dependencies);

        let empty = encode_expected_public_inputs_hash_and_dependencies::<QProvingJobDataID>(&hash, &[]);
        assert_eq!(decode_expected_public_inputs_hash_and_dependencies::<QProvingJobDataID>(&empty).unwrap(), (hash, vec![]));
        assert!(decode_expected_public_inputs_hash_and_dependencies::<QProvingJobDataID>(&encoded[..35]).is_err());

        let mut wrong_length = encoded.clone();
        wrong_length[32..36].copy_from_slice(&3u32.to_le_bytes());
        assert!(decode_expected_public_inputs_hash_and_dependencies::<QProvingJobDataID>(&wrong_length).is_err());

        let mut invalid_job = encoded;
        invalid_job[36] = 200;
        assert!(decode_expected_public_inputs_hash_and_dependencies::<QProvingJobDataID>(&invalid_job).is_err());
    }

    #[test]
    fn child_count_validation_reports_each_mismatch() {
        let dependencies = vec![job(ProvingJobCircuitType::UserEndCap, 1)];
        let valid = response(dependencies);
        assert!(valid.ensure_expected_child_proof_count(1).is_ok());
        assert!(valid.ensure_expected_child_proof_count_with_tags(1).is_ok());

        let mut bad_proofs = valid.clone();
        bad_proofs.input_proofs.clear();
        assert!(bad_proofs.ensure_expected_child_proof_count(1).unwrap_err().to_string().contains("input_proofs"));

        let mut bad_tags = valid.clone();
        bad_tags.base.child_proof_tag_values.clear();
        assert!(bad_tags.ensure_expected_child_proof_count_with_tags(1).unwrap_err().to_string().contains("child_proof_tag_values"));

        let mut bad_dependencies = valid;
        bad_dependencies.base.job.metadata.dependencies.clear();
        assert!(bad_dependencies.ensure_expected_child_proof_count(1).unwrap_err().to_string().contains("dependencies"));
    }

    #[test]
    fn circuit_type_helpers_validate_order_and_bounds() {
        let expected = [ProvingJobCircuitType::UserEndCap, ProvingJobCircuitType::GUTATwoGUTA];
        let value = response(vec![job(expected[0], 1), job(expected[1], 2)]);
        assert!(value.ensure_expected_child_proof_circuit_types_with_tags(&expected).is_ok());
        assert_eq!(value.get_child_proof_circuit_type(0).unwrap(), expected[0]);
        assert_eq!(value.get_child_proof_circuit_types(), expected);
        assert!(value.get_child_proof_circuit_type(2).is_err());

        let reversed = [expected[1], expected[0]];
        assert!(value.ensure_expected_child_proof_circuit_types_with_tags(&reversed).is_err());
    }

    #[test]
    fn child_proofs_response_fallback_serialization_handles_empty_and_non_empty_proofs() {
        let base = PsyWorkerGetProvingWorkAPIResponse {
            job: PsyProvingJobMetadataWithJobId {
                job_id: job(ProvingJobCircuitType::Unknown, 99),
                metadata: PsyProvingJobMetadata {
                    expected_public_inputs_hash: Hash::default(),
                    reward_tree_node_index: 0,
                    reward_tree_node_level: 0,
                    reward_tree_hash_mode: 0,
                    reward_tree_node_children: 0,
                    dependencies: vec![],
                },
            },
            child_proof_tag_values: vec![Hash::default(), Hash::default()],
            realm_id: 1,
            realm_sub_id: 2,
            unique_pending_id: 3,
            node_type: PROVING_JOB_NODE_TYPE_COORDINATOR,
            witness: vec![4, 5],
        };
        let empty_proofs = PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base: base.clone(),
            input_proofs: vec![],
        };
        let with_proofs = PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base,
            input_proofs: vec![vec![7; 10], vec![]],
        };

        let empty_bytes = empty_proofs.fallback_psy_ser_to_bytes_vec().unwrap();
        let proof_bytes = with_proofs.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(empty_bytes.len(), empty_proofs.fallback_pio_serialized_size());
        assert_eq!(proof_bytes.len(), with_proofs.fallback_pio_serialized_size());
        // Only the two proof length prefixes plus the 10 proof bytes differ.
        assert_eq!(proof_bytes.len() - empty_bytes.len(), 4 + 4 + 10);

        // The fallback decoder cannot be used for this type: the speedy-buffered
        // read of `base` drains a small cursor into its 8 KiB circular buffer, so
        // the trailing direct reads of `input_proofs` hit EOF. Decode through the
        // active in-memory reader instead.
        let decoded = PsyWorkerGetProvingWorkWithChildProofsAPIResponse::<Hash, QProvingJobDataID>::psy_ser_from_slice(&proof_bytes).unwrap();
        assert_eq!(decoded, with_proofs);
        assert_eq!(decoded.input_proofs, vec![vec![7u8; 10], vec![]]);
        assert_eq!(decoded.base.node_type, PROVING_JOB_NODE_TYPE_COORDINATOR);
        assert_eq!(decoded.base.child_proof_tag_values.len(), 2);

        let decoded_empty = PsyWorkerGetProvingWorkWithChildProofsAPIResponse::<Hash, QProvingJobDataID>::psy_ser_from_slice(&empty_bytes).unwrap();
        assert_eq!(decoded_empty, empty_proofs);
        assert!(decoded_empty.input_proofs.is_empty());
    }

    #[test]
    fn raw_proof_with_job_id_keeps_its_fields() {
        let raw = PsyRawProofWithJobId {
            job_id: job(ProvingJobCircuitType::UserEndCap, 1),
            proof: vec![1, 2, 3],
        };
        assert_eq!(raw.job_id, job(ProvingJobCircuitType::UserEndCap, 1));
        assert_eq!(raw.proof, vec![1, 2, 3]);
    }
}


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
