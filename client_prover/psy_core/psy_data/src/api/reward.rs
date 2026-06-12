use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};
use psy_client_common::{data::qhashout::QHashOut, job::id::QProvingJobDataID};
use psy_crypto::hash::merkle::{tag_tree::TagTreeMerkleProof, utils::common::SimpleMerkleNodeKey};
use serde::{Deserialize, Serialize};

/// Record size for PsyProvingJobClaimMetadata serialization
/// Calculation:
/// - job_id: 24 bytes without slot_id
/// - reward_tree_tag: 32 bytes
/// - reward_tree_tag_preimage: 32 bytes
/// - proving_duration_ms: 8 bytes
/// - job_submitted_at: 8 bytes
/// - unique_pending_id: 8 bytes
/// - realm_id: 8 bytes
/// - realm_sub_id: 8 bytes
/// - reward_tree_node_key: 9 bytes (1 level + 8 index)
/// - reward_tree_hash_mode: 1 byte
/// - reward_tree_node_children: 2 bytes
/// - node_type: 1 byte
/// - api_url_hash: 32 bytes
/// Total: 173 bytes
pub const PSY_PROVING_JOB_CLAIM_METADATA_SIZE: usize = 173;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct PsyProoffMinerRewardProof<Hash> {
    pub job_id: QProvingJobDataID,
    pub tag_tree_proof: TagTreeMerkleProof<Hash>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct PsyProoffMinerRewardProofWithRewardPreimage<Hash> {
    pub inner: PsyProoffMinerRewardProof<Hash>,
    pub reward_tree_tag_preimage: Hash,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd)]
pub struct PsyProvingJobClaimMetadata<Hash, JobId> {
    pub job_id: JobId,
    pub reward_tree_tag: Hash,
    pub reward_tree_tag_preimage: Hash,
    pub proving_duration_ms: u64,
    pub job_submitted_at: u64,
    pub unique_pending_id: u64,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub reward_tree_node_key: SimpleMerkleNodeKey,
    pub reward_tree_hash_mode: u8,
    pub reward_tree_node_children: u16,
    pub node_type: u8,
    pub api_url_hash: [u8; 32],
}

impl<Hash, JobId> PsyProvingJobClaimMetadata<Hash, JobId> {
    /// Fixed size of each record in bytes
    pub const fn record_size() -> usize {
        PSY_PROVING_JOB_CLAIM_METADATA_SIZE
    }
}

impl PsyProvingJobClaimMetadata<QHashOut<GoldilocksField>, QProvingJobDataID> {
    /// Deserialize PsyProvingJobClaimMetadata from a byte slice (173 bytes per
    /// record) Format matches the backup file format from psy-node
    pub fn psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < PSY_PROVING_JOB_CLAIM_METADATA_SIZE {
            anyhow::bail!(
                "Insufficient data: expected at least {} bytes, got {}",
                PSY_PROVING_JOB_CLAIM_METADATA_SIZE,
                data.len()
            );
        }

        let mut offset = 0usize;

        // job_id: 24 bytes (psy-node format, no slot_id field)
        let job_id = QProvingJobDataID::try_from_byte_vec_without_slot_id(&data[offset..offset + 24])?;
        offset += 24;

        // reward_tree_tag: 32 bytes (little-endian)
        let reward_tree_tag_bytes: [u8; 32] = data[offset..offset + 32].try_into()?;
        offset += 32;
        let reward_tree_tag = QHashOut::<GoldilocksField>(HashOut::from_bytes(&reward_tree_tag_bytes)?);

        // reward_tree_tag_preimage: 32 bytes (little-endian)
        let reward_tree_tag_preimage_bytes: [u8; 32] = data[offset..offset + 32].try_into()?;
        offset += 32;
        let reward_tree_tag_preimage = QHashOut::<GoldilocksField>(HashOut::from_bytes(&reward_tree_tag_preimage_bytes)?);

        // proving_duration_ms: 8 bytes (little-endian)
        let proving_duration_ms = u64::from_le_bytes(data[offset..offset + 8].try_into()?);
        offset += 8;

        // job_submitted_at: 8 bytes (little-endian)
        let job_submitted_at = u64::from_le_bytes(data[offset..offset + 8].try_into()?);
        offset += 8;

        // unique_pending_id: 8 bytes (little-endian)
        let unique_pending_id = u64::from_le_bytes(data[offset..offset + 8].try_into()?);
        offset += 8;

        // realm_id: 8 bytes (little-endian)
        let realm_id = u64::from_le_bytes(data[offset..offset + 8].try_into()?);
        offset += 8;

        // realm_sub_id: 8 bytes (little-endian)
        let realm_sub_id = u64::from_le_bytes(data[offset..offset + 8].try_into()?);
        offset += 8;

        // reward_tree_node_key: 9 bytes (1 byte level + 8 bytes little-endian index)
        let reward_tree_node_key_level = data[offset];
        offset += 1;
        let reward_tree_node_key_index = u64::from_le_bytes(data[offset..offset + 8].try_into()?);
        offset += 8;
        let reward_tree_node_key = SimpleMerkleNodeKey {
            level: reward_tree_node_key_level,
            index: reward_tree_node_key_index,
        };

        // reward_tree_hash_mode: 1 byte
        let reward_tree_hash_mode = data[offset];
        offset += 1;

        // reward_tree_node_children: 2 bytes (little-endian)
        let reward_tree_node_children = u16::from_le_bytes(data[offset..offset + 2].try_into()?);
        offset += 2;

        // node_type: 1 byte
        let node_type = data[offset];
        offset += 1;

        // api_url_hash: 32 bytes
        let api_url_hash: [u8; 32] = data[offset..offset + 32].try_into()?;

        Ok(Self {
            job_id,
            reward_tree_tag,
            reward_tree_tag_preimage,
            proving_duration_ms,
            job_submitted_at,
            unique_pending_id,
            realm_id,
            realm_sub_id,
            reward_tree_node_key,
            reward_tree_hash_mode,
            reward_tree_node_children,
            node_type,
            api_url_hash,
        })
    }

    /// Serialize PsyProvingJobClaimMetadata to a byte vector
    pub fn psy_ser_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(PSY_PROVING_JOB_CLAIM_METADATA_SIZE);

        // job_id: 24 bytes (psy-node format, no slot_id field)
        result.extend_from_slice(&self.job_id.to_bytes_without_slot_id());

        // reward_tree_tag: 32 bytes (little-endian)
        result.extend_from_slice(&self.reward_tree_tag.to_le_bytes());

        // reward_tree_tag_preimage: 32 bytes (little-endian)
        result.extend_from_slice(&self.reward_tree_tag_preimage.to_le_bytes());

        // proving_duration_ms: 8 bytes (little-endian)
        result.extend_from_slice(&self.proving_duration_ms.to_le_bytes());

        // job_submitted_at: 8 bytes (little-endian)
        result.extend_from_slice(&self.job_submitted_at.to_le_bytes());

        // unique_pending_id: 8 bytes (little-endian)
        result.extend_from_slice(&self.unique_pending_id.to_le_bytes());

        // realm_id: 8 bytes (little-endian)
        result.extend_from_slice(&self.realm_id.to_le_bytes());

        // realm_sub_id: 8 bytes (little-endian)
        result.extend_from_slice(&self.realm_sub_id.to_le_bytes());

        // reward_tree_node_key: 9 bytes (1 byte level + 8 bytes little-endian index)
        result.push(self.reward_tree_node_key.level);
        result.extend_from_slice(&self.reward_tree_node_key.index.to_le_bytes());

        // reward_tree_hash_mode: 1 byte
        result.push(self.reward_tree_hash_mode);

        // reward_tree_node_children: 2 bytes (little-endian)
        result.extend_from_slice(&self.reward_tree_node_children.to_le_bytes());

        // node_type: 1 byte
        result.push(self.node_type);

        // api_url_hash: 32 bytes
        result.extend_from_slice(&self.api_url_hash);

        debug_assert_eq!(result.len(), PSY_PROVING_JOB_CLAIM_METADATA_SIZE);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use psy_client_common::job::id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic};

    use super::*;

    /// Test reading PsyProvingJobClaimMetadata from a binary file
    /// Usage: cargo test --package psy_client_data read_from_bin_file --
    /// --nocapture Provide a binary file path via environment variable
    /// PSY_TEST_REWARD_CLAIM_METADATA_FILE
    #[test]
    fn read_from_bin_file() {
        let file_path = std::env::var("PSY_TEST_REWARD_CLAIM_METADATA_FILE")
            .expect("Please set PSY_TEST_REWARD_CLAIM_METADATA_FILE environment variable to the binary file path");

        println!("Reading from file: {}", file_path);

        let mut file = std::fs::File::open(&file_path).expect(&format!("Failed to open file: {}", file_path));

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).expect("Failed to read file");

        println!("File size: {} bytes", buffer.len());
        println!("Expected record size: {} bytes", PSY_PROVING_JOB_CLAIM_METADATA_SIZE);
        println!("Number of records: {}", buffer.len() / PSY_PROVING_JOB_CLAIM_METADATA_SIZE);

        let mut offset = 0usize;
        let mut record_count = 0usize;
        let mut failed_count = 0usize;

        while offset + PSY_PROVING_JOB_CLAIM_METADATA_SIZE <= buffer.len() {
            let record_data = &buffer[offset..offset + PSY_PROVING_JOB_CLAIM_METADATA_SIZE];

            match PsyProvingJobClaimMetadata::<QHashOut<GoldilocksField>, QProvingJobDataID>::psy_ser_from_slice(record_data) {
                Ok(metadata) => {
                    println!("\nRecord {}:", record_count + 1);
                    println!("  job_id: {:?}", metadata.job_id.to_hex_string());
                    println!("  reward_tree_tag: {}", hex::encode(&metadata.reward_tree_tag.to_bytes().unwrap()[..]));
                    println!("  proving_duration_ms: {}", metadata.proving_duration_ms);
                    println!("  job_submitted_at: {}", metadata.job_submitted_at);
                    println!("  unique_pending_id: {}", metadata.unique_pending_id);
                    println!("  realm_id: {}", metadata.realm_id);
                    println!("  realm_sub_id: {}", metadata.realm_sub_id);
                    println!(
                        "  reward_tree_node_key: level={}, index={}",
                        metadata.reward_tree_node_key.level, metadata.reward_tree_node_key.index
                    );
                    println!("  reward_tree_hash_mode: {}", metadata.reward_tree_hash_mode);
                    println!("  reward_tree_node_children: {}", metadata.reward_tree_node_children);
                    println!("  node_type: {}", metadata.node_type);
                    println!("  api_url_hash: {}", hex::encode(metadata.api_url_hash));
                    record_count += 1;
                }
                Err(e) => {
                    eprintln!("Failed to parse record at offset {}: {}", offset, e);
                    failed_count += 1;
                }
            }

            offset += PSY_PROVING_JOB_CLAIM_METADATA_SIZE;
        }

        println!("\n=== Summary ===");
        println!("Successfully parsed: {} records", record_count);
        println!("Failed: {} records", failed_count);
        println!("Total records: {}", record_count + failed_count);

        assert!(record_count > 0, "Expected at least one valid record");
    }

    /// Test round-trip serialization: serialize then deserialize
    /// Note: 173-byte format does not include slot_id, so it will be 0 after
    /// deserialization
    #[test]
    fn test_round_trip() {
        // Create a sample metadata with slot_id = 0 (as 173-byte format doesn't
        // preserve slot_id)
        let original = PsyProvingJobClaimMetadata::<QHashOut<GoldilocksField>, QProvingJobDataID> {
            job_id: QProvingJobDataID {
                topic: QJobTopic::GenerateStandardProof,
                goal_id: 100,
                slot_id: 0, // 173-byte format doesn't include slot_id
                circuit_type: ProvingJobCircuitType::AddDeposit,
                group_id: 1,
                sub_group_id: 0,
                task_index: 0,
                data_type: ProvingJobDataType::InputWitness,
                data_index: 0,
            },
            reward_tree_tag: QHashOut::rand(),
            reward_tree_tag_preimage: QHashOut::rand(),
            proving_duration_ms: 1234567890,
            job_submitted_at: 9876543210,
            unique_pending_id: 1111111111,
            realm_id: 2,
            realm_sub_id: 3,
            reward_tree_node_key: SimpleMerkleNodeKey { level: 10, index: 42 },
            reward_tree_hash_mode: 1,
            reward_tree_node_children: 5,
            node_type: 1,
            api_url_hash: [0xAB; 32],
        };

        // Serialize
        let bytes = original.psy_ser_to_bytes().expect("Failed to serialize");
        assert_eq!(bytes.len(), PSY_PROVING_JOB_CLAIM_METADATA_SIZE);

        // Deserialize
        let deserialized =
            PsyProvingJobClaimMetadata::<QHashOut<GoldilocksField>, QProvingJobDataID>::psy_ser_from_slice(&bytes).expect("Failed to deserialize");

        // Verify job_id fields individually (slot_id is always 0 in 173-byte format)
        assert_eq!(original.job_id.topic, deserialized.job_id.topic);
        assert_eq!(original.job_id.goal_id, deserialized.job_id.goal_id);
        assert_eq!(deserialized.job_id.slot_id, 0); // slot_id is not preserved in 173-byte format
        assert_eq!(original.job_id.circuit_type, deserialized.job_id.circuit_type);
        assert_eq!(original.job_id.group_id, deserialized.job_id.group_id);
        assert_eq!(original.job_id.sub_group_id, deserialized.job_id.sub_group_id);
        assert_eq!(original.job_id.task_index, deserialized.job_id.task_index);
        assert_eq!(original.job_id.data_type, deserialized.job_id.data_type);
        assert_eq!(original.job_id.data_index, deserialized.job_id.data_index);

        // Verify other fields
        assert_eq!(original.reward_tree_tag, deserialized.reward_tree_tag);
        assert_eq!(original.reward_tree_tag_preimage, deserialized.reward_tree_tag_preimage);
        assert_eq!(original.proving_duration_ms, deserialized.proving_duration_ms);
        assert_eq!(original.job_submitted_at, deserialized.job_submitted_at);
        assert_eq!(original.unique_pending_id, deserialized.unique_pending_id);
        assert_eq!(original.realm_id, deserialized.realm_id);
        assert_eq!(original.realm_sub_id, deserialized.realm_sub_id);
        assert_eq!(original.reward_tree_node_key.level, deserialized.reward_tree_node_key.level);
        assert_eq!(original.reward_tree_node_key.index, deserialized.reward_tree_node_key.index);
        assert_eq!(original.reward_tree_hash_mode, deserialized.reward_tree_hash_mode);
        assert_eq!(original.reward_tree_node_children, deserialized.reward_tree_node_children);
        assert_eq!(original.node_type, deserialized.node_type);
        assert_eq!(original.api_url_hash, deserialized.api_url_hash);

        println!("Round-trip test passed!");
    }
}
