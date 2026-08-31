use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;
use psy_core::job::job_id::QProvingJobDataID;
use psy_node_common::realm::processor::gatherers::realm_end_cap_gatherer::REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32;
use psy_node_core::qblob::{
    blob_type::{
        get_item_size_for_data_type, QBlobDataType, QBlobMerkleNodeTreeType,
        QBLOB_STANDARD_V1_MAGIC_U32,
    },
    structs::common::tree_node_batch_header::{
        QBlobMerkleTreeNodeBatchHeaderV1, QBLOB_TREE_NODE_BATCH_HEADER_SIZE,
    },
    traits::common::QBlobStructHeaderBase,
};
use serde::Serialize;

const HEADER_SIZE: usize = 4 + 32 + 32 + 8;
const JOB_ID_SIZE: usize = 24;
const USER_LEAF_SIZE: usize = 104;
const GUTA_STATS_SIZE: usize = 40;
const EVENTS_LEN_SIZE: usize = 4;
const QUEUE_ITEM_FIXED_PREFIX_SIZE: usize =
    JOB_ID_SIZE + 8 + 32 + 32 + USER_LEAF_SIZE + GUTA_STATS_SIZE + EVENTS_LEN_SIZE;
const END_CAP_EVENT_FIXED_FIELDS_SIZE: usize = 8 * 5 + 4;
const FOOTER_SIZE: usize = 216;

#[derive(Parser, Debug)]
pub struct ReadRealmBackupArgs {
    /// Path to the realm end-cap gatherer backup file
    #[arg(help = "Path to the realm end-cap gatherer backup file")]
    pub backup_file_path: String,

    /// Show summary only (header + counts)
    #[arg(long = "summary", help = "Show summary only")]
    pub summary: bool,

    /// Output file path (default: stdout)
    #[arg(short, long, help = "Output file path (default: stdout)")]
    pub output: Option<PathBuf>,
}

#[derive(Serialize, Debug)]
struct RealmBackupHeader {
    magic: String,
    start_root_hex: String,
    end_root_hex: String,
    expected_end_caps_processed: u64,
    file_size: u64,
}

#[derive(Serialize, Debug)]
struct EndCapRecord {
    job_id_hex: String,
    expected_checkpoint: u64,
    old_user_leaf_hash_hex: String,
    new_user_leaf_hash_hex: String,
    record_offset: usize,
}

#[derive(Serialize, Debug)]
struct RealmBackupFooter {
    guta_circuit_whitelist_hex: String,
    checkpoint_tree_root_hex: String,
    old_node_value_hex: String,
    new_node_value_hex: String,
    node_index: u64,
    node_level: u64,
    guta_fees_collected: u64,
    da_fees_collected: u64,
    user_ops_processed: u64,
    total_transactions: u64,
    slots_modified: u64,
    total_aggregation_proofs_generated: u64,
    job_id_hex: String,
}

#[derive(Serialize, Debug)]
struct RealmBackupOutput {
    header: RealmBackupHeader,
    records: Vec<EndCapRecord>,
    records_parsed: usize,
    truncated: bool,
    footer: RealmBackupFooter,
}

pub async fn run(args: ReadRealmBackupArgs) -> anyhow::Result<()> {
    let backup_bytes = std::fs::read(&args.backup_file_path)
        .with_context(|| format!("Failed to read realm backup file {}", args.backup_file_path))?;
    let output = parse_realm_backup(&backup_bytes)?;

    if args.summary {
        println!("=== Realm Backup Summary ===");
        println!("File: {}", args.backup_file_path);
        println!("Magic: RGE1 (0x{:x})", REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32);
        println!("File size: {} bytes", output.header.file_size);
        println!("Start global user tree root: 0x{}", output.header.start_root_hex);
        println!("End global user tree root:   0x{}", output.header.end_root_hex);
        println!("Expected end-caps: {}", output.header.expected_end_caps_processed);
        println!("End-caps parsed: {}", output.records_parsed);
        println!("Footer checkpoint tree root: 0x{}", output.footer.checkpoint_tree_root_hex);
        return Ok(());
    }

    let json_output = serde_json::to_string_pretty(&output)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json_output)?;
        println!("JSON output written to: {}", output_path.display());
    } else {
        println!("{}", json_output);
    }

    Ok(())
}

fn parse_realm_backup(bytes: &[u8]) -> anyhow::Result<RealmBackupOutput> {
    let minimum_size = HEADER_SIZE + FOOTER_SIZE;
    if bytes.len() < minimum_size {
        anyhow::bail!(
            "Backup file too small to contain the RGE1 header and GUTA footer: {} bytes (minimum {})",
            bytes.len(),
            minimum_size
        );
    }

    let magic_u32 = read_u32_le(bytes, 0, "RGE1 magic")?;
    if magic_u32 != REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 {
        anyhow::bail!(
            "Backup file magic number mismatch: expected {:x}, got {:x}",
            REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32,
            magic_u32
        );
    }

    let expected_end_caps = read_u64_le(bytes, 68, "declared end-cap count")?;
    let expected_end_caps_usize = usize::try_from(expected_end_caps)
        .map_err(|_| anyhow::anyhow!("Declared end-cap count {} exceeds usize range", expected_end_caps))?;
    let body_end = bytes.len() - FOOTER_SIZE;
    let mut offset = HEADER_SIZE;
    let mut records = Vec::new();

    for record_index in 0..expected_end_caps_usize {
        records.push(
            parse_end_cap_record(bytes, &mut offset, body_end)
                .with_context(|| format!("Failed to parse declared end-cap record {} at offset {}", record_index, offset))?,
        );
    }

    if offset != body_end {
        anyhow::bail!(
            "RGE1 body length does not match the declared record count: parsed through offset {}, footer starts at offset {} ({} unparsed bytes)",
            offset,
            body_end,
            body_end.saturating_sub(offset)
        );
    }

    let footer = parse_footer(&bytes[body_end..])?;
    let file_size = u64::try_from(bytes.len()).map_err(|_| anyhow::anyhow!("Backup file size exceeds u64 range"))?;
    let header = RealmBackupHeader {
        magic: "RGE1".to_string(),
        start_root_hex: hex::encode(&bytes[4..36]),
        end_root_hex: hex::encode(&bytes[36..68]),
        expected_end_caps_processed: expected_end_caps,
        file_size,
    };
    let records_parsed = records.len();

    Ok(RealmBackupOutput {
        header,
        records,
        records_parsed,
        truncated: false,
        footer,
    })
}

fn parse_end_cap_record(bytes: &[u8], offset: &mut usize, body_end: usize) -> anyhow::Result<EndCapRecord> {
    let record_offset = *offset;
    let prefix = take_before_footer(
        bytes,
        *offset,
        QUEUE_ITEM_FIXED_PREFIX_SIZE,
        body_end,
        "end-cap queue item fixed prefix",
    )?;

    let job_id_bytes = &prefix[..JOB_ID_SIZE];
    QProvingJobDataID::try_from_byte_vec(job_id_bytes).context("Invalid end-cap queue item job ID")?;
    let expected_checkpoint = u64::from_le_bytes(prefix[24..32].try_into()?);
    let old_user_leaf_hash_hex = hex::encode(&prefix[32..64]);
    let new_user_leaf_hash_hex = hex::encode(&prefix[64..96]);
    let events_len = u32::from_le_bytes(prefix[240..244].try_into()?) as usize;
    *offset += QUEUE_ITEM_FIXED_PREFIX_SIZE;

    for event_index in 0..events_len {
        let event_header = take_before_footer(
            bytes,
            *offset,
            END_CAP_EVENT_FIXED_FIELDS_SIZE,
            body_end,
            "end-cap event header",
        )?;
        let data_len = u32::from_le_bytes(event_header[40..44].try_into()?) as usize;
        *offset += END_CAP_EVENT_FIXED_FIELDS_SIZE;
        let event_data_size = data_len
            .checked_mul(8)
            .ok_or_else(|| anyhow::anyhow!("End-cap event {} data length {} overflows usize", event_index, data_len))?;
        take_before_footer(bytes, *offset, event_data_size, body_end, "end-cap event data")?;
        *offset += event_data_size;
    }

    parse_qblob(
        bytes,
        offset,
        body_end,
        QBlobDataType::GenericSingleIdMerkleNodeBatch,
        QBlobMerkleNodeTreeType::UserContractTree,
        "UserContractTree",
    )?;
    parse_qblob(
        bytes,
        offset,
        body_end,
        QBlobDataType::GenericDoubleIdMerkleNodeBatch,
        QBlobMerkleNodeTreeType::UserContractStateTree,
        "UserContractStateTree",
    )?;
    parse_qblob(
        bytes,
        offset,
        body_end,
        QBlobDataType::GenericIMTLeafBatch,
        QBlobMerkleNodeTreeType::IMTContractStateLeaf,
        "IMTContractStateLeaf",
    )?;

    Ok(EndCapRecord {
        job_id_hex: hex::encode(job_id_bytes),
        expected_checkpoint,
        old_user_leaf_hash_hex,
        new_user_leaf_hash_hex,
        record_offset,
    })
}

fn parse_qblob(
    bytes: &[u8],
    offset: &mut usize,
    body_end: usize,
    expected_blob_type: QBlobDataType,
    expected_tree_type: QBlobMerkleNodeTreeType,
    segment: &str,
) -> anyhow::Result<()> {
    let header_bytes = take_before_footer(
        bytes,
        *offset,
        QBLOB_TREE_NODE_BATCH_HEADER_SIZE,
        body_end,
        &format!("{} QBlob header", segment),
    )?;
    let header = QBlobMerkleTreeNodeBatchHeaderV1::try_read_header_from_slice(header_bytes)
        .with_context(|| format!("Invalid {} QBlob header at offset {}", segment, offset))?;

    if header.blob_magic != QBLOB_STANDARD_V1_MAGIC_U32 {
        anyhow::bail!(
            "{} QBlob has invalid magic at offset {}: expected {:x}, got {:x}",
            segment,
            offset,
            QBLOB_STANDARD_V1_MAGIC_U32,
            header.blob_magic
        );
    }
    if header.blob_type != expected_blob_type {
        anyhow::bail!(
            "{} QBlob has wrong blob type at offset {}: expected {:?}, got {:?}",
            segment,
            offset,
            expected_blob_type,
            header.blob_type
        );
    }
    if header.tree_type != expected_tree_type {
        anyhow::bail!(
            "{} QBlob has wrong tree type at offset {}: expected {:?}, got {:?}",
            segment,
            offset,
            expected_tree_type,
            header.tree_type
        );
    }

    let expected_item_size = get_item_size_for_data_type(expected_blob_type)
        .ok_or_else(|| anyhow::anyhow!("No fixed item size is defined for {:?}", expected_blob_type))?;
    if header.item_size as usize != expected_item_size {
        anyhow::bail!(
            "{} QBlob item_size mismatch at offset {}: expected {}, got {}",
            segment,
            offset,
            expected_item_size,
            header.item_size
        );
    }

    let item_count = usize::try_from(header.item_count)
        .map_err(|_| anyhow::anyhow!("{} QBlob item_count {} exceeds usize range", segment, header.item_count))?;
    let payload_size = item_count
        .checked_mul(expected_item_size)
        .ok_or_else(|| anyhow::anyhow!("{} QBlob payload size overflows usize", segment))?;
    let calculated_total_size = QBLOB_TREE_NODE_BATCH_HEADER_SIZE
        .checked_add(payload_size)
        .ok_or_else(|| anyhow::anyhow!("{} QBlob total size overflows usize", segment))?;
    let declared_total_size = usize::try_from(header.total_size)
        .map_err(|_| anyhow::anyhow!("{} QBlob total_size {} exceeds usize range", segment, header.total_size))?;
    if declared_total_size != calculated_total_size {
        anyhow::bail!(
            "{} QBlob total_size mismatch at offset {}: declared {}, calculated {} from item_count {} and item_size {}",
            segment,
            offset,
            declared_total_size,
            calculated_total_size,
            header.item_count,
            expected_item_size
        );
    }

    take_before_footer(
        bytes,
        *offset,
        declared_total_size,
        body_end,
        &format!("{} QBlob", segment),
    )?;
    *offset += declared_total_size;
    Ok(())
}

fn parse_footer(bytes: &[u8]) -> anyhow::Result<RealmBackupFooter> {
    if bytes.len() != FOOTER_SIZE {
        anyhow::bail!("Invalid GUTA footer size: expected {}, got {}", FOOTER_SIZE, bytes.len());
    }

    let job_id_bytes = &bytes[192..216];
    QProvingJobDataID::try_from_byte_vec(job_id_bytes).context("Invalid GUTA footer job ID")?;

    Ok(RealmBackupFooter {
        guta_circuit_whitelist_hex: hex::encode(&bytes[0..32]),
        checkpoint_tree_root_hex: hex::encode(&bytes[32..64]),
        old_node_value_hex: hex::encode(&bytes[64..96]),
        new_node_value_hex: hex::encode(&bytes[96..128]),
        node_index: read_u64_le(bytes, 128, "footer node index")?,
        node_level: read_u64_le(bytes, 136, "footer node level")?,
        guta_fees_collected: read_u64_le(bytes, 144, "footer GUTA fees")?,
        da_fees_collected: read_u64_le(bytes, 152, "footer DA fees")?,
        user_ops_processed: read_u64_le(bytes, 160, "footer user operations")?,
        total_transactions: read_u64_le(bytes, 168, "footer total transactions")?,
        slots_modified: read_u64_le(bytes, 176, "footer slots modified")?,
        total_aggregation_proofs_generated: read_u64_le(bytes, 184, "footer aggregation proof count")?,
        job_id_hex: hex::encode(job_id_bytes),
    })
}

fn take_before_footer<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    body_end: usize,
    segment: &str,
) -> anyhow::Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("{} range overflows usize at offset {}", segment, offset))?;
    if end > body_end {
        anyhow::bail!(
            "Truncated {} at offset {}: need {} bytes, only {} remain before the GUTA footer",
            segment,
            offset,
            length,
            body_end.saturating_sub(offset)
        );
    }
    Ok(&bytes[offset..end])
}

fn read_u32_le(bytes: &[u8], offset: usize, field: &str) -> anyhow::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("Truncated {} at offset {}", field, offset))?;
    Ok(u32::from_le_bytes(value.try_into()?))
}

fn read_u64_le(bytes: &[u8], offset: usize, field: &str) -> anyhow::Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow::anyhow!("Truncated {} at offset {}", field, offset))?;
    Ok(u64::from_le_bytes(value.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qblob(blob_type: QBlobDataType, tree_type: QBlobMerkleNodeTreeType) -> Vec<u8> {
        let mut header = match blob_type {
            QBlobDataType::GenericSingleIdMerkleNodeBatch => {
                QBlobMerkleTreeNodeBatchHeaderV1::new_single_id_header(tree_type, 0, 0, 0, 0, 1, 5)
            }
            QBlobDataType::GenericDoubleIdMerkleNodeBatch => {
                QBlobMerkleTreeNodeBatchHeaderV1::new_double_id_header(tree_type, 0, 0, 0, 0, 1, 5)
            }
            QBlobDataType::GenericIMTLeafBatch => {
                QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header(tree_type, 0, 0, 0, 0, 1, 5)
            }
            _ => panic!("unsupported test QBlob type"),
        };
        let item_size = header.item_size;
        header.modify_for_final_count_and_size(item_size, 0);
        header.to_bytes_fixed_size_array().to_vec()
    }

    fn end_cap_record(include_imt: bool) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&[0u8; JOB_ID_SIZE]);
        record.extend_from_slice(&7u64.to_le_bytes());
        record.extend_from_slice(&[2u8; 32]);
        record.extend_from_slice(&[3u8; 32]);
        record.extend_from_slice(&[0u8; USER_LEAF_SIZE]);
        record.extend_from_slice(&[0u8; GUTA_STATS_SIZE]);
        record.extend_from_slice(&1u32.to_le_bytes());
        record.extend_from_slice(&[0u8; 8 * 5]);
        record.extend_from_slice(&2u32.to_le_bytes());
        record.extend_from_slice(&11u64.to_le_bytes());
        record.extend_from_slice(&12u64.to_le_bytes());
        record.extend_from_slice(&qblob(
            QBlobDataType::GenericSingleIdMerkleNodeBatch,
            QBlobMerkleNodeTreeType::UserContractTree,
        ));
        record.extend_from_slice(&qblob(
            QBlobDataType::GenericDoubleIdMerkleNodeBatch,
            QBlobMerkleNodeTreeType::UserContractStateTree,
        ));
        if include_imt {
            record.extend_from_slice(&qblob(
                QBlobDataType::GenericIMTLeafBatch,
                QBlobMerkleNodeTreeType::IMTContractStateLeaf,
            ));
        }
        record
    }

    fn backup(records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
        bytes.extend_from_slice(&[4u8; 32]);
        bytes.extend_from_slice(&[5u8; 32]);
        bytes.extend_from_slice(&(records.len() as u64).to_le_bytes());
        for record in records {
            bytes.extend_from_slice(record);
        }
        let mut footer = [0u8; FOOTER_SIZE];
        footer[32..64].copy_from_slice(&[9u8; 32]);
        bytes.extend_from_slice(&footer);
        bytes
    }

    #[test]
    fn read_realm_backup_parses_every_record_and_footer() {
        let parsed = parse_realm_backup(&backup(&[end_cap_record(true), end_cap_record(true)])).unwrap();
        assert_eq!(parsed.records_parsed, 2);
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].record_offset, HEADER_SIZE);
        assert_eq!(parsed.footer.checkpoint_tree_root_hex, hex::encode([9u8; 32]));
        assert!(!parsed.truncated);
    }

    #[test]
    fn read_realm_backup_rejects_missing_mandatory_imt_qblob() {
        assert!(parse_realm_backup(&backup(&[end_cap_record(false)])).is_err());
    }

    #[test]
    fn read_realm_backup_rejects_wrong_typed_qblob() {
        let mut record = end_cap_record(false);
        record.extend_from_slice(&qblob(
            QBlobDataType::GenericDoubleIdMerkleNodeBatch,
            QBlobMerkleNodeTreeType::UserContractStateTree,
        ));
        assert!(parse_realm_backup(&backup(&[record])).is_err());
    }

    #[test]
    fn read_realm_backup_rejects_truncated_or_trailing_bytes() {
        let valid = backup(&[end_cap_record(true)]);

        let mut truncated = valid.clone();
        truncated.pop();
        assert!(parse_realm_backup(&truncated).is_err());

        let mut trailing = valid;
        trailing.push(0);
        assert!(parse_realm_backup(&trailing).is_err());
    }
}
