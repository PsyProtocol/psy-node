use std::{
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    path::PathBuf,
};

use clap::Parser;
use psy_node_common::realm::processor::gatherers::realm_end_cap_gatherer::REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32;
use serde::Serialize;

/// Header size: magic(4) + start_root(32) + end_root(32) + expected_end_caps(8) = 76
const HEADER_SIZE: usize = 4 + 32 + 32 + 8;

/// Fixed fields before the variable event data in each end-cap record.
/// job_id(24) + expected_checkpoint(8) + old_hash(32) + new_hash(32)
/// + user_leaf_node(variable, min 104) + stats(40) + events_len(4)
///
/// The user_leaf_node is variable-length (Plonky2 pio_read), so we cannot
/// statically compute per-record sizes. Instead we parse the header and
/// walk as many records as we can, collecting what is cheaply extractable.
const JOB_ID_SIZE: usize = 24;

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
struct RealmBackupOutput {
    header: RealmBackupHeader,
    records: Vec<EndCapRecord>,
    records_parsed: usize,
    truncated: bool,
}

pub async fn run(args: ReadRealmBackupArgs) -> anyhow::Result<()> {
    let mut file = File::open(&args.backup_file_path)?;
    let file_len = file.metadata()?.len();

    if file_len < HEADER_SIZE as u64 {
        anyhow::bail!(
            "Backup file too small to be valid: {} bytes (minimum {})",
            file_len,
            HEADER_SIZE
        );
    }

    // ── Header ──
    let mut magic_buf = [0u8; 4];
    file.read_exact(&mut magic_buf)?;
    let magic_u32 = u32::from_le_bytes(magic_buf);
    if magic_u32 != REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 {
        anyhow::bail!(
            "Backup file magic number mismatch: expected {:x}, got {:x}",
            REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32,
            magic_u32
        );
    }

    let mut start_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut start_root_hash_bytes)?;

    let mut end_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut end_root_hash_bytes)?;

    let mut expected_end_caps_buf = [0u8; 8];
    file.read_exact(&mut expected_end_caps_buf)?;
    let expected_end_caps = u64::from_le_bytes(expected_end_caps_buf);

    let header = RealmBackupHeader {
        magic: "RGE1".to_string(),
        start_root_hex: hex::encode(start_root_hash_bytes),
        end_root_hex: hex::encode(end_root_hash_bytes),
        expected_end_caps_processed: expected_end_caps,
        file_size: file_len,
    };

    if args.summary {
        println!("=== Realm Backup Summary ===");
        println!("File: {}", args.backup_file_path);
        println!("Magic: RGE1 (0x{:x})", magic_u32);
        println!("File size: {} bytes", file_len);
        println!("Start global user tree root: 0x{}", header.start_root_hex);
        println!("End global user tree root:   0x{}", header.end_root_hex);
        println!("Expected end-caps: {}", expected_end_caps);
        println!();
        // For summary we stop here — full parsing requires Plonky2 typed
        // deserialization which is expensive and not needed for a quick check.
        return Ok(());
    }

    // ── Body: walk end-cap records ──
    //
    // Each record starts with:
    //   job_id (24 bytes) + expected_checkpoint (8) + old_hash (32) + new_hash (32)
    // = 96 bytes of fixed fields, followed by a variable-length user_leaf_node
    // (Plonky2 pio format), stats (40), events_len (4), events (variable).
    //
    // We parse the first 96 bytes of each record (cheaply extractable) and
    // then attempt to skip the rest. The user_leaf_node is variable-length,
    // so we use a best-effort scan: we try to read the user_leaf via pio
    // deserialization, and if that fails we stop and report truncated.
    //
    // For a robust standalone tool without generic type parameters, we take
    // a simpler approach: read the known 96 fixed bytes per record, then
    // skip stats (40) and read events_len to skip events. The user_leaf_node
    // in between is the tricky part — its pio encoding length varies.
    // We use the user_id field (first 8 bytes after a 1-byte variant tag)
    // as a sanity signal, but for now we just collect the fixed prefix.

    let remaining_len = file_len as usize - HEADER_SIZE;
    let mut remaining = vec![0u8; remaining_len];
    file.read_exact(&mut remaining)?;
    let mut cursor = Cursor::new(&remaining);

    let mut records: Vec<EndCapRecord> = Vec::new();
    let mut truncated = false;

    for i in 0..expected_end_caps {
        let record_offset = HEADER_SIZE + cursor.position() as usize;

        // job_id (24 bytes)
        let mut job_id_bytes = [0u8; JOB_ID_SIZE];
        if cursor.read_exact(&mut job_id_bytes).is_err() {
            truncated = true;
            break;
        }

        // expected_checkpoint (8)
        let mut ckpt_bytes = [0u8; 8];
        if cursor.read_exact(&mut ckpt_bytes).is_err() {
            truncated = true;
            break;
        }
        let expected_checkpoint = u64::from_le_bytes(ckpt_bytes);

        // old_hash (32)
        let mut old_hash_bytes = [0u8; 32];
        if cursor.read_exact(&mut old_hash_bytes).is_err() {
            truncated = true;
            break;
        }

        // new_hash (32)
        let mut new_hash_bytes = [0u8; 32];
        if cursor.read_exact(&mut new_hash_bytes).is_err() {
            truncated = true;
            break;
        }

        records.push(EndCapRecord {
            job_id_hex: hex::encode(job_id_bytes),
            expected_checkpoint,
            old_user_leaf_hash_hex: hex::encode(old_hash_bytes),
            new_user_leaf_hash_hex: hex::encode(new_hash_bytes),
            record_offset,
        });

        // Skip the rest of this record (user_leaf_node + stats + events).
        // user_leaf_node is variable-length Plonky2 pio — we cannot skip
        // without deserializing it. We stop here and mark as truncated
        // for records beyond the first, unless we can find the next
        // record boundary.
        //
        // For now, we only parse the first record's fixed fields and stop.
        // A full parse requires the same generic typed deserialization as
        // read_realm_end_cap_gatherer_backup_file (which needs Hasher, Hash, F
        // type params + a SimpleMemoryMerkleRecorderStore).
        if i + 1 < expected_end_caps {
            truncated = true;
            break;
        }
    }
    let records_parsed = records.len();
    let output = RealmBackupOutput {
        header,
        records,
        records_parsed,
        truncated,
    };

    let json_output = serde_json::to_string_pretty(&output)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json_output)?;
        println!("JSON output written to: {}", output_path.display());
    } else {
        println!("{}", json_output);
    }

    Ok(())
}