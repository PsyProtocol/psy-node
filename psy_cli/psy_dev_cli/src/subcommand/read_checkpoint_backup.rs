use std::{
    fs::File,
    io::{Read, Seek},
    path::PathBuf,
};

use clap::Parser;
use parth_core::{data::hash::merkle_node_nest::MerkleLeafNode, protocol::core_types::Q256BitHash, PHash};
use psy_node_common::backup::checkpoint_tree::{CHECKPOINT_BACKUP_ITEM_SIZE, CHECKPOINT_BACKUP_MAGIC_LEN};

#[derive(Parser, Debug)]
pub struct ReadCheckpointBackupArgs {
    #[arg(help = "Path to the checkpoint tree backup file")]
    pub backup_file_path: String,

    #[arg(long = "summary", help = "Show summary only")]
    pub summary: bool,

    #[arg(short, long, help = "Output file path (default: stdout)")]
    pub output: Option<PathBuf>,
}

pub async fn run(args: ReadCheckpointBackupArgs) -> anyhow::Result<()> {
    let mut backup_file = File::open(&args.backup_file_path)?;

    let mut magic = [0u8; CHECKPOINT_BACKUP_MAGIC_LEN];
    backup_file.read_exact(&mut magic)?;

    let expected_magic: [u8; 8] = [0x50, 0x73, 0x79, 0x43, 0x68, 0x6B, 0x70, 0x74];
    if magic != expected_magic {
        anyhow::bail!("Invalid magic bytes in checkpoint backup file");
    }

    let file_len = backup_file.metadata()?.len();
    let data_len = file_len - CHECKPOINT_BACKUP_MAGIC_LEN as u64;
    let num_entries = data_len / CHECKPOINT_BACKUP_ITEM_SIZE as u64;

    let mut entries: Vec<MerkleLeafNode<PHash>> = Vec::with_capacity(num_entries as usize);

    backup_file.seek(std::io::SeekFrom::Start(CHECKPOINT_BACKUP_MAGIC_LEN as u64))?;
    for _ in 0..num_entries {
        let mut id_buf = [0u8; 8];
        let mut hash_buf = [0u8; 32];
        backup_file.read_exact(&mut id_buf)?;
        backup_file.read_exact(&mut hash_buf)?;
        let id = u64::from_le_bytes(id_buf);
        entries.push(MerkleLeafNode {
            index: id,
            value: PHash::from_ref_32bytes(&hash_buf),
        });
    }

    if args.summary {
        println!("=== Checkpoint Backup Summary ===");
        println!("File: {}", args.backup_file_path);
        println!("Total checkpoints: {}", entries.len());

        if !entries.is_empty() {
            let first = entries.first().unwrap();
            let last = entries.last().unwrap();
            println!("Range: [{}, {}]", first.index, last.index);

            println!("\nLast 5 checkpoints:");
            for entry in entries.iter().rev().take(5) {
                println!("  {}: {}", entry.index, entry.value);
            }
        }
    }

    let json_output = serde_json::to_string_pretty(&entries)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json_output)?;
        println!("JSON output written to: {}", output_path.display());
    } else {
        println!("{}", json_output);
    }

    Ok(())
}
