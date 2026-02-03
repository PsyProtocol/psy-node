use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use clap::Parser;
use parth_core::{protocol::core_types::Q256BitHash, PHash};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::worker::proving_work_history::PsyProvingJobClaimMetadata;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

const RECORD_SIZE: usize = 173;

#[derive(Parser, Debug)]
pub struct ReadWorkerBackupArgs {
    /// Path to the worker backup file
    #[arg(help = "Path to the worker completed jobs backup file")]
    pub backup_file_path: String,

    /// Output as summary only
    #[arg(long = "summary", help = "Show summary only")]
    pub summary: bool,

    /// Output to file instead of stdout
    #[arg(short, long, help = "Output file path (default: stdout)")]
    pub output: Option<PathBuf>,
}

/// Run the read-backup command.
pub async fn run(args: ReadWorkerBackupArgs) -> anyhow::Result<()> {
    let mut file = File::open(&args.backup_file_path)?;

    // Read entire file
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    if buffer.is_empty() {
        println!("Backup file is empty");
        return Ok(());
    }

    // Parse records using fixed-size format (173 bytes per record)
    let mut jobs: Vec<PsyProvingJobClaimMetadata<PHash, QProvingJobDataID>> = Vec::new();
    let mut offset = 0usize;

    while offset + RECORD_SIZE <= buffer.len() {
        let record_data = &buffer[offset..offset + RECORD_SIZE];

        match PsyProvingJobClaimMetadata::<PHash, QProvingJobDataID>::psy_ser_from_slice(record_data) {
            Ok(metadata) => jobs.push(metadata),
            Err(e) => eprintln!("Warning: Failed to parse record at offset {}: {}", offset, e),
        }

        offset += RECORD_SIZE;
    }

    if args.summary {
        // Summary output
        println!("=== Worker Backup Summary ===");
        println!("File: {}", args.backup_file_path);
        println!("Total jobs: {}", jobs.len());

        // Group by realm
        let mut realm_counts: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
        for job in &jobs {
            *realm_counts.entry(job.realm_id).or_insert(0) += 1;
        }

        println!("\nJobs per realm:");
        for (realm_id, count) in realm_counts {
            println!("  Realm {}: {} jobs", realm_id, count);
        }

        // Show sample jobs
        println!("\nFirst 5 jobs:");
        for job in jobs.iter().take(5) {
            let tag_hex = hex::encode(job.reward_tree_tag.into_owned_32bytes());
            println!("  - job_id: {:?} (realm {}, tag: {}...)", job.job_id, job.realm_id, &tag_hex[..16]);
        }

        if jobs.len() > 5 {
            println!("  ... and {} more", jobs.len() - 5);
        }
    }

    // Output JSON to file or stdout
    let json_output = serde_json::to_string_pretty(&jobs)?;
    if let Some(output_path) = &args.output {
        let mut output_file = OpenOptions::new().create(true).truncate(true).write(true).open(output_path)?;
        output_file.write_all(json_output.as_bytes())?;
        println!("JSON output written to: {}", output_path.display());
    } else {
        println!("{}", json_output);
    }

    Ok(())
}
