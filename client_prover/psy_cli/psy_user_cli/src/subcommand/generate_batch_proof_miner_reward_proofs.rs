use anyhow::Result;
use psy_client_common::job::id::QProvingJobDataIDWithRewardPath;
use psy_provider::provider::RpcProvider;

use super::args::{GenerateBatchProofMinerRewardProofsArgs, RpcProviderType};
use crate::result::{CommandResult, ProofsResult};

pub async fn run(args: GenerateBatchProofMinerRewardProofsArgs) -> Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    let job_ids = load_job_ids_from_file(&args.jobs_file)?;

    let proofs = match args.provider_type {
        RpcProviderType::Coordinator => {
            provider
                .generate_coordinator_batch_proof_miner_reward_proofs(args.unique_pending_id, job_ids)
                .await?
        }
        RpcProviderType::Realm => {
            provider
                .generate_realm_batch_proof_miner_reward_proofs(args.unique_pending_id, job_ids)
                .await?
        }
    };

    // Output proofs to file
    let output = serde_json::to_string_pretty(&proofs)?;
    std::fs::write(&args.output_file, output)?;
    tracing::info!("Wrote {} proofs to {}", proofs.len(), args.output_file);
    println!("Generated {} proofs to {}", proofs.len(), args.output_file);
    Ok(CommandResult::Proofs(ProofsResult {
        count: proofs.len(),
        output_file: args.output_file,
    }))
}

fn load_job_ids_from_file(path: &str) -> Result<Vec<QProvingJobDataIDWithRewardPath>> {
    tracing::info!("Loading job IDs from file: {}", path);

    if !std::path::Path::new(path).exists() {
        anyhow::bail!(
            "Jobs file not found: {}. Please create the file or specify a different path with --jobs-file",
            path
        );
    }

    let content = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Failed to read jobs file '{}': {}", path, e))?;

    let jobs_json = match serde_json::from_str::<Vec<QProvingJobDataIDWithRewardPath>>(&content) {
        Ok(jobs) => jobs,
        Err(e) => {
            anyhow::bail!(
                "Failed to parse JSON in jobs file '{}': {}. Expected format: {}",
                path,
                e,
                serde_json::to_string_pretty(&vec![QProvingJobDataIDWithRewardPath::default()])?
            )
        }
    };

    tracing::info!("Loaded {} job IDs from file", jobs_json.len());
    Ok(jobs_json)
}
