use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use hashbrown::HashMap;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::{
    args::ContractCallArgs,
    data::qhashout::QHashOut,
    job::id::{QProvingJobDataID, QProvingJobDataIDWithRewardPreimage, GUTA_REWARDS_TREE_V2_MAX_HEIGHT},
};
use psy_client_data::{
    api::reward::{PsyProoffMinerRewardProof, PsyProoffMinerRewardProofWithRewardPreimage, PsyProvingJobClaimMetadata},
    config::store_config::PsyHasher,
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_config::network_constants::{MINING_REWARDS_CONTRACT_ID, TOKEN_CONTRACT_ID, TOKEN_CONTRACT_STATE_TREE_HEIGHT};
use psy_crypto::hash::{merkle::tag_tree::TagTreeMerkleProofWithRewardPreimage, traits::hasher::FieldQHasher};
use psy_prover::session::{build_claim_calls_for_multi_checkpoints_v2, ProofWithCheckpointV2, LAST_CLAIMED_CHECKPOINT_SLOT};
use psy_provider::provider::RpcProvider;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{args::ClaimRewardsArgs, submit_end_cap_proof};
use crate::result::{write_json_atomically, CommandResult, TransactionResult, TransactionStatus};

type ClaimMetadata = PsyProvingJobClaimMetadata<QHashOut<GoldilocksField>, QProvingJobDataID>;

#[derive(Debug)]
struct LoadedClaimJobs {
    records: Vec<ClaimMetadata>,
    source_format: String,
    source_record_size: Option<usize>,
    source_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RewardSummary {
    schema_version: u32,
    network: String,
    generated_at_ms: u64,
    source: RewardSummarySource,
    summary: RewardSummaryTotals,
    checkpoints: Vec<RewardSummaryCheckpoint>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RewardSummarySource {
    path: String,
    format: String,
    record_size: Option<usize>,
    record_count: usize,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RewardSummaryTotals {
    checkpoint_count: usize,
    job_count: usize,
    estimated_total_reward: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RewardSummaryCheckpoint {
    checkpoint_id: u64,
    unique_pending_id: u64,
    node_type: String,
    realm_id: u64,
    realm_sub_id: u64,
    fees_collected: u64,
    gutas_completed: u64,
    reward_per_job: u64,
    job_count: usize,
    estimated_total_reward: u64,
    jobs: Vec<RewardSummaryJob>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RewardSummaryJob {
    #[serde(flatten)]
    metadata: ClaimMetadata,
    circuit_name: String,
    reward_path_info: u64,
    estimated_reward: u64,
    validation: RewardSummaryValidation,
}

#[derive(Debug, Serialize, Deserialize)]
struct RewardSummaryValidation {
    preimage_matches_backup_tag: bool,
    proof_leaf_tag_matches_backup_tag: bool,
}

pub async fn run(args: ClaimRewardsArgs) -> Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;
    let loaded = load_claim_jobs(&args.jobs_file)?;
    tracing::info!("Loaded {} job records from {}", loaded.records.len(), args.jobs_file);

    if let Some(summary_output) = &args.summary_output {
        let summary = build_reward_summary(&provider, psy_config.current_network_name(), &args.jobs_file, &loaded).await?;
        write_json_atomically(Path::new(summary_output), &summary)?;
        tracing::info!("Wrote reusable reward summary to {}", summary_output);
    }
    if args.summary_only {
        return Ok(CommandResult::generic("claim-rewards-summary"));
    }

    let info = load_wallet_key_info(&args.wallet, false)?;
    let user_id = provider
        .get_user_ids_for_public_key(info.public_key_hash)
        .await?
        .first()
        .ok_or(anyhow::format_err!("no user id"))?
        .clone();

    let job_ids = claim_jobs_from_metadata(loaded.records)?;
    tracing::info!("Loaded {} job IDs from file", job_ids.jobs_len());
    let job_ids = validate_and_deduplicate_jobs(job_ids, user_id, &args.jobs_file)?;
    tracing::info!(
        "Loaded claim jobs from {}: realm_jobs={}, coordinator_jobs={}",
        args.jobs_file,
        job_ids.realm_jobs.len(),
        job_ids.coordinator_jobs.len()
    );
    tracing::debug!("Total jobs: {}", serde_json::to_string_pretty(&job_ids)?);

    let latest_checkpoint_id = provider.get_latest_block_state().await?.checkpoint_id;
    let last_claimed_checkpoint_id = get_last_claimed_checkpoint_id(&provider, user_id, latest_checkpoint_id).await?;
    tracing::info!(
        "Claim reward checkpoint state: user_id={}, latest_checkpoint_id={}, last_claimed_checkpoint_id={}",
        user_id,
        latest_checkpoint_id,
        last_claimed_checkpoint_id
    );
    let mut proofs_with_checkpoint_id = build_realm_proofs(&provider, last_claimed_checkpoint_id, job_ids.realm_jobs).await?;
    for (k, v) in build_proofs(&provider, last_claimed_checkpoint_id, job_ids.coordinator_jobs, 2).await? {
        proofs_with_checkpoint_id.entry(k).or_default().extend(v);
    }
    tracing::info!(
        "Proofs after checkpoint filtering: checkpoints={}, proofs={}",
        proofs_with_checkpoint_id.len(),
        proofs_with_checkpoint_id.values().map(|proofs| proofs.len()).sum::<usize>()
    );

    // Build contract call args from proofs (pass job_ids to get reward_path_info)
    let contract_call_args = build_claim_calls_from_proofs(&provider, &proofs_with_checkpoint_id).await?;

    // Execute contract calls
    if !contract_call_args.is_empty() {
        let (tx_hash, _end_user_leaf_hash) = submit_end_cap_proof::prove_contract_call_data_once(
            &args.rpc_config,
            &args.wallet,
            psy_client_common::args::ContractCallData::new(contract_call_args),
        )
        .await?;
        tracing::info!("Successfully claimed rewards with v2 proof structure");
        Ok(CommandResult::Transaction(TransactionResult {
            transaction_hash: tx_hash,
            user_id: Some(user_id),
            status: TransactionStatus::Submitted,
            confirmed_checkpoint: None,
            network: psy_config.current_network_name().to_string(),
        }))
    } else {
        tracing::info!("No proofs to claim");
        Ok(CommandResult::generic("claim-rewards"))
    }
}

#[derive(Debug, serde::Serialize)]
struct ClaimRewardJobsWithRealm {
    realm_jobs: Vec<(u64, u64, QProvingJobDataIDWithRewardPreimage)>,
    coordinator_jobs: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
}

impl ClaimRewardJobsWithRealm {
    fn new_empty() -> Self {
        Self {
            realm_jobs: vec![],
            coordinator_jobs: vec![],
        }
    }

    fn jobs_len(&self) -> usize {
        self.realm_jobs.len() + self.coordinator_jobs.len()
    }
}

fn validate_and_deduplicate_jobs(
    jobs: ClaimRewardJobsWithRealm,
    expected_user_id: u64,
    jobs_file: &str,
) -> Result<ClaimRewardJobsWithRealm> {
    let mut seen: HashMap<QProvingJobDataID, (Option<u64>, u64, u64, QHashOut<GoldilocksField>)> = HashMap::new();
    let mut deduplicated = ClaimRewardJobsWithRealm::new_empty();
    for (realm_id, unique_pending_id, job) in jobs.realm_jobs {
        validate_reward_preimage_user(&job, expected_user_id, jobs_file, &format!("realm_id={realm_id}"))?;
        let identity = (Some(realm_id), unique_pending_id, job.inner.reward_path_info, job.reward_tree_tag_preimage);
        match seen.get(&job.inner.job_data_id) {
            Some(existing) if existing == &identity => {}
            Some(_) => anyhow::bail!("jobs file {} contains conflicting duplicate job_id {:?}", jobs_file, job.inner.job_data_id),
            None => {
                seen.insert(job.inner.job_data_id, identity);
                deduplicated.realm_jobs.push((realm_id, unique_pending_id, job));
            }
        }
    }
    for (unique_pending_id, job) in jobs.coordinator_jobs {
        validate_reward_preimage_user(&job, expected_user_id, jobs_file, "coordinator")?;
        let identity = (None, unique_pending_id, job.inner.reward_path_info, job.reward_tree_tag_preimage);
        match seen.get(&job.inner.job_data_id) {
            Some(existing) if existing == &identity => {}
            Some(_) => anyhow::bail!("jobs file {} contains conflicting duplicate job_id {:?}", jobs_file, job.inner.job_data_id),
            None => {
                seen.insert(job.inner.job_data_id, identity);
                deduplicated.coordinator_jobs.push((unique_pending_id, job));
            }
        }
    }
    Ok(deduplicated)
}

fn validate_reward_preimage_user(
    job: &QProvingJobDataIDWithRewardPreimage,
    expected_user_id: u64,
    jobs_file: &str,
    source: &str,
) -> Result<()> {
    let preimage_user_id = job.reward_tree_tag_preimage.0.elements[0].0;
    anyhow::ensure!(
        preimage_user_id == expected_user_id,
        "jobs file {} contains a reward for user_id {}, but current wallet user_id is {}: {}, job_id={:?}",
        jobs_file,
        preimage_user_id,
        expected_user_id,
        source,
        job.inner.job_data_id,
    );
    Ok(())
}

fn index_reward_preimages(
    jobs: &[QProvingJobDataIDWithRewardPreimage],
) -> Result<HashMap<QProvingJobDataID, QHashOut<GoldilocksField>>> {
    let mut index = HashMap::new();
    for job in jobs {
        if let Some(existing) = index.insert(job.inner.job_data_id, job.reward_tree_tag_preimage) {
            anyhow::ensure!(existing == job.reward_tree_tag_preimage, "conflicting reward preimages for duplicate job_id {:?}", job.inner.job_data_id);
        }
    }
    Ok(index)
}

fn attach_reward_preimages(
    proofs: Vec<PsyProoffMinerRewardProof<QHashOut<GoldilocksField>>>,
    preimages: &HashMap<QProvingJobDataID, QHashOut<GoldilocksField>>,
    source: &str,
) -> Result<Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>> {
    let mut matched = HashMap::new();
    let mut attached = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let reward_tree_tag_preimage = preimages
            .get(&proof.job_id)
            .copied()
            .with_context(|| format!("missing reward preimage for {} proof job {:?}", source, proof.job_id))?;
        anyhow::ensure!(
            matched.insert(proof.job_id, ()).is_none(),
            "duplicate {} proof for job {:?}",
            source,
            proof.job_id,
        );
        attached.push(PsyProoffMinerRewardProofWithRewardPreimage { inner: proof, reward_tree_tag_preimage });
    }
    if matched.len() != preimages.len() {
        let missing = preimages
            .keys()
            .filter(|job_id| !matched.contains_key(*job_id))
            .copied()
            .collect::<Vec<_>>();
        anyhow::bail!("{} proofs are missing requested job_ids {:?}", source, missing);
    }
    Ok(attached)
}

fn require_checkpoint_id(checkpoint_id: Option<u64>, source: &str) -> Result<u64> {
    checkpoint_id.with_context(|| format!("{} has no checkpoint id", source))
}

fn reward_path_info(level: u8, index: u64) -> Result<u64> {
    const INDEX_MASK: u64 = 0x00ff_ffff_ffff_ffff;
    anyhow::ensure!(index <= INDEX_MASK, "reward tree node index {} exceeds 56 bits", index);
    Ok(((level as u64) << 56) | index)
}

pub async fn build_realm_proofs(
    provider: &RpcProvider,
    last_claimed_checkpoint_id: u64,
    job_ids: Vec<(u64, u64, QProvingJobDataIDWithRewardPreimage)>,
) -> Result<HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>>> {
    let job_ids_with_realm_and_unique_pending_id: HashMap<(u64, u64), Vec<QProvingJobDataIDWithRewardPreimage>> =
        job_ids.into_iter().fold(HashMap::new(), |mut map, (realm_id, unique_pending_id, job)| {
            map.entry((realm_id, unique_pending_id)).or_default().push(job);
            map
        });

    let mut total_proofs = 0;
    let mut proofs_with_unique_pending_id: HashMap<
        u64,
        Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>,
    > = HashMap::new();

    for ((realm_id, unique_pending_id), job_id_with_preimages) in job_ids_with_realm_and_unique_pending_id.iter() {
        let job_ids = job_id_with_preimages
            .iter()
            .map(|job_id_with_preimage| job_id_with_preimage.inner)
            .collect::<Vec<_>>();
        let preimages = index_reward_preimages(job_id_with_preimages)?;

        let checkpoint_id = require_checkpoint_id(
            provider
                .get_realm_checkpoint_id_for_unique_pending_id_by_realm_id(*realm_id, *unique_pending_id)
                .await?,
            &format!("realm {} unique_pending_id {}", realm_id, unique_pending_id),
        )?;
        let proofs = provider
            .generate_realm_batch_proof_miner_reward_proofs_by_realm_id(*realm_id, *unique_pending_id, job_ids)
            .await?;

        if checkpoint_id <= last_claimed_checkpoint_id {
            tracing::info!(
                "Skipping realm {} unique_pending_id {} checkpoint {} because last_claimed_checkpoint_id is {}",
                realm_id,
                unique_pending_id,
                checkpoint_id,
                last_claimed_checkpoint_id
            );
            continue;
        }

        total_proofs += proofs.len();
        tracing::info!(
            "Including realm {} unique_pending_id {} checkpoint {} jobs={} proofs={}",
            realm_id,
            unique_pending_id,
            checkpoint_id,
            job_id_with_preimages.len(),
            proofs.len()
        );

        let proof_with_reward_preimages = attach_reward_preimages(proofs, &preimages, "realm")?;
        proofs_with_unique_pending_id
            .entry(checkpoint_id)
            .or_default()
            .extend(proof_with_reward_preimages);
    }
    tracing::info!("Total realm proofs: {}", total_proofs);

    Ok(proofs_with_unique_pending_id)
}

pub async fn build_proofs(
    provider: &RpcProvider,
    last_claimed_checkpoint_id: u64,
    job_ids: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
    node_type: u8,
) -> Result<HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>>> {
    let job_ids_with_unique_pending_id: HashMap<u64, Vec<QProvingJobDataIDWithRewardPreimage>> =
        job_ids.into_iter().fold(HashMap::new(), |mut map, (unique_pending_id, job)| {
            map.entry(unique_pending_id).or_default().push(job);
            map
        });

    let mut total_proofs = 0;
    let mut proofs_with_unique_pending_id: HashMap<
        u64,
        Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>,
    > = HashMap::new();

    for (unique_pending_id, job_id_with_preimages) in job_ids_with_unique_pending_id.iter() {
        let job_ids = job_id_with_preimages
            .iter()
            .map(|job_id_with_preimage| job_id_with_preimage.inner)
            .collect::<Vec<_>>();
        let preimages = index_reward_preimages(job_id_with_preimages)?;

        let (checkpoint_id, proofs) = if node_type == 1 {
            let checkpoint_id = require_checkpoint_id(
                provider.get_realm_checkpoint_id_for_unique_pending_id(*unique_pending_id).await?,
                &format!("realm unique_pending_id {}", unique_pending_id),
            )?;
            let proofs = provider
                .generate_realm_batch_proof_miner_reward_proofs(*unique_pending_id, job_ids)
                .await?;
            (checkpoint_id, proofs)
        } else {
            let checkpoint_id = require_checkpoint_id(
                provider
                    .get_coordinator_checkpoint_id_for_unique_pending_id(*unique_pending_id)
                    .await?,
                &format!("coordinator unique_pending_id {}", unique_pending_id),
            )?;
            let proofs = provider
                .generate_coordinator_batch_proof_miner_reward_proofs(*unique_pending_id, job_ids)
                .await?;
            (checkpoint_id, proofs)
        };

        if checkpoint_id <= last_claimed_checkpoint_id {
            tracing::info!(
                "Skipping coordinator unique_pending_id {} checkpoint {} because last_claimed_checkpoint_id is {}",
                unique_pending_id,
                checkpoint_id,
                last_claimed_checkpoint_id
            );
            continue;
        }

        total_proofs += proofs.len();
        tracing::info!(
            "Including coordinator unique_pending_id {} checkpoint {} jobs={} proofs={}",
            unique_pending_id,
            checkpoint_id,
            job_id_with_preimages.len(),
            proofs.len()
        );

        let proof_with_reward_preimages = attach_reward_preimages(proofs, &preimages, "coordinator")?;
        proofs_with_unique_pending_id
            .entry(checkpoint_id)
            .or_default()
            .extend(proof_with_reward_preimages);
    }
    tracing::info!("Total proofs: {}", total_proofs);

    Ok(proofs_with_unique_pending_id)
}

async fn get_last_claimed_checkpoint_id(provider: &RpcProvider, user_id: u64, latest_checkpoint_id: u64) -> Result<u64> {
    let proof = provider
        .get_user_contract_state_tree_merkle_proof(
            latest_checkpoint_id,
            user_id,
            TOKEN_CONTRACT_ID,
            TOKEN_CONTRACT_STATE_TREE_HEIGHT,
            LAST_CLAIMED_CHECKPOINT_SLOT,
        )
        .await?;

    Ok(proof.value.0.elements[1].0)
}

fn load_claim_jobs(path: &str) -> Result<LoadedClaimJobs> {
    let buffer = std::fs::read(path)?;
    let source_sha256 = format!("{:x}", Sha256::digest(&buffer));

    if buffer.is_empty() {
        tracing::info!("Backup file is empty");
        return Ok(LoadedClaimJobs {
            records: Vec::new(),
            source_format: "psy-worker-backup-v1".to_string(),
            source_record_size: Some(ClaimMetadata::record_size()),
            source_sha256,
        });
    }

    if buffer.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{') {
        let summary: RewardSummary = serde_json::from_slice(&buffer).context("failed to parse reward summary JSON")?;
        anyhow::ensure!(
            summary.schema_version == 1,
            "unsupported reward summary schema_version {}",
            summary.schema_version
        );
        let expected_job_count = summary.summary.job_count;
        let mut records = Vec::new();
        for checkpoint in summary.checkpoints {
            for job in checkpoint.jobs {
                let computed_path = reward_path_info(job.metadata.reward_tree_node_key.level, job.metadata.reward_tree_node_key.index)?;
                anyhow::ensure!(
                    computed_path == job.reward_path_info,
                    "{} has inconsistent reward_path_info for job {:?}: stored={}, computed={}",
                    path,
                    job.metadata.job_id,
                    job.reward_path_info,
                    computed_path,
                );
                records.push(job.metadata);
            }
        }
        anyhow::ensure!(
            records.len() == expected_job_count,
            "{} summary job_count is {}, but contains {} jobs",
            path,
            expected_job_count,
            records.len(),
        );
        let records = validate_and_deduplicate_metadata(records, path)?;
        return Ok(LoadedClaimJobs {
            records,
            source_format: "psy-reward-summary-v1".to_string(),
            source_record_size: None,
            source_sha256,
        });
    }

    let record_size = ClaimMetadata::record_size();
    anyhow::ensure!(
        buffer.len() % record_size == 0,
        "jobs backup length {} is not a multiple of record size {}",
        buffer.len(),
        record_size
    );

    let mut records = Vec::with_capacity(buffer.len() / record_size);
    for (record_index, record_data) in buffer.chunks_exact(record_size).enumerate() {
        let offset = record_index * record_size;
        let metadata =
            ClaimMetadata::psy_ser_from_slice(record_data).with_context(|| format!("failed to parse jobs backup record at offset {}", offset))?;
        validate_claim_metadata(&metadata, path)?;
        records.push(metadata);
    }

    Ok(LoadedClaimJobs {
        records: validate_and_deduplicate_metadata(records, path)?,
        source_format: "psy-worker-backup-v1".to_string(),
        source_record_size: Some(record_size),
        source_sha256,
    })
}

fn validate_claim_metadata(metadata: &ClaimMetadata, source: &str) -> Result<()> {
    let encoded = reward_path_info(metadata.reward_tree_node_key.level, metadata.reward_tree_node_key.index)?;
    let expected_tag = PsyHasher::q_two_to_one(metadata.reward_tree_tag_preimage, metadata.reward_tree_tag_preimage);
    anyhow::ensure!(
        expected_tag == metadata.reward_tree_tag,
        "{} contains a reward_tree_tag that does not match its preimage: job_id={:?}, reward_path_info={}",
        source,
        metadata.job_id,
        encoded,
    );
    Ok(())
}

fn validate_and_deduplicate_metadata(records: Vec<ClaimMetadata>, source: &str) -> Result<Vec<ClaimMetadata>> {
    let mut seen: HashMap<QProvingJobDataID, ClaimMetadata> = HashMap::new();
    let mut result = Vec::with_capacity(records.len());
    for metadata in records {
        validate_claim_metadata(&metadata, source)?;
        match seen.get(&metadata.job_id) {
            Some(existing) if existing == &metadata => continue,
            Some(_) => anyhow::bail!("{} contains conflicting duplicate job_id {:?}", source, metadata.job_id),
            None => {
                seen.insert(metadata.job_id, metadata.clone());
                result.push(metadata);
            }
        }
    }
    Ok(result)
}

fn claim_jobs_from_metadata(records: Vec<ClaimMetadata>) -> Result<ClaimRewardJobsWithRealm> {
    let mut claim_jobs = ClaimRewardJobsWithRealm::new_empty();
    for metadata in records {
        let job = QProvingJobDataIDWithRewardPreimage::new(
            metadata.job_id,
            reward_path_info(metadata.reward_tree_node_key.level, metadata.reward_tree_node_key.index)?,
            metadata.reward_tree_tag_preimage,
        );
        if metadata.node_type == 1 {
            claim_jobs.realm_jobs.push((metadata.realm_id, metadata.unique_pending_id, job));
        } else {
            claim_jobs.coordinator_jobs.push((metadata.unique_pending_id, job));
        }
    }

    Ok(claim_jobs)
}

#[cfg(test)]
fn load_job_ids_from_file(path: &str) -> Result<ClaimRewardJobsWithRealm> {
    claim_jobs_from_metadata(load_claim_jobs(path)?.records)
}

async fn build_reward_summary(provider: &RpcProvider, network: &str, source_path: &str, loaded: &LoadedClaimJobs) -> Result<RewardSummary> {
    let mut groups: BTreeMap<(u8, u64, u64, u64), Vec<&ClaimMetadata>> = BTreeMap::new();
    for metadata in &loaded.records {
        anyhow::ensure!(
            matches!(metadata.node_type, 1 | 2),
            "unsupported reward node_type {} for job {:?}",
            metadata.node_type,
            metadata.job_id,
        );
        groups
            .entry((metadata.node_type, metadata.realm_id, metadata.realm_sub_id, metadata.unique_pending_id))
            .or_default()
            .push(metadata);
    }

    let mut checkpoint_stats = BTreeMap::<u64, (u64, u64, u64)>::new();
    let mut checkpoints = Vec::with_capacity(groups.len());
    let mut distinct_checkpoint_ids = BTreeSet::new();
    let mut estimated_total_reward = 0u64;

    for ((node_type, realm_id, realm_sub_id, unique_pending_id), records) in groups {
        let request_jobs = records
            .iter()
            .map(|metadata| {
                Ok(QProvingJobDataIDWithRewardPreimage::new(
                    metadata.job_id,
                    reward_path_info(metadata.reward_tree_node_key.level, metadata.reward_tree_node_key.index)?,
                    metadata.reward_tree_tag_preimage,
                )
                .inner)
            })
            .collect::<Result<Vec<_>>>()?;

        let (checkpoint_id, proofs) = if node_type == 1 {
            let checkpoint_id = require_checkpoint_id(
                provider
                    .get_realm_checkpoint_id_for_unique_pending_id_by_realm_id(realm_id, unique_pending_id)
                    .await?,
                &format!("realm {} unique_pending_id {}", realm_id, unique_pending_id),
            )?;
            let proofs = provider
                .generate_realm_batch_proof_miner_reward_proofs_by_realm_id(realm_id, unique_pending_id, request_jobs)
                .await?;
            (checkpoint_id, proofs)
        } else {
            let checkpoint_id = require_checkpoint_id(
                provider.get_coordinator_checkpoint_id_for_unique_pending_id(unique_pending_id).await?,
                &format!("coordinator unique_pending_id {}", unique_pending_id),
            )?;
            let proofs = provider
                .generate_coordinator_batch_proof_miner_reward_proofs(unique_pending_id, request_jobs)
                .await?;
            (checkpoint_id, proofs)
        };

        let (fees_collected, gutas_completed, reward_per_job) = match checkpoint_stats.get(&checkpoint_id) {
            Some(stats) => *stats,
            None => {
                let leaf = provider.get_checkpoint_leaf_data(checkpoint_id).await?;
                let fees = leaf.stats.guta_fees_collected.to_canonical_u64();
                let gutas = leaf.stats.pm_jobs_completed.gutas_completed.to_canonical_u64();
                let reward = if gutas == 0 { 0 } else { fees / gutas };
                checkpoint_stats.insert(checkpoint_id, (fees, gutas, reward));
                (fees, gutas, reward)
            }
        };

        let mut proofs_by_job = HashMap::new();
        for proof in proofs {
            anyhow::ensure!(
                proofs_by_job.insert(proof.job_id, proof).is_none(),
                "duplicate reward proof for unique_pending_id {}",
                unique_pending_id,
            );
        }

        let mut jobs = Vec::with_capacity(records.len());
        for metadata in records {
            let proof = proofs_by_job
                .remove(&metadata.job_id)
                .with_context(|| format!("missing reward proof for job {:?}", metadata.job_id))?;
            anyhow::ensure!(
                proof.tag_tree_proof.leaf.tag == metadata.reward_tree_tag,
                "reward proof leaf tag does not match backup tag for job {:?}",
                metadata.job_id,
            );
            jobs.push(RewardSummaryJob {
                metadata: metadata.clone(),
                circuit_name: format!("{:?}", metadata.job_id.circuit_type),
                reward_path_info: reward_path_info(metadata.reward_tree_node_key.level, metadata.reward_tree_node_key.index)?,
                estimated_reward: reward_per_job,
                validation: RewardSummaryValidation {
                    preimage_matches_backup_tag: true,
                    proof_leaf_tag_matches_backup_tag: true,
                },
            });
        }
        anyhow::ensure!(
            proofs_by_job.is_empty(),
            "RPC returned unrequested reward proofs for unique_pending_id {}",
            unique_pending_id
        );

        let group_total = reward_per_job.checked_mul(jobs.len() as u64).context("estimated group reward overflow")?;
        estimated_total_reward = estimated_total_reward
            .checked_add(group_total)
            .context("estimated total reward overflow")?;
        distinct_checkpoint_ids.insert(checkpoint_id);
        checkpoints.push(RewardSummaryCheckpoint {
            checkpoint_id,
            unique_pending_id,
            node_type: if node_type == 1 { "realm" } else { "coordinator" }.to_string(),
            realm_id,
            realm_sub_id,
            fees_collected,
            gutas_completed,
            reward_per_job,
            job_count: jobs.len(),
            estimated_total_reward: group_total,
            jobs,
        });
    }

    Ok(RewardSummary {
        schema_version: 1,
        network: network.to_string(),
        generated_at_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
        source: RewardSummarySource {
            path: source_path.to_string(),
            format: loaded.source_format.clone(),
            record_size: loaded.source_record_size,
            record_count: loaded.records.len(),
            sha256: loaded.source_sha256.clone(),
        },
        summary: RewardSummaryTotals {
            checkpoint_count: distinct_checkpoint_ids.len(),
            job_count: loaded.records.len(),
            estimated_total_reward,
        },
        checkpoints,
    })
}

pub async fn build_claim_calls_from_proofs(
    provider: &RpcProvider,
    proofs_with_unique_pending_id: &HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>>,
) -> Result<Vec<ContractCallArgs>> {
    if proofs_with_unique_pending_id.is_empty() {
        tracing::info!("No valid checkpoints with rewards to claim");
        return Ok(Vec::new());
    }

    tracing::debug!("Building claim calls from proofs: {:?}", proofs_with_unique_pending_id);

    let mut sorted_checkpoints: Vec<_> = proofs_with_unique_pending_id.keys().copied().collect();
    sorted_checkpoints.sort();
    tracing::info!("Preparing claim calls for checkpoints: {:?}", sorted_checkpoints);

    let mut all_proofs_with_checkpoints = Vec::new();

    for &checkpoint_id in &sorted_checkpoints {
        let proofs = proofs_with_unique_pending_id
            .get(&checkpoint_id)
            .with_context(|| format!("missing proofs for checkpoint {}", checkpoint_id))?;
        tracing::debug!("Checkpoint {} - Proofs: {}", checkpoint_id, serde_json::to_string_pretty(&proofs)?);

        let checkpoint_leaf = provider.get_checkpoint_leaf_data(checkpoint_id).await?;
        let fees_collected = checkpoint_leaf.stats.guta_fees_collected.to_canonical_u64();
        let gutas_completed = checkpoint_leaf.stats.pm_jobs_completed.gutas_completed.to_canonical_u64();
        tracing::info!(
            "Checkpoint {} - Fees collected: {}, Gutas completed: {}",
            checkpoint_id,
            fees_collected,
            gutas_completed
        );

        let proposed_reward = if gutas_completed > 0 { fees_collected / gutas_completed } else { 0u64 };

        if proposed_reward == 0 {
            tracing::warn!(
                "Skipping checkpoint {} due to zero reward (fees_collected={}, gutas_completed={})",
                checkpoint_id,
                fees_collected,
                gutas_completed
            );
            continue;
        }

        tracing::info!("Checkpoint {} - Reward: {}, Proofs: {}", checkpoint_id, proposed_reward, proofs.len());
        for proof in proofs {
            all_proofs_with_checkpoints.push(ProofWithCheckpointV2 {
                checkpoint_id,
                proof: TagTreeMerkleProofWithRewardPreimage::new(proof.inner.tag_tree_proof.clone(), proof.reward_tree_tag_preimage)
                    .pad_to_height(GUTA_REWARDS_TREE_V2_MAX_HEIGHT as usize),
                proposed_reward,
            });
        }
    }

    if all_proofs_with_checkpoints.is_empty() {
        tracing::info!("No checkpoints with valid rewards to claim");
        return Ok(Vec::new());
    }

    tracing::info!(
        "Building claim calls for {} proofs across {} checkpoints",
        all_proofs_with_checkpoints.len(),
        sorted_checkpoints.len()
    );
    tracing::debug!("Proofs with checkpoints: {}", serde_json::to_string_pretty(&all_proofs_with_checkpoints)?);

    let mut all_contract_calls = Vec::new();
    let mut group_start = 0;
    while group_start < all_proofs_with_checkpoints.len() {
        let checkpoint_id = all_proofs_with_checkpoints[group_start].checkpoint_id;
        let mut group_end = group_start + 1;
        while group_end < all_proofs_with_checkpoints.len() && all_proofs_with_checkpoints[group_end].checkpoint_id == checkpoint_id {
            group_end += 1;
        }

        let mut checkpoint_calls = build_claim_calls_for_multi_checkpoints_v2(&all_proofs_with_checkpoints[group_start..group_end]).await;
        tracing::info!(
            "Prepared {} reward claim calls for checkpoint {} with {} proofs",
            checkpoint_calls.len(),
            checkpoint_id,
            group_end - group_start
        );
        all_contract_calls.append(&mut checkpoint_calls);
        group_start = group_end;
    }
    for (call_index, call) in all_contract_calls.iter().enumerate() {
        tracing::info!(
            "Prepared reward claim call {}: contract_id={}, method={}, input_count={}",
            call_index,
            call.contract_id,
            call.method_name,
            call.inputs.len()
        );
    }

    let last_checkpoint = all_proofs_with_checkpoints
        .last()
        .with_context(|| "claim proof list became empty before checkpoint finalization")?
        .checkpoint_id;

    all_contract_calls.push(ContractCallArgs {
        contract_id: MINING_REWARDS_CONTRACT_ID as u64,
        method_name: "end_session".to_string(),
        inputs: vec![last_checkpoint],
    });

    all_contract_calls.push(ContractCallArgs {
        contract_id: TOKEN_CONTRACT_ID as u64,
        method_name: "simple_claim_pow_rewards".to_string(),
        inputs: vec![last_checkpoint],
    });

    tracing::info!(
        "Executing {} contract calls in single transaction, last_checkpoint={}",
        all_contract_calls.len(),
        last_checkpoint
    );
    Ok(all_contract_calls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_client_common::job::id::{
        ProvingJobCircuitType, ProvingJobDataType, QJobTopic,
    };

    fn job(task_index: u32, user_id: u64, marker: u64) -> QProvingJobDataIDWithRewardPreimage {
        QProvingJobDataIDWithRewardPreimage::new(
            QProvingJobDataID::new(
                QJobTopic::GenerateStandardProof,
                11,
                0,
                0,
                0,
                task_index,
                ProvingJobCircuitType::AppendUserRegistrationTree,
                ProvingJobDataType::InputWitness,
                0,
            ),
            marker,
            QHashOut::from_values(user_id, 0, marker, marker + 1),
        )
    }

    #[test]
    fn mismatched_preimage_user_is_rejected() {
        let jobs = ClaimRewardJobsWithRealm {
            realm_jobs: vec![],
            coordinator_jobs: vec![(21, job(1, 8, 10))],
        };
        let error = validate_and_deduplicate_jobs(jobs, 7, "worker.backup").unwrap_err();
        assert!(error.to_string().contains("current wallet user_id is 7"));
    }

    #[test]
    fn identical_duplicates_are_deduplicated_but_conflicts_fail() {
        let first = job(1, 7, 10);
        let jobs = ClaimRewardJobsWithRealm {
            realm_jobs: vec![],
            coordinator_jobs: vec![(21, first.clone()), (21, first)],
        };
        assert_eq!(validate_and_deduplicate_jobs(jobs, 7, "worker.backup").unwrap().jobs_len(), 1);

        let jobs = ClaimRewardJobsWithRealm {
            realm_jobs: vec![],
            coordinator_jobs: vec![(21, job(1, 7, 10)), (22, job(1, 7, 11))],
        };
        assert!(validate_and_deduplicate_jobs(jobs, 7, "worker.backup")
            .unwrap_err()
            .to_string()
            .contains("conflicting duplicate job_id"));
    }

    #[test]
    fn proofs_are_matched_to_preimages_by_job_id_not_position() {
        let first = job(1, 7, 10);
        let second = job(2, 7, 20);
        let preimages = index_reward_preimages(&[first.clone(), second.clone()]).unwrap();
        let proofs = vec![
            PsyProoffMinerRewardProof {
                job_id: second.inner.job_data_id,
                tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
            },
            PsyProoffMinerRewardProof {
                job_id: first.inner.job_data_id,
                tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
            },
        ];
        let attached = attach_reward_preimages(proofs, &preimages, "test").unwrap();
        assert_eq!(attached[0].reward_tree_tag_preimage, second.reward_tree_tag_preimage);
        assert_eq!(attached[1].reward_tree_tag_preimage, first.reward_tree_tag_preimage);
    }

    #[test]
    fn proof_set_must_exactly_match_requested_jobs() {
        let first = job(1, 7, 10);
        let second = job(2, 7, 20);
        let preimages = index_reward_preimages(&[first.clone(), second.clone()]).unwrap();
        let missing = vec![PsyProoffMinerRewardProof {
            job_id: first.inner.job_data_id,
            tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
        }];
        assert!(attach_reward_preimages(missing, &preimages, "test")
            .unwrap_err()
            .to_string()
            .contains("missing requested job_ids"));

        let duplicate = vec![
            PsyProoffMinerRewardProof {
                job_id: first.inner.job_data_id,
                tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
            },
            PsyProoffMinerRewardProof {
                job_id: first.inner.job_data_id,
                tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty(),
            },
        ];
        assert!(attach_reward_preimages(duplicate, &preimages, "test")
            .unwrap_err()
            .to_string()
            .contains("duplicate test proof"));
    }

    #[test]
    fn same_checkpoint_proofs_are_appended_not_overwritten() {
        let mut by_checkpoint: HashMap<u64, Vec<u64>> = HashMap::new();
        by_checkpoint.entry(9).or_default().extend([1, 2]);
        by_checkpoint.entry(9).or_default().extend([3]);
        assert_eq!(by_checkpoint.get(&9).unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn unavailable_checkpoint_is_fail_closed() {
        assert!(require_checkpoint_id(None, "coordinator unique_pending_id 11")
            .unwrap_err()
            .to_string()
            .contains("has no checkpoint id"));
    }

    #[test]
    fn malformed_backup_length_is_rejected() {
        let path = std::env::temp_dir().join(format!("claim-rewards-truncated-{}", std::process::id()));
        std::fs::write(&path, [0u8]).unwrap();
        let error = load_job_ids_from_file(path.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("not a multiple of record size"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn backup_preserves_unique_pending_id_and_reward_tree_node_key() {
        use psy_crypto::hash::merkle::utils::common::SimpleMerkleNodeKey;

        let reward_tree_tag_preimage = QHashOut::from_values(7, 0, 10, 11);
        let metadata = PsyProvingJobClaimMetadata {
            job_id: job(1, 7, 10).inner.job_data_id,
            reward_tree_tag: PsyHasher::q_two_to_one(reward_tree_tag_preimage, reward_tree_tag_preimage),
            reward_tree_tag_preimage,
            proving_duration_ms: 1,
            job_submitted_at: 2,
            unique_pending_id: 987,
            realm_id: 3,
            realm_sub_id: 0,
            reward_tree_node_key: SimpleMerkleNodeKey { level: 3, index: 2 },
            reward_tree_hash_mode: 0,
            reward_tree_node_children: 0,
            node_type: 1,
            api_url_hash: [0; 32],
        };
        let path = std::env::temp_dir().join(format!("claim-rewards-metadata-{}", std::process::id()));
        std::fs::write(&path, metadata.psy_ser_to_bytes().unwrap()).unwrap();
        let loaded = load_job_ids_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.realm_jobs[0].0, 3);
        assert_eq!(loaded.realm_jobs[0].1, 987);
        assert_eq!(loaded.realm_jobs[0].2.inner.reward_path_info, (3u64 << 56) | 2);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reusable_json_recomputes_and_validates_reward_path() {
        use psy_crypto::hash::merkle::utils::common::SimpleMerkleNodeKey;

        let reward_tree_tag_preimage = QHashOut::from_values(7, 0, 10, 11);
        let metadata = PsyProvingJobClaimMetadata {
            job_id: job(1, 7, 10).inner.job_data_id,
            reward_tree_tag: PsyHasher::q_two_to_one(reward_tree_tag_preimage, reward_tree_tag_preimage),
            reward_tree_tag_preimage,
            proving_duration_ms: 1,
            job_submitted_at: 2,
            unique_pending_id: 987,
            realm_id: 3,
            realm_sub_id: 4,
            reward_tree_node_key: SimpleMerkleNodeKey { level: 3, index: 2 },
            reward_tree_hash_mode: 0,
            reward_tree_node_children: 0,
            node_type: 1,
            api_url_hash: [0; 32],
        };
        let summary = RewardSummary {
            schema_version: 1,
            network: "sepolia".to_string(),
            generated_at_ms: 1,
            source: RewardSummarySource {
                path: "worker.backup".to_string(),
                format: "psy-worker-backup-v1".to_string(),
                record_size: Some(ClaimMetadata::record_size()),
                record_count: 1,
                sha256: "00".to_string(),
            },
            summary: RewardSummaryTotals {
                checkpoint_count: 1,
                job_count: 1,
                estimated_total_reward: 42,
            },
            checkpoints: vec![RewardSummaryCheckpoint {
                checkpoint_id: 999,
                unique_pending_id: 987,
                node_type: "realm".to_string(),
                realm_id: 3,
                realm_sub_id: 4,
                fees_collected: 42,
                gutas_completed: 1,
                reward_per_job: 42,
                job_count: 1,
                estimated_total_reward: 42,
                jobs: vec![RewardSummaryJob {
                    metadata,
                    circuit_name: "test".to_string(),
                    reward_path_info: (3u64 << 56) | 2,
                    estimated_reward: 42,
                    validation: RewardSummaryValidation {
                        preimage_matches_backup_tag: true,
                        proof_leaf_tag_matches_backup_tag: true,
                    },
                }],
            }],
        };
        let path = std::env::temp_dir().join(format!("claim-rewards-summary-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec_pretty(&summary).unwrap()).unwrap();
        let loaded = load_claim_jobs(path.to_str().unwrap()).unwrap();
        let jobs = claim_jobs_from_metadata(loaded.records).unwrap();
        assert_eq!(jobs.realm_jobs[0].2.inner.reward_path_info, (3u64 << 56) | 2);
        std::fs::remove_file(path).unwrap();
    }
}
