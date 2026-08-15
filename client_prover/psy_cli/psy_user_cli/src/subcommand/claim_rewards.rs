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
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_config::network_constants::{MAX_CONTRACT_STATE_TREE_HEIGHT, MINING_REWARDS_CONTRACT_ID, TOKEN_CONTRACT_ID};
use psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProofWithRewardPreimage;
use psy_prover::session::{build_claim_calls_for_multi_checkpoints_v2, ProofWithCheckpointV2, LAST_CLAIMED_CHECKPOINT_SLOT};
use psy_provider::provider::RpcProvider;

use super::{args::ClaimRewardsArgs, submit_end_cap_proof};
use crate::result::{CommandResult, TransactionResult, TransactionStatus};

pub async fn run(args: ClaimRewardsArgs) -> Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let info = load_wallet_key_info(&args.wallet, false)?;

    let provider = RpcProvider::new_with_config(&rpc_config)?;
    let user_id = provider
        .get_user_ids_for_public_key(info.public_key_hash)
        .await?
        .first()
        .ok_or(anyhow::format_err!("no user id"))?
        .clone();

    let job_ids = load_job_ids_from_file(&args.jobs_file)?;
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

fn validate_and_deduplicate_jobs(jobs: ClaimRewardJobsWithRealm, expected_user_id: u64, jobs_file: &str) -> Result<ClaimRewardJobsWithRealm> {
    let mut seen: HashMap<QProvingJobDataID, (Option<u64>, u64, u64, QHashOut<GoldilocksField>)> = HashMap::new();
    let mut deduplicated = ClaimRewardJobsWithRealm::new_empty();
    for (realm_id, unique_pending_id, job) in jobs.realm_jobs {
        validate_reward_preimage_user(&job, expected_user_id, jobs_file, &format!("realm_id={realm_id}"))?;
        let identity = (
            Some(realm_id),
            unique_pending_id,
            job.inner.reward_path_info,
            job.reward_tree_tag_preimage,
        );
        match seen.get(&job.inner.job_data_id) {
            Some(existing) if existing == &identity => {}
            Some(_) => anyhow::bail!(
                "jobs file {} contains conflicting duplicate job_id {:?}",
                jobs_file,
                job.inner.job_data_id
            ),
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
            Some(_) => anyhow::bail!(
                "jobs file {} contains conflicting duplicate job_id {:?}",
                jobs_file,
                job.inner.job_data_id
            ),
            None => {
                seen.insert(job.inner.job_data_id, identity);
                deduplicated.coordinator_jobs.push((unique_pending_id, job));
            }
        }
    }
    Ok(deduplicated)
}

fn validate_reward_preimage_user(job: &QProvingJobDataIDWithRewardPreimage, expected_user_id: u64, jobs_file: &str, source: &str) -> Result<()> {
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

fn index_reward_preimages(jobs: &[QProvingJobDataIDWithRewardPreimage]) -> Result<HashMap<QProvingJobDataID, QHashOut<GoldilocksField>>> {
    let mut index = HashMap::new();
    for job in jobs {
        if let Some(existing) = index.insert(job.inner.job_data_id, job.reward_tree_tag_preimage) {
            anyhow::ensure!(
                existing == job.reward_tree_tag_preimage,
                "conflicting reward preimages for duplicate job_id {:?}",
                job.inner.job_data_id
            );
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
        attached.push(PsyProoffMinerRewardProofWithRewardPreimage {
            inner: proof,
            reward_tree_tag_preimage,
        });
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
    let mut proofs_with_unique_pending_id: HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>> = HashMap::new();

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
    let mut proofs_with_unique_pending_id: HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>> = HashMap::new();

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
                provider.get_coordinator_checkpoint_id_for_unique_pending_id(*unique_pending_id).await?,
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
            MAX_CONTRACT_STATE_TREE_HEIGHT,
            LAST_CLAIMED_CHECKPOINT_SLOT,
        )
        .await?;

    Ok(proof.value.0.elements[1].0)
}

fn load_job_ids_from_file(path: &str) -> Result<ClaimRewardJobsWithRealm> {
    let buffer = std::fs::read(path)?;
    let mut claim_jobs = ClaimRewardJobsWithRealm::new_empty();

    if buffer.is_empty() {
        tracing::info!("Backup file is empty");
        return Ok(claim_jobs);
    }

    let record_size = PsyProvingJobClaimMetadata::<QHashOut<GoldilocksField>, QProvingJobDataID>::record_size();
    anyhow::ensure!(
        buffer.len() % record_size == 0,
        "jobs backup length {} is not a multiple of record size {}",
        buffer.len(),
        record_size
    );

    for (record_index, record_data) in buffer.chunks_exact(record_size).enumerate() {
        let offset = record_index * record_size;
        let metadata = PsyProvingJobClaimMetadata::<QHashOut<GoldilocksField>, QProvingJobDataID>::psy_ser_from_slice(record_data)
            .with_context(|| format!("failed to parse jobs backup record at offset {}", offset))?;
        let job = QProvingJobDataIDWithRewardPreimage::new(metadata.job_id, metadata.reward_tree_node_key.index, metadata.reward_tree_tag_preimage);
        if metadata.node_type == 1 {
            claim_jobs.realm_jobs.push((metadata.realm_id, metadata.unique_pending_id, job));
        } else {
            claim_jobs.coordinator_jobs.push((metadata.unique_pending_id, job));
        }
    }

    Ok(claim_jobs)
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
    use psy_client_common::job::id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic};

    use super::*;

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
    fn backup_preserves_unique_pending_id() {
        use psy_crypto::hash::merkle::utils::common::SimpleMerkleNodeKey;

        let metadata = PsyProvingJobClaimMetadata {
            job_id: job(1, 7, 10).inner.job_data_id,
            reward_tree_tag: QHashOut::from_values(1, 2, 3, 4),
            reward_tree_tag_preimage: QHashOut::from_values(7, 0, 10, 11),
            proving_duration_ms: 1,
            job_submitted_at: 2,
            unique_pending_id: 987,
            realm_id: 3,
            realm_sub_id: 0,
            reward_tree_node_key: SimpleMerkleNodeKey { level: 1, index: 10 },
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
        std::fs::remove_file(path).unwrap();
    }
}
