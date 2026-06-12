use anyhow::{Context, Result};
use hashbrown::HashMap;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::{
    args::{ContractCallArgs, ContractCallData},
    data::qhashout::QHashOut,
    job::id::{QProvingJobDataID, QProvingJobDataIDWithRewardPreimage, GUTA_REWARDS_TREE_V2_MAX_HEIGHT},
};
use psy_client_data::{
    api::reward::{PsyProoffMinerRewardProofWithRewardPreimage, PsyProvingJobClaimMetadata},
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_config::{
    network_constants::{MAX_CONTRACT_STATE_TREE_HEIGHT, TOKEN_CONTRACT_ID},
    network_constants::MINING_REWARDS_CONTRACT_ID,
};
use psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProofWithRewardPreimage;
use psy_prover::session::{build_claim_calls_for_multi_checkpoints_v2, ProofWithCheckpointV2, WalletSession, LAST_CLAIMED_CHECKPOINT_SLOT};
use psy_provider::provider::RpcProvider;

use super::args::ClaimRewardsArgs;

pub async fn run(args: ClaimRewardsArgs) -> Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let info = load_wallet_key_info(&args.wallet, false)?;

    let provider = RpcProvider::new_with_config(&rpc_config)?;
    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let user_pk_hash = wallet_session.add_user(info.private_key, info.fingerprint).await?;
    let user_id = provider
        .get_user_ids_for_public_key(user_pk_hash)
        .await?
        .first()
        .ok_or(anyhow::format_err!("no user id"))?
        .clone();

    let job_ids = load_job_ids_from_file(&args.jobs_file)?;
    tracing::info!("Loaded {} job IDs from file", job_ids.jobs_len());
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
        wallet_session
            .exec_contract_call(user_pk_hash, ContractCallData::new(contract_call_args))
            .await?;
        tracing::info!("Successfully claimed rewards with v2 proof structure");
    } else {
        tracing::info!("No proofs to claim");
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct ClaimRewardJobsWithRealm {
    realm_jobs: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
    coordinator_jobs: Vec<QProvingJobDataIDWithRewardPreimage>,
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

pub async fn build_realm_proofs(
    provider: &RpcProvider,
    last_claimed_checkpoint_id: u64,
    job_ids: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
) -> Result<HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>>> {
    let job_ids_with_realm_and_unique_pending_id: HashMap<(u64, u64), Vec<QProvingJobDataIDWithRewardPreimage>> =
        job_ids.into_iter().fold(HashMap::new(), |mut map, (realm_id, job)| {
            map.entry((realm_id, job.inner.job_data_id.goal_id)).or_default().push(job);
            map
        });

    let mut total_proofs = 0;
    let mut proofs_with_unique_pending_id = HashMap::new();

    for ((realm_id, unique_pending_id), job_id_with_preimages) in job_ids_with_realm_and_unique_pending_id.iter() {
        let job_ids = job_id_with_preimages
            .iter()
            .map(|job_id_with_preimage| job_id_with_preimage.inner)
            .collect::<Vec<_>>();
        let pre_images = job_id_with_preimages
            .iter()
            .map(|job_id_with_preimage| job_id_with_preimage.reward_tree_tag_preimage.clone())
            .collect::<Vec<_>>();

        let checkpoint_id = provider
            .get_realm_checkpoint_id_for_unique_pending_id_by_realm_id(*realm_id, *unique_pending_id)
            .await?
            .with_context(|| format!("realm {} has no checkpoint id for unique_pending_id {}", realm_id, unique_pending_id))?;
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

        let proof_with_reward_preimages = proofs
            .into_iter()
            .zip(pre_images)
            .map(|(proof, reward_tree_tag_preimage)| PsyProoffMinerRewardProofWithRewardPreimage {
                inner: proof,
                reward_tree_tag_preimage,
            })
            .collect::<Vec<_>>();
        proofs_with_unique_pending_id.insert(checkpoint_id, proof_with_reward_preimages);
    }
    tracing::info!("Total realm proofs: {}", total_proofs);

    Ok(proofs_with_unique_pending_id)
}

pub async fn build_proofs(
    provider: &RpcProvider,
    last_claimed_checkpoint_id: u64,
    job_ids: Vec<QProvingJobDataIDWithRewardPreimage>,
    node_type: u8,
) -> Result<HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<GoldilocksField>>>>> {
    let job_ids_with_unique_pending_id: HashMap<u64, Vec<QProvingJobDataIDWithRewardPreimage>> =
        job_ids.into_iter().fold(HashMap::new(), |mut map, job| {
            map.entry(job.inner.job_data_id.goal_id).or_default().push(job);
            map
        });

    let mut total_proofs = 0;
    let mut proofs_with_unique_pending_id = HashMap::new();

    for (unique_pending_id, job_id_with_preimages) in job_ids_with_unique_pending_id.iter() {
        let job_ids = job_id_with_preimages
            .iter()
            .map(|job_id_with_preimage| job_id_with_preimage.inner)
            .collect::<Vec<_>>();
        let pre_images = job_id_with_preimages
            .iter()
            .map(|job_id_with_preimage| job_id_with_preimage.reward_tree_tag_preimage.clone())
            .collect::<Vec<_>>();

        let (checkpoint_id, proofs) = if node_type == 1 {
            let checkpoint_id = provider
                .get_realm_checkpoint_id_for_unique_pending_id(*unique_pending_id)
                .await?
                .with_context(|| format!("realm has no checkpoint id for unique_pending_id {}", unique_pending_id))?;
            let proofs = provider
                .generate_realm_batch_proof_miner_reward_proofs(*unique_pending_id, job_ids)
                .await?;
            (checkpoint_id, proofs)
        } else {
            let checkpoint_id = provider
                .get_coordinator_checkpoint_id_for_unique_pending_id(*unique_pending_id)
                .await?
                .with_context(|| format!("coordinator has no checkpoint id for unique_pending_id {}", unique_pending_id))?;
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

        let proof_with_reward_preimages = proofs
            .into_iter()
            .zip(pre_images)
            .map(|(proof, reward_tree_tag_preimage)| PsyProoffMinerRewardProofWithRewardPreimage {
                inner: proof,
                reward_tree_tag_preimage,
            })
            .collect::<Vec<_>>();
        proofs_with_unique_pending_id.insert(checkpoint_id, proof_with_reward_preimages);
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
    let mut offset = 0usize;

    while offset + record_size <= buffer.len() {
        let record_data = &buffer[offset..offset + record_size];

        match PsyProvingJobClaimMetadata::<QHashOut<GoldilocksField>, QProvingJobDataID>::psy_ser_from_slice(record_data) {
            Ok(metadata) => {
                let job =
                    QProvingJobDataIDWithRewardPreimage::new(metadata.job_id, metadata.reward_tree_node_key.index, metadata.reward_tree_tag_preimage);
                if metadata.node_type == 1 {
                    claim_jobs.realm_jobs.push((metadata.realm_id, job));
                } else {
                    claim_jobs.coordinator_jobs.push(job);
                }
            }
            Err(e) => tracing::warn!("Failed to parse record at offset {}: {}", offset, e),
        }

        offset += record_size;
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
        let proofs = proofs_with_unique_pending_id.get(&checkpoint_id).unwrap();
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

    let last_checkpoint = all_proofs_with_checkpoints.last().unwrap().checkpoint_id;

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
