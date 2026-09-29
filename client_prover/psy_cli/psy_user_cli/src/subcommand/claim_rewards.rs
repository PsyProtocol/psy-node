use anyhow::{Context, Result};
use hashbrown::HashMap;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::{
    args::SignType,
    data::{base_types::hash256::Hash256, qhashout::QHashOut},
    job::id::{QProvingJobDataID, QProvingJobDataIDWithRewardPreimage},
};
use psy_client_data::{
    api::reward::{PsyProoffMinerRewardProof, PsyProoffMinerRewardProofWithRewardPreimage, PsyProvingJobClaimMetadata},
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_provider::provider::RpcProvider;

use super::args::ClaimRewardsArgs;
use crate::result::CommandResult;
use psy_client_data::config::store_config::PsyHasher;
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_ups_circuit::signature::reward_authorization::RewardAuthorizationInput;
use psy_vm::{reward_authorization::RewardAuthorizationWitness, ups::multisig::{MultisigAccount, MultisigSignatures}};
use super::claim_withdrawal::ClaimClient;
use psy_prover::local::bridge_aggregate::{address, reward_record, reward_membership, multisig_authorization, select_multisig_signatures, FreshAuthorizationRequired, ClaimError};


fn wallet_authorization(info: &psy_cli_common::key_utils::WalletKeyInfo, message: [u8; 32]) -> Result<RewardAuthorizationWitness> {
    match info.sign_type {
        SignType::ZKSign => Ok(RewardAuthorizationWitness::Zk { private_key: info.private_key }),
        SignType::SECP256K1Sign | SignType::EthPersonalSECP256K1Sign => {
            let wallet = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&Hash256::from(info.private_key).0)?;
            let compressed_public_key = wallet.compressed_public_key();
            if info.sign_type == SignType::SECP256K1Sign { Ok(RewardAuthorizationWitness::Secp { compressed_public_key, signature_rs: wallet.sign_prehash_raw(&message)? }) }
            else { Ok(RewardAuthorizationWitness::PersonalSign { compressed_public_key, signature_rs: wallet.sign_prehash_raw(&psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message))? }) }
        }
        _ => anyhow::bail!("wallet identity is not a supported reward authorization family"),
    }
}



pub async fn run(args: ClaimRewardsArgs) -> Result<CommandResult> {
    anyhow::ensure!(args.multisig_account.is_some() == args.signatures.is_some(), "--multisig-account and --signatures must be supplied together");
    let user_id = u32::try_from(args.user_id)?;
    let recipient = address(&args.recipient)?;
    anyhow::ensure!(recipient != [0; 20], "reward recipient must be nonzero");
    let account: Option<MultisigAccount> = if let Some(path) = &args.multisig_account {
        anyhow::ensure!(args.wallet.private_key.is_none() && args.wallet.keystore_path.is_none() && args.wallet.fingerprint.is_none() && args.wallet.wallet_password.is_none(), "multisig authorization conflicts with secret wallet inputs");
        let account: MultisigAccount = serde_json::from_slice(&std::fs::read(path)?)?;
        account.public_key_param()?;
        Some(account)
    } else { None };
    let wallet = if account.is_none() {
        anyhow::ensure!(matches!(args.wallet.sign_type, SignType::ZKSign | SignType::SECP256K1Sign | SignType::EthPersonalSECP256K1Sign), "unsupported reward wallet identity");
        Some(load_wallet_key_info(&args.wallet, false)?)
    } else { None };
    let client = ClaimClient::load(&args.rpc_config, &args.aggregate_config, &args.services_url)?;
    let jobs = validate_and_deduplicate_jobs(load_job_ids_from_file(&args.jobs_file)?, args.user_id, &args.jobs_file)?;
    anyhow::ensure!(jobs.jobs_len() != 0, "no reward jobs selected");
    let mut proofs = build_realm_proofs(&client.provider, jobs.realm_jobs).await?;
    for (checkpoint, batch) in build_proofs(&client.provider, jobs.coordinator_jobs, 2).await? { proofs.entry(checkpoint).or_default().extend(batch); }
    let mut selected = Vec::new();
    let mut checkpoints: Vec<_> = proofs.keys().copied().collect();
    checkpoints.sort_unstable();
    for checkpoint in checkpoints {
        for proof in &proofs[&checkpoint] {
            let (record, tag) = reward_record(checkpoint, user_id, recipient, proof)?;
            selected.push((record, tag, proof.inner.tag_tree_proof.root));
        }
    }
    anyhow::ensure!(!selected.is_empty(), "no reward witnesses returned");
    let mut context = client.context().await?;
    for (reward, tag, tag_root) in selected {
        loop {
            let attempt: Result<()> = async {
                let membership = reward_membership(&client, &context, &reward).await?;
                anyhow::ensure!(membership.claim_checkpoint_leaf.stats.pm_rewards_commitment.gutas_root == tag_root, "reward proof does not reach authenticated full GUTA root");
                let authorization = if let Some(account) = &account {
                    let identity = client.circuits.entries().iter().find(|entry| entry.family == 4 && entry.level == 0 && entry.variant == 3).context("missing pinned multisig authorization identity")?.identity_fingerprint;
                    let public_key = psy_crypto::signature::zk::data::ZKPublicKeyInfo { fingerprint: QHashOut::from_values(identity[0], identity[1], identity[2], identity[3]), public_key_param: account.public_key_param()? }.qfhash::<PsyHasher>();
                    anyhow::ensure!(membership.authorization_user_leaf.public_key == public_key, "chosen-end account differs from multisig enrollment");
                    let bundles: Vec<MultisigSignatures> = serde_json::from_slice(&std::fs::read(args.signatures.as_ref().context("missing multisig signatures path")?)?)?;
                    let signatures = match select_multisig_signatures(&bundles, &membership.message()?)? {
                        Some(signatures) => signatures,
                        None => {
                            let request = FreshAuthorizationRequired::new(&context, &membership)?;
                            println!("{}", serde_json::to_string(&request)?);
                            return Err(request.into());
                        }
                    };
                    multisig_authorization(&client, &context, &reward, &membership, account, signatures).await?
                } else {
                    let wallet = wallet.as_ref().context("missing selected wallet")?;
                    anyhow::ensure!(membership.authorization_user_leaf.public_key == wallet.public_key_hash, "chosen-end user identity differs from selected wallet");
                    wallet_authorization(wallet, membership.message()?)?
                };
                let input = RewardAuthorizationInput { context: membership, authorization };
                let proof = client.circuits.reward.authorization_circuits().prove(&input)?;
                let request = client.prove_reward(&context, &input.context, &tag, &proof, &client.circuits.reward)?;
                client.submit(&context, request).await
            }.await;
            match attempt {
                Ok(()) => break,
                Err(error) => match error.downcast_ref::<ClaimError>() { Some(ClaimError::ContextChanged(current)) => context = current.clone(), _ => return Err(error) },
            }
        }
    }
    Ok(CommandResult::generic("claim-rewards"))
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

pub async fn build_realm_proofs(
    provider: &RpcProvider,
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
        let job = QProvingJobDataIDWithRewardPreimage::new(
            metadata.job_id,
            metadata.reward_tree_node_key.index,
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
