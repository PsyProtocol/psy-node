use std::collections::BTreeMap;
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, TxHash, TxKind, U256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result};
use hashbrown::HashMap;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
};
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::{
    args::SignType,
    data::qhashout::QHashOut,
    job::id::{QProvingJobDataID, QProvingJobDataIDWithRewardPreimage},
};
use psy_client_data::{
    api::reward::PsyProvingJobClaimMetadata,
    reward_claim::RewardClaim,
    traits::qdatastore::qmetadata::QMetaDataStoreReaderSync,
};
use psy_provider::provider::RpcProvider;
use psy_prover::local::reward_client::{
    bind_reward_checkpoint_statement, canonical_quantity, chain_id_word, decode_address, encode_reward_claim_calldata, encode_u64_word, recipient_limbs, reward_claim_chain,
    RewardCheckpointStatement, RewardClaimWrapProofInput, RewardClient, RewardJobAggregate, RewardJobAggregateCache,
    RewardJobOriginals, RewardPendingSelection, UserRewardCircuits,
};
use psy_plonky2_circuits::bridge::circuits::user_reward_checkpoint_aggregate::{UserRewardCheckpointAggregateCircuit, UserRewardCheckpointAggregateWitness, REWARD_CLAIM_MAX_CHECKPOINTS, USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT};

use super::args::ClaimRewardsArgs;
use super::claim_withdrawal::rpc_call;
use crate::result::{CommandResult, L1TransactionResult, L1TransactionStatus};
use psy_prover::signature::traits::SignatureUser;
use psy_prover::signature::users::zk_user::ZKUser;
use psy_crypto::signature::zk::wallet::SimplePsyPrivateKey;
use psy_crypto::common::user_id::get_registration_id_from_user_id;
use psy_client_data::config::store_config::PsyHasher;
use psy_crypto::hash::traits::qhashable::QFieldHashable;

pub async fn run(args: ClaimRewardsArgs) -> Result<CommandResult> {
    let user_id = u32::try_from(args.user_id)?;
    let recipient = decode_address(&args.recipient)?;
    anyhow::ensure!(recipient != [0; 20], "reward recipient must be nonzero");

    let wallet = Some(load_wallet_key_info(&args.wallet, false)?);
    let (client, circuits) = RewardClient::load(&args.rpc_config)?;
    let wallet = wallet.context("reward root requires the selected ZK private key")?;
    anyhow::ensure!(wallet.sign_type == SignType::ZKSign, "reward root accepts only ZK authorization");
    let signer = ZKUser::new(SimplePsyPrivateKey { private_key: wallet.private_key });
    let chain_id_hex: String = serde_json::from_value(rpc_call(&args.l1_rpc_url, "eth_chainId", serde_json::json!([])).await?)?;
    let chain_id = chain_id_word(canonical_quantity(&chain_id_hex)?)?;
    anyhow::ensure!(reward_claim_chain(chain_id), "reward chain identity must be 1, 31337, or 11155111");
    let block = client.read_l1_block(&args.l1_rpc_url).await?;
    let deployment = client.discover_reward_deployment(&args.l1_rpc_url, &block, &args.reward_token).await?;
    let token = format!("0x{}", hex::encode(deployment.token));
    let state_manager_address = format!("0x{}", hex::encode(deployment.state_manager));
    let loaded = validate_and_deduplicate_jobs(load_reward_jobs(&args.jobs_file)?, args.user_id, &args.jobs_file)?;
    anyhow::ensure!(loaded.jobs_len() != 0, "no reward jobs selected");
    let grouped = client.group_reward_jobs(loaded.into(), user_id, recipient).await?;
    let unloaded_ids = grouped.unloaded.keys().copied().collect::<Vec<_>>();
    let groups = grouped.groups;
    let (anchor_id, root_word, recognized) = client.read_finalized_checkpoint(&args.l1_rpc_url, &block, &state_manager_address).await?;
    let mut eligible = Vec::new();
    let mut remaining = Vec::new();
    for (checkpoint, originals) in groups {
        if client.read_claimed_pair(&args.l1_rpc_url, &block, &token, user_id, checkpoint).await? { continue; }
        if recognized && checkpoint <= anchor_id { eligible.push(originals); } else { remaining.push(originals); }
    }
    if eligible.is_empty() && !unloaded_ids.is_empty() {
        let ids = unloaded_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(",");
        anyhow::bail!("reward source groups unavailable: {ids}; original jobs file unchanged");
    }
    if eligible.is_empty() {
        preaggregate_remaining(&client, &circuits, &args, &token, remaining, None).await?;
        return Ok(CommandResult::L1Transaction(L1TransactionResult { transaction_hash: None, status: L1TransactionStatus::ProofOnly, chain_id: Some(chain_id) }));
    }
    eligible.sort_by_key(|originals| originals.source_checkpoint_id);
    let checkpoint_circuit = UserRewardCheckpointAggregateCircuit::new(&circuits.user_reward_root);
    let mut confirmed_hashes: Vec<String> = Vec::new();
    let mut submitted_hash: Option<String> = None;
    for chunk in eligible.chunks(REWARD_CLAIM_MAX_CHECKPOINTS) {
        let outcome = async {
        let mut claims = Vec::with_capacity(chunk.len());
        let mut proofs = Vec::with_capacity(chunk.len());
        let mut deferred = Vec::new();
        for originals in chunk {
            let material = async {
                let source = client.rpc_provider.get_checkpoint_leaf_data(u64::from(originals.source_checkpoint_id)).await?;
                let anchor = client.load_finalized_reward_anchor(anchor_id, root_word, originals).await?;
                Ok::<_, anyhow::Error>((source, anchor))
            }.await;
            let (source, anchor) = match material {
                Ok(material) => material,
                Err(error) => { tracing::warn!(checkpoint_id = originals.source_checkpoint_id, %error, "reward historical material unavailable; whole selection remains pending"); deferred.push(originals.clone()); continue; }
            };
            let aggregate = load_or_prove_aggregate(&client, &circuits, &args, originals, &source)?;
            let root = client.prove_finalized_reward_root(&circuits.user_reward_root, &circuits.user_reward_leaf, &circuits.user_reward_aggregate, &aggregate, &anchor, recipient_limbs(&recipient))?;
            let pi: [u64; 23] = root.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>().try_into().map_err(|_| anyhow::anyhow!("reward root statement width mismatch"))?;
            claims.push(RewardClaim::from_public_inputs(&pi)?);
            proofs.push(checkpoint_circuit.prove(&UserRewardCheckpointAggregateWitness::Root { root })?);
        }
        remaining.extend(deferred);
        if proofs.is_empty() { return Ok(()); }
        while proofs.len() > 1 {
            let mut round = proofs.into_iter();
            let mut reduced = Vec::new();
            while let Some(left) = round.next() {
                reduced.push(match round.next() {
                    Some(right) => checkpoint_circuit.prove(&UserRewardCheckpointAggregateWitness::Pair { left, right })?,
                    None => left,
                });
            }
            proofs = reduced;
        }
        let proof = proofs.pop().context("no eligible checkpoint proof")?;
        let statement = bind_reward_checkpoint_statement(&proof.public_inputs, user_id, &recipient, &root_word, &claims)?;
        let anchor = client.load_finalized_reward_anchor(anchor_id, root_word, chunk.first().context("reward claim has no payable group")?).await?;
        let wrapped = signer.prove_reward_claim(&client, &checkpoint_circuit, &proof, &anchor, deployment.token, deployment.state_manager).await?;
        let request_proof = RewardClaimWrapProofInput { reward_claim_wrap_proof_hex: hex::encode(bincode::serialize(&wrapped)?) };
        let wrap = client.prove_reward_claim_groth16(&args.prove_proxy_url, args.prove_proxy_token.as_deref(), &request_proof).await?;
        tracing::info!("Groth16 reward claim proof generated");
        let data = encode_reward_claim_calldata(&wrap.solidity_proof, user_id, recipient, &statement)?;
        let block = client.read_l1_block(&args.l1_rpc_url).await?;
        anyhow::ensure!(client.read_reward_root_recognized(&args.l1_rpc_url, &block, &state_manager_address, statement.checkpoint_tree_root).await?, "reward checkpoint root is no longer recognized");
        for id in &statement.checkpoint_ids {
            anyhow::ensure!(!client.read_claimed_pair(&args.l1_rpc_url, &block, &token, user_id, *id).await?, "reward checkpoint {id} is already claimed; rebuild the selected unclaimed batch");
        }
        let token_address = Address::from(deployment.token);
        let l1_signer: PrivateKeySigner = args.l1_private_key.parse()?;
        let from = l1_signer.address();
        let nonce_hex: String = serde_json::from_value(
            rpc_call(&args.l1_rpc_url, "eth_getTransactionCount", serde_json::json!([format!("{:#x}", from), "latest"])).await?,
        )?;
        let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16).map_err(|error| anyhow::anyhow!("reward nonce parse: {error}"))?;
        let gas_estimate = match rpc_call(
            &args.l1_rpc_url,
            "eth_estimateGas",
            serde_json::json!([{
                "from": format!("{:#x}", from),
                "to": format!("{:#x}", token_address),
                "data": format!("0x{}", hex::encode(&data)),
            }]),
        )
        .await
        {
            Ok(value) => value,
            Err(err) => Err(err)?,
        };
        let gas_hex: String = serde_json::from_value(gas_estimate).context("reward gas estimate type")?;
        let estimated_gas = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16).map_err(|error| anyhow::anyhow!("reward gas estimate parse: {error}"))?;
        let gas_limit = estimated_gas.checked_mul(6).context("reward gas estimate overflow")? / 5;

        let fee_history = rpc_call(&args.l1_rpc_url, "eth_feeHistory", serde_json::json!([1, "latest", [50.0]])).await?;
        let base_fee_str = fee_history["baseFeePerGas"][0].as_str().context("reward fee history has no base fee")?;
        let base_fee = u128::from_str_radix(base_fee_str.trim_start_matches("0x"), 16).map_err(|error| anyhow::anyhow!("reward base fee parse: {error}"))?;
        let priority_str = fee_history["reward"][0][0].as_str().context("reward fee history has no priority fee")?;
        let max_priority_fee = u128::from_str_radix(priority_str.trim_start_matches("0x"), 16).map_err(|error| anyhow::anyhow!("reward priority fee parse: {error}"))?;
        let max_fee_per_gas = base_fee.checked_mul(2).context("reward base fee overflow")?.checked_add(max_priority_fee).context("reward max fee overflow")?;

        let tx = TxEip1559 {
            chain_id,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas: max_priority_fee,
            gas_limit,
            to: TxKind::Call(token_address),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::from(data),
            access_list: Default::default(),
        };
        let sig = l1_signer.sign_hash(&tx.signature_hash()).await?;
        let signed = tx.into_signed(sig);
        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);
        let tx_hash_raw: String = match rpc_call(&args.l1_rpc_url, "eth_sendRawTransaction", serde_json::json!([format!("0x{}", hex::encode(&encoded))])).await {
            Ok(value) => serde_json::from_value(value)?,
            Err(err) => Err(err)?,
        };
        let tx_hash: TxHash = tx_hash_raw.parse()?;
        submitted_hash = Some(format!("{:#x}", tx_hash));
        tracing::info!("claim_reward tx submitted: {:#x}", tx_hash);
        println!("claim_reward tx: {:#x}", tx_hash);

        let receipt_deadline = std::time::Instant::now() + std::time::Duration::from_secs(RECEIPT_WAIT_SECS);
        let receipt = loop {
            anyhow::ensure!(std::time::Instant::now() < receipt_deadline, "reward claim receipt not observed within {}s: tx_hash={:#x}", RECEIPT_WAIT_SECS, tx_hash);
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let result = rpc_call(&args.l1_rpc_url, "eth_getTransactionReceipt", serde_json::json!([format!("{:#x}", tx_hash)])).await;
            match result {
                Ok(value) if !value.is_null() => break value,
                _ => continue,
            }
        };
        let receipt = client.read_canonical_reward_receipt(&args.l1_rpc_url, &format!("{:#x}", tx_hash), &receipt).await?;
        let status_str = receipt["status"].as_str().context("reward receipt has no status")?;
        anyhow::ensure!(status_str == "0x0" || status_str == "0x1", "malformed reward receipt status: {status_str}");
        let receipt_status = u64::from_str_radix(status_str.trim_start_matches("0x"), 16).map_err(|error| anyhow::anyhow!("reward receipt status parse: {error}"))?;
        println!("status: {}", if receipt_status == 1 { "success" } else { "failed" });
        if receipt_status != 1 {
            let trace = rpc_call(&args.l1_rpc_url, "debug_traceTransaction", serde_json::json!([format!("{:#x}", tx_hash), {"tracer": "callTracer"}])).await;
            let revert_reason = trace.ok().and_then(|value| value["revertReason"].as_str().map(str::to_owned));
            Err(anyhow::anyhow!("reward claim transaction reverted: tx_hash={:#x}, reason={}", tx_hash, revert_reason.as_deref().unwrap_or("unknown")))?;
        }
        client.reward_claimed_event(&receipt, deployment.token, user_id, recipient, &statement)?;
        client.mint_transfer_event(&receipt, deployment.token, recipient, statement.total_amount)?;
        let receipt_block = receipt["blockHash"].as_str().context("reward receipt has no block hash")?;
        for id in &statement.checkpoint_ids {
            anyhow::ensure!(client.read_claimed_pair(&args.l1_rpc_url, receipt_block, &token, user_id, *id).await?, "reward token claimed pair differs for checkpoint {id}");
        }
        confirmed_hashes.push(submitted_hash.take().context("confirmed reward claim has no submitted hash")?);
        Ok(())
        }.await;
        if let Err(error) = outcome {
            return Err(attach_claim_hashes(error, &confirmed_hashes, submitted_hash.as_deref()));
        }
    }
    preaggregate_remaining(&client, &circuits, &args, &token, remaining, confirmed_hashes.last().map(String::as_str)).await.map_err(|error| attach_claim_hashes(error, &confirmed_hashes, None))?;
    if !unloaded_ids.is_empty() {
        let ids = unloaded_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(",");
        return Err(attach_claim_hashes(anyhow::anyhow!("reward source groups unavailable: {ids}; original jobs file unchanged"), &confirmed_hashes, None));
    }
    let status = if confirmed_hashes.is_empty() { L1TransactionStatus::ProofOnly } else { L1TransactionStatus::Confirmed };
    Ok(CommandResult::L1Transaction(L1TransactionResult {
        transaction_hash: confirmed_hashes.last().cloned(),
        status,
        chain_id: Some(chain_id),
    }))
}
const RECEIPT_WAIT_SECS: u64 = 120;



fn load_or_prove_aggregate(client: &RewardClient, circuits: &UserRewardCircuits, args: &ClaimRewardsArgs, originals: &RewardJobOriginals, source: &psy_client_data::qdata::checkpoint::PsyCheckpointLeaf<GoldilocksField>) -> Result<RewardJobAggregate> {
    let directory = std::path::Path::new(&args.proof_cache_dir);
    std::fs::create_dir_all(directory)?;
    anyhow::ensure!(!std::fs::canonicalize(&args.jobs_file)?.starts_with(std::fs::canonicalize(directory)?), "original jobs must be outside the disposable cache directory");
    let path = directory.join(format!("{:016x}-{}-{}.json", psy_config::network_constants::PSY_NETWORK_MAGIC, originals.user_id, originals.source_checkpoint_id));
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(cache) = serde_json::from_slice::<RewardJobAggregateCache>(&bytes) {
            if let Ok(Some(aggregate)) = client.reuse_reward_job_aggregate(&circuits.user_reward_leaf, &circuits.user_reward_aggregate, &cache, originals, source) { return Ok(aggregate); }
        }
    }
    let aggregate = client.prove_reward_job_aggregate(&circuits.user_reward_leaf, &circuits.user_reward_aggregate, originals.user_id, originals.source_checkpoint_id, source, &originals.jobs)?;
    cache_proved_aggregate(circuits, &path, &aggregate)?;
    Ok(aggregate)
}

async fn preaggregate_remaining(client: &RewardClient, circuits: &UserRewardCircuits, args: &ClaimRewardsArgs, token: &str, remaining: Vec<RewardJobOriginals>, confirmed_tx: Option<&str>) -> Result<()> {
    let block = client.read_l1_block(&args.l1_rpc_url).await.map_err(|error| attach_confirmed_payout(error, confirmed_tx))?;
    for originals in remaining {
        if client.read_claimed_pair(&args.l1_rpc_url, &block, token, originals.user_id, originals.source_checkpoint_id).await.map_err(|error| attach_confirmed_payout(error, confirmed_tx))? { continue; }
        match client.rpc_provider.get_checkpoint_leaf_data(u64::from(originals.source_checkpoint_id)).await {
            Ok(source) => { let _aggregate = load_or_prove_aggregate(client, circuits, args, &originals, &source).map_err(|error| attach_confirmed_payout(error, confirmed_tx))?; }
            Err(error) => tracing::warn!(checkpoint_id = originals.source_checkpoint_id, %error, "complete reward source unavailable; originals remain pending"),
        };
    }
    Ok(())
}

fn attach_claim_hashes(error: anyhow::Error, confirmed: &[String], submitted: Option<&str>) -> anyhow::Error {
    let mut parts = Vec::new();
    if !confirmed.is_empty() { parts.push(format!("confirmed_tx={}", confirmed.join(","))); }
    if let Some(hash) = submitted { parts.push(format!("submitted_tx={hash}")); }
    if parts.is_empty() { error } else { error.context(parts.join("; ")) }
}
fn attach_confirmed_payout(error: anyhow::Error, confirmed_tx: Option<&str>) -> anyhow::Error {
    attach_claim_hashes(error, confirmed_tx.map(|hash| vec![hash.to_owned()]).as_deref().unwrap_or(&[]), None)
}

fn cache_proved_aggregate(circuits: &UserRewardCircuits, path: &std::path::Path, aggregate: &RewardJobAggregate) -> Result<()> {
    let (cache, _) = aggregate.build_reward_job_aggregate_cache(circuits)?;
    crate::result::write_json_atomically(path, &cache)
}


#[derive(Debug)]
struct ClaimRewardJobsWithRealm {
    realm_jobs: Vec<(u64, u64, u64, QProvingJobDataIDWithRewardPreimage)>,
    coordinator_jobs: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
}

impl ClaimRewardJobsWithRealm {
    fn new_empty() -> Self { Self { realm_jobs: vec![], coordinator_jobs: vec![] } }
    fn jobs_len(&self) -> usize { self.realm_jobs.len() + self.coordinator_jobs.len() }
}

impl From<ClaimRewardJobsWithRealm> for RewardPendingSelection {
    fn from(jobs: ClaimRewardJobsWithRealm) -> Self { Self { realm_jobs: jobs.realm_jobs, coordinator_jobs: jobs.coordinator_jobs } }
}

fn validate_and_deduplicate_jobs(
    jobs: ClaimRewardJobsWithRealm,
    expected_user_id: u64,
    jobs_file: &str,
) -> Result<ClaimRewardJobsWithRealm> {
    let mut seen: HashMap<QProvingJobDataID, (Option<u64>, u64, u64, u64, QHashOut<GoldilocksField>)> = HashMap::new();
    let mut deduplicated = ClaimRewardJobsWithRealm::new_empty();
    for (realm_id, realm_sub_id, unique_pending_id, job) in jobs.realm_jobs {
        validate_reward_preimage_user(&job, expected_user_id, jobs_file, &format!("realm_id={realm_id} realm_sub_id={realm_sub_id}"))?;
        let identity = (Some(realm_id), realm_sub_id, unique_pending_id, job.inner.reward_path_info, job.reward_tree_tag_preimage);
        match seen.get(&job.inner.job_data_id) {
            Some(existing) if existing == &identity => {}
            Some(_) => anyhow::bail!("jobs file {} contains conflicting duplicate job_id {:?}", jobs_file, job.inner.job_data_id),
            None => {
                seen.insert(job.inner.job_data_id, identity);
                deduplicated.realm_jobs.push((realm_id, realm_sub_id, unique_pending_id, job));
            }
        }
    }
    for (unique_pending_id, job) in jobs.coordinator_jobs {
        validate_reward_preimage_user(&job, expected_user_id, jobs_file, "coordinator")?;
        let identity = (None, 0, unique_pending_id, job.inner.reward_path_info, job.reward_tree_tag_preimage);
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


fn load_reward_jobs(path: &str) -> Result<ClaimRewardJobsWithRealm> {
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
        anyhow::ensure!(
            metadata.reward_tree_node_key.index <= 0x00FF_FFFF_FFFF_FFFF,
            "jobs backup record at offset {} has reward path index {} exceeding 56 bits",
            offset,
            metadata.reward_tree_node_key.index
        );
        let job = QProvingJobDataIDWithRewardPreimage::new(
            metadata.job_id,
            (u64::from(metadata.reward_tree_node_key.level) << 56) | metadata.reward_tree_node_key.index,
            metadata.reward_tree_tag_preimage,
        );
        if metadata.node_type == 1 {
            claim_jobs.realm_jobs.push((metadata.realm_id, metadata.realm_sub_id, metadata.unique_pending_id, job));
        } else {
            claim_jobs.coordinator_jobs.push((metadata.unique_pending_id, job));
        }
    }

    Ok(claim_jobs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::{Arc, atomic::{AtomicBool, Ordering}}};
    use plonky2::{
        field::types::{Field, PrimeField64},
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
        plonk::config::{Hasher, PoseidonGoldilocksConfig},
    };
    use psy_client_data::{
        reward_claim::RewardClaim,
        qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
    };
    use psy_crypto::hash::merkle::core::MerkleProofCore;
    use psy_prover::local::reward_client::RewardClient as PortableRewardClient;
    use psy_plonky2_circuits::bridge::circuits::user_reward_tree::{
        UserRewardAggregateCircuit, UserRewardJobWitness, UserRewardLeafCircuit, UserRewardRootCircuit,
    };
    type F = GoldilocksField;

    struct Server { url: String, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
    impl Server {
        fn new(reply: impl Fn(serde_json::Value) -> serde_json::Value + Send + 'static) -> Self {
            use std::io::{BufRead, Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let stop = Arc::new(AtomicBool::new(false)); let stopped = stop.clone();
            let thread = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopped.load(Ordering::SeqCst) { break; }
                    let mut stream = stream.unwrap();
                    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
                    let mut reader = std::io::BufReader::new(&mut stream); let mut length = None;
                    loop {
                        let mut line = String::new(); assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                        if line == "\r\n" { break; }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("content-length") { length = Some(value.trim().parse::<usize>().unwrap()); }
                        }
                    }
                    let mut body = vec![0; length.unwrap()]; reader.read_exact(&mut body).unwrap(); drop(reader);
                    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let response = serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":reply(request.clone())}).to_string();
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
                }
            });
            Self { url, stop, thread: Some(thread) }
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = std::net::TcpStream::connect(self.url.trim_start_matches("http://"));
            self.thread.take().unwrap().join().unwrap();
        }
    }
    fn path(leaves: &BTreeMap<u64, HashOut<F>>, index: u64) -> MerkleProofCore<QHashOut<F>> {
        let value = leaves[&index]; let mut nodes = leaves.clone(); let mut cursor = index;
        let mut empty = HashOut::ZERO; let mut siblings = Vec::new();
        for _ in 0..32 {
            siblings.push(QHashOut(nodes.get(&(cursor ^ 1)).copied().unwrap_or(empty)));
            let mut parents = BTreeMap::new();
            for child in nodes.keys() { parents.insert(child >> 1, PoseidonHash::two_to_one(nodes.get(&(child & !1)).copied().unwrap_or(empty), nodes.get(&(child | 1)).copied().unwrap_or(empty))); }
            nodes = parents; cursor >>= 1; empty = PoseidonHash::two_to_one(empty, empty);
        }
        MerkleProofCore { root: QHashOut(nodes[&0]), value: QHashOut(value), index, siblings }
    }
    struct Fixture {
        server: Server, client: PortableRewardClient,
        claimed: Arc<tokio::sync::Mutex<BTreeMap<(u32, u32), bool>>>,
        private_key: HashOut<F>, jobs: Vec<UserRewardJobWitness>,
    }
    impl Fixture {
        fn new() -> Self {
            let private_key = QHashOut::from_values(17, 23, 31, 47);
            let param = psy_ups_circuit::signature::sd_key_plonky2::get_sdc_public_key_param(&private_key);
            let identity = psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit::<PoseidonGoldilocksConfig, 2>::new().fingerprint.0;
            let registration_leaf = PoseidonHash::two_to_one(identity, param.0);
            let registration_index = get_registration_id_from_user_id(7);
            let registration_path = path(&BTreeMap::from([(registration_index, registration_leaf)]), registration_index);
            let mut roots = PsyCheckpointGlobalStateRoots::default(); roots.user_registration_tree_root = registration_path.root;
            let mut anchor = PsyCheckpointLeaf::default(); anchor.global_chain_root = roots.qfhash::<PsyHasher>();
            let preimage = parth_core::pgoldilocks::QHashOut::from_values(7, 1, 0, 0);
            let tag = PoseidonHash::two_to_one(preimage.0, preimage.0);
            let tagged = |left, right, tag| PoseidonHash::two_to_one(PoseidonHash::two_to_one(left, right), tag);
            let mut levels = vec![(0..128).map(|index| tagged(QHashOut::from_values(index, 0, 0, 0).0, HashOut::ZERO, tag)).collect::<Vec<_>>()];
            for level in 0..7 { levels.push(levels[level].chunks_exact(2).map(|pair| tagged(pair[0], pair[1], HashOut::ZERO)).collect()); }
            let jobs = (0..18usize).map(|index| UserRewardJobWitness {
                source_checkpoint_id: 10, height: 7, path_index: index as u32,
                tag: psy_plonky2_circuits::bridge::circuits::user_reward_tree::UserRewardTagWitness {
                    tag_preimage: preimage, leaf_left: parth_core::pgoldilocks::QHashOut::from_values(index as u64, 0, 0, 0),
                    leaf_right: parth_core::pgoldilocks::QHashOut::ZERO, leaf_tag: parth_core::pgoldilocks::QHashOut(tag),
                    siblings: std::array::from_fn(|level| if level < 7 { parth_core::pgoldilocks::QHashOut(levels[level][(index >> level) ^ 1]) } else { parth_core::pgoldilocks::QHashOut::ZERO }),
                    parent_tags: [parth_core::pgoldilocks::QHashOut::ZERO; 21],
                },
            }).collect();
            let mut source = PsyCheckpointLeaf::default(); source.stats.pm_rewards_commitment.gutas_root.0 = levels[7][0];
            source.stats.pm_jobs_completed.gutas_completed = F::from_canonical_u32(32); source.stats.guta_fees_collected = F::from_canonical_u32(320);
            let checkpoints = BTreeMap::from([(10, source.qfhash::<PsyHasher>().0), (11, anchor.qfhash::<PsyHasher>().0), (12, anchor.qfhash::<PsyHasher>().0)]);
            let checkpoint_root = path(&checkpoints, 11).root;
            let claimed = Arc::new(tokio::sync::Mutex::new(BTreeMap::new())); let claimed_read = claimed.clone();
            let server = Server::new(move |request| {
                let method = request["method"].as_str().unwrap();
                match method {
                    "eth_chainId" => serde_json::json!("0x1"),
                    "eth_getBlockByNumber" => { let tag = request["params"][0].as_str().unwrap().to_owned(); assert!(tag == "0x2a" || tag == "latest"); serde_json::json!({"hash": format!("0x{}", "ab".repeat(32))}) },
                    "eth_call" => {
                        assert_eq!(request["params"][0]["to"], format!("0x{}", "05".repeat(20)));
                        assert_eq!(request["params"][1], serde_json::json!({"blockHash":format!("0x{}", "ab".repeat(32)),"requireCanonical":true}));
                        let data = hex::decode(request["params"][0]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                        assert_eq!(&data[..4], &alloy_primitives::keccak256(b"claimed(uint32,uint32)")[..4]);
                        assert_eq!(data.len(), 68);
                        let user = u32::from_be_bytes(data[32..36].try_into().unwrap());
                        let checkpoint = u32::from_be_bytes(data[64..68].try_into().unwrap());
                        let value = claimed_read.blocking_lock().get(&(user, checkpoint)).copied().unwrap_or(false);
                        serde_json::json!(format!("0x{}{:02x}", "00".repeat(31), u8::from(value)))
                    },
                    "psy_get_checkpoint_leaf_data" => serde_json::to_value(if request["params"]["checkpoint_id"] == 10 { source } else { anchor }).unwrap(),
                    "psy_get_checkpoint_tree_merkle_proof" => serde_json::to_value(path(&checkpoints, request["params"]["leaf_checkpoint_id"].as_u64().unwrap())).unwrap(),
                    "psy_get_checkpoint_global_state_roots" => serde_json::to_value(roots).unwrap(),
                    "psy_get_user_registration_tree_leaf_hash" => serde_json::to_value(QHashOut(registration_leaf)).unwrap(),
                    "psy_get_user_registration_tree_merkle_proof" => serde_json::to_value(&registration_path).unwrap(),
                    _ => panic!("unexpected RPC {method}"),
                }
            });
            let rpc_provider = RpcProvider { client: Arc::new(reqwest::Client::new()), endpoint_clients: None, realm_configs: std::collections::HashMap::new(), coordinator_configs: std::collections::HashMap::from([(0, vec![server.url.clone()])]), users_per_realm: 1 << psy_config::network_constants::REALM_USER_TREE_HEIGHT, current_user_id: 0 };
            let client = PortableRewardClient::new(rpc_provider);
            Self { server, client, claimed, private_key: private_key.0, jobs }
        }
        fn recipient() -> [u8; 20] { decode_address("0x0102030405060708090a0b0c0d0e0f1011121314").unwrap() }
    }

    #[tokio::test]
    async fn aggregate_cache_loss_rebuilds_exact_selection() {
        let fixture = Fixture::new();
        let leaf = UserRewardLeafCircuit::new();
        let aggregate = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&aggregate);
        let circuits = UserRewardCircuits { user_reward_leaf: leaf, user_reward_aggregate: aggregate, user_reward_root: root };
        let source = fixture.client.rpc_provider.get_checkpoint_leaf_data(10).await.unwrap();
        let prove = || fixture.client.prove_reward_job_aggregate(&circuits.user_reward_leaf, &circuits.user_reward_aggregate, 7, 10, &source, &fixture.jobs[..2]).unwrap();
        let first = prove();
        let (cache, originals) = first.build_reward_job_aggregate_cache(&circuits).unwrap();
        assert!(fixture.client.reuse_reward_job_aggregate(&circuits.user_reward_leaf, &circuits.user_reward_aggregate, &cache, &originals, &source).unwrap().is_some());
        drop(cache);
        let rebuilt = prove();
        assert_eq!(first.proof.public_inputs, rebuilt.proof.public_inputs);
        let mut mixed = fixture.jobs[..2].to_vec(); mixed[1].source_checkpoint_id = 11;
        assert!(fixture.client.prove_reward_job_aggregate(&circuits.user_reward_leaf, &circuits.user_reward_aggregate, 7, 10, &source, &mixed).is_err());
    }

    #[tokio::test]
    async fn paid_preaggregation_failure_keeps_confirmed_hash_and_source_error() {
        let fixture = Fixture::new();
        let leaf = UserRewardLeafCircuit::new();
        let aggregate_circuit = UserRewardAggregateCircuit::new(&leaf);
        let root = UserRewardRootCircuit::new(&aggregate_circuit);
        let circuits = UserRewardCircuits { user_reward_leaf: leaf, user_reward_aggregate: aggregate_circuit, user_reward_root: root };
        let originals = RewardJobOriginals { user_id: 7, source_checkpoint_id: 10, jobs: fixture.jobs[..2].to_vec() };
        let root_dir = std::env::temp_dir().join(format!("claim-paid-preaggregate-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let jobs_file = root_dir.join("jobs.bin");
        let cache_dir = root_dir.join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(&jobs_file, []).unwrap();
        let cache_name = format!("{:016x}-7-10.json", psy_config::network_constants::PSY_NETWORK_MAGIC);
        std::fs::create_dir(cache_dir.join(&cache_name)).unwrap();
        std::fs::write(cache_dir.join(&cache_name).join("occupied"), []).unwrap();
        let token = format!("0x{}", "05".repeat(20));
        let args = ClaimRewardsArgs {
            rpc_config: String::new(), reward_token: String::new(), recipient: String::new(), user_id: 7,
            wallet: crate::subcommand::args::WalletSourceArgs { sign_type: psy_client_common::args::SignType::ZKSign, private_key: None, keystore_path: None, wallet_password: None, fingerprint: None, sd_key_allowed_contract_id: vec![], sd_key_allowed_method_id: vec![], sd_key_min_tx_count: Some(2), sd_key_max_tx_count: Some(2), sd_key_definition: None },
            jobs_file: jobs_file.to_str().unwrap().to_owned(), proof_cache_dir: cache_dir.to_str().unwrap().to_owned(),
            l1_rpc_url: fixture.server.url.clone(), l1_private_key: String::new(), prove_proxy_url: String::new(), prove_proxy_token: None,
        };
        let paid_hash = format!("0x{}", "cd".repeat(32));
        let error = preaggregate_remaining(&fixture.client, &circuits, &args, &token, vec![originals], Some(&paid_hash)).await.unwrap_err();
        assert!(error.chain().any(|cause| cause.is::<std::io::Error>()), "cache write error was replaced: {error:#}");
        assert!(error.chain().any(|cause| cause.to_string().contains(&paid_hash)), "confirmed hash dropped: {error:#}");
        assert!(jobs_file.is_file());
        std::fs::remove_dir_all(root_dir).unwrap();
    }

    #[tokio::test]
    async fn claimed_bool_decides_eligibility_without_cursor() {
        let fixture = Fixture::new();
        let token = format!("0x{}", "05".repeat(20));
        let url = &fixture.server.url;
        assert!(!fixture.client.read_claimed_pair(url, "0x2a", &token, 7, 10).await.unwrap());
        assert!(!fixture.client.read_claimed_pair(url, "0x2a", &token, 7, 9).await.unwrap());
        fixture.claimed.lock().await.insert((7, 10), true);
        assert!(fixture.client.read_claimed_pair(url, "0x2a", &token, 7, 10).await.unwrap());
        assert!(!fixture.client.read_claimed_pair(url, "0x2a", &token, 8, 10).await.unwrap());
    }

    #[test]
    fn claim_reward_abi_decodes_complete_list_and_total() {
        let mut proof_words = ["1".to_owned(), "1".to_owned(), "1".to_owned(), "1".to_owned(), "1".to_owned(), "1".to_owned(), "1".to_owned(), "1".to_owned()];
        for count in [1usize, 64] {
            let ids: Vec<u32> = (0..count as u32).collect();
            let total = encode_u64_word(u64::try_from(count).unwrap() * 2);
            let mut root = [0u8; 32]; root[0] = 0x11; root[31] = 1;
            let statement = RewardCheckpointStatement { checkpoint_tree_root: root, checkpoint_ids: ids.clone(), total_amount: total };
            let data = encode_reward_claim_calldata(&proof_words, 7, [1; 20], &statement).unwrap();
            assert_eq!(&data[..4], &alloy_primitives::keccak256(b"claimReward(bytes,bytes32,uint32,address,uint32[],uint256)")[..4]);
            assert_eq!(&data[4..4 + 32], &encode_u64_word(192));
            assert_eq!(&data[4 + 32..4 + 64], &root);
            assert_eq!(&data[4 + 64..4 + 96], &encode_u64_word(7));
            assert_eq!(&data[4 + 108..4 + 128], &[1; 20]);
            assert_eq!(&data[4 + 128..4 + 160], &encode_u64_word(480));
            assert_eq!(&data[4 + 160..4 + 192], &total);
            assert_eq!(&data[4 + 192..4 + 224], &encode_u64_word(256));
            for index in 0..8 {
                assert_eq!(&data[4 + 224 + index * 32..4 + 256 + index * 32], &encode_u64_word(1));
            }
            assert_eq!(&data[4 + 480..4 + 512], &encode_u64_word(u64::try_from(count).unwrap()));
            for (index, id) in ids.iter().enumerate() {
                assert_eq!(&data[4 + 512 + index * 32..4 + 544 + index * 32], &encode_u64_word(u64::from(*id)));
            }
            assert_eq!(data.len(), 4 + 512 + 32 * count);
        }
        let total = encode_u64_word(2);
        let bad = RewardCheckpointStatement { checkpoint_tree_root: [2; 32], checkpoint_ids: vec![0, 0], total_amount: total };
        assert!(encode_reward_claim_calldata(&proof_words, 7, [1; 20], &bad).is_err());
        proof_words[0] = "0".to_owned();
        assert!(encode_reward_claim_calldata(&proof_words, 7, [1; 20], &RewardCheckpointStatement { checkpoint_ids: (0..65).collect(), ..bad }).is_err());
    }

    #[tokio::test]
    async fn claimed_read_errors_do_not_become_unclaimed() {
        let server = Server::new(|request| match request["method"].as_str().unwrap() {
            "eth_chainId" => serde_json::json!("0x1"),
            "eth_call" => serde_json::json!("0x"),
            _ => panic!("unexpected method"),
        });
        let rpc_provider = RpcProvider { client: Arc::new(reqwest::Client::new()), endpoint_clients: None, realm_configs: std::collections::HashMap::new(), coordinator_configs: std::collections::HashMap::from([(0, vec![server.url.clone()])]), users_per_realm: 1, current_user_id: 0 };
        let client = PortableRewardClient::new(rpc_provider);
        let result = client.read_claimed_pair(&server.url, &format!("0x{}", "ab".repeat(32)), "0x1111111111111111111111111111111111111111", 7, 10).await;
        assert!(result.is_err());
    }

    #[test]
    fn confirmation_requires_reward_claimed_and_mint_transfer() {
        let token = [5u8; 20];
        let recipient = [1u8; 20];
        let root = [2u8; 32];
        let total = encode_u64_word(20);
        let statement = RewardCheckpointStatement { checkpoint_tree_root: root, checkpoint_ids: vec![10], total_amount: total };
        let mut recipient_word = [0u8; 32]; recipient_word[12..].copy_from_slice(&recipient);
        let mut claimed_data = encode_u64_word(64).to_vec();
        claimed_data.extend_from_slice(&total);
        claimed_data.extend_from_slice(&encode_u64_word(1));
        claimed_data.extend_from_slice(&encode_u64_word(10));
        let claimed_topic = alloy_primitives::keccak256(b"RewardClaimed(uint32,address,bytes32,uint32[],uint256)");
        let transfer_topic = alloy_primitives::keccak256(b"Transfer(address,address,uint256)");
        let claimed = serde_json::json!({"address":format!("0x{}", hex::encode(token)),"topics":[format!("0x{}",hex::encode(claimed_topic)),format!("0x{}",hex::encode(encode_u64_word(7))),format!("0x{}",hex::encode(recipient_word)),format!("0x{}",hex::encode(root))],"data":format!("0x{}",hex::encode(claimed_data))});
        let transfer = serde_json::json!({"address":format!("0x{}", hex::encode(token)),"topics":[format!("0x{}",hex::encode(transfer_topic)),format!("0x{}",hex::encode([0u8; 32])),format!("0x{}",hex::encode(recipient_word))],"data":format!("0x{}",hex::encode(total))});
        let receipt = serde_json::json!({"logs":[claimed, transfer]});
        let client = PortableRewardClient { rpc_provider: RpcProvider { client: Arc::new(reqwest::Client::new()), endpoint_clients: None, realm_configs: Default::default(), coordinator_configs: Default::default(), users_per_realm: 1, current_user_id: 0 }, http: reqwest::Client::new() };
        client.reward_claimed_event(&receipt, token, 7, recipient, &statement).unwrap();
        client.mint_transfer_event(&receipt, token, recipient, total).unwrap();
        assert!(client.reward_claimed_event(&receipt, token, 7, recipient, &RewardCheckpointStatement { checkpoint_ids: vec![11], ..statement }).is_err());
        assert!(client.mint_transfer_event(&receipt, token, recipient, encode_u64_word(21)).is_err());
    }



    #[test]
    fn aggregate_binding_accepts_nonzero_root_and_rejects_each_mutation() {
        use plonky2::field::types::Field;
        use plonky2::plonk::proof::ProofWithPublicInputs;
        let recipient = [1u8; 20];
        let limbs = recipient_limbs(&recipient);
        let mut root = [0u8; 32]; root[0] = 0x11; root[31] = 1;
        let root_limbs = [
            u64::from_be_bytes(root[24..32].try_into().unwrap()),
            u64::from_be_bytes(root[16..24].try_into().unwrap()),
            u64::from_be_bytes(root[8..16].try_into().unwrap()),
            u64::from_be_bytes(root[..8].try_into().unwrap()),
        ];
        let claims = vec![
            RewardClaim { user_id: 7, contract_id: 7, checkpoint_id: 0, count: 1, recipient, amount: encode_u64_word(5) },
            RewardClaim { user_id: 7, contract_id: 7, checkpoint_id: 9, count: 1, recipient, amount: encode_u64_word(7) },
        ];
        let mut inputs = vec![F::ZERO; USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT];
        inputs[0] = F::from_canonical_u32(7);
        for (index, limb) in limbs.iter().take(5).enumerate() { inputs[1 + index] = F::from_canonical_u32(*limb); }
        for (index, limb) in root_limbs.iter().enumerate() { inputs[6 + index] = F::from_canonical_u64(*limb); }
        inputs[10] = F::from_canonical_u32(2);
        inputs[11] = F::from_canonical_u32(12);
        inputs[15] = F::from_canonical_u32(0);
        inputs[16] = F::from_canonical_u32(9);
        let bound = bind_reward_checkpoint_statement(&inputs, 7, &recipient, &root, &claims).unwrap();
        assert_eq!(bound.checkpoint_tree_root, root);
        assert_eq!(bound.checkpoint_ids, vec![0, 9]);
        assert_eq!(bound.total_amount, encode_u64_word(12));
        let mut reject_at = |index: usize, value: F| {
            let mut changed = inputs.clone();
            changed[index] = value;
            assert!(bind_reward_checkpoint_statement(&changed, 7, &recipient, &root, &claims).is_err());
        };
        reject_at(0, F::from_canonical_u32(8));
        for index in 0..5 { reject_at(1 + index, inputs[1 + index] + F::ONE); }
        for index in 0..4 { reject_at(6 + index, inputs[6 + index] + F::ONE); }
        reject_at(10, F::from_canonical_u32(1));
        reject_at(11, F::from_canonical_u32(11));
        reject_at(15, F::from_canonical_u32(1));
        reject_at(17, F::ONE);
    }

    #[test]
    fn checkpoint_pairing_is_canonical_for_odd_and_large_selections() {
        for count in [1usize, 3, 5, 7, 33, 65] {
            let mut sizes = vec![1usize; count];
            while sizes.len() > 1 {
                let mut round = sizes.into_iter();
                let mut reduced = Vec::new();
                while let Some(left) = round.next() {
                    reduced.push(match round.next() {
                        Some(right) => { assert!(left.is_power_of_two()); assert!((1..=left).contains(&right)); left + right }
                        None => left,
                    });
                }
                sizes = reduced;
            }
            assert_eq!(sizes, vec![count]);
        }
    }


    use psy_client_common::job::id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic};

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
    fn malformed_backup_length_is_rejected() {
        let path = std::env::temp_dir().join(format!("claim-rewards-truncated-{}", std::process::id()));
        std::fs::write(&path, [0u8]).unwrap();
        let error = load_reward_jobs(path.to_str().unwrap()).unwrap_err();
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
        let loaded = load_reward_jobs(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.realm_jobs[0].0, 3);
        assert_eq!(loaded.realm_jobs[0].1, 0);
        assert_eq!(loaded.realm_jobs[0].2, 987);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn colliding_pending_ids_keep_distinct_realm_origins() {
        use psy_crypto::hash::merkle::utils::common::SimpleMerkleNodeKey;
        let mut bytes = Vec::new();
        for (sub, task) in [(1u64, 1u32), (2, 2)] {
            let metadata = PsyProvingJobClaimMetadata {
                job_id: job(task, 7, 10 + sub).inner.job_data_id,
                reward_tree_tag: QHashOut::from_values(1, 2, 3, 4),
                reward_tree_tag_preimage: QHashOut::from_values(7, 0, 10, 11),
                proving_duration_ms: 1,
                job_submitted_at: 2,
                unique_pending_id: 310,
                realm_id: 0,
                realm_sub_id: sub,
                reward_tree_node_key: SimpleMerkleNodeKey { level: 1, index: sub },
                reward_tree_hash_mode: 0,
                reward_tree_node_children: 0,
                node_type: 1,
                api_url_hash: [0; 32],
            };
            bytes.extend(metadata.psy_ser_to_bytes().unwrap());
        }
        let path = std::env::temp_dir().join(format!("claim-rewards-collision-{}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let loaded = validate_and_deduplicate_jobs(load_reward_jobs(path.to_str().unwrap()).unwrap(), 7, "worker.backup").unwrap();
        std::fs::remove_file(path).unwrap();
        let origins: Vec<(u64, u64, u64)> = loaded.realm_jobs.iter().map(|(realm, sub, pending, _)| (*realm, *sub, *pending)).collect();
        assert_eq!(origins, vec![(0, 1, 310), (0, 2, 310)]);
    }


    #[test]
    fn backup_reward_path_roundtrips_through_rpc_job() {
        use psy_crypto::hash::merkle::utils::common::SimpleMerkleNodeKey;
        let cases = [(1u8, 0u64, 1u8), (3, 7, 1), (0, 0, 0)];
        let mut bytes = Vec::new();
        for (level, index, node_type) in cases {
            let metadata = PsyProvingJobClaimMetadata {
                job_id: job(1, 7, 10).inner.job_data_id,
                reward_tree_tag: QHashOut::from_values(1, 2, 3, 4),
                reward_tree_tag_preimage: QHashOut::from_values(7, 0, 10, 11),
                proving_duration_ms: 1,
                job_submitted_at: 2,
                unique_pending_id: 64,
                realm_id: 3,
                realm_sub_id: 0,
                reward_tree_node_key: SimpleMerkleNodeKey { level, index },
                reward_tree_hash_mode: 0,
                reward_tree_node_children: 0,
                node_type,
                api_url_hash: [0; 32],
            };
            bytes.extend(metadata.psy_ser_to_bytes().unwrap());
        }
        let path = std::env::temp_dir().join(format!("claim-rewards-path-{}", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let loaded = load_reward_jobs(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        let jobs = loaded.realm_jobs.into_iter().map(|(_, _, _, job)| job).chain(loaded.coordinator_jobs.into_iter().map(|(_, job)| job)).collect::<Vec<_>>();
        assert_eq!(jobs.len(), cases.len());
        for ((expected_level, expected_index, _), loaded_job) in cases.into_iter().zip(jobs) {
            let request = psy_provider::request::QGenerateBatchProofMinerRewardProofsRPCRequest { unique_pending_id: 64, job_ids: vec![loaded_job.inner] };
            let packed = serde_json::to_value(&request).unwrap()["job_ids"][0]["reward_path_info"].as_u64().unwrap();
            assert_eq!(packed, (u64::from(expected_level) << 56) | expected_index);
            assert_eq!(((packed >> 56) as u8, packed & 0x00FF_FFFF_FFFF_FFFF), (expected_level, expected_index));
        }
    }

    #[test]
    fn backup_reward_path_rejects_index_above_56_bits() {
        use psy_crypto::hash::merkle::utils::common::SimpleMerkleNodeKey;
        let metadata = PsyProvingJobClaimMetadata {
            job_id: job(1, 7, 10).inner.job_data_id,
            reward_tree_tag: QHashOut::from_values(1, 2, 3, 4),
            reward_tree_tag_preimage: QHashOut::from_values(7, 0, 10, 11),
            proving_duration_ms: 1,
            job_submitted_at: 2,
            unique_pending_id: 64,
            realm_id: 3,
            realm_sub_id: 0,
            reward_tree_node_key: SimpleMerkleNodeKey { level: 1, index: 0x00FF_FFFF_FFFF_FFFF + 1 },
            reward_tree_hash_mode: 0,
            reward_tree_node_children: 0,
            node_type: 1,
            api_url_hash: [0; 32],
        };
        let path = std::env::temp_dir().join(format!("claim-rewards-high-index-{}", std::process::id()));
        std::fs::write(&path, metadata.psy_ser_to_bytes().unwrap()).unwrap();
        let error = load_reward_jobs(path.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("exceeding 56 bits"), "{error}");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reward_claim_chain_accepts_only_the_token_set() {
        for chain_id in [1u64, 31337, 11155111] {
            assert!(reward_claim_chain(chain_id));
            assert_eq!(chain_id_word(canonical_quantity(&format!("0x{chain_id:x}")).unwrap()).unwrap(), chain_id);
        }
        for chain_id in [0u64, 5, 31338, 11155110, 11155112] {
            assert!(!reward_claim_chain(chain_id));
        }
    }

}
