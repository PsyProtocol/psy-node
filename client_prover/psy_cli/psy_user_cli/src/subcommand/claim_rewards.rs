use std::future::Future;
use fs2::FileExt;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
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
    bridge_aggregate::{domain_hash, Domain},
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
use psy_prover::local::bridge_aggregate::{address, digest, reward_record, reward_root_bytes, word, ClaimError, RewardConsumptionState, RewardPendingClaim};





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
    anyhow::ensure!(args.multisig_account.is_none(), "reward root accepts only ZK authorization");
    let wallet = wallet.context("reward root requires the selected ZK private key")?;
    anyhow::ensure!(wallet.sign_type == SignType::ZKSign, "reward root accepts only ZK authorization");
    let lock = reward_state_lock(&args.consumed_state)?;
    let context = client.context().await?;
    let mut state = load_reward_state(&args.consumed_state, &args.l1_rpc_url, &args.l1_block, &client.config, user_id, &client.http).await?;
    let confirmed = state.confirmed.clone();
    let pending_selection = state.pending.as_ref().filter(|pending| pending.request.context_id != context.context_id).map(|pending| pending.jobs.clone());
    let (request, record) = prepare_reward_claim(&args.consumed_state, &mut state, &context.context_id, async {
        let loaded = match pending_selection {
            Some(selection) => selection,
            None => validate_and_deduplicate_jobs(load_job_ids_from_file(&args.jobs_file)?, args.user_id, &args.jobs_file)?.into(),
        };
        anyhow::ensure!(loaded.jobs_len() != 0, "no reward jobs selected");
        let (jobs, original_jobs) = selected_reward_jobs(&client, &loaded, user_id, recipient).await?;
        let (request, record, coordinates) = client.prove_reward(&context, &client.circuits.reward_segment, &client.circuits.reward_merge, &client.circuits.reward_root, user_id, recipient_limbs(&recipient), wallet.private_key.0, &jobs, &confirmed).await?;
        Ok(RewardPendingClaim { jobs: original_jobs, coordinates, request, record })
    }).await?;
    let anchor = STANDARD.decode(&request.anchor)?;
    let proof = STANDARD.decode(&request.proof)?;
    let claim_id = reward_claim_identity(&client.config.config_hash()?, &record, &anchor, &proof);
    let status = client.submit_reward(&context, &request).await?;
    client.validate_status(&context, &claim_id, 3, &status)?;
    drop(lock);
    Ok(CommandResult::generic("claim-rewards"))
}
async fn selected_reward_jobs(client: &psy_prover::local::bridge_aggregate::ClaimClient, loaded: &psy_prover::local::bridge_aggregate::RewardPendingSelection, user_id: u32, recipient: [u8; 20]) -> Result<(std::collections::BTreeMap<u32, Vec<psy_plonky2_circuits::bridge::circuits::reward_chain::AuthenticatedJobWitness>>, psy_prover::local::bridge_aggregate::RewardPendingSelection)> {
    let mut proofs = build_realm_proofs(&client.provider, loaded.realm_jobs.clone()).await?;
    for (checkpoint, batch) in build_proofs(&client.provider, loaded.coordinator_jobs.clone(), 2).await? { proofs.entry(checkpoint).or_default().extend(batch); }
    let mut jobs = std::collections::BTreeMap::new();
    for checkpoint in proofs.keys().copied().collect::<std::collections::BTreeSet<_>>() {
        let mut batch = proofs.remove(&checkpoint).context("reward checkpoint missing")?; batch.sort_by_key(|proof| (proof.inner.job_id, proof.inner.tag_tree_proof.index));
        let source = u32::try_from(checkpoint)?; let mut witnesses = Vec::new();
        for proof in batch { let (record, tag) = reward_record(checkpoint, user_id, recipient, &proof)?; anyhow::ensure!(record.claim_checkpoint_id == u64::from(source), "reward job source mismatch"); witnesses.push(psy_plonky2_circuits::bridge::circuits::reward_chain::AuthenticatedJobWitness { source_checkpoint_id: source, height: record.height, path_index: record.path_index, tag }); }
        jobs.insert(source, witnesses);
    }
    anyhow::ensure!(!jobs.is_empty(), "no reward witnesses returned"); Ok((jobs, loaded.clone()))
}
// The future is deliberately lazy: an exact-context retry never opens the jobs
// file or fetches historical witnesses. Save before submission, under the caller's lock.
async fn prepare_reward_claim(
    path: &str, state: &mut RewardConsumptionState, context_id: &str,
    prove: impl Future<Output = Result<RewardPendingClaim>>,
) -> Result<(psy_prover::local::bridge_aggregate::RewardClaimRequest, Vec<u8>)> {
    if let Some(pending) = &state.pending {
        if pending.request.context_id == context_id { return Ok((pending.request.clone(), pending.record.clone())); }
    }
    let pending = prove.await?;
    anyhow::ensure!(pending.request.context_id == context_id, "reward proof context mismatch");
    if let Some(previous) = &state.pending {
        anyhow::ensure!(previous.jobs == pending.jobs && previous.coordinates == pending.coordinates, "fresh context changed pending reward jobs");
    }
    let mut next = state.clone();
    next.pending = Some(pending);
    save_reward_state(path, &next)?;
    *state = next;
    let pending = state.pending.as_ref().context("pending reward claim missing")?;
    Ok((pending.request.clone(), pending.record.clone()))
}
async fn load_reward_state(path: &str, url: &str, block: &str, config: &psy_client_data::bridge_aggregate::NetworkConfig, user_id: u32, http: &reqwest::Client) -> Result<RewardConsumptionState> {
    let chain = config.chains.iter().find(|chain| chain.chain_index == config.ethereum_index).context("configured Ethereum chain missing")?;
    let identity = format!("0x{}", hex::encode(config.config_hash()?));
    let chain_id = format!("0x{}", hex::encode(chain.chain_id));
    let payer = format!("0x{}", hex::encode(config.reward_payer));
    let mut state = if std::path::Path::new(path).exists() { serde_json::from_slice(&std::fs::read(path)?)? } else { RewardConsumptionState { version: 1, config_hash: identity.clone(), chain_id: chain_id.clone(), payer: payer.clone(), user_id, confirmed: std::collections::BTreeMap::new(), pending: None } };
    anyhow::ensure!(state.version == 1 && state.config_hash == identity && state.chain_id == chain_id && state.payer == payer && state.user_id == user_id, "reward consumption identity mismatch");
    let observed = read_reward_root(http, url, block, &payer, &chain_id, user_id).await?;
    let (_, _, confirmed_root) = psy_prover::local::bridge_aggregate::rebuild_reward_tree(&state.confirmed)?;
    if observed == reward_root_bytes(confirmed_root)? { return Ok(state); }
    let pending = state.pending.clone().context("reward consumption history is missing")?;
    let mut combined = state.confirmed.clone();
    for (source, values) in &pending.coordinates { let entry = combined.entry(*source).or_default(); for value in values { anyhow::ensure!(entry.binary_search(value).is_err(), "reward pending coordinate was already consumed"); entry.push(*value); entry.sort_unstable(); } }
    let (_, _, pending_root) = psy_prover::local::bridge_aggregate::rebuild_reward_tree(&combined)?;
    anyhow::ensure!(observed == reward_root_bytes(pending_root)?, "reward consumption history is missing");
    state.confirmed = combined; state.pending = None; save_reward_state(path, &state)?; Ok(state)
}
async fn read_reward_root(http: &reqwest::Client, url: &str, block: &str, payer: &str, chain_id: &str, user_id: u32) -> Result<[u8; 32]> {
    let block_hash = fixed_block_hash(http, url, block, chain_id).await?;
    let mut data = alloy_primitives::keccak256(b"rewardNullifierRoot(uint256)")[..4].to_vec(); data.resize(36, 0); data[32..].copy_from_slice(&user_id.to_be_bytes());
    let call = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":payer,"data":format!("0x{}", hex::encode(data))},{"blockHash":block_hash,"requireCanonical":true}]});
    let response = http.post(url).json(&call).send().await?.json::<serde_json::Value>().await?;
    anyhow::ensure!(response.get("error").is_none(), "reward root read failed");
    let text = response["result"].as_str().context("reward root result missing")?.trim_start_matches("0x");
    anyhow::ensure!(text.len() == 64, "reward root width");
    let bytes: [u8; 32] = hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("reward root width"))?;
    if bytes == [0; 32] { return reward_root_bytes(*psy_plonky2_circuits::bridge::gadgets::reward_nullifier::REWARD_NULLIFIER_EMPTY_ROOT); }
    for limb in bytes.chunks_exact(8) { anyhow::ensure!(u64::from_be_bytes(limb.try_into().unwrap()) < psy_client_data::bridge_aggregate::GOLDILOCKS_MODULUS, "noncanonical reward root"); }
    Ok(bytes)
}
async fn fixed_block_hash(http: &reqwest::Client, url: &str, block: &str, chain_id: &str) -> Result<String> {
    anyhow::ensure!(block == "0x0" || (block.starts_with("0x") && block.len() > 2 && block[2..].chars().all(|value| value.is_ascii_hexdigit()) && !block[2..].starts_with('0')), "reward root block is not canonical");
    let chain = http.post(url).json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]})).send().await?.json::<serde_json::Value>().await?;
    let observed = chain["result"].as_str().context("reward chain identity missing")?;
    anyhow::ensure!(chain.get("error").is_none() && canonical_quantity(observed)? == chain_id_bytes(chain_id)?, "reward payer chain identity mismatch");
    let response = http.post(url).json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":[block,false]})).send().await?.json::<serde_json::Value>().await?;
    anyhow::ensure!(response.get("error").is_none(), "reward block read failed");
    let hash = response["result"]["hash"].as_str().context("reward block has no canonical hash")?.to_owned();
    anyhow::ensure!(hash.len() == 66 && hash.starts_with("0x") && hash[2..].chars().all(|value| value.is_ascii_hexdigit()), "reward block hash is not canonical");
    Ok(hash)
}
fn canonical_quantity(value: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(value == "0x0" || (value.starts_with("0x") && (3..=66).contains(&value.len()) && value[2..].chars().all(|digit| digit.is_ascii_hexdigit()) && !value[2..].starts_with('0')), "noncanonical chain quantity");
    let mut bytes = [0u8; 32]; hex::decode_to_slice(format!("{:0>64}", &value[2..]), &mut bytes)?; Ok(bytes)
}
fn chain_id_bytes(value: &str) -> Result<[u8; 32]> { anyhow::ensure!(value.len() == 66 && value.starts_with("0x"), "configured chain id width"); let mut bytes = [0u8; 32]; hex::decode_to_slice(&value[2..], &mut bytes)?; Ok(bytes) }
fn reward_state_lock(path: &str) -> Result<std::fs::File> { let file = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(format!("{path}.lock"))?; file.lock_exclusive()?; Ok(file) }
fn save_reward_state(path: &str, state: &RewardConsumptionState) -> Result<()> {
    let temporary = format!("{path}.tmp"); let mut file = std::fs::File::create(&temporary)?; use std::io::Write; file.write_all(&serde_json::to_vec(state)?)?; file.sync_all()?; drop(file); std::fs::rename(&temporary, path)?; let parent = std::path::Path::new(path).parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| std::path::Path::new(".")); std::fs::File::open(parent)?.sync_all()?; Ok(())
}

fn recipient_limbs(recipient: &[u8; 20]) -> [u32; 8] {
    let mut limbs = [0u32; 8];
    for index in 0..5 { limbs[index] = u32::from_be_bytes(recipient[16 - index * 4..20 - index * 4].try_into().unwrap()); }
    limbs
}

fn reward_claim_identity(config_hash: &[u8; 32], record: &[u8], anchor: &[u8], proof: &[u8]) -> String {
    digest(&[&domain_hash(Domain::LeafCommit), config_hash, &word(3), record, &alloy_primitives::keccak256([anchor, proof].concat())])
}


#[derive(Debug)]
struct ClaimRewardJobsWithRealm {
    realm_jobs: Vec<(u64, u64, QProvingJobDataIDWithRewardPreimage)>,
    coordinator_jobs: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
}

impl ClaimRewardJobsWithRealm {
    fn new_empty() -> Self { Self { realm_jobs: vec![], coordinator_jobs: vec![] } }
    fn jobs_len(&self) -> usize { self.realm_jobs.len() + self.coordinator_jobs.len() }
}

impl From<ClaimRewardJobsWithRealm> for psy_prover::local::bridge_aggregate::RewardPendingSelection {
    fn from(jobs: ClaimRewardJobsWithRealm) -> Self { Self { realm_jobs: jobs.realm_jobs, coordinator_jobs: jobs.coordinator_jobs } }
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
    // These tests exercise the same retry/reconciliation and real prover paths as run.
    use std::{collections::BTreeMap, sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}}};
    use plonky2::{field::types::{Field, PrimeField64}, hash::{hash_types::HashOut, poseidon::PoseidonHash}, plonk::config::{Hasher, PoseidonGoldilocksConfig}};
    use psy_client_data::{bridge_aggregate::{ChainConfig, NetworkConfig, RewardClaim}, qdata::{checkpoint::{PsyCheckpointLeaf, PsyCheckpointGlobalStateRoots}, user::PsyUserLeaf}};
    use psy_crypto::hash::merkle::core::MerkleProofCore;
    use psy_prover::local::bridge_aggregate::{AggregationContext, ClaimClient as PortableClaimClient, rebuild_reward_tree};
    use psy_plonky2_circuits::bridge::circuits::reward_chain::{AuthenticatedJobWitness, RewardMergeCircuit, RewardRootCircuit, RewardSegmentCircuit};
    type F = GoldilocksField;

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("reward-path-{}-{}", std::process::id(), rand::random::<u64>()));
            std::fs::create_dir(&path).unwrap(); Self(path)
        }
    }
    impl Drop for Directory { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }

    // Deterministic transport of authenticated witnesses and explicit root observations;
    // this server does not verify proofs, simulate payments, or claim L1 E2E evidence.
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
        server: Server, client: PortableClaimClient, context: AggregationContext,
        observed: Arc<tokio::sync::Mutex<[u8; 32]>>, calls: Arc<AtomicUsize>,
        private_key: HashOut<F>, jobs: Vec<AuthenticatedJobWitness>,
    }
    impl Fixture {
        fn new() -> Self {
            let private_key = QHashOut::from_values(17, 23, 31, 47);
            let param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&private_key);
            let identity = psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit::<PoseidonGoldilocksConfig, 2>::new().fingerprint.0;
            let mut user = PsyUserLeaf::default(); user.user_id = F::from_canonical_u32(7);
            user.public_key = QHashOut(PoseidonHash::two_to_one(identity, param.0));
            let user_path = path(&BTreeMap::from([(7, user.qfhash::<PsyHasher>().0)]), 7);
            let mut roots = PsyCheckpointGlobalStateRoots::default(); roots.user_tree_root = user_path.root;
            let mut anchor = PsyCheckpointLeaf::default(); anchor.global_chain_root = roots.qfhash::<PsyHasher>();
            let preimage = parth_core::pgoldilocks::QHashOut::from_values(7, 1, 0, 0);
            let tag = PoseidonHash::two_to_one(preimage.0, preimage.0);
            let tagged = |left, right, tag| PoseidonHash::two_to_one(PoseidonHash::two_to_one(left, right), tag);
            // Height seven permits 32 counted GUTA jobs (height six permits only 16).
            let mut levels = vec![(0..128).map(|index| tagged(QHashOut::from_values(index, 0, 0, 0).0, HashOut::ZERO, tag)).collect::<Vec<_>>()];
            for level in 0..7 { levels.push(levels[level].chunks_exact(2).map(|pair| tagged(pair[0], pair[1], HashOut::ZERO)).collect()); }
            let jobs = (0..18usize).map(|index| AuthenticatedJobWitness {
                source_checkpoint_id: 10, height: 7, path_index: index as u32,
                tag: psy_plonky2_circuits::bridge::circuits::reward_chain::RewardTagWitness {
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
            let observed = Arc::new(tokio::sync::Mutex::new([0; 32])); let root_read = observed.clone();
            let calls = Arc::new(AtomicUsize::new(0)); let recorded = calls.clone();
            let server = Server::new(move |request| {
                let method = request["method"].as_str().unwrap(); recorded.fetch_add(1, Ordering::SeqCst);
                match method {
                    "eth_chainId" => serde_json::json!("0x10000000000000001"),
                    "eth_getBlockByNumber" => { assert_eq!(request["params"], serde_json::json!(["0x2a", false])); serde_json::json!({"hash":format!("0x{}", "ab".repeat(32))}) },
                    "eth_call" => {
                        assert_eq!(request["params"][0]["to"], format!("0x{}", "22".repeat(20)));
                        assert_eq!(request["params"][1], serde_json::json!({"blockHash":format!("0x{}", "ab".repeat(32)),"requireCanonical":true}));
                        let mut data = alloy_primitives::keccak256(b"rewardNullifierRoot(uint256)")[..4].to_vec(); data.extend_from_slice(&word(7));
                        assert_eq!(request["params"][0]["data"], format!("0x{}", hex::encode(data)));
                        serde_json::json!(format!("0x{}", hex::encode(*root_read.blocking_lock())))
                    },
                    "psy_get_checkpoint_leaf_data" => serde_json::to_value(if request["params"]["checkpoint_id"] == 10 { source } else { anchor }).unwrap(),
                    "psy_get_checkpoint_tree_merkle_proof" => serde_json::to_value(path(&checkpoints, request["params"]["leaf_checkpoint_id"].as_u64().unwrap())).unwrap(),
                    "psy_get_checkpoint_global_state_roots" => serde_json::to_value(roots).unwrap(),
                    "psy_get_user_leaf_data" => serde_json::to_value(user).unwrap(),
                    "psy_get_user_tree_merkle_proof" => serde_json::to_value(&user_path).unwrap(),
                    "psy_get_user_sub_tree_merkle_proof" => {
                        let split = psy_config::network_constants::REALM_USER_TREE_HEIGHT as usize;
                        let mut value = user_path.value.0;
                        for (level, sibling) in user_path.siblings[..split].iter().enumerate() { value = if (7u64 >> level) & 1 == 0 { PoseidonHash::two_to_one(value, sibling.0) } else { PoseidonHash::two_to_one(sibling.0, value) }; }
                        serde_json::to_value(MerkleProofCore { root: user_path.root, value: QHashOut(value), index: 0, siblings: user_path.siblings[split..].to_vec() }).unwrap()
                    },
                    _ => panic!("unexpected RPC {method}"),
                }
            });
            let mut chain_id = word(1); chain_id[23] = 1;
            let config = NetworkConfig { version: 1, network_magic: 1, bridge_user_id: 524288, circuit_set_hash: [1; 32], chains: vec![ChainConfig { chain_index: 0, chain_id, bridge: [3; 20], state_manager: [4; 20], bootstrap_id: 0, bootstrap_root: [0; 4] }], ethereum_index: 0, reward_payer: [0x22; 20], reward_token: [5; 20], reward_per_claim: word(1), reward_token_decimals: 18, max_withdrawals: 32, max_rewards: 32 };
            let provider = RpcProvider { client: Arc::new(reqwest::Client::new()), endpoint_clients: None, realm_configs: std::collections::HashMap::from([(0, vec![server.url.clone()])]), coordinator_configs: std::collections::HashMap::from([(0, vec![server.url.clone()])]), users_per_realm: 1 << psy_config::network_constants::REALM_USER_TREE_HEIGHT, current_user_id: 0 };
            let client = PortableClaimClient::new(config, provider, &server.url).unwrap();
            let limbs = checkpoint_root.0.elements.map(|value| value.to_canonical_u64()); let config_hash = client.config.config_hash().unwrap();
            let context = AggregationContext { version: 4, config_hash: format!("0x{}", hex::encode(config_hash)), end_checkpoint_id: "11".into(), end_checkpoint_root: limbs.map(|value| value.to_string()), context_id: format!("0x{}", hex::encode(psy_client_data::bridge_aggregate::claim_context_id(config_hash, 11, limbs).unwrap())), max_proof_bytes: 16_777_216, max_records: 32 };
            Self { server, client, context, observed, calls, private_key: private_key.0, jobs }
        }
        async fn load(&self, path: &str) -> Result<RewardConsumptionState> { load_reward_state(path, &self.server.url, "0x2a", &self.client.config, 7, &self.client.http).await }
        async fn prove(&self, segment: &RewardSegmentCircuit, merge: &RewardMergeCircuit, root: &RewardRootCircuit, context: &AggregationContext, indices: std::ops::Range<usize>, confirmed: &BTreeMap<u32, Vec<u32>>) -> Result<RewardPendingClaim> {
            let jobs = BTreeMap::from([(10, self.jobs[indices.clone()].to_vec())]);
            let recipient = address("0x0102030405060708090a0b0c0d0e0f1011121314")?;
            let (request, record, coordinates) = self.client.prove_reward(context, segment, merge, root, 7, recipient_limbs(&recipient), self.private_key, &jobs, confirmed).await?;
            let jobs = psy_prover::local::bridge_aggregate::RewardPendingSelection {
                realm_jobs: vec![],
                coordinator_jobs: indices.map(|index| (21, QProvingJobDataIDWithRewardPreimage::new(
                    QProvingJobDataID::new(QJobTopic::GenerateStandardProof, 10, 0, 0, 0, index as u32, ProvingJobCircuitType::AppendUserRegistrationTree, ProvingJobDataType::InputWitness, 0),
                    index as u64, QHashOut(self.jobs[index].tag.tag_preimage.0),
                ))).collect(),
            };
            Ok(RewardPendingClaim { jobs, coordinates, request, record })
        }
    }
    #[tokio::test]
    async fn production_reward_seventeen_jobs_retry_and_two_observed_payments() {
        let fixture = Fixture::new(); let directory = Directory::new();
        let file = directory.0.join("consumption.json"); let file = file.to_str().unwrap();
        let _lock = reward_state_lock(file).unwrap();
        let segment = RewardSegmentCircuit::new(); let merge = RewardMergeCircuit::new(&segment); let root = RewardRootCircuit::new(&merge);
        let mut state = fixture.load(file).await.unwrap();
        let first = fixture.prove(&segment, &merge, &root, &fixture.context, 0..17, &state.confirmed).await.unwrap();
        let decoded = RewardClaim::decode(&first.record).unwrap();
        assert_eq!(decoded.count, 17); assert_eq!(decoded.amount, word(170));
        assert_eq!(decoded.recipient, address("0x0102030405060708090a0b0c0d0e0f1011121314").unwrap());
        assert_eq!(decoded.old_nullifier_root, rebuild_reward_tree(&state.confirmed).unwrap().2.elements.map(|x| x.to_canonical_u64()));
        assert_eq!(decoded.new_nullifier_root, rebuild_reward_tree(&first.coordinates).unwrap().2.elements.map(|x| x.to_canonical_u64()));
        assert_eq!(first.coordinates[&10], (127..144).collect::<Vec<_>>());
        let proof = plonky2::plonk::proof::ProofWithPublicInputs::<F, PoseidonGoldilocksConfig, 2>::from_bytes(STANDARD.decode(&first.request.proof).unwrap(), &root.circuit_data.common).unwrap();
        assert_eq!(RewardClaim::from_public_inputs(0, &proof.public_inputs.iter().map(|x| x.to_canonical_u64()).collect::<Vec<_>>().try_into().unwrap()).unwrap(), decoded);
        root.circuit_data.verify(proof).unwrap();
        prepare_reward_claim(file, &mut state, &fixture.context.context_id, async { Ok(first.clone()) }).await.unwrap();
        let saved = std::fs::read(file).unwrap();
        // Zero payer storage normalizes to the empty root: skipped/unpaid keeps pending.
        assert_eq!(fixture.load(file).await.unwrap(), state);
        assert_eq!(std::fs::read(file).unwrap(), saved);
        let before_calls = fixture.calls.load(Ordering::SeqCst);
        let missing_jobs = directory.0.join("absent-jobs.json");
        let replay = prepare_reward_claim(file, &mut state, &fixture.context.context_id, async {
            let _ = load_job_ids_from_file(missing_jobs.to_str().unwrap())?;
            panic!("same-context retry polled historical proof future")
        }).await.unwrap();
        assert_eq!(replay, (first.request.clone(), first.record.clone()));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), before_calls);
        assert_eq!(std::fs::read(file).unwrap(), saved);

        let mut changed = fixture.context.clone(); changed.end_checkpoint_id = "12".into();
        changed.context_id = format!("0x{}", hex::encode(psy_client_data::bridge_aggregate::claim_context_id(fixture.client.config.config_hash().unwrap(), 12, fixture.context.end_checkpoint_root.clone().map(|x| x.parse().unwrap())).unwrap()));
        let replacement = fixture.prove(&segment, &merge, &root, &changed, 0..17, &state.confirmed).await.unwrap();
        assert_eq!(replacement.coordinates, first.coordinates); assert_eq!(replacement.jobs, first.jobs);
        for mutate_jobs in [true, false] {
            let mut invalid = replacement.clone();
            if mutate_jobs { invalid.jobs.coordinator_jobs.pop(); } else { invalid.coordinates.get_mut(&10).unwrap().pop(); }
            let before = state.clone();
            assert!(prepare_reward_claim(file, &mut state, &changed.context_id, async { Ok(invalid) }).await.unwrap_err().to_string().contains("changed pending reward jobs"));
            assert_eq!(state, before); assert_eq!(std::fs::read(file).unwrap(), saved);
        }
        prepare_reward_claim(file, &mut state, &changed.context_id, async { Ok(replacement.clone()) }).await.unwrap();
        assert_eq!(state.pending.as_ref().unwrap(), &replacement);
        let replacement_saved = std::fs::read(file).unwrap();
        *fixture.observed.lock().await = reward_root_bytes(HashOut { elements: [F::ONE; 4] }).unwrap();
        assert!(fixture.load(file).await.unwrap_err().to_string().contains("history is missing"));
        assert_eq!(std::fs::read(file).unwrap(), replacement_saved);

        // These are authenticated local root observations, not onchain payment execution.
        *fixture.observed.lock().await = reward_root_bytes(rebuild_reward_tree(&first.coordinates).unwrap().2).unwrap();
        state = fixture.load(file).await.unwrap();
        assert_eq!(state.confirmed, first.coordinates); assert!(state.pending.is_none());
        assert!(fixture.prove(&segment, &merge, &root, &changed, 0..1, &state.confirmed).await.unwrap_err().to_string().contains("already consumed"));
        let second = fixture.prove(&segment, &merge, &root, &changed, 17..18, &state.confirmed).await.unwrap();
        let second_claim = RewardClaim::decode(&second.record).unwrap();
        assert_eq!(second_claim.old_nullifier_root, decoded.new_nullifier_root);
        assert_eq!(second_claim.count, 1); assert_eq!(second_claim.amount, word(10));
        let combined = BTreeMap::from([(10, (127..145).collect::<Vec<_>>())]);
        assert_eq!(second_claim.new_nullifier_root, rebuild_reward_tree(&combined).unwrap().2.elements.map(|x| x.to_canonical_u64()));
        prepare_reward_claim(file, &mut state, &changed.context_id, async { Ok(second) }).await.unwrap();
        assert_eq!(fixture.load(file).await.unwrap(), state);
        *fixture.observed.lock().await = reward_root_bytes(rebuild_reward_tree(&combined).unwrap().2).unwrap();
        state = fixture.load(file).await.unwrap();
        assert_eq!(state.confirmed, combined); assert!(state.pending.is_none());
    }

    #[tokio::test]
    async fn fresh_context_reloads_saved_selection_when_backup_changes() {
        let fixture = Fixture::new(); let directory = Directory::new();
        let file = directory.0.join("consumption.json"); let file = file.to_str().unwrap();
        let jobs_file = directory.0.join("jobs.backup"); let jobs_file = jobs_file.to_str().unwrap().to_owned();
        std::fs::write(&jobs_file, [7u8]).unwrap();
        let _lock = reward_state_lock(file).unwrap();
        let segment = RewardSegmentCircuit::new(); let merge = RewardMergeCircuit::new(&segment); let root = RewardRootCircuit::new(&merge);
        let mut state = fixture.load(file).await.unwrap();
        let first = fixture.prove(&segment, &merge, &root, &fixture.context, 0..17, &state.confirmed).await.unwrap();
        prepare_reward_claim(file, &mut state, &fixture.context.context_id, async { Ok(first.clone()) }).await.unwrap();
        let original_state = state.clone();
        drop(state);
        let mut changed = fixture.context.clone(); changed.end_checkpoint_id = "12".into();
        changed.context_id = format!("0x{}", hex::encode(psy_client_data::bridge_aggregate::claim_context_id(fixture.client.config.config_hash().unwrap(), 12, fixture.context.end_checkpoint_root.clone().map(|value| value.parse().unwrap())).unwrap()));
        use psy_crypto::hash::merkle::tag_tree::{compute_tag_tree_root_for_proof, TagTreeMerkleProof, TagTreeNodePreimage, TagTreeProofNode};
        let proof_responses = fixture.jobs.iter().take(17).zip(&first.jobs.coordinator_jobs).map(|(job, (_, original))| {
            let leaf = TagTreeNodePreimage { left: QHashOut(job.tag.leaf_left.0), right: QHashOut(job.tag.leaf_right.0), tag: QHashOut(job.tag.leaf_tag.0) };
            let siblings = (0..usize::from(job.height)).map(|level| TagTreeProofNode {
                sibling: QHashOut(job.tag.siblings[level].0), parent_tag: QHashOut(job.tag.parent_tags[level].0),
            }).collect::<Vec<_>>();
            let index = u64::from(job.path_index);
            let root = compute_tag_tree_root_for_proof::<QHashOut<F>, PsyHasher>(index, &leaf, &siblings);
            PsyProoffMinerRewardProof { job_id: original.inner.job_data_id, tag_tree_proof: TagTreeMerkleProof { root, leaf, index, siblings } }
        }).collect::<Vec<_>>();
        let selection_calls = Arc::new(AtomicUsize::new(0));
        let observed_selection_calls = selection_calls.clone();
        let selection_server = Server::new(move |request| {
            let method = request["method"].as_str().unwrap();
            if method == "psy_get_checkpoint_id_for_unique_pending_id" {
                assert_eq!(request["params"]["unique_pending_id"], 21);
                return serde_json::json!(10);
            }
            assert_eq!(method, "psy_generate_batch_proof_miner_reward_proofs");
            assert_eq!(request["params"]["unique_pending_id"], 21);
            let requested = request["params"]["job_ids"].as_array().unwrap();
            assert_eq!(requested.len(), 17);
            for (index, job) in requested.iter().enumerate() {
                let job: psy_client_common::job::id::QProvingJobDataIDWithRewardPath = serde_json::from_value(job.clone()).unwrap();
                assert_eq!(job.job_data_id, proof_responses[index].job_id);
                assert_eq!(job.reward_path_info, index as u64);
                assert_eq!(proof_responses[index].tag_tree_proof.siblings.len(), 7);
            }
            observed_selection_calls.fetch_add(1, Ordering::SeqCst);
            serde_json::to_value(&proof_responses).unwrap()
        });
        let provider = RpcProvider { client: Arc::new(reqwest::Client::new()), endpoint_clients: None, realm_configs: std::collections::HashMap::new(), coordinator_configs: std::collections::HashMap::from([(0, vec![selection_server.url.clone()])]), users_per_realm: 1, current_user_id: 0 };
        let selector = PortableClaimClient::new(fixture.client.config.clone(), provider, &selection_server.url).unwrap();
        let refresh = |backup: String| {
            let selector = &selector; let fixture = &fixture; let segment = &segment; let merge = &merge; let root = &root; let changed = changed.clone(); let file = file.to_owned();
            async move {
                let mut state = fixture.load(&file).await?;
                let selection = state.pending.as_ref().context("saved pending selection missing")?.jobs.clone();
                let confirmed = state.confirmed.clone();
                let context_id = changed.context_id.clone();
                let (request, record) = prepare_reward_claim(&file, &mut state, &context_id, async move {
                    anyhow::ensure!(std::fs::read(&backup).map(|bytes| bytes == [7u8]).unwrap_or(false) == false, "fresh context used the original jobs backup");
                    let (jobs, retained) = selected_reward_jobs(selector, &selection, 7, address("0x0102030405060708090a0b0c0d0e0f1011121314")?).await?;
                    let (request, record, coordinates) = fixture.client.prove_reward(&changed, segment, merge, root, 7, recipient_limbs(&address("0x0102030405060708090a0b0c0d0e0f1011121314")?), fixture.private_key, &jobs, &confirmed).await?;
                    Ok(RewardPendingClaim { jobs: retained, coordinates, request, record })
                }).await?;
                Ok::<_, anyhow::Error>((request, record, state))
            }
        };
        std::fs::remove_file(&jobs_file).unwrap();
        let (request, _, refreshed) = refresh(jobs_file.clone()).await.unwrap();
        assert_eq!(refreshed.pending.as_ref().unwrap().jobs, first.jobs);
        assert_eq!(refreshed.pending.as_ref().unwrap().coordinates, first.coordinates);
        assert_eq!(request.context_id, changed.context_id);
        assert_eq!(selection_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.jobs.coordinator_jobs.len(), 17);
        assert!(first.jobs.coordinator_jobs.iter().enumerate().all(|(index, (pending, job))| *pending == 21 && job.inner.job_data_id.task_index == index as u32 && job.inner.reward_path_info == index as u64));
        std::fs::write(&jobs_file, [9u8]).unwrap();
        save_reward_state(file, &original_state).unwrap();
        let (replacement, _, refreshed_again) = refresh(jobs_file.clone()).await.unwrap();
        assert_eq!(replacement.context_id, changed.context_id);
        assert_eq!(refreshed_again.pending.as_ref().unwrap().jobs, first.jobs);
        assert_eq!(refreshed_again.pending.as_ref().unwrap().coordinates, first.coordinates);
        assert_eq!(selection_calls.load(Ordering::SeqCst), 2);
        let (replay_request, replay_record, _) = refresh(jobs_file.clone()).await.unwrap();
        assert_eq!(replay_request, replacement); assert_eq!(replay_record, refreshed_again.pending.unwrap().record);
        assert_eq!(selection_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn reward_claim_identity_binds_decoded_anchor_and_proof() {
        let config = [9u8; 32];
        let record = b"record".to_vec();
        let anchor = b"anchor".to_vec();
        let proof = b"proof".to_vec();
        let identity = |anchor: &[u8], proof: &[u8]| reward_claim_identity(&config, &record, anchor, proof);
        assert_ne!(identity(&anchor, &proof), identity(b"changed", &proof));
        assert_ne!(identity(&anchor, &proof), identity(&anchor, b"changed"));
        assert_ne!(identity(&anchor, &proof), digest(&[&domain_hash(Domain::LeafCommit), &config, &word(3), &record, &alloy_primitives::keccak256(&proof)]));
    }


    #[test]
    fn production_state_writers_share_adjacent_lock_across_atomic_rename() {
        use std::os::unix::fs::MetadataExt;
        let directory = Directory::new(); let file = directory.0.join("state.json"); let file = file.to_str().unwrap().to_owned();
        let lock = reward_state_lock(&file).unwrap(); let inode = lock.metadata().unwrap().ino();
        let state = RewardConsumptionState { version: 1, config_hash: String::new(), chain_id: String::new(), payer: String::new(), user_id: 7, confirmed: BTreeMap::new(), pending: None };
        save_reward_state(&file, &state).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel(); let (done_tx, done_rx) = std::sync::mpsc::channel();
        let other_file = file.clone();
        let writer = std::thread::spawn(move || {
            let probe = std::fs::OpenOptions::new().write(true).open(format!("{other_file}.lock")).unwrap();
            assert_eq!(probe.metadata().unwrap().ino(), inode);
            assert_eq!(probe.try_lock_exclusive().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            ready_tx.send(()).unwrap();
            let acquired = reward_state_lock(&other_file).unwrap();
            assert_eq!(acquired.metadata().unwrap().ino(), inode);
            let mut loaded: RewardConsumptionState = serde_json::from_slice(&std::fs::read(&other_file).unwrap()).unwrap();
            assert_eq!(loaded.confirmed[&10], vec![127]);
            loaded.confirmed.get_mut(&10).unwrap().push(128); save_reward_state(&other_file, &loaded).unwrap();
            done_tx.send(()).unwrap();
        });
        ready_rx.recv().unwrap();
        let mut next = state; next.confirmed.insert(10, vec![127]); save_reward_state(&file, &next).unwrap();
        assert!(matches!(done_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
        drop(lock); done_rx.recv().unwrap(); writer.join().unwrap();
        let loaded: RewardConsumptionState = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(loaded.confirmed[&10], vec![127, 128]);
    }
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
