use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use futures::stream::StreamExt;
use plonky2::field::types::PrimeField64;
use psy_client_common::{args::ContractCallArgs, args::ContractCallData, data::qhashout::QHashOut};
use psy_client_data::{
    config::store_config::{C, D},
    traits::qdatastore::qmetadata::QMetaDataStoreReaderSync,
};
use psy_compiler::output::serialize::CompilationArtifact;
use psy_config::{NetworkConfigGoldilocks, PsyConfigGoldilocks};
use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::zk::data::ZKPublicKeyInfo};
use psy_prover::session::{
    compile_bridge::build_layout_aware_deploy_command, gen_contract_deploy_and_circuits_for_functions, WalletSession,
};
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::{QDeployContractRPCRequest, QRegisterUserRPCRequest},
};

use psy_cli_common::key_utils::load_wallet_key_info;

use crate::subcommand::benchmark::{
    account_pool::{
        create_missing_accounts, open_pool, wallet_source_args, OpStatus, PoolGuard, PoolOpRecord, RegistrationState,
    },
    report::{now_unix_ms, LatencySamples, ScenarioReport},
    BenchmarkCommonArgs,
};

type F = psy_client_data::config::store_config::F;

/// Per-run cap on recovery inclusion waits, so a permanently unresolved op
/// record cannot stall the start of every subsequent run.
const RECONCILE_WAIT_CAP_SECS: u64 = 60;

/// Per-run cap on registration confirmation waits: registrations land within
/// a couple of checkpoints, so a straggler absent this long is a lost request
/// and holding the whole run for the full scenario timeout buys nothing.
const REGISTER_CONFIRM_WAIT_CAP_SECS: u64 = 60;

struct BenchmarkContext {
    network: NetworkConfigGoldilocks,
    network_name: String,
}

fn load_context(rpc_config: &str) -> Result<BenchmarkContext> {
    let psy_config = PsyConfigGoldilocks::from_file(rpc_config)?;
    let network = psy_config.get_current_network()?.clone();
    Ok(BenchmarkContext { network_name: psy_config.current_network_name().to_string(), network })
}

fn finish_report(mut report: ScenarioReport) -> Result<ScenarioReport> {
    report.finish(now_unix_ms());
    Ok(report)
}

fn registered_accounts(guard: &PoolGuard) -> Vec<u32> {
    guard
        .pool()
        .accounts
        .iter()
        .filter(|account| account.user_id.is_some())
        .map(|account| account.index)
        .collect()
}

fn find_account_mut(guard: &mut PoolGuard, index: u32) -> Result<&mut crate::subcommand::benchmark::account_pool::PoolAccount> {
    guard
        .pool_mut()
        .accounts
        .iter_mut()
        .find(|account| account.index == index)
        .with_context(|| format!("pool account {} vanished", index))
}

/// Reset stale in-flight markers left by an interrupted run. The pool lock
/// guarantees no other scenario is using these accounts right now.
fn reset_stale_in_flight(guard: &mut PoolGuard, report: &mut ScenarioReport) {
    let stale: Vec<u32> = guard
        .pool()
        .accounts
        .iter()
        .filter(|account| account.in_flight)
        .map(|account| account.index)
        .collect();
    if stale.is_empty() {
        return;
    }
    for index in &stale {
        if let Ok(account) = find_account_mut(guard, *index) {
            account.in_flight = false;
        }
    }
    report
        .notes
        .push(format!("reset {} stale in-flight account marker(s) from an interrupted run", stale.len()));
}

// ---------------------------------------------------------------------------
// pool-create / register
// ---------------------------------------------------------------------------

/// Distinguish a registration that definitively never reached the network
/// (local validation failed before any RPC) from one whose request may be in
/// flight or queued. Only `RejectedLocally` may be treated as retryable
/// without a chain query first.
enum RegisterSubmitOutcome {
    Accepted(String),
    RejectedLocally(anyhow::Error),
    SendAmbiguous(anyhow::Error),
}

pub async fn run_pool_create(args: PoolCreateArgs) -> Result<ScenarioReport> {
    let context = load_context(&args.common.rpc_config)?;
    let mut guard = open_pool(&args.common.pool_dir, &context.network, &context.network_name)?;
    create_missing_accounts(&mut guard, args.count, args.common.wallet_password.as_deref())?;
    run_register_inner(&context, guard, args.concurrency, args.confirm_timeout_secs, "pool-create").await
}

pub async fn run_register(args: RegisterArgs) -> Result<ScenarioReport> {
    let context = load_context(&args.common.rpc_config)?;
    let guard = open_pool(&args.common.pool_dir, &context.network, &context.network_name)?;
    run_register_inner(&context, guard, args.concurrency, args.confirm_timeout_secs, "register").await
}

async fn run_register_inner(
    context: &BenchmarkContext,
    mut guard: PoolGuard,
    concurrency: usize,
    confirm_timeout_secs: u64,
    scenario: &str,
) -> Result<ScenarioReport> {
    let mut report = ScenarioReport::new(scenario, &context.network_name, now_unix_ms());
    let concurrency = concurrency.max(1);

    // Phase 1: reconcile pending, unknown, or previously failed registrations
    // by querying the chain first. A client-side RPC failure is ambiguous — the
    // registration may still have been accepted — so resubmission happens only
    // for Failed ops whose key is confirmed absent on-chain; Unknown stays
    // isolated because absence does not prove the earlier submission is not
    // still queued.
    let mut still_unknown: Vec<u32> = Vec::new();
    for account in guard.pool_mut().accounts.iter_mut() {
        let needs_query = matches!(
            account.registration,
            RegistrationState::Pending { .. } | RegistrationState::Unknown { .. } | RegistrationState::Failed { .. }
        );
        if !needs_query {
            continue;
        }
        let index = account.index;
        let outcome = async {
            let provider = RpcProvider::new_with_config(&context.network)?;
            let public_key_hash = QHashOut::<F>::from_str(&account.public_key_hash)?;
            let user_ids = provider.get_user_ids_for_public_key(public_key_hash).await?;
            Ok::<_, anyhow::Error>(user_ids.first().copied())
        }
        .await;
        match outcome {
            Ok(Some(user_id)) => {
                account.user_id = Some(user_id);
                account.registration = RegistrationState::Registered;
                report.counts.included += 1;
            }
            Ok(None) => {
                if matches!(account.registration, RegistrationState::Failed { .. }) {
                    // Confirmed absent after an explicit submit failure: safe to retry.
                    account.registration = RegistrationState::Unregistered;
                } else if matches!(account.registration, RegistrationState::Unknown { .. }) {
                    still_unknown.push(index);
                }
            }
            // The query itself failed: the on-chain state is ambiguous, so keep
            // the current status for the next run's reconcile instead of
            // resubmitting, and let the rest of the run proceed.
            Err(error) => {
                report.notes.push(format!("reconcile query failed for account {index}: {error:#}"));
            }
        }
    }
    if !still_unknown.is_empty() {
        report.notes.push(format!(
            "registration(s) for account(s) {:?} are still unknown from a previous run; not resubmitting (edit pool.json to reset if certain they never landed)",
            still_unknown
        ));
    }
    guard.save()?;

    // Phase 2: submit registrations for accounts confirmed absent on-chain.
    let candidates: Vec<(u32, String, String, String)> = guard
        .pool()
        .accounts
        .iter()
        .filter(|account| matches!(account.registration, RegistrationState::Unregistered))
        .map(|account| {
            (
                account.index,
                account.public_key_hash.clone(),
                account.fingerprint.clone(),
                account.public_key_param.clone(),
            )
        })
        .collect();
    report.counts.initiated = candidates.len() as u64;

    // Record submit intent before any request leaves: a crash after the RPC
    // fires but before its response lands must leave Pending, never
    // Unregistered, or a restart would resubmit a possibly-queued request.
    for (index, _, _, _) in &candidates {
        let account = find_account_mut(&mut guard, *index)?;
        account.registration = RegistrationState::Pending { tx_uuid: None };
    }
    guard.save()?;

    let mut submit_latency = LatencySamples::default();
    let mut stream = futures::stream::iter(candidates.into_iter().map(|(index, pk_hash, fingerprint, public_key_param)| {
        let network = context.network.clone();
        async move {
            let started = Instant::now();
            let outcome = async {
                // Local validation only: a failure here is definitive proof
                // the request never left the machine.
                let prepared = async {
                    let provider = RpcProvider::new_with_config(&network)?;
                    let public_key_info = ZKPublicKeyInfo {
                        fingerprint: QHashOut::<F>::from_str(&fingerprint)?,
                        public_key_param: QHashOut::<F>::from_str(&public_key_param)?,
                    };
                    anyhow::ensure!(
                        public_key_info.qfhash::<psy_client_data::config::store_config::PsyHasher>()
                            == QHashOut::<F>::from_str(&pk_hash)?,
                        "pool entry public key hash mismatch for account {}",
                        index
                    );
                    Ok::<_, anyhow::Error>((provider, public_key_info))
                }
                .await;
                let (provider, public_key_info) = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => return RegisterSubmitOutcome::RejectedLocally(error),
                };
                // From here the request may have reached the node even when
                // the call errors (lost response, timeout), so any failure is
                // ambiguous — never definitive.
                match provider.register_user(QRegisterUserRPCRequest { public_key: public_key_info }).await {
                    Ok(tx_uuid) => RegisterSubmitOutcome::Accepted(tx_uuid),
                    Err(error) => RegisterSubmitOutcome::SendAmbiguous(error),
                }
            }
            .await;
            (index, outcome, started.elapsed())
        }
    }))
    .buffer_unordered(concurrency);

    while let Some((index, outcome, elapsed)) = stream.next().await {
        submit_latency.record(elapsed);
        let account = find_account_mut(&mut guard, index)?;
        match outcome {
            RegisterSubmitOutcome::Accepted(tx_uuid) => {
                account.registration = RegistrationState::Pending { tx_uuid: Some(tx_uuid) };
                report.counts.submitted += 1;
            }
            RegisterSubmitOutcome::RejectedLocally(error) => {
                account.registration = RegistrationState::Failed { error: format!("{error:#}") };
                report.counts.failed += 1;
            }
            RegisterSubmitOutcome::SendAmbiguous(error) => {
                // The request may still be queued; intent is already recorded
                // as Pending, and the confirm phase decides by querying the
                // chain instead of resubmitting.
                account.registration = RegistrationState::Pending { tx_uuid: None };
                report.counts.unknown += 1;
                report.notes.push(format!("account {index} registration send ambiguous: {error:#}"));
            }
        }
        // Persist each decision immediately: a crash mid-batch must not lose
        // that an accepted registration was already submitted.
        guard.save()?;
    }

    // Phase 3: confirm submitted registrations. Registrations normally land
    // within a couple of checkpoints, so the wait is capped well below the
    // scenario timeout: a registration absent after this long is almost
    // certainly a lost request, and it becomes Unknown (never blindly
    // resubmitted) for the next run's reconcile either way — blocking the
    // whole run on it buys nothing.
    let confirm_wait_secs = confirm_timeout_secs.min(REGISTER_CONFIRM_WAIT_CAP_SECS);
    println!("[{scenario}] confirming registrations, waiting at most {confirm_wait_secs}s");
    let mut noted_confirm_failures: HashSet<String> = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(confirm_wait_secs);
    loop {
        let pending: Vec<String> = guard
            .pool()
            .accounts
            .iter()
            .filter(|account| matches!(account.registration, RegistrationState::Pending { .. }))
            .map(|account| account.public_key_hash.clone())
            .collect();
        if pending.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            let mut unconfirmed_accepted = 0u64;
            let mut unconfirmed_ambiguous = 0u64;
            for account in guard.pool_mut().accounts.iter_mut() {
                if let RegistrationState::Pending { tx_uuid } = account.registration.clone() {
                    if tx_uuid.is_some() {
                        unconfirmed_accepted += 1;
                    } else {
                        // Already counted as unknown when the ambiguous send
                        // was recorded; flipping state must not double-count.
                        unconfirmed_ambiguous += 1;
                    }
                    account.registration = RegistrationState::Unknown { tx_uuid };
                }
            }
            report.counts.unknown += unconfirmed_accepted;
            report.notes.push(format!(
                "{} registration(s) unconfirmed after {}s ({} with an accepted RPC response, {} with an ambiguous send); they stay unknown and are re-queried by the next run",
                unconfirmed_accepted + unconfirmed_ambiguous, confirm_wait_secs, unconfirmed_accepted, unconfirmed_ambiguous
            ));
            guard.save()?;
            break;
        }
        let mut stream = futures::stream::iter(pending.iter().map(|pk_hash| {
            let network = context.network.clone();
            let pk_hash = pk_hash.clone();
            async move {
                let outcome = async {
                    let provider = RpcProvider::new_with_config(&network)?;
                    let user_ids = provider.get_user_ids_for_public_key(QHashOut::<F>::from_str(&pk_hash)?).await?;
                    Ok::<_, anyhow::Error>(user_ids.first().copied())
                }
                .await;
                (pk_hash, outcome)
            }
        }))
        .buffer_unordered(concurrency);
        while let Some((pk_hash, outcome)) = stream.next().await {
            let user_id = match outcome {
                Ok(user_id) => user_id,
                // A flaky confirmation query must not abort the round: the
                // account stays Pending and is re-polled on the next pass.
                Err(error) => {
                    if noted_confirm_failures.insert(pk_hash.clone()) {
                        let prefix: String = pk_hash.chars().take(16).collect();
                        report.notes.push(format!("confirm query failed for {prefix}...: {error:#}"));
                    }
                    continue;
                }
            };
            if let Some(user_id) = user_id {
                if let Some(account) = guard
                    .pool_mut()
                    .accounts
                    .iter_mut()
                    .find(|account| account.public_key_hash == pk_hash)
                {
                    account.user_id = Some(user_id);
                    account.registration = RegistrationState::Registered;
                    report.counts.included += 1;
                }
            }
        }
        guard.save()?;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    report.submit_latency_ms = submit_latency.summarize();
    finish_report(report)
}

// ---------------------------------------------------------------------------
// faucet: fund every registered pool account through the network's faucet
// service. The benchmark never faucets implicitly; this scenario is the
// explicit funding step.
// ---------------------------------------------------------------------------

pub async fn run_faucet(args: FaucetArgs) -> Result<ScenarioReport> {
    let context = load_context(&args.common.rpc_config)?;
    let mut guard = open_pool(&args.common.pool_dir, &context.network, &context.network_name)?;
    let mut report = ScenarioReport::new("faucet", &context.network_name, now_unix_ms());
    let faucet_url = context
        .network
        .faucet_rpc_url
        .first()
        .context("selected network has no faucet_rpc_url configured")?
        .trim_end_matches('/')
        .to_string();

    let accounts: Vec<(u32, u64)> = guard
        .pool()
        .accounts
        .iter()
        .filter_map(|account| account.user_id.map(|user_id| (account.index, user_id)))
        .collect();
    anyhow::ensure!(!accounts.is_empty(), "pool has no registered accounts; run `benchmark register` first");
    report.counts.initiated = accounts.len() as u64;

    let client = reqwest::Client::new();
    let mut stream = futures::stream::iter(accounts.into_iter().map(|(account_index, user_id)| {
        let faucet_url = faucet_url.clone();
        let client = &client;
        async move {
            let started = Instant::now();
            let outcome = claim_faucet(client, &faucet_url, user_id).await;
            (account_index, user_id, outcome, started.elapsed())
        }
    }))
    .buffer_unordered(args.concurrency.max(1));

    let mut submit_latency = LatencySamples::default();
    let mut include_latency = LatencySamples::default();
    // (account, recipient user id, faucet operator, submit moment) awaiting
    // confirmation that the transfer is claimable in a committed checkpoint.
    let mut pending_confirmation: Vec<(u32, u64, u64, Instant)> = Vec::new();
    while let Some((account_index, user_id, outcome, elapsed)) = stream.next().await {
        submit_latency.record(elapsed);
        match outcome {
            Ok(response) => {
                report.counts.submitted += 1;
                if let Ok(account) = find_account_mut(&mut guard, account_index) {
                    account.last_faucet_operator = Some(response.operator_user_id);
                }
                pending_confirmation.push((account_index, user_id, response.operator_user_id, Instant::now()));
                report.notes.push(format!(
                    "account {} (user {}): funded {} by operator {} at checkpoint {}; run `benchmark claim` to move it into the spendable balance",
                    account_index, user_id, response.amount, response.operator_user_id, response.checkpoint_id
                ));
            }
            Err(error) => {
                report.counts.failed += 1;
                report.notes.push(format!("account {} (user {}): faucet claim failed: {error:#}", account_index, user_id));
            }
        }
    }
    guard.save()?;

    // Confirmation phase: the faucet RPC accepting the request is not
    // inclusion. Wait until each transfer is actually claimable from its
    // operator in a committed checkpoint — otherwise a follow-up
    // `benchmark claim` fails with "no tokens to claim".
    let provider = RpcProvider::new_with_config(&context.network)?;
    let deadline = Instant::now() + Duration::from_secs(args.confirm_timeout_secs);
    while !pending_confirmation.is_empty() && Instant::now() < deadline {
        let Ok(latest) = provider.get_coordinator_latest_checkpoint_id().await else {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        let mut still_pending = Vec::with_capacity(pending_confirmation.len());
        for (account_index, user_id, operator, submitted_at) in pending_confirmation {
            // Zero or an errored query both mean "not claimable yet" — the
            // transfer's checkpoint may not be committed, or the state read
            // raced a checkpoint boundary.
            let claimable = provider.get_claim_amount(latest, user_id, operator).await.unwrap_or(0);
            if claimable > 0 {
                report.counts.included += 1;
                include_latency.record(submitted_at.elapsed());
            } else {
                still_pending.push((account_index, user_id, operator, submitted_at));
            }
        }
        pending_confirmation = still_pending;
        if !pending_confirmation.is_empty() {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    if !pending_confirmation.is_empty() {
        report.counts.unknown += pending_confirmation.len() as u64;
        report.notes.push(format!(
            "{} faucet transfer(s) not claimable after {}s; rerun `benchmark faucet` or wait before claiming",
            pending_confirmation.len(),
            args.confirm_timeout_secs
        ));
    }
    report.submit_latency_ms = submit_latency.summarize();
    report.include_latency_ms = include_latency.summarize();
    finish_report(report)
}

#[derive(Debug, serde::Deserialize)]
struct FaucetClaimResponse {
    amount: String,
    operator_user_id: u64,
    checkpoint_id: u64,
}

async fn claim_faucet(client: &reqwest::Client, faucet_url: &str, user_id: u64) -> Result<FaucetClaimResponse> {
    #[derive(serde::Serialize)]
    struct ClaimParams {
        recipient_user_id: u64,
    }
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "psy_claim_faucet",
        "params": {"input": ClaimParams { recipient_user_id: user_id }},
    });
    let response = client.post(faucet_url).json(&body).send().await?;
    let status = response.status();
    let raw_body = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("faucet HTTP {}: {}", status, raw_body.chars().take(200).collect::<String>());
    }
    let value: serde_json::Value = serde_json::from_str(&raw_body)
        .with_context(|| format!("faucet returned a non-JSON body (HTTP {}): {}", status, raw_body.chars().take(200).collect::<String>()))?;
    if let Some(error) = value.get("error") {
        anyhow::bail!("faucet rejected the claim: {}", error);
    }
    let result = value
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(serde_json::from_value(result)?)
}

#[derive(clap::Args)]
pub struct FaucetArgs {
    #[command(flatten)]
    pub common: BenchmarkCommonArgs,
    /// Concurrent faucet claims.
    #[arg(long, default_value = "4")]
    pub concurrency: usize,
    /// Seconds to wait for the faucet transfers to become claimable in a
    /// committed checkpoint.
    #[arg(long, default_value = "600")]
    pub confirm_timeout_secs: u64,
}

/// A scheduling-loop event: `Dispatched` fires synchronously right before a
/// job's thread launches — the durable intent moment — and `Completed` carries
/// the job's outcome.
enum LiveEvent<R> {
    Dispatched,
    Completed(Result<R>),
}

/// Run jobs on bounded OS threads. `on_event` returns whether to keep
/// scheduling jobs that have not launched yet; already in-flight jobs are
/// always drained and reported.
fn run_bounded_live<T, R>(
    jobs: Vec<T>,
    concurrency: usize,
    worker: impl Fn(usize, T) -> Result<R> + Send + Sync + 'static,
    mut on_event: impl FnMut(usize, LiveEvent<R>) -> bool,
) where
    T: Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = mpsc::channel::<(usize, Result<R>)>();
    let worker = Arc::new(worker);
    let mut jobs: Vec<Option<T>> = jobs.into_iter().map(Some).collect();
    let mut next = 0usize;
    let mut active = 0usize;
    let mut schedule = true;
    while next < jobs.len() || active > 0 {
        while schedule && next < jobs.len() && active < concurrency.max(1) {
            if !on_event(next, LiveEvent::Dispatched) {
                schedule = false;
                next += 1;
                continue;
            }
            let job = jobs[next].take().expect("job enqueued once");
            let tx = tx.clone();
            let worker = worker.clone();
            std::thread::spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(next, job)))
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("benchmark worker panicked")));
                let _ = tx.send((next, result));
            });
            next += 1;
            active += 1;
        }
        if active == 0 {
            break;
        }
        match rx.recv() {
            Ok((index, result)) => {
                active -= 1;
                if !on_event(index, LiveEvent::Completed(result)) {
                    schedule = false;
                }
            }
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// deploy
// ---------------------------------------------------------------------------

pub async fn run_deploy(args: DeployArgs) -> Result<ScenarioReport> {
    let context = load_context(&args.common.rpc_config)?;
    let mut guard = open_pool(&args.common.pool_dir, &context.network, &context.network_name)?;
    let mut report = ScenarioReport::new("deploy", &context.network_name, now_unix_ms());
    reset_stale_in_flight(&mut guard, &mut report);

    let artifact_raw = std::fs::read_to_string(&args.contract_path)
        .with_context(|| format!("read contract artifact {}", args.contract_path.display()))?;
    serde_json::from_str::<CompilationArtifact>(&artifact_raw)
        .with_context(|| format!("parse contract artifact {}", args.contract_path.display()))?;
    report.notes.push(format!("contract artifact: {}", args.contract_path.display()));
    report.notes.push(
        "deploy RPC returns an acceptance uuid; after submission the scenario waits for checkpoint inclusion to resolve the sequentially assigned numeric contract ids"
            .to_string(),
    );

    let eligible = registered_accounts(&guard);
    anyhow::ensure!(
        !eligible.is_empty(),
        "pool has no registered accounts; run `benchmark register` (or `pool-create`) first"
    );
    report.counts.initiated = args.count as u64;

    // Contract ids are assigned sequentially at checkpoint inclusion; snapshot
    // the next id so this batch's ids can be resolved after submission.
    let provider = RpcProvider::new_with_config(&context.network)?;
    let id_before = provider.get_coordinator_latest_block_state().await?.next_contract_id as u64;
    let ops_start = guard.pool().ops.len();

    let jobs: Vec<DeployJob> = (0..args.count)
        .map(|op| {
            let account_index = eligible[op as usize % eligible.len()];
            let account = guard
                .pool()
                .accounts
                .iter()
                .find(|account| account.index == account_index)
                .expect("eligible account must exist")
                .clone();
            DeployJob {
                op_id: format!("deploy-{}-{}", now_unix_ms(), op),
                account_index,
                user_id: account.user_id.expect("eligible account has a user id"),
                public_key_hash: account.public_key_hash.clone(),
                keystore_file: account.keystore_file.clone(),
                pool_dir: guard.pool_dir().to_path_buf(),
                artifact_json: artifact_raw.clone(),
            }
        })
        .collect();

    let mut submit_latency = LatencySamples::default();
    let mut deployed_identities: Vec<(String, u64, String)> = Vec::new();
    let mut save_error: Option<anyhow::Error> = None;
    run_bounded_live(
        jobs,
        args.concurrency,
        {
            let network = context.network.clone();
            let wallet_password = args.common.wallet_password.clone();
            move |_, job: DeployJob| deploy_one(&network, wallet_password.as_deref(), &job)
        },
        |_, event| {
            let result = match event {
                LiveEvent::Dispatched => return true,
                LiveEvent::Completed(result) => result,
            };
            match result {
                Ok(outcome) => {
                    submit_latency.record(outcome.elapsed);
                    report.counts.submitted += 1;
                    deployed_identities.push((outcome.op_id.clone(), outcome.deployer, outcome.code_root));
                    guard.pool_mut().ops.push(PoolOpRecord {
                        op_id: outcome.op_id,
                        scenario: "deploy".to_string(),
                        account_index: outcome.account_index,
                        tx_hash: Some(outcome.contract_id.clone()),
                        status: OpStatus::Submitted,
                        error: None,
                        user_id: None,
                        end_user_leaf_hash: None,
                        checkpoint_before: None,
                        contract_id: None,
                        started_unix_ms: outcome.started_unix_ms,
                        finished_unix_ms: Some(now_unix_ms()),
                    });
                    if let Err(error) = guard.save() {
                        save_error.get_or_insert(error);
                    }
                }
                Err(error) => {
                    report.counts.failed += 1;
                    report.notes.push(format!("deploy failed: {error:#}"));
                }
            }
            save_error.is_none()
        },
    );
    if let Some(error) = save_error {
        return Err(error);
    }

    // Wait for checkpoint inclusion so the sequential contract ids are
    // assigned, then bind each op to its exact id by fetching every assigned
    // id's on-chain leaf and matching deployer + code root. A foreign
    // deployment in the window simply matches nothing; an op whose leaf is
    // absent stays Unknown instead of guessing.
    let submitted = report.counts.submitted;
    if submitted > 0 {
        let target = id_before + submitted;
        let mut resolved_end = id_before;
        let deadline = Instant::now() + Duration::from_secs(args.confirm_timeout_secs);
        loop {
            if let Ok(state) = provider.get_coordinator_latest_block_state().await {
                resolved_end = state.next_contract_id as u64;
            }
            if resolved_end >= target || Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let mut onchain: Vec<(u64, u64, String)> = Vec::new();
        for contract_id in id_before..resolved_end {
            match provider.get_contract_leaf_data(contract_id).await {
                Ok(leaf) => onchain.push((
                    contract_id,
                    leaf.deployer.to_noncanonical_u64(),
                    leaf.code_root.to_string(),
                )),
                Err(_) => break,
            }
        }
        let bound = bind_deploy_contract_ids(&deployed_identities, &onchain);
        for record in guard.pool_mut().ops[ops_start..].iter_mut() {
            match bound.get(&record.op_id) {
                Some(contract_id) => {
                    record.status = OpStatus::Included;
                    record.contract_id = Some(*contract_id);
                    report.counts.included += 1;
                }
                None => {
                    record.status = OpStatus::Unknown;
                    report.counts.unknown += 1;
                }
            }
        }
        if bound.len() < submitted as usize {
            report.notes.push(format!(
                "{} of {} deployed contract ids unresolved (not yet assigned, rejected, or unbindable); those ops stay unknown, rerun `benchmark deploy` or pass --contract-id manually",
                submitted - bound.len() as u64,
                submitted
            ));
        }
        guard.save()?;
    }
    report.submit_latency_ms = submit_latency.summarize();
    finish_report(report)
}

struct DeployJob {
    op_id: String,
    account_index: u32,
    user_id: u64,
    public_key_hash: String,
    keystore_file: String,
    pool_dir: PathBuf,
    artifact_json: String,
}

struct DeployOutcome {
    op_id: String,
    account_index: u32,
    contract_id: String,
    /// Identity of the deployed contract for post-inclusion binding: the
    /// on-chain leaf must carry this deployer and code root.
    deployer: u64,
    code_root: String,
    elapsed: Duration,
    started_unix_ms: i64,
}

/// Exact per-op binding: a deploy op owns contract id X iff X's on-chain leaf
/// carries the op's deployer and code root. Foreign deployments never match —
/// even of the same artifact, since the deployer differs — and rotating
/// deployers within one batch each match their own id. Every on-chain leaf
/// satisfies at most one op: repeated deployments of the same artifact by the
/// same account bind to distinct ids, and an op whose deployment is not yet
/// included stays unbound instead of shadowing a sibling's id.
fn bind_deploy_contract_ids(
    expected: &[(String, u64, String)],
    onchain: &[(u64, u64, String)],
) -> HashMap<String, u64> {
    let mut bound = HashMap::new();
    for (contract_id, leaf_deployer, leaf_code_root) in onchain {
        let unmatched = expected.iter().find(|(op_id, deployer, code_root)| {
            !bound.contains_key(op_id) && deployer == leaf_deployer && code_root == leaf_code_root
        });
        if let Some((op_id, _, _)) = unmatched {
            bound.insert(op_id.clone(), *contract_id);
        }
    }
    bound
}

fn deploy_one(network: &NetworkConfigGoldilocks, wallet_password: Option<&str>, job: &DeployJob) -> Result<DeployOutcome> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let started = Instant::now();
        let started_unix_ms = now_unix_ms();
        let artifact: CompilationArtifact = serde_json::from_str(&job.artifact_json)?;
        let keystore_abs = job.pool_dir.join(&job.keystore_file);
        let info = load_wallet_key_info(
            &wallet_source_args(keystore_abs.to_str().context("keystore path is not UTF-8")?, wallet_password),
            false,
        )?;
        anyhow::ensure!(
            info.public_key_hash.to_string() == job.public_key_hash,
            "keystore public key hash does not match the pool entry for account {}",
            job.account_index
        );
        let deployer = job.user_id;

        let abi = artifact.abi.clone();
        let abi_json = serde_json::to_string(&abi)?;
        let state_tree_height = usize::from(artifact.state_tree_height);
        let (_circuits, deploy_cmd) =
            gen_contract_deploy_and_circuits_for_functions::<C, D>(deployer, state_tree_height as u8, &artifact.circuit_definitions)?;
        let contract_output = psy_compiler::output::serialize::ContractOutput {
            contract_code: deploy_cmd.code_definition.clone(),
            circuit_definitions: artifact.circuit_definitions.clone(),
            abi,
        };
        let deploy_cmd = build_layout_aware_deploy_command(&contract_output, deploy_cmd)?;

        psy_user_cli::subcommand::contract_abi_upload::upload_contract_abi(network, &deploy_cmd, &abi_json).await?;
        let provider = RpcProvider::new_with_config(network)?;
        // Identity the on-chain contract leaf must carry for post-inclusion
        // binding: this deployer and this command's code root.
        let deployer = deploy_cmd.deploy_contract.deployer;
        let code_root = deploy_cmd.deploy_contract.code_root.to_string();
        let contract_uuid = provider.deploy_contract(QDeployContractRPCRequest { deploy_contract: deploy_cmd }).await?;

        Ok(DeployOutcome {
            op_id: job.op_id.clone(),
            account_index: job.account_index,
            contract_id: contract_uuid,
            deployer,
            code_root,
            elapsed: started.elapsed(),
            started_unix_ms,
        })
    })
}

// ---------------------------------------------------------------------------
// endcap
// ---------------------------------------------------------------------------

pub async fn run_endcap(args: EndcapArgs) -> Result<ScenarioReport> {
    let context = load_context(&args.common.rpc_config)?;
    let mut guard = open_pool(&args.common.pool_dir, &context.network, &context.network_name)?;
    let mut report = ScenarioReport::new("endcap", &context.network_name, now_unix_ms());
    reset_stale_in_flight(&mut guard, &mut report);

    reconcile_open_endcaps(&context, &mut guard, args.confirm_timeout_secs, &mut report).await?;

    let contract_call_data = build_contract_call_data(&args)?;
    let open_accounts = open_endcap_accounts(&guard);
    let eligible: Vec<u32> = registered_accounts(&guard)
        .into_iter()
        .filter(|index| !open_accounts.contains(index))
        .collect();
    if !open_accounts.is_empty() {
        report.notes.push(format!(
            "{} pool account(s) own open EndCaps from a previous run and are excluded from this run",
            open_accounts.len()
        ));
    }
    anyhow::ensure!(
        !eligible.is_empty(),
        "pool has no registered accounts; run `benchmark register` (or `pool-create`) first"
    );
    let concurrency = args.concurrency.max(1).min(eligible.len());
    if concurrency < args.concurrency.max(1) {
        report.notes.push(format!(
            "prove concurrency capped at {} by the number of registered accounts",
            concurrency
        ));
    }
    anyhow::ensure!(
        args.tx_count as usize <= eligible.len(),
        "tx-count {} exceeds the {} registered pool accounts; each EndCap needs its own account for one in-flight EndCap per account",
        args.tx_count,
        eligible.len()
    );
    report.counts.initiated = args.tx_count as u64;

    let planned: Vec<(crate::subcommand::benchmark::account_pool::PoolAccount, ContractCallData)> = (0..args.tx_count)
        .map(|op| {
            let account_index = eligible[op as usize % eligible.len()];
            let account = guard
                .pool()
                .accounts
                .iter()
                .find(|account| account.index == account_index)
                .expect("eligible account must exist")
                .clone();
            (account, contract_call_data.clone())
        })
        .collect();
    run_endcap_round(
        context,
        guard,
        report,
        planned,
        EndcapRoundParams {
            wallet_password: args.common.wallet_password.clone(),
            concurrency,
            confirm_concurrency: args.confirm_concurrency,
            confirm_timeout_secs: args.confirm_timeout_secs,
        },
    )
    .await
}

struct EndcapRoundParams {
    wallet_password: Option<String>,
    concurrency: usize,
    confirm_concurrency: usize,
    confirm_timeout_secs: u64,
}

/// Shared execution round for EndCap-shaped scenarios: durably record one op
/// per account, prove on bounded threads, persist submissions as they land,
/// then wait for checkpoint inclusion with bounded observation concurrency.
async fn run_endcap_round(
    context: BenchmarkContext,
    mut guard: PoolGuard,
    mut report: ScenarioReport,
    planned: Vec<(crate::subcommand::benchmark::account_pool::PoolAccount, ContractCallData)>,
    params: EndcapRoundParams,
) -> Result<ScenarioReport> {
    let scenario = report.scenario.clone();
    let mut op_record_indices: HashMap<String, usize> = HashMap::new();
    let jobs: Vec<EndcapJob> = planned
        .into_iter()
        .enumerate()
        .map(|(op, (account, contract_call_data))| {
            let op_id = format!("{}-{}-{}", scenario, now_unix_ms(), op);
            let record = PoolOpRecord {
                op_id: op_id.clone(),
                scenario: scenario.clone(),
                account_index: account.index,
                tx_hash: None,
                status: OpStatus::Unknown,
                error: None,
                user_id: Some(account.user_id.expect("planned account has a user id")),
                end_user_leaf_hash: None,
                checkpoint_before: None,
                contract_id: None,
                started_unix_ms: now_unix_ms(),
                finished_unix_ms: None,
            };
            op_record_indices.insert(op_id.clone(), guard.pool().ops.len());
            guard.pool_mut().ops.push(record);
            if let Ok(account) = find_account_mut(&mut guard, account.index) {
                account.in_flight = true;
            }
            EndcapJob {
                op_id,
                account_index: account.index,
                user_id: account.user_id.expect("planned account has a user id"),
                public_key_hash: account.public_key_hash.clone(),
                keystore_file: account.keystore_file.clone(),
                pool_dir: guard.pool_dir().to_path_buf(),
                contract_call_data,
            }
        })
        .collect();
    guard.save()?;

    // One shared proving session for the whole round: proving methods take
    // `&self` and per-user proving managers live in a DashMap, so concurrent
    // ops on distinct pool accounts reuse the circuit metadata fetched once
    // here instead of rebuilding a session per op.
    println!("[{scenario}] building shared WalletSession (circuit metadata fetch)");
    let mut wallet_session = WalletSession::new(&context.network).await?;
    let provider = Arc::new(RpcProvider::new_with_config(&context.network)?);

    // Register every account's user up front: `add_user` needs `&mut self`,
    // and keystore decryption leaves the per-op hot path. An account that
    // fails registration drops out of the round without aborting the rest.
    let mut registered: Vec<(EndcapJob, QHashOut<F>)> = Vec::with_capacity(jobs.len());
    for job in jobs {
        let op_id = job.op_id.clone();
        let account_index = job.account_index;
        let user_id = job.user_id;
        let keystore_abs = guard.pool_dir().join(&job.keystore_file);
        let registered_user = async {
            let wallet_args = wallet_source_args(
                keystore_abs.to_str().context("keystore path is not UTF-8")?,
                params.wallet_password.as_deref(),
            );
            let info = load_wallet_key_info(&wallet_args, false)?;
            anyhow::ensure!(
                info.public_key_hash.to_string() == job.public_key_hash,
                "keystore public key hash does not match the pool entry for account {}",
                account_index
            );
            wallet_session.add_user(info.private_key, info.fingerprint).await
        }
        .await;
        match registered_user {
            Ok(user_pk_hash) => registered.push((job, user_pk_hash)),
            Err(error) => {
                report.counts.failed += 1;
                if let Ok(account) = find_account_mut(&mut guard, account_index) {
                    account.in_flight = false;
                }
                if let Some(record_index) = op_record_indices.get(&op_id) {
                    let record = &mut guard.pool_mut().ops[*record_index];
                    record.status = OpStatus::Failed;
                    record.error = Some(format!("{error:#}"));
                    record.finished_unix_ms = Some(now_unix_ms());
                }
                report.notes.push(format!("endcap op {op_id} user_id={user_id} user registration failed: {error:#}"));
            }
        }
    }
    guard.save()?;

    let mut trace_latency = LatencySamples::default();
    let mut prove_latency = LatencySamples::default();
    let mut submit_latency = LatencySamples::default();
    let mut submitted: Vec<SubmittedEndcap> = Vec::new();
    let mut record_error: Option<anyhow::Error> = None;
    let wallet_session = Arc::new(wallet_session);

    // Phase A: generate traces. Trace generation is local (reads state, never
    // submits), so a failure here is final and the account is safely
    // reusable. The end user leaf hash — the identity reconciliation queries
    // inclusion by — is persisted BEFORE any proving runs, so a crash or lost
    // response around the submission always leaves a reconcilable record.
    println!(
        "[{scenario}] phase A: tracing {} op(s) at concurrency {}",
        registered.len(),
        params.concurrency.max(1)
    );
    let mut traced: Vec<TracedEndcap> = Vec::new();
    run_bounded_live(
        registered,
        params.concurrency,
        {
            let wallet_session = wallet_session.clone();
            let provider = provider.clone();
            move |_, (job, user_pk_hash): (EndcapJob, QHashOut<F>)| {
                let op_id = job.op_id.clone();
                let account_index = job.account_index;
                Ok(EndcapWorkerResult {
                    op_id,
                    account_index,
                    result: endcap_trace_one(&wallet_session, &provider, &job, user_pk_hash),
                })
            }
        },
        |_, event| {
            let worker_result = match event {
                LiveEvent::Dispatched => return true,
                LiveEvent::Completed(result) => result,
            };
            let result = (|| -> Result<()> {
                let EndcapWorkerResult { op_id, account_index, result } = worker_result?;
                match result {
                    Ok(outcome) => {
                        trace_latency.record(outcome.trace_time);
                        let record_index = op_record_indices
                            .get(&op_id)
                            .context("endcap op record vanished")?;
                        let record = &mut guard.pool_mut().ops[*record_index];
                        record.end_user_leaf_hash = Some(outcome.end_user_leaf_hash.clone());
                        record.checkpoint_before = Some(outcome.checkpoint_before);
                        record.status = OpStatus::Traced;
                        let record_user_id = record.user_id;
                        // Traced means the trace exists but nothing was
                        // submitted; the leaf hash above makes the op
                        // reconcilable the moment the submission phase starts.
                        guard.save()?;
                        traced.push(TracedEndcap {
                            op_id,
                            account_index,
                            user_id: record_user_id.expect("endcap round records carry a user id"),
                            user_pk_hash: outcome.user_pk_hash,
                            trace: outcome.trace,
                        });
                    }
                    Err(error) => {
                        report.counts.failed += 1;
                        if let Ok(account) = find_account_mut(&mut guard, account_index) {
                            account.in_flight = false;
                        }
                        let record_index = op_record_indices
                            .get(&op_id)
                            .context("endcap op record vanished")?;
                        let record = &mut guard.pool_mut().ops[*record_index];
                        let user_id = record.user_id.context("endcap op record has no user id")?;
                        record.status = OpStatus::Failed;
                        record.error = Some(format!("{error:#}"));
                        record.finished_unix_ms = Some(now_unix_ms());
                        guard.save()?;
                        report.notes.push(format!("endcap op {op_id} user_id={user_id} trace failed: {error:#}"));
                    }
                }
                Ok(())
            })();
            match result {
                // Keep scheduling unless a durable-record failure already
                // happened; in-flight results are always processed above.
                Ok(()) => record_error.is_none(),
                Err(error) => {
                    record_error.get_or_insert(error);
                    false
                }
            }
        },
    );
    if let Some(error) = record_error {
        return Err(error);
    }

    // Phase B: prove and submit. The Dispatched event flips exactly the op
    // whose thread is launching from Traced to Unknown — the durable boundary
    // of its submission phase. Ops never dispatched stay Traced and are freed
    // by recovery; dispatched-but-interrupted ops carry the leaf hash and are
    // reconciled instead of being assumed unsent or freed.
    let traced_op_ids: Vec<String> = traced.iter().map(|traced_one| traced_one.op_id.clone()).collect();
    println!(
        "[{scenario}] phase B: proving and submitting {} op(s) at concurrency {}",
        traced_op_ids.len(),
        params.concurrency.max(1)
    );
    run_bounded_live(
        traced,
        params.concurrency,
        {
            let wallet_session = wallet_session.clone();
            move |_, traced_one: TracedEndcap| {
                let op_id = traced_one.op_id.clone();
                let account_index = traced_one.account_index;
                let result = endcap_submit_one(&wallet_session, traced_one.user_pk_hash, &traced_one.trace);
                Ok(EndcapWorkerResult { op_id, account_index, result })
            }
        },
        |job_index, event| {
            let worker_result = match event {
                LiveEvent::Dispatched => {
                    // Durable per-op submit intent, written just before this
                    // job's thread launches.
                    let Some(record_index) = op_record_indices.get(&traced_op_ids[job_index]).copied() else {
                        return false;
                    };
                    let record = &mut guard.pool_mut().ops[record_index];
                    record.status = OpStatus::Unknown;
                    if let Err(error) = guard.save() {
                        record_error.get_or_insert(error);
                        return false;
                    }
                    return true;
                }
                LiveEvent::Completed(result) => result,
            };
            let result = (|| -> Result<()> {
                let EndcapWorkerResult { op_id, account_index, result } = worker_result?;
                if let Ok(account) = find_account_mut(&mut guard, account_index) {
                    account.in_flight = false;
                }
                let record_index = op_record_indices
                    .get(&op_id)
                    .context("endcap op record vanished")?;
                let record = &mut guard.pool_mut().ops[*record_index];
                match result {
                    Ok(outcome) => {
                        prove_latency.record(outcome.prove_time);
                        report.counts.submitted += 1;
                        record.status = OpStatus::Submitted;
                        record.tx_hash = Some(outcome.tx_hash.clone());
                        record.finished_unix_ms = Some(now_unix_ms());
                        let submitted_endcap = SubmittedEndcap {
                            user_id: record.user_id.expect("endcap round records carry a user id"),
                            end_user_leaf_hash: record.end_user_leaf_hash.clone().expect("phase A persisted it"),
                            checkpoint_before: record.checkpoint_before.unwrap_or(0),
                            op_id,
                            submitted_at: Instant::now(),
                        };
                        // Persist the submitted EndCap before anything else can fail.
                        guard.save()?;
                        submitted.push(submitted_endcap);
                    }
                    Err(error) => {
                        // The op may have reached the node before the error
                        // (lost response, timeout after acceptance). The leaf
                        // hash is already on record, so keep Unknown for
                        // reconciliation instead of freeing the account.
                        report.counts.unknown += 1;
                        let user_id = record.user_id.context("endcap op record has no user id")?;
                        record.status = OpStatus::Unknown;
                        record.error = Some(format!("submission outcome unknown: {error:#}"));
                        record.finished_unix_ms = Some(now_unix_ms());
                        guard.save()?;
                        report.notes.push(format!("endcap op {op_id} user_id={user_id} submission outcome unknown: {error:#}"));
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => record_error.is_none(),
                Err(error) => {
                    record_error.get_or_insert(error);
                    false
                }
            }
        },
    );
    if let Some(error) = record_error {
        return Err(error);
    }

    // Confirmation phase with bounded observation concurrency. RPC acceptance
    // is not inclusion; only a committed checkpoint counts as included.
    println!(
        "[{scenario}] waiting for checkpoint inclusion of {} submitted op(s), at most {}s",
        submitted.len(),
        params.confirm_timeout_secs
    );
    let confirm_concurrency = params.confirm_concurrency.max(1);
    let mut include_latency = LatencySamples::default();
    let mut confirm_stream = futures::stream::iter(submitted.into_iter().map(|endcap| {
        let network = context.network.clone();
        async move {
            let outcome = async {
                let provider = RpcProvider::new_with_config(&network)?;
                let leaf_hash = QHashOut::<F>::from_str(&endcap.end_user_leaf_hash)?;
                provider
                    .wait_for_endcap_inclusion(
                        endcap.user_id,
                        leaf_hash,
                        endcap.checkpoint_before,
                        Some(params.confirm_timeout_secs),
                        3,
                    )
                    .await
            }
            .await;
            let elapsed = endcap.submitted_at.elapsed();
            (endcap, outcome, elapsed)
        }
    }))
    .buffer_unordered(confirm_concurrency);

    while let Some((endcap, outcome, elapsed)) = confirm_stream.next().await {
        let record_index = op_record_indices
            .get(&endcap.op_id)
            .context("endcap op record vanished")?;
        let record = &mut guard.pool_mut().ops[*record_index];
        match outcome {
            Ok(included_checkpoint) => {
                let _included_checkpoint = included_checkpoint;
                record.status = OpStatus::Included;
                record.finished_unix_ms = Some(now_unix_ms());
                report.counts.included += 1;
                include_latency.record(elapsed);
            }
            Err(error) => {
                record.status = OpStatus::Unknown;
                record.error = Some(format!("{error:#}"));
                report.counts.unknown += 1;
            }
        }
    }
    guard.save()?;

    report.trace_latency_ms = trace_latency.summarize();
    report.prove_latency_ms = prove_latency.summarize();
    report.submit_latency_ms = submit_latency.summarize();
    report.include_latency_ms = include_latency.summarize();
    finish_report(report)
}

/// Claim incoming faucet funds: token `transfer` only records `amount_sent`
/// for the recipient, so each funded account must call `claim(operator)` to
/// move the funds into its spendable balance.
pub async fn run_claim(args: ClaimArgs) -> Result<ScenarioReport> {
    let context = load_context(&args.common.rpc_config)?;
    let mut guard = open_pool(&args.common.pool_dir, &context.network, &context.network_name)?;
    let mut report = ScenarioReport::new("claim", &context.network_name, now_unix_ms());
    reset_stale_in_flight(&mut guard, &mut report);

    reconcile_open_endcaps(&context, &mut guard, args.confirm_timeout_secs, &mut report).await?;

    let open_accounts = open_endcap_accounts(&guard);
    let funded: Vec<crate::subcommand::benchmark::account_pool::PoolAccount> = guard
        .pool()
        .accounts
        .iter()
        .filter(|account| {
            account.user_id.is_some()
                && account.last_faucet_operator.is_some()
                && !open_accounts.contains(&account.index)
        })
        .cloned()
        .collect();
    anyhow::ensure!(
        !funded.is_empty(),
        "no funded pool accounts; run `benchmark faucet` (and wait for its checkpoint) first"
    );

    // Pre-check the claimable balance: an account whose faucet funds were
    // already claimed would fail the trace's claim assertion after ~15s of
    // state reads, so only accounts with a live claimable amount are planned.
    // A failed balance read keeps the account planned — the trace will retry
    // the state access and surface a precise error.
    println!("[claim] checking claimable balances for {} funded account(s)", funded.len());
    let provider = RpcProvider::new_with_config(&context.network)?;
    let build_call_data = |operator: u64| {
        ContractCallData::new(vec![ContractCallArgs {
            contract_id: args.contract_id,
            method_name: "claim".to_string(),
            inputs: vec![operator],
        }])
    };
    let mut nothing_to_claim = 0u64;
    let mut planned: Vec<(crate::subcommand::benchmark::account_pool::PoolAccount, ContractCallData)> = Vec::new();
    for account in funded {
        let user_id = account.user_id.expect("filtered above");
        let operator = account.last_faucet_operator.expect("filtered above");
        let claimable = match provider.get_coordinator_latest_checkpoint_id().await {
            Ok(latest) => provider.get_claim_amount(latest, user_id, operator).await.ok(),
            Err(_) => None,
        };
        match claimable {
            Some(amount) if amount > 0 => planned.push((account, build_call_data(operator))),
            Some(_) => nothing_to_claim += 1,
            // Unreadable balance: keep the account in, the trace decides.
            None => planned.push((account, build_call_data(operator))),
        }
    }
    if nothing_to_claim > 0 {
        report
            .notes
            .push(format!("{} funded account(s) already claimed their faucet funds; skipped", nothing_to_claim));
    }
    anyhow::ensure!(
        !planned.is_empty(),
        "no claimable faucet funds; run `benchmark faucet` first (or the funds were already claimed)"
    );
    let concurrency = args.concurrency.max(1).min(planned.len());
    report.counts.initiated = planned.len() as u64;
    run_endcap_round(
        context,
        guard,
        report,
        planned,
        EndcapRoundParams {
            wallet_password: args.common.wallet_password.clone(),
            concurrency,
            confirm_concurrency: args.confirm_concurrency,
            confirm_timeout_secs: args.confirm_timeout_secs,
        },
    )
    .await
}

#[derive(clap::Args)]
pub struct ClaimArgs {
    #[command(flatten)]
    pub common: BenchmarkCommonArgs,
    /// Token contract id holding the claimable funds.
    #[arg(long, default_value = "0")]
    pub contract_id: u64,
    #[arg(long, default_value = "2")]
    pub concurrency: usize,
    #[arg(long, default_value = "4")]
    pub confirm_concurrency: usize,
    #[arg(long, default_value = "600")]
    pub confirm_timeout_secs: u64,
}

/// Ops recorded by `run_endcap_round`, whatever scenario name it ran under
/// ("endcap", "claim"). All of them submit a real EndCap and need recovery and
/// account isolation; deploy records never carry an end user leaf hash and are
/// naturally excluded by the callers' status/leaf-hash filters.
fn is_endcap_round_scenario(scenario: &str) -> bool {
    matches!(scenario, "endcap" | "claim")
}

fn open_endcap_accounts(guard: &PoolGuard) -> std::collections::HashSet<u32> {
    guard
        .pool()
        .ops
        .iter()
        .filter(|record| {
            is_endcap_round_scenario(&record.scenario)
                && matches!(record.status, OpStatus::Submitted | OpStatus::Unknown)
                && record.end_user_leaf_hash.is_some()
        })
        .map(|record| record.account_index)
        .collect()
}

/// Re-query EndCaps recorded as Submitted or Unknown by an interrupted run.
/// Inclusion is never assumed from the durable record; only a committed
/// checkpoint moves a record to Included.
/// Pure triage of endcap-round op records for recovery. `open` ops may have
/// reached the node and reconcile by their leaf hash; `traced` ops never
/// entered the submission phase; `leafless` ops were interrupted before their
/// trace was even recorded.
struct EndcapRoundTriage {
    open: Vec<(usize, u64, String, u64)>,
    traced: Vec<usize>,
    leafless: Vec<usize>,
}

fn triage_endcap_round_records(ops: &[PoolOpRecord]) -> EndcapRoundTriage {
    let mut triage = EndcapRoundTriage { open: Vec::new(), traced: Vec::new(), leafless: Vec::new() };
    for (index, record) in ops.iter().enumerate() {
        if !is_endcap_round_scenario(&record.scenario) {
            continue;
        }
        match record.status {
            OpStatus::Traced => triage.traced.push(index),
            OpStatus::Submitted | OpStatus::Unknown => match (&record.end_user_leaf_hash, record.user_id) {
                (Some(leaf_hash), Some(user_id)) => triage.open.push((
                    index,
                    user_id,
                    leaf_hash.clone(),
                    record.checkpoint_before.unwrap_or(0),
                )),
                (None, _) => triage.leafless.push(index),
                // A leaf hash without a user id should not happen; leave the
                // record untouched for manual inspection rather than guessing.
                (Some(_), None) => {}
            },
            _ => {}
        }
    }
    triage
}

async fn reconcile_open_endcaps(
    context: &BenchmarkContext,
    guard: &mut PoolGuard,
    confirm_timeout_secs: u64,
    report: &mut ScenarioReport,
) -> Result<()> {
    let EndcapRoundTriage { open, traced, leafless } = triage_endcap_round_records(&guard.pool().ops);
    let traced_count = traced.len();
    for index in &traced {
        let record = &mut guard.pool_mut().ops[*index];
        record.status = OpStatus::Failed;
        record.error =
            Some("traced but interrupted before the submission phase; nothing was submitted, the account is reusable".to_string());
        record.finished_unix_ms = Some(now_unix_ms());
    }
    let leafless_count = leafless.len();
    for index in &leafless {
        let record = &mut guard.pool_mut().ops[*index];
        record.status = OpStatus::Failed;
        record.error = Some("interrupted before the trace was recorded; nothing was submitted, the account is reusable".to_string());
        record.finished_unix_ms = Some(now_unix_ms());
    }
    if traced_count > 0 || leafless_count > 0 {
        guard.save()?;
        report.notes.push(format!(
            "{} traced and {} pre-trace EndCap record(s) interrupted before submission were marked failed; their accounts are reusable",
            traced_count, leafless_count
        ));
    }
    if open.is_empty() {
        return Ok(());
    }
    // Recovery waits are capped well below the scenario confirm timeout: an
    // op that has been Unknown for a whole previous run is unlikely to
    // confirm during this run's startup, and blocking every run on the full
    // timeout (600s against a permanently unresolved record) is pure waste.
    // The record stays Unknown either way; the next run re-queries it.
    let reconcile_wait_secs = confirm_timeout_secs.min(RECONCILE_WAIT_CAP_SECS);
    println!(
        "[reconcile] querying inclusion for {} open EndCap(s), waiting at most {}s",
        open.len(),
        reconcile_wait_secs
    );
    let mut stream = futures::stream::iter(open.into_iter().map(|(index, user_id, leaf_hash, checkpoint_before)| {
        let network = context.network.clone();
        async move {
            let outcome = async {
                let provider = RpcProvider::new_with_config(&network)?;
                let leaf_hash = QHashOut::<F>::from_str(&leaf_hash)?;
                provider
                    .wait_for_endcap_inclusion(user_id, leaf_hash, checkpoint_before, Some(reconcile_wait_secs), 3)
                    .await
            }
            .await;
            (index, outcome)
        }
    }))
    .buffer_unordered(4);
    let mut included = 0u64;
    let mut still_open = 0u64;
    while let Some((index, outcome)) = stream.next().await {
        let record = &mut guard.pool_mut().ops[index];
        match outcome {
            Ok(_) => {
                record.status = OpStatus::Included;
                record.finished_unix_ms = Some(now_unix_ms());
                included += 1;
            }
            Err(error) => {
                // The wait failed or timed out. A missing tx_hash only means
                // no response was recorded locally — the node may still have
                // accepted the op — and the error itself may be an RPC
                // failure rather than a completed wait. Never free the
                // account from here: keep Unknown and reconcile again on the
                // next run (manual pool.json reset if it is certain the op
                // never landed).
                record.status = OpStatus::Unknown;
                record.error = Some(format!("inclusion still unresolved: {error:#}"));
                still_open += 1;
            }
        }
    }
    guard.save()?;
    report.notes.push(format!(
        "reconciled interrupted run: {} EndCap(s) confirmed included, {} still unknown and isolated",
        included, still_open
    ));
    Ok(())
}

struct EndcapWorkerResult<T> {
    op_id: String,
    account_index: u32,
    result: Result<T>,
}

struct EndcapJob {
    op_id: String,
    account_index: u32,
    user_id: u64,
    public_key_hash: String,
    keystore_file: String,
    pool_dir: PathBuf,
    contract_call_data: ContractCallData,
}

/// Phase-A product: a provenance-free trace plus the identity reconciliation
/// will query inclusion by. Trace generation is local (reads state, never
/// submits), so failing here is final.
struct EndcapTraceOutcome {
    user_pk_hash: QHashOut<F>,
    trace: Arc<psy_prover::trace::TxTrace>,
    checkpoint_before: u64,
    end_user_leaf_hash: String,
    trace_time: Duration,
}

/// A traced op entering phase B (prove + submit).
struct TracedEndcap {
    op_id: String,
    account_index: u32,
    user_id: u64,
    user_pk_hash: QHashOut<F>,
    trace: Arc<psy_prover::trace::TxTrace>,
}

struct EndcapSubmitOutcome {
    tx_hash: String,
    prove_time: Duration,
}

struct SubmittedEndcap {
    op_id: String,
    user_id: u64,
    end_user_leaf_hash: String,
    checkpoint_before: u64,
    submitted_at: Instant,
}

fn endcap_trace_one(
    wallet_session: &Arc<WalletSession>,
    provider: &Arc<RpcProvider>,
    job: &EndcapJob,
    user_pk_hash: QHashOut<F>,
) -> Result<EndcapTraceOutcome> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let checkpoint_before = provider.get_coordinator_latest_checkpoint_id().await?;
        let trace_started = Instant::now();
        let trace = wallet_session.generate_tx_trace(user_pk_hash, job.contract_call_data.clone()).await?;
        let trace_time = trace_started.elapsed();
        let end_user_leaf_hash = trace.finalization.submit_end_cap_input.core.state_transition.end_user_leaf_hash;
        Ok(EndcapTraceOutcome {
            user_pk_hash,
            trace: Arc::new(trace),
            checkpoint_before,
            end_user_leaf_hash: end_user_leaf_hash.to_string(),
            trace_time,
        })
    })
}

fn endcap_submit_one(
    wallet_session: &Arc<WalletSession>,
    user_pk_hash: QHashOut<F>,
    trace: &Arc<psy_prover::trace::TxTrace>,
) -> Result<EndcapSubmitOutcome> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let prove_started = Instant::now();
        let tx_hash = wallet_session.prove_tx_trace(user_pk_hash, trace).await?;
        let prove_time = prove_started.elapsed();
        Ok(EndcapSubmitOutcome { tx_hash: tx_hash.to_string(), prove_time })
    })
}

fn build_contract_call_data(args: &EndcapArgs) -> Result<ContractCallData> {
    let mut contract_calls: Vec<ContractCallArgs> = Vec::new();
    if let Some(file_path) = &args.contract_calls_file {
        contract_calls.extend(
            serde_json::from_str::<Vec<ContractCallArgs>>(&std::fs::read_to_string(file_path)?)
                .with_context(|| format!("parse contract calls file {}", file_path.display()))?,
        );
    }
    if !args.contract_id.is_empty() {
        anyhow::ensure!(
            args.contract_id.len() == args.method_name.len() && args.method_name.len() == args.inputs.len(),
            "--contract-id, --method-name, and --inputs must have the same length"
        );
        for (index, contract_id) in args.contract_id.iter().enumerate() {
            let inputs: Vec<u64> = serde_json::from_str(&args.inputs[index])
                .map_err(|error| anyhow::anyhow!("invalid inputs JSON `{}`: {}", args.inputs[index], error))?;
            contract_calls.push(ContractCallArgs {
                contract_id: *contract_id,
                method_name: args.method_name[index].clone(),
                inputs,
            });
        }
    }
    anyhow::ensure!(!contract_calls.is_empty(), "provide --contract-calls-file or --contract-id/--method-name/--inputs");
    let mut data = ContractCallData::new(contract_calls);
    data.software_defined_call.inputs = args.sign_inputs.clone();
    Ok(data)
}

#[derive(clap::Args)]
pub struct PoolCreateArgs {
    #[command(flatten)]
    pub common: BenchmarkCommonArgs,
    /// Number of accounts the pool must contain; missing accounts are created.
    #[arg(long)]
    pub count: u32,
    /// Registration request concurrency.
    #[arg(long, default_value = "8")]
    pub concurrency: usize,
    /// How long to wait for user id confirmation before marking unknown.
    #[arg(long, default_value = "300")]
    pub confirm_timeout_secs: u64,
}

#[derive(clap::Args)]
pub struct RegisterArgs {
    #[command(flatten)]
    pub common: BenchmarkCommonArgs,
    #[arg(long, default_value = "8")]
    pub concurrency: usize,
    #[arg(long, default_value = "300")]
    pub confirm_timeout_secs: u64,
}

#[derive(clap::Args)]
pub struct DeployArgs {
    #[command(flatten)]
    pub common: BenchmarkCommonArgs,
    /// Compiled contract artifact (CompilationArtifact JSON).
    #[arg(long)]
    pub contract_path: PathBuf,
    /// Number of deploy operations.
    #[arg(long)]
    pub count: u32,
    /// Concurrent deploy operations.
    #[arg(long, default_value = "2")]
    pub concurrency: usize,
    /// Seconds to wait for checkpoint inclusion to resolve assigned contract ids.
    #[arg(long, default_value = "600")]
    pub confirm_timeout_secs: u64,
}

#[derive(clap::Args)]
pub struct EndcapArgs {
    #[command(flatten)]
    pub common: BenchmarkCommonArgs,
    /// JSON file with a list of contract calls reused for every operation.
    #[arg(long, conflicts_with = "contract_id")]
    pub contract_calls_file: Option<PathBuf>,
    #[arg(long, action = clap::ArgAction::Append)]
    pub contract_id: Vec<u64>,
    #[arg(long, action = clap::ArgAction::Append)]
    pub method_name: Vec<String>,
    #[arg(long, action = clap::ArgAction::Append)]
    pub inputs: Vec<String>,
    #[arg(long, action = clap::ArgAction::Append)]
    pub sign_inputs: Vec<u64>,
    /// Total number of EndCap operations.
    #[arg(long)]
    pub tx_count: u32,
    /// Concurrent proving operations (one OS thread each).
    #[arg(long, default_value = "1")]
    pub concurrency: usize,
    /// Concurrent checkpoint inclusion queries.
    #[arg(long, default_value = "4")]
    pub confirm_concurrency: usize,
    #[arg(long, default_value = "600")]
    pub confirm_timeout_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn run_bounded_live_respects_limit_and_reports_all() {
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let collected = Arc::new(std::sync::Mutex::new(Vec::new()));
        let jobs: Vec<u32> = (0..10).collect();
        run_bounded_live(
            jobs,
            3,
            {
                let active = active.clone();
                let max_active = max_active.clone();
                move |index, job| {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(5));
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(index + job as usize)
                }
            },
            {
                let collected = collected.clone();
                move |index, event| match event {
                    LiveEvent::Dispatched => true,
                    LiveEvent::Completed(result) => {
                        collected.lock().unwrap().push((index, result));
                        true
                    }
                }
            },
        );
        let results = collected.lock().unwrap();
        assert_eq!(results.len(), 10);
        for (index, result) in results.iter() {
            assert_eq!(*result.as_ref().unwrap(), index * 2);
        }
        assert!(max_active.load(Ordering::SeqCst) <= 3);
    }

    #[test]
    fn run_bounded_live_propagates_errors() {
        let collected = Arc::new(std::sync::Mutex::new(Vec::new()));
        run_bounded_live(
            vec![1u32, 2, 3],
            2,
            |_, job| {
                if job == 2 {
                    anyhow::bail!("boom");
                }
                Ok(job)
            },
            {
                let collected = collected.clone();
                move |index, event| match event {
                    LiveEvent::Dispatched => true,
                    LiveEvent::Completed(result) => {
                        collected.lock().unwrap().push((index, result));
                        true
                    }
                }
            },
        );
        let results: Vec<(usize, bool)> = collected
            .lock()
            .unwrap()
            .iter()
            .map(|(index, result)| (*index, result.is_ok()))
            .collect();
        let mut results = results;
        results.sort_by_key(|(index, _)| *index);
        assert_eq!(results.len(), 3);
        assert!(results[0].1);
        assert!(!results[1].1);
        assert!(results[2].1);
    }

    #[test]
    fn endcap_args_build_contract_call_data() {
        let args = EndcapArgs {
            common: crate::subcommand::benchmark::BenchmarkCommonArgs {
                pool_dir: PathBuf::from("/tmp/pool"),
                rpc_config: "config.json".to_string(),
                wallet_password: None,
                report_file: None,
            },
            contract_calls_file: None,
            contract_id: vec![7],
            method_name: vec!["transfer".to_string()],
            inputs: vec!["[1, 2]".to_string()],
            sign_inputs: vec![9],
            tx_count: 1,
            concurrency: 1,
            confirm_concurrency: 1,
            confirm_timeout_secs: 10,
        };
        let data = build_contract_call_data(&args).unwrap();
        assert_eq!(data.contract_calls.len(), 1);
        assert_eq!(data.contract_calls[0].contract_id, 7);
        assert_eq!(data.contract_calls[0].inputs, vec![1, 2]);
        assert_eq!(data.software_defined_call.inputs, vec![9]);
    }

    #[test]
    fn endcap_args_reject_mismatched_call_lists() {
        let mut args = EndcapArgs {
            common: crate::subcommand::benchmark::BenchmarkCommonArgs {
                pool_dir: PathBuf::from("/tmp/pool"),
                rpc_config: "config.json".to_string(),
                wallet_password: None,
                report_file: None,
            },
            contract_calls_file: None,
            contract_id: vec![7, 8],
            method_name: vec!["transfer".to_string()],
            inputs: vec!["[1]".to_string(), "[2]".to_string()],
            sign_inputs: Vec::new(),
            tx_count: 1,
            concurrency: 1,
            confirm_concurrency: 1,
            confirm_timeout_secs: 10,
        };
        assert!(build_contract_call_data(&args).is_err());
        args.method_name.push("mint".to_string());
        let data = build_contract_call_data(&args).unwrap();
        assert_eq!(data.contract_calls.len(), 2);
    }

    #[test]
    fn run_bounded_live_stops_scheduling_but_drains_in_flight() {
        let executed = Arc::new(AtomicUsize::new(0));
        let collected = Arc::new(std::sync::Mutex::new(Vec::new()));
        let jobs: Vec<u32> = (0..6).collect();
        run_bounded_live(
            jobs,
            2,
            {
                let executed = executed.clone();
                move |_, job| {
                    executed.fetch_add(1, Ordering::SeqCst);
                    Ok(job)
                }
            },
            {
                let collected = collected.clone();
                move |index, event| match event {
                    LiveEvent::Dispatched => true,
                    LiveEvent::Completed(result) => {
                        collected.lock().unwrap().push((index, result));
                        // Stop scheduling after the first result.
                        false
                    }
                }
            },
        );
        // Two jobs were already in flight when the stop arrived: both must
        // run and both results must be reported, and nothing else launches.
        assert_eq!(executed.load(Ordering::SeqCst), 2);
        assert_eq!(collected.lock().unwrap().len(), 2);
    }

    #[test]
    fn bind_deploy_contract_ids_matches_by_deployer_and_code_root() {
        let expected = vec![
            ("deploy-1-0".to_string(), 11u64, "code-a".to_string()),
            ("deploy-1-1".to_string(), 12u64, "code-a".to_string()),
        ];
        // Both ops bound to their own ids despite sharing the artifact: the
        // deployer distinguishes them.
        let onchain = vec![
            (5u64, 11u64, "code-a".to_string()),
            (6u64, 12u64, "code-a".to_string()),
        ];
        let bound = bind_deploy_contract_ids(&expected, &onchain);
        assert_eq!(bound.get("deploy-1-0"), Some(&5));
        assert_eq!(bound.get("deploy-1-1"), Some(&6));

        // A foreign deployment of the same artifact never matches: its
        // deployer differs, so the op stays unbound even when it is the only
        // id assigned.
        let foreign_only = vec![(5u64, 99u64, "code-a".to_string())];
        assert!(bind_deploy_contract_ids(&expected, &foreign_only).is_empty());

        // A different code root is a different contract entirely.
        let other_code = vec![(5u64, 11u64, "code-b".to_string())];
        assert!(bind_deploy_contract_ids(&expected, &other_code).is_empty());

        // Repeated deployments of the same artifact by the same account: each
        // on-chain leaf satisfies at most one op, so a not-yet-included
        // sibling never shadows another op's id.
        let repeated = vec![
            ("deploy-1-0".to_string(), 11u64, "code-a".to_string()),
            ("deploy-1-1".to_string(), 11u64, "code-a".to_string()),
        ];
        let one_leaf = vec![(5u64, 11u64, "code-a".to_string())];
        let bound = bind_deploy_contract_ids(&repeated, &one_leaf);
        assert_eq!(bound.len(), 1);
        assert_eq!(bound.get("deploy-1-0"), Some(&5));

        let two_leaves = vec![
            (5u64, 11u64, "code-a".to_string()),
            (6u64, 11u64, "code-a".to_string()),
        ];
        let bound = bind_deploy_contract_ids(&repeated, &two_leaves);
        assert_eq!(bound.get("deploy-1-0"), Some(&5));
        assert_eq!(bound.get("deploy-1-1"), Some(&6));
    }

    #[test]
    fn triage_separates_traced_open_and_leafless_records() {
        let record = |scenario: &str, status: OpStatus, leaf: Option<&str>, user: Option<u64>| PoolOpRecord {
            op_id: format!("{scenario}-1"),
            scenario: scenario.to_string(),
            account_index: 1,
            tx_hash: None,
            status,
            error: None,
            user_id: user,
            end_user_leaf_hash: leaf.map(str::to_string),
            checkpoint_before: Some(7),
            contract_id: None,
            started_unix_ms: 1,
            finished_unix_ms: None,
        };
        let ops = vec![
            // Traced endcap: interrupted before the submission phase.
            record("endcap", OpStatus::Traced, Some("leaf"), Some(1)),
            // Claim records reconcile exactly like endcap records.
            record("claim", OpStatus::Unknown, Some("leaf"), Some(2)),
            record("claim", OpStatus::Submitted, Some("leaf"), Some(3)),
            // Interrupted before the trace was recorded.
            record("endcap", OpStatus::Unknown, None, Some(4)),
            // Deploy records are not endcap-round records.
            record("deploy", OpStatus::Submitted, None, None),
        ];
        let triage = triage_endcap_round_records(&ops);
        assert_eq!(triage.traced, vec![0]);
        assert_eq!(triage.leafless, vec![3]);
        let open_indices: Vec<usize> = triage.open.iter().map(|(index, _, _, _)| *index).collect();
        assert_eq!(open_indices, vec![1, 2]);
        assert!(triage.open.iter().all(|(_, _, leaf, checkpoint)| leaf == "leaf" && *checkpoint == 7));
    }
}

#[cfg(test)]
mod faucet_tests {
    use super::*;

    #[test]
    fn faucet_response_parses_result_field() {
        let value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tx_hash": "0xabc",
                "operator_user_id": 9,
                "amount": "1000000000000",
                "checkpoint_id": 12,
                "window_id": 3,
                "already_submitted": false,
            }
        });
        let result = value.get("result").cloned().unwrap();
        let parsed: FaucetClaimResponse = serde_json::from_value(result).unwrap();
        assert_eq!(parsed.operator_user_id, 9);
        assert_eq!(parsed.amount, "1000000000000");
    }

    #[test]
    fn faucet_error_field_is_rejected() {
        let value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "turnstile required"}
        });
        assert!(value.get("error").is_some());
        let rendered = serde_json::to_string(&value["error"]).unwrap();
        assert!(rendered.contains("turnstile required"));
    }
}
