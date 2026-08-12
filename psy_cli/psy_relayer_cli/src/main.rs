use std::{fs, path::{Path, PathBuf}, time::Duration};
use std::collections::HashMap;

use anyhow::{anyhow, Context};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionRequest;
use clap::{Parser, Subcommand};
use gnark_plonky2_verifier_ffi as g16;
use parth_core::{felt::ToU64Value, pgoldilocks::QHashOut};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use serde::Deserialize;
use tokio::process::Command;
use tokio_postgres::NoTls;
use url::Url;

mod bridge;

#[derive(Parser)]
#[command(name = "psy_relayer_cli")]
#[command(about = "PSY relayer + bridge tool CLI")]
struct Cli {
    #[arg(long, default_value = "./psy_cli/psy_relayer_cli/config/local.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize keystore (generate or load Groth16 proving/verification keys)
    Initialize { keystore_dir: String },
    /// Export Solidity verifier contract from an initialized keystore.
    ExportSolidityVerifier { keystore_dir: String, out_verifier_sol: String },
    /// Scan L2 withdrawal events and propose them to the withdrawal tree.
    ProposeWithdrawals(bridge::propose_withdrawals::ProposeWithdrawalsArgs),
    /// Prove BridgeAgg + BridgeWrap pipeline.
    ProveBridgeAgg {
        #[arg(long)]
        from_checkpoint: u64,
        #[arg(long)]
        to_checkpoint: u64,
        #[arg(long, default_value = "config.json")]
        rpc_config: String,
        #[arg(long, default_value = bridge::constants::DEFAULT_DEPLOYMENTS_NETWORK)]
        deployments_network: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Call StateManager.finalize with a generated bridge proof JSON.
    FinalizeBridgeAgg(bridge::finalize_bridge::FinalizeBridgeAggArgs),
    /// Submit a proposer-managed batch of finalized withdrawals.
    ClaimWithdrawals(bridge::claim_withdrawals::BatchWithdrawalsArgs),
    /// Compute the Poseidon deposit leaf used by L2 deposit_tree / claim_deposit.
    ComputeDepositLeaf(bridge::compute_deposit_leaf::ComputeDepositLeafArgs),
    /// Regenerate local Groth16 keystore files for bridge wrapper circuits.
    RegenerateGroth16Keystore(bridge::regen_groth16_keystore::RegenerateGroth16KeystoreArgs),
}

#[derive(Debug, Clone, Deserialize)]
struct Cfg {
    poll_interval_secs: u64,
    #[serde(default = "default_source")]
    source: String,
    coordinator_rpc_url: String,
    #[serde(default)]
    l2_relayer_private_key: Option<String>,
    #[serde(default = "default_l2_rpc_config")]
    l2_rpc_config: String,
    #[serde(default = "default_deposit_tree_contract_id")]
    deposit_tree_contract_id: u64,
    indexer: Option<IndexerCfg>,
    chains: Vec<ChainCfg>,
}

#[derive(Debug, Clone, Deserialize)]
struct IndexerCfg {
    database_url: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ChainCfg {
    name: String,
    chain_id: i64,
    rpc_url: String,
    state_manager: Option<String>,
    deployments_network: Option<String>,
}

#[derive(Debug)]
struct DepositRow {
    chain_id: i64,
    deposit_index: i64,
    depositor: String,
    l2_recipient: String,
    token: String,
    l2_token_contract_id: String,
    amount: String,
    nonce: i64,
    chain_index: i64,
    block_number: i64,
    tx_hash: String,
    leaf_hash: String,
}

#[derive(Debug)]
struct FinalizedRow {
    chain_id: i64,
    checkpoint_id: i64,
    deposit_tree_root: String,
    withdrawal_tree_root: String,
    block_number: i64,
    tx_hash: String,
}

const DEPOSIT_RECORDED_TOPIC0: &str =
    "0x59e100f1202f99727a545c60a4db130a4c257764a6cf6dc81ca974855c6eb8eb";

fn contiguous_prefix_len(rows: &[DepositRow], start_index: i64) -> usize {
    let mut expected = start_index;
    let mut n = 0usize;
    for r in rows {
        if r.deposit_index != expected {
            break;
        }
        n += 1;
        expected += 1;
    }
    n
}

fn default_source() -> String {
    "indexer".to_string()
}

fn default_l2_rpc_config() -> String {
    "config.json".to_string()
}

fn default_deposit_tree_contract_id() -> u64 {
    2
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        None => run_bridge_daemon(cli.config).await,
        Some(Commands::Initialize { keystore_dir }) => {
            tracing::info!("Initializing keystore at: {}", keystore_dir);
            g16::initialize(&keystore_dir);
            tracing::info!("Initialization complete");
            Ok(())
        }
        Some(Commands::ExportSolidityVerifier { keystore_dir, out_verifier_sol }) => {
            if keystore_dir.is_empty() {
                anyhow::bail!("keystore_dir cannot be empty");
            }
            let sol = g16::export_solidity_verifier(&keystore_dir);
            if sol.trim_start().starts_with("error:") {
                anyhow::bail!("export solidity verifier failed for {}: {}", keystore_dir, sol.trim());
            }
            if let Some(parent) = Path::new(&out_verifier_sol).parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("failed to create dir: {:?}", parent))?;
                }
            }
            fs::write(&out_verifier_sol, &sol)
                .with_context(|| format!("failed to write verifier: {}", out_verifier_sol))?;
            println!("exported solidity verifier: {}", out_verifier_sol);
            Ok(())
        }
        Some(Commands::ProposeWithdrawals(args)) => bridge::propose_withdrawals::run(args).await,
        Some(Commands::ProveBridgeAgg {
            from_checkpoint,
            to_checkpoint,
            rpc_config,
            deployments_network,
            out,
        }) => {
            bridge::prove_bridge::run_prove_bridge_agg_with_result(
                from_checkpoint,
                to_checkpoint,
                rpc_config,
                out,
                deployments_network,
            )
            .await
            .map(|_| ())
        }
        Some(Commands::FinalizeBridgeAgg(args)) => bridge::finalize_bridge::run(args).await,
        Some(Commands::ClaimWithdrawals(args)) => bridge::claim_withdrawals::run(args).await,
        Some(Commands::ComputeDepositLeaf(args)) => bridge::compute_deposit_leaf::run(args),
        Some(Commands::RegenerateGroth16Keystore(args)) => bridge::regen_groth16_keystore::run(args),
    }
}

async fn run_bridge_daemon(config: PathBuf) -> anyhow::Result<()> {
    if !config.exists() {
        anyhow::bail!(
            "bridge-daemon config not found: {}",
            config.display()
        );
    }

    tracing::info!(
        config = %config.display(),
        "starting bridge-daemon in-process"
    );
    bridge::daemon::run(bridge::daemon::RunDaemonArgs { config }).await
}

async fn run_indexer(cfg: Cfg) -> anyhow::Result<()> {
    let indexer = cfg
        .indexer
        .as_ref()
        .ok_or_else(|| anyhow!("indexer config is required when source=indexer"))?;

    let (db, conn) = connect_indexer_db_with_retry(&indexer.database_url).await?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::error!(error=%err, "postgres connection task exited");
        }
    });
    wait_envio_tables_ready(&db).await?;
    let mut last_submitted_by_chain: HashMap<i64, i64> = HashMap::new();

    loop {
        for chain in &cfg.chains {
            // Bridge exposes the proved deposit count, while indexer rows use 0-based deposit_index.
            // Convert that count to the last proved index for an exclusive "after" window.
            let proved_count = get_proved_deposit_count(chain).await?;
            let last_proved_index = proved_count.saturating_sub(1);
            let after = last_proved_index
                .max(*last_submitted_by_chain.get(&chain.chain_id).unwrap_or(&-1))
                ;
            let deposits = get_new_deposits(chain, after).await?;
            let expected_next = after + 1;
            let relay_count = contiguous_prefix_len(&deposits, expected_next);
            if relay_count < deposits.len() {
                let observed = deposits
                    .get(relay_count)
                    .map(|d| d.deposit_index)
                    .unwrap_or(expected_next);
                tracing::warn!(
                    chain = %chain.name,
                    chain_id = chain.chain_id,
                    expected_next_deposit_index = expected_next + relay_count as i64,
                    observed_deposit_index = observed,
                    "deposit index gap detected; pause relay to preserve strict append order"
                );
            }

            for d in deposits.iter().take(relay_count) {
                tracing::info!(
                    chain=%chain.name,
                    chain_id=d.chain_id,
                    deposit_index=d.deposit_index,
                    depositor=%d.depositor,
                    l2_recipient=%d.l2_recipient,
                    token=%d.token,
                    amount=%d.amount,
                    block_number=d.block_number,
                    tx_hash=%d.tx_hash,
                    "indexer deposit"
                );
                match relay_deposit_to_l2(&cfg, d).await {
                    Ok(()) => {
                        last_submitted_by_chain.insert(chain.chain_id, d.deposit_index);
                    }
                    Err(err) => {
                        // Preserve strict ordering: stop current chain loop and retry from same index later.
                        tracing::error!(
                            chain = %chain.name,
                            chain_id = d.chain_id,
                            deposit_index = d.deposit_index,
                            error = %err,
                            "append_deposit failed; stop current cycle and retry later"
                        );
                        break;
                    }
                }
            }
            tracing::info!(
                chain=%chain.name,
                chain_id=chain.chain_id,
                proved_count,
                last_proved_index,
                fetched_deposits=deposits.len(),
                "indexer deposit sync window"
            );

            if let Some(f) = get_latest_finalized(&db, chain.chain_id).await? {
                tracing::info!(
                    chain=%chain.name,
                    chain_id=f.chain_id,
                    checkpoint_id=f.checkpoint_id,
                    deposit_tree_root=%f.deposit_tree_root,
                    withdrawal_tree_root=%f.withdrawal_tree_root,
                    block_number=f.block_number,
                    tx_hash=%f.tx_hash,
                    "indexer latest finalized"
                );

                tracing::info!(
                    chain=%chain.name,
                    chain_id=chain.chain_id,
                    finalized_deposit_tree_root=%normalize_hex32(&f.deposit_tree_root)?,
                    "latest finalized batch observed"
                );
            }
        }

        tokio::time::sleep(Duration::from_secs(cfg.poll_interval_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{contiguous_prefix_len, DepositRow};

    fn row(i: i64) -> DepositRow {
        DepositRow {
            chain_id: 31337,
            deposit_index: i,
            depositor: String::new(),
            l2_recipient: String::new(),
            token: String::new(),
            l2_token_contract_id: String::new(),
            amount: String::new(),
            nonce: 0,
            chain_index: 0,
            block_number: 0,
            tx_hash: String::new(),
            leaf_hash: String::new(),
        }
    }

    #[test]
    fn contiguous_prefix_empty() {
        let rows: Vec<DepositRow> = vec![];
        assert_eq!(contiguous_prefix_len(&rows, 5), 0);
    }

    #[test]
    fn contiguous_prefix_full_match() {
        let rows = vec![row(7), row(8), row(9)];
        assert_eq!(contiguous_prefix_len(&rows, 7), 3);
    }

    #[test]
    fn contiguous_prefix_stops_at_gap() {
        let rows = vec![row(7), row(9), row(10)];
        assert_eq!(contiguous_prefix_len(&rows, 7), 1);
    }

    #[test]
    fn contiguous_prefix_first_mismatch() {
        let rows = vec![row(11), row(12)];
        assert_eq!(contiguous_prefix_len(&rows, 7), 0);
    }
}

async fn get_l2_deposit_tree_next_index(cfg: &Cfg) -> anyhow::Result<i64> {
    let latest = Command::new("./target/release/psy_user_cli")
        .arg("get-latest-block-state")
        .arg("--rpc-config")
        .arg(&cfg.l2_rpc_config)
        .env("RUST_LOG", "error")
        .output()
        .await
        .context("spawn psy_user_cli get-latest-block-state failed")?;
    if !latest.status.success() {
        anyhow::bail!(
            "get-latest-block-state failed. stdout={} stderr={}",
            String::from_utf8_lossy(&latest.stdout),
            String::from_utf8_lossy(&latest.stderr)
        );
    }
    let latest_json: serde_json::Value =
        serde_json::from_slice(&latest.stdout).context("parse latest block state json failed")?;
    let checkpoint_id = latest_json
        .get("checkpoint_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("missing checkpoint_id in latest block state"))?;

    let next_index_slot = Command::new("./target/release/psy_user_cli")
        .arg("get-user-contract-state-tree-leaf-hash")
        .arg("--rpc-config")
        .arg(&cfg.l2_rpc_config)
        .arg("--checkpoint-id")
        .arg(checkpoint_id.to_string())
        .arg("--user-id")
        .arg("524288")
        .arg("--contract-id")
        .arg(cfg.deposit_tree_contract_id.to_string())
        .arg("--leaf-id")
        .arg("2")
        .env("RUST_LOG", "error")
        .output()
        .await
        .context("spawn psy_user_cli get-user-contract-state-tree-leaf-hash failed")?;
    if !next_index_slot.status.success() {
        anyhow::bail!(
            "get-user-contract-state-tree-leaf-hash failed. stdout={} stderr={}",
            String::from_utf8_lossy(&next_index_slot.stdout),
            String::from_utf8_lossy(&next_index_slot.stderr)
        );
    }

    let raw = String::from_utf8(next_index_slot.stdout).context("next_index slot stdout is not utf8")?;
    let line = raw
        .lines()
        .rev()
        .map(|s| s.trim())
        .find(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("empty output from get-user-contract-state-tree-leaf-hash"))?;
    let hex = line.trim_matches('"').trim_start_matches("0x");
    if hex.len() != 64 {
        anyhow::bail!("unexpected next_index slot hex length: {}", hex.len());
    }
    // root occupies slots 0 and 1; slot 2 stores next_index in the low 32 bits.
    let last_u64_hex = &hex[48..64];
    let last_u64 = u64::from_str_radix(last_u64_hex, 16).context("parse next_index slot last u64 failed")?;
    Ok((last_u64 & 0xffff_ffff) as i64)
}

async fn connect_indexer_db_with_retry(
    database_url: &str,
) -> anyhow::Result<(tokio_postgres::Client, tokio_postgres::Connection<tokio_postgres::Socket, tokio_postgres::tls::NoTlsStream>)> {
    let mut attempt: u64 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        match tokio_postgres::connect(database_url, NoTls).await {
            Ok(conn) => {
                tracing::info!(attempt, "connected to indexer postgres");
                return Ok(conn);
            }
            Err(err) => {
                tracing::warn!(
                    attempt,
                    error = %err,
                    "connect indexer postgres failed; retrying in 2s"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn wait_envio_tables_ready(db: &tokio_postgres::Client) -> anyhow::Result<()> {
    let mut attempt: u64 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        match ensure_envio_tables(db).await {
            Ok(()) => {
                tracing::info!(attempt, "envio schema is ready");
                return Ok(());
            }
            Err(err) => {
                tracing::warn!(
                    attempt,
                    error = %err,
                    "envio schema not ready; waiting for indexer bootstrap (retrying in 2s)"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

fn normalize_hex32(s: &str) -> anyhow::Result<String> {
    let v = parse_b256(s, "deposit_tree_root")?;
    Ok(hex::encode(v.as_slice()))
}

fn parse_b256(s: &str, field: &str) -> anyhow::Result<B256> {
    s.parse::<B256>()
        .with_context(|| format!("invalid bytes32 for {}: {}", field, s))
}

async fn ensure_envio_tables(db: &tokio_postgres::Client) -> anyhow::Result<()> {
    let rows = db
        .query(
            "SELECT table_name
             FROM information_schema.tables
             WHERE table_schema = 'public'
               AND table_name IN ('deposits', 'finalized_batches', 'Deposit', 'FinalizedBatch')",
            &[],
        )
        .await
        .context("query information_schema failed")?;
    let mut has_deposits_legacy = false;
    let mut has_finalized_legacy = false;
    let mut has_deposit_envio = false;
    let mut has_finalized_envio = false;
    for row in rows {
        let t: String = row.get(0);
        if t == "deposits" {
            has_deposits_legacy = true;
        } else if t == "finalized_batches" {
            has_finalized_legacy = true;
        } else if t == "Deposit" {
            has_deposit_envio = true;
        } else if t == "FinalizedBatch" {
            has_finalized_envio = true;
        }
    }
    let has_deposits = has_deposits_legacy || has_deposit_envio;
    let has_finalized = has_finalized_legacy || has_finalized_envio;
    if !has_deposits || !has_finalized {
        anyhow::bail!(
            "Envio schema not ready in PostgreSQL (need tables: deposits, finalized_batches). \
             Please run Envio indexer first."
        );
    }
    Ok(())
}

async fn get_new_deposits(chain: &ChainCfg, consumed_index: i64) -> anyhow::Result<Vec<DepositRow>> {
    #[derive(Deserialize)]
    struct EthLog {
        topics: Vec<String>,
        data: String,
        #[serde(rename = "blockNumber")]
        block_number: String,
        #[serde(rename = "transactionHash")]
        tx_hash: String,
    }

    #[derive(Deserialize)]
    struct JsonRpcResponse {
        result: Vec<EthLog>,
    }

    let bridge_address = resolve_bridge_address(chain)?;
    let rpc = bridge::api_client::build_default_http_client()?;
    tracing::info!(
        target: "psy_rpc_meter",
        source = "relayer.indexer",
        method = "eth_getLogs",
        chain = %chain.name,
        chain_id = chain.chain_id,
        bridge = %bridge_address,
        after_deposit_index = consumed_index,
        from_block = "0x0",
        to_block = "latest",
        "l1 rpc request"
    );
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getLogs",
        "params": [{
            "fromBlock": "0x0",
            "toBlock": "latest",
            "address": bridge_address.to_string(),
            "topics": [DEPOSIT_RECORDED_TOPIC0],
        }],
    });
    let response: JsonRpcResponse = rpc
        .post(chain.rpc_url.as_str())
        .json(&body)
        .send()
        .await
        .with_context(|| format!("eth_getLogs request failed for chain {}", chain.name))?
        .error_for_status()
        .with_context(|| format!("eth_getLogs returned error status for chain {}", chain.name))?
        .json()
        .await
        .with_context(|| format!("decode eth_getLogs response failed for chain {}", chain.name))?;

    let mut deposits = Vec::new();
    for log in response.result {
        if log.topics.len() < 4 {
            continue;
        }
        let words = split_event_data_words(&log.data)?;
        if words.len() < 7 {
            continue;
        }

        let deposit_index = bytes32_hex_to_i64(&log.topics[1])?;
        if deposit_index <= consumed_index {
            continue;
        }

        deposits.push(DepositRow {
            chain_id: chain.chain_id,
            deposit_index,
            depositor: bytes32_hex_to_address(&log.topics[2])?,
            l2_recipient: normalize_bytes32_hex(&words[2])?,
            token: bytes32_hex_to_address(&log.topics[3])?,
            l2_token_contract_id: normalize_bytes32_hex(&words[0])?,
            amount: bytes32_hex_to_u256_decimal(&words[1])?,
            nonce: bytes32_hex_to_i64(&words[3])?,
            chain_index: bytes32_hex_to_i64(&words[4])?,
            block_number: hex_quantity_to_i64(&log.block_number)?,
            tx_hash: log.tx_hash,
            leaf_hash: normalize_bytes32_hex(&words[5])?,
        });
    }

    deposits.sort_by_key(|row| row.deposit_index);
    Ok(deposits)
}

fn split_event_data_words(data: &str) -> anyhow::Result<Vec<String>> {
    let body = data.strip_prefix("0x").unwrap_or(data);
    anyhow::ensure!(body.len() % 64 == 0, "invalid event data length: {}", body.len());
    Ok((0..body.len())
        .step_by(64)
        .map(|offset| format!("0x{}", &body[offset..offset + 64]))
        .collect())
}

fn normalize_bytes32_hex(value: &str) -> anyhow::Result<String> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    anyhow::ensure!(raw.len() == 64, "expected bytes32 hex, got {} chars", raw.len());
    Ok(format!("0x{}", raw.to_lowercase()))
}

fn bytes32_hex_to_address(value: &str) -> anyhow::Result<String> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    anyhow::ensure!(raw.len() == 64, "expected bytes32 topic, got {} chars", raw.len());
    Ok(format!("0x{}", raw[24..].to_lowercase()))
}

fn bytes32_hex_to_i64(value: &str) -> anyhow::Result<i64> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    anyhow::ensure!(raw.len() == 64, "expected bytes32 hex, got {} chars", raw.len());
    let v = U256::from_str_radix(raw, 16)
        .with_context(|| format!("invalid bytes32 hex quantity: {value}"))?;
    let max = U256::from(i64::MAX as u64);
    anyhow::ensure!(v <= max, "value out of i64 range: {value}");
    Ok(v.to::<u64>() as i64)
}

fn bytes32_hex_to_u256_decimal(value: &str) -> anyhow::Result<String> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    anyhow::ensure!(raw.len() == 64, "expected bytes32 hex, got {} chars", raw.len());
    let v = U256::from_str_radix(raw, 16)
        .with_context(|| format!("invalid bytes32 hex quantity: {value}"))?;
    Ok(v.to_string())
}

fn hex_quantity_to_i64(value: &str) -> anyhow::Result<i64> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let v = i64::from_str_radix(raw, 16)
        .with_context(|| format!("invalid hex quantity: {value}"))?;
    Ok(v)
}

fn parse_hash_hex_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    anyhow::ensure!(bytes.len() == 32, "hash hex must be 32 bytes, got {}", bytes.len());
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    Ok(words)
}

async fn relay_deposit_to_l2(cfg: &Cfg, d: &DepositRow) -> anyhow::Result<()> {
    let leaf = compute_poseidon_deposit_leaf(d)
        .with_context(|| format!("compute poseidon leaf failed for deposit_index={}", d.deposit_index))?;
    let mut inputs = Vec::with_capacity(9);
    inputs.push(d.chain_index as u64);
    inputs.extend(leaf.iter().map(|v| *v as u64));
    let inputs_json = serde_json::to_string(&inputs).context("serialize append_deposit inputs failed")?;

    let output = Command::new("./target/release/psy_user_cli")
        .arg("call")
        .arg("--rpc-config")
        .arg(&cfg.l2_rpc_config)
        .arg("--contract-id")
        .arg(cfg.deposit_tree_contract_id.to_string())
        .arg("--method-name")
        .arg("append_deposit")
        .arg("--inputs")
        .arg(inputs_json)
        .args(
            cfg.l2_relayer_private_key
                .as_ref()
                .map(|pk| vec!["-p".to_string(), pk.clone()])
                .unwrap_or_default(),
        )
        .output()
        .await
        .context("spawn psy_user_cli call failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "relay append_deposit failed for deposit_index={} chain_index={}. stdout={} stderr={}",
            d.deposit_index,
            d.chain_index,
            stdout,
            stderr
        );
    }

    tracing::info!(
        chain_id = d.chain_id,
        deposit_index = d.deposit_index,
        chain_index = d.chain_index,
        contract_id = cfg.deposit_tree_contract_id,
        "relayed deposit to L2 deposit tree contract"
    );
    Ok(())
}

fn compute_poseidon_deposit_leaf(d: &DepositRow) -> anyhow::Result<[u32; 8]> {
    let depositor = parse_address_to_u32x8(&d.depositor)
        .with_context(|| format!("invalid depositor: {}", d.depositor))?;
    let l2_recipient = parse_bytes32_to_u32x8(&d.l2_recipient)
        .with_context(|| format!("invalid l2_recipient: {}", d.l2_recipient))?;
    let token = parse_address_to_u32x8(&d.token)
        .with_context(|| format!("invalid token: {}", d.token))?;
    let l2_token_contract_id = parse_bytes32_to_u32x8(&d.l2_token_contract_id)
        .with_context(|| format!("invalid l2_token_contract_id: {}", d.l2_token_contract_id))?;
    let amount = parse_u256_decimal_to_u32x8(&d.amount)
        .with_context(|| format!("invalid amount: {}", d.amount))?;
    let chain_index = u32::try_from(d.chain_index)
        .with_context(|| format!("chain_index out of range: {}", d.chain_index))?;
    let nonce = u32::try_from(d.nonce)
        .with_context(|| format!("nonce out of range: {}", d.nonce))?;

    let words = [
        depositor.as_slice(),
        l2_recipient.as_slice(),
        token.as_slice(),
        l2_token_contract_id.as_slice(),
        amount.as_slice(),
    ]
    .into_iter()
    .flatten()
    .copied()
    .chain([chain_index, nonce])
    .collect::<Vec<_>>();

    Ok(qhashout_to_u32x8_internal(poseidon_hash_u32_words(
        words.into_iter().map(u64::from),
    )))
}

fn poseidon_hash_u32_words(words: impl IntoIterator<Item = u64>) -> QHashOut<GoldilocksField> {
    let felts = words
        .into_iter()
        .map(GoldilocksField::from_canonical_u64)
        .collect::<Vec<_>>();
    QHashOut(PoseidonHash::hash_no_pad(&felts))
}

fn qhashout_to_u32x8_internal(hash: QHashOut<GoldilocksField>) -> [u32; 8] {
    let elems = hash.0.elements;
    [
        (elems[0].to_u64_value() & 0xffff_ffff) as u32,
        (elems[0].to_u64_value() >> 32) as u32,
        (elems[1].to_u64_value() & 0xffff_ffff) as u32,
        (elems[1].to_u64_value() >> 32) as u32,
        (elems[2].to_u64_value() & 0xffff_ffff) as u32,
        (elems[2].to_u64_value() >> 32) as u32,
        (elems[3].to_u64_value() & 0xffff_ffff) as u32,
        (elems[3].to_u64_value() >> 32) as u32,
    ]
}

fn parse_bytes32_to_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    parse_hash_hex_u32x8(hex_str)
}

fn parse_address_to_u32x8(addr: &str) -> anyhow::Result<[u32; 8]> {
    let address: Address = addr.parse()?;
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    parse_bytes32_to_u32x8(&format!("0x{}", hex::encode(bytes)))
}

fn parse_u256_decimal_to_u32x8(s: &str) -> anyhow::Result<[u32; 8]> {
    let value = U256::from_str_radix(s, 10)?;
    let bytes = value.to_be_bytes::<32>();
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    Ok(words)
}

async fn get_proved_deposit_count(chain: &ChainCfg) -> anyhow::Result<i64> {
    let rpc_url = Url::parse(&chain.rpc_url)
        .with_context(|| format!("invalid chain rpc url: {}", chain.rpc_url))?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let to = resolve_bridge_address(chain)?;
    let selector = selector_for("provedDepositCount()");
    let selector_bytes = hex::decode(selector.strip_prefix("0x").unwrap_or(&selector))
        .context("decode selector bytes failed")?;
    let call_data = Bytes::from(selector_bytes);
    let tx = TransactionRequest::default().to(to).input(call_data.into());
    tracing::debug!(
        target: "psy_rpc_meter",
        source = "relayer.indexer",
        method = "eth_call",
        chain = %chain.name,
        chain_id = chain.chain_id,
        bridge = %to,
        contract_method = "provedDepositCount",
        selector = %selector,
        "l1 rpc request"
    );
    let raw = provider
        .call(tx)
        .await
        .with_context(|| format!("alloy eth_call failed: {}", chain.rpc_url))?;
    let n = parse_u256_bytes_to_i64(raw.as_ref())
        .context("decode provedDepositCount return bytes failed")?;
    Ok(n)
}

fn resolve_state_manager_address(chain: &ChainCfg) -> anyhow::Result<Address> {
    if let Some(addr) = chain.state_manager.as_deref() {
        let trimmed = addr.trim();
        if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("auto") {
            return trimmed
                .parse::<Address>()
                .with_context(|| format!("invalid state_manager address: {}", trimmed));
        }
    }

    let network = chain.deployments_network.as_deref().unwrap_or("localhost");
    if let Ok(addr) = bridge::api_client::resolve_contract_address_from_deployments(network, "StateManager") {
        return Ok(addr);
    }

    #[derive(Deserialize)]
    struct DeploymentArtifact {
        address: String,
    }
    let artifact_path =
        bridge::api_client::resolve_deployments_file(network, "StateManager_Proxy.json");
    let raw = fs::read_to_string(&artifact_path)
        .with_context(|| format!("read deployment artifact failed: {}", artifact_path.display()))?;
    let artifact: DeploymentArtifact = serde_json::from_str(&raw)
        .with_context(|| format!("parse deployment artifact failed: {}", artifact_path.display()))?;
    artifact.address.trim().parse::<Address>().with_context(|| {
        format!(
            "invalid state_manager address in {}: {}",
            artifact_path.display(), artifact.address
        )
    })
}

fn resolve_bridge_address(chain: &ChainCfg) -> anyhow::Result<Address> {
    let network = chain.deployments_network.as_deref().unwrap_or("localhost");
    if let Ok(addr) = bridge::api_client::resolve_contract_address_from_deployments(network, "Bridge") {
        return Ok(addr);
    }

    #[derive(Deserialize)]
    struct DeploymentArtifact {
        address: String,
    }
    let artifact_path = bridge::api_client::resolve_deployments_file(network, "Bridge_Proxy.json");
    let raw = fs::read_to_string(&artifact_path)
        .with_context(|| format!("read deployment artifact failed: {}", artifact_path.display()))?;
    let artifact: DeploymentArtifact = serde_json::from_str(&raw)
        .with_context(|| format!("parse deployment artifact failed: {}", artifact_path.display()))?;
    artifact.address.trim().parse::<Address>().with_context(|| {
        format!(
            "invalid bridge address in {}: {}",
            artifact_path.display(), artifact.address
        )
    })
}

fn selector_for(sig: &str) -> String {
    use tiny_keccak::{Hasher, Keccak};
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(sig.as_bytes());
    hasher.finalize(&mut out);
    format!("0x{}", hex::encode(&out[..4]))
}

fn parse_u256_bytes_to_i64(raw: &[u8]) -> anyhow::Result<i64> {
    if raw.is_empty() {
        return Ok(0);
    }
    let v = U256::from_be_slice(raw);
    let max = U256::from(i64::MAX as u64);
    if v > max {
        anyhow::bail!("value does not fit into i64: {}", v);
    }
    Ok(v.to::<u64>() as i64)
}

async fn get_latest_finalized(
    db: &tokio_postgres::Client,
    chain_id: i64,
) -> anyhow::Result<Option<FinalizedRow>> {
    let chain_id_i32 = i32::try_from(chain_id)
        .with_context(|| format!("chain_id out of int4 range: {}", chain_id))?;
    let row = db
        .query_opt(
            "SELECT chain_id, finalized_checkpoint_id::bigint, deposit_tree_root, withdrawal_tree_root, block_number, tx_hash
             FROM \"FinalizedBatch\"
             WHERE chain_id = $1
             ORDER BY finalized_checkpoint_id DESC
             LIMIT 1",
            &[&chain_id_i32],
        )
        .await
        .context("query finalized_batches failed")?;

    Ok(row.map(|r| FinalizedRow {
        chain_id: i64::from(r.get::<usize, i32>(0)),
        checkpoint_id: r.get(1),
        deposit_tree_root: r.get(2),
        withdrawal_tree_root: r.get(3),
        block_number: i64::from(r.get::<usize, i32>(4)),
        tx_hash: r.get(5),
    }))
}
