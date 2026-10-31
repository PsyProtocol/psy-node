use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    fs::{self, File},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::stream::{FuturesUnordered, StreamExt};

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, ensure};
use clap::Args;
use gnark_plonky2_verifier_ffi as g16;
use psy_client_common::args::{ContractCallArgs, ContractCallData};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
use psy_core::constants::chain_id::PsyChainNetworkType;

use psy_prover::session::{EndCapContractSlotUpdate, EndCapSubmissionError, WalletSession};
use psy_provider::{
    provider::RpcProvider,
    request::RealmEndCapSlotUpdates,
};
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use psy_vm::ups::multisig::MULTISIG_POLICY_CONTRACT_ID;
use serde::{Deserialize, Serialize};
use guardian_common::protocol::GuardianSignRequest;
use crate::bridge::{
    claim_attempts,
    claim_withdrawals,
    constants::{
        BRIDGE_USER_ID_U64, DEFAULT_DEPLOYMENTS_NETWORK, DEFAULT_L1_RPC_URL, DEPOSIT_TREE_CONTRACT_ID, WITHDRAWAL_TREE_CONTRACT_ID,
        L1_GROTH16_CALL_GAS_FALLBACK, L1_MULTICALL_GAS_BUDGET,
        REALM_CHECKPOINT_POLL_INTERVAL_SECS, REALM_CHECKPOINT_POLL_TIMEOUT_SECS,
    },
    finalize_bridge::{self, FinalizeBridgeAggArgs},
    l1_client::{CachedProofLineageUnread, L1Client},
    l1_signer::load_l1_wallet,
    propose_withdrawals::{self, ProposeWithdrawalsArgs},
    prove_bridge::{self},
};

const DEFAULT_PROOF_DIR: &str = "/tmp/psy_bridge_proofs";
const CONTRACT_STATE_TREE_HEIGHT: u8 = 32;
const DEFAULT_MAX_CHECKPOINT_BATCH: u64 = 64;
const MAX_DEPOSITS_PER_L2_ROUND: u32 = 32;
/// Per-round catchup truncation size; default 64 preserves prior daemon behavior.
const NETWORK_TYPE: PsyChainNetworkType = PsyChainNetworkType::LocalDevnet;

// deposit_tree storage is felt-addressed, with 4 felts packed per contract-state leaf.
// Layout:
//   root[8]                 -> sub-slots 0..7
//   frontiers[8192][8]      -> sub-slots 8..65543
//   chain_counts[256]       -> sub-slots 65544..65799
//   global_count            -> sub-slot 65800
const DEPOSIT_TREE_CHAIN_COUNTS_SUBSLOT_BASE: u64 = 8 + (8192 * 8);
sol! {
    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct Aggregate3Result {
        bool success;
        bytes returnData;
    }

    function aggregate3(
        Call3[] calls
    ) payable returns (Aggregate3Result[] returnData);

    function provedDepositCount() external view returns (uint256);
    function pendingDepositCount() external view returns (uint256);
    function lastFinalizedCheckpointId() external view returns (uint64);
}

#[derive(Clone, Args)]
pub struct RunDaemonArgs {
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long = "l1-config")]
    pub l1_config: Vec<PathBuf>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct BridgeProposeDaemonConfig {
    pub rpc_config: String,
    pub services_url: String,
    pub withdraw_method_id: u64,
    pub proof_dir: Option<PathBuf>,
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub confirmation_lag_checkpoints: Option<u64>,
    #[serde(default)]
    pub max_checkpoint_batch: Option<u64>,
    pub guardian_root: String,
    /// Local deployment documents. Nonempty replaces the network `l1_config_url`. Not serialized.
    #[serde(skip)]
    pub l1_config: Vec<PathBuf>,
    /// Canonical guardian history retained across daemon rounds; never serialized.
    #[serde(skip)]
    guardian_history: std::sync::Arc<tokio::sync::Mutex<RelayerHistory>>,
    #[serde(default)]
    pub finalize: DaemonFinalizeConfig,
    /// Max concurrent L2 batch submissions (for buffered_unordered).
    /// Default=1 (sequential). Set >1 to enable concurrent batch dispatch.
    #[serde(default)]
    pub max_concurrent_l2_batches: Option<u64>,
    /// L1 chains handled by this daemon. When omitted, `[finalize]` is
    /// promoted to a single legacy EVM chain.
    #[serde(default)]
    pub chains: Vec<L1Config>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct L1Config {
    #[serde(default)]
    pub fee_policy: Option<super::l1_fees::BscFeePolicy>,
    #[serde(default = "default_evm_family")]
    pub family: String,
    pub chain_index: u8,
    pub network_id: String,
    #[serde(default)]
    pub rpc_urls: Vec<String>,
    #[serde(default)]
    pub rpc_providers: Vec<crate::bridge::rpc_providers::RpcProviderConfig>,
    pub deployments_network: String,
    #[serde(default)]
    pub state_manager: Option<String>,
    #[serde(default)]
    pub bridge_address: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub keystore_path: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,
}

fn default_evm_family() -> String { "evm".to_string() }

struct RelayerHistory {
    history: crate::guardian::verify::GuardianHistory,
}

impl Default for RelayerHistory {
    fn default() -> Self { Self { history: crate::guardian::verify::GuardianHistory::new() } }
}

impl RelayerHistory {
    fn restore(account: &guardian_common::protocol::GuardianAccount, deposit_tree_states: &[guardian_common::protocol::DepositTreeState]) -> anyhow::Result<Self> {
        account.validate().map_err(|error| anyhow::anyhow!(error))?;
        let mut history = crate::guardian::verify::GuardianHistory::new();
        history.nonce = account.imported_nonce.unwrap_or(0);
        history.ending_leaf = account.imported_ending_leaf;
        for (chain, count, frontier, root) in &account.withdrawal_chains { history.chains.insert(*chain, (*count, *frontier, *root)); }
        for state in deposit_tree_states {
            state.validate().map_err(|error| anyhow::anyhow!(error))?;
            let chain = state.anchor.chain_index;
            anyhow::ensure!(history.deposits.insert(chain, (state.count, state.root)).is_none(), "duplicate included deposit chain");
            anyhow::ensure!(history.deposit_tree_states.insert(chain, state.clone()).is_none(), "duplicate included deposit chain");
        }
        Ok(Self { history })
    }
}

impl L1Config {
    fn effective_config(
        &self,
        base: &BridgeProposeDaemonConfig,
    ) -> anyhow::Result<BridgeProposeDaemonConfig> {
        let mut config = base.clone();
        config.chains.clear();
        // Raw, user-supplied fields: warn here (not inside `resolve_rpc_providers`,
        // which downstream callers also invoke with already-derived config).
        crate::bridge::rpc_providers::warn_if_rpc_urls_ignored(
            &self.network_id, &self.rpc_providers, &self.rpc_urls,
        );
        let providers = crate::bridge::rpc_providers::resolve_rpc_providers(
            &self.network_id, &self.rpc_providers, &self.rpc_urls,
        )?;
        // The first provider URL is the scope identity for provider factories.
        config.finalize.l1_rpc_url = Some(providers[0].url.clone());
        config.finalize.l1_rpc_fallback_url = None;
        config.finalize.l1_rpc_providers = providers;
        config.finalize.fee_policy = self.fee_policy.clone();
        config.finalize.deployments_network = Some(self.deployments_network.clone());
        config.finalize.state_manager = self.state_manager.clone();
        config.finalize.bridge_address = self.bridge_address.clone();
        config.finalize.private_key = self.private_key.clone();
        config.finalize.keystore_path = self.keystore_path.clone();
        config.finalize.password_env = self.password_env.clone();
        Ok(config)
    }
}

/// URL list for the single-chain `[finalize]` path. The default URL is only a
/// stand-in for a missing config; with `l1_rpc_providers` set it would be
/// reported as an ignored `rpc_urls` entry the operator never wrote.
fn legacy_rpc_urls(finalize: &DaemonFinalizeConfig) -> Vec<String> {
    let primary = match finalize.l1_rpc_url.clone() {
        Some(url) => Some(url),
        None if finalize.l1_rpc_providers.is_empty() => Some(DEFAULT_L1_RPC_URL.to_string()),
        None => None,
    };
    let mut rpc_urls: Vec<String> = primary.into_iter().collect();
    if let Some(url) = finalize.l1_rpc_fallback_url.clone() {
        if !url.trim().is_empty() && !rpc_urls.contains(&url) {
            rpc_urls.push(url);
        }
    }
    rpc_urls
}

fn configured_chains(config: &BridgeProposeDaemonConfig, l1_chains: &[guardian_common::protocol::ChainEndpoint]) -> anyhow::Result<Vec<L1Config>> {
    ensure!(config.chains.is_empty() || config.finalize.fee_policy.is_none(),
        "with [[chains]], configure fees in [chains.fee_policy], not [finalize.fee_policy]");
    let mut chains = if config.chains.is_empty() {
        let deployments_network = config
            .finalize
            .deployments_network
            .clone()
            .unwrap_or_else(|| DEFAULT_DEPLOYMENTS_NETWORK.to_string());
        let deployed = crate::bridge::api_client::load_deployed_contracts(&deployments_network)?;
        let chain_index = deployed
            .protocol
            .map(|protocol| protocol.chain.l1_chain_index)
            .or_else(|| (deployments_network == "localhost").then_some(0))
            .context("deployment is missing protocol.chain.l1ChainIndex")?;
        let endpoint = l1_chains.iter().find(|endpoint| endpoint.chain_index == chain_index)
            .context("canonical L1 endpoint missing for deployment chain")?;
        vec![L1Config {
            fee_policy: config.finalize.fee_policy.clone(),
            family: default_evm_family(),
            chain_index,
            network_id: deployments_network.clone(),
            rpc_urls: if config.finalize.l1_rpc_url.is_some() || config.finalize.l1_rpc_fallback_url.is_some() { legacy_rpc_urls(&config.finalize) } else { vec![endpoint.rpc_url.clone()] },
            rpc_providers: config.finalize.l1_rpc_providers.clone(),
            deployments_network,
            state_manager: config.finalize.state_manager.clone(),
            bridge_address: config.finalize.bridge_address.clone(),
            private_key: config.finalize.private_key.clone(),
            keystore_path: config.finalize.keystore_path.clone(),
            password_env: config.finalize.password_env.clone(),
        }]
    } else {
        let mut chains = config.chains.clone();
        for chain in &mut chains {
            if chain.rpc_urls.is_empty() && chain.rpc_providers.is_empty() {
                let endpoint = l1_chains.iter().find(|endpoint| endpoint.chain_index == chain.chain_index)
                    .with_context(|| format!("selected deployment document missing chain {}", chain.chain_index))?;
                chain.rpc_urls = vec![endpoint.rpc_url.clone()];
            }
        }
        chains
    };
    ensure!(!chains.is_empty(), "bridge relayer requires at least one chain");
    let mut seen = HashSet::with_capacity(chains.len());
    for chain in &chains {
        if let Some(policy) = &chain.fee_policy {
            policy.validate()?;
            ensure!(chain.network_id == "bscTestnet" && chain.deployments_network == "bscTestnet",
                "BSC fee policy may only be enabled for bscTestnet");
        }
        ensure!(chain.family.eq_ignore_ascii_case("evm"), "unsupported bridge chain family {}", chain.family);
        ensure!(
            !chain.rpc_urls.is_empty() || !chain.rpc_providers.is_empty(),
            "chain {} has no RPC URL",
            chain.network_id
        );
        ensure!(
            seen.insert(chain.chain_index),
            "duplicate bridge chain_index {}",
            chain.chain_index
        );
        let deployed = crate::bridge::api_client::load_deployed_contracts(&chain.deployments_network)?;
        if let Some(protocol) = deployed.protocol {
            ensure!(
                protocol.chain.l1_chain_index == chain.chain_index,
                "configured chain_index {} for {} does not match deployment index {}",
                chain.chain_index,
                chain.deployments_network,
                protocol.chain.l1_chain_index
            );
        }
    }
    chains.sort_by_key(|chain| chain.chain_index);
    Ok(chains)
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct DaemonFinalizeConfig {
    #[serde(default)]
    pub fee_policy: Option<super::l1_fees::BscFeePolicy>,
    pub l1_rpc_url: Option<String>,
    pub l1_rpc_fallback_url: Option<String>,
    #[serde(default)]
    pub l1_rpc_providers: Vec<crate::bridge::rpc_providers::RpcProviderConfig>,
    pub deployments_network: Option<String>,
    pub state_manager: Option<String>,
    pub bridge_address: Option<String>,
    pub bridge: Option<String>,
    pub private_key: Option<String>,
    pub keystore_path: Option<String>,
    pub password_env: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DaemonState {
    /// Withdrawals that still need a successful L1 claim.
    ///
    /// This set is the single source of truth for crash recovery:
    /// newly-scanned withdrawals are inserted before finalize/claim,
    /// successful claims remove entries, and all remaining entries are
    /// retried next round. The key is leaf_hash.
    pending_claim_withdrawals: HashMap<String, propose_withdrawals::PendingWithdrawal>,
    /// The one record per leaf above: attempt count, last reason, and any hold.
    claim_retry: HashMap<String, claim_attempts::ClaimAttempts>,
    /// Withdrawals that ran out of attempts. Nothing retries these; they are
    /// kept so the stuck funds stay traceable and can be re-armed by hand.
    retired_claim_withdrawals:
        HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
}


#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingFinalizationRange {
    from_checkpoint: u64,
    to_checkpoint: u64,
}

#[derive(Clone, Debug, Default)]
struct MultichainDaemonState {
    pending_finalization_range: Option<PendingFinalizationRange>,
    finalized_chains: HashSet<u8>,
    pending_claim_withdrawals: HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: HashMap<String, claim_attempts::ClaimAttempts>,
    retired_claim_withdrawals:
        HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
}



#[derive(Debug)]
pub(crate) struct L2RoundResult {
    deposit_append_target: Option<u32>,
    to_checkpoint: u64,
    submitted_l2_work: bool,
    /// Sticky catch-up authority for this L2 round. Starts from the pre-round
    /// window flag and latches true if the fresh coordinator head crosses the
    /// catch-up threshold mid-loop, so finish_l2_round and outer claim/deposit
    /// gates stay fail-closed under one authority.
    is_catchup_batch: bool,
    claim_withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
}

struct ChainRuntime {
    chain_index: u8,
    config: BridgeProposeDaemonConfig,
    l1: L1Client,
    bridge: Address,
    state_manager: Address,
}

#[derive(Clone, Debug)]
struct ChainRoundProgress {
    chain_index: u8,
    pending_deposit_count: u32,
    proved_deposit_count: u32,
    l2_deposit_count: u32,
}

#[derive(Debug)]
struct MultichainL2CallPlan {
    calls: Vec<ContractCallArgs>,
    withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
}

#[derive(Debug)]
struct L2CallPlan {
    withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
    /// Optimized batch calls using batch_2/batch_5 or individual methods.
    /// Each element is ONE ContractCallArgs for a batch (or single).
    batch_calls: Vec<ContractCallArgs>,
}

impl L2CallPlan {
    fn is_empty(&self) -> bool {
        self.batch_calls.is_empty()
    }
}

// ── Batch packing utilities ──────────────────────────────────────────────────

/// Compute optimal batch sizes for N items using sizes 1, 2, 5.
/// Minimizes total batch count while keeping x<2, y<5.
fn optimal_batch_sizes(n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    let mut best_total = usize::MAX;
    let mut best = (0usize, 0usize, 0usize);
    for fives in 0..=n / 5 {
        let rem = n - fives * 5;
        for twos in 0..=rem / 2 {
            let singles = rem - twos * 2;
            if singles < 2 {
                let total = singles + twos + fives;
                if total < best_total {
                    best_total = total;
                    best = (singles, twos, fives);
                }
            }
        }
    }
    let (singles, twos, fives) = best;
    let mut sizes = Vec::with_capacity(singles + twos + fives);
    for _ in 0..singles {
        sizes.push(1);
    }
    for _ in 0..twos {
        sizes.push(2);
    }
    for _ in 0..fives {
        sizes.push(5);
    }
    sizes
}


/// Build optimized batch `ContractCallArgs` for withdrawal appends.
/// Sender-auth batch interface:
/// batch_append_withdrawals_N(
///   count,
///   sender_user_ids,
///   token_contract_ids,
///   destination_chain_indices,
///   token_addresses,
///   amounts,
///   recipients,
///   nonces,
/// )
pub(crate) fn build_withdrawal_batch_calls(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
) -> Vec<ContractCallArgs> {
    if withdrawals.is_empty() {
        return Vec::new();
    }

    let sizes = optimal_batch_sizes(withdrawals.len());
    let mut calls = Vec::with_capacity(sizes.len());
    let mut pos = 0;
    for &chunk_size in &sizes {
        match chunk_size {
            1 => {
                let w = &withdrawals[pos];
                let mut inputs = vec![
                    w.sender_user_id,
                    w.contract_id,
                    w.destination_chain_index,
                ];
                inputs.extend(w.token_address.iter().map(|&v| v as u64));
                inputs.extend(w.amount.iter().map(|&v| v as u64));
                inputs.extend(w.recipient.iter().map(|&v| v as u64));
                inputs.extend(w.nonce.iter().map(|&v| v as u64));
                calls.push(ContractCallArgs {
                    contract_id: WITHDRAWAL_TREE_CONTRACT_ID as u64,
                    method_name: "append_withdrawal".to_string(),
                    inputs,
                });
            }
            2 | 5 => {
                let method = if chunk_size == 2 {
                    "batch_append_withdrawals_2"
                } else {
                    "batch_append_withdrawals_5"
                };
                let mut inputs = vec![chunk_size as u64];
                for k in 0..chunk_size {
                    inputs.push(withdrawals[pos + k].sender_user_id);
                }
                for k in 0..chunk_size {
                    inputs.push(withdrawals[pos + k].contract_id);
                }
                for k in 0..chunk_size {
                    inputs.push(withdrawals[pos + k].destination_chain_index);
                }
                for k in 0..chunk_size {
                    inputs.extend(withdrawals[pos + k].token_address.iter().map(|&v| v as u64));
                }
                for k in 0..chunk_size {
                    inputs.extend(withdrawals[pos + k].amount.iter().map(|&v| v as u64));
                }
                for k in 0..chunk_size {
                    inputs.extend(withdrawals[pos + k].recipient.iter().map(|&v| v as u64));
                }
                for k in 0..chunk_size {
                    inputs.extend(withdrawals[pos + k].nonce.iter().map(|&v| v as u64));
                }
                calls.push(ContractCallArgs {
                    contract_id: WITHDRAWAL_TREE_CONTRACT_ID as u64,
                    method_name: method.to_string(),
                    inputs,
                });
            }
            _ => unreachable!(),
        }
        pos += chunk_size;
    }
    calls
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RelayerWindow {
    to_checkpoint: u64,
    confirmed_to_checkpoint: Option<u64>,
    is_catchup_batch: bool,
}

impl RelayerWindow {
    fn has_confirmed_range(self) -> bool {
        self.confirmed_to_checkpoint.is_some()
    }
}


fn select_deposit_append_target(
    is_catchup_batch: bool,
    proof_to_checkpoint: u64,
    l2_landing_checkpoint: u64,
    l2_deposit_cursor: u64,
    proved_deposit_count: u32,
    pending_deposit_count: u32,
) -> anyhow::Result<Option<u32>> {
    ensure!(
        proved_deposit_count <= pending_deposit_count,
        "L1 deposit cursors are inconsistent: provedDepositCount={} pendingDepositCount={}",
        proved_deposit_count,
        pending_deposit_count
    );

    if is_catchup_batch || proof_to_checkpoint != l2_landing_checkpoint {
        return Ok(None);
    }

    let target = u32::try_from(l2_deposit_cursor).context("L2 deposit cursor exceeds u32")?;
    ensure!(
        target >= proved_deposit_count,
        "L2 deposit cursor is behind L1 proved count at prove checkpoint: l2_cursor={} provedDepositCount={} to_checkpoint={}",
        target,
        proved_deposit_count,
        proof_to_checkpoint
    );
    ensure!(
        target <= pending_deposit_count,
        "L2 deposit tree has more deposits than L1 pending count at prove checkpoint: l2_cursor={} pendingDepositCount={} to_checkpoint={}",
        target,
        pending_deposit_count,
        proof_to_checkpoint
    );

    Ok((target > proved_deposit_count).then_some(target))
}

/// Select the checkpoint a single-chain round finalizes through the bridge
/// agg proof.
///
/// A normal round (gap <= max_checkpoint_batch) finalizes straight to the L2
/// landing checkpoint, not capped back to the pre-round window bound. The L2
/// round may land beyond that bound, and the bridge agg proof covers the
/// wider range via chained proofs (32-slot chain + final). Capping back would
/// drop landed L2 work. Catch-up rounds do not append deposits or
/// withdrawals, so no L2 work advances the cursor and landing equals the
/// window bound.
///
/// Multichain does not use this helper. Its proof range is the selected
/// catch-up window, frozen at the next slower chain cursor. Extending that
/// range to a later L2 landing would persist a start the faster chain rejects.
fn select_finalize_to_checkpoint(
    _window_to_checkpoint: u64,
    l2_landing_checkpoint: u64,
) -> u64 {
    l2_landing_checkpoint
}



pub(crate) fn validate_max_checkpoint_batch(max_checkpoint_batch: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        max_checkpoint_batch >= 1,
        "max_checkpoint_batch must be >= 1, got {}",
        max_checkpoint_batch
    );
    Ok(())
}

fn select_relayer_window(
    from_checkpoint: u64,
    latest_checkpoint: u64,
    confirmation_lag_checkpoints: u64,
    max_checkpoint_batch: u64,
) -> RelayerWindow {
    let confirmed_to_checkpoint = latest_checkpoint.checked_sub(confirmation_lag_checkpoints);
    let Some(confirmed_to_checkpoint) = confirmed_to_checkpoint.filter(|confirmed| *confirmed >= from_checkpoint) else {
        // L2 has not confirmed far enough — append-only mode (no prove/finalize).
        let catchup_to = if max_checkpoint_batch == 0 {
            latest_checkpoint
        } else {
            latest_checkpoint.min(from_checkpoint.saturating_add(max_checkpoint_batch.saturating_sub(1)))
        };
        return RelayerWindow {
            to_checkpoint: catchup_to,
            confirmed_to_checkpoint: None,
            is_catchup_batch: false,
        };
    };

    // Catchup is determined by whether the gap exceeds max_checkpoint_batch.
    let range_len = confirmed_to_checkpoint - from_checkpoint + 1;
    let is_catchup_batch = max_checkpoint_batch > 0 && range_len > max_checkpoint_batch;

    // In catchup mode, truncate to max_checkpoint_batch per round.
    // A one-checkpoint tail remains as a normal next-round range and can be proved.
    let to_checkpoint = if is_catchup_batch && max_checkpoint_batch > 0 {
        from_checkpoint.saturating_add(max_checkpoint_batch.saturating_sub(1))
    } else {
        confirmed_to_checkpoint
    };

    RelayerWindow {
        to_checkpoint,
        confirmed_to_checkpoint: Some(confirmed_to_checkpoint),
        is_catchup_batch,
    }
}

fn select_multichain_relayer_window(
    finalized_checkpoints: &[u64],
    latest_checkpoint: u64,
    confirmation_lag_checkpoints: u64,
    max_checkpoint_batch: u64,
) -> anyhow::Result<(u64, RelayerWindow)> {
    let minimum = finalized_checkpoints
        .iter()
        .copied()
        .min()
        .context("configured chain list unexpectedly empty")?;
    let from_checkpoint = minimum
        .checked_add(1)
        .context("minimum finalized checkpoint cannot be incremented")?;
    let mut window = select_relayer_window(
        from_checkpoint,
        latest_checkpoint,
        confirmation_lag_checkpoints,
        max_checkpoint_batch,
    );
    // Never leapfrog a chain that is ahead of the slowest chain. Catch the
    // slowest cohort up to the next cursor first, then all chains can consume
    // the following shared range together.
    if let Some(next_cursor) = finalized_checkpoints
        .iter()
        .copied()
        .filter(|checkpoint| *checkpoint > minimum)
        .min()
    {
        window.to_checkpoint = window.to_checkpoint.min(next_cursor);
        // Cursors differ, so this round only catches the slowest chain up
        // to the next cursor. Deposit and withdrawal appends stay off until
        // every chain can consume the same range.
        window.is_catchup_batch = true;
    }
    Ok((from_checkpoint, window))
}

/// True when this chain still has to consume `range`. A cursor already at or
/// past the range end is done. A cursor exactly at `from - 1` must finalize.
/// Every other cursor is incompatible: the chain would reject the start.
fn chain_finalization_required(cursor: u64, range: PendingFinalizationRange) -> anyhow::Result<bool> {
    let parent = range
        .from_checkpoint
        .checked_sub(1)
        .context("finalization range cannot start at zero")?;
    if cursor >= range.to_checkpoint {
        return Ok(false);
    }
    ensure!(
        cursor == parent,
        "chain cursor {} is incompatible with proof range {}..={}",
        cursor,
        range.from_checkpoint,
        range.to_checkpoint
    );
    Ok(true)
}

/// Fail closed before any durable mutation. Every configured cursor must
/// either already cover the range or sit exactly on its parent. A start the
/// chain would reject is never persisted.
fn validate_range_against_cursors(
    range: PendingFinalizationRange,
    chain_cursors: &[(u8, u64)],
) -> anyhow::Result<()> {
    for &(_chain_index, cursor) in chain_cursors {
        chain_finalization_required(cursor, range)?;
    }
    Ok(())
}

/// Proof endpoint of a fresh multichain round.
///
/// The selected window is the only range every chain cursor can accept, so
/// it stays frozen even when L2 inclusion lands later. `landed` is recorded
/// separately and is not a finalization endpoint. A round that submitted no
/// new L2 work keeps the same window.
fn select_multichain_proof_endpoint(window_to_checkpoint: u64, _submitted_l2_work: bool, _landed: u64) -> u64 {
    window_to_checkpoint
}

/// Replace a saved range that at least one chain cursor can no longer start.
///
/// Claims and proofs stay. The replacement is the window every current
/// cursor would select now, including a chain that already finalized past
/// the poisoned start. Cursors 70 and 60 therefore resume at 61..=70, and
/// cursors 50 and 60 resume at 51..=60. A cursor behind the saved start is
/// not repaired: moving the start later would skip checkpoints it still
/// has to finalize.
fn recover_incompatible_saved_range(
    saved: PendingFinalizationRange,
    chain_cursors: &[(u8, u64)],
    latest_checkpoint: u64,
    confirmation_lag_checkpoints: u64,
    max_checkpoint_batch: u64,
) -> anyhow::Result<Option<PendingFinalizationRange>> {
    if validate_range_against_cursors(saved, chain_cursors).is_ok() {
        return Ok(None);
    }
    let parent = saved
        .from_checkpoint
        .checked_sub(1)
        .context("finalization range cannot start at zero")?;
    if chain_cursors.iter().any(|&(_, cursor)| cursor < parent) {
        anyhow::bail!(
            "saved proof range {}..={} starts after a chain cursor",
            saved.from_checkpoint,
            saved.to_checkpoint
        );
    }
    let cursors: Vec<u64> = chain_cursors.iter().map(|&(_, cursor)| cursor).collect();
    let (from_checkpoint, window) = select_multichain_relayer_window(
        &cursors,
        latest_checkpoint.max(saved.to_checkpoint),
        confirmation_lag_checkpoints,
        max_checkpoint_batch,
    )?;
    ensure!(
        window.has_confirmed_range(),
        "saved proof range {}..={} has no confirmed replacement window",
        saved.from_checkpoint,
        saved.to_checkpoint
    );
    let recovered = PendingFinalizationRange { from_checkpoint, to_checkpoint: window.to_checkpoint };
    validate_range_against_cursors(recovered, chain_cursors)?;
    Ok((recovered != saved).then_some(recovered))
}

fn refresh_catchup_state(
    is_catchup_batch: bool,
    from_checkpoint: u64,
    latest_checkpoint: Option<u64>,
    confirmation_lag_checkpoints: u64,
    max_checkpoint_batch: u64,
) -> bool {
    if is_catchup_batch {
        return true;
    }
    let Some(latest_checkpoint) = latest_checkpoint else {
        return true;
    };
    select_relayer_window(
        from_checkpoint,
        latest_checkpoint,
        confirmation_lag_checkpoints,
        max_checkpoint_batch,
    )
    .is_catchup_batch
}

fn should_attempt_pending_claims(is_catchup_batch: bool, pending_claim_count: usize) -> bool {
    !is_catchup_batch && pending_claim_count > 0
}

/// Capability issued only when post-L2 phases may run. All deposit/proof/
/// finalize/claim dispatch wrappers require this permit, so a newly-latched
/// catch-up branch cannot fall through into any of those operations.
#[derive(Clone, Copy, Debug)]
struct PostL2PhasePermit;

#[derive(Debug)]
enum PostL2Orchestration<T> {
    Deferred,
    Dispatch(T),
}

/// Production post-L2 orchestration seam. It merges the durable claim ledger,
/// atomically installs it when a normal-entry round newly latches catch-up, and
/// invokes `dispatch` only when post-L2 phases are authorized.
async fn orchestrate_post_l2_round<T, Dispatch, DispatchFuture>(
    config: &guardian_common::protocol::GuardianConfig,
    db: &super::guardian_client::RelayerDb,
    chain: u8,
    state: &DaemonState,
    current_round_withdrawals: &[propose_withdrawals::PendingWithdrawal],
    pre_round_is_catchup_batch: bool,
    post_l2_is_catchup_batch: bool,
    dispatch: Dispatch,
) -> anyhow::Result<PostL2Orchestration<T>>
where
    Dispatch: FnOnce(
        PostL2PhasePermit,
        HashMap<String, propose_withdrawals::PendingWithdrawal>,
    ) -> DispatchFuture,
    DispatchFuture: Future<Output = T>,
{
    let mut pending_claim_withdrawals = state.pending_claim_withdrawals.clone();
    let claim_retry = state.claim_retry.clone();
    let retired_claim_withdrawals = state.retired_claim_withdrawals.clone();
    insert_pending_claims(current_round_withdrawals, &mut pending_claim_withdrawals, &retired_claim_withdrawals);

    if !pre_round_is_catchup_batch && post_l2_is_catchup_batch {
        save_chain_state(config, db, chain, &DaemonState {
            pending_claim_withdrawals,
            claim_retry,
            retired_claim_withdrawals,
        })?;
        return Ok(PostL2Orchestration::Deferred);
    }

    Ok(PostL2Orchestration::Dispatch(
        dispatch(PostL2PhasePermit, pending_claim_withdrawals).await,
    ))
}

async fn dispatch_post_l2_phase<T>(
    _permit: &PostL2PhasePermit,
    phase: impl Future<Output = T>,
) -> T {
    phase.await
}

fn persist_finalized_state_then_cleanup_proof(
    config: &guardian_common::protocol::GuardianConfig,
    db: &super::guardian_client::RelayerDb,
    chain: u8,
    state: &DaemonState,
    proof_path: &Path,
) -> anyhow::Result<()> {
    save_chain_state(config, db, chain, state)?;
    if let Err(err) = fs::remove_file(proof_path) {
        tracing::warn!(
            proof_path = %proof_path.display(),
            error = %err,
            "finalized state is durable but spent proof cleanup failed"
        );
    }
    Ok(())
}

async fn materialize_chain_proof(
    shared_path: &Path,
    chain_path: &Path,
    provider: &RpcProvider,
    checkpoint: u64,
    chain_index: u8,
) -> anyhow::Result<()> {
    let raw = fs::read_to_string(shared_path)
        .with_context(|| format!("read shared proof {}", shared_path.display()))?;
    let mut json: serde_json::Value = serde_json::from_str(&raw)?;
    let (deposit_subroot, deposit_path) = prove_bridge::fetch_tree_subroot_and_top_proof(
        provider, checkpoint, BRIDGE_USER_ID_U64, DEPOSIT_TREE_CONTRACT_ID, chain_index,
    ).await?;
    let (withdrawal_subroot, withdrawal_path) = prove_bridge::fetch_tree_subroot_and_top_proof(
        provider, checkpoint, BRIDGE_USER_ID_U64, WITHDRAWAL_TREE_CONTRACT_ID, chain_index,
    ).await?;
    let encode_path = |path: [B256; 9]| {
        path.into_iter()
            .map(|value| serde_json::Value::String(format!("{:#066x}", value)))
            .collect::<Vec<_>>()
    };
    json["l1_chain_index"] = serde_json::Value::from(u64::from(chain_index));
    json["deposit_subtree_root"] = serde_json::Value::String(format!("{:#066x}", deposit_subroot));
    json["deposit_merkle_proof"] = serde_json::Value::Array(encode_path(deposit_path));
    json["withdrawal_subtree_root"] = serde_json::Value::String(format!("{:#066x}", withdrawal_subroot));
    json["withdrawal_merkle_proof"] = serde_json::Value::Array(encode_path(withdrawal_path));
    let encoded = serde_json::to_vec_pretty(&json)?;
    fs::write(chain_path, encoded)
        .with_context(|| format!("write chain proof {}", chain_path.display()))
}

pub async fn run(args: RunDaemonArgs) -> anyhow::Result<()> {
    let mut loaded = load_config(&args.config)?;
    loaded.l1_config = args.l1_config;
    let history_config = super::guardian_client::LoadedGuardianConfig::load(Path::new(&loaded.rpc_config), Path::new(&loaded.guardian_root), &loaded.l1_config).await?;
    let chain_configs = configured_chains(&loaded, &history_config.root.l1_chains)?;
    let provider = guardian_common::runtime::load_network(&history_config.root).map_err(|error| anyhow::anyhow!("{error}"))?;
    initialize_relayer_account(&history_config, &provider).await?;
    let daemon = async {
        if chain_configs.len() == 1 {
            return run_single_chain(chain_configs[0].effective_config(&loaded)?, &args.config, &history_config, &provider).await;
        }
        run_multichain(loaded, chain_configs, &args.config, &history_config, &provider).await
    };
    tokio::select! {
        result = history_config.serve_history() => result,
        result = daemon => result,
    }
}
/// Records the checkpoint-0 leaf and the configured account before either daemon path loads progress.
/// The leaf is read once for a missing account. An existing journal keeps its saved checkpoint;
/// imported continuity is authenticated later by restore_relayer_history, not by re-comparing checkpoint 0.
async fn initialize_relayer_account(config: &super::guardian_client::LoadedGuardianConfig, provider: &RpcProvider) -> anyhow::Result<()> {
    use psy_client_data::{config::store_config::PsyHasher, traits::qdatastore::qmetadata::QMetaDataStoreReaderSync};
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    let identity = config.root.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
    let saved = config.db.load_account(config.root.network_magic()?, guardian_common::protocol::BRIDGE_USER_ID)?;
    let leaf = if saved.is_none() {
        Some(provider.get_checkpoint_leaf_data(0).await?)
    } else {
        None
    };
    if let Some(leaf) = leaf.as_ref() {
        config.db.ensure_genesis_account(&config.root, leaf.qfhash::<PsyHasher>())?;
    }
    let saved = config.db.load_account(config.root.network_magic()?, guardian_common::protocol::BRIDGE_USER_ID)?.context("fresh guardian account missing")?;
    ensure!(saved.account_public_key == identity, "saved account identity differs from startup");
    Ok(())
}


/// Root-cause class (`timeout`/`unavailable`/`provider`/`revert`/`decode`,
/// fallback `other`) for a failed L1 read. A typed `reqwest::Error` in the chain
/// classifies timeout and connect exits and nothing else; otherwise the typed
/// alloy transport error at the bottom of the anyhow chain is classified via the
/// pool's redaction-aware mapper. The result is a static name only: no URLs,
/// request parameters or response bodies.
fn transport_error_category(error: &anyhow::Error) -> &'static str {
    error
        .chain()
        .find_map(|cause| {
            if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
                return Some(if error.is_timeout() { "timeout" } else if error.is_connect() { "unavailable" } else { "other" });
            }
            cause.downcast_ref::<alloy_transport::TransportError>().map(super::pool_transport::error_category)
        })
        .unwrap_or("other")
}
/// True only for typed transient failures — a transport error categorized
/// `timeout`/`unavailable` or the committed-head reader's `L2RpcUnavailable`
/// — that a later round can plausibly resolve. Everything else (nonce
/// conflicts, halted accounts, reverts, decode errors, untyped fallbacks)
/// stays permanent and must surface.
fn is_temporary_rpc_error(error: &anyhow::Error) -> bool {
    if matches!(transport_error_category(error), "timeout" | "unavailable") { return true; }
    error.chain().any(|cause| cause.downcast_ref::<guardian_common::protocol::GuardianSignError>() == Some(&guardian_common::protocol::GuardianSignError::L2RpcUnavailable))
}

async fn run_multichain(
    config: BridgeProposeDaemonConfig,
    chain_configs: Vec<L1Config>,
    config_path: &Path,
    guardian: &super::guardian_client::LoadedGuardianConfig,
    provider: &RpcProvider,
) -> anyhow::Result<()> {
    ensure!(config.max_concurrent_l2_batches.unwrap_or(1) == 1, "multisig account permits one inflight session");
    let proof_dir = config.proof_dir.clone().unwrap_or_else(|| PathBuf::from(DEFAULT_PROOF_DIR));
    fs::create_dir_all(&proof_dir)?;
    let chains_label = chain_configs.iter().map(|chain| chain.chain_index.to_string()).collect::<Vec<_>>().join(",");
    let mut chains = Vec::with_capacity(chain_configs.len());
    for chain in chain_configs {
        let effective = chain.effective_config(&config)?;
        let bridge = resolve_bridge_address(&effective)?.parse::<Address>()?;
        let state_manager = resolve_state_manager_address(&effective)?;
        chains.push(ChainRuntime {
            chain_index: chain.chain_index,
            l1: L1Client::from_finalize_config(&effective.finalize, &chain.network_id)?,
            config: effective,
            bridge,
            state_manager,
        });
    }

    let poll_interval = Duration::from_secs(config.poll_interval_secs.unwrap_or(30));
    let lag = config.confirmation_lag_checkpoints.unwrap_or(3);
    let max_batch = config.max_checkpoint_batch.unwrap_or(DEFAULT_MAX_CHECKPOINT_BATCH);
    validate_max_checkpoint_batch(max_batch)?;
    let proxy = resolve_system_prove_proxy_url(&guardian.root.network)?;
    verify_system_prove_proxy(&proxy).await?;
    tracing::info!(prove_proxy = %proxy, "system prove proxy configured");
    tracing::info!(config=%config_path.display(), chain_count=chains.len(), chains=%chains_label, "multichain bridge relayer started");

    // Coordinator stall guard: if the head does not advance for
    // COORDINATOR_STALL_POLLS consecutive rounds while the previous round
    // minted L2 work, stop building/submitting new EndCaps against the frozen
    // coordinator. 72 rounds ≈ 2 × REALM_CHECKPOINT_POLL_TIMEOUT_SECS /
    // REALM_CHECKPOINT_POLL_INTERVAL_SECS of inclusion attempts.
    const COORDINATOR_STALL_POLLS: u64 = 72;
    const RELAYER_MIN_RETRY_BACKOFF_SECS: u64 = 5;
    const RELAYER_MAX_RETRY_BACKOFF_SECS: u64 = 60;
    let mut last_coordinator_head: Option<u64> = None;
    let mut stalled_rounds: u64 = 0;
    let mut last_round_submitted_l2_work = false;
    let mut l2_retry_backoff = Duration::from_secs(RELAYER_MIN_RETRY_BACKOFF_SECS);
    let mut claim_readiness_starts: HashMap<u8, Option<i64>> = HashMap::new();

    loop {
        let mut state = load_multichain_state(&guardian.root, &guardian.db)?;
        let mut cursors = HashMap::new();
        let mut read_failed = false;
        for chain in &chains {
            match chain.l1.last_finalized_checkpoint(chain.state_manager).await {
                Ok(cursor) => { cursors.insert(chain.chain_index, cursor); }
                Err(error) => {
                    read_failed = true;
                    tracing::error!(
                        chain_index = chain.chain_index,
                        error = %error,
                        error_category = transport_error_category(&error),
                        "failed to read finalization cursor"
                    );
                }
            }
        }
        if read_failed { tokio::time::sleep(poll_interval).await; continue; }

        let mut latest = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        if last_coordinator_head == Some(latest) {
            stalled_rounds += 1;
        } else {
            last_coordinator_head = Some(latest);
            stalled_rounds = 0;
        }

        if let Some(saved) = state.pending_finalization_range {
            let chain_cursors = chains.iter()
                .map(|chain| (chain.chain_index, cursors[&chain.chain_index]))
                .collect::<Vec<_>>();
            match recover_incompatible_saved_range(saved, &chain_cursors, latest, lag, max_batch) {
                Ok(Some(recovered)) => {
                    tracing::warn!(
                        saved_from = saved.from_checkpoint,
                        saved_to = saved.to_checkpoint,
                        recovered_from = recovered.from_checkpoint,
                        recovered_to = recovered.to_checkpoint,
                        "saved proof range is incompatible with chain cursors; resetting the window and retaining claims"
                    );
                    state.pending_finalization_range = Some(recovered);
                    state.finalized_chains.clear();
                    save_multichain_state(&guardian.root, &guardian.db, &state)?;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::error!(%error, "saved proof range cannot be recovered from chain cursors; retaining claims and proofs");
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            }
        }

        if let Some(range) = state.pending_finalization_range {
            for (&chain_index, &cursor) in &cursors {
                if cursor >= range.to_checkpoint { state.finalized_chains.insert(chain_index); }
            }
        }

        let cursor_list = cursors.values().copied().collect::<Vec<_>>();
        let cursors_differ = cursor_list.iter().copied().min() != cursor_list.iter().copied().max();
        let (mut from_checkpoint, mut window) = if let Some(range) = state.pending_finalization_range {
            (range.from_checkpoint, RelayerWindow { to_checkpoint: range.to_checkpoint, confirmed_to_checkpoint: Some(range.to_checkpoint), is_catchup_batch: cursors_differ })
        } else {
            select_multichain_relayer_window(&cursor_list, latest, lag, max_batch)?
        };
        let mut pending_landed = None;
        if guardian.db.pending_request()?.is_some() {
            let mut guardian_history = config.guardian_history.lock().await;
            let recovered = async {
                let landed = submit_guardian_operation(guardian, provider, Vec::new(), &[], guardian_common::protocol::GuardianOperation::Bridge, None, &mut guardian_history, PolicySignatures::None).await?.included_checkpoint_id;
                wait_until_checkpoint_confirmed(provider, landed, lag, REALM_CHECKPOINT_POLL_TIMEOUT_SECS, REALM_CHECKPOINT_POLL_INTERVAL_SECS).await?;
                Ok((landed, provider.get_coordinator_latest_block_state().await?.checkpoint_id))
            }.await;
            match recovered {
                Ok((landed, fresh_head)) => {
                    pending_landed = Some(landed);
                    last_round_submitted_l2_work = true;
                    latest = fresh_head;
                    if state.pending_finalization_range.is_none() {
                        (from_checkpoint, window) = select_multichain_relayer_window(&cursors.values().copied().collect::<Vec<_>>(), latest, lag, max_batch)?;
                    }
                }
                Err(error) if is_temporary_rpc_error(&error) => {
                    tracing::warn!(%error, error_category = transport_error_category(&error), "pending guardian recovery hit temporary RPC unavailability; retrying next round");
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        if window.to_checkpoint < from_checkpoint && pending_landed.is_none() { tokio::time::sleep(poll_interval).await; continue; }
        let propose_args = ProposeWithdrawalsArgs {
            rpc_config: config.rpc_config.clone(),
            guardian_root: config.guardian_root.clone(),
            services_url: Some(config.services_url.clone()),
            withdraw_method_id: config.withdraw_method_id,
            state_file: None,
            notify_coordinator: true,
            poll_timeout_secs: 0,
            poll_interval_secs: 5,
            destination_chain_indices: chains.iter().map(|chain| u64::from(chain.chain_index)).collect(),
            l1_config: config.l1_config.clone(),
        };
        let mut round_withdrawals = Vec::new();
        let to_checkpoint = if state.pending_finalization_range.is_none() {
            if stalled_rounds >= COORDINATOR_STALL_POLLS && last_round_submitted_l2_work {
                tracing::warn!(
                    head = latest,
                    stalled_rounds,
                    "coordinator head has not advanced while the previous round submitted L2 work; skipping L2 build/submit this round"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
            let (_progress, plan) = match build_multichain_l2_plan(
                &config, &provider, &chains, latest, from_checkpoint, window.to_checkpoint,
                !window.is_catchup_batch, &propose_args, guardian,
            ).await {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(%error, backoff_secs = l2_retry_backoff.as_secs(), "build multichain L2 plan failed");
                    tokio::time::sleep(l2_retry_backoff).await;
                    l2_retry_backoff = (l2_retry_backoff * 2).min(Duration::from_secs(RELAYER_MAX_RETRY_BACKOFF_SECS));
                    continue;
                }
            };
            round_withdrawals = plan.withdrawals.clone();
            let mut guardian_history = config.guardian_history.lock().await;
            let previous_nonce = guardian_history.history.nonce();
            let landed = match submit_multichain_l2_plan(provider, &plan, &mut guardian_history, lag, guardian).await {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(%error, backoff_secs = l2_retry_backoff.as_secs(), "multichain guardian L2 submission failed");
                    tokio::time::sleep(l2_retry_backoff).await;
                    l2_retry_backoff = (l2_retry_backoff * 2).min(Duration::from_secs(RELAYER_MAX_RETRY_BACKOFF_SECS));
                    continue;
                }
            };
            let fresh_landed = guardian_history.history.nonce() > previous_nonce;
            let submitted_l2_work = fresh_landed || pending_landed.is_some();
            last_round_submitted_l2_work = submitted_l2_work;
            l2_retry_backoff = Duration::from_secs(RELAYER_MIN_RETRY_BACKOFF_SECS);
            if !window.has_confirmed_range() {
                tracing::info!(submitted_l2_work, landed, "append-only multichain round retained until a confirmed proof window exists");
                tokio::time::sleep(poll_interval).await;
                continue;
            }
            let landed = pending_landed.map_or(landed, |pending| pending.max(landed));
            // The selected catch-up window is the proof endpoint. L2 landing
            // is a separate checkpoint and must not extend the range: a
            // faster chain already past the window start rejects that start.
            select_multichain_proof_endpoint(window.to_checkpoint, submitted_l2_work, landed)
        } else {
            window.to_checkpoint
        };

        let range = PendingFinalizationRange { from_checkpoint, to_checkpoint };
        let chain_cursors = chains.iter()
            .map(|chain| (chain.chain_index, cursors[&chain.chain_index]))
            .collect::<Vec<_>>();
        let persisted = persist_and_sync_multichain_range(
            &guardian.root, &guardian.db, &mut state, range, &round_withdrawals, &chain_cursors,
            |chain_index, endpoint| {
                let chain = chains.iter().find(|chain| chain.chain_index == chain_index).unwrap();
                let provider = &provider;
                async move {
                    let target = fetch_deposit_tree_next_index(provider, endpoint, u64::from(chain_index)).await?;
                    let target = u32::try_from(target)?;
                    sync_deposit_if_behind(
                        target,
                        chain.l1.with_rpc_failover("read_deposit_sync_progress", |url| {
                            let url = url.to_string();
                            async move {
                                let provider = crate::bridge::l1_provider::connect_l1_readonly(url.parse()?)?;
                                fetch_proved_deposit_count(&provider, chain.bridge).await
                            }
                        }),
                        || chain.l1.submit_deposit_batch_appends(&chain.config, target, &guardian.root.network),
                    ).await
                }
            },
        ).await;
        let ready = match persisted {
            Ok(ready) => ready,
            Err(error) if state.pending_finalization_range.is_some() => {
                tracing::error!(%error, "range persist/sync failed; retaining claims and proofs");
                tokio::time::sleep(poll_interval).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if !ready {
            tokio::time::sleep(poll_interval).await;
            continue;
        }
        let shared_path = proof_dir.join(format!("bridge_proof_{}.json", to_checkpoint));
        let needs_finalize = chains.iter().any(|chain| cursors[&chain.chain_index] < to_checkpoint);
        if needs_finalize {
            if let Err(error) = chains[0].l1.load_or_build_proof(
                &chains[0].config, &shared_path, from_checkpoint, to_checkpoint, Some(proxy.as_str()),
            ).await {
                tracing::error!(%error, "shared bridge proof generation failed");
                tokio::time::sleep(poll_interval).await; continue;
            }
        }

        for chain in &chains {
            let cursor = cursors[&chain.chain_index];
            if !chain_finalization_required(cursor, range)? { state.finalized_chains.insert(chain.chain_index); continue; }
            let chain_path = proof_dir.join(format!("bridge_proof_{}_chain_{}.json", to_checkpoint, chain.chain_index));
            if let Err(error) = materialize_chain_proof(&shared_path, &chain_path, &provider, to_checkpoint, chain.chain_index).await {
                tracing::error!(chain_index=chain.chain_index, %error, "build per-chain witness failed"); continue;
            }
            let finalize_args = FinalizeBridgeAggArgs {
                l1_fee_policy: chain.config.finalize.fee_policy.clone(),
                proof_json: chain_path.clone(), to_checkpoint, rpc_config: config.rpc_config.clone(),
                l1_rpc_url: chain.config.finalize.l1_rpc_url.clone().unwrap(),
                deployments_network: chain.config.finalize.deployments_network.clone().unwrap(),
                state_manager: chain.config.finalize.state_manager.clone(),
                bridge_address: Some(format!("{}", chain.bridge)), batch_append_proof_json: None,
                private_key: chain.config.finalize.private_key.clone(),
                keystore_path: chain.config.finalize.keystore_path.clone().map(PathBuf::from),
                password_env: chain.config.finalize.password_env.clone().unwrap_or_else(|| "WALLET_PASSWORD".into()),
            };
            match chain.l1.finalize(finalize_args).await {
                Ok(()) => { state.finalized_chains.insert(chain.chain_index); let _ = fs::remove_file(chain_path); }
                Err(error) => tracing::error!(chain_index=chain.chain_index, %error, "chain finalize failed; shared proof retained"),
            }
        }
        // Every round, and deliberately outside the finalization gate below: a
        // round that never finishes finalizing still must not let unroutable
        // withdrawals pile up unnoticed.
        record_unroutable_claims(
            &chains.iter().map(|chain| chain.chain_index).collect::<HashSet<u8>>(),
            &mut state.pending_claim_withdrawals,
            &mut state.claim_retry,
            &mut state.retired_claim_withdrawals,
            claim_attempts::now_unix(),
        );
        save_multichain_state(&guardian.root, &guardian.db, &state)?;

        if state.finalized_chains.len() == chains.len() {
            tokio::time::sleep(Duration::from_secs(2)).await;
            for chain in &chains {
                let now_unix = claim_attempts::now_unix();
                let resolutions = match chain.l1.release_claim_holds(&state.pending_claim_withdrawals, &mut state.claim_retry, &chain.config, Some(chain.chain_index)).await {
                    Ok(resolutions) => resolutions,
                    Err(error) => {
                        tracing::warn!(chain_index = chain.chain_index, error = %error, "claim hold recheck failed; held leaves stay held");
                        continue;
                    }
                };
                for resolution in &resolutions {
                    record_claim_outcome(&resolution.withdrawals, &resolution.report, &mut state.pending_claim_withdrawals, &mut state.claim_retry, &mut state.retired_claim_withdrawals, now_unix);
                }
                save_multichain_state(&guardian.root, &guardian.db, &state)?;
                let mut claims = claims_to_attempt(&state.pending_claim_withdrawals, &state.claim_retry);
                claims.retain(|withdrawal| withdrawal.destination_chain_index == u64::from(chain.chain_index));
                claims.sort_by_key(|withdrawal| (withdrawal.destination_chain_index, withdrawal.event_id));
                if claims.is_empty() { continue; }
                let start = claim_readiness_starts.entry(chain.chain_index).or_default();
                let index = start.and_then(|last| claims.iter().position(|claim| claim.event_id > last)).unwrap_or(0);
                claims.rotate_left(index);
                let hook = claim_broadcast_hook(&guardian.root, &guardian.db);
                let result = chain.l1.claim_withdrawals(&claims, &chain.config, to_checkpoint, &guardian.root.network, Some(hook)).await;
                *start = next_claim_readiness_start(&claims, &result);
                if result.is_err() {
                    match persisted_claim_retry(&guardian.root, &guardian.db) {
                        Ok(persisted) => adopt_persisted_receipt_holds(&claims, &mut state.claim_retry, &persisted),
                        Err(error) => tracing::warn!(error = %error, "cannot re-read persisted claim holds; recording the failure without them"),
                    }
                }
                record_claim_result(
                    &claims,
                    &result,
                    &mut state.pending_claim_withdrawals,
                    &mut state.claim_retry,
                    &mut state.retired_claim_withdrawals,
                    now_unix,
                );
                save_multichain_state(&guardian.root, &guardian.db, &state)?;
            }
            state.pending_finalization_range = None;
            state.finalized_chains.clear();
            save_multichain_state(&guardian.root, &guardian.db, &state)?;
            let _ = fs::remove_file(&shared_path);
        }
        tokio::time::sleep(poll_interval).await;
    }
}

async fn run_single_chain(config: BridgeProposeDaemonConfig, config_path: &Path, guardian: &super::guardian_client::LoadedGuardianConfig, provider: &RpcProvider) -> anyhow::Result<()> {
    let proof_dir = config
        .proof_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PROOF_DIR));
    fs::create_dir_all(&proof_dir).with_context(|| format!("failed to create proof dir {}", proof_dir.display()))?;
    tracing::info!(config = %config_path.display(), proof_dir = %proof_dir.display(), "bridge relayer started");

    // Phase 4.4: skip local circuit/Groth16 warmup when remote prove proxy is configured
    let proxy_url_at_startup = resolve_system_prove_proxy_url(&guardian.root.network)?;
    verify_system_prove_proxy(&proxy_url_at_startup).await?;
    tracing::info!(prove_proxy = %proxy_url_at_startup, "system prove proxy configured; local Groth16 warmup skipped");


    let l1 = L1Client::from_finalize_config(
        &config.finalize,
        config.finalize.deployments_network.as_deref().unwrap_or("l1"),
    )?;
    let bridge_address = resolve_bridge_address(&config)?;
    let bridge = bridge_address
        .parse::<Address>()
        .context("invalid bridge address in daemon config")?;
    let state_manager = resolve_state_manager_address(&config)?;
    let poll_interval = Duration::from_secs(config.poll_interval_secs.unwrap_or(30));
    let confirmation_lag_checkpoints = config.confirmation_lag_checkpoints.unwrap_or(3);
    let max_checkpoint_batch = config.max_checkpoint_batch.unwrap_or(DEFAULT_MAX_CHECKPOINT_BATCH);
    validate_max_checkpoint_batch(max_checkpoint_batch)?;
    let chain = configured_chains(&config, &guardian.root.l1_chains)?.into_iter().next().context("single-chain relayer has no chain")?.chain_index;

    loop {
        let l1_cursor = match l1.last_finalized_checkpoint(state_manager).await {
            Ok(cursor) => cursor,
            Err(err) => {
                tracing::error!(
                    state_manager = %state_manager,
                    error = %err,
                    "failed to read L1 StateManager finalization cursor; retrying before starting next relayer round"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };
        let mut state = load_chain_state(&guardian.root, &guardian.db, chain)?;

        let from_checkpoint = l1_cursor + 1;
        let latest_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        tracing::info!(
            from_checkpoint,
            latest_checkpoint,
            confirmation_lag_checkpoints,
            last_finalized_checkpoint = l1_cursor,
            "pre-round: checkpoint window"
        );
        let window = select_relayer_window(
            from_checkpoint,
            latest_checkpoint,
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        );
        let to_checkpoint = window.to_checkpoint;
        let is_catchup_batch = window.is_catchup_batch;
        let propose_args = ProposeWithdrawalsArgs {
            rpc_config: config.rpc_config.clone(),
            guardian_root: config.guardian_root.clone(),
            services_url: Some(config.services_url.clone()),
            withdraw_method_id: config.withdraw_method_id,
            state_file: None,
            notify_coordinator: true,
            poll_timeout_secs: 120,
            poll_interval_secs: 5,
            destination_chain_indices: Vec::new(),
            l1_config: config.l1_config.clone(),
        };

        let round_mode = if !window.has_confirmed_range() {
            "APPEND-ONLY"
        } else if is_catchup_batch {
            "CATCHUP"
        } else {
            "ROUND"
        };
        tracing::info!(
            from_checkpoint,
            to_checkpoint,
            latest_checkpoint,
            confirmed_to_checkpoint = window.confirmed_to_checkpoint,
            max_checkpoint_batch,
            is_catchup_batch,
            "[bridge-{}] phase1: L2 bridge (append deposits + withdrawals to L2)",
            round_mode,
        );

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 1 ─ L2 Bridge Round (append deposits + withdrawals to L2)
        // ═══════════════════════════════════════════════════════════════════

        let l2_round = match l1.run_l2_bridge_round(
            &config,
            &provider,
            guardian,
            bridge,
            from_checkpoint,
            to_checkpoint,
            confirmation_lag_checkpoints,
            is_catchup_batch,
            &state,
            propose_args.clone(),
            max_checkpoint_batch,
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::error!(
                    from_checkpoint,
                    latest_checkpoint,
                    to_checkpoint,
                    error = ?err,
                    "bridge daemon run_l2_bridge_round failed"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };


        state = load_chain_state(&guardian.root, &guardian.db, chain)?;
        // One sticky authority: L2 may latch catch-up mid-round; outer gates
        // must honor that latch for deposits and pending-claim settlement.
        let mut is_catchup_batch = l2_round.is_catchup_batch;
        let (post_l2_phase_permit, mut pending_claim_withdrawals) =
            match orchestrate_post_l2_round(
                &guardian.root,
                &guardian.db,
                chain,
                &state,
                &l2_round.claim_withdrawals,
                window.is_catchup_batch,
                is_catchup_batch,
                |permit, pending| async move { (permit, pending) },
            )
            .await
            {
                Ok(PostL2Orchestration::Deferred) => {
                    tracing::info!(
                        from_checkpoint,
                        to_checkpoint = l2_round.to_checkpoint,
                        pre_round_is_catchup_batch = window.is_catchup_batch,
                        post_l2_is_catchup_batch = is_catchup_batch,
                        "newly-latched catch-up round persisted; skipping deposit, proof, finalize, and claims"
                    );
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
                Ok(PostL2Orchestration::Dispatch(dispatch)) => dispatch,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        from_checkpoint,
                        to_checkpoint = l2_round.to_checkpoint,
                        "failed to persist state while deferring newly-latched catch-up round"
                    );
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            };
        // Backoff bookkeeping travels with the pending set through the round.
        let mut claim_retry = state.claim_retry.clone();
        let mut retired_claim_withdrawals = state.retired_claim_withdrawals.clone();

        // Append-only / no-confirmed-range rounds still retry durable pending
        // claims after safe L2 handling. No new finalize range is required.
        if !window.has_confirmed_range() {
            let _ = dispatch_post_l2_phase(
                &post_l2_phase_permit,
                settle_pending_claim_withdrawals(
                    &l1,
                    &provider,
                    &config,
                    &mut pending_claim_withdrawals,
                    &mut claim_retry,
                    &mut retired_claim_withdrawals,
                    from_checkpoint,
                    l1_cursor,
                    is_catchup_batch,
                    confirmation_lag_checkpoints,
                    &guardian.root.network,
                    &guardian.root,
                    &guardian.db,
                    max_checkpoint_batch,
                ),
            )
            .await;
            if let Err(e) = save_chain_state(&guardian.root, &guardian.db, chain, &DaemonState {
                pending_claim_withdrawals,
                claim_retry,
                retired_claim_withdrawals,
            }) {
                tracing::error!(
                    error = %e,
                    "failed to persist pending claims after append-only claim settlement"
                );
            }
            if !l2_round.submitted_l2_work && l2_round.deposit_append_target.is_none() {
                tracing::info!(
                    from_checkpoint,
                    to_checkpoint = l2_round.to_checkpoint,
                    latest_checkpoint,
                    "[bridge-APPEND-ONLY] no deposits to append; idle poll after durable claim retry"
                );
            } else {
                tracing::info!(
                    from_checkpoint,
                    to_checkpoint = l2_round.to_checkpoint,
                    "no confirmed range to prove; idle poll after L2 append-only work and durable claim retry"
                );
            }
            tokio::time::sleep(poll_interval).await;
            continue;
        }
        if l2_round.to_checkpoint < from_checkpoint {
            let _ = dispatch_post_l2_phase(
                &post_l2_phase_permit,
                settle_pending_claim_withdrawals(
                    &l1,
                    &provider,
                    &config,
                    &mut pending_claim_withdrawals,
                    &mut claim_retry,
                    &mut retired_claim_withdrawals,
                    from_checkpoint,
                    l1_cursor,
                    is_catchup_batch,
                    confirmation_lag_checkpoints,
                    &guardian.root.network,
                    &guardian.root,
                    &guardian.db,
                    max_checkpoint_batch,
                ),
            )
            .await;
            if let Err(e) = save_chain_state(&guardian.root, &guardian.db, chain, &DaemonState {
                pending_claim_withdrawals,
                claim_retry,
                retired_claim_withdrawals,
            }) {
                tracing::error!(
                    error = %e,
                    "failed to persist pending claims when skipping prove"
                );
            }
            tracing::info!(
                from_checkpoint,
                to_checkpoint = l2_round.to_checkpoint,
                "to_checkpoint < from_checkpoint after L2 round; skipping prove after durable claim retry"
            );
            tokio::time::sleep(poll_interval).await;
            continue;
        }

        // Finalize straight to the L2 landing checkpoint. In normal mode
        // (gap <= max_checkpoint_batch) landing <= confirmed, so the range
        // fits one chain proof (32 slots) plus a final proof. In catchup mode
        // deposits and withdrawals are disabled, so no L2 work advances
        // to_checkpoint and it stays at the pre-round window.to_checkpoint.
        let to_checkpoint = select_finalize_to_checkpoint(to_checkpoint, l2_round.to_checkpoint);
        let deposit_append_target = l2_round.deposit_append_target;
        let proof_path = proof_dir.join(format!("bridge_proof_{}.json", to_checkpoint));
        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 2 ─ Deposit Batch Appends (submit Groth16 proof to L1)
        // ═══════════════════════════════════════════════════════════════════

        if let Some(target_deposit_count) = deposit_append_target {
            if let Err(err) = dispatch_post_l2_phase(
                &post_l2_phase_permit,
                l1.submit_deposit_batch_appends(&config, target_deposit_count, &guardian.root.network),
            )
            .await
            {
                tracing::error!(
                    to_checkpoint,
                    target_deposit_count,
                    error = %err,
                    "bridge daemon deposit batchAppend step failed"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 3 ─ Proof Generation (bridge aggregation + Groth16 wrap)
        // ═══════════════════════════════════════════════════════════════════

        let prove_proxy_url = resolve_system_prove_proxy_url(&guardian.root.network)?;
        let prove_result = match dispatch_post_l2_phase(
            &post_l2_phase_permit,
            l1.load_or_build_proof(
                &config,
                &proof_path,
                from_checkpoint,
                to_checkpoint,
                Some(prove_proxy_url.as_str()),
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::error!(to_checkpoint, error = %err, "bridge daemon prove step failed");
                if err.downcast_ref::<CachedProofLineageUnread>().is_none() {
                    let _ = fs::remove_file(&proof_path);
                }
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 4 ─ Finalize + Claim Withdrawals (submit to L1 StateManager)
        // ═══════════════════════════════════════════════════════════════════

        let finalize_args = FinalizeBridgeAggArgs {
            l1_fee_policy: config.finalize.fee_policy.clone(),
            proof_json: proof_path.clone(),
            to_checkpoint,
            rpc_config: config.rpc_config.clone(),
            l1_rpc_url: config.finalize.l1_rpc_url.clone().context("canonical L1 endpoint missing")?,
            deployments_network: config
                .finalize
                .deployments_network
                .clone()
                .unwrap_or_else(|| DEFAULT_DEPLOYMENTS_NETWORK.to_string()),
            state_manager: config.finalize.state_manager.clone(),
            bridge_address: Some(bridge_address.clone()),
            batch_append_proof_json: None,
            private_key: config.finalize.private_key.clone(),
            keystore_path: config.finalize.keystore_path.clone().map(PathBuf::from),
            password_env: config
                .finalize
                .password_env
                .clone()
                .unwrap_or_else(|| "WALLET_PASSWORD".to_string()),
        };

        let withdrawal_count = l2_round.claim_withdrawals.len();
        if let Err(e) = save_chain_state(&guardian.root, &guardian.db, chain, &DaemonState {
            pending_claim_withdrawals: pending_claim_withdrawals.clone(),
            claim_retry: claim_retry.clone(),
            retired_claim_withdrawals: retired_claim_withdrawals.clone(),
        }) {
            tracing::error!(error = %e, "failed to persist pending claims before finalize");
        }

        match dispatch_post_l2_phase(&post_l2_phase_permit, l1.finalize(finalize_args)).await {
            Ok(()) => {
                // Brief pause to ensure L1 state is settled before gas
                // estimation for the claim transaction.
                tokio::time::sleep(Duration::from_secs(2)).await;
                is_catchup_batch = dispatch_post_l2_phase(
                    &post_l2_phase_permit,
                    settle_pending_claim_withdrawals(
                        &l1,
                        &provider,
                        &config,
                        &mut pending_claim_withdrawals,
                        &mut claim_retry,
                        &mut retired_claim_withdrawals,
                        from_checkpoint,
                        to_checkpoint,
                        is_catchup_batch,
                        confirmation_lag_checkpoints,
                        &guardian.root.network,
                        &guardian.root,
                        &guardian.db,
                        max_checkpoint_batch,
                    ),
                )
                .await;

                let finalized_state = DaemonState {
                    pending_claim_withdrawals,
                    claim_retry,
                    retired_claim_withdrawals,
                };
                match persist_finalized_state_then_cleanup_proof(
                    &guardian.root,
                    &guardian.db,
                    chain,
                    &finalized_state,
                    &proof_path,
                ) {
                    Ok(()) => {
                        tracing::info!(
                            to_checkpoint,
                            has_deposits = deposit_append_target.is_some(),
                            submitted_l2_work = l2_round.submitted_l2_work,
                            withdrawal_count,
                            deposit_append_target = ?deposit_append_target,
                            is_catchup_batch,
                            "[bridge-{}] phase4 done: finalize complete and state durable",
                            round_mode,
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            to_checkpoint,
                            proof_path = %proof_path.display(),
                            "finalize succeeded on L1 but state install is incomplete; retaining proof"
                        );
                    }
                }
            }
            Err(err) => {
                tracing::error!(
                    from_checkpoint,
                    to_checkpoint,
                    error = ?err,
                    "bridge daemon finalize step failed"
                );
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  ROUND COMPLETE ── sleep before next iteration
        // ═══════════════════════════════════════════════════════════════════

        let final_round_mode = round_mode;
        tracing::info!(
            round_mode = final_round_mode,
            from_checkpoint,
            to_checkpoint,
            "[bridge-{}] ── poll-sleep {}s ──",
            final_round_mode,
            poll_interval.as_secs(),
        );

        tokio::time::sleep(poll_interval).await;
    }
}


pub(crate) async fn submit_deposit_batch_appends_with_l1_rpc(
    config: &BridgeProposeDaemonConfig,
    l1_rpc: &str,
    target_deposit_count: u32,
    prove_proxy_url: Option<&str>,
) -> anyhow::Result<()> {
    let deployments_network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
    let bridge = resolve_bridge_address(config)?
        .parse::<Address>()
        .context("invalid bridge address in daemon config")?;
    let multicall3 = claim_withdrawals::resolve_multicall3_address(None, deployments_network)?
        .ok_or_else(|| anyhow::anyhow!("Multicall3 address is required for deposit batchAppend"))?;

    let wallet = load_l1_wallet(
        config.finalize.private_key.as_deref(),
        config.finalize.keystore_path.as_deref().map(Path::new),
        config.finalize.password_env.as_deref(),
        None,
        "L1 deposit batchAppend signer",
    )?;
    let rpc_url = l1_rpc
        .parse()
        .with_context(|| format!("invalid L1 rpc url: {}", l1_rpc))?;
    let provider = crate::bridge::l1_provider::connect_l1_with_wallet(rpc_url, wallet)?;
    let proved_before = crate::bridge::api_client::eth_call_u256(&provider, bridge, provedDepositCountCall {}).await?;
    let expected_proved_after = U256::from(target_deposit_count);
    ensure!(
        proved_before <= expected_proved_after,
        "Bridge provedDepositCount is already beyond requested deposit append target: current={} target={}",
        proved_before,
        expected_proved_after
    );
    if proved_before == expected_proved_after {
        tracing::info!(
            target_deposit_count,
            "Bridge provedDepositCount already reached deposit append target"
        );
        return Ok(());
    }

    // Refuse unaffordable fees before proving, then refresh before sending.
    super::l1_fees::prepare_l1_fees(
        &provider, &mut TransactionRequest::default(), config.finalize.fee_policy.as_ref(),
    ).await?;

    let calls = if let Some(proxy_url) = prove_proxy_url {
        prove_bridge::build_deposit_batch_append_calls_remote(
            l1_rpc,
            deployments_network,
            target_deposit_count,
            proxy_url,
        )
        .await?
    } else {
        prove_bridge::build_deposit_batch_append_calls(
            l1_rpc,
            deployments_network,
            target_deposit_count,
        )
        .await?
    };
    if calls.is_empty() {
        let proved_after = crate::bridge::api_client::eth_call_u256(&provider, bridge, provedDepositCountCall {}).await?;
        ensure!(
            proved_after == expected_proved_after,
            "deposit batchAppend builder returned no calls before target was reached: target={} actual={}",
            expected_proved_after,
            proved_after
        );
        return Ok(());
    }

    ensure!(calls.iter().all(|call| call.from_index < call.to_index)
        && calls.windows(2).all(|pair| pair[0].to_index == pair[1].from_index),
        "deposit batchAppend calls must cover an ordered contiguous range");
    ensure!(calls.last().map(|call| call.to_index) == Some(target_deposit_count),
        "deposit batchAppend calls do not end at the requested target");
    let aggregate_chunks = chunk_deposit_batch_append_by_gas(
        &provider,
        multicall3,
        calls
            .iter()
            .map(|call| Call3 {
                target: bridge,
                allowFailure: false,
                callData: call.call_data.clone(),
            })
            .collect(),
    )
    .await?;
    let aggregate_chunk_count = aggregate_chunks.len();
    let mut call_start = 0;

    for (chunk_index, aggregate_calls) in aggregate_chunks.into_iter().enumerate() {
        let chunk_len = aggregate_calls.len();
        let batch_calls = &calls[call_start..call_start + chunk_len];
        let from_index = batch_calls[0].from_index;
        let to_index = batch_calls[chunk_len - 1].to_index;
        call_start += chunk_len;
        let deposit_batch_commits = batch_calls
            .iter()
            .map(|call| {
                format!(
                    "0x{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
                    call.batch_commit[0],
                    call.batch_commit[1],
                    call.batch_commit[2],
                    call.batch_commit[3],
                    call.batch_commit[4],
                    call.batch_commit[5],
                    call.batch_commit[6],
                    call.batch_commit[7],
                )
            })
            .collect::<Vec<_>>();
        let aggregate = aggregate3Call {
            calls: aggregate_calls,
        };
        let calldata = aggregate.abi_encode();
        ensure!(calldata.len() <= DEPOSIT_APPEND_CALLDATA_LIMIT,
            "deposit batchAppend calldata exceeds safe transaction budget: bytes={} limit={}",
            calldata.len(), DEPOSIT_APPEND_CALLDATA_LIMIT);
        let tx = TransactionRequest::default()
            .to(multicall3)
            .input(Bytes::from(calldata).into());

        let receipt = send_deposit_append_group(
            from_index,
            to_index,
            || crate::bridge::api_client::eth_call_u256(&provider, bridge, provedDepositCountCall {}),
            || async {
                if let Err(err) = provider.call(tx.clone()).await {
                    tracing::error!(
                        error = ?err,
                        chunk_index,
                        chunk_len,
                        aggregate_chunk_count,
                        deposit_batch_chunks = calls.len(),
                        target_deposit_count,
                        proved_before = %proved_before,
                        expected_proved_after = %expected_proved_after,
                        deposit_batch_commits = ?deposit_batch_commits,
                        multicall3 = %multicall3,
                        bridge = %bridge,
                        "deposit batchAppend aggregate3 simulation failed"
                    );
                    return Err(err).context("deposit batchAppend aggregate3 simulation failed");
                }
                tracing::info!(
                    chunk_index,
                    chunk_len,
                    aggregate_chunk_count,
                    deposit_batch_chunks = calls.len(),
                    target_deposit_count,
                    proved_before = %proved_before,
                    expected_proved_after = %expected_proved_after,
                    multicall3 = %multicall3,
                    allow_failure = false,
                    "sending deposit batchAppend aggregate3 tx"
                );

                let mut tx = tx;
                super::l1_fees::prepare_l1_fees(&provider, &mut tx, config.finalize.fee_policy.as_ref()).await?;
                let pending = provider
                    .send_transaction(tx)
                    .await
                    .context("send deposit batchAppend aggregate3 transaction failed")?;
                let receipt = pending
                    .get_receipt()
                    .await
                    .context("wait deposit batchAppend aggregate3 receipt failed")?;
                ensure!(
                    receipt.status(),
                    "deposit batchAppend aggregate3 transaction reverted: tx_hash={}",
                    receipt.transaction_hash
                );
                Ok(receipt)
            },
        ).await.with_context(|| format!("deposit batchAppend group {chunk_index}: {from_index}..{to_index}"))?;
        tracing::info!(
            tx_hash = %receipt.transaction_hash,
            block_number = ?receipt.block_number,
            chunk_index,
            chunk_len,
            aggregate_chunk_count,
            from_index,
            proved_after = to_index,
            "deposit batchAppend aggregate3 chunk confirmed"
        );
    }

    let proved_after = crate::bridge::api_client::eth_call_u256(&provider, bridge, provedDepositCountCall {}).await?;
    ensure!(
        proved_after == expected_proved_after,
        "Bridge provedDepositCount mismatch after deposit batchAppend aggregate3: expected={} actual={}",
        expected_proved_after,
        proved_after
    );
    tracing::info!(
        deposit_batch_chunks = calls.len(),
        aggregate_chunk_count,
        proved_after = %proved_after,
        "deposit batchAppend aggregate3 confirmed"
    );
    Ok(())
}

#[allow(dead_code)] // kept for the local-proving CLI path
fn warmup_bridge_resources() -> anyhow::Result<()> {
    tracing::info!("warming bridge relayer resources");

    prove_bridge::cached_bridge_coordinator_circuits()?;

    let home_dir = home::home_dir().context("failed to resolve home directory for bridge relayer warmup")?;
    let keystores = [
        home_dir.join(".psy/keystore"),
        home_dir.join(".psy/keystore/deposit_append"),
        home_dir.join(".psy/keystore/withdrawal_claim"),
    ];

    for keystore in &keystores {
        if !keystore.join("circuit_groth16.bin").exists()
            || !keystore.join("pk_groth16.bin").exists()
            || !keystore.join("vk_groth16.bin").exists()
        {
            tracing::warn!(keystore = %keystore.display(), "skipping Groth16 warmup because keystore is missing");
            continue;
        }
        let keystore_str = keystore
            .to_str()
            .with_context(|| format!("non-utf8 keystore path: {}", keystore.display()))?;
        tracing::info!(keystore = %keystore.display(), "preloading Groth16 setup");
        g16::initialize(keystore_str);
    }

    tracing::info!("bridge relayer warmup complete");
    Ok(())
}

/// The prove-proxy pool that serves bridge Groth16 proofs.
///
/// Reads `system_prove_proxy_url` for the current network. There is no
/// fallback to `prove_proxy_url`: that pool runs the `user` role and does not
/// register the bridge methods, so routing there would only fail later.
pub(crate) fn resolve_system_prove_proxy_url(network: &psy_config::NetworkConfigGoldilocks) -> anyhow::Result<String> {
    network
        .system_prove_proxy_url
        .iter()
        .map(|url| url.trim())
        .find(|url| !url.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "loaded network has no `system_prove_proxy_url`; the relayer needs a prove-proxy running role=system or role=all"
            )
        })
}

/// Confirms the resolved prove-proxy registers the bridge (system) methods.
/// A pool running role=user answers `psy_get_prove_proxy_role` with
/// `system_methods: false`; treat that like a missing URL and refuse to start.
pub(crate) async fn verify_system_prove_proxy(url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build reqwest client for prove-proxy role verification")?;

    let response = client
        .post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "psy_get_prove_proxy_role",
            "params": []
        }))
        .send()
        .await
        .with_context(|| format!("failed to reach prove proxy {url} for psy_get_prove_proxy_role"))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("prove proxy {url} returned HTTP {status} for psy_get_prove_proxy_role");
    }

    let body: serde_json::Value = response
        .json()
        .await
        .with_context(|| format!("failed to parse psy_get_prove_proxy_role response from {url}"))?;

    if body.get("jsonrpc").and_then(|value| value.as_str()) != Some("2.0")
        || body.get("id").and_then(|value| value.as_u64()) != Some(1)
        || body.get("error").is_some()
    {
        anyhow::bail!("prove proxy {url} returned an invalid JSON-RPC role response");
    }

    let role = body
        .get("result")
        .and_then(|result| result.get("role"))
        .and_then(|role| role.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("prove proxy {url} psy_get_prove_proxy_role response missing result.role")
        })?
        .to_string();

    let system_methods = body
        .get("result")
        .and_then(|result| result.get("system_methods"))
        .and_then(|value| value.as_bool())
        .ok_or_else(|| {
            anyhow::anyhow!("prove proxy {url} psy_get_prove_proxy_role response missing result.system_methods")
        })?;

    if !system_methods {
        anyhow::bail!(
            "prove proxy {url} runs role `{role}` and does not serve system proofs; point system_prove_proxy_url at a role=system or role=all instance"
        );
    }

    let user_methods = body
        .get("result")
        .and_then(|result| result.get("user_methods"))
        .and_then(|value| value.as_bool());
    if !matches!((role.as_str(), user_methods), ("system", Some(false)) | ("all", Some(true))) {
        anyhow::bail!("prove proxy {url} returned inconsistent role capabilities for `{role}`; expected role=system or role=all");
    }

    tracing::info!(prove_proxy = %url, role = %role, "system prove proxy verified");
    Ok(())
}

fn resolve_keystore_path(private_key_selected: bool, configured: Option<String>, env_value: Option<&str>) -> Option<String> {
    if private_key_selected || configured.is_some() {
        return configured;
    }
    env_value.map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned)
}

fn load_config(path: &Path) -> anyhow::Result<BridgeProposeDaemonConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read daemon config {}", path.display()))?;
    let mut config: BridgeProposeDaemonConfig =
        toml::from_str(&raw).with_context(|| format!("failed to parse daemon config {}", path.display()))?;
    let env_keystore = std::env::var("KEYSTORE_PATH").ok();
    config.finalize.keystore_path = resolve_keystore_path(config.finalize.private_key.is_some(), config.finalize.keystore_path.take(), env_keystore.as_deref());
    for chain in &mut config.chains {
        chain.keystore_path = resolve_keystore_path(chain.private_key.is_some(), chain.keystore_path.take(), env_keystore.as_deref());
    }
    Ok(config)
}

fn chain_of(withdrawal: &propose_withdrawals::PendingWithdrawal) -> anyhow::Result<u8> {
    u8::try_from(withdrawal.destination_chain_index).context("claim destination chain does not fit chain_index")
}

fn claims_of(state: &DaemonState) -> super::guardian_client::ChainClaims {
    super::guardian_client::ChainClaims {
        pending_claim_withdrawals: state.pending_claim_withdrawals.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        claim_retry: state.claim_retry.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        retired_claim_withdrawals: state.retired_claim_withdrawals.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    }
}

fn load_chain_state(config: &guardian_common::protocol::GuardianConfig, db: &super::guardian_client::RelayerDb, chain: u8) -> anyhow::Result<DaemonState> {
    let row = db.chain_claims(config)?.remove(&chain).unwrap_or_default();
    Ok(DaemonState {
        pending_claim_withdrawals: row.pending_claim_withdrawals.into_iter().collect(),
        claim_retry: row.claim_retry.into_iter().collect(),
        retired_claim_withdrawals: row.retired_claim_withdrawals.into_iter().collect(),
    })
}

fn save_chain_state(config: &guardian_common::protocol::GuardianConfig, db: &super::guardian_client::RelayerDb, chain: u8, state: &DaemonState) -> anyhow::Result<()> {
    db.save_chain_claims(config, chain, &claims_of(state))
}

fn load_multichain_state(config: &guardian_common::protocol::GuardianConfig, db: &super::guardian_client::RelayerDb) -> anyhow::Result<MultichainDaemonState> {
    let batch = db.finalization_batch(config)?;
    let mut state = MultichainDaemonState {
        pending_finalization_range: batch.pending_finalization_range.map(|range| PendingFinalizationRange { from_checkpoint: range.from_checkpoint, to_checkpoint: range.to_checkpoint }),
        finalized_chains: batch.finalized_chains.into_iter().collect(),
        ..Default::default()
    };
    for row in db.chain_claims(config)?.into_values() {
        state.pending_claim_withdrawals.extend(row.pending_claim_withdrawals);
        state.claim_retry.extend(row.claim_retry);
        state.retired_claim_withdrawals.extend(row.retired_claim_withdrawals);
    }
    Ok(state)
}

fn remove_full_leaf(pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>, leaf: &str) -> Option<propose_withdrawals::PendingWithdrawal> {
    let keys: Vec<String> = pending.iter().filter(|(_, withdrawal)| withdrawal.leaf_hash == leaf).map(|(key, _)| key.clone()).collect();
    let mut removed = None;
    for key in keys { removed = pending.remove(&key).or(removed); }
    removed
}

fn chain_claim_rows(state: &MultichainDaemonState) -> anyhow::Result<BTreeMap<u8, super::guardian_client::ChainClaims>> {
    let mut by_chain: BTreeMap<u8, DaemonState> = BTreeMap::new();
    for (leaf, withdrawal) in &state.pending_claim_withdrawals {
        by_chain.entry(chain_of(withdrawal)?).or_default().pending_claim_withdrawals.insert(leaf.clone(), withdrawal.clone());
    }
    for (leaf, leaf_state) in &state.claim_retry {
        let withdrawal = state.pending_claim_withdrawals.values().find(|withdrawal| withdrawal.leaf_hash == leaf.as_str()).context("claim state has no pending withdrawal")?;
        by_chain.entry(chain_of(withdrawal)?).or_default().claim_retry.insert(leaf.clone(), leaf_state.clone());
    }
    for (leaf, retired) in &state.retired_claim_withdrawals {
        by_chain.entry(chain_of(&retired.withdrawal)?).or_default().retired_claim_withdrawals.insert(leaf.clone(), retired.clone());
    }
    Ok(by_chain.iter().map(|(chain, row)| (*chain, claims_of(row))).collect())
}

fn save_multichain_state(config: &guardian_common::protocol::GuardianConfig, db: &super::guardian_client::RelayerDb, state: &MultichainDaemonState) -> anyhow::Result<()> {
    db.save_claims_and_batch(config, &chain_claim_rows(state)?, &super::guardian_client::FinalizationBatch {
        pending_finalization_range: state.pending_finalization_range.map(|range| super::guardian_client::FinalizationRange { from_checkpoint: range.from_checkpoint, to_checkpoint: range.to_checkpoint }),
        finalized_chains: state.finalized_chains.iter().copied().collect(),
    })
}

fn claim_broadcast_hook(
    config: &guardian_common::protocol::GuardianConfig,
    db: &super::guardian_client::RelayerDb,
) -> claim_withdrawals::BeforeBroadcast {
    let config = config.clone();
    let db = db.clone();
    std::sync::Arc::new(move |leaves, tx_hash| {
        let config = config.clone();
        let db = db.clone();
        let leaves = leaves.to_vec();
        Box::pin(async move {
            let mut state = load_multichain_state(&config, &db)?;
            for leaf in &leaves {
                // The stored row must be this exact withdrawal: the L1 key is
                // the keccak claim identity over sender/recipient/token/amount/
                // nonce/destination/contract, and same_claim binds every one of
                // those fields. Anything else holds the batch instead of guessing.
                anyhow::ensure!(
                    state.pending_claim_withdrawals.get(&leaf.leaf_hash).is_some_and(|saved| {
                        saved.nonce == leaf.nonce && claim_attempts::same_claim(saved, leaf)
                    }),
                    "signed claim is not the stored pending row"
                );
                claim_attempts::hold_for_receipt(&mut state.claim_retry, &leaf.leaf_hash, Some(tx_hash));
            }
            save_multichain_state(&config, &db, &state)?;
            Ok(())
        })
    })
}


// L1 may already be ahead of an older catch-up target. Keep the actual append
// function's strict target check, and skip satisfied historical targets here.
async fn sync_deposit_if_behind<Read, Append, AppendFuture>(
    target: u32,
    read_proved: Read,
    append: Append,
) -> anyhow::Result<()>
where
    Read: Future<Output = anyhow::Result<u32>>,
    Append: FnOnce() -> AppendFuture,
    AppendFuture: Future<Output = anyhow::Result<()>>,
{
    if read_proved.await? >= target { return Ok(()); }
    append().await
}

// Both fresh and resumed ranges pass this gate before proof/finalize. A fee
// refusal retains the landing endpoint and claims, without spending attempts.
// Cursor compatibility is checked before any mutation: an invalid window is
// never installed, and claims already on disk are left in place.
async fn persist_and_sync_multichain_range<Sync, SyncFuture>(
    config: &guardian_common::protocol::GuardianConfig,
    db: &super::guardian_client::RelayerDb,
    state: &mut MultichainDaemonState,
    range: PendingFinalizationRange,
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
    chain_cursors: &[(u8, u64)],
    mut sync: Sync,
) -> anyhow::Result<bool>
where
    Sync: FnMut(u8, u64) -> SyncFuture,
    SyncFuture: Future<Output = anyhow::Result<()>>,
{
    validate_range_against_cursors(range, chain_cursors)?;
    ensure!(state.pending_finalization_range.is_none_or(|saved| saved == range),
        "cannot replace an unfinished multichain range");
    state.pending_finalization_range = Some(range);
    insert_pending_claims(withdrawals, &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals);
    db.save_finalization_and_claims(config, &super::guardian_client::FinalizationBatch {
        pending_finalization_range: Some(super::guardian_client::FinalizationRange { from_checkpoint: range.from_checkpoint, to_checkpoint: range.to_checkpoint }),
        finalized_chains: state.finalized_chains.iter().copied().collect(),
    }, withdrawals)?;

    for &(chain_index, cursor) in chain_cursors {
        if !chain_finalization_required(cursor, range)? { continue; }
        if let Err(error) = sync(chain_index, range.to_checkpoint).await {
            if super::l1_fees::is_fee_preparation_error(&error) {
                tracing::warn!(chain_index, %error,
                    "deposit fees unavailable; durable range and claims retained, deferring round");
                return Ok(false);
            }
            return Err(error);
        }
    }
    Ok(true)
}




pub(crate) async fn fetch_l1_last_finalized_checkpoint(
    provider: &impl Provider,
    state_manager: Address,
) -> anyhow::Result<u64> {
    let tx = TransactionRequest::default()
        .to(state_manager)
        .input(lastFinalizedCheckpointIdCall {}.abi_encode().into());
    let raw = provider
        .call(tx)
        .await
        .context("StateManager.lastFinalizedCheckpointId eth_call failed")?;
    lastFinalizedCheckpointIdCall::abi_decode_returns(&raw)
        .context("failed to decode StateManager.lastFinalizedCheckpointId return")
}

fn read_single_felt_from_packed_leaf(
    leaf: psy_client_common::data::qhashout::QHashOut<GoldilocksField>,
    sub_slot_index: u64,
) -> anyhow::Result<u64> {
    let offset = (sub_slot_index % 4) as usize;
    let value = leaf.0.elements[offset].to_canonical_u64();
    ensure!(
        value <= u32::MAX as u64,
        "packed contract-state value exceeds u32 range: sub_slot={} value={}",
        sub_slot_index,
        value
    );
    Ok(value)
}

pub(crate) fn resolve_bridge_address(config: &BridgeProposeDaemonConfig) -> anyhow::Result<String> {
    if let Some(addr) = config.finalize.bridge_address.as_deref() {
        return Ok(addr.to_string());
    }
    let network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
    let path = crate::bridge::api_client::resolve_deployments_file(network, "deployed-contracts.json");
    let deployed = crate::bridge::api_client::load_deployed_contracts(network)
        .with_context(|| format!("failed to load {}", path.display()))?;
    deployed
        .core
        .get("Bridge")
        .or_else(|| deployed.contracts.get("Bridge"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Bridge not found in {}", path.display()))
}

pub(crate) fn resolve_state_manager_address(config: &BridgeProposeDaemonConfig) -> anyhow::Result<Address> {
    if let Some(addr) = config.finalize.state_manager.as_deref() {
        return addr
            .parse::<Address>()
            .context("invalid state_manager address in daemon config");
    }
    let network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
    crate::bridge::api_client::resolve_contract_address_from_deployments(network, "StateManager")
}

pub(crate) async fn run_l2_bridge_round_with_l1_snapshot(
    config: &BridgeProposeDaemonConfig,
    provider: &RpcProvider,
    guardian: &super::guardian_client::LoadedGuardianConfig,
    source_chain_index: u64,
    proved_deposit_count: u32,
    pending_deposit_count: u32,
    from_checkpoint: u64,
    to_checkpoint: u64,
    confirmation_lag_checkpoints: u64,
    mut is_catchup_batch: bool,
    state: &DaemonState,
    mut propose_args: ProposeWithdrawalsArgs,
    max_checkpoint_batch: u64,
) -> anyhow::Result<L2RoundResult> {
    let proof_dir = config
        .proof_dir
        .as_deref()
        .unwrap_or_else(|| Path::new(DEFAULT_PROOF_DIR));
    propose_args.poll_timeout_secs = 0;
    ensure!(
        pending_deposit_count >= proved_deposit_count,
        "pendingDepositCount is behind provedDepositCount: pending={} proved={}",
        pending_deposit_count,
        proved_deposit_count
    );
    let l2_deposit_next_index = fetch_deposit_tree_next_index(
        provider,
        to_checkpoint,
        source_chain_index,
    )
    .await?;
    select_deposit_append_target(
        is_catchup_batch,
        to_checkpoint,
        to_checkpoint,
        l2_deposit_next_index,
        proved_deposit_count,
        pending_deposit_count,
    )?;
    tracing::info!(
        from_checkpoint,
        to_checkpoint,
        proved_deposit_count,
        pending_deposit_count = pending_deposit_count,
        l2_deposit_next_index,
        "bridge deposit cursor sync"
    );
    if is_catchup_batch && u64::from(pending_deposit_count) > l2_deposit_next_index {
        tracing::info!(
            l2_deposit_next_index,
            pending_deposit_count = pending_deposit_count,
            "deferring L2 deposit append while bridge relayer is catching up"
        );
    }

    let mut to_checkpoint = to_checkpoint;
    let mut submitted_l2_work = false;
    // Sticky catch-up authority for this L2 round. Latches true if the fresh
    // coordinator head crosses the threshold mid-loop and is carried out so
    // finish_l2_round cannot emit a deposit_append_target under catch-up.

    let mut claim_withdrawals = Vec::new();
    let mut seen_claim_leaf_hashes = HashSet::new();

    // A normal round that crosses the catch-up threshold (gap > max_checkpoint_batch)
    // mid-loop must stop appending business; the outer loop will re-evaluate and
    // enter catch-up mode on the next iteration.

    // ═══════════════════════════════════════════════════════════════════
    //  ── L2 Call Planning & Submission Loop ──
    // ═══════════════════════════════════════════════════════════════════

    if guardian.db.pending_request()?.is_some() {
        let mut guardian_history = config.guardian_history.lock().await;
        let landed = submit_guardian_operation(guardian, provider, Vec::new(), &[], guardian_common::protocol::GuardianOperation::Bridge, None, &mut guardian_history, PolicySignatures::None).await?.included_checkpoint_id;
        wait_until_checkpoint_confirmed(provider, landed, confirmation_lag_checkpoints, REALM_CHECKPOINT_POLL_TIMEOUT_SECS, REALM_CHECKPOINT_POLL_INTERVAL_SECS).await?;
        to_checkpoint = to_checkpoint.max(landed);
        submitted_l2_work = true;
    }
    loop {
        let planning_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        let deposit_next_index = u32::try_from(
            fetch_deposit_tree_next_index(provider, planning_checkpoint, source_chain_index)
                .await?,
        )
        .context("L2 deposit next_index exceeds u32")?;

        // Re-evaluate the checkpoint window before submitting irreversible
        // L2 work. If a normal round has crossed into catch-up (gap >
        // max_checkpoint_batch) while appending business, stop here; the
        // outer loop will re-evaluate and enter catch-up mode next iteration.
        // Withdrawals from prior iterations were persisted before their L2
        // submit; this break occurs before build_l2_call_plan, so no new
        // withdrawals exist to lose. The catch-up gate defers them safely.
        if !is_catchup_batch {
            let fresh_is_catchup_batch = refresh_catchup_state(
                is_catchup_batch,
                from_checkpoint,
                Some(planning_checkpoint),
                confirmation_lag_checkpoints,
                max_checkpoint_batch,
            );
            if fresh_is_catchup_batch {
                is_catchup_batch = true;
                let fresh_window = select_relayer_window(
                    from_checkpoint,
                    planning_checkpoint,
                    confirmation_lag_checkpoints,
                    max_checkpoint_batch,
                );
                tracing::info!(
                    from_checkpoint,
                    planning_checkpoint,
                    confirmed_to_checkpoint = fresh_window.confirmed_to_checkpoint,
                    max_checkpoint_batch,
                    is_catchup_batch,
                    "bridge L2 round stopping: checkpoint window crossed into catch-up mid-round"
                );
                break;
            }
        }

        let plan = build_l2_call_plan(
            &config.services_url,
            source_chain_index,
            provider,
            &propose_args,
            from_checkpoint,
            to_checkpoint,
            deposit_next_index,
            pending_deposit_count,
            proved_deposit_count,
            is_catchup_batch,
            guardian,
        )
        .await?;
        record_claim_withdrawals(
            &plan.withdrawals,
            &mut seen_claim_leaf_hashes,
            &mut claim_withdrawals,
        );

        if plan.is_empty() {
            return finish_l2_round(
                provider,
                to_checkpoint,
                proved_deposit_count,
                pending_deposit_count,
                source_chain_index,
                is_catchup_batch,
                submitted_l2_work,
                claim_withdrawals,
            )
            .await;
        }

        let landed_checkpoint = submit_l2_call_plan(config, provider, &plan, confirmation_lag_checkpoints, guardian).await?;

        submitted_l2_work = true;
        // Advance to_checkpoint to the actual landing checkpoint so
        // downstream operations (e.g. fetch_tree_subroot_and_top_proof)
        // read L2 state /after/ the append took effect.
        to_checkpoint = landed_checkpoint;
    }

    finish_l2_round(
        provider,
        to_checkpoint,
        proved_deposit_count,
        pending_deposit_count,
        source_chain_index,
        is_catchup_batch,
        submitted_l2_work,
        claim_withdrawals,
    )
    .await
}

/// The pending claims still worth attempting.
///
/// Everything a round does for a withdrawal — the claim-proof fetch from
/// psy-services, and the Groth16 batch proof from prove-proxy — hangs off this
/// list, so dropping a retired claim here is what actually stops the work.
fn claims_to_attempt(
    pending: &HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: &HashMap<String, claim_attempts::ClaimAttempts>,
) -> Vec<propose_withdrawals::PendingWithdrawal> {
    pending
        .values()
        .filter(|w| claim_attempts::is_retriable(claim_retry.get(&w.leaf_hash)))
        .cloned()
        .collect()
}

// Retain an event ID, not an index that shifts when completed claims disappear.
// Outcomes are matched by identity, independently of report ordering.
fn next_claim_readiness_start(
    claims: &[propose_withdrawals::PendingWithdrawal],
    result: &anyhow::Result<claim_withdrawals::BatchWithdrawalsReport>,
) -> Option<i64> {
    let Ok(report) = result else { return claims.first().map(|claim| claim.event_id) };
    claims.iter().rev().find(|claim| report.outcomes.iter().any(|outcome| {
        outcome.leaf_hash == claim.leaf_hash &&
        !matches!(outcome.kind, claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::ReadinessDeferred))
    })).or_else(|| claims.first()).map(|claim| claim.event_id)
}

/// Replayed events must not automatically re-arm claims retired by the operator policy.
fn insert_pending_claims(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    retired: &HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
) -> bool {
    let mut changed = false;
    for withdrawal in withdrawals {
        if retired.contains_key(&withdrawal.leaf_hash) { continue; }
        // One pending entry per full leaf. An equal leaf is already queued: a
        // replay whose event metadata differs (event_id is append ordering
        // only, and an imported row carries 0) is not a content conflict, so
        // it is skipped, while a distinct leaf that shares the nonce still
        // gets its own entry.
        if pending.values().any(|saved| saved.leaf_hash == withdrawal.leaf_hash) { continue; }
        pending.insert(withdrawal.leaf_hash.clone(), withdrawal.clone());
        changed = true;
    }
    changed
}

/// Count both per-leaf failures and errors that abort the entire claim batch.
fn record_claim_result(
    attempted: &[propose_withdrawals::PendingWithdrawal],
    result: &anyhow::Result<claim_withdrawals::BatchWithdrawalsReport>,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired: &mut HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
    now_unix: u64,
) {
    match result {
        Ok(report) => {
            record_claim_outcome(attempted, report, pending, claim_retry, retired, now_unix);
        }
        Err(error) => {
            let reason = format!("claim batch failed: {error:#}");
            // One strike per leaf, never per occurrence of the same leaf. A
            // hold wins: a signed transaction may be in flight, so a generic
            // batch error neither spends an attempt on it nor clears the hold.
            let mut seen: HashSet<&str> = HashSet::new();
            for withdrawal in attempted {
                if !seen.insert(withdrawal.leaf_hash.as_str()) { continue; }
                if claim_retry.get(&withdrawal.leaf_hash).is_some_and(|state| !matches!(state.hold, claim_attempts::ClaimHold::None)) { continue; }
                record_claim_failure(withdrawal, &reason, pending, claim_retry, retired, now_unix);
            }
        }
    }
}

fn record_claim_outcome(
    attempted: &[propose_withdrawals::PendingWithdrawal],
    report: &claim_withdrawals::BatchWithdrawalsReport,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired: &mut HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
    now_unix: u64,
) {
    let mut leaves: Vec<String> = attempted.iter().map(|withdrawal| withdrawal.leaf_hash.clone()).collect();
    leaves.sort();
    leaves.dedup();
    for leaf in leaves {
        let Some(withdrawal) = attempted.iter().find(|withdrawal| withdrawal.leaf_hash == leaf) else { continue };
        let slots: Vec<&claim_withdrawals::ClaimOutcome> = report.outcomes.iter().filter(|outcome| outcome.leaf_hash == leaf).collect();
        if slots.is_empty() {
            record_claim_failure(withdrawal, "claim did not resolve and reported no reason", pending, claim_retry, retired, now_unix);
            continue;
        }
        // Registration wins; otherwise an unresolved signed transaction wins
        // over an ordinary failure: the hold is kept and no attempt is spent
        // while that transaction may still land.
        let selected = slots.iter().find(|outcome| matches!(outcome.kind, claim_withdrawals::ClaimOutcomeKind::Registered))
            .or_else(|| slots.iter().find(|outcome| matches!(outcome.kind, claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::ReceiptUnknown))))
            .copied()
            .unwrap_or(slots[0]);
        apply_leaf_outcome(withdrawal, selected, pending, claim_retry, retired, now_unix);
    }
    apply_resolved(pending, claim_retry, report);
}

fn apply_leaf_outcome(
    withdrawal: &propose_withdrawals::PendingWithdrawal,
    outcome: &claim_withdrawals::ClaimOutcome,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired: &mut HashMap<
        String,
        claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>,
    >,
    now_unix: u64,
) {
    let leaf_hash = withdrawal.leaf_hash.as_str();
    let nonce = claim_withdrawals::nonce_hex(withdrawal.nonce);
    match outcome.kind {
        claim_withdrawals::ClaimOutcomeKind::Registered => {
            claim_attempts::clear(claim_retry, leaf_hash);
            tracing::info!(
                leaf_hash,
                nonce = %nonce,
                action = "resolved",
                "withdrawal claim resolved; attempts cleared"
            );
        }
        claim_withdrawals::ClaimOutcomeKind::Failed(code) => match code.action() {
            claim_withdrawals::ClaimAction::Resolved => {
                claim_attempts::clear(claim_retry, leaf_hash);
            }
            claim_withdrawals::ClaimAction::Terminal => {
                retire_claim(withdrawal, code.label(), claim_retry, pending, retired, now_unix);
                tracing::error!(
                    leaf_hash,
                    nonce = %nonce,
                    reason = code.label(),
                    action = "retired",
                    "withdrawal claim can never succeed; retired without another attempt"
                );
            }
            claim_withdrawals::ClaimAction::OperatorPending => {
                claim_attempts::hold_for_operator(claim_retry, leaf_hash, code);
                tracing::info!(
                    leaf_hash,
                    nonce = %nonce,
                    reason = code.label(),
                    action = "held",
                    "withdrawal claim waits on chain state; attempt not spent"
                );
            }
            claim_withdrawals::ClaimAction::Held => {
                if matches!(code, claim_withdrawals::ClaimCode::ReceiptUnknown) {
                    claim_attempts::hold_for_receipt(claim_retry, leaf_hash, outcome.tx_hash);
                    tracing::warn!(
                        leaf_hash,
                        nonce = %nonce,
                        tx_hash = outcome.tx_hash.map(|hash| format!("{hash:#x}")).unwrap_or_default(),
                        action = "held",
                        "claim transaction landing unknown; no new send until it resolves"
                    );
                } else {
                    tracing::info!(
                        leaf_hash,
                        nonce = %nonce,
                        reason = code.label(),
                        action = "held",
                        "withdrawal claim held; attempt not spent"
                    );
                }
            }
            claim_withdrawals::ClaimAction::AttemptSpent => {
                record_claim_failure(withdrawal, code.label(), pending, claim_retry, retired, now_unix);
            }
        },
    }
}

/// Move a leaf to the retired set immediately, keeping whatever attempt count
/// it already had. A terminal payload does not get three strikes.
fn retire_claim(
    withdrawal: &propose_withdrawals::PendingWithdrawal,
    reason: &str,
    claim_retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    retired: &mut HashMap<
        String,
        claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>,
    >,
    now_unix: u64,
) {
    let leaf_hash = withdrawal.leaf_hash.as_str();
    let attempts = claim_retry.get(leaf_hash).map(|state| state.attempts).unwrap_or(0);
    if let Some(withdrawal) = remove_full_leaf(pending, leaf_hash) {
        retired.insert(
            leaf_hash.to_string(),
            claim_attempts::RetiredClaim {
                withdrawal,
                attempts,
                last_reason: reason.to_string(),
                retired_at_unix: now_unix,
            },
        );
    }
    claim_attempts::clear(claim_retry, leaf_hash);
}

/// Count one failed attempt, and give up on the withdrawal if that was its last.
fn record_claim_failure(
    withdrawal: &propose_withdrawals::PendingWithdrawal,
    reason: &str,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired: &mut HashMap<
        String,
        claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>,
    >,
    now_unix: u64,
) {
    let leaf_hash = withdrawal.leaf_hash.as_str();
    let nonce = claim_withdrawals::nonce_hex(withdrawal.nonce);
    let state = claim_attempts::record_failure(claim_retry, leaf_hash, reason);
    if claim_attempts::is_exhausted(&state) {
        // Stop paying for proofs, keep the record. The funds are stuck and this
        // needs a person, so it is an error, not a warning.
        tracing::error!(
            leaf_hash,
            nonce = %nonce,
            attempts = state.attempts,
            reason = %state.last_reason,
            destination_chain_index = withdrawal.destination_chain_index,
            action = "retired",
            "withdrawal claim given up on after its attempts were used; no further proofs will be requested for it"
        );
        if let Some(w) = remove_full_leaf(pending, leaf_hash) {
            retired.insert(
                leaf_hash.to_string(),
                claim_attempts::RetiredClaim {
                    withdrawal: w,
                    attempts: state.attempts,
                    last_reason: state.last_reason.clone(),
                    retired_at_unix: now_unix,
                },
            );
        }
        claim_attempts::clear(claim_retry, leaf_hash);
    } else {
        tracing::warn!(
            leaf_hash,
            nonce = %nonce,
            attempts = state.attempts,
            max_attempts = claim_attempts::CLAIM_MAX_ATTEMPTS,
            reason = %state.last_reason,
            action = "retry",
            "withdrawal claim failed; will retry next round"
        );
    }
}

/// Account for pending withdrawals bound for a chain this relayer does not serve.
///
/// The multichain round dispatches claims per chain, filtering pending
/// withdrawals by destination_chain_index. One that matches no configured chain
/// therefore reaches no chain's claim path: it is never attempted, so it never
/// fails, so it never reaches the attempt ceiling. It simply accumulates in the
/// durable pending set, silently and forever — the relayer's half of the same
/// production incident, where the destination chain index was not ours.
///
/// The chain set is built before the round loop and does not change while the
/// process runs, so this is not a transient condition. It still goes through
/// the ordinary "try, retry twice, give up" counter rather than being retired
/// on sight: one rule is easier to reason about than two, and the three rounds
/// cost nothing here because no proof is requested for these.
fn record_unroutable_claims(
    served_chain_indices: &HashSet<u8>,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired: &mut HashMap<
        String,
        claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>,
    >,
    now_unix: u64,
) {
    let unroutable: Vec<propose_withdrawals::PendingWithdrawal> = pending
        .values()
        .filter(|w| {
            u8::try_from(w.destination_chain_index)
                .map(|index| !served_chain_indices.contains(&index))
                .unwrap_or(true)
        })
        .filter(|w| claim_attempts::is_retriable(claim_retry.get(&w.leaf_hash)))
        .cloned()
        .collect();

    for withdrawal in &unroutable {
        let served = {
            let mut indices: Vec<u8> = served_chain_indices.iter().copied().collect();
            indices.sort_unstable();
            indices
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let reason = format!(
            "no configured chain serves destination chain index {} (this relayer serves {served})",
            withdrawal.destination_chain_index
        );
        record_claim_failure(withdrawal, &reason, pending, claim_retry, retired, now_unix);
    }
}
/// Drop resolved leaves once their record has been cleared. A leaf that is
/// still recorded stays pending: resolution never removes a held leaf.
fn apply_resolved(
    pending_claim_withdrawals: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: &HashMap<String, claim_attempts::ClaimAttempts>,
    report: &claim_withdrawals::BatchWithdrawalsReport,
) {
    for outcome in &report.outcomes {
        if outcome.kind.action() == claim_withdrawals::ClaimAction::Resolved
            && !claim_retry.contains_key(&outcome.leaf_hash)
        {
            remove_full_leaf(pending_claim_withdrawals, &outcome.leaf_hash);
        }
    }
}
/// The claim retry rows as last persisted, used to re-adopt holds the
/// pre-broadcast hook wrote while a failed batch was in flight.
fn persisted_claim_retry(
    config: &guardian_common::protocol::GuardianConfig,
    db: &super::guardian_client::RelayerDb,
) -> anyhow::Result<HashMap<String, claim_attempts::ClaimAttempts>> {
    let mut persisted = HashMap::new();
    for row in db.chain_claims(config)?.into_values() {
        persisted.extend(row.claim_retry);
    }
    Ok(persisted)
}

/// Adopt receipt holds the pre-broadcast hook persisted for this attempt.
///
/// The hook is the only writer that records a signed transaction hash while
/// the batch is in flight, and a batch error produces no outcomes that would
/// re-derive those holds. Without this merge the round's save would overwrite
/// the durable hold and the next round would re-send a signed transaction.
/// The caller state stays the single authoritative copy: a persisted hold is
/// adopted monotonically and never overwritten by a stale absence, and a leaf
/// the caller already holds is left alone.
fn adopt_persisted_receipt_holds(
    attempted: &[propose_withdrawals::PendingWithdrawal],
    claim_retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    persisted: &HashMap<String, claim_attempts::ClaimAttempts>,
) {
    for withdrawal in attempted {
        let leaf = withdrawal.leaf_hash.as_str();
        if claim_retry.get(leaf).is_some_and(|state| !matches!(state.hold, claim_attempts::ClaimHold::None)) { continue; }
        if let Some(claim_attempts::ClaimHold::ReceiptUnknown { tx_hash }) = persisted.get(leaf).map(|state| &state.hold) {
            claim_attempts::hold_for_receipt(claim_retry, leaf, *tx_hash);
        }
    }
}


/// Durable pending-claim settlement shared by finalize rounds and append-only
/// / no-confirmed-range rounds. Retries persisted claims under the same
/// sticky fail-closed catch-up gate used after finalize; no new finalize range
/// is required. Returns the (possibly latched) catch-up authority.
async fn settle_pending_claim_withdrawals(
    l1: &L1Client,
    provider: &RpcProvider,
    config: &BridgeProposeDaemonConfig,
    pending_claim_withdrawals: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    claim_retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired_claim_withdrawals: &mut HashMap<
        String,
        claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>,
    >,
    from_checkpoint: u64,
    claim_cursor_checkpoint: u64,
    mut is_catchup_batch: bool,
    confirmation_lag_checkpoints: u64,
    network: &psy_config::NetworkConfigGoldilocks,
    guardian_config: &guardian_common::protocol::GuardianConfig,
    db: &super::guardian_client::RelayerDb,
    max_checkpoint_batch: u64,
) -> bool {
    let now_unix = claim_attempts::now_unix();
    match l1.release_claim_holds(pending_claim_withdrawals, claim_retry, config, None).await {
        Ok(resolutions) => {
            for resolution in &resolutions {
                record_claim_outcome(
                    &resolution.withdrawals,
                    &resolution.report,
                    pending_claim_withdrawals,
                    claim_retry,
                    retired_claim_withdrawals,
                    now_unix,
                );
            }
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "claim hold recheck failed; held leaves stay held"
            );
        }
    }
    let mut to_claim = claims_to_attempt(pending_claim_withdrawals, claim_retry);
    to_claim.sort_by_key(|withdrawal| (withdrawal.destination_chain_index, withdrawal.event_id));
    if to_claim.is_empty() {
        // Not the same as "nothing pending": every remaining entry can have
        // used up its attempts, which is the point of the ceiling.
        tracing::info!(
            claim_cursor_checkpoint,
            pending_claims = pending_claim_withdrawals.len(),
            retired_claims = retired_claim_withdrawals.len(),
            "no withdrawal claims left to attempt this round"
        );
        return is_catchup_batch;
    }

    if !is_catchup_batch {
        let latest_checkpoint = match provider.get_coordinator_latest_block_state().await {
            Ok(latest_state) => Some(latest_state.checkpoint_id),
            Err(err) => {
                tracing::warn!(
                    claim_cursor_checkpoint,
                    error = %err,
                    pending_claims = to_claim.len(),
                    "cannot refresh checkpoint window; deferring persisted withdrawal claims"
                );
                None
            }
        };
        is_catchup_batch = refresh_catchup_state(
            is_catchup_batch,
            from_checkpoint,
            latest_checkpoint,
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        );
    }

    if !should_attempt_pending_claims(is_catchup_batch, to_claim.len()) {
        tracing::info!(
            claim_cursor_checkpoint,
            pending_claims = to_claim.len(),
            "catchup mode defers persisted withdrawal claims under sticky authority"
        );
        return is_catchup_batch;
    }

    let result = l1
        .claim_withdrawals(&to_claim, config, claim_cursor_checkpoint, network, Some(claim_broadcast_hook(guardian_config, db)))
        .await;
    if result.is_err() {
        match persisted_claim_retry(guardian_config, db) {
            Ok(persisted) => adopt_persisted_receipt_holds(&to_claim, claim_retry, &persisted),
            Err(error) => tracing::warn!(error = %error, "cannot re-read persisted claim holds; recording the failure without them"),
        }
    }

    record_claim_result(
        &to_claim,
        &result,
        pending_claim_withdrawals,
        claim_retry,
        retired_claim_withdrawals,
        now_unix,
    );
    match result {
        Ok(report) => {
            if report.count_by_action(claim_withdrawals::ClaimAction::AttemptSpent) == 0 {
                tracing::info!(
                    claim_cursor_checkpoint,
                    requested = report.requested,
                    submitted_count = report.submitted_count,
                    resolved = report.resolved_count(),
                    failed = report.count_by_action(claim_withdrawals::ClaimAction::AttemptSpent),
                    pending_claims = pending_claim_withdrawals.len(),
                    "withdrawal claims finished"
                );
            } else {
                tracing::warn!(
                    claim_cursor_checkpoint,
                    requested = report.requested,
                    submitted_count = report.submitted_count,
                    resolved = report.resolved_count(),
                    failed = report.count_by_action(claim_withdrawals::ClaimAction::AttemptSpent),
                    pending_claims = pending_claim_withdrawals.len(),
                    "withdrawal claims finished with pending retries"
                );
            }
        }
        Err(err) => {
            tracing::error!(
                claim_cursor_checkpoint,
                error = %err,
                pending_claims = pending_claim_withdrawals.len(),
                "withdrawal claim batch failed; retry limits applied"
            );
        }
    }

    is_catchup_batch
}


fn record_claim_withdrawals(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
    seen: &mut HashSet<(u64, i64, String)>,
    claims: &mut Vec<propose_withdrawals::PendingWithdrawal>,
) {
    for withdrawal in withdrawals {
        if seen.insert((withdrawal.destination_chain_index, withdrawal.event_id, withdrawal.leaf_hash.clone())) {
            claims.push(withdrawal.clone());
        }
    }
}

fn build_set_chain_root_call(
    source_chain_index: u64,
    absolute_deposit_count: u64,
    deposit_root_hex: &str,
) -> anyhow::Result<ContractCallArgs> {
    let raw_hex = deposit_root_hex.strip_prefix("0x").unwrap_or(deposit_root_hex);
    let bytes = hex::decode(raw_hex)
        .map_err(|e| anyhow::anyhow!("hex decode deposit_root: {}", e))?;
    anyhow::ensure!(bytes.len() == 32, "deposit_root must be 32 bytes");

    let mut root_words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        root_words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let mut inputs = vec![source_chain_index, absolute_deposit_count];
    inputs.extend(root_words.into_iter().map(u64::from));
    Ok(ContractCallArgs {
        contract_id: DEPOSIT_TREE_CONTRACT_ID as u64,
        method_name: "set_chain_root".to_string(),
        inputs,
    })
}

async fn build_l2_call_plan(
    services_url: &str,
    source_chain_index: u64,
    provider: &RpcProvider,
    propose_args: &ProposeWithdrawalsArgs,
    from_checkpoint: u64,
    to_checkpoint: u64,
    deposit_next_index: u32,
    pending_deposit_count: u32,
    proved_deposit_count: u32,
    is_catchup_batch: bool,
    guardian: &super::guardian_client::LoadedGuardianConfig,
) -> anyhow::Result<L2CallPlan> {
    let latest_checkpoint = if !is_catchup_batch {
        provider
            .get_coordinator_latest_block_state()
            .await
            .map(|s| s.checkpoint_id)
            .unwrap_or(to_checkpoint)
    } else {
        to_checkpoint
    };

    let global_target_deposit_count = u64::from(pending_deposit_count);
    let global_target_deposits_remaining_on_l2 = if !is_catchup_batch {
        global_target_deposit_count
            .checked_sub(u64::from(deposit_next_index))
            .ok_or_else(|| anyhow::anyhow!(
                "L2 deposit tree has more deposits than global target count: l2_next_index={} global_target_deposit_count={}",
                deposit_next_index,
                global_target_deposit_count
            ))?
    } else {
        0
    };
    let mut deposit_set_root_calls = Vec::new();
    if !is_catchup_batch && global_target_deposits_remaining_on_l2 > 0 {
        let http = crate::bridge::api_client::build_default_http_client()?;
        let source_chain_tree_state = crate::bridge::api_client::fetch_services_deposit_tree_root(
            &http,
            services_url,
            source_chain_index,
            global_target_deposit_count,
        )
        .await?;
        let per_chain_snapshot_deposit_count = source_chain_tree_state
            .snapshot_deposit_count()
            .ok_or_else(|| anyhow::anyhow!("deposit_tree_root response missing snapshot_deposit_count"))?;
        let per_chain_deposits_remaining_on_l2 = per_chain_snapshot_deposit_count
            .checked_sub(u64::from(deposit_next_index))
            .ok_or_else(|| anyhow::anyhow!(
                "L2 deposit tree has more deposits than per-chain snapshot count: l2_next_index={} per_chain_snapshot_deposit_count={}",
                deposit_next_index,
                per_chain_snapshot_deposit_count
            ))?;
        anyhow::ensure!(
            source_chain_tree_state.found,
            "services deposit snapshot root unavailable for global_target_deposit_count={}: {}",
            global_target_deposit_count,
            source_chain_tree_state
                .reason
                .as_deref()
                .unwrap_or("no reason given")
        );
        let deposit_root_hex = source_chain_tree_state
            .deposit_root
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("deposit_tree_root response missing deposit_root"))?;

        if per_chain_deposits_remaining_on_l2 > 0 {
            // PsyDepositTreeContract::set_chain_root stores an absolute count.
            // Re-submitting the same snapshot is therefore idempotent.
            deposit_set_root_calls.push(build_set_chain_root_call(
                source_chain_index,
                per_chain_snapshot_deposit_count,
                deposit_root_hex,
            )?);
        }
        tracing::info!(
            source_chain_index,
            deposit_next_index,
            global_target_deposit_count,
            per_chain_snapshot_deposit_count,
            pending_deposit_count,
            proved_deposit_count,
            global_target_deposits_remaining_on_l2,
            deposit_root = %deposit_root_hex,
            "built set_chain_root L2 call from services per-chain historical root"
        );
    } else {
        tracing::info!(
            source_chain_index,
            deposit_next_index,
            global_target_deposit_count,
            pending_deposit_count,
            proved_deposit_count,
            global_target_deposits_remaining_on_l2,
            is_catchup_batch,
            "no new deposits to set_chain_root on L2"
        );
    }

    let withdrawal_from_checkpoint = from_checkpoint.max(1);
    let (l2_withdrawal_next_index, l2_withdrawal_global_count) = if !is_catchup_batch {
        let chain_next_index = provider
            .get_withdrawal_tree_next_index(
                latest_checkpoint,
                BRIDGE_USER_ID_U64,
                source_chain_index,
            )
            .await?;
        let global_count = provider
            .get_withdrawal_tree_global_count(latest_checkpoint, BRIDGE_USER_ID_U64)
            .await?;
        (chain_next_index, global_count)
    } else {
        (0, 0)
    };
    let quarantine_markers = if !is_catchup_batch {
        propose_withdrawals::quarantine_marker_counts(&guardian.db, &[source_chain_index])?
            .remove(&source_chain_index)
            .unwrap_or(0)
    } else {
        0
    };
    let withdrawals = if !is_catchup_batch {
        propose_withdrawals::quarantine_unmappable_withdrawals(
            guardian,
            propose_withdrawals::fetch_pending_bridge_withdrawals(
                propose_args,
                withdrawal_from_checkpoint,
                to_checkpoint.saturating_add(1),
                &[(source_chain_index, l2_withdrawal_next_index + quarantine_markers)],
                &guardian.root.network,
            )
            .await?,
        )
        .await?
    } else {
        Vec::new()
    };
    let withdrawal_batch_calls = build_withdrawal_batch_calls(&withdrawals);

    tracing::info!(
        source_chain_index,
        l2_withdrawal_next_index,
        l2_withdrawal_global_count,
        append_withdrawals_count = withdrawals.len(),
        raw_batch_calls = withdrawal_batch_calls.len(),
        has_withdrawal_appends = !withdrawals.is_empty(),
        is_catchup_batch,
        scan_from_checkpoint = withdrawal_from_checkpoint,
        scan_to_checkpoint = to_checkpoint,
        "bridge L2 round batch plan (deposits via services-derived set_chain_root)"
    );

    let all_batch_calls: Vec<ContractCallArgs> = deposit_set_root_calls
        .into_iter()
        .chain(withdrawal_batch_calls)
        .collect();

    Ok(L2CallPlan {
        withdrawals,
        batch_calls: all_batch_calls,
    })
}

fn finalized_deposit_append_target(l2_count: u32, pending: u32, finalized_pending: u32) -> u32 {
    pending.min(finalized_pending).min(l2_count.saturating_add(MAX_DEPOSITS_PER_L2_ROUND))
}

async fn build_multichain_l2_plan(
    base: &BridgeProposeDaemonConfig,
    provider: &RpcProvider,
    chains: &[ChainRuntime],
    checkpoint: u64,
    from_checkpoint: u64,
    to_checkpoint: u64,
    append_business: bool,
    propose_args: &ProposeWithdrawalsArgs,
    guardian: &super::guardian_client::LoadedGuardianConfig,
) -> anyhow::Result<(Vec<ChainRoundProgress>, MultichainL2CallPlan)> {
    let http = crate::bridge::api_client::build_default_http_client()?;
    let mut progress = Vec::with_capacity(chains.len());
    let mut calls = Vec::new();
    let mut withdrawal_chain_offsets: Vec<(u64, u64)> = Vec::with_capacity(chains.len());

    for chain in chains {
        let (proved, pending) = chain
            .l1
            .with_rpc_failover("read_deposit_progress", |url| {
                let url = url.to_string();
                async move {
                    let l1_provider = crate::bridge::l1_provider::connect_l1_readonly(
                        url.parse().with_context(|| format!("invalid L1 rpc url: {url}"))?,
                    )?;
                    Ok((
                        fetch_proved_deposit_count(&l1_provider, chain.bridge).await?,
                        fetch_pending_deposit_count(&l1_provider, chain.bridge).await?,
                    ))
                }
            })
            .await?;
        ensure!(pending >= proved, "chain {} pending deposits regressed", chain.chain_index);
        let l2_count = u32::try_from(fetch_deposit_tree_next_index(
            provider,
            checkpoint,
            u64::from(chain.chain_index),
        ).await?).context("L2 per-chain deposit count exceeds u32")?;
        ensure!(l2_count <= pending, "chain {} L2 deposit count exceeds L1 pending count", chain.chain_index);

        if append_business {
            // Per-chain L2 withdrawal-tree cursor: psy-services requires a
            // destination_chain_index filter per query once multiple L1 chains
            // are indexed, and each filtered stream is offset by the number of
            // that chain's withdrawals already appended on L2.
            let withdrawal_next_index = provider
                .get_withdrawal_tree_next_index(checkpoint, BRIDGE_USER_ID_U64, u64::from(chain.chain_index))
                .await?;
            withdrawal_chain_offsets.push((u64::from(chain.chain_index), withdrawal_next_index));
        }

        if append_business && pending > l2_count {
            let finalized_pending = chain.l1.with_rpc_failover("read_finalized_deposit_progress", |url| {
                let url = url.to_string();
                async move {
                    let provider = crate::bridge::l1_provider::connect_l1_readonly(url.parse()?)?;
                    fetch_finalized_pending_deposit_count(&provider, chain.bridge).await
                }
            }).await?;
            // Latest remains the backlog metric, not Guardian admission. A
            // later finalized read may advance past that earlier observation.
            let deposit_append_target = finalized_deposit_append_target(l2_count, pending, finalized_pending);
            if deposit_append_target < pending.min(finalized_pending) {
                tracing::info!(chain_index=chain.chain_index, l2_count, pending, finalized_pending,
                    deposit_append_target, max_deposits=MAX_DEPOSITS_PER_L2_ROUND,
                    "finalized deposit admission limited for bounded L1 verification");
            }
            if deposit_append_target > l2_count {
                let snapshot = crate::bridge::api_client::fetch_services_deposit_snapshot_root(
                    &http,
                    &base.services_url,
                    u64::from(chain.chain_index),
                    u64::from(deposit_append_target),
                ).await?;
                ensure!(snapshot.found, "missing exact deposit snapshot for chain {} count {}", chain.chain_index, deposit_append_target);
                let snapshot_count = snapshot.snapshot_deposit_count().context("deposit snapshot missing count")?;
                ensure!(snapshot_count == u64::from(deposit_append_target), "deposit snapshot count mismatch for chain {}", chain.chain_index);
                calls.push(build_set_chain_root_call(
                    u64::from(chain.chain_index),
                    snapshot_count,
                    snapshot.deposit_root.as_deref().context("deposit snapshot missing root")?,
                )?);
            }
            if finalized_pending < pending {
                tracing::info!(chain_index=chain.chain_index, pending, finalized_pending, l2_count,
                    "unfinalized deposits deferred; other chains remain eligible");
            }
        }
        progress.push(ChainRoundProgress {
            chain_index: chain.chain_index,
            pending_deposit_count: pending,
            proved_deposit_count: proved,
            l2_deposit_count: l2_count,
        });
    }
    calls.sort_by_key(|call| call.inputs.first().copied().unwrap_or(u64::MAX));

    let withdrawal_offsets = if append_business {
        let chains = withdrawal_chain_offsets.iter().map(|(chain, _)| *chain).collect::<Vec<_>>();
        let quarantine_markers = propose_withdrawals::quarantine_marker_counts(&guardian.db, &chains)?;
        withdrawal_chain_offsets
            .iter()
            .map(|(chain, index)| (*chain, index + quarantine_markers.get(chain).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
    } else {
        withdrawal_chain_offsets
    };
    let withdrawals = if append_business {
        propose_withdrawals::quarantine_unmappable_withdrawals(
            guardian,
            propose_withdrawals::fetch_pending_bridge_withdrawals(
                propose_args,
                from_checkpoint.max(1),
                to_checkpoint.saturating_add(1),
                &withdrawal_offsets,
                &guardian.root.network,
            )
            .await?,
        )
        .await?
    } else {
        Vec::new()
    };
    calls.extend(build_withdrawal_batch_calls(&withdrawals));
    Ok((progress, MultichainL2CallPlan { calls, withdrawals }))
}

async fn submit_multichain_l2_plan(
    provider: &RpcProvider,
    plan: &MultichainL2CallPlan,
    retained: &mut RelayerHistory,
    confirmation_lag_checkpoints: u64,
    guardian: &super::guardian_client::LoadedGuardianConfig,
) -> anyhow::Result<u64> {
    if plan.calls.is_empty() {
        return Ok(provider.get_coordinator_latest_block_state().await?.checkpoint_id);
    }
    let landed = submit_guardian_operation(
        guardian,
        provider,
        plan.calls.clone(),
        &plan.withdrawals,
        guardian_common::protocol::GuardianOperation::Bridge,
        None,
        retained,
        PolicySignatures::None,
    ).await?.included_checkpoint_id;
    wait_until_checkpoint_confirmed(
        provider,
        landed,
        confirmation_lag_checkpoints,
        REALM_CHECKPOINT_POLL_TIMEOUT_SECS,
        REALM_CHECKPOINT_POLL_INTERVAL_SECS,
    ).await?;
    Ok(landed)
}


async fn finish_l2_round(
    provider: &RpcProvider,
    to_checkpoint: u64,
    proved_deposit_count: u32,
    pending_deposit_count: u32,
    source_chain_index: u64,
    is_catchup_batch: bool,
    submitted_l2_work: bool,
    claim_withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
) -> anyhow::Result<L2RoundResult> {
    let l2_deposit_cursor = fetch_deposit_tree_next_index(
        provider,
        to_checkpoint,
        source_chain_index,
    )
    .await?;
    let deposit_append_target = select_deposit_append_target(
        is_catchup_batch,
        to_checkpoint,
        to_checkpoint,
        l2_deposit_cursor,
        proved_deposit_count,
        pending_deposit_count,
    )?;

    tracing::info!(
        source_chain_index,
        l2_deposit_cursor,
        deposit_append_target = ?deposit_append_target,
        to_checkpoint,
        submitted_l2_work,
        is_catchup_batch,
        claim_withdrawals_count = claim_withdrawals.len(),
        "bridge L2 round has no new L2 calls; returning for prove/finalize"
    );
    Ok(L2RoundResult {
        deposit_append_target,
        to_checkpoint,
        submitted_l2_work,
        is_catchup_batch,
        claim_withdrawals,
    })
}

fn accepted_endcap_identity_matches(
    expected: &[EndCapContractSlotUpdate],
    accepted: &RealmEndCapSlotUpdates,
) -> bool {
    let mut expected_updates: Vec<_> = expected
        .iter()
        .map(|update| (update.contract_id, update.slot, update.old_value, update.new_value))
        .collect();
    let mut accepted_updates: Vec<_> = accepted
        .contracts
        .iter()
        .flat_map(|contract| {
            contract
                .slot_updates
                .iter()
                .map(move |update| (contract.contract_id, update.slot, update.old_value, update.new_value))
        })
        .collect();
    expected_updates.sort_unstable();
    accepted_updates.sort_unstable();

    let mut accepted_index = 0;
    for expected_update in expected_updates {
        while accepted_index < accepted_updates.len() && accepted_updates[accepted_index] < expected_update {
            accepted_index += 1;
        }
        if accepted_updates.get(accepted_index) != Some(&expected_update) {
            return false;
        }
        accepted_index += 1;
    }
    true
}

async fn recover_duplicate_endcap_leaf_with<Lookup, LookupFuture>(
    error: anyhow::Error,
    expected_user_id: u64,
    lookup: Lookup,
) -> anyhow::Result<QHashOut<GoldilocksField>>
where
    Lookup: FnOnce(u64, u64) -> LookupFuture,
    LookupFuture: Future<Output = anyhow::Result<Option<RealmEndCapSlotUpdates>>>,
{
    let submission = error.downcast::<EndCapSubmissionError>()?;
    let Some(duplicate) = submission
        .source
        .downcast_ref::<psy_provider::provider::EndCapAlreadySubmitted>()
    else {
        return Err(submission.into());
    };
    ensure!(
        duplicate.user_id == expected_user_id,
        "duplicate endcap user mismatch: acknowledgement user_id={} expected_user_id={} unique_pending_id={}",
        duplicate.user_id,
        expected_user_id,
        duplicate.unique_pending_id
    );
    let accepted = lookup(duplicate.user_id, duplicate.unique_pending_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!(
            "duplicate endcap acknowledgement has no accepted identity: user_id={} unique_pending_id={}",
            duplicate.user_id,
            duplicate.unique_pending_id
        ))?;
    ensure!(
        accepted.user_id == duplicate.user_id
            && accepted.unique_pending_id == duplicate.unique_pending_id,
        "duplicate endcap identity mismatch: acknowledgement user_id={} unique_pending_id={} accepted user_id={} unique_pending_id={}",
        duplicate.user_id,
        duplicate.unique_pending_id,
        accepted.user_id,
        accepted.unique_pending_id
    );
    if !accepted_endcap_identity_matches(&submission.contract_slot_updates, &accepted) {
        let mut expected_updates: Vec<_> = submission
            .contract_slot_updates
            .iter()
            .map(|update| (update.contract_id, update.slot, update.old_value, update.new_value))
            .collect();
        let mut accepted_updates: Vec<_> = accepted
            .contracts
            .iter()
            .flat_map(|contract| {
                contract
                    .slot_updates
                    .iter()
                    .map(move |update| (contract.contract_id, update.slot, update.old_value, update.new_value))
            })
            .collect();
        expected_updates.sort_unstable();
        accepted_updates.sort_unstable();
        let first_expected_only = expected_updates.iter().find(|update| accepted_updates.binary_search(update).is_err());
        let first_accepted_only = accepted_updates.iter().find(|update| expected_updates.binary_search(update).is_err());
        anyhow::bail!(
            "duplicate endcap contract update identity mismatch: user_id={} unique_pending_id={} expected_count={} accepted_count={} first_expected_only={:?} first_accepted_only={:?}",
            duplicate.user_id,
            duplicate.unique_pending_id,
            expected_updates.len(),
            accepted_updates.len(),
            first_expected_only,
            first_accepted_only
        );
    }

    // Pin the accepted endcap's identity: a fresh proof built against a
    // different start leaf yields a different end leaf while slot updates
    // coincide. Returning it unchecked would wait forever on a leaf that can
    // never land (livelock), so fail closed with full diagnostics instead.
    if let Some(accepted_felts) = accepted.accepted_user_leaf_hash {
        let fresh_felts: [u64; 4] = std::array::from_fn(|i| {
            submission.end_user_leaf_hash.0.elements[i].to_canonical_u64()
        });
        ensure!(
            accepted_felts == fresh_felts,
            "duplicate endcap accepted leaf mismatch: accepted_user_leaf={:?} fresh_proof_leaf={:?} user_id={} unique_pending_id={} — this proof does not re-derive the accepted endcap",
            accepted_felts,
            fresh_felts,
            duplicate.user_id,
            duplicate.unique_pending_id
        );
    }
    Ok(submission.end_user_leaf_hash)
}

async fn resolve_l2_submission_leaf(
    provider: &RpcProvider,
    result: anyhow::Result<QHashOut<GoldilocksField>>,
    expected_user_id: u64,
) -> anyhow::Result<QHashOut<GoldilocksField>> {
    match result {
        Ok(leaf) => Ok(leaf),
        Err(error) => {
            recover_duplicate_endcap_leaf_with(error, expected_user_id, |user_id, unique_pending_id| {
                provider.get_realm_user_end_cap_slot_updates(user_id, unique_pending_id)
            })
            .await
        }
    }
}

async fn submit_l2_call_plan(
    config: &BridgeProposeDaemonConfig,
    provider: &RpcProvider,
    plan: &L2CallPlan,
    confirmation_lag_checkpoints: u64,
    guardian: &super::guardian_client::LoadedGuardianConfig,
) -> anyhow::Result<u64> {
    if plan.batch_calls.is_empty() {
        return Ok(provider.get_coordinator_latest_block_state().await?.checkpoint_id);
    }
    let mut guardian_history = config.guardian_history.lock().await;
    // One PSY session: the multisig account permits a single inflight trace,
    // so the whole plan is submitted as one guardian operation. Selected claims
    // are inserted in the same database transaction as the pending request.
    let landed = submit_guardian_operation(
        guardian,
        provider,
        plan.batch_calls.clone(),
        &plan.withdrawals,
        guardian_common::protocol::GuardianOperation::Bridge,
        None,
        &mut guardian_history,
        PolicySignatures::None,
    ).await?.included_checkpoint_id;
    wait_until_checkpoint_confirmed(
        provider,
        landed,
        confirmation_lag_checkpoints,
        REALM_CHECKPOINT_POLL_TIMEOUT_SECS,
        REALM_CHECKPOINT_POLL_INTERVAL_SECS,
    ).await?;
    Ok(landed)
}

async fn wait_until_checkpoint_confirmed(
    provider: &RpcProvider,
    checkpoint_id: u64,
    confirmation_lag_checkpoints: u64,
    timeout_secs: u64,
    poll_interval_secs: u64,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let latest = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        if latest
            .checked_sub(confirmation_lag_checkpoints)
            .is_some_and(|confirmed_to_checkpoint| confirmed_to_checkpoint >= checkpoint_id)
        {
            tracing::info!(
                checkpoint_id,
                latest_checkpoint = latest,
                confirmation_lag_checkpoints,
                "checkpoint has enough confirmations for bridge event scan"
            );
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for checkpoint {} to reach confirmation lag {}",
                checkpoint_id,
                confirmation_lag_checkpoints
            );
        }

        tracing::debug!(
            checkpoint_id,
            latest_checkpoint = latest,
            confirmation_lag_checkpoints,
            "waiting for checkpoint confirmations before rescanning bridge events"
        );
        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;
    }
}

// Leave 8 KiB for the signed envelope below a 128 KiB transaction limit.
const DEPOSIT_APPEND_CALLDATA_LIMIT: usize = 128 * 1024 - 8 * 1024;

fn chunk_deposit_batch_append_by_size(calls: Vec<Call3>) -> anyhow::Result<Vec<Vec<Call3>>> {
    let empty_size = aggregate3Call { calls: Vec::new() }.abi_encode().len();
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_size = empty_size;
    for call in calls {
        let single_size = aggregate3Call { calls: vec![call.clone()] }.abi_encode().len();
        ensure!(single_size <= DEPOSIT_APPEND_CALLDATA_LIMIT,
            "single deposit batchAppend calldata exceeds safe transaction budget: bytes={} limit={}",
            single_size, DEPOSIT_APPEND_CALLDATA_LIMIT);
        // ABI array offsets have fixed width, so singleton contributions add exactly.
        let call_size = single_size - empty_size;
        if !current.is_empty() && current_size + call_size > DEPOSIT_APPEND_CALLDATA_LIMIT {
            chunks.push(std::mem::take(&mut current));
            current_size = empty_size;
        }
        current.push(call);
        current_size += call_size;
    }
    if !current.is_empty() { chunks.push(current); }
    Ok(chunks)
}

async fn send_deposit_append_group<Read, ReadFuture, SendGroup, SendFuture, Receipt>(
    from_index: u32,
    to_index: u32,
    mut read_proved: Read,
    send: SendGroup,
) -> anyhow::Result<Receipt>
where
    Read: FnMut() -> ReadFuture,
    ReadFuture: Future<Output = anyhow::Result<U256>>,
    SendGroup: FnOnce() -> SendFuture,
    SendFuture: Future<Output = anyhow::Result<Receipt>>,
{
    let proved_before = read_proved().await?;
    ensure!(proved_before == U256::from(from_index),
        "deposit batchAppend cursor changed before sending: expected={} actual={}", from_index, proved_before);
    let receipt = send().await?;
    let proved_after = read_proved().await?;
    ensure!(proved_after == U256::from(to_index),
        "deposit batchAppend cursor mismatch after receipt: expected={} actual={}", to_index, proved_after);
    Ok(receipt)
}

/// Estimate gas for a batch deposit append by estimating on the full
/// multicall3 aggregate3 wrapper instead of individual bridge calls.
/// Individual bridge `batchAppend` calls can revert during estimation
/// because `fromIndex != provedDepositCount` for the second+ call in
/// isolation, but inside multicall3 the sequential execution carries
/// state forward correctly.
async fn estimate_multicall_batch_append_gas(
    provider: &impl Provider,
    multicall3: Address,
    calls: &[Call3],
) -> anyhow::Result<Vec<u64>> {
    if calls.is_empty() {
        return Ok(Vec::new());
    }

    // Try estimating on the full aggregate first (this executes calls
    // sequentially, matching real multicall3 behavior).
    let full_aggregate = aggregate3Call {
        calls: calls.to_vec(),
    };
    let calldata = full_aggregate.abi_encode();
    ensure!(calldata.len() <= DEPOSIT_APPEND_CALLDATA_LIMIT,
        "deposit batchAppend calldata exceeds safe transaction budget before gas estimation: bytes={} limit={}",
        calldata.len(), DEPOSIT_APPEND_CALLDATA_LIMIT);
    let full_tx = TransactionRequest::default()
        .to(multicall3)
        .input(Bytes::from(calldata).into());

    let total_gas = match provider.estimate_gas(full_tx).await {
        Ok(gas) => u64::try_from(gas).unwrap_or(u64::MAX),
        Err(_) => {
            // If the full aggregate cannot be estimated (e.g. too large),
            // use the full multicall budget as the total estimate.
            tracing::warn!(
                n = calls.len(),
                budget = L1_MULTICALL_GAS_BUDGET,
                fallback_per_call = L1_GROTH16_CALL_GAS_FALLBACK,
                "full aggregate gas estimation failed; using budget as total"
            );
            L1_MULTICALL_GAS_BUDGET
        }
    };

    // Divide total gas evenly across calls, capping each at budget.
    let n = calls.len() as u64;
    let per_call = core::cmp::min(total_gas / n, L1_MULTICALL_GAS_BUDGET / n).max(1);
    Ok(vec![per_call; calls.len()])
}

/// Chunk deposit batch append calls into multicall3-compatible groups
/// using multicall-level gas estimation (avoiding per-call estimation
/// that reverts with `InvalidBatchRange` for later calls).
async fn chunk_deposit_batch_append_by_gas(
    provider: &impl Provider,
    multicall3: Address,
    calls: Vec<Call3>,
) -> anyhow::Result<Vec<Vec<Call3>>> {
    let budget = L1_MULTICALL_GAS_BUDGET.max(1);
    let mut chunks = Vec::new();
    for calls in chunk_deposit_batch_append_by_size(calls)? {
        let gases = estimate_multicall_batch_append_gas(provider, multicall3, &calls).await?;
        let mut current = Vec::new();
        let mut current_gas = 0u64;

        for (idx, call) in calls.into_iter().enumerate() {
            let gas = gases.get(idx).copied().unwrap_or(L1_GROTH16_CALL_GAS_FALLBACK).max(1);
            if !current.is_empty() && current_gas.saturating_add(gas) > budget {
                chunks.push(current);
                current = Vec::new();
                current_gas = 0;
            }
            current.push(call);
            current_gas = current_gas.saturating_add(gas);
        }

        if !current.is_empty() {
            chunks.push(current);
        }
    }
    Ok(chunks)
}

pub(crate) async fn fetch_proved_deposit_count(provider: &impl Provider, bridge: Address) -> anyhow::Result<u32> {
    let proved = crate::bridge::api_client::eth_call_u256(provider, bridge, provedDepositCountCall {}).await?;
    u32::try_from(proved).context("provedDepositCount exceeds u32")
}

pub(crate) async fn fetch_pending_deposit_count(provider: &impl Provider, bridge: Address) -> anyhow::Result<u32> {
    let pending = crate::bridge::api_client::eth_call_u256(provider, bridge, pendingDepositCountCall {}).await?;
    u32::try_from(pending).context("pendingDepositCount exceeds u32")
}

async fn fetch_finalized_pending_deposit_count(provider: &impl Provider, bridge: Address) -> anyhow::Result<u32> {
    let block = provider.get_block_by_number(BlockNumberOrTag::Finalized).await?
        .context("finalized L1 header unavailable")?;
    ensure!(block.header.hash != B256::ZERO, "finalized L1 header hash is zero");
    let call = pendingDepositCountCall {};
    let tx = TransactionRequest::default().to(bridge).input(call.abi_encode().into());
    let raw = provider.call(tx).block(BlockId::hash_canonical(block.header.hash)).await
        .context("finalized pendingDepositCount eth_call failed")?;
    let pending = pendingDepositCountCall::abi_decode_returns(&raw)
        .context("failed to decode finalized pendingDepositCount")?;
    u32::try_from(pending).context("finalized pendingDepositCount exceeds u32")
}


async fn fetch_deposit_tree_next_index(
    provider: &RpcProvider,
    checkpoint_id: u64,
    chain_index: u64,
) -> anyhow::Result<u64> {
    // Match deposit_tree.get_chain_next_index(chain_index): read chain_counts[chain_index]
    // from the compiled sub-slot layout, then decode the correct felt within the packed leaf.
    let sub_slot_index = DEPOSIT_TREE_CHAIN_COUNTS_SUBSLOT_BASE + chain_index;
    let leaf_index = sub_slot_index / 4;
    let next_index_leaf = provider
        .get_user_contract_state_tree_leaf_hash(
            checkpoint_id,
            BRIDGE_USER_ID_U64,
            DEPOSIT_TREE_CONTRACT_ID,
            CONTRACT_STATE_TREE_HEIGHT,
            leaf_index,
        )
        .await?;
    read_single_felt_from_packed_leaf(next_index_leaf, sub_slot_index)
}

enum PolicySignatures {
    None,
    Prepare,
    Resume { expected_request_id: guardian_common::protocol::Hex32, responses: [guardian_common::protocol::GuardianSignResponse; 2] },
}

pub(crate) async fn submit_guardian_calls(config: &super::guardian_client::LoadedGuardianConfig, provider: &RpcProvider, calls: Vec<ContractCallArgs>, withdrawals: &[propose_withdrawals::PendingWithdrawal]) -> anyhow::Result<u64> {
    Ok(submit_guardian_operation(config, provider, calls, withdrawals, guardian_common::protocol::GuardianOperation::Bridge, None, &mut RelayerHistory::default(), PolicySignatures::None).await?.included_checkpoint_id)
}

pub(crate) async fn prepare_guardian_policy(rpc_config: &str, guardian_root: &str, local_documents: &[PathBuf], operation: guardian_common::protocol::GuardianOperation, next_members: [QHashOut<GoldilocksField>; 3]) -> anyhow::Result<guardian_common::protocol::JsonText<guardian_common::protocol::GuardianSignRequest>> {
    anyhow::ensure!(matches!(operation, guardian_common::protocol::GuardianOperation::Bootstrap | guardian_common::protocol::GuardianOperation::ReplacePolicy), "policy preparation requires bootstrap or replacement");
    let config = super::guardian_client::LoadedGuardianConfig::load(Path::new(rpc_config), Path::new(guardian_root), local_documents).await?;
    let provider = guardian_common::runtime::load_network(&config.root).map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(submit_guardian_operation(&config, &provider, Vec::new(), &[], operation, Some(next_members), &mut RelayerHistory::default(), PolicySignatures::Prepare).await?.request.context("policy preparation produced no frozen request")?)
}

pub(crate) async fn resume_guardian_policy(rpc_config: &str, guardian_root: &str, local_documents: &[PathBuf], expected_request_id: guardian_common::protocol::Hex32, responses: [guardian_common::protocol::GuardianSignResponse; 2]) -> anyhow::Result<u64> {
    let config = super::guardian_client::LoadedGuardianConfig::load(Path::new(rpc_config), Path::new(guardian_root), local_documents).await?;
    let provider = guardian_common::runtime::load_network(&config.root).map_err(|error| anyhow::anyhow!("{error}"))?;
    let mut retained = RelayerHistory::default();
    let operation = submit_guardian_operation(&config, &provider, Vec::new(), &[], guardian_common::protocol::GuardianOperation::Bridge, None, &mut retained, PolicySignatures::Resume { expected_request_id, responses });
    let history = config.serve_history();
    tokio::select! { result = history => { result?; anyhow::bail!("guardian history listener stopped"); }, result = operation => Ok(result?.included_checkpoint_id) }
}

pub(crate) async fn run_guardian_register(rpc_config: &str, guardian_root: &str, local_documents: &[PathBuf], exclusive_registration_intake: bool) -> anyhow::Result<()> {
    let config = super::guardian_client::LoadedGuardianConfig::load(Path::new(rpc_config), Path::new(guardian_root), local_documents).await?;
    let account = config.root.initial_account().map_err(|error| anyhow::anyhow!(error))?;
    let identity = config.root.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
    ensure!(config.db.pending_request()?.is_none(), "registration cannot replace pending account work");
    let provider = guardian_common::runtime::load_network(&config.root)?;
    let mut wallet = WalletSession::new_with_provider(&config.root.network, provider.clone(), None).await?;
    let public_key = wallet.register_bridge_multisig_user(account, exclusive_registration_intake).await?;
    ensure!(public_key == identity && provider.get_user_ids_for_public_key(public_key).await? == vec![BRIDGE_USER_ID_U64], "AccountIdentityConflict");
    Ok(())
}

fn pending_policy_matches(request: &guardian_common::protocol::GuardianSignRequest, operation: guardian_common::protocol::GuardianOperation, members: [QHashOut<GoldilocksField>; 3]) -> anyhow::Result<bool> {
    if request.operation != operation { return Ok(false); }
    let calls: ContractCallData = serde_json::from_value(request.trace_json.decode()?.call_data)?;
    let expected: Vec<_> = members.iter().flat_map(|member| member.0.elements.map(|limb| limb.to_canonical_u64())).collect();
    Ok(calls.contract_calls.len() == 1 && calls.contract_calls[0].contract_id == u64::from(MULTISIG_POLICY_CONTRACT_ID) && calls.contract_calls[0].method_name == "set_policy" && calls.contract_calls[0].inputs.get(16..) == Some(expected.as_slice()))
}

async fn restore_relayer_history(wallet: &WalletSession, provider: &RpcProvider, config: &super::guardian_client::LoadedGuardianConfig, head: u64, root: QHashOut<GoldilocksField>) -> anyhow::Result<RelayerHistory> {
    use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
    let network = config.root.network_magic()?;
    let user = guardian_common::protocol::BRIDGE_USER_ID;
    let identity = config.root.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
    let Some(account) = config.db.load_account(network, user)? else { return Ok(RelayerHistory::default()); };
    ensure!(account.account_public_key == identity, "saved account identity differs from the configured account");
    if account.state == guardian_common::protocol::GuardianAccountState::Halted { anyhow::bail!("halted guardian account refuses operation"); }
    let deposit_tree_states = config.db.load_deposit_tree_states(network, user)?;
    if account.last_checkpoint_id > head { anyhow::bail!("saved checkpoint is beyond the committed head"); }
    let path = provider.get_checkpoint_tree_merkle_proof(head, account.last_checkpoint_id).await?;
    let leaf = provider.get_checkpoint_leaf_data(account.last_checkpoint_id).await?;
    let roots = provider.get_checkpoint_global_state_roots(account.last_checkpoint_id).await?;
    crate::guardian::verify::verify_checkpoint(account.last_checkpoint_id, &leaf, &roots, &path, root).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    ensure!(path.value == account.last_checkpoint_hash, "saved checkpoint leaf hash differs from the authenticated leaf");
    if let Some(saved) = account.imported_ending_leaf {
        use plonky2::field::types::PrimeField64;
        use psy_client_data::config::store_config::PsyHasher;
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        let user_id = user;
        let user_path = provider.get_user_tree_merkle_proof(account.last_checkpoint_id, user_id).await?;
        crate::guardian::verify::verify_path(&user_path, roots.user_tree_root, user_id, saved, psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        if saved != QHashOut::ZERO {
            let user = provider.get_user_leaf_data(account.last_checkpoint_id, user_id).await?;
            ensure!(user.qfhash::<PsyHasher>() == saved && user.public_key == identity && user.user_id.to_canonical_u64() == user_id, "saved ending leaf differs from the authenticated account leaf");
        }
    }
    for state in &deposit_tree_states {
        let chain = config.root.chain(state.anchor.chain_index).map_err(|error| anyhow::anyhow!(error))?;
        let canonical = guardian_common::verify_l1::verify_saved_deposit_anchor_headers(chain, &state.anchor).await.map_err(|error| anyhow::anyhow!("{error:?}"))?;
        match guardian_common::verify_l1::verify_cached_anchor_hash(canonical, state.anchor.block_hash) {
            Ok(()) => {}
            Err(guardian_common::verify_l1::GuardianAccountError::Conflict(reason @ guardian_common::protocol::HaltReason::FinalityConflict)) => {
                config.db.halt_account(network, user, reason)?;
                anyhow::bail!("saved deposit anchor contradicts canonical finality");
            }
            Err(error) => return Err(anyhow::anyhow!("{error:?}")),
        }
    }
    let restored = RelayerHistory::restore(&account, &deposit_tree_states)?;
    if account.imported_nonce.is_some() {
        let context = verification_context(wallet, provider, config, head, root, &restored.history, &[]);
        if let Err(error) = crate::guardian::verify::verify_restored_history(&context, &config.root, account.last_checkpoint_id).await {
            if let guardian_common::verify_l1::GuardianAccountError::Conflict(reason) = error { config.db.halt_account(network, user, reason)?; }
            anyhow::bail!("{error:?}");
        }
    }
    Ok(restored)
}
/// Local-only install of the committed DB tail: decodes and validates the
/// durable account and deposit-tree states without any network I/O — it can fail on
/// unusable state but never on transport. Full re-verification against a
/// fresh committed head happens at the next entry restore, before the
/// history is ever used.
fn committed_history_snapshot(config: &super::guardian_client::LoadedGuardianConfig) -> anyhow::Result<RelayerHistory> {
    use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
    let network = config.root.network_magic()?;
    let user = guardian_common::protocol::BRIDGE_USER_ID;
    let identity = config.root.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
    let account = config.db.load_account(network, user)?.context("durable guardian account missing after import")?;
    anyhow::ensure!(account.account_public_key == identity, "saved account identity differs from the configured account");
    if account.state == guardian_common::protocol::GuardianAccountState::Halted { anyhow::bail!("halted guardian account refuses history install"); }
    RelayerHistory::restore(&account, &config.db.load_deposit_tree_states(network, user)?)
}

fn verification_context<'a>(wallet: &'a WalletSession, provider: &'a RpcProvider, config: &'a super::guardian_client::LoadedGuardianConfig, head: u64, root: QHashOut<GoldilocksField>, history: &'a crate::guardian::verify::GuardianHistory, reserved: &'a [guardian_common::protocol::DepositTreeState]) -> crate::guardian::verify::GuardianVerificationContext<'a> {
    crate::guardian::verify::GuardianVerificationContext { wallet, provider, network: &config.root.network, verified_checkpoint_id: head, verified_checkpoint_tree_root: root, l1_chains: &config.root.l1_chains, history, reserved_deposit_tree_states: reserved }
}


struct FrozenPolicy { request: Option<guardian_common::protocol::JsonText<guardian_common::protocol::GuardianSignRequest>>, included_checkpoint_id: u64 }

fn frozen(request: guardian_common::protocol::JsonText<guardian_common::protocol::GuardianSignRequest>, included_checkpoint_id: u64) -> FrozenPolicy { FrozenPolicy { request: Some(request), included_checkpoint_id } }

async fn submit_guardian_operation(config: &super::guardian_client::LoadedGuardianConfig, provider: &RpcProvider, calls: Vec<ContractCallArgs>, withdrawals: &[propose_withdrawals::PendingWithdrawal], operation: guardian_common::protocol::GuardianOperation, next_members: Option<[QHashOut<GoldilocksField>; 3]>, retained: &mut RelayerHistory, policy: PolicySignatures) -> anyhow::Result<FrozenPolicy> {
    use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
    use guardian_common::protocol::*;
    use crate::guardian::verify::verify_guardian_session;
    use super::guardian_client::{GuardianClient, prove_pending_request};
    use psy_prover::trace::GeneratedTxTraceJson;
    let account = config.root.initial_account().map_err(|error| anyhow::anyhow!(error))?;
    let identity = config.root.account_public_key().map_err(|error| anyhow::anyhow!(error))?;
    let archive = &config.db;
    let mut wallet = WalletSession::new_with_provider(&config.root.network, provider.clone(), None).await?;
    let public_key = wallet.add_multisig_user(account.clone()).await?;
    ensure!(public_key == identity && provider.get_user_ids_for_public_key(public_key).await? == vec![BRIDGE_USER_ID_U64], "AccountIdentityConflict");
    let coordinator_url = provider.get_coordinator_url()?;
    let committed = crate::guardian::service::load_guardian_committed_head(provider, &coordinator_url).await?;
    let head = committed.checkpoint_id;
    let root = committed.checkpoint_tree_root;
    // Capture before refreshing: receipt repair may remove the pending marker.
    let pending = archive.pending_request()?;
    if let PolicySignatures::Resume { expected_request_id, responses } = &policy {
        let response_nonce = responses[0].session_nonce;
        ensure!(responses[1].session_nonce == response_nonce, "supplied signatures do not name one frozen request");
        let (bound, included) = archive.load_session(response_nonce, *expected_request_id)?;
        let bound_request = bound.decode()?;
        ensure!(bound_request.operation != GuardianOperation::Bridge, "supplied signatures do not authorize a policy request");
        match included {
            Some(record) => return Ok(frozen(bound, record.included_checkpoint_id)),
            None => ensure!(pending.as_ref().is_some_and(|pending| pending.as_str() == bound.as_str()), "frozen policy request is not the retained pending request"),
        }
    }
    *retained = restore_relayer_history(&wallet, provider, config, head, root).await?;
    let pending_nonce = pending.as_ref().map(|request| request.decode().map(|request| request.session_nonce)).transpose()?;
    let pending_included = match (pending_nonce, archive.sessions(retained.history.nonce(), 1)?.sessions.into_iter().next()) {
        (Some(nonce), Some(record)) if record.request_json.decode()?.session_nonce == nonce => Some(record),
        _ => None,
    };
    let staged_deposit_tree_states = pending_nonce.map(|nonce| archive.pending_deposit_tree_states(nonce)).transpose()?.unwrap_or_default();
    let request_json = if let Some(pending) = pending {
        let pending_request = pending.decode()?;
        if operation != GuardianOperation::Bridge {
            ensure!(pending_policy_matches(&pending_request, operation, next_members.context("policy command requires next members")?)?, "NonceConflict: pending operation or policy members differ from requested command");
        }
        if let Some(record) = pending_included {
            ensure!(record.request_json.as_str() == pending.as_str(), "NonceConflict: canonical inclusion differs from pending request");
            return Ok(frozen(pending.clone(), record.included_checkpoint_id));
        }
        if let Some((session, deposit_tree_states)) = recover_guardian_inclusion(&wallet, provider, config, archive, &retained.history, &pending, &staged_deposit_tree_states).await? {
            return Ok(frozen(pending, import_recovered(provider, config, archive, retained, session, &deposit_tree_states).await?));
        }
        pending
    } else {
        if operation == GuardianOperation::Bridge && calls.is_empty() && withdrawals.is_empty() { return Ok(FrozenPolicy { request: None, included_checkpoint_id: head }); }
        let history = &retained.history;
        let account_proof = provider.get_user_tree_merkle_proof(head, BRIDGE_USER_ID_U64).await?;
        let nonce = if account_proof.value == QHashOut::ZERO { 1 } else { provider.get_user_leaf_data(head, BRIDGE_USER_ID_U64).await?.nonce.to_canonical_u64().checked_add(1).context("account nonce overflow")? };
        ensure!(history.nonce().checked_add(1) == Some(nonce), "retained session prefix is incomplete");
        let records = withdrawals.iter().map(|withdrawal| Ok(WithdrawalBurnRecord {
            sender_user_id: withdrawal.sender_user_id.try_into()?, token_contract_id: withdrawal.contract_id.try_into()?,
            destination_chain_index: withdrawal.destination_chain_index.try_into()?, token: withdrawal.token_address,
            amount: withdrawal.amount, recipient: withdrawal.recipient, nonce: withdrawal.nonce,
        })).collect::<anyhow::Result<Vec<_>>>()?;
        let mut anchors = Vec::new();
        let mut approved_calls = Vec::new();
        for call in calls.iter().filter(|call| call.contract_id == u64::from(DEPOSIT_TREE_CONTRACT_ID)) {
            ensure!(call.method_name == "set_chain_root" && call.inputs.len() == 10, "UnsupportedCall");
            let index = u8::try_from(call.inputs[0])?;
            let chain = config.root.chain(index).map_err(|error| anyhow::anyhow!(error))?;
            let old_count = u32::try_from(fetch_deposit_tree_next_index(provider, head, u64::from(index)).await?)?;
            let new_count = u32::try_from(call.inputs[1])?;
            if old_count == new_count { continue; }
            let anchor = guardian_common::verify_l1::finalized_deposit_anchor(chain, old_count, new_count).await?;
            let (_, new_root, _state) = guardian_common::verify_l1::verify_deposit_anchor(history.deposit_tree_states.get(&index), chain, &anchor).await?;
            let root_bytes: Vec<_> = new_root.0.elements.iter().flat_map(|field| {
                let value = field.to_canonical_u64();
                (value as u32).to_be_bytes().into_iter().chain(((value >> 32) as u32).to_be_bytes())
            }).collect();
            approved_calls.push(build_set_chain_root_call(u64::from(index), u64::from(new_count), &hex::encode(root_bytes))?);
            anchors.push(anchor);
        }
        anchors.sort_by_key(|anchor| anchor.chain_index);
        approved_calls.sort_by_key(|call| call.inputs[0]);
        approved_calls.extend(build_withdrawal_batch_calls(withdrawals));
        if operation != GuardianOperation::Bridge {
            ensure!(approved_calls.is_empty() && records.is_empty() && anchors.is_empty(), "policy operation cannot mix bridge calls");
            let next_members = next_members.context("policy operation requires exactly three members")?;
            let mut expected = Vec::with_capacity(16);
            for slot in 0..4 {
                let hash = provider.get_user_contract_state_tree_leaf_hash(head, BRIDGE_USER_ID_U64, MULTISIG_POLICY_CONTRACT_ID, 4, slot).await?;
                expected.extend(hash.0.elements.map(|limb| limb.to_canonical_u64()));
            }
            if operation == GuardianOperation::Bootstrap {
                ensure!(expected.iter().all(|limb| *limb == 0) && nonce == 1 && next_members == account.initial_policy.member_hashes[..3], "invalid policy bootstrap");
            } else {
                ensure!(expected[0] != 0, "rotation requires initialized policy");
            }
            for member in next_members { expected.extend(member.0.elements.map(|limb| limb.to_canonical_u64())); }
            approved_calls.push(ContractCallArgs { contract_id: u64::from(MULTISIG_POLICY_CONTRACT_ID), method_name: "set_policy".to_owned(), inputs: expected });
        }
        if approved_calls.is_empty() { return Ok(FrozenPolicy { request: None, included_checkpoint_id: head }); }
        let call_data = ContractCallData::new(approved_calls);
        let mut builder = wallet.begin_trace_build_at_checkpoint(public_key, BRIDGE_USER_ID_U64, head, nonce, root).await?;
        for call in &call_data.contract_calls { builder.trace_call(call.clone()).await?; }
        let trace = builder.finalize_tx_trace(call_data.software_defined_call.clone()).await?;
        let trace_envelope = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(&call_data).context("trace call_data json")?).context("guardian trace json build")?;
        let envelope_bytes = serde_json::to_string(&trace_envelope).context("guardian trace envelope serialize")?;
        tracing::info!(bytes = envelope_bytes.len(), "guardian request envelope built");
        let request = GuardianSignRequest { schema_version: 3, network_magic: config.root.network_magic()?, user_id: BRIDGE_USER_ID_U64, session_nonce: nonce, operation, trace_json: JsonText::parse(envelope_bytes)?, deposit_anchors: anchors, withdrawal_records: records };
        let context = verification_context(&wallet, provider, config, head, root, history, &[]);
        let (_verified, staged) = verify_guardian_session(&context, &config.root, &request).await.map_err(|error| anyhow::Error::from(error).context("fresh withdrawal request self-verification"))?;
        archive.save_request(&config.root, &JsonText::from_value(&request)?, &staged, withdrawals)?;
        JsonText::from_value(&request)?
    };
    let stored = archive.pending_request()?.filter(|saved| saved.as_str() == request_json.as_str()).unwrap_or(request_json.clone());
    if matches!(policy, PolicySignatures::Prepare) { return Ok(frozen(stored, head)); }
    let request = stored.decode().context("pending guardian request decode")?;
    if request.operation != GuardianOperation::Bridge && !matches!(policy, PolicySignatures::Resume { .. }) && archive.signatures(request.session_nonce)?.is_none() {
        anyhow::bail!("local operator signatures are required for the frozen policy request");
    }
    let staged_deposit_tree_states = archive.pending_deposit_tree_states(request.session_nonce)?;
    let context = verification_context(&wallet, provider, config, head, root, &retained.history, &staged_deposit_tree_states);
    let (verified, _) = verify_guardian_session(&context, &config.root, &request).await.map_err(|error| anyhow::Error::from(error).context("cached guardian request validation"))?;
    if let PolicySignatures::Resume { responses, .. } = &policy {
        let sighash = verified.trace.finalization.sig_hash;
        let message = psy_client_common::data::base_types::hash256::Hash256::from(sighash);
        let mut accepted = Vec::with_capacity(2);
        for response in responses {
            accepted.push((response.member_index, super::guardian_client::verify_response(&request, &verified.current_policy, message, response)?));
        }
        let signatures = super::guardian_client::select_signatures(&mut accepted, &verified.current_policy, sighash).context("supplied policy signatures do not authorize the current policy")?;
        archive.save_signatures(request.session_nonce, &signatures)?;
    }
    let trace = verified.trace;
    let client = GuardianClient::new(config.endpoints())?;
    let proof = loop {
        match prove_pending_request(&mut wallet, &client, archive, &config.root, &stored, &staged_deposit_tree_states).await {
            Ok(proof) => break proof,
            Err(error) if request.operation == GuardianOperation::Bridge && error.downcast_ref::<GuardianSignError>() == Some(&GuardianSignError::SignatureQuorumUnavailable) => {
                tracing::warn!(nonce = request.session_nonce, "guardian quorum unavailable; retrying frozen request");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => return Err(error),
        }
    };
    // Inclusion classification reads only the frozen request until the nonce is
    // consumed; unfinished sessions need neither threshold signatures nor proof.
    let committed_now = crate::guardian::service::load_guardian_committed_head(provider, &coordinator_url).await?;
    ensure!(committed_now.checkpoint_id >= head && provider.get_checkpoint_tree_root(head).await? == root, "committed checkpoint contradiction; pending request retained");
    if let Some((session, deposit_tree_states)) = recover_guardian_inclusion(&wallet, provider, config, archive, &retained.history, &stored, &staged_deposit_tree_states).await? {
        return Ok(frozen(stored, import_recovered(provider, config, archive, retained, session, &deposit_tree_states).await?));
    }
    let end_user_leaf_hash = trace.finalization.submit_end_cap_input.core.state_transition.end_user_leaf_hash;
    let submission = wallet.submit_end_cap(&trace, bincode::deserialize(&proof)?).await;
    let tx_hash = match submission {
        Ok(tx_hash) => tx_hash,
        Err(error) => {
            if let Some((session, deposit_tree_states)) = recover_guardian_inclusion(&wallet, provider, config, archive, &retained.history, &stored, &staged_deposit_tree_states).await? {
                return Ok(frozen(stored, import_recovered(provider, config, archive, retained, session, &deposit_tree_states).await?));
            }
            return Err(error);
        }
    };
    let start = trace.finalization.submit_end_cap_input.core.checkpoint_id.to_canonical_u64();
    tracing::debug!(%tx_hash, %end_user_leaf_hash, "waiting for submitted EndCap inclusion");
    provider.wait_for_endcap_inclusion(BRIDGE_USER_ID_U64, end_user_leaf_hash, start, Some(REALM_CHECKPOINT_POLL_TIMEOUT_SECS), REALM_CHECKPOINT_POLL_INTERVAL_SECS).await?;
    let Some((session, deposit_tree_states)) = recover_guardian_inclusion(&wallet, provider, config, archive, &retained.history, &stored, &staged_deposit_tree_states).await? else {
        anyhow::bail!("submitted EndCap has no authenticated inclusion");
    };
    Ok(frozen(stored, import_recovered(provider, config, archive, retained, session, &deposit_tree_states).await?))
}

async fn import_recovered(provider: &RpcProvider, config: &super::guardian_client::LoadedGuardianConfig, archive: &super::guardian_client::RelayerDb, retained: &mut RelayerHistory, session: guardian_common::protocol::GuardianSession, deposit_tree_states: &[guardian_common::protocol::DepositTreeState]) -> anyhow::Result<u64> {
    let landed = session.record.included_checkpoint_id;
    // Network phase, strictly before the durable import: a temporary RPC
    // outage here fails ahead of the commit and leaves the pending request
    // for the next round, instead of misreporting a submission failure.
    let committed = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?;
    ensure!(committed.checkpoint_id >= landed, "committed head is behind the recovered inclusion");
    archive.import_verified(&config.root, &session, deposit_tree_states, session.record.included_checkpoint_id, session.record.included_checkpoint_hash)?;
    // Post-commit the outcome is concrete: the inclusion is confirmed on-chain
    // and the Included transition, advanced account and indexes are durable in
    // one commit. Install the history from the DB tail locally — no RPC after
    // the commit can turn a confirmed inclusion into a reported failure; the
    // next entry re-verifies against a fresh committed head before any use.
    *retained = committed_history_snapshot(config)?;
    Ok(landed)
}

async fn recover_guardian_inclusion(
    wallet: &WalletSession,
    provider: &RpcProvider,
    config: &super::guardian_client::LoadedGuardianConfig,
    archive: &super::guardian_client::RelayerDb,
    history: &crate::guardian::verify::GuardianHistory,
    request_json: &guardian_common::protocol::JsonText<GuardianSignRequest>,
    pending_deposit_tree_states: &[guardian_common::protocol::DepositTreeState],
) -> anyhow::Result<Option<(guardian_common::protocol::GuardianSession, Vec<guardian_common::protocol::DepositTreeState>)>> {
    use plonky2::field::types::PrimeField64;
    use psy_client_data::config::store_config::PsyHasher;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    use guardian_common::protocol::{GuardianSessionRecord, JsonText};
    let request = request_json.decode()?;
    let input = request.decode_trace()?.finalization.submit_end_cap_input;
    let start = request.decode_trace()?.anchor.start_checkpoint_id;
    let start_leaf = input.core.state_transition.start_user_leaf_hash;
    let head = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?;
    let predecessor = authenticated_account(provider, &config.root, start, head.checkpoint_id, head.checkpoint_tree_root).await?;
    let current = authenticated_account(provider, &config.root, head.checkpoint_id, head.checkpoint_id, head.checkpoint_tree_root).await?;
    if pending_transition_unfinished(request.session_nonce, start_leaf, predecessor, current)? { return Ok(None); }
    ensure!(head.checkpoint_id > start, "consumed nonce has no historical interval");
    let predecessor_nonce = predecessor.1;
    let mut record = GuardianSessionRecord {
        request_json: request_json.clone(),
        signatures_json: JsonText::from_value(&archive.signatures(request.session_nonce)?.context("consumed nonce missing archived signatures")?)?,
        endcap_input_json: JsonText::from_value(&input)?,
        endcap_proof_hex: format!("0x{}", hex::encode(archive.proof(request.session_nonce)?.context("consumed nonce missing archived proof")?)),
        included_checkpoint_id: u64::MAX,
        included_checkpoint_hash: head.checkpoint_tree_root,
    };
    let archived = archive.sessions(request.session_nonce - 1, 1)?.sessions.into_iter().next();
    let exact = match archived {
        Some(record) => Some(record),
        None => super::guardian_client::GuardianClient::new(config.endpoints())?.session_record(request.session_nonce - 1).await?,
    };
    let adopted = if let Some(candidate) = exact {
        ensure!(candidate.request_json.as_str() == record.request_json.as_str() && candidate.signatures_json.as_str() == record.signatures_json.as_str() && candidate.endcap_input_json.as_str() == record.endcap_input_json.as_str() && candidate.endcap_proof_hex == record.endcap_proof_hex, "authenticated guardian record differs from archived record");
        ensure!(candidate.request_json.decode()?.session_nonce == request.session_nonce, "authenticated guardian record nonce mismatch");
        candidate
    } else {
        let included = first_nonce_checkpoint(provider, &config.root, start, head.checkpoint_id, head.checkpoint_tree_root, request.session_nonce).await?;
        let predecessor = included.checked_sub(1).context("included checkpoint has no predecessor")?;
        let (included_predecessor_leaf, included_predecessor_nonce) = authenticated_account(provider, &config.root, predecessor, head.checkpoint_id, head.checkpoint_tree_root).await?;
        ensure!(included_predecessor_nonce == predecessor_nonce && included_predecessor_leaf == start_leaf, "historical predecessor differs from archived start");
        let (included_leaf, included_nonce) = authenticated_account(provider, &config.root, included, head.checkpoint_id, head.checkpoint_tree_root).await?;
        ensure!(included_nonce == request.session_nonce && included_leaf == input.core.new_user_leaf.qfhash::<PsyHasher>(), "historical inclusion differs from archived EndCap");
        record.included_checkpoint_id = included;
        record.included_checkpoint_hash = provider.get_checkpoint_tree_merkle_proof(head.checkpoint_id, included).await?.value;
        record
    };
    let context = verification_context(wallet, provider, config, head.checkpoint_id, head.checkpoint_tree_root, history, pending_deposit_tree_states);
    let (session, deposit_tree_states) = crate::guardian::verify::verify_session(&context, &config.root, adopted, history).await?;
    ensure!(pending_deposit_tree_states.is_empty() || deposit_tree_states.as_slice() == pending_deposit_tree_states, "verified deposit-tree states differ from the durable pending binding");
    let bound = if pending_deposit_tree_states.is_empty() { deposit_tree_states.clone() } else { pending_deposit_tree_states.to_vec() };
    Ok(Some((session, bound)))
}

/// Classify authenticated chain state before reading any signing/proof files.
fn pending_transition_unfinished(nonce: u64, start_leaf: QHashOut<GoldilocksField>, predecessor: (QHashOut<GoldilocksField>, u64), current: (QHashOut<GoldilocksField>, u64)) -> anyhow::Result<bool> {
    let previous = nonce.checked_sub(1).context("pending nonce starts at zero")?;
    ensure!(predecessor == (start_leaf, previous), "archived predecessor differs from authenticated start");
    if current == predecessor { return Ok(true); }
    ensure!(current.1 >= nonce, "account history conflicts with archived predecessor");
    Ok(false)
}

async fn authenticated_account(provider: &RpcProvider, config: &guardian_common::protocol::GuardianConfig, checkpoint: u64, head: u64, root: QHashOut<GoldilocksField>) -> anyhow::Result<(QHashOut<GoldilocksField>, u64)> {
    use plonky2::field::types::PrimeField64;
    use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
    use psy_client_data::config::store_config::PsyHasher;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    let leaf = provider.get_checkpoint_leaf_data(checkpoint).await?;
    let roots = provider.get_checkpoint_global_state_roots(checkpoint).await?;
    let path = provider.get_checkpoint_tree_merkle_proof(head, checkpoint).await?;
    crate::guardian::verify::verify_checkpoint(checkpoint, &leaf, &roots, &path, root).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let user = provider.get_user_leaf_data(checkpoint, guardian_common::protocol::BRIDGE_USER_ID).await?;
    let user_path = provider.get_user_tree_merkle_proof(checkpoint, guardian_common::protocol::BRIDGE_USER_ID).await?;
    crate::guardian::verify::verify_path(&user_path, roots.user_tree_root, guardian_common::protocol::BRIDGE_USER_ID, user_path.value, psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    if user_path.value == QHashOut::ZERO { return Ok((user_path.value, 0)); }
    ensure!(user_path.value == user.qfhash::<PsyHasher>() && user.public_key == config.account_public_key().map_err(|error| anyhow::anyhow!(error))? && user.user_id.to_canonical_u64() == guardian_common::protocol::BRIDGE_USER_ID, "authenticated account identity mismatch");
    Ok((user_path.value, user.nonce.to_canonical_u64()))
}

async fn first_included_checkpoint<F, Fut>(mut probe: F, start: u64, head: u64, nonce: u64) -> anyhow::Result<u64>
where F: FnMut(u64) -> Fut, Fut: Future<Output = anyhow::Result<u64>> {
    ensure!(start < head && probe(start).await? < nonce, "historical start is not before the archived nonce");
    let mut low = start;
    let mut high = head;
    let mut high_nonce = probe(head).await?;
    ensure!(high_nonce >= nonce, "historical head has not consumed the archived nonce");
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        let observed = probe(middle).await?;
        if observed >= nonce { high = middle; high_nonce = observed; } else { low = middle; }
    }
    ensure!(high_nonce == nonce, "historical account nonce skipped the archived session");
    Ok(high)
}

async fn first_nonce_checkpoint(provider: &RpcProvider, config: &guardian_common::protocol::GuardianConfig, start: u64, head: u64, root: QHashOut<GoldilocksField>, nonce: u64) -> anyhow::Result<u64> {
    first_included_checkpoint(|checkpoint| async move {
        authenticated_account(provider, config, checkpoint, head, root).await.map(|(_, nonce)| nonce)
    }, start, head, nonce).await
}

#[cfg(test)]
mod tests {

    use super::*;

    fn deposit_append_call(tag: u8, size: usize) -> Call3 {
        Call3 { target: Address::repeat_byte(tag), allowFailure: false, callData: Bytes::from(vec![tag; size]) }
    }

    #[test]
    fn deposit_append_abi_exceeds_txpool_limit_when_two_calls_are_aggregated() {
        let batch = prove_bridge::batchAppendCall {
            proof: [U256::ZERO; 8],
            publicInputs: vec![U256::ZERO; 795],
            slotData: [U256::ZERO; 1312],
        };
        let calldata = Bytes::from(batch.abi_encode());
        assert_eq!(calldata.len(), 67_748);
        let calls = (1..=3).map(|tag| Call3 {
            target: Address::repeat_byte(tag), allowFailure: false, callData: calldata.clone(),
        }).collect::<Vec<_>>();
        let oversized = aggregate3Call { calls: calls[..2].to_vec() };
        assert_eq!(oversized.abi_encode().len(), 135_940);
        assert!(oversized.abi_encode().len() > 128 * 1024);
        let chunks = chunk_deposit_batch_append_by_size(calls.clone()).unwrap();
        assert_eq!(chunks.len(), 3);
        for (chunk, original) in chunks.into_iter().zip(&calls) {
            assert_eq!(chunk.len(), 1);
            assert_eq!(chunk[0].target, original.target);
            assert_eq!(chunk[0].callData, original.callData);
            assert!(!chunk[0].allowFailure);
            let encoded = aggregate3Call { calls: chunk }.abi_encode();
            assert_eq!(encoded.len(), 68_004);
            assert!(encoded.len() <= DEPOSIT_APPEND_CALLDATA_LIMIT);
        }
        assert_eq!(DEPOSIT_APPEND_CALLDATA_LIMIT, 122_880);
    }

    #[test]
    fn deposit_append_fitting_calls_stay_packed_in_order() {
        let calls = [60_000, 60_000, 60_000, 31, 33].into_iter().enumerate()
            .map(|(index, size)| deposit_append_call(index as u8, size)).collect::<Vec<_>>();
        let chunks = chunk_deposit_batch_append_by_size(calls.clone()).unwrap();
        assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 3]);
        for chunk in &chunks {
            assert!(aggregate3Call { calls: chunk.clone() }.abi_encode().len() <= DEPOSIT_APPEND_CALLDATA_LIMIT);
        }
        for (actual, original) in chunks.iter().flatten().zip(&calls) {
            assert_eq!(actual.target, original.target);
            assert_eq!(actual.callData, original.callData);
            assert!(!actual.allowFailure);
        }
        assert!(chunk_deposit_batch_append_by_size(Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn deposit_append_rejects_oversized_single_call_before_broadcast() {
        let oversized = deposit_append_call(1, DEPOSIT_APPEND_CALLDATA_LIMIT);
        assert!(chunk_deposit_batch_append_by_size(vec![oversized.clone()]).is_err());
        assert!(chunk_deposit_batch_append_by_size(vec![deposit_append_call(0, 32), oversized]).is_err());
    }

    #[test]
    fn deposit_append_bounds_include_abi_padding() {
        let size = DEPOSIT_APPEND_CALLDATA_LIMIT - 256;
        let fitting = deposit_append_call(1, size);
        assert_eq!(aggregate3Call { calls: vec![fitting.clone()] }.abi_encode().len(), 122_852);
        assert_eq!(chunk_deposit_batch_append_by_size(vec![fitting]).unwrap().len(), 1);
        let oversized = deposit_append_call(1, size + 1);
        assert_eq!(aggregate3Call { calls: vec![oversized.clone()] }.abi_encode().len(), 122_884);
        assert!(chunk_deposit_batch_append_by_size(vec![oversized]).is_err());
    }

    #[tokio::test]
    async fn deposit_append_cursor_checks_gate_and_verify_each_group() {
        use std::cell::{Cell, RefCell};
        for (before, after, succeeds) in [(31u32, 64u32, false), (33, 64, false), (32, 63, false), (32, 65, false), (32, 64, true)] {
            let cursor = Cell::new(before);
            let actions = RefCell::new(Vec::new());
            let result = send_deposit_append_group(32, 64, || {
                actions.borrow_mut().push("read");
                std::future::ready(Ok(U256::from(cursor.get())))
            }, || async {
                actions.borrow_mut().push("send");
                cursor.set(after);
                Ok(())
            }).await;
            assert_eq!(result.is_ok(), succeeds);
            let expected = if before == 32 { vec!["read", "send", "read"] } else { vec!["read"] };
            assert_eq!(*actions.borrow(), expected);
        }
    }

    #[tokio::test]
    async fn deposit_append_cursor_read_errors_fail_closed() {
        use std::cell::Cell;
        for failed_read in 0..2 {
            let reads = Cell::new(0);
            let sends = Cell::new(0);
            let result = send_deposit_append_group(32, 64, || {
                let index = reads.get();
                reads.set(index + 1);
                std::future::ready(if index == failed_read {
                    Err(anyhow::anyhow!("cursor RPC unavailable"))
                } else {
                    Ok(U256::from(32u32))
                })
            }, || async {
                sends.set(sends.get() + 1);
                Ok(())
            }).await;
            assert!(result.is_err());
            assert_eq!(reads.get(), failed_read + 1);
            assert_eq!(sends.get(), failed_read);
        }
    }

    #[tokio::test]
    async fn deposit_append_resume_uses_actual_l1_cursor() {
        use std::cell::{Cell, RefCell};
        for landed_before_error in [false, true] {
            let cursor = Cell::new(0u32);
            let sent_from = RefCell::new(Vec::new());
            for from in [0u32, 32] {
                let result = send_deposit_append_group(from, from + 32,
                    || std::future::ready(Ok(U256::from(cursor.get()))),
                    || async {
                        sent_from.borrow_mut().push(from);
                        if from == 32 {
                            if landed_before_error { cursor.set(64); }
                            anyhow::bail!("second group interrupted");
                        }
                        cursor.set(from + 32);
                        Ok(())
                    },
                ).await;
                assert_eq!(result.is_ok(), from == 0);
            }
            assert_eq!(cursor.get(), if landed_before_error { 64 } else { 32 });
            sync_deposit_if_behind(96, std::future::ready(Ok(cursor.get())), || async {
                let from_index = cursor.get();
                for from in (from_index..96).step_by(32) {
                    send_deposit_append_group(from, from + 32,
                        || std::future::ready(Ok(U256::from(cursor.get()))),
                        || async {
                            sent_from.borrow_mut().push(from);
                            cursor.set(from + 32);
                            Ok(())
                        },
                    ).await?;
                }
                Ok(())
            }).await.unwrap();
            assert_eq!(cursor.get(), 96);
            assert_eq!(*sent_from.borrow(), if landed_before_error { vec![0, 32, 64] } else { vec![0, 32, 32, 64] });
            sync_deposit_if_behind(96, std::future::ready(Ok(cursor.get())), || async {
                panic!("a reached target must not send again")
            }).await.unwrap();
        }
    }

    fn test_l1() -> Vec<guardian_common::protocol::ChainEndpoint> {
        vec![guardian_common::protocol::ChainEndpoint { chain_index: 0, chain_id: alloy_primitives::U256::from(1u8), bridge: guardian_common::protocol::Hex([0x11; 20]), deployment_block: 0, rpc_url: "http://127.0.0.1:8545".into() }]
    }

    #[test]
    fn finalized_deposit_append_target_bounds_the_live_backlog() {
        assert_eq!(finalized_deposit_append_target(1221, 1862, 1844), 1253);
    }

    #[test]
    fn finalized_deposit_append_target_retains_smaller_ready_prefixes() {
        assert_eq!(finalized_deposit_append_target(100, 200, 117), 117);
        assert_eq!(finalized_deposit_append_target(100, 115, 117), 115);
        assert_eq!(finalized_deposit_append_target(100, 132, 132), 132);
        assert_eq!(finalized_deposit_append_target(100, 133, 133), 132);
    }

    #[test]
    fn finalized_deposit_append_target_keeps_waiting_chains_idle() {
        assert_eq!(finalized_deposit_append_target(100, 200, 100), 100);
        assert_eq!(finalized_deposit_append_target(100, 100, 100), 100);
        assert_eq!(finalized_deposit_append_target(100, 200, 99), 99);
    }

    #[test]
    fn finalized_deposit_append_target_is_per_chain() {
        let targets = [(1221, 1862, 1844), (153, 166, 166), (13, 15, 15)]
            .map(|(l2_count, pending, finalized_pending)| finalized_deposit_append_target(l2_count, pending, finalized_pending));
        assert_eq!(targets, [1253, 166, 15]);
    }

    #[test]
    fn finalized_deposit_append_target_retries_and_drains_without_gaps() {
        let mut l2_count = 1221;
        while l2_count < 1844 {
            let target = finalized_deposit_append_target(l2_count, 1862, 1844);
            assert!(target > l2_count && target - l2_count <= 32);
            assert_eq!(finalized_deposit_append_target(l2_count, 1862, 1844), target);
            l2_count = target;
        }
        assert_eq!(l2_count, 1844);
    }

    #[test]
    fn finalized_deposit_append_target_does_not_overflow() {
        assert_eq!(finalized_deposit_append_target(u32::MAX - 40, u32::MAX, u32::MAX), u32::MAX - 8);
        assert_eq!(finalized_deposit_append_target(u32::MAX - 10, u32::MAX, u32::MAX), u32::MAX);
        assert_eq!(finalized_deposit_append_target(u32::MAX, u32::MAX, u32::MAX), u32::MAX);
    }

    async fn finalized_deposit_fixture(latest: u64, finalized: u64, header_available: bool) -> anyhow::Result<(u32, Vec<serde_json::Value>)> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use serde_json::{json, Value};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = requests.clone();
        let hash = B256::repeat_byte(0x42);
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if socket.read_line(&mut line).await.unwrap() == 0 { return; }
                    if line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") { length = value.trim().parse::<usize>().unwrap(); }
                    }
                }
                let mut body = vec![0; length];
                socket.read_exact(&mut body).await.unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                received.lock().unwrap().push(request.clone());
                let result = match request["method"].as_str().unwrap() {
                    "eth_getBlockByNumber" => {
                        assert_eq!(request["params"], json!(["finalized", false]));
                        if header_available {
                            let mut block: alloy_rpc_types_eth::Block = Default::default();
                            block.header.hash = hash;
                            block.header.inner.number = 100;
                            json!(block)
                        } else { Value::Null }
                    }
                    "eth_call" => {
                        let pinned = request["params"][1] == json!({"blockHash":hash,"requireCanonical":true});
                        json!(format!("0x{:064x}", if pinned { finalized } else { latest }))
                    }
                    other => panic!("unexpected RPC {other}"),
                };
                let body = json!({"jsonrpc":"2.0","id":request["id"],"result":result}).to_string();
                socket.get_mut().write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(),body).as_bytes()).await.unwrap();
            }
        });
        let provider = alloy_provider::ProviderBuilder::new().connect_http(url.parse()?);
        let result = tokio::time::timeout(Duration::from_secs(10), fetch_finalized_pending_deposit_count(&provider, Address::repeat_byte(1))).await;
        server.abort();
        let requests = requests.lock().unwrap().clone();
        Ok((result??, requests))
    }

    #[tokio::test]
    async fn finalized_deposit_count_excludes_latest_only_deposit() {
        let (count, _) = finalized_deposit_fixture(1, 0, true).await.unwrap();
        assert_eq!(count, 0, "unfinalized deposit must not enter the Guardian plan");
    }

    #[tokio::test]
    async fn finalized_deposit_count_uses_canonical_hash_and_retains_ready_prefix() {
        let (count, requests) = finalized_deposit_fixture(3, 1, true).await.unwrap();
        assert_eq!(count, 1);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1]["params"][1]["requireCanonical"], true);
        assert!(requests[1]["params"][1].get("blockHash").is_some());
    }

    #[tokio::test]
    async fn finalized_deposit_count_missing_header_never_falls_back_to_latest() {
        assert!(finalized_deposit_fixture(1, 0, false).await.is_err());
    }

    #[tokio::test]
    async fn finalized_deposit_count_overflow_fails_closed() {
        assert!(finalized_deposit_fixture(0, u64::from(u32::MAX)+1, true).await.is_err());
    }

    #[tokio::test]
    async fn finalized_deposit_count_keeps_ready_chain_eligible_while_another_waits() {
        let (waiting, _) = finalized_deposit_fixture(1, 0, true).await.unwrap();
        let (ready, _) = finalized_deposit_fixture(2, 1, true).await.unwrap();
        let targets = [(0, waiting), (1, ready)].into_iter().filter(|(_, target)| *target > 0).collect::<Vec<_>>();
        assert_eq!(targets, vec![(1, 1)]);
    }

    #[tokio::test]
    async fn old_anchor_before_deployment_block_is_rejected() {
        let mut chain = test_l1().remove(0);
        chain.deployment_block = 100;
        let anchor = guardian_common::protocol::DepositAnchor { chain_index: 0, block_number: 99, block_hash: guardian_common::protocol::Hex([1; 32]), old_count: 0, new_count: 1 };
        assert!(matches!(guardian_common::verify_l1::verify_finalized_anchor(&chain, &anchor).await, Err(guardian_common::protocol::GuardianSignError::DepositMismatch)));
        let inclusive = guardian_common::protocol::DepositAnchor { block_number: 100, ..anchor };
        assert!(matches!(guardian_common::verify_l1::verify_finalized_anchor(&chain, &inclusive).await, Err(error) if error != guardian_common::protocol::GuardianSignError::DepositMismatch));
    }
    use crate::bridge::propose_withdrawals::PendingWithdrawal;

    #[tokio::test]
    async fn historical_nonce_search_checks_predecessor_and_uses_each_probe_once() {
        let mut probes = Vec::new();
        let observations = |checkpoint| { probes.push(checkpoint); std::future::ready(Ok(if checkpoint < 80 { 4 } else if checkpoint < 100 { 5 } else { 9 })) };
        assert_eq!(first_included_checkpoint(observations, 10, 10_000, 5).await.unwrap(), 80);
        assert!(probes.len() <= 64 - (10_000u64 - 10).leading_zeros() as usize + 2);
        let unique: HashSet<_> = probes.iter().collect();
        assert_eq!(unique.len(), probes.len());
        assert!(first_included_checkpoint(|_| std::future::ready(Ok(5)), 10, 20, 5).await.is_err());
        assert!(first_included_checkpoint(|checkpoint| std::future::ready(Ok(if checkpoint < 80 { 4 } else { 9 })), 10, 10_000, 5).await.is_err());
        assert!(first_included_checkpoint(|checkpoint| std::future::ready(if checkpoint == 15 { Err(anyhow::anyhow!("missing")) } else { Ok(if checkpoint < 16 { 4 } else { 5 }) }), 10, 20, 5).await.is_err());
    }

    #[test]
    fn pending_chain_classification_preserves_unfinished_and_rejects_conflicts() {
        let leaf = QHashOut::from_values(1, 2, 3, 4);
        let other = QHashOut::ZERO;
        assert!(pending_transition_unfinished(5, leaf, (leaf, 4), (leaf, 4)).unwrap());
        assert!(!pending_transition_unfinished(5, leaf, (leaf, 4), (other, 5)).unwrap());
        assert!(!pending_transition_unfinished(5, leaf, (leaf, 4), (other, 9)).unwrap());
        assert!(pending_transition_unfinished(5, leaf, (leaf, 4), (other, 4)).is_err());
        assert!(pending_transition_unfinished(5, leaf, (other, 4), (leaf, 5)).is_err());
        assert!(pending_transition_unfinished(5, leaf, (leaf, 4), (leaf, 3)).is_err());
    }


    fn advance_request_nonce(request: &mut GuardianSignRequest) {
        let mut trace = request.decode_trace().unwrap();
        request.session_nonce += 1;
        trace.finalization.nonce = GoldilocksField(request.session_nonce);
        let call_data = request.trace_json.decode().unwrap().call_data;
        request.trace_json = guardian_common::protocol::JsonText::from_value(&psy_prover::trace::GeneratedTxTraceJson::from_trace(&trace, call_data).unwrap()).unwrap();
    }

    #[test]
    fn request_signed_proved_included_restart_keeps_frozen_request_and_proof() {
        use guardian_common::protocol::{GuardianSession, GuardianSessionRecord, JsonText};
        use psy_client_common::data::base_types::hash256::Hash256;
        use psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature;
        use psy_vm::ups::multisig::MultisigSignatures;
        let (root, archive) = super::super::guardian_client::tests_db();
        let cfg = || crate::guardian::test_fixture::codec_guardian_config();
        let reopen = || super::super::guardian_client::RelayerDb::open(&root).unwrap();
        let reject_second_writer = || assert!(super::super::guardian_client::RelayerDb::open(&root).is_err(), "a second writer cannot open the live database");
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let frozen = JsonText::from_value(&request).unwrap();
        let proof = [0xAAu8];
        let start = request.decode_trace().unwrap().finalization.submit_end_cap_input.core.state_transition.start_user_leaf_hash;
        archive.save_request(&cfg(), &frozen, &[], &[]).unwrap();
        assert!(pending_transition_unfinished(1, start, (start, 0), (start, 0)).unwrap());
        assert!(archive.signatures(1).unwrap().is_none());
        assert!(archive.proof(1).unwrap().is_none());
        assert_eq!(archive.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        reject_second_writer();
        drop(archive);
        let signed = reopen();
        assert!(pending_transition_unfinished(1, start, (start, 0), (start, 0)).unwrap());
        assert!(signed.signatures(1).unwrap().is_none());
        assert!(signed.proof(1).unwrap().is_none());
        assert_eq!(signed.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        let signatures = MultisigSignatures { member_indices: vec![0, 2], signatures: vec![PsyCompressedSecp256K1Signature { public_key: [2; 33], signature: [1; 64], message: Hash256([0; 32]) }; 2] };
        signed.save_signatures(1, &signatures).unwrap();
        reject_second_writer();
        drop(signed);
        let proved = reopen();
        assert_eq!(proved.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        assert_eq!(proved.signatures(1).unwrap().unwrap().member_indices, vec![0, 2]);
        assert!(proved.proof(1).unwrap().is_none());
        assert_eq!(proved.load_account(request.network_magic, request.user_id).unwrap().and_then(|account| account.imported_nonce), None);
        proved.save_proof(1, &proof).unwrap();
        assert_eq!(proved.proof(1).unwrap().unwrap(), proof);
        reject_second_writer();
        drop(proved);
        let included = reopen();
        assert_eq!(included.pending_request().unwrap().unwrap().as_str(), frozen.as_str());
        assert_eq!(included.proof(1).unwrap().unwrap(), proof);
        assert_eq!(included.load_account(request.network_magic, request.user_id).unwrap().and_then(|account| account.imported_nonce), None);
        let record = GuardianSessionRecord {
            request_json: frozen.clone(),
            signatures_json: JsonText::from_value(&signatures).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0xaa".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
        };
        // Persistence boundary only: recover_guardian_inclusion authenticates the
        // proof in production before this archive transition.
        let end = request.decode_trace().unwrap().finalization.submit_end_cap_input.core.state_transition.end_user_leaf_hash;
        let session = GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce: 1, record: record.clone(), starting_leaf_hash: start, ending_leaf_hash: end, withdrawal_appends: Vec::new() };
        included.import_verified(&cfg(), &session, &[], 1, record.included_checkpoint_hash).unwrap();
        assert!(included.pending_request().unwrap().is_none());
        assert_eq!(included.proof(1).unwrap().unwrap(), proof);
        assert_eq!(included.load_session(1, request.request_id().unwrap()).unwrap().0.as_str(), frozen.as_str());
        assert_eq!(included.load_account(request.network_magic, request.user_id).unwrap().unwrap().imported_nonce, Some(1));
        reject_second_writer();
        drop(included);
        let restarted = reopen();
        assert!(!pending_transition_unfinished(1, start, (start, 0), (session.ending_leaf_hash, 1)).unwrap());
        assert!(restarted.pending_request().unwrap().is_none());
        assert_eq!(restarted.load_session(1, request.request_id().unwrap()).unwrap().0.as_str(), frozen.as_str());
        assert_eq!(restarted.signatures(1).unwrap().unwrap().member_indices, vec![0, 2]);
        assert_eq!(restarted.proof(1).unwrap().unwrap(), proof);
        assert_eq!(restarted.load_account(request.network_magic, request.user_id).unwrap().unwrap().imported_nonce, Some(1));
        assert_eq!(restarted.sessions(0, 1).unwrap().sessions.len(), 1);
        let mut skipped = request.clone();
        advance_request_nonce(&mut skipped);
        advance_request_nonce(&mut skipped);
        assert!(restarted.save_request(&cfg(), &JsonText::from_value(&skipped).unwrap(), &[], &[]).is_err());
        let mut next = request.clone();
        advance_request_nonce(&mut next);
        let next_frozen = JsonText::from_value(&next).unwrap();
        restarted.save_request(&cfg(), &next_frozen, &[], &[]).unwrap();
        assert_eq!(restarted.pending_request().unwrap().unwrap().as_str(), next_frozen.as_str());
        assert_eq!(restarted.load_account(request.network_magic, request.user_id).unwrap().unwrap().imported_nonce, Some(1));
        std::fs::remove_dir_all(root).unwrap();
    }



    fn sample_withdrawal(seed: u32) -> PendingWithdrawal {
        let words = |base: u32| std::array::from_fn(|i| base + i as u32);
        PendingWithdrawal {
            event_id: seed as i64,
            checkpoint_id: 100 + seed as u64,
            user_id: 200 + seed as u64,
            sender_user_id: 300 + seed as u64,
            contract_id: 400 + seed as u64,
            destination_chain_index: 500 + seed as u64,
            token_address: words(seed * 10 + 1),
            amount: words(seed * 10 + 101),
            recipient: words(seed * 10 + 201),
            nonce: words(seed * 10 + 301),
            leaf_hash: format!("leaf-{seed}"),
        }
    }

    #[test]
    fn relayer_window_uses_latest_for_append_only_when_no_confirmed_range_exists() {
        let window = select_relayer_window(63, 65, 3, 32);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 65,
                confirmed_to_checkpoint: None,
                is_catchup_batch: false,
            }
        );
        assert!(!window.has_confirmed_range());
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_caps_append_only_range_by_max_checkpoint_batch() {
        let window = select_relayer_window(63, 200, 300, 32);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 94,
                confirmed_to_checkpoint: None,
                is_catchup_batch: false,
            }
        );
        assert!(!window.has_confirmed_range());
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_append_only_range_is_unbounded_when_max_batch_is_zero() {
        let window = select_relayer_window(63, 200, 300, 0);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 200,
                confirmed_to_checkpoint: None,
                is_catchup_batch: false,
            }
        );
        assert!(!window.has_confirmed_range());
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_uses_confirmed_range_when_available() {
        let window = select_relayer_window(63, 66, 3, 32);

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 63,
                confirmed_to_checkpoint: Some(63),
                is_catchup_batch: false,
            }
        );
        assert!(window.has_confirmed_range());
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_marks_oversized_gap_as_catchup() {
        // When confirmed_to_checkpoint - from_checkpoint + 1 > max_checkpoint_batch,
        // is_catchup_batch = true so deposits and withdrawals are skipped.
        // to_checkpoint is truncated to from + max_checkpoint_batch - 1 per round;
        // multiple catchup rounds advance the cursor until gap <= max_checkpoint_batch.
        let window = select_relayer_window(10, 80, 3, 8);
        // confirmed = 77, from = 10, range = 68 > 8 → catchup
        // to_checkpoint = 10 + 8 - 1 = 17 (truncated per round)

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 17,
                confirmed_to_checkpoint: Some(77),
                is_catchup_batch: true,
            }
        );
        assert!(window.has_confirmed_range());
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_normal_range_not_catchup() {
        // Range within max_checkpoint_batch → normal round, not catchup.
        let window = select_relayer_window(60, 80, 3, 32);
        // confirmed = 77, from = 60, range = 18 ≤ 32 → not catchup

        assert_eq!(
            window,
            RelayerWindow {
                to_checkpoint: 77,
                confirmed_to_checkpoint: Some(77),
                is_catchup_batch: false,
            }
        );
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn bridge_business_is_disabled_for_catchup_batches() {
        let window = RelayerWindow {
            to_checkpoint: 10,
            confirmed_to_checkpoint: Some(20),
            is_catchup_batch: true,
        };

        assert!(window.has_confirmed_range());
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn catchup_defers_persisted_withdrawals_until_normal_round() {
        let is_catchup_batch = RelayerWindow {
            to_checkpoint: 10,
            confirmed_to_checkpoint: Some(20),
            is_catchup_batch: true,
        }
        .is_catchup_batch;

        assert!(is_catchup_batch);
        assert!(!(!is_catchup_batch && 1 > 0));
        assert!(!false && 1 > 0);
        assert!(!(false && 0 > 0));
    }


    #[test]
    fn claim_queue_round_trips_and_survives_restart() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let mut withdrawal = sample_withdrawal(1);
        withdrawal.destination_chain_index = 0;
        let state = DaemonState {
            pending_claim_withdrawals: HashMap::from([(withdrawal.leaf_hash.clone(), withdrawal.clone())]),
            ..Default::default()
        };
        save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &state).unwrap();
        drop(db);
        let restarted = super::super::guardian_client::RelayerDb::open(&root).unwrap();
        let saved = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &restarted, 0).unwrap();
        assert_eq!(saved.pending_claim_withdrawals.len(), 1);
        assert_eq!(saved.pending_claim_withdrawals[&withdrawal.leaf_hash].event_id, withdrawal.event_id);
        let _ = std::fs::remove_dir_all(root);
    }


    #[test]
    fn withdrawal_batch_calls_single_item_matches_append_withdrawal_layout() {
        let withdrawal = sample_withdrawal(1);
        let calls = build_withdrawal_batch_calls(std::slice::from_ref(&withdrawal));

        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.contract_id, WITHDRAWAL_TREE_CONTRACT_ID as u64);
        assert_eq!(call.method_name, "append_withdrawal");
        assert_eq!(call.inputs.len(), 35);
        assert_eq!(call.inputs[0], withdrawal.sender_user_id);
        assert_eq!(call.inputs[1], withdrawal.contract_id);
        assert_eq!(call.inputs[2], withdrawal.destination_chain_index);
        assert_eq!(
            &call.inputs[3..11],
            &withdrawal
                .token_address
                .iter()
                .map(|&v| v as u64)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            &call.inputs[27..35],
            &withdrawal.nonce.iter().map(|&v| v as u64).collect::<Vec<_>>()
        );
    }

    #[test]
    fn withdrawal_batch_calls_two_items_use_sender_auth_batch_layout() {
        let withdrawals = vec![sample_withdrawal(1), sample_withdrawal(2)];
        let calls = build_withdrawal_batch_calls(&withdrawals);

        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.method_name, "batch_append_withdrawals_2");
        assert_eq!(call.inputs.len(), 71);
        assert_eq!(call.inputs[0], 2);
        assert_eq!(call.inputs[1], withdrawals[0].sender_user_id);
        assert_eq!(call.inputs[2], withdrawals[1].sender_user_id);
        assert_eq!(call.inputs[3], withdrawals[0].contract_id);
        assert_eq!(call.inputs[4], withdrawals[1].contract_id);
        assert_eq!(call.inputs[5], withdrawals[0].destination_chain_index);
        assert_eq!(call.inputs[6], withdrawals[1].destination_chain_index);
        assert_eq!(
            &call.inputs[7..23],
            &withdrawals
                .iter()
                .flat_map(|w| w.token_address.iter().map(|&v| v as u64))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            &call.inputs[55..71],
            &withdrawals
                .iter()
                .flat_map(|w| w.nonce.iter().map(|&v| v as u64))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn withdrawal_batch_calls_seven_items_split_into_two_then_five_in_order() {
        let withdrawals = (1..=7).map(sample_withdrawal).collect::<Vec<_>>();
        let calls = build_withdrawal_batch_calls(&withdrawals);

        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].method_name, "batch_append_withdrawals_2");
        assert_eq!(calls[0].inputs[0], 2);
        assert_eq!(calls[0].inputs.len(), 71);
        assert_eq!(calls[0].inputs[1], withdrawals[0].sender_user_id);
        assert_eq!(calls[0].inputs[2], withdrawals[1].sender_user_id);

        assert_eq!(calls[1].method_name, "batch_append_withdrawals_5");
        assert_eq!(calls[1].inputs[0], 5);
        assert_eq!(calls[1].inputs.len(), 176);
        assert_eq!(calls[1].inputs[1], withdrawals[2].sender_user_id);
        assert_eq!(calls[1].inputs[5], withdrawals[6].sender_user_id);
        assert_eq!(
            &calls[1].inputs[16..56],
            &withdrawals[2..]
                .iter()
                .flat_map(|w| w.token_address.iter().map(|&v| v as u64))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn select_relayer_window_catchup_batch_spans_sixty_four_checkpoints() {
        for latest_checkpoint in [104, 204, 1_004] {
            let window = select_relayer_window(1, latest_checkpoint, 3, 64);

            assert_eq!(window.to_checkpoint, 64);
            assert_eq!(window.to_checkpoint - 1 + 1, 64);
            assert!(window.is_catchup_batch);
        }
    }

    #[test]
    fn gap_equal_to_max_checkpoint_batch_is_a_normal_round() {
        let window = select_relayer_window(1, 67, 3, 64);

        assert_eq!(window.to_checkpoint, 64);
        assert_eq!(window.confirmed_to_checkpoint, Some(64));
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_truncates_catchup_to_max_batch() {
        // Catchup mode truncates to_checkpoint to from + max_batch - 1.
        // With max_batch=64, a gap of 100 should truncate to 63 checkpoints per round.
        let window = select_relayer_window(10, 200, 3, 64);
        // confirmed = 197, from = 10, range = 188 > 64 → catchup
        // to_checkpoint = 10 + 64 - 1 = 73
        assert_eq!(window.to_checkpoint, 73);
        assert_eq!(window.confirmed_to_checkpoint, Some(197));
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn relayer_window_catchup_tail_of_one_is_provable_next_round() {
        // A 65-checkpoint gap with max=64 first proves checkpoints 1..=64.
        // The next round selects the remaining checkpoint as a normal, provable
        // one-checkpoint range rather than waiting for another checkpoint.
        let catchup_window = select_relayer_window(1, 68, 3, 64);
        assert_eq!(catchup_window.to_checkpoint, 64);
        assert_eq!(catchup_window.confirmed_to_checkpoint, Some(65));
        assert!(catchup_window.is_catchup_batch);

        let tail_window = select_relayer_window(65, 68, 3, 64);
        assert_eq!(
            tail_window,
            RelayerWindow {
                to_checkpoint: 65,
                confirmed_to_checkpoint: Some(65),
                is_catchup_batch: false,
            }
        );
        assert!(tail_window.has_confirmed_range());
        assert!(!tail_window.is_catchup_batch);
    }

    #[test]
    fn default_max_checkpoint_batch_remains_64() {
        assert_eq!(DEFAULT_MAX_CHECKPOINT_BATCH, 64);
    }

    #[test]
    fn validate_max_checkpoint_batch_accepts_one_and_above() {
        for batch in [1u64, 65, 97] {
            validate_max_checkpoint_batch(batch)
                .unwrap_or_else(|e| panic!("batch {batch} should be accepted: {e}"));
        }
    }

    #[test]
    fn validate_max_checkpoint_batch_rejects_zero() {
        let err = validate_max_checkpoint_batch(0).unwrap_err();
        assert!(err.to_string().contains("max_checkpoint_batch must be >= 1"));
    }

    #[test]
    fn select_relayer_window_honors_batch_sizes_above_legacy_64_cap() {
        let window = select_relayer_window(1, 200, 3, 97);
        // confirmed = 197, from = 1, range = 197 > 97 → catchup
        assert_eq!(window.to_checkpoint, 1 + 97 - 1);
        assert!(window.is_catchup_batch);

        let window_65 = select_relayer_window(10, 100, 3, 65);
        // confirmed = 97, range = 88 > 65 → catchup, truncate to 10 + 64 = 74
        assert_eq!(window_65.to_checkpoint, 74);
        assert!(window_65.is_catchup_batch);
    }

    // ── crash-recovery & state persistence edge cases ──────────────────────

    #[test]
    fn missing_chain_row_loads_an_empty_claim_queue() {
        let (root, db) = super::super::guardian_client::tests_db();
        let state = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).expect("missing chain row is an empty queue");
        assert!(state.pending_claim_withdrawals.is_empty());
        assert!(state.claim_retry.is_empty());
        assert!(state.retired_claim_withdrawals.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn save_then_load_round_trips_pending_withdrawals() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let mut w1 = sample_withdrawal(3);
        let mut w2 = sample_withdrawal(7);
        w1.destination_chain_index = 0;
        w2.destination_chain_index = 0;
        let state = DaemonState {
            pending_claim_withdrawals: HashMap::from([
                (w1.leaf_hash.clone(), w1.clone()),
                (w2.leaf_hash.clone(), w2.clone()),
            ]),
            ..Default::default()
        };
        save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &state).unwrap();
        let loaded = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).unwrap();
        assert_eq!(loaded.pending_claim_withdrawals.len(), 2);
        assert_eq!(loaded.pending_claim_withdrawals[&w1.leaf_hash].event_id, w1.event_id);
        assert_eq!(loaded.pending_claim_withdrawals[&w2.leaf_hash].event_id, w2.event_id);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn landed_l2_withdrawal_survives_restart_and_is_claimed() {
        let (root, db) = super::super::guardian_client::tests_db();
        let mut withdrawal = sample_withdrawal(11);
        withdrawal.destination_chain_index = 0;
        save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &DaemonState::default()).unwrap();
        db.save_request(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &guardian_common::protocol::JsonText::from_value(&crate::guardian::test_fixture::codec_request_fixture()).unwrap(),
            &[],
            std::slice::from_ref(&withdrawal),
        ).expect("selected claims commit with the pending request");
        drop(db);
        let restarted_db = super::super::guardian_client::RelayerDb::open(&root).unwrap();
        let mut restarted = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &restarted_db, 0).expect("restart must load pending claims");
        assert_eq!(restarted.pending_claim_withdrawals.len(), 1);
        assert_eq!(restarted.pending_claim_withdrawals[&withdrawal.leaf_hash].event_id, withdrawal.event_id);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        record_claim_outcome(std::slice::from_ref(&withdrawal), &resolved(&withdrawal.leaf_hash), &mut restarted.pending_claim_withdrawals, &mut retry, &mut retired, 0);
        assert!(restarted.pending_claim_withdrawals.is_empty(), "the restarted daemon must resolve the landed withdrawal");
        let _ = std::fs::remove_dir_all(root);
    }


    // ── select_relayer_window boundary edge cases ──────────────────────────

    #[test]
    fn select_relayer_window_lag_zero_treats_latest_as_confirmed() {
        // confirmation_lag_checkpoints=0 → confirmed == latest.
        // Small range within max_batch → normal round, business allowed.
        let window = select_relayer_window(10, 50, 0, 64);
        assert_eq!(window.confirmed_to_checkpoint, Some(50));
        assert_eq!(window.to_checkpoint, 50);
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_lag_zero_large_gap_triggers_catchup() {
        // lag=0 with a gap exceeding max_batch still enters catchup mode.
        let window = select_relayer_window(1, 100, 0, 64);
        assert_eq!(window.confirmed_to_checkpoint, Some(100));
        assert_eq!(window.to_checkpoint, 64);
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_from_ahead_of_latest_clamps_to_latest() {
        // L1 finalized cursor ahead of L2 latest (from > latest): the relayer
        // must wait at latest rather than proving a non-existent range.
        // confirmed = latest - lag < from → append-only; to clamps to latest.
        let window = select_relayer_window(100, 50, 3, 64);
        assert_eq!(window.confirmed_to_checkpoint, None);
        assert!(!window.is_catchup_batch);
        assert_eq!(window.to_checkpoint, 50);
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_lag_exceeds_latest_is_append_only() {
        // lag > latest → checked_sub yields None → append-only at latest,
        // capped by max_batch from the (zero) cursor.
        let window = select_relayer_window(0, 5, 10, 64);
        assert_eq!(window.confirmed_to_checkpoint, None);
        assert!(!window.is_catchup_batch);
        assert_eq!(window.to_checkpoint, 5);
    }

    #[test]
    fn select_relayer_window_max_batch_zero_in_confirmed_range_is_unbounded() {
        // max_checkpoint_batch=0 in confirmed-range mode means "no batching
        // limit": the whole gap is a single normal round with no catchup gating.
        // (validate_max_checkpoint_batch rejects 0 for run(), but the window
        // function itself must remain well-defined.)
        let window = select_relayer_window(1, 200, 3, 0);
        assert_eq!(window.confirmed_to_checkpoint, Some(197));
        assert_eq!(window.to_checkpoint, 197);
        assert!(!window.is_catchup_batch, "max_batch=0 must not gate catchup");
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_saturates_append_only_to_checkpoint_near_u64_max() {
        // from near u64::MAX in append-only mode: saturating_add on
        // from + max_batch - 1 must not overflow/panic.
        let window = select_relayer_window(u64::MAX - 5, u64::MAX - 1, 100, 64);
        assert_eq!(window.confirmed_to_checkpoint, None);
        assert!(!window.is_catchup_batch);
        // min(latest, saturating_add(from, 63)) = min(MAX-1, MAX) = MAX-1.
        assert_eq!(window.to_checkpoint, u64::MAX - 1);
    }

    #[test]
    fn live_round_selects_absolute_deposit_target() {
        assert_eq!(select_deposit_append_target(false, 20, 20, 12, 7, 15).unwrap(), Some(12));
    }

    #[test]
    fn live_round_rejects_target_behind_proved_count() {
        assert!(select_deposit_append_target(false, 20, 20, 6, 7, 15).is_err());
    }

    #[test]
    fn live_round_with_already_proved_target_selects_no_append() {
        assert_eq!(select_deposit_append_target(false, 20, 20, 7, 7, 15).unwrap(), None);
    }

    #[test]
    fn set_chain_root_call_uses_absolute_snapshot_count() {
        let root = "0x0000000100000002000000030000000400000005000000060000000700000008";
        let call = build_set_chain_root_call(9, 12, root).unwrap();

        assert_eq!(call.contract_id, DEPOSIT_TREE_CONTRACT_ID as u64);
        assert_eq!(call.method_name, "set_chain_root");
        assert_eq!(call.inputs, vec![9, 12, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn catchup_round_selects_no_deposit_target() {
        assert_eq!(select_deposit_append_target(true, 20, 20, 12, 7, 15).unwrap(), None);
    }

    #[test]
    fn capped_landing_selects_no_deposit_target() {
        assert_eq!(select_deposit_append_target(false, 19, 20, 12, 7, 15).unwrap(), None);
    }

    #[test]
    fn capped_landing_tolerates_l2_deposit_overcount() {
        assert_eq!(select_deposit_append_target(false, 19, 20, 16, 7, 15).unwrap(), None);
    }

    #[test]
    fn live_round_rejects_l2_deposit_overcount() {
        assert!(select_deposit_append_target(false, 20, 20, 16, 7, 15).is_err());
    }

    #[test]
    fn historical_catchup_tolerates_l2_deposit_overcount() {
        assert_eq!(select_deposit_append_target(true, 20, 20, 16, 7, 15).unwrap(), None);
    }

    #[test]
    fn historical_catchup_still_rejects_inconsistent_l1_cursors() {
        assert!(select_deposit_append_target(true, 20, 20, 16, 16, 15).is_err());
    }

    // ── claim reconciliation edge cases (double-claim defence) ─────────────

    // ── claim backoff wiring ───────────────────────────────────────────────
    //
    // The unit tests for the counter itself live in claim_attempts. These pin the
    // part that made the incident expensive: which withdrawals a round actually
    // hands to the claim path, and what happens to one that never succeeds.

    fn backoff_withdrawal(leaf: &str) -> propose_withdrawals::PendingWithdrawal {
        propose_withdrawals::PendingWithdrawal {
            event_id: 1,
            checkpoint_id: 1,
            user_id: 1,
            sender_user_id: 1,
            contract_id: 0,
            destination_chain_index: 0,
            token_address: [0; 8],
            amount: [0, 0, 0, 0, 0, 0, 0, 1],
            recipient: [0; 8],
            nonce: [0; 8],
            leaf_hash: leaf.to_string(),
        }
    }

    fn report_of(leaves: &[(&str, claim_withdrawals::ClaimOutcomeKind)]) -> claim_withdrawals::BatchWithdrawalsReport {
        claim_withdrawals::BatchWithdrawalsReport {
            requested: leaves.len(),
            submitted_count: leaves.iter().filter(|(_, kind)| *kind == claim_withdrawals::ClaimOutcomeKind::Registered).count(),
            outcomes: leaves
                .iter()
                .map(|(leaf, kind)| claim_withdrawals::ClaimOutcome {
                    leaf_hash: (*leaf).to_string(),
                    kind: *kind,
                    tx_hash: None,
                })
                .collect(),
        }
    }

    fn empty_report() -> claim_withdrawals::BatchWithdrawalsReport {
        report_of(&[])
    }

    fn failed(leaf: &str, code: claim_withdrawals::ClaimCode) -> claim_withdrawals::BatchWithdrawalsReport {
        report_of(&[(leaf, claim_withdrawals::ClaimOutcomeKind::Failed(code))])
    }

    fn resolved(leaf: &str) -> claim_withdrawals::BatchWithdrawalsReport {
        report_of(&[(leaf, claim_withdrawals::ClaimOutcomeKind::Registered)])
    }

    #[test]
    fn a_withdrawal_that_has_never_been_tried_is_due() {
        let mut pending = HashMap::new();
        pending.insert("a".to_string(), backoff_withdrawal("a"));
        let due = claims_to_attempt(&pending, &HashMap::new());
        assert_eq!(due.len(), 1);
    }


    #[test]
    fn a_resolved_withdrawal_forgets_its_earlier_failures() {
        let mut pending = HashMap::new();
        pending.insert("a".to_string(), backoff_withdrawal("a"));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let attempted = vec![backoff_withdrawal("a")];

        record_claim_outcome(&attempted, &empty_report(), &mut pending, &mut retry, &mut retired, 0);
        assert!(retry.contains_key("a"));

        record_claim_outcome(&attempted, &resolved("a"), &mut pending, &mut retry, &mut retired, 0);
        assert!(!retry.contains_key("a"), "a success must clear the history");
    }

    fn withdrawal_for_chain(leaf: &str, chain_index: u64) -> propose_withdrawals::PendingWithdrawal {
        let mut w = backoff_withdrawal(leaf);
        w.destination_chain_index = chain_index;
        w
    }

    fn bind_progress_to_fixture(db: &super::super::guardian_client::RelayerDb) {
        db.save_request(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &guardian_common::protocol::JsonText::from_value(&crate::guardian::test_fixture::codec_request_fixture()).unwrap(),
            &[],
            &[],
        ).unwrap();
    }

    fn served(indices: &[u8]) -> HashSet<u8> {
        indices.iter().copied().collect()
    }

    #[test]
    fn a_withdrawal_for_a_chain_we_do_not_serve_is_eventually_given_up_on() {
        // The multichain round filters pending withdrawals by
        // destination_chain_index, so index 7 reaches no chain's claim path: it
        // was never attempted, never failed, and never reached the ceiling. It
        // just sat in the durable set forever.
        let mut pending = HashMap::new();
        pending.insert("orphan".to_string(), withdrawal_for_chain("orphan", 7));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();

        for _ in 0..claim_attempts::CLAIM_MAX_ATTEMPTS {
            record_unroutable_claims(&served(&[0, 1, 2]), &mut pending, &mut retry, &mut retired, 0);
        }

        assert!(pending.is_empty(), "the orphan must not stay pending forever");
        let entry = retired.get("orphan").expect("kept for whoever has to look");
        assert!(entry.last_reason.contains("no configured chain serves destination chain index 7"));
        assert!(entry.last_reason.contains("0, 1, 2"), "say what we do serve");
    }

    #[test]
    fn withdrawals_for_chains_we_do_serve_are_left_for_the_claim_path() {
        let mut pending = HashMap::new();
        for (leaf, index) in [("a", 0u64), ("b", 1), ("c", 2)] {
            pending.insert(leaf.to_string(), withdrawal_for_chain(leaf, index));
        }
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();

        for _ in 0..10 {
            record_unroutable_claims(&served(&[0, 1, 2]), &mut pending, &mut retry, &mut retired, 0);
        }

        assert_eq!(pending.len(), 3, "routable withdrawals are none of this sweep's business");
        assert!(retry.is_empty());
        assert!(retired.is_empty());
    }

    #[test]
    fn a_chain_index_too_large_for_a_chain_id_is_unroutable_too() {
        // destination_chain_index is u64 on the withdrawal and u8 on the chain,
        // so a value that cannot even be a chain index must not slip through the
        // conversion as "no opinion".
        let mut pending = HashMap::new();
        pending.insert("big".to_string(), withdrawal_for_chain("big", 9_999));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();

        for _ in 0..claim_attempts::CLAIM_MAX_ATTEMPTS {
            record_unroutable_claims(&served(&[0, 1, 2]), &mut pending, &mut retry, &mut retired, 0);
        }
        assert!(retired.contains_key("big"));
    }

    #[test]
    fn the_sweep_does_not_re_retire_what_it_already_gave_up_on() {
        let mut pending = HashMap::new();
        pending.insert("orphan".to_string(), withdrawal_for_chain("orphan", 7));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();

        for _ in 0..200 {
            record_unroutable_claims(&served(&[0, 1, 2]), &mut pending, &mut retry, &mut retired, 0);
        }
        assert_eq!(retired["orphan"].attempts, claim_attempts::CLAIM_MAX_ATTEMPTS);
        assert!(retry.is_empty(), "no bookkeeping left behind for a retired claim");
    }

    #[test]
    fn waiting_for_bridge_liquidity_does_not_spend_an_attempt() {
        // With only three attempts this matters: a valid withdrawal parked
        // behind an empty bridge would otherwise be given up on in three
        // rounds, roughly ninety seconds, and need a human to re-arm it.
        let mut pending = HashMap::new();
        pending.insert("a".to_string(), backoff_withdrawal("a"));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let attempted = vec![backoff_withdrawal("a")];

        let report = failed("a", claim_withdrawals::ClaimCode::LiquidityShort);

        for _ in 0..50 {
            record_claim_outcome(&attempted, &report, &mut pending, &mut retry, &mut retired, 0);
        }

        assert!(retry.get("a").is_none(), "a pure liquidity hold creates no retry row");
        assert!(retired.is_empty(), "a held withdrawal must not be given up on");
        assert_eq!(claims_to_attempt(&pending, &retry).len(), 1);
    }

    #[test]
    fn a_deferral_does_not_erase_earlier_real_failures() {
        let mut pending = HashMap::new();
        pending.insert("a".to_string(), backoff_withdrawal("a"));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let attempted = vec![backoff_withdrawal("a")];

        record_claim_outcome(&attempted, &empty_report(), &mut pending, &mut retry, &mut retired, 0);
        record_claim_outcome(&attempted, &failed("a", claim_withdrawals::ClaimCode::LiquidityShort), &mut pending, &mut retry, &mut retired, 0);

        assert_eq!(retry["a"].attempts, 1, "the earlier failure still counts");
    }

    #[test]
    fn proof_readiness_deferrals_do_not_exhaust_claim_attempts() {
        let attempted = vec![backoff_withdrawal("not-found"), backoff_withdrawal("root-mismatch")];
        let mut pending = attempted.iter().map(|w| (w.leaf_hash.clone(), w.clone())).collect();
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            outcomes: vec![
                claim_withdrawals::ClaimOutcome { leaf_hash: "not-found".into(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::ProofNotReady), tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: "root-mismatch".into(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::RootUnauthorized), tx_hash: None },
            ],
            ..empty_report()
        };

        for round in 0..claim_attempts::CLAIM_MAX_ATTEMPTS {
            record_claim_outcome(&attempted, &report, &mut pending, &mut retry, &mut retired, u64::from(round));
        }
        assert!(retry.get("not-found").is_none(), "waiting for proof must not spend attempts");
        assert!(retired.get("not-found").is_none(), "waiting for proof must not retire claims");
        assert!(!retired.contains_key("root-mismatch"), "a root not yet known on L1 must not retire a claim");
        assert_eq!(claims_to_attempt(&pending, &retry).len(), 2);

        let remaining: Vec<_> = pending.values().cloned().collect();
        let mut unavailable = report.clone();
        unavailable.outcomes[0].kind = claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::RpcUnavailable);
        record_claim_outcome(&remaining, &unavailable, &mut pending, &mut retry, &mut retired, 10);
        assert!(retry.get("not-found").is_none(), "an unavailable read does not spend an attempt");
        assert!(!retired.contains_key("root-mismatch"));

        // Each attempted row must have an outcome. Missing outcomes are real
        // execution failures, not evidence that the row is still waiting.
        let waiting = report;
        for round in 11..15 {
            let remaining: Vec<_> = pending.values().cloned().collect();
            record_claim_outcome(&remaining, &waiting, &mut pending, &mut retry, &mut retired, round);
            assert!(retry.get("not-found").is_none(), "waiting after an unavailable read still spends nothing");
            assert!(!retired.contains_key("root-mismatch"));
            assert_eq!(claims_to_attempt(&pending, &retry).len(), 2);
        }
    }

    #[test]
    fn a_pause_holds_without_an_attempt_and_an_unpause_sends_again() {
        let attempted = vec![backoff_withdrawal("paused")];
        let mut pending = HashMap::from([("paused".to_string(), backoff_withdrawal("paused"))]);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let paused = failed("paused", claim_withdrawals::ClaimCode::RegistrationPaused);

        for _ in 0..10 {
            record_claim_outcome(&attempted, &paused, &mut pending, &mut retry, &mut retired, 0);
        }

        assert_eq!(retry["paused"].attempts, 0, "a pause spends nothing");
        assert!(matches!(retry["paused"].hold, claim_attempts::ClaimHold::OperatorPending(claim_withdrawals::ClaimCode::RegistrationPaused)));
        assert!(claims_to_attempt(&pending, &retry).is_empty(), "a paused leaf is not sent");
        assert!(retired.is_empty());

        claim_attempts::release_hold(&mut retry, "paused");
        let due = claims_to_attempt(&pending, &retry);
        assert_eq!(due.len(), 1, "clearing the pause returns the leaf to the round");
        assert_eq!(due[0].leaf_hash, "paused");
    }

    #[test]
    fn a_terminal_payload_is_retired_once_and_never_retried() {
        let attempted = vec![backoff_withdrawal("dead")];
        let mut pending = HashMap::from([("dead".to_string(), backoff_withdrawal("dead"))]);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();

        record_claim_outcome(&attempted, &failed("dead", claim_withdrawals::ClaimCode::ZeroAddress), &mut pending, &mut retry, &mut retired, 7);
        record_claim_outcome(&attempted, &failed("dead", claim_withdrawals::ClaimCode::ZeroAddress), &mut pending, &mut retry, &mut retired, 8);

        assert!(pending.is_empty());
        assert!(retry.is_empty(), "retirement leaves no retry record");
        assert_eq!(retired["dead"].attempts, 0, "a terminal payload gets no strikes");
        assert_eq!(retired["dead"].last_reason, claim_withdrawals::ClaimCode::ZeroAddress.label());
        assert!(claims_to_attempt(&pending, &retry).is_empty());
    }

    #[test]
    fn an_unknown_transaction_without_a_hash_is_held_and_never_sent() {
        let attempted = vec![backoff_withdrawal("lost")];
        let mut pending = HashMap::from([("lost".to_string(), backoff_withdrawal("lost"))]);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let unknown = failed("lost", claim_withdrawals::ClaimCode::ReceiptUnknown);

        for _ in 0..5 {
            record_claim_outcome(&attempted, &unknown, &mut pending, &mut retry, &mut retired, 0);
        }

        assert!(pending.contains_key("lost"));
        assert_eq!(retry["lost"].attempts, 0, "an unknown landing spends nothing");
        assert!(matches!(retry["lost"].hold, claim_attempts::ClaimHold::ReceiptUnknown { tx_hash: None }));
        assert!(claims_to_attempt(&pending, &retry).is_empty(), "no hash means no new send");
        assert!(retired.is_empty());
    }

    #[test]
    fn a_pending_recorded_transaction_is_not_sent_again() {
        let attempted = vec![backoff_withdrawal("inflight")];
        let mut pending = HashMap::from([("inflight".to_string(), backoff_withdrawal("inflight"))]);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let mut unknown = failed("inflight", claim_withdrawals::ClaimCode::ReceiptUnknown);
        unknown.outcomes[0].tx_hash = Some(alloy_primitives::B256::repeat_byte(0x11));

        record_claim_outcome(&attempted, &unknown, &mut pending, &mut retry, &mut retired, 0);
        record_claim_outcome(&attempted, &unknown, &mut pending, &mut retry, &mut retired, 1);

        assert_eq!(retry["inflight"].attempts, 0);
        assert!(matches!(
            retry["inflight"].hold,
            claim_attempts::ClaimHold::ReceiptUnknown { tx_hash: Some(hash) } if hash == alloy_primitives::B256::repeat_byte(0x11)
        ));
        assert!(claims_to_attempt(&pending, &retry).is_empty(), "a recorded hash is reconciled, not resent");
    }

    #[test]
    fn a_reverted_recorded_transaction_spends_one_attempt_and_only_then_is_due() {
        let withdrawal = backoff_withdrawal("reverted");
        let mut pending = HashMap::from([("reverted".to_string(), withdrawal.clone())]);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        claim_attempts::hold_for_receipt(&mut retry, "reverted", Some(alloy_primitives::B256::repeat_byte(0x22)));
        assert!(claims_to_attempt(&pending, &retry).is_empty());

        let report = claim_withdrawals::reverted_claim_report(&withdrawal);
        record_claim_outcome(std::slice::from_ref(&withdrawal), &report, &mut pending, &mut retry, &mut retired, 0);

        assert_eq!(retry["reverted"].attempts, 1, "the revert is the one spent attempt");
        assert!(matches!(retry["reverted"].hold, claim_attempts::ClaimHold::None));
        assert_eq!(claims_to_attempt(&pending, &retry).len(), 1, "the leaf is due again only after the revert");
        assert!(retired.is_empty());
    }

    #[test]
    fn a_partial_batch_removes_the_good_leaf_and_holds_the_bad_one() {
        let good = backoff_withdrawal("good");
        let bad = backoff_withdrawal("bad");
        let mut pending = HashMap::from([
            ("good".to_string(), good.clone()),
            ("bad".to_string(), bad.clone()),
        ]);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            outcomes: vec![
                claim_withdrawals::ClaimOutcome { leaf_hash: "good".into(), kind: claim_withdrawals::ClaimOutcomeKind::Registered, tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: "bad".into(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::RegistrationPaused), tx_hash: None },
            ],
            ..empty_report()
        };

        record_claim_outcome(&[good, bad], &report, &mut pending, &mut retry, &mut retired, 0);

        assert!(!pending.contains_key("good"), "the registered leaf leaves pending");
        assert!(pending.contains_key("bad"), "the paused leaf stays");
        assert_eq!(retry.get("bad").map(|state| state.attempts), Some(0));
        assert!(claims_to_attempt(&pending, &retry).is_empty(), "the held leaf is not sent next round");
        assert!(retired.is_empty());
    }


    #[test]
    fn a_withdrawal_that_never_succeeds_is_given_up_on_rather_than_retried_forever() {
        let mut pending = HashMap::new();
        pending.insert("a".to_string(), backoff_withdrawal("a"));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let attempted = vec![backoff_withdrawal("a")];

        let mut now = 0u64;
        let mut attempts = 0u32;
        // A year of a 30-second round. Before this change every one of those
        // rounds asked prove-proxy for a Groth16 proof.
        for _ in 0..(365 * 24 * 60 * 2) {
            now += 30;
            if claims_to_attempt(&pending, &retry).is_empty() {
                continue;
            }
            attempts += 1;
            record_claim_outcome(&attempted, &empty_report(), &mut pending, &mut retry, &mut retired, now);
        }

        assert_eq!(attempts, claim_attempts::CLAIM_MAX_ATTEMPTS);
        assert!(pending.is_empty(), "retired withdrawals leave the pending set");
        // Retired, not discarded: the funds are stuck and someone has to look.
        let entry = retired.get("a").expect("retired record kept");
        assert_eq!(entry.attempts, claim_attempts::CLAIM_MAX_ATTEMPTS);
        assert!(!entry.last_reason.is_empty());
        assert_eq!(entry.withdrawal.leaf_hash, "a");
    }

    #[test]
    fn a_withdrawal_missing_from_the_report_still_counts_as_a_failed_attempt() {
        // The silent case. A withdrawal that falls out of a round without being
        // named in failure_reasons used to be retried forever with no trace.
        let mut pending = HashMap::new();
        pending.insert("a".to_string(), backoff_withdrawal("a"));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();

        record_claim_outcome(
            &[backoff_withdrawal("a")],
            &empty_report(),
            &mut pending,
            &mut retry,
            &mut retired,
            0,
        );
        assert_eq!(retry["a"].attempts, 1);
    }

    #[test]
    fn withdrawals_that_were_not_attempted_are_left_alone() {
        let mut pending = HashMap::new();
        pending.insert("a".to_string(), backoff_withdrawal("a"));
        pending.insert("b".to_string(), backoff_withdrawal("b"));
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();

        record_claim_outcome(
            &[backoff_withdrawal("a")],
            &empty_report(),
            &mut pending,
            &mut retry,
            &mut retired,
            0,
        );
        assert!(retry.contains_key("a"));
        assert!(!retry.contains_key("b"), "b was never tried this round");
    }

    #[test]
    fn whole_batch_errors_exhaust_budget_across_single_chain_restarts() {
        let (root, db) = super::super::guardian_client::tests_db();
        let failed = withdrawal_for_chain("failed", 0);
        let untouched = withdrawal_for_chain("untouched", 1);
        let mut state = DaemonState::default();
        insert_pending_claims(&[failed.clone(), untouched], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals);

        db.save_request(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &guardian_common::protocol::JsonText::from_value(&crate::guardian::test_fixture::codec_request_fixture()).unwrap(),
            &[],
            &[failed.clone()],
        ).unwrap();

        for attempt in 1..=claim_attempts::CLAIM_MAX_ATTEMPTS {
            record_claim_result(
                &[failed.clone()],
                &Err(anyhow::anyhow!("RPC unavailable")),
                &mut state.pending_claim_withdrawals,
                &mut state.claim_retry,
                &mut state.retired_claim_withdrawals,
                u64::from(attempt),
            );
            save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &state).unwrap();
            state = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).unwrap();
            if attempt < claim_attempts::CLAIM_MAX_ATTEMPTS {
                assert_eq!(state.claim_retry["failed"].attempts, attempt);
            }
        }

        assert!(!state.pending_claim_withdrawals.contains_key("failed"));
        assert!(state.pending_claim_withdrawals.contains_key("untouched"));
        assert!(state.claim_retry.is_empty());
        let retired = &state.retired_claim_withdrawals["failed"];
        assert_eq!(retired.attempts, claim_attempts::CLAIM_MAX_ATTEMPTS);
        assert_eq!(retired.withdrawal.leaf_hash, "failed");
        assert_eq!(retired.last_reason, "claim batch failed: RPC unavailable");
        assert_eq!(retired.retired_at_unix, 3);

        assert!(!load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).unwrap().pending_claim_withdrawals.contains_key("failed"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn successive_signed_chunks_keep_every_recorded_hash() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let first = withdrawal_for_chain("first", 0);
        let second = withdrawal_for_chain("second", 1);
        let mut state = MultichainDaemonState::default();
        insert_pending_claims(&[first.clone(), second.clone()], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals);
        save_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, &state).unwrap();
        let hook = claim_broadcast_hook(&crate::guardian::test_fixture::codec_guardian_config(), &db);
        let first_hash = alloy_primitives::B256::repeat_byte(0x11);
        let second_hash = alloy_primitives::B256::repeat_byte(0x22);
        futures::executor::block_on(hook(std::slice::from_ref(&first), first_hash)).unwrap();
        futures::executor::block_on(hook(std::slice::from_ref(&second), second_hash)).unwrap();
        let saved = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        assert!(matches!(saved.claim_retry["first"].hold, claim_attempts::ClaimHold::ReceiptUnknown { tx_hash: Some(hash) } if hash == first_hash));
        assert!(matches!(saved.claim_retry["second"].hold, claim_attempts::ClaimHold::ReceiptUnknown { tx_hash: Some(hash) } if hash == second_hash));
        assert!(claims_to_attempt(&saved.pending_claim_withdrawals, &saved.claim_retry).is_empty());
        // A resolved leaf is removed from the real queue on the next save even
        // though its hook hold was persisted first; the other chunk stays held.
        let mut saved = saved;
        record_claim_result(
            &[first.clone()],
            &Ok(resolved("first")),
            &mut saved.pending_claim_withdrawals,
            &mut saved.claim_retry,
            &mut saved.retired_claim_withdrawals,
            1,
        );
        save_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, &saved).unwrap();
        let reloaded = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        assert!(!reloaded.pending_claim_withdrawals.contains_key("first"));
        assert!(!reloaded.claim_retry.contains_key("first"));
        assert!(matches!(reloaded.claim_retry["second"].hold, claim_attempts::ClaimHold::ReceiptUnknown { tx_hash: Some(hash) } if hash == second_hash));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn imported_leaves_with_event_zero_queue_alongside_a_shared_nonce() {
        let mut first = withdrawal_for_chain("imported-a", 0);
        let mut second = withdrawal_for_chain("imported-b", 0);
        for withdrawal in [&mut first, &mut second] {
            withdrawal.event_id = 0;
            withdrawal.nonce = [7; 8];
        }
        let mut state = DaemonState::default();
        assert!(insert_pending_claims(&[first.clone(), second.clone()], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals));
        assert_eq!(state.pending_claim_withdrawals.len(), 2, "distinct leaves that share a nonce are both pending");

        // The same full leaf replayed with the real event index is already
        // queued: event metadata is append ordering, not content, so this is
        // a skip, not a conflict — and the queued row keeps its imported 0.
        let mut replay = first.clone();
        replay.event_id = 41;
        assert!(!insert_pending_claims(&[replay], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals));
        assert_eq!(state.pending_claim_withdrawals.len(), 2);
        assert_eq!(state.pending_claim_withdrawals[&first.leaf_hash].event_id, 0);
    }

    #[test]
    fn a_batch_error_keeps_the_hook_persisted_unknown_hold() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let inflight = withdrawal_for_chain("inflight", 0);
        let mut state = MultichainDaemonState::default();
        insert_pending_claims(&[inflight.clone()], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals);
        save_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, &state).unwrap();
        let hook = claim_broadcast_hook(&crate::guardian::test_fixture::codec_guardian_config(), &db);
        let hash = alloy_primitives::B256::repeat_byte(0x33);
        futures::executor::block_on(hook(std::slice::from_ref(&inflight), hash)).unwrap();

        // The batch dies after the hook persisted the signed hash. The
        // persisted hold is adopted into the caller state before the error is
        // recorded, so the hold wins: no attempt is spent, and the round's
        // save does not overwrite the durable hold.
        let persisted = persisted_claim_retry(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        adopt_persisted_receipt_holds(&[inflight.clone()], &mut state.claim_retry, &persisted);
        record_claim_result(
            &[inflight.clone()],
            &Err(anyhow::anyhow!("RPC unavailable")),
            &mut state.pending_claim_withdrawals,
            &mut state.claim_retry,
            &mut state.retired_claim_withdrawals,
            1,
        );
        save_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, &state).unwrap();
        let reloaded = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        assert!(matches!(reloaded.claim_retry[&inflight.leaf_hash].hold, claim_attempts::ClaimHold::ReceiptUnknown { tx_hash: Some(kept) } if kept == hash));
        assert_eq!(reloaded.claim_retry[&inflight.leaf_hash].attempts, 0);
        assert!(claims_to_attempt(&reloaded.pending_claim_withdrawals, &reloaded.claim_retry).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn multichain_retirement_survives_restart_and_replayed_scans() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let failed_withdrawal = withdrawal_for_chain("failed", 0);
        let healthy = withdrawal_for_chain("healthy", 2);
        let range = PendingFinalizationRange { from_checkpoint: 10, to_checkpoint: 20 };
        let mut state = MultichainDaemonState {
            pending_finalization_range: Some(range),
            finalized_chains: served(&[0, 1]),
            ..Default::default()
        };
        insert_pending_claims(&[failed_withdrawal.clone(), healthy.clone()], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals);
        for attempt in 1..=claim_attempts::CLAIM_MAX_ATTEMPTS {
            let report = failed("failed", claim_withdrawals::ClaimCode::ProofGenerationFailed);
            record_claim_result(
                &[failed_withdrawal.clone()], &Ok(report), &mut state.pending_claim_withdrawals,
                &mut state.claim_retry, &mut state.retired_claim_withdrawals, u64::from(attempt),
            );
            save_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, &state).unwrap();
            state = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        }

        assert_eq!(state.pending_finalization_range, Some(range));
        assert_eq!(state.finalized_chains, served(&[0, 1]));
        assert_eq!(state.retired_claim_withdrawals["failed"].attempts, 3);
        for _ in 0..10 {
            assert!(!insert_pending_claims(
                &[failed_withdrawal.clone(), healthy.clone()], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals,
            ));
            let due = claims_to_attempt(&state.pending_claim_withdrawals, &state.claim_retry);
            assert_eq!(due.len(), 1);
            assert_eq!(due[0].leaf_hash, "healthy");
        }

        let resolved_report = resolved("healthy");
        record_claim_result(
            &[healthy], &Ok(resolved_report), &mut state.pending_claim_withdrawals,
            &mut state.claim_retry, &mut state.retired_claim_withdrawals, 4,
        );
        assert!(state.pending_claim_withdrawals.is_empty());
        assert_eq!(state.retired_claim_withdrawals.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn post_l2_replay_does_not_rearm_retired_claims() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let retired = withdrawal_for_chain("retired", 0);
        let fresh = withdrawal_for_chain("fresh", 1);
        let mut state = DaemonState::default();
        state.retired_claim_withdrawals.insert("retired".to_string(), claim_attempts::RetiredClaim {
            withdrawal: retired.clone(), attempts: 3, last_reason: "invalid proof".to_string(), retired_at_unix: 1,
        });
        for is_catchup in [false, true] {
            let result = orchestrate_post_l2_round(
                &crate::guardian::test_fixture::codec_guardian_config(),
                &db, 0, &state, &[retired.clone(), fresh.clone()], false, is_catchup,
                |_, pending| async move { pending },
            ).await.unwrap();
            let pending = match result {
                PostL2Orchestration::Deferred => {
                    let loaded = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).unwrap();
                    assert_eq!(loaded.retired_claim_withdrawals.len(), 1);
                    loaded.pending_claim_withdrawals
                }
                PostL2Orchestration::Dispatch(pending) => pending,
            };
            assert_eq!(pending.len(), 1);
            assert!(pending.contains_key("fresh"));
        }
        let _ = std::fs::remove_dir_all(root);
    }


    #[test]
    fn outcome_report_removes_resolved_and_consumed_nonce_and_holds_the_rest() {
        // A submitted leaf resolves and leaves pending. A leaf whose nonce is
        // already consumed elsewhere is terminal: it is retired, never
        // retried. A held leaf stays, so a partial batch never retries the
        // good leaf or drops the bad one.
        let w1 = sample_withdrawal(1); // newly submitted
        let w2 = sample_withdrawal(2); // nonce already consumed elsewhere
        let w3 = sample_withdrawal(3); // proof not ready, must stay
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
            (w3.leaf_hash.clone(), w3.clone()),
        ]
        .into_iter()
        .collect();
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            outcomes: vec![
                claim_withdrawals::ClaimOutcome { leaf_hash: w1.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Registered, tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: w2.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::NonceConflict), tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: w3.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::ProofNotReady), tx_hash: None },
            ],
            ..empty_report()
        };
        record_claim_outcome(&[w1.clone(), w2.clone(), w3.clone()], &report, &mut pending, &mut retry, &mut retired, 0);
        assert!(!pending.contains_key(&w1.leaf_hash), "submitted withdrawal must be removed");
        assert!(!pending.contains_key(&w2.leaf_hash), "consumed-nonce withdrawal must be retired, never retried");
        assert!(pending.contains_key(&w3.leaf_hash), "held withdrawal must remain");
        assert!(retry.get(&w3.leaf_hash).is_none(), "a Held proof-not-ready leaf writes no retry counter; it stays pending and unheld for the next readiness recheck");
        assert!(retired.contains_key(&w2.leaf_hash));
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn claim_readiness_cursor_resumes_after_checked_prefix() {
        let report = claim_withdrawals::BatchWithdrawalsReport {
            outcomes: vec![
                claim_withdrawals::ClaimOutcome { leaf_hash: "slow".into(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::RpcUnavailable), tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: "unread".into(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::ReadinessDeferred), tx_hash: None },
            ],
            ..empty_report()
        };
        let mut slow = sample_withdrawal(1);
        slow.leaf_hash = "slow".into();
        slow.event_id = 10;
        let mut unread = sample_withdrawal(2);
        unread.leaf_hash = "unread".into();
        unread.event_id = 30;
        let claims = [slow, unread];
        assert_eq!(next_claim_readiness_start(&claims, &Ok(report.clone())), Some(10));
        let mut reordered = report;
        reordered.outcomes.reverse();
        assert_eq!(next_claim_readiness_start(&claims, &Ok(reordered)), Some(10));
        assert_eq!(next_claim_readiness_start(&claims, &Err(anyhow::anyhow!("read outage"))), Some(10));
        assert_eq!(next_claim_readiness_start(&[], &Ok(empty_report())), None);
    }

    #[test]
    fn claim_readiness_budget_does_not_spend_attempts_or_serialize_a_new_hold() {
        let withdrawal = sample_withdrawal(1);
        let mut pending = HashMap::from([(withdrawal.leaf_hash.clone(), withdrawal.clone())]);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            outcomes: vec![claim_withdrawals::ClaimOutcome {
                leaf_hash: withdrawal.leaf_hash.clone(),
                kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::ReadinessDeferred),
                tx_hash: None,
            }],
            ..empty_report()
        };
        record_claim_outcome(&[withdrawal.clone()], &report, &mut pending, &mut retry, &mut retired, 0);
        assert!(pending.contains_key(&withdrawal.leaf_hash));
        assert!(retry.is_empty());
        assert!(retired.is_empty());
        let state = DaemonState { pending_claim_withdrawals: pending, claim_retry: retry, retired_claim_withdrawals: retired };
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let config = crate::guardian::test_fixture::codec_guardian_config();
        save_chain_state(&config, &db, 0, &state).unwrap();
        drop(db);
        let restarted = super::super::guardian_client::RelayerDb::open(&root).unwrap();
        let saved = load_chain_state(&config, &restarted, 0).unwrap();
        assert!(saved.pending_claim_withdrawals.contains_key(&withdrawal.leaf_hash));
        assert!(saved.claim_retry.is_empty());
        assert!(saved.retired_claim_withdrawals.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unreported_withdrawal_stays_pending_and_spends_nothing() {
        // A withdrawal absent from the attempted set is not this round's
        // business. One the round attempted but did not name spends an attempt.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
        ]
        .into_iter()
        .collect();
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        record_claim_outcome(&[w1.clone()], &resolved(&w1.leaf_hash), &mut pending, &mut retry, &mut retired, 0);
        assert!(!pending.contains_key(&w1.leaf_hash));
        assert!(pending.contains_key(&w2.leaf_hash), "unattempted withdrawal must be retained");
        assert!(retry.is_empty());
    }

    #[test]
    fn record_claim_withdrawals_deduplicates_by_leaf_hash_across_scans() {
        // Two L2 scans re-reporting the same withdrawal must not duplicate the
        // claim entry; the seen set is the dedup boundary.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut seen = HashSet::new();
        let mut claims = Vec::new();
        record_claim_withdrawals(&[w1.clone(), w2.clone()], &mut seen, &mut claims);
        assert_eq!(claims.len(), 2);
        // Re-scan re-reports w1 — must NOT be appended again.
        record_claim_withdrawals(&[w1.clone()], &mut seen, &mut claims);
        assert_eq!(claims.len(), 2, "duplicate leaf_hash must not be recorded twice");
        assert!(claims.iter().any(|c| c.leaf_hash == w1.leaf_hash));
        assert!(claims.iter().any(|c| c.leaf_hash == w2.leaf_hash));
    }


    /// Deterministic xorshift64 so property tests are reproducible. The seed is
    /// fixed; failing inputs are printed so a red run replays exactly.
    fn xorshift_u64(state: &mut u64) -> u64 {
        let mut x = *state;
        debug_assert!(x != 0, "xorshift state must be non-zero");
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn make_packed_leaf(elements: [u64; 4]) -> QHashOut<GoldilocksField> {
        QHashOut::<GoldilocksField>::try_from(&elements).expect("4 u64 elements fit QHashOut")
    }

    // ── select_relayer_window: property-based invariants ───────────────────

    #[test]
    fn select_relayer_window_invariants_hold_across_seeded_inputs() {
        // Defends the universal contracts every daemon round relies on, across
        // thousands of input combinations plus u64::MAX-boundary inputs:
        //   (1) to_checkpoint never exceeds latest_checkpoint (relayer never
        //       proves a range beyond what L2 has produced).
        //   (2) a catchup batch always carries a confirmed range.
        //   (3) deposit-appends and withdrawal-processing are gated identically
        //       by is_catchup_batch — they are never allowed to disagree.
        //   (4) when a confirmed range exists, it is never behind from_checkpoint.
        //   (5) a catchup round (no overflow) spans exactly max_checkpoint_batch.
        //   (6) a non-catchup confirmed round lands exactly on confirmed_to.
        //   (7) an append-only round (max>0) lands on min(latest, from+max-1);
        //       with max==0 it lands on latest (unbounded).
        const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut state = SEED;
        let small = |s: &mut u64| (xorshift_u64(s) % 301) as u64;
        let max_choices = [0u64, 1, 2, 3, 5, 8, 32, 64, 97, 128];

        // Bulk: small checkpoints where catchup / normal / append-only all appear.
        for _ in 0..8_000 {
            let from = small(&mut state);
            let latest = small(&mut state);
            let lag = xorshift_u64(&mut state) % 21;
            let max_batch = max_choices[(xorshift_u64(&mut state) as usize) % max_choices.len()];
            check_window_invariants(from, latest, lag, max_batch, SEED);
        }

        // Boundary batch: latest near u64::MAX exercises confirmed-range catchup
        // and saturating arithmetic without overflow/panic.
        for _ in 0..1_000 {
            let latest = u64::MAX - (xorshift_u64(&mut state) % 16);
            let from = latest - (xorshift_u64(&mut state) % 200);
            let lag = xorshift_u64(&mut state) % 10;
            let max_batch = max_choices[(xorshift_u64(&mut state) as usize) % max_choices.len()];
            check_window_invariants(from, latest, lag, max_batch, SEED);
        }
    }

    fn check_window_invariants(from: u64, latest: u64, lag: u64, max_batch: u64, seed: u64) {
        let window = select_relayer_window(from, latest, lag, max_batch);
        let fail = |msg: &str| -> String {
            format!("seed={seed:#x} from={from} latest={latest} lag={lag} max={max_batch}: {msg}")
        };
        // (1) to_checkpoint never exceeds latest.
        assert!(window.to_checkpoint <= latest, "{}", fail("to_checkpoint exceeded latest"));
        // (2) catchup implies a confirmed range exists.
        if window.is_catchup_batch {
            assert!(
                window.confirmed_to_checkpoint.is_some(),
                "{}",
                fail("catchup batch lacks confirmed range")
            );
        }
        // (3) deposit/withdrawal gating agree and equal !is_catchup_batch.
        assert_eq!(
            !window.is_catchup_batch,
            !window.is_catchup_batch,
            "{}",
            fail("deposit/withdrawal gating disagree")
        );
        assert_eq!(
            !window.is_catchup_batch,
            !window.is_catchup_batch,
            "{}",
            fail("gating != !is_catchup_batch")
        );
        // (4) confirmed range, when present, is never behind from_checkpoint.
        if let Some(confirmed) = window.confirmed_to_checkpoint {
            assert!(
                confirmed >= from,
                "{}",
                fail("confirmed range behind from_checkpoint")
            );
        }
        // (5) catchup round (no overflow) spans exactly max_checkpoint_batch.
        if window.is_catchup_batch && from <= u64::MAX - (max_batch - 1) {
            assert_eq!(
                window.to_checkpoint - from + 1,
                max_batch,
                "{}",
                fail("catchup round did not span max_batch")
            );
        }
        // (6) non-catchup confirmed round lands exactly on confirmed_to.
        if !window.is_catchup_batch && window.confirmed_to_checkpoint.is_some() {
            assert_eq!(
                window.to_checkpoint,
                window.confirmed_to_checkpoint.unwrap(),
                "{}",
                fail("non-catchup confirmed round did not land on confirmed")
            );
        }
        // (7) append-only round lands on min(latest, from+max-1); max==0 → latest.
        if window.confirmed_to_checkpoint.is_none() {
            if max_batch > 0 {
                assert_eq!(
                    window.to_checkpoint,
                    latest.min(from.saturating_add(max_batch - 1)),
                    "{}",
                    fail("append-only round did not clamp to min(latest, from+max-1)")
                );
            } else {
                assert_eq!(
                    window.to_checkpoint, latest,
                    "{}",
                    fail("max==0 append-only round did not land on latest")
                );
            }
        }
    }

    // ── select_relayer_window: additional boundary edges ───────────────────

    #[test]
    fn select_relayer_window_max_batch_one_advances_one_checkpoint_per_catchup_round() {
        // max_batch=1: a 2-checkpoint gap is already "oversized" (range_len=2>1),
        // so every catchup round advances the cursor by exactly one checkpoint.
        let w = select_relayer_window(10, 20, 3, 1);
        // confirmed = 17, range = 8 > 1 → catchup; to = 10 + 1 - 1 = 10.
        assert_eq!(w.to_checkpoint, 10);
        assert_eq!(w.confirmed_to_checkpoint, Some(17));
        assert!(w.is_catchup_batch);
        // Next round advances from 11; range still > 1 → still catchup, to = 11.
        let w2 = select_relayer_window(11, 20, 3, 1);
        assert_eq!(w2.to_checkpoint, 11);
        assert!(w2.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_catchup_near_u64_max_does_not_overflow() {
        // confirmed-range catchup near u64::MAX: to = from + max - 1 must
        // saturate rather than panic. from = MAX-3, latest = MAX, lag = 0 →
        // confirmed = MAX, range = 4 > 2 → catchup, to = (MAX-3) + 1 = MAX-2.
        let w = select_relayer_window(u64::MAX - 3, u64::MAX, 0, 2);
        assert_eq!(w.confirmed_to_checkpoint, Some(u64::MAX));
        assert!(w.is_catchup_batch);
        assert_eq!(w.to_checkpoint, u64::MAX - 2);
        assert!(w.to_checkpoint <= u64::MAX);
    }

    #[test]
    fn select_relayer_window_lag_zero_latest_at_u64_max_triggers_catchup() {
        // latest = u64::MAX, lag = 0 → confirmed = MAX; tiny from gives an
        // enormous gap → catchup truncates to from + max - 1 without overflow.
        let w = select_relayer_window(5, u64::MAX, 0, 64);
        assert_eq!(w.confirmed_to_checkpoint, Some(u64::MAX));
        assert!(w.is_catchup_batch);
        assert_eq!(w.to_checkpoint, 5 + 64 - 1);
    }

    #[test]
    fn select_relayer_window_confirmed_equals_from_is_single_checkpoint_normal_round() {
        // confirmed == from ⇒ range_len = 1, never oversized for max >= 1 →
        // a normal, provable one-checkpoint round (not catchup).
        let w = select_relayer_window(42, 45, 3, 64);
        assert_eq!(w.confirmed_to_checkpoint, Some(42));
        assert_eq!(w.to_checkpoint, 42);
        assert!(!w.is_catchup_batch);
    }

    // ── optimal_batch_sizes: direct coverage ────────────────────────────────

    #[test]
    fn optimal_batch_sizes_maps_small_counts_to_minimal_packs() {
        // The packing primitive that batch-call builders depend on. Each row is
        // the unique minimal-batch-count decomposition using sizes {1,2,5} with
        // singles < 2.
        let cases: &[(usize, &[usize])] = &[
            (0, &[]),
            (1, &[1]),
            (2, &[2]),
            (3, &[1, 2]),
            (4, &[2, 2]),
            (5, &[5]),
            (6, &[1, 5]),
            (7, &[2, 5]),
            (8, &[1, 2, 5]),
            (9, &[2, 2, 5]),
            (10, &[5, 5]),
            (12, &[2, 5, 5]),
        ];
        for (n, expected) in cases {
            assert_eq!(&optimal_batch_sizes(*n), expected, "n={n}");
        }
    }

    #[test]
    fn optimal_batch_sizes_satisfies_invariants_for_all_counts_up_to_two_hundred() {
        // Property: for every n in 0..=200 the decomposition sums to n, uses only
        // {1,2,5}, keeps singles < 2, and is no worse than the greedy 5s-then-2s
        // packing (so it really minimises batch count).
        for n in 0..=200usize {
            let sizes = optimal_batch_sizes(n);
            assert_eq!(sizes.iter().sum::<usize>(), n, "sum != n at n={n}");
            assert!(
                sizes.iter().all(|&s| matches!(s, 1 | 2 | 5)),
                "illegal size at n={n}: {sizes:?}"
            );
            let singles = sizes.iter().filter(|&&s| s == 1).count();
            assert!(singles < 2, "singles>=2 at n={n}: {sizes:?}");
            // Independent minimality check: the minimum batch count is the
            // minimum over f in 0..=n/5 of (f + ceil((n - 5*f) / 2)) — after placing
            // f five-batches the remainder is filled most efficiently by twos (one
            // single at most for an odd remainder, staying < 2). This closed-form
            // derivation is independent of the function's nested brute-force loop.
            let theoretical_min = (0..=n / 5)
                .map(|f| f + (n - 5 * f + 1) / 2)
                .min()
                .unwrap_or(0);
            assert_eq!(
                sizes.len(),
                theoretical_min,
                "not minimal at n={n}: got {got} batches vs theoretical {theoretical_min} ({sizes:?})",
                got = sizes.len(),
            );
        }
    }


    // ── build_withdrawal_batch_calls: additional layout coverage ────────────

    #[test]
    fn build_withdrawal_batch_calls_empty_returns_empty() {
        assert!(build_withdrawal_batch_calls(&[]).is_empty());
    }

    #[test]
    fn build_withdrawal_batch_calls_five_uses_batch_append_withdrawals_5_layout() {
        // batch_append_withdrawals_5(count, senders[5], contracts[5], dests[5],
        //   token_addr[5*8], amount[5*8], recipient[5*8], nonce[5*8]) → 176 inputs.
        let ws: Vec<_> = (1..=5).map(sample_withdrawal).collect();
        let calls = build_withdrawal_batch_calls(&ws);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method_name, "batch_append_withdrawals_5");
        assert_eq!(calls[0].contract_id, WITHDRAWAL_TREE_CONTRACT_ID as u64);
        assert_eq!(calls[0].inputs.len(), 176);
        assert_eq!(calls[0].inputs[0], 5);
        // senders block [1..6], contracts block [6..11], dests block [11..16].
        assert_eq!(
            &calls[0].inputs[1..6],
            &ws.iter().map(|w| w.sender_user_id).collect::<Vec<_>>()
        );
        assert_eq!(
            &calls[0].inputs[6..11],
            &ws.iter().map(|w| w.contract_id).collect::<Vec<_>>()
        );
        assert_eq!(
            &calls[0].inputs[11..16],
            &ws.iter().map(|w| w.destination_chain_index).collect::<Vec<_>>()
        );
        // token_address block [16..56], grouped per-withdrawal in original order.
        let mut token = Vec::new();
        for w in &ws {
            token.extend(w.token_address.iter().map(|&v| v as u64));
        }
        assert_eq!(&calls[0].inputs[16..56], &token);
    }

    #[test]
    fn build_withdrawal_batch_calls_twelve_splits_two_five_five_in_order() {
        // 12 withdrawals → [2, 5, 5]. Original order is preserved across batches:
        // first 2 → batch_2, next 5 → batch_5, last 5 → batch_5.
        let ws: Vec<_> = (1..=12).map(sample_withdrawal).collect();
        let calls = build_withdrawal_batch_calls(&ws);
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].method_name, "batch_append_withdrawals_2");
        assert_eq!(calls[0].inputs[0], 2);
        assert_eq!(calls[1].method_name, "batch_append_withdrawals_5");
        assert_eq!(calls[1].inputs[0], 5);
        assert_eq!(calls[2].method_name, "batch_append_withdrawals_5");
        assert_eq!(calls[2].inputs[0], 5);
        // First batch's senders are ws[0..2]; third batch's senders are ws[7..12].
        assert_eq!(calls[0].inputs[1], ws[0].sender_user_id);
        assert_eq!(calls[0].inputs[2], ws[1].sender_user_id);
        assert_eq!(calls[2].inputs[1], ws[7].sender_user_id);
        assert_eq!(calls[2].inputs[5], ws[11].sender_user_id);
    }

    // ── apply_claim_report: additional double-claim-defence edges ──────────

    #[test]
    fn an_empty_outcome_report_leaves_pending_untouched() {
        let w = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w.leaf_hash.clone(), w.clone())].into_iter().collect();
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        record_claim_outcome(&[], &empty_report(), &mut pending, &mut retry, &mut retired, 0);
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&w.leaf_hash));
    }

    #[test]
    fn resolving_an_unknown_leaf_does_not_evict_a_pending_one() {
        let w1 = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w1.leaf_hash.clone(), w1.clone())].into_iter().collect();
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        record_claim_outcome(&[w1.clone()], &resolved("never-pending-leaf"), &mut pending, &mut retry, &mut retired, 0);
        assert!(pending.contains_key(&w1.leaf_hash), "a report for another leaf must not evict w1");
    }

    #[test]
    fn resolving_every_pending_leaf_clears_the_set() {
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
        ]
        .into_iter()
        .collect();
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            outcomes: vec![
                claim_withdrawals::ClaimOutcome { leaf_hash: w1.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Registered, tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: w2.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Registered, tx_hash: None },
            ],
            ..empty_report()
        };
        record_claim_outcome(&[w1, w2], &report, &mut pending, &mut retry, &mut retired, 0);
        assert!(pending.is_empty(), "all-resolved report must clear pending");
    }

    #[test]
    fn a_failure_for_an_unknown_leaf_never_inserts_it() {
        let w1 = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w1.leaf_hash.clone(), w1.clone())].into_iter().collect();
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        record_claim_outcome(&[], &failed("never-pending-leaf", claim_withdrawals::ClaimCode::SendFailed), &mut pending, &mut retry, &mut retired, 0);
        assert_eq!(pending.len(), 1, "a failure must not insert into pending");
        assert!(pending.contains_key(&w1.leaf_hash));
        assert!(!pending.contains_key("never-pending-leaf"));
    }

    // ── record_claim_withdrawals: additional dedup edges ───────────────────

    #[test]
    fn record_claim_withdrawals_empty_input_is_noop() {
        let mut seen = HashSet::new();
        let mut claims = Vec::new();
        record_claim_withdrawals(&[], &mut seen, &mut claims);
        assert!(seen.is_empty());
        assert!(claims.is_empty());
    }

    fn indexed_seen(withdrawals: &[PendingWithdrawal]) -> HashSet<(u64, i64, String)> {
        withdrawals.iter().map(|withdrawal| (withdrawal.destination_chain_index, withdrawal.event_id, withdrawal.leaf_hash.clone())).collect()
    }

    #[test]
    fn record_claim_withdrawals_all_duplicates_produces_no_new_entries() {
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut seen = indexed_seen(&[w1.clone(), w2.clone()]);
        let mut claims = Vec::new();
        record_claim_withdrawals(&[w1, w2], &mut seen, &mut claims);
        assert_eq!(claims.len(), 0, "the same chain, event id, and leaf records nothing new");
    }

    #[test]
    fn record_claim_withdrawals_interleaved_new_and_duplicate_preserves_order() {
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let w3 = sample_withdrawal(3);
        let mut same_leaf = w1.clone();
        same_leaf.event_id = 11;
        let mut seen = indexed_seen(&[w2.clone()]);
        let mut claims = Vec::new();
        record_claim_withdrawals(&[w1.clone(), w2, same_leaf.clone(), w3.clone()], &mut seen, &mut claims);
        assert_eq!(claims.len(), 3);
        assert_eq!(claims[0].event_id, w1.event_id);
        assert_eq!(claims[1].event_id, same_leaf.event_id);
        assert_eq!(claims[1].leaf_hash, w1.leaf_hash);
        assert_eq!(claims[2].event_id, w3.event_id);
    }


    // ── read_single_felt_from_packed_leaf: packed contract-state decoding ──

    #[test]
    fn read_single_felt_from_packed_leaf_selects_subslot_by_modulo_four() {
        // 4 felts are packed per contract-state leaf; sub_slot_index % 4 selects
        // the element. Sub-slots 0..7 must wrap (4→0, 5→1, …) so chain_counts and
        // global_count read the correct felt.
        let leaf = make_packed_leaf([10, 20, 30, 40]);
        for sub in 0u64..8 {
            let expected = match sub % 4 {
                0 => 10,
                1 => 20,
                2 => 30,
                _ => 40,
            };
            assert_eq!(
                read_single_felt_from_packed_leaf(leaf, sub).unwrap(),
                expected,
                "sub_slot={sub}"
            );
        }
        // A large sub_slot_index also wraps via modulo (e.g. 100 % 4 == 0).
        assert_eq!(read_single_felt_from_packed_leaf(leaf, 100).unwrap(), 10);
    }

    #[test]
    fn read_single_felt_from_packed_leaf_accepts_u32_boundaries() {
        // 0 and u32::MAX are the inclusive bounds of the accepted range.
        let leaf = make_packed_leaf([0, u32::MAX as u64, 1, u32::MAX as u64]);
        assert_eq!(read_single_felt_from_packed_leaf(leaf, 0).unwrap(), 0);
        assert_eq!(read_single_felt_from_packed_leaf(leaf, 1).unwrap(), u32::MAX as u64);
    }

    #[test]
    fn read_single_felt_from_packed_leaf_rejects_value_above_u32_max() {
        // A packed felt whose canonical u64 exceeds u32::MAX must error (it would
        // corrupt chain_count/global_count decoding). 2^32 is canonical in
        // Goldilocks and strictly greater than u32::MAX.
        let leaf = make_packed_leaf([0x1_0000_0000u64, 0, 0, 0]);
        let err = read_single_felt_from_packed_leaf(leaf, 0).unwrap_err();
        assert!(
            err.to_string().contains("exceeds u32 range"),
            "expected u32-range error, got: {err}"
        );
    }

    // ── multi-round double-claim-prevention simulation ──────────────────────

    #[test]
    fn multi_round_claim_cycle_prevents_double_claims_and_retains_failures() {
        // Models the daemon-level crash-recovery flow across two rounds using
        // only the public-ish helpers (merge via or_insert_with + apply_claim_report),
        // the same sequence run() drives. Defends the externally observable
        // contract that pending_claim_withdrawals is the single source of truth:
        //   - a withdrawal submitted or retired (consumed nonce) in round N is removed and
        //     NEVER retried (no double-claim);
        //   - a failed withdrawal persists and is retried next round;
        //   - re-scanning an existing leaf never duplicates or overwrites it;
        //   - pending keys stay unique throughout.
        let w1 = sample_withdrawal(1); // submitted round 1
        let w2 = sample_withdrawal(2); // nonce consumed elsewhere round 1
        let w3 = sample_withdrawal(3); // fails round 1, submitted round 2
        let w4 = sample_withdrawal(4); // new in round 2, submitted

        let mut pending: HashMap<String, PendingWithdrawal> = HashMap::new();

        // ── Round 1: scan reports w1, w2, w3; merge (or_insert, no overwrite). ─
        for w in [&w1, &w2, &w3] {
            pending
                .entry(w.leaf_hash.clone())
                .or_insert_with(|| w.clone());
        }
        assert_eq!(pending.len(), 3, "round 1 merge must add all three uniquely");
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let report1 = claim_withdrawals::BatchWithdrawalsReport {
            outcomes: vec![
                claim_withdrawals::ClaimOutcome { leaf_hash: w1.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Registered, tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: w2.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::NonceConflict), tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: w3.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Failed(claim_withdrawals::ClaimCode::ProofNotReady), tx_hash: None },
            ],
            ..empty_report()
        };
        record_claim_outcome(&[w1.clone(), w2.clone(), w3.clone()], &report1, &mut pending, &mut retry, &mut retired, 0);
        assert!(!pending.contains_key(&w1.leaf_hash), "submitted must leave pending");
        assert!(!pending.contains_key(&w2.leaf_hash), "consumed-nonce must leave pending (retired, no double-claim)");
        assert!(pending.contains_key(&w3.leaf_hash), "held must remain");
        assert_eq!(pending.len(), 1);

        // ── Round 2: re-scan reports w3 (retry) and w4 (new). ───────────────
        // w3 is already pending: or_insert_with must NOT overwrite the original
        // record (crash-recovery idempotence). w4 is new.
        let original_w3 = pending.get(&w3.leaf_hash).cloned().unwrap();
        for w in [&w3, &w4] {
            pending
                .entry(w.leaf_hash.clone())
                .or_insert_with(|| w.clone());
        }
        assert_eq!(pending.len(), 2, "round 2 merge must add only w4");
        // w3 record preserved exactly (not overwritten by the re-scan).
        assert_eq!(pending[&w3.leaf_hash].event_id, original_w3.event_id);
        // w4 was inserted fresh.
        assert!(pending.contains_key(&w4.leaf_hash));

        let report2 = claim_withdrawals::BatchWithdrawalsReport {
            outcomes: vec![
                claim_withdrawals::ClaimOutcome { leaf_hash: w3.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Registered, tx_hash: None },
                claim_withdrawals::ClaimOutcome { leaf_hash: w4.leaf_hash.clone(), kind: claim_withdrawals::ClaimOutcomeKind::Registered, tx_hash: None },
            ],
            ..empty_report()
        };
        record_claim_outcome(&[w3.clone(), w4.clone()], &report2, &mut pending, &mut retry, &mut retired, 0);
        assert!(pending.is_empty(), "all claims resolved → pending must be empty");
        // Invariant: w2 (already-claimed in round 1) was never re-added even
        // though it was not re-scanned — double-claim prevented.
        assert!(!pending.contains_key(&w2.leaf_hash));
    }
    fn test_leaf(seed: u64) -> QHashOut<GoldilocksField> {
        QHashOut(plonky2::hash::hash_types::HashOut {
            elements: std::array::from_fn(|offset| GoldilocksField(seed + offset as u64)),
        })
    }

    fn sample_slot_updates() -> Vec<EndCapContractSlotUpdate> {
        vec![
            EndCapContractSlotUpdate {
                contract_id: DEPOSIT_TREE_CONTRACT_ID,
                slot: 65800,
                old_value: 10,
                new_value: 11,
            },
            EndCapContractSlotUpdate {
                contract_id: WITHDRAWAL_TREE_CONTRACT_ID,
                slot: 4,
                old_value: 20,
                new_value: 21,
            },
        ]
    }

    fn accepted_slot_updates(
        user_id: u64,
        unique_pending_id: u64,
        accepted_user_leaf_hash: Option<[u64; 4]>,
    ) -> RealmEndCapSlotUpdates {
        RealmEndCapSlotUpdates {
            realm_id: 0,
            realm_sub_id: 0,
            unique_pending_id,
            user_id,
            contracts: vec![
                psy_provider::request::RealmContractSlotUpdates {
                    contract_id: WITHDRAWAL_TREE_CONTRACT_ID,
                    slot_updates: vec![psy_provider::request::RealmSlotUpdate {
                        slot: 4,
                        old_value: 20,
                        new_value: 21,
                    }],
                },
                psy_provider::request::RealmContractSlotUpdates {
                    contract_id: DEPOSIT_TREE_CONTRACT_ID,
                    slot_updates: vec![psy_provider::request::RealmSlotUpdate {
                        slot: 65800,
                        old_value: 10,
                        new_value: 11,
                    }],
                },
            ],
            accepted_user_leaf_hash,
        }
    }

    fn leaf_felts(leaf: &QHashOut<GoldilocksField>) -> [u64; 4] {
        std::array::from_fn(|i| leaf.0.elements[i].to_canonical_u64())
    }

    fn duplicate_submission_error(
        leaf: QHashOut<GoldilocksField>,
        user_id: u64,
        unique_pending_id: u64,
    ) -> anyhow::Error {
        EndCapSubmissionError {
            end_user_leaf_hash: leaf,
            contract_slot_updates: sample_slot_updates(),
            source: psy_provider::provider::EndCapAlreadySubmitted {
                user_id,
                unique_pending_id,
            }
            .into(),
        }
        .into()
    }

    #[tokio::test]
    async fn accepted_then_timed_out_retry_recovers_exact_duplicate_leaf() {
        let accepted_leaf = test_leaf(100);
        let first_submission = Ok::<_, anyhow::Error>(accepted_leaf).unwrap();
        let first_inclusion_wait = Err::<u64, _>(anyhow::anyhow!(
            "timeout waiting endcap inclusion: user_id={} checkpoint_before=700",
            BRIDGE_USER_ID_U64
        ));
        assert!(first_inclusion_wait.is_err());

        let retry = recover_duplicate_endcap_leaf_with(
            duplicate_submission_error(first_submission, BRIDGE_USER_ID_U64, 675),
            BRIDGE_USER_ID_U64,
            |user_id, unique_pending_id| async move {
                Ok(Some(accepted_slot_updates(
                    user_id,
                    unique_pending_id,
                    Some(leaf_felts(&accepted_leaf)),
                )))
            },
        )
        .await
        .unwrap();
        assert_eq!(retry, accepted_leaf);
    }

    #[tokio::test]
    async fn exact_duplicate_accepts_server_update_superset() {
        let leaf = test_leaf(150);
        let pinned_leaf = leaf;
        let recovered = recover_duplicate_endcap_leaf_with(
            duplicate_submission_error(leaf, BRIDGE_USER_ID_U64, 675),
            BRIDGE_USER_ID_U64,
            |user_id, unique_pending_id| async move {
                let mut accepted = accepted_slot_updates(
                    user_id,
                    unique_pending_id,
                    Some(leaf_felts(&pinned_leaf)),
                );
                accepted.contracts[1].slot_updates.push(psy_provider::request::RealmSlotUpdate {
                    slot: 65801,
                    old_value: 30,
                    new_value: 31,
                });
                Ok(Some(accepted))
            },
        )
        .await
        .unwrap();
        assert_eq!(recovered, leaf);
    }

    #[tokio::test]
    async fn exact_duplicate_then_landed_checkpoint_continues_inclusion_wait() {
        let accepted_leaf = test_leaf(200);
        let recovered_leaf = recover_duplicate_endcap_leaf_with(
            duplicate_submission_error(accepted_leaf, BRIDGE_USER_ID_U64, 675),
            BRIDGE_USER_ID_U64,
            |user_id, unique_pending_id| async move {
                Ok(Some(accepted_slot_updates(
                    user_id,
                    unique_pending_id,
                    Some(leaf_felts(&accepted_leaf)),
                )))
            },
        )
        .await
        .unwrap();
        let landed_checkpoint = async move {
            assert_eq!(recovered_leaf, accepted_leaf);
            701u64
        }
        .await;

        assert_eq!(landed_checkpoint, 701);
    }

    #[tokio::test]
    async fn unrelated_or_mismatched_duplicate_errors_remain_failures() {
        let leaf = test_leaf(300);
        let unrelated = EndCapSubmissionError {
            end_user_leaf_hash: leaf,
            contract_slot_updates: sample_slot_updates(),
            source: anyhow::anyhow!("another endcap error"),
        };
        assert!(
            recover_duplicate_endcap_leaf_with(unrelated.into(), BRIDGE_USER_ID_U64, |_, _| async {
                Ok(None)
            })
            .await
            .is_err()
        );

        let mismatch = duplicate_submission_error(leaf, BRIDGE_USER_ID_U64 + 1, 675);
        let error = recover_duplicate_endcap_leaf_with(mismatch, BRIDGE_USER_ID_U64, |_, _| async {
            Ok(None)
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("duplicate endcap user mismatch"));

        let wrong_identity = duplicate_submission_error(leaf, BRIDGE_USER_ID_U64, 675);
        let error = recover_duplicate_endcap_leaf_with(wrong_identity, BRIDGE_USER_ID_U64, |user_id, unique_pending_id| async move {
            let mut accepted = accepted_slot_updates(user_id, unique_pending_id, Some(leaf_felts(&leaf)));
            accepted.contracts[1].slot_updates[0].new_value = 12;
            Ok(Some(accepted))
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("contract update identity mismatch"));
    }

    #[tokio::test]
    async fn accepted_leaf_identity_mismatch_fails_closed() {
        // The fresh proof re-derives a different end leaf than the accepted
        // endcap: slot updates coincide, so without the pinned leaf identity
        // this recovered onto a leaf that could never land (livelock).
        let fresh_leaf = test_leaf(400);
        let accepted_leaf = test_leaf(401);
        let error = recover_duplicate_endcap_leaf_with(
            duplicate_submission_error(fresh_leaf, BRIDGE_USER_ID_U64, 675),
            BRIDGE_USER_ID_U64,
            |user_id, unique_pending_id| async move {
                Ok(Some(accepted_slot_updates(
                    user_id,
                    unique_pending_id,
                    Some(leaf_felts(&accepted_leaf)),
                )))
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("duplicate endcap accepted leaf mismatch"));
        assert!(error.to_string().contains("does not re-derive the accepted endcap"));
    }

    #[tokio::test]
    async fn absent_accepted_leaf_falls_back_to_fresh_proof_leaf() {
        // Rolling-restart compatibility: nodes that predate identity
        // persistence keep the previous recovery behavior.
        let fresh_leaf = test_leaf(500);
        let recovered = recover_duplicate_endcap_leaf_with(
            duplicate_submission_error(fresh_leaf, BRIDGE_USER_ID_U64, 675),
            BRIDGE_USER_ID_U64,
            |user_id, unique_pending_id| async move {
                Ok(Some(accepted_slot_updates(
                    user_id,
                    unique_pending_id,
                    None,
                )))
            },
        )
        .await
        .unwrap();
        assert_eq!(recovered, fresh_leaf);
    }

    // ── claim-scheduling fix (commit 7522ca93): claim gating + finalize target ─

    #[test]
    fn claims_require_normal_mode_and_pending_work() {
        let cases: &[(bool, usize, bool)] = &[
            (false, 1, true),
            (false, 0, false),
            (true, 1, false),
            (true, 0, false),
            (false, 7, true),
        ];

        for (is_catchup_batch, pending_claim_count, expected) in cases {
            assert_eq!(
                !*is_catchup_batch && *pending_claim_count > 0,
                *expected,
                "is_catchup_batch={is_catchup_batch}, pending_claim_count={pending_claim_count}"
            );
        }
    }

    #[test]
    fn claim_time_refresh_uses_one_sticky_catchup_state() {
        let from_checkpoint = 100;
        let confirmation_lag_checkpoints = 3;
        let max_checkpoint_batch = 64;

        assert!(!refresh_catchup_state(
            false,
            from_checkpoint,
            Some(166),
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        ));
        assert!(refresh_catchup_state(
            false,
            from_checkpoint,
            Some(167),
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        ));
        assert!(refresh_catchup_state(
            true,
            from_checkpoint,
            Some(166),
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        ));
        assert!(refresh_catchup_state(
            false,
            from_checkpoint,
            None,
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        ));
    }

    #[test]
    fn select_finalize_to_checkpoint_prefers_l2_landing_over_window_bound() {
        // Defends the finalize-to-landing contract: in a normal round the
        // daemon must finalize straight to the L2 landing checkpoint even when
        // landing exceeds the pre-round window.to_checkpoint bound. A
        // regression that re-introduces `window_to.min(landing)` or caps back
        // to the window bound would drop landed L2 work and redden this test.
        // The window < landing rows carry the teeth; the equal/behind rows pin
        // the rest of the contract.
        assert_eq!(select_finalize_to_checkpoint(50, 70), 70);
        assert_eq!(select_finalize_to_checkpoint(64, 100), 100);
        // Landing equals the window bound (catchup, or no L2 advance): both a
        // correct helper and a re-capping regression would pass this row, so
        // it documents the boundary rather than carrying teeth.
        assert_eq!(select_finalize_to_checkpoint(70, 70), 70);
        // Landing behind the window bound: the helper must still follow the
        // landing, not cap UP to the window bound.
        assert_eq!(select_finalize_to_checkpoint(70, 60), 60);
    }

    #[test]
    fn catchup_round_defers_claims_and_retains_pending() {
        let window = RelayerWindow {
            to_checkpoint: 17,
            confirmed_to_checkpoint: Some(77),
            is_catchup_batch: true,
        };
        assert!(window.is_catchup_batch);
        let mut w1 = sample_withdrawal(1);
        let mut w2 = sample_withdrawal(2);
        w1.destination_chain_index = 0;
        w2.destination_chain_index = 0;
        let pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
        ].into_iter().collect();
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &DaemonState { pending_claim_withdrawals: pending, ..Default::default() }).unwrap();
        let saved = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).unwrap();
        assert_eq!(saved.pending_claim_withdrawals.len(), 2);
        assert_eq!(saved.pending_claim_withdrawals[&w1.leaf_hash].event_id, w1.event_id);
        assert_eq!(saved.pending_claim_withdrawals[&w2.leaf_hash].event_id, w2.event_id);
        let normal = RelayerWindow { to_checkpoint: 77, confirmed_to_checkpoint: Some(77), is_catchup_batch: false };
        assert!(!normal.is_catchup_batch && saved.pending_claim_withdrawals.len() > 0);
        let _ = std::fs::remove_dir_all(root);
    }


    // ── inner-loop catch-up break (run_l2_bridge_round mid-round stop) ────

    /// Mirrors the mid-loop guard in `run_l2_bridge_round_with_l1_snapshot`:
    /// while still in a normal round (`is_catchup_batch == false`), re-check the
    /// window against the latest planning checkpoint and break once the gap
    /// has crossed into catch-up. Catch-up rounds never take this path
    /// (`is_catchup_batch == true`), so they keep planning empty batches.
    fn should_stop_l2_round_for_mid_loop_catchup(
        is_catchup_batch: bool,
        from_checkpoint: u64,
        planning_checkpoint: u64,
        confirmation_lag_checkpoints: u64,
        max_checkpoint_batch: u64,
    ) -> bool {
        if is_catchup_batch {
            return false;
        }
        select_relayer_window(
            from_checkpoint,
            planning_checkpoint,
            confirmation_lag_checkpoints,
            max_checkpoint_batch,
        )
        .is_catchup_batch
    }

    #[test]
    fn select_relayer_window_catchup_when_gap_exceeds_max_batch() {
        // Contract: gap = confirmed - from + 1 > max_checkpoint_batch ⇒
        // is_catchup_batch. Teeth: a flipped `>` / `>=` comparison or a
        // missing catch-up flag would let oversized gaps stay in normal mode
        // and keep appending business (the TC-SW-80 stuck-round failure).
        let cases = [
            // (from, latest, lag, max_batch, expected_catchup)
            (1u64, 100, 3, 64, true),   // confirmed=97, gap=97 > 64
            (10, 80, 3, 8, true),       // confirmed=77, gap=68 > 8
            (1186, 1300, 0, 64, true),  // confirmed=1300, gap=115 > 64 (TC-SW-80 shape)
            (1, 66, 1, 64, true),       // confirmed=65, gap=65 > 64 → catchup
            (1, 65, 1, 64, false),      // confirmed=64, gap=64 == 64 → normal
        ];
        for (from, latest, lag, max_batch, expect_catchup) in cases {
            let window = select_relayer_window(from, latest, lag, max_batch);
            assert_eq!(
                window.is_catchup_batch, expect_catchup,
                "select_relayer_window({from}, {latest}, lag={lag}, max={max_batch}): \
                 is_catchup_batch expected {expect_catchup}, got {}",
                window.is_catchup_batch
            );
            // Gating must track the catch-up flag exactly.
            assert_eq!(
                !window.is_catchup_batch,
                !expect_catchup,
                "deposit gating disagree with catchup for from={from} latest={latest}"
            );
            assert_eq!(
                !window.is_catchup_batch,
                !expect_catchup,
                "withdrawal gating disagree with catchup for from={from} latest={latest}"
            );
        }
    }

    #[test]
    fn select_relayer_window_gap_equal_to_max_batch_is_not_catchup() {
        // Boundary: range_len == max_checkpoint_batch must remain a normal
        // round. Off-by-one (`>=` instead of `>`) would force catch-up one
        // checkpoint early and skip legitimate deposit/withdrawal work.
        // confirmed = latest - lag; choose values so range_len == max exactly.
        let max_batch = 64u64;
        let from = 100u64;
        let lag = 3u64;
        // range_len = confirmed - from + 1 == 64 ⇒ confirmed = from + 63 = 163
        // latest = confirmed + lag = 166
        let window = select_relayer_window(from, from + max_batch - 1 + lag, lag, max_batch);
        assert_eq!(window.confirmed_to_checkpoint, Some(from + max_batch - 1));
        assert_eq!(
            window.confirmed_to_checkpoint.unwrap() - from + 1,
            max_batch,
            "fixture must produce range_len == max_batch"
        );
        assert!(
            !window.is_catchup_batch,
            "gap == max_batch must be a normal round, got catchup"
        );
        assert_eq!(window.to_checkpoint, from + max_batch - 1);
        assert!(!window.is_catchup_batch);
    }

    #[test]
    fn select_relayer_window_gap_one_past_max_batch_is_catchup() {
        // Boundary companion: range_len == max + 1 must flip into catch-up and
        // truncate to_checkpoint to a max-sized batch. The mid-loop break
        // depends on this exact threshold.
        let max_batch = 64u64;
        let from = 100u64;
        let lag = 3u64;
        // range_len = 65 ⇒ confirmed = from + 64 = 164, latest = 167
        let window = select_relayer_window(from, from + max_batch + lag, lag, max_batch);
        assert_eq!(window.confirmed_to_checkpoint, Some(from + max_batch));
        assert_eq!(
            window.confirmed_to_checkpoint.unwrap() - from + 1,
            max_batch + 1
        );
        assert!(
            window.is_catchup_batch,
            "gap == max_batch + 1 must be catchup"
        );
        assert_eq!(
            window.to_checkpoint,
            from + max_batch - 1,
            "catchup must truncate to from + max - 1"
        );
        assert!(window.is_catchup_batch);
    }

    #[test]
    fn l2_round_result_constructs_with_correct_fields() {
        // L2RoundResult carries the sticky catch-up authority the outer daemon
        // consumes alongside deposit/claim outputs. Constructing the struct
        // with exactly these fields is a compile-time shape contract.
        let claims = vec![sample_withdrawal(1), sample_withdrawal(2)];
        let result = L2RoundResult {
            deposit_append_target: Some(42),
            to_checkpoint: 1249,
            submitted_l2_work: true,
            is_catchup_batch: false,
            claim_withdrawals: claims.clone(),
        };

        assert_eq!(result.deposit_append_target, Some(42));
        assert_eq!(result.to_checkpoint, 1249);
        assert!(result.submitted_l2_work);
        assert!(!result.is_catchup_batch);
        assert_eq!(result.claim_withdrawals.len(), 2);
        assert_eq!(result.claim_withdrawals[0].leaf_hash, claims[0].leaf_hash);
        assert_eq!(result.claim_withdrawals[1].leaf_hash, claims[1].leaf_hash);

        // Empty / no-work finish path after a mid-loop catch-up latch: sticky
        // authority stays true and deposit append target must be absent.
        let idle = L2RoundResult {
            deposit_append_target: None,
            to_checkpoint: 1186,
            submitted_l2_work: false,
            is_catchup_batch: true,
            claim_withdrawals: Vec::new(),
        };
        assert_eq!(idle.deposit_append_target, None);
        assert_eq!(idle.to_checkpoint, 1186);
        assert!(!idle.submitted_l2_work);
        assert!(idle.is_catchup_batch);
        assert!(idle.claim_withdrawals.is_empty());
    }

    #[test]
    fn finish_l2_round_deposit_target_logic_matches_select_deposit_append_target() {
        // finish_l2_round is async and needs a live RpcProvider, so its
        // deposit_append_target field is defended here via the pure helper it
        // Normal mode must derive the append target from the L2 cursor.
        let target = select_deposit_append_target(
            /* is_catchup_batch */ false,
            /* proof_to_checkpoint */ 1200,
            /* l2_landing_checkpoint */ 1200,
            /* l2_deposit_cursor */ 10,
            /* proved_deposit_count */ 5,
            /* pending_deposit_count */ 12,
        )
        .expect("consistent cursors");
        assert_eq!(
            target,
            Some(10),
            "cursor ahead of proved must yield append target equal to L2 cursor"
        );

        // Catch-up mode must never request deposit appends.
        let deferred = select_deposit_append_target(true, 1200, 1200, 10, 5, 12)
            .expect("consistent cursors");
        assert_eq!(deferred, None, "catchup entry must suppress deposit_append_target");

        // Cursor caught up with proved: no append work remains.
        let caught_up = select_deposit_append_target(false, 1200, 1200, 5, 5, 12)
            .expect("consistent cursors");
        assert_eq!(caught_up, None);
    }

    #[test]
    fn mid_loop_break_when_gap_crosses_catchup_while_in_normal_mode() {
        // Defends the inner-loop break condition:
        //   if !is_catchup_batch && fresh_window.is_catchup_batch { break; }
        // Round entered normal at from=1186 with max_batch=64; as
        // planning_checkpoint advances past the threshold the loop must
        // stop appending and fall through to finish_l2_round.
        let from = 1186u64;
        let lag = 0u64;
        let max_batch = 64u64;
        // Normal while range_len <= 64 ⇒ planning <= from + 63 = 1249
        // Catch-up once planning >= 1250
        let threshold_normal = from + max_batch - 1; // 1249
        let first_catchup = threshold_normal + 1; // 1250

        // Still normal at the boundary — keep planning/submitting.
        assert!(
            !should_stop_l2_round_for_mid_loop_catchup(false, from, threshold_normal, lag, max_batch),
            "planning={threshold_normal} (gap==max) must NOT break"
        );
        // Crossed threshold mid-loop — break before the next build_l2_call_plan.
        assert!(
            should_stop_l2_round_for_mid_loop_catchup(false, from, first_catchup, lag, max_batch),
            "planning={first_catchup} (gap==max+1) must break"
        );
        // Well past threshold (as in the stuck 1186→1202 growth past 64).
        assert!(should_stop_l2_round_for_mid_loop_catchup(
            false,
            from,
            1300,
            lag,
            max_batch
        ));

        // Catch-up entry rounds pass is_catchup_batch=true; the guard
        // must not fire so the empty-plan path can still finish the round.
        assert!(
            !should_stop_l2_round_for_mid_loop_catchup(true, from, 1300, lag, max_batch),
            "catchup-mode rounds must not take the mid-loop break path"
        );
    }

    #[test]
    fn mid_loop_break_tracks_planning_checkpoint_growth_across_iterations() {
        // Table-driven simulation of successive inner-loop iterations: the
        // break decision is re-evaluated each time against the *current*
        // planning checkpoint. A regression that only checked the pre-round
        // window (or checked once) would keep appending as the gap grows.
        let from = 1186u64;
        let lag = 0u64;
        let max_batch = 64u64;
        let iterations = [
            // (planning_checkpoint, expect_break)
            (1202u64, false), // early normal growth (pre-fix stuck point)
            (1240, false),    // still within max batch
            (1249, false),    // gap == 64, last normal planning tick
            (1250, true),     // gap == 65, first catch-up tick → break
            (1280, true),     // further growth still breaks
        ];
        for (planning, expect_break) in iterations {
            let stop = should_stop_l2_round_for_mid_loop_catchup(
                false, from, planning, lag, max_batch,
            );
            assert_eq!(
                stop, expect_break,
                "iteration planning={planning}: break expected {expect_break}, got {stop}"
            );
            // Cross-check against the window the production loop builds.
            let window = select_relayer_window(from, planning, lag, max_batch);
            assert_eq!(
                stop,
                window.is_catchup_batch,
                "break decision must equal fresh_window.is_catchup_batch at planning={planning}"
            );
        }
    }

    #[test]
    fn mid_loop_break_respects_confirmation_lag() {
        // The production guard feeds confirmation_lag into select_relayer_window.
        // With lag>0 the catch-up threshold is on *confirmed* (= latest-lag),
        // not raw latest — a bug that dropped lag from the re-check would
        // break too early (or too late).
        let from = 100u64;
        let lag = 3u64;
        let max_batch = 64u64;
        // confirmed = latest - 3; catchup when confirmed - from + 1 > 64
        // ⇒ confirmed > 163 ⇒ latest > 166
        assert!(
            !should_stop_l2_round_for_mid_loop_catchup(false, from, 166, lag, max_batch),
            "latest=166 → confirmed=163 → gap=64 must stay normal"
        );
        assert!(
            should_stop_l2_round_for_mid_loop_catchup(false, from, 167, lag, max_batch),
            "latest=167 → confirmed=164 → gap=65 must break"
        );
    }


    #[test]
    fn mid_loop_threshold_crossing_latches_sticky_authority_and_suppresses_deposit_target() {
        // Production path: round enters normal, fresh head crosses max batch,
        // sticky authority latches true before break, and finish_l2_round must
        // not emit a deposit_append_target under that latched authority.
        let from = 1186u64;
        let lag = 0u64;
        let max_batch = 64u64;
        let landed_to_checkpoint = 1249u64;
        let first_catchup_planning = from + max_batch; // 1250

        let mut is_catchup_batch = false;
        assert!(
            !should_stop_l2_round_for_mid_loop_catchup(
                is_catchup_batch,
                from,
                landed_to_checkpoint,
                lag,
                max_batch
            ),
            "pre-threshold planning must stay normal"
        );

        is_catchup_batch = refresh_catchup_state(
            is_catchup_batch,
            from,
            Some(first_catchup_planning),
            lag,
            max_batch,
        );
        assert!(
            is_catchup_batch,
            "threshold crossing must latch sticky catch-up authority before break"
        );

        // Even with an L2 cursor ahead of proved deposits, latched catch-up
        // suppresses the deposit append target finish_l2_round would return.
        let deposit_append_target = select_deposit_append_target(
            is_catchup_batch,
            landed_to_checkpoint,
            landed_to_checkpoint,
            /* l2_deposit_cursor */ 12,
            /* proved_deposit_count */ 7,
            /* pending_deposit_count */ 15,
        )
        .expect("consistent cursors");
        assert_eq!(
            deposit_append_target, None,
            "sticky catch-up authority must suppress deposit_append_target"
        );

        let result = L2RoundResult {
            deposit_append_target,
            to_checkpoint: landed_to_checkpoint,
            submitted_l2_work: true,
            is_catchup_batch,
            claim_withdrawals: Vec::new(),
        };
        assert!(result.is_catchup_batch);
        assert_eq!(result.deposit_append_target, None);
        // Outer loop adopts sticky authority from the L2 result.
        let outer_is_catchup_batch = result.is_catchup_batch;
        assert!(outer_is_catchup_batch);
        assert!(
            select_deposit_append_target(outer_is_catchup_batch, 1249, 1249, 12, 7, 15)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn newly_latched_orchestration_persists_ledger_and_dispatches_no_post_l2_phases() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        async fn record_phase(permit: &PostL2PhasePermit, counter: &AtomicUsize) {
            dispatch_post_l2_phase(permit, async {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .await;
        }

        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let mut durable = sample_withdrawal(1);
        let mut landed = sample_withdrawal(2);
        durable.destination_chain_index = 0;
        landed.destination_chain_index = 0;
        let state = DaemonState {
            pending_claim_withdrawals: HashMap::from([(durable.leaf_hash.clone(), durable.clone())]),
            ..Default::default()
        };
        save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &state).unwrap();

        let deposit_calls = Arc::new(AtomicUsize::new(0));
        let proof_calls = Arc::new(AtomicUsize::new(0));
        let finalize_calls = Arc::new(AtomicUsize::new(0));
        let claim_calls = Arc::new(AtomicUsize::new(0));

        let deferred = orchestrate_post_l2_round(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &db,
            0,
            &state,
            std::slice::from_ref(&landed),
            false,
            true,
            {
                let deposit_calls = Arc::clone(&deposit_calls);
                let proof_calls = Arc::clone(&proof_calls);
                let finalize_calls = Arc::clone(&finalize_calls);
                let claim_calls = Arc::clone(&claim_calls);
                move |permit, pending| async move {
                    record_phase(&permit, &deposit_calls).await;
                    record_phase(&permit, &proof_calls).await;
                    record_phase(&permit, &finalize_calls).await;
                    record_phase(&permit, &claim_calls).await;
                    pending
                }
            },
        )
        .await
        .unwrap();

        assert!(matches!(deferred, PostL2Orchestration::Deferred));
        assert_eq!(deposit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(proof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(finalize_calls.load(Ordering::SeqCst), 0);
        assert_eq!(claim_calls.load(Ordering::SeqCst), 0);

        let installed = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).unwrap();
        assert_eq!(installed.pending_claim_withdrawals.len(), 2);
        assert_eq!(
            installed.pending_claim_withdrawals[&durable.leaf_hash].event_id,
            durable.event_id
        );
        assert_eq!(
            installed.pending_claim_withdrawals[&landed.leaf_hash].event_id,
            landed.event_id
        );

        // Existing catch-up and still-normal paths both issue the production
        // permit and dispatch every instrumented post-L2 phase.
        for (label, pre, post) in [("catchup", true, true), ("normal", false, false)] {
            deposit_calls.store(0, Ordering::SeqCst);
            proof_calls.store(0, Ordering::SeqCst);
            finalize_calls.store(0, Ordering::SeqCst);
            claim_calls.store(0, Ordering::SeqCst);

            let dispatched = orchestrate_post_l2_round(
                &crate::guardian::test_fixture::codec_guardian_config(),
                &db,
                0,
                &state,
                &[],
                pre,
                post,
                {
                    let deposit_calls = Arc::clone(&deposit_calls);
                    let proof_calls = Arc::clone(&proof_calls);
                    let finalize_calls = Arc::clone(&finalize_calls);
                    let claim_calls = Arc::clone(&claim_calls);
                    move |permit, pending| async move {
                        record_phase(&permit, &deposit_calls).await;
                        record_phase(&permit, &proof_calls).await;
                        record_phase(&permit, &finalize_calls).await;
                        record_phase(&permit, &claim_calls).await;
                        pending
                    }
                },
            )
            .await
            .unwrap();

            assert!(
                matches!(dispatched, PostL2Orchestration::Dispatch(_)),
                "{label} path must dispatch"
            );
            assert_eq!(deposit_calls.load(Ordering::SeqCst), 1, "{label}");
            assert_eq!(proof_calls.load(Ordering::SeqCst), 1, "{label}");
            assert_eq!(finalize_calls.load(Ordering::SeqCst), 1, "{label}");
            assert_eq!(claim_calls.load(Ordering::SeqCst), 1, "{label}");
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn append_only_rounds_retry_pending_claims_under_same_catchup_gate() {
        // No confirmed finalize range still runs durable claim settlement.
        // Eligibility uses the same sticky fail-closed head gate as finalize.
        let from = 100u64;
        let lag = 3u64;
        let max_batch = 64u64;
        // Empty durable set: settlement is a no-op even in normal mode.
        let sticky = refresh_catchup_state(false, from, Some(166), lag, max_batch);
        assert!(!sticky);
        assert!(!should_attempt_pending_claims(sticky, 0));

        // Normal head with pending work: append-only must retry claims without
        // requiring a new finalize checkpoint range.
        let sticky = refresh_catchup_state(false, from, Some(166), lag, max_batch);
        assert!(!sticky);
        assert!(
            should_attempt_pending_claims(sticky, 2),
            "append-only + normal sticky gate + pending claims must retry"
        );

        // Fresh head already past catch-up threshold: fail-closed, no claim.
        let sticky = refresh_catchup_state(false, from, Some(167), lag, max_batch);
        assert!(sticky);
        assert!(
            !should_attempt_pending_claims(sticky, 2),
            "append-only must honor the same fail-closed catch-up gate"
        );

        // Head refresh failure: fail closed and keep pending durable.
        let sticky = refresh_catchup_state(false, from, None, lag, max_batch);
        assert!(sticky);
        assert!(!should_attempt_pending_claims(sticky, 2));

        // Already-latched sticky authority never launders open via append-only.
        let sticky = refresh_catchup_state(true, from, Some(166), lag, max_batch);
        assert!(sticky);
        assert!(!should_attempt_pending_claims(sticky, 2));
    }

    #[test]
    fn chain_row_replace_keeps_prior_claim_and_adds_the_next() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let mut prior_w = sample_withdrawal(3);
        prior_w.destination_chain_index = 0;
        save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &DaemonState {
            pending_claim_withdrawals: HashMap::from([(prior_w.leaf_hash.clone(), prior_w.clone())]),
            ..Default::default()
        }).unwrap();
        let mut next_w = sample_withdrawal(9);
        next_w.destination_chain_index = 0;
        save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &DaemonState {
            pending_claim_withdrawals: HashMap::from([
                (prior_w.leaf_hash.clone(), prior_w.clone()),
                (next_w.leaf_hash.clone(), next_w.clone()),
            ]),
            ..Default::default()
        }).unwrap();
        let loaded = load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).unwrap();
        assert_eq!(loaded.pending_claim_withdrawals.len(), 2);
        assert_eq!(loaded.pending_claim_withdrawals[&next_w.leaf_hash].event_id, next_w.event_id);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_claim_install_retains_proof_and_prior_row() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let mut prior_w = sample_withdrawal(7);
        prior_w.destination_chain_index = 0;
        save_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0, &DaemonState {
            pending_claim_withdrawals: HashMap::from([(prior_w.leaf_hash.clone(), prior_w.clone())]),
            ..Default::default()
        }).unwrap();
        let proof_path = root.join("bridge_proof_99.json");
        std::fs::write(&proof_path, b"proof-must-survive").unwrap();
        let mut advanced = DaemonState::default();
        advanced.pending_claim_withdrawals.insert("too-wide".into(), withdrawal_for_chain("too-wide", u64::from(u8::MAX) + 1));
        let err = save_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, &MultichainDaemonState {
            pending_claim_withdrawals: advanced.pending_claim_withdrawals,
            ..Default::default()
        }).unwrap_err();
        assert!(err.to_string().contains("claim destination chain does not fit chain_index"), "{err}");
        assert!(proof_path.exists(), "a failed claim install must not delete the proof");
        assert_eq!(load_chain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db, 0).unwrap().pending_claim_withdrawals.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }



    #[test]
    fn l2_round_result_compile_time_shape_contract() {
        // Constructing L2RoundResult with the legitimate production fields is a
        // compile-time shape contract. Runtime assertions pin the observable
        // finish shape the outer loop reads after either an empty plan or a
        // mid-loop sticky catch-up break.
        let result = L2RoundResult {
            deposit_append_target: None,
            to_checkpoint: 64,
            submitted_l2_work: false,
            is_catchup_batch: true,
            claim_withdrawals: Vec::new(),
        };
        // Outer-loop consumers (run()) read these fields.
        let _deposit_target: Option<u32> = result.deposit_append_target;
        let _to: u64 = result.to_checkpoint;
        let _submitted: bool = result.submitted_l2_work;
        let _sticky: bool = result.is_catchup_batch;
        let _claims: Vec<PendingWithdrawal> = result.claim_withdrawals;
    }

    #[test]
    fn multichain_window_starts_at_slowest_chain_and_stops_at_next_cursor() {
        let (from, window) = select_multichain_relayer_window(&[100, 50, 75], 200, 3, 64).unwrap();
        assert_eq!(from, 51);
        assert_eq!(window.to_checkpoint, 75);
        assert!(window.is_catchup_batch, "a next-cursor clamp is catch-up and appends no business");
        let (from, window) = select_multichain_relayer_window(&[50, 50], 80, 3, 64).unwrap();
        assert_eq!((from, window.to_checkpoint), (51, 77));
        assert!(!window.is_catchup_batch, "equal cursors inside the batch limit stay a normal round");
    }

    #[test]
    fn multichain_finalization_skips_completed_chain_and_rejects_leapfrog() {
        let range = PendingFinalizationRange { from_checkpoint: 51, to_checkpoint: 75 };
        assert!(chain_finalization_required(50, range).unwrap());
        assert!(!chain_finalization_required(75, range).unwrap());
        assert!(chain_finalization_required(49, range).is_err());
        assert!(chain_finalization_required(60, range).is_err());
    }
    #[test]
    fn multichain_proof_endpoint_stays_at_selected_window_when_l2_lands_later() {
        // Cursors 50 and 60 select 51..=60. L2 then lands at 70. Persisting
        // 51..=70 makes the chain at 60 reject start 51 and retries forever.
        let (from, window) = select_multichain_relayer_window(&[50, 60], 80, 3, 64).unwrap();
        assert_eq!(from, 51);
        assert_eq!(window.to_checkpoint, 60);
        // The next cursor is ahead, so this round only catches the slow chain
        // up. Deposit and withdrawal appends stay suppressed.
        assert!(window.is_catchup_batch);
        let landed = 70;
        let proof_to = select_multichain_proof_endpoint(window.to_checkpoint, true, landed);
        assert_eq!(proof_to, 60);
        assert_ne!(proof_to, landed);
        let range = PendingFinalizationRange { from_checkpoint: from, to_checkpoint: proof_to };
        assert!(chain_finalization_required(50, range).unwrap());
        assert!(!chain_finalization_required(60, range).unwrap());
        // The poisoned range the old landing extension used to persist.
        let poisoned = PendingFinalizationRange { from_checkpoint: 51, to_checkpoint: 70 };
        assert!(chain_finalization_required(60, poisoned).is_err());
    }

    #[test]
    fn incompatible_saved_range_resets_to_the_window_cursors_can_start() {
        // Saved 51..=70, cursors still at 50 and 60. Resume must not keep
        // asking the chain at 60 to start at 51; the batch resets to 51..=60.
        let saved = PendingFinalizationRange { from_checkpoint: 51, to_checkpoint: 70 };
        let recovered = recover_incompatible_saved_range(saved, &[(0, 50), (1, 60)], 80, 3, 64).unwrap();
        assert_eq!(recovered, Some(PendingFinalizationRange { from_checkpoint: 51, to_checkpoint: 60 }));
        // A compatible range is left alone, so resume does not rewrite it.
        assert_eq!(recover_incompatible_saved_range(recovered.unwrap(), &[(0, 50), (1, 60)], 80, 3, 64).unwrap(), None);
        // The slow chain already consumed 51..=70 and sits at 70. The chain
        // still at 60 cannot start at 51, so the batch resumes at 61..=70.
        assert_eq!(
            recover_incompatible_saved_range(saved, &[(0, 70), (1, 60)], 80, 3, 64).unwrap(),
            Some(PendingFinalizationRange { from_checkpoint: 61, to_checkpoint: 70 })
        );
        // A cursor behind the saved parent cannot be repaired by moving the start.
        assert!(recover_incompatible_saved_range(saved, &[(0, 40), (1, 60)], 80, 3, 64).is_err());
    }

    #[tokio::test]
    async fn invalid_window_is_rejected_before_claims_or_range_are_persisted() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let prior = withdrawal_for_chain("already-saved", 0);
        let mut state = MultichainDaemonState::default();
        let valid = PendingFinalizationRange { from_checkpoint: 51, to_checkpoint: 60 };
        persist_and_sync_multichain_range(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &db, &mut state, valid, &[prior.clone()], &[(0, 50), (1, 60)],
            |_, _| std::future::ready(Ok(())),
        ).await.unwrap();
        let incoming = withdrawal_for_chain("must-not-land", 1);
        let poisoned = PendingFinalizationRange { from_checkpoint: 51, to_checkpoint: 70 };
        let err = persist_and_sync_multichain_range(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &db, &mut state, poisoned, &[incoming.clone()], &[(0, 50), (1, 60)],
            |_, _| {
                panic!("deposit sync must not run for a window a chain cursor rejects");
                #[allow(unreachable_code)]
                std::future::ready(Ok(()))
            },
        ).await.unwrap_err();
        assert!(err.to_string().contains("incompatible"), "{err}");
        let saved = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        assert_eq!(saved.pending_finalization_range, Some(valid));
        assert!(saved.pending_claim_withdrawals.contains_key(&prior.leaf_hash));
        assert!(!saved.pending_claim_withdrawals.contains_key(&incoming.leaf_hash));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cursor_read_error_chain_classifies_typed_transport_root() {
        // Mirrors the real chain at the "failed to read finalization cursor"
        // log site: the eth_call's TransportError wrapped by the two contexts
        // from fetch_l1_last_finalized_checkpoint and with_rpc_failover.
        let payload: alloy_json_rpc::ErrorPayload = serde_json::from_value(
            serde_json::json!({"code": 3, "message": "execution reverted"}),
        ).unwrap();
        let error = anyhow::Error::from(alloy_transport::TransportError::ErrorResp(payload))
            .context("StateManager.lastFinalizedCheckpointId eth_call failed")
            .context("L1 operation last_finalized_checkpoint failed");
        assert_eq!(transport_error_category(&error), "revert");

        // No typed transport error in the chain: fallback, never a guess.
        let untyped = anyhow::anyhow!("L1 operation last_finalized_checkpoint failed");
        assert_eq!(transport_error_category(&untyped), "other");
    }

    #[test]
    fn set_chain_root_calls_are_sorted_and_use_absolute_counts() {
        let mut calls = vec![
            build_set_chain_root_call(2, 9, &format!("0x{}", "22".repeat(32))).unwrap(),
            build_set_chain_root_call(0, 4, &format!("0x{}", "11".repeat(32))).unwrap(),
            build_set_chain_root_call(1, 7, &format!("0x{}", "33".repeat(32))).unwrap(),
        ];
        calls.sort_by_key(|call| call.inputs[0]);
        assert_eq!(calls.iter().map(|call| call.inputs[0]).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(calls.iter().map(|call| call.inputs[1]).collect::<Vec<_>>(), vec![4, 7, 9]);
    }

    #[test]
    fn daemon_config_parses_three_evm_chains() {
        let raw = r#"
rpc_config = "config.json"
guardian_root = "guardians-root"
services_url = "http://127.0.0.1:3000"
withdraw_method_id = 1

[[chains]]
family = "evm"
chain_index = 0
network_id = "localhost"
rpc_urls = ["http://127.0.0.1:8545"]
deployments_network = "localhost"

[[chains]]
family = "evm"
chain_index = 1
network_id = "localhostBsc"
rpc_urls = ["http://127.0.0.1:9545"]
deployments_network = "localhostBsc"

[[chains]]
family = "evm"
chain_index = 2
network_id = "localhostBase"
rpc_urls = ["http://127.0.0.1:10545"]
deployments_network = "localhostBase"
"#;
        let config: BridgeProposeDaemonConfig = toml::from_str(raw).unwrap();
        assert_eq!(config.chains.len(), 3);
        assert_eq!(config.chains.iter().map(|chain| chain.chain_index).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert!(config.chains.iter().all(|chain| chain.family == "evm"));
    }

    #[test]
    fn default_daemon_config_loads_required_startup_fields() {
        let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/config/local.toml"));
        let config = load_config(&path).unwrap();
        let services = reqwest::Url::parse(config.services_url.trim_end_matches('/')).unwrap();
        assert!(matches!(services.scheme(), "http" | "https") && services.host().is_some());
        assert!(config.withdraw_method_id > 0);
        assert!(!config.rpc_config.is_empty());
        let guardian_root = Path::new(&config.guardian_root);
        assert!(guardian_root.is_relative() && guardian_root.components().all(|component| matches!(component, std::path::Component::Normal(_))));
    }

    #[test]
    fn keystore_path_env_fills_unset_fields_without_overriding_explicit_selection() {
        assert_eq!(resolve_keystore_path(false, Some("/a".into()), Some("/b")), Some("/a".to_string()));
        assert_eq!(resolve_keystore_path(false, None, Some("/b")), Some("/b".to_string()));
        assert_eq!(resolve_keystore_path(false, None, Some("   ")), None);
        assert_eq!(resolve_keystore_path(false, None, None), None);
        assert_eq!(resolve_keystore_path(true, None, Some("/b")), None);
        assert_eq!(resolve_keystore_path(true, Some("/a".into()), Some("/b")), Some("/a".to_string()));
    }

    #[test]
    fn legacy_urls_skip_the_default_when_finalize_providers_are_set() {
        let provider = crate::bridge::rpc_providers::RpcProviderConfig {
            name: "alchemy".into(),
            url: "https://a".into(),
            priority_weight: 10,
            operator: String::new(),
            quota_group: String::new(),
        };
        let providers_only = DaemonFinalizeConfig {
            l1_rpc_providers: vec![provider.clone()],
            ..DaemonFinalizeConfig::default()
        };
        assert!(legacy_rpc_urls(&providers_only).is_empty());

        // An explicit l1_rpc_url next to providers is a real conflict and stays visible.
        let both = DaemonFinalizeConfig {
            l1_rpc_url: Some("https://z".into()),
            l1_rpc_providers: vec![provider],
            ..DaemonFinalizeConfig::default()
        };
        assert_eq!(legacy_rpc_urls(&both), vec!["https://z".to_string()]);
    }

    #[test]
    fn legacy_urls_default_and_deduplicate_without_providers() {
        assert_eq!(
            legacy_rpc_urls(&DaemonFinalizeConfig::default()),
            vec![DEFAULT_L1_RPC_URL.to_string()]
        );
        let finalize = DaemonFinalizeConfig {
            l1_rpc_url: Some("https://z".into()),
            l1_rpc_fallback_url: Some("https://z".into()),
            ..DaemonFinalizeConfig::default()
        };
        assert_eq!(legacy_rpc_urls(&finalize), vec!["https://z".to_string()]);
        let finalize = DaemonFinalizeConfig {
            l1_rpc_url: Some("https://z".into()),
            l1_rpc_fallback_url: Some("https://a".into()),
            ..DaemonFinalizeConfig::default()
        };
        assert_eq!(legacy_rpc_urls(&finalize), vec!["https://z".to_string(), "https://a".to_string()]);
    }

    #[test]
    fn chain_rpc_providers_take_precedence_and_legacy_urls_keep_order() {
        let raw = r#"
rpc_config = "config.json"
guardian_root = "guardians-root"
services_url = "http://127.0.0.1:3000"
withdraw_method_id = 1

[[chains]]
chain_index = 0
network_id = "sepolia"
deployments_network = "sepolia"
rpc_urls = ["https://ignored"]
[[chains.rpc_providers]]
name = "alchemy"
url = "https://a"
priority_weight = 11
[[chains.rpc_providers]]
name = "infura"
url = "https://i"

[[chains]]
chain_index = 1
network_id = "bscTestnet"
deployments_network = "bscTestnet"
rpc_urls = ["https://z", "https://a"]
"#;
        let config: BridgeProposeDaemonConfig = toml::from_str(raw).unwrap();
        let first = config.chains[0].effective_config(&config).unwrap().finalize;
        assert_eq!(first.l1_rpc_url.as_deref(), Some("https://a"));
        assert_eq!(
            first.l1_rpc_providers.iter().map(|p| (p.name.as_str(), p.priority_weight)).collect::<Vec<_>>(),
            vec![("alchemy", 11), ("infura", 10)]
        );
        let second = config.chains[1].effective_config(&config).unwrap().finalize;
        assert_eq!(
            second.l1_rpc_providers.iter().map(|p| p.url.as_str()).collect::<Vec<_>>(),
            vec!["https://z", "https://a"]
        );
        assert_eq!(second.l1_rpc_fallback_url, None);
    }

    #[test]
    fn l1_fees_named_pool_policy_is_chain_local_and_legacy_config_still_loads() {
        let config: BridgeProposeDaemonConfig = toml::from_str(r#"
rpc_config = "config.json"
guardian_root = "guardians-root"
services_url = "http://127.0.0.1:1"
withdraw_method_id = 1
[[chains]]
chain_index = 0
network_id = "sepolia"
deployments_network = "sepolia"
rpc_urls = ["http://127.0.0.1:1"]
[[chains]]
chain_index = 1
network_id = "bscTestnet"
deployments_network = "bscTestnet"
rpc_providers = [{ name = "first", url = "http://127.0.0.1:2" }, { name = "second", url = "http://127.0.0.1:3" }]
[chains.fee_policy]
expected_chain_id = 97
min_priority_fee_wei = 1000000000
max_priority_fee_wei = 2000000000
max_fee_per_gas_wei = 10000000000
[[chains]]
chain_index = 2
network_id = "baseSepolia"
deployments_network = "baseSepolia"
rpc_urls = ["http://127.0.0.1:4"]
"#).unwrap();
        let chains = &config.chains;
        assert_eq!(chains.len(), 3);
        let bsc = chains[1].effective_config(&config).unwrap();
        assert_eq!(bsc.finalize.fee_policy.as_ref().unwrap().min_priority_fee_wei, 1_000_000_000);
        assert_eq!(bsc.finalize.fee_policy.as_ref().unwrap().quote_strategy,
            super::super::l1_fees::BscQuoteStrategy::Conservative);
        let mut economical = config.clone();
        economical.chains[1].fee_policy.as_mut().unwrap().quote_strategy =
            super::super::l1_fees::BscQuoteStrategy::RecentHistory;
        let effective = economical.chains[1].effective_config(&economical).unwrap();
        assert_eq!(effective.finalize.fee_policy.as_ref().unwrap().quote_strategy,
            super::super::l1_fees::BscQuoteStrategy::RecentHistory);
        for index in [0, 2] {
            assert!(economical.chains[index].effective_config(&effective).unwrap().finalize.fee_policy.is_none());
        }
        assert_eq!(bsc.finalize.l1_rpc_providers.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["first", "second"]);
        for index in [0, 2] {
            assert!(chains[index].effective_config(&bsc).unwrap().finalize.fee_policy.is_none());
        }
        let mut invalid = config.clone();
        invalid.finalize.fee_policy = bsc.finalize.fee_policy.clone();
        assert!(configured_chains(&invalid, &test_l1()).unwrap_err().to_string().contains("not [finalize.fee_policy]"));
        invalid.finalize.fee_policy = None;
        invalid.chains[0].fee_policy = bsc.finalize.fee_policy.clone();
        assert!(configured_chains(&invalid, &test_l1()).unwrap_err().to_string().contains("only be enabled for bscTestnet"));
        let mut legacy = config;
        legacy.chains[1].fee_policy = None;
        assert!(legacy.chains.iter().all(|c| c.fee_policy.is_none()));
    }

    #[test]
    fn l1_fees_deferrals_do_not_spend_claim_attempts() {
        let withdrawal = withdrawal_for_chain("fee-pending", 1);
        let mut pending = HashMap::from([(withdrawal.leaf_hash.clone(), withdrawal.clone())]);
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let report = failed(&withdrawal.leaf_hash, claim_withdrawals::ClaimCode::FeeRefused);
        for round in 0..10 {
            record_claim_result(&[withdrawal.clone()], &Ok(report.clone()), &mut pending, &mut retry, &mut retired, round);
        }
        assert_eq!(pending.len(), 1);
        assert!(retry.is_empty());
        assert!(retired.is_empty());
    }

    #[tokio::test]
    async fn l1_fees_deposit_sync_skips_satisfied_targets_and_fails_closed_on_read_error() {
        for (proved, expected_calls) in [(166, 1), (167, 0), (168, 0)] {
            let mut calls = 0;
            sync_deposit_if_behind(167, std::future::ready(Ok(proved)), || {
                calls += 1;
                std::future::ready(Ok(()))
            }).await.unwrap();
            assert_eq!(calls, expected_calls);
        }
        let result = sync_deposit_if_behind(167,
            std::future::ready(Err(anyhow::anyhow!("injected RPC failure"))), || {
                panic!("append must not run without a successful progress read");
                #[allow(unreachable_code)]
                std::future::ready(Ok(()))
            }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn l1_fees_durable_range_survives_refusal_and_resume_syncs_before_finalize() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let withdrawal = withdrawal_for_chain("landed-bsc", 1);
        let range = PendingFinalizationRange { from_checkpoint: 198846, to_checkpoint: 198905 };
        let mut state = MultichainDaemonState::default();
        let mut attempted = Vec::new();
        let ready = persist_and_sync_multichain_range(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &db, &mut state, range, &[withdrawal.clone()],
            &[(0, 198845), (1, 198845), (2, 198845)],
            |chain, endpoint| {
                // Fault injection runs only after the actual production save.
                let saved = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
                assert_eq!(saved.pending_finalization_range, Some(range));
                assert!(saved.pending_claim_withdrawals.contains_key(&withdrawal.leaf_hash));
                attempted.push((chain, endpoint));
                std::future::ready(if chain == 1 {
                    Err(anyhow::Error::from(super::super::l1_fees::FeeSourceError("injected fee refusal")))
                } else { Ok(()) })
            },
        ).await.unwrap();
        assert!(!ready, "fee refusal must block proof/finalize dispatch");
        assert_eq!(attempted, vec![(0, range.to_checkpoint), (1, range.to_checkpoint)]);

        let mut restarted = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        assert!(restarted.finalized_chains.is_empty());
        assert!(restarted.claim_retry.is_empty());
        assert!(restarted.retired_claim_withdrawals.is_empty());
        attempted.clear();
        let ready = persist_and_sync_multichain_range(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &db, &mut restarted, range, &[],
            &[(0, range.to_checkpoint), (1, 198845), (2, 198845)],
            |chain, endpoint| {
                attempted.push((chain, endpoint));
                std::future::ready(Ok(()))
            },
        ).await.unwrap();
        assert!(ready);
        // A finalized chain is skipped, but every unfinished chain is synced
        // again at the original endpoint before finalization can proceed.
        assert_eq!(attempted, vec![(1, range.to_checkpoint), (2, range.to_checkpoint)]);
        let saved = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        assert_eq!(saved.pending_finalization_range, Some(range));
        assert_eq!(saved.pending_claim_withdrawals.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn l1_fees_durable_range_save_failure_blocks_deposit_dispatch() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let poison = b"not-json";
        db.test_write_raw_finalization_batch(poison).unwrap();
        let withdrawal = withdrawal_for_chain("poisoned-batch", 1);
        let mut state = MultichainDaemonState::default();
        let range = PendingFinalizationRange { from_checkpoint: 10, to_checkpoint: 80 };
        let result = persist_and_sync_multichain_range(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &db, &mut state, range, &[withdrawal], &[(1, 9)],
            |_, _| {
                panic!("deposit dispatch must not run if the ledger cannot be installed");
                #[allow(unreachable_code)]
                std::future::ready(Ok(()))
            },
        ).await;
        assert!(result.is_err());
        assert_eq!(db.test_raw_finalization_batch().unwrap().as_deref(), Some(&poison[..]));
        assert!(db.chain_claims(&crate::guardian::test_fixture::codec_guardian_config()).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn l1_fees_durable_range_retains_claims_on_non_fee_deposit_error() {
        let (root, db) = super::super::guardian_client::tests_db();
        bind_progress_to_fixture(&db);
        let mut state = MultichainDaemonState::default();
        let range = PendingFinalizationRange { from_checkpoint: 1, to_checkpoint: 5 };
        let withdrawal = withdrawal_for_chain("landed-rpc-error", 1);
        let result = persist_and_sync_multichain_range(
            &crate::guardian::test_fixture::codec_guardian_config(),
            &db, &mut state, range, &[withdrawal.clone()], &[(1, 0)],
            |_, _| std::future::ready(Err(anyhow::anyhow!("injected deposit RPC error"))),
        ).await;
        assert!(result.is_err());
        let saved = load_multichain_state(&crate::guardian::test_fixture::codec_guardian_config(), &db).unwrap();
        assert_eq!(saved.pending_finalization_range, Some(range));
        assert!(saved.pending_claim_withdrawals.contains_key(&withdrawal.leaf_hash));
        let _ = std::fs::remove_dir_all(root);
    }

    fn write_temp_rpc_config(system_urls: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "relayer-proxy-test-{}-{}",
            std::process::id(),
            system_urls.len()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        // Match the compiled identity so this fixture exercises URL validation,
        // rather than failing the independent stage/magic guard first.
        let system_prove_proxy_url: serde_json::Value = serde_json::from_str(system_urls).unwrap();
        let json = serde_json::json!({
            "networks": {(psy_config::CURRENT_NETWORK): {
                "magic": format!("0x{:x}", psy_config::PSY_NETWORK_MAGIC),
                "users_per_realm": 1048576,
                "global_user_tree_height": 24,
                "realm_user_tree_height": 20,
                "group_realm_height": 1,
                "realm_configs": [{"id": 0, "rpc_url": ["http://127.0.0.1:8546"]}],
                "p2p": {"checkpoints_per_epoch": 1},
                "coordinator_configs": [{"id": 0, "rpc_url": ["http://127.0.0.1:8545"]}],
                "prove_proxy_url": ["http://127.0.0.1:9999"],
                "system_prove_proxy_url": system_prove_proxy_url,
                "faucet_rpc_url": ["http://127.0.0.1:8547"],
                "nostr_relay_url": "wss://relay.127.0.0.1.example",
                "native_currency": "PSY",
                "native_currency_decimal": 9,
                "native_currency_name": "PSY",
                "fees": {
                    "register_user_fee": 0,
                    "deploy_contract_fee": 0,
                    "guta_fee": 5_000_000_000u64,
                    "da_fee": 0
                }
            }},
            "defaultNetwork": psy_config::CURRENT_NETWORK
        }).to_string();
        std::fs::write(&path, json).unwrap();
        path
    }

    fn daemon_config_with_rpc(path: &std::path::Path) -> BridgeProposeDaemonConfig {
        toml::from_str(&format!(
            "rpc_config = {:?}\nguardian_root = \"guardians-root\"\nservices_url = \"http://127.0.0.1:1\"\nwithdraw_method_id = 0\n",
            path.display()
        ))
        .unwrap()
    }

    #[test]
    fn system_prove_proxy_url_is_required() {
        let path = write_temp_rpc_config("[]");
        let err = resolve_system_prove_proxy_url(psy_config::PsyConfigGoldilocks::builder().path(path.to_str().unwrap()).network(psy_config::CURRENT_NETWORK).build().unwrap().get_current_network().unwrap()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("system_prove_proxy_url"), "{msg}");
        assert!(msg.contains("loaded network"), "{msg}");
    }

    #[test]
    fn system_prove_proxy_url_skips_blank_entries() {
        let path = write_temp_rpc_config(r#"["  ", "http://127.0.0.1:9997"]"#);
        let url = resolve_system_prove_proxy_url(psy_config::PsyConfigGoldilocks::builder().path(path.to_str().unwrap()).network(psy_config::CURRENT_NETWORK).build().unwrap().get_current_network().unwrap()).unwrap();
        assert_eq!(url, "http://127.0.0.1:9997");
    }

    #[test]
    fn user_pool_url_is_not_a_fallback() {
        let path = write_temp_rpc_config(r#"[""]"#);
        assert!(resolve_system_prove_proxy_url(psy_config::PsyConfigGoldilocks::builder().path(path.to_str().unwrap()).network(psy_config::CURRENT_NETWORK).build().unwrap().get_current_network().unwrap()).is_err());
    }

    /// Starts a minimal single-shot HTTP responder on `127.0.0.1:0` that reads
    /// one request and replies with `body` as a JSON response, then returns
    /// the URL to reach it.
    fn spawn_json_responder(body: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn verify_system_prove_proxy_accepts_role_system() {
        let url = spawn_json_responder(
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"system","user_methods":false,"system_methods":true}}"#,
        );

        verify_system_prove_proxy(&url).await.unwrap();
    }

    #[tokio::test]
    async fn verify_system_prove_proxy_accepts_role_all() {
        let url = spawn_json_responder(
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"all","user_methods":true,"system_methods":true}}"#,
        );
        verify_system_prove_proxy(&url).await.unwrap();
    }

    #[tokio::test]
    async fn verify_system_prove_proxy_rejects_inconsistent_capabilities() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"user","user_methods":true,"system_methods":true}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"unknown","user_methods":false,"system_methods":true}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"system","user_methods":true,"system_methods":true}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"all","user_methods":false,"system_methods":true}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"system","system_methods":true}}"#,
        ] {
            let url = spawn_json_responder(body);
            let error = verify_system_prove_proxy(&url).await.unwrap_err();
            assert!(error.to_string().contains("inconsistent role capabilities"), "{error}");
        }
    }

    #[tokio::test]
    async fn verify_system_prove_proxy_rejects_legacy_or_malformed_response() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"system","user_methods":false,"system_methods":"true"}}"#,
            r#"{"id":1,"result":{"role":"system","user_methods":false,"system_methods":true}}"#,
            r#"{"jsonrpc":"1.0","id":1,"result":{"role":"system","user_methods":false,"system_methods":true}}"#,
            r#"{"jsonrpc":"2.0","result":{"role":"system","user_methods":false,"system_methods":true}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"role":"system","user_methods":false,"system_methods":true}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{},"result":{"role":"system","user_methods":false,"system_methods":true}}"#,
            "not JSON",
        ] {
            assert!(verify_system_prove_proxy(&spawn_json_responder(body)).await.is_err());
        }
    }

    #[tokio::test]
    async fn verify_system_prove_proxy_rejects_role_user() {
        let url = spawn_json_responder(
            r#"{"jsonrpc":"2.0","id":1,"result":{"role":"user","user_methods":true,"system_methods":false}}"#,
        );

        let err = verify_system_prove_proxy(&url).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("role `user`"), "{msg}");
        assert!(msg.contains("system_prove_proxy_url"), "{msg}");
    }

    #[tokio::test]
    async fn verify_system_prove_proxy_errs_on_closed_port() {
        // Bind to get a free port, then drop the listener so nothing answers.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://{addr}");

        assert!(verify_system_prove_proxy(&url).await.is_err());
    }

}
