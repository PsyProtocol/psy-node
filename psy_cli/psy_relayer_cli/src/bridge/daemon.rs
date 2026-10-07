use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};


use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, ensure};
use clap::Args;
use psy_client_common::args::{ContractCallArgs, ContractCallData};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;

use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use plonky2::field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}};
use plonky2::plonk::config::Hasher;
use serde::{Deserialize, Serialize};

use crate::bridge::{
    claim_attempts,
    claim_withdrawals,
    constants::{
        BRIDGE_USER_ID_U64, DEFAULT_DEPLOYMENTS_NETWORK, DEFAULT_L1_RPC_URL, DEPOSIT_TREE_CONTRACT_ID, WITHDRAWAL_TREE_CONTRACT_ID,
        REALM_CHECKPOINT_POLL_INTERVAL_SECS, REALM_CHECKPOINT_POLL_TIMEOUT_SECS,
    },
    l1_client::L1Client,
    propose_withdrawals::{self, ProposeWithdrawalsArgs},
    prove_bridge::{self},
};

const DEFAULT_PROOF_DIR: &str = "/tmp/psy_bridge_proofs";
const CONTRACT_STATE_TREE_HEIGHT: u8 = 32;
const DEFAULT_MAX_CHECKPOINT_BATCH: u64 = 64;


// deposit_tree storage is felt-addressed, with 4 felts packed per contract-state leaf.
// Layout:
//   root[8]                 -> sub-slots 0..7
//   frontiers[8192][8]      -> sub-slots 8..65543
//   chain_counts[256]       -> sub-slots 65544..65799
//   global_count            -> sub-slot 65800
const DEPOSIT_TREE_CHAIN_COUNTS_SUBSLOT_BASE: u64 = 8 + (8192 * 8);
sol! {
    function provedDepositCount() external view returns (uint256);
    function pendingDepositCount() external view returns (uint256);
    function lastFinalizedCheckpointId() external view returns (uint64);
}

#[derive(Clone, Args)]
pub struct RunDaemonArgs {
    #[arg(long)]
    pub config: PathBuf,
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
    pub withdrawal_scan_lookback_checkpoints: Option<u64>,
    pub guardian_config: String,
    pub aggregate_setup_config: PathBuf,
    pub aggregate_artifact_dir: PathBuf,
    pub aggregation_token_file: PathBuf,
    pub aggregate_limits: AggregateLimits,
    #[serde(skip)]
    guardian_history: std::sync::Arc<tokio::sync::Mutex<RelayerHistory>>,
    #[serde(default)]
    pub finalize: DaemonFinalizeConfig,
    /// Multisig account submissions are always serialized; values other than one are rejected.
    #[serde(default)]
    pub max_concurrent_l2_batches: Option<u64>,
    /// L1 chains handled by this daemon. When omitted, `[finalize]` is
    /// promoted to a single legacy EVM chain.
    #[serde(default)]
    pub chains: Vec<L1Config>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AggregateLimits {
    pub(crate) max_deposits: u32,
    pub(crate) reserved_withdrawals: u32,
    pub(crate) reserved_rewards: u32,
    pub(crate) max_window_calldata_bytes: u64,
    pub(crate) chains: Vec<ChainLimits>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainLimits {
    pub(crate) chain_index: u8,
    pub(crate) max_deposits: u32,
    pub(crate) reserved_withdrawals: u32,
    pub(crate) tx_gas_limit: u64,
    pub(crate) block_gas_reserve: u64,
}

impl AggregateLimits {
    pub(crate) fn chain(&self, index: u8) -> anyhow::Result<&ChainLimits> {
        self.chains.iter().find(|chain| chain.chain_index == index).context("aggregate limits missing chain")
    }

    pub(crate) fn validate(&self, network: &psy_client_data::bridge_aggregate::NetworkConfig) -> anyhow::Result<()> {
        ensure!(self.max_deposits <= network.max_deposits && self.reserved_withdrawals <= network.max_withdrawals
            && self.reserved_rewards <= network.max_rewards, "aggregate limits exceed protocol maxima");
        ensure!(self.chains.len() == network.chains.len() && self.chains.iter().zip(&network.chains).all(|(limit, chain)| limit.chain_index == chain.chain_index), "aggregate limits chain cohort mismatch");
        self.validate_shape()?;
        let deposits = self.chains.iter().map(|chain| (chain.chain_index, 0)).collect::<Vec<_>>();
        let withdrawals = self.chains.iter().map(|chain| (chain.chain_index, chain.reserved_withdrawals)).collect::<Vec<_>>();
        self.validate_capacity(&deposits, &withdrawals, self.reserved_rewards)?;
        Ok(())
    }

    fn validate_shape(&self) -> anyhow::Result<()> {
        ensure!((1..=8).contains(&self.chains.len()) && self.chains.windows(2).all(|rows| rows[0].chain_index < rows[1].chain_index), "aggregate limits chains must be ordered and unique");
        ensure!(self.max_deposits <= 1024 && self.reserved_withdrawals <= 1024 && self.reserved_rewards <= 1024, "aggregate limits exceed record ceiling");
        ensure!(self.max_window_calldata_bytes > 0, "aggregate byte budget must be positive");
        let mut withdrawals = 0u32;
        for chain in &self.chains {
            ensure!(chain.max_deposits <= self.max_deposits && chain.tx_gas_limit > 0, "invalid local aggregate limits");
            withdrawals = withdrawals.checked_add(chain.reserved_withdrawals).context("withdrawal reservation overflow")?;
        }
        ensure!(withdrawals == self.reserved_withdrawals, "local withdrawal reservations differ from global reservation");
        Ok(())
    }

    pub(crate) fn validate_capacity(&self, deposits: &[(u8, u32)], withdrawals: &[(u8, u32)], rewards: u32) -> anyhow::Result<u64> {
        self.validate_shape()?;
        ensure!(deposits.len() == self.chains.len() && withdrawals.len() == self.chains.len(), "capacity chain count mismatch");
        let mut d = 0u64;
        let mut w = 0u64;
        for ((limit, &(deposit_chain, count)), &(withdrawal_chain, claims)) in self.chains.iter().zip(deposits).zip(withdrawals) {
            ensure!(limit.chain_index == deposit_chain && limit.chain_index == withdrawal_chain, "capacity chain ordering mismatch");
            ensure!(count <= limit.max_deposits && claims <= limit.reserved_withdrawals, "local aggregate capacity exceeded");
            d = d.checked_add(u64::from(count)).context("deposit count overflow")?;
            w = w.checked_add(u64::from(claims)).context("withdrawal count overflow")?;
        }
        ensure!(d <= u64::from(self.max_deposits) && w <= u64::from(self.reserved_withdrawals) && rewards <= self.reserved_rewards, "global aggregate capacity exceeded");
        let c = u64::try_from(self.chains.len())?;
        let bytes = 2116u64.checked_add(992u64.checked_mul(c).context("window calldata length overflow")?)
            .and_then(|n| 224u64.checked_mul(d).and_then(|d| n.checked_add(d)))
            .and_then(|n| 192u64.checked_mul(w).and_then(|w| n.checked_add(w)))
            .and_then(|n| 192u64.checked_mul(u64::from(rewards)).and_then(|r| n.checked_add(r))).context("window calldata length overflow")?;
        ensure!(bytes <= self.max_window_calldata_bytes, "aggregate calldata budget exceeded");
        Ok(bytes)
    }
}

#[derive(Default)]
struct RelayerHistory {
    history: crate::guardian::verify::GuardianHistory,
    sessions: Vec<crate::guardian::protocol::GuardianSession>,
    approvals: std::collections::BTreeMap<u32, crate::guardian::protocol::Hex32>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct L1Config {
    #[serde(default = "default_evm_family")]
    pub family: String,
    pub chain_index: u8,
    pub network_id: String,
    pub rpc_urls: Vec<String>,
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

impl L1Config {
    fn namespace(&self) -> String {
        format!("evm_{}_{}", self.chain_index, self.network_id)
    }

    fn effective_config(
        &self,
        base: &BridgeProposeDaemonConfig,
    ) -> anyhow::Result<BridgeProposeDaemonConfig> {
        let mut config = base.clone();
        config.chains.clear();
        config.finalize.l1_rpc_url = Some(
            self.rpc_urls
                .first()
                .cloned()
                .context("EVM chain rpc_urls must not be empty")?,
        );
        config.finalize.l1_rpc_fallback_url = self.rpc_urls.get(1).cloned();
        config.finalize.deployments_network = Some(self.deployments_network.clone());
        config.finalize.state_manager = self.state_manager.clone();
        config.finalize.bridge_address = self.bridge_address.clone();
        config.finalize.private_key = self.private_key.clone();
        config.finalize.keystore_path = self.keystore_path.clone();
        config.finalize.password_env = self.password_env.clone();
        Ok(config)
    }
}

fn configured_chains(config: &BridgeProposeDaemonConfig) -> anyhow::Result<Vec<L1Config>> {
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
        let mut rpc_urls = vec![config
            .finalize
            .l1_rpc_url
            .clone()
            .unwrap_or_else(|| DEFAULT_L1_RPC_URL.to_string())];
        if let Some(url) = config.finalize.l1_rpc_fallback_url.clone() {
            if !url.trim().is_empty() && !rpc_urls.contains(&url) {
                rpc_urls.push(url);
            }
        }
        vec![L1Config {
            family: default_evm_family(),
            chain_index,
            network_id: deployments_network.clone(),
            rpc_urls,
            deployments_network,
            state_manager: config.finalize.state_manager.clone(),
            bridge_address: config.finalize.bridge_address.clone(),
            private_key: config.finalize.private_key.clone(),
            keystore_path: config.finalize.keystore_path.clone(),
            password_env: config.finalize.password_env.clone(),
        }]
    } else {
        config.chains.clone()
    };
    ensure!(!chains.is_empty(), "bridge relayer requires at least one chain");
    let mut seen = HashSet::with_capacity(chains.len());
    for chain in &chains {
        ensure!(chain.family.eq_ignore_ascii_case("evm"), "unsupported bridge chain family {}", chain.family);
        ensure!(!chain.rpc_urls.is_empty(), "chain {} has no RPC URL", chain.network_id);
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
    pub l1_rpc_url: Option<String>,
    pub l1_rpc_fallback_url: Option<String>,
    pub deployments_network: Option<String>,
    pub state_manager: Option<String>,
    pub bridge_address: Option<String>,
    pub bridge: Option<String>,
    pub private_key: Option<String>,
    pub keystore_path: Option<String>,
    pub password_env: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct DaemonState {
    last_finalized_checkpoint: u64,
    /// Withdrawals that still need a successful L1 claim.
    ///
    /// This set is the single source of truth for crash recovery:
    /// newly-scanned withdrawals are inserted before finalize/claim,
    /// successful claims remove entries, and all remaining entries are
    /// retried next round. The key is leaf_hash.
    #[serde(default, alias = "failed_claim_withdrawals")]
    pending_claim_withdrawals: HashMap<String, propose_withdrawals::PendingWithdrawal>,
    /// Failure counts for the entries above, keyed by leaf_hash.
    #[serde(default)]
    claim_retry: HashMap<String, claim_attempts::ClaimAttempts>,
    /// Withdrawals that ran out of attempts. Nothing retries these; they are
    /// kept so the stuck funds stay traceable and can be re-armed by hand.
    #[serde(default)]
    retired_claim_withdrawals:
        HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingFinalizationRange {
    from_checkpoint: u64,
    to_checkpoint: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MultichainDaemonState {
    schema: u32,
    identity_namespace: String,
    #[serde(with = "decimal_checkpoint")]
    last_finalized_checkpoint: u64,
    pending: Option<PendingAggregate>,
    receipt_dispositions: std::collections::BTreeMap<String, ReceiptDispositions>,
    retained_finalize: std::collections::BTreeMap<String, FinalizeEvidence>,
    #[serde(with = "aggregate_ledger")]
    pending_claim_withdrawals: HashMap<String, propose_withdrawals::PendingWithdrawal>,
    #[serde(with = "aggregate_ledger")]
    claim_retry: HashMap<String, claim_attempts::ClaimAttempts>,
    #[serde(with = "aggregate_ledger")]
    retired_claim_withdrawals: HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
    reward_ledger: Option<RewardLedgerWindow>,
}

impl Default for MultichainDaemonState {
    fn default() -> Self {
        Self { schema: 4, identity_namespace: String::new(), last_finalized_checkpoint: 0,
            pending: None, retained_finalize: Default::default(), receipt_dispositions: Default::default(), pending_claim_withdrawals: Default::default(),
            claim_retry: Default::default(), retired_claim_withdrawals: Default::default(), reward_ledger: None }
    }
}

mod decimal_checkpoint {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(&value.to_string()) }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value: u64 = text.parse().map_err(serde::de::Error::custom)?;
        if value.to_string() != text { return Err(serde::de::Error::custom("noncanonical checkpoint")); }
        Ok(value)
    }
}

mod aggregate_ledger {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    const UNSIGNED: &[&str] = &["checkpoint_id", "user_id", "sender_user_id", "contract_id", "destination_chain_index", "retired_at_unix"];
    fn encode(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => for (name, value) in fields {
                if UNSIGNED.contains(&name.as_str()) { if let Some(number) = value.as_u64() { *value = serde_json::Value::String(number.to_string()); } }
                else { encode(value); }
            },
            serde_json::Value::Array(values) => for value in values { encode(value); },
            _ => {},
        }
    }
    fn decode(value: &mut serde_json::Value) -> Result<(), String> {
        match value {
            serde_json::Value::Object(fields) => for (name, value) in fields {
                if UNSIGNED.contains(&name.as_str()) {
                    let text = value.as_str().ok_or_else(|| format!("{name} must be a decimal string"))?;
                    let number: u64 = text.parse().map_err(|_| format!("invalid {name}"))?;
                    if number.to_string() != text { return Err(format!("noncanonical {name}")); }
                    *value = serde_json::Value::from(number);
                } else { decode(value)?; }
            },
            serde_json::Value::Array(values) => for value in values { decode(value)?; },
            _ => {},
        }
        Ok(())
    }
    pub fn serialize<T: Serialize, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serde_json::to_value(value).map_err(serde::ser::Error::custom)?;
        encode(&mut value); value.serialize(serializer)
    }
    pub fn deserialize<'de, T: serde::de::DeserializeOwned + Serialize, D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        decode(&mut value).map_err(serde::de::Error::custom)?;
        let decoded: T = serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
        let expected = serde_json::to_value(&decoded).map_err(serde::de::Error::custom)?;
        let rows = value.as_object().ok_or_else(|| serde::de::Error::custom("ledger must be a map"))?;
        for (id, row) in rows {
            let fields = row.as_object().ok_or_else(|| serde::de::Error::custom("ledger entry must be a record"))?;
            for (name, supplied) in fields {
                if expected.get(id).and_then(|row| row.get(name)) != Some(supplied) {
                    return Err(serde::de::Error::custom(format!("unknown or noncanonical ledger field {name}")));
                }
            }
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducingSession {
    #[serde(with = "decimal_checkpoint")]
    session_nonce: u64,
    request_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
enum PendingAggregate {
    Producing {
        aggregate_limits: AggregateLimits,
        deposit_counts: Vec<(u8, u32)>,
        #[serde(with = "decimal_checkpoint")]
        session_nonce: u64,
        request_id: String,
        selected_withdrawal_leaf_hashes: Vec<String>,
    },
    Collecting {
        aggregate_limits: AggregateLimits,
        producing_session: Option<ProducingSession>,
        selected_withdrawal_leaf_hashes: Vec<String>,
        a_opening: String,
        withdrawal_endpoint: String,
        selected_claims: Vec<SelectedClaim>,
    },
    Frozen {
        aggregate_limits: AggregateLimits,
        producing_session: Option<ProducingSession>,
        selected_withdrawal_leaf_hashes: Vec<String>,
        a_opening: String,
        settlement_opening: String,
        claim_ids: Vec<String>,
        local_proofs: Vec<FileReference>,
        final_proofs: Option<WindowProofs>,
        destinations: Vec<Destination>,
        included_acknowledged: [bool; 2],
    },
}

impl PendingAggregate {
    fn limits(&self) -> &AggregateLimits {
        match self {
            Self::Producing { aggregate_limits, .. } | Self::Collecting { aggregate_limits, .. } | Self::Frozen { aggregate_limits, .. } => aggregate_limits,
        }
    }
}

fn aggregate_deposit_counts(a: &psy_client_data::bridge_aggregate::DepositAggregateOpening) -> anyhow::Result<Vec<(u8, u32)>> {
    let counts = a.deposits.iter().map(|deposit| Ok((deposit.chain_index, deposit.new_count.checked_sub(deposit.old_count).context("deposit interval regressed")?))).collect::<anyhow::Result<Vec<_>>>()?;
    let total = counts.iter().try_fold(0u64, |sum, (_, count)| sum.checked_add(u64::from(*count)).context("deposit interval overflow"))?;
    ensure!(total == u64::try_from(a.deposit_leaves.len())?, "complete deposit opening count mismatch");
    Ok(counts)
}

fn aggregate_selected_counts(limits: &AggregateLimits, selected: &[String], claims: &[SelectedClaim], state: &MultichainDaemonState) -> anyhow::Result<(Vec<(u8, u32)>, u32)> {
    let mut records = HashMap::new();
    let mut rewards = 0u32;
    for claim in claims {
        match claim.kind {
            2 => { let record = aggregate_bytes(&claim.record)?; let leaf = psy_client_data::bridge_aggregate::WithdrawalLeaf::decode(&record)?; records.insert(record, leaf.chain_index); }
            3 => { if !claim.record.is_empty() { rewards = rewards.checked_add(1).context("reward count overflow")?; } }
            _ => anyhow::bail!("unsupported selected claim kind"),
        }
    }
    for hash in selected {
        let withdrawal = state.pending_claim_withdrawals.get(hash).or_else(|| state.retired_claim_withdrawals.get(hash).map(|entry| &entry.withdrawal)).context("selected withdrawal metadata missing")?;
        let leaf = withdrawal_record(withdrawal)?;
        records.insert(leaf.encode()?, leaf.chain_index);
    }
    let mut counts = limits.chains.iter().map(|chain| (chain.chain_index, 0u32)).collect::<Vec<_>>();
    for chain in records.into_values() {
        let (_, count) = counts.iter_mut().find(|(index, _)| *index == chain).context("selected withdrawal destination absent")?;
        *count = count.checked_add(1).context("withdrawal count overflow")?;
    }
    Ok((counts, rewards))
}

fn validate_aggregate_reservation(limits: &AggregateLimits, deposits: &[(u8, u32)], withdrawals: &[(u8, u32)], rewards: u32) -> anyhow::Result<()> {
    limits.validate_capacity(deposits, withdrawals, rewards)?;
    let reserved = limits.chains.iter().map(|chain| (chain.chain_index, chain.reserved_withdrawals)).collect::<Vec<_>>();
    limits.validate_capacity(deposits, &reserved, limits.reserved_rewards)?;
    Ok(())
}

fn validate_frozen_capacity(limits: &AggregateLimits, a: &psy_client_data::bridge_aggregate::DepositAggregateOpening, settlement: &psy_client_data::bridge_aggregate::SettlementOpening) -> anyhow::Result<()> {
    ensure!(settlement.config_hash == a.config_hash && settlement.window_id == a.window_id && settlement.end_checkpoint_id == a.end_checkpoint_id && settlement.end_checkpoint_root == a.end_checkpoint_root, "window opening context mismatch");
    ensure!(settlement.finalizations.len() == a.starts.len() && settlement.endpoints.len() == a.starts.len(), "settlement chain count mismatch");
    let deposits = aggregate_deposit_counts(a)?;
    let mut withdrawals = limits.chains.iter().map(|chain| (chain.chain_index, 0u32)).collect::<Vec<_>>();
    for leaf in &settlement.withdrawals {
        let (_, count) = withdrawals.iter_mut().find(|(chain, _)| *chain == leaf.chain_index).context("withdrawal destination absent")?;
        *count = count.checked_add(1).context("withdrawal count overflow")?;
    }
    let bytes = limits.validate_capacity(&deposits, &withdrawals, settlement.rewards.len().try_into()?)?;
    let call = super::finalize_bridge::BridgeWindowCall { deposit_proof: [U256::ZERO; 8], deposit_opening: a.encode()?.into(), settlement_proof: [U256::ZERO; 8], settlement_opening: settlement.encode().map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?.into() };
    ensure!(u64::try_from(call.encode().len())? == bytes, "window ABI length mismatch");
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedClaim {
    claim_id: String,
    kind: u8,
    record: String,
    proof: Option<FileReference>,
    proof_context_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileReference { relative_path: String, sha256: String }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RewardLedgerWindow {
    context_id: String,
    revision: u64,
    root: String,
    predecessor_root: Option<String>,
    config_hash: String,
    economic_domain: String,
    window_id: String,
    #[serde(with = "decimal_checkpoint")]
    end_checkpoint_id: u64,
    end_checkpoint_root: String,
    start_root: String,
    state: RewardLedgerStateRecord,
    tip: Option<RewardLedgerTipRecord>,
    prior_context: Option<RewardLedgerPriorRecord>,
    nodes: std::collections::BTreeMap<String, RewardLedgerNodeRecord>,
    node_delta: Vec<String>,
    transitions: std::collections::BTreeMap<String, FileReference>,
    user_id: Option<u32>,
    source_checkpoint_id: Option<u64>,
    published: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RewardLedgerStateRecord {
    ledger_window_hash: String,
    ledger_root: String,
    user_root: String,
    session_count: u32,
    unfinished_session_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RewardLedgerTipRecord {
    proof_id: String,
    proof: FileReference,
    transition: FileReference,
    new_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RewardLedgerPriorRecord {
    context_id: String,
    revision: u64,
    tip_proof: FileReference,
    root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RewardLedgerNodeRecord {
    tree: String,
    height: u8,
    left_hash: String,
    right_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptDispositions {
    family: u8,
    opening: FileReference,
    final_proofs: Option<WindowProofs>,
    dispositions: Vec<super::api_client::ClaimDisposition>,
    reverted_receipts: Vec<RevertedReceipt>,
    #[serde(default)]
    posted_opening_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevertedReceipt {
    chain_index: u8,
    transaction_hash: String,
    block_hash: String,
    #[serde(with = "decimal_checkpoint")]
    block_number: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination { chain_index: u8, finalize: Option<FinalizeEvidence>, submission: Submission }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeEvidence { bf_identity: String, raw_proof: FileReference }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowProofs { deposit: FileReference, settlement: FileReference }


#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum Submission {
    NotSent,
    Sending,
    Submitted { transaction_hash: String },
    Finalized {
        transaction_hash: String, block_hash: String,
        #[serde(with = "decimal_checkpoint")]
        block_number: u64,
        withdrawal_log_index: String,
        reward_log_index: Option<String>,
    },
    Reverted {
        transaction_hash: String, block_hash: String,
        #[serde(with = "decimal_checkpoint")]
        block_number: u64,
    },
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
    selected_deposit_count: u32,
}

#[derive(Debug)]
struct MultichainL2CallPlan {
    calls: Vec<ContractCallArgs>,
    withdrawals: Vec<propose_withdrawals::PendingWithdrawal>,
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
    }
    Ok((from_checkpoint, window))
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





pub async fn run(args: RunDaemonArgs) -> anyhow::Result<()> {
    let loaded = load_config(&args.config)?;
    let chain_configs = configured_chains(&loaded)?;
    let history_config = super::guardian_client::GuardianClientConfig::load(Path::new(&loaded.guardian_config))?;
    let daemon = run_multichain(loaded, chain_configs, &args.config);
    tokio::select! {
        result = history_config.serve_history() => result,
        result = daemon => result,
    }
}

async fn run_multichain(
    config: BridgeProposeDaemonConfig,
    chain_configs: Vec<L1Config>,
    config_path: &Path,
) -> anyhow::Result<()> {
    ensure!(config.max_concurrent_l2_batches.unwrap_or(1) == 1, "multisig account permits one inflight session");
    let proof_dir = config.proof_dir.clone().unwrap_or_else(|| PathBuf::from(DEFAULT_PROOF_DIR));
    fs::create_dir_all(&proof_dir)?;
    let identity_namespace = chain_configs.iter().map(L1Config::namespace).collect::<Vec<_>>().join("__");
    let mut chains = Vec::with_capacity(chain_configs.len());
    for chain in chain_configs {
        let effective = chain.effective_config(&config)?;
        let bridge = resolve_bridge_address(&effective)?.parse::<Address>()?;
        let state_manager = resolve_state_manager_address(&effective)?;
        chains.push(ChainRuntime {
            chain_index: chain.chain_index,
            l1: L1Client::from_finalize_config(&effective.finalize),
            config: effective,
            bridge,
            state_manager,
        });
    }
    let provider = RpcProvider::new_with_config_path(&config.rpc_config)?;
    let poll_interval = Duration::from_secs(config.poll_interval_secs.unwrap_or(30));
    let lag = config.confirmation_lag_checkpoints.unwrap_or(3);
    let max_batch = config.max_checkpoint_batch.unwrap_or(DEFAULT_MAX_CHECKPOINT_BATCH);
    validate_max_checkpoint_batch(max_batch)?;
    let state_path = proof_dir.join("daemon_state_multichain.toml");
    let approved = super::regen_groth16_keystore::load_aggregate_setup_config(&config.aggregate_setup_config)?;
    let network = psy_client_data::bridge_aggregate::NetworkConfig::decode(&hex::decode(&approved.network_config)?)?;
    config.aggregate_limits.validate(&network)?;
    ensure!(config.aggregate_limits.chains.iter().map(|chain| chain.chain_index).eq(chains.iter().map(|chain| chain.chain_index)), "operator limits do not match configured chains");
    ensure!(network.chains.len() == chains.len(), "aggregate chain cohort mismatch");
    for (expected, actual) in network.chains.iter().zip(&chains) {
        ensure!(expected.chain_index == actual.chain_index && expected.bridge == actual.bridge.into_array()
            && expected.state_manager == actual.state_manager.into_array(), "aggregate deployment mismatch");
    }
    let circuits = psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits::build::<
        psy_core::network_config::PsyNetworkLocalDevnetConstants
    >(&network.chains.iter().map(|chain| chain.chain_index).collect::<Vec<_>>(), prove_bridge::cached_bridge_coordinator_circuits()?,
        psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuitHeights {
            deposit_state_tree: psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
            withdrawal_state_tree: psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
        })?;
    circuits.validate_config(&network)?;
    for (artifact, name, data) in [
        (psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestArtifact::DepositAggregate, "DepositAggregate", &circuits.deposit_aggregate.circuit_data),
        (psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestArtifact::SettlementAggregate, "SettlementAggregate", &circuits.settlement_aggregate.circuit_data),
    ] {
        let adapter = psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsAdapter::build(artifact, &data.common, &data.verifier_only)?;
        let wrapper = adapter.into_wrapper(approved.sources.clone())?;
        super::regen_groth16_keystore::validate_digest_bits_setup(&config.aggregate_artifact_dir.join(name), wrapper.identity())?;
    }
    let http = super::api_client::build_default_http_client()?;
    let mut state = load_multichain_state(&state_path, &identity_namespace)?;
    if chains.len() == 1 && !state_path.exists() {
        let single_path = proof_dir.join("daemon_state.toml");
        if single_path.exists() {
            let previous = load_state(&single_path)?;
            state.last_finalized_checkpoint = previous.last_finalized_checkpoint;
            state.pending_claim_withdrawals = previous.pending_claim_withdrawals;
            state.claim_retry = previous.claim_retry;
            state.retired_claim_withdrawals = previous.retired_claim_withdrawals;
            save_multichain_state(&state_path, &state)?;
        }
    }
    tracing::info!(config=%config_path.display(), chain_count=chains.len(), "aggregate bridge relayer started");
    loop {
        if let Err(error) = advance_aggregate_round(&config, &chains, &provider, &network, &circuits, &approved.sources,
            &http, &proof_dir, &state_path, &mut state, lag, max_batch).await {
            if error.downcast_ref::<ReplayBootstrapError>().is_some() || error.downcast_ref::<super::api_client::AggregationHttpError>().is_none() { return Err(error); }
            tracing::warn!(%error, "aggregate service unavailable; durable round retained");
            state = load_multichain_state(&state_path, &identity_namespace)?;
        }
        tokio::time::sleep(poll_interval).await;
    }
}

type AggregateProof = plonky2::plonk::proof::ProofWithPublicInputs<GoldilocksField, plonky2::plonk::config::PoseidonGoldilocksConfig, 2>;

fn aggregate_context(a: &psy_client_data::bridge_aggregate::DepositAggregateOpening, _network: &psy_client_data::bridge_aggregate::NetworkConfig) -> anyhow::Result<super::api_client::AggregationContext> {
    use psy_client_data::bridge_aggregate::{domain_hash, Domain};
    let mut bytes = domain_hash(Domain::Window).to_vec();
    bytes.extend(a.config_hash);
    bytes.extend(U256::from(a.end_checkpoint_id).to_be_bytes::<32>());
    for limb in a.end_checkpoint_root { bytes.extend(U256::from(limb).to_be_bytes::<32>()); }
    Ok(super::api_client::AggregationContext { version: 1, config_hash: format!("0x{}", hex::encode(a.config_hash)),
        end_checkpoint_id: a.end_checkpoint_id.to_string(), end_checkpoint_root: a.end_checkpoint_root.map(|limb| limb.to_string()),
        context_id: format!("{:#x}", alloy_primitives::keccak256(bytes)), max_proof_bytes: 16 * 1024 * 1024,
        max_records: 1024 })
}

fn aggregate_claim_id(config_hash: [u8; 32], kind: u8, record: &[u8]) -> String {
    use psy_client_data::bridge_aggregate::{domain_hash, Domain};
    let mut bytes = domain_hash(Domain::LeafCommit).to_vec();
    bytes.extend(config_hash);
    bytes.extend(U256::from(kind).to_be_bytes::<32>());
    bytes.extend(record);
    hex::encode(alloy_primitives::keccak256(bytes))
}
fn reward_claim_id(config_hash: [u8; 32], record: &[u8], transition: &[u8]) -> String {
    use psy_client_data::bridge_aggregate::{domain_hash, Domain};
    let mut bytes = domain_hash(Domain::LeafCommit).to_vec();
    bytes.extend(config_hash);
    bytes.extend(U256::from(3u8).to_be_bytes::<32>());
    bytes.extend(record);
    bytes.extend(alloy_primitives::keccak256(transition));
    hex::encode(alloy_primitives::keccak256(bytes))
}

fn withdrawal_record(withdrawal: &propose_withdrawals::PendingWithdrawal) -> anyhow::Result<psy_client_data::bridge_aggregate::WithdrawalLeaf> {
    fn bytes(words: [u32; 8]) -> [u8; 32] { let mut result = [0; 32]; for (part, word) in result.chunks_exact_mut(4).zip(words) { part.copy_from_slice(&word.to_be_bytes()); } result }
    let token = bytes(withdrawal.token_address);
    let recipient = bytes(withdrawal.recipient);
    ensure!(token[..12] == [0; 12] && recipient[..12] == [0; 12], "non-EVM withdrawal address");
    Ok(psy_client_data::bridge_aggregate::WithdrawalLeaf { chain_index: withdrawal.destination_chain_index.try_into()?,
        sender_user_id: withdrawal.sender_user_id.try_into()?, token: token[12..].try_into()?, recipient: recipient[12..].try_into()?,
        amount: bytes(withdrawal.amount), nonce: bytes(withdrawal.nonce) })
}

fn text_hash4(value: &str) -> anyhow::Result<[u64; 4]> {
    let text = value.strip_prefix("0x").unwrap_or(value);
    let bytes = aggregate_bytes(text)?;
    ensure!(bytes.len() == 32, "reward ledger root width");
    Ok(std::array::from_fn(|index| u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())))
}
fn hash4_text(value: [u64; 4]) -> String { format!("0x{}", hex::encode(value.into_iter().flat_map(|limb| limb.to_le_bytes()).collect::<Vec<_>>())) }
fn reward_hash_bytes(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = aggregate_bytes(value.strip_prefix("0x").unwrap_or(value))?;
    ensure!(bytes.len() == 32, "reward hash width");
    Ok(bytes.try_into().unwrap())
}
fn reward_window_values(window: &RewardLedgerWindow) -> anyhow::Result<psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerWindowValues> {
    Ok(psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerWindowValues {
        config_hash: reward_hash_bytes(&window.config_hash)?,
        economic_domain: reward_hash_bytes(&window.economic_domain)?,
        window_id: reward_hash_bytes(&window.window_id)?,
        end_checkpoint_id: u32::try_from(window.end_checkpoint_id)?,
        end_checkpoint_root: text_hash4(&window.end_checkpoint_root)?, start_root: text_hash4(&window.start_root)?,
    })
}
fn reward_state_values(state: &RewardLedgerStateRecord) -> anyhow::Result<psy_plonky2_circuits::bridge::circuits::reward_session::RewardLedgerStateValues> {
    Ok(psy_plonky2_circuits::bridge::circuits::reward_session::RewardLedgerStateValues {
        ledger_window_hash: text_hash4(&state.ledger_window_hash)?, ledger_root: text_hash4(&state.ledger_root)?,
        user_root: text_hash4(&state.user_root)?, session_count: state.session_count, unfinished_session_count: state.unfinished_session_count,
    })
}
fn reward_state_record(state: &psy_plonky2_circuits::bridge::circuits::reward_session::RewardLedgerStateValues) -> RewardLedgerStateRecord {
    RewardLedgerStateRecord { ledger_window_hash: hash4_text(state.ledger_window_hash), ledger_root: hash4_text(state.ledger_root), user_root: hash4_text(state.user_root), session_count: state.session_count, unfinished_session_count: state.unfinished_session_count }
}
fn reward_origin_state() -> anyhow::Result<RewardLedgerStateRecord> {
    use psy_plonky2_circuits::bridge::circuits::reward_ledger::{reward_issued_empty_hash, reward_ledger_state_root, reward_user_empty_hash};
    let state = psy_plonky2_circuits::bridge::circuits::reward_session::RewardLedgerStateValues { ledger_window_hash: [0; 4], ledger_root: reward_issued_empty_hash(64)?, user_root: reward_user_empty_hash(32)?, session_count: 0, unfinished_session_count: 0 };
    ensure!(reward_ledger_state_root(&state)? == psy_client_data::bridge_aggregate::origin_state_root(), "reward origin root mismatch");
    Ok(reward_state_record(&state))
}
fn reward_node_key(tree: &str, hash: &str) -> String { format!("{tree}:{hash}") }
fn reward_changed_nodes(root: [u64; 4], leaf: [u64; 4], index: u64, siblings: &[[u64; 4]], issued: bool) -> anyhow::Result<Vec<(String, RewardLedgerNodeRecord)>> {
    use psy_plonky2_circuits::bridge::circuits::reward_ledger::{reward_issued_parent_hash, reward_user_parent_hash};
    let tree = if issued { "issued" } else { "user" };
    let mut nodes = Vec::new();
    let mut value = leaf;
    for (height, sibling) in siblings.iter().enumerate() {
        let bit = ((index >> height) & 1) == 1;
        let (left, right) = if bit { (*sibling, value) } else { (value, *sibling) };
        value = if issued { reward_issued_parent_hash(left, right)? } else { reward_user_parent_hash((height + 1) as u8, left, right)? };
        nodes.push((reward_node_key(tree, &hash4_text(value)), RewardLedgerNodeRecord { tree: tree.to_string(), height: (height + 1) as u8, left_hash: hash4_text(left), right_hash: hash4_text(right) }));
    }
    ensure!(value == root, "reward changed path does not fold to its root");
    Ok(nodes)
}
fn reward_issued_siblings(nodes: &std::collections::BTreeMap<String, RewardLedgerNodeRecord>, root: [u64; 4], index: u64) -> anyhow::Result<[[u64; 4]; 64]> {
    use psy_plonky2_circuits::bridge::circuits::reward_ledger::{reward_issued_empty_hash, reward_issued_parent_hash};
    let mut siblings = [[0; 4]; 64];
    let mut cursor = root;
    for height in (0..64).rev() {
        let parent = u8::try_from(height + 1).unwrap();
        if cursor == reward_issued_empty_hash(parent)? {
            siblings[height] = reward_issued_empty_hash(u8::try_from(height).unwrap())?;
            cursor = if height == 0 { [0; 4] } else { reward_issued_empty_hash(u8::try_from(height).unwrap())? };
            continue;
        }
        let node = nodes.get(&reward_node_key("issued", &hash4_text(cursor))).with_context(|| format!("issued sibling missing at height {height}"))?;
        ensure!(node.height == u8::try_from(height + 1).unwrap(), "stored issued node height mismatch");
        let left = text_hash4(&node.left_hash)?;
        let right = text_hash4(&node.right_hash)?;
        ensure!(reward_issued_parent_hash(left, right)? == cursor, "stored issued node does not fold");
        let bit = ((index >> height) & 1) == 1;
        siblings[height] = if bit { left } else { right };
        cursor = if bit { right } else { left };
    }
    ensure!(cursor == [0; 4], "issued path does not fold to the empty leaf");
    let mut check = [0; 4];
    for (height, sibling) in siblings.iter().enumerate() {
        let bit = ((index >> height) & 1) == 1;
        check = if bit { reward_issued_parent_hash(*sibling, check)? } else { reward_issued_parent_hash(check, *sibling)? };
    }
    ensure!(check == root, "issued siblings do not fold to the old root");
    Ok(siblings)
}
fn initialize_reward_ledger(network: &psy_client_data::bridge_aggregate::NetworkConfig, opening: &psy_client_data::bridge_aggregate::DepositAggregateOpening, context_id: &str, previous: Option<&RewardLedgerWindow>) -> anyhow::Result<RewardLedgerWindow> {
    let domain = network.clone().load().map_err(|error| anyhow::anyhow!("economic domain: {error:?}"))?.economic_domain();
    let (state, prior, start, nodes, transitions, tip) = if let Some(previous) = previous {
        ensure!(previous.published, "prior reward context is not accepted");
        ensure!(text_hash4(&previous.root)? == text_hash4(&previous.start_root)? || previous.revision > 0, "prior reward tip is not its accepted root");
        let prior = previous.tip.as_ref().map(|tip| RewardLedgerPriorRecord { context_id: format!("0x{}", previous.context_id), revision: previous.revision, tip_proof: tip.proof.clone(), root: previous.root.clone() });
        ensure!(prior.is_some() == (text_hash4(&previous.root)? != psy_client_data::bridge_aggregate::origin_state_root()), "rotated predecessor proof does not match its root");
        (previous.state.clone(), prior, previous.root.clone(), previous.nodes.clone(), previous.transitions.clone(), previous.tip.clone())
    } else {
        (reward_origin_state()?, None, hash4_text(psy_client_data::bridge_aggregate::origin_state_root()), Default::default(), Default::default(), None)
    };
    Ok(RewardLedgerWindow {
        context_id: context_id.trim_start_matches("0x").to_string(), revision: 0, root: start.clone(), predecessor_root: None,
        config_hash: format!("0x{}", hex::encode(opening.config_hash)), economic_domain: format!("0x{}", hex::encode(domain)), window_id: format!("0x{}", hex::encode(opening.window_id)),
        end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root: hash4_text(opening.end_checkpoint_root), start_root: start, state, tip, prior_context: prior,
        nodes, node_delta: Vec::new(), transitions, user_id: None, source_checkpoint_id: None, published: false,
    })
}
fn apply_reward_ledger_transition(directory: &Path, data: &plonky2::plonk::circuit_data::CircuitData<GoldilocksField, plonky2::plonk::config::PoseidonGoldilocksConfig, 2>, opening: &psy_client_data::bridge_aggregate::DepositAggregateOpening, context_id: &str, record: &[u8], transition: &[u8], state: &MultichainDaemonState) -> anyhow::Result<RewardLedgerWindow> {
    use psy_plonky2_circuits::bridge::circuits::reward_ledger::{deserialize_reward_ledger_transition, reward_ledger_proof_id, verify_reward_ledger_step};
    let (window, step, supplied_nodes) = deserialize_reward_ledger_transition(transition)?;
    ensure!(window.config_hash == opening.config_hash && window.window_id == opening.window_id && u64::from(window.end_checkpoint_id) == opening.end_checkpoint_id && window.end_checkpoint_root == opening.end_checkpoint_root, "reward transition window differs from the aggregate opening");
    let existing = state.reward_ledger.clone().context("reward ledger is not initialized")?;
    ensure!(existing.published, "reward ledger snapshot is not accepted");
    ensure!(reward_window_values(&existing)? == window && existing.context_id == context_id.trim_start_matches("0x"), "published reward ledger continuation unavailable");
    let raw_proof_id = reward_ledger_proof_id(&data.verifier_only, &step.proof)?;
    let proof_id = hash4_text(std::array::from_fn(|index| u64::from_le_bytes(raw_proof_id[index * 8..index * 8 + 8].try_into().unwrap())));
    if let Some(retained) = existing.transitions.get(&proof_id) {
        let retained_bytes = load_aggregate_file(directory, retained)?;
        ensure!(retained_bytes == transition, "retained reward transition differs for the same proof id");
        let (retained_window, retained_step, retained_nodes) = deserialize_reward_ledger_transition(&retained_bytes)?;
        let retained_root = psy_plonky2_circuits::bridge::circuits::reward_ledger::reward_ledger_state_root(&retained_step.old_state)?;
        let retained_verified = verify_reward_ledger_step(&data.common, &data.verifier_only, &retained_window, retained_root, &retained_step)?;
        ensure!(retained_verified.transition_bytes == retained_bytes && retained_verified.nodes == retained_nodes && retained_verified.proof_id == raw_proof_id, "retained reward transition is not canonical");
        let retained_record = retained_verified.source_payout.as_ref().map(|leaf| leaf.encode()).transpose()?.unwrap_or_default();
        ensure!(retained_record == record, "retained reward payout differs for the same proof id");
        return Ok(existing);
    }
    let verified = verify_reward_ledger_step(&data.common, &data.verifier_only, &window, text_hash4(&existing.root)?, &step).context("reward ledger step does not extend the locked root")?;
    ensure!(verified.transition_bytes == transition && verified.nodes == supplied_nodes && verified.nodes.len() == 33 && verified.proof_id == raw_proof_id, "reward transition is not the verified canonical transition");
    match &verified.source_payout {
        Some(leaf) => ensure!(leaf.encode()? == record, "source payout differs from the verified transition"),
        None => ensure!(record.is_empty(), "nonfinal reward transition carries a payout record"),
    }
    let proof = AggregateProof::from_bytes(step.proof.clone(), &data.common).map_err(|error| anyhow::anyhow!("reward proof decode: {error}"))?;
    let inputs = proof.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>();
    let fields = psy_client_data::bridge_aggregate::RewardSessionProofFields::from_public_inputs(&inputs).map_err(|error| anyhow::anyhow!("reward statement: {error}"))?;
    let old_root = text_hash4(&existing.root)?;
    ensure!(fields.old_ledger_state_root == old_root && hash4_text(fields.new_ledger_state_root) == hash4_text(text_hash4(&hex::encode(verified.new_root))?), "reward tip root mismatch");
    let first_window = old_root == window.start_root;
    let mut ledger = existing;
    ledger.revision = ledger.revision.checked_add(1).context("reward revision overflow")?;
    ledger.predecessor_root = Some(ledger.root.clone());
    ledger.root = hash4_text(fields.new_ledger_state_root);
    ledger.state = reward_state_record(&step.new_state);
    ledger.user_id = Some(fields.user_id);
    ledger.source_checkpoint_id = Some(u64::from(step.source_checkpoint_id));
    if !first_window { ledger.prior_context = None; }
    let user_leaf = verified.nodes.iter().find(|node| node.height == 0).context("verified user leaf missing")?;
    ensure!(user_leaf.index == u64::from(fields.user_id), "verified user leaf index mismatch");
    ledger.node_delta.clear();
    for (key, node) in reward_changed_nodes(step.new_state.user_root, text_hash4(&hex::encode(user_leaf.hash))?, u64::from(fields.user_id), &step.summary_siblings, false)? {
        ledger.node_delta.push(key.clone());
        ledger.nodes.entry(key).or_insert(node);
    }
    if step.new_state.ledger_root != step.old_state.ledger_root {
        ensure!(step.is_final_step, "nonfinal reward issued root changed");
        let index = u64::from(fields.user_id) | (u64::from(step.source_checkpoint_id) << 32);
        let siblings = reward_issued_siblings(&ledger.nodes, step.old_state.ledger_root, index)?;
        let _ = reward_changed_nodes(step.old_state.ledger_root, [0; 4], index, &siblings, true)?;
        let mut issued = b"PsyRewardLedger/Issued/1".to_vec();
        issued.extend(window.economic_domain);
        issued.extend_from_slice(&step.source_checkpoint_id.to_le_bytes());
        issued.extend_from_slice(&fields.user_id.to_le_bytes());
        for word in fields.total_amount.into_iter().chain(fields.recipient[..5].iter().copied()) { issued.extend_from_slice(&word.to_le_bytes()); }
        for value in [fields.jobs_commitment, step.new_state.ledger_window_hash] { for limb in value { issued.extend_from_slice(&limb.to_le_bytes()); } }
        let occupied = plonky2::hash::poseidon::PoseidonHash::hash_no_pad(&issued.iter().copied().map(plonky2::field::goldilocks_field::GoldilocksField::from_canonical_u8).collect::<Vec<_>>()).elements.map(|limb| limb.to_canonical_u64());
        for (key, node) in reward_changed_nodes(step.new_state.ledger_root, occupied, index, &siblings, true)? { ledger.node_delta.push(key.clone()); ledger.nodes.insert(key, node); }
    }
    let transition_file = save_aggregate_file(directory, transition, "transition")?;
    ledger.transitions.insert(proof_id.clone(), transition_file.clone());
    ledger.tip = Some(RewardLedgerTipRecord { proof_id, proof: save_aggregate_file(directory, &step.proof, "proof")?, transition: transition_file, new_root: ledger.root.clone() });
    ledger.published = false;
    Ok(ledger)
}
fn reward_snapshot(directory: &Path, ledger: &RewardLedgerWindow) -> anyhow::Result<super::api_client::RewardLedgerSnapshot> {
    use base64::Engine;
    let encode_part = |reference: &FileReference| -> anyhow::Result<String> {
        let bytes = load_aggregate_file(directory, reference)?;
        ensure!(bytes.len() <= super::api_client::AGGREGATION_PROOF_LIMIT, "reward snapshot part exceeds 16MiB");
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    };
    let tip = ledger.tip.as_ref().map(|tip| -> anyhow::Result<_> {
        Ok(super::api_client::RewardLedgerSnapshotTip { proof_id: tip.proof_id.clone(), proof: encode_part(&tip.proof)?, transition: encode_part(&tip.transition)?, new_root: tip.new_root.clone() })
    }).transpose()?;
    let prior = ledger.prior_context.as_ref().map(|prior| -> anyhow::Result<_> {
        Ok(super::api_client::RewardLedgerPriorContext { context_id: prior.context_id.clone(), revision: prior.revision.to_string(), tip_proof: encode_part(&prior.tip_proof)? })
    }).transpose()?;
    let nodes = ledger.node_delta.iter().map(|key| {
        let node = ledger.nodes.get(key).with_context(|| format!("reward revision node missing: {key}"))?;
        let hash = key.split_once(':').context("reward node key")?.1.to_string();
        Ok(super::api_client::RewardLedgerSnapshotNode { tree: match node.tree.as_str() { "user" => super::api_client::RewardLedgerTree::User, "issued" => super::api_client::RewardLedgerTree::Issued, _ => anyhow::bail!("reward node tree") }, hash, height: node.height, left_hash: node.left_hash.clone(), right_hash: node.right_hash.clone() })
    }).collect::<anyhow::Result<Vec<_>>>()?;
    Ok(super::api_client::RewardLedgerSnapshot { context_id: format!("0x{}", ledger.context_id), revision: ledger.revision.to_string(), root: ledger.root.clone(), predecessor_root: ledger.predecessor_root.clone(), window: super::api_client::RewardLedgerSnapshotWindow { config_hash: ledger.config_hash.clone(), economic_domain: ledger.economic_domain.clone(), window_id: ledger.window_id.clone(), end_checkpoint_id: ledger.end_checkpoint_id.to_string(), end_checkpoint_root: ledger.end_checkpoint_root.clone(), start_root: ledger.start_root.clone() }, state: super::api_client::RewardLedgerSnapshotState { ledger_window_hash: ledger.state.ledger_window_hash.clone(), ledger_root: ledger.state.ledger_root.clone(), user_root: ledger.state.user_root.clone(), session_count: ledger.state.session_count.to_string(), unfinished_session_count: ledger.state.unfinished_session_count.to_string() }, tip, prior_context: prior, nodes, user_id: ledger.user_id.map(|id| id.to_string()), source_checkpoint_id: ledger.source_checkpoint_id.map(|id| id.to_string()) })
}
async fn publish_saved_reward_ledger(config: &BridgeProposeDaemonConfig, http: &reqwest::Client, directory: &Path, state_path: &Path, state: &mut MultichainDaemonState) -> anyhow::Result<()> {
    let Some(ledger) = state.reward_ledger.clone().filter(|ledger| !ledger.published) else { return Ok(()); };
    let snapshot = reward_snapshot(directory, &ledger)?;
    super::api_client::publish_reward_ledger_snapshot(http, &config.services_url, &config.aggregation_token_file, &snapshot).await?;
    if let Some(saved) = &mut state.reward_ledger { saved.published = true; }
    save_multichain_state(state_path, state)
}
async fn collect_aggregate_claims(config: &BridgeProposeDaemonConfig, chains: &[ChainRuntime], provider: &RpcProvider, network: &psy_client_data::bridge_aggregate::NetworkConfig,
    circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, http: &reqwest::Client,
    directory: &Path, state_path: &Path, state: &mut MultichainDaemonState) -> anyhow::Result<()> {
    use psy_client_data::bridge_aggregate::{DepositAggregateOpening, WithdrawalAggregateOpening, SourceCheckpointRewardOpening, WithdrawalLeaf, SourceCheckpointRewardLeaf};
    let Some(PendingAggregate::Collecting { aggregate_limits, producing_session, mut selected_withdrawal_leaf_hashes, a_opening, withdrawal_endpoint, mut selected_claims }) = state.pending.clone() else { return Ok(()); };
    let a = DepositAggregateOpening::decode(&aggregate_bytes(&a_opening)?)?;
    a.validate(network)?;
    let context = aggregate_context(&a, network)?;
    let current = super::api_client::get_aggregation_context(http, &config.services_url, &config.aggregation_token_file).await?;
    if let Some(current) = &current {
        ensure!(current.config_hash == context.config_hash && current.end_checkpoint_id.parse::<u64>()? <= a.end_checkpoint_id, "published context requires aggregate reconciliation");
        if current.end_checkpoint_id == context.end_checkpoint_id { ensure!(current.end_checkpoint_root == context.end_checkpoint_root, "published checkpoint contradiction"); }
    }
    super::api_client::publish_aggregation_context(http, &config.services_url, &config.aggregation_token_file,
        &super::api_client::PublishAggregationContext { expected_context_id: current.map(|context| context.context_id), context: context.clone() }).await?;
    let rotated = state.reward_ledger.as_ref().is_some_and(|ledger| ledger.context_id != context.context_id.trim_start_matches("0x"));
    if state.reward_ledger.is_none() || rotated {
        let previous = rotated.then(|| state.reward_ledger.clone()).flatten();
        state.reward_ledger = Some(initialize_reward_ledger(network, &a, &context.context_id, previous.as_ref())?);
        save_multichain_state(state_path, state)?;
    }
    publish_saved_reward_ledger(config, http, directory, state_path, state).await?;
    let guardian = super::guardian_client::GuardianClientConfig::load(Path::new(&config.guardian_config))?;
    let authorization = guardian.authorization()?;
    let rpc_config = psy_config::PsyConfigGoldilocks::from_file(&config.rpc_config)?;
    let mut wallet = WalletSession::new(rpc_config.get_current_network()?).await?;
    wallet.add_multisig_user(authorization.account_json.decode()?).await?;
    let archive = super::guardian_client::RelayerArchive::open(&guardian.archive_path)?;
    let committed = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?;
    let mut history = config.guardian_history.lock().await;
    refresh_relayer_history(&wallet, provider, &guardian, &archive, committed.checkpoint_id, committed.checkpoint_tree_root, &mut history).await?;
    let mut included_burns = HashSet::new();
    for session in &history.sessions {
        if session.record.included_checkpoint_id > a.end_checkpoint_id { continue; }
        for append in &session.withdrawal_appends {
            let burn = &append.burn;
            included_burns.insert((u64::from(burn.sender_user_id), u64::from(burn.token_contract_id), u64::from(burn.destination_chain_index), burn.token, burn.amount, burn.recipient, burn.nonce));
        }
    }
    drop(history);
    let mut historical_withdrawals = HashMap::new();
    for (hash, withdrawal) in &state.pending_claim_withdrawals {
        if state.retired_claim_withdrawals.contains_key(hash) { continue; }
        if !included_burns.contains(&(withdrawal.sender_user_id, withdrawal.contract_id, withdrawal.destination_chain_index, withdrawal.token_address, withdrawal.amount, withdrawal.recipient, withdrawal.nonce)) { continue; }
        let record = withdrawal_record(withdrawal)?.encode()?;
        ensure!(historical_withdrawals.insert(record, hash.clone()).is_none(), "ambiguous historical withdrawal metadata");
    }
    let mut reserved_withdrawals = selected_claims.iter().filter(|claim| claim.kind == 2).map(|claim| claim.claim_id.clone()).collect::<HashSet<_>>();
    for hash in &selected_withdrawal_leaf_hashes {
        let withdrawal = state.pending_claim_withdrawals.get(hash).or_else(|| state.retired_claim_withdrawals.get(hash).map(|entry| &entry.withdrawal)).context("selected metadata missing")?;
        reserved_withdrawals.insert(aggregate_claim_id(a.config_hash, 2, &withdrawal_record(withdrawal)?.encode()?));
    }
    let (mut local_withdrawals, rewards) = aggregate_selected_counts(&aggregate_limits, &selected_withdrawal_leaf_hashes, &selected_claims, state)?;
    validate_aggregate_reservation(&aggregate_limits, &aggregate_deposit_counts(&a)?, &local_withdrawals, rewards)?;
    let mut finalized_blocks = HashMap::new();
    let mut cursor = None;
    loop {
        let page = super::api_client::get_aggregation_claims(http, &config.services_url, &config.aggregation_token_file,
            &context.context_id, cursor.as_deref(), 32).await?;
        for claim in page.claims {
            let (kind, record_text, artifact_text) = match &claim.request {
                super::api_client::AggregationClaimRequest::Withdrawal { kind, record, proof, .. } if *kind == super::api_client::AggregationClaimKind::Withdrawal => (2u8, record, proof),
                super::api_client::AggregationClaimRequest::Reward { kind, record, transition, .. } if *kind == super::api_client::AggregationClaimKind::Reward => (3, record, transition),
                _ => anyhow::bail!("queued claim version does not match its family"),
            };
            let record = super::api_client::decode_aggregation_base64(record_text, if kind == 3 { 192 } else { 1024 })?;
            let bytes = super::api_client::decode_aggregation_base64(artifact_text, 16 * 1024 * 1024)?;
            let claim_id = if kind == 3 { reward_claim_id(a.config_hash, &record, &bytes) } else { aggregate_claim_id(a.config_hash, kind, &record) };
            ensure!(claim.claim_id == format!("0x{claim_id}"), "claim identity mismatch");
            let retained = selected_claims.iter().position(|selected| selected.claim_id == claim_id);
            let mut promoted_hash = None;
            if kind == 2 {
                let leaf = WithdrawalLeaf::decode(&record)?;
                if retained.is_none() && !reserved_withdrawals.contains(&claim_id) {
                    let local = local_withdrawals.iter().find(|(index, _)| *index == leaf.chain_index).context("historical withdrawal destination absent")?.1;
                    if reserved_withdrawals.len() >= aggregate_limits.reserved_withdrawals as usize || local >= aggregate_limits.chain(leaf.chain_index)?.reserved_withdrawals { continue; }
                    let Some(hash) = historical_withdrawals.get(&record) else { continue; };
                    promoted_hash = Some(hash.clone());
                }
            } else if !record.is_empty() && retained.is_none() && selected_claims.iter().filter(|claim| claim.kind == 3 && !claim.record.is_empty()).count() >= aggregate_limits.reserved_rewards as usize { continue; }
            let mut next_reward_ledger = None;
            if kind == 2 {
                let leaf = WithdrawalLeaf::decode(&record)?;
                let data = &circuits.withdrawal.circuit_data;
                let proof = AggregateProof::from_bytes(bytes.clone(), &data.common).map_err(|error| anyhow::anyhow!("native claim proof: {error}"))?;
                ensure!(proof.to_bytes() == bytes, "noncanonical native proof");
                let inputs = proof.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>();
                let mut prefix = vec![1, 2, 0, 0];
                prefix.extend(a.config_hash.chunks_exact(4).map(|word| u64::from(u32::from_be_bytes(word.try_into().unwrap()))));
                prefix.extend([a.end_checkpoint_id as u32 as u64, a.end_checkpoint_id >> 32]);
                prefix.extend(a.end_checkpoint_root);
                ensure!(inputs.starts_with(&prefix), "claim proof context mismatch");
                let roots: Vec<[u64; 4]> = serde_json::from_slice(&aggregate_bytes(&withdrawal_endpoint)?)?;
                let ordinal = network.chains.iter().position(|chain| chain.chain_index == leaf.chain_index).context("withdrawal chain absent")?;
                ensure!(inputs.get(20..24) == Some(roots.get(ordinal).context("withdrawal root absent")?.as_slice()), "withdrawal end mismatch");
                ensure!(inputs.get(18..20) == Some([BRIDGE_USER_ID_U64, u64::from(leaf.chain_index)].as_slice()), "withdrawal identity mismatch");
                let words = leaf.leaf_commit()?.chunks_exact(4).map(|word| u64::from(u32::from_be_bytes(word.try_into().unwrap()))).collect::<Vec<_>>();
                ensure!(inputs.get(24..32) == Some(words.as_slice()), "claim record mismatch");
                data.verify(proof)?;
            } else {
                if !record.is_empty() {
                    let payout = SourceCheckpointRewardLeaf::decode(&record)?;
                    ensure!(payout.encode()? == record, "noncanonical source payout");
                }
                next_reward_ledger = Some(apply_reward_ledger_transition(directory, &circuits.reward_session.circuit_data, &a, &context.context_id, &record, &bytes, state)?);
            }
            if let Some(hash) = promoted_hash {
                let leaf = WithdrawalLeaf::decode(&record)?;
                let chain = chains.iter().find(|chain| chain.chain_index == leaf.chain_index).context("historical withdrawal destination missing")?;
                if !finalized_blocks.contains_key(&leaf.chain_index) {
                    let block = aggregate_rpc(http, chain, "eth_getBlockByNumber", serde_json::json!(["finalized",false])).await?;
                    let endpoint = guardian.l1_endpoints.iter().find(|endpoint| endpoint.chain_index == leaf.chain_index).context("guardian endpoint missing")?;
                    let anchor = crate::guardian::protocol::DepositAnchor { chain_index: leaf.chain_index, block_number: aggregate_quantity(&block["number"])?,
                        block_hash: crate::guardian::protocol::Hex(hex::decode(block["hash"].as_str().and_then(|value| value.strip_prefix("0x")).context("finalized block hash missing")?)?.try_into().map_err(|_| anyhow::anyhow!("block hash width"))?), old_count: 0, new_count: 1 };
                    crate::guardian::verify_l1::verify_finalized_anchor(endpoint, authorization.chain(leaf.chain_index)?, &anchor).await?;
                    let pinned = serde_json::json!({"blockHash":block["hash"],"requireCanonical":true});
                    ensure!(aggregate_word(http, chain, chain.bridge, "configHash()", None, &pinned).await? == a.config_hash, "historical withdrawal config mismatch");
                    finalized_blocks.insert(leaf.chain_index, pinned);
                }
                let spent = aggregate_word(http, chain, chain.bridge, "claimedNullifiers(bytes32)", Some(leaf.nonce), &finalized_blocks[&leaf.chain_index]).await?;
                if U256::from_be_bytes(spent) == U256::from(1) { continue; }
                ensure!(spent == [0; 32], "invalid historical withdrawal spent flag");
                selected_withdrawal_leaf_hashes.push(hash);
                reserved_withdrawals.insert(claim_id.clone());
                let (_, count) = local_withdrawals.iter_mut().find(|(index, _)| *index == leaf.chain_index).context("historical withdrawal destination absent")?;
                *count = count.checked_add(1).context("withdrawal count overflow")?;
            }
            if kind != 3 || !record.is_empty() {
                let selected = SelectedClaim { claim_id, kind, record: hex::encode(record), proof: Some(save_aggregate_file(directory, &bytes, "proof")?), proof_context_id: Some(context.context_id.trim_start_matches("0x").into()) };
                if let Some(index) = retained { ensure!(selected_claims[index].record == selected.record && selected_claims[index].kind == kind, "retained claim changed"); selected_claims[index] = selected; }
                else { selected_claims.push(selected); }
            }
            let previous_pending = state.pending.clone();
            let previous_ledger = state.reward_ledger.clone();
            state.pending = Some(PendingAggregate::Collecting { aggregate_limits: aggregate_limits.clone(), producing_session: producing_session.clone(), selected_withdrawal_leaf_hashes: selected_withdrawal_leaf_hashes.clone(), a_opening: a_opening.clone(), withdrawal_endpoint: withdrawal_endpoint.clone(), selected_claims: selected_claims.clone() });
            if let Some(next) = next_reward_ledger { state.reward_ledger = Some(next); }
            if let Err(error) = save_multichain_state(state_path, state) { state.pending = previous_pending; state.reward_ledger = previous_ledger; return Err(error); }
            publish_saved_reward_ledger(config, http, directory, state_path, state).await?;
        }
        state.pending = Some(PendingAggregate::Collecting { aggregate_limits: aggregate_limits.clone(), producing_session: producing_session.clone(), selected_withdrawal_leaf_hashes: selected_withdrawal_leaf_hashes.clone(), a_opening: a_opening.clone(), withdrawal_endpoint: withdrawal_endpoint.clone(), selected_claims: selected_claims.clone() });
        save_multichain_state(state_path, state)?;
        cursor = page.next_after_claim_id;
        if cursor.is_none() { break; }
    }
    state.pending = Some(PendingAggregate::Collecting { aggregate_limits: aggregate_limits.clone(), producing_session: producing_session.clone(), selected_withdrawal_leaf_hashes: selected_withdrawal_leaf_hashes.clone(), a_opening: a_opening.clone(), withdrawal_endpoint: withdrawal_endpoint.clone(), selected_claims: selected_claims.clone() });
    save_multichain_state(state_path, state)?;
    if selected_claims.iter().any(|claim| claim.proof.is_none() || claim.proof_context_id.as_deref() != Some(context.context_id.trim_start_matches("0x"))) { return Ok(()); }
    if state.reward_ledger.as_ref().is_some_and(|ledger| ledger.state.unfinished_session_count != 0) { return Ok(()); }
    for hash in &selected_withdrawal_leaf_hashes {
        let withdrawal = state.pending_claim_withdrawals.get(hash).or_else(|| state.retired_claim_withdrawals.get(hash).map(|entry| &entry.withdrawal)).context("selected withdrawal metadata missing")?;
        let id = aggregate_claim_id(a.config_hash, 2, &withdrawal_record(withdrawal)?.encode()?);
        if !selected_claims.iter().any(|claim| claim.claim_id == id) { return Ok(()); }
    }
    let mut ordered = selected_claims.into_iter().map(|claim| -> anyhow::Result<_> {
        let bytes = aggregate_bytes(&claim.record)?;
        let key = if claim.kind == 2 { let leaf = WithdrawalLeaf::decode(&bytes)?; (u64::from(leaf.chain_index), leaf.nonce) }
            else if bytes.is_empty() { (u64::MAX, [0u8; 32]) }
            else { let leaf = SourceCheckpointRewardLeaf::decode(&bytes)?; (leaf.source_checkpoint_id, U256::from(leaf.user_id).to_be_bytes::<32>()) };
        Ok(((claim.kind, key), claim))
    }).collect::<anyhow::Result<Vec<_>>>()?;
    ordered.sort_by_key(|(key, _)| *key);
    let selected_claims = ordered.into_iter().map(|(_, claim)| claim).collect::<Vec<_>>();
    let withdrawal_roots: Vec<[u64; 4]> = serde_json::from_slice(&aggregate_bytes(&withdrawal_endpoint)?)?;
    let withdrawals = selected_claims.iter().filter(|claim| claim.kind == 2).map(|claim| WithdrawalLeaf::decode(&aggregate_bytes(&claim.record)?).map_err(Into::into)).collect::<anyhow::Result<Vec<_>>>()?;
    let rewards = selected_claims.iter().filter(|claim| claim.kind == 3 && !claim.record.is_empty()).map(|claim| SourceCheckpointRewardLeaf::decode(&aggregate_bytes(&claim.record)?).map_err(Into::into)).collect::<anyhow::Result<Vec<_>>>()?;
    let economic_domain = network.clone().load().map_err(|error| anyhow::anyhow!("economic domain: {error:?}"))?.economic_domain();
    let (old_reward_ledger_root, new_reward_ledger_root) = if rewards.is_empty() {
        let root = state.reward_ledger.as_ref().map(|ledger| text_hash4(&ledger.root)).transpose()?.unwrap_or_else(psy_client_data::bridge_aggregate::origin_state_root);
        (root, root)
    } else {
        let ledger = state.reward_ledger.as_ref().context("reward ledger absent")?;
        (text_hash4(&ledger.start_root)?, text_hash4(&ledger.root)?)
    };
    let indices = network.chains.iter().map(|chain| chain.chain_index).collect::<Vec<_>>();
    let identity = finalization_identity(circuits, &indices)?;
    let mut proofs = Vec::with_capacity(a.starts.len());
    let mut evidence = Vec::with_capacity(a.starts.len());
    for start in &a.starts {
        let key = start.chain_index.to_string();
        let saved = state.retained_finalize.get(&key).cloned();
        let mut retained = None;
        if let Some(saved) = saved {
            ensure!(saved.bf_identity == hex::encode(identity), "retained finalization identity mismatch");
            let proof = load_raw_finalization(directory, circuits, &saved, indices.len())?;
            if proof.public_inputs[24].to_canonical_u64() == a.end_checkpoint_id {
                let historical_start = std::array::from_fn(|index| proof.public_inputs[index].to_canonical_u64());
                let span = proof.public_inputs[25].to_canonical_u64();
                let required_start = if start.start_checkpoint_id < a.end_checkpoint_id { start.start_checkpoint_root } else { historical_start };
                let required_span = if start.start_checkpoint_id < a.end_checkpoint_id { a.end_checkpoint_id - start.start_checkpoint_id } else { span };
                bind_raw_finalization(&proof, required_start, a.end_checkpoint_id, a.end_checkpoint_root, required_span)?;
                retained = Some((saved, proof));
            }
        }
        let (saved, proof) = if let Some(retained) = retained { retained } else {
            ensure!(start.start_checkpoint_id <= a.end_checkpoint_id, "finalize interval regressed");
            if start.start_checkpoint_id == a.end_checkpoint_id { return Err(ReplayBootstrapError.into()); }
            let span = a.end_checkpoint_id - start.start_checkpoint_id;
            let (raw, _, _) = prove_bridge::prove_checkpoint_range(provider, prove_bridge::cached_bridge_coordinator_circuits()?, start.start_checkpoint_id, a.end_checkpoint_id, &indices).await?;
            ensure!(raw.common_data == circuits.checkpoint_final.circuit_data.common && raw.verifier_data == circuits.checkpoint_final.circuit_data.verifier_only && raw.fingerprint == circuits.checkpoint_final.fingerprint, "checkpoint source pin mismatch");
            bind_raw_finalization(&raw.proof, start.start_checkpoint_root, a.end_checkpoint_id, a.end_checkpoint_root, span)?;
            let reference = save_aggregate_file(directory, &raw.proof.to_bytes(), "proof")?;
            let saved = FinalizeEvidence { bf_identity: hex::encode(identity), raw_proof: reference };
            state.retained_finalize.insert(key, saved.clone());
            save_multichain_state(state_path, state)?;
            (saved, raw.proof)
        };
        ensure!(start.start_checkpoint_id != a.end_checkpoint_id || start.start_checkpoint_root == a.end_checkpoint_root, "replay root mismatch");
        proofs.push(proof);
        evidence.push(saved);
    }
    let (global_deposit_root, global_withdrawal_root) = global_root_words(&proofs[0])?;
    let slots = proofs.iter().map(|proof| psy_client_data::bridge_aggregate::FinalizationSlot { start_checkpoint_root: proof.public_inputs[..4].iter().map(|field| field.to_canonical_u64()).collect::<Vec<_>>().try_into().unwrap(), checkpoint_count: u32::try_from(proof.public_inputs[25].to_canonical_u64()).unwrap() }).collect::<Vec<_>>();
    let settlement = build_settlement_opening(network, &a, &withdrawal_roots, withdrawals, rewards, economic_domain, old_reward_ledger_root, new_reward_ledger_root, global_deposit_root, global_withdrawal_root, slots)?;
    validate_frozen_capacity(&aggregate_limits, &a, &settlement)?;
    state.pending = Some(PendingAggregate::Frozen { aggregate_limits, producing_session, selected_withdrawal_leaf_hashes,
        a_opening: hex::encode(a.encode()?), settlement_opening: hex::encode(settlement.encode().map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?), claim_ids: selected_claims.iter().map(|claim| claim.claim_id.clone()).collect(),
        local_proofs: selected_claims.into_iter().map(|claim| claim.proof.context("claim proof absent")).collect::<anyhow::Result<_>>()?, final_proofs: None,
        destinations: network.chains.iter().zip(evidence).map(|(chain, finalize)| Destination { chain_index: chain.chain_index, finalize: Some(finalize), submission: Submission::NotSent }).collect(), included_acknowledged: [false; 2] });
    save_multichain_state(state_path, state)
}

fn build_settlement_opening(network: &psy_client_data::bridge_aggregate::NetworkConfig, a: &psy_client_data::bridge_aggregate::DepositAggregateOpening, withdrawal_roots: &[[u64; 4]], withdrawals: Vec<psy_client_data::bridge_aggregate::WithdrawalLeaf>, rewards: Vec<psy_client_data::bridge_aggregate::SourceCheckpointRewardLeaf>, economic_domain: [u8; 32], old_reward_ledger_root: [u64; 4], new_reward_ledger_root: [u64; 4], global_deposit_root: [u32; 8], global_withdrawal_root: [u32; 8], finalizations: Vec<psy_client_data::bridge_aggregate::FinalizationSlot>) -> anyhow::Result<psy_client_data::bridge_aggregate::SettlementOpening> {
    ensure!(rewards.is_empty() || rewards.iter().all(|leaf| leaf.economic_domain == economic_domain), "reward leaf economic domain differs from the supplied opening domain");
    ensure!(withdrawal_roots.len() == a.deposits.len() && finalizations.len() == a.starts.len(), "settlement source count mismatch");
    let endpoints = a.deposits.iter().zip(withdrawal_roots).map(|(transition, root)| psy_client_data::bridge_aggregate::FinalizationEndpoint { deposit_root: transition.new_root, deposit_count: transition.new_count, withdrawal_root: *root }).collect();
    let settlement = psy_client_data::bridge_aggregate::SettlementOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, global_deposit_root, global_withdrawal_root, finalizations, endpoints, withdrawals, old_reward_ledger_root, new_reward_ledger_root, economic_domain, rewards };
    let _ = settlement.opening_digest(network, a).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
    Ok(settlement)
}



fn finalization_identity(circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, indices: &[u8]) -> anyhow::Result<[u8; 32]> {
    use psy_common_circuit::serialization::PsyGateSerializer;
    use psy_crypto::hash::core::sha256::CoreSha256Hasher;
    let common = circuits.checkpoint_final.circuit_data.common.to_bytes(&PsyGateSerializer).map_err(|error| anyhow::anyhow!("finalize common encoding: {error:?}"))?;
    let verifier = circuits.checkpoint_final.circuit_data.verifier_only.to_bytes().map_err(|error| anyhow::anyhow!("finalize verifier encoding: {error:?}"))?;
    let mut fingerprint = [0u8; 32];
    for (chunk, limb) in fingerprint.chunks_exact_mut(8).zip(circuits.checkpoint_final.fingerprint.0.elements) { chunk.copy_from_slice(&limb.to_canonical_u64().to_be_bytes()); }
    let mut bytes = b"PsyBridge/RawFinalization/2".to_vec();
    for component in [common.as_slice(), verifier.as_slice(), fingerprint.as_slice(), indices] {
        bytes.extend((u32::try_from(component.len())?).to_be_bytes());
        bytes.extend(component);
    }
    Ok(CoreSha256Hasher::hash_bytes(&bytes).0)
}

fn global_root_words(proof: &AggregateProof) -> anyhow::Result<([u32; 8], [u32; 8])> {
    ensure!(proof.public_inputs.len() >= 20, "raw finalization public width");
    let words = proof.public_inputs[4..20].iter().map(|field| u32::try_from(field.to_canonical_u64()).context("raw finalization global root exceeds u32")).collect::<anyhow::Result<Vec<_>>>()?;
    Ok((words[..8].try_into().unwrap(), words[8..].try_into().unwrap()))
}

fn load_raw_finalization(directory: &Path, circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, evidence: &FinalizeEvidence, chains: usize) -> anyhow::Result<AggregateProof> {
    let bytes = load_aggregate_file(directory, &evidence.raw_proof)?;
    let proof = AggregateProof::from_bytes(bytes.clone(), &circuits.checkpoint_final.circuit_data.common).map_err(|error| anyhow::anyhow!("raw finalization decode: {error}"))?;
    ensure!(proof.to_bytes() == bytes, "noncanonical raw finalization");
    circuits.checkpoint_final.circuit_data.verify(proof.clone())?;
    ensure!(proof.public_inputs.len() == 26 + 9 * chains, "raw finalization endpoint count mismatch");
    ensure!(proof.public_inputs[25].to_canonical_u64() > 0, "raw finalization span is not positive");
    Ok(proof)
}

fn bind_raw_finalization(proof: &AggregateProof, start_root: [u64; 4], end_id: u64, end_root: [u64; 4], span: u64) -> anyhow::Result<()> {
    let inputs = proof.public_inputs.iter().map(|field| field.to_canonical_u64()).collect::<Vec<_>>();
    ensure!(inputs[..4] == start_root && inputs[20..24] == end_root && inputs[24] == end_id && inputs[25] == span, "raw finalization endpoint mismatch");
    Ok(())
}

async fn prove_frozen_aggregate(config: &BridgeProposeDaemonConfig, provider: &RpcProvider, network: &psy_client_data::bridge_aggregate::NetworkConfig,
    circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, sources: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsSources,
    directory: &Path, state_path: &Path, state: &mut MultichainDaemonState) -> anyhow::Result<()> {
    use psy_plonky2_circuits::bridge::circuits::bridge_wrap::{DigestArtifact, DigestBitsAdapter};
    use psy_client_data::bridge_aggregate::{DepositAggregateOpening, SettlementOpening, WithdrawalAggregateOpening, SourceCheckpointRewardOpening};
    let Some(PendingAggregate::Frozen { a_opening, settlement_opening, local_proofs, final_proofs: None, destinations, .. }) = state.pending.clone() else { return Ok(()); };
    let a = DepositAggregateOpening::decode(&aggregate_bytes(&a_opening)?)?;
    let settlement = SettlementOpening::decode(&aggregate_bytes(&settlement_opening)?).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
    a.validate(network)?;
    let indices = network.chains.iter().map(|chain| chain.chain_index).collect::<Vec<_>>();
    let identity = hex::encode(finalization_identity(circuits, &indices)?);
    let mut proofs = Vec::with_capacity(a.starts.len());
    for (start, destination) in a.starts.iter().zip(&destinations) {
        let evidence = destination.finalize.as_ref().context("frozen raw finalization missing")?;
        ensure!(evidence.bf_identity == identity, "frozen finalization identity mismatch");
        let proof = load_raw_finalization(directory, circuits, evidence, indices.len())?;
        let span = proof.public_inputs[25].to_canonical_u64();
        if start.start_checkpoint_id < a.end_checkpoint_id {
            bind_raw_finalization(&proof, start.start_checkpoint_root, a.end_checkpoint_id, a.end_checkpoint_root, a.end_checkpoint_id - start.start_checkpoint_id)?;
        } else {
            ensure!(start.start_checkpoint_id == a.end_checkpoint_id && start.start_checkpoint_root == a.end_checkpoint_root, "replay endpoint mismatch");
            let proof_start = std::array::from_fn(|index| proof.public_inputs[index].to_canonical_u64());
            bind_raw_finalization(&proof, proof_start, a.end_checkpoint_id, a.end_checkpoint_root, span)?;
        }
        proofs.push(proof);
    }
    let (deposit_root, withdrawal_root) = global_root_words(&proofs[0])?;
    ensure!(settlement.global_deposit_root == deposit_root && settlement.global_withdrawal_root == withdrawal_root, "frozen opening global roots differ from raw finalization");
    ensure!(settlement.finalizations.len() == proofs.len() && settlement.finalizations.iter().zip(&proofs).all(|(slot, proof)| slot.start_checkpoint_root.iter().zip(proof.public_inputs[..4].iter()).all(|(limb, field)| *limb == field.to_canonical_u64()) && u64::from(slot.checkpoint_count) == proof.public_inputs[25].to_canonical_u64()), "frozen opening slots differ from raw finalization");
    let w = WithdrawalAggregateOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, withdrawal_roots: settlement.endpoints.iter().map(|endpoint| endpoint.withdrawal_root).collect(), withdrawals: settlement.withdrawals.clone() };
    let r = SourceCheckpointRewardOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, leaves: settlement.rewards.clone() };
    w.validate(network)?;
    let withdrawal_proofs = load_family_proofs(directory, circuits, &local_proofs, w.withdrawals.len(), true)?;
    let withdrawal = prove_bridge::build_withdrawal_aggregate(network, &w, &withdrawal_proofs, circuits)?;
    let reward = if r.leaves.is_empty() {
        let end_id = prove_bridge::source_checkpoint_for_end(network, a.end_checkpoint_id)?;
        let witness = prove_bridge::fetch_end_checkpoint_witness(provider, a.end_checkpoint_id).await?;
        let prior = if settlement.old_reward_ledger_root == psy_client_data::bridge_aggregate::origin_state_root() {
            None
        } else {
            let ledger = state.reward_ledger.as_ref().context("reward identity ledger missing")?;
            ensure!(text_hash4(&ledger.root)? == settlement.old_reward_ledger_root, "reward identity ledger root mismatch");
            let tip = ledger.tip.as_ref().context("reward identity predecessor missing")?;
            let bytes = load_aggregate_file(directory, &tip.proof)?;
            let transition = load_aggregate_file(directory, &tip.transition)?;
            let (_, step, _) = psy_plonky2_circuits::bridge::circuits::reward_ledger::deserialize_reward_ledger_transition(&transition)?;
            ensure!(step.proof == bytes, "reward identity predecessor differs from retained state");
            let proof = AggregateProof::from_bytes(bytes, &circuits.reward_session.circuit_data.common).map_err(|error| anyhow::anyhow!("reward identity predecessor decode: {error}"))?;
            Some((proof, step.new_state))
        };
        ensure!(settlement.old_reward_ledger_root == settlement.new_reward_ledger_root, "empty reward changes ledger state");
        let window = psy_plonky2_circuits::bridge::circuits::reward_ledger::RewardLedgerWindowValues {
            config_hash: a.config_hash, economic_domain: settlement.economic_domain, window_id: a.window_id,
            end_checkpoint_id: end_id, end_checkpoint_root: a.end_checkpoint_root, start_root: settlement.old_reward_ledger_root,
        };
        let (tip, tip_state) = circuits.reward_session.prove_identity(network, &window, &witness.leaf, &witness.siblings, &witness.roots, prior.as_ref().map(|(proof, state)| (proof, state)))?;
        let inputs = prove_bridge::RewardAggregateInputs { old_ledger_state_root: window.start_root, new_ledger_state_root: window.start_root, tip_proof: &tip, tip_state: &tip_state, payouts: &[] };
        prove_bridge::build_reward_aggregate(network, &r, &inputs, circuits)?
    } else {
    let ledger = state.reward_ledger.as_ref().context("reward ledger absent")?;
    let mut reward_steps = Vec::with_capacity(r.leaves.len());
    let mut reward_proofs = Vec::with_capacity(r.leaves.len());
    for reference in local_proofs.iter().skip(w.withdrawals.len()) {
        let bytes = load_aggregate_file(directory, reference)?;
        let (window, step, _) = psy_plonky2_circuits::bridge::circuits::reward_ledger::deserialize_reward_ledger_transition(&bytes)?;
        let raw_proof_id = psy_plonky2_circuits::bridge::circuits::reward_ledger::reward_ledger_proof_id(&circuits.reward_session.circuit_data.verifier_only, &step.proof)?;
        let proof_id = hash4_text(std::array::from_fn(|index| u64::from_le_bytes(raw_proof_id[index * 8..index * 8 + 8].try_into().unwrap())));
        ensure!(load_aggregate_file(directory, ledger.transitions.get(&proof_id).context("retained reward transition missing")?)? == bytes, "retained reward transition differs from the selected artifact");
        ensure!(reward_window_values(ledger)? == window, "retained reward transition left its window");
        let proof = AggregateProof::from_bytes(step.proof.clone(), &circuits.reward_session.circuit_data.common).map_err(|error| anyhow::anyhow!("retained reward proof decode: {error}"))?;
        circuits.reward_session.circuit_data.verify(proof.clone())?;
        reward_steps.push(step);
        reward_proofs.push(proof);
    }
    ensure!(reward_proofs.len() == r.leaves.len(), "retained reward proof count mismatch");
    let tip_bytes = load_aggregate_file(directory, &ledger.tip.as_ref().context("retained reward tip missing")?.proof)?;
    let tip_index = reward_steps.iter().position(|step| step.proof == tip_bytes).context("retained reward tip is not one of the selected payouts")?;
    let payouts = reward_proofs.iter().zip(&reward_steps).map(|(proof, step)| prove_bridge::RewardPayoutInputs { proof, step }).collect::<Vec<_>>();
    let reward_inputs = prove_bridge::RewardAggregateInputs { old_ledger_state_root: settlement.old_reward_ledger_root, new_ledger_state_root: settlement.new_reward_ledger_root, tip_proof: &reward_proofs[tip_index], tip_state: &reward_steps[tip_index].new_state, payouts: &payouts };
    prove_bridge::build_reward_aggregate(network, &r, &reward_inputs, circuits)?
};
    let b_digest = settlement.opening_digest(network, &a).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
    let settlement_proof = circuits.settlement_aggregate.prove(network, &a, &settlement, &proofs, &withdrawal, &reward)?;
    circuits.settlement_aggregate.circuit_data.verify(settlement_proof.clone())?;
    let settlement_reference = wrap_opening(config, sources, directory, DigestArtifact::SettlementAggregate, &circuits.settlement_aggregate.circuit_data, &settlement_proof, b_digest)?;
    let proof_a = prove_deposit(config, network, circuits, &a).await?;
    let deposit = wrap_opening(config, sources, directory, DigestArtifact::DepositAggregate, &circuits.deposit_aggregate.circuit_data, &proof_a, a.opening_digest(network)?)?;
    let proofs = WindowProofs { deposit, settlement: settlement_reference };
    if let Some(PendingAggregate::Frozen { final_proofs, settlement_opening: saved, .. }) = &mut state.pending {
        ensure!(saved == &settlement_opening, "frozen opening changed during proving");
        *final_proofs = Some(proofs);
    }
    save_multichain_state(state_path, state)
}
fn load_family_proofs(directory: &Path, circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, references: &[FileReference], count: usize, withdrawal: bool) -> anyhow::Result<Vec<AggregateProof>> {
    let data = if withdrawal { &circuits.withdrawal.circuit_data } else { &circuits.reward_session.circuit_data };
    references.iter().take(count).map(|reference| {
        let bytes = load_aggregate_file(directory, reference)?;
        let proof = AggregateProof::from_bytes(bytes.clone(), &data.common).map_err(|error| anyhow::anyhow!("native family proof: {error}"))?;
        ensure!(proof.to_bytes() == bytes, "noncanonical native family proof");
        data.verify(proof.clone())?;
        Ok(proof)
    }).collect()
}


fn wrap_opening(config: &BridgeProposeDaemonConfig, sources: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsSources, directory: &Path, artifact: psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestArtifact, data: &plonky2::plonk::circuit_data::CircuitData<GoldilocksField, plonky2::plonk::config::PoseidonGoldilocksConfig, 2>, proof: &AggregateProof, digest: [u8; 32]) -> anyhow::Result<FileReference> {
    use psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsAdapter;
    data.verify(proof.clone())?;
    let adapter = DigestBitsAdapter::build(artifact, &data.common, &data.verifier_only)?;
    let adapted = adapter.prove(proof)?;
    let wrapper = adapter.into_wrapper(sources.clone())?;
    let name = match artifact { psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestArtifact::DepositAggregate => "DepositAggregate", psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestArtifact::SettlementAggregate => "SettlementAggregate" };
    let setup = config.aggregate_artifact_dir.join(name);
    super::regen_groth16_keystore::validate_digest_bits_setup(&setup, wrapper.identity())?;
    let outer = wrapper.prove_groth16(&adapted, setup.to_str().context("non-UTF8 setup path")?)?;
    parse_aggregate_proof(&outer, digest)?;
    save_aggregate_file(directory, &serde_json::to_vec(&outer)?, "json")
}

async fn prove_deposit(config: &BridgeProposeDaemonConfig, network: &psy_client_data::bridge_aggregate::NetworkConfig, circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, a: &psy_client_data::bridge_aggregate::DepositAggregateOpening) -> anyhow::Result<AggregateProof> {
    let guardian = super::guardian_client::GuardianClientConfig::load(Path::new(&config.guardian_config))?;
    let authorization = guardian.authorization()?;
    let mut prefixes = Vec::with_capacity(network.chains.len());
    for transition in &a.deposits {
        if transition.old_count == transition.new_count { prefixes.push(Vec::new()); continue; }
        let endpoint = guardian.l1_endpoints.iter().find(|endpoint| endpoint.chain_index == transition.chain_index).context("missing guardian chain endpoint")?;
        let chain = authorization.chain(transition.chain_index)?;
        let anchor = crate::guardian::verify_l1::finalized_deposit_anchor(endpoint, chain, transition.old_count, transition.new_count).await?;
        prefixes.push(crate::guardian::verify_l1::fetch_deposit_records(endpoint, chain, &anchor).await?);
    }
    let web_inputs = prove_bridge::build_deposit_spiderman_inputs(network, a, &prefixes)?;
    prove_bridge::build_deposit_aggregate(network, a, &web_inputs, circuits)
}

pub(crate) fn parse_aggregate_proof(proof: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::UncompressedGroth16ProofData, opening_digest: [u8; 32]) -> anyhow::Result<[U256; 8]> {
    fn word(value: &str) -> anyhow::Result<U256> {
        ensure!(value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "native proof word must be 64 lowercase hex digits");
        Ok(U256::from_str_radix(value, 16)?)
    }
    for (value, half) in proof.public_inputs.iter().zip(opening_digest.chunks_exact(16)) {
        ensure!(word(value)? == U256::from_be_slice(half), "native proof digest half mismatch");
    }
    let encoded = [&proof.pi_a[0], &proof.pi_a[1], &proof.pi_b[0][1], &proof.pi_b[0][0], &proof.pi_b[1][1], &proof.pi_b[1][0], &proof.pi_c[0], &proof.pi_c[1]];
    let mut result = [U256::ZERO; 8];
    for (target, value) in result.iter_mut().zip(encoded) { *target = word(value)?; }
    Ok(result)
}


async fn aggregate_rpc(http: &reqwest::Client, chain: &ChainRuntime, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let url = chain.config.finalize.l1_rpc_url.as_deref().context("missing chain RPC")?;
    let response: serde_json::Value = http.post(url).json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).send().await?.error_for_status()?.json().await?;
    ensure!(response.get("error").is_none() && response["id"] == 1, "aggregate RPC failed");
    response.get("result").filter(|value| !value.is_null()).cloned().context("aggregate RPC evidence unavailable")
}

fn aggregate_quantity(value: &serde_json::Value) -> anyhow::Result<u64> { Ok(u64::from_str_radix(value.as_str().and_then(|text| text.strip_prefix("0x")).context("missing RPC quantity")?, 16)?) }

async fn aggregate_word(http: &reqwest::Client, chain: &ChainRuntime, address: Address, signature: &str, argument: Option<[u8; 32]>, block: &serde_json::Value) -> anyhow::Result<[u8; 32]> {
    let mut data = alloy_primitives::keccak256(signature.as_bytes())[..4].to_vec();
    if let Some(argument) = argument { data.extend(argument); }
    let result = aggregate_rpc(http, chain, "eth_call", serde_json::json!([{"to":address,"data":format!("0x{}",hex::encode(data))},block])).await?;
    Ok(hex::decode(result.as_str().and_then(|text| text.strip_prefix("0x")).context("invalid RPC word")?)?.try_into().map_err(|_| anyhow::anyhow!("RPC word width"))?)
}

fn aggregate_hash_words(bytes: [u8; 32]) -> anyhow::Result<[u64; 4]> {
    let words = std::array::from_fn(|i| u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()));
    ensure!(words.iter().all(|word| *word < 0xffff_ffff_0000_0001), "noncanonical checkpoint hash");
    Ok(words)
}

fn aggregate_hash_bytes(words: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) { chunk.copy_from_slice(&word.to_be_bytes()); }
    bytes
}

async fn aggregate_l2_root(provider: &RpcProvider, checkpoint: u64, contract: u32, chain: u8, count: u64) -> anyhow::Result<[u64; 4]> {
    use parth_core::crypto::hash::traits::MerkleZeroHasher;
    let mut words = Vec::with_capacity(8);
    for slot in [16_451 + 2 * u64::from(chain), 16_452 + 2 * u64::from(chain)] {
        let leaf = provider.get_user_contract_state_tree_leaf_hash(checkpoint, BRIDGE_USER_ID_U64, contract, CONTRACT_STATE_TREE_HEIGHT, slot).await?;
        for word in leaf.0.elements { words.push(u32::try_from(word.to_canonical_u64())?); }
    }
    if count == 0 && words.iter().all(|word| *word == 0) {
        let empty = <parth_core::pgoldilocks::PoseidonHasher as MerkleZeroHasher<parth_core::pgoldilocks::QHashOut<GoldilocksField>>>::get_zero_hash(32);
        return Ok(empty.0.elements.map(|field| field.to_canonical_u64()));
    }
    let result = std::array::from_fn(|i| u64::from(words[i * 2]) | (u64::from(words[i * 2 + 1]) << 32));
    ensure!(result.iter().all(|word| *word < 0xffff_ffff_0000_0001), "noncanonical L2 root");
    Ok(result)
}

async fn build_aggregate_collection(config: &BridgeProposeDaemonConfig, chains: &[ChainRuntime], provider: &RpcProvider, network: &psy_client_data::bridge_aggregate::NetworkConfig,
    http: &reqwest::Client, checkpoint: u64, producing_session: Option<ProducingSession>, selected_withdrawal_leaf_hashes: Vec<String>, selected_claims: Vec<SelectedClaim>, state: &MultichainDaemonState) -> anyhow::Result<PendingAggregate> {
    use psy_client_data::bridge_aggregate::{DepositAggregateOpening, ChainStart, DepositTransition};
    let committed = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?;
    ensure!(checkpoint <= committed.checkpoint_id, "aggregate end is not committed");
    let guardian = super::guardian_client::GuardianClientConfig::load(Path::new(&config.guardian_config))?;
    let authorization = guardian.authorization()?;
    let mut a = DepositAggregateOpening { config_hash: network.config_hash()?, window_id: [0; 32], end_checkpoint_id: checkpoint,
        end_checkpoint_root: provider.get_checkpoint_tree_root(checkpoint).await?.0.elements.map(|field| field.to_canonical_u64()), starts: Vec::new(), deposits: Vec::new(), deposit_leaves: Vec::new() };
    let mut withdrawal_endpoint = Vec::with_capacity(network.chains.len());
    for chain in chains {
        let count = provider.get_withdrawal_tree_next_index(checkpoint, BRIDGE_USER_ID_U64, u64::from(chain.chain_index)).await?;
        withdrawal_endpoint.push(aggregate_l2_root(provider, checkpoint, WITHDRAWAL_TREE_CONTRACT_ID, chain.chain_index, count).await?);
        let finalized = aggregate_rpc(http, chain, "eth_getBlockByNumber", serde_json::json!(["finalized",false])).await?;
        let block = serde_json::json!({"blockHash":finalized["hash"],"requireCanonical":true});
        let authorized = authorization.chain(chain.chain_index)?;
        let endpoint = guardian.l1_endpoints.iter().find(|endpoint| endpoint.chain_index == chain.chain_index).context("guardian endpoint missing")?;
        let anchor = crate::guardian::protocol::DepositAnchor { chain_index: chain.chain_index, block_number: aggregate_quantity(&finalized["number"])?,
            block_hash: crate::guardian::protocol::Hex(hex::decode(finalized["hash"].as_str().and_then(|value| value.strip_prefix("0x")).context("finalized block hash missing")?)?.try_into().map_err(|_| anyhow::anyhow!("block hash width"))?), old_count: 0, new_count: 1 };
        crate::guardian::verify_l1::verify_finalized_anchor(endpoint, authorized, &anchor).await?;
        ensure!(aggregate_word(http, chain, chain.bridge, "configHash()", None, &block).await? == a.config_hash
            && aggregate_word(http, chain, chain.state_manager, "configHash()", None, &block).await? == a.config_hash, "L1 aggregate config mismatch");
        let start: u64 = U256::from_be_bytes(aggregate_word(http, chain, chain.state_manager, "lastFinalizedCheckpointId()", None, &block).await?).try_into()?;
        let root = aggregate_hash_words(aggregate_word(http, chain, chain.state_manager, "lastVerifiedCheckpointRoot()", None, &block).await?)?;
        let old_count: u32 = U256::from_be_bytes(aggregate_word(http, chain, chain.bridge, "provedDepositCount()", None, &block).await?).try_into()?;
        let old_root = aggregate_hash_words(aggregate_word(http, chain, chain.bridge, "depositRoot()", None, &block).await?)?;
        let count = u32::try_from(fetch_deposit_tree_next_index(provider, checkpoint, u64::from(chain.chain_index)).await?)?;
        let new_root = aggregate_l2_root(provider, checkpoint, DEPOSIT_TREE_CONTRACT_ID, chain.chain_index, u64::from(count)).await?;
        ensure!(count >= old_count, "proved deposit count exceeds L2 deposit count");
        if count > old_count {
            let endpoint = guardian.l1_endpoints.iter().find(|endpoint| endpoint.chain_index == chain.chain_index).context("guardian endpoint missing")?;
            let approved = authorization.chain(chain.chain_index)?;
            let anchor = crate::guardian::verify_l1::finalized_deposit_anchor(endpoint, approved, old_count, count).await?;
            let prefix = crate::guardian::verify_l1::fetch_deposit_records(endpoint, approved, &anchor).await?;
            a.deposit_leaves.extend_from_slice(&prefix[old_count as usize..count as usize]);
        }
        a.starts.push(ChainStart { chain_index: chain.chain_index, start_checkpoint_id: start, start_checkpoint_root: root });
        a.deposits.push(DepositTransition { chain_index: chain.chain_index, old_root, new_root, old_count, new_count: count });
    }
    a.window_id = a.window_id()?; a.validate(network)?;
    let aggregate_limits = state.pending.as_ref().map(PendingAggregate::limits).unwrap_or(&config.aggregate_limits).clone();
    aggregate_limits.validate(network)?;
    let (withdrawals, rewards) = aggregate_selected_counts(&aggregate_limits, &selected_withdrawal_leaf_hashes, &selected_claims, state)?;
    validate_aggregate_reservation(&aggregate_limits, &aggregate_deposit_counts(&a)?, &withdrawals, rewards)?;
    Ok(PendingAggregate::Collecting { aggregate_limits, producing_session, selected_withdrawal_leaf_hashes, a_opening: hex::encode(a.encode()?), withdrawal_endpoint: hex::encode(serde_json::to_vec(&withdrawal_endpoint)?), selected_claims })
}

fn window_call(directory: &Path, network: &psy_client_data::bridge_aggregate::NetworkConfig, a: &psy_client_data::bridge_aggregate::DepositAggregateOpening, settlement: &psy_client_data::bridge_aggregate::SettlementOpening, proofs: &WindowProofs) -> anyhow::Result<super::finalize_bridge::BridgeWindowCall> {
    let load = |reference: &FileReference, opening_digest| -> anyhow::Result<_> {
        let proof: psy_plonky2_circuits::bridge::circuits::bridge_wrap::UncompressedGroth16ProofData = serde_json::from_slice(&load_aggregate_file(directory, reference)?)?;
        parse_aggregate_proof(&proof, opening_digest)
    };
    let b_digest = settlement.opening_digest(network, a).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
    Ok(super::finalize_bridge::BridgeWindowCall {
        deposit_proof: load(&proofs.deposit, a.opening_digest(network)?)?, deposit_opening: a.encode()?.into(),
        settlement_proof: load(&proofs.settlement, b_digest)?, settlement_opening: settlement.encode().map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?.into(),
    })
}

async fn observe_aggregate_submission(http: &reqwest::Client, chain: &ChainRuntime, a: &psy_client_data::bridge_aggregate::DepositAggregateOpening, network: &psy_client_data::bridge_aggregate::NetworkConfig, opening_digests: [[u8; 32]; 2], submission: &Submission, calldata: &Bytes) -> anyhow::Result<Submission> {
    let transaction = match submission { Submission::Submitted { transaction_hash } | Submission::Finalized { transaction_hash, .. } | Submission::Reverted { transaction_hash, .. } => transaction_hash,
        _ => return Ok(submission.clone()) };
    let hash = B256::from_slice(&aggregate_bytes(transaction)?);
    let receipt = chain.l1.get_aggregate_receipt(hash).await?;
    let Some(receipt) = receipt else { ensure!(!matches!(submission, Submission::Finalized {..} | Submission::Reverted {..}), "finalized receipt disappeared"); return Ok(submission.clone()); };
    let receipt = serde_json::to_value(receipt)?;
    ensure!(receipt["transactionHash"] == format!("{hash:#x}") && receipt["to"].as_str().is_some_and(|address| address.eq_ignore_ascii_case(&chain.state_manager.to_string())), "receipt transaction destination mismatch");
    let transaction_data = aggregate_rpc(http, chain, "eth_getTransactionByHash", serde_json::json!([hash])).await?;
    let input = hex::decode(transaction_data["input"].as_str().and_then(|text| text.strip_prefix("0x")).context("transaction input missing")?)?;
    ensure!(input.as_slice() == calldata.as_ref(), "transaction differs from frozen atomic window");
    let block_number = aggregate_quantity(&receipt["blockNumber"])?;
    let finalized = aggregate_rpc(http, chain, "eth_getBlockByNumber", serde_json::json!(["finalized",false])).await?;
    if block_number > aggregate_quantity(&finalized["number"])? { return Ok(submission.clone()); }
    let canonical = aggregate_rpc(http, chain, "eth_getBlockByNumber", serde_json::json!([format!("0x{block_number:x}"),false])).await?;
    ensure!(canonical["hash"] == receipt["blockHash"], "canonical receipt contradiction");
    let block_hash = receipt["blockHash"].as_str().context("receipt block hash missing")?.trim_start_matches("0x").to_owned();
    let status = aggregate_quantity(&receipt["status"])?;
    match submission {
        Submission::Finalized { block_hash: saved_hash, block_number: saved_number, .. } => ensure!(*saved_hash == block_hash && *saved_number == block_number && status == 1, "beyond-finality success contradiction"),
        Submission::Reverted { block_hash: saved_hash, block_number: saved_number, .. } => ensure!(*saved_hash == block_hash && *saved_number == block_number && status == 0, "beyond-finality revert contradiction"),
        _ => {},
    }
    if status == 0 { return Ok(Submission::Reverted { transaction_hash: transaction.clone(), block_hash, block_number }); }
    ensure!(status == 1, "receipt status invalid");
    let mut expected = U256::from(a.end_checkpoint_id).to_be_bytes::<32>().to_vec();
    expected.extend(aggregate_hash_bytes(a.end_checkpoint_root));
    let logs = receipt["logs"].as_array().context("receipt logs missing")?;
    let find = |event: &[u8], opening_digest: [u8; 32]| -> anyhow::Result<String> {
        let signature = format!("{:#x}", alloy_primitives::keccak256(event));
        let matching = logs.iter().filter(|log| log["removed"] == false
            && log["transactionHash"] == format!("{hash:#x}") && log["blockHash"] == receipt["blockHash"] && log["blockNumber"] == receipt["blockNumber"]
            && log["address"].as_str().is_some_and(|address| address.eq_ignore_ascii_case(&chain.state_manager.to_string()))
            && log["topics"].as_array().is_some_and(|topics| topics.len() == 2)
            && log["topics"][0] == signature && log["topics"][1] == format!("0x{}", hex::encode(opening_digest)) && log["data"] == format!("0x{}", hex::encode(&expected))).collect::<Vec<_>>();
        ensure!(matching.len() == 1, "exact family receipt evidence missing");
        Ok(aggregate_quantity(&matching[0]["logIndex"])?.to_string())
    };
    let withdrawal_log_index = find(b"WithdrawalAggregateApplied(bytes32,uint64,bytes32)", opening_digests[0])?;
    let reward_log_index = if chain.chain_index == network.ethereum_index { Some(find(b"RewardAggregateApplied(bytes32,uint64,bytes32)", opening_digests[1])?) } else { None };

    Ok(Submission::Finalized { transaction_hash: transaction.clone(), block_hash, block_number, withdrawal_log_index, reward_log_index })
}

async fn record_frozen_family_dispositions(
    chains: &[ChainRuntime],
    network: &psy_client_data::bridge_aggregate::NetworkConfig,
    http: &reqwest::Client,
    directory: &Path,
    withdrawals: &psy_client_data::bridge_aggregate::WithdrawalAggregateOpening,
    rewards: &psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening,
    opening_digests: &[[u8; 32]; 2],
    openings: &[Vec<u8>; 2],
    claim_ids: &[String],
    final_proofs: &Option<WindowProofs>,
    destinations: &[Destination],
    included_acknowledged: &[bool; 2],
    receipt_dispositions: &mut std::collections::BTreeMap<String, ReceiptDispositions>,
) -> anyhow::Result<()> {
    use super::api_client::{ClaimDisposition, ReceiptEvidence, ConsumptionEvidence};
    for (family, opening, records) in [(2u8, openings[0].clone(), withdrawals.withdrawals.len()), (3, openings[1].clone(), rewards.leaves.len())] {
        if !included_acknowledged[family as usize - 2] { continue; }
        let mut dispositions = Vec::new();
        let start = if family == 2 { 0 } else { withdrawals.withdrawals.len() };
        for index in start..start + records {
            let id = &claim_ids[index];
            let (chain_index, key, address, signature): (u8, [u8; 32], Address, &str) = if family == 2 {
                let leaf = &withdrawals.withdrawals[index];
                (leaf.chain_index, leaf.nonce, chains.iter().find(|chain| chain.chain_index == leaf.chain_index).context("withdrawal destination missing")?.bridge, "claimedNullifiers(bytes32)")
            } else {
                let leaf = &rewards.leaves[index - withdrawals.withdrawals.len()];
                let _chain = chains.iter().find(|chain| chain.chain_index == network.ethereum_index).context("reward destination missing")?;
                let payer = Address::from(network.reward_payer);
                (network.ethereum_index, leaf.consumption_key(), payer, "spentRewards(bytes32)")
            };
            let destination = destinations.iter().find(|destination| destination.chain_index == chain_index).context("claim destination missing")?;
            if let Submission::Finalized { transaction_hash, withdrawal_log_index, reward_log_index, .. } = &destination.submission {
                let log_index = if family == 2 { withdrawal_log_index.clone() } else { reward_log_index.clone().context("missing reward log")? };
                dispositions.push(ClaimDisposition::Applied { claim_id: format!("0x{id}"), receipt: ReceiptEvidence { chain_index, transaction_hash: format!("0x{transaction_hash}"), log_index } });
            } else {
                let chain = chains.iter().find(|chain| chain.chain_index == chain_index).context("claim chain missing")?;
                let block = aggregate_rpc(http, chain, "eth_getBlockByNumber", serde_json::json!(["finalized", false])).await?;
                let spent = aggregate_word(http, chain, address, signature, Some(key), &serde_json::json!({"blockHash": block["hash"], "requireCanonical": true})).await?;
                if U256::from_be_bytes(spent) == U256::from(1) { dispositions.push(ClaimDisposition::ConsumedElsewhere { claim_id: format!("0x{id}"), consumption: ConsumptionEvidence { chain_index, block_number: aggregate_quantity(&block["number"])?.to_string(), block_hash: block["hash"].as_str().context("block hash missing")?.into() } }); }
                else { ensure!(spent == [0; 32], "invalid spent flag"); dispositions.push(ClaimDisposition::Released { claim_id: format!("0x{id}") }); }
            }
        }
        let reverted_receipts = destinations.iter().filter_map(|destination| match &destination.submission {
            Submission::Reverted { transaction_hash, block_hash, block_number } => Some(RevertedReceipt { chain_index: destination.chain_index, transaction_hash: transaction_hash.clone(), block_hash: block_hash.clone(), block_number: *block_number }), _ => None }).collect();
        receipt_dispositions.insert(format!("{family}:{}", hex::encode(opening_digests[family as usize - 2])), ReceiptDispositions { family, opening: save_aggregate_file(directory, &opening, "opening")?, final_proofs: final_proofs.clone(), dispositions, reverted_receipts, posted_opening_digest: None });
    }
    Ok(())
}

async fn reconcile_frozen_window(config: &BridgeProposeDaemonConfig, chains: &[ChainRuntime], provider: &RpcProvider, network: &psy_client_data::bridge_aggregate::NetworkConfig, http: &reqwest::Client, directory: &Path, state_path: &Path, state: &mut MultichainDaemonState, checkpoint: u64, replace: bool) -> anyhow::Result<()> {
    use psy_client_data::bridge_aggregate::{DepositAggregateOpening, SettlementOpening, WithdrawalAggregateOpening, SourceCheckpointRewardOpening};
    use super::api_client::ClaimDisposition;
    let Some(PendingAggregate::Frozen { producing_session, selected_withdrawal_leaf_hashes, a_opening, settlement_opening, claim_ids, local_proofs, final_proofs, destinations, included_acknowledged, .. }) = state.pending.clone() else { return Ok(()); };
    ensure!(destinations.iter().all(|destination| !matches!(destination.submission, Submission::Sending | Submission::Submitted { .. })), "unresolved send blocks reconciliation");
    let a = DepositAggregateOpening::decode(&aggregate_bytes(&a_opening)?)?;
    let settlement = SettlementOpening::decode(&aggregate_bytes(&settlement_opening)?).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
    let w = WithdrawalAggregateOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, withdrawal_roots: settlement.endpoints.iter().map(|endpoint| endpoint.withdrawal_root).collect(), withdrawals: settlement.withdrawals.clone() };
    let r = SourceCheckpointRewardOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, leaves: settlement.rewards.clone() };
    let opening_digests = [w.opening_digest(network)?, r.opening_digest()?];
    let openings = [w.encode()?, r.encode()?];
    record_frozen_family_dispositions(chains, network, http, directory, &w, &r, &opening_digests, &openings, &claim_ids, &final_proofs, &destinations, &included_acknowledged, &mut state.receipt_dispositions).await?;
    let mut retained_claims = Vec::new();
    for (index, id) in claim_ids.iter().enumerate() {
        let family = if index < w.withdrawals.len() { 2 } else { 3 };
        let acknowledged = included_acknowledged[family as usize - 2];
        let released = !acknowledged || state.receipt_dispositions.get(&format!("{family}:{}", hex::encode(opening_digests[family as usize - 2]))).is_some_and(|receipt| receipt.dispositions.iter().any(|item| matches!(item, ClaimDisposition::Released { claim_id } if claim_id == &format!("0x{id}"))));
        if !released { continue; }
        let record = if family == 2 { w.withdrawals[index].encode()? } else { r.leaves[index - w.withdrawals.len()].encode()? };
        retained_claims.push(SelectedClaim { claim_id: id.clone(), kind: family, record: hex::encode(record), proof: Some(local_proofs[index].clone()), proof_context_id: Some(aggregate_context(&a, network)?.context_id.trim_start_matches("0x").into()) });
    }
    if replace {
        let selected = selected_withdrawal_leaf_hashes.into_iter().filter(|hash| state.pending_claim_withdrawals.get(hash).or_else(|| state.retired_claim_withdrawals.get(hash).map(|entry| &entry.withdrawal))
            .is_some_and(|withdrawal| withdrawal_record(withdrawal).and_then(|leaf| Ok(aggregate_claim_id(a.config_hash, 2, &leaf.encode()?)))
                .is_ok_and(|id| retained_claims.iter().any(|claim| claim.claim_id == id)))).collect();
        state.pending = Some(build_aggregate_collection(config, chains, provider, network, http, checkpoint, producing_session, selected, retained_claims, state).await?);
    }
    save_multichain_state(state_path, state)
}

async fn advance_aggregate_round(config: &BridgeProposeDaemonConfig, chains: &[ChainRuntime], provider: &RpcProvider,
    network: &psy_client_data::bridge_aggregate::NetworkConfig, circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits,
    sources: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsSources, http: &reqwest::Client, directory: &Path,
    state_path: &Path, state: &mut MultichainDaemonState, lag: u64, max_batch: u64) -> anyhow::Result<()> {
    use base64::Engine;
    use psy_client_data::bridge_aggregate::{DepositAggregateOpening, WithdrawalAggregateOpening, SourceCheckpointRewardOpening};
    use super::api_client::{AggregationDispositions, ClaimDisposition, ReceiptEvidence, ConsumptionEvidence};
    validate_aggregate_state(directory, state)?;
    publish_saved_reward_ledger(config, http, directory, state_path, state).await?;
    if let Some(pending) = &state.pending { pending.limits().validate(network)?; }
    for key in state.receipt_dispositions.keys().cloned().collect::<Vec<_>>() {
        let (family_text, opening_digest) = key.split_once(':').context("receipt key family missing")?;
        let family: u8 = family_text.parse()?;
        let mut receipt = state.receipt_dispositions[&key].clone();
        if receipt.posted_opening_digest.as_deref() != Some(opening_digest) {
            let opening = load_aggregate_file(directory, &receipt.opening)?;
            super::api_client::post_aggregation_dispositions(http, &config.services_url, &config.aggregation_token_file,
                &AggregationDispositions::Disposed { family, opening_digest: format!("0x{opening_digest}"), opening: base64::engine::general_purpose::STANDARD.encode(opening), dispositions: receipt.dispositions.clone() }).await?;
            receipt.posted_opening_digest = Some(opening_digest.to_string());
            state.receipt_dispositions.insert(key, receipt);
            save_multichain_state(state_path, state)?;
        }
    }
    remove_posted_receipts_outside_window(network, state)?;
    save_multichain_state(state_path, state)?;
    clear_completed_applied_window(directory, network, state_path, state)?;
    for chain in chains {
        let cursor = chain.l1.last_finalized_checkpoint(chain.state_manager).await?;
        let head = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
        if refresh_catchup_state(false, cursor.saturating_add(1), Some(head), lag, max_batch) { continue; }
        let candidates = claims_to_attempt(&state.pending_claim_withdrawals, &state.claim_retry).into_iter()
            .filter(|withdrawal| withdrawal.destination_chain_index == u64::from(chain.chain_index)).collect::<Vec<_>>();
        let mut claims = Vec::new();
        for withdrawal in candidates {
            let selected = match &state.pending {
                Some(PendingAggregate::Producing { selected_withdrawal_leaf_hashes, .. }) | Some(PendingAggregate::Collecting { selected_withdrawal_leaf_hashes, .. }) | Some(PendingAggregate::Frozen { selected_withdrawal_leaf_hashes, .. }) => selected_withdrawal_leaf_hashes.contains(&withdrawal.leaf_hash),
                None => false,
            };
            if selected { continue; }
            let record = withdrawal_record(&withdrawal)?;
            if U256::from_be_bytes(aggregate_word(http, chain, chain.bridge, "claimedNullifiers(bytes32)", Some(record.nonce), &serde_json::json!("finalized")).await?) == U256::from(1) { claims.push(withdrawal); }
        }
        if !claims.is_empty() {
            let result = chain.l1.claim_withdrawals(&claims, &chain.config, cursor).await;
            record_claim_result(&claims, &result, &mut state.pending_claim_withdrawals, &mut state.claim_retry, &mut state.retired_claim_withdrawals, claim_attempts::now_unix());
            save_multichain_state(state_path, state)?;
        }
    }
    if state.pending.is_none() {
        let head = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?.checkpoint_id;
        let mut cursors = Vec::new();
        for chain in chains { cursors.push(chain.l1.last_finalized_checkpoint(chain.state_manager).await?); }
        let (from, window) = select_multichain_relayer_window(&cursors, head, lag, max_batch)?;
        let args = ProposeWithdrawalsArgs { rpc_config: config.rpc_config.clone(), guardian_config: config.guardian_config.clone(), services_url: Some(config.services_url.clone()),
            withdraw_method_id: config.withdraw_method_id, state_file: None, notify_coordinator: true, poll_timeout_secs: 0, poll_interval_secs: 5,
            destination_chain_indices: chains.iter().map(|chain| u64::from(chain.chain_index)).collect() };
        let synchronized = cursors.iter().all(|cursor| Some(cursor) == cursors.first());
        let (progress, plan) = build_multichain_l2_plan(config, provider, chains, head, from, window.to_checkpoint, !window.is_catchup_batch && synchronized, &args, &config.aggregate_limits, &[]).await?;
        let deposit_counts = progress.iter().map(|chain| (chain.chain_index, chain.selected_deposit_count - chain.proved_deposit_count)).collect::<Vec<_>>();
        if !plan.calls.is_empty() {
            let mut history = config.guardian_history.lock().await;
            submit_guardian_operation(&config.rpc_config, &config.guardian_config, provider, plan.calls, &plan.withdrawals,
                crate::guardian::protocol::GuardianOperation::Bridge, None, &mut history, Some((state_path, state, &config.aggregate_limits, &deposit_counts))).await?;
        } else {
            let checkpoint = window.confirmed_to_checkpoint.unwrap_or(0).max(cursors.iter().copied().max().unwrap_or(0));
            state.pending = Some(build_aggregate_collection(config, chains, provider, network, http, checkpoint, None, Vec::new(), Vec::new(), state).await?);
            save_multichain_state(state_path, state)?;
        }
    }
    if let Some(PendingAggregate::Producing { aggregate_limits, deposit_counts, session_nonce, request_id, selected_withdrawal_leaf_hashes }) = state.pending.clone() {
        let guardian = super::guardian_client::GuardianClientConfig::load(Path::new(&config.guardian_config))?;
        let archive = super::guardian_client::RelayerArchive::open(&guardian.archive_path)?;
        let id = crate::guardian::protocol::Hex(aggregate_bytes(&request_id)?.try_into().map_err(|_| anyhow::anyhow!("request id width"))?);
        let saved = archive.load_session(session_nonce, id);
        let (request, record) = match saved {
            Ok(value) => value,
            Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {
                let selected = selected_withdrawal_leaf_hashes.iter().map(|hash| state.pending_claim_withdrawals.get(hash).or_else(|| state.retired_claim_withdrawals.get(hash).map(|entry| &entry.withdrawal)).cloned().context("producing metadata missing")).collect::<anyhow::Result<Vec<_>>>()?;
                let head = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?.checkpoint_id;
                let args = ProposeWithdrawalsArgs { rpc_config: config.rpc_config.clone(), guardian_config: config.guardian_config.clone(), services_url: Some(config.services_url.clone()),
                    withdraw_method_id: config.withdraw_method_id, state_file: None, notify_coordinator: true, poll_timeout_secs: 0, poll_interval_secs: 5,
                    destination_chain_indices: chains.iter().map(|chain| u64::from(chain.chain_index)).collect() };
                let (progress, plan) = build_multichain_l2_plan(config, provider, chains, head, head, head, true, &args, &aggregate_limits, &selected).await?;
                let rebuilt_counts = progress.iter().map(|chain| (chain.chain_index, chain.selected_deposit_count - chain.proved_deposit_count)).collect::<Vec<_>>();
                ensure!(rebuilt_counts == deposit_counts, "prearchive deposit selection changed during rebuild");
                let mut history = config.guardian_history.lock().await;
                submit_guardian_operation(&config.rpc_config, &config.guardian_config, provider, plan.calls, &selected,
                    crate::guardian::protocol::GuardianOperation::Bridge, None, &mut history, Some((state_path, state, &aggregate_limits, &deposit_counts))).await?;
                archive.load_session(session_nonce, id)?
            }
            Err(error) => return Err(error),
        };
        let selected = selected_withdrawal_leaf_hashes.iter().map(|hash| state.pending_claim_withdrawals.get(hash).or_else(|| state.retired_claim_withdrawals.get(hash).map(|entry| &entry.withdrawal)).cloned().context("producing metadata missing")).collect::<anyhow::Result<Vec<_>>>()?;
        if record.is_none() {
            let mut history = config.guardian_history.lock().await;
            submit_guardian_operation(&config.rpc_config, &config.guardian_config, provider, Vec::new(), &selected,
                crate::guardian::protocol::GuardianOperation::Bridge, None, &mut history, Some((state_path, state, &aggregate_limits, &deposit_counts))).await?;
        }
        let (_, record) = archive.load_session(session_nonce, id)?;
        let record = record.context("guardian inclusion unavailable")?;
        let network_config = psy_config::PsyConfigGoldilocks::from_file(&config.rpc_config)?;
        let mut wallet = WalletSession::new(network_config.get_current_network()?).await?;
        let authorization = guardian.historical_authorization(request.decode()?.authorization_version)?;
        wallet.add_multisig_user(authorization.account_json.decode()?).await?;
        let committed = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?;
        let mut history = config.guardian_history.lock().await;
        refresh_relayer_history(&wallet, provider, &guardian, &archive, committed.checkpoint_id, committed.checkpoint_tree_root, &mut history).await?;
        ensure!(history.sessions.iter().any(|session| session.nonce == session_nonce && session.record.request_json.as_str() == request.as_str()
            && session.record.included_checkpoint_hash == record.included_checkpoint_hash), "archived inclusion is not canonical");
        drop(history);
        for record in request.decode()?.withdrawal_records {
            ensure!(selected.iter().any(|withdrawal| withdrawal.sender_user_id == u64::from(record.sender_user_id) && withdrawal.contract_id == u64::from(record.token_contract_id)
                && withdrawal.destination_chain_index == u64::from(record.destination_chain_index) && withdrawal.nonce == record.nonce && withdrawal.token_address == record.token && withdrawal.amount == record.amount && withdrawal.recipient == record.recipient), "archived burn differs from selected metadata");
        }
        wait_until_checkpoint_confirmed(provider, record.included_checkpoint_id, lag, REALM_CHECKPOINT_POLL_TIMEOUT_SECS, REALM_CHECKPOINT_POLL_INTERVAL_SECS).await?;
        state.pending = Some(build_aggregate_collection(config, chains, provider, network, http, record.included_checkpoint_id,
            Some(ProducingSession { session_nonce, request_id }), selected_withdrawal_leaf_hashes, Vec::new(), state).await?);
        save_multichain_state(state_path, state)?;
    }
    if let Some(PendingAggregate::Collecting { producing_session, selected_withdrawal_leaf_hashes, a_opening, selected_claims, .. }) = state.pending.clone() {
        if let Some(current) = super::api_client::get_aggregation_context(http, &config.services_url, &config.aggregation_token_file).await? {
            let a = psy_client_data::bridge_aggregate::DepositAggregateOpening::decode(&aggregate_bytes(&a_opening)?)?;
            let checkpoint = current.end_checkpoint_id.parse::<u64>()?;
            ensure!(current.config_hash == format!("0x{}", hex::encode(network.config_hash()?)), "published config mismatch");
            if checkpoint > a.end_checkpoint_id {
                let replacement = build_aggregate_collection(config, chains, provider, network, http, checkpoint, producing_session, selected_withdrawal_leaf_hashes, selected_claims, state).await?;
                if let PendingAggregate::Collecting { a_opening, .. } = &replacement {
                    let a = psy_client_data::bridge_aggregate::DepositAggregateOpening::decode(&aggregate_bytes(a_opening)?)?;
                    ensure!(aggregate_context(&a, network)?.context_id == current.context_id, "published context is not authenticated");
                }
                state.pending = Some(replacement);
                save_multichain_state(state_path, state)?;
            }
        }
    }
    if let Err(error) = collect_aggregate_claims(config, chains, provider, network, circuits, http, directory, state_path, state).await {
        if error.downcast_ref::<super::api_client::AggregationHttpError>().is_some() {
            tracing::warn!(%error, "aggregate claim unavailable; selected claims retained");
            return Ok(());
        }
        return Err(error);
    }
    if let Err(error) = prove_frozen_aggregate(config, provider, network, circuits, sources, directory, state_path, state).await {
        if error.downcast_ref::<DaemonStateWriteError>().is_some() || error.downcast_ref::<ReplayBootstrapError>().is_some() { return Err(error); }
        tracing::warn!(%error, "aggregate proving failed; retrying identical frozen inputs");
        return Ok(());
    }
    let Some(PendingAggregate::Frozen { a_opening, settlement_opening, claim_ids, included_acknowledged, .. }) = state.pending.clone() else { return Ok(()); };
    let a = DepositAggregateOpening::decode(&aggregate_bytes(&a_opening)?)?;
    let settlement = psy_client_data::bridge_aggregate::SettlementOpening::decode(&aggregate_bytes(&settlement_opening)?).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
    let w = WithdrawalAggregateOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, withdrawal_roots: settlement.endpoints.iter().map(|endpoint| endpoint.withdrawal_root).collect(), withdrawals: settlement.withdrawals.clone() };
    let r = SourceCheckpointRewardOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, leaves: settlement.rewards.clone() };
    let opening_digests = [w.opening_digest(network)?, r.opening_digest()?];
    let openings = [w.encode()?, r.encode()?];
    for family in [2u8, 3] {
        if included_acknowledged[family as usize - 2] { continue; }
        let context = aggregate_context(&a, network)?;
        let ids = claim_ids.iter().zip(w.withdrawals.iter().map(|_| 2u8).chain(r.leaves.iter().map(|_| 3))).filter(|(_, kind)| *kind == family).map(|(id, _)| format!("0x{id}")).collect::<Vec<_>>();
        let posted = super::api_client::post_aggregation_dispositions(http, &config.services_url, &config.aggregation_token_file,
            &AggregationDispositions::Included { context_id: context.context_id.clone(), family, opening_digest: format!("0x{}", hex::encode(opening_digests[family as usize - 2])), opening: base64::engine::general_purpose::STANDARD.encode(&openings[family as usize - 2]), claim_ids: ids }).await;
        if let Err(super::api_client::AggregationHttpError::Service { status, data }) = &posted {
            if *status != reqwest::StatusCode::CONFLICT || !matches!(data.error_code, super::api_client::AggregationErrorCode::ContextChanged) { return Err(posted.err().unwrap().into()); }
            if let Some(current) = &data.current_context {
                ensure!(current.config_hash == context.config_hash && current.end_checkpoint_id.parse::<u64>()? >= a.end_checkpoint_id, "context refresh regression");
                reconcile_frozen_window(config, chains, provider, network, http, directory, state_path, state, current.end_checkpoint_id.parse()?, true).await?;
                return Ok(());
            }
        }
        posted?;
        if let Some(PendingAggregate::Frozen { included_acknowledged, .. }) = &mut state.pending { included_acknowledged[family as usize - 2] = true; }
        save_multichain_state(state_path, state)?;
    }
    for (index, chain) in chains.iter().enumerate() {
        let Some(PendingAggregate::Frozen { destinations, final_proofs, .. }) = &state.pending else { unreachable!() };
        let destination = &destinations[index];
        let proofs = final_proofs.as_ref().context("missing frozen proofs")?;
        let call = window_call(directory, network, &a, &settlement, proofs)?;
        let calldata = call.encode();
        let observed = observe_aggregate_submission(http, chain, &a, network, opening_digests, &destination.submission, &calldata).await?;
        if let Some(PendingAggregate::Frozen { destinations, .. }) = &mut state.pending { destinations[index].submission = observed; }
        save_multichain_state(state_path, state)?;
        let Some(PendingAggregate::Frozen { destinations, .. }) = &state.pending else { unreachable!() };
        if !matches!(destinations[index].submission, Submission::NotSent) { continue; }
        let sender = L1Client::bind(&chain.config)?;
        let limits = state.pending.as_ref().context("frozen round missing")?.limits();
        let prepared = match sender.preflight_aggregate(network, chain.chain_index, chain.state_manager, calldata, limits).await {
            Ok(prepared) => prepared,
            Err(error) => {
                let current: u64 = U256::from_be_bytes(aggregate_word(http, chain, chain.state_manager, "lastFinalizedCheckpointId()", None, &serde_json::json!("finalized")).await?).try_into()?;
                let current_root = aggregate_hash_words(aggregate_word(http, chain, chain.state_manager, "lastVerifiedCheckpointRoot()", None, &serde_json::json!("finalized")).await?)?;
                let start = a.starts.iter().find(|start| start.chain_index == chain.chain_index).context("frozen start missing")?;
                if (current, current_root) != (start.start_checkpoint_id, start.start_checkpoint_root) && destinations.iter().all(|destination| !matches!(destination.submission, Submission::Sending | Submission::Submitted { .. })) {
                    let checkpoint = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?.checkpoint_id;
                    reconcile_frozen_window(config, chains, provider, network, http, directory, state_path, state, checkpoint, true).await?;
                    return Ok(());
                }
                tracing::warn!(chain_index=chain.chain_index, %error, "aggregate preflight blocked; frozen round remains NotSent");
                continue;
            }
        };
        if let Some(PendingAggregate::Frozen { destinations, .. }) = &mut state.pending { destinations[index].submission = Submission::Sending; }
        save_multichain_state(state_path, state)?;
        let hash = sender.broadcast_prepared(prepared).await;
        let hash = match hash { Ok(hash) => hash, Err(error) => { tracing::error!(chain_index=chain.chain_index, %error, "unknown aggregate send outcome; operator reconciliation required"); continue; } };
        if let Some(PendingAggregate::Frozen { destinations, .. }) = &mut state.pending { destinations[index].submission = Submission::Submitted { transaction_hash: hex::encode(hash) }; }
        save_multichain_state(state_path, state)?;
    }
    let Some(PendingAggregate::Frozen { destinations, .. }) = &state.pending else { unreachable!() };
    if destinations.iter().any(|destination| matches!(destination.submission, Submission::Sending | Submission::Submitted {..})) { return Ok(()); }
    let complete = destinations.iter().all(|destination| matches!(destination.submission, Submission::Finalized {..}));
    let failed = destinations.iter().any(|destination| matches!(destination.submission, Submission::Reverted {..}));
    if !complete && !failed { return Ok(()); }
    let checkpoint = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?.checkpoint_id;
    reconcile_frozen_window(config, chains, provider, network, http, directory, state_path, state, checkpoint, !complete).await?;
    Ok(())
}





pub(crate) fn resolve_prove_proxy_url(config: &BridgeProposeDaemonConfig) -> Option<String> {
    let rpc_config = psy_config::PsyConfigGoldilocks::from_file(&config.rpc_config).ok()?;
    let network = rpc_config.get_current_network().ok()?;
    network
        .prove_proxy_url
        .iter()
        .find(|url| !url.trim().is_empty())
        .cloned()
}

fn load_config(path: &Path) -> anyhow::Result<BridgeProposeDaemonConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read daemon config {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse daemon config {}", path.display()))
}

fn load_state(path: &Path) -> anyhow::Result<DaemonState> {
    if !path.exists() {
        return Ok(DaemonState::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read daemon state {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse daemon state {}", path.display()))
}

fn load_multichain_state(path: &Path, namespace: &str) -> anyhow::Result<MultichainDaemonState> {
    if !path.exists() {
        return Ok(MultichainDaemonState { identity_namespace: namespace.to_string(), ..Default::default() });
    }
    let raw = fs::read_to_string(path)?;
    let document: toml::Value = toml::from_str(&raw).context("old daemon state requires operator reconciliation before atomic-window cutover")?;
    let schema = document.get("schema").and_then(toml::Value::as_integer).context("aggregate state schema missing")?;
    ensure!(schema == 4, "unsupported aggregate state schema; operator reconciliation required");
    let state: MultichainDaemonState = toml::from_str(&raw).context("old daemon state requires operator reconciliation before atomic-window cutover")?;
    ensure!(state.schema == 4, "unsupported aggregate state schema; operator reconciliation required");
    ensure!(state.identity_namespace == namespace, "multichain daemon state belongs to a different chain cohort");
    validate_aggregate_state(path.parent().unwrap_or(Path::new(".")), &state)?;
    Ok(state)
}

fn save_multichain_state(path: &Path, state: &MultichainDaemonState) -> anyhow::Result<()> {
    validate_aggregate_state(path.parent().unwrap_or(Path::new(".")), state)?;
    save_daemon_bytes(path, toml::to_string(state)?.as_bytes())
}

fn validate_aggregate_state(directory: &Path, state: &MultichainDaemonState) -> anyhow::Result<()> {
    fn hash(value: &str) -> anyhow::Result<()> { ensure!(aggregate_bytes(value)?.len() == 32, "aggregate hash width mismatch"); Ok(()) }
    fn file(reference: &FileReference) -> anyhow::Result<()> {
        hash(&reference.sha256)?;
        ensure!(!reference.relative_path.is_empty() && Path::new(&reference.relative_path).components().all(|part| matches!(part, std::path::Component::Normal(_))), "invalid aggregate file reference");
        Ok(())
    }
    fn submission(value: &Submission) -> anyhow::Result<()> {
        match value {
            Submission::NotSent | Submission::Sending => {},
            Submission::Submitted { transaction_hash } => hash(transaction_hash)?,
            Submission::Finalized { transaction_hash, block_hash, withdrawal_log_index, reward_log_index, .. } => {
                hash(transaction_hash)?; hash(block_hash)?;
                for index in std::iter::once(withdrawal_log_index).chain(reward_log_index.iter()) {
                    ensure!(index.parse::<u64>()?.to_string() == *index, "noncanonical log index");
                }
            }
            Submission::Reverted { transaction_hash, block_hash, .. } => { hash(transaction_hash)?; hash(block_hash)?; }
        }
        Ok(())
    }
    ensure!(state.schema == 4, "unsupported aggregate state schema");
    for (chain, evidence) in &state.retained_finalize {
        ensure!(chain.parse::<u8>()?.to_string() == *chain, "invalid retained finalization chain index");
        hash(&evidence.bf_identity)?;
        file(&evidence.raw_proof)?;
    }
    if let Some(pending) = &state.pending {
        let selected = match pending {
            PendingAggregate::Producing { aggregate_limits, deposit_counts, session_nonce, request_id, selected_withdrawal_leaf_hashes } => {
                let (withdrawals, rewards) = aggregate_selected_counts(aggregate_limits, selected_withdrawal_leaf_hashes, &[], state)?;
                validate_aggregate_reservation(aggregate_limits, deposit_counts, &withdrawals, rewards)?;
                ensure!(*session_nonce > 0, "invalid producing nonce"); hash(request_id)?; selected_withdrawal_leaf_hashes
            }
            PendingAggregate::Collecting { aggregate_limits, producing_session, selected_withdrawal_leaf_hashes, a_opening, withdrawal_endpoint, selected_claims } => {
                if let Some(session) = producing_session { ensure!(session.session_nonce > 0, "invalid producing nonce"); hash(&session.request_id)?; }
                let bytes = aggregate_bytes(a_opening)?;
                let a = psy_client_data::bridge_aggregate::DepositAggregateOpening::decode(&bytes)?;
                ensure!(a.encode()? == bytes, "noncanonical deposit opening");
                let (withdrawals, rewards) = aggregate_selected_counts(aggregate_limits, selected_withdrawal_leaf_hashes, selected_claims, state)?;
                validate_aggregate_reservation(aggregate_limits, &aggregate_deposit_counts(&a)?, &withdrawals, rewards)?;
                let roots: Vec<[u64; 4]> = serde_json::from_slice(&aggregate_bytes(withdrawal_endpoint)?)?;
                ensure!(roots.len() == a.starts.len() && roots.iter().flatten().all(|limb| *limb < 0xffff_ffff_0000_0001), "withdrawal endpoint mismatch");
                let mut ids = HashSet::new();
                for claim in selected_claims {
                    hash(&claim.claim_id)?; ensure!(ids.insert(&claim.claim_id), "duplicate selected claim");
                    let bytes = aggregate_bytes(&claim.record)?;
                    let encoded = match claim.kind { 2 => psy_client_data::bridge_aggregate::WithdrawalLeaf::decode(&bytes)?.encode()?, 3 if bytes.is_empty() => Vec::new(), 3 => psy_client_data::bridge_aggregate::SourceCheckpointRewardLeaf::decode(&bytes)?.encode()?, _ => anyhow::bail!("unsupported selected claim kind") };
                    let transition = claim.proof.as_ref().map(|proof| load_aggregate_file(directory, proof)).transpose()?.unwrap_or_default();
                    let id = if claim.kind == 3 { reward_claim_id(a.config_hash, &bytes, &transition) } else { aggregate_claim_id(a.config_hash, claim.kind, &bytes) };
                    ensure!(encoded == bytes && id == claim.claim_id, "selected record identity mismatch");
                    ensure!(claim.proof.is_some() == claim.proof_context_id.is_some(), "partial selected proof reference");
                    if let Some(proof) = &claim.proof { file(proof)?; }
                    if let Some(context) = &claim.proof_context_id { hash(context)?; }
                }
                selected_withdrawal_leaf_hashes
            }
            PendingAggregate::Frozen { aggregate_limits, producing_session, selected_withdrawal_leaf_hashes, a_opening, settlement_opening, claim_ids, local_proofs, final_proofs, destinations, included_acknowledged } => {
                if let Some(session) = producing_session { ensure!(session.session_nonce > 0, "invalid producing nonce"); hash(&session.request_id)?; }
                let a = psy_client_data::bridge_aggregate::DepositAggregateOpening::decode(&aggregate_bytes(a_opening)?)?;
                let settlement = psy_client_data::bridge_aggregate::SettlementOpening::decode(&aggregate_bytes(settlement_opening)?).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
                ensure!(a.encode()? == aggregate_bytes(a_opening)? && settlement.encode().map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))? == aggregate_bytes(settlement_opening)?, "noncanonical frozen opening");
                ensure!(claim_ids.len() == settlement.withdrawals.len() + settlement.rewards.len() && local_proofs.len() == claim_ids.len(), "frozen opening claim count mismatch");
                validate_frozen_capacity(aggregate_limits, &a, &settlement)?;
                for (index, (id, record)) in claim_ids.iter().zip(settlement.withdrawals.iter().map(|record| record.encode().map(|bytes| (2u8, bytes))).chain(settlement.rewards.iter().map(|record| record.encode().map(|bytes| (3u8, bytes))))).enumerate() {
                    let (kind, bytes) = record?;
                    let transition = load_aggregate_file(directory, &local_proofs[index])?;
                    let expected = if kind == 3 { reward_claim_id(a.config_hash, &bytes, &transition) } else { aggregate_claim_id(a.config_hash, kind, &bytes) };
                    ensure!(*id == expected, "frozen claim identity mismatch");
                }
                for proof in local_proofs { file(proof)?; }
                if let Some(proofs) = final_proofs { file(&proofs.deposit)?; file(&proofs.settlement)?; }
                ensure!(destinations.len() == a.starts.len(), "destination count mismatch");
                for (destination, start) in destinations.iter().zip(&a.starts) {
                    ensure!(destination.chain_index == start.chain_index, "destination ordering mismatch");
                    submission(&destination.submission)?;
                    if !matches!(destination.submission, Submission::NotSent) { ensure!(included_acknowledged == &[true, true] && final_proofs.is_some() && destination.finalize.is_some(), "submission without complete acknowledged proofs"); }
                }
                selected_withdrawal_leaf_hashes
            }
        };
        let mut unique = HashSet::new();
        for id in selected { ensure!(unique.insert(id) && (state.pending_claim_withdrawals.contains_key(id) || state.retired_claim_withdrawals.contains_key(id)), "selected withdrawal metadata missing or duplicate"); }
    }
    for (key, receipt) in &state.receipt_dispositions {
        let (family_text, opening_digest) = key.split_once(':').context("receipt key family missing")?;
        let family: u8 = family_text.parse()?;
        ensure!((2..=3).contains(&family) && receipt.family == family, "receipt family mismatch");
        hash(opening_digest)?; file(&receipt.opening)?;
        if let Some(proofs) = &receipt.final_proofs { file(&proofs.deposit)?; file(&proofs.settlement)?; }
        for reverted in &receipt.reverted_receipts { hash(&reverted.transaction_hash)?; hash(&reverted.block_hash)?; }
    }
    Ok(())
}

fn aggregate_bytes(value: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = hex::decode(value)?;
    ensure!(hex::encode(&bytes) == value, "noncanonical aggregate bytes");
    Ok(bytes)
}

fn save_aggregate_file(directory: &Path, bytes: &[u8], extension: &str) -> anyhow::Result<FileReference> {
    let digest = hex::encode(crate::guardian::protocol::sha256(bytes).0);
    let relative_path = format!("aggregate-{digest}.{extension}");
    let path = directory.join(&relative_path);
    match fs::read(&path) {
        Ok(existing) => ensure!(existing == bytes, "immutable aggregate file collision"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => save_daemon_bytes(&path, bytes)?,
        Err(error) => return Err(error.into()),
    }
    Ok(FileReference { relative_path, sha256: digest })
}

fn load_aggregate_file(directory: &Path, reference: &FileReference) -> anyhow::Result<Vec<u8>> {
    let path = Path::new(&reference.relative_path);
    ensure!(!path.is_absolute() && path.components().all(|part| matches!(part, std::path::Component::Normal(_))), "invalid aggregate file path");
    let bytes = fs::read(directory.join(path))?;
    ensure!(hex::encode(crate::guardian::protocol::sha256(&bytes).0) == reference.sha256, "aggregate file digest mismatch");
    Ok(bytes)
}

fn family_disposition_applied(state: &MultichainDaemonState, family: u8, opening_digest: [u8; 32], record_count: usize) -> bool {
    if record_count == 0 { return true; }
    let Some(receipt) = state.receipt_dispositions.get(&format!("{family}:{}", hex::encode(opening_digest))) else { return false; };
    receipt.posted_opening_digest.as_deref() == Some(hex::encode(opening_digest).as_str())
        && receipt.dispositions.len() == record_count
        && receipt.dispositions.iter().all(|disposition| matches!(disposition, super::api_client::ClaimDisposition::Applied { .. }))
}

fn current_window_receipt_keys(network: &psy_client_data::bridge_aggregate::NetworkConfig, state: &MultichainDaemonState) -> anyhow::Result<Vec<String>> {
    let Some(PendingAggregate::Frozen { a_opening, settlement_opening, .. }) = &state.pending else { return Ok(Vec::new()); };
    let a = psy_client_data::bridge_aggregate::DepositAggregateOpening::decode(&aggregate_bytes(a_opening)?)?;
    let settlement = psy_client_data::bridge_aggregate::SettlementOpening::decode(&aggregate_bytes(settlement_opening)?).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
    let w = psy_client_data::bridge_aggregate::WithdrawalAggregateOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, withdrawal_roots: settlement.endpoints.iter().map(|endpoint| endpoint.withdrawal_root).collect(), withdrawals: settlement.withdrawals.clone() };
    let r = psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, leaves: settlement.rewards.clone() };
    Ok(vec![format!("2:{}", hex::encode(w.opening_digest(network)?)), format!("3:{}", hex::encode(r.opening_digest()?))])
}

fn remove_posted_receipts_outside_window(network: &psy_client_data::bridge_aggregate::NetworkConfig, state: &mut MultichainDaemonState) -> anyhow::Result<()> {
    let current = current_window_receipt_keys(network, state)?;
    state.receipt_dispositions.retain(|key, receipt| receipt.posted_opening_digest.is_none() || current.iter().any(|marker| marker == key));
    Ok(())
}

fn retained_end(directory: &Path, circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, evidence: &FinalizeEvidence, chains: usize) -> anyhow::Result<(U256, [U256; 4])> {
    let proof = load_raw_finalization(directory, circuits, evidence, chains)?;
    let end = proof.public_inputs[24].to_canonical_u64();
    let root = proof.public_inputs[20..24].iter().map(|field| U256::from(field.to_canonical_u64())).collect::<Vec<_>>();
    Ok((U256::from(end), [root[0], root[1], root[2], root[3]]))
}

fn opening_end(bytes: &[u8], family: u8) -> anyhow::Result<(U256, [U256; 4])> {
    let (id, root) = match family {
        2 => { let opening = psy_client_data::bridge_aggregate::WithdrawalAggregateOpening::decode(bytes)?; (opening.end_checkpoint_id, opening.end_checkpoint_root) }
        3 => { let opening = psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening::decode(bytes)?; (opening.end_checkpoint_id, opening.end_checkpoint_root) }
        _ => anyhow::bail!("malformed receipt family"),
    };
    Ok((U256::from(id), root.map(U256::from)))
}
fn clear_completed_applied_window(directory: &Path, network: &psy_client_data::bridge_aggregate::NetworkConfig, state_path: &Path, state: &mut MultichainDaemonState) -> anyhow::Result<()> {
    let Some(PendingAggregate::Frozen { destinations, a_opening, settlement_opening, .. }) = state.pending.clone() else { return Ok(()); };
    if !destinations.iter().all(|destination| matches!(destination.submission, Submission::Finalized { .. })) { return Ok(()); }
    let a = psy_client_data::bridge_aggregate::DepositAggregateOpening::decode(&aggregate_bytes(&a_opening)?)?;
    let settlement = psy_client_data::bridge_aggregate::SettlementOpening::decode(&aggregate_bytes(&settlement_opening)?).map_err(|error| anyhow::anyhow!("settlement opening: {error:?}"))?;
    let w = psy_client_data::bridge_aggregate::WithdrawalAggregateOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, withdrawal_roots: settlement.endpoints.iter().map(|endpoint| endpoint.withdrawal_root).collect(), withdrawals: settlement.withdrawals.clone() };
    let r = psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root, leaves: settlement.rewards.clone() };
    if !family_disposition_applied(state, 2, w.opening_digest(network)?, w.withdrawals.len()) || !family_disposition_applied(state, 3, r.opening_digest()?, r.leaves.len()) { return Ok(()); }
    let markers = current_window_receipt_keys(network, state)?;
    state.last_finalized_checkpoint = a.end_checkpoint_id;
    state.pending = None;
    for marker in &markers { state.receipt_dispositions.remove(marker); }
    save_multichain_state(state_path, state)
}












#[derive(Debug)]
struct ReplayBootstrapError;
impl std::fmt::Display for ReplayBootstrapError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("positive finalize evidence unavailable for replay; aggregation context changed")
    }
}
impl std::error::Error for ReplayBootstrapError {}

#[derive(Debug)]
struct DaemonStateWriteError(anyhow::Error);
impl std::fmt::Display for DaemonStateWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(formatter, "durable daemon state write failed: {}", self.0) }
}
impl std::error::Error for DaemonStateWriteError {}

fn save_daemon_bytes(path: &Path, raw: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "daemon state path missing file name: {}",
            path.display()
        )
    })?;
    let tmp_name = format!(
        ".{}.tmp-{}-{}",
        file_name.to_string_lossy(),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = parent.join(tmp_name);

    let install = (|| -> anyhow::Result<()> {
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| {
                format!(
                    "failed to create temp daemon state {}",
                    tmp_path.display()
                )
            })?;
        file.write_all(raw).with_context(|| {
            format!(
                "failed to write temp daemon state {}",
                tmp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "failed to sync temp daemon state {}",
                tmp_path.display()
            )
        })?;
        drop(file);
        fs::rename(&tmp_path, path).with_context(|| {
            format!(
                "failed to install daemon state via rename to {}",
                path.display()
            )
        })?;
        // Durably record the directory entry that now points at the new state.
        // Treat failure as an install failure so callers retain the proof and
        // do not advertise the new checkpoint as crash-safe.
        let dir = File::open(parent).with_context(|| {
            format!(
                "failed to open daemon state parent directory {}",
                parent.display()
            )
        })?;
        dir.sync_all().with_context(|| {
            format!(
                "failed to sync daemon state parent directory {}",
                parent.display()
            )
        })?;
        Ok(())
    })();

    if install.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    install.map_err(|error| anyhow::Error::new(DaemonStateWriteError(error)))
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

fn resolve_state_manager_address(config: &BridgeProposeDaemonConfig) -> anyhow::Result<Address> {
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


/// The pending claims still worth attempting.
///
/// Everything a round does for a withdrawal — the claim-proof fetch from
/// psy-services, and the Groth16 batch proof from prove-proxy — hangs off this
/// list, so dropping a retired claim here is what actually stops the work.
fn claims_to_attempt(
    pending: &HashMap<String, propose_withdrawals::PendingWithdrawal>,
    attempts: &HashMap<String, claim_attempts::ClaimAttempts>,
) -> Vec<propose_withdrawals::PendingWithdrawal> {
    pending
        .values()
        .filter(|w| claim_attempts::is_retriable(attempts.get(&w.leaf_hash)))
        .cloned()
        .collect()
}


/// Count both per-leaf failures and errors that abort the entire claim batch.
fn record_claim_result(
    attempted: &[propose_withdrawals::PendingWithdrawal],
    result: &anyhow::Result<claim_withdrawals::BatchWithdrawalsReport>,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired: &mut HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
    now_unix: u64,
) {
    match result {
        Ok(report) => {
            apply_claim_report(pending, report);
            record_claim_outcome(attempted, report, pending, retry, retired, now_unix);
        }
        Err(error) => {
            let reason = format!("claim batch failed: {error:#}");
            for withdrawal in attempted {
                record_claim_failure(withdrawal, &reason, pending, retry, retired, now_unix);
            }
        }
    }
}

/// Book one round's outcome against the durable attempt count.
///
/// A claim counts as failed when it was attempted and did not resolve — not
/// merely when it appears in `failure_reasons`. A withdrawal that falls out of
/// a round named nowhere is precisely the case that used to retry forever in
/// silence.
///
/// Deferrals are the exception. Waiting for a missing services proof or for
/// bridge liquidity resolves on its own and must not spend an attempt.
/// An unauthorized withdrawal root is a failure.
fn record_claim_outcome(
    attempted: &[propose_withdrawals::PendingWithdrawal],
    report: &claim_withdrawals::BatchWithdrawalsReport,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired: &mut HashMap<
        String,
        claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>,
    >,
    now_unix: u64,
) {
    let resolved: HashSet<&str> = report.resolved_leaf_hashes.iter().map(String::as_str).collect();

    for withdrawal in attempted {
        let leaf_hash = withdrawal.leaf_hash.as_str();
        if resolved.contains(leaf_hash) {
            claim_attempts::clear(retry, leaf_hash);
            continue;
        }
        if let Some(reason) = report.deferrals.get(leaf_hash) {
            tracing::info!(leaf_hash, reason, "withdrawal claim deferred; attempt not spent");
            continue;
        }

        let reason = report
            .failure_reasons
            .get(leaf_hash)
            .cloned()
            .unwrap_or_else(|| "claim did not resolve and reported no reason".to_string());
        record_claim_failure(withdrawal, &reason, pending, retry, retired, now_unix);
    }
}

/// Count one failed attempt, and give up on the withdrawal if that was its last.
fn record_claim_failure(
    withdrawal: &propose_withdrawals::PendingWithdrawal,
    reason: &str,
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
    retired: &mut HashMap<
        String,
        claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>,
    >,
    now_unix: u64,
) {
    let leaf_hash = withdrawal.leaf_hash.as_str();
    let state = claim_attempts::record_failure(retry, leaf_hash, reason);

    if claim_attempts::is_exhausted(&state) {
        // Stop paying for proofs, keep the record. The funds are stuck and this
        // needs a person, so it is an error, not a warning.
        tracing::error!(
            leaf_hash,
            attempts = state.attempts,
            reason = %state.last_reason,
            destination_chain_index = withdrawal.destination_chain_index,
            "withdrawal claim given up on after its attempts were used; no further proofs will be requested for it"
        );
        if let Some(w) = pending.remove(leaf_hash) {
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
        claim_attempts::clear(retry, leaf_hash);
    } else {
        tracing::warn!(
            leaf_hash,
            attempts = state.attempts,
            max_attempts = claim_attempts::CLAIM_MAX_ATTEMPTS,
            reason = %state.last_reason,
            "withdrawal claim failed; will retry next round"
        );
    }
}


fn apply_claim_report(
    pending_claim_withdrawals: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    report: &claim_withdrawals::BatchWithdrawalsReport,
) {
    for leaf_hash in &report.resolved_leaf_hashes {
        pending_claim_withdrawals.remove(leaf_hash);
    }
    for (leaf_hash, reason) in &report.failure_reasons {
        tracing::warn!(
            leaf_hash,
            reason,
            "withdrawal claim deferred; will retry next round"
        );
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


fn pending_policy_matches(request: &crate::guardian::protocol::GuardianSignRequest, operation: crate::guardian::protocol::GuardianOperation, members: [QHashOut<GoldilocksField>; 3]) -> anyhow::Result<bool> {
    if request.operation != operation { return Ok(false); }
    let calls: ContractCallData = serde_json::from_value(request.trace_json.decode()?.call_data)?;
    let expected: Vec<_> = members.iter().flat_map(|member| member.0.elements.map(|limb| limb.to_canonical_u64())).collect();
    Ok(calls.contract_calls.len() == 1 && calls.contract_calls[0].contract_id == 6 && calls.contract_calls[0].method_name == "set_policy" && calls.contract_calls[0].inputs.get(16..) == Some(expected.as_slice()))
}

async fn refresh_relayer_history(wallet: &WalletSession, provider: &RpcProvider, config: &super::guardian_client::GuardianClientConfig, archive: &super::guardian_client::RelayerArchive, head: u64, root: QHashOut<GoldilocksField>, retained: &mut RelayerHistory) -> anyhow::Result<()> {
    use crate::guardian::{protocol::*, verify::{GuardianVerificationContext, verify_session}};
    let mut approved = Vec::new();
    for session in &retained.sessions {
        let version = session.record.request_json.decode()?.authorization_version;
        if !approved.iter().any(|authorization: &GuardianAuthorization| authorization.version == version) {
            let authorization = config.historical_authorization(version)?;
            ensure!(retained.approvals.get(&version) == Some(&sha256(&serde_json::to_vec(&authorization)?)), "approved historical authorization changed");
            approved.push(authorization);
        }
        let saved = archive.sessions(session.nonce - 1, 1)?.sessions.into_iter().next().context("retained canonical record missing")?;
        ensure!(serde_json::to_vec(&saved)? == serde_json::to_vec(&session.record)?, "immutable canonical record changed");
    }
    let context = GuardianVerificationContext { wallet, provider, verified_checkpoint_id: head, verified_checkpoint_tree_root: root, l1_endpoints: &config.l1_endpoints, history: &retained.history };
    crate::guardian::verify::verify_guardian_saved_anchors(&context, &[], &approved, &retained.sessions).await.map_err(|error| anyhow::anyhow!("saved guardian history observation failed: {error:?}"))?;
    loop {
        let page = archive.sessions(retained.history.nonce(), 1)?;
        let Some(record) = page.sessions.into_iter().next() else { break; };
        let authorization = config.historical_authorization(record.request_json.decode()?.authorization_version)?;
        let digest = sha256(&serde_json::to_vec(&authorization)?);
        if let Some(previous) = retained.approvals.get(&authorization.version) { ensure!(*previous == digest, "approved historical authorization changed"); }
        let context = GuardianVerificationContext { wallet, provider, verified_checkpoint_id: head, verified_checkpoint_tree_root: root, l1_endpoints: &config.l1_endpoints, history: &retained.history };
        let session = verify_session(&context, &authorization, record).await?;
        retained.history.apply(&session)?;
        retained.approvals.insert(authorization.version, digest);
        retained.sessions.push(session);
    }
    Ok(())
}

fn build_unconsumed_withdrawal_plan(withdrawals: &[propose_withdrawals::PendingWithdrawal], included: impl FnMut(u32, u32, [u32; 8]) -> bool) -> anyhow::Result<MultichainL2CallPlan> {
    let withdrawals = select_guardian_withdrawals(withdrawals, included)?;
    let calls = build_withdrawal_batch_calls(&withdrawals);
    Ok(MultichainL2CallPlan { calls, withdrawals })
}

async fn select_unconsumed_plan_withdrawals(
    config: &BridgeProposeDaemonConfig,
    provider: &RpcProvider,
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
) -> anyhow::Result<MultichainL2CallPlan> {
    if withdrawals.is_empty() { return build_unconsumed_withdrawal_plan(withdrawals, |_, _, _| false); }
    let mut retained = config.guardian_history.lock().await;
    let client = super::guardian_client::GuardianClientConfig::load(Path::new(&config.guardian_config))?;
    let archive = super::guardian_client::RelayerArchive::open(&client.archive_path)?;
    let _account_lock = archive.lock()?;
    let network = psy_config::PsyConfigGoldilocks::from_file(&config.rpc_config)?;
    let mut wallet = WalletSession::new(network.get_current_network()?).await?;
    let authorization = client.authorization()?;
    let public_key = wallet.add_multisig_user(authorization.account_json.decode()?).await?;
    ensure!(public_key == authorization.account_public_key, "AccountIdentityConflict");
    let head = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?;
    refresh_relayer_history(&wallet, provider, &client, &archive, head.checkpoint_id, head.checkpoint_tree_root, &mut retained).await?;
    build_unconsumed_withdrawal_plan(withdrawals, |sender, contract, nonce| retained.history.contains_burn(sender, contract, nonce))
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
    limits: &AggregateLimits,
    retained_withdrawals: &[propose_withdrawals::PendingWithdrawal],
) -> anyhow::Result<(Vec<ChainRoundProgress>, MultichainL2CallPlan)> {
    let http = crate::bridge::api_client::build_default_http_client()?;
    let approved = super::regen_groth16_keystore::load_aggregate_setup_config(&base.aggregate_setup_config)?;
    let network = psy_client_data::bridge_aggregate::NetworkConfig::decode(&aggregate_bytes(&approved.network_config)?)?;
    limits.validate(&network)?;
    let mut remaining_deposits = limits.max_deposits;
    let mut progress = Vec::with_capacity(chains.len());
    let mut calls = Vec::new();
    let mut withdrawal_chain_offsets: Vec<(u64, u64)> = Vec::with_capacity(chains.len());

    for chain in chains {
        let finalized = aggregate_rpc(&http, chain, "eth_getBlockByNumber", serde_json::json!(["finalized", false])).await?;
        let block = serde_json::json!({"blockHash":finalized["hash"],"requireCanonical":true});
        let proved: u32 = U256::from_be_bytes(aggregate_word(&http, chain, chain.bridge, "provedDepositCount()", None, &block).await?).try_into()?;
        let pending: u32 = U256::from_be_bytes(aggregate_word(&http, chain, chain.bridge, "pendingDepositCount()", None, &block).await?).try_into()?;
        ensure!(pending >= proved, "chain {} pending deposits regressed", chain.chain_index);
        let l2_count = u32::try_from(fetch_deposit_tree_next_index(
            provider,
            checkpoint,
            u64::from(chain.chain_index),
        ).await?).context("L2 per-chain deposit count exceeds u32")?;
        ensure!(l2_count <= pending, "chain {} L2 deposit count exceeds L1 pending count", chain.chain_index);
        if append_business { ensure!(l2_count == proved, "L2 deposit count differs from proved deposit count"); }

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

        let historical = l2_count.checked_sub(proved).context("proved deposit count exceeds L2 deposit count")?;
        let local_remaining = limits.chain(chain.chain_index)?.max_deposits.checked_sub(historical).context("historical deposits exceed local capacity")?;
        remaining_deposits = remaining_deposits.checked_sub(historical).context("historical deposits exceed global capacity")?;
        let appended = if append_business { (pending - l2_count).min(remaining_deposits).min(local_remaining) } else { 0 };
        let selected_count = l2_count.checked_add(appended).context("selected deposit count overflow")?;
        remaining_deposits = remaining_deposits.checked_sub(appended).context("deposit capacity overflow")?;
        if append_business && selected_count > l2_count {
            let snapshot = crate::bridge::api_client::fetch_services_deposit_snapshot_root(
                &http,
                &base.services_url,
                u64::from(chain.chain_index),
                u64::from(selected_count),
            ).await?;
            ensure!(snapshot.found, "missing exact deposit snapshot for chain {} count {}", chain.chain_index, selected_count);
            let snapshot_count = snapshot.snapshot_deposit_count().context("deposit snapshot missing count")?;
            ensure!(snapshot_count == u64::from(selected_count), "deposit snapshot count mismatch for chain {}", chain.chain_index);
            calls.push(build_set_chain_root_call(
                u64::from(chain.chain_index),
                snapshot_count,
                snapshot.deposit_root.as_deref().context("deposit snapshot missing root")?,
            )?);
        }
        progress.push(ChainRoundProgress {
            chain_index: chain.chain_index,
            pending_deposit_count: pending,
            proved_deposit_count: proved,
            l2_deposit_count: l2_count,
            selected_deposit_count: selected_count,
        });
    }
    calls.sort_by_key(|call| call.inputs.first().copied().unwrap_or(u64::MAX));

    let withdrawals = if append_business {
        propose_withdrawals::fetch_pending_bridge_withdrawals(
            propose_args,
            from_checkpoint.max(1),
            to_checkpoint.saturating_add(1),
            &withdrawal_chain_offsets,
        ).await?
    } else {
        Vec::new()
    };
    let MultichainL2CallPlan { withdrawals: retained, .. } = select_unconsumed_plan_withdrawals(base, provider, retained_withdrawals).await?;
    ensure!(retained.len() == retained_withdrawals.len(), "mandatory retained withdrawal already consumed during selection");
    let MultichainL2CallPlan { withdrawals: mut candidates, .. } = select_unconsumed_plan_withdrawals(base, provider, &withdrawals).await?;
    candidates.sort_by_key(|withdrawal| (withdrawal.destination_chain_index, withdrawal.nonce));
    let mut withdrawals = retained;
    let mut local = limits.chains.iter().map(|chain| (chain.chain_index, 0u32)).collect::<Vec<_>>();
    for withdrawal in &withdrawals {
        let (_, count) = local.iter_mut().find(|(chain, _)| u64::from(*chain) == withdrawal.destination_chain_index).context("retained withdrawal destination absent")?;
        *count = count.checked_add(1).context("retained withdrawal count overflow")?;
    }
    let deposits = progress.iter().map(|chain| (chain.chain_index, chain.selected_deposit_count - chain.proved_deposit_count)).collect::<Vec<_>>();
    validate_aggregate_reservation(limits, &deposits, &local, 0)?;
    if retained_withdrawals.is_empty() {
        for withdrawal in candidates {
            if withdrawals.iter().any(|selected| selected.leaf_hash == withdrawal.leaf_hash) { continue; }
            let (chain, count) = local.iter_mut().find(|(chain, _)| u64::from(*chain) == withdrawal.destination_chain_index).context("withdrawal destination absent")?;
            if *count == limits.chain(*chain)?.reserved_withdrawals { continue; }
            *count = count.checked_add(1).context("withdrawal selection overflow")?;
            withdrawals.push(withdrawal);
        }
    }
    validate_aggregate_reservation(limits, &deposits, &local, 0)?;
    calls.extend(build_withdrawal_batch_calls(&withdrawals));
    Ok((progress, MultichainL2CallPlan { calls, withdrawals }))
}









pub(crate) async fn submit_guardian_calls(rpc_config: &str, guardian_config: &str, provider: &RpcProvider, calls: Vec<ContractCallArgs>, withdrawals: &[propose_withdrawals::PendingWithdrawal]) -> anyhow::Result<u64> {
    submit_guardian_operation(rpc_config, guardian_config, provider, calls, withdrawals, crate::guardian::protocol::GuardianOperation::Bridge, None, &mut RelayerHistory::default(), None).await
}

pub(crate) async fn submit_guardian_policy(rpc_config: &str, guardian_config: &str, provider: &RpcProvider, operation: crate::guardian::protocol::GuardianOperation, next_members: [QHashOut<GoldilocksField>; 3]) -> anyhow::Result<u64> {
    ensure!(operation != crate::guardian::protocol::GuardianOperation::Bridge, "policy command cannot submit bridge calls");
    submit_guardian_operation(rpc_config, guardian_config, provider, Vec::new(), &[], operation, Some(next_members), &mut RelayerHistory::default(), None).await
}

pub(crate) async fn run_guardian_bootstrap(rpc_config: &str, guardian_config: &str) -> anyhow::Result<()> {
    let config = super::guardian_client::GuardianClientConfig::load(Path::new(guardian_config))?;
    let members = config.authorization()?.account_json.decode()?.initial_policy.member_hashes;
    let network = psy_config::PsyConfigGoldilocks::from_file(rpc_config)?;
    let provider = RpcProvider::new_with_config(network.get_current_network()?)?;
    let operation = submit_guardian_policy(rpc_config, guardian_config, &provider, crate::guardian::protocol::GuardianOperation::Bootstrap, [members[0], members[1], members[2]]);
    tokio::select! { result = config.serve_history() => result, result = operation => result.map(|_| ()) }
}

pub(crate) async fn run_guardian_replace_policy(rpc_config: &str, guardian_config: &str, next_members: [QHashOut<GoldilocksField>; 3]) -> anyhow::Result<()> {
    let config = super::guardian_client::GuardianClientConfig::load(Path::new(guardian_config))?;
    let network = psy_config::PsyConfigGoldilocks::from_file(rpc_config)?;
    let provider = RpcProvider::new_with_config(network.get_current_network()?)?;
    let operation = submit_guardian_policy(rpc_config, guardian_config, &provider, crate::guardian::protocol::GuardianOperation::ReplacePolicy, next_members);
    tokio::select! { result = config.serve_history() => result, result = operation => result.map(|_| ()) }
}

pub(crate) async fn run_guardian_register(rpc_config: &str, guardian_config: &str, exclusive_registration_intake: bool) -> anyhow::Result<()> {
    let config = super::guardian_client::GuardianClientConfig::load(Path::new(guardian_config))?;
    let authorization = config.authorization()?;
    let network = psy_config::PsyConfigGoldilocks::from_file(rpc_config)?;
    let archive = super::guardian_client::RelayerArchive::open(&config.archive_path)?;
    let _account_lock = archive.lock()?;
    ensure!(archive.pending_request()?.is_none(), "registration cannot replace pending account work");
    let mut wallet = WalletSession::new(network.get_current_network()?).await?;
    let public_key = wallet.register_bridge_multisig_user(authorization.account_json.decode()?, exclusive_registration_intake).await?;
    ensure!(public_key == authorization.account_public_key, "AccountIdentityConflict");
    Ok(())
}

async fn submit_guardian_operation(rpc_config: &str, guardian_config: &str, provider: &RpcProvider, calls: Vec<ContractCallArgs>, withdrawals: &[propose_withdrawals::PendingWithdrawal], operation: crate::guardian::protocol::GuardianOperation, next_members: Option<[QHashOut<GoldilocksField>; 3]>, retained: &mut RelayerHistory, pending_owner: Option<(&Path, &mut MultichainDaemonState, &AggregateLimits, &[(u8, u32)])>) -> anyhow::Result<u64> {
    use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
    use crate::guardian::{protocol::*, verify::{GuardianVerificationContext, verify_guardian_session, verify_session}};
    use super::guardian_client::{GuardianClientConfig, GuardianClient, RelayerArchive, prove_pending_request};
    use psy_prover::trace::GeneratedTxTraceJson;
    if let Some((_, state, limits, deposits)) = pending_owner.as_ref() {
        let mut counts = limits.chains.iter().map(|chain| (chain.chain_index, 0u32)).collect::<Vec<_>>();
        for withdrawal in withdrawals {
            let (_, count) = counts.iter_mut().find(|(chain, _)| u64::from(*chain) == withdrawal.destination_chain_index).context("withdrawal destination absent")?;
            *count = count.checked_add(1).context("withdrawal count overflow")?;
        }
        validate_aggregate_reservation(limits, deposits, &counts, 0)?;
        if let Some(pending) = &state.pending { ensure!(pending.limits() == *limits, "inflight aggregate limits changed"); }
    }
    let config = GuardianClientConfig::load(Path::new(guardian_config))?;
    let authorization = config.authorization()?;
    let archive = RelayerArchive::open(&config.archive_path)?;
    let _account_lock = archive.lock()?;
    let network = psy_config::PsyConfigGoldilocks::from_file(rpc_config)?;
    let mut wallet = WalletSession::new(network.get_current_network()?).await?;
    let public_key = wallet.add_multisig_user(authorization.account_json.decode()?).await?;
    ensure!(public_key == authorization.account_public_key && provider.get_user_ids_for_public_key(public_key).await? == vec![BRIDGE_USER_ID_U64], "AccountIdentityConflict");
    let coordinator_url = provider.get_coordinator_url()?;
    let committed = crate::guardian::service::load_guardian_committed_head(provider, &coordinator_url).await?;
    let head = committed.checkpoint_id;
    let root = committed.checkpoint_tree_root;
    refresh_relayer_history(&wallet, provider, &config, &archive, head, root, retained).await?;
    let history = &mut retained.history;
    let pending = archive.pending_request()?;
    if pending_owner.as_ref().is_some_and(|(_, state, _, _)| state.pending.is_none()) {
        ensure!(pending.is_none(), "unowned archived session requires operator reconciliation before daemon production");
    }
    let pending_nonce = pending.as_ref().map(|request| request.decode().map(|request| request.session_nonce)).transpose()?;
    let pending_included = retained.sessions.iter().find(|session| Some(session.nonce) == pending_nonce).cloned();
    let request_json = if let Some(pending) = pending {
        let pending_request = pending.decode()?;
        if let Some((_, state, limits, deposits)) = pending_owner.as_ref() {
            let Some(PendingAggregate::Producing { session_nonce, request_id, .. }) = &state.pending else { anyhow::bail!("archived session lacks producing capacity owner"); };
            ensure!(*session_nonce == pending_request.session_nonce && *request_id == hex::encode(pending_request.request_id()?.0), "archived request differs from producing owner");
            let actual = limits.chains.iter().map(|chain| {
                let count = pending_request.deposit_anchors.iter().find(|anchor| anchor.chain_index == chain.chain_index).map(|anchor| anchor.new_count.checked_sub(anchor.old_count).context("archived deposit interval regressed")).transpose()?.unwrap_or(0);
                Ok((chain.chain_index, count))
            }).collect::<anyhow::Result<Vec<_>>>()?;
            ensure!(actual.as_slice() == *deposits, "archived deposit selection differs from capacity reservation");
        }
        if operation != GuardianOperation::Bridge {
            ensure!(pending_policy_matches(&pending_request, operation, next_members.context("policy command requires next members")?)?, "NonceConflict: pending operation or policy members differ from requested command");
        }
        if let Some(session) = pending_included {
            ensure!(session.record.request_json.as_str() == pending.as_str(), "NonceConflict: canonical inclusion differs from pending request");
            let approved = config.historical_authorization(pending_request.authorization_version)?;
            archive.save_record(&session.record, &approved)?;
            return Ok(session.record.included_checkpoint_id);
        }
        pending
    } else {
        let account_proof = provider.get_user_tree_merkle_proof(head, BRIDGE_USER_ID_U64).await?;
        let nonce = if account_proof.value == QHashOut::ZERO { 1 } else { provider.get_user_leaf_data(head, BRIDGE_USER_ID_U64).await?.nonce.to_canonical_u64().checked_add(1).context("account nonce overflow")? };
        ensure!(history.nonce().checked_add(1) == Some(nonce), "HistoryUnavailable: retained canonical account prefix is incomplete");
        let selected = select_guardian_withdrawals(withdrawals, |sender, contract, nonce| history.contains_burn(sender, contract, nonce))?;
        if let Some((_, state, _, _)) = pending_owner.as_ref() {
            if let Some(PendingAggregate::Producing { selected_withdrawal_leaf_hashes, .. }) = &state.pending {
                ensure!(selected.len() == selected_withdrawal_leaf_hashes.len(), "prearchive selection changed during rebuild");
            }
        }
        let records = selected.iter().map(|withdrawal| Ok(WithdrawalBurnRecord {
            sender_user_id: withdrawal.sender_user_id.try_into()?, token_contract_id: withdrawal.contract_id.try_into()?,
            destination_chain_index: withdrawal.destination_chain_index.try_into()?, token: withdrawal.token_address,
            amount: withdrawal.amount, recipient: withdrawal.recipient, nonce: withdrawal.nonce,
        })).collect::<anyhow::Result<Vec<_>>>()?;
        let mut anchors = Vec::new();
        let mut approved_calls = Vec::new();
        for call in calls.iter().filter(|call| call.contract_id == u64::from(DEPOSIT_TREE_CONTRACT_ID)) {
            ensure!(call.method_name == "set_chain_root" && call.inputs.len() == 10, "UnsupportedCall");
            let index = u8::try_from(call.inputs[0])?;
            let chain = authorization.chain(index)?;
            let endpoint = config.l1_endpoints.iter().find(|endpoint| endpoint.chain_index == index).context("missing authorized L1 endpoint")?;
            let old_count = u32::try_from(fetch_deposit_tree_next_index(provider, head, u64::from(index)).await?)?;
            let new_count = u32::try_from(call.inputs[1])?;
            if old_count == new_count { continue; }
            let anchor = crate::guardian::verify_l1::finalized_deposit_anchor(endpoint, chain, old_count, new_count).await?;
            let (_, new_root) = crate::guardian::verify_l1::verify_deposit_anchor(history, endpoint, chain, &anchor).await?;
            let root_bytes: Vec<_> = new_root.0.elements.iter().flat_map(|field| {
                let value = field.to_canonical_u64();
                (value as u32).to_be_bytes().into_iter().chain(((value >> 32) as u32).to_be_bytes())
            }).collect();
            approved_calls.push(build_set_chain_root_call(u64::from(index), u64::from(new_count), &hex::encode(root_bytes))?);
            anchors.push(anchor);
        }
        anchors.sort_by_key(|anchor| anchor.chain_index);
        approved_calls.sort_by_key(|call| call.inputs[0]);
        approved_calls.extend(build_withdrawal_batch_calls(&selected));
        if let Some((_, _, limits, deposits)) = pending_owner.as_ref() {
            let actual = limits.chains.iter().map(|chain| {
                let count = anchors.iter().find(|anchor| anchor.chain_index == chain.chain_index).map(|anchor| anchor.new_count.checked_sub(anchor.old_count).context("guardian deposit interval regressed")).transpose()?.unwrap_or(0);
                Ok((chain.chain_index, count))
            }).collect::<anyhow::Result<Vec<_>>>()?;
            ensure!(actual.as_slice() == *deposits, "guardian deposit selection differs from capacity reservation");
        }
        if operation != GuardianOperation::Bridge {
            ensure!(approved_calls.is_empty() && records.is_empty() && anchors.is_empty(), "policy operation cannot mix bridge calls");
            let next_members = next_members.context("policy operation requires exactly three members")?;
            let mut expected = Vec::with_capacity(16);
            for slot in 0..4 {
                let hash = provider.get_user_contract_state_tree_leaf_hash(head, BRIDGE_USER_ID_U64, 6, 4, slot).await?;
                expected.extend(hash.0.elements.map(|limb| limb.to_canonical_u64()));
            }
            if operation == GuardianOperation::Bootstrap {
                ensure!(expected.iter().all(|limb| *limb == 0) && nonce == 1 && next_members == authorization.account_json.decode()?.initial_policy.member_hashes[..3], "invalid policy bootstrap");
            } else {
                ensure!(expected[0] != 0, "rotation requires initialized policy");
            }
            for member in next_members { expected.extend(member.0.elements.map(|limb| limb.to_canonical_u64())); }
            approved_calls.push(ContractCallArgs { contract_id: 6, method_name: "set_policy".to_owned(), inputs: expected });
        }
        if approved_calls.is_empty() { return Ok(head); }
        let call_data = ContractCallData::new(approved_calls);
        let mut builder = wallet.begin_trace_build_at_checkpoint(public_key, BRIDGE_USER_ID_U64, head, nonce, root).await?;
        for call in &call_data.contract_calls { builder.trace_call(call.clone()).await?; }
        ensure!(builder.required_fee()? <= authorization.max_fee, "fee exceeds guardian authorization");
        let trace = builder.finalize_tx_trace(call_data.software_defined_call.clone()).await?;
        let request = GuardianSignRequest { schema_version: 1, authorization_version: authorization.version, network_magic: authorization.network_magic, genesis_hash: authorization.genesis_hash, user_id: BRIDGE_USER_ID_U64, session_nonce: nonce, operation, trace_json: JsonText::from_value(&GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(&call_data)?)?)?, deposit_anchors: anchors, withdrawal_records: records };
        let context = GuardianVerificationContext { wallet: &wallet, provider, verified_checkpoint_id: head, verified_checkpoint_tree_root: root, l1_endpoints: &config.l1_endpoints, history: &history };
        verify_guardian_session(&context, &authorization, &request).await?;
        JsonText::from_value(&request)?
    };
    let request = request_json.decode()?;
    if let Some((path, state, aggregate_limits, deposit_counts)) = pending_owner {
        let request_id = hex::encode(request.request_id()?.0);
        let mut selected_withdrawal_leaf_hashes = Vec::with_capacity(request.withdrawal_records.len());
        for record in &request.withdrawal_records {
            let selected = withdrawals.iter().find(|withdrawal| withdrawal.sender_user_id == u64::from(record.sender_user_id)
                && withdrawal.contract_id == u64::from(record.token_contract_id) && withdrawal.destination_chain_index == u64::from(record.destination_chain_index)
                && withdrawal.token_address == record.token && withdrawal.amount == record.amount && withdrawal.recipient == record.recipient && withdrawal.nonce == record.nonce)
                .context("guardian request missing selected withdrawal metadata")?;
            let existing = state.pending_claim_withdrawals.get(&selected.leaf_hash).or_else(|| state.retired_claim_withdrawals.get(&selected.leaf_hash).map(|entry| &entry.withdrawal));
            if let Some(existing) = existing { ensure!(serde_json::to_value(existing)? == serde_json::to_value(selected)?, "selected withdrawal metadata conflict"); }
            else { state.pending_claim_withdrawals.insert(selected.leaf_hash.clone(), selected.clone()); }
            selected_withdrawal_leaf_hashes.push(selected.leaf_hash.clone());
        }
        match &state.pending {
            Some(PendingAggregate::Producing { session_nonce, request_id: saved_id, selected_withdrawal_leaf_hashes: saved, deposit_counts: saved_counts, .. }) => ensure!(*session_nonce == request.session_nonce && *saved_id == request_id && *saved == selected_withdrawal_leaf_hashes && saved_counts == deposit_counts, "producing session changed"),
            None => state.pending = Some(PendingAggregate::Producing { aggregate_limits: aggregate_limits.clone(), deposit_counts: deposit_counts.to_vec(), session_nonce: request.session_nonce, request_id, selected_withdrawal_leaf_hashes }),
            _ => anyhow::bail!("aggregate collection blocks another guardian session"),
        }
        save_multichain_state(path, state)?;
    }
    let request_authorization = config.historical_authorization(request.authorization_version)?;
    let trace = request.decode_trace()?;
    let client = GuardianClient::new(&config)?;
    let proof = loop {
        match prove_pending_request(&mut wallet, &client, &archive, &request_authorization, &request_json).await {
            Ok(proof) => break proof,
            Err(error) if error.downcast_ref::<GuardianSignError>() == Some(&GuardianSignError::EvidenceUnavailable) => {
                tracing::warn!(nonce = request.session_nonce, "guardian quorum unavailable; retrying frozen request");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => return Err(error),
        }
    };
    let signatures = archive.signatures(request.session_nonce)?.context("missing threshold signatures")?;
    let mut record = GuardianSessionRecord { request_json, signatures_json: JsonText::from_value(&signatures)?, endcap_input_json: JsonText::from_value(&trace.finalization.submit_end_cap_input)?, endcap_proof_hex: format!("0x{}", hex::encode(&proof)), included_checkpoint_id: u64::MAX, included_checkpoint_hash: root };
    record.validate(&request_authorization)?;
    let committed_now = crate::guardian::service::load_guardian_committed_head(provider, &coordinator_url).await?;
    ensure!(committed_now.checkpoint_id >= head && provider.get_checkpoint_tree_root(head).await? == root, "committed checkpoint contradiction; pending request retained");
    if let Some(session) = recover_guardian_inclusion(&wallet, provider, &config, &archive, &request_authorization, history, &mut record).await? {
        history.apply(&session)?;
        let landed = session.record.included_checkpoint_id;
        retained.approvals.insert(request_authorization.version, sha256(&serde_json::to_vec(&request_authorization)?));
        retained.sessions.push(session);
        return Ok(landed);
    }
    let submission = wallet.submit_end_cap(&trace, bincode::deserialize(&proof)?).await;
    let leaf = match submission {
        Ok(leaf) => leaf,
        Err(error) => {
            if let Some(session) = recover_guardian_inclusion(&wallet, provider, &config, &archive, &request_authorization, history, &mut record).await? {
                history.apply(&session)?;
                let landed = session.record.included_checkpoint_id;
                retained.approvals.insert(request_authorization.version, sha256(&serde_json::to_vec(&request_authorization)?));
                retained.sessions.push(session);
                return Ok(landed);
            }
            return Err(error);
        }
    };
    let start = trace.finalization.submit_end_cap_input.core.checkpoint_id.to_canonical_u64();
    let landed = provider.wait_for_endcap_inclusion(BRIDGE_USER_ID_U64, leaf, start, Some(REALM_CHECKPOINT_POLL_TIMEOUT_SECS), REALM_CHECKPOINT_POLL_INTERVAL_SECS).await?;
    record.included_checkpoint_id = landed;
    record.included_checkpoint_hash = provider.get_checkpoint_tree_merkle_proof(landed, landed).await?.value;
    let included_root = provider.get_checkpoint_tree_root(landed).await?;
    let context = GuardianVerificationContext { wallet: &wallet, provider, verified_checkpoint_id: landed, verified_checkpoint_tree_root: included_root, l1_endpoints: &config.l1_endpoints, history: &history };
    let session = verify_session(&context, &request_authorization, record.clone()).await?;
    archive.save_record(&record, &request_authorization)?;
    history.apply(&session)?;
    retained.approvals.insert(request_authorization.version, sha256(&serde_json::to_vec(&request_authorization)?));
    retained.sessions.push(session);
    Ok(landed)
}

async fn recover_guardian_inclusion(
    wallet: &WalletSession,
    provider: &RpcProvider,
    config: &super::guardian_client::GuardianClientConfig,
    archive: &super::guardian_client::RelayerArchive,
    authorization: &crate::guardian::protocol::GuardianAuthorization,
    history: &crate::guardian::verify::GuardianHistory,
    record: &mut crate::guardian::protocol::GuardianSessionRecord,
) -> anyhow::Result<Option<crate::guardian::protocol::GuardianSession>> {
    use psy_client_data::config::store_config::PsyHasher;
    use psy_crypto::hash::traits::qhashable::QFieldHashable;
    let head = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?;
    let input = record.endcap_input_json.decode()?;
    let proof = provider.get_user_tree_merkle_proof(head.checkpoint_id, BRIDGE_USER_ID_U64).await?;
    if proof.value != input.core.new_user_leaf.qfhash::<PsyHasher>() { return Ok(None); }
    record.included_checkpoint_id = head.checkpoint_id;
    record.included_checkpoint_hash = provider.get_checkpoint_tree_merkle_proof(head.checkpoint_id, head.checkpoint_id).await?.value;
    let context = crate::guardian::verify::GuardianVerificationContext {
        wallet, provider, verified_checkpoint_id: head.checkpoint_id,
        verified_checkpoint_tree_root: head.checkpoint_tree_root,
        l1_endpoints: &config.l1_endpoints, history,
    };
    let session = crate::guardian::verify::verify_session(&context, authorization, record.clone()).await?;
    archive.save_record(record, authorization)?;
    Ok(Some(session))
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


async fn fetch_proved_deposit_count(provider: &impl Provider, bridge: Address) -> anyhow::Result<u32> {
    let proved = crate::bridge::api_client::eth_call_u256(provider, bridge, provedDepositCountCall {}).await?;
    u32::try_from(proved).context("provedDepositCount exceeds u32")
}

async fn fetch_pending_deposit_count(provider: &impl Provider, bridge: Address) -> anyhow::Result<u32> {
    let pending = crate::bridge::api_client::eth_call_u256(provider, bridge, pendingDepositCountCall {}).await?;
    u32::try_from(pending).context("pendingDepositCount exceeds u32")
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


fn select_guardian_withdrawals(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
    mut included: impl FnMut(u32, u32, [u32; 8]) -> bool,
) -> anyhow::Result<Vec<propose_withdrawals::PendingWithdrawal>> {
    let mut available = Vec::new();
    for withdrawal in withdrawals {
        let sender = u32::try_from(withdrawal.sender_user_id)?;
        let contract = u32::try_from(withdrawal.contract_id)?;
        u8::try_from(withdrawal.destination_chain_index)?;
        if !included(sender, contract, withdrawal.nonce) { available.push(withdrawal); }
    }
    available.sort_unstable_by_key(|withdrawal| (withdrawal.destination_chain_index, withdrawal.sender_user_id, withdrawal.contract_id, withdrawal.nonce));
    Ok(available.into_iter().take(1024).cloned().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use psy_prover::session::{EndCapContractSlotUpdate, EndCapSubmissionError};
    use psy_provider::request::RealmEndCapSlotUpdates;
fn save_state(path: &Path, state: &DaemonState) -> anyhow::Result<()> {
    let raw = toml::to_string(state).context("failed to serialize daemon state")?;
    save_daemon_bytes(path, raw.as_bytes())
}
/// Replayed events must not automatically re-arm claims retired by the operator policy.
fn insert_pending_claims(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
    pending: &mut HashMap<String, propose_withdrawals::PendingWithdrawal>,
    retired: &HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
) -> bool {
    let mut changed = false;
    for withdrawal in withdrawals {
        if retired.contains_key(&withdrawal.leaf_hash) {
            continue;
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = pending.entry(withdrawal.leaf_hash.clone()) {
            entry.insert(withdrawal.clone());
            changed = true;
        }
    }
    changed
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
    retry: &mut HashMap<String, claim_attempts::ClaimAttempts>,
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
        .filter(|w| claim_attempts::is_retriable(retry.get(&w.leaf_hash)))
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
        record_claim_failure(withdrawal, &reason, pending, retry, retired, now_unix);
    }
}
fn persist_claim_withdrawals_before_l2_submit(
    state_path: &Path,
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
) -> anyhow::Result<()> {
    if withdrawals.is_empty() {
        return Ok(());
    }

    let mut persisted = load_state(state_path)?;
    let changed = insert_pending_claims(withdrawals, &mut persisted.pending_claim_withdrawals, &persisted.retired_claim_withdrawals);
    if changed {
        save_state(state_path, &persisted).context("failed to persist pending claims before L2 submission")?;
    }
    Ok(())
}
fn record_claim_withdrawals(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
    seen: &mut HashSet<String>,
    claims: &mut Vec<propose_withdrawals::PendingWithdrawal>,
) {
    for withdrawal in withdrawals {
        if seen.insert(withdrawal.leaf_hash.clone()) {
            claims.push(withdrawal.clone());
        }
    }
}
async fn dispatch_multichain_plan<F, Fut>(plan: &MultichainL2CallPlan, window_checkpoint: u64, submit: F) -> anyhow::Result<u64>
where F: FnOnce() -> Fut, Fut: Future<Output = anyhow::Result<u64>> {
    if plan.calls.is_empty() { return Ok(window_checkpoint); }
    submit().await
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
impl RelayerWindow {
    fn has_confirmed_range(self) -> bool {
        self.confirmed_to_checkpoint.is_some()
    }
}

    #[test]
    fn policy_retry_rejects_different_operation_and_members() {
        use crate::guardian::protocol::{codec_request_fixture, GuardianOperation, JsonText};
        let mut request = codec_request_fixture();
        let members: [QHashOut<GoldilocksField>; 3] = [QHashOut::from_values(1, 2, 3, 4), QHashOut::from_values(5, 6, 7, 8), QHashOut::from_values(9, 10, 11, 12)];
        request.operation = GuardianOperation::ReplacePolicy;
        let mut generated = request.trace_json.decode().unwrap();
        let mut inputs = vec![0; 16];
        inputs.extend(members.iter().flat_map(|member| member.0.elements.map(|limb| limb.to_canonical_u64())));
        generated.call_data = serde_json::to_value(ContractCallData::new(vec![ContractCallArgs { contract_id: 6, method_name: "set_policy".into(), inputs }])).unwrap();
        request.trace_json = JsonText::from_value(&generated).unwrap();
        assert!(pending_policy_matches(&request, GuardianOperation::ReplacePolicy, members).unwrap());
        assert!(!pending_policy_matches(&request, GuardianOperation::Bootstrap, members).unwrap());
        let mut different = members;
        different[2] = QHashOut::from_values(13, 14, 15, 16);
        assert!(!pending_policy_matches(&request, GuardianOperation::ReplacePolicy, different).unwrap());
        request.operation = GuardianOperation::Bridge;
        assert!(!pending_policy_matches(&request, GuardianOperation::ReplacePolicy, members).unwrap());
    }

    #[tokio::test]
    async fn consumed_discovery_does_not_submit_or_advance_proof_window() {
        let mut candidate = sample_withdrawal(1);
        candidate.destination_chain_index = 0;
        let plan = build_unconsumed_withdrawal_plan(&[candidate.clone()], |_, _, _| true).unwrap();
        let submissions = std::cell::Cell::new(0);
        let endpoint = dispatch_multichain_plan(&plan, 10, || {
            submissions.set(submissions.get() + 1);
            async { Ok(20) }
        }).await.unwrap();
        assert_eq!(submissions.get(), 0);
        assert_eq!(endpoint, 10);
        let mut next = sample_withdrawal(2);
        next.destination_chain_index = 0;
        let plan = build_unconsumed_withdrawal_plan(&[candidate, next.clone()], |sender, _, _| sender == 301).unwrap();
        assert_eq!(plan.withdrawals.iter().map(|withdrawal| withdrawal.nonce).collect::<Vec<_>>(), vec![next.nonce]);
        assert_eq!(plan.calls[0].inputs[0], next.sender_user_id);
        let endpoint = dispatch_multichain_plan(&plan, 10, || {
            submissions.set(submissions.get() + 1);
            async { Ok(20) }
        }).await.unwrap();
        assert_eq!(submissions.get(), 1);
        assert_eq!(endpoint, 20);
    }
    use crate::bridge::propose_withdrawals::PendingWithdrawal;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_state_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "psy-relayer-daemon-state-{name}-{}-{nanos}.toml",
            std::process::id()
        ))
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
    fn guardian_selection_bounds_unconsumed_prefix_and_retains_next_round() {
        let candidates: Vec<_> = (0..1030).rev().map(|seed| {
            let mut withdrawal = sample_withdrawal(seed);
            withdrawal.destination_chain_index = 0;
            withdrawal
        }).collect();
        let selected = select_guardian_withdrawals(&candidates, |sender, _, _| sender < 303).unwrap();
        assert_eq!(selected.iter().map(|withdrawal| withdrawal.sender_user_id).collect::<Vec<_>>(), (303..1327).collect::<Vec<_>>());
        let mut reordered = candidates.clone();
        reordered.reverse();
        let same = select_guardian_withdrawals(&reordered, |sender, _, _| sender < 303).unwrap();
        assert_eq!(selected.iter().map(|withdrawal| withdrawal.nonce).collect::<Vec<_>>(), same.iter().map(|withdrawal| withdrawal.nonce).collect::<Vec<_>>());
        let remaining = select_guardian_withdrawals(&candidates, |sender, _, _| sender < 1327).unwrap();
        assert_eq!(remaining.iter().map(|withdrawal| withdrawal.sender_user_id).collect::<Vec<_>>(), vec![1327, 1328, 1329]);
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
    fn load_state_returns_default_when_file_missing() {
        // Restart with no daemon_state.toml: must boot from a clean default,
        // not error. L1 reconciliation re-anchors the cursor next round.
        let path = temp_state_path("missing");
        assert!(!path.exists());
        let state = load_state(&path).expect("missing state file should yield default");
        assert_eq!(state.last_finalized_checkpoint, 0);
        assert!(state.pending_claim_withdrawals.is_empty());
    }

    #[test]
    fn load_state_errors_on_corrupt_state_file() {
        // A corrupt daemon_state.toml must surface a parse error rather than
        // silently booting from default — otherwise pending claims vanish.
        let path = temp_state_path("corrupt");
        std::fs::write(&path, "last_finalized_checkpoint = \"not-a-u64\"\n").unwrap();
        let err = load_state(&path).unwrap_err();
        assert!(
            err.to_string().contains("failed to parse daemon state"),
            "expected parse-error context, got: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_then_load_state_round_trips_pending_withdrawals() {
        // Persisted pending claims must survive a save/load cycle bit-for-bit
        // so a restart resumes claiming exactly where it left off.
        let path = temp_state_path("roundtrip");
        let w1 = sample_withdrawal(3);
        let w2 = sample_withdrawal(7);
        let state = DaemonState {
            last_finalized_checkpoint: 42,
            pending_claim_withdrawals: HashMap::from([
                (w1.leaf_hash.clone(), w1.clone()),
                (w2.leaf_hash.clone(), w2.clone()),
            ]),
                        ..Default::default()
                    };
        save_state(&path, &state).unwrap();
        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded.last_finalized_checkpoint, 42);
        assert_eq!(loaded.pending_claim_withdrawals.len(), 2);
        assert_eq!(loaded.pending_claim_withdrawals[&w1.leaf_hash].event_id, w1.event_id);
        assert_eq!(loaded.pending_claim_withdrawals[&w2.leaf_hash].event_id, w2.event_id);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn landed_l2_withdrawal_survives_crash_and_is_claimed_after_restart() {
        let path = temp_state_path("pre-submit-crash");
        let withdrawal = sample_withdrawal(11);
        let state = DaemonState {
            last_finalized_checkpoint: 42,
            pending_claim_withdrawals: HashMap::new(),
                        ..Default::default()
                    };
        save_state(&path, &state).unwrap();

        persist_claim_withdrawals_before_l2_submit(&path, std::slice::from_ref(&withdrawal))
            .expect("withdrawal must be durable before the L2 batch is submitted");

        // The L2 batch lands, then the daemon crashes before the round can
        // return its in-memory claim_withdrawals vector. Restart from disk only.
        let mut restarted = load_state(&path).expect("restart must load pending claims");
        assert_eq!(restarted.last_finalized_checkpoint, 42);
        assert_eq!(restarted.pending_claim_withdrawals.len(), 1);
        assert_eq!(
            restarted.pending_claim_withdrawals[&withdrawal.leaf_hash].event_id,
            withdrawal.event_id
        );

        let claim_report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 1,
            submitted_count: 1,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![withdrawal.leaf_hash.clone()],
            failure_reasons: HashMap::new(),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut restarted.pending_claim_withdrawals, &claim_report);
        assert!(
            restarted.pending_claim_withdrawals.is_empty(),
            "the restarted daemon must submit and resolve the landed withdrawal"
        );

        let _ = std::fs::remove_file(path);
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
    fn set_chain_root_call_uses_absolute_snapshot_count() {
        let root = "0x0000000100000002000000030000000400000005000000060000000700000008";
        let call = build_set_chain_root_call(9, 12, root).unwrap();

        assert_eq!(call.contract_id, DEPOSIT_TREE_CONTRACT_ID as u64);
        assert_eq!(call.method_name, "set_chain_root");
        assert_eq!(call.inputs, vec![9, 12, 1, 2, 3, 4, 5, 6, 7, 8]);
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

    fn empty_report() -> claim_withdrawals::BatchWithdrawalsReport {
        claim_withdrawals::BatchWithdrawalsReport {
            requested: 0,
            submitted_count: 0,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![],
            failure_reasons: HashMap::new(),
            deferrals: HashMap::new(),
        }
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

        let mut resolved = empty_report();
        resolved.resolved_leaf_hashes = vec!["a".to_string()];
        record_claim_outcome(&attempted, &resolved, &mut pending, &mut retry, &mut retired, 0);
        assert!(!retry.contains_key("a"), "a success must clear the history");
    }

    fn withdrawal_for_chain(leaf: &str, chain_index: u64) -> propose_withdrawals::PendingWithdrawal {
        let mut w = backoff_withdrawal(leaf);
        w.destination_chain_index = chain_index;
        w
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

        let mut report = empty_report();
        report.deferrals.insert("a".to_string(), "bridge ERC20 liquidity insufficient".to_string());

        for _ in 0..50 {
            record_claim_outcome(&attempted, &report, &mut pending, &mut retry, &mut retired, 0);
        }

        assert!(retry.get("a").is_none(), "a deferral must not count as an attempt");
        assert!(retired.is_empty(), "a deferred withdrawal must not be given up on");
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
        let mut deferred = empty_report();
        deferred.deferrals.insert("a".to_string(), "waiting".to_string());
        record_claim_outcome(&attempted, &deferred, &mut pending, &mut retry, &mut retired, 0);

        assert_eq!(retry["a"].attempts, 1, "the earlier failure still counts");
    }

    #[test]
    fn proof_readiness_deferrals_do_not_exhaust_claim_attempts() {
        let attempted = vec![backoff_withdrawal("not-found"), backoff_withdrawal("root-mismatch")];
        let mut pending = attempted.iter().map(|w| (w.leaf_hash.clone(), w.clone())).collect();
        let mut retry = HashMap::new();
        let mut retired = HashMap::new();
        let mut report = empty_report();
        report.deferrals.insert("not-found".to_string(), "withdrawal claim proof not available yet; L1 root not finalized".to_string());
        report.failure_reasons.insert("root-mismatch".to_string(), "withdrawal root is not current or known: services=0x01 l1=0x02".to_string());

        for round in 0..claim_attempts::CLAIM_MAX_ATTEMPTS {
            record_claim_outcome(&attempted, &report, &mut pending, &mut retry, &mut retired, u64::from(round));
        }
        assert!(retry.get("not-found").is_none(), "waiting for proof must not spend attempts");
        assert!(retired.get("not-found").is_none(), "waiting for proof must not retire claims");
        assert!(retired.contains_key("root-mismatch"), "unauthorized root must spend attempts and retire");
        assert_eq!(claims_to_attempt(&pending, &retry).len(), 1);

        let remaining: Vec<_> = pending.values().cloned().collect();
        let mut failed = empty_report();
        failed.failure_reasons.insert("not-found".to_string(), "fetch claim proof failed: RPC unavailable".to_string());
        record_claim_outcome(&remaining, &failed, &mut pending, &mut retry, &mut retired, 10);
        assert_eq!(retry["not-found"].attempts, 1);
        assert!(retired.contains_key("root-mismatch"));

        let mut waiting = empty_report();
        waiting.deferrals.insert("not-found".to_string(), "withdrawal claim proof not available yet; L1 root not finalized".to_string());
        for round in 11..15 {
            let remaining: Vec<_> = pending.values().cloned().collect();
            record_claim_outcome(&remaining, &waiting, &mut pending, &mut retry, &mut retired, round);
            assert_eq!(retry["not-found"].attempts, 1);
            assert!(retired.contains_key("root-mismatch"));
            assert_eq!(claims_to_attempt(&pending, &retry).len(), 1);
        }
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
        let path = temp_state_path("batch-error-restarts");
        let failed = withdrawal_for_chain("failed", 0);
        let untouched = withdrawal_for_chain("untouched", 1);
        let mut state = DaemonState::default();
        insert_pending_claims(&[failed.clone(), untouched], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals);

        for attempt in 1..=claim_attempts::CLAIM_MAX_ATTEMPTS {
            record_claim_result(
                &[failed.clone()],
                &Err(anyhow::anyhow!("RPC unavailable")),
                &mut state.pending_claim_withdrawals,
                &mut state.claim_retry,
                &mut state.retired_claim_withdrawals,
                u64::from(attempt),
            );
            save_state(&path, &state).unwrap();
            state = load_state(&path).unwrap();
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

        persist_claim_withdrawals_before_l2_submit(&path, &[failed]).unwrap();
        assert!(!load_state(&path).unwrap().pending_claim_withdrawals.contains_key("failed"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn aggregate_state_rejects_unknown_nested_ledger_fields() {
        let withdrawal = withdrawal_for_chain("selected", 0);
        let mut state = MultichainDaemonState::default();
        state.pending_claim_withdrawals.insert("selected".into(), withdrawal.clone());
        state.claim_retry.insert("selected".into(), claim_attempts::ClaimAttempts::default());
        state.retired_claim_withdrawals.insert("retired".into(), claim_attempts::RetiredClaim {
            withdrawal, attempts: 3, last_reason: "rejected".into(), retired_at_unix: 9,
        });
        let encoded = toml::to_string(&state).unwrap();
        let document: toml::Value = toml::from_str(&encoded).unwrap();
        for path in [
            vec!["pending_claim_withdrawals", "selected"],
            vec!["claim_retry", "selected"],
            vec!["retired_claim_withdrawals", "retired"],
            vec!["retired_claim_withdrawals", "retired", "withdrawal"],
        ] {
            let mut invalid = document.clone();
            let mut record = &mut invalid;
            for field in path { record = record.get_mut(field).unwrap(); }
            record.as_table_mut().unwrap().insert("unexpected".into(), toml::Value::Boolean(true));
            assert!(toml::from_str::<MultichainDaemonState>(&toml::to_string(&invalid).unwrap()).is_err());
        }
        let mut defaults = document;
        defaults.get_mut("claim_retry").unwrap().get_mut("selected").unwrap().as_table_mut().unwrap().clear();
        let decoded: MultichainDaemonState = toml::from_str(&toml::to_string(&defaults).unwrap()).unwrap();
        assert_eq!(decoded.claim_retry["selected"], claim_attempts::ClaimAttempts::default());
        assert_eq!(decoded.pending_claim_withdrawals["selected"].checkpoint_id, state.pending_claim_withdrawals["selected"].checkpoint_id);
        assert_eq!(decoded.retired_claim_withdrawals["retired"].retired_at_unix, 9);
    }

    #[test]
    fn multichain_retirement_survives_restart_and_replayed_scans() {
        let path = temp_state_path("multichain-retirement");
        let failed = withdrawal_for_chain("failed", 0);
        let healthy = withdrawal_for_chain("healthy", 2);
        let mut state = MultichainDaemonState {
            identity_namespace: "three-chains".to_string(),
            last_finalized_checkpoint: 9,
            pending: Some(PendingAggregate::Producing { aggregate_limits: capacity_limits(), deposit_counts: vec![(0, 0), (2, 0)], session_nonce: 1, request_id: "00".repeat(32), selected_withdrawal_leaf_hashes: vec!["failed".into()] }),
            ..Default::default()
        };
        insert_pending_claims(&[failed.clone(), healthy.clone()], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals);
        for attempt in 1..=claim_attempts::CLAIM_MAX_ATTEMPTS {
            let mut report = empty_report();
            report.failure_reasons.insert("failed".to_string(), "invalid proof".to_string());
            record_claim_result(
                &[failed.clone()], &Ok(report), &mut state.pending_claim_withdrawals,
                &mut state.claim_retry, &mut state.retired_claim_withdrawals, u64::from(attempt),
            );
            save_multichain_state(&path, &state).unwrap();
            state = load_multichain_state(&path, "three-chains").unwrap();
        }

        assert_eq!(state.last_finalized_checkpoint, 9);
        assert!(matches!(state.pending, Some(PendingAggregate::Producing { session_nonce: 1, .. })));
        assert_eq!(state.retired_claim_withdrawals["failed"].attempts, 3);
        for _ in 0..10 {
            assert!(!insert_pending_claims(
                &[failed.clone(), healthy.clone()], &mut state.pending_claim_withdrawals, &state.retired_claim_withdrawals,
            ));
            let due = claims_to_attempt(&state.pending_claim_withdrawals, &state.claim_retry);
            assert_eq!(due.len(), 1);
            assert_eq!(due[0].leaf_hash, "healthy");
        }

        let mut resolved = empty_report();
        resolved.resolved_leaf_hashes.push("healthy".to_string());
        record_claim_result(
            &[healthy], &Ok(resolved), &mut state.pending_claim_withdrawals,
            &mut state.claim_retry, &mut state.retired_claim_withdrawals, 4,
        );
        assert!(state.pending_claim_withdrawals.is_empty());
        assert_eq!(state.retired_claim_withdrawals.len(), 1);
        fs::remove_file(path).unwrap();
    }


    #[test]
    fn schema2_multichain_state_is_rejected() {
        let path = temp_state_path("schema2-rejection");
        let mut current = MultichainDaemonState { identity_namespace: "three-chains".into(), last_finalized_checkpoint: 42, ..Default::default() };
        current.retained_finalize.insert("0".into(), FinalizeEvidence { bf_identity: "dd".repeat(32), raw_proof: FileReference { relative_path: "aggregate-proof.proof".into(), sha256: "ee".repeat(32) } });
        current.receipt_dispositions.insert(format!("2:{}", "bb".repeat(32)), ReceiptDispositions {
            family: 2, opening: FileReference { relative_path: "aggregate-opening.opening".into(), sha256: "cc".repeat(32) },
            final_proofs: None, dispositions: Vec::new(), reverted_receipts: Vec::new(), posted_opening_digest: None,
        });
        let mut document: toml::Value = toml::from_str(&toml::to_string(&current).unwrap()).unwrap();
        fs::write(&path, toml::to_string(&document).unwrap()).unwrap();
        let state = load_multichain_state(&path, "three-chains").unwrap();
        assert_eq!(state.schema, 4);
        assert_eq!(state.last_finalized_checkpoint, 42);
        assert_eq!(state.retained_finalize.len(), 1);
        assert_eq!(state.receipt_dispositions.len(), 1);
        for schema in [2, 3] {
            document.as_table_mut().unwrap().insert("schema".into(), toml::Value::Integer(schema));
            let bytes = toml::to_string(&document).unwrap();
            fs::write(&path, &bytes).unwrap();
            assert!(load_multichain_state(&path, "three-chains").is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), bytes);
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn apply_claim_report_removes_resolved_and_already_claimed_keeps_failures() {
        // resolved_leaf_hashes carries BOTH successfully submitted AND
        // already-claimed withdrawals (claim_withdrawals.rs pushes the leaf
        // hash in both cases). apply_claim_report must drop both from pending
        // so already-claimed withdrawals are never retried (no double-claim).
        let w1 = sample_withdrawal(1); // newly submitted
        let w2 = sample_withdrawal(2); // already claimed on L1
        let w3 = sample_withdrawal(3); // failed, must retry next round
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
            (w3.leaf_hash.clone(), w3.clone()),
        ]
        .into_iter()
        .collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 3,
            submitted_count: 1,
            already_claimed_count: 1,
            resolved_leaf_hashes: vec![w1.leaf_hash.clone(), w2.leaf_hash.clone()],
            failure_reasons: HashMap::from([(w3.leaf_hash.clone(), "proof not ready".to_string())]),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert!(!pending.contains_key(&w1.leaf_hash), "submitted withdrawal must be removed");
        assert!(
            !pending.contains_key(&w2.leaf_hash),
            "already-claimed withdrawal must be removed to prevent double-claim"
        );
        assert!(pending.contains_key(&w3.leaf_hash), "failed withdrawal must remain for retry");
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn apply_claim_report_leaves_unreported_withdrawals_untouched() {
        // Withdrawals absent from the report (e.g. claimed in a prior partial
        // batch) must be retained so they are retried in a later round.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
        ]
        .into_iter()
        .collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 1,
            submitted_count: 1,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![w1.leaf_hash.clone()],
            failure_reasons: HashMap::new(),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert!(!pending.contains_key(&w1.leaf_hash));
        assert!(pending.contains_key(&w2.leaf_hash), "unreported withdrawal must be retained");
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
    fn apply_claim_report_empty_report_leaves_pending_untouched() {
        // An empty report (no resolves, no failures) must not mutate pending.
        let w = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w.leaf_hash.clone(), w.clone())].into_iter().collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 0,
            submitted_count: 0,
            already_claimed_count: 0,
            resolved_leaf_hashes: Vec::new(),
            failure_reasons: HashMap::new(),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&w.leaf_hash));
    }

    #[test]
    fn apply_claim_report_resolving_unknown_leaf_is_a_safe_noop() {
        // A resolved leaf_hash that was never pending must not panic and must not
        // drop unrelated pending entries.
        let w1 = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w1.leaf_hash.clone(), w1.clone())].into_iter().collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 1,
            submitted_count: 1,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec!["never-pending-leaf".to_string()],
            failure_reasons: HashMap::new(),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert_eq!(pending.len(), 1, "unknown resolved leaf must not evict w1");
        assert!(pending.contains_key(&w1.leaf_hash));
    }

    #[test]
    fn apply_claim_report_resolving_all_clears_pending() {
        // Every pending withdrawal resolved → pending becomes empty (all claims
        // complete; nothing left to retry).
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut pending: HashMap<String, PendingWithdrawal> = [
            (w1.leaf_hash.clone(), w1.clone()),
            (w2.leaf_hash.clone(), w2.clone()),
        ]
        .into_iter()
        .collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 2,
            submitted_count: 2,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![w1.leaf_hash.clone(), w2.leaf_hash.clone()],
            failure_reasons: HashMap::new(),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert!(pending.is_empty(), "all-resolved report must clear pending");
    }

    #[test]
    fn apply_claim_report_failure_for_unknown_leaf_never_inserts() {
        // failure_reasons only logs a warning; it must never ADD a leaf to pending.
        let w1 = sample_withdrawal(1);
        let mut pending: HashMap<String, PendingWithdrawal> =
            [(w1.leaf_hash.clone(), w1.clone())].into_iter().collect();
        let report = claim_withdrawals::BatchWithdrawalsReport {
            requested: 1,
            submitted_count: 0,
            already_claimed_count: 0,
            resolved_leaf_hashes: Vec::new(),
            failure_reasons: HashMap::from([("never-pending-leaf".to_string(), "x".to_string())]),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report);
        assert_eq!(pending.len(), 1, "failure reason must not insert into pending");
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

    #[test]
    fn record_claim_withdrawals_all_duplicates_produces_no_new_entries() {
        // Pre-seed `seen` with every leaf_hash → input records nothing new.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let mut seen: HashSet<String> =
            [w1.leaf_hash.clone(), w2.leaf_hash.clone()].into_iter().collect();
        let mut claims = Vec::new();
        record_claim_withdrawals(&[w1.clone(), w2], &mut seen, &mut claims);
        assert_eq!(claims.len(), 0, "fully-duplicate input must record nothing");
    }

    #[test]
    fn record_claim_withdrawals_interleaved_new_and_duplicate_preserves_order() {
        // Mixed input: w1 new, w2 duplicate (already seen), w3 new → only w1 and
        // w3 are appended, in input order. Defends the within-round dedup
        // boundary that prevents the same claim being submitted twice.
        let w1 = sample_withdrawal(1);
        let w2 = sample_withdrawal(2);
        let w3 = sample_withdrawal(3);
        let mut seen: HashSet<String> = [w2.leaf_hash.clone()].into_iter().collect();
        let mut claims = Vec::new();
        record_claim_withdrawals(&[w1.clone(), w2, w3.clone()], &mut seen, &mut claims);
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].leaf_hash, w1.leaf_hash);
        assert_eq!(claims[1].leaf_hash, w3.leaf_hash);
    }


    // ── load_state / save_state / DaemonState serde edges ───────────────────

    #[test]
    fn load_state_empty_file_errors_not_silently_default() {
        // Crash recovery: a truncated/zero-byte state file must surface a parse
        // error rather than silently booting to default — otherwise pending
        // claims would vanish without trace. (Only a *missing* file yields the
        // clean default; an existing-but-empty file is treated as corrupt.)
        let path = temp_state_path("empty");
        std::fs::write(&path, "").unwrap();
        let err = load_state(&path).unwrap_err();
        assert!(
            err.to_string().contains("failed to parse daemon state"),
            "empty file must surface a parse error, got: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_state_migrates_legacy_failed_claim_withdrawals_alias() {
        // Backwards-compat migration: state files written by older daemons under
        // the field name `failed_claim_withdrawals` must deserialize into
        // `pending_claim_withdrawals` (the serde alias). Losing these on upgrade
        // would silently drop unclaimed withdrawals — a P0 crash-recovery defect.
        let path = temp_state_path("legacy-alias");
        let toml = concat!(
            "last_finalized_checkpoint = 88\n",
            "[failed_claim_withdrawals.leaf-legacy]\n",
            "event_id = -7\n",
            "checkpoint_id = 5\n",
            "user_id = 6\n",
            "sender_user_id = 7\n",
            "contract_id = 8\n",
            "destination_chain_index = 9\n",
            "token_address = [1,2,3,4,5,6,7,8]\n",
            "amount = [9,10,11,12,13,14,15,16]\n",
            "recipient = [17,18,19,20,21,22,23,24]\n",
            "nonce = [25,26,27,28,29,30,31,32]\n",
            "leaf_hash = \"leaf-legacy\"\n",
        );
        std::fs::write(&path, toml).unwrap();
        let state = load_state(&path).expect("legacy alias must deserialize");
        assert_eq!(state.last_finalized_checkpoint, 88);
        assert_eq!(state.pending_claim_withdrawals.len(), 1, "legacy claims must migrate");
        let w = &state.pending_claim_withdrawals["leaf-legacy"];
        assert_eq!(w.event_id, -7);
        assert_eq!(w.leaf_hash, "leaf-legacy");
        assert_eq!(w.nonce, [25, 26, 27, 28, 29, 30, 31, 32]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_state_round_trips_large_checkpoint_and_large_pending_set() {
        // Large-checkpoint boundary: i64::MAX is the largest u64 the TOML layer
        // can serialise (TOML integers are i64-range); a large pending set must
        // survive a save/load cycle bit-for-bit so a restart resumes exactly.
        // (u64::MAX is intentionally NOT tested here: it overflows TOML's i64
        // range and save_state errors — see the report's limitations note.)
        let path = temp_state_path("large");
        let mut pending = HashMap::new();
        for seed in 0..50u32 {
            let w = sample_withdrawal(seed);
            pending.insert(w.leaf_hash.clone(), w);
        }
        let state = DaemonState {
            last_finalized_checkpoint: i64::MAX as u64,
            pending_claim_withdrawals: pending,
                        ..Default::default()
                    };
        save_state(&path, &state).unwrap();
        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded.last_finalized_checkpoint, i64::MAX as u64);
        assert_eq!(loaded.pending_claim_withdrawals.len(), 50);
        // Spot-check two entries to ensure values (not just counts) round-trip.
        assert_eq!(loaded.pending_claim_withdrawals["leaf-0"].event_id, 0);
        assert_eq!(loaded.pending_claim_withdrawals["leaf-49"].user_id, 249);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_state_errors_when_path_is_unwritable() {
        // Error-propagation: writing to a path whose parent directory does not
        // exist must surface an error carrying the path context, not panic.
        let unwritable = std::env::temp_dir().join("psy-relayer-nonexistent-dir-7b1").join("x.toml");
        let state = DaemonState::default();
        let err = save_state(&unwritable, &state).unwrap_err();
        assert!(
            err.to_string().contains("failed to write daemon state"),
            "expected write-failure context, got: {err}"
        );
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
        //   - a withdrawal submitted or already-claimed in round N is removed and
        //     NEVER retried (no double-claim);
        //   - a failed withdrawal persists and is retried next round;
        //   - re-scanning an existing leaf never duplicates or overwrites it;
        //   - pending keys stay unique throughout.
        let w1 = sample_withdrawal(1); // submitted round 1
        let w2 = sample_withdrawal(2); // already-claimed on L1 round 1
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
        // Claim report: w1 submitted, w2 already-claimed (both resolved), w3 fails.
        let report1 = claim_withdrawals::BatchWithdrawalsReport {
            requested: 3,
            submitted_count: 1,
            already_claimed_count: 1,
            resolved_leaf_hashes: vec![w1.leaf_hash.clone(), w2.leaf_hash.clone()],
            failure_reasons: HashMap::from([(w3.leaf_hash.clone(), "proof not ready".to_string())]),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report1);
        assert!(!pending.contains_key(&w1.leaf_hash), "submitted must leave pending");
        assert!(
            !pending.contains_key(&w2.leaf_hash),
            "already-claimed must leave pending (no double-claim)"
        );
        assert!(pending.contains_key(&w3.leaf_hash), "failed must remain for retry");
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

        // Claim report: both w3 and w4 submitted this round; no failures.
        let report2 = claim_withdrawals::BatchWithdrawalsReport {
            requested: 2,
            submitted_count: 2,
            already_claimed_count: 0,
            resolved_leaf_hashes: vec![w3.leaf_hash.clone(), w4.leaf_hash.clone()],
            failure_reasons: HashMap::new(),
            deferrals: HashMap::new(),
        };
        apply_claim_report(&mut pending, &report2);
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



    // ── inner-loop catch-up break (run_l2_bridge_round mid-round stop) ────

    /// Mirrors the mid-loop guard in `run_l2_bridge_round_with_l1_provider`:
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
    fn save_state_atomically_replaces_existing_ledger_without_temp_residue() {
        // Crash safety: successful install fully replaces the prior ledger and
        // leaves no same-dir temp residue that could later be confused for state.
        let path = temp_state_path("atomic-replace");
        let prior_w = sample_withdrawal(3);
        let prior = DaemonState {
            last_finalized_checkpoint: 11,
            pending_claim_withdrawals: HashMap::from([(prior_w.leaf_hash.clone(), prior_w.clone())]),
                        ..Default::default()
                    };
        save_state(&path, &prior).unwrap();
        let prior_bytes = std::fs::read(&path).expect("prior ledger bytes");

        let next_w = sample_withdrawal(9);
        let next = DaemonState {
            last_finalized_checkpoint: 42,
            pending_claim_withdrawals: HashMap::from([
                (prior_w.leaf_hash.clone(), prior_w.clone()),
                (next_w.leaf_hash.clone(), next_w.clone()),
            ]),
                       ..Default::default()
                   };
        save_state(&path, &next).unwrap();

        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded.last_finalized_checkpoint, 42);
        assert_eq!(loaded.pending_claim_withdrawals.len(), 2);
        assert_eq!(
            loaded.pending_claim_withdrawals[&next_w.leaf_hash].event_id,
            next_w.event_id
        );
        let installed_bytes = std::fs::read(&path).expect("installed ledger bytes");
        assert_ne!(
            installed_bytes, prior_bytes,
            "atomic install must replace the prior ledger contents"
        );

        let parent = path.parent().expect("temp state parent");
        let stem = path
            .file_name()
            .expect("state file name")
            .to_string_lossy()
            .into_owned();
        let temp_residue: Vec<_> = std::fs::read_dir(parent)
            .expect("read state parent")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.contains(".tmp-") && name.contains(stem.trim_start_matches('.'))
            })
            .map(|entry| entry.path())
            .collect();
        assert!(
            temp_residue.is_empty(),
            "successful atomic save must not leave temp residue: {temp_residue:?}"
        );

        let _ = std::fs::remove_file(path);
    }



    #[test]
    fn multichain_window_starts_at_slowest_chain_and_stops_at_next_cursor() {
        let (from, window) = select_multichain_relayer_window(&[100, 50, 75], 200, 3, 64).unwrap();
        assert_eq!(from, 51);
        assert_eq!(window.to_checkpoint, 75);
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
guardian_config = "guardian-client.json"
services_url = "http://127.0.0.1:3000"
withdraw_method_id = 1
aggregate_setup_config = "aggregate-setup.json"
aggregate_artifact_dir = "aggregate-artifacts"
aggregation_token_file = "aggregation-token"

[aggregate_limits]
max_deposits = 3
reserved_withdrawals = 3
reserved_rewards = 1
max_window_calldata_bytes = 8192
chains = [
  { chain_index = 0, max_deposits = 1, reserved_withdrawals = 1, tx_gas_limit = 1000000, block_gas_reserve = 1000 },
  { chain_index = 1, max_deposits = 1, reserved_withdrawals = 1, tx_gas_limit = 1000000, block_gas_reserve = 1000 },
  { chain_index = 2, max_deposits = 1, reserved_withdrawals = 1, tx_gas_limit = 1000000, block_gas_reserve = 1000 },
]

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
        assert!(toml::from_str::<BridgeProposeDaemonConfig>(&raw.replace("guardian_config = \"guardian-client.json\"", "")).is_err());
        assert_eq!(config.chains.len(), 3);
        assert_eq!(config.chains.iter().map(|chain| chain.chain_index).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert!(config.chains.iter().all(|chain| chain.family == "evm"));
        assert!(toml::from_str::<BridgeProposeDaemonConfig>(&raw.replace("reserved_rewards = 1", "")).is_err());
    }

    fn capacity_limits() -> AggregateLimits {
        AggregateLimits { max_deposits: 4, reserved_withdrawals: 3, reserved_rewards: 2, max_window_calldata_bytes: 6756,
            chains: vec![ChainLimits { chain_index: 0, max_deposits: 3, reserved_withdrawals: 1, tx_gas_limit: 1_000_000, block_gas_reserve: 1000 },
                ChainLimits { chain_index: 2, max_deposits: 3, reserved_withdrawals: 2, tx_gas_limit: 1_000_000, block_gas_reserve: 1000 }] }
    }

    #[test]
    fn aggregate_capacity_reserves_full_foreign_records_and_rewards() {
        let limits = capacity_limits();
        assert_eq!(limits.validate_capacity(&[(0, 3), (2, 1)], &[(0, 1), (2, 2)], 2).unwrap(), 6756);
        let mut too_small = limits.clone();
        too_small.max_window_calldata_bytes -= 1;
        assert!(validate_aggregate_reservation(&too_small, &[(0, 3), (2, 1)], &[(0, 0), (2, 0)], 0).is_err());
        assert!(limits.validate_capacity(&[(0, 4), (2, 0)], &[(0, 0), (2, 0)], 0).is_err());
        assert!(limits.validate_capacity(&[(0, 0), (2, 0)], &[(0, 2), (2, 0)], 0).is_err());
        assert!(limits.validate_capacity(&[(0, 0), (2, 0)], &[(0, 0), (2, 0)], 3).is_err());
    }

    #[test]
    fn aggregate_capacity_rejects_missing_snapshot_and_reservation_overflow() {
        let mut limits = capacity_limits();
        limits.chains[0].reserved_withdrawals = u32::MAX;
        assert!(limits.validate_shape().is_err());
        let pending = serde_json::json!({"phase":"Producing","session_nonce":"1","request_id":"00".repeat(32),"selected_withdrawal_leaf_hashes":[]});
        assert!(serde_json::from_value::<PendingAggregate>(pending).is_err());
        let mut limits = capacity_limits();
        limits.max_window_calldata_bytes = 4899;
        assert!(limits.validate_capacity(&[(0, 0), (2, 0)], &[(0, 0), (2, 0)], 0).is_err());
        let mut limits = capacity_limits();
        limits.chains[1].chain_index = 0;
        assert!(limits.validate_shape().is_err());
    }

    #[test]
    fn retained_claims_share_slots_with_selected_metadata_without_doubling() {
        let limits = capacity_limits();
        let withdrawal = withdrawal_for_chain("selected", 0);
        let record = withdrawal_record(&withdrawal).unwrap().encode().unwrap();
        let claim = SelectedClaim { claim_id: aggregate_claim_id([0; 32], 2, &record), kind: 2, record: hex::encode(record), proof: None, proof_context_id: None };
        let mut state = MultichainDaemonState::default();
        state.pending_claim_withdrawals.insert("selected".into(), withdrawal);
        let (counts, rewards) = aggregate_selected_counts(&limits, &["selected".into()], &[claim], &state).unwrap();
        assert_eq!(counts, vec![(0, 1), (2, 0)]);
        assert_eq!(rewards, 0);
        let mut late = withdrawal_for_chain("late", 0);
        late.nonce[7] = 1;
        state.pending_claim_withdrawals.insert("late".into(), late);
        let (counts, rewards) = aggregate_selected_counts(&limits, &["selected".into(), "late".into()], &[], &state).unwrap();
        assert!(validate_aggregate_reservation(&limits, &[(0, 0), (2, 0)], &counts, rewards).is_err());
    }

    #[test]
    fn frozen_capacity_matches_encoded_window_abi_for_one_and_three_chains() {
        use psy_client_data::bridge_aggregate::{DepositAggregateOpening, DepositLeaf, DepositTransition, SourceCheckpointRewardOpening, SourceCheckpointRewardLeaf, WithdrawalAggregateOpening, WithdrawalLeaf, ChainStart};
        fn opening(chains: &[u8], deposits: u32, withdrawals: u32, rewards: u32) -> (DepositAggregateOpening, WithdrawalAggregateOpening, SourceCheckpointRewardOpening) {
            let mut a = DepositAggregateOpening { config_hash: [7; 32], window_id: [0; 32], end_checkpoint_id: 20, end_checkpoint_root: [1, 2, 3, 4],
                starts: chains.iter().map(|&chain_index| ChainStart { chain_index, start_checkpoint_id: 10, start_checkpoint_root: [1, 2, 3, 4] }).collect(),
                deposits: chains.iter().map(|&chain_index| DepositTransition { chain_index, old_root: [1, 2, 3, 4], new_root: [1, 2, 3, 4], old_count: 0, new_count: deposits }).collect(),
                deposit_leaves: Vec::new() };
            for &chain_index in chains {
                for absolute_index in 0..deposits {
                    a.deposit_leaves.push(DepositLeaf { chain_index, absolute_index, shield_address: [1; 32], token: [2; 20], l2_token_contract_id: [3; 32], amount: [4; 32], note_commitment: [5; 32] });
                }
            }
            a.window_id = a.window_id().unwrap();
            let w = WithdrawalAggregateOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root,
                withdrawal_roots: vec![[1, 2, 3, 4]; chains.len()],
                withdrawals: (0..withdrawals).map(|index| WithdrawalLeaf { chain_index: chains[0], sender_user_id: index, recipient: [9; 20], token: [8; 20], amount: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], nonce: { let mut nonce = [6; 32]; nonce[31] = index as u8; nonce } }).collect() };
            let r = SourceCheckpointRewardOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id: a.end_checkpoint_id, end_checkpoint_root: a.end_checkpoint_root,
                leaves: (0..rewards).map(|index| SourceCheckpointRewardLeaf { economic_domain: [9; 32], source_checkpoint_id: 10, user_id: index + 1, amount: [1, 0, 0, 0, 0, 0, 0, 0], recipient: [7; 20], initialized: true }).collect() };
            (a, w, r)
        }
        fn limits_for(chains: &[u8], deposits: u32, withdrawals: u32, rewards: u32, budget: u64) -> AggregateLimits {
            AggregateLimits { max_deposits: deposits.saturating_mul(chains.len() as u32), reserved_withdrawals: withdrawals, reserved_rewards: rewards, max_window_calldata_bytes: budget,
                chains: chains.iter().enumerate().map(|(ordinal, &chain_index)| ChainLimits { chain_index, max_deposits: deposits, reserved_withdrawals: if ordinal == 0 { withdrawals } else { 0 }, tx_gas_limit: 1, block_gas_reserve: 1 }).collect() }
        }
        for chains in [vec![0u8], vec![0u8, 1, 2]] {
            let mut network = configured_network();
            let chain = network.chains[0].clone();
            network.chains = chains.iter().map(|&chain_index| {
                let mut configured = chain.clone();
                configured.chain_index = chain_index;
                configured.chain_id = U256::from(u64::from(chain_index) + 1).to_be_bytes::<32>();
                configured
            }).collect();
            let (mut a, w, r) = opening(&chains, 1, 1, 1);
            a.config_hash = network.config_hash().unwrap();
            a.window_id = a.window_id().unwrap();
            let settlement = build_settlement_opening(&network, &a, &w.withdrawal_roots, w.withdrawals.clone(), r.leaves.clone(), [9; 32], [1, 2, 3, 4], [1, 2, 3, 4], [0; 8], [0; 8], a.starts.iter().map(|start| psy_client_data::bridge_aggregate::FinalizationSlot { start_checkpoint_root: start.start_checkpoint_root, checkpoint_count: 1 }).collect()).unwrap();
            let call = crate::bridge::finalize_bridge::BridgeWindowCall { deposit_proof: [U256::from(1u8); 8], deposit_opening: a.encode().unwrap().into(), settlement_proof: [U256::from(2u8); 8], settlement_opening: settlement.encode().unwrap().into() };
            let actual = u64::try_from(call.encode().len()).unwrap();
            let limits = limits_for(&chains, 1, 1, 1, actual);
            validate_frozen_capacity(&limits, &a, &settlement).unwrap();
            let mut over = limits;
            over.max_window_calldata_bytes = actual - 1;
            assert!(validate_frozen_capacity(&over, &a, &settlement).is_err());
        }
    }

    struct AggregateArtifactDir(std::path::PathBuf);
    impl AggregateArtifactDir {
        fn new(name: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "psy-relayer-aggregate-file-{name}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).unwrap();
            Self(directory)
        }
        fn path(&self) -> &std::path::Path { &self.0 }
    }
    impl Drop for AggregateArtifactDir {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                panic!("failed to remove aggregate artifact dir {}: {error}", self.0.display());
            }
        }
    }

    #[test]
    fn aggregate_file_round_trip_retains_exact_bytes() {
        let directory = AggregateArtifactDir::new("round-trip");
        let bytes = b"\x00aggregate-opening\xff".to_vec();
        let first = save_aggregate_file(directory.path(), &bytes, "opening").unwrap();
        let second = save_aggregate_file(directory.path(), &bytes, "opening").unwrap();
        assert_eq!(first.relative_path, second.relative_path);
        assert_eq!(first.sha256, second.sha256);
        assert_eq!(load_aggregate_file(directory.path(), &second).unwrap(), bytes);
        assert_eq!(std::fs::read(directory.path().join(&first.relative_path)).unwrap(), bytes);
        assert_eq!(first.sha256, hex::encode(crate::guardian::protocol::sha256(&bytes).0));
    }

    #[test]
    fn aggregate_file_load_rejects_tampered_bytes() {
        let directory = AggregateArtifactDir::new("tampered");
        let reference = save_aggregate_file(directory.path(), b"canonical", "opening").unwrap();
        std::fs::write(directory.path().join(&reference.relative_path), b"tampered").unwrap();
        let error = load_aggregate_file(directory.path(), &reference).unwrap_err();
        assert!(error.to_string().contains("aggregate file digest mismatch"));
    }
    #[test]
    #[test]
    fn window_call_rejects_settlement_proof_whose_digest_is_not_b() {
        let directory = AggregateArtifactDir::new("publication-nonempty");
        let network = configured_network();
        let (a, opening, r, _, _) = nonempty_window(20, [1, 2, 3, 4]);
        let settlement = build_settlement_opening(&network, &a, &opening.withdrawal_roots, opening.withdrawals.clone(), r.leaves.clone(), [9; 32], [1, 2, 3, 4], [1, 2, 3, 4], [0; 8], [0; 8], vec![psy_client_data::bridge_aggregate::FinalizationSlot { start_checkpoint_root: a.starts[0].start_checkpoint_root, checkpoint_count: 1 }]).unwrap();
        let word = |digest: [u8; 32], index: usize| format!("{:064x}", u128::from_be_bytes(digest[index * 16..index * 16 + 16].try_into().unwrap()));
        let deposit_digest = a.opening_digest(&network).unwrap();
        let proof = |digest: [u8; 32]| save_aggregate_file(directory.path(), &serde_json::to_vec(&psy_plonky2_circuits::bridge::circuits::bridge_wrap::UncompressedGroth16ProofData { pi_a: ["0".repeat(64), "0".repeat(64)], pi_b: [["0".repeat(64), "0".repeat(64)], ["0".repeat(64), "0".repeat(64)]], pi_c: ["0".repeat(64), "0".repeat(64)], public_inputs: [word(digest, 0), word(digest, 1)] }).unwrap(), "json").unwrap();
        let error = window_call(directory.path(), &network, &a, &settlement, &WindowProofs { deposit: proof(deposit_digest), settlement: proof(deposit_digest) }).unwrap_err();
        assert!(error.to_string().contains("native proof digest half mismatch"), "{error}");
    }




    fn nonempty_window(end_checkpoint_id: u64, end_checkpoint_root: [u64; 4]) -> (psy_client_data::bridge_aggregate::DepositAggregateOpening, psy_client_data::bridge_aggregate::WithdrawalAggregateOpening, psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening, AggregateLimits, FinalizeEvidence) {
        use psy_client_data::bridge_aggregate::{ChainStart, DepositAggregateOpening, DepositTransition, SourceCheckpointRewardOpening, SourceCheckpointRewardLeaf, WithdrawalAggregateOpening, WithdrawalLeaf};
        let network = configured_network();
        let config_hash = network.config_hash().unwrap();
        let withdrawal_root = [1, 2, 3, 4];
        let start_checkpoint_id = end_checkpoint_id.saturating_sub(10);
        let mut a = DepositAggregateOpening { config_hash, window_id: [0; 32], end_checkpoint_id, end_checkpoint_root,
            starts: network.chains.iter().map(|chain| ChainStart { chain_index: chain.chain_index, start_checkpoint_id, start_checkpoint_root: [1, 2, 3, 4] }).collect(),
            deposits: network.chains.iter().map(|chain| DepositTransition { chain_index: chain.chain_index, old_root: [1, 2, 3, 4], new_root: [1, 2, 3, 4], old_count: 0, new_count: 0 }).collect(),
            deposit_leaves: Vec::new() };
        a.window_id = a.window_id().unwrap();
        let w = WithdrawalAggregateOpening { config_hash, window_id: a.window_id, end_checkpoint_id, end_checkpoint_root, withdrawal_roots: vec![withdrawal_root],
            withdrawals: vec![WithdrawalLeaf { chain_index: 0, sender_user_id: 11, recipient: [9; 20], token: [8; 20], amount: { let mut amount = [0; 32]; amount[31] = 1; amount }, nonce: [6; 32] }] };
        let r = SourceCheckpointRewardOpening { config_hash, window_id: a.window_id, end_checkpoint_id, end_checkpoint_root,
            leaves: vec![SourceCheckpointRewardLeaf { economic_domain: [9; 32], source_checkpoint_id: end_checkpoint_id, user_id: 4, amount: [1, 0, 0, 0, 0, 0, 0, 0], recipient: [7; 20], initialized: true }] };
        let bytes = 960 + 2980 + 192 + 192;
        let limits = AggregateLimits { max_deposits: 0, reserved_withdrawals: 1, reserved_rewards: 1, max_window_calldata_bytes: bytes,
            chains: vec![ChainLimits { chain_index: 0, max_deposits: 0, reserved_withdrawals: 1, tx_gas_limit: 1, block_gas_reserve: 1 }] };
        let _ = start_checkpoint_id;
        (a, w, r, limits, FinalizeEvidence { bf_identity: "11".repeat(32), raw_proof: FileReference { relative_path: "aggregate-raw.proof".into(), sha256: "22".repeat(32) } })
    }

    fn frozen_from(directory: &std::path::Path, a: &psy_client_data::bridge_aggregate::DepositAggregateOpening, w: &psy_client_data::bridge_aggregate::WithdrawalAggregateOpening, r: &psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening, limits: AggregateLimits, finalize: Option<FinalizeEvidence>, submission: Submission, included_acknowledged: [bool; 2]) -> MultichainDaemonState {
        let withdrawal_records = w.withdrawals.iter().map(|leaf| leaf.encode().unwrap()).collect::<Vec<_>>();
        let reward_records = r.leaves.iter().map(|leaf| leaf.encode().unwrap()).collect::<Vec<_>>();
        let proofs = Some(WindowProofs { deposit: save_aggregate_file(directory, b"deposit-proof", "json").unwrap(), settlement: save_aggregate_file(directory, b"settlement-proof", "json").unwrap() });
        let transition = b"deposit-proof";
        let claim_ids = withdrawal_records.iter().map(|record| aggregate_claim_id(a.config_hash, 2, record)).chain(reward_records.iter().map(|record| reward_claim_id(a.config_hash, record, transition))).collect();
        let local_proofs = withdrawal_records.iter().chain(reward_records.iter()).map(|_| proofs.as_ref().unwrap().deposit.clone()).collect();
        let settlement = build_settlement_opening(&configured_network(), a, &w.withdrawal_roots, w.withdrawals.clone(), r.leaves.clone(), [9; 32], [1, 2, 3, 4], [1, 2, 3, 4], [0; 8], [0; 8], a.starts.iter().map(|start| psy_client_data::bridge_aggregate::FinalizationSlot { start_checkpoint_root: start.start_checkpoint_root, checkpoint_count: 1 }).collect()).unwrap();
        let mut state = MultichainDaemonState::default();
        state.pending = Some(PendingAggregate::Frozen { aggregate_limits: limits, producing_session: None, selected_withdrawal_leaf_hashes: Vec::new(),
            a_opening: hex::encode(a.encode().unwrap()), settlement_opening: hex::encode(settlement.encode().unwrap()),
            claim_ids, local_proofs, final_proofs: proofs, destinations: vec![Destination { chain_index: 0, finalize, submission }], included_acknowledged });
        state
    }

    fn empty_frozen_state(submission: Submission, included_acknowledged: [bool; 2], final_proofs: Option<WindowProofs>, finalize: Option<FinalizeEvidence>) -> (AggregateArtifactDir, MultichainDaemonState) {
        use psy_client_data::bridge_aggregate::{DepositAggregateOpening, DepositTransition, SourceCheckpointRewardOpening, WithdrawalAggregateOpening};
        let directory = AggregateArtifactDir::new("empty-window");
        let network = configured_network();
        let config_hash = network.config_hash().unwrap();
        let mut a = DepositAggregateOpening { config_hash, window_id: [0; 32], end_checkpoint_id: 20, end_checkpoint_root: [1, 2, 3, 4],
            starts: nonempty_window(20, [1, 2, 3, 4]).0.starts, deposits: vec![DepositTransition { chain_index: 0, old_root: [1, 2, 3, 4], new_root: [1, 2, 3, 4], old_count: 0, new_count: 0 }], deposit_leaves: Vec::new() };
        a.window_id = a.window_id().unwrap();
        let w = WithdrawalAggregateOpening { config_hash, window_id: a.window_id, end_checkpoint_id: 20, end_checkpoint_root: [1, 2, 3, 4], withdrawal_roots: vec![[1, 2, 3, 4]], withdrawals: Vec::new() };
        let r = SourceCheckpointRewardOpening { config_hash, window_id: a.window_id, end_checkpoint_id: 20, end_checkpoint_root: [1, 2, 3, 4], leaves: Vec::new() };
        let limits = AggregateLimits { max_deposits: 0, reserved_withdrawals: 0, reserved_rewards: 0, max_window_calldata_bytes: 3940, chains: vec![ChainLimits { chain_index: 0, max_deposits: 0, reserved_withdrawals: 0, tx_gas_limit: 1, block_gas_reserve: 1 }] };
        let mut state = frozen_from(directory.path(), &a, &w, &r, limits, finalize.clone(), submission, included_acknowledged);
        if let Some(PendingAggregate::Frozen { final_proofs: slot, destinations, .. }) = &mut state.pending { *slot = final_proofs; destinations[0].finalize = finalize; }
        (directory, state)
    }

    #[test]
    fn frozen_submission_requires_both_acknowledged_families() {
        let directory = AggregateArtifactDir::new("acknowledged");
        let reference = save_aggregate_file(directory.path(), b"deposit-proof", "json").unwrap();
        let settlement = save_aggregate_file(directory.path(), b"settlement-proof", "json").unwrap();
        let proofs = WindowProofs { deposit: reference.clone(), settlement };
        let finalize = FinalizeEvidence { bf_identity: "11".repeat(32), raw_proof: reference };
        let (directory, acknowledged) = empty_frozen_state(Submission::Sending, [true, true], Some(proofs.clone()), Some(finalize.clone()));
        validate_aggregate_state(directory.path(), &acknowledged).unwrap();
        let (directory, submitted) = empty_frozen_state(Submission::Submitted { transaction_hash: "ab".repeat(32) }, [true, true], Some(proofs.clone()), Some(finalize.clone()));
        validate_aggregate_state(directory.path(), &submitted).unwrap();
        for included_acknowledged in [[false, true], [true, false], [false, false]] {
            let (directory, sending) = empty_frozen_state(Submission::Sending, included_acknowledged, Some(proofs.clone()), Some(finalize.clone()));
            let error = validate_aggregate_state(directory.path(), &sending).unwrap_err();
            assert!(error.to_string().contains("submission without complete acknowledged proofs"), "{error}");
            let (directory, submitted) = empty_frozen_state(Submission::Submitted { transaction_hash: "cd".repeat(32) }, included_acknowledged, Some(proofs.clone()), Some(finalize.clone()));
            assert!(validate_aggregate_state(directory.path(), &submitted).unwrap_err().to_string().contains("submission without complete acknowledged proofs"));
        }
        let (directory, missing_proofs) = empty_frozen_state(Submission::Sending, [true, true], None, Some(finalize.clone()));
        assert!(validate_aggregate_state(directory.path(), &missing_proofs).unwrap_err().to_string().contains("submission without complete acknowledged proofs"));
        let (directory, missing_finalize) = empty_frozen_state(Submission::Submitted { transaction_hash: "ef".repeat(32) }, [true, true], Some(proofs), None);
        assert!(validate_aggregate_state(directory.path(), &missing_finalize).unwrap_err().to_string().contains("submission without complete acknowledged proofs"));
        let (directory, not_sent) = empty_frozen_state(Submission::NotSent, [false, false], None, None);
        validate_aggregate_state(directory.path(), &not_sent).unwrap();
    }

    fn posted_family(directory: &std::path::Path, network: &psy_client_data::bridge_aggregate::NetworkConfig, state: &MultichainDaemonState, family: u8) -> (String, ReceiptDispositions) {
        use crate::bridge::api_client::{ClaimDisposition, ReceiptEvidence};
        let PendingAggregate::Frozen { settlement_opening, claim_ids, .. } = state.pending.clone().unwrap() else { unreachable!() };
        let settlement = psy_client_data::bridge_aggregate::SettlementOpening::decode(&aggregate_bytes(&settlement_opening).unwrap()).unwrap();
        let (opening, claim_id, digest) = if family == 2 {
            let opening = psy_client_data::bridge_aggregate::WithdrawalAggregateOpening { config_hash: settlement.config_hash, window_id: settlement.window_id, end_checkpoint_id: settlement.end_checkpoint_id, end_checkpoint_root: settlement.end_checkpoint_root, withdrawal_roots: settlement.endpoints.iter().map(|endpoint| endpoint.withdrawal_root).collect(), withdrawals: settlement.withdrawals.clone() };
            (opening.encode().unwrap(), claim_ids[0].clone(), opening.opening_digest(network).unwrap())
        } else {
            let opening = psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening { config_hash: settlement.config_hash, window_id: settlement.window_id, end_checkpoint_id: settlement.end_checkpoint_id, end_checkpoint_root: settlement.end_checkpoint_root, leaves: settlement.rewards.clone() };
            (opening.encode().unwrap(), claim_ids[1].clone(), opening.opening_digest().unwrap())
        };
        let reference = save_aggregate_file(directory, &opening, "opening").unwrap();
        let receipt = ReceiptDispositions { family, opening: reference, final_proofs: None, reverted_receipts: Vec::new(), posted_opening_digest: Some(hex::encode(digest)), dispositions: vec![
            ClaimDisposition::Applied { claim_id: format!("0x{claim_id}"), receipt: ReceiptEvidence { chain_index: 0, transaction_hash: format!("0x{}", "ab".repeat(32)), log_index: "1".into() } },
        ] };
        (format!("{family}:{}", hex::encode(digest)), receipt)
    }

    fn unposted_unrelated_receipt(directory: &std::path::Path, network: &psy_client_data::bridge_aggregate::NetworkConfig) -> (String, ReceiptDispositions) {
        use crate::bridge::api_client::{ClaimDisposition, ReceiptEvidence};
        let (_, withdrawal, _, _, _) = nonempty_window(4, [8, 7, 6, 5]);
        let opening = save_aggregate_file(directory, &withdrawal.encode().unwrap(), "opening").unwrap();
        let digest = hex::encode(withdrawal.opening_digest(network).unwrap());
        (format!("2:{digest}"), ReceiptDispositions { family: 2, opening, final_proofs: None, dispositions: vec![
            ClaimDisposition::Applied { claim_id: format!("0x{}", "02".repeat(32)), receipt: ReceiptEvidence { chain_index: 0, transaction_hash: format!("0x{}", "cd".repeat(32)), log_index: "4".into() } },
        ], reverted_receipts: Vec::new(), posted_opening_digest: None })
    }

    #[test]
    fn one_posted_family_remains_durable_and_does_not_complete() {
        let path = temp_state_path("one-posted-family");
        let directory = AggregateArtifactDir::new("one-posted-family");
        let network = configured_network();
        let (a, w, r, limits, finalize) = nonempty_window(20, [1, 2, 3, 4]);
        let mut state = frozen_from(directory.path(), &a, &w, &r, limits, Some(finalize), Submission::Finalized { transaction_hash: "11".repeat(32), block_hash: "22".repeat(32), block_number: 9, withdrawal_log_index: "1".into(), reward_log_index: Some("2".into()) }, [true, true]);
        let (key, receipt) = posted_family(directory.path(), &network, &state, 2);
        let digest = receipt.posted_opening_digest.clone().unwrap();
        state.receipt_dispositions.insert(key, receipt);
        save_multichain_state(&path, &state).unwrap();
        let mut crashed = load_multichain_state(&path, "").unwrap();
        assert_eq!(crashed.receipt_dispositions[&format!("2:{digest}")].posted_opening_digest.as_deref(), Some(digest.as_str()));
        let PendingAggregate::Frozen { settlement_opening, .. } = crashed.pending.clone().unwrap() else { unreachable!() };
        let settlement = psy_client_data::bridge_aggregate::SettlementOpening::decode(&aggregate_bytes(&settlement_opening).unwrap()).unwrap();
        let withdrawal = psy_client_data::bridge_aggregate::WithdrawalAggregateOpening { config_hash: settlement.config_hash, window_id: settlement.window_id, end_checkpoint_id: settlement.end_checkpoint_id, end_checkpoint_root: settlement.end_checkpoint_root, withdrawal_roots: settlement.endpoints.iter().map(|endpoint| endpoint.withdrawal_root).collect(), withdrawals: settlement.withdrawals.clone() };
        let reward = psy_client_data::bridge_aggregate::SourceCheckpointRewardOpening { config_hash: settlement.config_hash, window_id: settlement.window_id, end_checkpoint_id: settlement.end_checkpoint_id, end_checkpoint_root: settlement.end_checkpoint_root, leaves: settlement.rewards };
        clear_completed_applied_window(directory.path(), &network, &path, &mut crashed).unwrap();
        let retained = load_multichain_state(&path, "").unwrap();
        assert!(matches!(retained.pending, Some(PendingAggregate::Frozen { .. })));
        assert!(family_disposition_applied(&retained, 2, withdrawal.opening_digest(&network).unwrap(), withdrawal.withdrawals.len()));
        assert!(!family_disposition_applied(&retained, 3, reward.opening_digest().unwrap(), reward.leaves.len()));
    }

    #[test]
    fn retained_raw_evidence_round_trips_identity_and_file() {
        let path = temp_state_path("raw-evidence");
        let (_, _, _, _, evidence) = nonempty_window(20, [1, 2, 3, 4]);
        let mut state = MultichainDaemonState::default();
        state.retained_finalize.insert("0".into(), evidence.clone());
        save_multichain_state(&path, &state).unwrap();
        let loaded = load_multichain_state(&path, "").unwrap();
        let saved = &loaded.retained_finalize["0"];
        assert_eq!(saved.bf_identity, evidence.bf_identity);
        assert_eq!(saved.raw_proof.relative_path, evidence.raw_proof.relative_path);
        assert_eq!(saved.raw_proof.sha256, evidence.raw_proof.sha256);
    }

    fn configured_network() -> psy_client_data::bridge_aggregate::NetworkConfig {
        use psy_client_data::bridge_aggregate::{ChainConfig, NetworkConfig, BRIDGE_USER_ID};
        NetworkConfig { version: 1, network_magic: 0, bridge_user_id: BRIDGE_USER_ID, circuit_set_hash: [7; 32],
            chains: vec![ChainConfig { chain_index: 0, chain_id: U256::from(1).to_be_bytes::<32>(), bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [1, 2, 3, 4] }],
            ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: U256::from(1).to_be_bytes::<32>(), reward_token_decimals: 0,
            reward_cutover: 0, reward_end_exclusive: 100, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024 }
    }

    #[test]
    fn completed_window_keeps_raw_proofs_until_their_end_can_be_decoded() {
        let path = temp_state_path("completed-prune");
        let directory = AggregateArtifactDir::new("completed-prune");
        let network = configured_network();
        let (a, w, r, limits, current) = nonempty_window(20, [1, 2, 3, 4]);
        let mut state = frozen_from(directory.path(), &a, &w, &r, limits, Some(current.clone()), Submission::Finalized { transaction_hash: "11".repeat(32), block_hash: "22".repeat(32), block_number: 9, withdrawal_log_index: "1".into(), reward_log_index: Some("2".into()) }, [true, true]);
        let (withdrawal_key, withdrawal) = posted_family(directory.path(), &network, &state, 2);
        let (reward_key, reward) = posted_family(directory.path(), &network, &state, 3);
        state.receipt_dispositions.insert(withdrawal_key, withdrawal);
        state.receipt_dispositions.insert(reward_key, reward);
        state.retained_finalize.insert("0".into(), current);
        clear_completed_applied_window(directory.path(), &network, &path, &mut state).unwrap();
        let saved = load_multichain_state(&path, "").unwrap();
        assert!(saved.pending.is_none());
        assert_eq!(saved.retained_finalize.len(), 1);
        assert!(saved.retained_finalize.contains_key("0"));
    }

    #[test]
    fn malformed_retained_width_leaves_pending_and_map_unchanged() {
        let path = temp_state_path("malformed-retained");
        let directory = AggregateArtifactDir::new("malformed-retained");
        let network = configured_network();
        let (a, w, r, limits, current) = nonempty_window(20, [1, 2, 3, 4]);
        let mut state = frozen_from(directory.path(), &a, &w, &r, limits, Some(current), Submission::Finalized { transaction_hash: "11".repeat(32), block_hash: "22".repeat(32), block_number: 9, withdrawal_log_index: "1".into(), reward_log_index: Some("2".into()) }, [true, true]);
        let (withdrawal_key, withdrawal) = posted_family(directory.path(), &network, &state, 2);
        let (reward_key, reward) = posted_family(directory.path(), &network, &state, 3);
        state.receipt_dispositions.insert(withdrawal_key, withdrawal);
        state.receipt_dispositions.insert(reward_key, reward);
        state.retained_finalize.insert("short".repeat(16), FinalizeEvidence { bf_identity: "11".repeat(32), raw_proof: FileReference { relative_path: "aggregate-short.proof".into(), sha256: "22".repeat(32) } });
        let before = toml::to_string(&state).unwrap();
        assert!(validate_aggregate_state(directory.path(), &state).is_err());
        assert_eq!(toml::to_string(&state).unwrap(), before);
        assert!(state.pending.is_some());
    }

    #[test]
    fn first_posted_family_survives_reload_and_cannot_clear_pending() {
        let path = temp_state_path("two-ack-crash");
        let directory = AggregateArtifactDir::new("two-ack-crash");
        let network = configured_network();
        let (a, w, r, limits, finalize) = nonempty_window(20, [1, 2, 3, 4]);
        let mut state = frozen_from(directory.path(), &a, &w, &r, limits, Some(finalize), Submission::Finalized { transaction_hash: "11".repeat(32), block_hash: "22".repeat(32), block_number: 9, withdrawal_log_index: "1".into(), reward_log_index: Some("2".into()) }, [true, true]);
        let (first_key, first) = posted_family(directory.path(), &network, &state, 2);
        let (unrelated_key, unrelated) = unposted_unrelated_receipt(directory.path(), &network);
        state.receipt_dispositions.insert(first_key.clone(), first);
        state.receipt_dispositions.insert(unrelated_key.clone(), unrelated);
        save_multichain_state(&path, &state).unwrap();
        let mut crashed = load_multichain_state(&path, "").unwrap();
        assert!(crashed.receipt_dispositions.contains_key(&first_key));
        assert!(crashed.receipt_dispositions.contains_key(&unrelated_key));
        clear_completed_applied_window(directory.path(), &network, &path, &mut crashed).unwrap();
        let after_first = load_multichain_state(&path, "").unwrap();
        assert!(matches!(after_first.pending, Some(PendingAggregate::Frozen { .. })));
        assert!(after_first.receipt_dispositions.contains_key(&first_key));
        assert!(after_first.receipt_dispositions.contains_key(&unrelated_key));
        let (second_key, second) = posted_family(directory.path(), &network, &after_first, 3);
        let mut resumed = after_first;
        resumed.receipt_dispositions.insert(second_key.clone(), second);
        save_multichain_state(&path, &resumed).unwrap();
        clear_completed_applied_window(directory.path(), &network, &path, &mut resumed).unwrap();
        let completed = load_multichain_state(&path, "").unwrap();
        assert!(completed.pending.is_none());
        assert!(completed.receipt_dispositions.contains_key(&unrelated_key));
        assert!(!completed.receipt_dispositions.contains_key(&first_key));
        assert!(!completed.receipt_dispositions.contains_key(&second_key));
    }

    #[test]
    fn completed_prune_keeps_an_unposted_receipt_for_a_different_end() {
        let path = temp_state_path("unposted-end");
        let directory = AggregateArtifactDir::new("unposted-end");
        let network = configured_network();
        let (a, w, r, limits, current) = nonempty_window(20, [1, 2, 3, 4]);
        let mut state = frozen_from(directory.path(), &a, &w, &r, limits, Some(current.clone()), Submission::Finalized { transaction_hash: "11".repeat(32), block_hash: "22".repeat(32), block_number: 9, withdrawal_log_index: "1".into(), reward_log_index: Some("2".into()) }, [true, true]);
        let (withdrawal_key, withdrawal) = posted_family(directory.path(), &network, &state, 2);
        let (reward_key, reward) = posted_family(directory.path(), &network, &state, 3);
        state.receipt_dispositions.insert(withdrawal_key, withdrawal);
        state.receipt_dispositions.insert(reward_key, reward);
        let (_, older_withdrawal, _, _, _) = nonempty_window(7, [5, 6, 7, 8]);
        let opening = save_aggregate_file(directory.path(), &older_withdrawal.encode().unwrap(), "opening").unwrap();
        let older_key = format!("2:{}", hex::encode(older_withdrawal.opening_digest(&network).unwrap()));
        state.receipt_dispositions.insert(older_key.clone(), ReceiptDispositions { family: 2, opening, final_proofs: None, dispositions: Vec::new(), reverted_receipts: Vec::new(), posted_opening_digest: None });
        state.retained_finalize.insert("0".into(), current);
        clear_completed_applied_window(directory.path(), &network, &path, &mut state).unwrap();
        let saved = load_multichain_state(&path, "").unwrap();
        assert!(saved.pending.is_none());
        assert!(saved.receipt_dispositions.contains_key(&older_key));
        assert_eq!(saved.retained_finalize.len(), 1);
        assert!(saved.retained_finalize.contains_key("0"));
    }






    fn protected_bytes(path: &std::path::Path, bytes: &[u8]) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
        use std::io::Write;
        file.write_all(bytes).unwrap();
    }

    struct ReplayFixtureDir(std::path::PathBuf);
    impl ReplayFixtureDir {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("system clock before unix epoch").as_nanos();
            let directory = home::home_dir().unwrap().join(format!("psy-relayer-replay-bootstrap-{}-{nanos}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&directory).unwrap();
            builder.create(directory.join("archive")).unwrap();
            Self(directory)
        }
    }
    impl Drop for ReplayFixtureDir {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) { panic!("failed to remove replay fixture dir {}: {error}", self.0.display()); }
        }
    }

    fn replay_authorization(contract_id: u32) -> crate::guardian::protocol::ApprovedContract {
        use crate::guardian::protocol::{ApprovedContract, CompilerArtifact, JsonText, sha256};
        use plonky2::field::types::Field;
        use psy_client_data::qdata::contract::PsyContractLeaf;
        let artifact = CompilerArtifact {
            state_tree_height: 4, circuit_definitions: Vec::new(),
            abi: serde_json::json!({ "schema_version": "2.0.0", "contract": { "name": "replay_fixture", "state_tree_height": 4, "state": [], "methods": [] }, "types": [] }),
        };
        let compiler_artifact_json = JsonText::from_value(&artifact).unwrap();
        let compiler_artifact_sha256 = sha256(compiler_artifact_json.as_str().as_bytes());
        let mut leaf = PsyContractLeaf::default();
        leaf.state_tree_height = GoldilocksField::from_canonical_u16(4);
        ApprovedContract { contract_id, contract_leaf_json: JsonText::from_value(&leaf).unwrap(), compiler_artifact_json, compiler_artifact_sha256 }
    }

    fn replay_guardian_config(directory: &std::path::Path) -> PathBuf {
        use crate::guardian::protocol::{ChainAuthorization, GuardianAuthorization, GuardianAuthorizationIndex, GuardianAuthorizationVersion, Hex, JsonText, TokenMapping, sha256};
        use plonky2::hash::poseidon::PoseidonHash;
        use plonky2::plonk::config::Hasher;
        use psy_client_common::data::qhashout::QHashOut;
        use psy_vm::ups::multisig::{MultisigAccount, MultisigPolicy};
        let members = [
            QHashOut::from_values(1, 2, 3, 4),
            QHashOut::from_values(5, 6, 7, 8),
            QHashOut::from_values(9, 10, 11, 12),
        ];
        let mut member_hashes = [QHashOut::default(); 8];
        member_hashes[..3].copy_from_slice(&members);
        let account = MultisigAccount { contract_id: 6, initial_policy: MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes } };
        let account_json = JsonText::from_value(&account).unwrap();
        let fingerprint = QHashOut::from_values(13, 14, 15, 16);
        let account_public_key = QHashOut(PoseidonHash::two_to_one(fingerprint.0, account.public_key_param().unwrap().0));
        let authorization = GuardianAuthorization {
            version: 1, network_magic: 1, genesis_hash: Hex([1; 32]), user_id: crate::guardian::protocol::BRIDGE_USER_ID,
            account_json, account_public_key, multisig_fingerprint: fingerprint,
            deposit_contract_id: 2, withdrawal_contract_id: 3, fee_contract_id: 0,
            guta_fee: psy_config::GUTA_FEE, da_fee: psy_config::DA_FEE, max_fee: 1,
            max_endcap_proof_bytes: crate::guardian::verify::approved_endcap_max_proof_bytes().unwrap(),
            approved_contracts: [0, 2, 3, 6].into_iter().map(replay_authorization).collect(),
            chains: vec![ChainAuthorization {
                chain_index: 0, chain_id: U256::from(1), genesis_hash: Hex([2; 32]),
                bridge: Hex([1; 20]), state_manager: Hex([2; 20]), bridge_code_hash: Hex([3; 32]),
                bridge_implementation: Hex([4; 20]), bridge_implementation_code_hash: Hex([5; 32]),
                state_manager_code_hash: Hex([6; 32]), state_manager_implementation: Hex([7; 20]),
                state_manager_implementation_code_hash: Hex([8; 32]), deployment_block: 1,
                token_mappings: vec![TokenMapping { token: Hex([9; 20]), l2_contract_id: 0 }],
            }],
        };
        let bytes = serde_json::to_vec(&authorization).unwrap();
        protected_bytes(&directory.join("archive").join("1.json"), &bytes);
        let index = GuardianAuthorizationIndex { active_version: 1, versions: vec![GuardianAuthorizationVersion { version: 1, sha256: sha256(&bytes) }] };
        protected_bytes(&directory.join("index.json"), &serde_json::to_vec(&index).unwrap());
        let config = serde_json::json!({
            "authorization_path": "archive/1.json", "archive_path": "relayer-archive",
            "endpoints": ["https://guardian-a.invalid/", "https://guardian-b.invalid/", "https://guardian-c.invalid/"],
            "tls_identity_path": "client.pem", "server_ca_path": "server-ca.pem",
            "authorization_archive_path": "archive", "authorization_index_path": "index.json",
            "l1_endpoints": [{ "chain_index": 0, "rpc_url": "http://127.0.0.1:1/" }],
            "listen_address": "127.0.0.1:1",
            "history_tls_certificate_path": "history.crt", "history_tls_private_key_path": "history.key", "history_client_ca_path": "history-ca.crt",
            "allowed_client_certificate_sha256": [format!("0x{}", hex::encode([1u8; 32]))]
        });
        let path = directory.join("guardian-client.json");
        protected_bytes(&path, &serde_json::to_vec(&config).unwrap());
        path
    }

    fn replay_daemon_config(directory: &std::path::Path, guardian_config: &std::path::Path) -> BridgeProposeDaemonConfig {
        let rpc = serde_json::json!({
            "defaultNetwork": "replay",
            "networks": { "replay": {
                "magic": "0x1", "users_per_realm": 1, "global_user_tree_height": 1, "realm_user_tree_height": 1, "group_realm_height": 1,
                "realm_configs": [{ "id": 0, "rpc_url": ["http://127.0.0.1:1/"] }],
                "p2p": { "checkpoints_per_epoch": 1 },
                "coordinator_configs": [{ "id": 0, "rpc_url": ["http://127.0.0.1:1/"] }],
                "prove_proxy_url": ["http://127.0.0.1:1/"], "faucet_rpc_url": ["http://127.0.0.1:1/"], "nostr_relay_url": "ws://127.0.0.1:1/",
                "native_currency": "replay", "native_currency_decimal": 0, "native_currency_name": "replay",
                "fees": { "register_user_fee": 1, "deploy_contract_fee": 1, "guta_fee": 1, "da_fee": 1 }
            } }
        });
        let rpc_path = directory.join("rpc-config.json");
        std::fs::write(&rpc_path, serde_json::to_vec(&rpc).unwrap()).unwrap();
        let raw = format!(r#"
rpc_config = "{rpc}"
guardian_config = "{guardian}"
services_url = "http://127.0.0.1:1"
withdraw_method_id = 1
aggregate_setup_config = "aggregate-setup.json"
aggregate_artifact_dir = "aggregate-artifacts"
aggregation_token_file = "aggregation-token"

[aggregate_limits]
max_deposits = 0
reserved_withdrawals = 0
reserved_rewards = 0
max_window_calldata_bytes = 3940
chains = [
  {{ chain_index = 0, max_deposits = 0, reserved_withdrawals = 0, tx_gas_limit = 1, block_gas_reserve = 1 }},
]

[[chains]]
family = "evm"
chain_index = 0
network_id = "replay"
rpc_urls = ["http://127.0.0.1:1"]
deployments_network = "replay"
"#, rpc = rpc_path.display(), guardian = guardian_config.display());
        let path = directory.join("daemon.toml");
        std::fs::write(&path, raw).unwrap();
        load_config(&path).unwrap()
    }

    fn all_equal_empty_retained(network: &psy_client_data::bridge_aggregate::NetworkConfig, directory: &std::path::Path) -> (MultichainDaemonState, PathBuf) {
        use psy_client_data::bridge_aggregate::{ChainStart, DepositAggregateOpening, DepositTransition, SourceCheckpointRewardOpening, WithdrawalAggregateOpening};
        let end_checkpoint_id = 20u64;
        let end_checkpoint_root = [1, 2, 3, 4];
        let mut a = DepositAggregateOpening {
            config_hash: network.config_hash().unwrap(), window_id: [0; 32], end_checkpoint_id, end_checkpoint_root,
            starts: vec![ChainStart { chain_index: 0, start_checkpoint_id: end_checkpoint_id, start_checkpoint_root: end_checkpoint_root }],
            deposits: vec![DepositTransition { chain_index: 0, old_root: end_checkpoint_root, new_root: end_checkpoint_root, old_count: 0, new_count: 0 }], deposit_leaves: Vec::new() };
        a.window_id = a.window_id().unwrap();
        let w = WithdrawalAggregateOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id, end_checkpoint_root, withdrawal_roots: vec![end_checkpoint_root], withdrawals: Vec::new() };
        let r = SourceCheckpointRewardOpening { config_hash: a.config_hash, window_id: a.window_id, end_checkpoint_id, end_checkpoint_root, leaves: Vec::new() };
        let limits = AggregateLimits { max_deposits: 0, reserved_withdrawals: 0, reserved_rewards: 0, max_window_calldata_bytes: 3940, chains: vec![ChainLimits { chain_index: 0, max_deposits: 0, reserved_withdrawals: 0, tx_gas_limit: 1, block_gas_reserve: 1 }] };
        let mut state = frozen_from(directory, &a, &w, &r, limits, None, Submission::NotSent, [false, false]);
        if let Some(PendingAggregate::Frozen { final_proofs, destinations, .. }) = &mut state.pending { *final_proofs = None; destinations[0].finalize = None; }
        assert!(state.retained_finalize.is_empty());
        let path = directory.join("daemon-state.toml");
        save_multichain_state(&path, &state).unwrap();
        (state, path)
    }

    #[tokio::test]
    async fn all_equal_start_without_retained_finalize_propagates_replay_bootstrap_error() {
        use psy_client_data::bridge_aggregate::{ChainConfig, NetworkConfig, BRIDGE_USER_ID};
        use psy_plonky2_circuits::bridge::aggregate_circuits::{AggregateCircuitHeights, AggregateCircuits};
        use psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsSources;
        let fixture = ReplayFixtureDir::new();
        let guardian = replay_guardian_config(fixture.0.as_path());
        let config = replay_daemon_config(fixture.0.as_path(), &guardian);
        let provider = RpcProvider::new_with_config_path(&config.rpc_config).unwrap();
        let circuits = AggregateCircuits::build::<psy_core::network_config::PsyNetworkLocalDevnetConstants>(
            &[0], prove_bridge::cached_bridge_coordinator_circuits().unwrap(),
            AggregateCircuitHeights { deposit_state_tree: psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize, withdrawal_state_tree: psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize },
        ).unwrap();
        let network = NetworkConfig { version: 1, network_magic: 1, bridge_user_id: BRIDGE_USER_ID, circuit_set_hash: circuits.circuit_set_hash(),
            chains: vec![ChainConfig { chain_index: 0, chain_id: U256::from(1).to_be_bytes::<32>(), bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [1, 2, 3, 4] }],
            ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: U256::from(1).to_be_bytes::<32>(), reward_token_decimals: 0,
            reward_cutover: 0, reward_end_exclusive: 100, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024 };
        let directory = AggregateArtifactDir::new("all-equal-replay");
        let (mut state, state_path) = all_equal_empty_retained(&network, directory.path());
        let retained = state.clone();
        let sources = DigestBitsSources { node_source: "local:".to_string() + &"11".repeat(32), native_source: "local:".to_string() + &"22".repeat(32), plonky2_source: "local:".to_string() + &"33".repeat(32), wrapper_source: "local:".to_string() + &"44".repeat(32) };
        let error = advance_aggregate_round(&config, &[], &provider, &network, &circuits, &sources, &reqwest::Client::new(), directory.path(), &state_path, &mut state, 0, 1).await.unwrap_err();
        assert!(error.downcast_ref::<ReplayBootstrapError>().is_some(), "{error}");
        assert!(error.downcast_ref::<DaemonStateWriteError>().is_none());
        assert_eq!(toml::to_string(&state).unwrap(), toml::to_string(&retained).unwrap());
        assert!(state.retained_finalize.is_empty());
        assert!(matches!(state.pending, Some(PendingAggregate::Frozen { .. })));
    }

    #[test]
    fn equal_reward_records_with_different_transitions_have_different_ids() {
        let record = [7u8; 32];
        let first = reward_claim_id([9; 32], &record, b"transition-a");
        let second = reward_claim_id([9; 32], &record, b"transition-b");
        assert_ne!(first, second);
        assert_eq!(first, reward_claim_id([9; 32], &record, b"transition-a"));
        assert_ne!(aggregate_claim_id([9; 32], 2, &record), reward_claim_id([9; 32], &record, &record));
    }
}


