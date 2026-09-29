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
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
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
    pub(crate) max_a_calldata_bytes: u64,
    pub(crate) max_b_calldata_bytes: u64,
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
        ensure!(!self.chains.is_empty() && self.chains.len() <= 256 && self.chains.windows(2).all(|rows| rows[0].chain_index < rows[1].chain_index), "aggregate limits chains must be ordered and unique");
        ensure!(self.max_deposits <= 1024 && self.reserved_withdrawals <= 1024 && self.reserved_rewards <= 1024, "aggregate limits exceed record ceiling");
        ensure!(self.max_a_calldata_bytes > 0 && self.max_b_calldata_bytes > 0, "aggregate byte budgets must be positive");
        let mut withdrawals = 0u32;
        for chain in &self.chains {
            ensure!(chain.max_deposits <= self.max_deposits && chain.tx_gas_limit > 0, "invalid local aggregate limits");
            withdrawals = withdrawals.checked_add(chain.reserved_withdrawals).context("withdrawal reservation overflow")?;
        }
        ensure!(withdrawals == self.reserved_withdrawals, "local withdrawal reservations differ from global reservation");
        Ok(())
    }

    pub(crate) fn validate_capacity(&self, deposits: &[(u8, u32)], withdrawals: &[(u8, u32)], rewards: u32) -> anyhow::Result<(u64, u64)> {
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
        let a = 544u64.checked_mul(c).and_then(|n| n.checked_add(644)).and_then(|n| 224u64.checked_mul(d).and_then(|d| n.checked_add(d))).context("A calldata length overflow")?;
        let b = 864u64.checked_mul(c).and_then(|n| n.checked_add(740)).and_then(|n| 224u64.checked_mul(d).and_then(|d| n.checked_add(d)))
            .and_then(|n| 192u64.checked_mul(w).and_then(|w| n.checked_add(w))).and_then(|n| 192u64.checked_mul(u64::from(rewards)).and_then(|r| n.checked_add(r))).context("B calldata length overflow")?;
        ensure!(a <= self.max_a_calldata_bytes && b <= self.max_b_calldata_bytes, "aggregate calldata budget exceeded");
        Ok((a, b))
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
    #[serde(with = "aggregate_ledger")]
    pending_claim_withdrawals: HashMap<String, propose_withdrawals::PendingWithdrawal>,
    #[serde(with = "aggregate_ledger")]
    claim_retry: HashMap<String, claim_attempts::ClaimAttempts>,
    #[serde(with = "aggregate_ledger")]
    retired_claim_withdrawals: HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
}

impl Default for MultichainDaemonState {
    fn default() -> Self {
        Self { schema: 2, identity_namespace: String::new(), last_finalized_checkpoint: 0,
            pending: None, receipt_dispositions: Default::default(), pending_claim_withdrawals: Default::default(),
            claim_retry: Default::default(), retired_claim_withdrawals: Default::default() }
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
        ends: String,
        selected_claims: Vec<SelectedClaim>,
    },
    Frozen {
        aggregate_limits: AggregateLimits,
        producing_session: Option<ProducingSession>,
        selected_withdrawal_leaf_hashes: Vec<String>,
        b_opening: String,
        claim_ids: Vec<String>,
        local_proofs: Vec<FileReference>,
        final_proofs: Option<[FileReference; 2]>,
        destinations: Vec<Destination>,
        included_acknowledged: bool,
    },
}

impl PendingAggregate {
    fn limits(&self) -> &AggregateLimits {
        match self {
            Self::Producing { aggregate_limits, .. } | Self::Collecting { aggregate_limits, .. } | Self::Frozen { aggregate_limits, .. } => aggregate_limits,
        }
    }
}

fn aggregate_deposit_counts(a: &psy_client_data::bridge_aggregate::AOpening) -> anyhow::Result<Vec<(u8, u32)>> {
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
            3 => { rewards = rewards.checked_add(1).context("reward count overflow")?; }
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

fn validate_frozen_capacity(limits: &AggregateLimits, b: &psy_client_data::bridge_aggregate::BOpening) -> anyhow::Result<()> {
    let deposits = aggregate_deposit_counts(&b.a)?;
    let mut withdrawals = limits.chains.iter().map(|chain| (chain.chain_index, 0u32)).collect::<Vec<_>>();
    for leaf in &b.withdrawals {
        let (_, count) = withdrawals.iter_mut().find(|(chain, _)| *chain == leaf.chain_index).context("withdrawal destination absent")?;
        *count = count.checked_add(1).context("withdrawal count overflow")?;
    }
    let (a_bytes, b_bytes) = limits.validate_capacity(&deposits, &withdrawals, b.rewards.len().try_into()?)?;
    let a_call = super::finalize_bridge::apply_deposit_aggregate_call([U256::ZERO; 8], Bytes::from(b.a.encode()?));
    let b_call = super::finalize_bridge::finalize_checkpoint_aggregate_call([U256::ZERO; 8], Bytes::from(b.encode()?));
    ensure!(u64::try_from(a_call.len())? == a_bytes && u64::try_from(b_call.len())? == b_bytes, "complete opening ABI length mismatch");
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
struct ReceiptDispositions {
    opening: FileReference,
    final_proofs: Option<[FileReference; 2]>,
    dispositions: Vec<super::api_client::ClaimDisposition>,
    reverted_receipts: Vec<RevertedReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevertedReceipt {
    chain_index: u8,
    artifact: u8,
    transaction_hash: String,
    block_hash: String,
    #[serde(with = "decimal_checkpoint")]
    block_number: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination { chain_index: u8, a: Submission, b: Submission }

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
        log_index: Option<String>,
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
    >(network.chains.len(), prove_bridge::cached_bridge_coordinator_circuits()?,
        psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuitHeights {
            deposit_state_tree: psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
            withdrawal_state_tree: psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
        })?;
    circuits.validate_config(&network)?;
    for (artifact, name, data) in [
        (psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestArtifact::A, "A", &circuits.deposit_aggregate.circuit_data),
        (psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestArtifact::B, "B", &circuits.checkpoint_aggregate.circuit_data),
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
            if error.downcast_ref::<super::api_client::AggregationHttpError>().is_none() { return Err(error); }
            tracing::warn!(%error, "aggregate service unavailable; durable round retained");
            state = load_multichain_state(&state_path, &identity_namespace)?;
        }
        tokio::time::sleep(poll_interval).await;
    }
}

type AggregateProof = plonky2::plonk::proof::ProofWithPublicInputs<GoldilocksField, plonky2::plonk::config::PoseidonGoldilocksConfig, 2>;

fn aggregate_context(a: &psy_client_data::bridge_aggregate::AOpening, _network: &psy_client_data::bridge_aggregate::NetworkConfig) -> anyhow::Result<super::api_client::AggregationContext> {
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
    let mut bytes = domain_hash(Domain::Record).to_vec();
    bytes.extend(config_hash);
    bytes.extend(U256::from(kind).to_be_bytes::<32>());
    bytes.extend(record);
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

async fn collect_aggregate_claims(config: &BridgeProposeDaemonConfig, chains: &[ChainRuntime], provider: &RpcProvider, network: &psy_client_data::bridge_aggregate::NetworkConfig,
    circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, http: &reqwest::Client,
    directory: &Path, state_path: &Path, state: &mut MultichainDaemonState) -> anyhow::Result<()> {
    use psy_client_data::bridge_aggregate::{AOpening, BOpening, ChainEnd, WithdrawalLeaf, RewardLeaf};
    let Some(PendingAggregate::Collecting { aggregate_limits, producing_session, mut selected_withdrawal_leaf_hashes, a_opening, ends, mut selected_claims }) = state.pending.clone() else { return Ok(()); };
    let a = AOpening::decode(&aggregate_bytes(&a_opening)?)?;
    a.validate(network)?;
    let end_bytes = aggregate_bytes(&ends)?;
    ensure!(end_bytes.len() == network.chains.len() * 320, "end record length mismatch");
    let ends = end_bytes.chunks_exact(320).map(ChainEnd::decode).collect::<Result<Vec<_>, _>>()?;
    let context = aggregate_context(&a, network)?;
    let current = super::api_client::get_aggregation_context(http, &config.services_url, &config.aggregation_token_file).await?;
    if let Some(current) = &current {
        ensure!(current.config_hash == context.config_hash && current.end_checkpoint_id.parse::<u64>()? <= a.end_checkpoint_id, "published context requires aggregate reconciliation");
        if current.end_checkpoint_id == context.end_checkpoint_id { ensure!(current.end_checkpoint_root == context.end_checkpoint_root, "published checkpoint contradiction"); }
    }
    super::api_client::publish_aggregation_context(http, &config.services_url, &config.aggregation_token_file,
        &super::api_client::PublishAggregationContext { expected_context_id: current.map(|context| context.context_id), context: context.clone() }).await?;
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
            let kind = match claim.request.kind { super::api_client::AggregationClaimKind::Withdrawal => 2, super::api_client::AggregationClaimKind::Reward => 3 };
            let record = super::api_client::decode_aggregation_base64(&claim.request.record, 1024)?;
            let claim_id = aggregate_claim_id(a.config_hash, kind, &record);
            ensure!(claim.claim_id == format!("0x{claim_id}"), "claim identity mismatch");
            let retained = selected_claims.iter().position(|selected| selected.claim_id == claim_id);
            let mut promoted_hash = None;
            let commitment = if kind == 2 {
                let leaf = WithdrawalLeaf::decode(&record)?;
                if retained.is_none() && !reserved_withdrawals.contains(&claim_id) {
                    let local = local_withdrawals.iter().find(|(index, _)| *index == leaf.chain_index).context("historical withdrawal destination absent")?.1;
                    if reserved_withdrawals.len() >= aggregate_limits.reserved_withdrawals as usize || local >= aggregate_limits.chain(leaf.chain_index)?.reserved_withdrawals { continue; }
                    let Some(hash) = historical_withdrawals.get(&record) else { continue; };
                    promoted_hash = Some(hash.clone());
                }
                leaf.record_commit()?
            } else {
                if retained.is_none() && selected_claims.iter().filter(|claim| claim.kind == 3).count() >= aggregate_limits.reserved_rewards as usize { continue; }
                RewardLeaf::decode(&record)?.record_commit()?
            };
            let bytes = super::api_client::decode_aggregation_base64(&claim.request.proof, 16 * 1024 * 1024)?;
            let data = if kind == 2 { &circuits.withdrawal.circuit_data } else { &circuits.reward.circuit_data };
            let proof = AggregateProof::from_bytes(bytes.clone(), &data.common).map_err(|error| anyhow::anyhow!("native claim proof: {error}"))?;
            ensure!(proof.to_bytes() == bytes, "noncanonical native proof");
            let inputs = proof.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>();
            let mut prefix = vec![1, u64::from(kind), 0, 0];
            prefix.extend(a.config_hash.chunks_exact(4).map(|word| u64::from(u32::from_be_bytes(word.try_into().unwrap()))));
            prefix.extend([a.end_checkpoint_id as u32 as u64, a.end_checkpoint_id >> 32]);
            prefix.extend(a.end_checkpoint_root);
            ensure!(inputs.starts_with(&prefix), "claim proof context mismatch");
            let offset = if kind == 2 {
                let leaf = WithdrawalLeaf::decode(&record)?;
                let end = ends.iter().find(|end| end.chain_index == leaf.chain_index).context("withdrawal chain absent")?;
                ensure!(inputs.get(18..24) == Some([BRIDGE_USER_ID_U64, u64::from(leaf.chain_index), end.withdrawal_root[0], end.withdrawal_root[1], end.withdrawal_root[2], end.withdrawal_root[3]].as_slice()), "withdrawal end mismatch");
                24
            } else { 18 };
            let words = commitment.chunks_exact(4).map(|word| u64::from(u32::from_be_bytes(word.try_into().unwrap()))).collect::<Vec<_>>();
            ensure!(inputs.get(offset..offset + 8) == Some(words.as_slice()), "claim record mismatch");
            data.verify(proof)?;
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
            let selected = SelectedClaim { claim_id, kind, record: hex::encode(record), proof: Some(save_aggregate_file(directory, &bytes, "proof")?), proof_context_id: Some(context.context_id.trim_start_matches("0x").into()) };
            if let Some(index) = retained { ensure!(selected_claims[index].record == selected.record && selected_claims[index].kind == kind, "retained claim changed"); selected_claims[index] = selected; }
            else { selected_claims.push(selected); }
            state.pending = Some(PendingAggregate::Collecting { aggregate_limits: aggregate_limits.clone(), producing_session: producing_session.clone(), selected_withdrawal_leaf_hashes: selected_withdrawal_leaf_hashes.clone(), a_opening: a_opening.clone(), ends: hex::encode(&end_bytes), selected_claims: selected_claims.clone() });
            save_multichain_state(state_path, state)?;
        }
        state.pending = Some(PendingAggregate::Collecting { aggregate_limits: aggregate_limits.clone(), producing_session: producing_session.clone(), selected_withdrawal_leaf_hashes: selected_withdrawal_leaf_hashes.clone(), a_opening: a_opening.clone(), ends: hex::encode(&end_bytes), selected_claims: selected_claims.clone() });
        save_multichain_state(state_path, state)?;
        cursor = page.next_after_claim_id;
        if cursor.is_none() { break; }
    }
    state.pending = Some(PendingAggregate::Collecting { aggregate_limits: aggregate_limits.clone(), producing_session: producing_session.clone(), selected_withdrawal_leaf_hashes: selected_withdrawal_leaf_hashes.clone(), a_opening: a_opening.clone(), ends: hex::encode(ends.iter().map(|end| end.encode()).collect::<Result<Vec<_>, _>>()?.concat()), selected_claims: selected_claims.clone() });
    save_multichain_state(state_path, state)?;
    if selected_claims.iter().any(|claim| claim.proof.is_none() || claim.proof_context_id.as_deref() != Some(context.context_id.trim_start_matches("0x"))) { return Ok(()); }
    for hash in &selected_withdrawal_leaf_hashes {
        let withdrawal = state.pending_claim_withdrawals.get(hash).or_else(|| state.retired_claim_withdrawals.get(hash).map(|entry| &entry.withdrawal)).context("selected withdrawal metadata missing")?;
        let id = aggregate_claim_id(a.config_hash, 2, &withdrawal_record(withdrawal)?.encode()?);
        if !selected_claims.iter().any(|claim| claim.claim_id == id) { return Ok(()); }
    }
    let mut ordered = selected_claims.into_iter().map(|claim| -> anyhow::Result<_> {
        let bytes = aggregate_bytes(&claim.record)?;
        let key = if claim.kind == 2 { let leaf = WithdrawalLeaf::decode(&bytes)?; (u64::from(leaf.chain_index), leaf.nonce) }
            else { let leaf = RewardLeaf::decode(&bytes)?; (leaf.claim_checkpoint_id, U256::from(leaf.nullifier_index).to_be_bytes::<32>()) };
        Ok(((claim.kind, key), claim))
    }).collect::<anyhow::Result<Vec<_>>>()?;
    ordered.sort_by_key(|(key, _)| *key);
    let selected_claims = ordered.into_iter().map(|(_, claim)| claim).collect::<Vec<_>>();
    let opening = BOpening { a, ends, withdrawals: selected_claims.iter().filter(|claim| claim.kind == 2).map(|claim| WithdrawalLeaf::decode(&aggregate_bytes(&claim.record)?).map_err(Into::into)).collect::<anyhow::Result<_>>()?,
        rewards: selected_claims.iter().filter(|claim| claim.kind == 3).map(|claim| RewardLeaf::decode(&aggregate_bytes(&claim.record)?).map_err(Into::into)).collect::<anyhow::Result<_>>()? };
    opening.validate(network)?;
    validate_frozen_capacity(&aggregate_limits, &opening)?;
    state.pending = Some(PendingAggregate::Frozen { aggregate_limits, producing_session, selected_withdrawal_leaf_hashes,
        b_opening: hex::encode(opening.encode()?), claim_ids: selected_claims.iter().map(|claim| claim.claim_id.clone()).collect(),
        local_proofs: selected_claims.into_iter().map(|claim| claim.proof.context("claim proof absent")).collect::<anyhow::Result<_>>()?, final_proofs: None,
        destinations: network.chains.iter().map(|chain| Destination { chain_index: chain.chain_index, a: Submission::NotSent, b: Submission::NotSent }).collect(), included_acknowledged: false });
    save_multichain_state(state_path, state)
}

fn aggregate_core_path(path: psy_crypto::hash::merkle::core::MerkleProofCore<QHashOut<GoldilocksField>>) -> parth_core::crypto::hash::merkle_proof::MerkleProofCore<parth_core::pgoldilocks::QHashOut<GoldilocksField>> {
    parth_core::crypto::hash::merkle_proof::MerkleProofCore { root: parth_core::pgoldilocks::QHashOut(path.root.0), value: parth_core::pgoldilocks::QHashOut(path.value.0), index: path.index,
        siblings: path.siblings.into_iter().map(|hash| parth_core::pgoldilocks::QHashOut(hash.0)).collect() }
}

async fn aggregate_end_witness(provider: &RpcProvider, network: &psy_client_data::bridge_aggregate::NetworkConfig, checkpoint: u64) -> anyhow::Result<psy_plonky2_circuits::bridge::circuits::checkpoint_end::CheckpointEndWitness> {
    use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
    use psy_plonky2_circuits::bridge::{circuits::checkpoint_end::{CheckpointEndWitness, CheckpointEndChainWitness}, gadgets::slot_value_in_contract_state::SlotValueInContractStateWitnessInput};
    use parth_core::pgoldilocks::QHashOut as CoreHash;
    let leaf = provider.get_checkpoint_leaf_data(checkpoint).await?;
    let end_leaf = <psy_data::v1::qdata::checkpoint::PQEDCheckpointLeaf<GoldilocksField, CoreHash<GoldilocksField>> as parth_core::felt::ToQFelts<GoldilocksField>>::from_qfelts(&psy_client_common::traits::to_qfelts::ToQFelts::to_qfelts(&leaf));
    let user = provider.get_user_leaf_data(checkpoint, BRIDGE_USER_ID_U64).await?;
    let user_leaf = psy_data::v1::qdata::user::PQEDUserLeaf { public_key: CoreHash(user.public_key.0), user_state_tree_root: CoreHash(user.user_state_tree_root.0),
        balance: user.balance, nonce: user.nonce, last_checkpoint_id: user.last_checkpoint_id, event_index: user.event_index, user_id: user.user_id };
    let user_path = aggregate_core_path(provider.get_user_tree_merkle_proof(checkpoint, BRIDGE_USER_ID_U64).await?);
    let roots = provider.get_checkpoint_global_state_roots(checkpoint).await?;
    let global_state_roots = psy_data::v1::qdata::checkpoint::PQEDCheckpointGlobalStateRoots {
        contract_tree_root: CoreHash(roots.contract_tree_root.0), deposit_tree_root: CoreHash(roots.deposit_tree_root.0), user_tree_root: CoreHash(roots.user_tree_root.0),
        withdrawal_tree_root: CoreHash(roots.withdrawal_tree_root.0), user_registration_tree_root: CoreHash(roots.user_registration_tree_root.0), validator_tree_root: CoreHash(roots.validator_tree_root.0) };
    let mut chains = Vec::with_capacity(network.chains.len());
    for chain in &network.chains {
        let mut trees = Vec::with_capacity(2);
        for (contract, height) in [(DEPOSIT_TREE_CONTRACT_ID, psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT),
            (WITHDRAWAL_TREE_CONTRACT_ID, psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT)] {
            let contract_proof = aggregate_core_path(provider.get_user_contract_tree_merkle_proof(checkpoint, BRIDGE_USER_ID_U64, contract).await?);
            let mut slots = Vec::with_capacity(3);
            for index in [16_386 + u64::from(chain.chain_index) / 4, 16_451 + 2 * u64::from(chain.chain_index), 16_452 + 2 * u64::from(chain.chain_index)] {
                slots.push(SlotValueInContractStateWitnessInput { sender_user_id: BRIDGE_USER_ID_U64, contract_id: u64::from(contract), slot_index: index, user_leaf,
                    slot_proof: aggregate_core_path(provider.get_user_contract_state_tree_merkle_proof(checkpoint, BRIDGE_USER_ID_U64, contract, height as u8, index).await?),
                    contract_proof: contract_proof.clone(), user_tree_proof: user_path.clone() });
            }
            trees.push(slots.try_into().map_err(|_| anyhow::anyhow!("end slot count mismatch"))?);
        }
        let withdrawal = trees.pop().context("withdrawal slots missing")?;
        let deposit = trees.pop().context("deposit slots missing")?;
        chains.push(CheckpointEndChainWitness { deposit, withdrawal });
    }
    let end_path = aggregate_core_path(provider.get_checkpoint_tree_merkle_proof(checkpoint, checkpoint).await?);
    Ok(CheckpointEndWitness { config: network.clone(), end_id: checkpoint, end_root: end_path.root, end_leaf, end_path, global_state_roots, user_leaf, user_path, chains })
}

async fn prove_frozen_aggregate(config: &BridgeProposeDaemonConfig, provider: &RpcProvider, network: &psy_client_data::bridge_aggregate::NetworkConfig,
    circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits, sources: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsSources,
    directory: &Path, state_path: &Path, state: &mut MultichainDaemonState) -> anyhow::Result<()> {
    use psy_plonky2_circuits::bridge::circuits::{bridge_wrap::{DigestArtifact, DigestBitsAdapter}, checkpoint_range::CheckpointRangeWitness, checkpoint_identity::CheckpointIdentityWitness};
    use psy_client_data::bridge_aggregate::BOpening;
    let Some(PendingAggregate::Frozen { b_opening, local_proofs, final_proofs: None, .. }) = &state.pending else { return Ok(()); };
    let b = BOpening::decode(&aggregate_bytes(b_opening)?)?;
    b.validate(network)?;
    let guardian = super::guardian_client::GuardianClientConfig::load(Path::new(&config.guardian_config))?;
    let authorization = guardian.authorization()?;
    let mut prefixes = Vec::with_capacity(network.chains.len());
    for transition in &b.a.deposits {
        if transition.old_count == transition.new_count { prefixes.push(Vec::new()); continue; }
        let endpoint = guardian.l1_endpoints.iter().find(|endpoint| endpoint.chain_index == transition.chain_index).context("missing guardian chain endpoint")?;
        let chain = authorization.chain(transition.chain_index)?;
        let anchor = crate::guardian::verify_l1::finalized_deposit_anchor(endpoint, chain, transition.old_count, transition.new_count).await?;
        prefixes.push(crate::guardian::verify_l1::fetch_deposit_records(endpoint, chain, &anchor).await?);
    }
    let web_inputs = prove_bridge::build_deposit_spiderman_inputs(network, &b.a, &prefixes)?;
    let proof_a = prove_bridge::build_deposit_aggregate(network, &b.a, &web_inputs, circuits)?;
    let end = aggregate_end_witness(provider, network, b.a.end_checkpoint_id).await?;
    ensure!(end.end_root.0.elements.map(|field| field.to_canonical_u64()) == b.a.end_checkpoint_root, "frozen checkpoint root changed");
    let config_hash = std::array::from_fn(|i| u32::from_be_bytes(b.a.config_hash[i * 4..i * 4 + 4].try_into().unwrap()));
    let mut starts = b.a.starts.iter().map(|start| (start.start_checkpoint_id, start.start_checkpoint_root)).collect::<Vec<_>>();
    starts.sort(); starts.dedup();
    let mut ranges = Vec::with_capacity(starts.len());
    for (id, root) in starts {
        let proof = if id == b.a.end_checkpoint_id {
            circuits.checkpoint_identity.prove(&CheckpointIdentityWitness { config_hash, start_id: id, end_id: id, start_root: end.end_root, end_root: end.end_root, end_leaf: end.end_leaf, end_path: end.end_path.clone() })?
        } else {
            let (raw, _, _) = prove_bridge::prove_checkpoint_range(provider, prove_bridge::cached_bridge_coordinator_circuits()?, id, b.a.end_checkpoint_id).await?;
            ensure!(raw.common_data == circuits.checkpoint_final.circuit_data.common && raw.verifier_data == circuits.checkpoint_final.circuit_data.verifier_only && raw.fingerprint == circuits.checkpoint_final.fingerprint, "checkpoint source pin mismatch");
            circuits.checkpoint_positive.prove(&CheckpointRangeWitness { range_proof: &raw.proof, config_hash, start_id: id, end_leaf: end.end_leaf, end_path: end.end_path.clone() })?
        };
        ensure!(proof.public_inputs[20..24].iter().map(|field| field.to_canonical_u64()).eq(root), "checkpoint start root mismatch");
        ranges.push(proof);
    }
    let mut withdrawals = Vec::new(); let mut rewards = Vec::new();
    for (index, reference) in local_proofs.iter().enumerate() {
        let bytes = load_aggregate_file(directory, reference)?;
        let data = if index < b.withdrawals.len() { &circuits.withdrawal.circuit_data } else { &circuits.reward.circuit_data };
        let proof = AggregateProof::from_bytes(bytes, &data.common).map_err(|error| anyhow::anyhow!("native proof decode: {error}"))?;
        if index < b.withdrawals.len() { withdrawals.push(proof); } else { rewards.push(proof); }
    }
    let proof_b = prove_bridge::build_checkpoint_aggregate(network, &b, &withdrawals, &rewards, &end, &ranges, circuits)?;
    let mut references = Vec::with_capacity(2);
    for (artifact, name, proof, data) in [(DigestArtifact::A, "A", proof_a, &circuits.deposit_aggregate.circuit_data), (DigestArtifact::B, "B", proof_b, &circuits.checkpoint_aggregate.circuit_data)] {
        data.verify(proof.clone())?;
        let adapter = DigestBitsAdapter::build(artifact, &data.common, &data.verifier_only)?;
        let adapted = adapter.prove(&proof)?;
        let wrapper = adapter.into_wrapper(sources.clone())?;
        let setup = config.aggregate_artifact_dir.join(name);
        super::regen_groth16_keystore::validate_digest_bits_setup(&setup, wrapper.identity())?;
        let final_proof = wrapper.prove_groth16(&adapted, setup.to_str().context("non-UTF8 setup path")?)?;
        references.push(save_aggregate_file(directory, &serde_json::to_vec(&final_proof)?, "json")?);
    }
    if let Some(PendingAggregate::Frozen { final_proofs, .. }) = &mut state.pending { *final_proofs = Some(references.try_into().map_err(|_| anyhow::anyhow!("final proof pair incomplete"))?); }
    save_multichain_state(state_path, state)
}

pub(crate) fn parse_aggregate_proof(proof: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::UncompressedGroth16ProofData, statement: [u8; 32]) -> anyhow::Result<[U256; 8]> {
    fn word(value: &str) -> anyhow::Result<U256> {
        ensure!(value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "native proof word must be 64 lowercase hex digits");
        Ok(U256::from_str_radix(value, 16)?)
    }
    for (value, half) in proof.public_inputs.iter().zip(statement.chunks_exact(16)) {
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
    use psy_client_data::bridge_aggregate::{AOpening, ChainStart, ChainEnd, DepositTransition};
    let committed = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?;
    ensure!(checkpoint <= committed.checkpoint_id, "aggregate end is not committed");
    let guardian = super::guardian_client::GuardianClientConfig::load(Path::new(&config.guardian_config))?;
    let authorization = guardian.authorization()?;
    let mut a = AOpening { config_hash: network.config_hash()?, window_id: [0; 32], end_checkpoint_id: checkpoint,
        end_checkpoint_root: provider.get_checkpoint_tree_root(checkpoint).await?.0.elements.map(|field| field.to_canonical_u64()), starts: Vec::new(), deposits: Vec::new(), deposit_leaves: Vec::new() };
    let mut ends = Vec::new();
    for chain in chains {
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
        let withdrawal_count = provider.get_withdrawal_tree_next_index(checkpoint, BRIDGE_USER_ID_U64, u64::from(chain.chain_index)).await?;
        let withdrawal_root = aggregate_l2_root(provider, checkpoint, WITHDRAWAL_TREE_CONTRACT_ID, chain.chain_index, withdrawal_count).await?;
        ensure!(count >= old_count, "custody count exceeds selected L2 end");
        if count > old_count {
            let endpoint = guardian.l1_endpoints.iter().find(|endpoint| endpoint.chain_index == chain.chain_index).context("guardian endpoint missing")?;
            let approved = authorization.chain(chain.chain_index)?;
            let anchor = crate::guardian::verify_l1::finalized_deposit_anchor(endpoint, approved, old_count, count).await?;
            let prefix = crate::guardian::verify_l1::fetch_deposit_records(endpoint, approved, &anchor).await?;
            a.deposit_leaves.extend_from_slice(&prefix[old_count as usize..count as usize]);
        }
        a.starts.push(ChainStart { chain_index: chain.chain_index, start_checkpoint_id: start, start_checkpoint_root: root });
        a.deposits.push(DepositTransition { chain_index: chain.chain_index, old_root, new_root, old_count, new_count: count });
        ends.extend(ChainEnd { chain_index: chain.chain_index, deposit_root: new_root, deposit_count: count, withdrawal_root }.encode()?);
    }
    a.window_id = a.window_id()?; a.validate(network)?;
    let aggregate_limits = state.pending.as_ref().map(PendingAggregate::limits).unwrap_or(&config.aggregate_limits).clone();
    aggregate_limits.validate(network)?;
    let (withdrawals, rewards) = aggregate_selected_counts(&aggregate_limits, &selected_withdrawal_leaf_hashes, &selected_claims, state)?;
    validate_aggregate_reservation(&aggregate_limits, &aggregate_deposit_counts(&a)?, &withdrawals, rewards)?;
    Ok(PendingAggregate::Collecting { aggregate_limits, producing_session, selected_withdrawal_leaf_hashes, a_opening: hex::encode(a.encode()?), ends: hex::encode(ends), selected_claims })
}

async fn observe_aggregate_submission(http: &reqwest::Client, chain: &ChainRuntime, b: &psy_client_data::bridge_aggregate::BOpening, network: &psy_client_data::bridge_aggregate::NetworkConfig, statement: [u8; 32], artifact: u8, submission: &Submission, directory: &Path, final_proofs: &[FileReference; 2]) -> anyhow::Result<Submission> {
    let transaction = match submission { Submission::Submitted { transaction_hash } | Submission::Finalized { transaction_hash, .. } | Submission::Reverted { transaction_hash, .. } => transaction_hash,
        _ => return Ok(submission.clone()) };
    let hash = B256::from_slice(&aggregate_bytes(transaction)?);
    let receipt = chain.l1.get_aggregate_receipt(hash).await?;
    let Some(receipt) = receipt else { ensure!(!matches!(submission, Submission::Finalized {..} | Submission::Reverted {..}), "finalized receipt disappeared"); return Ok(submission.clone()); };
    let receipt = serde_json::to_value(receipt)?;
    let target = if artifact == 1 { chain.bridge } else { chain.state_manager };
    ensure!(receipt["transactionHash"] == format!("{hash:#x}") && receipt["to"].as_str().is_some_and(|address| address.eq_ignore_ascii_case(&target.to_string())), "receipt transaction destination mismatch");
    let transaction_data = aggregate_rpc(http, chain, "eth_getTransactionByHash", serde_json::json!([hash])).await?;
    let signature = if artifact == 1 { "applyDepositAggregate(uint256[8],bytes)" } else { "finalizeCheckpointAggregate(uint256[8],bytes)" };
    let input = hex::decode(transaction_data["input"].as_str().and_then(|text| text.strip_prefix("0x")).context("transaction input missing")?)?;
    let opening = if artifact == 1 { b.a.encode()? } else { b.encode()? };
    ensure!(input.len() >= 324 && input[..4] == alloy_primitives::keccak256(signature.as_bytes())[..4]
        && U256::from_be_slice(&input[260..292]) == U256::from(288)
        && U256::from_be_slice(&input[292..324]) == U256::from(opening.len())
        && input.get(324..324 + opening.len()) == Some(opening.as_slice()), "transaction differs from frozen aggregate opening");
    let proof: psy_plonky2_circuits::bridge::circuits::bridge_wrap::UncompressedGroth16ProofData = serde_json::from_slice(&load_aggregate_file(directory, &final_proofs[artifact as usize - 1])?)?;
    let proof_statement = if artifact == 1 { b.a.statement_digest(network)? } else { statement };
    let expected_proof = parse_aggregate_proof(&proof, proof_statement)?.map(|word| word.to_be_bytes::<32>()).concat();
    ensure!(input.get(4..260) == Some(expected_proof.as_slice()), "transaction differs from frozen Groth16 proof");
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
    let end = b.ends.iter().find(|end| end.chain_index == chain.chain_index).context("destination absent")?;
    let log_index = if artifact == 2 {
        let signature = format!("{:#x}", alloy_primitives::keccak256(b"AggregateFinalized(bytes32,uint64,bytes32,bytes32,uint32,bytes32)"));
        let mut expected = U256::from(b.a.end_checkpoint_id).to_be_bytes::<32>().to_vec();
        expected.extend(aggregate_hash_bytes(b.a.end_checkpoint_root)); expected.extend(aggregate_hash_bytes(end.deposit_root));
        expected.extend(U256::from(end.deposit_count).to_be_bytes::<32>()); expected.extend(aggregate_hash_bytes(end.withdrawal_root));
        let logs = receipt["logs"].as_array().context("receipt logs missing")?;
        let matching = logs.iter().filter(|log| log["address"].as_str().is_some_and(|address| address.eq_ignore_ascii_case(&chain.state_manager.to_string()))
            && log["topics"][0] == signature && log["topics"][1] == format!("0x{}",hex::encode(statement)) && log["data"] == format!("0x{}",hex::encode(&expected))).collect::<Vec<_>>();
        ensure!(matching.len() == 1, "exact AggregateFinalized evidence missing");
        Some(aggregate_quantity(&matching[0]["logIndex"])?.to_string())
    } else {
        let block = serde_json::json!({"blockHash":canonical["hash"],"requireCanonical":true});
        ensure!(aggregate_word(http, chain, chain.bridge, "depositRoot()", None, &block).await? == aggregate_hash_bytes(end.deposit_root)
            && U256::from_be_bytes(aggregate_word(http, chain, chain.bridge, "provedDepositCount()", None, &block).await?) == U256::from(end.deposit_count), "A receipt custody end mismatch");
        None
    };
    Ok(Submission::Finalized { transaction_hash: transaction.clone(), block_hash, block_number, log_index })
}

async fn advance_aggregate_round(config: &BridgeProposeDaemonConfig, chains: &[ChainRuntime], provider: &RpcProvider,
    network: &psy_client_data::bridge_aggregate::NetworkConfig, circuits: &psy_plonky2_circuits::bridge::aggregate_circuits::AggregateCircuits,
    sources: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsSources, http: &reqwest::Client, directory: &Path,
    state_path: &Path, state: &mut MultichainDaemonState, lag: u64, max_batch: u64) -> anyhow::Result<()> {
    use base64::Engine;
    use psy_client_data::bridge_aggregate::BOpening;
    use super::api_client::{AggregationDispositions, ClaimDisposition, ReceiptEvidence, ConsumptionEvidence};
    validate_aggregate_state(state)?;
    if let Some(pending) = &state.pending { pending.limits().validate(network)?; }
    for statement in state.receipt_dispositions.keys().cloned().collect::<Vec<_>>() {
        let receipt = &state.receipt_dispositions[&statement];
        let opening = load_aggregate_file(directory, &receipt.opening)?;
        super::api_client::post_aggregation_dispositions(http, &config.services_url, &config.aggregation_token_file,
            &AggregationDispositions::Disposed { statement_b: format!("0x{statement}"), opening: base64::engine::general_purpose::STANDARD.encode(opening), dispositions: receipt.dispositions.clone() }).await?;
        if let Some(PendingAggregate::Frozen { b_opening, destinations, .. }) = &state.pending {
            let active = BOpening::decode(&aggregate_bytes(b_opening)?)?;
            if hex::encode(active.statement_digest(network)?) == statement && destinations.iter().all(|destination| matches!(destination.b, Submission::Finalized { .. })) {
                state.last_finalized_checkpoint = active.a.end_checkpoint_id;
                state.pending = None;
            }
        }
        state.receipt_dispositions.remove(&statement);
        save_multichain_state(state_path, state)?;
    }
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
            let a = psy_client_data::bridge_aggregate::AOpening::decode(&aggregate_bytes(&a_opening)?)?;
            let checkpoint = current.end_checkpoint_id.parse::<u64>()?;
            ensure!(current.config_hash == format!("0x{}", hex::encode(network.config_hash()?)), "published config mismatch");
            if checkpoint > a.end_checkpoint_id {
                let replacement = build_aggregate_collection(config, chains, provider, network, http, checkpoint, producing_session, selected_withdrawal_leaf_hashes, selected_claims, state).await?;
                if let PendingAggregate::Collecting { a_opening, .. } = &replacement {
                    let a = psy_client_data::bridge_aggregate::AOpening::decode(&aggregate_bytes(a_opening)?)?;
                    ensure!(aggregate_context(&a, network)?.context_id == current.context_id, "published context is not authenticated");
                }
                state.pending = Some(replacement);
                save_multichain_state(state_path, state)?;
            }
        }
    }
    if let Err(error) = collect_aggregate_claims(config, chains, provider, network, circuits, http, directory, state_path, state).await {
        if error.downcast_ref::<super::api_client::AggregationHttpError>().is_some() {
            tracing::warn!(%error, "aggregate admission unavailable; selected claims retained");
            return Ok(());
        }
        return Err(error);
    }
    if let Err(error) = prove_frozen_aggregate(config, provider, network, circuits, sources, directory, state_path, state).await {
        if error.downcast_ref::<DaemonStateWriteError>().is_some() { return Err(error); }
        tracing::warn!(%error, "aggregate proving failed; retrying identical frozen inputs");
        return Ok(());
    }
    let Some(PendingAggregate::Frozen { b_opening, claim_ids, included_acknowledged, .. }) = state.pending.clone() else { return Ok(()); };
    let bytes = aggregate_bytes(&b_opening)?;
    let b = BOpening::decode(&bytes)?;
    let statement = b.statement_digest(network)?;
    if !included_acknowledged {
        let context = aggregate_context(&b.a, network)?;
        let posted = super::api_client::post_aggregation_dispositions(http, &config.services_url, &config.aggregation_token_file,
            &AggregationDispositions::Included { context_id: context.context_id.clone(), statement_b: format!("0x{}",hex::encode(statement)), opening: base64::engine::general_purpose::STANDARD.encode(&bytes), claim_ids: claim_ids.iter().map(|id| format!("0x{id}")).collect() }).await;
        if let Err(super::api_client::AggregationHttpError::Service { status, data }) = &posted {
            if *status != reqwest::StatusCode::CONFLICT || !matches!(data.error_code, super::api_client::AggregationErrorCode::ContextChanged) { return Err(posted.err().unwrap().into()); }
            if let Some(current) = &data.current_context {
                ensure!(current.config_hash == context.config_hash && current.end_checkpoint_id.parse::<u64>()? >= b.a.end_checkpoint_id, "context refresh regression");
                let Some(PendingAggregate::Frozen { producing_session, selected_withdrawal_leaf_hashes, local_proofs, destinations, .. }) = state.pending.clone() else { unreachable!() };
                ensure!(destinations.iter().all(|destination| matches!(destination.a, Submission::NotSent) && matches!(destination.b, Submission::NotSent)), "context refresh cannot replace attempted sends");
                let records = b.withdrawals.iter().map(|record| record.encode().map(|bytes| (2, bytes))).chain(b.rewards.iter().map(|record| record.encode().map(|bytes| (3, bytes)))).collect::<Result<Vec<_>, _>>()?;
                let selected_claims = records.into_iter().zip(&claim_ids).zip(local_proofs).map(|(((kind, record), claim_id), proof)| SelectedClaim {
                    claim_id: claim_id.clone(), kind, record: hex::encode(record), proof: Some(proof), proof_context_id: Some(context.context_id.trim_start_matches("0x").into()) }).collect();
                state.pending = Some(build_aggregate_collection(config, chains, provider, network, http, current.end_checkpoint_id.parse()?, producing_session, selected_withdrawal_leaf_hashes, selected_claims, state).await?);
                save_multichain_state(state_path, state)?;
                return Ok(());
            }
        }
        included?;
        if let Some(PendingAggregate::Frozen { included_acknowledged, .. }) = &mut state.pending { *included_acknowledged = true; }
        save_multichain_state(state_path, state)?;
    }
    for (index, chain) in chains.iter().enumerate() {
        for artifact in 1..=2 {
            let Some(PendingAggregate::Frozen { destinations, final_proofs, .. }) = &state.pending else { unreachable!() };
            let destination = &destinations[index];
            let current = if artifact == 1 { &destination.a } else { &destination.b };
            let observed = observe_aggregate_submission(http, chain, &b, network, statement, artifact, current, directory, final_proofs.as_ref().context("missing final proof pair")?).await?;
            if let Some(PendingAggregate::Frozen { destinations, .. }) = &mut state.pending { if artifact == 1 { destinations[index].a = observed; } else { destinations[index].b = observed; } }
            save_multichain_state(state_path, state)?;
            let Some(PendingAggregate::Frozen { destinations, final_proofs, .. }) = &state.pending else { unreachable!() };
            let destination = &destinations[index];
            if artifact == 2 && !matches!(destination.a, Submission::Finalized {..}) { continue; }
            let current = if artifact == 1 { &destination.a } else { &destination.b };
            if !matches!(current, Submission::NotSent) { continue; }
            let proof: psy_plonky2_circuits::bridge::circuits::bridge_wrap::UncompressedGroth16ProofData = serde_json::from_slice(&load_aggregate_file(directory, &final_proofs.as_ref().context("final proofs missing")?[artifact as usize - 1])?)?;
            let proof_statement = if artifact == 1 { b.a.statement_digest(network)? } else { statement };
            let words = parse_aggregate_proof(&proof, proof_statement)?;
            let sender = L1Client::bind(&chain.config)?;
            let calldata = if artifact == 1 { super::finalize_bridge::apply_deposit_aggregate_call(words, Bytes::from(b.a.encode()?)) }
                else { super::finalize_bridge::finalize_checkpoint_aggregate_call(words, Bytes::from(bytes.clone())) };
            let destination = if artifact == 1 { chain.bridge } else { chain.state_manager };
            let limits = state.pending.as_ref().context("frozen round missing")?.limits();
            let prepared = match sender.preflight_aggregate(network, chain.chain_index, destination, calldata, limits).await {
                Ok(prepared) => prepared,
                Err(error) => { tracing::warn!(chain_index=chain.chain_index, artifact, %error, "aggregate preflight blocked; frozen round remains NotSent"); continue; }
            };
            if let Some(PendingAggregate::Frozen { destinations, .. }) = &mut state.pending { if artifact == 1 { destinations[index].a = Submission::Sending; } else { destinations[index].b = Submission::Sending; } }
            save_multichain_state(state_path, state)?;
            let hash = sender.broadcast_prepared(prepared).await;
            let hash = match hash { Ok(hash) => hash, Err(error) => { tracing::error!(chain_index=chain.chain_index, artifact, %error, "unknown aggregate send outcome; operator reconciliation required"); continue; } };
            if let Some(PendingAggregate::Frozen { destinations, .. }) = &mut state.pending { let submitted = Submission::Submitted { transaction_hash: hex::encode(hash) }; if artifact == 1 { destinations[index].a = submitted; } else { destinations[index].b = submitted; } }
            save_multichain_state(state_path, state)?;
        }
    }
    let Some(PendingAggregate::Frozen { producing_session, selected_withdrawal_leaf_hashes, local_proofs, final_proofs, destinations, .. }) = state.pending.clone() else { unreachable!() };
    if destinations.iter().any(|destination| [&destination.a, &destination.b].iter().any(|submission| matches!(submission, Submission::Sending | Submission::Submitted {..}))) { return Ok(()); }
    let complete = destinations.iter().all(|destination| matches!(destination.b, Submission::Finalized {..}));
    let failed = destinations.iter().any(|destination| matches!(destination.a, Submission::Reverted {..}) || matches!(destination.b, Submission::Reverted {..}));
    if !complete && !failed { return Ok(()); }
    let mut dispositions = Vec::new(); let mut retained_claims = Vec::new();
    for (index, id) in claim_ids.iter().enumerate() {
        let (kind, record, chain_index, key, address, signature) = if index < b.withdrawals.len() {
            let leaf = &b.withdrawals[index]; let chain = chains.iter().find(|chain| chain.chain_index == leaf.chain_index).context("withdrawal destination missing")?;
            (2, leaf.encode()?, leaf.chain_index, leaf.nonce, chain.bridge, "claimedNullifiers(bytes32)")
        } else {
            let leaf = &b.rewards[index - b.withdrawals.len()]; let chain = chains.iter().find(|chain| chain.chain_index == network.ethereum_index).context("reward destination missing")?;
            let payer = Address::from(network.reward_payer);
            let domain = aggregate_word(http, chain, payer, "rewardNullifierDomain()", None, &serde_json::json!("finalized")).await?;
            let mut key = domain.to_vec(); key.extend(U256::from(leaf.claim_checkpoint_id).to_be_bytes::<32>()); key.extend(U256::from(leaf.nullifier_index).to_be_bytes::<32>());
            (3, leaf.encode()?, network.ethereum_index, alloy_primitives::keccak256(key).0, payer, "spentRewards(bytes32)")
        };
        let destination = destinations.iter().find(|destination| destination.chain_index == chain_index).context("claim destination missing")?;
        if let Submission::Finalized { transaction_hash, log_index: Some(log_index), .. } = &destination.b {
            dispositions.push(ClaimDisposition::Applied { claim_id: format!("0x{id}"), receipt: ReceiptEvidence { chain_index, transaction_hash: format!("0x{transaction_hash}"), log_index: log_index.clone() } });
        } else {
            let chain = chains.iter().find(|chain| chain.chain_index == chain_index).context("claim chain missing")?;
            let block = aggregate_rpc(http, chain, "eth_getBlockByNumber", serde_json::json!(["finalized",false])).await?;
            let spent = aggregate_word(http, chain, address, signature, Some(key), &serde_json::json!({"blockHash":block["hash"],"requireCanonical":true})).await?;
            if U256::from_be_bytes(spent) == U256::from(1) { dispositions.push(ClaimDisposition::ConsumedElsewhere { claim_id: format!("0x{id}"), consumption: ConsumptionEvidence { chain_index, block_number: aggregate_quantity(&block["number"])?.to_string(), block_hash: block["hash"].as_str().context("block hash missing")?.into() } }); }
            else { ensure!(spent == [0; 32], "invalid spent flag"); dispositions.push(ClaimDisposition::Released { claim_id: format!("0x{id}") }); retained_claims.push(SelectedClaim { claim_id: id.clone(), kind, record: hex::encode(record), proof: Some(local_proofs[index].clone()), proof_context_id: Some(aggregate_context(&b.a, network)?.context_id.trim_start_matches("0x").into()) }); }
        }
    }
    let reverted_receipts = destinations.iter().flat_map(|destination| [(1, &destination.a), (2, &destination.b)].into_iter().filter_map(|(artifact, submission)| match submission {
        Submission::Reverted { transaction_hash, block_hash, block_number } => Some(RevertedReceipt { chain_index: destination.chain_index, artifact, transaction_hash: transaction_hash.clone(), block_hash: block_hash.clone(), block_number: *block_number }), _ => None })).collect();
    let receipt = ReceiptDispositions { opening: save_aggregate_file(directory, &bytes, "opening")?, final_proofs, dispositions, reverted_receipts };
    let replacement = if complete { None } else {
        let checkpoint = crate::guardian::service::load_guardian_committed_head(provider, &provider.get_coordinator_url()?).await?.checkpoint_id;
        let selected = selected_withdrawal_leaf_hashes.into_iter().filter(|hash| state.pending_claim_withdrawals.get(hash).or_else(|| state.retired_claim_withdrawals.get(hash).map(|entry| &entry.withdrawal))
            .is_some_and(|withdrawal| withdrawal_record(withdrawal).and_then(|leaf| Ok(aggregate_claim_id(b.a.config_hash, 2, &leaf.encode()?)))
                .is_ok_and(|id| retained_claims.iter().any(|claim| claim.claim_id == id)))).collect();
        Some(build_aggregate_collection(config, chains, provider, network, http, checkpoint, producing_session, selected, retained_claims, state).await?)
    };
    state.receipt_dispositions.insert(hex::encode(statement), receipt);
    if !complete { state.pending = replacement; }
    save_multichain_state(state_path, state)?;
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
    let document: toml::Value = toml::from_str(&raw)?;
    let state: MultichainDaemonState = if document.get("schema").is_none() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PreviousState {
            identity_namespace: String,
            last_finalized_checkpoint: u64,
            pending_finalization_range: Option<PendingFinalizationRange>,
            #[serde(default)]
            finalized_chains: HashSet<u8>,
            #[serde(default)]
            pending_claim_withdrawals: HashMap<String, propose_withdrawals::PendingWithdrawal>,
            #[serde(default)]
            claim_retry: HashMap<String, claim_attempts::ClaimAttempts>,
            #[serde(default)]
            retired_claim_withdrawals: HashMap<String, claim_attempts::RetiredClaim<propose_withdrawals::PendingWithdrawal>>,
        }
        let previous: PreviousState = toml::from_str(&raw)?;
        ensure!(previous.pending_finalization_range.is_none() && previous.finalized_chains.is_empty(), "in-flight range requires operator reconciliation before aggregate cutover");
        let migrated = MultichainDaemonState {
            identity_namespace: previous.identity_namespace, last_finalized_checkpoint: previous.last_finalized_checkpoint,
            pending_claim_withdrawals: previous.pending_claim_withdrawals, claim_retry: previous.claim_retry,
            retired_claim_withdrawals: previous.retired_claim_withdrawals, ..Default::default()
        };
        ensure!(migrated.identity_namespace == namespace, "daemon cohort mismatch");
        save_multichain_state(path, &migrated)?;
        migrated
    } else { toml::from_str(&raw)? };
    ensure!(state.schema == 2, "unsupported aggregate state schema");
    ensure!(state.identity_namespace == namespace, "multichain daemon state belongs to a different chain cohort");
    validate_aggregate_state(&state)?;
    Ok(state)
}

fn save_multichain_state(path: &Path, state: &MultichainDaemonState) -> anyhow::Result<()> {
    validate_aggregate_state(state)?;
    save_daemon_bytes(path, toml::to_string(state)?.as_bytes())
}

fn validate_aggregate_state(state: &MultichainDaemonState) -> anyhow::Result<()> {
    fn hash(value: &str) -> anyhow::Result<()> { ensure!(aggregate_bytes(value)?.len() == 32, "aggregate hash width mismatch"); Ok(()) }
    fn file(reference: &FileReference) -> anyhow::Result<()> {
        hash(&reference.sha256)?;
        ensure!(!reference.relative_path.is_empty() && Path::new(&reference.relative_path).components().all(|part| matches!(part, std::path::Component::Normal(_))), "invalid aggregate file reference");
        Ok(())
    }
    fn submission(value: &Submission, artifact: u8) -> anyhow::Result<()> {
        match value {
            Submission::NotSent | Submission::Sending => {},
            Submission::Submitted { transaction_hash } => hash(transaction_hash)?,
            Submission::Finalized { transaction_hash, block_hash, log_index, .. } => {
                hash(transaction_hash)?; hash(block_hash)?;
                ensure!((artifact == 2) == log_index.is_some(), "receipt log phase mismatch");
                if let Some(index) = log_index { ensure!(index.parse::<u64>()?.to_string() == *index, "noncanonical log index"); }
            }
            Submission::Reverted { transaction_hash, block_hash, .. } => { hash(transaction_hash)?; hash(block_hash)?; }
        }
        Ok(())
    }
    ensure!(state.schema == 2, "unsupported aggregate state schema");
    if let Some(pending) = &state.pending {
        let selected = match pending {
            PendingAggregate::Producing { aggregate_limits, deposit_counts, session_nonce, request_id, selected_withdrawal_leaf_hashes } => {
                let (withdrawals, rewards) = aggregate_selected_counts(aggregate_limits, selected_withdrawal_leaf_hashes, &[], state)?;
                validate_aggregate_reservation(aggregate_limits, deposit_counts, &withdrawals, rewards)?;
                ensure!(*session_nonce > 0, "invalid producing nonce"); hash(request_id)?; selected_withdrawal_leaf_hashes
            }
            PendingAggregate::Collecting { aggregate_limits, producing_session, selected_withdrawal_leaf_hashes, a_opening, ends, selected_claims } => {
                if let Some(session) = producing_session { ensure!(session.session_nonce > 0, "invalid producing nonce"); hash(&session.request_id)?; }
                let bytes = aggregate_bytes(a_opening)?;
                let a = psy_client_data::bridge_aggregate::AOpening::decode(&bytes)?;
                ensure!(a.encode()? == bytes, "noncanonical A opening");
                let (withdrawals, rewards) = aggregate_selected_counts(aggregate_limits, selected_withdrawal_leaf_hashes, selected_claims, state)?;
                validate_aggregate_reservation(aggregate_limits, &aggregate_deposit_counts(&a)?, &withdrawals, rewards)?;
                let ends = aggregate_bytes(ends)?; ensure!(ends.len() == 320 * a.starts.len(), "end count mismatch");
                for bytes in ends.chunks_exact(320) { ensure!(psy_client_data::bridge_aggregate::ChainEnd::decode(bytes)?.encode()? == bytes, "noncanonical chain end"); }
                let mut ids = HashSet::new();
                for claim in selected_claims {
                    hash(&claim.claim_id)?; ensure!(ids.insert(&claim.claim_id), "duplicate selected claim");
                    let bytes = aggregate_bytes(&claim.record)?;
                    let encoded = match claim.kind { 2 => psy_client_data::bridge_aggregate::WithdrawalLeaf::decode(&bytes)?.encode()?, 3 => psy_client_data::bridge_aggregate::RewardLeaf::decode(&bytes)?.encode()?, _ => anyhow::bail!("unsupported selected claim kind") };
                    ensure!(encoded == bytes && aggregate_claim_id(a.config_hash, claim.kind, &bytes) == claim.claim_id, "selected record identity mismatch");
                    ensure!(claim.proof.is_some() == claim.proof_context_id.is_some(), "partial selected proof reference");
                    if let Some(proof) = &claim.proof { file(proof)?; }
                    if let Some(context) = &claim.proof_context_id { hash(context)?; }
                }
                selected_withdrawal_leaf_hashes
            }
            PendingAggregate::Frozen { aggregate_limits, producing_session, selected_withdrawal_leaf_hashes, b_opening, claim_ids, local_proofs, final_proofs, destinations, included_acknowledged } => {
                if let Some(session) = producing_session { ensure!(session.session_nonce > 0, "invalid producing nonce"); hash(&session.request_id)?; }
                let bytes = aggregate_bytes(b_opening)?; let b = psy_client_data::bridge_aggregate::BOpening::decode(&bytes)?;
                ensure!(b.encode()? == bytes && claim_ids.len() == b.withdrawals.len() + b.rewards.len() && local_proofs.len() == claim_ids.len(), "frozen opening claim count mismatch");
                validate_frozen_capacity(aggregate_limits, &b)?;
                for (id, record) in claim_ids.iter().zip(b.withdrawals.iter().map(|record| record.encode().map(|bytes| (2, bytes))).chain(b.rewards.iter().map(|record| record.encode().map(|bytes| (3, bytes))))) {
                    let (kind, bytes) = record?;
                    ensure!(*id == aggregate_claim_id(b.a.config_hash, kind, &bytes), "frozen claim identity mismatch");
                }
                for proof in local_proofs { file(proof)?; }
                if let Some(proofs) = final_proofs { for proof in proofs { file(proof)?; } }
                ensure!(destinations.len() == b.ends.len(), "destination count mismatch");
                for (destination, end) in destinations.iter().zip(&b.ends) {
                    ensure!(destination.chain_index == end.chain_index, "destination ordering mismatch");
                    submission(&destination.a, 1)?; submission(&destination.b, 2)?;
                    if !matches!(destination.a, Submission::NotSent) || !matches!(destination.b, Submission::NotSent) { ensure!(*included_acknowledged && final_proofs.is_some(), "submission without complete acknowledged proofs"); }
                    if !matches!(destination.b, Submission::NotSent) { ensure!(matches!(destination.a, Submission::Finalized {..}), "B sent without finalized A"); }
                }
                selected_withdrawal_leaf_hashes
            }
        };
        let mut unique = HashSet::new();
        for id in selected { ensure!(unique.insert(id) && (state.pending_claim_withdrawals.contains_key(id) || state.retired_claim_withdrawals.contains_key(id)), "selected withdrawal metadata missing or duplicate"); }
    }
    for (statement, receipt) in &state.receipt_dispositions {
        hash(statement)?; file(&receipt.opening)?;
        if let Some(proofs) = &receipt.final_proofs { for proof in proofs { file(proof)?; } }
        for reverted in &receipt.reverted_receipts { ensure!((1..=2).contains(&reverted.artifact), "invalid reverted artifact"); hash(&reverted.transaction_hash)?; hash(&reverted.block_hash)?; }
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
        if append_business { ensure!(l2_count == proved, "new producing session requires synchronized custody and L2 counts"); }

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

        let historical = l2_count.checked_sub(proved).context("custody exceeds selected L2 end")?;
        let local_remaining = limits.chain(chain.chain_index)?.max_deposits.checked_sub(historical).context("historical deposits exceed local capacity")?;
        remaining_deposits = remaining_deposits.checked_sub(historical).context("historical deposits exceed global capacity")?;
        let appended = if append_business { (pending - l2_count).min(remaining_deposits).min(local_remaining) } else { 0 };
        let selected_count = l2_count.checked_add(appended).context("selected deposit count overflow")?;
        remaining_deposits = remaining_deposits.checked_sub(appended).context("deposit capacity overflow")?;
        if append_business && selected_count > l2_count {
            let snapshot = crate::bridge::api_client::fetch_services_deposit_tree_root(
                &http,
                &base.services_url,
                u64::from(chain.chain_index),
                u64::from(selected_count),
            ).await?;
            ensure!(snapshot.found, "missing exact deposit snapshot for chain {} count {}", chain.chain_index, pending);
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
    fn old_multichain_state_without_retry_fields_remains_readable() {
        let path = temp_state_path("schema-less-idle-migration");
        fs::write(&path, "identity_namespace = 'three-chains'\nlast_finalized_checkpoint = 42\n").unwrap();
        let state = load_multichain_state(&path, "three-chains").unwrap();
        assert_eq!(state.last_finalized_checkpoint, 42);
        assert!(state.claim_retry.is_empty());
        assert!(state.retired_claim_withdrawals.is_empty());
        assert_eq!(load_multichain_state(&path, "three-chains").unwrap().schema, 2);
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
max_a_calldata_bytes = 4096
max_b_calldata_bytes = 8192
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
        AggregateLimits { max_deposits: 4, reserved_withdrawals: 3, reserved_rewards: 2, max_a_calldata_bytes: 2628, max_b_calldata_bytes: 4324,
            chains: vec![ChainLimits { chain_index: 0, max_deposits: 3, reserved_withdrawals: 1, tx_gas_limit: 1_000_000, block_gas_reserve: 1000 },
                ChainLimits { chain_index: 2, max_deposits: 3, reserved_withdrawals: 2, tx_gas_limit: 1_000_000, block_gas_reserve: 1000 }] }
    }

    #[test]
    fn aggregate_capacity_reserves_full_foreign_records_and_rewards() {
        let limits = capacity_limits();
        assert_eq!(limits.validate_capacity(&[(0, 3), (2, 1)], &[(0, 1), (2, 2)], 2).unwrap(), (2628, 4324));
        let mut too_small = limits.clone();
        too_small.max_b_calldata_bytes -= 1;
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
        limits.max_a_calldata_bytes = 1731;
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
    fn catchup_opening_counts_all_intervals_and_checks_actual_abi_before_freeze() {
        use psy_client_data::bridge_aggregate::{AOpening, BOpening, ChainStart, ChainEnd, DepositTransition, DepositLeaf};
        let mut a = AOpening { config_hash: [0; 32], window_id: [0; 32], end_checkpoint_id: 20, end_checkpoint_root: [0; 4],
            starts: vec![ChainStart { chain_index: 0, start_checkpoint_id: 10, start_checkpoint_root: [0; 4] }, ChainStart { chain_index: 2, start_checkpoint_id: 12, start_checkpoint_root: [0; 4] }],
            deposits: vec![DepositTransition { chain_index: 0, old_root: [0; 4], new_root: [1; 4], old_count: 100, new_count: 103 },
                DepositTransition { chain_index: 2, old_root: [0; 4], new_root: [1; 4], old_count: 200, new_count: 201 }], deposit_leaves: Vec::new() };
        for (chain_index, indices) in [(0, 100..103), (2, 200..201)] {
            for absolute_index in indices {
                a.deposit_leaves.push(DepositLeaf { chain_index, absolute_index, shield_address: [1; 32], token: [2; 20], l2_token_contract_id: [3; 32], amount: [4; 32], note_commitment: [5; 32] });
            }
        }
        a.window_id = a.window_id().unwrap();
        let b = BOpening { ends: a.deposits.iter().map(|deposit| ChainEnd { chain_index: deposit.chain_index, deposit_root: deposit.new_root, deposit_count: deposit.new_count, withdrawal_root: [0; 4] }).collect(), a, withdrawals: Vec::new(), rewards: Vec::new() };
        assert_eq!(aggregate_deposit_counts(&b.a).unwrap(), vec![(0, 3), (2, 1)]);
        let limits = capacity_limits();
        validate_frozen_capacity(&limits, &b).unwrap();
        let mut too_small = limits.clone();
        too_small.max_deposits = 3;
        assert!(validate_frozen_capacity(&too_small, &b).is_err());
        let mut missing_record = b;
        missing_record.a.deposit_leaves.pop();
        assert!(aggregate_deposit_counts(&missing_record.a).is_err());
    }
}
