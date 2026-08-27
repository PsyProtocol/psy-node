//! Psy Wallet — MCP server (native Rust, over `WalletSession`).
//!
//! Exposes the real Psy wallet engine (`psy_prover::session::WalletSession`) to
//! AI agents as MCP tools, so registration, transfers, and claim/UPS batching
//! run with REAL client-side Plonky2 proving through the prove-proxy — not a
//! mock. Human control is expressed ahead of time as spending policy (caps +
//! allowlists + session TTL, enforced below the model in `policy.rs`); the agent
//! holds a session token and never the key.
//!
//! Config (endpoints incl. prove_proxy_url and api_services_url) is read from
//! the standard Psy `config.json` via `PsyConfigGoldilocks`, exactly as the CLI
//! and the relayer daemon build their sessions.

mod token_units;
mod agent_account;
mod keystore;
mod nostr_delivery;
mod l1;
mod x402;
mod policy;
mod wallet;
mod psyup;
mod psy_lang_docs;

mod startup;
mod wallet_tools;
mod x402_state;
mod x402_tools;
mod network;
mod claims_tools;
mod private_tools;

use std::sync::Arc;

use std::future::Future;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Parameters;
use rmcp::model::{CallToolResult, Content, ErrorData as McpError, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use serde::Deserialize;
use token_units::nano_equivalent;
use serde_json::json;
use tokio::sync::Mutex;

use network::NetworkId;
use policy::{Limits, PolicyEngine, SELF_RECIPIENT};
use wallet::{WalletManager, CONTRACT_PSY, CONTRACT_USDT};

/// Standard fee charged by a submitted transaction, denominated in Nano PSY.
const TX_FEE_NANO: u64 = 1_000_000_000;

/// Refuses unknown symbols instead of mapping them to PSY: a 402 challenge
/// naming asset "USDC" with USDC-scaled figures must not get paid in PSY at
/// that number. Same reason the x402 module refuses unknown SCHEMES.
fn contract_for(token: &str) -> Option<u64> {
    match token.to_ascii_uppercase().as_str() {
        "PSY" => Some(CONTRACT_PSY),
        "USDT" | "USDT_P" => Some(CONTRACT_USDT),
        _ => None,
    }
}

/// Chain-read balance pre-flight for spend tools. Bug #6: an over-budget USDT
/// transfer used to sail into proving and fail on the circuit's assertion
/// ~45s (and one fee) later, while PSY failed fast in the wallet layer —
/// same user mistake, two very different experiences, and the prove-stage
/// message names an assertion instead of the balance. One check for every
/// token, BEFORE any budget is charged. The PSY leg additionally needs the
/// tx fee headroom; USDT fees are charged in PSY.
async fn ensure_spendable_balance(
    wallet: &WalletManager,
    network: &NetworkId, 
    contract: u64, 
    amount: u64, 
    token_label: &str,
) -> Result<(), String> {
    let bal = wallet
        .balance(network, contract)
        .await
        .map_err(|e| format!("could not read the {token_label} balance: {e:#}"))?;
    if bal < amount {
        return Err(format!(
            "insufficient {token_label} balance: {bal} available, {amount} needed — the transfer was NOT sent (no fee charged)"
        ));
    }
    if contract == CONTRACT_PSY {
        let with_fee = amount.checked_add(TX_FEE_NANO).ok_or_else(|| {
            "transfer amount plus the 1 PSY fee exceeds the supported amount range".to_string()
        })?;
        if bal < with_fee {
            return Err(format!(
                "insufficient PSY balance for transfer plus the 1 PSY fee: {bal} available, {with_fee} needed"
            ));
        }
    } else {
        let psy_bal = wallet
            .balance(network, CONTRACT_PSY)
            .await
            .map_err(|e| format!("could not read the PSY balance needed for the transaction fee: {e:#}"))?;
        if psy_bal < TX_FEE_NANO {
            return Err(format!(
                "insufficient PSY balance for the 1 PSY transaction fee: {psy_bal} available, {TX_FEE_NANO} needed"
            ));
        }
    }
    Ok(())
}

/// JSON result helpers — every tool returns one structured JSON blob.
fn ok_json(value: serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        json!({ "status": "ok" }).as_object().map(|_| ()).map_or_else(
            || value.to_string(),
            |_| {
                let mut merged = json!({ "status": "ok" });
                if let (Some(m), Some(v)) = (merged.as_object_mut(), value.as_object()) {
                    for (k, val) in v {
                        m.insert(k.clone(), val.clone());
                    }
                }
                merged.to_string()
            },
        ),
    )]))
}

fn err_json(reason: impl std::fmt::Display, extra: serde_json::Value) -> Result<CallToolResult, McpError> {
    let mut v = json!({ "status": "error", "error": reason.to_string() });
    if let (Some(m), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in e {
            m.insert(k.clone(), val.clone());
        }
    }
    Ok(CallToolResult::error(vec![Content::text(v.to_string())]))
}

macro_rules! wallet_network {
    ($wallet:expr, $requested:expr) => {
        match $wallet.network_for($requested).await {
            Ok(network) => network,
            Err(e) => return err_json(e, json!({ "gate": "network" })),
        }
    };
}
pub(crate) use wallet_network;

struct ServerState {
    wallet: WalletManager,
}

#[derive(Clone)]
pub struct PsyWalletServer {
    /// `WalletManager` owns one async lock per network. Tool handlers never
    /// wrap it in another mutex, so a long proof on one network cannot block
    /// another network.
    state: Arc<ServerState>,
    /// Kept separate from wallet sessions: replay accounting never needs to
    /// wait for a proof, nor extend the wallet lock while persisting its set.
    consumed_payments: Arc<x402_state::ConsumedPayments>,
    /// The policy engine lives OUTSIDE the wallet mutex, behind a sync lock
    /// that is never held across an await: the wallet lock is held for whole
    /// tool bodies, including multi-minute proving and settlement waits, and
    /// the emergency pause must not queue behind them. This is what makes
    /// pause_policy an actual kill switch instead of a 10-minute promise.
    /// Lock rule: policy guards finish before any `.await`; wallet and replay
    /// locks are never acquired while a policy guard is live.
    policy: Arc<std::sync::Mutex<PolicyEngine>>,
    tool_router: ToolRouter<PsyWalletServer>,
}

impl PsyWalletServer {
    async fn authorize_wallet(
        &self,
        network: &NetworkId,
        token: &str,
        recipient: &str,
        amount: u64,
        method: &str,
    ) -> anyhow::Result<policy::Authorization> {
        let user_id = self.state.wallet.current_user(network).await.map(|user| user.user_id);
        self.policy
            .lock()
            .unwrap()
            .authorize_for(network.as_str(), user_id, token, recipient, amount, method)
    }

    async fn authorize_wallet_aliases(
        &self,
        network: &NetworkId,
        token: &str,
        recipients: &[&str],
        amount: u64,
        method: &str,
    ) -> anyhow::Result<policy::Authorization> {
        let user_id = self.state.wallet.current_user(network).await.map(|user| user.user_id);
        self.policy
            .lock()
            .unwrap()
            .authorize_aliases_for(network.as_str(), user_id, token, recipients, amount, method)
    }

    async fn check_wallet_can_act(&self, network: &NetworkId, token: &str, method: &str) -> anyhow::Result<()> {
        let user_id = self.state.wallet.current_user(network).await.map(|user| user.user_id);
        self.policy.lock().unwrap().check_can_act_for(network.as_str(), user_id, token, method)
    }

    async fn authorize_wallet_batch(
        &self,
        network: &NetworkId,
        token: &str,
        legs: &[(&str, u64)],
        method: &str,
    ) -> anyhow::Result<policy::Authorization> {
        let user_id = self.state.wallet.current_user(network).await.map(|user| user.user_id);
        self.policy
            .lock()
            .unwrap()
            .authorize_batch_for(network.as_str(), user_id, token, legs, method)
    }
}

// ── Tool argument schemas ─────────────────────────────────────────────

#[derive(Deserialize, schemars::JsonSchema)]
struct CreateWalletArgs {
    /// Psy config network. Omit to use the server's --network default.
    #[serde(default)]
    network: Option<String>,
    /// "generate" a fresh key and register it, or "load" an existing private key.
    #[serde(default = "default_generate")]
    mode: String,
    /// For mode="load": the NAME of an environment variable (set by the owner
    /// in the server's environment) holding the private key. The key itself is
    /// never a tool argument — an argument is model context, and a key that
    /// has passed through the transcript is burned.
    #[serde(default)]
    private_key_env: Option<String>,
    /// For mode="load": alternatively, a key-backup file written by this
    /// server (the generate flow's backup, or PSY_MCP_KEY_FILE format).
    #[serde(default)]
    key_file: Option<String>,
    #[serde(default = "default_agent")]
    agent_id: String,
    #[serde(default)]
    #[serde(rename = "perTransaction", alias = "per_transaction_nano")]
    per_transaction_nano: Option<u64>,
    #[serde(default)]
    #[serde(rename = "perDay", alias = "per_day_nano")]
    per_day_nano: Option<u64>,
    /// Rolling 30-day cap. Omit for no monthly limit.
    #[serde(default)]
    #[serde(rename = "perMonth", alias = "per_month_nano")]
    per_month_nano: Option<u64>,
    #[serde(default)]
    #[serde(rename = "totalBudget", alias = "total_budget_nano")]
    total_budget_nano: Option<u64>,
    /// Required when the server was started with PSY_MCP_OWNER_TOKEN set.
    #[serde(default)]
    owner_token: Option<String>,
    /// Who this agent may pay. Omit for "anyone"; pass a list to restrict it.
    /// Entries may be user ids (`1234`), Psy IDs (`Psy-00001234`), shielded
    /// addresses (`0x…`), or the URL/host of an x402 seller — they are matched
    /// in canonical form, so spelling never decides whether a payment goes
    /// through. An empty list means "pay nobody" (claims still work).
    #[serde(default, alias = "allowedRecipients")]
    allowed_recipients: Option<Vec<String>>,
}
fn default_generate() -> String { "generate".into() }
fn default_agent() -> String { "default-agent".into() }

#[derive(Deserialize, schemars::JsonSchema)]
struct MintAgentAccountArgs {
    /// Psy config network. Omit to use the server's --network default.
    #[serde(default)]
    network: Option<String>,
    /// Capabilities as "contract_id:method_name", e.g. ["0:simple_transfer", "0:simple_claim"].
    /// This IS the agent's authority — anything omitted is unprovable.
    capabilities: Vec<String>,
    /// Exact number of contract calls per transaction (equality-enforced by the
    /// circuit, so this is a transaction shape, not a budget). A spend session
    /// carries 2 introspectable txs (the sd-call + the endcap), so the default
    /// 2 is the minimum for an agent that SPENDS or CLAIMS — minting with 1
    /// makes every spend fail at prove with "SD key circuit expects 1
    /// introspectable txs, but session has 2 txs" (live-verified 2026-08-15:
    /// transfer/claim/claim_batch/call_contract all rejected on a shape-1
    /// agent; the same ops on a shape-2 agent pass the shape gate).
    #[serde(default = "default_calls_per_tx")]
    calls_per_transaction: u64,
    #[serde(default = "default_agent")]
    agent_id: String,
    #[serde(default)]
    #[serde(rename = "perTransaction")]
    per_transaction_nano: Option<u64>,
    #[serde(default)]
    #[serde(rename = "perDay")]
    per_day_nano: Option<u64>,
    #[serde(default)]
    #[serde(rename = "perMonth")]
    per_month_nano: Option<u64>,
    #[serde(default)]
    #[serde(rename = "totalBudget")]
    total_budget_nano: Option<u64>,
    /// Same meaning as create_wallet's: omit for "anyone". The circuit cannot
    /// constrain recipients, so this list is the only thing that does.
    #[serde(default)]
    allowed_recipients: Option<Vec<String>>,
    /// Required when the server was started with PSY_MCP_OWNER_TOKEN set.
    #[serde(default)]
    owner_token: Option<String>,
}
fn default_calls_per_tx() -> u64 {
    // 2, not 1: a spend session carries 2 introspectable txs (sd-call + endcap),
    // and the mandate circuit enforces this by EQUALITY — an agent minted with 1
    // cannot spend or claim at all (see the field docs above).
    2
}

#[derive(Deserialize, schemars::JsonSchema)]
struct IssueSessionArgs {
    policy_id: String,
    #[serde(default = "default_ttl")]
    ttl_minutes: u64,
    /// Optional lifetime cap for this session token, in nano-PSY.
    #[serde(default)]
    #[serde(rename = "maxSessionTotal", alias = "max_session_total", alias = "max_session_total_nano")]
    max_session_total_nano: Option<u64>,
    /// Required when the server was started with PSY_MCP_OWNER_TOKEN set.
    #[serde(default)]
    owner_token: Option<String>,
}
fn default_ttl() -> u64 { 60 }

#[derive(Deserialize, schemars::JsonSchema)]
struct PsyGetDocArgs {
    /// One of: types, contract, variables, control, assert, struct, operators, storage.
    topic: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PsyupNewArgs {
    /// Project name — letters, digits, `_`, `-` only.
    name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct WriteSourceArgs {
    /// Existing project name (created by psyup_new).
    project: String,
    /// Project-relative file path, e.g. `src/main.psy`. Must stay inside the project.
    path: String,
    /// Full file contents to write (overwrites).
    source: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PsyupBuildArgs {
    /// Existing project name.
    project: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PsyupDeployArgs {
    #[serde(default)]
    network: Option<String>,
    /// Existing project name.
    project: String,
    /// Agent spending session. Deploying is POLICY-GATED like any spend: the
    /// policy must explicitly allow the `deploy_contract` method (owner adds it
    /// via update_policy), and the deploy fee is charged against the caps.
    session: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct CallContractArgs {
    #[serde(default)]
    network: Option<String>,
    /// Agent spending session. Calling is POLICY-GATED like any spend: the
    /// policy must allow the `call_contract` method, and the call fee is
    /// charged against the caps.
    session: String,
    /// Deployed contract id — what `psyup_deploy` printed as `contract_id`.
    contract_id: u64,
    /// Method on that contract, e.g. `main` (a zero-arg pure function) or any
    /// #[contract_method] the project compiled.
    method_name: String,
    /// Method inputs as a JSON array of integers, e.g. `[860160, 5000000000]`.
    /// Omit (or pass `[]`) for a zero-argument method.
    #[serde(default)]
    inputs: Vec<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PolicyIdArgs {
    policy_id: String,
    /// Required for resume_policy when PSY_MCP_OWNER_TOKEN is set. (pause
    /// never needs it — pausing is always allowed, it only removes authority.)
    #[serde(default)]
    owner_token: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct UpdatePolicyArgs {
    policy_id: String,
    /// Omit to leave the per-payment cap unchanged.
    #[serde(default)]
    #[serde(rename = "perTransaction", alias = "per_transaction_nano")]
    per_transaction_nano: Option<u64>,
    /// Omit to leave the daily cap unchanged.
    #[serde(default)]
    #[serde(rename = "perDay", alias = "per_day_nano")]
    per_day_nano: Option<u64>,
    /// Rolling 30-day cap. OMIT to leave it unchanged; pass `null` to remove
    /// it.
    #[serde(default, alias = "perMonth")]
    per_month_nano: Option<Option<u64>>,
    /// Lifetime cap. OMIT to leave it unchanged; pass `null` to remove it.
    #[serde(default, deserialize_with = "double_option", alias = "totalBudget")]
    total_budget_nano: Option<Option<u64>>,
    /// Who the agent may pay. OMIT to leave the current allow-list unchanged
    /// (so a "tighten my budget" edit can never silently widen it to anyone);
    /// pass `null` to explicitly clear it (pay anyone); pass a list to replace
    /// it.
    #[serde(default, deserialize_with = "double_option", alias = "allowedRecipients")]
    allowed_recipients: Option<Option<Vec<String>>>,
    /// Omit or empty to leave the method list unchanged.
    #[serde(default)]
    allowed_methods: Option<Vec<String>>,
    /// Limits to REMOVE, e.g. ["perMonth","totalBudget","allowedRecipients"].
    /// rmcp strips JSON `null` from parameters, so "pass null to clear" can
    /// never be distinguished from "omit" — this is the explicit way to clear.
    #[serde(default, alias = "removeLimits")]
    remove_limits: Option<Vec<String>>,
    /// Required when the server was started with PSY_MCP_OWNER_TOKEN set.
    #[serde(default)]
    owner_token: Option<String>,
}

/// Distinguishes "field absent" (`None`) from "field present and null"
/// (`Some(None)`) — the difference between "leave the allow-list alone" and
/// "clear it". `#[serde(default)]` alone collapses both to `None`.
fn double_option<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

/// The line between the owner and the agent. Tools that MINT or RESTORE
/// authority (issue_session, resume_policy, create_wallet, mint_agent_account)
/// are owner actions: without a gate, an agent holding the policy_id from
/// create_wallet's own output could undo a pause or re-mint a session after a
/// revoke, and the emergency stop would be theater. When PSY_MCP_OWNER_TOKEN
/// is set in the server's environment those tools demand it; tools that only
/// REMOVE authority (pause_policy, revoke_session) stay open to everyone.
/// Without the env var the server runs in single-operator dev mode, unchanged.
fn owner_gate(supplied: Option<&str>) -> Result<(), String> {
    let expected = match std::env::var("PSY_MCP_OWNER_TOKEN") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(()),
    };
    let supplied = supplied.unwrap_or("");
    // Constant-time comparison — an equality that short-circuits would let a
    // caller grow a prefix byte by byte from the timing.
    let a = expected.as_bytes();
    let b = supplied.as_bytes();
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= (*a.get(i).unwrap_or(&0) ^ *b.get(i).unwrap_or(&0)) as usize;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err("this is an owner tool: the server was started with PSY_MCP_OWNER_TOKEN, so it requires the matching owner_token argument".to_string())
    }
}

/// The gate for an edit that GRANTS MORE than the policy grants today.
///
/// `owner_gate` deliberately runs in single-operator dev mode when
/// PSY_MCP_OWNER_TOKEN is unset. That is a defensible default for tools that
/// re-mint authority the owner already chose — and an indefensible one for the
/// single tool that can invent new authority. Ungated, an agent reads its own
/// `policyId` out of `describe_policy` (a read-only tool it is *told* to call
/// first) and then raises its own caps, drops the 30-day and lifetime
/// ceilings, and clears its allow-list in one call. Every limit the owner set
/// becomes advisory, and the dashboard's promise — "a prompt or jailbreak
/// can't raise a limit or add a payee" — is false.
///
/// So widening demands the owner, and NO CONFIGURED TOKEN MEANS NOBODY CAN
/// PROVE THEY ARE THE OWNER. Refusing is the only safe reading: it fails
/// toward less spending power, and the message spells out the one step that
/// recovers it. Narrowing stays open to everyone.
fn owner_gate_for_widening(supplied: Option<&str>, what: &str) -> Result<(), String> {
    match std::env::var("PSY_MCP_OWNER_TOKEN") {
        Ok(v) if !v.trim().is_empty() => owner_gate(supplied)
            .map_err(|_| format!("refused: this edit {what} — only the owner may widen a policy, and the owner_token argument does not match")),
        _ => Err(format!(
            "refused: this edit {what}, and this server was started WITHOUT PSY_MCP_OWNER_TOKEN, \
             so there is no way to tell the owner from the agent. Tightening a policy still works. \
             To widen it, restart the server with PSY_MCP_OWNER_TOKEN set and pass that value as owner_token."
        )),
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SessionArg { session: String }

#[derive(Deserialize, schemars::JsonSchema)]
struct NetworkArgs {
    #[serde(default)]
    network: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SelectWalletArgs {
    #[serde(default)]
    network: Option<String>,
    /// Decimal user id or public pk hash returned by list_wallets.
    user: String,
    #[serde(default)]
    owner_token: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DescribePolicyArgs {
    /// Which policy to describe. Omit when the server holds only one.
    #[serde(default)]
    policy_id: Option<String>,
    /// An agent that holds only a session token can name its policy with it.
    #[serde(default)]
    session: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SpendLogArgs {
    /// How many entries to return (1–100, default 20).
    #[serde(default)]
    limit: Option<u32>,
    /// Restrict to one policy; omit to see every agent's spends.
    #[serde(default)]
    policy_id: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct TransferArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    to_user_id: u64,
    #[serde(rename = "amount")]
    amount_nano: u64,
    #[serde(default = "default_psy")]
    token: String,
}
fn default_psy() -> String { "PSY".into() }

/// One payment inside a batch.
#[derive(Deserialize, schemars::JsonSchema)]
struct BatchPayment {
    /// Who to pay.
    to_user_id: u64,
    /// How much, in Nano.
    #[serde(rename = "amount")]
    amount_nano: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct TransferBatchArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    /// The payments to make. All-or-nothing: if the policy refuses any one of
    /// them, none are sent and no budget is consumed.
    payments: Vec<BatchPayment>,
    #[serde(default = "default_psy")]
    token: String,
}

#[tool_router]
impl PsyWalletServer {
    pub async fn new(wallet: WalletManager) -> Self {
        // A wallet restored at startup (PSY_MCP_KEY_FILE) is already loaded by
        // the time the engine is built, so tell the engine which identity it is
        // governing before it authorizes anything.
        let network = wallet.default_network().clone();
        let restored = wallet.current_user(&network).await.map(|u| u.user_id);
        let mut engine = PolicyEngine::load_or_new(&keystore::keystore_dir());
        if let Some(uid) = restored {
            engine.set_current_wallet(network.as_str(), uid);
        }
        Self {
            state: Arc::new(ServerState { wallet }),
            consumed_payments: Arc::new(x402_state::ConsumedPayments::load(&keystore::keystore_dir())),
            // Budgets — including the lifetime cap — survive restarts; an
            // engine that forgets its counters re-grants them on every crash
            // loop.
            policy: Arc::new(std::sync::Mutex::new(engine)),
            tool_router: Self::tool_router()
                + Self::wallet_tools_router()
                + Self::claims_tools_router()
                + Self::private_tools_router()
                + Self::x402_tools_router(),
        }
    }

    // ── Contract authoring (psyup) ──────────────────────────────────────────

    #[tool(
        description = "Scaffold a new Psy-lang contract project from the official boilerplate, under the contracts root (PSY_MCP_CONTRACTS_ROOT, default ~/psy-mcp-contracts). Runs `psyup new` with the installed toolchain. Then use write_source / psyup_build to iterate."
    )]
    async fn psyup_new(&self, Parameters(a): Parameters<PsyupNewArgs>) -> Result<CallToolResult, McpError> {
        let root = match psyup::contracts_root() {
            Ok(r) => r,
            Err(e) => return err_json(e, json!({})),
        };
        if let Err(e) = std::fs::create_dir_all(&root) {
            return err_json(format!("cannot create contracts root {}: {e}", root.display()), json!({}));
        }
        let dir = match psyup::project_dir(&root, &a.name) {
            Ok(d) => d,
            Err(e) => return err_json(e, json!({})),
        };
        if dir.exists() {
            return err_json(format!("project `{}` already exists", a.name), json!({}));
        }
        match psyup::run_psyup(&["new", &a.name], &root, &[]) {
            Ok((true, out)) => ok_json(json!({ "ok": true, "project": a.name, "path": dir.display().to_string(), "output": out })),
            Ok((false, out)) => err_json(format!("psyup new failed:\n{out}"), json!({ "output": out })),
            Err(e) => err_json(e, json!({})),
        }
    }

    #[tool(
        description = "Write (or overwrite) one source file inside an existing contract project. `path` is project-relative and must stay inside the project — traversal is refused. After writing, call psyup_build to compile."
    )]
    async fn write_source(&self, Parameters(a): Parameters<WriteSourceArgs>) -> Result<CallToolResult, McpError> {
        let root = match psyup::contracts_root() {
            Ok(r) => r,
            Err(e) => return err_json(e, json!({})),
        };
        let dir = match psyup::project_dir(&root, &a.project) {
            Ok(d) => d,
            Err(e) => return err_json(e, json!({})),
        };
        if !dir.is_dir() {
            return err_json(
                format!("project `{}` does not exist — create it with psyup_new first", a.project),
                json!({}),
            );
        }
        // Source lives where Dargo.toml lives (dapp templates nest it under contract/).
        let cdir = match psyup::find_contract_dir(&dir) {
            Ok(c) => c,
            Err(e) => return err_json(e, json!({})),
        };
        let file = match psyup::safe_project_file(&cdir, &a.path) {
            Ok(f) => f,
            Err(e) => return err_json(e, json!({})),
        };
        if let Some(parent) = file.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return err_json(format!("cannot create {}: {e}", parent.display()), json!({}));
            }
        }
        if let Err(e) = std::fs::write(&file, &a.source) {
            return err_json(format!("cannot write {}: {e}", file.display()), json!({}));
        }
        ok_json(json!({ "ok": true, "project": a.project, "path": file.display().to_string(), "bytes": a.source.len() }))
    }

    #[tool(
        description = "Compile a contract project with the installed toolchain (`psyup build` → dargo compile). Returns the compiler output; iterate with write_source until it succeeds."
    )]
    async fn psyup_build(&self, Parameters(a): Parameters<PsyupBuildArgs>) -> Result<CallToolResult, McpError> {
        let root = match psyup::contracts_root() {
            Ok(r) => r,
            Err(e) => return err_json(e, json!({})),
        };
        let dir = match psyup::project_dir(&root, &a.project) {
            Ok(d) => d,
            Err(e) => return err_json(e, json!({})),
        };
        if !dir.is_dir() {
            return err_json(format!("project `{}` does not exist — create it with psyup_new first", a.project), json!({}));
        }
        let cdir = match psyup::find_contract_dir(&dir) {
            Ok(c) => c,
            Err(e) => return err_json(e, json!({})),
        };
        match psyup::run_psyup(&["build"], &cdir, &[]) {
            Ok((true, out)) => ok_json(json!({ "ok": true, "project": a.project, "output": out })),
            Ok((false, out)) => err_json(format!("build failed:\n{out}"), json!({ "output": out })),
            Err(e) => err_json(e, json!({})),
        }
    }

    #[tool(
        description = "Deploy a compiled contract project to the chain (`psyup deploy` → psy_user_cli deploy-contract). POLICY-GATED like any spend: needs a valid session, the policy must allow the `deploy_contract` method (owner adds it via update_policy), and the 1 PSY deploy fee is charged against the policy caps. Signs with THIS wallet's private key."
    )]
    async fn psyup_deploy(&self, Parameters(a): Parameters<PsyupDeployArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        let (key_hex, key_user_id) = match state.wallet.current_user(&network).await {
            Some(u) => (u.private_key.to_string(), u.user_id),
            None => return err_json("no wallet loaded — deploy needs a wallet to pay the deploy fee", json!({})),
        };
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        // Policy gate BELOW the model, same shape as transfer. The deploy fee
        // is charged as one 1 PSY spend so the daily/30-day caps bound how much
        // an agent can deploy, and the audit trail shows it like any spend.
        const DEPLOY_FEE_NANO: u64 = 1_000_000_000; // 1 PSY, the standard tx fee
        let auth = match self
            .authorize_wallet(&network, &a.session, SELF_RECIPIENT, DEPLOY_FEE_NANO, "deploy_contract")
            .await
        {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        if auth.user_id != Some(key_user_id) {
            self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
            return err_json(
                "active wallet changed while deploy was being authorized; refusing to use a different key",
                json!({ "gate": "wallet" }),
            );
        }
        let root = match psyup::contracts_root() {
            Ok(r) => r,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
                return err_json(e, json!({}));
            }
        };
        let dir = match psyup::project_dir(&root, &a.project) {
            Ok(d) => d,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
                return err_json(e, json!({}));
            }
        };
        if !dir.is_dir() {
            self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
            return err_json(
                format!("project `{}` does not exist — create it with psyup_new first", a.project),
                json!({}),
            );
        }
        let cdir = match psyup::find_contract_dir(&dir) {
            Ok(c) => c,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
                return err_json(e, json!({}));
            }
        };
        match psyup::run_psyup(&["deploy"], &cdir, &[("PRIVATE_KEY", key_hex)]) {
            Ok((true, out)) => ok_json(json!({ "ok": true, "project": a.project, "output": out })),
            Ok((false, out)) => {
                // Nothing went on chain; give the fee back.
                self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
                err_json(format!("deploy failed:\n{out}"), json!({ "output": out }))
            }
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
                err_json(e, json!({}))
            }
        }
    }

    #[tool(
        description = "Call a deployed contract method on this wallet's behalf — the read/write side of psyup_deploy, which the toolset was missing: an agent could author and deploy a contract but had no way to invoke it. POLICY-GATED like any spend: needs a valid session, the policy must allow the `call_contract` method (owner adds it via update_policy), and the 1 PSY call fee is charged against the policy caps. Submits a REAL proof with this wallet's key and returns the end-user-leaf-hash; a method that fails in-circuit (wrong method name, wrong arity, an assertion) refunds the fee and reports the error. `inputs` is a JSON array of integers — pass `[]` for a zero-argument method like `main`."
    )]
    async fn call_contract(&self, Parameters(a): Parameters<CallContractArgs>) -> Result<CallToolResult, McpError> {
        const CALL_FEE_NANO: u64 = 1_000_000_000; // 1 PSY, same as a deploy
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        // Policy gate below the model, same shape as deploy: a call is a tx on
        // the user's chain identity and is charged against the owner's caps.
        let auth = match self
            .authorize_wallet(&network, &a.session, SELF_RECIPIENT, CALL_FEE_NANO, "call_contract")
            .await
        {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        if state.wallet.current_user(&network).await.is_none() {
            self.policy.lock().unwrap().refund(&auth, CALL_FEE_NANO);
            return err_json(
                "no wallet loaded — a call needs a wallet to sign and pay the call fee",
                json!({ "gate": "wallet" }),
            );
        }
        // exec_call already retries once on a stale-state rejection (stale nonce /
        // stale start_user_leaf_hash), so a call after any recent tx survives.
        let execution = match auth.user_id {
            Some(user_id) => {
                state
                    .wallet
                    .exec_call_for(&network, user_id, a.contract_id, &a.method_name, a.inputs.clone())
                    .await
            }
            None => Err(anyhow::anyhow!("authorization did not bind a wallet identity")),
        };
        match execution {
            Ok(leaf) => ok_json(json!({
                "submitted": true, "contractId": a.contract_id, "method": a.method_name,
                "inputs": a.inputs, "endUserLeafHash": leaf,
                "note": "Call submitted with a real proof — watch the tx on the explorer.",
            })),
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, CALL_FEE_NANO);
                err_json(format!("call failed: {e:#}"), json!({ "gate": "execute" }))
            }
        }
    }

    // ── Contract authoring guidance (psy_lang_docs) ───────────────────────

    #[tool(
        description = "Psy-lang contract authoring quickstart for the agent: types (Felt/u32, NOT u64), #[contract_method], the psyup_new→write_source→psyup_build→psyup_deploy flow, and the compiler errors you will hit with their fixes. Call this BEFORE writing a contract."
    )]
    async fn psy_agent_instructions(&self) -> Result<CallToolResult, McpError> {
        ok_json(json!({ "instructions": psy_lang_docs::agent_instructions() }))
    }

    #[tool(
        description = "Look up one Psy-lang syntax topic. Topics: types, contract/contract_method, variables/let, control (if/for), assert/assert_eq, struct/array, operators, storage. Returns the exact syntax, distilled from the compiler test suite."
    )]
    async fn psy_get_doc(&self, Parameters(a): Parameters<PsyGetDocArgs>) -> Result<CallToolResult, McpError> {
        match psy_lang_docs::get_doc(&a.topic) {
            Some(doc) => ok_json(json!({ "topic": a.topic, "doc": doc })),
            None => err_json(
                format!("unknown topic `{}` — try: {}", a.topic, psy_lang_docs::known_topics()),
                json!({ "topics": psy_lang_docs::known_topics() }),
            ),
        }
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ClaimableArgs {
    #[serde(default)]
    network: Option<String>,
    sender_user_id: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct BalanceArgs {
    #[serde(default)]
    network: Option<String>,
    #[serde(default = "default_psy")]
    token: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ClaimAllArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    /// User ids that owe you public claims (discover via get_claimable).
    sender_user_ids: Vec<u64>,
    #[serde(default = "default_psy")]
    token: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PrivateTransferArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    to_shielded_address: String,
    /// Recipient's Nostr npub — how the note reaches them. Without it the note
    /// is undeliverable and the funds would be debited but unclaimable.
    recipient_npub: String,
    #[serde(rename = "amount")]
    amount_nano: u64,
    #[serde(default = "default_psy")]
    token: String,
    /// Relay to publish the note to. Omit to use this network's config.json value.
    #[serde(default)]
    relay: Option<String>,
    /// Derive and show the call without settling anything.
    #[serde(default)]
    dry_run: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FaucetArgs {
    #[serde(default)]
    network: Option<String>,
    /// Faucet service endpoint. Omit to use this network's config.json value.
    #[serde(default)]
    faucet_url: Option<String>,
}

fn required_network_value(value: Option<String>, network: &NetworkId, field: &str) -> Result<String, String> {
    value.filter(|value| !value.trim().is_empty()).ok_or_else(|| {
        format!("network `{network}` has no non-empty `{field}` in config.json")
    })
}

fn network_faucet_url(wallet: &WalletManager, network: &NetworkId) -> Result<String, String> {
    required_network_value(wallet.faucet_url(network), network, "faucet_rpc_url")
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PrivateClaimArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    /// A specific note to claim. Omit to claim everything psy-services is
    /// holding for this wallet — it already subscribes to the relay, so no
    /// direct Nostr connection is needed here.
    #[serde(default)]
    note: Option<String>,
    #[serde(default = "default_psy")]
    token: String,
    /// psy-services endpoint; omit to use this network's config.json value.
    #[serde(default)]
    services_url: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ActivityArgs {
    #[serde(default)]
    network: Option<String>,
    /// How many entries to return (1–200, default 20).
    #[serde(default)]
    limit: Option<u32>,
    /// psy-services endpoint; omit to use this network's config.json value.
    #[serde(default)]
    services_url: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct X402FetchArgs {
    session: String,
    /// Psy config network whose wallet pays. Omit for the server default.
    #[serde(default)]
    psy_network: Option<String>,
    /// The paywalled URL to fetch.
    url: String,
    /// Refuse to pay more than this, whatever the server asks.
    #[serde(default)]
    #[serde(rename = "maxAmount")]
    max_amount_nano: Option<u64>,
    /// x402 network label to match; defaults to the configured Psy network.
    #[serde(default)]
    network: Option<String>,
    /// Show what would be paid without paying.
    #[serde(default)]
    dry_run: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct X402VerifyArgs {
    /// Psy config network whose receiving wallet is verified.
    #[serde(default)]
    psy_network: Option<String>,
    /// The X-PAYMENT header value the caller sent.
    x_payment: String,
    /// How long to wait for the payment to appear in the indexer before
    /// refusing (default 90 s, max 600). Settlement precedes indexing.
    #[serde(default)]
    settlement_wait_seconds: Option<u64>,
    /// Price of the resource; the payment must cover it.
    #[serde(default)]
    #[serde(rename = "expectedAmount")]
    expected_amount_nano: Option<u64>,
    #[serde(default)]
    services_url: Option<String>,
    /// How old (in checkpoints) a settled payment may be and still count
    /// (default 240). An old payment is a receipt, not money offered now.
    #[serde(default)]
    max_age_checkpoints: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DepositArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    /// Amount in the token's base units (USDT: 6 decimals; PSY: 9).
    amount_base_units: u64,
    #[serde(default = "default_usdt")]
    token: String,
    /// Psy's internal index for the source chain.
    #[serde(default)]
    source_chain_index: u32,
    // The L1 RPC URL and every contract address are OWNER configuration
    // (the selected network's config.json), never tool arguments: this
    // tool signs with the owner's L1 key, and an agent that chooses where and
    // against which contracts that key signs effectively holds the key.
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ClaimDepositArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    /// Path returned by `deposit`; or pass deposit_index instead.
    #[serde(default)]
    backup_path: Option<String>,
    #[serde(default)]
    deposit_index: Option<u64>,
    #[serde(default)]
    services_url: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct RetryDepositDeliveryArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    /// Recovery file written by `deposit`; or pass deposit_index instead.
    #[serde(default)]
    backup_path: Option<String>,
    #[serde(default)]
    deposit_index: Option<u64>,
    #[serde(default)]
    services_url: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PublicClaimSpec {
    sender_user_id: u64,
    #[serde(default = "default_psy")]
    token: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PrivateNoteSpec {
    /// A `note_proof` envelope (or a whole `psy_private_payment` packet).
    note: String,
    #[serde(default = "default_psy")]
    token: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ClaimBatchArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    /// Public `simple_claim` items — one per sender, any mix of PSY/USDT.
    #[serde(default)]
    public_claims: Vec<PublicClaimSpec>,
    /// Public `simple_transfer` legs fused into the SAME proof — any mix of
    /// PSY/USDT, different recipients, all-or-nothing with the rest.
    #[serde(default)]
    transfers: Vec<TransferLegSpec>,
    /// `withdraw` legs fused into the SAME proof (burn on Psy; the relayer
    /// settles the L1 leg). Same semantics as the standalone withdraw.
    #[serde(default)]
    withdraws: Vec<WithdrawLegSpec>,
    /// Deposit indices saved by `deposit`.
    #[serde(default)]
    deposit_indices: Vec<u64>,
    /// Alternative to `deposit_indices`: paths returned by `deposit`.
    #[serde(default)]
    backup_paths: Vec<String>,
    /// Explicit private notes to fold in.
    #[serde(default)]
    private_notes: Vec<PrivateNoteSpec>,
    /// Also drain whatever psy-services is holding for this wallet.
    #[serde(default)]
    drain_private: bool,
    /// Token used when `drain_private` is true.
    #[serde(default = "default_psy")]
    private_token: String,
    #[serde(default)]
    services_url: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct TransferLegSpec {
    to_user_id: u64,
    #[serde(rename = "amount")]
    amount_nano: u64,
    #[serde(default = "default_psy")]
    token: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct WithdrawLegSpec {
    #[serde(rename = "amount")]
    amount_nano: u64,
    #[serde(default = "default_psy")]
    token: String,
    /// Ethereum address to receive the funds.
    l1_recipient: String,
    /// L1 ERC-20 address; defaults to the staging deployment for the token.
    #[serde(default)]
    l1_token_address: Option<String>,
    /// Psy's internal chain index for the destination (0 = the L1 it bridges
    /// to).
    #[serde(default)]
    dest_chain_index: u64,
    /// Unique per withdrawal; defaults to the current unix time.
    #[serde(default)]
    nonce: Option<u64>,
}

fn default_usdt() -> String {
    "USDT".to_string()
}

fn network_l1_rpc(wallet: &WalletManager, network: &NetworkId) -> Result<String, String> {
    required_network_value(wallet.l1_rpc_url(network), network, "l1_rpc_urls")
}
fn network_router(wallet: &WalletManager, network: &NetworkId) -> Result<String, String> {
    required_network_value(wallet.l1_router_address(network), network, "l1_router_address")
}
fn network_erc20_gateway(wallet: &WalletManager, network: &NetworkId) -> Result<String, String> {
    required_network_value(wallet.l1_erc20_gateway_address(network), network, "l1_erc20_gateway_address")
}
fn network_bridge(wallet: &WalletManager, network: &NetworkId) -> Result<String, String> {
    required_network_value(wallet.l1_bridge_address(network), network, "l1_bridge_address")
}

fn default_x402_network(psy_network: &NetworkId) -> String {
    std::env::var("PSY_MCP_X402_NETWORK").unwrap_or_else(|_| psy_network.as_str().to_string())
}

/// Bodies can be large; keep tool output readable.

/// SSRF guard for x402_fetch: the URL is agent-supplied and the response body
/// is returned into model context, so an unguarded fetch is a free read of the
/// server's network position — cloud metadata (169.254.169.254), the local
/// coordinator/prove-proxy ports, anything on the LAN. Allow only http(s) to
/// public addresses; PSY_MCP_X402_ALLOW_PRIVATE=1 opts back in for local
/// development against sellers on localhost. Redirects are refused separately
/// (Policy::none()) so a public host cannot bounce the request somewhere
/// private. Residual risk we accept: DNS answers are not pinned to the socket,
/// so a rebinding resolver defeats this — the env var is a dev switch, not a
/// sandbox.

/// Resolve a URL the agent MAY override, guarding only the override.
///
/// Every one of these arguments already had a server-side default the owner
/// configures. The threat is not the default — it is the agent CHOOSING the
/// destination: `get_activity(services_url: "http://169.254.169.254/…")` reads
/// cloud metadata, the local coordinator, the prove-proxy, or anything on the
/// LAN, and `get_activity` and `private_claim` echo the remote body straight
/// back into model context on failure.
///
/// The SSRF guard existed and was applied at exactly ONE of seven such
/// arguments (x402_fetch's url). This applies it to the rest.
///
/// The owner's OWN default is deliberately not guarded: a deployment may
/// legitimately point at a private services host, and refusing that would break
/// it for a threat that is not present — the owner is the one who set it.

/// Is a settled payment recent enough to be payment for a resource served NOW?
///
/// Extracted so the fail-closed rule is testable. Both inputs are `Option`
/// because the row may omit its checkpoint and the coordinator may be
/// unreachable — and BOTH of those used to skip the check entirely rather than
/// refuse, which let an arbitrarily old receipt buy something today.
///
/// `Ok(())` only when we positively know the payment is within `max_age`.
pub fn check_payment_age(paid_at: Option<u64>, latest: Option<u64>, max_age: u64) -> Result<(), String> {
    let Some(paid_at) = paid_at else {
        return Err("no settlement checkpoint — the payment's age cannot be established".into());
    };
    let Some(latest) = latest else {
        return Err("the chain could not be reached to establish the payment's age".into());
    };
    let age = latest.saturating_sub(paid_at);
    if age > max_age {
        return Err(format!("settled {age} checkpoints ago (limit {max_age})"));
    }
    Ok(())
}

/// The identity under which a settled payment is marked used, or an error when
/// it has none.
///
/// A payment with no unique row identity cannot be enforced as one-use, and the
/// field-based match that normally selects the row does NOT require a tx_hash —
/// so this used to be skipped, letting one payment unlock any number of
/// resources.
pub fn payment_consume_key(row_tx_hash: Option<&str>) -> Result<String, String> {
    match row_tx_hash {
        Some(h) if !h.trim().is_empty() => Ok(h.to_string()),
        _ => Err("no transaction hash — the payment cannot be marked as used".into()),
    }
}

pub fn resolve_agent_url(
    supplied: Option<&str>,
    configured: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    match supplied {
        Some(u) => guard_outbound_url(u).map(|()| u.to_string()),
        None => configured(),
    }
}

pub fn guard_outbound_url(raw: &str) -> Result<(), String> {
    let url: reqwest::Url = raw.parse().map_err(|e| format!("bad URL {raw}: {e}"))?;
    match url.scheme() {
        // ws/wss for the Nostr relay override; http/https for every service URL.
        "http" | "https" | "ws" | "wss" => {}
        other => return Err(format!("refusing to reach a {other}:// URL — only http(s) and ws(s)")),
    }
    if std::env::var("PSY_MCP_X402_ALLOW_PRIVATE").map(|v| v == "1").unwrap_or(false) {
        return Ok(());
    }
    let host = url.host_str().ok_or_else(|| "URL has no host".to_string())?.to_string();
    // `host_str()` serializes an IPv6 literal WITH brackets ("[::1]"), which
    // to_socket_addrs cannot parse — so `http://[::1]:3000` never produced an
    // address to inspect and fell through to allowed. Strip them.
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port)).map_err(|e| format!("could not resolve {host}: {e}"))?;
    // FAIL CLOSED on an empty resolution. The loop below only rejects addresses
    // it actually sees, so zero addresses meant zero rejections and the guard
    // returned Ok — a name that resolves to nothing was treated as safe.
    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        let bad = match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                ip.is_loopback() || ip.is_private() || ip.is_link_local()
                    || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()
                    || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64) // CGNAT 100.64/10
            }
            std::net::IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
                    || (ip.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                    || (ip.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                    || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback() || v4.is_private() || v4.is_link_local())
            }
        };
        if bad {
            return Err(format!(
                "refusing to fetch {raw}: {host} resolves to a private/internal address ({}) — set PSY_MCP_X402_ALLOW_PRIVATE=1 only for local development",
                addr.ip()
            ));
        }
    }
    if !saw_any {
        return Err(format!(
            "refusing to reach {raw}: {host} resolved to no addresses, so it cannot be checked"
        ));
    }
    Ok(())
}

fn truncate(body: &str) -> String {
    const MAX: usize = 4000;
    if body.len() <= MAX {
        return body.to_string();
    }
    // Cut on a char boundary — a remote body with a multi-byte char straddling
    // the offset must not be able to panic the tool.
    let mut cut = MAX;
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}… [{} bytes truncated]", &body[..cut], body.len() - cut)
}

fn network_services_url(wallet: &WalletManager, network: &NetworkId) -> Result<String, String> {
    required_network_value(wallet.api_services_url(network), network, "api_services_url")
}

enum DepositMaterial {
    Ready {
        note: crate::wallet::DepositNote,
        proof: serde_json::Value,
    },
    AlreadyClaimed {
        note: crate::wallet::DepositNote,
    },
}

/// Load a persisted deposit note and its services merkle proof, or explain
/// why it is not claimable yet. Shared by `claim_deposit` and `claim_batch`.
async fn load_claimable_deposit(
    wallet: &WalletManager,
    network: &str,
    backup_path: Option<String>,
    deposit_index: Option<u64>,
    services_url: Option<&str>,
) -> Result<DepositMaterial, (String, serde_json::Value)> {
    let dir = crate::keystore::keystore_dir();
    let path = match backup_path {
        Some(p) => std::path::PathBuf::from(p),
        None => match deposit_index {
            Some(i) => crate::wallet::DepositNote::path_in(&dir, network, i).map_err(|e| (format!("{e:#}"), json!({ "gate": "network" })))?,
            None => {
                return Err((
                    "pass backup_path or deposit_index (both are in deposit's output)".to_string(),
                    json!({ "gate": "args" }),
                ))
            }
        },
    };
    let mut note = crate::wallet::DepositNote::load(&path).map_err(|e| (format!("{e:#}"), json!({ "gate": "load" })))?;
    match note.network.as_deref() {
        Some(saved) if saved != network => {
            return Err((
                format!("deposit backup belongs to network `{saved}`, not `{network}`"),
                json!({ "gate": "network", "backupNetwork": saved, "network": network }),
            ));
        }
        None => note.network = Some(network.to_string()),
        _ => {}
    }
    if note.claimed {
        return Ok(DepositMaterial::AlreadyClaimed { note });
    }

    let network_id = NetworkId::new(network).map_err(|e| (format!("{e:#}"), json!({ "gate": "network" })))?;
    let services = resolve_agent_url(services_url, || network_services_url(wallet, &network_id)).map_err(|e| (e, json!({ "gate": "url" })))?;
    // proved_deposit_count is read from the L1 bridge and passed through
    // HONESTLY. Inflating it past reality makes the service build a proof
    // over a tree the chain does not have yet — which then fails at the
    // claim itself with an opaque error instead of a retryable "not yet".
    let bridge_value = network_bridge(wallet, &network_id).map_err(|e| (e, json!({ "gate": "config", "field": "l1_bridge_address" })))?;
    let bridge: alloy_primitives::Address = bridge_value.parse().map_err(|e| {
        (
            format!("network `{network_id}` has an invalid `l1_bridge_address`: {e}"),
            json!({ "gate": "config", "field": "l1_bridge_address" }),
        )
    })?;
    // Read the proved count keylessly — this is a plain eth_call; it needs no
    // signer. The old from_env-or-0 here made every keyless claim read a fake 0
    // and report "relayer still working" long after the chain proved the deposit.
    let l1_rpc = network_l1_rpc(wallet, &network_id).map_err(|e| (e, json!({ "gate": "config", "field": "l1_rpc_urls" })))?;
    let proved = crate::l1::L1Client::read_only(l1_rpc)
        .call_u64(bridge, "provedDepositCount()")
        .await
        .unwrap_or(0);
    if proved <= note.expected_deposit_index {
        return Err((
            format!(
                "deposit {} is not proved on Psy yet (bridge has proved {} deposits) — the relayer is still working; retry shortly",
                note.expected_deposit_index, proved
            ),
            json!({ "gate": "unproved", "depositIndex": note.expected_deposit_index, "provedCount": proved }),
        ));
    }
    let url = format!(
        "{}/api/v1/bridge/deposit-claim-proof?deposit_index={}&source_chain_index={}&proved_deposit_count={}",
        services.trim_end_matches('/'),
        note.expected_deposit_index,
        note.source_chain_index,
        proved,
    );
    let body: serde_json::Value = match reqwest::Client::new().get(&url).send().await {
        Ok(r) => r
            .json()
            .await
            .map_err(|e| (format!("psy-services returned non-JSON: {e}"), json!({ "gate": "services" })))?,
        Err(e) => {
            return Err((
                format!("psy-services unreachable: {e}"),
                json!({ "gate": "services" }),
            ))
        }
    };
    let data = body.get("data").cloned().unwrap_or(json!({}));
    if data.get("found").and_then(|f| f.as_bool()) != Some(true) {
        return Err((
            format!(
                "the deposit is not claimable yet (reason: {}) — the relayer may still be proving it",
                data.get("reason").and_then(|r| r.as_str()).unwrap_or("unknown")
            ),
            json!({ "gate": "unproved", "depositIndex": note.expected_deposit_index }),
        ));
    }
    Ok(DepositMaterial::Ready { note, proof: data })
}

#[derive(Deserialize, schemars::JsonSchema)]
struct WithdrawArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    /// Ethereum address to receive the funds.
    l1_recipient: String,
    #[serde(rename = "amount")]
    amount_nano: u64,
    #[serde(default = "default_psy")]
    token: String,
    /// L1 ERC-20 address; defaults to the staging deployment for the token.
    #[serde(default)]
    l1_token_address: Option<String>,
    /// Psy's internal chain index for the destination (0 = the L1 it bridges to).
    #[serde(default)]
    dest_chain_index: u64,
    /// Unique per withdrawal; defaults to the current unix time.
    #[serde(default)]
    nonce: Option<u64>,
}

fn network_l1_token(wallet: &WalletManager, network: &NetworkId, token: &str) -> Option<String> {
    wallet.l1_token_address(network, token)
}

/// Slot holding the note-tree root in the token contract's state.
const NOTE_ROOT_SLOT: u64 = 2_147_483_649;

#[tool_handler]
impl ServerHandler for PsyWalletServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "psy-wallet".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "Psy wallet over MCP. Real client-side ZK proving via WalletSession. \
                 Create/load a wallet, issue a session, then spend under policy caps. \
                 Amounts are in Nano (1 PSY = 1e9 Nano)."
                    .into(),
            ),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).with_ansi(false).init();

    let mut config_path = std::env::var("PSY_CONFIG").unwrap_or_else(|_| "config.json".into());
    let mut network = std::env::var("PSY_MCP_NETWORK").ok().filter(|v| !v.trim().is_empty());
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next().ok_or_else(|| anyhow::anyhow!("--config requires a path"))?,
            "--network" => network = Some(args.next().ok_or_else(|| anyhow::anyhow!("--network requires a name"))?),
            "-h" | "--help" => {
                eprintln!("Usage: psy-mcp-server [--config <path>] [--network <name>]\n\nEnvironment: PSY_CONFIG, PSY_MCP_NETWORK");
                return Ok(());
            }
            other => anyhow::bail!("unknown argument `{other}` (use --help)"),
        }
    }
    tracing::info!("loading Psy config from {config_path}");
    let wallet = WalletManager::from_config(&config_path, network.as_deref()).await?;
    tracing::info!("using default Psy network {}", wallet.default_network());

    startup::restore_wallets(&wallet).await?;
    if std::env::var("PSY_MCP_OWNER_TOKEN").map(|v| v.trim().is_empty()).unwrap_or(true) {
        tracing::warn!(
            "PSY_MCP_OWNER_TOKEN is not set: owner tools (issue_session, resume_policy, \
             create_wallet, mint_agent_account) are callable by the agent, so a paused \
             policy can be un-paused and a revoked session re-minted by the party they \
             were meant to stop. Widening a policy (raising a cap, dropping a ceiling, \
             clearing an allow-list) is REFUSED outright in this mode, because there is \
             no way to tell the owner from the agent. Fine for local development; set it \
             in production."
        );
    }
    tracing::info!("WalletSession ready — serving MCP over stdio");

    let service = PsyWalletServer::new(wallet).await.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod router_tests {
    use super::PsyWalletServer;

    #[test]
    fn every_domain_router_is_merged() {
        let router = PsyWalletServer::tool_router()
            + PsyWalletServer::wallet_tools_router()
            + PsyWalletServer::claims_tools_router()
            + PsyWalletServer::private_tools_router()
            + PsyWalletServer::x402_tools_router();
        let names = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(names.len(), 40);
        for required in ["create_wallet", "get_balance", "private_transfer", "x402_fetch", "x402_verify"] {
            assert!(names.contains(required), "missing tool route {required}");
        }
    }
}

#[cfg(test)]
mod url_guard_tests {
    use super::{guard_outbound_url, resolve_agent_url};

    // The SSRF guard existed and was applied at exactly ONE of seven
    // agent-supplied URL arguments. The other six let the agent choose the
    // destination — and get_activity and private_claim echo the remote body
    // straight back into model context on failure, which turns "reach an
    // internal host" into "read an internal host".

    fn default_url() -> Result<String, String> {
        Ok("https://services-stg.psy-protocol.xyz".to_string())
    }

    #[test]
    fn an_agent_override_pointing_at_cloud_metadata_is_refused() {
        let err = resolve_agent_url(Some("http://169.254.169.254/latest/meta-data/"), default_url)
            .expect_err("link-local metadata must be refused");
        assert!(!err.is_empty());
    }

    #[test]
    fn an_agent_override_pointing_at_loopback_is_refused() {
        // The local coordinator, realm and prove-proxy all live here.
        for u in [
            "http://127.0.0.1:1337",
            "http://localhost:9998/psy_get_circuits_data",
            "http://[::1]:3000",
        ] {
            assert!(resolve_agent_url(Some(u), default_url).is_err(), "loopback must be refused: {u}",);
        }
    }

    #[test]
    fn a_non_http_scheme_is_refused() {
        for u in ["file:///etc/passwd", "gopher://x/", "ftp://x/"] {
            assert!(resolve_agent_url(Some(u), default_url).is_err(), "{u}");
        }
    }

    #[test]
    fn websocket_schemes_are_allowed_because_the_relay_override_needs_them() {
        // private_transfer's `relay` is a Nostr websocket. Rejecting ws/wss
        // would have made this guard unusable there.
        assert!(guard_outbound_url("wss://nostr-stg.psy-protocol.xyz").is_ok());
    }

    #[test]
    fn a_public_https_override_is_allowed() {
        let got = resolve_agent_url(Some("https://services-stg.psy-protocol.xyz"), default_url)
            .expect("a public host is a legitimate override");
        assert_eq!(got, "https://services-stg.psy-protocol.xyz");
    }

    #[test]
    fn the_owners_OWN_default_is_never_guarded() {
        // A deployment may legitimately point at a private services host. The
        // threat is the AGENT choosing the destination, not the owner — and
        // refusing the owner's own config would break the deployment for a
        // threat that is not present.
        let got = resolve_agent_url(None, || Ok("http://127.0.0.1:3000".to_string()))
            .expect("the owner's default must pass untouched");
        assert_eq!(got, "http://127.0.0.1:3000");
    }

    #[test]
    fn a_malformed_url_is_refused_rather_than_fetched() {
        assert!(resolve_agent_url(Some("not a url"), default_url).is_err());
        assert!(resolve_agent_url(Some(""), default_url).is_err());
    }
}

#[cfg(test)]
mod x402_verify_gate_tests {
    use super::{check_payment_age, payment_consume_key};

    // Both of these gates were written as `if let ... { check }` with NO else,
    // so the check was SKIPPED whenever its input was missing — the classic
    // fail-open shape: "reject what I recognise as bad" instead of "permit only
    // what I recognise as good".

    #[test]
    fn a_recent_payment_passes() {
        assert!(check_payment_age(Some(1000), Some(1100), 240).is_ok());
    }

    #[test]
    fn an_old_payment_is_refused() {
        let err = check_payment_age(Some(1000), Some(2000), 240).unwrap_err();
        assert!(err.contains("1000 checkpoints ago"), "{err}");
    }

    #[test]
    fn a_row_with_NO_checkpoint_is_refused_not_skipped() {
        // Used to skip the age gate entirely: an arbitrarily old receipt then
        // bought a resource served today.
        let err = check_payment_age(None, Some(2000), 240).unwrap_err();
        assert!(err.contains("cannot be established"), "{err}");
    }

    #[test]
    fn an_unreachable_chain_is_refused_not_skipped() {
        // A coordinator outage must not become "accept anything".
        let err = check_payment_age(Some(1), None, 240).unwrap_err();
        assert!(err.contains("could not be reached"), "{err}");
    }

    #[test]
    fn exactly_at_the_limit_is_still_accepted() {
        assert!(check_payment_age(Some(1000), Some(1240), 240).is_ok());
        assert!(check_payment_age(Some(1000), Some(1241), 240).is_err());
    }

    #[test]
    fn a_clock_that_runs_backwards_does_not_underflow_into_acceptance() {
        // saturating_sub: a paid_at ahead of latest yields age 0, not a huge
        // wrapped number — and 0 is within any limit, which is the safe read.
        assert!(check_payment_age(Some(5000), Some(1000), 240).is_ok());
    }

    #[test]
    fn a_payment_with_a_hash_can_be_consumed() {
        assert_eq!(payment_consume_key(Some("0xabc")).unwrap(), "0xabc");
    }

    #[test]
    fn a_payment_with_NO_hash_is_refused_not_silently_unconsumed() {
        // The field-based match does not require a tx_hash, so this row shape
        // is reachable — and it used to unlock resources without ever being
        // marked used.
        assert!(payment_consume_key(None).is_err());
        assert!(payment_consume_key(Some("")).is_err());
        assert!(payment_consume_key(Some("   ")).is_err());
    }
}
