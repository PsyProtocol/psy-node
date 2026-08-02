//! Psy Wallet — MCP server (native Rust, over `WalletSession`).
//!
//! Exposes the real Psy wallet engine (`psy_prover::session::WalletSession`) to
//! AI agents as MCP tools, so registration, transfers, and claim/UPS batching
//! run with REAL client-side Plonky2 proving through the prove-proxy — not a
//! mock. Human control is expressed ahead of time as spending policy (caps +
//! allowlists + session TTL, enforced below the model in `policy.rs`); the
//! agent holds a session token and never the key.
//!
//! Config (endpoints incl. prove_proxy_url and api_services_url) is read from
//! the standard Psy `config.json` via `PsyConfigGoldilocks`, exactly as the CLI
//! and the relayer daemon build their sessions.

mod nostr_delivery;
mod policy;
mod wallet;

use std::{future::Future, sync::Arc};

use policy::{Limits, PolicyEngine};
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::Parameters},
    model::{CallToolResult, Content, ErrorData as McpError, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use wallet::{WalletManager, CONTRACT_PSY, CONTRACT_USDT};

fn contract_for(token: &str) -> u64 {
    match token.to_ascii_uppercase().as_str() {
        "USDT" => CONTRACT_USDT,
        _ => CONTRACT_PSY,
    }
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

struct Inner {
    wallet: WalletManager,
    policy: PolicyEngine,
}

#[derive(Clone)]
pub struct PsyWalletServer {
    inner: Arc<Mutex<Inner>>,
    tool_router: ToolRouter<PsyWalletServer>,
}

// ── Tool argument schemas ─────────────────────────────────────────────

#[derive(Deserialize, schemars::JsonSchema)]
struct CreateWalletArgs {
    /// "generate" a fresh key and register it, or "load" an existing private
    /// key.
    #[serde(default = "default_generate")]
    mode: String,
    /// Required for mode="load": the private key (QHashOut hex).
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default = "default_agent")]
    agent_id: String,
    #[serde(default)]
    per_transaction_nano: Option<u64>,
    #[serde(default)]
    per_day_nano: Option<u64>,
    #[serde(default)]
    total_budget_nano: Option<u64>,
}
fn default_generate() -> String {
    "generate".into()
}
fn default_agent() -> String {
    "default-agent".into()
}

#[derive(Deserialize, schemars::JsonSchema)]
struct IssueSessionArgs {
    policy_id: String,
    #[serde(default = "default_ttl")]
    ttl_minutes: u64,
}
fn default_ttl() -> u64 {
    60
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PolicyIdArgs {
    policy_id: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SessionArg {
    session: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct TransferArgs {
    session: String,
    to_user_id: u64,
    amount_nano: u64,
    #[serde(default = "default_psy")]
    token: String,
}
fn default_psy() -> String {
    "PSY".into()
}

#[tool_router]
impl PsyWalletServer {
    pub fn new(wallet: WalletManager) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                wallet,
                policy: PolicyEngine::new(),
            })),
            tool_router: Self::tool_router(),
        }
    }

    // ── Owner / policy ────────────────────────────────────────────────

    #[tool(
        description = "Create a wallet: generate a fresh Psy key and register it on-chain, or load an existing private key. Also creates a spending policy the agent draws sessions from."
    )]
    async fn create_wallet(&self, Parameters(a): Parameters<CreateWalletArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        let loaded = if a.mode == "load" {
            match &a.private_key {
                Some(pk) => inner.wallet.load(pk).await,
                None => return err_json("mode=load requires private_key", json!({})),
            }
        } else {
            match inner.wallet.generate_keypair().await {
                Ok((pk, _fp)) => inner.wallet.register(&pk).await,
                Err(e) => Err(e),
            }
        };
        let loaded = match loaded {
            Ok(l) => l,
            Err(e) => return err_json(e, json!({})),
        };
        let limits = Limits {
            per_transaction: a.per_transaction_nano.unwrap_or(5_000_000_000),
            per_day: a.per_day_nano.unwrap_or(50_000_000_000),
            total_budget: a.total_budget_nano,
        };
        let policy_id = inner.policy.create_policy(&a.agent_id, limits, vec![], vec![]);
        ok_json(json!({
            "userId": loaded.user_id,
            "psyId": format!("Psy-{:08}", loaded.user_id),
            "policyId": policy_id,
            "note": "Key registered with REAL on-chain proving via WalletSession. Issue a session with issue_session to let the agent spend."
        }))
    }

    #[tool(description = "Owner: mint a short-TTL session token for the agent from a policy.")]
    async fn issue_session(&self, Parameters(a): Parameters<IssueSessionArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        match inner.policy.issue_session(&a.policy_id, a.ttl_minutes) {
            Ok((token, exp)) => ok_json(json!({ "token": token, "expiresAt": exp })),
            Err(e) => err_json(e, json!({})),
        }
    }

    #[tool(description = "Owner: pause a policy. Every subsequent spend authorization fails immediately.")]
    async fn pause_policy(&self, Parameters(a): Parameters<PolicyIdArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        if inner.policy.pause(&a.policy_id) {
            ok_json(json!({ "paused": a.policy_id }))
        } else {
            err_json("policy not found", json!({}))
        }
    }

    #[tool(description = "Owner: resume a paused policy.")]
    async fn resume_policy(&self, Parameters(a): Parameters<PolicyIdArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        if inner.policy.resume(&a.policy_id) {
            ok_json(json!({ "resumed": a.policy_id }))
        } else {
            err_json("policy not found", json!({}))
        }
    }

    #[tool(description = "Owner: revoke an agent session token immediately.")]
    async fn revoke_session(&self, Parameters(a): Parameters<SessionArg>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        if inner.policy.revoke(&a.session) {
            ok_json(json!({ "revoked": true }))
        } else {
            err_json("token not found", json!({}))
        }
    }

    #[tool(description = "Agent: remaining spend under the active policy (daily / total / per-tx), in Nano.")]
    async fn check_budget(&self, Parameters(a): Parameters<SessionArg>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        match inner.policy.budget(&a.session) {
            Some((day, total, per_tx)) => ok_json(json!({ "remainingDayNano": day, "remainingTotalNano": total, "maxPerTxNano": per_tx })),
            None => err_json("invalid or expired session", json!({})),
        }
    }

    // ── Live reads ─────────────────────────────────────────────────────

    #[tool(description = "Live chain status: the latest coordinator checkpoint id.")]
    async fn get_chain_status(&self) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        match inner.wallet.latest_checkpoint().await {
            Ok(cp) => ok_json(json!({ "checkpointId": cp })),
            Err(e) => err_json(format!("chain unreachable: {e}"), json!({})),
        }
    }

    #[tool(description = "Info about the loaded wallet: user id and Psy ID.")]
    async fn get_user_info(&self) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        match inner.wallet.current_user() {
            Some(u) => ok_json(json!({ "userId": u.user_id, "psyId": format!("Psy-{:08}", u.user_id) })),
            None => err_json("no wallet loaded", json!({})),
        }
    }

    #[tool(description = "Public claimable (Nano) owed to the loaded wallet by a specific sender user id.")]
    async fn get_claimable(&self, Parameters(a): Parameters<ClaimableArgs>) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        match inner.wallet.claim_amount_from(a.sender_user_id).await {
            Ok(amount) => ok_json(json!({ "senderUserId": a.sender_user_id, "claimableNano": amount })),
            Err(e) => err_json(e, json!({ "failClosed": true })),
        }
    }

    // ── Spend (policy-gated → REAL proof via WalletSession) ────────────

    #[tool(
        description = "Public transfer by user id, with REAL client-side proving. Policy-gated: the session's caps/allowlist must permit it. Returns the submitted end-user-leaf-hash."
    )]
    async fn transfer(&self, Parameters(a): Parameters<TransferArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        // 1. Policy gate BELOW the model.
        let auth = inner
            .policy
            .authorize(&a.session, &a.to_user_id.to_string(), a.amount_nano, "simple_transfer");
        if let Err(e) = auth {
            return err_json(format!("policy denied: {e}"), json!({ "gate": "policy" }));
        }
        // 2. Real proof + submit through WalletSession.
        let contract = contract_for(&a.token);
        match inner.wallet.transfer(a.to_user_id, a.amount_nano, contract).await {
            Ok(leaf) => ok_json(
                json!({ "submitted": true, "endUserLeafHash": leaf, "toUserId": a.to_user_id, "amountNano": a.amount_nano, "token": a.token }),
            ),
            Err(e) => err_json(format!("transfer failed: {e}"), json!({ "gate": "execute" })),
        }
    }

    #[tool(
        description = "Claim ALL public claimables owed by the given senders, fused into ONE UPS proof / one fee (real proving). Claiming only folds funds already addressed to you into spendable balance. Discover sender ids with get_claimable."
    )]
    async fn claim_all(&self, Parameters(a): Parameters<ClaimAllArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        // Policy gate — claims move value into the account, so we gate them too
        // (amount 0: claiming does not spend). This keeps a paused policy able to
        // freeze all activity.
        if let Err(e) = inner.policy.authorize(&a.session, "self", 0, "simple_claim") {
            return err_json(format!("policy denied: {e}"), json!({ "gate": "policy" }));
        }
        let contract = contract_for(&a.token);
        match inner.wallet.claim_all_public(a.sender_user_ids.clone(), contract).await {
            Ok(leaf) => ok_json(
                json!({ "submitted": true, "endUserLeafHash": leaf, "claimedFrom": a.sender_user_ids, "token": a.token, "note": "One UPS proof, one fee." }),
            ),
            Err(e) => err_json(format!("claim_all failed: {e}"), json!({ "gate": "execute" })),
        }
    }

    #[tool(
        description = "PREPARE a private transfer to a shielded address: derives the note and the exact on-chain call, WITHOUT submitting. Settlement is withheld on purpose — a private transfer is only claimable once its note is delivered to the recipient over Nostr in the exact format their wallet drains, and that delivery is not yet wired/verified here. Submitting before delivery is verified would strand the funds. This returns the note material and the prepared call for inspection."
    )]
    async fn private_transfer(&self, Parameters(a): Parameters<PrivateTransferArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        // Policy gate below the model (this WOULD spend, so gate at the amount).
        if let Err(e) = inner
            .policy
            .authorize(&a.session, &a.to_shielded_address, a.amount_nano, "private_transfer")
        {
            return err_json(format!("policy denied: {e}"), json!({ "gate": "policy" }));
        }
        let contract = contract_for(&a.token);
        match inner.wallet.prepare_private_transfer(&a.to_shielded_address, a.amount_nano, contract) {
            Ok(p) => ok_json(json!({
                "prepared": true,
                "submitted": false,
                "reason": "Settlement withheld until Nostr note delivery is wired and verified against recipient wallets (delivery-format mismatch risk would otherwise strand funds).",
                "toShielded": a.to_shielded_address,
                "amountNano": a.amount_nano,
                "token": a.token,
                "noteCommitment": p.note_commitment,
                "callInputs": p.call_inputs,
            })),
            Err(e) => err_json(format!("prepare failed: {e}"), json!({ "gate": "prepare" })),
        }
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ClaimableArgs {
    sender_user_id: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ClaimAllArgs {
    session: String,
    /// User ids that owe you public claims (discover via get_claimable).
    sender_user_ids: Vec<u64>,
    #[serde(default = "default_psy")]
    token: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PrivateTransferArgs {
    session: String,
    to_shielded_address: String,
    amount_nano: u64,
    #[serde(default = "default_psy")]
    token: String,
}

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

    let config_path = std::env::var("PSY_CONFIG").unwrap_or_else(|_| "config.json".into());
    tracing::info!("loading Psy config from {config_path}");
    let wallet = WalletManager::from_config(&config_path).await?;
    tracing::info!("WalletSession ready — serving MCP over stdio");

    let service = PsyWalletServer::new(wallet).serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
