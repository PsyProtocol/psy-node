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

use policy::{Limits, PolicyEngine, SELF_RECIPIENT};
use wallet::{WalletManager, CONTRACT_PSY, CONTRACT_USDT};

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
    /// Indexer tx hashes x402_verify has already accepted. One settled payment
    /// must not satisfy an unlimited stream of resources: the first verify
    /// consumes it, later verifies of the same row report a replay. PERSISTED
    /// to <keystore>/consumed_payments.json — a restart must not empty this,
    /// or an old-but-still-in-window payment (age < max_age_checkpoints) could
    /// be re-presented and re-accepted, serving the resource a second time
    /// for free.
    consumed_payments: std::collections::HashSet<String>,
}

/// Load the set of already-consumed x402 payment tx-hashes. Missing/corrupt
/// file → empty (first run), same fail-open-then-rebuild policy as the keystore.
fn load_consumed_payments(dir: &std::path::Path) -> std::collections::HashSet<String> {
    match std::fs::read_to_string(dir.join("consumed_payments.json")) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Default::default(),
    }
}

/// Atomic 0600 write, same discipline as policies.json/the keystore. A failure
/// is logged, not fatal: refusing to serve because the DISK is full would brick
/// the seller, and the in-memory set is still correct for this process.
fn save_consumed_payments(dir: &std::path::Path, set: &std::collections::HashSet<String>) {
    let path = dir.join("consumed_payments.json");
    let tmp = path.with_extension("json.tmp");
    let write = (|| -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(serde_json::to_string(set)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    })();
    if let Err(e) = write {
        tracing::warn!("could not persist consumed_payments: {e:#}");
    }
}

#[derive(Clone)]
pub struct PsyWalletServer {
    inner: Arc<Mutex<Inner>>,
    /// The policy engine lives OUTSIDE the wallet mutex, behind a sync lock
    /// that is never held across an await: the wallet lock is held for whole
    /// tool bodies, including multi-minute proving and settlement waits, and
    /// the emergency pause must not queue behind them. This is what makes
    /// pause_policy an actual kill switch instead of a 10-minute promise.
    policy: Arc<std::sync::Mutex<PolicyEngine>>,
    tool_router: ToolRouter<PsyWalletServer>,
}

// ── Tool argument schemas ─────────────────────────────────────────────

#[derive(Deserialize, schemars::JsonSchema)]
struct CreateWalletArgs {
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
    /// Existing project name.
    project: String,
    /// Agent spending session. Deploying is POLICY-GATED like any spend: the
    /// policy must explicitly allow the `deploy_contract` method (owner adds it
    /// via update_policy), and the deploy fee is charged against the caps.
    session: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct CallContractArgs {
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
    /// Rolling 30-day cap. OMIT to leave it unchanged; pass `null` to remove it.
    #[serde(default, alias = "perMonth")]
    per_month_nano: Option<Option<u64>>,
    /// Lifetime cap. OMIT to leave it unchanged; pass `null` to remove it.
    #[serde(default, deserialize_with = "double_option", alias = "totalBudget")]
    total_budget_nano: Option<Option<u64>>,
    /// Who the agent may pay. OMIT to leave the current allow-list unchanged
    /// (so a "tighten my budget" edit can never silently widen it to anyone);
    /// pass `null` to explicitly clear it (pay anyone); pass a list to replace it.
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
        Ok(v) if !v.trim().is_empty() => owner_gate(supplied).map_err(|_| {
            format!("refused: this edit {what} — only the owner may widen a policy, and the owner_token argument does not match")
        }),
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
    session: String,
    /// The payments to make. All-or-nothing: if the policy refuses any one of
    /// them, none are sent and no budget is consumed.
    payments: Vec<BatchPayment>,
    #[serde(default = "default_psy")]
    token: String,
}

#[tool_router]
impl PsyWalletServer {
    pub fn new(wallet: WalletManager) -> Self {
        // A wallet restored at startup (PSY_MCP_KEY_FILE) is already loaded by
        // the time the engine is built, so tell the engine which identity it is
        // governing before it authorizes anything.
        let restored = wallet.current_user().map(|u| u.user_id);
        let mut engine = PolicyEngine::load_or_new(&keystore::keystore_dir());
        if let Some(uid) = restored {
            engine.set_current_user(uid);
        }
        Self {
            inner: Arc::new(Mutex::new(Inner {
                wallet,
                consumed_payments: load_consumed_payments(&keystore::keystore_dir()),
            })),
            // Budgets — including the lifetime cap — survive restarts; an
            // engine that forgets its counters re-grants them on every crash
            // loop.
            policy: Arc::new(std::sync::Mutex::new(engine)),
            tool_router: Self::tool_router(),
        }
    }

    // ── Owner / policy ────────────────────────────────────────────────

    #[tool(description = "Create a wallet: generate a fresh Psy key and register it on-chain, or load an existing private key. Generated keys are durably backed up to the keystore (owner-readable file; the key itself is never returned). Also creates a spending policy the agent draws sessions from.")]
    async fn create_wallet(&self, Parameters(a): Parameters<CreateWalletArgs>) -> Result<CallToolResult, McpError> {
        if let Err(e) = owner_gate(a.owner_token.as_deref()) {
            return err_json(e, json!({ "gate": "owner" }));
        }
        // Minting a policy is the same escalation as widening one, one step to
        // the left: mode="load" reloads the SAME key, so an agent naming a
        // published key env var would otherwise get a brand-new uncapped policy
        // over the owner's live wallet and never touch update_policy. Checked
        // BEFORE any chain work, so a refusal costs nothing.
        let requested = Limits {
            per_transaction: a.per_transaction_nano.unwrap_or(5_000_000_000),
            per_day: a.per_day_nano.unwrap_or(50_000_000_000),
            per_month: a.per_month_nano,
            total_budget: a.total_budget_nano,
        };
        if let Some(what) =
            self.policy
                .lock()
                .unwrap()
                .creation_widens(&requested, &a.allowed_recipients, &[])
        {
            if let Err(e) = owner_gate_for_widening(a.owner_token.as_deref(), &what) {
                return err_json(e, json!({ "gate": "owner", "widens": what, "policyCreated": false }));
            }
        }
        let mut inner = self.inner.lock().await;
        let (loaded, key_backup_path) = if a.mode == "load" {
            // Resolve the key OUTSIDE the transcript: from the owner's
            // environment or a server-side key file, named — not carried — by
            // the argument.
            // A key file may describe an AGENT ACCOUNT, whose identity is
            // (private_key, CIRCUIT fingerprint). Reading the backup and
            // keeping only `private_key` recomputes the DEFAULT zk fingerprint,
            // which produces a different pk_hash — so the load either resolves
            // no user id at all or, worse, a different identity, and
            // describe_mandate then reports "not an agent account" for one that
            // is. load_from_backup rebuilds the circuit from the recorded
            // mandate and refuses on a fingerprint mismatch; use it whenever we
            // have a whole backup, and keep the raw-key path for the env var,
            // which carries no mandate by construction.
            let loaded = if let Some(env_name) = a.private_key_env.as_deref() {
                let pk = match std::env::var(env_name) {
                    Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
                    _ => return err_json(
                        format!("mode=load: the environment variable {env_name} is not set in the server's environment (the owner sets it; the agent only names it)"),
                        json!({ "gate": "args" })),
                };
                match inner.wallet.load(&pk).await {
                    Ok(l) => l,
                    Err(e) => return err_json(e, json!({})),
                }
            } else if let Some(file) = a.key_file.as_deref() {
                let backup = match keystore::load_key_file(file) {
                    Ok(b) => b,
                    Err(e) => return err_json(format!("mode=load: {e:#}"), json!({ "gate": "args" })),
                };
                match inner.wallet.load_from_backup(&backup).await {
                    Ok(l) => l,
                    Err(e) => return err_json(format!("mode=load: {e:#}"), json!({})),
                }
            } else {
                return err_json(
                    "mode=load requires private_key_env (the NAME of an env var holding the key) or key_file — raw keys are not accepted as arguments, because a tool argument is model context",
                    json!({ "gate": "args" }));
            };
            (loaded, None)
        } else {
            let (pk, fp) = match inner.wallet.generate_keypair().await {
                Ok(kp) => kp,
                Err(e) => return err_json(e, json!({})),
            };
            // Funds-safety invariant: the key is durably backed up BEFORE the
            // chain learns the identity. A crash after this write leaves a
            // harmless stray file; the reverse order could leave an on-chain
            // wallet whose key nobody has. See keystore.rs.
            let backup_path = match keystore::persist_generated_key(&pk, &fp) {
                Ok(p) => p,
                Err(e) => {
                    return err_json(
                        format!("key backup failed — refusing to register an unrecoverable wallet: {e:#}"),
                        json!({ "hint": format!("set {} to a writable directory", keystore::KEYSTORE_DIR_ENV) }),
                    )
                }
            };
            match inner.wallet.register(&pk).await {
                Ok(l) => (l, Some(backup_path)),
                Err(e) => {
                    tracing::info!("generated key backed up at {} (owner-side; not disclosed to the agent)", backup_path.display());
                    return err_json(
                        format!("registration failed: {e:#}"),
                        json!({
                            "note": "The generated key is safely backed up on the server host (path printed to the server log, for the OWNER); retry create_wallet once the chain is reachable."
                        }),
                    )
                }
            }
        };
        let recipient_count = a.allowed_recipients.as_ref().map(|r| r.len());
        // Bind the policy to the wallet we just loaded, and tell the engine which
        // identity this process is now operating — a policy is a budget for ONE
        // wallet, and mode="load" swaps the process's wallet globally.
        self.policy.lock().unwrap().set_current_user(loaded.user_id);
        let policy_id = self.policy.lock().unwrap().create_policy(&a.agent_id, requested, a.allowed_recipients, vec![]);
        let mut result = json!({
            "userId": loaded.user_id,
            "psyId": format!("Psy-{:08}", loaded.user_id),
            "policyId": policy_id,
            "allowedRecipientCount": recipient_count,
            "note": "Key registered with REAL on-chain proving via WalletSession. Issue a session with issue_session to let the agent spend.",
            "next": "Call describe_policy to see, in plain terms, what this agent is allowed to do.",
        });
        if let (Some(obj), Some(path)) = (result.as_object_mut(), key_backup_path) {
            // The backup path goes to the server log (the owner's terminal),
            // NEVER into the tool result: a tool result is model context, the
            // agent runs as the same uid, and a path it can read is a key it
            // holds. 0600 does not protect a file from its own owner.
            tracing::info!("wallet key backed up at {} (owner-side; not disclosed to the agent)", path.display());
            obj.insert(
                "keyBackupNote".into(),
                json!(format!(
                    "Private key backed up on the server host for the OWNER (path in the server log; never shared with the agent). Restart the server with {}=<path> to reload this wallet without exposing the key.",
                    keystore::KEY_FILE_ENV
                )),
            );
        }
        ok_json(result)
    }

    #[tool(
        description = "Owner: mint an AGENT ACCOUNT whose key is a Software-Defined Key circuit. The mandate — the \
                       (contract, method) calls it may make — is compiled into the identity, so a call outside it is \
                       UNPROVABLE rather than merely refused, and the constraint survives compromise of this server. \
                       Capabilities are given as \"contract_id:method_name\" (e.g. [\"0:simple_transfer\"]). \
                       NOTE: calls_per_transaction is enforced by EQUALITY — a transaction must contain exactly that \
                       many contract calls — so it is a transaction shape, not a budget. The circuit cannot constrain \
                       amounts or recipients; those stay operational limits (see check_budget)."
    )]
    async fn mint_agent_account(&self, Parameters(a): Parameters<MintAgentAccountArgs>) -> Result<CallToolResult, McpError> {
        if let Err(e) = owner_gate(a.owner_token.as_deref()) {
            return err_json(e, json!({ "gate": "owner" }));
        }
        let requests = match agent_account::parse_capability_requests(&a.capabilities) {
            Ok(r) => r,
            Err(e) => return err_json(e, json!({ "gate": "mandate" })),
        };
        // Same creation gate as create_wallet — checked before the (expensive,
        // irreversible) mint, so a refusal costs neither a key nor a chain
        // registration. The method set is the mandate's, which is at most as
        // wide as the capabilities just parsed.
        let requested_limits = Limits {
            per_transaction: a.per_transaction_nano.unwrap_or(5_000_000_000),
            per_day: a.per_day_nano.unwrap_or(50_000_000_000),
            per_month: a.per_month_nano,
            total_budget: a.total_budget_nano,
        };
        let requested_methods: Vec<String> =
            requests.iter().map(|r| r.method_name.clone()).collect();
        if let Some(what) = self.policy.lock().unwrap().creation_widens(
            &requested_limits,
            &a.allowed_recipients,
            &requested_methods,
        ) {
            if let Err(e) = owner_gate_for_widening(a.owner_token.as_deref(), &what) {
                return err_json(e, json!({ "gate": "owner", "widens": what, "policyCreated": false }));
            }
        }
        let mut inner = self.inner.lock().await;

        // The key is written to owner-only disk inside this closure, which runs
        // BEFORE the chain learns the identity — the same ordering invariant
        // create_wallet relies on (see keystore.rs).
        let minted = inner
            .wallet
            .mint_agent_account(&requests, a.calls_per_transaction, keystore::persist_generated_key_with_mandate)
            .await;

        let (loaded, backup_path) = match minted {
            Ok(m) => (m.user, m.key_backup),
            Err(e) => {
                return err_json(
                    format!("mint_agent_account failed: {e:#}"),
                    json!({
                        "keystoreDir": keystore::keystore_dir().display().to_string(),
                        "note": "If the failure happened after key generation the key is already backed up in keystoreDir. Recover THAT account from its backup file (identity = key + mandate circuit) — do NOT re-mint: a new mint generates a fresh random key, so it creates a NEW account with a new userId and zero balance (only the circuit is reproduced, not the identity)."
                    }),
                );
            }
        };

        let limits = Limits {
            per_transaction: a.per_transaction_nano.unwrap_or(5_000_000_000),
            per_day: a.per_day_nano.unwrap_or(50_000_000_000),
            per_month: a.per_month_nano,
            total_budget: a.total_budget_nano,
        };
        // Restrict the operational policy to the methods the circuit already
        // allows, so the two layers cannot disagree about what is permitted.
        let mut methods: Vec<String> = loaded
            .mandate
            .as_ref()
            .map(|m| m.capabilities.iter().map(|c| c.method_name.clone()).collect())
            .unwrap_or_default();
        // x402_fetch is a policy-level name for "pay a 402 challenge"; on chain
        // it IS a simple_transfer, so an identity whose circuit permits
        // simple_transfer can pay challenges too — without this, minted agents
        // silently lose x402 the moment the method names diverged.
        if methods.iter().any(|m| m == "simple_transfer") {
            methods.push("x402_fetch".into());
        }
        let recipient_count = a.allowed_recipients.as_ref().map(|r| r.len());
        // Same binding as create_wallet: the minted account is the identity this
        // policy governs.
        self.policy.lock().unwrap().set_current_user(loaded.user_id);
        let policy_id = self.policy.lock().unwrap().create_policy(&a.agent_id, limits, a.allowed_recipients, methods);

        let mandate = loaded.mandate.as_ref();
        let mut result = json!({
            "userId": loaded.user_id,
            "psyId": format!("Psy-{:08}", loaded.user_id),
            "policyId": policy_id,
            "allowedRecipientCount": recipient_count,
            "mandate": mandate,
            "enforcement": {
                "circuit": "Which (contract, method) calls are possible, and the exact call count per transaction. Enforced by the chain — violations are unprovable.",
                "policy": "Amount and budget limits. Enforced by this server, NOT by the chain.",
            },
            "limits": agent_account::Mandate::LIMITS_NOTE,
        });
        if let Some(obj) = result.as_object_mut() {
            tracing::info!("agent key backed up at {} (owner-side; not disclosed to the agent)", backup_path.display());
            obj.insert(
                "keyBackupNote".into(),
                json!(format!(
                    "Agent key backed up on the server host for the OWNER (path in the server log; never shared with the agent). Restart with {}=<path> to reload.",
                    keystore::KEY_FILE_ENV
                )),
            );
        }
        ok_json(result)
    }

    #[tool(
        description = "What the loaded agent account is CRYPTOGRAPHICALLY permitted to do, read from its identity \
                       circuit rather than from configuration. Returns the capabilities, the exact calls per \
                       transaction, and the circuit fingerprint — the publicly auditable identity of the mandate."
    )]
    async fn describe_mandate(&self) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        match inner.wallet.current_mandate() {
            Some(m) => ok_json(json!({
                "mandate": m,
                "limits": agent_account::Mandate::LIMITS_NOTE,
            })),
            None => err_json(
                "the loaded wallet is not an agent account — it has no mandate circuit",
                json!({ "hint": "mint one with mint_agent_account; a plain key wallet is unconstrained at the circuit level" }),
            ),
        }
    }

    #[tool(description = "Owner: mint a short-TTL session token for the agent from a policy.")]
    async fn issue_session(&self, Parameters(a): Parameters<IssueSessionArgs>) -> Result<CallToolResult, McpError> {
        if let Err(e) = owner_gate(a.owner_token.as_deref()) {
            return err_json(e, json!({ "gate": "owner" }));
        }
        match self.policy.lock().unwrap().issue_session(&a.policy_id, a.ttl_minutes) {
            Ok((token, exp)) => ok_json(json!({ "token": token, "expiresAt": exp })),
            Err(e) => err_json(e, json!({})),
        }
    }

    #[tool(description = "Owner: pause a policy. Every subsequent spend authorization fails immediately.")]
    async fn pause_policy(&self, Parameters(a): Parameters<PolicyIdArgs>) -> Result<CallToolResult, McpError> {
        if self.policy.lock().unwrap().pause(&a.policy_id) { ok_json(json!({ "paused": a.policy_id })) } else { err_json("policy not found", json!({})) }
    }

    #[tool(description = "Owner: resume a paused policy.")]
    async fn resume_policy(&self, Parameters(a): Parameters<PolicyIdArgs>) -> Result<CallToolResult, McpError> {
        if let Err(e) = owner_gate(a.owner_token.as_deref()) {
            return err_json(e, json!({ "gate": "owner" }));
        }
        if self.policy.lock().unwrap().resume(&a.policy_id) { ok_json(json!({ "resumed": a.policy_id })) } else { err_json("policy not found", json!({})) }
    }

    #[tool(description = "Owner: revoke an agent session token immediately.")]
    async fn revoke_session(&self, Parameters(a): Parameters<SessionArg>) -> Result<CallToolResult, McpError> {
        if self.policy.lock().unwrap().revoke(&a.session) { ok_json(json!({ "revoked": true })) } else { err_json("token not found", json!({})) }
    }

    #[tool(description = "Owner: change an existing policy's spending limits and allow-lists in place. \
                          Every field is optional and OMITTING one leaves it unchanged, so a \
                          \"tighten the daily limit\" edit can never silently delete a cap or widen the \
                          allow-list. Pass null for the 30-day or total cap to remove that limit. Spent \
                          counters and live sessions are kept, so a tightened limit binds immediately \
                          without re-issuing a session. This is what the owner dashboard's policy editor calls. \
                          TIGHTENING is always allowed; WIDENING (raising a cap, removing the 30-day or lifetime \
                          ceiling, approving a new recipient or action, or clearing the allow-list) is an owner \
                          action and requires a server started with PSY_MCP_OWNER_TOKEN plus the matching \
                          owner_token — an agent cannot grant itself more than it was given.")]
    async fn update_policy(&self, Parameters(a): Parameters<UpdatePolicyArgs>) -> Result<CallToolResult, McpError> {
        if let Err(e) = owner_gate(a.owner_token.as_deref()) {
            return err_json(e, json!({ "gate": "owner" }));
        }
        let mut policy = self.policy.lock().unwrap();
        // Tightening is safe for anyone to ask for; GRANTING MORE is the
        // escalation, so it is gated separately and strictly. Checked before
        // anything is written, so a refused widening leaves the policy exactly
        // as it was.
        // Explicitly requested removals. Clearing a cap is TIGHTENING-adjacent
        // (removing a limit could be widening if the policy relied on it, so
        // route through the widening gate with the removed cap named).
        if let Some(removes) = &a.remove_limits {
            for name in removes {
                match name.as_str() {
                    "perMonth" | "per_month" | "per_month_nano" => {
                        if let Err(e) = owner_gate_for_widening(a.owner_token.as_deref(), &format!("clear perMonth (remove the 30-day cap)")) {
                            return err_json(e, json!({ "gate": "owner", "policyUnchanged": true }));
                        }
                    }
                    "totalBudget" | "total_budget" | "total_budget_nano" => {
                        if let Err(e) = owner_gate_for_widening(a.owner_token.as_deref(), &format!("clear totalBudget (remove the lifetime cap)")) {
                            return err_json(e, json!({ "gate": "owner", "policyUnchanged": true }));
                        }
                    }
                    "allowedRecipients" | "allowed_recipients" => {
                        if let Err(e) = owner_gate_for_widening(a.owner_token.as_deref(), &format!("clear the recipient allow-list (pay anyone)")) {
                            return err_json(e, json!({ "gate": "owner", "policyUnchanged": true }));
                        }
                    }
                    other => return err_json(format!("unknown limit to remove: {other} — try perMonth, totalBudget or allowedRecipients"), json!({ "gate": "args" })),
                }
            }
        }
        let methods = a.allowed_methods.clone().unwrap_or_default();
        match policy.update_widens(
            &a.policy_id,
            a.per_transaction_nano,
            a.per_day_nano,
            a.per_month_nano,
            a.total_budget_nano,
            &a.allowed_recipients,
            &methods,
        ) {
            Ok(Some(what)) => {
                if let Err(e) = owner_gate_for_widening(a.owner_token.as_deref(), &what) {
                    return err_json(
                        e,
                        json!({ "gate": "owner", "widens": what, "policyUnchanged": true }),
                    );
                }
            }
            Ok(None) => {}
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "args" })),
        }
        let update_result = policy.update_policy(
            &a.policy_id,
            a.per_transaction_nano,
            a.per_day_nano,
            a.per_month_nano,
            a.total_budget_nano,
            a.allowed_recipients,
            methods,
        );
        if let Ok(()) = &update_result {
            if let Some(removes) = &a.remove_limits {
                let _ = policy.remove_limits(&a.policy_id, removes);
            }
        }
        match update_result {
            Ok(()) => match policy.describe(&a.policy_id) {
                Ok(d) => ok_json(json!({ "updated": a.policy_id, "summary": d.summary, "policy": d })),
                Err(e) => err_json(format!("{e:#}"), json!({})),
            },
            Err(e) => err_json(format!("{e:#}"), json!({ "gate": "args" })),
        }
    }

    #[tool(description = "Agent: remaining spend under the active policy (daily / 30-day / total / per-tx), in Nano.")]
    async fn check_budget(&self, Parameters(a): Parameters<SessionArg>) -> Result<CallToolResult, McpError> {
        match self.policy.lock().unwrap().budget(&a.session) {
            Some(b) => ok_json(json!({
                "remainingDay": b.remaining_day,
                "remainingMonth": b.remaining_month,
                "remainingTotal": b.remaining_total,
                "spentToday": b.spent_today,
                "spentThisMonth": b.spent_this_month,
                "spentTotal": b.spent_total,
                "maxPerTx": b.per_transaction,
                // Reported explicitly: a paused policy has no headroom whatever
                // its caps say, and an agent that only reads the numbers would
                // otherwise plan spends the gate will refuse.
                "paused": b.paused,
                "note": if b.paused {
                    "This policy is PAUSED by the owner — nothing can be spent until they resume it, so every remaining figure is 0."
                } else {
                    "Remaining headroom under the owner's caps. A spend is still checked against the recipient allow-list and the allowed methods."
                },
            })),
            None => err_json("invalid or expired session", json!({})),
        }
    }

    #[tool(
        description = "What this agent is allowed to do, in plain language: the per-payment / daily / 30-day / total \
                       caps, how many approved recipients it may pay, which methods it may call, and how long its \
                       session has left. Read this first when you are handed a wallet — it is the contract you are \
                       operating under, and every limit in it is enforced below you. Read-only: no session needed, \
                       nothing is spent. Omit policy_id when the server holds only one policy."
    )]
    async fn describe_policy(&self, Parameters(a): Parameters<DescribePolicyArgs>) -> Result<CallToolResult, McpError> {
        // A session token is the only id an agent normally holds, so accept it
        // as a way of naming the policy — it names the one it is already bound
        // to and reveals nothing it could not already spend under.
        let policy_id = match a.policy_id.clone() {
            Some(id) => id,
            None => {
                // All three reads under ONE lock; the guard drops before the
                // branch below. A re-lock inside the None arm of a match whose
                // scrutinee still holds the guard deadlocks: `match
                // self.policy.lock().unwrap()...` keeps the MutexGuard alive
                // for the whole match, the Mutex is not reentrant, and
                // describe_policy({}) against several policies hung the server
                // until the client's timeout gave up.
                let (by_session, sole, ids) = {
                    let p = self.policy.lock().unwrap();
                    let by_session = a.session.as_deref().and_then(|s| p.policy_id_for_session(s));
                    (by_session, p.sole_policy_id(), p.policy_ids())
                };
                match by_session {
                    Some(id) => id,
                    None => match sole {
                        Some(id) => id,
                        None => {
                            return err_json(
                                if ids.is_empty() {
                                    "no policy exists yet — call create_wallet (or mint_agent_account) first".to_string()
                                } else {
                                    format!("several policies exist ({}) — pass policy_id to say which", ids.join(", "))
                                },
                                json!({ "gate": "args", "policyIds": ids }),
                            );
                        }
                    },
                }
            }
        };
        match self.policy.lock().unwrap().describe(&policy_id) {
            Ok(d) => ok_json(json!({
                "summary": d.summary,
                "policy": d,
                "auditNote": "Every authorized spend is recorded — call get_spend_log to see what this agent has actually done.",
            })),
            Err(e) => err_json(format!("{e:#}"), json!({ "gate": "args" })),
        }
    }

    #[tool(
        description = "The spends this server has AUTHORIZED, newest first — timestamp, method, recipient and \
                       amount. This is the audit trail of decisions, so it also shows a payment that was approved and \
                       then failed to settle, which the indexer would never show. Denied attempts are not spends and \
                       are not listed. Read-only; no session needed. Kept in memory (100 rows, biased toward real payments so failed attempts cannot crowd them out) and cleared on restart."
    )]
    async fn get_spend_log(&self, Parameters(a): Parameters<SpendLogArgs>) -> Result<CallToolResult, McpError> {
        let limit = a.limit.unwrap_or(20).clamp(1, 100) as usize;
        let entries = self.policy.lock().unwrap().spend_log(limit, a.policy_id.as_deref());
        // Refunded rows are attempts that never moved money — counting them here
        // produced a headline total that contradicted the budget meter on the
        // same screen. They stay in `entries` (the owner should see the attempt)
        // but they are not money spent.
        let total_nano: u64 = entries.iter().filter(|e| !e.refunded).map(|e| e.amount_nano).sum();
        let refunded_count = entries.iter().filter(|e| e.refunded).count();
        let (retained, dropped) = {
            let p = self.policy.lock().unwrap();
            (p.spend_log_len(), p.spend_log_dropped())
        };
        ok_json(json!({
            "count": entries.len(),
            "retained": retained,
            // Non-zero means this is a TRUNCATED view. Without it a short list
            // is indistinguishable from a short history.
            "dropped": dropped,
            "totalNanoInThisView": total_nano,
            "notSentCount": refunded_count,
            "entries": entries,
            "note": if entries.is_empty() && dropped == 0 {
                "No spend has been authorized yet.".to_string()
            } else if dropped > 0 {
                // The old sentence sent the owner to the chain for the evicted
                // rows. The hardest ones to reconstruct are exactly the ones
                // NOT on chain: authorized-but-unsettled, and refunded.
                format!("Newest first. `retained` is what the in-memory ring still holds (capped at 100); {dropped} older row(s) have aged out. Settled payments can be found on chain; authorized-but-unsettled and refunded ones cannot.")
            } else {
                "Newest first. `retained` is how many the in-memory ring still holds (capped at 100).".to_string()
            },
        }))
    }

    #[tool(description = "The BLOCKED attempts, newest first — what the agent tried to spend and the \
                          plain-language reason your rules refused it (over a cap, an unapproved recipient, a \
                          paused policy, a method not allowed). This is the trust half of the audit trail: \
                          pair it with get_spend_log to see everything the agent did AND everything it could not. \
                          Read-only; no session needed. Kept in memory (last 100).")]
    async fn get_blocked(&self, Parameters(a): Parameters<SpendLogArgs>) -> Result<CallToolResult, McpError> {
        let limit = a.limit.unwrap_or(20).clamp(1, 100) as usize;
        let entries = self.policy.lock().unwrap().denied_log(limit, a.policy_id.as_deref());
        let (retained, dropped) = {
            let p = self.policy.lock().unwrap();
            (p.denied_log_len(), p.denied_log_dropped())
        };
        ok_json(json!({
            "count": entries.len(),
            "retained": retained,
            // A denial costs the agent nothing — no funds, no chain call, no
            // budget — so an agent that wants its attempts forgotten can simply
            // make 100 more. This counter is what stops that from being silent.
            "dropped": dropped,
            "entries": entries,
            "note": if entries.is_empty() && dropped == 0 {
                "Nothing has been blocked — every attempt so far was within your rules.".to_string()
            } else if dropped > 0 {
                format!("Newest first. {dropped} older blocked attempt(s) have aged out of this 100-row ring and their details are gone — a burst of refused calls can push earlier ones out.")
            } else {
                "Newest first. Each is an attempt your rules refused; no money moved.".to_string()
            },
        }))
    }

    // ── Live reads ─────────────────────────────────────────────────────


    // ── Contract authoring (psyup) ──────────────────────────────────────────

    #[tool(description = "Scaffold a new Psy-lang contract project from the official boilerplate, under the contracts root (PSY_MCP_CONTRACTS_ROOT, default ~/psy-mcp-contracts). Runs `psyup new` with the installed toolchain. Then use write_source / psyup_build to iterate.")]
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

    #[tool(description = "Write (or overwrite) one source file inside an existing contract project. `path` is project-relative and must stay inside the project — traversal is refused. After writing, call psyup_build to compile.")]
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
            return err_json(format!("project `{}` does not exist — create it with psyup_new first", a.project), json!({}));
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

    #[tool(description = "Compile a contract project with the installed toolchain (`psyup build` → dargo compile). Returns the compiler output; iterate with write_source until it succeeds.")]
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

    #[tool(description = "Deploy a compiled contract project to the chain (`psyup deploy` → psy_user_cli deploy-contract). POLICY-GATED like any spend: needs a valid session, the policy must allow the `deploy_contract` method (owner adds it via update_policy), and the 1 PSY deploy fee is charged against the policy caps. Signs with THIS wallet's private key.")]
    async fn psyup_deploy(&self, Parameters(a): Parameters<PsyupDeployArgs>) -> Result<CallToolResult, McpError> {
        // Policy gate BELOW the model, same shape as transfer. The deploy fee
        // is charged as one 1 PSY spend so the daily/30-day caps bound how much
        // an agent can deploy, and the audit trail shows it like any spend.
        const DEPLOY_FEE_NANO: u64 = 1_000_000_000; // 1 PSY, the standard tx fee
        let auth = match self
            .policy
            .lock()
            .unwrap()
            .authorize(&a.session, SELF_RECIPIENT, DEPLOY_FEE_NANO, "deploy_contract")
        {
            Ok(auth) => auth,
            Err(e) => {
                return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" }))
            }
        };
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
            return err_json(format!("project `{}` does not exist — create it with psyup_new first", a.project), json!({}));
        }
        let cdir = match psyup::find_contract_dir(&dir) {
            Ok(c) => c,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
                return err_json(e, json!({}));
            }
        };
        let inner = self.inner.lock().await;
        let key_hex = match inner.wallet.current_user() {
            Some(u) => u.private_key.to_string(),
            None => {
                drop(inner);
                self.policy.lock().unwrap().refund(&auth, DEPLOY_FEE_NANO);
                return err_json("no wallet loaded — deploy needs a wallet to pay the deploy fee", json!({}));
            }
        };
        drop(inner);
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

    #[tool(description = "Call a deployed contract method on this wallet's behalf — the read/write side of psyup_deploy, which the toolset was missing: an agent could author and deploy a contract but had no way to invoke it. POLICY-GATED like any spend: needs a valid session, the policy must allow the `call_contract` method (owner adds it via update_policy), and the 1 PSY call fee is charged against the policy caps. Submits a REAL proof with this wallet's key and returns the end-user-leaf-hash; a method that fails in-circuit (wrong method name, wrong arity, an assertion) refunds the fee and reports the error. `inputs` is a JSON array of integers — pass `[]` for a zero-argument method like `main`.")]
    async fn call_contract(&self, Parameters(a): Parameters<CallContractArgs>) -> Result<CallToolResult, McpError> {
        const CALL_FEE_NANO: u64 = 1_000_000_000; // 1 PSY, same as a deploy
        let mut inner = self.inner.lock().await;
        // Policy gate below the model, same shape as deploy: a call is a tx on
        // the user's chain identity and is charged against the owner's caps.
        let auth = match self.policy.lock().unwrap().authorize(&a.session, SELF_RECIPIENT, CALL_FEE_NANO, "call_contract") {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        if inner.wallet.current_user().is_none() {
            self.policy.lock().unwrap().refund(&auth, CALL_FEE_NANO);
            return err_json("no wallet loaded — a call needs a wallet to sign and pay the call fee", json!({ "gate": "wallet" }));
        }
        // exec_call already retries once on a stale-state rejection (stale nonce /
        // stale start_user_leaf_hash), so a call after any recent tx survives.
        match inner.wallet.exec_call(a.contract_id, &a.method_name, a.inputs.clone()).await {
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

    #[tool(description = "Psy-lang contract authoring quickstart for the agent: types (Felt/u32, NOT u64), #[contract_method], the psyup_new→write_source→psyup_build→psyup_deploy flow, and the compiler errors you will hit with their fixes. Call this BEFORE writing a contract.")]
    async fn psy_agent_instructions(&self) -> Result<CallToolResult, McpError> {
        ok_json(json!({ "instructions": psy_lang_docs::agent_instructions() }))
    }

    #[tool(description = "Look up one Psy-lang syntax topic. Topics: types, contract/contract_method, variables/let, control (if/for), assert/assert_eq, struct/array, operators, storage. Returns the exact syntax, distilled from the compiler test suite.")]
    async fn psy_get_doc(&self, Parameters(a): Parameters<PsyGetDocArgs>) -> Result<CallToolResult, McpError> {
        match psy_lang_docs::get_doc(&a.topic) {
            Some(doc) => ok_json(json!({ "topic": a.topic, "doc": doc })),
            None => err_json(
                format!("unknown topic `{}` — try: {}", a.topic, psy_lang_docs::known_topics()),
                json!({ "topics": psy_lang_docs::known_topics() }),
            ),
        }
    }

    #[tool(description = "Live chain status: the latest coordinator checkpoint id.")]
    async fn get_chain_status(&self) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        match inner.wallet.latest_checkpoint().await {
            Ok(cp) => ok_json(json!({ "checkpointId": cp })),
            Err(e) => err_json(format!("chain unreachable: {e:#}"), json!({})),
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

    #[tool(description = "This wallet's spendable public balance for a token, read from the chain at the latest checkpoint. Read-only; no session needed. A freshly claimed amount appears here only once its checkpoint settles — poll this before spending money you just received.")]
    async fn get_balance(&self, Parameters(a): Parameters<BalanceArgs>) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        let Some(contract) = contract_for(&a.token) else {
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        match inner.wallet.balance(contract).await {
            Ok(nano) => ok_json(json!({ "status": "ok", "token": a.token, "balance": nano })),
            Err(e) => err_json(format!("{e:#}"), json!({ "gate": "read" })),
        }
    }

    #[tool(description = "Public claimable (Nano) owed to the loaded wallet by a specific sender user id.")]
    async fn get_claimable(&self, Parameters(a): Parameters<ClaimableArgs>) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        match inner.wallet.claim_amount_from(a.sender_user_id).await {
            Ok(amount) => ok_json(json!({ "senderUserId": a.sender_user_id, "claimable": amount })),
            Err(e) => err_json(e, json!({ "failClosed": true })),
        }
    }

    // ── Spend (policy-gated → REAL proof via WalletSession) ────────────

    #[tool(description = "Public transfer by user id, with REAL client-side proving. Policy-gated: the session's caps/allowlist must permit it. Returns the submitted end-user-leaf-hash.")]
    async fn transfer(&self, Parameters(a): Parameters<TransferArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        // 1. Policy gate BELOW the model.
        // Charge the gate in the unit the owner's caps are written in. Without
        // this a USDT amount is a thousandth of its real size to every cap.
        let Some(charge) = nano_equivalent(&a.token, a.amount_nano) else {
            return err_json(
                format!("unknown token {}: refusing to guess its scale for the policy gate", a.token),
                json!({ "gate": "args" }));
        };
        if a.amount_nano == 0 {
            // The contract asserts amount > 0, so a zero transfer would spend a
            // proof (~10-40s) to fail in-circuit. Reject it here instead.
            return err_json("a transfer of 0 is a no-op — pass a positive amount", json!({ "gate": "args" }));
        }
        let auth = match self.policy.lock().unwrap().authorize(&a.session, &a.to_user_id.to_string(), charge, "simple_transfer") {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        // 2. Real proof + submit through WalletSession.
        let Some(contract) = contract_for(&a.token) else {
            self.policy.lock().unwrap().refund(&auth, charge);
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        match inner.wallet.transfer(a.to_user_id, a.amount_nano, contract).await {
            Ok(leaf) => ok_json(json!({ "submitted": true, "endUserLeafHash": leaf, "toUserId": a.to_user_id, "amount": a.amount_nano, "token": a.token })),
            Err(e) => {
                // The spend never settled — give the headroom back, or a flaky
                // chain burns the daily budget with failures.
                self.policy.lock().unwrap().refund(&auth, charge);
                err_json(format!("transfer failed: {e:#}"), json!({ "gate": "execute" }))
            }
        }
    }

    #[tool(description = "Pay SEVERAL recipients at once, fused into ONE proof and one fee (real proving). All-or-nothing: if the policy refuses any single payment, nothing is sent and no budget is used. Each payment is checked against the per-payment cap and the running total against the daily, 30-day and lifetime budgets.")]
    async fn transfer_batch(&self, Parameters(a): Parameters<TransferBatchArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        if a.payments.is_empty() {
            return err_json("a batch needs at least one payment".to_string(), json!({ "gate": "args" }));
        }
        if a.payments.iter().any(|p| p.amount_nano == 0) {
            // Same reasoning as the single transfer: the contract asserts
            // amount > 0, so a zero leg would burn a proof to fail in-circuit.
            return err_json("a batch payment of 0 is a no-op — pass positive amounts".to_string(),
                            json!({ "gate": "args", "sent": false }));
        }
        // 1. Policy gate BELOW the model, as ONE decision. authorize_batch either
        //    charges every leg or charges nothing — see the note on why this
        //    cannot be a loop over authorize().
        let recipients: Vec<String> = a.payments.iter().map(|p| p.to_user_id.to_string()).collect();
        // Same normalization as the single transfer, per leg — otherwise a
        // USDT batch is charged a thousandth of its real total.
        let mut charged: Vec<u64> = Vec::with_capacity(a.payments.len());
        for p in &a.payments {
            match nano_equivalent(&a.token, p.amount_nano) {
                Some(v) => charged.push(v),
                None => return err_json(
                    format!("unknown token {}: refusing to guess its scale for the policy gate", a.token),
                    json!({ "gate": "args", "sent": false })),
            }
        }
        let legs: Vec<(&str, u64)> = recipients
            .iter()
            .zip(charged.iter())
            .map(|(r, c)| (r.as_str(), *c))
            .collect();
        let total_nano: u64 = charged.iter().fold(0u64, |acc, n| acc.saturating_add(*n));
        let auth = match self.policy.lock().unwrap().authorize_batch(&a.session, &legs, "simple_transfer") {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy", "sent": false })),
        };
        let Some(contract) = contract_for(&a.token) else {
            self.policy.lock().unwrap().refund(&auth, total_nano);
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        // 2. Real proof + submit. One recursive proof carries every payment, so
        //    the batch settles together or not at all.
        let payments: Vec<(u64, u64)> = a.payments.iter().map(|p| (p.to_user_id, p.amount_nano)).collect();
        let count = payments.len();
        match inner.wallet.transfer_batch(payments, contract).await {
            Ok(leaf) => ok_json(json!({
                "submitted": true,
                "endUserLeafHash": leaf,
                "paymentCount": count,
                "totalNano": total_nano,
                "token": a.token,
                "note": "One proof, one fee, one transaction.",
            })),
            Err(e) => {
                // Nothing settled — hand the whole batch's headroom back, or a
                // flaky chain burns the daily budget on payments that failed.
                self.policy.lock().unwrap().refund(&auth, total_nano);
                err_json(format!("batch transfer failed: {e:#}"), json!({ "gate": "execute", "sent": false }))
            }
        }
    }

    #[tool(description = "Claim ALL public claimables owed by the given senders, fused into ONE UPS proof / one fee (real proving). Claiming only folds funds already addressed to you into spendable balance. Discover sender ids with get_claimable.")]
    async fn claim_all(&self, Parameters(a): Parameters<ClaimAllArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        // Policy gate — claims move value into the account, so we gate them too
        // (amount 0: claiming does not spend). This keeps a paused policy able to
        // freeze all activity.
        if let Err(e) = self.policy.lock().unwrap().authorize(&a.session, SELF_RECIPIENT, 0, "simple_claim") {
            return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" }));
        }
        let Some(contract) = contract_for(&a.token) else {
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        match inner.wallet.claim_all_public(a.sender_user_ids.clone(), contract).await {
            Ok(leaf) => ok_json(json!({ "submitted": true, "endUserLeafHash": leaf, "claimedFrom": a.sender_user_ids, "token": a.token, "note": "One UPS proof, one fee." })),
            Err(e) => err_json(format!("claim_all failed: {e:#}"), json!({ "gate": "execute" })),
        }
    }

    #[tool(description = "List this wallet's transaction history — payments in and out, claims, deposits and withdrawals — as recorded by the indexer. Read-only: it spends nothing and needs no session.")]
    async fn get_activity(&self, Parameters(a): Parameters<ActivityArgs>) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        let user = match inner.wallet.current_user() {
            Some(u) => u,
            None => return err_json("no wallet loaded — call create_wallet first".to_string(), json!({ "gate": "wallet" })),
        };
        let base = match resolve_agent_url(a.services_url.as_deref(), default_services_url) {
            Ok(u) => u,
            Err(e) => return err_json(e, json!({ "gate": "url" })),
        };
        let limit = a.limit.unwrap_or(20).clamp(1, 200);
        let url = format!(
            "{}/api/v1/get/user/activity?user_id={}&limit={}",
            base.trim_end_matches('/'), user.user_id, limit
        );
        let body: serde_json::Value = match reqwest::Client::new().get(&url).send().await {
            Ok(r) => match r.json().await {
                Ok(v) => v,
                Err(e) => return err_json(format!("indexer returned a non-JSON response: {e}"), json!({ "gate": "indexer" })),
            },
            Err(e) => return err_json(format!("indexer unreachable at {base}: {e}"), json!({ "gate": "indexer" })),
        };
        if body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return err_json(format!("indexer rejected the query: {body}"), json!({ "gate": "indexer" }));
        }
        let data = body.get("data").cloned().unwrap_or(json!({}));
        let items = data.get("items").cloned().unwrap_or(json!([]));
        // The indexer's rows are snake_case; expose them camelCase so every
        // tool in this server speaks one naming scheme. `amount` stays `amount`.
        let items = items
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|row| {
                        let mut o = serde_json::Map::new();
                        for (k, v) in row.as_object().unwrap_or(&serde_json::Map::new()) {
                            let camel = {
                                let mut it = k.chars();
                                match it.next() {
                                    Some(f) => {
                                        let mut out = String::new();
                                        let mut upper = false;
                                        for c in f.to_string().chars().chain(it) {
                                            if c == '_' {
                                                upper = true;
                                            } else if upper {
                                                out.push(c.to_ascii_uppercase());
                                                upper = false;
                                            } else {
                                                out.push(c);
                                            }
                                        }
                                        out
                                    }
                                    None => k.clone(),
                                }
                            };
                            o.insert(camel, v.clone());
                        }
                        serde_json::Value::Object(o)
                    })
                    .collect::<Vec<_>>()
            })
            .map(serde_json::Value::Array)
            .unwrap_or(items);
        let count = items.as_array().map(|a| a.len()).unwrap_or(0);
        ok_json(json!({
            "status": "ok",
            "userId": user.user_id,
            "psyId": format!("Psy-{:08}", user.user_id),
            "count": count,
            "items": items,
            "nextCursor": data.get("next_cursor"),
            "note": if count == 0 {
                "No activity recorded yet. Settled transactions appear once the indexer has ingested their checkpoint."
            } else { "Newest first." },
        }))
    }

    #[tool(description = "Deposit tokens from Ethereum into this wallet's shielded address on Psy. Uses the owner-provisioned L1 key (PSY_MCP_L1_KEY env — the agent never sees it): saves the claim secrets to disk FIRST, then approves if needed and calls Router.deposit. Once the bridge relayer proves it, finish with claim_deposit. Policy-gated at the amount.")]
    async fn deposit(&self, Parameters(a): Parameters<DepositArgs>) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        // Policy caps are denominated in Nano (9 decimals); L1 base units are
        // token-specific (USDT: 6). Charging base units against Nano caps
        // silently authorized ~1000x what the owner set for USDT — normalize
        // BEFORE the gate, and refuse tokens whose scale we do not know rather
        // than guess one.
        let Some(amount_nano_equivalent) = nano_equivalent(&a.token, a.amount_base_units) else {
            return err_json(
                format!("unknown token {}: cannot convert its base units to Nano for the policy gate", a.token),
                json!({ "gate": "args" }));
        };
        let Some(l2_contract) = contract_for(&a.token) else {
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        let auth = match self.policy.lock().unwrap().authorize(&a.session, SELF_RECIPIENT, amount_nano_equivalent, "deposit") {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        // Every failure below this line refunds the gate: authorized-but-
        // unmoved money must not eat the budget (a deposit that fails on L1
        // moved nothing on Psy).
        macro_rules! fail {
            ($m:expr, $x:expr) => {{
                self.policy.lock().unwrap().refund(&auth, amount_nano_equivalent);
                return err_json($m, $x);
            }};
        }
        let l1 = match crate::l1::L1Client::from_env(default_l1_rpc()) {
            Ok(c) => c,
            Err(e) => fail!(format!("{e:#}"), json!({ "gate": "l1-key" })),
        };
        let token_str = match default_l1_token(&a.token) {
            Some(t) => t,
            None => fail!(format!("no L1 address known for {}", a.token), json!({ "gate": "config" })),
        };
        let token: alloy_primitives::Address = match token_str.parse() {
            Ok(t) => t,
            Err(e) => fail!(format!("bad token address {token_str}: {e}"), json!({ "gate": "config" })),
        };
        let router: alloy_primitives::Address = match default_router().parse() {
            Ok(r) => r,
            Err(e) => fail!(format!("bad router address: {e}"), json!({ "gate": "config" })),
        };
        let bridge: alloy_primitives::Address = match default_bridge().parse() {
            Ok(b) => b,
            Err(e) => fail!(format!("bad bridge address: {e}"), json!({ "gate": "config" })),
        };
        let amount = alloy_primitives::U256::from(a.amount_base_units);

        // Fail on funds BEFORE writing anything or prompting anything.
        match l1.erc20_balance(token).await {
            Ok(bal) if bal < amount => fail!(format!("L1 balance {bal} is less than the deposit {amount}"),
                json!({ "gate": "funds", "l1Address": format!("{}", l1.address()) })),
            Err(e) => fail!(format!("could not read the L1 balance: {e:#}"), json!({ "gate": "l1" })),
            _ => {}
        }

        // Fresh secrets, persisted BEFORE any broadcast: a deposit whose secrets
        // are lost is permanently unclaimable, with no error anywhere.
        let identity = match inner.wallet.receive_identity() {
            Ok(i) => i,
            Err(e) => fail!(format!("{e:#}"), json!({ "gate": "wallet" })),
        };
        let expected_index = match l1.call_u64(bridge, "pendingDepositCount()").await {
            Ok(n) => n,
            Err(e) => fail!(format!("could not read the bridge's deposit count: {e:#}"), json!({ "gate": "l1" })),
        };
        let (note_secret, nullifier_secret) = {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            ([rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()],
             [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()])
        };
        let mut note = crate::wallet::DepositNote {
            note_secret, nullifier_secret,
            shield_address_hex: identity.shield_address_hex.clone(),
            l1_token_address: token_str.clone(),
            l2_token_contract_id: l2_contract,
            amount_base_units: a.amount_base_units,
            source_chain_index: a.source_chain_index,
            expected_deposit_index: expected_index,
            l1_tx_hash: None,
            claimed: false,
        };
        let dir = crate::keystore::keystore_dir();
        let backup = match note.persist(&dir) {
            Ok(p) => p,
            Err(e) => fail!(format!("refusing to deposit: the claim secrets could not be persisted ({e:#})"), json!({ "gate": "persist" })),
        };

        // The ERC20Gateway is what pulls the funds (the Router only forwards),
        // so the allowance must be granted to the GATEWAY — approving the
        // Router leaves allowance(gateway)=0 and the deposit reverts with
        // ERC20InsufficientAllowance. Mirrors the web wallet's
        // `spender = erc20GatewayAddress || routerAddress`.
        let spender: alloy_primitives::Address = match default_erc20_gateway().parse() {
            Ok(g) => g,
            Err(e) => fail!(format!("bad gateway address: {e}"), json!({ "gate": "config" })),
        };
        match l1.erc20_allowance(token, spender).await {
            Ok(cur) if cur < amount => {
                if let Err(e) = l1.send(token, crate::l1::L1Client::encode_approve(spender, amount),
                                        alloy_primitives::U256::ZERO).await {
                    tracing::info!("deposit claim secrets remain at {} (owner-side)", backup.display());
                    fail!(format!("approve failed: {e:#}"), json!({ "gate": "l1" }));
                }
            }
            Err(e) => fail!(format!("allowance read failed: {e:#}"), json!({ "gate": "l1" })),
            _ => {}
        }

        let (shield32, commitment32) = match note.l1_words() {
            Ok(w) => w,
            Err(e) => fail!(format!("{e:#}"), json!({ "gate": "encode" })),
        };
        match l1.send(router,
                      crate::l1::L1Client::encode_deposit(token, amount, shield32, commitment32),
                      alloy_primitives::U256::ZERO).await {
            Ok(tx) => {
                note.l1_tx_hash = Some(tx.clone());
                let _ = note.persist(&dir);
                ok_json(json!({
                    "status": "ok", "submitted": true, "l1TxHash": tx,
                    "amountBaseUnits": a.amount_base_units, "token": a.token,
                    "expectedDepositIndex": expected_index,
                    "next": "The bridge relayer proves it onto Psy (minutes). Then call claim_deposit. (Claim secrets are persisted server-side; path in the server log.)",
                }))
            }
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, amount_nano_equivalent);
                tracing::info!("deposit claim secrets remain at {} (owner-side)", backup.display());
                err_json(
                    format!("deposit failed on L1: {e:#}"),
                    json!({ "gate": "l1" }))
            }
        }
    }

    #[tool(description = "Claim a deposit that the bridge relayer has proved onto Psy, folding it into this wallet's balance. Reads the claim secrets saved by `deposit`, fetches the merkle proof from psy-services, verifies it locally, proves inclusion and claims. Amount-0 gated: claiming only folds in funds already addressed to this wallet.")]
    async fn claim_deposit(&self, Parameters(a): Parameters<ClaimDepositArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        if let Err(e) = self.policy.lock().unwrap().authorize(&a.session, SELF_RECIPIENT, 0, "claim_deposit") {
            return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" }));
        }
        let loaded = match load_claimable_deposit(a.backup_path.clone(), a.deposit_index, a.services_url.as_deref()).await {
            Ok(m) => m,
            Err((reason, extra)) => return err_json(reason, extra),
        };
        let DepositMaterial::Ready { note, proof } = loaded else {
            return ok_json(json!({ "status": "ok", "alreadyClaimed": true,
                                   "note": "This deposit was already claimed." }));
        };

        match inner.wallet.claim_shield_deposit(&note, &proof).await {
            Ok(leaf) => {
                let mut done = note.clone();
                done.claimed = true;
                let _ = done.persist(&crate::keystore::keystore_dir());
                ok_json(json!({
                    "status": "ok", "submitted": true, "claimedBaseUnits": note.amount_base_units,
                    "token": note.l2_token_contract_id, "txHash": leaf,
                    "depositIndex": note.expected_deposit_index,
                }))
            }
            Err(e) => err_json(format!("deposit claim failed: {e:#}"), json!({ "gate": "execute" })),
        }
    }

    #[tool(description = "Claim private notes sent to this wallet's shielded address. With no arguments it claims everything psy-services is holding for this wallet (the service subscribes to the relay for us). Pass `note` to claim one specific delivered note instead.")]
    async fn private_claim(&self, Parameters(a): Parameters<PrivateClaimArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        // Amount 0: claiming folds in funds already addressed to us, it does not
        // spend — same convention claim_all uses.
        if let Err(e) = self.policy.lock().unwrap().authorize(&a.session, SELF_RECIPIENT, 0, "private_claim") {
            return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" }));
        }
        let Some(contract) = contract_for(&a.token) else {
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };

        // Explicit note: claim exactly that one.
        if let Some(raw) = a.note.as_deref() {
            let note = match crate::wallet::IncomingPrivateNote::parse(raw) {
                Ok(n) => n,
                Err(e) => return err_json(format!("could not read the note: {e:#}"), json!({ "gate": "parse" })),
            };
            return match inner.wallet.claim_private_note(&note, contract).await {
                Ok(leaf) => ok_json(json!({
                    "status": "ok", "submitted": true, "claimed": 1,
                    "claimedNano": note.amount, "token": a.token, "txHash": leaf,
                })),
                Err(e) => err_json(format!("private claim failed: {e:#}"), json!({ "gate": "execute" })),
            };
        }

        // Otherwise drain whatever the service is holding for us.
        let identity = match inner.wallet.receive_identity() {
            Ok(i) => i,
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "wallet" })),
        };
        let services = match resolve_agent_url(a.services_url.as_deref(), default_services_url) {
            Ok(u) => u,
            Err(e) => return err_json(e, json!({ "gate": "url" })),
        };
        let notes = match crate::nostr_delivery::fetch_notes(&services, &identity.npub, true).await {
            Ok(n) => n,
            Err(e) => return err_json(format!("could not fetch notes: {e:#}"), json!({ "gate": "fetch" })),
        };
        if notes.is_empty() {
            return ok_json(json!({
                "status": "ok", "claimed": 0, "npub": identity.npub,
                "note": "Nothing waiting. Notes appear here once a sender delivers one and the service has ingested it.",
            }));
        }

        let secret = match nostr::SecretKey::parse(&identity.nsec) {
            Ok(k) => k,
            Err(e) => return err_json(format!("bad derived Nostr key: {e}"), json!({ "gate": "wallet" })),
        };
        // Decrypt everything first, then reassemble: large notes arrive as
        // several chunk events that only make sense together. Claim each
        // resulting note independently — one undecryptable or already-spent
        // note must not strand the rest.
        let (mut claimed, mut total, mut failures) = (0u64, 0u64, Vec::new());
        let mut decrypted = Vec::new();
        for item in &notes {
            match crate::nostr_delivery::open_note(&secret, &item.wrapped_note) {
                Ok(p) => decrypted.push(p),
                Err(e) => failures.push(json!({ "eventId": item.event_id, "error": format!("{e:#}") })),
            }
        }
        let payloads = crate::nostr_delivery::reassemble_payloads(decrypted);
        for payload in &payloads {
            let note = match crate::wallet::IncomingPrivateNote::parse(payload) {
                Ok(n) => n,
                Err(e) => { failures.push(json!({ "error": format!("{e:#}") })); continue }
            };
            match inner.wallet.claim_private_note(&note, contract).await {
                Ok(_) => { claimed += 1; total += note.amount }
                Err(e) => failures.push(json!({ "nullifier": note.nullifier, "error": format!("{e:#}") })),
            }
        }
        ok_json(json!({
            "status": "ok", "claimed": claimed, "claimedNano": total,
            "found": notes.len(), "failed": failures, "token": a.token, "npub": identity.npub,
        }))
    }

    #[tool(description = "Fuse public claims, private-note claims and shield-deposit claims into ONE UPS proof / one fee. The chain primitive has always accepted mixed items; this is the tool that builds that mixed batch. Pass any combination of public_claims, deposit_indices / backup_paths, private_notes, or drain_private. Each present category is policy-gated as simple_claim / claim_deposit / private_claim (amount 0 — claiming folds in funds already addressed to this wallet).")]
    async fn claim_batch(&self, Parameters(a): Parameters<ClaimBatchArgs>) -> Result<CallToolResult, McpError> {
        let wants_public = !a.public_claims.is_empty();
        let wants_deposit = !a.deposit_indices.is_empty() || !a.backup_paths.is_empty();
        let wants_private = !a.private_notes.is_empty() || a.drain_private;
        let wants_transfer = !a.transfers.is_empty();
        let wants_withdraw = !a.withdraws.is_empty();
        if !wants_public && !wants_deposit && !wants_private && !wants_transfer && !wants_withdraw {
            return err_json(
                "nothing to claim — pass public_claims, transfers, withdraws, deposit_indices/backup_paths, private_notes, and/or drain_private=true".to_string(),
                json!({ "gate": "args" }),
            );
        }
        // Gate each constituent method the batch will actually perform, so a
        // policy that allows simple_claim but not claim_deposit cannot sneak a
        // deposit into the same UPS. Amount 0: claiming does not spend.
        if wants_public {
            if let Err(e) = self.policy.lock().unwrap().authorize(&a.session, SELF_RECIPIENT, 0, "simple_claim") {
                return err_json(format!("policy denied public claims: {e:#}"), json!({ "gate": "policy", "method": "simple_claim" }));
            }
        }
        if wants_deposit {
            if let Err(e) = self.policy.lock().unwrap().authorize(&a.session, SELF_RECIPIENT, 0, "claim_deposit") {
                return err_json(format!("policy denied deposit claims: {e:#}"), json!({ "gate": "policy", "method": "claim_deposit" }));
            }
        }
        if wants_private {
            if let Err(e) = self.policy.lock().unwrap().authorize(&a.session, SELF_RECIPIENT, 0, "private_claim") {
                return err_json(format!("policy denied private claims: {e:#}"), json!({ "gate": "policy", "method": "private_claim" }));
            }
        }
        // Transfer and withdraw legs SPEND, so they authorize at their real
        // amounts (in the unit the owner's caps are written in) exactly like
        // the standalone tools. The batch is all-or-nothing: any refused leg
        // refunds every leg authorized before it and nothing is sent.
        let mut spent_auths: Vec<(policy::Authorization, u64)> = Vec::new(); // (auth, charge) for refund
        let refund_all = |auths: &mut Vec<(policy::Authorization, u64)>| {
            for (auth, chg) in auths.drain(..) {
                self.policy.lock().unwrap().refund(&auth, chg);
            }
        };
        for spec in &a.transfers {
            let Some(charge) = nano_equivalent(&spec.token, spec.amount_nano) else {
                refund_all(&mut spent_auths);
                return err_json(format!("unknown token {}: refusing to guess its scale for the policy gate", spec.token), json!({ "gate": "args" }));
            };
            match self.policy.lock().unwrap().authorize(&a.session, &spec.to_user_id.to_string(), charge, "simple_transfer") {
                Ok(auth) => spent_auths.push((auth, charge)),
                Err(e) => {
                    refund_all(&mut spent_auths);
                    return err_json(format!("policy denied a transfer leg: {e:#}"), json!({ "gate": "policy", "method": "simple_transfer" }));
                }
            }
        }
        const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";
        for spec in &a.withdraws {
            if spec.l1_recipient.trim().eq_ignore_ascii_case(ZERO_ADDR) {
                refund_all(&mut spent_auths);
                return err_json("a withdraw leg has the zero L1 recipient — the funds would burn into an address nobody can recover. Nothing was submitted.".to_string(), json!({ "gate": "args" }));
            }
            let Some(charge) = nano_equivalent(&spec.token, spec.amount_nano) else {
                refund_all(&mut spent_auths);
                return err_json(format!("unknown token {}: refusing to guess its scale for the policy gate", spec.token), json!({ "gate": "args" }));
            };
            match self.policy.lock().unwrap().authorize(&a.session, &spec.l1_recipient, charge, "withdraw") {
                Ok(auth) => spent_auths.push((auth, charge)),
                Err(e) => {
                    refund_all(&mut spent_auths);
                    return err_json(format!("policy denied a withdraw leg: {e:#}"), json!({ "gate": "policy", "method": "withdraw" }));
                }
            }
        }

        let mut public_items: Vec<(u64, u64)> = Vec::new();
        for spec in &a.public_claims {
            let Some(contract) = contract_for(&spec.token) else {
                return err_json(format!("unknown token {}", spec.token), json!({ "gate": "args" }));
            };
            public_items.push((spec.sender_user_id, contract));
        }
        let mut transfer_items: Vec<(u64, u64, u64)> = Vec::new();
        for spec in &a.transfers {
            let Some(contract) = contract_for(&spec.token) else {
                refund_all(&mut spent_auths);
                return err_json(format!("unknown token {}", spec.token), json!({ "gate": "args" }));
            };
            transfer_items.push((spec.to_user_id, spec.amount_nano, contract));
        }
        let mut withdraw_legs: Vec<crate::wallet::WithdrawLeg> = Vec::new();
        for spec in &a.withdraws {
            let Some(contract) = contract_for(&spec.token) else {
                refund_all(&mut spent_auths);
                return err_json(format!("unknown token {}", spec.token), json!({ "gate": "args" }));
            };
            let token_addr = match spec.l1_token_address.clone() {
                Some(t) => t,
                None => match default_l1_token(&spec.token) {
                    Some(t) => t,
                    None => {
                        refund_all(&mut spent_auths);
                        return err_json(format!("no default L1 token address known for {} — pass l1_token_address", spec.token), json!({ "gate": "config" }));
                    }
                },
            };
            if token_addr.eq_ignore_ascii_case(ZERO_ADDR) {
                refund_all(&mut spent_auths);
                return err_json("a withdraw leg has the zero L1 token address — the bridge routes it into the WETH branch, which reverts and stalls the relayer. Nothing was submitted.".to_string(), json!({ "gate": "args" }));
            }
            withdraw_legs.push(crate::wallet::WithdrawLeg {
                dest_chain_index: spec.dest_chain_index,
                l1_token_address: token_addr,
                amount_nano: spec.amount_nano,
                l1_recipient: spec.l1_recipient.trim().to_string(),
                nonce: spec.nonce.unwrap_or_else(|| {
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
                }),
                contract_id: contract,
            });
        }

        let mut deposit_notes: Vec<crate::wallet::DepositNote> = Vec::new();
        let mut deposit_proofs: Vec<serde_json::Value> = Vec::new();
        let mut skipped_claimed: Vec<u64> = Vec::new();
        let mut deposit_lookups: Vec<(Option<String>, Option<u64>)> = a
            .backup_paths
            .iter()
            .map(|p| (Some(p.clone()), None))
            .collect();
        deposit_lookups.extend(a.deposit_indices.iter().copied().map(|i| (None, Some(i))));
        for (backup_path, deposit_index) in deposit_lookups {
            match load_claimable_deposit(backup_path, deposit_index, a.services_url.as_deref()).await {
                Ok(DepositMaterial::Ready { note, proof }) => {
                    deposit_notes.push(note);
                    deposit_proofs.push(proof);
                }
                Ok(DepositMaterial::AlreadyClaimed { note }) => skipped_claimed.push(note.expected_deposit_index),
                Err((reason, extra)) => return err_json(reason, extra),
            }
        }

        let mut private_parsed: Vec<(crate::wallet::IncomingPrivateNote, u64)> = Vec::new();
        let mut private_failures: Vec<serde_json::Value> = Vec::new();
        for spec in &a.private_notes {
            let Some(contract) = contract_for(&spec.token) else {
                return err_json(format!("unknown token {}", spec.token), json!({ "gate": "args" }));
            };
            match crate::wallet::IncomingPrivateNote::parse(&spec.note) {
                Ok(n) => private_parsed.push((n, contract)),
                Err(e) => private_failures.push(json!({ "error": format!("{e:#}") })),
            }
        }

        let mut inner = self.inner.lock().await;
        if a.drain_private {
            let Some(contract) = contract_for(&a.private_token) else {
                return err_json(format!("unknown token {}", a.private_token), json!({ "gate": "args" }));
            };
            let identity = match inner.wallet.receive_identity() {
                Ok(i) => i,
                Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "wallet" })),
            };
            let services = match resolve_agent_url(a.services_url.as_deref(), default_services_url) {
                Ok(u) => u,
                Err(e) => return err_json(e, json!({ "gate": "url" })),
            };
            let notes = match crate::nostr_delivery::fetch_notes(&services, &identity.npub, true).await {
                Ok(n) => n,
                Err(e) => return err_json(format!("could not fetch notes: {e:#}"), json!({ "gate": "fetch" })),
            };
            let secret = match nostr::SecretKey::parse(&identity.nsec) {
                Ok(k) => k,
                Err(e) => return err_json(format!("bad derived Nostr key: {e}"), json!({ "gate": "wallet" })),
            };
            let mut decrypted = Vec::new();
            for item in &notes {
                match crate::nostr_delivery::open_note(&secret, &item.wrapped_note) {
                    Ok(p) => decrypted.push(p),
                    Err(e) => private_failures.push(json!({ "eventId": item.event_id, "error": format!("{e:#}") })),
                }
            }
            for payload in crate::nostr_delivery::reassemble_payloads(decrypted) {
                match crate::wallet::IncomingPrivateNote::parse(&payload) {
                    Ok(n) => {
                        if private_parsed.iter().any(|(e, _)| e.nullifier == n.nullifier) {
                            continue;
                        }
                        private_parsed.push((n, contract));
                    }
                    Err(e) => private_failures.push(json!({ "error": format!("{e:#}") })),
                }
            }
        }

        let deposits: Vec<(&crate::wallet::DepositNote, &serde_json::Value)> = deposit_notes
            .iter()
            .zip(deposit_proofs.iter())
            .map(|(n, p)| (n, p))
            .collect();
        // Pre-check every private note's owner BEFORE building the batch: a
        // permanently-unclaimable note (e.g. one sent to a reversed/mangled
        // shield by an old buggy sender) would otherwise fail the WHOLE
        // all-or-nothing proof at prove time — poisoning every future drain.
        // Skip the dead ones into `failed` and claim the rest.
        let user = inner.wallet.require_user().ok();
        let identity_rcv = inner.wallet.receive_identity().ok();
        let mut privates: Vec<(&crate::wallet::IncomingPrivateNote, u64)> = Vec::new();
        for (n, c) in private_parsed.iter() {
            let owner_ok = match (&user, &identity_rcv) {
                (Some(u), Some(id)) => {
                    let expected = crate::wallet::derive_shield_address_pub(u.user_id, id.random0, id.random1);
                    crate::wallet::qhash_to_u64x4_pub(expected) == n.owner
                }
                _ => true, // cannot check — let the proof decide
            };
            if owner_ok {
                privates.push((n, *c));
            } else {
                private_failures.push(json!({
                    "nullifier": n.nullifier,
                    "error": "skipped: this note is addressed to a different shielded address — it is not claimable by this wallet",
                }));
            }
        }

        if public_items.is_empty() && transfer_items.is_empty() && withdraw_legs.is_empty()
            && deposits.is_empty() && privates.is_empty() {
            refund_all(&mut spent_auths);
            return ok_json(json!({
                "submitted": false,
                "alreadyClaimed": skipped_claimed,
                "failed": private_failures,
                "note": "Nothing left to fold in. Deposits were already claimed and/or private notes failed to parse.",
            }));
        }

        match inner.wallet.claim_batch_mixed(public_items.clone(), transfer_items.clone(), withdraw_legs.clone(), deposits, privates).await {
            Ok(leaf) => {
                let dir = crate::keystore::keystore_dir();
                let mut claimed_deposits = Vec::new();
                for note in &deposit_notes {
                    let mut done = note.clone();
                    done.claimed = true;
                    let _ = done.persist(&dir);
                    claimed_deposits.push(note.expected_deposit_index);
                }
                ok_json(json!({
                    "submitted": true,
                    "endUserLeafHash": leaf,
                    "publicClaimedFrom": public_items.iter().map(|(s, _)| s).copied().collect::<Vec<_>>(),
                    "transfersSent": transfer_items.iter().map(|(to, amt, _)| json!({"toUserId": to, "amount": amt})).collect::<Vec<_>>(),
                    "withdrawsBurned": withdraw_legs.iter().map(|w| json!({"l1Recipient": w.l1_recipient, "amount": w.amount_nano})).collect::<Vec<_>>(),
                    "depositsClaimed": claimed_deposits,
                    "alreadyClaimed": skipped_claimed,
                    "privateClaimed": private_parsed.len(),
                    "failed": private_failures,
                    "note": "One UPS proof, one fee.",
                }))
            }
            Err(e) => {
                // Nothing settled — the spends in this batch must give the
                // headroom back, or a flaky chain burns the budget with failures.
                refund_all(&mut spent_auths);
                err_json(format!("claim_batch failed: {e:#}"), json!({ "gate": "execute" }))
            }
        }
    }

    #[tool(description = "Withdraw to an Ethereum address: burns the amount on Psy and the bridge relayer settles the L1 leg, so the agent needs no Ethereum gas. Policy-gated at the amount like any other spend.")]
    async fn withdraw(&self, Parameters(a): Parameters<WithdrawArgs>) -> Result<CallToolResult, McpError> {
        // ZERO RECIPIENT = burned money. The L1 leg is settled by the relayer
        // to `l1_recipient` as-is; 0x000...0 receives the tokens and nobody can
        // ever recover them. Events 415/436 burned on a zero TOKEN address; the
        // recipient side has the same cost and the same shape. Refuse before
        // anything is submitted. (The token-address check lives at the builder
        // in the Mode-A wallet; here it guards the recipient the wallet-side
        // check does not cover.)
        const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";
        let recipient = a.l1_recipient.trim();
        if recipient.eq_ignore_ascii_case(ZERO_ADDR) {
            return err_json(
                "the L1 recipient is the zero address — the withdrawal would burn the funds into an address nobody can recover. Nothing was submitted.",
                json!({ "gate": "args" }),
            );
        }
        let mut inner = self.inner.lock().await;
        let Some(charge) = nano_equivalent(&a.token, a.amount_nano) else {
            return err_json(
                format!("unknown token {}: refusing to guess its scale for the policy gate", a.token),
                json!({ "gate": "args" }));
        };
        let auth = match self.policy.lock().unwrap().authorize(&a.session, &a.l1_recipient, charge, "withdraw") {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        let Some(contract) = contract_for(&a.token) else {
            self.policy.lock().unwrap().refund(&auth, charge);
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        let token_addr = match a.l1_token_address.clone() {
            Some(t) => t,
            None => match default_l1_token(&a.token) {
                Some(t) => t,
                None => {
                    self.policy.lock().unwrap().refund(&auth, charge);
                    return err_json(
                        format!("no default L1 token address known for {} — pass l1_token_address", a.token),
                        json!({ "gate": "config" }));
                }
            },
        };
        // ZERO TOKEN = events 415/436 replayed. The bridge routes
        // `token == address(0)` into the WETH branch, which reverts, and
        // claim_withdrawals has no allowFailure — one such row stalls the
        // relayer and blocks every correct withdrawal behind it. Mode-A fixed
        // this at the builder; the MCP tool must refuse it too.
        if token_addr.eq_ignore_ascii_case(ZERO_ADDR) {
            self.policy.lock().unwrap().refund(&auth, charge);
            return err_json(
                "the L1 token address is the zero address — the bridge routes it into the WETH branch, which reverts and stalls the relayer (events 415/436). Nothing was submitted.",
                json!({ "gate": "args" }),
            );
        }
        // A withdrawal is irreversible once burned, so the nonce must be unique
        // per withdrawal; derive one from the clock unless the caller pins it.
        let nonce = a.nonce.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
        match inner
            .wallet
            .withdraw(a.dest_chain_index, &token_addr, a.amount_nano, &a.l1_recipient, nonce, contract)
            .await
        {
            Ok(leaf) => ok_json(json!({
                "status": "ok", "submitted": true, "amount": a.amount_nano, "token": a.token,
                "l1Recipient": a.l1_recipient, "l1TokenAddress": token_addr, "nonce": nonce,
                "txHash": leaf,
                "note": "Burned on Psy. The bridge relayer settles the Ethereum leg; watch the L1 recipient.",
            })),
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, charge);
                err_json(format!("withdraw failed: {e:#}"), json!({ "gate": "execute" }))
            }
        }
    }

    #[tool(description = "Show how to pay this agent PRIVATELY: its shielded address (which owns the note) and its Nostr npub (where the note is delivered). A payer needs BOTH — a note sent without delivery is unclaimable. The Nostr secret never leaves the server.")]
    async fn get_receive_address(&self) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        match inner.wallet.receive_identity() {
            Ok(id) => ok_json(json!({
                "status": "ok",
                "shieldedAddress": id.shield_address_hex,
                "npub": id.npub,
                "note": "Give BOTH to the payer: the shielded address owns the note, the npub receives it.",
            })),
            Err(e) => err_json(format!("{e:#}"), json!({ "gate": "wallet" })),
        }
    }

    #[tool(description = "Fetch a paywalled URL, paying for it if asked. Requests the resource; on HTTP 402 it reads the challenge, pays the demanded amount on Psy (policy-gated like any other spend), and retries with the X-PAYMENT proof. Set dry_run=true to see what would be paid without paying. This is the whole x402 loop in one call.")]
    async fn x402_fetch(&self, Parameters(a): Parameters<X402FetchArgs>) -> Result<CallToolResult, McpError> {
        // Gate the SESSION before the network, at amount 0 — the same shape the
        // claim tools use so a paused policy freezes all activity.
        //
        // The session used to be validated only at the payment step, far below.
        // Everything above it therefore ran for a REVOKED or EXPIRED session and
        // for a PAUSED policy: the URL was fetched, a non-402 response body was
        // returned straight into model context, and the whole dry_run branch
        // answered normally. So Pause and Revoke — the owner's two stop
        // controls — did not stop the agent using the wallet as a fetcher, and
        // the SSRF guard only bounds WHICH host, not whether the agent is still
        // allowed to act at all.
        //
        // Gating here also means a dry_run needs a live session, which is
        // correct: it is an agent capability, not a public endpoint.
        if let Err(e) = self.policy.lock().unwrap().check_can_act(&a.session, "x402_fetch") {
            return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy", "paid": false }));
        }
        if let Err(e) = guard_outbound_url(&a.url) {
            return err_json(e, json!({ "gate": "url" }));
        }
        let mut inner = self.inner.lock().await;
        let client = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build() {
            Ok(c) => c,
            Err(e) => return err_json(format!("http client: {e}"), json!({ "gate": "fetch" })),
        };

        let first = match client.get(&a.url).send().await {
            Ok(r) => r,
            Err(e) => return err_json(format!("could not reach {}: {e}", a.url), json!({ "gate": "fetch" })),
        };
        if first.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            let status = first.status().as_u16();
            let body = first.text().await.unwrap_or_default();
            return ok_json(json!({
                "status": "ok", "paid": false, "httpStatus": status,
                "body": truncate(&body), "note": "No payment was requested.",
            }));
        }

        let challenge_raw = first.text().await.unwrap_or_default();
        let challenge: crate::x402::PaymentRequired = match serde_json::from_str(&challenge_raw) {
            Ok(c) => c,
            Err(e) => return err_json(
                format!("the server asked for payment but its 402 body could not be read: {e}"),
                json!({ "gate": "challenge", "body": truncate(&challenge_raw) })),
        };
        let network = a.network.clone().unwrap_or_else(default_x402_network);
        let req = match crate::x402::select_requirement(&challenge.accepts, &network) {
            Ok(r) => r,
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "challenge" })),
        };
        let (amount, recipient) = match (req.amount(), req.recipient_user_id()) {
            (Ok(a2), Ok(r2)) => (a2, r2),
            (Err(e), _) | (_, Err(e)) => return err_json(format!("unusable 402 challenge: {e:#}"), json!({ "gate": "challenge" })),
        };
        let token = req.token_symbol();
        let Some(contract) = contract_for(&token) else {
            return err_json(format!("the 402 challenge names an unknown asset {token} — refusing to guess its scale"), json!({ "gate": "challenge" }));
        };

        // Never pay more than the caller sanctioned, even if policy would allow
        // it: an agent that follows links can be led to an expensive resource.
        if let Some(cap) = a.max_amount_nano {
            if amount > cap {
                return err_json(
                    format!("the resource costs {amount} but max_amount_nano was {cap} — not paying"),
                    json!({ "gate": "budget", "required": amount, "cap": cap }));
            }
        }
        if a.dry_run {
            return ok_json(json!({
                "status": "ok", "paid": false, "dryRun": true,
                "wouldPayNano": amount, "toUserId": recipient, "token": token,
                "resource": req.resource, "description": req.description,
            }));
        }

        // The asset here is named by the REMOTE SERVER's 402 body, so without
        // normalizing, the counterparty picks the unit the owner's caps are
        // enforced in: a challenge saying asset "USDT" would get a thousand
        // times the owner's per-payment limit. contract_for already refused
        // unknown assets for the same reason; this refuses unknown SCALES.
        let Some(charge) = nano_equivalent(&token, amount) else {
            return err_json(
                format!("the 402 challenge names asset {token}, whose scale is unknown — refusing to charge it against caps written in Nano"),
                json!({ "gate": "challenge" }));
        };
        // Same gate as a direct transfer — this is the point of the wallet.
        // An x402 payee has two names an owner might have allowlisted: the user
        // id its challenge demands payment to, and the host that demanded it.
        // Both come from THIS response, so either one identifies this seller.
        let auth = match self.policy.lock().unwrap().authorize_aliases(
            &a.session,
            &[&recipient.to_string(), &a.url],
            charge,
            "x402_fetch",
        ) {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"),
                            json!({ "gate": "policy", "required": amount, "toUserId": recipient })),
        };
        let tx_hash = match inner.wallet.transfer(recipient, amount, contract).await {
            Ok(h) => h,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, charge);
                return err_json(format!("payment failed: {e:#}"), json!({ "gate": "execute" }));
            }
        };
        let payer = inner.wallet.current_user().map(|u| u.user_id).unwrap_or(0);
        let payload = crate::x402::PaymentPayload::new(&network, crate::x402::PsyPaymentProof {
            tx_hash: tx_hash.clone(), payer_user_id: payer, recipient_user_id: recipient,
            amount_nano: amount, contract_id: contract, resource: req.resource.clone(),
        });
        let header = match payload.to_header() {
            Ok(h) => h,
            Err(e) => return err_json(
                format!("paid {amount} (tx {tx_hash}) but could not build the X-PAYMENT header: {e:#}"),
                json!({ "gate": "header", "paid": true, "txHash": tx_hash })),
        };

        // Paid but not yet served: report the receipt either way so the caller
        // can retry by hand rather than pay twice.
        let retry = client.get(&a.url).header("X-PAYMENT", &header).send().await;
        match retry {
            Ok(r) => {
                let status = r.status().as_u16();
                let settled = r.headers().get("x-payment-response")
                    .and_then(|v| v.to_str().ok()).map(String::from);
                let body = r.text().await.unwrap_or_default();
                ok_json(json!({
                    "status": "ok", "paid": true, "httpStatus": status,
                    "amount": amount, "toUserId": recipient, "token": token,
                    "txHash": tx_hash, "paymentResponse": settled,
                    "body": truncate(&body),
                }))
            }
            Err(e) => err_json(
                format!("paid {amount} (tx {tx_hash}) but the retry failed: {e}. Retry with the X-PAYMENT header below — do not pay again."),
                json!({ "gate": "retry", "paid": true, "txHash": tx_hash, "xPayment": header })),
        }
    }

    #[tool(description = "Verify an X-PAYMENT header someone sent you, for an agent that SELLS access. Checks the claimed payment against the chain via psy-services — that it exists, went to you, and covers the price — so a resource server can settle without running a prover.")]
    async fn x402_verify(&self, Parameters(a): Parameters<X402VerifyArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        let payload = match crate::x402::PaymentPayload::from_header(&a.x_payment) {
            Ok(p) => p,
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "decode", "valid": false })),
        };
        let proof = &payload.payload;

        // Fail CLOSED on the recipient check: with no wallet loaded there is
        // no "you" for the payment to have been made to, and skipping the
        // check would validate any payment between any two strangers.
        let me = match inner.wallet.current_user().map(|u| u.user_id) {
            Some(me) => me,
            None => return err_json(
                "no wallet is loaded, so there is no recipient to verify against — load the selling wallet first",
                json!({ "gate": "recipient", "valid": false })),
        };
        if proof.recipient_user_id != me {
            return err_json(
                format!("this payment was made to Psy-{:08}, not to this wallet (Psy-{:08})",
                        proof.recipient_user_id, me),
                json!({ "gate": "recipient", "valid": false }));
        }
        if let Some(price) = a.expected_amount_nano {
            if proof.amount_nano < price {
                return err_json(
                    format!("paid {} but the resource costs {price}", proof.amount_nano),
                    json!({ "gate": "amount", "valid": false, "paid": proof.amount_nano, "required": price }));
            }
        }

        // The claim is only worth what the chain says: look the payer's activity
        // up and find this transaction. A payment settles seconds before the
        // indexer ingests it, so a fresh receipt is not proof of fraud — poll
        // briefly (bounded) before refusing, or every honest just-paid caller
        // gets bounced back into paying twice.
        let base = match resolve_agent_url(a.services_url.as_deref(), default_services_url) {
            Ok(u) => u,
            Err(e) => return err_json(e, json!({ "gate": "url" })),
        };
        let url = format!("{}/api/v1/get/user/activity?user_id={}&limit=100",
                          base.trim_end_matches('/'), proof.payer_user_id);
        let wait_secs = a.settlement_wait_seconds.unwrap_or(90).min(600);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
        let matched = loop {
            let body: serde_json::Value = match reqwest::Client::new().get(&url).send().await {
                Ok(r) => match r.json().await { Ok(v) => v, Err(e) =>
                    return err_json(format!("indexer returned a non-JSON response: {e}"), json!({ "gate": "indexer", "valid": false })) },
                Err(e) => return err_json(format!("indexer unreachable: {e}"), json!({ "gate": "indexer", "valid": false })),
            };
            let items = body.get("data").and_then(|d| d.get("items")).and_then(|i| i.as_array()).cloned().unwrap_or_default();
            // The hash a payer holds is the end-user-leaf-hash its wallet
            // returned; the indexer records the endcap CONTENT hash — they
            // never match for a fresh payment. Exact hash match is accepted
            // when it happens, but the chain-truth match is the FIELDS: a
            // settled transfer from this payer to this recipient covering the
            // amount. Newest first, so a fresh payment cannot be satisfied by
            // an ancient one at a different price by accident.
            let matched = items.iter().find(|it| {
                it.get("tx_hash").and_then(|h| h.as_str()) == Some(proof.tx_hash.as_str())
            }).or_else(|| items.iter().find(|it| {
                it.get("recipient_user_id").and_then(|r| r.as_u64()) == Some(proof.recipient_user_id)
                    && it.get("sender_user_id").and_then(|r| r.as_u64()) == Some(proof.payer_user_id)
                    && it.get("amount").and_then(|a2| a2.as_str())
                        .and_then(|s2| s2.parse::<u64>().ok())
                        .map(|v| v >= proof.amount_nano)
                        .unwrap_or(false)
            })).cloned();
            if matched.is_some() || std::time::Instant::now() >= deadline {
                break matched;
            }
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        };
        match matched.as_ref() {
            Some(it) => {
                let onchain_amount = it.get("amount").and_then(|a2| a2.as_str())
                    .and_then(|s| s.parse::<u64>().ok());
                let onchain_recipient = it.get("recipient_user_id").and_then(|r| r.as_u64());
                // Trust the chain over the header: a payload can claim anything.
                if onchain_recipient != Some(proof.recipient_user_id)
                    || onchain_amount.map(|v| v < proof.amount_nano).unwrap_or(true)
                {
                    return err_json(
                        "the transaction exists but does not match the claimed recipient/amount".to_string(),
                        json!({ "gate": "mismatch", "valid": false, "onchain": it }));
                }
                // An old settled payment is a receipt, not money offered now:
                // bound how far back a claim may reach, so one historic payment
                // cannot be replayed against future resources indefinitely.
                let max_age = a.max_age_checkpoints.unwrap_or(240);
                // FAIL CLOSED. This was `if let (Some(paid_at), Ok(latest))`
                // with no else, so a row without a checkpoint_id, or an
                // unreachable coordinator, silently SKIPPED the age gate — and
                // an arbitrarily old settled payment was then accepted as
                // payment for a resource served now. A verifier that cannot
                // establish how old a payment is has not verified it.
                let paid_at = it.get("checkpoint_id").and_then(|c| c.as_u64());
                let latest = inner.wallet.latest_checkpoint().await.ok();
                if let Err(reason) = check_payment_age(paid_at, latest, max_age) {
                    return err_json(
                        format!("not accepting this payment: {reason}. A payment whose age cannot be established is not payment for a resource served now."),
                        json!({ "gate": "stale", "valid": false,
                                "paidAtCheckpoint": paid_at, "latestCheckpoint": latest,
                                "retryable": latest.is_none() }));
                }
                // Consume the on-chain row: the FIRST verification of a payment
                // wins; the same settled transfer must not unlock a second
                // resource. Keyed by the indexer's own tx hash (unique per
                // settled endcap), not the header's claim.
                // FAIL CLOSED here too. This was `if let Some(row_hash)` with no
                // else, and the row does NOT have to carry a tx_hash: the normal
                // match is the FIELD match above (the comment there notes the
                // hashes "never match for a fresh payment"). A matched row
                // without one was therefore never consumed, and could unlock an
                // unlimited number of resources.
                //
                // Without a unique row identity there is no way to enforce
                // one-use, so refuse. A verifier that cannot account for a
                // payment must not hand over the goods.
                let row_hash = match payment_consume_key(it.get("tx_hash").and_then(|h| h.as_str())) {
                    Ok(k) => k,
                    Err(reason) => return err_json(
                        format!("not accepting this payment: {reason}. One payment must unlock at most one resource, and that cannot be enforced without a unique identity for it."),
                        json!({ "gate": "replay", "valid": false })),
                };
                if !inner.consumed_payments.insert(row_hash.clone()) {
                    return err_json(
                        "this settled payment was already used to unlock a resource — a replay, not a new payment",
                        json!({ "gate": "replay", "valid": false }));
                }
                // Persist immediately: a crash right after serving the resource
                // must not forget that this payment was spent.
                save_consumed_payments(&crate::keystore::keystore_dir(), &inner.consumed_payments);
                ok_json(json!({
                    "status": "ok", "valid": true,
                    "txHash": proof.tx_hash, "payerUserId": proof.payer_user_id,
                    "recipientUserId": proof.recipient_user_id,
                    "amount": onchain_amount, "checkpointId": it.get("checkpoint_id"),
                    "resource": proof.resource,
                }))
            }
            None => err_json(
                format!("no settled transaction {} found for Psy-{:08} — it may still be settling, or the claim is false",
                        proof.tx_hash, proof.payer_user_id),
                json!({ "gate": "unsettled", "valid": false })),
        }
    }

    #[tool(description = "Fund this wallet from the network's faucet service. Asks the hosted faucet to send test PSY to the loaded user; the grant then arrives as a claimable, so follow with claim_all from the returned operator id. Read-only on the agent's side — it spends nothing and needs no session.")]
    async fn claim_faucet(&self, Parameters(a): Parameters<FaucetArgs>) -> Result<CallToolResult, McpError> {
        let inner = self.inner.lock().await;
        let user = match inner.wallet.current_user() {
            Some(u) => u,
            None => return err_json("no wallet loaded — call create_wallet first".to_string(), json!({ "gate": "wallet" })),
        };
        let url = match resolve_agent_url(a.faucet_url.as_deref(), default_faucet_url) {
            Ok(u) => u,
            Err(e) => return err_json(e, json!({ "gate": "url" })),
        };
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "psy_claim_faucet",
            "params": [{ "recipient_user_id": user.user_id }],
        });
        let resp = match reqwest::Client::new().post(&url).json(&body).send().await {
            Ok(r) => r,
            Err(e) => return err_json(format!("faucet service unreachable at {url}: {e:#}"), json!({ "gate": "faucet" })),
        };
        let parsed: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return err_json(format!("faucet returned a non-JSON response: {e:#}"), json!({ "gate": "faucet" })),
        };
        if let Some(err) = parsed.get("error") {
            return err_json(format!("faucet refused: {err}"), json!({ "gate": "faucet" }));
        }
        let result = parsed.get("result").cloned().unwrap_or(json!({}));
        // The grant lands as a claimable from the operator, not as balance —
        // surface the operator id so the caller knows what to claim_all from.
        ok_json(json!({
            "status": "ok",
            "recipientUserId": user.user_id,
            "operatorUserId": result.get("operator_user_id"),
            "amount": result.get("amount"),
            "txHash": result.get("tx_hash"),
            "alreadySubmitted": result.get("already_submitted"),
            "next": "The grant arrives as a claimable — call claim_all with sender_user_ids=[operatorUserId] once it settles.",
        }))
    }

    #[tool(description = "Send a private transfer to a shielded address: settles on chain, proves the note's inclusion, and delivers the gift-wrapped note to the recipient over Nostr so they can claim it. Requires the recipient's npub — without delivery the funds are debited but unclaimable. Set dry_run=true to derive the note and inspect the exact call without settling.")]
    async fn private_transfer(&self, Parameters(a): Parameters<PrivateTransferArgs>) -> Result<CallToolResult, McpError> {
        let mut inner = self.inner.lock().await;
        // Policy gate below the model (this spends, so gate at the amount).
        let Some(charge) = nano_equivalent(&a.token, a.amount_nano) else {
            return err_json(
                format!("unknown token {}: refusing to guess its scale for the policy gate", a.token),
                json!({ "gate": "args" }));
        };
        if a.amount_nano == 0 {
            // A zero note can never be claimed and would fail in-circuit.
            return err_json("a private transfer of 0 is a no-op — pass a positive amount", json!({ "gate": "args" }));
        }
        let auth = match self.policy.lock().unwrap().authorize(&a.session, &a.to_shielded_address, charge, "private_transfer") {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        let Some(contract) = contract_for(&a.token) else {
            // Refund: the authorization above already committed the spend, and
            // nothing moved. Every sibling does this (transfer, transfer_batch,
            // withdraw); this branch was the one that did not, so an agent
            // looping private_transfer with a bogus token drained the daily,
            // 30-day and lifetime budgets without sending anything — and left a
            // spend-log row that read as a completed payment.
            self.policy.lock().unwrap().refund(&auth, charge);
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };

        if a.dry_run {
            // A dry run spends nothing — the authorization above proved the
            // policy WOULD allow it; give the headroom straight back.
            self.policy.lock().unwrap().refund(&auth, charge);
            return match inner.wallet.prepare_private_transfer(&a.to_shielded_address, a.amount_nano, contract) {
                Ok(p) => ok_json(json!({
                    "dryRun": true, "submitted": false,
                    "toShielded": a.to_shielded_address, "amount": a.amount_nano, "token": a.token,
                    "noteCommitment": p.note_commitment, "callInputs": p.call_inputs,
                })),
                Err(e) => err_json(format!("prepare failed: {e:#}"), json!({ "gate": "prepare" })),
            };
        }

        let relay = match resolve_agent_url(a.relay.as_deref(), default_relay) {
            Ok(u) => u,
            Err(e) => return err_json(e, json!({ "gate": "url" })),
        };
        // Prepare, persist the recovery material, and only THEN settle. A note
        // that settles but is not delivered is debited-and-unclaimable, and
        // the secrets that recover it must already be on the owner's disk —
        // never in a tool result (the agent can read those) and never only in
        // the model's context (which gets compacted away).
        let prepared = match inner.wallet.prepare_private_transfer(&a.to_shielded_address, a.amount_nano, contract) {
            Ok(p) => p,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, charge);
                return err_json(format!("prepare failed: {e:#}"), json!({ "gate": "prepare" }));
            }
        };
        let dir = crate::keystore::keystore_dir();
        let mut recovery = crate::wallet::PrivateNoteRecovery {
            note_secret: prepared.note_secret,
            nullifier_secret: prepared.nullifier_secret,
            note_commitment: prepared.note_commitment,
            recipient_shielded_hex: a.to_shielded_address.clone(),
            recipient_npub: a.recipient_npub.clone(),
            amount_nano: a.amount_nano,
            contract_id: contract,
            tx_hash: None,
            checkpoint_id: None,
            note_proof_json: None,
            delivered: false,
        };
        let recovery_path = match recovery.persist(&dir) {
            Ok(p) => p,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, charge);
                return err_json(
                    format!("refusing to transfer: the recovery material could not be persisted ({e:#})"),
                    json!({ "gate": "persist" }));
            }
        };
        tracing::info!("private-note recovery material persisted at {} (owner-side)", recovery_path.display());
        let settled = match inner
            .wallet
            .settle_private_transfer(prepared, NOTE_ROOT_SLOT)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                // The settle failed before money moved — refund. (Once settled,
                // delivery failures do NOT refund: the funds really left.)
                self.policy.lock().unwrap().refund(&auth, charge);
                return err_json(format!("private transfer failed: {e:#}"), json!({ "gate": "execute" }));
            }
        };
        recovery.tx_hash = Some(settled.leaf_hash.clone());
        recovery.checkpoint_id = Some(settled.checkpoint_id);
        recovery.note_proof_json = Some(settled.note_proof_json.clone());
        let _ = recovery.persist(&dir);

        let payload = json!({
            "type": "psy_private_payment",
            "protocol": "psy-private-payment",
            "shieldAddress": a.to_shielded_address,
            "amount": a.amount_nano.to_string(),
            "contractId": contract.to_string(),
            "tokenSymbol": a.token,
            "txHash": settled.leaf_hash,
            "noteProofRaw": settled.note_proof_json,
        })
        .to_string();

        // Note proofs are ~90 KB of base64 — far past NIP-44's 65,535-byte cap —
        // so the payload is split into independently wrapped chunks the
        // recipient reassembles (the same protocol the shipped wallet uses).
        let events = match crate::nostr_delivery::build_note_events(
            &a.recipient_npub, &payload,
            &settled.prepared.owner, &settled.nullifier_hash,
        ) {
            Ok(w) => w,
            Err(e) => return err_json(
                format!("settled on chain but the note could not be wrapped for delivery: {e:#}"),
                json!({ "gate": "deliver", "submitted": true, "txHash": settled.leaf_hash,
                        "note": "The funds are debited and the recovery material is safe on the server host (owner-side; path in the server log). Retry with private_transfer once the cause is fixed — the recipient cannot claim until the note reaches them." })),
        };

        match crate::nostr_delivery::publish_events(&relay, &events).await {
            Ok(event_ids) => {
                recovery.delivered = true;
                let _ = recovery.persist(&dir);
                ok_json(json!({
                "status": "ok", "submitted": true, "delivered": true,
                "toShielded": a.to_shielded_address, "amount": a.amount_nano, "token": a.token,
                "txHash": settled.leaf_hash, "checkpointId": settled.checkpoint_id,
                "nostrEventIds": event_ids, "chunks": events.len(), "relay": relay,
                "note": "Settled and delivered. The recipient can now claim it.",
            }))
            }
            Err(e) => err_json(
                format!("settled on chain but Nostr delivery failed: {e:#}. The recipient cannot claim until the note reaches them."),
                json!({ "gate": "deliver", "submitted": true, "txHash": settled.leaf_hash,
                        "note": "The funds are debited and the recovery material is safe on the server host (owner-side; path in the server log). Retry the delivery once the relay is reachable." })),
        }
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ClaimableArgs { sender_user_id: u64 }

#[derive(Deserialize, schemars::JsonSchema)]
struct BalanceArgs {
    #[serde(default = "default_psy")]
    token: String,
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
    /// Recipient's Nostr npub — how the note reaches them. Without it the note
    /// is undeliverable and the funds would be debited but unclaimable.
    recipient_npub: String,
    #[serde(rename = "amount")]
    amount_nano: u64,
    #[serde(default = "default_psy")]
    token: String,
    /// Relay to publish the note to. Defaults to the staging relay.
    #[serde(default)]
    relay: Option<String>,
    /// Derive and show the call without settling anything.
    #[serde(default)]
    dry_run: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FaucetArgs {
    /// Faucet service endpoint. Defaults to the staging faucet.
    #[serde(default)]
    faucet_url: Option<String>,
}

fn default_faucet_url() -> String {
    std::env::var("PSY_MCP_FAUCET_URL")
        .unwrap_or_else(|_| "https://faucet-stg.psy-protocol.xyz".to_string())
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PrivateClaimArgs {
    session: String,
    /// A specific note to claim. Omit to claim everything psy-services is
    /// holding for this wallet — it already subscribes to the relay, so no
    /// direct Nostr connection is needed here.
    #[serde(default)]
    note: Option<String>,
    #[serde(default = "default_psy")]
    token: String,
    /// psy-services endpoint; defaults to staging.
    #[serde(default)]
    services_url: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ActivityArgs {
    /// How many entries to return (1–200, default 20).
    #[serde(default)]
    limit: Option<u32>,
    /// psy-services endpoint; defaults to staging.
    #[serde(default)]
    services_url: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct X402FetchArgs {
    session: String,
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
    session: String,
    /// Amount in the token's base units (USDT: 6 decimals; PSY: 9).
    amount_base_units: u64,
    #[serde(default = "default_usdt")]
    token: String,
    /// Psy's internal index for the source chain.
    #[serde(default)]
    source_chain_index: u32,
    // The L1 RPC URL and every contract address are OWNER configuration
    // (PSY_MCP_L1_RPC / PSY_MCP_ROUTER / … env), never tool arguments: this
    // tool signs with the owner's L1 key, and an agent that chooses where and
    // against which contracts that key signs effectively holds the key.
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ClaimDepositArgs {
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
    /// Psy's internal chain index for the destination (0 = the L1 it bridges to).
    #[serde(default)]
    dest_chain_index: u64,
    /// Unique per withdrawal; defaults to the current unix time.
    #[serde(default)]
    nonce: Option<u64>,
}

fn default_usdt() -> String { "USDT".to_string() }

/// Staging L1 endpoints (config-stg.psy-protocol.xyz/config.json is the source
/// of truth — these go stale when staging redeploys, as they did once already).
fn default_l1_rpc() -> String {
    std::env::var("PSY_MCP_L1_RPC").unwrap_or_else(|_| "https://rpc-stg.psy-protocol.xyz".to_string())
}
fn default_router() -> String {
    std::env::var("PSY_MCP_L1_ROUTER").unwrap_or_else(|_| "0x960B4E47CD335990A2C3a7aeb6909e4C9084AA7a".to_string())
}
fn default_erc20_gateway() -> String {
    std::env::var("PSY_MCP_L1_ERC20_GATEWAY")
        .unwrap_or_else(|_| "0xB51F25b34622c5B791f5c32e8695a22A17bf03E4".to_string())
}
fn default_bridge() -> String {
    std::env::var("PSY_MCP_L1_BRIDGE").unwrap_or_else(|_| "0x5B8010e8F5F4BAe5cd7737A3398B16C115274Cd9".to_string())
}

fn default_x402_network() -> String {
    std::env::var("PSY_MCP_X402_NETWORK").unwrap_or_else(|_| "psy-sepolia".to_string())
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
pub fn check_payment_age(
    paid_at: Option<u64>,
    latest: Option<u64>,
    max_age: u64,
) -> Result<(), String> {
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
    default: impl FnOnce() -> String,
) -> Result<String, String> {
    match supplied {
        Some(u) => guard_outbound_url(u).map(|()| u.to_string()),
        None => Ok(default()),
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
    let addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
        .map_err(|e| format!("could not resolve {host}: {e}"))?;
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

fn default_services_url() -> String {
    std::env::var("PSY_MCP_SERVICES_URL")
        .unwrap_or_else(|_| "https://services-stg.psy-protocol.xyz".to_string())
}

enum DepositMaterial {
    Ready { note: crate::wallet::DepositNote, proof: serde_json::Value },
    AlreadyClaimed { note: crate::wallet::DepositNote },
}

/// Load a persisted deposit note and its services merkle proof, or explain
/// why it is not claimable yet. Shared by `claim_deposit` and `claim_batch`.
async fn load_claimable_deposit(
    backup_path: Option<String>,
    deposit_index: Option<u64>,
    services_url: Option<&str>,
) -> Result<DepositMaterial, (String, serde_json::Value)> {
    let dir = crate::keystore::keystore_dir();
    let path = match backup_path {
        Some(p) => std::path::PathBuf::from(p),
        None => match deposit_index {
            Some(i) => crate::wallet::DepositNote::path_in(&dir, i),
            None => {
                return Err((
                    "pass backup_path or deposit_index (both are in deposit's output)".to_string(),
                    json!({ "gate": "args" }),
                ))
            }
        },
    };
    let note = crate::wallet::DepositNote::load(&path)
        .map_err(|e| (format!("{e:#}"), json!({ "gate": "load" })))?;
    if note.claimed {
        return Ok(DepositMaterial::AlreadyClaimed { note });
    }

    let services = resolve_agent_url(services_url, default_services_url)
        .map_err(|e| (e, json!({ "gate": "url" })))?;
    // proved_deposit_count is read from the L1 bridge and passed through
    // HONESTLY. Inflating it past reality makes the service build a proof
    // over a tree the chain does not have yet — which then fails at the
    // claim itself with an opaque error instead of a retryable "not yet".
    let bridge: alloy_primitives::Address = default_bridge().parse().map_err(|e| (
        format!("PSY_MCP_L1_BRIDGE is not a valid Ethereum address: {e}"),
        json!({ "gate": "config", "var": "PSY_MCP_L1_BRIDGE" }),
    ))?;
    // Read the proved count keylessly — this is a plain eth_call; it needs no
    // signer. The old from_env-or-0 here made every keyless claim read a fake 0
    // and report "relayer still working" long after the chain proved the deposit.
    let proved = crate::l1::L1Client::read_only(default_l1_rpc())
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

/// Staging L1 token addresses (config-stg.psy-protocol.xyz/config.json).
fn default_l1_token(token: &str) -> Option<String> {
    match token.to_ascii_uppercase().as_str() {
        "PSY" => Some("0xd8B4F2bf23daaeC19686190d1013E4778E003dFb".to_string()),
        "USDT" => Some("0xbBC0D21A312006eB0E902c279d5E53Dc8225cBB6".to_string()),
        _ => None,
    }
}

/// Slot holding the note-tree root in the token contract's state.
const NOTE_ROOT_SLOT: u64 = 8_388_609;

fn default_relay() -> String {
    std::env::var("PSY_MCP_NOSTR_RELAY")
        .unwrap_or_else(|_| "wss://nostr-stg.psy-protocol.xyz/".to_string())
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
    let mut wallet = WalletManager::from_config(&config_path).await?;

    // Owner-side wallet restore: load a key backup at startup so a restart
    // never requires routing the private key through the model's context.
    if let Ok(key_file) = std::env::var(keystore::KEY_FILE_ENV) {
        if !key_file.trim().is_empty() {
            let backup = keystore::load_key_file(&key_file)?;
            // A failed restore must NOT kill the server. `mint_agent_account`
            // tells the owner to restart with PSY_MCP_KEY_FILE=<path>, and a
            // mandate-bound account cannot currently be reloaded (its identity
            // is derived from the SD-key CIRCUIT fingerprint, and nothing
            // re-registers that circuit on this path) — so following the tool's
            // own instruction exited the process before it served anything.
            // Boot without a wallet instead and say exactly what happened; the
            // owner can still reach every read-only and setup tool.
            match wallet.load_from_backup(&backup).await {
                Ok(loaded) => tracing::info!(
                    "wallet restored from {} — user id {} (Psy-{:08}); create a policy to let the agent spend",
                    key_file,
                    loaded.user_id,
                    loaded.user_id
                ),
                Err(e) => tracing::error!(
                    "could not restore the wallet from {key_file}: {e:#}. \
                     Starting WITHOUT a loaded wallet — fund-moving tools will report no wallet \
                     until one is loaded. If this key was created by mint_agent_account (backup \
                     fingerprint {}), reloading a mandate-bound account is not supported yet: the \
                     identity comes from its software-defined circuit, which this path does not \
                     re-register. Use a create_wallet-generated key file, or re-mint.",
                    backup.fingerprint
                ),
            }
        }
    }
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

    let service = PsyWalletServer::new(wallet).serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod url_guard_tests {
    use super::{guard_outbound_url, resolve_agent_url};

    // The SSRF guard existed and was applied at exactly ONE of seven
    // agent-supplied URL arguments. The other six let the agent choose the
    // destination — and get_activity and private_claim echo the remote body
    // straight back into model context on failure, which turns "reach an
    // internal host" into "read an internal host".

    fn default_url() -> String {
        "https://services-stg.psy-protocol.xyz".to_string()
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
            assert!(
                resolve_agent_url(Some(u), default_url).is_err(),
                "loopback must be refused: {u}",
            );
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
        let got = resolve_agent_url(None, || "http://127.0.0.1:3000".to_string())
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
