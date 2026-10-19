use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::FutureExt;

use super::*;
use crate::wide_private as w;
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WideBalanceArgs {
    #[serde(default)]
    network: Option<String>,
    contract_id: u64,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WideSendArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    contract_id: u64,
    to_user_id: u64,
    /// Exact integer base units as DECIMAL TEXT (1..2^124-1). Never a JSON
    /// number.
    amount: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WideAcceptArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    contract_id: u64,
    /// Opaque encrypted delivery returned by private_ft_transfer. Contains no
    /// readable note secrets.
    delivery: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WideSyncArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WideClaimArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    contract_id: u64,
    note_id: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WideRecoverArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    contract_id: u64,
    to_user_id: u64,
    recovery_id: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WidePublicClaimArgs {
    #[serde(default)]
    network: Option<String>,
    session: String,
    contract_id: u64,
    sender_user_id: u64,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct WideStatusArgs {
    #[serde(default)]
    network: Option<String>,
    record_id: String,
    /// outgoing, incoming or public
    direction: String,
}
fn failure(network: &NetworkId, id: &str, prefix: &str, attempted: bool, error: impl std::fmt::Display) -> Result<CallToolResult, McpError> {
    let path = w::directory(network.as_str()).ok().map(|p| p.join(format!("{prefix}-{id}.json")));
    let public = path.and_then(|p| w::read::<serde_json::Value>(&p).ok());
    let broadcast = public.as_ref().and_then(|v| v["end_leaf"].as_str()).map(str::to_owned);
    err_json(
        error,
        json!({"gate":"private-ft","recordId":id,"submitted":if attempted{Some(true)}else{public.as_ref().map(|_|broadcast.is_some())},"submissionAttemptedThisCall":attempted,"submissionMayBeUnresolved":attempted||broadcast.is_some()||public.is_none(),"endUserLeafHash":broadcast,"retryTransferAllowed":false,"next":if broadcast.is_some(){"Reconcile the exact leaf hash; recover the saved outgoing record or reconcile the pending claim. Never send another payment to retry delivery."}else{"No broadcast identity was recorded. Inspect the local failure before preparing a new transaction."}}),
    )
}
#[tool_router(router=wide_private_tools_router,vis="pub(crate)")]
impl PsyWalletServer {
    #[tool(
        description = "Read the exact spendable balance of an owner-registered private FT. Automatically selects the pinned single-Felt or U124 contract profile. Returns DECIMAL TEXT and profile; rejects unknown or changed code/layout pins."
    )]
    async fn get_private_ft_balance(&self, Parameters(a): Parameters<WideBalanceArgs>) -> Result<CallToolResult, McpError> {
        let n = wallet_network!(self.state.wallet, a.network.as_deref());
        let asset = match self.wide_assets.asset(n.as_str(), a.contract_id) {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"submitted":false})),
        };
        match self.state.wallet.wide_balance(&n, &asset).await {
            Ok(v) => ok_json(
                json!({"contractId":a.contract_id,"amount":v,"decimals":asset.decimals,"profile":asset.profile,"policyNanoPerWholeToken":asset.policy_nano_per_token}),
            ),
            Err(e) => err_json(e, json!({"submitted":false})),
        }
    }
    #[tool(
        description = "Unified ordinary-wallet private FT transfer. Selects the single-Felt or U124 adapter from the owner-pinned contract profile, never from amount or decimals. amount is decimal text in base units. Requires registered recipient, private_transfer permission and budget. Saves recovery before one broadcast, verifies full UPS and confirms inclusion. Automatically publishes encrypted chunks to the configured Nostr relay and returns an ACK receipt plus a recovery delivery. Receiver calls private_ft_sync; retry delivery via private_ft_recover, never resend payment."
    )]
    async fn private_ft_transfer(&self, Parameters(a): Parameters<WideSendArgs>) -> Result<CallToolResult, McpError> {
        let n = wallet_network!(self.state.wallet, a.network.as_deref());
        let prepared = (|| -> anyhow::Result<_> {
            let asset = self.wide_assets.asset(n.as_str(), a.contract_id)?;
            let contact = self.wide_assets.contact(n.as_str(), a.to_user_id)?;
            let amount = w::amount(&a.amount)?;
            asset.profile.encode(amount)?;
            let charge = w::charge(&asset, amount)?;
            Ok((asset, contact, amount, charge))
        })();
        let (asset, contact, amount, charge) = match prepared {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"gate":"args","submitted":false})),
        };
        let auth = match self
            .authorize_wallet(&n, &a.session, &a.to_user_id.to_string(), charge, "private_transfer")
            .await
        {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"gate":"policy","submitted":false})),
        };
        let id = w::new_id();
        let Some(user) = auth.user_id else {
            self.policy.lock().unwrap().refund(&auth, charge);
            return err_json("authorization lacks wallet identity", json!({"submitted":false}));
        };
        let broadcast = AtomicBool::new(false);
        let result = std::panic::AssertUnwindSafe(self.state.wallet.wide_send(&n, user, &asset, &contact, amount, &id, &broadcast))
            .catch_unwind()
            .await;
        match result {
            Ok(Ok(mut value)) => {
                let delivery = serde_json::to_string(&value["delivery"]).expect("JSON value");
                value["delivery"] = serde_json::Value::String(delivery);
                value["policyChargeNano"] = serde_json::Value::String(charge.to_string());
                value["profile"] = json!(asset.profile);
                ok_json(value)
            }
            other => {
                // In-memory fact is set immediately before the ONLY submit RPC;
                // journal I/O after broadcast can never re-grant the amount budget.
                if !broadcast.load(Ordering::SeqCst) {
                    self.policy.lock().unwrap().refund(&auth, charge);
                }
                match other {
                    Ok(Err(e)) => failure(&n, &id, "out", broadcast.load(Ordering::SeqCst), format!("{e:#}")),
                    Err(_) => failure(
                        &n,
                        &id,
                        "out",
                        broadcast.load(Ordering::SeqCst),
                        "wallet proof aborted; inspect/reconcile saved transaction identity",
                    ),
                    _ => unreachable!(),
                }
            }
        }
    }
    #[tool(description = "Fetch encrypted single-Felt and U124 FT deliveries from this network's configured Nostr relay; decrypt and independently verify locally, then save accepted notes. Uses private_claim permission, never broadcasts and never exposes keys or decrypted proof material. Returns note IDs for private_ft_claim. Repeated sync is idempotent.")]
    async fn private_ft_sync(&self, Parameters(a): Parameters<WideSyncArgs>) -> Result<CallToolResult, McpError> {
        let n = wallet_network!(self.state.wallet, a.network.as_deref());
        let auth = match self.authorize_wallet(&n, &a.session, SELF_RECIPIENT, 0, "private_claim").await {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"gate":"policy","submitted":false})),
        };
        let Some(user) = auth.user_id else { return err_json("authorization lacks wallet identity", json!({"submitted":false})); };
        match self.state.wallet.wide_sync(&n, user, &self.wide_assets).await {
            Ok(v) => ok_json(v),
            Err(e) => err_json(e, json!({"submitted":false})),
        }
    }
    #[tool(
        description = "Verify and save an encrypted single-Felt or U124 FT delivery for the selected ordinary wallet, using the registered contract profile. Rejects cross-format packets; checks recipient, token and all native proofs. Does not broadcast or export decrypted data."
    )]
    async fn private_ft_accept(&self, Parameters(a): Parameters<WideAcceptArgs>) -> Result<CallToolResult, McpError> {
        let n = wallet_network!(self.state.wallet, a.network.as_deref());
        let auth = match self.authorize_wallet(&n, &a.session, SELF_RECIPIENT, 0, "private_claim").await {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"gate":"policy","submitted":false})),
        };
        let prepared = (|| -> anyhow::Result<_> {
            anyhow::ensure!(a.delivery.len() <= 8 * 1024 * 1024, "delivery too large");
            Ok((
                self.wide_assets.asset(n.as_str(), a.contract_id)?,
                serde_json::from_str::<w::Delivery>(&a.delivery)?,
            ))
        })();
        let (asset, delivery) = match prepared {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"submitted":false})),
        };
        let Some(user) = auth.user_id else {
            return err_json("authorization lacks wallet identity", json!({"submitted":false}));
        };
        match self.state.wallet.wide_accept(&n, user, &asset, &delivery).await {
            Ok(v) => ok_json(v),
            Err(e) => err_json(e, json!({"submitted":false})),
        }
    }
    #[tool(
        description = "Unified single-Felt/U124 private FT claim by local note_id. Selects the registered contract adapter, adds all native proofs before final session paths, verifies full CFC/UPS, journals one broadcast and confirms it. Pending/consumed notes cannot be submitted again."
    )]
    async fn private_ft_claim(&self, Parameters(a): Parameters<WideClaimArgs>) -> Result<CallToolResult, McpError> {
        let n = wallet_network!(self.state.wallet, a.network.as_deref());
        let asset = match self.wide_assets.asset(n.as_str(), a.contract_id) {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"submitted":false})),
        };
        let auth = match self.authorize_wallet(&n, &a.session, SELF_RECIPIENT, 0, "private_claim").await {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"gate":"policy","submitted":false})),
        };
        let Some(user) = auth.user_id else {
            return err_json("no authorized wallet", json!({"submitted":false}));
        };
        let broadcast = AtomicBool::new(false);
        match std::panic::AssertUnwindSafe(self.state.wallet.wide_claim(&n, user, &asset, &a.note_id, &broadcast))
            .catch_unwind()
            .await
        {
            Ok(Ok(v)) => ok_json(v),
            Ok(Err(e)) => failure(&n, &a.note_id, "in", broadcast.load(Ordering::SeqCst), format!("{e:#}")),
            Err(_) => failure(
                &n,
                &a.note_id,
                "in",
                broadcast.load(Ordering::SeqCst),
                "wallet proof aborted; reconcile saved transaction identity",
            ),
        }
    }
    #[tool(
        description = "Recover/prove an already submitted single-Felt or U124 FT outgoing record, preserving its adapter and returning encrypted delivery. Never broadcasts or charges the amount again."
    )]
    async fn private_ft_recover(&self, Parameters(a): Parameters<WideRecoverArgs>) -> Result<CallToolResult, McpError> {
        let n = wallet_network!(self.state.wallet, a.network.as_deref());
        let auth = match self.authorize_wallet(&n, &a.session, SELF_RECIPIENT, 0, "private_transfer").await {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"gate":"policy","submitted":false})),
        };
        let p = (|| -> anyhow::Result<_> {
            Ok((
                self.wide_assets.asset(n.as_str(), a.contract_id)?,
                self.wide_assets.contact(n.as_str(), a.to_user_id)?,
            ))
        })();
        let (asset, contact) = match p {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"submitted":false})),
        };
        let Some(u) = auth.user_id else {
            return err_json("authorization lacks wallet identity", json!({"submitted":false}));
        };
        match self.state.wallet.wide_recover(&n, u, &asset, &contact, &a.recovery_id).await {
            Ok(mut v) => {
                v["delivery"] = serde_json::Value::String(serde_json::to_string(&v["delivery"]).expect("JSON value"));
                ok_json(v)
            }
            Err(e) => failure(&n, &a.recovery_id, "out", false, format!("{e:#}")),
        }
    }
    #[tool(
        description = "Claim public single-Felt or U124 credits owed to this ordinary wallet. Selects simple_claim for native assets or claim for registered PSY20/U124 templates. Authorizes simple_claim to self."
    )]
    async fn private_ft_public_claim(&self, Parameters(a): Parameters<WidePublicClaimArgs>) -> Result<CallToolResult, McpError> {
        let n = wallet_network!(self.state.wallet, a.network.as_deref());
        let asset = match self.wide_assets.asset(n.as_str(), a.contract_id) {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"submitted":false})),
        };
        let auth = match self.authorize_wallet(&n, &a.session, SELF_RECIPIENT, 0, "simple_claim").await {
            Ok(v) => v,
            Err(e) => return err_json(e, json!({"submitted":false})),
        };
        let Some(user) = auth.user_id else {
            return err_json("no authorized wallet", json!({"submitted":false}));
        };
        let id = w::new_id();
        let broadcast = AtomicBool::new(false);
        match std::panic::AssertUnwindSafe(self.state.wallet.wide_public_claim(&n, user, &asset, a.sender_user_id, &id, &broadcast))
            .catch_unwind()
            .await
        {
            Ok(Ok(v)) => ok_json(v),
            Ok(Err(e)) => failure(&n, &id, "public", broadcast.load(Ordering::SeqCst), format!("{e:#}")),
            Err(_) => failure(
                &n,
                &id,
                "public",
                broadcast.load(Ordering::SeqCst),
                "wallet proof aborted; reconcile saved identity",
            ),
        }
    }
    #[tool(
        description = "Read/reconcile an ordinary wallet's pending U124 FT transaction by opaque local record id. Never submits. Returns only status, public transaction identity and checkpoint; no note or key material."
    )]
    async fn private_ft_status(&self, Parameters(a): Parameters<WideStatusArgs>) -> Result<CallToolResult, McpError> {
        let n = wallet_network!(self.state.wallet, a.network.as_deref());
        match self.state.wallet.wide_status(&n, &a.record_id, &a.direction).await {
            Ok(v) => ok_json(v),
            Err(e) => err_json(e, json!({"submitted":false})),
        }
    }
}
