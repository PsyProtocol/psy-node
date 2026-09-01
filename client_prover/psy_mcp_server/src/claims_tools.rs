use super::*;
use crate::wallet_network;

#[tool_router(router = claims_tools_router, vis = "pub(crate)")]
impl PsyWalletServer {
    #[tool(description = "Live chain status: the latest coordinator checkpoint id.")]
    async fn get_chain_status(&self, Parameters(a): Parameters<NetworkArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        match state.wallet.latest_checkpoint(&network).await {
            Ok(cp) => ok_json(json!({ "network": network.as_str(), "checkpointId": cp })),
            Err(e) => err_json(format!("chain unreachable: {e:#}"), json!({})),
        }
    }

    #[tool(description = "Info about the loaded wallet: user id and Psy ID.")]
    async fn get_user_info(&self, Parameters(a): Parameters<NetworkArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        match state.wallet.current_user(&network).await {
            Some(u) => ok_json(json!({ "network": network.as_str(), "userId": u.user_id, "psyId": format!("Psy-{:08}", u.user_id) })),
            None => err_json("no wallet loaded", json!({})),
        }
    }

    #[tool(
        description = "This wallet's spendable public balance for a token, read from the chain at the latest checkpoint. Read-only; no session needed. A freshly claimed amount appears here only once its checkpoint settles — poll this before spending money you just received."
    )]
    async fn get_balance(&self, Parameters(a): Parameters<BalanceArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        let Some(contract) = contract_for(&a.token) else {
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        match state.wallet.balance(&network, contract).await {
            Ok(nano) => ok_json(json!({ "status": "ok", "network": network.as_str(), "token": a.token, "balance": nano })),
            Err(e) => err_json(format!("{e:#}"), json!({ "gate": "read" })),
        }
    }

    #[tool(description = "Public claimable (Nano) owed to the loaded wallet by a specific sender user id.")]
    async fn get_claimable(&self, Parameters(a): Parameters<ClaimableArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        match state.wallet.claim_amount_from(&network, a.sender_user_id).await {
            Ok(amount) => ok_json(json!({ "network": network.as_str(), "senderUserId": a.sender_user_id, "claimable": amount })),
            Err(e) => err_json(e, json!({ "failClosed": true })),
        }
    }

    // ── Spend (policy-gated → REAL proof via WalletSession) ────────────

    #[tool(
        description = "Public transfer by user id, with REAL client-side proving. Policy-gated: the session's caps/allowlist must permit it. Returns the submitted end-user-leaf-hash."
    )]
    async fn transfer(&self, Parameters(a): Parameters<TransferArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        // 1. Policy gate BELOW the model.
        // Charge the gate in the unit the owner's caps are written in. Without
        // this a USDT amount is a thousandth of its real size to every cap.
        let Some(charge) = nano_equivalent(&a.token, a.amount_nano) else {
            return err_json(
                format!("unknown token {}: refusing to guess its scale for the policy gate", a.token),
                json!({ "gate": "args" }),
            );
        };
        if a.amount_nano == 0 {
            // The contract asserts amount > 0, so a zero transfer would spend a
            // proof (~10-40s) to fail in-circuit. Reject it here instead.
            return err_json("a transfer of 0 is a no-op — pass a positive amount", json!({ "gate": "args" }));
        }
        let auth = match self
            .authorize_wallet(&network, &a.session, &a.to_user_id.to_string(), charge, "simple_transfer")
            .await
        {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        // 2. Real proof + submit through WalletSession.
        let Some(contract) = contract_for(&a.token) else {
            self.policy.lock().unwrap().refund(&auth, charge);
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        if let Err(reason) = ensure_spendable_balance(&state.wallet, &network, contract, a.amount_nano, &a.token).await {
            self.policy.lock().unwrap().refund(&auth, charge);
            return err_json(reason, json!({ "gate": "balance" }));
        }
        let execution = match auth.user_id {
            Some(user_id) => state.wallet.transfer_for(&network, user_id, a.to_user_id, a.amount_nano, contract).await,
            None => Err(anyhow::anyhow!("authorization did not bind a wallet identity")),
        };
        match execution {
            Ok(leaf) => {
                ok_json(json!({ "submitted": true, "endUserLeafHash": leaf, "toUserId": a.to_user_id, "amount": a.amount_nano, "token": a.token }))
            }
            Err(e) => {
                // The spend never settled — give the headroom back, or a flaky
                // chain burns the daily budget with failures.
                self.policy.lock().unwrap().refund(&auth, charge);
                err_json(format!("transfer failed: {e:#}"), json!({ "gate": "execute" }))
            }
        }
    }

    #[tool(
        description = "Pay SEVERAL recipients at once, fused into ONE proof and one fee (real proving). All-or-nothing: if the policy refuses any single payment, nothing is sent and no budget is used. Each payment is checked against the per-payment cap and the running total against the daily, 30-day and lifetime budgets."
    )]
    async fn transfer_batch(&self, Parameters(a): Parameters<TransferBatchArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        if a.payments.is_empty() {
            return err_json("a batch needs at least one payment".to_string(), json!({ "gate": "args" }));
        }
        if a.payments.iter().any(|p| p.amount_nano == 0) {
            // Same reasoning as the single transfer: the contract asserts
            // amount > 0, so a zero leg would burn a proof to fail in-circuit.
            return err_json(
                "a batch payment of 0 is a no-op — pass positive amounts".to_string(),
                json!({ "gate": "args", "sent": false }),
            );
        }
        // 1. Policy gate BELOW the model, as ONE decision. authorize_batch either
        //    charges every leg or charges nothing — see the note on why this cannot be
        //    a loop over authorize().
        let recipients: Vec<String> = a.payments.iter().map(|p| p.to_user_id.to_string()).collect();
        // Same normalization as the single transfer, per leg — otherwise a
        // USDT batch is charged a thousandth of its real total.
        let mut charged: Vec<u64> = Vec::with_capacity(a.payments.len());
        for p in &a.payments {
            match nano_equivalent(&a.token, p.amount_nano) {
                Some(v) => charged.push(v),
                None => {
                    return err_json(
                        format!("unknown token {}: refusing to guess its scale for the policy gate", a.token),
                        json!({ "gate": "args", "sent": false }),
                    )
                }
            }
        }
        let legs: Vec<(&str, u64)> = recipients.iter().zip(charged.iter()).map(|(r, c)| (r.as_str(), *c)).collect();
        let total_nano: u64 = charged.iter().fold(0u64, |acc, n| acc.saturating_add(*n));
        let auth = match self.authorize_wallet_batch(&network, &a.session, &legs, "simple_transfer").await {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy", "sent": false })),
        };
        let Some(contract) = contract_for(&a.token) else {
            self.policy.lock().unwrap().refund(&auth, total_nano);
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        let total_base = a.payments.iter().fold(0u64, |total, payment| total.saturating_add(payment.amount_nano));
        if let Err(reason) = ensure_spendable_balance(&state.wallet, &network, contract, total_base, &a.token).await {
            self.policy.lock().unwrap().refund(&auth, total_nano);
            return err_json(reason, json!({ "gate": "balance", "sent": false }));
        }
        // 2. Real proof + submit. One recursive proof carries every payment, so the
        //    batch settles together or not at all.
        let payments: Vec<(u64, u64)> = a.payments.iter().map(|p| (p.to_user_id, p.amount_nano)).collect();
        let count = payments.len();
        let execution = match auth.user_id {
            Some(user_id) => state.wallet.transfer_batch_for(&network, user_id, payments, contract).await,
            None => Err(anyhow::anyhow!("authorization did not bind a wallet identity")),
        };
        match execution {
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

    #[tool(
        description = "Claim ALL public claimables owed by the given senders, fused into ONE UPS proof / one fee (real proving). Claiming only folds funds already addressed to you into spendable balance. Discover sender ids with get_claimable."
    )]
    async fn claim_all(&self, Parameters(a): Parameters<ClaimAllArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        // Policy gate — claims move value into the account, so we gate them too
        // (amount 0: claiming does not spend). This keeps a paused policy able to
        // freeze all activity.
        if let Err(e) = self.authorize_wallet(&network, &a.session, SELF_RECIPIENT, 0, "simple_claim").await {
            return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" }));
        }
        let Some(contract) = contract_for(&a.token) else {
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        match state.wallet.claim_all_public(&network, a.sender_user_ids.clone(), contract).await {
            Ok(leaf) => ok_json(
                json!({ "submitted": true, "endUserLeafHash": leaf, "claimedFrom": a.sender_user_ids, "token": a.token, "note": "One UPS proof, one fee." }),
            ),
            Err(e) => err_json(format!("claim_all failed: {e:#}"), json!({ "gate": "execute" })),
        }
    }

    #[tool(
        description = "List this wallet's transaction history — payments in and out, claims, deposits and withdrawals — as recorded by the indexer. Read-only: it spends nothing and needs no session."
    )]
    async fn get_activity(&self, Parameters(a): Parameters<ActivityArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        let user = match state.wallet.current_user(&network).await {
            Some(u) => u,
            None => return err_json("no wallet loaded — call create_wallet first".to_string(), json!({ "gate": "wallet" })),
        };
        let base = match resolve_agent_url(a.services_url.as_deref(), || network_services_url(&state.wallet, &network)) {
            Ok(u) => u,
            Err(e) => return err_json(e, json!({ "gate": "url" })),
        };
        let limit = a.limit.unwrap_or(20).clamp(1, 200);
        let url = format!(
            "{}/api/v1/get/user/activity?user_id={}&limit={}",
            base.trim_end_matches('/'),
            user.user_id,
            limit
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

    #[tool(
        description = "Deposit tokens from Ethereum into this wallet's shielded address on Psy. Uses the owner-provisioned L1 key (PSY_MCP_L1_KEY env — the agent never sees it): saves the claim secrets to disk FIRST, then approves if needed and calls Router.deposit. After the bridge relayer proves it, publishes the wallet-compatible proof/secrets pair to the configured Nostr relay so psy-wallet can claim it. Policy-gated at the amount."
    )]
    async fn deposit(&self, Parameters(a): Parameters<DepositArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        // Policy caps are denominated in Nano (9 decimals); L1 base units are
        // token-specific (USDT: 6). Charging base units against Nano caps
        // silently authorized ~1000x what the owner set for USDT — normalize
        // BEFORE the gate, and refuse tokens whose scale we do not know rather
        // than guess one.
        let Some(amount_nano_equivalent) = nano_equivalent(&a.token, a.amount_base_units) else {
            return err_json(
                format!("unknown token {}: cannot convert its base units to Nano for the policy gate", a.token),
                json!({ "gate": "args" }),
            );
        };
        let Some(l2_contract) = contract_for(&a.token) else {
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        let auth = match self
            .authorize_wallet(&network, &a.session, SELF_RECIPIENT, amount_nano_equivalent, "deposit")
            .await
        {
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
        let l1_rpc = match network_l1_rpc(&state.wallet, &network) {
            Ok(url) => url,
            Err(e) => fail!(e, json!({ "gate": "config", "field": "l1_rpc_urls" })),
        };
        let l1 = match crate::l1::L1Client::from_env(l1_rpc) {
            Ok(c) => c,
            Err(e) => fail!(format!("{e:#}"), json!({ "gate": "l1-key" })),
        };
        let token_str = match network_l1_token(&state.wallet, &network, &a.token) {
            Some(t) => t,
            None => fail!(format!("no L1 address known for {}", a.token), json!({ "gate": "config" })),
        };
        let token: alloy_primitives::Address = match token_str.parse() {
            Ok(t) => t,
            Err(e) => fail!(format!("bad token address {token_str}: {e}"), json!({ "gate": "config" })),
        };
        let router_value = match network_router(&state.wallet, &network) {
            Ok(value) => value,
            Err(e) => fail!(e, json!({ "gate": "config", "field": "l1_router_address" })),
        };
        let router: alloy_primitives::Address = match router_value.parse() {
            Ok(r) => r,
            Err(e) => fail!(format!("bad router address: {e}"), json!({ "gate": "config" })),
        };
        let bridge_value = match network_bridge(&state.wallet, &network) {
            Ok(value) => value,
            Err(e) => fail!(e, json!({ "gate": "config", "field": "l1_bridge_address" })),
        };
        let bridge: alloy_primitives::Address = match bridge_value.parse() {
            Ok(b) => b,
            Err(e) => fail!(format!("bad bridge address: {e}"), json!({ "gate": "config" })),
        };
        let amount = alloy_primitives::U256::from(a.amount_base_units);

        // Fail on funds BEFORE writing anything or prompting anything.
        match l1.erc20_balance(token).await {
            Ok(bal) if bal < amount => fail!(
                format!("L1 balance {bal} is less than the deposit {amount}"),
                json!({ "gate": "funds", "l1Address": format!("{}", l1.address()) })
            ),
            Err(e) => fail!(format!("could not read the L1 balance: {e:#}"), json!({ "gate": "l1" })),
            _ => {}
        }

        // Fresh secrets, persisted BEFORE any broadcast: a deposit whose secrets
        // are lost is permanently unclaimable, with no error anywhere.
        let identity = match state.wallet.receive_identity(&network).await {
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
            (
                [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()],
                [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()],
            )
        };
        let mut note = crate::wallet::DepositNote {
            network: Some(network.as_str().to_string()),
            note_secret,
            nullifier_secret,
            shield_address_hex: identity.shield_address_hex.clone(),
            l1_token_address: token_str.clone(),
            l2_token_contract_id: l2_contract,
            amount_base_units: a.amount_base_units,
            source_chain_index: a.source_chain_index,
            expected_deposit_index: expected_index,
            l1_tx_hash: None,
            claimed: false,
            delivered: false,
            deposit_proof_json: None,
            nostr_event_ids: Vec::new(),
        };
        let dir = crate::keystore::keystore_dir();
        let backup = match note.persist(&dir) {
            Ok(p) => p,
            Err(e) => fail!(
                format!("refusing to deposit: the claim secrets could not be persisted ({e:#})"),
                json!({ "gate": "persist" })
            ),
        };

        // The ERC20Gateway is what pulls the funds (the Router only forwards),
        // so the allowance must be granted to the GATEWAY — approving the
        // Router leaves allowance(gateway)=0 and the deposit reverts with
        // ERC20InsufficientAllowance. Mirrors the web wallet's
        // `spender = erc20GatewayAddress || routerAddress`.
        let gateway_value = match network_erc20_gateway(&state.wallet, &network) {
            Ok(value) => value,
            Err(e) => fail!(e, json!({ "gate": "config", "field": "l1_erc20_gateway_address" })),
        };
        let spender: alloy_primitives::Address = match gateway_value.parse() {
            Ok(g) => g,
            Err(e) => fail!(format!("bad gateway address: {e}"), json!({ "gate": "config" })),
        };
        match l1.erc20_allowance(token, spender).await {
            Ok(cur) if cur < amount => {
                if let Err(e) = l1
                    .send(token, crate::l1::L1Client::encode_approve(spender, amount), alloy_primitives::U256::ZERO)
                    .await
                {
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
        match l1
            .send(
                router,
                crate::l1::L1Client::encode_deposit(token, amount, shield32, commitment32),
                alloy_primitives::U256::ZERO,
            )
            .await
        {
            Ok(tx) => {
                note.l1_tx_hash = Some(tx.clone());
                let _ = note.persist(&dir);
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
                let service_proof = loop {
                    match load_claimable_deposit(&state.wallet, network.as_str(), Some(backup.to_string_lossy().to_string()), None, None).await {
                        Ok(DepositMaterial::Ready { proof, .. }) => break proof,
                        Ok(DepositMaterial::AlreadyClaimed { .. }) => {
                            return err_json(
                                "deposit settled but was already claimed before its wallet backup could be delivered".to_string(),
                                json!({ "gate": "deliver", "submitted": true, "l1TxHash": tx, "depositIndex": expected_index }),
                            );
                        }
                        Err((reason, extra)) if std::time::Instant::now() < deadline => {
                            tracing::info!("waiting to deliver deposit {} to psy-wallet: {}", expected_index, reason);
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            let _ = extra;
                        }
                        Err((reason, extra)) => {
                            return err_json(
                                format!("deposit settled on L1 but its wallet backup could not be delivered before timeout: {reason}"),
                                json!({ "gate": "deliver", "submitted": true, "l1TxHash": tx, "depositIndex": expected_index,
                                    "detail": extra, "note": "Do not deposit again. The recovery record is saved server-side; call retry_deposit_delivery after the relayer proof is ready." }),
                            );
                        }
                    }
                };
                let deposit_proof_raw = match state.wallet.build_shield_deposit_delivery_proof(&network, &note, &service_proof).await {
                    Ok(proof) => proof,
                    Err(e) => {
                        return err_json(
                            format!("deposit settled on L1 but the wallet-compatible deposit proof could not be built: {e:#}"),
                            json!({ "gate": "deliver", "submitted": true, "l1TxHash": tx, "depositIndex": expected_index,
                            "note": "Do not deposit again. The recovery record is saved server-side." }),
                        )
                    }
                };
                note.deposit_proof_json = Some(deposit_proof_raw.clone());
                let _ = note.persist(&dir);
                let events = match crate::nostr_delivery::build_deposit_backup_events(&identity.npub, &note, &deposit_proof_raw) {
                    Ok(events) => events,
                    Err(e) => {
                        return err_json(
                            format!("deposit settled on L1 but its wallet backup could not be encoded: {e:#}"),
                            json!({ "gate": "deliver", "submitted": true, "l1TxHash": tx, "depositIndex": expected_index }),
                        )
                    }
                };
                let relay = match state.wallet.nostr_relay(&network) {
                    Some(relay) => relay,
                    None => {
                        return err_json(
                            format!("deposit settled on L1 but network `{network}` has no nostr_relay_url"),
                            json!({ "gate": "deliver", "submitted": true, "l1TxHash": tx, "depositIndex": expected_index }),
                        )
                    }
                };
                match crate::nostr_delivery::publish_events(&relay, &events).await {
                    Ok(event_ids) => {
                        note.delivered = true;
                        note.nostr_event_ids = event_ids.clone();
                        let _ = note.persist(&dir);
                        ok_json(json!({
                            "status": "ok", "submitted": true, "delivered": true, "l1TxHash": tx,
                            "amountBaseUnits": a.amount_base_units, "token": a.token,
                            "expectedDepositIndex": expected_index, "nostrEventIds": event_ids,
                            "recipientNpub": identity.npub,
                            "next": "The deposit proof and secrets were delivered to psy-wallet. Claim it from the wallet claim list.",
                        }))
                    }
                    Err(e) => err_json(
                        format!("deposit settled on L1 but Nostr backup delivery failed: {e:#}"),
                        json!({ "gate": "deliver", "submitted": true, "l1TxHash": tx, "depositIndex": expected_index,
                            "relay": relay, "note": "Do not deposit again. The recovery record and proof are saved server-side; call retry_deposit_delivery." }),
                    ),
                }
            }
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, amount_nano_equivalent);
                tracing::info!("deposit claim secrets remain at {} (owner-side)", backup.display());
                err_json(format!("deposit failed on L1: {e:#}"), json!({ "gate": "l1" }))
            }
        }
    }

    #[tool(
        description = "Retry delivery of an already-submitted deposit to psy-wallet. Reads the persisted recovery record, reuses its saved proof when available (otherwise fetches it after the relayer proves the deposit), and republishes the proof/secrets pair to Nostr. It never submits another L1 deposit."
    )]
    async fn retry_deposit_delivery(&self, Parameters(a): Parameters<RetryDepositDeliveryArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        if let Err(e) = self
            .authorize_wallet(&network, &a.session, SELF_RECIPIENT, 0, "retry_deposit_delivery")
            .await
        {
            return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" }));
        }

        let dir = crate::keystore::keystore_dir();
        let path = match a.backup_path.as_deref() {
            Some(path) => std::path::PathBuf::from(path),
            None => match a.deposit_index {
                Some(index) => match crate::wallet::DepositNote::path_in(&dir, network.as_str(), index) {
                    Ok(path) => path,
                    Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "network" })),
                },
                None => {
                    return err_json(
                        "pass backup_path or deposit_index from the original deposit".to_string(),
                        json!({ "gate": "args" }),
                    )
                }
            },
        };
        let mut note = match crate::wallet::DepositNote::load(&path) {
            Ok(note) => note,
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "load" })),
        };
        if let Some(saved_network) = note.network.as_deref() {
            if saved_network != network.as_str() {
                return err_json(
                    format!("deposit backup belongs to network `{saved_network}`, not `{network}`"),
                    json!({ "gate": "network", "backupNetwork": saved_network, "network": network.as_str() }),
                );
            }
        } else {
            note.network = Some(network.as_str().to_string());
        }
        if note.delivered {
            return ok_json(json!({
                "status": "ok", "alreadyDelivered": true,
                "depositIndex": note.expected_deposit_index,
                "nostrEventIds": note.nostr_event_ids,
            }));
        }

        let deposit_proof_raw = if let Some(proof) = note.deposit_proof_json.clone() {
            proof
        } else {
            let loaded = match load_claimable_deposit(
                &state.wallet,
                network.as_str(),
                Some(path.to_string_lossy().to_string()),
                None,
                a.services_url.as_deref(),
            )
            .await
            {
                Ok(material) => material,
                Err((reason, extra)) => return err_json(reason, extra),
            };
            let DepositMaterial::Ready { proof, .. } = loaded else {
                return ok_json(json!({ "status": "ok", "alreadyClaimed": true, "depositIndex": note.expected_deposit_index }));
            };
            let proof = match state.wallet.build_shield_deposit_delivery_proof(&network, &note, &proof).await {
                Ok(proof) => proof,
                Err(e) => return err_json(format!("could not build wallet-compatible deposit proof: {e:#}"), json!({ "gate": "deliver" })),
            };
            note.deposit_proof_json = Some(proof.clone());
            if let Err(e) = note.persist(&dir) {
                return err_json(format!("could not persist deposit proof before delivery: {e:#}"), json!({ "gate": "persist" }));
            }
            proof
        };

        let identity = match state.wallet.receive_identity(&network).await {
            Ok(identity) => identity,
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "wallet" })),
        };
        let events = match crate::nostr_delivery::build_deposit_backup_events(&identity.npub, &note, &deposit_proof_raw) {
            Ok(events) => events,
            Err(e) => return err_json(format!("deposit backup encoding failed: {e:#}"), json!({ "gate": "deliver" })),
        };
        let relay = match state.wallet.nostr_relay(&network) {
            Some(relay) => relay,
            None => return err_json(format!("network `{network}` has no nostr_relay_url"), json!({ "gate": "deliver" })),
        };
        match crate::nostr_delivery::publish_events(&relay, &events).await {
            Ok(event_ids) => {
                note.delivered = true;
                note.nostr_event_ids = event_ids.clone();
                if let Err(e) = note.persist(&dir) {
                    return err_json(
                        format!("delivery succeeded but its status could not be persisted: {e:#}"),
                        json!({ "gate": "persist", "delivered": true, "nostrEventIds": event_ids }),
                    );
                }
                ok_json(json!({
                    "status": "ok", "delivered": true,
                    "depositIndex": note.expected_deposit_index,
                    "nostrEventIds": event_ids,
                    "recipientNpub": identity.npub,
                }))
            }
            Err(e) => err_json(
                format!("Nostr backup delivery failed: {e:#}"),
                json!({ "gate": "deliver", "relay": relay, "note": "The saved proof can be retried with retry_deposit_delivery." }),
            ),
        }
    }

    #[tool(
        description = "Claim a deposit that the bridge relayer has proved onto Psy, folding it into this wallet's balance. Reads the claim secrets saved by `deposit`, fetches the merkle proof from psy-services, verifies it locally, proves inclusion and claims. Amount-0 gated: claiming only folds in funds already addressed to this wallet."
    )]
    async fn claim_deposit(&self, Parameters(a): Parameters<ClaimDepositArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        if let Err(e) = self.authorize_wallet(&network, &a.session, SELF_RECIPIENT, 0, "claim_deposit").await {
            return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" }));
        }
        let loaded = match load_claimable_deposit(
            &state.wallet,
            network.as_str(),
            a.backup_path.clone(),
            a.deposit_index,
            a.services_url.as_deref(),
        )
        .await
        {
            Ok(m) => m,
            Err((reason, extra)) => return err_json(reason, extra),
        };
        let DepositMaterial::Ready { note, proof } = loaded else {
            return ok_json(json!({ "status": "ok", "alreadyClaimed": true,
                                   "note": "This deposit was already claimed." }));
        };

        match state.wallet.claim_shield_deposit(&network, &note, &proof).await {
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

    #[tool(
        description = "Claim private notes sent to this wallet's shielded address. With no arguments it claims everything psy-services is holding for this wallet (the service subscribes to the relay for us). Pass `note` to claim one specific delivered note instead."
    )]
    async fn private_claim(&self, Parameters(a): Parameters<PrivateClaimArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        // Amount 0: claiming folds in funds already addressed to us, it does not
        // spend — same convention claim_all uses.
        if let Err(e) = self.authorize_wallet(&network, &a.session, SELF_RECIPIENT, 0, "private_claim").await {
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
            return match state.wallet.claim_private_note(&network, &note, contract).await {
                Ok(leaf) => ok_json(json!({
                    "status": "ok", "submitted": true, "claimed": 1,
                    "claimedNano": note.amount, "token": a.token, "txHash": leaf,
                })),
                Err(e) => err_json(format!("private claim failed: {e:#}"), json!({ "gate": "execute" })),
            };
        }

        // Otherwise drain whatever the service is holding for us.
        let identity = match state.wallet.receive_identity(&network).await {
            Ok(i) => i,
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "wallet" })),
        };
        let services = match resolve_agent_url(a.services_url.as_deref(), || network_services_url(&state.wallet, &network)) {
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
                Err(e) => {
                    failures.push(json!({ "error": format!("{e:#}") }));
                    continue;
                }
            };
            match state.wallet.claim_private_note(&network, &note, contract).await {
                Ok(_) => {
                    claimed += 1;
                    total += note.amount
                }
                Err(e) => failures.push(json!({ "nullifier": note.nullifier, "error": format!("{e:#}") })),
            }
        }
        ok_json(json!({
            "status": "ok", "claimed": claimed, "claimedNano": total,
            "found": notes.len(), "failed": failures, "token": a.token, "npub": identity.npub,
        }))
    }

    #[tool(
        description = "Fuse public claims, private-note claims and shield-deposit claims into ONE UPS proof / one fee. The chain primitive has always accepted mixed items; this is the tool that builds that mixed batch. Pass any combination of public_claims, deposit_indices / backup_paths, private_notes, or drain_private. Each present category is policy-gated as simple_claim / claim_deposit / private_claim (amount 0 — claiming folds in funds already addressed to this wallet)."
    )]
    async fn claim_batch(&self, Parameters(a): Parameters<ClaimBatchArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        let wants_public = !a.public_claims.is_empty();
        let wants_deposit = !a.deposit_indices.is_empty() || !a.backup_paths.is_empty();
        let wants_private = !a.private_notes.is_empty() || a.drain_private;
        let wants_transfer = !a.transfers.is_empty();
        let wants_withdraw = !a.withdraws.is_empty();
        if !wants_public && !wants_deposit && !wants_private && !wants_transfer && !wants_withdraw {
            return err_json(
                "nothing to claim — pass public_claims, transfers, withdraws, deposit_indices/backup_paths, private_notes, and/or drain_private=true"
                    .to_string(),
                json!({ "gate": "args" }),
            );
        }
        // Gate each constituent method the batch will actually perform, so a
        // policy that allows simple_claim but not claim_deposit cannot sneak a
        // deposit into the same UPS. Amount 0: claiming does not spend.
        if wants_public {
            if let Err(e) = self.authorize_wallet(&network, &a.session, SELF_RECIPIENT, 0, "simple_claim").await {
                return err_json(
                    format!("policy denied public claims: {e:#}"),
                    json!({ "gate": "policy", "method": "simple_claim" }),
                );
            }
        }
        if wants_deposit {
            if let Err(e) = self.authorize_wallet(&network, &a.session, SELF_RECIPIENT, 0, "claim_deposit").await {
                return err_json(
                    format!("policy denied deposit claims: {e:#}"),
                    json!({ "gate": "policy", "method": "claim_deposit" }),
                );
            }
        }
        if wants_private {
            if let Err(e) = self.authorize_wallet(&network, &a.session, SELF_RECIPIENT, 0, "private_claim").await {
                return err_json(
                    format!("policy denied private claims: {e:#}"),
                    json!({ "gate": "policy", "method": "private_claim" }),
                );
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
                return err_json(
                    format!("unknown token {}: refusing to guess its scale for the policy gate", spec.token),
                    json!({ "gate": "args" }),
                );
            };
            match self
                .authorize_wallet(&network, &a.session, &spec.to_user_id.to_string(), charge, "simple_transfer")
                .await
            {
                Ok(auth) => spent_auths.push((auth, charge)),
                Err(e) => {
                    refund_all(&mut spent_auths);
                    return err_json(
                        format!("policy denied a transfer leg: {e:#}"),
                        json!({ "gate": "policy", "method": "simple_transfer" }),
                    );
                }
            }
        }
        const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";
        for spec in &a.withdraws {
            if spec.l1_recipient.trim().eq_ignore_ascii_case(ZERO_ADDR) {
                refund_all(&mut spent_auths);
                return err_json(
                    "a withdraw leg has the zero L1 recipient — the funds would burn into an address nobody can recover. Nothing was submitted."
                        .to_string(),
                    json!({ "gate": "args" }),
                );
            }
            let Some(charge) = nano_equivalent(&spec.token, spec.amount_nano) else {
                refund_all(&mut spent_auths);
                return err_json(
                    format!("unknown token {}: refusing to guess its scale for the policy gate", spec.token),
                    json!({ "gate": "args" }),
                );
            };
            match self.authorize_wallet(&network, &a.session, &spec.l1_recipient, charge, "withdraw").await {
                Ok(auth) => spent_auths.push((auth, charge)),
                Err(e) => {
                    refund_all(&mut spent_auths);
                    return err_json(
                        format!("policy denied a withdraw leg: {e:#}"),
                        json!({ "gate": "policy", "method": "withdraw" }),
                    );
                }
            }
        }

        let mut public_items: Vec<(u64, u64)> = Vec::new();
        for spec in &a.public_claims {
            let Some(contract) = contract_for(&spec.token) else {
                refund_all(&mut spent_auths);
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
                None => match network_l1_token(&state.wallet, &network, &spec.token) {
                    Some(t) => t,
                    None => {
                        refund_all(&mut spent_auths);
                        return err_json(
                            format!("no default L1 token address known for {} — pass l1_token_address", spec.token),
                            json!({ "gate": "config" }),
                        );
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
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                }),
                contract_id: contract,
            });
        }

        let mut deposit_notes: Vec<crate::wallet::DepositNote> = Vec::new();
        let mut deposit_proofs: Vec<serde_json::Value> = Vec::new();
        let mut skipped_claimed: Vec<u64> = Vec::new();
        let mut deposit_lookups: Vec<(Option<String>, Option<u64>)> = a.backup_paths.iter().map(|p| (Some(p.clone()), None)).collect();
        deposit_lookups.extend(a.deposit_indices.iter().copied().map(|i| (None, Some(i))));
        for (backup_path, deposit_index) in deposit_lookups {
            match load_claimable_deposit(&state.wallet, network.as_str(), backup_path, deposit_index, a.services_url.as_deref()).await {
                Ok(DepositMaterial::Ready { note, proof }) => {
                    deposit_notes.push(note);
                    deposit_proofs.push(proof);
                }
                Ok(DepositMaterial::AlreadyClaimed { note }) => skipped_claimed.push(note.expected_deposit_index),
                Err((reason, extra)) => {
                    refund_all(&mut spent_auths);
                    return err_json(reason, extra);
                }
            }
        }

        let mut private_parsed: Vec<(crate::wallet::IncomingPrivateNote, u64)> = Vec::new();
        let mut private_failures: Vec<serde_json::Value> = Vec::new();
        for spec in &a.private_notes {
            let Some(contract) = contract_for(&spec.token) else {
                refund_all(&mut spent_auths);
                return err_json(format!("unknown token {}", spec.token), json!({ "gate": "args" }));
            };
            match crate::wallet::IncomingPrivateNote::parse(&spec.note) {
                Ok(n) => private_parsed.push((n, contract)),
                Err(e) => private_failures.push(json!({ "error": format!("{e:#}") })),
            }
        }

        if a.drain_private {
            let Some(contract) = contract_for(&a.private_token) else {
                refund_all(&mut spent_auths);
                return err_json(format!("unknown token {}", a.private_token), json!({ "gate": "args" }));
            };
            let identity = match state.wallet.receive_identity(&network).await {
                Ok(i) => i,
                Err(e) => {
                    refund_all(&mut spent_auths);
                    return err_json(format!("{e:#}"), json!({ "gate": "wallet" }));
                }
            };
            let services = match resolve_agent_url(a.services_url.as_deref(), || network_services_url(&state.wallet, &network)) {
                Ok(u) => u,
                Err(e) => {
                    refund_all(&mut spent_auths);
                    return err_json(e, json!({ "gate": "url" }));
                }
            };
            let notes = match crate::nostr_delivery::fetch_notes(&services, &identity.npub, true).await {
                Ok(n) => n,
                Err(e) => {
                    refund_all(&mut spent_auths);
                    return err_json(format!("could not fetch notes: {e:#}"), json!({ "gate": "fetch" }));
                }
            };
            let secret = match nostr::SecretKey::parse(&identity.nsec) {
                Ok(k) => k,
                Err(e) => {
                    refund_all(&mut spent_auths);
                    return err_json(format!("bad derived Nostr key: {e}"), json!({ "gate": "wallet" }));
                }
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

        let deposits: Vec<(&crate::wallet::DepositNote, &serde_json::Value)> =
            deposit_notes.iter().zip(deposit_proofs.iter()).map(|(n, p)| (n, p)).collect();
        // Pre-check every private note's owner BEFORE building the batch: a
        // permanently-unclaimable note (e.g. one sent to a reversed/mangled
        // shield by an old buggy sender) would otherwise fail the WHOLE
        // all-or-nothing proof at prove time — poisoning every future drain.
        // Skip the dead ones into `failed` and claim the rest.
        let user = state.wallet.require_user(&network).await.ok();
        let identity_rcv = state.wallet.receive_identity(&network).await.ok();
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

        if public_items.is_empty() && transfer_items.is_empty() && withdraw_legs.is_empty() && deposits.is_empty() && privates.is_empty() {
            refund_all(&mut spent_auths);
            return ok_json(json!({
                "submitted": false,
                "alreadyClaimed": skipped_claimed,
                "failed": private_failures,
                "note": "Nothing left to fold in. Deposits were already claimed and/or private notes failed to parse.",
            }));
        }

        match state
            .wallet
            .claim_batch_mixed(
                &network,
                spent_auths.first().and_then(|(auth, _)| auth.user_id),
                public_items.clone(),
                transfer_items.clone(),
                withdraw_legs.clone(),
                deposits,
                privates,
            )
            .await
        {
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

    #[tool(
        description = "Withdraw to an Ethereum address: burns the amount on Psy and the bridge relayer settles the L1 leg, so the agent needs no Ethereum gas. Policy-gated at the amount like any other spend."
    )]
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
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        let Some(charge) = nano_equivalent(&a.token, a.amount_nano) else {
            return err_json(
                format!("unknown token {}: refusing to guess its scale for the policy gate", a.token),
                json!({ "gate": "args" }),
            );
        };
        let auth = match self.authorize_wallet(&network, &a.session, &a.l1_recipient, charge, "withdraw").await {
            Ok(auth) => auth,
            Err(e) => return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy" })),
        };
        let Some(contract) = contract_for(&a.token) else {
            self.policy.lock().unwrap().refund(&auth, charge);
            return err_json(format!("unknown token {}", a.token), json!({ "gate": "args" }));
        };
        let token_addr = match a.l1_token_address.clone() {
            Some(t) => t,
            None => match network_l1_token(&state.wallet, &network, &a.token) {
                Some(t) => t,
                None => {
                    self.policy.lock().unwrap().refund(&auth, charge);
                    return err_json(
                        format!("no default L1 token address known for {} — pass l1_token_address", a.token),
                        json!({ "gate": "config" }),
                    );
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
        let execution = match auth.user_id {
            Some(user_id) => {
                state
                    .wallet
                    .withdraw_for(
                        &network,
                        user_id,
                        a.dest_chain_index,
                        &token_addr,
                        a.amount_nano,
                        &a.l1_recipient,
                        nonce,
                        contract,
                    )
                    .await
            }
            None => Err(anyhow::anyhow!("authorization did not bind a wallet identity")),
        };
        match execution {
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

    #[tool(
        description = "Show how to pay this agent PRIVATELY: its shielded address (which owns the note) and its Nostr npub (where the note is delivered). A payer needs BOTH — a note sent without delivery is unclaimable. The Nostr secret never leaves the server."
    )]
    async fn get_receive_address(&self, Parameters(a): Parameters<NetworkArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        match state.wallet.receive_identity(&network).await {
            Ok(id) => ok_json(json!({
                "status": "ok",
                "shieldedAddress": id.shield_address_base58,
                "shieldedAddressHex": id.shield_address_hex,
                "npub": id.npub,
                "note": "Give BOTH to the payer: the shielded address owns the note, the npub receives it.",
            })),
            Err(e) => err_json(format!("{e:#}"), json!({ "gate": "wallet" })),
        }
    }
}
