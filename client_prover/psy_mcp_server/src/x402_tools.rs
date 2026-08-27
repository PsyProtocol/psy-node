use super::*;
use crate::wallet_network;

#[tool_router(router = x402_tools_router, vis = "pub(crate)")]
impl PsyWalletServer {
    #[tool(
        description = "Fetch a paywalled URL, paying for it if asked. Requests the resource; on HTTP 402 it reads the challenge, pays the demanded amount on Psy (policy-gated like any other spend), and retries with the X-PAYMENT proof. Set dry_run=true to see what would be paid without paying. This is the whole x402 loop in one call."
    )]
    async fn x402_fetch(&self, Parameters(a): Parameters<X402FetchArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.psy_network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
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
        if let Err(e) = self.check_wallet_can_act(&network, &a.session, "x402_fetch").await {
            return err_json(format!("policy denied: {e:#}"), json!({ "gate": "policy", "paid": false }));
        }
        if let Err(e) = guard_outbound_url(&a.url) {
            return err_json(e, json!({ "gate": "url" }));
        }
        let client = match reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build() {
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
            Err(e) => {
                return err_json(
                    format!("the server asked for payment but its 402 body could not be read: {e}"),
                    json!({ "gate": "challenge", "body": truncate(&challenge_raw) }),
                )
            }
        };
        let x402_network = a.network.clone().unwrap_or_else(|| default_x402_network(&network));
        let req = match crate::x402::select_requirement(&challenge.accepts, &x402_network) {
            Ok(r) => r,
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "challenge" })),
        };
        let (amount, recipient) = match (req.amount(), req.recipient_user_id()) {
            (Ok(a2), Ok(r2)) => (a2, r2),
            (Err(e), _) | (_, Err(e)) => return err_json(format!("unusable 402 challenge: {e:#}"), json!({ "gate": "challenge" })),
        };
        let token = req.token_symbol();
        let Some(contract) = contract_for(&token) else {
            return err_json(
                format!("the 402 challenge names an unknown asset {token} — refusing to guess its scale"),
                json!({ "gate": "challenge" }),
            );
        };

        // Never pay more than the caller sanctioned, even if policy would allow
        // it: an agent that follows links can be led to an expensive resource.
        if let Some(cap) = a.max_amount_nano {
            if amount > cap {
                return err_json(
                    format!("the resource costs {amount} but max_amount_nano was {cap} — not paying"),
                    json!({ "gate": "budget", "required": amount, "cap": cap }),
                );
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
                json!({ "gate": "challenge" }),
            );
        };
        // Same gate as a direct transfer — this is the point of the wallet.
        // An x402 payee has two names an owner might have allowlisted: the user
        // id its challenge demands payment to, and the host that demanded it.
        // Both come from THIS response, so either one identifies this seller.
        let auth = match self
            .authorize_wallet_aliases(&network, &a.session, &[&recipient.to_string(), &a.url], charge, "x402_fetch")
            .await
        {
            Ok(auth) => auth,
            Err(e) => {
                return err_json(
                    format!("policy denied: {e:#}"),
                    json!({ "gate": "policy", "required": amount, "toUserId": recipient }),
                )
            }
        };
        let transfer = match auth.user_id {
            Some(user_id) => state.wallet.transfer_for(&network, user_id, recipient, amount, contract).await,
            None => Err(anyhow::anyhow!("authorization did not bind a wallet identity")),
        };
        let tx_hash = match transfer {
            Ok(h) => h,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, charge);
                return err_json(format!("payment failed: {e:#}"), json!({ "gate": "execute" }));
            }
        };
        let payer = state.wallet.current_user(&network).await.map(|u| u.user_id).unwrap_or(0);
        let payload = crate::x402::PaymentPayload::new(
            &x402_network,
            crate::x402::PsyPaymentProof {
                tx_hash: tx_hash.clone(),
                payer_user_id: payer,
                recipient_user_id: recipient,
                amount_nano: amount,
                contract_id: contract,
                resource: req.resource.clone(),
            },
        );
        let header = match payload.to_header() {
            Ok(h) => h,
            Err(e) => {
                return err_json(
                    format!("paid {amount} (tx {tx_hash}) but could not build the X-PAYMENT header: {e:#}"),
                    json!({ "gate": "header", "paid": true, "txHash": tx_hash }),
                )
            }
        };

        // Paid but not yet served: report the receipt either way so the caller
        // can retry by hand rather than pay twice.
        let retry = client.get(&a.url).header("X-PAYMENT", &header).send().await;
        match retry {
            Ok(r) => {
                let status = r.status().as_u16();
                let settled = r.headers().get("x-payment-response").and_then(|v| v.to_str().ok()).map(String::from);
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
                json!({ "gate": "retry", "paid": true, "txHash": tx_hash, "xPayment": header }),
            ),
        }
    }

    #[tool(
        description = "Verify an X-PAYMENT header someone sent you, for an agent that SELLS access. Checks the claimed payment against the chain via psy-services — that it exists, went to you, and covers the price — so a resource server can settle without running a prover."
    )]
    async fn x402_verify(&self, Parameters(a): Parameters<X402VerifyArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.psy_network.as_deref());
        let payload = match crate::x402::PaymentPayload::from_header(&a.x_payment) {
            Ok(p) => p,
            Err(e) => return err_json(format!("{e:#}"), json!({ "gate": "decode", "valid": false })),
        };
        let proof = &payload.payload;

        // Fail CLOSED on the recipient check: with no wallet loaded there is
        // no "you" for the payment to have been made to, and skipping the
        // check would validate any payment between any two strangers.
        let me = match state.wallet.current_user(&network).await.map(|u| u.user_id) {
            Some(me) => me,
            None => {
                return err_json(
                    "no wallet is loaded, so there is no recipient to verify against — load the selling wallet first",
                    json!({ "gate": "recipient", "valid": false }),
                )
            }
        };
        if proof.recipient_user_id != me {
            return err_json(
                format!(
                    "this payment was made to Psy-{:08}, not to this wallet (Psy-{:08})",
                    proof.recipient_user_id, me
                ),
                json!({ "gate": "recipient", "valid": false }),
            );
        }
        if let Some(price) = a.expected_amount_nano {
            if proof.amount_nano < price {
                return err_json(
                    format!("paid {} but the resource costs {price}", proof.amount_nano),
                    json!({ "gate": "amount", "valid": false, "paid": proof.amount_nano, "required": price }),
                );
            }
        }

        // The claim is only worth what the chain says: look the payer's activity
        // up and find this transaction. A payment settles seconds before the
        // indexer ingests it, so a fresh receipt is not proof of fraud — poll
        // briefly (bounded) before refusing, or every honest just-paid caller
        // gets bounced back into paying twice.
        let base = match resolve_agent_url(a.services_url.as_deref(), || network_services_url(&state.wallet, &network)) {
            Ok(u) => u,
            Err(e) => return err_json(e, json!({ "gate": "url" })),
        };
        let url = format!(
            "{}/api/v1/get/user/activity?user_id={}&limit=100",
            base.trim_end_matches('/'),
            proof.payer_user_id
        );
        let wait_secs = a.settlement_wait_seconds.unwrap_or(90).min(600);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
        let matched = loop {
            let body: serde_json::Value = match reqwest::Client::new().get(&url).send().await {
                Ok(r) => match r.json().await {
                    Ok(v) => v,
                    Err(e) => {
                        return err_json(
                            format!("indexer returned a non-JSON response: {e}"),
                            json!({ "gate": "indexer", "valid": false }),
                        )
                    }
                },
                Err(e) => return err_json(format!("indexer unreachable: {e}"), json!({ "gate": "indexer", "valid": false })),
            };
            let items = body
                .get("data")
                .and_then(|d| d.get("items"))
                .and_then(|i| i.as_array())
                .cloned()
                .unwrap_or_default();
            // The hash a payer holds is the end-user-leaf-hash its wallet
            // returned; the indexer records the endcap CONTENT hash — they
            // never match for a fresh payment. Exact hash match is accepted
            // when it happens, but the chain-truth match is the FIELDS: a
            // settled transfer from this payer to this recipient covering the
            // amount. Newest first, so a fresh payment cannot be satisfied by
            // an ancient one at a different price by accident.
            let hash_match = items
                .iter()
                .find(|it| it.get("tx_hash").and_then(|h| h.as_str()) == Some(proof.tx_hash.as_str()))
                .cloned();
            // A field match can refer to an older payment with the same payer,
            // recipient and amount. Only stop polling when that row is fresh;
            // otherwise wait for the just-submitted payment to be indexed.
            let latest = state.wallet.latest_checkpoint(&network).await.ok();
            let max_age = a.max_age_checkpoints.unwrap_or(240);
            let field_match = items
                .iter()
                .find(|it| {
                    it.get("recipient_user_id").and_then(|r| r.as_u64()) == Some(proof.recipient_user_id)
                        && it.get("sender_user_id").and_then(|r| r.as_u64()) == Some(proof.payer_user_id)
                        && it
                            .get("amount")
                            .and_then(|a2| a2.as_str())
                            .and_then(|s2| s2.parse::<u64>().ok())
                            .map(|v| v >= proof.amount_nano)
                            .unwrap_or(false)
                        && check_payment_age(it.get("checkpoint_id").and_then(|c| c.as_u64()), latest, max_age).is_ok()
                })
                .cloned();
            let matched = hash_match.or(field_match);
            if matched.is_some() || std::time::Instant::now() >= deadline {
                break matched;
            }
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        };
        match matched.as_ref() {
            Some(it) => {
                let onchain_amount = it.get("amount").and_then(|a2| a2.as_str()).and_then(|s| s.parse::<u64>().ok());
                let onchain_recipient = it.get("recipient_user_id").and_then(|r| r.as_u64());
                // Trust the chain over the header: a payload can claim anything.
                if onchain_recipient != Some(proof.recipient_user_id) || onchain_amount.map(|v| v < proof.amount_nano).unwrap_or(true) {
                    return err_json(
                        "the transaction exists but does not match the claimed recipient/amount".to_string(),
                        json!({ "gate": "mismatch", "valid": false, "onchain": it }),
                    );
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
                let latest = state.wallet.latest_checkpoint(&network).await.ok();
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
                let consume_key = format!("{}:{row_hash}", network.as_str());
                let consumed = match self.consumed_payments.consume(consume_key) {
                    Ok(consumed) => consumed,
                    Err(e) => {
                        return err_json(
                            format!("could not durably record payment consumption: {e:#}"),
                            json!({ "gate": "replay", "valid": false, "retryable": true }),
                        )
                    }
                };
                if !consumed {
                    return err_json(
                        "this settled payment was already used to unlock a resource — a replay, not a new payment",
                        json!({ "gate": "replay", "valid": false }),
                    );
                }
                ok_json(json!({
                    "status": "ok", "valid": true,
                    "txHash": proof.tx_hash, "payerUserId": proof.payer_user_id,
                    "recipientUserId": proof.recipient_user_id,
                    "amount": onchain_amount, "checkpointId": it.get("checkpoint_id"),
                    "resource": proof.resource,
                }))
            }
            None => err_json(
                format!(
                    "no settled transaction {} found for Psy-{:08} — it may still be settling, or the claim is false",
                    proof.tx_hash, proof.payer_user_id
                ),
                json!({ "gate": "unsettled", "valid": false }),
            ),
        }
    }
}
