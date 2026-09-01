use super::*;
use crate::wallet_network;

#[tool_router(router = private_tools_router, vis = "pub(crate)")]
impl PsyWalletServer {
    #[tool(
        description = "Fund this wallet from the network's faucet service. Asks the hosted faucet to send test PSY to the loaded user; the grant then arrives as a claimable, so follow with claim_all from the returned operator id. Read-only on the agent's side — it spends nothing and needs no session."
    )]
    async fn claim_faucet(&self, Parameters(a): Parameters<FaucetArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        let user = match state.wallet.current_user(&network).await {
            Some(u) => u,
            None => return err_json("no wallet loaded — call create_wallet first".to_string(), json!({ "gate": "wallet" })),
        };
        let url = match resolve_agent_url(a.faucet_url.as_deref(), || network_faucet_url(&state.wallet, &network)) {
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

    #[tool(
        description = "Send a private transfer to a shielded address: settles on chain, proves the note's inclusion, and delivers the gift-wrapped note to the recipient over Nostr so they can claim it. Requires the recipient's npub — without delivery the funds are debited but unclaimable. Set dry_run=true to derive the note and inspect the exact call without settling."
    )]
    async fn private_transfer(&self, Parameters(a): Parameters<PrivateTransferArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        if let Some(user) = state.wallet.current_user(&network).await {
            self.policy.lock().unwrap().set_current_wallet(network.as_str(), user.user_id);
        }
        // Policy gate below the model (this spends, so gate at the amount).
        let Some(charge) = nano_equivalent(&a.token, a.amount_nano) else {
            return err_json(
                format!("unknown token {}: refusing to guess its scale for the policy gate", a.token),
                json!({ "gate": "args" }),
            );
        };
        if a.amount_nano == 0 {
            // A zero note can never be claimed and would fail in-circuit.
            return err_json("a private transfer of 0 is a no-op — pass a positive amount", json!({ "gate": "args" }));
        }
        let auth = match self
            .authorize_wallet(&network, &a.session, &a.to_shielded_address, charge, "private_transfer")
            .await
        {
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
            return match state
                .wallet
                .prepare_private_transfer(&network, &a.to_shielded_address, a.amount_nano, contract)
                .await
            {
                Ok(p) => ok_json(json!({
                    "dryRun": true, "submitted": false,
                    "toShielded": a.to_shielded_address, "amount": a.amount_nano, "token": a.token,
                    "noteCommitment": p.note_commitment, "callInputs": p.call_inputs,
                })),
                Err(e) => err_json(format!("prepare failed: {e:#}"), json!({ "gate": "prepare" })),
            };
        }

        // The relay must follow the NETWORK, not a hardcoded staging default:
        // a note delivered to the wrong network's relay is unclaimable. An
        // explicit `relay` argument still wins (it goes through the same
        // SSRF guard); otherwise use only the network's configured relay.
        let relays = match a.relay.as_deref() {
            Some(explicit) => match guard_outbound_url(explicit) {
                Ok(()) => vec![explicit.to_string()],
                Err(e) => return err_json(e, json!({ "gate": "url" })),
            },
            None => {
                match state.wallet.nostr_relay(&network) {
                    Some(configured) => vec![configured],
                    None => return err_json(
                        format!("network `{network}` has no non-empty `nostr_relay_url` in config.json"),
                        json!({ "gate": "config", "field": "nostr_relay_url" }),
                    ),
                }
            }
        };
        // Prepare, persist the recovery material, and only THEN settle. A note
        // that settles but is not delivered is debited-and-unclaimable, and
        // the secrets that recover it must already be on the owner's disk —
        // never in a tool result (the agent can read those) and never only in
        // the model's context (which gets compacted away).
        let prepared = match state
            .wallet
            .prepare_private_transfer(&network, &a.to_shielded_address, a.amount_nano, contract)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                self.policy.lock().unwrap().refund(&auth, charge);
                return err_json(format!("prepare failed: {e:#}"), json!({ "gate": "prepare" }));
            }
        };
        let dir = crate::keystore::keystore_dir();
        let mut recovery = crate::wallet::PrivateNoteRecovery {
            network: Some(network.as_str().to_string()),
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
                    json!({ "gate": "persist" }),
                );
            }
        };
        tracing::info!("private-note recovery material persisted at {} (owner-side)", recovery_path.display());
        let settlement = match auth.user_id {
            Some(user_id) => {
                state
                    .wallet
                    .settle_private_transfer_for(&network, user_id, prepared, NOTE_ROOT_SLOT)
                    .await
            }
            None => Err(anyhow::anyhow!("authorization did not bind a wallet identity")),
        };
        let settled = match settlement {
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

        // The current wallet protocol requires a signed proof event paired with
        // an encrypted secrets event under one backup_id. A relay ACK alone is
        // not delivery unless both events were accepted.
        let normalized_note_proof = match crate::wallet::normalize_private_note_proof_envelope(&settled.note_proof_json, contract) {
            Ok(proof) => proof,
            Err(e) => {
                return err_json(
                    format!("settled on chain but the proof packet could not be normalized for wallet delivery: {e:#}"),
                    json!({ "gate": "deliver", "submitted": true, "txHash": settled.leaf_hash,
                        "note": "Do NOT call private_transfer again. Re-deliver the saved recovery record after fixing the proof packet." }),
                );
            }
        };
        recovery.note_proof_json = Some(normalized_note_proof.clone());
        let _ = recovery.persist(&dir);
        let events = match crate::nostr_delivery::build_private_transfer_events(
            &a.recipient_npub,
            a.amount_nano,
            contract,
            &settled.leaf_hash,
            &recovery.note_commitment,
            &normalized_note_proof,
            &recovery.nullifier_secret,
            &recovery.note_secret,
            &settled.prepared.owner,
            &settled.nullifier_hash,
        ) {
            Ok(w) => w,
            Err(e) => {
                return err_json(
                    format!("settled on chain but the note could not be wrapped for delivery: {e:#}"),
                    json!({ "gate": "deliver", "submitted": true, "txHash": settled.leaf_hash,
                        "note": "The funds are debited and the recovery material is safe on the server host (owner-side; path in the server log). Do NOT call private_transfer again: that would submit and debit a second payment. Re-deliver this saved recovery record instead." }),
                )
            }
        };

        let mut failures = Vec::new();
        for relay in &relays {
            match crate::nostr_delivery::publish_events(relay, &events).await {
                Ok(event_ids) => {
                    recovery.delivered = true;
                    let _ = recovery.persist(&dir);
                    return ok_json(json!({
                        "status": "ok", "submitted": true, "delivered": true,
                        "toShielded": a.to_shielded_address, "amount": a.amount_nano, "token": a.token,
                        "txHash": settled.leaf_hash, "checkpointId": settled.checkpoint_id,
                        "nostrEventIds": event_ids, "chunks": events.len(), "relay": relay,
                        "relayAttempts": failures.len() + 1,
                        "note": "Settled and delivered. The recipient can now claim it.",
                    }));
                }
                Err(e) => failures.push(format!("{relay}: {e:#}")),
            }
        }
        err_json(
            format!(
                "settled on chain but Nostr delivery failed on all relays: {}. The recipient cannot claim until the note reaches them.",
                failures.join("; ")
            ),
            json!({ "gate": "deliver", "submitted": true, "txHash": settled.leaf_hash,
                    "relays": relays,
                    "note": "The funds are debited and the recovery material is safe on the server host (owner-side; path in the server log)." }),
        )
    }
}
