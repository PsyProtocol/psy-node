use super::*;
use crate::wallet_network;

#[tool_router(router = wallet_tools_router, vis = "pub(crate)")]
impl PsyWalletServer {
    // ── Owner / policy ────────────────────────────────────────────────

    #[tool(
        description = "Create a wallet: generate a fresh Psy key and register it on-chain, or load an existing private key. Generated keys are durably backed up to the keystore (owner-readable file; the key itself is never returned). Also creates a spending policy the agent draws sessions from."
    )]
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
        if let Some(what) = self.policy.lock().unwrap().creation_widens(&requested, &a.allowed_recipients, &[]) {
            if let Err(e) = owner_gate_for_widening(a.owner_token.as_deref(), &what) {
                return err_json(e, json!({ "gate": "owner", "widens": what, "policyCreated": false }));
            }
        }
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
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
                match state.wallet.load(&network, &pk).await {
                    Ok(l) => l,
                    Err(e) => return err_json(e, json!({})),
                }
            } else if let Some(file) = a.key_file.as_deref() {
                let backup = match keystore::load_key_file(file) {
                    Ok(b) => b,
                    Err(e) => return err_json(format!("mode=load: {e:#}"), json!({ "gate": "args" })),
                };
                match state.wallet.load_from_backup(&network, &backup).await {
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
            let (pk, fp) = match state.wallet.generate_keypair(&network).await {
                Ok(kp) => kp,
                Err(e) => return err_json(e, json!({})),
            };
            // Funds-safety invariant: the key is durably backed up BEFORE the
            // chain learns the identity. A crash after this write leaves a
            // harmless stray file; the reverse order could leave an on-chain
            // wallet whose key nobody has. See keystore.rs.
            let backup_path = match keystore::persist_generated_key(&pk, &fp, network.as_str()) {
                Ok(p) => p,
                Err(e) => {
                    return err_json(
                        format!("key backup failed — refusing to register an unrecoverable wallet: {e:#}"),
                        json!({ "hint": format!("set {} to a writable directory", keystore::KEYSTORE_DIR_ENV) }),
                    )
                }
            };
            match state.wallet.register(&network, &pk).await {
                Ok(l) => (l, Some(backup_path)),
                Err(e) => {
                    tracing::info!(
                        "generated key backed up at {} (owner-side; not disclosed to the agent)",
                        backup_path.display()
                    );
                    return err_json(
                        format!("registration failed: {e:#}"),
                        json!({
                            "note": "The generated key is safely backed up on the server host (path printed to the server log, for the OWNER); retry create_wallet once the chain is reachable."
                        }),
                    );
                }
            }
        };
        if let Some(path) = key_backup_path.as_ref() {
            match state.wallet.receive_identity(&network).await {
                Ok(identity) => {
                    if let Err(e) = keystore::persist_default_receive_address(path, &identity.shield_address_base58, &identity.npub) {
                        tracing::warn!("could not add the default receive address to {}: {e:#}", path.display());
                    }
                }
                Err(e) => tracing::warn!("could not derive the default receive address for {}: {e:#}", path.display()),
            }
        }
        let recipient_count = a.allowed_recipients.as_ref().map(|r| r.len());
        // Bind the policy to the wallet we just loaded, and tell the engine which
        // identity this process is now operating — a policy is a budget for ONE
        // wallet, and mode="load" swaps the process's wallet globally.
        self.policy.lock().unwrap().set_current_wallet(network.as_str(), loaded.user_id);
        if let Err(e) = keystore::persist_active_wallet(network.as_str(), &loaded.pk_hash.to_string()) {
            tracing::warn!("could not persist active wallet on {}: {e:#}", network.as_str());
        }
        let policy_id = self
            .policy
            .lock()
            .unwrap()
            .create_policy(&a.agent_id, requested, a.allowed_recipients, vec![]);
        let mut result = json!({
            "network": network.as_str(),
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
        let requested_methods: Vec<String> = requests.iter().map(|r| r.method_name.clone()).collect();
        if let Some(what) = self
            .policy
            .lock()
            .unwrap()
            .creation_widens(&requested_limits, &a.allowed_recipients, &requested_methods)
        {
            if let Err(e) = owner_gate_for_widening(a.owner_token.as_deref(), &what) {
                return err_json(e, json!({ "gate": "owner", "widens": what, "policyCreated": false }));
            }
        }
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());

        // The key is written to owner-only disk inside this closure, which runs
        // BEFORE the chain learns the identity — the same ordering invariant
        // create_wallet relies on (see keystore.rs).
        let mint_network = network.as_str().to_string();
        let minted = state
            .wallet
            .mint_agent_account(&network, &requests, a.calls_per_transaction, |key, fingerprint, mandate| {
                keystore::persist_generated_key_with_mandate(key, fingerprint, &mint_network, mandate)
            })
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

        match state.wallet.receive_identity(&network).await {
            Ok(identity) => {
                if let Err(e) = keystore::persist_default_receive_address(&backup_path, &identity.shield_address_base58, &identity.npub) {
                    tracing::warn!("could not add the default receive address to {}: {e:#}", backup_path.display());
                }
            }
            Err(e) => tracing::warn!("could not derive the default receive address for {}: {e:#}", backup_path.display()),
        }

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
        self.policy.lock().unwrap().set_current_wallet(network.as_str(), loaded.user_id);
        if let Err(e) = keystore::persist_active_wallet(network.as_str(), &loaded.pk_hash.to_string()) {
            tracing::warn!("could not persist active wallet on {}: {e:#}", network.as_str());
        }
        let policy_id = self
            .policy
            .lock()
            .unwrap()
            .create_policy(&a.agent_id, limits, a.allowed_recipients, methods);

        let mandate = loaded.mandate.as_ref();
        let mut result = json!({
            "network": network.as_str(),
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
            tracing::info!(
                "agent key backed up at {} (owner-side; not disclosed to the agent)",
                backup_path.display()
            );
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
    async fn describe_mandate(&self, Parameters(a): Parameters<NetworkArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        match state.wallet.current_mandate(&network).await {
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

    #[tool(description = "List every wallet loaded for one Psy network. Returns only public identifiers; private keys are never exposed.")]
    async fn list_wallets(&self, Parameters(a): Parameters<NetworkArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        let active = state.wallet.current_user(&network).await.map(|u| u.pk_hash.to_string());
        let wallets = state
            .wallet
            .list_users(&network)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|u| {
                json!({
                    "userId": u.user_id,
                    "psyId": format!("Psy-{:08}", u.user_id),
                    "pkHash": u.pk_hash.to_string(),
                    "active": active.as_deref() == Some(u.pk_hash.to_string().as_str()),
                    "softwareDefined": u.mandate.is_some(),
                })
            })
            .collect::<Vec<_>>();
        let count = wallets.len();
        ok_json(json!({ "network": network.as_str(), "wallets": wallets, "count": count }))
    }

    #[tool(description = "Owner: select the active wallet within one Psy network by user id or public pk hash.")]
    async fn select_wallet(&self, Parameters(a): Parameters<SelectWalletArgs>) -> Result<CallToolResult, McpError> {
        if let Err(e) = owner_gate(a.owner_token.as_deref()) {
            return err_json(e, json!({ "gate": "owner" }));
        }
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        let previous = state.wallet.current_user(&network).await.map(|u| u.pk_hash.to_string());
        let selected = match state.wallet.select_user(&network, &a.user).await {
            Ok(user) => user,
            Err(e) => return err_json(e, json!({ "gate": "wallet" })),
        };
        if let Err(e) = keystore::persist_active_wallet(network.as_str(), &selected.pk_hash.to_string()) {
            if let Some(previous) = previous {
                let _ = state.wallet.select_user(&network, &previous).await;
            }
            return err_json(
                format!("active wallet could not be persisted; selection was not changed: {e:#}"),
                json!({ "gate": "persistence", "network": network.as_str() }),
            );
        }
        self.policy.lock().unwrap().set_current_wallet(network.as_str(), selected.user_id);
        ok_json(json!({
            "network": network.as_str(),
            "userId": selected.user_id,
            "psyId": format!("Psy-{:08}", selected.user_id),
            "pkHash": selected.pk_hash.to_string(),
            "active": true,
        }))
    }

    #[tool(description = "Show the resolved network, active wallet, loaded-wallet count, and non-sensitive RPC endpoint summary.")]
    async fn wallet_status(&self, Parameters(a): Parameters<NetworkArgs>) -> Result<CallToolResult, McpError> {
        let state = &self.state;
        let network = wallet_network!(state.wallet, a.network.as_deref());
        let endpoints = match state.wallet.endpoint_summary(&network) {
            Ok(endpoints) => endpoints,
            Err(e) => return err_json(e, json!({ "gate": "network" })),
        };
        let active = state.wallet.current_user(&network).await.map(|u| {
            json!({
                "userId": u.user_id,
                "psyId": format!("Psy-{:08}", u.user_id),
                "pkHash": u.pk_hash.to_string(),
                "softwareDefined": u.mandate.is_some(),
            })
        });
        ok_json(json!({
            "network": network.as_str(),
            "defaultNetwork": state.wallet.default_network(),
            "activeWallet": active,
            "walletCount": state.wallet.list_users(&network).await.map(|users| users.len()).unwrap_or(0),
            "endpoints": {
                "coordinator": endpoints.coordinator,
                "realm": endpoints.realm,
                "proveProxy": endpoints.prove_proxy,
                "apiServices": endpoints.api_services,
            },
        }))
    }

    #[tool(description = "Owner: mint a short-TTL session token for the agent from a policy.")]
    async fn issue_session(&self, Parameters(a): Parameters<IssueSessionArgs>) -> Result<CallToolResult, McpError> {
        if let Err(e) = owner_gate(a.owner_token.as_deref()) {
            return err_json(e, json!({ "gate": "owner" }));
        }
        match self
            .policy
            .lock()
            .unwrap()
            .issue_session(&a.policy_id, a.ttl_minutes, a.max_session_total_nano)
        {
            Ok((token, exp)) => ok_json(json!({ "token": token, "expiresAt": exp })),
            Err(e) => err_json(e, json!({})),
        }
    }

    #[tool(description = "Owner: pause a policy. Every subsequent spend authorization fails immediately.")]
    async fn pause_policy(&self, Parameters(a): Parameters<PolicyIdArgs>) -> Result<CallToolResult, McpError> {
        if self.policy.lock().unwrap().pause(&a.policy_id) {
            ok_json(json!({ "paused": a.policy_id }))
        } else {
            err_json("policy not found", json!({}))
        }
    }

    #[tool(description = "Owner: resume a paused policy.")]
    async fn resume_policy(&self, Parameters(a): Parameters<PolicyIdArgs>) -> Result<CallToolResult, McpError> {
        if let Err(e) = owner_gate(a.owner_token.as_deref()) {
            return err_json(e, json!({ "gate": "owner" }));
        }
        if self.policy.lock().unwrap().resume(&a.policy_id) {
            ok_json(json!({ "resumed": a.policy_id }))
        } else {
            err_json("policy not found", json!({}))
        }
    }

    #[tool(description = "Owner: revoke an agent session token immediately.")]
    async fn revoke_session(&self, Parameters(a): Parameters<SessionArg>) -> Result<CallToolResult, McpError> {
        if self.policy.lock().unwrap().revoke(&a.session) {
            ok_json(json!({ "revoked": true }))
        } else {
            err_json("token not found", json!({}))
        }
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
                    other => {
                        return err_json(
                            format!("unknown limit to remove: {other} — try perMonth, totalBudget or allowedRecipients"),
                            json!({ "gate": "args" }),
                        )
                    }
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
                    return err_json(e, json!({ "gate": "owner", "widens": what, "policyUnchanged": true }));
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

    #[tool(description = "The spends this server has AUTHORIZED, newest first — timestamp, method, recipient and \
                       amount. This is the audit trail of decisions, so it also shows a payment that was approved and \
                       then failed to settle, which the indexer would never show. Denied attempts are not spends and \
                       are not listed. Read-only; no session needed. Kept in memory (100 rows, biased toward real payments so failed attempts cannot crowd them out) and cleared on restart.")]
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
}
