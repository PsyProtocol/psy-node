# psy_mcp_server

A native Rust **Model Context Protocol** server that exposes the real Psy wallet
engine — [`psy_prover::session::WalletSession`](../psy_prover/src/session/session.rs) —
to AI agents. Because it wraps `WalletSession` directly, registration, transfers,
and claim/UPS batching run with **real client-side Plonky2 proving** through the
prove-proxy, not a mock.

> **Agents pay, humans control.** The agent never holds the key. The human sets a
> spending policy (per-tx / daily / total caps, recipient & method allowlists,
> session TTL) up front; the agent presents a session token to every fund-moving
> tool. Every check is enforced *below the model* (`src/policy.rs`), so a
> prompt-injected agent cannot exceed its budget or pay a non-allowlisted
> recipient.

## Why native Rust (not a Node shim)

`WalletSession` is the same engine the CLI (`psy_user_cli`) and the relayer
daemon drive. Wrapping it in-process means the MCP server gets real proofs for
free — no reimplemented RPC, no `pending_proving` stub. Construction mirrors the
proven CLI path (`psy_cli/psy_user_cli/src/subcommand/submit_end_cap_proof.rs`):

```
PsyConfigGoldilocks::from_file(config.json)   // carries prove_proxy_url + api_services_url
  → get_current_network()
  → WalletSession::new(&rpc_config)            // warms circuits from the prove-proxy
  → add_user / register_user                    // load the key
  → exec_contract_call / claim_batch            // REAL Plonky2 proof + submit
```

Reads go through the session's `RpcProvider` (`st_provider`) — the same reads the
wallet itself uses.

## Tools

- **Owner/policy:** `create_wallet` (generate+register or load) · `issue_session`
  · `pause_policy` · `resume_policy` · `revoke_session` · `check_budget`
- **Live reads:** `get_chain_status` · `get_user_info` · `get_claimable`
- **Spend / claim (policy-gated → real proof):**
  - `transfer` — public `simple_transfer`, real proof + submit.
  - `claim_all` — fuse all public claimables from the given senders into ONE UPS
    proof / one fee (`claim_batch` + `simple_claim`). Safe: claiming only folds
    funds already addressed to you.
  - `private_transfer` — **prepare-only.** Derives the note and the exact
    on-chain `private_transfer` call but does NOT submit: a private transfer is
    claimable only once its note is delivered to the recipient over Nostr in the
    exact format their wallet drains. That delivery is not yet wired/verified
    (the CLI reference tags `psy_private_transfer` while recipient wallets drain
    `psy_private_transfer_proof` — a mismatch that would strand funds). Settlement
    is withheld until delivery is wired and verified against a live recipient.
  - Deposit / withdraw and the x402 tools layer on the same `exec_call` /
    `claim_batch` primitives next.

## Run

```bash
# Point at a Psy config (default: ./config.json). Endpoints — coordinator, realm,
# prove-proxy, api_services — are read from its selected network.
PSY_CONFIG=/path/to/config.json cargo run -p psy_mcp_server

# Claude Desktop / MCP Inspector: spawn the built binary over stdio
#   { "command": "target/release/psy-mcp-server", "env": { "PSY_CONFIG": "…" } }
```

Amounts are in **Nano** (1 PSY = 1e9 Nano).

## Status

Builds green against the workspace; verified initializing `WalletSession` and
serving MCP over stdio against the live `-local` mesh. Registration/transfer run
real proofs when the prove-proxy is reachable (it falls back to a local circuit
manager otherwise — `WalletSession`'s own behavior). `private_transfer`,
`claim_all`, `deposit`/`withdraw`, and the x402 tools are the next layer on the
same `exec_call` / `claim_batch` primitives.

## Layout

```
src/main.rs     rmcp server + tool surface
src/wallet.rs   thin wrapper over WalletSession (the real engine)
src/policy.rs   spending-policy gate (caps, allowlist, sessions) — below the model
```
