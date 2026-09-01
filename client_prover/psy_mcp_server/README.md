# psy_mcp_server

A native Rust **Model Context Protocol** server that exposes the real Psy wallet
engine — [`psy_prover::session::WalletSession`](../psy_prover/src/session/session.rs) —
to AI agents. Because it wraps `WalletSession` directly, registration, transfers,
and claim/UPS batching run with **real client-side Plonky2 proving** through the
prove-proxy, not a mock.

> **Agents pay, humans control.** The agent never holds the key. The human sets a
> spending policy (per-tx / daily / 30-day / total caps, recipient & method
> allowlists, session TTL) up front; the agent presents a session token to every
> fund-moving tool. Every check is enforced *below the model* (`src/policy.rs`),
> so a prompt-injected agent cannot exceed its budget or pay a non-allowlisted
> recipient.

## Why native Rust (not a Node shim)

`WalletSession` is the same engine the CLI (`psy_user_cli`) and the relayer
daemon drive. Wrapping it in-process means the MCP server gets real proofs for
free — no reimplemented RPC, no `pending_proving` stub. Construction mirrors the
proven CLI path:

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
  · `pause_policy` · `resume_policy` · `revoke_session` · `check_budget` ·
  `describe_policy` · `get_spend_log`
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

## Policy

Set at `create_wallet` / `mint_agent_account` time, enforced on every spend:

| Knob | Meaning |
| --- | --- |
| `per_transaction_nano` | ceiling on a single payment |
| `per_day_nano` | ceiling per calendar-day bucket |
| `per_month_nano` | ceiling per 30-day bucket (omit for none) |
| `total_budget_nano` | lifetime ceiling for the policy (omit for none) |
| `allowed_recipients` | who may be paid — omit for anyone, `[]` for nobody |

`allowed_recipients` entries are matched in canonical form, so the spelling never
decides whether a payment goes through: `Psy-00001234` ≡ `1234`, `0xDEADBEEF` ≡
`deadbeef`, and `https://api.example.com/paid` ≡ the host `api.example.com` (an
x402 seller is allowlistable by host *or* by the user id its 402 demands). Claims
and deposits are exempt from this list — it says who may receive the agent's
money, and funds coming *in* have no third-party payee.

Two read-only surfaces close the loop:

- **`describe_policy`** — the policy as one sentence ("*This agent may spend up
  to 0.1 PSY per payment, 1 PSY per day, 20 PSY per 30 days, to 3 approved
  recipients, via methods … Session expires in 43 minutes.*"). This is the
  agent-onboarding surface: hand it a wallet and it can read its own contract.
  The allowlist's *size* is returned, never its contents.
- **`get_spend_log`** — the last 100 **authorized** spends (timestamp, method,
  recipient, amount) held in this process. It records *decisions*, so it shows a
  payment that was approved and then failed to settle — which the indexer, by
  construction, never will. In memory only; cleared on restart.

## Run

```bash
# Point at a Psy config (default: ./config.json). Endpoints — coordinator, realm,
# prove-proxy, api_services — are read from its selected network.
PSY_CONFIG=/path/to/config.json cargo run -p psy_mcp_server

# Claude Desktop / MCP Inspector: spawn the built binary over stdio
#   { "command": "target/release/psy-mcp-server", "env": { "PSY_CONFIG": "…" } }
```

### Native install (without Docker)

From the repository root, build and register the release binary directly with
the MCP client:

```bash
bash install-mcp-binary.sh
```

The script installs `psy-mcp-server` under `~/.psy/bin`, uses
`~/.psy/config.json` (or `PSY_CONFIG`), stores keys under
`~/.psy-mcp-keys` (or `PSY_MCP_KEYSTORE_DIR`), and supports
`PSY_INSTALL_TARGET=claude-code|claude-desktop|codex|cursor|workbuddy`.

## Docker build & test

The repository includes a `Dockerfile` that builds a self-contained Linux image.
You need **no local Rust toolchain, config files, or running services** to use the
image — the binary is compiled inside the builder and the staging network
endpoints are baked in. Cold build takes 30–60 minutes; subsequent builds are
fast thanks to the layer cache.

### Build

From the repository root:

```bash
docker build -f Dockerfile.psy-mcp-server -t psy-mcp-server:staging .
```

Runtime environment:

| Variable | Required | Purpose |
|---|---|---|
| `PSY_MCP_OWNER_TOKEN` | Yes for owner tools | Owner gate token; agent tools still work without it |
| `PSY_MCP_KEY_FILE` | Optional | Load an existing key backup instead of creating a fresh wallet |

The keystore lives at `/app/keys` inside the container. Mount a host directory or
a named volume to keep identities across `docker rm`:

```bash
docker run -i --rm \
  -v psy_wallet_keys:/app/keys \
  -e PSY_MCP_OWNER_TOKEN=my-test-token-123 \
  psy-mcp-server:staging
```

### Connect to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "psy": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "psy_wallet_keys:/app/keys",
        "-e", "PSY_MCP_OWNER_TOKEN",
        "psy-mcp-server:staging"
      ],
      "env": {
        "PSY_MCP_OWNER_TOKEN": "my-test-token-123"
      }
    }
  }
}
```

Restart Claude Desktop, then ask: **"List the psy wallet tools"**. You should
see ~37 tools including `transfer`, `claim_batch`, and `x402_fetch`.

### Connect to Claude Code

```bash
claude mcp add -s user psy \
  -e PSY_MCP_OWNER_TOKEN=my-test-token-123 \
  -- docker run -i --rm -v psy_wallet_keys:/app/keys -e PSY_MCP_OWNER_TOKEN psy-mcp-server:staging
```

Restart the Claude Code session.

### Key persistence

Generated keys are backed up under `/app/keys` **before** any on-chain
registration. If you do not mount a volume, deleting the container deletes the
identity. To recover an existing identity after restart, pass the backup file:

```bash
docker run --rm -v psy_wallet_keys:/app/keys --entrypoint sh \
  psy-mcp-server:staging -c 'ls /app/keys'
# then add -e PSY_MCP_KEY_FILE=/app/keys/wallet-xxxx.json to your MCP config
```

## Smoke test

A quick read-only smoke test is available in `test-kit/smoke-test.sh`. With the
image loaded:

```bash
cd client_prover/psy_mcp_server/test-kit
bash smoke-test.sh
```

To run the full 6-check suite you need a wallet file:

```bash
SMOKE_KEY_FILE=/app/keys/wallet-xxxx.json bash smoke-test.sh
```

## Manual test checklist

Copy and fill as you test. Amounts are in Nano (1 PSY = 1e9 Nano).

### Group 1 — Identity & reads (~5 min)

| # | Prompt | Expected |
|---|---|---|
| 1.1 | "Get my psy user info" | Returns `userId` / `psyId` |
| 1.2 | "Check my PSY and USDT balance" | `status=ok`, PSY balance present |
| 1.3 | "Check my NOPE balance" | Error: "unknown token NOPE" |
| 1.4 | "Show my receive address" | Returns `shieldedAddress` + `npub` |
| 1.5 | "What is the chain status?" | `checkpointId` > 180000 |
| 1.6 | "Show my recent activity" | `get_activity` returns in/out items |
| 1.7 | "Describe my policy" | `perTransaction` etc. have values |

### Group 2 — Transfers & claims (~30 min)

| # | Prompt | Expected |
|---|---|---|
| 2.1 | "Transfer 0.001 PSY to Psy-00860160" | `submitted=true` + `endUserLeafHash` |
| 2.2 | "Transfer -5 PSY" | Rejected: invalid amount |
| 2.3 | "Transfer 0 PSY" | Error: "a transfer of 0 is a no-op" |
| 2.4 | "Batch transfer 0.001 to Psy-00860160 and 0.002 to Psy-0024576" | One `endUserLeafHash` |
| 2.5 | "Private transfer 0.05 PSY to my own shield address" | `delivered=true` |
| 2.6 | "Claim all my private notes" | `claimed >= 1` |

### Group 3 — Super UPS batch (~15 min)

| # | Prompt | Expected |
|---|---|---|
| 3.1 | "Claim faucet, then in one batch: claim grant, transfer 0.001 to Psy-00860160, withdraw 0.001 PSY to 0xd307a971BBb3007467A1fc99Ab3f8B1460ce10EF, and claim my private notes" | One `endUserLeafHash`; all legs present |
| 3.2 | "Run an empty batch" | Error: "nothing to claim" |
| 3.3 | `[owner]` "Remove claim_deposit from allowed methods, then run a batch with a deposit claim" | Error: "policy denied deposit claims" |

### Group 4 — Cross-chain bridge (optional, ~30 min)

| # | Prompt | Expected |
|---|---|---|
| 4.1 | "Deposit 1 USDT" | Returns `expectedDepositIndex` |
| 4.2 | "Claim the deposit once it is claimable" | `claimedBaseUnits=1000000` |
| 4.3 | "Withdraw 0.005 PSY to 0xd307...10EF" | `submitted=true` + txHash |
| 4.4 | "Withdraw to 0x000...0" | Error: "zero address — would burn the funds" |

### Group 5 — Contracts (~20 min)

| # | Prompt | Expected |
|---|---|---|
| 5.1 | "Create a new contract project qa-myname" | `ok=true` |
| 5.2 | "Write a contract with main returning 42 and compile it" | Build ok |
| 5.3 | "Deploy it" | Output contains `contract_id` |
| 5.4 | "Call its main" | `submitted=true` |
| 5.5 | "Deploy an add(a,b) contract and call it with 40 and 2" | `submitted=true` |
| 5.6 | "Call add with only one argument 40" | Proving error: arity mismatch |

### Group 6 — x402 payments (~10 min)

Start the demo paid API first:

```bash
python3 client_prover/psy_mcp_server/test-kit/tools/x402_paid_api_demo.py
```

Then:

| # | Prompt | Expected |
|---|---|---|
| 6.1 | "Fetch http://host.docker.internal:8410/resource with x402" | `paid=true` |
| 6.2 | "Verify the previous payment" | `status=ok` |
| 6.3 | "Verify this fake credential: garbage" | Error |

### Group 7 — Policy engine `[owner]` (~15 min)

| # | Action | Expected |
|---|---|---|
| 7.1 | Pause policy → ask agent to transfer | Error: "policy paused by owner" |
| 7.2 | Resume → transfer again | `submitted=true` |
| 7.3 | Issue session → revoke it → spend with old session | Error: "session token is not valid" |
| 7.4 | Edit policy with wrong owner token | Error: "this is an owner tool" |
| 7.5 | Set per-tx cap to 1 PSY → transfer 2 PSY | Error: "over the per-transaction cap" |
| 7.6 | Check spend log | Records present; refunded items marked |
| 7.7 | `[owner]` Create wallet with `allowed_recipients=["Psy-00860160"]` → agent pays Psy-00245760 | Error: "recipient not on this policy's allowlist" |

## Key custody

Generated keys are **durably backed up before the chain ever learns the
identity** (`src/keystore.rs`): `create_wallet(mode="generate")` writes an
owner-only key file (0600, atomic write) and only then registers on-chain, so a
crash can never leave an on-chain wallet whose key nobody has. Tool results
carry the backup *path* and fingerprint — never key material.

- `PSY_MCP_KEYSTORE_DIR` — where backups are written (default `~/.psy-mcp-keys`).
- `PSY_MCP_KEY_FILE` — a backup file to load at startup, so a restarted server
  reattaches its wallet **without the private key ever passing through the
  model's context**.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Tool list empty / cannot connect | Container not running | Run `docker run --rm -i psy-mcp-server:staging < /dev/null` and check logs |
| `create_wallet` times out | On-chain registration proof is slow | Wait 2 minutes and retry; check `docker logs` |
| Balance unchanged after claim | Checkpoint settlement delay | Wait 45 seconds and recheck |
| "prove claim batch failed" | Faucet cooldown (claimable amount is 0) | Run `get_claimable` first and confirm > 0 |
| New wallet after restart | Keystore volume missing | Ensure `-v psy_wallet_keys:/app/keys` is in the MCP config |
| Want to start completely fresh | — | `docker volume rm psy_wallet_keys` |

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
