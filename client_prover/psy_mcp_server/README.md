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
- **Transactions (two-phase, see below):** `transfer` · `transfer_batch` ·
  `claim_all` · `claim_deposit` · `private_claim` · `claim_batch` · `deposit` ·
  `retry_deposit_delivery` · `withdraw` · `private_transfer` · `claim_faucet` ·
  `call_contract` · `psyup_deploy` · `x402_fetch` · plus `create_wallet` /
  `mint_agent_account`. None of these is callable directly: each is exposed as a
  `prepare_<name>` / `execute_<name>` pair.

### Transaction confirmation (prepare → execute)

Every operation that can cause an on-chain write, an L1 write, or a payment
requires two calls with a human in the loop:

1. **`prepare_<name>`** — takes the operation's real arguments. Does NOT
   authorize, charge budget, or submit anything. Stores them verbatim for five
   minutes and returns a one-time `confirmation_token` plus the full summary
   for review — complete network, addresses, token, and amounts; only
   credentials (`session`, `owner_token`, `private_key*`) are redacted.
2. **`execute_<name>`** — takes ONLY `confirmation_token` + `owner_token`.
   Transaction fields cannot be re-passed or modified. The ticket is bound to
   the operation, wallet, network, and every parameter, expires in five
   minutes, and is consumed on first use. Execution always requires the
   `PSY_MCP_OWNER_TOKEN` the server was started with — without it every
   `execute_*` is disabled outright (fail closed, no dev fallback).

The ticket's wallet binding rides the session token stored at prepare time: a
policy governs one wallet, so swapping the active wallet between prepare and
execute makes authorization fail and records the attempt. `create_wallet` /
`mint_agent_account` take no session; for them the execute call's owner token
is forwarded to their internal owner gate.

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
| `PSY_MCP_OWNER_TOKEN` | Yes for owner tools **and every `execute_*`** | Owner gate token. Without it all `execute_*` transaction tools are disabled (prepare/read-only tools still work) |
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
see read-only tools (`get_balance`, `wallet_status`, …) plus `prepare_*` /
`execute_*` pairs for every transaction (`prepare_transfer`, `execute_claim_batch`,
`prepare_x402_fetch`, …) — no raw `transfer`/`claim_batch`/`x402_fetch`.

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

`scripts/smoke_confirmation_flow.py` drives a built binary over stdio MCP and
verifies the confirmation flow end to end: no raw transaction routes in
`tools/list`, direct calls refused, prepare storing verbatim arguments with
credentials redacted, wrong owner token refused, smuggled fields refused,
correct-owner dispatch reaching the real tool (stopped safely at the policy
gate by a fake session), single-use tickets, and unknown tickets refused. It
runs against a throwaway keystore with a random owner token, so it never
touches real wallets or funds:

```bash
cargo build --release
python3 client_prover/psy_mcp_server/scripts/smoke_confirmation_flow.py
# or point it at a specific binary/config:
python3 scripts/smoke_confirmation_flow.py ../../target/release/psy-mcp-server ~/.psy/config.json
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

Every prompt below now ends in a `prepare_*` result (`status=prepared`, full
summary, `confirmation_token`) — nothing submits until the owner runs the
matching `execute_*` with the owner token. "…then execute" below means exactly
that second, human-made call.

| # | Prompt | Expected |
|---|---|---|
| 2.1 | "Transfer 0.001 PSY to Psy-00860160" then execute | `submitted=true` + `endUserLeafHash` |
| 2.2 | "Transfer -5 PSY" | Rejected: invalid amount |
| 2.3 | "Transfer 0 PSY" | Error: "a transfer of 0 is a no-op" |
| 2.4 | "Batch transfer 0.001 to Psy-00860160 and 0.002 to Psy-0024576" then execute | One `endUserLeafHash` |
| 2.5 | "Private transfer 0.05 PSY to my own shield address" then execute | `delivered=true` |
| 2.6 | "Claim all my private notes" then execute | `claimed >= 1` |

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
| 4.3 | "Withdraw 0.005 PSY to 0xd307...10EF" then execute | `submitted=true` + txHash |
| 4.4 | "Withdraw to 0x000...0" | Error: "zero address — would burn the funds" |

### Group 5 — Contracts (~20 min)

| # | Prompt | Expected |
|---|---|---|
| 5.1 | "Create a new contract project qa-myname" | `ok=true` |
| 5.2 | "Write a contract with main returning 42 and compile it" | Build ok |
| 5.3 | "Deploy it" then execute | Output contains `contract_id` |
| 5.4 | "Call its main" then execute | `submitted=true` |
| 5.5 | "Deploy an add(a,b) contract and call it with 40 and 2" then execute | `submitted=true` |
| 5.6 | "Call add with only one argument 40" | Proving error: arity mismatch |

### Group 6 — x402 payments (~10 min)

Start the demo paid API first:

```bash
python3 client_prover/psy_mcp_server/test-kit/tools/x402_paid_api_demo.py
```

Then:

| # | Prompt | Expected |
|---|---|---|
| 6.1 | "Fetch http://host.docker.internal:8410/resource with x402" then execute | `paid=true` |
| 6.2 | "Verify the previous payment" | `status=ok` |
| 6.3 | "Verify this fake credential: garbage" | Error |

### Group 7 — Policy engine `[owner]` (~15 min)

| # | Action | Expected |
|---|---|---|
| 7.1 | Pause policy → ask agent to transfer | Error at execute: "policy paused by owner" |
| 7.2 | Resume → transfer again (prepare + execute) | `submitted=true` |
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

## Unified private FT (ordinary wallets)

The same `get_private_ft_balance` and `private_ft_transfer` / `private_ft_accept`
/ `private_ft_claim` / `private_ft_recover` / `private_ft_public_claim` tools now
accept registered single-Felt and two-Felt contracts. Callers supply a contract
ID, decimal amount string, and numeric recipient ID; they never choose an
encoding. The immutable owner registry selects a versioned adapter, then the
client checks that its code root, layout root and state dimensions match the
chain before using it. Unknown contracts fail closed. Amount size and decimals
never determine the adapter; there is no fallback to another format on failure.
Fetched method definitions are rehashed to the pinned code root; private
transfer, private claim and public claim input counts are checked as well.

| Owner `profile` | Contract support | Amount range | Private transfer / claim inputs |
| --- | --- | --- | --- |
| `single_felt_native_v1` | Native PSY 0 / pUSDT 4 with individually pinned code | 1..18446744069414584320 | 9 / 82 |
| `single_felt_psy20_v1` | Private PSY20 v3 layout (22 fields, 2149832488 slots) | 1..18446744069414584320 | 9 / 82 |
| `u124_private_v1` | Private U124 layout (24 fields, 2178599700 slots) | 1..2^124-1 | 14 / 151 |

Omitting `profile` preserves the prior U124 configuration behavior. Each
registered deployment needs its own reviewed code/layout pins; declaring a
profile does not make arbitrary contract code trustworthy. Public-only FT
contracts without private methods and other ABI/layout versions need separate
adapters. This supports both known formats, not arbitrary ABI inference.

For example, add a second `assets` entry for current staging PSY:

```json
{
  "network": "sepolia", "contract_id": 0,
  "profile": "single_felt_native_v1",
  "code_root": "53735dc64de34c4a84281e22a3d1606d983ad6d617ab717480421883fc88d4ba",
  "layout_root": "0000000000000000000000000000000000000000000000000000000000000000",
  "decimals": 9, "policy_nano_per_token": 1000000000
}
```

Single-Felt amounts are checked before policy charging/proving, and received
notes are checked against the selected contract's amount range and proof
domain. Single-Felt and U124 encrypted packets have different authenticated
format tags; relabeling or cross-format claims are rejected. Existing U124
packets, accepted note IDs and recovery records stay compatible. New recovery
records bind the adapter; no recovery operation chooses another encoding or
submits another transfer. Native PSY sends reserve headroom for principal plus
fee; private claims check balance overflow and an unchanged caller leaf before
broadcast. Native public credits use `simple_claim`; template credits use
`claim`. Single-Felt public claims check the sender's unclaimed delta against
balance capacity and require unchanged sender/caller leaves before broadcasting.
The current Native adapter uses count/path/root offsets 8589934595/8589934600/
2147483649 (root is a four-Felt leaf index); PSY20 v3 uses 33554435/33554440/
8388609. Width alone therefore does not select a storage layout version.
Original legacy `private_transfer` / `private_claim` tools stay intact.
Native PSY contract 0 requires decimals 9 and weight 1,000,000,000: its policy
charge always equals the exact NanoPSY principal, never a discounted FT weight.

This is an MCP client change only. No Node runtime/circuit, deployed contract,
services API, Genesis regeneration or SDK package update is required for the
explicit encrypted handoff flow. Automatic services/Nostr discovery and
services-side amount displays would require their own dual-format adaptation.

### U124-specific encoding

The dedicated `private_ft_*` tools support the new two-Felt FT profile. Amounts
are **canonical decimal strings in token base units**, with two 62-bit limbs.
The U124 adapter is separate from the legacy one-Felt `private_transfer`/`private_claim`.

The owner supplies an immutable process configuration file through
`PSY_MCP_PRIVATE_FT_CONFIG`; agents cannot register assets, change pins, choose
budget weights, or replace recipient contacts through these tools:

```json
{
  "assets": [{
    "network": "sepolia", "contract_id": 2457,
    "code_root": "fc19619943370196243a67e0947342d05cd430a6fb076b4cb3ca8c7a827b284f",
    "layout_root": "35e546bb64ad8405e725377eae4cedd54032ca6980cda5520cc3cb18d81c0a03",
    "profile": "u124_private_v1",
    "decimals": 18, "policy_nano_per_token": 100000000
  }],
  "contacts": [{
    "network": "sepolia", "user_id": 1234,
    "shielded_address": "ELEMENTS_ORDER_HEX_FROM_GET_RECEIVE_ADDRESS",
    "npub": "RECIPIENT_NPUB_FROM_GET_RECEIVE_ADDRESS"
  }]
}
```

The example weight means one whole test token counts as 0.1 PSY toward the
existing policy budget. **It is an owner-selected accounting weight, not a
market price.** The gate rounds up in integer arithmetic, checks the numeric
recipient allowlist and `private_transfer` permission, and rejects overflow.
Native transaction fees are paid in PSY; the principal budget weight does not
represent a Native PSY transfer. Token ID, code/layout roots, 32-level tree,
24 fields, and 2178599700 slots must match the pinned profile.

1. Owner retrieves and registers the recipient's public receive address/npub.
2. `get_private_ft_balance` reads the exact spendable decimal amount.
3. `prepare_private_ft_transfer` / `execute_private_ft_transfer` authorize and
   send `amount: "20000000000000000017"` to the registered `to_user_id`.
4. Hand the opaque encrypted `delivery` string to the recipient. It contains
   bounded NIP44 chunks with encrypted package/index/count/digest bindings.
   It is a new MCP format; do not submit it to an old one-Felt wallet or the
   legacy services drain. This entry provides explicit ciphertext handoff,
   not an automatic Nostr relay subscription.
5. Recipient calls `prepare_private_ft_accept` / `execute_private_ft_accept`
   with that delivery and `contract_id`. The server decrypts, checks the
   recipient, and independently verifies both native inclusion proofs. The
   decrypted packet and receive blinding factors never enter a tool result.
6. Recipient calls `prepare_private_ft_claim` / `execute_private_ft_claim`
   with the returned `note_id`. Both proofs enter the session before final
   paths are read; CFC and full UPS are proved and independently verified.

`private_ft_public_claim` folds a public U124 FT credit addressed to this wallet
into its spendable balance, under the existing `simple_claim` permission.
`private_ft_recover` reconstructs an **already submitted** outgoing delivery,
without another payment or amount charge. `private_ft_status` reconciles an
opaque outgoing/incoming/public record ID through historical checkpoints.
These preserve the exact authorized wallet identity across selection changes.

The server persists a mode-0600 recovery record before proving, then the exact
signed leaf hash, nonce and pre-submit checkpoint before its one submit RPC.
Later delivery/journal failures cannot refund a possibly submitted amount.
A network error is not proof of rejection: reconcile the recorded hash, then
recover the delivery. Pending/consumed claims cannot be resubmitted. Sender
operations have cross-process file locks and verify that the note-index
baseline did not change. State/proof failures before submission do not spend
the principal budget. No ordinary wallet keys or note secrets are exported.

This profile hides note linkage through inclusion proofs; it does **not** claim
all amounts, balances, events or calldata are confidential. Independent audit
and broader release acceptance remain separate requirements.

### Verification

```sh
cargo +nightly-2025-09-20 test --offline --locked --release -p psy_mcp_server
# Explicitly exercise chunking with a local two-native-proof fixture:
PSY_MCP_U124_TEST_PACKET=/owner/local/native-two-proof-fixture.json \
  cargo +nightly-2025-09-20 test --offline --locked --release -p psy_mcp_server \
  wide_private::tests::real_two_native_proofs_roundtrip_without_exceeding_nip44 \
  -- --ignored --nocapture
```

The external fixture is read inside the test process, never printed; the test
reports only packet byte size/chunk count. The test is ignored by default
because the fixture is intentionally not committed. All other U124 tests run
normally, including decimal/policy bounds, recipient-bound encryption,
missing/reordered/spliced chunks, exclusive durable creation and route gates.

Owner `select_wallet` can also lazily restore a saved wallet by its public user ID or pk hash when the bounded startup restore did not load it. The server resolves the saved key/fingerprint internally and validates its network and public identity against the chain; no key-file path or key enters tool arguments.
Older backups without public identity caches are resolved inside the MCP process; only a key whose on-chain user ID or public hash matches the owner selection is activated.
