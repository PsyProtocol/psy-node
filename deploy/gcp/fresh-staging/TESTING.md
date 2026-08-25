# Public Staging E2E Testing

This is the canonical handoff for validating the deployed Parth/Psy public
staging network. An acceptance run has three independent parts:

1. **Read-only node audit** proves that the deployed services and infrastructure
   are healthy enough to test.
2. **CLI transaction E2E** proves the complete public-staging business flow.
3. **Playwright E2E** proves the deployed IDE, Explorer, App, and wallet-facing
   browser behavior.

Do not report a complete pass when any required part was skipped. A recovered
retry does not erase the original failure; preserve both attempts and explain
the cause.

## Environment

Set the deployment checkout once:

```bash
export WORKSPACE_HOME="/path/to/bridge-workspace"
export PSY_NODE_HOME="$WORKSPACE_HOME/psy-node-deploy-unified"
```

The expected backend source revisions are recorded in:

```text
deploy/source-versions.env
```

The public staging endpoints are:

| Component | URL |
| --- | --- |
| App | `https://app-stg.psy-protocol.xyz` |
| Explorer | `https://explorer-stg.psy-protocol.xyz` |
| IDE | `https://ide-stg.psy-protocol.xyz` |
| Coordinator | `https://coordinator-stg.psy-protocol.xyz` |
| Realm 0 / 1 | `https://realm0-stg.psy-protocol.xyz`, `https://realm1-stg.psy-protocol.xyz` |
| Prove Proxy | `https://prove-stg.psy-protocol.xyz` |
| Faucet | `https://faucet-stg.psy-protocol.xyz` |
| Services | `https://services-stg.psy-protocol.xyz` |
| Indexer | `https://indexer-stg.psy-protocol.xyz` |
| Nostr | `https://nostr-stg.psy-protocol.xyz` |

Playwright wallet tests use the dedicated Lenovo `psy_test` Chrome profile
through localhost-only CDP. Do not operate the default Chrome profile. Never
print its password, mnemonic, wallet private keys, private receive packets,
notes, nullifiers, or recovery material.

## Part 0: Read-only node audit

Run this before creating any transactions:

```bash
"${CODEX_HOME:-$HOME/.codex}/skills/parth-staging-node-status/scripts/check_staging_nodes.sh" \
  --repo "$PSY_NODE_HOME" \
  --since "60 minutes ago"
```

The audit covers chain synchronization, L1 bridge counters, systemd services,
relayer progress, cloud and offsite workers, prove-proxy capacity, stateful
containers, recent errors, restarts, disk, memory, and public endpoints.

Do not start the transaction E2E when:

- coordinator or either realm is unavailable or persistently out of sync;
- the faucet is disabled, requires Turnstile, or has no operators;
- psy-services is unavailable;
- `provedDepositCount` is ahead of `pendingDepositCount`;
- the relayer or prove-proxy is down;
- a current infrastructure failure would make results ambiguous.

A documented warning such as low prove-proxy memory headroom may allow a
diagnostic run, but it must remain in the final report.

## Part A: CLI transaction E2E

### Coverage

The canonical staging CLI flow covers:

1. two fresh disposable Psy user registrations;
2. contract deployment and psy-services lookup;
3. standalone faucet and `simple_claim` for both users;
4. bidirectional public transfers and claims;
5. bidirectional private transfers and private claims;
6. Sepolia USDT deposit and L2 `claim_deposit`;
7. Psy-to-Sepolia PSY withdrawal and L1 settlement;
8. Sepolia PSY deposit and L2 `claim_deposit`;
9. Psy-to-Sepolia USDT withdrawal and L1 settlement;
10. final bridge counters, chain synchronization, API stability, relayer, and
    worker-log checks.

This flow spends Sepolia ETH and creates irreversible public-staging
transactions. Obtain explicit authorization before running it.

### Build

The wrapper builds only the E2E orchestrator when it is absent. The deployment
worktree must already contain a matching release `psy_user_cli`:

```bash
cd "$PSY_NODE_HOME"
cargo build --release -p psy_user_cli -p psy_cli_full_e2e
```

### Initialize a disposable run

```bash
cd "$PSY_NODE_HOME"
e2e/staging/run-cli-e2e.sh init
```

The command creates a mode-700 directory under `.private/e2e-runs/` and prints
only the public disposable Sepolia address. Fund that address with at least
`0.005` Sepolia ETH.

An existing disposable funded key may be imported by file without printing it:

```bash
e2e/staging/run-cli-e2e.sh init \
  /absolute/private/run-directory \
  /secure/path/disposable-sepolia.key
```

Never use a genesis, faucet operator, relayer, worker, deployer, or treasury key.

### Check readiness

```bash
e2e/staging/run-cli-e2e.sh status \
  /absolute/path/to/.private/e2e-runs/psy-cli-full-e2e.PID.EPOCH
```

The status command is read-only. It checks staging preconditions, disposable
Sepolia funding, chain heights, token balances, and completed phase files.

### Execute or resume

```bash
AUTHORIZED_STAGING_TRANSACTIONS=1 \
  e2e/staging/run-cli-e2e.sh run \
  /absolute/path/to/.private/e2e-runs/psy-cli-full-e2e.PID.EPOCH
```

Every mutating phase writes an intent before submission and an `.ok.json`
checkpoint only after independent verification. The same command may resume
verified phases, but it refuses to repeat an unresolved intent.

On timeout, do not blindly rerun faucet, deposit, withdrawal, or claim. Preserve
the run directory and inspect the existing intent, CLI log, transaction receipt,
services response, L1 counters, and chain state. Use the deposit or withdrawal
debug skill for the failed phase.

The run directory contains secrets. Do not upload or share it. A redacted report
may include public user IDs, checkpoints, transaction hashes, durations, and L1
balance changes, but must exclude keys, notes, nullifiers, nonces, deposit proof
secrets, and private receive packets.

### Required pass evidence

- both fresh public keys resolve to numeric user IDs;
- faucet transfer appears through `public-claimable`, then `simple_claim`
  clears it;
- public transfer becomes claimable and is claimed;
- private claim event is indexed for the receiver;
- each L1 deposit receipt succeeds and advances `pendingDepositCount` and
  `provedDepositCount` equally;
- each L2 deposit claim event is indexed;
- each withdrawal appears on L2, is settled by the relayer, increases the
  authoritative L1 token balance, and exposes claimed L1 state;
- coordinator and realms remain synchronized;
- no transport failure or HTTP 5xx occurs in recorded `public-claimable`
  attempts;
- no unresolved relayer or worker warning/error is caused by the test.

## Part B: Playwright E2E

### One-time preparation

```bash
cd "$PSY_NODE_HOME/e2e/ide-explorer"
npm install --no-package-lock
```

If Chromium is absent, run `npx playwright install chromium`. SSH alias
`lenovo` must reach the browser machine. CDP must remain bound to
`127.0.0.1:9222` and be reached through the SSH tunnel.

### Safe repeatable run

```bash
cd "$PSY_NODE_HOME"
e2e/staging/run-playwright-e2e.sh
```

The default run is non-transactional:

- IDE landing, routing, template, WASM, and compile behavior;
- Explorer lists, details, navigation, search, filters, pagination, status,
  and rendered-data comparison with independent staging APIs;
- App wallet injection, Bridge/Activity/Faucet navigation, form controls,
  notification/error behavior, reconnect recovery, and idle performance.

It does not click Deposit, Withdraw, Claim, faucet funding, Lock, or wallet
approval buttons. It also does not run the transactional `ide-deploy` project.

Durable evidence is written under:

```text
e2e/ide-explorer/artifacts/staging/<UTC-run-id>/
```

Failed tests retain Playwright traces and screenshots under
`e2e/ide-explorer/test-results/`. The App smoke writes its initial report to
`test-results/app-staging/`; the wrapper copies it into the durable run
directory.

### Optional wallet state run

This checks connect, approval, disconnect, reconnect, `accountsChanged`,
account-specific Explorer navigation, lock behavior, and restoration of the
original account. It requires two existing disposable accounts:

```bash
RUN_IDE=0 RUN_APP=0 RUN_WALLET_STATE=1 \
PSY_EXPLORER_FIRST_ACCOUNT=<existing-account-name> \
PSY_EXPLORER_SECOND_ACCOUNT=<second-disposable-account-name> \
  e2e/staging/run-playwright-e2e.sh
```

Do not put the wallet password in this document or shell history.

### Transactional UI tests

The default Playwright run intentionally does not duplicate CLI transactions.
Real UI faucet, deposit, claim, withdrawal, or private-transfer tests require
separate explicit authorization and exactly-once handling of wallet
confirmations. Follow the prompts in:

- `e2e/ide-explorer/APP_AUTOMATION_TEST_PROMPT.md`
- `e2e/ide-explorer/AUTOMATION_TEST_PROMPT.md`

Never resubmit after a UI timeout until the existing Activity receipt, wallet
popup, transaction hash, and chain state have been checked.

## Final report contract

Report each part independently:

```text
Environment and source revisions:
Read-only node audit: Pass/Degraded/Fail/Not run
CLI E2E: Pass/Fail/Partial/Not run
  registration + contract deployment:
  faucet + simple_claim:
  public transfer + claim:
  private transfer + claim:
  USDT deposit + claim:
  PSY withdraw + settlement:
  PSY deposit + claim:
  USDT withdraw + settlement:
  final counters and checkpoints:
Playwright E2E: Pass/Fail/Partial/Not run
  IDE:
  Explorer UI:
  Explorer data integrity:
  Explorer interaction coverage:
  App:
  Wallet state (optional):
Evidence paths:
New service errors:
Residual risks:
```

Classify failures as test harness, deployment configuration, backend/indexer,
relayer/prover/worker, frontend, wallet/provider, or external browser-machine
infrastructure. Never call skipped coverage a complete pass.
