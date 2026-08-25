# Local Testnet E2E Testing

This is the canonical handoff for testing the shared local Parth/Psy testnet.
An acceptance run has two independent parts:

1. **CLI transaction E2E** proves backend and on-chain business flows.
2. **Playwright E2E** proves the deployed IDE, Explorer, App, and wallet-facing
   browser behavior.

Do not report a complete pass when either part was skipped. Read
[`HANDOFF.md`](HANDOFF.md) first because deployment paths and snapshots can
change.

## Current machine context

Set the workspace paths once:

```bash
export WORKSPACE_HOME="/path/to/bridge-workspace"
export PSY_NODE_HOME="$WORKSPACE_HOME/psy-node-deploy-unified"
export LOCAL_TESTNET_RUNTIME_HOME="$PSY_NODE_HOME"
```

The public local endpoints are:

| Component | URL |
| --- | --- |
| App | `https://app-local.psy-protocol.xyz` |
| Explorer | `https://explorer-local.psy-protocol.xyz` |
| IDE | `https://ide-local.psy-protocol.xyz` |
| Coordinator | `https://coordinator-local.psy-protocol.xyz` |
| Realm 0 / 1 | `https://realm0-local.psy-protocol.xyz`, `https://realm1-local.psy-protocol.xyz` |
| Services | `https://services-local.psy-protocol.xyz` |
| Indexer | `https://indexer-local.psy-protocol.xyz` |
| L1 RPC | `https://rpc-local.psy-protocol.xyz` |

The local Playwright wallet tests use the dedicated Lenovo `psy_local_test`
Chrome profile through localhost-only CDP port `9223`. Public staging uses the
separate `psy_test` profile on port `9222`. Never switch either profile to the
other environment just to continue a test. Do not operate the default Chrome
profile. Each test profile should contain only Psy Wallet and MetaMask. Do not
print its password, mnemonic, wallet private keys, private receive packets,
notes, or nullifiers.

## Part A: CLI transaction E2E

### What it covers

The canonical local CLI flow is:

1. read-only process, endpoint, tunnel, relayer, and checkpoint preflight;
2. a fresh disposable Psy user registration;
3. standalone faucet, indexer event, `public_claims`, and claimable API checks;
4. faucet funding and `simple_claim` for the deterministic local bridge user;
5. one local-L1 USDT deposit, `pendingDepositCount`, `provedDepositCount`, and
   L2 `claim_deposit`;
6. one L2 USDT withdrawal and final local-L1 token balance increase;
7. a final coordinator/realm synchronization check.

It creates local chain transactions. Obtain explicit authorization before
running it.

### Run

```bash
cd "$PSY_NODE_HOME"

AUTHORIZED_LOCAL_TRANSACTIONS=1 \
  e2e/local-testnet/run-cli-e2e.sh \
  "$LOCAL_TESTNET_RUNTIME_HOME"
```

The wrapper calls the installed `parth-local-testnet-status` skill in `--e2e`
mode and stores a mode-600 transcript under:

```text
e2e/local-testnet/test-results/cli/<UTC-run-id>/
```

Required pass evidence:

- fresh faucet user ID, faucet transaction hash, event checkpoint, and
  claimable amount;
- L1 deposit transaction hash and deposit index;
- final `pendingDepositCount == provedDepositCount`;
- L2 deposit-claim event/checkpoint;
- withdrawal nonce and realm event/checkpoint;
- L1 withdrawal claim transaction when available, plus authoritative L1 token
  balance before/after;
- synchronized and advancing coordinator, realm0, and realm1.

On timeout, do not blindly rerun faucet, deposit, or withdrawal. Preserve the
run directory, inspect already submitted transactions and chain state, and use
the deposit- or withdrawal-debug skill for the failed phase.

### Similar scripts that are not this local acceptance test

- `e2e/cli-full-e2e/` is the larger Rust orchestrator for public staging and
  Sepolia. It requires funded disposable Sepolia credentials.
- `e2e/bridge-e2e.sh` is an older standalone local script. Do not use it as the
  canonical acceptance entrypoint; its recovery/evidence behavior is weaker
  than the healthcheck wrapper.

## Part B: Playwright E2E

### One-time preparation

```bash
cd "$PSY_NODE_HOME/e2e/ide-explorer"
npm install --no-package-lock
```

If the bundled headless browser is absent, run `npx playwright install
chromium`. SSH alias `lenovo` must reach the test laptop. The Explorer runner
starts or reuses Chrome with:

```text
user-data-dir=/home/peter/.local/share/psy_local_test
remote-debugging-address=127.0.0.1
remote-debugging-port=9223
```

`psy_test` remains the staging-only profile on port 9222. The local wrapper
supplies the local values to the shared Explorer runner.

CDP must remain loopback-only and be reached through the SSH tunnel.

### Safe repeatable run

```bash
cd "$PSY_NODE_HOME"
e2e/local-testnet/run-playwright-e2e.sh
```

The default run is non-transactional:

- IDE landing, routing, template, WASM, and compile behavior;
- Explorer lists/details/navigation/search;
- Explorer rendered-data comparison with independent services, coordinator,
  realms, GraphQL indexer, and L1 RPC oracles;
- Explorer menus, keyboard shortcuts, search types, filters, pagination,
  watchlist, Users, contract cards, 404 handling, and status page;
- App wallet injection, Bridge/Activity/Faucet navigation, amount presets,
  token/direction controls, notifications, errors, and an idle performance
  sample.

For the local App the wrapper disables the staging-only injected reconnect
fault. It does not click Deposit, Withdraw, Claim, faucet funding, Lock, or any
wallet approval.

Durable per-run evidence is written below:

```text
e2e/ide-explorer/artifacts/local-testnet/<UTC-run-id>/
```

Failed Playwright tests also retain traces and screenshots in
`e2e/ide-explorer/test-results/`. The App first writes under the legacy
directory name `test-results/app-staging/` even when `PSY_APP_URL` targets the
local environment; the wrapper copies it into the per-run evidence directory.
Trust the URL recorded inside `report.json`.

### Known wallet recovery defect: interrupted initialization never settles

Observed on 2026-07-28 with Psy Wallet `0.4.24` in the Lenovo `psy_test`
profile:

1. Unlock/restore entered the narrated account-initialization screen.
2. The proving path became unavailable while the operation was in flight.
3. After proving service health recovered, the popup remained on the same
   screen for more than 47 minutes. It emitted no new proof request and exposed
   no cancel, retry, or failure action.
4. The line `Registering on the Psy network` / `正在 Psy 网络上注册` was only
   generic progress copy. Independent coordinator queries showed that the
   existing staging public key was still bound to user `704512`, while that
   key had not been registered on the local coordinator. Do not treat this
   animation as transaction-submission evidence.
5. Reloading the extension runtime cleared the orphaned operation and returned
   the popup to the unlock screen. Encrypted wallet storage was still present;
   no account reset or duplicate registration was required.

Classification: wallet/provider recovery defect. An interrupted or lost
background/offscreen request can leave the popup's `loadWallets`/initialization
promise pending indefinitely. Service recovery alone does not reconnect or
reject that promise.

Until fixed:

- do not click unlock, create-account, or network-save repeatedly;
- first query the relevant coordinator for the public key and inspect prover
  logs for an active request;
- if no request is active and the chain state is already known, reload only
  the extension runtime and confirm encrypted wallet data remains present;
- retry once, and preserve the first failure as evidence.

Required automated regression:

- start unlock/restore with a disposable account;
- interrupt the proving request after the popup enters initialization;
- restore the proving service;
- assert that the wallet reaches either a successful unlocked state or an
  actionable error with retry/cancel within a bounded timeout;
- assert that reopening the popup cannot retain an unbounded spinner and that
  no duplicate registration is submitted.

### 2026-07-28 local App transaction run

The first isolated run used Lenovo profile `psy_local_test`, CDP port `9223`,
Psy Wallet `0.4.25`, one fresh Psy user, and one freshly initialized disposable
MetaMask account. Secrets and private receive material were not persisted in
the report.

Passed:

- fresh Psy account registration was independently visible on the local
  coordinator;
- App connected both injected wallets and showed the correct Psy identity;
- the standalone local ETH faucet funded the disposable L1 account;
- App USDT faucet completed once and its L1 balance became 10,000 USDT;
- a 10 USDT deposit completed its L1 approval and deposit, became claimable,
  was claimed once through Psy Wallet, and settled with a 10 USDT L2 balance;
- a 10 PSY withdrawal burned on L2 at checkpoint 9720 and settled on local L1.
  The L1 claim transaction was
  `0x2ce99bb6425dccdc687df8331a39fb5cb54b473ced8df4d6f60ce7f6ed173e47`
  in block 62673, and the recipient token balance changed from 0 to
  10,000,000,000 base units (10 PSY);
- the App receipt subsequently rendered `Settled` and `Settled on ETH`.
- two fresh disposable Psy users completed a wallet-native private transfer:
  the sender's 5 PSY `private_transfer` was included at checkpoint 9897,
  Nostr delivery succeeded on the first attempt, the receiver saw the 5 PSY
  UTXO without importing the backup, and its `private_claim` was included at
  checkpoint 9906. The receiver's spendable balance increased by about 4 PSY
  after the displayed claim fee;
- the same two users completed a 5 PSY public transfer in the opposite
  direction. The sender transaction was indexed at checkpoint 9938, the
  receiver identified it as a public payment from the correct Psy ID, and the
  receiving claim was included at checkpoint 9950.

Observed defects and non-blocking findings:

1. **Local faucet copy and missing gas-faucet step.** The connected wallet was
   already on Localhost (chain ID 31338), but `/faucet` still said `Sepolia
   ETH`, instructed the user to use faucets in step 3, and numbered the next
   visible section as step 4. In local mode `NATIVE_FAUCETS` is empty, so step
   3 is hidden even though the separate local ETH faucet is healthy. The local
   page must use the configured L1 network/gas labels and link or embed the
   local ETH faucet.
2. **Back to Bridge leaves the connected App.** On the raw `/faucet` route,
   the button calls `window.location.assign('/')`. The current root renders the
   marketing landing, so the user loses the connected Bridge shell instead of
   returning to `/#/bridge`. The App smoke records this as
   `faucet_back_does_not_open_bridge`.
3. **Misleading account-creation error survives in wallet 0.4.25.** Fresh
   account creation succeeded in about 12 seconds and the coordinator confirmed
   the new user, but the popup and service worker each logged an `offscreen
   addUser error`. No error was shown to the user and the account was usable.
   Treat the log as a wallet defect/regression, not as failed registration.
4. **Withdrawal proof availability races the first relayer retry budget.** The
   withdrawal nonce timestamp was `02:33:54Z`. The first relayer batch began at
   `02:36:06Z` and exhausted proof polling at `02:37:01Z`. Psy-services first
   returned a found proof at `02:37:35Z`, roughly 34 seconds after that budget
   expired. The next relayer round generated the G16 proof and submitted the
   successful L1 claim at `02:38:29Z`; the receipt confirmed at `02:38:30Z`.
   End-to-end settlement was about 276 seconds. Do not classify the transient
   first-round ERROR as a failed withdrawal when the same identity later has a
   successful `WithdrawalClaimed`/token transfer and balance delta.
5. The App remained at `waiting for signature` while Psy Wallet was already
   executing the deposit claim. It eventually settled without intervention.
   This is currently a progress-label observation, not a transaction failure.
6. **psy-services cannot verify wallet NIP-59 private-transfer events.** At the
   successful private-transfer delivery time, psy-services emitted repeated
   `Nostr proof verification failed` warnings with `parse content JSON`.
   Wallet 0.4.25 correctly publishes an encrypted NIP-44/NIP-59 kind-1059
   gift-wrap whose outer tag is `psy_private_transfer_proof`; its `content` is
   ciphertext. The deployed services verifier selects that tag and immediately
   runs `serde_json::from_str(event.content)`, while its subscriber comment and
   parsing path assume plaintext JSON content. The receiver decrypts the same
   event locally, so wallet delivery and claim pass, but services stores the
   proof as unverified and cannot provide the intended independently verified
   private-claimable visibility. This is a wallet/services event-contract
   mismatch, not a failed Nostr delivery.

The reusable private-transfer helper was updated during this run to select the
real wallet home target when duplicate popup targets exist, redact shield/Nostr
identifiers in button output, and wait through the final `Updating your
balance` phase. The old condition returned while the claim progress modal was
still visible.

The final read-only status check passed: all managed processes and public local
endpoints were healthy, coordinator/realm0/realm1 converged at checkpoint
10029, and checkpoints advanced during the second sample. The Nostr verifier
warnings above remain a product defect even though overall node health passed.

### Optional Explorer wallet state run

This checks connect, approval, disconnect, reconnect, `accountsChanged`,
account-specific Users navigation, lock behavior, and restoring the original
account. It needs two existing disposable account names in `psy_local_test`:

```bash
RUN_IDE=0 RUN_APP=0 RUN_WALLET_STATE=1 \
PSY_EXPLORER_FIRST_ACCOUNT=<existing-account-name> \
PSY_EXPLORER_SECOND_ACCOUNT=<second-disposable-account-name> \
  e2e/local-testnet/run-playwright-e2e.sh
```

Create a fresh second account first when the test request requires one:

```bash
cd e2e/ide-explorer
PSY_WALLET_ACCOUNT_NAME=<unique-name> npm run test:wallet:lenovo:create
```

Do not put the wallet password in this document or command history. Supply it
through the existing secure test environment when the profile is locked.

### Transactional UI coverage

The default Playwright run intentionally does not duplicate bridge
transactions. Run CLI E2E first to establish backend correctness. Real UI
deposit/claim/withdraw or private-transfer tests require separate explicit
authorization and exactly-once handling of wallet confirmations. Follow:

- [`e2e/ide-explorer/APP_AUTOMATION_TEST_PROMPT.md`](../../e2e/ide-explorer/APP_AUTOMATION_TEST_PROMPT.md)
- [`e2e/ide-explorer/AUTOMATION_TEST_PROMPT.md`](../../e2e/ide-explorer/AUTOMATION_TEST_PROMPT.md)

Never resubmit after a UI timeout until the existing Activity receipt, wallet
popup, transaction hash, and chain state have been checked.

## Final report contract

Report each part independently:

```text
Environment and source revisions:
CLI E2E: Pass/Fail/Not run
  faucet:
  simple_claim:
  deposit + claim_deposit:
  withdraw + L1 settlement:
  checkpoints:
Playwright E2E: Pass/Fail/Not run
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
frontend, wallet/provider, or external browser-machine infrastructure. A retry
does not erase the first failure; preserve both results and explain whether it
was a product defect, asynchronous race, or bad assertion.
