# BSC Testnet Deployment Plan

This document is the canonical staged plan for running Psy with BNB Smart
Chain Testnet as its L1. Work through the phases in order and record evidence
for every acceptance gate. Do not start public BSC or GCP deployment work until
the local BSC-mode environment passes.

The first target is an isolated Psy network backed by BSC Testnet. It is not a
second L1 attached to the existing Sepolia-backed Psy network.

## Goals

- Run the current Psy protocol against BSC Testnet, chain ID `97`.
- Validate contract deployment, indexing, relaying, proving, deposit, and
  withdrawal behavior locally before using public BSC Testnet.
- Keep the existing Sepolia staging network and all of its state unchanged.
- Keep network-specific values in a profile instead of duplicating deployment
  scripts.
- Produce reproducible manifests, logs, transaction hashes, and E2E evidence.

## Non-goals for the first release

- Simultaneous Sepolia and BSC support in one Psy L2 state.
- Migration of Sepolia balances, roots, transactions, or relayer cursors.
- BSC mainnet deployment.
- Native tBNB bridging before the wrapped-native path is independently tested.
- Replacing the existing Sepolia staging environment.

## External network facts

| Setting | BSC Testnet value |
| --- | --- |
| EVM chain ID | `97` (`0x61`) |
| Native gas token | `tBNB` |
| Explorer | `https://testnet.bscscan.com/` |
| Official RPC fallback | `https://bsc-testnet-dataseed.bnbchain.org` |
| Envio HyperSync | `https://bsc-testnet.hypersync.xyz` |
| Envio HyperRPC | `https://bsc-testnet.rpc.hypersync.xyz` |

References:

- [BNB Chain wallet configuration](https://docs.bnbchain.org/bnb-smart-chain/developers/wallet-configuration/)
- [BNB Chain JSON-RPC endpoints](https://docs.bnbchain.org/bnb-smart-chain/developers/json_rpc/json-rpc-endpoint/)
- [BNB Chain finality](https://docs.bnbchain.org/bnb-smart-chain/introduction/)
- [Envio BSC Testnet support](https://envio.dev/chains/bsc-testnet)

Do not use an unauthenticated public RPC as the only relayer or indexer RPC.
The official endpoints are suitable as fallbacks and smoke-test targets. Use a
dedicated provider endpoint for sustained deployment traffic.

## Safety invariants

These conditions apply to every phase.

1. Existing Sepolia services, databases, DNS records, contracts, and frontend
   projects must not be modified by BSC work.
2. BSC deployment state must use separate directories, service names, database
   names or keyspaces, NATS subjects, Redis prefixes, and relayer cursor files.
3. `l1ChainIndex` is a Psy bridge index, not EVM chain ID `97`.
4. Contract addresses must come from the generated
   `deployments/bsc-testnet/deployed-contracts.json`; do not copy Sepolia
   addresses.
5. A command that creates a transaction must require an explicit authorization
   environment variable.
6. Secrets must stay outside Git. Reports must redact RPC keys, private keys,
   wallet recovery material, private notes, and nullifiers.
7. A timed-out transaction must be investigated by hash before it is retried.
8. A phase cannot pass when a required test was skipped.

## Architecture decision

The first deployment is a fresh, isolated network:

```text
BSC Testnet
  StateManager / Bridge / Router / Gateways / Verifiers
  PsyToken / test USDT
        |
        v
Isolated Psy L2
  coordinator / realm0 / realm1
  workers / prove-proxy / faucet-server
  psy-services / indexers / Nostr
  BSC-specific Envio and relayer
        |
        v
BSC-specific App / Explorer / IDE / wallet network profile
```

The same GCP projects or physical machines may be reused later, but BSC
processes must remain isolated by ports, service instances, storage paths, and
state namespaces. Dedicated hosts are safer for the first public run.

## Open decisions

Resolve these decisions during the local phases. Record the result and the
supporting test below before deploying public contracts.

| Decision | Initial position | Required evidence | Final value |
| --- | --- | --- | --- |
| Psy `l1ChainIndex` | Reserve index `1`; do not assume it is correct | Deposit/withdraw top-tree and circuit tests | Pending |
| BSC confirmation policy | Keep the current conservative 10-block UI policy initially | Real BSC finality/indexer test | Pending |
| Native tBNB bridge | Disabled initially | Wrapped-native deposit and withdrawal E2E | Pending |
| Public RPC provider | Dedicated authenticated RPC plus official fallback | Rate, log, and failover test | Pending |
| Public domain names | Use a BSC-specific namespace | DNS and TLS review | Pending |

If index `1` conflicts with an existing protocol commitment, stop and resolve
the bridge-index allocation before proceeding. Never substitute `97`.

## Remaining implementation gaps

The canonical Genesis, contract, Bridge, Explorer, and IDE network models now
support `bsc-testnet`. The remaining work is concentrated in runtime and
public deployment integration:

- Audit and add the Psy Wallet BSC network profile.
- Extend the full local Psy stack launcher beyond the isolated L1 contract
  harness.
- `deploy/gcp/deploy-l1-contracts.sh` defaults unknown public networks to the
  localhost chain ID.
- `deploy/gcp/remote/deploy-l1-contracts.sh` maps RPC environment variables
  only for localhost and Sepolia.
- `deploy/gcp/deploy-relayer.sh` and fresh-deploy preflight apply public signer
  safety checks only to Sepolia.
- Envio defaults non-local polling to 12 seconds and needs an explicit BSC
  HyperSync profile.
- Add BSC-specific public frontend projects, config publication, DNS, and TLS.
- Run deposit/withdraw circuit tests that prove bridge index `1` is safe.

Changes should generalize the network model. Do not add scattered
`if network == bsc-testnet` branches where a profile or typed chain descriptor
can express the same behavior.

## Progress summary

Update this table as work proceeds.

| Phase | Description | Status | Evidence |
| --- | --- | --- | --- |
| 0 | Baseline and isolation | In progress | Clean product/deploy worktrees; isolated `.local-bsc-testnet` runtime |
| 1 | Canonical BSC network model | In progress | Genesis `25e5fa9`; contracts `a6f442f`; dapp `63978c1`; psy-node pins `708fd6b6`; wallet audit pending |
| 2 | Local L1 Chain ID 97 contract test | In progress | Full contract deployment passed; on-chain `l1ChainIndex=1`; token behavior and bridge transaction tests pending |
| 3 | Full local BSC-mode Psy E2E | Not started | |
| 4 | Public BSC contract-only deployment | Blocked by phases 1-3 | |
| 5 | Isolated cloud backend deployment | Blocked by phase 4 | |
| 6 | BSC frontend and wallet publication | Blocked by phase 5 | |
| 7 | Public full E2E and resilience | Blocked by phase 6 | |
| 8 | Operational handoff | Blocked by phase 7 | |

## Phase 0: Baseline and isolation

### Work

1. Record the pinned psy-node, psy-genesis, psy-contracts, psy-dapp,
   psy-services, wallet, and SDK commits in `deploy/source-versions.env`.
2. Confirm the deployment worktree differs from its product baseline only
   under `deploy/`.
3. Capture the current Sepolia staging health report and contract addresses.
4. Define a separate local runtime root, for example:

   ```text
   .local-bsc-testnet/
   ```

5. Define separate public resource names before any GCP work:

   ```text
   psy-bsc-testnet-*
   bsc_testnet_* databases/keyspaces
   /var/lib/parth-bsc-testnet/*
   ```

6. Add a BSC profile template containing no secrets.

### Acceptance gate

- Source pins and artifact checksums are recorded.
- The Sepolia baseline report is saved outside generated BSC state.
- No BSC script can resolve to the Sepolia database, relayer state, contract
  deployment directory, or frontend project by default.
- A dry run prints BSC-specific resource names without changing state.

### Stop conditions

- Any default BSC path points at an existing Sepolia state path.
- Product-source commits are ambiguous or dirty.
- The canonical Genesis contract checksum is not reproducible.

## Phase 1: Canonical BSC network model

Implement the network definition before changing deployment orchestration.

### Work

1. Add `bsc-testnet` to `psy-contracts/protocol-config`:

   ```text
   l1ChainId = 97
   l1ChainIndex = pending decision
   native currency = tBNB
   explorer = https://testnet.bscscan.com
   RPC = BSC_TESTNET_RPC_URL with a safe public fallback
   ```

2. Add `psy-contracts/config/bsc-testnet.json`.
3. Add the Hardhat BSC Testnet network and verification adapter.
4. Add BSC deployment artifact loading without committing generated addresses
   before deployment.
5. Add `bsc-testnet` to the canonical `psy-genesis/config.json` and the dapp
   copy consumed by browser builds.
6. Replace frontend network-name unions and explorer-link switches with typed
   protocol configuration.
7. Make deposit confirmation count network-configurable. Keep its BSC initial
   value at 10 until phase 4 gathers real finality evidence.
8. Replace user-visible hard-coded Ethereum wording in active BSC paths with
   configured chain names.

### Required tests

- Protocol config resolves `bsc-testnet` and rejects unknown names.
- Hardhat reports chain ID 97 for `--network bsc-testnet`.
- Frontend config generation agrees across psy-genesis, psy-contracts, and
  generated deployment metadata.
- Wallet add/switch network payload uses `0x61`, `tBNB`, and the BSC Testnet
  explorer.
- A bridge chain index test proves the selected index is used consistently in
  contract config, frontend deposit metadata, relayer config, and circuits.

### Acceptance gate

- Unit and config-consistency tests pass.
- No BSC build falls back to Sepolia or Ethereum when a required value is
  missing; it fails with an actionable configuration error.
- No generated transaction has EVM chain ID or Psy chain index silently set to
  zero because parsing failed.

## Phase 2: Local L1 Chain ID 97 contract test

This phase validates EVM and configuration compatibility without touching
public BSC Testnet.

### Local profile

Start a separate Anvil instance with:

```text
chain ID: 97
state path: .local-bsc-testnet/anvil
RPC port: separate from the normal local testnet
deployment network: bsc-testnet
```

Do not reuse the normal local Anvil data directory or localhost deployment
artifact.

### Work

1. Deploy all required L1 contracts to local chain ID 97.
2. Generate `deployments/bsc-testnet/deployed-contracts.json` in an isolated
   build/output directory.
3. Verify deployed bytecode and configured addresses by RPC.
4. Verify `StateManager.l1ChainIndex()` matches the chosen protocol index.
5. Verify proposer/admin/finalizer addresses and permissions.
6. Test PSY and test-USDT faucet/mint behavior.
7. Test ERC-20 allowance, deposit, deposit event decoding, withdrawal root
   publication, and withdrawal claim.
8. Keep native tBNB bridging disabled unless its dedicated test is enabled.

### Required evidence

- Local L1 deployment manifest and bytecode hashes.
- Contract addresses and deployment transaction receipts.
- StateManager chain-index query.
- Deposit and withdrawal transaction hashes.
- Final token balance deltas for both directions.

### Evidence recorded 2026-08-25

- Isolated Anvil started at `127.0.0.1:18545` with EVM chain ID `97`.
- The full Hardhat deployment completed and generated a BSC-specific manifest.
- `StateManager.l1ChainIndex()` returned `1` on chain.
- Bridge, StateManager, Router, ERC20Gateway, TokenFaucetManager, PsyToken, and
  USDTToken all returned non-empty bytecode.
- The BSC Bridge build consumed the generated manifest without deterministic
  placeholders and included the BSC Testnet wallet/explorer metadata.
- Evidence is runtime-generated under `.local-bsc-testnet/evidence/` and is
  intentionally excluded from Git.

### Acceptance gate

- Contracts deploy from a clean checkout using only the BSC profile.
- Repeating read-only verification produces the same manifest.
- ERC-20 deposit and withdrawal complete on chain ID 97.
- A deliberately wrong chain ID and wrong Psy chain index are both rejected.

### Optional fork test

After the plain Anvil test passes, run a separate Anvil fork of BSC Testnet at
a pinned block. This catches BSC-specific RPC and gas-estimation behavior but
does not replace a real BSC finality test.

## Phase 3: Full local BSC-mode Psy E2E

Extend the existing local testnet tooling with a BSC profile. Do not fork the
entire local deployment implementation.

### Work

1. Start isolated Docker dependencies and Psy services using BSC-specific
   state namespaces.
2. Start coordinator, both realms, cloud-equivalent workers, prove-proxy,
   faucet-server, psy-services, indexers, Nostr, Envio, and relayer.
3. Point Envio and relayer at the local chain ID 97 RPC.
4. Publish local BSC-profile App, Explorer, IDE, and wallet configuration.
5. Run the complete transaction flow with disposable users.

### Transaction acceptance flow

1. Register a new Psy user.
2. Request faucet funds and complete `simple_claim`.
3. Execute one public transfer.
4. Execute one private transfer and private claim.
5. Mint or faucet local L1 test USDT.
6. Deposit USDT from local BSC-mode L1 to Psy and claim it.
7. Withdraw USDT from Psy to local BSC-mode L1 and verify the L1 balance
   increase.
8. Restart Envio, relayer, psy-services, and one node independently.
9. Confirm replay is idempotent and no deposit or withdrawal is duplicated.

### Evidence directory

Use a dedicated path such as:

```text
e2e/bsc-testnet/test-results/local/<UTC-run-id>/
```

Store mode-600 logs containing:

- user IDs and public transaction hashes;
- L1 transaction hashes and block numbers;
- deposit index and source chain index;
- checkpoint IDs for claims and withdrawals;
- relayer cursor before and after restart;
- contract and token balance queries;
- service status and error summaries.

Do not store private keys, private note plaintext, or nullifiers.

### Acceptance gate

- All transaction flows pass without a skipped required step.
- Coordinator and realms remain synchronized and advancing.
- Envio reaches the current local L1 head.
- Relayer pending/proved/finalized counters converge.
- Restart tests do not duplicate state or lose queued work.
- Browser UI identifies the network as BSC Testnet and uses BscScan-style
  links without Ethereum/Sepolia copy in the active flow.

## Phase 4: Public BSC contract-only deployment

This phase touches BSC Testnet but does not start the public Psy backend.

### Preconditions

- Phases 0 through 3 have passed and evidence is attached to the relevant PR.
- The L1 deployer/finalizer address is fixed and backed up.
- The deployer has sufficient tBNB.
- A dedicated authenticated BSC RPC is configured, with an independent
  fallback.
- Groth16 verifier artifacts match the pinned circuit source and manifest.

### Work

1. Record the BSC head and chosen `START_BLOCK` immediately before deployment.
2. Deploy contracts from the pinned clean source checkout.
3. Save the deployment artifact and transaction receipts.
4. Verify all supported contracts on BscScan.
5. Query every critical contract address, role, verifier, token, gateway, and
   `l1ChainIndex` directly through a second RPC provider.
6. Start an isolated Envio instance from the deployment block and verify it can
   decode deployment and test events.
7. Measure BSC finalized height versus latest height and record the initial
   confirmation policy decision.

### Acceptance gate

- All critical contracts have matching bytecode and expected owners/roles.
- BscScan verification succeeds or any unsupported verification path has a
  documented manual procedure.
- Envio reaches the BSC head without sustained 429 responses.
- The secondary RPC agrees on contract code and deployment receipts.
- No Sepolia deployment artifact or service configuration changed.

### Rollback

Public contract deployment cannot be rolled back. A failed contract set is
abandoned and a new versioned set is deployed. Do not overwrite the last known
good deployment manifest.

## Phase 5: Isolated cloud backend deployment

### Proposed profile

Create a non-secret profile similar to:

```bash
L1_NETWORK="bsc-testnet"
L1_DEPLOYMENTS_NETWORK="bsc-testnet"
CHAIN_ID="97"
L1_NATIVE_SYMBOL="tBNB"
L1_EXPLORER_URL="https://testnet.bscscan.com"
ENVIO_USE_HYPERSYNC="1"
ENVIO_HYPERSYNC_URL="https://bsc-testnet.hypersync.xyz"
ENVIO_CONFIRMED_BLOCK_THRESHOLD="10"
ENVIO_RPC_POLLING_INTERVAL_MILLIS="1000"
START_BLOCK="<deployment-block>"
```

Keep RPC URLs, API tokens, keystore paths, and passwords in the protected
environment config, not this profile.

### Work

1. Prebuild and checksum all binaries, frontends, Genesis state, and Groth16
   artifacts before starting services.
2. Provision or select isolated stateful infrastructure.
3. Deploy coordinator and realms with new Genesis state.
4. Deploy baseline cloud workers before optional offsite workers.
5. Deploy prove-proxy and faucet-server.
6. Deploy psy-services, indexers, Nostr, and BSC Envio.
7. Deploy the BSC relayer with separate cursor and durable state files.
8. Fund the relayer L1 signer with tBNB and its L2 user through Genesis or a
   documented treasury allocation.
9. Keep every BSC public endpoint private until backend acceptance passes.

### Acceptance gate

- Coordinator and realms remain synchronized and advance for at least 30
  minutes.
- Baseline cloud workers pick up and complete jobs.
- Prove-proxy initializes all required circuits without OOM or sustained swap
  pressure.
- Envio and psy-services ingest new data.
- Relayer reaches the latest eligible Psy checkpoint and current BSC indexed
  height.
- A backend-only CLI E2E passes before public frontend publication.

## Phase 6: BSC frontend and wallet publication

Use distinct Cloudflare Pages projects, R2 artifacts, and domains. Suggested
names are placeholders until DNS review:

```text
app-bsc-testnet.psy-protocol.xyz
explorer-bsc-testnet.psy-protocol.xyz
ide-bsc-testnet.psy-protocol.xyz
coordinator-bsc-testnet.psy-protocol.xyz
realm0-bsc-testnet.psy-protocol.xyz
realm1-bsc-testnet.psy-protocol.xyz
prove-bsc-testnet.psy-protocol.xyz
faucet-bsc-testnet.psy-protocol.xyz
services-bsc-testnet.psy-protocol.xyz
indexer-bsc-testnet.psy-protocol.xyz
nostr-bsc-testnet.psy-protocol.xyz
```

### Acceptance gate

- Frontends load only BSC-specific configuration and deployment addresses.
- MetaMask add/switch network requests Chain ID `0x61` and displays tBNB.
- Transaction and block links resolve to BSC Testnet explorer pages.
- Wallet download points to the intended BSC-compatible build manifest.
- Sepolia Pages projects, R2 objects, and domains remain unchanged.

## Phase 7: Public E2E and resilience

Run the same required transaction sequence as phase 3 using disposable BSC
Testnet accounts funded with tBNB.

Additionally test:

1. Primary RPC failure with fallback read RPC available.
2. Envio restart and replay from its durable cursor.
3. Relayer restart with an in-flight deposit and withdrawal.
4. Prove-proxy restart between request and response.
5. One worker unavailable while baseline capacity remains.
6. BSC latest versus finalized-height behavior.
7. Duplicate event delivery and idempotent psy-services ingestion.
8. Rate limiting and malformed public RPC requests.

### Acceptance gate

- Faucet, claim, public transfer, private transfer, deposit, and withdrawal all
  pass.
- L1 and L2 balance deltas agree with fees.
- No required component emits an unexplained ERROR during the acceptance
  window.
- Recoverable polling misses are WARN-level and converge within their bounded
  retry policy.
- Restart and failover tests do not duplicate or lose bridge operations.

## Phase 8: Operational handoff

Before declaring the environment available to testers, document:

- exact source commits and artifact checksums;
- contract addresses and BscScan verification links;
- public and private endpoint inventory;
- service-to-host mapping and SSH access path;
- state directories, database names, and backup policy;
- relayer L1 and L2 addresses and funding thresholds;
- RPC provider quotas and fallback order;
- Envio token location and rate-limit alarms;
- PagerDuty/Slack alerts for stalled checkpoints, worker failures, relayer gas,
  RPC errors, disk, memory, and OOM;
- rollback and full-redeploy procedures;
- canonical CLI and Playwright E2E commands.

## PR structure

Keep implementation reviewable with separate changesets:

1. **Network model:** protocol config, Genesis config, typed frontend network
   support, and config tests.
2. **Contracts:** BSC Hardhat network, deployment config, verification, and
   contract tests.
3. **Local deployment:** isolated chain ID 97 profile, local stack integration,
   and local E2E.
4. **Backend profile:** relayer, Envio, signer safety, state isolation, and GCP
   dry-run tests.
5. **Frontend publication:** App, Explorer, IDE, wallet network profile, and
   Cloudflare project isolation.
6. **Public E2E and operations:** acceptance wrappers, reports, alerts, and
   handoff documentation.

Do not combine public deployment execution with the PR that first introduces
network support. Merge and validate each phase before starting the next one.

## Next action

Start phase 0 and phase 1 only. The first implementation milestone is:

```text
A clean local build can select bsc-testnet, report EVM chain ID 97, preserve a
separate Psy bridge chain index, and generate internally consistent contract,
Genesis, frontend, and wallet configuration without touching Sepolia state.
```

After that milestone passes, add the separate local Anvil chain ID 97
deployment and run phase 2.
