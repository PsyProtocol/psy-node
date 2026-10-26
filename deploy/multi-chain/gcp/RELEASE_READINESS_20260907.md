# Multichain release preparation, 2026-09-07

Scope: local deployment tooling and offline verification. No fresh deployment,
database reset, new Genesis, L1 contract deployment, backend restart, or live
transaction E2E was performed during this preparation.

## Source decisions

| Component | Repository | Selected published source |
| --- | --- | --- |
| Node and Relayer | PsyProtocol/psy-node | `ae7be0348287589207c89cce46ce2db6865f27ab` |
| Services and Indexer | PsyProtocol/psy-services | `9122e5de2d33ea6aba6d7bef101e742198879836` |
| L1 contracts | PsyProtocol/psy-contracts | `d59d83ecb7508669606f650fa0abbc1abffbcb15` |
| Genesis | PsyProtocol/psy-genesis | `628e2fc785d61ccd780dc6a500a7fd7cf9ae161c` |
| Wallet | PsyProtocol/psy-wallet | `5ecd8c02b6013413d658b46592dd9115d94bba4e` |
| Monitoring | PsyProtocol/psy-notifier | `9d85ffada628a19a2b561f61b071788fe49b650c` |

These are release inputs, not a claim that every running backend already uses
them. The Relayer has no independent source revision or local product patch.
The selected L1 constructor uses `Psy USDT` / `pUSDT`; internal deployment keys
remain compatible. Existing deployed token contracts are not renamed in place.

Wallet 0.4.26 was published separately from the multichain wallet branch. This
deployment-tool change does not regenerate its SDK or trigger another release.

## DApp publication

DApp `212aac031f206c53f26c79b56b0dcedb86fee19d` was pushed with operator
authorization to `PsyProtocol/psy-dapp:deploy/multi-chain-staging` on September 7.
Remote reachability was verified before advancing this profile's pin.
The App, Explorer, and Config frontend workflow completed successfully for
this exact SHA (GitHub Actions run `34117641844`). Git push and workflow
success were checked separately.

The selected source is now pinned in `source-versions.env`. **This source
update alone is not a successful fresh deployment or full E2E acceptance.**

## Tooling verification

- Offline plan lists all 22 ordered steps without SSH, RPC, builds or writes
  to the runtime deployment state.
- Runner fixtures cover selection, failure propagation, private logs, and
  preserving sources during partial runs.
- L1 fixtures cover failure after one successful chain, rejection of stale
  manifests, concurrent invocation exclusion, and complete atomic publication.
- Source fixtures reject product/Cargo drift and preserve exact metadata
  exceptions needed by deployment branches.
- Submodule preparation initializes missing children only; existing children
  reach the shared dirty-tree guard without an earlier checkout.
- Rust CLI E2E is a standalone workspace under `deploy/e2e/`, with 11 unit
  tests. Three-chain init tests use disposable local fixtures, not live funds.
- ShellCheck and Bash syntax checks cover the changed orchestration scripts.

These checks do not prove RPC balances, live DNS/SSH availability, real contract
deployment, current service health, or transaction settlement.

## Before authorizing a fresh deployment

1. Verify the published DApp SHA and successful workflow against the profile
   pin. Publication and workflow verification are complete as recorded above.
2. Prepare pinned submodules in a clean dedicated checkout. Preserve private
   config, signer files, and current deployment artifacts outside Git.
3. Run both profile and shared preflight without dirty-source, RPC, or DNS
   bypasses. Check the deployer/Relayer gas balance on all three chains.
4. Review the offline plan and separately authorize destructive replacement.
5. After deployment, run node health checks and the Base/BSC/Sepolia CLI and
   browser acceptance flows. A smoke test alone is not full E2E acceptance.

The shared workspace's uncommitted standalone Relayer updater and fixed-wallet
wrapper were not swept into this delivery. They need their own scoped review;
this runner's fresh-deployment Relayer step remains the existing shared step.

## Follow-up audit, September 7

Read-only checks around 10:59 UTC observed the coordinator progressing from
24772 to 24774, with realms at most one checkpoint behind. Expected cloud and
offsite services were active, including exactly three cloud workers. Public
service/frontend endpoints responded successfully. These spot checks are not
a full log audit or transaction E2E run and do not establish release readiness.

Audit issues and their current status:

- Open, transaction-test recovery: `deploy/e2e/cli-full-e2e/src/main.rs` calls
  `--resume-deposit-index`, but the selected Node `ae7be034` CLI does not expose
  it. The implementation exists only in an older shared checkout's local
  patches. Resolve the CLI/tool interface through committed, reviewed source
  before accepting timeout recovery; do not blindly resubmit an L1 deposit.
- Resolved, funding gate: the deployer/Relayer address `0x490f8192725255c2c3de0cbce66312335ca019ad`
  had approximately 0.0953605 ETH on Base Sepolia, below the current default
  preflight minimum of 0.1 ETH. The operator subsequently funded 0.02 ETH;
  the real profile preflight passed with approximately 0.11534 ETH on Base.
  These are time-specific observations, not a permanent gas-budget guarantee.
- Resolved, DApp: publication, the downstream pin update and frontend workflow run
  `34117641844` have since been completed successfully.

The fixed E2E wallet already exists at the ignored workspace path
`.private/test-wallets/staging-multichain/wallet.json`; its address is
`0x5c30fa7525ce6ed04d051730cda40671b509e0cc`. Read-only checks found native gas
on all three chains. No private key was copied into this report or rotated.

Step 32 now integrates the pinned monitoring fleet installer. Source checks,
orchestration and freshness predicates have offline fixture coverage. No
monitoring deployment, restart or test notification was performed here.
See [monitoring prerequisites and acceptance limits](MONITORING.md).
