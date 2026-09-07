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

These are release inputs, not a claim that every running backend already uses
them. The Relayer has no independent source revision or local product patch.
The selected L1 constructor uses `Psy USDT` / `pUSDT`; internal deployment keys
remain compatible. Existing deployed token contracts are not renamed in place.

Wallet 0.4.26 was published separately from the multichain wallet branch. This
deployment-tool change does not regenerate its SDK or trigger another release.

## Pending DApp publication

DApp candidate `212aac031f206c53f26c79b56b0dcedb86fee19d` has been prepared and
tested separately. It must be explicitly authorized and published to
`PsyProtocol/psy-dapp:deploy/multi-chain-staging` before this profile pins it.
That push automatically publishes the App, Explorer, and Config frontends.

Until then, `source-versions.env` retains the previously published DApp pin,
`dddf10677b91894cb626b3e717702fc33feeb77f`. **This preparation is not the final
go-ahead for a fresh release.** Do not treat the old pin as the intended new
frontend candidate or change it to an unpublished SHA.

## Tooling verification

- Offline plan lists all 21 ordered steps without SSH, RPC, builds or writes
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

1. Publish the approved DApp source; verify the frontend workflow result and
   then update the profile pin in a reviewed follow-up commit.
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
