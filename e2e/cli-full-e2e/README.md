# Psy staging CLI E2E

This resumable orchestrator drives the deployment-matching `psy_user_cli`
and Foundry `cast`. It covers disposable user registration, contract
deployment, standalone faucet and claim, L1 token faucet, deposits and claims,
withdrawal settlement, and bidirectional public and private transfers.

## Supported L1 profiles

| Profile | EVM chain ID | Bridge chain index | Deployment directory |
| --- | ---: | ---: | --- |
| `sepolia` | 11155111 | 0 | `psy-contracts/deployments/sepolia` |
| `bsc` | 97 | 1 | `psy-contracts/deployments/bscTestnet` |
| `base` | 84532 | 2 | `psy-contracts/deployments/baseSepolia` |

The selected network, chain ID, bridge chain index, and deployment directory
are persisted in the run manifest. `status` and `run` reject a mismatched
profile instead of silently querying another L1.

The current deposit and claim CLI resolves individual contract artifacts from
a legacy `deployments/localhost` path. `init` creates that compatibility copy
inside the private run directory and copies the complete selected deployment
artifact set. It does not alter repository deployment files.

## Build

```bash
cargo build --release -p psy_cli_full_e2e -p psy_user_cli
```

Validate all profile mappings and private run-directory construction without
accessing the network or submitting transactions:

```bash
e2e/staging/tests/test-multichain-init.sh
```

## Single-chain run

Use a single profile while debugging or resuming one chain. BSC is the default
when `STAGING_CHAIN` is omitted.

```bash
STAGING_CHAIN=base e2e/staging/run-cli-e2e.sh init /tmp/psy-base-e2e
STAGING_CHAIN=base e2e/staging/run-cli-e2e.sh status /tmp/psy-base-e2e

AUTHORIZED_STAGING_TRANSACTIONS=1 \
STAGING_CHAIN=base \
  e2e/staging/run-cli-e2e.sh run /tmp/psy-base-e2e
```

`init` writes mode-600 disposable keys and prints only the public L1 address.
Fund it with the selected chain's native test token before `status` or `run`.
An existing disposable key can be imported as the second `init` argument.

RPC endpoints default to the public staging domains. Override them with
`SEPOLIA_RPC_URL`, `BSC_TESTNET_RPC_URL`, or `BASE_SEPOLIA_RPC_URL`.
`STAGING_L1_RPC_URL` is available only for a single-chain invocation.

## Complete three-chain run

The release-level entry creates an independent run and disposable account for
each supported L1:

```bash
e2e/staging/run-multichain-e2e.sh init /tmp/psy-multichain-e2e
e2e/staging/run-multichain-e2e.sh status /tmp/psy-multichain-e2e

AUTHORIZED_STAGING_TRANSACTIONS=1 \
  e2e/staging/run-multichain-e2e.sh run /tmp/psy-multichain-e2e
```

Fund all three printed addresses with Sepolia ETH, tBNB, and Base Sepolia ETH
respectively. Existing funded disposable keys may be supplied through
`SEPOLIA_EVM_KEY_FILE`, `BSC_EVM_KEY_FILE`, and `BASE_EVM_KEY_FILE` during
initialization. To use one persistent MetaMask-compatible test address on all
three EVM chains, set `MULTICHAIN_EVM_KEY_FILE` instead; a per-chain variable
overrides it when both are set.

The matrix executes serially to bound prove-proxy memory use. It fails fast by
default. `MULTICHAIN_E2E_FAIL_FAST=0` runs the remaining chains after a failure,
but the final result still fails unless all three chains pass. A skipped or
unfunded profile must not be reported as a complete multichain pass.

## Recovery and evidence

Every mutating phase writes an intent before submission and an `.ok.json`
checkpoint only after independent verification. An unresolved intent blocks
automatic resubmission. After a timeout, inspect the saved CLI log, L1 receipt,
psy-services response, and chain state before deciding whether to resume.

The default test contract is the deterministic small artifact at
`e2e/staging/fixtures/e2e-contract.json`; it avoids coupling the E2E to the
genesis token artifact format.

Run directories contain private keys and note material. Do not share or archive
them without removing keys, notes, nullifiers, nonces, and deposit proofs.
