# Public multichain staging E2E

This directory contains the canonical release acceptance entrypoints for the
public staging deployment. Required network order is Base Sepolia, BSC
Testnet, then Ethereum Sepolia. Transaction suites run serially so only one L1
profile drives prove-proxy at a time.

## Standard gates

1. Static deployment/profile checks:

   ```bash
   bash deploy/gcp/tests/test-source-versions.sh
   bash deploy/gcp/tests/test-multichain-profile.sh
   bash deploy/gcp/tests/test-frontend-workflow-safety.sh
   bash e2e/staging/tests/test-multichain-init.sh
   ```

2. Per-network read-only readiness:

   ```bash
   e2e/staging/run-multichain-e2e.sh status /absolute/private/matrix-dir
   ```

3. Full CLI protocol E2E after explicit transaction authorization:

   ```bash
   AUTHORIZED_STAGING_TRANSACTIONS=1 \
     e2e/staging/run-multichain-e2e.sh run /absolute/private/matrix-dir
   ```

4. Read-only published frontend E2E:

   ```bash
   e2e/staging/run-browser-e2e.sh
   ```

Initialize a matrix with three independent Psy identities and either one
shared funded EVM key or per-network keys:

```bash
MULTICHAIN_EVM_KEY_FILE=/secure/path/e.key \
  e2e/staging/run-multichain-e2e.sh init \
  "$PWD/.private/e2e-runs/release-$(date -u +%Y%m%dT%H%M%SZ)"
```

Never print, upload, or commit a matrix directory. It contains private keys,
notes, nullifiers, nonces, and recovery material.

## Coverage

The CLI suite verifies, on every L1 profile: two user registrations, contract
deployment, faucet and `simple_claim`, bidirectional public transfer and
claim, bidirectional private transfer and claim, PSY and USDT deposits with L2
claims, PSY and USDT withdrawals with L1 settlement, synchronized final
checkpoints, equal pending/proved deposit counters, services responses, and
L1 balance changes.

The browser suite verifies that the published App contains all three public
profiles without private RPC leakage, then executes separate Base, BSC, and
Sepolia browser-origin chain ID and Bridge bytecode checks. It also verifies
that the published Explorer renders. It does not connect a wallet or submit a
transaction.

## Evidence

Each CLI profile stores exactly-once intent and `.ok.json` phase evidence in
its private run directory. The matrix wrapper stores operation logs and a
summary under `matrix-evidence/<UTC-run-id>/`. The browser wrapper stores a
sanitized context, JSON report, attachments, log, and result under
`.private/e2e-runs/staging-browser.<run-id>/`.

During a full matrix run, retain before/during/after prove-proxy cgroup memory,
swap, OOM counters, and service logs. A pass is not complete if a profile was
skipped, an unresolved intent remains, or prove-proxy restarted/OOMed.

## Other test assets

- `e2e/cli-full-e2e/` is the Rust implementation used by the wrappers, not a
  separate release entrypoint.
- `e2e/ide-explorer/` is the specialized local IDE/Explorer suite; its
  transactional IDE project is not part of the public multichain gate.
- `e2e/bridge-e2e.sh` is the legacy single-chain bridge script and is not an
  acceptance substitute.
- `deploy/gcp/fresh-staging/23_smoke_test_simple_mint.sh` is a deployment smoke
  test, not full protocol E2E.
- `deploy/gcp/tests/` contains static deployment-script regression tests.
