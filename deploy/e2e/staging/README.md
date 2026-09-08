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
   bash deploy/e2e/staging/tests/test-multichain-init.sh
   ```

2. Per-network read-only readiness:

   ```bash
   deploy/e2e/staging/run-multichain-e2e.sh status /absolute/private/matrix-dir
   ```

3. Full CLI protocol E2E after explicit transaction authorization:

   ```bash
   AUTHORIZED_STAGING_TRANSACTIONS=1 \
     deploy/e2e/staging/run-multichain-e2e.sh run /absolute/private/matrix-dir
   ```

4. Read-only published frontend E2E:

   ```bash
   deploy/e2e/staging/run-browser-e2e.sh
   ```

Initialize a matrix with three independent Psy identities and either one
shared funded EVM key or per-network keys:

```bash
MULTICHAIN_EVM_KEY_FILE=/secure/path/e.key \
  deploy/e2e/staging/run-multichain-e2e.sh init \
  "$PWD/.private/e2e-runs/release-$(date -u +%Y%m%dT%H%M%SZ)"
```

Never print, upload, or commit a matrix directory. It contains private keys,
notes, nullifiers, nonces, and recovery material.

To test with the exact packaged deployment CLI rather than a host-native build,
set `PSY_E2E_USER_CLI` to the absolute path of the verified release binary (for
example `$PWD/deploy/artifacts/bin/parth/psy_user_cli`). The wrapper and Rust
runner use the same override. Record its SHA-256 with the run evidence.

Public claim discovery uses services, then the runner waits for all three L2
endpoints to reach a common checkpoint and confirms a positive on-chain PSY
claim amount before calling `simple_claim`. This is a readiness check, not
permission to retry a failed mutation. An unresolved intent still blocks
automatic retry and must be reconciled against the original logs and chain.

### Recover an already-submitted deposit

Build the CLI from the current `deploy/multi-chain-gcp` tip, including the
L1 Keccak recovery fix. `add50ab2` introduced the flags but still compared L1
and L2 leaves using different hash schemes; it is not sufficient by itself.
The previous `ae7be034` binary cannot recover proofs. Both `run` and `recover-deposit` check
the CLI's required recovery flags before starting transactions. The wrapper
always performs an incremental build of the orchestrator to avoid stale tools.

```bash
cargo build --locked --release -p psy_user_cli --no-default-features
STAGING_CHAIN=base PSY_E2E_USER_CLI="$PWD/target/release/psy_user_cli" \
  deploy/e2e/staging/run-cli-e2e.sh recover-deposit "$RUN_ROOT/base" --token usdt
```

This command requires the retained intent, original stdout containing the L1
transaction hash and deposit index, registered p1 evidence, and saved note
secrets. It does not call faucet, approve, deposit submission, or L2 claim.
It passes `--resume-deposit-index`, `--resume-tx-hash`, and `--resume-chain-id`
without an L1 private key. The CLI checks the successful canonical receipt,
Router calldata and Bridge event, then generates the inclusion proof locally.
The runner accepts only a `proof_only` result with no new transaction hash and
the expected chain ID. Recovery writes the deposit phase evidence; the
original intent and logs are retained. A later authorized `run` skips that
deposit and proceeds to its L2 claim before continuing the remaining phases.

Use `STAGING_CHAIN=bsc` or `sepolia` with that profile's own run directory.
For non-default deposit amounts, pass the same `--deposit-usdt` or
`--deposit-psy` value as the original run; a mismatch fails calldata validation.
Do not delete an unresolved intent or generate replacement secrets. Recovery
does not restore lost secrets and is not proof of a completed L2 claim.

Validation: the deposit module's 10 tests, the runner's 13 tests, Bash syntax
and ShellCheck pass. A read-only Base Sepolia recovery of transaction
`0x14a08ca12258bd9864950ba165df466b9594c21026bca477a8bc41507394b413`
(chain index 2, deposit index 0) produced a mode-600 inclusion proof and a
`proof_only` result with no new transaction hash. Repeating recovery skipped
the completed phase; the previous CLI and a wrong expected chain ID were
rejected. This validation did not execute L2 claim or the full three-chain
matrix. The broader CLI library suite also has an unrelated failing
localhost withdrawal fixture lookup when localhost deployments are absent.

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

- `deploy/e2e/cli-full-e2e/` is the Rust implementation used by the wrappers, not a
  separate release entrypoint.
- `e2e/ide-explorer/` is the specialized local IDE/Explorer suite; its
  transactional IDE project is not part of the public multichain gate.
- `e2e/bridge-e2e.sh` is the legacy single-chain bridge script and is not an
  acceptance substitute.
- `deploy/gcp/fresh-staging/23_smoke_test_simple_mint.sh` is a deployment smoke
  test, not full protocol E2E.
- `deploy/gcp/tests/` contains static deployment-script regression tests.
