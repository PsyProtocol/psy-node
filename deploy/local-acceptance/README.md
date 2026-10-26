# Isolated Release Acceptance

Deployment-only overlay for the native `make run-all` launcher. This is a local
CLI acceptance environment, not a cloud rollout or a frontend publication.
The Psy stage is `testnet`, retaining magic `0x1337CF514544CF69`. The three L1s
are independent local Anvil chains, not public testnets.

## Prepare

Supply clean, reviewed source checkouts matching
`deploy/multi-chain/gcp/source-versions.env`, and release binaries built with
`PSY_NETWORK=testnet` and the cohort's Genesis config.

```bash
export COHORT_DIR=/path/to/release-cohort
export ACCEPTANCE_ROOT="$COHORT_DIR/local-acceptance"
export NODE_ARTIFACT_DIR=/path/to/node/target/release
export SERVICES_ARTIFACT_DIR=/path/to/services/target/release
bash deploy/local-acceptance/prepare.sh
```

Preparation refuses to overwrite an existing runtime. It records checksums,
uses the public Anvil development key for the relayer Genesis allocation, and
does not copy a real relayer wallet. The services build must also use the new
Genesis config even when its Cargo dependency still pins an older Node revision.

Generate fresh setup for this cohort; never copy production setup implicitly:

```bash
"$ACCEPTANCE_ROOT/psy-node/target/release/psy_relayer_cli" regenerate-groth16-keystore \
  --keystore-dir "$ACCEPTANCE_ROOT/home/.psy/keystore" --include-bridge-agg
```

Keep the successful generation/proof verification log and record SHA256 for the
generator and all nine `circuit_groth16.bin`, `pk_groth16.bin`, and
`vk_groth16.bin` files (root, `deposit_append/`, `withdrawal_claim/`) in
`evidence/setup-sha256.txt`. The launcher requires both setup and runtime
manifests; hashes alone do not replace generation provenance.

## Start And Stop

```bash
bash deploy/local-acceptance/run.sh
```

The command stays in the foreground. Stop with Ctrl-C. It terminates its own
process group and stops only its scoped Compose projects, preserving volumes
and logs. Do not use the legacy global `make shutdown` or local-multichain
start/stop scripts against this environment. Existing acceptance infrastructure
causes a refusal; inspect it before deciding whether to resume or start fresh.

Infrastructure uses `psy-accept-<instance>-infra`; Envio uses
`psy-accept-<instance>-envio`. Default instance: `stages-20260918`.
All published infrastructure ports bind loopback. PostgreSQL is 15433 and
Hasura is 9080, avoiding the shared 5433/8080 containers. Required other free
ports: 1337, 13380, 13390, 6379, 4222, 9042, 8081, 8545, 9545, 10545,
9898, 9998, 9999, and 3000. Port conflicts fail without killing listeners.

## Acceptance Gates

- Each component must become healthy, and coordinator/realm heights must advance.
- Registration, faucet and claim must complete, not merely return a job ID.
- All three local chains must pass deposit, L2 claim, withdrawal and L1 settlement.
- Verify actual Nostr notes against this cohort; old fixture tests alone do not
  establish services/SDK proof compatibility.
- Record transaction hashes, checkpoints, balance deltas and logs. A timeout
  after broadcast requires recovery by the existing transaction, not a new deposit.
- Skipped or blocked flows are not a complete pass. This local run does not
  authorize npm/R2 publication or any online deployment.

The overlay deliberately avoids UI installation, global Docker cleanup and
process-name/port-based termination. Changes remain under `deploy/` rather than
modifying the published runtime commit.
