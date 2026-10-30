# Fresh Testnet: 192-Word Preparation

This is the next source/config preparation profile, not an activation package.
The published runtime candidate is
`d64871fe87e80b7fbc1203195a5ac1afec5a622c`. Deployment scripts stay on
`deploy/testnet`; runtime integration into `testnet-dev` remains a separate step.
Neither a successful preflight nor a Git push authorizes reset or activation.

## Preparation Parameters

`release.json` records testnet magic `0x1337CF514544CF69`, Plonky2, epoch 32,
192 calldata words, 64 introspectable transactions, 100 Faucet operators,
two Realms with three validators each, and the three existing Guardians.
Bridge Reader is excluded. Only PSY (L2 contract 0) and pUSDT (contract 4)
may be admitted; native deposits and initial public deposits stay disabled.
Host roles are preparation inputs, not fresh SSH or resource measurements.

See [the measured circuit alignment](FINGERPRINT-AUDIT.md). Inclusion, EndCap,
ZK and both secp fingerprints match; Faucet SD-key identity changes. These
measurements do not replace the downstream rebuild and Genesis gates below.

The Relayer candidate already supports L2 withdrawal-tree append packs of
1, 2 and 5. Five withdrawals use one `batch_append_withdrawals_5` call with
176 Felt inputs, fitting 192. Use that existing packing rather than porting
the old 128-word `2 + 2 + 1` workaround into this cohort. This is not five
parallel L1 sends, nor a change to L1 deposit aggregation. Keep smaller-pack
regressions and require real five-entry Guardian/SD-key/EndCap acceptance
against the new Genesis before rollout.

## Read-Only Preflight

```sh
python3 -B deploy/multi-chain/gcp/fresh-192-20261030/preflight.py \
  --source "$RUNTIME_SOURCE" --config "$CANONICAL_RUNTIME_CONFIG"
```

This only reads public files and local Git identity/status. It never contacts
nodes, reads private keys, runs Cargo, writes configuration, broadcasts, or
starts/stops services. Missing or inconsistent inputs return 2. Input contents
are not logged. The selected runtime config must already select testnet,
use epoch 32, enable the owned worker whitelist, and carry the retained public
Guardian commitments and six-validator membership. Format checks do not prove
curve-point validity, key possession, provenance or native Genesis acceptance.
Those remain separate runtime checks. A zero exit means these limited input
checks passed, never that `deployment_ready` or `activation_authorized` is true.
The source checkout is operator-trusted: repository-configured Git filters may
execute during status checks. Inherited Git directory/worktree overrides are
removed. All six validator identities must be structurally complete and unique;
this does not establish retained-key provenance or curve-point validity.

The historical `core-only` planner/installers still pin R3 source, epoch 10,
old account identities, artifact hashes and namespaces. Do not call them with
renamed inputs or replace only their version strings. Likewise, the historical
`source-versions.env` and published SDK 2.1.0 are not this release lock.

## Remaining Preparation Order

1. Freeze one accepted published runtime revision for all downstream Node pins.
2. Rebuild Compiler and full contract artifacts, measuring affected fingerprints
   and checking token0/token4 layouts, methods and privacy bindings.
3. Prepare a fresh Genesis and 100 Faucet public identities. Retain Guardian,
   P2P, worker and operator private-key material; the changed Faucet fingerprint
   does not preserve old public identity. The old import-only generator will
   reject that change. Implement/review explicit fresh-identity handling before
   generation; never rewrite the old baseline or disable its identity check.
4. Rebuild the SDK/WASM and clients from the accepted cohort. No npm publication
   is included here. Measure the full 64-slot SD-key resource envelope.
5. Build the five CLIs with the pinned offline Bookworm procedure in
   [BUILD_RUNTIME.md](../core-only/BUILD_RUNTIME.md). Bind the actual config,
   bundle/stamp, source and image, retaining build manifests and hashes. A cache
   build against previous bundle inputs is preliminary, not the final package.
6. Adapt packages/activation scripts and isolated namespaces, journals and
   indexer cursors. Do not transplant old chain state. Resolve baseline holds
   from [REVIEW-NOTES.md](../fresh-sdk210-20261030/REVIEW-NOTES.md).
7. Prepare matching L1 setup/verifiers and paused fresh contracts for all three
   chains. The shared L1 runner now checks the compiled Router ABI before
   broadcasting and checks dual mappings/native rejection at one block before
   writing success readbacks. It does not automatically recover or redeploy
   after a partial deployment or failed readback.
8. Complete real illegal-then-legal deposit, claim and withdrawal E2E for each
   chain before opening public deposits. Mocked readbacks are not this gate.

The PostgreSQL installer now fixes 2 GiB Docker shared memory and compressed
`100m`/100-file logs, checking actual container policy before readiness. It is
a fresh installer that replaces a container, not a live database maintenance
command. Hasura's existing bounded logging remains unchanged.
