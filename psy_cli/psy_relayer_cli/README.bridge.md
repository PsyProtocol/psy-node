# psy_relayer_cli (Bridge Commands)

Proposer CLI wired to the unchanged generic `gnark-plonky2-verifier` FFI. BridgeOpening uses the direct Goldilocks public-input vector. There is no digest, compact, or high/low acceptance path.

## Commands

```bash
cargo run -p psy_relayer_cli -- prove-bridge-aggregate-proof \
  --from-checkpoint <from> --to-checkpoint <to> \
  --rpc-config <config.json> --aggregate-config <approved.json> \
  --witness-json <witness.json> --out <bound.proof>

cargo run -p psy_relayer_cli -- regenerate-groth16-keystore \
  --aggregate-proofs --aggregate-config <approved.json> \
  --aggregate-proof <bound.proof> --output-dir <fresh-dir>

cargo run -p psy_relayer_cli -- prove-bridge-agg \
  --from-checkpoint <from> --to-checkpoint <to> \
  --rpc-config <config.json> --deployments-network <network> \
  --aggregate-config <approved.json> --witness-json <witness.json> \
  --artifact-dir <installed-dir> --out <groth16.json>

cargo run -p psy_relayer_cli -- export-opening-verifier \
  --aggregate-config <approved.json> --artifact-dir <installed-dir> \
  --out-verifier-sol <verifier.sol>
```

`prove-bridge-aggregate-proof` writes canonical `ProofWithPublicInputs` bytes of the bound aggregate proof. It does not read a deployment file, create a keystore, or skip witness checks. It still needs a compatible L2 RPC and real checkpoint witnesses.

`regenerate-groth16-keystore --aggregate-proofs` requires that proof. It reconstructs the approved wrapper, checks the proof against its own top common, prefix `[4,12,0,0]`, width, and canonical bytes, then calls one `prove_groth16` in fresh staging. That call is the setup. The command then writes canonical `identity.json`, the product `verifier.sol`, and `manifest.json`, validates the six-file set, and installs with `renameat2(RENAME_NOREPLACE)`. A failure before install removes only that staging directory. It never installs an identity-only set.

Normal `prove-bridge-agg` keeps its deployment-file preflight, then uses the same producer, requires the installed six-file set, and writes Groth16 JSON. The wrapper checks the full returned vector. Daemon startup uses the same strict validator and does not regenerate missing files.

`export-opening-verifier` rebuilds identity from the approved configuration and returns the validated installed product verifier. It does not call generic export and does not trust `identity.json` by itself.

Deposit-append and withdrawal-claim keystore regeneration remain separate and still use their sample witnesses.

## Trust boundary

The approved configuration and the reconstructed wrapper are the identity authority. Fresh staging proves that this process created the Groth16 keys from that wrapper and the supplied real aggregate proof. After install, the manifest hash detects later corruption of that set.

A coherent replacement of every file, including `identity.json` and `manifest.json`, is not authenticated by those hashes. The loaded generic CCS checks circuit shape only. `IsSolved` does not bind the requested product identity. This CLI does not retain the historical complete-reader or compile-versus-stored equality check, and hashing is not a substitute for it. If that independent guarantee is required, the unchanged generic API does not provide it.

Generated artifacts are not a StateManager-compatible statement. The direct vector is not converted back into two digest words, and this CLI does not deploy contracts.
