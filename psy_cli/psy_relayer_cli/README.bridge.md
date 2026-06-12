# psy_relayer_cli (Bridge Commands)

Proposer CLI wired to `gnark-plonky2-verifier`.

## Commands

```bash
cargo run -p psy_relayer_cli -- generate-groth16 \
  <common_circuit_data.json> \
  <proof_with_public_inputs.json> \
  <verifier_only_circuit_data.json> \
  <keystore_dir> \
  <out_proof.json> \
  <out_vk.json>

cargo run -p psy_relayer_cli -- verify-groth16 \
  <proof.json> <vk.json>

cargo run -p psy_relayer_cli -- export-solidity-verifier \
  <keystore_dir> <out_verifier.sol>
```

## Notes

- Current implementation uses the Rust FFI crate `gnark-plonky2-verifier-ffi`; it no longer shells out through a local Go adapter directory.
- Any local checkout path for `gnark-plonky2-verifier` should be configured in the FFI dependency layer, not hardcoded in this README.
- `generate-groth16` / `verify-groth16` currently use uncompressed proof/vk only.
