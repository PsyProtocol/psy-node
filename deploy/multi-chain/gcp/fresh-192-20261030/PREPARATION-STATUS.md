# Preparation Status: 2026-10-30

This is an offline preparation checkpoint, not a completed deployment or an
activation package. No database, live service, L1 contract, key or npm package
was changed by this work.

## Source And Consumers

The published Node candidate is
`3c34ab575fc78ac1515f34555af3b70124f1225e`, on the historical topic
`fix/sd-key-calldata-196-20261030`. It contains the final **192**-word limit
and the explicit fresh Faucet identity transition. The deployment integration
was locally committed at `37180db0`, before the config checkpoint recorded here.
Its push failed with GitHub SSH public-key
authentication, so do not assume the remote deployment branch includes it.
Keep all local commits; do not force-push or change transport credentials.

Three isolated consumer candidates are committed on `prepare/sd192-20261030`:

| Repository | Local Commit | Checks Passed |
|---|---|---|
| Compiler | `708c4c6b6e4b51bf5fbbf2cbaeb204e3fa7981ec` | Locked metadata; release check of `psy-precompiles --lib` |
| SDK | `e85f44cc09873117eeff6beb65c182473e567eb7` | Locked metadata; release library check |
| Services | `4e79359f7e2bc1960e8520cec44201bc82fb50bb` | Locked metadata; release library check |

All three dependency graphs resolve one Node revision: `3c34ab57`. Only Git
source pins changed in their TOML/locks; package versions, features, aliases,
registry versions/checksums and dependency lists stayed unchanged. Compiler
and SDK also resolve the already-selected Node Gnark closure to the
`hellojason3/gnark-plonky2-verifier` commit
`96a1d13b31f440316af1af7225943a1260f5150d`, rather than the old upstream pin.
Services has no Gnark dependency. The complete three-repository staged diff
passed independent review before local commits. These consumer branches have
not been pushed or integrated; no new npm version is reserved or published.

The checks used the immutable Bookworm image, release mode and compiled
testnet selection. They used the canonical template config, not the final
membership-populated config below. They are compilation checks, not WASM,
new compiler-contract generation or final release artifact acceptance.

## Actual Config Candidate

The canonical checked-in config defaults to localhost and has no testnet
Guardian, Validator or Worker identities. `PSY_NETWORK=testnet` selected
testnet during the checks; the template itself is not a usable host config.

`prepare_config.py` assembled a candidate from that hash-pinned canonical
config and the retained approved public testnet config. No private-key files
were opened by the script. It selects testnet, keeps epoch **32**, retains **3 Guardian commitments,
6 Validator memberships and 2 Worker whitelist keys**, and enables the
whitelist. Existing identity files were not edited.

| Input/Output | SHA-256 |
|---|---|
| Canonical template | `7274eebbd98e17c1e76ead05793a9d5c503311469990a93d7aad1e07e07b9db9` |
| Retained approved config | `c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0` |
| Candidate config | `d044bb4b16fc1a06a2c5a44a771271665b98c08a8db3d10ba0a6d1829d88ffbf` |

The hardened script rejects unknown nested fields, credential-bearing RPC URLs,
nonempty old Guardian history and hashes outside the checked-in release profile.
Ordered Guardian endpoint ids match the three commitment slots; this is not
cryptographic endpoint authentication or proof of possession.

Local artifacts: `tmp/sd-key-calldata-196-20261030/runtime-config-192-reviewed/`.
Read-only preflight passed both exact source and config checks. Its output
still says `deployment_ready=false` and `activation_authorized=false`.
Host/key provenance and native acceptance are separate checks.

## Completed Regression Milestones

- Native Genesis tests: **55 passed, 1 previously ignored**. The fresh Faucet
  transition failed against the old identity guard and passes with the opt-in.
- Genesis adapter: **21 passed**, including old-v1 preservation and explicit
  v2 epoch-32/fresh-Faucet command forwarding. Children are mocked.
- Network assembly: **37 passed**; the historical default remains epoch 10.
- Source/config preflight: **11 passed**; config preparation: **8 passed**.
- Fingerprint measurements remain as recorded in [FINGERPRINT-AUDIT.md](FINGERPRINT-AUDIT.md).

## Remaining Work

1. Restore GitHub SSH publication, then publish/reconcile the reviewed local
   deployment and consumer commits. Runtime integration into `testnet-dev`
   remains pending; do not merge deployment scripts backward.
2. Rebuild full Compiler contract artifacts and compatible SDK/WASM from the
   accepted cohort; publish producer revisions before downstream gitlinks.
3. Generate the actual-key Genesis and 100-operator export using spec v2 and
   the explicit fresh-Faucet mode. The old public Genesis remains unchanged.
   Non-Faucet fingerprints/public-key parameters remain strict: stop if any
   also differs, and assess that separate identity transition rather than
   widening or bypassing the Faucet flag.
4. Verify generated layouts/methods/token bindings, rebuild final caches and
   five CLIs against the accepted config and final bundle, and validate native
   Genesis construction. No actual-key new Genesis was generated in this step.
5. Prepare matching Bridge setup/verifiers, host packages and isolated state;
   measure full-policy proving/memory and pass real five-withdrawal and
   three-chain deposit/claim/withdrawal acceptance before activation.

Evidence logs and dependency graph audit remain under
`tmp/sd-key-calldata-196-20261030/`. Native check log SHA-256 values:

```text
SDK      195f4f61368d71567d9a175a3fc44729f411b6224a219ca7b4765fd3010eeba3
Compiler 996068f45e5793901e3fec2cf93b1d86ab3344ec7d5d749d1982f337a2bfa866
Services 0dcc27e1b3ecf613234e96b359fa9ef1966fdd6bbb673197d7e11ac31925d425
Lock DAG 76ac257a81a815946ae93e59f9297bac3fba5bf976643f5db5eb9621b266b959
```
