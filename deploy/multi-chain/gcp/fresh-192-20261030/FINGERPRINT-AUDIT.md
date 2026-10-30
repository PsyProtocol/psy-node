# 192-Word Circuit Alignment

Measured on 2026-10-30 using release builds, `PSY_NETWORK=testnet`, explicit
`PSY_CONFIG_PATH`, Plonky2, and the immutable Bookworm build image
`sha256:02a4dd5c2ea776982084a4a856610836fc9f944203e85948fd4b475177f6b4af`.
Runtime source is `d64871fe87e80b7fbc1203195a5ac1afec5a622c`, published on
`fix/sd-key-calldata-196-20261030`. The branch name retains the earlier 196-word
candidate's history; the final source bound is **192** and the transaction
introspection count remains **64**. No live service or chain was changed.

## Results

| Item | Result | Evidence |
|---|---|---|
| `local_circuits.json` | All three embedded circuits match fresh construction | `embedded_local_circuits_match_current_sources` passed |
| Private-note inclusion | Minifier fingerprint unchanged | Native circuit build; both compiler tokens and actual Genesis methods checked |
| Deposit inclusion | Minifier fingerprint unchanged | Native compiled `deposit_inclusion.rs` circuit; both compiler tokens and actual Genesis methods checked |
| EndCap | Fingerprint and complete alternate verifier JSON unchanged | Real `get-user-end-cap-common-data` output compared with both network declarations and tracked verifier |
| ZK signature | Fingerprint unchanged | Real constructor output matches Wallet and Genesis configuration constants |
| secp256k1 | Fingerprint unchanged | Real constructor output matches Wallet constant |
| ETH-personal secp256k1 | Fingerprint unchanged | Real constructor output matches Wallet constant |
| Faucet SD-key | Changed; new public account identities required | Full default 64-slot policy constructed in both library and CLI test targets |

The embedded bundle contains **inner** circuits. Genesis token contracts bind
the **minified** inclusion circuits. These are different identities and must
not be copied interchangeably. The uncompiled `privacy/shield_deposit_claim.rs`
file was not used as measurement evidence.

## Inclusion Bindings

Deposit inclusion minifier limbs:

```text
[10300675757615779284, 7959431029994071658,
 2858758774398267815, 15642499089729770720]
```

Private-note inclusion minifier limbs:

```text
[2482434993266711942, 6028864160300535936,
 2827549014984201026, 3018365102481798071]
```

Both match `psy-compiler` revision
`1d1f8fe8af17f5f5cddf285577378b7b14fb0d49` in
`psy-precompiles/{token,usdt_token}/src/main.psy`.

The Zstandard-compressed `psy-genesis/genesis_contracts.json` was streamed,
contracts **0 and 4** were extracted, and their CBOR function definitions were
decoded with a structured parser preserving u64 precision. In each contract,
`claim_deposit` (method `1577908089`) contains all four measured deposit limbs
as Constant operations; `private_claim` (method `635905178`) contains all four
measured note limbs. Each limb occurs once in its corresponding function.
This checks actual encoded methods, not just compiler text or a standalone
token artifact. It does not prove a real claim transaction succeeds.

The compiler artifact stamp also matches all three files' exact bytes and sizes:

| Artifact | SHA-256 |
|---|---|
| `genesis_contracts.json` | `0f4a4a8cbeaff5621d05fa795b6aa157809eb5753fde1c5da62027753bbb9c9f` |
| `token.json` | `36cb09dc75798a28a09586067f6b577da4e1eb675522d5bea4507fb15d886ddd` |
| `token.update.json` | `d4fdcd384595bc4899a4115275f78fe72e8c3a1c726f18844245b58f22858ff6` |

Matching privacy bindings do not establish that old compiler artifacts are a
complete new release. Compiler, SDK and Services still need the accepted Node
pin, followed by the applicable rebuild/provenance checks.

## Signature Bindings

```text
EndCap:
[11759116326290479251, 11289239174989169558,
 15612226363787444833, 305684495212004112]

ZK:
[10809942084296272720, 6801881445144280090,
 13901098532226573745, 7340892251884443121]

secp256k1:
[10343028442007653325, 7900492699015058022,
 11323444284884699300, 5212312826826937272]

ETH-personal secp256k1:
[8910808775875266372, 1939876395565792506,
 4400602774105039709, 738332823617062494]
```

The measured EndCap full verifier was JSON-parsed and deeply compared, not
accepted from its fingerprint alone. The command printed `testnet` and magic
`0x1337cf514544cf69`. No verifier replacement or artifact regeneration was
performed because the measured identities already match.

## Faucet Identity Change

Measured full-policy fingerprint:

```text
d48255a10a5b3049b6aad5169603336ed6b80b9358b2da78527b385bca95a109

[5943406100137484553, 15472129247307553400,
 13162567153926484846, 15312895833164951625]
```

The base circuit has `degree_bits = 18`. Both test targets measured the same
fingerprint. The synthetic Genesis fixture has six validator accounts, one
Relayer account, and **100 operators** (107 accounts total), and compares the
Genesis, exported and runtime-derived public identities. This is not a test
with the retained production private keys or a generated deployment Genesis.

Retain operator private-key material where possible, but regenerate the public
identities and new Genesis from the accepted policy. The existing import-only
generator rejects changed public identities: implement explicit fresh-identity
handling rather than disabling that check or rewriting the old baseline.
Faucet runtime must derive/use the same policy and exported accounts.

Legacy `client_prover/Makefile` example SD-key fingerprint literals belong to
their own explicitly configured three-call policy. They are not the full
Genesis Faucet policy and must not be overwritten with this fingerprint.

## Remaining Gates

- The published SDK **2.1.0** is the old capacity cohort. Matching some embedded
  circuits does not make its SD-key implementation support 192 words. Rebuild
  compatible SDK/WASM, Compiler and native consumers with one published Node pin.
- Generate and validate the fresh Genesis and actual 100-operator export. Preserve
  Guardian/P2P/worker keys and check their public bindings separately.
- Complete 64-slot proving/verification resource measurement. This audit covers
  construction, not a fully loaded 64-transaction proof or concurrent Faucet load.
- Five withdrawals occupy `1 + 5 * 35 = 176` Felts and pass the focused SD-key
  calldata test; real five-entry Guardian/SD-key/EndCap acceptance remains required.
- Build final five-CLI artifacts against the accepted bundle/config and complete
  the three-chain real bridge E2E and independent baseline release holds.

## Retained Evidence

Local evidence is under `tmp/sd-key-calldata-196-20261030/`; paths retain the
historical candidate name. `audit192-fingerprints.cjs` rechecks the exact u64
values, complete EndCap verifier, compiler constants, encoded Genesis methods,
artifact stamps and successful test markers. Its generated report is
`fingerprint192-audit.json`.

| Evidence | SHA-256 |
|---|---|
| `endcap192-measurement.log` | `88a2182fcfaf58e3190a3e00aa394042e82b9ac7da7972957c38ec593315e279` |
| `privacy192-fingerprints.log` | `643e0df3cebf9b644e70c207819f900d3385b79dd260041f138496b2bb58b3c6` |
| `local-circuits192-alignment.log` | `4db4125705ecb0bbe35cd7d1ec5f58da5cebb65155ea786d9f80f9a83fc07eaa` |
| `faucet192-fingerprint.log` | `504bbdee8b3b2d8683577738c330cae8e7b00b8db72515ff77fed593ad3c3ff0` |
| `genesis192-token-functions.json` | `d92484abb2f62b85483cb7fbe8b58745cd04d8e1135c7d1b906d07cac40066b9` |

The 42 focused capacity tests passed. The two privacy-build tests, embedded
bundle test, and Faucet identity test (both targets) also passed. These are
targeted evidence, not a claim that the complete repository suite passed.
