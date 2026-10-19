# Packed deposit transactions

The Relayer can losslessly encode consecutive, existing 32-deposit proofs for
`PackedDepositAppendAdapter.appendPackedBatches(bytes)`. The adapter restores
the original `Bridge.batchAppend` arguments. This changes transport and
transaction grouping; it does not aggregate proofs or change circuits, proving
setup, Genesis, or the deployed Bridge/verifier ABI.

## Request and submission semantics

Multichain snapshots request the chain-local `snapshot_deposit_count`. The
legacy global-index path retains `target_deposit_count`. A chain-local count
must not be sent as a global index cutoff. Snapshot chain, count and root
validation remain mandatory.

Packed submission is opt-in per chain. Without it, the nonce-safe legacy
single-call path remains available. The sender takes one ready proof and drains
only additional proofs already available, up to the configured maximum. It
does not wait to fill a transaction. Groups must be consecutive and end within
the persisted target. Each receipt must succeed and advance the Bridge cursor
to exactly the expected position before the next group is submitted.

One record is 8,684 bytes: eight full-width proof coordinates, 795 uint32 public
input words and 1,312 uint32 slot words, encoded big-endian. Values exceeding
uint32 are rejected. One call has 8,772 bytes of ABI calldata; four calls have
34,820 bytes and can advance at most 128 deposits.

## Per-chain configuration

These tables belong inside their corresponding existing `[[chains]]` entry in
the daemon TOML configuration. Keep the chain's other settings intact.

```toml
# Existing Sepolia chain (index 0 / chain ID 11155111)
[chains.packed_deposit]
adapter_address = "0x76Fee5DA6F1Cfed60c80F72dCB553b38DA3245c7"
max_calls_per_tx = 4
max_gas_per_tx = 15000000
max_fee_per_gas_wei = 5000000000
max_tx_fee_wei = 75000000000000000
```

```toml
# Existing BSC Testnet chain (index 1 / chain ID 97)
[chains.packed_deposit]
adapter_address = "0x77E2D427793B3B6Db5eB2E33aFFDF9d2d8796C10"
max_calls_per_tx = 4
max_gas_per_tx = 15000000
max_fee_per_gas_wei = 1000000000
max_tx_fee_wei = 15000000000000000
```

```toml
# Existing Base Sepolia chain (index 2 / chain ID 84532)
[chains.packed_deposit]
adapter_address = "0xA07d826f3765f6E606755B85640565F7c0cae292"
max_calls_per_tx = 4
max_gas_per_tx = 15000000
max_fee_per_gas_wei = 1000000000
max_tx_fee_wei = 15000000000000000
include_base_data_fee = true
```

The sender validates the adapter's immutable Bridge binding and chain-specific
configuration. Gas limits include a 4% margin above the live estimate. Larger
prefixes are reduced when gas or the Base total-fee budget will not fit; an
invalid or unaffordable single call fails. RPC failures and proof reverts are
not replaced with guessed gas estimates.

BSC retains its existing `recent_history` fee policy with 0.1 Gwei minimum
priority fee and 1 Gwei maximum priority/total gas price. Its 0.015 native-token
budget is denominated in tBNB, not ETH.

Base requires `include_base_data_fee=true` on chain IDs 8453/84532; the flag is
rejected on other chains. In addition to execution gas, the canonical
GasPriceOracle at `0x420000000000000000000000000000000000000F` supplies
`getL1FeeUpperBound(calldata length + 1024)` and `getOperatorFee(gas limit)`.
Their sum receives 20% headroom and participates in prefix selection and a fresh
pre-broadcast budget check. Oracle failure stops submission. The 0.015 ETH
budget uses buffered estimates; it is not an on-chain hard cap on changing
L1/operator fees.

## Release and validation, 2026-10-19

| Component | Exact deployed source |
| --- | --- |
| Relayer | `a15cc3f20b047baf79225a4b74d3a620c2629432` |
| Adapter, PsyProtocol/psy-contracts | `d161b96068915d7795195eb408e5d341679720d2` |

Relayer executable SHA256:
`6ad22a3a6fa699a3b0fc8b151c052f73e920370bee564e41625974241d3c56ad`.
Later test/documentation commits are not the deployed executable's source pin.
The runtime release preserves prior BSC pricing, RPC failover, withdrawal nonce
isolation, system proof-pool concurrency and per-chain snapshot fixes.

The production candidate passed 278 release tests, release build and CLI smoke
check. Exact adapter runtimes passed read-only historical replays for one, two,
three and four calls on both new chains; mutated proofs reverted. Base's
four-call / 128-deposit replay estimated 14,752,795 gas including margin. BSC's
four-call historical fixture contains 14 deposits and estimated 13,807,375 gas
including margin; it is not a measured 128-deposit BSC transaction.

Real single-call acceptance advanced BSC `675 -> 707` and Base
`44958 -> 44990`, with successful receipts:

- BSC: `0x476433fc95ebf31faf55712b5cba516cd57a4e8063ece67f8ab3ff80ba856405`.
- Base: `0x0af3f15cf19f8614c139ebac44b4bb5d8437289da483e8732cfdf2753ba47a26`.

Both were promoted to maximum four calls / 15M gas at 08:35 UTC. Sepolia's
configuration was preserved; proof concurrency remained 3. At that acceptance
sample, live four-call transactions on the two new chains had not yet been
observed because the daemon processes Sepolia first in the persisted range.

The test-only `packed_deposit_live_canary` module is ignored by default. It
requires explicit confirmation, the main daemon stopped, and existing work in
the durable range; it processes at most 32 deposits without writing daemon/L2
state. Running its ignored live test broadcasts a real transaction. Ordinary
unit tests do not broadcast. Its boundary test passed separately.

Before changing or reverting a running deployment, stop new submissions and
drain all signer nonces. Preserve current daemon state and on-chain progress;
never restore a historical state file. Rollback of this extension restores the
preceding working Sepolia-packed configuration and binary, leaving the new
adapters deployed but unused.
