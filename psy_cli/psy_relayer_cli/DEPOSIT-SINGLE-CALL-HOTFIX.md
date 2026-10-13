# Deposit append transaction-size hotfix (2026-10-12)

## Incident and delivery scope

Live baseline: `8bde3dcbefd59621c4f8e8c317878f9654bd87c5` (includes the deployed BSC cost-aware fee policy).
Only the Relayer deposit append submission policy changes. Genesis, contracts,
ABI, circuit/setup artifacts, dependencies, signing, database formats, fee policy,
and the persisted daemon cursor are unchanged.

The live RPC rejected an aggregate transaction of 136059 bytes against a
131072-byte transaction limit. The deployed `batchAppend` ABI encodes 67748
bytes per call, even for a partial batch: the 1312-word slot array is fixed.
An aggregate of two calls is 135940 bytes before the signed envelope; a single
call is 68004 bytes. A gas budget cannot protect this byte-size limit.

## Behavior

- Build the same ordered batch proofs, with at most 32 deposits per call.
- Submit exactly one call per aggregate3 transaction, with allowFailure=false.
- Reject calldata above 120 KiB before simulation or broadcast, reserving 8 KiB
  for the currently used plain signed transaction envelope. This is a conservative
  calldata bound, not measurement of every possible future transaction envelope.
- Check the current deposit cursor against the call's from_index, simulate, apply
  the existing per-chain fees, send, and wait for a successful receipt.
- Check the cursor against to_index before proceeding to the next call.
- A failure after an earlier successful call does not roll back the L1 cursor;
  the existing daemon restart path rebuilds from the current proved count.

The size regression tests use the real Solidity ABI encoder. They reproduce
an oversized two-call aggregate, verify single-call encoding and retained order,
and reject an oversized individual call. No valid proof or signing key is needed.

## Stateful deployment and recovery

Build only psy_relayer_cli with the pinned nightly-2025-09-20 Bookworm builder
and PSY_NETWORK=testnet. Retain the old immutable binary and override files.
Stop only parth-relayer.service, reconcile signer pending/latest nonces on all
configured L1 providers, then select the new binary through a new systemd
EnvironmentFile override. Do not rewrite configuration, keys or daemon state.

Observe successful append receipts, advancing provedDepositCount, and a found
original deposit proof. Keep test admission paused while recovering the original
backlog. Never resend successful user L1 deposits or reset the chain/daemon state.
Rollback selects the previous binary; it must not restore an old daemon cursor.
