# Live verification, 2026-10-01

All times below are UTC (local time is UTC+8). The operator authorized the
initial recovery restart, Faucet-only upgrade, branch pushes, and one Faucet
disconnect/retry regression to existing E2E user 868352.

## Recovery and deployment

- Old Faucet restarted at 06:46:44; PID 1685801. New Faucet transactions appeared
  at checkpoints 101622, 101625, 101628 and 101631, restoring real issuance.
- Candidate `153b8ca6594c4b6f78c2832577e219bf4ece5e64` deployed under
  `/opt/parth/faucet/releases/20261001-153b8ca6594c/`.
- New PID 1687269; startup account initialization completed at 07:01:59.
- Running executable SHA256:
  `af79853480889e6a01142b84167aba82fcef861fa38de7e17d170b650e7baa74`.
- Readiness returned exactly the same ten accounts and other public config.
- Relayer PID 1488948 and executable unchanged. Genesis/config/environment file
  hashes passed the installer's protected-file checks. No other service restarted
  by this rollout. No contract or chain state reset.
- Shared `/opt/parth/current` release and binary were not replaced.

## Regression evidence

Tests use a mocked blocking worker and the production lifecycle helper, then the
real release was verified against an existing registered test account.

- Baseline local HTTP reproduction: eleven tasks completed (one connected
  control, ten disconnected requests), cleanup=1, leaked locks=10.
- Fixed local reproduction: eleven completed, cleanup=11, leaked locks=0.
- Six targeted tests passed in the actual `psy_prover` release test binary inside
  the pinned Bookworm builder; 65 unrelated tests filtered out.
- Three deployment readiness tests passed; Python syntax and ShellCheck passed.
- Independent read-only review found no concrete code defects. It noted the
  unit tests did not exercise the complete WalletSession/cache path; the live
  disconnected claim and cached retry below cover that integration path.

### One authorized live claim

Recipient: 868352. Operator selected by the unchanged account selector: 786432.

1. Before the test, Services reported token 0 claimable=0, item_count=0.
2. At 07:02:21, sent `psy_claim_faucet` to localhost on the Faucet host and
   deliberately closed the HTTP request at 1 second (`curl` exit 28).
3. Operator acquired at 07:02:21.735923; released at 07:02:40.523653,
   elapsed_ms=18787, success=true, after the client had disconnected.
4. At checkpoint 101774 (07:02:48), the operator's indexed transaction count
   increased from 72 to 73. Indexed content hash:
   `a43fe0956cb6291873518e9709df9dc45e5dd5b4acd0dd5f23ea2c60eea5bc64`.
5. Services public-claimable showed exactly one new token 0 entry from operator
   786432, raw amount 1000000000000, created_at=07:02:48, claimed=false.
6. Retrying in window 848 at checkpoint 101777 returned
   `already_submitted=true`, without another operator acquisition, and the saved
   end-user-leaf hash `093e0806d874dc66564a1d116167e825c1bf7c9ca7ef720122c2d9322e8a804f`.

The RPC's `tx_hash` above is the end-user-leaf hash; it is not the indexer's
transaction content hash. These are distinct identifiers, not a mismatch.
No recipient claim/other transfer was performed. The granted test funds remain
claimable; this verification is not a full wallet or bridge E2E run.

## Branches

- Fix branch: `fix/faucet-cancel-safe-20261001`, `153b8ca6`.
- `release/testnet-stable`: backport `b105752e`.
- `deploy/multi-chain-gcp`: runtime merge `06440230`, installer `729d05fd`,
  followed by this verification record.
- `multi_chain` was not modified by this rollout.

Remaining limitations: no durable claim journal across process restart; no
solution here for indefinitely hung downstream work or unknown submission
outcomes. The verified fix addresses HTTP cancellation leaking account locks.
