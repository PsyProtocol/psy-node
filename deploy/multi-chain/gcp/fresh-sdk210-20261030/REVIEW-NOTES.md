# Preparation Review Holds

The independent reviewer was Claude Opus 5.5 (`claude-opus-5-5`), different from
the implementing Codex model. Review covered the textual delivery in four
disjoint parts. Generated blobs received exact upstream byte/hash comparison,
not manual decoding. The verdict was **changes requested**, not release
approval. Line numbers from the review must be resolved again after integration.

## Addressed During Integration

- A durable quarantine marker behind an unsubmitted valid withdrawal could
  advance the next services offset past that valid withdrawal. Only the leading
  invalid prefix is now marked. The regression failed before the fix, then
  passed for mapping mismatch and unencodable inputs across database reopen.
- Prior deployment Genesis layout validation, identity reuse, and the final
  positional-value IMT checks are retained instead of overwritten by Audit.
- The historical submodule topology and DApp `update = none` are retained.
- Imported runbook text no longer claims standing authorization for a fresh
  clear. Each destructive campaign needs its own target-specific authorization.
- The testnet EndCap verifier and both declared fingerprints match an actual
  testnet circuit construction. Supporting procedures require its own evidence.
- The stale Faucet test now uses the current SD-key module and generator API.
- The Services withdrawal-proof route was checked at `81b33abe`: required query
  fields are destination chain and Poseidon leaf `nullifier`, not the raw nonce
  or recipient tuple. The Node runbook now matches that adopted handler.

## Required Before Release

These are findings or hypotheses in imported code, not observations of newly
deployed behavior. No live runtime was changed. Do not change protocol circuits
to address a hypothesis without reproducing it and rebuilding its dependency
cohort.

| Area | Evidence / risk | Next action |
| --- | --- | --- |
| Withdrawal packing | `daemon::build_withdrawal_batch_calls` can emit 176 inputs while the adopted VM capacity is 128 | Keep capacity 128; restore bounded append packing and test 2 + 2 + 1 with real Guardian acceptance |
| Standalone quarantine planning | `propose_withdrawals::run_and_get_withdrawal_root` invokes a marker-writing filter on an empty-offset scan | Establish the authoritative per-chain append cursor on that path; do not write markers outside its contiguous prefix; add non-cursor scan regression |
| Held token mapping | `claim_withdrawals::operator_condition_cleared` has no TokenMappingMismatch arm, although that code produces an operator hold | Recheck both Router directions at a pinned block; add held-then-repaired and read-failure cases |
| MCP uncertain submission | `claims_tools::claim_batch` can refund policy authorizations after an uncertain submission | Keep charged budget and reservation together until the authoritative outcome is known; test EndCapSubmissionError |
| MCP returned identity | Withdrawal tools render raw nonce as nullifier although the L1 key covers all 35 words | Return the derived L1 key and keep raw nonce separately; verify exact 140-byte keccak preimage |
| External IMT cache | Reviewer suspects external-map cache keys omit base/capacity while current-contract keys include them | Reproduce external two-map same-key reads and inspect witness cache keys before selecting any circuit change |
| Local reset scope | `locSetupV4.ts` can include non-local deployment directories when purging a sibling contracts checkout | Restrict local launcher purge to owned localhost outputs; prove Sepolia/Ethereum records survive |
| XOR helpers | Reviewer suspects slot-sum rejection breaks multi-input XOR | Inspect actual callers: the current three-input path is already pairwise. Run real prove/verify tests; investigate unsupported larger folds separately rather than accepting the diff-only hypothesis as proven |
| Realm recovery | Reviewer questions own-inclusion recovery, discarded rollback errors, and shutdown sampling during vote waits | Reproduce each against retained testnet recovery behavior and inspect surrounding code; add failure and restart tests before changing the pipeline |
| Guardian liveness | Some unbounded sign/verification waits have no demonstrated dead-peer recovery | Bound individual network attempts without shortening valid total proving time; test a hung attempt followed by recovery |
| Receipt classification | Reason 5 may represent an already registered full-identity key rather than a raw-nonce conflict | Confirm authoritative L1 state and V6 semantics; test idempotent registration recovery without replaying uncertain sends |
| E2E and docs | Small withdrawals may pay directly while the local script still expects a pending entry; several imported comments describe old identities | Update executable acceptance to distinguish direct payment and pending claims, then reconcile comments |
| Provenance and setup | Historical npm source cannot be fully reconstructed; new 35-word verifiers/setup and final pins have not been accepted together | Preserve the evidence limitation, publish a coherent final source cohort, and complete real three-chain proof acceptance |

The deployment candidate remains blocked even when its unit tests pass. None
of these holds is resolved by increasing memory, raising the 128-word limit,
restarting the old chain, or declaring a Git push to be a successful rollout.
