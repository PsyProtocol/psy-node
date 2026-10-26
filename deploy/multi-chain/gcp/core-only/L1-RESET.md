# Fixed Three-Chain Reset

This is the narrow reset following the reviewed quarantine, not a reusable
contract installer or an activation tool. The quarantine dependency is commit
`c6e8222105803d655192a7106cdd8a127f255d5d`. Retain its frozen helpers alongside
`run_l1_reset.py` and `run_l1_reset.cjs`; the runner checks their hashes.

## Scope and Gates

Only six transactions are reachable: on each of the three pinned testnets,
`StateManager.forceSetState(expected, zero)` followed by
`StateManager.revokeCheckpointTreeRoots(allOldRoots)`. The complete reset plan
must equal the output reconstructed by the reviewed `prepare_l1_reset.cjs`.
Plan, snapshot and fence bytes require operator-supplied SHA256 pins.

The runner verifies genuine post-quarantine readback against the original
quarantine plan and requires a snapshot later than the pinned prebroadcast
baseline. It never substitutes an in-memory expected delta for a collector
snapshot. The fence binds the new runtime, Genesis, stopped producers, drained
pending transactions and operator acceptance of the snapshot's finality policy.
`snapshot_finality_accepted` is an operator attestation, not an RPC finalized-tag
proof. The recorded run used main's accepted two-confirmation policy.

Before every signature, the runner checks chain ID, exact nonce and pending
view, implementation/proxy code, roles/provider wiring, all root registrations,
business state and event history. The expected-state CAS remains on chain.
Receipt identity, canonical block/transaction, two confirmations, event hashes
and complete state readback are checked before advancing to the next call.

There is no Bridge reset, clean=true, pause removal, role change, fresh key,
service action, automatic retry, fee bump, resume, or old-data deletion.
Bridge's retained empty deposit root is **not** the zero bytes32 value.

## Custody and Attempts

Default mode is check-only and does not open signer custody. Main alone may
select `--execute` after reviewing the exact plan and successful host check.
Execution uses the retained encrypted signer key and password env, with the
ciphertext hash and decrypted public address checked. Password transport is
stdin only; no secrets or raw signed transactions are saved in audit output.
Use root-owned, non-symlink inputs and `python3 -I -B`; Node and the complete
frozen dependency bundle are also verified before custody use.

The completed original quarantine audit is required for reset execution.
The fixed reset attempt directory is `/var/lib/psy-l1-reset-20261027`.
**Never delete either reset or quarantine attempt directory to retry.**
Changing `--output` cannot bypass the exclusive attempt claim. Failure after
that claim, including an unavailable password, requires manual investigation.
No execution-start marker and no intents means the runner never reached
signing; it does not prove that custody was never opened during an unlock
failure, and it does not authorize clearing the attempt.

Every public transaction hash and unsigned intent is fsynced before the one
send. Observed receipts, including failed receipts, are retained before
validation. Receipt polling may retry reads; send never retries. Public error
files contain stages, plus bounded assertion text only in check mode. An
uncertain send or partial completion needs a separately reviewed recovery plan.

Original deployment budget files remain pinned. Suggested gas price must fit
the cap; the chosen price is `min(2 * suggested, cap)`. Estimated gas receives
a 20% margin. Per-chain gas/spend limits and Base's L1 fee reserve apply. The
reserve is accounting, not a chain-enforced maximum L1 data fee.

## Recorded Execution

Main reported the unique reset invocation completed all six transactions.
The agent collected the real post-reset snapshot and separately rechecked all
six receipts through read-only RPC. These are historical facts at the pinned
blocks, not a claim about subsequent live activation. The agent did not sign,
broadcast, enable clean, start services or push source.

| Artifact | SHA256 |
| --- | --- |
| `run_l1_reset.py` | `7ffdcaa4a5e52454daad47df00bb7b9c5ba112a59635cf95f70b98c51476373f` |
| `run_l1_reset.cjs` | `b4a1e1e8e02e70ba0eddb624f2e33e7c52bcda2a4a93bed27a920d2e02f3c114` |
| `reset-fence-r1.json` | `3d3418974883ae8c9592c09c90a4be69802a976d26ca756be6aa95090d54475a` |
| `reset-r1.json` | `8d487f7dda6a8e7b52b082256b73cea27c63a7e411b26c23cb43834495d82ab1` |
| `l1-postreset-20261027-r1.json` | `0039c2969031533761c8cdefca6775382a318393479a9351de7e4217f7b7fa91` |
| `reset-readback-main-r1.json` | `cd135ca73db82a761326a562dfbd4ff9854cf01be73a80021f1f10649b4a58f4` |
| `reset-receipts-canonical-r1.json` | `a2cd292fa0f93017706bc860918d38c6c5b71257cdf293793a9caed3983e51be` |
| `envio-reset-evidence-r1.json` | `b3fb58931ca6992b6c3b6c12fc97ad4f8e31af9f9ab01566e90bfe0a4d16e5a0` |

Retain these artifacts in the operator's protected evidence archive; they are
not bundled as synthetic repository fixtures. The unchanged collector pin is
`0aacb78d196d17b19289193e9bd9f3c6376482c34ef37a285e95440508ab68ba` and the
planner pin is `77bf8d9b60f5d352b305b9d3891b88058d10b1e60a452b8b23185bc679ee3128`.

At the recorded post-reset boundary, all five StateManager fields were zero,
all 90 old checkpoint-root registrations were revoked, known zero-subtree
permissions remained true, clean remained false, and Bridge pause remained 7.
Custody and zero business activity were unchanged. Envio's schema validator
accepted starts **11999455 / 139076883 / 50567718** for Sepolia / BSC Testnet /
Base Sepolia, respectively. Those starts follow the audited empty boundary;
they do not authorize changing existing databases or starting consumers.

## Verification

The different-model review closed B1 (pre-CAS call and budget checks), B2
(actual EVM stateJobs readback covering all four contract targets), and B3
(precise negative gates); its final targeted review returned APPROVE.
Five JS tests and four Python tests passed and were independently rerun by main.
The JS suite includes six actual in-process EVM CAS/revoke calls across the
three address sets. These local simulations are not on-chain evidence.

From this repository root, provide the retained public fixture paths:

```bash
C=deploy/multi-chain/gcp/core-only
R='<workspace>/tmp/core-rollout-20261026'
Q='<quarantine-plan-file>'
B='<prebroadcast-snapshot-file>'
"$R/node-v22.23.4-linux-x64/bin/node" "$C/test_run_l1_reset.cjs" \
  "$R/fresh-l1-bundle-5ba12a36-r1" "$R/l1-evidence-20261026" \
  "$Q" "$B" "$R/assess-l1-reset-readonly.cjs" "$R/fresh-l1-budgets-r1"
python3 -B -m unittest discover -s "$C" -p test_run_l1_reset.py -v
python3 -I -B "$C/run_l1_reset.py" --help
```

The recorded reset is already consumed; do not rerun its execution as a test.
Its frozen inputs remain available for offline reconstruction and unit tests.

## Separate Activation

Reset completion is not clean/unpause approval. `finalize` rejects clean=false
before verifying a proof. A separately reviewed checker must fork the actual
post-reset block/state, change clean only inside that fork and successfully
`eth_call finalize` with the genuine new-runtime/new-Genesis proof, including
negative controls. Only then may main separately approve the three real
clean=true transactions. Bridge remains pause7 during that step and initial
relayer startup. This runner neither performs nor attests to that later gate.
