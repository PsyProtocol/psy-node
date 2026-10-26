# Relayer source reconciliation

## Release rule

Relayer is the `psy_cli/psy_relayer_cli` binary in `PsyProtocol/psy-node`.
It is not a separate repository or a deployment-only runtime fork. Runtime
changes belong on `multi_chain`; `deploy/multi-chain-gcp` merges that source.
Independent service deployment remains possible, but must use the same reviewed
node source pin from `source-versions.env`. The `EXPECTED_RELAYER_*` variables
are compatibility aliases, not independently maintained source versions.

Published runtime: `ae7be0348287589207c89cce46ce2db6865f27ab` on `multi_chain`.

This revision includes:

- `cd55955e`: per-chain withdrawal discovery and per-chain cursors.
- `0a26329c`: persistent withdrawal claim attempt limits, whole-batch errors,
  and protection against re-arming retired claims when events are replayed.
- `ae7be034`: bounded deposit log queries and RPC regression tests.

## Uncommitted patch audit

Reviewed the three modified relayer files in the shared
`psy-node-multi-chain-gcp-deploy` worktree without modifying that worktree.

| File | Disposition |
| --- | --- |
| `daemon.rs` | Superseded by upstream per-chain cursors. Do not replay the old patch, which passed one global event offset to multiple chains. |
| `propose_withdrawals.rs` | Superseded by upstream filtered pagination. The temporary patch compared totals across different chains and advanced by the requested 10,000 rows despite the services page cap of 1,000. Those behaviors must not be retained. |
| `deposit_logs.rs` | Useful fix ported to `multi_chain`: both search and collection use inclusive ranges of at most 50,000 blocks. Added a lazy iterator, one fixed head snapshot, block-tag resolution and RPC-level tests. |

The entire merged `psy_cli/psy_relayer_cli` directory is byte-identical to the
published runtime revision, including the retry and per-chain cursor fixes.
The merge keeps the existing deployment DApp gitlink unchanged; no frontend
deployment or contract/genesis generation is part of this change.

## Verification

Run from the clean runtime source checkout:

```bash
cargo test --release --locked --offline -p psy_relayer_cli --bin psy_relayer_cli
cargo build --release --locked --offline -p psy_relayer_cli --bin psy_relayer_cli
```

Results: 149 tests passed, including nine new deposit-log tests; release build
and CLI `--help` passed. Existing compiler warnings remain.
Independent staged-diff review found no defects.

From a clean checkout of the reconciled deployment branch:

```bash
source deploy/multi-chain/gcp/source-versions.env
bash deploy/gcp/verify-relayer-source.sh "$PWD"
bash deploy/gcp/tests/test-relayer-source.sh
```

The source gate is also called by multichain preflight and direct multichain
relayer deployment. It rejects an independent relayer pin, unpublished tracked
or untracked relayer files, and committed deployment-only relayer changes.
`ALLOW_DIRTY_DEPLOY_SOURCES=1` does not bypass this check.
This is a source gate, not a substitute for binary manifest/checksum verification.

## Remaining workspace work

The original shared worktree remains untouched, including its old relayer diff,
uncommitted user CLI changes, standalone updater scaffolding, and other deployment
work. Preserve those edits for their owners; do not deploy from that dirty tree
or apply its relayer patch again. Use a clean checkout of the published branches.

This reconciliation does not claim that the complete fresh-deployment profile is
ready. Older deployment branch differences outside `deploy/` still include the
frontend workflow, root Cargo metadata and E2E files. The general deployment-only
preflight remains strict and must not be bypassed; those differences and remaining
child-repository pins require a separate release cleanup before a full fresh run.

No online services were restarted or deployed, no transactions were submitted,
and no key, database, Genesis, or Groth16 setup was changed during this task.
