# Live component mapping (2026-10-09)

This directory maps the running stateful testnet to `deploy/multi-chain-gcp`,
compared at `9199c6288b4392a55b487e23484a8fcb3271f27c`. It is an observation,
NOT a new release cohort, executable build input, or deployment authorization.
Do not replace live binaries merely to make their source equal the branch tip.

## Files and confidence

- `components.json`: exact source/artifact mappings, known gaps and topology.
- `observed-20261009.json`: read-only systemd and file-hash evidence; each host
  has its own UTC sampling timestamp. No arguments, environment values or keys
  are stored.
- `collect.py`: repeatable read-only collector. It hashes `/proc/PID/exe` and
  checks PID/start-time stability, not just `/opt/parth/current`. Permission
  failures remain explicit; exit zero means collection completed, not health.
- `check.py`: checks coverage and verified artifact hashes against the snapshot.
  Default exit zero permits explicitly listed unverified identities; use
  `--require-verified` to fail until every mapped binary with a non-null expected
  SHA256 is verified. Envio's Node interpreter and Nginx have no pinned binary
  hash in this map; their process identities do not attest application source.
  This does not establish reproducible source provenance or business health.

`source-versions.env` one directory above remains the historical full-cohort
input. It cannot express the component exceptions in this map. Its Services,
Indexer, Relayer and runtime pins must not be used to overwrite live hotfixes.
New component updater work must read a separately reviewed component release
manifest, preserve the old-chain Genesis/setup, and compare current state first.

## Source correspondence

| Live component | Exact source or identity | Correspondence / remaining work |
| --- | --- | --- |
| Coordinator Processor | Node `32bfd3da` | Baseline present; still the old binary, not the newer deployment tip |
| Realm Processors 0/1 | Node `72da74e3` | GUTA-only artifact; selected fixes integrated; preserve this scope |
| Coordinator Edge | Node `876c1432` | Exact hotfix artifact; stable fixes integrated as `1c0863fa` and predecessors |
| Realm Edges 0/1 | Node `4ff86c81` | EndCap handoff live backport; stable `6eb53500`, deploy merge `9f4bcff5`; separate from Coordinator Edge |
| Relayer | Node `d1f0e4fc` | Selected changes integrated as `585022a3`; fee policy support in `21af7e5f` |
| Services API | Services `b6dd702` | External repository; API pin recorded here, not copied into Node source |
| Three L2 Indexers | Services `7c1e1f6` | Different from API version; do not update them implicitly with Services |
| Faucet | Binary SHA256 starts `b244e5f4` | This is NOT a Git SHA. Notes associate it with `619ba2ba` + `5c83064a`; exact build-source attestation missing |
| x2 Workers | Node `013d70b0`, AVX-512 | Missing runtime allocator/thread-pool backports and installation tooling |
| x1 USER | GPU composite artifact `8c6232b0...` | Running hash verified; exact dirty patch still needs reconciliation with build manifest |
| x3 SYSTEM | CPU composite artifact `ffffcb1d...` | Base `0d958525` plus gate/dependency patches; running hash verified |
| x4 USER | CPU composite artifact `e780e5bb...` | Base `116b9955` plus gate/dependency patches; running hash verified |
| Envio | Node `af6620fe` subtree + Envio 2.32.10/RPC patch | Missing source commit now published; stable/deploy integration and RPC patch lifecycle remain outstanding |

Cloud application hashes were read from running executables, including the
three Indexers. Services and Indexer source pins were also read from their
respective release `BUILD-MANIFEST.env` files. Faucet's release has no source
manifest, so its hash is authoritative while its exact Git source stays null.
Proxy composite source descriptions are historical build evidence, not proof
that the dependency revisions/patches are remotely published or reproduced.

All eight hosts were sampled at 06:52:49-06:53:42 UTC on 2026-10-09. The four
offsite snapshots were collected with operator sudo. All mapped, expected
application binary hashes now match running `/proc/PID/exe`; there are no
remaining permission gaps in this snapshot. This is not a workload health test.

`selected_fixes_integrated` means a scoped original/backport correspondence has
been recorded, not that the live binary was built from the stable/deploy tip.
`source_ref` is a source locator; the immutable `source_commit` remains the pin.
`complete: false` deliberately remains: verified binary identity does not close
missing source provenance, backports or reproducible build recipes.

The Envio history fix was the concrete unpublished-source gap found here:
`fix/envio-deposit-timestamps-20260928` was still at `e77f48ca`, while the historical
deployed timestamp/history fix came from `af6620fe`. The current installed-file
paths resolve to `20261009-local-rpc-sepolia`, not `20260928-history-af6620fe`.
Selected file hashes do not attest the entire newer release or loaded JS.
After independent review the existing history-fix commit was
published as a fast-forward on 2026-10-09. No server files or processes changed.
The x2 exact source is already published on `perf/worker-efficiency-20260930`;
it is contained in `multi_chain`, not yet fully integrated into the deploy tree.

The combined Redis proof-lifetime/NATS changes are in the deployment source,
but the observed Coordinator Processor remains `32bfd3da` and Realm Processors
remain the GUTA-only `72da74e3`. Do not report those combined fixes as deployed.

## Configuration and topology

- USER ingress: x1 Nginx, x1:x3:x4 weights **75:0:25**. x3 USER is disabled.
- SYSTEM: x3. x1 SYSTEM is disabled and still has a failed-state marker; this
  inventory does not clear it or restart anything.
- Faucet: `gcp-coordinator-worker`, not `gcp-faucet`; the old unit is disabled.
- Workers: x2 coordinator/realm-0/realm-1. Do not re-enable cloud standby or
  retired workers from an old topology example.
- Services: MemoryHigh 8 GiB, MemoryMax 12 GiB; retain its Nostr scan-state
  override. These protections still need a reviewed declarative installer.
- Relayer config hash at this observation is
  `6bdba497f75300d67f83e70835f8e2dd3b7d7b2ac499a559ca220feae1711ca5`,
  different from the earlier activation record. Its BSC-only fee policy was
  independently re-read and still has expected chain 97 and all three limits
  at 1 gwei. The complete configuration diff was not audited; do NOT restore
  the old file to force the hash to match. Private endpoint URLs stay private.
- Envio has the named-column history patch and `psyRpcPollingInterval()` in
  the installed JS. Installed file hashes are recorded; this check does not
  prove which bytes the existing Node process loaded at startup or remeasure
  the three chains' actual polling frequency.

## Repeat the audit

From this repository (cloud sudo must already be authorized/noninteractive):

```sh
python3 deploy/multi-chain/gcp/live/collect.py gcp-cp-ce --sudo
python3 deploy/multi-chain/gcp/live/collect.py gcp-faucet --sudo
python3 deploy/multi-chain/gcp/live/collect.py gcp-coordinator-worker --sudo
python3 deploy/multi-chain/gcp/live/collect.py gcp-postgres --sudo
python3 deploy/multi-chain/gcp/live/check.py --require-verified
```

The unprivileged arc audit cannot read the `parth` processes' `/proc/PID/exe`.
After copying `collect.py` as `~/psy-live-version-audit-20261009.py`, the operator
can run the following. These commands only read service properties and hashes;
they do not read private-key contents or restart any service.

```sh
ssh -t arc99x1 'sudo python3 ~/psy-live-version-audit-20261009.py arc99x1 --local'
ssh -t arc99x2 'sudo python3 ~/psy-live-version-audit-20261009.py arc99x2 --local'
ssh -t arc99x3 'sudo python3 ~/psy-live-version-audit-20261009.py arc99x3 --local'
ssh -t arc99x4 'sudo python3 ~/psy-live-version-audit-20261009.py arc99x4 --local'
```

Review host identity, timestamps and all hashes before replacing the snapshot.
Then run `check.py --require-verified`. Never turn PermissionError into success
by copying an expected hash into an observed field. A new binary or changed
source requires a new, separately reviewed component manifest.

## Integration boundary

This delivery adds the mapping and audit tooling only. It does not assert that
all listed runtime gaps are merged. Next work should preserve exact artifacts,
review/backport missing runtime changes through `release/testnet-stable`, and
place installers/configuration under this deployment branch's `deploy/` tree.
Do not wholesale-merge optimization branches or copy a local dirty source tree.
Frontend/Wallet/SDK and infrastructure package versions are outside this audit;
their separate repository release flows are not moved back into Node.

Open items, in order:

1. Backport Envio timestamp/history source and preserve the independent 12000 ms
   RPC polling patch in the install lifecycle; no clearing or replaying indexes.
2. Review x2 worker allocator/thread-pool source for stable integration separately
   from global plonky2 dependency changes. Keep its exact 013d70b0 build pin.
3. Recover and review the three proxy composite patches/dependencies and build
   recipes before publishing clean reproducible source refs. x1's recorded dirty
   diff digest is not yet reconciled with the local archived patch.
4. Recover Faucet build-source attestation; do not relabel its binary hash as a
   source commit or assume the latest PR21 commit was deployed.
5. Consolidate the reviewed per-host proxy/worker/ingress installers and Services
   overrides under deploy, preserving current topology rather than replaying
   historical one-shot scripts.
