# R3 Caddy source reconciliation

This tool changes only the two Faucet upstreams and their temporary maintenance
fence, and carries forward the existing private-claimable maintenance fence.
It does not change Nostr, public L1 RPC/provider routing, billing isolation,
Services backends, query routes, access-log filters, keys, TLS or containers.
No Faucet grant, deposit, claim or backend-readiness check is performed here.

## Phases

```text
existing source + two runtime maintenance routes
    -> stage prepare -> check -> approved apply
both sources + runtime: new Faucet upstream, Faucet 503, private 503
    -> main verifies grant and approves evidence
    -> stage open -> check -> approved apply --open-confirmed
both sources + runtime: new Faucet upstream open, private 503 retained
```

`prepare` replaces only `10.148.0.31:29998` with `10.148.0.32:29998`
for `faucet-stg.psy-protocol.xyz` and `faucet.psy-protocol.xyz`. Both remain
503 for all methods, including OPTIONS. `open` removes only those two fences.
Both phases retain 503 for the **existing** matcher: host
`services-stg.psy-protocol.xyz`, paths `/api/v1/wallet/private-claimable` and
`/api/v1/wallet/private-claimable/*`. This is not a claim that the other Services
alias is fenced. Expansion of the matcher is a separate reviewed change.

The source remains Caddyfile text, never JSON disguised as Caddyfile. Exact
top-level blocks are wrapped with controlled `route`/`handle` blocks, retaining
the previous adapter-sorted fallback handlers and the site log declaration.
Native adaptation must equal an independently constructed whole-config result.
Only the stdin config hide path and consistent renaming of adapter-generated
mutually exclusive route groups are normalized. Group membership is preserved;
no arbitrary routes, headers, log settings or IDs are ignored.
The two legacy top-level runtime `@id` maintenance entries are deliberately
replaced by these checked Caddyfile-generated fences. After prepare, do not use
an old tag-deletion helper to reopen Faucet: use this tool's `open` phase. Private
maintenance remains enforced even though its old runtime-only `@id` is absent.

## Read-only discovery

Actual read-only inspection found the startup command:
`caddy run --config /etc/caddy/Caddyfile --adapter caddyfile`.
Its single-file bind source is `/opt/nostr-relay/Caddyfile`, mounted read-only.
The host inode was394629 and the bound inode393238 on device2049. These are
observations, not permanent pins; the stage captures and binds current identities.
The two files had identical bytes, but different inodes. The source adapted to
runtime exactly after removing the two checked R3 top-level maintenance routes.

On the actual Caddy host (`gcp-nostr`, not the separate WireGuard gateway), run
the reviewed, hash-checked deployment script as root. With no output directory,
this performs read/admin-GET/native-adapt only and prints hashes, not configs:

```sh
python3 -I -B caddy_r3.py stage --phase prepare
```

Full configs may contain credentials. They must remain in root0700 stage
directories with mode0600 files. Do not print full adapt output or copy those
configs into source control. Native `validate` provisions modules and can open
configured log/storage files; it is not part of adapt-only read-only discovery.
It is mandatory in `check` and again in `apply`, without starting Caddy listeners.

## Main-owned operation

Exclude all parallel Caddy writers during the operation. Locks protect cooperating
writers; full source/bind/runtime checks reject observed concurrent modifications.
Any drift after review requires a new reviewed stage, not looser comparisons.

```sh
python3 -I -B caddy_r3.py stage --phase prepare --output /opt/nostr-relay/caddy_config/r3-fenced
python3 -I -B caddy_r3.py check --stage /opt/nostr-relay/caddy_config/r3-fenced --report-sha256 REPORT_SHA
python3 -I -B caddy_r3.py check --stage /opt/nostr-relay/caddy_config/r3-fenced --report-sha256 REPORT_SHA --apply
```

The first command prints `report_sha256`. Independently review that report and
the tool hash before either apply command. Staging is create-only. `check` does
not write either Caddyfile, remount or reload. Never reuse an attempted stage.

For `open`, main supplies a hash-pinned JSON approval file, not a claim generated
by this tool. Its `prepared_caddyfile_sha256` binds the currently fenced source;
`grant_evidence_sha256` references the separately inspected real grant evidence:

```json
{
  "action": "open-r3-faucet",
  "approved_by_main": true,
  "prepared_caddyfile_sha256": "<64 lowercase hex characters>",
  "grant_evidence_sha256": "<64 lowercase hex characters>"
}
```

```sh
python3 -I -B caddy_r3.py stage --phase open --gate-evidence /root/r3-faucet-approval.json --gate-evidence-sha256 EVIDENCE_SHA --output /opt/nostr-relay/caddy_config/r3-open
python3 -I -B caddy_r3.py check --stage /opt/nostr-relay/caddy_config/r3-open --report-sha256 REPORT_SHA
python3 -I -B caddy_r3.py check --stage /opt/nostr-relay/caddy_config/r3-open --report-sha256 REPORT_SHA --apply --open-confirmed
```

## Bind writes and failure handling

The transaction is manually adapted from the reviewed R2 `apply_caddy_r2.py`:
hold the host file lock, pin container ID/PID/start time and both file identities,
briefly remount only the bound Caddyfile RW in that container's mount namespace,
write/fsync both existing inodes, and restore RO before validate/reload. No
rename, container restart/recreate, Nostr restart or DB operation is used.

Original host text, stale-bound text and runtime JSON are separate backups in
the stage. On failure, rollback only when both sources and runtime remain among
this attempt's known states. Restore the exact three-way baseline, including
runtime-only fences, not a reload of a stale Caddyfile. Unknown or partial writes,
container replacement, RO restoration failure or third-party changes require
manual recovery; never blindly retry. In-place two-file updates are not crash
atomic, and host/container restart must be excluded throughout this short window.

After apply, require source and bound bytes to match the candidate, original
inodes and container instance retained, bind RO, and runtime JSON exactly matching
native adaptation. Main separately verifies public queries, intended Faucet
state and private503 responses. This is not an E2E acceptance or grant attestation.

Do not run the old full-template `update-caddy-entrypoints.sh`: it can discard
parallel configuration and its stale-bind branch recreates the container.
`realm1-maintenance/gateway.py` controls a different WireGuard relay; it is not
a Caddy persistence helper. The R2 renderer/apply CLI is cohort-specific and
must not be used directly with R3 stages.

References: [Caddy route ordering](https://caddyserver.com/docs/caddyfile/directives/route)
and [native validation](https://caddyserver.com/docs/command-line#caddy-validate).

## Draft verification

Read-only native adaptation of the actual source/runtime pair passed for both
the fenced preparation and an in-memory open rendering. No stage was written
on the host, no remount/reload occurred, and runtime was checked unchanged.
Prepare Caddyfile SHA256:
`793506734c73bda4cff6e0e6aafce4d66ebd2e05c3a90ed6de2cbf88a42c9319`.
Open Caddyfile SHA256:
`5138e1c3e41c20d72ad1790727cc13218d0e695c4f80ecec790904ed3420557d`.
These are snapshot-specific candidate hashes, not authorization or evidence of
application. Native provisioning/validate and actual transaction remain pending
main's separately reviewed operation. Focused tests use synthetic configurations
and mocked host operations; they do not claim real remount or rollback execution.
