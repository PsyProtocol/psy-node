# Runtime Risk Acceptance

Release `core-testnet-20261030-sd192`. The release profile requires every open runtime risk to be
disposed of before the reset. The owner decided that the unresolved items below are accepted and
recorded here, and fixed after launch. Acceptance changes no check: the deployment still verifies
every hash, fingerprint, authentication and proof gate. It only allows the reset to proceed while
these items remain open.

The items are the "Required Before Release" table of the independent review
(`../fresh-sdk210-20261030/REVIEW-NOTES.md`). They are findings or hypotheses in imported code, not
observations of deployed behavior. Each stays open until it is reproduced, fixed and rebuilt in its
own dependency cohort.

| # | Area | Status | Condition |
| --- | --- | --- | --- |
| 1 | Withdrawal packing: 176 inputs possible against a capacity of 128 | Accepted, fix after launch | Capacity stays 128; the five-entry withdrawal acceptance runs before public admission |
| 2 | Standalone quarantine planning writes markers on an empty-offset scan | Accepted, fix after launch | Fix needs the per-chain append cursor on that path |
| 3 | Held token mapping has no TokenMappingMismatch clear arm | Accepted, fix after launch | Operator holds stay manual until the arm exists |
| 4 | MCP uncertain submission can refund a policy authorization | Accepted, fix after launch | MCP tools are not part of this release |
| 5 | MCP tools render the raw nonce as the nullifier | Accepted, fix after launch | MCP tools are not part of this release |
| 6 | External IMT cache keys may omit base and capacity | Accepted, fix after launch | Reproduce before choosing any circuit change |
| 7 | Local launcher reset can include non-local deployment directories | Accepted, fix after launch | Applies to local launchers only; no deployment step runs them |
| 8 | XOR helper slot-sum rejection hypothesis | Accepted, fix after launch | The current three-input path is pairwise; unsupported larger folds stay untested |
| 9 | Realm recovery: own-inclusion recovery, discarded rollback errors, shutdown sampling | Accepted, fix after launch | Restart and failure tests precede any pipeline change |
| 10 | Guardian liveness: unbounded sign and verification waits | Accepted, fix after launch | Guardians start only at the bridge step, after the L2 gate; the three-readiness check at that step must pass before the bridge is activated |
| 11 | Receipt reason 5 may be an already registered full-identity key | Accepted, fix after launch | Registration recovery never replays an uncertain send |
| 12 | End-to-end script expects a pending entry for direct small withdrawals; stale comments | Accepted, fix after launch | Acceptance distinguishes direct payment from pending claims |
| 13 | Provenance and setup: historical npm source not reconstructable; 35-word verifiers and final pins not yet accepted together | Accepted, fix after launch | Closed by Groth16 setup, L1 bundle and three-chain acceptance before public admission |

Acceptance does not cover the gates that stay mandatory: the five-entry withdrawal acceptance, the
three-chain illegal-then-legal deposit, claim and withdrawal run, the L2 stability gate, and public
admission staying closed until those pass.

## Infrastructure Baseline

Read-only inspection of the live testnet on 2026-11-01 (`docker inspect` fields Image, RepoDigests,
Config.Cmd, Config.Entrypoint and HostConfig only). The lock pins each image by the digest below.
Every digest equals the image the live container already runs. The previous deployment ran Scylla and
Valkey from the `latest` tag and NATS from `2.11-alpine`; pinning changes nothing about the running
bytes today but stops a later pull from moving them.

| Service | Pinned image | Start arguments on the live host |
| --- | --- | --- |
| Scylla | `scylladb/scylla@sha256:7e93267357fe3fbd3da3c92aa0e980f08ddadc1fe8a38c2aae3a3f7f9a1014a7` | `--smp 4 --developer-mode 1 --overprovisioned 1 --experimental-features=lwt --commitlog-sync=batch --commitlog-sync-batch-window-in-ms=2 --commitlog-sync-period-in-ms=10`; entrypoint `/docker-entrypoint.py`; memory limit 28 GiB; capability `PERFMON`; port 9042; restart `unless-stopped`; data and udev directories bind-mounted from the host |
| Valkey | `valkey/valkey@sha256:3b55fbaa0cd93cf0d9d961f405e4dfcc70efe325e2d84da207a0a8e6d8fde4f9` | `valkey-server --dir /data --dbfilename dump.rdb --appendonly yes --appendfilename appendonly.aof --appendfsync everysec --no-appendfsync-on-rewrite yes --auto-aof-rewrite-percentage 100 --auto-aof-rewrite-min-size 64mb --maxmemory 24gb --maxmemory-policy noeviction --save ""`; port 6379; restart `unless-stopped` |
| NATS | `nats@sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00` | `-c /etc/nats/nats-server.conf` with the server configuration bind-mounted read-only; ports 4222 and 8222; JSON log rotation 5 files of 100 MiB; restart `unless-stopped` |
| Postgres | `postgres@sha256:71e27bf60b70bded003791b5573f8b808365613f341df20ffcf0c1ed7bc13ddf` | `postgres` with default arguments; shared memory 2 GiB; port 5432; initialization directory bind-mounted read-only; JSON log rotation 100 files of 100 MiB, compressed; restart `unless-stopped` |
| Nostr relay | `scsibug/nostr-rs-relay@sha256:03f54bfbffff80a50db62c9287913bd25a2dec08033b56d2122bc2550363d5c5` | `./nostr-rs-relay --db ${APP_DATA}` with the database directory and a read-only configuration file bind-mounted; restart `unless-stopped` |
| Hasura (Envio) | `hasura/graphql-engine@sha256:13bb9088f5b011b15af117fd1b175360f5205946bee1a78d9e0c846e5a38551c` | `/bin/sh -c "${HGE_BINARY}" serve`; open-file limit 65536 soft and 524288 hard; bound to the private Postgres address; restart policy differs per Envio project |

Differences the new infrastructure steps must reproduce or decide on:

- Scylla runs with `--developer-mode 1` and `--overprovisioned 1`. Both are inherited from the old
  deployment, not chosen for this release. Production sizing is a separate decision; changing it is
  out of scope here and the flags are recorded so the rebuild does not drop them silently.
- Valkey is configured for `noeviction`, matching the release profile. The step must read the policy
  back from the running server, not from the start arguments.
- The Postgres image has no start arguments; capacity settings come only from the shared-memory size
  and the initialization directory.
- Only the image digests are pinned here. Host-specific bind-mount paths and environment values stay in
  the private host configuration.

## Left on disk until an operator clears them

The Proxy hosts and the Faucet host have no passwordless sudo, so inspection read only what any user can read. The
retirement lists keep the following in `retain`, which means the automated clearing never touches them. They hold
retired chain state or may hold credentials, and stay on disk until an operator clears them in the operator step:

- Retired Proxy release state directories under `/var/lib/psy-core-prove-proxy/` and their private targets under
  `/var/lib/private/psy-core-prove-proxy/` (SYSTEM and USER Proxy hosts), and the drop-in directories of the Proxy units.
- Retired Faucet state directories `/var/lib/psy-faucet-*-x2` and the Faucet staging directory on the Faucet host.
- The Faucet custody directory `/etc/psy-faucet`, which is protected as Faucet operator material and is never cleared.
- WireGuard configuration and the host credential secret on those hosts; both are protected.

Paths on other hosts that could not be shown free of key material were treated the same way: relayer and Guardian
RPC documents, relayer RPC cut-over records, and the legacy worker and Faucet environment files stay in `retain`.
