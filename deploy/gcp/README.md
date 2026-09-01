# GCP Staging SSH Deployment

For the isolated BSC Testnet profile that reuses the current machine topology,
see [`bsc-testnet/README.md`](bsc-testnet/README.md).

For the isolated BSC Testnet profile that reuses the current machine topology,
see [`bsc-testnet/README.md`](bsc-testnet/README.md).

These scripts deploy onto pre-created staging machines reachable through local
SSH config. They do not create VMs, networks, disks, or firewall rules.

## Setup

Copy and edit the config:

```sh
cp deploy/gcp/config.example.env deploy/gcp/config.env
editor deploy/gcp/config.env
```

The default config uses these SSH aliases:

```text
gcp-nostr
gcp-realm-worker-0
realm-worker-1
gcp-cp-ce
gcp-nats
gcp-postgres
gcp-prove-proxy  # legacy cloud prove/forwarder host
gcp-faucet
gcp-relayer  # legacy rollback host
gcp-redis
gcp-scylla
```

Check SSH access and endpoint discovery:

```sh
bash deploy/gcp/check-ssh-hosts.sh
```

The deployment scripts normally target pre-created VMs. A GCP operator can
create the dedicated `faucet` VM with the reviewed staging defaults:

```sh
bash deploy/gcp/admin/create-faucet-vm.sh
bash deploy/gcp/admin/create-faucet-vm.sh --apply
```

The script creates an `e2-standard-2` VM with a 30GB balanced boot disk and
private IP `10.148.0.33`. Staging runs Faucet Server and the lightweight
Relayer on this VM. It does not expose Faucet port `9998`; Caddy reaches that
port over the VPC. The legacy `gcp-relayer` host remains only as a rollback
target until it is retired.

## Bootstrap Existing Hosts

Run scripts from the repository root:

```sh
bash deploy/gcp/create-redis.sh
bash deploy/gcp/create-nats.sh
bash deploy/gcp/create-scylla.sh
bash deploy/gcp/create-postgres.sh
bash deploy/gcp/create-anvil.sh
bash deploy/gcp/deploy-l1-contracts.sh
bash deploy/gcp/deploy-faucet-server.sh
bash deploy/gcp/create-nostr.sh
```

These `create-*` names are kept for continuity, but they now mean "initialize
the existing SSH host". Each script waits for SSH, installs the service, starts
it, and runs a health check.

Scylla is started with `SCYLLA_SMP=4` by default and `SCYLLA_MEMORY=28g`.
`SCYLLA_MEMORY` is applied as the Docker/cgroup memory cap for the container,
so Scylla sizes its row cache against the capped memory while leaving several
GiB for the OS on the current 32 GiB staging VM class. Override
`SCYLLA_MEMORY` in `deploy/gcp/config.env` before running `create-scylla.sh` if
a future VM has a different memory size. `SCYLLA_DOCKER_MEMORY` can be used as
an explicit alias for the same container guard.

Envio is enabled by default and currently reuses `gcp-postgres`. It uses the
shared Postgres database `envio_bridge` and starts only Hasura plus the Envio
systemd service. Hasura listens on `HASURA_EXTERNAL_PORT` (`18080` by default).
Anvil runs on `ANVIL_VM_NAME` (`gcp-cp-ce` by default) as
`parth-anvil.service`. After Anvil is healthy, run `deploy-l1-contracts.sh` to
deploy `psy-contracts` to the staging L1 RPC and write the resulting addresses
to `/etc/parth/l1.env` on the Anvil host. `create-envio.sh` and
`deploy-relayer.sh` default to `http://${ANVIL_HOST}:${ANVIL_PORT}`.

Set `L1_DEPLOYER_PRIVATE_KEY` in `deploy/gcp/config.env`, or export it for the
whole deployment shell, to use a custom L1 deployer/admin key instead of
Anvil's default account. `deploy-l1-contracts.sh` derives the address, funds it
through Anvil's test RPC, patches the remote deployment copy of
`psy-contracts/config/localhost.json` so `admin/proposer/owner` use that
address, and syncs `L1_DEPLOYER_ADDRESS` back into `deploy/gcp/config.env`.

## Bundle Flow

For hosts that need Parth binaries:

```sh
bash deploy/scripts/build-linux-artifacts-bookworm.sh
```

This builds release binaries inside a Debian 12/bookworm container, copies them
to `deploy/artifacts`, and rebuilds `dist/parth-node-bundle.tar.gz`. The current
GCP staging VMs are Ubuntu 24, but the bookworm build remains the conservative
portable build path.

If you already built compatible release binaries some other way:

```sh
bash deploy/scripts/package-local-artifacts.sh
bash deploy/gcp/build-parth-bundle.sh
export PARTH_BUNDLE=dist/parth-node-bundle.tar.gz
```

`deploy-staging-stack.sh` builds `PARTH_BUNDLE` automatically when it is empty.
In the default staging mode, the bundle is uploaded once to
`PARTH_BUNDLE_CACHE_HOST` (`gcp-cp-ce`) and the other VMs fetch it over the
private VPC from `PARTH_BUNDLE_CACHE_PORT`. If the same bundle sha256 is already
installed, deployment skips the transfer.

## Service Deployment

Deploy services with wrappers:

```sh
bash deploy/gcp/deploy-cp-ce-stack.sh
bash deploy/gcp/deploy-coordinator-processor.sh
bash deploy/gcp/deploy-coordinator-edge.sh
bash deploy/gcp/deploy-realm-processor.sh
bash deploy/gcp/deploy-realm-edge.sh
bash deploy/gcp/deploy-coordinator-workers.sh
bash deploy/gcp/deploy-coordinator-worker.sh
bash deploy/gcp/deploy-realm-worker.sh
bash deploy/gcp/deploy-psy-services.sh
bash deploy/gcp/deploy-psy-indexer-coordinator.sh
bash deploy/gcp/deploy-psy-indexer-realm.sh
bash deploy/gcp/deploy-prove-proxy.sh
```

The current staging topology sets `DEPLOY_CLOUD_PROVE_PROXY=0`. Public Caddy
and internal bundle clients use the WireGuard gateway address configured by
`PUBLIC_PROVE_PROXY_UPSTREAM` and `CLIENT_PROVE_PROXY_URL`, and the heavy
prove-proxy runs on `arc99x2`. `deploy-prove-proxy.sh` remains available only
for an explicit cloud fallback deployment.

For the current staging topology, `deploy-cp-ce-stack.sh` runs these services on
`NODE_VM_NAME` (`gcp-cp-ce`): coordinator processor/edge, realm0
processor/edge, realm1 processor/edge, psy-services, coordinator psy-indexer,
realm0 psy-indexer, and realm1 psy-indexer. The bridge
relayer/proposer runs separately on `RELAYER_VM_NAME` (`gcp-faucet`) together
with the standalone Faucet Server. Realm edge ports are `1338` for realm0 and
`1339` for realm1.

Genesis wallet allocation for the current staging topology:
`private_keys.json[0]`, `[1]`, and `[3]` are reserved ZK wallets with zero PSY
in genesis. The cloud coordinator worker defaults to key index `0`; realm workers
default to key index `3`. The bridge relayer must use the key
registered as `BRIDGE_USER_ID=524288`; with the current 2-realm genesis
mapping, that is `private_keys.json[2]`, funded with `1,000,000 PSY`. Faucet
operators use SDK-key wallets from `private_keys.json[4]` through `[103]`.
Indexes `[4]` through `[102]` receive `10,000,000 PSY` each and the final
operator at `[103]` receives `9,000,000 PSY`. L2 genesis therefore starts with
exactly `1,000,000,000 PSY`, matching the L1 PSY token supply. The simple-mint
smoke test is disabled by default to preserve that parity; set
`SMOKE_SIMPLE_MINT_ENABLED=1` only when intentionally testing mint behavior.
`private_keys.json` and `genesis.json` are intentionally ignored by git.

`deploy-cloud-workers.sh` deploys the required cloud baseline on
`COORDINATOR_WORKER_VM_NAME`: one coordinator worker plus one worker for each
realm by default. This three-process cloud baseline fits the 16 GiB worker VM
and remains enabled even when offsite workers are healthy.

```sh
bash deploy/gcp/deploy-cloud-workers.sh
```

`deploy-worker-1.sh` and `deploy-worker-2.sh` remain available for the legacy
dedicated GCP realm-worker VMs. They are disabled in the fresh flow by default.

When `DEPLOY_OFFSITE_WORKERS=1`, the fresh flow adds coordinator, realm0, and
realm1 workers on `arc99x4` only after all cloud deployment steps and smoke
tests pass. Offsite workers are incremental capacity, not fallback or baseline;
their deployment never disables cloud workers.

The end-to-end staging orchestrator runs infra in parallel and node services in
dependency order:

```sh
bash deploy/gcp/deploy-staging-stack.sh
```

## Service Endpoints

By default `SSH_SERVICE_ENDPOINT_MODE=private-ip`: the deploy script SSHes into
each alias and writes the VM private IPv4 into `/etc/parth/common.env` and
service env files.

Override `SCYLLA_HOST`, `REDIS_HOST`, `NATS_HOST`, or `POSTGRES_HOST` in
`deploy/gcp/config.env` if you need explicit addresses.

## NATS Monitoring Uploads

`create-nats.sh` installs a lightweight performance monitor on the NATS VM when
`NATS_MONITOR_ENABLED=1`. It also installs `parth-upload-receiver.service` on
`NATS_MONITOR_UPLOAD_HOST_VM` (`gcp-cp-ce` by default). The monitor runs from
`parth-nats-monitor.timer` and periodically uploads JSON snapshots to:

```sh
gcp-cp-ce:/var/lib/parth/monitoring-uploads/nats/<nats-host>/
```

Each snapshot includes memory, disk, pressure, listening sockets, Docker/NATS
status, NATS `/varz` and `/jsz`, and recent kernel OOM/hung-task messages.
Inspect the newest report with:

```sh
ssh gcp-cp-ce 'sudo ls -lh /var/lib/parth/monitoring-uploads/nats/*/latest.json'
ssh gcp-cp-ce 'sudo jq . /var/lib/parth/monitoring-uploads/nats/*/latest.json'
```

To install or update only the monitoring pieces without recreating the NATS
Docker container:

```sh
bash deploy/gcp/install-nats-monitoring.sh
```

`create-nats.sh` also installs NATS with JetStream guardrails. The defaults pin
the Docker image to `nats:2.11-alpine`, cap JetStream at `4G` memory store and
`80G` file store, cap JetStream API buffering, and cap Docker JSON logs at
`100m x 5`. Override `NATS_MAX_MEMORY_STORE`, `NATS_MAX_FILE_STORE`, or
`NATS_IMAGE` in `deploy/gcp/config.env` if the VM size changes. JetStream
consumer `ack_wait` is not a NATS process flag; Parth writes it when creating
durable consumers. Staging defaults `NATS_WORKER_ACK_WAIT_MS=30000` for worker
queues and `NATS_EPHEMERAL_ACK_WAIT_MS=5000` for short-lived queues.

## Notes

- These scripts use plain `ssh` against local `~/.ssh/config`; large bundles use
  `rsync --checksum` so repeated deployments skip identical uploads.
- Remote commands use `sudo`; the configured SSH user must have sudo access.
- Data disk mounting is opt-in. Set `DATA_DISK_DEVICE` only after confirming the
  attached disk is safe to format/mount; otherwise scripts use the root disk.
- Nostr runs Docker Compose under `/opt/nostr-relay`: `nostr-rs-relay` listens on
  internal port `8080`, and the Caddy container exposes only `80`/`443`. Do not
  open `8080` publicly. Set `NOSTR_DATA_DISK_DEVICE` only when the Nostr data
  disk is confirmed safe to format/mount.
- Nostr installs `nostr-maintenance.timer` by default. The timer runs daily at
  `NOSTR_MAINTENANCE_ONCALENDAR` (`03:00 Asia/Singapore` by default), checks
  free space on `NOSTR_HOME`, and only deletes old SQLite events when free space
  is below `NOSTR_DISK_FREE_TARGET_PERCENT`. Retention windows are tried in
  order from `NOSTR_RETENTION_WINDOWS_DAYS`.
- The Nostr VM's Caddy can also act as the staging public HTTPS entrypoint.
  Staging defaults use `PUBLIC_BASE_DOMAIN=psy-protocol.xyz` and
  `PUBLIC_ENV_SLUG=stg`, which derive domains such as
  `coordinator-stg.psy-protocol.xyz`, `realm0-stg.psy-protocol.xyz`,
  `prove-stg.psy-protocol.xyz`, and `rpc-stg.psy-protocol.xyz`. Point those DNS
  records at the Nostr VM public IP, then re-run `create-nostr.sh` or
  `deploy-caddy-entrypoints.sh`. The scripts generate Caddy reverse proxies to
  the private VPC upstreams. Do not open the service ports directly to the
  internet.
