# Psy-services update 9122e5d

## Target

- Repository: `PsyProtocol/psy-services`
- Branch: `multi_chain`
- Commit: `9122e5de2d33ea6aba6d7bef101e742198879836`
- Previous pin: `46f8463cc5d6393ce73c5cbbeac79e08c6add821`
- Release archive: `dist/psy-services/psy-services-9122e5de2d33ea6aba6d7bef101e742198879836.tar.gz`
- Archive SHA-256: `e4ce1fc7b17a8d7649dc0be6eb75d12c2fc94a2d94e827803a4667825fccfe34`

The archive was built twice in Debian Bookworm and produced the same SHA-256.
Both binaries require at most GLIBC 2.34.

## Change boundary

The two commits after the previous pin modify the psy-services API and
repository query layer. They do not modify:

- `src/indexer/` or the `psy-indexer` CLI;
- `Cargo.toml` or `Cargo.lock`;
- PostgreSQL migrations;
- the pinned psy-node dependency revision.

The three indexer instances remain coordinator, realm 0, and realm 1. They
index L2 checkpoints and do not multiply by the number of L1 networks. Envio
continues to index Sepolia, BSC Testnet, and Base Sepolia.

The service-only deployment restarts psy-services and those three indexers so
all four processes use binaries from the same source commit. It does not reset
their backup or watermark state.

## Online baseline

Read-only checks before deployment found:

- coordinator, realm 0, and realm 1 synchronized and advancing from checkpoint
  18383 to 18384 during a 12-second sample;
- psy-services and all three indexers active, with no warning-or-higher journal
  entries in the preceding two hours;
- public psy-services health returned HTTP 200;
- the new `/api/v1/explorer/bridge/activity` endpoint returned HTTP 404, as
  expected before this release;
- current processes run from `/opt/parth/releases/20260904095105/psy-services`;
- current service configuration contains the multichain `PSY_L1_CHAINS` registry;
- relayer was six checkpoints behind and actively producing bridge proofs;
- offsite prove-proxy on `arc99x3` was active with zero restarts, about 62.8
  GiB current memory, 65.2 GiB peak, 26 GiB host memory available, and no swap
  in use.

The generic staging audit still expects the retired `arc99x2` host and an
intentionally disabled second cloud coordinator worker. Those checks are stale
topology assumptions, not failures in this psy-services deployment.

## Deployment

Do not run this update unattended. First review:

```bash
cd /home/peter/git/bridge_zilong/psy-node-multi-chain-gcp-deploy

GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  DRY_RUN=1 \
  bash deploy/multi-chain/gcp/deploy-psy-services-update.sh
```

When the operator is present:

```bash
GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  SKIP_BUILD=1 \
  CONFIRM_PSY_SERVICES_UPDATE=1 \
  bash deploy/multi-chain/gcp/deploy-psy-services-update.sh
```

The script refuses to proceed unless the old service/indexers, old binaries,
migrations, and public health endpoint are available. It verifies the archive
checksum and manifest, registers the existing full-bundle service directory as
the first rollback target, stops the indexers, restarts psy-services with
migrations enabled, restarts each indexer, then checks:

- all four systemd units are active;
- every process executable resolves into the independent release;
- the public health endpoint is healthy;
- the new activity endpoint returns all three chain indexes;
- no error-priority journal records appeared during deployment.

## Rollback

```bash
GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  CONFIRM_PSY_SERVICES_ROLLBACK=1 \
  bash deploy/multi-chain/gcp/rollback-psy-services-update.sh
```

The first rollback target is the currently running full-bundle service
directory. Later deployments retain explicit `current` and `previous`
symlinks. Binary rollback does not reverse PostgreSQL migrations. This
particular update has no migration delta.
