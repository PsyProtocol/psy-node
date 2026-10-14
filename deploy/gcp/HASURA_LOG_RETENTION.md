# Hasura log retention

## Policy

The 2026-10-14 read-only inspection found `generated-graphql-engine-1` using
`json-file` with an empty options map. Its approximately 215 GiB log is container
stdout/stderr, not the indexed deposit database. PostgreSQL shares this host, so
unbounded logs can exhaust space required by the database.

The deployment-owned `remote/install-envio.sh` now emits:

```yaml
logging:
  driver: json-file
  options:
    max-size: "100m"
    max-file: "100"
    compress: "true"
```

- Rotate around 100 MiB and keep at most 100 files, including the active file.
- Nominal uncompressed budget is 10,000 MiB (about 9.77 GiB) per Hasura container.
  This is the operator-approved approximately 10 GiB local retention budget.
  Allow headroom
  for large log records and rotation/compression work; this is not a disk quota.
- Docker removes the oldest rotated file. Do not use host logrotate, truncate,
  or unlink Docker-owned log files while Docker is writing them.
- Preserve existing log types for this patch. Reducing query-log verbosity is a
  separate change requiring measurement and consideration of incident evidence.
- No guaranteed local retention in days. At the historical average of roughly
  215 GiB / 11 days, this budget covers about twelve hours, not seven days.
  Compression reduces disk usage but does not increase the retained file count.
  Measure the current byte rate before quoting a retention window.

If time-based retention is needed, proposed centralized targets are seven days
for full operational logs and thirty days for warning/error records. A collector
must redact credentials, GraphQL variables and personal/proof data and export
before local rotation. These targets are NOT implemented by this patch. Do not
put the archive on the PostgreSQL root disk. Avoid retaining unredacted raw
query logs in shared storage.

Suggested alerts (not installed here): filesystem 70% warning, 85% critical,
free space below 20 GiB critical; inspect log policy on every deployment.

## Fresh deployments

The installer writes the policy after Envio codegen and checks the running
container's `HostConfig.LogConfig` after creation. A mismatch fails deployment.
Keep this change under the existing `deploy/multi-chain-gcp` branch's `deploy/`.
No application, circuit, schema or logging backend change is required.

## Existing live container: separate approved maintenance window

Do NOT rerun `install-envio.sh` to apply this hotfix: that installer regenerates
Envio files and restarts the indexer. Do not run `envio dev`, schema resets,
`docker compose down`, volume removal, or global Docker cleanup.

1. Record container ID/image digest, Compose project and file labels, sanitized
   logging settings, health, Envio PID/restarts, per-chain cursors and deposit
   counts. Back up the actual Compose files and metadata/config in a protected
   directory, not in Git. Never print container environment secrets.
2. Decide which historical logs must survive. Export a bounded incident window
   through `docker logs` to protected off-host storage. Recreating the container
   deletes its previous local logs; do not silently discard required evidence or
   copy the entire 215 GiB onto the same disk.
3. Update only the actual Hasura service logging block, preserving image digest,
   project name, ports, mounts, database URL and all environment. Validate the
   rendered Compose configuration without printing secrets. Check that the diff
   has no unrelated changes. Do not substitute the fresh-deploy template.
4. With approval for a brief GraphQL outage, recreate only `graphql-engine` using
   the verified existing Compose project/files and `up -d --no-deps
   --force-recreate graphql-engine`. Do not restart Docker or PostgreSQL. A
   container restart alone does not install new log-driver options.
5. Inspect the NEW container ID and LogConfig, verify Hasura health and a real
   GraphQL read via both private and public endpoints. Check disk space released.
   Compare all three Envio cursors over at least two samples and check recent
   L1 deposit IDs against the indexed records for the maintenance window. Counts
   alone do not establish no missing events. Confirm Envio PID/restarts and
   PostgreSQL container identity stayed unchanged.
6. If unhealthy, restore the saved Compose definition and recreate only Hasura
   against the same database. Prefer retaining the bounded logging settings;
   rollback of application availability must not silently reinstate unlimited
   logging. Deleted old container logs cannot be restored except from the export.

This patch prepares future deployment policy; no live container was recreated,
logs deleted, collector configured, or retention alarm installed.

## Validation

```sh
bash -n deploy/gcp/remote/install-envio.sh
python3 deploy/gcp/tests/test-hasura-log-retention.py
```

The test uses PyYAML and validates the actual installer template and inspection
guard. It is not a live rotation/recreation test.

Reference: https://docs.docker.com/engine/logging/drivers/json-file/
