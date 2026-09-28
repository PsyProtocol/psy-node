# Envio deposit timestamp rollout

## Status

Activated on 2026-09-28 after the operator authorized commit then deployment.
Both runtime candidates are committed locally on `fix/envio-deposit-timestamps-20260928`:

- Node/Envio: `e77f48ca3e54aa0ae978aa24f0a2c25d6264ab22`.
- Services: `6ce3c2ac1d739312ea346a6e774123031ea5b860`.

No push or maintained-branch merge was performed. Only Envio and Services were
restarted. No indexer/node/relayer/proxy restart, database reset or reindex.

## Sources and artifact

- Node worktree: `$WORKSPACE_HOME/psy-node-envio-timestamps-20260928`, based on
  `32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6`, plus timestamp changes.
  Old Envio handlers/schema/schema.ts/package.json hashes match live inputs.
- Services worktree: `$WORKSPACE_HOME/psy-services-envio-timestamps-20260928`,
  based on previous live `7c1e1f61673949bb7343529d4dd51d66f631d236`, bridge handler only
  plus documentation. No Cargo pins/lock, migrations or ABI metadata changes.
- Built with `psy-services-shared-client-builder:20260924`, Debian Bookworm,
  nightly-2025-09-20, `cargo build --locked --offline --release --bin psy-services`.
  Max GLIBC requirement: 2.34. Source mounted read-only, isolated target copy.
- Binary: `$WORKSPACE_HOME/tmp/envio-timestamp-rollout-20260928/services-target/release/psy-services`.
  SHA256: `93f183431c127025ead2ab832a57b369e33375560343b19bd1519ed3f60bdd6f`.
  Running: `gcp-cp-ce:/opt/parth/psy-services/releases/6ce3c2ac1d73-timestamps-93f18343/target/release/psy-services`.

## Completed checks

- Envio two handler/schema tests passed, covering all three L1 chain IDs.
- Services 48 bridge tests passed in the Bookworm build environment with
  dedicated disposable PostgreSQL/Redis: 0 failed, 0 ignored. Includes actual
  list/proof API tests asserting zero timestamp block RPCs for populated rows.
  Test containers/network were removed afterward; no production DB was used.
- Candidate Envio codegen and generated build ran against a copy of the REAL
  live config, not the offline timestamp fixture.
- Both original .env/config.yaml hashes retained. The source/generated polling
  patch survived codegen/build; actual RpcSource.make probe returned 12000 ms
  when run with the production interval environment.
- Envio database (about 20 MB) and Hasura metadata backed up under the protected
  `/var/lib/parth-envio-maintenance/20260928-timestamps/` on gcp-postgres.
- Restored a separate database `envio_timestamp_validation_20260928`; applied
  the additive migration twice. All 701 original Deposit row digests, saved
  chain state and DepositTreeMeta were unchanged by migration.
- Ran the new indexer for 45 seconds AGAINST THE CLONE, Hasura updates disabled,
  isolated metrics port 19898. It resumed existing state without reset/hash edits;
  Sepolia/BSC/Base all progressed. Original 701 deposits remained unchanged.
  Clone process ended; no active sessions remained on the clone database.

## Prepared Envio release and activation gate

Candidate: `/opt/parth/envio/releases/20260928-deposit-timestamps/psy-relayer-envio`.
Previous release: `/opt/parth/envio/releases/20260918161800/psy-relayer-envio`.
Activated candidate at 11:51:56 UTC. Final Envio PID: 3188867.

The pinned `remote/update-envio-timestamps.py` supports prepare/validate/activate.
It is staged under `/tmp/envio-timestamps-staged/` on gcp-postgres. Preparation
and clone validation already ran; do not rerun these phases blindly.
Activation requires the reviewed full source commit, rechecks staged/config
hashes and polling policy, stops only Envio, takes an additional backup, adds
nullable NUMERIC to Deposit AND rollback history, reloads Hasura and resumes
the new release. Rollback keeps additive columns and restores the old application,
never an old DB snapshot. No --restart, dev, schema reset or reindex command.

Services should follow via a services-only independent release, retaining the
running indexer binaries and processes. Its immutable manifest must identify
the committed candidate; preserve all existing env/ABI/Nostr settings. The
generic four-service updater is unnecessarily broad for this one-handler change.

## Live verification

- Services PID 1194110; running executable SHA matches the artifact above.
- All other CP-host service PIDs/states, protected env files and node release
  unchanged. Indexer bytes unchanged. Existing Nostr settings retained.
- Initial Services activation failed for about 80 seconds because copytree
  retained the release root's 0700 mode but changed its owner to root. Corrected
  the new root owner to match the old release. The rollout helper now preserves
  ownership and checks binary access as `parth` BEFORE switching configuration.
  Services recovered without binary/code changes; restart counter 15 is evidence
  of that activation failure, not 15 crashes in the new running application.
- 701 existing Deposit row digests unchanged. Both Deposit and rollback-history
  timestamp columns are nullable numeric. Hasura exposes the new field.
- Public list and proof endpoints passed on all chains: Sepolia deposit 579,
  BSC 58, Base 61; each proof returned found=true, with nonempty list timestamps.
- 90-second sample: processed heights Sepolia 11800350 -> 11800358,
  BSC 133665764 -> 133665952, Base 47414119 -> 47414162.
- Runtime interval and actual patched module both verify 12000 ms. Height-call
  rates per minute: Sepolia 9.33, BSC 12.67, Base 10.00; Envio may query again
  immediately when height changes, so the setting is not a strict 5/min cap.
- No populated timestamp rows yet: no new deposit arrived during observation.
  Live new-row timestamp validation remains pending; tests covered zero timestamp
  RPC calls when populated. Legacy rows intentionally still use RPC fallback.

Protected evidence on gcp-postgres:
`/var/lib/parth-envio-maintenance/20260928-timestamps/`
contains before/after snapshots, activation.dump, live-polling.json and
live-verification.json. Services evidence is at
`/var/lib/parth-services-maintenance/20260928-timestamps/` on gcp-cp-ce.

## Next maintenance

Observe a natural new deposit and compare block_timestamp with its L1 block;
do not submit transactions or backfill history merely to complete this check.
The verification helper runs on gcp-postgres with the staged rollout helper.
Keep these candidates when preparing the next authorized stable/deploy branch
integration; do not replace live Services with a newer incompatible product head.
The source manifest for the Node bundle remains unchanged: this rollout upgrades
only Envio's TypeScript application, NOT the Node/relayer/proxy Rust runtime.
