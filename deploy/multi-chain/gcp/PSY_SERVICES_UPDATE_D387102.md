# Registered-user public-key update

Source: `PsyProtocol/psy-services`, deployment branch `multi_chain`,
commit `d387102497405d6034a97c617164cc9ed9dc32ba` (parent `9122e5d`).
Publish the source branch before deployment; source preparation checks remote
reachability. No node, compiler, SDK, wallet, Genesis or L1 contract change.

## Upgrade

Use `deploy-psy-services-update.sh`, not the fresh deployment runner.
The Debian Bookworm build packages both services/indexer binaries and all
migrations. The indexer wire format is unchanged; the fix is in the services
registration handler. Migration 051 repairs unambiguous confirmed historical
registrations, preserving genesis/ambiguous user rows and unrelated metadata.

1. Run the Rust registration test and disposable-Postgres fixture
   `scripts/fixtures/registered-user-public-keys.sql` from the services repo.
2. Run `check-registered-user-keys.sql` read-only against the services DB;
   retain private copies of `user_info` and registration `tx_events` first.
3. Verify the built archive SHA and source manifest. The live process path,
   not a potentially stale independent `current` symlink, is the rollback target.
4. Stage the independent release, stop the three indexers, start new services
   with migrations enabled, then start coordinator/realm indexers in order.
5. Require migration 051 successful, zero eligible public-key mismatches,
   user API keys matching node lookup, healthy API, advancing indexers, and
   unchanged node/Genesis provenance. No checkpoint replay is necessary.

```bash
DRY_RUN=1 bash deploy/multi-chain/gcp/deploy-psy-services-update.sh
CONFIRM_PSY_SERVICES_UPDATE=1 \
  bash deploy/multi-chain/gcp/deploy-psy-services-update.sh
```

## Rollback is API-only

`rollback-psy-services-update.sh` does not undo database changes. It disables
and stops all three indexers before restoring old binaries. It adds a final
services EnvironmentFile with `PSY_SERVICES_RUN_MIGRATIONS=false`, avoiding
SQLx rejection of migration 051 missing from the old release directory.
This is a deliberately degraded API-only recovery, not a healthy full stack.
Do not replay registrations into the old writer: it would restore the bug.

A forward deployment recognizes the rollback marker, permits stopped indexers,
removes only this managed override, applies migrations, and re-enables the
indexers through the normal deployment functions. Keep the private snapshot
for manual data investigation; never delete migration bookkeeping or revert
the corrected keys to make old code appear healthy.
