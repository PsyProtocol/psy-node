# API Services HTTP Methods

> Updated: 2026-09-07. Regenerated from `../psy-services/src/api/server.rs` (`configure_api_v1`).

## Abstract

`psy-services` exposes HTTP under `/api/v1` plus a few root routes (`/health`, …). This is **not** the old `/register` / `/rewards` / `/leaderboard` surface.

Source of truth: `../psy-services/src/api/server.rs`.

## Root routes

| Method | Path |
|---|---|
| GET | `/health` |

(Additional root routes may exist beside the v1 scope; check `server.rs` after the v1 configure block.)

## `/api/v1` inventory (active)

### Checkpoint / telemetry / metrics

- `GET /api/v1/test`
- `POST /api/v1/telemetry/coordinator`
- `POST /api/v1/telemetry/realm`
- `GET /api/v1/telemetry/stats/{checkpoint_id}`
- `GET /api/v1/checkpoint/latest`
- `GET /api/v1/checkpoint/{checkpoint_id}`
- `GET /api/v1/checkpoint/{checkpoint_id}/realms`
- `GET /api/v1/checkpoints`
- `POST /api/v1/checkpoint_leaf`
- `GET /api/v1/metrics/tps`
- `GET /api/v1/metrics/dashboard`

### Transactions / events / bridge

- `GET /api/v1/transactions`
- `GET /api/v1/events`
- `GET /api/v1/user/activity`
- `GET /api/v1/bridge/withdrawals`
- `GET /api/v1/bridge/deposit-claim-proof`
- `GET /api/v1/bridge/deposit-tree-root`
- `GET /api/v1/bridge/deposit-snapshot-root`
- `GET /api/v1/bridge/withdrawal-claim-proof`
- `GET /api/v1/transaction/{tx_id}`
- `GET /api/v1/transaction/hash/{content_hash}`

### Indexer submission

- `POST /api/v1/tx/register_user`
- `POST /api/v1/tx/deploy_contract`
- `POST /api/v1/tx/update_contract`
- `POST /api/v1/tx/end_cap`
- `POST /api/v1/tx/contract_events`
- `POST /api/v1/tx/slot_updates`
- `POST /api/v1/tx/bytecode`
- `POST /api/v1/tx/bytecode/batch`

### Jobs / blocks / stats

- `GET /api/v1/checkpoint/{checkpoint_id}/jobs`
- `GET /api/v1/checkpoint/{checkpoint_id}/jobs/reports`
- `GET /api/v1/checkpoint/{checkpoint_id}/jobs/{role_type}/{role_id}`
- `GET /api/v1/jobs/aggregations`
- `GET /api/v1/jobs/role/{role_type}/{role_id}`
- `GET /api/v1/jobs/stats`
- `GET /api/v1/jobs/latest-checkpoint`
- `GET /api/v1/blocks/latest`
- `GET /api/v1/blocks/{block_number}`
- `GET /api/v1/blocks/{block_number}/header`
- `GET /api/v1/tps/range`
- `GET /api/v1/stats/checkpoint/{checkpoint_id}`

### Contract verification / ABI

- `POST /api/v1/contract/verify`
- `GET /api/v1/contract/{contract_id}/verification`
- `GET /api/v1/contract/{contract_id}/source`
- `GET /api/v1/artifact/{id}`
- `POST /api/v1/artifact/{id}/verify`
- `GET /api/v1/artifact/tx/{tx_hash}`
- `GET /api/v1/artifacts/public`
- `POST /api/v1/contract/abi/pending`
- `POST /api/v1/contract/abi/pending-update`
- `PATCH /api/v1/contract/{contract_id}/whitelist_root`

### Nested `/api/v1/get/...` query scopes

Under `/api/v1/get/user`, `/api/v1/get/contract`, `/api/v1/get/wallet`, and `/api/v1/get/search` (see `server.rs` nested scopes for exact `/info`, `/list`, fuzzy search, and related paths).

## Obsolete names

Do not use documentation that lists `/register`, `/user_info`, `/worker_events`, `/rewards/...`, or `/leaderboard/workers` as current `psy-services` routes — those are not the live `/api/v1` surface.
