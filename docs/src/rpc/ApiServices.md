# API Services (HTTP)

> Regenerated 2026-09-08 from live `psy-services/src/api/server.rs`.

## Abstract

Actix-web HTTP API for explorer/indexer/wallet surfaces. Most routes live under `/api/v1`. Health probes are outside that scope.

## Authentication

- Env / flag: `PSY_JWT_SECRET` (see `psy-services/src/bin/main.rs` and `config/mod.rs`).
- `JwtAuth` middleware is wired for future per-route use; do not document bare `JWT_SECRET`.
- Expiration comes from config `api.jwt_expiration_secs`.

## Route inventory (80 routes)

| Method | Path |
|---|---|
| GET | `/api/v1/test` |
| POST | `/api/v1/telemetry/coordinator` |
| POST | `/api/v1/telemetry/realm` |
| GET | `/api/v1/telemetry/stats/{checkpoint_id}` |
| GET | `/api/v1/checkpoint/latest` |
| GET | `/api/v1/checkpoint/{checkpoint_id}` |
| GET | `/api/v1/checkpoint/{checkpoint_id}/realms` |
| GET | `/api/v1/checkpoints` |
| POST | `/api/v1/checkpoint_leaf` |
| GET | `/api/v1/metrics/tps` |
| GET | `/api/v1/metrics/dashboard` |
| GET | `/api/v1/transactions` |
| GET | `/api/v1/events` |
| GET | `/api/v1/explorer/bridge/activity` |
| GET | `/api/v1/user/activity` |
| GET | `/api/v1/bridge/withdrawals` |
| GET | `/api/v1/bridge/deposit-claim-proof` |
| GET | `/api/v1/bridge/deposit-tree-root` |
| GET | `/api/v1/bridge/deposit-snapshot-root` |
| GET | `/api/v1/bridge/withdrawal-claim-proof` |
| GET | `/api/v1/transaction/{tx_id}` |
| GET | `/api/v1/transaction/hash/{content_hash}` |
| POST | `/api/v1/tx/register_user` |
| POST | `/api/v1/tx/deploy_contract` |
| POST | `/api/v1/tx/update_contract` |
| POST | `/api/v1/tx/end_cap` |
| POST | `/api/v1/tx/contract_events` |
| POST | `/api/v1/tx/slot_updates` |
| POST | `/api/v1/tx/bytecode` |
| POST | `/api/v1/tx/bytecode/batch` |
| GET | `/api/v1/checkpoint/{checkpoint_id}/jobs` |
| GET | `/api/v1/checkpoint/{checkpoint_id}/jobs/reports` |
| GET | `/api/v1/checkpoint/{checkpoint_id}/jobs/{role_type}/{role_id}` |
| GET | `/api/v1/jobs/aggregations` |
| GET | `/api/v1/jobs/role/{role_type}/{role_id}` |
| GET | `/api/v1/jobs/stats` |
| GET | `/api/v1/jobs/latest-checkpoint` |
| GET | `/api/v1/blocks/latest` |
| GET | `/api/v1/blocks/{block_number}` |
| GET | `/api/v1/blocks/{block_number}/header` |
| GET | `/api/v1/tps/range` |
| GET | `/api/v1/stats/checkpoint/{checkpoint_id}` |
| POST | `/api/v1/contract/verify` |
| GET | `/api/v1/contract/{contract_id}/verification` |
| GET | `/api/v1/contract/{contract_id}/source` |
| GET | `/api/v1/artifact/{id}` |
| POST | `/api/v1/artifact/{id}/verify` |
| GET | `/api/v1/artifact/tx/{tx_hash}` |
| GET | `/api/v1/artifacts/public` |
| POST | `/api/v1/contract/abi/pending` |
| POST | `/api/v1/contract/abi/pending-update` |
| PATCH | `/api/v1/contract/{contract_id}/whitelist_root` |
| GET | `/api/v1/get/user/info` |
| GET | `/api/v1/get/user/list` |
| GET | `/api/v1/get/user/transactions` |
| GET | `/api/v1/get/user/activity` |
| GET | `/api/v1/get/user/public-claims` |
| GET | `/api/v1/get/user/notes` |
| GET | `/api/v1/get/contract/info` |
| GET | `/api/v1/get/contract/{id}/abi` |
| GET | `/api/v1/get/contract/list` |
| GET | `/api/v1/get/bridge/withdrawals` |
| GET | `/api/v1/get/bridge/deposit-claim-proof` |
| GET | `/api/v1/get/bridge/deposit-tree-root` |
| GET | `/api/v1/get/bridge/deposit-snapshot-root` |
| GET | `/api/v1/get/bridge/withdrawal-claim-proof` |
| GET | `/api/v1/get/bridge/public-claim` |
| GET | `/api/v1/get/bridge/deposits` |
| GET | `/api/v1/get/search/fuzzy` |
| GET | `/api/v1/get/search/users` |
| GET | `/api/v1/get/search/contracts` |
| GET | `/api/v1/get/search/transactions` |
| GET | `/api/v1/get/search/checkpoints` |
| GET | `/api/v1/get/checkpoint/{checkpoint_id}/user_events` |
| GET | `/api/v1/get/metrics/dashboard` |
| POST | `/api/v1/wallet/public-claimable` |
| POST | `/api/v1/wallet/private-claimable` |
| GET | `/health` |
| GET | `/health/ready` |
| GET | `/health/live` |

## Absent vs older docs

These paths from prior documentation are **not** registered in the current `configure_api_v1`:

- `POST /register`
- `/leaderboard/*`
- `/ws/tps` and other WebSocket reward streams
- Bare `/deposits`, `/withdrawals`, `/notes` at the API root (use `/api/v1/get/...` or `/api/v1/bridge/...`)

## Source

- `../psy-services/src/api/server.rs` (`configure_api_v1`, `build_app`)
- `../psy-services/src/bin/main.rs` (`PSY_JWT_SECRET`)
