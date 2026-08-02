# API Services RPC Documentation

This document provides comprehensive documentation for the Psy API Services, which offer HTTP REST endpoints for querying blockchain data, worker statistics, rewards, and telemetry.

**Base URL**: `http://localhost:{port}`

**Default Port**: Configurable via `--port` parameter

---

## Table of Contents

1. [Authentication](#authentication)
2. [Health & User Management](#health--user-management)
3. [Event Management](#event-management)
4. [Statistics](#statistics)
5. [Job Status](#job-status)
6. [Legacy Rewards](#legacy-rewards)
7. [Leaderboard](#leaderboard)
8. [Checkpoint Operations](#checkpoint-operations)
9. [Worker Rewards](#worker-rewards)
10. [Admin Operations](#admin-operations)
11. [Contract Management](#contract-management)
12. [WebSocket Endpoints](#websocket-endpoints)
13. [Data Structures](#data-structures)

---

## Authentication

Some endpoints require JWT authentication with a secret token. Configure authentication using environment variables:

```bash
export JWT_SECRET="your-secret-key-here"
export JWT_EXPIRATION_HOURS="3"
```

**Authentication Header**:
```
Authorization: Bearer <jwt_token>
```

---

## Health & User Management

### GET /health

Health check endpoint.

**Request**: No parameters

**Response**:
```json
{
  "status": "ok"
}
```

**Example**:
```bash
curl http://localhost:3000/health
```

---

### POST /register

Register a new user in the system.

**Request Body**:
```json
{
  "public_key": "0x1234567890abcdef...",
  "twitter_handle": "@username",
  "label": "My Mining Rig",
  "signature": "0xabcdef..."
}
```

**Parameters**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key` | `string` | Yes | User's public key |
| `twitter_handle` | `string` | Yes | Twitter handle for verification |
| `label` | `string` | Yes | User-friendly label |
| `signature` | `string` | Yes | Signature for verification |

**Response**:
```json
{
  "success": true,
  "user_id": "12345"
}
```

**Example**:
```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "0x...",
    "twitter_handle": "@miner123",
    "label": "Mining Rig #1",
    "signature": "0x..."
  }'
```

---

### GET /user_info

Get user information by public key.

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `public_key` | `string` | Yes | User's public key |

**Response**:
```json
{
  "id": 12345,
  "public_key": "0x...",
  "twitter_handle": "@username",
  "label": "My Mining Rig",
  "created_at": "2024-01-01T00:00:00Z"
}
```

**Example**:
```bash
curl "http://localhost:3000/user_info?public_key=0x..."
```

---

## Event Management

### GET /worker_events

Query worker events with filtering options.

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `realm_id` | `u64` | Filter by realm |
| `status` | `WorkerEventStatus` | Filter by event status |
| `public_key` | `string` | Filter by worker public key |
| `topic` | `QJobTopic` | Filter by job topic |
| `circuit_type` | `ProvingJobCircuitType` | Filter by circuit type |
| `from_checkpoint_id` | `i64` | Start checkpoint (inclusive) |
| `to_checkpoint_id` | `i64` | End checkpoint (inclusive) |
| `offset` | `i64` | Pagination offset (default: 0) |
| `limit` | `i64` | Pagination limit (default: 300, max: 1000) |
| `order` | `string` | Sort order: "asc" or "desc" (default: "desc") |
| `category` | `JobFilterCategory` | Job category filter |

**Response**:
```json
[
  {
    "id": 1,
    "realm_id": 1,
    "worker_public_key": "0x...",
    "status": "Completed",
    "start_time": "2024-01-01T00:00:00Z",
    "end_time": "2024-01-01T00:01:00Z",
    "job_id": "...",
    "circuit_type": "UserRegistration"
  }
]
```

**Example**:
```bash
curl "http://localhost:3000/worker_events?realm_id=1&limit=100&order=desc"
```

---

### GET /user_events

Query user events with filtering options.

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_id` | `string` | Filter by user ID |
| `start_time` | `DateTime<Utc>` | Start time filter |
| `end_time` | `DateTime<Utc>` | End time filter |
| `tx_type` | `UserEventTxType` | Transaction type filter |
| `offset` | `i64` | Pagination offset (default: 0) |
| `limit` | `i64` | Pagination limit (default: 300, max: 1000) |
| `order` | `string` | Sort order: "asc" or "desc" (default: "desc") |

**Response**:
```json
[
  {
    "id": 1,
    "user_id": "12345",
    "public_key": "0x...",
    "tx_type": "RegisterUser",
    "checkpoint_id": 100,
    "timestamp": "2024-01-01T00:00:00Z"
  }
]
```

---

### GET /worker_events_aggregations

Get aggregated worker events statistics.

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `start_time` | `DateTime<Utc>` | Start time filter |
| `end_time` | `DateTime<Utc>` | End time filter |
| `bucket` | `string` | Time bucket: "2min", "1h", "1d", "1w", "1m", "all_time" |
| `offset` | `i64` | Pagination offset |
| `limit` | `i64` | Pagination limit |
| `order` | `string` | Sort order |

**Response**:
```json
[
  {
    "time_bucket": "2024-01-01T00:00:00Z",
    "total_events": 1000,
    "completed_events": 950,
    "failed_events": 50,
    "unique_workers": 25
  }
]
```

**Example**:
```bash
curl "http://localhost:3000/worker_events_aggregations?bucket=1h&limit=24"
```

---

### GET /user_events_aggregations

Get aggregated user events statistics.

**Query Parameters**: Same as worker events aggregations

**Response**:
```json
[
  {
    "time_bucket": "2024-01-01T00:00:00Z",
    "total_events": 500,
    "register_user_count": 10,
    "deploy_contract_count": 5,
    "user_tx_count": 485
  }
]
```

---

## Statistics

### GET /stats

Get general system statistics for the last 24 hours.

**Request**: No parameters

**Response**:
```json
{
  "status": "ok",
  "worker_events_24h": 1000,
  "user_events_24h": 500,
  "block_height": 150,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

**Example**:
```bash
curl http://localhost:3000/stats
```

---

### GET /stats/realms

Get global realm statistics.

**Response**:
```json
{
  "total_realms": 5,
  "active_realms": 4,
  "total_jobs_24h": 10000,
  "average_completion_time": 30.5
}
```

---

### GET /stats/realms/{realm_id}

Get statistics for a specific realm.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `realm_id` | `i64` | Realm identifier |

**Response**:
```json
{
  "realm_id": 1,
  "jobs_24h": 2000,
  "active_workers": 10,
  "average_completion_time": 28.3,
  "success_rate": 0.95
}
```

**Example**:
```bash
curl http://localhost:3000/stats/realms/1
```

---

### GET /stats/workers/{worker_public_key}

Get statistics for a specific worker.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `worker_public_key` | `string` | Worker's public key |

**Response**:
```json
{
  "worker_public_key": "0x...",
  "jobs_completed_24h": 100,
  "jobs_failed_24h": 5,
  "average_completion_time": 25.7,
  "success_rate": 0.95,
  "total_rewards": 1000
}
```

**Example**:
```bash
curl http://localhost:3000/stats/workers/0x...
```

---

## Job Status

### GET /stats/jobs

Get job status summary across all realms.

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `hours` | `u32` | Time window in hours |
| `realm_id` | `i64` | Filter by realm |

**Response**:
```json
{
  "summary": [
    {
      "status": "Completed",
      "circuit_type": "UserRegistration",
      "job_count": 1000,
      "average_duration": 25.5
    }
  ],
  "total_jobs": 5000,
  "query_time": "2024-01-01T12:00:00Z",
  "materialized_view_healthy": true
}
```

**Example**:
```bash
curl "http://localhost:3000/stats/jobs?hours=24"
```

---

### GET /stats/jobs/realm/{realm_id}

Get job status for a specific realm.

**Response**: Array of `JobStatusSummary` objects

---

### GET /stats/jobs/all-realms

Get job status grouped by all realms.

**Response**:
```json
[
  {
    "realm_id": 1,
    "total_jobs": 2000,
    "completed_jobs": 1900,
    "failed_jobs": 100,
    "success_rate": 0.95
  }
]
```

---

### GET /stats/jobs/counts

Get simple job counts by status.

**Response**:
```json
{
  "Completed": 4500,
  "Failed": 300,
  "InProgress": 200,
  "Pending": 1000
}
```

---

## Legacy Rewards

### GET /rewards/{worker_public_key}

Get worker rewards for a specific checkpoint.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `worker_public_key` | `string` | Worker's public key |

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `checkpoint_id` | `i64` | Yes | Checkpoint identifier |

**Response**:
```json
{
  "worker_public_key": "0x...",
  "checkpoint_id": 100,
  "total_rewards": 500,
  "job_count": 25,
  "reward_breakdown": [
    {
      "circuit_type": "UserRegistration",
      "job_count": 10,
      "rewards": 200
    }
  ]
}
```

**Example**:
```bash
curl "http://localhost:3000/rewards/0x...?checkpoint_id=100"
```

---

### GET /rewards_aggregations/{worker_public_key}

Get worker rewards aggregations over time.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `worker_public_key` | `string` | Worker's public key |

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `bucket` | `string` | Time bucket: "1d", "1w", "1m", "all_time" |
| `start_time` | `DateTime<Utc>` | Start time filter |
| `end_time` | `DateTime<Utc>` | End time filter |
| `limit` | `i64` | Pagination limit (default: 100) |

**Response**:
```json
[
  {
    "time_bucket": "2024-01-01T00:00:00Z",
    "total_rewards": 1000,
    "job_count": 50,
    "average_reward_per_job": 20.0
  }
]
```

**Example**:
```bash
curl "http://localhost:3000/rewards_aggregations/0x...?bucket=1d&limit=30"
```

---

## Leaderboard

### GET /leaderboard/workers

Get worker leaderboard based on 24-hour performance.

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | `i64` | Number of entries (default: 100, max: 100) |

**Response**:
```json
[
  {
    "rank": 1,
    "worker_public_key": "0x...",
    "total_rewards_24h": 2000,
    "jobs_completed_24h": 100,
    "success_rate": 0.98
  }
]
```

**Example**:
```bash
curl "http://localhost:3000/leaderboard/workers?limit=50"
```

---

## Checkpoint Operations

### GET /checkpoint/stats

Get checkpoint statistics by range.

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `start_checkpoint` | `i64` | Start checkpoint (default: 0) |
| `end_checkpoint` | `i64` | End checkpoint (default: max) |

**Response**:
```json
[
  {
    "checkpoint_id": 100,
    "total_jobs": 5000,
    "completed_jobs": 4800,
    "total_rewards_distributed": 50000,
    "unique_workers": 25,
    "processing_time": 120.5
  }
]
```

**Example**:
```bash
curl "http://localhost:3000/checkpoint/stats?start_checkpoint=90&end_checkpoint=100"
```

---

### GET /checkpoint/stats/{checkpoint_id}

Get statistics for a specific checkpoint.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `i64` | Checkpoint identifier |

**Response**: Single `CheckpointStats` object

**Example**:
```bash
curl http://localhost:3000/checkpoint/stats/100
```

---

### GET /checkpoint/job-events/{checkpoint_id}

Get job events for a specific checkpoint.

**Response**:
```json
[
  {
    "id": 1,
    "checkpoint_id": 100,
    "job_id": "...",
    "worker_public_key": "0x...",
    "circuit_type": "UserRegistration",
    "status": "Completed",
    "duration_ms": 30000,
    "start_time": "2024-01-01T00:00:00Z",
    "end_time": "2024-01-01T00:00:30Z"
  }
]
```

**Example**:
```bash
curl http://localhost:3000/checkpoint/job-events/100
```

---

### GET /checkpoint/summary/{checkpoint_id}

Get checkpoint reward summary.

**Response**:
```json
{
  "checkpoint_id": 100,
  "total_rewards": 50000,
  "total_jobs": 5000,
  "unique_workers": 25,
  "reward_distribution": {
    "UserRegistration": 20000,
    "ContractExecution": 30000
  },
  "processing_status": "Completed"
}
```

**Example**:
```bash
curl http://localhost:3000/checkpoint/summary/100
```

---

### GET /checkpoint/distributions/{checkpoint_id}

Get reward distributions for a checkpoint.

**Response**:
```json
[
  {
    "id": 1,
    "checkpoint_id": 100,
    "worker_public_key": "0x...",
    "circuit_type": "UserRegistration",
    "job_count": 10,
    "total_rewards": 500,
    "created_at": "2024-01-01T12:00:00Z"
  }
]
```

**Example**:
```bash
curl http://localhost:3000/checkpoint/distributions/100
```

---

## Worker Rewards

### GET /checkpoint/rewards/{worker_public_key}

Get worker's reward aggregations with flexible time periods.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `worker_public_key` | `string` | Worker's public key |

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `time_period` | `string` | Time period: "2m", "1h", "1d", "1w", "1m" (default: "1d") |
| `start_time` | `DateTime<Utc>` | Start time filter |
| `end_time` | `DateTime<Utc>` | End time filter |
| `limit` | `i64` | Pagination limit (default: 100) |

**Response**:
```json
{
  "worker_public_key": "0x...",
  "time_period": "1d",
  "aggregations": [
    {
      "time_bucket": "2024-01-01T00:00:00Z",
      "total_rewards": 1000,
      "jobs_completed": 50,
      "checkpoints_participated": 5
    }
  ],
  "total_rewards": 10000,
  "total_jobs": 500,
  "total_checkpoints": 50
}
```

**Example**:
```bash
curl "http://localhost:3000/checkpoint/rewards/0x...?time_period=1d&limit=30"
```

---

### GET /checkpoint/rewards/{worker_public_key}/stats

Get worker's overall reward statistics.

**Response**:
```json
{
  "worker_public_key": "0x...",
  "total_rewards_all_time": 100000,
  "total_jobs_completed": 5000,
  "total_checkpoints_participated": 500,
  "average_reward_per_job": 20.0,
  "first_job_date": "2024-01-01T00:00:00Z",
  "last_job_date": "2024-12-31T23:59:59Z"
}
```

**Example**:
```bash
curl http://localhost:3000/checkpoint/rewards/0x.../stats
```

---

## Admin Operations

### POST /checkpoint/calculate-rewards/{checkpoint_id}

Manually trigger reward calculation for a checkpoint.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `i64` | Checkpoint identifier |

**Response**: Array of `CheckpointRewardDistribution` objects

**Example**:
```bash
curl -X POST http://localhost:3000/checkpoint/calculate-rewards/100
```

---

### GET /admin/checkpoint-processing-status

Get the status of checkpoint reward processing.

**Response**:
```json
{
  "pending_count": 5,
  "pending_checkpoints": [101, 102, 103, 104, 105],
  "last_processed_checkpoint": 100,
  "status": "5 checkpoints pending"
}
```

**Example**:
```bash
curl http://localhost:3000/admin/checkpoint-processing-status
```

---

## Contract Management

### GET /contracts

Get list of deployed contracts with metadata.

**Query Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `deployer` | `string` | Filter by deployer public key |
| `limit` | `i64` | Pagination limit |
| `offset` | `i64` | Pagination offset |

**Response**:
```json
[
  {
    "uuid": "contract-uuid-123",
    "deployer": "0x...",
    "state_tree_height": 10,
    "function_count": 5,
    "functions": [
      {
        "name": "transfer",
        "method_id": 12345678,
        "description": "Transfer tokens"
      }
    ],
    "deployed_at": "2024-01-01T00:00:00Z"
  }
]
```

**Example**:
```bash
curl "http://localhost:3000/contracts?limit=100"
```

---

### GET /contracts/{contract_uuid}

Get detailed information about a specific contract.

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `contract_uuid` | `string` | Contract UUID |

**Response**: Single contract object with detailed metadata

**Example**:
```bash
curl http://localhost:3000/contracts/contract-uuid-123
```

---

## WebSocket Endpoints

### WS /ws/tps

Real-time TPS (Transactions Per Second) data stream.

**Connection**: Upgrade HTTP to WebSocket

**Message Format**:
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "tps": 150.5,
  "block_height": 1000,
  "total_transactions_24h": 500000
}
```

**Example**:
```javascript
const ws = new WebSocket('ws://localhost:3000/ws/tps');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Current TPS:', data.tps);
};
```

---

## Data Structures

### WorkerEventStatus

```rust
enum WorkerEventStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}
```

### UserEventTxType

```rust
enum UserEventTxType {
    RegisterUser,
    DeployContract,
    UserTransaction,
}
```

### JobFilterCategory

```rust
enum JobFilterCategory {
    All,
    UserRegistration,
    ContractDeployment,
    ContractExecution,
    Maintenance,
}
```

### CheckpointStats

```rust
struct CheckpointStats {
    pub checkpoint_id: i64,
    pub total_jobs: i64,
    pub completed_jobs: i64,
    pub failed_jobs: i64,
    pub total_rewards_distributed: i64,
    pub unique_workers: i64,
    pub processing_time_seconds: Option<f64>,
    pub created_at: DateTime<Utc>,
}
```

### WorkerRewardResponse

```rust
struct WorkerRewardResponse {
    pub worker_public_key: String,
    pub time_period: String,
    pub aggregations: Vec<WorkerRewardAggregation>,
    pub total_rewards: i64,
    pub total_jobs: i64,
    pub total_checkpoints: i64,
}
```

### CheckpointProcessingStatus

```rust
struct CheckpointProcessingStatus {
    pub pending_count: usize,
    pub pending_checkpoints: Vec<i64>,
    pub last_processed_checkpoint: Option<i64>,
    pub status: String,
}
```

---

## Error Handling

All endpoints return standard HTTP status codes:

- `200`: Success
- `400`: Bad Request (invalid parameters)
- `401`: Unauthorized (missing/invalid JWT)
- `404`: Not Found
- `500`: Internal Server Error

**Error Response Format**:
```json
{
  "error": "Error message description",
  "details": "Optional additional details"
}
```

---

## Rate Limiting

Rate limiting may be applied to prevent abuse. Check response headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1609459200
```

---

## Background Services

The API Services automatically run several background tasks:

1. **Job Status Refresh**: Updates job status every 10 seconds
2. **Checkpoint Reward Processing**: Processes rewards every 30 seconds  
3. **Worker Event Processing**: Converts worker events to job events
4. **TPS Broadcasting**: Broadcasts TPS data every 12 seconds via WebSocket

---

**Document Version**: 1.0  
**Last Updated**: 2024-12-16  
**Total Endpoints**: 35+