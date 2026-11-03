# Worker admission implementation

This crate implements the first stage of [Worker PoW admission and reputation recovery](../docs/src/protocol/WorkerAdmissionPoW.md): canonical SHA256 challenges, signed requests, atomic Redis identity state, recovery after an internally verified violation, and five RPC methods shared by realm and coordinator edges.

**Rollout mode is observe only.** New admission scores are stored separately from existing worker reputation. Legacy task RPCs continue to use their existing rules. Responses report `mode: "observe"` and `task_enforcement: false`; `enforce` is rejected at startup. A successful PoW in this stage is a shadow admission result, not protection for the task queue.

## Enable on an isolated edge

Admission RPCs are off by default. To register them, configure every edge for the same admission scope with matching values:

```sh
export PSY_WORKER_ADMISSION_MODE=observe
export PSY_WORKER_ADMISSION_NETWORK_ID=<64 lowercase hex characters identifying the network and genesis>
export PSY_WORKER_ADMISSION_EPOCH=<64 lowercase hex characters shared across these edges>
export PSY_WORKER_ADMISSION_BASE_BITS=<explicit measured difficulty>
export PSY_WORKER_ADMISSION_REDIS_URL=<Redis connection URL>
```

The edge supplies its existing realm ID, sub-ID and role. Realm and coordinator identities are separate, even when their numeric IDs match. Network ID and epoch must be nonzero and must survive normal restarts. The Redis URL is never included in RPC errors. These settings do not change the chain's genesis or rollback branch namespace.

Redis keys are under `admission:{scope_hash}:...`, independently of temporary checkpoint cleanup. A persistent policy fingerprint rejects edges configured with different difficulty or rate limits. This stage pins the whole policy per scope; changing it requires a coordinated new admission epoch. Live policy migration with outstanding challenges is reserved for the next stage.

The default policy uses a ten-minute challenge, a sixty-second signed request window, a thirty-second future clock tolerance, at most 1,024 outstanding challenges, 6,000 requests per minute per scope and 120 authenticated requests per minute per public key. These limits use shared Redis counters. Unauthenticated requests consume only the shared budget, so forged signatures do not spend another worker's identity budget. IP limits remain the ingress proxy's responsibility.

Never-activated temporary identities expire after their challenge and request windows. Activated identities and penalties do not expire. Activation and revocation also append audit events to a scope-local Redis stream; the stream retains approximately the latest 10,000 events and is diagnostic, not an external permanent audit archive. No authorization decision depends on that stream's retention.

Observe mode does not certify Redis persistence or failover safety. Before task enforcement, deployment checks must require the persistence, eviction, single-writer and epoch-recovery rules in the design. Keep this module in observe mode while those checks and the task lease/outbox implementation are incomplete.

## RPC methods

| Method | Parameters |
| --- | --- |
| `psy_worker_get_admission_info` | none |
| `psy_worker_get_admission_status` | signed `RequestAuth` |
| `psy_worker_get_pow_challenge` | signed `RequestAuth` |
| `psy_worker_submit_pow` | signed `RequestAuth`, `PowSolution` |
| `psy_worker_get_request_status` | signed `RequestAuth`, original request ID |

Method IDs in the signed envelope are 1 for status, 2 for challenge, 3 for submission and 4 for request status. The exact binary encoding is in `protocol.rs`, with independent Python-generated golden vectors in the tests. Hex strings have fixed lengths and lowercase encoding; all u64 fields use canonical decimal strings. Unknown fields are rejected in signed input types.

Status queries do not allocate identity records. They use generation 0 as a query placeholder. Mutations must use the generation returned by status. The payload hash is SHA256 of empty bytes for status/challenge, SHA256 of `challenge_id || nonce` for PoW submission, and SHA256 of the original 16-byte request ID for request status.

Only the latest activation receipt is currently available through request status. An identical submission retry returns the same receipt plus **current** admission state. A historical receipt after a penalty reports zero reputation; it does not activate the identity again. Reusing the latest activation request ID with different signed contents returns `REQUEST_CONFLICT`. Full task request receipts belong to the forthcoming lease protocol.

`revoke_for_verified_violation` is a trusted internal API and is not registered as an RPC. Its caller must first establish authenticated current-lease evidence. The first stage does not wire existing tag mismatches or timeouts to this API, because those paths do not yet supply the lease evidence required for safe punishment.

## Client probe

The probe performs the signed status/challenge/solve/submit flow against a trusted test edge. It supports both new identities and identities whose cooldown has ended. It obtains the scope from the edge and checks the configured network ID. Use a disposable test identity and set `PSY_WORKER_ADMISSION_PROBE_PRIVATE_KEY` through your secret mechanism; keys are read from the environment and are not printed or passed in argv.

```sh
cargo run --release -p psy_worker_admission --example pow_probe -- https://your-test-edge.example
```

The probe defaults to a maximum accepted difficulty of 30 bits. `PSY_WORKER_ADMISSION_PROBE_MAX_BITS` changes that local compute budget. This is a standalone integration probe; automatic recovery inside the existing proving worker will be connected alongside the V2 task protocol.

## Validation

```sh
cargo test -p psy_worker_admission
cargo test -p psy_worker_admission --test redis_integration -- --ignored   # includes the lease transactions
cargo check -p psy_node_common
```

The Redis tests require `redis-server` on PATH. Each starts its own disposable server on a private Unix socket with AOF and `appendfsync always`, without connecting to existing services. They check concurrent edge instances, exactly-once activation, penalty persistence across abrupt restarts, rate limits, challenge capacity, policy conflicts, corrupt storage and generations above JavaScript's precise integer range.

## Task leases (library only)

`lease.rs` implements the task lease state machine on a multi-record Redis transaction. **It is not called by any edge handler, queue or RPC yet**; legacy task paths are unchanged and `task_enforcement` stays false.

| Call | Effect, in one transaction |
| --- | --- |
| `reserve_claim` | Signed method 5. Charges per-identity in-flight (1/2/4 by reputation), scope `task_budget` and, for reputation 1 to 3, `low_reputation_budget`. A retried request ID returns the original claim and its lease |
| `attach_lease` | Binds the reservation to one `JobInstance` (pending ID, processing ID, job ID). A live lease is never replaced (`LEASE_BUSY`); after expiry or release the next lease gets `lease_version + 1` |
| `release_claim` | Returns a reservation that got no job, without penalty |
| `begin_verification` | Signed method 6 over lease, version, tag and proof hash. Only the current owner before the hard deadline gets the single verification slot; identical submissions share it. A signed tag mismatch returns evidence, it does not punish by itself |
| `accept_verified_result` | Re-checks the owner generation, then accepts, adds 1 (max 10), returns capacity and queues the outbox entry. If the owner was revoked first: stale, nothing scored |
| `fail_verification` | Infrastructure failure: lease released, nobody scored |
| `apply_attributable_violation` | Zeroes the owner and closes the lease; idempotent per lease instance |
| `reconcile` | Expires leases past their hard deadline whether or not the worker returns (minus 1, revocation at 0 without cooldown), releases overrun verifications and abandoned reservations without penalty. Safe on every edge at once |
| `pending_publications`, `mark_published` | Outbox for the publisher; mark only after canonical proof, reward tree and dependents are durable |

The Redis `COMMIT` script compares exact bytes of every record, type-checks every key and bounds every counter before its first write, so a refused transaction writes nothing. Capacity stays charged until the lease or reservation that holds it closes, including across a revocation. Lease records have no TTL and no garbage collection yet.

Not implemented: V2 task RPCs and handler wiring, NATS progress ACK and per-delivery ACK receipts, staged proof storage and the publisher, verification semaphores, scoped timeout exemption during outages, lease record retention, and Redis persistence checks. The worker then adopts V2 task requests and automatic PoW recovery. Enforced rollout follows multi-edge and fault-injection validation.
