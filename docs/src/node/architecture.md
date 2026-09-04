# Node Architecture

> Updated: 2026-09-03.

## Abstract

The Psy network separates global coordination, realm transaction processing, proof generation, external data services, and storage. Coordinator and realm nodes each use edge and processor components, while workers generate proofs and peer-to-peer validators certify realm proposals.

## Table of Contents

- [1. Core Components](#1-core-components)
- [2. Node Roles](#2-node-roles)
- [3. Proof Generation](#3-proof-generation)
- [4. Supporting Services](#4-supporting-services)
- [5. Storage](#5-storage)
- [6. Network Topology](#6-network-topology)
- [7. Security Boundaries](#7-security-boundaries)

## 1. Core Components

### 1.1 Coordinator

The coordinator maintains upper-level network state and coordinates global updates.

Responsibilities:

- Maintain the global contract tree and user registration tree.
- Store user public-key parameters and fingerprints.
- Store contract bytecode and function circuit fingerprints and signatures.
- Assign user identifiers and contract identifiers as tree leaf indices.
- Aggregate realm proofs into global user-tree updates.

Tree capacity:

- The global user tree has 32 levels.
- The global contract tree has 24 levels and supports up to $2^{24}$ contract leaves.
- The coordinator owns 12 levels of the global user tree, while realms own 20 levels.

The contract and user-tree constants are defined in `psy_core/src/network_config/local_devnet.rs:27-37`.

### 1.2 Realm

Realms process user transactions and maintain the realm portion of the user tree and contract-specific user data.

Responsibilities:

- Accept and process user transactions.
- Store the lower 20 levels of the global user tree.
- Manage realm-local contract user data.
- Produce aggregated zero-knowledge proofs and Global User Tree Aggregator updates.
- Submit certified realm results to the coordinator.

Each realm covers $2^{20}$ user leaves. The configured 32-level global user tree therefore supports 4096 realms.

Each realm targets tens of thousands of transactions per second, while horizontal scaling across dozens of realms targets aggregate throughput of one million transactions per second.

## 2. Node Roles

### 2.1 Edge

Coordinator and realm edges:

- Receive external remote procedure calls.
- Validate submitted state transitions and proofs.
- Expose job discovery and proof-submission interfaces to workers.
- Forward accepted work to processors.

### 2.2 Processor

Coordinator and realm processors:

- Execute accepted state transitions.
- Process contract deployment and user registration operations.
- Generate witness data and proof-job graphs.
- Coordinate proof work and persist committed state.

### 2.3 Peer-to-peer validators

Realm peer-to-peer validators exchange proposals, votes, and certificates. The current node command exposes identity, BLS key, listen address, bootnode, coordinator, validator-set, and epoch-rotation inputs (`psy_cli/psy_node_cli/src/subcommand.rs:60-88`).

## 3. Proof Generation

### 3.1 Local proving

Psy uses local execution and proof generation:

1. A user executes contract logic locally.
2. The user produces a proof-backed state transition.
3. An edge validates the submitted transition.
4. A processor incorporates accepted work into realm or coordinator state.
5. Workers generate assigned recursive proofs.

The network stores proof-verified state transitions rather than executing a virtual machine for each transaction on the node.

### 3.2 Worker flow

1. A processor produces witness data and a proof-job graph.
2. A worker claims available jobs from an edge.
3. The worker generates proofs for the assigned jobs.
4. The worker submits completed proofs.
5. The processor combines completed work into the next state transition.

### 3.3 Aggregation

At realm level, transaction proofs are aggregated into one realm proof and one Global User Tree Aggregator update. At coordinator level, certified realm updates are aggregated into the global state transition.

## 4. Supporting Services

### 4.1 Prove proxy

The prove proxy assists clients that need remote proof computation. It supplements the local proving path without changing the proof-verification boundary.

The prove proxy is intended to reduce the computational burden on resource-constrained clients and can scale down as client proving performance improves.

### 4.2 API and indexer services

The external `psy-services` repository provides application-facing APIs and indexing. These services read network data and expose explorer and application queries; they are not `psy_node_cli` subcommands.

## 5. Storage

### 5.1 Runtime systems

The node runtime accepts these storage and messaging inputs:

| Input | Role |
|---|---|
| `--scylla-db-url` | Persistent distributed state |
| `--redis-url` | Temporary state and queue data |
| `--nats-jetstream-url` | Durable node messaging |
| `--db-namespace` | Role-specific storage namespace |

The flags are defined for realm and coordinator processes in `psy_cli/psy_node_cli/src/subcommand.rs:24-34,95-105,163-173,201-211`.

### 5.2 Data ownership

- Coordinator nodes store global trees, registrations, contract metadata, and coordinator checkpoints.
- Realm nodes store realm user data, contract state, and realm checkpoints.
- Redis and NATS JetStream support processing and communication; ScyllaDB owns persistent node state.

## 6. Network Topology

```text
                         +----------------------+
                         | Coordinator cluster  |
                         | global state         |
                         +----------+-----------+
                                    |
                    certified realm updates and queries
                                    |
                 +------------------+------------------+
                 |                                     |
        +--------v---------+                  +--------v---------+
        | Realm 0 cluster  |                  | Realm N cluster  |
        | user state       |                  | user state       |
        +--------+---------+                  +--------+---------+
                 |                                     |
            proof jobs                              proof jobs
                 |                                     |
        +--------v---------+                  +--------v---------+
        | Workers          |                  | Workers          |
        +------------------+                  +------------------+

Each coordinator or realm cluster:

        +------------------+    queue/messages    +------------------+
        | Edge             |<-------------------->| Processor        |
        | external RPC     |                      | state transition |
        +------------------+                      +------------------+
```

This separation allows edge capacity, processor capacity, realm count, and worker count to scale independently.

## 7. Security Boundaries

1. Edge admission is not state commitment; processors and proof verification determine accepted state.
2. Realm certificates bind validator votes to realm proposals before coordinator inclusion.
3. Persistent state belongs in ScyllaDB; Redis and NATS JetStream must not become competing state authorities.
4. User private keys remain outside node services and must not be placed in node configuration.
