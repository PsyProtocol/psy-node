# Node Architecture

The Psy network consists of multiple node types that work together to maintain the blockchain state and process user transactions through zero-knowledge proofs.

## Core Components

### Coordinator

The coordinator maintains the upper-level blockchain state and serves as the central coordination point for the network.

**Responsibilities:**
- Maintains contract tree for all deployed contracts
- Manages upper portion of user tree (level 0)
- Stores user registration tree
- Maintains user information including `ZKPublicKeyInfo` (public key parameters and fingerprint)
- Stores contract bytecode and circuit fingerprints/signatures for each contract function
- Assigns user IDs and contract IDs as tree leaf indices

**Tree Management:**
- Supports up to 2^32 registered users
- Supports up to 2^32 deployed contracts
- Coordinator manages 12 layers of user tree height
- Aggregates realm-level proofs into level 0 user tree root modifications

### Realm

Realms handle user transactions and manage the lower portion of the user tree along with contract-specific user data.

**Responsibilities:**
- Accepts and processes user transactions
- Stores lower portion of user tree (up to 20 layers height)
- Manages user data for specific contracts within the realm
- Generates aggregated ZK proofs and GUTA (Generalized User Transaction Aggregation) for realm root modifications

**Capacity:**
- Each realm can handle up to 2^20 users (when using 20-layer height)
- Tree height is configurable based on network requirements
- Each realm supports tens of thousands of TPS (transactions per second)
- Network target: 1 million TPS achievable with dozens of realms

## Node Architecture

### Multiple Node Consensus

Both coordinator and realm operations are distributed across multiple nodes:
- **Multiple Coordinator Nodes**: Consensus mechanism determines the primary coordinator
- **Multiple Realm Nodes**: Each realm has multiple nodes with consensus for primary selection
- **One Coordinator, Multiple Realms**: Network topology supports horizontal scaling

### Edge and Processor Components

Each coordinator and realm consists of two main components:

#### Edge Nodes
- Receive and validate user transactions
- Verify uploaded state deltas through ZK proof validation
- Manage task priority ordering for proof generation
- Handle external communication and API endpoints

#### Processor Nodes
- Execute user-submitted state deltas
- Process contract deployment requests
- Handle user registration requests
- Generate witness data and job graphs for proof workers
- Coordinate with workers for ZK proof generation

### Inter-Component Communication

**V1 Architecture:**
- Edge and processor communication through shared Redis storage

**V2 Architecture:**
- Communication via NATS JetStream for improved reliability and performance

## Proof Generation Architecture

### Local Proving Model

Psy implements a local proving architecture where:
- Users perform VM execution locally
- Blockchain only stores ZK-verified state deltas
- No on-chain VM execution or gas metering
- Edge nodes validate correctness through ZK proof verification

### Worker-Based Proof Generation

**Workflow:**
1. Processor generates witness data and job graphs from state deltas
2. Workers claim tasks based on priority ordering (managed by edge nodes)
3. Workers generate ZK proofs for assigned jobs
4. Completed proofs are submitted back to processors

### Proof Aggregation

**Realm Level:**
- Multiple user transactions affecting contract state generate individual proofs
- Realm aggregates all proofs into a single ZK proof + GUTA
- Represents realm's modifications to its portion of user tree root

**Coordinator Level:**
- Receives aggregated proofs from all realms
- Generates final ZK proof for level 0 user tree root modifications
- Maintains global state consistency

## Additional Services

### Prover Proxy

The prover proxy assists users with local proof generation:

**Current Role:**
- Helps optimize proof generation for resource-constrained users
- Provides computational assistance for complex proofs
- Bridges the gap between user devices and proof requirements

**Future Considerations:**
- May become optional as ZK systems optimize and hardware improves
- Designed to scale down as local proving capabilities increase

### Watcher Service

The watcher service retrieves and processes blockchain data:

**Responsibilities:**
- Index and retrieve blockchain data
- Process transaction and state data from the chain
- Send processed data to API services
- Monitor and extract relevant blockchain events

### API Services

API services provide data interfaces for external applications:

**Responsibilities:**
- Receive processed data from watcher service
- Provide HTTP/JSON-RPC endpoints for block explorers
- Serve blockchain data to upper-layer applications
- Handle queries for transaction history, block data, and state information

## Storage Backend

### Supported Storage Systems

**Current Support:**
- **ScyllaDB**: High-performance distributed database
- **LMDBX**: Memory-mapped key-value store
- **TiKV**: Distributed transactional key-value database

**Primary Choice:**
- **ScyllaDB** is the preferred storage backend due to its exceptional write performance
- Optimized for the high-throughput requirements of blockchain state updates

### Storage Architecture

**Data Distribution:**
- Coordinator nodes store global state trees and contract metadata
- Realm nodes store user-specific data and transaction history
- Prover proxy may cache frequently accessed proving data

## Network Topology

```
┌─────────────────┐
│   Coordinator   │ ← Global state, contracts, user registration
│  (Multi-node)   │
└─────────┬───────┘
          │
    ┌─────┴─────┐
    │           │
┌───▼───┐   ┌───▼───┐
│Realm 1│   │Realm N│ ← User transactions, local state
│       │   │       │
└───────┘   └───────┘

Each node contains:
┌─────────┐   ┌─────────────┐
│  Edge   │◄─►│ Processor   │
│         │   │             │
└─────────┘   └─────────────┘
     │               │
     │         ┌─────▼─────┐
     │         │  Workers  │
     │         │ (Provers) │
     └─────────┤           │
               └───────────┘
```

This architecture enables horizontal scaling while maintaining security through zero-knowledge proofs and efficient state management through hierarchical trees.