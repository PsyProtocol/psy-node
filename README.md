# QP Network Example

## Introduction
The QP Network is a simple example network that demonstrates the fundamentals of building a hierarchical topology for useful work.
While not built as a production ready secure network, the QP Network is built to be example of how to impelment a network which has the stablility and state consistency of a production network.

The QP Network stores users data in a verifiable merkle tree.
Users can register an account with a Realm and submit data which is gzipped by workers and the hash of the stored data, the user's public key, and the last modified checkpoint id (not guarenteed to be exact, but always moves forward in time) is hashed and stored as a leaf in a merkle tree of users.

After registering, users can update the data stored by the network by sending the new data they would like stored as well as a signature with their public key.

Each realm can stores a portion of the Global User Tree to help the network scale out. The network also has a coordinator node who stores the top part of the global user tree, linking all of the realm roots to the global user tree root.

This means for each checkpoint, we can prove what the user's data is with a merkle proof.

To demonstrate workers and how to dispatch remote jobs, workers on the network are used to compress the user data, but this would be a zero knowledge proof in the case of parth (again this is more of an example on how to build database+network topology+job manager that is resiliant).


The coordinator produces a checkpoint every 30 seconds, and dumps any realm updates received from a queue to built the state deltas for the block.
The coordinator then produces a miniature merkle tree containing the roots of the realms that submitted for each checkpoint (this is useless, but again here to demonstrate job manager).

Merkle Database Design:
This merkle database can be viewed as it was at any checkpoint id (You can grab merkle proofs and read data as it was in the past). This is accomplished by storing the node kys in a clever database key where we store:
Key = 17 Bytes = [level.to_be_bytes(), index.to_be_bytes(), checkpoint_id.to_be_bytes()]
and the value as the node value (Hash256). 

When we get a node from the database, we search for a key where:
level = query.level, index = query.index, checkpoint_id <= max_checkpoint_id

If the backing kv store supports less than or equal to queries which find the highest key such that the leq condition is preserved, we can simply perform the query, ensuring to decode the key and make sure the level and index match. If no key is found or the leq returns some other node in the tree's key, we say the the leaf is empty, and compute its value by computing the corresponding Zero Hash at the node's reverse level (reverse_level = distance from leaf level = TREE_HEIGHT-level):
ZeroHash(0) = 0x0000000000000000000000000000000000000000000000000000000000000000
ZeroHash(reverse_level) = hash(ZeroHash(reverse_level - 1), ZeroHash(reverse_level -1))


Hence, we only need to store nodes in the merkle tree whose values of been modified and can keep it sparse, while also maintaining full historical history.

We make sure that at any point, we could pull the power cord on any of the node servers, and the network would not be put in an irrecoverable state.


The architecture is the following:

The QP Network actors are **Workers**, **Realms**, and **Coordinators**:

### Workers
* Workers are nodes which request jobs from the Realms/Coordinators, complete them and then send over the result to the edge api that it requested the job from
* The jobs are CompressGzip data and build ComputeCombinedRealmRootUpdateMerkleRoot (builds a mini merkle tree from a bunch of leaves), these are just placeholder jobs for your own system



### Realms
Realms are actors responsible for maintaing a lower portion of the Global User Tree which reaches from level = QP_REALM_GUSER_TREE_HEIGHT (the realm root), to the user leaves at level = QP_GLOBAL_USER_TREE_HEIGHT.
Each Realm has one **Realm Processor Node** and many **Realm Edge API Nodes**.

**Realm Edge API Nodes** provide functions including:
* Collecting user registration requests and user data updates and pushing them to a queue so the processor can process them in the next checkpoint
* Allowing anyone to query the realm user tree and get merkle proofs/other user data
* Allow anyone to get the data of any user in the realm at any checkpoint height
* Allow workers to request job tasks 
* Allow workers to submit finished job work/data


A **Realm Processor Nodes** responsible for processing, submitting and finalizing checkpoint updates for a realm.
Each Realm's Realm Processor is responsible for:
* Keeping the Realm's state data in sync with the rest of the network/coordinator
* Injesting updates to the user tree and generating/planning jobs for the workers
* Using worker results to build a state delta in memory with all the items that need to be updated in the database once a checkpoint is finalized
* Only realm processor nodes can write to the core db for the realm

The Realm Processor Ensures that the Realm can never get in an irrecoverable state by:
1. Generating a full state delta in memory for each checkpoint without any writes to the store
2. Backing up the realm checkpoint state delta incase of crash before sending the new realm root to the coordinator
3. Submitting a new realm root to the coordinator to be included in a block, only after the state delta is 
4. Only committing/applying a state delta once it is already included by the coordinator in a finalized block

This covers all of the critical resiliance issues:
1. If the coordinator crashes while creating a checkpoint, the realm root will not be updated, so the delta will not be applied by the realms (ensuring the realms are not in an irrecoverable state). Only negative consequence is mempool cleared, which is expected behavior for a node crash and is 100000x better than any chance of network state irreconciliability. 
2. If the realm processor crashes while generating the state delta, nothing is written to disk, the mempool is cleared, no chance of being out of sync with the coordinator (nothing has been applied, and nothing has been sent to the coordinator, so the coordinator assumes no changes for the realm in the checkpoint)
3. If the realm processor crashes while jobs are being worked on by workers, nothing has been committed so mempool is cleared by the node has 0% chance of being out of being in an irecconciliable state with the coordinator.
4. If the realm processor crashes while waiting for the coordinator to finish building the checkpoint, this is also ok. Even though we have sent the new realm root to the coordinator, we don't know if the coordinator will include it or not (maybe the coordinator node also crashes), and even this is ok because we have our state delta backed up to disk, so when the realm processor node boots up again, we can check if the coordinator has a realm root that is different from our last finalized one. If it does, it means we crashed while waiting for the coordinator or while applying the state delta, and we need to fetch the delta backup from disk and apply it.
5. If the realm processor loses power while applying a state delta, no worries, we set the new finalized realm checkpoint id + root at the VERY END of apply the state delta, so the node will detect it is out of sync with the coordinator on startup (the node delta cannot even start to be applied until the coordinator has included our new realm root in a finalized block), and apply the entire state delta again in its entirety, ensuring any potentially corrupted/incomplete data is also thoroughly overwritten.


### Coordinator
The coordinator is the actor responsible for maintaing the top half of the merkle tree. The coordinator stores no user data directly, instead storing the merkle nodes from the realm roots to a global use tree root. 
This hierarchy of realms and a coordinator allows the network to scale horizontally. When you have more users, just add more realms and with each additional realm, the chain gains 2**20 user capacity but the performance impact of processing an additional realm root per block for the coordinator is almost nothing.
Much like realms, each coordinator has one **Coordinator Processor Node** and many **Coordinator Edge API Nodes**.

**Coordinator Edge API Nodes**
Much like a Realm Edge API Node, the **Coordinator Edge API Nodes** perform critical functions including:
* Allow realm processors to submit newly updated realm roots, putting them in a queue for the Coordinator Processor node to use in the next checkpoint.
* Allow anyone to get a merkle proof that links the global user tree to any realm root (leaves of the tree stored by coordinators are the merkle roots of each realm, ex. realm_id = 12's merkle root is at leaf index = 12 on level QP_COORDINATOR_GUSER_TREE_HEIGHT). Also supports full history, with proofs at any checkpoint height
* Allow querying of global network state info at any checkpoint height
* Allow people to query the mini merkle root (a toy work task for the coordinator to do in order to demonstrate how to use job manager), just the root of a merkle tree whose leaves are only the realm roots which updated in the current checkpoint, totaly useless, but important for make it easy to use this example repo as the base for other projects.
* Allow anyone to get the data of any user in the realm at any checkpoint height
* Allow workers to request job tasks 
* Allow workers to submit finished job work/data


**Coordinator Processor Nodes**
Coordinator processor nodes are responsible for finalizing checkpoints and updating the top half of the global user tree (from QP_COORDINATOR_GUSER_TREE_HEIGHT to 0, aka level=QP_COORDINATOR_GUSER_TREE_HEIGHT to the root level). The coordinator is also the single source of truth for what the state of the network is at a given checkpoint height. This is why it is so important to ensure the realms never fall out of sync with the realm roots stored by the coordinator. The coordinator produces blocks/checkpoints every 30 seconds regardless of if there are any updates in the realm root udpate queue. The coordinator also notifies the connected realms when a checkpoint is created.



## Connections, Databases and Networking:

### Realms
Each Realm has one **Realm Processor Node** and many **Realm Edge API Nodes**. 

The Realm Edge API Nodes communicate with the processor by pushing updates/registrations to a queue that the Realm Processor Node dumps into memory each checkpoint. 


#### DataStores/Databases
The most import data store for each Realm is its STORE_DB_REALM_CORE, the core database responsible for storing the finalized chain state. It is only writable by the Realm Processor, but it can be read by any Realm Edge API Node.


Description:
The core, append only store for the realm. Stores the user leaves, the compressed user data, the portion of the global user tree managed by the realm, a merkle proof which links the current root of the sub-tree within the global user tree managed by the realm and the unique checkpoint id for the realm.

Who can read from the store:
* All edge api nodes in the realm, 
* The realm processor node

Who can write to the store:
* Only the realm processor node

What data it stores:
- A checkpointed data store of users, key: user_id, value: QPUserDataRecord (which contains the user's public key, last submitted checkpoint id and data hash), supports historical queries with max_checkpoint_id 
    * {[user_id: u64] => QPUserDataRecord} , supports historical queries with max_checkpoint_id
- A checkpointed store of each user's data in gzipped form, key: user_id, value: Vec<u8>, supports historical queries with max_checkpoint_id 
    * {[user_id: u64] => Vec<u8>}, supports historical queries with max_checkpoint_id
- A checkpointed merkle tree whose leaves are the user leaf hashes within the realm (has a height of QP_REALM_GUSER_TREE_HEIGHT)
    * {[level: u8, index: u64] => Hash256}, supports historical queries with max_checkpoint_id
- A singleton UniqueCheckpointId (checkpoint_id: u64, uuid: u128) which is incremented each time a new checkpoint is finalized, uuid is random -- singleton for the realm, value is a UniqueCheckpointId
- A singleton MerkleProofCore which links the current realm root to the global user tree root. After a coordinator finalizes the block and the realm finishes waiting for the coordinator, this is fetched from the coordinator and stored in the database so users can query full merkle proofs from root to their user leaf
- A singleton u64 which is the number of worker jobs to be completed for the current checkpoint (set by the realm processor when it starts processing a new checkpoint, when workers call notify_job_completed
When it is cleared/deleted:
* The STORE_DB_REALM_CORE is NEVER cleared or deleted, it is an append-only store which supports historical queries with max_checkpoint_id
------------------------------------------------
### STORE_DB_REALM_EDGE_CACHE
Who can read from the store:
* All edge api nodes in the realm, 

Who can write to the store:
* Only the realm processor node

What data it stores:
- A mapping of user,unique checkpoint to a random number generated by the edge to prevent race condition issues with multiple submissions in rapid succession
    * {[unique_checkpoint_id: UniqueCheckpointId, user_id: u64] => u64}
- An atomic counter for a given checkpoint id for when workers submit completed jobs via the submit_compression_job_result api, which is atomically incremented each time a worker submits a completed job
    * {[unique_checkpoint_id: UniqueCheckpointId] => u64}
- A mapping of QPWorkerJobDataID to the actual user data to be compressed
    * {[job_data_id: QPWorkerJobDataID] => Vec<u8>}
When it is cleared/deleted:
- The realm operator can clear it from time to time to free up space (can be cleared only when all realm edge api nodes are offline)

The unique checkpoint does NOT neceesarily correspond to the correct checkpoint_id, but instead is a just a unique id that identifies the queue used by the edge apis to push items for the realm processor.
------------------------------------------------
### STORE_DB_TEMP_SUBMITTED_COMPRESSED_USER_DATA
Who can read from the store:
* The realm processor node (The realm processor reads from this to get the compressed user data to be added to the realm core store and deletes the data after it has been used to build the block delta)

Who can write to the store:
* Only the realm edge nodes

What data it stores:
- A mapping of QPWorkerJobDataID to the actual user data to be compressed
    * {[job_data_id: QPWorkerJobDataID] => Vec<u8>}
When it is cleared/deleted:
- The realm operator can clear it from time to time to free up space (can be cleared only when all realm edge api nodes are offline)

Who can write to the store:
* Only the realm processor node 

This store stores the compressed user data submitted by the workers.
------------------------------------------------



The coordinator has similiar data patterns to the Realm, see the code implementation for more details.



