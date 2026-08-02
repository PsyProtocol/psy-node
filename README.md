# Psy V3

## Dependencies
- docker
- modern rust version
- bun


### Spinning up a local development cluster
```bash
cargo build --release
bun run ./dev/locSetupV3.ts --realm-workers 32 --realm-edges 8
# or for JTMB (dev only) mode
bun run ./dev/locSetupV3.ts --jtmb --realm-workers 32 --realm-edges 8
```

You now have realm edges listening on ports 13370 -> realm_edges + 13370
You will find the logs for the workers/edges/processors in the ./logs directory

To run some example transactions first run:
```bash
cargo run --release --package psy_node_cli --example register_users_deploy_contracts
```
This registers 1000 users and deploys 100 contracts.
Repeat this command for however many users you need.


Then, if you want to submit some end caps run:
```bash
./dev/dummy.sh --realm-edge-nodes 8 --groups 8 --group-size 200 --max-contract-calls 10
```

This will start up 12 end cap provers each of which submits 200 user proofs at a time (8*200 = 1600 users), each of which call on average 5 txs = 8000 txs.



### FAQ

Q:
I got an invalid user leaf hash message in the dummy prover, what is wrong?

A:
Right now, validate every user leaf's user contract tree against the canonical value in the database, which does not get set until the block containing your new leaf is committed to the database, which can sometimes take a few seconds depending on how the coordinator/realm cycle is synchronized and how long it takes the realm to prove to their block. Since we already also check if a user contract tree root is correct for a user in the gatherer and gracefully discard the submission if the user leaf containing the root doesn't match the canonical value in the in-memory global user tree, in the future we might want to store the last submitted user leaf in redis along with the submitted gathering unique pending id. If the current proving (standard unique pending id) is the same as the gathering one, we may allow the user to submit an end cap which starts from the root they last submitted at, and which would be discarded if the block that gathered the tx is reverted. If we do not store the latest submitted user state root in redis, during the time between when the unique pending id is changed to the previous gathering unique pending id and when the state is committed, it is of course possible for the user to submit an end-cap which proves from the state root which is currently in the database but will be soon overwritten. This is an OK behavior for now, as the GUTA gatherer just discards it, but again the redis thing would be nice.




### Performance
Right now the endcap/request proof/submit proof API endpoints take ~3-5ms per request on my Macbook. 
These are the PERFORMANCE CRITICAL endpoints, and the perf can be significantly improved by a few things, most notably caching the nats connection/queue consumer for the latest unique pending id. For now I have not done that because I need to first phase out the QProcCheckpointId from all of the codebase. In the future, the logic will be that we have an RWLock'd <(u64, Consumer)> for each topic which gets updated when it encounters a queue key with the corresponding topic and a unique pending id greater than the current value (again soon there will be no more random u128, just the unique pending id, so it is sequential). As of recent performance testing, the time to ensure_consumer/etc is a whopping 2ms -- nearly half of the entire API call processing time on the server, which can be reduced in this fashion to something like ~90µs. This will also significantly improve the performance of the gatherers, which constantly try to consume from the queue. Their is an unavoidable task of verifying plonky2 proofs which takes ~2ms for a single hardware thread. This is CPU bound, so for getting around this issue we will just need to spin up more edges per realm to compensate. The eventual goal is for each realm to be able to handle ~100k UOPS with ~150 edge api node instances (think 1 edge API = 2 vCPU). This way, if we had 1000 realms, we could handle 100,000,000 UOPS (think over 1 billion TPS), able to support the full payment load of the internet. 




