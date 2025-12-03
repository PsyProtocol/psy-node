# Psy V3

## Running

### 1. Database/Queue/Cache
First, in one terminal run the command:
```bash
./dev/start_db.sh
```

This starts nats, scylla and valkey (aka. redis).
You can delete the nats, scylla and valkey instances at any time by using CTRL+C to exit the script, and the nats/scylla/valkey stores will gracefully exit and clear any data (docker --rm). This is useful for testing



### 2. Coordinator Processor
Then, in another terminal tab, run the command below to start the coordinator processor
```bash
./dev/d.sh p -g
```

The -g flag means the coordinator will start from genesis and delete the local_checkpoints backups in ./local/checkpoints_0_0 for the coordinator.


If you don't want to delete the backups, you can run:
```bash
./dev/d.sh p -b
```
to just rebuild the latest processor and start it leaving off from the most recent checkpoint.

### 3. Coordinator Edge
Once the coordinator processor is started, you can start the coordinator edge by running:
```bash
./dev/d.sh edge -b
```


### 4. Coordinator Worker
To allow the coordinator to start working, we need to start a proof miner.
It is possible to run a miner which does jobs for both realms and coordinators, but for debugging it is recommended to run a worker which talks just to the coordinator and a worker which just talks to the realms as they have different circuits.

To run the coordinator worker run the command:
```bash
./dev/d.sh worker -b
```

Great! Now the coordinator is all setup, let's setup our first realm.


### 5. Realm Processor
To start the realm processor, run:
```bash
./dev/d.sh rp -g
```

Similar to the coordinator, the realm has a genesis flag -g and also a just build flag -b.

### 6. Realm Edge
To start the realm edge, run:
```bash
./dev/d.sh re -b
```

### 7. Realm Worker
To start a realm worker, run the command:
```bash
./dev/d.sh realm_worker -b
```



## Testing
To test registering some users, run:
```bash
cargo run --release --package psy_node_cli --example register_user
```


To test deploy contracts, run:
```bash
cargo run --release --package psy_node_cli --example deploy_contracts
```

Once you have registered some users and deployed some contracts, you can prove some dummy end caps with the dummy end cap prover.
To test the dummy end cap prover, run:
```bash
./dev/d.sh dummy_prover
```