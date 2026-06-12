# Psy V3

## Dependencies
- docker
- modern rust version
- bun


### Spinning up a local development cluster
```bash
# Start full system with default settings (realms 0-3, 1 coordinator worker)
bun run dev/locSetupV4.ts

# Start with realm workers and multiple edge nodes
bun run dev/locSetupV4.ts --realm-workers 32 --realm-edge-nodes 8

# Specify a realm range
bun run dev/locSetupV4.ts --start-realm-id 0 --end-realm-id 7 --realm-workers 8 --realm-edge-nodes 4

# Use JTMB proving backend (dev only)
bun run dev/locSetupV4.ts --jtmb --realm-workers 32 --realm-edge-nodes 8

# Use a specific proving backend
bun run dev/locSetupV4.ts --proving-backend jtmb-sha256-u64

# Use custom genesis data
bun run dev/locSetupV4.ts --genesis-data-path ./my-genesis.json

# Start components separately (useful for distributed setups)
bun run dev/locSetupV4.ts --db-only
bun run dev/locSetupV4.ts --coordinator-only
bun run dev/locSetupV4.ts --realm-only --start-realm-id 0 --end-realm-id 3
bun run dev/locSetupV4.ts --workers-only --coordinator-workers 3 --realm-workers 2
```

Run `bun run dev/locSetupV4.ts --help` for full usage details.

You will find the logs for the workers/edges/processors in the `./logs` directory.

To run some example transactions first run:
```bash
cargo run --release --package psy_node_cli --example register_users_deploy_contracts
```
This registers 1000 users and deploys 100 contracts.
Repeat this command for however many users you need. 




