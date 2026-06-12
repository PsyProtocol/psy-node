# Client Prover Dev Scripts

Scripts for running client operations against a local PSY devnet.

## Two-Terminal Workflow

### Terminal 1: Start the local network

From the repo root:
```bash
# Start everything: DB + coordinator + 4 realms + workers
make run-all

# Or step by step:
bun run dev/locSetupV4.ts --proving-backend plonky2-poseidon-goldilocks \
    --db-only --coordinator-only --realm-only \
    --start-realm-id 0 --end-realm-id 3 \
    --workers-only --coordinator-workers 1 --realm-workers 4
```

### Terminal 2: Run client operations

From the repo root:
```bash
# Full UPS end-to-end example (register -> deploy -> mint -> transfer -> claim)
./client_prover/dev/ups_e2e.sh

# Or step by step:
./client_prover/dev/register_and_deploy.sh   # Register users + deploy contract
# (wait for checkpoint processing)
./client_prover/dev/run_transactions.sh      # Mint + transfer + claim
```

Or using the client_prover Makefile:
```bash
cd client_prover
make build
make register-user      # Register 4 test users
make deploy-contract    # Deploy token contract
make mint               # Mint tokens for users
make transfer           # Transfer between users
make claim              # Claim pending transfers
```

## Scripts

| Script | Description |
|--------|-------------|
| `register_and_deploy.sh` | Register 3 test users and deploy a token contract |
| `run_transactions.sh` | Mint, transfer, and claim tokens |
| `ups_e2e.sh` | Full UPS end-to-end: register -> deploy -> mint -> transfer -> claim |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGN_TYPE` | `zk` | Signature type (`zk` or `secp256k1`) |
| `WAIT_CHECKPOINT` | `12` | Seconds to wait between operations for checkpoint processing |

## Test User Keys

These are insecure keys for local devnet testing only:

| User | Private Key |
|------|------------|
| USER0 | `c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359` |
| USER1 | `f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d` |
| USER2 | `73ae514d6f69510ad778a05128d980951d9d8c097beb022471b2f50f19c41268` |
