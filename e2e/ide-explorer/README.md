# IDE + Explorer specialized E2E

Playwright suite for the local Psy IDE (`:5176`) and blockchain explorer (`:5178`).

| App | Coverage |
|---|---|
| **IDE** | Landing → Studio/Dashboard routing, default template projects, WASM runtime ready, compile success |
| **IDE deploy** | **On-chain** `compile-and-deploy` (VotingContract) via `psy_user_cli`, services/indexer resolution, explorer detail, real wallet connect to IDE |
| **Explorer** | Home metrics/ticker, blocks/txs/contracts list→detail, charts + status health, nav + `/transactions` alias, checkpoint search |

## Prerequisites

A running local stack that serves:

```bash
# typically from repo root
PSY_SKIP_BRANCH_CHECK=1 PSY_SKIP_KEYSTORE=1 make run-all
# keeps these up:
#   IDE        http://127.0.0.1:5176
#   Explorer   http://127.0.0.1:5178
#   services   http://127.0.0.1:3000
#   coordinator/realms/indexer
```

For **IDE-05 on-chain deploy** additionally:

```bash
# built wallet extension (sibling repo)
ls ../psy-wallet/dist/manifest.json
# or: cd ../psy-wallet && npx vite build --mode dev

# user CLI for register + simple_mint gas
cargo build --release -p psy_user_cli
```

Override URLs/paths if needed:

```bash
export IDE_URL=http://127.0.0.1:5176
export EXPLORER_URL=http://127.0.0.1:5178
export SERVICES_URL=http://127.0.0.1:3000
export PSY_WALLET_DIST=/abs/path/to/psy-wallet/dist
```

## Run

```bash
cd e2e/ide-explorer
npm install
npx playwright test                      # all (IDE UI + deploy + explorer)
npx playwright test --project=ide
npx playwright test --project=ide-deploy # on-chain deploy only (~minutes)
npx playwright test --project=explorer
```

## Notes

- IDE UI tests clear `localStorage` each case so default template projects are deterministic.
- IDE-05 on-chain deploy uses `psy_user_cli compile-and-deploy` with `fixtures/VotingContract.psy.rs` (standalone psy-compiler syntax: `#[contract]` + `#[derive(Storage)]`, free-standing `#[contract::write_method]` functions, `ContractRef`/`ContractMetadata` storage access). Studio Deploy is gated on runtime-generated circuit definitions that the browser compile path does not materialize; the CLI path is the load-bearing on-chain proof.
- IDE-05 also loads the real Psy Wallet extension, imports anvil#0, and connects to Studio (approve popup).
- Explorer accepts either `Staging` or `Degraded` health pills as long as list/detail pages render real chain content.
