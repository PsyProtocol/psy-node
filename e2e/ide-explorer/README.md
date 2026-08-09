# IDE + Explorer E2E

Run against the mainnet-layout local stack from `psy-node`, with the IDE and Explorer served from the `psy-dapp` submodule and the wallet from sibling `../psy-wallet`.

Prerequisites:

- `make run-all` from the psy-node root
- `target/release/psy_user_cli`
- sibling `../psy-wallet/dist/manifest.json`, or `PSY_WALLET_DIST`
- IDE on `:5176`, Explorer on `:5178`, services on `:3000`

Run:

```bash
cd e2e/ide-explorer
npm install
npx playwright test
```

Override `IDE_URL`, `EXPLORER_URL`, `SERVICES_URL`, or `PSY_WALLET_DIST` as needed. Tests are serial because deploy and indexing checks mutate the shared local chain.
