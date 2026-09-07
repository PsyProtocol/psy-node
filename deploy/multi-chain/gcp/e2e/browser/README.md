# Multichain staging browser E2E

This read-only Playwright gate validates the deployed staging app against the
canonical three-chain runtime file. It does not connect a wallet or submit a
transaction.

The suite checks that:

- the published JavaScript contains Sepolia, BSC Testnet, and Base Sepolia;
- every chain uses its expected Bridge address and public RPC URL;
- authenticated/private upstream RPC URLs are absent from the browser bundle;
- browser-origin JSON-RPC requests pass CORS and return the expected chain ID;
- every configured Bridge address contains deployed bytecode.
- Base Sepolia, BSC Testnet, and Sepolia RPC checks are separate test cases;
- the published Explorer renders its live application shell.

The GitHub workflow checks out only the requested `deploy/multi-chain-gcp`
snapshot. It does not read or compose from `mainnet-beta`, has read-only
repository permissions, and never commits or pushes any branch. It publishes
only the bridge app and explorer; backend deployment remains manual.

The repository must define `PSY_DAPP_READ_TOKEN` with read-only access to the
private `PsyProtocol/psy-dapp` repository, plus `CLOUDFLARE_ACCOUNT_ID` and a
Cloudflare Pages-scoped `CLOUDFLARE_API_TOKEN`.

The canonical runner uses system Chromium when available and stores durable
evidence outside this ignored package directory:

```bash
deploy/e2e/staging/run-browser-e2e.sh
```

Override `APP_URL` or `MULTICHAIN_RUNTIME_FILE` to test another deployment.
