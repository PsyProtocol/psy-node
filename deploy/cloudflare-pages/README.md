# Cloudflare Pages Frontend Deploy

Cloudflare Pages should deploy the staging frontends through GitHub integration.
This lets Cloudflare build from the private GitHub repository automatically on
pushes and pull requests. Direct Upload remains available as a manual fallback.

Important: a Pages project created with Git integration cannot later be switched
to Direct Upload. If manual uploads are needed later, create a separate Direct
Upload project.

## GitHub Integration Setup

Create one Pages project per deployed frontend:

| Pages project | Root directory | Build command | Build output directory |
| --- | --- | --- | --- |
| `psy-privacy-bridge-demo-stg` | `psy-dapp/apps/bridge` | `pnpm run build` | `dist` |
| `psy-explorer-stg` | `psy-dapp/apps/explorer` | `pnpm run build` | `dist` |
| `psy-ide-stg` | `psy-dapp/apps/ide` | `pnpm run build` | `dist` |
| `psy-config-stg` | generated locally from `deploy/gcp/config.env` | none | `dist/staging-config` |

Dashboard flow:

1. Open Cloudflare Dashboard -> Workers & Pages.
2. Create application -> Pages -> Import from an existing Git repository.
3. Authorize the Cloudflare Workers & Pages GitHub App for the private repo.
4. Select the repository and configure the project using the table above.
5. Set the production branch, for example `main` or `staging`.
6. Save and deploy.

For monorepo builds, install dependencies from the `psy-dapp` pnpm workspace
root, then run the selected app's build script. The deployment scripts in this
directory already implement that workspace-aware behavior.
If `psy-privacy-bridge-demo` is imported from its standalone repository, leave
Root directory empty or set it to `.`.

## Build Environment Variables

Vite reads `VITE_*` values at build time, so configure them in each Pages project
under Settings -> Environment variables. Use different values for Production and
Preview if needed.

`psy-privacy-bridge-demo-stg` is the staging app. Its custom domain is
`https://app-stg.psy-protocol.xyz/`. The legacy `psy-bridge-stg` and
`psy-privacy-stg` Pages projects are retired and are no longer deployed by the
fresh-staging scripts.

The app needs both L1 contract addresses and Parth RPC entrypoints:

```sh
VITE_PSY_RPC_MODE="remote"
VITE_DEFAULT_CHAIN_ID="31337"
VITE_L1_RPC_URL="https://rpc-stg.psy-protocol.xyz"
VITE_L1_EXPLORER_URL="https://rpc-stg.psy-protocol.xyz"
VITE_L1_ADDRESSES_PROVIDER_ADDRESS="0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
VITE_L1_ROUTER_ADDRESS="0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE"
VITE_L1_BRIDGE_ADDRESS="0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"
VITE_L1_STATE_MANAGER_ADDRESS="0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
VITE_L1_ERC20_GATEWAY_ADDRESS="0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e"
VITE_L1_ETH_GATEWAY_ADDRESS="0x9A676e781A523b5d0C0e43731313A708CB607508"
VITE_L1_WETH_ADDRESS="0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0"
VITE_PSY_TOKEN_ADDRESS="0x0B306BF915C4d645ff596e518fAf3F9669b97016"
VITE_PSY_COORDINATOR_URL="https://coordinator-stg.psy-protocol.xyz"
VITE_PSY_REALM_URLS="https://realm0-stg.psy-protocol.xyz"
VITE_PSY_PROVE_PROXY_URL="https://prove-stg.psy-protocol.xyz"
VITE_PSY_SERVICES_URL="https://services-stg.psy-protocol.xyz"
VITE_PSY_INDEXER_API_URL="https://services-stg.psy-protocol.xyz"
```

`psy-privacy-bridge-demo-stg` also serves the browser wallet download route at
`/wallet`. The Direct Upload script packages `psy-wallet`, copies the generated
zip into the app's static assets, and injects these build-time values:

```sh
VITE_WALLET_VERSION="0.4.16"
VITE_WALLET_MODE="staging"
VITE_WALLET_CHROME_URL="/downloads/psy-wallet-staging-v0.4.16.zip"
VITE_WALLET_SHA256="<generated-by-script>"
VITE_COORDINATOR_URL="https://coordinator-stg.psy-protocol.xyz"
VITE_NOSTR_RELAY_URL="wss://nostr-stg.psy-protocol.xyz/"
VITE_PROVE_PROXY_URL="https://prove-stg.psy-protocol.xyz"
```

`psy-explorer-stg` reads public Vite env vars at build time:

```sh
VITE_API_BASE_URL="https://services-stg.psy-protocol.xyz"
VITE_API_RPC_COORDINATORS="https://coordinator-stg.psy-protocol.xyz"
VITE_API_RPC_REALMS="https://realm0-stg.psy-protocol.xyz"
```

Important for `psy-privacy-bridge-demo-stg`: the demo vendors the built
`@psy/psy-sdk` package as `vendor/psy-sdk/psy-psy-sdk-1.1.5.tgz` and references
it with a `file:` dependency. This keeps Cloudflare's build self-contained.
The public `PsyProtocol/psy-sdk` repository can be used as the source for this
tarball, but direct source builds on Cloudflare are not recommended until the
SDK publishes a ready-to-install package, because the SDK package lives under a
subdirectory and its ignored WASM/dist artifacts must be generated first.

Current staging backends are fronted by Caddy on `gcp-nostr`, but the Pages apps
will only be usable after DNS points at that VM and public `80/443` are open for
these browser-facing HTTPS endpoints:

- `VITE_PSY_SERVICES_URL`: public URL for psy-services.
- `VITE_INDEXER_URL`: public URL for the indexer GraphQL endpoint if the bridge
  UI reads it directly.
- `VITE_PSY_NODE_URL`: public URL for coordinator edge.
- `VITE_L1_RPC_URL`: browser-reachable RPC endpoint for the staging L1 chain.

Do not point Pages builds at `127.0.0.1` or internal `10.x` addresses. Those are
resolved from the browser user's machine, not from the GCP VPC.

## Branch And Preview Behavior

Use Cloudflare branch controls to avoid deploying every branch if that is too
noisy:

- Production branch: `main`, `staging`, or the branch you want as the canonical
  staging frontend.
- Preview branches: enable for pull requests or restrict to selected branches.
- Skip one deployment by adding a Cloudflare-supported skip marker in the commit
  message, such as `[CF-Pages-Skip]`.

## Manual Fallback

The Direct Upload helpers can still deploy prebuilt artifacts to Direct Upload
projects. Deploy the staging app:

```sh
bash deploy/cloudflare-pages/deploy-privacy-bridge-demo.sh
```

Deploy the standalone Psy explorer repository:

```sh
bash deploy/cloudflare-pages/deploy-psy-explorer.sh
```

Deploy the public staging config page:

```sh
bash deploy/cloudflare-pages/deploy-staging-config.sh
```

Required local environment variables for Direct Upload:

```sh
export CLOUDFLARE_ACCOUNT_ID="..."
export CLOUDFLARE_API_TOKEN="..."
```

The API token needs Cloudflare Pages edit permission for the account.
Use `CF_PAGES_PROJECT` to override a project name, `CF_PAGES_BRANCH` to override
the deployment branch label, or `CF_PAGES_SKIP_DEPLOY=1` to build without
uploading.
