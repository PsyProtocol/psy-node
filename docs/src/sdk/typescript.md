# TypeScript SDK

> Updated: 2026-09-04.

## Abstract

The TypeScript workspace contains `@psy-protocol/psy-sdk` for remote procedure call clients, wallets, local web proving, and local web compilation, plus `@psy-protocol/contract-sdk` for generated contract bindings. The examples below use interfaces verified in the current SDK checkout; values that depend on a deployment remain placeholders.

## Table of Contents

- [1. Packages and Installation](#1-packages-and-installation)
- [2. Network Configuration](#2-network-configuration)
- [3. Wallet Provider](#3-wallet-provider)
- [4. User Registration](#4-user-registration)
- [5. Contract Calls](#5-contract-calls)
- [6. Contract Binding Generation](#6-contract-binding-generation)
- [7. Demo](#7-demo)
- [8. Verification Boundary](#8-verification-boundary)

## 1. Packages and Installation

The workspace package names are:

```text
@psy-protocol/psy-sdk
@psy-protocol/contract-sdk
```

For repository development, install dependencies from the TypeScript workspace:

```bash
cd <workspace>/psy-sdk/psy-ts-sdk
pnpm install
```

Applications import the public package root:

```typescript
import {
  ContractCallArgs,
  PsyUserWallet,
  SignType,
  createMemoryWalletProvider,
} from "@psy-protocol/psy-sdk";
```

## 2. Network Configuration

`createMemoryWalletProvider` accepts a complete `PsyNetworkConfig`. Supply every required field from the target deployment configuration:

```typescript
import type { PsyNetworkConfig } from "@psy-protocol/psy-sdk";

const networkConfig: PsyNetworkConfig = {
  magic: "<network-magic>",
  users_per_realm: 1_000_000,
  global_user_tree_height: 32,
  realm_user_tree_height: 20,
  group_realm_height: 1,
  coordinator_configs: [
    { id: 0, rpc_url: ["http://127.0.0.1:8545"] },
  ],
  realm_configs: [
    { id: 0, rpc_url: ["http://127.0.0.1:8546"] },
  ],
  prove_proxy_url: ["http://127.0.0.1:9999"],
  native_currency: "<symbol>",
  native_currency_decimal: 18,
  native_currency_name: "<name>",
  fees: {
    register_user_fee: 0,
    deploy_contract_fee: 0,
    guta_fee: 5_000_000_000,
  },
};
```

The constants in this configuration are illustrative. Use the values supplied by the target deployment.

## 3. Wallet Provider

Create the in-memory provider asynchronously:

```typescript
const provider = await createMemoryWalletProvider(networkConfig);
```

The provider constructs coordinator and realm clients, a web prover, and an in-memory signer provider. The current implementation fixes its network identifier to `regtest`.

The `RpcProvider` class remains available for direct coordinator and realm routing:

```typescript
import { RpcProvider } from "@psy-protocol/psy-sdk";

const rpcProvider = new RpcProvider(
  networkConfig.coordinator_configs,
  networkConfig.realm_configs,
  networkConfig.users_per_realm,
);
```

## 4. User Registration

Register a private key through the signer provider, then wait for the Coordinator to expose its user identifier before constructing a wallet:

```typescript
const privateKey = "<private-key>";
const signType = SignType.SECP256K1Sign;

const publicKey = await provider.signerProvider.registerUser(
  privateKey,
  signType,
);

const userId = await provider.coordinatorEdgeRpcProvider.getUserId(publicKey);
const signer = await provider.signerProvider.importPrivateKey!(
  privateKey,
  signType,
  "<zk-fingerprint-when-required>",
);
const realm = provider.realmEdgeRpcProvider.getRpcProviderByUserId(userId);
const wallet = new PsyUserWallet(
  provider.networkId,
  signer,
  provider.coordinatorEdgeRpcProvider,
  realm,
  userId,
  publicKey,
  true,
);
```

Registration is asynchronous at the network level. A production caller must poll the Coordinator or react to deployment-specific confirmation before assuming `getUserId` will succeed.

## 5. Contract Calls

`PsyUserWallet.execContractCall` takes the wallet public-key hash followed by one `ContractCallArgs` value or an array of values:

```typescript
async function transferTokens(
  wallet: PsyUserWallet,
  recipientUserId: bigint,
  amount: bigint,
): Promise<string> {
  const call: ContractCallArgs = {
    contract_id: 0n,
    method_name: "simple_transfer",
    inputs: [recipientUserId, amount],
  };

  return wallet.execContractCall(wallet.publicKeyHex, call);
}
```

A claim uses the same verified call path and the `simple_claim` token method:

```typescript
async function claimTokens(
  wallet: PsyUserWallet,
  senderUserId: bigint,
): Promise<string> {
  const call: ContractCallArgs = {
    contract_id: 0n,
    method_name: "simple_claim",
    inputs: [senderUserId],
  };

  return wallet.execContractCall(wallet.publicKeyHex, call);
}
```

The `claimTokens` function is an application helper, not an exported SDK method.

## 6. Contract Binding Generation

Place the contract Application Binary Interface file at the generator input path, then run the package script:

```bash
cd <workspace>/psy-sdk/psy-ts-sdk/packages/contract-sdk
cp <workspace>/application/contract.abi.json ./abi/contract.abi.json
pnpm generate
pnpm build
```

`pnpm generate` invokes the generator with `./abi/contract.abi.json` and writes generated bindings under `./generated`.

## 7. Demo

Run the checked-in basic demo from its package:

```bash
cd <workspace>/psy-sdk/psy-ts-sdk/packages/contract-sdk/demo
pnpm install
pnpm example:basic
```

The demo requires reachable network endpoints and deployment-specific configuration.

## 8. Verification Boundary

Verified against the SDK checkout:

1. Package imports use the `@psy-protocol` scope, not `@psy/psy-sdk`.
2. `createMemoryWalletProvider` takes a complete `PsyNetworkConfig` and returns a promise.
3. `PsyUserWalletProvider` is constructed internally from a network identifier, coordinator provider, realm provider, signer provider, and prover; it does not accept a single network configuration argument.
4. `PsyUserWallet.execContractCall` requires the public-key hash as its first argument.
5. `simple_transfer` and `simple_claim` exist in the checked-in token contract Application Binary Interface.
6. The contract generator and basic demo scripts exist at the documented paths.

The network constants and application helper functions in this guide are illustrative because their values and confirmation policy depend on the deployment.
