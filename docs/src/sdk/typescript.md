# TypeScript SDK

The Psy TypeScript SDK provides JavaScript/TypeScript interfaces for interacting with contracts and the Psy network from web applications and Node.js environments.

## Installation

Follow the [Node Installation](../node/installation.md) guide to install the required components and build the TypeScript SDK.

### Setup Contract SDK

Generate TypeScript bindings for your contracts:

1. Place your `contract.abi.json` in `psy_sdk/psy-ts-sdk/packages/contract-sdk/abi/`
2. Run the generator:

```bash
cd psy_sdk/psy-ts-sdk/packages/contract-sdk
pnpm install
pnpm generate
```

The generator creates TypeScript bindings based on your contract ABI, which are then used to create typed contract instances.

## Core Components

### RpcProvider

The `RpcProvider` handles network communication with Psy nodes:

```typescript
import { RpcProvider } from "@psy/psy-sdk/rpc-provider/provider.js";

// Initialize provider
const rpcProvider = new RpcProvider(
  coordinator_configs,
  realm_configs,
  users_per_realm
);

// Singleton pattern
let rpcProvider: null | RpcProvider = null;

export function getRpcProvider() {
  if (!rpcProvider) {
    rpcProvider = new RpcProvider(
      rpcConfig.coordinator_configs,
      rpcConfig.realm_configs,
      rpcConfig.users_per_realm
    );
  }
  return rpcProvider;
}
```

### Configuration

Create configuration for network endpoints:

```typescript
const rpcConfig = {
  coordinator_configs: [
    { id: 0, rpc_url: ["http://127.0.0.1:8545"] }
  ],
  realm_configs: [
    { id: 0, rpc_url: ["http://127.0.0.1:8546"] },
    { id: 1, rpc_url: ["http://127.0.0.1:8547"] }
  ],
  users_per_realm: 1000000
};
```

### Memory Wallet Provider

Create a provider for on-chain data and transactions:

```typescript
import { createMemoryWalletProvider } from "@psy/psy-sdk";

const walletProvider = createMemoryWalletProvider(privateKey);
```

## Contract Interaction

### Basic Usage

```typescript
import { getRpcProvider } from "./rpcProvider";
// Import generated contract class based on your ABI
import { YourContractSDK } from "./generated/contract-bindings";

// Initialize contract with generated bindings
const contract = new YourContractSDK({
  rpcProvider: getRpcProvider(),
  walletProvider,
  contractId,
  checkpointId,
  userId
});

// Call contract method (typed based on ABI)
const result = await contract.methodName(param1, param2);
```

### Contract Object Management

The contract object automatically handles:
- `checkpointId` association
- `userId` mapping
- `contractId` tracking

## User Operations

### User Registration

```typescript
import { 
  PsyUserWalletProvider,
  SignType,
  createMemoryWalletProvider 
} from "@psy/psy-sdk";

// Create wallet provider
const provider = new PsyUserWalletProvider(networkConfig);

// Register user with private key
async function registerUser(privateKeyHex: string, signType: SignType) {
  try {
    await provider.signerProvider.registerUser(privateKeyHex, signType);
    console.log("User registered successfully");
  } catch (error) {
    console.error("Error registering user:", error);
  }
}

// Get user ID from public key
async function getUserId(publicKeyHex: string): Promise<number> {
  const userId = await provider.coordinatorEdgeRpcProvider.getUserId(publicKeyHex);
  return userId;
}
```

### Wallet Management

```typescript
import { 
  PsyUserWallet,
  PsyUserWalletProvider,
  SignType 
} from "@psy/psy-sdk";

// Create wallet from private key
async function createWallet(
  provider: PsyUserWalletProvider,
  privateKeyHex: string,
  signType: SignType
) {
  // Import private key and get signer
  const signer = await provider.signerProvider.importPrivateKey!(
    privateKeyHex,
    signType,
    ""
  );

  // Get public key
  const publicKeyHex = await signer.getPublicKeyHex();
  
  // Get user ID
  const userId = await provider.coordinatorEdgeRpcProvider.getUserId(publicKeyHex);
  
  // Create wallet instance
  const wallet = new PsyUserWallet(
    provider.networkId,
    signer,
    provider.coordinatorEdgeRpcProvider,
    provider.realmEdgeRpcProvider.getRpcProviderByUserId(userId),
    userId,
    publicKeyHex,
    true
  );

  return wallet;
}
```

### Data Fetching Operations

```typescript
import { 
  Felt, 
  PsyUserWalletProvider,
  IRealmEdgeRpcProvider 
} from "@psy/psy-sdk";

// Fetch latest checkpoint/block number
async function fetchBlockNumber(
  walletProvider: PsyUserWalletProvider
): Promise<number> {
  const checkpointResponse = 
    await walletProvider.coordinatorEdgeRpcProvider.getLatestCheckpoint();
  
  return checkpointResponse ? Number(checkpointResponse.checkpoint_id) : 0;
}

// Fetch user balance from contract state
async function fetchUserBalance(
  walletProvider: PsyUserWalletProvider,
  checkpointId: Felt,
  userId: Felt,
  userContractId: Felt
): Promise<number> {
  const merkleProof = await walletProvider.realmEdgeRpcProvider
    .getRpcProviderByUserId(userId)
    .getUserContractStateTreeMerkleProof(
      checkpointId,
      userId,
      userContractId,
      32,
      0
    );

  if (merkleProof && merkleProof.value.length === 64) {
    return parseInt(merkleProof.value.substring(48, 64), 16);
  }
  
  return 0;
}

// Get user ID from public key
async function fetchUserId(
  walletProvider: PsyUserWalletProvider,
  publicKeyHex: string
): Promise<number> {
  return await walletProvider.coordinatorEdgeRpcProvider.getUserId(publicKeyHex);
}
```

### Transaction Operations

```typescript
import { ContractCallArgs, Felt, PsyJSON } from "@psy/psy-sdk";

// Execute contract call using wallet
async function execContractCall(
  wallet: PsyUserWallet,
  address: string,
  args: ContractCallArgs | ContractCallArgs[]
) {
  try {
    const result = await wallet.execContractCall(address, args);
    return result;
  } catch (error) {
    console.error("Contract call failed:", error);
    throw error;
  }
}

// Transfer tokens example
async function transferTokens(
  wallet: PsyUserWallet,
  walletAddress: string,
  recipient: Felt,
  amount: Felt
) {
  const contractCallArgs: ContractCallArgs = {
    contract_id: "token-contract-id",
    method_name: "transfer",
    inputs: [recipient, amount]
  };
  
  return await execContractCall(wallet, walletAddress, contractCallArgs);
}

// Claim rewards from another user
async function claimTokens(
  wallet: PsyUserWallet,
  walletAddress: string,
  senderUserId: Felt
) {
  const contractCallArgs: ContractCallArgs = {
    contract_id: "token-contract-id",
    method_name: "simple_claim",
    inputs: [senderUserId]
  };
  
  return await execContractCall(wallet, walletAddress, contractCallArgs);
}
```

## Examples

### Complete Application Setup

```typescript
import { 
  PsyUserWalletProvider,
  SignType,
  createMemoryWalletProvider 
} from "@psy/psy-sdk";

// 1. Setup configuration
const networkConfig = {
  coordinator_configs: [
    { id: 0, rpc_url: ["http://127.0.0.1:8545"] }
  ],
  realm_configs: [
    { id: 0, rpc_url: ["http://127.0.0.1:8546"] }
  ],
  users_per_realm: 1000000
};

// 2. Initialize wallet provider
const provider = new PsyUserWalletProvider(networkConfig);

// 3. Register and create wallet
const privateKey = "your-private-key";
await provider.signerProvider.registerUser(privateKey, SignType.SECP256K1);

const wallet = await createWallet(provider, privateKey, SignType.SECP256K1);

// 4. Get user info
const userInfo = await wallet.getUserInfo();
console.log("User info:", userInfo);

// 5. Execute transactions
await transferTokens(wallet, recipientId, amount);
```

## Demo Examples

Run the provided demo examples:

```bash
cd psy_sdk/psy-ts-sdk/packages/contract-sdk/demo

pnpm install
pnpm example:basic
```

## Important Notes

1. Ensure `config.json` is correctly configured with network details
2. The contract object handles `checkpointId`, `userId`, and `contractId` association automatically
3. Use `createMemoryWalletProvider` for wallet operations
4. Generated contract bindings provide type-safe interfaces for your contracts