# Rust SDK

> Updated: 2026-09-04.

## Abstract

The `psy_rust_sdk` crate provides programmatic access to Psy by re-exporting shared configuration, cryptography, request, provider, session, and wallet modules. The exact request payloads and data-type fields remain source-defined; examples below that omit constructors are explicitly illustrative.

## Table of Contents

- [1. Installation](#1-installation)
- [2. Re-exports](#2-re-exports)
- [3. Configuration](#3-configuration)
- [4. RpcProvider](#4-rpcprovider)
- [5. ProveProxyRpcProvider](#5-proveproxyrpcprovider)
- [6. Data Types](#6-data-types)
- [7. Verification Boundary](#7-verification-boundary)

## 1. Installation

Add the workspace crate to `Cargo.toml`:

```toml
[dependencies]
psy_rust_sdk = { path = "<workspace>/psy-sdk/psy-rust-sdk" }
```

The package name in the SDK repository is `psy_rust_sdk`. Cargo dependency keys can use that name directly.

## 2. Re-exports

On native targets, the crate re-exports these modules:

```rust
use psy_rust_sdk::{
    network_constants,
    provider,
    psy_common,
    psy_crypto,
    request,
    session,
    wallet,
};
```

The native provider, session, and wallet re-exports are excluded on `wasm32`; the crate exposes its `wasm` module for that target.

## 3. Configuration

`RpcProvider::new_with_config_path` loads the repository's network configuration format. Use the configuration supplied for the target deployment rather than deriving a partial configuration from this guide.

```rust
use psy_rust_sdk::provider::RpcProvider;

let rpc_provider = RpcProvider::new_with_config_path("<repo-root>/config.json")?;
```

`RpcProvider::new_with_config` accepts a `psy_config::NetworkConfigGoldilocks` value:

```rust
let rpc_provider = RpcProvider::new_with_config(&network_config)?;
```

## 4. RpcProvider

The provider supports user registration, contract deployment, EndCap submission, and state queries. The request constructors in this sketch are omitted because their complete fields are defined by the source types:

```rust
use psy_rust_sdk::{provider::RpcProvider, request::*};

let rpc_provider = RpcProvider::new_with_config_path("<repo-root>/config.json")?;
rpc_provider.set_user_id(user_id);

// Illustrative: construct every source-defined field before calling the provider.
let user_uuid = rpc_provider
    .register_user(register_request)
    .await?;
let contract_uuid = rpc_provider
    .deploy_contract(deploy_request)
    .await?;
let end_cap_uuid = rpc_provider
    .submit_end_cap_proof(end_cap_request)
    .await?;
let block_state = rpc_provider.get_realm_latest_block_state().await?;
```

## 5. ProveProxyRpcProvider

`ProveProxyRpcProvider::new_with_config` accepts one proof-proxy URL as a `String` and returns the provider synchronously:

```rust
use psy_rust_sdk::provider::ProveProxyRpcProvider;

let prove_provider = ProveProxyRpcProvider::new_with_config(proof_proxy_url)?;
```

The earlier method examples for registering contract circuits and proving individual operations are not retained because those exact methods were not verified on the current SDK provider surface.

## 6. Data Types

The crate depends on `psy_data`, but `psy_data` is not re-exported from `psy_rust_sdk`. Import data types from the `psy_data` dependency when an application needs them:

```rust
use psy_data::qdata::{
    checkpoint::PsyCheckpointLeaf,
    contract::{ContractCodeDefinition, PsyContractLeaf},
    user::PsyUserLeaf,
    user_public_key::PsyUserPublicKeyRecord,
};
```

The field summaries previously listed for these types are not repeated because they were not verified against the current SDK checkout. Treat the Rust definitions in `psy_data` as the interface source.

## 7. Verification Boundary

Verified against the SDK checkout:

1. The crate package name is `psy_rust_sdk`.
2. Native builds re-export `psy_common`, `network_constants`, `psy_crypto`, `request`, `provider`, `session`, and `wallet`.
3. `RpcProvider` exposes `new_with_config_path` and `new_with_config`.
4. `ProveProxyRpcProvider::new_with_config` takes a `String` and is not asynchronous.

Unverified SDK claims are marked as illustrative or omitted rather than presented as callable interfaces.
