# Psy SDK Overview

> Updated: 2026-09-04.

## Abstract

The Psy SDK repository provides a Rust library and TypeScript packages for network access, wallet operations, local proving, contract binding generation, and contract interaction.

## 1. Available SDKs

- **[Rust SDK](rust.md)**: The `psy_rust_sdk` crate re-exports native provider, session, wallet, request, configuration, and cryptography modules.
- **[TypeScript SDK](typescript.md)**: The `@psy-protocol/psy-sdk` package provides remote procedure call clients, wallet providers, local web proving, and local web compilation. The `@psy-protocol/contract-sdk` package generates and runs typed contract bindings.

## 2. Common Use Cases

- **User management**: Register users and operate wallets.
- **Contract development**: Generate bindings and interact with contracts.
- **Network interaction**: Query network state and submit transactions.
- **Proof generation**: Use native or web proving providers.

## 3. Getting Started

1. Choose the [Rust SDK](rust.md) or [TypeScript SDK](typescript.md).
2. Follow that SDK's installation and configuration instructions.
3. Configure the target network endpoints.
4. Use the documented provider and wallet interfaces.
