# Installation

> Updated: 2026-09-03.

## Abstract

This guide installs the Psy node command-line tools from source, summarizes their primary commands, and verifies that each binary is available.

## Table of Contents

- [1. Prerequisites](#1-prerequisites)
- [2. Build](#2-build)
- [3. Command-Line Tools](#3-command-line-tools)
- [4. Verification](#4-verification)
- [5. Next Steps](#5-next-steps)

## 1. Prerequisites

- Rust, using the latest stable toolchain
- Git
- Make
- At least 16 GB of memory and 8 CPU cores are recommended

## 2. Build

### 2.1 Clone the repository

```bash
git clone https://github.com/PsyProtocol/psy-node.git
cd psy-node
```

### 2.2 Build the project

```bash
make build
```

The `build` target compiles the node, worker, developer, relayer, and user command-line tools (`Makefile:22-23`).

## 3. Command-Line Tools

### 3.1 `psy_node_cli`

`psy_node_cli` starts coordinator and realm nodes.

```bash
# Start coordinator components
psy_node_cli start-coordinator-edge
psy_node_cli start-coordinator-processor

# Start realm components with generated runtime config and local P2P keys
# (recommended)
bun dev/locSetupV4.ts
```

The node command names are defined in `psy_cli/psy_node_cli/src/subcommand.rs:18-253`.

### 3.2 `psy_worker_cli`

`psy_worker_cli` starts proof workers.

```bash
psy_worker_cli worker
```

The worker command is defined in `psy_cli/psy_worker_cli/src/subcommand.rs:18-57`.

API services are maintained in the separate `psy-services` repository.

### 3.3 `psy_user_cli`

`psy_user_cli` supports user registration, contract deployment, and contract calls.

```bash
psy_user_cli register-user
psy_user_cli deploy-contract
psy_user_cli call
```

### 3.4 `psy_dev_cli`

`psy_dev_cli` provides development and inspection utilities.

```bash
psy_dev_cli chain-info
```

The developer commands are defined in `psy_cli/psy_dev_cli/src/subcommand.rs:27-44`.

## 4. Verification

Verify each built tool by opening its help output:

```bash
psy_node_cli --help
psy_worker_cli --help
psy_user_cli --help
psy_dev_cli --help
```

A missing command indicates that the release binary directory is not on `PATH` or that `make build` did not complete successfully.

## 5. Next Steps

- Configure the network by following [Configuration](./configuration.md).
- Start a local network by following [Getting Started](./getting_started.md).
- Review the user commands in [User CLI](../rpc/UserCli.md).
