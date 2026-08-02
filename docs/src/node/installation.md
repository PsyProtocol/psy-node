# Installation

This guide walks you through installing and setting up Psy network nodes.

## Prerequisites

- Rust (latest stable version)
- Git
- Make
- Sufficient system resources (recommended: 16GB+ RAM, 8+ CPU cores)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/PsyProtocol/psy-v1
cd psy-v1
```

### 2. Build the Project

```bash
make build
```

This command compiles all necessary components including node binaries and CLI tools.

### 3. Install CLI Tools

```bash
make install
```

This installs three main CLI tools to your system:

## Installed CLI Tools

### psy_node_cli

**Purpose**: Start and manage network nodes

**Key Commands:**
```bash
# Start coordinator
psy_node_cli coordinator-edge
psy_node_cli coordinator-processor

# Start realm
psy_node_cli realm-edge
psy_node_cli realm-processor

# Start supporting services
psy_node_cli worker
psy_node_cli api-services
```

### psy_user_cli

**Purpose**: User interaction with the network

**Key Commands:**
```bash
# Register user
psy_user_cli register-user

# Deploy contract
psy_user_cli deploy-contract

# Call contract function
psy_user_cli call
```

### psy_dev_cli

**Purpose**: Development utilities

**Key Command:**
```bash
# Hash utilities
psy_dev_cli qhash
```

## Verification

After installation, verify that all tools are correctly installed:

```bash
# Check installations
psy_node_cli --version
psy_user_cli --version
psy_dev_cli --version

# View help for each tool
psy_node_cli --help
psy_user_cli --help
psy_dev_cli --help
```

## Next Steps

- Configure your node: See [Configuration](./configuration.md)
- Start your first node: See [Getting Started](./getting_started.md)
- Explore the API: See [API Reference](../rpc/UserCli.md)
