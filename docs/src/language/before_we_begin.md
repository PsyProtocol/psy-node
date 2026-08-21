# Before We Begin

[Psy Smart Contract Language] requires a development environment to write and run programs. This chapter covers the prerequisites: setting up your IDE, installing the compiler, and understanding the basic tools.

If you already have the compiler installed (via `git` or another method), you can skip to the next chapter.

## Installing the Compiler

The Psy compiler (`dargo`) is available from the official repository at [https://github.com/PsyProtocol/psy-compiler].

### Installation via Cargo

Currently, the only supported installation method is via Cargo (Rust package manager):

**Install the Psy compiler:**
```bash
cargo install --git https://github.com/PsyProtocol/psy-compiler dargo
```

**Install the Language Server (for IDE support):**
```bash
cargo install --git https://github.com/PsyProtocol/psy-compiler psy-lsp-server
```

**Prerequisites:**
- Rust toolchain installed (visit [rustup.rs](https://rustup.rs/) to install)
- Git for cloning the repository

**Note:** Package managers like Homebrew (macOS) and Chocolatey (Windows) are not currently supported, but may be available in future releases.

## Verifying Installation

After installation, verify that both tools are available in your PATH:

```bash
# Verify the compiler
dargo --version

# Verify the language server
psy-lsp-server --version
```

You should see version information for both the Psy compiler and language server.

## Environment Setup

Set the `DARGO_STD_PATH` environment variable to point to the standard library:

```bash
# For bash/zsh — point at the psy-compiler checkout next to this repo
export DARGO_STD_PATH="$PWD/../psy-compiler/psy-std/std.psy"

# For fish shell
set -gx DARGO_STD_PATH "$PWD/../psy-compiler/psy-std/std.psy"
```

Add this to your shell configuration file (`.bashrc`, `.zshrc`, or `~/.config/fish/config.fish`) to make it persistent.

## Setting Up Your IDE

Psy provides Language Server Protocol (LSP) support for enhanced development experience. Currently supported IDEs:

- **Visual Studio Code** - Full LSP support with extension
- **Neovim** - LSP configuration guide

See the [Set up your IDE](./setup_your_ide.md) section for detailed configuration instructions.

**LSP Features:**
- Hover for type information
- Go to definition
- Find references  
- Code formatting
- Real-time error diagnostics

## Getting Started

Once you have `dargo` installed and your IDE configured, you're ready to start writing Psy smart contracts! Continue to the [Hello, World!](./hello_world.md) chapter to create your first program.
