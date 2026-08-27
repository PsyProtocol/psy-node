#!/usr/bin/env bash
# Psy MCP Wallet — install and register the native binary (no Docker).
#
# Usage:
#   bash install-mcp-binary.sh
#   PSY_INSTALL_TARGET=codex bash install-mcp-binary.sh
#
# Optional:
#   PSY_CONFIG=/path/to/config.json
#   PSY_MCP_INSTALL_DIR="$HOME/.psy/bin"
#   PSY_MCP_KEYSTORE_DIR="$HOME/.psy-mcp-keys"
#   PSY_MCP_L1_KEY=0x...              (required at MCP runtime for Bridge deposit/withdraw; never persisted)
#   Contract and token addresses are loaded from config.json's l1_config_url.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${PSY_CONFIG:-$HOME/.psy/config.json}"
INSTALL_DIR="${PSY_MCP_INSTALL_DIR:-$HOME/.psy/bin}"
KEYSTORE_DIR="${PSY_MCP_KEYSTORE_DIR:-$HOME/.psy-mcp-keys}"
BINARY_NAME="psy-mcp-server"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
TARGET="${PSY_INSTALL_TARGET:-claude-code}"

if command -v openssl >/dev/null 2>&1; then
  OWNER_TOKEN="psy-$(openssl rand -hex 8)"
else
  OWNER_TOKEN="psy-$(date +%s)-$$"
fi

die() {
  echo "error: $*" >&2
  exit 1
}

echo "========================================"
echo "  Psy MCP Wallet — native installer"
echo "========================================"

command -v cargo >/dev/null 2>&1 || die "cargo not found; install Rust from https://rustup.rs/"
command -v rustc >/dev/null 2>&1 || die "rustc not found; install Rust from https://rustup.rs/"

if [ -n "${PSY_MCP_L1_KEY:-}" ]; then
  echo "[Bridge] PSY_MCP_L1_KEY is set (value is not displayed or persisted)."
fi

if [ ! -f "$CONFIG_FILE" ]; then
  DEFAULT_CONFIG="$SCRIPT_DIR/psy-genesis/config.json"
  [ -f "$DEFAULT_CONFIG" ] || die "Psy config not found: $CONFIG_FILE"
  mkdir -p "$(dirname "$CONFIG_FILE")"
  cp "$DEFAULT_CONFIG" "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
  echo "(1) Initialized config -> $CONFIG_FILE"
else
  echo "(1) Using config -> $CONFIG_FILE"
fi

mkdir -p "$INSTALL_DIR" "$KEYSTORE_DIR"
chmod 700 "$KEYSTORE_DIR"

echo "(2) Building release binary (this may take a while on a cold checkout)..."
(cd "$SCRIPT_DIR" && cargo build --release -p psy_mcp_server)
cp "$SCRIPT_DIR/target/release/$BINARY_NAME" "$BINARY_PATH"
chmod 755 "$BINARY_PATH"
echo "    Installed -> $BINARY_PATH"

case ":${PATH}:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "warning: $INSTALL_DIR is not currently on PATH" >&2 ;;
esac

register_json() {
  local config_path="$1"
  python3 - "$config_path" "$BINARY_PATH" "$CONFIG_FILE" "$KEYSTORE_DIR" "$OWNER_TOKEN" <<'PY'
import json
import sys

path, binary, config, keystore, token = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (FileNotFoundError, json.JSONDecodeError):
    data = {}

env = {
    "PSY_CONFIG": config,
    "PSY_MCP_KEYSTORE_DIR": keystore,
    "PSY_MCP_OWNER_TOKEN": token,
}
data.setdefault("mcpServers", {})["psy"] = {
    "command": binary,
    "args": ["--config", config],
    "env": env,
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
PY
}

toml_quote() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

case "$TARGET" in
  claude-code|claude-cli)
    if command -v claude >/dev/null 2>&1; then
      claude mcp remove -s user psy >/dev/null 2>&1 || true
      CLAUDE_ARGS=(
        mcp add -s user psy
        -e "PSY_CONFIG=$CONFIG_FILE"
        -e "PSY_MCP_KEYSTORE_DIR=$KEYSTORE_DIR"
        -e "PSY_MCP_OWNER_TOKEN=$OWNER_TOKEN"
      )
      CLAUDE_ARGS+=(-- "$BINARY_PATH" --config "$CONFIG_FILE")
      claude "${CLAUDE_ARGS[@]}"
      echo "(3) Registered with Claude Code"
    else
      register_json "$HOME/.claude.json"
      echo "(3) Written -> $HOME/.claude.json"
    fi
    ;;
  claude-desktop)
    CONFIG_DIR="$HOME/Library/Application Support/Claude"
    mkdir -p "$CONFIG_DIR"
    register_json "$CONFIG_DIR/claude_desktop_config.json"
    echo "(3) Written -> $CONFIG_DIR/claude_desktop_config.json"
    ;;
  codex)
    CONFIG_DIR="$HOME/.codex"
    CONFIG_PATH="$CONFIG_DIR/config.toml"
    mkdir -p "$CONFIG_DIR"
    if ! grep -q '^\[mcp_servers\.psy\]' "$CONFIG_PATH" 2>/dev/null; then
      {
        echo ""
        echo "[mcp_servers.psy]"
        printf 'command = %s\n' "$(toml_quote "$BINARY_PATH")"
        printf 'args = ["--config", %s]\n' "$(toml_quote "$CONFIG_FILE")"
        echo ""
        echo "[mcp_servers.psy.env]"
        printf 'PSY_CONFIG = %s\n' "$(toml_quote "$CONFIG_FILE")"
        printf 'PSY_MCP_KEYSTORE_DIR = %s\n' "$(toml_quote "$KEYSTORE_DIR")"
        printf 'PSY_MCP_OWNER_TOKEN = %s\n' "$(toml_quote "$OWNER_TOKEN")"
      } >> "$CONFIG_PATH"
    else
      echo "warning: $CONFIG_PATH already contains [mcp_servers.psy]; leaving it unchanged" >&2
    fi
    echo "(3) Codex config -> $CONFIG_PATH"
    ;;
  cursor|workbuddy)
    if [ "$TARGET" = cursor ]; then
      CONFIG_PATH="$HOME/.cursor/mcp.json"
    else
      CONFIG_PATH="$HOME/.workbuddy/mcp.json"
    fi
    mkdir -p "$(dirname "$CONFIG_PATH")"
    register_json "$CONFIG_PATH"
    echo "(3) Written -> $CONFIG_PATH"
    ;;
  *)
    die "unknown PSY_INSTALL_TARGET=$TARGET (use claude-code, claude-desktop, codex, cursor, or workbuddy)"
    ;;
esac

if [ -z "${PSY_MCP_L1_KEY:-}" ]; then
  echo "" >&2
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
  echo "!! WARNING: PSY_MCP_L1_KEY is not set.                        !!" >&2
  echo "!! The MCP wallet will install, but Bridge deposit/withdraw   !!" >&2
  echo "!! will be unavailable. Export PSY_MCP_L1_KEY before starting !!" >&2
  echo "!! Claude Code / the MCP server to enable Bridge operations.  !!" >&2
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
fi

echo ""
echo "Done. Restart $TARGET and ask the client to list the Psy tools."
echo "Binary:  $BINARY_PATH"
echo "Config:  $CONFIG_FILE"
echo "Keys:    $KEYSTORE_DIR"
echo "Token:   $OWNER_TOKEN (save this; it is not recoverable from the MCP client)"
