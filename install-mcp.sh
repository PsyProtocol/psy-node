#!/usr/bin/env bash
# Psy MCP Wallet — install and register the native binary (no Docker).
#
# Usage:
#   bash install-mcp.sh
#   PSY_INSTALL_TARGET=codex bash install-mcp.sh
#
# Optional:
#   PSY_CONFIG=/path/to/config.json
#   PSY_MCP_INSTALL_DIR="$HOME/.psy/bin"
#   PSY_MCP_KEYSTORE_DIR="$HOME/.psy-mcp-keys"
#   PSY_MCP_VERSION=vX.Y.Z               (optional release tag; omitted uses latest)
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
echo "  Psy MCP Wallet — GitHub Release installer"
echo "========================================"


if [ -n "${PSY_MCP_L1_KEY:-}" ]; then
  echo "[Bridge] PSY_MCP_L1_KEY is set (value is not displayed or persisted)."
fi

if [ ! -f "$CONFIG_FILE" ]; then
  DEFAULT_CONFIG="$SCRIPT_DIR/psy-genesis/config.json"
  if [ -f "$DEFAULT_CONFIG" ]; then
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cp "$DEFAULT_CONFIG" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    echo "(1) Initialized config -> $CONFIG_FILE"
  else
    command -v curl >/dev/null 2>&1 || die "Psy config not found: $CONFIG_FILE (curl is required to download it)"
    CONFIG_URL="${PSY_CONFIG_URL:-https://raw.githubusercontent.com/PsyProtocol/psy-genesis/mainnet-beta/config.json}"
    mkdir -p "$(dirname "$CONFIG_FILE")"
    curl --fail --location --silent --show-error --retry 3 --output "$CONFIG_FILE" "$CONFIG_URL" || die "Psy config not found and download failed: $CONFIG_URL"
    chmod 600 "$CONFIG_FILE"
    echo "(1) Downloaded config -> $CONFIG_FILE"
  fi
else
  echo "(1) Using config -> $CONFIG_FILE"
fi

mkdir -p "$INSTALL_DIR" "$KEYSTORE_DIR"
chmod 700 "$KEYSTORE_DIR"

echo "(2) Resolving GitHub release..."
command -v curl >/dev/null 2>&1 || die "curl not found"
if [ -n "${PSY_MCP_VERSION:-}" ]; then
  echo "    Using requested version $PSY_MCP_VERSION"
else
  LATEST_URL="${PSY_MCP_LATEST_URL:-https://github.com/PsyProtocol/psy-node/releases/latest}"
  LOCATION="$(curl --fail --location --silent --show-error --max-time 20 --write-out "%{url_effective}" --output /dev/null "$LATEST_URL")"
  PSY_MCP_VERSION="${LOCATION##*/}"
  [ -n "$PSY_MCP_VERSION" ] || die "could not resolve the latest GitHub release tag"
  echo "    Latest version: $PSY_MCP_VERSION"
fi
case "$(uname -s):$(uname -m)" in
  Linux:x86_64) RELEASE_TRIPLE="x86_64-unknown-linux-gnu" ;;
  Linux:aarch64|Linux:arm64) RELEASE_TRIPLE="aarch64-unknown-linux-gnu" ;;
  Darwin:x86_64) RELEASE_TRIPLE="x86_64-apple-darwin" ;;
  Darwin:arm64) RELEASE_TRIPLE="aarch64-apple-darwin" ;;
  *) die "unsupported platform $(uname -s)/$(uname -m)" ;;
esac
case "$PSY_MCP_VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "PSY_MCP_VERSION must look like vX.Y.Z" ;; esac
ARCHIVE="psy-node-${PSY_MCP_VERSION}-${RELEASE_TRIPLE}.tar.gz"
DOWNLOAD_DIR="${PSY_MCP_DOWNLOAD_DIR:-${TMPDIR:-/tmp}/psy-mcp-downloads/${PSY_MCP_VERSION}-${RELEASE_TRIPLE}}"
mkdir -p "$DOWNLOAD_DIR"
RELEASE_BASE="${PSY_MCP_RELEASE_BASE:-https://github.com/PsyProtocol/psy-node/releases/download/$PSY_MCP_VERSION}"
command -v curl >/dev/null 2>&1 || die "curl not found"
download_asset() {
  local url="$1"
  local destination="$2"
  curl --fail --location --continue-at - --progress-bar --retry 3 --retry-all-errors --output "$destination" "$url"
}
if [ -s "$DOWNLOAD_DIR/$ARCHIVE" ] && tar -tzf "$DOWNLOAD_DIR/$ARCHIVE" >/dev/null 2>&1; then
  echo "    Reusing complete $ARCHIVE"
else
  echo "    Downloading $ARCHIVE (resumable)"
  download_asset "$RELEASE_BASE/$ARCHIVE" "$DOWNLOAD_DIR/$ARCHIVE"
fi
if [ -s "$DOWNLOAD_DIR/SHA256SUMS" ] && grep -q " $ARCHIVE$" "$DOWNLOAD_DIR/SHA256SUMS"; then
  echo "    Reusing SHA256SUMS"
else
  echo "    Downloading SHA256SUMS (resumable)"
  download_asset "$RELEASE_BASE/SHA256SUMS" "$DOWNLOAD_DIR/SHA256SUMS"
fi
if command -v sha256sum >/dev/null 2>&1; then
  if ! (cd "$DOWNLOAD_DIR" && sha256sum --check SHA256SUMS --ignore-missing | sed 's/^/    /'); then
    die "checksum mismatch; installation stopped and the existing binary was not changed. Cache directory: $DOWNLOAD_DIR. Remove it and retry with rm -rf $DOWNLOAD_DIR"
  fi
elif command -v shasum >/dev/null 2>&1; then
  expected="$(grep " $ARCHIVE$" "$DOWNLOAD_DIR/SHA256SUMS" | awk "{print $1}")"
  actual="$(shasum -a 256 "$DOWNLOAD_DIR/$ARCHIVE" | awk "{print $1}")"
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    die "checksum mismatch; installation stopped and the existing binary was not changed. Cache directory: $DOWNLOAD_DIR. Remove it and retry with rm -rf $DOWNLOAD_DIR"
  fi
  echo "    $ARCHIVE: OK"
else
  die "sha256sum or shasum not found"
fi
tar -xzf "$DOWNLOAD_DIR/$ARCHIVE" -C "$DOWNLOAD_DIR"
[ -x "$DOWNLOAD_DIR/$BINARY_NAME" ] || die "release archive does not contain $BINARY_NAME"
install -m 755 "$DOWNLOAD_DIR/$BINARY_NAME" "$BINARY_PATH"
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
except FileNotFoundError:
    data = {}
except json.JSONDecodeError as error:
    raise SystemExit(f"invalid JSON in {path}: {error}; refusing to overwrite it")

env = {
    "PSY_CONFIG": config,
    "PSY_MCP_KEYSTORE_DIR": keystore,
    "PSY_MCP_OWNER_TOKEN": token,
}
servers = data.setdefault("mcpServers", {})
entry = servers.setdefault("psy", {})
if not isinstance(entry, dict):
    raise SystemExit(f"mcpServers.psy in {path} is not an object; refusing to overwrite it")
entry.update({"command": binary, "args": ["--config", config], "env": {**entry.get("env", {}), **env}})
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

register_codex() {
  local config_path="$1"
  python3 - "$config_path" "$BINARY_PATH" "$CONFIG_FILE" "$KEYSTORE_DIR" "$OWNER_TOKEN" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
binary, config, keystore, token = sys.argv[2:]
text = path.read_text() if path.exists() else ""
lines = text.splitlines()
out = []
skipping = False

def toml_quote(value):
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
for line in lines:
    if line.startswith("["):
        skipping = line == "[mcp_servers.psy]" or line.startswith("[mcp_servers.psy.")
    if not skipping:
        out.append(line)
while out and not out[-1].strip():
    out.pop()
out += ["", "[mcp_servers.psy]", f"command = {toml_quote(binary)}", f"args = [\"--config\", {toml_quote(config)}]", "", "[mcp_servers.psy.env]", f"PSY_CONFIG = {toml_quote(config)}", f"PSY_MCP_KEYSTORE_DIR = {toml_quote(keystore)}", f"PSY_MCP_OWNER_TOKEN = {toml_quote(token)}", ""]
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("\n".join(out))
PY
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
    register_codex "$CONFIG_PATH"
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
