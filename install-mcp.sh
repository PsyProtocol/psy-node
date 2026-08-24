#!/usr/bin/env bash
# Psy MCP Wallet - one-click installer for Claude Desktop / Claude Code
# Usage: bash install-mcp.sh
#   PSY_INSTALL_TARGET=claude-desktop|codex|cursor bash install-mcp.sh  # other clients (default: Claude Code)
set -euo pipefail

OWNER_TOKEN="psy-$(openssl rand -hex 8 2>/dev/null || date +%s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PSY_CONFIG_FILE="$HOME/.psy/config.json"

echo "========================================"
echo "  Psy MCP Wallet Installer"
echo "========================================"

# 1. ensure image exists; build from the Dockerfile next to this script if not.
if docker image inspect psy-mcp-server:staging >/dev/null 2>&1; then
  echo "(1) Image already present"
else
  echo "(1) Image not found; building from Dockerfile.psy-mcp-server (cold build takes 10 min)..."
  if (cd "$SCRIPT_DIR" && docker build -f Dockerfile.psy-mcp-server -t psy-mcp-server:staging .); then
    echo "(1) Image built"
  else
    echo "(1) X Image build failed"
    exit 1
  fi
fi

echo "(2) Generated owner token: $OWNER_TOKEN"

# Keep network selection on the host. Editing defaultNetwork in this file and
# restarting the MCP client switches networks without rebuilding the image.
if [ ! -f "$PSY_CONFIG_FILE" ]; then
  mkdir -p "$(dirname "$PSY_CONFIG_FILE")"
  cp "$SCRIPT_DIR/psy-genesis/config.json" "$PSY_CONFIG_FILE"
  chmod 600 "$PSY_CONFIG_FILE"
  echo "(2) Initialized config -> $PSY_CONFIG_FILE"
else
  echo "(2) Using config -> $PSY_CONFIG_FILE"
fi

# 2. target selection (default: Claude Code)
TARGET="${PSY_INSTALL_TARGET:-claude-code}"
case "$TARGET" in
  claude-code)    ;;
  claude-desktop) CFG_DIR="$HOME/Library/Application Support/Claude"; CFG="$CFG_DIR/claude_desktop_config.json" ;;
  codex)   CFG_DIR="$HOME/.codex"; CFG="$CFG_DIR/config.toml" ;;
  cursor)  CFG_DIR="$HOME/.cursor"; CFG="$CFG_DIR/mcp.json" ;;
  workbuddy) CFG_DIR="$HOME/.workbuddy"; CFG="$CFG_DIR/mcp.json" ;;
  *)
    echo "X Unknown target $TARGET - supported: claude-code | claude-desktop | codex | cursor | workbuddy"; exit 1 ;;
esac
[ -n "${CFG_DIR:-}" ] && mkdir -p "$CFG_DIR"

case "$TARGET" in
  claude-cli|claude-code)
    # Claude Code does NOT read mcpServers from ~/.claude/settings.json -
    # the only registry it loads is ~/.claude.json, written by `claude mcp add`.
    # (Writing settings.json looked fine but the server never loaded - caught
    # live by a colleague 2026-08-17.) Register via the CLI, idempotently.
    if command -v claude >/dev/null 2>&1; then
      claude mcp remove -s user psy >/dev/null 2>&1 || true
      claude mcp add -s user psy -e PSY_MCP_OWNER_TOKEN="$OWNER_TOKEN" -- docker run -i --rm -v "$PSY_CONFIG_FILE:/app/config.json:ro" -v psy_wallet_keys:/app/keys -e PSY_CONFIG=/app/config.json -e PSY_MCP_OWNER_TOKEN psy-mcp-server:staging
      echo "(3) Registered in ~/.claude.json (visible via claude mcp list)"
    else
      # no claude CLI: write ~/.claude.json directly (same registry)
      CFG_DIR="$HOME"; CFG="$HOME/.claude.json"
      python3 -c "
import json, sys
p, tok, config = sys.argv[1], sys.argv[2], sys.argv[3]
try: cfg = json.load(open(p))
except Exception: cfg = {}
cfg.setdefault('mcpServers', {})['psy'] = {'command':'docker','args':['run','-i','--rm','-v',f'{config}:/app/config.json:ro','-v','psy_wallet_keys:/app/keys','-e','PSY_CONFIG=/app/config.json','-e','PSY_MCP_OWNER_TOKEN','psy-mcp-server:staging'],'env':{'PSY_MCP_OWNER_TOKEN':tok}}
json.dump(cfg, open(p,'w'), indent=2)
" "$CFG" "$OWNER_TOKEN" "$PSY_CONFIG_FILE"
      echo "(3) Written to ~/.claude.json"
    fi
    ;;
  codex)
    # Codex config.toml - pure bash append (TOML has no JSON merge)
    if ! grep -q "mcp_servers.psy" "$CFG"; then
      {
        echo ""
        echo "[mcp_servers.psy]"
        echo 'command = "docker"'
        echo "args = [\"run\",\"-i\",\"--rm\",\"-v\",\"$PSY_CONFIG_FILE:/app/config.json:ro\",\"-v\",\"psy_wallet_keys:/app/keys\",\"-e\",\"PSY_CONFIG=/app/config.json\",\"-e\",\"PSY_MCP_OWNER_TOKEN\",\"psy-mcp-server:staging\"]"
        echo ""
        echo "[mcp_servers.psy.env]"
        echo "PSY_MCP_OWNER_TOKEN = \"$OWNER_TOKEN\""
      } >> "$CFG"
    fi
    echo "(3) Codex config appended -> $CFG"
    ;;
  cursor|workbuddy)
    # Cursor (~/.cursor/mcp.json) and WorkBuddy (~/.workbuddy/mcp.json) share the
    # same registry shape: { "mcpServers": { name: {command,args,env} } }.
    # WorkBuddy is the Tencent coding-copilot desktop app; its ~/.workbuddy/mcp.json
    # is the user-level MCP registry (verified present even when empty).
    mkdir -p "$CFG_DIR"
    python3 -c "
import json, sys
p, tok, config = sys.argv[1], sys.argv[2], sys.argv[3]
try: cfg = json.load(open(p))
except Exception: cfg = {}
cfg.setdefault('mcpServers', {})['psy'] = {'command':'docker','args':['run','-i','--rm','-v',f'{config}:/app/config.json:ro','-v','psy_wallet_keys:/app/keys','-e','PSY_CONFIG=/app/config.json','-e','PSY_MCP_OWNER_TOKEN','psy-mcp-server:staging'],'env':{'PSY_MCP_OWNER_TOKEN':tok}}
json.dump(cfg, open(p,'w'), indent=2)
" "$CFG" "$OWNER_TOKEN" "$PSY_CONFIG_FILE"
    echo "(3) $TARGET config written -> $CFG"
    ;;
  *)
    # Claude Code / Desktop - JSON merge (idempotent)
    mkdir -p "$CFG_DIR"
    python3 -c "
import json, sys
p, tok, config = sys.argv[1], sys.argv[2], sys.argv[3]
try: cfg = json.load(open(p))
except Exception: cfg = {}
cfg.setdefault('mcpServers', {})['psy'] = {'command':'docker','args':['run','-i','--rm','-v',f'{config}:/app/config.json:ro','-v','psy_wallet_keys:/app/keys','-e','PSY_CONFIG=/app/config.json','-e','PSY_MCP_OWNER_TOKEN','psy-mcp-server:staging'],'env':{'PSY_MCP_OWNER_TOKEN':tok}}
json.dump(cfg, open(p,'w'), indent=2)
" "$CFG" "$OWNER_TOKEN" "$PSY_CONFIG_FILE"
    echo "(3) Config written -> $CFG"
    ;;
esac

case "$TARGET" in
  claude-code)    RESTART_HINT="Claude Code" ;;
  claude-desktop) RESTART_HINT="Claude Desktop" ;;
  codex)          RESTART_HINT="Codex" ;;
  cursor)         RESTART_HINT="Cursor" ;;
  workbuddy)      RESTART_HINT="WorkBuddy" ;;
  *)              RESTART_HINT="your MCP client" ;;
esac

echo "Done! Restart $RESTART_HINT, then tell the AI:"
echo ""
echo '   "Create a new psy wallet, 100 PSY per-transaction cap"'
echo ""
echo "========================================"
echo "  Token (please save): $OWNER_TOKEN"
echo "  Test guide: README.md"
echo "========================================"
