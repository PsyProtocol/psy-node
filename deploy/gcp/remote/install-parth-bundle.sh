#!/usr/bin/env bash
set -euo pipefail

if [ ! -f /tmp/parth-node-bundle.tar.gz ]; then
  echo "missing /tmp/parth-node-bundle.tar.gz" >&2
  exit 1
fi

bash /tmp/prepare-parth-host.sh 2>/dev/null || true

release="/opt/parth/releases/$(date -u +%Y%m%d%H%M%S)"
keep_releases="${PARTH_KEEP_RELEASES:-1}"
allow_genesis_overwrite="${PARTH_ALLOW_GENESIS_OVERWRITE:-0}"
install -d -m 0755 "$release"
tar -xzf /tmp/parth-node-bundle.tar.gz -C "$release"

[ -f "$release/deploy/bin/run-parth-service" ] || {
  echo "bundle is missing deploy/bin/run-parth-service" >&2
  exit 1
}
chmod 0755 "$release/deploy/bin/run-parth-service"
[ -x "$release/target/release/psy_node_cli" ] || {
  echo "bundle is missing target/release/psy_node_cli" >&2
  exit 1
}
if [ -n "${PARTH_BUNDLE_SHA256:-}" ]; then
  install -m 0644 /dev/null "$release/.bundle.sha256"
  printf '%s\n' "$PARTH_BUNDLE_SHA256" > "$release/.bundle.sha256"
fi

current_release="$(readlink -f /opt/parth/current 2>/dev/null || true)"
current_genesis=""
if [ -n "$current_release" ] && [ -f "$current_release/genesis.json" ]; then
  current_genesis="$current_release/genesis.json"
elif [ -f /opt/parth/current/genesis.json ]; then
  current_genesis="/opt/parth/current/genesis.json"
fi

if [ -n "$current_genesis" ] && [ -f "$release/genesis.json" ]; then
  current_genesis_sha="$(sha256sum "$current_genesis" | awk '{ print $1 }')"
  release_genesis_sha="$(sha256sum "$release/genesis.json" | awk '{ print $1 }')"
  if [ "$current_genesis_sha" != "$release_genesis_sha" ]; then
    if [ "$allow_genesis_overwrite" = "1" ]; then
      echo "genesis overwrite allowed: current=${current_genesis_sha} release=${release_genesis_sha}"
    else
      echo "preserving existing genesis.json for non-fresh bundle install"
      echo "  current genesis sha: ${current_genesis_sha}"
      echo "  bundled genesis sha: ${release_genesis_sha}"
      cp "$release/genesis.json" "$release/genesis.json.bundled"
      cp "$current_genesis" "$release/genesis.json"
    fi
  fi
fi

release_config_genesis="$release/deploy/config/parth/genesis.json"
if [ -n "$current_genesis" ] && [ -f "$release_config_genesis" ] && [ "$allow_genesis_overwrite" != "1" ]; then
  current_genesis_sha="$(sha256sum "$current_genesis" | awk '{ print $1 }')"
  release_config_genesis_sha="$(sha256sum "$release_config_genesis" | awk '{ print $1 }')"
  if [ "$current_genesis_sha" != "$release_config_genesis_sha" ]; then
    echo "preserving existing deploy/config/parth/genesis.json for non-fresh bundle install"
    echo "  current genesis sha: ${current_genesis_sha}"
    echo "  bundled deploy/config/parth/genesis sha: ${release_config_genesis_sha}"
    cp "$release_config_genesis" "$release_config_genesis.bundled"
    cp "$current_genesis" "$release_config_genesis"
  fi
fi

if [ -e /opt/parth/current ] && [ ! -L /opt/parth/current ]; then
  mv /opt/parth/current "/opt/parth/current.pre-bundle.$(date -u +%Y%m%d%H%M%S)"
fi
ln -sfn "$release" /opt/parth/current
chown -R parth:parth /opt/parth /var/lib/parth

if [ "$keep_releases" -gt 0 ] 2>/dev/null; then
  current_release="$(readlink -f /opt/parth/current)"
  find /opt/parth/releases -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
    | sort -rn \
    | awk -v keep="$keep_releases" -v current="$current_release" '{
        path=$2
        if (path == current) {
          next
        }
        kept_non_current += 1
        if (kept_non_current >= keep) {
          print path
        }
      }' \
    | while IFS= read -r old_release; do
        if [ -n "$old_release" ] && [ "$old_release" != "$current_release" ]; then
          echo "removing old Parth release: $old_release"
          rm -rf "$old_release"
        fi
      done
fi

echo "installed Parth bundle to $release"
echo "current -> $(readlink -f /opt/parth/current)"
