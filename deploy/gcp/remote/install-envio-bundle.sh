#!/usr/bin/env bash
set -euo pipefail

if [ ! -f /tmp/parth-envio-bundle.tar.gz ]; then
  echo "missing /tmp/parth-envio-bundle.tar.gz" >&2
  exit 1
fi

bash /tmp/mount-data-disk.sh
install -d -m 0755 /opt/parth/envio/releases /var/lib/parth/envio
release="/opt/parth/envio/releases/$(date -u +%Y%m%d%H%M%S)"
install -d -m 0755 "$release"
tar -xzf /tmp/parth-envio-bundle.tar.gz -C "$release"
if [ -n "${ENVIO_BUNDLE_SHA256:-}" ]; then
  install -m 0644 /dev/null "$release/psy-relayer-envio/.bundle.sha256"
  printf '%s\n' "$ENVIO_BUNDLE_SHA256" > "$release/psy-relayer-envio/.bundle.sha256"
fi
ln -sfn "$release/psy-relayer-envio" /opt/parth/envio/current

echo "installed Envio bundle to $release"
echo "current -> $(readlink -f /opt/parth/envio/current)"
