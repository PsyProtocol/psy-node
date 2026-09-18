#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORKSPACE_HOME=${WORKSPACE_HOME:-$(cd "$HERE/../.." && pwd)}
SRC=${SRC:-$WORKSPACE_HOME/psy-node-rollout-src}
EXPECTED=3a81f59e0cf9333fc2ad4aefda7c83787660c9ab
test "$(git -C "$SRC" rev-parse HEAD)" = "$EXPECTED"
test -z "$(git -C "$SRC" status --porcelain)"
test -f "$SRC/psy-genesis/config.json"
test "$(git -C "$SRC/psy-genesis" rev-parse HEAD)" = 285d9a2a82e20ae20053f81345537abba23136a1
test -z "$(git -C "$SRC/psy-genesis" status --porcelain)"
auth=()
if [ -n "${BOOKWORM_BUILD_GITHUB_SSH_KEY:-}" ]; then
  test -f "$BOOKWORM_BUILD_GITHUB_SSH_KEY"
  auth=(-v "$BOOKWORM_BUILD_GITHUB_SSH_KEY:/tmp/build-key:ro"
    -e 'GIT_SSH_COMMAND=ssh -F none -i /tmp/build-key -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/known-hosts')
else
  test -S "${SSH_AUTH_SOCK:?provide SSH agent or BOOKWORM_BUILD_GITHUB_SSH_KEY}"
  auth=(-v "$SSH_AUTH_SOCK:/tmp/agent" -e SSH_AUTH_SOCK=/tmp/agent
    -e 'GIT_SSH_COMMAND=ssh -F none -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/known-hosts')
fi
mkdir -p "$HERE/out"
docker run --rm "${auth[@]}" \
  -v "$WORKSPACE_HOME:/work" -v "$SRC:/psy-node" \
  -e CARGO_HOME=/work/.cargo-bookworm -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
  -e CARGO_BUILD_JOBS="${BUILD_JOBS:-16}" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -w /psy-node parth-bookworm-builder:latest bash -lc '
    set -euo pipefail
    export PATH="/usr/local/go/bin:/usr/local/cargo/bin:$PATH"
    trap '\''chown -R "$HOST_UID:$HOST_GID" /psy-node/target'\'' EXIT
    PSY_CONFIG_PATH=/psy-node/psy-genesis/config.json PSY_NETWORK="${PSY_NETWORK:-testnet}" \
      cargo +nightly build --locked --release --bin psy_relayer_cli
    rustc +nightly --version > target/release/role-build-toolchain.txt
  '
test -z "$(git -C "$SRC" status --porcelain)"
install -m 0755 "$SRC/target/release/psy_relayer_cli" "$HERE/out/psy_relayer_cli"
cp "$SRC/target/release/role-build-toolchain.txt" "$HERE/out/TOOLCHAIN.txt"
printf '%s\n' "$EXPECTED" > "$HERE/out/SOURCE_COMMIT"
(cd "$HERE/out" && sha256sum psy_relayer_cli SOURCE_COMMIT TOOLCHAIN.txt > SHA256SUMS)
objdump -T "$HERE/out/psy_relayer_cli" | sed -n 's/.*(GLIBC_\([0-9.]*\)).*/\1/p' | sort -Vu | tail -n 1
echo 'Built relayer only; no runtime deployment or genesis generation performed.'
