#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/build-parallelism.sh
source "$SCRIPT_DIR/lib/build-parallelism.sh"
WORKSPACE_ROOT="${WORKSPACE_HOME:-$(cd "$ROOT/.." && pwd)}"
PARTH_DIR="${PARTH_DIR:-$ROOT}"
IMAGE="${BOOKWORM_BUILDER_IMAGE:-parth-bookworm-builder:latest}"
GO_VERSION="${GO_VERSION:-1.22.3}"
PACKAGE_ARTIFACTS="${PACKAGE_ARTIFACTS:-1}"
BUILD_PARTH_BUNDLE="${BUILD_PARTH_BUNDLE:-1}"
PSY_SERVICES_DIR="${PSY_SERVICES_DIR:-$WORKSPACE_ROOT/psy-services}"
bookworm_build_jobs="$(resolve_rust_build_jobs "${BOOKWORM_BUILD_JOBS:-}")"

WORKSPACE_ROOT="$(cd "$WORKSPACE_ROOT" && pwd -P)"
PARTH_DIR="$(cd "$PARTH_DIR" && pwd -P)"
PSY_SERVICES_DIR="$(cd "$PSY_SERVICES_DIR" && pwd -P)" || {
  echo "missing psy-services checkout: ${PSY_SERVICES_DIR}" >&2
  exit 1
}

PARTH_WORKDIR="/psy-node"
PSY_SERVICES_WORKDIR="/psy-services"

command -v docker >/dev/null 2>&1 || {
  echo "docker is required" >&2
  exit 1
}

# psy_config embeds contract IDs and method IDs at compile time. Validate the
# canonical psy-genesis submodule before entering the build container.
bash "$PARTH_DIR/deploy/scripts/ensure-genesis-contracts.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/Dockerfile" <<EOF
FROM rust:bookworm

ARG GO_VERSION=${GO_VERSION}

RUN apt-get update \\
  && apt-get install -y --no-install-recommends \\
    bash \\
    build-essential \\
    ca-certificates \\
    clang \\
    cmake \\
    curl \\
    git \\
    libclang-dev \\
    libssl-dev \\
    llvm-dev \\
    make \\
    openssh-client \\
    perl \\
    pkg-config \\
    protobuf-compiler \\
    xz-utils \\
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go\${GO_VERSION}.linux-amd64.tar.gz" \\
  | tar -C /usr/local -xz

ENV PATH="/usr/local/go/bin:/usr/local/cargo/bin:\${PATH}"
RUN rustup toolchain install nightly --profile minimal

WORKDIR /work
EOF

echo "[bookworm-build] building Docker image: ${IMAGE}"
docker build -t "$IMAGE" "$tmp"
echo "[bookworm-build] using $bookworm_build_jobs parallel Cargo jobs"

docker_run_args=(
  --rm
  -e PARTH_WORKDIR="$PARTH_WORKDIR"
  -e PSY_SERVICES_WORKDIR="$PSY_SERVICES_WORKDIR"
  -e HOST_UID="$(id -u)"
  -e HOST_GID="$(id -g)"
  -e CARGO_HOME=/work/.cargo-bookworm
  -e RUSTUP_HOME=/usr/local/rustup
  -e CARGO_NET_GIT_FETCH_WITH_CLI=true
  -e CARGO_BUILD_JOBS="$bookworm_build_jobs"
  -v "$WORKSPACE_ROOT:/work"
  -v "$PARTH_DIR:$PARTH_WORKDIR"
  -v "$PSY_SERVICES_DIR:$PSY_SERVICES_WORKDIR"
  -w /work
)

private_git_dependency=0
if grep -R "ssh://git@github.com" "$PARTH_DIR/Cargo.toml" "$PSY_SERVICES_DIR/Cargo.toml" >/dev/null 2>&1; then
  private_git_dependency=1
fi

if [ "$private_git_dependency" = "1" ]; then
  ssh_command="${BOOKWORM_BUILD_GIT_SSH_COMMAND:-ssh -F none -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/bookworm-known-hosts}"

  if [ -n "${BOOKWORM_BUILD_GITHUB_SSH_KEY:-}" ]; then
    [ -f "$BOOKWORM_BUILD_GITHUB_SSH_KEY" ] || {
      echo "BOOKWORM_BUILD_GITHUB_SSH_KEY does not exist: $BOOKWORM_BUILD_GITHUB_SSH_KEY" >&2
      exit 1
    }
    docker_run_args+=(
      -v "$BOOKWORM_BUILD_GITHUB_SSH_KEY:/tmp/bookworm-github-key:ro"
      -e GIT_SSH_COMMAND="$ssh_command -i /tmp/bookworm-github-key -o IdentitiesOnly=yes"
    )
    echo "[bookworm-build] using explicit GitHub SSH key for private Cargo dependencies"
  elif [ -n "${SSH_AUTH_SOCK:-}" ] && [ -S "$SSH_AUTH_SOCK" ]; then
    docker_run_args+=(
      -v "$SSH_AUTH_SOCK:/tmp/bookworm-ssh-agent"
      -e SSH_AUTH_SOCK=/tmp/bookworm-ssh-agent
      -e GIT_SSH_COMMAND="$ssh_command"
    )
    echo "[bookworm-build] using host ssh-agent for private Cargo dependencies"
  else
    cat >&2 <<'EOF'
This workspace has private Cargo git dependencies, but no SSH agent is
available for the Debian bookworm builder container.

Start an agent and add your GitHub key:
  eval "$(ssh-agent -s)"
  ssh-add ~/.ssh/id_ed25519

Then rerun the deploy command. Alternatively set:
  BOOKWORM_BUILD_GITHUB_SSH_KEY="$HOME/.ssh/id_ed25519"
EOF
    exit 1
  fi
fi

echo "[bookworm-build] building release binaries inside Debian bookworm"
docker run \
  "${docker_run_args[@]}" \
  "$IMAGE" \
  bash -lc '
    set -euo pipefail
    export PATH="/usr/local/go/bin:/usr/local/cargo/bin:${PATH}"

    cd "$PARTH_WORKDIR"
    PSY_CONFIG_PATH="$PARTH_WORKDIR/psy-genesis/config.json" \
      cargo +nightly build --release \
        --bin psy_node_cli \
        --bin psy_worker_cli \
        --bin psy_user_cli \
        --bin psy_relayer_cli \
        --bin psy_dev_cli

    cd "$PSY_SERVICES_WORKDIR"
    cargo +nightly build --release --bin psy-services --bin psy-indexer

    chown -R "${HOST_UID}:${HOST_GID}" \
      /work/.cargo-bookworm \
      "$PARTH_WORKDIR/target" \
      "$PSY_SERVICES_WORKDIR/target"
  '

echo "[bookworm-build] verifying maximum required GLIBC versions"
for bin in \
  "$PARTH_DIR/target/release/psy_node_cli" \
  "$PARTH_DIR/target/release/psy_worker_cli" \
  "$PARTH_DIR/target/release/psy_user_cli" \
  "$PARTH_DIR/target/release/psy_relayer_cli" \
  "$PSY_SERVICES_DIR/target/release/psy-services" \
  "$PSY_SERVICES_DIR/target/release/psy-indexer"; do
  max_glibc="$(objdump -T "$bin" 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1 || true)"
  echo "[bookworm-build] $(basename "$bin") max ${max_glibc:-unknown}"
done

if [ "$PACKAGE_ARTIFACTS" = "1" ]; then
  echo "[bookworm-build] packaging deploy artifacts"
  bash "$PARTH_DIR/deploy/scripts/package-local-artifacts.sh"
fi

if [ "$BUILD_PARTH_BUNDLE" = "1" ]; then
  echo "[bookworm-build] building Parth node bundle"
  bash "$PARTH_DIR/deploy/gcp/build-parth-bundle.sh"
fi

echo "[bookworm-build] done"
