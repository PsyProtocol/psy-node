#!/usr/bin/env bash
set -euo pipefail
source_dir="$(realpath "${1:?source checkout required}")"
out="$(realpath -m "${2:?output directory required}")"
workspace="$(dirname "$source_dir")"
image=sha256:02a4dd5c2ea776982084a4a856610836fc9f944203e85948fd4b475177f6b4af
revision="$(git -C "$source_dir" rev-parse HEAD)"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]]
[[ "$(git -C "$source_dir/psy-genesis" rev-parse HEAD)" == cb3ea4a1e743c3c01037ae968e10f27389788a7d ]]
[[ "$(git -C "$source_dir" rev-parse HEAD:Cargo.lock)" == "$(git -C "$source_dir" rev-parse 32bfd3da:Cargo.lock)" ]]
while read -r file; do
  case "$file" in
    client_prover/psy_prover/src/local/native/faucet.rs|client_prover/psy_prover/src/local/native/faucet_tasks.rs|client_prover/psy_prover/src/local/native/mod.rs) ;;
    *) echo "Unexpected runtime change: $file" >&2; exit 1 ;;
  esac
done < <(git -C "$source_dir" diff --name-only 32bfd3da HEAD)
mkdir -p "$out"
args=(run --rm --network none --user "$(id -u):$(id -g)"
  -e PATH=/usr/local/cargo/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  -e RUSTUP_HOME=/usr/local/rustup -e RUSTUP_TOOLCHAIN=nightly-2025-09-20
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/out/target
  -e HOME=/out -e GOPATH=/out/go -e GOCACHE=/out/go-build
  -e GOMODCACHE=/go-mod -e GOPROXY=off -e GOSUMDB=off
  -e CARGO_BUILD_JOBS="${BUILD_JOBS:-24}" -e CARGO_INCREMENTAL=0
  -e PSY_NETWORK=localhost -e PSY_CONFIG_PATH=/src/psy-genesis/config.json
  -v "$source_dir:/src:ro" -v "$workspace/.cargo-bookworm:/cargo"
  -v "$HOME/go/pkg/mod:/go-mod:ro" -v "$out:/out" -w /src "$image")
docker "${args[@]}" cargo test --offline --locked --release -p psy_prover --features gnark-wrap --lib local::native::faucet_tasks::tests \
  2>&1 | tee "$out/tests.log"
docker "${args[@]}" cargo build --offline --locked --release -p psy_user_cli --bin psy_user_cli \
  2>&1 | tee "$out/build.log"
install -m 0755 "$out/target/release/psy_user_cli" "$out/psy_user_cli"
glibc="$(objdump -T "$out/psy_user_cli" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)"
[[ "$(printf '%s\n' GLIBC_2.36 "$glibc" | sort -V | tail -1)" == GLIBC_2.36 ]]
sha="$(sha256sum "$out/psy_user_cli" | cut -d ' ' -f1)"
jq -n --arg commit "$revision" --arg sha "$sha" --arg image "$image" --arg glibc "$glibc" \
  '{source_commit:$commit,base_commit:"32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6",
    binary_sha256:$sha,builder_image:$image,max_glibc:$glibc,psy_network:"localhost",
    magic:"0x1337CF514544CF69",service:"parth-faucet-server.service",target_cpu:"portable-default"}' > "$out/manifest.json"
printf '%s  psy_user_cli\n' "$sha" > "$out/SHA256SUMS"
