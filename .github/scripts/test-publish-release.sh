#!/usr/bin/env bash
# Shell-level unit simulation for .github/scripts/publish-release.sh.
#
# Stubs `gh` against an on-disk release store and asserts the immutability
# contract: published releases are never mutated, only owned drafts resume,
# and publication finalizes only after exact inventory + checksum verification.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PUBLISH="${ROOT}/publish-release.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STORE="${WORK}/store"
BIN="${WORK}/bin"
mkdir -p "$STORE" "$BIN"

PASS=0
FAIL=0
assert_eq() {
  local name="$1" exp="$2" got="$3"
  if [[ "$exp" == "$got" ]]; then
    PASS=$((PASS + 1))
    printf '  ok   %s\n' "$name"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL %s\n      expected: %s\n      got:      %s\n' "$name" "$exp" "$got" >&2
  fi
}
assert_file() {
  local name="$1" path="$2"
  if [[ -f "$path" ]]; then
    PASS=$((PASS + 1))
    printf '  ok   %s\n' "$name"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL %s: missing %s\n' "$name" "$path" >&2
  fi
}
assert_no_file() {
  local name="$1" path="$2"
  if [[ -e "$path" ]]; then
    FAIL=$((FAIL + 1))
    printf '  FAIL %s: unexpected %s exists\n' "$name" "$path" >&2
  else
    PASS=$((PASS + 1))
    printf '  ok   %s\n' "$name"
  fi
}

# gh stub: an on-disk release store keyed by tag.
# Assets are copied verbatim; optional corruption via GH_STUB_CORRUPT=name.
cat > "${BIN}/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
STORE="${GH_STUB_STORE:?}"
CORRUPT="${GH_STUB_CORRUPT:-}"
[[ "${1:-}" == "release" ]] || { echo "gh stub: only 'release' supported" >&2; exit 2; }
sub="$2"; shift 2
# Collect --opt value pairs and positionals.
pos=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo|--dir|--title|--json|--notes) pos+=("_OPT_:$1" "$2"); shift 2 ;;
    -q) pos+=("_OPT_:-q" "$2"); shift 2 ;;
    --verify-tag|--draft|--generate-notes|--clobber) pos+=("_FLAG_:$1"); shift ;;
    --draft=*) pos+=("_OPT_:--draft" "${1#--draft=}"); shift ;;
    *) pos+=("$1"); shift ;;
  esac
done
positionals=()
declare -A optv
i=0
while [[ $i -lt ${#pos[@]} ]]; do
  v="${pos[$i]}"
  case "$v" in
    _OPT_:*) optv["${v#_OPT_:}"]="${pos[$((i+1))]}"; i=$((i+2)) ;;
    _FLAG_:*) optv["${v#_FLAG_:}"]=1; i=$((i+1)) ;;
    *) positionals+=("$v"); i=$((i+1)) ;;
  esac
done

tag="${positionals[0]:-}"
meta="$STORE/$tag/meta.json"
case "$sub" in
  view)
    [[ -f "$meta" ]] || { echo "release $tag not found" >&2; exit 1; }
    isDraft="$(jq -r .isDraft "$meta")"
    body="$(jq -r .body "$meta")"
    if [[ -n "${optv[-q]:-}" ]]; then
      case "${optv[-q]}" in
        .body) printf '%s' "$body" ;;
        .isDraft) printf '%s' "$isDraft" ;;
      esac
    else
      printf '{"isDraft":%s,"body":%s}\n' "$isDraft" "$(jq -Rs . <<<"$body")"
    fi
    ;;
  create)
    mkdir -p "$STORE/$tag/assets"
    printf '{"isDraft":%s,"title":"%s","body":""}\n' \
      "${optv[--draft]:+true}" "${optv[--title]:-}" > "$meta"
    ;;
  edit)
    tmp="$(mktemp)"
    if [[ -n "${optv[--notes]:-}" ]]; then
      jq --arg b "${optv[--notes]}" '.body=$b' "$meta" > "$tmp" && mv "$tmp" "$meta"
    fi
    if [[ -n "${optv[--draft]:-}" ]]; then
      jq --arg d "${optv[--draft]}" '.isDraft=($d=="true")' "$meta" > "$tmp" && mv "$tmp" "$meta"
    fi
    ;;
  upload)
    mkdir -p "$STORE/$tag/assets"
    for f in "${positionals[@]:1}"; do cp -f "$f" "$STORE/$tag/assets/"; done
    ;;
  download)
    dir="${optv[--dir]:-}"
    mkdir -p "$dir"
    cp -f "$STORE/$tag/assets/"* "$dir/"
    if [[ -n "$CORRUPT" ]]; then
      echo "corrupted" >> "$dir/$CORRUPT"
    fi
    ;;
  *) echo "gh stub: unknown release subcommand $sub" >&2; exit 2 ;;
esac
STUB
chmod +x "${BIN}/gh"

export GH_STUB_STORE="$STORE"
export GH="${BIN}/gh"
JQ="$(command -v jq)"
export JQ
export GITHUB_REPOSITORY="test/repo"

mk_payload() {
  local dir="$1" tag="$2" count="${3:-5}"
  mkdir -p "$dir"
  rm -f "$dir"/*
  local triples=(aarch64-apple-darwin aarch64-unknown-linux-gnu x86_64-apple-darwin x86_64-unknown-linux-gnu)
  local sumfile="$dir/SHA256SUMS"
  : > "$sumfile"
  local i=0
  for t in "${triples[@]}"; do
    if [[ $i -ge $((count - 1)) ]]; then break; fi
    local f="psy-node-${tag}-${t}.tar.gz"
    printf 'payload for %s\n' "$t" > "$dir/$f"
    ( cd "$dir" && sha256sum "$f" ) >> "$sumfile"
    i=$((i+1))
  done
}

mk_full_payload() {
  local dir="$1" tag="$2"
  mk_payload "$dir" "$tag" 5
}

run_publish() {
  DIST_DIR="$1" RELEASE_TAG="$2" STAGE_DIR="${WORK}/stage" \
    bash "$PUBLISH"
}

reset_store() { rm -rf "$STORE"; mkdir -p "$STORE"; }

echo "scenario: fresh publish (no existing release)"
reset_store
dist="${WORK}/d-fresh"; mk_full_payload "$dist" "v1.2.3"
out="$(run_publish "$dist" "v1.2.3" 2>&1)" || { echo "  FAIL fresh publish exited non-zero: $out" >&2; FAIL=$((FAIL+1)); }
echo "$out" | sed 's/^/    /'
assert_file "fresh: draft meta created" "$STORE/v1.2.3/meta.json"
assert_eq "fresh: published (isDraft=false)" "false" "$(jq -r .isDraft "$STORE/v1.2.3/meta.json")"
assert_file "fresh: 5 assets uploaded" "$STORE/v1.2.3/assets/SHA256SUMS"
assert_eq "fresh: sentinel stamped" "1" "$(grep -c 'psy-node-release-workflow' "$STORE/v1.2.3/meta.json")"

echo "scenario: existing published release -> fail (immutability)"
reset_store
mkdir -p "$STORE/v2.0.0/assets"
printf '{"isDraft":false,"body":"manual"}\n' > "$STORE/v2.0.0/meta.json"
dist="${WORK}/d-pub"; mk_full_payload "$dist" "v2.0.0"
if run_publish "$dist" "v2.0.0" >/dev/null 2>&1; then
  echo "  FAIL immutability: published release was mutated" >&2
  FAIL=$((FAIL+1))
fi
assert_no_file "immutability: no assets uploaded" "$STORE/v2.0.0/assets/SHA256SUMS"
assert_eq "immutability: still published" "false" "$(jq -r .isDraft "$STORE/v2.0.0/meta.json")"

echo "scenario: existing non-owned draft -> fail"
reset_store
mkdir -p "$STORE/v3.0.0/assets"
printf '{"isDraft":true,"body":"someone elses draft"}\n' > "$STORE/v3.0.0/meta.json"
dist="${WORK}/d-foreign"; mk_full_payload "$dist" "v3.0.0"
if run_publish "$dist" "v3.0.0" >/dev/null 2>&1; then
  echo "  FAIL foreign: non-owned draft was mutated" >&2
  FAIL=$((FAIL+1))
fi
assert_no_file "foreign: no assets uploaded" "$STORE/v3.0.0/assets/SHA256SUMS"

echo "scenario: existing owned draft -> resume and publish"
reset_store
mkdir -p "$STORE/v4.0.0/assets"
printf '{"isDraft":true,"body":"<!-- psy-node-release-workflow -->\n\nprior notes"}\n' > "$STORE/v4.0.0/meta.json"
dist="${WORK}/d-owned"; mk_full_payload "$dist" "v4.0.0"
if out="$(run_publish "$dist" "v4.0.0" 2>&1)"; then
  PASS=$((PASS+1)); echo "  ok   owned draft resumed and published"
else
  echo "  FAIL owned: resume failed: $out" >&2; FAIL=$((FAIL+1))
fi
assert_eq "owned: published (isDraft=false)" "false" "$(jq -r .isDraft "$STORE/v4.0.0/meta.json")"
assert_file "owned: assets uploaded" "$STORE/v4.0.0/assets/SHA256SUMS"

echo "scenario: payload missing an asset -> fail before any gh call"
reset_store
dist="${WORK}/d-short"; mk_payload "$dist" "v5.0.0" 4
if run_publish "$dist" "v5.0.0" >/dev/null 2>&1; then
  echo "  FAIL short: incomplete payload was published" >&2
  FAIL=$((FAIL+1))
fi
assert_no_file "short: no release created" "$STORE/v5.0.0/meta.json"

echo "scenario: post-upload checksum mismatch -> refuse to finalize"
reset_store
dist="${WORK}/d-corrupt"; mk_full_payload "$dist" "v6.0.0"
# Corrupt one archive after payload creation but the stub corrupts on download.
bad="psy-node-v6.0.0-aarch64-apple-darwin.tar.gz"
GH_STUB_CORRUPT="$bad" run_publish "$dist" "v6.0.0" >/dev/null 2>&1 \
  && { echo "  FAIL corrupt asset published" >&2; FAIL=$((FAIL+1)); } \
  || { PASS=$((PASS+1)); echo "  ok   corrupt asset refused finalization"; }
assert_eq "corrupt: left as draft" "true" "$(jq -r .isDraft "$STORE/v6.0.0/meta.json" 2>/dev/null || echo missing)"

echo
echo "PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]