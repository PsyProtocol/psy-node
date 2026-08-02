#!/usr/bin/env bash
# Publish a psy-node GitHub Release with immutability guarantees.
#
# Published semver assets are immutable: a non-draft release for the tag is
# never mutated. Only an owned draft (created by this workflow) may be resumed.
# Publication is finalized only after the exact five-asset inventory and the
# SHA256SUMS checksums are verified against the assets actually uploaded.
#
# Inputs (env):
#   RELEASE_TAG        required, vX.Y.Z
#   GITHUB_REPOSITORY  required, owner/repo passed to gh
#   GH_TOKEN           required by gh for auth (set by the workflow)
#   DIST_DIR           payload dir holding the 5 assets (default: dist)
#   WORKFLOW_OWNER     sentinel marker stamped into draft notes (default:
#                      psy-node-release-workflow)
#   STAGE_DIR          scratch dir for temp files (default: RUNNER_TEMP or /tmp)
#   GH                 gh binary (default: gh)
#   JQ                 jq binary (default: jq)
set -euo pipefail

: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${DIST_DIR:=dist}"
: "${WORKFLOW_OWNER:=psy-node-release-workflow}"
: "${STAGE_DIR:=${RUNNER_TEMP:-/tmp}}"
mkdir -p "$STAGE_DIR"
GH="${GH:-gh}"
JQ="${JQ:-jq}"
SENTINEL="<!-- ${WORKFLOW_OWNER} -->"

cd "$DIST_DIR"

# Pre-publish gate: exact five assets and valid checksums.
shopt -s nullglob
assets=(psy-node-"${RELEASE_TAG}"-*.tar.gz SHA256SUMS)
if [[ "${#assets[@]}" -ne 5 ]]; then
  echo "release payload must contain four archives and SHA256SUMS, found ${#assets[@]}" >&2
  exit 1
fi
sha256sum --check SHA256SUMS

release_json="${STAGE_DIR}/release-${RELEASE_TAG}.json"
if "$GH" release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" \
      --json isDraft,body > "$release_json" 2>/dev/null; then
  is_draft="$("$JQ" -r .isDraft "$release_json")"
  if [[ "$is_draft" != "true" ]]; then
    echo "error: release ${RELEASE_TAG} already exists and is published; semver assets are immutable" >&2
    exit 1
  fi
  body="$("$JQ" -r .body "$release_json")"
  if ! grep -qF "$SENTINEL" <<<"$body"; then
    echo "error: existing draft release ${RELEASE_TAG} is not owned by this workflow; refusing to mutate" >&2
    exit 1
  fi
  echo "resuming owned draft ${RELEASE_TAG}"
else
  "$GH" release create "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" \
    --verify-tag --draft --title "psy-node ${RELEASE_TAG}" --generate-notes
  existing_body="$("$GH" release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" \
    --json body -q .body)"
  "$GH" release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" \
    --notes "${SENTINEL}

${existing_body}"
fi

# Safe to clobber: at this point the release is always a draft (freshly created
# or a verified owned draft), so no published asset is ever replaced.
"$GH" release upload "$RELEASE_TAG" "${assets[@]}" --clobber --repo "$GITHUB_REPOSITORY"

# Post-upload verification before finalizing publication.
verify_dir="$(mktemp -d)"
trap 'rm -rf "$verify_dir"' EXIT
"$GH" release download "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" \
  --dir "$verify_dir" --clobber
(
  cd "$verify_dir"
  printf '%s\n' "${assets[@]}" | LC_ALL=C sort > "${STAGE_DIR}/expected-release-assets"
  printf '%s\n' * | LC_ALL=C sort > "${STAGE_DIR}/actual-release-assets"
  diff -u "${STAGE_DIR}/expected-release-assets" "${STAGE_DIR}/actual-release-assets"
  sha256sum --check SHA256SUMS
)

"$GH" release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --draft=false
echo "published ${RELEASE_TAG}"