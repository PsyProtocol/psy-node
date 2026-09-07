#!/usr/bin/env bash
set -euo pipefail

: "${PSY_SERVICES_RELEASE_ARCHIVE:=/tmp/psy-services-release.tar.gz}"
: "${PSY_SERVICES_RELEASE_ROOT:=/opt/parth/psy-services}"
: "${PSY_SERVICES_LEGACY_HOME:=}"
: "${PSY_SERVICES_RELEASE_SHA256:?PSY_SERVICES_RELEASE_SHA256 is required}"
: "${EXPECTED_PSY_SERVICES_REPOSITORY:?EXPECTED_PSY_SERVICES_REPOSITORY is required}"
: "${EXPECTED_PSY_SERVICES_COMMIT:?EXPECTED_PSY_SERVICES_COMMIT is required}"
: "${PSY_SERVICES_KEEP_RELEASES:=3}"

fail() {
  echo "[install-psy-services-release] $*" >&2
  exit 1
}

[ -f "$PSY_SERVICES_RELEASE_ARCHIVE" ] || fail "missing archive: $PSY_SERVICES_RELEASE_ARCHIVE"
actual_archive_sha="$(sha256sum "$PSY_SERVICES_RELEASE_ARCHIVE" | awk '{print $1}')"
[ "$actual_archive_sha" = "$PSY_SERVICES_RELEASE_SHA256" ] \
  || fail "archive checksum mismatch: expected $PSY_SERVICES_RELEASE_SHA256, got $actual_archive_sha"

if tar -tzf "$PSY_SERVICES_RELEASE_ARCHIVE" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
  fail "archive contains an unsafe path"
fi

release_id="${EXPECTED_PSY_SERVICES_COMMIT:0:12}-${PSY_SERVICES_RELEASE_SHA256:0:12}"
release="$PSY_SERVICES_RELEASE_ROOT/releases/$release_id"
install -d -m 0755 "$PSY_SERVICES_RELEASE_ROOT/releases"

if [ ! -d "$release" ]; then
  staging="${release}.staging.$$"
  trap 'rm -rf "${staging:-}"' EXIT
  install -d -m 0755 "$staging"
  tar -xzf "$PSY_SERVICES_RELEASE_ARCHIVE" -C "$staging"

  [ -x "$staging/target/release/psy-services" ] || fail "archive is missing psy-services"
  [ -x "$staging/target/release/psy-indexer" ] || fail "archive is missing psy-indexer"
  [ -d "$staging/migrations" ] || fail "archive is missing migrations"
  [ -f "$staging/BUILD-MANIFEST.env" ] || fail "archive is missing BUILD-MANIFEST.env"
  grep -Fxq "PSY_SERVICES_REPOSITORY=$EXPECTED_PSY_SERVICES_REPOSITORY" "$staging/BUILD-MANIFEST.env" \
    || fail "manifest repository does not match"
  grep -Fxq "PSY_SERVICES_COMMIT=$EXPECTED_PSY_SERVICES_COMMIT" "$staging/BUILD-MANIFEST.env" \
    || fail "manifest commit does not match"

  printf '%s\n' "$PSY_SERVICES_RELEASE_SHA256" >"$staging/.bundle.sha256"
  if [ "$(id -u)" = "0" ] && id parth >/dev/null 2>&1; then
    chown -R parth:parth "$staging"
  fi
  mv "$staging" "$release"
fi

[ -x "$release/target/release/psy-services" ] || fail "installed release is missing psy-services"
[ -x "$release/target/release/psy-indexer" ] || fail "installed release is missing psy-indexer"
[ -f "$release/BUILD-MANIFEST.env" ] || fail "installed release is missing BUILD-MANIFEST.env"
grep -Fxq "PSY_SERVICES_REPOSITORY=$EXPECTED_PSY_SERVICES_REPOSITORY" "$release/BUILD-MANIFEST.env" \
  || fail "installed release repository does not match"
grep -Fxq "PSY_SERVICES_COMMIT=$EXPECTED_PSY_SERVICES_COMMIT" "$release/BUILD-MANIFEST.env" \
  || fail "installed release commit does not match"

current=""
if [ -L "$PSY_SERVICES_RELEASE_ROOT/current" ]; then
  current="$(readlink -f "$PSY_SERVICES_RELEASE_ROOT/current")"
fi
if [ -z "$current" ] && [ -n "$PSY_SERVICES_LEGACY_HOME" ]; then
  legacy="$(readlink -f "$PSY_SERVICES_LEGACY_HOME" 2>/dev/null || true)"
  [ -x "$legacy/target/release/psy-services" ] \
    || fail "legacy release is missing psy-services: $PSY_SERVICES_LEGACY_HOME"
  [ -x "$legacy/target/release/psy-indexer" ] \
    || fail "legacy release is missing psy-indexer: $PSY_SERVICES_LEGACY_HOME"
  previous_next="$PSY_SERVICES_RELEASE_ROOT/previous.next.$$"
  ln -s "$legacy" "$previous_next"
  mv -Tf "$previous_next" "$PSY_SERVICES_RELEASE_ROOT/previous"
  echo "[install-psy-services-release] registered legacy rollback target=$legacy"
fi
if [ -n "$current" ] && [ "$current" != "$release" ]; then
  previous_next="$PSY_SERVICES_RELEASE_ROOT/previous.next.$$"
  ln -s "$current" "$previous_next"
  mv -Tf "$previous_next" "$PSY_SERVICES_RELEASE_ROOT/previous"
fi
current_next="$PSY_SERVICES_RELEASE_ROOT/current.next.$$"
ln -s "$release" "$current_next"
mv -Tf "$current_next" "$PSY_SERVICES_RELEASE_ROOT/current"

current="$(readlink -f "$PSY_SERVICES_RELEASE_ROOT/current")"
previous=""
if [ -L "$PSY_SERVICES_RELEASE_ROOT/previous" ]; then
  previous="$(readlink -f "$PSY_SERVICES_RELEASE_ROOT/previous")"
fi
kept=0
while IFS= read -r old_release; do
  [ "$old_release" = "$current" ] && continue
  [ -n "$previous" ] && [ "$old_release" = "$previous" ] && continue
  kept=$((kept + 1))
  if [ "$kept" -gt "$PSY_SERVICES_KEEP_RELEASES" ]; then
    rm -rf "$old_release"
  fi
done < <(find "$PSY_SERVICES_RELEASE_ROOT/releases" -mindepth 1 -maxdepth 1 -type d \
  -printf '%T@ %p\n' | sort -nr | cut -d' ' -f2-)

echo "[install-psy-services-release] current=$current"
echo "[install-psy-services-release] previous=${previous:-<none>}"
