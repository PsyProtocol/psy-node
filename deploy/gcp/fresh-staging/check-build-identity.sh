#!/usr/bin/env bash
# Gate 1 collector: after a deploy, before traffic, confirm every process on
# every host reports the same chain identity.
#
# Each process logs exactly one line on successful config load (psy_config's
# verify_chain_identity, client_prover/psy_core/psy_config/src/lib.rs):
#
#   psy build identity: stage=<localhost|testnet|mainnet> magic=<0x...> config_network=<network>
#
# `stage` is the network name compiled into the binary (PSY_NETWORK at build
# time) and `config_network` is the network block the runtime config selected
# (PsyConfig::default_network). These legitimately differ: localhost and
# testnet share one magic, so a single localhost-staged build can serve a
# testnet config unmodified. The pass/fail decision below is therefore made
# on `magic` alone; `stage` and `config_network` are printed for a human to
# eyeball, never compared.
#
# A host/unit that never printed the line at all (MISSING) is treated the
# same as a hard failure, not skipped -- after a deploy, silence is the
# failure mode that matters most: a process that never reached
# verify_chain_identity (crashed first, hung on an earlier step, wrong
# binary entirely) would otherwise pass by never being checked. This also
# means an unreachable host (bad SSH, VM not up) reports as MISSING for
# every unit on it, on purpose: "can't confirm" and "didn't say" both block
# a deploy the same way.
set -euo pipefail

# stage -> magic, client_prover/psy_core/psy_config/src/stage_magic.rs is the
# source of truth. localhost and testnet intentionally share one magic;
# mainnet's is different on purpose (see that file's comment on why).
#   localhost = 0x1337CF514544CF69
#   testnet   = 0x1337CF514544CF69
#   mainnet   = 0x1337CF514544C069
expected_magic="${EXPECTED_MAGIC:-0x1337CF514544CF69}"
hosts="${IDENTITY_HOSTS:?set IDENTITY_HOSTS to the space-separated VM list, e.g. IDENTITY_HOSTS=\"gcp-cp-ce gcp-prove-proxy\"}"
units="${IDENTITY_UNITS:-psy-coordinator psy-realm0 psy-realm1 psy-worker psy-prove-proxy psy-system-prove-proxy psy-faucet psy-relayer}"
since="${IDENTITY_SINCE:--2h}"
zone_flag=()
if [ -n "${IDENTITY_ZONE:-}" ]; then
  zone_flag=(--zone="$IDENTITY_ZONE")
fi

# Normalize a hex string for comparison: strip an optional 0x/0X prefix,
# lowercase what's left. Both the log line and $EXPECTED_MAGIC are trusted to
# already be hex, so no further validation is done here -- a malformed value
# on either side just fails to match, which is caught below either way.
normalize_hex() {
  local value="$1"
  value="${value#0x}"
  value="${value#0X}"
  printf '%s' "${value,,}"
}

expected_magic_norm="$(normalize_hex "$expected_magic")"

ok_count=0
missing_count=0
mismatch_count=0

for host in $hosts; do
  for unit in $units; do
    line="$(gcloud compute ssh "$host" "${zone_flag[@]}" \
      --command "journalctl -u $unit --since '$since' | grep -m1 'psy build identity'" \
      2>/dev/null || true)"

    if [ -z "$line" ]; then
      echo "MISSING  $host/$unit"
      missing_count=$((missing_count + 1))
      continue
    fi

    # Pull the magic field out of:
    #   psy build identity: stage=X magic=0x... config_network=Y
    # rather than string-matching the whole line, so a harmless difference in
    # stage/config_network never gets misreported as a magic mismatch.
    line_magic="$(printf '%s\n' "$line" | grep -oE 'magic=(0[xX])?[0-9A-Fa-f]+' | head -1 | cut -d= -f2)"
    line_magic_norm="$(normalize_hex "$line_magic")"

    if [ -n "$line_magic_norm" ] && [ "$line_magic_norm" = "$expected_magic_norm" ]; then
      echo "ok       $host/$unit: $line"
      ok_count=$((ok_count + 1))
    else
      echo "MISMATCH $host/$unit: $line"
      mismatch_count=$((mismatch_count + 1))
    fi
  done
done

echo
echo "summary: ok=$ok_count missing=$missing_count mismatch=$mismatch_count (expected magic $expected_magic)"

if [ "$missing_count" -gt 0 ] || [ "$mismatch_count" -gt 0 ]; then
  exit 1
fi
exit 0
