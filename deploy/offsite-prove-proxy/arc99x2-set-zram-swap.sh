#!/usr/bin/env bash
set -euo pipefail

TARGET_SIZE_GIB="${TARGET_SIZE_GIB:-15}"
CONFIG_DIR="/etc/systemd/zram-generator.conf.d"
CONFIG_PATH="$CONFIG_DIR/90-parth-prove-proxy.conf"
ZRAM_DEVICE="/dev/zram0"
ZRAM_SWAP_UNIT="dev-zram0.swap"
ZRAM_SETUP_UNIT="systemd-zram-setup@zram0.service"

if [[ "$EUID" -ne 0 ]]; then
  exec sudo --preserve-env=TARGET_SIZE_GIB bash "$0" "$@"
fi

if ! [[ "$TARGET_SIZE_GIB" =~ ^[1-9][0-9]*$ ]] || (( TARGET_SIZE_GIB > 48 )); then
  echo "TARGET_SIZE_GIB must be an integer between 1 and 48" >&2
  exit 1
fi

for command in awk free grep install mktemp swapon swapoff systemctl zramctl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing executable: $command" >&2
    exit 1
  fi
done

if ! systemctl cat "$ZRAM_SETUP_UNIT" >/dev/null 2>&1; then
  echo "zram-generator is not installed or $ZRAM_SETUP_UNIT is unavailable" >&2
  exit 1
fi

swap_used_kib="$(awk -v device="$ZRAM_DEVICE" '$1 == device { print $4; found=1 } END { if (!found) print 0 }' /proc/swaps)"
mem_available_kib="$(awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo)"
reserve_kib=$((2 * 1024 * 1024))

if (( swap_used_kib + reserve_kib > mem_available_kib )); then
  echo "not enough available RAM to swapoff $ZRAM_DEVICE safely" >&2
  echo "swap_used_kib=$swap_used_kib mem_available_kib=$mem_available_kib reserve_kib=$reserve_kib" >&2
  exit 1
fi

install -d -m 0755 "$CONFIG_DIR"
backup_path=""
if [[ -e "$CONFIG_PATH" ]]; then
  backup_path="${CONFIG_PATH}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a "$CONFIG_PATH" "$backup_path"
fi

restore_config() {
  if [[ -n "$backup_path" && -e "$backup_path" ]]; then
    cp -a "$backup_path" "$CONFIG_PATH"
  else
    rm -f "$CONFIG_PATH"
  fi
}

start_zram() {
  systemctl daemon-reload
  systemctl start "$ZRAM_SWAP_UNIT"
}

rollback() {
  local exit_code=$?
  trap - ERR
  echo "zram resize failed; restoring the previous configuration" >&2
  restore_config
  systemctl stop "$ZRAM_SWAP_UNIT" "$ZRAM_SETUP_UNIT" >/dev/null 2>&1 || true
  start_zram >/dev/null 2>&1 || true
  exit "$exit_code"
}
trap rollback ERR

temp_config="$(mktemp "$CONFIG_DIR/.90-parth-prove-proxy.conf.XXXXXX")"
printf '[zram0]\nzram-size = %s\ncompression-algorithm = zstd\n' \
  "$((TARGET_SIZE_GIB * 1024))" >"$temp_config"
chmod 0644 "$temp_config"
mv -f "$temp_config" "$CONFIG_PATH"

# Recreate the generated swap unit so the new disk size takes effect now.
swapoff "$ZRAM_DEVICE" 2>/dev/null || true
systemctl stop "$ZRAM_SWAP_UNIT" "$ZRAM_SETUP_UNIT"
start_zram

expected_bytes=$((TARGET_SIZE_GIB * 1024 * 1024 * 1024))
actual_bytes="$(cat /sys/block/zram0/disksize)"
if [[ "$actual_bytes" -ne "$expected_bytes" ]]; then
  echo "unexpected zram size: expected=$expected_bytes actual=$actual_bytes" >&2
  false
fi
if ! awk -v device="$ZRAM_DEVICE" '$1 == device { found=1 } END { exit !found }' /proc/swaps; then
  echo "$ZRAM_DEVICE is not active as swap" >&2
  false
fi

trap - ERR

echo "zram swap resized successfully"
echo "config: $CONFIG_PATH"
zramctl "$ZRAM_DEVICE"
swapon --show
free -h
