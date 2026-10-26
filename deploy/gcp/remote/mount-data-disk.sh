#!/usr/bin/env bash
set -euo pipefail

: "${DATA_DISK_DEVICE:=}"
: "${DATA_DISK_MOUNTPOINT:=/var/lib/parth}"

if [ -z "$DATA_DISK_DEVICE" ]; then
  echo "[mount-data-disk] DATA_DISK_DEVICE is empty; skipping"
  exit 0
fi

if [ ! -e "$DATA_DISK_DEVICE" ]; then
  echo "[mount-data-disk] data disk not found at ${DATA_DISK_DEVICE}; skipping"
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive
if ! command -v rsync >/dev/null 2>&1 || ! command -v blkid >/dev/null 2>&1 || ! command -v mkfs.ext4 >/dev/null 2>&1; then
  apt-get update
  apt-get install -y e2fsprogs rsync util-linux
fi

install -d -m 0755 "$DATA_DISK_MOUNTPOINT"

if mountpoint -q "$DATA_DISK_MOUNTPOINT"; then
  echo "[mount-data-disk] already mounted: ${DATA_DISK_MOUNTPOINT}"
  exit 0
fi

fs_type="$(blkid -o value -s TYPE "$DATA_DISK_DEVICE" 2>/dev/null || true)"
if [ -z "$fs_type" ]; then
  mkfs.ext4 -F "$DATA_DISK_DEVICE"
fi

uuid="$(blkid -o value -s UUID "$DATA_DISK_DEVICE")"
tmp_mount="/mnt/parth-data-disk"
marker=".parth-data-disk-initialized"

install -d -m 0755 "$tmp_mount"
if ! mountpoint -q "$tmp_mount"; then
  mount "$DATA_DISK_DEVICE" "$tmp_mount"
fi

if [ ! -e "$tmp_mount/$marker" ]; then
  rsync -aHAX --numeric-ids "${DATA_DISK_MOUNTPOINT}/" "${tmp_mount}/" 2>/dev/null || \
    rsync -a "${DATA_DISK_MOUNTPOINT}/" "${tmp_mount}/"
  touch "$tmp_mount/$marker"
fi

umount "$tmp_mount"

fstab_line="UUID=${uuid} ${DATA_DISK_MOUNTPOINT} ext4 defaults,nofail 0 2"
tmp_fstab="$(mktemp)"
cp /etc/fstab "/etc/fstab.parth-data-disk.$(date -u +%Y%m%d%H%M%S).bak"
awk -v mountpoint="$DATA_DISK_MOUNTPOINT" -v line="$fstab_line" '
  $2 == mountpoint {
    if (!done) {
      print line
      done = 1
    }
    next
  }
  { print }
  END {
    if (!done) {
      print line
    }
  }
' /etc/fstab > "$tmp_fstab"
cat "$tmp_fstab" >/etc/fstab
rm -f "$tmp_fstab"

mount "$DATA_DISK_MOUNTPOINT"
echo "[mount-data-disk] mounted ${DATA_DISK_DEVICE} at ${DATA_DISK_MOUNTPOINT}"
