# Appended after the generated KVM/hostname/lab-marker guard.
[[ $# == 1 && $1 == --initialize-empty-virtual-disk ]] || { echo 'Explicit empty lab virtual disk initialization flag required' >&2; exit 1; }
disk=/dev/disk/by-id/virtio-psy-lab-data
[[ -b $disk && $(readlink -f "$disk") == /dev/vdb ]] || exit 1
[[ ! -e /srv/psy-lab ]] || { echo 'Existing data directory; inspect before proceeding' >&2; exit 1; }
[[ $(lsblk -n -o TYPE "$disk" | wc -l) == 1 ]] || { echo 'Partitions present; refusing to format' >&2; exit 1; }
[[ -z $(lsblk -n -o MOUNTPOINTS "$disk") ]] || exit 1
[[ -z $(wipefs --no-act --noheadings "$disk") ]] || { echo 'Filesystem signatures present; refusing to format' >&2; exit 1; }
mkfs.ext4 -L psy-lab-data "$disk"
install -d -m 755 /srv/psy-lab
uuid=$(blkid -s UUID -o value "$disk")
printf 'UUID=%s /srv/psy-lab ext4 defaults 0 2\n' "$uuid" >> /etc/fstab
mount /srv/psy-lab
for directory in k3s prometheus alertmanager grafana; do
  install -d -m 755 "/srv/psy-lab/$directory"
done
echo 'Initialized only the new work-x4 virtual data disk'
