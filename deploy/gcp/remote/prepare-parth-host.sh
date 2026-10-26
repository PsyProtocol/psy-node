#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

disable_auto_apt_updates() {
  # Parth services must only restart through explicit deploy or recovery commands.
  # unattended-upgrades + needrestart can otherwise restart critical services
  # while service env files point at old releases.
  systemctl disable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  systemctl mask apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  systemctl disable --now unattended-upgrades.service >/dev/null 2>&1 || true
  systemctl mask unattended-upgrades.service >/dev/null 2>&1 || true

  install -d -m 0755 /etc/apt/apt.conf.d
  cat >/etc/apt/apt.conf.d/99-disable-auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

  install -d -m 0755 /etc/needrestart/conf.d
  cat >/etc/needrestart/conf.d/99-parth-no-auto-restart.conf <<'EOF'
# Do not let needrestart restart Parth services during apt operations.
# Parth services must only be restarted by explicit deploy/recovery commands.
$nrconf{override_rc}->{qr(^parth-)} = 0;
EOF
}

disable_auto_apt_updates
apt-get update
apt-get install -y ca-certificates curl jq rsync tar make
disable_auto_apt_updates

bash /tmp/mount-data-disk.sh

if ! getent group parth >/dev/null 2>&1; then
  groupadd --system parth
fi

if ! id parth >/dev/null 2>&1; then
  useradd --system --gid parth --home-dir /var/lib/parth --create-home --shell /usr/sbin/nologin parth
fi

install -d -m 0755 /opt/parth /opt/parth/releases /var/lib/parth /var/lib/parth/checkpoints /var/lib/parth/indexer-backups
chown -R parth:parth /opt/parth /var/lib/parth
