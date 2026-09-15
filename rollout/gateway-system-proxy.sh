#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0
name=parth-offsite-system-prove-ingress
case "${1:-verify}" in
  deploy)
    ip -4 addr show | grep -F '10.148.0.32/' >/dev/null
    systemctl is-active --quiet wg-quick@wg0.service
    test -x /lib/systemd/systemd-socket-proxyd
    if [ -e "/etc/systemd/system/$name.socket" ]; then
      grep -Fxq 'ListenStream=10.148.0.32:19998' "/etc/systemd/system/$name.socket"
      grep -Fxq 'ExecStart=/lib/systemd/systemd-socket-proxyd 10.250.0.12:9998' "/etc/systemd/system/$name.service"
      echo 'Dedicated system forwarding already installed'; exit
    fi
    test ! -e "/etc/systemd/system/$name.service"
    if ss -ltnH | awk '{print $4}' | grep -Eq ':19998$'; then
      echo '19998 already in use' >&2; exit 1
    fi
    cat >"/etc/systemd/system/$name.socket" <<'EOF'
[Unit]
Description=Private system proof ingress for relayer

[Socket]
ListenStream=10.148.0.32:19998
NoDelay=true
IPAddressDeny=any
IPAddressAllow=10.148.0.33/32
IPAddressAllow=10.148.0.32/32

[Install]
WantedBy=sockets.target
EOF
    cat >"/etc/systemd/system/$name.service" <<'EOF'
[Unit]
Description=Forward system proofs through WireGuard
Requires=parth-offsite-system-prove-ingress.socket
After=network-online.target wg-quick@wg0.service

[Service]
ExecStart=/lib/systemd/systemd-socket-proxyd 10.250.0.12:9998
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
EOF
    chmod 0644 "/etc/systemd/system/$name.socket" "/etc/systemd/system/$name.service"
    systemd-analyze verify "/etc/systemd/system/$name.socket" "/etc/systemd/system/$name.service"
    systemctl daemon-reload
    systemctl enable --now "$name.socket"
    systemctl is-active "$name.socket"
    echo 'Added only system :19998 -> :9998. Existing user forwarding and WireGuard unchanged.'
    ;;
  verify)
    curl -fsS --max-time 10 http://10.148.0.32:19998 -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_prove_proxy_role","params":[]}' |
      jq -e '.error == null and .result.role == "system" and .result.system_methods == true and .result.user_methods == false'
    ;;
  rollback)
    systemctl disable --now "$name.socket"
    systemctl stop "$name.service"
    ;;
  *) echo 'Usage: deploy|verify|rollback'; exit 2 ;;
esac
