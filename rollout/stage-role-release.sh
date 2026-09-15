#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ssh_config=${SSH_CONFIG:-$HOME/.ssh/config}
kind=${1:?proxy or relayer}
case "$kind" in
  proxy) host=${HOST:-arc99x3}; dir=out-arch; script=remote-proxy.sh ;;
  relayer) host=${HOST:-gcp-faucet}; dir=out; script=remote-relayer.sh ;;
  *) exit 2 ;;
esac
(cd "$HERE/$dir" && sha256sum -c SHA256SUMS)
ssh -F "$ssh_config" "$host" 'install -d -m 0700 ~/prove-proxy-role-3a81f59e'
rsync -a -e "ssh -F $ssh_config" "$HERE/$dir" "$HERE/$script" "$host:prove-proxy-role-3a81f59e/"
ssh -F "$ssh_config" "$host" "cd ~/prove-proxy-role-3a81f59e/$dir && sha256sum -c SHA256SUMS"
echo "Staged only, no service changed: $host:~/prove-proxy-role-3a81f59e/$script"
