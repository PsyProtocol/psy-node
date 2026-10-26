# Local Prove Proxy Tunnel

This mode keeps the public endpoint unchanged:

```text
Browser -> Cloudflare -> Caddy on gcp-nostr -> 10.148.0.26:9999 -> SSH reverse tunnel -> local prove-proxy
```

The local machine does not need a public IP. It only needs SSH access to
`gcp-prove-proxy`.

## Install

```bash
cd "$WORKSPACE_HOME/psy-node-deploy-unified"

bash deploy/local-prove-proxy/deploy_all.sh
```

## Start

```bash
systemctl --user start parth-local-prove-proxy.service
systemctl --user start parth-local-prove-proxy-tunnel.service
systemctl --user start parth-local-prove-proxy-tunnel-monitor.timer
```

## Logs

```bash
journalctl --user -u parth-local-prove-proxy.service -f
journalctl --user -u parth-local-prove-proxy-tunnel.service -f
```

## Status

```bash
bash deploy/local-prove-proxy/status-systemd-user-services.sh
curl -i https://prove-stg.psy-protocol.xyz/ \
  -H 'Origin: https://app-stg.psy-protocol.xyz' \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_circuits_data","params":[]}'
```

## Notes

- The cloud `parth-prove-proxy@0.service` is stopped and disabled by
  `configure-remote-tunnel-target.sh` so port `10.148.0.26:9999` can be owned
  by SSH reverse forwarding.
- The tunnel service restarts automatically when SSH exits.
- The monitor timer checks both local `127.0.0.1:9999` and remote
  `10.148.0.26:9999`, and restarts the tunnel if the remote port is not
  reachable.
- Full fresh staging deployment can include this as step 24:

```bash
CONFIRM_FULL_FRESH_DEPLOY=1 USE_LOCAL_PROVE_PROXY=1 \
  bash deploy/gcp/fresh-staging/deploy_all.sh
```
