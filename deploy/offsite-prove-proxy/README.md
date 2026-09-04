# Offsite prove-proxy on arc99x2

This directory moves the CPU and memory-heavy prove-proxy process to
`arc99x2` while preserving every existing public and internal caller URL.

## Topology

```text
wallet / app
  -> existing public domain and Caddy
  -> GCP WireGuard gateway VPC_IP:19999
  -> WireGuard 10.250.0.12:9999 on arc99x2

cloud relayer / internal clients
  -> GCP WireGuard gateway VPC_IP:19999
  -> WireGuard 10.250.0.12:9999 on arc99x2

arc99x2 prove-proxy
  -> 10.250.0.1:11337 -> coordinator 10.148.0.25:1337
  -> 10.250.0.1:11338 -> realm0      10.148.0.25:1338
  -> 10.250.0.1:11339 -> realm1      10.148.0.25:1339
  -> 10.250.0.1:11300 -> psy-services 10.148.0.25:3000
```

The existing `arc99x4` worker peer (`10.250.0.11`) is not modified.
`arc99x2` uses `10.250.0.12`.

The standalone faucet-server and relayer run on their dedicated cloud host.
No faucet operator keys, genesis private keys, relayer keys, or wallet keys
are copied to `arc99x2`. The offsite host receives only:

- `psy_user_cli` and its runtime bundle;
- the bridge, deposit append, and withdrawal claim Groth16 setup files;
- a generated RPC config using WireGuard-only backend relays;
- captured prove request inputs and outputs.

## Capacity

The preflight requires at least 56 GiB visible RAM, 16 logical CPUs, and
30 GiB free disk. The intended host is a 64 GiB `arc99x2`.

The previous 32 GiB GCP host reached roughly 28 GiB resident memory plus
8.6 GiB swap during deposit proof generation. Do not deploy this process to a
32 GiB host without accepting OOM risk.

## Phase 1: stage release and setup

From the deployment worktree:

```bash
bash deploy/offsite-prove-proxy/deploy-arc99x2-release.sh
```

This uploads the bundle and all three setup kinds. It does not use sudo, start
services, or change production traffic.

For a full fresh deployment, `13_deploy_prove_proxy.sh` sets
`OFFSITE_PROVE_PROXY_APPLY_STAGED=1` and performs both staging and the
interactive apply operation. Standalone staging remains available for
maintenance and rollback preparation.

## Phase 2: prepare the arc99x2 WireGuard key

The bootstrap script installs `wireguard-tools`, `jq`, `curl`, and `rsync`,
creates a protected client key, and prints only its public key.

Run on `arc99x2`:

```bash
GATEWAY_PUBLIC_KEY='kBMlwzvRKmP+FiLQ2UBVSsP0tT0fbhZ3YTycrS2SSnY=' \
GATEWAY_ENDPOINT='34.1.130.235:51820' \
bash ~/parth-prove-proxy/deploy/offsite-prove-proxy/arc99x2-bootstrap-wireguard.sh
```

The script requires interactive sudo for package installation. Copy the
printed `arc99x2` public key. Do not copy the private key or generated config
off the host.

## Phase 3: add the peer and relays on the GCP gateway

Copy `gateway-install-arc99x2-relays.sh` to `gcp-gateway`, then run:

```bash
sudo ARC99X2_PUBLIC_KEY='<printed arc99x2 public key>' \
  bash gateway-install-arc99x2-relays.sh
```

The script incrementally appends the new peer to `wg0`, installs backend RPC
socket relays, and prints the gateway VPC forwarder target. It does not rewrite
or restart the existing `arc99x4` peer.

## Phase 4: install and start arc99x2

Use the release ID printed by the stage command:

```bash
RELEASE_ID='<release-id>' \
  bash ~/parth-prove-proxy/deploy/offsite-prove-proxy/arc99x2-apply-staged.sh
```

This interactive-sudo script:

1. activates the protected WireGuard config;
2. verifies the peer handshake and all backend relays;
3. installs the release and Groth16 setup under `/opt/parth` and
   `/var/lib/parth`;
4. starts `parth-offsite-prove-proxy.service`;
5. waits up to five minutes for `psy_get_fn_id(0, "simple_claim")` to return
   method ID `4`.

No public traffic changes during this phase.

Check the host before cutover:

```bash
bash ~/parth-prove-proxy/deploy/offsite-prove-proxy/status-arc99x2.sh
```

The host bootstrap leaves the existing zram swap unchanged. To explicitly
resize `/dev/zram0` to 15 GiB after installation:

```bash
bash ~/parth-prove-proxy/deploy/offsite-prove-proxy/arc99x2-set-zram-swap.sh
```

The script writes a `zram-generator` drop-in, verifies that enough RAM is
available for `swapoff`, recreates the zram device, and restores the previous
configuration if activation fails. Override the size with
`TARGET_SIZE_GIB=<integer>` when needed.

## Phase 5: initial cut over

From the deployment worktree:

```bash
bash deploy/offsite-prove-proxy/cutover-to-arc99x2.sh
```

The cutover validates arc99x2 directly and through the GCP gateway before
stopping the cloud process. It then replaces the cloud process on port 9999
with `systemd-socket-proxyd`, restarts only faucet-server, and validates the
public prove-proxy domain. A failed public health check triggers an immediate
rollback.

All callers continue using the same URL or internal address. DNS, Caddy,
faucet-server configuration, and relayer configuration are unchanged.

This is manual failover, not automatic HA. If the home host or tunnel fails,
run the rollback command.

## Phase 6: retire the cloud prove-proxy VM

Once the offsite process has been validated, callers can bypass the temporary
forwarder on the old cloud prove-proxy VM:

1. set `PUBLIC_PROVE_PROXY_UPSTREAM` to the gateway VPC address and relay port,
   for example `10.148.0.32:19999`;
2. set `CLIENT_PROVE_PROXY_URL` to the matching HTTP URL, for example
   `http://10.148.0.32:19999`;
3. redeploy Caddy entrypoints;
4. update the active relayer bundle config and restart only the relayer;
5. verify public proving and relayer checkpoint progress;
6. disable the old cloud forwarder socket.

After this phase, the old cloud prove-proxy VM is no longer in the request
path and can be stopped. There is no automatic cloud fallback: availability
depends on the GCP WireGuard gateway, the tunnel, and `arc99x2`.

## Roll back

```bash
bash deploy/offsite-prove-proxy/rollback-to-cloud.sh
```

Rollback disables the forwarder, removes the cloud-service suppression
condition, starts the original `parth-prove-proxy@0.service`, waits up to five
minutes for its cold circuit build, restarts faucet-server, and validates the
public RPC.

The arc99x2 process can remain running for diagnosis; it receives no production
traffic after rollback.

## Request captures

The offsite service writes bounded per-method captures to:

```text
/var/lib/parth/prove-captures
```

Defaults:

- 20 captures per method;
- inputs and outputs enabled;
- faucet operators and other server-side private keys are absent.

Treat captures as sensitive test material. Do not commit or publish them.
