# `arc99x4` Offsite Worker Assets

These files install the three offsite worker services described in
`docs/offsite-coordinator-worker-plan-2026-07-12.md`.

They intentionally do not contain secrets and do not start or enable workers.
Protected role env files and the staged release must already exist under
`$HOME/parth` on `arc99x4`.

The cloud administrator can create the dedicated gateway and its UDP firewall
rule with:

```bash
bash deploy/offsite-worker/gcp-create-wireguard-gateway.sh
```

The script is intentionally separate from guest configuration. Confirm how SSH
is authorized in the project before creating the VM; it does not add a new
public TCP/22 firewall rule.

Copy the guest scripts through the project's approved SSH/SCP path after the VM
exists. The operator performing Phase 1 must be able to use `sudo` on the guest;
VM creation alone does not grant another local operator access.

Install after reviewing the staged files:

```bash
bash deploy/offsite-worker/arc99x4-install-staged.sh
```

After the dedicated gateway VM exists, install WireGuard on it. Pass only the
public key from `arc99x4`; the gateway generates and retains its own private key:

```bash
sudo ARC_PUBLIC_KEY='<arc-public-key>' \
  bash deploy/offsite-worker/gateway-install-wireguard.sh
```

Copy `arc99x4-wg0-gateway.conf.example` outside git, fill in the protected
client configuration, then switch `arc99x4` to the dedicated endpoint:

```bash
CONFIG="$HOME/parth-wg0-gateway.conf" \
  bash deploy/offsite-worker/arc99x4-switch-wireguard-gateway.sh
```

The switch preserves the previous protected configuration. Roll back with:

```bash
bash deploy/offsite-worker/arc99x4-rollback-wireguard.sh
```

After the GCP UDP firewall is open, verify WireGuard and all three private RPCs:

```bash
bash deploy/offsite-worker/arc99x4-preflight.sh
```

On the gateway, the corresponding live check is:

```bash
sudo bash deploy/offsite-worker/gateway-preflight.sh
```

To observe gateway traffic, install the optional one-minute sampler on the
gateway:

```bash
sudo bash deploy/offsite-worker/gateway-install-traffic-observer.sh
```

It writes JSONL samples to `/var/log/parth/wireguard-traffic.jsonl`.
`wg_tx_bytes` is the gateway-to-arc internet egress counter and is the main GCP
traffic-cost signal. Estimate current run-rate with:

```bash
sudo /usr/local/sbin/parth-wireguard-traffic-estimate
```

Start one role at a time only after preflight succeeds. Do not stop GCP workers:
the cloud coordinator, realm0, and realm1 workers are the baseline, while these
offsite workers only add throughput.

## Deploy a fresh-network release

For the current staging topology, GCP retains a complete coordinator, realm0,
and realm1 worker baseline. After the fresh GCP flow has built
`dist/parth-node-bundle.tar.gz`, restored the private RPCs, and passed smoke
tests, deploy the same bundle and genesis to `arc99x4` with:

```bash
OFFSITE_WORKER_HOST=arc99x4 \
RESET_OFFSITE_WORKER_STATE=1 \
bash deploy/offsite-worker/deploy-arc99x4-release.sh
```

Before clearing NATS or L2 state, stop the offsite workers with:

```bash
bash deploy/offsite-worker/stop-arc99x4-workers.sh
```

The script stages the bundle as the SSH user, then opens a TTY for `sudo` while
installing the release, archiving old completed-job logs, and starting the
coordinator, realm0, and realm1 workers. It never reads or copies worker private
keys; the protected role env files already installed on `arc99x4` are reused.
