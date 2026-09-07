# Final-step monitoring deployment

The multichain runner ends with **32_deploy_monitoring.sh**, after frontend
publication, protocol smoke checks and offsite workers. It deploys the existing
`PsyProtocol/psy-notifier` system, not a new monitoring implementation.
Its exact published commit is pinned in `source-versions.env`.

## Inventory and configuration

- Controller: `gcp-faucet`, private gRPC `10.148.0.33:9443` and localhost-only
  status API `127.0.0.1:9099`.
- Nine GCP collectors: cp-ce, coordinator-worker, faucet, postgres, scylla,
  nats, redis, nostr and gateway (SSH aliases carry the `gcp-` prefix).
- Two offsite collectors: `arc99x4` workers and `arc99x3` prove-proxy.
- Offsite reporting: existing WireGuard gateway `10.250.0.1:9443`, forwarded
  only to the Controller. No public monitoring endpoint is created.
- Existing `parth-sentinel-*` systemd names, users and persistent paths remain
  unchanged. Binary branding is now `psy-notifier-*`.

The adapter intentionally supports this fixed, reviewed staging inventory.
If hosts change, review the Notifier inventory, forwarder and adapter together;
changing only a node deployment host setting does not move its monitoring.

Private deployment config can set:

```bash
DEPLOY_MONITORING=1
PSY_NOTIFIER_DIR="$WORKSPACE_HOME/parth-sentinel"
NOTIFIER_SSH_CONFIG="$HOME/.ssh/config"
NOTIFIER_BOOKWORM_BUILDER_IMAGE="parth-bookworm-builder:latest"
NOTIFIER_CARGO_REGISTRY="${CARGO_HOME:-$HOME/.cargo}/registry"
```

The checkout must already exist, have the canonical origin, match the pinned
SHA and be clean. No automatic pull, reset or cleanup is performed. Local
source validation happens before the runner stops business services. Full
`--plan` stays offline and does not require a monitoring checkout.

## Prerequisites

1. Retain `/etc/parth-sentinel/secrets/slack-webhook-url` on `gcp-faucet`, owned
   and readable only by root. The installer checks existence without fetching
   its content; no webhook is committed. Provision it separately on a new VM.
2. Deploy the multi-chain Relayer first. The Controller installer reads its
   root-only configuration to obtain current RPCs and the existing signer.
   It does not use historical hard-coded provider credentials.
3. Keep sudo access on GCP hosts and an interactive terminal for offsite sudo.
   The existing installer prompts once per offsite host; a missing password
   or failed installation fails step 32, not a successful "staged" result.
4. The Bookworm builder image must contain Rust 1.97.1, matching the reviewed
   Notifier portable build. The adapter builds locked release binaries before
   touching monitoring services, with configurable home/cache paths.
5. Arrange the existing monitor's maintenance/notification handling before
   starting a destructive fresh deployment. Moving installation to the last
   step does **not** silence monitors that are already running. This adapter
   does not stop those monitors early, delete their databases, discard incident
   queues, or promise that deployment-related alerts cannot be emitted.

## Execution and checks

From the deployment checkout, with private `config.env` prepared:

```bash
# Local source/inventory checks only: no SSH, build, service changes or alerts.
bash deploy/multi-chain/gcp/deploy-monitoring.sh --check

# Read-only remote systemd, Controller and recent-report checks.
bash deploy/multi-chain/gcp/deploy-monitoring.sh --status

# After deployment approval: normally invoked as final step 32 by deploy_all.sh.
# This standalone entry only updates monitoring; it never redeploys the chain.
bash deploy/multi-chain/gcp/deploy-monitoring.sh --apply
```

Apply builds both binaries in Bookworm, validates all eleven collector configs
and the Controller config, installs the private gateway forwarder, then invokes
the pinned fleet installer. That installer checks deployed binary checksums
and service activation. Finally, this adapter requires:

- Controller `ready=true`;
- healthy probes for exactly Sepolia 11155111, BSC 97 and Base Sepolia 84532;
- all eleven expected staging collectors observed within the last 120 seconds
  (clock synchronization is required; future timestamps beyond 30s fail).

If those checks fail, the step exits nonzero and the runner records `FAILED`.
Do not rerun destructive steps: diagnose and retry only monitoring. A healthy
transport does not mean no incidents exist. Review firing incidents/outbox
separately. The pinned configuration enables Slack and has a dry-run PagerDuty
sink; this integration does not claim live PagerDuty delivery. No synthetic
Slack test notification is sent. Real configured alerts may start as soon as
the Controller is enabled.

`DEPLOY_MONITORING=0` explicitly skips step 32 and prints a coverage warning.
Similarly, `--until 31` is an intentionally partial deployment, not monitoring
acceptance. Full transaction E2E remains a separate post-deployment step.

## Offline regression tests

```bash
bash deploy/gcp/tests/test-multichain-deploy-runner.sh
bash deploy/gcp/tests/test-multichain-monitoring.sh
```

Fixtures replace SSH/Docker/installers and never deploy services or send
notifications. They cover final ordering, no-side-effect planning/checks,
pin and dirty-tree rejection, credential/build/install failures, missing or
stale collector records, wrong environments and incomplete chain probes.
