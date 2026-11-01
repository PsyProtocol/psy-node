# Monitoring deployment (step 85)

Step 85 of the release orchestrator deploys the existing `PsyProtocol/psy-notifier` system, not a
new monitoring implementation. It runs after acceptance step 84. The legacy runner step 32
(`32_deploy_monitoring.sh`, "11 collectors") is retired: it refuses to run and is superseded by step 85.
The Notifier checkout is the path in `local-inputs.json` (`notifier.checkout`); its pinned commit
is `sources.notifier` in the release lock and `EXPECTED_PSY_NOTIFIER_COMMIT` in
`source-versions.env`. Both change together at Task C1, after the Notifier commit is published
(the lock field is empty until then; `source-versions.env` still holds the retired commit).

## Inventory and configuration

Step 85 (`core-only/deploy_monitoring_steps.py`) derives the fleet from the release;
no host list lives in `deploy-monitoring.sh` or in this document.

- Hosts: every alias in `topology.json` and the lock `hosts`. Aliases in 10.250.0.0/16
  are offsite (WireGuard gateway `10.250.0.1:9443`); all others report to the Controller.
- Collector configs are rendered per host: host resources, the infrastructure targets of
  the Notifier repository config where one exists, and every loaded unit that matches a
  lock `units` prefix or name (discovered read-only over SSH). Retired `parth-*` units are dropped.
- Controller: `gcp-faucet`, private gRPC `10.148.0.33:9443`, status API `127.0.0.1:9099`.
  Its config is the Notifier staging file with the lock `l1.signer` as the balance address
  and one `[[settlement]]` probe per release chain index (StateManager read from the
  deployed documents on the Relayer host).
- Alerts: `l1-low-balance` per chain (warning at 7 days of finalize gas, critical at 2 days, at
  240 finalizes per day priced at 1 Gwei, the BSC floor; 400k gas on BSC and Base, 700k on Sepolia.
  1 Gwei is an upper bound for Base, about 0.006 Gwei, and Sepolia, base fee about 15 wei) and
  `settlement-stalled` per chain index (no `lastFinalizedCheckpointId` advance for 30 minutes).
  The shared finalize round freezes all three cursors when one chain is starved, so all three alert.
  A burst such as 644 finalizes in 20 hours spends 3x faster; `l1-runway-low` measures actual spend.
  Step 85 refuses a Notifier config whose thresholds fall below these floors.
- Controller `collectors.expected` is rendered from the release hosts (the Controller refuses any
  other collector). Core targets (coordinator edges, Realm processors and edges) and their
  latest-checkpoint probes come from `topology.json` and the lock `core_prefix`; infrastructure
  targets of the Notifier repository configs and their non-`parth-*` services are kept.
- The adapter takes `MONITORING_HOSTS_FILE`, `MONITORING_COLLECTOR_DIR`,
  `MONITORING_CONTROLLER_CONFIG`, `MONITORING_CHAIN_INDEXES`, `MONITORING_NOTIFIER_DIR` and
  `MONITORING_SSH_CONFIG` from the step; the SSH config is generated from the access file.
- Known gaps: Guardian readiness probes and Guardian quorum groups, and probes for the services,
  indexer, Envio and Relayer HTTP endpoints, are not rendered; those hosts get unit health and logs only.
- Existing `parth-sentinel-*` systemd names, users and persistent paths remain unchanged.

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
   Apply stages the offsite packages and returns exit code 3 (PENDING).
   The user runs the printed installation commands; the agent never handles
   offsite sudo passwords. Step 32 is not recorded as SUCCEEDED at this point.
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
the pinned Controller and nine cloud Collector installers with checksum checks.
It stages, but does not activate, the two offsite packages and exits 3. Run:

```bash
ssh -t arc99x3 'cd ~/psy-notifier-install && sudo ./install-collector.sh ./psy-notifier-collector ./collector.toml ./parth-sentinel-collector.service'
ssh -t arc99x4 'cd ~/psy-notifier-install && sudo ./install-collector.sh ./psy-notifier-collector ./collector.toml ./parth-sentinel-collector.service'
bash deploy/multi-chain/gcp/deploy-monitoring.sh --status
```

Only the final read-only status check accepts fleet readiness. Keep its output
beside the original step-32 PENDING receipt; do not rewrite that receipt.
It requires:

- Controller `ready=true`;
- healthy probes for exactly Sepolia 11155111, BSC 97 and Base Sepolia 84532;
- all eleven expected staging collectors observed within the last 120 seconds
  (clock synchronization is required; future timestamps beyond 30s fail).

If those checks fail, the standalone status command exits nonzero; the original
step-32 receipt remains `PENDING` until readiness is established separately.
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
