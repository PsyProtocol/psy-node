# Four-node preparation validation — 2026-10-16

Scope: deploy tooling only. Existing live network state, x1, source/runtime pins,
Genesis, keys and contracts are unchanged. Host prerequisites were installed by
the operator, not by this agent. No physical bridge or disk was modified by the
agent and no persistent cluster VM has been created.

Passed:

- 10 four-node regression tests: exact host/role/resource/API targeting, physical
  IP collision rejection, x4 mount/pool distinction, no-overwrite plan behavior,
  ordinary-user/root guards, XML disk/passthrough guards, four-node kubeconfig and
  control-plane taint validation. The legacy 13 platform and 12 host-setup tests
  also passed (35 total).
- Four rendered VM domains accepted by the installed libvirt Relax NG schema.
- Eight generated installation/verification shell scripts plus check-addresses.sh
  passed Bash syntax and ShellCheck using a confirmed test fixture. Actual pending
  bundles remain unconfirmed for storage and deliberately exit before mutation;
  ShellCheck reports unreachable-code info on those intentionally disabled copies.
- Fixed Ubuntu/K3s/Helm/chart/CRD assets downloaded into the private persistent lab
  directory and verified against the existing lock. Real Helm template rendering,
  Traefik worker placement/3 replicas/rollingUpdate 1/0, worker-only node-exporter,
  and platform verify-assets.py passed.
- Real local QEMU KVM smoke boot: pinned Ubuntu qcow2, 2 vCPU/2 GiB, no NIC,
  temporary snapshot; observed Linux kernel and init/systemd, then exited QEMU
  normally (0). The original image was not modified. This does not validate
  bridged guest networking, cloud-init, or libvirt DAC ownership at VM start.
- Four-host read-only probe: KVM/helpers/libvirt/operator access/memory/OS capacity
  passed. Local refreshed libvirt group was verified using newgrp (the persistent
  agent session predates the group addition). x3 OS pool now about 139 GiB free.

Still pending:

- Four br0 bridges; x4 expanded physical disk/mount/pool. The full preflight
  correctly returned failure, reporting these missing prerequisites on all hosts.
- ARP duplicate-address probe: ordinary operator lacked raw socket permission,
  so no collision-free claim was made. Operator-run check-addresses.sh is included;
  router reservations were confirmed by the user separately.
- Actual four guest creation, cloud-init/SSH/networking, K3s joining, zero-Pod
  control plane, platform rollout/Prometheus targets, LAN ingress and failure tests.
- Psy compilation, business manifests, policy allow/deny and transaction E2E.

Scheduling design accounts for the pinned K3s defaults: both
[CoreDNS](https://github.com/k3s-io/k3s/blob/v1.35.9%2Bk3s1/manifests/coredns.yaml)
and [metrics-server](https://github.com/k3s-io/k3s/blob/v1.35.9%2Bk3s1/manifests/metrics-server/metrics-server-deployment.yaml)
tolerate the standard control-plane taint. A dedicated control-only taint is added,
worker-only node-exporter is rendered, and verification requires zero scheduled
Pods on psy-lab-cp-local. CoreDNS/metrics Pending before workers join is expected.

## Additional preparation while x4 disk is being expanded

- Added per-host delivery assembly and network acceptance, with 11 new regression
  tests (46 including the previous suites). Coverage includes package role/hash
  boundaries, bad-asset rejection before output, offline/unconfirmed execution
  guards, worker-only restricted probes, positive and negative connectivity
  controls, namespace AND Pod selectors, and fake-cluster orchestration.
- Resolved official BusyBox 1.37.0 linux/amd64 digest via Docker Hub manifest.
  Ran its httpd/wget as UID 1000, no external network, no capabilities, read-only
  root filesystem and temporary /www; unique HTTP response matched. This tests
  image commands, not Kubernetes networking or CNI enforcement.
- Used pinned K3s in an isolated temporary Docker container, without agent, host
  mounts or published ports. Actual API/server dry-run admitted all 16 workload,
  Service, NetworkPolicy, ReferenceGrant and HTTPRoute objects, with restricted
  Pod admission enforced on the two fixture namespaces; no warnings/errors.
  The test caught a default ServiceAccount creation race. The runner now creates
  dedicated tokenless probe identities before Pods. Container was stopped/removed.
- Live four-host cluster/NetworkPolicy/Gateway acceptance still requires the
  operator's br0 and x4 disk steps. API dry-run does not demonstrate DNS, routing,
  policy enforcement, storage recovery or Psy transactions.
- Read-only host update: x2/x3 still lack br0; x4 SSH was unavailable during the
  operator's disk work. No host network/disk action was attempted by the agent.
