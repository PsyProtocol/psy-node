# Construction preparation validation — 2026-10-14

This delivery adds platform construction tooling to the preparation branch. It
does not attest that the three physical hosts are ready or that Psy business
flows have been migrated.

- 13 stdlib tests passed: LAN/VIP/CIDR collisions, unsafe identities/paths,
  memory budgets, x4-only data disk, consistent K3s server flags, configuration
  permissions, unconfirmed execution rejection, physical-host guest rejection,
  no-overwrite rendering, Retain storage, kubeconfig/cluster identity gates, and
  pre-existing fully traversable pools without creating/changing parent paths.
- Existing nine build-policy tests also passed; application binaries were not
  rebuilt in this construction step.
- All generated shell scripts passed ShellCheck; Python modules compiled.
- SHA256 checks passed for K3s, Helm, three packaged Helm charts and Gateway API
  CRDs. Ubuntu image URL and published checksum were checked; the 626 MB image
  was not downloaded or booted in this step.
- Actual fixed charts rendered with Helm 3.19.0 for Kubernetes 1.35.9.
  Traefik's rendered Deployment explicitly uses maxUnavailable=1/maxSurge=0,
  allowing updates with required anti-affinity on exactly three workers.
- All six VM definitions passed xmllint against official libvirt v12.8.0
  domain.rng. This is schema validation, not a real libvirt/KVM boot test.
- K3s v1.35.9+k3s1 API ran in a new isolated local Docker container using image
  `rancher/k3s@sha256:ec9868c6a38d4e8c1869832fb5fd1eb8473c39794a0b44d2b952e7ba911951bc`.
  Only test namespaces, CRDs and chart ServiceAccounts were persisted there;
  storage, kube-vip RBAC/DaemonSet, MetalLB pool/L2Advertisement and complete
  MetalLB/Traefik/Prometheus chart objects passed server-side dry-run. Chart test
  Pods require their ServiceAccount to exist even for dry-run; those accounts
  were created in the isolated container before the final check.
- Read-only SSH preflight succeeded against arc99x2/arc99x3/arc99x4. All are Arch
  Linux with KVM access. All lack virsh/qemu-img/cloud-localds and the example br0.
  Approximate OS-pool free space: x2 84 GiB, x3 39 GiB, x4 155 GiB. Required:
  96 GiB each. x4's example new data mount does not yet exist. No remote system
  packages, services, bridges, disks or VMs were modified.

Local validation artifacts are under
`/tmp/psy-k8s-construction-render-reviewed-20261014/` and
`/tmp/psy-k8s-api-manifests-final-20261014/`. They use a synthetic public key and
example IP addresses, and must not be used as a real construction inventory.

Remaining live gates: host helper/daemon setup and directory traversal/security
policy; disk expansion and pool capacity; console-backed bridge/IP reservation;
libvirt XML acceptance, cloud-init boot and SSH; etcd quorum and kube-vip RBAC/L2
behavior; MetalLB/Traefik route traffic; Prometheus targets and actual storage
permissions; restart/failover/backup restore. API dry-run proves schema admission,
not controller behavior or reachability. The temporary API node experienced
ephemeral-storage pressure on this build machine, so this run is not a storage
capacity, scheduling, or full monitoring-stack acceptance test.
