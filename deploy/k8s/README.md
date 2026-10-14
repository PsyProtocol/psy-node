# Psy local Kubernetes preparation

The `deploy/k8s/` directory owns the local Kubernetes build and deployment
preparation. The initial target is an isolated lab on x2/x3/x4, with three
control-plane VMs, three application VMs, and experimental data storage on x4.

Current implementation:

```text
deploy/k8s/
  build/
    versions.json             # Candidate source/toolchain/image inputs
    build.py                  # Plan, prepare, builder, compile, verify, images
    compile.sh
    build-images.sh
    Dockerfile.builder
    Dockerfile.runtime-base
    Dockerfile.runtime
    test_build.py
    README.md
  platform/
    inventory.example.json    # Six VMs; unconfirmed addresses/storage
    assets.lock.json          # Fixed downloads + SHA256
    lab.py                    # Plan, read-only preflight, fetch, render, charts
    create-vms.py             # Scoped libvirt VM creation
    initialize-data.sh        # Empty new work-x4 virtual data disk only
    bootstrap-vip.sh
    install-platform.sh
    verify-platform.sh
    check-cluster.py
    verify-assets.py
    test_lab.py
    README.md
```

Start with [the build instructions](build/README.md). The six core Rust runtime
image paths have a tested build harness; real Psy compilation/proof/E2E and the
remaining Envio/frontend/admission inputs are still pending. Published platform
versions are candidates rather than a verified installation combination.

Continue with [the platform construction runbook](platform/README.md). It covers
host checks, six VM bundles, K3s/embedded etcd, kube-vip, MetalLB, Traefik Gateway
API and kube-prometheus-stack. Preparation and rendering are offline/read-only;
the generated installation scripts require deliberate execution on confirmed lab
hosts/VMs and a checked lab kubeconfig. Live three-host acceptance is still pending.

Application manifests and transaction acceptance follow platform acceptance.
The monitoring target is Prometheus,
Grafana and Alertmanager, with native Psy metrics or a small read-only exporter;
the legacy Collector/Controller are not long-term deployment dependencies.

No script has been executed to change x2/x3/x4 as part of this preparation.
Construction scripts do not stop existing services, change host bridges, format
physical disks, reset chain state, push images or publish packages.
