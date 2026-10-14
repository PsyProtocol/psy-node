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
```

Start with [the build instructions](build/README.md). The six core Rust runtime
image paths have a tested build harness; real Psy compilation/proof/E2E and the
remaining Envio/frontend/admission inputs are still pending. Published platform
versions are candidates rather than a verified installation combination.

Future manifests, local platform configuration, environment overlays, tests and
runbooks will also live under `deploy/k8s/`. The monitoring target is Prometheus,
Grafana and Alertmanager, with native Psy metrics or a small read-only exporter;
the legacy Collector/Controller are not long-term deployment dependencies.

These entrypoints only prepare/build local artifacts. They do not modify x2/x3/x4,
deploy applications, reset chain state, push images or publish packages.
