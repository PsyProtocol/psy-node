# Isolated chain deployment and native CLI acceptance

The database layer is accepted separately. A chain pass additionally requires
real native CLI transactions, Worker pick/prove/submit evidence, Coordinator
and both Realm checkpoints, and correct Pod placement/readiness/resources.
Do not start the legacy native stack or point the CLI at existing localhost
ports or staging defaults.

`resize-worker.py` can increase one existing x2/x3/x4 lab worker VM to at most
48 GiB. It requires the confirmed inventory, rendered platform identity gate,
an explicit libvirt domain UUID, matching disks/bridge/MAC, and enough physical
MemAvailable to preserve 8 GiB beyond the entire future VM allocation. This
deliberately gives no credit for existing guest RAM: an idle VM may not have
backed all of its allocation on the physical host. The default
is read-only. With `--apply --evidence /absolute/new-directory` it records the
original domain/node, cordons that worker, requests graceful ACPI shutdown,
changes only its persistent memory fields, starts the same VM, and waits for
Ready plus the new reported memory capacity before uncordoning it. There is
no host sudo, disk change, forced power-off, or native service restart. A failed
operation leaves the worker cordoned and its original XML available for review.
Run one worker at a time, check workload recovery before proceeding, and keep
the original immutable construction inventory as historical evidence.

Application manifests and the native CLI transaction runner are being prepared.
This directory's existence does not mean the chain acceptance has passed.
