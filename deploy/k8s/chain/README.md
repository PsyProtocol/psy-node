# Isolated chain deployment and native CLI acceptance

The database layer is accepted separately. A chain pass additionally requires
real native CLI transactions, Worker pick/prove/submit evidence, Coordinator
and both Realm checkpoints, and correct Pod placement/readiness/resources.
Do not start the legacy native stack or point the CLI at existing localhost
ports or staging defaults.

`resize-worker.py` can increase one existing x2/x3/x4 lab worker VM to at most
56 GiB, with optional `--cpus` up to the physical logical CPU count. It requires the confirmed inventory, rendered platform identity gate,
an explicit libvirt domain UUID, matching disks/bridge/MAC, and enough physical
MemAvailable to preserve the chosen host reserve (8 GiB default; 4 GiB for a
dedicated host) beyond the entire future VM allocation. The final gate runs
after graceful guest shutdown, when its actual resident RAM has been released.
An insufficient-capacity result restarts the unchanged VM and restores scheduling.
It never credits unbacked virtual guest RAM. The default
is read-only. With `--apply --evidence /absolute/new-directory` it records the
original domain/node, cordons that worker, requests graceful ACPI shutdown,
changes only its requested persistent CPU/memory fields, starts the same VM,
and waits for a changed guest boot ID, Ready, unchanged node UID, and the new
reported capacities before uncordoning it. There is
no host sudo, disk change, forced power-off, or native service restart. A failed
operation leaves the worker cordoned and its original XML available for review.
Run one worker at a time, check workload recovery before proceeding, and keep
the original immutable construction inventory as historical evidence.

Application manifests and the native CLI transaction runner are being prepared.
This directory's existence does not mean the chain acceptance has passed.
