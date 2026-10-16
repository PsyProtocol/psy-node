# Host prerequisite scripts — 2026-10-16 validation

- Read-only SSH confirmed arc99x2/x3/x4 rebooted and reachable; KVM exists there,
  virtualization programs are absent, and existing Proxy services remain active.
  Root SSH and passwordless sudo are unavailable. No attempts changed auth rules.
- Local host is arch3900x, NetworkManager on enp5s0; the three remote hosts use
  systemd-networkd on enp3s0. Hostname, NIC MAC and existing LAN IP were inspected.
- 12 stdlib tests passed: target identity/x1 exclusion, no-apply no-mutation,
  root/console/IP acknowledgement, no-overwrite files, missing-SVM refusal,
  ancestor symlink refusal, dedicated network files, and new-disk signature,
  partition/mount/size/serial/root-disk rejection.
- Python compilation and check_host.sh ShellCheck passed.
- Both NetworkManager bridge/port argument sets passed real `nmcli --offline`
  keyfile generation. Its initial priority 1000 was rejected and corrected to
  the supported maximum 999. No profile was saved or activated in this check.
- The install action without --apply ran locally and printed the plan only.

No administrator install/bridge/storage/format action was executed. Actual Arch
package installation, libvirt/polkit access in a fresh login, QEMU DAC access,
networkd bridge activation/rollback, and VM boot remain operator/field checks.
Disk initialization is optional and restricted to a verified new blank disk;
the currently observed x4 has no such expanded disk. x3 cleanup belongs to user.

The shared Kubernetes runner still targets the original six-VM topology.
These scripts prepare host capabilities and permissions; they do not claim the
new four-node renderer or cluster installation has already been completed.
