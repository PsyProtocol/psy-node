# Temporarily free the x3/x4 hosts

`pause-host-services.py` stops only the explicitly listed native Psy system
services on physical `arc99x3` or `arc99x4`. The operator runs privileged actions.
The default invocation prints a read-only plan and verifies the physical hostname.

```sh
# On arc99x3:
python3 pause-host-services.py x3
sudo python3 pause-host-services.py x3 --apply
# On arc99x4:
python3 pause-host-services.py x4
sudo python3 pause-host-services.py x4 --apply
```

Each apply saves before/after state and a resume script under a new private
`/var/tmp/psy-pause-x3-*` or `psy-pause-x4-*` directory. To resume the previously
running native services, the operator can run `sudo sh` with the exact saved
`resume-native-services.sh` path printed by that invocation. Services retain their
enabled settings, so a host reboot can start them again.

The script does not stop KVM guests. Shut down the identified lab guests gracefully
and cordon their Kubernetes nodes separately before freeing the hosts. Preserve
their persistent definitions and disks. When resuming, start the same guests,
wait for both nodes to become Ready, and then uncordon them. Verify the databases
before continuing chain tests.

SSH, networking, libvirt and the unrelated x3 embedding service remain available.
Database disks, credentials and VM definitions are retained. Existing application
endpoints served by the stopped native proxies will be unavailable while paused.
