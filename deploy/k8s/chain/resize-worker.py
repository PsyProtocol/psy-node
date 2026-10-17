#!/usr/bin/env python3
"""Increase one existing lab worker VM's memory through ordinary libvirt access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET


def require(ok, message):
    if not ok:
        raise ValueError(message)


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=40, **kwargs).stdout.strip()


def ssh(host, argv):
    return run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', host, shlex.join(argv)])


def virsh(host, *argv):
    return ssh(host, ['virsh', '-c', 'qemu:///system', *argv])


def shape(xml):
    root = ET.fromstring(xml)
    for name in ['memory', 'currentMemory']:
        root.remove(root.find(name))
    return ET.tostring(root)


def capacity_check(available_kib, target_gib):
    # Idle guest RAM may not yet be resident on the physical host. Budget the
    # entire future allocation, not just the increase from its old VM ceiling.
    require(available_kib >= (target_gib + 8) * 2**20, 'Insufficient physical memory: reserve the full target plus 8 GiB')


def validate(xml, node, host, uuid, target):
    root = ET.fromstring(xml)
    require(root.tag == 'domain' and root.get('type') == 'kvm', 'Only an existing KVM domain is supported')
    require(root.findtext('name') == node['name'] and root.findtext('uuid') == uuid, 'VM identity mismatch')
    require(int(root.findtext('vcpu')) == node['cpus'], 'Unexpected VM CPU allocation')
    require(not root.findall('./devices/hostdev') and not root.findall('./devices/filesystem'), 'Unexpected host passthrough device')
    for tag in ['memory', 'currentMemory']:
        field = root.find(tag)
        require(field is not None and field.get('unit') == 'KiB', 'Expected KiB memory fields')
    current = int(root.findtext('currentMemory'))
    require(int(root.findtext('memory')) == current, 'Unexpected live/config memory arrangement')
    require(current < target * 2**20 <= 48 * 2**20, 'Only a memory increase up to 48 GiB is supported')
    expected = {'vda': str(Path(host['os_pool']) / (node['name'] + '.qcow2')),
                'sda': str(Path(host['os_pool']) / (node['name'] + '-seed.iso'))}
    if node['host'] == 'x4':
        expected['vdb'] = str(Path(host['data_pool']) / (node['name'] + '-data.qcow2'))
    fields = root.findall('./devices/disk')
    require(all(d.get('type') == 'file' for d in fields), 'Only existing file-backed disks are supported')
    disks = {d.find('target').get('dev'): d.find('source').get('file') for d in fields}
    require(len(disks) == len(fields), 'Duplicate disk target')
    require(disks == expected, 'VM disk identity differs from the confirmed inventory')
    interfaces = root.findall('./devices/interface')
    require(len(interfaces) == 1 and interfaces[0].find('mac').get('address') == node['mac']
            and interfaces[0].find('source').get('bridge') == host['bridge'], 'VM bridge/MAC mismatch')
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--platform', type=Path, required=True)
    parser.add_argument('--node', choices=['x2', 'x3', 'x4'], required=True)
    parser.add_argument('--domain-uuid', required=True)
    parser.add_argument('--memory-gib', type=int, required=True)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f-]{36}', args.domain_uuid), 'Explicit domain UUID required')
    inventory = json.loads(args.inventory.read_text())
    inventory_hash = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    require((args.platform.parent / 'inventory.sha256').read_text().strip() == inventory_hash, 'Inventory differs from platform construction inputs')
    require(inventory['lab'] == 'psy-k8s-local' and inventory['topology'] == 'local-control-plane'
            and inventory['network_confirmed'] and inventory['storage_confirmed'], 'Confirmed local lab inventory required')
    host = inventory['hosts'][args.node]
    node = next(n for n in inventory['nodes'] if n['host'] == args.node)
    require(node['name'] == 'psy-lab-work-' + args.node and node['role'] == 'agent', 'Worker identity required')
    require(host['ssh'] == 'arc99' + args.node, 'Unexpected host SSH target')
    run(['python3', str(args.platform / 'check-cluster.py')], cwd=args.platform)
    require(ssh(host['ssh'], ['cat', '/proc/sys/kernel/hostname']) == host['expected_hostname'], 'Physical host identity mismatch')
    xml = virsh(host['ssh'], 'dumpxml', args.domain_uuid, '--inactive')
    before = validate(xml, node, host, args.domain_uuid, args.memory_gib)
    require(virsh(host['ssh'], 'domstate', args.domain_uuid) == 'running', 'Expected running VM')
    memory = ssh(host['ssh'], ['cat', '/proc/meminfo'])
    available = int(re.search(r'^MemAvailable:\s+(\d+) kB$', memory, re.M).group(1))
    capacity_check(available, args.memory_gib)
    state = json.loads(run(['kubectl', 'get', 'node', node['name'], '-o', 'json']))
    require(not state.get('spec', {}).get('unschedulable'), 'Worker is already cordoned; preserve existing maintenance')
    print(json.dumps({'node': node['name'], 'before_gib': before / 2**20, 'after_gib': args.memory_gib,
                      'host_available_gib': available / 2**20, 'apply': args.apply}), flush=True)
    if not args.apply:
        return
    require(args.evidence is not None and args.evidence.is_absolute() and not args.evidence.exists(), 'Fresh absolute evidence directory required')
    os.umask(0o077)
    args.evidence.mkdir(mode=0o700, parents=True)
    (args.evidence / 'domain-before.xml').write_text(xml + '\n')
    (args.evidence / 'node-before.json').write_text(json.dumps(state, indent=2))
    run(['kubectl', 'cordon', node['name']])
    print('Cordoned worker; requesting graceful ACPI guest shutdown', flush=True)
    virsh(host['ssh'], 'shutdown', args.domain_uuid, '--mode', 'acpi')
    deadline = time.monotonic() + 180
    while virsh(host['ssh'], 'domstate', args.domain_uuid) != 'shut off':
        require(time.monotonic() < deadline, 'Guest shutdown timed out; worker remains cordoned; no forced power-off')
        time.sleep(3)
    virsh(host['ssh'], 'setmaxmem', args.domain_uuid, str(args.memory_gib * 2**20), '--config')
    virsh(host['ssh'], 'setmem', args.domain_uuid, str(args.memory_gib * 2**20), '--config')
    after = virsh(host['ssh'], 'dumpxml', args.domain_uuid, '--inactive')
    require(shape(after) == shape(xml), 'Unexpected domain change; inspect XML before starting VM')
    (args.evidence / 'domain-after.xml').write_text(after + '\n')
    print('Only memory configuration changed; starting the same guest', flush=True)
    virsh(host['ssh'], 'start', args.domain_uuid)
    deadline = time.monotonic() + 240
    while True:
        state = json.loads(run(['kubectl', 'get', 'node', node['name'], '-o', 'json']))
        ready = any(c['type'] == 'Ready' and c['status'] == 'True' for c in state['status']['conditions'])
        capacity = state['status']['capacity']['memory']
        if ready and capacity.endswith('Ki') and int(capacity[:-2]) >= (args.memory_gib - 1) * 2**20:
            break
        require(time.monotonic() < deadline, 'Guest did not report increased memory; worker remains cordoned')
        time.sleep(3)
    run(['kubectl', 'uncordon', node['name']])
    run(['python3', str(args.platform / 'check-cluster.py')], cwd=args.platform)
    (args.evidence / 'node-after.json').write_text(json.dumps(state, indent=2))
    print('Same worker Ready with increased memory and scheduling restored', flush=True)


if __name__ == '__main__':
    main()
