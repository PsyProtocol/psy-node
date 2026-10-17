#!/usr/bin/env python3
"""Increase one existing lab worker VM's CPU/RAM through ordinary libvirt access."""
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


def shape(xml, *, allow_cpu=False):
    root = ET.fromstring(xml)
    for name in ['memory', 'currentMemory']:
        root.remove(root.find(name))
    if allow_cpu:
        root.remove(root.find('vcpu'))
    return ET.tostring(root)


def capacity_check(available_kib, target_gib, reserve_gib=8):
    # Idle guest RAM may not yet be resident on the physical host. Budget the
    # entire future allocation, not just the increase from its old VM ceiling.
    require(available_kib >= (target_gib + reserve_gib) * 2**20, 'Insufficient physical memory: reserve the full target plus host reserve')


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
    require(current < target * 2**20 <= 56 * 2**20, 'Only a memory increase up to 56 GiB is supported')
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


def host_memory(host):
    memory = ssh(host, ['cat', '/proc/meminfo'])
    return {key: int(re.search('^' + key + r':\s+(\d+) kB$', memory, re.M).group(1)) for key in ['MemAvailable', 'MemTotal']}


def wait_node(name, memory_gib, previous_boot_id):
    deadline = time.monotonic() + 240
    while True:
        state = json.loads(run(['kubectl', 'get', 'node', name, '-o', 'json']))
        ready = any(c['type'] == 'Ready' and c['status'] == 'True' for c in state['status']['conditions'])
        capacity = state['status']['capacity']['memory']
        boot = state['status'].get('nodeInfo', {}).get('bootID')
        if ready and boot and boot != previous_boot_id and capacity.endswith('Ki') and int(capacity[:-2]) >= (memory_gib - 1) * 2**20:
            return state
        require(time.monotonic() < deadline, 'Guest did not report expected memory; worker remains cordoned')
        time.sleep(3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--platform', type=Path, required=True)
    parser.add_argument('--node', choices=['x2', 'x3', 'x4'], required=True)
    parser.add_argument('--domain-uuid', required=True)
    parser.add_argument('--memory-gib', type=int, required=True)
    parser.add_argument('--cpus', type=int)
    parser.add_argument('--host-reserve-gib', type=int, choices=[4, 8], default=8)
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
    physical = host_memory(host['ssh'])
    cpus = args.cpus if args.cpus is not None else node['cpus']
    physical_cpus = int(ssh(host['ssh'], ['getconf', '_NPROCESSORS_ONLN']))
    require(node['cpus'] <= cpus <= physical_cpus, 'CPU target must fit the physical logical CPU count')
    require(physical['MemTotal'] >= (args.memory_gib + args.host_reserve_gib) * 2**20, 'Target leaves insufficient physical host reserve')
    state = json.loads(run(['kubectl', 'get', 'node', node['name'], '-o', 'json']))
    require(not state.get('spec', {}).get('unschedulable'), 'Worker is already cordoned; preserve existing maintenance')
    boot_id = state['status']['nodeInfo']['bootID']
    node_uid = state['metadata']['uid']
    require(bool(boot_id) and bool(node_uid), 'Existing node UID/boot ID required')
    print(json.dumps({'node': node['name'], 'before_gib': before / 2**20, 'after_gib': args.memory_gib,
                      'cpus_before': node['cpus'], 'cpus_after': cpus, 'host_reserve_gib': args.host_reserve_gib,
                      'host_available_gib': physical['MemAvailable'] / 2**20, 'apply': args.apply,
                      'capacity_gate': 'full target plus host reserve checked again after guest shutdown'}), flush=True)
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
    try:
        # The old guest is now stopped: MemAvailable includes its released
        # resident pages. No credit based on its unbacked virtual ceiling.
        capacity_check(host_memory(host['ssh'])['MemAvailable'], args.memory_gib, args.host_reserve_gib)
    except ValueError:
        print('Capacity gate refused; restoring unchanged VM and scheduling', flush=True)
        virsh(host['ssh'], 'start', args.domain_uuid)
        recovered = wait_node(node['name'], before / 2**20, boot_id)
        require(recovered['metadata']['uid'] == node_uid, 'Node identity changed during restoration; remains cordoned')
        run(['kubectl', 'uncordon', node['name']])
        raise
    virsh(host['ssh'], 'setmaxmem', args.domain_uuid, str(args.memory_gib * 2**20), '--config')
    virsh(host['ssh'], 'setmem', args.domain_uuid, str(args.memory_gib * 2**20), '--config')
    if cpus != node['cpus']:
        virsh(host['ssh'], 'setvcpus', args.domain_uuid, str(cpus), '--maximum', '--config')
        virsh(host['ssh'], 'setvcpus', args.domain_uuid, str(cpus), '--config')
    after = virsh(host['ssh'], 'dumpxml', args.domain_uuid, '--inactive')
    require(shape(after, allow_cpu=True) == shape(xml, allow_cpu=True), 'Unexpected domain change; inspect XML before starting VM')
    after_root = ET.fromstring(after)
    require(all(int(after_root.findtext(tag)) == args.memory_gib * 2**20 for tag in ['memory', 'currentMemory']), 'Unexpected memory target')
    require(int(after_root.findtext('vcpu')) == cpus and int(after_root.find('vcpu').get('current', str(cpus))) == cpus, 'Unexpected CPU target')
    before_cpu_attrs = ET.fromstring(xml).find('vcpu').attrib.copy()
    after_cpu_attrs = after_root.find('vcpu').attrib.copy()
    before_cpu_attrs.pop('current', None)
    after_cpu_attrs.pop('current', None)
    require(before_cpu_attrs == after_cpu_attrs, 'Unexpected CPU placement change')
    (args.evidence / 'domain-after.xml').write_text(after + '\n')
    print('Only requested CPU/memory configuration changed; starting the same guest', flush=True)
    virsh(host['ssh'], 'start', args.domain_uuid)
    state = wait_node(node['name'], args.memory_gib, boot_id)
    require(state['metadata']['uid'] == node_uid, 'Node identity changed; worker remains cordoned')
    require(int(state['status']['capacity']['cpu']) == cpus, 'Guest CPU capacity mismatch; worker remains cordoned')
    run(['kubectl', 'uncordon', node['name']])
    run(['python3', str(args.platform / 'check-cluster.py')], cwd=args.platform)
    (args.evidence / 'node-after.json').write_text(json.dumps(state, indent=2))
    print('Same worker Ready with increased memory and scheduling restored', flush=True)


if __name__ == '__main__':
    main()
