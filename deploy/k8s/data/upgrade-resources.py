#!/usr/bin/env python3
"""Upgrade this lab's existing DB budget, preserving its Retain PV data/credentials."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time

import databases as db


def get(kind, name, *, optional=False):
    args = ['get', kind, name, '-o', 'json']
    if kind != 'pv':
        args += ['-n', db.NS]
    if optional:
        args += ['--ignore-not-found']
    raw = db.kubectl(*args).stdout.strip()
    return json.loads(raw) if raw else None


def owned(item, meta):
    db.require(item['metadata'].get('annotations', {}).get('psy.local/data-bundle') == meta['bundle_id'], 'Resource belongs to a different data bundle')
    db.require(all(item['metadata']['labels'].get(k) == v for k, v in db.LABELS.items()), 'Foreign resource label')


def patch(kind, current, operations):
    before = current['metadata']
    tests = [{'op': 'test', 'path': '/metadata/uid', 'value': before['uid']},
             {'op': 'test', 'path': '/metadata/resourceVersion', 'value': before['resourceVersion']}]
    args = ['patch', kind, before['name'], '--type=json', '--patch-file=/dev/stdin']
    if kind != 'pv':
        args += ['-n', db.NS]
    # stdin also protects Secret config payloads from process arguments/logging.
    db.kubectl(*args, data=json.dumps(tests + operations))


def storage_pair(pv, pvc, name):
    claim = 'psy-lab-data-' + name
    db.require(pv['metadata']['name'] == claim and pvc['metadata']['name'] == claim, 'Unexpected volume names')
    spec = pv['spec']
    db.require(spec['persistentVolumeReclaimPolicy'] == 'Retain' and spec['storageClassName'] == 'psy-lab-local', 'Retain local volume required')
    db.require(spec['local']['path'] == '/srv/psy-lab/db-' + name, 'Unexpected local data directory')
    affinity = spec['nodeAffinity']['required']['nodeSelectorTerms']
    db.require(affinity == [{'matchExpressions': [{'key': 'kubernetes.io/hostname', 'operator': 'In', 'values': ['psy-lab-work-x4']}]}], 'Unexpected PV node affinity')
    db.require(spec['claimRef']['uid'] == pvc['metadata']['uid'] and spec['claimRef']['namespace'] == db.NS, 'PV/PVC binding identity mismatch')
    db.require(pvc['spec']['volumeName'] == claim and pvc['status']['phase'] == 'Bound', 'Bound dedicated PVC required')
    return claim


def wait_absent(kind, name):
    deadline = time.monotonic() + 240
    while get(kind, name, optional=True):
        db.require(time.monotonic() < deadline, 'Timed out waiting for graceful removal; inspect retained objects')
        time.sleep(2)


def private_backup(args, meta, name, token):
    db.require(name in db.DATABASES, 'Only the five dedicated database directories may be backed up')
    for path in [args.ssh_key, args.known_hosts]:
        db.require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'Explicit guest SSH files required')
    db.require(stat.S_IMODE(args.ssh_key.stat().st_mode) == 0o600, 'Guest key must be private')
    db.require(re.fullmatch('[0-9a-f]{12}', token), 'Invalid backup ID')
    code = '''import hashlib,json,os,shutil,stat,subprocess
from pathlib import Path
assert os.geteuid()==0
assert subprocess.check_output(['systemd-detect-virt'],text=True).strip()=='kvm'
assert Path('/proc/sys/kernel/hostname').read_text().strip()=='psy-lab-work-x4'
assert Path('/etc/psy-k8s-lab').read_text().strip()==MARKER
assert subprocess.check_output(['findmnt','-n','-o','UUID','-T','/srv/psy-lab'],text=True).strip()==FSUUID
assert not Path('/srv/psy-lab').is_symlink()
source=Path('/srv/psy-lab')/('db-'+NAME)
assert source.is_dir() and not source.is_symlink()
parent=Path('/srv/psy-lab')/('pre-resource-upgrade-'+TOKEN)
assert not parent.is_symlink()
parent.mkdir(mode=0o700,exist_ok=True)
assert parent.stat().st_uid==0 and stat.S_IMODE(parent.stat().st_mode)==0o700
target=parent/NAME
assert not target.exists() and not target.is_symlink()
size=int(subprocess.check_output(['du','-s','-B1','--apparent-size','--one-file-system','--',str(source)],text=True).split()[0])
assert shutil.disk_usage(parent).free>=int(size*1.05)+32*2**30
subprocess.run(['cp','-a','--reflink=auto','--',str(source),str(target)],check=True)
def manifest(root):
 h=hashlib.sha256();count=0;size=0
 for path in sorted(root.rglob('*')):
  rel=str(path.relative_to(root));s=path.lstat()
  h.update(json.dumps([rel,s.st_mode,s.st_uid,s.st_gid,os.readlink(path) if path.is_symlink() else None]).encode())
  if path.is_file() and not path.is_symlink():
   with path.open('rb') as f:h.update(hashlib.file_digest(f,'sha256').digest())
   count+=1;size+=s.st_size
 return {'sha256':h.hexdigest(),'files':count,'bytes':size}
before=manifest(source);after=manifest(target)
assert before==after
print(json.dumps({'backup':str(target),'tree':after,'apparent_source_bytes':size,'free_after_bytes':shutil.disk_usage(parent).free}))
'''
    values = {'MARKER': meta['inventory_sha256'] + ':psy-lab-work-x4', 'FSUUID': args.virtual_fs_uuid, 'NAME': name, 'TOKEN': token}
    for key, value in values.items():
        code = re.sub(r'\b' + key + r'\b', repr(value), code)
    command = 'sudo python3 -c ' + shlex.quote(code)
    ssh = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'IdentitiesOnly=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(args.known_hosts),
           '-i', str(args.ssh_key), 'ubuntu@192.168.5.215', command]
    result = subprocess.run(ssh, capture_output=True, text=True, timeout=600)
    db.require(result.returncode == 0, 'Consistent offline guest backup failed; preserve data and inspect')
    return json.loads(result.stdout)


def recover_stopped_database(name, meta):
    """Resume an unchanged stopped instance only if its original local path is bound."""
    current = get('statefulset', name)
    owned(current, meta)
    if current['spec']['replicas'] != 0:
        return
    claim = get('pvc', 'psy-lab-data-' + name, optional=True)
    if not claim or claim.get('status', {}).get('phase') != 'Bound':
        return
    volume = get('pv', 'psy-lab-data-' + name)
    owned(volume, meta)
    owned(claim, meta)
    storage_pair(volume, claim, name)
    patch('statefulset', current, [{'op': 'replace', 'path': '/spec/replicas', 'value': 1}])
    print('Restart requested for still-bound ' + name + ' after failed upgrade step', flush=True)


def rebind(pv, pvc, desired_gib, evidence):
    # Static local PVs have no expansion controller. Grow the capacity
    # declaration by rebinding a replacement claim to the SAME Retain PV/path.
    # A verified offline copy is required by the caller before entering here.
    name = pvc['metadata']['name']
    old_gib = int(pvc['spec']['resources']['requests']['storage'][:-2])
    db.require(desired_gib >= old_gib, 'Never shrink an existing volume')
    if desired_gib == old_gib:
        return pvc
    options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': pvc['metadata']['uid']}}
    db.kubectl('delete', '--raw', '/api/v1/namespaces/' + db.NS + '/persistentvolumeclaims/' + name, '-f', '-', data=json.dumps(options))
    wait_absent('pvc', name)
    deadline = time.monotonic() + 120
    while True:
        current = get('pv', name)
        db.require(current['metadata']['uid'] == pv['metadata']['uid'] and current['spec'] == pv['spec'], 'PV changed during claim removal')
        if current.get('status', {}).get('phase') == 'Released' and rebind_patch(current, desired_gib):
            break
        db.require(time.monotonic() < deadline, 'PV release/rebind conflict did not settle; original data/backup retained')
        time.sleep(1)
    spec = json.loads(json.dumps(pvc['spec']))
    spec['resources']['requests']['storage'] = str(desired_gib) + 'Gi'
    replacement = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {
        'name': name, 'namespace': db.NS, 'labels': pvc['metadata']['labels'], 'annotations': {
            k: v for k, v in pvc['metadata'].get('annotations', {}).items() if k.startswith('psy.local/')}}, 'spec': spec}
    db.write(evidence / (name + '-replacement.json'), replacement)
    db.kubectl('create', '-f', '-', data=json.dumps(replacement))
    deadline = time.monotonic() + 120
    while True:
        after = get('pvc', name)
        if after['status'].get('phase') == 'Bound':
            break
        db.require(time.monotonic() < deadline, 'Replacement PVC did not bind; original data/PV/backup are retained')
        time.sleep(2)
    db.require(get('pv', name)['metadata']['uid'] == pv['metadata']['uid'], 'PV identity must remain unchanged')
    return after


def rebind_patch(current, gib):
    """Use an API resourceVersion precondition and retry only genuine conflicts."""
    ref = {key: None for key in current['spec']['claimRef']}
    ref.update(namespace=db.NS, name=current['metadata']['name'])
    body = {'metadata': {key: current['metadata'][key] for key in ['uid', 'resourceVersion']},
            'spec': {'capacity': {'storage': str(gib) + 'Gi'}, 'claimRef': ref}}
    result = db.kubectl('patch', 'pv', current['metadata']['name'], '--type=merge', '--patch-file=/dev/stdin', data=json.dumps(body), check=False)
    if result.returncode == 0:
        return True
    if '(Conflict)' in result.stderr or 'the object has been modified' in result.stderr:
        return False
    raise RuntimeError('PV rebind patch failed for a reason other than a resourceVersion conflict')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['bundle', 'evidence', 'ssh-key', 'known-hosts']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--virtual-fs-uuid', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    db.require(re.fullmatch('[0-9a-f-]{36}', args.virtual_fs_uuid), 'Explicit virtual data filesystem UUID required')
    db.require(args.evidence.is_absolute() and not args.evidence.exists(), 'Fresh private evidence directory required')
    db.require(not subprocess.check_output(['git', '-C', str(db.HERE.parents[2]), 'status', '--porcelain'], text=True).strip(), 'Source must be reviewed and committed')
    meta = db.guard(args.bundle)
    desired = db.manifests(db.credentials(Path(meta['secrets_file'])), meta['images'])
    wanted = {(x['kind'], x['metadata']['name']): x for x in desired}
    node = json.loads(db.kubectl('get', 'node', 'psy-lab-work-x4', '-o', 'json').stdout)
    capacity = node['status']['allocatable']
    db.require(int(capacity['cpu']) >= 22 and capacity['memory'].endswith('Ki') and int(capacity['memory'][:-2]) >= 46 * 2**20, 'Increase worker VM capacity before reserving 20 CPU/40 GiB for databases')
    sizes = db.kubectl('-n', db.NS, 'exec', 'scylla-0', '--', 'df', '--output=size,avail', '-B1', '/var/lib/scylla').stdout.splitlines()[-1].split()
    db.require(int(sizes[0]) >= 216 * 2**30 and int(sizes[1]) >= 82 * 2**30, 'Insufficient local filesystem space for declared volumes, offline backups and reserve')
    old = {}
    for name in db.DATABASES:
        old[name] = {kind: get(kind, 'psy-lab-data-' + name if kind in ['pv', 'pvc'] else name) for kind in ['statefulset', 'pv', 'pvc']}
        for item in old[name].values():
            owned(item, meta)
        storage_pair(old[name]['pv'], old[name]['pvc'], name)
        sts = old[name]['statefulset']
        db.require(sts['spec']['replicas'] == 1 and sts['spec']['template']['spec']['containers'][0]['image'] == meta['images'][db.DATABASES[name]['image']], 'Expected one unchanged-image database replica')
    print('Five DB targets: each request=limit 4 vCPU/8 GiB; storage 20/20/50/20/20 GiB', flush=True)
    if not args.apply:
        return
    args.evidence.mkdir(mode=0o700, parents=True)
    token = os.urandom(6).hex()
    db.write(args.evidence / 'before.json', old)
    db.write(args.evidence / 'desired-private.json', {'items': desired})
    results = {}
    def upgrade_one(name, definition):
        print('Gracefully stopping and backing up ' + name, flush=True)
        current = get('statefulset', name)
        owned(current, meta)
        patch('statefulset', current, [{'op': 'replace', 'path': '/spec/replicas', 'value': 0}])
        wait_absent('pod', name + '-0')
        backup = private_backup(args, meta, name, token)
        db.write(args.evidence / (name + '-backup.json'), backup)
        claim = rebind(old[name]['pv'], old[name]['pvc'], definition['gib'], args.evidence)
        for kind, resource_name in [('ConfigMap', 'psy-lab-' + name)] if name == 'valkey' else [('Secret', 'psy-lab-nats')] if name == 'nats' else []:
            actual = get(kind, resource_name)
            owned(actual, meta)
            db.write(args.evidence / (name + '-config-before-private.json'), actual)
            target = wanted[(kind, resource_name)]
            key = 'nats.conf' if name == 'nats' else 'valkey.conf'
            if name == 'nats':
                before = json.loads(base64.b64decode(actual['data'][key]))
                after = json.loads(base64.b64decode(target['data'][key]))
                db.require(before['authorization'] == after['authorization'], 'NATS credentials/ACL must not change')
            patch(kind, actual, [{'op': 'replace', 'path': '/data/' + key, 'value': target['data'][key]}])
        current = get('statefulset', name)
        container = wanted[('StatefulSet', name)]['spec']['template']['spec']['containers'][0]
        patch('statefulset', current, [{'op': 'replace', 'path': '/spec/template/spec/containers/0/resources', 'value': container['resources']},
            {'op': 'replace', 'path': '/spec/template/spec/containers/0/args', 'value': container['args']},
            {'op': 'replace', 'path': '/spec/replicas', 'value': 1}])
        db.kubectl('-n', db.NS, 'rollout', 'status', 'statefulset/' + name, '--timeout=10m', timeout=660)
        after_pv = get('pv', 'psy-lab-data-' + name)
        db.require(after_pv['spec']['local'] == old[name]['pv']['spec']['local'], 'Local directory must remain unchanged')
        storage_pair(after_pv, get('pvc', 'psy-lab-data-' + name), name)
        results[name] = {'backup': backup, 'pv_uid': after_pv['metadata']['uid'], 'pvc_uid_before': old[name]['pvc']['metadata']['uid'],
                         'pvc_uid_after': claim['metadata']['uid'], 'gib': definition['gib']}
        db.write(args.evidence / (name + '-result.json'), results[name])
        print(name + ' restored Ready on its original data directory', flush=True)
    for name, definition in db.DATABASES.items():
        try:
            upgrade_one(name, definition)
        except Exception:
            # Do not recreate a missing claim or change files after failure.
            # If the safe binding still exists, restore a stopped replica.
            try:
                recover_stopped_database(name, meta)
            except Exception:
                print('Automatic restart was not safe; original data and evidence retained for recovery', flush=True)
            raise
    db.write(args.evidence / 'result.json', {'upgraded': True, 'databases': results, 'acceptance': 'must run real DB acceptance next'})


if __name__ == '__main__':
    main()
