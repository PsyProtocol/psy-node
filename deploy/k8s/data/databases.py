#!/usr/bin/env python3
"""Render and install only the isolated four-node lab's new data services."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent

NS = 'psy-data'
LABELS = {'psy.local/lab': 'psy-k8s-local', 'psy.local/component': 'data'}
DATABASES = {
    'postgres-services': {'image': 'postgres', 'port': 5432, 'gib': 10, 'uid': 999, 'gid': 999, 'memory': '1Gi', 'request': '256Mi', 'database': 'psy_services'},
    'postgres-envio': {'image': 'postgres', 'port': 5432, 'gib': 10, 'uid': 999, 'gid': 999, 'memory': '1Gi', 'request': '256Mi', 'database': 'psy_envio'},
    'scylla': {'image': 'scylla', 'port': 9042, 'gib': 50, 'uid': 999, 'gid': 1000, 'memory': '6Gi', 'request': '4Gi'},
    'valkey': {'image': 'valkey', 'port': 6379, 'gib': 5, 'uid': 999, 'gid': 1000, 'memory': '1Gi', 'request': '256Mi'},
    'nats': {'image': 'nats', 'port': 4222, 'gib': 5, 'uid': 1000, 'gid': 1000, 'memory': '512Mi', 'request': '128Mi'},
}
PYTHON_IMAGE = 'docker.io/library/python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('x') as f:
        f.write(value if isinstance(value, str) else json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def private_json(path):
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'Absolute real private file required')
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Private file must be mode 600')
    return json.loads(path.read_text())


def obj(kind, name, spec=None, *, ns=NS, api='v1', **extra):
    meta = {'name': name, 'labels': dict(LABELS)}
    if ns:
        meta['namespace'] = ns
    result = {'apiVersion': api, 'kind': kind, 'metadata': meta}
    if spec is not None:
        result['spec'] = spec
    result.update(extra)
    return result


def credentials(path):
    if not path.exists():
        write(path, {'schema': 1, 'lab': 'psy-k8s-local', 'passwords': {n: {'admin': secrets.token_hex(32), 'app': secrets.token_hex(32)} for n in DATABASES}})
    result = private_json(path)
    require(result.get('schema') == 1 and result.get('lab') == 'psy-k8s-local', 'Wrong credential identity')
    require(set(result['passwords']) == set(DATABASES), 'Unexpected credential service set')
    require(all(re.fullmatch('[0-9a-f]{64}', p) for v in result['passwords'].values() for p in v.values()), 'Invalid private password format')
    require(len({p for v in result['passwords'].values() for p in v.values()}) == 10, 'Every password must be independent')
    return result['passwords']


def pg_init(database):
    return '''#!/bin/sh
set -eu
app_password=$(cat /credentials/app-password)
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<SQL
CREATE ROLE psy_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$app_password';
CREATE DATABASE ''' + database + ''' OWNER psy_app;
REVOKE CONNECT ON DATABASE ''' + database + ''' FROM PUBLIC;
GRANT CONNECT ON DATABASE ''' + database + ''' TO psy_app;
\\connect ''' + database + '''
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
'''


def peer(namespace, labels):
    return {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': namespace}}, 'podSelector': {'matchLabels': labels}}


def scylla_args():
    # Scylla's outer parser forwards Seastar flags only in --name=value form.
    return ['--options-file', '/config/scylla.yaml', '--broadcast-rpc-address', '$(POD_IP)', '--smp=2', '--memory=4G', '--overprovisioned', '--lock-memory=0', '--developer-mode=1', '--log-to-stdout=1', '--log-to-syslog=0']


def manifests(passwords, images):
    result = [obj('ServiceAccount', 'psy-lab-data', automountServiceAccountToken=False)]
    result.append(obj('NetworkPolicy', 'psy-lab-data-default-deny', {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}, api='networking.k8s.io/v1'))
    result.append(obj('NetworkPolicy', 'psy-lab-data-dns', {'podSelector': {}, 'policyTypes': ['Egress'], 'egress': [{'to': [peer('kube-system', {'k8s-app': 'kube-dns'})], 'ports': [{'port': 53, 'protocol': p} for p in ['UDP', 'TCP']]}]}, api='networking.k8s.io/v1'))
    for name, d in DATABASES.items():
        labels = {**LABELS, 'app.kubernetes.io/name': name}
        access = {'psy.local/access-' + name: 'true'}
        sources = [peer(n, access) for n in (['psy-app'] if name.startswith('postgres') else ['psy-chain', 'psy-compute'])]
        sources.append({'namespaceSelector': {'matchLabels': {'psy.local/data-probe': 'true', 'psy.local/lab': 'psy-k8s-local'}}, 'podSelector': {'matchLabels': {'psy.local/data-probe': 'true', **access}}})
        result.append(obj('NetworkPolicy', 'psy-lab-allow-' + name, {'podSelector': {'matchLabels': {'app.kubernetes.io/name': name}}, 'policyTypes': ['Ingress'], 'ingress': [{'from': sources, 'ports': [{'port': d['port'], 'protocol': 'TCP'}]}]}, api='networking.k8s.io/v1'))
        pv = 'psy-lab-data-' + name
        result.append(obj('PersistentVolume', pv, {'capacity': {'storage': str(d['gib']) + 'Gi'}, 'volumeMode': 'Filesystem', 'accessModes': ['ReadWriteOnce'], 'persistentVolumeReclaimPolicy': 'Retain', 'storageClassName': 'psy-lab-local', 'local': {'path': '/srv/psy-lab/db-' + name}, 'claimRef': {'namespace': NS, 'name': pv}, 'nodeAffinity': {'required': {'nodeSelectorTerms': [{'matchExpressions': [{'key': 'kubernetes.io/hostname', 'operator': 'In', 'values': ['psy-lab-work-x4']}]}]}}}, ns=None))
        result.append(obj('PersistentVolumeClaim', pv, {'accessModes': ['ReadWriteOnce'], 'volumeMode': 'Filesystem', 'storageClassName': 'psy-lab-local', 'volumeName': pv, 'resources': {'requests': {'storage': str(d['gib']) + 'Gi'}}}))
        values = {'admin-password': passwords[name]['admin'], 'app-password': passwords[name]['app']}
        env, config = [], {}
        args, command = [], None
        mount = '/data'
        if name.startswith('postgres'):
            env = [{'name': 'POSTGRES_PASSWORD_FILE', 'value': '/credentials/admin-password'}, {'name': 'PGDATA', 'value': '/var/lib/postgresql/data/pgdata'}, {'name': 'POSTGRES_INITDB_ARGS', 'value': '--auth-host=scram-sha-256 --auth-local=trust'}]
            config = {'01-app.sh': pg_init(d['database'])}
            mount = '/var/lib/postgresql/data'
            args = ['postgres', '-c', 'shared_buffers=128MB', '-c', 'max_connections=50', '-c', 'max_wal_size=1GB']
        elif name == 'scylla':
            config = {'scylla.yaml': json.dumps({'cluster_name': 'psy-k8s-lab', 'workdir': '/var/lib/scylla', 'num_tokens': 16, 'listen_address': '127.0.0.1', 'rpc_address': '0.0.0.0', 'broadcast_rpc_address': '127.0.0.1', 'seed_provider': [{'class_name': 'org.apache.cassandra.locator.SimpleSeedProvider', 'parameters': [{'seeds': '127.0.0.1'}]}], 'endpoint_snitch': 'SimpleSnitch', 'authenticator': 'PasswordAuthenticator', 'authorizer': 'CassandraAuthorizer', 'commitlog_sync': 'batch', 'commitlog_sync_batch_window_in_ms': 2, 'commitlog_total_space_in_mb': 1024, 'api_address': '127.0.0.1', 'prometheus_address': '0.0.0.0', 'tablets_mode_for_new_keyspaces': 'disabled'})}
            # Override advertised RPC IP through a native CLI option. No shell
            # expansion or writable ConfigMap is needed in the container.
            env = [{'name': 'POD_IP', 'valueFrom': {'fieldRef': {'fieldPath': 'status.podIP'}}}]
            command = ['/usr/bin/scylla']
            args = scylla_args()
            mount = '/var/lib/scylla'
            for role, user, password in [('admin', 'lab_admin', values['admin-password']), ('app', 'psy_app', values['app-password']), ('bootstrap', 'cassandra', 'cassandra')]:
                values['cqlshrc-' + role] = '[authentication]\nusername = '+user+'\npassword = '+password+'\n'
        elif name == 'valkey':
            command = ['valkey-server']
            args = ['/config/valkey.conf']
            config = {'valkey.conf': 'bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\nsave ""\nmaxmemory 512mb\nmaxmemory-policy noeviction\naclfile /credentials/users.acl\n'}
            values['users.acl'] = 'user default off\nuser lab_admin on #'+hashlib.sha256(values['admin-password'].encode()).hexdigest()+' ~* &* +@all\nuser psy_app on #'+hashlib.sha256(values['app-password'].encode()).hexdigest()+' ~psy:* &psy:* +@all -@admin -@dangerous\n'
        else:
            args = ['--config', '/credentials/nats.conf']
            values['nats.conf'] = json.dumps({'server_name': 'psy-k8s-lab-nats', 'listen': '0.0.0.0:4222', 'http': '127.0.0.1:8222', 'max_payload': 8388608, 'jetstream': {'store_dir': '/data/jetstream', 'max_memory_store': 134217728, 'max_file_store': 4294967296}, 'authorization': {'users': [{'user': 'psy_app', 'password': values['app-password'], 'permissions': {'publish': ['psy.>', '$JS.API.>', '$JS.ACK.>'], 'subscribe': ['psy.>', '_INBOX.>']}}]}})
        result.append(obj('Secret', 'psy-lab-' + name, type='Opaque', data={k: base64.b64encode(v.encode()).decode() for k, v in values.items()}))
        if config:
            result.append(obj('ConfigMap', 'psy-lab-' + name, data=config))
        volumes = [{'name': 'data', 'persistentVolumeClaim': {'claimName': pv}}, {'name': 'credentials', 'secret': {'secretName': 'psy-lab-' + name, 'defaultMode': 0o440}}]
        mounts = [{'name': 'data', 'mountPath': mount}, {'name': 'credentials', 'mountPath': '/credentials', 'readOnly': True}]
        if config:
            volumes.append({'name': 'config', 'configMap': {'name': 'psy-lab-' + name, 'defaultMode': 0o444}})
            mounts.append({'name': 'config', 'mountPath': '/docker-entrypoint-initdb.d' if name.startswith('postgres') else '/config', 'readOnly': True})
        container = {'name': name, 'image': images[d['image']], 'args': args, 'env': env, 'ports': [{'name': 'client', 'containerPort': d['port']}], 'volumeMounts': mounts, 'resources': {'requests': {'cpu': '1' if name == 'scylla' else '100m', 'memory': d['request']}, 'limits': {'cpu': '2' if name == 'scylla' else '1', 'memory': d['memory']}}, 'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}, 'startupProbe': {'tcpSocket': {'port': 'client'}, 'periodSeconds': 5, 'failureThreshold': 120}, 'readinessProbe': {'tcpSocket': {'port': 'client'}, 'periodSeconds': 5}, 'livenessProbe': {'tcpSocket': {'port': 'client'}, 'periodSeconds': 20, 'failureThreshold': 6}}
        if command:
            container['command'] = command
        result.append(obj('StatefulSet', name, {'replicas': 1, 'serviceName': name, 'selector': {'matchLabels': {'app.kubernetes.io/name': name}}, 'persistentVolumeClaimRetentionPolicy': {'whenDeleted': 'Retain', 'whenScaled': 'Retain'}, 'template': {'metadata': {'labels': labels}, 'spec': {'serviceAccountName': 'psy-lab-data', 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 120, 'nodeSelector': {'psy.local/role': 'worker', 'kubernetes.io/hostname': 'psy-lab-work-x4'}, 'securityContext': {'runAsNonRoot': True, 'runAsUser': d['uid'], 'runAsGroup': d['gid'], 'fsGroup': d['gid'], 'fsGroupChangePolicy': 'OnRootMismatch', 'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [container], 'volumes': volumes}}}, api='apps/v1'))
        result.append(obj('Service', name, {'type': 'ClusterIP', 'selector': {'app.kubernetes.io/name': name}, 'ports': [{'name': 'client', 'port': d['port'], 'targetPort': 'client'}]}))
    return result


def prepare_script(inventory_hash, fs_uuid):
    require(re.fullmatch('[0-9a-f]{64}', inventory_hash), 'Invalid inventory hash')
    require(re.fullmatch('[0-9a-f-]{36}', fs_uuid), 'Expected virtual filesystem UUID required')
    text = '''#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 && $(systemd-detect-virt) == kvm ]] || exit 1
[[ $(cat /proc/sys/kernel/hostname) == psy-lab-work-x4 ]] || exit 1
[[ $(cat /etc/psy-k8s-lab) == INVENTORY:psy-lab-work-x4 ]] || exit 1
[[ ! -L /srv/psy-lab && $(findmnt -n -o UUID -T /srv/psy-lab) == FSUUID ]] || exit 1
[[ $(findmnt -n -o SOURCE -T /srv/psy-lab) == /dev/vdb ]] || exit 1
[[ $(df --output=avail -B1 /srv/psy-lab | tail -1) -ge 107374182400 ]] || exit 1
'''.replace('INVENTORY', inventory_hash).replace('FSUUID', fs_uuid)
    for name in DATABASES:
        text += '[[ ! -e /srv/psy-lab/db-'+name+' && ! -L /srv/psy-lab/db-'+name+' ]] || { echo "Existing database directory; inspect and preserve" >&2; exit 1; }\n'
    for name, d in DATABASES.items():
        text += f"install -d -m 750 -o {d['uid']} -g {d['gid']} /srv/psy-lab/db-{name}\n"
    return text + "echo 'Prepared only five new database directories inside the x4 lab VM'\n"


def render(inventory, platform, output, secrets_file, fs_uuid):
    sys.path.insert(0, str(HERE.parent / 'platform'))
    import lab
    config = lab.validate(json.loads(inventory.read_text()))
    require(lab.local_control(config) and config['network_confirmed'] and config['storage_confirmed'], 'Confirmed four-node topology required')
    require(output.is_absolute() and not output.exists(), 'Fresh absolute output directory required')
    expected = {n['name']: {'ip': n['ip'], 'role': n['role']} for n in config['nodes']}
    require(json.loads((platform / 'expected-nodes.json').read_text()) == expected, 'Platform/inventory mismatch')
    ih = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    require((platform.parent / 'inventory.sha256').read_text().strip() == ih, 'Inventory hash mismatch')
    root = HERE.parents[2]
    require(not subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True).strip(), 'Review/commit source before rendering a deployment')
    revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    p = credentials(secrets_file)
    versions = json.loads((HERE.parent / 'build/versions.json').read_text())['dependency_images']
    images = {n: ('docker.io/library/' if '/' not in versions[n].split('@')[0] else 'docker.io/') + versions[n] for n in ['postgres', 'scylla', 'valkey', 'nats']}
    require(all(re.fullmatch(r'docker.io/[a-z0-9_./-]+@sha256:[0-9a-f]{64}', i) for i in images.values()), 'Digest-pinned images required')
    output.mkdir(mode=0o700)
    bundle_id = secrets.token_hex(8)
    items = manifests(p, images)
    for item in items:
        item['metadata']['annotations'] = {'psy.local/data-bundle': bundle_id}
    write(output / 'resources.json', {'apiVersion': 'v1', 'kind': 'List', 'items': items})
    write(output / 'prepare-data.sh', prepare_script(ih, fs_uuid))
    for source in [HERE / 'databases.py', HERE / 'acceptance.py', HERE / 'probe.py']:
        shutil.copyfile(source, output / source.name)
        (output / source.name).chmod(0o600)
    write(output / 'deployment.json', {'lab': 'psy-k8s-local', 'source_revision': revision, 'inventory_sha256': ih, 'bundle_id': bundle_id, 'platform': str(platform), 'secrets_file': str(secrets_file), 'images': images, 'python_image': PYTHON_IMAGE, 'namespace': NS, 'services': DATABASES, 'credentials_sha256': digest(secrets_file), 'resources_sha256': digest(output / 'resources.json')})
    print('Rendered private five-service data bundle at ' + str(output))


def kubectl(*args, data=None, check=True, timeout=900):
    p = subprocess.run(['kubectl', *args], input=data, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        # Never emit Secret payloads or arbitrary DB errors containing credentials.
        raise RuntimeError('kubectl operation failed: ' + ' '.join(args[:5]) + '; inspect private evidence')
    return p


def guard(bundle):
    meta = private_json(bundle / 'deployment.json')
    require(meta['lab'] == 'psy-k8s-local' and meta['namespace'] == NS, 'Not the isolated data bundle')
    require(digest(Path(meta['secrets_file'])) == meta['credentials_sha256'], 'Private credentials changed; preserve existing data')
    private_json(Path(meta['secrets_file']))
    platform = Path(meta['platform'])
    subprocess.run([sys.executable, str(platform / 'check-cluster.py')], cwd=platform, check=True, timeout=60)
    require(digest(bundle / 'resources.json') == meta['resources_sha256'], 'Rendered resources changed')
    ns = json.loads(kubectl('get', 'namespace', NS, '-o', 'json').stdout)
    require(ns['metadata']['labels'].get('psy.local/lab') == meta['lab'], 'Unexpected data namespace owner')
    pods = json.loads(kubectl('get', 'pods', '-A', '--field-selector=spec.nodeName=psy-lab-cp-local', '-o', 'json').stdout)['items']
    require(not pods, 'Control plane must have zero Pods')
    existing = json.loads(kubectl('-n', NS, 'get', 'pods', '-o', 'json').stdout)['items']
    require(all(all(p['metadata'].get('labels', {}).get(k) == v for k, v in LABELS.items()) for p in existing), 'Foreign Pod in data namespace; default-deny must not disrupt it')
    return meta


def bootstrap_scylla(bundle):
    p = credentials(Path(json.loads((bundle / 'deployment.json').read_text())['secrets_file']))['scylla']
    prefix = 'cp /credentials/cqlshrc-'
    def cql(role, sql):
        command = prefix + role + ' /tmp/psy-cqlshrc; chmod 600 /tmp/psy-cqlshrc; exec cqlsh --cqlshrc=/tmp/psy-cqlshrc 127.0.0.1 9042'
        return kubectl('-n', NS, 'exec', '-i', 'scylla-0', '--', '/bin/sh', '-c', command, data=sql, check=False, timeout=45)
    admin = cql('admin', 'SELECT cluster_name FROM system.local;\n')
    role = 'admin' if admin.returncode == 0 and 'psy-k8s-lab' in admin.stdout else 'bootstrap'
    for attempt in range(30):
        ready = cql(role, 'SELECT cluster_name FROM system.local;\n')
        if ready.returncode == 0 and 'psy-k8s-lab' in ready.stdout:
            break
        require(attempt < 29, 'Scylla authentication bootstrap did not become ready')
        time.sleep(3)
    # Each password is validated as hex by credentials(); SQL input is never logged.
    sql = "CREATE ROLE IF NOT EXISTS lab_admin WITH PASSWORD = '"+p['admin']+"' AND SUPERUSER = true AND LOGIN = true;\nCREATE ROLE IF NOT EXISTS psy_app WITH PASSWORD = '"+p['app']+"' AND SUPERUSER = false AND LOGIN = true;\nCREATE KEYSPACE IF NOT EXISTS psy_lab WITH replication = {'class': 'NetworkTopologyStrategy', 'replication_factor': 1};\nGRANT ALL PERMISSIONS ON KEYSPACE psy_lab TO psy_app;\nALTER ROLE cassandra WITH LOGIN = false;\n"
    result = cql(role, sql)
    require(result.returncode == 0 and not any(s in result.stdout + result.stderr for s in ['Unauthorized', 'InvalidRequest', 'SyntaxException', 'AuthenticationFailed']), 'Scylla role bootstrap failed; preserve database and inspect privately')
    result = cql('admin', 'SELECT cluster_name FROM system.local;\n')
    require(result.returncode == 0 and 'psy-k8s-lab' in result.stdout, 'Scylla dedicated admin verification failed')


def install(bundle):
    meta = guard(bundle)
    items = json.loads((bundle / 'resources.json').read_text())['items']
    # Refuse to overwrite unrelated or pre-existing state. Same-bundle partial
    # construction can resume by skipping only its exact owned resource names.
    for item in items:
        args = ['get', item['kind'], item['metadata']['name'], '--ignore-not-found', '-o', 'json']
        if item['metadata'].get('namespace'):
            args += ['-n', item['metadata']['namespace']]
        existing = kubectl(*args).stdout.strip()
        if existing:
            old = json.loads(existing)['metadata']
            require(old.get('annotations', {}).get('psy.local/data-bundle') == meta['bundle_id'] and all(old.get('labels', {}).get(k) == v for k, v in LABELS.items()), 'Existing foreign resource: ' + item['kind'] + '/' + item['metadata']['name'])
    for item in items:
        args = ['get', item['kind'], item['metadata']['name'], '--ignore-not-found', '-o', 'json']
        if item['metadata'].get('namespace'):
            args += ['-n', item['metadata']['namespace']]
        if not kubectl(*args).stdout.strip():
            kubectl('create', '-f', '-', data=json.dumps(item))
            print('Created '+item['kind']+'/'+item['metadata']['name'], flush=True)
    for name in DATABASES:
        kubectl('-n', NS, 'rollout', 'status', 'statefulset/' + name, '--timeout=10m')
        print(name + ' ready', flush=True)
    bootstrap_scylla(bundle)
    pvcs = json.loads(kubectl('-n', NS, 'get', 'pvc', '-o', 'json').stdout)['items']
    require(all(any(p['metadata']['name'] == 'psy-lab-data-'+n and p['status']['phase'] == 'Bound' for p in pvcs) for n in DATABASES), 'Five bound database PVCs required')
    print('Five database services ready; run acceptance before declaring completion')


def repair_scylla(bundle, evidence):
    require(evidence.is_absolute() and not evidence.exists(), 'Fresh absolute repair evidence required')
    meta = guard(bundle)
    original = next(x for x in json.loads((bundle / 'resources.json').read_text())['items'] if x['kind'] == 'StatefulSet' and x['metadata']['name'] == 'scylla')
    current = json.loads(kubectl('-n', NS, 'get', 'statefulset', 'scylla', '-o', 'json').stdout)
    require(current['metadata'].get('annotations', {}).get('psy.local/data-bundle') == meta['bundle_id'], 'Foreign Scylla StatefulSet')
    before = current['spec']['template']['spec']['containers'][0]
    require(before['image'] == meta['images']['scylla'], 'Scylla image changed; inspect before repair')
    require(before['args'] in [original['spec']['template']['spec']['containers'][0]['args'], scylla_args()], 'Unexpected Scylla arguments; refusing to overwrite')
    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': current['metadata']['uid']}, {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']}, {'op': 'test', 'path': '/spec/template/spec/containers/0/args', 'value': before['args']}, {'op': 'replace', 'path': '/spec/template/spec/containers/0/args', 'value': scylla_args()}]
    write(evidence, {'repair': 'Scylla Seastar CLI argument format only', 'bundle_id': meta['bundle_id'], 'statefulset_uid': current['metadata']['uid'], 'before_args': before['args'], 'after_args': scylla_args(), 'volumes_preserved': True})
    if before['args'] != scylla_args():
        kubectl('-n', NS, 'patch', 'statefulset', 'scylla', '--type=json', '-p', json.dumps(patch))
    print('Patched only owned Scylla arguments; existing PVC and credentials retained')


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('plan')
    r = sub.add_parser('render')
    for arg in ['inventory', 'platform', 'output', 'secrets-file']:
        r.add_argument('--'+arg, type=Path, required=True)
    r.add_argument('--virtual-fs-uuid', required=True)
    i = sub.add_parser('install')
    i.add_argument('--bundle', type=Path, required=True)
    fix = sub.add_parser('repair-scylla-args')
    fix.add_argument('--bundle', type=Path, required=True)
    fix.add_argument('--evidence', type=Path, required=True)
    a = p.parse_args()
    if a.command == 'plan':
        print(json.dumps({'namespace': NS, 'databases': DATABASES, 'new_pvc_gib': sum(d['gib'] for d in DATABASES.values()), 'node': 'psy-lab-work-x4', 'external_services': 0, 'deployment': False}, indent=2))
    elif a.command == 'render':
        render(a.inventory, a.platform.resolve(), a.output, a.secrets_file, a.virtual_fs_uuid)
    elif a.command == 'install':
        install(a.bundle.resolve())
    else:
        repair_scylla(a.bundle.resolve(), a.evidence)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
