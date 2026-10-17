#!/usr/bin/env python3
"""Real five-service read/write/auth/NetworkPolicy/Pod-recreation acceptance."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import databases as db

WORKERS = ['psy-lab-work-'+r for r in ['x2', 'x3', 'x4']]


def fixtures(meta, run, secret_objects):
    allowed, forbidden = 'psy-db-probe-'+run, 'psy-db-denied-'+run
    namespaces, items = [], []
    owner = {'psy.local/lab': 'psy-k8s-local', 'psy.local/data-test-run': run}
    for ns in [allowed, forbidden]:
        labels = {**owner, 'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.35'}
        if ns == allowed:
            labels['psy.local/data-probe'] = 'true'
        namespaces.append({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns, 'labels': labels}})
        items.append(db.obj('ServiceAccount', 'probe', ns=ns, automountServiceAccountToken=False))
        items.append(db.obj('ConfigMap', 'probe-code', ns=ns, data={'probe.py': (Path(__file__).parent / 'probe.py').read_text()}))
        items.append(db.obj('NetworkPolicy', 'default-deny', {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}, ns=ns, api='networking.k8s.io/v1'))
        egress = [{'to': [db.peer('kube-system', {'k8s-app': 'kube-dns'})], 'ports': [{'port': 53, 'protocol': p} for p in ['TCP', 'UDP']]}]
        for name, d in db.DATABASES.items():
            egress.append({'to': [db.peer(db.NS, {'app.kubernetes.io/name': name})], 'ports': [{'port': d['port'], 'protocol': 'TCP'}]})
        items.append(db.obj('NetworkPolicy', 'probe-egress', {'podSelector': {}, 'policyTypes': ['Egress'], 'egress': egress}, ns=ns, api='networking.k8s.io/v1'))
    for secret in secret_objects:
        name = secret['metadata']['name']
        data = {'app-password': secret['data']['app-password']}
        if name.endswith('-scylla'):
            data['cqlshrc-app'] = secret['data']['cqlshrc-app']
        items.append(db.obj('Secret', name, ns=allowed, data=data, type='Opaque'))
    access = {'psy.local/access-'+n: 'true' for n in db.DATABASES}
    def pod(name, ns, worker, grant, clients):
        labels = {**owner, 'psy.local/data-probe': 'true', **(access if grant else {})}
        volumes = [{'name': 'code', 'configMap': {'name': 'probe-code'}}, {'name': 'tmp', 'emptyDir': {'sizeLimit': '32Mi'}}]
        mounts = [{'name': 'code', 'mountPath': '/probe', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}]
        if clients:
            for n in db.DATABASES:
                volumes.append({'name': n, 'secret': {'secretName': 'psy-lab-'+n, 'defaultMode': 0o440}})
                mounts.append({'name': n, 'mountPath': '/credentials/'+n, 'readOnly': True})
        containers = []
        for kind, image in [('python', meta['python_image'])]+([('postgres', meta['images']['postgres']), ('scylla', meta['images']['scylla'])] if clients else []):
            containers.append({'name': kind, 'image': image, 'command': ['python3', '-c', 'import time;time.sleep(7200)'] if kind == 'python' else ['sleep', '7200'], 'env': [{'name': 'HOME', 'value': '/tmp'}], 'volumeMounts': mounts, 'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '500m', 'memory': '512Mi' if kind == 'scylla' else '128Mi'}}, 'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}})
        return db.obj('Pod', name, {'serviceAccountName': 'probe', 'automountServiceAccountToken': False, 'activeDeadlineSeconds': 3600, 'restartPolicy': 'Never', 'nodeSelector': {'psy.local/role': 'worker', 'kubernetes.io/hostname': worker}, 'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000, 'fsGroup': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': containers, 'volumes': volumes}, ns=ns, metadata={'name': name, 'namespace': ns, 'labels': labels})
    items += [pod('probe-'+role, allowed, worker, True, True) for role, worker in zip(['x2', 'x3', 'x4'], WORKERS)]
    items += [pod('denied-label', allowed, WORKERS[0], False, False), pod('denied-namespace', forbidden, WORKERS[1], True, False)]
    return namespaces, items


def wait_until(action, why, seconds=90):
    end = time.monotonic()+seconds
    while not action():
        db.require(time.monotonic() < end, why)
        time.sleep(2)


def run(bundle, evidence, prior_run=None):
    db.require(prior_run is None or (len(prior_run) == 8 and all(c in '0123456789abcdef' for c in prior_run)), 'Prior acceptance run must be eight hex characters')
    db.require(evidence.is_absolute() and not evidence.exists(), 'Fresh absolute evidence directory required')
    meta = db.guard(bundle)
    evidence.mkdir(parents=True, mode=0o700)
    result = {'run_id': uuid.uuid4().hex[:8], 'passed': False, 'checks': [], 'pod_recreations': []}
    run_id = result['run_id']
    allowed, forbidden = 'psy-db-probe-'+run_id, 'psy-db-denied-'+run_id
    objects = json.loads((bundle / 'resources.json').read_text())['items']
    secret_objects = [x for x in objects if x['kind'] == 'Secret']
    namespaces, items = fixtures(meta, run_id, secret_objects)
    db.write(evidence / 'fixtures.json', {'namespaces': namespaces, 'items': [x for x in items if x['kind'] != 'Secret']})
    result['namespaces'] = [allowed, forbidden]
    def record(name):
        result['checks'].append(name)
        print(name, flush=True)
    def create(values):
        db.kubectl('create', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': values}))
    def execute(ns, pod, container, command, data=None, check=True):
        p = db.kubectl('-n', ns, 'exec', '-i', pod, '-c', container, '--', *command, data=data, check=False, timeout=180)
        if check:
            db.require(p.returncode == 0, 'Probe execution failed: '+ns+'/'+pod+'/'+container)
        return p
    def python_probe(ns, pod, op, identity, phase, check=True):
        return execute(ns, pod, 'python', ['python3', '/probe/probe.py', op, identity, phase], check=check)
    def pg(pod, name, identity, phase):
        database = db.DATABASES[name]['database']
        base = 'export PGPASSWORD="$(cat /credentials/'+name+'/app-password)"; exec psql -X -At -v ON_ERROR_STOP=1 -h '+name+'.psy-data.svc.cluster.local -U psy_app -d '+database
        body = 'persistent-'+identity
        sql = ''
        if phase == 'write':
            sql = "CREATE TABLE IF NOT EXISTS psy_lab_probe (id text PRIMARY KEY, value text NOT NULL); INSERT INTO psy_lab_probe VALUES ('"+identity+"', '"+body+"') ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value; INSERT INTO psy_lab_probe VALUES ('crud-"+identity+"','one'); UPDATE psy_lab_probe SET value='two' WHERE id='crud-"+identity+"'; DELETE FROM psy_lab_probe WHERE id='crud-"+identity+"';\n"
        sql += "SELECT value FROM psy_lab_probe WHERE id='"+identity+"'; SELECT rolsuper OR rolcreatedb OR rolcreaterole FROM pg_roles WHERE rolname=current_user;\n"
        p = execute(allowed, pod, 'postgres', ['sh', '-c', base], sql)
        db.require(body in p.stdout.splitlines() and p.stdout.splitlines()[-1] == 'f', 'PostgreSQL read/least privilege failed: '+name)
        wrong = 'export PGPASSWORD=deliberately-invalid; exec psql -X -At -h '+name+'.psy-data.svc.cluster.local -U psy_app -d '+database+' -c "SELECT 1"'
        p = execute(allowed, pod, 'postgres', ['sh', '-c', wrong], check=False)
        db.require(p.returncode != 0 and 'password authentication failed' in p.stderr, 'PostgreSQL wrong-password rejection failed')
        other = 'postgres-envio' if name == 'postgres-services' else 'postgres-services'
        p = execute(allowed, pod, 'postgres', ['sh', '-c', base.replace('/'+name+'/app-password', '/'+other+'/app-password')], 'SELECT 1;\n', check=False)
        db.require(p.returncode != 0 and 'password authentication failed' in p.stderr, 'Two PostgreSQL instances must reject each other credentials')
    def cql(pod, identity, phase):
        base = 'cp /credentials/scylla/cqlshrc-app /tmp/cqlshrc; chmod 600 /tmp/cqlshrc; exec cqlsh --cqlshrc=/tmp/cqlshrc scylla.psy-data.svc.cluster.local 9042'
        body = 'persistent-'+identity
        sql = ''
        if phase == 'write':
            sql = "CREATE TABLE IF NOT EXISTS psy_lab.probe (id text PRIMARY KEY, value text); INSERT INTO psy_lab.probe (id,value) VALUES ('"+identity+"','"+body+"'); INSERT INTO psy_lab.probe (id,value) VALUES ('crud-"+identity+"','one'); UPDATE psy_lab.probe SET value='two' WHERE id='crud-"+identity+"'; DELETE FROM psy_lab.probe WHERE id='crud-"+identity+"';\n"
        sql += "SELECT value FROM psy_lab.probe WHERE id='"+identity+"';\n"
        p = execute(allowed, pod, 'scylla', ['sh', '-c', base], sql)
        db.require(body in p.stdout and not any(x in p.stdout+p.stderr for x in ['Unauthorized', 'SyntaxException', 'InvalidRequest']), 'Scylla CRUD/read failed')
        p = execute(allowed, pod, 'scylla', ['sh', '-c', base], 'CREATE ROLE psy_lab_forbidden WITH LOGIN = true;\n', check=False)
        db.require('Unauthorized' in p.stdout+p.stderr, 'Scylla app must not administer roles')
        bad = "printf '[authentication]\\nusername = psy_app\\npassword = deliberately-invalid\\n' > /tmp/cqlshrc-bad; chmod 600 /tmp/cqlshrc-bad; exec cqlsh --cqlshrc=/tmp/cqlshrc-bad scylla.psy-data.svc.cluster.local 9042"
        p = execute(allowed, pod, 'scylla', ['sh', '-c', bad], 'SELECT release_version FROM system.local;\n', check=False)
        db.require(p.returncode != 0 and any(s in p.stdout+p.stderr for s in ['AuthenticationFailed', 'Failed to authenticate', 'Provided username']), 'Scylla wrong-password rejection failed')
    try:
        # Check collisions before creating namespaces, ServiceAccounts or Secrets.
        for ns in [allowed, forbidden]:
            db.require(not db.kubectl('get', 'namespace', ns, '--ignore-not-found', '-o', 'json').stdout.strip(), 'Probe namespace already exists')
        create(namespaces)
        create([x for x in items if x['kind'] != 'Pod'])
        create([x for x in items if x['kind'] == 'Pod'])
        for ns in [allowed, forbidden]:
            db.kubectl('-n', ns, 'wait', '--for=condition=Ready', 'pod', '--all', '--timeout=10m')
        for x in items:
            if x['kind'] == 'Pod':
                actual = json.loads(db.kubectl('-n', x['metadata']['namespace'], 'get', 'pod', x['metadata']['name'], '-o', 'json').stdout)
                db.require(actual['spec']['nodeName'] == x['spec']['nodeSelector']['kubernetes.io/hostname'], 'Unexpected probe scheduling')
        if prior_run:
            result['prior_run'] = prior_run
            for worker in WORKERS:
                pod = 'probe-' + worker.rsplit('-', 1)[1]
                identity = hashlib.sha256((prior_run + worker).encode()).hexdigest()[:8]
                for name in ['postgres-services', 'postgres-envio']:
                    pg(pod, name, identity, 'read')
                cql(pod, identity, 'read')
                for operation in ['valkey', 'nats']:
                    python_probe(allowed, pod, operation, identity, 'read')
                record(worker + ' five services prior-run persistent read passed')
        for phase in ['write', 'read']:
            if phase == 'read':
                old_pvcs = json.loads(db.kubectl('-n', db.NS, 'get', 'pvc', '-o', 'json').stdout)
                # Gracefully recreate exact owned database Pods, retaining PVCs.
                for name in db.DATABASES:
                    pod = json.loads(db.kubectl('-n', db.NS, 'get', 'pod', name+'-0', '-o', 'json').stdout)
                    stateful = json.loads(db.kubectl('-n', db.NS, 'get', 'statefulset', name, '-o', 'json').stdout)
                    db.require(stateful['metadata'].get('annotations', {}).get('psy.local/data-bundle') == meta['bundle_id'], 'Foreign StatefulSet')
                    db.require(any(o['uid'] == stateful['metadata']['uid'] and o['kind'] == 'StatefulSet' for o in pod['metadata']['ownerReferences']), 'Foreign database Pod')
                    db.kubectl('-n', db.NS, 'delete', 'pod', name+'-0', '--wait=true', '--timeout=3m')
                    def replacement():
                        p = db.kubectl('-n', db.NS, 'get', 'pod', name+'-0', '--ignore-not-found', '-o', 'json')
                        return p.stdout.strip() and json.loads(p.stdout)['metadata']['uid'] != pod['metadata']['uid']
                    wait_until(replacement, 'No replacement database Pod: '+name)
                    db.kubectl('-n', db.NS, 'wait', '--for=condition=Ready', 'pod/'+name+'-0', '--timeout=10m')
                    new = json.loads(db.kubectl('-n', db.NS, 'get', 'pod', name+'-0', '-o', 'json').stdout)
                    result['pod_recreations'].append({'name': name, 'old_uid': pod['metadata']['uid'], 'new_uid': new['metadata']['uid']})
                    record(name+' Pod recreated on the same PVC')
                new_pvcs = json.loads(db.kubectl('-n', db.NS, 'get', 'pvc', '-o', 'json').stdout)
                db.require({p['metadata']['name']: p['metadata']['uid'] for p in old_pvcs['items']} == {p['metadata']['name']: p['metadata']['uid'] for p in new_pvcs['items']}, 'PVC identity changed during recreation')
            for worker in WORKERS:
                pod = 'probe-'+worker.rsplit('-', 1)[1]
                identity = hashlib.sha256((run_id+worker).encode()).hexdigest()[:8]
                for name in ['postgres-services', 'postgres-envio']:
                    pg(pod, name, identity, phase)
                cql(pod, identity, phase)
                for op in ['valkey', 'nats']:
                    python_probe(allowed, pod, op, identity, phase)
                record(worker+' five services '+('CRUD/auth/least-privilege' if phase == 'write' else 'persistent read after recreation')+' passed')
        for ns, pod in [(allowed, 'denied-label'), (forbidden, 'denied-namespace')]:
            python_probe(ns, pod, 'tcp', run_id, 'deny')
            if ns == allowed:
                keys = ['psy.local/access-'+name for name in db.DATABASES]
                db.kubectl('-n', ns, 'label', 'pod', pod, *[k+'=true' for k in keys])
                revoke = ['-n', ns, 'label', 'pod', pod, *[k+'-' for k in keys]]
            else:
                db.kubectl('label', 'namespace', ns, 'psy.local/data-probe=true')
                revoke = ['label', 'namespace', ns, 'psy.local/data-probe-']
            try:
                wait_until(lambda: python_probe(ns, pod, 'tcp', run_id, 'allow', check=False).returncode == 0, 'Grant did not restore blocked client')
            finally:
                db.kubectl(*revoke)
            wait_until(lambda: python_probe(ns, pod, 'tcp', run_id, 'deny', check=False).returncode == 0, 'Revocation did not reject client')
            record(pod+' five-port deny/grant/revoke passed')
        for role in ['x2', 'x3', 'x4']:
            python_probe(allowed, 'probe-'+role, 'tcp', run_id, 'allow')
        db.guard(bundle)
        result['passed'] = True
        # Keep DB test rows/streams as persistence evidence, remove only this
        # run's client fixtures after rechecking exact namespace ownership.
        for ns in [allowed, forbidden]:
            current = json.loads(db.kubectl('get', 'namespace', ns, '-o', 'json').stdout)
            db.require(current['metadata']['labels'].get('psy.local/data-test-run') == run_id, 'Cleanup owner changed')
            db.kubectl('delete', 'namespace', ns, '--wait=true', '--timeout=3m')
        result['probe_namespaces_removed'] = True
        print('Five-service database acceptance passed', flush=True)
    except Exception as exc:
        result['error'] = str(exc)
        result['passed'] = False
        raise
    finally:
        db.write(evidence / 'result.json', result)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--prior-run', help='Also read the persistent records/messages of a previous successful acceptance run')
    args = p.parse_args()
    run(args.bundle.resolve(), args.evidence, args.prior_run)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
