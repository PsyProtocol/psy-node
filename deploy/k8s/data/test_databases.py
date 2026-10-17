#!/usr/bin/env python3
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import databases as db
import acceptance
import probe


class DataTests(unittest.TestCase):
    def passwords(self):
        return {n: {'admin': f'{2*i+1:064x}', 'app': f'{2*i+2:064x}'} for i,n in enumerate(db.DATABASES)}

    def objects(self):
        return db.manifests(self.passwords(), {n:'docker.io/library/'+n+'@sha256:'+'a'*64 for n in ['postgres','scylla','valkey','nats']})

    def test_credentials_are_private_independent_and_reused_without_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'credentials.json'
            first=db.credentials(p)
            self.assertEqual(first, db.credentials(p))
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len({v for service in first.values() for v in service.values()}), 10)
            before=p.read_bytes()
            p.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'mode 600'):
                db.credentials(p)
            self.assertEqual(p.read_bytes(),before)

    def test_storage_is_prebound_retained_separate_and_pods_cannot_use_control_plane(self):
        items=self.objects()
        self.assertEqual(len([p for p in items if p['kind']=='StatefulSet']),5)
        self.assertEqual(sum(x['gib'] for x in db.DATABASES.values()),80)
        for p in items:
            if p['kind']=='PersistentVolume':
                self.assertEqual(p['spec']['persistentVolumeReclaimPolicy'],'Retain')
                self.assertEqual(p['spec']['claimRef']['namespace'],'psy-data')
                self.assertTrue(p['spec']['local']['path'].startswith('/srv/psy-lab/db-'))
                self.assertEqual(p['spec']['nodeAffinity']['required']['nodeSelectorTerms'][0]['matchExpressions'][0]['values'],['psy-lab-work-x4'])
            if p['kind']=='StatefulSet':
                spec=p['spec']['template']['spec']
                self.assertEqual(spec['nodeSelector']['kubernetes.io/hostname'],'psy-lab-work-x4')
                self.assertTrue(spec['securityContext']['runAsNonRoot'])
                self.assertFalse(spec['automountServiceAccountToken'])
                self.assertNotIn('tolerations',spec)
                self.assertNotIn('hostNetwork',spec)
            if p['kind']=='Service':
                self.assertEqual(p['spec']['type'],'ClusterIP')
                self.assertNotIn('nodePort',p['spec']['ports'][0])

    def test_credentials_never_enter_configmaps_or_process_arguments(self):
        items=self.objects()
        public=[p for p in items if p['kind']!='Secret']
        for value in [v for service in self.passwords().values() for v in service.values()]:
            self.assertNotIn(value,json.dumps(public))
        for p in items:
            if p['kind']=='StatefulSet':
                c=p['spec']['template']['spec']['containers'][0]
                self.assertIn('@sha256:',c['image'])
        pg=db.pg_init('psy_services')
        self.assertIn('NOSUPERUSER NOCREATEDB NOCREATEROLE',pg)
        self.assertIn('REVOKE CONNECT',pg)
        scylla=next(p for p in items if p['kind']=='ConfigMap' and p['metadata']['name']=='psy-lab-scylla')
        cfg=json.loads(scylla['data']['scylla.yaml'])
        self.assertEqual(cfg['authenticator'],'PasswordAuthenticator')
        self.assertEqual(cfg['authorizer'],'CassandraAuthorizer')

    def test_policy_peers_require_both_namespace_and_access_label(self):
        policies=[p for p in self.objects() if p['kind']=='NetworkPolicy']
        self.assertEqual(len(policies),7)
        deny=next(p for p in policies if p['metadata']['name'].endswith('default-deny'))
        self.assertEqual(deny['spec']['ingress'],[])
        self.assertEqual(deny['spec']['egress'],[])
        for p in policies:
            for rule in p['spec'].get('ingress',[]):
                for peer in rule['from']:
                    self.assertIn('namespaceSelector',peer)
                    self.assertIn('podSelector',peer)
                    self.assertTrue(any(k.startswith('psy.local/access-') for k in peer['podSelector']['matchLabels']))

    def test_probe_secrets_are_app_only_and_denied_clients_have_no_credentials(self):
        meta={'images':{n:n+'@sha256:'+'a'*64 for n in ['postgres','scylla']},'python_image':db.PYTHON_IMAGE}
        ns,items=acceptance.fixtures(meta,'c0ffee00',[x for x in self.objects() if x['kind']=='Secret'])
        for secret in [x for x in items if x['kind']=='Secret']:
            self.assertNotIn('admin-password',secret['data'])
            self.assertNotIn('cqlshrc-admin',secret['data'])
        for pod in [x for x in items if x['kind']=='Pod']:
            spec=pod['spec']
            self.assertEqual(spec['restartPolicy'],'Never')
            self.assertFalse(spec['automountServiceAccountToken'])
            self.assertIn(spec['nodeSelector']['kubernetes.io/hostname'],acceptance.WORKERS)
            if pod['metadata']['name'].startswith('denied-'):
                self.assertFalse(any('secret' in v for v in spec['volumes']))
        self.assertEqual(len(ns),2)

    def test_tcp_rejection_does_not_accept_dns_or_unrelated_os_errors(self):
        with patch.object(socket,'create_connection',side_effect=ConnectionRefusedError):
            probe.tcp({'postgres-services':5432},True)
        for error in [socket.gaierror('bad DNS'), PermissionError('local failure')]:
            with patch.object(socket,'create_connection',side_effect=error),self.assertRaises(type(error)):
                probe.tcp({'postgres-services':5432},True)
        with patch.object(socket,'create_connection') as connect:
            with self.assertRaises(ValueError):
                probe.tcp({'postgres-services':5432},True)

    def test_guest_directory_script_rejects_wrong_identity_before_writing(self):
        script=db.prepare_script('a'*64,'5593a211-3685-40dd-b341-cbb79b26d722')
        self.assertNotIn('mkfs',script)
        self.assertNotIn('chown -R',script)
        self.assertLess(script.index('cat /etc/psy-k8s-lab'),script.index('install -d'))
        self.assertLess(script.index('findmnt'),script.index('install -d'))
        with self.assertRaises(ValueError):
            db.prepare_script('a'*64,'bad; reboot')
        if os.geteuid()!=0:
            self.assertNotEqual(subprocess.run(['bash','-c',script],capture_output=True).returncode,0)

    def test_scylla_bootstrap_uses_cluster_identity_not_cassandra_compatibility_version(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle=Path(directory)
            secret=bundle/'credentials.json'
            db.credentials(secret)
            db.write(bundle/'deployment.json',{'secrets_file':str(secret)})
            calls=[]
            def cql(*args, **kwargs):
                calls.append((args,kwargs))
                self.assertNotIn('release_version',kwargs['data'])
                return subprocess.CompletedProcess(args,0,'cluster_name\npsy-k8s-lab\n(1 rows)\n','')
            with patch.object(db,'kubectl',side_effect=cql):
                db.bootstrap_scylla(bundle)
            self.assertTrue(any('ALTER ROLE cassandra WITH LOGIN = false' in kw['data'] for _,kw in calls))
            self.assertGreaterEqual(sum('SELECT cluster_name' in kw['data'] for _,kw in calls),3)

    def test_scylla_seastar_options_are_single_arguments(self):
        args=db.scylla_args()
        for flag in ['--smp=2','--memory=4G','--overprovisioned','--lock-memory=0','--log-to-stdout=1','--log-to-syslog=0']:
            self.assertIn(flag,args)
        self.assertNotIn('--smp',args)
        self.assertNotIn('--memory',args)

    def test_plan_is_offline_and_does_not_create_or_contact_cluster(self):
        p=subprocess.run([sys.executable,str(db.HERE/'databases.py'),'plan'],capture_output=True,text=True,check=True)
        value=json.loads(p.stdout)
        self.assertFalse(value['deployment'])
        self.assertEqual(value['external_services'],0)
        self.assertEqual(value['new_pvc_gib'],80)


if __name__=='__main__':
    unittest.main(verbosity=2)
