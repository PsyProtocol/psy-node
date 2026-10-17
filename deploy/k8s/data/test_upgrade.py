#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('upgrade', Path(__file__).with_name('upgrade-resources.py'))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def fixture():
    meta={'uid':'pv-uid','name':'psy-lab-data-valkey','resourceVersion':'1'}
    pv={'metadata':meta,'status':{'phase':'Released'},'spec':{'persistentVolumeReclaimPolicy':'Retain','storageClassName':'psy-lab-local',
        'capacity':{'storage':'5Gi'},'claimRef':{'namespace':'psy-data','name':meta['name'],'uid':'old-claim'},
        'local':{'path':'/srv/psy-lab/db-valkey'},'nodeAffinity':{'required':{'nodeSelectorTerms':[{'matchExpressions':[
            {'key':'kubernetes.io/hostname','operator':'In','values':['psy-lab-work-x4']}]}]}}}}
    pvc={'metadata':{'name':meta['name'],'uid':'old-claim','labels':{},'annotations':{}},
         'spec':{'volumeName':meta['name'],'storageClassName':'psy-lab-local','resources':{'requests':{'storage':'5Gi'}}},'status':{'phase':'Bound'}}
    return pv,pvc


class UpgradeSafety(unittest.TestCase):
    def test_volume_guard_rejects_delete_policy_foreign_path_node_and_binding(self):
        pv,pvc=fixture()
        self.assertEqual(upgrade.storage_pair(pv,pvc,'valkey'),pvc['metadata']['name'])
        for change in [lambda p:p['spec'].update(persistentVolumeReclaimPolicy='Delete'),
                       lambda p:p['spec']['local'].update(path='/data/foreign'),
                       lambda p:p['spec']['claimRef'].update(uid='other-claim'),
                       lambda p:p['spec']['nodeAffinity']['required']['nodeSelectorTerms'][0]['matchExpressions'][0].update(values=['psy-lab-cp-local'])]:
            broken=copy.deepcopy(pv);change(broken)
            with self.assertRaises(ValueError):upgrade.storage_pair(broken,pvc,'valkey')

    def test_unchanged_size_avoids_claim_deletion_and_shrink_is_rejected(self):
        pv,pvc=fixture()
        with patch.object(upgrade.db,'kubectl') as api:
            self.assertIs(upgrade.rebind(pv,pvc,5,Path('/unused')),pvc)
            with self.assertRaises(ValueError):upgrade.rebind(pv,pvc,4,Path('/unused'))
            api.assert_not_called()

    def test_rebind_keeps_pv_and_directory_and_deletes_only_expected_claim_uid(self):
        pv,pvc=fixture();new=copy.deepcopy(pvc);new['metadata']['uid']='new-claim'
        calls=[]
        def api(*args,**kwargs):
            calls.append((args,kwargs))
            return subprocess.CompletedProcess(args,0,'','')
        with tempfile.TemporaryDirectory() as directory,patch.object(upgrade,'get',side_effect=[pv,new,pv]),\
             patch.object(upgrade,'wait_absent'),patch.object(upgrade.db,'kubectl',side_effect=api):
            self.assertEqual(upgrade.rebind(pv,pvc,20,Path(directory))['metadata']['uid'],'new-claim')
            delete=next(c for c in calls if c[0][0]=='delete')
            self.assertEqual(json.loads(delete[1]['data'])['preconditions'],{'uid':'old-claim'})
            created=json.loads(next(c for c in calls if c[0][0]=='create')[1]['data'])
            self.assertEqual(created['spec']['volumeName'],pv['metadata']['name'])
            self.assertEqual(created['spec']['resources']['requests']['storage'],'20Gi')
            edit=json.loads(next(c for c in calls if c[0][0]=='patch')[1]['data'])
            self.assertEqual(edit['metadata'],{'uid':'pv-uid','resourceVersion':'1'})
            self.assertEqual(edit['spec']['claimRef']['uid'],None)
            self.assertEqual(set(edit['spec']),{'capacity','claimRef'})

    def test_pv_release_controller_conflict_is_retried_with_fresh_version(self):
        pv,pvc=fixture();stale=copy.deepcopy(pv);stale['status']['phase']='Bound'
        newer=copy.deepcopy(pv);newer['metadata']['resourceVersion']='2'
        new_claim=copy.deepcopy(pvc);new_claim['metadata']['uid']='replacement'
        with tempfile.TemporaryDirectory() as directory,patch.object(upgrade,'get',side_effect=[stale,pv,newer,new_claim,newer]),\
             patch.object(upgrade,'wait_absent'),patch.object(upgrade,'rebind_patch',side_effect=[False,True]) as edit,\
             patch.object(upgrade.db,'kubectl'),patch.object(upgrade.time,'sleep'):
            upgrade.rebind(pv,pvc,20,Path(directory))
            self.assertEqual([c.args[0]['metadata']['resourceVersion'] for c in edit.call_args_list],['1','2'])

    def test_only_resource_version_conflicts_are_retryable(self):
        pv,_=fixture()
        with patch.object(upgrade.db,'kubectl',return_value=subprocess.CompletedProcess([],1,'','Error from server (Conflict): changed')):
            self.assertFalse(upgrade.rebind_patch(pv,20))
        with patch.object(upgrade.db,'kubectl',return_value=subprocess.CompletedProcess([],1,'','Forbidden')):
            with self.assertRaisesRegex(RuntimeError,'other than'):
                upgrade.rebind_patch(pv,20)

    def test_patch_payloads_use_stdin_even_for_secret_configuration(self):
        current={'metadata':{'name':'psy-lab-nats','uid':'same-secret','resourceVersion':'5'}}
        with patch.object(upgrade.db,'kubectl') as api:
            upgrade.patch('Secret',current,[{'op':'replace','path':'/data/nats.conf','value':'sensitive-fixture'}])
            self.assertNotIn('sensitive-fixture',' '.join(api.call_args.args))
            self.assertIn('--patch-file=/dev/stdin',api.call_args.args)
            self.assertEqual(json.loads(api.call_args.kwargs['data'])[0]['value'],'same-secret')


if __name__=='__main__':unittest.main(verbosity=2)
