#!/usr/bin/env python3
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('resize', Path(__file__).with_name('resize-worker.py'))
resize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resize)
UUID = '11111111-2222-3333-4444-555555555555'
NODE = {'name': 'psy-lab-work-x2', 'host': 'x2', 'mac': '52:54:00:70:02:02', 'cpus': 4}
HOST = {'os_pool': '/home/psy/k8s-lab/os', 'bridge': 'br0'}
XML = '''<domain type="kvm"><name>psy-lab-work-x2</name><uuid>UUID</uuid>
<memory unit="KiB">8388608</memory><currentMemory unit="KiB">8388608</currentMemory><vcpu>4</vcpu>
<devices><disk type="file"><target dev="vda"/><source file="/home/psy/k8s-lab/os/psy-lab-work-x2.qcow2"/></disk>
<disk type="file"><target dev="sda"/><source file="/home/psy/k8s-lab/os/psy-lab-work-x2-seed.iso"/></disk>
<interface type="bridge"><mac address="52:54:00:70:02:02"/><source bridge="br0"/></interface></devices></domain>'''.replace('UUID', UUID)


class ResizeSafety(unittest.TestCase):
    def test_budget_counts_the_entire_vm_ceiling_even_for_an_idle_guest(self):
        resize.capacity_check(44 * 2**20, 36)
        with self.assertRaises(ValueError):
            resize.capacity_check(43 * 2**20, 36)

    def test_accepts_only_an_increase_and_rejects_huge_allocation(self):
        self.assertEqual(resize.validate(XML, NODE, HOST, UUID, 16), 8 * 2**20)
        for size in [8, 4, 64]:
            with self.assertRaises(ValueError):
                resize.validate(XML, NODE, HOST, UUID, size)

    def test_rejects_foreign_uuid_disk_bridge_and_cpu(self):
        for before, after in [(UUID, 'another-domain'), ('-x2.qcow2', '-x1.qcow2'),
                              ('bridge="br0"', 'bridge="foreign"'), ('<vcpu>4', '<vcpu>8')]:
            with self.assertRaises(ValueError):
                resize.validate(XML.replace(before, after), NODE, HOST, UUID, 16)

    def test_rejects_passthrough_and_duplicate_disk_targets(self):
        for value in ['<hostdev/>', '<filesystem/>', '<disk type="file"><target dev="vda"/><source file="/elsewhere"/></disk>']:
            with self.assertRaises(ValueError):
                resize.validate(XML.replace('</devices>', value + '</devices>'), NODE, HOST, UUID, 16)

    def test_domain_shape_ignores_only_the_two_memory_fields(self):
        self.assertEqual(resize.shape(XML), resize.shape(XML.replace('8388608', '16777216')))
        self.assertNotEqual(resize.shape(XML), resize.shape(XML.replace('<vcpu>4', '<vcpu>8')))
        self.assertEqual(resize.shape(XML,allow_cpu=True),resize.shape(XML.replace('<vcpu>4','<vcpu>8'),allow_cpu=True))

    def test_insufficient_capacity_after_shutdown_restores_the_unchanged_vm(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            platform=root/'platform'; platform.mkdir()
            node={**NODE,'role':'agent'}
            inventory={'lab':'psy-k8s-local','topology':'local-control-plane','network_confirmed':True,'storage_confirmed':True,
                       'nodes':[node],'hosts':{'x2':{**HOST,'ssh':'arc99x2','expected_hostname':'arc99x2'}}}
            config=root/'inventory.json'; config.write_text(json.dumps(inventory))
            (root/'inventory.sha256').write_text(hashlib.sha256(json.dumps(inventory,sort_keys=True).encode()).hexdigest())
            calls=[]
            def virsh(host,*args):
                calls.append(args)
                if args[0]=='dumpxml':return XML
                if args[0]=='domstate':return 'shut off' if any(c[0]=='shutdown' for c in calls) else 'running'
                return ''
            def ssh(host,args):return '24' if args[0]=='getconf' else 'arc99x2'
            state={'spec':{},'metadata':{'uid':'same-node'},'status':{'nodeInfo':{'bootID':'old-boot'}}}
            def run(args,**kwargs):return json.dumps(state) if args[:3]==['kubectl','get','node'] else ''
            argv=['resize-worker.py','--inventory',str(config),'--platform',str(platform),'--node','x2',
                  '--domain-uuid',UUID,'--memory-gib','16','--cpus','6','--apply','--evidence',str(root/'evidence')]
            with patch('sys.argv',argv),patch.object(resize,'virsh',side_effect=virsh),patch.object(resize,'ssh',side_effect=ssh),\
                 patch.object(resize,'run',side_effect=run) as runner,patch.object(resize,'host_memory',return_value={'MemTotal':32*2**20,'MemAvailable':20*2**20}),\
                 patch.object(resize,'wait_node',return_value=state) as wait:
                with self.assertRaisesRegex(ValueError,'Insufficient physical memory'):
                    resize.main()
                wait.assert_called_once_with(NODE['name'],8,'old-boot')
                self.assertIn(('start',UUID),calls)
                self.assertFalse(any(c[0].startswith('set') for c in calls))
                self.assertTrue(any(c.args[0]==['kubectl','uncordon',NODE['name']] for c in runner.call_args_list))
            self.assertEqual((root/'evidence/domain-before.xml').read_text(),XML+'\n')

    def test_wait_ignores_stale_ready_until_the_guest_boot_id_changes(self):
        old={'status':{'conditions':[{'type':'Ready','status':'True'}],'capacity':{'memory':str(16*2**20)+'Ki'},'nodeInfo':{'bootID':'old'}}}
        new=json.loads(json.dumps(old));new['status']['nodeInfo']['bootID']='new'
        with patch.object(resize,'run',side_effect=[json.dumps(old),json.dumps(new)]) as runner,patch.object(resize.time,'sleep'):
            self.assertEqual(resize.wait_node('psy-lab-work-x2',16,'old'),new)
            self.assertEqual(runner.call_count,2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
