#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
