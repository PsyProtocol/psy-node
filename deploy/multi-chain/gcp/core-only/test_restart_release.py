"""Historical per-component release isolation; not fresh-release acceptance."""
import unittest

import install_host as install
import place_realm1_on_coordinator as placement
import plan
import prepare_host_packages as packages
import prepare_network as network
import prepare_proxies as proxies
import prepare_workers as workers
from test_plan import fixture


class RestartReleaseTests(unittest.TestCase):
    def test_core_runtime_and_workers_are_pinned_to_r3_but_proxy_remains_r2(self):
        source = "3d31758738f833a7eea6f9ff7fd680a69a0d9a44"
        for value in (plan.RUNTIME_COMMIT, network.RUNTIME_COMMIT,
                      install.SOURCE_COMMIT, workers.SOURCE):
            self.assertEqual(value, source)
        for value in (install.RELEASE_ID, workers.RELEASE_ID):
            self.assertEqual(value, "core-testnet-20261027-r3")
        self.assertEqual(proxies.SOURCE, "5d38eefc07b0925ed9875b74805d9c3fea73d998")
        self.assertEqual(proxies.RELEASE_ID, "core-testnet-20261026-r2")
        with self.assertRaises(proxies.ProxyError):
            proxies.validate_source("d" * 40)
        with self.assertRaises(proxies.ProxyError):
            proxies.validate_source(source)

    def test_core_units_paths_and_namespaces_are_isolated(self):
        topology, config, genesis, whitelist = fixture()
        report = plan.make_plan(topology, config, genesis, whitelist)
        for service in report["services"]:
            self.assertTrue(service["unit"].startswith("psy-core-r3-"))
            self.assertTrue(service["namespace"].startswith("fresh20261027r3_"))
            self.assertIn("/core-testnet-20261027-r3/", service["argv"][0])
            if "--checkpoint-backup-path" in service["argv"]:
                index = service["argv"].index("--checkpoint-backup-path")
                self.assertTrue(service["argv"][index + 1].endswith(
                    "/core-testnet-20261027-r3/checkpoints"))
        topology["coordinator"]["namespace"] = "fresh20261026_coordinator"
        with self.assertRaises(plan.PlanError):
            plan.validate_topology(topology)

    def test_placement_and_consumers_have_separate_unit_names(self):
        self.assertEqual(placement.unit_name(1, "processor"),
                         "psy-core-r3-realm-1-v1-processor.service")
        self.assertEqual(placement.SLICE, "psy-realm1-r3.slice")
        self.assertEqual(workers.unit_name("realm-1"), "psy-core-worker-r3-realm-1.service")
        self.assertEqual(proxies.unit_name("user"), "psy-core-prove-proxy-r2-user.service")
        self.assertIn("psy-core-prove-proxy-user.service", proxies.OLD_UNITS)

    def test_frozen_r3_build_and_genesis_pins_cannot_reuse_preceding_cohorts(self):
        self.assertEqual(packages.NODE_SHA256,
                         "bc5419fd8ef89eb6cdef3dfbd29f4f6a232bcb4920ec97809a995a1bc225b7e9")
        self.assertEqual(install.PINNED_SHA256["bin/psy_node_cli"], packages.NODE_SHA256)
        self.assertEqual(packages.GENESIS_SHA256,
                         "f839b453ab130c29998620c4c5d4bf9a30ce341a2e7c480aa9dbd8ed10902173")
        self.assertEqual(install.PINNED_SHA256["genesis.json"], packages.GENESIS_SHA256)
        self.assertEqual(workers.WORKER_SHA256,
                         "08d76103fb40639ecbe8182113e7fc5df61ae9a408abefb2f96de9b0ad56238d")
        self.assertEqual(workers.TOPOLOGY_SHA256,
                         "78403e274c24dd8bbb44405775868477b3cfe0ad9c9a3815cb59a1f267e5675f")


if __name__ == "__main__":
    unittest.main()
