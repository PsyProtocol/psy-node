"""Release isolation checks; no network, credentials or host operations."""
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
    def test_runtime_and_release_are_pinned_to_r2(self):
        source = "5d38eefc07b0925ed9875b74805d9c3fea73d998"
        for value in (plan.RUNTIME_COMMIT, network.RUNTIME_COMMIT,
                      install.SOURCE_COMMIT, workers.SOURCE, proxies.SOURCE):
            self.assertEqual(value, source)
        for value in (install.RELEASE_ID, workers.RELEASE_ID, proxies.RELEASE_ID):
            self.assertEqual(value, "core-testnet-20261026-r2")
        with self.assertRaises(proxies.ProxyError):
            proxies.validate_source("d" * 40)

    def test_core_units_paths_and_namespaces_are_isolated(self):
        topology, config, genesis, whitelist = fixture()
        report = plan.make_plan(topology, config, genesis, whitelist)
        for service in report["services"]:
            self.assertTrue(service["unit"].startswith("psy-core-r2-"))
            self.assertTrue(service["namespace"].startswith("fresh20261026r2_"))
            self.assertIn("/core-testnet-20261026-r2/", service["argv"][0])
            if "--checkpoint-backup-path" in service["argv"]:
                index = service["argv"].index("--checkpoint-backup-path")
                self.assertTrue(service["argv"][index + 1].endswith(
                    "/core-testnet-20261026-r2/checkpoints"))
        topology["coordinator"]["namespace"] = "fresh20261026_coordinator"
        with self.assertRaises(plan.PlanError):
            plan.validate_topology(topology)

    def test_placement_and_consumers_have_separate_unit_names(self):
        self.assertEqual(placement.unit_name(1, "processor"),
                         "psy-core-r2-realm-1-v1-processor.service")
        self.assertEqual(placement.SLICE, "psy-realm1-r2.slice")
        self.assertEqual(workers.unit_name("realm-1"), "psy-core-worker-r2-realm-1.service")
        self.assertEqual(proxies.unit_name("user"), "psy-core-prove-proxy-r2-user.service")
        self.assertIn("psy-core-prove-proxy-user.service", proxies.OLD_UNITS)

    def test_unfrozen_binary_and_genesis_pins_cannot_reuse_r1(self):
        # Remain closed until the build and Genesis owners supply reviewed hashes.
        self.assertIsNone(packages.NODE_SHA256)
        self.assertIsNone(packages.GENESIS_SHA256)
        self.assertIsNone(install.PINNED_SHA256["bin/psy_node_cli"])
        self.assertIsNone(install.PINNED_SHA256["genesis.json"])
        self.assertIsNone(workers.WORKER_SHA256)
        self.assertIsNone(workers.TOPOLOGY_SHA256)


if __name__ == "__main__":
    unittest.main()
