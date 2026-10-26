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

    def test_frozen_build_pins_and_pending_genesis_cannot_reuse_r1(self):
        self.assertEqual(packages.NODE_SHA256,
                         "9b7a792da5c8cb45ec1c2db022ac52ce405e5cd05d154a1c7ac7c4941faaf9cb")
        self.assertEqual(install.PINNED_SHA256["bin/psy_node_cli"], packages.NODE_SHA256)
        # Remain closed until the Genesis owner supplies the reviewed candidate.
        self.assertIsNone(packages.GENESIS_SHA256)
        self.assertIsNone(install.PINNED_SHA256["genesis.json"])
        self.assertEqual(workers.WORKER_SHA256,
                         "db160bf77e00fecc92907cc9eaf0bba371853d1c6d6c9f8589238853fbd96f45")
        self.assertEqual(workers.TOPOLOGY_SHA256,
                         "89a9c4cfaa43d6537427c23c34ac2919291a582926f4841aa6926a419dc65473")


if __name__ == "__main__":
    unittest.main()
