"""Historical per-component release isolation; not fresh-release acceptance."""
import unittest

import install_host as install
import plan
import prepare_proxies as proxies
import prepare_workers as workers
from test_plan import fixture, profile_for
from test_release_lock import build_test_lock

LOCK = build_test_lock()
RELEASE = install.load_core_release(LOCK)


class RestartReleaseTests(unittest.TestCase):
    def test_core_runtime_comes_from_the_lock_and_workers_stay_r3_but_proxy_remains_r2(self):
        source = "3d31758738f833a7eea6f9ff7fd680a69a0d9a44"
        topology = fixture(LOCK)[0]
        for value in (RELEASE.source_commit, topology["runtime_commit"], LOCK["sources"]["runtime"]):
            self.assertEqual(value, "1" * 40)
        self.assertEqual(workers.SOURCE, source)
        self.assertEqual(RELEASE.release_id, LOCK["release_id"])
        self.assertNotEqual(RELEASE.release_id, workers.RELEASE_ID)
        self.assertEqual(workers.RELEASE_ID, "core-testnet-20261027-r3")
        self.assertEqual(proxies.SOURCE, "5d38eefc07b0925ed9875b74805d9c3fea73d998")
        self.assertEqual(proxies.RELEASE_ID, "core-testnet-20261026-r2")
        with self.assertRaises(proxies.ProxyError):
            proxies.validate_source("d" * 40)
        with self.assertRaises(proxies.ProxyError):
            proxies.validate_source(source)

    def test_core_units_paths_and_namespaces_are_isolated(self):
        topology, config, genesis, whitelist = fixture(LOCK)
        profile = profile_for(LOCK)
        report = plan.make_plan(topology, config, genesis, whitelist, release_profile=profile)
        for service in report["services"]:
            self.assertTrue(service["unit"].startswith(LOCK["units"]["core_prefix"]))
            self.assertTrue(service["namespace"].startswith(LOCK["units"]["core_namespace_prefix"] + "_"))
            self.assertIn("/" + LOCK["release_id"] + "/", service["argv"][0])
            if "--checkpoint-backup-path" in service["argv"]:
                index = service["argv"].index("--checkpoint-backup-path")
                self.assertTrue(service["argv"][index + 1].endswith("/" + LOCK["release_id"] + "/checkpoints"))
        topology["coordinator"]["namespace"] = "fresh20261026_coordinator"
        with self.assertRaises(plan.PlanError):
            plan.validate_topology(topology, profile)

    def test_core_and_consumers_have_separate_unit_names(self):
        self.assertTrue(RELEASE.unit_prefix.startswith("psy-core-" + RELEASE.namespace_prefix))
        self.assertEqual(workers.unit_name("realm-1"), "psy-core-worker-r3-realm-1.service")
        self.assertEqual(proxies.unit_name("user"), "psy-core-prove-proxy-r2-user.service")
        self.assertIn("psy-core-prove-proxy-user.service", proxies.OLD_UNITS)
        self.assertNotEqual(RELEASE.unit_prefix, LOCK["units"]["worker_prefix"])
        self.assertNotEqual(RELEASE.unit_prefix, LOCK["units"]["proxy_prefix"])

    def test_core_pins_come_from_the_lock_and_worker_pins_stay_frozen(self):
        self.assertEqual(RELEASE.pins["bin/psy_node_cli"], LOCK["binaries"]["psy_node_cli"])
        self.assertEqual(RELEASE.pins["config.json"], LOCK["inputs"]["runtime_config"])
        self.assertEqual(RELEASE.pins["genesis.json"], LOCK["inputs"]["genesis"])
        self.assertEqual(workers.WORKER_SHA256,
                         "08d76103fb40639ecbe8182113e7fc5df61ae9a408abefb2f96de9b0ad56238d")
        self.assertEqual(workers.TOPOLOGY_SHA256,
                         "78403e274c24dd8bbb44405775868477b3cfe0ad9c9a3815cb59a1f267e5675f")


if __name__ == "__main__":
    unittest.main()
