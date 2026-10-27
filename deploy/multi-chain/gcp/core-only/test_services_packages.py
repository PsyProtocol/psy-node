import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import activate_services
import indexer_backup_mirror
import install_services as installer
import prepare_envio
import prepare_services_packages as packages


class ServicesPackageTests(unittest.TestCase):
    def test_services_l1_routes_are_only_protected_forwards(self):
        documents = {f"l1/{name}/summary.json": json.dumps({"core": {"StateManager": "0x" + "1" * 40}})
                     for name in prepare_envio.CHAINS}
        config = packages.service_config(packages.deployment_topology(), documents)
        self.assertEqual([row["eth_rpc_url"] for row in config["l1_chains"]], list(prepare_envio.RPC_URLS.values()))
        self.assertTrue(all(row["graphql_url"] == "http://10.148.0.24:38081/v1/graphql" for row in config["l1_chains"]))

    def test_missing_documents_never_generate_old_addresses(self):
        config = packages.service_config(packages.deployment_topology(), {})
        self.assertEqual(config["l1_chains"], [])
        self.assertFalse(config["nostr"]["enabled"])

    def test_pending_install_refused_before_commands_or_files(self):
        with patch.object(installer.os, "geteuid", return_value=0), patch.object(installer.subprocess, "run") as run:
            with self.assertRaisesRegex(installer.ValidationError, "documents"):
                installer.check_host(Path("/not-created"), {"l1_ready": False}, {})
            with self.assertRaisesRegex(installer.ValidationError, "documents"):
                installer.install(Path("/not-created"), {"l1_ready": False}, {}, None)
            run.assert_not_called()

    def test_pending_activation_refused_before_commands(self):
        with patch.object(activate_services.os, "geteuid", return_value=0), patch.object(activate_services.subprocess, "check_output") as run:
            with self.assertRaisesRegex(installer.ValidationError, "fresh L1"):
                activate_services.preflight(installer, Path(installer.RELEASE), {"l1_ready": False}, {})
            run.assert_not_called()

    def test_old_service_fence_refuses_active_without_stopping(self):
        row = "psy-services-fresh-20261026-r2.service loaded active running Old\n"
        with patch.object(installer.subprocess, "check_output", return_value=row), patch.object(installer, "unit_status",
                return_value={"MainPID": "123", "ActiveState": "active"}), patch.object(installer.subprocess, "run") as run:
            with self.assertRaisesRegex(installer.ValidationError, "still running"):
                installer.fence_services()
            run.assert_not_called()

    def test_units_use_fresh_paths_and_all_validator_sources(self):
        topology = packages.deployment_topology()
        for name, group in topology["groups"].items():
            for role in group["roles"]:
                unit = packages.unit(topology, group, role).decode()
                self.assertIn("/install_services.py guard", unit)
                self.assertIn(installer.RELEASE, unit)
                self.assertNotIn("20261026-r2", unit)
                if role.startswith("realm"):
                    self.assertIn("--committed-realm-sources", unit)

    def test_mirror_reads_only_r3_backups(self):
        self.assertEqual(str(indexer_backup_mirror.BACKUPS), installer.BACKUPS)
        self.assertEqual(str(indexer_backup_mirror.STATE), "/var/lib/psy-indexer-r3-mirror")
        self.assertEqual(str(indexer_backup_mirror.PROGRAM), "/usr/local/libexec/psy-indexer-r3-mirror.py")

    def test_activation_waits_for_executor_without_restarting(self):
        values = [{"ActiveState": "active", "MainPID": "20"}] * 2
        with patch.object(installer, "unit_status", side_effect=values), patch.object(activate_services.os, "readlink",
                side_effect=["/usr/lib/systemd/systemd-executor", installer.RELEASE + "/psy-services"]), \
                patch.object(activate_services, "process", return_value={"pid": 20}) as process, \
                patch.object(activate_services.time, "sleep") as sleep:
            self.assertEqual(activate_services.wait_process(installer, "new.service", "psy-services"), {"pid": 20})
            sleep.assert_called_once_with(0.25)
            process.assert_called_once()

    def test_activation_rejects_wrong_exe_or_restarted_pid(self):
        with patch.object(installer, "unit_status", return_value={"ActiveState": "active", "MainPID": "20"}), \
                patch.object(activate_services.os, "readlink", return_value="/usr/bin/other"), \
                patch.object(activate_services.time, "sleep") as sleep:
            with self.assertRaisesRegex(installer.ValidationError, "unexpected executor"):
                activate_services.wait_process(installer, "new.service", "psy-services")
            sleep.assert_not_called()
        with patch.object(installer, "unit_status", side_effect=[
                {"ActiveState": "active", "MainPID": "20"}, {"ActiveState": "active", "MainPID": "21"}]), \
                patch.object(activate_services.os, "readlink", return_value="/usr/lib/systemd/systemd"), \
                patch.object(activate_services.time, "sleep"):
            with self.assertRaisesRegex(installer.ValidationError, "restarted"):
                activate_services.wait_process(installer, "new.service", "psy-services")

    def test_activation_failed_or_deadline_does_not_retry_start(self):
        with patch.object(installer, "unit_status", return_value={"ActiveState": "failed", "MainPID": "0"}), \
                patch.object(activate_services.subprocess, "run") as run:
            with self.assertRaisesRegex(installer.ValidationError, "failed during"):
                activate_services.wait_process(installer, "new.service", "psy-services")
            run.assert_not_called()
        with patch.object(installer, "unit_status", return_value={"ActiveState": "active", "MainPID": "0"}), \
                patch.object(activate_services.time, "monotonic", side_effect=[0, 16]):
            with self.assertRaisesRegex(installer.ValidationError, "deadline"):
                activate_services.wait_process(installer, "new.service", "psy-services")


if __name__ == "__main__":
    unittest.main()
