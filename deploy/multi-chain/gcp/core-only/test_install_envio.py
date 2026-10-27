import copy
import ipaddress
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import install_envio as installer
import prepare_envio as prepare


class InstallEnvioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / "package"
        self.package.mkdir()
        self.address = str(ipaddress.IPv4Address(0xAC100102))
        self.placement = {"postgres_host": self.address, "postgres_port": 5432, "postgres_user": installer.DATABASE,
                          "hasura_bind": self.address, "hasura_port": 38081, "indexer_port": 29899}
        self.runtime = {"ENVIO_PG_HOST": self.address, "ENVIO_PG_PORT": "5432", "ENVIO_PG_USER": installer.DATABASE,
                        "ENVIO_PG_DATABASE": installer.DATABASE, "ENVIO_PG_PUBLIC_SCHEMA": "envio",
                        "ENVIO_PG_SSL_MODE": "false", "ENVIO_HASURA": "true", "ENVIO_INDEXER_PORT": "29899",
                        "TUI_OFF": "true", "HASURA_GRAPHQL_ENDPOINT": f"http://{self.address}:38081/v1/metadata",
                        "ENVIO_RPC_POLLING_INTERVAL_MILLIS": "12000", "PSY_ENVIO_FRESH_REORG_PARENT": "1",
                        "PSY_ENVIO_ORDERED_FAILOVER": "0"}
        self.write(self.package / "runtime-env.json", self.runtime)
        self.write(self.package / "compose.hasura.json", prepare.compose(self.placement))
        self.node = b"synthetic Node fixture"
        self.write(self.package / "node/bin/node", self.node, 0o755)
        self.write(self.package / "generated/fixture.js", b"compiled fixture")
        (self.package / "generated/alias.js").symlink_to("fixture.js")
        self.node_patch = patch.object(installer, "NODE_HASH", installer.sha(self.node))
        self.node_patch.start()
        self.addCleanup(self.node_patch.stop)
        self.build = {"source_commit": installer.SOURCE, "node_sha256": installer.sha(self.node),
                      "frozen_install_verified": True, "patches_verified": True, "native_help_verified": True,
                      "generated_config_verified": True}
        self.secret_path = self.root / "secrets.json"
        self.write(self.secret_path, {"postgres_password": "fixture-password-" + "a" * 32,
                                     "hasura_admin_secret": "fixture-admin-" + "b" * 32})
        self.spec = {"version": 1, "hostname": "fixture.example.invalid", "address": self.address,
                     "postgres_container_id": "a" * 64, "package": str(self.package), "build_sha256": "",
                     "secrets": {"path": str(self.secret_path), "sha256": installer.sha(self.secret_path.read_bytes())}}
        self.spec_path = self.root / "spec.json"
        self.freeze()

    def write(self, path, value, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else prepare.encode(value))
        path.chmod(mode)

    def freeze(self):
        self.build["files"] = installer.inventory(self.package)
        self.write(self.package / "build.json", self.build)
        self.spec["build_sha256"] = installer.sha((self.package / "build.json").read_bytes())
        self.write(self.spec_path, self.spec)

    def plan(self):
        return installer.load_plan(self.spec_path, installer.sha(self.spec_path.read_bytes()))

    def test_plan_never_executes_host_commands(self):
        with patch.object(installer.subprocess, "run", side_effect=AssertionError("unexpected subprocess")):
            self.assertEqual(self.plan()[4]["ENVIO_PG_DATABASE"], installer.DATABASE)

    def test_modified_file_extra_file_and_external_links_rejected(self):
        self.write(self.package / "extra", b"unexpected")
        with self.assertRaises(ValueError):
            self.plan()
        (self.package / "extra").unlink()
        self.write(self.package / "generated/fixture.js", b"changed")
        with self.assertRaises(ValueError):
            self.plan()
        (self.package / "external").symlink_to(self.secret_path)
        with self.assertRaises(ValueError):
            installer.inventory(self.package)

    def test_unverified_build_or_wrong_source_rejected(self):
        original = copy.deepcopy(self.build)
        for key in ("frozen_install_verified", "patches_verified", "native_help_verified", "generated_config_verified", "source_commit"):
            self.build = copy.deepcopy(original)
            self.build[key] = False if key != "source_commit" else "old-source"
            self.freeze()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.plan()

    def test_optional_platform_link_stays_relative_and_inside_package(self):
        (self.package / "optional").symlink_to("node_modules/missing-platform-package")
        self.assertEqual(installer.inventory(self.package)["optional"], {"link": "node_modules/missing-platform-package"})
        (self.package / "escape").symlink_to("../absent")
        with self.assertRaises(ValueError):
            installer.inventory(self.package)

    def test_wrong_database_and_extra_compose_capability_rejected(self):
        original = prepare.compose(self.placement)
        for key in ("HASURA_GRAPHQL_DATABASE_URL", "HASURA_GRAPHQL_METADATA_DATABASE_URL", "volumes"):
            compose = copy.deepcopy(original)
            service = compose["services"]["graphql-engine"]
            if key == "volumes":
                service[key] = ["/:/host"]
            else:
                service["environment"][key] = "postgres://example.invalid/old_database"
            self.write(self.package / "compose.hasura.json", compose)
            self.freeze()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.plan()

    def test_runtime_database_url_override_is_rejected(self):
        self.runtime["DATABASE_URL"] = "postgres://example.invalid/old_database"
        self.write(self.package / "runtime-env.json", self.runtime)
        self.freeze()
        with self.assertRaises(ValueError):
            self.plan()

    def test_secret_file_permissions_and_pin_rejected(self):
        self.secret_path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.plan()
        self.secret_path.chmod(0o600)
        self.write(self.secret_path, {"postgres_password": "changed"})
        with self.assertRaises(ValueError):
            self.plan()

    def test_install_creates_only_new_database_and_never_starts_services(self):
        plan = self.plan()
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        release, state, config, unit = (self.root / name for name in ("release", "state", "config", "new.service"))
        with patch.object(installer, "RELEASE", release), patch.object(installer, "STATE", state), \
                patch.object(installer, "CONFIG", config), patch.object(installer, "UNIT", unit), \
                patch.object(installer, "host_checks", return_value=account), \
                patch.object(installer.os, "chown"), patch.object(installer.os, "fchown"), \
                patch.object(installer, "pg", return_value="") as pg, patch.object(installer, "run", return_value="") as run:
            installer.install(plan)
            self.assertEqual(run.call_args_list[0].args[0], ["systemctl", "daemon-reload"])
            self.assertEqual(run.call_count, 1)
            self.assertEqual(pg.call_count, 1)
            sql = pg.call_args.args[1]
            self.assertIn(f'CREATE DATABASE "{installer.DATABASE}"', sql)
            self.assertNotIn("ALTER", sql)
            self.assertNotIn("DROP", sql)
            self.assertNotIn("password", sql.lower())
            self.assertEqual(installer.inventory(release), self.build["files"])
            self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE((config / "runtime.env").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            self.assertIn("runUpMigrations(true,false)", unit.read_text())
            self.assertNotIn("runDown", unit.read_text())
            with self.assertRaises(FileExistsError):
                installer.install(plan)
            self.assertEqual(pg.call_count, 1)

    def test_hostcheck_is_readonly_and_refuses_existing_db(self):
        plan = self.plan()
        account = SimpleNamespace(pw_uid=1234, pw_gid=1234, pw_shell="/usr/sbin/nologin")
        def command(args, input=None):
            if args[:2] == ["ip", "-j"]:
                return json.dumps([{"addr_info": [{"local": self.address}]}])
            if args[:3] == ["docker", "ps", "-aq"]:
                return ""
            if args[:2] == ["docker", "inspect"]:
                return json.dumps("a" * 64) if ".Id" in args[3] else "true"
            if args[0] == "ss":
                return ""
            if args[0] == "systemctl":
                return "not-found"
            return "available"
        with patch.object(installer.os, "geteuid", return_value=0), \
                patch.object(installer.socket, "gethostname", return_value=self.spec["hostname"]), \
                patch.object(installer.pwd, "getpwnam", return_value=account), \
                patch.object(installer.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=1234)), \
                patch.object(installer, "trusted"), patch.object(installer.Path, "lstat", return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)), \
                patch.object(installer.os, "walk", return_value=[]), patch.object(installer.os.path, "lexists", return_value=False), \
                patch.object(installer, "run", side_effect=command) as run, \
                patch.object(installer, "pg", return_value="0\n1\n0") as pg:
            self.assertEqual(installer.host_checks(plan), account)
            sql = pg.call_args.args[1]
            self.assertIn("default_transaction_read_only=on", sql)
            self.assertNotIn("CREATE", sql)
            self.assertFalse(any("restart" in c.args[0] or "start" in c.args[0] for c in run.call_args_list))
            pg.return_value = "1\n1\n0"
            with self.assertRaises(ValueError):
                installer.host_checks(plan)


if __name__ == "__main__":
    unittest.main()
