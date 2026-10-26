import copy
import ctypes
import errno
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import prepare_bridge_forwarders as forwarders


ADDRESSES = [str(ipaddress.IPv4Address(0x0A000000 + index)) for index in range(1, 15)]
TOPOLOGY = {
    "gateway": {"hostname": "gateway.example.test",
                "wireguard": {"interface": "wgtest", "address": ADDRESSES[0]},
                "cloud": {"interface": "eth1", "address": ADDRESSES[1]}},
    "edges": dict(zip(("coordinator", "realm0", "realm1"), ADDRESSES[2:5])),
    "proxies": dict(zip(("system", "user"), ADDRESSES[5:7])),
    "cloud_clients": ADDRESSES[7:14],
}
RAW = json.dumps(TOPOLOGY).encode()
PIN = hashlib.sha256(RAW).hexdigest()


class TopologyTests(unittest.TestCase):
    def test_schema_accepts_valid_topology(self):
        self.assertEqual(forwarders.validate_topology(copy.deepcopy(TOPOLOGY)), TOPOLOGY)

    def test_schema_rejects_unsafe_addresses(self):
        for address in ("0.0.0.0", "127.0.0.1", "192.0.2.1", "::1", "224.0.0.1", "169.254.1.1", "8.8.8.8"):
            candidate = copy.deepcopy(TOPOLOGY)
            candidate["gateway"]["wireguard"]["address"] = address
            with self.subTest(address=address), self.assertRaises(ValueError):
                forwarders.validate_topology(candidate)

    def test_schema_rejects_injection_unknown_fields_and_overlap(self):
        candidates = []
        for name in ("host\nExecStart=bad", "host%H"):
            candidate = copy.deepcopy(TOPOLOGY)
            candidate["gateway"]["hostname"] = name
            candidates.append(candidate)
        candidate = copy.deepcopy(TOPOLOGY)
        candidate["gateway"]["wireguard"]["interface"] = "wg0;bad"
        candidates.append(candidate)
        candidate = copy.deepcopy(TOPOLOGY)
        candidate["proxies"]["user"] = candidate["proxies"]["system"]
        candidates.append(candidate)
        candidate = copy.deepcopy(TOPOLOGY)
        candidate["cloud_clients"] = [ADDRESSES[0]] * 7
        candidates.append(candidate)
        candidate = copy.deepcopy(TOPOLOGY)
        candidate["secret"] = "not-permitted"
        candidates.append(candidate)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                forwarders.validate_topology(candidate)

    def test_hash_pin_duplicate_keys_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "topology.json"
            path.write_bytes(RAW)
            self.assertEqual(forwarders.read_topology(path, PIN), (TOPOLOGY, RAW))
            with self.assertRaisesRegex(forwarders.ForwarderError, "hash mismatch"):
                forwarders.read_topology(path, "0" * 64)
            duplicate = b'{"gateway":{},"gateway":{}}'
            path.write_bytes(duplicate)
            with self.assertRaisesRegex(forwarders.ForwarderError, "duplicate"):
                forwarders.read_topology(path, hashlib.sha256(duplicate).hexdigest())
            path.unlink()
            path.symlink_to(Path(directory) / "missing")
            with self.assertRaises(OSError):
                forwarders.read_topology(path, PIN)

    def test_cli_requires_pin_without_defaults(self):
        with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
            forwarders.main(["preview"])


class UnitTests(unittest.TestCase):
    def test_exact_listener_backend_and_filters_in_rendered_units(self):
        units = forwarders.build_units(TOPOLOGY, PIN)
        expected = [(port, ADDRESSES[0], host, port, ADDRESSES[5:7], "wgtest", f"edge-{port}")
                    for host, ports in ((ADDRESSES[2], range(15370, 15373)),
                                        (ADDRESSES[3], range(15380, 15383)),
                                        (ADDRESSES[4], range(15383, 15386))) for port in ports]
        expected += [(19998, ADDRESSES[1], ADDRESSES[5], 9998, ADDRESSES[7:14], "eth1", "system"),
                     (19999, ADDRESSES[1], ADDRESSES[6], 9999, ADDRESSES[7:14], "eth1", "user")]
        self.assertEqual(len(units), 22)
        for port, listen, backend, backend_port, clients, interface, name in expected:
            socket_name = f"psy-bridge-private-{name}.socket"
            service_name = f"psy-bridge-private-{name}.service"
            socket_unit, service_unit = units[socket_name], units[service_name]
            self.assertIn(f"ListenStream={listen}:{port}\n", socket_unit)
            self.assertIn(f"BindToDevice={interface}\n", socket_unit)
            self.assertIn(f"Service={service_name}\n", socket_unit)
            self.assertIn(f"BindsTo={socket_name}\n", service_unit)
            self.assertIn(f"ExecStart={forwarders.PROXY} --connections-max=256 {backend}:{backend_port}\n", service_unit)
            self.assertIn("User=nobody\nGroup=nogroup\n", service_unit)
            for unit, allowed in ((socket_unit, clients), (service_unit, [backend])):
                self.assertEqual([line for line in unit.splitlines() if line.startswith("IPAddressAllow=")],
                                 [f"IPAddressAllow={ip}/32" for ip in allowed])
                self.assertIn("IPAddressDeny=any\n", unit)
                self.assertIn(f"--topology {forwarders.TOPOLOGY} --topology-sha256 {PIN}", unit)
                self.assertNotIn("ExecStartPost=", unit)
            self.assertIn(f"check-filter {socket_name}\n", socket_unit)
            self.assertIn(f"check-filter {service_name}\n", service_unit)
            self.assertIn("ExecStartPre=+", service_unit)
            self.assertIn("FreeBind=no\nReusePort=no\n", socket_unit)
            self.assertIn("DefaultDependencies=no\n", socket_unit)

    def test_scopes_partition_the_same_units(self):
        edges = forwarders.build_units(TOPOLOGY, PIN, "edges")
        proxies = forwarders.build_units(TOPOLOGY, PIN, "proxies")
        self.assertEqual((len(edges), len(proxies)), (18, 4))
        self.assertFalse(set(edges) & set(proxies))
        self.assertEqual({**edges, **proxies}, forwarders.build_units(TOPOLOGY, PIN))


class FilterTests(unittest.TestCase):
    def test_filters_fail_closed(self):
        for counts in ([], [1], [0, 0], [1, 0], [0, 1]):
            with self.subTest(counts=counts), patch.object(forwarders, "get_filter_counts", return_value=counts):
                with self.assertRaises(forwarders.ForwarderError):
                    forwarders.verify_filters(Path("/unused"))
        with patch.object(forwarders, "get_filter_counts", return_value=[1, 1]):
            forwarders.verify_filters(Path("/unused"))

    def test_query_is_read_only_and_checks_both_directions(self):
        queries = []
        def syscall(number, command, pointer, size):
            query = ctypes.cast(pointer, ctypes.POINTER(forwarders.BPFQuery)).contents
            queries.append((number, command, query.attach_type, query.query_flags, size))
            query.prog_cnt = 1
            return 0
        libc = Mock()
        libc.syscall.side_effect = syscall
        with patch.object(forwarders.platform, "machine", return_value="x86_64"), \
                patch.object(Path, "is_file", return_value=True), \
                patch.object(forwarders.ctypes, "CDLL", return_value=libc), \
                patch.object(os, "open", return_value=19), patch.object(os, "close"):
            self.assertEqual(forwarders.get_filter_counts(Path("/unused")), [1, 1])
        self.assertEqual(queries, [(321, 16, 0, 0, 32), (321, 16, 1, 0, 32)])

    def test_query_error_and_unknown_architecture_fail_closed(self):
        libc = Mock()
        libc.syscall.return_value = -1
        with patch.object(forwarders.platform, "machine", return_value="x86_64"), \
                patch.object(Path, "is_file", return_value=True), \
                patch.object(forwarders.ctypes, "CDLL", return_value=libc), \
                patch.object(os, "open", return_value=19), patch.object(os, "close"):
            with self.assertRaisesRegex(forwarders.ForwarderError, "BPF_PROG_QUERY failed"):
                forwarders.get_filter_counts(Path("/unused"))
        with patch.object(forwarders.platform, "machine", return_value="unknown"):
            with self.assertRaises(forwarders.ForwarderError):
                forwarders.get_filter_counts(Path("/unused"))

    def test_guard_requires_own_cgroup_and_actual_denial(self):
        for suffix in ("socket", "service"):
            name = "psy-bridge-private-system." + suffix
            with patch.object(Path, "read_text", return_value="0::/system.slice/foreign.socket\n"):
                with self.assertRaisesRegex(forwarders.ForwarderError, "own systemd unit"):
                    forwarders.check_filter(name, TOPOLOGY, PIN)
            for returned in (0, errno.ECONNREFUSED, errno.EACCES, errno.EPERM):
                probe = Mock()
                probe.__enter__ = Mock(return_value=probe)
                probe.__exit__ = Mock(return_value=False)
                probe.sendto.side_effect = OSError(returned, "probe failed") if returned else None
                with patch.object(Path, "read_text", return_value=f"0::/system.slice/{name}\n"), \
                        patch.object(forwarders, "verify_filters") as verify, \
                        patch.object(socket, "socket", return_value=probe):
                    if returned == errno.EPERM:
                        forwarders.check_filter(name, TOPOLOGY, PIN)
                        verify.assert_called_once_with(forwarders.CGROUPS / "system.slice" / name)
                    else:
                        with self.assertRaises(forwarders.ForwarderError):
                            forwarders.check_filter(name, TOPOLOGY, PIN)
        with self.assertRaisesRegex(forwarders.ForwarderError, "not an owned"):
            forwarders.check_filter("foreign.socket", TOPOLOGY, PIN)


class BackendTests(unittest.TestCase):
    def get_checkpoint(self, reply, status=200):
        connection = Mock()
        connection.getresponse.return_value.status = status
        connection.getresponse.return_value.read.return_value = json.dumps(reply).encode()
        with patch.object(forwarders.http.client, "HTTPConnection", return_value=connection):
            checkpoint = forwarders.get_checkpoint(forwarders.build_forwarders(TOPOLOGY)[0])
        self.assertEqual(json.loads(connection.request.call_args.args[2]),
                         {"jsonrpc": "2.0", "id": 1, "method": "psy_get_latest_checkpoint_id", "params": []})
        connection.close.assert_called_once()
        return checkpoint

    def test_read_only_checkpoint(self):
        self.assertEqual(self.get_checkpoint({"jsonrpc": "2.0", "id": 1, "result": 374}), 374)

    def test_invalid_rpc_and_http_rejected(self):
        for reply in ([], {}, {"jsonrpc": "2.0", "id": 1, "error": {}},
                      {"jsonrpc": "2.0", "id": 1, "result": True},
                      {"jsonrpc": "2.0", "id": 1, "result": -1},
                      {"jsonrpc": "2.0", "id": 1, "result": "374"},
                      {"jsonrpc": "2.0", "id": 2, "result": 374},
                      {"jsonrpc": "2.0", "id": 1, "result": 2 ** 64},
                      {"jsonrpc": "2.0", "id": 1, "result": 374, "error": None}):
            with self.subTest(reply=reply), self.assertRaises(forwarders.ForwarderError):
                self.get_checkpoint(reply)
        with self.assertRaises(forwarders.ForwarderError):
            self.get_checkpoint({"jsonrpc": "2.0", "id": 1, "result": 374}, status=503)

    def test_oversized_response_rejected(self):
        connection = Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b" " * 4097
        with patch.object(forwarders.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(forwarders.ForwarderError, "HTTP response"):
                forwarders.get_checkpoint(forwarders.build_forwarders(TOPOLOGY)[0])

    def test_edges_scope_never_contacts_proxy_backends(self):
        with patch.object(forwarders, "get_checkpoint", return_value=374) as rpc, \
                patch.object(socket, "create_connection", side_effect=ConnectionRefusedError) as tcp:
            checks = forwarders.check_backends(TOPOLOGY, "edges")
            self.assertEqual(rpc.call_count, 9)
            self.assertTrue(all(check["ready"] for check in checks))
            tcp.assert_not_called()
            checks = forwarders.check_backends(TOPOLOGY)
        self.assertEqual([check["ready"] for check in checks], [True] * 9 + [False] * 2)


class HostTests(unittest.TestCase):
    def test_hostname_interfaces_and_addresses_must_match(self):
        interfaces = [{"ifname": network["interface"], "addr_info": [{"family": "inet", "local": network["address"]}]}
                      for network in (TOPOLOGY["gateway"]["wireguard"], TOPOLOGY["gateway"]["cloud"])]
        with patch.object(os, "geteuid", return_value=0), \
                patch.object(socket, "gethostname", return_value="gateway.example.test"), \
                patch.object(forwarders, "run_command", return_value=json.dumps(interfaces)):
            forwarders.verify_host(TOPOLOGY)
            with patch.object(socket, "gethostname", return_value="foreign.example.test"):
                with self.assertRaises(forwarders.ForwarderError):
                    forwarders.verify_host(TOPOLOGY)
            with patch.object(forwarders, "run_command", return_value="[]"):
                with self.assertRaises(forwarders.ForwarderError):
                    forwarders.verify_host(TOPOLOGY)

    def test_ipv4_and_ipv6_conflicts_and_scoping(self):
        tcp = "header\n0: 00000000:3C0A 00000000:0000 0A\n1: 0100007F:4E1F 00000000:0000 01\n"
        tcp6 = "header\n0: 00000000000000000000000000000000:4E1E 00000000000000000000000000000000:0000 0A\n"
        with patch.object(Path, "read_text", side_effect=[tcp, tcp6]):
            self.assertEqual(forwarders.get_listening_ports(), {15370, 19998})
        with patch.object(forwarders, "get_listening_ports", return_value={15370}):
            with self.assertRaises(forwarders.ForwarderError):
                forwarders.verify_ports(TOPOLOGY, "edges")
            forwarders.verify_ports(TOPOLOGY, "proxies")

    def test_directory_rejects_symlink_nonroot_and_group_write(self):
        for mode, uid in ((stat.S_IFLNK | 0o755, 0), (stat.S_IFDIR | 0o755, 1000), (stat.S_IFDIR | 0o775, 0)):
            with patch.object(Path, "lstat", return_value=Mock(st_mode=mode, st_uid=uid)):
                with self.assertRaises(forwarders.ForwarderError):
                    forwarders.verify_directory(Path("/test"))
        with patch.object(Path, "lstat", return_value=Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0)):
            forwarders.verify_directory(Path("/test"))

    def test_command_error_preserves_diagnostic(self):
        with patch.object(subprocess, "run", return_value=Mock(returncode=1, stderr="bad unit\nsyntax", stdout="")):
            with self.assertRaisesRegex(forwarders.ForwarderError, "bad unit syntax"):
                forwarders.run_command(["systemd-analyze", "verify"])


class OwnedFileTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.units = root / "systemd"
        self.units.mkdir()
        self.helper = root / "helper" / "prepare_bridge_forwarders.py"
        self.topology = self.helper.with_name("topology.json")
        self.input = root / "input.json"
        self.input.write_bytes(RAW)
        self.flags = ["--topology", str(self.input), "--topology-sha256", PIN]
        replacements = [patch.object(forwarders, "UNITS", self.units),
                        patch.object(forwarders, "HELPER", self.helper),
                        patch.object(forwarders, "TOPOLOGY", self.topology),
                        patch.object(forwarders, "verify_directory")]
        real_fstat = os.fstat
        def root_fstat(fd):
            values = list(real_fstat(fd))
            values[4] = 0
            return os.stat_result(values)
        replacements.append(patch.object(os, "fstat", side_effect=root_fstat))
        for replacement in replacements:
            replacement.start()
            self.addCleanup(replacement.stop)
        self.files = forwarders.build_files(TOPOLOGY, RAW)

    def test_preview_offline_and_pin_failure_before_host_access(self):
        with patch.object(forwarders, "run_command") as run, patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(forwarders.main(["preview", *self.flags]), 0)
        run.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), forwarders.build_units(TOPOLOGY, PIN))
        self.input.write_bytes(RAW + b" ")
        with patch.object(forwarders, "verify_host") as host, patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(forwarders.main(["install", "--apply", *self.flags]), 1)
        host.assert_not_called()

    def test_dryrun_and_scope_threading(self):
        with patch.object(forwarders, "verify_host"), patch.object(forwarders, "verify_owned_files") as ownership, \
                patch.object(forwarders, "verify_ports") as ports, patch.object(os, "access", return_value=True), \
                patch.object(forwarders, "run_command", return_value="--connections-max=") as run, \
                patch.object(forwarders, "verify_filters"), \
                patch.object(forwarders, "check_backends", return_value=[{"ready": True}]) as backends, \
                patch.object(forwarders, "install_files") as install, patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(forwarders.main(["install", "--scope", "edges", *self.flags]), 0)
        install.assert_not_called()
        ports.assert_called_once_with(TOPOLOGY, "edges")
        backends.assert_called_once_with(TOPOLOGY, "edges")
        self.assertEqual(len(ownership.call_args.args[0]), 20)
        self.assertEqual(run.call_count, 1)

    def test_backend_failure_blocks_install(self):
        with patch.object(forwarders, "verify_host"), patch.object(forwarders, "verify_owned_files"), \
                patch.object(forwarders, "verify_ports"), patch.object(os, "access", return_value=True), \
                patch.object(forwarders, "run_command", return_value="--connections-max="), \
                patch.object(forwarders, "verify_filters"), \
                patch.object(forwarders, "check_backends", return_value=[{"ready": False}]), \
                patch.object(forwarders, "install_files") as install, \
                patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(forwarders.main(["install", "--apply", *self.flags]), 1)
        install.assert_not_called()

    def test_create_only_idempotent_and_no_start_enable(self):
        foreign = self.units / "existing-forwarder.service"
        foreign.write_text("untouched")
        with patch.object(forwarders, "run_command", return_value="") as run:
            forwarders.install_files(self.files)
            inodes = {path: path.stat().st_ino for path in self.files}
            forwarders.install_files(self.files)
        self.assertEqual({path: path.stat().st_ino for path in self.files}, inodes)
        self.assertEqual(stat.S_IMODE(self.topology.stat().st_mode), 0o600)
        self.assertEqual(foreign.read_text(), "untouched")
        self.assertEqual([call.args[0] for call in run.call_args_list].count(["systemctl", "daemon-reload"]), 1)
        self.assertTrue(all(call.args[0][0] == "systemd-analyze" or call.args[0] == ["systemctl", "daemon-reload"]
                            for call in run.call_args_list))

    def test_atomic_write_never_exposes_partial_destination(self):
        path = self.units / "unit.service"
        real_link = os.link
        def publish(source, destination, **kwargs):
            self.assertFalse(path.exists())
            self.assertEqual((path.parent / source).read_bytes(), b"complete unit")
            return real_link(source, destination, **kwargs)
        with patch.object(os, "link", side_effect=publish):
            forwarders.write_new(path, b"complete unit", 0o644)
        with self.assertRaises(FileExistsError):
            forwarders.write_new(path, b"replacement", 0o644)
        self.assertEqual(list(self.units.iterdir()), [path])
        self.assertEqual(path.read_bytes(), b"complete unit")

    def test_failed_stage_leaves_no_destination_or_temporary(self):
        path = self.units / "unit.service"
        with patch.object(os, "fsync", side_effect=OSError("sync failed")):
            with self.assertRaises(OSError):
                forwarders.write_new(path, b"complete unit", 0o644)
        self.assertFalse(path.exists())
        self.assertEqual(list(self.units.iterdir()), [])

    def test_changed_symlink_hardlink_and_wrong_mode_rejected(self):
        path = next(iter(self.files))
        path.write_bytes(b"truncated")
        path.chmod(0o644)
        with self.assertRaisesRegex(forwarders.ForwarderError, "changed/unowned"):
            forwarders.install_files(self.files)
        self.assertEqual(path.read_bytes(), b"truncated")
        alias = self.units / "alias.service"
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            forwarders.read_owned_file(alias, b"truncated")
        alias.unlink()
        os.link(path, alias)
        with self.assertRaises(forwarders.ForwarderError):
            forwarders.read_owned_file(path, b"truncated")
        alias.unlink()
        path.chmod(0o666)
        with self.assertRaises(forwarders.ForwarderError):
            forwarders.read_owned_file(path, b"truncated")

    def test_failed_install_removes_only_new_files(self):
        existing = next(iter(self.files))
        existing.write_bytes(self.files[existing])
        existing.chmod(0o644)
        with patch.object(forwarders, "run_command", side_effect=forwarders.ForwarderError("verify failed")):
            with self.assertRaises(forwarders.ForwarderError):
                forwarders.install_files(self.files)
        self.assertEqual(set(self.units.iterdir()), {existing})
        self.assertFalse(self.helper.parent.exists())

    def test_failed_reload_reloads_after_cleanup(self):
        with patch.object(forwarders, "run_command", side_effect=["", forwarders.ForwarderError("reload failed"), ""]) as run:
            with self.assertRaises(forwarders.ForwarderError):
                forwarders.install_files(self.files)
        self.assertEqual(list(self.units.iterdir()), [])
        self.assertEqual(run.call_args_list[-1].args[0], ["systemctl", "daemon-reload"])

    def test_scoped_install_rollback_preserves_other_scope_and_shared_files(self):
        edge_files = forwarders.build_files(TOPOLOGY, RAW, "edges")
        proxy_files = forwarders.build_files(TOPOLOGY, RAW, "proxies")
        with patch.object(forwarders, "run_command", return_value=""):
            forwarders.install_files(edge_files)
            helper_inode = self.helper.stat().st_ino
            forwarders.install_files(proxy_files)
        self.assertEqual(helper_inode, self.helper.stat().st_ino)
        foreign = self.units / "existing-forwarder.service"
        foreign.write_text("untouched")
        with patch.object(forwarders, "run_command", return_value="") as run, \
                patch.object(forwarders, "get_unit_properties", return_value={"ActiveState": "inactive"}):
            forwarders.rollback_files(edge_files, set(edge_files))
            self.assertTrue(all(path.exists() for path in proxy_files))
            self.assertTrue(all(not path.exists() for path in edge_files if path.parent == self.units))
            self.assertTrue(all("-system." not in " ".join(call.args[0]) for call in run.call_args_list))
            forwarders.rollback_files(proxy_files, set(proxy_files))
            forwarders.rollback_files(self.files, set())
        self.assertEqual(set(self.units.iterdir()), {foreign})
        self.assertFalse(self.helper.parent.exists())

    def test_changed_topology_blocks_rollback_before_stop(self):
        with patch.object(forwarders, "run_command", return_value=""):
            forwarders.install_files(self.files)
        self.topology.write_bytes(RAW + b" ")
        with patch.object(forwarders, "verify_host"), patch.object(forwarders, "verify_unit_overrides"), \
                patch.object(forwarders, "run_command") as run, patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(forwarders.main(["rollback", "--apply", *self.flags]), 1)
        run.assert_not_called()
        self.assertTrue(all(path.exists() for path in self.files))

    def test_failed_stop_preserves_files(self):
        with patch.object(forwarders, "run_command", return_value=""):
            forwarders.install_files(self.files)
        with patch.object(forwarders, "run_command", side_effect=forwarders.ForwarderError("stop failed")):
            with self.assertRaises(forwarders.ForwarderError):
                forwarders.rollback_files(self.files, set(self.files))
        self.assertTrue(all(path.exists() for path in self.files))

    def test_dropins_and_foreign_unit_paths_rejected(self):
        vendor = self.units.parent / "vendor"
        vendor.mkdir()
        names = list(forwarders.build_units(TOPOLOGY, PIN))
        with patch.object(forwarders, "run_command", return_value=f"{self.units}\n{vendor}\n"):
            forwarders.verify_unit_overrides(names)
            dropin = vendor / "service.d"
            dropin.mkdir()
            with self.assertRaisesRegex(forwarders.ForwarderError, "drop-ins"):
                forwarders.verify_unit_overrides(names)
            dropin.rmdir()
            (vendor / names[0]).write_text("foreign")
            with self.assertRaisesRegex(forwarders.ForwarderError, "shadows"):
                forwarders.verify_unit_overrides(names)

    def test_foreign_loaded_and_enabled_units_rejected(self):
        for properties in ({"LoadState": "loaded", "ActiveState": "inactive", "FragmentPath": "/foreign/unit"},
                           {"LoadState": "not-found", "ActiveState": "active"},
                           {"LoadState": "not-found", "ActiveState": "inactive", "UnitFileState": "enabled"},
                           {"LoadState": "masked", "ActiveState": "inactive"}):
            with patch.object(forwarders, "verify_unit_overrides"), \
                    patch.object(forwarders, "get_unit_properties", return_value=properties):
                with self.assertRaises(forwarders.ForwarderError):
                    forwarders.verify_owned_files(self.files, require_inactive=False)

    def test_rollback_allows_only_present_owned_active_units(self):
        with patch.object(forwarders, "run_command", return_value=""):
            forwarders.install_files(self.files)
        def properties(name):
            return {"LoadState": "loaded", "ActiveState": "active", "FragmentPath": str(self.units / name)}
        with patch.object(forwarders, "verify_unit_overrides"), \
                patch.object(forwarders, "get_unit_properties", side_effect=properties):
            self.assertEqual(forwarders.verify_owned_files(self.files, require_inactive=False), set(self.files))
            next(iter(self.files)).unlink()
            with self.assertRaisesRegex(forwarders.ForwarderError, "foreign loaded"):
                forwarders.verify_owned_files(self.files, require_inactive=False)

    def test_lock_contention_prevents_mutation(self):
        with patch.object(forwarders, "check_host"), patch.object(forwarders.fcntl, "flock", side_effect=BlockingIOError), \
                patch.object(forwarders, "install_files") as install, patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(forwarders.main(["install", "--apply", *self.flags]), 1)
        install.assert_not_called()


if __name__ == "__main__":
    unittest.main()
