"""Tests of steps 65-67 and the Worker package builder with a fake Remote; nothing here touches a host."""
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import deploy
import deploy_core_steps as steps
import deploy_health as health
import deploy_prepare_steps as prepare_steps
import install_host
import prepare_workers
from deploy_remote import RemoteConnectionError, RemoteError
from test_deploy_prepare_steps import Workspace, done, run_all, sha

FRESH_TOPOLOGY = Path(__file__).resolve().parents[1] / "fresh-192-20261030" / "topology.json"
WORKER_LABELS = ("pickup", "prove", "submit")
LEASE_NS = 30_000_000_000
PROCESSOR_HOSTS = install_host.PROCESSORS
EDGE_HOSTS = install_host.EDGES
COORDINATOR_HOST = steps.COORDINATOR_HOST


class FakeRemote:
    """A tiny model of the hosts: unit states, keyspaces, markers, edge heights, connections and NATS consumers."""

    def __init__(self, fixture, *, installed=False, active=False):
        self.fixture = fixture
        self.units = {}
        for host, unit_set in fixture.unit_sets().items():
            self.units[host] = {unit: self.row(unit_set, installed, active) for unit in unit_set.units}
        self.events, self.copies, self.broken = [], [], {}
        self.height, self.heights, self.restarts, self.panics, self.uploads = 1000, {}, {}, {}, 7
        self.pids, self.no_log, self.whitelist_errors = {}, set(), {}
        self.realm_marker_after, self.realm_marker_calls = 0, 0
        self.keyspace_calls, self.no_tablet_after = 0, 0
        self.drop_connection = None
        self.consumers = [{"stream": "s", "ack_policy": "explicit", "ack_wait": LEASE_NS, "max_deliver": -1}]
        self.evidence = {unit: {label: 4 for label in WORKER_LABELS} for unit in self.units[health.WORKER_HOST]}
        self.edge_config_sha256 = fixture.lock["inputs"]["runtime_config"]
        self.wrong_binary = set()
        self.fail_run_script = None

    @staticmethod
    def row(unit_set, installed, active):
        row = {"load": "loaded" if installed or active else "not-found", "active": "inactive", "exe": None, "sha256": None}
        if active:
            row.update(active="active", exe=unit_set.exe_path, sha256=unit_set.exe_sha256)
        return row

    def realm_marker_ready(self):
        return self.realm_marker_calls >= self.realm_marker_after

    def tablet_ready(self):
        return self.keyspace_calls > self.no_tablet_after

    def check_reachable(self, host):
        if host in self.broken:
            error = self.broken[host]
            if isinstance(error, list):
                if error:
                    raise error.pop(0)
            else:
                raise error

    def run_script(self, host, script, timeout_seconds):
        self.check_reachable(host)
        if "psy_get_latest_checkpoint_id" in script:
            return self.sample_output(host, script)
        if self.fail_run_script and self.fail_run_script in script:
            raise RemoteError(f"{host}: exit 1: failed", host=host, exit_code=1)
        for text, event in (("install -d", "stage"), ("rm -rf", "unstage"), ("sha256sum -c", "verify-tools")):
            if text in script:
                self.events.append((event, host))
        return ""

    def copy_files(self, host, sources, destination, **options):
        self.copies.append((host, sorted(Path(source).name for source in sources), destination))

    def set_state(self, host, units, **changes):
        for unit in units:
            self.units[host][unit].update(changes)

    def run_root_json(self, host, argv, timeout, *, show_stderr=False):
        tool, arguments = Path(argv[3]).name, argv[4:]
        names = sorted(self.units[host])
        unit_set = self.fixture.unit_sets()[host]
        if tool == "install_host.py" or arguments[:1] == ["install"]:
            self.events.append(("install", host))
            self.set_state(host, names, load="loaded")
            return {"mode": "installed"}
        if tool == "prepare_workers.py" and arguments[:1] == ["check-host"]:
            self.events.append(("check-host", host))
            return {"mode": "checked"}
        phase = arguments[arguments.index("--phase") + 1] if "--phase" in arguments else "workers"
        selected = steps.phase_units(unit_set, phase) if phase != "workers" else names
        self.events.append(("activate", host, phase, self.realm_marker_ready(), self.tablet_ready()))
        for unit in selected:
            sha256 = "0" * 64 if unit in self.wrong_binary else unit_set.exe_sha256
            self.units[host][unit].update(active="active", exe=unit_set.exe_path, sha256=sha256)
        return {"started": True}

    def keyspaces(self):
        self.keyspace_calls += 1
        found, topology = [], self.fixture.topology
        coordinator = self.units[COORDINATOR_HOST]
        if any(row["active"] == "active" for unit, row in coordinator.items() if unit.endswith("coordinator-processor.service")):
            found.append(topology["coordinator"]["namespace"])
        for realm in topology["realms"]:
            for position, validator in enumerate(realm["validators"], start=1):
                ending = f"realm-{realm['id']}-v{position}-processor.service"
                processor = self.units[PROCESSOR_HOSTS[position - 1]]
                if any(row["active"] == "active" for unit, row in processor.items() if unit.endswith(ending)):
                    found.append(validator["namespace"])
        return found + ([name + steps.NO_TABLET_SUFFIX for name in found] if self.tablet_ready() else [])

    def sample_output(self, host, script):
        lines = []
        for line in script.splitlines():
            rpc, unit = re.fullmatch(r"rpc (\S+) (\S+) &", line), re.fullmatch(r"unit (\S+)", line)
            if rpc:
                height = self.heights.get(rpc.group(1), self.height)
                lines.append(f"edge {rpc.group(1)} " + ("timeout" if height is None else json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "result": height})))
            elif unit:
                name = unit.group(1)
                state = self.units[host][name]["active"]
                pid = self.pids.get(name, 1000 + sorted(self.units[host]).index(name))
                lines.append(f"unit {name} LoadState=loaded ActiveState={state} MainPID={pid} "
                             f"NRestarts={self.restarts.get(name, 0)} ")
                lines += ([f"nolog {name}"] if name in self.no_log else
                          [f"panic {name} {text}" for text in self.panics.get(name, [])])
            elif line.startswith('echo "uploads'):
                lines.append(f"uploads {self.uploads}")
        return "\n".join(lines)

    def marker_output(self, host, script):
        labels = dict((text, name) for name, text in steps.WORKER_MARKERS)
        lines = []
        for found in re.findall(r"-u (\S+) --no-pager -o cat -g (?:'([^']*)'|(\S+))", script):
            unit, marker = found[0], found[1] or found[2]
            if marker == steps.REALM_INIT_MARKER:
                self.realm_marker_calls += 1
                count = 1 if self.realm_marker_ready() else 0
            elif marker == steps.COORDINATOR_INIT_MARKER:
                count = 1 if self.units[host][unit]["active"] == "active" else 0
            elif marker == steps.WHITELIST_ERROR_PATTERN:
                count = self.whitelist_errors.get(unit, 0)
            else:
                count = self.evidence[unit][labels[marker]]
            lines.append(f"{unit} {count}")
        return "\n".join(lines)

    def connection_output(self, host):
        topology, hosts, lines = self.fixture.topology, self.fixture.topology["hosts"], []
        for realm in topology["realms"]:
            validators = realm["validators"]
            for position, validator in enumerate(validators, start=1):
                if validator["processor_host"] != host:
                    continue
                local = f"{hosts[host]}:{validator['processor_port']}"
                peers = [f"{hosts[o['processor_host']]}:{o['processor_port']}" for o in validators if o is not validator]
                peers += [f"{hosts[o['edge_host']]}:{o['edge_port']}" for o in validators]
                for peer in peers:
                    if self.drop_connection != (realm["id"], position, peer):
                        lines.append(f"conn {local} {peer}")
        return "\n".join(lines)

    def run_root_text(self, host, argv, timeout, *, stdin_text=None, show_stderr=False):
        self.check_reachable(host)
        if argv[:4] == steps.ROOT_PYTHON:
            if argv[4:5] == ["nats-consumers"]:
                assert stdin_text == (self.fixture.ws.tools_dir / "probe_databases.py").read_text()
                return json.dumps({"ok": True, "component": "nats", "consumers": self.consumers})
            return json.dumps({unit: {**self.units[host][unit], "restarts": 0} for unit in argv[4:]})
        if argv[0] == steps.DOCKER:
            return "\n keyspace_name\n---------\n" + "\n".join(f" {name}" for name in self.keyspaces()) + "\n"
        if argv[0] == "/usr/bin/sha256sum":
            return f"{self.edge_config_sha256}  {argv[-1]}\n"
        if "ss -Htn" in (stdin_text or ""):
            return self.connection_output(host)
        if "NRestarts" in (stdin_text or ""):
            return self.sample_output(host, stdin_text)
        return self.marker_output(host, stdin_text)


class CoreFixture:
    """A synthetic release: the fresh topology, a lock edited in step with it, and staged package directories."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ws = Workspace(self.temp.name)
        self.lock = self.ws.lock
        text = FRESH_TOPOLOGY.read_text()
        (self.ws.release_dir / "topology.json").write_text(text)
        self.lock["inputs"]["topology"] = sha(text)
        self.topology = json.loads(text)
        self.whitelist = {"networks": {"testnet": {"whitelist": {
            "enabled": True, "secp256k1": sorted(set(prepare_workers.PUBLIC_KEYS.values()))}}}}
        self.write_policy(self.whitelist)
        self.patchers = [patch.object(steps, "TOOLS_DIR", self.ws.tools_dir)]
        for patcher in self.patchers:
            patcher.start()
        self.write_core_packages()
        self.worker_root = self.ws.root / "worker-package"
        self.worker_root.mkdir()
        (self.worker_root / "psy_worker_cli").write_bytes(b"worker")
        (self.ws.state_dir / "prepare_packages.json").write_text(json.dumps(
            {"core": str(self.core_root), "worker": str(self.worker_root)}))

    def close(self):
        for patcher in self.patchers:
            patcher.stop()
        self.temp.cleanup()

    def write_core_packages(self):
        self.core_root = self.ws.root / "core-packages"
        node, genesis = b"node", b"genesis"
        self.lock["binaries"]["psy_node_cli"], self.lock["inputs"]["genesis"] = sha(node), sha(genesis)
        files = {"bin/psy_node_cli": node, "config.json": self.config_bytes, "genesis.json": genesis}
        manifests = {}
        for host in install_host.HOSTS:
            for name, data in files.items():
                target = self.core_root / host / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            text = json.dumps({"schema_version": 1, "host": host, "files": {name: sha(data) for name, data in files.items()}})
            (self.core_root / host / "manifest.json").write_text(text)
            manifests[host] = sha(text)
        self.ws.set_artifacts(core_host_packages={"manifest_sha256": manifests})

    def write_policy(self, config, listed=None):
        ws = self.ws
        self.config_bytes = json.dumps(config).encode()
        ws.put_file("config", self.config_bytes, pin=lambda digest: self.lock["inputs"].update(runtime_config=digest))
        text = json.dumps(listed or self.whitelist)
        (ws.tools_dir / "worker-whitelist.json").write_text(text)
        self.lock["inputs"]["worker_whitelist"] = sha(text)
        ws.write_local()

    def context(self, remote):
        return self.ws.context(remote)

    def unit_sets(self):
        ctx = self.context(None)
        sets = steps.core_unit_sets(ctx)
        sets[health.WORKER_HOST] = steps.worker_unit_set(ctx)
        return sets


def wait_stub(remote, attempts=30):
    """A wait that polls without sleeping and moves the chain forward on every poll."""
    def wait(is_ready, read_failure, poll_seconds, timeout_seconds, label):
        for _ in range(attempts):
            remote.height += 5
            failure = read_failure()
            if failure:
                raise RuntimeError(f"{label}: failed while waiting: {failure}")
            if is_ready():
                return
        raise TimeoutError(f"{label}: not ready after {timeout_seconds}s")
    return wait


class StepTestCase(unittest.TestCase):
    def setUp(self):
        self.fixture = CoreFixture()
        self.addCleanup(self.fixture.close)
        self.lock = self.fixture.lock

    def start(self, **options):
        self.remote = FakeRemote(self.fixture, **options)
        self.ctx = self.fixture.context(self.remote)
        patcher = patch.object(steps, "wait_until", wait_stub(self.remote))
        patcher.start()
        self.addCleanup(patcher.stop)
        return self.ctx

    def events(self, *kinds):
        return [event for event in self.remote.events if event[0] in kinds]


class CoreStartTests(StepTestCase):
    def test_start_order_is_processor_edge_realm_wait_realm_edge(self):
        ctx = self.start()
        steps.core_apply(ctx)
        activations = [event[1:3] for event in self.events("activate")]
        self.assertEqual(activations, [(COORDINATOR_HOST, "processors"), (COORDINATOR_HOST, "edges"),
                                       *[(host, "processors") for host in PROCESSOR_HOSTS],
                                       *[(host, "edges") for host in EDGE_HOSTS]])
        installs = [event[1] for event in self.events("install")]
        self.assertEqual(sorted(installs), sorted(install_host.HOSTS))
        first_activation = next(index for index, event in enumerate(self.remote.events) if event[0] == "activate")
        self.assertTrue(all(self.remote.events.index(("install", host)) < first_activation for host in installs))

    def test_realm_edges_wait_for_namespace_init(self):
        ctx = self.start()
        self.remote.realm_marker_after = 4
        steps.core_apply(ctx)
        edge_events = [event for event in self.events("activate") if event[2] == "edges" and event[1] in EDGE_HOSTS]
        self.assertEqual(len(edge_events), 2)
        self.assertTrue(all(event[3] for event in edge_events))
        self.assertGreaterEqual(self.remote.realm_marker_calls, 4)

    def test_edges_wait_for_both_keyspaces_of_every_namespace(self):
        ctx = self.start()
        self.remote.no_tablet_after = 4
        steps.core_apply(ctx)
        edge_events = [event for event in self.events("activate") if event[2] == "edges"]
        self.assertEqual(len(edge_events), 3)
        self.assertTrue(all(event[4] for event in edge_events))
        self.assertEqual(steps.keyspaces_of(["a", "b"]), ["a", "a_no_tablet", "b", "b_no_tablet"])

    def test_coordinator_edges_wait_for_the_coordinator_marker(self):
        ctx = self.start()
        original = self.remote.marker_output
        waits = []
        def late(host, script):
            if steps.COORDINATOR_INIT_MARKER in script:
                waits.append(1)
                if len(waits) < 3:
                    return "\n".join(f"{unit} 0" for unit in re.findall(r"-u (\S+) --no-pager", script))
            return original(host, script)
        self.remote.marker_output = late
        steps.core_apply(ctx)
        self.assertGreaterEqual(len(waits), 3)

    def test_a_processor_that_dies_while_waiting_stops_the_step(self):
        ctx = self.start()
        original = self.remote.run_root_json
        def die_after_start(host, argv, timeout, **options):
            report = original(host, argv, timeout, **options)
            if host == PROCESSOR_HOSTS[0] and "processors" in argv:
                self.remote.set_state(host, list(self.remote.units[host]), active="failed")
            return report
        self.remote.run_root_json = die_after_start
        with self.assertRaisesRegex(RuntimeError, "failed while waiting"):
            steps.core_apply(ctx)
        self.assertEqual([event[1] for event in self.events("activate") if event[2] == "edges"], [COORDINATOR_HOST])

    def test_a_restart_or_a_panic_during_a_wait_stops_the_step(self):
        for change, message in ((lambda r: r.restarts.update({r.fixture.unit_sets()[PROCESSOR_HOSTS[0]].units[0]: 1}), "restarted"),
                                (lambda r: r.panics.update({r.fixture.unit_sets()[PROCESSOR_HOSTS[1]].units[0]: ["thread x panicked at y"]}),
                                 "panic in a unit log")):
            with self.subTest(message=message):
                ctx = self.start()
                change(self.remote)
                self.remote.realm_marker_after = 100
                with self.assertRaisesRegex(RuntimeError, message):
                    steps.core_apply(ctx)
                self.assertEqual([event[1] for event in self.events("activate") if event[2] == "edges"], [COORDINATOR_HOST])

    def test_packages_are_removed_from_hosts_even_when_the_start_fails(self):
        ctx = self.start()
        self.remote.fail_run_script = "sha256sum -c"
        with self.assertRaises(RemoteError):
            steps.core_apply(ctx)
        self.assertEqual(sorted(host for _, host in self.events("unstage")), sorted(host for _, host in self.events("stage")))
        self.assertEqual(self.events("install", "activate"), [])

    def test_rerun_skips_units_already_active_with_expected_hash(self):
        ctx = self.start(active=True)
        steps.core_apply(ctx)
        self.assertEqual(self.remote.events, [])
        self.assertEqual(self.remote.copies, [])

    def test_rerun_after_processors_only_starts_the_missing_phase_without_install(self):
        ctx = self.start(installed=True)
        for host in (COORDINATOR_HOST, *PROCESSOR_HOSTS):
            unit_set = self.fixture.unit_sets()[host]
            self.remote.set_state(host, steps.phase_units(unit_set, "processors"), active="active", exe=unit_set.exe_path,
                                  sha256=unit_set.exe_sha256)
        steps.core_apply(ctx)
        self.assertEqual(self.events("install"), [])
        self.assertEqual([event[1:3] for event in self.events("activate")],
                         [(COORDINATOR_HOST, "edges"), *[(host, "edges") for host in EDGE_HOSTS]])

    def test_an_active_unit_with_another_binary_is_never_restarted(self):
        ctx = self.start(installed=True)
        host = PROCESSOR_HOSTS[1]
        unit_set = self.fixture.unit_sets()[host]
        self.remote.set_state(host, [unit_set.units[0]], active="active", exe=unit_set.exe_path, sha256="1" * 64)
        with self.assertRaisesRegex(ValueError, "unexpected binary"):
            steps.core_apply(ctx)
        self.assertEqual(self.events("activate", "install"), [])

    def test_partly_installed_host_with_a_running_unit_is_refused(self):
        ctx = self.start()
        unit_set = self.fixture.unit_sets()[COORDINATOR_HOST]
        self.remote.set_state(COORDINATOR_HOST, unit_set.units[:1], load="loaded", active="active", exe=unit_set.exe_path,
                              sha256=unit_set.exe_sha256)
        with self.assertRaisesRegex(ValueError, "some units are active but others are not installed"):
            steps.core_apply(ctx)

    def test_check_needs_the_pinned_tools_and_a_package_bound_to_the_verified_manifest(self):
        ctx = self.start()
        steps.core_check(ctx)
        manifest = self.fixture.core_root / PROCESSOR_HOSTS[0] / "manifest.json"
        original = manifest.read_text()
        manifest.write_text(original + " ")
        with self.assertRaisesRegex(ValueError, "package manifest hash differs from artifacts"):
            steps.core_check(ctx)
        manifest.write_text(original)
        (self.fixture.core_root / EDGE_HOSTS[0] / "bin" / "psy_node_cli").write_bytes(b"other")
        with self.assertRaisesRegex(ValueError, "package file hash differs"):
            steps.core_check(ctx)
        (self.fixture.ws.tools_dir / "activate_host.py").write_text("changed")
        with self.assertRaisesRegex(ValueError, "tool hash differs: activate_host.py"):
            steps.core_check(ctx)


class CoreVerifyTests(StepTestCase):
    def test_core_verify_passes_with_sixteen_healthy_units_and_nine_agreeing_edges(self):
        ctx = self.start(active=True)
        report = steps.core_verify(ctx)
        self.assertEqual(sum(report["units"].values()), 16)
        self.assertEqual(len(report["edge_checkpoints"]), 9)
        self.assertEqual(report["ack_wait_ns"], LEASE_NS)

    def test_core_verify_does_not_demand_advance(self):
        ctx = self.start(active=True)
        patcher = patch.object(steps, "wait_until", wait_stub(self.remote, attempts=1))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.remote.height -= 5
        self.assertEqual(len(steps.core_verify(ctx)["edge_checkpoints"]), 9)

    def test_core_verify_requires_a_connection_per_peer_and_edge_for_every_validator(self):
        ctx = self.start(active=True)
        peer = f"{self.fixture.topology['hosts']['gcp-edge-2']}:{self.fixture.topology['realms'][1]['validators'][1]['edge_port']}"
        self.remote.drop_connection = (1, 2, peer)
        with self.assertRaisesRegex(ValueError, "realm 1 validator 2 lacks 1 of 5"):
            steps.core_verify(ctx)

    def test_core_verify_names_the_edge_that_does_not_answer(self):
        ctx = self.start(active=True)
        self.remote.heights["realm-1-v2"] = None
        with self.assertRaisesRegex(ValueError, r"no answer from \[realm-1-v2\]"):
            steps.core_verify(ctx)

    def test_core_verify_fails_when_an_edge_does_not_follow(self):
        ctx = self.start(active=True)
        self.remote.heights["realm-0-v3"] = 7
        with self.assertRaisesRegex(ValueError, "edges did not agree"):
            steps.core_verify(ctx)

    def test_core_verify_fails_on_an_inactive_unit_and_on_a_missing_namespace(self):
        ctx = self.start(active=True)
        host = EDGE_HOSTS[0]
        self.remote.set_state(host, self.fixture.unit_sets()[host].units[:1], active="inactive")
        with self.assertRaisesRegex(ValueError, "not active with the pinned binary"):
            steps.core_verify(ctx)
        ctx = self.start(active=True)
        self.remote.keyspaces = lambda: [self.fixture.topology["coordinator"]["namespace"]]
        with self.assertRaisesRegex(ValueError, "realm namespaces are not initialised"):
            steps.core_verify(ctx)

    def test_core_verify_needs_both_keyspaces_of_the_coordinator(self):
        ctx = self.start(active=True)
        names = FakeRemote.keyspaces(self.remote)
        coordinator = self.fixture.topology["coordinator"]["namespace"]
        self.remote.keyspaces = lambda: [name for name in names if name != coordinator + steps.NO_TABLET_SUFFIX]
        with self.assertRaisesRegex(ValueError, "coordinator namespace is not initialised"):
            steps.core_verify(ctx)

    def test_core_verify_reads_live_consumer_ack_wait_and_needs_consumers_to_exist(self):
        ctx = self.start(active=True)
        self.assertEqual(self.lock["gates"]["worker_queue_ack_wait_ms"], 30000)
        steps.core_verify(ctx)
        self.remote.consumers = [{"stream": "s", "ack_policy": "explicit", "ack_wait": 30000, "max_deliver": -1}]
        with self.assertRaisesRegex(ValueError, "ack_wait .*30000.* expected 30000000000 ns"):
            steps.core_verify(ctx)
        self.remote.consumers = []
        with self.assertRaisesRegex(ValueError, "no worker queue consumer exists"):
            steps.core_verify(ctx)

    def test_ack_wait_ignores_ack_all_and_bounded_redelivery_consumers(self):
        ctx = self.start(active=True)
        self.remote.consumers = [{"stream": "s", "ack_policy": "all", "ack_wait": 5_000_000_000, "max_deliver": 1},
                                 {"stream": "s", "ack_policy": "explicit", "ack_wait": 1, "max_deliver": 5},
                                 {"stream": "s", "ack_policy": "explicit", "ack_wait": LEASE_NS, "max_deliver": -1}]
        self.assertEqual(steps.check_ack_wait(ctx, True)["worker_consumers"], 1)

    def test_a_failed_consumer_listing_is_an_error_not_an_empty_list(self):
        ctx = self.start(active=True)
        original = self.remote.run_root_text
        def refused(host, argv, timeout, **options):
            if argv[4:5] == ["nats-consumers"]:
                return json.dumps({"ok": False, "error": "JetStream refused consumer listing"})
            return original(host, argv, timeout, **options)
        self.remote.run_root_text = refused
        with self.assertRaisesRegex(ValueError, "JetStream refused consumer listing"):
            steps.check_ack_wait(ctx, False)

    def test_the_consumer_listing_comes_from_the_pinned_probe(self):
        ctx = self.start(active=True)
        (self.fixture.ws.tools_dir / "probe_databases.py").write_text("changed")
        with self.assertRaisesRegex(ValueError, "tool hash differs: probe_databases.py"):
            steps.check_ack_wait(ctx, False)

    def test_verify_holds_when_rerun_on_a_chain_that_has_advanced(self):
        ctx = self.start(active=True)
        first = steps.core_verify(ctx)
        self.remote.height += 5000
        second = steps.core_verify(ctx)
        self.assertGreater(min(second["edge_checkpoints"].values()), max(first["edge_checkpoints"].values()))


class WorkerStepTests(StepTestCase):
    def coordinator_unit(self):
        return health.worker_units(self.ctx)[0]

    def realm_units(self):
        return health.worker_units(self.ctx)[1:]

    def test_workers_install_and_activate_then_clean_up(self):
        ctx = self.start()
        steps.workers_apply(ctx)
        self.assertEqual([event[0] for event in self.remote.events if event[1] == health.WORKER_HOST],
                         ["stage", "verify-tools", "check-host", "install", "activate", "unstage"])
        self.assertTrue(all(row["active"] == "active" for row in self.remote.units[health.WORKER_HOST].values()))

    def test_rerun_with_healthy_workers_does_nothing(self):
        ctx = self.start(active=True)
        steps.workers_apply(ctx)
        self.assertEqual(self.remote.events, [])

    def test_partly_installed_workers_are_refused(self):
        ctx = self.start()
        unit = self.fixture.unit_sets()[health.WORKER_HOST].units[0]
        self.remote.set_state(health.WORKER_HOST, [unit], load="loaded")
        with self.assertRaisesRegex(ValueError, "partly installed"):
            steps.workers_apply(ctx)

    def test_worker_with_another_binary_is_not_restarted(self):
        ctx = self.start(installed=True)
        unit_set = self.fixture.unit_sets()[health.WORKER_HOST]
        self.remote.set_state(health.WORKER_HOST, [unit_set.units[0]], active="active", exe=unit_set.exe_path, sha256="2" * 64)
        with self.assertRaisesRegex(ValueError, "unexpected binary"):
            steps.workers_apply(ctx)
        self.assertEqual(self.events("activate"), [])

    def test_check_verifies_the_package_and_the_pinned_tool(self):
        ctx = self.start()
        with patch.object(steps, "worker_verify") as verify:
            steps.workers_check(ctx)
        verify.assert_called_once()
        (self.fixture.ws.tools_dir / "prepare_workers.py").write_text("changed")
        with self.assertRaisesRegex(ValueError, "tool hash differs: prepare_workers.py"):
            steps.workers_check(ctx)

    def test_workers_verify_passes_with_coordinator_evidence_and_an_advancing_chain(self):
        ctx = self.start(active=True)
        report = steps.workers_verify(ctx)
        self.assertEqual(report["workers"], 3)
        self.assertEqual(set(report["coordinator_evidence"]), set(WORKER_LABELS))
        self.assertEqual(report["whitelist_errors"], 0)
        self.assertIn("deferred to acceptance", report["realm_proof_evidence"])

    def test_workers_verify_requires_coordinator_pickup_prove_and_submit(self):
        ctx = self.start(active=True)
        coordinator = self.coordinator_unit()
        for missing in WORKER_LABELS:
            with self.subTest(missing=missing):
                self.remote.evidence[coordinator][missing] = 0
                with self.assertRaisesRegex(ValueError, f"{coordinator}:{missing}"):
                    steps.workers_verify(ctx)
                self.remote.evidence[coordinator][missing] = 4

    def test_realm_workers_need_no_jobs_but_must_run_without_whitelist_errors(self):
        ctx = self.start(active=True)
        for unit in self.realm_units():
            self.remote.evidence[unit] = {label: 0 for label in WORKER_LABELS}
        steps.workers_verify(ctx)
        self.remote.whitelist_errors[self.realm_units()[1]] = 2
        with self.assertRaisesRegex(ValueError, "whitelist errors: .*realm-1"):
            steps.workers_verify(ctx)

    def test_workers_verify_requires_the_chain_to_advance(self):
        ctx = self.start(active=True)
        patcher = patch.object(steps, "wait_until", wait_stub(self.remote, attempts=3))
        patcher.start()
        self.addCleanup(patcher.stop)
        original = self.remote.sample_output
        frozen = self.remote.height
        def stuck(host, script):
            self.remote.height = frozen
            return original(host, script)
        self.remote.sample_output = stuck
        with self.assertRaisesRegex(ValueError, "did not advance together"):
            steps.workers_verify(ctx)

    def test_workers_verify_stops_on_a_worker_restart(self):
        ctx = self.start(active=True)
        self.remote.evidence[self.coordinator_unit()]["prove"] = 0
        self.remote.restarts[self.realm_units()[0]] = 1
        with self.assertRaisesRegex(RuntimeError, "restarted"):
            steps.workers_verify(ctx)

    def test_workers_verify_rejects_unlisted_worker(self):
        ctx = self.start(active=True)
        keys = self.fixture.whitelist["networks"]["testnet"]["whitelist"]["secp256k1"]
        extra = json.loads(json.dumps(self.fixture.whitelist))
        extra["networks"]["testnet"]["whitelist"]["secp256k1"] = [*keys, "03" + "ab" * 32]
        self.fixture.write_policy(extra)
        with self.assertRaisesRegex(ValueError, "whitelist differs from the lock whitelist"):
            steps.workers_verify(ctx)
        disabled = json.loads(json.dumps(self.fixture.whitelist))
        disabled["networks"]["testnet"]["whitelist"]["enabled"] = False
        self.fixture.write_policy(disabled)
        with self.assertRaisesRegex(ValueError, "whitelist is not enforced"):
            steps.workers_verify(ctx)
        self.fixture.write_policy(self.fixture.whitelist)
        steps.workers_verify(ctx)

    def test_a_worker_identity_missing_from_the_whitelist_is_refused(self):
        ctx = self.start(active=True)
        short = {"networks": {"testnet": {"whitelist": {"enabled": True, "secp256k1": ["03" + "cd" * 32]}}}}
        self.fixture.write_policy(short, listed=short)
        with self.assertRaisesRegex(ValueError, "identity is not on the whitelist"):
            steps.workers_verify(ctx)

    def test_an_edge_running_another_config_is_refused(self):
        ctx = self.start(active=True)
        self.remote.edge_config_sha256 = "3" * 64
        with self.assertRaisesRegex(ValueError, "Edge config differs"):
            steps.workers_verify(ctx)


def chain_samples(heights, **options):
    names = [target.name for target in health.edge_targets(CoreFixtureTopology.topology)]
    return [health.ChainSample({name: height for name in names}, {}, (), options.get("uploads", index * 3))
            for index, height in enumerate(heights)]


class CoreFixtureTopology:
    topology = json.loads(FRESH_TOPOLOGY.read_text())


class GateTests(StepTestCase):
    def feed(self, samples):
        queue = iter(samples)
        patcher = patch.object(health, "read_chain_sample", side_effect=lambda ctx: next(queue))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_gate_passes_after_the_required_checkpoints_and_records_the_evidence(self):
        ctx = self.start(active=True)
        self.feed(chain_samples(range(1000, 1200, 10)))
        steps.gate_apply(ctx)
        recorded = json.loads((self.fixture.ws.state_dir / "gate_l2_stability.json").read_text())
        self.assertEqual(recorded["advanced"], 100)
        self.assertEqual(recorded["proof_uploads"], 30)

    def test_gate_fails_on_checkpoint_regression(self):
        ctx = self.start(active=True)
        self.feed(chain_samples([1000, 1010, 1005]))
        with self.assertRaisesRegex(RuntimeError, "regressed"):
            steps.gate_apply(ctx)

    def test_unfinished_gate_reports_progress_at_the_limit(self):
        ctx = self.start(active=True)
        self.feed(chain_samples([1000 + 2 * index for index in range(30)]))
        with self.assertRaisesRegex(ValueError, "not passed within 2200s: advanced 58 of 100 checkpoints, 9 of 9 edges"):
            steps.gate_apply(ctx)

    def test_gate_without_proof_uploads_does_not_pass(self):
        ctx = self.start(active=True)
        self.feed(chain_samples(range(1000, 1400, 10), uploads=5))
        with self.assertRaisesRegex(ValueError, "5 proof uploads"):
            steps.gate_apply(ctx)

    def test_a_stalled_chain_stops_the_gate(self):
        ctx = self.start(active=True)
        self.feed(chain_samples([1000] * 10))
        with self.assertRaisesRegex(RuntimeError, "did not advance in 6 samples"):
            steps.gate_apply(ctx)

    def test_gate_rerun_starts_fresh_samples(self):
        ctx = self.start(active=True)
        self.feed(chain_samples([1000, 1010, 1005]))
        with self.assertRaises(RuntimeError):
            steps.gate_apply(ctx)
        ctx = self.start(active=True)
        self.feed(chain_samples(range(500, 700, 10)))
        steps.gate_apply(ctx)

    def test_gate_limit_comes_from_the_lock_count(self):
        self.lock["gates"]["l2_stability_checkpoint_count"] = 50
        self.assertEqual(health.gate_limit_seconds(steps.gate_required(self.start())), 1100)
        for bad in (0, True, "100", None):
            self.lock["gates"]["l2_stability_checkpoint_count"] = bad
            with self.assertRaises(ValueError):
                steps.gate_required(self.start())

    def record_gate(self):
        (self.fixture.ws.state_dir / "gate_l2_stability.json").write_text(json.dumps({"samples": 3}))

    def test_gate_verify_takes_a_fresh_strict_sample(self):
        ctx = self.start(active=True)
        self.record_gate()
        report = steps.gate_verify(ctx)
        self.assertEqual(report["units"], 19)
        self.assertEqual(report["worker_consumers"], 1)
        first_core = lambda r: r.fixture.unit_sets()[COORDINATOR_HOST].units[0]
        for change, message in ((lambda r: r.restarts.update({first_core(r): 1}), "restarted"),
                                (lambda r: r.panics.update({first_core(r): ["thread x panicked at y"]}), "panic"),
                                (lambda r: r.heights.update({"realm-0-v1": 1}), "do not agree")):
            ctx = self.start(active=True)
            change(self.remote)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                steps.gate_verify(ctx)

    def test_gate_verify_retries_a_silent_host_and_then_gives_up(self):
        ctx = self.start(active=True)
        self.record_gate()
        error = RemoteConnectionError("unreachable", host=EDGE_HOSTS[0], exit_code=255)
        self.remote.broken[EDGE_HOSTS[0]] = [error, error]
        self.assertEqual(steps.gate_verify(ctx)["units"], 19)
        ctx = self.start(active=True)
        self.remote.broken[EDGE_HOSTS[0]] = [error] * 9
        with self.assertRaisesRegex(ValueError, "not every unit could be read"):
            steps.gate_verify(ctx)
        self.assertEqual(len(self.remote.broken[EDGE_HOSTS[0]]), 9 - steps.FINAL_READ_ATTEMPTS)

    def test_a_timed_out_host_is_silent_but_a_failed_command_is_fatal(self):
        ctx = self.start(active=True)
        self.remote.broken[EDGE_HOSTS[0]] = [RemoteError("host: timed out after 120s", host=EDGE_HOSTS[0])]
        self.assertEqual(len(health.read_chain_sample(ctx).unit_restart_counts), 16)
        self.remote.broken[EDGE_HOSTS[0]] = [RemoteError("host: exit 124", host=EDGE_HOSTS[0], exit_code=124)]
        self.assertEqual(len(health.read_chain_sample(ctx).unit_restart_counts), 16)
        self.remote.broken[EDGE_HOSTS[0]] = [RemoteError("host: exit 1: boom", host=EDGE_HOSTS[0], exit_code=1)]
        with self.assertRaises(RemoteError):
            health.read_chain_sample(ctx)

    def test_gate_verify_without_a_recorded_gate_fails(self):
        ctx = self.start(active=True)
        with self.assertRaisesRegex(ValueError, "no recorded state"):
            steps.gate_verify(ctx)


class RegistrationTests(unittest.TestCase):
    def test_core_steps_are_cutover_steps_registered_in_the_orchestrator(self):
        self.assertEqual(set(steps.CORE_STEPS), {"start_core", "start_workers", "gate_l2_stability"})
        self.assertTrue(all(step.cutover and step.name == name for name, step in steps.CORE_STEPS.items()))
        self.assertIn("deploy_core_steps", deploy.STEP_MODULES)
        registry = deploy.build_registry()
        self.assertTrue(set(steps.CORE_STEPS) <= set(registry))
        table = Path(__file__).resolve().parents[1] / "fresh-192-20261030" / "steps.tsv"
        self.assertEqual(deploy.mismatched_cutover_steps(table, registry), [])

    def test_the_module_imports_from_deploy_remote_not_from_deploy(self):
        for module in (steps, health):
            self.assertNotRegex(Path(module.__file__).read_text(), r"(?m)^(import deploy|from deploy) ")


class WorkerPackageBuilderTests(unittest.TestCase):
    """The Worker entry of PACKAGE_BUILDERS in deploy_prepare_steps."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ws = Workspace(temp.name)
        patcher = patch.object(prepare_steps, "TOOLS_DIR", self.ws.tools_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.build_dir = self.ws.root / "build"
        self.build_dir.mkdir()
        self.output = self.ws.root / "worker-package"
        self.ws.local["packages"] = {"worker": {"output": str(self.output)}}
        self.ws.put_file("config", b"config", pin=lambda digest: self.ws.lock["inputs"].update(runtime_config=digest))
        self.ws.write_local()
        (self.ws.state_dir / "rebuild_binaries.json").write_text(json.dumps({"build_dir": str(self.build_dir)}))
        self.builder = [b for b in prepare_steps.PACKAGE_BUILDERS if b.name == "worker"][0]

    def test_the_worker_builder_is_registered_with_its_input_declaration(self):
        self.assertEqual([builder.name for builder in prepare_steps.PACKAGE_BUILDERS], ["core", "proxy", "worker", "faucet"])
        self.assertEqual(self.builder.inputs, ("output",))
        with patch.object(prepare_steps, "PACKAGE_BUILDERS", [self.builder]):
            prepare_steps.PREPARE_STEPS["prepare_packages"].check(self.ws.context())
            del self.ws.local["packages"]["worker"]["output"]
            self.ws.write_local()
            with self.assertRaisesRegex(ValueError, "lacks packages.worker.output"):
                prepare_steps.PREPARE_STEPS["prepare_packages"].check(self.ws.context())

    def test_build_calls_prepare_workers_with_the_lock_the_rebuilt_dir_and_the_config(self):
        calls = []
        with patch.object(prepare_steps, "run_local", side_effect=lambda argv, timeout=None: calls.append(argv) or done()):
            result = self.builder.build(self.ws.context(), {"output": str(self.output)})
        argv = calls[0]
        self.assertEqual(Path(argv[argv.index("package") - 1]).name, "prepare_workers.py")
        self.assertEqual(argv[argv.index("--release-lock") + 1], str(self.ws.release_dir / "release-lock.json"))
        self.assertEqual(argv[argv.index("--release-lock-sha256") + 1], "a" * 64)
        self.assertEqual(argv[argv.index("--build-dir") + 1], str(self.build_dir))
        self.assertEqual(argv[argv.index("--network-config") + 1], self.ws.local["files"]["config"])
        self.assertEqual(result, self.output)

    def test_build_refuses_a_tool_that_differs_from_the_lock_and_keeps_an_existing_package(self):
        self.output.mkdir()
        with patch.object(prepare_steps, "run_local") as run:
            self.assertEqual(self.builder.build(self.ws.context(), {"output": str(self.output)}), self.output)
        run.assert_not_called()
        self.output.rmdir()
        (self.ws.tools_dir / "prepare_workers.py").write_text("changed")
        with self.assertRaisesRegex(ValueError, "tool hash differs: prepare_workers.py"):
            self.builder.build(self.ws.context(), {"output": str(self.output)})

    def test_a_failed_tool_is_reported_without_its_output(self):
        with patch.object(prepare_steps, "run_local", return_value=done(1, "", "boom")):
            with self.assertRaisesRegex(RuntimeError, "prepare_workers failed"):
                self.builder.build(self.ws.context(), {"output": str(self.output)})

    def make_package(self):
        """Build a real package with the real tool code against a lock edited to match its inputs."""
        lock = self.ws.lock
        binary, config = b"worker-binary", b'{"defaultNetwork": "testnet", "networks": {"testnet": {"whitelist": ' + json.dumps(
            {"enabled": True, "secp256k1": sorted(set(prepare_workers.PUBLIC_KEYS.values()))}).encode() + b"}}}"
        topology = prepare_workers.encode(dict(json.loads(FRESH_TOPOLOGY.read_bytes()), release_id=lock["release_id"],
                                               runtime_commit=lock["sources"]["runtime"]))
        lock["binaries"]["psy_worker_cli"], lock["inputs"]["runtime_config"] = sha(binary), sha(config)
        lock["inputs"]["topology"] = sha(topology)
        lock["tool_sha256"]["prepare_workers.py"] = sha(Path(prepare_workers.__file__).read_bytes())
        build = {"source_commit": lock["sources"]["runtime"], "network": "testnet", "network_magic": lock["network_magic"],
                 "config_sha256": sha(config), "binaries": {"psy_worker_cli": sha(binary)}}
        (self.build_dir / "psy_worker_cli").write_bytes(binary)
        (self.build_dir / "manifest.json").write_bytes(prepare_workers.encode(build))
        for name, raw in (("config.json", config), ("topology.json", topology)):
            (self.ws.root / name).write_bytes(raw)
        prepare_workers.prepare_package(prepare_workers.load_worker_release(lock), self.build_dir,
                                        self.ws.root / "config.json", self.ws.root / "topology.json", self.output)

    def test_verify_accepts_a_real_package_and_rejects_a_tampered_one(self):
        self.make_package()
        report = self.builder.verify(self.ws.context(), {}, self.output)
        self.assertEqual(report["worker_sha256"], self.ws.lock["binaries"]["psy_worker_cli"])
        unit = next(path for path in self.output.iterdir() if path.name.endswith("coordinator.service"))
        unit.write_bytes(unit.read_bytes() + b"\n")
        with self.assertRaises(ValueError):
            self.builder.verify(self.ws.context(), {}, self.output)

    def test_verify_rejects_a_helper_that_differs_from_the_lock(self):
        self.make_package()
        self.ws.lock["tool_sha256"]["prepare_workers.py"] = "4" * 64
        with self.assertRaisesRegex(ValueError, "package helper differs from the lock"):
            self.builder.verify(self.ws.context(), {}, self.output)


if __name__ == "__main__":
    unittest.main()
