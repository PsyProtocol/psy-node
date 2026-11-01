import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
import unittest
import unittest.mock

import deploy
import deploy_monitoring_steps as steps
import release_lock
import test_release_lock
from deploy_remote import DeployContext, OperatorPending, Remote, RemoteError, find_secret

CHAINS = [{"name": "sepolia", "index": 0, "chain_id": 11155111}, {"name": "bscTestnet", "index": 1, "chain_id": 97},
          {"name": "baseSepolia", "index": 2, "chain_id": 84532}]
ADAPTER = steps.ADAPTER
NOTIFIER = Path(os.environ["PSY_NOTIFIER_DIR"]) if os.environ.get("PSY_NOTIFIER_DIR") else None
TARGET = os.environ.get("CARGO_TARGET_DIR")
TOPOLOGY = {
    "hosts": {"gcp-cp-ce": "10.148.0.25", "gcp-realm-processor": "10.148.0.37", "gcp-edge-1": "10.148.0.36"},
    "coordinator": {"host": "gcp-cp-ce", "edge_ports": [15370, 15371, 15372]},
    "realms": [{"id": 0, "validators": [
        {"registration_id": 0, "validator_user_id": 7, "processor_host": "gcp-realm-processor", "edge_host": "gcp-edge-1",
         "http_port": 15380},
        {"registration_id": 4, "validator_user_id": 9, "processor_host": "gcp-realm-processor", "edge_host": "gcp-edge-1",
         "http_port": 15381}]}],
}
LOCK_HOSTS = {"gcp-faucet": "10.148.0.33", "gcp-coordinator-worker": "10.148.0.31", "gcp-psy-service": "10.148.0.38",
              "arc99x1": "10.250.0.13", "arc99x3": "10.250.0.12"}
OLD_EXPECTED = "".join(f'[[collectors.expected]]\nid = "{host}"\nenvironment = "staging"\nheartbeat_timeout = "60s"\n\n'
                       for host in ("gcp-cp-ce", "gcp-faucet", "arc99x4"))
ETHEREUM = """
[[ethereum]]
environment = "staging"
network_id = "{net}"
address = "0x490f8192725255c2c3de0cbce66312335ca019ad"
expected_chain_id = {cid}
primary_url_env = "ethereum-{net}-primary-url"
balance_warning_wei = "{warn}"
balance_critical_wei = "{crit}"
balance_recovery_wei = "{rec}"
"""
ARC_BASE = """schema_version = 1

[collector]
id = "arc99x3"

[[targets]]
id = "h"
kind = "host"

[[targets.probes]]
id = "host-resources"
kind = "host"
interval = "5s"

[[targets]]
id = "offsite-prove-proxy"
kind = "prove_proxy"

[[targets.services]]
id = "p"
unit = "parth-prove-proxy@user.service"
"""
CP_BASE = """[collector]
id = "gcp-cp-ce"

[[filters.immediate_patterns]]
name = "psy-services-nostr-unavailable"
regex = 'x'

[[targets]]
id = "gcp-cp-ce-host"
kind = "host"

[[targets.probes]]
id = "host-resources"
kind = "host"
interval = "5s"

[[targets]]
id = "coordinator-0"
kind = "coordinator"

[[targets.services]]
id = "processor"
unit = "parth-coordinator-processor.service"
"""
GATEWAY_BASE = """[[targets]]
id = "wireguard-gateway"
kind = "infrastructure"

[[targets.services]]
id = "wireguard"
unit = "wg-quick@wg0.service"

[[targets.services]]
id = "prove-ingress"
unit = "parth-offsite-prove-ingress.service"
"""


def controller_text(warning=None):
    text = 'schema_version = 1\n[server]\ngrpc_listen = "127.0.0.1:9443"\n\n' + OLD_EXPECTED
    for chain in CHAINS:
        floor_warning, floor_critical = steps.threshold_floors(chain["name"])
        text += ETHEREUM.format(net=steps.NETWORK_IDS[chain["name"]], cid=chain["chain_id"],
                                warn=floor_warning if warning is None else warning, crit=floor_critical,
                                rec=floor_warning * 2)
    return text + '\n[balance_report]\nenabled = true\n'


class FakeRemote:
    """Records calls; operator hosts refuse root, as the real Remote does."""

    def __init__(self, units_by_host=None, state_manager="0x" + "ab" * 20, status=None, operator=()):
        self.units_by_host, self.state_manager, self.status = units_by_host or {}, state_manager, status
        self.operator, self.calls = set(operator), []

    def missing_aliases(self, aliases):
        return []

    def ssh_config(self):
        return "Host x\n"

    def run_script(self, host, script, timeout_seconds):
        self.calls.append((host, script))
        if "list-units" in script:
            return "".join(f"{unit} loaded active running {unit}\n" for unit in self.units_by_host.get(host, []))
        return json.dumps(self.status)

    def run_root_text(self, host, argv, timeout_seconds, **options):
        raise RemoteError(f"operator host {host} cannot run sudo without a prompt", host=host)

    def read_text(self, host, path):
        return json.dumps({"core": {"StateManager": self.state_manager}})


class Fixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.release_dir, self.private_dir, self.run_dir = root / "release", root / "private", root / "run"
        for path in (self.release_dir, self.private_dir, self.run_dir):
            path.mkdir()
        (self.private_dir / "state").mkdir()
        self.lock = test_release_lock.build_test_lock(self.release_dir, self.private_dir, topology_text=json.dumps(TOPOLOGY))
        self.lock["hosts"] = dict(LOCK_HOSTS)
        self.lock["sources"]["notifier"] = ""
        self.lock["l1"]["signer"] = "0x" + "12" * 20
        (self.release_dir / "release.json").write_text(json.dumps(
            {"chains": CHAINS, "core_placement": {"relayer": "gcp-coordinator-worker"}}))
        self.notifier = root / "notifier"
        (self.notifier / "config/staging/collectors").mkdir(parents=True)
        (self.notifier / steps.CONTROLLER_CONFIG).write_text(controller_text())
        collectors = self.notifier / "config/staging/collectors"
        (collectors / "arc99x3.toml").write_text(ARC_BASE)
        (collectors / "gcp-cp-ce.toml").write_text(CP_BASE)
        (collectors / "gcp-faucet.toml").write_text(GATEWAY_BASE)
        (self.private_dir / "local-inputs.json").write_text(json.dumps({"notifier": {"checkout": str(self.notifier)}}))

    def context(self, remote):
        return DeployContext(lock=self.lock, lock_sha256="a" * 64, release_dir=self.release_dir, run_dir=self.run_dir,
                             remote=remote, private_dir=self.private_dir, state_dir=self.private_dir / "state")

    def render(self, remote=None):
        return steps.render_files(self.context(remote or FakeRemote()))


class HostTests(Fixture):
    def test_monitoring_hosts_come_from_release(self):
        hosts = steps.monitoring_hosts(self.release_dir, self.lock)
        self.assertEqual({alias for alias, _ in hosts}, set(LOCK_HOSTS) | set(TOPOLOGY["hosts"]))
        self.assertEqual({alias for alias, zone in hosts if zone == "offsite"}, {"arc99x1", "arc99x3"})
        self.lock["hosts"]["guardian-next-9"] = "10.148.0.99"
        self.assertIn(("guardian-next-9", "gcp"), steps.monitoring_hosts(self.release_dir, self.lock))
        script = ADAPTER.read_text()
        self.assertIsNone(re.search(r"gcp-(cp-ce|scylla|nats)|arc99x[0-9]", script), "no host list in the adapter")
        self.assertFalse((ADAPTER.parent / "monitoring-arc99x3.toml").exists())

    def test_unit_patterns_are_the_lock_prefixes(self):
        patterns = steps.unit_patterns(self.lock)
        listing = f"{self.lock['units']['relayer']} loaded active running x\nparth-relayer.service loaded active running x\n"
        self.assertEqual(steps.parse_unit_list(listing, patterns), [self.lock["units"]["relayer"]])

    def test_ssh_config_covers_every_access_host_including_jumped_ones(self):
        access = {"known_hosts": "/priv/known_hosts", "hosts": {
            "jump": {"ssh": "ubuntu@203.0.113.1", "identity": self.key("jump"), "jump": None, "sudo": "passwordless"},
            "guardian-next-1": {"ssh": "ubuntu@10.148.0.39", "identity": self.key("g"), "jump": "jump",
                                "sudo": "passwordless"}}}
        text = Remote(access, {"hosts": {"guardian-next-1": "10.148.0.39"}}).ssh_config()
        self.assertIn("Host guardian-next-1", text)
        self.assertRegex(text, r"ProxyCommand ssh .* -W %h:%p ubuntu@203\.0\.113\.1")
        self.assertIn("StrictHostKeyChecking yes", text)

    def key(self, name):
        path = Path(self.directory.name) / f"key-{name}"
        path.write_text("fixture\n")
        return str(path)

    def test_missing_access_aliases_are_refused_before_apply(self):
        remote = FakeRemote()
        remote.missing_aliases = lambda aliases: ["guardian-next-1"]
        with self.assertRaisesRegex(ValueError, "guardian-next-1"):
            self.render(remote)


class CollectorTests(Fixture):
    def collector(self, host, units=()):
        work = self.render(FakeRemote({host: list(units)}))
        return tomllib.loads((work / "collectors" / f"{host}.toml").read_text()), (work / "collectors" / f"{host}.toml").read_text()

    def test_every_host_gets_a_config_with_five_second_host_probe(self):
        work = self.render()
        hosts = [alias for alias, _ in steps.monitoring_hosts(self.release_dir, self.lock)]
        for alias in hosts:
            document = tomllib.loads((work / "collectors" / f"{alias}.toml").read_text())
            probes = [probe for target in document["targets"] for probe in target.get("probes", [])
                      if probe["id"] == "host-resources"]
            self.assertEqual([probe["interval"] for probe in probes], ["5s"], alias)
        self.assertEqual((work / "hosts").read_text().count("offsite"), 2)

    def test_core_targets_keep_checkpoint_probes_on_release_ports(self):
        document, _ = self.collector("gcp-cp-ce")
        targets = {target["id"]: target for target in document["targets"]}
        for index, port in enumerate((15370, 15371, 15372)):
            probe = targets[f"coordinator-edge-{index}"]["probes"][0]
            self.assertEqual((probe["id"], probe["url"]), ("latest-checkpoint", f"http://10.148.0.25:{port}"))
            self.assertEqual(targets[f"coordinator-edge-{index}"]["labels"], {"replica_id": str(index)})
        self.assertEqual(targets["coordinator-processor"]["services"][0]["id"], "processor")
        self.assertNotIn("coordinator-0", targets)
        edges, _ = self.collector("gcp-edge-1")
        urls = sorted(target["probes"][0]["url"] for target in edges["targets"] if "probes" in target
                      and target["kind"] == "realm")
        self.assertEqual(urls, ["http://10.148.0.36:15380", "http://10.148.0.36:15381"])
        edge = next(target for target in edges["targets"] if target["id"] == "realm-0-v1-edge")
        self.assertEqual(edge["labels"], {"realm_id": "0", "validator_id": "7", "registration_id": "0",
                                          "expected_validators": "2"})
        self.assertEqual(edge["services"][0]["unit"], self.lock["units"]["core_prefix"] + "realm-0-v1-edge.service")
        processors, _ = self.collector("gcp-realm-processor")
        self.assertEqual({target["id"] for target in processors["targets"] if target["kind"] == "realm"},
                         {"realm-0-v1-processor", "realm-0-v2-processor"})

    def test_non_parth_services_filters_and_infrastructure_survive(self):
        proxy = self.lock["units"]["proxy_prefix"] + "user.service"
        arc, text = self.collector("arc99x3", [proxy])
        self.assertIn(proxy, text)
        self.assertNotIn("parth-prove-proxy", text)
        self.assertIn("10.250.0.1:9443", text)
        ids = {target["id"] for target in arc["targets"]}
        self.assertEqual(ids, {"h", "arc99x3-release-units"})
        faucet, _ = self.collector("gcp-faucet")
        wireguard = next(target for target in faucet["targets"] if target["id"] == "wireguard-gateway")
        self.assertEqual([service["unit"] for service in wireguard["services"]], ["wg-quick@wg0.service"])
        cp, _ = self.collector("gcp-cp-ce")
        self.assertEqual(cp["filters"]["immediate_patterns"][0]["name"], "psy-services-nostr-unavailable")

    def test_services_unit_gets_the_nostr_filter_and_a_matching_service_id(self):
        unit = self.lock["units"]["services"]
        document, _ = self.collector("gcp-psy-service", [unit])
        self.assertEqual(document["filters"]["immediate_patterns"][0]["name"], "psy-services-nostr-unavailable")
        service = document["targets"][-1]["services"][0]
        self.assertEqual((service["id"], service["unit"]), ("psy-services", unit))
        rule = tomllib.loads(self.rule_text())
        self.assertIn(service["id"], rule["service_ids"])

    def rule_text(self):
        if NOTIFIER is None:
            return 'service_ids = ["psy-services"]'
        config = tomllib.loads((NOTIFIER / steps.CONTROLLER_CONFIG).read_text())
        rule = next(rule for rule in config["rules"] if rule["id"] == "psy-services-nostr-unavailable")
        return "service_ids = " + json.dumps(rule["match"]["service_ids"])

    def test_discovery_uses_a_script_so_operator_hosts_work(self):
        remote = FakeRemote({"arc99x1": [self.lock["units"]["proxy_prefix"] + "system.service"]}, operator=["arc99x1"])
        units = steps.discover_units(self.context(remote), "arc99x1")
        self.assertEqual(units, [self.lock["units"]["proxy_prefix"] + "system.service"])
        self.assertIn("systemctl", remote.calls[0][1])


class ControllerTests(Fixture):
    def test_expected_collectors_are_exactly_the_release_hosts(self):
        work = self.render()
        rendered = tomllib.loads((work / "controller.toml").read_text())
        hosts = {alias for alias, _ in steps.monitoring_hosts(self.release_dir, self.lock)}
        self.assertEqual({expected["id"] for expected in rendered["collectors"]["expected"]}, hosts)
        self.assertNotIn("arc99x4", (work / "controller.toml").read_text())

    def test_controller_config_gets_release_signer_and_one_settlement_probe_per_chain(self):
        rendered = tomllib.loads((self.render() / "controller.toml").read_text())
        self.assertEqual({monitor["address"] for monitor in rendered["ethereum"]}, {self.lock["l1"]["signer"]})
        probes = rendered["settlement"]
        self.assertEqual([probe["chain_index"] for probe in probes], [0, 1, 2])
        self.assertEqual([probe["expected_chain_id"] for probe in probes], [11155111, 97, 84532])
        self.assertEqual({probe["stall_after"] for probe in probes}, {"30m"})

    def test_missing_state_manager_is_refused(self):
        with self.assertRaises(ValueError):
            self.render(FakeRemote(state_manager="0x" + "0" * 40))

    def test_thresholds_below_the_finalize_runway_are_refused(self):
        (self.notifier / steps.CONTROLLER_CONFIG).write_text(controller_text(warning=50_000_000_000_000_000))
        with self.assertRaises(ValueError):
            self.render()

    def test_bsc_threshold_covers_seven_days_at_one_gwei(self):
        warning, critical = steps.threshold_floors("bscTestnet")
        self.assertGreaterEqual(warning, 7 * 240 * 360_000 * 10**9)
        self.assertEqual(critical * 7, warning * 2)

    @unittest.skipUnless(NOTIFIER and (NOTIFIER / steps.CONTROLLER_CONFIG).is_file(), "needs PSY_NOTIFIER_DIR")
    def test_committed_notifier_config_meets_the_floors(self):
        steps.check_thresholds(tomllib.loads((NOTIFIER / steps.CONTROLLER_CONFIG).read_text()), CHAINS)


@unittest.skipUnless(NOTIFIER and TARGET and shutil.which("cargo"), "needs PSY_NOTIFIER_DIR and CARGO_TARGET_DIR")
class RealPathTests(Fixture):
    """Real Remote in operator mode, real SSH config, and the Controller's own inventory gate."""

    def access(self):
        hosts = {"jump": {"ssh": "ubuntu@203.0.113.1", "identity": self.key("jump"), "jump": None, "sudo": "passwordless"}}
        for alias, address in {**LOCK_HOSTS, **TOPOLOGY["hosts"]}.items():
            operator = alias.startswith("arc99x")
            hosts[alias] = {"ssh": f"ubuntu@{address}", "identity": self.key(alias), "jump": "jump",
                            "sudo": "operator" if operator else "passwordless"}
        return {"known_hosts": "/priv/known_hosts", "hosts": hosts}

    def key(self, name):
        path = Path(self.directory.name) / f"key-{name}"
        path.write_text("fixture\n")
        return str(path)

    def runner(self, argv, **kwargs):
        script = kwargs["input"].decode()
        proxy = self.lock["units"]["proxy_prefix"] + "user.service"
        if "list-units" in script:
            reply = f"{proxy} loaded active running x\n" if "10.250.0.12" in " ".join(argv) else ""
        else:
            reply = json.dumps({"core": {"StateManager": "0x" + "cd" * 20}})
        return subprocess.CompletedProcess(argv, 0, reply.encode(), b"")

    def test_release_fleet_passes_the_real_inventory_gate_and_operator_hosts_are_discovered(self):
        (self.notifier / steps.CONTROLLER_CONFIG).write_text((NOTIFIER / steps.CONTROLLER_CONFIG).read_text())
        remote = Remote(self.access(), self.lock, runner=self.runner, topology_hosts=TOPOLOGY["hosts"])
        with self.assertRaises(RemoteError):
            remote.run_root_text("arc99x3", ["/usr/bin/true"], 5)
        work = self.render(remote)
        self.assertIn("arc99x3-release-units", (work / "collectors/arc99x3.toml").read_text())
        self.assertIn("Host arc99x3", (work / "ssh_config").read_text())
        self.assertEqual((work / "ssh_config").stat().st_mode & 0o077, 0)
        hosts = [alias for alias, _ in steps.monitoring_hosts(self.release_dir, self.lock)]
        environment = {**os.environ, "RENDERED_CONTROLLER_CONFIG": str(work / "controller.toml"),
                       "RENDERED_COLLECTOR_IDS": ",".join(hosts)}
        run = subprocess.run(["cargo", "test", "--offline", "-p", "psy-notifier-controller", "rendered_inventory",
                              "--", "--nocapture"], cwd=NOTIFIER, env=environment, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout[-800:] + run.stderr[-800:])
        self.assertIn(f"checked {len(hosts)} collectors", run.stdout)


class CheckoutTests(Fixture):
    def test_checkout_is_required_in_local_inputs(self):
        (self.private_dir / "local-inputs.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "notifier.checkout"):
            steps.check_notifier_checkout(self.context(FakeRemote()))

    def test_unset_pin_accepts_any_checkout_and_a_set_pin_must_match_a_clean_head(self):
        self.assertEqual(steps.check_notifier_checkout(self.context(FakeRemote())), self.notifier)
        git = lambda *args: subprocess.run(["git", "-C", str(self.notifier), "-c", "user.name=f", "-c", "user.email=f@x",
                                            *args], check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q")
        git("add", ".")
        git("commit", "-qm", "fixture")
        self.lock["sources"]["notifier"] = git("rev-parse", "HEAD")
        steps.check_notifier_checkout(self.context(FakeRemote()))
        (self.notifier / "stray").write_text("x")
        with self.assertRaisesRegex(ValueError, "clean"):
            steps.check_notifier_checkout(self.context(FakeRemote()))
        self.lock["sources"]["notifier"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "differs"):
            steps.check_notifier_checkout(self.context(FakeRemote()))

    def test_lock_carries_a_notifier_source_that_stays_pending_until_set(self):
        self.assertIn("notifier", release_lock.SOURCES)
        lock = json.loads((ADAPTER.parent / "fresh-192-20261030/release-lock.json").read_text())
        self.assertEqual(lock["sources"]["notifier"], "")


class StatusTests(Fixture):
    def status(self, now):
        return {"ready": True, "evm_all_healthy": True, "settlement_all_healthy": True, "outbox_depth": 0,
                "incidents": [], "settlement_probes": [{"chain_index": i, "healthy": True, "last_finalized_checkpoint": 9}
                                                       for i in range(3)],
                "collectors": [{"collector_id": h, "environment": "staging", "last_seen_ms": now}
                               for h in ("a", "b")]}

    def test_status_requires_every_chain_and_host(self):
        now = 10_000_000
        self.assertIsNone(steps.evaluate_status(self.status(now), ["a", "b"], [0, 1, 2], now))
        for mutate in (lambda s: s.update(ready=False), lambda s: s.update(settlement_all_healthy=False),
                       lambda s: s["settlement_probes"].pop(1), lambda s: s["settlement_probes"][2].update(healthy=False),
                       lambda s: s["collectors"].pop(), lambda s: s["collectors"][0].update(last_seen_ms=now - 200_000)):
            status = self.status(now)
            mutate(status)
            self.assertIsNotNone(steps.evaluate_status(status, ["a", "b"], [0, 1, 2], now))

    def test_verify_reads_status_over_a_script_and_carries_no_secret(self):
        hosts = [alias for alias, _ in steps.monitoring_hosts(self.release_dir, self.lock)]
        now = int(time.time() * 1000)
        status = self.status(now)
        status["collectors"] = [{"collector_id": h, "environment": "staging", "last_seen_ms": now} for h in hosts]
        report = steps.monitoring_verify(self.context(FakeRemote(status=status)))
        self.assertEqual(report["hosts"], hosts)
        self.assertEqual([probe["chain_index"] for probe in report["settlement"]], [0, 1, 2])
        self.assertFalse(find_secret(report))


class StepTests(Fixture):
    def test_step_is_registered_and_not_a_cutover(self):
        step = steps.MONITORING_STEPS["deploy_monitoring"]
        self.assertFalse(step.cutover)
        self.assertIs(deploy.build_registry()["deploy_monitoring"], step)

    def adapter(self, codes, stdout=""):
        outputs = iter(codes)
        def run(ctx, mode, work):
            return unittest.mock.Mock(returncode=next(outputs), stdout=stdout, stderr="")
        return run

    def test_offsite_installation_is_pending_with_the_printed_commands(self):
        printed = ("[monitoring] user action: ssh -t arc99x1 'cd ~/psy-notifier-install && sudo ./install-collector.sh'\n"
                   "[monitoring] user action: ssh -t arc99x3 'cd ~/psy-notifier-install && sudo ./install-collector.sh'\n"
                   "[monitoring] PENDING: cloud installed\n")
        with unittest.mock.patch.object(steps, "run_adapter", self.adapter([1, 3], printed)):
            with self.assertRaises(OperatorPending) as raised:
                steps.monitoring_apply(self.context(FakeRemote()))
        self.assertEqual(raised.exception.host, "arc99x1")
        self.assertEqual(raised.exception.command.count("sudo ./install-collector.sh"), 2)
        self.assertIn("ssh -t arc99x3", raised.exception.command)

    def test_ready_fleet_skips_installation(self):
        modes = []
        def run(ctx, mode, work):
            modes.append(mode)
            return unittest.mock.Mock(returncode=0, stdout="", stderr="")
        with unittest.mock.patch.object(steps, "run_adapter", run):
            steps.monitoring_apply(self.context(FakeRemote()))
        self.assertEqual(modes, ["--status"])

    def test_adapter_environment_uses_the_rendered_inputs_and_the_generated_ssh_config(self):
        work = self.render()
        env = steps.adapter_env(self.context(FakeRemote()), work)
        self.assertEqual(env["MONITORING_SSH_CONFIG"], str(work / "ssh_config"))
        self.assertEqual(env["MONITORING_NOTIFIER_DIR"], str(self.notifier))
        self.assertEqual(json.loads(env["MONITORING_CHAIN_INDEXES"]), [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
