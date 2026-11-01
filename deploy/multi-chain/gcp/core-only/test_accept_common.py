"""The pause window: restore on every exit, one chain at a time, illegal deposits first; gateway reads and the tunnel."""
import http.server
import json
import sys
import threading
import unittest
import unittest.mock
from types import SimpleNamespace

import accept_common as ac
import test_deploy_remote as remote_tests
from deploy_remote import Remote


class FakeAdmin:
    """Records every call; flags follow the last executed target, as the real read-back would."""

    def __init__(self, fail_pause=0, wrong_readback=False):
        self.calls, self.fail_pause, self.wrong_readback = [], fail_pause, wrong_readback

    def __call__(self, ctx, chain, target, execute):
        self.calls.append((chain, target, execute))
        if target == 1 and execute and self.fail_pause > 0:
            self.fail_pause -= 1
            raise RuntimeError("signer unreachable")
        flags = [[1, 0, 1]] * 3 if target == 1 else [[0, 0, 0]] * 3
        if self.wrong_readback and target == 1 and execute:
            flags = [[0, 0, 0]] * 3
        return {"ok": True, "flags": flags, "flagsBefore": [[1, 0, 1]] * 3, "broadcast": execute}


def window(admin, chain="sepolia"):
    return ac.unpaused_chain(None, chain, admin, sleep=lambda seconds: None)


class WindowTests(unittest.TestCase):
    def setUp(self):
        ac.OPEN_CHAINS.clear()
        self.addCleanup(ac.OPEN_CHAINS.clear)

    def test_the_pause_returns_after_a_normal_exit_and_is_read_back(self):
        admin = FakeAdmin()
        with window(admin):
            self.assertEqual(ac.OPEN_CHAINS, ["sepolia"])
        self.assertEqual(admin.calls, [("sepolia", 0, True), ("sepolia", 1, True)])
        self.assertEqual(ac.OPEN_CHAINS, [])

    def test_repause_runs_after_an_exception_and_the_exception_is_kept(self):
        admin = FakeAdmin()
        with self.assertRaisesRegex(ValueError, "deposit failed"):
            with window(admin):
                raise ValueError("deposit failed")
        self.assertEqual(admin.calls[-1], ("sepolia", 1, True))

    def test_repause_runs_after_keyboard_interrupt(self):
        admin = FakeAdmin()
        with self.assertRaises(KeyboardInterrupt):
            with window(admin):
                raise KeyboardInterrupt
        self.assertEqual(admin.calls[-1], ("sepolia", 1, True))
        self.assertEqual(ac.OPEN_CHAINS, [])

    def test_repause_retries_then_succeeds(self):
        admin = FakeAdmin(fail_pause=2)
        with window(admin):
            pass
        self.assertEqual([call for call in admin.calls if call[1] == 1], [("sepolia", 1, True)] * 3)

    def test_repause_failure_surfaces_with_the_original_error(self):
        admin = FakeAdmin(fail_pause=99)
        with self.assertRaises(RuntimeError) as caught:
            with window(admin):
                raise ValueError("gas ran out")
        message = str(caught.exception)
        self.assertIn("still OPEN", message)
        self.assertIn("ValueError: gas ran out", message)
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertEqual(ac.OPEN_CHAINS, ["sepolia"], "a chain that could not be paused keeps blocking the next window")

    def test_a_repause_that_reads_back_open_is_a_failure_even_without_an_original_error(self):
        with self.assertRaisesRegex(RuntimeError, "still OPEN"):
            with window(FakeAdmin(wrong_readback=True)):
                pass

    def test_an_unpause_that_does_not_read_back_open_never_starts_the_window(self):
        bad = lambda ctx, chain, target, execute: {"ok": True, "flags": [[1, 0, 1]] * 3}
        with self.assertRaisesRegex(ValueError, "not read back as open"):
            with window(bad):
                self.fail("the body must not run")

    def test_chains_are_unpaused_one_at_a_time(self):
        admin = FakeAdmin()
        with window(admin, "sepolia"):
            with self.assertRaisesRegex(RuntimeError, "one chain at a time"):
                with window(admin, "bscTestnet"):
                    pass
        self.assertNotIn(("bscTestnet", 0, True), admin.calls)

    def test_check_reports_a_chain_left_unpaused(self):
        def admin(ctx, chain, target, execute):
            before = [[0, 0, 0]] * 3 if chain == "bscTestnet" else [[1, 0, 1]] * 3
            return {"ok": True, "flagsBefore": before}
        self.assertEqual(ac.unpaused_chains(None, admin), ["bscTestnet"])


class RunWindowTests(unittest.TestCase):
    DOCUMENTS = {"sepolia": {"core": {"Bridge": "0x" + "b" * 40, "Router": "0x" + "c" * 40, "USDTToken": "0x" + "d" * 40}}}

    def setUp(self):
        ac.OPEN_CHAINS.clear()
        self.addCleanup(ac.OPEN_CHAINS.clear)
        self.events = []
        self.flags = list(ac.PAUSED)
        self.admin = FakeAdmin()

        def admin(ctx, chain, target, execute):
            self.events.append(("admin", target))
            self.flags = list(ac.OPEN if target == 0 else ac.PAUSED)
            return FakeAdmin.__call__(self.admin, ctx, chain, target, execute)
        self.admin_function = admin
        for name, replacement in (("read_flags", lambda chain, bridge, asset: list(self.flags)),
                                  ("estimate_deposit", self.estimate), ("wait_for_flags", lambda *args: None)):
            patcher = unittest.mock.patch.object(ac, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def estimate(self, chain, wallet, router, asset, amount):
        self.events.append(("estimate", amount, tuple(self.flags)))
        return (ac.REVERT_PAUSED if self.flags == ac.PAUSED else ac.REVERT_ZERO_AMOUNT if amount == 0 else None), None

    def run_window(self):
        return ac.run_window(None, "sepolia", self.DOCUMENTS, "0x" + "e" * 40, lambda: self.events.append(("deposit",)) or "done",
                             self.admin_function)

    def test_illegal_deposit_must_be_rejected_before_the_legal_one(self):
        self.assertEqual(self.run_window(), "done")
        kinds = [event[0] if event[0] != "admin" else f"admin{event[1]}" for event in self.events]
        self.assertEqual(kinds, ["estimate", "admin0", "estimate", "deposit", "admin1"])
        self.assertEqual(self.events[0][2], tuple(ac.PAUSED))
        self.assertEqual(self.events[2][1], 0)

    def test_a_paused_deposit_that_is_not_rejected_stops_before_any_unpause(self):
        with unittest.mock.patch.object(ac, "estimate_deposit", return_value=(None, 1)):
            with self.assertRaisesRegex(ValueError, "not rejected"):
                self.run_window()
        self.assertEqual([event for event in self.events if event[0] == "admin"], [])

    def test_a_failed_legal_deposit_still_restores_the_pause(self):
        def broken():
            raise RuntimeError("cli failed")
        with self.assertRaisesRegex(RuntimeError, "cli failed"):
            ac.run_window(None, "sepolia", self.DOCUMENTS, "0x" + "e" * 40, broken, self.admin_function)
        self.assertEqual(self.flags, ac.PAUSED)

    def test_a_chain_that_starts_open_is_refused(self):
        self.flags = list(ac.OPEN)
        with self.assertRaisesRegex(ValueError, "paused chain to start"):
            self.run_window()


class ChainReadTests(unittest.TestCase):
    def serve(self, answers):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(handler):
                body = json.loads(handler.rfile.read(int(handler.headers["Content-Length"])))
                reply = json.dumps({"jsonrpc": "2.0", "id": 1, **answers[body["method"]](body["params"])}).encode()
                handler.send_response(200)
                handler.send_header("Content-Length", str(len(reply)))
                handler.end_headers()
                handler.wfile.write(reply)

            def log_message(handler, *args):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def test_flags_and_reverts_are_read_over_http(self):
        url = self.serve({"eth_call": lambda params: {"result": "0x" + "".join(f"{value:064x}" for value in (1, 0, 1))},
                          "eth_estimateGas": lambda params: {"error": {"code": 3, "message": "execution reverted",
                                                                          "data": ac.REVERT_PAUSED + "00" * 32}}})
        with unittest.mock.patch.object(ac, "local_url", return_value=url):
            self.assertEqual(ac.read_flags("sepolia", "0x" + "b" * 40, "0x" + "d" * 40), [1, 0, 1])
            self.assertEqual(ac.estimate_deposit("sepolia", "0x" + "e" * 40, "0x" + "c" * 40, "0x" + "d" * 40, 5), (ac.REVERT_PAUSED, None))

    def test_a_successful_estimate_carries_the_measured_gas(self):
        url = self.serve({"eth_estimateGas": lambda params: {"result": hex(490275)}})
        with unittest.mock.patch.object(ac, "local_url", return_value=url):
            self.assertEqual(ac.estimate_deposit("sepolia", "0x" + "e" * 40, "0x" + "c" * 40, "0x" + "d" * 40, 5), (None, 490275))

    def test_the_deposit_calldata_is_selector_asset_amount_and_two_words(self):
        seen = {}
        with unittest.mock.patch.object(ac, "json_rpc", side_effect=lambda url, method, params: seen.update(params=params) or ("0x1", None)):
            ac.estimate_deposit("sepolia", "0x" + "e" * 40, "0x" + "c" * 40, "0x" + "d" * 40, 7)
        data = seen["params"][0]["data"]
        self.assertEqual(data[:10], ac.DEPOSIT_SELECTOR)
        self.assertEqual(len(data), 10 + 4 * 64)
        self.assertEqual(data[10:74], "0" * 24 + "d" * 40)
        self.assertEqual(int(data[74:138], 16), 7)


class TunnelTests(unittest.TestCase):
    def test_tunnel_argv_forwards_each_port_to_loopback_on_the_host(self):
        remote = Remote(remote_tests.ACCESS, remote_tests.LOCK, runner=None)
        argv = remote.tunnel_argv("inner", [(28545, 18545), (28645, 18645)])
        self.assertEqual(argv[0], "ssh")
        self.assertIn("-N", argv)
        self.assertIn("ExitOnForwardFailure=yes", argv)
        self.assertEqual([argv[index + 1] for index, value in enumerate(argv) if value == "-L"],
                         ["127.0.0.1:28545:127.0.0.1:18545", "127.0.0.1:28645:127.0.0.1:18645"])
        self.assertEqual(argv[-1], "ubuntu@10.0.0.2")

    def test_a_real_tunnel_process_is_waited_for_and_stopped(self):
        script = ("import socket, sys, time\nports = [int(p) for p in sys.argv[1:]]\n"
                  "servers = []\nfor port in ports:\n    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                  "    s.bind(('127.0.0.1', port)); s.listen(); servers.append(s)\ntime.sleep(60)\n")
        ports = [ac.GATEWAY_PORTS[chain] + ac.LOCAL_PORT_OFFSET for chain in ac.release_lock.CHAINS]
        remote = SimpleNamespace(tunnel_argv=lambda host, forwards: [sys.executable, "-c", script, *map(str, ports)])
        ctx = SimpleNamespace(remote=remote, lock={"l1": {"signer_host": "inner"}})
        with ac.gateway_tunnel(ctx) as forwards:
            self.assertEqual([local for local, _ in forwards], ports)
        import socket
        with socket.socket() as probe:
            probe.settimeout(1)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", ports[0])), 0)

    def test_a_tunnel_that_dies_at_once_fails_the_wait(self):
        remote = SimpleNamespace(tunnel_argv=lambda host, forwards: [sys.executable, "-c", "raise SystemExit(255)"])
        ctx = SimpleNamespace(remote=remote, lock={"l1": {"signer_host": "inner"}})
        with self.assertRaisesRegex(RuntimeError, "tunnel exited"):
            with ac.gateway_tunnel(ctx):
                pass


if __name__ == "__main__":
    unittest.main()
