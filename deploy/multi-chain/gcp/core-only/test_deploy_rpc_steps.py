#!/usr/bin/env python3
import hashlib
import json
import unittest
from types import SimpleNamespace
from unittest import mock

import deploy_rpc_steps as rpc
from deploy_prepare_steps import file_sha256


class FakeRemote:
    def __init__(self, state, journal=""):
        self.state, self.journal, self.calls = state, journal, []

    def run_root_text(self, host, argv, timeout, stdin_text=None, show_stderr=True):
        self.calls.append(argv)
        if "-c" in argv and argv[argv.index("-c") + 1] == rpc.READ_STATE:
            return json.dumps(self.state)
        if argv[0].endswith("journalctl"):
            return self.journal
        return ""


def ctx(state, journal=""):
    return SimpleNamespace(remote=FakeRemote(state, journal))


RETAINED = next(line.split("'")[1] for line in rpc.SOURCE.read_text().splitlines() if line.startswith("WRAPPER_SHA256"))
INSTALLED = {"target": file_sha256(rpc.SOURCE), "drop_in": rpc.text_sha256(rpc.DROP_IN_TEXT), "retained": RETAINED}
FRESH = "\n".join(json.dumps({"chain": chain, "local_fresh": True}) for chain in rpc.CHAINS)


class RpcSteps(unittest.TestCase):
    def test_check_needs_the_retained_wrapper(self):
        with self.assertRaises(Exception):
            rpc.rpc_check(ctx({**INSTALLED, "retained": None}))

    def test_check_refuses_another_retained_wrapper(self):
        with self.assertRaises(Exception):
            rpc.rpc_check(ctx({**INSTALLED, "retained": "ab" * 32}))

    def test_apply_leaves_a_settled_gateway_alone(self):
        context = ctx(INSTALLED)
        rpc.rpc_apply(context)
        self.assertFalse(any("restart" in argv for argv in context.remote.calls))

    def test_apply_installs_and_restarts_once(self):
        context = ctx({**INSTALLED, "target": None})
        rpc.rpc_apply(context)
        self.assertEqual(sum("restart" in argv for argv in context.remote.calls), 1)
        self.assertEqual(sum("daemon-reload" in argv for argv in context.remote.calls), 1)

    def test_verify_needs_every_chain_fresh(self):
        journal = FRESH + "\n" + json.dumps({"chain": "bscTestnet", "local_fresh": False})
        with mock.patch.object(rpc, "FRESH_WAIT_SECONDS", 0), self.assertRaises(TimeoutError):
            rpc.rpc_verify(ctx(INSTALLED, journal))

    def test_verify_records_the_settled_state(self):
        result = rpc.rpc_verify(ctx(INSTALLED, FRESH))
        self.assertTrue(all(result["local_fresh"].values()))

    def test_drop_in_runs_the_target(self):
        self.assertIn(rpc.TARGET, rpc.DROP_IN_TEXT)
        self.assertTrue(rpc.DROP_IN_TEXT.startswith("[Service]\nExecStart=\n"))


if __name__ == "__main__":
    unittest.main()
