#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).parents[1] / "remote/patch-envio-rpc-source.py"
spec = importlib.util.spec_from_file_location("policy", path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
RES = '''exception QueryTimout(string)
  let logsPromise =
    provider
    pollingInterval: 1000,
    getHeightOrThrow: () => Rpc.GetBlockHeight.route->Rest.fetch((), ~client),
'''
JS = ''''use strict';
  var logsPromise = provider.getLogs({});
pollingInterval: 1000,
              return Rest.$$fetch(Rpc.GetBlockHeight.route, undefined, client);
'''


class TestPatch(unittest.TestCase):
    def test_both_formats_and_idempotence(self):
        for kind, text in (("res", RES), ("js", JS)):
            out = policy.transformed(text, kind)
            self.assertNotIn("pollingInterval: 1000", out)
            self.assertEqual(policy.transformed(out, kind), out)

    def test_changed_dependency_layout_fails(self):
        with self.assertRaises(RuntimeError):
            policy.transformed(JS.replace("pollingInterval: 1000", "pollingInterval: 2000"), "js")

    def test_duplicate_anchor_fails(self):
        with self.assertRaises(RuntimeError):
            policy.transformed(RES + RES, "res")

    def test_variable_mention_is_not_enough(self):
        out = policy.transformed(JS, "js").replace("pollingInterval: psyRpcPollingInterval()", "pollingInterval: 1000")
        with self.assertRaises(RuntimeError):
            policy.verify(out, "js")

    def test_final_build_is_followed_by_gate(self):
        install = (path.parent / "install-envio.sh").read_text()
        tail = install.split("build_generated_rescript\n", 1)[1]
        self.assertLess(tail.index("patch_envio_rpc_source"), tail.index("--check"))
        self.assertIn("ExecStartPre=/usr/bin/python3 /opt/parth/envio/patch-envio-rpc-source.py", install)
        self.assertIn("ExecStart=/usr/local/bin/pnpm start\n", install)
        self.assertNotIn("ExecStart=/usr/local/bin/pnpm dev", install)


if __name__ == "__main__":
    unittest.main()
