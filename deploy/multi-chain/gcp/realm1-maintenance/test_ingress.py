import copy
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import ingress as i


def fixture():
    pool = {"handler": "reverse_proxy", "upstreams": [{"dial": x} for x in i.UPSTREAMS],
            "health_checks": {"active": {"uri": "/"}}}
    routes = [{"match": [{"host": [h]}], "handle": [copy.deepcopy(pool)], "terminal": True}
              for h in sorted(i.HOSTS)]
    routes.append({"match": [{"host": ["services-stg.psy-protocol.xyz"]}],
                   "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "10.148.0.38:3000"}]}]})
    return {"logging": {"logs": {"private": {"level": "INFO"}}},
            "apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": routes}}}}}


class IngressTests(unittest.TestCase):
    def test_atomic_save_failure_keeps_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Caddyfile"
            path.write_text("original")
            with patch.object(i.os, "replace", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    i.save(path, "candidate", 0o644)
            self.assertEqual(path.read_text(), "original")
            self.assertEqual(list(Path(directory).iterdir()), [path])
            i.save(path, "candidate", 0o644)
            self.assertEqual(path.read_text(), "candidate")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_atomic_save_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Caddyfile"
            destination = Path(directory) / "original"
            destination.write_text("original")
            path.symlink_to(destination)
            with self.assertRaises(RuntimeError):
                i.save(path, "candidate")
            self.assertEqual(destination.read_text(), "original")

    def test_only_two_public_upstreams_change(self):
        original = fixture()
        candidate, backend = i.render(original)
        self.assertEqual(original, fixture())
        restored = copy.deepcopy(candidate)
        for r in i.realm_routes(restored):
            next(i.proxies(r))["upstreams"] = [{"dial": x} for x in i.UPSTREAMS]
        self.assertEqual(restored, original)
        private = backend["apps"]["http"]["servers"]["realm1_private"]
        self.assertEqual(private["listen"], ["127.0.0.1:21342"])
        self.assertEqual(next(i.proxies(private)), next(i.proxies(i.realm_routes(original)[0])))

    def test_unknown_pool_fails_closed(self):
        config = fixture()
        next(i.proxies(i.realm_routes(config)[0]))["upstreams"][0]["dial"] = "1.1.1.1:1339"
        with self.assertRaises(RuntimeError):
            i.render(config)

    def test_missing_alias_fails_closed(self):
        config = fixture()
        config["apps"]["http"]["servers"]["srv0"]["routes"].pop(0)
        with self.assertRaises(RuntimeError):
            i.render(config)

    def test_normalization_preserves_real_hidden_paths(self):
        a = {"handler": "file_server", "hide": ["/dev/stdin", "*.key"]}
        b = {"handler": "file_server", "hide": ["./-", "*.key"]}
        self.assertEqual(i.normalize(a), i.normalize(b))
        b["hide"].pop()
        self.assertNotEqual(i.normalize(a), i.normalize(b))


if __name__ == "__main__":
    unittest.main()
