import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import finalize_bridge_setup as finalize

VERIFIERS = {
    "bridge_agg": "GnarkGroth16Verifier.sol",
    "deposit_append": "DepositBatchVerifier.sol",
    "withdrawal_claim": "WithdrawalClaimVerifier.sol",
    "reward_claim": "RewardClaimVerifier.sol",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Fixture:
    def __init__(self, root, network="testnet", magic="0x1337CF514544CF69"):
        root = Path(root)
        self.setup, self.contracts = root / "setup", root / "contracts"
        (self.contracts / "src").mkdir(parents=True)
        self.binary, self.config = root / "cli", root / "config.json"
        self.binary.write_bytes(b"binary")
        self.config.write_bytes(b"config")
        for cohort, verifier in VERIFIERS.items():
            keystore = self.setup / "keystore"
            if cohort != "bridge_agg":
                keystore = keystore / cohort
            keystore.mkdir(parents=True, exist_ok=True)
            for name in ("circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"):
                (keystore / name).write_bytes((cohort + name).encode())
            (self.setup / verifier).write_bytes(("verifier " + cohort).encode())
            (self.contracts / "src" / verifier).write_bytes(("verifier " + cohort).encode())
            (self.setup / (cohort + ".log")).write_text(
                "[prove] groth16.Verify took 1s\nproofString {}\n")
        self.build = root / "manifest.json"
        self.build.write_text(json.dumps({
            "network": network, "network_magic": magic, "source_commit": "c" * 40,
            "config_sha256": sha(b"config"), "local_circuits_sha256": "d" * 64,
            "binaries": {"psy_relayer_cli": sha(b"binary"), "psy_user_cli": sha(b"user")},
        }))
        self.checker = root / "checker.cjs"
        self.checker.write_text("// stub")

    def checker_ok(self, argv, **kwargs):
        assert argv[0] == "node" and argv[1] == str(self.checker)
        assert argv[2] == str(self.contracts) and argv[3] == str(self.setup)
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    def export_same(self, binary, config, keystore, target):
        cohort = Path(keystore).name if Path(keystore).name != "keystore" else "bridge_agg"
        Path(target).write_bytes(("verifier " + cohort).encode())

    def run(self, **override):
        args = dict(setup=self.setup, contracts=self.contracts, binary=self.binary,
                    config=self.config, build_manifest=self.build, checker=self.checker,
                    run=self.checker_ok, export=self.export_same)
        args.update(override)
        return finalize.finalize(**args)


class FinalizeBridgeSetupTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def test_finalize_rejects_binary_hash_mismatch(self):
        fixture = Fixture(self.root)
        fixture.binary.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "binary"):
            fixture.run()
        self.assertFalse((fixture.setup / "setup-manifest.json").exists())

    def test_finalize_rejects_network_other_than_testnet(self):
        fixture = Fixture(self.root, network="mainnet")
        with self.assertRaisesRegex(ValueError, "network"):
            fixture.run()
        other = Fixture(self.root / "b", magic="0x1")
        with self.assertRaisesRegex(ValueError, "magic"):
            other.run()

    def test_finalize_records_all_four_verifier_hashes(self):
        fixture = Fixture(self.root)
        fixture.run()
        manifest = json.loads((fixture.setup / "setup-manifest.json").read_text())
        self.assertEqual(manifest["magic"], "0x1337CF514544CF69")
        self.assertEqual(manifest["generator"]["binary_sha256"], sha(b"binary"))
        self.assertEqual(manifest["consumer"]["binary_sha256"], sha(b"user"))
        self.assertNotEqual(manifest["consumer"]["binary_sha256"],
                            manifest["generator"]["binary_sha256"])
        self.assertEqual(manifest["consumer"]["config_sha256"], sha(b"config"))
        self.assertEqual(set(manifest["verifier_solidity_sha256"]), set(VERIFIERS))
        for cohort, verifier in VERIFIERS.items():
            self.assertEqual(manifest["verifier_solidity_sha256"][cohort],
                             sha(("verifier " + cohort).encode()))
        self.assertEqual(len(manifest["files"]), 12)

    def test_finalize_rejects_contract_source_that_differs_from_export(self):
        fixture = Fixture(self.root)
        (fixture.contracts / "src" / "WithdrawalClaimVerifier.sol").write_bytes(b"stale")
        with self.assertRaisesRegex(ValueError, "differs"):
            fixture.run()

    def test_finalize_checker_failure_writes_no_manifest_and_allows_rerun(self):
        fixture = Fixture(self.root)
        failing = lambda argv, **k: subprocess.CompletedProcess(argv, 1, "", "bad")
        with self.assertRaises(SystemExit):
            fixture.run(run=failing)
        self.assertFalse((fixture.setup / "setup-manifest.json").exists())
        self.assertFalse((fixture.setup / "evm-verification.json").exists())
        fixture.run()
        self.assertTrue((fixture.setup / "setup-manifest.json").exists())

    def test_finalize_rejects_any_existing_output_before_running(self):
        for name in ("evm-verification.json", "setup-manifest.json", "verifiers.json"):
            fixture = Fixture(self.root / name)
            (fixture.setup / name).write_text("{}")
            with self.assertRaisesRegex(ValueError, "already exists"):
                fixture.run(run=None)

    def test_finalize_rejects_config_hash_mismatch(self):
        fixture = Fixture(self.root)
        fixture.config.write_bytes(b"other config")
        with self.assertRaisesRegex(ValueError, "config"):
            fixture.run()

    def test_finalize_rejects_logs_without_verify_or_with_extra_proofs(self):
        for text, message in (("proofString {}\n", "native verification"),
                              ("[prove] groth16.Verify took 1s\n", "exactly one proof"),
                              ("[prove] groth16.Verify took 1s\nproofString {}\nproofString {}\n",
                               "exactly one proof")):
            fixture = Fixture(self.root / message / str(len(text)))
            (fixture.setup / "reward_claim.log").write_text(text)
            with self.assertRaisesRegex(ValueError, message):
                fixture.run()

    def test_finalize_rejects_empty_key_file(self):
        fixture = Fixture(self.root)
        (fixture.setup / "keystore" / "reward_claim" / "vk_groth16.bin").write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            fixture.run()

    def test_finalize_rejects_keystore_that_does_not_match_the_verifier(self):
        fixture = Fixture(self.root)
        def export_other(binary, config, keystore, target):
            Path(target).write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "re-export"):
            fixture.run(export=export_other)


if __name__ == "__main__":
    unittest.main()
