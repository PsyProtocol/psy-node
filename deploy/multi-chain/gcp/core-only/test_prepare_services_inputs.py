"""Focused offline input checks; no host, database or application commands."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_services_inputs as prep


class ServicesInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        rows = []
        for index, name in enumerate(prep.ABI_NAMES):
            methods = [{"name": f"method{i}", "method_id": i} for i in range(prep.METHOD_COUNTS[index])]
            if index in (0, 4):
                methods[0]["name"], methods[1]["name"] = "mint", "burn"
            if index == 3:
                methods[-1] = {"name": "set_chain_root", "method_id": 4192350829,
                               "input_felt_count": 10, "output_felt_count": 0}
            self.write(name + ".json", {"contract": {"name": name, "state_tree_height": prep.HEIGHTS[index],
                "state_layout": {"field_count": 1}, "methods": methods}})
            rows.append({"contract_id": index, "abi_path": name + ".json", "state_tree_height": prep.HEIGHTS[index]})
        self.write("abi_list.json", {"users": [], "contracts": [], "precompiles": rows})

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def test_active_six_abis_only(self):
        self.write("PsyPOWMiningRewardsClaimContract.json", {"unused": True})
        files = prep.read_abis(self.root)
        self.assertEqual(len(files), 7)
        self.assertNotIn("PsyPOWMiningRewardsClaimContract.json", files)

    def test_withdrawal_setter_required(self):
        path = self.root / "PsyWithdrawalTreeContract.json"
        value = json.loads(path.read_text())
        value["contract"]["methods"][-1]["name"] = "different_method"
        self.write(path.name, value)
        with self.assertRaisesRegex(ValueError, "withdrawal setter missing"):
            prep.read_abis(self.root)

    def test_token_mint_burn_required(self):
        path = self.root / "USDTTokenContract.json"
        value = json.loads(path.read_text())
        value["contract"]["methods"][0]["name"] = "different_method"
        self.write(path.name, value)
        with self.assertRaisesRegex(ValueError, "mint/burn missing"):
            prep.read_abis(self.root)

    def test_wrong_slot_rejected(self):
        value = json.loads((self.root / "abi_list.json").read_text())
        value["precompiles"][4]["contract_id"] = 7
        self.write("abi_list.json", value)
        with self.assertRaisesRegex(ValueError, "slot mismatch"):
            prep.read_abis(self.root)

    def test_existing_output_never_reused(self):
        with patch.object(prep, "check_source") as source:
            with self.assertRaisesRegex(ValueError, "output already exists"):
                prep.prepare(SimpleNamespace(output=self.root))
            source.assert_not_called()

    def test_all_validator_sources_use_fresh_backups(self):
        for realm in (0, 1):
            sources = prep.realm_sources(realm)
            self.assertEqual(sources["coordinator_backup_base_dir"], prep.MIRROR + "/cp/checkpoints")
            self.assertEqual([v["realm_sub_id"] for v in sources["validators"]], [1, 2, 3])
            self.assertEqual(sources["validators"][0]["backup_base_dir"], prep.BACKUPS)
            for sub in (2, 3):
                self.assertEqual(sources["validators"][sub - 1]["backup_base_dir"], f"{prep.MIRROR}/v{sub}/checkpoints")
            self.assertNotIn("20261026", json.dumps(sources))

    def test_fresh_state_preserves_owner_and_excludes_bridge_reader(self):
        topology = prep.topology()
        self.assertEqual(topology["database"], "psy_services_fresh_20261027_r3")
        self.assertEqual(topology["database_owner"], "psy_services_fresh_20261026")
        self.assertFalse(topology["bridge_reader_enabled"])
        self.assertFalse(topology["nostr_enabled"])
        self.assertEqual(topology["hasura_url"], "http://10.148.0.24:38081/v1/graphql")
        self.assertEqual(topology["envio_database"], "envio_bridge_fresh_20261027_r3")
        self.assertEqual(topology["roles"]["realm1"]["host"], "10.148.0.37")
        self.assertEqual(topology["mirror_sources"]["v3"]["host"], "10.148.0.43")


if __name__ == "__main__":
    unittest.main()
