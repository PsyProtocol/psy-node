"""Steps 77-79: archive, generated config and the frontend push, with real tar, bash and git where a script runs."""
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import unittest.mock

import deploy
import deploy_prepare_steps as prepare
import deploy_public_steps as steps
import public_release as pr
import release_lock
import test_deploy_prepare_steps as base
from deploy_remote import OperatorPending, find_secret

HERE = Path(__file__).resolve().parent
PUBLIC_JSON = HERE.parent / "fresh-192-20261030" / "public.json"
CHAINS = release_lock.CHAINS
OLD = {chain: "0x" + f"{index + 1:x}" * 40 for index, chain in enumerate(CHAINS)}


def address(chain, name, salt=""):
    return "0x" + hashlib.sha256(f"{chain}{name}{salt}".encode()).hexdigest()[:40]


def document(chain, salt=""):
    core = {name: address(chain, name, salt) for name in (
        "Bridge", "DefaultProxyAdmin", "DepositBatchVerifier", "ERC20Gateway", "ETHGateway", "ExecutorWithTimelock", "Multicall3",
        "PsyACLManager", "PsyAddressesProvider", "PsyToken", "Router", "StateManager", "TokenFaucetManager", "USDTToken", "WETH9",
        "WithdrawalClaimVerifier", "ZKVerifier")}
    index = CHAINS.index(chain)
    return {"network": chain, "chainId": str(11155111 + index), "deploymentBlock": str(1000 + index), "core": core,
            "contracts": {**core, "RewardClaimVerifier": address(chain, "reward")},
            "protocol": {"chain": {"network": chain, "bridgeChain": ("ethereum", "bsc", "base")[index], "l1ChainId": str(11155111 + index),
                                   "l1ChainIndex": str(index), "name": f"Chain {index}", "shortName": f"C{index}",
                                   "nativeCurrency": {"name": "N", "symbol": "N", "decimals": 18},
                                   "defaultRpcUrl": f"http://127.0.0.1:{18545 + index}", "defaultExplorerUrl": "https://explorer.invalid"},
                         "tokens": {"PSY": {"symbol": "PSY", "decimals": 9, "l2TokenContractId": "0x" + "0" * 64, "l1Address": core["PsyToken"]},
                                    "USDT": {"symbol": "USDT", "decimals": 6, "l2TokenContractId": "0x" + "0" * 63 + "4", "l1Address": core["USDTToken"]}}}}


class PublicWorld(base.PrepareTestCase):
    """A workspace with real-shaped L1 documents, the committed public.json and a fake web."""

    def setUp(self):
        super().setUp()
        self.ws.lock_sha = "a" * 64
        shutil.copy(PUBLIC_JSON, self.ws.release_dir / "public.json")
        self.public = pr.read_public(self.ws.release_dir)
        self.write_documents()
        self.web = {}
        self.fake_fetch = lambda url, limit=None, method="GET": self.web.get(url, (None, b""))
        for target, replacement in (("fetch", self.fake_fetch), ("head_length", self.head_length)):
            patcher = unittest.mock.patch.object(pr, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.remote = FakeRemote()
        self.ctx = self.ws.context(self.remote)
        patcher = unittest.mock.patch.object(steps, "wait_until", side_effect=lambda ready, failure, *a: (
            self.assertIsNone(failure()), self.assertTrue(ready(), "wait_until condition not met")))
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_documents(self, salt=""):
        chains = {}
        for chain in CHAINS:
            path = self.ws.root / f"{chain}-deployed-contracts.json"
            path.write_text(json.dumps(document(chain, salt)))
            chains[chain] = {"summary": {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}}
        (self.ws.state_dir / "deploy_l1.json").write_text(json.dumps({"lock_sha256": "a" * 64, "chains": chains}))

    def head_length(self, url):
        status, body = self.web.get(url + "#head", (None, b""))
        return status, len(body)

    def serve(self, url, body, status=200):
        self.web[url] = (status, body if isinstance(body, bytes) else body.encode())


class FakeRemote:
    sudo = "passwordless"

    def __init__(self):
        self.copies, self.root_scripts = [], []

    def sudo_mode(self, host):
        return self.sudo

    def copy_files(self, host, sources, destination, *, timeout_seconds=0):
        self.copies.append((host, [Path(source).name for source in sources], destination))

    def run_root_text(self, host, argv, timeout, *, stdin_text=None, show_stderr=True):
        self.root_scripts.append((host, stdin_text))
        return ""


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.keystore = self.root / "keystore"
        files = {}
        for name in (*pr.PUBLIC_SETUP_FILES, "reward_claim/pk_groth16.bin", "extra-secret-material.bin"):
            path = self.keystore / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode() * 10)
            files[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
        self.manifest = {"files": files}

    def test_the_archive_holds_exactly_the_nine_public_files_and_is_reproducible(self):
        first, digest = pr.build_trust_archive(self.keystore, self.manifest, self.root / "out1", "a.tar.gz")
        _, again = pr.build_trust_archive(self.keystore, self.manifest, self.root / "out2", "a.tar.gz")
        self.assertEqual(digest, again)
        self.assertEqual(pr.archive_members(first), sorted("keystore/" + name for name in pr.PUBLIC_SETUP_FILES))
        self.assertEqual(len(pr.archive_members(first)), 9)
        self.assertEqual((self.root / "out1" / "a.tar.gz.sha256").read_text(), f"{digest}  a.tar.gz\n")
        with tarfile.open(first) as bundle:
            for member in bundle.getmembers():
                self.assertEqual((member.uid, member.gid, member.mtime, member.mode), (0, 0, 0, 0o644))

    def test_a_file_that_differs_from_the_setup_manifest_is_refused(self):
        (self.keystore / "pk_groth16.bin").write_bytes(b"x" * len(b"pk_groth16.bin" * 10))
        with self.assertRaisesRegex(ValueError, "differs from the setup manifest: pk_groth16.bin"):
            pr.build_trust_archive(self.keystore, self.manifest, self.root / "out", "a.tar.gz")
        self.assertFalse((self.root / "out" / "a.tar.gz").exists())

    def test_install_script_runs_in_a_real_bash_and_checks_the_digest_first(self):
        name = f"psy-test-{os.getpid()}.tar.gz"
        staged = Path("/var/tmp") / name
        staged.write_bytes(b"archive")
        Path(str(staged) + ".sha256").write_text("sum\n")
        root = self.root / "public"
        public = {"trust_setup": {"root": str(root)}}
        try:
            wrong = subprocess.run(["/usr/bin/bash", "-s"], input=steps.install_script(public, "0" * 64, name).encode(), capture_output=True)
            self.assertNotEqual(wrong.returncode, 0)
            self.assertFalse(root.exists())
            digest = hashlib.sha256(b"archive").hexdigest()
            done = subprocess.run(["/usr/bin/bash", "-s"], input=steps.install_script(public, digest, name).encode(), capture_output=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(oct((root / name).stat().st_mode & 0o777), "0o644")
            self.assertTrue((root / (name + ".sha256")).exists())
            self.assertFalse(staged.exists())
        finally:
            for leftover in (staged, Path(str(staged) + ".sha256")):
                leftover.unlink(missing_ok=True)


class BundleCrawlTests(unittest.TestCase):
    SITE = "https://site.example/"
    FILES = {
        "": '<script type="module" src="/assets/index-1.js"></script>',
        "assets/index-1.js": 'import("./chainConfig-2.js"); const deps=["assets/lazy-3.js"];',
        "assets/chainConfig-2.js": 'import("./nested-4.js");',
        "assets/nested-4.js": 'const psy="0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";',
        "assets/lazy-3.js": 'import("../assets/deep/never.js"); const old="0x1111111111111111111111111111111111111111";',
    }

    def fetch(self, url, limit=None):
        key = url.removeprefix(self.SITE)
        return (200, self.FILES[key].encode()) if key in self.FILES else (404, b"")

    def test_a_chunk_reachable_only_through_a_nested_relative_import_is_read(self):
        text = "\n".join(pr.bundle_texts(self.SITE, self.fetch))
        self.assertIn("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", text)
        self.assertIn("0x1111111111111111111111111111111111111111", text, "the root-relative preload entry is read too")

    def test_relative_references_resolve_against_the_referring_chunk_not_the_site_root(self):
        asked = []
        pr.bundle_texts(self.SITE, lambda url, limit=None: asked.append(url) or self.fetch(url))
        self.assertIn(self.SITE + "assets/nested-4.js", asked)
        self.assertNotIn(self.SITE + "chainConfig-2.js", asked)

    def test_check_bundle_finds_the_new_address_and_flags_an_old_one_in_a_nested_chunk(self):
        new = {"sepolia.PSY": "0x" + "a" * 40}
        pr.check_bundle(self.SITE, new, [], self.fetch)
        with self.assertRaisesRegex(ValueError, "previous release"):
            pr.check_bundle(self.SITE, new, ["0x" + "1" * 40], self.fetch)
        with self.assertRaisesRegex(ValueError, "does not serve the new address"):
            pr.check_bundle(self.SITE, {"sepolia.PSY": "0x" + "c" * 40}, [], self.fetch)


class TrustStepTests(PublicWorld):
    def setUp(self):
        super().setUp()
        self.keystore = self.ws.root / "keystore"
        files = {}
        for name in pr.PUBLIC_SETUP_FILES:
            path = self.keystore / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode() * 5)
            files[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
        manifest = self.ws.root / "setup-manifest.json"
        manifest.write_text(json.dumps({"files": files}))
        self.ws.lock["groth16"]["setup_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.ws.local["files"]["groth16_setup_manifest"] = str(manifest)
        self.ws.local["packages"]["proxy"] = {"setup_dir": str(self.keystore)}
        self.ws.write_local()
        self.ws.lock["hosts"]["gcp-nostr"] = "10.0.0.9"
        self.step = steps.PUBLIC_STEPS["publish_trust_setup"]

    def publish(self, digest_on_host=None):
        archive = self.ctx.private_dir / "public" / "psy-groth16-trust-setup.tar.gz"
        url, sha_url = steps.trust_urls(self.public)
        if digest_on_host:
            self.serve(sha_url, f"{digest_on_host}  x\n")

    def test_upload_installs_then_records_the_digest(self):
        self.step.check(self.ctx)
        self.step.apply(self.ctx)
        state = json.loads((self.ws.state_dir / "publish_trust_setup.json").read_text())
        self.assertEqual(self.remote.copies, [("gcp-nostr", ["psy-groth16-trust-setup.tar.gz", "psy-groth16-trust-setup.tar.gz.sha256"], "/var/tmp/")])
        self.assertIn(state["sha256"], self.remote.root_scripts[0][1])
        url, sha_url = steps.trust_urls(self.public)
        self.serve(sha_url, f"{state['sha256']}  x\n")
        self.serve(url + "#head", b"x" * state["size"])
        report = self.step.verify(self.ctx)
        self.assertEqual((report["files"], report["archive_sha256"]), (9, state["sha256"]))
        self.assertIsNone(find_secret(report))

    def test_a_published_matching_digest_is_not_uploaded_again(self):
        self.step.apply(self.ctx)
        state = json.loads((self.ws.state_dir / "publish_trust_setup.json").read_text())
        self.remote.copies.clear()
        self.serve(steps.trust_urls(self.public)[1], f"{state['sha256']}  x\n")
        self.step.apply(self.ctx)
        self.assertEqual(self.remote.copies, [])

    def test_verify_refuses_a_public_archive_of_another_size(self):
        self.step.apply(self.ctx)
        state = json.loads((self.ws.state_dir / "publish_trust_setup.json").read_text())
        url, sha_url = steps.trust_urls(self.public)
        self.serve(sha_url, f"{state['sha256']}  x\n")
        self.serve(url + "#head", b"short")
        with self.assertRaisesRegex(ValueError, "another size"):
            self.step.verify(self.ctx)

    def test_operator_hosts_are_refused_in_check(self):
        self.remote.sudo = "operator"
        with self.assertRaisesRegex(ValueError, "no-prompt sudo"):
            self.step.check(self.ctx)


class ConfigTests(PublicWorld):
    TRUST = {"lock_sha256": "a" * 64, "sha256": "c" * 64}

    def setUp(self):
        super().setUp()
        (self.ws.state_dir / "publish_trust_setup.json").write_text(json.dumps(self.TRUST))
        dapp = self.ws.root / "dapp"
        (dapp / "apps/config").mkdir(parents=True)
        (dapp / "apps/config/index.html").write_text("<html></html>")
        credentials = self.ws.root / "cf_env"
        credentials.write_text("export CLOUDFLARE_ACCOUNT_ID=acct\nexport CLOUDFLARE_API_TOKEN=tok\n")
        credentials.chmod(0o600)
        self.ws.local["public"] = {"dapp_checkout": str(dapp), "cloudflare_env": str(credentials)}
        self.ws.write_local()
        self.step = steps.PUBLIC_STEPS["publish_public_config"]
        self.deployed = []
        patcher = unittest.mock.patch.object(steps, "run_wrangler", side_effect=lambda site, public, creds: self.deployed.append((site, creds)))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = unittest.mock.patch.object(shutil, "which", return_value="/usr/bin/pnpm")
        patcher.start()
        self.addCleanup(patcher.stop)

    def serve_live(self, config_raw, installer_raw):
        page = self.public["frontends"]["config"].rstrip("/")
        self.serve(page + "/config.json", config_raw)
        self.serve(page + "/" + self.public["trust_setup"]["installer"], installer_raw)

    def run_steps(self):
        self.step.check(self.ctx)
        self.step.apply(self.ctx)
        recorded = json.loads((self.ws.state_dir / "publish_public_config.json").read_text())
        site = Path(recorded["site_dir"])
        self.serve_live((site / "config.json").read_bytes(), (site / "install-groth16-trust-setup.sh").read_bytes())
        return recorded, self.step.verify(self.ctx)

    def test_config_comes_from_the_documents_and_deploys_with_the_private_credentials(self):
        recorded, report = self.run_steps()
        site = Path(recorded["site_dir"])
        config = json.loads((site / "config.json").read_text())
        pr.check_config_matches_documents(config, l1_documents_of(self), "sepolia")
        self.assertEqual([entry["network"] for entry in config["l1_chains"]], list(CHAINS))
        self.assertEqual(config["trust_setup"]["sha256"], "c" * 64)
        self.assertIn("c" * 64, (site / "install-groth16-trust-setup.sh").read_text())
        self.assertEqual(self.deployed[0][1], {"CLOUDFLARE_ACCOUNT_ID": "acct", "CLOUDFLARE_API_TOKEN": "tok"})
        self.assertIsNone(find_secret(report))
        self.assertNotIn("tok", json.dumps(report) + json.dumps(recorded))
        self.assertEqual(sorted(path.name for path in site.iterdir() if path.name != "index.html"),
                         ["_headers", "config.json", "install-groth16-trust-setup.sh", "robots.txt"])

    def test_addresses_of_the_previous_release_are_recorded_from_the_live_config(self):
        old_documents = {chain: document(chain, "r3") for chain in CHAINS}
        old = pr.build_config(self.public, old_documents, "u", "s", "i", "g")
        self.serve_live(json.dumps(old).encode(), b"old installer")
        recorded, report = self.run_steps()
        r3_psy = old_documents["sepolia"]["core"]["PsyToken"].lower()
        self.assertIn(r3_psy, recorded["previous_addresses"])
        new_addresses = set(pr.config_addresses(json.loads((Path(recorded["site_dir"]) / "config.json").read_text())).values())
        self.assertFalse(new_addresses & set(recorded["previous_addresses"]))

    def test_a_rerun_with_the_live_config_in_place_deploys_nothing(self):
        self.run_steps()
        self.step.apply(self.ctx)
        self.assertEqual(len(self.deployed), 1)

    def test_a_live_config_that_differs_is_deployed_again_and_keeps_the_recorded_previous_addresses(self):
        recorded, _ = self.run_steps()
        self.serve_live(b"{}", b"x")
        self.step.apply(self.ctx)
        self.assertEqual(len(self.deployed), 2)
        again = json.loads((self.ws.state_dir / "publish_public_config.json").read_text())
        self.assertEqual(again["previous_addresses"], recorded["previous_addresses"])

    def test_verify_refuses_a_live_config_with_a_wrong_address(self):
        recorded, _ = self.run_steps()
        site = Path(recorded["site_dir"])
        tampered = json.loads((site / "config.json").read_text())
        tampered["l1_chains"][1]["contracts"]["Bridge"] = "0x" + "9" * 40
        raw = json.dumps(tampered, indent=2).encode() + b"\n"
        state = json.loads((self.ws.state_dir / "publish_public_config.json").read_text())
        state["config_sha256"] = hashlib.sha256(raw).hexdigest()
        (self.ws.state_dir / "publish_public_config.json").write_text(json.dumps(state))
        self.serve_live(raw, (site / "install-groth16-trust-setup.sh").read_bytes())
        with self.assertRaisesRegex(ValueError, "differs from the L1 documents: bscTestnet.Bridge"):
            self.step.verify(self.ctx)

    def test_credentials_readable_by_others_are_refused(self):
        path = Path(self.ws.local["public"]["cloudflare_env"])
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "readable only by its owner"):
            self.step.check(self.ctx)

    def test_a_trust_state_from_another_lock_is_refused(self):
        (self.ws.state_dir / "publish_trust_setup.json").write_text(json.dumps({"lock_sha256": "b" * 64, "sha256": "c" * 64}))
        with self.assertRaisesRegex(ValueError, "another release lock"):
            self.step.check(self.ctx)


def l1_documents_of(world):
    return steps.l1_documents(world.ctx)


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}).stdout.strip()


class FrontendTests(PublicWorld):
    def setUp(self):
        super().setUp()
        root = self.ws.root
        self.origin = root / "origin.git"
        git("init", "--bare", "-b", "deploy/testnet", str(self.origin), cwd=root)
        self.dapp = root / "dapp"
        git("clone", str(self.origin), str(self.dapp), cwd=root)
        (self.dapp / "app").mkdir()
        (self.dapp / "app/index.txt").write_text("application\n")
        git("add", ".", cwd=self.dapp)
        git("commit", "-m", "application", cwd=self.dapp)
        self.source = git("rev-parse", "HEAD", cwd=self.dapp)
        git("push", "origin", "HEAD:refs/heads/release/testnet", cwd=self.dapp)
        (self.dapp / "deploy/common").mkdir(parents=True)
        (self.dapp / "deploy/common/public-l1-r3.json").write_text('{"old": true}\n')
        (self.dapp / "deploy/common/public-client-r3.json").write_text('{"networks": {"testnet": {"p2p": {"checkpoints_per_epoch": 10}}}}\n')
        (self.dapp / "deploy/common/stable-release.json").write_text(self.policy(self.source))
        (self.dapp / "deploy/common/staging-env.sh").write_text("export VITE_L1_DEPOSITS_PAUSED=true\n")
        git("add", ".", cwd=self.dapp)
        git("commit", "-m", "base", cwd=self.dapp)
        git("push", "origin", "HEAD:deploy/testnet", cwd=self.dapp)
        self.config_raw = b'{"environment": "live"}\n'
        site = root / "site"
        site.mkdir()
        (site / "config.json").write_bytes(self.config_raw)
        self.config_sha = hashlib.sha256(self.config_raw).hexdigest()
        (self.ws.state_dir / "publish_public_config.json").write_text(json.dumps({
            "lock_sha256": "a" * 64, "config_sha256": self.config_sha, "site_dir": str(site), "previous_addresses": [OLD["sepolia"]]}))
        self.ws.local["public"] = {"dapp_checkout": str(self.dapp)}
        self.ws.write_local()
        self.serve(self.public["frontends"]["config"].rstrip("/") + "/config.json", self.config_raw)
        self.step = steps.PUBLIC_STEPS["publish_frontends"]

    @staticmethod
    def policy(commit):
        return json.dumps({"sourceBranch": "release/testnet", "sourceCommit": commit, "publishEnabled": True,
                           "releaseScope": {"l1DepositsPaused": True}}, indent=2) + "\n"

    def commit_pin(self, commit):
        (self.dapp / "deploy/common/stable-release.json").write_text(self.policy(commit))
        git("commit", "-am", "pin", cwd=self.dapp)

    def pin(self):
        return json.loads(git("show", "HEAD:deploy/common/stable-release.json", cwd=self.dapp))["sourceCommit"]

    def remote_head(self):
        return git("rev-parse", "deploy/testnet", cwd=self.origin)

    def allow(self):
        self.ws.local["public"]["allow_frontend_push"] = True
        self.ws.write_local()

    def test_without_the_private_setting_the_step_prints_the_exact_push_and_pushes_nothing(self):
        before = self.remote_head()
        self.step.check(self.ctx)
        with self.assertRaises(OperatorPending) as pending:
            self.step.apply(self.ctx)
        self.assertEqual(pending.exception.command, f"git -C {self.dapp} push origin HEAD:refs/heads/deploy/testnet")
        self.assertEqual(self.remote_head(), before)
        self.assertEqual(git("log", "-1", "--format=%s", cwd=self.dapp), steps.COMMIT_MESSAGE)
        self.assertEqual((self.dapp / "deploy/common/public-l1-r3.json").read_bytes(), self.config_raw)
        self.assertIn('"checkpoints_per_epoch": 32', (self.dapp / "deploy/common/public-client-r3.json").read_text())

    def test_with_the_setting_the_commit_is_pushed_fast_forward_and_a_rerun_pushes_nothing(self):
        self.allow()
        self.step.apply(self.ctx)
        pushed = self.remote_head()
        self.assertEqual(pushed, git("rev-parse", "HEAD", cwd=self.dapp))
        self.assertEqual(git("show", "deploy/testnet:deploy/common/public-l1-r3.json", cwd=self.origin).encode() + b"\n", self.config_raw)
        self.step.apply(self.ctx)
        self.assertEqual(self.remote_head(), pushed)
        state = json.loads((self.ws.state_dir / "publish_frontends.json").read_text())
        self.assertEqual((state["dapp_commit"], state["config_sha256"]), (pushed, self.config_sha))

    def test_a_diverged_remote_is_refused_and_nothing_is_forced(self):
        other = self.ws.root / "other"
        git("clone", str(self.origin), str(other), cwd=self.ws.root)
        (other / "x.txt").write_text("x")
        git("add", ".", cwd=other)
        git("commit", "-m", "elsewhere", cwd=other)
        git("push", "origin", "HEAD:deploy/testnet", cwd=other)
        before = self.remote_head()
        self.allow()
        with self.assertRaisesRegex(ValueError, "non-fast-forward"):
            self.step.apply(self.ctx)
        self.assertEqual(self.remote_head(), before)

    def test_uncommitted_changes_outside_the_two_deploy_files_are_refused(self):
        (self.dapp / "deploy/common/staging-env.sh").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "outside the deploy files"):
            self.step.apply(self.ctx)

    def test_a_valid_source_pin_is_kept_and_the_commit_touches_no_policy_file(self):
        self.allow()
        self.step.apply(self.ctx)
        self.assertEqual(self.pin(), self.source)
        changed = git("diff", "--name-only", "HEAD~1", "HEAD", cwd=self.dapp).splitlines()
        self.assertEqual(sorted(changed), ["deploy/common/public-client-r3.json", "deploy/common/public-l1-r3.json"])

    def test_a_stale_source_pin_is_moved_to_the_source_branch_head_in_the_same_deploy_only_commit(self):
        base = git("rev-parse", "HEAD", cwd=self.dapp)
        self.commit_pin(base)
        self.allow()
        self.step.apply(self.ctx)
        self.assertEqual(self.pin(), self.source)
        changed = git("diff", "--name-only", self.source, "HEAD", cwd=self.dapp).splitlines()
        self.assertTrue(changed and all(path.startswith("deploy/") for path in changed), changed)
        self.assertEqual(self.remote_head(), git("rev-parse", "HEAD", cwd=self.dapp))

    def test_a_source_branch_head_missing_from_the_deploy_branch_refuses_before_any_push(self):
        base = git("rev-parse", "HEAD", cwd=self.dapp)
        self.commit_pin(base)
        other = self.ws.root / "other-release"
        git("clone", "-b", "release/testnet", str(self.origin), str(other), cwd=self.ws.root)
        (other / "app/index.txt").write_text("newer application\n")
        git("commit", "-am", "newer source", cwd=other)
        git("push", "origin", "HEAD:refs/heads/release/testnet", cwd=other)
        before = self.remote_head()
        self.allow()
        with self.assertRaisesRegex(ValueError, "stable-release pin cannot be made valid"):
            self.step.apply(self.ctx)
        self.assertEqual(self.remote_head(), before)
        self.assertFalse((self.ws.state_dir / "publish_frontends.json").exists())

    def test_application_paths_changed_since_the_source_refuse_before_any_push(self):
        (self.dapp / "app/index.txt").write_text("edited on the deploy branch\n")
        git("commit", "-am", "application change on deploy", cwd=self.dapp)
        self.commit_pin(git("rev-parse", "HEAD", cwd=self.dapp))
        before = self.remote_head()
        self.allow()
        with self.assertRaisesRegex(ValueError, "stable-release pin cannot be made valid"):
            self.step.apply(self.ctx)
        self.assertEqual(self.remote_head(), before)

    def test_check_refuses_when_the_live_config_is_not_the_published_one(self):
        self.serve(self.public["frontends"]["config"].rstrip("/") + "/config.json", b"{}")
        with self.assertRaisesRegex(ValueError, "built from another deployment"):
            self.step.check(self.ctx)

    def test_check_refuses_disagreeing_deposit_pause_settings(self):
        (self.dapp / "deploy/common/staging-env.sh").write_text("export VITE_L1_DEPOSITS_PAUSED=false\n")
        with self.assertRaisesRegex(ValueError, "deposit-pause settings disagree"):
            self.step.check(self.ctx)

    def test_wallet_command_names_no_credential_and_runs_only_when_allowed(self):
        wallet = self.ws.root / "wallet"
        git("init", "-b", "main", str(wallet), cwd=self.ws.root)
        (wallet / "f").write_text("f")
        git("add", ".", cwd=wallet)
        git("commit", "-m", "w", cwd=wallet)
        credentials = self.ws.root / "cf_env"
        credentials.write_text("export CLOUDFLARE_ACCOUNT_ID=a\nexport CLOUDFLARE_API_TOKEN=t\n")
        credentials.chmod(0o600)
        self.ws.local["public"].update(wallet_checkout=str(wallet), wallet_sdk_label="a2e3dc8c", cloudflare_env=str(credentials))
        self.ws.write_local()
        self.step.check(self.ctx)
        with self.assertRaises(OperatorPending) as pending:
            self.step.apply(self.ctx)
        command = pending.exception.command
        self.assertIn("scripts/publish-wallet-r2-stg.sh", command)
        self.assertIn("sdk-a2e3dc8c", command)
        self.assertNotIn("=t ", command)
        self.assertIsNone(find_secret({"command": command}))

    def verify_world(self, runs, app_text="", account_text=""):
        self.allow()
        self.step.apply(self.ctx)
        documents = steps.l1_documents(self.ctx)
        new = " ".join(address.lower() for address in steps.new_psy_addresses(documents).values())
        for site, url in self.public["sites"].items():
            self.serve(url, f"<html><script src=\"/assets/{site}.js\"></script></html>")
            self.serve(url.rstrip("/") + f"/assets/{site}.js", {"app": new + app_text, "account": new + account_text}.get(site, "ok"))
        patcher = unittest.mock.patch.object(steps, "workflow_runs", return_value=runs)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = unittest.mock.patch.object(steps, "repository_of", return_value="owner/psy-dapp")
        patcher.start()
        self.addCleanup(patcher.stop)

    GREEN = [{"workflowName": name, "status": "completed", "conclusion": "success"} for name in
             ["Deploy Testnet Frontends", "Deploy Testnet Wallet Site", "Deploy Testnet IDE", "Deploy Testnet Account"]]

    def test_verify_passes_with_green_workflows_and_new_addresses(self):
        self.verify_world(self.GREEN)
        report = self.step.verify(self.ctx)
        self.assertEqual(sorted(report["bundles"]), ["account", "app"])
        self.assertTrue(all(code == 200 for code in report["sites"].values()))
        steps.require_frontends_current(self.ctx)

    def test_a_previous_release_address_in_the_app_bundle_fails_but_the_account_dead_data_does_not(self):
        self.verify_world(self.GREEN, account_text=" " + OLD["sepolia"])
        self.step.verify(self.ctx)
        self.verify_world(self.GREEN, app_text=" " + OLD["sepolia"])
        with self.assertRaisesRegex(ValueError, "still serves an address of the previous release"):
            self.step.verify(self.ctx)

    def test_a_missing_new_address_in_the_served_bundle_fails(self):
        self.verify_world(self.GREEN)
        url = self.public["sites"]["app"].rstrip("/") + "/assets/app.js"
        self.serve(url, "nothing here")
        with self.assertRaisesRegex(ValueError, "does not serve the new address"):
            self.step.verify(self.ctx)

    def test_a_failed_or_missing_workflow_blocks_the_step(self):
        failed = [dict(self.GREEN[0], conclusion="failure"), *self.GREEN[1:]]
        self.verify_world(failed)
        with self.assertRaises(AssertionError):
            self.step.verify(self.ctx)
        self.assertEqual(steps.workflow_verdict(failed, ["Deploy Testnet Frontends"]), "workflow failed for this commit: Deploy Testnet Frontends")
        self.assertIsNone(steps.workflow_verdict(self.GREEN[:3], [run["workflowName"] for run in self.GREEN]))
        self.assertIsNone(steps.workflow_verdict([dict(self.GREEN[0], status="in_progress", conclusion="")], ["Deploy Testnet Frontends"]))

    def test_the_committed_config_must_equal_the_live_one(self):
        self.verify_world(self.GREEN)
        self.serve(self.public["frontends"]["config"].rstrip("/") + "/config.json", b"{}")
        with self.assertRaisesRegex(ValueError, "committed dapp config differs from the live config"):
            self.step.verify(self.ctx)

    def test_acceptance_is_blocked_for_frontends_built_for_another_config(self):
        self.verify_world(self.GREEN)
        state = json.loads((self.ws.state_dir / "publish_frontends.json").read_text())
        state["config_sha256"] = "f" * 64
        (self.ws.state_dir / "publish_frontends.json").write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, "another config"):
            steps.require_frontends_current(self.ctx)
        (self.ws.state_dir / "publish_frontends.json").unlink()
        with self.assertRaisesRegex(ValueError, "no recorded state"):
            steps.require_frontends_current(self.ctx)


class RegistrationTests(unittest.TestCase):
    def test_steps_are_registered_and_not_cutover(self):
        registry = deploy.build_registry()
        for name in ("publish_trust_setup", "publish_public_config", "publish_frontends"):
            self.assertIs(registry[name], steps.PUBLIC_STEPS[name])
            self.assertFalse(registry[name].cutover)

    def test_public_json_matches_the_release_chains(self):
        public = pr.read_public(PUBLIC_JSON.parent)
        self.assertEqual(set(public["chains"]), set(CHAINS))
        self.assertEqual(set(public["bundle_sites"]) - set(public["sites"]), set())


if __name__ == "__main__":
    unittest.main()
