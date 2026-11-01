#!/usr/bin/env python3
"""Steps 77-79: publish the public side of the release, trust setup, config page and frontends.

Step 77 uploads the public Groth16 files. Step 78 generates config.json and the installer from the recorded L1
deployment documents and deploys the config page. Step 79 applies that config to the dapp deploy files, pushes
deploy/testnet (a push is outward-facing: it needs public.allow_frontend_push in the private local inputs, otherwise
the step prints the exact commands) and verifies CI and the served bundles. Acceptance steps call
require_frontends_current, so the table cannot finish with frontends built for another deployment.
Private inputs live in local-inputs.json under "public"; see fresh-192-20261030/README.md.
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

import deploy_prepare_steps as prepare
import public_release as pr
import release_lock
from deploy_prepare_steps import file_sha256, local_inputs, read_state, require, run_local, write_state
from deploy_remote import OperatorPending, Step, redact_tail, wait_until

TRUST_STATE = "publish_trust_setup"
CONFIG_STATE = "publish_public_config"
FRONTEND_STATE = "publish_frontends"
PENDING_STATE = "publish_frontends_pending"
UPLOAD_SECONDS = 7200
INSTALL_SECONDS = 900
LIVE_POLL_SECONDS = 15
LIVE_WAIT_SECONDS = 300
CI_POLL_SECONDS = 30
CI_WAIT_SECONDS = 3600
GIT_SECONDS = 300
WRANGLER_SECONDS = 900
CLIENT_EPOCH = re.compile(r'("checkpoints_per_epoch"\s*:\s*)\d+')
GITHUB_REMOTE = re.compile(r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$")
COMMIT_MESSAGE = "deploy: publish the release L1 addresses and client epoch"


def public_section(ctx):
    section = local_inputs(ctx).get("public")
    require(isinstance(section, dict), "local-inputs.json lacks the public section")
    return section


def public_path(ctx, name, optional=False):
    section = public_section(ctx)
    if optional and name not in section:
        return None
    value = section.get(name)
    require(isinstance(value, str) and value.startswith("/") and ".." not in value.split("/"),
            f"local-inputs.json public.{name} must be an absolute path")
    return Path(value)


def read_recorded(ctx, name):
    document = read_state(ctx, name)
    require(document.get("lock_sha256") == ctx.lock_sha256, f"recorded {name} belongs to another release lock")
    return document


def l1_documents(ctx):
    state = read_state(ctx, "deploy_l1")
    require(state.get("lock_sha256") == ctx.lock_sha256, "recorded L1 documents belong to another release lock")
    require(set(state.get("chains", {})) == set(release_lock.CHAINS), "recorded L1 documents do not cover three chains")
    return pr.read_documents(state, ctx.state_dir)


def trust_urls(public):
    trust = public["trust_setup"]
    base = trust["base_url"].rstrip("/")
    return f"{base}/{trust['archive']}", f"{base}/{trust['archive']}.sha256"


def installer_url(public):
    return public["frontends"]["config"].rstrip("/") + "/" + public["trust_setup"]["installer"]


# ---- step 77: public trust setup ----

def setup_manifest(ctx):
    path = prepare.local_path(ctx, "files", "groth16_setup_manifest")
    require(file_sha256(path) == ctx.lock["groth16"]["setup_manifest_sha256"], "setup manifest differs from the lock")
    return release_lock.read_document(path)


def setup_keystore(ctx):
    return Path(prepare.local_value(ctx, "packages", "proxy")["setup_dir"])


def trust_check(ctx):
    public = pr.read_public(ctx.release_dir)
    host = public["trust_setup"]["host"]
    require(host in ctx.lock["hosts"] and ctx.remote.sudo_mode(host) == "passwordless",
            f"{host} must be in the lock and take no-prompt sudo")
    pr.verify_setup_files(setup_keystore(ctx), setup_manifest(ctx))


def live_digest(public):
    _, sha_url = trust_urls(public)
    status, body = pr.fetch(sha_url, limit=4096)
    words = body.decode("utf-8", errors="replace").split()
    return words[0] if status == 200 and words else None


def install_script(public, digest, name):
    staged, root = f"/var/tmp/{name}", public["trust_setup"]["root"]
    return (f"set -euo pipefail\ntest \"$(sha256sum {shlex.quote(staged)} | awk '{{print $1}}')\" = {shlex.quote(digest)}\n"
            f"install -d -m 0755 {shlex.quote(root)}\n"
            f"install -m 0644 {shlex.quote(staged)} {shlex.quote(root + '/' + name)}\n"
            f"install -m 0644 {shlex.quote(staged + '.sha256')} {shlex.quote(root + '/' + name + '.sha256')}\n"
            f"rm -f {shlex.quote(staged)} {shlex.quote(staged + '.sha256')}\n")


def trust_apply(ctx):
    public = pr.read_public(ctx.release_dir)
    name, host = public["trust_setup"]["archive"], public["trust_setup"]["host"]
    out_dir = ctx.private_dir / "public"
    archive = out_dir / name
    if not (archive.is_file() and (out_dir / (name + ".sha256")).is_file()):
        archive, _ = pr.build_trust_archive(setup_keystore(ctx), setup_manifest(ctx), out_dir, name)
    digest = pr.file_sha256(archive)
    if live_digest(public) != digest:
        ctx.remote.copy_files(host, [archive, out_dir / (name + ".sha256")], "/var/tmp/", timeout_seconds=UPLOAD_SECONDS)
        ctx.remote.run_root_text(host, ["/usr/bin/bash", "-s"], INSTALL_SECONDS, stdin_text=install_script(public, digest, name))
    write_state(ctx, TRUST_STATE, {"lock_sha256": ctx.lock_sha256, "sha256": digest, "size": archive.stat().st_size,
                                   "archive": str(archive)})


def trust_verify(ctx):
    public = pr.read_public(ctx.release_dir)
    recorded = read_recorded(ctx, TRUST_STATE)
    url, _ = trust_urls(public)
    wait_until(lambda: live_digest(public) == recorded["sha256"], lambda: None, LIVE_POLL_SECONDS, LIVE_WAIT_SECONDS,
               "public trust setup digest")
    status, length = pr.head_length(url)
    require(status == 200 and length == recorded["size"], "the public trust setup archive is missing or has another size")
    members = pr.archive_members(Path(recorded["archive"]))
    require(members == sorted("keystore/" + item for item in pr.PUBLIC_SETUP_FILES), "the archive holds more or less than the nine public files")
    return {"archive_sha256": recorded["sha256"], "size": recorded["size"], "files": len(members), "url": url}


# ---- step 78: public config page ----

def cloudflare_credentials(ctx):
    return pr.read_cloudflare_env(public_path(ctx, "cloudflare_env"))


def page_source(ctx, public):
    return public_path(ctx, "dapp_checkout") / public["dapp"]["page_source"]


def build_candidate(ctx, public, trust, generated_at):
    documents = l1_documents(ctx)
    url, _ = trust_urls(public)
    installer = pr.render_installer(url, public["trust_setup"]["archive"], trust["sha256"])
    config = pr.build_config(public, documents, url, trust["sha256"], installer_url(public), generated_at)
    pr.check_config_matches_documents(config, documents, public["l1_primary"]["network"])
    return config, installer, documents


def config_check(ctx):
    public = pr.read_public(ctx.release_dir)
    read_recorded(ctx, TRUST_STATE)
    l1_documents(ctx)
    cloudflare_credentials(ctx)
    require(page_source(ctx, public).joinpath("index.html").is_file(), "the config page source is missing from the dapp checkout")
    require(shutil.which("pnpm") is not None, "pnpm is required to run wrangler")


def live_config(public):
    status, body = pr.fetch(public["frontends"]["config"].rstrip("/") + "/config.json")
    if status != 200:
        return None, b""
    try:
        parsed = json.loads(body)
    except ValueError:
        return None, body
    return (parsed if isinstance(parsed, dict) and isinstance(parsed.get("l1_chains"), list) else None), body


def run_wrangler(site, public, credentials):
    argv = ["pnpm", "dlx", public["config_site"]["wrangler"], "pages", "deploy", str(site), "--project-name",
            public["config_site"]["project"], "--branch", public["config_site"]["branch"]]
    outcome = subprocess.run(argv, env={**os.environ, **credentials}, capture_output=True, text=True, timeout=WRANGLER_SECONDS, check=False)
    if outcome.returncode != 0:
        raise RuntimeError(f"config page deploy failed (exit {outcome.returncode}): {redact_tail(outcome.stderr)}")


def previous_addresses(public, config, recorded):
    """Addresses of earlier releases: what was recorded before plus whatever the live config holds that this one does not."""
    live, _ = live_config(public)
    seen = set(recorded)
    if live is not None:
        seen |= set(pr.config_addresses(live).values())
    return sorted(seen - set(pr.config_addresses(config).values()))


def config_apply(ctx):
    public = pr.read_public(ctx.release_dir)
    trust = read_recorded(ctx, TRUST_STATE)
    recorded = read_state(ctx, CONFIG_STATE) if (ctx.state_dir / f"{CONFIG_STATE}.json").is_file() else {}
    _, live_raw = live_config(public)
    if recorded.get("lock_sha256") == ctx.lock_sha256 and live_raw and pr.sha256_bytes(live_raw) == recorded.get("config_sha256"):
        return
    config, installer, _ = build_candidate(ctx, public, trust, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    site = pr.build_site(page_source(ctx, public), ctx.private_dir / "public" / "config-site", config, installer)
    old = previous_addresses(public, config, recorded.get("previous_addresses", []))
    run_wrangler(site, public, cloudflare_credentials(ctx))
    write_state(ctx, CONFIG_STATE, {"lock_sha256": ctx.lock_sha256, "config_sha256": file_sha256(site / "config.json"),
                                    "installer_sha256": file_sha256(site / "install-groth16-trust-setup.sh"),
                                    "trust_sha256": trust["sha256"], "site_dir": str(site), "previous_addresses": old})


def config_verify(ctx):
    public = pr.read_public(ctx.release_dir)
    recorded = read_recorded(ctx, CONFIG_STATE)
    page = public["frontends"]["config"].rstrip("/")
    state = {}

    def is_live():
        config_status, config_body = pr.fetch(page + "/config.json")
        installer_status, installer_body = pr.fetch(page + "/" + public["trust_setup"]["installer"])
        state.update(config=pr.sha256_bytes(config_body), installer=pr.sha256_bytes(installer_body), body=config_body)
        return (config_status == 200 and installer_status == 200 and state["config"] == recorded["config_sha256"]
                and state["installer"] == recorded["installer_sha256"])
    wait_until(is_live, lambda: None, LIVE_POLL_SECONDS, LIVE_WAIT_SECONDS, "live config page")
    documents = l1_documents(ctx)
    pr.check_config_matches_documents(json.loads(state["body"]), documents, public["l1_primary"]["network"])
    return {"config_sha256": recorded["config_sha256"], "installer_sha256": recorded["installer_sha256"],
            "trust_sha256": recorded["trust_sha256"], "addresses_checked": len(pr.document_addresses(documents, public["l1_primary"]["network"])),
            "previous_release_addresses": len(recorded["previous_addresses"])}


# ---- step 79: frontends ----

def git(repo, *args):
    outcome = run_local(["git", "-C", str(repo), *args], GIT_SECONDS)
    if outcome.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed (exit {outcome.returncode}): {redact_tail(outcome.stderr)}")
    return outcome.stdout.strip()


def release_epoch(ctx):
    return int(release_lock.read_document(ctx.release_dir / "release.json")["checkpoints_per_epoch"])


FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
POLICY_PATHS = ("deploy/", ".github/workflows/")


def pin_is_valid(repo, commit, source_branch):
    """The rule of psy-dapp check-stable-release.mjs: a full commit on origin/<source branch>, an ancestor of HEAD, and
    nothing but deploy/ and workflow files changed since."""
    if not (isinstance(commit, str) and FULL_COMMIT.fullmatch(commit)):
        return False
    for tip in (f"refs/remotes/origin/{source_branch}", "HEAD"):
        if run_local(["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, tip], GIT_SECONDS).returncode != 0:
            return False
    changed = git(repo, "diff", "--name-only", commit, "HEAD", "--").splitlines()
    return all(path.startswith(POLICY_PATHS) for path in changed)


def resolve_source_pin(repo, public):
    """The stable-release pin that CI will accept: the current one when valid, else the head of the source branch
    when that is valid, else a refusal before anything is pushed."""
    policy_file = repo / public["dapp"]["policy_file"]
    policy = json.loads(policy_file.read_text())
    require(isinstance(policy.get("sourceBranch"), str) and "sourceCommit" in policy, "the stable-release policy has no source pin")
    branch = policy["sourceBranch"]
    git(repo, "fetch", "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}")
    if pin_is_valid(repo, policy["sourceCommit"], branch):
        return None
    candidate = git(repo, "rev-parse", f"refs/remotes/origin/{branch}")
    require(pin_is_valid(repo, candidate, branch),
            f"the stable-release pin cannot be made valid: land the source commit on origin/{branch} first, "
            "then rebuild the deploy branch so only deploy/ paths differ from it")
    return candidate


def apply_dapp_files(repo, public, config_raw, epoch):
    """Write the config, the client epoch and, when stale, the source pin; refuse any other uncommitted change."""
    l1_file, client_file, policy_file = public["dapp"]["l1_file"], public["dapp"]["client_file"], public["dapp"]["policy_file"]
    other = [line for line in git(repo, "status", "--porcelain", "--untracked-files=no").splitlines()
             if line[3:] not in (l1_file, client_file, policy_file)]
    require(not other, "the dapp checkout has uncommitted changes outside the deploy files")
    new_pin = resolve_source_pin(repo, public)
    (repo / l1_file).write_bytes(config_raw)
    text = (repo / client_file).read_text()
    updated = CLIENT_EPOCH.sub(lambda found: f"{found.group(1)}{epoch}", text)
    require(updated != text or CLIENT_EPOCH.search(text), "the client config has no checkpoints_per_epoch to align")
    json.loads(updated)
    (repo / client_file).write_text(updated)
    if new_pin is not None:
        policy_text = (repo / policy_file).read_text()
        policy = json.loads(policy_text)
        (repo / policy_file).write_text(policy_text.replace(policy["sourceCommit"], new_pin, 1))
    if git(repo, "status", "--porcelain", "--untracked-files=no"):
        git(repo, "add", "--", l1_file, client_file, policy_file)
        git(repo, "commit", "-m", COMMIT_MESSAGE)
    return git(repo, "rev-parse", "HEAD")


def fast_forward_state(repo, branch):
    """(head, remote head or None, True when HEAD descends from the remote branch)."""
    git(repo, "fetch", "origin", branch)
    head, remote = git(repo, "rev-parse", "HEAD"), git(repo, "rev-parse", "FETCH_HEAD")
    descends = run_local(["git", "-C", str(repo), "merge-base", "--is-ancestor", remote, head], GIT_SECONDS).returncode == 0
    return head, remote, descends


def push_command(repo, branch):
    return shlex.join(["git", "-C", str(repo), "push", "origin", f"HEAD:refs/heads/{branch}"])


def wallet_settings(ctx, public):
    """The wallet release command and env, or None when the release has no wallet checkout."""
    checkout = public_path(ctx, "wallet_checkout", optional=True)
    if checkout is None:
        return None
    section = public_section(ctx)
    commit = git(checkout, "rev-parse", "HEAD")
    hosts = {key: public["services"][key].removeprefix("https://") for key in ("coordinator_rpc", "prove_proxy", "faucet_rpc")}
    env = {"R2_RELEASE_PREFIX": f"releases/{public['wallet']['package_mode']}/wallet-{commit}/sdk-{section['wallet_sdk_label']}/testnet",
           "WALLET_COMMIT": commit, "WALLET_REF": section.get("wallet_ref", "release/testnet"),
           "SKIP_WALLET_BUILD": "1" if section.get("wallet_skip_build") else "0",
           "PUBLIC_COORDINATOR_DOMAIN": hosts["coordinator_rpc"], "PUBLIC_PROVE_PROXY_DOMAIN": hosts["prove_proxy"],
           "PUBLIC_FAUCET_DOMAIN": hosts["faucet_rpc"], "PUBLIC_PSY_EXPLORER_URL": public["frontends"]["psy_explorer"],
           "R2_BUCKET": public["wallet"]["r2_bucket"], "R2_PUBLIC_BASE_URL": public["wallet"]["public_base_url"]}
    return checkout, commit, env


def wallet_command(checkout, env, public, credentials_path):
    words = [f"{key}={value}" for key, value in sorted(env.items())]
    return shlex.join(["env", f"CF_ENV_FILE={credentials_path}", *words, "bash", str(Path(checkout) / public["wallet"]["script"])])


def wallet_published(public, commit):
    status, body = pr.fetch(public["wallet"]["public_base_url"].rstrip("/") + "/wallet-release.json")
    try:
        return status == 200 and json.loads(body).get("walletCommit") == commit
    except ValueError:
        return False


def frontends_allowed(ctx):
    return public_section(ctx).get("allow_frontend_push") is True


def frontends_check(ctx):
    public = pr.read_public(ctx.release_dir)
    config = read_recorded(ctx, CONFIG_STATE)
    _, live = live_config(public)
    require(pr.sha256_bytes(live) == config["config_sha256"],
            "the live config is not the one step 78 published; the frontends would be built from another deployment")
    repo = public_path(ctx, "dapp_checkout")
    require((repo / ".git").exists(), "public.dapp_checkout is not a git checkout")
    flag = deposit_flags(repo, public)
    require(len(set(flag.values())) == 1, "the dapp deposit-pause settings disagree with each other: " + json.dumps(flag, sort_keys=True))
    release_epoch(ctx)
    if public_path(ctx, "wallet_checkout", optional=True) is not None:
        wallet_settings(ctx, public)
        cloudflare_credentials(ctx)


def deposit_flags(repo, public):
    """The deposit-pause value in each dapp file that carries it, as booleans."""
    release = json.loads((repo / "deploy/common/stable-release.json").read_text())["releaseScope"]["l1DepositsPaused"]
    match = re.search(r"VITE_L1_DEPOSITS_PAUSED=(\w+)", (repo / "deploy/common/staging-env.sh").read_text())
    return {"stable-release.json": release, "staging-env.sh": match.group(1) == "true" if match else None}


def frontends_apply(ctx):
    public = pr.read_public(ctx.release_dir)
    config = read_recorded(ctx, CONFIG_STATE)
    repo, branch = public_path(ctx, "dapp_checkout"), public["dapp"]["branch"]
    head = apply_dapp_files(repo, public, (Path(config["site_dir"]) / "config.json").read_bytes(), release_epoch(ctx))
    _, remote, descends = fast_forward_state(repo, branch)
    require(descends, f"the dapp checkout does not descend from origin/{branch}; refusing a non-fast-forward push")
    commands = [] if head == remote else [push_command(repo, branch)]
    wallet = wallet_settings(ctx, public)
    credentials_file = public_path(ctx, "cloudflare_env", optional=True)
    if wallet is not None and not wallet_published(public, wallet[1]):
        commands.append(wallet_command(wallet[0], wallet[2], public, credentials_file))
    if commands and not frontends_allowed(ctx):
        raise OperatorPending("local", "; ".join(commands), str(ctx.state_dir / f"{PENDING_STATE}.json"))
    if head != remote:
        git(repo, "push", "origin", f"HEAD:refs/heads/{branch}")
    if wallet is not None and not wallet_published(public, wallet[1]):
        run_wallet(wallet, public, cloudflare_credentials(ctx))
    (ctx.state_dir / f"{FRONTEND_STATE}.json").unlink(missing_ok=True)
    write_state(ctx, PENDING_STATE, {"lock_sha256": ctx.lock_sha256, "dapp_commit": head, "config_sha256": config["config_sha256"],
                                     "wallet_commit": wallet[1] if wallet else None,
                                     "deposits_paused_setting": next(iter(deposit_flags(repo, public).values()))})


def run_wallet(wallet, public, credentials):
    checkout, _, env = wallet
    argv = ["bash", str(Path(checkout) / public["wallet"]["script"])]
    outcome = subprocess.run(argv, cwd=checkout, env={**os.environ, **env, **credentials}, capture_output=True, text=True,
                             timeout=WRANGLER_SECONDS * 4, check=False)
    if outcome.returncode != 0:
        raise RuntimeError(f"wallet release failed (exit {outcome.returncode}): {redact_tail(outcome.stderr)}")


def repository_of(repo):
    found = GITHUB_REMOTE.search(git(repo, "remote", "get-url", "origin"))
    require(found is not None, "the dapp origin is not a GitHub remote")
    return found.group(1)


def workflow_runs(repository, commit):
    outcome = run_local(["gh", "run", "list", "--repo", repository, "--commit", commit, "--limit", "50", "--json",
                         "workflowName,status,conclusion"], GIT_SECONDS)
    if outcome.returncode != 0:
        raise RuntimeError("gh run list failed: " + redact_tail(outcome.stderr))
    return json.loads(outcome.stdout)


def workflow_verdict(runs, names):
    """None while a listed workflow is missing or running, a message when one failed, True when all are green."""
    states = {name: [run for run in runs if run["workflowName"] == name] for name in names}
    failed = [name for name, rows in states.items() if any(r["status"] == "completed" and r["conclusion"] != "success" for r in rows)]
    if failed:
        return "workflow failed for this commit: " + ", ".join(failed)
    done = all(rows and all(r["status"] == "completed" for r in rows) for rows in states.values())
    return True if done else None


def new_psy_addresses(documents):
    return {f"{chain}.PSY": document["protocol"]["tokens"]["PSY"]["l1Address"].lower() for chain, document in documents.items()}


def check_live_frontends(ctx, public, config):
    """What is served right now: the live config is the recorded one, every bundle site holds the new PSY addresses
    (and, where flagged, none of the previous release's), every public site answers 200. Any network failure fails."""
    _, live = live_config(public)
    require(live and pr.sha256_bytes(live) == config["config_sha256"], "the live config is not the recorded one")
    documents = l1_documents(ctx)
    new = new_psy_addresses(documents)
    checks = {site: pr.check_bundle(public["sites"][site], new, config["previous_addresses"] if flag else {})
              for site, flag in public["bundle_sites"].items()}
    served = {site: pr.fetch(url)[0] for site, url in public["sites"].items()}
    require(all(code == 200 for code in served.values()), "a public site does not answer 200: " + json.dumps(served, sort_keys=True))
    return checks, served


def frontends_verify(ctx):
    """Checks CI and the served sites; only a pass records the step as complete."""
    public = pr.read_public(ctx.release_dir)
    pending = read_recorded(ctx, PENDING_STATE)
    config = read_recorded(ctx, CONFIG_STATE)
    require(pending["config_sha256"] == config["config_sha256"], "frontends were published for another config than the live one")
    repo, branch = public_path(ctx, "dapp_checkout"), public["dapp"]["branch"]
    remote = git(repo, "ls-remote", "origin", f"refs/heads/{branch}").split()[0]
    shown = subprocess.run(["git", "-C", str(repo), "show", f"{remote}:{public['dapp']['l1_file']}"], capture_output=True,
                           timeout=GIT_SECONDS, check=False)
    require(shown.returncode == 0, "the pushed dapp branch has no config file")
    _, live = live_config(public)
    require(pr.sha256_bytes(shown.stdout) == pr.sha256_bytes(live) == config["config_sha256"],
            "the committed dapp config differs from the live config; CI builds from the live one")
    repository, verdict = repository_of(repo), {}

    def settled():
        verdict["value"] = workflow_verdict(workflow_runs(repository, remote), public["workflows"])
        return verdict["value"] is True
    wait_until(settled, lambda: verdict.get("value") if isinstance(verdict.get("value"), str) else None, CI_POLL_SECONDS, CI_WAIT_SECONDS,
               "frontend workflows")
    checks, served = check_live_frontends(ctx, public, config)
    if pending["wallet_commit"]:
        require(wallet_published(public, pending["wallet_commit"]), "the published wallet release is not the recorded commit")
    write_state(ctx, FRONTEND_STATE, dict(pending, dapp_commit=remote))
    return {"dapp_commit": remote, "workflows": public["workflows"], "bundles": checks, "sites": served,
            "wallet_commit": pending["wallet_commit"]}


def require_frontends_current(ctx):
    """Acceptance and the release table continue only when step 79 completed for this lock and the live sites still
    serve this deployment; a network error is a refusal, never a pass."""
    recorded = read_recorded(ctx, FRONTEND_STATE)
    config = read_recorded(ctx, CONFIG_STATE)
    require(recorded.get("config_sha256") == config.get("config_sha256"),
            "the frontends were published for another config than the recorded live one; rerun step 79")
    check_live_frontends(ctx, pr.read_public(ctx.release_dir), config)


PUBLIC_STEPS = {
    "publish_trust_setup": Step("publish_trust_setup", trust_check, trust_apply, trust_verify, cutover=False),
    "publish_public_config": Step("publish_public_config", config_check, config_apply, config_verify, cutover=False),
    "publish_frontends": Step("publish_frontends", frontends_check, frontends_apply, frontends_verify, cutover=False),
}
