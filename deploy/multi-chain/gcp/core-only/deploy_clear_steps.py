#!/usr/bin/env python3
"""Cutover steps 61-64: stop old services, clear node state and rebuild the databases.

These steps delete data on live hosts. Every deletion comes from the private retired-state.json, goes through
clear_host_state.py, and is validated by a read-only pass over the whole fleet before the first change.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shlex

import clear_host_state
import release_lock
from deploy_prepare_steps import TOOLS_DIR as DEFAULT_TOOLS_DIR, file_sha256, local_path, require, write_state
from deploy_remote import HERE_DOCUMENT_MARKER, OperatorPending, RemoteConnectionError, RemoteError, Step


TOOLS_DIR = DEFAULT_TOOLS_DIR
REMOTE_SCRIPTS = Path(__file__).resolve().parents[3] / "gcp" / "remote"
TOOL, PROBE = "clear_host_state.py", "probe_databases.py"
CORE_HOST = "gcp-cp-ce"
SHORT_TIMEOUT_SECONDS = 600
CLEAR_TIMEOUT_SECONDS = 3600
INSTALL_TIMEOUT_SECONDS = 1800
MAX_REFUSAL_LINES = 15
SUPPORT_SCRIPTS = ("install-docker.sh", "mount-data-disk.sh")
ROOT_PYTHON = ["/usr/bin/python3", "-I", "-B", "/dev/stdin"]
DOCKER = "/usr/bin/docker"
SYSTEMCTL = "/usr/bin/systemctl"
ACTIVE_STATES = ("active", "activating", "reloading", "deactivating")
EXIT_MISSING, EXIT_WRONG_OWNER = 3, 4


@dataclass(frozen=True)
class Engine:
    host: str
    component: str
    image_key: str
    image_var: str
    container: str
    script: str


ENGINES = (Engine("gcp-scylla", "scylla", "scylla", "SCYLLA_IMAGE", "scylla-server", "install-scylla.sh"),
           Engine("gcp-redis", "valkey", "valkey", "VALKEY_IMAGE", "valkey-server", "install-valkey.sh"),
           Engine("gcp-nats", "nats", "nats", "NATS_IMAGE", "nats-server", "install-nats.sh"),
           Engine("gcp-postgres", "postgres", "postgres", "POSTGRES_IMAGE", "parth-postgres", "install-postgres.sh"),
           Engine("gcp-nostr", "nostr", "nostr", "NOSTR_RELAY_IMAGE", "nostr-relay", "install-nostr-relay.sh"))
DATABASE_HOSTS = frozenset(engine.host for engine in ENGINES)


def read_checked_tool(ctx, name):
    raw = (TOOLS_DIR / name).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ctx.lock["tool_sha256"][name], f"tool hash differs: {name}")
    return raw.decode()


def retirement(ctx):
    """Return ({host: entry}, retained document), both hash-checked against the lock and structurally validated."""
    documents = {}
    for name, key in (("retired-state.json", "retired_state"), ("retained-paths.json", "retained_paths")):
        path = ctx.private_dir / name
        require(path.is_file() and file_sha256(path) == ctx.lock["inputs"][key], f"{name} differs from the lock")
        documents[key] = release_lock.read_document(path)
    release_lock.validate_retirement(documents["retired_state"], documents["retained_paths"])
    return documents["retired_state"]["hosts"], documents["retained_paths"]


def retained_slice(retained, host):
    text = json.dumps({"paths": [item for item in retained["paths"] if item["host"] == host]}, sort_keys=True)
    return text, hashlib.sha256(text.encode()).hexdigest()


def keep_units(entry):
    suffixes = tuple("." + kind for kind in clear_host_state.UNIT_TYPES)
    return sorted({Path(path).name for path in entry["retain"] if path.endswith(suffixes)})


def host_addresses(ctx):
    topology = release_lock.read_document(ctx.release_dir / "topology.json")["hosts"]
    return {**topology, **ctx.lock["hosts"]}


def lock_text(ctx):
    raw = (ctx.release_dir / "release-lock.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ctx.lock_sha256, "release-lock.json differs from the loaded lock")
    return raw.decode()


@dataclass(frozen=True)
class Request:
    """What one tool run is asked to do on one host."""
    host: str
    entry: dict
    retained_text: str
    retained_sha256: str
    stop: list
    clear: list
    containers: list
    address: str = None

    def plan(self):
        allow = self.entry.get("clear_allow", []) if self.clear else []
        return {"clear": self.clear, "allow": allow, "stop": self.stop, "keep": keep_units(self.entry),
                "containers": self.containers}

    def digest(self, lock_sha256):
        return clear_host_state.request_digest(self.host, self.plan(), self.retained_sha256, lock_sha256)

    def flags(self):
        plan = self.plan()
        flags = ["--host", self.host, "--clear-paths", json.dumps(plan["clear"]), "--clear-allow", json.dumps(plan["allow"]),
                 "--stop-units", json.dumps(plan["stop"]), "--keep-units", json.dumps(plan["keep"]),
                 "--containers", json.dumps(plan["containers"])]
        return flags + (["--address", self.address] if self.address else [])


def make_request(retired, retained, host, *, stop=True, clear=True, containers=True, address=None):
    entry = retired[host]
    text, digest = retained_slice(retained, host)
    return Request(host, entry, text, digest, entry["stop"] if stop else [], entry["clear"] if clear else [],
                   entry["containers"] if containers else [], address)


def request_for(ctx, retired, retained, host, **parts):
    return make_request(retired, retained, host, address=host_addresses(ctx).get(host), **parts)


def parse_report(host, output):
    try:
        report = json.loads(output)
    except ValueError:
        report = None
    require(isinstance(report, dict) and report.get("host") == host, f"{host}: the tool did not print its report")
    return report


def tool_flags(ctx, request, *, apply, unprivileged=False):
    flags = [*request.flags(), "--release-lock", "inline:" + lock_text(ctx), "--release-lock-sha256", ctx.lock_sha256,
             "--retained-paths", "inline:" + request.retained_text, "--retained-paths-sha256", request.retained_sha256,
             "--exit-zero-with-report"]
    if apply:
        flags.append("--apply")
    if unprivileged:
        flags.append("--skip-retained-hash")
    return flags


def stream_tool(ctx, request, *, apply):
    """Run the tool as root with the script on stdin; the report is returned, never raised on."""
    output = ctx.remote.run_root_text(request.host, [*ROOT_PYTHON, *tool_flags(ctx, request, apply=apply)],
                                      CLEAR_TIMEOUT_SECONDS, stdin_text=read_checked_tool(ctx, TOOL), show_stderr=True)
    return parse_report(request.host, output)


def stream_unprivileged(ctx, request):
    """Dry run as the login user (operator hosts have no no-prompt sudo); retained paths are not read."""
    source = read_checked_tool(ctx, TOOL)
    require(HERE_DOCUMENT_MARKER not in source, "the tool collides with the here-document marker")
    command = shlex.join([*ROOT_PYTHON, *tool_flags(ctx, request, apply=False, unprivileged=True)])
    script = f"set -euo pipefail\n{command} <<'{HERE_DOCUMENT_MARKER}'\n{source}\n{HERE_DOCUMENT_MARKER}\n"
    return parse_report(request.host, ctx.remote.run_script(request.host, script, CLEAR_TIMEOUT_SECONDS))


def raise_on_error(host, report):
    if not report.get("error"):
        return
    lines = [f"{host}: {report['error']}", *[f"  {reason}" for reason in report.get("refused", [])[:MAX_REFUSAL_LINES]]]
    raise ValueError("\n".join(lines))


def retained_digest(report):
    rows = sorted((item["path"], item["kind"], item["sha256"]) for item in report["retained"])
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()


def partition_hosts(ctx, hosts):
    cloud = sorted(host for host in hosts if ctx.remote.sudo_mode(host) == "passwordless")
    return cloud, sorted(set(hosts) - set(cloud))


def collect_failures(failures, action):
    try:
        return action()
    except (ValueError, RemoteError) as error:
        failures.append(str(error))
        return None


def raise_failures(failures):
    if failures:
        raise ValueError("\n".join(failures))


def dry_run_fleet(ctx):
    """Read-only gate: the full request of every host, without --apply; any refusal or error fails all."""
    retired, retained = retirement(ctx)
    postgres_password(ctx)
    failures = []
    for host in sorted(retired):
        request = request_for(ctx, retired, retained, host)
        if ctx.remote.sudo_mode(host) == "passwordless":
            report = collect_failures(failures, lambda: stream_tool(ctx, request, apply=False))
        else:
            report = collect_failures(failures, lambda: stream_unprivileged(ctx, request))
        if report is None:
            continue
        if report.get("error"):
            collect_failures(failures, lambda: raise_on_error(host, report))
        elif report["unlisted_active"]:
            failures.append(f"{host}: business units active that no list names: {', '.join(report['unlisted_active'])}")
    raise_failures(failures)
    return {"hosts": len(retired)}


# Retained baseline: the first hashes seen before a delete are kept; every later run must still match them.
def load_baseline(ctx):
    path = ctx.state_dir / "retained_baseline.json"
    if not path.exists():
        return {"lock_sha256": ctx.lock_sha256, "hosts": {}}
    baseline = release_lock.read_document(path)
    require(baseline.get("lock_sha256") == ctx.lock_sha256 and isinstance(baseline.get("hosts"), dict),
            "the retained baseline belongs to another release lock; remove it only on purpose")
    return baseline


def check_baseline(ctx, host, report, *, record):
    rows = {item["path"]: {"kind": item["kind"], "sha256": item["sha256"]} for item in report["retained"]}
    missing = [item["path"] for item in report["retained"] if item.get("class") == "secret" and item["kind"] == "missing"]
    require(not missing, f"{host}: retained secret is missing: {missing[0] if missing else ''}")
    for item in report["retained"]:
        after = item.get("sha256_after")
        require(after is None or after == item["sha256"], f"{host}: a retained secret changed during the clear")
    baseline = load_baseline(ctx)
    known = baseline["hosts"].get(host)
    if known is None:
        require(record, f"{host}: no retained baseline was recorded before the first delete")
        baseline["hosts"][host] = rows
        write_state(ctx, "retained_baseline", baseline)
        return
    require(known == rows, f"{host}: retained state differs from the baseline recorded before the first delete")


def all_hosts_check(ctx):
    read_checked_tool(ctx, TOOL)
    return retirement(ctx)[0]


def stop_check(ctx):
    all_hosts_check(ctx)
    dry_run_fleet(ctx)


def stop_apply(ctx):
    retired, retained = retirement(ctx)
    cloud, _ = partition_hosts(ctx, retired)
    for host in cloud:
        request = request_for(ctx, retired, retained, host, clear=False, containers=False)
        raise_on_error(host, stream_tool(ctx, request, apply=True))


def stop_verify(ctx):
    retired, retained = retirement(ctx)
    cloud, _ = partition_hosts(ctx, retired)
    failures, hosts = [], {}
    for host in cloud:
        request = request_for(ctx, retired, retained, host, clear=False, containers=False)
        report = stream_tool(ctx, request, apply=False)
        raise_on_error(host, report)
        hosts[host] = {"listed_units": len(retired[host]["stop"]), "still_active": len(report["active_listed"]),
                       "retained_units_active": len(report["active_kept"])}
        if report["active_listed"]:
            failures.append(f"{host}: listed units still active: {', '.join(report['active_listed'])}")
        if report["unlisted_active"]:
            failures.append(f"{host}: business units active that no list names: {', '.join(report['unlisted_active'])}")
    raise_failures(failures)
    return {"hosts": hosts}


# Operator hosts: one fixed command stops and clears; the result file carries the request digest.
def operator_home(ctx, host):
    home = ctx.remote.run_script(host, 'set -euo pipefail\nprintf %s "$HOME"\n', 60).strip()
    require(home.startswith("/") and ".." not in home.split("/") and " " not in home, f"{host}: unusable home directory")
    return home


def operator_dir(ctx, host):
    return f"{operator_home(ctx, host)}/.psy-release-{ctx.lock_sha256[:12]}"


def operator_result_path(ctx, host):
    return f"{operator_dir(ctx, host)}/{host}-result.json"


def read_operator_result(ctx, host):
    directory, path = operator_dir(ctx, host), operator_result_path(ctx, host)
    script = (f"set -euo pipefail\ndir={shlex.quote(directory)}\nfile={shlex.quote(path)}\n"
              f'[ -f "$file" ] || exit {EXIT_MISSING}\nme=$(id -u)\n'
              f'[ "$(stat -c %u -- "$dir")" = "$me" ] && [ "$(stat -c %a -- "$dir")" = 700 ] || exit {EXIT_WRONG_OWNER}\n'
              f'[ "$(stat -c %u -- "$file")" = "$me" ] && [ "$(stat -c %a -- "$file")" = 600 ] || exit {EXIT_WRONG_OWNER}\n'
              'cat -- "$file"\n')
    try:
        text = ctx.remote.run_script(host, script, 60)
    except RemoteConnectionError:
        raise
    except RemoteError as error:
        if error.exit_code == EXIT_MISSING:
            return None
        if error.exit_code == EXIT_WRONG_OWNER:
            raise ValueError(f"{host}: the operator result has the wrong owner or mode") from None
        raise
    try:
        report = json.loads(text)
    except ValueError:
        return None
    return report if isinstance(report, dict) else None


def judge_operator_result(ctx, request, report):
    """Return 'done' or 'stale'; raise when the operator run reported a failure for this exact request."""
    if report.get("request_sha256") != request.digest(ctx.lock_sha256) or report.get("lock_sha256") != ctx.lock_sha256:
        return "stale"
    if report.get("retained"):
        check_baseline(ctx, request.host, report, record=True)
    if report.get("error"):
        raise ValueError(f"{request.host}: the operator run failed: {report['error']}")
    done = (report.get("applied") is True and report.get("host") == request.host
            and report.get("retained_unchanged") is True and not report.get("unlisted_active"))
    require(done, f"{request.host}: the operator result is incomplete")
    return "done"


def remove_operator_result(ctx, host):
    ctx.remote.run_script(host, f"set -euo pipefail\nrm -f -- {shlex.quote(operator_result_path(ctx, host))}\n", 60)


def operator_command(ctx, request):
    directory = operator_dir(ctx, request.host)
    tool_path = f"{directory}/{TOOL}"
    tool_hash = ctx.lock["tool_sha256"][TOOL]
    run = shlex.join(["sudo", "/usr/bin/python3", "-I", "-B", tool_path, *request.flags(),
                      "--release-lock", f"{directory}/release-lock.json", "--release-lock-sha256", ctx.lock_sha256,
                      "--retained-paths", f"{directory}/{request.host}-retained.json",
                      "--retained-paths-sha256", request.retained_sha256,
                      "--result", operator_result_path(ctx, request.host), "--apply"])
    return f"echo '{tool_hash}  {tool_path}' | sha256sum -c - && {run}"


def stage_operator(ctx, request):
    host = request.host
    directory = operator_dir(ctx, host)
    read_checked_tool(ctx, TOOL)
    local_retained = ctx.state_dir / f"operator-{host}-retained.json"
    local_retained.write_text(request.retained_text)
    local_retained.chmod(0o600)
    ctx.remote.run_script(host, f"set -euo pipefail\numask 077\ninstall -d -m 0700 -- {shlex.quote(directory)}\n", 60)
    ctx.remote.copy_files(host, [TOOLS_DIR / TOOL, ctx.release_dir / "release-lock.json"], directory)
    ctx.remote.copy_files(host, [local_retained], f"{directory}/{host}-retained.json")


def operator_requests(ctx):
    retired, retained = retirement(ctx)
    _, operator = partition_hosts(ctx, retired)
    return [request_for(ctx, retired, retained, host) for host in operator]


def operator_state(ctx, request):
    report = read_operator_result(ctx, request.host)
    if report is None:
        return None
    if judge_operator_result(ctx, request, report) == "done":
        return report
    remove_operator_result(ctx, request.host)
    return None


def operator_apply(ctx):
    for request in operator_requests(ctx):
        try:
            report = operator_state(ctx, request)
        except ValueError:
            remove_operator_result(ctx, request.host)
            raise
        if report is None:
            stage_operator(ctx, request)
            raise OperatorPending(request.host, operator_command(ctx, request), operator_result_path(ctx, request.host))


def operator_live_script(request):
    lines = ["set -uo pipefail",
             'unit() { s=$(systemctl is-active -- "$2" 2>/dev/null || true); echo "unit $1 ${s:-unknown}"; }',
             'path() { if out=$(stat -c %F -- "$2" 2>&1); then echo "path $1 present";'
             ' elif [[ "$out" == *"No such file"* ]]; then echo "path $1 absent"; else echo "path $1 denied"; fi; }']
    lines += [f"unit {index} {shlex.quote(unit)}" for index, unit in enumerate(request.stop)]
    lines += [f"path {index} {shlex.quote(path)}" for index, path in enumerate(request.clear)]
    return "\n".join(lines) + "\n"


def operator_live_problems(ctx, request):
    """Unprivileged read of the live state: listed units must be inactive and listed paths gone."""
    output = ctx.remote.run_script(request.host, operator_live_script(request), 120)
    active, present, denied = [], 0, 0
    for line in output.splitlines():
        kind, index, state = (line.split() + ["", "", ""])[:3]
        if kind == "unit" and state in ACTIVE_STATES:
            active.append(request.stop[int(index)])
        elif kind == "path" and state == "present":
            present += 1
        elif kind == "path" and state == "denied":
            denied += 1
    problems = []
    if active:
        problems.append(f"{request.host}: listed units still active: {', '.join(active)}")
    if present:
        problems.append(f"{request.host}: {present} listed paths still exist")
    if denied:
        problems.append(f"{request.host}: {denied} listed paths cannot be checked without privileges")
    return problems


def operator_verify_hosts(ctx):
    summary, failures = {}, []
    for request in operator_requests(ctx):
        report = collect_failures(failures, lambda: read_operator_result(ctx, request.host))
        if report is None:
            failures.append(f"{request.host}: no valid operator result; run step stop_operator_hosts")
            continue
        if collect_failures(failures, lambda: judge_operator_result(ctx, request, report)) != "done":
            continue
        problems = operator_live_problems(ctx, request)
        failures += problems
        summary[request.host] = {"stopped": len(report["stopped"]), "cleared": len(report["cleared"]),
                                 "retained_digest": retained_digest(report), "live_problems": len(problems)}
    raise_failures(failures)
    return summary


def operator_check(ctx):
    all_hosts_check(ctx)
    require(lock_text(ctx), "release lock is empty")


def operator_verify(ctx):
    return {"hosts": operator_verify_hosts(ctx)}


# Step 63: node state on the passwordless, non-database hosts.
def node_hosts(ctx, retired):
    cloud, _ = partition_hosts(ctx, retired)
    return [host for host in cloud if host not in DATABASE_HOSTS and retired[host]["clear"]]


def clear_check(ctx):
    all_hosts_check(ctx)
    retired, retained = retirement(ctx)
    failures = []
    for host in node_hosts(ctx, retired):
        request = request_for(ctx, retired, retained, host, stop=False, containers=False)
        report = collect_failures(failures, lambda: stream_tool(ctx, request, apply=False))
        if report is not None:
            collect_failures(failures, lambda: raise_on_error(host, report))
    raise_failures(failures)


def clear_host(ctx, request):
    """Read-only pass, baseline on first sight, then the clear, then the same baseline again."""
    host = request.host
    before = stream_tool(ctx, request, apply=False)
    raise_on_error(host, before)
    check_baseline(ctx, host, before, record=True)
    report = stream_tool(ctx, request, apply=True)
    raise_on_error(host, report)
    check_baseline(ctx, host, report, record=False)
    return report


def clear_apply(ctx):
    retired, retained = retirement(ctx)
    recorded = {}
    for host in node_hosts(ctx, retired):
        report = clear_host(ctx, request_for(ctx, retired, retained, host, stop=False, containers=False))
        recorded[host] = {"retained_digest": retained_digest(report), "cleared": len(report["cleared"])}
    write_state(ctx, "clear_node_state", recorded)


def clear_verify(ctx):
    retired, retained = retirement(ctx)
    failures, hosts = [], {}
    for host in node_hosts(ctx, retired):
        request = request_for(ctx, retired, retained, host, stop=False, containers=False)
        report = stream_tool(ctx, request, apply=False)
        raise_on_error(host, report)
        if report["cleared"]:
            failures.append(f"{host}: {len(report['cleared'])} listed paths still exist")
        collect_failures(failures, lambda: check_baseline(ctx, host, report, record=False))
        hosts[host] = {"retained_digest": retained_digest(report), "retained_count": len(report["retained"])}
    raise_failures(failures)
    return {"hosts": hosts, "operator_hosts": operator_verify_hosts(ctx)}


# Step 64: databases.
def database_address(url):
    return url.split("://", 1)[-1].rsplit(":", 1)[0]


def check_database_hosts(ctx):
    infrastructure = release_lock.read_document(ctx.release_dir / "topology.json")["infrastructure"]
    expected = {"gcp-scylla": database_address(infrastructure["scylla_db_url"]),
                "gcp-redis": database_address(infrastructure["redis_url"]),
                "gcp-nats": database_address(infrastructure["nats_jetstream_url"])}
    for host, address in expected.items():
        require(ctx.lock["hosts"].get(host) == address, f"{host}: lock address differs from topology infrastructure")
    for engine in ENGINES:
        require(engine.host in ctx.lock["hosts"], f"{engine.host} is not a release host")


def check_images(ctx):
    for engine in ENGINES:
        image = ctx.lock["images"][engine.image_key]
        require(isinstance(image, str) and release_lock.IMAGE.fullmatch(image),
                f"images.{engine.image_key} must be pinned by digest")
    for engine in ENGINES:
        require((REMOTE_SCRIPTS / engine.script).is_file(), f"install script missing: {engine.script}")


def postgres_password(ctx):
    password = local_path(ctx, "databases", "postgres_password_file").read_text().strip("\n")
    require(password and "\n" not in password and password != "change-me", "postgres password file is empty or a placeholder")
    return password


def rebuild_check(ctx):
    all_hosts_check(ctx)
    for name in (TOOL, PROBE):
        read_checked_tool(ctx, name)
    check_images(ctx)
    check_database_hosts(ctx)
    postgres_password(ctx)
    retired, retained = retirement(ctx)
    failures = []
    for engine in ENGINES:
        require(ctx.remote.sudo_mode(engine.host) == "passwordless", f"{engine.host}: needs no-prompt sudo")
        request = request_for(ctx, retired, retained, engine.host)
        report = collect_failures(failures, lambda: stream_tool(ctx, request, apply=False))
        if report is not None:
            collect_failures(failures, lambda: raise_on_error(engine.host, report))
    raise_failures(failures)


def engine_env(ctx, engine):
    env = [f"{engine.image_var}={ctx.lock['images'][engine.image_key]}"]
    if engine.component == "nostr":
        env += [f"NOSTR_RELAY_HOME={ctx.lock['nostr']['home']}", f"NOSTR_RELAY_NETWORK={ctx.lock['nostr']['network']}"]
    return env


def install_engine(ctx, engine):
    """Copy the pinned installer to the host, check its hash there, and run it with the lock's image."""
    files = [REMOTE_SCRIPTS / name for name in (engine.script, *SUPPORT_SCRIPTS)]
    digests = {path.name: file_sha256(path) for path in files}
    ctx.remote.copy_files(engine.host, files, "/tmp")
    listing = "".join(f"{digest}  /tmp/{name}\n" for name, digest in digests.items())
    ctx.remote.run_root_text(engine.host, ["/usr/bin/sha256sum", "-c", "-"], 60, stdin_text=listing)
    script = f"/tmp/{engine.script}"
    if engine.component == "postgres":
        wrapper = f"read -r POSTGRES_PASSWORD; export POSTGRES_PASSWORD; exec /usr/bin/bash {script}"
        ctx.remote.run_root_text(engine.host, ["/usr/bin/env", *engine_env(ctx, engine), "/usr/bin/bash", "-c", wrapper],
                                 INSTALL_TIMEOUT_SECONDS, stdin_text=postgres_password(ctx), show_stderr=True)
    else:
        ctx.remote.run_root_text(engine.host, ["/usr/bin/env", *engine_env(ctx, engine), "/usr/bin/bash", script],
                                 INSTALL_TIMEOUT_SECONDS, show_stderr=True)


def probe_engine(ctx, engine, event_id=None):
    """Live write and read; for Nostr, a recorded event id switches to a read-back so one run writes one event."""
    argv = [*ROOT_PYTHON, "nostr-read", event_id] if event_id and engine.component == "nostr" else [*ROOT_PYTHON, engine.component]
    output = ctx.remote.run_root_text(engine.host, argv, SHORT_TIMEOUT_SECONDS,
                                      stdin_text=read_checked_tool(ctx, PROBE), show_stderr=True)
    try:
        report = json.loads(output)
    except ValueError:
        report = None
    require(isinstance(report, dict), f"{engine.host}: the probe did not print a report")
    require(report.get("ok") is True and report.get("read_write") is True,
            f"{engine.host}: {report.get('error', 'probe failed')}")
    if engine.component == "valkey":
        require(report.get("maxmemory_policy") == "noeviction", f"{engine.host}: live maxmemory-policy is not noeviction")
    return report


def running_image(ctx, engine):
    output = ctx.remote.run_root_text(engine.host, [DOCKER, "inspect", "-f", "{{.Config.Image}}", engine.container],
                                      60).strip()
    expected = ctx.lock["images"][engine.image_key]
    require(output == expected, f"{engine.host}: container {engine.container} does not run the locked image")
    return output


def rebuild_record(ctx):
    """The completion record; unreadable or foreign content is a failure, never 'nothing recorded'."""
    path = ctx.state_dir / "rebuild_databases.json"
    if not path.exists():
        return {"lock_sha256": ctx.lock_sha256, "hosts": {}}
    record = release_lock.read_document(path)
    require(record.get("lock_sha256") == ctx.lock_sha256 and isinstance(record.get("hosts"), dict),
            "the rebuild record belongs to another lock or is malformed; do not wipe again without a deliberate decision")
    return record


def check_recorded(ctx, engine, row, request):
    require(row["image"] == ctx.lock["images"][engine.image_key],
            f"{engine.host}: rebuilt with another image; remove its record only after a deliberate decision")
    require(row["request_sha256"] == request.digest(ctx.lock_sha256),
            f"{engine.host}: the rebuild request differs from the recorded one; it is never wiped again automatically")


def refuse_live_chain(ctx):
    """A lost record after step 65 must not let this step wipe a running chain."""
    prefix = ctx.lock["units"]["core_prefix"]
    output = ctx.remote.run_root_text(CORE_HOST, [SYSTEMCTL, "list-units", "--type=service", "--state=active,activating,reloading",
                                                  "--no-legend", "--plain", "--no-pager"], 120)
    active = [line.split()[0] for line in output.splitlines() if line.split() and line.split()[0].startswith(prefix)]
    require(not active, f"refusing to wipe the databases: core unit {active[0] if active else ''} is active on {CORE_HOST}")


def rebuild_engine(ctx, engine, request, record):
    dry = stream_tool(ctx, request, apply=False)
    raise_on_error(engine.host, dry)
    check_baseline(ctx, engine.host, dry, record=True)
    report = stream_tool(ctx, request, apply=True)
    raise_on_error(engine.host, report)
    check_baseline(ctx, engine.host, report, record=False)
    install_engine(ctx, engine)
    running_image(ctx, engine)
    probed = probe_engine(ctx, engine)
    row = {"image": ctx.lock["images"][engine.image_key], "request_sha256": request.digest(ctx.lock_sha256)}
    if engine.component == "nostr":
        row["event_id"] = probed["event_id"]
    record["hosts"][engine.host] = row
    write_state(ctx, "rebuild_databases", record)


def rebuild_apply(ctx):
    retired, retained = retirement(ctx)
    record = rebuild_record(ctx)
    requests = {engine.host: request_for(ctx, retired, retained, engine.host) for engine in ENGINES}
    for engine in ENGINES:
        if engine.host in record["hosts"]:
            check_recorded(ctx, engine, record["hosts"][engine.host], requests[engine.host])
    pending = [engine for engine in ENGINES if engine.host not in record["hosts"]]
    if pending:
        refuse_live_chain(ctx)
    for engine in pending:
        rebuild_engine(ctx, engine, requests[engine.host], record)


def rebuild_verify(ctx):
    record = rebuild_record(ctx)
    failures, hosts = [], {}
    for engine in ENGINES:
        row = record["hosts"].get(engine.host)
        if row is None:
            failures.append(f"{engine.host}: no rebuild record; run the step again")
            continue
        report = collect_failures(failures, lambda: (running_image(ctx, engine),
                                                     probe_engine(ctx, engine, row.get("event_id")))[1])
        if report is not None:
            hosts[engine.host] = {key: value for key, value in report.items() if key != "ok"}
            hosts[engine.host]["image"] = row["image"]
    raise_failures(failures)
    return {"hosts": hosts}


CLEAR_STEPS = {
    "stop_services": Step("stop_services", stop_check, stop_apply, stop_verify, cutover=True),
    "stop_operator_hosts": Step("stop_operator_hosts", operator_check, operator_apply, operator_verify, cutover=True),
    "clear_node_state": Step("clear_node_state", clear_check, clear_apply, clear_verify, cutover=True),
    "rebuild_databases": Step("rebuild_databases", rebuild_check, rebuild_apply, rebuild_verify, cutover=True),
}
