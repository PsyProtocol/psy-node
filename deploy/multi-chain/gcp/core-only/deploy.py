#!/usr/bin/env python3
"""Step registry and command line of the release orchestrator; step logic lives in the step modules."""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys

import release_lock
from deploy_remote import DeployContext, OperatorPending, Remote, ResultRefused, find_secret, redact_tail


# Step modules to import; each exports one or more NAME_STEPS dicts of Step.
STEP_MODULES = ("deploy_prepare_steps", "deploy_clear_steps", "deploy_proxy_steps", "deploy_monitoring_steps", "deploy_ingress_steps", "deploy_core_steps", "deploy_faucet_steps", "deploy_bridge_steps", "deploy_services_steps")
EXIT_FAILURE = 1
EXIT_UNKNOWN_STEP = 2
EXIT_PENDING = 3
CUTOVER_KIND = "py-cutover"
CUTOVER_CONFIRMATIONS = ("CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING", "CONFIRM_FULL_FRESH_DEPLOY")
MESSAGE_LIMIT = 2000


def merge_steps(step_groups):
    registry = {}
    for group in step_groups:
        for name, step in group.items():
            if step.name != name:
                raise ValueError(f"step name differs from its key: {name}")
            if name in registry:
                raise ValueError(f"duplicate step: {name}")
            registry[name] = step
    return registry


def build_registry(module_names=STEP_MODULES):
    groups = []
    for module_name in module_names:
        module = importlib.import_module(module_name)
        groups += [value for attribute, value in vars(module).items() if attribute.endswith("_STEPS")
                   and isinstance(value, dict)]
    return merge_steps(groups)


def step_kinds(steps_file):
    """Map each py: or py-cutover: step name in the step table to its kind; a missing table is an error."""
    path = Path(steps_file)
    if not path.is_file():
        raise ValueError(f"step table not found: {path.name}")
    kinds = {}
    for line in path.read_text().splitlines():
        fields = line.split("\t")
        if line.startswith("#") or len(fields) < 2 or ":" not in fields[1]:
            continue
        kind, name = fields[1].split(":", 1)
        if kind in ("py", CUTOVER_KIND):
            kinds[name] = kind
    return kinds


def unregistered_steps(steps_file, registry):
    return [name for name in step_kinds(steps_file) if name not in registry]


def mismatched_cutover_steps(steps_file, registry):
    """Names whose table type disagrees with the cutover flag of their registered step."""
    return [name for name, kind in step_kinds(steps_file).items()
            if name in registry and (kind == CUTOVER_KIND) != registry[name].cutover]


def require_cutover_confirmations(step, steps_file):
    kinds = step_kinds(steps_file)
    if step.name not in kinds:
        raise ValueError(f"step is not in the step table: {step.name}")
    if (kinds[step.name] == CUTOVER_KIND) != step.cutover:
        raise ValueError(f"step table type differs from the cutover flag of {step.name}")
    if step.cutover and any(os.environ.get(var) != "1" for var in CUTOVER_CONFIRMATIONS):
        raise ValueError("cutover step requires " + " and ".join(CUTOVER_CONFIRMATIONS) + " set to 1")


def host_addresses(release_dir):
    return release_lock.read_document(release_dir / "topology.json")["hosts"]


def host_aliases(release_dir, lock):
    return sorted(set(host_addresses(release_dir)) | set(lock["hosts"]))


def build_context(args, step):
    release_dir, private_dir = Path(args.release_dir).resolve(), Path(args.private_dir).resolve()
    raw = release_lock.read_regular(release_dir / "release-lock.json")
    lock = release_lock.parse(raw)
    release_lock.validate_release_lock(lock, release_dir, step.requires_complete, private_dir)
    remote = Remote(release_lock.read_document(args.access), lock, topology_hosts=host_addresses(release_dir))
    missing = remote.missing_aliases(host_aliases(release_dir, lock))
    if missing:
        raise ValueError("hosts missing from the access file: " + ", ".join(missing))
    state_dir = private_dir / "state"
    state_dir.mkdir(mode=0o700, exist_ok=True)
    state_dir.chmod(0o700)
    return DeployContext(lock=lock, lock_sha256=hashlib.sha256(raw).hexdigest(), release_dir=release_dir,
                         run_dir=Path(args.run_dir).resolve(), remote=remote, private_dir=private_dir,
                         state_dir=state_dir)


def write_verify_result(run_dir, name, verify_report):
    if not isinstance(verify_report, dict):
        raise TypeError(f"verify of {name} must return a dict")
    where = find_secret(verify_report)
    if where:
        raise ResultRefused(where)
    text = json.dumps(verify_report, indent=2, sort_keys=True) + "\n"
    target = Path(run_dir) / f"{name}.json"
    temporary = target.with_name(target.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(text)
    os.replace(temporary, target)


def print_pending(name, pending):
    print(f"[deploy] PENDING {name}: operator action required on {pending.host}")
    print(f"[deploy]   command: {pending.command}")
    print(f"[deploy]   result file: {pending.result_path}")
    print("[deploy]   after it finishes, rerun deploy_all with --from for this step")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run one release deployment step.")
    parser.add_argument("step")
    parser.add_argument("--release-dir", required=True)
    parser.add_argument("--access", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--private-dir", required=True)
    parser.add_argument("--steps-file", required=True)
    parser.add_argument("--plan", action="store_true")
    return parser.parse_args(argv)


def plan(args, step, registry):
    context = build_context(args, step)
    print(f"[deploy] plan {step.name}: requires_complete={step.requires_complete} lock={context.lock_sha256}")
    missing = unregistered_steps(args.steps_file, registry)
    if missing:
        raise ValueError("no registered module for step: " + ", ".join(missing))
    mismatched = mismatched_cutover_steps(args.steps_file, registry)
    if mismatched:
        raise ValueError("step table type differs from the cutover flag of: " + ", ".join(mismatched))


def run_step(args, step):
    require_cutover_confirmations(step, args.steps_file)
    context = build_context(args, step)
    if not (context.run_dir.is_dir() and os.access(context.run_dir, os.W_OK)):
        raise ValueError("run directory is not a writable directory")
    step.check(context)
    step.apply(context)
    write_verify_result(context.run_dir, step.name, step.verify(context))
    print(f"[deploy] OK {step.name}")


def main(argv=None, registry=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        registry = build_registry() if registry is None else registry
        step = registry.get(args.step)
        if step is None:
            print(f"deploy: no registered step: {args.step}", file=sys.stderr)
            return EXIT_UNKNOWN_STEP
        if args.plan:
            plan(args, step, registry)
        else:
            run_step(args, step)
    except OperatorPending as pending:
        print_pending(args.step, pending)
        return EXIT_PENDING
    except ResultRefused as error:
        print(f"deploy: {args.step} failed: verify result refused at {redact_tail(str(error), MESSAGE_LIMIT)}",
              file=sys.stderr)
        return EXIT_FAILURE
    except (Exception, SystemExit) as error:
        # A step or module that calls sys.exit must not turn into success or PENDING.
        detail = f"exited with status {error.code!r}" if isinstance(error, SystemExit) else str(error)
        print(f"deploy: {args.step} failed: {redact_tail(detail, MESSAGE_LIMIT)}", file=sys.stderr)
        return EXIT_FAILURE
    return 0


if __name__ == "__main__":
    sys.exit(main())
