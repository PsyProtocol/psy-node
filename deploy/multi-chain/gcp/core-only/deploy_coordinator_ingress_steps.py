#!/usr/bin/env python3
"""Step 57: install the internal coordinator ingress (Nginx) on the coordinator host.

Realm processors, Workers, the Relayer, Guardians, the Faucet and the Services indexer reach the coordinator only
through this ingress. It spreads requests over the coordinator edges and moves a request that could not connect, or
timed out before it was sent, to the next edge; a request an edge already received is never sent again. It listens
only on the coordinator host's private address. Installed before the cutover: until the edges run it has no live
upstream, which changes nothing.
"""
import base64
import hashlib
import json

import deploy_health as health
from deploy_prepare_steps import require
from deploy_remote import Step

COORDINATOR_HOST = "gcp-cp-ce"
SITE_NAME = "psy-coordinator-ingress"
SITE = f"/etc/nginx/sites-available/{SITE_NAME}"
ENABLED = f"/etc/nginx/sites-enabled/{SITE_NAME}"
DEFAULT_SITE = "/etc/nginx/sites-enabled/default"
COMMAND_SECONDS = 60
INSTALL_SECONDS = 600
READ_STATE = """import hashlib, json, os, subprocess, sys
site, enabled, default = sys.argv[1:4]
def sha(path):
    try:
        return hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except FileNotFoundError:
        return None
def show(prop):
    return subprocess.run(['systemctl', 'show', '-p', prop, '--value', 'nginx'], capture_output=True, text=True).stdout.strip()
test = subprocess.run(['/usr/sbin/nginx', '-t'], capture_output=True) if os.path.exists('/usr/sbin/nginx') else None
status = subprocess.run(['dpkg-query', '-W', '-f=${Status}', 'nginx'], capture_output=True, text=True).stdout
print(json.dumps(dict(installed=status == 'install ok installed', site=sha(site),
                      enabled=os.path.islink(enabled) and os.readlink(enabled) == site,
                      default=os.path.lexists(default), active=show('ActiveState'), enabled_unit=show('UnitFileState'),
                      config_ok=test is not None and test.returncode == 0)))
"""
INSTALL = """import base64, json, os, signal, subprocess, sys
args = json.loads(sys.stdin.readline())
def stop(signum, frame):
    raise SystemExit('interrupted by signal ' + str(signum))
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGHUP, stop)
env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
def run(argv):
    done = subprocess.run(argv, env=env, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(' '.join(argv[:2]) + ' failed: ' + (done.stderr or done.stdout)[-800:])
status = subprocess.run(['dpkg-query', '-W', '-f=${Status}', 'nginx'], capture_output=True, text=True).stdout
if status != 'install ok installed':
    if os.path.lexists('/usr/sbin/policy-rc.d'):
        raise SystemExit('/usr/sbin/policy-rc.d already exists; inspect it before installing nginx')
    # Keep the package's default site from ever starting on port 80.
    with open('/usr/sbin/policy-rc.d', 'x') as file:
        file.write('#!/bin/sh\\nexit 101\\n')
    os.chmod('/usr/sbin/policy-rc.d', 0o755)
    try:
        run(['dpkg', '--configure', '-a'])
        run(['apt-get', '-o', 'DPkg::Lock::Timeout=120', 'update'])
        run(['apt-get', '-o', 'DPkg::Lock::Timeout=120', 'install', '-y', '--no-install-recommends', 'nginx'])
        run(['dpkg', '--configure', '-a'])
    finally:
        os.unlink('/usr/sbin/policy-rc.d')
temporary = args['site'] + '.new'
with open(temporary, 'wb') as file:
    file.write(base64.b64decode(args['text']))
os.chmod(temporary, 0o644)
os.replace(temporary, args['site'])
if os.path.lexists(args['default']):
    os.unlink(args['default'])
if os.path.lexists(args['enabled']) and not os.path.islink(args['enabled']):
    raise SystemExit(args['enabled'] + ' is not a symlink; inspect it before enabling the ingress')
if os.path.islink(args['enabled']) and os.readlink(args['enabled']) != args['site']:
    os.unlink(args['enabled'])
if not os.path.islink(args['enabled']):
    os.symlink(args['site'], args['enabled'])
run(['/usr/sbin/nginx', '-t'])
run(['systemctl', 'enable', 'nginx'])
run(['systemctl', 'reload-or-restart', 'nginx'])
"""


def site_text(topology):
    """The Nginx site for the coordinator ingress, derived only from the release topology."""
    coordinator = topology["coordinator"]
    address = topology["hosts"][coordinator["host"]]
    servers = "".join(f"    server {address}:{port} max_fails=2 fail_timeout=15s;\n" for port in coordinator["edge_ports"])
    return (f"upstream psy_coordinator_edges {{\n{servers}}}\n"
            f"server {{\n"
            f"    listen {address}:{coordinator['ingress_port']};\n"
            f"    allow 10.0.0.0/8;\n"
            f"    deny all;\n"
            f"    client_max_body_size 512m;\n"
            f"    location / {{\n"
            f"        proxy_pass http://psy_coordinator_edges;\n"
            f"        proxy_buffering off;\n"
            f"        proxy_request_buffering off;\n"
            f"        proxy_connect_timeout 2s;\n"
            f"        proxy_send_timeout 300s;\n"
            f"        proxy_read_timeout 300s;\n"
            f"        proxy_next_upstream error timeout;\n"
            f"        proxy_next_upstream_tries 3;\n"
            f"        proxy_next_upstream_timeout 10s;\n"
            f"    }}\n"
            f"}}\n")


def read_installed(ctx):
    output = ctx.remote.run_root_text(COORDINATOR_HOST, ["/usr/bin/python3", "-I", "-c", READ_STATE, SITE, ENABLED,
                                                         DEFAULT_SITE], COMMAND_SECONDS)
    return json.loads(output)


def is_installed(state, text):
    return (state["installed"] and state["site"] == hashlib.sha256(text.encode()).hexdigest() and state["enabled"]
            and not state["default"] and state["config_ok"] and state["active"] == "active"
            and state["enabled_unit"] == "enabled")


def ingress_check(ctx):
    topology = health.read_topology(ctx)
    require(topology["coordinator"]["host"] == COORDINATOR_HOST, "the coordinator ingress host differs from the topology")
    site_text(topology)


def ingress_apply(ctx):
    text = site_text(health.read_topology(ctx))
    if is_installed(read_installed(ctx), text):
        return
    arguments = {"site": SITE, "enabled": ENABLED, "default": DEFAULT_SITE,
                 "text": base64.b64encode(text.encode()).decode()}
    ctx.remote.run_root_text(COORDINATOR_HOST, ["/usr/bin/python3", "-I", "-c", INSTALL], INSTALL_SECONDS,
                             stdin_text=json.dumps(arguments) + "\n")


def ingress_verify(ctx):
    text = site_text(health.read_topology(ctx))
    state = read_installed(ctx)
    require(is_installed(state, text), "the coordinator host does not run the reviewed coordinator ingress")
    return {"site_sha256": state["site"]}


COORDINATOR_INGRESS_STEPS = {"install_coordinator_ingress": Step("install_coordinator_ingress", ingress_check, ingress_apply,
                                                     ingress_verify, cutover=False)}
