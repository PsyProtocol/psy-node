#!/usr/bin/env python3
"""Enable Nostr on the exact installed R3 Services package; check-only by default.

Relay observation is read-only. Empty history is an observation, not replay protection.
Apply stops/starts Services only and preserves the old seal outside the release.
"""
import argparse
import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import time
import types

RELEASE = Path('/opt/psy-services/releases/core-testnet-20261027-dfd4e483-r3')
BACKUP = Path('/var/lib/psy-services-nostr-enable-20261027-r3')
STATE = Path('/var/lib/psy-services-fresh-20261027-r3/nostr')
UNIT = 'psy-services-fresh-20261027-r3.service'
OLD_MANIFEST = '97c25050b122f00f3d65a114d6fd3e2c79dfd94ea326bc04f70336f61d374bda'
OLD_CONFIG = 'c4bad8c1c05a58f4f355eaf69ed063c306f9aa12112f1f02ff7556ff6b9a174a'
UNIT_SHA = '9ac2fff93d41cfa450998523420847a314a85b439e59a1c5bff74532ae12ff6b'
INSTALLER_SHA = '3de33d91a1110779e8b270a5e490ad4607b3111b948823775d2f01f4be286e55'
ACTIVATION_SHA = '8843b826d669f13c4e17009ec105d3b224683d26abba7b1779ac3d1103788413'
RELAY_URL = 'wss://nostr-stg.psy-protocol.xyz/'
RELAY_ID = '831911e38adc253e9469b9fac0b15ce80092de8e6bed27bf42eaddfc0d106317'
RELAY_IMAGE = 'sha256:64025dc3b517ff376ac482f33fcb10329410ac81b524ab4934245f1ef2c8d1f8'
RELAY_ROOT = Path('/opt/nostr-relay-r2-20261027')
RELAY_CONFIG = '1efd2fe4aaaba1cd9d73ccfb77ea886116b397aa4c5cb9f78d3594be33128ec5'
MAX_OBSERVATION_AGE = 120


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def load_module(name, pin):
    path = RELEASE / (name + '.py')
    for part in (path, *path.parents):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, 'untrusted installed helper path')
    raw = path.read_bytes()
    require(sha(raw) == pin, 'installed helper pin mismatch')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def transition(config_raw, manifest_raw):
    require(sha(config_raw) == OLD_CONFIG and sha(manifest_raw) == OLD_MANIFEST,
            'only the frozen disabled package can be enabled')
    config, manifest = json.loads(config_raw), json.loads(manifest_raw)
    require(config['nostr'] == {'enabled': False, 'lookback_seconds': 0, 'relay_url': RELAY_URL}
            and config['nostr']['enabled'] is False
            and type(config['nostr']['lookback_seconds']) is int, 'unexpected Nostr baseline')
    require(manifest['group'] == 'services' and manifest['files']['services.json'] == OLD_CONFIG
            and manifest['files']['units/' + UNIT] == UNIT_SHA
            and 'configuration_transition' not in manifest, 'unexpected package baseline')
    updated = copy.deepcopy(config)
    updated['nostr'].update(enabled=True, lookback_seconds=172800)
    raw = encode(updated)
    new_manifest = copy.deepcopy(manifest)
    new_manifest['files']['services.json'] = sha(raw)
    new_manifest['configuration_transition'] = {
        'operation': 'enable-nostr-r3', 'previous_manifest_sha256': OLD_MANIFEST,
        'previous_services_config_sha256': OLD_CONFIG,
        'services_config_sha256': sha(raw),
        'changed_fields': ['nostr.enabled', 'nostr.lookback_seconds'],
    }
    return raw, encode(new_manifest)


def relay_container():
    value = json.loads(subprocess.check_output(
        ['docker', 'inspect', RELAY_ID], timeout=15, stderr=subprocess.PIPE))[0]
    require(value['Id'] == RELAY_ID and value['Image'] == RELAY_IMAGE
            and value['State']['Running'] and value['State']['Pid'] > 0,
            'relay identity or running state mismatch')
    mounts = {(m['Source'], m['Destination'], m['RW']) for m in value['Mounts']}
    require(mounts == {(str(RELAY_ROOT / 'data'), '/usr/src/app/db', True),
                       (str(RELAY_ROOT / 'config.toml'), '/usr/src/app/config.toml', False)},
            'relay mounts changed')
    return value


def observe_relay():
    require(os.geteuid() == 0, 'root required')
    addresses = subprocess.check_output(['hostname', '-I'], text=True).split()
    require('10.148.0.29' in addresses, 'relay observation requires .29')
    before = relay_container()
    require(sha((RELAY_ROOT / 'config.toml').read_bytes()) == RELAY_CONFIG, 'relay config changed')
    path = RELAY_ROOT / 'data/nostr.db'
    require(path.is_file() and not path.is_symlink(), 'relay database missing or symlink')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)) as db:
        db.execute('PRAGMA query_only=ON')
        count = db.execute('SELECT count(*) FROM event').fetchone()[0]
    after = relay_container()
    require(before['State']['Pid'] == after['State']['Pid'], 'relay process changed during observation')
    return {'observed_at_unix': int(time.time()), 'host': '10.148.0.29',
            'container_id': RELAY_ID, 'image': RELAY_IMAGE, 'config_sha256': RELAY_CONFIG,
            'database': str(path), 'event_count': count, 'relay_url': RELAY_URL}


def read_evidence(helper, path, expected):
    helper.trusted_parents(path)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'relay evidence must be root-owned and not writable by others')
    raw = path.read_bytes()
    require(sha(raw) == expected, 'relay evidence hash mismatch')
    evidence = json.loads(raw)
    require(type(evidence.get('observed_at_unix')) is int
            and 0 <= time.time() - evidence['observed_at_unix'] <= MAX_OBSERVATION_AGE,
            'relay observation stale or future-dated; observe again')
    require(evidence.get('host') == '10.148.0.29' and evidence.get('container_id') == RELAY_ID
            and evidence.get('image') == RELAY_IMAGE and evidence.get('config_sha256') == RELAY_CONFIG
            and evidence.get('database') == str(RELAY_ROOT / 'data/nostr.db')
            and evidence.get('relay_url') == RELAY_URL
            and type(evidence.get('event_count')) is int and evidence['event_count'] == 0,
            'relay identity mismatch or history is not empty')
    return raw


def preflight(args):
    require(os.geteuid() == 0, 'root required')
    helper = load_module('install_services', INSTALLER_SHA)
    activation = load_module('activate_services', ACTIVATION_SHA)
    manifest, topology = helper.load_package(RELEASE, OLD_MANIFEST)
    require(manifest['group'] == 'services', 'Services group required')
    require(activation.preflight(helper, RELEASE, manifest, topology) == [UNIT], 'wrong unit scope')
    running = activation.process(helper, UNIT, 'psy-services')
    helper.no_links(STATE)
    require(not os.path.lexists(STATE), 'fresh Nostr state must not exist; never remove or import a cursor')
    helper.trusted_parents(BACKUP)
    require(not os.path.lexists(BACKUP), 'prior transition exists; inspect without retry')
    evidence = read_evidence(helper, args.relay_evidence, args.relay_evidence_sha256)
    credentials = helper.read_credentials(Path(topology['credentials']) / 'services.env', 'services', topology)
    environment = {'PATH': '/usr/bin:/bin', 'PSY_NETWORK_TYPE': 'psy-public-testnet', **credentials}
    subprocess.run(['/usr/bin/python3', '-I', '-B', str(RELEASE / 'install_services.py'),
                    'guard', '--package', str(RELEASE), '--role', 'services'],
                   env=environment, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    config_raw = (RELEASE / 'services.json').read_bytes()
    manifest_raw = (RELEASE / 'manifest.json').read_bytes()
    new_config, new_manifest = transition(config_raw, manifest_raw)
    return helper, activation, topology, running, evidence, config_raw, manifest_raw, new_config, new_manifest


def replace_file(helper, path, raw):
    mode = stat.S_IMODE(path.stat().st_mode)
    temporary = path.with_name(path.name + '.nostr-enable-new')
    helper.write_new(temporary, raw, mode)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def enable(args):
    values = preflight(args)
    helper, activation, topology, running, evidence, config_raw, manifest_raw, new_config, new_manifest = values
    result = {'applied': False, 'previous_manifest_sha256': OLD_MANIFEST,
              'manifest_sha256': sha(new_manifest), 'config_sha256': sha(new_config),
              'relay_observation_sha256': sha(evidence), 'unit': UNIT,
              'history_imported': False, 'active_replay_protection': False}
    if not args.apply:
        return result
    require(args.new_manifest_sha256 == sha(new_manifest), 'apply requires exact new seal from check')
    # The external create-only backup also excludes another successful invocation.
    BACKUP.mkdir(mode=0o700)
    helper.write_new(BACKUP / 'services.json.before', config_raw)
    helper.write_new(BACKUP / 'manifest.json.before', manifest_raw)
    helper.write_new(BACKUP / 'services.json.after', new_config)
    helper.write_new(BACKUP / 'manifest.json.after', new_manifest)
    helper.write_new(BACKUP / 'relay-observation.json', evidence)
    helper.write_new(BACKUP / 'transition.json', encode({**result, 'tool_sha256': sha(Path(__file__).read_bytes())}))
    require(activation.process(helper, UNIT, 'psy-services')['pid'] == running['pid'], 'Services process changed')
    read_evidence(helper, args.relay_evidence, args.relay_evidence_sha256)
    subprocess.run(['systemctl', 'stop', UNIT], check=True, timeout=90)
    status = helper.unit_status(UNIT)
    require(status['ActiveState'] == 'inactive' and status['MainPID'] == '0', 'Services did not stop')
    helper.fence_services()
    require(not os.path.lexists(STATE), 'Nostr cursor appeared; preserve state')
    read_evidence(helper, args.relay_evidence, args.relay_evidence_sha256)
    helper.load_package(RELEASE, OLD_MANIFEST)
    # Each rename is atomic; Services remains stopped until both files validate.
    replace_file(helper, RELEASE / 'services.json', new_config)
    replace_file(helper, RELEASE / 'manifest.json', new_manifest)
    manifest, topology = helper.load_package(RELEASE, sha(new_manifest))
    activation.preflight(helper, RELEASE, manifest, topology)
    subprocess.run(['systemctl', 'start', UNIT], check=True, timeout=90)
    result.update(applied=True, process=activation.wait_process(helper, UNIT, 'psy-services'),
                  nostr_ingestion_accepted=False, backup=str(BACKUP))
    helper.write_new(BACKUP / 'result.json', encode(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observe-relay', action='store_true', help='Read-only .29 SQLite observation; prints public JSON')
    parser.add_argument('--relay-evidence', type=Path)
    parser.add_argument('--relay-evidence-sha256')
    parser.add_argument('--new-manifest-sha256')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.observe_relay:
        require(not args.apply and not args.relay_evidence and not args.relay_evidence_sha256
                and not args.new_manifest_sha256, 'conflicting observation options')
        print(json.dumps(observe_relay(), sort_keys=True))
    else:
        require(args.relay_evidence is not None and args.relay_evidence.is_absolute()
                and args.relay_evidence_sha256, 'absolute pinned relay evidence required')
        print(json.dumps(enable(args), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Subprocess/configuration exceptions can contain credentials; print no payload.
        raise SystemExit('Nostr enable refused: ' + type(error).__name__
                         + '; preserve files and service state, no automatic retry') from None
