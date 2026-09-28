#!/usr/bin/env python3
"""Pinned additive Envio upgrade. No reset, historical backfill or live DB restore."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request

ROOT = Path('/var/lib/parth-envio-maintenance/20260928-timestamps')
OLD = Path('/opt/parth/envio/releases/20260918161800/psy-relayer-envio')
NEW = Path('/opt/parth/envio/releases/20260928-deposit-timestamps/psy-relayer-envio')
CURRENT = Path('/opt/parth/envio/current')
STAGE = Path('/tmp/envio-timestamps-staged')
PATCH = Path('/opt/parth/envio/patch-envio-rpc-source.py')
UNIT = 'parth-envio.service'
CLONE = 'envio_timestamp_validation_20260928'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(args, **kwargs):
    r = subprocess.run(args, capture_output=True, **kwargs)
    if r.returncode:
        raise RuntimeError(f'Command failed ({Path(args[0]).name}); inspect protected evidence')
    return r.stdout


def env_values(home):
    return dict(line.split('=', 1) for line in (home / '.env').read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def pg(database, sql):
    return run(['docker', 'exec', '-i', '-u', 'postgres', 'parth-postgres',
                'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-d', database],
               input=sql.encode()).decode().strip()


def snapshot(database):
    return json.loads(pg(database, '''BEGIN READ ONLY;
SET LOCAL statement_timeout='20s';
SELECT json_build_object(
'deposits',(SELECT coalesce(json_agg(json_build_object('id',id,'chain_id',chain_id,
 'digest',md5((to_jsonb(d)-'block_timestamp')::text))), '[]'::json) FROM envio."Deposit" d),
'chains',(SELECT json_agg(row_to_json(c)) FROM envio.chain_metadata c),
'trees',(SELECT json_agg(row_to_json(t)) FROM envio."DepositTreeMeta" t));
COMMIT;'''))


def dump(name):
    with (ROOT / name).open('xb') as f:
        subprocess.run(['docker', 'exec', '-u', 'postgres', 'parth-postgres',
                        'pg_dump', '-Fc', '-d', 'envio_bridge'], stdout=f, check=True)


def migration(database):
    sql = (STAGE / '001-deposit-block-timestamp.sql').read_bytes()
    run(['docker', 'exec', '-i', '-u', 'postgres', 'parth-postgres', 'psql', '-Xq',
         '-v', 'ON_ERROR_STOP=1', '-v', 'envio_schema=envio', '-d', database], input=sql)


def metadata(action):
    values = env_values(OLD)
    secret = values.get('HASURA_GRAPHQL_ADMIN_SECRET', '').strip('"\'')
    if not secret:
        raise RuntimeError('Missing Hasura credentials; inspect before rollout')
    req = urllib.request.Request('http://127.0.0.1:18080/v1/metadata',
        data=json.dumps({'type': action, 'args': {}}).encode(),
        headers={'Content-Type': 'application/json', 'x-hasura-admin-secret': secret})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def logged(args, label, cwd=None, env=None):
    with (ROOT / label).open('wb') as f:
        r = subprocess.run(args, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT)
    if r.returncode:
        raise RuntimeError(f'{label} failed; inspect protected log')


def policy():
    run(['python3', str(PATCH), '--home', str(NEW), '--check'],
        env=dict(os.environ, ENVIO_RPC_POLLING_INTERVAL_MILLIS='12000'))


def prepare():
    if CURRENT.resolve() != OLD or NEW.exists() or ROOT.exists():
        raise RuntimeError('Unexpected release or existing preparation; inspect, do not overwrite')
    manifest = json.loads((STAGE / 'source.json').read_text())
    for name, expected in manifest['baseline'].items():
        if sha(OLD / name) != expected:
            raise RuntimeError(f'Live baseline mismatch: {name}')
    for name, expected in manifest['candidate'].items():
        if sha(STAGE / name) != expected:
            raise RuntimeError(f'Staged input mismatch: {name}')
    ROOT.mkdir(mode=0o700)
    protected = {name: sha(OLD / name) for name in ('.env', 'config.yaml')}
    (ROOT / 'protected.json').write_text(json.dumps(protected))
    (ROOT / 'source.json').write_text(json.dumps(manifest, indent=2))
    (ROOT / 'before-prepare.json').write_text(json.dumps(snapshot('envio_bridge')))
    dump('prepare.dump')
    (ROOT / 'hasura-metadata.json').write_text(json.dumps(metadata('export_metadata')))
    NEW.parent.mkdir(parents=True)
    shutil.copytree(OLD, NEW, symlinks=True, ignore=shutil.ignore_patterns('logs'))
    for name in ('handlers.ts', 'schema.graphql', 'schema.ts', 'package.json'):
        shutil.copyfile(STAGE / name, NEW / name)
    build_env = dict(os.environ, **env_values(NEW))
    logged(['/usr/local/bin/pnpm', 'exec', 'envio', 'codegen', '--config', 'config.yaml'],
           'codegen.log', cwd=NEW, env=build_env)
    logged(['/usr/local/bin/pnpm', 'exec', 'rescript', 'build'],
           'generated-build.log', cwd=NEW / 'generated', env=build_env)
    logged(['python3', str(PATCH), '--home', str(NEW)], 'poll-patch.log', env=build_env)
    policy()
    if any(sha(NEW / name) != value for name, value in protected.items()):
        raise RuntimeError('Protected config changed during preparation')
    print(json.dumps({'prepared': str(NEW), 'live_unchanged': str(CURRENT.resolve())}))


def validate():
    if CURRENT.resolve() != OLD:
        raise RuntimeError('Live release changed')
    if pg('postgres', f"SELECT count(*) FROM pg_database WHERE datname='{CLONE}'") != '0':
        raise RuntimeError('Validation DB already exists; inspect, no automatic drop')
    values = env_values(NEW)
    user = values['ENVIO_PG_USER'].strip('"\'')
    if not user.replace('_', '').isalnum():
        raise RuntimeError('Unexpected DB owner')
    pg('postgres', f'CREATE DATABASE {CLONE} OWNER "{user}";')
    with (ROOT / 'prepare.dump').open('rb') as f:
        r = subprocess.run(['docker', 'exec', '-i', '-u', 'postgres', 'parth-postgres',
            'pg_restore', '--exit-on-error', '--no-owner', '--role', user, '-d', CLONE],
            stdin=f, capture_output=True)
    if r.returncode:
        raise RuntimeError('Clone restore failed')
    before = snapshot(CLONE)
    migration(CLONE)
    migration(CLONE)
    if snapshot(CLONE) != before:
        raise RuntimeError('Migration changed existing data')
    values.update(ENVIO_PG_DATABASE=CLONE, ENVIO_INDEXER_PORT='19898', METRICS_PORT='19898',
                  ENVIO_HASURA='false', TUI_OFF='true', LOG_STRATEGY='console-raw')
    # Both selectors are overridden; never use the production DB in this probe.
    if 'ENVIO_DATABASE_URL' in values:
        from urllib.parse import urlsplit, urlunsplit
        u = urlsplit(values['ENVIO_DATABASE_URL'].strip('"\''))
        values['ENVIO_DATABASE_URL'] = urlunsplit(u._replace(path='/' + CLONE))
    with (ROOT / 'clone-resume.log').open('wb') as f:
        r = subprocess.run(['timeout', '--signal=INT', '--kill-after=10s', '45s',
                            '/usr/local/bin/pnpm', 'start'], cwd=NEW,
                           env=dict(os.environ, **values), stdout=f, stderr=subprocess.STDOUT)
    log = (ROOT / 'clone-resume.log').read_text()
    if r.returncode not in (0, 124) or 'Successfully resumed indexing state!' not in log:
        raise RuntimeError('Clone did not safely resume; do not activate')
    after = snapshot(CLONE)
    old = {d['id']: d['digest'] for d in before['deposits']}
    new = {d['id']: d['digest'] for d in after['deposits']}
    if not all(new.get(k) == v for k, v in old.items()):
        raise RuntimeError('Existing clone deposits changed')
    result = {'resume_pass': True, 'before': before['chains'], 'after': after['chains'],
              'deposits_preserved': len(old), 'test_database': CLONE}
    (ROOT / 'validation.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


def switch(home):
    link = CURRENT.with_name('current.timestamp-next')
    link.symlink_to(home)
    link.replace(CURRENT)


def ready():
    for _ in range(60):
        try:
            with urllib.request.urlopen('http://127.0.0.1:9898/healthz', timeout=3) as r:
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(2)
    raise RuntimeError('Envio health timeout')


def activate(commit):
    if not commit or len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise RuntimeError('Reviewed source commit required')
    if CURRENT.resolve() != OLD or not json.loads((ROOT / 'validation.json').read_text())['resume_pass']:
        raise RuntimeError('Unexpected release or missing clone validation')
    manifest = json.loads((ROOT / 'source.json').read_text())
    for name, expected in manifest['candidate'].items():
        path = NEW / name if name in ('handlers.ts', 'schema.graphql', 'schema.ts', 'package.json') else STAGE / name
        if sha(path) != expected:
            raise RuntimeError(f'Candidate changed: {name}')
    policy()
    protected = json.loads((ROOT / 'protected.json').read_text())
    if any(sha(OLD / name) != value or sha(NEW / name) != value for name, value in protected.items()):
        raise RuntimeError('Live/candidate config changed')
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    run(['systemctl', 'stop', UNIT])
    try:
        dump('activation.dump')
        before = snapshot('envio_bridge')
        (ROOT / 'before-activation.json').write_text(json.dumps(before))
        migration('envio_bridge')
        metadata('reload_metadata')
        (NEW / 'TIMESTAMP-RELEASE.json').write_text(json.dumps({'commit': commit, 'source': manifest}))
        switch(NEW)
        run(['systemctl', 'start', UNIT])
        ready()
        time.sleep(15)
        after = snapshot('envio_bridge')
        (ROOT / 'after-activation.json').write_text(json.dumps(after))
        old = {d['id']: d['digest'] for d in before['deposits']}
        new = {d['id']: d['digest'] for d in after['deposits']}
        if not all(new.get(k) == v for k, v in old.items()):
            raise RuntimeError('Existing live deposits changed')
        result = {'activated': str(NEW), 'commit': commit, 'since': started, 'preserved_deposits': len(old)}
        (ROOT / 'result.json').write_text(json.dumps(result))
        print(json.dumps(result))
    except Exception:
        run(['systemctl', 'stop', UNIT])
        if CURRENT.resolve() != OLD:
            switch(OLD)
        run(['systemctl', 'start', UNIT])
        ready()
        raise RuntimeError('Activation failed; prior application resumed. Additive columns retained; no DB restore.') from None


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase', choices=['prepare', 'validate', 'activate'])
    p.add_argument('--commit')
    args = p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Root required on gcp-postgres')
    os.umask(0o077)
    if args.phase == 'prepare':
        prepare()
    elif args.phase == 'validate':
        validate()
    else:
        activate(args.commit)
