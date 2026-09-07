import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const sourceDir = dirname(fileURLToPath(import.meta.url));

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'psy-bsc-paths-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repo = join(root, 'deployment checkout');
  const scripts = join(repo, 'deploy/bsc-testnet');
  mkdirSync(scripts, { recursive: true });
  for (const file of ['lib.sh', 'full-stack-lib.sh', 'full-stack.env.example']) {
    copyFileSync(join(sourceDir, file), join(scripts, file));
  }
  return { root, repo, scripts };
}

function readPaths(f, overrides = {}) {
  const stdout = execFileSync('bash', [
    '-c',
    'source "$1"; bsc_full_stack_export; printf "%s\\n" "$BSC_PSY_DAPP_DIR" "$LOCAL_STAGING_PSY_DAPP_DIR" "$LOCAL_CF_PUBLISH_FRONTENDS"',
    'test-source-paths',
    join(f.scripts, 'full-stack-lib.sh'),
  ], {
    encoding: 'utf8',
    cwd: f.root,
    // Do not source the operator's real local.env/full-stack.env or ABI files.
    env: { PATH: process.env.PATH, HOME: f.root, BSC_LOCAL_RELAYER_WITHDRAW_METHOD_ID: '1', ...overrides },
  });
  return stdout.trimEnd().split('\n');
}

test('defaults to this deployment submodule without a historical sibling', (t) => {
  const f = fixture(t);
  const path = join(f.repo, 'psy-dapp');
  assert.deepEqual(readPaths(f), [path, path, '0']);
});

test('shared DApp override is propagated unchanged, including spaces', (t) => {
  const f = fixture(t);
  const path = join(f.root, 'shared frontend');
  assert.deepEqual(readPaths(f, { PSY_DAPP_DIR: path }), [path, path, '0']);
});

test('BSC override takes precedence over the shared source', (t) => {
  const f = fixture(t);
  const path = join(f.root, 'historical reproduction');
  assert.deepEqual(readPaths(f, { BSC_PSY_DAPP_DIR: path, PSY_DAPP_DIR: '/unused' }), [path, path, '0']);
});

test('copied example resolves to its deployment, not the workspace parent', (t) => {
  const f = fixture(t);
  copyFileSync(join(f.scripts, 'full-stack.env.example'), join(f.scripts, 'full-stack.env'));
  const path = join(f.repo, 'psy-dapp');
  assert.deepEqual(readPaths(f), [path, path, '0']);
  assert.notEqual(path, resolve(f.repo, '../psy-dapp'));
});

test('copied example preserves shared and BSC source overrides', (t) => {
  const f = fixture(t);
  copyFileSync(join(f.scripts, 'full-stack.env.example'), join(f.scripts, 'full-stack.env'));
  const path = join(f.root, 'explicit source');
  assert.deepEqual(readPaths(f, { PSY_DAPP_DIR: path }), [path, path, '0']);
  assert.deepEqual(readPaths(f, { BSC_PSY_DAPP_DIR: path, PSY_DAPP_DIR: '/unused' }), [path, path, '0']);
});
