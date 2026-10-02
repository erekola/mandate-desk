// NF-02 (varmennus-V04.md P3): tools/check-vendor-advisories.mjs used to treat
// any non-array `vulns` value, including null, an explicit error object or a
// wrongly typed result, as an empty list and print a clean "Last run" record
// with exit code 0. These tests run the real script as a child process with
// fetch intercepted before import, so no OSV.dev network call is made and no
// file on disk is touched; the script only ever prints and sets process.exitCode,
// which is what the child process itself exits with once main() returns.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { ROOT } from '../src/store.mjs';

const SCRIPT_URL = new URL('../tools/check-vendor-advisories.mjs', import.meta.url).href;

function runWithFetchResults(results) {
  const module = `
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => (${JSON.stringify({ results })})
    });
    await import(${JSON.stringify(SCRIPT_URL)});
  `;
  const result = spawnSync(process.execPath, ['--input-type=module'], { input: module, encoding: 'utf8', cwd: ROOT, windowsHide: true });
  return { ...result, checkerExitCode: result.status };
}

// vendor/ethers-6.17.0/sbom.json currently lists exactly five components
// (README/SECURITY.md, MD-07); the mocked OSV response must match that count
// or the script's own count-mismatch check (not the one under test) rejects it.
const COMPONENT_COUNT = 5;

// Each malformed value sits inside an otherwise clean five-result batch, so the
// checker's per-component validation reaches that value's own branch. A single
// batch holding all five would stop at the first one and leave the rest unread.
const CLEAN_BATCH = [{}, { vulns: [] }, {}, { vulns: [] }, {}];
const MALFORMED_CASES = [
  ['null', null, /was not an object \(got null\)/],
  ['a non-array vulns field', { vulns: 'not-an-array' }, /non-array vulns field \(got "not-an-array"\)/],
  ['an explicit error field', { error: 'fixture failure' }, /returned an error for .*"fixture failure"/],
  ['a number', 17, /was not an object \(got 17\)/],
  ['a boolean', false, /was not an object \(got false\)/]
];

for (const [label, value, message] of MALFORMED_CASES) {
  test(`NF-02: a malformed OSV.dev result (${label}) is a failed check, not a clean record`, () => {
    const batch = CLEAN_BATCH.map((entry, index) => (index === 2 ? value : entry));
    assert.equal(batch.length, COMPONENT_COUNT);
    const run = runWithFetchResults(batch);
    assert.equal(run.checkerExitCode, 2, run.stdout + run.stderr);
    assert.doesNotMatch(run.stdout, /^OK /m, 'a malformed batch must not print any clean OK line');
    assert.doesNotMatch(run.stdout, /Last run:/, 'a malformed batch must not print a pasteable "Last run" record');
    assert.match(run.stderr, /malformed/i);
    assert.match(run.stderr, message);
  });
}

test('NF-02: a clean OSV.dev response (missing vulns key, meaning none found) still reports OK and prints "Last run"', () => {
  const clean = [{}, { vulns: [] }, {}, { vulns: [] }, {}];
  assert.equal(clean.length, COMPONENT_COUNT);
  const run = runWithFetchResults(clean);
  assert.equal(run.checkerExitCode, 0, run.stdout + run.stderr);
  assert.equal((run.stdout.match(/^OK /gm) || []).length, COMPONENT_COUNT);
  assert.match(run.stdout, /Last run:.*no advisory found for any of them/);
});

test('NF-02: a real advisory is still reported as FOUND and fails the run', () => {
  const oneVulnerable = [{}, { vulns: [] }, { vulns: [{ id: 'OSV-TEST-1' }] }, { vulns: [] }, {}];
  assert.equal(oneVulnerable.length, COMPONENT_COUNT);
  const run = runWithFetchResults(oneVulnerable);
  assert.equal(run.checkerExitCode, 1, run.stdout + run.stderr);
  assert.match(run.stdout, /FOUND .*OSV-TEST-1/);
  assert.match(run.stdout, /Last run:.*at least one advisory found/);
});
