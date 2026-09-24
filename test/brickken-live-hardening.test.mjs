// Acceptance tests for the repository hardening of 24 September 2026, which
// closes the open items of the repository reviews of 19 and 22 September 2026:
// the live lock path bound to the file its handle holds, the signer endpoint
// record checked as a whole and against this process's code identity, two
// different x402 quotes in one response refused, a closed field schema for
// the evidence export, and a least-privilege CI workflow. Each test states the
// corrected behaviour and fails on the source before this change. Everything
// runs on the in-memory FakeSepolia harness: no network, no real keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { ROOT } from '../src/store.mjs';
import { BrickkenLiveWorkspace } from '../src/brickken-workspace.mjs';
import { loadLiveProposal } from '../src/brickken-live-plan.mjs';
import { LiveSignerClient, validSignerEndpoint } from '../src/brickken-live-adapter.mjs';
import { LIVE_LOCK_KIND, LiveLockError, acquireLiveLock, pathBindingProblem, readLockHolder } from '../src/live-lock.mjs';
import { PROCESS_CODE_IDENTITY_SHA256 } from '../src/code-identity.mjs';
import { EVIDENCE_SCHEMA_KINDS, evidenceKindOf, fieldsOutsideSchema } from '../src/brickken-live-evidence-schema.mjs';
import { FakeRpc, FakeSepolia, FakeSignerGateway, createClock } from './live-fakes.mjs';

// ---------------------------------------------------------------------------
// Harness

function testDir(name) {
  fs.mkdirSync(path.join(ROOT, 'test-output'), { recursive: true });
  return fs.mkdtempSync(path.join(ROOT, 'test-output', `hardening-${name}-`));
}
function environment() {
  const proposal = loadLiveProposal();
  const clock = createClock();
  const chain = new FakeSepolia({ proposal, clock });
  const rpcs = { primary: new FakeRpc(chain, 'primary'), secondary: new FakeRpc(chain, 'secondary') };
  const gateway = new FakeSignerGateway({ chain, proposal, clock });
  const dir = testDir('run');
  const sleep = async ms => { clock.ms += ms; chain.advanceTo(clock.ms); };
  const common = { rpcs, now: () => clock.ms, sleep, pollMs: 5000, verifySignedTransaction: gateway.verify };
  return { proposal, clock, chain, rpcs, gateway, dir, common, sleep };
}
async function ownerApproved(env, overrides = {}) {
  const owner = new BrickkenLiveWorkspace(env.dir, { role: 'owner', signer: env.gateway.client('owner'), ...env.common, ...overrides });
  const { run, approval } = await owner.prepareRun();
  env.gateway.setApproval(approval);
  owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: run.codeIdentitySha256 });
  return { owner, run, approval };
}
function staleRecord() {
  return { kind: LIVE_LOCK_KIND, ownerId: randomUUID(), pid: 2_000_000_000, at: new Date(Date.now() - 60_000).toISOString() };
}

// ---------------------------------------------------------------------------
// The live lock path

test('hardening: a lock path that is a second name of another file is refused before it is opened, and the other file is never written', () => {
  const dir = testDir('lock-link');
  const decoy = path.join(dir, 'unrelated.json');
  const file = path.join(dir, 'live-run.lock');
  fs.writeFileSync(decoy, JSON.stringify(staleRecord()));
  const bytes = fs.readFileSync(decoy);
  fs.linkSync(decoy, file);
  assert.throws(() => acquireLiveLock(file, { holder: { purpose: 'hardening' } }),
    error => error instanceof LiveLockError && error.code === 'LOCK_INVALID' && error.details.reason === 'SECOND_NAME');
  assert.deepEqual(fs.readFileSync(decoy), bytes);
  assert.equal(fs.existsSync(file), true);
  // With the second name gone the same path is an ordinary stale lock and is taken over.
  fs.unlinkSync(file);
  fs.writeFileSync(file, JSON.stringify(staleRecord()));
  const lease = acquireLiveLock(file, { holder: { purpose: 'hardening' } });
  assert.ok(lease.holds());
  assert.equal(lease.release(), true);
  assert.equal(readLockHolder(file).state, 'released');
});

test('hardening: a lock path that is a junction is refused and left in place, instead of the lock opening the folder it points to', () => {
  const dir = testDir('lock-junction');
  const target = path.join(dir, 'elsewhere');
  const file = path.join(dir, 'live-workspace.lock');
  fs.mkdirSync(target);
  fs.symlinkSync(target, file, 'junction');
  assert.throws(() => acquireLiveLock(file, { holder: { purpose: 'hardening' } }),
    error => error instanceof LiveLockError && error.code === 'LOCK_INVALID' && error.details.reason === 'NOT_A_REGULAR_FILE');
  assert.equal(fs.lstatSync(file).isSymbolicLink(), true);
  assert.deepEqual(fs.readdirSync(target), []);
});

test('hardening: a lock path that is a file symbolic link is refused (skipped where Windows refuses to create one without elevation)', t => {
  const dir = testDir('lock-symlink');
  const decoy = path.join(dir, 'unrelated.json');
  const file = path.join(dir, 'live-journal.lock');
  fs.writeFileSync(decoy, JSON.stringify(staleRecord()));
  try { fs.symlinkSync(decoy, file, 'file'); }
  catch (error) {
    if (error?.code === 'EPERM') { t.skip('creating a file symbolic link needs elevation or developer mode here'); return; }
    throw error;
  }
  const bytes = fs.readFileSync(decoy);
  assert.throws(() => acquireLiveLock(file, { holder: { purpose: 'hardening' } }),
    error => error instanceof LiveLockError && error.code === 'LOCK_INVALID' && error.details.reason === 'NOT_A_REGULAR_FILE');
  assert.deepEqual(fs.readFileSync(decoy), bytes);
});

test('hardening: after the open the path must name the very file the handle holds, with one name only', () => {
  const dir = testDir('lock-binding');
  const held = path.join(dir, 'held.lock');
  const other = path.join(dir, 'other.lock');
  fs.writeFileSync(held, 'x');
  fs.writeFileSync(other, 'y');
  const descriptor = fs.openSync(held, 'r+');
  try {
    assert.equal(pathBindingProblem(held, descriptor), null);
    assert.equal(pathBindingProblem(other, descriptor), 'NOT_THE_HELD_FILE');
    assert.equal(pathBindingProblem(path.join(dir, 'missing.lock'), descriptor), 'MISSING');
    fs.linkSync(held, path.join(dir, 'second-name.lock'));
    assert.equal(pathBindingProblem(held, descriptor), 'SECOND_NAME');
  } finally {
    fs.closeSync(descriptor);
  }
});

test('hardening: a run lock replaced by a second name stops owner setup with LIVE_RUN_LOCK_INVALID and the reason in its details, before any write', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  const lock = path.join(env.dir, 'live', 'live-run.lock');
  if (fs.existsSync(lock)) fs.unlinkSync(lock);
  const decoy = path.join(env.dir, 'live', 'decoy.json');
  fs.writeFileSync(decoy, JSON.stringify(staleRecord()));
  fs.linkSync(decoy, lock);
  await assert.rejects(owner.startOwnerSetup({ runId: run.runId }),
    error => error.code === 'LIVE_RUN_LOCK_INVALID' && error.details?.reason === 'SECOND_NAME' && error.details?.lockFile === 'live-run.lock');
  assert.equal(env.gateway.entries.filter(entry => entry.type === 'signed').length, 0);
  assert.equal(owner.view().runs[0].status, 'owner-approved');
});

// ---------------------------------------------------------------------------
// The signer endpoint record

function endpointRecord(overrides = {}) {
  return {
    schemaVersion: 1, kind: 'mandate-desk-live-signer-endpoint', port: 40123, pid: 4242,
    approvalSha256: 'a'.repeat(64), codeIdentitySha256: PROCESS_CODE_IDENTITY_SHA256,
    notAfter: '2026-09-19T08:00:44.990Z', startedAt: '2026-09-15T07:00:00.000Z', ...overrides
  };
}
function writeEndpoint(dir, record, token = 'b'.repeat(64)) {
  fs.mkdirSync(path.join(dir, 'live'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'live', 'signer-endpoint.json'), typeof record === 'string' ? record : JSON.stringify(record));
  fs.writeFileSync(path.join(dir, 'live', 'signer-owner.token'), token);
}

test('hardening: the signer endpoint record is read only as the exact record the signer writes, naming this process\'s code identity', () => {
  const dir = testDir('endpoint');
  const client = new LiveSignerClient({ dataDirectory: dir, role: 'owner', fetchImpl: async () => { throw new Error('no network in this test'); } });
  writeEndpoint(dir, endpointRecord());
  assert.equal(client.approvalSha256(), 'a'.repeat(64));
  assert.equal(validSignerEndpoint(endpointRecord()), true);

  const refused = (record, reason, token) => {
    writeEndpoint(dir, record, token);
    assert.throws(() => client.approvalSha256(), error => error.code === 'SIGNER_UNAVAILABLE' && error.details.layer === 'signer' && error.details.reason === reason, JSON.stringify(record));
  };
  refused(endpointRecord({ codeIdentitySha256: 'f'.repeat(64) }), 'ENDPOINT_CODE_IDENTITY');
  const { codeIdentitySha256, ...withoutIdentity } = endpointRecord();
  refused(withoutIdentity, 'ENDPOINT_FORMAT');
  refused(endpointRecord({ extra: true }), 'ENDPOINT_FORMAT');
  refused(endpointRecord({ schemaVersion: 2 }), 'ENDPOINT_FORMAT');
  refused(endpointRecord({ port: 80 }), 'ENDPOINT_FORMAT');
  refused(endpointRecord({ pid: 0 }), 'ENDPOINT_FORMAT');
  refused(endpointRecord({ approvalSha256: 'A'.repeat(64) }), 'ENDPOINT_FORMAT');
  refused(endpointRecord({ notAfter: 'tomorrow' }), 'ENDPOINT_FORMAT');
  refused(endpointRecord({ startedAt: '2026-09-15T07:00:00Z' }), 'ENDPOINT_FORMAT');
  refused(endpointRecord(), 'ENDPOINT_FORMAT', 'not-a-token');
  refused([endpointRecord()], 'ENDPOINT_FORMAT');
  // A missing or unreadable file stays a plain unavailable signer.
  fs.writeFileSync(path.join(dir, 'live', 'signer-endpoint.json'), '{');
  assert.throws(() => client.approvalSha256(), error => error.code === 'SIGNER_UNAVAILABLE' && error.details.reason === undefined);
});

test('hardening: an endpoint record naming other source bytes stops owner setup with SIGNER_UNAVAILABLE and the reason, before anything is prepared', async () => {
  const env = environment();
  const fetchImpl = async () => { throw new Error('the signer must not be called'); };
  const { owner, run } = await ownerApproved(env, { signer: undefined, fetchImpl });
  writeEndpoint(env.dir, endpointRecord({ codeIdentitySha256: 'f'.repeat(64) }));
  await assert.rejects(owner.startOwnerSetup({ runId: run.runId }),
    error => error.code === 'SIGNER_UNAVAILABLE' && error.details?.layer === 'signer' && error.details?.reason === 'ENDPOINT_CODE_IDENTITY');
  assert.equal((await owner.signerStatus()).code, 'SIGNER_UNAVAILABLE');
  assert.equal(owner.view().runs[0].status, 'owner-approved');
});

// ---------------------------------------------------------------------------
// The x402 quote

test('hardening: a response with two different quotes, beside and inside the data envelope, stops the run with QUOTE_CONFLICT and nothing is signed', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  const transactionsBefore = env.chain.transactions.size;
  env.gateway.faults.prepare = ['QUOTE_CONFLICT'];
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = owner.view().runs[0];
  assert.equal(view.status, 'stopped');
  assert.equal(view.stop.code, 'QUOTE_CONFLICT', JSON.stringify(view.stop));
  assert.equal(env.gateway.entries.filter(entry => entry.type === 'signed').length, 0);
  assert.equal(view.steps.find(step => step.step === 'setAction').journalState, null);
  assert.equal(env.chain.transactions.size, transactionsBefore);
});

// ---------------------------------------------------------------------------
// The CI workflow

test('hardening: CI runs the suite on Windows with read-only repository access, SHA-pinned actions, no persisted credentials and no secrets', () => {
  const workflow = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.match(workflow, /^permissions:\n {2}contents: read$/m);
  assert.doesNotMatch(workflow, /write/);
  assert.doesNotMatch(workflow, /secrets\./);
  assert.match(workflow, /runs-on: windows-latest/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /- run: node tools\/check-demo\.mjs$/m);
  const uses = workflow.split('\n').filter(line => line.includes('uses:'));
  assert.ok(uses.length >= 2);
  for (const line of uses) assert.match(line, /uses: [a-z-]+\/[a-z-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/, line);
  const dependabot = fs.readFileSync(path.join(ROOT, '.github', 'dependabot.yml'), 'utf8');
  assert.match(dependabot, /package-ecosystem: github-actions/);
});

// ---------------------------------------------------------------------------
// The evidence export

async function completedAndFinal(env) {
  const { owner, run } = await ownerApproved(env);
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(owner.view().runs[0].status, 'awaiting-agent', JSON.stringify(owner.view().runs[0].stop));
  const agent = new BrickkenLiveWorkspace(env.dir, { role: 'agent', signer: env.gateway.client('agent'), ...env.common });
  let receipt;
  for (let attempt = 0; attempt < 15; attempt++) {
    receipt = await agent.agentExecute({ operationId: `${run.runId}_execute` });
    if (receipt.execute.status === 'verified') break;
  }
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(owner.view().runs[0].status, 'completed', JSON.stringify(owner.view().runs[0].stop));
  await env.sleep(40 * 12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, true);
  return { owner, run };
}
function exportEvidence(env, run, extra = []) {
  const output = path.relative(ROOT, path.join(ROOT, 'test-output', `hardening-export-${randomUUID().slice(0, 8)}`));
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'tools', 'export-live-evidence.mjs'), '--data', path.relative(ROOT, env.dir), '--run', run.runId, '--output', output, ...extra
  ], { cwd: ROOT, encoding: 'utf8', windowsHide: true });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, output: path.join(ROOT, output) };
}
function evidenceFile(env, run, name) { return path.join(env.dir, 'live', 'evidence', run.runId, `${name}.json`); }
function editEvidence(env, run, name, change) {
  const file = evidenceFile(env, run, name);
  const original = fs.readFileSync(file);
  const value = JSON.parse(original.toString('utf8'));
  change(value);
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
  return () => fs.writeFileSync(file, original);
}
// Nothing named after the target is left beside it: no package and no staging folder.
function leftovers(output) {
  const parent = path.dirname(output);
  const name = path.basename(output);
  return fs.readdirSync(parent).filter(entry => entry === name || entry.startsWith(`.${name}.partial-`));
}
function refusedCleanly(exported, schemaKind) {
  assert.notEqual(exported.status, 0);
  assert.match(exported.stderr, new RegExp(`outside the ${schemaKind} schema`));
  assert.doesNotMatch(exported.stderr, /synthetic|apiKey|authorization|leakedToken/i);
  assert.deepEqual(leftovers(exported.output), []);
}

test('hardening: every member of an exported package has a kind and passes its closed field schema, including the SHA-256 sums', async () => {
  const env = environment();
  const { run } = await completedAndFinal(env);
  const exported = exportEvidence(env, run);
  assert.equal(exported.status, 0, exported.stderr);
  const sums = JSON.parse(fs.readFileSync(path.join(exported.output, 'SHA256SUMS.json'), 'utf8'));
  assert.ok(Object.keys(sums).length >= 25);
  for (const [relative, digest] of Object.entries(sums)) {
    const bytes = fs.readFileSync(path.join(exported.output, ...relative.split('/')));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), digest, relative);
    const kind = evidenceKindOf(relative);
    assert.ok(EVIDENCE_SCHEMA_KINDS.includes(kind), relative);
    assert.deepEqual(fieldsOutsideSchema(kind, JSON.parse(bytes.toString('utf8'))), [], relative);
  }
  assert.deepEqual(fieldsOutsideSchema('sums', sums), []);
  assert.equal(JSON.parse(fs.readFileSync(path.join(exported.output, 'transactions.json'), 'utf8')).complete, true);
  assert.deepEqual(leftovers(exported.output), [path.basename(exported.output)]);
});

test('hardening: synthetic credential fields nested in an evidence member stop the export, and nothing of them is written or echoed (F06, probe P05)', async () => {
  const env = environment();
  const { run } = await completedAndFinal(env);
  // The review's probe: extra fields inside a nested array of a copied member.
  let restore = editEvidence(env, run, `${run.runId}_execute-preparation`, value => {
    value.extra = { nested: [{ apiKey: 'synthetic-api-key', authorization: 'Bearer synthetic' }] };
  });
  refusedCleanly(exportEvidence(env, run), 'step-preparation');
  restore();
  // The same fields hidden inside the API quote's own extra object.
  restore = editEvidence(env, run, `${run.runId}_grant-preparation`, value => {
    value.x402Quote[0].extra = { leakedToken: 'synthetic' };
  });
  refusedCleanly(exportEvidence(env, run), 'step-preparation');
  restore();
  // A field one level down in a control observation.
  restore = editEvidence(env, run, 'control-transaction-cap', value => { value.calls[0].result.authorization = 'synthetic'; });
  refusedCleanly(exportEvidence(env, run), 'control');
  restore();
  // The existing guard stays: a signedTransaction key anywhere stops the export.
  restore = editEvidence(env, run, 'finality', value => { value.entries[0].signedTransaction = '0x02f8'; });
  const signed = exportEvidence(env, run);
  assert.notEqual(signed.status, 0);
  assert.match(signed.stderr, /finality\.json would contain signed transaction bytes/);
  assert.deepEqual(leftovers(signed.output), []);
  restore();
  // The run approval is read under the same bounds as every other member: a second name stops the export.
  const secondName = path.join(env.dir, 'live', 'evidence', 'second-name-of-approval.json');
  fs.linkSync(evidenceFile(env, run, 'run-approval'), secondName);
  const linked = exportEvidence(env, run);
  assert.notEqual(linked.status, 0);
  assert.match(linked.stderr, /an evidence member is not a bounded regular file/);
  assert.deepEqual(leftovers(linked.output), []);
  fs.unlinkSync(secondName);
  // With every member restored the same run exports as complete.
  const clean = exportEvidence(env, run);
  assert.equal(clean.status, 0, clean.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(clean.output, 'transactions.json'), 'utf8')).complete, true);
});

test('hardening: the closed schema also covers the derived summary files and refuses a member path the package does not have', () => {
  assert.equal(evidenceKindOf('steps/execute-preparation.json'), 'step-preparation');
  assert.equal(evidenceKindOf('controls/control-after-revoke.json'), 'control');
  assert.equal(evidenceKindOf('replays/replay-1.json'), 'replay');
  assert.equal(evidenceKindOf('cleanup-reset-refused-1789482394000.json'), 'cleanup-reset-refused');
  for (const unknown of ['steps/transfer-preparation.json', 'controls/control-other.json', 'signer-log.json', '../run.json', 'replays/replay-0.json']) {
    assert.equal(evidenceKindOf(unknown), null, unknown);
  }
  assert.deepEqual(fieldsOutsideSchema('run', { schemaVersion: 1, stop: { code: 'X', details: { layer: 'signer', reason: 'ENDPOINT_FORMAT' } } }), []);
  assert.deepEqual(fieldsOutsideSchema('run', { stop: { details: { credential: 'synthetic' } } }), ['stop.details']);
  assert.deepEqual(fieldsOutsideSchema('run', { cleanup: { attribution: { approve: { attributed: true, reason: null, extra: 1 } } } }), ['cleanup.attribution.approve']);
  assert.deepEqual(fieldsOutsideSchema('transactions', { transactions: [{ step: 'grant', semanticVerification: { verifiedAt: 'x', token: 'y' } }] }), ['transactions[].semanticVerification']);
  assert.deepEqual(fieldsOutsideSchema('sums', { 'run.json': 'a'.repeat(64), 'signer-log.json': 'b'.repeat(64) }), ['(root)']);
  assert.deepEqual(fieldsOutsideSchema('step-preparation', [1]), ['(root)']);
  // A key that spells a listed path by itself is not that path.
  assert.deepEqual(fieldsOutsideSchema('control', { 'block.hash': 'synthetic' }), ['(root)']);
  assert.deepEqual(fieldsOutsideSchema('control', { 'calls[]': { label: 'synthetic' } }), ['(root)']);
  assert.deepEqual(fieldsOutsideSchema('control', { calls: [{ 'result.ok': true }] }), ['calls[]']);
  assert.deepEqual(fieldsOutsideSchema('control', { '': 1 }), ['(root)']);
});
