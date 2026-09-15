// Acceptance tests for the Codex re-check of fix round 3 (astra/md/MANDATE-DESK-
// LIVE-AUDIT-A1-CODEX-ROUND-3-RECHECK-2026-09-15.md, 2026-09-15). R3-F01: the
// controls a write rests on are read from both sources inside #sign, after the
// last nonce reads and right before signer.sign, for execute, revoke and
// approveReset. R3-F02: the allowance on chain is reset by cleanup only when the
// Approval history of the owner and spender pair on both sources attributes it
// to the run's own approve, so a later independent approval of the same amount
// is left in place, and the origin is read again right before the reset is signed
// (ADV4-B3). 5.4: the recording binding names the package's own finality
// reading time apart from the run's current one. Every test states the corrected
// behaviour and fails on the tree the re-check audited. Everything runs on the
// in-memory FakeSepolia harness with public Hardhat test keys: no network, no
// real key, no chain write.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import { MAX_LOG_BLOCKS } from '../src/brickken-rpc.mjs';
import { EVENT_TOPICS } from '../src/brickken-postcheck.mjs';
import { ROOT } from '../src/store.mjs';
import { BrickkenLiveWorkspace } from '../src/brickken-workspace.mjs';
import { LiveBrickkenJournal } from '../src/brickken-journal.mjs';
import { loadLiveProposal } from '../src/brickken-live-plan.mjs';
import { FakeRpc, FakeSepolia, FakeSignerGateway, createClock } from './live-fakes.mjs';

// ---------------------------------------------------------------------------
// Harness (the same shape as test/brickken-live-round2-recheck.test.mjs)

function testDir(name = 'r3') {
  fs.mkdirSync(path.join(ROOT, 'test-output'), { recursive: true });
  return fs.mkdtempSync(path.join(ROOT, 'test-output', `fable-r3-${name}-`));
}
function environment() {
  const proposal = loadLiveProposal();
  const clock = createClock();
  const chain = new FakeSepolia({ proposal, clock });
  const rpcs = { primary: new FakeRpc(chain, 'primary'), secondary: new FakeRpc(chain, 'secondary') };
  const gateway = new FakeSignerGateway({ chain, proposal, clock });
  const dir = testDir();
  const sleep = async ms => { clock.ms += ms; chain.advanceTo(clock.ms); };
  const common = { rpcs, now: () => clock.ms, sleep, pollMs: 5000, verifySignedTransaction: gateway.verify };
  return { proposal, clock, chain, rpcs, gateway, dir, common, sleep };
}
function ownerOf(env, overrides = {}) {
  return new BrickkenLiveWorkspace(env.dir, { role: 'owner', signer: env.gateway.client('owner'), ...env.common, ...overrides });
}

test('round5: fake event history applies the same inclusive range limit as the RPC client', async () => {
  const env = environment();
  const filter = { address: env.proposal.token.address, topics: [EVENT_TOPICS.Approval], fromBlock: '1', toBlock: MAX_LOG_BLOCKS.toString() };
  for (const rpc of Object.values(env.rpcs)) {
    assert.deepEqual(await rpc.getLogs(filter), []);
    await assert.rejects(rpc.getLogs({ ...filter, toBlock: (MAX_LOG_BLOCKS + 1n).toString() }), { code: 'INPUT_INVALID' });
    await assert.rejects(rpc.getLogs({ ...filter, fromBlock: '2', toBlock: '1' }), { code: 'INPUT_INVALID' });
  }
});
function agentOf(env, overrides = {}) {
  return new BrickkenLiveWorkspace(env.dir, { role: 'agent', signer: env.gateway.client('agent'), ...env.common, ...overrides });
}
async function ownerApproved(env) {
  const owner = ownerOf(env);
  const { run, approval } = await owner.prepareRun();
  env.gateway.setApproval(approval);
  owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: run.codeIdentitySha256 });
  return { owner, run, approval };
}
async function setupToAwaitingAgent(env) {
  const { owner, run, approval } = await ownerApproved(env);
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = owner.view().runs[0];
  assert.equal(view.status, 'awaiting-agent', JSON.stringify(view.stop));
  return { owner, run, approval };
}
async function driveAgentExecute(agent, operationId, attempts = 15) {
  let receipt;
  for (let i = 0; i < attempts; i++) {
    receipt = await agent.agentExecute({ operationId });
    if (receipt.execute.status === 'verified') return receipt;
  }
  return receipt;
}
async function executeVerified(env, run) {
  const receipt = await driveAgentExecute(agentOf(env), opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
}
async function completeRun(env) {
  const { owner, run, approval } = await setupToAwaitingAgent(env);
  await executeVerified(env, run);
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(owner.view().runs[0].status, 'completed', JSON.stringify(owner.view().runs[0].stop));
  return { owner, run, approval };
}
const opId = (run, step) => `${run.runId}_${step}`;
const journalOf = env => new LiveBrickkenJournal({ directory: path.join(env.dir, 'live', 'journal') });
const runView = owner => owner.view().runs[0];
const controlView = (owner, id) => runView(owner).controls.find(item => item.id === id);
const signedCount = (env, step) => env.gateway.entries.filter(entry => entry.type === 'signed' && entry.step === step).length;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const CONTROL_OF = { execute: 'control-transaction-cap', revoke: 'control-before-revoke', approveReset: 'control-after-revoke' };
function evidence(env, run, name) {
  const file = path.join(env.dir, 'live', 'evidence', run.runId, `${name}.json`);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null;
}
function exportEvidence(env, run, allowIncomplete = false) {
  const output = path.relative(ROOT, path.join(ROOT, 'test-output', `fable-r3-export-${randomUUID().slice(0, 8)}`));
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'tools', 'export-live-evidence.mjs'), '--data', path.relative(ROOT, env.dir), '--run', run.runId, '--output', output,
    ...(allowIncomplete ? ['--allow-incomplete'] : [])
  ], { cwd: ROOT, encoding: 'utf8', windowsHide: true });
  return { status: result.status, stderr: result.stderr, output: path.join(ROOT, output), relative: output.split(path.sep).join('/') };
}
// The re-check's technique: the preparation of the step is already recorded as
// pending, so the next nonce read for the step's signer is the one inside #sign,
// after the pending-case checks. The chain tip, which the most recent control
// observation rests on, is replaced there (R3-F01).
function actOnLastNonceRead(env, run, step, act) {
  const rpc = env.rpcs.primary;
  const real = rpc.getTransactionCount.bind(rpc);
  const journal = journalOf(env);
  let fired = 0;
  rpc.getTransactionCount = async (address, tag) => {
    const record = journal.find(opId(run, step));
    if (fired === 0 && record?.state === 'pending' && address === record.transaction.from) { fired += 1; act(); }
    return real(address, tag);
  };
  return () => fired;
}
// A later, independent approval by the principal to the same executor, mined
// on the fake chain outside the run's journal.
function mineForeignApproval(env, run, allowance) {
  const prior = journalOf(env).get(opId(run, 'approve')).transaction;
  const foreign = { ...prior, nonce: env.chain.state.nonce[env.proposal.principal].toString(), data: prior.data.slice(0, 74) + allowance.toString(16).padStart(64, '0') };
  const bytes = '0xfade' + randomUUID().replaceAll('-', '').slice(0, 8);
  const hash = '0x' + sha256(Buffer.from(bytes)).slice(0, 64);
  env.chain.register(bytes, foreign, hash);
  env.chain.accept(bytes);
  env.chain.mine();
  assert.equal(env.chain.transactions.get(hash).receipt.status, 1);
  assert.equal(env.chain.state.allowance, allowance);
  return hash;
}

// ---------------------------------------------------------------------------
// R3-F01: the controls are read again inside #sign, after the last nonce reads

test('R3-F01: a control block reorganised during the last nonce read before the execute signature withdraws the control and signs nothing; the earlier prepare-time case still holds; the owner observes it again and the retry signs', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const before = controlView(owner, CONTROL_OF.execute);
  const fired = actOnLastNonceRead(env, run, 'execute', () => {
    assert.equal(String(env.chain.latest().number), before.blockNumber);
    env.chain.reorg(1);
  });
  const agent = agentOf(env);
  await assert.rejects(agent.agentExecute({ operationId: opId(run, 'execute') }), { code: 'CONTROL_WITHDRAWN' });
  assert.equal(fired(), 1);
  assert.equal(signedCount(env, 'execute'), 0);
  const record = journalOf(env).get(opId(run, 'execute'));
  assert.equal(record.state, 'pending');
  assert.equal(record.signed, null);
  assert.equal(controlView(owner, CONTROL_OF.execute).canonical, false);
  assert.equal(runView(owner).phase, 'owner-setup');
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'awaiting-agent', JSON.stringify(runView(owner).stop));
  assert.notEqual(controlView(owner, CONTROL_OF.execute).blockHash, before.blockHash);
  const receipt = await driveAgentExecute(agent, opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  assert.equal(signedCount(env, 'execute'), 1);
});

test('round5: a stopped run retains ALLOWANCE_NOT_ZERO until its own cleanup, then a new plan has no allowance blocker', async () => {
  const env = environment();
  env.gateway.faults.prepare.push(null, 'PAYMENT_REQUIRED');
  const { owner, run } = await ownerApproved(env);
  await owner.startOwnerSetup({ runId: run.runId });await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'stopped');
  assert.equal(env.chain.state.allowance, 15000n);assert.equal(signedCount(env, 'grant'), 0);
  const isolated = ownerOf({ ...env, dir: testDir('new-plan') });
  const blocked = await isolated.prepareRun();
  assert.ok(blocked.run.preflightBlockers.some(item => item.code === 'ALLOWANCE_NOT_ZERO'));
  await owner.startCleanup({ runId: run.runId });await owner.whenIdle(run.runId);
  assert.equal(env.chain.state.allowance, 0n);assert.equal(signedCount(env, 'approveReset'), 1);
  const next = await owner.prepareRun();assert.equal(next.run.preflightBlockers.length, 0);
});

test('round5: unfinished cleanup exports both origin observations and its refusal in SHA256SUMS, without claiming completeness', async () => {
  const env = environment(), { owner, run } = await setupToAwaitingAgent(env);
  actOnLastNonceRead(env, run, 'approveReset', () => mineForeignApproval(env, run, 15000n));
  await owner.startCleanup({ runId: run.runId });await owner.whenIdle(run.runId);
  const exported = exportEvidence(env, run, true);assert.equal(exported.status, 0, exported.stderr);
  const sums = JSON.parse(fs.readFileSync(path.join(exported.output, 'SHA256SUMS.json'), 'utf8'));
  const names = Object.keys(sums).filter(name => name.startsWith('cleanup-allowance-origin') || name.startsWith('cleanup-reset-refused-'));
  assert.equal(names.length, 3);
  for (const name of names) assert.equal(sha256(fs.readFileSync(path.join(exported.output, name))), sums[name]);
  const record = JSON.parse(fs.readFileSync(path.join(exported.output, 'run.json'), 'utf8'));
  assert.equal(record.complete, false);assert.equal(record.stop.details.originReason, 'FOREIGN_APPROVAL');
  assert.equal(env.chain.state.allowance, 15000n);assert.equal(signedCount(env, 'approveReset'), 0);
  // A matching filename must still be a regular JSON file, never a directory.
  fs.mkdirSync(path.join(env.dir, 'live', 'evidence', run.runId, 'cleanup-reset-refused-123.json'));
  assert.notEqual(exportEvidence(env, run, true).status, 0);
});

test('round5: the documented second execute call supplies the page replay scene without signing; general package binding works before and after it', async () => {
  const env = environment(), { owner, run } = await completeRun(env);
  await env.sleep(40 * 12 * 1000);await owner.refreshFinality({ runId: run.runId });
  assert.equal(runView(owner).replays.length, 0);
  const initial = exportEvidence(env, run);assert.equal(initial.status, 0, initial.stderr);
  assert.ok(owner.recordingBinding(run.runId, { packageDirectory: initial.relative }));
  const copy = JSON.parse(fs.readFileSync(path.join(ROOT, 'public/live-demo-copy.json'), 'utf8'));
  const element = { getContext: () => new Proxy({}, { get: (_target, name) => name === 'measureText' ? () => ({ width: 0 }) : () => {} }), addEventListener() {} };
  const context = vm.createContext({ document: { getElementById: () => ({ ...element }) }, fetch: async url => ({ ok: false, json: async () => url === '/live-demo-copy.json' ? copy : {} }) });
  const script = fs.readFileSync(path.join(ROOT, 'public/live-demo.mjs'), 'utf8');
  const buildScenes = await vm.runInContext(`(async () => { ${script}\nreturn buildScenes; })()`, context);
  assert.ok(buildScenes(runView(owner), owner.view().proposal).missing.includes(copy.missing.replay));
  const signedBefore = env.gateway.entries.filter(entry => entry.type === 'signed').length;
  const nonceBefore = env.chain.state.nonce[env.proposal.agent];
  const replay = await agentOf(env).agentExecute({ operationId: opId(run, 'execute') });
  assert.ok(replay);assert.equal(env.gateway.entries.filter(entry => entry.type === 'signed').length, signedBefore);
  assert.equal(env.chain.state.nonce[env.proposal.agent], nonceBefore);
  assert.equal(runView(owner).replays.at(-1).passed, true);
  assert.equal(buildScenes(runView(owner), owner.view().proposal).scenes.length, 10);
  const after = exportEvidence(env, run);assert.equal(after.status, 0, after.stderr);
  assert.ok(owner.recordingBinding(run.runId, { packageDirectory: after.relative }));
});

test('R3-F01: the pre-revocation controls reorganised during the last nonce read before the revoke signature stop the revocation with no signature and a pending record; the resumed owner observes them again and completes', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  await executeVerified(env, run);
  let before = null;
  const fired = actOnLastNonceRead(env, run, 'revoke', () => {
    before = controlView(owner, CONTROL_OF.revoke);
    assert.equal(String(env.chain.latest().number), before.blockNumber);
    env.chain.reorg(1);
  });
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const stopped = runView(owner);
  assert.equal(fired(), 1);
  assert.equal(stopped.status, 'stopped');
  assert.equal(stopped.stop.code, 'CONTROL_WITHDRAWN', JSON.stringify(stopped.stop));
  assert.equal(stopped.phase, 'owner-revocation');
  assert.equal(signedCount(env, 'revoke'), 0);
  const record = journalOf(env).get(opId(run, 'revoke'));
  assert.equal(record.state, 'pending');
  assert.equal(record.signed, null);
  // Both pre-revocation controls rest on the replaced block; the first one read
  // is withdrawn and stops the phase, the other is withdrawn by the resume's recheck.
  assert.ok(['control-cumulative-cap', 'control-before-revoke'].some(id => controlView(owner, id).canonical === false));
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'completed', JSON.stringify(runView(owner).stop));
  assert.notEqual(controlView(owner, CONTROL_OF.revoke).blockHash, before.blockHash);
  assert.ok(runView(owner).controls.every(item => item.observed && item.passed && item.canonical === true));
  assert.equal(signedCount(env, 'revoke'), 1);
  assert.equal(signedCount(env, 'approveReset'), 1);
});

test('R3-F01: the revocation control reorganised during the last nonce read before the approve reset signature stops the phase with no reset signature; the verified revoke stays, and the resumed owner observes the control again and completes', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  await executeVerified(env, run);
  let before = null;
  const fired = actOnLastNonceRead(env, run, 'approveReset', () => {
    before = controlView(owner, CONTROL_OF.approveReset);
    assert.equal(String(env.chain.latest().number), before.blockNumber);
    env.chain.reorg(1);
  });
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const stopped = runView(owner);
  assert.equal(fired(), 1);
  assert.equal(stopped.stop.code, 'CONTROL_WITHDRAWN', JSON.stringify(stopped.stop));
  assert.equal(stopped.phase, 'owner-revocation');
  assert.equal(signedCount(env, 'revoke'), 1);
  assert.equal(signedCount(env, 'approveReset'), 0);
  assert.equal(journalOf(env).get(opId(run, 'revoke')).state, 'semantically_verified');
  assert.equal(journalOf(env).get(opId(run, 'approveReset')).state, 'pending');
  assert.equal(controlView(owner, CONTROL_OF.approveReset).canonical, false);
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'completed', JSON.stringify(runView(owner).stop));
  assert.notEqual(controlView(owner, CONTROL_OF.approveReset).blockHash, before.blockHash);
  assert.equal(signedCount(env, 'revoke'), 1);
  assert.equal(signedCount(env, 'approveReset'), 1);
});

test('R3-F01: a source that has no block at the control height during the last nonce read leaves the execute unresolved and unsigned, and the retry signs once the source answers', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const control = controlView(owner, CONTROL_OF.execute);
  actOnLastNonceRead(env, run, 'execute', () => {
    env.rpcs.secondary.faults.hideBlock = block => String(block.number) === control.blockNumber;
  });
  const agent = agentOf(env);
  await assert.rejects(agent.agentExecute({ operationId: opId(run, 'execute') }), { code: 'CONTROL_UNRESOLVED' });
  assert.equal(signedCount(env, 'execute'), 0);
  assert.equal(journalOf(env).get(opId(run, 'execute')).state, 'pending');
  assert.equal(controlView(owner, CONTROL_OF.execute).canonical, true);
  assert.equal(runView(owner).phase, 'agent-execute');
  env.rpcs.secondary.faults.hideBlock = null;
  const receipt = await driveAgentExecute(agent, opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  assert.equal(signedCount(env, 'execute'), 1);
});

// ---------------------------------------------------------------------------
// R3-F02: the allowance's origin is read from the Approval history on both sources

test('R3-F02: a later independent approval of the same amount is not reset by cleanup: the Approval history on both sources shows a transaction the run did not sign, the value stays, and the origin evidence names it', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const own = journalOf(env).get(opId(run, 'approve'));
  const value = env.chain.state.allowance;
  const foreignHash = mineForeignApproval(env, run, value);
  assert.notEqual(foreignHash, own.signed.ethereumTransactionHash);
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.stop.code, 'CLEANUP_UNATTRIBUTED_ALLOWANCE', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.stop.details.originReason, 'FOREIGN_APPROVAL');
  assert.equal(cleaned.stop.details.allowance, value.toString());
  assert.equal(cleaned.stop.details.expectedFromRun, value.toString());
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, false);
  assert.deepEqual(cleaned.cleanup.problems, ['CLEANUP_UNATTRIBUTED_ALLOWANCE']);
  assert.equal(env.chain.state.allowance, value);
  assert.equal(signedCount(env, 'approveReset'), 0);
  assert.equal(cleaned.cleanup.revokedByCleanup, true);
  const origin = evidence(env, run, 'cleanup-allowance-origin');
  assert.equal(origin.attributed, false);
  assert.equal(origin.reason, 'FOREIGN_APPROVAL');
  assert.deepEqual(origin.foreign.map(item => item.transactionHash), [foreignHash]);
  assert.equal(origin.events.primary.length, 2);
  assert.deepEqual(origin.events.primary, origin.events.secondary);
});

test('R3-F02: the run\'s own allowance is attributed by its own Approval event and reset: after a verified execute the remaining value is reset, and the origin evidence shows only the run\'s transaction and the principal nonce on both sources', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  await executeVerified(env, run);
  const own = journalOf(env).get(opId(run, 'approve'));
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.stop, null, JSON.stringify(cleaned.stop));
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, true);
  assert.equal(env.chain.state.allowance, 0n);
  assert.equal(signedCount(env, 'approveReset'), 1);
  const origin = evidence(env, run, 'cleanup-allowance-origin');
  assert.equal(origin.attributed, true);
  assert.equal(origin.reason, null);
  assert.deepEqual(origin.events.primary.map(item => item.transactionHash), [own.signed.ethereumTransactionHash]);
  assert.equal(origin.events.primary[0].blockHash, own.confirmation.blockHash);
  assert.equal(origin.principalNonce.primary, origin.principalNonce.secondary);
});

test('R3-F02: a source that cannot answer the history, or two sources that disagree on it, leave the allowance in place and name the reason', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const value = env.chain.state.allowance;
  env.rpcs.secondary.faults.logsError = 'RPC_ERROR';
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const unavailable = runView(owner);
  assert.equal(unavailable.stop.code, 'CLEANUP_UNATTRIBUTED_ALLOWANCE', JSON.stringify(unavailable.stop));
  assert.equal(unavailable.stop.details.originReason, 'HISTORY_UNAVAILABLE');
  assert.equal(env.chain.state.allowance, value);
  assert.equal(signedCount(env, 'approveReset'), 0);
  assert.equal(evidence(env, run, 'cleanup-allowance-origin').error, 'RPC_ERROR');

  // The second source hides the block of the run's own approve, so its history
  // lacks the event the first source returns.
  env.rpcs.secondary.faults.logsError = null;
  const ownBlock = journalOf(env).get(opId(run, 'approve')).confirmation.blockNumber;
  env.rpcs.secondary.faults.hideBlock = block => String(block.number) === ownBlock;
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const disagreeing = runView(owner);
  assert.equal(disagreeing.stop.code, 'CLEANUP_UNATTRIBUTED_ALLOWANCE', JSON.stringify(disagreeing.stop));
  assert.equal(disagreeing.stop.details.originReason, 'SOURCE_HISTORY_DISAGREEMENT');
  assert.equal(env.chain.state.allowance, value);
  assert.equal(signedCount(env, 'approveReset'), 0);

  // Both sources answering the same history attribute the value and the reset follows.
  env.rpcs.secondary.faults.hideBlock = null;
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).stop, null, JSON.stringify(runView(owner).stop));
  assert.equal(env.chain.state.allowance, 0n);
  assert.equal(signedCount(env, 'approveReset'), 1);
});

test('ADV4-B3: an independent approval mined after the cleanup decision and before the reset signature is not wiped: the origin is read again right before the signature, the reset is not signed, and the value stays', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const value = env.chain.state.allowance;
  const foreign = value + 4242n;
  let foreignHash = null;
  // The decision read happened and the reset preparation is pending. A later
  // approval by the principal lands at its last nonce read; that also consumes
  // the nonce the preparation carried, so the reset is prepared again and the
  // origin is read again right before the signature of the fresh preparation.
  const fired = actOnLastNonceRead(env, run, 'approveReset', () => { foreignHash = mineForeignApproval(env, run, foreign); });
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(fired(), 1);
  assert.equal(cleaned.status, 'stopped');
  assert.equal(cleaned.stop.code, 'CLEANUP_UNATTRIBUTED_ALLOWANCE', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.stop.details.originReason, 'FOREIGN_APPROVAL');
  assert.equal(cleaned.stop.details.allowance, foreign.toString());
  assert.equal(signedCount(env, 'approveReset'), 0);
  assert.equal(journalOf(env).get(opId(run, 'approveReset')).state, 'pending');
  assert.equal(env.chain.state.allowance, foreign);
  const decision = evidence(env, run, 'cleanup-allowance-origin');
  const atSign = evidence(env, run, 'cleanup-allowance-origin-sign');
  assert.equal(decision.attributed, true);
  assert.equal(atSign.attributed, false);
  assert.deepEqual(atSign.foreign.map(item => item.transactionHash), [foreignHash]);
  assert.ok(BigInt(atSign.block.number) > BigInt(decision.block.number));
  // The refusal itself is kept as evidence, because the next attempt clears run.stop (ADV4b-1).
  const refusals = fs.readdirSync(path.join(env.dir, 'live', 'evidence', run.runId)).filter(name => name.startsWith('cleanup-reset-refused-'));
  assert.equal(refusals.length, 1);
  const refusal = JSON.parse(fs.readFileSync(path.join(env.dir, 'live', 'evidence', run.runId, refusals[0]), 'utf8'));
  assert.equal(refusal.code, 'CLEANUP_UNATTRIBUTED_ALLOWANCE');
  assert.equal(refusal.originReason, 'FOREIGN_APPROVAL');
  // The mandate revoke of the same cleanup was signed before the reset and stays verified.
  assert.equal(signedCount(env, 'revoke'), 1);
  assert.equal(journalOf(env).get(opId(run, 'revoke')).state, 'semantically_verified');
});

// ---------------------------------------------------------------------------
// 5.4: the binding names the package's own finality reading time apart from the run's

test('5.4: a later finality reading with the same statement keeps the package bound, and the binding carries the run\'s reading time and the package\'s reading time as two values', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  await env.sleep(40 * 12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, true);
  const exported = exportEvidence(env, run);
  assert.equal(exported.status, 0, exported.stderr);
  const packageRun = JSON.parse(fs.readFileSync(path.join(exported.output, 'run.json'), 'utf8'));
  const first = owner.recordingBinding(run.runId, { packageDirectory: exported.relative });
  assert.equal(first.finality.packageCheckedAt, packageRun.finality.checkedAt);
  assert.equal(first.finality.checkedAt, packageRun.finality.checkedAt);
  await env.sleep(12 * 1000);
  const later = await owner.refreshFinality({ runId: run.runId });
  assert.equal(later.allFinalized, true);
  assert.notEqual(later.checkedAt, packageRun.finality.checkedAt);
  const second = owner.recordingBinding(run.runId, { packageDirectory: exported.relative });
  assert.equal(second.evidencePackage.sha256sumsSha256, first.evidencePackage.sha256sumsSha256);
  assert.equal(second.finality.checkedAt, later.checkedAt);
  assert.equal(second.finality.packageCheckedAt, packageRun.finality.checkedAt);
  assert.notEqual(second.finality.checkedAt, second.finality.packageCheckedAt);
  assert.deepEqual(runView(owner).finality.entries, packageRun.finality.entries);
});
