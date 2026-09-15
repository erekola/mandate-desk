// Acceptance tests for the A1 live audit findings (astra/md/MANDATE-DESK-LIVE-
// AUDIT-A1-RESPONSE.md, 2026-09-14). Each finding's reproduction from that audit
// is turned around here: the test states the corrected behaviour, fails on the
// audited source and passes on the fixed one. Everything runs on the in-memory
// FakeSepolia harness with public Hardhat test keys: no network, no real keys,
// no chain write. Lock tests spawn real child processes for a live, a crashed
// and a racing holder.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { once } from 'node:events';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { Readable } from 'node:stream';
import { ROOT, Store } from '../src/store.mjs';
import { createApp } from '../src/server.mjs';
import { BrickkenLiveWorkspace } from '../src/brickken-workspace.mjs';
import { LiveBrickkenJournal } from '../src/brickken-journal.mjs';
import { loadLiveProposal, buildRunApproval, facadeBody, expectedCalldata, stepSignerAddress, stepTarget, validateRunApproval } from '../src/brickken-live-plan.mjs';
import { sha256Canonical } from '../src/brickken-intent.mjs';
import { saveDemoRecording } from '../src/demo-recording.mjs';
import { evaluateLiveRunCompleteness } from '../src/brickken-live-completeness.mjs';
import { BROADCAST_ATTEMPT_WINDOW_MS, MAX_BROADCAST_ATTEMPTS_PER_WINDOW, broadcastBackoffUntil } from '../src/brickken-live-adapter.mjs';
import {
  MAX_PREPARE_ATTEMPTS, MAX_SEND_ATTEMPTS, PREPARE_ATTEMPT_WINDOW_MS, SEND_ATTEMPT_WINDOW_MS, authorizePrepare, authorizeSend
} from '../src/brickken-live-signer.mjs';
import { LIVE_LOCK_KIND, LiveLockError, acquireLiveLock, exclusiveOpenSupported, readLockHolder } from '../src/live-lock.mjs';
import { stableCodeIdentitySha256 } from '../src/code-identity.mjs';
import { FakeRpc, FakeSepolia, FakeSignerGateway, createClock } from './live-fakes.mjs';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const CHILD = path.join(ROOT, 'test', 'helpers', 'live-lock-child.mjs');

// ---------------------------------------------------------------------------
// Harness

function testDir(name = 'live-recovery') {
  fs.mkdirSync(path.join(ROOT, 'test-output'), { recursive: true });
  return fs.mkdtempSync(path.join(ROOT, 'test-output', `fable-a1-${name}-`));
}
function environment(chainOverrides = {}) {
  const proposal = loadLiveProposal();
  const clock = createClock();
  const chain = new FakeSepolia({ proposal, clock, ...chainOverrides });
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
function agentOf(env, overrides = {}) {
  return new BrickkenLiveWorkspace(env.dir, { role: 'agent', signer: env.gateway.client('agent'), ...env.common, ...overrides });
}
// A restarted signer process shares only its persisted entries and the approval.
function restart(env, approval) {
  const gateway = new FakeSignerGateway({ chain: env.chain, proposal: env.proposal, clock: env.clock });
  gateway.entries = env.gateway.entries;
  gateway.counter = env.gateway.counter;
  gateway.setApproval(approval);
  const common = { ...env.common, verifySignedTransaction: gateway.verify };
  return {
    gateway,
    owner: new BrickkenLiveWorkspace(env.dir, { role: 'owner', signer: gateway.client('owner'), ...common }),
    agent: new BrickkenLiveWorkspace(env.dir, { role: 'agent', signer: gateway.client('agent'), ...common })
  };
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
async function completeRun(env) {
  const { owner, run, approval } = await setupToAwaitingAgent(env);
  const receipt = await driveAgentExecute(agentOf(env), opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(owner.view().runs[0].status, 'completed', JSON.stringify(owner.view().runs[0].stop));
  return { owner, run, approval };
}
const opId = (run, step) => `${run.runId}_${step}`;
const journalOf = env => new LiveBrickkenJournal({ directory: path.join(env.dir, 'live', 'journal') });
const runView = owner => owner.view().runs[0];
const stepView = (owner, step) => runView(owner).steps.find(item => item.step === step);
const controlView = (owner, id) => runView(owner).controls.find(item => item.id === id);
const signedCount = (env, step) => env.gateway.entries.filter(entry => entry.type === 'signed' && entry.step === step).length;
const sendAttempts = (env, step) => env.gateway.entries.filter(entry => entry.type === 'send-attempt' && entry.step === step);
const minedCount = (env, predicate) => [...env.chain.transactions.values()].filter(item => predicate(item.tx)).length;
const approveTxs = env => minedCount(env, tx => tx.to === env.proposal.token.address && tx.data.startsWith('0x095ea7b3'));
const agentTxs = env => minedCount(env, tx => tx.from === env.proposal.agent);
// The largest number of attempt times inside any window of the given length.
function maxInWindow(times, windowMs) {
  const sorted = times.map(at => Date.parse(at)).sort((a, b) => a - b);
  return sorted.reduce((best, start) => Math.max(best, sorted.filter(t => t >= start && t < start + windowMs).length), 0);
}
function evidence(env, run, name) {
  return JSON.parse(fs.readFileSync(path.join(env.dir, 'live', 'evidence', run.runId, `${name}.json`), 'utf8'));
}
function rewriteWorkspace(env, change) {
  const file = path.join(env.dir, 'live', 'live-workspace.json');
  const state = JSON.parse(fs.readFileSync(file, 'utf8'));
  change(state);
  state.selfHash = sha256Canonical({ schemaVersion: state.schemaVersion, kind: state.kind, proposalHash: state.proposalHash, runs: state.runs });
  fs.writeFileSync(file, JSON.stringify(state, null, 2));
}
function deadPid() {
  return spawnSync(process.execPath, ['-e', '0'], { windowsHide: true }).pid;
}
function staleRecord(pid) {
  return { kind: LIVE_LOCK_KIND, ownerId: randomUUID(), pid, at: '2026-09-14T00:00:00.000Z', purpose: 'crashed-holder' };
}
function child(mode, file, argument) {
  const process_ = spawn(process.execPath, [CHILD, mode, file, String(argument ?? '')], { windowsHide: true, stdio: ['ignore', 'pipe', 'inherit'] });
  let output = '';
  const lines = [];
  const waiters = [];
  process_.stdout.on('data', chunk => {
    output += chunk;
    const parts = output.split('\n'); output = parts.pop();
    for (const line of parts) { lines.push(line); for (const waiter of waiters.splice(0)) waiter(); }
  });
  const exit = new Promise(resolve => process_.on('exit', code => { if (output) lines.push(output); resolve(code); }));
  const waitFor = text => new Promise(resolve => {
    const check = () => { if (lines.some(line => line.includes(text))) resolve(); else waiters.push(check); };
    check();
  });
  return { pid: process_.pid, lines, exit, waitFor };
}

// ---------------------------------------------------------------------------
// A1-F01: attempt budgets are windows, not lifetime caps

test('A1-F01: a long RPC outage on approve stops with a resumable code, keeps one signature, and a restarted owner finishes the same hash once the network returns', async () => {
  const env = environment();
  const { owner, run, approval } = await ownerApproved(env);
  const sends = [];
  const original = env.rpcs.primary.sendRawTransaction.bind(env.rpcs.primary);
  env.rpcs.primary.sendRawTransaction = async bytes => { sends.push(env.clock.ms); return original(bytes); };
  env.rpcs.primary.faults.sendErrors = Array(12).fill('RPC_TIMEOUT');

  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const stopped = runView(owner);
  assert.equal(stopped.status, 'stopped');
  assert.equal(stopped.stop.code, 'STEP_TIMEOUT', JSON.stringify(stopped.stop));
  assert.equal(stopped.stop.details.step, 'approve');
  const journal = journalOf(env);
  const before = journal.get(opId(run, 'approve'));
  assert.equal(before.state, 'uncertain');
  assert.ok(before.broadcast.attempts >= MAX_BROADCAST_ATTEMPTS_PER_WINDOW + 1, `attempts ${before.broadcast.attempts}`);
  assert.ok(before.broadcast.attempts <= 12);
  assert.equal(sends.length, before.broadcast.attempts);
  // The budget holds per window: never more than five identical resends in fifteen minutes.
  assert.ok(maxInWindow(before.broadcast.attemptsAt, BROADCAST_ATTEMPT_WINDOW_MS) <= MAX_BROADCAST_ATTEMPTS_PER_WINDOW);
  assert.equal(signedCount(env, 'approve'), 1);
  assert.equal(approveTxs(env), 0);

  // The network returns and a fresh process resumes the same run.
  env.rpcs.primary.faults.sendErrors = [];
  const { owner: owner2, gateway: gateway2 } = restart(env, approval);
  await owner2.resumeRun({ runId: run.runId });
  await owner2.whenIdle(run.runId);
  assert.equal(runView(owner2).status, 'awaiting-agent', JSON.stringify(runView(owner2).stop));
  const after = journal.get(opId(run, 'approve'));
  assert.equal(after.state, 'semantically_verified');
  assert.equal(after.signed.ethereumTransactionHash, before.signed.ethereumTransactionHash);
  assert.equal(after.signed.signedTransaction, before.signed.signedTransaction);
  assert.equal(after.broadcast.attempts, before.broadcast.attempts + 1);
  assert.equal(signedCount(env, 'approve'), 1);
  assert.equal(approveTxs(env), 1);

  // Cleanup and a later run work only after the earlier transaction was resolved, and they do work.
  await owner2.startCleanup({ runId: run.runId });
  await owner2.whenIdle(run.runId);
  assert.equal(runView(owner2).status, 'stopped');
  assert.equal(runView(owner2).cleanup.allowance, '0');
  assert.equal(runView(owner2).cleanup.mandateRevoked, true);
  // A new approval means a new signer log; the fake gateway's txId counter is per instance and is carried over
  // because a real Brickken account never reuses a preparation id (see the restart test in brickken-live-workspace).
  const gateway3 = new FakeSignerGateway({ chain: env.chain, proposal: env.proposal, clock: env.clock });
  gateway3.counter = Math.max(env.gateway.counter, gateway2.counter);
  const owner3 = new BrickkenLiveWorkspace(env.dir, { role: 'owner', signer: gateway3.client('owner'), ...env.common, verifySignedTransaction: gateway3.verify });
  const fresh = await owner3.prepareRun();
  gateway3.setApproval(fresh.approval);
  owner3.approveRun({ runId: fresh.run.runId, approvalSha256: fresh.approval.approvalSha256, codeIdentitySha256: fresh.run.codeIdentitySha256 });
  await owner3.startOwnerSetup({ runId: fresh.run.runId });
  await owner3.whenIdle(fresh.run.runId);
  const next = owner3.view().runs.find(item => item.runId === fresh.run.runId);
  // The earlier transaction is resolved, so the later run's owner writes are no longer blocked by it.
  assert.notEqual(next.stop?.code, 'UNRESOLVED_EARLIER_TRANSACTION', JSON.stringify(next.stop));
  assert.equal(journal.get(opId(fresh.run, 'approve')).state, 'semantically_verified', JSON.stringify(next.stop));
  assert.equal(approveTxs(env), 3);
});

test('A1-F01: the Brickken send route uses the signer window budget, never spins, and resumes with the identical bytes after a restart', async () => {
  const env = environment();
  const { owner, run, approval } = await ownerApproved(env);
  env.gateway.faults.send = Array(8).fill('TIMEOUT_DROPPED');
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const stopped = runView(owner);
  assert.equal(stopped.stop.code, 'STEP_TIMEOUT', JSON.stringify(stopped.stop));
  assert.equal(stopped.stop.details.step, 'setAction');
  const journal = journalOf(env);
  const before = journal.get(opId(run, 'setAction'));
  assert.equal(before.state, 'uncertain');
  const attempts = sendAttempts(env, 'setAction');
  assert.ok(attempts.length >= MAX_SEND_ATTEMPTS + 1 && attempts.length <= 8, `send attempts ${attempts.length}`);
  assert.equal(before.broadcast.attempts, attempts.length);
  assert.ok(maxInWindow(attempts.map(entry => entry.at), SEND_ATTEMPT_WINDOW_MS) <= MAX_SEND_ATTEMPTS);
  assert.equal(signedCount(env, 'setAction'), 1);

  env.gateway.faults.send = [];
  const { owner: owner2 } = restart(env, approval);
  await owner2.resumeRun({ runId: run.runId });
  await owner2.whenIdle(run.runId);
  assert.equal(runView(owner2).status, 'awaiting-agent', JSON.stringify(runView(owner2).stop));
  const after = journal.get(opId(run, 'setAction'));
  assert.equal(after.state, 'semantically_verified');
  assert.equal(after.signed.ethereumTransactionHash, before.signed.ethereumTransactionHash);
  assert.equal(signedCount(env, 'setAction'), 1);
  assert.equal(minedCount(env, tx => tx.to === env.proposal.executor && tx.data.startsWith('0xa4a22854')), 1);
});

test('A1-F01: after the approval expires an unresolved signed transaction is only tracked by reads; no resend, no new signature, and a late confirmation is still verified', async () => {
  const env = environment();
  const { owner, run, approval } = await ownerApproved(env);
  const sends = [];
  const original = env.rpcs.primary.sendRawTransaction.bind(env.rpcs.primary);
  env.rpcs.primary.sendRawTransaction = async bytes => { sends.push(env.clock.ms); return original(bytes); };
  env.rpcs.primary.faults.sendErrors = Array(500).fill('RPC_TIMEOUT');
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).stop.code, 'STEP_TIMEOUT');
  const journal = journalOf(env);
  const before = journal.get(opId(run, 'approve'));
  const sendsBefore = sends.length;

  // The approval lifetime passes with the transaction still unresolved.
  env.clock.ms += 97 * HOUR;
  env.chain.jumpTo(env.clock.ms);
  const { owner: owner2 } = restart(env, approval);
  await owner2.resumeRun({ runId: run.runId });
  await owner2.whenIdle(run.runId);
  const tracked = runView(owner2);
  assert.equal(tracked.status, 'stopped');
  assert.equal(tracked.stop.code, 'RECOVERY_AUTHORIZATION_REQUIRED', JSON.stringify(tracked.stop));
  assert.equal(tracked.stop.details.transactionHash, before.signed.ethereumTransactionHash);
  const during = journal.get(opId(run, 'approve'));
  assert.equal(during.state, 'uncertain');
  assert.equal(during.broadcast.attempts, before.broadcast.attempts);
  assert.equal(during.signed.signedTransaction, before.signed.signedTransaction);
  assert.equal(sends.length, sendsBefore);
  assert.equal(signedCount(env, 'approve'), 1);

  // The original bytes reach the chain late through another path; tracking picks the confirmation up.
  env.chain.accept(before.signed.signedTransaction);
  await env.sleep(30_000);
  await owner2.resumeRun({ runId: run.runId });
  await owner2.whenIdle(run.runId);
  const late = runView(owner2);
  assert.equal(late.stop.code, 'APPROVAL_EXPIRED', JSON.stringify(late.stop));
  const verified = journal.get(opId(run, 'approve'));
  assert.equal(verified.state, 'semantically_verified');
  assert.equal(verified.signed.ethereumTransactionHash, before.signed.ethereumTransactionHash);
  assert.equal(sends.length, sendsBefore);
  assert.equal(signedCount(env, 'grant'), 0);
  assert.equal(approveTxs(env), 1);
});

test('A1-F01: signer prepare and send budgets count only attempts inside their windows', () => {
  const proposal = loadLiveProposal();
  const approval = buildRunApproval(proposal, { createdAt: '2026-09-14T00:00:00.000Z', notAfter: '2026-09-15T00:00:00.000Z', preflight: null });
  const nowMs = Date.parse('2026-09-14T12:00:00.000Z');
  const body = facadeBody(proposal, 'setAction', { nonce: '0', gasLimit: proposal.gasLimitCaps.setAction });
  const prepareAttempt = at => ({ at, type: 'prepare-attempt', role: 'owner', step: 'setAction', bodySha256: 'a'.repeat(64) });
  const recent = Array.from({ length: MAX_PREPARE_ATTEMPTS }, (_, i) => prepareAttempt(new Date(nowMs - (i + 1) * MINUTE).toISOString()));
  const old = Array.from({ length: MAX_PREPARE_ATTEMPTS }, (_, i) => prepareAttempt(new Date(nowMs - PREPARE_ATTEMPT_WINDOW_MS - (i + 1) * MINUTE).toISOString()));
  const request = { role: 'owner', step: 'setAction', body };
  assert.throws(() => authorizePrepare({ proposal, approval, entries: recent, request, nowMs }), { code: 'PREPARE_ATTEMPTS_EXHAUSTED' });
  assert.deepEqual(authorizePrepare({ proposal, approval, entries: old, request, nowMs }), body);
  // Entries without a time stay conservative: they count as recent.
  const untimed = recent.map(({ at: _at, ...entry }) => entry);
  assert.throws(() => authorizePrepare({ proposal, approval, entries: untimed, request, nowMs }), { code: 'PREPARE_ATTEMPTS_EXHAUSTED' });

  const transaction = {
    chainId: proposal.chainId, from: stepSignerAddress(proposal, 'setAction'), to: stepTarget(proposal, 'setAction'), value: '0',
    data: expectedCalldata(proposal, 'setAction'), nonce: '0', gasLimit: proposal.gasLimitCaps.setAction, type: 2,
    maxPriorityFeePerGas: proposal.fees.maxPriorityFeePerGas, maxFeePerGas: proposal.fees.maxFeePerGas
  };
  const signedTransaction = `0x${'11'.repeat(64)}`;
  const base = [
    { type: 'signed', step: 'setAction', transaction, signedTransaction, transactionHash: `0x${'22'.repeat(32)}` },
    { type: 'prepared', step: 'setAction', transaction, txId: 'fake' }
  ];
  const sendAttempt = at => ({ at, type: 'send-attempt', step: 'setAction' });
  const sendRequest = { role: 'owner', step: 'setAction', txId: 'fake', signedTransaction };
  const recentSends = Array.from({ length: MAX_SEND_ATTEMPTS }, (_, i) => sendAttempt(new Date(nowMs - (i + 1) * MINUTE).toISOString()));
  const oldSends = Array.from({ length: MAX_SEND_ATTEMPTS }, (_, i) => sendAttempt(new Date(nowMs - SEND_ATTEMPT_WINDOW_MS - (i + 1) * MINUTE).toISOString()));
  assert.throws(() => authorizeSend({ approval, entries: [...base, ...recentSends], request: sendRequest, nowMs }), { code: 'SEND_ATTEMPTS_EXHAUSTED' });
  assert.equal(authorizeSend({ approval, entries: [...base, ...oldSends], request: sendRequest, nowMs }), base[0]);
  assert.equal(authorizeSend({ approval, entries: [...base, ...oldSends, ...recentSends.slice(0, MAX_SEND_ATTEMPTS - 1)], request: sendRequest, nowMs }), base[0]);
});

test('A1-F01: the adapter resend budget follows the route and the window', () => {
  const at = offsetMinutes => new Date(Date.parse('2026-09-14T12:00:00.000Z') - offsetMinutes * MINUTE).toISOString();
  const nowMs = Date.parse('2026-09-14T12:00:00.000Z');
  const record = (route, attemptsAt) => ({ route, broadcast: { attempts: attemptsAt.length, attemptsAt, lastAttemptAt: attemptsAt.at(-1) } });
  assert.equal(broadcastBackoffUntil(record('sepolia-rpc', [at(1), at(2), at(3), at(4)]), nowMs), null);
  assert.notEqual(broadcastBackoffUntil(record('sepolia-rpc', [at(1), at(2), at(3), at(4), at(5)]), nowMs), null);
  assert.equal(broadcastBackoffUntil(record('sepolia-rpc', [at(16), at(17), at(18), at(19), at(20)]), nowMs), null);
  assert.equal(broadcastBackoffUntil(record('brickken-api', [at(1), at(2)]), nowMs), null);
  assert.notEqual(broadcastBackoffUntil(record('brickken-api', [at(1), at(2), at(3)]), nowMs), null);
  // Without attempt times the last attempt alone is counted.
  assert.equal(broadcastBackoffUntil({ route: 'sepolia-rpc', broadcast: { attempts: 9, lastAttemptAt: at(1) } }, nowMs), null);
});

// ---------------------------------------------------------------------------
// A1-F02 and A1-F03: one lock protocol for the three live locks

test('A1-F02: a journal or workspace lock left by a dead process is taken over; a live holder blocks; unreadable content is reported and left in place', async () => {
  const env = environment();
  const { owner, run, approval } = await ownerApproved(env);
  const journal = journalOf(env);
  const journalLock = path.join(env.dir, 'live', 'journal', 'live-journal.lock');
  const workspaceLock = path.join(env.dir, 'live', 'live-workspace.lock');
  const binding = () => ({
    operationId: `live_${randomUUID().replaceAll('-', '')}_approve`, operationKind: 'approve', route: 'sepolia-rpc', apiTxId: null,
    preparationHash: 'd'.repeat(64), createdAt: '2026-09-14T12:00:00.000Z',
    transaction: {
      chainId: '11155111', from: env.proposal.principal, to: env.proposal.token.address, value: '0', data: '0x095ea7b3' + '0'.repeat(128),
      nonce: '7', type: 2, gasLimit: '60000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000'
    }
  });

  // Dead holder: taken over by the next exclusive open, and the file then carries this process's released record.
  fs.writeFileSync(journalLock, JSON.stringify(staleRecord(deadPid())));
  fs.writeFileSync(workspaceLock, JSON.stringify(staleRecord(deadPid())));
  const created = journal.createPending(binding());
  assert.equal(created.state, 'pending');
  assert.equal(readLockHolder(journalLock).state, 'released');
  assert.equal(readLockHolder(journalLock).record.pid, process.pid);
  owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: run.codeIdentitySha256 });
  assert.equal(readLockHolder(workspaceLock).state, 'released');

  // Live holder: the write waits its bounded time, fails with the busy code and leaves the lock.
  for (const [lock, write, code] of [
    [journalLock, () => journal.createPending(binding()), 'JOURNAL_BUSY'],
    [workspaceLock, () => owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: run.codeIdentitySha256 }), 'LIVE_WORKSPACE_BUSY']
  ]) {
    const holder = child('hold', lock, 6000);
    await holder.waitFor('HELD');
    assert.throws(write, { code });
    assert.equal(readLockHolder(lock).state, 'held');
    assert.equal(await holder.exit, 0);
    assert.equal(readLockHolder(lock).state, 'released');
    write();
  }

  // Crashed holder: the child acquires and exits without releasing; the next writer recovers.
  const crasher = child('crash', journalLock);
  await crasher.waitFor('HELD');
  assert.equal(await crasher.exit, 3);
  assert.equal(readLockHolder(journalLock).state, 'valid');
  assert.equal(readLockHolder(journalLock).record.pid, crasher.pid);
  const listBefore = journal.list();
  const recovered = journal.createPending(binding());
  assert.equal(journal.list().length, listBefore.length + 1);
  assert.equal(journal.get(recovered.operationId).state, 'pending');
  assert.equal(readLockHolder(journalLock).state, 'released');
  assert.equal(readLockHolder(journalLock).record.pid, process.pid);

  // An empty lock file that no process holds is not a holder record: it is reported and left in place, never taken over.
  fs.writeFileSync(workspaceLock, '');
  assert.throws(() => owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: run.codeIdentitySha256 }), { code: 'LIVE_WORKSPACE_LOCK_INVALID' });
  assert.equal(fs.existsSync(workspaceLock), true);
  fs.unlinkSync(workspaceLock);

  // Unreadable content is never treated as dead, whatever its age: reported with its own code and left in place.
  const past = new Date(Date.now() - 2 * MINUTE);
  for (const [lock, write, code] of [
    [journalLock, () => journal.createPending(binding()), 'JOURNAL_LOCK_INVALID'],
    [workspaceLock, () => owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: run.codeIdentitySha256 }), 'LIVE_WORKSPACE_LOCK_INVALID']
  ]) {
    fs.writeFileSync(lock, '');
    fs.utimesSync(lock, past, past);
    const before = fs.readFileSync(path.join(env.dir, 'live', 'journal', 'live-journal.json'), 'utf8');
    assert.throws(write, { code });
    assert.equal(fs.existsSync(lock), true);
    assert.equal(fs.readFileSync(path.join(env.dir, 'live', 'journal', 'live-journal.json'), 'utf8'), before);
    fs.unlinkSync(lock);
  }
});

test('A1-F03: the run lock is an exclusive process-bound handle: a stale record is taken over by the next exclusive open, a live holder cannot be read, renamed, unlinked or displaced by anyone, a release never touches a later holder, and racing processes never overlap', async () => {
  assert.equal(exclusiveOpenSupported(), true);
  const dir = testDir('lock-race');
  const file = path.join(dir, 'live-run.lock');
  const stale = staleRecord(deadPid());
  fs.writeFileSync(file, JSON.stringify(stale));
  assert.equal(readLockHolder(file).state, 'valid');

  // S -> A: the stale record is taken over within one exclusive open; no rename, no second step.
  const leaseA = acquireLiveLock(file, { holder: { purpose: 'A' } });
  assert.equal(leaseA.protocol, 'exclusive-handle');
  assert.ok(leaseA.holds());
  assert.equal(readLockHolder(file).state, 'held');
  // B, whatever it read earlier, cannot open, rename, unlink or read the path while A holds it: the OS refuses, not a comparison.
  assert.throws(() => acquireLiveLock(file, { attempts: 1, busyCode: 'LIVE_RUN_BUSY' }), error => error instanceof LiveLockError && error.code === 'LIVE_RUN_BUSY');
  assert.throws(() => fs.renameSync(file, `${file}.claim`), error => error.code === 'EBUSY');
  assert.throws(() => fs.unlinkSync(file), error => error.code === 'EBUSY');
  assert.throws(() => fs.readFileSync(file), error => error.code === 'EBUSY');
  assert.ok(leaseA.holds());
  // A releases: its record is marked released through its own handle and the handle closes. C takes over.
  assert.equal(leaseA.release(), true);
  assert.equal(readLockHolder(file).state, 'released');
  const leaseC = acquireLiveLock(file, { holder: { purpose: 'C' } });
  assert.ok(leaseC.holds());
  // A's second release and A's ownership check do nothing to C; a fourth acquirer is busy while C holds.
  assert.equal(leaseA.release(), false);
  assert.equal(leaseA.holds(), false);
  assert.throws(() => acquireLiveLock(file, { attempts: 2, waitMs: 1, busyCode: 'LIVE_RUN_BUSY' }), error => error instanceof LiveLockError && error.code === 'LIVE_RUN_BUSY');
  assert.ok(leaseC.holds());
  assert.equal(leaseC.release(), true);
  assert.equal(readLockHolder(file).record.purpose, 'C');

  // Real processes racing for the same stale lock.
  fs.writeFileSync(file, JSON.stringify(staleRecord(deadPid())));
  const racers = Array.from({ length: 6 }, () => child('race', file, 250));
  await Promise.all(racers.map(racer => racer.exit));
  const reports = racers.map(racer => JSON.parse(racer.lines.find(line => line.startsWith('{'))));
  const winners = reports.filter(report => report.ok).sort((x, y) => x.start - y.start);
  const losers = reports.filter(report => !report.ok);
  assert.ok(winners.length >= 1, JSON.stringify(reports));
  assert.equal(winners.length + losers.length, 6);
  for (const loser of losers) assert.equal(loser.code, 'LIVE_RUN_BUSY', JSON.stringify(loser));
  for (const winner of winners) { assert.equal(winner.held, true); assert.equal(winner.released, true); }
  for (let index = 1; index < winners.length; index++) assert.ok(winners[index].start >= winners[index - 1].end, 'two holders overlapped');
  assert.equal(readLockHolder(file).state, 'released');
});

// ---------------------------------------------------------------------------
// A1-F04 and A1-F05: two sources for the parent state and the confirmation depth

test('A1-F04: a parent-block state that the second source reports differently stops verification, and a second source without the parent block never verifies', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  // Alter the allowance answer only on blocks without transactions: the parent block of execute is one of them, the receipt block is not.
  env.rpcs.secondary.faults.viewOverride = (block, input, data) =>
    input.data.startsWith('0xdd62ed3e') && block.txHashes.length === 0 ? '0x' + '1'.padStart(64, '0') : data;
  const agent = agentOf(env);
  let stop = null;
  for (let attempt = 0; attempt < 8 && !stop; attempt++) {
    try { const receipt = await agent.agentExecute({ operationId: opId(run, 'execute') }); if (receipt.execute.status === 'verified') break; }
    catch (error) { stop = error; }
  }
  assert.ok(stop, 'execute should have stopped at the two-source parent check');
  assert.equal(stop.code, 'SOURCE_STATE_DISAGREEMENT');
  assert.equal(stop.details.field, 'before');
  assert.notEqual(journalOf(env).get(opId(run, 'execute')).state, 'semantically_verified');

  const env2 = environment();
  const { run: run2 } = await setupToAwaitingAgent(env2);
  const tip = env2.chain.latest().number;
  // The second source refuses exactly the parent block of a block that carries a transaction.
  env2.rpcs.secondary.faults.hideBlock = block => block.number >= tip && block.txHashes.length === 0 &&
    (env2.chain.blocks.find(next => next.number === block.number + 1)?.txHashes.length ?? 0) > 0;
  const receipt = await driveAgentExecute(agentOf(env2), opId(run2, 'execute'), 6);
  assert.equal(receipt.execute.status, 'confirmed', JSON.stringify(receipt.stop));
  assert.equal(receipt.execute.semanticallyVerified, false);
  const postcheck = path.join(env2.dir, 'live', 'evidence', run2.runId, `${opId(run2, 'execute')}-postcheck.json`);
  assert.equal(fs.existsSync(postcheck), false);
});

test('A1-F04: a verified write records both sources for the parent and receipt states', async () => {
  const env = environment();
  const { run } = await completeRun(env);
  const postcheck = evidence(env, run, `${opId(run, 'execute')}-postcheck`);
  assert.equal(postcheck.twoSourceObservation.before.agreed, true);
  assert.equal(postcheck.twoSourceObservation.after.agreed, true);
  assert.deepEqual(postcheck.twoSourceObservation.before.primary, postcheck.twoSourceObservation.before.secondary);
  assert.equal(postcheck.twoSourceObservation.parentBlock.hash, postcheck.envelope.before.blockHash);
  assert.equal(postcheck.twoSourceObservation.receiptBlock.hash, postcheck.envelope.after.blockHash);
});

test('A1-F05: a step advances only when both sources show the required depth, and the stored depth is the smaller one', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  env.rpcs.secondary.faults.lagBlocks = 3;
  // Since 2026-09-15 a source without the control block leaves execute waiting (CONTROL_UNRESOLVED),
  // so the lagging source is given the blocks it needs to show the control block before the agent acts.
  await env.sleep(3 * 12 * 1000);
  const receipt = await driveAgentExecute(agentOf(env), opId(run, 'execute'), 20);
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  const record = journalOf(env).get(opId(run, 'execute'));
  const secondaryDepth = Number(await env.rpcs.secondary.blockNumber()) - Number(record.confirmation.blockNumber) + 1;
  const primaryDepth = Number(await env.rpcs.primary.blockNumber()) - Number(record.confirmation.blockNumber) + 1;
  assert.ok(secondaryDepth >= env.proposal.confirmations.stepProgression, `secondary depth ${secondaryDepth}`);
  assert.ok(record.confirmation.confirmations >= env.proposal.confirmations.stepProgression);
  assert.ok(record.confirmation.confirmations <= Math.min(primaryDepth, secondaryDepth));
  const receiptEvidence = evidence(env, run, `${opId(run, 'execute')}-receipt`);
  assert.equal(receiptEvidence.confirmations, Math.min(receiptEvidence.confirmationsPrimary, receiptEvidence.confirmationsSecondary));
  assert.ok(receiptEvidence.confirmationsSecondary >= env.proposal.confirmations.stepProgression);
});

test('A1-F05: a recheck stores the depth it observed instead of keeping an earlier larger count', () => {
  const env = environment();
  const journal = journalOf(env);
  const proposal = env.proposal;
  const gateway = env.gateway;
  const transaction = {
    chainId: proposal.chainId, from: proposal.principal, to: proposal.token.address, value: '0',
    data: expectedCalldata(proposal, 'approve'), nonce: '0', type: 2, gasLimit: proposal.gasLimitCaps.approve,
    maxPriorityFeePerGas: proposal.fees.maxPriorityFeePerGas, maxFeePerGas: proposal.fees.maxFeePerGas
  };
  const record = journal.createPending({
    operationId: `live_${randomUUID().replaceAll('-', '')}_approve`, operationKind: 'approve', route: 'sepolia-rpc', apiTxId: null,
    preparationHash: 'd'.repeat(64), transaction, createdAt: '2026-09-14T12:00:00.000Z'
  });
  // Sign with the fake gateway's owner key; the verifier substitutes the intended sender as every live test does.
  const signed = gateway.client('owner');
  gateway.setApproval(buildRunApproval(proposal, { createdAt: '2026-09-14T00:00:00.000Z', notAfter: '2026-09-18T00:00:00.000Z', preflight: null }));
  return signed.sign('approve', transaction).then(result => {
    journal.recordSigned(record.operationId, { source: 'live-signer-v1', approvalSha256: 'f'.repeat(64), signedTransaction: result.signedTransaction, signedAt: '2026-09-14T12:00:01.000Z' }, gateway.verify);
    journal.recordBroadcast(record.operationId, result.signedTransaction, { result: 'accepted', attemptedAt: '2026-09-14T12:00:02.000Z', relayTransactionHash: result.transactionHash });
    const hash = '0x' + 'ab'.repeat(32);
    journal.confirm(record.operationId, { transactionHash: result.transactionHash, blockNumber: '1000', blockHash: hash, secondaryBlockHash: hash, receiptStatus: 1, confirmations: 5, checkedAt: '2026-09-14T12:00:05.000Z' });
    const rechecked = journal.recheckConfirmation(record.operationId, { transactionHash: result.transactionHash, blockNumber: '1000', blockHash: hash, secondaryBlockHash: hash, confirmations: 3, checkedAt: '2026-09-14T12:00:06.000Z' });
    assert.equal(rechecked.confirmation.confirmations, 3);
    assert.deepEqual(journal.get(record.operationId).broadcast.attemptsAt, ['2026-09-14T12:00:02.000Z']);
  });
});

// ---------------------------------------------------------------------------
// A1-F06: control evidence is canonical and final or it is nothing

test('A1-F06: a transaction-cap control whose block was reorganised before execute is observed again at the same stage, never carried forward', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const old = controlView(owner, 'control-transaction-cap');
  env.chain.reorg(env.chain.latest().number - Number(old.blockNumber) + 1);
  assert.equal(await env.rpcs.primary.getBlock({ blockHash: old.blockHash }), null);
  await assert.rejects(agentOf(env).agentExecute({ operationId: opId(run, 'execute') }), { code: 'CONTROL_WITHDRAWN' });
  const withdrawn = runView(owner);
  assert.equal(withdrawn.status, 'stopped');
  assert.equal(withdrawn.phase, 'owner-setup');
  assert.equal(controlView(owner, 'control-transaction-cap').passed, false);
  assert.equal(controlView(owner, 'control-transaction-cap').canonical, false);
  assert.equal(journalOf(env).find(opId(run, 'execute')), null);
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'awaiting-agent', JSON.stringify(runView(owner).stop));
  const renewed = controlView(owner, 'control-transaction-cap');
  assert.equal(renewed.passed, true);
  assert.equal(renewed.canonical, true);
  assert.notEqual(renewed.blockHash, old.blockHash);
  const receipt = await driveAgentExecute(agentOf(env), opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified');
  assert.equal(agentTxs(env), 1);
});

test('A1-F06: after completion a reorganisation past the pre-revocation control blocks invalidates the three later controls, stops the run as incomplete evidence, refuses finality and completeness, and cleanup re-verifies the same transactions', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  const cumulative = controlView(owner, 'control-cumulative-cap');
  const journal = journalOf(env);
  const hashesBefore = Object.fromEntries(['execute', 'revoke', 'approveReset'].map(step => [step, journal.get(opId(run, step)).signed.ethereumTransactionHash]));
  // Deep enough to remove the three controls observed after execute and the two writes after them; execute itself stays.
  env.chain.reorg(env.chain.latest().number - Number(cumulative.blockNumber) + 1);
  const finality = await owner.refreshFinality({ runId: run.runId });
  assert.equal(finality.allFinalized, false);
  const stopped = runView(owner);
  assert.equal(stopped.status, 'stopped');
  assert.equal(stopped.stop.code, 'CONTROL_EVIDENCE_LOST', JSON.stringify(stopped.stop));
  assert.deepEqual(stopped.stop.details.controlIds.sort(), ['control-after-revoke', 'control-before-revoke', 'control-cumulative-cap']);
  for (const control of stopped.controls) {
    const lost = control.id !== 'control-transaction-cap';
    assert.equal(control.passed, !lost, control.id);
    assert.equal(control.canonical, !lost, control.id);
  }
  assert.equal(journal.get(opId(run, 'execute')).state, 'semantically_verified');
  for (const step of ['revoke', 'approveReset']) assert.equal(journal.get(opId(run, step)).state, 'uncertain', step);
  assert.ok(finality.entries.some(entry => entry.controlId && entry.finalized === false));
  const completeness = evaluateLiveRunCompleteness({ run: owner.read().runs[0], journal });
  assert.equal(completeness.complete, false);
  assert.ok(completeness.missing.some(code => code.startsWith('CONTROL_NOT_CANONICAL:')));

  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.status, 'stopped', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.cleanup.mandateRevoked, true);
  assert.equal(cleaned.cleanup.allowance, '0');
  for (const step of ['execute', 'revoke', 'approveReset']) {
    const record = journal.get(opId(run, step));
    assert.equal(record.state, 'semantically_verified', step);
    assert.equal(record.signed.ethereumTransactionHash, hashesBefore[step], step);
  }
  assert.equal(agentTxs(env), 1);
  assert.equal(signedCount(env, 'revoke'), 1);
  assert.equal(signedCount(env, 'approveReset'), 1);
});

// ---------------------------------------------------------------------------
// A1-F07: the workspace phase is derived from the journal after a crash

test('A1-F07: a crash between the execute journal write and the workspace write is reconciled by replay, by revocation and by cleanup, without a second transaction', async () => {
  // Replay path.
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  assert.equal((await driveAgentExecute(agentOf(env), opId(run, 'execute'))).execute.status, 'verified');
  rewriteWorkspace(env, state => { state.runs[0].status = 'agent-executing'; state.runs[0].phase = 'agent-execute'; });
  const replay = await agentOf(env).agentExecute({ operationId: opId(run, 'execute') });
  assert.equal(replay.execute.status, 'verified');
  assert.equal(replay.runStatus, 'awaiting-owner-revocation');
  assert.equal(replay.replays.at(-1).newAgentTransaction, false);
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'completed', JSON.stringify(runView(owner).stop));
  assert.equal(agentTxs(env), 1);

  // Owner revocation without any replay.
  const env2 = environment();
  const { owner: owner2, run: run2 } = await setupToAwaitingAgent(env2);
  assert.equal((await driveAgentExecute(agentOf(env2), opId(run2, 'execute'))).execute.status, 'verified');
  rewriteWorkspace(env2, state => { state.runs[0].status = 'agent-executing'; state.runs[0].phase = 'agent-execute'; });
  await owner2.startOwnerRevocation({ runId: run2.runId });
  await owner2.whenIdle(run2.runId);
  assert.equal(runView(owner2).status, 'completed', JSON.stringify(runView(owner2).stop));
  assert.equal(agentTxs(env2), 1);

  // Cleanup from a stopped execute phase whose journal already says verified.
  const env3 = environment();
  const { owner: owner3, run: run3 } = await setupToAwaitingAgent(env3);
  assert.equal((await driveAgentExecute(agentOf(env3), opId(run3, 'execute'))).execute.status, 'verified');
  rewriteWorkspace(env3, state => { state.runs[0].status = 'stopped'; state.runs[0].phase = 'agent-execute'; });
  await owner3.startCleanup({ runId: run3.runId });
  await owner3.whenIdle(run3.runId);
  const cleaned = runView(owner3);
  assert.equal(cleaned.status, 'stopped', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.cleanup.revokedByCleanup, true);
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, true);
  assert.equal(env3.chain.state.mandate.revoked, true);
  assert.equal(env3.chain.state.allowance, 0n);
  assert.equal(agentTxs(env3), 1);
});

// ---------------------------------------------------------------------------
// A1-F08: completed is revocable while its chain evidence is not final

test('A1-F08: a reorganisation of the last write after completion reopens the revocation phase; resume tracks the same transaction to completion and finality', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  const journal = journalOf(env);
  const resetHash = journal.get(opId(run, 'approveReset')).signed.ethereumTransactionHash;
  const reset = stepView(owner, 'approveReset');
  env.chain.reorg(env.chain.latest().number - Number(reset.blockNumber) + 1);
  const finality = await owner.refreshFinality({ runId: run.runId });
  assert.equal(finality.allFinalized, false);
  const reopened = runView(owner);
  assert.equal(reopened.status, 'stopped');
  assert.equal(reopened.phase, 'owner-revocation');
  assert.equal(reopened.stop.code, 'CONFIRMATION_WITHDRAWN', JSON.stringify(reopened.stop));
  assert.equal(reopened.stop.details.step, 'approveReset');
  assert.equal(stepView(owner, 'approveReset').status, 'uncertain');
  // The agent surface derives its view from the same state.
  assert.equal(agentOf(env).agentReceipt({ operationId: opId(run, 'execute') }).runStatus, 'stopped');
  // Cleanup is available for the stopped run. It follows the same recorded
  // transaction, signs nothing new, and leaves the run stopped with a cleanup
  // record instead of completed, because the withdrawn evidence was re-verified
  // by cleanup and not by the revocation phase.
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'stopped');
  assert.equal(runView(owner).phase, null);
  assert.ok(runView(owner).cleanup, 'cleanup record');
  assert.equal(journal.get(opId(run, 'approveReset')).state, 'semantically_verified');

  // A restarted owner has nothing to resume: the run is not in an owner phase.
  const { owner: owner2 } = restart(env, owner.approvalDocument(run.runId));
  await assert.rejects(owner2.resumeRun({ runId: run.runId }), error => error.code === 'RUN_STATE');
  const after = journal.get(opId(run, 'approveReset'));
  assert.equal(after.state, 'semantically_verified');
  assert.equal(after.signed.ethereumTransactionHash, resetHash);
  assert.equal(signedCount(env, 'approveReset'), 1);
  assert.equal(minedCount(env, tx => tx.data.startsWith('0x095ea7b3') && tx.data.endsWith('0'.repeat(64))), 1);
});

test('A1-F08: without an interfering cleanup the reopened run completes again and reaches finality with every control finalized', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  const reset = stepView(owner, 'approveReset');
  env.chain.reorg(env.chain.latest().number - Number(reset.blockNumber) + 1);
  await owner.refreshFinality({ runId: run.runId });
  assert.equal(runView(owner).stop.code, 'CONFIRMATION_WITHDRAWN');
  await owner.resumeRun({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'completed', JSON.stringify(runView(owner).stop));
  await env.sleep(40 * 12 * 1000);
  const finality = await owner.refreshFinality({ runId: run.runId });
  assert.equal(finality.allFinalized, true, JSON.stringify(finality.entries));
  assert.equal(finality.entries.filter(entry => entry.controlId).length, 4);
  assert.ok(finality.entries.filter(entry => entry.controlId).every(entry => entry.finalized));
  assert.equal(runView(owner).status, 'completed');
  const revokeReport = evidence(env, run, `${opId(run, 'revoke')}-postcheck`).report;
  assert.ok(revokeReport.checks.includes('post-revoke-denial-state'));
  assert.equal(evaluateLiveRunCompleteness({ run: owner.read().runs[0], journal: journalOf(env) }).complete, true);
});

// ---------------------------------------------------------------------------
// A1-F09: cleanup revokes a mandate that is no longer executable

test('A1-F09: cleanup after the mandate expired revokes it, resets the allowance and records the prior executability instead of claiming a demonstration', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  await env.sleep(61 * MINUTE);
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.status, 'stopped', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.cleanup.revokedByCleanup, true);
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, true);
  assert.equal(cleaned.cleanup.allowance, '0');
  assert.equal(env.chain.state.mandate.revoked, true);
  assert.equal(env.chain.state.allowance, 0n);
  const report = evidence(env, run, `${opId(run, 'revoke')}-postcheck`).report;
  assert.equal(report.scope.cleanupRevocation, true);
  assert.equal(report.scope.revocationEffectDemonstrated, false);
  assert.ok(report.checks.includes('cleanup-revocation:before-executable-false:after-executable-false'), JSON.stringify(report.checks));
  assert.equal(report.checks.includes('post-revoke-denial-state'), false);
  // No control gained a pass it did not earn.
  assert.deepEqual(cleaned.controls.filter(control => control.observed).map(control => control.id), ['control-transaction-cap']);
  assert.equal(agentTxs(env), 0);

  // Cleanup after execute, with an executable mandate, keeps the same record shape and still resets everything.
  const env2 = environment();
  const { owner: owner2, run: run2 } = await setupToAwaitingAgent(env2);
  assert.equal((await driveAgentExecute(agentOf(env2), opId(run2, 'execute'))).execute.status, 'verified');
  await owner2.startCleanup({ runId: run2.runId });
  await owner2.whenIdle(run2.runId);
  assert.equal(runView(owner2).cleanup.allowance, '0', JSON.stringify(runView(owner2).stop));
  assert.equal(env2.chain.state.mandate.revoked, true);
  const report2 = evidence(env2, run2, `${opId(run2, 'revoke')}-postcheck`).report;
  assert.ok(report2.checks.includes('cleanup-revocation:before-executable-true:after-executable-false'), JSON.stringify(report2.checks));
});

// ---------------------------------------------------------------------------
// A1-F10: the evidence export has one explicit completeness rule

function exportEvidence(env, run, extra = [], target = null) {
  const output = target ?? path.relative(ROOT, path.join(ROOT, 'test-output', `fable-a1-export-${randomUUID().slice(0, 8)}`));
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'tools', 'export-live-evidence.mjs'), '--data', path.relative(ROOT, env.dir), '--run', run.runId, '--output', output, ...extra
  ], { cwd: ROOT, encoding: 'utf8', windowsHide: true });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, output: path.join(ROOT, output) };
}

test('A1-F10: a completed run without finality, with one source pending, with a stale finality entry or with a lost control is not exported as complete', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  const before = exportEvidence(env, run);
  assert.equal(before.status, 1);
  assert.match(before.stderr, /FINALITY_MISSING/);
  assert.equal(fs.existsSync(before.output), false);
  const partial = exportEvidence(env, run, ['--allow-incomplete']);
  assert.equal(partial.status, 0, partial.stderr);
  const partialTable = JSON.parse(fs.readFileSync(path.join(partial.output, 'transactions.json'), 'utf8'));
  assert.equal(partialTable.complete, false);
  assert.ok(partialTable.missing.includes('FINALITY_MISSING'));

  // One source still short of finality.
  env.rpcs.secondary.faults.lagBlocks = 20;
  await env.sleep(40 * 12 * 1000);
  const lagged = await owner.refreshFinality({ runId: run.runId });
  assert.equal(lagged.allFinalized, false);
  const pending = exportEvidence(env, run);
  assert.equal(pending.status, 1);
  assert.match(pending.stderr, /FINALITY_NOT_ALL_FINALIZED/);
  env.rpcs.secondary.faults.lagBlocks = 0;
  await env.sleep(30 * 12 * 1000);
  const final = await owner.refreshFinality({ runId: run.runId });
  assert.equal(final.allFinalized, true, JSON.stringify(final.entries));
  const complete = exportEvidence(env, run);
  assert.equal(complete.status, 0, complete.stderr);
  const table = JSON.parse(fs.readFileSync(path.join(complete.output, 'transactions.json'), 'utf8'));
  assert.equal(table.complete, true);
  assert.deepEqual(table.missing, []);
  assert.ok(table.transactions.filter(item => item.executed).every(item => item.finalizedOnBothSources === true));
  const runJson = JSON.parse(fs.readFileSync(path.join(complete.output, 'run.json'), 'utf8'));
  assert.ok(runJson.controls.every(control => control.finalizedOnBothSources === true));
  assert.equal(fs.existsSync(path.join(complete.output, 'controls', 'control-after-revoke.json')), true);

  // A finality entry that no longer names the journal's block is stale.
  rewriteWorkspace(env, state => {
    const entry = state.runs[0].finality.entries.find(item => item.operationId === opId(run, 'approveReset'));
    entry.blockHash = '0x' + 'f'.repeat(64);
  });
  const stale = exportEvidence(env, run);
  assert.equal(stale.status, 1);
  assert.match(stale.stderr, /FINALITY_ENTRY_STALE:approveReset/);
  rewriteWorkspace(env, state => { state.runs[0].controls['control-after-revoke'].canonical = false; state.runs[0].controls['control-after-revoke'].passed = false; });
  const lost = exportEvidence(env, run);
  assert.equal(lost.status, 1);
  assert.match(lost.stderr, /CONTROL_NOT_PASSED:control-after-revoke/);
});

// ---------------------------------------------------------------------------
// A1-F11: a live recording is bound by the server to one complete run

test('A1-F11: a live recording without a server-side binding is refused, an incomplete run is refused with what is missing, and a complete run binds the metadata to the journal', async () => {
  const webm = Buffer.concat([Buffer.from('1a45dfa3', 'hex'), Buffer.alloc(20)]);
  const dir = testDir('recording');
  await assert.rejects(saveDemoRecording(Readable.from([webm]), dir, 'live-run-evidence'), /RECORDING_BINDING/);
  await assert.rejects(saveDemoRecording(Readable.from([webm]), dir, 'simulation', { runId: 'x' }), /RECORDING_BINDING/);
  assert.equal(fs.existsSync(path.join(dir, 'recordings')), false);

  const env = environment();
  const { owner, run } = await completeRun(env);
  assert.throws(() => owner.recordingBinding(run.runId), error => error.code === 'RECORDING_RUN_INCOMPLETE' && error.details.missing.includes('FINALITY_MISSING'));
  await env.sleep(40 * 12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, true);
  // Since the recheck of 2026-09-15 the binding needs the exported package: the recording names its hash.
  assert.throws(() => owner.recordingBinding(run.runId), { code: 'RECORDING_PACKAGE_REQUIRED' });
  const packageRoot = path.relative(ROOT, testDir('packages')).split(path.sep).join('/');
  const exported = exportEvidence(env, run, [], `${packageRoot}/sepolia-live-${run.runId.slice(5, 17)}`);
  assert.equal(exported.status, 0, exported.stderr);
  const packaged = ownerOf(env, { evidencePackageRoot: packageRoot });
  const binding = packaged.recordingBinding(run.runId);
  assert.equal(binding.evidencePackage.directory, `${packageRoot}/sepolia-live-${run.runId.slice(5, 17)}`);
  assert.equal(binding.evidencePackage.sha256sumsSha256, createHash('sha256').update(fs.readFileSync(path.join(exported.output, 'SHA256SUMS.json'))).digest('hex'));
  assert.equal(binding.runId, run.runId);
  assert.equal(binding.approvalSha256, run.approvalSha256);
  assert.equal(binding.proposalHash, env.proposal.proposalHash);
  assert.match(binding.codeIdentitySha256, /^[a-f0-9]{64}$/);
  assert.equal(binding.transactions.length, 6);
  assert.equal(binding.controls.length, 4);
  const journal = journalOf(env);
  for (const item of binding.transactions) {
    const record = journal.get(item.operationId);
    assert.equal(item.transactionHash, record.signed.ethereumTransactionHash);
    assert.equal(item.blockHash, record.confirmation.blockHash);
  }
  const saved = await saveDemoRecording(Readable.from([webm]), env.dir, 'live-run-evidence', binding);
  const metadata = JSON.parse(fs.readFileSync(path.join(env.dir, 'recordings', `${saved.name}.json`), 'utf8'));
  assert.equal(metadata.mode, 'live-run-evidence');
  assert.equal(metadata.binding.runId, run.runId);
  assert.equal(metadata.binding.approvalSha256, run.approvalSha256);
  assert.equal(metadata.binding.finality.allFinalized, true);
  assert.match(metadata.bindingSha256, /^[a-f0-9]{64}$/);

  // The HTTP route: the page names the run, the server decides.
  const server = createApp({ store: new Store(env.dir), liveWorkspace: packaged });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const { csrf } = await (await fetch(`${origin}/api/session`)).json();
    const post = headers => fetch(`${origin}/api/live-recording`, { method: 'POST', headers: { 'content-type': 'video/webm', 'x-mandate-csrf': csrf, ...headers }, body: webm });
    const unnamed = await post({});
    assert.equal(unnamed.status, 400);
    assert.equal((await unnamed.json()).error, 'RECORDING_RUN_REQUIRED');
    const unknown = await post({ 'x-mandate-live-run': `live_${'0'.repeat(32)}` });
    assert.equal(unknown.status, 409);
    assert.equal((await unknown.json()).error, 'RUN_NOT_FOUND');
    const bound = await post({ 'x-mandate-live-run': run.runId });
    assert.equal(bound.status, 200);
    const body = await bound.json();
    assert.equal(body.binding.runId, run.runId);
    assert.equal(fs.existsSync(path.join(env.dir, 'recordings', body.name)), true);
    // The same run refuses once its finality is withdrawn.
    rewriteWorkspace(env, state => { state.runs[0].finality = null; });
    const withdrawn = await post({ 'x-mandate-live-run': run.runId });
    assert.equal(withdrawn.status, 409);
    const refused = await withdrawn.json();
    assert.equal(refused.error, 'RECORDING_RUN_INCOMPLETE');
    assert.ok(refused.details.missing.includes('FINALITY_MISSING'));
  } finally {
    server.close();
  }
});

// ---------------------------------------------------------------------------
// Findings of the adversarial check of the fixes (ADV-1 to ADV-3)

test('ADV-1: send attempts the signer logged but the journal never saw back off and finish inside the window instead of a hard SEND_REJECTED', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  // Three crashes between the signer's log write and the journal write leave three attempts only the signer knows about.
  const at = new Date(env.clock.ms).toISOString();
  for (let index = 0; index < MAX_SEND_ATTEMPTS; index++) env.gateway.entries.push({ at, type: 'send-attempt', role: 'owner', step: 'setAction' });
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const view = runView(owner);
  assert.equal(view.status, 'awaiting-agent', JSON.stringify(view.stop));
  const record = journalOf(env).get(opId(run, 'setAction'));
  assert.equal(record.state, 'semantically_verified');
  assert.equal(record.broadcast.attempts, 1);
  assert.ok(Date.parse(record.broadcast.attemptsAt[0]) - Date.parse(at) >= SEND_ATTEMPT_WINDOW_MS, 'the first real send waited for the signer window');
  assert.equal(signedCount(env, 'setAction'), 1);
});

test('ADV-2: cleanup is refused while the agent execute is unsettled, and the agent can still finish it afterwards', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  env.gateway.faults.send = Array(10).fill('TIMEOUT_DROPPED');
  const first = await agentOf(env).agentExecute({ operationId: opId(run, 'execute') });
  assert.equal(first.execute.status, 'uncertain', JSON.stringify(first.stop));
  assert.equal(first.runStatus, 'agent-executing');
  await assert.rejects(owner.startCleanup({ runId: run.runId }), error => error.code === 'RUN_STATE' && /agent/.test(error.message));
  assert.equal(runView(owner).phase, 'agent-execute');
  env.gateway.faults.send = [];
  await env.sleep(SEND_ATTEMPT_WINDOW_MS);
  const receipt = await driveAgentExecute(agentOf(env), opId(run, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  assert.equal(agentTxs(env), 1);
  assert.equal(signedCount(env, 'execute'), 1);
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).cleanup.allowance, '0', JSON.stringify(runView(owner).stop));
});

test('ADV-3: a lost control does not erase the phase that tracks a withdrawn execute in the same finality refresh', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  const cap = controlView(owner, 'control-transaction-cap');
  env.chain.reorg(env.chain.latest().number - Number(cap.blockNumber) + 1);
  await owner.refreshFinality({ runId: run.runId });
  const after = runView(owner);
  assert.equal(after.status, 'stopped');
  assert.equal(after.stop.code, 'CONTROL_EVIDENCE_LOST');
  assert.equal(after.phase, 'agent-execute');
  assert.equal(journalOf(env).get(opId(run, 'execute')).state, 'uncertain');
  // The agent's own resume path stays open; whatever the re-verification concludes, it is not refused for the phase.
  let code = null;
  try { await agentOf(env).agentExecute({ operationId: opId(run, 'execute') }); } catch (error) { code = error.code; }
  assert.notEqual(code, 'EXECUTION_NOT_AVAILABLE');
  assert.equal(agentTxs(env), 1);
  assert.equal(signedCount(env, 'execute'), 1);
});

// ---------------------------------------------------------------------------
// Clarification 1: the approval hash and the code identity are two hashes

test('A1 clarification: prepareRun names the code identity hash separately, and the approval hash does not depend on it', async () => {
  const env = environment();
  const owner = ownerOf(env);
  const { run, approval, codeIdentitySha256 } = await owner.prepareRun();
  assert.match(codeIdentitySha256, /^[a-f0-9]{64}$/);
  assert.equal(run.codeIdentitySha256, codeIdentitySha256);
  // The stable hash covers the sorted file table only; the recording time and the git head are metadata.
  const identity = evidence(env, run, 'code-identity');
  assert.equal(identity.schemaVersion, 2);
  assert.equal(identity.codeIdentitySha256, codeIdentitySha256);
  assert.equal(stableCodeIdentitySha256(identity), codeIdentitySha256);
  assert.notEqual(codeIdentitySha256, approval.approvalSha256);
  // The approval rebuilds byte for byte from the plan and the preflight alone.
  assert.equal(validateRunApproval(approval, env.proposal).approvalSha256, approval.approvalSha256);
  assert.equal(owner.read().runs[0].codeIdentitySha256, codeIdentitySha256);
});
