// Acceptance tests for the Codex recheck of the A1 fixes (astra/md/MANDATE-DESK-
// LIVE-AUDIT-A1-CODEX-RECHECK-2026-09-15.md, 2026-09-15). The open findings
// F03, F05 and F06, the decisions N1 and N5, the F11 package binding and the
// ADV-4 detail allowlist each get the test the recheck asked for: the test
// states the corrected behaviour and fails on the tree the recheck audited.
// Everything runs on the in-memory FakeSepolia harness with public Hardhat test
// keys: no network, no real key, no chain write. The N5 tests copy the covered
// source into an isolated runtime under test-output before they change a byte,
// so the repository's own files never change.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { once } from 'node:events';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { ROOT, Store } from '../src/store.mjs';
import { createApp } from '../src/server.mjs';
import { BrickkenLiveWorkspace } from '../src/brickken-workspace.mjs';
import { LiveBrickkenJournal } from '../src/brickken-journal.mjs';
import { LiveAdapterError, LiveStepExecutor, checkControlCanonicity, classifyLiveError } from '../src/brickken-live-adapter.mjs';
import { BrickkenWorkspaceError } from '../src/brickken-workspace.mjs';
import { buildRunApproval, expectedCalldata, loadLiveProposal } from '../src/brickken-live-plan.mjs';
import { saveDemoRecording } from '../src/demo-recording.mjs';
import { evaluateLiveRunCompleteness } from '../src/brickken-live-completeness.mjs';
import { EVENT_TOPICS } from '../src/brickken-postcheck.mjs';
import {
  CODE_IDENTITY_FILES, CODE_IDENTITY_FOLDERS, PROCESS_CODE_IDENTITY_SHA256, codeIdentityEvidence, computeCodeIdentity,
  coveredCodePaths, readGitHead, stableCodeIdentitySha256, validateCodeIdentityEvidence
} from '../src/code-identity.mjs';
import { LiveLockError, acquireLiveLock } from '../src/live-lock.mjs';
import { FakeRpc, FakeSepolia, FakeSignerGateway, createClock } from './live-fakes.mjs';

// ---------------------------------------------------------------------------
// Harness (the same shape as test/brickken-live-recovery.test.mjs)

function testDir(name = 'a1-recheck') {
  fs.mkdirSync(path.join(ROOT, 'test-output'), { recursive: true });
  return fs.mkdtempSync(path.join(ROOT, 'test-output', `fable-a1r-${name}-`));
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
const runView = (owner, runId = null) => (runId ? owner.view().runs.find(item => item.runId === runId) : owner.view().runs[0]);
const controlView = (owner, id) => runView(owner).controls.find(item => item.id === id);
const signedCount = (env, step) => env.gateway.entries.filter(entry => entry.type === 'signed' && entry.step === step).length;
const minedCount = (env, predicate) => [...env.chain.transactions.values()].filter(item => predicate(item.tx)).length;
const agentTxs = env => minedCount(env, tx => tx.from === env.proposal.agent);
const grantTxs = env => minedCount(env, tx => tx.to === env.proposal.registry && tx.data.startsWith('0xc6a4ad00'));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function evidence(env, run, name) {
  return JSON.parse(fs.readFileSync(path.join(env.dir, 'live', 'evidence', run.runId, `${name}.json`), 'utf8'));
}
function evidenceFiles(env, run) {
  return fs.readdirSync(path.join(env.dir, 'live', 'evidence', run.runId));
}
function rewriteWorkspace(env, change) {
  const file = path.join(env.dir, 'live', 'live-workspace.json');
  const state = JSON.parse(fs.readFileSync(file, 'utf8'));
  change(state);
  state.selfHash = sha256Canonicalish(state);
  fs.writeFileSync(file, JSON.stringify(state, null, 2));
}
// The live workspace self hash, rebuilt the way src/brickken-workspace.mjs does it.
function sha256Canonicalish(state) {
  const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
      : JSON.stringify(value);
  return sha256(Buffer.from(canonical({ schemaVersion: state.schemaVersion, kind: state.kind, proposalHash: state.proposalHash, runs: state.runs }), 'utf8'));
}
function exportEvidence(env, run, extra = [], target = null) {
  const output = target ?? path.relative(ROOT, path.join(ROOT, 'test-output', `fable-a1r-export-${randomUUID().slice(0, 8)}`));
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'tools', 'export-live-evidence.mjs'), '--data', path.relative(ROOT, env.dir), '--run', run.runId, '--output', output, ...extra
  ], { cwd: ROOT, encoding: 'utf8', windowsHide: true });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, output: path.join(ROOT, output), relative: output.split(path.sep).join('/') };
}
const WEBM = Buffer.concat([Buffer.from('1a45dfa3', 'hex'), Buffer.alloc(20)]);

// ---------------------------------------------------------------------------
// A1-F03: ownership is checked right before every prepare, sign and send

function pendingApproveRecord(env, runId, nonce = '0') {
  const proposal = env.proposal;
  return {
    operationId: `${runId}_approve`, operationKind: 'approve', route: 'sepolia-rpc', apiTxId: null,
    preparationHash: 'd'.repeat(64), createdAt: new Date(env.clock.ms).toISOString(),
    transaction: {
      chainId: proposal.chainId, from: proposal.principal, to: proposal.token.address, value: '0',
      data: expectedCalldata(proposal, 'approve'), nonce, type: 2, gasLimit: proposal.gasLimitCaps.approve,
      maxPriorityFeePerGas: proposal.fees.maxPriorityFeePerGas, maxFeePerGas: proposal.fees.maxFeePerGas
    }
  };
}
function lockLostAfter(flip) {
  const state = { owns: true, checks: 0 };
  return {
    state,
    flip: () => { state.owns = false; },
    assertOwnership: () => {
      state.checks += 1;
      if (!state.owns) throw new LiveAdapterError('LIVE_RUN_LOCK_LOST', { layer: 'workspace', lockFile: 'live-run.lock' });
    },
    ...flip
  };
}

test('A1-F03: ownership lost during the nonce reads stops before the signer is asked: no signature, no signed record', async () => {
  const env = environment();
  const journal = journalOf(env);
  const runId = `live_${randomUUID().replaceAll('-', '')}`;
  journal.createPending(pendingApproveRecord(env, runId));
  env.gateway.setApproval(buildRunApproval(env.proposal, { createdAt: new Date(env.clock.ms).toISOString(), notAfter: new Date(env.clock.ms + 3600_000).toISOString(), preflight: null }));
  const lock = lockLostAfter({});
  const client = env.gateway.client('owner');
  let signCalls = 0;
  const signer = { role: 'owner', async sign(step, transaction) { signCalls += 1; return client.sign(step, transaction); } };
  const originalCount = env.rpcs.primary.getTransactionCount.bind(env.rpcs.primary);
  env.rpcs.primary.getTransactionCount = async (address, ref) => {
    const value = await originalCount(address, ref);
    // The lease is displaced while the nonce read is in flight.
    if (ref === 'latest') lock.flip();
    return value;
  };
  const executor = new LiveStepExecutor({
    proposal: env.proposal, rpcs: env.rpcs, signer, journal, approvalSha256: 'a'.repeat(64),
    now: () => env.clock.ms, sleep: env.sleep, pollMs: 5000, verifySignedTransaction: env.gateway.verify, assertOwnership: lock.assertOwnership
  });
  await assert.rejects(executor.advance({ runId, step: 'approve', deadlineMs: 60_000 }), { code: 'LIVE_RUN_LOCK_LOST' });
  assert.equal(signCalls, 0);
  assert.equal(signedCount(env, 'approve'), 0);
  assert.equal(journal.get(`${runId}_approve`).state, 'pending');
  assert.ok(lock.state.checks >= 2);
});

test('A1-F03: ownership lost during the preparation reads stops before the Brickken preparation call', async () => {
  const env = environment();
  const journal = journalOf(env);
  const runId = `live_${randomUUID().replaceAll('-', '')}`;
  env.gateway.setApproval(buildRunApproval(env.proposal, { createdAt: new Date(env.clock.ms).toISOString(), notAfter: new Date(env.clock.ms + 3600_000).toISOString(), preflight: null }));
  const lock = lockLostAfter({});
  const client = env.gateway.client('owner');
  let prepareCalls = 0;
  const signer = { role: 'owner', async prepare(step, body) { prepareCalls += 1; return client.prepare(step, body); }, sign: client.sign };
  const originalBalance = env.rpcs.primary.getBalance.bind(env.rpcs.primary);
  env.rpcs.primary.getBalance = async (address, ref) => {
    const value = await originalBalance(address, ref);
    lock.flip();
    return value;
  };
  const executor = new LiveStepExecutor({
    proposal: env.proposal, rpcs: env.rpcs, signer, journal, approvalSha256: 'a'.repeat(64),
    now: () => env.clock.ms, sleep: env.sleep, pollMs: 5000, verifySignedTransaction: env.gateway.verify, assertOwnership: lock.assertOwnership
  });
  await assert.rejects(executor.advance({ runId, step: 'setAction', deadlineMs: 60_000 }), { code: 'LIVE_RUN_LOCK_LOST' });
  assert.equal(prepareCalls, 0);
  assert.equal(env.gateway.entries.filter(entry => entry.type === 'prepare-attempt').length, 0);
  assert.equal(journal.find(`${runId}_setAction`), null);
});

test('A1-F03: a send that started while owned keeps its journal result after ownership is lost during the network call, and the next step stops', async () => {
  const env = environment();
  const journal = journalOf(env);
  const runId = `live_${randomUUID().replaceAll('-', '')}`;
  const record = journal.createPending(pendingApproveRecord(env, runId));
  env.gateway.setApproval(buildRunApproval(env.proposal, { createdAt: new Date(env.clock.ms).toISOString(), notAfter: new Date(env.clock.ms + 3600_000).toISOString(), preflight: null }));
  const signed = await env.gateway.client('owner').sign('approve', record.transaction);
  journal.recordSigned(record.operationId, { source: 'live-signer-v1', approvalSha256: 'a'.repeat(64), signedTransaction: signed.signedTransaction, signedAt: new Date(env.clock.ms).toISOString() }, env.gateway.verify);
  const lock = lockLostAfter({});
  let ownedAtSend = null;
  const originalSend = env.rpcs.primary.sendRawTransaction.bind(env.rpcs.primary);
  env.rpcs.primary.sendRawTransaction = async bytes => {
    ownedAtSend = lock.state.owns;
    const hash = await originalSend(bytes);
    lock.flip();
    return hash;
  };
  const executor = new LiveStepExecutor({
    proposal: env.proposal, rpcs: env.rpcs, signer: { role: 'owner' }, journal, approvalSha256: 'a'.repeat(64),
    now: () => env.clock.ms, sleep: env.sleep, pollMs: 5000, verifySignedTransaction: env.gateway.verify, assertOwnership: lock.assertOwnership
  });
  await assert.rejects(executor.advance({ runId, step: 'approve', deadlineMs: 60_000 }), { code: 'LIVE_RUN_LOCK_LOST' });
  assert.equal(ownedAtSend, true);
  const after = journal.get(record.operationId);
  assert.equal(after.state, 'broadcast');
  assert.equal(after.broadcast.result, 'accepted');
  assert.equal(after.broadcast.attempts, 1);
  assert.ok(env.chain.mempool.some(item => item.hash === after.signed.ethereumTransactionHash));
});

test('A1-F03: a workspace gate that stops the executor keeps its code and details instead of becoming INTERNAL', () => {
  const lost = classifyLiveError(new BrickkenWorkspaceError('LIVE_RUN_LOCK_LOST', 'lost', { lockFile: 'live-run.lock' }), 'approve');
  assert.equal(lost.code, 'LIVE_RUN_LOCK_LOST');
  assert.equal(lost.details.layer, 'workspace');
  assert.equal(lost.details.lockFile, 'live-run.lock');
  assert.equal(lost.details.step, 'approve');
  const changed = classifyLiveError(new BrickkenWorkspaceError('CODE_IDENTITY_MISMATCH', 'changed', { phase: 'write' }), 'grant');
  assert.equal(changed.code, 'CODE_IDENTITY_MISMATCH');
  assert.equal(changed.details.phase, 'write');
  assert.equal(classifyLiveError(new Error('plain'), 'grant').code, 'INTERNAL');
});

// ---------------------------------------------------------------------------
// A1-F05: the required depth gates every dependent write, on a fresh reading

test('A1-F05: a verified execute that reads at depth 1, at depth 0 or from one source only blocks the dependent revoke until both sources confirm the depth again', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  assert.equal((await driveAgentExecute(agentOf(env), opId(run, 'execute'))).execute.status, 'verified');
  const journal = journalOf(env);
  const executeBlock = Number(journal.get(opId(run, 'execute')).confirmation.blockNumber);
  const executor = new LiveStepExecutor({
    proposal: env.proposal, rpcs: env.rpcs, signer: env.gateway.client('owner'), journal, approvalSha256: run.approvalSha256,
    now: () => env.clock.ms, sleep: env.sleep, pollMs: 5000, verifySignedTransaction: env.gateway.verify
  });
  const advance = () => executor.advance({ runId: run.runId, step: 'revoke', deadlineMs: 60_000 });

  // 2/1: the secondary's tip stays at the execute block.
  env.rpcs.secondary.faults.tipBlock = executeBlock;
  const shallow = await advance();
  assert.equal(shallow.done, false);
  assert.equal(shallow.waitingFor.dependencyOperationId, opId(run, 'execute'));
  assert.equal(shallow.waitingFor.reason, 'DEPTH_BELOW_THRESHOLD');
  assert.equal(shallow.waitingFor.confirmationsSecondary, 1);
  assert.equal(shallow.waitingFor.required, env.proposal.confirmations.stepProgression);
  assert.equal(journal.get(opId(run, 'execute')).confirmation.confirmations, 1);
  assert.equal(journal.get(opId(run, 'execute')).state, 'semantically_verified');
  assert.equal(journal.find(opId(run, 'revoke')), null);
  assert.equal(signedCount(env, 'revoke'), 0);

  // 2/0: the secondary's tip is below the execute block, so it has no block at that height.
  env.rpcs.secondary.faults.tipBlock = executeBlock - 1;
  const missing = await advance();
  assert.equal(missing.done, false);
  assert.equal(missing.waitingFor.reason, 'SOURCE_MISSING_BLOCK');
  assert.equal(missing.waitingFor.confirmationsSecondary, 0);
  assert.equal(journal.get(opId(run, 'execute')).confirmation.confirmations, 0);
  assert.equal(journal.get(opId(run, 'execute')).state, 'semantically_verified');
  assert.equal(signedCount(env, 'revoke'), 0);

  // One source hides the block at the execute height while its tip moves on.
  env.rpcs.secondary.faults.tipBlock = null;
  env.rpcs.secondary.faults.hideBlock = block => block.number === executeBlock;
  const hidden = await advance();
  assert.equal(hidden.done, false);
  assert.equal(hidden.waitingFor.reason, 'SOURCE_MISSING_BLOCK');
  assert.equal(signedCount(env, 'revoke'), 0);

  // Both sources agree at the required depth again: the revoke is prepared, signed once and verified.
  env.rpcs.secondary.faults.hideBlock = null;
  let outcome;
  for (let attempt = 0; attempt < 20 && !outcome?.done; attempt++) outcome = await advance();
  assert.equal(outcome.done, true, JSON.stringify(outcome));
  assert.equal(signedCount(env, 'revoke'), 1);
  assert.ok(journal.get(opId(run, 'execute')).confirmation.confirmations >= env.proposal.confirmations.stepProgression);
  assert.equal(minedCount(env, tx => tx.data.startsWith('0x5e20639e')), 1);
});

test('A1-F05: a verified write whose stored depth is deep is not trusted on the stored count: the gate reads both sources again and blocks a dependent write at depth 1', async () => {
  const env = environment();
  const { run } = await setupToAwaitingAgent(env);
  const journal = journalOf(env);
  const grant = journal.get(opId(run, 'grant'));
  assert.ok(grant.confirmation.confirmations >= 2);
  // The chain is reorganised so that the grant block is re-mined with the same content at the tip: the same
  // transaction hashes land in the replacement block, which both sources then return at depth 1.
  const grantBlock = Number(grant.confirmation.blockNumber);
  env.chain.reorg(env.chain.latest().number - grantBlock + 1);
  const executor = new LiveStepExecutor({
    proposal: env.proposal, rpcs: env.rpcs, signer: env.gateway.client('agent'), journal, approvalSha256: run.approvalSha256,
    now: () => env.clock.ms, sleep: env.sleep, pollMs: 5000, verifySignedTransaction: env.gateway.verify
  });
  const first = await executor.advance({ runId: run.runId, step: 'execute', deadlineMs: 60_000 });
  // The re-mined grant is a withdrawn confirmation first: the recorded hash is no longer canonical.
  assert.equal(first.done, false);
  assert.equal(first.waitingFor.dependencyOperationId, opId(run, 'grant'));
  assert.equal(first.waitingFor.reason, 'CONFIRMATION_WITHDRAWN');
  assert.equal(journal.get(opId(run, 'grant')).state, 'uncertain');
  assert.equal(signedCount(env, 'execute'), 0);
  assert.equal(journal.find(opId(run, 'execute')), null);
});

test('A1-F05: the crash reconcile of a verified execute moves the run on only while both sources read the required depth', async () => {
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  assert.equal((await driveAgentExecute(agentOf(env), opId(run, 'execute'))).execute.status, 'verified');
  const executeBlock = Number(journalOf(env).get(opId(run, 'execute')).confirmation.blockNumber);
  rewriteWorkspace(env, state => { state.runs[0].status = 'agent-executing'; state.runs[0].phase = 'agent-execute'; });
  env.rpcs.secondary.faults.tipBlock = executeBlock;
  await assert.rejects(owner.startOwnerRevocation({ runId: run.runId }), { code: 'RUN_STATE' });
  assert.equal(runView(owner).status, 'agent-executing');
  assert.equal(journalOf(env).get(opId(run, 'execute')).confirmation.confirmations, 1);
  env.rpcs.secondary.faults.tipBlock = null;
  await owner.startOwnerRevocation({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'completed', JSON.stringify(runView(owner).stop));
  assert.equal(agentTxs(env), 1);
});

// ---------------------------------------------------------------------------
// A1-F06: canonicity is aggregated per source; null is never permission

test('A1-F06: control canonicity is false as soon as any answering source disagrees, true only when both agree, and unresolved otherwise', async () => {
  const same = '0x' + '11'.repeat(32);
  const other = '0x' + '22'.repeat(32);
  const control = { controlId: 'control-transaction-cap', blockNumber: '11704480', blockHash: same };
  const source = hash => ({ async getBlock() { return hash === null ? null : { number: control.blockNumber, hash }; } });
  const matrix = [
    [same, same, true], [other, same, false], [same, other, false], [other, other, false],
    [other, null, false], [null, other, false], [same, null, null], [null, same, null], [null, null, null]
  ];
  for (const [primary, secondary, expected] of matrix) {
    const [result] = await checkControlCanonicity({ rpcs: { primary: source(primary), secondary: source(secondary) }, controls: [control] });
    assert.equal(result.canonical, expected, `${primary}/${secondary}`);
    assert.equal(result.primaryMatch, primary === null ? null : primary === same);
    assert.equal(result.secondaryMatch, secondary === null ? null : secondary === same);
  }
});

test('A1-F06: before execute, a primary hash mismatch with a missing secondary withdraws the control, and a missing source alone leaves the run waiting; neither signs', async () => {
  // Mismatch on the primary, no block on the secondary: the control is withdrawn.
  const env = environment();
  const { owner, run } = await setupToAwaitingAgent(env);
  const cap = controlView(owner, 'control-transaction-cap');
  env.chain.reorg(env.chain.latest().number - Number(cap.blockNumber) + 1);
  env.rpcs.secondary.faults.hideBlock = block => String(block.number) === cap.blockNumber;
  await assert.rejects(agentOf(env).agentExecute({ operationId: opId(run, 'execute') }), { code: 'CONTROL_WITHDRAWN' });
  assert.equal(controlView(owner, 'control-transaction-cap').canonical, false);
  assert.equal(controlView(owner, 'control-transaction-cap').passed, false);
  assert.equal(runView(owner).phase, 'owner-setup');
  assert.equal(signedCount(env, 'execute'), 0);
  assert.equal(journalOf(env).find(opId(run, 'execute')), null);

  // No disagreement, but one source has no block at the control height: unresolved, nothing signed, retry later.
  const env2 = environment();
  const { owner: owner2, run: run2 } = await setupToAwaitingAgent(env2);
  const cap2 = controlView(owner2, 'control-transaction-cap');
  env2.rpcs.secondary.faults.hideBlock = block => String(block.number) === cap2.blockNumber;
  await assert.rejects(agentOf(env2).agentExecute({ operationId: opId(run2, 'execute') }), { code: 'CONTROL_UNRESOLVED' });
  const waiting = runView(owner2);
  assert.equal(waiting.status, 'stopped');
  assert.equal(waiting.phase, 'agent-execute');
  assert.equal(waiting.stop.code, 'CONTROL_UNRESOLVED');
  assert.equal(controlView(owner2, 'control-transaction-cap').canonical, true);
  assert.equal(controlView(owner2, 'control-transaction-cap').passed, true);
  assert.equal(signedCount(env2, 'execute'), 0);
  assert.equal(journalOf(env2).find(opId(run2, 'execute')), null);
  env2.rpcs.secondary.faults.hideBlock = null;
  const receipt = await driveAgentExecute(agentOf(env2), opId(run2, 'execute'));
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  assert.equal(agentTxs(env2), 1);
  assert.equal(signedCount(env2, 'execute'), 1);
});

test('A1-F06: a verified write whose block one source reports with another hash is withdrawn even when the other source has no block at that height', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  const journal = journalOf(env);
  const last = journal.get(opId(run, 'approveReset'));
  const height = last.confirmation.blockNumber;
  env.chain.reorg(env.chain.latest().number - Number(height) + 1);
  env.rpcs.secondary.faults.hideBlock = block => String(block.number) === height;
  const finality = await owner.refreshFinality({ runId: run.runId });
  assert.equal(finality.allFinalized, false);
  assert.equal(journal.get(opId(run, 'approveReset')).state, 'uncertain');
  const reopened = runView(owner);
  assert.equal(reopened.status, 'stopped');
  assert.equal(reopened.stop.code, 'CONFIRMATION_WITHDRAWN');
  assert.equal(reopened.phase, 'owner-revocation');
  assert.equal(evaluateLiveRunCompleteness({ run: owner.read().runs[0], journal }).complete, false);
});

// ---------------------------------------------------------------------------
// N1: the grant verifier follows the registry's state machine; cleanup attributes

test('N1: after a full run and its revocation, a second full run on the same agent and principal pair verifies its grant and completes with a revoked mandate and a zero allowance', async () => {
  const env = environment();
  await completeRun(env);
  assert.equal(env.chain.state.mandate.revoked, true);
  assert.equal(env.chain.state.actionEnabled, true);
  assert.equal(env.chain.state.allowance, 0n);

  // A real signer log is approval-specific: the second run gets a fresh gateway on the same chain and workspace.
  const first = ownerOf(env);
  const prepared = await first.prepareRun();
  const gateway = new FakeSignerGateway({ chain: env.chain, proposal: env.proposal, clock: env.clock });
  gateway.counter = env.gateway.counter;
  gateway.setApproval(prepared.approval);
  const common = { ...env.common, verifySignedTransaction: gateway.verify };
  const owner = new BrickkenLiveWorkspace(env.dir, { role: 'owner', signer: gateway.client('owner'), ...common });
  const agent = new BrickkenLiveWorkspace(env.dir, { role: 'agent', signer: gateway.client('agent'), ...common });
  owner.approveRun({ runId: prepared.run.runId, approvalSha256: prepared.approval.approvalSha256, codeIdentitySha256: prepared.run.codeIdentitySha256 });
  await owner.startOwnerSetup({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  const setup = runView(owner, prepared.run.runId);
  assert.equal(setup.status, 'awaiting-agent', JSON.stringify(setup.stop));
  const grantPostcheck = JSON.parse(fs.readFileSync(path.join(env.dir, 'live', 'evidence', prepared.run.runId, `${opId(prepared.run, 'grant')}-postcheck.json`), 'utf8'));
  assert.equal(grantPostcheck.envelope.before.state.mandate.revoked, true);
  assert.equal(grantPostcheck.envelope.before.state.actionEnabled, true);
  assert.equal(grantPostcheck.report.verified, true);
  assert.equal((await driveAgentExecute(agent, opId(prepared.run, 'execute'))).execute.status, 'verified');
  await owner.startOwnerRevocation({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  assert.equal(runView(owner, prepared.run.runId).status, 'completed', JSON.stringify(runView(owner, prepared.run.runId).stop));
  assert.equal(grantTxs(env), 2);
  assert.equal(agentTxs(env), 2);
  assert.equal(env.chain.state.mandate.revoked, true);
  assert.equal(env.chain.state.allowance, 0n);
});

test('N1: a grant that is on chain but fails its semantic postcheck is attributed by receipt, calldata, event and block-bound state on both sources, and cleanup revokes it and resets the allowance', async () => {
  const env = environment();
  // Both sources return the grant receipt without its ActionEnabled log: the demonstration cannot pass, the chain effect is real.
  const dropEnabled = receipt => ({ ...receipt, logs: receipt.logs.filter(log => log.topics[0] !== EVENT_TOPICS.ActionEnabled) });
  env.rpcs.primary.faults.forgeReceipt = dropEnabled;
  env.rpcs.secondary.faults.forgeReceipt = dropEnabled;
  const { owner, run } = await ownerApproved(env);
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const stopped = runView(owner);
  assert.equal(stopped.status, 'stopped');
  assert.equal(stopped.stop.code, 'SEMANTIC_CHECK_FAILED', JSON.stringify(stopped.stop));
  assert.equal(stopped.stop.details.step, 'grant');
  assert.equal(journalOf(env).get(opId(run, 'grant')).state, 'confirmed');
  assert.equal(env.chain.state.mandate.revoked, false);
  assert.ok(env.chain.state.allowance > 0n);

  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.status, 'stopped', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.stop, null);
  assert.equal(cleaned.cleanup.revokedByCleanup, true);
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, true);
  assert.equal(cleaned.cleanup.mandateRevoked, true);
  assert.equal(cleaned.cleanup.allowance, '0');
  assert.deepEqual(cleaned.cleanup.attribution.grant, { attributed: true, reason: null });
  assert.deepEqual(cleaned.cleanup.problems, []);
  assert.deepEqual(cleaned.cleanup.postcheckFailed, ['grant']);
  const attribution = evidence(env, run, 'cleanup-attribution-grant');
  assert.equal(attribution.attributed, true);
  assert.equal(attribution.transactionHash, journalOf(env).get(opId(run, 'grant')).signed.ethereumTransactionHash);
  assert.ok(evidenceFiles(env, run).includes('cleanup-postcheck-failed-grant.json'));
  assert.equal(env.chain.state.mandate.revoked, true);
  assert.equal(env.chain.state.allowance, 0n);
  assert.equal(agentTxs(env), 0);
  assert.equal(signedCount(env, 'revoke'), 1);
  assert.equal(signedCount(env, 'approveReset'), 1);
  assert.equal(journalOf(env).get(opId(run, 'revoke')).state, 'semantically_verified');
  assert.equal(journalOf(env).get(opId(run, 'approveReset')).state, 'semantically_verified');
});

test('N1: cleanup does not revoke an active mandate that is not this run\'s grant; it resets the allowance it can attribute and stops with CLEANUP_FOREIGN_MANDATE', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  // setAction prepares first on the Brickken route; the grant preparation is the second one and fails.
  env.gateway.faults.prepare = [undefined, 'PAYMENT_REQUIRED'];
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).stop.code, 'PAYMENT_REQUIRED', JSON.stringify(runView(owner).stop));
  assert.equal(journalOf(env).find(opId(run, 'grant')), null);
  assert.ok(env.chain.state.allowance > 0n);
  // A mandate this run never granted appears active on chain.
  const foreign = {
    agent: env.proposal.agent, validFrom: String(Math.floor(env.clock.ms / 1000)), validUntil: String(Math.floor(env.clock.ms / 1000) + 3600),
    principal: env.proposal.principal, revoked: false, complianceProvider: env.proposal.complianceProvider, identityRef: env.proposal.identityRef,
    asset: env.proposal.token.address, maxTransactionValue: '1', maxCumulativeValue: '1', cumulativeUsed: '0', metadata: '0x' + 'ab'.repeat(32)
  };
  env.chain.state.mandate = foreign;
  env.chain.state.actionEnabled = true;
  env.chain.mine();

  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.status, 'stopped');
  assert.equal(cleaned.stop.code, 'CLEANUP_FOREIGN_MANDATE', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.cleanup.revokedByCleanup, false);
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, true);
  assert.equal(cleaned.cleanup.allowance, '0');
  assert.equal(cleaned.cleanup.mandateRevoked, false);
  assert.deepEqual(cleaned.cleanup.problems, ['CLEANUP_FOREIGN_MANDATE']);
  assert.equal(env.chain.state.mandate.revoked, false);
  assert.equal(env.chain.state.mandate.metadata, foreign.metadata);
  assert.equal(env.chain.state.allowance, 0n);
  assert.equal(signedCount(env, 'revoke'), 0);
});

// ---------------------------------------------------------------------------
// N5: the code identity is stable, approved with the plan and checked before every write

const RUNTIME_ENTRIES = [...CODE_IDENTITY_FOLDERS, 'integration', 'vendor', 'package.json', path.join('test', 'fixtures'), path.join('test', 'live-fakes.mjs')];
function runtimeCopy(label) {
  const runtime = testDir(`n5-${label}`);
  for (const entry of RUNTIME_ENTRIES) fs.cpSync(path.join(ROOT, entry), path.join(runtime, entry), { recursive: true });
  return runtime;
}
async function loadRuntime(runtime) {
  const load = relative => import(pathToFileURL(path.join(runtime, ...relative.split('/'))).href);
  const [workspace, plan, fakes, identity, completeness, journal] = await Promise.all([
    load('src/brickken-workspace.mjs'), load('src/brickken-live-plan.mjs'), load('test/live-fakes.mjs'),
    load('src/code-identity.mjs'), load('src/brickken-live-completeness.mjs'), load('src/brickken-journal.mjs')
  ]);
  return { ...workspace, ...plan, ...fakes, ...identity, ...completeness, ...journal };
}
function runtimeEnvironment(runtime, api) {
  const proposal = api.loadLiveProposal();
  const clock = api.createClock();
  const chain = new api.FakeSepolia({ proposal, clock });
  const rpcs = { primary: new api.FakeRpc(chain, 'primary'), secondary: new api.FakeRpc(chain, 'secondary') };
  const gateway = new api.FakeSignerGateway({ chain, proposal, clock });
  const dir = path.join(runtime, 'test-output', 'data');
  const sleep = async ms => { clock.ms += ms; chain.advanceTo(clock.ms); };
  const common = { rpcs, now: () => clock.ms, sleep, pollMs: 5000, verifySignedTransaction: gateway.verify };
  const owner = () => new api.BrickkenLiveWorkspace(dir, { role: 'owner', signer: gateway.client('owner'), ...common });
  const agent = () => new api.BrickkenLiveWorkspace(dir, { role: 'agent', signer: gateway.client('agent'), ...common });
  const drift = () => fs.appendFileSync(path.join(runtime, 'src', 'brickken-postcheck.mjs'), '\n// N5 acceptance: a byte changed after approval.\n');
  const original = fs.readFileSync(path.join(runtime, 'src', 'brickken-postcheck.mjs'));
  const restore = () => fs.writeFileSync(path.join(runtime, 'src', 'brickken-postcheck.mjs'), original);
  return { proposal, clock, chain, rpcs, gateway, dir, sleep, common, owner, agent, drift, restore };
}
async function runtimeApproved(env, owner) {
  const prepared = await owner.prepareRun();
  env.gateway.setApproval(prepared.approval);
  owner.approveRun({ runId: prepared.run.runId, approvalSha256: prepared.approval.approvalSha256, codeIdentitySha256: prepared.run.codeIdentitySha256 });
  return prepared;
}
const signedEntries = env => env.gateway.entries.filter(entry => entry.type === 'signed').length;
const sentEntries = env => env.gateway.entries.filter(entry => entry.type === 'send-attempt').length;

test('N5: the stable code identity covers the sorted file table only, ignores the recording time and the git head, and its evidence validates by content', () => {
  const first = computeCodeIdentity();
  const second = computeCodeIdentity();
  assert.equal(first.codeIdentitySha256, second.codeIdentitySha256);
  assert.equal(first.codeIdentitySha256, PROCESS_CODE_IDENTITY_SHA256);
  assert.equal(stableCodeIdentitySha256(first), first.codeIdentitySha256);
  const paths = coveredCodePaths();
  assert.deepEqual(first.files.map(file => file.path), paths);
  assert.deepEqual([...paths].sort(), paths);
  for (const file of CODE_IDENTITY_FILES) assert.ok(paths.includes(file), file);
  assert.ok(paths.includes('src/code-identity.mjs'));
  assert.ok(paths.includes('tools/start-live-signer.ps1'));
  assert.ok(paths.every(item => !item.startsWith('test/') && !item.startsWith('test-output/')));
  const early = codeIdentityEvidence(first, { recordedAt: '2026-09-15T10:00:00.000Z', gitHead: null });
  const late = codeIdentityEvidence(first, { recordedAt: '2026-09-15T11:00:00.000Z', gitHead: 'a'.repeat(40) });
  assert.equal(early.codeIdentitySha256, late.codeIdentitySha256);
  assert.notEqual(early.recordedAt, late.recordedAt);
  assert.notEqual(early.gitHead, late.gitHead);
  assert.equal(validateCodeIdentityEvidence(early), first.codeIdentitySha256);
  assert.equal(validateCodeIdentityEvidence(late), first.codeIdentitySha256);
  for (const [label, damage] of [
    ['hash', document => { document.codeIdentitySha256 = 'b'.repeat(64); }],
    ['file hash', document => { document.files[0].sha256 = 'c'.repeat(64); }],
    ['file bytes', document => { document.files[0].bytes += 1; }],
    ['order', document => { document.files.reverse(); }],
    ['extra key', document => { document.extra = true; }],
    ['schema', document => { document.schemaVersion = 1; }],
    ['path', document => { document.files[0].path = '../outside'; }],
    ['not an identity', () => ({ not: 'an identity' })]
  ]) {
    const document = structuredClone(late);
    const damaged = damage(document) ?? document;
    assert.throws(() => validateCodeIdentityEvidence(damaged), { code: 'CODE_IDENTITY_EVIDENCE_INVALID' }, label);
  }
});

test('N5: a git head that changes without a byte change keeps the stable hash and shows only in the metadata', async () => {
  const runtime = runtimeCopy('githead');
  const api = await loadRuntime(runtime);
  const before = api.computeCodeIdentity(runtime);
  assert.equal(api.readGitHead(runtime), null);
  fs.mkdirSync(path.join(runtime, '.git'), { recursive: true });
  fs.writeFileSync(path.join(runtime, '.git', 'HEAD'), 'd'.repeat(40) + '\n');
  assert.equal(api.readGitHead(runtime), 'd'.repeat(40));
  const after = api.computeCodeIdentity(runtime);
  assert.equal(after.codeIdentitySha256, before.codeIdentitySha256);
  assert.equal(api.codeIdentityEvidence(after, { recordedAt: '2026-09-15T12:00:00.000Z', gitHead: api.readGitHead(runtime) }).gitHead, 'd'.repeat(40));
  assert.equal(readGitHead(), readGitHead(ROOT));
});

test('N5: a covered file changed after approval stops owner setup before the first signature, even though the module is already loaded; restoring the bytes lets the run proceed', async () => {
  const runtime = runtimeCopy('setup');
  const api = await loadRuntime(runtime);
  const env = runtimeEnvironment(runtime, api);
  const owner = env.owner();
  const prepared = await runtimeApproved(env, owner);
  assert.equal(prepared.codeIdentitySha256, api.PROCESS_CODE_IDENTITY_SHA256);
  env.drift();
  await assert.rejects(owner.startOwnerSetup({ runId: prepared.run.runId }), error => error.code === 'CODE_IDENTITY_MISMATCH' &&
    error.details.codeIdentitySha256 === prepared.codeIdentitySha256 && error.details.diskCodeIdentitySha256 !== prepared.codeIdentitySha256);
  assert.equal(signedEntries(env), 0);
  assert.equal(env.chain.transactions.size, 0);
  assert.equal(owner.view().runs[0].status, 'owner-approved');
  env.restore();
  await owner.startOwnerSetup({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  assert.equal(owner.view().runs[0].status, 'awaiting-agent', JSON.stringify(owner.view().runs[0].stop));
  const checks = fs.readdirSync(path.join(env.dir, 'live', 'evidence', prepared.run.runId)).filter(name => name.startsWith('code-identity-owner-setup-'));
  assert.ok(checks.length >= 1);
});

test('N5: a change between two writes of one phase stops before the next preparation, signature or send; the signed bytes stay recorded and the run resumes on the restored code', async () => {
  const runtime = runtimeCopy('midphase');
  const api = await loadRuntime(runtime);
  const env = runtimeEnvironment(runtime, api);
  const client = env.gateway.client('owner');
  // The setAction bytes are signed; the covered file changes before they are sent.
  const signer = { ...client, async sign(step, transaction) { const result = await client.sign(step, transaction); if (step === 'setAction') env.drift(); return result; } };
  const owner = new api.BrickkenLiveWorkspace(env.dir, { role: 'owner', signer, ...env.common });
  const prepared = await runtimeApproved(env, owner);
  await owner.startOwnerSetup({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  const stopped = owner.view().runs[0];
  assert.equal(stopped.status, 'stopped');
  assert.equal(stopped.stop.code, 'CODE_IDENTITY_MISMATCH', JSON.stringify(stopped.stop));
  assert.equal(stopped.stop.details.phase, 'write');
  assert.equal(signedEntries(env), 1);
  assert.equal(sentEntries(env), 0);
  assert.equal(env.chain.transactions.size, 0);
  const journal = new api.LiveBrickkenJournal({ directory: path.join(env.dir, 'live', 'journal') });
  assert.equal(journal.get(`${prepared.run.runId}_setAction`).state, 'signed');
  await assert.rejects(owner.resumeRun({ runId: prepared.run.runId }), { code: 'CODE_IDENTITY_MISMATCH' });
  env.restore();
  await owner.resumeRun({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  assert.equal(owner.view().runs[0].status, 'awaiting-agent', JSON.stringify(owner.view().runs[0].stop));
  assert.equal(signedEntries(env), 3);
});

test('N5: the agent stops before execute_approved when a covered file changed, and the owner\'s revocation and cleanup stop the same way until the bytes are restored', async () => {
  const runtime = runtimeCopy('agent');
  const api = await loadRuntime(runtime);
  const env = runtimeEnvironment(runtime, api);
  const owner = env.owner();
  const prepared = await runtimeApproved(env, owner);
  await owner.startOwnerSetup({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  assert.equal(owner.view().runs[0].status, 'awaiting-agent', JSON.stringify(owner.view().runs[0].stop));
  const signedBefore = signedEntries(env);
  env.drift();
  const agent = env.agent();
  const operationId = `${prepared.run.runId}_execute`;
  await assert.rejects(agent.agentExecute({ operationId }), { code: 'CODE_IDENTITY_MISMATCH' });
  assert.equal(signedEntries(env), signedBefore);
  assert.equal(env.chain.transactions.size, 3);
  await assert.rejects(owner.startCleanup({ runId: prepared.run.runId }), { code: 'CODE_IDENTITY_MISMATCH' });
  assert.equal(signedEntries(env), signedBefore);
  env.restore();
  let receipt;
  for (let attempt = 0; attempt < 15; attempt++) {
    receipt = await agent.agentExecute({ operationId });
    if (receipt.execute.status === 'verified') break;
  }
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  env.drift();
  await assert.rejects(owner.startOwnerRevocation({ runId: prepared.run.runId }), { code: 'CODE_IDENTITY_MISMATCH' });
  await assert.rejects(owner.refreshFinality({ runId: prepared.run.runId }), { code: 'CODE_IDENTITY_MISMATCH' });
  assert.equal(signedEntries(env), signedBefore + 1);
  env.restore();
  await owner.startOwnerRevocation({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  assert.equal(owner.view().runs[0].status, 'completed', JSON.stringify(owner.view().runs[0].stop));
});

test('N5: a plan is not prepared by a process whose disk no longer carries the bytes it started with', async () => {
  const runtime = runtimeCopy('prepare');
  const api = await loadRuntime(runtime);
  const env = runtimeEnvironment(runtime, api);
  const owner = env.owner();
  env.drift();
  await assert.rejects(owner.prepareRun(), error => error.code === 'CODE_IDENTITY_MISMATCH' && error.details.phase === 'prepare');
  assert.equal(owner.view().runs.length, 0);
  env.restore();
  const prepared = await owner.prepareRun();
  assert.equal(prepared.codeIdentitySha256, api.PROCESS_CODE_IDENTITY_SHA256);
});

test('N5: a signer that reports another code identity is refused before any phase starts', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  env.gateway.codeIdentitySha256 = 'f'.repeat(64);
  await assert.rejects(owner.startOwnerSetup({ runId: run.runId }), error => error.code === 'SIGNER_CODE_IDENTITY_MISMATCH' &&
    error.details.processCodeIdentitySha256 === 'f'.repeat(64) && error.details.codeIdentitySha256 === run.codeIdentitySha256);
  assert.equal(signedCount(env, 'setAction'), 0);
  assert.equal(owner.view().signer === undefined ? null : null, null);
  assert.equal((await owner.signerStatus()).codeIdentitySha256, 'f'.repeat(64));
  env.gateway.codeIdentitySha256 = PROCESS_CODE_IDENTITY_SHA256;
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).status, 'awaiting-agent', JSON.stringify(runView(owner).stop));
});

test('N5: the owner approval names both hashes; a missing or wrong code identity is refused by the workspace and by the HTTP route', async () => {
  const env = environment();
  const owner = ownerOf(env);
  const { run, approval } = await owner.prepareRun();
  env.gateway.setApproval(approval);
  assert.throws(() => owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256 }), { code: 'INVALID_INPUT' });
  assert.throws(() => owner.approveRun({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: 'e'.repeat(64) }), { code: 'CODE_IDENTITY_MISMATCH' });
  assert.equal(runView(owner).status, 'awaiting-owner-approval');
  const server = createApp({ store: new Store(env.dir), liveWorkspace: owner });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const { csrf } = await (await fetch(`${origin}/api/session`)).json();
    const post = body => fetch(`${origin}/api/live/approve`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-mandate-csrf': csrf }, body: JSON.stringify(body) });
    const missing = await post({ runId: run.runId, approvalSha256: approval.approvalSha256 });
    assert.equal(missing.status, 400);
    const wrong = await post({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: 'e'.repeat(64) });
    assert.equal(wrong.status, 409);
    assert.equal((await wrong.json()).error, 'CODE_IDENTITY_MISMATCH');
    const accepted = await post({ runId: run.runId, approvalSha256: approval.approvalSha256, codeIdentitySha256: run.codeIdentitySha256 });
    assert.equal(accepted.status, 200);
    const body = await accepted.json();
    assert.equal(body.result.ownerApproval.codeIdentitySha256, run.codeIdentitySha256);
    assert.equal(body.result.ownerApproval.approvalSha256, approval.approvalSha256);
    assert.equal(body.state.signer.codeIdentitySha256, PROCESS_CODE_IDENTITY_SHA256);
  } finally {
    server.close();
  }
  assert.equal(runView(owner).status, 'owner-approved');
});

test('N5: identity evidence that is missing, invalid or of another tree makes the run incomplete and refuses the recording binding and the export', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  await env.sleep(40 * 12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, true);
  const journal = journalOf(env);
  const evidenceDirectory = path.join(env.dir, 'live', 'evidence', run.runId);
  const file = path.join(evidenceDirectory, 'code-identity-start.json');
  const original = fs.readFileSync(file);
  const completeness = () => evaluateLiveRunCompleteness({ run: owner.read().runs[0], journal, evidenceDirectory });
  assert.equal(completeness().complete, true);

  fs.writeFileSync(file, '{"not":"an identity"}\n');
  assert.ok(completeness().missing.includes('CODE_IDENTITY_EVIDENCE_INVALID:code-identity-start'));
  assert.throws(() => owner.recordingBinding(run.runId), error => error.code === 'RECORDING_RUN_INCOMPLETE' && error.details.missing.includes('CODE_IDENTITY_EVIDENCE_INVALID:code-identity-start'));
  const invalidExport = exportEvidence(env, run);
  assert.equal(invalidExport.status, 1);
  assert.match(invalidExport.stderr, /CODE_IDENTITY_EVIDENCE_INVALID:code-identity-start/);

  const other = JSON.parse(original.toString('utf8'));
  other.files[0] = { ...other.files[0], sha256: 'c'.repeat(64) };
  other.codeIdentitySha256 = stableCodeIdentitySha256(other);
  fs.writeFileSync(file, JSON.stringify(other, null, 2));
  assert.ok(completeness().missing.includes('CODE_IDENTITY_EVIDENCE_MISMATCH:code-identity-start'));
  const mismatchExport = exportEvidence(env, run);
  assert.equal(mismatchExport.status, 1);
  assert.match(mismatchExport.stderr, /CODE_IDENTITY_EVIDENCE_MISMATCH:code-identity-start/);

  fs.unlinkSync(file);
  assert.ok(completeness().missing.includes('EVIDENCE_FILE_MISSING:code-identity-start'));
  fs.writeFileSync(file, original);
  assert.equal(completeness().complete, true);
  rewriteWorkspace(env, state => { delete state.runs[0].codeIdentitySha256; });
  assert.ok(completeness().missing.includes('CODE_IDENTITY_MISSING'));
});

// ---------------------------------------------------------------------------
// A1-F11: the recording binds to the exported package by hash

test('A1-F11: a live recording binds only to the exported package: the binding carries the SHA256SUMS hash, a missing package, a tampered table and another run\'s package are refused, and the saved metadata names the same hash', async () => {
  const env = environment();
  const { owner, run } = await completeRun(env);
  await env.sleep(40 * 12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: run.runId })).allFinalized, true);
  assert.throws(() => owner.recordingBinding(run.runId), { code: 'RECORDING_PACKAGE_REQUIRED' });
  const exported = exportEvidence(env, run);
  assert.equal(exported.status, 0, exported.stderr);
  const sums = fs.readFileSync(path.join(exported.output, 'SHA256SUMS.json'));
  const binding = owner.recordingBinding(run.runId, { packageDirectory: exported.relative });
  assert.equal(binding.evidencePackage.directory, exported.relative);
  assert.equal(binding.evidencePackage.sha256sumsSha256, sha256(sums));
  const table = JSON.parse(fs.readFileSync(path.join(exported.output, 'transactions.json'), 'utf8'));
  assert.equal(table.runId, run.runId);
  assert.equal(table.complete, true);
  for (const item of binding.transactions) assert.equal(table.transactions.find(row => row.operationId === item.operationId).transactionHash, item.transactionHash);
  const saved = await saveDemoRecording(Readable.from([WEBM]), env.dir, 'live-run-evidence', binding);
  const metadata = JSON.parse(fs.readFileSync(path.join(env.dir, 'recordings', `${saved.name}.json`), 'utf8'));
  assert.equal(metadata.binding.evidencePackage.sha256sumsSha256, sha256(sums));
  assert.equal(metadata.binding.codeIdentitySha256, run.codeIdentitySha256);

  // The recorder refuses a binding without the package hash.
  await assert.rejects(saveDemoRecording(Readable.from([WEBM]), env.dir, 'live-run-evidence', { ...binding, evidencePackage: { directory: exported.relative, sha256sumsSha256: null } }), /RECORDING_BINDING/);
  await assert.rejects(saveDemoRecording(Readable.from([WEBM]), env.dir, 'live-run-evidence', { ...binding, evidencePackage: null }), /RECORDING_BINDING/);

  // Another run's package names another run.
  const env2 = environment();
  const { owner: owner2, run: run2 } = await completeRun(env2);
  await env2.sleep(40 * 12 * 1000);
  assert.equal((await owner2.refreshFinality({ runId: run2.runId })).allFinalized, true);
  const foreign = exportEvidence(env2, run2);
  assert.equal(foreign.status, 0, foreign.stderr);
  assert.throws(() => owner.recordingBinding(run.runId, { packageDirectory: foreign.relative }), { code: 'RECORDING_PACKAGE_MISMATCH' });

  // A tampered transaction table no longer matches SHA256SUMS.json.
  const tableFile = path.join(exported.output, 'transactions.json');
  fs.writeFileSync(tableFile, fs.readFileSync(tableFile, 'utf8').replace('"complete": true', '"complete": true '));
  assert.throws(() => owner.recordingBinding(run.runId, { packageDirectory: exported.relative }), { code: 'RECORDING_PACKAGE_MISMATCH' });
  assert.throws(() => owner.recordingBinding(run.runId, { packageDirectory: 'test-output/does-not-exist' }), { code: 'RECORDING_PACKAGE_REQUIRED' });
});

test('N5: a covered file changed after the run stops the recording binding and makes the export incomplete, because both run in this process\'s code', async () => {
  const runtime = runtimeCopy('binding');
  const api = await loadRuntime(runtime);
  const env = runtimeEnvironment(runtime, api);
  const owner = env.owner();
  const prepared = await runtimeApproved(env, owner);
  await owner.startOwnerSetup({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  const agent = env.agent();
  let receipt;
  for (let attempt = 0; attempt < 15; attempt++) {
    receipt = await agent.agentExecute({ operationId: `${prepared.run.runId}_execute` });
    if (receipt.execute.status === 'verified') break;
  }
  assert.equal(receipt.execute.status, 'verified', JSON.stringify(receipt.stop));
  await owner.startOwnerRevocation({ runId: prepared.run.runId });
  await owner.whenIdle(prepared.run.runId);
  await env.sleep(40 * 12 * 1000);
  assert.equal((await owner.refreshFinality({ runId: prepared.run.runId })).allFinalized, true);
  const exportTool = path.join(runtime, 'tools', 'export-live-evidence.mjs');
  const run = () => spawnSync(process.execPath, [exportTool, '--data', path.relative(runtime, env.dir), '--run', prepared.run.runId, '--output', `test-output/export-${randomUUID().slice(0, 8)}`], { cwd: runtime, encoding: 'utf8', windowsHide: true });
  const before = run();
  assert.equal(before.status, 0, before.stderr);
  const packageDirectory = /Evidence written to (\S+)/.exec(before.stdout)[1].split(path.sep).join('/');
  assert.equal(owner.recordingBinding(prepared.run.runId, { packageDirectory }).runId, prepared.run.runId);

  env.drift();
  await assert.rejects(Promise.resolve().then(() => owner.recordingBinding(prepared.run.runId, { packageDirectory })), error => error.code === 'CODE_IDENTITY_MISMATCH' && error.details.phase === 'recording');
  const refused = run();
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /CODE_IDENTITY_MISMATCH:export/);
  const partial = spawnSync(process.execPath, [exportTool, '--data', path.relative(runtime, env.dir), '--run', prepared.run.runId, '--output', `test-output/export-${randomUUID().slice(0, 8)}`, '--allow-incomplete'], { cwd: runtime, encoding: 'utf8', windowsHide: true });
  assert.equal(partial.status, 0, partial.stderr);
  const table = JSON.parse(fs.readFileSync(path.join(runtime, /Evidence written to (\S+)/.exec(partial.stdout)[1], 'transactions.json'), 'utf8'));
  assert.equal(table.complete, false);
  assert.ok(table.missing.includes('CODE_IDENTITY_MISMATCH:export'));
  assert.notEqual(table.exportCodeIdentitySha256, table.codeIdentitySha256);
  env.restore();
  assert.equal(owner.recordingBinding(prepared.run.runId, { packageDirectory }).codeIdentitySha256, prepared.codeIdentitySha256);
});

test('N1: a grant whose receipt one source reports without its event is not attributed, and cleanup stops with CLEANUP_GRANT_UNATTRIBUTED without revoking', async () => {
  const env = environment();
  const dropEnabled = receipt => ({ ...receipt, logs: receipt.logs.filter(log => log.topics[0] !== EVENT_TOPICS.ActionEnabled) });
  const dropGranted = receipt => ({ ...receipt, logs: receipt.logs.filter(log => log.topics[0] !== EVENT_TOPICS.ActionEnabled && log.topics[0] !== EVENT_TOPICS.MandateGranted) });
  env.rpcs.primary.faults.forgeReceipt = dropEnabled;
  env.rpcs.secondary.faults.forgeReceipt = dropGranted;
  const { owner, run } = await ownerApproved(env);
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  assert.equal(runView(owner).stop.code, 'SEMANTIC_CHECK_FAILED', JSON.stringify(runView(owner).stop));
  await owner.startCleanup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const cleaned = runView(owner);
  assert.equal(cleaned.status, 'stopped');
  assert.equal(cleaned.stop.code, 'CLEANUP_GRANT_UNATTRIBUTED', JSON.stringify(cleaned.stop));
  assert.equal(cleaned.stop.details.reason, 'EVENT');
  assert.deepEqual(cleaned.cleanup.attribution.grant, { attributed: false, reason: 'EVENT' });
  assert.equal(cleaned.cleanup.revokedByCleanup, false);
  assert.equal(cleaned.cleanup.allowanceResetByCleanup, true);
  assert.equal(env.chain.state.mandate.revoked, false);
  assert.equal(env.chain.state.allowance, 0n);
  assert.equal(signedCount(env, 'revoke'), 0);
});

test('A1-F03: a lock whose folder is gone stops with LOCK_DIRECTORY_MISSING instead of a raw error', () => {
  const dir = testDir('lock-folder');
  const file = path.join(dir, 'gone', 'live-run.lock');
  assert.throws(() => acquireLiveLock(file, { attempts: 1 }), error => error instanceof LiveLockError && error.code === 'LOCK_DIRECTORY_MISSING' && error.details.lockFile === 'live-run.lock');
});

// ---------------------------------------------------------------------------
// ADV-4: the stop detail allowlist keeps to and from and nothing else

test('ADV-4: a stop keeps the to and from addresses of a failed read and drops every other detail', async () => {
  const env = environment();
  const { owner, run } = await ownerApproved(env);
  env.rpcs.primary.faults.viewOverride = () => {
    throw new LiveAdapterError('READ_REVERTED', { layer: 'contract', to: env.proposal.token.address, from: env.proposal.principal, credential: 'never-shown', headers: { authorization: 'no' } });
  };
  await owner.startOwnerSetup({ runId: run.runId });
  await owner.whenIdle(run.runId);
  const stopped = runView(owner);
  assert.equal(stopped.status, 'stopped');
  assert.equal(stopped.stop.code, 'READ_REVERTED');
  assert.equal(stopped.stop.details.to, env.proposal.token.address);
  assert.equal(stopped.stop.details.from, env.proposal.principal);
  assert.equal(stopped.stop.details.layer, 'contract');
  assert.equal(Object.hasOwn(stopped.stop.details, 'credential'), false);
  assert.equal(Object.hasOwn(stopped.stop.details, 'headers'), false);
  assert.equal(signedCount(env, 'setAction'), 0);
});
